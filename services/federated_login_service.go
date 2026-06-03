package services

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// FederatedLoginService is the lean tenant-scoped OIDC+SAML federated
// login surface for the prod-mcp-v2 backport. Two operations per
// protocol: initiate (mint state + build upstream auth URL) and callback
// (validate state + exchange code/assertion at upstream + resolve to
// AuthSec users.id + return claims).
//
// The actual Hydra accept-login call happens in the LoginV2Controller —
// this service just produces the user identity + login_challenge pair
// the controller needs.
//
// Backport-lean equivalent of dev's services/oidc_service.go (~600 lines)
// and the SAML side of hmgr_controller.go (~200 lines). We strip:
//   - Multiple Action types (login, register, discover, hydra_login).
//     This is hydra_login only — the v2 surface doesn't have a self-serve
//     register flow.
//   - Signed-state verification (dev has HMAC signing for cross-host
//     state). Backport runs single-host; the state token's
//     opaque randomness is sufficient CSRF protection.
//   - Discovery mode for tenant_domain resolution. We always know which
//     tenant from the auth_request_context.
type FederatedLoginService struct {
	httpClient *http.Client
}

func NewFederatedLoginService() *FederatedLoginService {
	return &FederatedLoginService{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// InitiateOIDCInput is what the controller passes in.
type InitiateOIDCInput struct {
	TenantID          string
	ApplicationID    uuid.UUID
	IdentityProviderID uuid.UUID
	LoginChallenge    string
	ContextID         string
	CallbackURL       string // the absolute URL to /login/oidc/callback we want upstream to redirect to
}

// InitiateOIDCResponse: where to send the browser + the state we minted.
type InitiateOIDCResponse struct {
	UpstreamAuthURL string
	State           string
}

// InitiateOIDC builds the upstream provider's authorize URL. Steps:
//
//  1. Resolve identity_providers row; verify it's OIDC + configured.
//  2. Resolve the oidc_providers config row via config_ref.
//  3. Apply the per-Application IDP whitelist gate (matches the existing
//     pattern in Authorize and login/page-data).
//  4. Mint state_token + code_verifier; persist oidc_states row carrying
//     login_challenge for the callback to recover.
//  5. Build the upstream authorization URL with code_challenge (S256) +
//     redirect_uri pointed at our /login/oidc/callback.
func (s *FederatedLoginService) InitiateOIDC(in InitiateOIDCInput) (*InitiateOIDCResponse, error) {
	tenantDB, err := config.GetTenantGORMDB(in.TenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}

	// 1. Resolve identity_providers row.
	var idp models.IdentityProvider
	if err := tenantDB.Where("id = ? AND tenant_id = ? AND status = ?",
		in.IdentityProviderID, in.TenantID, "configured").First(&idp).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("identity provider not found or not configured")
		}
		return nil, err
	}
	if idp.ProviderType != models.IdentityProviderOIDC {
		return nil, errors.New("identity provider is not OIDC")
	}

	// 2. Per-Application policy gate (default-allow when no policy rows).
	allowed, err := s.idpAllowedForApplication(tenantDB, in.TenantID, in.ApplicationID, in.IdentityProviderID)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, errors.New("identity provider not enabled for this application")
	}

	// 3. Resolve underlying oidc_providers config.
	configUUID, err := uuid.Parse(idp.ConfigRef)
	if err != nil {
		return nil, fmt.Errorf("invalid oidc config_ref: %w", err)
	}
	var oidcRow struct {
		ID               uuid.UUID
		ProviderName     string
		ClientID         string
		AuthorizationURL string
		Scopes           string
		RedirectURI      string
	}
	if err := tenantDB.Table("oidc_providers").
		Select("id, provider_name, client_id, authorization_url, scopes, COALESCE(redirect_uri,'') AS redirect_uri").
		Where("id = ?", configUUID).
		First(&oidcRow).Error; err != nil {
		return nil, fmt.Errorf("load oidc_providers config: %w", err)
	}

	// 4. Mint state + PKCE.
	randomToken, err := federatedRandomToken(32)
	if err != nil {
		return nil, fmt.Errorf("state token: %w", err)
	}
	codeVerifier, err := federatedRandomToken(64)
	if err != nil {
		return nil, fmt.Errorf("code verifier: %w", err)
	}
	codeChallenge := pkceS256Challenge(codeVerifier)

	tenantUUID, err := uuid.Parse(in.TenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant_id: %w", err)
	}
	// State sent upstream encodes tenant so callback can pick the right DB
	// without a master-side index. DB-side we still store just the random
	// half in state_token (unique-indexed).
	wireState := buildStateToken(tenantUUID, randomToken)

	stateRow := models.OIDCState{
		StateToken:     randomToken,
		TenantID:       &tenantUUID,
		TenantDomain:   "", // not used on backport — we resolve via auth_request_context
		ProviderName:   oidcRow.ProviderName,
		Action:         "hydra_login",
		CodeVerifier:   codeVerifier,
		ApplicationID:  &in.ApplicationID,
		LoginChallenge: in.LoginChallenge,
		ExpiresAt:      time.Now().Add(15 * time.Minute),
	}
	if err := tenantDB.Create(&stateRow).Error; err != nil {
		return nil, fmt.Errorf("store oidc_states: %w", err)
	}

	// 5. Build upstream URL.
	callbackURL := in.CallbackURL
	if oidcRow.RedirectURI != "" {
		callbackURL = oidcRow.RedirectURI
	}
	scopes := oidcRow.Scopes
	if scopes == "" {
		scopes = "openid email profile"
	}
	params := url.Values{}
	params.Set("client_id", oidcRow.ClientID)
	params.Set("redirect_uri", callbackURL)
	params.Set("response_type", "code")
	params.Set("scope", scopes)
	params.Set("state", wireState)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")
	// Provider-specific extras: Google wants access_type=offline for refresh tokens.
	if oidcRow.ProviderName == "google" {
		params.Set("access_type", "offline")
		params.Set("prompt", "select_account")
	}
	authURL := oidcRow.AuthorizationURL + "?" + params.Encode()

	return &InitiateOIDCResponse{
		UpstreamAuthURL: authURL,
		State:           wireState,
	}, nil
}

// HandleOIDCCallbackInput is what the controller passes after upstream
// redirects to our callback URL.
type HandleOIDCCallbackInput struct {
	State       string
	Code        string
	CallbackURL string // same one we sent upstream, for token exchange
}

// HandleOIDCCallbackResult is what we return to the controller.
type HandleOIDCCallbackResult struct {
	TenantID       string
	ApplicationID  *uuid.UUID
	LoginChallenge string
	UserID         uuid.UUID    // the AuthSec users.id (JIT-created if first time)
	UserEmail      string
	UserName       string
	ProviderName   string
	AuthMethod     string // "oidc_federated"
}

// HandleOIDCCallback runs after upstream redirects with ?code=... &state=...
//
// Flow:
//  1. Look up the oidc_states row by state_token across all tenants
//     (state is a 32-byte random — globally unique). Find which tenant.
//  2. Verify not expired + not consumed.
//  3. Exchange code at upstream token endpoint (with code_verifier).
//  4. Fetch userinfo to get sub + email.
//  5. Resolve AuthSec users.id via oidc_user_identities; JIT-create if
//     first time.
//  6. Return the result so the controller can call Hydra accept-login.
//  7. Delete the state row (one-shot).
func (s *FederatedLoginService) HandleOIDCCallback(in HandleOIDCCallbackInput) (*HandleOIDCCallbackResult, error) {
	if in.State == "" || in.Code == "" {
		return nil, errors.New("state and code required")
	}

	// 1. Find the state row. We don't know which tenant DB yet — we have
	// to scan. On real prod with hundreds of tenants this would need a
	// master-side state→tenant index; for now we walk via the
	// resource_server_tenant_index (which we already use for resource_uri
	// lookups) — but state isn't keyed by resource. So actual approach:
	// state_token is globally random enough that we accept the cost of
	// looking it up by trying the tenant DBs we know about.
	//
	// Pragmatic shortcut for the backport: we encoded tenant_id into the
	// state via the oidc_states.workspace_id column. We can't read it
	// without knowing which DB to query. Solution: ask Hydra to round-trip
	// us through the callback with a server-side cookie OR keep the
	// tenant_id as part of the state token itself.
	//
	// Easiest approach: prefix the state_token with the tenant_id as a
	// hex-uuid: "<32hex tenant><32hex random>". Server splits and queries
	// the right DB. Drift-proof and self-contained.
	tenantID, randomToken, ok := splitStateToken(in.State)
	if !ok {
		return nil, errors.New("invalid state format")
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}

	var stateRow models.OIDCState
	if err := tenantDB.Where("state_token = ?", randomToken).First(&stateRow).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("invalid or expired state")
		}
		return nil, err
	}
	if time.Now().After(stateRow.ExpiresAt) {
		return nil, errors.New("state expired")
	}

	// 2. Resolve the provider config.
	var oidcRow struct {
		ID                    uuid.UUID
		ProviderName          string
		ClientID              string
		ClientSecretVaultPath string
		TokenURL              string
		UserinfoURL           string
	}
	if err := tenantDB.Table("oidc_providers").
		Select("id, provider_name, client_id, client_secret_vault_path, token_url, userinfo_url").
		Where("provider_name = ?", stateRow.ProviderName).
		First(&oidcRow).Error; err != nil {
		return nil, fmt.Errorf("load oidc_providers config: %w", err)
	}

	// 3. Fetch client_secret from Vault. Backport pattern: per-tenant
	// per-provider path. Fallback to env var (only safe for shared
	// providers like Google).
	clientSecret, err := s.loadClientSecret(tenantID, oidcRow.ProviderName)
	if err != nil {
		return nil, fmt.Errorf("load client secret: %w", err)
	}

	// 4. Exchange code at upstream token endpoint.
	tokens, err := s.exchangeCode(oidcRow.TokenURL, oidcRow.ClientID, clientSecret,
		in.Code, stateRow.CodeVerifier, in.CallbackURL, oidcRow.ProviderName)
	if err != nil {
		return nil, fmt.Errorf("exchange code: %w", err)
	}

	// 5. Fetch userinfo.
	userInfo, err := s.fetchUserinfo(oidcRow.UserinfoURL, tokens.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("fetch userinfo: %w", err)
	}

	// 6. Resolve AuthSec users.id via oidc_user_identities.
	if stateRow.TenantID == nil {
		return nil, errors.New("state has no tenant_id")
	}
	user, err := s.resolveFederatedUser(tenantDB, *stateRow.TenantID,
		stateRow.ProviderName, userInfo)
	if err != nil {
		return nil, fmt.Errorf("resolve user: %w", err)
	}

	// 7. Delete the state row (one-shot use).
	if err := tenantDB.Delete(&stateRow).Error; err != nil {
		// best effort
		_ = err
	}

	return &HandleOIDCCallbackResult{
		TenantID:       tenantID,
		ApplicationID:  stateRow.ApplicationID,
		LoginChallenge: stateRow.LoginChallenge,
		UserID:         user.ID,
		UserEmail:      user.Email,
		UserName:       user.Name,
		ProviderName:   stateRow.ProviderName,
		AuthMethod:     "oidc_federated",
	}, nil
}

// ─────────────────────────────────────────────────────────────────────────
// SAML
// ─────────────────────────────────────────────────────────────────────────

// SAML on this backport is intentionally narrower than OIDC: we accept the
// SP-initiated POST from /login/saml/initiate, build a SAMLRequest with a
// generic NameIDPolicy + AssertionConsumerService binding, store state,
// and return the RelayState URL the UI navigates to.
//
// The ACS handler at /login/saml/acs accepts the SAMLResponse POST,
// verifies signature against the saml_providers row's certificate, extracts
// NameID + attributes, and runs the same identity-resolution path as OIDC.
//
// Full SAML support requires a SAML XML library (the dev branch uses
// crewjam/saml). The backport's go.mod doesn't currently have it. Rather
// than pulling in a 12k-line XML SAML implementation here, this commit
// stubs the SAML initiate/ACS to return 501 with a clear "SAML federated
// login is not yet supported on this backend" message. Sessions can
// re-enable it by adding the crewjam/saml dependency + filling in the
// stubs. The route shape, request bodies, and JSON responses match what
// a full implementation would emit, so the consuming UI doesn't need to
// change when SAML lands.

// InitiateSAMLInput / HandleSAMLACSInput are placeholders for the
// not-yet-implemented SAML flow.
type InitiateSAMLInput struct {
	TenantID           string
	ApplicationID      uuid.UUID
	IdentityProviderID uuid.UUID
	LoginChallenge     string
	ContextID          string
	CallbackURL        string
}

type InitiateSAMLResponse struct {
	UpstreamSSOURL string
	RelayState     string
	SAMLRequest    string // base64-encoded — the UI POSTs this to the IdP
}

// InitiateSAML returns 501 for now. See package doc above.
func (s *FederatedLoginService) InitiateSAML(in InitiateSAMLInput) (*InitiateSAMLResponse, error) {
	return nil, errors.New("SAML federated login is not yet supported on the prod-mcp-v2 backend; use OIDC or custom-login")
}

type HandleSAMLACSInput struct {
	SAMLResponse string
	RelayState   string
}

type HandleSAMLACSResult struct {
	TenantID       string
	ApplicationID  *uuid.UUID
	LoginChallenge string
	UserID         uuid.UUID
	UserEmail      string
	UserName       string
	ProviderName   string
	AuthMethod     string // "saml_federated"
}

// HandleSAMLACS returns 501 for now. See package doc above.
func (s *FederatedLoginService) HandleSAMLACS(in HandleSAMLACSInput) (*HandleSAMLACSResult, error) {
	return nil, errors.New("SAML federated login is not yet supported on the prod-mcp-v2 backend; use OIDC or custom-login")
}

// ─────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────

// idpAllowedForApplication is the per-Application IDP whitelist gate.
// Same logic the login/page-data handler uses.
func (s *FederatedLoginService) idpAllowedForApplication(
	tenantDB *gorm.DB, tenantID string, applicationID, idpID uuid.UUID,
) (bool, error) {
	var total int64
	if err := tenantDB.Model(&models.ApplicationIdentityProviderPolicy{}).
		Where("application_id = ? AND tenant_id = ?", applicationID, tenantID).
		Count(&total).Error; err != nil {
		return false, err
	}
	if total == 0 {
		return true, nil
	}
	var enabled int64
	if err := tenantDB.Model(&models.ApplicationIdentityProviderPolicy{}).
		Where("application_id = ? AND identity_provider_id = ? AND enabled = true",
			applicationID, idpID).Count(&enabled).Error; err != nil {
		return false, err
	}
	return enabled > 0, nil
}

// loadClientSecret reads the OIDC client_secret from Vault. Pattern is
// (tenant_id, provider_name) → secret. Fallback to env var when Vault
// isn't configured (dev environments).
func (s *FederatedLoginService) loadClientSecret(tenantID, providerName string) (string, error) {
	secrets, err := config.GetProviderSecretFromVault(tenantID, providerName)
	if err == nil {
		if v, ok := secrets["client_secret"].(string); ok && v != "" {
			return v, nil
		}
	}
	// Fallback for shared/system providers in dev environments.
	switch providerName {
	case "google":
		if v := config.AppConfig.GoogleClientSecret; v != "" {
			return v, nil
		}
	case "github":
		if v := config.AppConfig.GitHubClientSecret; v != "" {
			return v, nil
		}
	case "microsoft":
		if v := config.AppConfig.MicrosoftClientSecret; v != "" {
			return v, nil
		}
	}
	return "", fmt.Errorf("no client_secret available for provider %q", providerName)
}

type oidcTokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func (s *FederatedLoginService) exchangeCode(
	tokenURL, clientID, clientSecret, code, codeVerifier, redirectURI, providerName string,
) (*oidcTokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	// GitHub doesn't support PKCE; everyone else does.
	if providerName != "github" && codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token endpoint status %d: %s", resp.StatusCode, body)
	}
	var out oidcTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	return &out, nil
}

type federatedUserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name,omitempty"`
	Picture       string `json:"picture,omitempty"`
}

func (s *FederatedLoginService) fetchUserinfo(userinfoURL, accessToken string) (*federatedUserInfo, error) {
	req, err := http.NewRequest("GET", userinfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("userinfo status %d: %s", resp.StatusCode, body)
	}
	var out federatedUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}
	return &out, nil
}

// resolveFederatedUser looks up a federated identity match for the user
// the upstream IdP just returned.
//
// Resolution order:
//
//  1. oidc_user_identities row matching (tenant, provider, provider_user_id)
//     — the user has logged in via this provider before, just look up the
//     linked ExtendedUser.
//  2. email match against the existing users table — the user already has
//     an AuthSec account (e.g. custom-login signup) and is logging in via
//     a federated provider for the first time. We auto-link by creating
//     an oidc_user_identities row.
//
// We DELIBERATELY do not JIT-create new ExtendedUser rows here. JIT user
// creation requires a clients.id (ExtendedUser.ClientID is NOT NULL) which
// the federated-login flow doesn't carry — it carries an applications.id,
// which is a different concept (resource server, not OAuth client). The
// existing custom-login signup path already handles user creation; users
// must register there first, then federated login picks them up by email.
type federatedUser struct {
	ID    uuid.UUID
	Email string
	Name  string
}

func (s *FederatedLoginService) resolveFederatedUser(
	tenantDB *gorm.DB,
	tenantUUID uuid.UUID,
	providerName string,
	info *federatedUserInfo,
) (*federatedUser, error) {
	// 1. Try existing identity link.
	var existing models.OIDCUserIdentity
	err := tenantDB.Where("tenant_id = ? AND provider_name = ? AND provider_user_id = ?",
		tenantUUID, providerName, info.Sub).First(&existing).Error
	if err == nil {
		var u models.ExtendedUser
		if err := tenantDB.Where("id = ?", existing.UserID).First(&u).Error; err != nil {
			return nil, err
		}
		now := time.Now().UTC()
		_ = tenantDB.Model(&existing).Update("last_login_at", &now).Error
		return &federatedUser{ID: u.ID, Email: u.Email, Name: u.Name}, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	// 2. No identity link. Try email match (same tenant, existing user).
	if info.Email == "" {
		return nil, errors.New("federated provider returned no email and no existing identity link; cannot resolve user")
	}
	var u models.ExtendedUser
	emailErr := tenantDB.Where("LOWER(email) = ? AND tenant_id = ?",
		strings.ToLower(info.Email), tenantUUID).First(&u).Error
	if emailErr != nil {
		if errors.Is(emailErr, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("no AuthSec user found for email %q in this tenant; register via custom-login signup first", info.Email)
		}
		return nil, emailErr
	}
	linkRow := models.OIDCUserIdentity{
		TenantID:       tenantUUID,
		UserID:         u.ID,
		ProviderName:   providerName,
		ProviderUserID: info.Sub,
		Email:          info.Email,
	}
	if err := tenantDB.Create(&linkRow).Error; err != nil {
		return nil, fmt.Errorf("link existing user to federated identity: %w", err)
	}
	return &federatedUser{ID: u.ID, Email: u.Email, Name: u.Name}, nil
}

// federatedRandomToken returns n cryptographically random bytes encoded
// as base64-url-no-padding. Local to the federated service to avoid name
// collision with services/oidc_service.go:generateSecureToken which has
// a slightly different signature.
func federatedRandomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// pkceS256Challenge returns the base64-url-no-padding SHA256 hash of the
// code verifier per RFC 7636.
func pkceS256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// buildStateToken composes the state we send upstream. Format:
//
//	<tenant-uuid-no-dashes>.<random>
//
// Splitting at callback time lets us pick the right tenant DB without
// scanning every tenant. The tenant_uuid is public anyway (it's in our
// JWTs); putting it in the state token isn't a leak.
//
// (Not used during initiate yet — we use the raw stateToken to avoid
// double-encoding. The callback splits via splitStateToken. We compose
// the wire-state value in the controller.)
func buildStateToken(tenantUUID uuid.UUID, randomToken string) string {
	return strings.ReplaceAll(tenantUUID.String(), "-", "") + "." + randomToken
}

// splitStateToken reverses buildStateToken. Returns (tenantID, randomToken, ok).
func splitStateToken(state string) (string, string, bool) {
	idx := strings.IndexByte(state, '.')
	if idx <= 0 || idx == len(state)-1 {
		return "", "", false
	}
	hex32 := state[:idx]
	rest := state[idx+1:]
	if len(hex32) != 32 {
		return "", "", false
	}
	// Reassemble UUID 8-4-4-4-12.
	tenantUUID := hex32[0:8] + "-" + hex32[8:12] + "-" + hex32[12:16] + "-" + hex32[16:20] + "-" + hex32[20:32]
	if _, err := uuid.Parse(tenantUUID); err != nil {
		return "", "", false
	}
	return tenantUUID, rest, true
}
