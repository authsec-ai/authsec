package azure

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AppConfig is AuthSec's ONE multi-tenant Entra app registration, shared by
// every customer. It is deployment configuration (AZURE_AUTHSEC_* env vars),
// never per-workspace data: a customer authorizes this application in their
// own tenant, and admin consent creates their tenant's service principal of it.
type AppConfig struct {
	ClientID     string
	ClientSecret string
	// HomeTenantID is the tenant that owns the registration. OPTIONAL: no
	// token is ever requested from it. When set, a customer's service
	// principal of the app must name it as appOwnerOrganizationId -- a
	// deployment-misconfiguration check, not a security boundary.
	HomeTenantID string
	// RedirectURI must be registered on the app (Web platform) exactly.
	RedirectURI string
}

// AppConfigFromEnv reads the registration from AZURE_AUTHSEC_CLIENT_ID,
// AZURE_AUTHSEC_CLIENT_SECRET, AZURE_AUTHSEC_TENANT_ID (optional) and
// AZURE_REDIRECT_URI. Read at each use rather than cached, so the secret lives
// only in the environment.
func AppConfigFromEnv() AppConfig {
	return AppConfig{
		ClientID:     strings.TrimSpace(os.Getenv("AZURE_AUTHSEC_CLIENT_ID")),
		ClientSecret: strings.TrimSpace(os.Getenv("AZURE_AUTHSEC_CLIENT_SECRET")),
		HomeTenantID: strings.ToLower(strings.TrimSpace(os.Getenv("AZURE_AUTHSEC_TENANT_ID"))),
		RedirectURI:  strings.TrimSpace(os.Getenv("AZURE_REDIRECT_URI")),
	}
}

// Configured reports whether every field needed by the flow is present.
// HomeTenantID is not one of them.
func (c AppConfig) Configured() bool {
	return c.ClientID != "" && c.ClientSecret != "" && c.RedirectURI != ""
}

// AuthRef is the non-secret handle stored on cloud_connector.auth_ref: the
// application the connector authenticates as. The secret itself stays in the
// deployment environment and is never written to the database.
func (c AppConfig) AuthRef() string { return "azure-app:" + c.ClientID }

const (
	// ScopeARMDelegated asks for the signed-in administrator's own Azure
	// Resource Manager access, so AuthSec can create Reader assignments as
	// them. offline_access is deliberately absent: no refresh token is ever
	// issued, so nothing long-lived exists to store or leak.
	ScopeARMDelegated = ARMEndpoint + "/user_impersonation openid profile"
	// ScopeARMApp and ScopeGraphApp are AuthSec's own app-only scopes.
	ScopeARMApp   = ARMEndpoint + "/.default"
	ScopeGraphApp = GraphEndpoint + "/.default"
)

var guidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// IsGUID reports whether s is a canonical GUID (tenant, subscription and
// object ids all are).
func IsGUID(s string) bool { return guidRe.MatchString(s) }

// tenantHintRe accepts a GUID or a verified-domain style name
// (contoso.onmicrosoft.com, contoso.com).
var tenantHintRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}\.)+[A-Za-z]{2,63}$`)

// ValidTenantHint reports whether hint may be placed in an authority URL path.
func ValidTenantHint(hint string) bool {
	return IsGUID(hint) || tenantHintRe.MatchString(hint)
}

// AdminConsentURL is leg 1: tenant-wide admin consent for every permission
// statically configured on the app registration -- the three Graph application
// permissions and the Azure Service Management delegated permission. Granting
// it creates the customer's service principal of the AuthSec app.
//
// The /adminconsent endpoint is used rather than /authorize?prompt=admin_consent,
// which the v2.0 endpoint rejects (AADSTS901001). Microsoft answers on the
// redirect URI with admin_consent=True&tenant=<guid>&state, or error=...
//
// tenantHint may be "" ("common": the admin's own work account decides).
func AdminConsentURL(cfg AppConfig, state, tenantHint string) string {
	authority := "common"
	if tenantHint != "" {
		authority = tenantHint
	}
	q := url.Values{}
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", cfg.RedirectURI)
	q.Set("state", state)
	return AuthorityHost + "/" + url.PathEscape(authority) + "/adminconsent?" + q.Encode()
}

// SignInURL is leg 2: an authorization-code + PKCE sign-in AGAINST THE
// CONSENTED TENANT, asking for the administrator's delegated ARM access. The
// account picker is always shown, so an admin signed into several directories
// chooses deliberately.
func SignInURL(cfg AppConfig, tenantID, state, codeChallenge, loginHint string) string {
	q := url.Values{}
	q.Set("client_id", cfg.ClientID)
	q.Set("response_type", "code")
	q.Set("response_mode", "query")
	q.Set("redirect_uri", cfg.RedirectURI)
	q.Set("scope", ScopeARMDelegated)
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("prompt", "select_account")
	if loginHint != "" {
		q.Set("login_hint", loginHint)
	}
	return AuthorityHost + "/" + url.PathEscape(tenantID) + "/oauth2/v2.0/authorize?" + q.Encode()
}

func tokenURL(tenantID string) string {
	return AuthorityHost + "/" + url.PathEscape(tenantID) + "/oauth2/v2.0/token"
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// DelegatedToken is the signed-in administrator's one-shot ARM access, plus
// the identity facts AuthSec derives from the id_token.
type DelegatedToken struct {
	AccessToken string
	ExpiresAt   time.Time
	// TenantID is the tid claim. THIS, not the tenant= query parameter on
	// the consent redirect, is the tenant AuthSec trusts: it comes from a
	// server-to-server token response, while the query parameter passes
	// through the browser and can be edited.
	TenantID string
	ObjectID string
	Username string
}

// idTokenClaims are the id_token claims AuthSec reads.
type idTokenClaims struct {
	TenantID          string `json:"tid"`
	ObjectID          string `json:"oid"`
	PreferredUsername string `json:"preferred_username"`
	jwt.RegisteredClaims
}

// ExchangeCode redeems leg 2's authorization code at the tenant's token
// endpoint, with AuthSec's client secret and the PKCE verifier.
func (c *Client) ExchangeCode(ctx context.Context, cfg AppConfig, tenantID, code, verifier string) (*DelegatedToken, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", cfg.ClientID)
	form.Set("client_secret", cfg.ClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", cfg.RedirectURI)
	form.Set("code_verifier", verifier)
	form.Set("scope", ScopeARMDelegated)

	var tr tokenResponse
	if _, err := c.do(ctx, "login", http.MethodPost, tokenURL(tenantID), "", form, nil, &tr); err != nil {
		return nil, err
	}
	if tr.AccessToken == "" || tr.IDToken == "" {
		return nil, fmt.Errorf("%w: the token response carried no access or id token", ErrSignInFailed)
	}
	claims, err := parseIDToken(tr.IDToken, cfg.ClientID)
	if err != nil {
		return nil, err
	}
	return &DelegatedToken{
		AccessToken: tr.AccessToken,
		ExpiresAt:   time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second),
		TenantID:    strings.ToLower(claims.TenantID),
		ObjectID:    strings.ToLower(claims.ObjectID),
		Username:    claims.PreferredUsername,
	}, nil
}

// parseIDToken reads the id_token returned by ExchangeCode.
//
// The signature is not verified, and that is the OIDC Core 3.1.3.7 rule rather
// than a shortcut: the token arrived over TLS directly from Microsoft's token
// endpoint, in response to a request authenticated with AuthSec's own client
// secret, so the TLS server check is the issuer check. Audience, issuer and
// expiry are still checked, because a token that is genuine but meant for
// someone else is the failure that check exists for.
func parseIDToken(raw, clientID string) (*idTokenClaims, error) {
	var claims idTokenClaims
	if _, _, err := jwt.NewParser().ParseUnverified(raw, &claims); err != nil {
		return nil, fmt.Errorf("%w: unreadable id token", ErrSignInFailed)
	}
	audOK := false
	for _, a := range claims.Audience {
		if strings.EqualFold(a, clientID) {
			audOK = true
		}
	}
	if !audOK {
		return nil, fmt.Errorf("%w: the id token was issued to a different application", ErrSignInFailed)
	}
	if !IsGUID(claims.TenantID) || !IsGUID(claims.ObjectID) {
		return nil, fmt.Errorf("%w: the id token carries no tenant or object id", ErrSignInFailed)
	}
	wantIss := AuthorityHost + "/" + strings.ToLower(claims.TenantID) + "/v2.0"
	if !strings.EqualFold(claims.Issuer, wantIss) {
		return nil, fmt.Errorf("%w: unexpected id token issuer", ErrSignInFailed)
	}
	if claims.ExpiresAt == nil || time.Now().After(claims.ExpiresAt.Time) {
		return nil, fmt.Errorf("%w: the id token has expired", ErrSignInFailed)
	}
	return &claims, nil
}

// AppToken is AuthSec's own client-credentials token in the customer tenant,
// for scope ScopeGraphApp or ScopeARMApp. It succeeds only once admin consent
// has created the AuthSec service principal there.
func (c *Client) AppToken(ctx context.Context, cfg AppConfig, tenantID, scope string) (string, error) {
	return c.appToken(ctx, cfg, tenantID, scope)
}
