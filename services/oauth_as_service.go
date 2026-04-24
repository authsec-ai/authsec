package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type OAuthASService struct {
	db        *gorm.DB
	authzCtx  *AuthorizationContextService
	rsService *ResourceServerService
	jwksCache *jwksCache
}

func NewOAuthASService(db *gorm.DB) *OAuthASService {
	return &OAuthASService{
		db:        db,
		authzCtx:  NewAuthorizationContextService(db),
		rsService: NewResourceServerService(db),
		jwksCache: &jwksCache{},
	}
}

// ASMetadata returns the OIDC Discovery / RFC 8414 Authorization Server Metadata.
// This is a superset: OIDC Discovery 1.0 extends RFC 8414 with id_token, userinfo,
// and session management fields. Both /.well-known/openid-configuration and
// /.well-known/oauth-authorization-server serve this same document.
func (s *OAuthASService) ASMetadata(baseURL string) map[string]interface{} {
	return map[string]interface{}{
		// RFC 8414 core
		"issuer":                                        baseURL,
		"authorization_endpoint":                        baseURL + "/oauth/authorize",
		"token_endpoint":                                baseURL + "/oauth/token",
		"registration_endpoint":                         baseURL + "/oauth/register",
		"introspection_endpoint":                        baseURL + "/oauth/introspect",
		"revocation_endpoint":                           baseURL + "/oauth/revoke",
		"jwks_uri":                                      baseURL + "/oauth/jwks",
		"response_types_supported":                      []string{"code"},
		"response_modes_supported":                      []string{"query"},
		"grant_types_supported":                         []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported":         []string{"none"},
		"introspection_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		"revocation_endpoint_auth_methods_supported":    []string{"none"},
		"code_challenge_methods_supported":              []string{"S256"},
		"resource_indicators_supported":                 true,

		// OIDC Discovery 1.0 extensions
		"userinfo_endpoint":                     baseURL + "/oauth/userinfo",
		"end_session_endpoint":                  baseURL + "/oauth/logout",
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
			"email", "email_verified", "name", "preferred_username", "picture",
		},
	}
}

// RegisterDCRClient creates a new OAuth client via Dynamic Client Registration (RFC 7591).
// When the request includes OIDC scopes (openid, offline_access), the Hydra client and
// MCPOAuthClient are configured to support id_token issuance and refresh_token grants.
func (s *OAuthASService) RegisterDCRClient(req DCRRequest, rs *models.ResourceServer) (*models.MCPOAuthClient, error) {
	if rs != nil && !rs.AllowsRegistrationMode("dcr") {
		return nil, fmt.Errorf("resource server does not allow DCR")
	}

	clientID := uuid.New().String()
	hydraClientID := clientID

	// Determine OIDC capabilities from requested scope
	hydraScope, grantTypes, supportsRefresh := resolveOIDCClientCapabilities(req.Scope)

	// Register in Hydra
	err := hydraAdminCreateClient(hydraClient{
		ClientID:      hydraClientID,
		ClientName:    req.ClientName,
		GrantTypes:    grantTypes,
		RedirectURIs:  req.RedirectURIs,
		ResponseTypes: []string{"code"},
		TokenEndpoint: "none",
		Scope:         hydraScope,
	})
	if err != nil {
		return nil, fmt.Errorf("register hydra client for DCR: %w", err)
	}

	client := &models.MCPOAuthClient{
		ClientID:                clientID,
		HydraClientID:           hydraClientID,
		ClientName:              req.ClientName,
		RedirectURIs:            pq.StringArray(req.RedirectURIs),
		GrantTypes:              pq.StringArray(grantTypes),
		ResponseTypes:           pq.StringArray{"code"},
		TokenEndpointAuthMethod: "none",
		Scope:                   req.Scope,
		RegistrationType:        "dcr",
		SupportsRefreshToken:    supportsRefresh,
		PostLogoutRedirectURIs:  pq.StringArray(req.PostLogoutRedirectURIs),
	}

	if err := s.authzCtx.CreateMCPOAuthClient(client); err != nil {
		// Rollback Hydra client
		_ = hydraAdminDeleteClient(hydraClientID)
		return nil, fmt.Errorf("store DCR client: %w", err)
	}

	// When rs is non-nil, bind the client to the RS up-front. When nil, the
	// client is registered unbound; binding is deferred to /authorize, which
	// enforces the resource parameter (RFC 8707) and creates the join row
	// lazily at that point. This accommodates DCR clients (e.g. Claude Code)
	// that follow RFC 7591 strictly and omit `resource` at registration time.
	if rs != nil {
		if _, err := s.authzCtx.EnsureClientRegistration(rs.ID, client.ID, "dcr"); err != nil {
			return nil, fmt.Errorf("create DCR client registration: %w", err)
		}
	}

	return client, nil
}

// GetOAuthClient looks up an MCP OAuth client by its public client_id.
func (s *OAuthASService) GetOAuthClient(clientID string) (*models.MCPOAuthClient, error) {
	return s.authzCtx.GetMCPOAuthClientByClientID(clientID)
}

// GetClientRegistration checks the join table.
func (s *OAuthASService) GetClientRegistration(rsID, clientID uuid.UUID) (*models.ResourceServerClientRegistration, error) {
	return s.authzCtx.GetClientRegistration(rsID, clientID)
}

// EnsureClientRegistration upserts a join row (used by CIMD).
func (s *OAuthASService) EnsureClientRegistration(rsID, clientID uuid.UUID, regType string) (*models.ResourceServerClientRegistration, error) {
	return s.authzCtx.EnsureClientRegistration(rsID, clientID, regType)
}

// StoreAuthRequestContext saves the bridge context before redirecting to Hydra.
func (s *OAuthASService) StoreAuthRequestContext(ctx *models.AuthRequestContext) error {
	return s.authzCtx.StoreAuthRequestContext(ctx)
}

// UpdateAuthRequestContextPAR sets the Hydra request_uri and aligned expiry after PAR.
func (s *OAuthASService) UpdateAuthRequestContextPAR(state, requestURI string, expiresAt time.Time) error {
	return s.authzCtx.UpdateAuthRequestContextPAR(state, requestURI, expiresAt)
}

// ConsumeAuthRequestContext marks context as consumed after token exchange.
func (s *OAuthASService) ConsumeAuthRequestContext(state string) error {
	return s.authzCtx.ConsumeAuthRequestContext(state)
}

// GetAuthRequestContextByContextID looks up auth context by server-generated context_id.
// Requires consent_completed = true AND consumed = false. FAIL CLOSED.
func (s *OAuthASService) GetAuthRequestContextByContextID(contextID string) (*models.AuthRequestContext, error) {
	return s.authzCtx.GetAuthRequestContextByContextID(contextID)
}

// GetActiveAuthRequestContextByHydraRequestURI retrieves a live auth context by Hydra request_uri.
func (s *OAuthASService) GetActiveAuthRequestContextByHydraRequestURI(requestURI string) (*models.AuthRequestContext, error) {
	return s.authzCtx.GetActiveAuthRequestContextByHydraRequestURI(requestURI)
}

// ValidateIntrospectionCredentials checks RS credentials for introspection.
// Dual-read: tries bcrypt hash first, falls back to plaintext for un-migrated rows.
// Opportunistically backfills plaintext → hash on successful legacy validation.
func (s *OAuthASService) ValidateIntrospectionCredentials(rsID, secret string) (*models.ResourceServer, error) {
	rs, err := s.rsService.GetByID(rsID)
	if err != nil {
		return nil, fmt.Errorf("unknown resource server: %w", err)
	}

	// Primary path: bcrypt hash
	if rs.IntrospectionSecretHash != "" {
		if bcryptErr := bcrypt.CompareHashAndPassword([]byte(rs.IntrospectionSecretHash), []byte(secret)); bcryptErr != nil {
			return nil, fmt.Errorf("invalid introspection credentials")
		}
		return rs, nil
	}

	// Legacy path: plaintext comparison + opportunistic backfill
	if rs.IntrospectionSecret != "" {
		if rs.IntrospectionSecret != secret {
			return nil, fmt.Errorf("invalid introspection credentials")
		}
		// Backfill: compute hash, store it, clear plaintext
		hashed, hashErr := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
		if hashErr == nil {
			log.Printf("[MCP_AUTH] ValidateIntrospectionCredentials: backfilling hash for RS %s", rsID)
			s.db.Model(&models.ResourceServer{}).Where("id = ?", rs.ID).Updates(map[string]interface{}{
				"introspection_secret_hash": string(hashed),
				"introspection_secret":      "",
			})
		}
		return rs, nil
	}

	return nil, fmt.Errorf("no credentials configured for resource server")
}

// ProxyToHydraPublic forwards a request to Hydra's public endpoint.
// WARNING: Do NOT use this for POST handlers that call ParseForm() — the body will be drained.
// Use ProxyFormToHydraPublic instead.
func (s *OAuthASService) ProxyToHydraPublic(path string, r *http.Request, w http.ResponseWriter) {
	targetURL := config.AppConfig.HydraPublicURL + path

	var body io.Reader
	if r.Body != nil {
		body = r.Body
	}

	proxyReq, err := http.NewRequest(r.Method, targetURL, body)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	proxyReq.Header = r.Header.Clone()
	if r.URL.RawQuery != "" {
		proxyReq.URL.RawQuery = r.URL.RawQuery
	}

	resp, err := CircuitDoHydra(proxyReq)
	if err != nil {
		http.Error(w, "authorization server unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// ProxyFormToHydraPublic re-encodes the parsed form data and forwards it to Hydra.
// Use this instead of ProxyToHydraPublic when the request body has been drained by ParseForm().
func (s *OAuthASService) ProxyFormToHydraPublic(path string, form url.Values, header http.Header, w http.ResponseWriter) {
	targetURL := config.AppConfig.HydraPublicURL + path
	encoded := form.Encode()

	proxyReq, err := http.NewRequest("POST", targetURL, strings.NewReader(encoded))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	proxyReq.Header = header.Clone()
	proxyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	proxyReq.Header.Del("Content-Length") // let http.Client recompute

	resp, err := CircuitDoHydra(proxyReq)
	if err != nil {
		http.Error(w, "authorization server unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// ProxyFormToHydraPublicCapture re-encodes form data, sends to Hydra, and returns
// the raw response body + status instead of writing directly to the client.
// The caller is responsible for forwarding the response.
func (s *OAuthASService) ProxyFormToHydraPublicCapture(path string, form url.Values, header http.Header) (int, []byte, http.Header, error) {
	targetURL := config.AppConfig.HydraPublicURL + path
	encoded := form.Encode()

	proxyReq, err := http.NewRequest("POST", targetURL, strings.NewReader(encoded))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("create proxy request: %w", err)
	}
	proxyReq.Header = header.Clone()
	proxyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	proxyReq.Header.Del("Content-Length")

	resp, err := CircuitDoHydra(proxyReq)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("hydra unavailable: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, resp.Header, fmt.Errorf("read hydra response: %w", err)
	}

	return resp.StatusCode, body, resp.Header, nil
}

// IntrospectViaHydraAdmin calls Hydra's admin introspection endpoint (no auth needed, internal network only).
// IMPORTANT: The Hydra admin API must NOT be externally reachable — it listens on a separate port
// (typically 4445) that should be firewalled to internal network only.
func (s *OAuthASService) IntrospectViaHydraAdmin(token string) (map[string]interface{}, error) {
	targetURL := config.AppConfig.HydraAdminURL + "/admin/oauth2/introspect"
	form := url.Values{"token": {token}}

	proxyReq, err := http.NewRequest("POST", targetURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create introspect request: %w", err)
	}
	proxyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := CircuitDoHydra(proxyReq)
	if err != nil {
		return nil, fmt.Errorf("hydra admin unavailable: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read introspect response: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse introspect response: %w", err)
	}

	return result, nil
}

// RevokeHydraToken revokes a single token via Hydra's public revocation endpoint.
// Best-effort, fire-and-forget — errors are logged but not returned.
// Prefer RevokeFullTokenSet for post-Hydra rejection paths.
func (s *OAuthASService) RevokeHydraToken(token string) {
	if err := s.revokeOneToken(token); err != nil {
		log.Printf("[MCP_AUTH] RevokeHydraToken: %v", err)
	}
}

// revokeOneToken is the low-level synchronous revocation primitive.
//
// Error semantics:
//   - Transport/circuit-breaker failure → error
//   - Hydra responds with non-200 (e.g. 429 rate-limited, 503 unavailable) → error.
//     RFC 7009 §2.2 requires the revocation endpoint to return HTTP 200 for any
//     successfully processed request, including unknown tokens. A non-200 means the
//     server did not process the revocation; the token may still be live.
//   - Hydra responds with 200 → nil (revocation confirmed)
func (s *OAuthASService) revokeOneToken(token string) error {
	if token == "" {
		return nil
	}
	form := url.Values{"token": {token}}
	targetURL := config.AppConfig.HydraPublicURL + "/oauth2/revoke"
	req, err := http.NewRequest("POST", targetURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("create revoke request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, circuitErr := CircuitDoHydra(req)
	// Always drain and close the body. CircuitDoHydra returns (resp, err) for 5xx
	// responses — the resp is non-nil even in the error path — so the body must be
	// closed regardless of whether circuitErr is set.
	if resp != nil {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
	}
	if circuitErr != nil {
		return fmt.Errorf("Hydra revoke transport/circuit error: %w", circuitErr)
	}
	// Any non-200 status is a revocation failure. 4xx responses (e.g. 429 Too Many
	// Requests) are not caught by the circuit breaker but still indicate the token
	// was not revoked. Return an error so the caller can log the failure and decide
	// the denial policy (always 403 regardless, per plan).
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Hydra revoke returned non-200 status %d", resp.StatusCode)
	}
	return nil
}

// RevokeFullTokenSet revokes both the access token and refresh token (when present)
// via Hydra's public revocation endpoint. Per RFC 7009, revoking a refresh token
// cascades to all associated access tokens for that grant, but we also revoke the
// access token explicitly as a defensive measure for opaque token deployments.
//
// Returns an error if either revocation call fails. The caller is responsible for
// deciding the response to the client — the plan specifies that hard denials
// (RBAC fail, missing context) must return 403 regardless of revocation outcome,
// and revocation errors must be logged but must not change the 403 to a 502.
func (s *OAuthASService) RevokeFullTokenSet(accessToken, refreshToken string) error {
	var errs []error
	// Revoke refresh token first: Hydra cascades this to all associated access tokens.
	if refreshToken != "" {
		if err := s.revokeOneToken(refreshToken); err != nil {
			errs = append(errs, fmt.Errorf("refresh token revoke: %w", err))
		}
	}
	// Also explicitly revoke access token (defensive — catches opaque token deployments
	// where the cascade may not cover the specific access token instance).
	if accessToken != "" {
		if err := s.revokeOneToken(accessToken); err != nil {
			errs = append(errs, fmt.Errorf("access token revoke: %w", err))
		}
	}
	return errors.Join(errs...)
}

// RevokeHydraLoginSession revokes all login sessions for a subject via Hydra admin API.
// Used by RP-initiated logout (OIDC RP-Initiated Logout 1.0).
func (s *OAuthASService) RevokeHydraLoginSession(subject string) error {
	targetURL := config.AppConfig.HydraAdminURL + "/admin/oauth2/auth/sessions/login?subject=" + url.QueryEscape(subject)
	req, err := http.NewRequest("DELETE", targetURL, nil)
	if err != nil {
		return fmt.Errorf("create revoke request: %w", err)
	}
	resp, err := CircuitDoHydra(req)
	if err != nil {
		return fmt.Errorf("hydra admin unavailable: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("hydra returned status %d", resp.StatusCode)
	}
	log.Printf("[MCP_AUTH] RevokeHydraLoginSession: revoked sessions for sub=%s", subject)
	return nil
}

// FetchJWKS returns the cached Hydra JWKS.
func (s *OAuthASService) FetchJWKS() (json.RawMessage, error) {
	return s.jwksCache.get()
}

// ResolveCIMDClient fetches a CIMD document, validates it, and upserts the client.
func (s *OAuthASService) ResolveCIMDClient(cimdURL string) (*models.MCPOAuthClient, error) {
	// Check cache first
	existing, err := s.authzCtx.GetMCPOAuthClientByClientID(cimdURL)
	if err == nil && existing.CIMDCachedAt != nil {
		if time.Since(*existing.CIMDCachedAt) < 5*time.Minute {
			return existing, nil
		}
	}

	// Fetch CIMD document
	cimdMeta, err := fetchCIMDDocument(cimdURL)
	if err != nil {
		// If we have a cached version less than 1 hour old, use it
		if existing != nil && existing.CIMDCachedAt != nil && time.Since(*existing.CIMDCachedAt) < time.Hour {
			return existing, nil
		}
		return nil, fmt.Errorf("fetch CIMD document: %w", err)
	}

	// Validate client_id matches URL
	if cimdMeta.ClientID != cimdURL {
		return nil, fmt.Errorf("CIMD client_id mismatch: document says %q but fetched from %q", cimdMeta.ClientID, cimdURL)
	}

	now := time.Now()

	if existing != nil {
		// Update existing
		existing.ClientName = cimdMeta.ClientName
		redirectsChanged := !stringSlicesEqual([]string(existing.RedirectURIs), cimdMeta.RedirectURIs)
		existing.CIMDCachedAt = &now

		// Bug 10: If redirect URIs changed, stage them for admin review instead of auto-applying.
		if redirectsChanged {
			// Validate structural correctness of incoming URIs before staging.
			// Malformed URIs are rejected here to prevent them from reaching Hydra at approval time.
			if err := validateRedirectURIs(cimdMeta.RedirectURIs); err != nil {
				return nil, fmt.Errorf("CIMD document contains invalid redirect_uri: %w", err)
			}
			existing.PendingRedirectURIs = pq.StringArray(cimdMeta.RedirectURIs)
			existing.RedirectReviewPending = true
			// Do NOT update Hydra client — pending review
			log.Printf("[MCP_AUTH] ResolveCIMDClient: redirect change detected for %s, staged for review", cimdURL)
		}

		if err := s.authzCtx.UpdateMCPOAuthClient(existing); err != nil {
			return nil, fmt.Errorf("update CIMD client: %w", err)
		}
		return existing, nil
	}

	// Create new CIMD client — scope is determined by the CIMD metadata document.
	// Do NOT default to OIDC scopes; CIMD clients opt into OIDC by declaring scopes in their document.

	// Validate redirect URIs structurally before creating the Hydra client.
	if err := validateRedirectURIs(cimdMeta.RedirectURIs); err != nil {
		return nil, fmt.Errorf("CIMD document contains invalid redirect_uri: %w", err)
	}

	hydraClientID := uuid.New().String()
	cimdScope := cimdMeta.Scope // from CIMD document; empty = auth-code-only (MCP default)
	cimdHydraScope, cimdGrantTypes, cimdSupportsRefresh := resolveOIDCClientCapabilities(cimdScope)
	err = hydraAdminCreateClient(hydraClient{
		ClientID:      hydraClientID,
		ClientName:    cimdMeta.ClientName,
		GrantTypes:    cimdGrantTypes,
		RedirectURIs:  cimdMeta.RedirectURIs,
		ResponseTypes: []string{"code"},
		TokenEndpoint: "none",
		Scope:         cimdHydraScope,
	})
	if err != nil {
		return nil, fmt.Errorf("create Hydra client for CIMD: %w", err)
	}

	client := &models.MCPOAuthClient{
		ClientID:                cimdURL,
		HydraClientID:           hydraClientID,
		ClientName:              cimdMeta.ClientName,
		RedirectURIs:            pq.StringArray(cimdMeta.RedirectURIs),
		GrantTypes:              pq.StringArray(cimdGrantTypes),
		ResponseTypes:           pq.StringArray{"code"},
		TokenEndpointAuthMethod: "none",
		Scope:                   cimdScope,
		RegistrationType:        "cimd",
		CIMDUrl:                 cimdURL,
		CIMDCachedAt:            &now,
		SupportsRefreshToken:    cimdSupportsRefresh,
	}

	if err := s.authzCtx.CreateMCPOAuthClient(client); err != nil {
		_ = hydraAdminDeleteClient(hydraClientID)
		return nil, fmt.Errorf("store CIMD client: %w", err)
	}

	return client, nil
}

// PreRegisterClient creates a client + Hydra client + join row with registration_type="prereg".
func (s *OAuthASService) PreRegisterClient(rs *models.ResourceServer, req DCRRequest) (*models.MCPOAuthClient, error) {
	if !rs.AllowsRegistrationMode("prereg") {
		return nil, fmt.Errorf("resource server does not allow pre-registration")
	}

	clientID := uuid.New().String()
	hydraClientID := clientID

	hydraScope, grantTypes, supportsRefresh := resolveOIDCClientCapabilities(req.Scope)

	err := hydraAdminCreateClient(hydraClient{
		ClientID:      hydraClientID,
		ClientName:    req.ClientName,
		GrantTypes:    grantTypes,
		RedirectURIs:  req.RedirectURIs,
		ResponseTypes: []string{"code"},
		TokenEndpoint: "none",
		Scope:         hydraScope,
	})
	if err != nil {
		return nil, fmt.Errorf("register hydra client for prereg: %w", err)
	}

	client := &models.MCPOAuthClient{
		ClientID:                clientID,
		HydraClientID:           hydraClientID,
		ClientName:              req.ClientName,
		RedirectURIs:            pq.StringArray(req.RedirectURIs),
		GrantTypes:              pq.StringArray(grantTypes),
		ResponseTypes:           pq.StringArray{"code"},
		TokenEndpointAuthMethod: "none",
		Scope:                   req.Scope,
		RegistrationType:        "prereg",
		SupportsRefreshToken:    supportsRefresh,
		PostLogoutRedirectURIs:  pq.StringArray(req.PostLogoutRedirectURIs),
	}

	if err := s.authzCtx.CreateMCPOAuthClient(client); err != nil {
		_ = hydraAdminDeleteClient(hydraClientID)
		return nil, fmt.Errorf("store prereg client: %w", err)
	}

	if _, err := s.authzCtx.EnsureClientRegistration(rs.ID, client.ID, "prereg"); err != nil {
		return nil, fmt.Errorf("create prereg client registration: %w", err)
	}

	return client, nil
}

// ListClientsForRS returns all client registrations for a resource server.
func (s *OAuthASService) ListClientsForRS(rsID string) ([]map[string]interface{}, error) {
	rsUUID, err := uuid.Parse(rsID)
	if err != nil {
		return nil, fmt.Errorf("invalid RS ID: %w", err)
	}

	var regs []models.ResourceServerClientRegistration
	if err := s.db.Where("resource_server_id = ?", rsUUID).Find(&regs).Error; err != nil {
		return nil, err
	}

	result := make([]map[string]interface{}, 0, len(regs))
	for _, reg := range regs {
		var client models.MCPOAuthClient
		if err := s.db.Where("id = ?", reg.OAuthClientID).First(&client).Error; err != nil {
			continue
		}
		result = append(result, map[string]interface{}{
			"client_id":         client.ClientID,
			"client_name":       client.ClientName,
			"registration_type": reg.RegistrationType,
			"status":            reg.Status,
		})
	}
	return result, nil
}

// RevokeClientRegistration sets a client's join-table status to "revoked" for an RS.
func (s *OAuthASService) RevokeClientRegistration(rsID, clientID string) error {
	rsUUID, err := uuid.Parse(rsID)
	if err != nil {
		return fmt.Errorf("invalid RS ID: %w", err)
	}

	// Find the MCP client by public client_id
	client, err := s.authzCtx.GetMCPOAuthClientByClientID(clientID)
	if err != nil {
		return fmt.Errorf("client not found: %w", err)
	}

	result := s.db.Model(&models.ResourceServerClientRegistration{}).
		Where("resource_server_id = ? AND oauth_client_id = ?", rsUUID, client.ID).
		Update("status", "revoked")
	if result.RowsAffected == 0 {
		return fmt.Errorf("client registration not found")
	}
	return result.Error
}

// ApprovePendingRedirects copies pending redirect URIs to approved, updates Hydra, clears flag.
func (s *OAuthASService) ApprovePendingRedirects(clientID string) error {
	client, err := s.authzCtx.GetMCPOAuthClientByClientID(clientID)
	if err != nil {
		return fmt.Errorf("client not found: %w", err)
	}

	if !client.RedirectReviewPending {
		return fmt.Errorf("no pending redirect changes")
	}

	// Validate staged redirect URIs structurally before promoting to Hydra.
	// (They were validated when staged but re-validate here as a defence-in-depth.)
	if err := validateRedirectURIs([]string(client.PendingRedirectURIs)); err != nil {
		return fmt.Errorf("pending redirect URIs are invalid: %w", err)
	}

	// Copy pending → approved
	client.RedirectURIs = client.PendingRedirectURIs
	client.PendingRedirectURIs = nil
	client.RedirectReviewPending = false

	// Update Hydra client — preserve OIDC capabilities
	hydraScope, grantTypes, _ := resolveOIDCClientCapabilities(client.Scope)
	err = hydraAdminUpdateClient(client.HydraClientID, hydraClient{
		ClientID:      client.HydraClientID,
		ClientName:    client.ClientName,
		GrantTypes:    grantTypes,
		RedirectURIs:  []string(client.RedirectURIs),
		ResponseTypes: []string{"code"},
		TokenEndpoint: "none",
		Scope:         hydraScope,
	})
	if err != nil {
		return fmt.Errorf("update Hydra client redirects: %w", err)
	}

	return s.authzCtx.UpdateMCPOAuthClient(client)
}

// --- DCR Request/Response types ---

type DCRRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Resource                string   `json:"resource"`
	Scope                   string   `json:"scope"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris,omitempty"`
}

type DCRResponse struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Resource                string   `json:"resource"`
	Scope                   string   `json:"scope,omitempty"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris,omitempty"`
}

// resolveOIDCClientCapabilities determines Hydra client scope and grant types based on
// the requested scope string. Returns (hydraScope, grantTypes, supportsRefreshToken).
func resolveOIDCClientCapabilities(scope string) (string, []string, bool) {
	grantTypes := []string{"authorization_code"}
	supportsRefresh := false

	if scope == "" {
		return "", grantTypes, false
	}

	// Filter to only OIDC core scopes for the Hydra client
	var hydraScopes []string
	for _, s := range strings.Fields(scope) {
		if IsOIDCCoreScope(s) {
			hydraScopes = append(hydraScopes, s)
		}
		if s == "offline_access" {
			supportsRefresh = true
		}
	}

	if supportsRefresh {
		grantTypes = append(grantTypes, "refresh_token")
	}

	return strings.Join(hydraScopes, " "), grantTypes, supportsRefresh
}

// --- CIMD types ---

type cimdDocument struct {
	ClientID     string   `json:"client_id"`
	ClientName   string   `json:"client_name"`
	LogoURI      string   `json:"logo_uri,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	Scope        string   `json:"scope,omitempty"` // OIDC scopes the client opts into (e.g. "openid profile email")
}

// blockedCIDRs is the set of IP ranges that CIMD fetch must never reach.
// Covers loopback, RFC 1918 private, link-local (cloud metadata endpoints),
// IPv6 ULA, unspecified, and shared address space (RFC 6598).
var blockedCIDRs = mustParseCIDRs([]string{
	"127.0.0.0/8",    // loopback IPv4
	"::1/128",        // loopback IPv6
	"10.0.0.0/8",     // RFC 1918
	"172.16.0.0/12",  // RFC 1918
	"192.168.0.0/16", // RFC 1918
	"169.254.0.0/16", // link-local / cloud metadata (AWS 169.254.169.254, Azure, GCP)
	"fd00::/8",       // IPv6 ULA
	"0.0.0.0/8",      // unspecified
	"100.64.0.0/10",  // shared address space (RFC 6598)
})

func mustParseCIDRs(cidrs []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("invalid CIDR %q: %v", cidr, err))
		}
		out = append(out, network)
	}
	return out
}

func isBlockedIP(ip net.IP) bool {
	for _, network := range blockedCIDRs {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// fetchCIMDDocument fetches and parses a CIMD metadata document from an HTTPS URL.
// SSRF protection: resolves DNS before dialing and re-checks resolved IPs at connect
// time (anti-rebinding). Rejects any URL that resolves to a reserved/private IP.
func fetchCIMDDocument(cimdURL string) (*cimdDocument, error) {
	parsed, err := url.Parse(cimdURL)
	if err != nil || parsed.Scheme != "https" {
		return nil, fmt.Errorf("CIMD URL must be HTTPS: %s", cimdURL)
	}

	hostname := parsed.Hostname()

	// Pre-resolve DNS and validate all returned IPs before opening a connection.
	addrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), hostname)
	if err != nil {
		return nil, fmt.Errorf("CIMD DNS resolution failed for %s: %w", hostname, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("CIMD URL %s resolved to no addresses", hostname)
	}
	for _, addr := range addrs {
		if isBlockedIP(addr.IP) {
			return nil, fmt.Errorf("CIMD URL %s resolves to a reserved address (%s)", cimdURL, addr.IP)
		}
	}

	// Custom transport: re-checks the resolved IP at dial time to prevent DNS rebinding
	// (time-of-check / time-of-use gap between the pre-resolution above and connect).
	baseDialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				return nil, fmt.Errorf("invalid dial address %q: %w", address, splitErr)
			}
			ips, lookupErr := net.DefaultResolver.LookupIPAddr(ctx, host)
			if lookupErr != nil {
				return nil, fmt.Errorf("CIMD dial DNS failed: %w", lookupErr)
			}
			for _, ip := range ips {
				if isBlockedIP(ip.IP) {
					return nil, fmt.Errorf("CIMD connect blocked: resolved to reserved IP %s", ip.IP)
				}
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("CIMD dial: no addresses for %s", host)
			}
			return baseDialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		},
	}
	httpClient := &http.Client{Timeout: 10 * time.Second, Transport: transport}

	resp, err := httpClient.Get(cimdURL)
	if err != nil {
		return nil, fmt.Errorf("fetch CIMD: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CIMD fetch status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read CIMD body: %w", err)
	}

	var doc cimdDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse CIMD: %w", err)
	}

	return &doc, nil
}

// validateRedirectURIs checks redirect URIs for structural correctness before Hydra sync.
//
// Redirect URIs are callback identifiers — the AS never fetches them server-side during
// the OAuth flow, so SSRF IP-blocklists do NOT apply here. Validation is structural only:
// absolute URL, no fragment, https scheme (or http for localhost in dev).
func validateRedirectURIs(uris []string) error {
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil || !u.IsAbs() {
			return fmt.Errorf("redirect URI must be an absolute URL: %q", raw)
		}
		if u.Fragment != "" {
			return fmt.Errorf("redirect URI must not contain a fragment: %q", raw)
		}
		if u.Scheme != "https" {
			// Allow http only for localhost (existing repo policy for dev convenience).
			// url.Hostname() strips brackets, so IPv6 loopback arrives as "::1" not "[::1]".
			host := u.Hostname()
			if u.Scheme != "http" || (host != "localhost" && host != "127.0.0.1" && host != "::1") {
				return fmt.Errorf("redirect URI must use https (or http for localhost): %q", raw)
			}
		}
	}
	return nil
}

// --- JWKS cache ---

type jwksCache struct {
	mu        sync.RWMutex
	data      json.RawMessage
	fetchedAt time.Time
}

func (c *jwksCache) get() (json.RawMessage, error) {
	c.mu.RLock()
	if c.data != nil && time.Since(c.fetchedAt) < 5*time.Minute {
		data := c.data
		c.mu.RUnlock()
		return data, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if c.data != nil && time.Since(c.fetchedAt) < 5*time.Minute {
		return c.data, nil
	}

	jwksURL := config.AppConfig.HydraPublicURL + "/.well-known/jwks.json"
	httpClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := httpClient.Get(jwksURL)
	if err != nil {
		if c.data != nil {
			return c.data, nil // stale cache is better than error
		}
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read JWKS: %w", err)
	}

	c.data = json.RawMessage(body)
	c.fetchedAt = time.Now()
	return c.data, nil
}

// EnrichUserinfoClaims enriches session-based claims with data from the local user table and
// OIDC identity repository. Falls back to session claims if DB lookups fail (graceful degradation).
// The sub may be a UUID (AdminUser.ID) or a composite like "google-<providerUserID>".
func (s *OAuthASService) EnrichUserinfoClaims(claims map[string]interface{}, sub string, scopeSet map[string]bool) {
	if sub == "" {
		return
	}

	// Try to load user by UUID (email/password logins use AdminUser.ID as sub)
	userID, parseErr := uuid.Parse(sub)
	if parseErr != nil {
		// sub is not a UUID — could be a social login composite ID like "google-email-abc123".
		// Session claims are sufficient for these; no local user row to enrich from.
		return
	}

	var user models.AdminUser
	if err := s.db.Where("id = ?", userID).First(&user).Error; err != nil {
		log.Printf("[MCP_AUTH] EnrichUserinfoClaims: user lookup failed sub=%s: %v", sub, err)
		return
	}

	// Enrich profile claims if not already set by session
	if scopeSet["profile"] {
		if _, exists := claims["name"]; !exists && user.Name != "" {
			claims["name"] = user.Name
		}
		if _, exists := claims["preferred_username"]; !exists && user.Username != "" {
			claims["preferred_username"] = user.Username
		}
		if _, exists := claims["picture"]; !exists && user.AvatarURL != "" {
			claims["picture"] = user.AvatarURL
		}
		if !user.UpdatedAt.IsZero() {
			claims["updated_at"] = user.UpdatedAt.Unix()
		}
	}

	if scopeSet["email"] {
		if _, exists := claims["email"]; !exists && user.Email != "" {
			claims["email"] = user.Email
		}
	}

	// Load most recent OIDC identity for federated claims
	if user.TenantID != nil {
		var identity models.OIDCUserIdentity
		err := s.db.Where("user_id = ? AND tenant_id = ?", userID, *user.TenantID).
			Order("last_login_at DESC NULLS LAST").
			First(&identity).Error
		if err == nil && identity.ProfileData != "" {
			// Parse the JSONB profile_data for additional claims
			var profileData map[string]interface{}
			if jsonErr := json.Unmarshal([]byte(identity.ProfileData), &profileData); jsonErr == nil {
				// Merge federated claims that aren't already set
				if scopeSet["email"] {
					if _, exists := claims["email_verified"]; !exists {
						if ev, ok := profileData["email_verified"]; ok {
							claims["email_verified"] = ev
						}
					}
				}
				if scopeSet["profile"] {
					if _, exists := claims["given_name"]; !exists {
						if v, ok := profileData["given_name"].(string); ok && v != "" {
							claims["given_name"] = v
						}
					}
					if _, exists := claims["family_name"]; !exists {
						if v, ok := profileData["family_name"].(string); ok && v != "" {
							claims["family_name"] = v
						}
					}
					if _, exists := claims["locale"]; !exists {
						if v, ok := profileData["locale"].(string); ok && v != "" {
							claims["locale"] = v
						}
					}
				}
			}
		}
	}
}

// VerifyIDTokenHint verifies an id_token JWT signature against the AS JWKS and returns the
// "sub" claim. Used by EndSession to securely identify the subject for session revocation.
// Unlike introspection (which is for access tokens), this validates the id_token signature directly.
func (s *OAuthASService) VerifyIDTokenHint(idToken, expectedIssuer, expectedAudience string) (string, error) {
	jwksData, err := s.jwksCache.get()
	if err != nil {
		return "", fmt.Errorf("fetch JWKS for id_token verification: %w", err)
	}

	// Parse JWKS
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(jwksData, &jwks); err != nil {
		return "", fmt.Errorf("parse JWKS: %w", err)
	}

	// Build a map of kid → RSA public key
	keyMap := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 + int(b)
		}
		keyMap[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}
	}

	// Parse and verify the JWT
	token, err := jwt.Parse(idToken, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			// No kid — try the first available key
			for _, k := range keyMap {
				return k, nil
			}
			return nil, fmt.Errorf("no RSA keys in JWKS")
		}
		key, ok := keyMap[kid]
		if !ok {
			return nil, fmt.Errorf("kid %q not found in JWKS", kid)
		}
		return key, nil
	}, jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}))
	if err != nil {
		return "", fmt.Errorf("id_token verification failed: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", fmt.Errorf("invalid id_token claims")
	}

	if expectedIssuer != "" {
		iss, _ := claims["iss"].(string)
		if iss != expectedIssuer {
			return "", fmt.Errorf("id_token issuer mismatch")
		}
	}

	if expectedAudience != "" && !audienceContains(claims["aud"], expectedAudience) {
		return "", fmt.Errorf("id_token audience mismatch")
	}

	expUnix, ok := numericClaimToInt64(claims["exp"])
	if !ok {
		return "", fmt.Errorf("id_token missing exp claim")
	}
	if time.Unix(expUnix, 0).Before(time.Now()) {
		return "", fmt.Errorf("id_token expired")
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", fmt.Errorf("id_token missing sub claim")
	}
	return sub, nil
}

func audienceContains(raw interface{}, expected string) bool {
	switch v := raw.(type) {
	case string:
		return v == expected
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && s == expected {
				return true
			}
		}
	case []string:
		for _, item := range v {
			if item == expected {
				return true
			}
		}
	}
	return false
}

func numericClaimToInt64(raw interface{}) (int64, bool) {
	switch v := raw.(type) {
	case float64:
		return int64(v), true
	case float32:
		return int64(v), true
	case int64:
		return v, true
	case int32:
		return int64(v), true
	case int:
		return int64(v), true
	case json.Number:
		n, err := v.Int64()
		return n, err == nil
	}
	return 0, false
}

// --- Helpers ---

func IsHTTPSURL(s string) bool {
	return strings.HasPrefix(s, "https://")
}

func generateClientID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]bool, len(a))
	for _, s := range a {
		m[s] = true
	}
	for _, s := range b {
		if !m[s] {
			return false
		}
	}
	return true
}
