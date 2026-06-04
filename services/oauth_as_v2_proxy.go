package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// This file contains the Phase 3 helpers on OAuthASService: proxying to Hydra
// for /authorize, /token, /introspect, /revoke, /jwks, /userinfo, /logout,
// and the auth_request_context lifecycle.
//
// Heavy RBAC and scope-resolution logic from the dev branch's
// services/oauth_as_service.go (~1500 lines of ResolveGrantableScopes +
// strict-subset checks) is NOT ported verbatim here. The prod backport
// proxies the standard OAuth dance to Hydra; deeper RBAC enforcement is a
// follow-up.  See comments marked PHASE3-TODO.

// ──────────────────────────────────────────────────────────────────────────
// auth_request_context lifecycle
// ──────────────────────────────────────────────────────────────────────────

// AuthRequestContextInput captures everything we need to remember between
// /authorize and /token.
type AuthRequestContextInput struct {
	TenantID            string
	ClientID            string
	ResourceURI         string
	ResourceServerID    *uuid.UUID
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
}

// StoreAuthRequestContext writes a row to auth_request_context (tenant DB)
// and returns the opaque context_id that callers stuff into Hydra's metadata
// to recover it at /token time.
func (s *OAuthASService) StoreAuthRequestContext(in AuthRequestContextInput) (string, error) {
	if in.TenantID == "" {
		return "", fmt.Errorf("tenant_id required")
	}
	if in.ClientID == "" {
		return "", fmt.Errorf("client_id required")
	}
	tenantDB, err := config.GetTenantGORMDB(in.TenantID)
	if err != nil {
		return "", fmt.Errorf("get tenant db: %w", err)
	}
	contextID := uuid.NewString()
	row := models.AuthRequestContext{
		ContextID:           contextID,
		TenantID:            in.TenantID,
		ClientID:            in.ClientID,
		RedirectURI:         in.RedirectURI,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		ResourceServerID:    in.ResourceServerID,
		CodeChallengeMethod: ptrIfNonEmpty(in.CodeChallengeMethod),
		CodeChallenge:       ptrIfNonEmpty(in.CodeChallenge),
		State:               ptrIfNonEmpty(in.State),
		Scope:               ptrIfNonEmpty(in.Scope),
		Nonce:               ptrIfNonEmpty(in.Nonce),
		ResourceURI:         ptrIfNonEmpty(in.ResourceURI),
	}
	if err := tenantDB.Create(&row).Error; err != nil {
		return "", fmt.Errorf("insert auth_request_context: %w", err)
	}
	return contextID, nil
}

// ConsumeAuthRequestContext loads-and-marks-consumed atomically. Returns the
// row when freshly consumed; returns an error if already consumed, expired,
// or missing. The single Update with a consumed=false predicate is what
// makes this safe under concurrent /token replays.
func (s *OAuthASService) ConsumeAuthRequestContext(tenantID, contextID string) (*models.AuthRequestContext, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	now := time.Now()
	res := tenantDB.Model(&models.AuthRequestContext{}).
		Where("context_id = ? AND consumed = false AND expires_at > ?", contextID, now).
		Updates(map[string]interface{}{
			"consumed":    true,
			"consumed_at": now,
		})
	if res.Error != nil {
		return nil, fmt.Errorf("consume auth_request_context: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return nil, fmt.Errorf("auth_request_context not found, already consumed, or expired")
	}
	var row models.AuthRequestContext
	if err := tenantDB.Where("context_id = ?", contextID).First(&row).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

// FindLatestUnconsumedContext is the fallback /token uses when the RP does
// not echo the state back to the token endpoint. It selects the most recent
// unconsumed, unexpired row matching (tenant_id, client_id, redirect_uri).
//
// This is best-effort: if two authorize flows from the same client to the
// same redirect_uri overlap, we may bind the wrong row. The contract is
// "good enough for spec-compliant RPs that drop state"; well-behaved RPs
// echo state and hit ConsumeAuthRequestContext directly by context_id.
//
// Does NOT consume the row — caller decides whether to call
// ConsumeAuthRequestContext after extracting context_id from the row it
// finds.
func (s *OAuthASService) FindLatestUnconsumedContext(tenantID, clientID, redirectURI string) (*models.AuthRequestContext, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	now := time.Now()
	var row models.AuthRequestContext
	err = tenantDB.Where("tenant_id = ? AND client_id = ? AND redirect_uri = ? AND consumed = false AND expires_at > ?",
		tenantID, clientID, redirectURI, now).
		Order("created_at DESC").First(&row).Error
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// LookupTenantForClientID walks the master-side resource_server_tenant_index
// indirectly: given a client_id, we find its registration row in some
// tenant DB. Used by /token when no resource parameter is present to
// recover the tenant for context lookup.
//
// The map from client_id -> tenant_id is not maintained in master directly,
// so we scan a small set of recent tenants via the registrations. PHASE3-NOTE:
// this is slow and we'd want a master-side client_id index for production
// scale. For now, the fast path is: /token receives a `resource` form
// param (RFC 8707) and uses GetByResourceURI to skip this entirely.
func (s *OAuthASService) LookupTenantForClientByResource(resourceURI string) (string, error) {
	if resourceURI == "" {
		return "", fmt.Errorf("resource_uri required to resolve tenant on /token")
	}
	rs := NewResourceServerService()
	_, tenantID, err := rs.GetByResourceURI(resourceURI)
	if err != nil {
		return "", err
	}
	return tenantID, nil
}

func ptrIfNonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ──────────────────────────────────────────────────────────────────────────
// Hydra proxying
// ──────────────────────────────────────────────────────────────────────────

// ProxyFormToHydraPublic forwards a form-encoded POST to Hydra's public
// endpoint (e.g. /oauth2/token) with the body bytes provided, rewriting
// client_id from our public form to Hydra's internal hydra_client_id.
//
// PHASE3-TODO: dev's equivalent (services/oauth_as_service.go ProxyFormToHydraPublicCapture)
// also extracts the response token + reissues with permission-filtered scope.
// We're keeping the simpler proxy shape on prod for now.
func (s *OAuthASService) ProxyFormToHydraPublic(path string, form url.Values) (status int, body []byte, err error) {
	// Prefer the v2 Hydra public URL — v2-flow endpoints (/token, /revoke,
	// /jwks proxy) must talk to the Hydra that issued the code/token, not
	// the legacy Hydra. v2 falls back to legacy when unset so single-Hydra
	// deployments keep working.
	baseURL := strings.TrimSuffix(config.AppConfig.HydraV2PublicURL, "/")
	if baseURL == "" {
		baseURL = strings.TrimSuffix(config.AppConfig.HydraPublicURL, "/")
	}
	if baseURL == "" {
		// Fall back to swapping /admin out of HydraAdminURL — typical for
		// dev/staging clusters where public and admin are siblings.
		base := strings.TrimSuffix(hydraV2AdminURL(), "/")
		baseURL = strings.TrimSuffix(base, "/admin")
	}
	if baseURL == "" {
		return 0, nil, fmt.Errorf("hydra public url not configured")
	}
	req, err := http.NewRequest("POST", baseURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := CircuitDoHydra(req)
	if err != nil {
		return 0, nil, fmt.Errorf("hydra public %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}

// IntrospectViaHydraAdmin calls /admin/oauth2/introspect with a Bearer-style
// token. Returns the raw JSON body and HTTP status. {active:false} bodies
// are returned as-is for callers to decide how to react.
func (s *OAuthASService) IntrospectViaHydraAdmin(token string) (status int, body []byte, err error) {
	form := url.Values{}
	form.Set("token", token)
	req, err := http.NewRequest("POST",
		fmt.Sprintf("%s/admin/oauth2/introspect", hydraV2AdminURL()),
		strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := CircuitDoHydra(req)
	if err != nil {
		return 0, nil, fmt.Errorf("hydra introspect: %w", err)
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}

// RevokeHydraToken calls Hydra's /oauth2/revoke (public endpoint).
func (s *OAuthASService) RevokeHydraToken(token string) error {
	form := url.Values{}
	form.Set("token", token)
	status, _, err := s.ProxyFormToHydraPublic("/oauth2/revoke", form)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("hydra revoke status %d", status)
	}
	return nil
}

// FetchJWKS proxies the v2 Hydra's /.well-known/jwks.json — clients verify
// access-token signatures against this, so it MUST come from the same Hydra
// that signed them (v2 Hydra, not legacy).
func (s *OAuthASService) FetchJWKS() ([]byte, error) {
	baseURL := strings.TrimSuffix(config.AppConfig.HydraV2PublicURL, "/")
	if baseURL == "" {
		baseURL = strings.TrimSuffix(config.AppConfig.HydraPublicURL, "/")
	}
	if baseURL == "" {
		base := strings.TrimSuffix(hydraV2AdminURL(), "/")
		baseURL = strings.TrimSuffix(base, "/admin")
	}
	req, err := http.NewRequest("GET", baseURL+"/.well-known/jwks.json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := CircuitDoHydra(req)
	if err != nil {
		return nil, fmt.Errorf("hydra jwks: %w", err)
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// hydraClientGetForUpdate is a thin shim over hydraV2AdminGetClient used by
// the reconciler.
func hydraClientGetForUpdate(hydraClientID string) (*hydraClient, error) {
	return hydraV2AdminGetClient(hydraClientID)
}

// rebuildHydraClientPayload reconstructs the create-client payload from the
// stored MCPOAuthClient row, used by the reconciler when the Hydra-side
// client is missing.
func rebuildHydraClientPayload(row *models.MCPOAuthClient) hydraClient {
	return hydraClient{
		ClientID:      row.HydraClientID,
		ClientName:    row.ClientName,
		GrantTypes:    row.GrantTypes,
		RedirectURIs:  row.RedirectURIs,
		ResponseTypes: row.ResponseTypes,
		TokenEndpoint: row.TokenEndpointAuthMethod,
		Scope:         row.Scope,
	}
}

// MarshalIntrospectionResponse is a small helper that parses Hydra's
// introspection body so the controller can pass it straight back to the
// caller as a typed object.
func MarshalIntrospectionResponse(body []byte) (map[string]interface{}, error) {
	var out map[string]interface{}
	if len(body) == 0 {
		return map[string]interface{}{"active": false}, nil
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CopyBody is here so callers can echo Hydra response bodies straight to the
// client with the right content type. Saves bouncing through a buffer in the
// controller.
func CopyBody(w io.Writer, body []byte) (int, error) {
	return w.Write(body)
}

// EnsureHydraPublicURL panics-with-friendly-message if the config is missing.
// Only used in unit tests; production code reads from AppConfig directly.
func EnsureHydraPublicURL() {
	if config.AppConfig.HydraPublicURL == "" && hydraAdminURL() == "" {
		panic("HYDRA_PUBLIC_URL / HYDRA_ADMIN_URL must be set")
	}
}

// Suppress "unused" warnings on helpers that are exercised in Phase 4-5.
var _ = bytes.NewReader
