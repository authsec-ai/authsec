package services

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
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

// ASMetadata returns the RFC 8414 Authorization Server Metadata.
// Note: CIMD support is per-RS policy (via registration_modes), not globally advertised.
// AuthSec does not expose a CIMD-discovery extension in v1, so CIMD availability
// remains out-of-band/private rather than discoverable from AS metadata.
func (s *OAuthASService) ASMetadata(baseURL string) map[string]interface{} {
	return map[string]interface{}{
		"issuer":                                        baseURL,
		"authorization_endpoint":                        baseURL + "/oauth/authorize",
		"token_endpoint":                                baseURL + "/oauth/token",
		"registration_endpoint":                         baseURL + "/oauth/register",
		"introspection_endpoint":                        baseURL + "/oauth/introspect",
		"revocation_endpoint":                           baseURL + "/oauth/revoke",
		"jwks_uri":                                      baseURL + "/oauth/jwks",
		"response_types_supported":                      []string{"code"},
		"response_modes_supported":                      []string{"query"},
		"grant_types_supported":                         []string{"authorization_code"},
		"token_endpoint_auth_methods_supported":         []string{"none"},
		"introspection_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		"revocation_endpoint_auth_methods_supported":    []string{"none"},
		"code_challenge_methods_supported":              []string{"S256"},
		"resource_indicators_supported":                 true,
	}
}

// RegisterDCRClient creates a new OAuth client via Dynamic Client Registration (RFC 7591).
func (s *OAuthASService) RegisterDCRClient(req DCRRequest, rs *models.ResourceServer) (*models.MCPOAuthClient, error) {
	if rs != nil && !rs.AllowsRegistrationMode("dcr") {
		return nil, fmt.Errorf("resource server does not allow DCR")
	}

	clientID := uuid.New().String()
	hydraClientID := clientID

	// Register in Hydra
	err := hydraAdminCreateClient(hydraClient{
		ClientID:      hydraClientID,
		ClientName:    req.ClientName,
		GrantTypes:    []string{"authorization_code"},
		RedirectURIs:  req.RedirectURIs,
		ResponseTypes: []string{"code"},
		TokenEndpoint: "none",
		Scope:         "", // no OIDC defaults for MCP
	})
	if err != nil {
		return nil, fmt.Errorf("register hydra client for DCR: %w", err)
	}

	client := &models.MCPOAuthClient{
		ClientID:                clientID,
		HydraClientID:           hydraClientID,
		ClientName:              req.ClientName,
		RedirectURIs:            pq.StringArray(req.RedirectURIs),
		GrantTypes:              pq.StringArray{"authorization_code"},
		ResponseTypes:           pq.StringArray{"code"},
		TokenEndpointAuthMethod: "none",
		RegistrationType:        "dcr",
	}

	if err := s.authzCtx.CreateMCPOAuthClient(client); err != nil {
		// Rollback Hydra client
		_ = hydraAdminDeleteClient(hydraClientID)
		return nil, fmt.Errorf("store DCR client: %w", err)
	}

	// RS is required — fail-closed if nil (defense-in-depth; controller validates this)
	if rs == nil {
		return nil, fmt.Errorf("resource server is required for DCR registration")
	}
	if _, err := s.authzCtx.EnsureClientRegistration(rs.ID, client.ID, "dcr"); err != nil {
		return nil, fmt.Errorf("create DCR client registration: %w", err)
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

// RevokeHydraToken revokes a token via Hydra's public revocation endpoint.
// Best-effort, fire-and-forget — errors are logged but not returned.
func (s *OAuthASService) RevokeHydraToken(token string) {
	form := url.Values{"token": {token}}
	targetURL := config.AppConfig.HydraPublicURL + "/oauth2/revoke"
	req, err := http.NewRequest("POST", targetURL, strings.NewReader(form.Encode()))
	if err != nil {
		log.Printf("[MCP_AUTH] RevokeHydraToken: failed to create request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := CircuitDoHydra(req)
	if err != nil {
		log.Printf("[MCP_AUTH] RevokeHydraToken: Hydra unavailable: %v", err)
		return
	}
	resp.Body.Close()
	log.Printf("[MCP_AUTH] RevokeHydraToken: revoked orphaned token (status=%d)", resp.StatusCode)
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

	// Create new CIMD client
	hydraClientID := uuid.New().String()
	err = hydraAdminCreateClient(hydraClient{
		ClientID:      hydraClientID,
		ClientName:    cimdMeta.ClientName,
		GrantTypes:    []string{"authorization_code"},
		RedirectURIs:  cimdMeta.RedirectURIs,
		ResponseTypes: []string{"code"},
		TokenEndpoint: "none",
		Scope:         "",
	})
	if err != nil {
		return nil, fmt.Errorf("create Hydra client for CIMD: %w", err)
	}

	client := &models.MCPOAuthClient{
		ClientID:                cimdURL,
		HydraClientID:           hydraClientID,
		ClientName:              cimdMeta.ClientName,
		RedirectURIs:            pq.StringArray(cimdMeta.RedirectURIs),
		GrantTypes:              pq.StringArray{"authorization_code"},
		ResponseTypes:           pq.StringArray{"code"},
		TokenEndpointAuthMethod: "none",
		RegistrationType:        "cimd",
		CIMDUrl:                 cimdURL,
		CIMDCachedAt:            &now,
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

	err := hydraAdminCreateClient(hydraClient{
		ClientID:      hydraClientID,
		ClientName:    req.ClientName,
		GrantTypes:    []string{"authorization_code"},
		RedirectURIs:  req.RedirectURIs,
		ResponseTypes: []string{"code"},
		TokenEndpoint: "none",
		Scope:         "",
	})
	if err != nil {
		return nil, fmt.Errorf("register hydra client for prereg: %w", err)
	}

	client := &models.MCPOAuthClient{
		ClientID:                clientID,
		HydraClientID:           hydraClientID,
		ClientName:              req.ClientName,
		RedirectURIs:            pq.StringArray(req.RedirectURIs),
		GrantTypes:              pq.StringArray{"authorization_code"},
		ResponseTypes:           pq.StringArray{"code"},
		TokenEndpointAuthMethod: "none",
		RegistrationType:        "prereg",
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

	// Copy pending → approved
	client.RedirectURIs = client.PendingRedirectURIs
	client.PendingRedirectURIs = nil
	client.RedirectReviewPending = false

	// Update Hydra client
	err = hydraAdminUpdateClient(client.HydraClientID, hydraClient{
		ClientID:      client.HydraClientID,
		ClientName:    client.ClientName,
		GrantTypes:    []string{"authorization_code"},
		RedirectURIs:  []string(client.RedirectURIs),
		ResponseTypes: []string{"code"},
		TokenEndpoint: "none",
		Scope:         "",
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
}

type DCRResponse struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Resource                string   `json:"resource"`
}

// --- CIMD types ---

type cimdDocument struct {
	ClientID     string   `json:"client_id"`
	ClientName   string   `json:"client_name"`
	LogoURI      string   `json:"logo_uri,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
}

func fetchCIMDDocument(cimdURL string) (*cimdDocument, error) {
	parsed, err := url.Parse(cimdURL)
	if err != nil || parsed.Scheme != "https" {
		return nil, fmt.Errorf("CIMD URL must be HTTPS: %s", cimdURL)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(cimdURL)
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
