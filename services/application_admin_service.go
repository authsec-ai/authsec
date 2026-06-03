package services

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ApplicationAdminService is the lean tenant-scoped admin reader/writer for
// the prod-mcp-v2 backport. It powers Phases 1-3 of the full port plan:
// easy reads, activation state machine, and connection (OAuth client)
// admin pre-register / revoke.
//
// Heavy concerns explicitly NOT included:
//   - Drift event emission (Phase 4)
//   - Per-application scope CRUD (Phase 5)
//   - RBAC bindings (Phase 8)
// Those land in later sessions.
type ApplicationAdminService struct {
	rs *ResourceServerService
}

func NewApplicationAdminService() *ApplicationAdminService {
	return &ApplicationAdminService{rs: NewResourceServerService()}
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 1 — Reads
// ─────────────────────────────────────────────────────────────────────────

// ListTools returns the Application's tool rows for the admin UI. Same data
// the SDK reads via /sdk-policy, just under a JWT-protected route.
func (s *ApplicationAdminService) ListTools(tenantID string, applicationID uuid.UUID) ([]models.MCPTool, error) {
	if _, err := s.rs.GetByID(tenantID, applicationID); err != nil {
		return nil, err
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	var rows []models.MCPTool
	if err := tenantDB.Where("resource_server_id = ?", applicationID).
		Order("name ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// ListScopes returns the Application's scopes from the oauth_scopes table.
// As of Phase 5 this reads from the authoritative table (vs the legacy
// resource_servers.scopes_supported array). The array is still kept in
// sync for back-compat with the SDK's /sdk-policy reader.
func (s *ApplicationAdminService) ListScopes(tenantID string, applicationID uuid.UUID) ([]models.OAuthScope, error) {
	if _, err := s.rs.GetByID(tenantID, applicationID); err != nil {
		return nil, err
	}
	scopeSvc := NewScopeService()
	return scopeSvc.List(tenantID, applicationID)
}

// ScopeMatrixRow is one row of the /scope-matrix view. Tools cross
// scopes — used by the UI to render a 2D editing grid.
type ScopeMatrixRow struct {
	ToolName       string   `json:"tool_name"`
	ToolID         string   `json:"tool_id"`
	IsPublic       bool     `json:"is_public"`
	RequiredScopes []string `json:"required_scopes"`
}

// ScopeMatrixResponse is what /scope-matrix returns.
type ScopeMatrixResponse struct {
	ScopesSupported []string         `json:"scopes_supported"`
	Tools           []ScopeMatrixRow `json:"tools"`
}

// GetScopeMatrix composes the Application's scopes_supported + tools into
// a single payload.
func (s *ApplicationAdminService) GetScopeMatrix(tenantID string, applicationID uuid.UUID) (*ScopeMatrixResponse, error) {
	rs, err := s.rs.GetByID(tenantID, applicationID)
	if err != nil {
		return nil, err
	}
	tools, err := s.ListTools(tenantID, applicationID)
	if err != nil {
		return nil, err
	}
	scopes := []string(rs.ScopesSupported)
	if scopes == nil {
		scopes = []string{}
	}
	rows := make([]ScopeMatrixRow, 0, len(tools))
	for _, t := range tools {
		rows = append(rows, ScopeMatrixRow{
			ToolName:       t.Name,
			ToolID:         t.ID.String(),
			IsPublic:       t.IsPublic,
			RequiredScopes: []string(t.RequiredScopes),
		})
	}
	return &ScopeMatrixResponse{ScopesSupported: scopes, Tools: rows}, nil
}

// SetupChecklistItem is one boolean check + a human-readable label.
type SetupChecklistItem struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Done  bool   `json:"done"`
}

// SetupChecklistResponse drives the Setup tab in the admin UI.
type SetupChecklistResponse struct {
	State           string               `json:"state"`
	Items           []SetupChecklistItem `json:"items"`
	ReadyToActivate bool                 `json:"ready_to_activate"`
}

// GetSetupChecklist returns the readiness checklist used by the Setup tab
// AND consumed by /activate's gate.
func (s *ApplicationAdminService) GetSetupChecklist(tenantID string, applicationID uuid.UUID) (*SetupChecklistResponse, error) {
	rs, err := s.rs.GetByID(tenantID, applicationID)
	if err != nil {
		return nil, err
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}

	var clientCount int64
	if err := tenantDB.Model(&models.ResourceServerClientRegistration{}).
		Where("resource_server_id = ? AND status = ?", applicationID, models.RegistrationStatusApproved).
		Count(&clientCount).Error; err != nil {
		return nil, fmt.Errorf("count clients: %w", err)
	}

	var toolCount int64
	if err := tenantDB.Model(&models.MCPTool{}).
		Where("resource_server_id = ?", applicationID).
		Count(&toolCount).Error; err != nil {
		return nil, fmt.Errorf("count tools: %w", err)
	}

	var policy models.ApplicationAccessPolicy
	policyErr := tenantDB.Where("application_id = ? AND tenant_id = ?", applicationID, tenantID).
		First(&policy).Error
	hasPolicy := policyErr == nil
	policyEnabled := hasPolicy && policy.Enabled

	hasSecret := rs.IntrospectionSecretHash != "" || rs.IntrospectionSecret != ""

	items := []SetupChecklistItem{
		{Key: "introspection_secret", Label: "Introspection secret rotated", Done: hasSecret},
		{Key: "tools_published", Label: "Tool manifest published by SDK", Done: toolCount > 0},
		{Key: "scopes_defined", Label: "At least one scope defined", Done: len(rs.ScopesSupported) > 0},
		{Key: "access_policy", Label: "Access policy configured", Done: policyEnabled},
		{Key: "clients_registered", Label: "At least one OAuth client registered", Done: clientCount > 0},
	}

	readyToActivate := hasSecret && toolCount > 0 && len(rs.ScopesSupported) > 0 && clientCount > 0
	// access_policy is not required for activation — clients can still get
	// tokens; per-tool scope enforcement still works through sdk-policy.
	// We surface it as a checklist item but don't gate on it.

	return &SetupChecklistResponse{
		State:           rs.State,
		Items:           items,
		ReadyToActivate: readyToActivate,
	}, nil
}

// SDKManifestStatusResponse is /sdk-manifest-status.
type SDKManifestStatusResponse struct {
	ScanGeneration            int        `json:"scan_generation"`
	LastSuccessfulGeneration  int        `json:"last_successful_generation"`
	ToolCount                 int64      `json:"tool_count"`
	LastPublishedAt           *time.Time `json:"last_published_at,omitempty"`
}

// GetSDKManifestStatus returns the manifest-publish snapshot.
func (s *ApplicationAdminService) GetSDKManifestStatus(tenantID string, applicationID uuid.UUID) (*SDKManifestStatusResponse, error) {
	rs, err := s.rs.GetByID(tenantID, applicationID)
	if err != nil {
		return nil, err
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	var toolCount int64
	if err := tenantDB.Model(&models.MCPTool{}).
		Where("resource_server_id = ?", applicationID).
		Count(&toolCount).Error; err != nil {
		return nil, fmt.Errorf("count tools: %w", err)
	}
	var lastPublished *time.Time
	var latest models.MCPTool
	err = tenantDB.Where("resource_server_id = ? AND last_published_at IS NOT NULL", applicationID).
		Order("last_published_at DESC").First(&latest).Error
	if err == nil {
		lastPublished = latest.LastPublishedAt
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	return &SDKManifestStatusResponse{
		ScanGeneration:           rs.ScanGeneration,
		LastSuccessfulGeneration: rs.LastSuccessfulGeneration,
		ToolCount:                toolCount,
		LastPublishedAt:          lastPublished,
	}, nil
}

// ActivationPreviewResponse extends the Setup checklist with the validate
// result. Same idea as Validate but unified so the UI can do one fetch.
type ActivationPreviewResponse struct {
	Checklist     *SetupChecklistResponse      `json:"checklist"`
	ValidateResult *ApplicationValidationResult `json:"validate"`
}

// GetActivationPreview is the convenience read the UI uses on the Setup tab
// to render both the checklist AND the live validate result side by side.
func (s *ApplicationAdminService) GetActivationPreview(tenantID string, applicationID uuid.UUID, onboarding *ApplicationOnboardingService) (*ActivationPreviewResponse, error) {
	checklist, err := s.GetSetupChecklist(tenantID, applicationID)
	if err != nil {
		return nil, err
	}
	rs, err := s.rs.GetByID(tenantID, applicationID)
	if err != nil {
		return nil, err
	}
	clientCount, err := onboarding.CountRegisteredClients(tenantID, applicationID)
	if err != nil {
		return nil, err
	}
	policyEnabled, err := onboarding.GetAccessPolicySummary(tenantID, applicationID)
	if err != nil {
		return nil, err
	}
	validate := onboarding.ValidateResourceServer(rs, int(clientCount), policyEnabled)
	return &ActivationPreviewResponse{
		Checklist:      checklist,
		ValidateResult: validate,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 2 — Activation state machine
// ─────────────────────────────────────────────────────────────────────────

var (
	ErrAlreadyActivated  = errors.New("application is already activated")
	ErrNotReadyToActivate = errors.New("application is not ready to activate")
)

// Activate gates on the Setup checklist's ReadyToActivate flag, then flips
// state -> ready, sets setup_completed_at/_by, and bumps scan_generation
// so SDKs refetch sdk-policy. Returns the updated RS row.
//
// Setting `force=true` skips the gate. Useful for admin recovery when the
// checklist is wrong (e.g. the SDK published tools but we don't see them
// because the tenant DB is rolling back). Use sparingly.
func (s *ApplicationAdminService) Activate(tenantID string, applicationID uuid.UUID, performedBy uuid.UUID, force bool) (*models.ResourceServer, error) {
	rs, err := s.rs.GetByID(tenantID, applicationID)
	if err != nil {
		return nil, err
	}
	if rs.State == models.RSStateReady {
		return nil, ErrAlreadyActivated
	}
	if !force {
		checklist, err := s.GetSetupChecklist(tenantID, applicationID)
		if err != nil {
			return nil, err
		}
		if !checklist.ReadyToActivate {
			return nil, ErrNotReadyToActivate
		}
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	now := time.Now().UTC()
	updates := map[string]interface{}{
		"state":              models.RSStateReady,
		"status":             models.RSStateReady,
		"setup_completed_at": now,
		"scan_generation":    rs.ScanGeneration + 1,
		"updated_at":         now,
	}
	if performedBy != uuid.Nil {
		updates["setup_completed_by"] = performedBy
	}
	if err := tenantDB.Model(rs).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("activate: %w", err)
	}
	// Reload fresh row.
	return s.rs.GetByID(tenantID, applicationID)
}

// RescanResponse is what /rescan returns.
type RescanResponse struct {
	ScanGeneration int       `json:"scan_generation"`
	StartedAt      time.Time `json:"started_at"`
	Status         string    `json:"status"`
}

// Rescan bumps scan_generation. The dev branch kicks off an outbound scan
// against the RS's public_base_url to refresh tools/scopes; the backport
// is purely admin-triggered (no real scan), but UIs use this to force
// SDKs to refetch sdk-policy on next TTL.
func (s *ApplicationAdminService) Rescan(tenantID string, applicationID uuid.UUID) (*RescanResponse, error) {
	rs, err := s.rs.GetByID(tenantID, applicationID)
	if err != nil {
		return nil, err
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	now := time.Now().UTC()
	newGen := rs.ScanGeneration + 1
	if err := tenantDB.Model(rs).Updates(map[string]interface{}{
		"scan_generation": newGen,
		"updated_at":      now,
	}).Error; err != nil {
		return nil, fmt.Errorf("rescan: %w", err)
	}
	return &RescanResponse{
		ScanGeneration: newGen,
		StartedAt:      now,
		Status:         "queued",
	}, nil
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 3 — Connection admin (pre-register + revoke)
// ─────────────────────────────────────────────────────────────────────────

// PreregisterConnectionRequest is the body for POST /:id/connections.
// Same shape as DCR but admin-initiated and bound to a specific RS without
// going through the public registration endpoint.
type PreregisterConnectionRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris" binding:"required"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris,omitempty"`
}

// PreregisterConnectionResponse is what we return. Includes a one-time
// client_secret because preregistered clients use `client_secret_basic`
// auth by default (vs DCR's `none`).
type PreregisterConnectionResponse struct {
	ClientID         string   `json:"client_id"`
	ClientSecret     string   `json:"client_secret"`
	ClientName       string   `json:"client_name,omitempty"`
	RedirectURIs     []string `json:"redirect_uris"`
	GrantTypes       []string `json:"grant_types"`
	ResponseTypes    []string `json:"response_types"`
	AuthMethod       string   `json:"token_endpoint_auth_method"`
	Scope            string   `json:"scope,omitempty"`
	RegistrationType string   `json:"registration_type"`
}

// PreregisterConnection mints a Hydra client + writes an mcp_oauth_clients
// row + writes a resource_server_client_registrations join row with
// registration_type='prereg'. Returns the client_id and one-time secret.
//
// Differs from DCR in three ways:
//   - registration_type='prereg' (not 'dcr')
//   - token_endpoint_auth_method defaults to 'client_secret_basic' (vs 'none')
//   - the client secret is admin-bound and persisted on the Hydra row,
//     not the in-memory transient that DCR public clients use
func (s *ApplicationAdminService) PreregisterConnection(tenantID string, applicationID uuid.UUID, req PreregisterConnectionRequest) (*PreregisterConnectionResponse, error) {
	rs, err := s.rs.GetByID(tenantID, applicationID)
	if err != nil {
		return nil, err
	}
	if len(req.RedirectURIs) == 0 {
		return nil, fmt.Errorf("redirect_uris required")
	}
	for _, u := range req.RedirectURIs {
		if err := validateRedirectURI(u); err != nil {
			return nil, fmt.Errorf("invalid redirect_uri %q: %w", u, err)
		}
	}
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic"
	}

	clientID := uuid.NewString()
	hydraClientID := uuid.NewString()
	// Generate a one-time secret. 32 bytes -> 43 chars base64url.
	clientSecret, err := generateRandomSecret()
	if err != nil {
		return nil, fmt.Errorf("generate client secret: %w", err)
	}

	hc := hydraClient{
		ClientID:      hydraClientID,
		ClientSecret:  clientSecret,
		ClientName:    req.ClientName,
		GrantTypes:    req.GrantTypes,
		RedirectURIs:  req.RedirectURIs,
		ResponseTypes: req.ResponseTypes,
		TokenEndpoint: req.TokenEndpointAuthMethod,
		Scope:         req.Scope,
		Audience:      []string{rs.ResourceURI},
	}
	if err := hydraAdminCreateClient(hc); err != nil {
		return nil, fmt.Errorf("hydra create client: %w", err)
	}

	supportsRefresh := false
	for _, g := range req.GrantTypes {
		if g == "refresh_token" {
			supportsRefresh = true
			break
		}
	}

	row := models.MCPOAuthClient{
		ClientID:                clientID,
		HydraClientID:           hydraClientID,
		ClientName:              req.ClientName,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		Scope:                   req.Scope,
		RegistrationType:        "prereg",
		PostLogoutRedirectURIs:  req.PostLogoutRedirectURIs,
		SupportsRefreshToken:    supportsRefresh,
		SyncStatus:              "active",
	}
	if err := config.DB.Create(&row).Error; err != nil {
		_ = hydraAdminDeleteClient(hydraClientID)
		return nil, fmt.Errorf("insert mcp_oauth_clients: %w", err)
	}

	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	reg := models.ResourceServerClientRegistration{
		ResourceServerID: rs.ID,
		ClientID:         clientID,
		Status:           models.RegistrationStatusApproved,
		RegistrationType: "prereg",
	}
	if err := tenantDB.Create(&reg).Error; err != nil {
		// Mark master row pending_delete; reconciler will clean up Hydra.
		now := time.Now()
		_ = config.DB.Model(&row).Updates(map[string]interface{}{
			"sync_status":        "pending_delete",
			"sync_last_error":    err.Error(),
			"sync_last_error_at": now,
			"updated_at":         now,
		}).Error
		return nil, fmt.Errorf("insert resource_server_client_registrations: %w", err)
	}

	return &PreregisterConnectionResponse{
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		ClientName:       req.ClientName,
		RedirectURIs:     req.RedirectURIs,
		GrantTypes:       req.GrantTypes,
		ResponseTypes:    req.ResponseTypes,
		AuthMethod:       req.TokenEndpointAuthMethod,
		Scope:            req.Scope,
		RegistrationType: "prereg",
	}, nil
}

// RevokeConnection marks the join row revoked and queues the master client
// for Hydra deletion via sync_status='pending_delete'. The Hydra reconciler
// goroutine does the actual delete on its next tick.
func (s *ApplicationAdminService) RevokeConnection(tenantID string, applicationID uuid.UUID, clientID string, reason string) error {
	if _, err := s.rs.GetByID(tenantID, applicationID); err != nil {
		return err
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return fmt.Errorf("get tenant db: %w", err)
	}

	// Verify the join row exists and isn't already revoked.
	var reg models.ResourceServerClientRegistration
	err = tenantDB.Where("resource_server_id = ? AND client_id = ?", applicationID, clientID).
		First(&reg).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("connection not found")
		}
		return err
	}
	if reg.Status == models.RegistrationStatusRevoked {
		return fmt.Errorf("connection already revoked")
	}

	now := time.Now().UTC()
	if err := tenantDB.Model(&reg).Updates(map[string]interface{}{
		"status":         models.RegistrationStatusRevoked,
		"revoked_at":     now,
		"revoked_reason": reason,
		"updated_at":     now,
	}).Error; err != nil {
		return fmt.Errorf("mark join revoked: %w", err)
	}

	// Queue master row for Hydra delete. Reconciler picks it up.
	if err := config.DB.Model(&models.MCPOAuthClient{}).
		Where("client_id = ?", clientID).
		Updates(map[string]interface{}{
			"sync_status": "pending_delete",
			"updated_at":  now,
		}).Error; err != nil {
		return fmt.Errorf("queue master delete: %w", err)
	}
	return nil
}

// generateRandomSecret returns 32 cryptographically random bytes encoded
// as base64url. Same shape as introspection secrets minted elsewhere.
func generateRandomSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
