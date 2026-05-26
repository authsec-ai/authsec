package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strings"
	"time"

	mcpclient "github.com/authsec-ai/authsec/internal/mcp"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// ErrScanInProgress is returned when a rescan is requested while one is already running.
// Callers should map this to HTTP 409 Conflict.
var ErrScanInProgress = errors.New("rescan already in progress")

type ResourceServerService struct {
	db *gorm.DB
}

func NewResourceServerService(db *gorm.DB) *ResourceServerService {
	return &ResourceServerService{db: db}
}

type CreateResourceServerRequest struct {
	WorkspaceID       uuid.UUID `json:"workspace_id"`
	Name              string    `json:"name"`
	PublicBaseURL     string    `json:"public_base_url"`
	ProtectedBasePath string    `json:"protected_base_path"`
	ScopesSupported   []string  `json:"scopes_supported"`
	RegistrationModes []string  `json:"registration_modes"`
	// ApplicationType is one of models.ApplicationType* — mcp_server (default),
	// ai_agent, clawbot, api_service. Optional; left empty defaults to mcp_server.
	ApplicationType string `json:"application_type,omitempty"`
	// ScopePresetID, if set and not "blank", seeds preset scopes for this RS.
	ScopePresetID *string `json:"scope_preset_id,omitempty"`
	// DefaultAccessEnabled controls the initial enabled flag on the auto-created
	// access policy. Defaults to false (closed) per the wireframe redesign.
	DefaultAccessEnabled *bool `json:"default_access_enabled,omitempty"`
}

// ValidApplicationType reports whether the supplied type is one of the
// supported Application type constants. Empty string is treated as valid and
// resolved to mcp_server by the caller.
func ValidApplicationType(t string) bool {
	switch t {
	case "",
		models.ApplicationTypeMCPServer,
		models.ApplicationTypeAIAgent,
		models.ApplicationTypeClawbot,
		models.ApplicationTypeAPIService:
		return true
	default:
		return false
	}
}

type ResourceServerResponse struct {
	ID                    string `json:"id"`
	IssuerURL             string `json:"issuer_url"`
	ResourceURL           string `json:"resource_url"`
	JWKSURI               string `json:"jwks_uri"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	IntrospectionSecret   string `json:"introspection_secret,omitempty"`
	// SDK endpoints. Both use Basic auth keyed by (id : introspection_secret).
	// Provided in the create response so the SDK Config can be assembled by
	// pasting directly from this payload — no hand-written URLs.
	ScopeMatrixURL  string   `json:"scope_matrix_url"`
	ManifestURL     string   `json:"manifest_url"`
	ValidationMode  string   `json:"validation_mode"`
	ScopesSupported []string `json:"scopes_supported"`
	Status          string   `json:"status"`
}

func (s *ResourceServerService) Create(req CreateResourceServerRequest, baseURL string) (*models.ResourceServer, *ResourceServerResponse, error) {
	// Bug 11: HTTPS validation
	parsed, err := url.Parse(req.PublicBaseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid public_base_url: %w", err)
	}
	isLocal := parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1"
	if parsed.Scheme != "https" && !isLocal {
		return nil, nil, fmt.Errorf("public_base_url must use HTTPS (http allowed only for localhost)")
	}

	publicURL := strings.TrimRight(req.PublicBaseURL, "/")
	basePath := req.ProtectedBasePath
	if basePath == "" {
		basePath = "/mcp"
	}
	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	resourceURI := publicURL + basePath

	secret, err := generateIntrospectionSecret()
	if err != nil {
		return nil, nil, fmt.Errorf("generate introspection secret: %w", err)
	}

	modes := req.RegistrationModes
	if len(modes) == 0 {
		modes = []string{"dcr", "cimd", "prereg"}
	}

	// Bug 12: Store bcrypt hash, not plaintext
	hashedSecret, hashErr := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if hashErr != nil {
		return nil, nil, fmt.Errorf("hash introspection secret: %w", hashErr)
	}

	appType := req.ApplicationType
	if appType == "" {
		appType = models.ApplicationTypeMCPServer
	}
	appSlug := SlugForApp(req.Name)
	canonicalRequestedScopes := CanonicalAuthSecScopes(req.ScopesSupported, appSlug)

	rs := &models.ResourceServer{
		WorkspaceID:             req.WorkspaceID,
		ApplicationType:         appType,
		Name:                    req.Name,
		PublicBaseURL:           publicURL,
		ProtectedBasePath:       basePath,
		ResourceURI:             resourceURI,
		ScopesSupported:         canonicalRequestedScopes,
		RegistrationModes:       modes,
		IntrospectionSecret:     "", // Not stored in plaintext for new rows
		IntrospectionSecretHash: string(hashedSecret),
		Active:                  true,
		Status:                  "pending_scan",
		State:                   models.RSStatePendingScan,
		ScanGeneration:          0,
	}

	txErr := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(rs).Error; err != nil {
			return fmt.Errorf("create resource server: %w", err)
		}

		// Auto-create viewer role and access policy (§3.3, §4.1 step 5).
		viewerRole := &models.RBACRole{
			WorkspaceID: &rs.WorkspaceID,
			Name:        fmt.Sprintf("rs-%s:viewer", rs.ID.String()),
			Description: fmt.Sprintf("Default viewer role for %s (auto-generated)", rs.Name),
		}
		if err := tx.Create(viewerRole).Error; err != nil {
			return fmt.Errorf("create viewer role: %w", err)
		}

		// Default access is now closed (Enabled=false). Operators opt in by passing
		// default_access_enabled=true at registration, or flip the policy from the
		// Access tab after activation.
		policyEnabled := false
		if req.DefaultAccessEnabled != nil && *req.DefaultAccessEnabled {
			policyEnabled = true
		}
		policy := &models.ResourceServerAccessPolicy{
			WorkspaceID:      rs.WorkspaceID,
			ResourceServerID: rs.ID,
			Enabled:          policyEnabled,
			DefaultRoleID:    &viewerRole.ID,
		}
		if err := tx.Create(policy).Error; err != nil {
			return fmt.Errorf("create access policy: %w", err)
		}

		// Seed preset scopes (idempotent — FirstOrCreate on the unique key).
		// Skipped for "blank" and when no preset is selected. Scopes are tagged
		// source="preset" so the UI can distinguish them from discovered ones.
		if req.ScopePresetID != nil && *req.ScopePresetID != "" && *req.ScopePresetID != "blank" {
			if preset, ok := GetScopePreset(*req.ScopePresetID); ok {
				for _, ss := range ExpandPresetScopes(preset, appSlug) {
					scope := models.OAuthScope{
						WorkspaceID:      req.WorkspaceID,
						ResourceServerID: &rs.ID,
						ScopeString:      ss,
						DisplayName:      ss,
						RiskLevel:        inferRiskLevel(ss),
						Source:           "preset",
						IsAutoDiscovered: false,
					}
					if err := tx.Where(
						"(workspace_id = ? OR tenant_id = ?) AND resource_server_id = ? AND scope_string = ?",
						req.WorkspaceID, req.WorkspaceID, rs.ID, ss,
					).FirstOrCreate(&scope).Error; err != nil {
						return fmt.Errorf("seed preset scope %s: %w", ss, err)
					}
				}
			}
		}
		for _, ss := range canonicalRequestedScopes {
			scope := models.OAuthScope{
				WorkspaceID:      req.WorkspaceID,
				ResourceServerID: &rs.ID,
				ScopeString:      ss,
				DisplayName:      ss,
				RiskLevel:        inferRiskLevel(ss),
				Source:           "manual",
				IsAutoDiscovered: false,
			}
			if err := tx.Where(
				"(workspace_id = ? OR tenant_id = ?) AND resource_server_id = ? AND scope_string = ?",
				req.WorkspaceID, req.WorkspaceID, rs.ID, ss,
			).FirstOrCreate(&scope).Error; err != nil {
				return fmt.Errorf("seed canonical scope %s: %w", ss, err)
			}
		}
		supported, err := syncSupportedScopesFromRegistry(tx, req.WorkspaceID, rs.ID)
		if err != nil {
			return err
		}
		rs.ScopesSupported = supported
		return nil
	})
	if txErr != nil {
		return nil, nil, txErr
	}

	// Trigger MCP discovery in background — populates scope registry and tool map.
	// Best-effort: failure doesn't block RS creation.
	go func() {
		discoverCtx := context.Background()
		if _, discoverErr := s.DiscoverAndSync(discoverCtx, rs); discoverErr != nil {
			log.Printf("[MCP_DISCOVERY] background discovery failed for RS %s (%s): %v",
				rs.Name, rs.PublicBaseURL, discoverErr)
		}
	}()

	resp := &ResourceServerResponse{
		ID:                    rs.ID.String(),
		IssuerURL:             baseURL,
		ResourceURL:           rs.ResourceURI,
		JWKSURI:               baseURL + "/oauth/jwks",
		IntrospectionEndpoint: baseURL + "/oauth/introspect",
		IntrospectionSecret:   secret,
		ScopeMatrixURL:        fmt.Sprintf("%s/authsec/resource-servers/%s/sdk-policy", baseURL, rs.ID.String()),
		ManifestURL:           fmt.Sprintf("%s/authsec/resource-servers/%s/sdk-manifest", baseURL, rs.ID.String()),
		ValidationMode:        "auto",
		ScopesSupported:       rs.ScopesSupported,
		Status:                rs.Status,
	}

	return rs, resp, nil
}

// CanonicalAuthSecScopes returns the subset of scopes that already follow the
// AuthSec-owned application namespace. Server-defined and OIDC scopes are
// treated as legacy hints and ignored.
func CanonicalAuthSecScopes(scopes []string, appSlug string) []string {
	if appSlug == "" {
		return nil
	}
	prefix := appSlug + ":"
	seen := make(map[string]struct{}, len(scopes))
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" || !strings.HasPrefix(scope, prefix) {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	sort.Strings(out)
	return out
}

func syncSupportedScopesFromRegistry(tx *gorm.DB, workspaceID, rsID uuid.UUID) (pq.StringArray, error) {
	var scopeStrings []string
	if err := tx.Model(&models.OAuthScope{}).
		Where("(workspace_id = ? OR tenant_id = ?) AND resource_server_id = ?", workspaceID, workspaceID, rsID).
		Order("scope_string ASC").
		Pluck("scope_string", &scopeStrings).Error; err != nil {
		return nil, fmt.Errorf("sync supported scopes from registry: %w", err)
	}
	if err := tx.Model(&models.ResourceServer{}).
		Where("id = ?", rsID).
		Update("scopes_supported", pq.StringArray(scopeStrings)).Error; err != nil {
		return nil, fmt.Errorf("update scopes_supported: %w", err)
	}
	return pq.StringArray(scopeStrings), nil
}

func (s *ResourceServerService) GetByID(id string) (*models.ResourceServer, error) {
	var rs models.ResourceServer
	if err := s.db.Where("id = ? AND active = true", id).First(&rs).Error; err != nil {
		return nil, err
	}
	return &rs, nil
}

func (s *ResourceServerService) GetByResourceURI(uri string) (*models.ResourceServer, error) {
	var rs models.ResourceServer
	if err := s.db.Where("resource_uri = ? AND active = true", uri).First(&rs).Error; err != nil {
		return nil, err
	}
	return &rs, nil
}

func (s *ResourceServerService) ListByTenant(tenantID string) ([]models.ResourceServer, error) {
	var servers []models.ResourceServer
	if err := s.db.Where("tenant_id = ? AND active = true", tenantID).Find(&servers).Error; err != nil {
		return nil, err
	}
	return servers, nil
}

// ListByWorkspace returns Applications in a workspace, optionally filtered by
// application_type. During the tenant_id -> workspace_id rollout this matches
// rows where workspace_id = $1 OR (workspace_id IS NULL AND tenant_id = $1) so
// unbackfilled rows are still surfaced to their owning workspace.
//
// applicationType is matched as a literal string ("" means no filter).
func (s *ResourceServerService) ListByWorkspace(workspaceID string, applicationType string) ([]models.ResourceServer, error) {
	var servers []models.ResourceServer
	q := s.db.Where(
		"(workspace_id = ? OR (workspace_id IS NULL AND tenant_id = ?)) AND active = true",
		workspaceID, workspaceID,
	)
	if applicationType != "" {
		q = q.Where("application_type = ?", applicationType)
	}
	if err := q.Find(&servers).Error; err != nil {
		return nil, err
	}
	return servers, nil
}

func (s *ResourceServerService) Update(id string, updates map[string]interface{}) (*models.ResourceServer, error) {
	var rs models.ResourceServer
	if err := s.db.Where("id = ?", id).First(&rs).Error; err != nil {
		return nil, err
	}
	if err := s.db.Model(&rs).Updates(updates).Error; err != nil {
		return nil, err
	}
	return &rs, nil
}

func (s *ResourceServerService) Delete(id string) error {
	return s.db.Where("id = ?", id).Delete(&models.ResourceServer{}).Error
}

// GetByIDAndTenant fetches a resource server by ID with tenant ownership check.
func (s *ResourceServerService) GetByIDAndTenant(id, tenantID string) (*models.ResourceServer, error) {
	var rs models.ResourceServer
	if err := s.db.Where("id = ? AND tenant_id = ? AND active = true", id, tenantID).First(&rs).Error; err != nil {
		return nil, err
	}
	return &rs, nil
}

// UpdateByTenant updates a resource server with tenant ownership check.
// If public_base_url or protected_base_path change, resource_uri is recomputed.
func (s *ResourceServerService) UpdateByTenant(id, tenantID string, updates map[string]interface{}) (*models.ResourceServer, error) {
	var rs models.ResourceServer
	if err := s.db.Where("id = ? AND tenant_id = ?", id, tenantID).First(&rs).Error; err != nil {
		return nil, err
	}
	if err := s.db.Model(&rs).Updates(updates).Error; err != nil {
		return nil, err
	}

	// Recompute resource_uri if either component changed
	_, urlChanged := updates["public_base_url"]
	_, pathChanged := updates["protected_base_path"]
	if urlChanged || pathChanged {
		// Re-read to get the applied values
		s.db.Where("id = ?", id).First(&rs)
		newURI := strings.TrimRight(rs.PublicBaseURL, "/") + rs.ProtectedBasePath
		if newURI != rs.ResourceURI {
			s.db.Model(&rs).Update("resource_uri", newURI)
			rs.ResourceURI = newURI
		}
	}

	return &rs, nil
}

// DeleteByTenant deletes a resource server with tenant ownership check.
func (s *ResourceServerService) DeleteByTenant(id, tenantID string) error {
	result := s.db.Where("id = ? AND tenant_id = ?", id, tenantID).Delete(&models.ResourceServer{})
	if result.RowsAffected == 0 {
		return fmt.Errorf("resource server not found")
	}
	return result.Error
}

// RotateIntrospectionSecret generates a new secret, stores its bcrypt hash, returns plaintext once.
func (s *ResourceServerService) RotateIntrospectionSecret(id, tenantID string) (string, error) {
	var rs models.ResourceServer
	if err := s.db.Where("id = ? AND tenant_id = ?", id, tenantID).First(&rs).Error; err != nil {
		return "", fmt.Errorf("resource server not found")
	}

	secret, err := generateIntrospectionSecret()
	if err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash secret: %w", err)
	}

	if err := s.db.Model(&rs).Updates(map[string]interface{}{
		"introspection_secret_hash": string(hashed),
		"introspection_secret":      "", // clear plaintext
	}).Error; err != nil {
		return "", err
	}

	return secret, nil
}

func generateIntrospectionSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "sec_" + hex.EncodeToString(b), nil
}

// DiscoverySyncResult contains the outcome of a discovery + sync operation.
// Always returned non-nil from DiscoverAndSync, even on error.
type DiscoverySyncResult struct {
	ToolsAdded     int      `json:"tools_added"`
	ToolsUpdated   int      `json:"tools_updated"`
	ToolsRemoved   int      `json:"tools_removed"`
	ScopesAdded    int      `json:"scopes_added"`
	ScopesRemoved  int      `json:"scopes_removed"`
	UnmappedScopes []string `json:"unmapped_scopes"`
	Warnings       []string `json:"warnings"`
	FailureReason  string   `json:"failure_reason,omitempty"`
}

// DiscoverAndSync performs MCP discovery (PRM + tools/list) for a resource server
// and reconciles the DB state. It is the single reconciliation unit for tools,
// scopes, and mappings.
//
// Three outcomes based on client.Discover():
//   - Hard failure (tools/list error): nothing committed, status=degraded
//   - Partial (PRM nil, tools OK): tool upserts committed, no stale deletion,
//     no scope/mapping changes, last_successful_generation NOT advanced
//   - Full (PRM fetched, tools OK): full reconciliation committed atomically,
//     last_successful_generation advanced to the new generation
//
// Always returns a non-nil *DiscoverySyncResult.
func (s *ResourceServerService) DiscoverAndSync(ctx context.Context, rs *models.ResourceServer) (*DiscoverySyncResult, error) {
	return s.DiscoverAndSyncWithToken(ctx, rs, "")
}

// DiscoverAndSyncWithToken is identical to DiscoverAndSync but lets the caller
// supply a one-shot bearer token used for the synthetic tools/list call. This
// is the "authenticated scan" path: when the MCP server requires a token to
// list tools, an admin pastes one in the wizard and we forward it to the
// scanner. The token is never persisted — it lives on the mcpclient for the
// duration of this call only.
func (s *ResourceServerService) DiscoverAndSyncWithToken(ctx context.Context, rs *models.ResourceServer, mcpBearerToken string) (*DiscoverySyncResult, error) {
	syncResult := &DiscoverySyncResult{}

	// ── Stage 1: Claim scan lock ────────────────────────────────────────────
	// Atomic UPDATE: only succeeds if no scan is running, or the existing lock is
	// stale (started > 10 minutes ago — crash recovery).
	var nextGeneration int
	res := s.db.Raw(`
		UPDATE resource_servers
		SET scan_in_progress     = true,
		    scan_generation      = scan_generation + 1,
		    status               = 'pending_scan',
		    last_scan_started_at = NOW(),
		    last_scan_error      = NULL,
		    last_scan_status     = NULL
		WHERE id = ?
		  AND (
		    scan_in_progress = false
		    OR last_scan_started_at < NOW() - INTERVAL '10 minutes'
		  )
		RETURNING scan_generation
	`, rs.ID).Scan(&nextGeneration)

	if res.Error != nil || res.RowsAffected == 0 {
		syncResult.FailureReason = ErrScanInProgress.Error()
		return syncResult, ErrScanInProgress
	}
	rs.ScanGeneration = nextGeneration

	// ── Stage 2: MCP Discovery (no DB locks held) ───────────────────────────
	// Fix: use resourceURI (PublicBaseURL + ProtectedBasePath), not bare PublicBaseURL.
	resourceURI := strings.TrimRight(rs.PublicBaseURL, "/") + rs.ProtectedBasePath
	client := mcpclient.NewClient().WithBearerToken(mcpBearerToken)
	discovered, err := client.Discover(ctx, resourceURI)
	// protectedServer: RFC 9728 bearer challenge on tools/list. Server is
	// reachable and properly OAuth-protected. We cannot enumerate tools
	// without a token, but this is NOT a discovery failure — it means the
	// server correctly rejects anonymous access. Commit a zero-tool scan
	// that advances last_successful_generation so sdk-policy can serve
	// (empty policy = deny-all on the Go SDK side, which is the safe default).
	protectedServer := false
	if err != nil {
		if errors.Is(err, mcpclient.ErrProtectedServer) {
			protectedServer = true
			if discovered == nil {
				discovered = &mcpclient.DiscoveryResult{}
			}
			syncResult.Warnings = append(syncResult.Warnings,
				"MCP server is protected (401 with bearer challenge) — committed zero-tool scan; tools will be discovered once a service token is configured")
			err = nil
		} else {
			// tools/list failed — hard failure, nothing to commit.
			// Pass nextGeneration so markScanFailed only updates the row if this scan
			// still owns the lock (generation guard). Superseded scans are a no-op.
			syncResult.FailureReason = err.Error()
			s.markScanFailed(rs, nextGeneration, err.Error())
			return syncResult, fmt.Errorf("MCP discovery failed: %w", err)
		}
	}

	// prmFetched distinguishes:
	//   nil  → PRM fetch failed (non-fatal per spec); partial scan
	//   non-nil → PRM fetched; may have empty ScopesSupported (legitimately)
	prmFetched := discovered.PRM != nil

	// ── Stage 3: Reconciliation (single atomic transaction) ─────────────────
	txErr := s.db.Transaction(func(tx *gorm.DB) error {

		// ── 3a. Scope reconciliation (full scan only) ─────────────────────
		if prmFetched {
			appSlug := SlugForApp(rs.Name)
			legacyScopeCount := len(discovered.PRM.ScopesSupported)
			currentScopeStrings := CanonicalAuthSecScopes(discovered.PRM.ScopesSupported, appSlug)
			legacyScopeCount -= len(currentScopeStrings)
			if legacyScopeCount > 0 {
				syncResult.Warnings = append(syncResult.Warnings,
					fmt.Sprintf("ignored %d server-declared legacy scope(s); AuthSec canonical scopes are authoritative", legacyScopeCount))
			}

			scopeRegistry := NewScopeRegistryService(tx)

			// Count existing auto-discovered scopes before upsert
			var beforeCount int64
			tx.Model(&models.OAuthScope{}).
				Where("(workspace_id = ? OR tenant_id = ?) AND resource_server_id = ? AND is_auto_discovered = true",
					rs.WorkspaceID, rs.WorkspaceID, rs.ID).Count(&beforeCount)

			if len(currentScopeStrings) > 0 {
				if _, err := scopeRegistry.SyncFromPRM(rs.WorkspaceID, rs.ID, currentScopeStrings); err != nil {
					return fmt.Errorf("scope sync: %w", err)
				}
			}

			var afterCount int64
			tx.Model(&models.OAuthScope{}).
				Where("(workspace_id = ? OR tenant_id = ?) AND resource_server_id = ? AND is_auto_discovered = true",
					rs.WorkspaceID, rs.WorkspaceID, rs.ID).Count(&afterCount)
			syncResult.ScopesAdded = int(afterCount - beforeCount)

			// Find stale auto-discovered scopes (not in current PRM list)
			var staleAutoScopes []models.OAuthScope
			if len(currentScopeStrings) > 0 {
				tx.Where(
					"(workspace_id = ? OR tenant_id = ?) AND resource_server_id = ? AND is_auto_discovered = true AND scope_string NOT IN ?",
					rs.WorkspaceID, rs.WorkspaceID, rs.ID, currentScopeStrings,
				).Find(&staleAutoScopes)
			} else {
				// PRM legitimately returned empty — remove ALL auto-discovered scopes
				tx.Where(
					"(workspace_id = ? OR tenant_id = ?) AND resource_server_id = ? AND is_auto_discovered = true",
					rs.WorkspaceID, rs.WorkspaceID, rs.ID,
				).Find(&staleAutoScopes)
			}

			for _, scope := range staleAutoScopes {
				// Check for manual mappings referencing this scope
				var manualCount int64
				tx.Model(&models.MCPToolScopeMap{}).
					Where("scope_id = ? AND auto_matched = false", scope.ID).
					Count(&manualCount)

				if manualCount > 0 {
					// Promote to manually managed: keep row, clear auto-discovery flag,
					// delete only its auto-matched mappings.
					tx.Model(&scope).Update("is_auto_discovered", false)
					tx.Where("scope_id = ? AND auto_matched = true", scope.ID).
						Delete(&models.MCPToolScopeMap{})
					syncResult.Warnings = append(syncResult.Warnings,
						fmt.Sprintf("scope %q removed from PRM but has manual mappings — promoted to manually managed",
							scope.ScopeString))
				} else {
					// Safe to delete; ON DELETE CASCADE removes all its mappings
					if err := tx.Delete(&scope).Error; err != nil {
						return fmt.Errorf("delete stale scope %s: %w", scope.ScopeString, err)
					}
					syncResult.ScopesRemoved++
				}
			}

			// Keep scopes_supported aligned to AuthSec-owned OAuth scopes, not to
			// arbitrary MCP/PRM scope declarations from the server.
			supportedScopes, err := syncSupportedScopesFromRegistry(tx, rs.WorkspaceID, rs.ID)
			if err != nil {
				return err
			}
			rs.ScopesSupported = supportedScopes
		} else {
			syncResult.Warnings = append(syncResult.Warnings,
				"PRM unavailable — scope registry and scopes_supported not modified")
		}

		// ── 3b. Tool reconciliation ───────────────────────────────────────
		var upsertedToolIDs []uuid.UUID

		for _, tool := range discovered.Tools {
			existing := models.MCPTool{}
			// Scope to mcp_scan only: never overwrite sdk_manifest or manual entries.
			if err := tx.Where("resource_server_id = ? AND name = ? AND inventory_source = ?",
				rs.ID, tool.Name, models.InventorySourceMCPScan).
				First(&existing).Error; err == nil {
				// Update existing mcp_scan tool, stamp new generation.
				if err := tx.Model(&existing).Updates(map[string]interface{}{
					"title":                tool.Title,
					"description":          tool.Description,
					"input_schema":         tool.InputSchema,
					"annotations":          tool.Annotations,
					"last_scan_generation": nextGeneration,
					"inventory_source":     models.InventorySourceMCPScan,
				}).Error; err != nil {
					return fmt.Errorf("update tool %s: %w", tool.Name, err)
				}
				upsertedToolIDs = append(upsertedToolIDs, existing.ID)
				syncResult.ToolsUpdated++
			} else {
				// If a non-mcp_scan tool with this name already exists, skip — don't duplicate.
				var conflictCount int64
				tx.Model(&models.MCPTool{}).
					Where("resource_server_id = ? AND name = ?", rs.ID, tool.Name).
					Count(&conflictCount)
				if conflictCount > 0 {
					continue // sdk_manifest or manual entry wins; track as upserted so we don't delete it
				}
				newTool := models.MCPTool{
					WorkspaceID:        rs.WorkspaceID,
					ResourceServerID:   rs.ID,
					Name:               tool.Name,
					Title:              tool.Title,
					Description:        tool.Description,
					InputSchema:        tool.InputSchema,
					Annotations:        tool.Annotations,
					LastScanGeneration: nextGeneration,
					InventorySource:    models.InventorySourceMCPScan,
				}
				if err := tx.Create(&newTool).Error; err != nil {
					return fmt.Errorf("create tool %s: %w", tool.Name, err)
				}
				upsertedToolIDs = append(upsertedToolIDs, newTool.ID)
				syncResult.ToolsAdded++
			}
		}

		if len(discovered.Tools) == 0 {
			syncResult.Warnings = append(syncResult.Warnings,
				"MCP server returned empty tools list")
		}

		// Stale tool deletion — only on full scan, only mcp_scan-sourced tools.
		// sdk_manifest and manual tools are never deleted by the scanner.
		if prmFetched {
			var staleToolIDs []uuid.UUID
			staleQ := tx.Model(&models.MCPTool{}).
				Where("resource_server_id = ? AND last_scan_generation < ? AND inventory_source = ?",
					rs.ID, nextGeneration, models.InventorySourceMCPScan)
			if len(upsertedToolIDs) > 0 {
				staleQ = staleQ.Where("id NOT IN ?", upsertedToolIDs)
			}
			if err := staleQ.Pluck("id", &staleToolIDs).Error; err != nil {
				return fmt.Errorf("find stale tools: %w", err)
			}

			if len(staleToolIDs) > 0 {
				// Delete auto-matched mappings for stale tools first
				tx.Where("tool_id IN ? AND auto_matched = true", staleToolIDs).
					Delete(&models.MCPToolScopeMap{})
				// Hard-delete stale tools; manual mappings are also lost via CASCADE.
				// A tool removed from the MCP server has no valid policy to preserve.
				result := tx.Where("id IN ?", staleToolIDs).Delete(&models.MCPTool{})
				if result.Error != nil {
					return fmt.Errorf("delete stale tools: %w", result.Error)
				}
				syncResult.ToolsRemoved = int(result.RowsAffected)
			}
		}

		// ── 3c. Auto-matched mapping reconciliation (full scan only) ──────
		// Full replace: clear then re-apply. This ensures stale convention matches
		// (e.g., a scope that disappeared from PRM) don't linger on surviving tools.
		if prmFetched {
			currentScopeStrings, err := scopesForResourceServer(tx, rs.WorkspaceID, rs.ID)
			if err != nil {
				return err
			}

			if len(upsertedToolIDs) > 0 {
				tx.Where("tool_id IN ? AND auto_matched = true", upsertedToolIDs).
					Delete(&models.MCPToolScopeMap{})
			}

			mappings, unmapped := MapToolsToScopes(discovered.Tools, currentScopeStrings)
			syncResult.UnmappedScopes = unmapped

			for _, m := range mappings {
				var tool models.MCPTool
				if tx.Where("resource_server_id = ? AND name = ?", rs.ID, m.ToolName).
					First(&tool).Error != nil {
					continue
				}
				var scope models.OAuthScope
				if tx.Where("(workspace_id = ? OR tenant_id = ?) AND resource_server_id = ? AND scope_string = ?",
					rs.WorkspaceID, rs.WorkspaceID, rs.ID, m.ScopeString).First(&scope).Error != nil {
					continue
				}
				mapping := models.MCPToolScopeMap{
					ToolID:      tool.ID,
					ScopeID:     scope.ID,
					AutoMatched: true,
					Source:      models.ScopeMapSourceSDKSuggested,
				}
				tx.Where("tool_id = ? AND scope_id = ?", tool.ID, scope.ID).
					FirstOrCreate(&mapping)
			}

			// ── 3d. Reconcile default roles (inside transaction) ──
			s.reconcileDefaultRoles(rs, NewScopeRegistryService(tx), tx)
		}

		// ── 3e. Commit lifecycle state atomically with tool/scope changes ─
		//
		// Generation guard: verify scan_generation still equals nextGeneration.
		// If another scan stole the lock after the 10-minute stale threshold,
		// it incremented scan_generation. RowsAffected == 0 means this scan
		// was superseded and its results must be discarded.
		now := time.Now().UTC()
		if prmFetched {
			// Full scan: advance the serving pointer.
			// state always becomes 'needs_setup' after scan — admin must activate.
			// Status retains 'ready'/'degraded' for backwards compat with older callers.
			finalStatus := "ready"
			if len(syncResult.Warnings) > 0 {
				finalStatus = "degraded"
			}
			result := tx.Model(rs).
				Where("id = ? AND scan_generation = ?", rs.ID, nextGeneration).
				Updates(map[string]interface{}{
					"last_successful_generation": nextGeneration,
					"status":                     finalStatus,
					"state":                      models.RSStateNeedsSetup,
					"last_scan_status":           "success",
					"last_scan_error":            nil,
					"last_scan_completed_at":     &now,
					"scan_in_progress":           false,
				})
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected == 0 {
				return fmt.Errorf("scan generation %d was superseded by a concurrent scan — discarding results", nextGeneration)
			}
			return nil
		}
		// Protected-server outcome: DON'T advance last_successful_generation (option a).
		// The prior serving snapshot (if any) continues to be served.
		// State: if the RS is already 'ready', preserve it — protected scans after
		// activation are normal (the RS legitimately requires auth for tools/list)
		// and must not regress an activated RS to needs_setup. Only flip to
		// needs_setup when the RS has not yet been activated.
		if protectedServer {
			updates := map[string]interface{}{
				"status":                 "degraded",
				"last_scan_status":       "success",
				"last_scan_error":        nil,
				"last_scan_completed_at": &now,
				"scan_in_progress":       false,
			}
			if rs.State != models.RSStateReady {
				updates["state"] = models.RSStateNeedsSetup
			}
			result := tx.Model(rs).
				Where("id = ? AND scan_generation = ?", rs.ID, nextGeneration).
				Updates(updates)
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected == 0 {
				return fmt.Errorf("scan generation %d was superseded by a concurrent scan — discarding results", nextGeneration)
			}
			return nil
		}
		// Partial scan (PRM unavailable): do NOT advance last_successful_generation.
		// Same state-preservation rule as protected scans — a partial scan against
		// an already-ready RS is not a setup regression.
		partialUpdates := map[string]interface{}{
			"status":                 "degraded",
			"last_scan_status":       "partial",
			"last_scan_error":        nil,
			"last_scan_completed_at": &now,
			"scan_in_progress":       false,
		}
		if rs.State != models.RSStateReady {
			partialUpdates["state"] = models.RSStateNeedsSetup
		}
		result := tx.Model(rs).
			Where("id = ? AND scan_generation = ?", rs.ID, nextGeneration).
			Updates(partialUpdates)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return fmt.Errorf("scan generation %d was superseded by a concurrent scan — discarding results", nextGeneration)
		}
		return nil
	})

	if txErr != nil {
		syncResult.FailureReason = txErr.Error()
		// Pass nextGeneration so a superseded scan (txErr = "superseded" sentinel)
		// cannot clear the newer scan's lock. Generation guard makes this safe in
		// all cases: genuine DB error → guard matches → status updated correctly;
		// superseded → guard mismatches → no-op.
		s.markScanFailed(rs, nextGeneration, txErr.Error())
		return syncResult, txErr
	}

	log.Printf("[MCP_DISCOVERY] RS %s gen=%d: +%d/~%d/-%d tools, +%d/-%d scopes, %d warnings",
		rs.Name, nextGeneration,
		syncResult.ToolsAdded, syncResult.ToolsUpdated, syncResult.ToolsRemoved,
		syncResult.ScopesAdded, syncResult.ScopesRemoved,
		len(syncResult.Warnings))

	return syncResult, nil
}

func scopesForResourceServer(tx *gorm.DB, workspaceID, rsID uuid.UUID) ([]string, error) {
	var scopeStrings []string
	if err := tx.Model(&models.OAuthScope{}).
		Where("(workspace_id = ? OR tenant_id = ?) AND resource_server_id = ?", workspaceID, workspaceID, rsID).
		Order("scope_string ASC").
		Pluck("scope_string", &scopeStrings).Error; err != nil {
		return nil, fmt.Errorf("list resource server scopes: %w", err)
	}
	return scopeStrings, nil
}

// markScanFailed updates RS status to degraded on a hard failure.
//
// The generation parameter MUST be the scan_generation value this scan claimed in
// Stage 1. The UPDATE is guarded with AND scan_generation = generation so that a
// superseded scan (whose generation was overwritten by a newer scan stealing the
// stale lock) cannot clear the newer scan's lock or overwrite its status.
// If RowsAffected == 0 the update is a silent no-op — correct behaviour.
//
// Critically does NOT touch last_successful_generation — the old serving snapshot
// remains valid and continues to be served by SDKPolicy / GetScopeMatrix.
func (s *ResourceServerService) markScanFailed(rs *models.ResourceServer, generation int, reason string) {
	now := time.Now().UTC()
	scanStatus := "failure"
	s.db.Model(rs).
		Where("id = ? AND scan_generation = ?", rs.ID, generation).
		Updates(map[string]interface{}{
			"status":                 "degraded",
			"last_scan_status":       &scanStatus,
			"last_scan_error":        &reason,
			"last_scan_completed_at": &now,
			"scan_in_progress":       false,
		})
}

// ExposedMarkScanFailed is a test-only export of markScanFailed.
// It MUST NOT be called from production code.
func (s *ResourceServerService) ExposedMarkScanFailed(rs *models.ResourceServer, generation int, reason string) {
	s.markScanFailed(rs, generation, reason)
}

// isScopeReadonly is the deterministic rule for readonly role generation.
// Scopes containing "read" or ":list" are read-only.
// Scopes containing write/delete/admin/create or ending in ":*" are not.
func isScopeReadonly(scopeString string) bool {
	lower := strings.ToLower(scopeString)
	return strings.Contains(lower, "read") || strings.Contains(lower, ":list") ||
		(!strings.Contains(lower, "write") && !strings.Contains(lower, "delete") &&
			!strings.Contains(lower, "admin") && !strings.Contains(lower, "create") &&
			!strings.HasSuffix(lower, ":*"))
}

// reconcileDefaultRoles creates or updates "admin", "readonly", and "viewer"
// roles for a resource server. Unlike the old seedDefaultRoles, this does NOT
// early-exit when roles already exist — it reconciles permissions so new/deleted
// scopes are reflected in existing roles (correctness fix #6).
//
// Role names use rs-<rs_id>:admin / :readonly / :viewer. The "viewer" role is
// created at RS-creation time (Create method) with zero perms; this function
// is what populates it once scopes exist, otherwise activation gate
// "step 5: default role grants ≥1 scope" stays false forever.
//
// Must be called with a transaction-scoped db so role creation is part of the
// reconciliation commit.
func (s *ResourceServerService) reconcileDefaultRoles(rs *models.ResourceServer, scopeRegistry *ScopeRegistryService, db *gorm.DB) {
	adminRoleName := fmt.Sprintf("rs-%s:admin", rs.ID.String())
	readonlyRoleName := fmt.Sprintf("rs-%s:readonly", rs.ID.String())
	viewerRoleName := fmt.Sprintf("rs-%s:viewer", rs.ID.String())

	var existingAdmin, existingReadonly, existingViewer models.RBACRole
	adminExists := db.Where("name = ? AND tenant_id = ?", adminRoleName, rs.WorkspaceID).First(&existingAdmin).Error == nil
	readonlyExists := db.Where("name = ? AND tenant_id = ?", readonlyRoleName, rs.WorkspaceID).First(&existingReadonly).Error == nil
	viewerExists := db.Where("name = ? AND tenant_id = ?", viewerRoleName, rs.WorkspaceID).First(&existingViewer).Error == nil

	// Removed early-exit: always reconcile permissions even when both roles exist.

	scopes, err := scopeRegistry.ListByResourceServer(rs.WorkspaceID, rs.ID)
	if err != nil || len(scopes) == 0 {
		return
	}

	// Build permissions and oauth_scope_permission bridges (idempotent regardless of role state)
	var allPermIDs []uuid.UUID
	var readPermIDs []uuid.UUID
	for _, scope := range scopes {
		perm := models.RBACPermission{
			WorkspaceID: &rs.WorkspaceID,
			Resource:    scope.ScopeString,
			Action:      "access",
			Description: fmt.Sprintf("OAuth scope: %s", scope.DisplayName),
		}
		existing := models.RBACPermission{}
		if err := db.Where("tenant_id = ? AND resource = ? AND action = ?",
			rs.WorkspaceID, perm.Resource, perm.Action).First(&existing).Error; err == nil {
			perm = existing
		} else {
			db.Create(&perm)
		}
		allPermIDs = append(allPermIDs, perm.ID)
		if isScopeReadonly(scope.ScopeString) {
			readPermIDs = append(readPermIDs, perm.ID)
		}
		osp := models.OAuthScopePermission{ScopeID: scope.ID, PermissionID: perm.ID}
		db.Where("scope_id = ? AND permission_id = ?", scope.ID, perm.ID).FirstOrCreate(&osp)
	}

	if !adminExists {
		adminRole := models.RBACRole{
			WorkspaceID: &rs.WorkspaceID,
			Name:        adminRoleName,
			Description: fmt.Sprintf("Full access to %s (auto-generated)", rs.Name),
		}
		db.Create(&adminRole)
		for _, permID := range allPermIDs {
			db.FirstOrCreate(&models.RolePermission{RoleID: adminRole.ID, PermissionID: permID})
		}
		log.Printf("[MCP_DISCOVERY] reconcileDefaultRoles: created role %q (%d perms) for RS %s",
			adminRoleName, len(allPermIDs), rs.Name)
	} else {
		// Reconcile: ensure role_permissions has all current scope permissions (add missing rows).
		for _, permID := range allPermIDs {
			db.FirstOrCreate(&models.RolePermission{RoleID: existingAdmin.ID, PermissionID: permID})
		}
		log.Printf("[MCP_DISCOVERY] reconcileDefaultRoles: reconciled admin role for RS %s", rs.Name)
	}

	if !readonlyExists {
		readonlyRole := models.RBACRole{
			WorkspaceID: &rs.WorkspaceID,
			Name:        readonlyRoleName,
			Description: fmt.Sprintf("Read-only access to %s (auto-generated)", rs.Name),
		}
		db.Create(&readonlyRole)
		for _, permID := range readPermIDs {
			db.FirstOrCreate(&models.RolePermission{RoleID: readonlyRole.ID, PermissionID: permID})
		}
		log.Printf("[MCP_DISCOVERY] reconcileDefaultRoles: created role %q (%d perms) for RS %s",
			readonlyRoleName, len(readPermIDs), rs.Name)
	} else {
		// Reconcile: ensure role_permissions for readonly role matches current read-scope permissions.
		for _, permID := range readPermIDs {
			db.FirstOrCreate(&models.RolePermission{RoleID: existingReadonly.ID, PermissionID: permID})
		}
		log.Printf("[MCP_DISCOVERY] reconcileDefaultRoles: reconciled readonly role for RS %s", rs.Name)
	}

	// Viewer role: default role assigned to first-time users via the access policy.
	// Created at RS-creation time but populated lazily here once scopes exist.
	// Viewer gets the same read-scope set as readonly — admins can later customize
	// via the roles UI. The activation gate "step 5: default role grants ≥1 scope"
	// depends on this populating viewer's role_permissions.
	viewerPermIDs := readPermIDs
	if len(viewerPermIDs) == 0 {
		// No read-only scopes detected — fall back to all scopes so the gate
		// can pass for RSes whose scope strings don't match the read-only heuristic.
		viewerPermIDs = allPermIDs
	}
	if !viewerExists {
		viewerRole := models.RBACRole{
			WorkspaceID: &rs.WorkspaceID,
			Name:        viewerRoleName,
			Description: fmt.Sprintf("Default viewer role for %s (auto-generated)", rs.Name),
		}
		db.Create(&viewerRole)
		for _, permID := range viewerPermIDs {
			db.FirstOrCreate(&models.RolePermission{RoleID: viewerRole.ID, PermissionID: permID})
		}
		log.Printf("[MCP_DISCOVERY] reconcileDefaultRoles: created role %q (%d perms) for RS %s",
			viewerRoleName, len(viewerPermIDs), rs.Name)
	} else {
		for _, permID := range viewerPermIDs {
			db.FirstOrCreate(&models.RolePermission{RoleID: existingViewer.ID, PermissionID: permID})
		}
		log.Printf("[MCP_DISCOVERY] reconcileDefaultRoles: reconciled viewer role for RS %s", rs.Name)
	}
}

// ── Activation gate ──────────────────────────────────────────────────────────────────────────────

// ActivationGateError carries a structured list of failed gates so callers can
// render a human-readable error and the wizard can highlight the blocking step.
type ActivationGateError struct {
	Failed []string `json:"failed"`
}

func (e ActivationGateError) Error() string {
	return fmt.Sprintf("activation blocked: %v", e.Failed)
}

func policyEffectiveToolQuery(db *gorm.DB, rs *models.ResourceServer) *gorm.DB {
	return db.Model(&models.MCPTool{}).
		Where(
			"resource_server_id = ? AND (inventory_source IN ? OR last_scan_generation = ?)",
			rs.ID,
			[]string{models.InventorySourceSDKManifest, models.InventorySourceManual},
			rs.LastSuccessfulGeneration,
		)
}

// ChecklistStep represents one wizard step's completion state.
type ChecklistStep struct {
	Step     int    `json:"step"`
	Name     string `json:"name"`
	Complete bool   `json:"complete"`
	Detail   string `json:"detail,omitempty"`
}

// SetupChecklist returns the step-by-step status for the wizard rail.
func (s *ResourceServerService) SetupChecklist(rsID uuid.UUID, tenantID uuid.UUID) ([]ChecklistStep, error) {
	rs, err := s.GetByIDAndTenant(rsID.String(), tenantID.String())
	if err != nil {
		return nil, err
	}

	// Step 1: Register (always complete once RS exists)
	steps := []ChecklistStep{
		{Step: 1, Name: "Register", Complete: true},
	}

	// Step 2: Tool inventory — ≥1 tool
	var toolCount int64
	policyEffectiveToolQuery(s.db, rs).Count(&toolCount)
	steps = append(steps, ChecklistStep{
		Step:     2,
		Name:     "Tool inventory",
		Complete: toolCount > 0,
		Detail:   fmt.Sprintf("%d tools", toolCount),
	})

	// Step 3: Define scopes — ≥1 scope
	var scopeCount int64
	s.db.Model(&models.OAuthScope{}).Where("resource_server_id = ?", rs.ID).Count(&scopeCount)
	steps = append(steps, ChecklistStep{
		Step:     3,
		Name:     "Define scopes",
		Complete: scopeCount > 0,
		Detail:   fmt.Sprintf("%d scopes", scopeCount),
	})

	// Step 4: Map tools — every non-public tool has ≥1 admin_override mapping
	var unmappedCount int64
	s.db.Raw(`
		SELECT COUNT(*) FROM mcp_tools mt
		 WHERE mt.resource_server_id = ?
		   AND (mt.inventory_source IN ? OR mt.last_scan_generation = ?)
		   AND mt.is_public = false
		   AND NOT EXISTS (
			   SELECT 1 FROM mcp_tool_scope_map m
			    WHERE m.tool_id = mt.id
			      AND m.source = 'admin_override'
		   )
	`, rs.ID, []string{models.InventorySourceSDKManifest, models.InventorySourceManual}, rs.LastSuccessfulGeneration).Scan(&unmappedCount)
	step4Complete := toolCount > 0 && unmappedCount == 0
	steps = append(steps, ChecklistStep{
		Step:     4,
		Name:     "Map tools to scopes",
		Complete: step4Complete,
		Detail:   fmt.Sprintf("%d unmapped", unmappedCount),
	})

	// Step 5: Default role — viewer exists and has ≥1 scope
	viewerName := fmt.Sprintf("rs-%s:viewer", rs.ID.String())
	var viewerRole models.RBACRole
	viewerExists := s.db.Where("name = ? AND tenant_id = ?", viewerName, rs.WorkspaceID).First(&viewerRole).Error == nil
	var viewerPermCount int64
	if viewerExists {
		s.db.Model(&models.RolePermission{}).Where("role_id = ?", viewerRole.ID).Count(&viewerPermCount)
	}
	steps = append(steps, ChecklistStep{
		Step:     5,
		Name:     "Default role",
		Complete: viewerExists && viewerPermCount > 0,
		Detail:   fmt.Sprintf("viewer: %d scopes", viewerPermCount),
	})

	// Step 6: Activate
	canActivate := toolCount > 0 && scopeCount > 0 && unmappedCount == 0 && viewerExists && viewerPermCount > 0
	steps = append(steps, ChecklistStep{
		Step:     6,
		Name:     "Activate",
		Complete: rs.State == models.RSStateReady,
		Detail:   fmt.Sprintf("can_activate=%v", canActivate),
	})

	return steps, nil
}

// ActivationPreview returns the summary card shown before activation (§4.1 step 6).
func (s *ResourceServerService) ActivationPreview(rsID uuid.UUID, tenantID uuid.UUID) (map[string]interface{}, error) {
	rs, err := s.GetByIDAndTenant(rsID.String(), tenantID.String())
	if err != nil {
		return nil, err
	}

	var tools []models.MCPTool
	policyEffectiveToolQuery(s.db, rs).Find(&tools)

	var scopes []models.OAuthScope
	s.db.Where("resource_server_id = ?", rs.ID).Find(&scopes)

	totalTools := len(tools)
	publicTools := 0
	mappedTools := 0
	unmappedTools := 0
	publicToolNames := make([]string, 0)

	for _, t := range tools {
		if t.IsPublic {
			publicTools++
			publicToolNames = append(publicToolNames, t.Name)
		}
		var overrideCount int64
		s.db.Model(&models.MCPToolScopeMap{}).
			Where("tool_id = ? AND source = 'admin_override'", t.ID).
			Count(&overrideCount)
		if t.IsPublic || overrideCount > 0 {
			mappedTools++
		} else {
			unmappedTools++
		}
	}

	// Scope counters
	type scopeInfo struct {
		ScopeString string `json:"scope_string"`
		DisplayName string `json:"display_name"`
		ToolCount   int64  `json:"tool_count"`
	}
	scopeInfos := make([]scopeInfo, 0, len(scopes))
	for _, sc := range scopes {
		var cnt int64
		s.db.Model(&models.MCPToolScopeMap{}).
			Where("scope_id = ? AND source = 'admin_override'", sc.ID).
			Count(&cnt)
		scopeInfos = append(scopeInfos, scopeInfo{
			ScopeString: sc.ScopeString,
			DisplayName: sc.DisplayName,
			ToolCount:   cnt,
		})
	}

	// Default role info
	viewerName := fmt.Sprintf("rs-%s:viewer", rs.ID.String())
	var viewerRole models.RBACRole
	viewerScopeStrings := make([]string, 0)
	if s.db.Where("name = ? AND tenant_id = ?", viewerName, rs.WorkspaceID).First(&viewerRole).Error == nil {
		var perms []models.RBACPermission
		s.db.Joins("JOIN role_permissions rp ON rp.permission_id = permissions.id").
			Where("rp.role_id = ?", viewerRole.ID).
			Find(&perms)
		for _, p := range perms {
			viewerScopeStrings = append(viewerScopeStrings, p.Resource)
		}
	}

	preview := map[string]interface{}{
		"tools": map[string]interface{}{
			"total":    totalTools,
			"public":   publicTools,
			"mapped":   mappedTools,
			"unmapped": unmappedTools,
		},
		"scopes":                scopeInfos,
		"scope_count":           len(scopes),
		"default_role":          viewerName,
		"viewer_scopes":         viewerScopeStrings,
		"public_tool_names":     publicToolNames,
		"first_time_user_grant": viewerScopeStrings,
		"can_activate":          unmappedTools == 0 && totalTools > 0 && len(scopes) > 0 && len(viewerScopeStrings) > 0,
	}
	return preview, nil
}

// Activate flips state to 'ready' after verifying all gates. Returns
// ActivationGateError if any gate fails.
func (s *ResourceServerService) Activate(rsID uuid.UUID, tenantID uuid.UUID, activatedByUserID uuid.UUID) error {
	rs, err := s.GetByIDAndTenant(rsID.String(), tenantID.String())
	if err != nil {
		return err
	}

	// Ensure default roles (admin/readonly/viewer) are reconciled against the
	// current scope set BEFORE evaluating activation gates. Manual scope creation
	// goes through the CreateScope controller and never triggers reconciliation
	// from DiscoverAndSync, so without this call the viewer role stays empty
	// and gate "step_5_viewer_role_empty" fails forever.
	s.db.Transaction(func(tx *gorm.DB) error {
		s.reconcileDefaultRoles(rs, NewScopeRegistryService(tx), tx)
		return nil
	})

	var failed []string

	// Gate 1: ≥1 tool
	var toolCount int64
	policyEffectiveToolQuery(s.db, rs).Count(&toolCount)
	if toolCount == 0 {
		failed = append(failed, "step_2_no_tools")
	}

	// Gate 2: ≥1 scope
	var scopeCount int64
	s.db.Model(&models.OAuthScope{}).Where("resource_server_id = ?", rs.ID).Count(&scopeCount)
	if scopeCount == 0 {
		failed = append(failed, "step_3_no_scopes")
	}

	// Gate 3: every non-public tool has ≥1 admin_override mapping
	var unmappedCount int64
	s.db.Raw(`
		SELECT COUNT(*) FROM mcp_tools mt
		 WHERE mt.resource_server_id = ?
		   AND (mt.inventory_source IN ? OR mt.last_scan_generation = ?)
		   AND mt.is_public = false
		   AND NOT EXISTS (
			   SELECT 1 FROM mcp_tool_scope_map m
			    WHERE m.tool_id = mt.id
			      AND m.source = 'admin_override'
		   )
	`, rs.ID, []string{models.InventorySourceSDKManifest, models.InventorySourceManual}, rs.LastSuccessfulGeneration).Scan(&unmappedCount)
	if unmappedCount > 0 {
		failed = append(failed, fmt.Sprintf("step_4_unmapped_tool_count: %d", unmappedCount))
	}

	// Gate 4: viewer role has ≥1 scope
	viewerName := fmt.Sprintf("rs-%s:viewer", rs.ID.String())
	var viewerRole models.RBACRole
	viewerExists := s.db.Where("name = ? AND tenant_id = ?", viewerName, rs.WorkspaceID).First(&viewerRole).Error == nil
	if !viewerExists {
		failed = append(failed, "step_5_no_viewer_role")
	} else {
		var viewerPermCount int64
		s.db.Model(&models.RolePermission{}).Where("role_id = ?", viewerRole.ID).Count(&viewerPermCount)
		if viewerPermCount == 0 {
			failed = append(failed, "step_5_viewer_role_empty")
		}
	}

	if len(failed) > 0 {
		return ActivationGateError{Failed: failed}
	}

	now := time.Now().UTC()
	return s.db.Model(rs).Updates(map[string]interface{}{
		"state":              models.RSStateReady,
		"status":             "ready",
		"setup_completed_at": now,
		"setup_completed_by": activatedByUserID,
	}).Error
}
