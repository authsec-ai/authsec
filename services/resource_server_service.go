package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/url"
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
	TenantID          uuid.UUID `json:"tenant_id"`
	Name              string    `json:"name"`
	PublicBaseURL     string    `json:"public_base_url"`
	ProtectedBasePath string    `json:"protected_base_path"`
	ScopesSupported   []string  `json:"scopes_supported"`
	RegistrationModes []string  `json:"registration_modes"`
}

type ResourceServerResponse struct {
	ID                    string   `json:"id"`
	IssuerURL             string   `json:"issuer_url"`
	ResourceURL           string   `json:"resource_url"`
	JWKSURI               string   `json:"jwks_uri"`
	IntrospectionEndpoint string   `json:"introspection_endpoint"`
	IntrospectionSecret   string   `json:"introspection_secret,omitempty"`
	ValidationMode        string   `json:"validation_mode"`
	ScopesSupported       []string `json:"scopes_supported"`
	Status                string   `json:"status"`
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

	rs := &models.ResourceServer{
		TenantID:                req.TenantID,
		Name:                    req.Name,
		PublicBaseURL:           publicURL,
		ProtectedBasePath:       basePath,
		ResourceURI:             resourceURI,
		ScopesSupported:         req.ScopesSupported,
		RegistrationModes:       modes,
		IntrospectionSecret:     "", // Not stored in plaintext for new rows
		IntrospectionSecretHash: string(hashedSecret),
		Active:                  true,
		Status:                  "pending_scan",
		ScanGeneration:          0,
	}

	if err := s.db.Create(rs).Error; err != nil {
		return nil, nil, fmt.Errorf("create resource server: %w", err)
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
		ValidationMode:        "auto",
		ScopesSupported:       rs.ScopesSupported,
		Status:                rs.Status,
	}

	return rs, resp, nil
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
	client := mcpclient.NewClient()
	discovered, err := client.Discover(ctx, resourceURI)
	if err != nil {
		// tools/list failed — hard failure, nothing to commit.
		// Pass nextGeneration so markScanFailed only updates the row if this scan
		// still owns the lock (generation guard). Superseded scans are a no-op.
		syncResult.FailureReason = err.Error()
		s.markScanFailed(rs, nextGeneration, err.Error())
		return syncResult, fmt.Errorf("MCP discovery failed: %w", err)
	}

	// prmFetched distinguishes:
	//   nil  → PRM fetch failed (non-fatal per spec); partial scan
	//   non-nil → PRM fetched; may have empty ScopesSupported (legitimately)
	prmFetched := discovered.PRM != nil

	// ── Stage 3: Reconciliation (single atomic transaction) ─────────────────
	txErr := s.db.Transaction(func(tx *gorm.DB) error {

		// ── 3a. Scope reconciliation (full scan only) ─────────────────────
		if prmFetched {
			currentScopeStrings := discovered.PRM.ScopesSupported // may be []

			scopeRegistry := NewScopeRegistryService(tx)

			// Count existing auto-discovered scopes before upsert
			var beforeCount int64
			tx.Model(&models.OAuthScope{}).
				Where("tenant_id = ? AND resource_server_id = ? AND is_auto_discovered = true",
					rs.TenantID, rs.ID).Count(&beforeCount)

			if len(currentScopeStrings) > 0 {
				if _, err := scopeRegistry.SyncFromPRM(rs.TenantID, rs.ID, currentScopeStrings); err != nil {
					return fmt.Errorf("scope sync: %w", err)
				}
			}

			var afterCount int64
			tx.Model(&models.OAuthScope{}).
				Where("tenant_id = ? AND resource_server_id = ? AND is_auto_discovered = true",
					rs.TenantID, rs.ID).Count(&afterCount)
			syncResult.ScopesAdded = int(afterCount - beforeCount)

			// Find stale auto-discovered scopes (not in current PRM list)
			var staleAutoScopes []models.OAuthScope
			if len(currentScopeStrings) > 0 {
				tx.Where(
					"tenant_id = ? AND resource_server_id = ? AND is_auto_discovered = true AND scope_string NOT IN ?",
					rs.TenantID, rs.ID, currentScopeStrings,
				).Find(&staleAutoScopes)
			} else {
				// PRM legitimately returned empty — remove ALL auto-discovered scopes
				tx.Where(
					"tenant_id = ? AND resource_server_id = ? AND is_auto_discovered = true",
					rs.TenantID, rs.ID,
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

			// Update scopes_supported to reflect PRM (only on full scan)
			if err := tx.Model(rs).Update("scopes_supported", pq.StringArray(currentScopeStrings)).Error; err != nil {
				return fmt.Errorf("update scopes_supported: %w", err)
			}
		} else {
			syncResult.Warnings = append(syncResult.Warnings,
				"PRM unavailable — scope registry and scopes_supported not modified")
		}

		// ── 3b. Tool reconciliation ───────────────────────────────────────
		var upsertedToolIDs []uuid.UUID

		for _, tool := range discovered.Tools {
			existing := models.MCPTool{}
			if err := tx.Where("resource_server_id = ? AND name = ?", rs.ID, tool.Name).
				First(&existing).Error; err == nil {
				// Update existing tool, stamp new generation
				if err := tx.Model(&existing).Updates(map[string]interface{}{
					"title":               tool.Title,
					"description":         tool.Description,
					"input_schema":        tool.InputSchema,
					"annotations":         tool.Annotations,
					"last_scan_generation": nextGeneration,
				}).Error; err != nil {
					return fmt.Errorf("update tool %s: %w", tool.Name, err)
				}
				upsertedToolIDs = append(upsertedToolIDs, existing.ID)
				syncResult.ToolsUpdated++
			} else {
				newTool := models.MCPTool{
					TenantID:           rs.TenantID,
					ResourceServerID:   rs.ID,
					Name:               tool.Name,
					Title:              tool.Title,
					Description:        tool.Description,
					InputSchema:        tool.InputSchema,
					Annotations:        tool.Annotations,
					LastScanGeneration: nextGeneration,
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

		// Stale tool deletion — only on full scan.
		// Skipped on partial scan to preserve the old serving snapshot's integrity.
		if prmFetched {
			var staleToolIDs []uuid.UUID
			staleQ := tx.Model(&models.MCPTool{}).
				Where("resource_server_id = ? AND last_scan_generation < ?", rs.ID, nextGeneration)
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
			currentScopeStrings := discovered.PRM.ScopesSupported

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
				if tx.Where("tenant_id = ? AND resource_server_id = ? AND scope_string = ?",
					rs.TenantID, rs.ID, m.ScopeString).First(&scope).Error != nil {
					continue
				}
				mapping := models.MCPToolScopeMap{
					ToolID:      tool.ID,
					ScopeID:     scope.ID,
					AutoMatched: true,
				}
				tx.Where("tool_id = ? AND scope_id = ?", tool.ID, scope.ID).
					FirstOrCreate(&mapping)
			}

			// ── 3d. Seed default roles (first scan only, inside transaction) ──
			s.seedDefaultRoles(rs, NewScopeRegistryService(tx), tx)
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
			// last_scan_status = "success" whenever last_successful_generation advances —
			// even when warnings exist. "partial" is reserved exclusively for PRM-missing
			// scans where the serving pointer does NOT advance.
			finalStatus := "ready"
			if len(syncResult.Warnings) > 0 {
				finalStatus = "degraded"
			}
			result := tx.Model(rs).
				Where("id = ? AND scan_generation = ?", rs.ID, nextGeneration).
				Updates(map[string]interface{}{
					"last_successful_generation": nextGeneration,
					"status":                     finalStatus,
					"last_scan_status":            "success",
					"last_scan_error":             nil,
					"last_scan_completed_at":      &now,
					"scan_in_progress":            false,
				})
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected == 0 {
				return fmt.Errorf("scan generation %d was superseded by a concurrent scan — discarding results", nextGeneration)
			}
			return nil
		}
		// Partial scan (PRM unavailable): do NOT advance last_successful_generation.
		// last_scan_status = "partial" exclusively means the serving pointer was NOT moved.
		result := tx.Model(rs).
			Where("id = ? AND scan_generation = ?", rs.ID, nextGeneration).
			Updates(map[string]interface{}{
				"status":                "degraded",
				"last_scan_status":      "partial",
				"last_scan_error":       nil,
				"last_scan_completed_at": &now,
				"scan_in_progress":      false,
			})
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
			"status":                "degraded",
			"last_scan_status":      &scanStatus,
			"last_scan_error":       &reason,
			"last_scan_completed_at": &now,
			"scan_in_progress":      false,
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

// seedDefaultRoles creates "admin" (all scopes) and "readonly" (:read scopes) roles
// for a resource server, keyed by RS UUID for stability across renames.
//
// Role names use the format rs-<rs_id>:admin and rs-<rs_id>:readonly.
// Each role is checked and created independently so a partial previous run is recoverable.
// Must be called with a transaction-scoped db so role creation is part of the
// reconciliation commit.
func (s *ResourceServerService) seedDefaultRoles(rs *models.ResourceServer, scopeRegistry *ScopeRegistryService, db *gorm.DB) {
	adminRoleName := fmt.Sprintf("rs-%s:admin", rs.ID.String())
	readonlyRoleName := fmt.Sprintf("rs-%s:readonly", rs.ID.String())

	var existingAdmin, existingReadonly models.RBACRole
	adminExists := db.Where("name = ? AND tenant_id = ?", adminRoleName, rs.TenantID).First(&existingAdmin).Error == nil
	readonlyExists := db.Where("name = ? AND tenant_id = ?", readonlyRoleName, rs.TenantID).First(&existingReadonly).Error == nil

	if adminExists && readonlyExists {
		log.Printf("[MCP_DISCOVERY] seedDefaultRoles: skipping (both roles exist) for RS %s", rs.Name)
		return
	}

	scopes, err := scopeRegistry.ListByResourceServer(rs.TenantID, rs.ID)
	if err != nil || len(scopes) == 0 {
		return
	}

	// Build permissions and oauth_scope_permission bridges (idempotent regardless of role state)
	var allPermIDs []uuid.UUID
	var readPermIDs []uuid.UUID
	for _, scope := range scopes {
		perm := models.RBACPermission{
			TenantID:    &rs.TenantID,
			Resource:    scope.ScopeString,
			Action:      "access",
			Description: fmt.Sprintf("OAuth scope: %s", scope.DisplayName),
		}
		existing := models.RBACPermission{}
		if err := db.Where("tenant_id = ? AND resource = ? AND action = ?",
			rs.TenantID, perm.Resource, perm.Action).First(&existing).Error; err == nil {
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
			TenantID:    &rs.TenantID,
			Name:        adminRoleName,
			Description: fmt.Sprintf("Full access to %s (auto-generated)", rs.Name),
		}
		db.Create(&adminRole)
		for _, permID := range allPermIDs {
			db.FirstOrCreate(&models.RolePermission{RoleID: adminRole.ID, PermissionID: permID})
		}
		log.Printf("[MCP_DISCOVERY] seedDefaultRoles: created role %q (%d perms) for RS %s",
			adminRoleName, len(allPermIDs), rs.Name)
	} else {
		log.Printf("[MCP_DISCOVERY] seedDefaultRoles: skipping admin role (already exists) for RS %s", rs.Name)
	}

	if !readonlyExists {
		readonlyRole := models.RBACRole{
			TenantID:    &rs.TenantID,
			Name:        readonlyRoleName,
			Description: fmt.Sprintf("Read-only access to %s (auto-generated)", rs.Name),
		}
		db.Create(&readonlyRole)
		for _, permID := range readPermIDs {
			db.FirstOrCreate(&models.RolePermission{RoleID: readonlyRole.ID, PermissionID: permID})
		}
		log.Printf("[MCP_DISCOVERY] seedDefaultRoles: created role %q (%d perms) for RS %s",
			readonlyRoleName, len(readPermIDs), rs.Name)
	} else {
		log.Printf("[MCP_DISCOVERY] seedDefaultRoles: skipping readonly role (already exists) for RS %s", rs.Name)
	}
}
