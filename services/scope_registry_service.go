package services

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrInvalidParentScope is returned when parent_scope_id fails ownership/domain validation.
// Handlers use errors.Is(err, ErrInvalidParentScope) to distinguish 400 from 404.
var ErrInvalidParentScope = errors.New("parent_scope_id not found in this tenant/resource server")

// ScopeRegistryService manages the OAuth scope catalog.
type ScopeRegistryService struct {
	db *gorm.DB
}

func NewScopeRegistryService(db *gorm.DB) *ScopeRegistryService {
	return &ScopeRegistryService{db: db}
}

// SyncFromPRM upserts scopes from a PRM scopes_supported list.
// Auto-discovered scopes get is_auto_discovered=true. Existing admin-created scopes are untouched.
func (s *ScopeRegistryService) SyncFromPRM(workspaceID, resourceServerID uuid.UUID, scopesSupported []string) ([]models.OAuthScope, error) {
	var upserted []models.OAuthScope

	for _, scopeStr := range scopesSupported {
		scopeStr = strings.TrimSpace(scopeStr)
		if scopeStr == "" {
			continue
		}

		scope := models.OAuthScope{
			WorkspaceID:         workspaceID,
			ResourceServerID: &resourceServerID,
			ScopeString:      scopeStr,
			DisplayName:      generateDisplayName(scopeStr),
			RiskLevel:        inferRiskLevel(scopeStr),
			IsAutoDiscovered: true,
			Source:           "discovered",
		}

		// Upsert: create if not exists, don't overwrite admin-edited fields
		result := s.db.Where(
			"workspace_id = ? AND resource_server_id = ? AND scope_string = ?",
			workspaceID, resourceServerID, scopeStr,
		).FirstOrCreate(&scope)

		if result.Error != nil {
			return upserted, fmt.Errorf("upsert scope %q: %w", scopeStr, result.Error)
		}
		upserted = append(upserted, scope)
	}

	// Build hierarchy for wildcard scopes
	if err := s.buildHierarchy(workspaceID, resourceServerID); err != nil {
		return upserted, fmt.Errorf("build hierarchy: %w", err)
	}

	return upserted, nil
}

// buildHierarchy sets parent_scope_id for scopes that follow the colon-delimited convention.
// e.g., "tools:weather:read" gets parent "tools:weather:*", which gets parent "tools:*".
func (s *ScopeRegistryService) buildHierarchy(workspaceID, rsID uuid.UUID) error {
	var scopes []models.OAuthScope
	if err := s.db.Where("workspace_id = ? AND resource_server_id = ?", workspaceID, rsID).Find(&scopes).Error; err != nil {
		return err
	}

	scopeByString := make(map[string]*models.OAuthScope, len(scopes))
	for i := range scopes {
		scopeByString[scopes[i].ScopeString] = &scopes[i]
	}

	for i := range scopes {
		parentStr := findParentScope(scopes[i].ScopeString)
		if parentStr == "" {
			continue
		}
		if parent, ok := scopeByString[parentStr]; ok {
			if scopes[i].ParentScopeID == nil || *scopes[i].ParentScopeID != parent.ID {
				s.db.Model(&scopes[i]).Update("parent_scope_id", parent.ID)
			}
		}
	}

	return nil
}

// findParentScope returns the wildcard parent of a scope string.
// "tools:weather:read" → "tools:weather:*"
// "tools:weather:*" → "tools:*"
// "tools:*" → "" (no parent)
func findParentScope(scope string) string {
	parts := strings.Split(scope, ":")
	if len(parts) <= 1 {
		return ""
	}

	// If last part is not "*", replace with "*"
	if parts[len(parts)-1] != "*" {
		parentParts := make([]string, len(parts))
		copy(parentParts, parts)
		parentParts[len(parentParts)-1] = "*"
		return strings.Join(parentParts, ":")
	}

	// If last part is "*", go up one level
	if len(parts) <= 2 {
		return ""
	}
	parentParts := make([]string, len(parts)-1)
	copy(parentParts, parts[:len(parts)-2])
	parentParts[len(parentParts)-1] = "*"
	return strings.Join(parentParts, ":")
}

// ResolveHierarchy returns all scope strings that are implied by the given scopes.
// If granted contains "tools:*", it expands to include "tools:weather:read", "tools:weather:write", etc.
func (s *ScopeRegistryService) ResolveHierarchy(workspaceID, rsID uuid.UUID, grantedScopeStrings []string) ([]string, error) {
	if len(grantedScopeStrings) == 0 {
		return nil, nil
	}

	// Load all scopes for this RS
	var allScopes []models.OAuthScope
	if err := s.db.Where("workspace_id = ? AND resource_server_id = ?", workspaceID, rsID).Find(&allScopes).Error; err != nil {
		return nil, err
	}

	grantedSet := make(map[string]bool, len(grantedScopeStrings))
	for _, s := range grantedScopeStrings {
		grantedSet[s] = true
	}

	// Expand: for each scope, check if any ancestor is in the granted set
	var expanded []string
	for _, scope := range allScopes {
		if grantedSet[scope.ScopeString] {
			expanded = append(expanded, scope.ScopeString)
			continue
		}
		// Walk up parent chain
		if s.ancestorInSet(scope, allScopes, grantedSet) {
			expanded = append(expanded, scope.ScopeString)
		}
	}

	return expanded, nil
}

func (s *ScopeRegistryService) ancestorInSet(scope models.OAuthScope, all []models.OAuthScope, grantedSet map[string]bool) bool {
	// Also check wildcard pattern matching
	parts := strings.Split(scope.ScopeString, ":")
	for i := len(parts) - 1; i >= 1; i-- {
		wildcard := strings.Join(parts[:i], ":") + ":*"
		if grantedSet[wildcard] {
			return true
		}
	}
	return false
}

// Create creates a new scope in the registry.
func (s *ScopeRegistryService) Create(scope *models.OAuthScope) error {
	return s.db.Create(scope).Error
}

// ValidateParentScope verifies that parentScopeIDStr names a scope that exists within the
// given tenant and resource-server domain, enforcing the hierarchy isolation rule:
//
//	RS-scoped scope (rsID != nil)  → parent must have the exact same resource_server_id
//	tenant-global scope (rsID nil) → parent must also have resource_server_id IS NULL
//
// Returns the parsed UUID on success; returns ErrInvalidParentScope when the parent row
// is not found (wrong tenant, wrong RS, or simply absent), and a wrapped parse error when
// the string is not a valid UUID.
func (s *ScopeRegistryService) ValidateParentScope(parentScopeIDStr string, workspaceID uuid.UUID, rsID *uuid.UUID) (uuid.UUID, error) {
	pid, err := uuid.Parse(parentScopeIDStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid parent_scope_id: %w", err)
	}
	q := s.db.Model(&models.OAuthScope{}).Where("id = ? AND workspace_id = ?", pid, workspaceID)
	if rsID != nil {
		q = q.Where("resource_server_id = ?", *rsID)
	} else {
		q = q.Where("resource_server_id IS NULL")
	}
	var count int64
	q.Count(&count)
	if count == 0 {
		return uuid.Nil, ErrInvalidParentScope
	}
	return pid, nil
}

// applyUpdate applies field updates and ownership-verified permission + parent sync.
// workspaceID is enforced on both parent_scope_id (same tenant+RS domain) and
// permission_ids (tenant-owned or global). Callers must pass the already-fetched scope.
func (s *ScopeRegistryService) applyUpdate(
	scope *models.OAuthScope,
	workspaceID uuid.UUID,
	req *models.UpdateOAuthScopeRequest,
) (*models.OAuthScope, error) {
	updates := map[string]interface{}{}
	if req.DisplayName != "" {
		updates["display_name"] = req.DisplayName
	}
	if req.Description != "" {
		updates["description"] = req.Description
	}
	if req.Icon != "" {
		updates["icon"] = req.Icon
	}
	if req.RiskLevel != "" {
		updates["risk_level"] = req.RiskLevel
	}
	if req.ParentScopeID != "" {
		pid, err := s.ValidateParentScope(req.ParentScopeID, workspaceID, scope.ResourceServerID)
		if err != nil {
			return nil, err
		}
		updates["parent_scope_id"] = pid
	}

	if len(updates) > 0 {
		if err := s.db.Model(scope).Updates(updates).Error; err != nil {
			return nil, err
		}
	}

	// Re-sync permission mappings with tenant ownership filter.
	if req.PermissionIDs != nil {
		if err := s.db.Where("scope_id = ?", scope.ID).Delete(&models.OAuthScopePermission{}).Error; err != nil {
			return nil, err
		}
		for _, pidStr := range req.PermissionIDs {
			pid, err := uuid.Parse(pidStr)
			if err != nil {
				continue
			}
			// SECURITY: only link permissions owned by this tenant or globally scoped (tenant_id IS NULL).
			// Never remove this filter — it prevents cross-tenant permission bridges.
			var count int64
			s.db.Model(&models.RBACPermission{}).
				Where("id = ? AND (workspace_id = ? OR workspace_id IS NULL)", pid, workspaceID).
				Count(&count)
			if count == 0 {
				log.Printf("[SCOPE_REGISTRY] applyUpdate: skipping permission %s (not owned by tenant %s)", pid, workspaceID)
				continue
			}
			s.db.Create(&models.OAuthScopePermission{ScopeID: scope.ID, PermissionID: pid})
		}
	}

	s.db.Preload("Permissions").First(scope, "id = ?", scope.ID)
	return scope, nil
}

// Update updates scope metadata (no tenant ownership check — kept for internal use).
func (s *ScopeRegistryService) Update(scopeID uuid.UUID, req *models.UpdateOAuthScopeRequest) (*models.OAuthScope, error) {
	var scope models.OAuthScope
	if err := s.db.First(&scope, "id = ?", scopeID).Error; err != nil {
		return nil, err
	}
	return s.applyUpdate(&scope, scope.WorkspaceID, req)
}

// UpdateByTenant updates scope metadata only when the scope belongs to workspaceID.
func (s *ScopeRegistryService) UpdateByTenant(
	scopeID, workspaceID uuid.UUID,
	req *models.UpdateOAuthScopeRequest,
) (*models.OAuthScope, error) {
	var scope models.OAuthScope
	if err := s.db.First(&scope, "id = ? AND workspace_id = ?", scopeID, workspaceID).Error; err != nil {
		return nil, fmt.Errorf("scope not found")
	}
	return s.applyUpdate(&scope, workspaceID, req)
}

// DeleteByTenant removes a scope only when it belongs to workspaceID.
func (s *ScopeRegistryService) DeleteByTenant(scopeID, workspaceID uuid.UUID) error {
	result := s.db.Where("id = ? AND workspace_id = ?", scopeID, workspaceID).Delete(&models.OAuthScope{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("scope not found")
	}
	return nil
}

// LinkPermissionsTenantScoped writes oauth_scope_permissions rows for a newly created scope,
// skipping any permission ID that doesn't belong to workspaceID and isn't a global permission.
// This is the only sanctioned write path to oauth_scope_permissions from external caller input.
func (s *ScopeRegistryService) LinkPermissionsTenantScoped(scopeID, workspaceID uuid.UUID, permIDs []string) {
	for _, pidStr := range permIDs {
		pid, err := uuid.Parse(pidStr)
		if err != nil {
			continue
		}
		// SECURITY: only link permissions owned by this tenant or globally scoped (tenant_id IS NULL).
		// Never remove this filter — it prevents cross-tenant permission bridges.
		var count int64
		s.db.Model(&models.RBACPermission{}).
			Where("id = ? AND (workspace_id = ? OR workspace_id IS NULL)", pid, workspaceID).
			Count(&count)
		if count == 0 {
			log.Printf("[SCOPE_REGISTRY] LinkPermissions: skipping permission %s (not owned by tenant %s)", pid, workspaceID)
			continue
		}
		s.db.Create(&models.OAuthScopePermission{ScopeID: scopeID, PermissionID: pid})
	}
}

// Delete removes a scope from the registry.
func (s *ScopeRegistryService) Delete(scopeID uuid.UUID) error {
	return s.db.Delete(&models.OAuthScope{}, "id = ?", scopeID).Error
}

// ListByResourceServer returns all scopes for an RS.
func (s *ScopeRegistryService) ListByResourceServer(workspaceID, rsID uuid.UUID) ([]models.OAuthScope, error) {
	var scopes []models.OAuthScope
	err := s.db.Preload("Permissions").Preload("ChildScopes").
		Where("workspace_id = ? AND resource_server_id = ?", workspaceID, rsID).
		Order("scope_string").
		Find(&scopes).Error
	return scopes, err
}

// GetByID returns a scope with its relations.
func (s *ScopeRegistryService) GetByID(scopeID uuid.UUID) (*models.OAuthScope, error) {
	var scope models.OAuthScope
	err := s.db.Preload("Permissions").Preload("ChildScopes").Preload("ParentScope").
		First(&scope, "id = ?", scopeID).Error
	return &scope, err
}

// GetScopesByPermissions returns OAuth scopes that map to the given permission IDs.
// This is the reverse lookup: permission → scope (used during token resolution).
func (s *ScopeRegistryService) GetScopesByPermissions(workspaceID, rsID uuid.UUID, permissionIDs []uuid.UUID) ([]string, error) {
	if len(permissionIDs) == 0 {
		return nil, nil
	}

	var scopeStrings []string
	err := s.db.Model(&models.OAuthScope{}).
		Joins("JOIN oauth_scope_permissions osp ON osp.scope_id = oauth_scopes.id").
		Where("oauth_scopes.workspace_id = ? AND oauth_scopes.resource_server_id = ?", workspaceID, rsID).
		Where("osp.permission_id IN ?", permissionIDs).
		Distinct().
		Pluck("scope_string", &scopeStrings).Error

	return scopeStrings, err
}

// UpsertScope upserts a scope, used during PRM sync.
func (s *ScopeRegistryService) UpsertScope(scope *models.OAuthScope) error {
	return s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "workspace_id"}, {Name: "resource_server_id"}, {Name: "scope_string"}},
		DoNothing: true,
	}).Create(scope).Error
}

// generateDisplayName converts a scope string to a human-readable display name.
// "tools:weather:read" → "Weather - Read"
func generateDisplayName(scope string) string {
	parts := strings.Split(scope, ":")
	if len(parts) == 1 {
		return strings.Title(parts[0])
	}

	// Skip the first part if it's a namespace prefix like "tools" or "mcp"
	start := 0
	if parts[0] == "tools" || parts[0] == "mcp" {
		start = 1
	}

	var displayParts []string
	for _, p := range parts[start:] {
		if p == "*" {
			displayParts = append(displayParts, "All")
		} else {
			displayParts = append(displayParts, strings.Title(strings.ReplaceAll(p, "_", " ")))
		}
	}

	return strings.Join(displayParts, " - ")
}

// inferRiskLevel guesses a risk level from the scope string.
func inferRiskLevel(scope string) string {
	lower := strings.ToLower(scope)
	switch {
	case strings.Contains(lower, "admin") || strings.Contains(lower, "delete"):
		return "critical"
	case strings.Contains(lower, "write") || strings.Contains(lower, "create") || strings.Contains(lower, "update"):
		return "medium"
	case strings.HasSuffix(lower, ":*"):
		return "high"
	default:
		return "low"
	}
}
