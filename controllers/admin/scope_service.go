package admin

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type scopeService struct{}

type scopeMappingRecord struct {
	ScopeName         string   `json:"scope_name"`
	Usage             string   `json:"usage"`
	Description       string   `json:"description,omitempty"`
	Resources         []string `json:"resources"`
	PermissionIDs     []string `json:"permission_ids,omitempty"`
	PermissionStrings []string `json:"permission_strings,omitempty"`
}

type permissionRow struct {
	ID       uuid.UUID
	Resource string
	Action   string
}

func newScopeService() *scopeService {
	return &scopeService{}
}

func (s *scopeService) normalizeUsage(raw, fallback string, allowed []string) (string, error) {
	usage := models.NormalizeScopeUsage(raw, fallback)
	for _, candidate := range allowed {
		if usage == candidate {
			return usage, nil
		}
	}
	return "", fmt.Errorf("usage must be one of %s", strings.Join(allowed, ", "))
}

func (s *scopeService) validatePermissionIDs(
	db *gorm.DB,
	tenantID uuid.UUID,
	permissionIDs []string,
) ([]uuid.UUID, error) {
	if len(permissionIDs) == 0 {
		return []uuid.UUID{}, nil
	}

	seen := make(map[uuid.UUID]struct{}, len(permissionIDs))
	parsed := make([]uuid.UUID, 0, len(permissionIDs))
	for _, rawID := range permissionIDs {
		id, err := uuid.Parse(strings.TrimSpace(rawID))
		if err != nil {
			return nil, fmt.Errorf("invalid permission id %q", rawID)
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		parsed = append(parsed, id)
	}

	var count int64
	if err := db.Table("permissions").
		Where("tenant_id = ?", tenantID).
		Where("id IN ?", parsed).
		Count(&count).Error; err != nil {
		return nil, fmt.Errorf("validate permissions: %w", err)
	}
	if count != int64(len(parsed)) {
		return nil, fmt.Errorf("one or more permissions do not belong to tenant %s", tenantID)
	}

	return parsed, nil
}

func (s *scopeService) resolvePermissionIDs(
	db *gorm.DB,
	tenantID uuid.UUID,
	permissionIDs []string,
	mappedPermissionIDs []string,
	permissionStrings []string,
) ([]uuid.UUID, error) {
	if len(permissionIDs) == 0 && len(mappedPermissionIDs) > 0 {
		permissionIDs = mappedPermissionIDs
	}
	if len(permissionIDs) > 0 {
		return s.validatePermissionIDs(db, tenantID, permissionIDs)
	}
	if len(permissionStrings) == 0 {
		return []uuid.UUID{}, nil
	}

	type permissionKey struct {
		resource string
		action   string
	}

	keys := make([]permissionKey, 0, len(permissionStrings))
	seenKeys := make(map[permissionKey]struct{}, len(permissionStrings))
	for _, raw := range permissionStrings {
		parts := strings.SplitN(strings.TrimSpace(raw), ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("invalid permission string %q", raw)
		}
		key := permissionKey{resource: parts[0], action: parts[1]}
		if _, exists := seenKeys[key]; exists {
			continue
		}
		seenKeys[key] = struct{}{}
		keys = append(keys, key)
	}

	ids := make([]uuid.UUID, 0, len(keys))
	for _, key := range keys {
		var id uuid.UUID
		if err := db.Table("permissions").
			Select("id").
			Where("tenant_id = ?", tenantID).
			Where("resource = ? AND action = ?", key.resource, key.action).
			Take(&id).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return nil, fmt.Errorf("permission %s:%s does not exist", key.resource, key.action)
			}
			return nil, fmt.Errorf("resolve permission %s:%s: %w", key.resource, key.action, err)
		}
		ids = append(ids, id)
	}

	return ids, nil
}

func (s *scopeService) applyUsageFilter(query *gorm.DB, allowed []string) *gorm.DB {
	return query.Where("usage IN ?", allowed)
}

func (s *scopeService) loadScopeByID(db *gorm.DB, tenantID, scopeID uuid.UUID, allowed []string) (*models.APIScope, error) {
	var scope models.APIScope
	if err := s.applyUsageFilter(db.Where("tenant_id = ? AND id = ?", tenantID, scopeID), allowed).First(&scope).Error; err != nil {
		return nil, err
	}
	return &scope, nil
}

func (s *scopeService) loadScopeByName(db *gorm.DB, tenantID uuid.UUID, name string, allowed []string) (*models.APIScope, error) {
	var scope models.APIScope
	if err := s.applyUsageFilter(db.Where("tenant_id = ? AND name = ?", tenantID, name), allowed).First(&scope).Error; err != nil {
		return nil, err
	}
	return &scope, nil
}

func (s *scopeService) replaceScopePermissions(tx *gorm.DB, scopeID uuid.UUID, permissionIDs []uuid.UUID) error {
	if err := tx.Where("scope_id = ?", scopeID).Delete(&models.APIScopePermission{}).Error; err != nil {
		return fmt.Errorf("delete scope permissions: %w", err)
	}
	for _, permissionID := range permissionIDs {
		mapping := models.APIScopePermission{
			ScopeID:      scopeID,
			PermissionID: permissionID,
		}
		if err := tx.Create(&mapping).Error; err != nil {
			return fmt.Errorf("create scope permission: %w", err)
		}
	}
	return nil
}

func (s *scopeService) permissionRows(db *gorm.DB, scopeID uuid.UUID) ([]permissionRow, error) {
	var rows []permissionRow
	if err := db.Table("scope_permissions").
		Select("permissions.id, permissions.resource, permissions.action").
		Joins("JOIN permissions ON permissions.id = scope_permissions.permission_id").
		Where("scope_permissions.scope_id = ?", scopeID).
		Order("permissions.resource ASC, permissions.action ASC").
		Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("load scope permissions: %w", err)
	}
	return rows, nil
}

func (s *scopeService) buildScopeResponse(db *gorm.DB, scope models.APIScope) (models.APIScopeResponse, error) {
	rows, err := s.permissionRows(db, scope.ID)
	if err != nil {
		return models.APIScopeResponse{}, err
	}

	permissionIDs := make([]string, 0, len(rows))
	permissionStrings := make([]string, 0, len(rows))
	resourceSet := make(map[string]struct{})
	resources := make([]string, 0, len(rows))
	for _, row := range rows {
		permissionIDs = append(permissionIDs, row.ID.String())
		permissionStrings = append(permissionStrings, row.Resource+":"+row.Action)
		if _, exists := resourceSet[row.Resource]; !exists {
			resourceSet[row.Resource] = struct{}{}
			resources = append(resources, row.Resource)
		}
	}

	return models.APIScopeResponse{
		ID:                scope.ID.String(),
		Name:              scope.Name,
		Description:       scope.Description,
		Usage:             scope.Usage,
		PermissionsLinked: len(rows),
		PermissionIDs:     permissionIDs,
		PermissionStrings: permissionStrings,
		Resources:         resources,
		CreatedAt:         scope.CreatedAt.Format(time.RFC3339),
		UpdatedAt:         scope.UpdatedAt.Format(time.RFC3339),
	}, nil
}

func (s *scopeService) createScope(
	db *gorm.DB,
	tenantID uuid.UUID,
	name string,
	description string,
	usage string,
	permissionIDs []uuid.UUID,
) (models.APIScopeResponse, error) {
	scope := models.APIScope{
		ID:          uuid.New(),
		TenantID:    &tenantID,
		Name:        name,
		Description: description,
		Usage:       usage,
	}

	if err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&scope).Error; err != nil {
			return err
		}
		return s.replaceScopePermissions(tx, scope.ID, permissionIDs)
	}); err != nil {
		return models.APIScopeResponse{}, err
	}

	return s.buildScopeResponse(db, scope)
}

func (s *scopeService) updateScope(
	db *gorm.DB,
	scope *models.APIScope,
	name *string,
	description *string,
	usage *string,
	permissionIDs []uuid.UUID,
	replacePermissions bool,
) (models.APIScopeResponse, error) {
	if err := db.Transaction(func(tx *gorm.DB) error {
		updates := map[string]interface{}{}
		if name != nil {
			updates["name"] = *name
		}
		if description != nil {
			updates["description"] = *description
		}
		if usage != nil {
			updates["usage"] = *usage
		}
		if len(updates) > 0 {
			updates["updated_at"] = time.Now().UTC()
			if err := tx.Model(scope).Updates(updates).Error; err != nil {
				return err
			}
		}
		if replacePermissions {
			if err := s.replaceScopePermissions(tx, scope.ID, permissionIDs); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return models.APIScopeResponse{}, err
	}

	if err := db.Where("id = ?", scope.ID).First(scope).Error; err != nil {
		return models.APIScopeResponse{}, err
	}
	return s.buildScopeResponse(db, *scope)
}

func (s *scopeService) deleteScope(db *gorm.DB, scope *models.APIScope) error {
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("scope_id = ?", scope.ID).Delete(&models.APIScopePermission{}).Error; err != nil {
			return err
		}
		return tx.Delete(scope).Error
	})
}

func (s *scopeService) listScopeItems(db *gorm.DB, tenantID uuid.UUID, allowed []string, nameFilter string) ([]models.APIScopeListItem, error) {
	var scopes []models.APIScope
	query := s.applyUsageFilter(db.Where("tenant_id = ?", tenantID), allowed)
	if trimmed := strings.TrimSpace(nameFilter); trimmed != "" {
		query = query.Where("LOWER(name) LIKE LOWER(?)", "%"+trimmed+"%")
	}
	if err := query.Order("created_at DESC").Find(&scopes).Error; err != nil {
		return nil, err
	}

	type countRow struct {
		ScopeID uuid.UUID
		Count   int
	}
	var counts []countRow
	if len(scopes) > 0 {
		scopeIDs := make([]uuid.UUID, 0, len(scopes))
		for _, scope := range scopes {
			scopeIDs = append(scopeIDs, scope.ID)
		}
		if err := db.Table("scope_permissions").
			Select("scope_id, count(*) as count").
			Where("scope_id IN ?", scopeIDs).
			Group("scope_id").
			Scan(&counts).Error; err != nil {
			return nil, err
		}
	}

	countMap := make(map[uuid.UUID]int, len(counts))
	for _, count := range counts {
		countMap[count.ScopeID] = count.Count
	}

	resp := make([]models.APIScopeListItem, 0, len(scopes))
	for _, scope := range scopes {
		resp = append(resp, models.APIScopeListItem{
			ID:                scope.ID.String(),
			Name:              scope.Name,
			Description:       scope.Description,
			Usage:             scope.Usage,
			PermissionsLinked: countMap[scope.ID],
			CreatedAt:         scope.CreatedAt.Format(time.RFC3339),
			UpdatedAt:         scope.UpdatedAt.Format(time.RFC3339),
		})
	}
	return resp, nil
}

func (s *scopeService) listScopeMappings(db *gorm.DB, tenantID uuid.UUID, allowed []string) ([]scopeMappingRecord, error) {
	var scopes []models.APIScope
	if err := s.applyUsageFilter(db.Where("tenant_id = ?", tenantID), allowed).
		Order("name ASC").
		Find(&scopes).Error; err != nil {
		return nil, err
	}

	resp := make([]scopeMappingRecord, 0, len(scopes))
	for _, scope := range scopes {
		scopeResp, err := s.buildScopeResponse(db, scope)
		if err != nil {
			return nil, err
		}
		record := scopeMappingRecord{
			ScopeName:         scopeResp.Name,
			Usage:             scopeResp.Usage,
			Description:       scopeResp.Description,
			Resources:         append([]string{}, scopeResp.Resources...),
			PermissionIDs:     append([]string{}, scopeResp.PermissionIDs...),
			PermissionStrings: append([]string{}, scopeResp.PermissionStrings...),
		}
		sort.Strings(record.Resources)
		sort.Strings(record.PermissionStrings)
		resp = append(resp, record)
	}
	return resp, nil
}
