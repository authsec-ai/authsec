package services

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// ScopeService is the per-Application scope CRUD service. Every write
// keeps oauth_scopes (authoritative) AND resource_servers.scopes_supported
// (back-compat array for the SDK) in sync within a single transaction.
//
// Backport semantics:
//   - Scopes can be deleted even if a tool's required_scopes references them.
//     The mcp_tools.required_scopes column is text[] so we can't enforce
//     referential integrity. On delete we emit `tool_unmapped` drift events
//     for affected tools (Phase 4 retrofit, this batch).
//   - Risk-level edits + display name edits are pure metadata updates and
//     don't touch resource_servers.scopes_supported.
type ScopeService struct{}

func NewScopeService() *ScopeService { return &ScopeService{} }

var (
	ErrScopeNotFound      = errors.New("scope not found")
	ErrScopeAlreadyExists = errors.New("scope already exists for this application")
	ErrInvalidRiskLevel   = errors.New("risk_level must be one of: low, medium, high, critical")
)

// CreateScopeInput is the body of POST /scopes.
type CreateScopeInput struct {
	ScopeString string `json:"scope_string" binding:"required"`
	DisplayName string `json:"display_name,omitempty"`
	Description string `json:"description,omitempty"`
	RiskLevel   string `json:"risk_level,omitempty"` // defaults to 'low'
}

// UpdateScopeInput is the body of PUT /scopes/:scope_id. ScopeString
// renames are NOT supported — clients of the SDK and Hydra hold scope
// strings as opaque identifiers, and renaming would break in-flight tokens.
// Display name / description / risk level only.
type UpdateScopeInput struct {
	DisplayName *string `json:"display_name,omitempty"`
	Description *string `json:"description,omitempty"`
	RiskLevel   *string `json:"risk_level,omitempty"`
}

// List returns all scopes for an Application.
func (s *ScopeService) List(tenantID string, applicationID uuid.UUID) ([]models.OAuthScope, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	var rows []models.OAuthScope
	if err := tenantDB.Where("application_id = ? AND tenant_id = ?", applicationID, tenantID).
		Order("scope_string ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// Create inserts a new scope and adds it to resource_servers.scopes_supported.
func (s *ScopeService) Create(tenantID string, applicationID uuid.UUID, in CreateScopeInput) (*models.OAuthScope, error) {
	scopeString := strings.TrimSpace(in.ScopeString)
	if scopeString == "" {
		return nil, fmt.Errorf("scope_string required")
	}
	risk := in.RiskLevel
	if risk == "" {
		risk = models.RiskLevelLow
	}
	if !validRiskLevel(risk) {
		return nil, ErrInvalidRiskLevel
	}

	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}

	var row models.OAuthScope
	txErr := tenantDB.Transaction(func(tx *gorm.DB) error {
		// Load RS to (a) validate it exists in this tenant and (b) sync
		// scopes_supported.
		var rs models.ResourceServer
		if err := tx.Where("id = ? AND tenant_id = ?", applicationID, tenantID).
			First(&rs).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrResourceServerNotFound
			}
			return err
		}

		row = models.OAuthScope{
			TenantID:      tenantID,
			ApplicationID: applicationID,
			ScopeString:   scopeString,
			DisplayName:   coalesceStr(in.DisplayName, scopeString),
			Description:   in.Description,
			RiskLevel:     risk,
			Source:        models.ScopeSourceAdmin,
		}
		if err := tx.Create(&row).Error; err != nil {
			if isUniqueViolation(err) {
				return ErrScopeAlreadyExists
			}
			return fmt.Errorf("insert oauth_scopes: %w", err)
		}

		// Sync scopes_supported. Idempotent — only adds if not already there.
		if !contains(rs.ScopesSupported, scopeString) {
			newScopes := append([]string(rs.ScopesSupported), scopeString)
			if err := tx.Model(&rs).Updates(map[string]interface{}{
				"scopes_supported": pq.StringArray(newScopes),
				"updated_at":       time.Now().UTC(),
			}).Error; err != nil {
				return fmt.Errorf("sync scopes_supported: %w", err)
			}
		}
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}
	return &row, nil
}

// Update changes metadata only (display_name / description / risk_level).
// scope_string is immutable post-create — see UpdateScopeInput comment.
func (s *ScopeService) Update(tenantID string, applicationID, scopeID uuid.UUID, in UpdateScopeInput) (*models.OAuthScope, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	var row models.OAuthScope
	if err := tenantDB.Where("id = ? AND application_id = ? AND tenant_id = ?", scopeID, applicationID, tenantID).
		First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrScopeNotFound
		}
		return nil, err
	}
	updates := map[string]interface{}{"updated_at": time.Now().UTC()}
	if in.DisplayName != nil {
		updates["display_name"] = *in.DisplayName
	}
	if in.Description != nil {
		updates["description"] = *in.Description
	}
	if in.RiskLevel != nil {
		if !validRiskLevel(*in.RiskLevel) {
			return nil, ErrInvalidRiskLevel
		}
		updates["risk_level"] = *in.RiskLevel
	}
	if err := tenantDB.Model(&row).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("update oauth_scopes: %w", err)
	}
	// Reload to get fresh updated_at + all fields.
	if err := tenantDB.Where("id = ?", scopeID).First(&row).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

// DeleteResult is what Delete returns: the deleted scope's string + a list
// of tool names that had it in their required_scopes (drift signal).
type DeleteResult struct {
	ScopeString     string   `json:"scope_string"`
	AffectedTools   []string `json:"affected_tools"`
}

// Delete removes a scope, syncs scopes_supported, and returns the names of
// tools whose required_scopes included the deleted scope. Caller is
// responsible for emitting drift events (controller does it).
func (s *ScopeService) Delete(tenantID string, applicationID, scopeID uuid.UUID) (*DeleteResult, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	var result DeleteResult
	txErr := tenantDB.Transaction(func(tx *gorm.DB) error {
		var row models.OAuthScope
		if err := tx.Where("id = ? AND application_id = ? AND tenant_id = ?", scopeID, applicationID, tenantID).
			First(&row).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrScopeNotFound
			}
			return err
		}
		result.ScopeString = row.ScopeString

		// Find tools that reference this scope.
		var tools []models.MCPTool
		if err := tx.Where("resource_server_id = ?", applicationID).
			Where("? = ANY(required_scopes)", row.ScopeString).
			Find(&tools).Error; err != nil {
			return fmt.Errorf("find affected tools: %w", err)
		}
		for _, t := range tools {
			result.AffectedTools = append(result.AffectedTools, t.Name)
		}

		// Delete the scope row.
		if err := tx.Delete(&row).Error; err != nil {
			return fmt.Errorf("delete oauth_scopes: %w", err)
		}

		// Strip the scope from resource_servers.scopes_supported.
		var rs models.ResourceServer
		if err := tx.Where("id = ?", applicationID).First(&rs).Error; err != nil {
			return err
		}
		filtered := make([]string, 0, len(rs.ScopesSupported))
		for _, s := range rs.ScopesSupported {
			if s != row.ScopeString {
				filtered = append(filtered, s)
			}
		}
		if err := tx.Model(&rs).Updates(map[string]interface{}{
			"scopes_supported": pq.StringArray(filtered),
			"updated_at":       time.Now().UTC(),
		}).Error; err != nil {
			return fmt.Errorf("sync scopes_supported: %w", err)
		}

		// Strip the scope from each affected tool's required_scopes.
		// PostgreSQL array_remove is the cleanest way.
		if len(tools) > 0 {
			if err := tx.Exec(`
                UPDATE mcp_tools
                   SET required_scopes = array_remove(required_scopes, ?),
                       updated_at = now()
                 WHERE resource_server_id = ?
                   AND ? = ANY(required_scopes)
            `, row.ScopeString, applicationID, row.ScopeString).Error; err != nil {
				return fmt.Errorf("strip scope from tools: %w", err)
			}
		}
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}
	return &result, nil
}

// ──────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────

func validRiskLevel(v string) bool {
	switch v {
	case models.RiskLevelLow, models.RiskLevelMedium, models.RiskLevelHigh, models.RiskLevelCritical:
		return true
	}
	return false
}

func coalesceStr(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	// pq returns "duplicate key value violates unique constraint" in the error string.
	// Cheap but reliable on Postgres.
	return strings.Contains(err.Error(), "unique constraint") ||
		strings.Contains(err.Error(), "duplicate key")
}
