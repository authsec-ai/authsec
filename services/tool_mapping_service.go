package services

import (
	"errors"
	"fmt"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// ToolMappingService manages the tool ↔ scope binding side of mcp_tools.
// Two operations:
//   - UpdateToolScopeMap: replace the required_scopes for a tool
//   - MarkToolPublic: flip is_public (orthogonal to required_scopes — when
//     is_public=true, the SDK skips scope checks for that tool entirely)
//
// Both emit drift signals when the change weakens the tool's protection:
//   - required_scopes goes from non-empty to empty -> tool_unmapped
//   - is_public flips from false to true            -> tool_unmapped
type ToolMappingService struct{}

func NewToolMappingService() *ToolMappingService { return &ToolMappingService{} }

var ErrToolNotFound = errors.New("tool not found")

// UpdateToolScopeMapInput is the body of PUT /tool-scope-map.
type UpdateToolScopeMapInput struct {
	RequiredScopes []string `json:"required_scopes"`
}

// MarkToolPublicInput is the body of POST /tools/:tool_id/public.
// Pass {"is_public": false} to un-mark a tool public.
type MarkToolPublicInput struct {
	IsPublic bool `json:"is_public"`
}

// ToolChangeResult is what both mutators return. PriorRequiredScopes and
// PriorIsPublic let the controller decide whether to emit drift events.
type ToolChangeResult struct {
	Tool                 models.MCPTool `json:"tool"`
	PriorRequiredScopes  []string       `json:"prior_required_scopes"`
	PriorIsPublic        bool           `json:"prior_is_public"`
	ProtectionWeakened   bool           `json:"protection_weakened"`
}

// UpdateToolScopeMap replaces a tool's required_scopes. Validates that
// every requested scope is in the Application's scopes_supported (otherwise
// the SDK's policy_complete check would fail). Empty list = "no scopes
// required" — combined with is_public=false this means deny-all (the SDK
// contract: tools with empty required_scopes AND is_public=false are denied).
func (s *ToolMappingService) UpdateToolScopeMap(
	tenantID string,
	applicationID, toolID uuid.UUID,
	in UpdateToolScopeMapInput,
) (*ToolChangeResult, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}

	var result ToolChangeResult
	txErr := tenantDB.Transaction(func(tx *gorm.DB) error {
		var tool models.MCPTool
		if err := tx.Where("id = ? AND resource_server_id = ? AND tenant_id = ?",
			toolID, applicationID, tenantID).First(&tool).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrToolNotFound
			}
			return err
		}

		// Snapshot prior state for drift detection.
		prior := make([]string, len(tool.RequiredScopes))
		copy(prior, tool.RequiredScopes)
		priorPublic := tool.IsPublic
		result.PriorRequiredScopes = prior
		result.PriorIsPublic = priorPublic

		// Validate every requested scope is registered for this Application.
		if len(in.RequiredScopes) > 0 {
			var rs models.ResourceServer
			if err := tx.Where("id = ?", applicationID).First(&rs).Error; err != nil {
				return err
			}
			for _, requested := range in.RequiredScopes {
				if !contains(rs.ScopesSupported, requested) {
					return fmt.Errorf("scope %q is not registered for this application", requested)
				}
			}
		}

		updates := map[string]interface{}{
			"required_scopes": pq.StringArray(in.RequiredScopes),
			"updated_at":      time.Now().UTC(),
		}
		if err := tx.Model(&tool).Updates(updates).Error; err != nil {
			return fmt.Errorf("update tool: %w", err)
		}
		if err := tx.Where("id = ?", toolID).First(&tool).Error; err != nil {
			return err
		}
		result.Tool = tool

		// Drift: weakened protection means
		// (was protected AND now public) OR (had scopes AND now has none AND not public).
		hadProtection := len(prior) > 0 && !priorPublic
		hasProtection := len(in.RequiredScopes) > 0 && !tool.IsPublic
		result.ProtectionWeakened = hadProtection && !hasProtection
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}
	return &result, nil
}

// MarkToolPublic flips a tool's is_public flag. Idempotent.
func (s *ToolMappingService) MarkToolPublic(
	tenantID string,
	applicationID, toolID uuid.UUID,
	in MarkToolPublicInput,
) (*ToolChangeResult, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}

	var result ToolChangeResult
	txErr := tenantDB.Transaction(func(tx *gorm.DB) error {
		var tool models.MCPTool
		if err := tx.Where("id = ? AND resource_server_id = ? AND tenant_id = ?",
			toolID, applicationID, tenantID).First(&tool).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrToolNotFound
			}
			return err
		}

		prior := make([]string, len(tool.RequiredScopes))
		copy(prior, tool.RequiredScopes)
		result.PriorRequiredScopes = prior
		result.PriorIsPublic = tool.IsPublic

		if err := tx.Model(&tool).Updates(map[string]interface{}{
			"is_public":  in.IsPublic,
			"updated_at": time.Now().UTC(),
		}).Error; err != nil {
			return fmt.Errorf("update tool: %w", err)
		}
		if err := tx.Where("id = ?", toolID).First(&tool).Error; err != nil {
			return err
		}
		result.Tool = tool

		// Drift: false -> true is the only weakening transition for is_public.
		result.ProtectionWeakened = !result.PriorIsPublic && tool.IsPublic
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}
	return &result, nil
}
