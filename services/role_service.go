package services

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RoleService is the per-Application RBAC role lifecycle. Phase 8 part 1
// covers List + Create + scope-grant management; Phase 8 part 2 will add
// bindings (the user→role join).
//
// Backport semantics:
//   - Scope-grant writes use REPLACE semantics: PUT scope-grants with
//     {scope_ids: [...]} computes the diff and inserts/deletes as needed.
//   - Validates every passed scope_id is registered for THIS Application
//     (defence against cross-application scope grants).
//   - System roles cannot be deleted but can be renamed/edited.
type RoleService struct{}

func NewRoleService() *RoleService { return &RoleService{} }

var (
	ErrRoleNotFound      = errors.New("role not found")
	ErrRoleAlreadyExists = errors.New("role already exists for this application")
	ErrInvalidScopeID    = errors.New("scope_id is not registered for this application")
)

// CreateRoleInput is the body of POST /:id/roles.
type CreateRoleInput struct {
	Name        string   `json:"name" binding:"required"`
	Description string   `json:"description,omitempty"`
	// Optional: scope IDs to grant to this role at creation time. If empty,
	// the role is created with no scope grants. Caller can update later via
	// PUT /:id/roles/:role_id/scope-grants.
	ScopeIDs []string `json:"scope_ids,omitempty"`
}

// UpdateScopeGrantsInput is the body of PUT /:id/roles/:role_id/scope-grants.
// `ScopeIDs` is the desired complete set — anything not in the list gets
// removed. Pass `[]` to strip all scope grants from the role.
type UpdateScopeGrantsInput struct {
	ScopeIDs []string `json:"scope_ids"`
}

// RoleView is the read shape — adds the resolved scope strings (handy for
// admin UIs that want to display "viewer = mcp_demo.read + mcp_demo.tools.read"
// without a second round trip).
type RoleView struct {
	models.ApplicationRole
	GrantedScopes []ScopeGrantInfo `json:"granted_scopes"`
}

// ScopeGrantInfo is one scope grant joined with its OAuth scope row.
type ScopeGrantInfo struct {
	ScopeID     uuid.UUID `json:"scope_id"`
	ScopeString string    `json:"scope_string"`
	DisplayName string    `json:"display_name,omitempty"`
	RiskLevel   string    `json:"risk_level"`
}

// List returns every role for an Application, each hydrated with its
// scope grants.
func (s *RoleService) List(tenantID string, applicationID uuid.UUID) ([]RoleView, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	var roles []models.ApplicationRole
	if err := tenantDB.Where("application_id = ? AND tenant_id = ?", applicationID, tenantID).
		Order("name ASC").Find(&roles).Error; err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	if len(roles) == 0 {
		return []RoleView{}, nil
	}

	// Hydrate scope grants in one pass.
	roleIDs := make([]uuid.UUID, 0, len(roles))
	for _, r := range roles {
		roleIDs = append(roleIDs, r.ID)
	}
	type grantRow struct {
		RoleID      uuid.UUID
		ScopeID     uuid.UUID
		ScopeString string
		DisplayName string
		RiskLevel   string
	}
	var grants []grantRow
	if err := tenantDB.Table("application_role_scope_grants AS g").
		Select("g.role_id, g.scope_id, s.scope_string, s.display_name, s.risk_level").
		Joins("JOIN oauth_scopes s ON s.id = g.scope_id").
		Where("g.role_id IN ?", roleIDs).
		Find(&grants).Error; err != nil {
		return nil, fmt.Errorf("hydrate scope grants: %w", err)
	}
	byRole := make(map[uuid.UUID][]ScopeGrantInfo, len(roles))
	for _, g := range grants {
		byRole[g.RoleID] = append(byRole[g.RoleID], ScopeGrantInfo{
			ScopeID:     g.ScopeID,
			ScopeString: g.ScopeString,
			DisplayName: g.DisplayName,
			RiskLevel:   g.RiskLevel,
		})
	}

	out := make([]RoleView, 0, len(roles))
	for _, r := range roles {
		gs := byRole[r.ID]
		if gs == nil {
			gs = []ScopeGrantInfo{}
		}
		out = append(out, RoleView{ApplicationRole: r, GrantedScopes: gs})
	}
	return out, nil
}

// Create inserts a new role and optionally seeds its scope grants. Returns
// the hydrated role view.
func (s *RoleService) Create(tenantID string, applicationID uuid.UUID, in CreateRoleInput) (*RoleView, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, fmt.Errorf("name required")
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	var role models.ApplicationRole
	var grants []ScopeGrantInfo

	txErr := tenantDB.Transaction(func(tx *gorm.DB) error {
		// Verify the Application exists in this tenant.
		var rsCount int64
		if err := tx.Model(&models.ResourceServer{}).
			Where("id = ? AND tenant_id = ?", applicationID, tenantID).
			Count(&rsCount).Error; err != nil {
			return err
		}
		if rsCount == 0 {
			return ErrResourceServerNotFound
		}

		role = models.ApplicationRole{
			TenantID:      tenantID,
			ApplicationID: applicationID,
			Name:          name,
			Description:   in.Description,
		}
		if err := tx.Create(&role).Error; err != nil {
			if isUniqueViolation(err) {
				return ErrRoleAlreadyExists
			}
			return fmt.Errorf("insert application_role: %w", err)
		}

		if len(in.ScopeIDs) > 0 {
			parsed, hydrated, err := s.validateAndHydrateScopes(tx, applicationID, in.ScopeIDs)
			if err != nil {
				return err
			}
			now := time.Now().UTC()
			rows := make([]models.ApplicationRoleScopeGrant, 0, len(parsed))
			for _, sid := range parsed {
				rows = append(rows, models.ApplicationRoleScopeGrant{
					TenantID:  tenantID,
					RoleID:    role.ID,
					ScopeID:   sid,
					CreatedAt: now,
				})
			}
			if err := tx.Create(&rows).Error; err != nil {
				return fmt.Errorf("insert scope grants: %w", err)
			}
			grants = hydrated
		} else {
			grants = []ScopeGrantInfo{}
		}
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}

	return &RoleView{ApplicationRole: role, GrantedScopes: grants}, nil
}

// ListScopeGrants returns the scope grants on a single role.
func (s *RoleService) ListScopeGrants(tenantID string, applicationID, roleID uuid.UUID) ([]ScopeGrantInfo, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	// Verify the role belongs to this tenant + application.
	var role models.ApplicationRole
	if err := tenantDB.Where("id = ? AND application_id = ? AND tenant_id = ?",
		roleID, applicationID, tenantID).First(&role).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRoleNotFound
		}
		return nil, err
	}
	type grantRow struct {
		ScopeID     uuid.UUID
		ScopeString string
		DisplayName string
		RiskLevel   string
	}
	var rows []grantRow
	if err := tenantDB.Table("application_role_scope_grants AS g").
		Select("g.scope_id, s.scope_string, s.display_name, s.risk_level").
		Joins("JOIN oauth_scopes s ON s.id = g.scope_id").
		Where("g.role_id = ?", roleID).
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list scope grants: %w", err)
	}
	out := make([]ScopeGrantInfo, 0, len(rows))
	for _, r := range rows {
		out = append(out, ScopeGrantInfo{
			ScopeID:     r.ScopeID,
			ScopeString: r.ScopeString,
			DisplayName: r.DisplayName,
			RiskLevel:   r.RiskLevel,
		})
	}
	return out, nil
}

// UpdateScopeGrants replaces a role's scope grants with the provided set.
// Empty input strips all grants. Validates every scope_id belongs to the
// same Application (defence against cross-application grants).
func (s *RoleService) UpdateScopeGrants(
	tenantID string,
	applicationID, roleID uuid.UUID,
	in UpdateScopeGrantsInput,
) (*RoleView, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	var role models.ApplicationRole
	var grants []ScopeGrantInfo

	txErr := tenantDB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("id = ? AND application_id = ? AND tenant_id = ?",
			roleID, applicationID, tenantID).First(&role).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrRoleNotFound
			}
			return err
		}

		// Validate + parse the requested scope IDs.
		var parsed []uuid.UUID
		var hydrated []ScopeGrantInfo
		var err error
		if len(in.ScopeIDs) > 0 {
			parsed, hydrated, err = s.validateAndHydrateScopes(tx, applicationID, in.ScopeIDs)
			if err != nil {
				return err
			}
		} else {
			hydrated = []ScopeGrantInfo{}
		}

		// Load the current grants for diff.
		var existing []models.ApplicationRoleScopeGrant
		if err := tx.Where("role_id = ?", roleID).Find(&existing).Error; err != nil {
			return fmt.Errorf("load existing grants: %w", err)
		}
		existingSet := make(map[uuid.UUID]uuid.UUID, len(existing)) // scope_id -> grant_id
		for _, g := range existing {
			existingSet[g.ScopeID] = g.ID
		}
		desired := make(map[uuid.UUID]struct{}, len(parsed))
		for _, sid := range parsed {
			desired[sid] = struct{}{}
		}

		// Delete grants no longer desired.
		toDelete := make([]uuid.UUID, 0)
		for scopeID, grantID := range existingSet {
			if _, keep := desired[scopeID]; !keep {
				toDelete = append(toDelete, grantID)
			}
		}
		if len(toDelete) > 0 {
			if err := tx.Where("id IN ?", toDelete).
				Delete(&models.ApplicationRoleScopeGrant{}).Error; err != nil {
				return fmt.Errorf("delete grants: %w", err)
			}
		}

		// Insert grants that aren't already there.
		now := time.Now().UTC()
		toInsert := make([]models.ApplicationRoleScopeGrant, 0)
		for scopeID := range desired {
			if _, exists := existingSet[scopeID]; !exists {
				toInsert = append(toInsert, models.ApplicationRoleScopeGrant{
					TenantID:  tenantID,
					RoleID:    roleID,
					ScopeID:   scopeID,
					CreatedAt: now,
				})
			}
		}
		if len(toInsert) > 0 {
			if err := tx.Create(&toInsert).Error; err != nil {
				return fmt.Errorf("insert grants: %w", err)
			}
		}

		// Touch the role's updated_at so admin audit trails show the change.
		if err := tx.Model(&role).Update("updated_at", now).Error; err != nil {
			return fmt.Errorf("touch role: %w", err)
		}
		role.UpdatedAt = now
		grants = hydrated
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}

	return &RoleView{ApplicationRole: role, GrantedScopes: grants}, nil
}

// validateAndHydrateScopes parses the inbound scope_id strings, checks each
// one belongs to the given Application, and returns the parsed UUIDs +
// the hydrated ScopeGrantInfo list.
func (s *RoleService) validateAndHydrateScopes(
	tx *gorm.DB,
	applicationID uuid.UUID,
	rawIDs []string,
) ([]uuid.UUID, []ScopeGrantInfo, error) {
	parsed := make([]uuid.UUID, 0, len(rawIDs))
	for _, raw := range rawIDs {
		u, err := uuid.Parse(strings.TrimSpace(raw))
		if err != nil {
			return nil, nil, fmt.Errorf("invalid scope_id %q: %w", raw, err)
		}
		parsed = append(parsed, u)
	}
	// Verify every scope belongs to this Application.
	var scopes []models.OAuthScope
	if err := tx.Where("id IN ? AND application_id = ?", parsed, applicationID).
		Find(&scopes).Error; err != nil {
		return nil, nil, fmt.Errorf("verify scopes: %w", err)
	}
	if len(scopes) != len(parsed) {
		// Find the missing one for a helpful error.
		found := make(map[uuid.UUID]struct{}, len(scopes))
		for _, s := range scopes {
			found[s.ID] = struct{}{}
		}
		for _, p := range parsed {
			if _, ok := found[p]; !ok {
				return nil, nil, fmt.Errorf("%w: %s", ErrInvalidScopeID, p)
			}
		}
	}
	hydrated := make([]ScopeGrantInfo, 0, len(scopes))
	for _, sc := range scopes {
		hydrated = append(hydrated, ScopeGrantInfo{
			ScopeID:     sc.ID,
			ScopeString: sc.ScopeString,
			DisplayName: sc.DisplayName,
			RiskLevel:   sc.RiskLevel,
		})
	}
	return parsed, hydrated, nil
}
