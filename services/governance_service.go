package services

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// GovernanceService is the read-only compliance/audit surface for an
// Application. All methods compose existing tables (bindings, roles,
// scope grants, scopes, tools, users) — no new schema.
//
// Backport-lean equivalent of dev's governance views. Dev pulls
// additional signals from workspace-level audit logs and the Hydra
// session store; the backport sticks to what's queryable from the
// Application's own tables.
type GovernanceService struct{}

func NewGovernanceService() *GovernanceService { return &GovernanceService{} }

// ─────────────────────────────────────────────────────────────────────────
// /access-assignments — auditable view of every binding with full context
// ─────────────────────────────────────────────────────────────────────────

// AccessAssignmentFilters parameterizes the access-assignments query.
type AccessAssignmentFilters struct {
	UserID    uuid.UUID // empty = all users
	RoleID    uuid.UUID // empty = all roles
	GrantedAfter  *time.Time
	GrantedBefore *time.Time
}

// AccessAssignment is one fully-hydrated binding row: who, what role,
// what scopes that role grants, when, by whom.
type AccessAssignment struct {
	BindingID    uuid.UUID  `json:"binding_id"`
	UserID       uuid.UUID  `json:"user_id"`
	UserEmail    string     `json:"user_email"`
	UserName     string     `json:"user_name,omitempty"`
	UserActive   bool       `json:"user_active"`
	RoleID       uuid.UUID  `json:"role_id"`
	RoleName     string     `json:"role_name"`
	ScopeStrings []string   `json:"scope_strings"`
	GrantedAt    time.Time  `json:"granted_at"`
	GrantedBy    *uuid.UUID `json:"granted_by,omitempty"`
}

// ListAccessAssignments returns the full audit-grade view of bindings.
// Each row hydrates the role's scope_strings so a compliance reviewer
// can answer "exactly what does this grant?" without follow-up queries.
func (s *GovernanceService) ListAccessAssignments(
	tenantID string,
	applicationID uuid.UUID,
	f AccessAssignmentFilters,
) ([]AccessAssignment, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	type row struct {
		BindingID    uuid.UUID
		UserID       uuid.UUID
		UserEmail    string
		UserName     string
		UserActive   bool
		RoleID       uuid.UUID
		RoleName     string
		ScopeStrings []string `gorm:"type:text[]"`
		GrantedAt    time.Time
		GrantedBy    *uuid.UUID
	}
	q := tenantDB.Table("application_role_bindings AS b").
		Select(`b.id AS binding_id,
		        b.user_id, u.email AS user_email,
		        COALESCE(u.name,'') AS user_name, u.active AS user_active,
		        b.role_id, r.name AS role_name,
		        COALESCE(array_remove(array_agg(DISTINCT s.scope_string), NULL), '{}') AS scope_strings,
		        b.granted_at, b.granted_by`).
		Joins("JOIN users u ON u.id = b.user_id").
		Joins("JOIN application_roles r ON r.id = b.role_id").
		Joins("LEFT JOIN application_role_scope_grants g ON g.role_id = r.id").
		Joins("LEFT JOIN oauth_scopes s ON s.id = g.scope_id").
		Where("b.application_id = ? AND b.tenant_id = ?", applicationID, tenantID)
	if f.UserID != uuid.Nil {
		q = q.Where("b.user_id = ?", f.UserID)
	}
	if f.RoleID != uuid.Nil {
		q = q.Where("b.role_id = ?", f.RoleID)
	}
	if f.GrantedAfter != nil {
		q = q.Where("b.granted_at >= ?", *f.GrantedAfter)
	}
	if f.GrantedBefore != nil {
		q = q.Where("b.granted_at < ?", *f.GrantedBefore)
	}
	q = q.Group("b.id, b.user_id, u.email, u.name, u.active, b.role_id, r.name, b.granted_at, b.granted_by").
		Order("b.granted_at DESC")

	var rows []row
	if err := q.Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("list access assignments: %w", err)
	}
	out := make([]AccessAssignment, 0, len(rows))
	for _, r := range rows {
		out = append(out, AccessAssignment{
			BindingID:    r.BindingID,
			UserID:       r.UserID,
			UserEmail:    r.UserEmail,
			UserName:     r.UserName,
			UserActive:   r.UserActive,
			RoleID:       r.RoleID,
			RoleName:     r.RoleName,
			ScopeStrings: r.ScopeStrings,
			GrantedAt:    r.GrantedAt,
			GrantedBy:    r.GrantedBy,
		})
	}
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────────
// /access-change-previews — dry-run a binding mutation
// ─────────────────────────────────────────────────────────────────────────

// AccessChangePreviewRequest describes a proposed mutation to a user's
// access. The service computes the before/after effective-scope diff
// WITHOUT touching the DB.
type AccessChangePreviewRequest struct {
	UserID     uuid.UUID
	AddRoles   []uuid.UUID
	RemoveRoles []uuid.UUID
}

// AccessChangePreviewResponse is the diff.
type AccessChangePreviewResponse struct {
	UserID        uuid.UUID `json:"user_id"`
	UserEmail     string    `json:"user_email"`
	PriorRoles    []string  `json:"prior_roles"`
	NextRoles     []string  `json:"next_roles"`
	PriorScopes   []string  `json:"prior_scopes"`
	NextScopes    []string  `json:"next_scopes"`
	AddedScopes   []string  `json:"added_scopes"`
	RemovedScopes []string  `json:"removed_scopes"`
}

// PreviewAccessChange computes what would happen if we added/removed the
// given roles for the user. Pure read — no writes.
func (s *GovernanceService) PreviewAccessChange(
	tenantID string,
	applicationID uuid.UUID,
	req AccessChangePreviewRequest,
) (*AccessChangePreviewResponse, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}

	// 1. Resolve the user.
	var u struct {
		ID    uuid.UUID
		Email string
	}
	if err := tenantDB.Table("users").Select("id, email").
		Where("id = ?", req.UserID).First(&u).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotInTenant
		}
		return nil, err
	}

	// 2. Current bindings + roles.
	type rb struct {
		RoleID   uuid.UUID
		RoleName string
	}
	var current []rb
	err = tenantDB.Table("application_role_bindings AS b").
		Select("r.id AS role_id, r.name AS role_name").
		Joins("JOIN application_roles r ON r.id = b.role_id").
		Where("b.application_id = ? AND b.user_id = ?", applicationID, req.UserID).
		Scan(&current).Error
	if err != nil {
		return nil, fmt.Errorf("load current bindings: %w", err)
	}
	currentByID := make(map[uuid.UUID]string, len(current))
	for _, r := range current {
		currentByID[r.RoleID] = r.RoleName
	}

	// 3. Compute the next role set.
	addSet := uuidSet(req.AddRoles)
	removeSet := uuidSet(req.RemoveRoles)
	nextByID := make(map[uuid.UUID]string, len(current)+len(req.AddRoles))
	for id, name := range currentByID {
		if _, drop := removeSet[id]; !drop {
			nextByID[id] = name
		}
	}
	// Add new roles — look up their names.
	if len(addSet) > 0 {
		addIDs := make([]uuid.UUID, 0, len(addSet))
		for id := range addSet {
			if _, alreadyHave := nextByID[id]; alreadyHave {
				continue
			}
			addIDs = append(addIDs, id)
		}
		if len(addIDs) > 0 {
			var addRoles []models.ApplicationRole
			if err := tenantDB.Where("id IN ? AND application_id = ? AND tenant_id = ?",
				addIDs, applicationID, tenantID).Find(&addRoles).Error; err != nil {
				return nil, fmt.Errorf("resolve add roles: %w", err)
			}
			found := make(map[uuid.UUID]struct{}, len(addRoles))
			for _, r := range addRoles {
				nextByID[r.ID] = r.Name
				found[r.ID] = struct{}{}
			}
			for _, id := range addIDs {
				if _, ok := found[id]; !ok {
					return nil, fmt.Errorf("role %s not found in this application", id)
				}
			}
		}
	}

	// 4. Resolve the scope strings for prior and next role sets.
	priorScopes, err := s.scopesForRoles(tenantDB, applicationID, currentByID)
	if err != nil {
		return nil, err
	}
	nextScopes, err := s.scopesForRoles(tenantDB, applicationID, nextByID)
	if err != nil {
		return nil, err
	}

	added, removed := stringDiff(priorScopes, nextScopes)

	return &AccessChangePreviewResponse{
		UserID:        u.ID,
		UserEmail:     u.Email,
		PriorRoles:    mapValuesSorted(currentByID),
		NextRoles:     mapValuesSorted(nextByID),
		PriorScopes:   priorScopes,
		NextScopes:    nextScopes,
		AddedScopes:   added,
		RemovedScopes: removed,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────────
// /access-simulations — "if user X had role Y..."
// ─────────────────────────────────────────────────────────────────────────

// AccessSimulationRequest names a (user, role-set) pair to simulate.
// Distinct from PreviewAccessChange in that it REPLACES the user's roles
// rather than diffing add/remove.
type AccessSimulationRequest struct {
	UserID  uuid.UUID
	RoleIDs []uuid.UUID
}

// AccessSimulationResponse is what /access-simulations returns.
type AccessSimulationResponse struct {
	UserID            uuid.UUID `json:"user_id"`
	UserEmail         string    `json:"user_email"`
	SimulatedRoles    []string  `json:"simulated_roles"`
	SimulatedScopes   []string  `json:"simulated_scopes"`
	ToolsReachable    []string  `json:"tools_reachable"`
	ToolsNotReachable []string  `json:"tools_not_reachable"`
}

// SimulateAccess answers "if user X had EXACTLY these roles, what scopes
// would they have AND which tools could they call?" Pure read.
func (s *GovernanceService) SimulateAccess(
	tenantID string,
	applicationID uuid.UUID,
	req AccessSimulationRequest,
) (*AccessSimulationResponse, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}

	var u struct {
		ID    uuid.UUID
		Email string
	}
	if err := tenantDB.Table("users").Select("id, email").
		Where("id = ?", req.UserID).First(&u).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotInTenant
		}
		return nil, err
	}

	// Resolve the roles + verify they belong to this Application.
	var roles []models.ApplicationRole
	if len(req.RoleIDs) > 0 {
		if err := tenantDB.Where("id IN ? AND application_id = ? AND tenant_id = ?",
			req.RoleIDs, applicationID, tenantID).Find(&roles).Error; err != nil {
			return nil, fmt.Errorf("resolve roles: %w", err)
		}
		if len(roles) != len(req.RoleIDs) {
			return nil, fmt.Errorf("one or more role_ids not found in this application")
		}
	}
	roleNames := make([]string, 0, len(roles))
	roleByID := make(map[uuid.UUID]string, len(roles))
	for _, r := range roles {
		roleNames = append(roleNames, r.Name)
		roleByID[r.ID] = r.Name
	}
	sort.Strings(roleNames)

	scopes, err := s.scopesForRoles(tenantDB, applicationID, roleByID)
	if err != nil {
		return nil, err
	}

	// Which tools are reachable given those scopes? A tool is reachable if
	// it's_public OR at least one of its required_scopes is in the
	// simulated scope set.
	reachable, notReachable, err := s.toolReachability(tenantDB, applicationID, scopes)
	if err != nil {
		return nil, err
	}

	return &AccessSimulationResponse{
		UserID:            u.ID,
		UserEmail:         u.Email,
		SimulatedRoles:    roleNames,
		SimulatedScopes:   scopes,
		ToolsReachable:    reachable,
		ToolsNotReachable: notReachable,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────────
// /effective-access — Application-wide effective access
// ─────────────────────────────────────────────────────────────────────────

// ApplicationEffectiveAccessUser is one row of the Application-wide
// effective-access view: a user and their resolved scope set.
type ApplicationEffectiveAccessUser struct {
	UserID          uuid.UUID `json:"user_id"`
	Email           string    `json:"email"`
	Name            string    `json:"name,omitempty"`
	Active          bool      `json:"active"`
	EffectiveScopes []string  `json:"effective_scopes"`
}

// GetApplicationEffectiveAccess returns the resolved effective scope set
// for every user with at least one binding on this Application. Same
// resolver pattern as BindingService.GetEffectiveAccess, but for all
// users in one query.
func (s *GovernanceService) GetApplicationEffectiveAccess(tenantID string, applicationID uuid.UUID) ([]ApplicationEffectiveAccessUser, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	type row struct {
		UserID          uuid.UUID
		Email           string
		Name            string
		Active          bool
		EffectiveScopes []string `gorm:"type:text[]"`
	}
	var rows []row
	err = tenantDB.Raw(`
        SELECT
            u.id AS user_id,
            u.email,
            COALESCE(u.name,'') AS name,
            u.active,
            COALESCE(array_remove(array_agg(DISTINCT s.scope_string), NULL), '{}') AS effective_scopes
          FROM application_role_bindings b
          JOIN users u ON u.id = b.user_id
          LEFT JOIN application_role_scope_grants g ON g.role_id = b.role_id
          LEFT JOIN oauth_scopes s ON s.id = g.scope_id
         WHERE b.application_id = ? AND b.tenant_id = ?
         GROUP BY u.id, u.email, u.name, u.active
         ORDER BY u.email ASC
    `, applicationID, tenantID).Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("application effective access: %w", err)
	}
	out := make([]ApplicationEffectiveAccessUser, 0, len(rows))
	for _, r := range rows {
		out = append(out, ApplicationEffectiveAccessUser{
			UserID:          r.UserID,
			Email:           r.Email,
			Name:            r.Name,
			Active:          r.Active,
			EffectiveScopes: r.EffectiveScopes,
		})
	}
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────────
// /end-user-access-summary — paged per-user summary
// ─────────────────────────────────────────────────────────────────────────

// EndUserAccessSummaryPage paginates ApplicationEffectiveAccessUser rows
// for compliance UIs that don't want to load everything at once.
type EndUserAccessSummaryPage struct {
	Users  []ApplicationEffectiveAccessUser `json:"users"`
	Total  int64                            `json:"total"`
	Page   int                              `json:"page"`
	Limit  int                              `json:"limit"`
}

// EndUserAccessSummary is the paged view. page is 1-indexed.
func (s *GovernanceService) EndUserAccessSummary(
	tenantID string,
	applicationID uuid.UUID,
	page, limit int,
) (*EndUserAccessSummaryPage, error) {
	if page < 1 {
		page = 1
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	// Total count of distinct users with bindings.
	var total int64
	if err := tenantDB.Raw(`
        SELECT COUNT(DISTINCT b.user_id)
          FROM application_role_bindings b
         WHERE b.application_id = ? AND b.tenant_id = ?
    `, applicationID, tenantID).Scan(&total).Error; err != nil {
		return nil, fmt.Errorf("count users: %w", err)
	}

	offset := (page - 1) * limit
	type row struct {
		UserID          uuid.UUID
		Email           string
		Name            string
		Active          bool
		EffectiveScopes []string `gorm:"type:text[]"`
	}
	var rows []row
	err = tenantDB.Raw(`
        SELECT
            u.id AS user_id, u.email, COALESCE(u.name,'') AS name, u.active,
            COALESCE(array_remove(array_agg(DISTINCT s.scope_string), NULL), '{}') AS effective_scopes
          FROM application_role_bindings b
          JOIN users u ON u.id = b.user_id
          LEFT JOIN application_role_scope_grants g ON g.role_id = b.role_id
          LEFT JOIN oauth_scopes s ON s.id = g.scope_id
         WHERE b.application_id = ? AND b.tenant_id = ?
         GROUP BY u.id, u.email, u.name, u.active
         ORDER BY u.email ASC
         LIMIT ? OFFSET ?
    `, applicationID, tenantID, limit, offset).Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("paged end user summary: %w", err)
	}
	users := make([]ApplicationEffectiveAccessUser, 0, len(rows))
	for _, r := range rows {
		users = append(users, ApplicationEffectiveAccessUser{
			UserID:          r.UserID,
			Email:           r.Email,
			Name:            r.Name,
			Active:          r.Active,
			EffectiveScopes: r.EffectiveScopes,
		})
	}
	return &EndUserAccessSummaryPage{
		Users: users,
		Total: total,
		Page:  page,
		Limit: limit,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────────
// /evidence-exports — CSV-friendly audit dump
// ─────────────────────────────────────────────────────────────────────────

// EvidenceRow is one line of the evidence export. Flattened for CSV use:
// one row per (user, role, scope) triple, redundant on user_email + role_name
// across rows but easy to load into a spreadsheet.
type EvidenceRow struct {
	UserID      uuid.UUID `json:"user_id"`
	UserEmail   string    `json:"user_email"`
	UserActive  bool      `json:"user_active"`
	RoleID      uuid.UUID `json:"role_id"`
	RoleName    string    `json:"role_name"`
	ScopeString string    `json:"scope_string"`
	GrantedAt   time.Time `json:"granted_at"`
	GrantedBy   *uuid.UUID `json:"granted_by,omitempty"`
}

// EvidenceExport produces the auditable flat view. Suited for export to
// CSV by the consumer; we return JSON.
func (s *GovernanceService) EvidenceExport(tenantID string, applicationID uuid.UUID) ([]EvidenceRow, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	var rows []EvidenceRow
	err = tenantDB.Raw(`
        SELECT
            b.user_id, u.email AS user_email, u.active AS user_active,
            b.role_id, r.name AS role_name,
            s.scope_string,
            b.granted_at, b.granted_by
          FROM application_role_bindings b
          JOIN users u ON u.id = b.user_id
          JOIN application_roles r ON r.id = b.role_id
          JOIN application_role_scope_grants g ON g.role_id = r.id
          JOIN oauth_scopes s ON s.id = g.scope_id
         WHERE b.application_id = ? AND b.tenant_id = ?
         ORDER BY u.email ASC, r.name ASC, s.scope_string ASC
    `, applicationID, tenantID).Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("evidence export: %w", err)
	}
	return rows, nil
}

// ─────────────────────────────────────────────────────────────────────────
// /posture-summary — compliance metrics
// ─────────────────────────────────────────────────────────────────────────

// PostureSummary is the at-a-glance compliance view.
type PostureSummary struct {
	ApplicationState  string `json:"application_state"`
	TotalRoles        int64  `json:"total_roles"`
	TotalScopes       int64  `json:"total_scopes"`
	TotalTools        int64  `json:"total_tools"`
	PublicTools       int64  `json:"public_tools"`
	UnmappedTools     int64  `json:"unmapped_tools"`
	TotalUsersBound   int64  `json:"total_users_bound"`
	UsersWithNoBindings int64 `json:"users_with_no_bindings"`
	TotalBindings     int64  `json:"total_bindings"`
	OrphanRoles       int64  `json:"orphan_roles"`
	UndismissedDriftEvents int64 `json:"undismissed_drift_events"`
}

// GetPostureSummary computes a single-shot compliance snapshot.
// Each metric is a separate query; we accept the round-trip cost for
// clarity. None of these grow super-linearly with tenant size.
func (s *GovernanceService) GetPostureSummary(tenantID string, applicationID uuid.UUID) (*PostureSummary, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	var rs models.ResourceServer
	if err := tenantDB.Select("state").Where("id = ?", applicationID).First(&rs).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrResourceServerNotFound
		}
		return nil, err
	}
	out := &PostureSummary{ApplicationState: rs.State}

	if err := tenantDB.Model(&models.ApplicationRole{}).
		Where("application_id = ? AND tenant_id = ?", applicationID, tenantID).
		Count(&out.TotalRoles).Error; err != nil {
		return nil, err
	}
	if err := tenantDB.Model(&models.OAuthScope{}).
		Where("application_id = ? AND tenant_id = ?", applicationID, tenantID).
		Count(&out.TotalScopes).Error; err != nil {
		return nil, err
	}
	if err := tenantDB.Model(&models.MCPTool{}).
		Where("resource_server_id = ? AND tenant_id = ?", applicationID, tenantID).
		Count(&out.TotalTools).Error; err != nil {
		return nil, err
	}
	if err := tenantDB.Model(&models.MCPTool{}).
		Where("resource_server_id = ? AND is_public = true", applicationID).
		Count(&out.PublicTools).Error; err != nil {
		return nil, err
	}
	// Unmapped = not public AND no required_scopes.
	if err := tenantDB.Raw(`
        SELECT COUNT(*) FROM mcp_tools
         WHERE resource_server_id = ? AND tenant_id = ?
           AND is_public = false
           AND (required_scopes IS NULL OR cardinality(required_scopes) = 0)
    `, applicationID, tenantID).Scan(&out.UnmappedTools).Error; err != nil {
		return nil, err
	}
	if err := tenantDB.Raw(`
        SELECT COUNT(DISTINCT user_id) FROM application_role_bindings
         WHERE application_id = ? AND tenant_id = ?
    `, applicationID, tenantID).Scan(&out.TotalUsersBound).Error; err != nil {
		return nil, err
	}
	if err := tenantDB.Model(&models.ApplicationRoleBinding{}).
		Where("application_id = ? AND tenant_id = ?", applicationID, tenantID).
		Count(&out.TotalBindings).Error; err != nil {
		return nil, err
	}
	// Orphan roles: roles in this Application with no scope grants AND
	// no bindings — pure dead weight admin should clean up.
	if err := tenantDB.Raw(`
        SELECT COUNT(*) FROM application_roles r
         WHERE r.application_id = ? AND r.tenant_id = ?
           AND NOT EXISTS (SELECT 1 FROM application_role_scope_grants g WHERE g.role_id = r.id)
           AND NOT EXISTS (SELECT 1 FROM application_role_bindings b WHERE b.role_id = r.id)
    `, applicationID, tenantID).Scan(&out.OrphanRoles).Error; err != nil {
		return nil, err
	}
	// Users with no bindings: users in the tenant who could use this app
	// but don't have any access yet. Useful "outreach" metric.
	if err := tenantDB.Raw(`
        SELECT COUNT(*) FROM users u
         WHERE u.deleted_at IS NULL
           AND u.id NOT IN (
               SELECT user_id FROM application_role_bindings
                WHERE application_id = ? AND tenant_id = ?
           )
    `, applicationID, tenantID).Scan(&out.UsersWithNoBindings).Error; err != nil {
		return nil, err
	}
	// Undismissed drift events (across all admins — just a count).
	if err := tenantDB.Model(&models.ApplicationDriftEvent{}).
		Where("application_id = ? AND tenant_id = ?", applicationID, tenantID).
		Count(&out.UndismissedDriftEvents).Error; err != nil {
		return nil, err
	}
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────────
// /tool-exposure — which tools are reachable by which users
// ─────────────────────────────────────────────────────────────────────────

// ToolExposureRow is one row of the tool-exposure view. For each tool,
// lists the users who can reach it (via their effective scopes OR because
// the tool is public).
type ToolExposureRow struct {
	ToolID         uuid.UUID `json:"tool_id"`
	ToolName       string    `json:"tool_name"`
	IsPublic       bool      `json:"is_public"`
	RequiredScopes []string  `json:"required_scopes"`
	ReachableBy    []string  `json:"reachable_by"` // user emails
}

// GetToolExposure returns one row per tool, listing which users in the
// tenant can call it. Public tools are reachable by anyone with an active
// session; non-public tools by users whose effective scopes intersect
// the tool's required_scopes.
//
// Cost: O(tools × users-bound). Fine for typical Application sizes; if
// you have 1000+ tools and 1000+ users, paginate by tool.
func (s *GovernanceService) GetToolExposure(tenantID string, applicationID uuid.UUID) ([]ToolExposureRow, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	// 1. Load all tools.
	var tools []models.MCPTool
	if err := tenantDB.Where("resource_server_id = ? AND tenant_id = ?", applicationID, tenantID).
		Order("name ASC").Find(&tools).Error; err != nil {
		return nil, fmt.Errorf("load tools: %w", err)
	}
	if len(tools) == 0 {
		return []ToolExposureRow{}, nil
	}
	// 2. Load every user's effective scope set in one go.
	users, err := s.GetApplicationEffectiveAccess(tenantID, applicationID)
	if err != nil {
		return nil, err
	}

	out := make([]ToolExposureRow, 0, len(tools))
	for _, t := range tools {
		row := ToolExposureRow{
			ToolID:         t.ID,
			ToolName:       t.Name,
			IsPublic:       t.IsPublic,
			RequiredScopes: []string(t.RequiredScopes),
		}
		if t.IsPublic {
			// Every active user can reach a public tool.
			for _, u := range users {
				if u.Active {
					row.ReachableBy = append(row.ReachableBy, u.Email)
				}
			}
			out = append(out, row)
			continue
		}
		if len(t.RequiredScopes) == 0 {
			// Not public AND no scopes required = deny-all per SDK contract.
			row.ReachableBy = []string{}
			out = append(out, row)
			continue
		}
		// Reachable if user's effective scopes intersect required_scopes.
		for _, u := range users {
			if hasIntersection([]string(t.RequiredScopes), u.EffectiveScopes) {
				row.ReachableBy = append(row.ReachableBy, u.Email)
			}
		}
		if row.ReachableBy == nil {
			row.ReachableBy = []string{}
		}
		out = append(out, row)
	}
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────

// scopesForRoles returns the deduplicated sorted scope strings for the
// given role-id set in this Application.
func (s *GovernanceService) scopesForRoles(
	tenantDB *gorm.DB,
	applicationID uuid.UUID,
	roles map[uuid.UUID]string,
) ([]string, error) {
	if len(roles) == 0 {
		return []string{}, nil
	}
	roleIDs := make([]uuid.UUID, 0, len(roles))
	for id := range roles {
		roleIDs = append(roleIDs, id)
	}
	var scopes []string
	err := tenantDB.Raw(`
        SELECT DISTINCT s.scope_string
          FROM application_role_scope_grants g
          JOIN oauth_scopes s ON s.id = g.scope_id
         WHERE g.role_id IN ? AND s.application_id = ?
         ORDER BY s.scope_string ASC
    `, roleIDs, applicationID).Scan(&scopes).Error
	if err != nil {
		return nil, fmt.Errorf("resolve scopes for roles: %w", err)
	}
	if scopes == nil {
		scopes = []string{}
	}
	return scopes, nil
}

// toolReachability returns (reachable, not_reachable) tool name lists
// given a scope set.
func (s *GovernanceService) toolReachability(
	tenantDB *gorm.DB,
	applicationID uuid.UUID,
	scopes []string,
) ([]string, []string, error) {
	scopeSet := make(map[string]struct{}, len(scopes))
	for _, sc := range scopes {
		scopeSet[sc] = struct{}{}
	}
	var tools []models.MCPTool
	if err := tenantDB.Where("resource_server_id = ?", applicationID).
		Order("name ASC").Find(&tools).Error; err != nil {
		return nil, nil, fmt.Errorf("load tools: %w", err)
	}
	reachable := make([]string, 0)
	notReachable := make([]string, 0)
	for _, t := range tools {
		if t.IsPublic {
			reachable = append(reachable, t.Name)
			continue
		}
		if len(t.RequiredScopes) == 0 {
			notReachable = append(notReachable, t.Name)
			continue
		}
		hit := false
		for _, req := range t.RequiredScopes {
			if _, ok := scopeSet[req]; ok {
				hit = true
				break
			}
		}
		if hit {
			reachable = append(reachable, t.Name)
		} else {
			notReachable = append(notReachable, t.Name)
		}
	}
	return reachable, notReachable, nil
}

func uuidSet(ids []uuid.UUID) map[uuid.UUID]struct{} {
	out := make(map[uuid.UUID]struct{}, len(ids))
	for _, id := range ids {
		out[id] = struct{}{}
	}
	return out
}

func mapValuesSorted(m map[uuid.UUID]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// stringDiff returns (added, removed) — what's in next but not prior, and
// what's in prior but not next. Both inputs are assumed deduplicated.
func stringDiff(prior, next []string) (added, removed []string) {
	priorSet := make(map[string]struct{}, len(prior))
	for _, s := range prior {
		priorSet[s] = struct{}{}
	}
	nextSet := make(map[string]struct{}, len(next))
	for _, s := range next {
		nextSet[s] = struct{}{}
	}
	for _, s := range next {
		if _, ok := priorSet[s]; !ok {
			added = append(added, s)
		}
	}
	for _, s := range prior {
		if _, ok := nextSet[s]; !ok {
			removed = append(removed, s)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return
}

func hasIntersection(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	bset := make(map[string]struct{}, len(b))
	for _, s := range b {
		bset[s] = struct{}{}
	}
	for _, s := range a {
		if _, ok := bset[s]; ok {
			return true
		}
	}
	return false
}

// Ensure strings.TrimSpace is referenced so the import is used even when
// the rest of the file doesn't trim. (We keep it for symmetry with the
// rest of the codebase's handler-side input trimming.)
var _ = strings.TrimSpace
