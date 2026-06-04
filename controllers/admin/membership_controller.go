// Package admin – Phase A membership controller.
//
// Two related resources live here:
//
//   - workspace_memberships   → operator-side identities (Owner/Admin/Member/...).
//   - workspace_end_user_states  → consumer-side state (plan tier, suspension, …).
//
// Two distinct user kinds is a deliberate product decision (see
// docs/USER_MANAGEMENT_AND_MCP_AUTHZ.md §2.3, §2.4). Members are who the
// tenant invites; End Users are who consents to use the tenant's published
// Applications. The admin UI manages them on separate pages.
package admin

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// revokeTokensOnSuspend is the fan-out the admin paths run after flipping an
// end-user's status to 'suspended'. Without this, the new status row is
// visible to the scope resolver (which fail-closes on the next /authorize and
// next introspect), but any token already issued keeps working until its TTL.
// The Hydra consent revoke + oauth_consent_grants.revoked_at update kills
// in-flight sessions within one introspect cycle.
//
// Fire-and-forget — matches the call shape used by roles_scoped_bindings_controller.
func revokeTokensOnSuspend(workspaceID, userID uuid.UUID) {
	oauthAS := services.NewOAuthASService(config.DB)
	go oauthAS.RevokeUserTokensForWorkspace(userID, workspaceID)
}

// actorUserID returns the calling user's UUID from the auth-middleware context,
// or nil if not present (e.g. during integration tests that bypass auth).
func actorUserID(c *gin.Context) *uuid.UUID {
	return getUserIDFromRequest(c)
}

// timeNow returns the current wall-clock time. Centralised so tests can stub.
func timeNow() time.Time {
	return time.Now().UTC()
}

// MembershipController serves /v2 tenant-scoped membership + end-user-state endpoints.
type MembershipController struct {
	db *gorm.DB
}

// NewMembershipController returns a controller bound to the global DB handle.
func NewMembershipController() *MembershipController {
	return &MembershipController{db: config.DB}
}

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

func parseWorkspaceID(c *gin.Context) (uuid.UUID, bool) {
	raw := c.Param("workspace_id")
	id, err := uuid.Parse(raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid workspace_id", "detail": err.Error()})
		return uuid.Nil, false
	}
	return id, true
}

func parseUserID(c *gin.Context) (uuid.UUID, bool) {
	raw := c.Param("user_id")
	id, err := uuid.Parse(raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id", "detail": err.Error()})
		return uuid.Nil, false
	}
	return id, true
}

func (mc *MembershipController) workspaceRoleID(workspaceID uuid.UUID, roleName string) (uuid.UUID, error) {
	var roleID uuid.UUID
	err := mc.db.Table("roles").
		Select("id").
		Where("workspace_id = ? AND name = ?", workspaceID, roleName).
		Take(&roleID).Error
	return roleID, err
}

// ────────────────────────────────────────────────────────────────────
// workspace_memberships
// ────────────────────────────────────────────────────────────────────

// ListMembers GET /v2/tenants/:workspace_id/memberships
// Optional ?status=active|suspended|invited|left and ?type=owner|admin|...
func (mc *MembershipController) ListMembers(c *gin.Context) {
	workspaceID, ok := parseWorkspaceID(c)
	if !ok {
		return
	}

	q := mc.db.Table("workspace_memberships AS wm").
		Select(`
			wm.id,
			wm.workspace_id AS workspace_id,
			wm.user_id,
			wm.status,
			r.name AS membership_type,
			'workspace' AS source,
			wm.created_at AS joined_at,
			wm.created_at,
			wm.updated_at,
			u.email AS user_email,
			u.name AS user_name,
			u.username AS user_username,
			u.last_login AS user_last_login
		`).
		Joins("LEFT JOIN roles r ON r.id = wm.role_id").
		Joins("LEFT JOIN users u ON u.workspace_id = wm.workspace_id AND u.id = wm.user_id").
		Where("wm.workspace_id = ?", workspaceID)
	if s := c.Query("status"); s != "" {
		q = q.Where("wm.status = ?", s)
	}
	if t := c.Query("type"); t != "" {
		q = q.Where("r.name = ?", t)
	}

	var rows []map[string]interface{}
	if err := q.Order("wm.created_at DESC").Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list memberships", "detail": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": rows, "count": len(rows)})
}

// GetMembership GET /v2/tenants/:workspace_id/memberships/:user_id
func (mc *MembershipController) GetMembership(c *gin.Context) {
	workspaceID, ok := parseWorkspaceID(c)
	if !ok {
		return
	}
	userID, ok := parseUserID(c)
	if !ok {
		return
	}

	var row map[string]interface{}
	err := mc.db.Table("workspace_memberships AS wm").
		Select(`
			wm.id,
			wm.workspace_id AS workspace_id,
			wm.user_id,
			wm.status,
			r.name AS membership_type,
			'workspace' AS source,
			wm.created_at AS joined_at,
			wm.created_at,
			wm.updated_at,
			u.email AS user_email,
			u.name AS user_name,
			u.username AS user_username,
			u.last_login AS user_last_login
		`).
		Joins("LEFT JOIN roles r ON r.id = wm.role_id").
		Joins("LEFT JOIN users u ON u.workspace_id = wm.workspace_id AND u.id = wm.user_id").
		Where("wm.workspace_id = ? AND wm.user_id = ?", workspaceID, userID).
		Take(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "membership not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, row)
}

// createMembershipRequest is the payload for POST /memberships.
type createMembershipRequest struct {
	UserID         string  `json:"user_id" binding:"required"`
	MembershipType string  `json:"membership_type"`
	Status         string  `json:"status"`
	Source         string  `json:"source"`
	ExternalID     *string `json:"external_id,omitempty"`
}

// CreateMembership POST /v2/tenants/:workspace_id/memberships
// Records that a user is a tenant operator. Idempotent on (workspace_id, user_id).
func (mc *MembershipController) CreateMembership(c *gin.Context) {
	workspaceID, ok := parseWorkspaceID(c)
	if !ok {
		return
	}

	var req createMembershipRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body", "detail": err.Error()})
		return
	}
	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id", "detail": err.Error()})
		return
	}

	// Defaults
	mtype := strings.ToLower(strings.TrimSpace(req.MembershipType))
	if mtype == "" {
		mtype = models.MembershipTypeMember
	}
	status := strings.ToLower(strings.TrimSpace(req.Status))
	if status == "" {
		status = models.MembershipStatusActive
	}
	roleID, err := mc.workspaceRoleID(workspaceID, mtype)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "workspace role not found", "detail": err.Error()})
		return
	}

	m := models.WorkspaceMembership{
		WorkspaceID: workspaceID,
		UserID:      userID,
		RoleID:      roleID,
		Status:      status,
	}
	result := mc.db.Where("workspace_id = ? AND user_id = ?", workspaceID, userID).FirstOrCreate(&m)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create membership", "detail": result.Error.Error()})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusOK, m)
		return
	}
	c.JSON(http.StatusCreated, m)
}

// updateMembershipRequest is the payload for PATCH /memberships/:user_id.
type updateMembershipRequest struct {
	Status         *string `json:"status,omitempty"`
	MembershipType *string `json:"membership_type,omitempty"`
	ExternalID     *string `json:"external_id,omitempty"`
}

// UpdateMembership PATCH /v2/tenants/:workspace_id/memberships/:user_id
func (mc *MembershipController) UpdateMembership(c *gin.Context) {
	workspaceID, ok := parseWorkspaceID(c)
	if !ok {
		return
	}
	userID, ok := parseUserID(c)
	if !ok {
		return
	}

	var req updateMembershipRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body", "detail": err.Error()})
		return
	}

	updates := map[string]interface{}{}
	if req.Status != nil {
		updates["status"] = *req.Status
	}
	if req.MembershipType != nil {
		mtype := strings.ToLower(strings.TrimSpace(*req.MembershipType))
		roleID, err := mc.workspaceRoleID(workspaceID, mtype)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "workspace role not found", "detail": err.Error()})
			return
		}
		updates["role_id"] = roleID
	}
	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
		return
	}

	res := mc.db.Model(&models.WorkspaceMembership{}).
		Where("workspace_id = ? AND user_id = ?", workspaceID, userID).
		Updates(updates)
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed", "detail": res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "membership not found"})
		return
	}

	var row map[string]interface{}
	_ = mc.db.Table("workspace_memberships AS wm").
		Select("wm.id, wm.workspace_id AS workspace_id, wm.user_id, wm.status, r.name AS membership_type, 'workspace' AS source, wm.created_at AS joined_at, wm.created_at, wm.updated_at").
		Joins("LEFT JOIN roles r ON r.id = wm.role_id").
		Where("wm.workspace_id = ? AND wm.user_id = ?", workspaceID, userID).
		Take(&row).Error
	c.JSON(http.StatusOK, row)
}

// DeleteMembership DELETE /v2/tenants/:workspace_id/memberships/:user_id
// Hard-deletes the membership row. Use UpdateMembership(status=suspended) for a soft state change.
func (mc *MembershipController) DeleteMembership(c *gin.Context) {
	workspaceID, ok := parseWorkspaceID(c)
	if !ok {
		return
	}
	userID, ok := parseUserID(c)
	if !ok {
		return
	}

	res := mc.db.Where("workspace_id = ? AND user_id = ?", workspaceID, userID).
		Delete(&models.WorkspaceMembership{})
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed", "detail": res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "membership not found"})
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

// ────────────────────────────────────────────────────────────────────
// workspace_end_user_states
// ────────────────────────────────────────────────────────────────────

type endUserAccessApplication struct {
	ApplicationID string `json:"application_id"`
	Name          string `json:"name"`
	ResourceURI   string `json:"resource_uri"`
	RoleID        string `json:"role_id"`
	RoleName      string `json:"role_name"`
	RoleLabel     string `json:"role_label"`
	BindingID     string `json:"binding_id"`
	ScopesCount   int64  `json:"scopes_count"`
}

func applicationRoleLabel(roleName string) string {
	idx := strings.LastIndex(roleName, ":")
	if idx >= 0 && idx < len(roleName)-1 {
		roleName = roleName[idx+1:]
	}
	roleName = strings.TrimSpace(strings.ReplaceAll(roleName, "_", " "))
	if roleName == "" {
		return "Application role"
	}
	parts := strings.Fields(roleName)
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + strings.ToLower(part[1:])
	}
	return strings.Join(parts, " ")
}

func (mc *MembershipController) endUserAccessSnapshot(workspaceID uuid.UUID, userID uuid.UUID) ([]endUserAccessApplication, string, int64) {
	type row struct {
		ApplicationID string
		Name          string
		ResourceURI   string
		RoleID        string
		RoleName      string
		BindingID     string
		ScopesCount   int64
	}
	var rows []row
	err := mc.db.Table("role_bindings rb").
		Select(`rs.id::text AS application_id, COALESCE(rs.name, '') AS name,
			COALESCE(rs.resource_uri, '') AS resource_uri, rb.role_id::text AS role_id,
			COALESCE(rb.role_name, ro.name, '') AS role_name, rb.id::text AS binding_id,
			COUNT(DISTINCT osp.scope_id) AS scopes_count`).
		Joins("JOIN roles ro ON ro.id = rb.role_id").
		Joins("JOIN resource_servers rs ON rs.workspace_id = rb.workspace_id AND ro.name LIKE ('rs-' || rs.id::text || ':%')").
		Joins("LEFT JOIN role_permissions rp ON rp.role_id = rb.role_id").
		Joins("LEFT JOIN oauth_scope_permissions osp ON osp.permission_id = rp.permission_id").
		Where("rb.workspace_id = ? AND rb.user_id = ?", workspaceID, userID).
		Where("(rb.expires_at IS NULL OR rb.expires_at > NOW())").
		Where("(rb.scope_type IS NULL AND rb.scope_id IS NULL) OR (rb.scope_type = 'resource_server' AND rb.scope_id = rs.id)").
		Group("rs.id, rs.name, rs.resource_uri, rb.role_id, rb.role_name, ro.name, rb.id").
		Order("rs.name ASC").
		Scan(&rows).Error
	if err != nil || len(rows) == 0 {
		return []endUserAccessApplication{}, "No application access", 0
	}

	apps := make([]endUserAccessApplication, 0, len(rows))
	var totalScopes int64
	for _, r := range rows {
		totalScopes += r.ScopesCount
		apps = append(apps, endUserAccessApplication{
			ApplicationID: r.ApplicationID,
			Name:          r.Name,
			ResourceURI:   r.ResourceURI,
			RoleID:        r.RoleID,
			RoleName:      r.RoleName,
			RoleLabel:     applicationRoleLabel(r.RoleName),
			BindingID:     r.BindingID,
			ScopesCount:   r.ScopesCount,
		})
	}

	summary := apps[0].RoleLabel + " on " + apps[0].Name
	if apps[0].ScopesCount == 1 {
		summary += " · 1 scope"
	} else {
		summary += fmt.Sprintf(" · %d scopes", apps[0].ScopesCount)
	}
	if len(apps) > 1 {
		summary += fmt.Sprintf(" · +%d more", len(apps)-1)
	}

	return apps, summary, totalScopes
}

func uuidFromMapValue(v interface{}) (uuid.UUID, bool) {
	switch typed := v.(type) {
	case uuid.UUID:
		return typed, true
	case string:
		id, err := uuid.Parse(typed)
		return id, err == nil
	case []byte:
		id, err := uuid.Parse(string(typed))
		return id, err == nil
	default:
		return uuid.Nil, false
	}
}

func (mc *MembershipController) decorateEndUserAccess(row map[string]interface{}, workspaceID uuid.UUID, userID uuid.UUID) {
	apps, summary, scopesCount := mc.endUserAccessSnapshot(workspaceID, userID)
	row["access_summary"] = summary
	row["applications"] = apps
	row["applications_count"] = len(apps)
	row["effective_scopes_count"] = scopesCount
}

// ListEndUsers GET /v2/tenants/:workspace_id/end-users
// Optional ?status=, ?plan_tier=, ?q=<email substring>.
func (mc *MembershipController) ListEndUsers(c *gin.Context) {
	workspaceID, ok := parseWorkspaceID(c)
	if !ok {
		return
	}

	q := mc.db.Table("workspace_end_user_states AS s").
		Select("s.*, u.email AS user_email, u.name AS user_name, u.username AS user_username, u.last_login AS user_last_login").
		Joins("LEFT JOIN users u ON u.workspace_id = s.workspace_id AND u.id = s.user_id").
		Where("s.workspace_id = ?", workspaceID)
	if v := c.Query("status"); v != "" {
		q = q.Where("s.status = ?", v)
	}
	if v := c.Query("plan_tier"); v != "" {
		q = q.Where("s.plan_tier = ?", v)
	}
	if v := strings.TrimSpace(c.Query("q")); v != "" {
		q = q.Where("u.email ILIKE ? OR u.username ILIKE ?", "%"+v+"%", "%"+v+"%")
	}

	var rows []map[string]interface{}
	if err := q.Order("s.last_seen_at DESC NULLS LAST, s.first_consent_at DESC").
		Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list end users", "detail": err.Error()})
		return
	}
	for _, row := range rows {
		if userID, ok := uuidFromMapValue(row["user_id"]); ok {
			mc.decorateEndUserAccess(row, workspaceID, userID)
		}
	}
	c.JSON(http.StatusOK, gin.H{"items": rows, "count": len(rows)})
}

// GetEndUser GET /v2/tenants/:workspace_id/end-users/:user_id
func (mc *MembershipController) GetEndUser(c *gin.Context) {
	workspaceID, ok := parseWorkspaceID(c)
	if !ok {
		return
	}
	userID, ok := parseUserID(c)
	if !ok {
		return
	}

	var row map[string]interface{}
	err := mc.db.Table("workspace_end_user_states AS s").
		Select("s.*, u.email AS user_email, u.name AS user_name, u.username AS user_username, u.last_login AS user_last_login").
		Joins("LEFT JOIN users u ON u.workspace_id = s.workspace_id AND u.id = s.user_id").
		Where("s.workspace_id = ? AND s.user_id = ?", workspaceID, userID).
		Take(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "end-user state not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	mc.decorateEndUserAccess(row, workspaceID, userID)
	c.JSON(http.StatusOK, row)
}

// updateEndUserRequest is the payload for PATCH /end-users/:user_id.
type updateEndUserRequest struct {
	Status            *string `json:"status,omitempty"`
	PlanTier          *string `json:"plan_tier,omitempty"`
	RateLimitOverride *string `json:"rate_limit_override,omitempty"` // raw JSON string, validated by app
	SuspendedReason   *string `json:"suspended_reason,omitempty"`
}

// UpdateEndUser PATCH /v2/tenants/:workspace_id/end-users/:user_id
func (mc *MembershipController) UpdateEndUser(c *gin.Context) {
	workspaceID, ok := parseWorkspaceID(c)
	if !ok {
		return
	}
	userID, ok := parseUserID(c)
	if !ok {
		return
	}

	var req updateEndUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body", "detail": err.Error()})
		return
	}

	updates := map[string]interface{}{}
	if req.Status != nil {
		updates["status"] = *req.Status
		if *req.Status == models.EndUserStatusSuspended {
			updates["suspended_at"] = timeNow()
			updates["suspended_by"] = actorUserID(c)
			if req.SuspendedReason != nil {
				updates["suspended_reason"] = *req.SuspendedReason
			}
		}
	}
	if req.PlanTier != nil {
		if *req.PlanTier == "" {
			updates["plan_tier"] = nil
		} else {
			updates["plan_tier"] = *req.PlanTier
		}
	}
	if req.RateLimitOverride != nil {
		updates["rate_limit_override"] = *req.RateLimitOverride
	}
	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
		return
	}

	res := mc.db.Model(&models.TenantEndUserState{}).
		Where("workspace_id = ? AND user_id = ?", workspaceID, userID).
		Updates(updates)
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed", "detail": res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		// Upsert if it doesn't exist (an end user can be edited before their first consent in Phase A admin tooling).
		s := models.TenantEndUserState{
			WorkspaceID: workspaceID,
			UserID:   userID,
			Status:   models.EndUserStatusActive,
		}
		for k, v := range updates {
			switch k {
			case "status":
				s.Status = v.(string)
			case "plan_tier":
				if v == nil {
					s.PlanTier = nil
				} else {
					sv := v.(string)
					s.PlanTier = &sv
				}
			}
		}
		if err := mc.db.Create(&s).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "upsert failed", "detail": err.Error()})
			return
		}
		if s.Status == models.EndUserStatusSuspended {
			revokeTokensOnSuspend(workspaceID, userID)
		}
		c.JSON(http.StatusOK, s)
		return
	}

	if req.Status != nil && *req.Status == models.EndUserStatusSuspended {
		revokeTokensOnSuspend(workspaceID, userID)
	}

	var s models.TenantEndUserState
	_ = mc.db.Where("workspace_id = ? AND user_id = ?", workspaceID, userID).First(&s).Error
	c.JSON(http.StatusOK, s)
}

// SuspendEndUser POST /v2/tenants/:workspace_id/end-users/:user_id/suspend
// Convenience over UpdateEndUser when the caller has a free-text reason.
func (mc *MembershipController) SuspendEndUser(c *gin.Context) {
	body := struct {
		Reason string `json:"reason"`
	}{}
	_ = c.ShouldBindJSON(&body)
	// Reuse UpdateEndUser by stuffing a synthetic body via context.
	susp := models.EndUserStatusSuspended
	req := updateEndUserRequest{
		Status:          &susp,
		SuspendedReason: &body.Reason,
	}
	mc.runEndUserUpdate(c, req)
}

// ReactivateEndUser POST /v2/tenants/:workspace_id/end-users/:user_id/reactivate
func (mc *MembershipController) ReactivateEndUser(c *gin.Context) {
	active := models.EndUserStatusActive
	mc.runEndUserUpdate(c, updateEndUserRequest{Status: &active})
}

// ────────────────────────────────────────────────────────────────────
// group-subject role bindings & effective access
// ────────────────────────────────────────────────────────────────────

// bindGroupToRoleRequest is the payload for POST /v2/groups/:group_id/role-bindings.
// A simpler shape than the legacy AssignRoleScopedAdmin handler: subject is
// always the group identified in the URL.
type bindGroupToRoleRequest struct {
	WorkspaceID  string                 `json:"workspace_id" binding:"required"`
	RoleID    string                 `json:"role_id"   binding:"required"`
	ScopeType *string                `json:"scope_type,omitempty"`
	ScopeID   *string                `json:"scope_id,omitempty"`
	Condition map[string]interface{} `json:"conditions,omitempty"`
	ExpiresAt *time.Time             `json:"expires_at,omitempty"`
}

// BindGroupToRole POST /v2/groups/:group_id/role-bindings
// Creates a role_bindings row with group_id set as the subject.
func (mc *MembershipController) BindGroupToRole(c *gin.Context) {
	groupIDRaw := c.Param("group_id")
	groupID, err := uuid.Parse(groupIDRaw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid group_id", "detail": err.Error()})
		return
	}

	var req bindGroupToRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body", "detail": err.Error()})
		return
	}
	workspaceID, err := uuid.Parse(req.WorkspaceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid workspace_id", "detail": err.Error()})
		return
	}
	roleID, err := uuid.Parse(req.RoleID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role_id", "detail": err.Error()})
		return
	}

	binding := models.RoleBinding{
		ID:        uuid.New(),
		WorkspaceID:  &workspaceID,
		GroupID:   &groupID,
		RoleID:    roleID,
		ScopeType: req.ScopeType,
		ExpiresAt: req.ExpiresAt,
		CreatedBy: actorUserID(c),
	}
	if req.ScopeID != nil && *req.ScopeID != "" && *req.ScopeID != "*" {
		sid, err := uuid.Parse(*req.ScopeID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scope_id", "detail": err.Error()})
			return
		}
		binding.ScopeID = &sid
	}

	if err := mc.db.Create(&binding).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create binding", "detail": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, binding)
}

// EffectiveAccess GET /v2/users/:user_id/effective-access
// Returns every role binding affecting this user — direct + group-mediated.
// Powers the Effective Access Explorer admin page.
func (mc *MembershipController) EffectiveAccess(c *gin.Context) {
	userID, ok := parseUserID(c)
	if !ok {
		return
	}

	// Hand off to RBACService.ListEffectiveBindings via a lightweight inline query
	// to avoid adding a service-init dependency here.
	principalGroups := mc.db.Table("user_groups").Select("group_id").Where("user_id = ?", userID)

	type row struct {
		BindingID uuid.UUID  `json:"binding_id"`
		RoleID    uuid.UUID  `json:"role_id"`
		RoleName  string     `json:"role_name"`
		Subject   string     `json:"subject"`
		SubjectID uuid.UUID  `json:"subject_id"`
		ScopeType *string    `json:"scope_type"`
		ScopeID   *uuid.UUID `json:"scope_id"`
		ExpiresAt *string    `json:"expires_at,omitempty"`
	}

	var rows []row
	if err := mc.db.Table("role_bindings rb").
		Select(`rb.id as binding_id, rb.role_id, r.name as role_name,
			CASE
				WHEN rb.user_id IS NOT NULL THEN 'user'
				WHEN rb.group_id IS NOT NULL THEN 'group'
				WHEN rb.service_account_id IS NOT NULL THEN 'service_account'
			END as subject,
			COALESCE(rb.user_id, rb.group_id, rb.service_account_id) as subject_id,
			rb.scope_type, rb.scope_id,
			TO_CHAR(rb.expires_at, 'YYYY-MM-DD"T"HH24:MI:SSZ') as expires_at`).
		Joins("JOIN roles r ON rb.role_id = r.id").
		Where("rb.user_id = ? OR rb.group_id IN (?)", userID, principalGroups).
		Where("(rb.expires_at IS NULL OR rb.expires_at > NOW())").
		Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "effective-access query failed", "detail": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": rows, "count": len(rows)})
}

// runEndUserUpdate is the shared core used by the convenience handlers above.
func (mc *MembershipController) runEndUserUpdate(c *gin.Context, req updateEndUserRequest) {
	workspaceID, ok := parseWorkspaceID(c)
	if !ok {
		return
	}
	userID, ok := parseUserID(c)
	if !ok {
		return
	}

	updates := map[string]interface{}{}
	if req.Status != nil {
		updates["status"] = *req.Status
		if *req.Status == models.EndUserStatusSuspended {
			updates["suspended_at"] = timeNow()
			updates["suspended_by"] = actorUserID(c)
			if req.SuspendedReason != nil {
				updates["suspended_reason"] = *req.SuspendedReason
			}
		}
	}

	res := mc.db.Model(&models.TenantEndUserState{}).
		Where("workspace_id = ? AND user_id = ?", workspaceID, userID).
		Updates(updates)
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed", "detail": res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "end-user state not found"})
		return
	}
	if req.Status != nil && *req.Status == models.EndUserStatusSuspended {
		revokeTokensOnSuspend(workspaceID, userID)
	}
	var s models.TenantEndUserState
	_ = mc.db.Where("workspace_id = ? AND user_id = ?", workspaceID, userID).First(&s).Error
	c.JSON(http.StatusOK, s)
}
