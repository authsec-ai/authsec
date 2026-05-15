// Package admin – Phase A membership controller.
//
// Two related resources live here:
//
//   • tenant_memberships      → operator-side identities (Owner/Admin/Member/...).
//   • tenant_end_user_states  → consumer-side state (plan tier, suspension, …).
//
// Two distinct user kinds is a deliberate product decision (see
// docs/USER_MANAGEMENT_AND_MCP_AUTHZ.md §2.3, §2.4). Members are who the
// tenant invites; End Users are who consents to use the tenant's published
// Applications. The admin UI manages them on separate pages.
package admin

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

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

func parseTenantID(c *gin.Context) (uuid.UUID, bool) {
	raw := c.Param("tenant_id")
	id, err := uuid.Parse(raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id", "detail": err.Error()})
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

// ────────────────────────────────────────────────────────────────────
// tenant_memberships
// ────────────────────────────────────────────────────────────────────

// ListMembers GET /v2/tenants/:tenant_id/memberships
// Optional ?status=active|suspended|invited|left and ?type=owner|admin|...
func (mc *MembershipController) ListMembers(c *gin.Context) {
	tenantID, ok := parseTenantID(c)
	if !ok {
		return
	}

	q := mc.db.Table("tenant_memberships AS tm").
		Select("tm.*, u.email AS user_email, u.name AS user_name, u.username AS user_username, u.last_login AS user_last_login").
		Joins("LEFT JOIN users u ON u.tenant_id = tm.tenant_id AND u.id = tm.user_id").
		Where("tm.tenant_id = ?", tenantID)
	if s := c.Query("status"); s != "" {
		q = q.Where("tm.status = ?", s)
	}
	if t := c.Query("type"); t != "" {
		q = q.Where("tm.membership_type = ?", t)
	}

	var rows []map[string]interface{}
	if err := q.Order("tm.created_at DESC").Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list memberships", "detail": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": rows, "count": len(rows)})
}

// GetMembership GET /v2/tenants/:tenant_id/memberships/:user_id
func (mc *MembershipController) GetMembership(c *gin.Context) {
	tenantID, ok := parseTenantID(c)
	if !ok {
		return
	}
	userID, ok := parseUserID(c)
	if !ok {
		return
	}

	var row map[string]interface{}
	err := mc.db.Table("tenant_memberships AS tm").
		Select("tm.*, u.email AS user_email, u.name AS user_name, u.username AS user_username, u.last_login AS user_last_login").
		Joins("LEFT JOIN users u ON u.tenant_id = tm.tenant_id AND u.id = tm.user_id").
		Where("tm.tenant_id = ? AND tm.user_id = ?", tenantID, userID).
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

// CreateMembership POST /v2/tenants/:tenant_id/memberships
// Records that a user is a tenant operator. Idempotent on (tenant_id, user_id).
func (mc *MembershipController) CreateMembership(c *gin.Context) {
	tenantID, ok := parseTenantID(c)
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
	source := strings.ToLower(strings.TrimSpace(req.Source))
	if source == "" {
		source = models.MembershipSourceAPI
	}

	actor := actorUserID(c) // set by auth middleware; helper below
	m := models.TenantMembership{
		TenantID:       tenantID,
		UserID:         userID,
		Status:         status,
		MembershipType: mtype,
		Source:         source,
		ExternalID:     req.ExternalID,
		InvitedBy:      actor,
	}
	if status == models.MembershipStatusActive {
		now := timeNow()
		m.JoinedAt = &now
	}

	result := mc.db.Where("tenant_id = ? AND user_id = ?", tenantID, userID).FirstOrCreate(&m)
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

// UpdateMembership PATCH /v2/tenants/:tenant_id/memberships/:user_id
func (mc *MembershipController) UpdateMembership(c *gin.Context) {
	tenantID, ok := parseTenantID(c)
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
		if *req.Status == models.MembershipStatusSuspended {
			updates["suspended_at"] = timeNow()
		}
	}
	if req.MembershipType != nil {
		updates["membership_type"] = *req.MembershipType
	}
	if req.ExternalID != nil {
		updates["external_id"] = *req.ExternalID
	}
	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
		return
	}

	res := mc.db.Model(&models.TenantMembership{}).
		Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		Updates(updates)
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed", "detail": res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "membership not found"})
		return
	}

	var m models.TenantMembership
	_ = mc.db.Where("tenant_id = ? AND user_id = ?", tenantID, userID).First(&m).Error
	c.JSON(http.StatusOK, m)
}

// DeleteMembership DELETE /v2/tenants/:tenant_id/memberships/:user_id
// Hard-deletes the membership row. Use UpdateMembership(status=suspended) for a soft state change.
func (mc *MembershipController) DeleteMembership(c *gin.Context) {
	tenantID, ok := parseTenantID(c)
	if !ok {
		return
	}
	userID, ok := parseUserID(c)
	if !ok {
		return
	}

	res := mc.db.Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		Delete(&models.TenantMembership{})
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
// tenant_end_user_states
// ────────────────────────────────────────────────────────────────────

// ListEndUsers GET /v2/tenants/:tenant_id/end-users
// Optional ?status=, ?plan_tier=, ?q=<email substring>.
func (mc *MembershipController) ListEndUsers(c *gin.Context) {
	tenantID, ok := parseTenantID(c)
	if !ok {
		return
	}

	q := mc.db.Table("tenant_end_user_states AS s").
		Select("s.*, u.email AS user_email, u.name AS user_name, u.username AS user_username, u.last_login AS user_last_login").
		Joins("LEFT JOIN users u ON u.tenant_id = s.tenant_id AND u.id = s.user_id").
		Where("s.tenant_id = ?", tenantID)
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
	c.JSON(http.StatusOK, gin.H{"items": rows, "count": len(rows)})
}

// GetEndUser GET /v2/tenants/:tenant_id/end-users/:user_id
func (mc *MembershipController) GetEndUser(c *gin.Context) {
	tenantID, ok := parseTenantID(c)
	if !ok {
		return
	}
	userID, ok := parseUserID(c)
	if !ok {
		return
	}

	var row map[string]interface{}
	err := mc.db.Table("tenant_end_user_states AS s").
		Select("s.*, u.email AS user_email, u.name AS user_name, u.username AS user_username, u.last_login AS user_last_login").
		Joins("LEFT JOIN users u ON u.tenant_id = s.tenant_id AND u.id = s.user_id").
		Where("s.tenant_id = ? AND s.user_id = ?", tenantID, userID).
		Take(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "end-user state not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, row)
}

// updateEndUserRequest is the payload for PATCH /end-users/:user_id.
type updateEndUserRequest struct {
	Status            *string `json:"status,omitempty"`
	PlanTier          *string `json:"plan_tier,omitempty"`
	RateLimitOverride *string `json:"rate_limit_override,omitempty"` // raw JSON string, validated by app
	SuspendedReason   *string `json:"suspended_reason,omitempty"`
}

// UpdateEndUser PATCH /v2/tenants/:tenant_id/end-users/:user_id
func (mc *MembershipController) UpdateEndUser(c *gin.Context) {
	tenantID, ok := parseTenantID(c)
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
		Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		Updates(updates)
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed", "detail": res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		// Upsert if it doesn't exist (an end user can be edited before their first consent in Phase A admin tooling).
		s := models.TenantEndUserState{
			TenantID: tenantID,
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
		c.JSON(http.StatusOK, s)
		return
	}

	var s models.TenantEndUserState
	_ = mc.db.Where("tenant_id = ? AND user_id = ?", tenantID, userID).First(&s).Error
	c.JSON(http.StatusOK, s)
}

// SuspendEndUser POST /v2/tenants/:tenant_id/end-users/:user_id/suspend
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

// ReactivateEndUser POST /v2/tenants/:tenant_id/end-users/:user_id/reactivate
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
	TenantID  string                 `json:"tenant_id" binding:"required"`
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
	tenantID, err := uuid.Parse(req.TenantID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant_id", "detail": err.Error()})
		return
	}
	roleID, err := uuid.Parse(req.RoleID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role_id", "detail": err.Error()})
		return
	}

	binding := models.RoleBinding{
		ID:        uuid.New(),
		TenantID:  &tenantID,
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
	tenantID, ok := parseTenantID(c)
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
		Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		Updates(updates)
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed", "detail": res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "end-user state not found"})
		return
	}
	var s models.TenantEndUserState
	_ = mc.db.Where("tenant_id = ? AND user_id = ?", tenantID, userID).First(&s).Error
	c.JSON(http.StatusOK, s)
}
