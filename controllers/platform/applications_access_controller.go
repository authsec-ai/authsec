package platform

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ── GET /authsec/applications/:id/access-assignments ─────────────────────────

type accessAssignmentItem struct {
	ID              string   `json:"id"`
	IdentityType    string   `json:"identity_type"` // "user" | "service_account"
	IdentityID      string   `json:"identity_id"`
	IdentityName    string   `json:"identity_name"`
	RoleID          string   `json:"role_id"`
	RoleName        string   `json:"role_name"`
	EffectiveScopes []string `json:"effective_scopes"`
	Status          string   `json:"status"`
	CreatedAt       string   `json:"created_at"`
}

// ListAccessAssignments returns all user and service-account role bindings
// scoped to this application, with effective_scopes per row.
// GET /authsec/applications/:id/access-assignments
func (ctrl *ScopeMatrixController) ListAccessAssignments(c *gin.Context) {
	workspaceID, err := extractWorkspaceID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	rs, err := ctrl.rsService.GetByIDAndTenant(rsID, workspaceID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}

	prefix := fmt.Sprintf("rs-%s:%%", rs.ID.String())

	type rawRow struct {
		ID           string    `gorm:"column:id"`
		IdentityType string    `gorm:"column:identity_type"`
		IdentityID   string    `gorm:"column:identity_id"`
		IdentityName string    `gorm:"column:identity_name"`
		RoleID       string    `gorm:"column:role_id"`
		RoleName     string    `gorm:"column:role_name"`
		CreatedAt    time.Time `gorm:"column:created_at"`
	}

	var rows []rawRow
	err = config.DB.Raw(`
		SELECT rb.id::text AS id,
		       'user' AS identity_type,
		       rb.user_id::text AS identity_id,
		       COALESCE(NULLIF(u.name,''), u.email, rb.user_id::text) AS identity_name,
		       rb.role_id::text AS role_id,
		       COALESCE(NULLIF(rb.role_name,''), ro.name, '') AS role_name,
		       rb.created_at
		FROM role_bindings rb
		JOIN roles ro ON ro.id = rb.role_id
		LEFT JOIN users u ON u.id = rb.user_id AND u.workspace_id = rb.workspace_id
		WHERE rb.workspace_id = ?
		  AND rb.user_id IS NOT NULL
		  AND (rb.expires_at IS NULL OR rb.expires_at > NOW())
		  AND ro.name LIKE ?
		  AND (rb.scope_type IS NULL OR (rb.scope_type = 'resource_server' AND rb.scope_id = ?))

		UNION ALL

		SELECT rb.id::text AS id,
		       'service_account' AS identity_type,
		       rb.service_account_id::text AS identity_id,
		       COALESCE(sa.name, rb.service_account_id::text) AS identity_name,
		       rb.role_id::text AS role_id,
		       COALESCE(NULLIF(rb.role_name,''), ro.name, '') AS role_name,
		       rb.created_at
		FROM role_bindings rb
		JOIN roles ro ON ro.id = rb.role_id
		LEFT JOIN service_accounts sa ON sa.id = rb.service_account_id
		WHERE rb.workspace_id = ?
		  AND rb.service_account_id IS NOT NULL
		  AND (rb.expires_at IS NULL OR rb.expires_at > NOW())
		  AND ro.name LIKE ?
		  AND (rb.scope_type IS NULL OR (rb.scope_type = 'resource_server' AND rb.scope_id = ?))

		ORDER BY created_at DESC
	`, workspaceID, prefix, rs.ID,
		workspaceID, prefix, rs.ID).Scan(&rows).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Batch-resolve effective scopes: role_id → []scope_string for this RS.
	roleIDs := make([]string, 0, len(rows))
	seen := map[string]struct{}{}
	for _, r := range rows {
		if _, ok := seen[r.RoleID]; !ok {
			roleIDs = append(roleIDs, r.RoleID)
			seen[r.RoleID] = struct{}{}
		}
	}

	scopesByRole := map[string][]string{}
	if len(roleIDs) > 0 {
		type scopeRow struct {
			RoleID      string `gorm:"column:role_id"`
			ScopeString string `gorm:"column:scope_string"`
		}
		var scopeRows []scopeRow
		config.DB.Raw(`
			SELECT rp.role_id::text AS role_id, os.scope_string AS scope_string
			FROM role_permissions rp
			JOIN oauth_scope_permissions osp ON osp.permission_id = rp.permission_id
			JOIN oauth_scopes os ON os.id = osp.scope_id
			WHERE rp.role_id::text IN ?
			  AND os.resource_server_id = ?
		`, roleIDs, rs.ID).Scan(&scopeRows)
		for _, sr := range scopeRows {
			scopesByRole[sr.RoleID] = append(scopesByRole[sr.RoleID], sr.ScopeString)
		}
		for k := range scopesByRole {
			sort.Strings(scopesByRole[k])
		}
	}

	items := make([]accessAssignmentItem, 0, len(rows))
	for _, r := range rows {
		scopes := scopesByRole[r.RoleID]
		if scopes == nil {
			scopes = []string{}
		}
		items = append(items, accessAssignmentItem{
			ID:              r.ID,
			IdentityType:    r.IdentityType,
			IdentityID:      r.IdentityID,
			IdentityName:    r.IdentityName,
			RoleID:          r.RoleID,
			RoleName:        r.RoleName,
			EffectiveScopes: scopes,
			Status:          "active",
			CreatedAt:       r.CreatedAt.UTC().Format(time.RFC3339),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"application_id": rs.ID.String(),
		"items":          items,
	})
}

// ── POST /authsec/applications/:id/access-assignments/users ──────────────────

// CreateUserAssignment assigns a user to an RS-scoped role on this application.
// POST /authsec/applications/:id/access-assignments/users
func (ctrl *ScopeMatrixController) CreateUserAssignment(c *gin.Context) {
	workspaceID, err := extractWorkspaceID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	rs, err := ctrl.rsService.GetByIDAndTenant(rsID, workspaceID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}

	var req struct {
		UserID string `json:"user_id" binding:"required"`
		RoleID string `json:"role_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id and role_id required"})
		return
	}

	userUUID, err := uuid.Parse(req.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
		return
	}
	roleUUID, err := uuid.Parse(req.RoleID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role_id"})
		return
	}

	var role models.RBACRole
	if err := config.DB.Where("id = ? AND workspace_id = ?", roleUUID, workspaceID).First(&role).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "role not found"})
		return
	}
	if !strings.HasPrefix(role.Name, fmt.Sprintf("rs-%s:", rs.ID.String())) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role is not scoped to this application"})
		return
	}

	var userRow struct {
		ID       uuid.UUID
		Email    string
		Name     string
		Username *string
	}
	if err := config.DB.Table("users").
		Select("id, email, name, username").
		Where("id = ? AND workspace_id = ?", userUUID, workspaceID).
		Take(&userRow).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	scopeType := "resource_server"
	var existingCount int64
	config.DB.Model(&models.RoleBinding{}).
		Where("workspace_id = ? AND user_id = ? AND role_id = ?", workspaceID, userUUID, roleUUID).
		Where("scope_type = ? AND scope_id = ?", scopeType, rs.ID).
		Count(&existingCount)
	if existingCount > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "assignment already exists for this user and role"})
		return
	}

	username := ""
	if userRow.Username != nil {
		username = *userRow.Username
	}
	if username == "" {
		username = userRow.Email
	}
	if username == "" {
		username = userRow.ID.String()
	}

	ws := workspaceID
	binding := models.RoleBinding{
		WorkspaceID:      &ws,
		UserID:           &userUUID,
		Username:         username,
		RoleID:           roleUUID,
		RoleName:         role.Name,
		ScopeType:        &scopeType,
		ScopeID:          &rs.ID,
		Conditions:       json.RawMessage([]byte("{}")),
		AssignmentSource: "manual_admin",
		CreatedAt:        time.Now().UTC(),
	}
	if err := config.DB.Create(&binding).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, workspaceID.String(), "access_assignment_created", "role_binding",
		binding.ID.String(), http.StatusCreated, nil,
		map[string]interface{}{"user_id": userUUID, "role_id": roleUUID, "application_id": rs.ID})
	c.JSON(http.StatusCreated, gin.H{"id": binding.ID.String()})
}

// ── POST /authsec/applications/:id/access-assignments/service-accounts ────────

// CreateSAAssignment assigns a service account to an RS-scoped role.
// POST /authsec/applications/:id/access-assignments/service-accounts
func (ctrl *ScopeMatrixController) CreateSAAssignment(c *gin.Context) {
	workspaceID, err := extractWorkspaceID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	rs, err := ctrl.rsService.GetByIDAndTenant(rsID, workspaceID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}

	var req struct {
		ServiceAccountID string `json:"service_account_id" binding:"required"`
		RoleID           string `json:"role_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "service_account_id and role_id required"})
		return
	}

	saUUID, err := uuid.Parse(req.ServiceAccountID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid service_account_id"})
		return
	}
	roleUUID, err := uuid.Parse(req.RoleID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role_id"})
		return
	}

	var sa models.ServiceAccount
	if err := config.DB.Where("id = ? AND workspace_id = ?", saUUID, workspaceID).First(&sa).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "service account not found"})
		return
	}

	var role models.RBACRole
	if err := config.DB.Where("id = ? AND workspace_id = ?", roleUUID, workspaceID).First(&role).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "role not found"})
		return
	}
	if !strings.HasPrefix(role.Name, fmt.Sprintf("rs-%s:", rs.ID.String())) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role is not scoped to this application"})
		return
	}

	scopeType := "resource_server"
	var existingCount int64
	config.DB.Model(&models.RoleBinding{}).
		Where("workspace_id = ? AND service_account_id = ? AND role_id = ?", workspaceID, saUUID, roleUUID).
		Where("scope_type = ? AND scope_id = ?", scopeType, rs.ID).
		Count(&existingCount)
	if existingCount > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "assignment already exists for this service account and role"})
		return
	}

	ws := workspaceID
	binding := models.RoleBinding{
		WorkspaceID:      &ws,
		ServiceAccountID: &saUUID,
		RoleID:           roleUUID,
		RoleName:         role.Name,
		ScopeType:        &scopeType,
		ScopeID:          &rs.ID,
		Conditions:       json.RawMessage([]byte("{}")),
		AssignmentSource: "manual_admin",
		CreatedAt:        time.Now().UTC(),
	}
	if err := config.DB.Create(&binding).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, workspaceID.String(), "access_assignment_created", "role_binding",
		binding.ID.String(), http.StatusCreated, nil,
		map[string]interface{}{"service_account_id": saUUID, "role_id": roleUUID, "application_id": rs.ID})
	c.JSON(http.StatusCreated, gin.H{"id": binding.ID.String()})
}

// ── DELETE /authsec/applications/:id/access-assignments/:assignment_id ────────

// DeleteAssignment removes a role binding (user or SA) from this application.
// DELETE /authsec/applications/:id/access-assignments/:assignment_id
func (ctrl *ScopeMatrixController) DeleteAssignment(c *gin.Context) {
	workspaceID, err := extractWorkspaceID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	rs, err := ctrl.rsService.GetByIDAndTenant(rsID, workspaceID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}

	assignmentID, err := uuid.Parse(c.Param("assignment_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid assignment_id"})
		return
	}

	res := config.DB.
		Where("id = ? AND workspace_id = ?", assignmentID, workspaceID).
		Where("scope_type = 'resource_server' AND scope_id = ?", rs.ID).
		Delete(&models.RoleBinding{})
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "assignment not found"})
		return
	}

	auditAdminMutation(c, workspaceID.String(), "access_assignment_deleted", "role_binding",
		assignmentID.String(), http.StatusOK, nil,
		map[string]interface{}{"application_id": rs.ID})
	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}

// ── GET /authsec/applications/:id/access-assignments/summary ─────────────────

type accessAssignmentSummary struct {
	TotalAssignments    int `json:"total_assignments"`
	UserAssignments     int `json:"user_assignments"`
	SAAssignments       int `json:"service_account_assignments"`
	WorkloadAssignments int `json:"workload_assignments"`
	PendingRequests     int `json:"pending_requests"`
	ActiveConnections   int `json:"active_connections"`
}

// GetAccessSummary returns lightweight counts for the Overview tab.
// GET /authsec/applications/:id/access-assignments/summary
func (ctrl *ScopeMatrixController) GetAccessSummary(c *gin.Context) {
	workspaceID, err := extractWorkspaceID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	rs, err := ctrl.rsService.GetByIDAndTenant(rsID, workspaceID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}

	ctx := c.Request.Context()

	// role_bindings has no subject_type column — the principal is whichever of
	// user_id / service_account_id / group_id is non-null (check_principal CHECK).
	var userCount, saCount int64
	config.DB.WithContext(ctx).Model(&models.RoleBinding{}).
		Where("workspace_id = ? AND scope_type = 'resource_server' AND scope_id = ? AND user_id IS NOT NULL", workspaceID, rs.ID).
		Count(&userCount)
	config.DB.WithContext(ctx).Model(&models.RoleBinding{}).
		Where("workspace_id = ? AND scope_type = 'resource_server' AND scope_id = ? AND service_account_id IS NOT NULL", workspaceID, rs.ID).
		Count(&saCount)

	var workloadCount int64
	config.DB.WithContext(ctx).Model(&models.ApplicationSpiffeIdentity{}).
		Where("application_id = ? AND workspace_id = ? AND status NOT IN ('revoked')", rs.ID, workspaceID).
		Count(&workloadCount)

	var pendingCount int64
	config.DB.WithContext(ctx).Table("access_requests").
		Where("resource_server_id = ? AND workspace_id = ? AND status = 'pending'", rs.ID, workspaceID).
		Count(&pendingCount)

	var activeConns int64
	config.DB.WithContext(ctx).Table("resource_server_client_registrations").
		Where("resource_server_id = ? AND workspace_id = ? AND status = 'approved'", rs.ID, workspaceID).
		Count(&activeConns)

	c.JSON(http.StatusOK, accessAssignmentSummary{
		TotalAssignments:    int(userCount + saCount),
		UserAssignments:     int(userCount),
		SAAssignments:       int(saCount),
		WorkloadAssignments: int(workloadCount),
		PendingRequests:     int(pendingCount),
		ActiveConnections:   int(activeConns),
	})
}
