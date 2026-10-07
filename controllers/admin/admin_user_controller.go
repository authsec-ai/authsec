package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/controllers/shared"
	"github.com/authsec-ai/authsec/database"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/monitoring"
	"github.com/authsec-ai/authsec/services"
	"github.com/authsec-ai/authsec/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type AdminUserController struct {
	workspaceRepo *database.WorkspaceRepository
	userRepo      *database.UserRepository
	adminUserRepo *database.AdminUserRepository
}

// TenantUserListRequest represents payload for listing tenant users
type TenantUserListRequest struct {
	WorkspaceID string `json:"workspace_id"` // ignored: the token's workspace is used
	Page        int    `json:"page"`
	Limit       int    `json:"limit"`
	ClientID    string `json:"client_id"`
	ProjectID   string `json:"project_id"`
	Provider    string `json:"provider"`
}

// AdminUserListRequest represents the request payload for listing admin users
type AdminUserListRequest struct {
	Status      string `json:"status"`       // Filter by status: "pending" or "active"
	Provider    string `json:"provider"`     // Filter by provider
	WorkspaceID string `json:"workspace_id"` // Optional (usually from JWT)
	ClientID    string `json:"client_id"`    // Optional
	ProjectID   string `json:"project_id"`   // Optional
	Page        int    `json:"page"`         // Pagination
	Limit       int    `json:"limit"`        // Pagination
}

type toggleAdminUserActiveRequest struct {
	UserID string               `json:"user_id" binding:"required"`
	Active *shared.FlexibleBool `json:"active" binding:"required"`
}

// NewAdminUserController creates a new admin user controller
func NewAdminUserController() (*AdminUserController, error) {
	db := config.GetDatabase()
	if db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	return &AdminUserController{
		workspaceRepo: database.NewWorkspaceRepository(db),
		userRepo:      database.NewUserRepository(db),
		adminUserRepo: database.NewAdminUserRepository(db),
	}, nil
}

// ListTenants retrieves all tenants
func (auc *AdminUserController) ListTenants(c *gin.Context) {
	// A workspace admin sees their own workspace only. This listed every
	// workspace on the platform, with owner emails and password hashes (AS-009).
	tc, err := tenancy.From(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace context required"})
		return
	}
	tenant, err := auc.workspaceRepo.GetWorkspaceByWorkspaceID(tc.WorkspaceID.String())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve tenants"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"tenants": []interface{}{tenant}})
}

// ListAdminUsers godoc
// @Summary List admin users
// @Description Retrieves all users assigned to the admin role with optional provider and status filtering
// @Tags Admin-Users
// @Security BearerAuth
// @Produce json
// @Param provider query string false "Filter by authentication provider (e.g., local, google, azure, okta)"
// @Param input body AdminUserListRequest false "Filter options including status"
// @Success 200 {object} map[string]interface{}
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/admin/users/list [get]
// @Router /authsec/uflow/admin/users/list [post]
func (auc *AdminUserController) ListAdminUsers(c *gin.Context) {
	requestID := c.GetString("request_id")
	logPrefix := "ListAdminUsers"
	if requestID != "" {
		logPrefix = fmt.Sprintf("%s request_id=%s", logPrefix, requestID)
	}
	log.Printf("%s: handling %s %s from %s", logPrefix, c.Request.Method, c.FullPath(), c.ClientIP())

	if auc.adminUserRepo == nil {
		log.Printf("%s: admin user repository not initialized", logPrefix)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Admin user repository not initialized"})
		return
	}

	if _, err := tenancy.From(c); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace context required"})
		return
	}
	ctx := c.Request.Context()

	if err := auc.adminUserRepo.EnsureTenantAdminRoleAssignment(ctx); err != nil {
		log.Printf("%s: failed ensure tenant admin roles: %v", logPrefix, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reconcile admin roles"})
		return
	}

	// Get optional provider filter from query parameter
	provider := c.Query("provider")
	if provider != "" {
		log.Printf("%s: filtering by provider: %s", logPrefix, provider)
	}

	// Get optional status filter from request body (for POST) or query param (for GET)
	var statusFilter string
	if c.Request.Method == "POST" {
		var req AdminUserListRequest
		if err := c.ShouldBindJSON(&req); err == nil {
			statusFilter = req.Status
		}
	} else {
		statusFilter = c.Query("status")
	}
	if statusFilter != "" {
		log.Printf("%s: filtering by status: %s", logPrefix, statusFilter)
	}

	users, err := auc.adminUserRepo.ListAdminUsersInWorkspace(ctx, provider)
	if err != nil {
		log.Printf("%s: failed to retrieve admin users: %v", logPrefix, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve admin users"})
		return
	}

	if users == nil {
		users = []models.AdminUser{}
	}
	log.Printf("%s: returning %d admin users", logPrefix, len(users))

	responseUsers := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		payload, err := buildAdminUserResponse(user)
		if err != nil {
			log.Printf("%s: failed to marshal admin user %s: %v", logPrefix, user.ID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare admin user response"})
			return
		}

		// Fetch and add roles for this user
		roles, err := auc.adminUserRepo.GetUserRoles(ctx, user.ID)
		if err != nil {
			log.Printf("%s: failed to get roles for user %s: %v", logPrefix, user.ID, err)
			payload["roles"] = []interface{}{} // Return empty array on error
		} else {
			payload["roles"] = roles
		}

		// Check for pending registration
		hasPending, err := auc.adminUserRepo.HasPendingRegistrationInWorkspace(ctx, user.Email)
		if err != nil {
			log.Printf("%s: failed to check pending registration for user %s: %v", logPrefix, user.ID, err)
			payload["pending_registration"] = false
		} else {
			payload["pending_registration"] = hasPending
		}

		// Apply status filter if specified
		if statusFilter != "" {
			if statusFilter == "pending" && !hasPending {
				continue // Skip non-pending users
			}
			if statusFilter == "active" && hasPending {
				continue // Skip pending users
			}
		}

		responseUsers = append(responseUsers, payload)
	}

	log.Printf("%s: returning %d users after filtering", logPrefix, len(responseUsers))
	c.JSON(http.StatusOK, gin.H{"users": responseUsers})
}

// ToggleAdminUserActive godoc
// @Summary Activate or deactivate an admin user
// @Description Updates the active flag for an admin user in the master database
// @Tags Admin-Users
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param input body toggleAdminUserActiveRequest true "Admin user toggle payload"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/admin/users/active [post]
func (auc *AdminUserController) ToggleAdminUserActive(c *gin.Context) {
	requestID := c.GetString("request_id")
	logger := monitoring.GetLogger().WithField("request_id", requestID).WithField("operation", "toggle_admin_user_active")
	logger.Info("Processing admin user activation/deactivation request")

	// Validate repository initialization
	if auc.adminUserRepo == nil {
		logger.Error("Admin user repository not initialized")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Admin user repository not initialized"})
		return
	}

	// Parse and validate request body
	var req toggleAdminUserActiveRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.WithError(err).Warn("Failed to bind JSON request body")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload: " + err.Error()})
		return
	}

	active := false
	if req.Active == nil {
		logger.Warn("Active flag missing in request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "active flag is required"})
		return
	} else {
		active = req.Active.Bool()
	}

	// Validate and parse user ID
	userUUID, err := uuid.Parse(strings.TrimSpace(req.UserID))
	if err != nil {
		logger.WithError(err).WithField("user_id", req.UserID).Warn("Invalid user ID format")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user_id format"})
		return
	}

	// The workspace comes from the verified token, never the body.
	tc, err := tenancy.From(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace context required"})
		return
	}
	ctx := c.Request.Context()

	logger = logger.WithField("user_id", userUUID).WithField("workspace_id", tc.WorkspaceID).WithField("active", active)

	// Another workspace's user does not exist here: 404.
	adminUser, ok := auc.loadAdminUser(c, userUUID)
	if !ok {
		return
	}

	// Check if trying to deactivate primary admin
	if adminUser.IsPrimaryAdmin && !active {
		logger.Warn("Attempted to deactivate primary admin")
		if config.AuditLogger != nil {
			config.AuditLogger.LogAuthentication(requestID, auditWorkspaceID(adminUser.WorkspaceID), "admin", adminUser.ID.String(), "deactivate_primary_admin", c.ClientIP(), c.GetHeader("User-Agent"), false, "Cannot deactivate primary admin")
		}
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot deactivate the primary admin"})
		return
	}

	// Check if trying to deactivate the last active admin
	if !active {
		activeCount, err := auc.countOtherActiveAdmins(ctx, userUUID)
		if err != nil {
			logger.WithError(err).Error("Failed to verify admin count")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify admin count"})
			return
		}

		if activeCount == 0 {
			logger.Warn("Attempted to deactivate last active admin")
			if config.AuditLogger != nil {
				config.AuditLogger.LogAuthentication(requestID, auditWorkspaceID(adminUser.WorkspaceID), "admin", adminUser.ID.String(), "deactivate_last_admin", c.ClientIP(), c.GetHeader("User-Agent"), false, "Cannot deactivate last admin")
			}
			c.JSON(http.StatusForbidden, gin.H{"error": "Cannot deactivate the last active admin in the tenant"})
			return
		}
	}

	// Update admin user active status
	if err := auc.adminUserRepo.SetAdminUserActiveInWorkspace(ctx, userUUID, active); err != nil {
		if shared.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Admin user not found"})
			return
		}
		logger.WithError(err).Error("Failed to update admin user active flag")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update admin user"})
		return
	}

	// Send email notification if account is being deactivated
	if !active {
		if err := utils.SendAccountDeactivationEmail(adminUser.Email); err != nil {
			logger.WithError(err).Warn("Failed to send deactivation email, but proceeding with deactivation")
			// Don't fail the deactivation if email fails - it's a notification only
		} else {
			logger.Info("Deactivation email sent successfully")
		}
	}

	// Audit log the successful operation
	action := "admin_user_deactivated"
	message := "Admin user deactivated successfully"
	if active {
		action = "admin_user_activated"
		message = "Admin user activated successfully"
	}

	if config.AuditLogger != nil {
		config.AuditLogger.LogAuthentication(requestID, auditWorkspaceID(adminUser.WorkspaceID), "admin", adminUser.ID.String(), action, c.ClientIP(), c.GetHeader("User-Agent"), true, message)
	}

	// Audit log: Admin user activated/deactivated (stdout)
	middlewares.Audit(c, "admin_user", adminUser.ID.String(), action, &middlewares.AuditChanges{
		Before: map[string]interface{}{
			"active": !active,
			"email":  adminUser.Email,
		},
		After: map[string]interface{}{
			"active": active,
			"email":  adminUser.Email,
		},
	})

	logger.Info("Successfully toggled admin user active status")
	c.JSON(http.StatusOK, gin.H{
		"message": message,
		"user_id": userUUID.String(),
		"active":  active,
	})
}

// DeleteAdminUser godoc
// @Summary Soft delete an admin user
// @Description Marks an admin user as inactive in the master database. Cannot delete the primary admin or the last remaining admin.
// @Tags Admin-Users
// @Security BearerAuth
// @Produce json
// @Param user_id path string true "Admin user ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/admin/users/{user_id} [delete]
func (auc *AdminUserController) DeleteAdminUser(c *gin.Context) {
	requestID := c.GetString("request_id")
	logger := monitoring.GetLogger().WithField("request_id", requestID).WithField("operation", "delete_admin_user")
	logger.Info("Processing admin user delete request")

	// Validate user ID parameter
	userID := c.Param("user_id")
	if userID == "" {
		logger.Warn("Missing user_id parameter")
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		logger.WithError(err).WithField("user_id", userID).Warn("Invalid user ID format")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user_id format"})
		return
	}

	logger = logger.WithField("user_id", userUUID)

	// The workspace comes from the tenant context set by AuthMiddleware; the
	// handler used to read user_info, which nothing sets, and always
	// answered 403 (AS-048).
	tc, err := tenancy.From(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace context required"})
		return
	}
	ctx := c.Request.Context()
	logger = logger.WithField("workspace_id", tc.WorkspaceID)

	// Another workspace's user does not exist here: 404.
	adminUser, ok := auc.loadAdminUser(c, userUUID)
	if !ok {
		return
	}

	// Check if this is the primary admin
	if adminUser.IsPrimaryAdmin {
		logger.Warn("Attempted to delete primary admin")
		if config.AuditLogger != nil {
			config.AuditLogger.LogAuthentication(requestID, auditWorkspaceID(adminUser.WorkspaceID), "admin", adminUser.ID.String(), "delete_primary_admin", c.ClientIP(), c.GetHeader("User-Agent"), false, "Cannot delete primary admin")
		}
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot delete the primary admin"})
		return
	}

	// Check if this is the last active admin for the tenant
	activeCount, err := auc.countOtherActiveAdmins(ctx, userUUID)
	if err != nil {
		logger.WithError(err).Error("Failed to verify admin count")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify admin count"})
		return
	}

	if activeCount == 0 {
		logger.Warn("Attempted to delete last active admin in tenant")
		if config.AuditLogger != nil {
			config.AuditLogger.LogAuthentication(requestID, auditWorkspaceID(adminUser.WorkspaceID), "admin", adminUser.ID.String(), "delete_last_admin", c.ClientIP(), c.GetHeader("User-Agent"), false, "Cannot delete last admin")
		}
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot delete the last active admin in the tenant"})
		return
	}

	// Perform soft delete
	if err := auc.adminUserRepo.SetAdminUserActiveInWorkspace(ctx, userUUID, false); err != nil {
		if shared.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Admin user not found"})
			return
		}
		logger.WithError(err).Error("Failed to delete admin user")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete admin user"})
		return
	}

	// Audit log the successful deletion
	if config.AuditLogger != nil {
		config.AuditLogger.LogAuthentication(requestID, auditWorkspaceID(adminUser.WorkspaceID), "admin", adminUser.ID.String(), "admin_user_deleted", c.ClientIP(), c.GetHeader("User-Agent"), true, "Admin user soft deleted successfully")
	}

	// Audit log: Admin user deleted (stdout)
	middlewares.Audit(c, "admin_user", adminUser.ID.String(), "delete", &middlewares.AuditChanges{
		Before: map[string]interface{}{
			"email":            adminUser.Email,
			"active":           adminUser.Active,
			"is_primary_admin": adminUser.IsPrimaryAdmin,
		},
		After: map[string]interface{}{
			"deleted": true,
		},
	})

	logger.Info("Successfully soft deleted admin user")
	c.JSON(http.StatusOK, gin.H{"message": "Admin user soft deleted"})
}

// DeleteAdminUserAllRequest is the optional request body for hard delete. The
// user comes from the :user_id path parameter when present; workspace_id is
// ignored (the token's workspace is used).
type DeleteAdminUserAllRequest struct {
	WorkspaceID string `json:"workspace_id"`
	UserID      string `json:"user_id"`
}

// DeleteAdminUserAll godoc
// @Summary Hard delete admin user and all related data
// @Description Permanently deletes an admin user and all associated data from the master database. This includes role_bindings, totp_secrets, backup_codes, webauthn_credentials, sessions, etc. Cannot delete the primary admin or the last remaining admin.
// @Tags Admin-Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param input body DeleteAdminUserAllRequest true "Admin user delete payload"
// @Success 200 {object} map[string]interface{} "Admin user and all related data deleted successfully"
// @Failure 400 {object} map[string]string "Invalid request"
// @Failure 403 {object} map[string]string "Cannot delete primary admin or last admin"
// @Failure 404 {object} map[string]string "Admin user not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /authsec/uflow/admin/users/delete_all [post]
func (auc *AdminUserController) DeleteAdminUserAll(c *gin.Context) {
	requestID := c.GetString("request_id")
	logger := monitoring.GetLogger().WithField("request_id", requestID).WithField("operation", "delete_admin_user_all")
	logger.Info("Processing admin user hard delete request")

	var req DeleteAdminUserAllRequest
	if c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			logger.WithError(err).Warn("Failed to bind JSON request body")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload: " + err.Error()})
			return
		}
	}
	rawUserID := strings.TrimSpace(c.Param("user_id"))
	if rawUserID == "" {
		rawUserID = strings.TrimSpace(req.UserID)
	}

	// Validate and parse user ID
	userUUID, err := uuid.Parse(rawUserID)
	if err != nil {
		logger.WithError(err).WithField("user_id", rawUserID).Warn("Invalid user ID format")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user_id format"})
		return
	}

	// The workspace comes from the tenant context (AS-048).
	tc, err := tenancy.From(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace context required"})
		return
	}
	workspaceUUID := tc.WorkspaceID
	ctx := c.Request.Context()

	logger = logger.WithField("user_id", userUUID).WithField("workspace_id", workspaceUUID)

	// Validate repository initialization
	if auc.adminUserRepo == nil {
		logger.Error("Admin user repository not initialized")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Admin user repository not initialized"})
		return
	}

	// Another workspace's user does not exist here: 404.
	adminUser, ok := auc.loadAdminUser(c, userUUID)
	if !ok {
		return
	}

	// Check if this is the primary admin - CANNOT be deleted
	if adminUser.IsPrimaryAdmin {
		logger.Warn("Attempted to delete primary admin")
		if config.AuditLogger != nil {
			config.AuditLogger.LogAuthentication(requestID, auditWorkspaceID(adminUser.WorkspaceID), "admin", adminUser.ID.String(), "delete_all_primary_admin", c.ClientIP(), c.GetHeader("User-Agent"), false, "Cannot delete primary admin")
		}
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot delete the primary admin who created this tenant"})
		return
	}

	// Check if this is the last active admin for the tenant
	activeCount, err := auc.countOtherActiveAdmins(ctx, userUUID)
	if err != nil {
		logger.WithError(err).Error("Failed to verify admin count")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify admin count"})
		return
	}

	if activeCount == 0 {
		logger.Warn("Attempted to delete last active admin in tenant")
		if config.AuditLogger != nil {
			config.AuditLogger.LogAuthentication(requestID, auditWorkspaceID(adminUser.WorkspaceID), "admin", adminUser.ID.String(), "delete_all_last_admin", c.ClientIP(), c.GetHeader("User-Agent"), false, "Cannot delete last admin")
		}
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot delete the last active admin in the tenant"})
		return
	}

	logger.Info("Hard deleting admin user and all related data")

	// Get database connection
	db := config.GetDatabase()
	if db == nil {
		logger.Error("Database not initialized")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database not initialized"})
		return
	}

	// Delete all related data in one row-level security transaction for the
	// caller's workspace. Every statement goes through the scoped layer
	// (workspace_id = $1); every table below has user_id and workspace_id.
	deletedCounts := make(map[string]int64)
	record := func(table string, res sql.Result, err error) error {
		if err != nil {
			return fmt.Errorf("failed to delete from %s: %w", table, err)
		}
		if rows, err := res.RowsAffected(); err == nil {
			deletedCounts[table] = rows
		}
		return nil
	}
	err = tenancy.WithTx(ctx, db.DB, workspaceUUID, func(tx *sql.Tx) error {
		// 1. role_bindings
		res, err := tenancy.ExecContext(ctx, tx, `DELETE FROM role_bindings WHERE workspace_id = $1 AND user_id = $2`, userUUID)
		if err := record("role_bindings", res, err); err != nil {
			return err
		}
		// 2. totp_secrets
		res, err = tenancy.ExecContext(ctx, tx, `DELETE FROM totp_secrets WHERE workspace_id = $1 AND user_id = $2`, userUUID)
		if err := record("totp_secrets", res, err); err != nil {
			return err
		}
		// 3. totp_backup_codes
		res, err = tenancy.ExecContext(ctx, tx, `DELETE FROM totp_backup_codes WHERE workspace_id = $1 AND user_id = $2`, userUUID)
		if err := record("totp_backup_codes", res, err); err != nil {
			return err
		}
		// 4. user_groups
		res, err = tenancy.ExecContext(ctx, tx, `DELETE FROM user_groups WHERE workspace_id = $1 AND user_id = $2`, userUUID)
		if err := record("user_groups", res, err); err != nil {
			return err
		}
		// 5. Finally, the user
		res, err = tenancy.ExecContext(ctx, tx, `DELETE FROM users WHERE workspace_id = $1 AND id = $2`, userUUID)
		return record("users", res, err)
	})
	if err != nil {
		logger.WithError(err).Error("Failed to hard delete admin user")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	logger.WithField("deleted_counts", deletedCounts).Info("Successfully hard deleted admin user")

	// Phase H-5: even though FK cascades cleared role_bindings + the user row, any
	// access tokens issued before the delete are still cryptographically valid
	// until Hydra introspection rejects them. Explicit consent-session revoke
	// closes the seconds-wide window between "user deleted from DB" and
	// "introspection sees the user is gone". Fire-and-forget; the response
	// returns to the operator immediately.
	oauthAS := services.NewOAuthASService(config.DB)
	go oauthAS.RevokeUserTokensForWorkspace(adminUser.ID, workspaceUUID)

	// Audit log the successful deletion
	if config.AuditLogger != nil {
		config.AuditLogger.LogAuthentication(requestID, auditWorkspaceID(adminUser.WorkspaceID), "admin", adminUser.ID.String(), "admin_user_hard_deleted", c.ClientIP(), c.GetHeader("User-Agent"), true, "Admin user and all related data deleted")
	}

	// Audit log: Admin user hard deleted (stdout)
	middlewares.Audit(c, "admin_user", adminUser.ID.String(), "delete_all", &middlewares.AuditChanges{
		Before: map[string]interface{}{
			"email":            adminUser.Email,
			"username":         adminUser.Username,
			"is_primary_admin": adminUser.IsPrimaryAdmin,
		},
		After: map[string]interface{}{
			"deleted":        true,
			"deleted_counts": deletedCounts,
		},
	})

	c.JSON(http.StatusOK, gin.H{
		"message":        "Admin user and all related data deleted successfully",
		"user_id":        userUUID.String(),
		"deleted_counts": deletedCounts,
	})
}

// loadAdminUser loads an admin user of the request's workspace. It answers
// 404 itself for a user that does not exist there, including another
// workspace's user, and 500 on a database error.
func (auc *AdminUserController) loadAdminUser(c *gin.Context, userID uuid.UUID) (*models.AdminUser, bool) {
	adminUser, err := auc.adminUserRepo.GetAdminUserInWorkspace(c.Request.Context(), userID)
	if err != nil {
		if shared.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Admin user not found"})
			return nil, false
		}
		monitoring.GetLogger().WithError(err).Error("Failed to fetch admin user")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load admin user"})
		return nil, false
	}
	return adminUser, true
}

// countOtherActiveAdmins counts the workspace's active admins other than
// the given user.
func (auc *AdminUserController) countOtherActiveAdmins(ctx context.Context, except uuid.UUID) (int, error) {
	admins, err := auc.adminUserRepo.ListAdminUsersInWorkspace(ctx, "")
	if err != nil {
		return 0, err
	}
	n := 0
	for _, admin := range admins {
		if admin.Active && admin.ID != except {
			n++
		}
	}
	return n, nil
}

func buildAdminUserResponse(user models.AdminUser) (map[string]interface{}, error) {
	raw, err := json.Marshal(user)
	if err != nil {
		return nil, fmt.Errorf("marshal admin user: %w", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal admin user: %w", err)
	}

	if isAdminUserInvite(user) {
		// Only invited admins (those with temporary passwords) can be "pending"
		pending := isPendingAdminInvite(user)
		payload["pending"] = pending
		payload["accepted_invite"] = !pending
		payload["invite_accepted"] = !pending
	} else {
		// Non-invited users should never show as pending
		payload["pending"] = false
		payload["accepted_invite"] = true
		payload["invite_accepted"] = true
	}

	return payload, nil
}

func isAdminUserInvite(user models.AdminUser) bool {
	return user.TemporaryPassword
}

func isPendingAdminInvite(user models.AdminUser) bool {
	return user.TemporaryPassword && user.LastLogin == nil
}

// ListEndUsersByTenant godoc
// @Summary List tenant end users
// @Description Retrieves users for a tenant using request payload filtering with optional provider filter
// @Tags Admin
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param input body TenantUserListRequest true "Tenant listing payload with optional provider filter"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/admin/enduser/list [post]
func (auc *AdminUserController) ListEndUsersByTenant(c *gin.Context) {
	var req TenantUserListRequest
	if c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	_, db, ok := shared.TenantScope(c)
	if !ok {
		return
	}

	// Validate client_id if provided
	var clientUUID *uuid.UUID
	if strings.TrimSpace(req.ClientID) != "" {
		parsed, err := uuid.Parse(req.ClientID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid client_id format"})
			return
		}
		clientUUID = &parsed
	}

	users, err := listWorkspaceEndUsers(db, clientUUID, req.Provider)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list users"})
		return
	}

	page := req.Page
	if page < 1 {
		page = 1
	}
	limit := req.Limit
	if limit <= 0 {
		limit = len(users)
	}
	start := (page - 1) * limit
	if start > len(users) {
		start = len(users)
	}
	end := start + limit
	if end > len(users) {
		end = len(users)
	}

	responseUsers := users[start:end]
	c.JSON(http.StatusOK, gin.H{
		"users": responseUsers,
		"total": len(users),
		"page":  page,
		"limit": limit,
	})
}

// CreateTenant creates a new tenant
func (auc *AdminUserController) CreateTenant(c *gin.Context) {
	var input struct {
		Email           string `json:"email" binding:"required,email"`
		Username        string `json:"username" binding:"required"`
		Password        string `json:"password" binding:"required,min=8"`
		Name            string `json:"name" binding:"required"`
		WorkspaceDomain string `json:"workspace_domain"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if tenant already exists
	exists, err := auc.workspaceRepo.TenantExists(input.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check tenant existence"})
		return
	}
	if exists {
		c.JSON(http.StatusConflict, gin.H{"error": "Tenant with this email already exists"})
		return
	}

	// Hash password
	hashedPassword, err := utils.HashPassword(input.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Create tenant
	workspaceID := uuid.New()
	tenant := &models.Tenant{
		ID:              workspaceID,
		WorkspaceID:     workspaceID,
		Email:           input.Email,
		Username:        &input.Username,
		PasswordHash:    hashedPassword,
		Name:            input.Name,
		WorkspaceDomain: input.WorkspaceDomain,
		Source:          "admin",
		Status:          "active",
	}

	if err := auc.workspaceRepo.CreateTenant(tenant); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create tenant"})
		return
	}

	// Audit log: Tenant created
	middlewares.Audit(c, "tenant", workspaceID.String(), "create", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"email":            input.Email,
			"username":         input.Username,
			"name":             input.Name,
			"workspace_domain": input.WorkspaceDomain,
			"source":           "admin",
			"status":           "active",
		},
	})

	c.JSON(http.StatusCreated, gin.H{"tenant": tenant})
}

// UpdateTenant updates an existing tenant
func (auc *AdminUserController) UpdateTenant(c *gin.Context) {
	// The workspace comes from the verified token, not the URL.
	tc, err := tenancy.From(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace context required"})
		return
	}
	workspaceID := tc.WorkspaceID

	var input struct {
		Email           string `json:"email,omitempty"`
		Username        string `json:"username,omitempty"`
		Name            string `json:"name,omitempty"`
		WorkspaceDomain string `json:"workspace_domain,omitempty"`
		Status          string `json:"status,omitempty"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get existing tenant
	existingTenant, err := auc.workspaceRepo.GetWorkspaceByWorkspaceID(workspaceID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
		return
	}

	// Update fields if provided
	if input.Email != "" {
		existingTenant.Email = input.Email
	}
	if input.Username != "" {
		existingTenant.Username = &input.Username
	}
	if input.Name != "" {
		existingTenant.Name = input.Name
	}
	if input.WorkspaceDomain != "" {
		existingTenant.WorkspaceDomain = input.WorkspaceDomain
	}
	if input.Status != "" {
		existingTenant.Status = input.Status
	}

	// Note: UpdateTenant method doesn't exist in repository, so this is a placeholder
	// In a real implementation, you'd need to add an UpdateTenant method to the repository
	c.JSON(http.StatusOK, gin.H{"message": "Tenant update not implemented yet", "tenant": existingTenant})
}

// GetTenantUsers retrieves all users for a specific tenant
func (auc *AdminUserController) GetTenantUsers(c *gin.Context) {
	workspaceIDStr := c.Param("workspace_id")
	c.JSON(http.StatusServiceUnavailable, gin.H{
		"error":        "Per-tenant user listing is managed by mt-plugin",
		"workspace_id": workspaceIDStr,
		"hint":         "Configure MT_PLUGIN_GRPC_ADDR to enable multi-tenant operations",
	})
}

// listWorkspaceEndUsers lists the users of the workspace db is scoped to,
// with their role bindings. It replaces a lookup that opened a per-tenant
// database which no longer exists, so the endpoint always answered 400.
func listWorkspaceEndUsers(db *gorm.DB, clientID *uuid.UUID, provider string) ([]map[string]interface{}, error) {
	type userRow struct {
		ID        uuid.UUID
		Email     string
		Name      *string
		ClientID  *uuid.UUID
		Provider  *string
		Active    bool
		CreatedAt time.Time
		UpdatedAt *time.Time
	}
	q := db.Table("users").
		Select("id, email, name, client_id, provider, active, created_at, updated_at").
		Where("deleted_at IS NULL")
	if clientID != nil {
		q = q.Where("client_id = ?", *clientID)
	}
	if provider != "" {
		q = q.Where("provider = ?", provider)
	}
	var rows []userRow
	if err := q.Order("created_at DESC").Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("failed to query users: %w", err)
	}

	type bindingRow struct {
		UserID   uuid.UUID
		RoleID   uuid.UUID
		RoleName *string
	}
	var bindings []bindingRow
	if err := db.Table("role_bindings").
		Select("user_id, role_id, role_name").
		Where("user_id IS NOT NULL").
		Scan(&bindings).Error; err != nil {
		return nil, fmt.Errorf("failed to query role bindings: %w", err)
	}
	type roleRow struct {
		ID   uuid.UUID
		Name string
	}
	var roles []roleRow
	if err := db.Table("roles").Select("id, name").Scan(&roles).Error; err != nil {
		return nil, fmt.Errorf("failed to query roles: %w", err)
	}
	roleNames := make(map[uuid.UUID]string, len(roles))
	for _, r := range roles {
		roleNames[r.ID] = r.Name
	}
	userRoles := make(map[uuid.UUID][]database.UserRole)
	for _, b := range bindings {
		name := roleNames[b.RoleID]
		if b.RoleName != nil && *b.RoleName != "" {
			name = *b.RoleName
		}
		userRoles[b.UserID] = append(userRoles[b.UserID], database.UserRole{ID: b.RoleID, Name: name})
	}

	users := make([]map[string]interface{}, 0, len(rows))
	for _, r := range rows {
		name := ""
		if r.Name != nil {
			name = *r.Name
		}
		parts := strings.Fields(name)
		firstName, lastName := "", ""
		if len(parts) > 0 {
			firstName = parts[0]
		}
		if len(parts) > 1 {
			lastName = strings.Join(parts[1:], " ")
		}
		status := "inactive"
		if r.Active {
			status = "active"
		}
		clientIDStr, providerStr := "", ""
		if r.ClientID != nil {
			clientIDStr = r.ClientID.String()
		}
		if r.Provider != nil {
			providerStr = *r.Provider
		}
		user := map[string]interface{}{
			"id":         r.ID.String(),
			"email":      r.Email,
			"first_name": firstName,
			"last_name":  lastName,
			"client_id":  clientIDStr,
			"provider":   providerStr,
			"status":     status,
			"created_at": r.CreatedAt,
		}
		if r.UpdatedAt != nil {
			user["updated_at"] = *r.UpdatedAt
		}
		if ur, ok := userRoles[r.ID]; ok {
			user["roles"] = ur
		} else {
			user["roles"] = []database.UserRole{}
		}
		users = append(users, user)
	}
	return users, nil
}

// ToggleEndUserActive godoc
// @Summary Activate or deactivate an end user
// @Description Updates the active flag for an end user in the tenant database
// @Tags Admin
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param input body toggleAdminUserActiveRequest true "End user toggle payload"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/admin/enduser/active [post]
func (auc *AdminUserController) ToggleEndUserActive(c *gin.Context) {
	requestID := c.GetString("request_id")
	logger := monitoring.GetLogger().WithField("request_id", requestID).WithField("operation", "toggle_enduser_active")
	logger.Info("Processing end user activation/deactivation request")

	// Parse and validate request body
	var req toggleAdminUserActiveRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.WithError(err).Warn("Failed to bind JSON request body")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload: " + err.Error()})
		return
	}

	active := false
	if req.Active == nil {
		logger.Warn("Active flag missing in request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "active flag is required"})
		return
	} else {
		active = req.Active.Bool()
	}

	// Validate and parse user ID
	userUUID, err := uuid.Parse(strings.TrimSpace(req.UserID))
	if err != nil {
		logger.WithError(err).WithField("user_id", req.UserID).Warn("Invalid user ID format")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user_id format"})
		return
	}

	// The workspace comes from the verified token, never the body.
	tc, tenantDB, ok := shared.TenantScope(c)
	if !ok {
		return
	}

	logger = logger.WithField("user_id", userUUID).WithField("workspace_id", tc.WorkspaceID).WithField("active", active)

	// Another workspace's user does not exist here: 404.
	var user models.ExtendedUser
	if err := tenantDB.Where("id = ? AND deleted_at IS NULL", userUUID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Warn("End user not found in tenant database")
			c.JSON(http.StatusNotFound, gin.H{"error": "End user not found"})
			return
		}
		logger.WithError(err).Error("Failed to fetch end user")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load end user"})
		return
	}

	// Update the active status
	if err := tenantDB.Model(&models.ExtendedUser{}).Where("id = ?", user.ID).Update("active", active).Error; err != nil {
		logger.WithError(err).Error("Failed to update end user active flag")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update end user"})
		return
	}

	// Send email notification if account is being deactivated
	if !active {
		if err := utils.SendAccountDeactivationEmail(user.Email); err != nil {
			logger.WithError(err).Warn("Failed to send deactivation email, but proceeding with deactivation")
			// Don't fail the deactivation if email fails - it's a notification only
		} else {
			logger.Info("Deactivation email sent successfully to end user")
		}
	}

	// Audit log the successful operation
	action := "enduser_deactivated"
	message := "End user deactivated successfully"
	if active {
		action = "enduser_activated"
		message = "End user activated successfully"
	}

	if config.AuditLogger != nil {
		config.AuditLogger.LogAuthentication(requestID, user.WorkspaceID.String(), "enduser", user.ID.String(), action, c.ClientIP(), c.GetHeader("User-Agent"), true, message)
	}

	// Audit log: End user activated/deactivated (stdout)
	middlewares.Audit(c, "end_user", user.ID.String(), action, &middlewares.AuditChanges{
		Before: map[string]interface{}{
			"active": !active,
			"email":  user.Email,
		},
		After: map[string]interface{}{
			"active": active,
			"email":  user.Email,
		},
	})

	logger.Info("Successfully toggled end user active status")
	c.JSON(http.StatusOK, gin.H{
		"message": message,
		"user_id": userUUID.String(),
		"active":  active,
	})
}

// DeleteTenant permanently deletes a tenant and ALL associated data including:
// - All users (admin and end users) in the tenant
// - All roles, permissions, and role bindings
// - All MFA data (TOTP, backup codes, WebAuthn credentials)
// - All sessions and refresh tokens
// - All OAuth clients and API scopes
// - All projects
// - The tenant database itself
// - The tenant record
//
// This is an EXTREMELY DESTRUCTIVE operation and cannot be undone.
// Only super admins or the primary admin of the tenant can perform this operation.
//
// @Summary Delete tenant and all data
// @Description Permanently delete a tenant and ALL associated data. This is irreversible.
// @Tags Admin - Tenant Management
// @Accept json
// @Produce json
// @Param workspace_id path string true "Tenant ID (UUID)"
// @Security BearerAuth
// @Success 200 {object} map[string]interface{} "Tenant deleted successfully"
// @Failure 400 {object} map[string]string "Invalid tenant ID"
// @Failure 403 {object} map[string]string "Permission denied"
// @Failure 404 {object} map[string]string "Tenant not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router /authsec/uflow/admin/tenants/{workspace_id} [delete]
func (auc *AdminUserController) DeleteTenant(c *gin.Context) {
	requestID := c.GetString("request_id")
	logger := monitoring.GetLogger().WithField("request_id", requestID).WithField("operation", "delete_tenant")

	// Get workspace_id from path parameter
	workspaceIDParam := c.Param("workspace_id")
	if workspaceIDParam == "" {
		logger.Warn("Missing workspace_id parameter")
		c.JSON(http.StatusBadRequest, gin.H{"error": "workspace_id is required"})
		return
	}

	workspaceUUID, err := uuid.Parse(workspaceIDParam)
	if err != nil {
		logger.WithError(err).Warn("Invalid workspace_id format")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid workspace_id format"})
		return
	}

	logger = logger.WithField("workspace_id", workspaceUUID.String())
	logger.Info("Processing delete_tenant request")

	// The caller acts in the workspace of their token (AS-048: this read
	// user_info, which nothing sets). Another workspace does not exist here.
	tc, err := tenancy.From(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace context required"})
		return
	}
	if tc.WorkspaceID != workspaceUUID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
		return
	}

	// Only the workspace's owner (its primary admin) may delete it. There is
	// no platform super admin on a workspace token (ADR-0001 §7).
	var ownerID *uuid.UUID
	if err := config.DB.Table("workspaces").Select("owner_user_id").Where("id = ?", tc.WorkspaceID).Scan(&ownerID).Error; err != nil {
		logger.WithError(err).Error("Failed to load workspace owner")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch tenant"})
		return
	}
	if ownerID == nil || *ownerID != tc.PrincipalID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Only the workspace owner can delete the workspace"})
		return
	}
	requesterID := tc.PrincipalID.String()
	requesterEmail := c.GetString("email")

	// Fetch the tenant to verify it exists
	tenant, err := auc.workspaceRepo.GetWorkspaceByWorkspaceID(workspaceUUID.String())
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			logger.Warn("Tenant not found")
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		logger.WithError(err).Error("Failed to fetch tenant")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch tenant"})
		return
	}

	// Store tenant info for audit log before deletion
	tenantEmail := tenant.Email
	workspaceDomain := tenant.WorkspaceDomain
	tenantDB := tenant.WorkspaceDB

	logger.WithFields(map[string]interface{}{
		"tenant_email":     tenantEmail,
		"workspace_domain": workspaceDomain,
		"workspace_db":     tenantDB,
	}).Info("Starting tenant deletion")

	// Step 1: Delete all data from the master database
	logger.Info("Step 1: Deleting tenant data from master database")
	deletedCounts, err := auc.workspaceRepo.DeleteTenant(c.Request.Context())
	if err != nil {
		logger.WithError(err).Error("Failed to delete tenant data from master database")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete tenant data: " + err.Error()})
		return
	}

	logger.WithField("deleted_counts", deletedCounts).Info("Successfully deleted tenant data from master database")

	// Step 2: Single-tenant deployment — no per-tenant database to drop.
	// Workspace data lives in master DB and was removed in Step 1.
	databaseDropped := true
	deletedCounts["tenant_database"] = 0

	// Audit log the deletion
	if config.AuditLogger != nil {
		config.AuditLogger.LogAuthentication(requestID, workspaceUUID.String(), "admin", requesterID, "tenant_deleted", c.ClientIP(), c.GetHeader("User-Agent"), true, fmt.Sprintf("Tenant %s deleted by %s", workspaceUUID.String(), requesterEmail))
	}

	// Audit log: Tenant deleted (stdout)
	middlewares.Audit(c, "tenant", workspaceUUID.String(), "delete_tenant", &middlewares.AuditChanges{
		Before: map[string]interface{}{
			"workspace_id":     workspaceUUID.String(),
			"tenant_email":     tenantEmail,
			"workspace_domain": workspaceDomain,
			"workspace_db":     tenantDB,
		},
		After: map[string]interface{}{
			"deleted":          true,
			"deleted_counts":   deletedCounts,
			"database_dropped": databaseDropped,
		},
	})

	logger.Info("Tenant deletion completed successfully")

	c.JSON(http.StatusOK, gin.H{
		"message":          "Tenant and all associated data deleted successfully",
		"workspace_id":     workspaceUUID.String(),
		"deleted_counts":   deletedCounts,
		"database_dropped": databaseDropped,
		"warning":          "This action is irreversible. All tenant data has been permanently deleted.",
	})
}
