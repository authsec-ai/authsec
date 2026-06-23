package enduser

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/controllers/shared"
	sharedmodels "github.com/authsec-ai/authsec/internal/sharedmodels"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	hydra "github.com/ory/hydra-client-go/v2"
	"gorm.io/gorm"
)

// countWorkspaceUsers returns the total number of active user records in a workspace.
func countWorkspaceUsers(workspaceID uuid.UUID) (int64, error) {
	var count int64
	err := config.DB.Raw("SELECT COUNT(*) FROM users WHERE workspace_id = ? AND deleted_at IS NULL", workspaceID).Scan(&count).Error
	return count, err
}

// tenantConnectionProvider is a test seam — activation tests swap it for an
// in-memory DB. In runtime it just returns config.DB; the tenant-routing
// behavior was removed when the single-DB collapse landed.
var (
	tenantConnectionProvider = func() *gorm.DB { return config.DB }
	timeNow                  = time.Now
)

type EndUserController struct{}

// RegisterEndUser godoc
// RegisterClient — deleted in Phase G (final workspace_id sweep, 2026-05-31).
// Was an unrouted legacy handler that queried the dropped `clients` and
// `tenants` tables and inserted via the obsolete models.Client struct. The v4
// equivalent is /uflow/user/register/initiate → /uflow/user/register/complete
// (workspace-scoped, no client_id/workspace_id input).

// GetEndUser godoc
// @Summary Get end user
// @Description Retrieves an end user by ID or by email (requires client_id) with all associations
// @Tags EndUser
// @Accept json
// @Produce json
// @Param workspace_id path string true "Workspace ID"
// @Param user_id path string true "User ID"
// @Param client_id query string false "Client ID (required when using email identifier)"
// @Success 200 {object} object
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/user/enduser/{workspace_id}/{user_id} [get]
type GetEndUsersFilter struct {
	WorkspaceID string `json:"workspace_id" binding:"required" validate:"required"`
	Page        int    `json:"page,omitempty"`
	Limit       int    `json:"limit,omitempty"`
	Active      *bool  `json:"active,omitempty"`
	ClientID    string `json:"client_id,omitempty"`
	Email       string `json:"email,omitempty"`
	Name        string `json:"name,omitempty"`
	Provider    string `json:"provider,omitempty"`
}

func (euc *EndUserController) GetEndUser(c *gin.Context) {
	workspaceID, ok := middlewares.GetWorkspaceIDFromToken(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found in authentication token"})
		return
	}
	userIdentifier := c.Param("user_id")

	lookupByID, userUUID, _, emailIdentifier, parseErr := resolveEndUserLookup(userIdentifier, c.Query("client_id"))
	if parseErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": parseErr.Error()})
		return
	}

	// Connect to tenant database
	if config.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection not available"})
		return
	}
	workspaceUUID, err := uuid.Parse(workspaceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid workspace_id format"})
		return
	}

	tenantDB := config.DB

	// Fetch user with all associations. Single-DB collapse means tenant
	// isolation must come from explicit row-level predicates.
	var user models.User
	if lookupByID {
		if err := tenantDB.Preload("Groups").
			Where("id = ? AND workspace_id = ? AND deleted_at IS NULL", userUUID, workspaceUUID).First(&user).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch user"})
			return
		}
	} else {
		if err := tenantDB.Preload("Groups").
			Where("workspace_id = ? AND LOWER(email) = LOWER(?) AND deleted_at IS NULL", workspaceUUID, emailIdentifier).First(&user).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch user"})
			return
		}
	}

	if user.WorkspaceID != uuid.Nil && !strings.EqualFold(user.WorkspaceID.String(), workspaceID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "user does not belong to tenant"})
		return
	}

	c.JSON(http.StatusOK, user)
}

func resolveEndUserLookup(identifier, clientIDParam string) (byID bool, userID uuid.UUID, clientID uuid.UUID, email string, err error) {
	trimmedIdentifier := strings.TrimSpace(identifier)
	if trimmedIdentifier == "" {
		err = fmt.Errorf("user identifier is required")
		return
	}

	if parsedID, parseErr := uuid.Parse(trimmedIdentifier); parseErr == nil {
		byID = true
		userID = parsedID
		return
	}

	trimmedClientID := strings.TrimSpace(clientIDParam)
	if trimmedClientID == "" {
		err = fmt.Errorf("client_id is required when using email identifier")
		return
	}

	clientUUID, parseErr := uuid.Parse(trimmedClientID)
	if parseErr != nil {
		err = fmt.Errorf("invalid client_id")
		return
	}

	clientID = clientUUID
	email = trimmedIdentifier
	return
}

// GetEndUsers godoc
// @Summary Get all end users for a tenant
// @Description Retrieves all end users for a specific tenant with pagination and filtering. Supports both GET (query parameters) and POST (JSON body) methods.
// @Tags EndUser
// @Accept json
// @Produce json
// @Param workspace_id query string true "Workspace ID (GET) or in body (POST)"
// @Param page query int false "Page number (default: 1) - GET method"
// @Param limit query int false "Items per page (default: 10, max: 100) - GET method"
// @Param active query bool false "Filter by active status - GET method"
// @Param client_id query string false "Filter by client ID - GET method"
// @Param email query string false "Filter by email - GET method"
// @Param name query string false "Filter by name - GET method"
// @Param provider query string false "Filter by provider - GET method"
// @Param input body GetEndUsersFilter false "End users filter and pagination parameters - POST method"
// @Success 200 {object} sharedmodels.PaginatedEndUsersResponse
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/user/enduser/list [get]
// @Router /authsec/uflow/user/enduser/list [post]
func (euc *EndUserController) GetEndUsers(c *gin.Context) {
	var filter GetEndUsersFilter

	// Handle different HTTP methods
	if c.Request.Method == "POST" {
		// POST: Bind from JSON body
		if err := c.ShouldBindJSON(&filter); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	} else if c.Request.Method == "GET" {
		// GET: Bind from query parameters
		if err := c.ShouldBindQuery(&filter); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	// Set default values
	if filter.Page <= 0 {
		filter.Page = 1
	}
	if filter.Limit <= 0 {
		filter.Limit = 10
	}
	if filter.Limit > 100 {
		filter.Limit = 100
	}

	// Validate client ID format if provided
	if filter.ClientID != "" {
		if _, err := uuid.Parse(filter.ClientID); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client_id format"})
			return
		}
	}

	offset := (filter.Page - 1) * filter.Limit

	// Determine tenant identifier: prefer request filter, fall back to authenticated context
	tenantIdentifier := filter.WorkspaceID
	if tenantIdentifier == "" {
		if tenantVal, exists := c.Get("workspace_id"); exists {
			if tenantStr, ok := tenantVal.(string); ok && tenantStr != "" {
				tenantIdentifier = tenantStr
			}
		}
	}
	if tenantIdentifier == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "workspace_id is required"})
		return
	}
	filter.WorkspaceID = tenantIdentifier

	// Connect to tenant database
	if config.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database connection not available"})
		return
	}
	tenantDB := config.DB

	// Build query - no base tenant filter needed since we're in tenant-specific DB.
	// Exclude soft-deleted users from all listings.
	query := tenantDB.Model(&models.User{}).Where("deleted_at IS NULL")

	// Apply filters
	if filter.Active != nil {
		query = query.Where("active = ?", *filter.Active)
	} else {
		query = query.Where("active = ?", true)
	}

	if filter.Email != "" {
		// Use ILIKE for case-insensitive partial matching (PostgreSQL)
		// Use LIKE for case-sensitive partial matching (other databases)
		query = query.Where("LOWER(email) LIKE LOWER(?)", "%"+filter.Email+"%")
	}

	if filter.Name != "" {
		// Case-insensitive partial matching for name
		query = query.Where("LOWER(name) LIKE LOWER(?)", "%"+filter.Name+"%")
	}

	if filter.Provider != "" {
		query = query.Where("provider = ?", filter.Provider)
	}

	// Count total records with filters applied
	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to count users"})
		return
	}

	// Fetch users with pagination and all associations
	var users []models.User
	if err := query.Preload("Groups").
		Order("created_at DESC").
		Offset(offset).Limit(filter.Limit).Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch users"})
		return
	}

	// Calculate total pages
	totalPages := int((total + int64(filter.Limit) - 1) / int64(filter.Limit))

	response := models.PaginatedEndUsersResponse{
		Users:      users,
		Total:      int(total),
		Page:       filter.Page,
		Limit:      filter.Limit,
		TotalPages: totalPages,
	}

	c.JSON(http.StatusOK, response)
}

// UpdateEndUserStatus godoc
// @Summary Update end user status
// @Description Updates the active status of an end user
// @Tags EndUser
// @Accept json
// @Produce json
// @Param workspace_id path string true "Workspace ID"
// @Param user_id path string true "User ID"
// @Param input body object true "Status update data"
// @Success 200 {object} object
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/user/enduser/{workspace_id}/{user_id}/status [put]
func (euc *EndUserController) UpdateEndUserStatus(c *gin.Context) {
	workspaceID, ok := middlewares.GetWorkspaceIDFromToken(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found in authentication token"})
		return
	}
	userID := c.Param("user_id")

	var input models.UpdateEndUserStatusInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id format"})
		return
	}

	// Connect to tenant database
	if config.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection not available"})
		return
	}
	tenantDB := config.DB

	// Update user status
	result := tenantDB.Model(&models.User{}).Where("id = ? AND workspace_id = ?", userUUID, workspaceID).
		Updates(map[string]interface{}{
			"active":     input.Active,
			"updated_at": time.Now(),
		})

	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user status"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	// Audit log: End user status updated
	middlewares.Audit(c, "enduser", userID, "update_status", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"user_id":      userID,
			"workspace_id": workspaceID,
			"active":       input.Active,
		},
	})

	response := models.UpdateEndUserStatusResponse{
		Message:   "User status updated successfully",
		Active:    input.Active,
		UpdatedAt: time.Now(),
	}

	c.JSON(http.StatusOK, response)
}

// UpdateUser godoc
// @Summary Update user profile
// @Description Updates user profile information in tenant database
// @Tags EndUser
// @Accept json
// @Produce json
// @Param workspace_id path string true "Workspace ID"
// @Param user_id path string true "User ID"
// @Param input body object true "User update data"
// @Success 200 {object} object
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/user/enduser/{workspace_id}/{user_id} [put]
func (euc *EndUserController) UpdateUser(c *gin.Context) {
	workspaceID, ok := middlewares.GetWorkspaceIDFromToken(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found in authentication token"})
		return
	}
	userID := c.Param("user_id")

	var input models.UpdateUserRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id format"})
		return
	}

	// Connect to tenant database
	if config.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection not available"})
		return
	}
	tenantDB := config.DB

	// Prepare update data
	updateData := make(map[string]interface{})
	updateData["updated_at"] = time.Now()

	if input.Name != nil {
		updateData["name"] = *input.Name
	}
	if input.Username != nil {
		updateData["username"] = *input.Username
	}
	if input.Email != nil {
		updateData["email"] = *input.Email
	}
	if input.AvatarURL != nil {
		updateData["avatar_url"] = *input.AvatarURL
	}
	if input.WorkspaceDomain != nil {
		updateData["workspace_domain"] = *input.WorkspaceDomain
	}

	// Update user
	result := tenantDB.Model(&models.User{}).Where("id = ? AND workspace_id = ?", userUUID, workspaceID).
		Updates(updateData)

	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	// Fetch updated user
	var updatedUser models.User
	if err := tenantDB.Where("id = ? AND workspace_id = ?", userUUID, workspaceID).First(&updatedUser).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch updated user"})
		return
	}

	// Audit log: End user profile updated
	middlewares.Audit(c, "enduser", userID, "update", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"user_id":      userID,
			"workspace_id": workspaceID,
			"updates":      updateData,
		},
	})

	response := map[string]interface{}{
		"message": "User updated successfully",
		"user":    updatedUser,
	}

	c.JSON(http.StatusOK, response)
}

// DeleteEndUser godoc

// @Summary Delete end user

// @Description Soft deletes an end user from tenant database

// @Tags EndUser

// @Accept json

// @Produce json

// @Param workspace_id path string true "Workspace ID"

// @Param user_id path string true "User ID"

// @Success 200 {object} map[string]string

// @Failure 400 {object} map[string]string

// @Failure 404 {object} map[string]string

// @Failure 500 {object} map[string]string

// @Router /authsec/uflow/user/enduser/{workspace_id}/{user_id} [delete]

// @Router /authsec/uflow/user/enduser/delete [post]

func (euc *EndUserController) DeleteEndUser(c *gin.Context) {

	workspaceID, ok := middlewares.GetWorkspaceIDFromToken(c)

	if !ok {

		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found in authentication token"})

		return

	}

	userID := c.Param("user_id")

	jsonData := make(map[string]string)

	if userID == "" {

		if err := c.ShouldBindJSON(&jsonData); err != nil {

			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format: " + err.Error()})

			return

		}

		if userID == "" {

			userID = jsonData["user_id"]

		}

	}

	if userID == "" {

		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})

		return

	}

	userInfo := middlewares.GetUserInfo(c)

	if userInfo == nil || strings.TrimSpace(userInfo.WorkspaceID) == "" {

		c.JSON(http.StatusForbidden, gin.H{"error": "tenant scope is required"})

		return

	}

	if !strings.EqualFold(strings.TrimSpace(userInfo.WorkspaceID), workspaceID) {

		c.JSON(http.StatusForbidden, gin.H{"error": "cross-tenant deletion is not allowed"})

		return

	}

	if config.DB == nil {

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection not available"})

		return

	}

	workspaceUUID, err := uuid.Parse(workspaceID)

	if err != nil {

		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid workspace_id format"})

		return

	}

	tenantDB := tenantConnectionProvider()

	userUUID, err := uuid.Parse(userID)

	if err != nil {

		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id format"})

		return

	}

	if others, err := countOtherActiveEndUsers(tenantDB, workspaceUUID, userUUID); err != nil {

		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify active users"})

		return

	} else if others == 0 {

		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot deactivate the last active user in this tenant"})

		return

	}

	rowsAffected, err := updateUserActiveStatus(tenantDB, workspaceUUID, userUUID, false)

	if err != nil {

		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to disable user"})

		return

	}

	// Check if a user was actually found and disabled.

	if rowsAffected == 0 {

		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})

		return

	}

	// Audit log: End user deleted (soft delete)

	middlewares.Audit(c, "enduser", userID, "delete", &middlewares.AuditChanges{

		Before: map[string]interface{}{

			"user_id": userID,

			"workspace_id": workspaceID,

			"active": true,
		},

		After: map[string]interface{}{

			"active": false,
		},
	})

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})

}

// DeleteUserAllRequest is the request body for hard delete

type DeleteUserAllRequest struct {
	WorkspaceID string `json:"workspace_id" binding:"required"`

	UserID string `json:"user_id" binding:"required"`
}

// DeleteUserAll godoc

// @Summary Hard delete end user and all related data

// @Description Permanently deletes an end user and all associated data from the tenant database. This includes role_bindings, totp_secrets, backup_codes, webauthn_credentials, ciba_push_devices, ciba_auth_requests, etc. Cannot delete the last active user.

// @Tags EndUser

// @Accept json

// @Produce json

// @Security BearerAuth

// @Param input body DeleteUserAllRequest true "User delete payload"

// @Success 200 {object} map[string]interface{} "User and all related data deleted successfully"

// @Failure 400 {object} map[string]string "Invalid request or cannot delete last user"

// @Failure 403 {object} map[string]string "Cross-tenant operation not allowed"

// @Failure 404 {object} map[string]string "User not found"

// @Failure 500 {object} map[string]string "Internal server error"

// @Router /authsec/uflow/user/enduser/delete_all [post]

func (euc *EndUserController) DeleteUserAll(c *gin.Context) {

	var req DeleteUserAllRequest

	if err := c.ShouldBindJSON(&req); err != nil {

		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})

		return

	}

	workspaceID := strings.TrimSpace(req.WorkspaceID)

	userID := strings.TrimSpace(req.UserID)

	if workspaceID == "" || userID == "" {

		c.JSON(http.StatusBadRequest, gin.H{"error": "workspace_id and user_id are required"})

		return

	}

	// Verify caller's tenant matches target tenant

	userInfo := middlewares.GetUserInfo(c)

	if userInfo == nil || strings.TrimSpace(userInfo.WorkspaceID) == "" {

		c.JSON(http.StatusForbidden, gin.H{"error": "tenant scope is required"})

		return

	}

	if !strings.EqualFold(strings.TrimSpace(userInfo.WorkspaceID), workspaceID) {

		c.JSON(http.StatusForbidden, gin.H{"error": "cross-tenant deletion is not allowed"})

		return

	}

	workspaceUUID, err := uuid.Parse(workspaceID)

	if err != nil {

		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid workspace_id format"})

		return

	}

	userUUID, err := uuid.Parse(userID)

	if err != nil {

		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id format"})

		return

	}

	if config.DB == nil {

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection not available"})

		return

	}

	tenantDB := tenantConnectionProvider()

	// Use fresh session to avoid stale transaction states

	freshDB := tenantDB.Session(&gorm.Session{NewDB: true})

	// Verify user exists

	var user models.User

	if err := freshDB.Where("id = ? AND workspace_id = ?", userUUID, workspaceUUID).First(&user).Error; err != nil {

		if errors.Is(err, gorm.ErrRecordNotFound) {

			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})

			return

		}

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user: " + err.Error()})

		return

	}

	// Check if this is the last active user

	others, err := countOtherActiveEndUsers(freshDB, workspaceUUID, userUUID)

	if err != nil {

		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify active users"})

		return

	}

	if others == 0 {

		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot delete the last active user in this tenant"})

		return

	}

	log.Printf("INFO: Hard deleting user %s and all related data for tenant %s", userUUID, workspaceUUID)

	// Delete all related data in a transaction

	deletedCounts := make(map[string]int64)

	err = freshDB.Transaction(func(tx *gorm.DB) error {

		// 1. Delete role_bindings

		result := tx.Where("user_id = ? AND workspace_id = ?", userUUID, workspaceUUID).Delete(&models.RoleBinding{})

		if result.Error != nil {

			return fmt.Errorf("failed to delete role_bindings: %w", result.Error)

		}

		deletedCounts["role_bindings"] = result.RowsAffected

		// 2. Delete totp_secrets (MFA devices)

		result = tx.Exec("DELETE FROM totp_secrets WHERE user_id = ? AND workspace_id = ?", userUUID, workspaceUUID)

		if result.Error != nil {

			return fmt.Errorf("failed to delete totp_secrets: %w", result.Error)

		}

		deletedCounts["totp_secrets"] = result.RowsAffected

		// 3. Delete totp_backup_codes

		result = tx.Exec("DELETE FROM totp_backup_codes WHERE user_id = ? AND workspace_id = ?", userUUID, workspaceUUID)

		if result.Error != nil {

			return fmt.Errorf("failed to delete totp_backup_codes: %w", result.Error)

		}

		deletedCounts["totp_backup_codes"] = result.RowsAffected

		// 4. Delete ciba_auth_requests

		result = tx.Exec("DELETE FROM ciba_auth_requests WHERE user_id = ? AND workspace_id = ?", userUUID, workspaceUUID)

		if result.Error != nil {

			return fmt.Errorf("failed to delete ciba_auth_requests: %w", result.Error)

		}

		deletedCounts["ciba_auth_requests"] = result.RowsAffected

		// 5. Delete voice_identity_links

		result = tx.Exec("DELETE FROM voice_identity_links WHERE user_id = ? AND workspace_id = ?", userUUID, workspaceUUID)

		if result.Error != nil {

			return fmt.Errorf("failed to delete voice_identity_links: %w", result.Error)

		}

		deletedCounts["voice_identity_links"] = result.RowsAffected

		// 6. Delete user_groups

		result = tx.Exec("DELETE FROM user_groups WHERE user_id = ? AND workspace_id = ?", userUUID, workspaceUUID)

		if result.Error != nil {

			return fmt.Errorf("failed to delete user_groups: %w", result.Error)

		}

		deletedCounts["user_groups"] = result.RowsAffected

		// 7. Finally, delete the user

		result = tx.Where("id = ? AND workspace_id = ?", userUUID, workspaceUUID).Delete(&models.User{})

		if result.Error != nil {

			return fmt.Errorf("failed to delete user: %w", result.Error)

		}

		deletedCounts["users"] = result.RowsAffected

		return nil

	})

	if err != nil {

		log.Printf("ERROR: Failed to hard delete user %s: %v", userUUID, err)

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user: " + err.Error()})

		return

	}

	log.Printf("INFO: Successfully hard deleted user %s with counts: %+v", userUUID, deletedCounts)

	// Audit log: End user hard deleted

	middlewares.Audit(c, "enduser", userID, "delete_all", &middlewares.AuditChanges{

		Before: map[string]interface{}{

			"user_id": userID,

			"workspace_id": workspaceID,

			"email": user.Email,

			"username": user.Username,
		},

		After: map[string]interface{}{

			"deleted": true,

			"deleted_counts": deletedCounts,
		},
	})

	c.JSON(http.StatusOK, gin.H{

		"message": "User and all related data deleted successfully",

		"user_id": userID,

		"deleted_counts": deletedCounts,
	})

}

type toggleEndUserActiveRequest struct {
	WorkspaceID string               `json:"workspace_id" binding:"required"`
	UserID      string               `json:"user_id" binding:"required"`
	Active      *shared.FlexibleBool `json:"active" binding:"required"`
}

func countOtherActiveEndUsers(db *gorm.DB, workspaceID uuid.UUID, excludeUser uuid.UUID) (int64, error) {
	if db == nil {
		return 0, fmt.Errorf("tenant database connection not available")
	}

	var count int64
	if err := db.Model(&models.User{}).
		Where("workspace_id = ? AND id <> ? AND active = ?", workspaceID, excludeUser, true).
		Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

func (euc *EndUserController) ActiveOrDeactiveEndUser(c *gin.Context) {
	var req toggleEndUserActiveRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	workspaceID := strings.TrimSpace(req.WorkspaceID)
	userID := strings.TrimSpace(req.UserID)
	if workspaceID == "" || userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "workspace_id and user_id are required"})
		return
	}

	// Verify the caller's workspace (from the JWT) matches the target workspace.
	// Without this, a workspace-A admin could toggle a user in workspace B.
	userInfo := middlewares.GetUserInfo(c)
	if userInfo == nil || strings.TrimSpace(userInfo.WorkspaceID) == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "workspace scope is required"})
		return
	}
	if !strings.EqualFold(strings.TrimSpace(userInfo.WorkspaceID), workspaceID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "cross-workspace operation is not allowed"})
		return
	}

	if req.Active == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "active field is required"})
		return
	}

	active := req.Active.Bool()

	workspaceUUID, err := uuid.Parse(workspaceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid workspace_id format"})
		return
	}

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id format"})
		return
	}

	if config.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection not available"})
		return
	}

	tenantDB := tenantConnectionProvider()

	if !active {
		others, err := countOtherActiveEndUsers(tenantDB, workspaceUUID, userUUID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify active users"})
			return
		}
		if others == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "cannot deactivate the last active user in this tenant"})
			return
		}
	}

	rowsAffected, err := updateUserActiveStatus(tenantDB, workspaceUUID, userUUID, active)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user status"})
		return
	}

	// Check if a user was actually found and deleted.
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	// Audit log: End user active status toggled
	action := "deactivate"
	if active {
		action = "activate"
	}
	middlewares.Audit(c, "enduser", userID, action, &middlewares.AuditChanges{
		After: map[string]interface{}{
			"user_id":      userID,
			"workspace_id": workspaceID,
			"active":       active,
		},
	})

	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
}

// Private helper methods

func updateUserActiveStatus(db *gorm.DB, workspaceID uuid.UUID, userID uuid.UUID, active bool) (int64, error) {
	if db == nil {
		return 0, fmt.Errorf("tenant database connection not available")
	}

	result := db.Table("users").
		Where("id = ? AND workspace_id = ?", userID, workspaceID).
		Updates(map[string]interface{}{
			"active":     active,
			"updated_at": timeNow(),
		})

	return result.RowsAffected, result.Error
}

func (euc *EndUserController) OIDCLogin(c *gin.Context) {
	var input models.OIDCLoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate OIDC token against Ory Hydra
	introspection, err := euc.validateOIDCToken(input.AccessToken)
	if err != nil || !*introspection.Active {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or inactive OIDC token"})
		return
	}

	// Safely extract workspaceID, emailID, and clientID with type assertions and checks
	ext := introspection.Ext
	if ext == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing extension fields in OIDC token"})
		return
	}
	workspaceID, ok := ext["workspace_id"].(string)
	if !ok || workspaceID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or missing workspace_id in OIDC token"})
		return
	}
	emailID, ok := ext["email"].(string)
	if !ok || emailID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or missing email in OIDC token"})
		return
	}

	// clientID is the OAuth client that issued the token (Category A — for logging only).
	// It is NOT a user-identity predicate; user identity is (workspace_id, LOWER(email)).
	clientID := introspection.ClientID

	// Parse workspace UUID before user lookup so it can be used as a WHERE predicate.
	workspaceIDUUID, err := uuid.Parse(workspaceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid workspace ID format"})
		return
	}

	// Find user by (workspace_id, email) — the canonical v4 identity predicate.
	// Category-C fix: client_id is NOT a user-identity predicate; it was the OAuth client
	// that issued the token. MFA check is attempted first, then falls back to active check.
	tenantDB := config.DB
	var user models.User
	err = tenantDB.Where("workspace_id = ? AND LOWER(email) = LOWER(?) AND active = ? AND mfa_enabled = ? AND deleted_at IS NULL",
		workspaceIDUUID, emailID, true, true).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("MFA not enabled or user not found for workspace: %s, email: %s, oauth_client: %s", workspaceID, emailID, clientID)
		} else {
			log.Printf("Database error during MFA-enabled user query for workspace: %s, email: %s, error: %v", workspaceID, emailID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			return
		}

		// Fallback: user exists but MFA is not enabled
		err = tenantDB.Where("workspace_id = ? AND LOWER(email) = LOWER(?) AND active = ? AND deleted_at IS NULL",
			workspaceIDUUID, emailID, true).First(&user).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				log.Printf("User not found in fallback query for workspace: %s, email: %s", workspaceID, emailID)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			} else {
				log.Printf("Database error in fallback user query for workspace: %s, email: %s, error: %v", workspaceID, emailID, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			}
			return
		}
		log.Printf("Fallback successful: User found with MFA disabled for workspace: %s, email: %s", workspaceID, user.Email)
	} else {
		log.Printf("MFA-enabled user found for workspace: %s, email: %s", workspaceID, user.Email)
	}

	// Cross-verify workspace ID from token matches user's workspace
	if user.WorkspaceID != workspaceIDUUID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Workspace mismatch in credentials"})
		return
	}

	// Check if this is first-time login by examining last_login column
	isFirstLogin := user.LastLogin == nil

	// Prepare base response
	response := models.LoginResponse{
		WorkspaceID: user.WorkspaceID.String(),
		Email:       user.Email,
		FirstLogin:  isFirstLogin,
		OTPRequired: false,
	}

	// Handle logic based on MFA and login type
	if !user.MFAEnabled {
		log.Printf("MFA not enabled for user: %s - proceeding with login", user.Email)
		authController, authErr := NewEndUserAuthController()
		if authErr != nil {
			log.Printf("failed to initialize end-user auth controller for custom login token issuance: %v", authErr)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initialize authentication flow"})
			return
		}

		token, tokenErr := authController.generateJWTToken(
			user.WorkspaceID.String(),
			clientID,
			user.Email,
			user.WorkspaceDomain,
			&user.ID,
			tenantDB,
		)
		if tokenErr != nil {
			log.Printf("failed to generate end-user token for OIDC login user=%s client_id=%s: %v", user.Email, clientID, tokenErr)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to issue login token"})
			return
		}

		response.Token = token
		response.MFARequired = false
	} else if isFirstLogin {
		log.Printf("First-time login for: %s - may require MFA setup", user.Email)
		// TODO: Optionally generate temporary token or redirect to MFA enrollment
		response.MFARequired = true
	} else {
		// Returning user with MFA enabled: require verification, no token yet
		log.Printf("Returning user login for: %s - requires MFA verification", user.Email)
		response.MFARequired = true
		c.JSON(http.StatusOK, response)
		return
	}

	// Update last_login for successful partial/full login (before token issuance or MFA prompt)

	// Return response (with token if applicable)
	c.JSON(http.StatusOK, response)
}

// validateOIDCToken validates the OIDC token against Ory Hydra's introspection endpoint
func (tc *EndUserController) validateOIDCToken(token string) (*sharedmodels.Introspection, error) {
	// Initialize Ory Hydra client
	if config.AppConfig == nil {
		return nil, errors.New("application configuration not available")
	}
	hydraAdminURL := config.AppConfig.HydraAdminURL
	if hydraAdminURL == "" {
		return nil, errors.New("hydra Admin URL is not configured")
	}
	//remove initial "http://"
	if hydraAdminURL[:7] == "http://" {
		hydraAdminURL = hydraAdminURL[7:]
	}

	// Create a new Hydra client
	config := hydra.NewConfiguration()
	config.Host = hydraAdminURL
	config.Scheme = "http"
	client := hydra.NewAPIClient(config)

	// Perform token introspection using the correct API method
	resp, httpResp, err := client.OAuth2API.IntrospectOAuth2Token(context.Background()).Token(token).Execute()
	if err != nil {
		return nil, errors.New("failed to introspect token: " + err.Error())
	}
	if httpResp.StatusCode != http.StatusOK {
		return nil, errors.New("token introspection failed with status: " + httpResp.Status)
	}

	// Convert the response to IntrospectionResponse
	introspection := &sharedmodels.Introspection{
		Active:   &resp.Active,
		Scope:    *resp.Scope, // Dereference the pointer to get the string value
		ClientID: *resp.ClientId,
		Ext:      resp.Ext,
	}

	return introspection, nil
}

func (euc *EndUserController) CustomLogin(c *gin.Context) {
	var input models.CustomLoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	input.Email = strings.ToLower(input.Email)

	// Workspace comes from explicit workspace_id (set by UI from page-data),
	// ?workspace= query param, or Host header — never from client_id.
	workspaceID, err := shared.ResolveWorkspace(c, input.WorkspaceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("workspace resolution failed: %v", err)})
		return
	}

	// Single-DB collapse: tenant isolation must come from explicit predicates.
	tenantDB := config.DB

	// Find user by (workspace_id, email) — the canonical identity tuple.
	// Soft-deleted users (deleted_at set) must never authenticate.
	var user models.User
	if err := tenantDB.Where("workspace_id = ? AND LOWER(email) = ? AND provider IN (?) AND deleted_at IS NULL", workspaceID, input.Email, []string{"custom", "ad_sync", "entra_id", "scim"}).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Verify password
	if !user.CheckPassword(input.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Check if MFA is enabled
	var user2 models.User
	if err := tenantDB.Where("workspace_id = ? AND LOWER(email) = ? AND mfa_enabled = ?", workspaceID, input.Email, "true").First(&user2).Error; err != nil {
		// MFA is not enabled
		var isFirstLogin bool
		if user.Provider == "ad_sync" || user.Provider == "entra_id" {
			isFirstLogin = true
		} else {
			isFirstLogin = user.LastLogin == nil
		}

		response := models.LoginResponse{
			WorkspaceID: user.WorkspaceID.String(),
			Email:       user.Email,
			FirstLogin:  isFirstLogin,
			OTPRequired: false,
		}

		authController, authErr := NewEndUserAuthController()
		if authErr != nil {
			log.Printf("failed to initialize end-user auth controller for custom login token issuance: %v", authErr)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initialize authentication flow"})
			return
		}

		token, tokenErr := authController.generateJWTToken(
			user.WorkspaceID.String(),
			input.ClientID,
			user.Email,
			user.WorkspaceDomain,
			&user.ID,
			tenantDB,
		)
		if tokenErr != nil {
			log.Printf("failed to generate end-user token for custom login user=%s client_id=%s: %v", user.Email, input.ClientID, tokenErr)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to issue login token"})
			return
		}
		response.Token = token
		response.MFARequired = false

		c.JSON(http.StatusOK, response)
		return
	}

	// MFA is enabled
	isFirstLogin := user2.LastLogin == nil

	// Prepare base response
	response := models.LoginResponse{
		WorkspaceID: user2.WorkspaceID.String(),
		Email:       user2.Email,
		FirstLogin:  isFirstLogin,
		OTPRequired: false,
		MFARequired: true,
	}

	log.Printf("Returning user login for: %s - requires MFA verification", user.Email)
	c.JSON(http.StatusOK, response)
}

func (euc *EndUserController) CustomLoginStatus(c *gin.Context) {
	var input models.CustomLoginStatus
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	if input.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email is required"})
		return
	}

	// Workspace comes from the explicit workspace_id the UI resolved from the
	// Hydra login_challenge (via page-data), then ?workspace=, then Host header.
	// NEVER from an OAuth client_id (global per OAuth 2.1) and never from email
	// (ambiguous across workspaces).
	workspaceID, err := shared.ResolveWorkspace(c, input.WorkspaceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("unknown workspace: %v", err)})
		return
	}

	// User identity is (workspace_id, email). Period. No client_id in the WHERE.
	var existingUser models.User
	err = config.DB.Where(
		"workspace_id = ? AND LOWER(email) = ? AND provider IN (?)",
		workspaceID, input.Email, []string{"custom", "ad_sync", "scim", "entra_id"},
	).First(&existingUser).Error
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"response": "false", "message": "User does not exist, proceed with registration"})
		return
	}

	// Synced users (ad_sync / entra_id / scim) without a password_hash need to
	// finish registration (password setup), so report as "not yet registered".
	if (existingUser.Provider == "ad_sync" || existingUser.Provider == "entra_id" || existingUser.Provider == "scim") && existingUser.PasswordHash == "" {
		c.JSON(http.StatusOK, gin.H{"response": "false", "message": "User does not exist, proceed with registration"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"response": "true", "message": "User already exists"})
}

// InitiateCustomLoginRegister godoc
// @Summary Initiate custom login registration with OTP
// @Description Initiates custom login registration by sending OTP to email for verification
// @Tags EndUser Auth
// @Accept json
// @Produce json
// @Param input body object true "User registration initiation data"
// @Success 200 {object} object
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/user/register/initiate [post]
func (euc *EndUserController) InitiateCustomLoginRegister(c *gin.Context) {
	var input models.CustomLoginRegister
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	input.Email = strings.ToLower(input.Email)

	// Workspace comes from explicit workspace_id (set by UI from page-data),
	// ?workspace= query param, or Host header — never from client_id.
	workspaceID, err := shared.ResolveWorkspace(c, input.WorkspaceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("workspace resolution failed: %v", err)})
		return
	}

	// Get tenant database connection
	tenantDB := config.DB

	// Check if email already exists in this workspace
	var existingUser models.User
	if err := tenantDB.Where("workspace_id = ? AND LOWER(email) = ? AND provider IN (?)", workspaceID, input.Email, []string{"custom", "ad_sync", "entra_id", "scim"}).First(&existingUser).Error; err == nil {
		// If user exists and is not a synced user with empty password, reject registration
		if !((existingUser.Provider == "ad_sync" || existingUser.Provider == "entra_id" || existingUser.Provider == "scim") && existingUser.PasswordHash == "") {
			c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
			return
		}
	}

	// Hash the password for storage in pending registration
	tempUser := models.ExtendedUser{
		User: sharedmodels.User{
			PasswordHash: input.Password,
		},
	}
	if err := tempUser.HashPassword(); err != nil {
		log.Printf("Failed to hash password: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process password"})
		return
	}

	// Delete any existing pending registration for this email
	db := config.GetDatabase()
	if _, err := db.Exec("DELETE FROM pending_registrations WHERE email = $1", input.Email); err != nil {
		log.Printf("Error deleting existing pending registration: %v", err)
	}

	// Phase A: client_id and project_id removed from pending_registrations.
	// workspace_id is the only scope identifier.
	insertQuery := `INSERT INTO pending_registrations (email, password_hash, first_name, last_name, workspace_id, workspace_domain, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())`
	if _, err := db.Exec(insertQuery,
		input.Email,
		tempUser.PasswordHash,
		"", // first_name: not collected during custom-login signup
		"", // last_name:  same
		workspaceID,
		config.AppConfig.WorkspaceDomainSuffix,
		time.Now().Add(30*time.Minute),
	); err != nil {
		log.Printf("Failed to create pending registration: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initiate registration"})
		return
	}

	// Generate and send OTP
	otp, err := utils.GenerateOTP()
	if err != nil {
		log.Printf("Failed to generate OTP: %v", err)
		// Cleanup pending registration
		db.Exec("DELETE FROM pending_registrations WHERE email = $1", input.Email)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send verification email"})
		return
	}

	// Delete any existing OTP for this email
	if _, err := db.Exec("DELETE FROM otp_entries WHERE email = $1", input.Email); err != nil {
		log.Printf("Warning - failed to delete old OTPs: %v", err)
	}

	// Create new OTP entry
	otpInsert := `INSERT INTO otp_entries (email, otp, expires_at, verified, created_at, updated_at)
		VALUES ($1, $2, $3, false, NOW(), NOW())`
	if _, err := db.Exec(otpInsert, input.Email, otp, time.Now().Add(10*time.Minute)); err != nil {
		log.Printf("Failed to create OTP: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create OTP"})
		return
	}

	// Send OTP via email
	if err := utils.SendOTPEmail(input.Email, otp); err != nil {
		if strings.EqualFold(config.AppConfig.Environment, "development") && config.AppConfig.SMTPHost == "" {
			log.Printf("Custom login registration initiated for %s with development OTP fallback: %s", input.Email, otp)
			c.JSON(http.StatusOK, gin.H{
				"message": fmt.Sprintf("Registration initiated. Development OTP: %s", otp),
				"email":   input.Email,
				"dev_otp": otp,
			})
			return
		}
		log.Printf("Failed to send OTP email: %v", err)
		// Cleanup
		db.Exec("DELETE FROM otp_entries WHERE email = $1", input.Email)
		db.Exec("DELETE FROM pending_registrations WHERE email = $1", input.Email)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send verification email"})
		return
	}

	log.Printf("Custom login registration initiated for: %s", input.Email)

	c.JSON(http.StatusOK, gin.H{
		"message": "Registration initiated. Please check your email for OTP verification.",
		"email":   input.Email,
	})
}

// CompleteCustomLoginRegister godoc
// @Summary Complete custom login registration with OTP verification
// @Description Verifies the OTP and completes custom login user registration
// @Tags EndUser Auth
// @Accept json
// @Produce json
// @Param input body object true "OTP verification data"
// @Success 200 {object} object
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/user/register/complete [post]
func (euc *EndUserController) CompleteCustomLoginRegister(c *gin.Context) {
	var input struct {
		Email       string `json:"email" binding:"required,email"`
		OTP         string `json:"otp" binding:"required"`
		WorkspaceID string `json:"workspace_id"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	input.Email = strings.ToLower(input.Email)

	// Workspace comes from explicit workspace_id (set by the UI from page-data),
	// ?workspace=, or Host — never from client_id. Scopes the pending lookup so
	// the same email registering across multiple workspaces resolves correctly.
	workspaceID, err := shared.ResolveWorkspace(c, input.WorkspaceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("workspace resolution failed: %v", err)})
		return
	}

	db := config.GetDatabase()

	// Verify OTP
	var otpVerified bool
	var otpExpiry time.Time
	err = db.QueryRow("SELECT verified, expires_at FROM otp_entries WHERE email = $1 AND otp = $2", input.Email, input.OTP).Scan(&otpVerified, &otpExpiry)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired OTP"})
		return
	}

	if otpExpiry.Before(time.Now()) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "OTP has expired"})
		return
	}

	// Mark OTP as verified
	if _, err := db.Exec("UPDATE otp_entries SET verified = true, updated_at = NOW() WHERE email = $1 AND otp = $2", input.Email, input.OTP); err != nil {
		log.Printf("Failed to mark OTP as verified: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify OTP"})
		return
	}

	// Get pending registration, scoped by (workspace_id, email). The legacy
	// client_id and project_id columns are no longer selected — client_id was
	// dropped in Phase A and project_id is unused by the user creation below.
	var pendingReg models.PendingRegistration
	err = db.QueryRow(`SELECT email, password_hash, first_name, last_name, workspace_id, workspace_domain, expires_at
		FROM pending_registrations WHERE email = $1 AND workspace_id = $2`, input.Email, workspaceID).Scan(
		&pendingReg.Email, &pendingReg.PasswordHash, &pendingReg.FirstName, &pendingReg.LastName,
		&pendingReg.WorkspaceID, &pendingReg.WorkspaceDomain, &pendingReg.ExpiresAt)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Registration session expired. Please initiate registration again"})
		return
	}

	// Single-DB collapse: scope by pendingReg.WorkspaceID explicitly.
	tenantDB := config.DB

	// Check if there's an existing synced user (AD/Entra/SCIM) that needs password update.
	// Identity is (workspace_id, email) — no client_id predicate.
	var adSyncUser models.User
	if err := tenantDB.Where("workspace_id = ? AND LOWER(email) = ? AND provider IN (?)", pendingReg.WorkspaceID, input.Email, []string{"ad_sync", "entra_id", "scim"}).First(&adSyncUser).Error; err == nil {
		// Update the existing synced user's password_hash
		if err := tenantDB.Model(&adSyncUser).Update("password_hash", pendingReg.PasswordHash).Error; err != nil {
			log.Printf("Failed to update user password: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
			return
		}

		// Cleanup
		db.Exec("DELETE FROM pending_registrations WHERE email = $1", input.Email)
		db.Exec("DELETE FROM otp_entries WHERE email = $1", input.Email)

		c.JSON(http.StatusOK, gin.H{
			"message": "Registration completed successfully",
			"email":   input.Email,
		})
		return
	}

	// Derive a display name. The custom-login signup form doesn't collect
	// first/last name, and historically we wrote pendingReg.Email into the
	// users.name column — which the admin UI then split on whitespace and
	// surfaced as `first_name`, making "first_name" appear to equal the user's
	// email. Use the email local-part as a friendlier default; if the pending
	// registration captured an explicit first/last name (non-email), prefer
	// that. The local-part is purely cosmetic and the UI can still let the
	// user edit their name later.
	displayName := strings.TrimSpace(pendingReg.FirstName + " " + pendingReg.LastName)
	if displayName == "" || strings.Contains(displayName, "@") {
		// Either nothing captured, or the legacy bug filled FirstName with
		// the full email — fall back to the email local-part.
		if at := strings.Index(pendingReg.Email, "@"); at > 0 {
			displayName = pendingReg.Email[:at]
		} else {
			displayName = ""
		}
	}

	// Phase A: client_id and project_id removed from PendingRegistration.
	// User identity is (workspace_id, email); no client_id predicate.
	newUser := models.ExtendedUser{
		User: sharedmodels.User{
			ID:           uuid.New(),
			WorkspaceID:  pendingReg.WorkspaceID,
			Name:         displayName,
			Email:        pendingReg.Email,
			PasswordHash: pendingReg.PasswordHash,
			WorkspaceDomain: pendingReg.WorkspaceDomain,
			Provider:     "custom",
			ProviderID:   pendingReg.Email,
			Active:       true,
			MFAEnabled:   false,
		},
	}

	if err := tenantDB.Create(&newUser).Error; err != nil {
		log.Printf("Failed to create new user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to complete registration"})
		return
	}

	// Cleanup pending registration and OTP
	db.Exec("DELETE FROM pending_registrations WHERE email = $1", input.Email)
	db.Exec("DELETE FROM otp_entries WHERE email = $1", input.Email)

	log.Printf("Custom login registration completed for: %s", input.Email)

	c.JSON(http.StatusOK, gin.H{
		"message": "Registration completed successfully",
		"email":   input.Email,
	})
}

// CustomLoginRegister - Legacy single-step registration endpoint.
// Deprecated: Use InitiateCustomLoginRegister + CompleteCustomLoginRegister instead.
func (euc *EndUserController) CustomLoginRegister(c *gin.Context) {
	var input models.CustomLoginRegister
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	input.Email = strings.ToLower(input.Email)

	// Workspace comes from explicit workspace_id (set by UI from page-data),
	// ?workspace= query param, or Host header — never from client_id.
	workspaceID, err := shared.ResolveWorkspace(c, input.WorkspaceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("workspace resolution failed: %v", err)})
		return
	}

	tenantDB := config.DB

	// Check if email already exists in this workspace
	var existingUser models.User
	if err := tenantDB.Where("workspace_id = ? AND LOWER(email) = ? AND provider IN (?)", workspaceID, input.Email, []string{"custom", "ad_sync", "entra_id", "scim"}).First(&existingUser).Error; err == nil {
		if (existingUser.Provider == "ad_sync" || existingUser.Provider == "entra_id" || existingUser.Provider == "scim") && existingUser.PasswordHash == "" {
			// Synced user without password — update their password_hash instead.
			tempUser := models.ExtendedUser{User: sharedmodels.User{PasswordHash: input.Password}}
			if err := tempUser.HashPassword(); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process password"})
				return
			}
			if err := tenantDB.Model(&existingUser).Update("password_hash", tempUser.PasswordHash).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"message": "Registration completed successfully", "email": input.Email})
			return
		}
		c.JSON(http.StatusOK, gin.H{"response": "true", "message": "User already exists"})
		return
	}

	tempUser := models.ExtendedUser{User: sharedmodels.User{PasswordHash: input.Password}}
	if err := tempUser.HashPassword(); err != nil {
		log.Printf("Failed to hash password: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process password"})
		return
	}

	// Gate: check total-user limit before creating the account. Phase A killed
	// the client_id-as-tenant-resolver concept — workspaceID is already resolved
	// above from host / explicit param / JWT (see shared.ResolveWorkspace at the
	// top of this handler), so we no longer parse input.ClientID/workspaceID here.
	if currentCount, countErr := countWorkspaceUsers(workspaceID); countErr == nil {
		if resp, billErr := config.BillingClient.CheckTotalUsers(c.Request.Context(), workspaceID.String(), int(currentCount)); billErr != nil {
			log.Printf("[REGISTER] billing check failed (fail-open) workspace=%s: %v", workspaceID, billErr)
		} else if !resp.Allowed {
			c.JSON(http.StatusPaymentRequired, gin.H{
				"error":        "user limit reached",
				"current":      resp.Current,
				"limit":        resp.Limit,
				"plan":         resp.PlanID,
				"upgrade_hint": resp.UpgradeHint,
			})
			return
		}
	}

	newUser := models.ExtendedUser{
		User: sharedmodels.User{
			ID:           uuid.New(),
			WorkspaceID:  workspaceID,
			Name:         input.Email,
			Email:        input.Email,
			PasswordHash: tempUser.PasswordHash,
			WorkspaceDomain: config.AppConfig.WorkspaceDomainSuffix,
			Provider:     "custom",
			ProviderID:   input.Email,
			Active:       true,
			MFAEnabled:   false,
		},
	}
	if err := tenantDB.Create(&newUser).Error; err != nil {
		log.Printf("Failed to create new user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initiate registration"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Registration completed successfully",
		"email":   input.Email,
	})
}

// tenantMapping and resolveCustomLoginProjectID deleted in Phase A.
// Workspace is resolved via shared.ResolveWorkspace(c, input.WorkspaceID).
// There is no general client_id → workspace mapping in OAuth 2.1.

// Add these methods to your EndUserController struct in enduser_controller.go

// CustomForgotPassword godoc
// @Summary Initiate forgot password for custom login
// @Description Sends OTP to user's email for password reset verification
// @Tags Auth
// @Accept json
// @Produce json
// @Param input body object true "Forgot password data"
// @Success 200 {object} object
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/user/forgot-password [post]
func (euc *EndUserController) CustomForgotPassword(c *gin.Context) {
	var input models.CustomForgotPasswordInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	input.Email = strings.ToLower(input.Email)

	// Workspace comes from explicit workspace_id (set by UI from page-data),
	// ?workspace= query param, or Host header — never from client_id.
	workspaceID, err := shared.ResolveWorkspace(c, input.WorkspaceID)
	if err != nil {
		// For security, don't reveal workspace resolution failure
		c.JSON(http.StatusOK, models.CustomForgotPasswordResponse{
			Message: "If your email is registered, you will receive a password reset OTP",
			Email:   input.Email,
		})
		return
	}

	// Single-DB collapse: scope user lookup by workspace_id explicitly.
	tenantDB := config.DB

	// Check if user exists with custom provider in this workspace
	var user models.User
	if err := tenantDB.Where("workspace_id = ? AND LOWER(email) = ? AND provider IN (?) AND active = ? AND deleted_at IS NULL", workspaceID, input.Email, []string{"custom", "ad_sync", "entra_id", "scim"}, true).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("User not found for forgot password request: %s", input.Email)
		} else {
			log.Printf("Database error during forgot password user lookup: %v", err)
		}
		// For security, always return success message regardless of whether user exists
		c.JSON(http.StatusOK, models.CustomForgotPasswordResponse{
			Message: "If your email is registered, you will receive a password reset OTP",
			Email:   input.Email,
		})
		return
	}

	// Generate and send OTP using existing utility
	if err := euc.generateAndSendCustomPasswordResetOTP(input.Email); err != nil {
		log.Printf("Failed to send password reset OTP: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send verification email"})
		return
	}

	log.Printf("Password reset OTP sent for custom login user: %s", input.Email)

	c.JSON(http.StatusOK, models.CustomForgotPasswordResponse{
		Message: "If your email is registered, you will receive a password reset OTP",
		Email:   input.Email,
	})
}

// CustomVerifyPasswordResetOTP godoc
// @Summary Verify OTP for custom login password reset
// @Description Verifies the OTP sent for custom login password reset
// @Tags Auth
// @Accept json
// @Produce json
// @Param input body object true "OTP verification data"
// @Success 200 {object} object
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/user/forgot-password/verify-otp [post]
func (euc *EndUserController) CustomVerifyPasswordResetOTP(c *gin.Context) {
	var input models.CustomVerifyPasswordResetOTPInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	input.Email = strings.ToLower(input.Email)

	// Verify OTP using the same pattern as tenant controller
	var otpEntry models.OTPEntry
	if err := config.DB.Where("email = ? AND otp = ? AND expires_at > ? AND verified = ?",
		input.Email, input.OTP, time.Now(), false).First(&otpEntry).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired OTP"})
		return
	}

	// Mark OTP as verified
	if err := config.DB.Model(&otpEntry).Update("verified", true).Error; err != nil {
		log.Printf("Failed to mark OTP as verified: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify OTP"})
		return
	}

	log.Printf("Password reset OTP verified for custom login user: %s", input.Email)

	c.JSON(http.StatusOK, models.CustomVerifyPasswordResetOTPResponse{
		Message: "OTP verified successfully. You can now reset your password",
		Email:   input.Email,
	})
}

// CustomResetPassword godoc
// @Summary Reset password for custom login user
// @Description Resets password for custom login user after OTP verification
// @Tags Auth
// @Accept json
// @Produce json
// @Param input body object true "Password reset data"
// @Success 200 {object} object
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/user/forgot-password/reset [post]
func (euc *EndUserController) CustomResetPassword(c *gin.Context) {
	var input models.CustomResetPasswordInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	input.Email = strings.ToLower(input.Email)

	// Validate password strength
	if len(input.NewPassword) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 8 characters long"})
		return
	}

	// Check if OTP was verified (following tenant controller pattern)
	var otpEntry models.OTPEntry
	if err := config.DB.Where("email = ? AND verified = ? AND expires_at > ?",
		input.Email, true, time.Now()).First(&otpEntry).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "OTP not verified or expired. Please request a new OTP"})
		return
	}

	// Workspace comes from explicit workspace_id (set by UI from page-data),
	// ?workspace= query param, or Host header — never from client_id.
	workspaceID, err := shared.ResolveWorkspace(c, input.WorkspaceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("workspace resolution failed: %v", err)})
		return
	}

	// Single-DB collapse: scope password reset lookup by workspace_id explicitly.
	tenantDB := config.DB

	// Find the user in the workspace database
	var user models.User
	if err := tenantDB.Where("workspace_id = ? AND LOWER(email) = ? AND provider IN (?) AND active = ? AND deleted_at IS NULL", workspaceID, input.Email, []string{"custom", "ad_sync", "entra_id", "scim"}, true).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to find user"})
		return
	}

	// Hash the new password using the same method as your existing code
	tempUser := models.ExtendedUser{
		User: sharedmodels.User{
			PasswordHash: input.NewPassword,
		},
	}
	if err := tempUser.HashPassword(); err != nil {
		log.Printf("Failed to hash new password: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process new password"})
		return
	}

	// Begin transaction for password update (following tenant controller pattern)
	tx := config.DB.Begin()
	tenantTx := tenantDB.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			tenantTx.Rollback()
		}
	}()

	// Update user password in tenant database
	if err := tenantTx.Model(&user).Updates(map[string]interface{}{
		"password_hash": tempUser.PasswordHash,
		"updated_at":    time.Now(),
	}).Error; err != nil {
		tx.Rollback()
		tenantTx.Rollback()
		log.Printf("Failed to update user password: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	// Clean up OTP entries (following tenant controller cleanup pattern)
	tx.Where("email = ?", input.Email).Delete(&models.OTPEntry{})

	// Commit both transactions
	if err := tenantTx.Commit().Error; err != nil {
		tx.Rollback()
		log.Printf("Failed to commit tenant transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to complete password reset"})
		return
	}

	if err := tx.Commit().Error; err != nil {
		log.Printf("Failed to commit main transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to complete password reset"})
		return
	}

	log.Printf("Password reset completed successfully for custom login user: %s", input.Email)

	c.JSON(http.StatusOK, models.CustomResetPasswordResponse{
		Message: "Password reset successfully",
		Email:   input.Email,
	})
}

// Helper function to generate and send password reset OTP (reusing existing OTP utilities)
func (euc *EndUserController) generateAndSendCustomPasswordResetOTP(email string) error {
	log.Printf("generateAndSendCustomPasswordResetOTP: starting for %s", email)
	// Check if config.DB is available
	if config.DB == nil {
		log.Printf("generateAndSendCustomPasswordResetOTP: database connection unavailable for %s", email)
		return fmt.Errorf("database connection not available")
	}

	// Generate OTP using existing utility
	otp, err := utils.GenerateOTP()
	if err != nil {
		log.Printf("generateAndSendCustomPasswordResetOTP: failed to generate OTP for %s: %v", email, err)
		return fmt.Errorf("failed to generate OTP: %w", err)
	}

	log.Printf("generateAndSendCustomPasswordResetOTP: generated OTP for %s", email)

	// Delete any existing OTP for this email (following tenant controller pattern)
	if err := config.DB.Where("email = ?", email).Delete(&models.OTPEntry{}).Error; err != nil {
		log.Printf("generateAndSendCustomPasswordResetOTP: warning - failed to delete old OTPs for %s: %v", email, err)
	} else {
		log.Printf("generateAndSendCustomPasswordResetOTP: cleared existing OTPs for %s", email)
	}

	// Create new OTP entry using existing structure
	otpEntry := models.OTPEntry{
		Email:     email,
		OTP:       otp,
		ExpiresAt: time.Now().Add(30 * time.Minute), // OTP expires in 30 minutes
		Verified:  false,
	}

	if err := config.DB.Create(&otpEntry).Error; err != nil {
		log.Printf("generateAndSendCustomPasswordResetOTP: failed to persist OTP for %s: %v", email, err)
		return fmt.Errorf("failed to save password reset OTP: %w", err)
	}

	log.Printf("generateAndSendCustomPasswordResetOTP: stored OTP entry (%s) for %s", otpEntry.ID.String(), email)

	// Send password reset OTP email using modified version of existing function
	if err := utils.SendPasswordResetOTPEmail(email, otp); err != nil {
		// FIX: Don't delete OTP on email failure - the OTP is still valid
		// and the email might still be delivered despite the error
		log.Printf("generateAndSendCustomPasswordResetOTP: failed to send email to %s, but OTP remains valid: %v", email, err)
		return fmt.Errorf("failed to send password reset OTP email: %w", err)
	}

	log.Printf("generateAndSendCustomPasswordResetOTP: password reset OTP email sent successfully to %s", email)

	return nil
}
func (euc *EndUserController) AdminChangeUserPassword(c *gin.Context) {
	var input models.AdminChangePasswordInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	input.Email = strings.ToLower(input.Email)

	// Check if config.DB is available
	if config.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database connection not available"})
		return
	}

	// Validate password strength
	if len(input.NewPassword) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 8 characters long"})
		return
	}

	// Parse tenant ID
	workspaceUUID, err := uuid.Parse(input.WorkspaceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID format"})
		return
	}
	workspaceID := workspaceUUID.String()

	// Get tenant database connection
	tenantDB := config.DB

	// Find the user in tenant database
	var user models.User
	query := tenantDB.Where("workspace_id = ? AND active = ?", workspaceID, true)

	// Search by email or user ID based on what's provided
	if input.Email != "" {
		query = query.Where("email = ? AND provider IN (?)", input.Email, []string{"custom", "ad_sync"})
	} else if input.UserID != "" {
		userUUID, err := uuid.Parse(input.UserID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
			return
		}
		query = query.Where("id = ?", userUUID.String())
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Either email or user_id must be provided"})
		return
	}

	if err := query.First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to find user"})
		return
	}

	// Hash the new password using the same method as your existing code
	tempUser := models.ExtendedUser{
		User: sharedmodels.User{
			PasswordHash: input.NewPassword,
		},
	}
	if err := tempUser.HashPassword(); err != nil {
		log.Printf("Failed to hash new password: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process new password"})
		return
	}

	// Update user password in tenant database
	if err := tenantDB.Model(&user).Updates(map[string]interface{}{
		"password_hash": tempUser.PasswordHash,
		"updated_at":    time.Now(),
	}).Error; err != nil {
		log.Printf("Failed to update user password via admin: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	log.Printf("Admin changed password for user: %s (ID: %s) in tenant: %s", user.Email, user.ID, workspaceID)

	// Audit log: Admin changed user password
	middlewares.Audit(c, "enduser", user.ID.String(), "admin_change_password", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"user_id":      user.ID.String(),
			"email":        user.Email,
			"workspace_id": workspaceID,
		},
	})

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"message":      "User password changed successfully",
		"user_id":      user.ID.String(),
		"email":        user.Email,
		"workspace_id": user.WorkspaceID.String(),
	})
}

// AdminResetUserPassword godoc
// @Summary Admin reset user password to temporary password
// @Description Allows admin to reset user password to a temporary password and optionally send it via email
// @Tags Admin
// @Accept json
// @Produce json
// @Param input body object true "Admin password reset data"
// @Success 200 {object} object
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/user/admin/reset-password [post]
func (euc *EndUserController) AdminResetUserPassword(c *gin.Context) {
	var input models.AdminResetPasswordInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	input.Email = strings.ToLower(input.Email)

	// Check if config.DB is available
	if config.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database connection not available"})
		return
	}

	// Parse tenant ID
	workspaceUUID, err := uuid.Parse(input.WorkspaceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID format"})
		return
	}
	workspaceID := workspaceUUID.String()

	// Get tenant database connection
	tenantDB := config.DB

	// Find the user in tenant database
	var user models.User
	query := tenantDB.Where("workspace_id = ? AND active = ?", workspaceID, true)

	if input.Email != "" {
		query = query.Where("email = ? AND provider IN (?)", input.Email, []string{"custom", "ad_sync"})
	} else if input.UserID != "" {
		userUUID, err := uuid.Parse(input.UserID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
			return
		}
		query = query.Where("id = ?", userUUID.String())
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Either email or user_id must be provided"})
		return
	}

	if err := query.First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to find user"})
		return
	}

	// Generate temporary password
	tempPassword, err := utils.GenerateTemporaryPassword()
	if err != nil {
		log.Printf("Failed to generate temporary password: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate temporary password"})
		return
	}

	// Hash the temporary password
	tempUser := models.ExtendedUser{
		User: sharedmodels.User{
			PasswordHash: tempPassword,
		},
	}
	if err := tempUser.HashPassword(); err != nil {
		log.Printf("Failed to hash temporary password: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process temporary password"})
		return
	}

	// Update user password in tenant database
	if err := tenantDB.Model(&user).Updates(map[string]interface{}{
		"password_hash": tempUser.PasswordHash,
		"updated_at":    time.Now(),
	}).Error; err != nil {
		log.Printf("Failed to reset user password via admin: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset password"})
		return
	}

	// Send temporary password via email if requested
	var emailSent bool
	if input.SendEmail {
		if err := utils.SendTemporaryPasswordEmail(user.Email, tempPassword); err != nil {
			log.Printf("Failed to send temporary password email: %v", err)
			// Don't fail the request, just note that email wasn't sent
			emailSent = false
		} else {
			emailSent = true
		}
	}

	log.Printf("Admin reset password for user: %s (ID: %s) in tenant: %s", user.Email, user.ID, workspaceID)

	// Audit log: Admin reset user password
	middlewares.Audit(c, "enduser", user.ID.String(), "admin_reset_password", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"user_id":      user.ID.String(),
			"email":        user.Email,
			"workspace_id": workspaceID,
			"email_sent":   emailSent,
		},
	})

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"message":      "User password reset successfully",
		"user_id":      user.ID.String(),
		"email":        user.Email,
		"workspace_id": user.WorkspaceID.String(),
		"email_sent":   emailSent,
	})
}

// NotifyOwnerNewRegistration godoc
// @Summary Notify tenant owner about a new user registration
// @Description Sends a notification email to the specified owner email with details of the newly registered user
// @Tags EndUser
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param input body object true "Notification request with owner_email and optional user details"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/auth/notify/new-user-registration [post]
func (euc *EndUserController) NotifyOwnerNewRegistration(c *gin.Context) {
	const ownerEmail = "a@authnull.com"

	var input struct {
		UserName     string `json:"user_name,omitempty"`
		WorkspaceDomain string `json:"workspace_domain,omitempty"`
	}
	// Body is optional — ignore bind errors for empty body
	_ = c.ShouldBindJSON(&input)

	// Extract user email from JWT context
	userEmail := c.GetString("email_id")
	if userEmail == "" {
		userEmail = c.GetString("email")
	}
	if userEmail == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user email not found in authentication token"})
		return
	}

	// Extract tenant ID from JWT context
	workspaceID, ok := middlewares.GetWorkspaceIDFromToken(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id not found in authentication token"})
		return
	}

	// Use provided user_name or fall back to email
	userName := input.UserName
	if userName == "" {
		userName = userEmail
	}

	// Use provided workspace_domain or fall back to tenant ID
	workspaceDomain := input.WorkspaceDomain
	if workspaceDomain == "" {
		workspaceDomain = workspaceID
	}

	if err := utils.SendNewUserRegistrationNotificationEmail(ownerEmail, userName, userEmail, workspaceDomain); err != nil {
		log.Printf("NotifyOwnerNewRegistration: failed to send notification email to %s: %v", ownerEmail, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to send notification email"})
		return
	}

	log.Printf("NotifyOwnerNewRegistration: notification sent to %s for new user %s in tenant %s", ownerEmail, userEmail, workspaceID)

	c.JSON(http.StatusOK, gin.H{
		"message":     "Owner notification email sent successfully",
		"owner_email": ownerEmail,
		"user_email":  userEmail,
	})
}
