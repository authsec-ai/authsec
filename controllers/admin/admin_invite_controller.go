package admin

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/controllers/shared"
	"github.com/authsec-ai/authsec/database"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// AdminInviteController handles admin user invitation
type AdminInviteController struct {
	adminUserRepo *database.AdminUserRepository
}

// NewAdminInviteController creates a new admin invite controller
func NewAdminInviteController() (*AdminInviteController, error) {
	db := config.GetDatabase()
	if db == nil {
		return nil, nil
	}

	return &AdminInviteController{
		adminUserRepo: database.NewAdminUserRepository(db),
	}, nil
}

// InviteAdminRequest represents the request body for inviting an admin
type InviteAdminRequest struct {
	Email        string `json:"email" binding:"required,email"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
	Username     string `json:"username" binding:"required"`
	ClientID     string `json:"client_id"`
	WorkspaceID     string `json:"workspace_id"`
	ProjectID    string `json:"project_id"`
	WorkspaceDomain string `json:"workspace_domain"`
}

// InviteAdminResponse represents the response after inviting an admin
type InviteAdminResponse struct {
	Message           string              `json:"message"`
	UserID            string              `json:"user_id"`
	Email             string              `json:"email"`
	Username          string              `json:"username"`
	TemporaryPassword string              `json:"temporary_password"`
	ExpiresAt         string              `json:"expires_at"`
	EmailSent         bool                `json:"email_sent"`
	User              *InvitedUserPayload `json:"user,omitempty"`
}

// InvitedUserPayload is a sanitized view of the invited admin.
type InvitedUserPayload struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	Username     string `json:"username"`
	ClientID     string `json:"client_id,omitempty"`
	WorkspaceID     string `json:"workspace_id,omitempty"`
	ProjectID    string `json:"project_id,omitempty"`
	WorkspaceDomain string `json:"workspace_domain,omitempty"`
}

// generateTemporaryPassword generates a secure random password with proper entropy
func generateTemporaryPassword(length int) (string, error) {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	password := make([]byte, length)
	for i := range password {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random character: %w", err)
		}
		password[i] = chars[n.Int64()]
	}
	return string(password), nil
}

// InviteAdmin creates a new admin user with a temporary password
// @Summary Invite a new admin user
// @Description Create a new admin user with a temporary password that must be changed on first login
// @Tags Admin
// @Accept json
// @Produce json
// @Param request body InviteAdminRequest true "Admin invitation details"
// @Success 201 {object} InviteAdminResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 409 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /authsec/uflow/admin/invite [post]
func (aic *AdminInviteController) InviteAdmin(c *gin.Context) {
	var req InviteAdminRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("User-flow: error binding JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// The invitee always joins the inviter's workspace, taken from the
	// verified token; a body workspace_id is ignored. An omitted one used to
	// create a user with no workspace at all.
	tc, err := tenancy.From(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace context required"})
		return
	}
	workspaceUUID := tc.WorkspaceID
	workspaceIDFromToken := workspaceUUID.String()
	ctx := c.Request.Context()

	// Check if user with this email already exists IN THIS TENANT (tenant-scoped check)
	// This respects the new composite UNIQUE constraint (email, workspace_id)
	u, err := aic.adminUserRepo.GetAdminUserByEmailAndTenant(ctx, req.Email)
	if err == nil && u != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "User with this email already exists in this tenant"})
		return
	} else if err != nil && err != sql.ErrNoRows {
		log.Printf("User-flow:ERROR: Failed to check user existence: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check user existence"})
		return
	}

	// Check if username already exists in this workspace
	db := config.GetDatabase()
	var existingUsername string
	err = tenancy.QueryRowContext(ctx, db.DB, `
		SELECT username FROM users
		WHERE workspace_id = $1 AND username = $2 LIMIT 1`, []interface{}{req.Username}, &existingUsername)
	if err == nil {
		// Reactivate the user as a side-effect — log on failure but still surface
		// the 409 conflict so the inviter knows the username is taken.
		if _, reactivateErr := tenancy.ExecContext(ctx, db.DB, `
			UPDATE users SET active = true
			WHERE workspace_id = $1 AND username = $2`, req.Username); reactivateErr != nil {
			log.Printf("WARN: AdminInvite reactivate failed for username=%s workspace=%s: %v", req.Username, workspaceUUID, reactivateErr)
		}
		c.JSON(http.StatusConflict, gin.H{"error": "User with this username already exists in this workspace"})
		return
	}

	// Generate temporary password (20 characters)
	temporaryPassword, err := generateTemporaryPassword(20)
	if err != nil {
		log.Printf("User-flow: failed to generate temporary password: %v", err)

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate temporary password"})
		return
	}

	// Set expiration to 7 days from now
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	fullName := strings.TrimSpace(strings.TrimSpace(req.FirstName + " " + req.LastName))
	if fullName == "" {
		fullName = req.Username
	}
	if fullName == "" {
		fullName = req.Email
	}

	var clientIDPtr *uuid.UUID
	if strings.TrimSpace(req.ClientID) != "" {
		clientUUID, parseErr := uuid.Parse(req.ClientID)
		if parseErr != nil {
			log.Printf("User-flow: invalid client_id format: %v", parseErr)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid client_id format"})
			return
		}
		clientIDPtr = &clientUUID
	}

	workspaceIDPtr := &workspaceUUID

	var projectIDPtr *uuid.UUID
	if strings.TrimSpace(req.ProjectID) != "" {
		projectUUID, parseErr := uuid.Parse(req.ProjectID)
		if parseErr != nil {
			log.Printf("User-flow: invalid project_id format: %v", parseErr)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid project_id format"})
			return
		}
		projectIDPtr = &projectUUID
	}

	// Create new admin user
	adminUser := models.AdminUser{
		Email:                      req.Email,
		Username:                   req.Username,
		Name:                       fullName,
		Password:                   temporaryPassword,
		Provider:                   "local",
		Active:                     true,
		TemporaryPassword:          true,
		TemporaryPasswordExpiresAt: &expiresAt,
		CreatedAt:                  time.Now(),
		UpdatedAt:                  time.Now(),
		ClientID:                   clientIDPtr,
		WorkspaceID:                   workspaceIDPtr,
		ProjectID:                  projectIDPtr,
		WorkspaceDomain:               strings.TrimSpace(req.WorkspaceDomain),
	}

	// Hash the password
	if err := adminUser.HashPassword(); err != nil {
		log.Printf("User-flow: failed to hash password: %v", err)

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Save to database using repository
	if err := aic.adminUserRepo.CreateAdminUser(ctx, &adminUser); err != nil {
		log.Printf("User-flow: failed to create admin user: %v", err)

		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create admin user: " + err.Error()})
		return
	}

	// CreateAdminUser bound the user to the workspace's admin role
	// (role_bindings). The same users row is the invitee's end-user account:
	// admin and end users share one table, scoped by workspace_id.
	//
	// Bind to workspace_memberships (RequireWorkspaceRole checks this), with
	// the workspace's admin role; the role must be the caller's workspace's.
	if roleID, err := database.NewAdminSeedRepository(config.GetDatabase()).EnsureAdminRoleAndPermissions(ctx); err != nil {
		log.Printf("User-flow:ERROR: Failed to ensure admin role/perms for invited admin: %v", err)
	} else if _, err := tenancy.ExecContext(ctx, db.DB, `
		INSERT INTO workspace_memberships (id, workspace_id, user_id, role_id, status, source, created_at, updated_at)
		SELECT $2::uuid, r.workspace_id, $3::uuid, r.id, 'active', 'invite', NOW(), NOW()
		  FROM roles r
		 WHERE r.workspace_id = $1 AND r.id = $4
		ON CONFLICT (workspace_id, user_id) DO NOTHING
	`, uuid.New(), adminUser.ID, roleID); err != nil {
		log.Printf("User-flow:ERROR: Failed to create workspace_membership for invited admin: %v", err)
	}

	emailSent := false
	if err := utils.SendAdminInviteEmail(adminUser.Email, adminUser.Username, adminUser.WorkspaceDomain, temporaryPassword); err != nil {
		log.Printf("User-flow: failed to send admin invite email to %s: %v", adminUser.Email, err)
	} else {
		emailSent = true
	}

	responseMessage := "Admin user invited successfully. Please send the temporary password securely."
	if emailSent {
		responseMessage = "Admin user invited successfully. Temporary password emailed to the recipient."
	}

	// Audit log: Admin user invited
	middlewares.Audit(c, "admin_user", adminUser.ID.String(), "invite", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"email":      adminUser.Email,
			"username":   adminUser.Username,
			"name":       adminUser.Name,
			"workspace_id":  workspaceIDFromToken,
			"email_sent": emailSent,
		},
	})

	c.JSON(http.StatusCreated, InviteAdminResponse{
		Message:           responseMessage,
		UserID:            adminUser.ID.String(),
		Email:             adminUser.Email,
		Username:          adminUser.Username,
		TemporaryPassword: temporaryPassword,
		ExpiresAt:         expiresAt.Format(time.RFC3339),
		EmailSent:         emailSent,
		User: &InvitedUserPayload{
			ID:           adminUser.ID.String(),
			Email:        adminUser.Email,
			Username:     adminUser.Username,
			ClientID:     uuidOrEmpty(adminUser.ClientID),
			WorkspaceID:     uuidOrEmpty(adminUser.WorkspaceID),
			ProjectID:    uuidOrEmpty(adminUser.ProjectID),
			WorkspaceDomain: adminUser.WorkspaceDomain,
		},
	})
}

func uuidOrEmpty(id *uuid.UUID) string {
	if id == nil || *id == uuid.Nil {
		return ""
	}
	return id.String()
}

// CancelInviteRequest represents the request body for canceling an invite
type CancelInviteRequest struct {
	UserID string `json:"user_id" binding:"required"`
}

// CancelInviteResponse represents the response after canceling an invite
type CancelInviteResponse struct {
	Message string `json:"message"`
	UserID  string `json:"user_id"`
	Email   string `json:"email"`
}

// CancelInvite cancels a pending admin invitation by deleting the user
// @Summary Cancel a pending admin invitation
// @Description Cancel a pending admin invitation. Only works for users who have not yet logged in (temporary_password=true and last_login is null)
// @Tags Admin - Invitations
// @Accept json
// @Produce json
// @Param request body CancelInviteRequest true "Cancel invitation request"
// @Success 200 {object} CancelInviteResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /authsec/uflow/admin/invite/cancel [post]
func (aic *AdminInviteController) CancelInvite(c *gin.Context) {
	var req CancelInviteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("User-flow: error binding JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userUUID, err := uuid.Parse(req.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user_id format"})
		return
	}

	// The invite must belong to the caller's workspace; another workspace's
	// user does not exist here (404).
	user, ok := aic.loadInvitee(c, userUUID)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	ws, err := tenancy.Workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace context required"})
		return
	}

	// Verify this is a pending invite (temporary_password=true and never logged in)
	if !user.TemporaryPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User has already accepted the invitation and set their password"})
		return
	}

	if user.LastLogin != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User has already logged in. Use deactivate instead."})
		return
	}

	// Delete the user (hard delete since they never used the account)
	db := config.GetDatabase()
	if db == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database not available"})
		return
	}
	// One row-level security transaction for the caller's workspace; every
	// statement binds workspace_id = $1.
	err = tenancy.WithTx(ctx, db.DB, ws, func(tx *sql.Tx) error {
		if _, err := tenancy.ExecContext(ctx, tx, `DELETE FROM role_bindings WHERE workspace_id = $1 AND user_id = $2`, userUUID); err != nil {
			return err
		}
		if _, err := tenancy.ExecContext(ctx, tx, `DELETE FROM workspace_memberships WHERE workspace_id = $1 AND user_id = $2`, userUUID); err != nil {
			return err
		}
		_, err := tenancy.ExecContext(ctx, tx, `DELETE FROM users WHERE workspace_id = $1 AND id = $2`, userUUID)
		return err
	})
	if err != nil {
		log.Printf("User-flow: failed to cancel invite for %s: %v", userUUID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to cancel invitation"})
		return
	}

	// Audit log
	middlewares.Audit(c, "admin_user", userUUID.String(), "invite_cancelled", &middlewares.AuditChanges{
		Before: map[string]interface{}{
			"email":    user.Email,
			"username": user.Username,
		},
		After: map[string]interface{}{
			"deleted": true,
		},
	})

	c.JSON(http.StatusOK, CancelInviteResponse{
		Message: "Invitation cancelled successfully",
		UserID:  userUUID.String(),
		Email:   user.Email,
	})
}

// loadInvitee loads an invited admin of the request's workspace. It answers
// 404 itself when there is none, including another workspace's user.
func (aic *AdminInviteController) loadInvitee(c *gin.Context, userID uuid.UUID) (*models.AdminUser, bool) {
	user, err := aic.adminUserRepo.GetAdminUserInWorkspace(c.Request.Context(), userID)
	if err != nil {
		if shared.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return nil, false
		}
		log.Printf("User-flow: failed to get admin user %s: %v", userID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load user"})
		return nil, false
	}
	return user, true
}

// ResendInviteRequest represents the request body for resending an invite
type ResendInviteRequest struct {
	UserID string `json:"user_id" binding:"required"`
}

// ResendInviteResponse represents the response after resending an invite.
// The temporary password is never returned in the response — it travels only via email.
type ResendInviteResponse struct {
	Message   string `json:"message"`
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	ExpiresAt string `json:"expires_at"`
	EmailSent bool   `json:"email_sent"`
}

// ResendInvite resends the invitation email with a new temporary password
// @Summary Resend admin invitation email
// @Description Resend the invitation email to a pending admin with a new temporary password. Only works for users who haven't logged in yet.
// @Tags Admin - Invitations
// @Accept json
// @Produce json
// @Param request body ResendInviteRequest true "Resend invitation request"
// @Success 200 {object} ResendInviteResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /authsec/uflow/admin/invite/resend [post]
func (aic *AdminInviteController) ResendInvite(c *gin.Context) {
	var req ResendInviteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("User-flow: error binding JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userUUID, err := uuid.Parse(req.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user_id format"})
		return
	}

	// The invite must belong to the caller's workspace; another workspace's
	// user does not exist here (404).
	user, ok := aic.loadInvitee(c, userUUID)
	if !ok {
		return
	}
	ctx := c.Request.Context()

	// Verify this is a pending invite
	if !user.TemporaryPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User has already accepted the invitation and set their password"})
		return
	}

	if user.LastLogin != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User has already logged in. They should use 'forgot password' instead."})
		return
	}

	// Generate new temporary password
	newTempPassword, err := generateTemporaryPassword(20)
	if err != nil {
		log.Printf("User-flow: failed to generate temporary password: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate temporary password"})
		return
	}

	// Set new expiration to 7 days from now
	newExpiresAt := time.Now().Add(7 * 24 * time.Hour)

	// Hash the new password
	user.Password = newTempPassword
	if err := user.HashPassword(); err != nil {
		log.Printf("User-flow: failed to hash password: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Update the user in database
	err = aic.adminUserRepo.UpdateAdminUserInWorkspace(ctx, userUUID, map[string]interface{}{
		"password_hash":                 user.PasswordHash,
		"temporary_password_expires_at": newExpiresAt,
	})
	if err != nil {
		log.Printf("User-flow: failed to update user password: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update invitation"})
		return
	}

	// Send the invitation email
	emailSent := false
	if err := utils.SendAdminInviteEmail(user.Email, user.Username, user.WorkspaceDomain, newTempPassword); err != nil {
		log.Printf("User-flow: failed to send admin invite email to %s: %v", user.Email, err)
	} else {
		emailSent = true
	}

	// Audit log
	middlewares.Audit(c, "admin_user", userUUID.String(), "invite_resent", &middlewares.AuditChanges{
		Before: map[string]interface{}{
			"email": user.Email,
		},
		After: map[string]interface{}{
			"email_sent":  emailSent,
			"new_expires": newExpiresAt.Format(time.RFC3339),
		},
	})

	responseMessage := "Invitation resent. Please send the new temporary password securely."
	if emailSent {
		responseMessage = "Invitation resent successfully. New temporary password emailed to the recipient."
	}

	c.JSON(http.StatusOK, ResendInviteResponse{
		Message:   responseMessage,
		UserID:    userUUID.String(),
		Email:     user.Email,
		ExpiresAt: newExpiresAt.Format(time.RFC3339),
		EmailSent: emailSent,
	})
}

// PendingInvite represents a pending admin invitation
type PendingInvite struct {
	UserID       string  `json:"user_id"`
	Email        string  `json:"email"`
	Username     string  `json:"username"`
	Name         string  `json:"name"`
	WorkspaceDomain string  `json:"workspace_domain,omitempty"`
	ExpiresAt    *string `json:"expires_at,omitempty"`
	IsExpired    bool    `json:"is_expired"`
	CreatedAt    string  `json:"created_at"`
}

// ListPendingInvitesResponse represents the response for listing pending invites
type ListPendingInvitesResponse struct {
	Invites []PendingInvite `json:"invites"`
	Total   int             `json:"total"`
}

// ListPendingInvites returns all pending admin invitations for the tenant
// @Summary List pending admin invitations
// @Description Get all pending admin invitations (users with temporary_password=true who haven't logged in)
// @Tags Admin - Invitations
// @Accept json
// @Produce json
// @Success 200 {object} ListPendingInvitesResponse
// @Failure 500 {object} map[string]interface{}
// @Router /authsec/uflow/admin/invite/pending [get]
func (aic *AdminInviteController) ListPendingInvites(c *gin.Context) {
	db := config.GetDatabase()
	if db == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database not available"})
		return
	}

	// Pending invites of the caller's workspace only. With no workspace in
	// the request this used to list every workspace's invites.
	query := `
		SELECT id, email, username, name, workspace_domain, temporary_password_expires_at, created_at
		FROM users
		WHERE workspace_id = $1
		  AND temporary_password = true
		  AND last_login IS NULL
		ORDER BY created_at DESC
	`

	rows, err := tenancy.Query(c, db.DB, query)
	if err != nil {
		log.Printf("User-flow: failed to query pending invites: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve pending invitations"})
		return
	}
	defer rows.Close()

	invites := []PendingInvite{}
	now := time.Now()

	for rows.Next() {
		var (
			id           uuid.UUID
			email        string
			username     string
			name         sql.NullString
			workspaceDomain sql.NullString
			expiresAt    sql.NullTime
			createdAt    time.Time
		)

		if err := rows.Scan(&id, &email, &username, &name, &workspaceDomain, &expiresAt, &createdAt); err != nil {
			log.Printf("User-flow: failed to scan pending invite row: %v", err)
			continue
		}

		invite := PendingInvite{
			UserID:    id.String(),
			Email:     email,
			Username:  username,
			CreatedAt: createdAt.Format(time.RFC3339),
		}

		if name.Valid {
			invite.Name = name.String
		}
		if workspaceDomain.Valid {
			invite.WorkspaceDomain = workspaceDomain.String
		}
		if expiresAt.Valid {
			expStr := expiresAt.Time.Format(time.RFC3339)
			invite.ExpiresAt = &expStr
			invite.IsExpired = expiresAt.Time.Before(now)
		}

		invites = append(invites, invite)
	}

	c.JSON(http.StatusOK, ListPendingInvitesResponse{
		Invites: invites,
		Total:   len(invites),
	})
}
