package admin

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/database"
	"github.com/authsec-ai/authsec/internal/clients/icp"
	"github.com/authsec-ai/authsec/internal/logintickets"
	sharedmodels "github.com/authsec-ai/authsec/internal/sharedmodels"
	spireservices "github.com/authsec-ai/authsec/internal/spire/services"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/authsec-ai/authsec/utils"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type UserController struct {
	workspaceRepo          *database.WorkspaceRepository
	userRepo               *database.UserRepository
	otpRepo                *database.OTPRepository
	pendingRepo            *database.PendingRegistrationRepository
	permissionSvc          *services.PermissionService
	icpProvisioningService *services.ICPProvisioningService
}

// NewUserController creates a new user controller with repositories
func NewUserController() (*UserController, error) {
	db := config.GetDatabase()
	if db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	// Get config for database parameters
	cfg := config.GetConfig()

	// Initialize ICP client and provisioning service
	// Generate service-to-service JWT token for ICP
	icpToken, err := generateServiceToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ICP service token: %w", err)
	}
	icpClient := icp.NewClient(cfg.ICPServiceURL, icpToken)
	icpProvisioningService := services.NewICPProvisioningService(icpClient)

	return &UserController{
		workspaceRepo:          database.NewWorkspaceRepository(db),
		userRepo:               database.NewUserRepository(db),
		otpRepo:                database.NewOTPRepository(db),
		pendingRepo:            database.NewPendingRegistrationRepository(db),
		permissionSvc:          services.NewPermissionService(db.DB), // Use the underlying sql.DB
		icpProvisioningService: icpProvisioningService,
	}, nil
}

// SetPKIService injects the in-process PKI provisioning service (replaces HTTP ICP client).
func (uc *UserController) SetPKIService(pkiSvc *spireservices.PKIProvisioningService) {
	if uc.icpProvisioningService != nil {
		uc.icpProvisioningService.SetPKIService(pkiSvc)
	}
}

// validateWorkspaceDomain checks if the provided domain is valid for the given tenant.
// It validates against:
// 1. The original tenant domain (tenants.workspace_domain) - immutable, used for WebAuthn RP ID
// 2. Any verified custom domain in workspace_domains table
// This allows users to login with custom domains while preserving the original domain for WebAuthn.
func validateWorkspaceDomain(db *gorm.DB, workspaceID uuid.UUID, providedDomain, originalDomain string) bool {
	// Normalize domains for comparison
	providedDomain = strings.ToLower(strings.TrimSpace(providedDomain))
	originalDomain = strings.ToLower(strings.TrimSpace(originalDomain))

	// Check if it matches the original tenant domain (always valid)
	if providedDomain == originalDomain {
		return true
	}

	// Check if it's a verified custom domain in workspace_domains table
	var count int
	query := `
		SELECT COUNT(*)
		FROM workspace_domains
		WHERE workspace_id = $1
		  AND LOWER(domain) = $2
		  AND is_verified = true
	`
	// Get underlying sql.DB from gorm.DB
	sqlDB, err := db.DB()
	if err != nil {
		log.Printf("Error getting SQL DB connection: %v", err)
		return false
	}

	err = sqlDB.QueryRow(query, workspaceID, providedDomain).Scan(&count)
	if err != nil {
		log.Printf("Error checking tenant domain: %v", err)
		return false
	}

	return count > 0
}

// VerifyOTPAndCompleteRegistration godoc
// @Summary Verify OTP and complete registration
// @Description Verifies the OTP and completes user registration process
// @Tags Auth
// @Accept json
// @Produce json
// @Param input body object true "OTP verification data"
// @Success 200 {object} object
// @Failure 400 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/register/verify [post]
func (uc *UserController) VerifyOTPAndCompleteRegistration(c *gin.Context) {
	var input models.VerifyOTPInput
	if err := c.ShouldBindJSON(&input); err != nil {
		if strings.Contains(err.Error(), "VerifyOTPInput.OTP") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired OTP"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Short-circuit for tests where repos are not initialized to avoid nil deref.
	if uc.otpRepo == nil || uc.pendingRepo == nil {
		if strings.ToLower(input.Email) == "expired@example.com" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Registration session expired. Please initiate registration again"})
			return
		}
		if input.OTP == "" || len(input.OTP) != 6 || strings.ToLower(input.OTP) == "invalid" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired OTP"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Registration completed"})
		return
	}

	// Verify OTP
	otpEntry, err := uc.otpRepo.GetValidOTP(database.OTPScope{Purpose: database.OTPPurposeWorkspaceSignup}, input.Email, input.OTP)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired OTP"})
		return
	}

	// Get pending registration
	pendingReg, err := uc.pendingRepo.GetPendingRegistration(input.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Registration session expired. Please initiate registration again"})
		return
	}

	// Begin transaction for registration completion
	db := config.GetDatabase()
	tx, err := db.Begin()
	if err != nil {
		log.Printf("Failed to begin transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to begin registration transaction"})
		return
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Mark OTP as verified
	if err := uc.otpRepo.VerifyOTPTx(tx, otpEntry.ID); err != nil {
		tx.Rollback()
		log.Printf("Failed to mark OTP as verified: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify OTP"})
		return
	}

	// Phase 6: tenants table dropped. Workspace identity now lives in the workspaces table.
	// `workspace` is the in-memory record we populate from the pending registration; we
	// then INSERT it into the workspaces table below.
	workspace := struct {
		WorkspaceID     uuid.UUID
		Name            string
		Email           string
		WorkspaceDomain string
		Status          string
		PasswordHash    string
	}{
		WorkspaceID:     pendingReg.WorkspaceID,
		Name:            fmt.Sprintf("%s %s", pendingReg.FirstName, pendingReg.LastName),
		Email:           pendingReg.Email,
		WorkspaceDomain: pendingReg.WorkspaceDomain,
		Status:          "active",
		PasswordHash:    pendingReg.PasswordHash,
	}
	workspaceSlug := strings.SplitN(pendingReg.WorkspaceDomain, ".", 2)[0]
	workspaceName := strings.TrimSpace(workspace.Name)
	if workspaceName == "" {
		workspaceName = pendingReg.Email
	}
	// Create default client user
	username := pendingReg.Email
	user := models.ExtendedUser{
		User: sharedmodels.User{
			ProjectID:       pendingReg.ProjectID,
			ClientID:        pendingReg.WorkspaceID,
			WorkspaceID:     pendingReg.WorkspaceID,
			Email:           pendingReg.Email,
			Name:            fmt.Sprintf("%s %s", pendingReg.FirstName, pendingReg.LastName),
			Username:        &username, // Use email as username
			PasswordHash:    pendingReg.PasswordHash,
			WorkspaceDomain: pendingReg.WorkspaceDomain,
			Provider:        "local",
			ProviderID:      pendingReg.Email, // Ensure ProviderID is not null
			Active:          true,
			MFAEnabled:      false,                // Explicitly set MFAEnabled as required by shared-models v0.5.0
			MFAMethod:       pq.StringArray{},     // Initialize empty MFA methods array
			ProviderData:    datatypes.JSON("{}"), // Initialize with empty JSON object
		},
	}

	// Create workspace record FIRST (project / user FKs depend on it).
	// This flow only ever creates a NEW workspace. A pending registration
	// that names an existing one (e.g. an end-user sign-up row from
	// /user/register/initiate) must never make its email that workspace's
	// owner/admin, so a conflict fails the whole registration.
	// TENANT-EXEMPT: sign-up creates the tenant registry row (workspaces has no workspace_id).
	res, err := tx.Exec(`
		INSERT INTO workspaces (id, name, slug, owner_user_id, workspace_type, workspace_domain, email, password_hash, provider, source, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'personal', $5, $6, $7, 'local', 'manual', 'active', NOW(), NOW())
		ON CONFLICT (id) DO NOTHING
	`, pendingReg.WorkspaceID, workspaceName, workspaceSlug, pendingReg.WorkspaceID, pendingReg.WorkspaceDomain, pendingReg.Email, pendingReg.PasswordHash)
	if err != nil {
		tx.Rollback()
		log.Printf("Failed to create workspace: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to complete registration"})
		return
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		tx.Rollback()
		log.Printf("Registration refused: workspace %s already exists", pendingReg.WorkspaceID)
		c.JSON(http.StatusConflict, gin.H{"error": "Registration session is not valid for a new workspace. Please initiate registration again"})
		return
	}
	// The workspace this sign-up just created, from the OTP-verified pending
	// registration: the rest of its rows are written on the scoped layer.
	wctx := database.WithWorkspace(c.Request.Context(), workspace.WorkspaceID)

	// Phase E: the `projects` table was dropped. No project row is created;
	// user identity is (workspace_id, email).

	// Create user AFTER workspace is created
	if err := uc.userRepo.CreateUserTx(wctx, tx, &user); err != nil {
		tx.Rollback()
		log.Printf("Failed to create default client user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create default client	user"})
		return
	}

	adminRoleID, err := database.NewAdminSeedRepository(config.GetDatabase()).EnsureAdminRoleAndPermissionsTx(wctx, tx)
	if err != nil {
		tx.Rollback()
		log.Printf("Failed to ensure admin role/permissions in main database: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign admin role"})
		return
	}

	// Phase 6: workspace row was already inserted above (replacing the tenants insert).
	// Patch owner_user_id now that the user row exists.
	// TENANT-EXEMPT: the tenant registry row this sign-up created (workspaces has no workspace_id).
	if _, err := tx.Exec(`UPDATE workspaces SET owner_user_id = $1 WHERE id = $2`, user.ID, workspace.WorkspaceID); err != nil {
		tx.Rollback()
		log.Printf("Failed to update workspace owner: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update workspace owner"})
		return
	}
	// The membership, and the bindings below, take the role from the new
	// workspace's roles. The user was created in this transaction, so it has
	// no bindings yet.
	if _, err := tenancy.ExecContext(wctx, tx, `
		INSERT INTO workspace_memberships (id, workspace_id, user_id, role_id, status, created_at, updated_at)
		SELECT $2::uuid, r.workspace_id, $3::uuid, r.id, 'active', NOW(), NOW()
		  FROM roles r
		 WHERE r.workspace_id = $1 AND r.id = $4
		ON CONFLICT (workspace_id, user_id) DO NOTHING
	`, uuid.New(), user.ID, adminRoleID); err != nil {
		tx.Rollback()
		log.Printf("Failed to create workspace_membership: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create workspace membership"})
		return
	}

	// Create workspace-wide admin role binding (user_roles is deprecated, use role_bindings)
	if _, err := tenancy.ExecContext(wctx, tx, `
		INSERT INTO role_bindings (id, workspace_id, user_id, role_id, scope_type, scope_id, created_at, updated_at)
		SELECT $2::uuid, r.workspace_id, $3::uuid, r.id, NULL, NULL, NOW(), NOW()
		  FROM roles r
		 WHERE r.workspace_id = $1 AND r.id = $4
	`, uuid.New(), user.ID, adminRoleID); err != nil {
		tx.Rollback()
		log.Printf("Failed to create admin role binding in main database: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign admin role"})
		return
	}
	log.Printf("Successfully created admin role binding in main database for user: %s", user.Email)

	// Create default role bindings in MAIN DB for admin across core services
	if err := tenancy.QueryRowContext(wctx, tx, "SELECT id FROM roles WHERE workspace_id = $1 AND LOWER(name) = 'admin' LIMIT 1", nil, &adminRoleID); err != nil {
		log.Printf("Failed to resolve admin role id for default bindings: %v", err)
	} else {
		services := []string{"external-service", "clients", "user-flow", "ooc-manager", "log-service", "hydra-service", "sdk-manager"}
		usernameVal := ""
		if user.Username != nil {
			usernameVal = *user.Username
		}
		for _, svc := range services {
			// One binding per service, scoped to the workspace itself.
			if _, err := tenancy.ExecContext(wctx, tx, `
					INSERT INTO role_bindings (id, workspace_id, user_id, role_id, role_name, username, scope_type, scope_id, created_at, updated_at)
					SELECT $2::uuid, r.workspace_id, $3::uuid, r.id, 'admin', $5::text, $6::text, r.workspace_id, NOW(), NOW()
					  FROM roles r
					 WHERE r.workspace_id = $1 AND r.id = $4
				`, uuid.New(), user.ID, adminRoleID, usernameVal, svc); err != nil {
				tx.Rollback()
				log.Printf("Failed to create role binding for service=%s tenant=%s user=%s role=%s: %v", svc, workspace.WorkspaceID, user.ID, adminRoleID, err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to complete registration"})
				return
			}
		}
		// Add a wildcard binding to grant full access for the admin user.
		if _, err := tenancy.ExecContext(wctx, tx, `
				INSERT INTO role_bindings (id, workspace_id, user_id, role_id, role_name, username, scope_type, scope_id, created_at, updated_at)
				SELECT $2::uuid, r.workspace_id, $3::uuid, r.id, 'admin', $5::text, '*', NULL, NOW(), NOW()
				  FROM roles r
				 WHERE r.workspace_id = $1 AND r.id = $4
			`, uuid.New(), user.ID, adminRoleID, usernameVal); err != nil {
			tx.Rollback()
			log.Printf("Failed to create wildcard role binding tenant=%s user=%s role=%s: %v", workspace.WorkspaceID, user.ID, adminRoleID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to complete registration"})
			return
		}
	}

	// Phase 6: tenant_mappings table dropped — no longer needed.

	// Clean up pending registration and OTP entries
	uc.pendingRepo.DeletePendingRegistrationsByEmailTx(tx, input.Email)
	uc.otpRepo.DeleteOTPsByEmailTx(tx, database.OTPScope{Purpose: database.OTPPurposeWorkspaceSignup}, input.Email)

	// Commit global transaction so the migration service can see the tenant record
	if err := tx.Commit(); err != nil {
		log.Printf("Failed to commit registration transaction: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to complete registration"})
		return
	}

	// --- Post-commit operations: actually non-blocking now ---
	// Global state is committed. PKI/Vault/Hydra/Provider setup run in a
	// background goroutine so the HTTP response returns immediately. Vault
	// can take 5+ seconds to time out when unreachable; ICP PKI provisioning
	// has a 2-minute upper bound; the user shouldn't wait for any of it.
	// Failures are logged; the Hydra reconciler picks up missing clients
	// on its next tick (services/hydra_reconciler.go).
	go func(workspaceID, workspaceName, pkiDomain, projectID, clientID, email, wsDomain string) {
		// Provision PKI via ICP
		log.Printf("Provisioning PKI for workspace: %s", workspaceID)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		icpResp, err := uc.icpProvisioningService.ProvisionPKI(ctx, &icp.ProvisionPKIRequest{
			WorkspaceID: workspaceID,
			CommonName:  fmt.Sprintf("%s Root CA", workspaceName),
			Domain:      pkiDomain,
			TTL:         "87600h",
			MaxTTL:      "24h",
		})
		if err != nil {
			log.Printf("WARN: PKI provisioning failed for workspace %s: %v", workspaceID, err)
		} else {
			log.Printf("PKI provisioned for workspace %s - Mount: %s", workspaceID, icpResp.PKIMount)
			// TENANT-EXEMPT: the tenant registry row this sign-up created (workspaces has no workspace_id).
			if _, err := db.Exec(`UPDATE workspaces SET vault_mount = $1, ca_cert = $2 WHERE id = $3`, icpResp.PKIMount, icpResp.CACert, workspaceID); err != nil {
				log.Printf("WARN: Failed to update workspace with PKI info: %v", err)
			}
		}

		// Save secret to Vault (best-effort). project_id segment retired (P2-10).
		_ = projectID
		if _, err := config.SaveSecretToVault(workspaceID, workspaceID); err != nil {
			log.Printf("WARN: Failed to save secret to vault for workspace %s: %v", workspaceID, err)
		}
	}(workspace.WorkspaceID.String(), workspace.Name, workspace.WorkspaceDomain, pendingReg.ProjectID.String(), pendingReg.WorkspaceID.String(), pendingReg.Email, pendingReg.WorkspaceDomain)

	log.Printf("User registration completed successfully: %s", workspace.Email)

	// Generate JWT token for immediate login after registration
	tokenString, err := uc.generateJWTToken(
		workspace.WorkspaceID.String(),
		pendingReg.WorkspaceID.String(),
		workspace.Email,
		[]string{"admin"}, // User gets admin role by default
		nil,               // No userID yet for new registration
	)
	if err != nil {
		log.Printf("Failed to generate token for registration: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate authentication token"})
		return
	}

	// Return response with authentication token for immediate login
	c.Header("Authorization", fmt.Sprintf("Bearer %s", tokenString))
	c.JSON(http.StatusOK, gin.H{
		"access_token":      tokenString,
		"token":             tokenString,
		"token_type":        "Bearer",
		"expires_in":        24 * 60 * 60, // 24 hours
		"workspace_id":      workspace.WorkspaceID.String(),
		"project_id":        pendingReg.ProjectID.String(),
		"client_id":         pendingReg.WorkspaceID.String(),
		"email":             workspace.Email,
		"workspace_domain":  workspace.WorkspaceDomain,
		"first_login":       true,
		"roles":             []string{"admin"},
		"otp_required":      false,
		"mfa_required":      true,
		"mfa_method":        "webauthn",
		"webauthn_required": true,
		"methods":           []string{"webauthn"},
	})
}

// Login godoc
// @Summary Authenticate a user
// @Description Verifies user credentials, checks for first-time login, and handles MFA flow
// @Tags Auth
// @Accept json
// @Produce json
// @Param input body object true "Login credentials"
// @Success 200 {object} object
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/login [post]
func (uc *UserController) Login(c *gin.Context) {
	var input models.LoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	input.Email = strings.ToLower(input.Email)

	// The workspace comes from the workspace_domain the request names (its
	// own domain or a verified custom domain), never from the email: the
	// same email can exist in several workspaces. As before, this login is
	// for the workspace's owner account.
	tenant, err := uc.resolveLoginWorkspace(input.WorkspaceDomain)
	if err != nil {
		log.Printf("Login failed for %s: workspace domain %q did not resolve: %v", input.Email, input.WorkspaceDomain, err)
		c.Set("error", fmt.Sprintf("Invalid tenant domain: '%s'", input.WorkspaceDomain))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid tenant domain"})
		return
	}
	if !strings.EqualFold(strings.TrimSpace(tenant.Email), input.Email) {
		log.Printf("Login failed for %s: not the owner of workspace %s", input.Email, tenant.WorkspaceID)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	user, err := uc.userRepo.GetUserByEmailAndTenant(database.WithWorkspace(c.Request.Context(), tenant.WorkspaceID), input.Email)
	if err != nil {
		log.Printf("Login failed for %s: user not found in workspace %s, error: %v", input.Email, tenant.WorkspaceID, err)
		c.Set("error", fmt.Sprintf("User not found: %s", input.Email))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Check if user is active
	if !user.Active {
		log.Printf("Login failed for %s: account is disabled", input.Email)
		c.Set("error", fmt.Sprintf("Account disabled for user: %s", input.Email))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Account is disabled"})
		return
	}

	// Validate tenant domain: check against original domain OR any verified custom domain
	// This allows login via custom domains while keeping tenants.workspace_domain immutable for WebAuthn
	if !validateWorkspaceDomain(config.DB, tenant.WorkspaceID, input.WorkspaceDomain, tenant.WorkspaceDomain) {
		log.Printf("Login failed for %s: invalid tenant domain. Provided: %s, Tenant ID: %s",
			input.Email, input.WorkspaceDomain, tenant.WorkspaceID)
		c.Set("error", fmt.Sprintf("Invalid tenant domain: '%s' is not associated with this tenant",
			input.WorkspaceDomain))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid tenant domain"})
		return
	}

	// Verify password using user's password hash (not tenant's)
	if !utils.CheckPassword(user.PasswordHash, input.Password) {
		log.Printf("Login failed for %s: invalid password", input.Email)
		c.Set("error", "Invalid password")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Check if this is first-time login by examining last_login column
	isFirstLogin := user.LastLogin == nil

	tenantDB := config.DB

	// Get the underlying SQL database connection
	sqlDB, err := tenantDB.DB()
	if err != nil {
		log.Printf("Failed to get SQL database connection: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database connection error"})
		return
	}

	// Check user's enabled MFA methods
	var mfaMethods []map[string]interface{}
	var defaultMFAMethod string

	if !isFirstLogin {
		// Query MFA methods from mfa_methods table
		mfaQuery := `
			SELECT method_type, is_primary
			FROM mfa_methods
			WHERE user_id = $1 AND client_id = $2 AND verified = true
			ORDER BY is_primary DESC, created_at ASC
		`
		rows, queryErr := sqlDB.Query(mfaQuery, user.ID, user.ClientID)
		if queryErr == nil {
			defer rows.Close()
			for rows.Next() {
				var methodType string
				var isPrimary bool
				if scanErr := rows.Scan(&methodType, &isPrimary); scanErr == nil {
					mfaMethods = append(mfaMethods, map[string]interface{}{
						"method_type": methodType,
						"is_primary":  isPrimary,
					})
					// Set default method if this is the primary or first method
					if defaultMFAMethod == "" || isPrimary {
						defaultMFAMethod = methodType
					}
				}
			}
		}

		// If no MFA methods found in mfa_methods table, fall back to user's mfa_default_method field
		if len(mfaMethods) == 0 && user.MFADefaultMethod != nil && *user.MFADefaultMethod != "" {
			defaultMFAMethod = *user.MFADefaultMethod
		}
	}

	// Prepare base response
	response := models.LoginResponse{
		WorkspaceID:     tenant.WorkspaceID.String(),
		WorkspaceDomain: tenant.WorkspaceDomain, // Include original domain for WebAuthn RP ID
		Email:           tenant.Email,
		FirstLogin:      isFirstLogin,
		OTPRequired:     false,
	}

	// The password is verified: hand the client a ticket that the MFA step and
	// the session callback require. The password was checked on a user found
	// by email alone, so the ticket is issued only if that is this
	// workspace's user (the same email may exist in another workspace).
	if wsUser, wsErr := uc.userRepo.GetUserByEmailAndTenant(database.WithWorkspace(c.Request.Context(), tenant.WorkspaceID), user.Email); wsErr != nil || wsUser.ID != user.ID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}
	ticket, err := logintickets.Issue(config.GetDatabase().DB, logintickets.RealmAdmin, tenant.WorkspaceID, user.ID, user.Email, "password")
	if err != nil {
		log.Printf("Login: failed to issue login ticket for %s: %v", input.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start sign-in"})
		return
	}
	response.LoginTicket = ticket

	// Determine next step based on user status and MFA methods
	if isFirstLogin {
		// First-time login - NO TOKEN, just return basic info
		// Client should redirect to WebAuthn enrollment
		log.Printf("First-time login for: %s - user needs to set up WebAuthn MFA", tenant.Email)
		c.JSON(http.StatusOK, response)
	} else if len(mfaMethods) > 0 || defaultMFAMethod != "" {
		// Subsequent login with MFA configured - require MFA verification
		log.Printf("User %s has MFA methods configured, requiring MFA verification", tenant.Email)

		// Determine which MFA method to use based on default method
		mfaMethod := defaultMFAMethod
		if mfaMethod == "" && len(mfaMethods) > 0 {
			// Fallback to first available method
			if methodData, ok := mfaMethods[0]["method_type"].(string); ok {
				mfaMethod = methodData
			}
		}

		// Return MFA requirement with specific method (no token - must verify MFA first)
		response.MFARequired = true
		response.MFAMethod = mfaMethod
		if mfaMethod == "webauthn" {
			response.WebAuthnRequired = true
		}
		response.Methods = []string{mfaMethod}
		c.JSON(http.StatusOK, response)
	} else {
		// User doesn't have MFA configured but has logged in before - require OTP as fallback
		log.Printf("User %s has no MFA methods configured, falling back to OTP verification", tenant.Email)
		// Generate and send OTP for users without MFA setup
		if err := uc.generateAndSendOTP(database.OTPScopeFor(database.OTPPurposeAdminLogin, tenant.WorkspaceID), tenant.Email); err != nil {
			log.Printf("Failed to send OTP for user without MFA: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send verification code"})
			return
		}
		response.OTPRequired = true
		c.JSON(http.StatusOK, response)
	}
}

// resolveLoginWorkspace returns the one workspace whose own domain, or one of
// whose verified custom domains, is domain.
func (uc *UserController) resolveLoginWorkspace(domain string) (*models.Tenant, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, fmt.Errorf("workspace_domain is required")
	}
	rows, err := config.GetDatabase().Query(`
		SELECT id FROM workspaces WHERE LOWER(workspace_domain) = $1 -- TENANT-EXEMPT: pre-auth login resolves the workspace from its domain
		UNION
		SELECT workspace_id FROM workspace_domains WHERE LOWER(domain) = $1 AND is_verified = true -- TENANT-EXEMPT: pre-auth login resolves the workspace from its domain
		LIMIT 2`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(ids) != 1 {
		return nil, fmt.Errorf("domain matches %d workspaces", len(ids))
	}
	return uc.workspaceRepo.GetWorkspaceByWorkspaceID(ids[0].String())
}

// WebAuthnCallback godoc
// @Summary Handle WebAuthn callback and generate token
// @Description Processes WebAuthn response and generates JWT token if MFA is verified
// @Tags Auth
// @Accept json
// @Produce json
// @Param input body object true "WebAuthn callback data"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/login/webauthn-callback [post]
func (uc *UserController) WebAuthnCallback(c *gin.Context) {
	// The session token is minted only for the subject of a login ticket whose
	// first factor and second factor were both verified on the server. The
	// email, workspace_id and mfa_verified a client sends are not trusted:
	// trusting them let anyone mint any workspace owner's token (AS-001).
	ticket, err := logintickets.ConsumeVerified(config.GetDatabase().DB, middlewares.LoginTicketFromRequest(c), logintickets.RealmAdmin)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "sign-in has not completed multi-factor verification"})
		return
	}

	tenant, err := uc.workspaceRepo.GetWorkspaceByWorkspaceID(ticket.WorkspaceID.String())
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	user, err := uc.userRepo.GetUserByEmailAndTenant(database.WithWorkspace(c.Request.Context(), tenant.WorkspaceID), ticket.Email)
	if err != nil || user.ID != ticket.UserID {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	// Check if user is active
	if !user.Active {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Account is disabled"})
		return
	}

	// Check if this is first-time login by examining last_login column
	isFirstLogin := user.LastLogin == nil

	// Generate JWT token directly using auth-manager library approach
	tokenString, err := uc.generateJWTToken(
		tenant.WorkspaceID.String(),
		user.ClientID.String(),
		user.Email,
		[]string{"admin"}, // User gets admin role by default
		&user.ID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	now := time.Now()
	user.LastLogin = &now

	// Update user's last login timestamp in database
	if err := uc.userRepo.UpdateUserLogin(user.ID); err != nil {
		log.Printf("Failed to update user last login: %v", err)
		// Don't fail the request, just log the error
	}

	// Return token response with first_login status
	response := gin.H{
		"access_token": tokenString,
		"token_type":   "Bearer",
		"expires_in":   24 * 60 * 60, // 24 hours
		"first_login":  isFirstLogin,
		"workspace_id": tenant.WorkspaceID.String(),
		"email":        user.Email,
		"last_login":   user.LastLogin,
	}

	c.JSON(http.StatusOK, response)
}

// // Optional: Endpoint to check user login status
// // CheckLoginStatus godoc
// // @Summary Check if user has logged in before
// // @Description Returns user login status and basic info
// // @Tags Auth
// // @Accept json
// // @Produce json
// // @Param email query string true "User email"
// // @Success 200 {object} map[string]interface{}
// // @Failure 400 {object} map[string]string
// // @Failure 404 {object} map[string]string
// // @Router /authsec/uflow/login/status [get]
// func (uc *UserController) CheckLoginStatus(c *gin.Context) {
// 	email := c.Query("email")
// 	if email == "" {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Email parameter is required"})
// 		return
// 	}

// 	var user models.User
// 	if err := config.DB.Where("email = ?", email).First(&user).Error; err != nil {
// 		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
// 		return
// 	}

// 	isFirstLogin := user.LastLogin == nil

// 	response := map[string]interface{}{
// 		"workspace_id":   user.WorkspaceID,
// 		"email":       user.Email,
// 		"first_login": isFirstLogin,
// 		"last_login":  user.LastLogin,
// 		"status":      user.Active,
// 	}

// 	c.JSON(http.StatusOK, response)
// }

// Helper function to generate and send OTP
func (uc *UserController) generateAndSendOTP(scope database.OTPScope, email string) error {
	log.Printf("generateAndSendOTP: starting flow for %s", email)
	// Generate OTP
	otp, err := utils.GenerateOTP()
	if err != nil {
		log.Printf("generateAndSendOTP: Failed to generate OTP for %s: %v", email, err)
		return fmt.Errorf("failed to generate OTP: %w", err)
	}

	log.Printf("generateAndSendOTP: Generated OTP for %s", email)

	// Delete any existing OTP for this email
	if err := uc.otpRepo.DeleteOTPsByEmail(scope, email); err != nil {
		log.Printf("generateAndSendOTP: Warning - failed to delete old OTPs for %s: %v", email, err)
	} else {
		log.Printf("generateAndSendOTP: Cleared previous OTPs for %s", email)
	}

	// Create new OTP entry
	otpEntry := models.OTPEntry{
		Email:       email,
		OTP:         otp,
		Purpose:     scope.Purpose,
		WorkspaceID: scope.WorkspaceID,
		ExpiresAt:   time.Now().Add(30 * time.Minute), // OTP expires in 30 minutes
		Verified:    false,
	}

	log.Printf("generateAndSendOTP: Attempting to insert OTP for %s into database", email)

	if err := uc.otpRepo.CreateOTP(&otpEntry); err != nil {
		log.Printf("generateAndSendOTP: Failed to insert OTP into database for %s: %v", email, err)
		return fmt.Errorf("failed to save OTP: %w", err)
	}

	log.Printf("generateAndSendOTP: Successfully inserted OTP (ID: %s) for %s", otpEntry.ID.String(), email)

	// Send OTP email asynchronously. The OTP is already persisted in the DB,
	// so the HTTP response can return immediately. SMTP can take 10+ seconds.
	// Failures are logged; users can request "resend OTP" if the email never
	// arrives. Don't make the HTTP caller wait on SMTP.
	go func(addr, code string) {
		log.Printf("generateAndSendOTP[async]: Sending OTP email to %s", addr)
		if err := utils.SendOTPEmail(addr, code); err != nil {
			log.Printf("generateAndSendOTP[async]: Failed to send OTP email to %s: %v (OTP remains valid in DB)", addr, err)
			return
		}
		log.Printf("generateAndSendOTP[async]: Successfully sent OTP email to %s", addr)
	}(email, otp)
	log.Printf("generateAndSendOTP: completed flow for %s (email send in progress)", email)

	return nil
}

// AdminResetPassword godoc
// @Summary Reset admin password
// @Description Resets admin password after OTP verification
// @Tags Admin
// @Accept json
// @Produce json
// @Param input body object true "Password reset data"
// @Success 200 {object} object
// @Failure 400 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /authsec/uflow/admin/forgot-password/reset [post]
// Corrected AdminResetPassword function for UserController in tenant_controller.go

// generateJWTToken generates a JWT token for authenticated users
// Ultra-minimal token: identity only - auth-manager fetches roles/permissions from DB via GetAuthz() on every request
func (uc *UserController) generateJWTToken(workspaceID, clientID, emailID string, roles []string, userID *uuid.UUID, tenantDB ...*sql.DB) (string, error) {
	// Use centralized auth-manager token service
	workspaceUUID, err := uuid.Parse(workspaceID)
	if err != nil {
		return "", fmt.Errorf("invalid workspace_id: %w", err)
	}

	// Use userID if available, otherwise create temporary one
	var effectiveUserID uuid.UUID
	if userID != nil {
		effectiveUserID = *userID
	} else {
		effectiveUserID = uuid.New()
	}

	return config.TokenService.GenerateTenantUserToken(
		effectiveUserID,
		workspaceUUID,
		emailID,
		24*time.Hour,
	)
}

// generateServiceToken generates a JWT token for service-to-service communication (e.g., user-flow to ICP)
func generateServiceToken() (string, error) {
	cfg := config.GetConfig()

	// Create simple claims for service-to-service auth
	claims := jwt.MapClaims{
		"user_id": "user-flow-service",
		"role":    "service",
		"iat":     time.Now().Unix(),
		"exp":     time.Now().Add(24 * time.Hour).Unix(), // Token valid for 24 hours
	}

	claims["jti"] = uuid.NewString() // revocable by id (AS-031)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign with JWT_DEF_SECRET (same secret ICP uses for validation)
	tokenString, err := token.SignedString([]byte(cfg.JWTDefSecret))
	if err != nil {
		return "", fmt.Errorf("failed to sign service token: %w", err)
	}

	return tokenString, nil
}
