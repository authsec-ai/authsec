package admin

import (
	"errors"
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/controllers/shared"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ServiceAccountsController manages service account CRUD under a workspace.
type ServiceAccountsController struct{}

func NewServiceAccountsController() *ServiceAccountsController {
	return &ServiceAccountsController{}
}

// ── request / response types ──────────────────────────────────────────────────

type CreateServiceAccountRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
	// OwnerEmail is the accountable human for this agent/service account (D1:
	// "owner always"). Required — every agent must have an accountable owner so
	// an autonomous action can never lack a human to attribute it to.
	OwnerEmail string `json:"owner_email" binding:"required,email"`
	OwnerTeam  string `json:"owner_team"`
}

type UpdateServiceAccountRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type ServiceAccountResponse struct {
	ID              string  `json:"id"`
	WorkspaceID     string  `json:"workspace_id"`
	Name            string  `json:"name"`
	Description     string  `json:"description"`
	Status          string  `json:"status"`
	OAuthClientID   *string `json:"oauth_client_id,omitempty"`
	SpiffeID        *string `json:"spiffe_id,omitempty"`
	ExternalSubject *string `json:"external_subject,omitempty"`
	OwnerEmail      *string `json:"owner_email,omitempty"`
	OwnerTeam       *string `json:"owner_team,omitempty"`
	LastSeenAt      *string `json:"last_seen_at,omitempty"`
	CreatedAt       string  `json:"created_at"`
	UpdatedAt       string  `json:"updated_at"`
}

func saToResponse(sa models.ServiceAccount) ServiceAccountResponse {
	r := ServiceAccountResponse{
		ID:              sa.ID.String(),
		WorkspaceID:     sa.WorkspaceID.String(),
		Name:            sa.Name,
		Description:     sa.Description,
		Status:          sa.Status,
		SpiffeID:        sa.SpiffeID,
		ExternalSubject: sa.ExternalSubject,
		OwnerEmail:      sa.OwnerEmail,
		OwnerTeam:       sa.OwnerTeam,
		CreatedAt:       sa.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:       sa.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if sa.OAuthClientID != nil {
		s := sa.OAuthClientID.String()
		r.OAuthClientID = &s
	}
	if sa.LastSeenAt != nil {
		s := sa.LastSeenAt.UTC().Format(time.RFC3339)
		r.LastSeenAt = &s
	}
	return r
}

// ── handlers ──────────────────────────────────────────────────────────────────

// CreateServiceAccount godoc
// @Summary Create service account
// @Tags Service Accounts
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param input body CreateServiceAccountRequest true "Service account payload"
// @Success 201 {object} ServiceAccountResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /uflow/admin/service-accounts [post]
func (ctrl *ServiceAccountsController) CreateServiceAccount(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromTokenPtr(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	var req CreateServiceAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	sa, err := services.NewServiceAccountService(config.DB).CreateServiceAccount(*workspaceID, req.Name, req.Description, req.OwnerEmail, req.OwnerTeam)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	middlewares.Audit(c, "service_account", sa.ID.String(), "create", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"name":         sa.Name,
			"description":  sa.Description,
			"workspace_id": sa.WorkspaceID.String(),
		},
	})

	c.JSON(http.StatusCreated, saToResponse(*sa))
}

// ListServiceAccounts godoc
// @Summary List service accounts
// @Tags Service Accounts
// @Produce json
// @Security BearerAuth
// @Success 200 {array} ServiceAccountResponse
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /uflow/admin/service-accounts [get]
func (ctrl *ServiceAccountsController) ListServiceAccounts(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromTokenPtr(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	var sas []models.ServiceAccount
	if err := config.DB.Session(&gorm.Session{NewDB: true}).
		Where("workspace_id = ?", workspaceID).
		Order("created_at DESC").
		Find(&sas).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list service accounts: " + err.Error()})
		return
	}

	resp := make([]ServiceAccountResponse, 0, len(sas))
	for _, sa := range sas {
		resp = append(resp, saToResponse(sa))
	}
	c.JSON(http.StatusOK, resp)
}

// GetServiceAccount godoc
// @Summary Get service account
// @Tags Service Accounts
// @Produce json
// @Security BearerAuth
// @Param sa_id path string true "Service account ID"
// @Success 200 {object} ServiceAccountResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /uflow/admin/service-accounts/{sa_id} [get]
func (ctrl *ServiceAccountsController) GetServiceAccount(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromTokenPtr(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	saID, err := uuid.Parse(c.Param("sa_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid sa_id"})
		return
	}

	var sa models.ServiceAccount
	if err := config.DB.Session(&gorm.Session{NewDB: true}).
		Where("workspace_id = ? AND id = ?", workspaceID, saID).
		First(&sa).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "service account not found"})
		return
	}

	c.JSON(http.StatusOK, saToResponse(sa))
}

// UpdateServiceAccount godoc
// @Summary Update service account
// @Tags Service Accounts
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param sa_id path string true "Service account ID"
// @Param input body UpdateServiceAccountRequest true "Update payload"
// @Success 200 {object} ServiceAccountResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /uflow/admin/service-accounts/{sa_id} [put]
func (ctrl *ServiceAccountsController) UpdateServiceAccount(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromTokenPtr(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	saID, err := uuid.Parse(c.Param("sa_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid sa_id"})
		return
	}

	var req UpdateServiceAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	db := config.DB.Session(&gorm.Session{NewDB: true})

	updates := map[string]interface{}{"updated_at": time.Now().UTC()}
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.Description != "" {
		updates["description"] = req.Description
	}

	res := db.Model(&models.ServiceAccount{}).
		Where("workspace_id = ? AND id = ?", workspaceID, saID).
		Updates(updates)
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update: " + res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "service account not found"})
		return
	}

	var sa models.ServiceAccount
	db.Where("workspace_id = ? AND id = ?", workspaceID, saID).First(&sa)

	middlewares.Audit(c, "service_account", saID.String(), "update", &middlewares.AuditChanges{
		After: map[string]interface{}{"name": sa.Name, "description": sa.Description},
	})

	c.JSON(http.StatusOK, saToResponse(sa))
}

// DeleteServiceAccount godoc
// @Summary Delete service account
// @Tags Service Accounts
// @Produce json
// @Security BearerAuth
// @Param sa_id path string true "Service account ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /uflow/admin/service-accounts/{sa_id} [delete]
func (ctrl *ServiceAccountsController) DeleteServiceAccount(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromTokenPtr(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	saID, err := uuid.Parse(c.Param("sa_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid sa_id"})
		return
	}

	res := config.DB.Session(&gorm.Session{NewDB: true}).
		Where("workspace_id = ? AND id = ?", workspaceID, saID).
		Delete(&models.ServiceAccount{})
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete: " + res.Error.Error()})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "service account not found"})
		return
	}

	middlewares.Audit(c, "service_account", saID.String(), "delete", &middlewares.AuditChanges{
		Before: map[string]interface{}{"id": saID.String(), "workspace_id": workspaceID.String()},
		After:  nil,
	})

	c.JSON(http.StatusOK, gin.H{"message": "service account deleted", "id": saID.String()})
}

// ── Credential provisioning ───────────────────────────────────────────────────

// CredentialRequest is the request body for POST /admin/service-accounts/:sa_id/credentials.
// Exactly one of jwks_uri/jwks (private_key_jwt) or use_client_secret (client_secret_basic)
// must be provided.
type CredentialRequest struct {
	// JWKSUri registers a remote JWKS endpoint for private_key_jwt auth.
	JWKSUri *string `json:"jwks_uri"`
	// JWKS is an inline JWKS JSON document for private_key_jwt auth.
	JWKS *string `json:"jwks"`
	// UseClientSecret provisions a shared secret instead (client_secret_basic).
	// The plaintext is returned once and never stored.
	UseClientSecret bool `json:"use_client_secret"`
}

// CredentialResponse is the response for POST /admin/service-accounts/:sa_id/credentials.
type CredentialResponse struct {
	ClientID     string  `json:"client_id"`
	AuthMethod   string  `json:"token_endpoint_auth_method"`
	ClientSecret *string `json:"client_secret,omitempty"` // shown once for client_secret_basic
}

// CredentialServiceAccount godoc
// @Summary Provision credentials for a service account (confidential client)
// @Tags Service Accounts
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param sa_id path string true "Service account ID"
// @Param input body CredentialRequest true "Credential payload"
// @Success 201 {object} CredentialResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /uflow/admin/service-accounts/{sa_id}/credentials [post]
func (ctrl *ServiceAccountsController) CredentialServiceAccount(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromTokenPtr(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	saID, err := uuid.Parse(c.Param("sa_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid sa_id"})
		return
	}

	var req CredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	cred, err := services.NewServiceAccountService(config.DB).ProvisionCredential(
		*workspaceID, saID, services.CredentialOptions{
			JWKSUri:         req.JWKSUri,
			JWKS:            req.JWKS,
			UseClientSecret: req.UseClientSecret,
		})
	if err != nil {
		switch {
		case errors.Is(err, services.ErrServiceAccountNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		case errors.Is(err, services.ErrCredentialTypeMissing),
			errors.Is(err, services.ErrCredentialTypeAmbiguous),
			errors.Is(err, services.ErrServiceAccountHasCredential):
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	middlewares.Audit(c, "service_account", saID.String(), "credential_provisioned", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"client_id":   cred.ClientID,
			"auth_method": cred.AuthMethod,
		},
	})

	c.JSON(http.StatusCreated, CredentialResponse{
		ClientID:     cred.ClientID,
		AuthMethod:   cred.AuthMethod,
		ClientSecret: cred.Secret,
	})
}

// RotateCredentialServiceAccount handles
// POST /uflow/admin/service-accounts/:sa_id/credentials/rotate — mints a fresh
// client secret for the SA's existing credential client and revokes the old
// one(s). The client_id is unchanged, so assignments/role bindings survive; the
// new plaintext is returned once. Recovers a lost/leaked/fumbled secret without
// deleting the service account.
func (ctrl *ServiceAccountsController) RotateCredentialServiceAccount(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromTokenPtr(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	saID, err := uuid.Parse(c.Param("sa_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid sa_id"})
		return
	}

	cred, err := services.NewServiceAccountService(config.DB).RotateCredentialSecret(*workspaceID, saID)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrServiceAccountNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		case errors.Is(err, services.ErrServiceAccountNoSecretCredential):
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	middlewares.Audit(c, "service_account", saID.String(), "credential_rotated", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"client_id":   cred.ClientID,
			"auth_method": cred.AuthMethod,
		},
	})

	c.JSON(http.StatusOK, CredentialResponse{
		ClientID:     cred.ClientID,
		AuthMethod:   cred.AuthMethod,
		ClientSecret: cred.Secret,
	})
}

// ServiceAccountAccessItem is one MCP server a workload can reach, with the
// role it was granted and the scopes that role currently yields on that server.
type ServiceAccountAccessItem struct {
	ResourceServerID   string   `json:"resource_server_id"`
	ResourceServerName string   `json:"resource_server_name"`
	ResourceURI        string   `json:"resource_uri"`
	RoleID             string   `json:"role_id"`
	RoleName           string   `json:"role_name"`
	EffectiveScopes    []string `json:"effective_scopes"`
}

// ListServiceAccountAccess handles GET /uflow/admin/service-accounts/:sa_id/access.
// It is the reverse index of the per-application access lists: "which MCP
// servers can THIS workload call, and with what scopes" — powering the Workloads
// inventory (plan Journey 3). Read-only.
func (ctrl *ServiceAccountsController) ListServiceAccountAccess(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromTokenPtr(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	saUUID, err := uuid.Parse(c.Param("sa_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid service account id"})
		return
	}
	sa, err := services.NewServiceAccountService(config.DB).GetServiceAccount(*workspaceID, saUUID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "service account not found"})
		return
	}

	// All RS-scoped role bindings for this workload.
	var bindings []models.RoleBinding
	if err := config.DB.
		Where("workspace_id = ? AND service_account_id = ? AND scope_type = 'resource_server'", *workspaceID, saUUID).
		Find(&bindings).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	resolver := services.NewScopeResolver(config.DB)
	items := make([]ServiceAccountAccessItem, 0, len(bindings))
	for _, b := range bindings {
		if b.ScopeID == nil {
			continue
		}
		var rs models.ResourceServer
		if err := config.DB.Where("id = ?", *b.ScopeID).First(&rs).Error; err != nil {
			continue // RS deleted out from under the binding — skip
		}
		scopes, _ := resolver.ServiceAccountEffectiveScopes(
			c.Request.Context(), workspaceID.String(), saUUID.String(), b.ScopeID.String(),
		)
		items = append(items, ServiceAccountAccessItem{
			ResourceServerID:   b.ScopeID.String(),
			ResourceServerName: rs.Name,
			ResourceURI:        rs.ResourceURI,
			RoleID:             b.RoleID.String(),
			RoleName:           b.RoleName,
			EffectiveScopes:    scopes,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"service_account_id":   saUUID.String(),
		"service_account_name": sa.Name,
		"items":                items,
	})
}
