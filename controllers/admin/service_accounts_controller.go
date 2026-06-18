package admin

import (
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/controllers/shared"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"
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
}

type UpdateServiceAccountRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type ServiceAccountResponse struct {
	ID            string  `json:"id"`
	WorkspaceID   string  `json:"workspace_id"`
	Name          string  `json:"name"`
	Description   string  `json:"description"`
	Status        string  `json:"status"`
	OAuthClientID *string `json:"oauth_client_id,omitempty"`
	SpiffeID      *string `json:"spiffe_id,omitempty"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

func saToResponse(sa models.ServiceAccount) ServiceAccountResponse {
	r := ServiceAccountResponse{
		ID:          sa.ID.String(),
		WorkspaceID: sa.WorkspaceID.String(),
		Name:        sa.Name,
		Description: sa.Description,
		Status:      sa.Status,
		SpiffeID:    sa.SpiffeID,
		CreatedAt:   sa.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:   sa.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if sa.OAuthClientID != nil {
		s := sa.OAuthClientID.String()
		r.OAuthClientID = &s
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

	sa := models.ServiceAccount{
		ID:          uuid.New(),
		WorkspaceID: *workspaceID,
		Name:        req.Name,
		Description: req.Description,
		Status:      "disabled",
	}

	if err := config.DB.Session(&gorm.Session{NewDB: true}).Create(&sa).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create service account: " + err.Error()})
		return
	}

	middlewares.Audit(c, "service_account", sa.ID.String(), "create", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"name":         sa.Name,
			"description":  sa.Description,
			"workspace_id": sa.WorkspaceID.String(),
		},
	})

	c.JSON(http.StatusCreated, saToResponse(sa))
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

	// Validate: exactly one credential type.
	hasJWKS := (req.JWKSUri != nil && *req.JWKSUri != "") || (req.JWKS != nil && *req.JWKS != "")
	if !hasJWKS && !req.UseClientSecret {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provide jwks_uri, jwks, or use_client_secret=true"})
		return
	}
	if hasJWKS && req.UseClientSecret {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provide exactly one of jwks/jwks_uri or use_client_secret"})
		return
	}

	db := config.DB.Session(&gorm.Session{NewDB: true})

	// Load the service account.
	var sa models.ServiceAccount
	if err := db.Where("workspace_id = ? AND id = ?", workspaceID, saID).First(&sa).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "service account not found"})
		return
	}
	if sa.OAuthClientID != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "service account already has a credential client"})
		return
	}

	authMethod := "private_key_jwt"
	if req.UseClientSecret {
		authMethod = "client_secret_basic"
	}

	// Build the new confidential M2M client.
	newClientID := uuid.New()
	newClientIDStr := newClientID.String()
	now := time.Now().UTC()
	mcpClient := models.MCPOAuthClient{
		ID:                              newClientID,
		ClientID:                        newClientIDStr,
		HydraClientID:                   newClientIDStr, // never synced to Hydra
		ClientName:                      sa.Name + " (m2m)",
		RedirectURIs:                    pq.StringArray{},
		GrantTypes:                      pq.StringArray{"client_credentials"},
		ResponseTypes:                   pq.StringArray{},
		RegistrationType:                "admin",
		ClientKind:                      "m2m",
		SyncStatus:                      "active",
		HomeWorkspaceID:                 workspaceID,
		AllowedTokenEndpointAuthMethods: pq.StringArray{authMethod},
		CreatedAt:                       now,
		UpdatedAt:                       now,
	}

	var plainSecret *string

	txErr := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&mcpClient).Error; err != nil {
			return err
		}

		if hasJWKS {
			jwksRow := models.OAuthClientJWKS{
				ID:       uuid.New(),
				ClientID: mcpClient.ID,
				JWKSUri:  req.JWKSUri,
				JWKS:     req.JWKS,
			}
			if err := tx.Create(&jwksRow).Error; err != nil {
				return err
			}
		} else {
			// Generate and hash a client secret.
			secret, genErr := services.GenerateClientSecret()
			if genErr != nil {
				return genErr
			}
			hash, hashErr := services.HashClientSecret(secret)
			if hashErr != nil {
				return hashErr
			}
			secretRow := models.OAuthClientSecret{
				ID:         uuid.New(),
				ClientID:   mcpClient.ID,
				SecretHash: hash,
			}
			if err := tx.Create(&secretRow).Error; err != nil {
				return err
			}
			plainSecret = &secret
		}

		// Link SA → client and flip status to active.
		return tx.Model(&models.ServiceAccount{}).
			Where("workspace_id = ? AND id = ?", workspaceID, saID).
			Updates(map[string]interface{}{
				"oauth_client_id": mcpClient.ID,
				"status":          "active",
				"updated_at":      now,
			}).Error
	})
	if txErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to provision credentials: " + txErr.Error()})
		return
	}

	middlewares.Audit(c, "service_account", saID.String(), "credential_provisioned", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"client_id":   newClientIDStr,
			"auth_method": authMethod,
		},
	})

	resp := CredentialResponse{
		ClientID:     newClientIDStr,
		AuthMethod:   authMethod,
		ClientSecret: plainSecret,
	}
	c.JSON(http.StatusCreated, resp)
}
