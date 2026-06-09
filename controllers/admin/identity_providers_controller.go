package admin

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/controllers/shared"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// IdentityProvidersController serves the workspace IDP write API. One canonical
// POST endpoint dispatches on provider_type and writes both the underlying
// provider config (oidc_providers or saml_providers) and the identity_providers
// row in a single transaction.
//
// Routes:
//
//	POST    /authsec/identity-providers
//	GET     /authsec/identity-providers
//	GET     /authsec/identity-providers/:id
//	PUT     /authsec/identity-providers/:id/status
//	DELETE  /authsec/identity-providers/:id
type IdentityProvidersController struct {
	service *services.IdentityProviderService
}

func NewIdentityProvidersController() *IdentityProvidersController {
	return &IdentityProvidersController{
		service: services.NewIdentityProviderService(config.DB),
	}
}

// createIDPRequest is the inbound payload for POST /authsec/identity-providers.
// `config` is protocol-specific JSON unmarshalled into the matching service
// request based on provider_type.
type createIDPRequest struct {
	ProviderType string          `json:"provider_type" binding:"required"`
	DisplayName  string          `json:"display_name" binding:"required"`
	Config       json.RawMessage `json:"config" binding:"required"`
}

type oidcCreateConfig struct {
	ProviderName     string `json:"provider_name" binding:"required"`
	AuthorizationURL string `json:"authorization_url" binding:"required"`
	TokenURL         string `json:"token_url" binding:"required"`
	UserinfoURL      string `json:"userinfo_url" binding:"required"`
	ClientID         string `json:"client_id" binding:"required"`
	ClientSecret     string `json:"client_secret" binding:"required"`
	Scopes           string `json:"scopes,omitempty"`
	IconURL          string `json:"icon_url,omitempty"`
	RedirectURI      string `json:"redirect_uri,omitempty"`
}

type samlCreateConfig struct {
	ProviderName     string          `json:"provider_name" binding:"required"`
	EntityID         string          `json:"entity_id" binding:"required"`
	SSOUrl           string          `json:"sso_url" binding:"required"`
	SLOUrl           string          `json:"slo_url,omitempty"`
	Certificate      string          `json:"certificate" binding:"required"`
	NameIDFormat     string          `json:"name_id_format,omitempty"`
	AttributeMapping json.RawMessage `json:"attribute_mapping,omitempty"`
}

// Create handles POST /authsec/identity-providers.
func (ctrl *IdentityProvidersController) Create(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}
	userID := extractUserID(c)
	if userID == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user_id required in JWT"})
		return
	}

	var req createIDPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[IDP] Create: JSON binding failed: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}
	log.Printf("[IDP] Create: type=%s display=%s config_len=%d", req.ProviderType, req.DisplayName, len(req.Config))

	switch req.ProviderType {
	case models.IdentityProviderOIDC:
		var cfg oidcCreateConfig
		if err := json.Unmarshal(req.Config, &cfg); err != nil {
			log.Printf("[IDP] Create: OIDC config unmarshal failed: %v (raw: %s)", err, string(req.Config))
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid oidc config: " + err.Error()})
			return
		}
		log.Printf("[IDP] CreateOIDC: provider=%s workspace=%s client_id=%s", cfg.ProviderName, workspaceID, cfg.ClientID)
		idp, err := ctrl.service.CreateOIDC(services.CreateOIDCIDPRequest{
			WorkspaceID:      workspaceID,
			CreatedByUserID:  userID,
			DisplayName:      req.DisplayName,
			ProviderName:     cfg.ProviderName,
			AuthorizationURL: cfg.AuthorizationURL,
			TokenURL:         cfg.TokenURL,
			UserinfoURL:      cfg.UserinfoURL,
			ClientID:         cfg.ClientID,
			ClientSecret:     cfg.ClientSecret,
			Scopes:           cfg.Scopes,
			IconURL:          cfg.IconURL,
			RedirectURI:      cfg.RedirectURI,
		})
		if err != nil {
			if errors.Is(err, services.ErrIdentityProviderAlreadyExists) {
				c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusCreated, idp)

	case models.IdentityProviderSAML:
		var cfg samlCreateConfig
		if err := json.Unmarshal(req.Config, &cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid saml config: " + err.Error()})
			return
		}
		idp, err := ctrl.service.CreateSAML(services.CreateSAMLIDPRequest{
			WorkspaceID:      workspaceID,
			CreatedByUserID:  userID,
			DisplayName:      req.DisplayName,
			ProviderName:     cfg.ProviderName,
			EntityID:         cfg.EntityID,
			SSOUrl:           cfg.SSOUrl,
			SLOUrl:           cfg.SLOUrl,
			Certificate:      cfg.Certificate,
			NameIDFormat:     cfg.NameIDFormat,
			AttributeMapping: cfg.AttributeMapping,
		})
		if err != nil {
			if errors.Is(err, services.ErrIdentityProviderAlreadyExists) {
				c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusCreated, idp)

	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "unsupported provider_type; must be 'oidc' or 'saml'",
		})
	}
}

// List handles GET /authsec/identity-providers. Optional ?provider_type= filter.
func (ctrl *IdentityProvidersController) List(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}
	providerType := c.Query("provider_type")
	rows, err := ctrl.service.ListByWorkspace(workspaceID, providerType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, rows)
}

// Get handles GET /authsec/identity-providers/:id.
//
// For SAML and OIDC providers, the underlying protocol config row
// (saml_providers / oidc_providers) is attached to the response under
// `config` so the admin UI can render Edit forms without a second round-trip
// or fabricated defaults.
func (ctrl *IdentityProvidersController) Get(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}
	idpID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity provider id"})
		return
	}
	idp, err := ctrl.service.GetByID(workspaceID, idpID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "identity provider not found"})
		return
	}

	// Attach protocol config row when available. Gorm scans the saml_providers
	// row into a map so we don't need to import the hydra SAML model here
	// (that would create an import cycle). OIDC uses its typed model.
	resp := gin.H{
		"id":                idp.ID,
		"workspace_id":      idp.WorkspaceID,
		"provider_type":     idp.ProviderType,
		"display_name":      idp.DisplayName,
		"status":            idp.Status,
		"redirect_uri":      idp.RedirectURI,
		"saml_provider_id":  idp.SAMLProviderID,
		"oidc_provider_id":  idp.OIDCProviderID,
		"created_at":        idp.CreatedAt,
		"updated_at":        idp.UpdatedAt,
	}

	switch idp.ProviderType {
	case models.IdentityProviderSAML:
		var samlCfg map[string]interface{}
		if cfgErr := ctrl.service.ResolveSAMLConfig(idp, &samlCfg); cfgErr == nil {
			resp["config"] = samlCfg
		} else {
			log.Printf("[IDP] Get: ResolveSAMLConfig failed for idp=%s: %v", idp.ID, cfgErr)
		}
	case models.IdentityProviderOIDC:
		var oidcCfg models.OIDCProvider
		if cfgErr := ctrl.service.ResolveOIDCConfig(idp, &oidcCfg); cfgErr == nil {
			// Drop the Vault path — secret never leaves the server.
			oidcCfg.ClientSecretVaultPath = ""
			resp["config"] = oidcCfg
		} else {
			log.Printf("[IDP] Get: ResolveOIDCConfig failed for idp=%s: %v", idp.ID, cfgErr)
		}
	}
	c.JSON(http.StatusOK, resp)
}

// updateIDPRequest matches the create payload shape so admin UIs can reuse
// their form serialization. `config` is unmarshalled per provider_type.
type updateIDPRequest struct {
	ProviderType string          `json:"provider_type" binding:"required"`
	DisplayName  string          `json:"display_name"`
	Config       json.RawMessage `json:"config"`
}

type samlUpdateConfig struct {
	ProviderName     string          `json:"provider_name,omitempty"`
	EntityID         string          `json:"entity_id,omitempty"`
	SSOUrl           string          `json:"sso_url,omitempty"`
	SLOUrl           *string         `json:"slo_url,omitempty"`
	Certificate      string          `json:"certificate,omitempty"`
	NameIDFormat     string          `json:"name_id_format,omitempty"`
	AttributeMapping json.RawMessage `json:"attribute_mapping,omitempty"`
}

// Update handles PUT /authsec/identity-providers/:id — full SAML/OIDC config
// update. Body shape matches Create: `{provider_type, display_name, config}`.
// Status toggling stays on its dedicated PUT .../status endpoint.
func (ctrl *IdentityProvidersController) Update(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}
	idpID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity provider id"})
		return
	}

	var req updateIDPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}

	switch req.ProviderType {
	case models.IdentityProviderSAML:
		var cfg samlUpdateConfig
		if len(req.Config) > 0 {
			if err := json.Unmarshal(req.Config, &cfg); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid saml config: " + err.Error()})
				return
			}
		}
		idp, err := ctrl.service.UpdateSAML(services.UpdateSAMLIDPRequest{
			WorkspaceID:      workspaceID,
			IDPID:            idpID,
			DisplayName:      req.DisplayName,
			ProviderName:     cfg.ProviderName,
			EntityID:         cfg.EntityID,
			SSOUrl:           cfg.SSOUrl,
			SLOUrl:           cfg.SLOUrl,
			Certificate:      cfg.Certificate,
			NameIDFormat:     cfg.NameIDFormat,
			AttributeMapping: cfg.AttributeMapping,
		})
		if err != nil {
			if errors.Is(err, services.ErrIdentityProviderAlreadyExists) {
				c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
				return
			}
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "identity provider not found"})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, idp)

	case models.IdentityProviderOIDC:
		// OIDC update is out of scope for this change — keep the door open
		// rather than 500ing. Add a service method here when needed.
		c.JSON(http.StatusNotImplemented, gin.H{"error": "OIDC full-config update is not yet supported; use PUT .../status for now"})

	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "unsupported provider_type; must be 'oidc' or 'saml'",
		})
	}
}

// UpdateStatus handles PUT /authsec/identity-providers/:id/status.
// Body: {"status": "configured" | "disabled"}.
func (ctrl *IdentityProvidersController) UpdateStatus(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}
	idpID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity provider id"})
		return
	}
	var body struct {
		Status string `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if err := ctrl.service.UpdateStatus(workspaceID, idpID, body.Status); err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "identity provider not found"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": body.Status})
}

// Delete handles DELETE /authsec/identity-providers/:id.
func (ctrl *IdentityProvidersController) Delete(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}
	idpID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity provider id"})
		return
	}
	if err := ctrl.service.Delete(workspaceID, idpID); err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "identity provider not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// extractUserID pulls the user_id claim from the JWT context as a UUID.
// Returns uuid.Nil when the claim is missing or unparseable; the handler
// decides whether to reject the request.
func extractUserID(c *gin.Context) uuid.UUID {
	if uid, ok := middlewares.GetWorkspaceIDFromToken(c); ok {
		_ = uid // not used; we want the user_id specifically
	}
	if v, exists := c.Get("user_id"); exists {
		if s, ok := v.(string); ok {
			if id, err := uuid.Parse(s); err == nil {
				return id
			}
		}
	}
	return uuid.Nil
}
