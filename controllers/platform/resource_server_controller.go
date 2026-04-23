package platform

import (
	"fmt"
	"net/http"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ResourceServerController handles CRUD for MCP resource server registration.
type ResourceServerController struct {
	service  *services.ResourceServerService
	oauthSvc *services.OAuthASService
}

func NewResourceServerController() *ResourceServerController {
	return &ResourceServerController{
		service:  services.NewResourceServerService(config.DB),
		oauthSvc: services.NewOAuthASService(config.DB),
	}
}

// Create registers a new resource server.
// POST /authsec/resource-servers
func (ctrl *ResourceServerController) Create(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	var req services.CreateResourceServerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	req.TenantID = tenantID

	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if req.PublicBaseURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "public_base_url is required"})
		return
	}

	baseURL := config.AppConfig.OAuthBaseURL()
	_, resp, err := ctrl.service.Create(req, baseURL)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, tenantID.String(), "rs_created", "resource_server",
		resp.ID, http.StatusCreated, nil,
		map[string]interface{}{"name": req.Name, "url": req.PublicBaseURL})
	c.JSON(http.StatusCreated, resp)
}

// List returns all resource servers for the tenant.
// GET /authsec/resource-servers
func (ctrl *ResourceServerController) List(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	servers, err := ctrl.service.ListByTenant(tenantID.String())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, servers)
}

// Get returns a single resource server by ID (tenant-scoped).
// GET /authsec/resource-servers/:id
func (ctrl *ResourceServerController) Get(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	id := c.Param("id")
	rs, err := ctrl.service.GetByIDAndTenant(id, tenantID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}
	c.JSON(http.StatusOK, rs)
}

// Update modifies a resource server (tenant-scoped).
// PUT /authsec/resource-servers/:id
func (ctrl *ResourceServerController) Update(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	id := c.Param("id")
	var raw map[string]interface{}
	if err := c.ShouldBindJSON(&raw); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Whitelist updatable fields — prevent overwriting id, tenant_id, secrets, deleted_at
	allowed := map[string]bool{
		"name": true, "public_base_url": true, "protected_base_path": true,
		"scopes_supported": true, "registration_modes": true, "active": true,
	}
	updates := make(map[string]interface{})
	for k, v := range raw {
		if allowed[k] {
			updates[k] = v
		}
	}
	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no valid fields to update"})
		return
	}

	rs, err := ctrl.service.UpdateByTenant(id, tenantID.String(), updates)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}

	auditAdminMutation(c, tenantID.String(), "rs_updated", "resource_server",
		id, http.StatusOK, nil, updates)
	c.JSON(http.StatusOK, rs)
}

// Delete removes a resource server (tenant-scoped).
// DELETE /authsec/resource-servers/:id
func (ctrl *ResourceServerController) Delete(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	id := c.Param("id")
	if err := ctrl.service.DeleteByTenant(id, tenantID.String()); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}
	auditAdminMutation(c, tenantID.String(), "rs_deleted", "resource_server",
		id, http.StatusNoContent, nil, nil)
	c.JSON(http.StatusNoContent, nil)
}

// RotateIntrospectionSecret generates a new introspection secret for an RS.
// POST /authsec/resource-servers/:id/rotate-introspection-secret
func (ctrl *ResourceServerController) RotateIntrospectionSecret(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	id := c.Param("id")
	secret, err := ctrl.service.RotateIntrospectionSecret(id, tenantID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, tenantID.String(), "rs_introspection_secret_rotated", "resource_server",
		id, http.StatusOK, nil, nil) // never log the secret value
	c.JSON(http.StatusOK, gin.H{"introspection_secret": secret})
}

// PreRegisterClient pre-registers an OAuth client for a resource server.
// POST /authsec/resource-servers/:id/clients
func (ctrl *ResourceServerController) PreRegisterClient(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	rs, err := ctrl.service.GetByIDAndTenant(rsID, tenantID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}

	if !rs.AllowsRegistrationMode("prereg") {
		c.JSON(http.StatusForbidden, gin.H{"error": "resource server does not allow pre-registration"})
		return
	}

	var req services.DCRRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	client, err := ctrl.oauthSvc.PreRegisterClient(rs, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, tenantID.String(), "rs_client_preregistered", "oauth_client",
		client.ClientID, http.StatusCreated, nil,
		map[string]interface{}{"rs_id": rsID, "client_name": client.ClientName})
	c.JSON(http.StatusCreated, gin.H{
		"client_id":   client.ClientID,
		"client_name": client.ClientName,
	})
}

// ListClients lists all registered OAuth clients for a resource server.
// GET /authsec/resource-servers/:id/clients
func (ctrl *ResourceServerController) ListClients(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	_, err = ctrl.service.GetByIDAndTenant(rsID, tenantID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}

	clients, err := ctrl.oauthSvc.ListClientsForRS(rsID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, clients)
}

// RevokeClient revokes a client's registration for a resource server.
// DELETE /authsec/resource-servers/:id/clients/:client_id
func (ctrl *ResourceServerController) RevokeClient(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	_, err = ctrl.service.GetByIDAndTenant(rsID, tenantID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}

	clientID := c.Param("client_id")
	if err := ctrl.oauthSvc.RevokeClientRegistration(rsID, clientID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, tenantID.String(), "rs_client_revoked", "oauth_client",
		clientID, http.StatusOK, nil, map[string]interface{}{"rs_id": rsID})
	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}

// ApproveRedirects approves pending CIMD redirect URI changes for a client.
// PUT /authsec/resource-servers/:rs_id/clients/:client_id/approve-redirects
func (ctrl *ResourceServerController) ApproveRedirects(c *gin.Context) {
	tenantID, err := extractTenantID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id required in JWT"})
		return
	}

	rsID := c.Param("id")
	_, err = ctrl.service.GetByIDAndTenant(rsID, tenantID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource server not found"})
		return
	}

	clientID := c.Param("client_id")
	if err := ctrl.oauthSvc.ApprovePendingRedirects(clientID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, tenantID.String(), "rs_client_redirects_approved", "oauth_client",
		clientID, http.StatusOK, nil, nil)
	c.JSON(http.StatusOK, gin.H{"status": "redirects approved"})
}

func extractTenantID(c *gin.Context) (uuid.UUID, error) {
	tidStr, err := middlewares.GetValidatedTenantID(c)
	if err != nil {
		return uuid.Nil, fmt.Errorf("tenant_id not found in token: %w", err)
	}
	return uuid.Parse(tidStr)
}
