// Package controllers — OocmgrController: OIDC Configuration Manager.
// Ported from oath_oidc_configuration_manager microservice.
package platform

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	oocmgrdto "github.com/authsec-ai/authsec/internal/oocmgr/dto"
	oocmgrrepo "github.com/authsec-ai/authsec/internal/oocmgr/repository"
	oocmgrsvc "github.com/authsec-ai/authsec/internal/oocmgr/service"

	"github.com/gin-gonic/gin"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// ===== CONTROLLER =====

// OocmgrController is the OIDC Configuration Manager controller.
type OocmgrController struct {
	authService           *oocmgrsvc.AuthService
	hydraConfig           oocmgrHydraConfig
	tenantHydraClientRepo *oocmgrrepo.TenantHydraClientRepository
}

type oocmgrHydraConfig struct {
	AdminURL  string
	PublicURL string
}

// NewOocmgrController initialises the controller wiring up all dependencies.
func NewOocmgrController() *OocmgrController {
	authRepo := oocmgrrepo.NewAuthRepository()
	authService := oocmgrsvc.NewAuthService(authRepo)
	return &OocmgrController{
		authService: authService,
		hydraConfig: oocmgrHydraConfig{
			AdminURL:  config.AppConfig.HydraAdminURL,
			PublicURL: config.AppConfig.HydraPublicURL,
		},
		tenantHydraClientRepo: oocmgrrepo.NewTenantHydraClientRepository(),
	}
}

// ===== HYDRA CLIENT TYPES =====

// oocmgrHydraClient mirrors the Hydra admin API client object.
type oocmgrHydraClient struct {
	ClientID      string                 `json:"client_id"`
	ClientSecret  string                 `json:"client_secret,omitempty"`
	ClientName    string                 `json:"client_name"`
	GrantTypes    []string               `json:"grant_types"`
	RedirectURIs  []string               `json:"redirect_uris"`
	ResponseTypes []string               `json:"response_types"`
	TokenEndpoint string                 `json:"token_endpoint_auth_method"`
	Scope         string                 `json:"scope"`
	Audience      []string               `json:"audience,omitempty"`
	SubjectType   string                 `json:"subject_type,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// ===== REQUEST STRUCTS =====

type oocmgrTenantClientConfig struct {
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes,omitempty"`
	GrantTypes   []string `json:"grant_types,omitempty"`
}

type oocmgrOIDCProviderConfig struct {
	ProviderName     string                 `json:"provider_name"`
	DisplayName      string                 `json:"display_name"`
	ClientID         string                 `json:"client_id"`
	ClientSecret     string                 `json:"client_secret"`
	AuthURL          string                 `json:"auth_url"`
	TokenURL         string                 `json:"token_url"`
	UserInfoURL      string                 `json:"user_info_url"`
	Scopes           []string               `json:"scopes"`
	IssuerURL        string                 `json:"issuer_url,omitempty"`
	JWKsURL          string                 `json:"jwks_url,omitempty"`
	AdditionalParams map[string]interface{} `json:"additional_params,omitempty"`
	IsActive         bool                   `json:"is_active"`
	SortOrder        int                    `json:"sort_order"`
}

// oocmgrOIDCProvider is used internally when listing providers for a tenant.
type oocmgrOIDCProvider struct {
	ProviderName string                 `json:"provider_name"`
	DisplayName  string                 `json:"display_name"`
	IsActive     bool                   `json:"is_active"`
	SortOrder    int                    `json:"sort_order"`
	CallbackURL  string                 `json:"callback_url"`
	Config       map[string]interface{} `json:"config"`
}

// editAuthProviderReq is the named type for EditAuthProvider / helper calls.

// ===== MAIN CONFIGURATION ENDPOINT =====

// ===== MANAGEMENT ENDPOINTS =====

func (ac *OocmgrController) EditConfig(c *gin.Context) {
	var req oocmgrdto.EditConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, oocmgrdto.ErrorResponse{Error: "Invalid request", Message: err.Error(), Code: http.StatusBadRequest, Timestamp: time.Now()})
		return
	}

	c.Set("tenant_db", config.DB)

	updatedConfig, err := ac.authService.EditConfig(c, &req)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(err.Error(), "validation"):
			status = http.StatusBadRequest
		case strings.Contains(err.Error(), "not found"):
			status = http.StatusNotFound
		case strings.Contains(err.Error(), "mismatch"):
			status = http.StatusBadRequest
		}
		log.Printf("[oocmgr] audit failure: config update %s err=%v", req.ID.String(), err)
		c.JSON(status, oocmgrdto.ErrorResponse{Error: "Failed to edit configuration", Message: err.Error(), Code: status, Timestamp: time.Now()})
		return
	}

	log.Printf("[oocmgr] EditConfig config_id=%s tenant=%s", req.ID.String(), req.TenantID)
	c.JSON(http.StatusOK, oocmgrdto.MessageResponse{
		Message: "Configuration updated successfully", Success: true, Data: updatedConfig, Timestamp: time.Now(),
	})
}

// ===== TESTING ENDPOINTS =====

// ===== ADDITIONAL HELPER ENDPOINTS =====

func (ac *OocmgrController) GetClientsByTenant(c *gin.Context) {
	var req struct {
		TenantID   string `json:"tenant_id"`
		ActiveOnly bool   `json:"active_only"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, oocmgrdto.ErrorResponse{Error: "Invalid request", Message: err.Error(), Code: http.StatusBadRequest, Timestamp: time.Now()})
		return
	}

	tenantDB := config.DB

	type clientRow struct {
		ClientID string `gorm:"column:client_id"`
	}
	var rows []clientRow
	query := tenantDB.Table("clients").Where("tenant_id = ?", req.TenantID)
	if req.ActiveOnly {
		query = query.Where("active = ?", true)
	}
	if err := query.Select("client_id").Order("created_at ASC").Find(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, oocmgrdto.ErrorResponse{Error: "Failed to query client IDs", Message: err.Error(), Code: http.StatusInternalServerError, Timestamp: time.Now()})
		return
	}

	clientIDs := make([]string, 0, len(rows))
	for _, r := range rows {
		clientIDs = append(clientIDs, r.ClientID)
	}

	c.JSON(http.StatusOK, oocmgrdto.MessageResponse{
		Message: "Client IDs retrieved successfully", Success: true,
		Data: map[string]interface{}{
			"tenant_id": req.TenantID, "client_ids": clientIDs,
			"count": len(clientIDs), "active_only": req.ActiveOnly,
		},
		Timestamp: time.Now(),
	})
}

func (ac *OocmgrController) GetTenantStats(c *gin.Context) {
	var req struct {
		TenantID string `json:"tenant_id"`
		OrgID    string `json:"org_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, oocmgrdto.ErrorResponse{Error: "Invalid request", Message: err.Error(), Code: http.StatusBadRequest, Timestamp: time.Now()})
		return
	}

	clients, err := ac.getAllHydraClients()
	if err != nil {
		c.JSON(http.StatusInternalServerError, oocmgrdto.ErrorResponse{Error: "Failed to get client information", Message: err.Error(), Code: http.StatusInternalServerError, Timestamp: time.Now()})
		return
	}

	var tenantClientCount, oidcProviderCount, activeProviders, inactiveProviders int
	providersByType := make(map[string]int)

	for _, client := range clients {
		if tenantID, ok := client.Metadata["tenant_id"].(string); ok && tenantID == req.TenantID {
			if orgID, ok := client.Metadata["org_id"].(string); ok && orgID == req.OrgID {
				if clientType, ok := client.Metadata["type"].(string); ok {
					switch clientType {
					case "tenant_main_client":
						tenantClientCount++
					case "oidc_provider":
						oidcProviderCount++
						if isActive, ok := client.Metadata["is_active"].(bool); ok && isActive {
							activeProviders++
						} else {
							inactiveProviders++
						}
						if pn, ok := client.Metadata["provider_name"].(string); ok {
							providersByType[pn]++
						}
					}
				}
			}
		}
	}

	c.JSON(http.StatusOK, oocmgrdto.MessageResponse{
		Message: "Tenant statistics retrieved successfully", Success: true,
		Data: map[string]interface{}{
			"tenant_id": req.TenantID, "org_id": req.OrgID,
			"tenant_clients": tenantClientCount, "total_providers": oidcProviderCount,
			"active_providers": activeProviders, "inactive_providers": inactiveProviders,
			"providers_by_type": providersByType, "last_updated": time.Now(),
		},
		Timestamp: time.Now(),
	})
}

func (ac *OocmgrController) DeleteCompleteTenantConfig(c *gin.Context) {
	var req struct {
		TenantID string `json:"tenant_id"`
		ClientID string `json:"client_id"`
		Force    bool   `json:"force"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, oocmgrdto.ErrorResponse{Error: "Invalid request", Message: err.Error(), Code: http.StatusBadRequest, Timestamp: time.Now()})
		return
	}

	clients, err := ac.getAllHydraClients()
	if err != nil {
		c.JSON(http.StatusInternalServerError, oocmgrdto.ErrorResponse{Error: "Failed to get Hydra clients", Message: err.Error(), Code: http.StatusInternalServerError, Timestamp: time.Now()})
		return
	}

	var deletedClients []string
	var failedDeletions []map[string]interface{}

	for _, client := range clients {
		if tenantID, ok := client.Metadata["c_id"].(string); ok && tenantID == req.TenantID {
			if orgID, ok := client.Metadata["tenant_id"].(string); ok && orgID == req.ClientID {
				if err := ac.deleteHydraClient(client.ClientID); err != nil {
					if !req.Force {
						c.JSON(http.StatusInternalServerError, oocmgrdto.ErrorResponse{
							Error:   "Failed to delete client",
							Message: fmt.Sprintf("Failed to delete client %s: %v", client.ClientID, err),
							Code:    http.StatusInternalServerError, Timestamp: time.Now(),
						})
						return
					}
					failedDeletions = append(failedDeletions, map[string]interface{}{"client_id": client.ClientID, "error": err.Error()})
				} else {
					deletedClients = append(deletedClients, client.ClientID)
				}
			}
		}
	}

	if len(deletedClients) == 0 && len(failedDeletions) == 0 {
		c.JSON(http.StatusNotFound, oocmgrdto.ErrorResponse{Error: "Tenant configuration not found", Message: "No configuration found for the specified tenant", Code: http.StatusNotFound, Timestamp: time.Now()})
		return
	}

	statusCode := http.StatusOK
	message := "Tenant configuration deleted successfully"
	if len(failedDeletions) > 0 {
		if len(deletedClients) == 0 {
			statusCode = http.StatusInternalServerError
			message = "Failed to delete tenant configuration"
		} else {
			statusCode = http.StatusPartialContent
			message = "Tenant configuration partially deleted"
		}
	}

	log.Printf("[oocmgr] DeleteCompleteTenantConfig tenant=%s deleted=%d failed=%d", req.TenantID, len(deletedClients), len(failedDeletions))
	c.JSON(statusCode, oocmgrdto.MessageResponse{
		Message: message, Success: len(deletedClients) > 0,
		Data: map[string]interface{}{
			"tenant_id": req.TenantID, "org_id": req.ClientID,
			"deleted_clients": deletedClients, "failed_deletions": failedDeletions,
			"deleted_count": len(deletedClients), "failed_count": len(failedDeletions),
		},
		Timestamp: time.Now(),
	})
}

func (ac *OocmgrController) ListAllTenants(c *gin.Context) {
	clients, err := ac.getAllHydraClients()
	if err != nil {
		c.JSON(http.StatusInternalServerError, oocmgrdto.ErrorResponse{Error: "Failed to get Hydra clients", Message: err.Error(), Code: http.StatusInternalServerError, Timestamp: time.Now()})
		return
	}

	tenants := make(map[string]map[string]interface{})
	for _, client := range clients {
		tenantID, ok1 := client.Metadata["tenant_id"].(string)
		orgID, ok2 := client.Metadata["org_id"].(string)
		if !ok1 || !ok2 {
			continue
		}
		tenantKey := fmt.Sprintf("%s:%s", tenantID, orgID)
		if _, exists := tenants[tenantKey]; !exists {
			tenants[tenantKey] = map[string]interface{}{
				"tenant_id": tenantID, "org_id": orgID,
				"tenant_name": client.Metadata["tenant_name"],
				"main_client": nil, "oidc_providers": []map[string]interface{}{},
				"total_clients": 0, "active_providers": 0,
			}
		}
		tenant := tenants[tenantKey]
		tenant["total_clients"] = tenant["total_clients"].(int) + 1

		if clientType, ok := client.Metadata["type"].(string); ok {
			switch clientType {
			case "tenant_main_client":
				tenant["main_client"] = map[string]interface{}{
					"client_id": client.ClientID, "client_name": client.ClientName,
					"created_at": client.Metadata["created_at"],
				}
			case "oidc_provider":
				provider := map[string]interface{}{
					"provider_name": client.Metadata["provider_name"],
					"display_name":  client.Metadata["display_name"],
					"client_id":     client.ClientID,
					"is_active":     client.Metadata["is_active"],
					"sort_order":    client.Metadata["sort_order"],
				}
				providers := tenant["oidc_providers"].([]map[string]interface{})
				tenant["oidc_providers"] = append(providers, provider)
				if isActive, ok := client.Metadata["is_active"].(bool); ok && isActive {
					tenant["active_providers"] = tenant["active_providers"].(int) + 1
				}
			}
		}
	}

	var tenantList []map[string]interface{}
	for _, tenant := range tenants {
		tenantList = append(tenantList, tenant)
	}

	c.JSON(http.StatusOK, oocmgrdto.MessageResponse{
		Message: "Tenants listed successfully", Success: true,
		Data:      map[string]interface{}{"tenants": tenantList, "count": len(tenantList)},
		Timestamp: time.Now(),
	})
}

func (ac *OocmgrController) CheckTenantExists(c *gin.Context) {
	var req struct {
		TenantID string `json:"tenant_id"`
		OrgID    string `json:"org_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, oocmgrdto.ErrorResponse{Error: "Invalid request", Message: err.Error(), Code: http.StatusBadRequest, Timestamp: time.Now()})
		return
	}

	mainClientID := fmt.Sprintf("%s-main-client", req.TenantID)
	client, err := ac.getHydraClient(mainClientID)
	exists := err == nil && client != nil

	var tenantInfo map[string]interface{}
	if exists {
		tenantInfo = map[string]interface{}{
			"tenant_id": req.TenantID, "org_id": req.OrgID,
			"tenant_name": client.Metadata["tenant_name"],
			"client_id":   client.ClientID, "client_name": client.ClientName,
			"created_at": client.Metadata["created_at"],
		}
	}

	c.JSON(http.StatusOK, oocmgrdto.MessageResponse{
		Message: "Tenant existence check completed", Success: true,
		Data: map[string]interface{}{
			"exists": exists, "tenant_id": req.TenantID, "org_id": req.OrgID, "tenant_info": tenantInfo,
		},
		Timestamp: time.Now(),
	})
}

func (ac *OocmgrController) UpdateCompleteTenantConfig(c *gin.Context) {
	var req struct {
		TenantID      string                     `json:"tenant_id"`
		OrgID         string                     `json:"org_id"`
		TenantName    *string                    `json:"tenant_name,omitempty"`
		TenantClient  *oocmgrTenantClientConfig  `json:"tenant_client,omitempty"`
		OIDCProviders []oocmgrOIDCProviderConfig `json:"oidc_providers,omitempty"`
		UpdatedBy     string                     `json:"updated_by"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, oocmgrdto.ErrorResponse{Error: "Invalid request", Message: err.Error(), Code: http.StatusBadRequest, Timestamp: time.Now()})
		return
	}

	mainClientID := fmt.Sprintf("%s-main-client", req.TenantID)
	existingMainClient, err := ac.getHydraClient(mainClientID)
	if err != nil {
		c.JSON(http.StatusNotFound, oocmgrdto.ErrorResponse{
			Error: "Tenant not found", Message: fmt.Sprintf("Tenant with ID %s does not exist", req.TenantID),
			Code: http.StatusNotFound, Timestamp: time.Now(),
		})
		return
	}

	var updatedMainClient *oocmgrHydraClient
	var updatedProviders []map[string]interface{}
	var failedProviders []map[string]interface{}

	if req.TenantClient != nil {
		grantTypes := req.TenantClient.GrantTypes
		if len(grantTypes) == 0 {
			grantTypes = []string{"authorization_code", "refresh_token"}
		}
		scopes := req.TenantClient.Scopes
		if len(scopes) == 0 {
			scopes = []string{"openid", "profile", "email", "offline_access"}
		}
		tenantName, _ := existingMainClient.Metadata["tenant_name"].(string)
		if req.TenantName != nil {
			tenantName = *req.TenantName
		}
		updatedMainClient = &oocmgrHydraClient{
			ClientID: mainClientID, ClientName: req.TenantClient.ClientName,
			GrantTypes: grantTypes, RedirectURIs: req.TenantClient.RedirectURIs,
			ResponseTypes: []string{"code"}, Scope: strings.Join(scopes, " "),
			Metadata: map[string]interface{}{
				"type": "tenant_main_client", "tenant_id": req.TenantID, "org_id": req.OrgID,
				"tenant_name": tenantName, "created_at": existingMainClient.Metadata["created_at"],
				"updated_at": time.Now().Format(time.RFC3339), "updated_by": req.UpdatedBy,
			},
		}
		if err := ac.updateHydraClient(mainClientID, *updatedMainClient); err != nil {
			c.JSON(http.StatusInternalServerError, oocmgrdto.ErrorResponse{Error: "Failed to update tenant client", Message: err.Error(), Code: http.StatusInternalServerError, Timestamp: time.Now()})
			return
		}
	}

	if len(req.OIDCProviders) > 0 {
		existingProviders, _ := ac.getOIDCProvidersForTenant(req.TenantID)
		existingProviderMap := make(map[string]bool)
		for _, p := range existingProviders {
			existingProviderMap[p.ProviderName] = true
		}

		tenantName, _ := existingMainClient.Metadata["tenant_name"].(string)
		if req.TenantName != nil {
			tenantName = *req.TenantName
		}

		for _, provider := range req.OIDCProviders {
			oidcClientID := fmt.Sprintf("%s-%s-oidc", req.TenantID, oocmgrNormalizeProviderName(provider.ProviderName))
			oidcClient := oocmgrHydraClient{
				ClientID:   oidcClientID,
				ClientName: fmt.Sprintf("%s %s OIDC Config", tenantName, provider.DisplayName),
				GrantTypes: []string{"client_credentials"},
				Metadata: map[string]interface{}{
					"type": "oidc_provider", "tenant_id": req.TenantID, "org_id": req.OrgID,
					"provider_name": provider.ProviderName, "display_name": provider.DisplayName,
					"provider_config": map[string]interface{}{
						"client_id": provider.ClientID, "client_secret": provider.ClientSecret,
						"auth_url": provider.AuthURL, "token_url": provider.TokenURL,
						"user_info_url": provider.UserInfoURL, "scopes": provider.Scopes,
						"issuer_url": provider.IssuerURL, "jwks_url": provider.JWKsURL,
						"additional_params": provider.AdditionalParams,
					},
					"is_active": provider.IsActive, "sort_order": provider.SortOrder,
					"callback_url": fmt.Sprintf("%s/oauth2/callback/%s",
						ac.hydraConfig.PublicURL, oocmgrNormalizeProviderName(provider.ProviderName)),
					"updated_at": time.Now().Format(time.RFC3339), "updated_by": req.UpdatedBy,
				},
			}

			var opErr error
			if existingProviderMap[provider.ProviderName] {
				opErr = ac.updateHydraClient(oidcClientID, oidcClient)
			} else {
				opErr = ac.createHydraClient(oidcClient)
			}

			if opErr != nil {
				action := "update"
				if !existingProviderMap[provider.ProviderName] {
					action = "create"
				}
				failedProviders = append(failedProviders, map[string]interface{}{
					"provider_name": provider.ProviderName, "action": action, "error": opErr.Error(),
				})
				continue
			}

			action := "created"
			if existingProviderMap[provider.ProviderName] {
				action = "updated"
			}
			updatedProviders = append(updatedProviders, map[string]interface{}{
				"provider_name": provider.ProviderName, "display_name": provider.DisplayName,
				"client_id": oidcClientID, "is_active": provider.IsActive, "action": action,
			})
		}
	}

	response := map[string]interface{}{
		"success": true, "tenant_id": req.TenantID, "org_id": req.OrgID,
		"updated_at": time.Now(), "updated_by": req.UpdatedBy,
	}
	if updatedMainClient != nil {
		response["tenant_client"] = map[string]interface{}{
			"client_id": updatedMainClient.ClientID, "client_name": updatedMainClient.ClientName,
			"redirect_uris": updatedMainClient.RedirectURIs,
			"scopes":        strings.Split(updatedMainClient.Scope, " "), "updated": true,
		}
	}
	if len(req.OIDCProviders) > 0 {
		response["oidc_providers"] = map[string]interface{}{
			"updated": updatedProviders, "failed": failedProviders,
			"success_count": len(updatedProviders), "failed_count": len(failedProviders),
		}
	}

	statusCode := http.StatusOK
	message := "Tenant configuration updated successfully"
	if len(failedProviders) > 0 {
		if len(updatedProviders) == 0 {
			statusCode = http.StatusInternalServerError
			message = "Failed to update tenant configuration"
		} else {
			statusCode = http.StatusPartialContent
			message = "Tenant configuration partially updated"
		}
	}

	log.Printf("[oocmgr] UpdateCompleteTenantConfig tenant=%s providers_updated=%d failed=%d", req.TenantID, len(updatedProviders), len(failedProviders))
	c.JSON(statusCode, oocmgrdto.MessageResponse{
		Message: message, Success: len(updatedProviders) > 0 || updatedMainClient != nil,
		Data: response, Timestamp: time.Now(),
	})
}

func (ac *OocmgrController) GetTenantLoginPageData(c *gin.Context) {
	var req struct {
		TenantID string `json:"tenant_id"`
		OrgID    string `json:"org_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, oocmgrdto.ErrorResponse{Error: "Invalid request", Message: err.Error(), Code: http.StatusBadRequest, Timestamp: time.Now()})
		return
	}

	mainClientID := fmt.Sprintf("%s-main-client", req.TenantID)
	tenantClient, err := ac.getHydraClient(mainClientID)
	if err != nil {
		c.JSON(http.StatusNotFound, oocmgrdto.ErrorResponse{
			Error: "Tenant not found", Message: fmt.Sprintf("No client found for tenant %s", req.TenantID),
			Code: http.StatusNotFound, Timestamp: time.Now(),
		})
		return
	}

	providers, err := ac.getOIDCProvidersForTenant(req.TenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, oocmgrdto.ErrorResponse{Error: "Failed to get providers", Message: err.Error(), Code: http.StatusInternalServerError, Timestamp: time.Now()})
		return
	}

	var activeProviders []map[string]interface{}
	for _, provider := range providers {
		if provider.IsActive {
			activeProviders = append(activeProviders, map[string]interface{}{
				"provider_name": provider.ProviderName, "display_name": provider.DisplayName,
				"sort_order": provider.SortOrder,
			})
		}
	}

	sort.Slice(activeProviders, func(i, j int) bool {
		return activeProviders[i]["sort_order"].(int) < activeProviders[j]["sort_order"].(int)
	})

	c.JSON(http.StatusOK, oocmgrdto.MessageResponse{
		Message: "Login page data retrieved successfully", Success: true,
		Data: map[string]interface{}{
			"tenant_id": req.TenantID, "org_id": req.OrgID,
			"tenant_name": tenantClient.Metadata["tenant_name"],
			"client_name": tenantClient.ClientName, "main_client_id": tenantClient.ClientID,
			"providers": activeProviders, "provider_count": len(activeProviders),
		},
		Timestamp: time.Now(),
	})
}

func (ac *OocmgrController) CreateBaseTenantClient(c *gin.Context) {
	var req struct {
		TenantID     string   `json:"tenant_id"`
		TenantName   string   `json:"tenant_name"`
		ClientID     string   `json:"client_id"`
		ClientSecret string   `json:"client_secret"`
		RedirectURIs []string `json:"redirect_uris"`
		Scopes       []string `json:"scopes,omitempty"`
		CreatedBy    string   `json:"created_by"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, oocmgrdto.ErrorResponse{Error: "Invalid request", Message: err.Error(), Code: http.StatusBadRequest, Timestamp: time.Now()})
		return
	}

	existingClient, _ := ac.getHydraClient(req.ClientID)
	if existingClient != nil {
		c.JSON(http.StatusConflict, oocmgrdto.ErrorResponse{
			Error:   "Tenant client already exists",
			Message: fmt.Sprintf("Client with ID %s already exists in Hydra", req.ClientID),
			Code:    http.StatusConflict, Timestamp: time.Now(),
		})
		return
	}

	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email", "offline_access"}
	}
	for i, scope := range scopes {
		if scope == "offline" {
			scopes[i] = "offline_access"
		}
	}

	tenantClient := oocmgrHydraClient{
		ClientID: req.ClientID, ClientSecret: req.ClientSecret,
		ClientName:   fmt.Sprintf("%s Main OAuth Client", req.TenantName),
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		RedirectURIs: req.RedirectURIs, TokenEndpoint: "client_secret_post",
		ResponseTypes: []string{"code"}, Scope: strings.Join(scopes, " "),
		Audience: []string{}, SubjectType: "public",
		Metadata: map[string]interface{}{
			"type":        "tenant_main_client",
			"tenant_id":   strings.TrimSuffix(req.ClientID, "-main-client"),
			"c_id":        strings.TrimSuffix(req.TenantID, "-main-client"),
			"tenant_name": req.TenantName,
			"created_at":  time.Now().Format(time.RFC3339), "created_by": req.CreatedBy,
		},
	}

	if err := ac.createHydraClient(tenantClient); err != nil {
		log.Printf("[oocmgr] audit failure: tenant_client create %s err=%v", req.TenantID, err)
		c.JSON(http.StatusInternalServerError, oocmgrdto.ErrorResponse{Error: "Failed to create tenant client", Message: err.Error(), Code: http.StatusInternalServerError, Timestamp: time.Now()})
		return
	}

	thc := &oocmgrdto.TenantHydraClient{
		TenantID: req.TenantID, TenantName: req.TenantName,
		HydraClientID: req.ClientID, HydraClientSecret: req.ClientSecret,
		ClientName:   fmt.Sprintf("%s Main OAuth Client", req.TenantName),
		RedirectURIs: req.RedirectURIs, Scopes: scopes,
		ClientType: "main", IsActive: true, CreatedBy: req.CreatedBy, UpdatedBy: req.CreatedBy,
	}
	if err := ac.tenantHydraClientRepo.Create(thc); err != nil {
		log.Printf("[oocmgr] Warning: Failed to store tenant-client mapping: %v", err)
	}

	log.Printf("[oocmgr] CreateBaseTenantClient client_id=%s tenant=%s", req.ClientID, req.TenantID)
	c.JSON(http.StatusCreated, oocmgrdto.MessageResponse{
		Message: "Tenant base client created successfully", Success: true,
		Data: map[string]interface{}{
			"tenant_name": req.TenantName, "client_id": req.ClientID,
			"client_secret": req.ClientSecret, "redirect_uris": req.RedirectURIs,
			"scopes": scopes, "created_at": time.Now(),
		},
		Timestamp: time.Now(),
	})
}

func (ac *OocmgrController) GetTenantHydraClients(c *gin.Context) {
	var req struct {
		TenantID string `json:"tenant_id"`
		OrgID    string `json:"org_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, oocmgrdto.ErrorResponse{Error: "Invalid request", Message: err.Error(), Code: http.StatusBadRequest, Timestamp: time.Now()})
		return
	}

	clients, err := ac.tenantHydraClientRepo.GetByTenantID(req.TenantID, req.OrgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, oocmgrdto.ErrorResponse{Error: "Failed to get tenant clients", Message: err.Error(), Code: http.StatusInternalServerError, Timestamp: time.Now()})
		return
	}

	var mainClient *oocmgrdto.TenantHydraClientResponse
	var providerClients []oocmgrdto.TenantHydraClientResponse

	for _, client := range clients {
		resp := oocmgrdto.TenantHydraClientResponse{
			ID: client.ID, OrgID: client.OrgID, TenantID: client.TenantID,
			TenantName: client.TenantName, HydraClientID: client.HydraClientID,
			HydraClientSecret: client.HydraClientSecret, ClientName: client.ClientName,
			RedirectURIs: client.RedirectURIs, Scopes: client.Scopes,
			ClientType: client.ClientType, ProviderName: client.ProviderName,
			IsActive: client.IsActive, CreatedAt: client.CreatedAt, UpdatedAt: client.UpdatedAt,
			CreatedBy: client.CreatedBy, UpdatedBy: client.UpdatedBy,
		}
		if client.ClientType == "main" {
			mainClient = &resp
		} else {
			providerClients = append(providerClients, resp)
		}
	}

	c.JSON(http.StatusOK, oocmgrdto.MessageResponse{
		Message: "Tenant Hydra clients retrieved successfully", Success: true,
		Data: map[string]interface{}{
			"main_client": mainClient, "provider_clients": providerClients, "total_clients": len(clients),
		},
		Timestamp: time.Now(),
	})
}

func (ac *OocmgrController) SyncHydraClients(c *gin.Context) {
	var req struct {
		TenantID string `json:"tenant_id,omitempty"`
		OrgID    string `json:"org_id,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, oocmgrdto.ErrorResponse{Error: "Invalid request", Message: err.Error(), Code: http.StatusBadRequest, Timestamp: time.Now()})
		return
	}

	hydraClients, err := ac.getAllHydraClients()
	if err != nil {
		c.JSON(http.StatusInternalServerError, oocmgrdto.ErrorResponse{Error: "Failed to get Hydra clients", Message: err.Error(), Code: http.StatusInternalServerError, Timestamp: time.Now()})
		return
	}

	syncedCount, missingCount := 0, 0
	for _, hClient := range hydraClients {
		if _, err := ac.tenantHydraClientRepo.GetByHydraClientID(hClient.ClientID); err != nil {
			log.Printf("[oocmgr] Hydra client %s not found in database mappings", hClient.ClientID)
			missingCount++
		} else {
			syncedCount++
		}
	}

	c.JSON(http.StatusOK, oocmgrdto.MessageResponse{
		Message: "Hydra clients sync completed", Success: true,
		Data: map[string]interface{}{
			"total_hydra_clients": len(hydraClients),
			"synced_clients":      syncedCount, "missing_mappings": missingCount,
		},
		Timestamp: time.Now(),
	})
}

func (ac *OocmgrController) ListTenantHydraClients(c *gin.Context) {
	var req oocmgrdto.GetTenantHydraClientsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, oocmgrdto.ErrorResponse{Error: "Invalid request", Message: err.Error(), Code: http.StatusBadRequest, Timestamp: time.Now()})
		return
	}

	clients, err := ac.tenantHydraClientRepo.ListAll(&req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, oocmgrdto.ErrorResponse{Error: "Failed to list clients", Message: err.Error(), Code: http.StatusInternalServerError, Timestamp: time.Now()})
		return
	}

	var responses []oocmgrdto.TenantHydraClientResponse
	for _, client := range clients {
		resp := oocmgrdto.TenantHydraClientResponse{
			ID: client.ID, OrgID: client.OrgID, TenantID: client.TenantID,
			TenantName: client.TenantName, HydraClientID: client.HydraClientID,
			ClientName: client.ClientName, RedirectURIs: client.RedirectURIs,
			Scopes: client.Scopes, ClientType: client.ClientType,
			ProviderName: client.ProviderName, IsActive: client.IsActive,
			CreatedAt: client.CreatedAt, UpdatedAt: client.UpdatedAt,
			CreatedBy: client.CreatedBy, UpdatedBy: client.UpdatedBy,
		}
		if req.TenantID != "" && req.OrgID != "" {
			resp.HydraClientSecret = client.HydraClientSecret
		}
		responses = append(responses, resp)
	}

	c.JSON(http.StatusOK, oocmgrdto.MessageResponse{
		Message: "Hydra clients retrieved successfully", Success: true, Data: responses, Timestamp: time.Now(),
	})
}

func (ac *OocmgrController) DumpHydraRawData(c *gin.Context) {
	var req struct {
		TenantID   string `json:"tenant_id"`
		ClientType string `json:"client_type"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, oocmgrdto.ErrorResponse{Error: "Invalid request", Message: err.Error(), Code: http.StatusBadRequest, Timestamp: time.Now()})
		return
	}

	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, oocmgrdto.ErrorResponse{Error: "tenant_id is required", Message: "Provide a tenant_id to dump Hydra data.", Code: http.StatusBadRequest, Timestamp: time.Now()})
		return
	}

	clients, err := ac.getAllHydraClients()
	if err != nil {
		c.JSON(http.StatusInternalServerError, oocmgrdto.ErrorResponse{Error: "Failed to query Hydra", Message: err.Error(), Code: http.StatusInternalServerError, Timestamp: time.Now()})
		return
	}

	clientTypeFilter := strings.TrimSpace(req.ClientType)
	var dump []map[string]interface{}

	for _, client := range clients {
		matchesTenant := oocmgrBelongsToTenant(client.Metadata, tenantID)
		if !matchesTenant && strings.HasPrefix(strings.ToLower(client.ClientID), strings.ToLower(tenantID)) {
			matchesTenant = true
		}
		if !matchesTenant {
			continue
		}
		if clientTypeFilter != "" {
			if ct, _ := client.Metadata["type"].(string); ct != clientTypeFilter {
				continue
			}
		}
		dump = append(dump, oocmgrSanitizeHydraClientForDump(client))
	}

	c.JSON(http.StatusOK, oocmgrdto.MessageResponse{
		Message: "Hydra client dump retrieved successfully", Success: true,
		Data: map[string]interface{}{
			"tenant_id": tenantID, "client_type": clientTypeFilter,
			"count": len(dump), "clients": dump,
		},
		Timestamp: time.Now(),
	})
}

// ===== SAML ENDPOINTS =====

// ===== HYDRA API HELPERS =====

func (ac *OocmgrController) createHydraClient(client oocmgrHydraClient) error {
	jsonData, err := json.Marshal(client)
	if err != nil {
		return fmt.Errorf("failed to marshal client data: %w", err)
	}
	log.Printf("[oocmgr] Sending to Hydra: %s", string(jsonData))

	url := fmt.Sprintf("%s/admin/clients", ac.hydraConfig.AdminURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("failed to call Hydra API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[oocmgr] Hydra error response: %s", string(body))
		return fmt.Errorf("Hydra API returned status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func (ac *OocmgrController) getHydraClient(clientID string) (*oocmgrHydraClient, error) {
	url := fmt.Sprintf("%s/admin/clients/%s", ac.hydraConfig.AdminURL, clientID)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client not found or API error: %d", resp.StatusCode)
	}

	var client oocmgrHydraClient
	if err := json.NewDecoder(resp.Body).Decode(&client); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &client, nil
}

func (ac *OocmgrController) getAllHydraClients() ([]oocmgrHydraClient, error) {
	url := fmt.Sprintf("%s/admin/clients", ac.hydraConfig.AdminURL)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get clients: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error: %d", resp.StatusCode)
	}

	var clients []oocmgrHydraClient
	if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return clients, nil
}

func (ac *OocmgrController) updateHydraClient(clientID string, client oocmgrHydraClient) error {
	jsonData, err := json.Marshal(client)
	if err != nil {
		return fmt.Errorf("failed to marshal client data: %w", err)
	}

	url := fmt.Sprintf("%s/admin/clients/%s", ac.hydraConfig.AdminURL, clientID)
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("failed to call Hydra API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Hydra API returned status %d", resp.StatusCode)
	}
	return nil
}

func (ac *OocmgrController) deleteHydraClient(clientID string) error {
	url := fmt.Sprintf("%s/admin/clients/%s", ac.hydraConfig.AdminURL, clientID)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("failed to call Hydra API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		log.Printf("[oocmgr] deleteHydraClient: %s already removed (404)", clientID)
		return nil
	}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Hydra API returned status %d", resp.StatusCode)
	}
	return nil
}

// ===== UTILITY HELPERS =====

func (ac *OocmgrController) getOIDCProvidersForTenant(tenantID string) ([]oocmgrOIDCProvider, error) {
	clients, err := ac.getAllHydraClients()
	if err != nil {
		return nil, err
	}

	var providers []oocmgrOIDCProvider
	for _, client := range clients {
		if clientTenantID, ok := client.Metadata["tenant_id"].(string); ok && clientTenantID == tenantID {
			if clientType, ok := client.Metadata["type"].(string); ok && clientType == "oidc_provider" {
				providerName, _ := client.Metadata["provider_name"].(string)
				displayName, _ := client.Metadata["display_name"].(string)
				isActive, _ := client.Metadata["is_active"].(bool)
				sortOrder, _ := client.Metadata["sort_order"].(float64)
				callbackURL, _ := client.Metadata["callback_url"].(string)
				providerConfig, _ := client.Metadata["provider_config"].(map[string]interface{})

				if providerName != "" {
					providers = append(providers, oocmgrOIDCProvider{
						ProviderName: providerName, DisplayName: displayName,
						IsActive: isActive, SortOrder: int(sortOrder),
						CallbackURL: callbackURL, Config: providerConfig,
					})
				}
			}
		}
	}
	return providers, nil
}

// ===== PACKAGE-LEVEL HELPERS =====

// oocmgrGetTenantDB is a vestigial helper from the multi-tenant era. The
// single-DB collapse removed tenant routing, so this always returns the shared
// config.DB. Kept for backward compatibility with callers — remove once they're
// inlined.
func oocmgrGetTenantDB(_ string) (*gorm.DB, error) {
	return config.DB, nil
}

func oocmgrJSONToMap(jsonData datatypes.JSON) map[string]interface{} {
	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		return nil
	}
	return result
}

func oocmgrNormalizeProviderName(name string) string {
	return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(name, " ", "-"), "_", "-"))
}

// oocmgrResolveMicrosoftAuthorityURLs auto-populates Microsoft auth/token/issuer/jwks URLs
// based on the "authority_type" field in additional_params.
// Supported values: "common" (default), "organizations", "consumers", or a specific tenant ID.

func oocmgrGetClientIDFromHeaders(c *gin.Context) string {
	for _, key := range []string{"Client-Id", "client-id", "X-Client-Id"} {
		if v := strings.TrimSpace(c.GetHeader(key)); v != "" {
			return v
		}
	}
	return ""
}

func oocmgrBelongsToTenant(metadata map[string]interface{}, tenantID string) bool {
	if metadata == nil || tenantID == "" {
		return false
	}
	if metaTenantID, ok := metadata["tenant_id"].(string); ok && metaTenantID == tenantID {
		return true
	}
	if cid, ok := metadata["c_id"].(string); ok && cid == tenantID {
		return true
	}
	return false
}

func oocmgrExtractServiceClientID(metadata map[string]interface{}) string {
	if metadata == nil {
		return ""
	}
	if pc, ok := metadata["provider_config"].(map[string]interface{}); ok {
		if clientID, ok := pc["client_id"].(string); ok {
			return strings.TrimSpace(clientID)
		}
	}
	if clientID, ok := metadata["client_id"].(string); ok {
		return strings.TrimSpace(clientID)
	}
	return ""
}

func oocmgrSanitizeHydraClientForDump(client oocmgrHydraClient) map[string]interface{} {
	output := map[string]interface{}{
		"client_id": client.ClientID, "client_name": client.ClientName,
		"grant_types": client.GrantTypes, "redirect_uris": client.RedirectURIs,
		"response_types":             client.ResponseTypes,
		"token_endpoint_auth_method": client.TokenEndpoint,
		"scope":                      client.Scope, "subject_type": client.SubjectType, "audience": client.Audience,
	}
	if client.ClientSecret != "" {
		output["client_secret"] = "***hidden***"
	}
	if client.Metadata != nil {
		output["metadata"] = oocmgrSanitizeMetadata(client.Metadata)
	}
	return output
}

func oocmgrSanitizeMetadata(data map[string]interface{}) map[string]interface{} {
	if data == nil {
		return nil
	}
	sanitized := make(map[string]interface{}, len(data))
	for key, value := range data {
		sanitized[key] = oocmgrSanitizeEntry(key, value)
	}
	return sanitized
}

func oocmgrSanitizeEntry(key string, value interface{}) interface{} {
	if strings.Contains(strings.ToLower(key), "secret") {
		return "***hidden***"
	}
	switch typed := value.(type) {
	case map[string]interface{}:
		return oocmgrSanitizeMetadata(typed)
	case []interface{}:
		result := make([]interface{}, len(typed))
		for i, item := range typed {
			switch nested := item.(type) {
			case map[string]interface{}:
				result[i] = oocmgrSanitizeMetadata(nested)
			default:
				result[i] = nested
			}
		}
		return result
	default:
		return value
	}
}
