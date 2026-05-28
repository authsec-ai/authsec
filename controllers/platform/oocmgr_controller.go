// Package controllers — OocmgrController: OIDC Configuration Manager.
// Ported from oath_oidc_configuration_manager microservice.
package platform

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	oocmgrdto "github.com/authsec-ai/authsec/internal/oocmgr/dto"
	oocmgrrepo "github.com/authsec-ai/authsec/internal/oocmgr/repository"
	oocmgrsvc "github.com/authsec-ai/authsec/internal/oocmgr/service"

	"github.com/gin-gonic/gin"
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

// ===== MANAGEMENT ENDPOINTS =====

// ===== TESTING ENDPOINTS =====

// ===== ADDITIONAL HELPER ENDPOINTS =====

func (ac *OocmgrController) SyncHydraClients(c *gin.Context) {
	var req struct {
		WorkspaceID string `json:"workspace_id,omitempty"`
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

func (ac *OocmgrController) DumpHydraRawData(c *gin.Context) {
	var req struct {
		WorkspaceID   string `json:"workspace_id"`
		ClientType string `json:"client_type"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, oocmgrdto.ErrorResponse{Error: "Invalid request", Message: err.Error(), Code: http.StatusBadRequest, Timestamp: time.Now()})
		return
	}

	tenantID := strings.TrimSpace(req.WorkspaceID)
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
			"workspace_id": tenantID, "client_type": clientTypeFilter,
			"count": len(dump), "clients": dump,
		},
		Timestamp: time.Now(),
	})
}

// ===== SAML ENDPOINTS =====

// ===== HYDRA API HELPERS =====

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

// ===== UTILITY HELPERS =====

// ===== PACKAGE-LEVEL HELPERS =====

// oocmgrGetTenantDB is a vestigial helper from the multi-tenant era. The
// single-DB collapse removed tenant routing, so this always returns the shared
// config.DB. Kept for backward compatibility with callers — remove once they're
// inlined.

// oocmgrResolveMicrosoftAuthorityURLs auto-populates Microsoft auth/token/issuer/jwks URLs
// based on the "authority_type" field in additional_params.
// Supported values: "common" (default), "organizations", "consumers", or a specific tenant ID.

func oocmgrBelongsToTenant(metadata map[string]interface{}, tenantID string) bool {
	if metadata == nil || tenantID == "" {
		return false
	}
	if metaTenantID, ok := metadata["workspace_id"].(string); ok && metaTenantID == tenantID {
		return true
	}
	if cid, ok := metadata["c_id"].(string); ok && cid == tenantID {
		return true
	}
	return false
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
