package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// ClientsOIDCService handles communication with oath_oidc_configuration_manager
type ClientsOIDCService struct {
	baseURL    string
	httpClient *http.Client
}

// NewClientsOIDCService creates a new OIDC service instance
func NewClientsOIDCService() *ClientsOIDCService {
	baseURL := os.Getenv("OOC_MANAGER_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	return &ClientsOIDCService{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ClientsOIDCClientResponse represents the response from creating an OIDC client
type ClientsOIDCClientResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Success      bool   `json:"success"`
	Message      string `json:"message"`
}

// ClientsCreateTenantClientRequest represents the request structure for creating a tenant client
type ClientsCreateTenantClientRequest struct {
	TenantID     string   `json:"tenant_id"`
	TenantName   string   `json:"tenant_name"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	CreatedBy    string   `json:"created_by"`
}

// CreateTenantClient creates a new OIDC client via oath_oidc_configuration_manager
func (o *ClientsOIDCService) CreateTenantClient(tenantID, clientName string) (*ClientsOIDCClientResponse, error) {
	clientID := fmt.Sprintf("client_%s_%s_%d", tenantID, clientName, time.Now().Unix())
	clientSecret := generateClientsClientSecret()

	request := ClientsCreateTenantClientRequest{
		TenantID:     tenantID,
		TenantName:   clientName,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		ClientName:   clientName,
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Scopes:       []string{"openid", "profile", "email"},
		CreatedBy:    "clients-microservice",
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/oocmgr/tenant/create-base-client", o.baseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request to OIDC manager: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("OIDC manager returned error %d: %s", resp.StatusCode, string(body))
	}

	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if message, ok := response["message"].(string); ok && message == "Tenant base client created successfully" {
		return &ClientsOIDCClientResponse{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Success:      true,
			Message:      message,
		}, nil
	}

	return nil, fmt.Errorf("unexpected response format: %s", string(body))
}

// CheckOIDCManagerHealth checks if the OIDC configuration manager is available
func (o *ClientsOIDCService) CheckOIDCManagerHealth() error {
	url := fmt.Sprintf("%s/oocmgr/health", o.baseURL)
	resp, err := o.httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("OIDC manager health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OIDC manager health check returned status %d", resp.StatusCode)
	}

	return nil
}

func generateClientsClientSecret() string {
	return fmt.Sprintf("secret_%d_%d", time.Now().UnixNano(), time.Now().Unix())
}
