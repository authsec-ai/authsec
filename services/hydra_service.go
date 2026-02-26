package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/golang-jwt/jwt/v5"
)

// OOCManager represents the request structure for OOC Manager API
type OOCManager struct {
	TenantID     string   `json:"tenant_id" validate:"required"`
	TenantName   string   `json:"tenant_name" validate:"required"`
	ClientID     string   `json:"client_id" validate:"required"`
	ClientSecret string   `json:"client_secret" validate:"required"`
	RedirectURIs []string `json:"redirect_uris" validate:"required"`
	Scopes       []string `json:"scopes,omitempty"`
	CreatedBy    string   `json:"created_by"`
}

// ProviderConfig represents the provider configuration for OIDC
type ProviderConfig struct {
	ProviderName string   `json:"provider_name"`
	DisplayName  string   `json:"display_name"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	AuthURL      string   `json:"auth_url"`
	TokenURL     string   `json:"token_url"`
	UserInfoURL  string   `json:"user_info_url"`
	Scopes       []string `json:"scopes"`
	IsActive     bool     `json:"is_active"`
}

// AddProviderRequest represents the request structure for adding a provider
type AddProviderRequest struct {
	TenantID     string         `json:"tenant_id"`
	ClientID     string         `json:"client_id"`
	ReactAppURL  string         `json:"react_app_url"`
	Provider     ProviderConfig `json:"provider"`
	CreatedBy    string         `json:"created_by"`
}

// generateServiceToken generates a JWT token for service-to-service authentication
func generateServiceToken() (string, error) {
	secret := config.AppConfig.JWTSdkSecret
	if secret == "" {
		return "", fmt.Errorf("JWT_SDK_SECRET not configured")
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"service": "user-flow",
		"iat":     time.Now().Unix(),
		"exp":     time.Now().Add(5 * time.Minute).Unix(), // Short-lived service token
	})

	// Sign the token
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("failed to sign service token: %w", err)
	}

	return tokenString, nil
}

// RegisterClientWithHydra registers the client with OOC Manager
// This function creates an OAuth2 client via OOC Manager which then creates it in Hydra
func RegisterClientWithHydra(clientID, clientSecret, clientName, tenantID, tenantDomain string) error {
	// Get OOC Manager URL from config or environment
	oocManagerURL := config.AppConfig.OOCManagerURL
	if oocManagerURL == "" {
		oocManagerURL = "http://localhost:7467" // fallback to default
	}

	oocManager := OOCManager{
		TenantID:     tenantID,
		TenantName:   clientName,
		ClientID:     fmt.Sprintf("%s-main-client", clientID),
		ClientSecret: clientSecret,
		RedirectURIs: []string{fmt.Sprintf("https://%s/oidc/auth/callback", tenantDomain)},
		Scopes:       []string{"openid", "offline", "email", "profile"},
		CreatedBy:    "system",
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(oocManager)
	if err != nil {
		return fmt.Errorf("failed to marshal OOC Manager client data: %w", err)
	}

	// Generate service token for authentication
	token, err := generateServiceToken()
	if err != nil {
		return fmt.Errorf("failed to generate service token: %w", err)
	}

	// Create HTTP request
	url := fmt.Sprintf("%s/oocmgr/tenant/create-base-client", oocManagerURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make HTTP request to OOC Manager: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Read response body for error details
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("OOC Manager error - Status: %d, Failed to read response body", resp.StatusCode)
		} else {
			log.Printf("OOC Manager error - Status: %d, Response: %s", resp.StatusCode, string(bodyBytes))
		}
		
		// Log the request that was sent
		requestJSON, _ := json.Marshal(oocManager)
		log.Printf("OOC Manager request - URL: %s, Payload: %s", url, string(requestJSON))
		
		return fmt.Errorf("OOC Manager API returned status %d", resp.StatusCode)
	}

	log.Printf("Successfully registered client %s with OOC Manager", oocManager.ClientID)
	return nil
}

// DeleteClientFromHydra removes a client via OOC Manager
func DeleteClientFromHydra(clientID string) error {
	// Get OOC Manager URL from config
	oocManagerURL := config.AppConfig.OOCManagerURL
	if oocManagerURL == "" {
		oocManagerURL = "http://localhost:7467"
	}

	// Create request payload
	payload := map[string]string{
		"client_id": fmt.Sprintf("%s-main-client", clientID),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal delete request: %w", err)
	}

	// Generate service token for authentication
	token, err := generateServiceToken()
	if err != nil {
		return fmt.Errorf("failed to generate service token: %w", err)
	}

	// Create HTTP request
	url := fmt.Sprintf("%s/oocmgr/tenant/delete-complete", oocManagerURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make HTTP request to OOC Manager: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("OOC Manager API returned status %d during deletion", resp.StatusCode)
	}

	log.Printf("Successfully deleted client %s via OOC Manager", clientID)
	return nil
}

// UpdateClientInHydra updates a client via OOC Manager
func UpdateClientInHydra(clientID, secret, email, tenantID string) error {
	// Get OOC Manager URL from config
	oocManagerURL := config.AppConfig.OOCManagerURL
	if oocManagerURL == "" {
		oocManagerURL = "http://localhost:7467"
	}

	// Create update request payload
	payload := map[string]interface{}{
		"client_id":     fmt.Sprintf("%s-main-client", clientID),
		"client_secret": secret,
		"tenant_id":     tenantID,
		"email":         email,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal update request: %w", err)
	}

	// Generate service token for authentication
	token, err := generateServiceToken()
	if err != nil {
		return fmt.Errorf("failed to generate service token: %w", err)
	}

	// Create HTTP request
	url := fmt.Sprintf("%s/oocmgr/tenant/update-complete", oocManagerURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make HTTP request to OOC Manager: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("OOC Manager API returned status %d during update", resp.StatusCode)
	}

	log.Printf("Successfully updated client %s via OOC Manager", clientID)
	return nil
}

// AddProviderToClient adds a dummy AuthSec provider to a client via OOC Manager
func AddProviderToClient(tenantID, clientID, reactAppURL, createdBy string) error {
	oocManagerURL := config.AppConfig.OOCManagerURL
	if oocManagerURL == "" {
		oocManagerURL = "http://localhost:7467"
	}

	// Create dummy AuthSec provider configuration
	providerReq := AddProviderRequest{
		TenantID:    tenantID,
		ClientID:    clientID,
		ReactAppURL: reactAppURL,
		Provider: ProviderConfig{
			ProviderName: "authsec",
			DisplayName:  "AuthSec",
			ClientID:     clientID,
			ClientSecret: "dummy-secret-" + clientID,
			AuthURL:      fmt.Sprintf("https://%s/oauth2/auth", reactAppURL),
			TokenURL:     fmt.Sprintf("https://%s/oauth2/token", reactAppURL),
			UserInfoURL:  fmt.Sprintf("https://%s/userinfo", reactAppURL),
			Scopes:       []string{"openid", "profile", "email"},
			IsActive:     true,
		},
		CreatedBy: createdBy,
	}

	jsonData, err := json.Marshal(providerReq)
	if err != nil {
		return fmt.Errorf("failed to marshal provider request data: %w", err)
	}

	// Generate service token for authentication
	token, err := generateServiceToken()
	if err != nil {
		return fmt.Errorf("failed to generate service token: %w", err)
	}

	url := fmt.Sprintf("%s/oocmgr/oidc/add-provider", oocManagerURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make HTTP request to OOC Manager: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Read response body for error details
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("OOC Manager add-provider error - Status: %d, Failed to read response body", resp.StatusCode)
		} else {
			log.Printf("OOC Manager add-provider error - Status: %d, Response: %s", resp.StatusCode, string(bodyBytes))
		}
		return fmt.Errorf("OOC Manager API returned status %d", resp.StatusCode)
	}

	log.Printf("Successfully added AuthSec provider for client %s", clientID)
	return nil
}
