package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/authsec-ai/authsec/config"
)

// hydraClient mirrors the Hydra admin API client object used for direct calls.
type hydraClient struct {
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

func hydraAdminURL() string {
	return config.AppConfig.HydraAdminURL
}

func hydraAdminGetClient(clientID string) (*hydraClient, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/admin/clients/%s", hydraAdminURL(), clientID), nil)
	if err != nil {
		return nil, err
	}
	resp, err := CircuitDoHydra(req)
	if err != nil {
		return nil, fmt.Errorf("hydra get client: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hydra get client status %d", resp.StatusCode)
	}
	var c hydraClient
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return nil, fmt.Errorf("hydra get client decode: %w", err)
	}
	return &c, nil
}

func hydraAdminCreateClient(c hydraClient) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/admin/clients", hydraAdminURL()), bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := CircuitDoHydra(req)
	if err != nil {
		return fmt.Errorf("hydra create client: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("hydra create client status %d: %s", resp.StatusCode, body)
	}
	return nil
}

func hydraAdminUpdateClient(clientID string, c hydraClient) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("PUT", fmt.Sprintf("%s/admin/clients/%s", hydraAdminURL(), clientID), bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := CircuitDoHydra(req)
	if err != nil {
		return fmt.Errorf("hydra update client: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("hydra update client status %d: %s", resp.StatusCode, body)
	}
	return nil
}

func hydraAdminDeleteClient(clientID string) error {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/admin/clients/%s", hydraAdminURL(), clientID), nil)
	if err != nil {
		return err
	}
	resp, err := CircuitDoHydra(req)
	if err != nil {
		return fmt.Errorf("hydra delete client: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("hydra delete client status %d: %s", resp.StatusCode, body)
	}
	return nil
}

// hydraAdminDeleteClientTokens flushes all access tokens Hydra has issued to a
// client. Used when an admin revokes the client's LAST approved registration —
// per-app gating is enforced at introspection, this is Hydra-side hygiene so
// dead tokens don't linger until TTL. 204 and 404 both count as success
// (idempotent: nothing to flush is fine).
func hydraAdminDeleteClientTokens(clientID string) error {
	req, err := http.NewRequest("DELETE",
		fmt.Sprintf("%s/admin/oauth2/tokens?client_id=%s", hydraAdminURL(), url.QueryEscape(clientID)), nil)
	if err != nil {
		return err
	}
	resp, err := CircuitDoHydra(req)
	if err != nil {
		return fmt.Errorf("hydra delete client tokens: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("hydra delete client tokens status %d: %s", resp.StatusCode, body)
	}
	return nil
}

func hydraAdminGetAllClients() ([]hydraClient, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/admin/clients", hydraAdminURL()), nil)
	if err != nil {
		return nil, err
	}
	resp, err := CircuitDoHydra(req)
	if err != nil {
		return nil, fmt.Errorf("hydra get all clients: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hydra get all clients status %d", resp.StatusCode)
	}
	var clients []hydraClient
	if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
		return nil, fmt.Errorf("hydra get all clients decode: %w", err)
	}
	return clients, nil
}

// PushAuthorizationRequest sends authorization params to Hydra via PAR (RFC 9126).
// Server-to-server call using CircuitDoHydra. Returns (request_uri, expires_in_seconds, error).
func PushAuthorizationRequest(params url.Values) (string, int, error) {
	parURL := config.AppConfig.HydraPublicURL + "/oauth2/par"
	req, err := http.NewRequest("POST", parURL, strings.NewReader(params.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("PAR build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := CircuitDoHydra(req)
	if err != nil {
		return "", 0, fmt.Errorf("PAR request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return "", 0, fmt.Errorf("PAR status %d: %s", resp.StatusCode, body)
	}

	var parResp struct {
		RequestURI string `json:"request_uri"`
		ExpiresIn  int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &parResp); err != nil {
		return "", 0, fmt.Errorf("PAR decode: %w", err)
	}
	if parResp.RequestURI == "" {
		return "", 0, fmt.Errorf("PAR response missing request_uri")
	}
	return parResp.RequestURI, parResp.ExpiresIn, nil
}

// RegisterHydraClientWithParams creates a Hydra client with full control over parameters.
// Used by DCR and CIMD flows where the client needs specific audience and scope configuration.
func RegisterHydraClientWithParams(clientID, clientName string, redirectURIs []string, audience []string, scope string) error {
	return hydraAdminCreateClient(hydraClient{
		ClientID:      clientID,
		ClientName:    clientName,
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		RedirectURIs:  redirectURIs,
		ResponseTypes: []string{"code"},
		TokenEndpoint: "none",
		Scope:         scope,
		Audience:      audience,
	})
}

// OOCManager represents the request structure for OOC Manager API
type OOCManager struct {
	WorkspaceID     string   `json:"workspace_id" validate:"required"`
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
	WorkspaceID    string         `json:"workspace_id"`
	ClientID    string         `json:"client_id"`
	ReactAppURL string         `json:"react_app_url"`
	Provider    ProviderConfig `json:"provider"`
	CreatedBy   string         `json:"created_by"`
}

// DeleteClientFromHydra removes all Hydra clients belonging to the tenant directly.
func DeleteClientFromHydra(clientID string) error {
	clients, err := hydraAdminGetAllClients()
	if err != nil {
		return fmt.Errorf("failed to list Hydra clients: %w", err)
	}

	deleted := 0
	for _, c := range clients {
		cID, _ := c.Metadata["c_id"].(string)
		wID, _ := c.Metadata["workspace_id"].(string)
		if cID != clientID && wID != clientID {
			continue
		}
		if err := hydraAdminDeleteClient(c.ClientID); err != nil {
			log.Printf("Warning: failed to delete Hydra client %s: %v", c.ClientID, err)
		} else {
			deleted++
		}
	}

	log.Printf("Deleted %d Hydra client(s) for clientID=%s", deleted, clientID)
	return nil
}

