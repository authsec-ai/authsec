package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/vault"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

var (
	ErrNotConnected       = errors.New("not_connected")
	ErrTokenRefreshFailed = errors.New("token_refresh_failed")
)

// TokenResponse is returned by GetToken.
type TokenResponse struct {
	AccessToken string     `json:"access_token"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Scopes      []string   `json:"scopes"`
}

// ConnectURLs is returned by InitiateConnect.
type ConnectURLs struct {
	AuthorizeURL string `json:"url"`
	CallbackURL  string `json:"callback_url"`
}

type oauthStateClaims struct {
	ServiceID     string `json:"service_id"`
	UserID        string `json:"user_id"`
	WorkspaceID   string `json:"workspace_id"`
	RedirectAfter string `json:"redirect_after"`
	Nonce         string `json:"nonce"`
	jwt.RegisteredClaims
}

type providerTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

// OAuthConnectService handles the OAuth connect flow and per-user token management.
type OAuthConnectService struct {
	serviceRepo repositories.ExternalServiceRepository
	tokenRepo   repositories.ServiceUserTokenRepository
	vault       vault.VaultClient
	jwtSecret   []byte
	appBaseURL  string
}

// NewOAuthConnectService constructs an OAuthConnectService.
func NewOAuthConnectService(
	serviceRepo repositories.ExternalServiceRepository,
	tokenRepo repositories.ServiceUserTokenRepository,
	vaultClient vault.VaultClient,
) *OAuthConnectService {
	baseURL := ""
	if config.AppConfig != nil {
		baseURL = strings.TrimRight(config.AppConfig.BaseURL, "/")
	}
	return &OAuthConnectService{
		serviceRepo: serviceRepo,
		tokenRepo:   tokenRepo,
		vault:       vaultClient,
		jwtSecret:   []byte(os.Getenv("JWT_SECRET")),
		appBaseURL:  baseURL,
	}
}

// InitiateConnect builds the provider authorization URL and returns it with the callback URL.
func (s *OAuthConnectService) InitiateConnect(serviceID, userID, workspaceID, redirectAfter string) (ConnectURLs, error) {
	svc, err := s.serviceRepo.GetByID(serviceID)
	if err != nil {
		return ConnectURLs{}, fmt.Errorf("service not found")
	}
	if svc.AuthType != "oauth2_code" {
		return ConnectURLs{}, fmt.Errorf("service auth_type is not oauth2_code")
	}

	authorizeURL := svc.OAuthAuthorizeURL
	tokenURL := svc.OAuthTokenURL

	if svc.OAuthProvider == "microsoft" && svc.AuthConfig != "" {
		var cfg map[string]string
		if json.Unmarshal([]byte(svc.AuthConfig), &cfg) == nil {
			if msTenantID, ok := cfg["ms_tenant_id"]; ok {
				authorizeURL, tokenURL = ApplyMSTenantID(authorizeURL, tokenURL, msTenantID)
				_ = tokenURL
			}
		}
	}

	callbackURL := fmt.Sprintf("%s/authsec/exsvc/oauth/callback/%s", s.appBaseURL, workspaceID)
	scopes := []string(svc.OAuthDefaultScopes)

	claims := oauthStateClaims{
		ServiceID:     serviceID,
		UserID:        userID,
		WorkspaceID:   workspaceID,
		RedirectAfter: redirectAfter,
		Nonce:         uuid.NewString(),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	stateJWT, err := tok.SignedString(s.jwtSecret)
	if err != nil {
		return ConnectURLs{}, fmt.Errorf("failed to sign state JWT: %w", err)
	}

	secrets, err := s.vault.ReadSecret(svc.VaultPath)
	if err != nil {
		return ConnectURLs{}, fmt.Errorf("failed to read service credentials from vault: %w", err)
	}
	clientID, _ := secrets["client_id"].(string)

	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", callbackURL)
	params.Set("scope", strings.Join(scopes, " "))
	params.Set("state", stateJWT)
	params.Set("response_type", "code")
	if svc.OAuthProvider == "google" {
		params.Set("access_type", "offline")
		params.Set("prompt", "consent")
	}

	fullAuthorizeURL := fmt.Sprintf("%s?%s", authorizeURL, params.Encode())
	return ConnectURLs{AuthorizeURL: fullAuthorizeURL, CallbackURL: callbackURL}, nil
}

// HandleCallback processes the OAuth callback: exchanges the code for tokens,
// stores them in Vault, and upserts the service_user_tokens row.
// Returns the redirect_after URL (for the HTTP redirect) and any error.
func (s *OAuthConnectService) HandleCallback(workspaceID, code, stateJWT string) (string, error) {
	var claims oauthStateClaims
	tok, err := jwt.ParseWithClaims(stateJWT, &claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.jwtSecret, nil
	})
	if err != nil || !tok.Valid {
		return "", fmt.Errorf("invalid state token")
	}
	if claims.WorkspaceID != workspaceID {
		return claims.RedirectAfter, fmt.Errorf("workspace mismatch in state")
	}

	svc, err := s.serviceRepo.GetByID(claims.ServiceID)
	if err != nil {
		return claims.RedirectAfter, fmt.Errorf("service not found")
	}

	tokenURL := svc.OAuthTokenURL
	if svc.OAuthProvider == "microsoft" && svc.AuthConfig != "" {
		var cfg map[string]string
		if json.Unmarshal([]byte(svc.AuthConfig), &cfg) == nil {
			if msTenantID, ok := cfg["ms_tenant_id"]; ok {
				_, tokenURL = ApplyMSTenantID(svc.OAuthAuthorizeURL, tokenURL, msTenantID)
			}
		}
	}

	secrets, err := s.vault.ReadSecret(svc.VaultPath)
	if err != nil {
		return claims.RedirectAfter, fmt.Errorf("failed to read service credentials")
	}
	clientID, _ := secrets["client_id"].(string)
	clientSecret, _ := secrets["client_secret"].(string)

	callbackURL := fmt.Sprintf("%s/authsec/exsvc/oauth/callback/%s", s.appBaseURL, workspaceID)

	providerResp, err := s.exchangeCode(tokenURL, clientID, clientSecret, callbackURL, code)
	if err != nil {
		return claims.RedirectAfter, err
	}

	userVaultPath := fmt.Sprintf("kv/data/secret/workspaces/%s/users/%s/services/%s",
		workspaceID, claims.UserID, claims.ServiceID)
	vaultData := map[string]interface{}{
		"access_token":  providerResp.AccessToken,
		"refresh_token": providerResp.RefreshToken,
		"token_type":    providerResp.TokenType,
		"scope":         providerResp.Scope,
	}
	if err := s.vault.WriteSecret(userVaultPath, vaultData); err != nil {
		return claims.RedirectAfter, fmt.Errorf("failed to store tokens in vault: %w", err)
	}

	var expiresAt *time.Time
	if providerResp.ExpiresIn > 0 {
		t := time.Now().Add(time.Duration(providerResp.ExpiresIn) * time.Second)
		expiresAt = &t
	}

	var scopes pq.StringArray
	if providerResp.Scope != "" {
		scopes = pq.StringArray(strings.Fields(providerResp.Scope))
	}

	tokenRow := &repositories.ServiceUserToken{
		ID:          uuid.NewString(),
		ServiceID:   claims.ServiceID,
		UserID:      claims.UserID,
		WorkspaceID: workspaceID,
		VaultPath:   userVaultPath,
		Scopes:      scopes,
		ExpiresAt:   expiresAt,
		ConnectedAt: time.Now(),
		UpdatedAt:   time.Now(),
	}
	if err := s.tokenRepo.Upsert(tokenRow); err != nil {
		return claims.RedirectAfter, fmt.Errorf("failed to save token record: %w", err)
	}

	return claims.RedirectAfter, nil
}

// GetToken returns a fresh access token for the user, auto-refreshing if needed.
// Returns (token, connectURL, error). connectURL is non-empty only on ErrNotConnected or ErrTokenRefreshFailed.
func (s *OAuthConnectService) GetToken(serviceID, userID, workspaceID string) (*TokenResponse, string, error) {
	connectURL := fmt.Sprintf("/authsec/exsvc/services/%s/connect", serviceID)

	row, err := s.tokenRepo.GetByServiceAndUser(serviceID, userID)
	if err != nil {
		return nil, connectURL, ErrNotConnected
	}

	needsRefresh := row.ExpiresAt != nil && row.ExpiresAt.Before(time.Now().Add(5*time.Minute))
	if needsRefresh {
		return s.refreshToken(row, serviceID, workspaceID)
	}

	secrets, err := s.vault.ReadSecret(row.VaultPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read token from vault: %w", err)
	}
	accessToken, _ := secrets["access_token"].(string)

	return &TokenResponse{
		AccessToken: accessToken,
		ExpiresAt:   row.ExpiresAt,
		Scopes:      []string(row.Scopes),
	}, "", nil
}

func (s *OAuthConnectService) refreshToken(row *repositories.ServiceUserToken, serviceID, workspaceID string) (*TokenResponse, string, error) {
	connectURL := fmt.Sprintf("/authsec/exsvc/services/%s/connect", serviceID)

	vaultSecrets, err := s.vault.ReadSecret(row.VaultPath)
	if err != nil {
		return nil, connectURL, ErrTokenRefreshFailed
	}
	refreshToken, _ := vaultSecrets["refresh_token"].(string)
	if refreshToken == "" {
		row.RefreshError = "no refresh token available"
		row.UpdatedAt = time.Now()
		_ = s.tokenRepo.Update(row)
		return nil, connectURL, ErrTokenRefreshFailed
	}

	svc, err := s.serviceRepo.GetByID(serviceID)
	if err != nil {
		return nil, connectURL, ErrTokenRefreshFailed
	}

	tokenURL := svc.OAuthTokenURL
	if svc.OAuthProvider == "microsoft" && svc.AuthConfig != "" {
		var cfg map[string]string
		if json.Unmarshal([]byte(svc.AuthConfig), &cfg) == nil {
			if msTenantID, ok := cfg["ms_tenant_id"]; ok {
				_, tokenURL = ApplyMSTenantID(svc.OAuthAuthorizeURL, tokenURL, msTenantID)
			}
		}
	}

	svcSecrets, err := s.vault.ReadSecret(svc.VaultPath)
	if err != nil {
		return nil, connectURL, ErrTokenRefreshFailed
	}
	clientID, _ := svcSecrets["client_id"].(string)
	clientSecret, _ := svcSecrets["client_secret"].(string)

	form := url.Values{}
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("grant_type", "refresh_token")

	req, _ := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	httpClient := &http.Client{Timeout: 10 * time.Second}
	res, err := httpClient.Do(req)
	if err != nil {
		row.RefreshError = err.Error()
		row.UpdatedAt = time.Now()
		_ = s.tokenRepo.Update(row)
		return nil, connectURL, ErrTokenRefreshFailed
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)

	if res.StatusCode >= 400 {
		row.RefreshError = fmt.Sprintf("provider returned %d: %s", res.StatusCode, string(body))
		row.UpdatedAt = time.Now()
		_ = s.tokenRepo.Update(row)
		return nil, connectURL, ErrTokenRefreshFailed
	}

	var providerResp providerTokenResponse
	if err := json.Unmarshal(body, &providerResp); err != nil {
		row.RefreshError = "failed to parse refresh response"
		row.UpdatedAt = time.Now()
		_ = s.tokenRepo.Update(row)
		return nil, connectURL, ErrTokenRefreshFailed
	}

	newVaultData := map[string]interface{}{
		"access_token": providerResp.AccessToken,
		"token_type":   providerResp.TokenType,
		"scope":        providerResp.Scope,
	}
	if providerResp.RefreshToken != "" {
		newVaultData["refresh_token"] = providerResp.RefreshToken
	} else {
		newVaultData["refresh_token"] = refreshToken
	}
	if err := s.vault.WriteSecret(row.VaultPath, newVaultData); err != nil {
		return nil, connectURL, ErrTokenRefreshFailed
	}

	var expiresAt *time.Time
	if providerResp.ExpiresIn > 0 {
		t := time.Now().Add(time.Duration(providerResp.ExpiresIn) * time.Second)
		expiresAt = &t
	}
	row.ExpiresAt = expiresAt
	row.RefreshError = ""
	row.UpdatedAt = time.Now()
	if providerResp.Scope != "" {
		row.Scopes = pq.StringArray(strings.Fields(providerResp.Scope))
	}
	_ = s.tokenRepo.Update(row)

	return &TokenResponse{
		AccessToken: providerResp.AccessToken,
		ExpiresAt:   expiresAt,
		Scopes:      []string(row.Scopes),
	}, "", nil
}

// DisconnectUser removes the user's token from Vault and the DB.
func (s *OAuthConnectService) DisconnectUser(serviceID, userID string) error {
	row, err := s.tokenRepo.GetByServiceAndUser(serviceID, userID)
	if err != nil {
		return nil // already disconnected
	}
	if s.vault != nil && row.VaultPath != "" {
		_ = s.vault.DeleteSecret(row.VaultPath) // best effort
	}
	return s.tokenRepo.DeleteByServiceAndUser(serviceID, userID)
}

// ListConnections returns all user token rows for a service (admin use).
func (s *OAuthConnectService) ListConnections(serviceID string) ([]repositories.ServiceUserToken, error) {
	return s.tokenRepo.ListByService(serviceID)
}

func (s *OAuthConnectService) exchangeCode(tokenURL, clientID, clientSecret, redirectURI, code string) (*providerTokenResponse, error) {
	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("redirect_uri", redirectURI)
	form.Set("grant_type", "authorization_code")

	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	httpClient := &http.Client{Timeout: 10 * time.Second}
	res, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)

	if res.StatusCode >= 400 {
		return nil, fmt.Errorf("token exchange failed (status %d): %s", res.StatusCode, string(body))
	}

	var resp providerTokenResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	return &resp, nil
}
