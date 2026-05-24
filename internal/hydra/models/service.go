package hydramodels

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/services"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/datatypes"
)

// OAuthLoginService manages OAuth operations
type OAuthLoginService struct {
	cfg config.Config
}

// NewOAuthLoginService creates a new OAuthLoginService
func NewOAuthLoginService(cfg config.Config) *OAuthLoginService {
	return &OAuthLoginService{cfg: cfg}
}

// GetConfig returns the configuration
func (s *OAuthLoginService) GetConfig() config.Config {
	return s.cfg
}

// JWT Claims structure
type JWTClaims struct {
	Audience  []string `json:"aud"`
	ClientID  string   `json:"client_id"`
	ExpiresAt int64    `json:"exp"`
	Ext       struct {
		Email      string `json:"email"`
		Name       string `json:"name"`
		OrgID      string `json:"org_id"`
		Provider   string `json:"provider"`
		ProviderID string `json:"provider_id"`
		TenantID   string `json:"tenant_id"`
		UserID     string `json:"user_id"`
	} `json:"ext"`
	IssuedAt  int64    `json:"iat"`
	Issuer    string   `json:"iss"`
	JWTID     string   `json:"jti"`
	NotBefore int64    `json:"nbf"`
	Scopes    []string `json:"scp"`
	Subject   string   `json:"sub"`
	jwt.RegisteredClaims
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	Kid string   `json:"kid"`
	X5t string   `json:"x5t"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

var jwksCache = make(map[string]*rsa.PublicKey)
var jwksCacheMutex sync.RWMutex

func fetchJWKS(issuer string) (*JWKS, error) {
	jwksURL := strings.TrimSuffix(issuer, "/") + "/.well-known/jwks.json"
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status: %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}
	return &jwks, nil
}

func jwkToRSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode N: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode E: %w", err)
	}
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

func getPublicKey(issuer, kid string) (*rsa.PublicKey, error) {
	jwksCacheMutex.RLock()
	if key, exists := jwksCache[kid]; exists {
		jwksCacheMutex.RUnlock()
		return key, nil
	}
	jwksCacheMutex.RUnlock()

	jwks, err := fetchJWKS(issuer)
	if err != nil {
		return nil, err
	}

	for _, jwk := range jwks.Keys {
		if jwk.Kid == kid {
			publicKey, err := jwkToRSAPublicKey(jwk)
			if err != nil {
				return nil, err
			}
			jwksCacheMutex.Lock()
			jwksCache[kid] = publicKey
			jwksCacheMutex.Unlock()
			return publicKey, nil
		}
	}
	return nil, fmt.Errorf("key with kid %s not found", kid)
}

func DecodeJWTToken(tokenString string) (*JWTClaims, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &JWTClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token header: %w", err)
	}

	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("no kid in token header")
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	issuer := claims.Issuer
	if issuer == "" {
		return nil, fmt.Errorf("no issuer in token")
	}

	publicKey, err := getPublicKey(issuer, kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	verifiedToken, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}

	if verifiedClaims, ok := verifiedToken.Claims.(*JWTClaims); ok && verifiedToken.Valid {
		return verifiedClaims, nil
	}
	return nil, fmt.Errorf("invalid token claims")
}

func (s *OAuthLoginService) CreateOrUpdateUser(accessToken string, users *User) (*User, error) {
	tenantID := users.TenantID
	clientID := users.ClientID
	tenantIDStr := tenantID.String()
	clientIDStr := strings.TrimSuffix(clientID.String(), "-main-client")

	if tenantIDStr == "" || clientIDStr == "" {
		return nil, fmt.Errorf("missing tenant_id or client_id in JWT token")
	}

	db := config.DB

	var client Client
	if err := db.Table("clients").Where("client_id = ? and tenant_id = ?", clientIDStr, tenantIDStr).First(&client).Error; err != nil {
		return nil, fmt.Errorf("failed to get client details: %w", err)
	}

	var existingUser User
	err := db.Table("users").Where(
		"provider = ? AND provider_id = ? AND tenant_id = ? AND client_id = ?",
		users.Provider, users.ProviderID, tenantID, clientID,
	).First(&existingUser).Error

	now := time.Now()
	if err == nil {
		existingUser.ProjectID = client.ProjectID
		existingUser.Name = *users.Username
		existingUser.Email = users.Email
		existingUser.ProviderData = datatypes.JSON(users.ProviderData)
		existingUser.Active = true
		existingUser.UpdatedAt = now

		if err := db.Table("users").Save(&existingUser).Error; err != nil {
			return nil, fmt.Errorf("failed to update user: %w", err)
		}
		return &existingUser, nil
	}

	user := &User{
		ID:           uuid.New(),
		ClientID:     clientID,
		TenantID:     tenantID,
		ProjectID:    client.ProjectID,
		Name:         *users.Username,
		Username:     nil,
		Email:        users.Email,
		Provider:     users.Provider,
		ProviderID:   users.ProviderID,
		ProviderData: datatypes.JSON(users.ProviderData),
		AvatarURL:    nil,
		Active:       true,
		MFAVerified:  false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := db.Table("users").Create(user).Error; err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}
	return user, nil
}

func (s *OAuthLoginService) GetHydraLoginRequest(loginChallenge string) (*HydraLoginRequest, error) {
	reqURL := fmt.Sprintf("%s/admin/oauth2/auth/requests/login?login_challenge=%s",
		s.cfg.HydraAdminURL, loginChallenge)

	resp, err := http.Get(reqURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch login request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	log.Printf("Hydra login request response for challenge %s: %s", loginChallenge, string(bodyBytes))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("login request not found, status code: %d", resp.StatusCode)
	}

	var loginRequest HydraLoginRequest
	if err := json.Unmarshal(bodyBytes, &loginRequest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal login request: %w", err)
	}
	return &loginRequest, nil
}

func (s *OAuthLoginService) AcceptHydraLoginRequestWithContext(loginChallenge, subject string, ctx map[string]interface{}) (*HydraAcceptLoginResponse, error) {
	acceptRequest := HydraAcceptLoginRequest{
		Subject:     subject,
		Remember:    true,
		RememberFor: 3600,
		Context:     ctx,
	}

	jsonData, err := json.Marshal(acceptRequest)
	if err != nil {
		return nil, err
	}

	reqURL := fmt.Sprintf("%s/admin/oauth2/auth/requests/login/accept?login_challenge=%s",
		s.cfg.HydraAdminURL, loginChallenge)

	req, err := http.NewRequest("PUT", reqURL, strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var acceptResponse HydraAcceptLoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&acceptResponse); err != nil {
		return nil, err
	}
	return &acceptResponse, nil
}

// RejectHydraLoginRequest rejects a login challenge with an OIDC-compliant error.
// Used for prompt=none when no session exists (OIDC Core §3.1.2.6).
func (s *OAuthLoginService) RejectHydraLoginRequest(loginChallenge, errorID, errorDescription string) error {
	body := map[string]interface{}{
		"error":             errorID,
		"error_description": errorDescription,
	}
	jsonData, err := json.Marshal(body)
	if err != nil {
		return err
	}

	reqURL := fmt.Sprintf("%s/admin/oauth2/auth/requests/login/reject?login_challenge=%s",
		s.cfg.HydraAdminURL, loginChallenge)

	req, err := http.NewRequest("PUT", reqURL, strings.NewReader(string(jsonData)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Hydra reject login returned %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// RejectHydraConsentRequest rejects a consent challenge with an OAuth-compliant error.
// Used when RBAC resolution determines the user has no grantable scopes (fail-closed).
func (s *OAuthLoginService) RejectHydraConsentRequest(consentChallenge, errorID, errorDescription string) (*HydraAcceptConsentResponse, error) {
	body := map[string]interface{}{
		"error":             errorID,
		"error_description": errorDescription,
	}
	jsonData, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	reqURL := fmt.Sprintf("%s/admin/oauth2/auth/requests/consent/reject?consent_challenge=%s",
		s.cfg.HydraAdminURL, consentChallenge)

	req, err := http.NewRequest("PUT", reqURL, strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Hydra reject consent returned %d: %s", resp.StatusCode, string(respBody))
	}

	var rejectResponse HydraAcceptConsentResponse
	if err := json.NewDecoder(resp.Body).Decode(&rejectResponse); err != nil {
		return nil, err
	}
	return &rejectResponse, nil
}

func (s *OAuthLoginService) GetHydraConsentRequest(consentChallenge string) (*HydraConsentRequest, error) {
	reqURL := fmt.Sprintf("%s/admin/oauth2/auth/requests/consent?consent_challenge=%s",
		s.cfg.HydraAdminURL, consentChallenge)

	resp, err := http.Get(reqURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var consentRequest HydraConsentRequest
	if err := json.NewDecoder(resp.Body).Decode(&consentRequest); err != nil {
		return nil, err
	}
	return &consentRequest, nil
}

func (s *OAuthLoginService) AcceptHydraConsentRequest(consentChallenge string, consentRequest *HydraConsentRequest) (*HydraAcceptConsentResponse, error) {
	userContext := make(map[string]interface{})
	if consentRequest.Context != nil {
		userContext = consentRequest.Context
	}

	acceptRequest := HydraAcceptConsentRequest{
		GrantScope:               consentRequest.RequestedScope,
		GrantAccessTokenAudience: consentRequest.RequestedAccessTokenAudience,
		Remember:                 true,
		RememberFor:              3600,
		Session: map[string]interface{}{
			"access_token": map[string]interface{}{
				"user_id":     consentRequest.Subject,
				"email":       userContext["email"],
				"name":        userContext["name"],
				"provider":    userContext["provider"],
				"provider_id": userContext["provider_id"],
				"tenant_id":   userContext["tenant_id"],
				"org_id":      userContext["org_id"],
			},
			"id_token": map[string]interface{}{
				"user_id":     consentRequest.Subject,
				"email":       userContext["email"],
				"name":        userContext["name"],
				"provider":    userContext["provider"],
				"provider_id": userContext["provider_id"],
				"tenant_id":   userContext["tenant_id"],
				"org_id":      userContext["org_id"],
			},
		},
	}

	jsonData, err := json.Marshal(acceptRequest)
	if err != nil {
		return nil, err
	}

	reqURL := fmt.Sprintf("%s/admin/oauth2/auth/requests/consent/accept?consent_challenge=%s",
		s.cfg.HydraAdminURL, consentChallenge)

	req, err := http.NewRequest("PUT", reqURL, strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var acceptResponse HydraAcceptConsentResponse
	if err := json.NewDecoder(resp.Body).Decode(&acceptResponse); err != nil {
		return nil, err
	}
	return &acceptResponse, nil
}

// AcceptHydraConsentRequestMCP accepts a consent request for the new MCP OAuth path.
// It uses the ScopeResolver-computed scopes and RS-specific audience instead of blindly
// granting all requested scopes/audiences.
func (s *OAuthLoginService) AcceptHydraConsentRequestMCP(
	consentChallenge string,
	consentRequest *HydraConsentRequest,
	grantedScopes []string,
	grantedAudience []string,
	extraSessionClaims map[string]interface{},
) (*HydraAcceptConsentResponse, error) {
	userContext := make(map[string]interface{})
	if consentRequest.Context != nil {
		userContext = consentRequest.Context
	}

	accessTokenSession := map[string]interface{}{
		"user_id":     consentRequest.Subject,
		"email":       userContext["email"],
		"name":        userContext["name"],
		"provider":    userContext["provider"],
		"provider_id": userContext["provider_id"],
	}
	// Merge extra session claims (tenant_id, resource_server_id)
	for k, v := range extraSessionClaims {
		accessTokenSession[k] = v
	}

	acceptRequest := HydraAcceptConsentRequest{
		GrantScope:               grantedScopes,
		GrantAccessTokenAudience: grantedAudience,
		Remember:                 true,
		RememberFor:              3600,
		Session: map[string]interface{}{
			"access_token": accessTokenSession,
			"id_token": map[string]interface{}{
				"user_id":     consentRequest.Subject,
				"email":       userContext["email"],
				"name":        userContext["name"],
				"provider":    userContext["provider"],
				"provider_id": userContext["provider_id"],
			},
		},
	}

	jsonData, err := json.Marshal(acceptRequest)
	if err != nil {
		return nil, err
	}

	reqURL := fmt.Sprintf("%s/admin/oauth2/auth/requests/consent/accept?consent_challenge=%s",
		s.cfg.HydraAdminURL, consentChallenge)

	req, err := http.NewRequest("PUT", reqURL, strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var acceptResponse HydraAcceptConsentResponse
	if err := json.NewDecoder(resp.Body).Decode(&acceptResponse); err != nil {
		return nil, err
	}
	return &acceptResponse, nil
}

func (s *OAuthLoginService) GetHydraClient(clientID string) (*HydraClient, string, error) {
	reqURL := fmt.Sprintf("%s/admin/clients/%s", s.cfg.HydraAdminURL, clientID)

	resp, err := http.Get(reqURL)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch client: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, string(bodyBytes), fmt.Errorf("client not found, status code: %d", resp.StatusCode)
	}

	var client HydraClient
	if err := json.Unmarshal(bodyBytes, &client); err != nil {
		return nil, string(bodyBytes), fmt.Errorf("failed to unmarshal response: %w", err)
	}
	return &client, string(bodyBytes), nil
}

func (s *OAuthLoginService) GetAllHydraClients() ([]HydraClient, error) {
	reqURL := fmt.Sprintf("%s/admin/clients", s.cfg.HydraAdminURL)

	resp, err := http.Get(reqURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var clients []HydraClient
	if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
		return nil, err
	}
	return clients, nil
}

// GetOIDCProvidersForTenant returns the workspace's OIDC providers by joining
// the v4 identity_providers + oidc_providers tables. The workspace_id passed
// in is the workspace UUID (same as legacy tenant_id during the transition).
// Returns providers whose identity_providers row exists and is not disabled.
func (s *OAuthLoginService) GetOIDCProvidersForTenant(workspaceID string) ([]OIDCProvider, error) {
	db := config.DB

	type joinedRow struct {
		ProviderName     string
		DisplayName      string
		ClientID         string
		AuthorizationURL string
		TokenURL         string
		UserinfoURL      string
		Scopes           string
		IconURL          string
		Status           string
	}

	var rows []joinedRow
	err := db.
		Table("oidc_providers op").
		Select(`
			op.provider_name AS provider_name,
			COALESCE(NULLIF(ip.display_name, ''), op.display_name) AS display_name,
			op.client_id AS client_id,
			op.authorization_url AS authorization_url,
			op.token_url AS token_url,
			op.userinfo_url AS userinfo_url,
			op.scopes AS scopes,
			op.icon_url AS icon_url,
			ip.status AS status`).
		Joins(`JOIN identity_providers ip
		         ON ip.workspace_id = op.workspace_id
		        AND ip.provider_type = 'oidc'
		        AND ip.config_ref = op.id::text`).
		Where("op.workspace_id = ?", workspaceID).
		Where("ip.status <> 'disabled'").
		Order("op.provider_name ASC").
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("failed to load workspace OIDC providers: %w", err)
	}

	providers := make([]OIDCProvider, 0, len(rows))
	for i, r := range rows {
		providers = append(providers, OIDCProvider{
			ProviderName: r.ProviderName,
			DisplayName:  r.DisplayName,
			IsActive:     r.Status != "disabled",
			SortOrder:    i, // alphabetical; UI may override
			Config: map[string]interface{}{
				"client_id":         r.ClientID,
				"authorization_url": r.AuthorizationURL,
				"token_url":         r.TokenURL,
				"user_info_url":     r.UserinfoURL,
				"scopes":            r.Scopes,
				"icon_url":          r.IconURL,
			},
		})
	}
	return providers, nil
}

func (s *OAuthLoginService) GetUIAccessToken(ctx context.Context, req string) (*TokenResponse, error) {
	resp, err := services.IssueOIDCJWT(ctx, req)
	if err != nil {
		return nil, err
	}
	return &TokenResponse{
		AccessToken: resp.AccessToken,
		TokenType:   resp.TokenType,
		ExpiresIn:   int(resp.ExpiresIn),
	}, nil
}
