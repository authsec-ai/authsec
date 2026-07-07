package services

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ConnectorOAuthService drives the connect-once OAuth flow: it builds the
// provider authorize URL (state + PKCE), then on callback exchanges the code for
// tokens and stores them as a workspace-scope Connection (secret → Vault, only
// lifecycle metadata in Postgres).
type ConnectorOAuthService struct {
	db    *gorm.DB
	repo  repositories.ConnectorRepository
	vault vault.VaultClient
}

// NewConnectorOAuthService constructs the service.
func NewConnectorOAuthService(db *gorm.DB, vaultClient vault.VaultClient) *ConnectorOAuthService {
	return &ConnectorOAuthService{db: db, repo: repositories.NewConnectorRepository(db), vault: vaultClient}
}

const connectStateTTL = 10 * time.Minute

// StartResult is returned to the admin UI to begin the provider consent flow.
type StartResult struct {
	AuthorizeURL string `json:"authorize_url"`
	State        string `json:"state"`
}

// Start builds the provider authorize URL for a workspace-scope connect and
// persists the CSRF/PKCE state. redirectAfter is the UI page to return to.
func (s *ConnectorOAuthService) Start(workspaceID, connectorID uuid.UUID, createdBy, redirectAfter string, scopes []string) (*StartResult, error) {
	conn, err := s.repo.GetByID(workspaceID, connectorID)
	if err != nil {
		return nil, errors.New("connector not found")
	}
	provider, err := s.repo.GetProvider(conn.ProviderKey)
	if err != nil {
		return nil, fmt.Errorf("unknown provider %q", conn.ProviderKey)
	}
	if !providerSupports(provider.SupportedAuthMethods, models.ConnectionAuthOAuth2) || provider.OAuthAuthorizeURL == "" {
		return nil, fmt.Errorf("provider %q is not OAuth2", provider.Key)
	}

	clientID, _, redirectURI, cErr := s.resolveProviderApp(workspaceID, provider.Key)
	if cErr != nil {
		return nil, cErr
	}

	requested := scopes
	if len(requested) == 0 {
		requested = provider.OAuthDefaultScopes
	}

	state, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	verifier, err := randomToken(48)
	if err != nil {
		return nil, err
	}
	challenge := pkceS256(verifier)

	st := &models.ConnectorOAuthState{
		State:         state,
		WorkspaceID:   workspaceID,
		ConnectorID:   connectorID,
		ProviderKey:   provider.Key,
		BindingType:   models.ConnectionScopeWorkspace,
		CodeVerifier:  verifier,
		RedirectAfter: redirectAfter,
		CreatedBy:     createdBy,
		ExpiresAt:     time.Now().Add(connectStateTTL),
	}
	if err := s.db.Create(st).Error; err != nil {
		return nil, fmt.Errorf("persist state: %w", err)
	}

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	if len(requested) > 0 {
		q.Set("scope", strings.Join(requested, " "))
	}
	// Providers that need explicit offline consent to return a refresh token.
	if provider.Key == "google" {
		q.Set("access_type", "offline")
		q.Set("prompt", "consent")
	}

	sep := "?"
	if strings.Contains(provider.OAuthAuthorizeURL, "?") {
		sep = "&"
	}
	return &StartResult{
		AuthorizeURL: provider.OAuthAuthorizeURL + sep + q.Encode(),
		State:        state,
	}, nil
}

// CallbackResult tells the caller where to redirect the browser back to.
type CallbackResult struct {
	RedirectAfter string
	ConnectorID   uuid.UUID
}

// HandleCallback validates the state, exchanges the code for tokens, and stores
// the resulting workspace-scope Connection (secret → Vault). One-shot: the state
// row is deleted regardless of outcome.
func (s *ConnectorOAuthService) HandleCallback(code, state string) (*CallbackResult, error) {
	if code == "" || state == "" {
		return nil, errors.New("missing code or state")
	}
	var st models.ConnectorOAuthState
	if err := s.db.First(&st, "state = ?", state).Error; err != nil {
		return nil, errors.New("invalid or expired state")
	}
	// One-shot: consume the state now.
	s.db.Delete(&models.ConnectorOAuthState{}, "state = ?", state)
	if time.Now().After(st.ExpiresAt) {
		return nil, errors.New("state expired")
	}

	provider, err := s.repo.GetProvider(st.ProviderKey)
	if err != nil {
		return nil, fmt.Errorf("unknown provider %q", st.ProviderKey)
	}
	clientID, clientSecret, redirectURI, cErr := s.resolveProviderApp(st.WorkspaceID, provider.Key)
	if cErr != nil {
		return nil, cErr
	}

	tok, err := s.exchangeCode(provider, clientID, clientSecret, redirectURI, code, st.CodeVerifier)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}

	// Store secret material in Vault; only metadata in Postgres.
	vaultPath := fmt.Sprintf("kv/data/secret/workspaces/%s/connectors/%s/connection", st.WorkspaceID, st.ConnectorID)
	secret := map[string]interface{}{"access_token": tok.AccessToken}
	if tok.RefreshToken != "" {
		secret["refresh_token"] = tok.RefreshToken
	}
	if tok.TokenType != "" {
		secret["token_type"] = tok.TokenType
	}
	if s.vault == nil {
		return nil, errors.New("vault client not configured")
	}
	if err := s.vault.WriteSecret(vaultPath, secret); err != nil {
		return nil, fmt.Errorf("store token: %w", err)
	}

	var expiresAt *time.Time
	if tok.ExpiresIn > 0 {
		t := time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
		expiresAt = &t
	}
	// Upsert the workspace-scope Connection (one per connector).
	existing, _ := s.repo.GetWorkspaceConnection(st.ConnectorID)
	conn := &models.ConnectorConnection{
		ConnectorID:         st.ConnectorID,
		Scope:               models.ConnectionScopeWorkspace,
		Status:              models.ConnectionStatusActive,
		AuthType:            models.ConnectionAuthOAuth2,
		VaultPath:           vaultPath,
		ScopesGranted:       strings.Fields(tok.Scope),
		AccessExpiresAt:     expiresAt,
		RefreshTokenPresent: tok.RefreshToken != "",
	}
	if existing != nil {
		conn.ID = existing.ID
		if err := s.db.Save(conn).Error; err != nil {
			return nil, fmt.Errorf("update connection: %w", err)
		}
	} else if err := s.repo.CreateConnection(conn); err != nil {
		return nil, fmt.Errorf("create connection: %w", err)
	}

	return &CallbackResult{RedirectAfter: st.RedirectAfter, ConnectorID: st.ConnectorID}, nil
}

// --- token exchange ----------------------------------------------------------

type tokenResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	Error        string `json:"error"`
}

func (s *ConnectorOAuthService) exchangeCode(provider *models.ConnectorProvider, clientID, clientSecret, redirectURI, code, verifier string) (*tokenResp, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code_verifier", verifier)

	req, err := http.NewRequest(http.MethodPost, provider.OAuthTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("provider token endpoint %d", resp.StatusCode)
	}
	tok, err := parseTokenResponse(body)
	if err != nil {
		return nil, err
	}
	if tok.AccessToken == "" || tok.Error != "" {
		return nil, fmt.Errorf("no access token (err=%q)", tok.Error)
	}
	return tok, nil
}

// --- helpers -----------------------------------------------------------------

// SetProviderApp configures a workspace's own OAuth app for a provider: stores
// the client_secret in Vault and upserts the client_id/redirect_uri row. This is
// how a workspace brings its own OAuth app instead of the deployment-wide env one.
func (s *ConnectorOAuthService) SetProviderApp(workspaceID uuid.UUID, providerKey, clientID, clientSecret, redirectURI, createdBy string) error {
	if clientID == "" || redirectURI == "" {
		return errors.New("client_id and redirect_uri are required")
	}
	if _, err := s.repo.GetProvider(providerKey); err != nil {
		return fmt.Errorf("unknown provider %q", providerKey)
	}
	vaultPath := fmt.Sprintf("kv/data/secret/workspaces/%s/provider-apps/%s", workspaceID.String(), providerKey)
	if clientSecret != "" {
		if s.vault == nil {
			return errors.New("vault client not configured")
		}
		if err := s.vault.WriteSecret(vaultPath, map[string]interface{}{"client_secret": clientSecret}); err != nil {
			return fmt.Errorf("store client secret: %w", err)
		}
	}
	return s.repo.UpsertProviderApp(&models.ConnectorProviderApp{
		WorkspaceID: workspaceID,
		ProviderKey: providerKey,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		VaultPath:   vaultPath,
		CreatedBy:   createdBy,
	})
}

// resolveProviderApp returns the OAuth app credentials for (workspace, provider):
// a workspace-specific app (client_id in DB, secret in Vault) takes precedence,
// else the global env vars CONNECTOR_OAUTH_<P>_CLIENT_ID/_SECRET/_REDIRECT_URI.
// Lets a workspace bring its own OAuth app while keeping the deployment-wide
// default working. The secret is read from Vault only for the DB path.
func (s *ConnectorOAuthService) resolveProviderApp(workspaceID uuid.UUID, providerKey string) (clientID, clientSecret, redirectURI string, err error) {
	// 1. Workspace-specific app (DB row + Vault secret).
	if app, e := s.repo.GetProviderApp(workspaceID, providerKey); e == nil && app != nil {
		secret := ""
		if s.vault != nil && app.VaultPath != "" {
			if sec, e2 := s.vault.ReadSecret(app.VaultPath); e2 == nil {
				if v, ok := sec["client_secret"].(string); ok {
					secret = v
				}
			}
		}
		if app.ClientID != "" && app.RedirectURI != "" {
			return app.ClientID, secret, app.RedirectURI, nil
		}
	}

	// 2. Global env fallback.
	p := strings.ToUpper(providerKey)
	clientID = os.Getenv("CONNECTOR_OAUTH_" + p + "_CLIENT_ID")
	clientSecret = os.Getenv("CONNECTOR_OAUTH_" + p + "_CLIENT_SECRET")
	redirectURI = os.Getenv("CONNECTOR_OAUTH_" + p + "_REDIRECT_URI")
	if redirectURI == "" {
		redirectURI = os.Getenv("CONNECTOR_OAUTH_REDIRECT_URI")
	}
	if clientID == "" || redirectURI == "" {
		return "", "", "", fmt.Errorf("OAuth app not configured for provider %q in workspace %s (set a workspace provider app, or CONNECTOR_OAUTH_%s_CLIENT_ID / _REDIRECT_URI)", providerKey, workspaceID, p)
	}
	return clientID, clientSecret, redirectURI, nil
}

func providerSupports(methods []string, want string) bool {
	for _, m := range methods {
		if m == want {
			return true
		}
	}
	return false
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// parseTokenResponse handles both JSON (most providers) and form-encoded
// (GitHub's default) token responses.
func parseTokenResponse(body []byte) (*tokenResp, error) {
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "{") {
		var tok tokenResp
		if err := json.Unmarshal(body, &tok); err != nil {
			return nil, err
		}
		return &tok, nil
	}
	// form-encoded: access_token=...&token_type=...&scope=...
	vals, err := url.ParseQuery(trimmed)
	if err != nil {
		return nil, err
	}
	return &tokenResp{
		AccessToken:  vals.Get("access_token"),
		RefreshToken: vals.Get("refresh_token"),
		TokenType:    vals.Get("token_type"),
		Scope:        vals.Get("scope"),
		Error:        vals.Get("error"),
	}, nil
}

// Refresh performs an on-demand refresh of a workspace connection's OAuth token
// using its stored refresh_token, updates the Vault secret + lifecycle metadata.
// Called before an action when the access token is near/after expiry.
func (s *ConnectorOAuthService) Refresh(conn *models.ConnectorConnection) error {
	if !conn.RefreshTokenPresent || conn.VaultPath == "" {
		return errors.New("no refresh token available")
	}
	providerKey, workspaceID := connectorContextForConnection(s.db, conn)
	provider, err := s.repo.GetProvider(providerKey)
	if err != nil {
		return err
	}
	clientID, clientSecret, _, cErr := s.resolveProviderApp(workspaceID, provider.Key)
	if cErr != nil {
		return cErr
	}
	if s.vault == nil {
		return errors.New("vault client not configured")
	}
	secret, err := s.vault.ReadSecret(conn.VaultPath)
	if err != nil {
		return fmt.Errorf("read secret: %w", err)
	}
	refreshTok, _ := secret["refresh_token"].(string)
	if refreshTok == "" {
		return errors.New("stored refresh token empty")
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshTok)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)

	req, err := http.NewRequest(http.MethodPost, provider.OAuthTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		s.markRefreshError(conn, err.Error())
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		s.markRefreshError(conn, fmt.Sprintf("refresh %d", resp.StatusCode))
		return fmt.Errorf("refresh endpoint %d", resp.StatusCode)
	}
	tok, err := parseTokenResponse(body)
	if err != nil || tok.AccessToken == "" {
		s.markRefreshError(conn, "no access token on refresh")
		return errors.New("no access token on refresh")
	}

	secret["access_token"] = tok.AccessToken
	if tok.RefreshToken != "" {
		secret["refresh_token"] = tok.RefreshToken // rotation
	}
	if err := s.vault.WriteSecret(conn.VaultPath, secret); err != nil {
		return fmt.Errorf("write refreshed token: %w", err)
	}

	now := time.Now()
	conn.LastRefreshAt = &now
	conn.LastRefreshError = ""
	conn.Status = models.ConnectionStatusActive
	if tok.ExpiresIn > 0 {
		t := now.Add(time.Duration(tok.ExpiresIn) * time.Second)
		conn.AccessExpiresAt = &t
	}
	return s.db.Save(conn).Error
}

func (s *ConnectorOAuthService) markRefreshError(conn *models.ConnectorConnection, msg string) {
	now := time.Now()
	conn.LastRefreshAt = &now
	conn.LastRefreshError = msg
	conn.Status = models.ConnectionStatusError
	s.db.Save(conn)
}

// connectorContextForConnection resolves the provider key + workspace id from
// the connection's connector (the connection row stores neither).
func connectorContextForConnection(db *gorm.DB, conn *models.ConnectorConnection) (providerKey string, workspaceID uuid.UUID) {
	var row struct {
		ProviderKey string
		WorkspaceID uuid.UUID
	}
	db.Table("connectors").Select("provider_key, workspace_id").
		Where("id = ?", conn.ConnectorID).Limit(1).Scan(&row)
	return row.ProviderKey, row.WorkspaceID
}
