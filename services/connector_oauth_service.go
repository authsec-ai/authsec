package services

import (
	"context"
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

	"github.com/authsec-ai/authsec/internal/connectoradapters"
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

// Start builds the provider authorize URL for a workspace-scope connect (the
// shared org credential) and persists the CSRF/PKCE state.
func (s *ConnectorOAuthService) Start(workspaceID, connectorID uuid.UUID, createdBy, redirectAfter string, scopes []string) (*StartResult, error) {
	return s.startConnect(workspaceID, connectorID, models.ConnectionBindingWorkspace, nil, createdBy, redirectAfter, scopes)
}

// StartUser builds the authorize URL for a USER-scope connect (R4): an
// authenticated end-user consents to the provider for their own account. The
// resulting connection is keyed by subjectUserID and resolved by the broker when
// a delegated (XAA) token carries sub=this user. subjectUserID is the caller's
// own local user UUID (from their session) — never a value they supply.
func (s *ConnectorOAuthService) StartUser(workspaceID, connectorID, subjectUserID uuid.UUID, redirectAfter string, scopes []string) (*StartResult, error) {
	sid := subjectUserID
	return s.startConnect(workspaceID, connectorID, models.ConnectionBindingUser, &sid, subjectUserID.String(), redirectAfter, scopes)
}

// ListUserConnections returns a user's own provider connections in a workspace
// (their "connected accounts"). R4.
func (s *ConnectorOAuthService) ListUserConnections(workspaceID, subjectUserID uuid.UUID) ([]models.ConnectorConnection, error) {
	return s.repo.ListUserConnectionsBySubject(workspaceID, subjectUserID.String())
}

// RevokeUserConnection lets a user disconnect their own provider account for a
// connector: marks the connection revoked (broker then fails closed) and best-
// effort deletes the Vault secret. R4.
func (s *ConnectorOAuthService) RevokeUserConnection(workspaceID, connectorID, subjectUserID uuid.UUID) error {
	// Grab the row first so we can clear its Vault secret after revoking.
	existing, _ := s.repo.GetUserConnection(connectorID, subjectUserID.String())
	n, err := s.repo.RevokeUserConnection(workspaceID, connectorID, subjectUserID.String())
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("no user connection to revoke")
	}
	if existing != nil && s.vault != nil && existing.VaultPath != "" {
		_ = s.vault.DeleteSecret(existing.VaultPath) // best-effort
	}
	return nil
}

func (s *ConnectorOAuthService) startConnect(workspaceID, connectorID uuid.UUID, bindingType string, subjectUserID *uuid.UUID, createdBy, redirectAfter string, scopes []string) (*StartResult, error) {
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

	var subjStr *string
	if subjectUserID != nil {
		v := subjectUserID.String()
		subjStr = &v
	}
	st := &models.ConnectorOAuthState{
		State:         state,
		WorkspaceID:   workspaceID,
		ConnectorID:   connectorID,
		ProviderKey:   provider.Key,
		BindingType:   bindingType,
		SubjectUserID: subjStr,
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

	// Vault path differs by binding: a user connection is keyed by the subject so
	// each user's token is stored separately.
	isUser := st.BindingType == models.ConnectionBindingUser && st.SubjectUserID != nil
	vaultPath := fmt.Sprintf("kv/data/secret/workspaces/%s/connectors/%s/connection", st.WorkspaceID, st.ConnectorID)
	if isUser {
		vaultPath = fmt.Sprintf("kv/data/secret/workspaces/%s/connectors/%s/users/%s", st.WorkspaceID, st.ConnectorID, *st.SubjectUserID)
	}
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

	conn := &models.ConnectorConnection{
		WorkspaceID:         st.WorkspaceID,
		ConnectorID:         st.ConnectorID,
		BindingType:         st.BindingType,
		Status:              models.ConnectionStatusActive,
		AuthMethod:          models.ConnectionAuthOAuth2,
		VaultPath:           vaultPath,
		ScopesGranted:       strings.Fields(tok.Scope),
		AccessExpiresAt:     expiresAt,
		RefreshTokenPresent: tok.RefreshToken != "",
		ConnectedBy:         st.CreatedBy,
	}

	// Upsert the matching connection (one workspace conn per connector; one user
	// conn per (connector, subject)).
	var existing *models.ConnectorConnection
	if isUser {
		subj, _ := uuid.Parse(*st.SubjectUserID)
		conn.SubjectUserID = &subj
		existing, _ = s.repo.GetUserConnection(st.ConnectorID, *st.SubjectUserID)
	} else {
		existing, _ = s.repo.GetWorkspaceConnection(st.ConnectorID)
	}
	if existing != nil {
		conn.ID = existing.ID
		conn.Version = existing.Version // preserve CAS counter on reconnect
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

// MintGitHubAppToken mints a fresh GitHub-App installation access token for a
// github_app connection: resolves the workspace's GitHub App (app id + private
// key PEM in Vault) and the connection's installation id, then signs the App JWT
// and exchanges it. The token is short-lived and never stored — it's minted per
// need and injected by the broker. providerKey lets other App-style providers
// reuse this later; today only 'github' uses it.
func (s *ConnectorOAuthService) MintGitHubAppToken(ctx context.Context, workspaceID uuid.UUID, providerKey string, conn *models.ConnectorConnection) (string, error) {
	app, err := s.repo.GetProviderApp(workspaceID, providerKey)
	if err != nil || app == nil {
		return "", fmt.Errorf("no GitHub App configured for provider %q in this workspace", providerKey)
	}
	if app.AppKind != models.ProviderAppKindGitHubApp || app.GitHubAppID == "" {
		return "", fmt.Errorf("provider app for %q is not a GitHub App", providerKey)
	}
	if s.vault == nil {
		return "", errors.New("vault client not configured")
	}
	secret, err := s.vault.ReadSecret(app.VaultPath)
	if err != nil {
		return "", fmt.Errorf("read app private key: %w", err)
	}
	privateKey, _ := secret["private_key"].(string)
	if privateKey == "" {
		return "", errors.New("GitHub App private key missing in vault")
	}
	// The installation id is stored on the connection's external-account id.
	installationID := conn.ExternalAccountID
	if installationID == "" {
		return "", errors.New("connection has no GitHub App installation id")
	}
	return connectoradapters.MintGitHubInstallationToken(ctx, connectoradapters.GitHubAppCreds{
		WorkspaceID:    workspaceID.String(),
		AppID:          app.GitHubAppID,
		PrivateKeyPEM:  privateKey,
		InstallationID: installationID,
	})
}

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
		AppKind:     models.ProviderAppKindOAuth2,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		VaultPath:   vaultPath,
		CreatedBy:   createdBy,
	})
}

// SetGitHubApp configures a workspace's GitHub App for the github provider:
// stores the App id (DB) + private-key PEM (Vault). Distinct from the OAuth-app
// path — a GitHub App mints installation tokens, not OAuth code exchanges.
func (s *ConnectorOAuthService) SetGitHubApp(workspaceID uuid.UUID, appID, privateKeyPEM, createdBy string) error {
	if appID == "" || privateKeyPEM == "" {
		return errors.New("app_id and private_key are required")
	}
	if s.vault == nil {
		return errors.New("vault client not configured")
	}
	vaultPath := fmt.Sprintf("kv/data/secret/workspaces/%s/provider-apps/github", workspaceID.String())
	if err := s.vault.WriteSecret(vaultPath, map[string]interface{}{"private_key": privateKeyPEM}); err != nil {
		return fmt.Errorf("store app private key: %w", err)
	}
	return s.repo.UpsertProviderApp(&models.ConnectorProviderApp{
		WorkspaceID: workspaceID,
		ProviderKey: "github",
		AppKind:     models.ProviderAppKindGitHubApp,
		GitHubAppID: appID,
		VaultPath:   vaultPath,
		CreatedBy:   createdBy,
	})
}

// DeleteGitHubAppKey removes an App private key from Vault.
//
// Takes the path rather than the workspace because the caller has already
// resolved and authorised the provider-app row it belongs to; re-deriving the
// path here would be a second place for the two to drift apart.
func (s *ConnectorOAuthService) DeleteGitHubAppKey(vaultPath string) error {
	if s.vault == nil || vaultPath == "" {
		return nil
	}
	return s.vault.DeleteSecret(vaultPath)
}

// ConnectGitHubApp binds a connector to a GitHub App installation: creates (or
// updates) the connector's workspace-scope github_app connection with the given
// installation id. No OAuth dance — the installation id + the workspace App are
// all that's needed; tokens are minted per action.
func (s *ConnectorOAuthService) ConnectGitHubApp(workspaceID, connectorID uuid.UUID, installationID, orgName, createdBy string) error {
	if installationID == "" {
		return errors.New("installation_id is required")
	}
	if _, err := s.repo.GetProviderApp(workspaceID, "github"); err != nil {
		return errors.New("configure the workspace GitHub App first")
	}

	// Prove the installation is ours before recording it.
	//
	// installation_id arrives from caller-supplied input (a request body here, an
	// X-GitHub-Installation-ID header elsewhere) and is not a secret — it is
	// visible in GitHub URLs and webhook payloads. Stored unverified, it lets a
	// workspace bind an installation belonging to somebody else's organisation
	// and then have this service mint tokens against it.
	//
	// Minting is itself the verification: GitHub only issues an installation
	// token when the App identified by our workspace's own key is actually
	// installed there. A foreign installation fails, and a successful call warms
	// the cache legitimately, so this costs nothing on the happy path.
	if _, err := s.MintGitHubAppToken(context.Background(), workspaceID, "github",
		&models.ConnectorConnection{ExternalAccountID: installationID}); err != nil {
		return fmt.Errorf("installation %s is not reachable with this workspace's GitHub App; "+
			"check that the App is installed on that organisation: %w", installationID, err)
	}
	// The github_app connection carries no Vault secret of its own (tokens are
	// minted from the provider-app key); vault_path points at the app key path.
	vaultPath := fmt.Sprintf("kv/data/secret/workspaces/%s/provider-apps/github", workspaceID.String())
	existing, _ := s.repo.GetWorkspaceConnection(connectorID)
	conn := &models.ConnectorConnection{
		WorkspaceID:         workspaceID,
		ConnectorID:         connectorID,
		BindingType:         models.ConnectionBindingWorkspace,
		Status:              models.ConnectionStatusActive,
		AuthMethod:          models.ConnectionAuthGitHubApp,
		VaultPath:           vaultPath,
		ExternalAccountID:   installationID, // installation id lives here
		ExternalOrgName:     orgName,
		RefreshTokenPresent: false,
		ConnectedBy:         createdBy,
	}
	if existing != nil {
		conn.ID = existing.ID
		conn.Version = existing.Version
		return s.db.Save(conn).Error
	}
	return s.repo.CreateConnection(conn)
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

// Refresh performs an on-demand refresh of a connection's OAuth token, guarded
// against a thundering herd: N concurrent executes on an expiring token would
// otherwise all refresh at once and race refresh-token rotation. We take a
// non-blocking Postgres advisory lock keyed on the connection id; if another
// worker holds it, we skip (that worker is refreshing) and re-read the row so
// the caller uses the freshly-rotated token. Inside the lock we re-check via a
// version CAS so a lock winner that already refreshed isn't refreshed again.
func (s *ConnectorOAuthService) Refresh(conn *models.ConnectorConnection) error {
	if !conn.RefreshTokenPresent || conn.VaultPath == "" {
		return errors.New("no refresh token available")
	}

	// Advisory lock key derived from the connection UUID (stable per connection).
	lockKey := int64(conn.ID.ID()) // low 32 bits of the UUID → int; fine for lock keying
	var got bool
	if err := s.db.Raw("SELECT pg_try_advisory_lock(?)", lockKey).Scan(&got).Error; err != nil {
		return fmt.Errorf("acquire refresh lock: %w", err)
	}
	if !got {
		// Someone else is refreshing this connection. Re-read the row so we pick
		// up their rotated token instead of racing them; don't refresh ourselves.
		var fresh models.ConnectorConnection
		if e := s.db.First(&fresh, "id = ?", conn.ID).Error; e == nil {
			*conn = fresh
		}
		return nil
	}
	defer s.db.Exec("SELECT pg_advisory_unlock(?)", lockKey)

	// Version CAS: re-read under the lock; if the stored version advanced past
	// what we hold, another worker already refreshed — adopt their row and stop.
	var current models.ConnectorConnection
	if e := s.db.First(&current, "id = ?", conn.ID).Error; e == nil {
		if current.Version > conn.Version {
			*conn = current
			return nil
		}
		*conn = current // work from the authoritative row
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
	conn.Version++ // CAS increment — signals other waiters this token is fresh
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

/* ----------------------- GitHub App self-service reads ---------------------- */
//
// These exist so the console can stop asking a human for values GitHub already
// knows. Copying an App ID off one settings page and an installation ID out of
// a URL on another is the single most error-prone part of onboarding, and the
// two numbers are easy to swap -- a mistake that only surfaces much later, as an
// opaque token-minting failure. Every value below is read from GitHub with the
// key already in Vault.

// GitHubAppInfo is the App's own description of itself. Non-secret.
type GitHubAppInfo struct {
	AppID       string            `json:"app_id"`
	Name        string            `json:"name"`
	Slug        string            `json:"slug"`
	Owner       string            `json:"owner"`
	Permissions map[string]string `json:"permissions"`
	// OwnerType is "User" or "Organization".
	//
	// Together with Public it decides where this App can be installed AT ALL:
	// GitHub only allows a private App on the account that owns it. A private,
	// personally-owned App therefore can never be installed on an organisation,
	// and the console needs to be able to say so -- otherwise the organisation
	// list is simply empty with no way to find out why.
	OwnerType string `json:"owner_type"`
	// Public is GitHub's "any account may install this" flag. False means owner
	// only.
	Public bool `json:"public"`
	// InstallURL is where a human installs this App. Derived from the slug so
	// the console can offer a button instead of instructions.
	InstallURL string `json:"install_url"`
}

// GitHubInstallation is one place this App is installed.
type GitHubInstallation struct {
	InstallationID      string `json:"installation_id"`
	Account             string `json:"account"`
	AccountType         string `json:"account_type"`
	RepositorySelection string `json:"repository_selection"`
}

// appJWTFor loads the workspace's App credentials and signs an App-level JWT.
func (s *ConnectorOAuthService) appJWTFor(workspaceID uuid.UUID) (jwtStr, appID string, err error) {
	app, err := s.repo.GetProviderApp(workspaceID, "github")
	if err != nil || app == nil || app.GitHubAppID == "" {
		return "", "", errors.New("no GitHub App configured for this workspace")
	}
	if s.vault == nil {
		return "", "", errors.New("vault client not configured")
	}
	secret, err := s.vault.ReadSecret(app.VaultPath)
	if err != nil {
		return "", "", fmt.Errorf("read app private key: %w", err)
	}
	pem, _ := secret["private_key"].(string)
	if pem == "" {
		return "", "", errors.New("GitHub App private key missing in vault")
	}
	j, err := connectoradapters.AppJWT(app.GitHubAppID, pem)
	if err != nil {
		return "", "", err
	}
	return j, app.GitHubAppID, nil
}

// githubAppGet performs an App-JWT-authenticated GET and decodes into out.
func (s *ConnectorOAuthService) githubAppGet(ctx context.Context, jwtStr, path string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com"+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+jwtStr)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("reach GitHub: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		// 401 here almost always means the stored App ID and private key are not
		// a matching pair, which is worth saying plainly rather than echoing a
		// bare status code.
		if resp.StatusCode == http.StatusUnauthorized {
			return errors.New("GitHub rejected this App's credentials — the App ID and private key may not belong to the same App")
		}
		return fmt.Errorf("github %s returned %d", path, resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}

// DescribeGitHubApp asks GitHub what this App actually is, so the console can
// confirm the right App was registered instead of trusting a pasted number.
func (s *ConnectorOAuthService) DescribeGitHubApp(ctx context.Context, workspaceID uuid.UUID) (*GitHubAppInfo, error) {
	j, appID, err := s.appJWTFor(workspaceID)
	if err != nil {
		return nil, err
	}
	var raw struct {
		Name  string `json:"name"`
		Slug  string `json:"slug"`
		Owner struct {
			Login string `json:"login"`
			Type  string `json:"type"`
		} `json:"owner"`
		Permissions map[string]string `json:"permissions"`
		Public      bool              `json:"public"`
	}
	if err := s.githubAppGet(ctx, j, "/app", &raw); err != nil {
		return nil, err
	}
	return &GitHubAppInfo{
		AppID:       appID,
		Name:        raw.Name,
		Slug:        raw.Slug,
		Owner:       raw.Owner.Login,
		OwnerType:   raw.Owner.Type,
		Public:      raw.Public,
		Permissions: raw.Permissions,
		InstallURL:  "https://github.com/apps/" + raw.Slug + "/installations/new",
	}, nil
}

// ListGitHubInstallations returns everywhere this App is installed, so the
// console can offer a list to click instead of asking for an id.
func (s *ConnectorOAuthService) ListGitHubInstallations(ctx context.Context, workspaceID uuid.UUID) ([]GitHubInstallation, error) {
	j, _, err := s.appJWTFor(workspaceID)
	if err != nil {
		return nil, err
	}
	var raw []struct {
		ID                  int64  `json:"id"`
		RepositorySelection string `json:"repository_selection"`
		Account             struct {
			Login string `json:"login"`
			Type  string `json:"type"`
		} `json:"account"`
	}
	if err := s.githubAppGet(ctx, j, "/app/installations", &raw); err != nil {
		return nil, err
	}
	out := make([]GitHubInstallation, 0, len(raw))
	for _, i := range raw {
		out = append(out, GitHubInstallation{
			InstallationID:      fmt.Sprintf("%d", i.ID),
			Account:             i.Account.Login,
			AccountType:         i.Account.Type,
			RepositorySelection: i.RepositorySelection,
		})
	}
	return out, nil
}

// ConvertGitHubAppManifest exchanges the temporary code GitHub hands back after
// a manifest-created App for the App's real credentials, and stores them.
//
// This is what removes App creation from the operator's hands entirely: instead
// of creating an App by hand, choosing permissions, generating a key, and
// pasting an id, they approve one pre-filled GitHub screen and the id + key
// arrive here directly. The code is single-use and expires after an hour.
func (s *ConnectorOAuthService) ConvertGitHubAppManifest(ctx context.Context, workspaceID uuid.UUID, code, createdBy string) (*GitHubAppInfo, error) {
	if code == "" {
		return nil, errors.New("manifest code is required")
	}
	if s.vault == nil {
		return nil, errors.New("vault client not configured")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.github.com/app-manifests/"+url.PathEscape(code)+"/conversions", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("reach GitHub: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		// The usual cause is a reused or expired code -- say so, because the
		// remedy (start the create flow again) is not obvious from a 404.
		return nil, fmt.Errorf("GitHub rejected the manifest code (%d); it is single-use and expires after an hour — start the setup again", resp.StatusCode)
	}

	var out struct {
		ID          int64                  `json:"id"`
		Name        string                 `json:"name"`
		Slug        string                 `json:"slug"`
		PEM         string                 `json:"pem"`
		Owner       struct{ Login string } `json:"owner"`
		Permissions map[string]string      `json:"permissions"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("parse manifest conversion: %w", err)
	}
	if out.ID == 0 || out.PEM == "" {
		return nil, errors.New("manifest conversion returned no app id or private key")
	}

	appID := fmt.Sprintf("%d", out.ID)
	vaultPath := fmt.Sprintf("kv/data/secret/workspaces/%s/provider-apps/github", workspaceID.String())
	if err := s.vault.WriteSecret(vaultPath, map[string]interface{}{"private_key": out.PEM}); err != nil {
		return nil, fmt.Errorf("store app private key: %w", err)
	}
	if err := s.repo.UpsertProviderApp(&models.ConnectorProviderApp{
		WorkspaceID: workspaceID,
		ProviderKey: "github",
		AppKind:     models.ProviderAppKindGitHubApp,
		GitHubAppID: appID,
		VaultPath:   vaultPath,
		CreatedBy:   createdBy,
	}); err != nil {
		return nil, err
	}

	return &GitHubAppInfo{
		AppID:       appID,
		Name:        out.Name,
		Slug:        out.Slug,
		Owner:       out.Owner.Login,
		Permissions: out.Permissions,
		InstallURL:  "https://github.com/apps/" + out.Slug + "/installations/new",
	}, nil
}
