package platform

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"

	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ConnectorController serves the workspace-scoped connector registry.
// Admin CRUD plus two agent-facing reads (config + credentials) gated by
// agent_accessible on the SPIFFE JWT-SVID path.
type ConnectorController struct {
	db *gorm.DB

	vaultOnce   sync.Once
	vaultClient vault.VaultClient
	vaultErr    error
}

// NewConnectorController constructs a ConnectorController.
func NewConnectorController(db *gorm.DB) *ConnectorController {
	return &ConnectorController{db: db}
}

/* -------------------------------------------------------------------------- */
/*                              Request types                                 */
/* -------------------------------------------------------------------------- */

// ConnectorCreateRequest is the body for POST /authsec/connectors.
type ConnectorCreateRequest struct {
	ProviderKey     string                 `json:"provider_key" binding:"required"`
	Name            string                 `json:"name" binding:"required"`
	Enabled         *bool                  `json:"enabled,omitempty"`
	Config          map[string]interface{} `json:"config,omitempty"`
	Subscriptions   json.RawMessage        `json:"subscriptions,omitempty"`
	AgentAccessible bool                   `json:"agent_accessible"`
	Secrets         map[string]interface{} `json:"secrets,omitempty"`
}

// ConnectorUpdateRequest is the body for PUT /authsec/connectors/:id.
type ConnectorUpdateRequest struct {
	Name            *string                `json:"name,omitempty"`
	Enabled         *bool                  `json:"enabled,omitempty"`
	Config          map[string]interface{} `json:"config,omitempty"`
	Subscriptions   json.RawMessage        `json:"subscriptions,omitempty"`
	AgentAccessible *bool                  `json:"agent_accessible,omitempty"`
	Secrets         map[string]interface{} `json:"secrets,omitempty"`
}

/* -------------------------------------------------------------------------- */
/*                            Internal helpers                                */
/* -------------------------------------------------------------------------- */

// resolveWorkspace returns the workspace UUID and the creating principal.
// Works for both the standard JWT path (context keys set by AuthMiddleware)
// and the SPIFFE JWT-SVID path (only claims set), reading from claims as a
// fallback.
func (ctl *ConnectorController) resolveWorkspace(c *gin.Context) (uuid.UUID, string, error) {
	workspaceStr := c.GetString("workspace_id")
	principal := c.GetString("client_id")

	if workspaceStr == "" || principal == "" {
		claims := connectorClaims(c)
		if workspaceStr == "" {
			workspaceStr, _ = claims["workspace_id"].(string)
		}
		if principal == "" {
			if v, ok := claims["client_id"].(string); ok {
				principal = v
			} else if v, ok := claims["sub"].(string); ok {
				principal = v
			}
		}
	}

	if workspaceStr == "" {
		return uuid.Nil, "", fmt.Errorf("workspace_id not found in token")
	}
	wsID, err := uuid.Parse(workspaceStr)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("invalid workspace_id: %w", err)
	}
	if principal == "" {
		principal = workspaceStr
	}
	return wsID, principal, nil
}

func connectorClaims(c *gin.Context) jwt.MapClaims {
	raw, ok := c.Get("claims")
	if !ok {
		return jwt.MapClaims{}
	}
	switch v := raw.(type) {
	case jwt.MapClaims:
		return v
	case map[string]interface{}:
		return jwt.MapClaims(v)
	default:
		return jwt.MapClaims{}
	}
}

func (ctl *ConnectorController) getVaultClient() (vault.VaultClient, error) {
	ctl.vaultOnce.Do(func() {
		addr := os.Getenv("VAULT_ADDR")
		token := os.Getenv("VAULT_TOKEN")
		if addr == "" || token == "" {
			ctl.vaultErr = fmt.Errorf("VAULT_ADDR or VAULT_TOKEN not set")
			return
		}
		ctl.vaultClient, ctl.vaultErr = vault.NewClient(addr, token)
	})
	return ctl.vaultClient, ctl.vaultErr
}

func (ctl *ConnectorController) manager(vaultClient vault.VaultClient) services.ConnectorManager {
	return services.NewConnectorManager(repositories.NewConnectorRepository(ctl.db), vaultClient)
}

/* -------------------------------------------------------------------------- */
/*                                Handlers                                    */
/* -------------------------------------------------------------------------- */

// ListProviders handles GET /authsec/connectors/providers — the fixed catalog.
func (ctl *ConnectorController) ListProviders(c *gin.Context) {
	providers, err := ctl.manager(nil).ListProviders()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"providers": providers})
}

// CreateConnector handles POST /authsec/connectors.
func (ctl *ConnectorController) CreateConnector(c *gin.Context) {
	wsID, principal, err := ctl.resolveWorkspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var req ConnectorCreateRequest
	if err = c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var vaultClient vault.VaultClient
	if len(req.Secrets) > 0 {
		if vaultClient, err = ctl.getVaultClient(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	out, err := ctl.manager(vaultClient).Create(wsID, principal, services.ConnectorInput{
		ProviderKey:     req.ProviderKey,
		Name:            req.Name,
		Enabled:         req.Enabled,
		Config:          req.Config,
		Subscriptions:   req.Subscriptions,
		AgentAccessible: req.AgentAccessible,
		Secrets:         req.Secrets,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Ensure the workspace's Connector Broker Resource Server exists — it is the
	// audience for all runtime action tokens. Idempotent get-or-create.
	if _, bErr := services.EnsureBrokerResourceServer(ctl.db, wsID); bErr != nil {
		log.Printf("CONNECTOR: failed to ensure broker RS for workspace %s: %v", wsID, bErr)
	}

	auditAdminMutation(c, wsID.String(), "create", "connector", out.ID.String(), http.StatusCreated, nil, out)
	c.JSON(http.StatusCreated, out)
}

// ListConnectors handles GET /authsec/connectors.
func (ctl *ConnectorController) ListConnectors(c *gin.Context) {
	wsID, _, err := ctl.resolveWorkspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	list, err := ctl.manager(nil).List(wsID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"connectors": list})
}

// GetConnector handles GET /authsec/connectors/:id.
func (ctl *ConnectorController) GetConnector(c *gin.Context) {
	wsID, _, err := ctl.resolveWorkspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector id"})
		return
	}
	mgr := ctl.manager(nil)
	conn, err := mgr.Get(wsID, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "connector not found"})
		return
	}
	// P1: surface the connector's credential bindings + lifecycle (no secrets).
	connections, _ := mgr.Connections(conn.ID)
	if connections == nil {
		connections = []models.ConnectorConnection{}
	}
	c.JSON(http.StatusOK, gin.H{
		"connector":   conn,
		"connections": connections,
	})
}

// UpdateConnector handles PUT /authsec/connectors/:id.
func (ctl *ConnectorController) UpdateConnector(c *gin.Context) {
	wsID, _, err := ctl.resolveWorkspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector id"})
		return
	}
	var req ConnectorUpdateRequest
	if err = c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var vaultClient vault.VaultClient
	if len(req.Secrets) > 0 {
		if vaultClient, err = ctl.getVaultClient(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	out, err := ctl.manager(vaultClient).Update(wsID, id, services.ConnectorUpdateInput{
		Name:            req.Name,
		Enabled:         req.Enabled,
		Config:          req.Config,
		Subscriptions:   req.Subscriptions,
		AgentAccessible: req.AgentAccessible,
		Secrets:         req.Secrets,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, wsID.String(), "update", "connector", id.String(), http.StatusOK, nil, out)
	c.JSON(http.StatusOK, out)
}

// DeleteConnector handles DELETE /authsec/connectors/:id.
func (ctl *ConnectorController) DeleteConnector(c *gin.Context) {
	wsID, _, err := ctl.resolveWorkspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector id"})
		return
	}
	vaultClient, _ := ctl.getVaultClient()
	if err := ctl.manager(vaultClient).Delete(wsID, id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	auditAdminMutation(c, wsID.String(), "delete", "connector", id.String(), http.StatusNoContent, nil, nil)
	c.Status(http.StatusNoContent)
}

// StartOAuthConnect handles POST /authsec/connectors/:id/connections/oauth/start.
// Admin session. Returns a provider authorize_url to redirect the browser to.
func (ctl *ConnectorController) StartOAuthConnect(c *gin.Context) {
	wsID, principal, err := ctl.resolveWorkspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector id"})
		return
	}
	var req struct {
		Scopes        []string `json:"scopes"`
		RedirectAfter string   `json:"redirect_after"`
	}
	_ = c.ShouldBindJSON(&req)

	vaultClient, err := ctl.getVaultClient()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	svc := services.NewConnectorOAuthService(ctl.db, vaultClient)
	out, err := svc.Start(wsID, id, principal, req.RedirectAfter, req.Scopes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	auditAdminMutation(c, wsID.String(), "connect_start", "connector", id.String(), http.StatusOK, nil, gin.H{"provider": true})
	c.JSON(http.StatusOK, out)
}

// OAuthCallback handles GET /authsec/connectors/oauth/callback. Unauthenticated
// (validated by the one-shot state); the provider redirects here with code+state.
func (ctl *ConnectorController) OAuthCallback(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")

	vaultClient, err := ctl.getVaultClient()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	svc := services.NewConnectorOAuthService(ctl.db, vaultClient)
	res, err := svc.HandleCallback(code, state)
	if err != nil {
		// Bad/expired state or provider error.
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if res.RedirectAfter != "" {
		c.Redirect(http.StatusFound, res.RedirectAfter)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "connected", "connector_id": res.ConnectorID})
}

// GrantAssignment handles POST /authsec/connectors/:id/assignments — grant an
// agent (client_id) access to this connector, optionally scoped to one action.
func (ctl *ConnectorController) GrantAssignment(c *gin.Context) {
	wsID, principal, err := ctl.resolveWorkspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector id"})
		return
	}
	var req struct {
		ClientID         string          `json:"client_id" binding:"required"`
		ActionKey        *string         `json:"action_key,omitempty"`
		InputConstraints json.RawMessage `json:"input_constraints,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	out, err := ctl.manager(nil).GrantAssignment(wsID, id, req.ClientID, req.ActionKey, req.InputConstraints, principal)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	auditAdminMutation(c, wsID.String(), "assign", "connector", id.String(), http.StatusCreated, nil, out)
	c.JSON(http.StatusCreated, out)
}

// ListAssignments handles GET /authsec/connectors/:id/assignments.
func (ctl *ConnectorController) ListAssignments(c *gin.Context) {
	wsID, _, err := ctl.resolveWorkspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector id"})
		return
	}
	list, err := ctl.manager(nil).ListAssignments(wsID, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"assignments": list})
}

// RevokeAssignment handles DELETE /authsec/connectors/:id/assignments/:aid.
func (ctl *ConnectorController) RevokeAssignment(c *gin.Context) {
	wsID, _, err := ctl.resolveWorkspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	aid, err := uuid.Parse(c.Param("aid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid assignment id"})
		return
	}
	if err := ctl.manager(nil).RevokeAssignment(wsID, aid); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	auditAdminMutation(c, wsID.String(), "unassign", "connector", c.Param("id"), http.StatusNoContent, nil, nil)
	c.Status(http.StatusNoContent)
}

// GetConnectorAudit handles GET /authsec/connectors/:id/audit — the activity
// log: who ran which action on whose behalf with which token, allow/deny.
func (ctl *ConnectorController) GetConnectorAudit(c *gin.Context) {
	wsID, _, err := ctl.resolveWorkspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector id"})
		return
	}
	limit := 100
	if v := c.Query("limit"); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			limit = n
		}
	}
	rows, err := ctl.manager(nil).AuditLog(wsID, id, limit)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"audit": rows})
}

// SetProviderApp handles POST /authsec/connectors/providers/:provider/app —
// configure this workspace's own OAuth app for a provider (client_id + secret +
// redirect). Secret goes to Vault; only client_id/redirect are stored in PG.
func (ctl *ConnectorController) SetProviderApp(c *gin.Context) {
	wsID, principal, err := ctl.resolveWorkspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	providerKey := c.Param("provider")
	var req struct {
		ClientID     string `json:"client_id" binding:"required"`
		ClientSecret string `json:"client_secret"`
		RedirectURI  string `json:"redirect_uri" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	vaultClient, err := ctl.getVaultClient()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	svc := services.NewConnectorOAuthService(ctl.db, vaultClient)
	if err := svc.SetProviderApp(wsID, providerKey, req.ClientID, req.ClientSecret, req.RedirectURI, principal); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	auditAdminMutation(c, wsID.String(), "set_provider_app", "connector_provider", providerKey, http.StatusOK, nil, gin.H{"client_id": req.ClientID})
	c.JSON(http.StatusOK, gin.H{"status": "configured", "provider": providerKey})
}

// SetGitHubApp handles POST /authsec/connectors/providers/github/app-github —
// configure this workspace's GitHub App (App id + private key PEM). Distinct
// from the OAuth-app path: a GitHub App is an org bot identity, not a human
// OAuth login (F1). Private key → Vault; only the App id is stored in PG.
func (ctl *ConnectorController) SetGitHubApp(c *gin.Context) {
	wsID, principal, err := ctl.resolveWorkspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var req struct {
		AppID      string `json:"app_id" binding:"required"`
		PrivateKey string `json:"private_key" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	vaultClient, err := ctl.getVaultClient()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	svc := services.NewConnectorOAuthService(ctl.db, vaultClient)
	if err := svc.SetGitHubApp(wsID, req.AppID, req.PrivateKey, principal); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	auditAdminMutation(c, wsID.String(), "set_github_app", "connector_provider", "github", http.StatusOK, nil, gin.H{"app_id": req.AppID})
	c.JSON(http.StatusOK, gin.H{"status": "configured", "provider": "github", "app_kind": "github_app"})
}

// ConnectGitHubApp handles POST /authsec/connectors/:id/connections/github-app —
// bind a connector to a GitHub App installation (org-scoped bot). No OAuth dance.
func (ctl *ConnectorController) ConnectGitHubApp(c *gin.Context) {
	wsID, principal, err := ctl.resolveWorkspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector id"})
		return
	}
	var req struct {
		InstallationID string `json:"installation_id" binding:"required"`
		OrgName        string `json:"org_name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	vaultClient, err := ctl.getVaultClient()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	svc := services.NewConnectorOAuthService(ctl.db, vaultClient)
	if err := svc.ConnectGitHubApp(wsID, id, req.InstallationID, req.OrgName, principal); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	auditAdminMutation(c, wsID.String(), "connect_github_app", "connector", id.String(), http.StatusOK, nil, gin.H{"installation_id": req.InstallationID})
	c.JSON(http.StatusOK, gin.H{"status": "connected", "connector_id": id, "installation_id": req.InstallationID})
}

// callerUserID resolves the authenticated end-user's local UUID from their
// session. R4 user-consent endpoints bind to THIS identity — never a supplied
// user_id — so a user can only connect/list/revoke their own accounts.
func (ctl *ConnectorController) callerUserID(c *gin.Context) (uuid.UUID, error) {
	uidStr, err := middlewares.ResolveUserID(c)
	if err != nil || uidStr == "" {
		return uuid.Nil, fmt.Errorf("user identity not available")
	}
	uid, err := uuid.Parse(uidStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid user id")
	}
	return uid, nil
}

// StartUserConnect handles POST /authsec/connectors/:id/connections/user/oauth/start —
// R4: the authenticated end-user consents to the provider for their OWN account.
// Produces a user-scope connection the broker resolves when an XAA token carries
// sub=this user.
func (ctl *ConnectorController) StartUserConnect(c *gin.Context) {
	wsID, _, err := ctl.resolveWorkspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	userID, err := ctl.callerUserID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector id"})
		return
	}
	var req struct {
		Scopes        []string `json:"scopes"`
		RedirectAfter string   `json:"redirect_after"`
	}
	_ = c.ShouldBindJSON(&req)

	vaultClient, err := ctl.getVaultClient()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	svc := services.NewConnectorOAuthService(ctl.db, vaultClient)
	out, err := svc.StartUser(wsID, id, userID, req.RedirectAfter, req.Scopes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, out)
}

// ListMyConnections handles GET /authsec/connectors/connections/me — the
// authenticated user's own connected provider accounts. R4.
func (ctl *ConnectorController) ListMyConnections(c *gin.Context) {
	wsID, _, err := ctl.resolveWorkspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	userID, err := ctl.callerUserID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	svc := services.NewConnectorOAuthService(ctl.db, nil)
	conns, err := svc.ListUserConnections(wsID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list connections"})
		return
	}
	if conns == nil {
		conns = []models.ConnectorConnection{}
	}
	c.JSON(http.StatusOK, gin.H{"connections": conns})
}

// RevokeMyConnection handles DELETE /authsec/connectors/:id/connections/me —
// the user disconnects their own provider account for a connector. R4.
func (ctl *ConnectorController) RevokeMyConnection(c *gin.Context) {
	wsID, _, err := ctl.resolveWorkspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	userID, err := ctl.callerUserID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector id"})
		return
	}
	vaultClient, _ := ctl.getVaultClient()
	svc := services.NewConnectorOAuthService(ctl.db, vaultClient)
	if err := svc.RevokeUserConnection(wsID, id, userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

// SetSubjectGroups handles PUT /authsec/connectors/:id/subject-groups — set the
// connector's F5 subject-group policy (which teams an agent may act FOR).
func (ctl *ConnectorController) SetSubjectGroups(c *gin.Context) {
	wsID, _, err := ctl.resolveWorkspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector id"})
		return
	}
	var req struct {
		GroupIDs []string `json:"group_ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Validate each is a UUID (they reference groups in this workspace).
	for _, g := range req.GroupIDs {
		if _, e := uuid.Parse(g); e != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "group_ids must be UUIDs"})
			return
		}
	}
	out, err := ctl.manager(nil).SetAllowedSubjectGroups(wsID, id, req.GroupIDs)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	auditAdminMutation(c, wsID.String(), "set_subject_groups", "connector", id.String(), http.StatusOK, nil, gin.H{"group_ids": req.GroupIDs})
	c.JSON(http.StatusOK, gin.H{"connector_id": id, "allowed_subject_groups": out.AllowedSubjectGroups})
}

// GetConnectorConfig handles GET /authsec/connectors/:id/config.
// Admin/internal non-secret contract: provider, config, subscriptions. Never
// secrets and never vault_path. A disabled connector fails closed (404).
func (ctl *ConnectorController) GetConnectorConfig(c *gin.Context) {
	wsID, _, err := ctl.resolveWorkspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector id"})
		return
	}
	conn, err := ctl.manager(nil).Get(wsID, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "connector not found"})
		return
	}
	// Fail closed: a disabled connector exposes nothing.
	if !conn.Enabled {
		c.JSON(http.StatusNotFound, gin.H{"error": "connector not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"connector_id":  conn.ID,
		"name":          conn.Name,
		"provider_key":  conn.ProviderKey,
		"enabled":       conn.Enabled,
		"config":        conn.Config,
		"subscriptions": conn.Subscriptions,
	})
}
