package platform

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/connectoradapters"
	"github.com/authsec-ai/authsec/internal/tokens"
	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ConnectorBrokerController serves the runtime DATA plane (/broker/connectors/*).
// It is the identity-aware action broker: it accepts only AuthSec native access
// tokens audience-bound to the workspace Connector Broker Resource Server,
// authorizes on Principal + Actor + assignments (never on token provenance),
// and (in P2) executes typed actions server-side. It NEVER returns a credential.
type ConnectorBrokerController struct {
	db            *gorm.DB
	oauthSvc      *services.OAuthASService
	rsService     *services.ResourceServerService
	scopeResolver *services.ScopeResolver

	vaultOnce   sync.Once
	vaultClient vault.VaultClient
	vaultErr    error
}

// NewConnectorBrokerController constructs the broker controller.
func NewConnectorBrokerController(db *gorm.DB) *ConnectorBrokerController {
	return &ConnectorBrokerController{
		db:            db,
		oauthSvc:      services.NewOAuthASService(db),
		rsService:     services.NewResourceServerService(db),
		scopeResolver: services.NewScopeResolver(db),
	}
}

func (ctl *ConnectorBrokerController) repo() repositories.ConnectorRepository {
	return repositories.NewConnectorRepository(ctl.db)
}

func (ctl *ConnectorBrokerController) getVaultClient() (vault.VaultClient, error) {
	ctl.vaultOnce.Do(func() {
		addr := os.Getenv("VAULT_ADDR")
		token := os.Getenv("VAULT_TOKEN")
		if addr == "" || token == "" {
			ctl.vaultErr = errBrokerVaultUnset
			return
		}
		ctl.vaultClient, ctl.vaultErr = vault.NewClient(addr, token)
	})
	return ctl.vaultClient, ctl.vaultErr
}

// authenticate runs the shared ProtectedResourceVerifier against the workspace
// Connector Broker RS named by the token's audience. Any failure → nil + an
// obscured 401/403 already written. On success the returned AuthContext is
// guaranteed audience-bound to a managed broker RS (RFC 8707; confused-deputy
// guard).
func (ctl *ConnectorBrokerController) authenticate(c *gin.Context) (*services.AuthContext, *models.ResourceServer) {
	token := bearerToken(c)
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "bearer token required"})
		return nil, nil
	}

	// Only native AuthSec tokens are accepted here — never an HMAC authsec-api
	// token, never Hydra-opaque. A native kid commits to the native path.
	cls := tokens.Classify(token, tokens.NativeKeys().NativeKeyIDs())
	if cls.Family != tokens.FamilyNative {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return nil, nil
	}

	// Discover the candidate audience (unverified parse, header/claims only) so
	// we can load the RS the token claims to target. The verifier then RE-CHECKS
	// aud authoritatively against native_tokens, so a spoofed aud cannot pass.
	aud := unverifiedAudience(token)
	if aud == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return nil, nil
	}

	rs, err := ctl.rsService.GetByResourceURI(aud)
	if err != nil || rs == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return nil, nil
	}
	// The data plane only ever accepts tokens bound to a managed broker RS — a
	// token minted for a real Application RS must not reach connectors.
	if !rs.Managed || rs.ApplicationType != models.ApplicationTypeConnectorBroker {
		c.JSON(http.StatusForbidden, gin.H{"error": "token not bound to the connector broker"})
		return nil, nil
	}

	authCtx, err := services.VerifyProtectedResourceToken(c.Request.Context(), ctl.db, ctl.oauthSvc, ctl.scopeResolver, token, cls.Kid, rs)
	if err != nil {
		log.Printf("BROKER: token verification failed rs=%s: %v", rs.ResourceURI, err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return nil, nil
	}
	return authCtx, rs
}

// ListConnectors handles GET /broker/connectors — connectors this caller is
// assigned and that are enabled + agent_accessible. Never includes secrets.
func (ctl *ConnectorBrokerController) ListConnectors(c *gin.Context) {
	authCtx, _ := ctl.authenticate(c)
	if authCtx == nil {
		return
	}
	repo := ctl.repo()
	all, err := repo.ListByWorkspace(authCtx.Principal.WorkspaceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list connectors"})
		return
	}
	out := make([]gin.H, 0, len(all))
	for _, conn := range all {
		if !conn.Enabled || !conn.AgentAccessible {
			continue
		}
		allowed, aerr := repo.AssignmentAllows(conn.ID, authCtx.ClientID, "")
		if aerr != nil || !allowed {
			continue
		}
		out = append(out, gin.H{
			"connector_id": conn.ID,
			"name":         conn.Name,
			"provider_key": conn.ProviderKey,
		})
	}
	c.JSON(http.StatusOK, gin.H{"connectors": out})
}

// ListActions handles GET /broker/connectors/:id/actions — typed actions this
// caller may invoke. (Action catalog is populated in P2; for now this validates
// the full policy chain and returns the — currently empty — action set.)
func (ctl *ConnectorBrokerController) ListActions(c *gin.Context) {
	authCtx, _ := ctl.authenticate(c)
	if authCtx == nil {
		return
	}
	connID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector id"})
		return
	}
	conn, err := ctl.repo().GetByID(authCtx.Principal.WorkspaceID, connID)
	if err != nil {
		// Obscure existence.
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	// Fail closed on disabled / not-agent-accessible / unassigned.
	if !conn.Enabled || !conn.AgentAccessible {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	allowed, aerr := ctl.repo().AssignmentAllows(conn.ID, authCtx.ClientID, "")
	if aerr != nil || !allowed {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	// Typed actions come from the provider-level catalog.
	actions, err := ctl.repo().ListActions(conn.ProviderKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list actions"})
		return
	}
	out := make([]gin.H, 0, len(actions))
	for _, a := range actions {
		out = append(out, gin.H{
			"action_key":   a.ActionKey,
			"display_name": a.DisplayName,
			"input_schema": a.InputSchema,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"connector_id": conn.ID,
		"provider_key": conn.ProviderKey,
		"actions":      out,
	})
}

// ExecuteAction handles POST /broker/connectors/:id/actions/:key:execute — the
// REST entry to the broker. Delegates to runAction (shared with the MCP surface).
func (ctl *ConnectorBrokerController) ExecuteAction(c *gin.Context) {
	authCtx, _ := ctl.authenticate(c)
	if authCtx == nil {
		return
	}
	connID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid connector id"})
		return
	}
	// Gin routes ":key:execute" — the param includes the literal ":execute".
	actionKey := strings.TrimSuffix(c.Param("key"), ":execute")
	var body struct {
		Input map[string]interface{} `json:"input"`
	}
	_ = c.ShouldBindJSON(&body)

	result, status, reason := ctl.runAction(c, authCtx, connID, actionKey, body.Input)
	if status != http.StatusOK {
		c.JSON(status, gin.H{"error": reason})
		return
	}
	c.JSON(http.StatusOK, gin.H{"result": result})
}

// runAction is the heart of the broker, shared by the REST and MCP surfaces. It
// runs the full policy chain (RBAC scope → enabled/agent_accessible → assignment
// → action/adapter), resolves the connection (refresh-if-near-expiry), injects
// the credential server-side, calls the typed adapter, and audits allow/deny.
// Returns the redacted result, an HTTP status, and (on failure) a public reason.
// The credential never leaves the broker.
func (ctl *ConnectorBrokerController) runAction(c *gin.Context, authCtx *services.AuthContext, connID uuid.UUID, actionKey string, input map[string]interface{}) (*connectoradapters.Result, int, string) {
	deny := func(status int, auditReason, publicMsg string) (*connectoradapters.Result, int, string) {
		ctl.auditAction(c, authCtx, connID.String(), actionKey, "deny", auditReason)
		return nil, status, publicMsg
	}

	if actionKey == "" {
		return deny(http.StatusBadRequest, "empty action key", "action key required")
	}
	// Gate 1 — RBAC: the acting principal must hold connector:execute.
	if !authContextHasScope(authCtx, services.BrokerExecuteScope) {
		return deny(http.StatusForbidden, "missing connector:execute scope", "forbidden")
	}
	// Load connector; fail closed on disabled/not-accessible.
	conn, err := ctl.repo().GetByID(authCtx.Principal.WorkspaceID, connID)
	if err != nil {
		return deny(http.StatusNotFound, "connector not found", "not found")
	}
	if !conn.Enabled || !conn.AgentAccessible {
		return deny(http.StatusNotFound, "connector disabled or not agent-accessible", "not found")
	}
	// Gate 2 — assignment allowlist.
	allowed, aerr := ctl.repo().AssignmentAllows(conn.ID, authCtx.ClientID, actionKey)
	if aerr != nil || !allowed {
		return deny(http.StatusForbidden, "no assignment for client/connector/action", "forbidden")
	}
	// Resolve typed action + adapter.
	action, err := ctl.repo().GetAction(conn.ProviderKey, actionKey)
	if err != nil {
		return deny(http.StatusNotFound, "unknown action for provider", "not found")
	}
	adapter, ok := connectoradapters.Get(action.AdapterKey)
	if !ok {
		return deny(http.StatusNotFound, "no adapter for action", "not found")
	}

	// Delegated (XAA) → user subject; M2M → workspace connection.
	subjectUserID := ""
	if authCtx.Actor != nil && authCtx.Principal.SubjectType == tokens.SubjectTypeUser {
		subjectUserID = authCtx.Principal.SubjectID.String()
	}
	vaultClient, err := ctl.getVaultClient()
	if err != nil {
		return deny(http.StatusInternalServerError, "vault unavailable", "internal error")
	}
	mgr := services.NewConnectorManager(ctl.repo(), vaultClient)
	resolved, err := mgr.ResolveActionCredential(conn.ID, subjectUserID)
	if err != nil {
		return deny(http.StatusFailedDependency, "connection: "+err.Error(), "connection unavailable")
	}
	if connectionNeedsRefresh(resolved.Connection) {
		oauthSvc := services.NewConnectorOAuthService(ctl.db, vaultClient)
		if err := oauthSvc.Refresh(resolved.Connection); err != nil {
			return deny(http.StatusFailedDependency, "refresh failed: "+err.Error(), "connection unavailable")
		}
		if resolved, err = mgr.ResolveActionCredential(conn.ID, subjectUserID); err != nil {
			return deny(http.StatusFailedDependency, "post-refresh resolve: "+err.Error(), "connection unavailable")
		}
	}

	cred := connectoradapters.Credential{
		AccessToken: firstSecretString(resolved.Secret, "access_token", "apiKey", "token"),
		TokenType:   firstSecretString(resolved.Secret, "token_type"),
	}
	result, err := adapter.Execute(c.Request.Context(), cred, connectoradapters.Request{ActionKey: actionKey, Input: input})
	if err != nil {
		return deny(http.StatusBadGateway, "adapter error: "+err.Error(), "provider call failed")
	}

	ctl.auditAction(c, authCtx, connID.String(), actionKey, "allow", "")
	return result, http.StatusOK, ""
}

// --- MCP tools surface -------------------------------------------------------
//
// The "automatic" path: an MCP agent lists tools and sees every action of every
// connector it's been granted, then calls them like any tool. Tool name encodes
// the connector id + action key so tools/call routes straight into runAction —
// the same policy chain as the REST execute endpoint.

const mcpToolSep = "__" // connectorID + sep + actionKey

// MCPListTools handles GET /broker/mcp/tools — the agent's tool list. Only
// enabled + agent_accessible connectors this client is assigned appear, each
// action flattened into an MCP tool descriptor with its typed input schema.
func (ctl *ConnectorBrokerController) MCPListTools(c *gin.Context) {
	authCtx, _ := ctl.authenticate(c)
	if authCtx == nil {
		return
	}
	repo := ctl.repo()
	connectors, err := repo.ListByWorkspace(authCtx.Principal.WorkspaceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list connectors"})
		return
	}
	tools := make([]gin.H, 0)
	for _, conn := range connectors {
		if !conn.Enabled || !conn.AgentAccessible {
			continue
		}
		actions, aerr := repo.ListActions(conn.ProviderKey)
		if aerr != nil {
			continue
		}
		for _, a := range actions {
			// Only surface actions this client is actually assigned.
			allowed, e := repo.AssignmentAllows(conn.ID, authCtx.ClientID, a.ActionKey)
			if e != nil || !allowed {
				continue
			}
			name := conn.ID.String() + mcpToolSep + a.ActionKey
			desc := a.DisplayName
			if desc == "" {
				desc = conn.Name + " " + a.ActionKey
			}
			tools = append(tools, gin.H{
				"name":        name,
				"description": desc,
				"inputSchema": a.InputSchema,
			})
		}
	}
	c.JSON(http.StatusOK, gin.H{"tools": tools})
}

// MCPCallTool handles POST /broker/mcp/call — invoke a tool by its name
// (connectorID__actionKey) with typed arguments. Delegates to the shared
// runAction policy chain and returns the redacted result in MCP content shape.
func (ctl *ConnectorBrokerController) MCPCallTool(c *gin.Context) {
	authCtx, _ := ctl.authenticate(c)
	if authCtx == nil {
		return
	}
	var body struct {
		Name      string                 `json:"name" binding:"required"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	idStr, actionKey, ok := splitMCPToolName(body.Name)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tool name"})
		return
	}
	connID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tool name"})
		return
	}

	result, status, reason := ctl.runAction(c, authCtx, connID, actionKey, body.Arguments)
	if status != http.StatusOK {
		// MCP tool-call error shape.
		c.JSON(status, gin.H{
			"isError": true,
			"content": []gin.H{{"type": "text", "text": reason}},
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"content": []gin.H{{"type": "text", "text": mustJSON(result)}},
	})
}

func splitMCPToolName(name string) (connectorID, actionKey string, ok bool) {
	i := strings.Index(name, mcpToolSep)
	if i <= 0 || i+len(mcpToolSep) >= len(name) {
		return "", "", false
	}
	return name[:i], name[i+len(mcpToolSep):], true
}

func mustJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// --- helpers ----------------------------------------------------------------

var errBrokerVaultUnset = &brokerError{"VAULT_ADDR or VAULT_TOKEN not set"}

type brokerError struct{ msg string }

func (e *brokerError) Error() string { return e.msg }

// connectionNeedsRefresh reports whether an OAuth2 connection's access token is
// near/after expiry and a refresh token is available to renew it. api_key
// connections and those without expiry/refresh never refresh.
func connectionNeedsRefresh(conn *models.ConnectorConnection) bool {
	if conn == nil || conn.AuthType != models.ConnectionAuthOAuth2 {
		return false
	}
	if !conn.RefreshTokenPresent || conn.AccessExpiresAt == nil {
		return false
	}
	// Refresh a minute ahead of expiry to avoid racing the provider.
	return time.Now().Add(60 * time.Second).After(*conn.AccessExpiresAt)
}

// authContextHasScope reports whether the verified token carries a scope.
func authContextHasScope(ctx *services.AuthContext, scope string) bool {
	for _, s := range ctx.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// firstSecretString returns the first present, non-empty string value among the
// given keys of the resolved Vault secret. Used to locate the access token /
// api key regardless of the field name a provider connection stored.
func firstSecretString(secret map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := secret[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// auditAction writes an action-broker audit event for both allow and deny. It
// records Principal, Actor (act), the connector + action, and the outcome — the
// action-level accountability a token vault cannot produce. Never logs secrets.
func (ctl *ConnectorBrokerController) auditAction(c *gin.Context, authCtx *services.AuthContext, connectorID, actionKey, outcome, reason string) {
	if config.AuditLogger == nil {
		return
	}
	newValues := map[string]interface{}{
		"outcome":      outcome,
		"connector_id": connectorID,
		"action_key":   actionKey,
		"client_id":    authCtx.ClientID,
		"subject_type": authCtx.Principal.SubjectType,
		"token_family": authCtx.TokenFamily,
	}
	if authCtx.Actor != nil {
		newValues["actor_client_id"] = authCtx.Actor.ClientID
	}
	status := http.StatusOK
	if outcome != "allow" {
		status = http.StatusForbidden
	}
	config.AuditLogger.LogAdminAction(
		c.GetString("request_id"),
		authCtx.Principal.WorkspaceID.String(),
		authCtx.Principal.SubjectID.String(),
		"connector.action."+outcome,
		"connector_action",
		connectorID+":"+actionKey,
		c.Request.Method,
		c.Request.URL.Path,
		c.ClientIP(),
		c.GetHeader("User-Agent"),
		status,
		0,
		nil,
		newValues,
		reason,
	)
}

func bearerToken(c *gin.Context) string {
	h := c.GetHeader("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	return ""
}

// unverifiedAudience parses the token WITHOUT signature verification purely to
// read its aud claim, so the broker can load the candidate RS. The audience is
// then re-validated authoritatively inside VerifyProtectedResourceToken against
// the native_tokens row — this unverified read grants no trust.
func unverifiedAudience(token string) string {
	parser := jwt.NewParser()
	claims := jwt.MapClaims{}
	_, _, err := parser.ParseUnverified(token, claims)
	if err != nil {
		return ""
	}
	switch aud := claims["aud"].(type) {
	case string:
		return aud
	case []interface{}:
		if len(aud) > 0 {
			if s, ok := aud[0].(string); ok {
				return s
			}
		}
	}
	return ""
}
