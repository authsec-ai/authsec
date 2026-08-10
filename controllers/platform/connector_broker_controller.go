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
	c.JSON(http.StatusOK, gin.H{"result": result, "identity": identityBlock(authCtx)})
}

// runAction is the heart of the broker, shared by the REST and MCP surfaces. It
// runs the full policy chain (RBAC scope → enabled/agent_accessible → assignment
// → action/adapter), resolves the connection (refresh-if-near-expiry), injects
// the credential server-side, calls the typed adapter, and audits allow/deny.
// Returns the redacted result, an HTTP status, and (on failure) a public reason.
// The credential never leaves the broker.
func (ctl *ConnectorBrokerController) runAction(c *gin.Context, authCtx *services.AuthContext, connID uuid.UUID, actionKey string, input map[string]interface{}) (*connectoradapters.Result, int, string) {
	deny := func(status int, auditReason, publicMsg string) (*connectoradapters.Result, int, string) {
		ctl.auditAction(c, authCtx, connID.String(), actionKey, actionAudit{
			authzOutcome:  "deny",
			brokerStatus:  status,
			actionOutcome: models.ActionOutcomePolicyDeny,
			denyReason:    auditReason,
		})
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
	// Gate 2 — assignment allowlist (returns the authorizing row so its
	// input_constraints can be enforced below).
	assignment, aerr := ctl.repo().MatchingAssignment(conn.ID, authCtx.ClientID, actionKey)
	if aerr != nil || assignment == nil {
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
	// Gate 3 — input constraints (F3): the input schema was validated when it was
	// parsed; now enforce the per-assignment predicate bounding WHERE this action
	// may run (e.g. repo glob). A violation is a policy deny, not a bad request.
	if ok, why := evalInputConstraints(assignment.InputConstraints, input); !ok {
		return deny(http.StatusForbidden, "input constraint: "+why, "forbidden")
	}

	// Delegated (XAA) → user subject; M2M → workspace connection.
	subjectUserID := ""
	if authCtx.Actor != nil && authCtx.Principal.SubjectType == tokens.SubjectTypeUser {
		subjectUserID = authCtx.Principal.SubjectID.String()
	}

	// Gate 4 — subject-group policy (F5): if the connector restricts which teams
	// an agent may act FOR, the on-behalf-of user must be in an allowed group.
	// Only applies to delegated (user-subject) calls; an M2M call has no human
	// subject and is unaffected.
	if len(conn.AllowedSubjectGroups) > 0 {
		if subjectUserID == "" {
			return deny(http.StatusForbidden, "connector requires an on-behalf-of user in an allowed group", "forbidden")
		}
		inGroup, gErr := ctl.repo().SubjectInAnyGroup(authCtx.Principal.WorkspaceID, subjectUserID, []string(conn.AllowedSubjectGroups))
		if gErr != nil || !inGroup {
			return deny(http.StatusForbidden, "subject not in an allowed group for this connector", "forbidden")
		}
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

	// Build the credential to inject. For github_app connections there is no
	// static token in Vault — mint a fresh installation token (F1: org bot
	// identity, no human attached) from the workspace's GitHub App.
	var cred connectoradapters.Credential
	if resolved.Connection != nil && resolved.Connection.AuthMethod == models.ConnectionAuthGitHubApp {
		oauthSvc := services.NewConnectorOAuthService(ctl.db, vaultClient)
		instTok, mErr := oauthSvc.MintGitHubAppToken(c.Request.Context(), authCtx.Principal.WorkspaceID, conn.ProviderKey, resolved.Connection)
		if mErr != nil {
			return deny(http.StatusFailedDependency, "github app token: "+mErr.Error(), "connection unavailable")
		}
		cred = connectoradapters.Credential{AccessToken: instTok, TokenType: "Bearer"}
	} else {
		cred = connectoradapters.Credential{
			AccessToken: firstSecretString(resolved.Secret, "access_token", "apiKey", "token"),
			TokenType:   firstSecretString(resolved.Secret, "token_type"),
		}
	}
	result, err := adapter.Execute(c.Request.Context(), cred, connectoradapters.Request{ActionKey: actionKey, Input: input})
	if err != nil {
		// The broker authorized the attempt but the provider call itself errored
		// (network/adapter). F8: authz=allow, but action_outcome=provider_error.
		ctl.auditAction(c, authCtx, connID.String(), actionKey, actionAudit{
			authzOutcome:  "allow",
			brokerStatus:  http.StatusOK,
			actionOutcome: models.ActionOutcomeProviderError,
			denyReason:    "adapter error: " + err.Error(),
		})
		return nil, http.StatusBadGateway, "provider call failed"
	}

	// F8: the broker authorized AND called the provider — record the real upstream
	// status and whether the provider itself accepted the call. "allow" no longer
	// hides a provider 4xx/5xx: authz_outcome=allow, provider_status=<real>,
	// action_outcome=success|provider_error.
	providerStatus := result.StatusCode
	outcome := models.ActionOutcomeSuccess
	if !result.OK {
		outcome = models.ActionOutcomeProviderError
	}
	ctl.auditAction(c, authCtx, connID.String(), actionKey, actionAudit{
		authzOutcome:   "allow",
		brokerStatus:   http.StatusOK,
		providerStatus: &providerStatus,
		actionOutcome:  outcome,
	})

	// Best-effort lifecycle: mark the SA recently seen (Agent 360) + the
	// connection last-used.
	if authCtx.Principal.SubjectType == tokens.SubjectTypeServiceAccount && authCtx.Principal.SubjectID != uuid.Nil {
		ctl.db.Exec(`UPDATE service_accounts SET last_seen_at = NOW() WHERE id = ?`, authCtx.Principal.SubjectID)
	}
	if resolved.Connection != nil {
		ctl.db.Exec(`UPDATE connector_connections SET last_used_at = NOW() WHERE id = ?`, resolved.Connection.ID)
	}
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
		"content":  []gin.H{{"type": "text", "text": mustJSON(result)}},
		"identity": identityBlock(authCtx),
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
	if conn == nil || conn.AuthMethod != models.ConnectionAuthOAuth2 {
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

// identityBlock renders the caller identity for an action response: who the
// principal is (sub), on whose behalf / which agent acted (act), and which token
// authorized it (family + jti). This is the "who did what, on whose behalf, with
// which token" surface — echoed to the caller and mirrored into the audit record.
func identityBlock(authCtx *services.AuthContext) gin.H {
	// Actor always (F7b): the act-claim client for XAA/CIBA, else the
	// authenticating client for direct M2M.
	actorClientID := authCtx.ClientID
	var spiffeID *string
	if authCtx.Actor != nil {
		actorClientID = authCtx.Actor.ClientID
		spiffeID = authCtx.Actor.SpiffeID
	}
	return gin.H{
		"principal": gin.H{
			"sub":  authCtx.Principal.SubjectID.String(),
			"type": authCtx.Principal.SubjectType,
		},
		"actor":        gin.H{"client_id": actorClientID, "spiffe_id": spiffeID},
		"token":        gin.H{"family": authCtx.TokenFamily, "jti": authCtx.JTI},
		"workspace_id": authCtx.Principal.WorkspaceID.String(),
	}
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

// actionAudit carries the F8 outcome fields for one broker action attempt.
type actionAudit struct {
	authzOutcome   string // allow | deny
	brokerStatus   int
	providerStatus *int   // nil if the broker denied before calling the provider
	actionOutcome  string // success | provider_error | policy_deny
	denyReason     string
}

// auditAction writes an action-broker audit event for both allow and deny,
// recording the F8 outcome triad (authz vs. broker-status vs. provider-status vs.
// action-outcome) plus Principal, Actor (always), and the accountable Owner.
// Never logs secrets.
func (ctl *ConnectorBrokerController) auditAction(c *gin.Context, authCtx *services.AuthContext, connectorID, actionKey string, a actionAudit) {
	if config.AuditLogger == nil {
		return
	}
	newValues := map[string]interface{}{
		"authz_outcome":  a.authzOutcome,
		"action_outcome": a.actionOutcome,
		"broker_status":  a.brokerStatus,
		"connector_id":   connectorID,
		"action_key":     actionKey,
		"client_id":      authCtx.ClientID,
		"subject_type":   authCtx.Principal.SubjectType,
		"token_family":   authCtx.TokenFamily,
	}
	if a.providerStatus != nil {
		newValues["provider_status"] = *a.providerStatus
	}
	if authCtx.Actor != nil {
		newValues["actor_client_id"] = authCtx.Actor.ClientID
		if authCtx.Actor.SpiffeID != nil {
			newValues["actor_spiffe_id"] = *authCtx.Actor.SpiffeID
		}
	}
	config.AuditLogger.LogAdminAction(
		c.GetString("request_id"),
		authCtx.Principal.WorkspaceID.String(),
		authCtx.Principal.SubjectID.String(),
		"connector.action."+a.authzOutcome,
		"connector_action",
		connectorID+":"+actionKey,
		c.Request.Method,
		c.Request.URL.Path,
		c.ClientIP(),
		c.GetHeader("User-Agent"),
		a.brokerStatus,
		0,
		nil,
		newValues,
		a.denyReason,
	)

	// Durable, queryable action-audit record (source of truth for the activity
	// view): who / on-whose-behalf / which token / F8 outcome triad. Best-effort.
	rec := &models.ConnectorActionAudit{
		WorkspaceID:    authCtx.Principal.WorkspaceID,
		ActionKey:      actionKey,
		AuthzOutcome:   a.authzOutcome,
		BrokerStatus:   a.brokerStatus,
		ProviderStatus: a.providerStatus,
		ActionOutcome:  a.actionOutcome,
		DenyReason:     a.denyReason,
		SubjectType:    authCtx.Principal.SubjectType,
		TokenFamily:    authCtx.TokenFamily,
		TokenJTI:       authCtx.JTI,
	}
	if sid := authCtx.Principal.SubjectID; sid != uuid.Nil {
		rec.SubjectID = &sid
	}
	if cid, err := uuid.Parse(connectorID); err == nil {
		rec.ConnectorID = &cid
	}
	// F7b — "actor always": use the act claim's client when present (XAA/CIBA),
	// otherwise fall back to the authenticating client (direct M2M). Without this
	// a direct-M2M action recorded no actor at all.
	if authCtx.Actor != nil {
		rec.ActorClientID = authCtx.Actor.ClientID
		if authCtx.Actor.SpiffeID != nil {
			rec.ActorSpiffeID = *authCtx.Actor.SpiffeID
		}
	} else {
		rec.ActorClientID = authCtx.ClientID
	}
	// F7c — "owner always": stamp the accountable human from the acting service
	// account into every row, so an autonomous action is never unattributable.
	if authCtx.Principal.SubjectType == tokens.SubjectTypeServiceAccount && authCtx.Principal.SubjectID != uuid.Nil {
		var owner struct {
			OwnerEmail *string
			OwnerTeam  *string
		}
		if e := ctl.db.Table("service_accounts").
			Select("owner_email, owner_team").
			Where("id = ?", authCtx.Principal.SubjectID).Scan(&owner).Error; e == nil {
			if owner.OwnerEmail != nil {
				rec.OwnerEmail = *owner.OwnerEmail
			}
			if owner.OwnerTeam != nil {
				rec.OwnerTeam = *owner.OwnerTeam
			}
		}
	}
	if err := ctl.repo().RecordActionAudit(rec); err != nil {
		log.Printf("BROKER: failed to write action audit: %v", err)
	}
}

// evalInputConstraints enforces a per-assignment F3 predicate against an
// action's input. The constraints JSON maps input field → rule, and ALL listed
// fields must satisfy their rule (AND). Supported per-field rules:
//
//	{"equals": "acme-eng"}          field must equal exactly
//	{"one_of": ["a","b"]}           field must be one of the values
//	{"glob":  "release-*"}          field must match the glob (* wildcard)
//
// Empty/absent constraints = allow. A listed field missing from the input, or a
// non-string input value where a rule expects one, is a violation (fail closed).
// Returns (ok, reason-when-not-ok).
func evalInputConstraints(raw json.RawMessage, input map[string]interface{}) (bool, string) {
	if len(raw) == 0 || string(raw) == "{}" || string(raw) == "null" {
		return true, ""
	}
	var rules map[string]struct {
		Equals *string  `json:"equals"`
		OneOf  []string `json:"one_of"`
		Glob   *string  `json:"glob"`
	}
	if err := json.Unmarshal(raw, &rules); err != nil {
		// Malformed constraints → fail closed (never silently allow).
		return false, "malformed input_constraints"
	}
	for field, rule := range rules {
		v, present := input[field]
		s, isStr := v.(string)
		if !present || !isStr {
			return false, "field " + field + " missing or not a string"
		}
		switch {
		case rule.Equals != nil:
			if s != *rule.Equals {
				return false, field + " must equal " + *rule.Equals
			}
		case rule.OneOf != nil:
			matched := false
			for _, allowed := range rule.OneOf {
				if s == allowed {
					matched = true
					break
				}
			}
			if !matched {
				return false, field + " not in allowed set"
			}
		case rule.Glob != nil:
			if !globMatch(*rule.Glob, s) {
				return false, field + " does not match " + *rule.Glob
			}
		default:
			return false, "no rule for field " + field
		}
	}
	return true, ""
}

// globMatch does simple glob matching where '*' matches any run of characters
// (including empty). No other metacharacters — small, predictable, injection-safe.
func globMatch(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return s == pattern // no wildcard → exact
	}
	// Must start with the first part and end with the last part.
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	if !strings.HasSuffix(s, parts[len(parts)-1]) {
		return false
	}
	pos := len(parts[0])
	for _, mid := range parts[1 : len(parts)-1] {
		idx := strings.Index(s[pos:], mid)
		if idx < 0 {
			return false
		}
		pos += idx + len(mid)
	}
	return pos <= len(s)
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
