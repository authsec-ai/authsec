package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// IGAController serves /api/iga/v1 — the Agentic IGA read/write surface plus
// the provider ingress.
//
// Two rules shape every handler here. The authenticated workspace comes from
// middleware and is never read from a body, query parameter or provider
// identifier. And unknown coverage is reported as unknown: a response never
// implies zero agents for estate that was not inspected.
type IGAController struct {
	db *gorm.DB
}

// NewIGAController constructs an IGAController.
func NewIGAController(db *gorm.DB) *IGAController { return &IGAController{db: db} }

// manager builds the service with the configured provider. Until the Stage-0
// spike records real endpoint fixtures, the fixture provider is the honest
// default — it exercises the whole pipeline without pretending to have
// verified GitHub behaviour that nobody has measured yet.
func (ctl *IGAController) manager() services.IGAManager {
	return services.NewIGAManager(repositories.NewIGARepository(ctl.db), ctl.provider())
}

// provider chooses the discovery source.
//
// The live GitHub client is OPT-IN via IGA_GITHUB_LIVE=1. Its transport is
// tested, but its endpoint shapes have not been confirmed against a real
// tenant, and turning it on by default would dress unverified endpoint mapping
// up as working discovery. It also reuses the connector's existing GitHub App
// credentials rather than standing up a second private-key store.
func (ctl *IGAController) provider() services.IGAProvider {
	if igaProviderOverride != nil {
		return igaProviderOverride
	}
	if os.Getenv("IGA_GITHUB_LIVE") == "1" {
		vc, err := vault.NewClient(os.Getenv("VAULT_ADDR"), os.Getenv("VAULT_TOKEN"))
		if err == nil {
			return services.NewGitHubProviderFromConnector(ctl.db, vc)
		}
		// Vault is unreachable, so no App key can be read and no token minted.
		// Falling back to fixtures here would be the worst possible outcome: the
		// scan would "succeed", find nothing, and publish that nothing as
		// authoritative coverage. Refuse instead.
		return &services.UnavailableProvider{
			Reason: "IGA_GITHUB_LIVE is set but Vault is unreachable, so the GitHub App private key cannot be read",
		}
	}
	// Live mode is off. Return a provider that refuses rather than one that
	// silently reports an empty estate — an inaccessible source must never
	// contribute a zero-agent conclusion.
	return &services.UnavailableProvider{
		Reason: "GitHub discovery is not enabled; set IGA_GITHUB_LIVE=1 and configure Vault plus a GitHub App in the connector",
	}
}

var igaProviderOverride services.IGAProvider

// SetIGAProvider swaps the provider. Used to install a fixture set for
// end-to-end testing without a live tenant.
func SetIGAProvider(p services.IGAProvider) { igaProviderOverride = p }

/* ------------------------------- helpers ------------------------------- */

func (ctl *IGAController) workspace(c *gin.Context) (uuid.UUID, string, error) {
	ws := c.GetString("workspace_id")
	if ws == "" {
		return uuid.Nil, "", fmt.Errorf("workspace_id not found in token")
	}
	id, err := uuid.Parse(ws)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("invalid workspace_id: %w", err)
	}
	actor := c.GetString("client_id")
	if actor == "" {
		if u, uerr := middlewares.ResolveUserID(c); uerr == nil {
			actor = u
		}
	}
	if actor == "" {
		actor = ws
	}
	return id, actor, nil
}

// igaError maps a domain error to the status the API contract requires.
// Permission denial, absence, staleness and conflict are distinct machine
// states — collapsing them into 500 is what the contract forbids.
func igaError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, repositories.ErrIGANotFound):
		c.JSON(http.StatusNotFound, igaProblem("not_found", "Resource not found", http.StatusNotFound, c))
	case errors.Is(err, repositories.ErrIGAVersionStale):
		c.JSON(http.StatusConflict, igaProblem("version_conflict",
			"The resource changed since you read it; re-read and retry", http.StatusConflict, c))
	case errors.Is(err, repositories.ErrIGABindingFailed):
		c.JSON(http.StatusForbidden, igaProblem("binding_failed", err.Error(), http.StatusForbidden, c))
	case errors.Is(err, repositories.ErrIGASignature):
		c.JSON(http.StatusUnauthorized, igaProblem("signature_invalid",
			"Webhook signature verification failed", http.StatusUnauthorized, c))
	default:
		// An unreachable provider is 503, never 400 and never an empty 200.
		// "We could not look" and "we looked and found nothing" are opposite
		// facts about a customer's security posture; a 400 invites a client to
		// render the first as a caller mistake, one step from a false all-clear.
		var unavailable *services.ProviderUnavailableError
		if errors.As(err, &unavailable) {
			c.JSON(http.StatusServiceUnavailable,
				igaProblem("provider_unavailable", err.Error(), http.StatusServiceUnavailable, c))
			return
		}
		c.JSON(http.StatusBadRequest, igaProblem("invalid_request", err.Error(), http.StatusBadRequest, c))
	}
}

// igaProblem is the single structured error object. Provider payloads, tokens
// and secret material never appear in it.
func igaProblem(code, title string, status int, c *gin.Context) gin.H {
	return gin.H{
		"type":       "about:blank",
		"title":      title,
		"status":     status,
		"code":       code,
		"request_id": c.GetString("request_id"),
	}
}

// igaMeta is the common response envelope. as_of and coverage travel with every
// collection so a caller can tell a real zero from an uninspected scope.
func igaMeta(coverage []models.IGACoverageState) gin.H {
	if coverage == nil {
		coverage = []models.IGACoverageState{}
	}
	return gin.H{"as_of": time.Now().UTC(), "coverage": coverage}
}

// igaPage reads the opaque cursor and page size. Offset is deliberately NOT
// supported: on an inventory that changes under the reader, offset pagination
// silently skips and repeats rows, which the API contract forbids.
func igaPage(c *gin.Context) (cursor string, limit int) {
	limit, _ = strconv.Atoi(c.Query("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	return c.Query("cursor"), limit
}

// idempotent wraps a mutating handler so a replayed Idempotency-Key returns the
// original result instead of acting twice. Reuse with a DIFFERENT body is a
// conflict, not a silent second execution.
func (ctl *IGAController) idempotent(c *gin.Context, ws uuid.UUID, route string, body []byte, run func() (int, interface{}, error)) {
	key := c.GetHeader("Idempotency-Key")
	if key == "" {
		c.JSON(http.StatusBadRequest, igaProblem("idempotency_key_required",
			"Idempotency-Key header is required on this route", http.StatusBadRequest, c))
		return
	}
	hash := services.HashBody(append([]byte(route+"|"), body...))
	repo := repositories.NewIGARepository(ctl.db)

	if prior, err := repo.GetIdempotent(ws, key); err == nil {
		if prior.RequestHash != hash {
			c.JSON(http.StatusConflict, igaProblem("idempotency_key_reused",
				"This Idempotency-Key was used with a different request body",
				http.StatusConflict, c))
			return
		}
		// Same key, same request: replay the stored response verbatim.
		c.Data(prior.ResponseStatus, "application/json", prior.ResponseBody)
		return
	}

	status, payload, err := run()
	if err != nil {
		igaError(c, err)
		return
	}
	encoded, _ := json.Marshal(payload)
	_ = repo.PutIdempotent(&repositories.IdempotencyRecord{
		WorkspaceID: ws, IdempotencyKey: key, Route: route,
		RequestHash: hash, ResponseStatus: status, ResponseBody: encoded,
	})
	c.Data(status, "application/json", encoded)
}

// expectedVersion reads the optimistic-concurrency token, preferring If-Match
// and falling back to the body field.
func expectedVersion(c *gin.Context, fromBody int64) (int64, bool) {
	raw := strings.Trim(c.GetHeader("If-Match"), `"`)
	if raw == "" {
		if fromBody <= 0 {
			return 0, false
		}
		return fromBody, true
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v <= 0 {
		return 0, false
	}
	return v, true
}

/* ----------------------------- integrations ---------------------------- */

// IGAIntegrationCreateRequest starts an authorization. No installation id: it
// arrives from the provider and is untrusted until verified.
type IGAIntegrationCreateRequest struct {
	Provider             string                 `json:"provider" binding:"required"`
	ProviderHost         string                 `json:"provider_host" binding:"required"`
	AppRegistrationID    string                 `json:"app_registration_id" binding:"required"`
	CapabilityProfile    map[string]interface{} `json:"capability_profile,omitempty"`
	RequestedPermissions map[string]interface{} `json:"requested_permissions,omitempty"`
}

// IGAVerifyRequest completes the callback. authenticated_account_id is the
// account of the admin who actually authorized; the binding is refused unless
// it matches the installation's account.
type IGAVerifyRequest struct {
	InstallationID         string                 `json:"installation_id" binding:"required"`
	AccountNativeID        string                 `json:"account_native_id" binding:"required"`
	AuthenticatedAccountID string                 `json:"authenticated_account_id" binding:"required"`
	GrantedPermissions     map[string]interface{} `json:"granted_permissions,omitempty"`
}

func (ctl *IGAController) CreateIntegration(c *gin.Context) {
	ws, actor, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, igaProblem("unauthenticated", err.Error(), http.StatusUnauthorized, c))
		return
	}
	var req IGAIntegrationCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		igaError(c, err)
		return
	}
	out, err := ctl.manager().CreateIntegration(ws, actor, services.IntegrationInput{
		Provider:             req.Provider,
		ProviderHost:         req.ProviderHost,
		AppRegistrationID:    req.AppRegistrationID,
		CapabilityProfile:    req.CapabilityProfile,
		RequestedPermissions: req.RequestedPermissions,
	})
	if err != nil {
		igaError(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "create", "iga_integration", out.ID.String(), http.StatusCreated, nil, out)
	c.JSON(http.StatusCreated, gin.H{"data": out, "meta": igaMeta(nil)})
}

func (ctl *IGAController) VerifyIntegration(c *gin.Context) {
	ws, actor, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, igaProblem("unauthenticated", err.Error(), http.StatusUnauthorized, c))
		return
	}
	id, err := uuid.Parse(c.Param("integration_id"))
	if err != nil {
		igaError(c, err)
		return
	}
	var req IGAVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		igaError(c, err)
		return
	}
	out, err := ctl.manager().VerifyIntegration(ws, id, services.VerifyInput{
		InstallationID:         req.InstallationID,
		AccountNativeID:        req.AccountNativeID,
		AuthenticatedAccountID: req.AuthenticatedAccountID,
		GrantedPermissions:     req.GrantedPermissions,
	})
	if err != nil {
		igaError(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "verify", "iga_integration", id.String(), http.StatusOK, nil, out)
	_ = actor
	c.JSON(http.StatusOK, gin.H{"data": out, "meta": igaMeta(nil)})
}

func (ctl *IGAController) GetIntegration(c *gin.Context) {
	ws, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, igaProblem("unauthenticated", err.Error(), http.StatusUnauthorized, c))
		return
	}
	id, err := uuid.Parse(c.Param("integration_id"))
	if err != nil {
		igaError(c, err)
		return
	}
	mgr := ctl.manager()
	out, err := mgr.GetIntegration(ws, id)
	if err != nil {
		igaError(c, err)
		return
	}
	cov, _ := mgr.Coverage(ws, id)
	c.JSON(http.StatusOK, gin.H{"data": out, "meta": igaMeta(cov)})
}

func (ctl *IGAController) ListIntegrations(c *gin.Context) {
	ws, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, igaProblem("unauthenticated", err.Error(), http.StatusUnauthorized, c))
		return
	}
	out, err := ctl.manager().ListIntegrations(ws)
	if err != nil {
		igaError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out, "meta": igaMeta(nil)})
}

func (ctl *IGAController) DisconnectIntegration(c *gin.Context) {
	ws, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, igaProblem("unauthenticated", err.Error(), http.StatusUnauthorized, c))
		return
	}
	id, err := uuid.Parse(c.Param("integration_id"))
	if err != nil {
		igaError(c, err)
		return
	}
	if err := ctl.manager().Disconnect(ws, id); err != nil {
		igaError(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "disconnect", "iga_integration", id.String(), http.StatusOK, nil, nil)
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"status": "disconnected", "history_retained": true}})
}

/* --------------------------------- scans -------------------------------- */

func (ctl *IGAController) CreateScan(c *gin.Context) {
	ws, actor, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, igaProblem("unauthenticated", err.Error(), http.StatusUnauthorized, c))
		return
	}
	id, err := uuid.Parse(c.Param("integration_id"))
	if err != nil {
		igaError(c, err)
		return
	}
	mgr := ctl.manager()
	// A retried POST must not launch a second scan.
	ctl.idempotent(c, ws, "POST /integrations/scans", []byte(id.String()+c.Query("mode")),
		func() (int, interface{}, error) {
			run, err := mgr.StartScan(ws, id, c.Query("mode"), actor)
			if err != nil {
				return 0, nil, err
			}
			// Run inline so the scan is observable in a single call. A
			// production deployment hands this to the worker; the durable job
			// path already exists for the webhook-driven case.
			report, err := mgr.RunScan(c.Request.Context(), ws, run.ID)
			if err != nil {
				return 0, nil, err
			}
			auditAdminMutation(c, ws.String(), "scan", "iga_integration", id.String(),
				http.StatusAccepted, nil, report)
			return http.StatusAccepted, gin.H{"data": report, "meta": igaMeta(report.Coverage)}, nil
		})
}

func (ctl *IGAController) GetScanRun(c *gin.Context) {
	ws, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, igaProblem("unauthenticated", err.Error(), http.StatusUnauthorized, c))
		return
	}
	id, err := uuid.Parse(c.Param("scan_id"))
	if err != nil {
		igaError(c, err)
		return
	}
	out, err := ctl.manager().GetScanRun(ws, id)
	if err != nil {
		igaError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out, "meta": igaMeta(nil)})
}

// GetCoverage returns per-scope, per-object-class state. There is no averaged
// percentage anywhere in this response, by design.
func (ctl *IGAController) GetCoverage(c *gin.Context) {
	ws, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, igaProblem("unauthenticated", err.Error(), http.StatusUnauthorized, c))
		return
	}
	id, err := uuid.Parse(c.Param("integration_id"))
	if err != nil {
		igaError(c, err)
		return
	}
	out, err := ctl.manager().Coverage(ws, id)
	if err != nil {
		igaError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out, "meta": gin.H{"as_of": time.Now().UTC(), "averaged": false}})
}

// GetSourceHealth returns operational issues — permission loss, truncation,
// rate limiting. Deliberately a different route from findings: a scan failure
// is an administrator's problem, not a security fact about an agent.
func (ctl *IGAController) GetSourceHealth(c *gin.Context) {
	ws, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, igaProblem("unauthenticated", err.Error(), http.StatusUnauthorized, c))
		return
	}
	id, err := uuid.Parse(c.Param("integration_id"))
	if err != nil {
		igaError(c, err)
		return
	}
	out, err := ctl.manager().SourceHealth(ws, &id)
	if err != nil {
		igaError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out, "meta": igaMeta(nil)})
}

/* ------------------------------- inventory ------------------------------ */

// ListAgents returns confirmed agents. Candidates are a DIFFERENT route with a
// different count — the headline never adds them together.
func (ctl *IGAController) ListAgents(c *gin.Context) {
	ws, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, igaProblem("unauthenticated", err.Error(), http.StatusUnauthorized, c))
		return
	}
	cursor, limit := igaPage(c)
	page, err := ctl.manager().ListAgentsPage(ws, c.Query("rollup_state"), cursor, limit)
	if err != nil {
		igaError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": page.Items,
		"meta": gin.H{"as_of": time.Now().UTC(), "total_confirmed_agents": page.Total,
			"note": "candidates, identities and credentials are counted separately"},
		"page": gin.H{"limit": limit, "next_cursor": page.NextCursor},
	})
}

func (ctl *IGAController) GetAgent(c *gin.Context) {
	ws, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, igaProblem("unauthenticated", err.Error(), http.StatusUnauthorized, c))
		return
	}
	id, err := uuid.Parse(c.Param("agent_id"))
	if err != nil {
		igaError(c, err)
		return
	}
	out, err := ctl.manager().AgentDetail(ws, id)
	if err != nil {
		igaError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data":  out,
		"links": gin.H{"evidence": fmt.Sprintf("/api/iga/v1/agents/%s/evidence", id)},
		"meta":  igaMeta(nil),
	})
}

// GetAgentEvidence is the drill-down: the observations behind the agent.
func (ctl *IGAController) GetAgentEvidence(c *gin.Context) {
	ws, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, igaProblem("unauthenticated", err.Error(), http.StatusUnauthorized, c))
		return
	}
	id, err := uuid.Parse(c.Param("agent_id"))
	if err != nil {
		igaError(c, err)
		return
	}
	out, err := ctl.manager().AgentEvidence(ws, id)
	if err != nil {
		igaError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out, "meta": igaMeta(nil)})
}

func (ctl *IGAController) ListCandidates(c *gin.Context) {
	ws, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, igaProblem("unauthenticated", err.Error(), http.StatusUnauthorized, c))
		return
	}
	cursor, limit := igaPage(c)
	state := c.DefaultQuery("state", models.CandidatePending)
	page, err := ctl.manager().ListCandidatesPage(ws, state, cursor, limit)
	if err != nil {
		igaError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": page.Items,
		"meta": gin.H{"as_of": time.Now().UTC(), "total_candidates": page.Total,
			"note": "candidates are NOT confirmed agents and are counted separately"},
		"page": gin.H{"limit": limit, "next_cursor": page.NextCursor},
	})
}

// IGADecisionRequest carries a governance decision. expected_version is
// mandatory: a stale decision is rejected rather than silently overwriting.
type IGADecisionRequest struct {
	Decision        string `json:"decision" binding:"required"`
	Reason          string `json:"reason,omitempty"`
	ExpectedVersion int64  `json:"expected_version,omitempty"`
}

func (ctl *IGAController) DecideCandidate(c *gin.Context) {
	ws, actor, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, igaProblem("unauthenticated", err.Error(), http.StatusUnauthorized, c))
		return
	}
	id, err := uuid.Parse(c.Param("candidate_id"))
	if err != nil {
		igaError(c, err)
		return
	}
	var req IGADecisionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		igaError(c, err)
		return
	}
	ver, ok := expectedVersion(c, req.ExpectedVersion)
	if !ok {
		c.JSON(http.StatusPreconditionRequired, igaProblem("expected_version_required",
			"Supply If-Match with the version you read, or expected_version in the body",
			http.StatusPreconditionRequired, c))
		return
	}
	ctl.idempotent(c, ws, "POST /classification-candidates/decisions",
		[]byte(fmt.Sprintf("%s|%s|%d", id, req.Decision, ver)),
		func() (int, interface{}, error) {
			out, err := ctl.manager().DecideCandidate(ws, id, ver, req.Decision, req.Reason, actor)
			if err != nil {
				return 0, nil, err
			}
			auditAdminMutation(c, ws.String(), req.Decision, "iga_candidate", id.String(),
				http.StatusOK, nil, out)
			return http.StatusOK, gin.H{"data": out, "meta": igaMeta(nil)}, nil
		})
}

func (ctl *IGAController) DecideOwnership(c *gin.Context) {
	ws, actor, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, igaProblem("unauthenticated", err.Error(), http.StatusUnauthorized, c))
		return
	}
	id, err := uuid.Parse(c.Param("candidate_id"))
	if err != nil {
		igaError(c, err)
		return
	}
	var req IGADecisionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		igaError(c, err)
		return
	}
	ver, ok := expectedVersion(c, req.ExpectedVersion)
	if !ok {
		c.JSON(http.StatusPreconditionRequired, igaProblem("expected_version_required",
			"Supply If-Match with the version you read, or expected_version in the body",
			http.StatusPreconditionRequired, c))
		return
	}
	out, err := ctl.manager().DecideOwnership(ws, id, ver, req.Decision, actor)
	if err != nil {
		igaError(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), req.Decision, "iga_ownership_candidate", id.String(), http.StatusOK, nil, out)
	c.JSON(http.StatusOK, gin.H{
		"data": out,
		"meta": gin.H{"as_of": time.Now().UTC(),
			"note": "technical owner only; business sponsor is a separate governance action"},
	})
}

/* -------------------------------- ingress ------------------------------- */

// ReceiveWebhook implements the normative ingress order:
//
//	read the raw body once (bounded)  ->  verify HMAC over those exact bytes
//	 ->  resolve the binding server-side  ->  commit delivery + job in one
//	 transaction  ->  only then 202.
//
// The route is necessarily unauthenticated at the token layer — GitHub has no
// AuthSec token — but it is NOT unauthenticated: the signature is the
// authentication, and the workspace comes from the resolved binding, never
// from the payload.
func (ctl *IGAController) ReceiveWebhook(c *gin.Context) {
	appRegID := c.Param("app_registration_id")

	// Bounded read. An oversized body is rejected before any parsing and
	// without touching the queue.
	const maxBody = 5 << 20
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxBody+1))
	if err != nil {
		c.JSON(http.StatusBadRequest, igaProblem("unreadable_body", "Could not read request body", http.StatusBadRequest, c))
		return
	}
	if len(body) > maxBody {
		c.JSON(http.StatusRequestEntityTooLarge,
			igaProblem("payload_too_large", "Webhook body exceeds limit", http.StatusRequestEntityTooLarge, c))
		return
	}

	secret := os.Getenv("IGA_GITHUB_WEBHOOK_SECRET")

	res, err := ctl.manager().AcceptWebhook(services.WebhookInput{
		AppRegistrationID: appRegID,
		DeliveryID:        c.GetHeader("X-GitHub-Delivery"),
		EventType:         c.GetHeader("X-GitHub-Event"),
		Action:            c.Query("action"),
		Signature:         c.GetHeader("X-Hub-Signature-256"),
		Secret:            secret,
		Body:              body,
		InstallationID:    c.GetHeader("X-GitHub-Installation-ID"),
	})
	if err != nil {
		igaError(c, err)
		return
	}

	// 202 only after the durable records committed.
	c.JSON(http.StatusAccepted, gin.H{"data": gin.H{
		"accepted": res.Accepted, "redelivery": res.Redelivery,
	}})
}

// ListIdentityAccounts handles GET /api/iga/v1/identity-accounts — the GitHub
// identities and their non-secret credential metadata. Separate route and
// separate count from agents: an App installation or a PAT is an identity, and
// calling it an agent is the mistake this separation exists to prevent.
func (ctl *IGAController) ListIdentityAccounts(c *gin.Context) {
	ws, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, igaProblem("unauthenticated", err.Error(), http.StatusUnauthorized, c))
		return
	}
	cursor, limit := igaPage(c)
	page, err := ctl.manager().ListIdentityAccountsPage(ws, cursor, limit)
	if err != nil {
		igaError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data": page.Items,
		"meta": gin.H{"as_of": time.Now().UTC(), "total_identities": page.Total,
			"note": "identities and credentials are never counted as agents"},
		"page": gin.H{"limit": limit, "next_cursor": page.NextCursor},
	})
}

// GetAgentAccessPaths handles GET /api/iga/v1/agents/:agent_id/access-paths.
//
// The summary is the important half of the response: an empty path list means
// "not calculated", not "no access", and the payload says which.
func (ctl *IGAController) GetAgentAccessPaths(c *gin.Context) {
	ws, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, igaProblem("unauthenticated", err.Error(), http.StatusUnauthorized, c))
		return
	}
	id, err := uuid.Parse(c.Param("agent_id"))
	if err != nil {
		igaError(c, err)
		return
	}
	paths, summary, err := ctl.manager().AgentAccessPaths(ws, id)
	if err != nil {
		igaError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data":  paths,
		"meta":  gin.H{"as_of": time.Now().UTC(), "access_summary": summary},
		"links": gin.H{"evidence": fmt.Sprintf("/api/iga/v1/agents/%s/evidence", id)},
	})
}
