package platform

// Discovery ingress authentication: the ingest tokens an agent presents on
// /authsec/discovery/{agent-registration,sightings,lifecycle,resync-manifest,
// rbac-snapshot}, the admin endpoints that mint and revoke them, and the
// enforcement every ingress handler runs before it trusts the workspace_id in
// its body. Rollout: DISCOVERY_INGEST_AUTH.md next to this file.

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/authsec-ai/authsec/monitoring"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

/* -------------------------------------------------------------------------- */
/*                         Admin: mint, list, revoke                          */
/* -------------------------------------------------------------------------- */

// MountDiscoveryIngestTokenRoutes registers the ingest-token admin endpoints
// on an AUTHENTICATED discovery group (routes.go's /authsec/discovery behind
// AuthMiddleware). All three are discovery:admin: a token is a credential that
// writes into the workspace's inventory and graph, and even its list is
// credential metadata.
func MountDiscoveryIngestTokenRoutes(g gin.IRouter, ctl *DiscoveryController, require func(resource, action string) gin.HandlerFunc) {
	g.POST("/ingest-tokens", require("discovery", "admin"), ctl.MintIngestToken)
	g.GET("/ingest-tokens", require("discovery", "admin"), ctl.ListIngestTokens)
	g.DELETE("/ingest-tokens/:id", require("discovery", "admin"), ctl.RevokeIngestToken)
}

// IngestTokenMintRequest is the body for POST /authsec/discovery/ingest-tokens.
// There is deliberately no workspace field: the workspace is the caller's.
type IngestTokenMintRequest struct {
	// DiscoverySourceID binds the token to one source of the workspace. Omit
	// it for an enrollment token, valid for any of the workspace's sources
	// (and the only kind usable before the agent has registered).
	DiscoverySourceID *uuid.UUID `json:"discovery_source_id,omitempty"`
	Label             string     `json:"label,omitempty"`
}

func (ctl *DiscoveryController) ingestTokens() *services.DiscoveryIngestTokens {
	return services.NewDiscoveryIngestTokens(ctl.db)
}

// MintIngestToken handles POST /authsec/discovery/ingest-tokens. The response
// is the only place the plaintext token ever appears.
func (ctl *DiscoveryController) MintIngestToken(c *gin.Context) {
	wsID, principal, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	var req IngestTokenMintRequest
	// An empty body is a valid request: an unbound, unlabelled token.
	if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.Label) > 200 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "label must be at most 200 characters"})
		return
	}

	row, plain, err := ctl.ingestTokens().Mint(wsID, req.DiscoverySourceID, req.Label, principal)
	if errors.Is(err, repositories.ErrIngestTokenSourceNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not mint ingest token"})
		return
	}
	// The audit record carries the row, which has no hash and no plaintext.
	auditAdminMutation(c, wsID.String(), "create", "discovery_ingest_token",
		row.ID.String(), http.StatusCreated, nil, row)
	c.JSON(http.StatusCreated, gin.H{
		"id":                  row.ID,
		"token":               plain,
		"token_prefix":        row.TokenPrefix,
		"workspace_id":        row.WorkspaceID,
		"discovery_source_id": row.DiscoverySourceID,
		"label":               row.Label,
		"created_by":          row.CreatedBy,
		"created_at":          row.CreatedAt,
		"last_used_at":        row.LastUsedAt,
		"revoked_at":          row.RevokedAt,
	})
}

// ListIngestTokens handles GET /authsec/discovery/ingest-tokens: the caller's
// workspace's tokens, newest first, revoked ones included. Never a hash.
func (ctl *DiscoveryController) ListIngestTokens(c *gin.Context) {
	wsID, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	out, err := ctl.ingestTokens().List(wsID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not list ingest tokens"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tokens": out})
}

// RevokeIngestToken handles DELETE /authsec/discovery/ingest-tokens/:id. The
// row stays, with revoked_at set; a token of another workspace is a 404.
func (ctl *DiscoveryController) RevokeIngestToken(c *gin.Context) {
	wsID, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	id, err := pathID(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	row, err := ctl.ingestTokens().Revoke(wsID, id)
	if errors.Is(err, repositories.ErrIngestTokenNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not revoke ingest token"})
		return
	}
	auditAdminMutation(c, wsID.String(), "revoke", "discovery_ingest_token",
		row.ID.String(), http.StatusOK, nil, row)
	c.JSON(http.StatusOK, row)
}

/* -------------------------------------------------------------------------- */
/*                         Ingress: enforcement                               */
/* -------------------------------------------------------------------------- */

// LogDiscoveryIngestAuthMode logs the ingress auth mode, once, at route setup,
// so which mode a deployment runs in is never a guess.
func LogDiscoveryIngestAuthMode() {
	log.Printf("discovery ingress auth mode: %s (%s)",
		services.DiscoveryIngestAuthModeFromEnv(), services.DiscoveryIngestAuthEnv)
}

// Context keys set on an authenticated ingress call.
const (
	ctxIngestTokenID     = "discovery_ingest_token_id"
	ctxIngestTokenPrefix = "discovery_ingest_token_prefix"
)

// ingestCounts counts ingress auth outcomes since start, by outcome and
// reason. Warn mode's whole purpose is that an operator can watch the
// unauthenticated counts fall to zero before switching to enforce.
var ingestCounts sync.Map // string -> *atomic.Int64

func countIngest(key string) {
	v, _ := ingestCounts.LoadOrStore(key, new(atomic.Int64))
	v.(*atomic.Int64).Add(1)
}

// DiscoveryIngestAuthCounts returns the ingress auth counters since start:
//
//	accepted_token                      authenticated calls
//	accepted_unauthenticated_<reason>   warn mode, let through
//	rejected_unauthenticated_<reason>   enforce mode, 401
//	rejected_other_workspace            403
//	error                               verification could not run
//
// reason is missing | invalid | wrong_source. The same outcomes are exported
// to Prometheus as auth_requests_total{auth_type="discovery_ingest"}.
func DiscoveryIngestAuthCounts() map[string]int64 {
	out := map[string]int64{}
	ingestCounts.Range(func(k, v any) bool {
		out[k.(string)] = v.(*atomic.Int64).Load()
		return true
	})
	return out
}

// ingestLogEvery bounds the ingress auth log: one line per key per interval,
// carrying how many were suppressed since the last, so a large cluster's
// sightings do not flood the log while the signal stays exact.
const ingestLogEvery = time.Minute

// ingestLogMaxKeys caps the throttle table. Keys include a workspace only once
// that workspace is known to exist, but the cap keeps the table bounded
// whatever arrives; when it is reached the table starts over.
const ingestLogMaxKeys = 4096

type ingestLogState struct {
	mu         sync.Mutex
	last       time.Time
	suppressed int64
}

var (
	ingestLogStates sync.Map // string -> *ingestLogState
	ingestLogKeys   atomic.Int64
)

func logIngestThrottled(key, msg string) {
	v, loaded := ingestLogStates.LoadOrStore(key, &ingestLogState{})
	if !loaded && ingestLogKeys.Add(1) > ingestLogMaxKeys {
		ingestLogStates.Range(func(k, _ any) bool {
			ingestLogStates.Delete(k)
			return true
		})
		ingestLogKeys.Store(0)
	}
	st := v.(*ingestLogState)
	st.mu.Lock()
	defer st.mu.Unlock()
	now := time.Now()
	if !st.last.IsZero() && now.Sub(st.last) < ingestLogEvery {
		st.suppressed++
		return
	}
	if st.suppressed > 0 {
		msg = fmt.Sprintf("%s (+%d similar in the last %s)", msg, st.suppressed, now.Sub(st.last).Round(time.Second))
	}
	st.last, st.suppressed = now, 0
	log.Print(msg)
}

// presentedPrefix is what may be logged of a presented credential: the same
// eight characters the token list shows, never enough to use it.
func presentedPrefix(tok string) string {
	if len(tok) > 8 {
		return tok[:8]
	}
	return ""
}

// staticIngestSource resolves a call to the source its body names.
func staticIngestSource(id *uuid.UUID) func(uuid.UUID) func() (*uuid.UUID, error) {
	return func(uuid.UUID) func() (*uuid.UUID, error) {
		return func() (*uuid.UUID, error) { return id, nil }
	}
}

// parsedIngestSource is staticIngestSource for a body that carries the id as a
// string (the RBAC snapshot). Empty or malformed names no source.
func parsedIngestSource(raw string) func(uuid.UUID) func() (*uuid.UUID, error) {
	var id *uuid.UUID
	if parsed, err := uuid.Parse(raw); err == nil {
		id = &parsed
	}
	return staticIngestSource(id)
}

// registrationIngestSource resolves an agent-registration to the source it
// would upsert: the self-registered row keyed by (workspace, kind,
// instance_id). None yet means the call would CREATE a source, which a token
// bound to an existing one does not authorise.
func (ctl *DiscoveryController) registrationIngestSource(kind, instanceID string) func(uuid.UUID) func() (*uuid.UUID, error) {
	return func(wsID uuid.UUID) func() (*uuid.UUID, error) {
		return func() (*uuid.UUID, error) {
			if instanceID == "" {
				return nil, nil
			}
			var ids []uuid.UUID
			if err := ctl.db.Table("discovery_sources").
				Where("workspace_id = ? AND kind = ? AND instance_id = ?", wsID, kind, instanceID).
				Limit(1).Pluck("id", &ids).Error; err != nil {
				return nil, err
			}
			if len(ids) == 0 {
				return nil, nil
			}
			return &ids[0], nil
		}
	}
}

// ingressWorkspace replaces assertedWorkspace on the ingress: it parses the
// body's workspace (400 if not a uuid, unchanged), authorises the call's
// ingest token against it per IGA_DISCOVERY_INGEST_AUTH, and only then
// confirms the workspace exists, so an unauthenticated caller in enforce mode
// learns nothing about which workspace ids are real. On false the response
// has been written; on true nothing has, and the handler answers exactly as
// it did before ingest tokens existed.
//
// source is a constructor rather than an id because the registration route
// has to look its source up, and that lookup is only worth doing for a token
// bound to a source.
func (ctl *DiscoveryController) ingressWorkspace(c *gin.Context, raw string,
	source func(uuid.UUID) func() (*uuid.UUID, error)) (uuid.UUID, bool) {
	wsID, err := uuid.Parse(raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("workspace_id %q is not a valid uuid", raw),
		})
		return uuid.Nil, false
	}
	ok, accepted := ctl.authorizeIngest(c, wsID, source(wsID))
	if !ok {
		return uuid.Nil, false
	}
	if _, ok = ctl.assertedWorkspace(c, raw); !ok {
		return uuid.Nil, false
	}
	// Recorded only for a workspace that exists, so what is logged and
	// exported per workspace cannot be grown by posting made-up ids.
	accepted()
	return wsID, true
}

// authorizeIngest runs the decision and maps a refusal to HTTP. On ok it
// returns what to record once the workspace is confirmed to exist.
func (ctl *DiscoveryController) authorizeIngest(c *gin.Context, wsID uuid.UUID,
	resolveSource func() (*uuid.UUID, error)) (ok bool, accepted func()) {
	nothing := func() {}
	mode := services.DiscoveryIngestAuthModeFromEnv()
	if mode == services.IngestAuthOff {
		return true, nothing
	}
	presented := bearerToken(c)
	route := c.Request.URL.Path
	d, err := ctl.ingestTokens().Authorize(mode, presented, wsID, resolveSource)
	if err != nil {
		countIngest("error")
		monitoring.RecordAuthRequest("discovery_ingest", "error", "-")
		log.Printf("discovery ingest auth: could not verify a token on %s: %v", route, err)
		if mode == services.IngestAuthEnforce {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not verify ingest token"})
			return false, nil
		}
		// warn: the call would have been accepted without a token, so a
		// verification failure must not be what stops it.
		return true, nothing
	}

	switch d.Outcome {
	case services.IngestAccept:
		c.Set(ctxIngestTokenID, d.Token.ID.String())
		c.Set(ctxIngestTokenPrefix, d.Token.TokenPrefix)
		return true, func() {
			countIngest("accepted_token")
			monitoring.RecordAuthRequest("discovery_ingest", "accepted_token", wsID.String())
		}

	case services.IngestRejectForeignWorkspace:
		// The token is real, so its workspace is: label by it, not the body's.
		countIngest("rejected_other_workspace")
		monitoring.RecordAuthRequest("discovery_ingest", "rejected_other_workspace", d.Token.WorkspaceID.String())
		log.Printf("discovery ingest auth: 403 %s from %s: token %s (%s) belongs to workspace %s, the body names %s",
			route, c.ClientIP(), d.Token.TokenPrefix, d.Token.ID, d.Token.WorkspaceID, wsID)
		c.JSON(http.StatusForbidden, gin.H{"error": "ingest token is not valid for this workspace"})
		return false, nil

	case services.IngestRejectUnauthenticated:
		// Nothing about the caller is verified, so nothing it chose (the
		// workspace) becomes a label or a throttle key.
		key := "rejected_unauthenticated_" + d.Reason
		countIngest(key)
		monitoring.RecordAuthRequest("discovery_ingest", key, "-")
		logIngestThrottled("enforce|"+route+"|"+d.Reason,
			fmt.Sprintf("discovery ingest auth: 401 %s for workspace %s from %s: token %s (presented %q)",
				route, wsID, c.ClientIP(), d.Reason, presentedPrefix(presented)))
		c.Header("WWW-Authenticate", `Bearer realm="authsec-discovery"`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "ingest token required"})
		return false, nil

	default: // services.IngestAcceptUnauthenticated
		key := "accepted_unauthenticated_" + d.Reason
		ip, prefix := c.ClientIP(), presentedPrefix(presented)
		return true, func() {
			countIngest(key)
			monitoring.RecordAuthRequest("discovery_ingest", key, wsID.String())
			logIngestThrottled("warn|"+wsID.String()+"|"+route+"|"+d.Reason,
				fmt.Sprintf("discovery ingest auth (warn): accepted %s for workspace %s from %s without a valid ingest token: %s (presented %q); %s=enforce will refuse it",
					route, wsID, ip, d.Reason, prefix, services.DiscoveryIngestAuthEnv))
		}
	}
}

// ingestPrincipal is how an ingress call is attributed: to the token that
// authenticated it, or explicitly as unauthenticated.
func ingestPrincipal(c *gin.Context, source string) string {
	if id := c.GetString(ctxIngestTokenID); id != "" {
		return "ingest-token:" + id + ":" + source
	}
	return "unauthenticated:" + source
}
