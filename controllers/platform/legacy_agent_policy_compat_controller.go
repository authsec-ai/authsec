package platform

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// The LEGACY agent-policy compatibility routes (SPEC-iga-phase3-policy.md
// §7.10, PLAN-existing-policy-code-disposition.md §3.1, task T3.19):
//
//	GET    /api/iga/v1/legacy/agent-policies?cursor&limit
//	POST   /api/iga/v1/legacy/agent-policies/:id/pause      {reason?}
//	DELETE /api/iga/v1/legacy/agent-policies/:id            {reason}
//
// This is legacy code under the IGA prefix, and named so. Every read and write
// goes through the legacy service (services/agent_policy_legacy_compat.go) and
// the legacy manager; this file names no table. No Phase 3 code reads or
// writes agent_policies.
//
// Contract (spec §7 intro):
//   - Workspace: only the token's. An id from another workspace is 404, never
//     403, so ids do not leak existence.
//   - Envelope: {"data": ..., "meta": {...}}; errors
//     {"error": {"code", "message", "detail"?}} -- including the 401 and 403
//     of the auth and permission middlewares, rewritten by GraphEnvelope.
//   - Paging: signed cursor (IGA_CURSOR_SECRET), limit 1-200, as the
//     inventory API.
//   - Audit: both mutations write audit_events through auditAdminMutation,
//     with the reason.
//   - Existence: the routes exist while IGA_LEGACY_AGENT_POLICY is on OR the
//     workspace has legacy policies; otherwise 404 legacy_agent_policies_unavailable.
//
// Permissions. The spec names governance:read and governance:enforce;
// governance:enforce does not exist yet (a later Phase 3 migration creates
// it). These routes use what the legacy /authsec/governance/agent-policies
// routes use for the same acts: governance:read to list (as GET
// /agent-policies) and governance:admin to pause or remove (as DELETE
// /agent-policies/:id). No new permission.

// legacyCompatRoute is the route bound into this list's cursors.
const legacyCompatRoute = "legacy/agent-policies"

// legacyCompatSort is the list's one order, bound into its cursors.
const legacyCompatSort = "-created_at"

// Paging bounds: as the inventory API.
const (
	legacyCompatDefaultLimit = 50
	legacyCompatMaxLimit     = igaread.MaxLimit
)

// LegacyAgentPolicyCompatController serves the compatibility routes.
type LegacyAgentPolicyCompatController struct {
	db   func() *gorm.DB
	gate func() services.LegacyAgentPolicyGate
	key  []byte

	signerOnce sync.Once
	signer     *igaread.Reader
}

// NewLegacyAgentPolicyCompatController is the production controller: the
// process gate main installed, and the shared cursor secret.
func NewLegacyAgentPolicyCompatController(db *gorm.DB) *LegacyAgentPolicyCompatController {
	return NewLegacyAgentPolicyCompatControllerWith(db, services.LegacyAgentPolicy, cursorKeyFromEnv())
}

// NewLegacyAgentPolicyCompatControllerWith builds a controller over an explicit
// database, gate and cursor key. Tests use it.
func NewLegacyAgentPolicyCompatControllerWith(db *gorm.DB, gate func() services.LegacyAgentPolicyGate,
	cursorKey []byte) *LegacyAgentPolicyCompatController {
	return &LegacyAgentPolicyCompatController{
		db:   func() *gorm.DB { return db },
		gate: gate,
		key:  cursorKey,
	}
}

// MountLegacyAgentPolicyCompatRoutes mounts the three routes on their own
// /api/iga/v1/legacy group of r, behind auth, each with its permission
// middleware built by require -- both wrapped by GraphEnvelope so a 401 or 403
// is the §7 envelope. Production calls it from routes.SetupRoutes with
// middlewares.AuthMiddleware() and middlewares.Require.
func MountLegacyAgentPolicyCompatRoutes(r gin.IRouter, ctl *LegacyAgentPolicyCompatController,
	auth gin.HandlerFunc, require func(resource, action string) gin.HandlerFunc) {
	g := r.Group("/api/iga/v1/legacy")
	g.Use(GraphEnvelope(auth))
	req := GraphRequire(require)
	g.GET("/agent-policies", req("governance", "read"), ctl.ListLegacyAgentPolicies)
	g.POST("/agent-policies/:id/pause", req("governance", "admin"), ctl.PauseLegacyAgentPolicy)
	g.DELETE("/agent-policies/:id", req("governance", "admin"), ctl.RemoveLegacyAgentPolicy)
}

func (ctl *LegacyAgentPolicyCompatController) service() *services.LegacyAgentPolicyCompat {
	return services.NewLegacyAgentPolicyCompat(ctl.db())
}

func (ctl *LegacyAgentPolicyCompatController) cursors() *igaread.Reader {
	ctl.signerOnce.Do(func() { ctl.signer = igaread.NewReader(ctl.db(), ctl.key) })
	return ctl.signer
}

// legacyCompatError writes the §7 error envelope and aborts.
func legacyCompatError(c *gin.Context, status int, code, message string, detail gin.H) {
	inner := gin.H{"code": code, "message": message}
	if detail != nil {
		inner["detail"] = detail
	}
	c.AbortWithStatusJSON(status, gin.H{"error": inner})
}

// admit resolves the token's workspace and applies the existence rule: with
// the legacy stack off, the routes exist only for a workspace that still has
// legacy policies to see or clean up.
func (ctl *LegacyAgentPolicyCompatController) admit(c *gin.Context) (uuid.UUID, bool) {
	ws, ok := tokenWorkspace(c)
	if !ok {
		legacyCompatError(c, http.StatusUnauthorized, "unauthenticated",
			"No workspace in the token.", nil)
		return uuid.Nil, false
	}
	if ctl.gate().On {
		return ws, true
	}
	has, err := ctl.service().HasPolicies(ws)
	if err != nil {
		log.Printf("[legacy-agent-policy] %s %s: %v", c.Request.Method, c.FullPath(), err)
		legacyCompatError(c, http.StatusInternalServerError, "internal",
			"Could not read the legacy agent policies.", nil)
		return uuid.Nil, false
	}
	if !has {
		legacyCompatError(c, http.StatusNotFound, "legacy_agent_policies_unavailable",
			"The legacy agent-policy stack is off ("+services.LegacyAgentPolicyEnv+
				"=off) and this workspace has no legacy agent policies.", nil)
		return uuid.Nil, false
	}
	return ws, true
}

// policyID parses :id. A malformed id is 400; an id that is not this
// workspace's is the service's 404.
func policyID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil || id == uuid.Nil {
		legacyCompatError(c, http.StatusBadRequest, "invalid_parameter",
			"id must be a policy uuid.", gin.H{"parameter": "id"})
		return uuid.Nil, false
	}
	return id, true
}

// legacyCompatServiceError maps a service error: not this workspace's (or not
// at all) is 404; anything else is 500 and logged.
func legacyCompatServiceError(c *gin.Context, err error) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		legacyCompatError(c, http.StatusNotFound, "not_found", "Not found.", nil)
		return
	}
	log.Printf("[legacy-agent-policy] %s %s: %v", c.Request.Method, c.FullPath(), err)
	legacyCompatError(c, http.StatusInternalServerError, "internal",
		"Could not complete the legacy agent-policy operation.", nil)
}

// legacyCompatCursorKey is the sort key a cursor carries: the last row's
// created_at.
type legacyCompatCursorKey struct {
	CreatedAt time.Time `json:"t"`
}

// ListLegacyAgentPolicies handles GET /api/iga/v1/legacy/agent-policies.
func (ctl *LegacyAgentPolicyCompatController) ListLegacyAgentPolicies(c *gin.Context) {
	ws, ok := ctl.admit(c)
	if !ok {
		return
	}

	vals := c.Request.URL.Query()
	for k := range vals {
		if k != "cursor" && k != "limit" {
			legacyCompatError(c, http.StatusBadRequest, "invalid_parameter",
				"unknown parameter "+strconv.Quote(k)+"; this route takes cursor and limit",
				gin.H{"parameter": k})
			return
		}
	}
	limit := legacyCompatDefaultLimit
	if l := vals.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > legacyCompatMaxLimit {
			legacyCompatError(c, http.StatusBadRequest, "invalid_parameter",
				"limit must be 1-"+strconv.Itoa(legacyCompatMaxLimit), gin.H{"parameter": "limit"})
			return
		}
		limit = n
	}

	want := igaread.CursorContext{WS: ws, Route: legacyCompatRoute,
		Filter: igaread.FilterHash(vals), Sort: legacyCompatSort}
	var after *services.LegacyAgentPolicyPosition
	if token := vals.Get("cursor"); token != "" {
		cur, cerr := ctl.cursors().OpenCursor(token, want)
		if cerr != nil {
			legacyCompatError(c, cerr.Status, cerr.Code, cerr.Message, nil)
			return
		}
		var key legacyCompatCursorKey
		if err := json.Unmarshal(cur.Key, &key); err != nil || key.CreatedAt.IsZero() {
			legacyCompatError(c, http.StatusBadRequest, "cursor_invalid", "Malformed cursor.", nil)
			return
		}
		after = &services.LegacyAgentPolicyPosition{CreatedAt: key.CreatedAt, ID: cur.ID}
	}

	rows, more, err := ctl.service().Page(ws, after, limit)
	if err != nil {
		legacyCompatServiceError(c, err)
		return
	}
	var next *string
	if more && len(rows) > 0 {
		last := rows[len(rows)-1]
		raw, _ := json.Marshal(legacyCompatCursorKey{CreatedAt: last.CreatedAt})
		tok := ctl.cursors().SignCursor(igaread.Cursor{WS: ws, Route: legacyCompatRoute,
			Filter: want.Filter, Sort: legacyCompatSort, Key: raw, ID: last.ID})
		next = &tok
	}
	c.JSON(http.StatusOK, gin.H{
		"data": rows,
		"meta": gin.H{
			"next_cursor": next,
			"limit":       limit,
			// Whether this process runs the legacy reconciler and warning workers,
			// so the console can say whether these policies are still acting.
			"legacy_workers": ctl.gate().State(),
		},
	})
}

// legacyCompatReason is the optional (pause) or required (remove) body.
type legacyCompatReason struct {
	Reason string `json:"reason"`
}

// bindReason reads {reason}. An absent body is an empty reason; a body that is
// not that JSON is 400.
func bindReason(c *gin.Context) (string, bool) {
	var body legacyCompatReason
	if c.Request.Body != nil && c.Request.ContentLength != 0 {
		err := json.NewDecoder(c.Request.Body).Decode(&body)
		if err != nil && !errors.Is(err, io.EOF) {
			legacyCompatError(c, http.StatusBadRequest, "invalid_body",
				"The body must be JSON: {\"reason\": \"...\"}.", nil)
			return "", false
		}
	}
	return strings.TrimSpace(body.Reason), true
}

// PauseLegacyAgentPolicy handles POST /api/iga/v1/legacy/agent-policies/:id/pause:
// the legacy manager sets the policy disabled, so the legacy reconciler and
// warning scheduler stop acting on it from their next pass. Optional
// {reason}, recorded in the audit event.
func (ctl *LegacyAgentPolicyCompatController) PauseLegacyAgentPolicy(c *gin.Context) {
	ws, ok := ctl.admit(c)
	if !ok {
		return
	}
	id, ok := policyID(c)
	if !ok {
		return
	}
	reason, ok := bindReason(c)
	if !ok {
		return
	}

	before, after, err := ctl.service().Pause(ws, id)
	if err != nil {
		legacyCompatServiceError(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "pause", "agent_policy", id.String(), http.StatusOK,
		gin.H{"enabled": before.Enabled},
		gin.H{"enabled": after.Enabled, "reason": reason, "via": "legacy_compat"})
	c.JSON(http.StatusOK, gin.H{"data": after, "meta": gin.H{}})
}

// RemoveLegacyAgentPolicy handles DELETE /api/iga/v1/legacy/agent-policies/:id
// with {reason}: the legacy delete, as DELETE /authsec/governance/agent-policies/:id.
// Effects the policy already had are not undone, and its recorded actions are
// kept (their policy_id is cleared by the schema's ON DELETE SET NULL).
func (ctl *LegacyAgentPolicyCompatController) RemoveLegacyAgentPolicy(c *gin.Context) {
	ws, ok := ctl.admit(c)
	if !ok {
		return
	}
	id, ok := policyID(c)
	if !ok {
		return
	}
	reason, ok := bindReason(c)
	if !ok {
		return
	}
	if reason == "" {
		legacyCompatError(c, http.StatusBadRequest, "reason_required",
			"Removing a legacy agent policy needs a reason: {\"reason\": \"...\"}.",
			gin.H{"parameter": "reason"})
		return
	}

	before, err := ctl.service().Remove(ws, id)
	if err != nil {
		legacyCompatServiceError(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "delete", "agent_policy", id.String(), http.StatusOK,
		before, gin.H{"removed": true, "reason": reason, "via": "legacy_compat"})
	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"id":      id,
			"removed": true,
			"note": "already-applied effects are NOT undone; the actions this policy took " +
				"remain in agent_policy_actions",
		},
		"meta": gin.H{},
	})
}
