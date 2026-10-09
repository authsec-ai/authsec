// The legacy agent-policy compatibility routes (SPEC-iga-phase3-policy.md
// §7.10, T3.19; disposition plan §3.1; scenarios A8 and A56):
//
//	GET    /api/iga/v1/legacy/agent-policies?cursor&limit
//	POST   /api/iga/v1/legacy/agent-policies/:id/pause
//	DELETE /api/iga/v1/legacy/agent-policies/:id   {reason}
//
// Proven against real Postgres through the mount production uses
// (MountLegacyAgentPolicyCompatRoutes), with stand-ins only for the token
// (which workspace) and the permission check (recorded, and deniable):
// paging and fields; another workspace's id is 404 and changes nothing; both
// mutations are audited with the reason and their effect is visible through
// the legacy /authsec/governance/agent-policies routes; the existence rule
// under IGA_LEGACY_AGENT_POLICY; and those legacy routes answer exactly as
// before.
package ownership

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/routes"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

var compatCursorKey = []byte("legacy-compat-test-cursor-key")

const compatBase = "/api/iga/v1/legacy/agent-policies"

// compatLab is a workspace A with five legacy policies and a workspace B with
// two, behind one engine mounting the compatibility routes and the legacy
// governance routes they must not disturb.
type compatLab struct {
	provFixture
	r       *gin.Engine
	gate    *services.LegacyAgentPolicyGate
	perms   *[]string
	wsB     uuid.UUID
	pDirect uuid.UUID // direct, quarantined, two recorded actions
	pSel    uuid.UUID // selector, active
	pEvict  uuid.UUID // direct, evict on expiry in 72h: a pending destructive deadline
	pOff    uuid.UUID // selector, disabled
	pOffEv  uuid.UUID // selector, evict on expiry, disabled: no pending deadline
	bPols   []uuid.UUID
	agent1  uuid.UUID
	agent2  uuid.UUID
}

func newCompatLab(t *testing.T) *compatLab {
	t.Helper()
	f := newProvFixture(t)
	l := &compatLab{provFixture: f, wsB: uuid.MustParse(wsB)}
	gate := services.ParseLegacyAgentPolicyGate("on")
	l.gate = &gate
	pm := policyMgr(t, f)

	l.agent1 = claimedAgent(t, f, "compat-a1", "iga-demo", "crewai", "automated")
	l.agent2 = claimedAgent(t, f, "compat-a2", "iga-demo", "crewai", "automated")
	in72h := time.Now().Add(72 * time.Hour)
	in24h := time.Now().Add(24 * time.Hour)

	mk := func(ws uuid.UUID, in services.AgentPolicyInput) uuid.UUID {
		t.Helper()
		p, err := pm.Create(ws, claimOwner.String(), in)
		if err != nil {
			t.Fatalf("create %q: %v", in.Name, err)
		}
		return p.ID
	}
	l.pDirect = mk(f.ws, services.AgentPolicyInput{Name: "contain a1", DiscoveredAgentID: &l.agent1,
		DesiredState: models.AgentPolicyStateQuarantined})
	l.pSel = mk(f.ws, services.AgentPolicyInput{Name: "demo namespace",
		Selector: &models.AgentPolicySelector{Namespace: "iga-demo"}})
	l.pEvict = mk(f.ws, services.AgentPolicyInput{Name: "decommission a2", DiscoveredAgentID: &l.agent2,
		ExpiresAt: &in72h, OnExpiry: models.OnExpiryEvict, Reason: "project closed",
		ConfirmedBy: &claimOwner, ConfirmAgentIDs: []uuid.UUID{l.agent2}})
	l.pOff = mk(f.ws, services.AgentPolicyInput{Name: "old namespace",
		Selector: &models.AgentPolicySelector{Namespace: "old"}})
	l.pOffEv = mk(f.ws, services.AgentPolicyInput{Name: "old evict",
		Selector: &models.AgentPolicySelector{Cluster: "k3s-master"}, ExpiresAt: &in24h,
		OnExpiry: models.OnExpiryEvict, Reason: "sunset", ConfirmedBy: &claimOwner,
		ConfirmAgentIDs: []uuid.UUID{l.agent1}})
	exec(t, f.raw, `UPDATE agent_policies SET enabled = false WHERE id IN ($1, $2)`, l.pOff, l.pOffEv)

	// A known order, with a created_at tie (pSel, pEvict) the id must break.
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	for i, id := range []uuid.UUID{l.pDirect, l.pSel, l.pEvict, l.pOff, l.pOffEv} {
		at := base.Add(time.Duration(i) * time.Minute)
		if id == l.pEvict {
			at = base.Add(time.Minute) // same as pSel
		}
		exec(t, f.raw, `UPDATE agent_policies SET created_at = $2 WHERE id = $1`, id, at)
	}

	// What the reconciler recorded: two rows for pDirect (the newer wins), one
	// for pEvict, none for the others.
	exec(t, f.raw, `INSERT INTO agent_policy_actions
	    (workspace_id, policy_id, discovered_agent_id, action, arm, dry_run, outcome, detail, acted_at)
	  VALUES ($1,$2,$3,'quarantined','cluster',true,'planned','policy asks for quarantined', now() - interval '2 hours'),
	         ($1,$2,$3,'quarantined','cluster',false,'applied','', now() - interval '1 hour'),
	         ($1,$4,$5,'noop','cluster',true,'planned','REFUSED: no eviction capability', now() - interval '30 minutes')`,
		f.ws, l.pDirect, l.agent1, l.pEvict, l.agent2)

	for _, n := range []string{"b-one", "b-two"} {
		l.bPols = append(l.bPols, mk(l.wsB, services.AgentPolicyInput{Name: n,
			Selector: &models.AgentPolicySelector{Namespace: n}}))
	}

	l.r, l.perms = compatRouter(t, f.raw, func() services.LegacyAgentPolicyGate { return *l.gate })
	return l
}

// compatRouter mounts the compatibility routes through the production mount
// and the legacy agent-policy routes as routes.go registers them. The token
// stand-in takes the workspace from X-Test-WS (none: 401 in the shared
// middleware's own body); the permission stand-in records each check and
// denies the one named in X-Test-Deny (403 in the shared middleware's body).
func compatRouter(t *testing.T, raw *sql.DB, gate func() services.LegacyAgentPolicyGate) (*gin.Engine, *[]string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db := gormFor(t, raw)
	perms := &[]string{}
	auth := func(c *gin.Context) {
		ws := c.GetHeader("X-Test-WS")
		if ws == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Set("workspace_id", ws)
		c.Set("user_id", claimOwner.String())
		c.Set("email", "u@a.com")
		c.Next()
	}
	require := func(resource, action string) gin.HandlerFunc {
		return func(c *gin.Context) {
			p := resource + ":" + action
			*perms = append(*perms, c.Request.Method+" "+c.FullPath()+" "+p)
			if c.GetHeader("X-Test-Deny") == p {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "insufficient_scope", "required_permissions": []string{p}})
				return
			}
			c.Next()
		}
	}
	r := gin.New()
	platform.MountLegacyAgentPolicyCompatRoutes(r,
		platform.NewLegacyAgentPolicyCompatControllerWith(db, gate, compatCursorKey), auth, require)

	gov := platform.NewGovernanceController(db)
	g := r.Group("/authsec/governance")
	g.Use(auth)
	g.GET("/agent-policies", require("governance", "read"), gov.ListAgentPolicies)
	g.GET("/agent-policies/:id", require("governance", "read"), gov.GetAgentPolicy)
	g.DELETE("/agent-policies/:id", require("governance", "admin"), gov.DeleteAgentPolicy)
	g.GET("/policies/upcoming", require("governance", "read"), gov.ListUpcomingPolicyActions)
	return r, perms
}

func (l *compatLab) do(t *testing.T, method, path string, ws uuid.UUID, body any, hdr ...string) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	if ws != uuid.Nil {
		req.Header.Set("X-Test-WS", ws.String())
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	l.r.ServeHTTP(rec, req)
	return rec
}

type compatList struct {
	Data []services.LegacyAgentPolicyView `json:"data"`
	Meta struct {
		NextCursor    *string `json:"next_cursor"`
		Limit         int     `json:"limit"`
		LegacyWorkers string  `json:"legacy_workers"`
	} `json:"meta"`
}

type compatErr struct {
	Error struct {
		Code    string         `json:"code"`
		Message string         `json:"message"`
		Detail  map[string]any `json:"detail"`
	} `json:"error"`
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %T: %v\n%s", v, err, rec.Body.String())
	}
	return v
}

func wantErr(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("want %d %s, got %d: %s", status, code, rec.Code, rec.Body.String())
	}
	e := decode[compatErr](t, rec)
	if e.Error.Code != code || e.Error.Message == "" {
		t.Fatalf("want error code %q with a message, got %s", code, rec.Body.String())
	}
}

// tableState is agent_policies, confirmations and actions for every workspace,
// as text -- what A8 compares before and after.
func tableState(t *testing.T, raw *sql.DB) string {
	t.Helper()
	var out []string
	for _, q := range []string{
		`SELECT coalesce(json_agg(p ORDER BY p.id)::text,'[]') FROM agent_policies p`,
		`SELECT coalesce(json_agg(c ORDER BY c.id)::text,'[]') FROM agent_policy_confirmations c`,
		`SELECT coalesce(json_agg(a ORDER BY a.id)::text,'[]') FROM agent_policy_actions a`,
	} {
		var s string
		if err := raw.QueryRow(q).Scan(&s); err != nil {
			t.Fatalf("snapshot: %v", err)
		}
		out = append(out, s)
	}
	return strings.Join(out, "\n")
}

/* --------------------------------- the list -------------------------------- */

func TestLegacyCompatListPagesTheWorkspacesPoliciesWithTheirState(t *testing.T) {
	l := newCompatLab(t)
	before := tableState(t, l.raw)

	// Page through: every policy of A once, newest first, the created_at tie
	// broken by id, and none of B's. limit=1 and 3 put a page boundary INSIDE
	// the tie (pSel/pEvict share created_at), which is where a keyset without
	// the id loses or repeats a row.
	tie := []uuid.UUID{l.pSel, l.pEvict}
	if strings.Compare(tie[0].String(), tie[1].String()) < 0 {
		tie[0], tie[1] = tie[1], tie[0]
	}
	want := []uuid.UUID{l.pOffEv, l.pOff, tie[0], tie[1], l.pDirect}
	var got []services.LegacyAgentPolicyView
	for _, limit := range []string{"1", "2", "3"} {
		got = nil
		path := compatBase + "?limit=" + limit
		for pages := 0; ; pages++ {
			if pages > 6 {
				t.Fatalf("limit=%s: paging did not terminate", limit)
			}
			rec := l.do(t, http.MethodGet, path, l.ws, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
			}
			page := decode[compatList](t, rec)
			if strconv.Itoa(page.Meta.Limit) != limit || page.Meta.LegacyWorkers != "on" ||
				len(page.Data) > page.Meta.Limit {
				t.Fatalf("meta/page size wrong: %+v (%d rows)", page.Meta, len(page.Data))
			}
			got = append(got, page.Data...)
			if page.Meta.NextCursor == nil {
				break
			}
			path = compatBase + "?limit=" + limit + "&cursor=" + *page.Meta.NextCursor
		}
		// Expected order: created_at DESC, id DESC.
		if len(got) != len(want) {
			t.Fatalf("limit=%s: want %d policies across the pages, got %d", limit, len(want), len(got))
		}
		for i := range want {
			if got[i].ID != want[i] {
				t.Errorf("limit=%s row %d: got %s (%s), want %s", limit, i, got[i].ID, got[i].Name, want[i])
			}
		}
	}

	by := map[uuid.UUID]services.LegacyAgentPolicyView{}
	for _, v := range got {
		by[v.ID] = v
	}
	d := by[l.pDirect]
	if d.Target.Kind != "agent" || d.Target.DiscoveredAgentID == nil || *d.Target.DiscoveredAgentID != l.agent1 ||
		d.Target.AgentLabel != "compat-a1" || !d.Enabled || d.DesiredState != "quarantined" {
		t.Errorf("direct policy fields wrong: %+v", d)
	}
	if d.LastReconcile == nil || d.LastReconcile.Outcome != "applied" || d.LastReconcile.DryRun ||
		d.LastReconcile.Action != "quarantined" || d.LastReconcile.At.IsZero() {
		t.Errorf("last reconcile must be the NEWEST recorded action, got %+v", d.LastReconcile)
	}
	if d.PendingDestructiveDeadline != nil {
		t.Error("a non-destructive policy has no destructive deadline")
	}
	s := by[l.pSel]
	if s.Target.Kind != "selector" || !strings.Contains(string(s.Target.Selector), "iga-demo") ||
		s.Target.DiscoveredAgentID != nil || s.LastReconcile != nil {
		t.Errorf("selector policy fields wrong: %+v", s)
	}
	e := by[l.pEvict]
	if e.PendingDestructiveDeadline == nil || e.OnExpiry != "evict" ||
		time.Until(*e.PendingDestructiveDeadline) < 71*time.Hour {
		t.Errorf("an enabled evict policy must show its pending destructive deadline: %+v", e)
	}
	if e.LastReconcile == nil || e.LastReconcile.Outcome != "planned" ||
		!strings.Contains(e.LastReconcile.Detail, "REFUSED") {
		t.Errorf("the refusal the reconciler recorded must show: %+v", e.LastReconcile)
	}
	if o := by[l.pOffEv]; o.Enabled || o.PendingDestructiveDeadline != nil || o.EffectiveExpiry == nil {
		t.Errorf("a disabled evict policy has its clock but no PENDING deadline: %+v", o)
	}
	if o := by[l.pOff]; o.Enabled {
		t.Errorf("disabled policy listed as enabled: %+v", o)
	}

	// B sees only B's.
	rec := l.do(t, http.MethodGet, compatBase, l.wsB, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list B: %d %s", rec.Code, rec.Body.String())
	}
	if b := decode[compatList](t, rec); len(b.Data) != 2 || b.Meta.NextCursor != nil || b.Meta.Limit != 50 {
		t.Errorf("workspace B must see exactly its own two policies, default limit 50: %+v", b)
	}

	// The read changed nothing (A8: legacy rows as without it).
	if after := tableState(t, l.raw); after != before {
		t.Error("the compatibility list must be read-only")
	}
}

func TestLegacyCompatListRejectsBadParametersAndForeignCursors(t *testing.T) {
	l := newCompatLab(t)
	for _, q := range []string{"limit=0", "limit=201", "limit=abc", "limit=-1"} {
		rec := l.do(t, http.MethodGet, compatBase+"?"+q, l.ws, nil)
		wantErr(t, rec, http.StatusBadRequest, "invalid_parameter")
	}
	if rec := l.do(t, http.MethodGet, compatBase+"?limit=200", l.ws, nil); rec.Code != http.StatusOK {
		t.Errorf("limit=200 is the maximum and must be accepted, got %d", rec.Code)
	}
	wantErr(t, l.do(t, http.MethodGet, compatBase+"?workspace_id="+wsB, l.ws, nil),
		http.StatusBadRequest, "invalid_parameter")

	page := decode[compatList](t, l.do(t, http.MethodGet, compatBase+"?limit=1", l.ws, nil))
	if page.Meta.NextCursor == nil {
		t.Fatal("want a next cursor")
	}
	cur := *page.Meta.NextCursor
	// Another workspace cannot use it, and it cannot be edited.
	wantErr(t, l.do(t, http.MethodGet, compatBase+"?limit=1&cursor="+cur, l.wsB, nil),
		http.StatusBadRequest, "cursor_invalid")
	tampered := cur[:len(cur)-2] + "AA"
	if tampered == cur {
		tampered = cur[:len(cur)-2] + "BB"
	}
	wantErr(t, l.do(t, http.MethodGet, compatBase+"?limit=1&cursor="+tampered, l.ws, nil),
		http.StatusBadRequest, "cursor_invalid")
}

/* ---------------------------- permissions, envelope ------------------------ */

func TestLegacyCompatUsesTheLegacyGovernancePermissionsAndTheEnvelope(t *testing.T) {
	l := newCompatLab(t)
	*l.perms = nil
	l.do(t, http.MethodGet, compatBase, l.ws, nil)
	l.do(t, http.MethodPost, compatBase+"/"+l.pSel.String()+"/pause", l.ws, nil)
	l.do(t, http.MethodDelete, compatBase+"/"+l.pOff.String(), l.ws, map[string]string{"reason": "cleanup"})
	want := []string{
		"GET " + compatBase + " governance:read",
		"POST " + compatBase + "/:id/pause governance:enforce",
		"DELETE " + compatBase + "/:id governance:enforce",
	}
	if strings.Join(*l.perms, "\n") != strings.Join(want, "\n") {
		t.Errorf("permission checks:\n got %v\nwant %v", *l.perms, want)
	}

	// 401 and 403 from the shared middlewares come back in the §7 envelope.
	wantErr(t, l.do(t, http.MethodGet, compatBase, uuid.Nil, nil), http.StatusUnauthorized, "unauthenticated")
	before := tableState(t, l.raw)
	// §7.10 (review fix R1a P2): pause and remove need governance:enforce,
	// which 055 seeds; governance:admin alone no longer suffices.
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, compatBase + "/" + l.pDirect.String() + "/pause"},
		{http.MethodDelete, compatBase + "/" + l.pDirect.String()},
	} {
		rec := l.do(t, c.method, c.path, l.ws, map[string]string{"reason": "x"}, "X-Test-Deny", "governance:enforce")
		wantErr(t, rec, http.StatusForbidden, "forbidden")
	}
	if after := tableState(t, l.raw); after != before {
		t.Error("a denied pause or remove must change nothing")
	}
}

/* --------------------------- workspace isolation --------------------------- */

func TestLegacyCompatAnotherWorkspacesPolicyIs404(t *testing.T) {
	l := newCompatLab(t)
	withAuditLogger(t, l.raw)
	before := tableState(t, l.raw)
	audits := countAudit(t, l.raw)

	// B acting on A's policy: 404, never 403, and nothing changes.
	wantErr(t, l.do(t, http.MethodPost, compatBase+"/"+l.pDirect.String()+"/pause", l.wsB,
		map[string]string{"reason": "x"}), http.StatusNotFound, "not_found")
	wantErr(t, l.do(t, http.MethodDelete, compatBase+"/"+l.pDirect.String(), l.wsB,
		map[string]string{"reason": "x"}), http.StatusNotFound, "not_found")
	// An id that exists nowhere answers the same.
	wantErr(t, l.do(t, http.MethodPost, compatBase+"/"+uuid.NewString()+"/pause", l.ws, nil),
		http.StatusNotFound, "not_found")
	wantErr(t, l.do(t, http.MethodPost, compatBase+"/not-a-uuid/pause", l.ws, nil),
		http.StatusBadRequest, "invalid_parameter")

	if after := tableState(t, l.raw); after != before {
		t.Error("a refused cross-workspace call must change nothing")
	}
	if n := countAudit(t, l.raw); n != audits {
		t.Errorf("a refused call must not be audited (%d -> %d)", audits, n)
	}
}

/* ------------------------------ pause and remove --------------------------- */

func TestLegacyCompatPauseIsAuditedAndVisibleThroughTheLegacyRoute(t *testing.T) {
	l := newCompatLab(t)
	withAuditLogger(t, l.raw)
	legacy := "/authsec/governance/agent-policies/" + l.pDirect.String()

	pre := l.do(t, http.MethodGet, legacy, l.ws, nil)
	if pre.Code != http.StatusOK || !strings.Contains(pre.Body.String(), `"enabled":true`) {
		t.Fatalf("legacy get before: %d %s", pre.Code, pre.Body.String())
	}

	rec := l.do(t, http.MethodPost, compatBase+"/"+l.pDirect.String()+"/pause", l.ws,
		map[string]string{"reason": "superseded by Phase 3 policy"})
	if rec.Code != http.StatusOK {
		t.Fatalf("pause: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Data services.LegacyAgentPolicyView `json:"data"`
		Meta map[string]any                 `json:"meta"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Data.ID != l.pDirect || out.Data.Enabled || out.Meta == nil {
		t.Fatalf("pause must answer the paused policy in the envelope: %v %s", err, rec.Body.String())
	}

	// Visible through the legacy route, and the legacy reconciler no longer
	// sees it (it reads enabled policies only).
	post := l.do(t, http.MethodGet, legacy, l.ws, nil)
	if post.Code != http.StatusOK || !strings.Contains(post.Body.String(), `"enabled":false`) {
		t.Fatalf("legacy get after pause: %d %s", post.Code, post.Body.String())
	}
	enabled, err := policyMgr(t, l.provFixture).List(l.ws, true)
	if err != nil {
		t.Fatalf("list enabled: %v", err)
	}
	for _, p := range enabled {
		if p.ID == l.pDirect {
			t.Error("a paused policy must drop out of what the reconciler acts on")
		}
	}

	rows := waitAudit(t, l.raw, "pause", "agent_policy", l.pDirect.String())
	if len(rows) != 1 {
		t.Fatalf("want one pause audit row, got %d", len(rows))
	}
	a := rows[0]
	if a.WorkspaceID != l.ws.String() || a.UserID != claimOwner.String() || a.StatusCode != http.StatusOK ||
		!strings.Contains(a.NewValues.String, "superseded by Phase 3 policy") ||
		!strings.Contains(a.NewValues.String, `"enabled": false`) ||
		!strings.Contains(a.OldValues.String, `"enabled": true`) {
		t.Errorf("pause audit row incomplete: %+v", a)
	}

	// Pausing again changes nothing (updated_at not bumped).
	var upd1, upd2 time.Time
	_ = l.raw.QueryRow(`SELECT updated_at FROM agent_policies WHERE id = $1`, l.pDirect).Scan(&upd1)
	if rec := l.do(t, http.MethodPost, compatBase+"/"+l.pDirect.String()+"/pause", l.ws, nil); rec.Code != http.StatusOK {
		t.Fatalf("second pause: %d", rec.Code)
	}
	_ = l.raw.QueryRow(`SELECT updated_at FROM agent_policies WHERE id = $1`, l.pDirect).Scan(&upd2)
	if !upd1.Equal(upd2) {
		t.Error("pausing a paused policy must not change it")
	}
}

func TestLegacyCompatRemoveIsAuditedAndVisibleThroughTheLegacyRoute(t *testing.T) {
	l := newCompatLab(t)
	withAuditLogger(t, l.raw)
	path := compatBase + "/" + l.pDirect.String()

	// A reason is required, and its absence changes nothing.
	before := tableState(t, l.raw)
	wantErr(t, l.do(t, http.MethodDelete, path, l.ws, nil), http.StatusBadRequest, "reason_required")
	wantErr(t, l.do(t, http.MethodDelete, path, l.ws, map[string]string{"reason": "  "}),
		http.StatusBadRequest, "reason_required")
	if after := tableState(t, l.raw); after != before {
		t.Fatal("a refused remove must change nothing")
	}

	rec := l.do(t, http.MethodDelete, path, l.ws, map[string]string{"reason": "retiring the legacy stack"})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"removed":true`) {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body.String())
	}

	// Gone through the legacy route; its recorded actions remain, unattributed.
	if rec := l.do(t, http.MethodGet, "/authsec/governance/agent-policies/"+l.pDirect.String(), l.ws, nil); rec.Code != http.StatusNotFound {
		t.Errorf("legacy get after remove: want 404, got %d %s", rec.Code, rec.Body.String())
	}
	var kept int
	if err := l.raw.QueryRow(`SELECT count(*) FROM agent_policy_actions
	                           WHERE workspace_id = $1 AND discovered_agent_id = $2 AND policy_id IS NULL`,
		l.ws, l.agent1).Scan(&kept); err != nil || kept != 2 {
		t.Errorf("the removed policy's recorded actions must be kept: %v (%d)", err, kept)
	}

	rows := waitAudit(t, l.raw, "delete", "agent_policy", l.pDirect.String())
	if len(rows) != 1 {
		t.Fatalf("want one delete audit row, got %d", len(rows))
	}
	a := rows[0]
	if a.WorkspaceID != l.ws.String() || a.Method != http.MethodDelete || a.Path != path ||
		!strings.Contains(a.NewValues.String, "retiring the legacy stack") ||
		!strings.Contains(a.NewValues.String, "legacy_compat") ||
		!strings.Contains(a.OldValues.String, "contain a1") {
		t.Errorf("delete audit row incomplete: %+v", a)
	}

	// Removing again is 404.
	wantErr(t, l.do(t, http.MethodDelete, path, l.ws, map[string]string{"reason": "again"}),
		http.StatusNotFound, "not_found")
}

/* ------------------------------ existence rule ----------------------------- */

func TestLegacyCompatRoutesExistWhileTheGateIsOnOrPoliciesRemain(t *testing.T) {
	l := newCompatLab(t)
	// A third workspace with no legacy policies.
	wsC := uuid.New()
	exec(t, l.raw, `INSERT INTO workspaces (id, name) VALUES ($1,'ws-C')`, wsC)

	// On: every workspace has the routes, even one with nothing in them.
	rec := l.do(t, http.MethodGet, compatBase, wsC, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("gate on, empty workspace: %d %s", rec.Code, rec.Body.String())
	}
	if c := decode[compatList](t, rec); len(c.Data) != 0 || c.Data == nil {
		t.Errorf("an empty workspace lists [] (not null): %s", rec.Body.String())
	}

	// Off: only a workspace that still has legacy policies.
	*l.gate = services.ParseLegacyAgentPolicyGate("off")
	for _, call := range []struct{ method, path string }{
		{http.MethodGet, compatBase},
		{http.MethodPost, compatBase + "/" + l.pDirect.String() + "/pause"},
		{http.MethodDelete, compatBase + "/" + l.pDirect.String()},
	} {
		wantErr(t, l.do(t, call.method, call.path, wsC, map[string]string{"reason": "r"}),
			http.StatusNotFound, "legacy_agent_policies_unavailable")
	}
	rec = l.do(t, http.MethodGet, compatBase, l.ws, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("gate off, workspace with policies: %d %s", rec.Code, rec.Body.String())
	}
	if c := decode[compatList](t, rec); len(c.Data) != 5 || c.Meta.LegacyWorkers != "off" {
		t.Errorf("gate off must still list the workspace's policies and say the workers are off: %+v", c.Meta)
	}
	// ...including a workspace whose policies are all paused: they still exist.
	exec(t, l.raw, `UPDATE agent_policies SET enabled = false WHERE workspace_id = $1`, l.wsB)
	if rec := l.do(t, http.MethodGet, compatBase, l.wsB, nil); rec.Code != http.StatusOK {
		t.Errorf("paused policies still count: %d", rec.Code)
	}
	// Once the last one is removed, the routes are gone for that workspace.
	for _, id := range l.bPols {
		if rec := l.do(t, http.MethodDelete, compatBase+"/"+id.String(), l.wsB,
			map[string]string{"reason": "cleanup"}); rec.Code != http.StatusOK {
			t.Fatalf("remove %s: %d %s", id, rec.Code, rec.Body.String())
		}
	}
	wantErr(t, l.do(t, http.MethodGet, compatBase, l.wsB, nil),
		http.StatusNotFound, "legacy_agent_policies_unavailable")
}

/* ------------------------- A8: legacy routes unchanged --------------------- */

// The legacy /authsec/governance agent-policy routes answer byte-for-byte as
// before the compatibility routes were used -- the read leaves them untouched
// -- and a compat pause shows there only as that policy's enabled flag (and
// updated_at), everything else identical.
func TestLegacyGovernanceAgentPolicyRoutesAreUnchanged(t *testing.T) {
	l := newCompatLab(t)
	legacyGets := []string{
		"/authsec/governance/agent-policies",
		"/authsec/governance/agent-policies?enabled=true",
		"/authsec/governance/agent-policies/" + l.pEvict.String(),
		"/authsec/governance/agent-policies/" + l.pSel.String(),
		"/authsec/governance/policies/upcoming?days=7",
	}
	snap := func() []string {
		var out []string
		for _, p := range legacyGets {
			rec := l.do(t, http.MethodGet, p, l.ws, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: %d %s", p, rec.Code, rec.Body.String())
			}
			out = append(out, rec.Body.String())
		}
		return out
	}

	before := snap()
	for i := 0; i < 3; i++ {
		l.do(t, http.MethodGet, compatBase+"?limit=1", l.ws, nil)
		l.do(t, http.MethodGet, compatBase, l.wsB, nil)
	}
	after := snap()
	for i := range before {
		if before[i] != after[i] {
			t.Errorf("%s changed after compat reads:\nbefore %s\nafter  %s", legacyGets[i], before[i], after[i])
		}
	}

	// Pause pSel through compat: the legacy list differs only in pSel's
	// enabled and updated_at.
	if rec := l.do(t, http.MethodPost, compatBase+"/"+l.pSel.String()+"/pause", l.ws, nil); rec.Code != http.StatusOK {
		t.Fatalf("pause: %d", rec.Code)
	}
	normalise := func(body string) string {
		var v struct {
			Policies []map[string]any `json:"policies"`
			Total    int              `json:"total"`
		}
		if err := json.Unmarshal([]byte(body), &v); err != nil {
			t.Fatalf("legacy list body: %v", err)
		}
		for _, p := range v.Policies {
			if p["id"] == l.pSel.String() {
				delete(p, "enabled")
				delete(p, "updated_at")
			}
		}
		b, _ := json.Marshal(v)
		return string(b)
	}
	paused := l.do(t, http.MethodGet, legacyGets[0], l.ws, nil).Body.String()
	if normalise(paused) != normalise(before[0]) {
		t.Errorf("a compat pause changed more than enabled/updated_at in the legacy list:\nbefore %s\nafter  %s",
			before[0], paused)
	}
	if !strings.Contains(paused, `"enabled":false`) {
		t.Error("the pause must be visible in the legacy list")
	}

	// The legacy delete still answers as it always has.
	rec := l.do(t, http.MethodDelete, "/authsec/governance/agent-policies/"+l.pOff.String(), l.ws, nil)
	if rec.Code != http.StatusOK || rec.Body.String() != `{"deleted":true,"note":"already-applied effects are NOT undone; the actions this policy took remain in agent_policy_actions"}` {
		t.Errorf("legacy delete response changed: %d %s", rec.Code, rec.Body.String())
	}
}

/* ------------------------------ production wiring -------------------------- */

// The compat group mounts beside the whole /api/iga/v1 surface without a
// route conflict (gin panics on one), and SetupRoutes -- which cannot be built
// here -- mounts it exactly once, with the production auth and permission
// middlewares.
func TestLegacyCompatMountsBesideTheIGASurface(t *testing.T) {
	f := newProvFixture(t)
	db := gormFor(t, f.raw)
	gin.SetMode(gin.TestMode)
	// SetupIGARoutes builds the production AuthMiddleware, which reads these.
	t.Setenv("JWT_SDK_SECRET", "legacy-compat-mount-secret")
	t.Setenv("JWT_DEF_SECRET", "legacy-compat-mount-secret-default")
	t.Setenv("AUTH_EXPECT_ISS", "authsec-ai/auth-manager")
	eng := gin.New()
	routes.SetupIGARoutes(eng, platform.NewIGAController(db),
		platform.NewIGAGraphReadControllerWith(db, services.NewGraphProjectionGate(false, ""), compatCursorKey))
	platform.MountLegacyAgentPolicyCompatRoutes(eng,
		platform.NewLegacyAgentPolicyCompatControllerWith(db, services.LegacyAgentPolicy, compatCursorKey),
		func(c *gin.Context) { c.Next() }, func(string, string) gin.HandlerFunc { return func(c *gin.Context) { c.Next() } })

	found := 0
	for _, ri := range eng.Routes() {
		if strings.HasPrefix(ri.Path, compatBase) {
			found++
		}
	}
	if found != 3 {
		t.Errorf("want the 3 compat routes mounted, found %d", found)
	}

	dir := filepath.Join("..", "..", "routes")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read routes: %v", err)
	}
	var callers []string
	var args []string
	fset := gotoken.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "MountLegacyAgentPolicyCompatRoutes" {
					callers = append(callers, fn.Name.Name)
					for _, a := range call.Args[2:] {
						var b strings.Builder
						ast.Inspect(a, func(m ast.Node) bool {
							if s, ok := m.(*ast.SelectorExpr); ok {
								if x, ok := s.X.(*ast.Ident); ok {
									b.WriteString(x.Name + "." + s.Sel.Name)
								}
							}
							return true
						})
						args = append(args, b.String())
					}
				}
				return true
			})
		}
	}
	if strings.Join(callers, ",") != "SetupRoutes" {
		t.Errorf("MountLegacyAgentPolicyCompatRoutes is called from %v, want once from SetupRoutes", callers)
	}
	if strings.Join(args, ",") != "middlewares.AuthMiddleware,middlewares.Require" {
		t.Errorf("SetupRoutes must mount it with the production middlewares, got %v", args)
	}
}
