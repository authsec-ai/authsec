package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/services"
)

// AS-174: gateway revocation cannot fail open. A live containment makes its
// identity (and the identity's workloads) a stopped subject: the PDP refuses
// it (agent_stopped, never cached) and the policy hints hand the stop list
// to the gateway, versioned (ETag/304). A gateway's fail mode and cache cap
// are AuthSec's; tightening applies at once, loosening is a pending change
// a second governance:approve holder applies (never the requester), or
// break-glass when the workspace has no second approver. Another
// workspace's gateway, hints and changes are invisible (404).

func agwHints(t *testing.T, api *p3OwnersAPI, cred string, hdr map[string]string) (int, services.AgentGatewayPolicyHints, http.Header) {
	t.Helper()
	code, raw, h := agwPDP(t, api, "GET", "/v1/policy-hints", cred, nil, hdr)
	var out services.AgentGatewayPolicyHints
	if code == 200 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("hints: %v %s", err, raw)
		}
	}
	return code, out, h
}

// pcCall calls /api/iga/v1<path> as bearer.
func pcCall(t *testing.T, api *p3OwnersAPI, method, path, bearer string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader = http.NoBody
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, "/api/iga/v1"+path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	api.eng.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func agentEval(agent, identity string) map[string]any {
	props := map[string]any{}
	if identity != "" {
		props["identity_id"] = identity
	}
	return map[string]any{
		"subject":  map[string]any{"type": "agent", "id": agent, "properties": props},
		"action":   map[string]any{"name": "model/invoke"},
		"resource": map[string]any{"type": "model", "id": "openai/gpt-4o"},
	}
}

func hasStop(h services.AgentGatewayPolicyHints, field, value, refPrefix string) bool {
	for _, s := range h.Stopped {
		v := map[string]string{"identity_id": s.IdentityID, "workload_id": s.WorkloadID, "client_id": s.ClientID}[field]
		if strings.EqualFold(v, value) && strings.HasPrefix(s.Ref, refPrefix) {
			return true
		}
	}
	return false
}

func TestAgentGatewayStopListAndRuntimeApproval(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "agw-stop-a")
	b := p3NewGov(t, db, "agw-stop-b")
	p3Audit(t, db, a.ws, b.ws)
	api := agwNewAPI(t, db)
	all := "governance:read governance:enforce governance:approve"
	tokA := api.token(a.ws, a.author, a.authorMember, all)
	tokB := api.token(b.ws, b.author, b.authorMember, all)
	var m struct{ ID uuid.UUID }
	if err := db.Raw(`SELECT id FROM workspace_memberships WHERE workspace_id = ? AND user_id = ?`, a.ws, a.approver).Scan(&m).Error; err != nil || m.ID == uuid.Nil {
		t.Fatalf("approver membership: %v", err)
	}
	approverA := api.token(a.ws, a.approver, m.ID, all)

	newGW := func(tok, name string) (string, string) {
		code, out := agwAdmin(t, api, "POST", "/gateways", tok, map[string]any{"name": name})
		if code != http.StatusCreated {
			t.Fatalf("create gateway: %d %v", code, out)
		}
		d := agwData(t, out)
		return d["credential"].(string), d["gateway"].(map[string]any)["id"].(string)
	}
	credA, gwA := newGW(tokA, "edge-a")
	credB, gwB := newGW(tokB, "edge-b")

	// --- stop list from a live containment ---------------------------------
	identity, workload, contain := uuid.New(), uuid.New(), uuid.New()
	p3exec(t, db, `INSERT INTO cloud_identity (id, workspace_id, connector_id, kind, native_id, name) VALUES (?, ?, ?, 'iam_role', ?, 'stop-role')`,
		identity, a.ws, a.conn, "arn:aws:iam::111111111111:role/stop-"+a.ws.String()[:8])
	p3exec(t, db, `INSERT INTO cloud_workload (id, workspace_id, connector_id, identity_id, runtime_kind, native_id, name, region)
		VALUES (?, ?, ?, ?, 'lambda_function', ?, 'stop-fn', 'us-east-1')`,
		workload, a.ws, a.conn, identity, "arn:aws:lambda:us-east-1:111111111111:function:stop-"+a.ws.String()[:8])

	code, h0, hdr := agwHints(t, api, credA, nil)
	if code != 200 || len(h0.Stopped) != 0 || h0.FailMode != "auto" || h0.CacheTTLSeconds != 30 || h0.Version == "" ||
		hdr.Get("ETag") != `"`+h0.Version+`"` || h0.PolicyVersion == "" {
		t.Fatalf("initial hints: %d %+v etag=%s", code, h0, hdr.Get("ETag"))
	}
	if code, _, _ := agwHints(t, api, credA, map[string]string{"If-None-Match": hdr.Get("ETag")}); code != http.StatusNotModified {
		t.Fatalf("unchanged hints: %d, want 304", code)
	}
	if ok, reason, _ := agwEval(t, api, credA, agentEval("billing", identity.String())); !ok || reason != "default_allow" {
		t.Fatalf("before the stop: %v %s", ok, reason)
	}

	p3exec(t, db, `INSERT INTO agent_containment (id, workspace_id, connector_id, identity_id, identity_kind, identity_arn, unique_id,
		level, state, reason, created_by, contained_at) VALUES (?, ?, ?, ?, 'iam_role', ?, 'AROASTOP', 'identity', 'contained',
		'stop it', ?, now())`, contain, a.ws, a.conn, identity, "arn:aws:iam::111111111111:role/stop-"+a.ws.String()[:8], a.author)
	services.InvalidateAgentGatewayWorkspace(a.ws, uuid.Nil) // what Contain does after commit

	code, h1, hdr1 := agwHints(t, api, credA, map[string]string{"If-None-Match": hdr.Get("ETag")})
	if code != 200 || h1.Version == h0.Version || !hasStop(h1, "identity_id", identity.String(), "containment:"+contain.String()) ||
		!hasStop(h1, "workload_id", workload.String(), "containment:"+contain.String()) || hdr1.Get("ETag") == hdr.Get("ETag") {
		t.Fatalf("hints after the stop: %d %+v", code, h1)
	}
	ok, reason, ctx := agwEval(t, api, credA, agentEval("billing", identity.String()))
	if ok || reason != "agent_stopped" || ctx["ttl_seconds"].(float64) != 0 {
		t.Fatalf("PDP served a stopped agent: %v %s %v", ok, reason, ctx)
	}
	if ok, reason, _ := agwEval(t, api, credA, agentEval("other", uuid.NewString())); !ok || reason == "agent_stopped" {
		t.Fatalf("another agent refused: %v %s", ok, reason)
	}
	// Workspace B: its gateway sees no stop of A's, and A's identity is not
	// stopped there.
	if code, hb, _ := agwHints(t, api, credB, nil); code != 200 || len(hb.Stopped) != 0 {
		t.Fatalf("B's hints carry A's stops: %d %+v", code, hb)
	}
	if ok, reason, _ := agwEval(t, api, credB, agentEval("billing", identity.String())); !ok || reason == "agent_stopped" {
		t.Fatalf("A's containment stopped B's agent: %v %s", ok, reason)
	}

	// A deny policy that blocks every model for a named agent is a stop too.
	if code, out := agwAdmin(t, api, "POST", "/tool-policies", tokA, map[string]any{"name": "block-rogue", "effect": "deny", "kind": "model",
		"subject": map[string]any{"client_id": "rogue-*"}, "target": map[string]any{}}); code != 201 {
		t.Fatalf("%d %v", code, out)
	}
	if _, h2, _ := agwHints(t, api, credA, nil); !hasStop(h2, "client_id", "rogue-*", "policy:") || h2.PolicyVersion == h1.PolicyVersion {
		t.Fatalf("policy stop / policy version: %+v", h2)
	}

	// Released: the stop is gone from the next hints.
	p3exec(t, db, `UPDATE agent_containment SET state = 'released', released_at = now() WHERE workspace_id = ? AND id = ?`, a.ws, contain)
	if _, h3, _ := agwHints(t, api, credA, nil); hasStop(h3, "identity_id", identity.String(), "") {
		t.Fatalf("released containment still a stop: %+v", h3)
	}

	// --- fail mode and cache cap -------------------------------------------
	gw := func(tok, id string) map[string]any {
		code, out := agwAdmin(t, api, "GET", "/gateways/"+id, tok, nil)
		if code != 200 {
			t.Fatalf("get gateway: %d %v", code, out)
		}
		return agwData(t, out)
	}
	version := func() int { return int(gw(tokA, gwA)["version"].(float64)) }
	runtime := func(tok, id string, body map[string]any) (int, map[string]any) {
		return agwAdmin(t, api, "PUT", "/gateways/"+id+"/runtime", tok, body)
	}

	// Another workspace's gateway is 404.
	if code, out := runtime(tokB, gwA, map[string]any{"fail_mode": "open", "version": version()}); code != 404 {
		t.Fatalf("B changed A's gateway: %d %v", code, out)
	}
	// Tightening applies at once.
	code, out := runtime(tokA, gwA, map[string]any{"fail_mode": "closed", "cache_ttl_seconds": 10, "version": version()})
	if code != 200 || agwData(t, out)["applied"] != true {
		t.Fatalf("tighten: %d %v", code, out)
	}
	if _, h, _ := agwHints(t, api, credA, nil); h.FailMode != "closed" || h.CacheTTLSeconds != 10 {
		t.Fatalf("hints after tightening: %+v", h)
	}
	// W5 (rule drift fixed): with nobody holding governance:approve, a
	// requester who does not hold it either never applies alone; the
	// loosening waits for a second person. The requester withdraws it.
	code, out = runtime(tokA, gwA, map[string]any{"fail_mode": "auto", "reason": "pdp outage drill", "version": version()})
	if code != http.StatusAccepted || agwData(t, out)["applied"] != false || agwData(t, out)["break_glass"] == true {
		t.Fatalf("loosening by a non-approver with no approver: %d %v", code, out)
	}
	firstID := agwData(t, out)["pending_change"].(map[string]any)["id"].(string)
	if code, out := pcCall(t, api, "POST", "/pending-changes/"+firstID+"/reject", tokA, map[string]any{"reason": "withdrawn"}); code != 200 {
		t.Fatalf("withdraw: %d %v", code, out)
	}
	// The author becomes the workspace's only approver: break-glass.
	p3exec(t, db, `INSERT INTO role_permissions (role_id, permission_id)
		SELECT ?, id FROM permissions WHERE workspace_id IS NULL AND resource = 'governance' AND action = 'approve'
		ON CONFLICT DO NOTHING`, a.roles[0])
	code, out = runtime(tokA, gwA, map[string]any{"fail_mode": "auto", "reason": "pdp outage drill", "version": version()})
	d := agwData(t, out)
	if code != 200 || d["applied"] != true || d["break_glass"] != true {
		t.Fatalf("break-glass: %d %v", code, out)
	}
	pc := d["pending_change"].(map[string]any)
	if pc["state"] != "applied" || pc["break_glass"] != true || pc["review_due_at"] == nil {
		t.Fatalf("break-glass record: %v", pc)
	}

	// Two approvers now (author and approver hold governance:approve).
	for _, role := range a.roles[:2] {
		p3exec(t, db, `INSERT INTO role_permissions (role_id, permission_id)
			SELECT ?, id FROM permissions WHERE workspace_id IS NULL AND resource = 'governance' AND action = 'approve'
			ON CONFLICT DO NOTHING`, role)
	}
	code, out = runtime(tokA, gwA, map[string]any{"fail_mode": "open", "cache_ttl_seconds": 120, "reason": "maintenance", "version": version()})
	if code != http.StatusAccepted || agwData(t, out)["applied"] != false {
		t.Fatalf("loosen: %d %v", code, out)
	}
	change := agwData(t, out)["pending_change"].(map[string]any)
	changeID := change["id"].(string)
	if g := gw(tokA, gwA); g["fail_mode"] != "auto" || g["cache_ttl_seconds"].(float64) != 10 {
		t.Fatalf("loosening applied before approval: %v", g)
	}
	// One open request per gateway.
	if code, out := runtime(tokA, gwA, map[string]any{"fail_mode": "open", "version": version()}); code != http.StatusConflict {
		t.Fatalf("second open request: %d %v", code, out)
	}
	// The requester cannot approve; another workspace cannot see it.
	if code, out := pcCall(t, api, "POST", "/pending-changes/"+changeID+"/approve", tokA, nil); code != http.StatusForbidden ||
		!strings.Contains(mustJSONString(out), "self_approval") {
		t.Fatalf("self approval: %d %v", code, out)
	}
	if code, _ := pcCall(t, api, "POST", "/pending-changes/"+changeID+"/approve", tokB, nil); code != 404 {
		t.Fatalf("B approved A's change: %d", code)
	}
	if code, _ := pcCall(t, api, "GET", "/pending-changes/"+changeID, tokB, nil); code != 404 {
		t.Fatalf("B read A's change: %d", code)
	}
	if code, _ := pcCall(t, api, "POST", "/pending-changes/"+changeID+"/reject", tokB, map[string]any{"reason": "x"}); code != 404 {
		t.Fatalf("B rejected A's change: %d", code)
	}
	if code, out := pcCall(t, api, "GET", "/pending-changes?state=pending", tokB, nil); code != 200 || strings.Contains(mustJSONString(out), changeID) {
		t.Fatalf("B lists A's change: %d %v", code, out)
	}
	if code, out := pcCall(t, api, "GET", "/pending-changes?state=pending", tokA, nil); code != 200 || !strings.Contains(mustJSONString(out), changeID) {
		t.Fatalf("A's list: %d %v", code, out)
	}
	// The second person applies it.
	code, out = pcCall(t, api, "POST", "/pending-changes/"+changeID+"/approve", approverA, nil)
	if code != 200 {
		t.Fatalf("approve: %d %v", code, out)
	}
	if ap := out["data"].(map[string]any); ap["state"] != "applied" || ap["approved_by"] != a.approver.String() {
		t.Fatalf("approved change: %v", ap)
	}
	if g := gw(tokA, gwA); g["fail_mode"] != "open" || g["cache_ttl_seconds"].(float64) != 120 {
		t.Fatalf("approved change not applied: %v", g)
	}
	// The workspace setting (30) still caps what is handed out.
	if _, h, _ := agwHints(t, api, credA, nil); h.FailMode != "open" || h.CacheTTLSeconds != 30 {
		t.Fatalf("hints after approval: %+v", h)
	}
	if code, _ := pcCall(t, api, "POST", "/pending-changes/"+changeID+"/approve", approverA, nil); code != http.StatusConflict {
		t.Fatalf("approved twice: %d", code)
	}

	// The requester may withdraw a request.
	if code, out := runtime(tokA, gwA, map[string]any{"fail_mode": "closed", "version": version()}); code != 200 {
		t.Fatalf("tighten: %d %v", code, out)
	}
	code, out = runtime(tokA, gwA, map[string]any{"fail_mode": "auto", "version": version()})
	if code != http.StatusAccepted {
		t.Fatalf("loosen: %d %v", code, out)
	}
	second := agwData(t, out)["pending_change"].(map[string]any)["id"].(string)
	code, out = pcCall(t, api, "POST", "/pending-changes/"+second+"/reject", tokA, map[string]any{"reason": "not needed"})
	if code != 200 || out["data"].(map[string]any)["state"] != "rejected" {
		t.Fatalf("withdraw: %d %v", code, out)
	}
	if g := gw(tokA, gwA); g["fail_mode"] != "closed" {
		t.Fatalf("rejected change applied: %v", g)
	}
	// B's gateway was never touched.
	if g := gw(tokB, gwB); g["fail_mode"] != "auto" || g["cache_ttl_seconds"].(float64) != 30 {
		t.Fatalf("B's gateway changed: %v", g)
	}
}
