package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/services"
)

// Agent runtime gateway (SPEC-agent-runtime-gateway.md) through the
// production chains: the admin routes via routes.SetupIGARoutes (real
// AuthMiddleware and permission middleware) and the PDP routes as
// routes.go mounts them. A gateway credential decides workspace and gateway
// and nothing else does: gateway A's credential evaluates only A's
// policies and writes only A's decisions; B can neither read nor change A's
// gateways, policies or decisions (404, like an unknown id).

func agwAdmin(t *testing.T, api *p3OwnersAPI, method, path, tok string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader = http.NoBody
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, "/api/iga/v1/agent-runtime"+path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	api.eng.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func agwPDP(t *testing.T, api *p3OwnersAPI, method, path, cred string, body any, hdr map[string]string) (int, []byte, http.Header) {
	t.Helper()
	var rd io.Reader = http.NoBody
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, "/authsec/pdp"+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if cred != "" {
		req.Header.Set("Authorization", "Bearer "+cred)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	api.eng.ServeHTTP(w, req)
	return w.Code, w.Body.Bytes(), w.Header()
}

func agwData(t *testing.T, out map[string]any) map[string]any {
	t.Helper()
	d, ok := out["data"].(map[string]any)
	if !ok {
		t.Fatalf("no data: %v", out)
	}
	return d
}

func toolEval(agent, server, tool string) map[string]any {
	return map[string]any{
		"subject":  map[string]any{"type": "agent", "id": agent, "properties": map[string]any{"labels": []string{"prod"}}},
		"action":   map[string]any{"name": "tools/call"},
		"resource": map[string]any{"type": "mcp_tool", "id": server + "/" + tool},
		"context":  map[string]any{"args_digest": "sha256:" + strings.Repeat("ab", 32), "prompt": "never stored"},
	}
}

type agwDecision struct {
	Decision bool           `json:"decision"`
	Context  map[string]any `json:"context"`
}

func agwEval(t *testing.T, api *p3OwnersAPI, cred string, body any) (bool, string, map[string]any) {
	t.Helper()
	code, raw, _ := agwPDP(t, api, "POST", "/access/v1/evaluation", cred, body, nil)
	if code != 200 {
		t.Fatalf("evaluation: %d %s", code, raw)
	}
	var d agwDecision
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	ra, _ := d.Context["reason_admin"].(map[string]any)
	reason, _ := ra["reason"].(string)
	return d.Decision, reason, d.Context
}

func agwNewAPI(t *testing.T, db *gorm.DB) *p3OwnersAPI {
	api := p3NewOwnersAPI(t, db)
	platform.MountAgentGatewayPDPRoutes(api.eng.Group("/authsec"), platform.NewAgentGatewayPDPControllerWith(db))
	return api
}

func TestAgentGatewayPDPAndAdminIsolation(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "agw-a")
	b := p3NewGov(t, db, "agw-b")
	p3Audit(t, db, a.ws, b.ws)
	api := agwNewAPI(t, db)
	svc := services.AgentGatewayServiceFor(db)
	all := "governance:read governance:enforce"
	tokA := api.token(a.ws, a.author, a.authorMember, all)
	tokB := api.token(b.ws, b.author, b.authorMember, all)
	readerA := api.token(a.ws, a.author, a.authorMember, "governance:read")

	// Gateways: the credential is in the create response only.
	code, out := agwAdmin(t, api, "POST", "/gateways", tokA, map[string]any{"name": "prod-cluster"})
	if code != http.StatusCreated {
		t.Fatalf("create gateway: %d %v", code, out)
	}
	d := agwData(t, out)
	credA := d["credential"].(string)
	gwA := d["gateway"].(map[string]any)["id"].(string)
	if !strings.HasPrefix(credA, "agw_") || len(credA) != 47 {
		t.Fatalf("credential shape: %q", credA)
	}
	code, out = agwAdmin(t, api, "POST", "/gateways", tokB, map[string]any{"name": "prod-cluster"}) // same name, other workspace
	if code != http.StatusCreated {
		t.Fatalf("create gateway B: %d %v", code, out)
	}
	credB := agwData(t, out)["credential"].(string)
	gwB := agwData(t, out)["gateway"].(map[string]any)["id"].(string)
	if code, out := agwAdmin(t, api, "POST", "/gateways", tokA, map[string]any{"name": "PROD-cluster"}); code != http.StatusConflict {
		t.Fatalf("duplicate live name: %d %v", code, out)
	}
	if code, _ := agwAdmin(t, api, "POST", "/gateways", readerA, map[string]any{"name": "x"}); code != http.StatusForbidden {
		t.Fatalf("governance:read created a gateway: %d", code)
	}
	// Only the hash is stored; no row or audit record carries the credential.
	sum := sha256.Sum256([]byte(credA))
	var n int64
	db.Raw(`SELECT count(*) FROM agent_gateway WHERE workspace_id = ? AND credential_hash = ?`, a.ws, hex.EncodeToString(sum[:])).Scan(&n)
	if n != 1 {
		t.Fatal("credential hash not stored")
	}
	p3WaitAudit(t, db, a.ws, "POST", "/api/iga/v1/agent-runtime/gateways")
	db.Raw(`SELECT count(*) FROM audit_events WHERE workspace_id = ? AND (coalesce(new_values::text,'') LIKE ? OR coalesce(old_values::text,'') LIKE ?)`,
		a.ws.String(), "%"+credA[4:20]+"%", "%"+credA[4:20]+"%").Scan(&n)
	if n != 0 {
		t.Fatal("the credential reached audit_events")
	}

	// Workspace A: enforce mode; deny github/delete_*, allow github/*.
	if code, out := agwAdmin(t, api, "PUT", "/gateway-settings", tokA, map[string]any{"mode": "enforce", "cache_ttl_seconds": 10}); code != 200 {
		t.Fatalf("settings: %d %v", code, out)
	}
	code, out = agwAdmin(t, api, "POST", "/tool-policies", tokA, map[string]any{"name": "no-github-deletes", "effect": "deny",
		"kind": "mcp_tool", "target": map[string]any{"server": "github", "tool": "delete_*"}})
	if code != http.StatusCreated {
		t.Fatalf("deny policy: %d %v", code, out)
	}
	denyID := agwData(t, out)["id"].(string)
	code, out = agwAdmin(t, api, "POST", "/tool-policies", tokA, map[string]any{"name": "github-for-billing", "effect": "allow",
		"kind": "mcp_tool", "subject": map[string]any{"client_id": "billing-*"}, "target": map[string]any{"server": "github"}, "priority": 10})
	if code != http.StatusCreated {
		t.Fatalf("allow policy: %d %v", code, out)
	}
	allowID := agwData(t, out)["id"].(string)
	if code, out := agwAdmin(t, api, "POST", "/tool-policies", tokA, map[string]any{"name": "bad", "effect": "deny", "kind": "mcp_tool",
		"conditions": map[string]any{"max_calls_per_minute": 5}}); code != http.StatusUnprocessableEntity {
		t.Fatalf("a rate on a deny was accepted: %d %v", code, out)
	}
	if code, _ := agwAdmin(t, api, "POST", "/tool-policies", tokA, map[string]any{"name": "x", "effect": "allow", "kind": "mcp_tool",
		"subject": map[string]any{"gateway_id": gwB}}); code != http.StatusUnprocessableEntity {
		t.Fatalf("a policy naming B's gateway was accepted: %d", code)
	}

	// PDP, gateway A: A's policies.
	if ok, reason, ctx := agwEval(t, api, credA, toolEval("billing-agent", "github", "delete_repo")); ok || reason != "policy_deny" ||
		ctx["reason_admin"].(map[string]any)["policy_id"] != denyID || ctx["ttl_seconds"].(float64) != 10 || ctx["decision_id"] == nil {
		t.Fatalf("A delete_repo: %v %s %v", ok, reason, ctx)
	}
	if ok, reason, ctx := agwEval(t, api, credA, toolEval("billing-agent", "github", "create_issue")); !ok || reason != "policy_allow" ||
		ctx["reason_admin"].(map[string]any)["policy_id"] != allowID {
		t.Fatalf("A create_issue: %v %s", ok, reason)
	}
	if ok, reason, _ := agwEval(t, api, credA, toolEval("support-agent", "github", "create_issue")); ok || reason != "default_deny" {
		t.Fatalf("A other agent (enforce default): %v %s", ok, reason)
	}
	model := map[string]any{"subject": map[string]any{"type": "agent", "id": "billing-agent"},
		"action":   map[string]any{"name": "model/invoke", "properties": map[string]any{"operation": "chat.completions"}},
		"resource": map[string]any{"type": "model", "id": "openai/gpt-4o"}}
	if ok, reason, _ := agwEval(t, api, credA, model); ok || reason != "default_deny" {
		t.Fatalf("A model: %v %s", ok, reason)
	}
	// PDP, gateway B: none of A's policies, B's default (observe).
	if ok, reason, _ := agwEval(t, api, credB, toolEval("billing-agent", "github", "delete_repo")); !ok || reason != "default_allow" {
		t.Fatalf("B saw A's policy: %v %s", ok, reason)
	}
	// Nothing in the body names a workspace; a stray workspace_id is ignored.
	body := toolEval("billing-agent", "github", "delete_repo")
	body["workspace_id"] = a.ws.String()
	if ok, _, _ := agwEval(t, api, credB, body); !ok {
		t.Fatal("a body workspace_id changed the decision")
	}

	// Batch (§7): deny_on_first_deny stops at the first deny.
	code, raw, hdr := agwPDP(t, api, "POST", "/access/v1/evaluations", credA, map[string]any{
		"subject": map[string]any{"type": "agent", "id": "billing-agent"}, "action": map[string]any{"name": "tools/call"},
		"evaluations": []any{
			map[string]any{"resource": map[string]any{"type": "mcp_tool", "id": "github/list_issues"}},
			map[string]any{"resource": map[string]any{"type": "mcp_tool", "id": "github/delete_repo"}},
			map[string]any{"resource": map[string]any{"type": "mcp_tool", "id": "github/create_issue"}},
			map[string]any{"resource": map[string]any{"type": "file", "id": "x"}},
		},
		"options": map[string]any{"evaluations_semantic": "deny_on_first_deny"}}, map[string]string{"X-Request-ID": "req-42"})
	var batch struct {
		Evaluations []agwDecision `json:"evaluations"`
	}
	_ = json.Unmarshal(raw, &batch)
	if code != 200 || len(batch.Evaluations) != 2 || !batch.Evaluations[0].Decision || batch.Evaluations[1].Decision || hdr.Get("X-Request-ID") != "req-42" {
		t.Fatalf("batch: %d %s", code, raw)
	}
	code, raw, _ = agwPDP(t, api, "POST", "/access/v1/evaluations", credA, map[string]any{
		"subject": map[string]any{"type": "agent", "id": "billing-agent"}, "action": map[string]any{"name": "tools/call"},
		"evaluations": []any{map[string]any{"resource": map[string]any{"type": "file", "id": "x"}}}}, nil)
	_ = json.Unmarshal(raw, &batch)
	if code != 200 || len(batch.Evaluations) != 1 || batch.Evaluations[0].Decision || batch.Evaluations[0].Context["error"] == nil {
		t.Fatalf("per-evaluation error (§7.2.1): %d %s", code, raw)
	}

	// Refused requests.
	if code, _, _ := agwPDP(t, api, "POST", "/access/v1/evaluation", "", toolEval("a", "s", "t"), nil); code != 401 {
		t.Fatalf("no credential: %d", code)
	}
	if code, _, _ := agwPDP(t, api, "POST", "/access/v1/evaluation", "agw_"+strings.Repeat("A", 43), toolEval("a", "s", "t"), nil); code != 401 {
		t.Fatalf("unknown credential: %d", code)
	}
	if code, _, _ := agwPDP(t, api, "POST", "/access/v1/evaluation", tokA, toolEval("a", "s", "t"), nil); code != 401 {
		t.Fatalf("a console token at the PDP: %d", code)
	}
	if code, _, _ := agwPDP(t, api, "POST", "/access/v1/evaluation", credA, map[string]any{"subject": map[string]any{"type": "agent", "id": "a"}}, nil); code != 400 {
		t.Fatalf("incomplete evaluation: %d", code)
	}

	// Uploads: stamped with A's gateway; a forged pdp source refused.
	recID := uuid.NewString()
	rec := map[string]any{"id": recID, "record_type": "decision", "source": "cache", "decided_at": time.Now().UTC(),
		"subject": map[string]any{"type": "agent", "id": "billing-agent"}, "action": map[string]any{"name": "tools/call"},
		"resource": map[string]any{"type": "mcp_tool", "id": "github/create_issue"}, "decision": "allow", "reason": "policy_allow",
		"latency_ms": 0.2, "args_digest": "sha256:" + strings.Repeat("cd", 32)}
	forged := map[string]any{}
	for k, v := range rec {
		forged[k] = v
	}
	forged["id"], forged["source"] = uuid.NewString(), "pdp"
	outcome := map[string]any{"id": uuid.NewString(), "record_type": "outcome", "source": "pdp", "decided_at": time.Now().UTC(),
		"subject": map[string]any{"type": "agent", "id": "billing-agent"}, "action": map[string]any{"name": "model/invoke"},
		"resource": map[string]any{"type": "model", "id": "openai/gpt-4o"}, "decision": "allow", "reason": "upstream_completed",
		"usage": map[string]any{"input_tokens": 10, "output_tokens": 3, "total_tokens": 13}, "upstream_status": 200}
	code, raw, _ = agwPDP(t, api, "POST", "/v1/decisions", credA, map[string]any{"records": []any{rec, forged, outcome}}, nil)
	var upRes services.AgentGatewayUploadResult
	_ = json.Unmarshal(raw, &upRes)
	if code != 202 || upRes.Accepted != 2 || upRes.Rejected != 1 {
		t.Fatalf("upload: %d %s", code, raw)
	}
	// A retry is idempotent; B re-using A's record id writes B's own row.
	code, raw, _ = agwPDP(t, api, "POST", "/v1/decisions", credA, map[string]any{"records": []any{rec}}, nil)
	_ = json.Unmarshal(raw, &upRes)
	if code != 202 || upRes.Accepted != 0 || upRes.Duplicates != 1 {
		t.Fatalf("retry: %d %s", code, raw)
	}
	code, raw, _ = agwPDP(t, api, "POST", "/v1/decisions", credB, map[string]any{"records": []any{rec}}, nil)
	_ = json.Unmarshal(raw, &upRes)
	if code != 202 || upRes.Accepted != 1 {
		t.Fatalf("B with A's id: %d %s", code, raw)
	}

	// Decisions list: A sees its own, every row of A's gateway; B none of them.
	svc.FlushDecisions()
	code, out = agwAdmin(t, api, "GET", "/gateway-decisions?limit=200", tokA, nil)
	if code != 200 {
		t.Fatalf("list: %d %v", code, out)
	}
	rows := out["data"].([]any)
	var pdpRows, cacheRows, outcomes int
	for _, r := range rows {
		m := r.(map[string]any)
		if m["gateway_id"] != gwA {
			t.Fatalf("A's log holds another gateway's row: %v", m)
		}
		if strings.Contains(mustJSONString(m), "never stored") {
			t.Fatal("a context key outside the kept set was stored")
		}
		switch {
		case m["record_type"] == "outcome":
		case m["source"] == "pdp":
			pdpRows++
		case m["source"] == "cache":
			cacheRows++
		}
		if m["record_type"] == "outcome" {
			outcomes++
			if m["usage"].(map[string]any)["total_tokens"].(float64) != 13 {
				t.Fatalf("usage: %v", m)
			}
		}
	}
	// 4 single evaluations + 2 in the first batch (it stops at the deny);
	// an invalid evaluation is not a decision.
	if pdpRows != 6 || cacheRows != 1 || outcomes != 1 {
		t.Fatalf("A's log: pdp=%d cache=%d outcome=%d (%d rows)", pdpRows, cacheRows, outcomes, len(rows))
	}
	code, out = agwAdmin(t, api, "GET", "/gateway-decisions?decision=deny&kind=mcp_tool&subject_id=billing-agent", tokA, nil)
	if code != 200 || len(out["data"].([]any)) != 2 {
		t.Fatalf("filtered list: %d %v", code, out)
	}
	code, out = agwAdmin(t, api, "GET", "/gateway-decisions?limit=2", tokA, nil)
	next, _ := out["meta"].(map[string]any)["next_cursor"].(string)
	if code != 200 || len(out["data"].([]any)) != 2 || next == "" {
		t.Fatalf("page 1: %v", out)
	}
	code, out = agwAdmin(t, api, "GET", "/gateway-decisions?limit=2&cursor="+next, tokA, nil)
	if code != 200 || len(out["data"].([]any)) != 2 || out["data"].([]any)[0].(map[string]any)["id"] == rows[1].(map[string]any)["id"] {
		t.Fatalf("page 2: %v", out)
	}
	code, out = agwAdmin(t, api, "GET", "/gateway-decisions?limit=200", tokB, nil)
	for _, r := range out["data"].([]any) {
		if r.(map[string]any)["gateway_id"] != gwB {
			t.Fatal("B sees A's decisions")
		}
	}
	if code != 200 || len(out["data"].([]any)) != 3 { // 2 evaluations + the re-used id
		t.Fatalf("B's log: %d rows", len(out["data"].([]any)))
	}
	if code, out := agwAdmin(t, api, "GET", "/gateway-decisions?gateway_id="+gwA, tokB, nil); code != 200 || len(out["data"].([]any)) != 0 {
		t.Fatal("B filtered by A's gateway saw rows")
	}

	// Admin isolation: A's ids are 404 for B on every route.
	for _, c := range []struct{ method, path string }{
		{"GET", "/gateways/" + gwA}, {"PATCH", "/gateways/" + gwA}, {"POST", "/gateways/" + gwA + "/rotate"},
		{"DELETE", "/gateways/" + gwA}, {"GET", "/tool-policies/" + denyID}, {"PUT", "/tool-policies/" + denyID},
		{"DELETE", "/tool-policies/" + denyID},
	} {
		var body any
		if c.method == "PATCH" {
			body = map[string]any{"name": "stolen", "version": 1}
		}
		if c.method == "PUT" {
			body = map[string]any{"name": "stolen", "effect": "allow", "kind": "mcp_tool", "version": 1}
		}
		if code, out := agwAdmin(t, api, c.method, c.path, tokB, body); code != http.StatusNotFound {
			t.Errorf("B %s %s: %d %v", c.method, c.path, code, out)
		}
	}
	code, out = agwAdmin(t, api, "GET", "/tool-policies", tokB, nil)
	if code != 200 || len(out["data"].([]any)) != 0 {
		t.Fatalf("B lists A's policies: %v", out)
	}
	code, out = agwAdmin(t, api, "GET", "/gateways", tokB, nil)
	if code != 200 || len(out["data"].([]any)) != 1 {
		t.Fatalf("B's gateways: %v", out)
	}
	if code, _ := agwAdmin(t, api, "POST", "/tool-policies/evaluate", tokB, map[string]any{"gateway_id": gwA,
		"subject": map[string]any{"type": "agent", "id": "a"}, "action": map[string]any{"name": "tools/call"},
		"resource": map[string]any{"type": "mcp_tool", "id": "github/delete_repo"}}); code != http.StatusNotFound {
		t.Fatalf("B dry run as A's gateway: %d", code)
	}
	// Row-level security: a B transaction sees none of A's policies whatever its SQL says.
	err := tenancy.InWorkspaceRead(context.Background(), db, b.ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT count(*) FROM agent_tool_policy`).Scan(&n).Error
	})
	if err != nil || n != 0 {
		t.Fatalf("RLS: B sees %d policies (%v)", n, err)
	}

	// Dry run: decision and trace, nothing recorded, no token taken.
	svc.FlushDecisions()
	var before int64
	db.Raw(`SELECT count(*) FROM agent_gateway_decision WHERE workspace_id = ?`, a.ws).Scan(&before)
	code, out = agwAdmin(t, api, "POST", "/tool-policies/evaluate", readerA, toolEval("billing-agent", "github", "delete_repo"))
	if code != 200 {
		t.Fatalf("dry run: %d %v", code, out)
	}
	dr := agwData(t, out)
	if dr["decision"] != false || dr["reason"] != "policy_deny" || len(dr["policies"].([]any)) != 2 {
		t.Fatalf("dry run: %v", dr)
	}
	svc.FlushDecisions()
	var after int64
	db.Raw(`SELECT count(*) FROM agent_gateway_decision WHERE workspace_id = ?`, a.ws).Scan(&after)
	if after != before {
		t.Fatal("a dry run was recorded")
	}

	// Policy change takes effect at once; PUT needs the current version.
	if code, out := agwAdmin(t, api, "PUT", "/tool-policies/"+denyID, tokA, map[string]any{"name": "no-github-deletes", "effect": "deny",
		"kind": "mcp_tool", "target": map[string]any{"server": "github", "tool": "delete_*"}, "enabled": false, "version": 7}); code != http.StatusConflict {
		t.Fatalf("stale version: %d %v", code, out)
	}
	if code, out := agwAdmin(t, api, "PUT", "/tool-policies/"+denyID, tokA, map[string]any{"name": "no-github-deletes", "effect": "deny",
		"kind": "mcp_tool", "target": map[string]any{"server": "github", "tool": "delete_*"}, "enabled": false, "version": 1}); code != 200 {
		t.Fatalf("disable: %d %v", code, out)
	}
	if ok, reason, _ := agwEval(t, api, credA, toolEval("billing-agent", "github", "delete_repo")); !ok || reason != "policy_allow" {
		t.Fatalf("after disabling the deny: %v %s", ok, reason)
	}
	if code, _ := agwAdmin(t, api, "DELETE", "/tool-policies/"+denyID, tokA, nil); code != http.StatusNoContent {
		t.Fatalf("delete policy: %d", code)
	}

	// Rotation: the old credential is refused at once; revocation too.
	code, out = agwAdmin(t, api, "POST", "/gateways/"+gwA+"/rotate", tokA, nil)
	if code != 200 {
		t.Fatalf("rotate: %d %v", code, out)
	}
	newA := agwData(t, out)["credential"].(string)
	if code, _, _ := agwPDP(t, api, "POST", "/access/v1/evaluation", credA, toolEval("a", "github", "x"), nil); code != 401 {
		t.Fatalf("rotated credential still works: %d", code)
	}
	if ok, _, _ := agwEval(t, api, newA, toolEval("billing-agent", "github", "x")); !ok {
		t.Fatal("new credential")
	}
	if code, out := agwAdmin(t, api, "DELETE", "/gateways/"+gwA, tokA, nil); code != 200 || agwData(t, out)["state"] != "revoked" {
		t.Fatalf("revoke: %d %v", code, out)
	}
	if code, _, _ := agwPDP(t, api, "GET", "/v1/policy-hints", newA, nil, nil); code != 401 {
		t.Fatalf("revoked credential still works: %d", code)
	}
	if code, _ := agwAdmin(t, api, "POST", "/gateways/"+gwA+"/rotate", tokA, nil); code != http.StatusConflict {
		t.Fatalf("rotate a revoked gateway: %d", code)
	}
	// A revoked gateway's name is free again.
	if code, _ := agwAdmin(t, api, "POST", "/gateways", tokA, map[string]any{"name": "prod-cluster"}); code != http.StatusCreated {
		t.Fatalf("reuse a revoked name: %d", code)
	}
}

func mustJSONString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestAgentGatewayHintsRatesAndRetention(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "agw-hints")
	p3Audit(t, db, a.ws)
	api := agwNewAPI(t, db)
	svc := services.AgentGatewayServiceFor(db)
	tok := api.token(a.ws, a.author, a.authorMember, "governance:read governance:enforce")
	_, out := agwAdmin(t, api, "POST", "/gateways", tok, map[string]any{"name": "gw"})
	cred := agwData(t, out)["credential"].(string)

	// A rate: 2 calls a minute, never cached.
	if code, out := agwAdmin(t, api, "POST", "/tool-policies", tok, map[string]any{"name": "gpt-2pm", "effect": "allow", "kind": "model",
		"target": map[string]any{"provider": "openai", "model": "gpt-*"}, "conditions": map[string]any{"max_calls_per_minute": 2}}); code != 201 {
		t.Fatalf("%d %v", code, out)
	}
	if code, out := agwAdmin(t, api, "POST", "/tool-policies", tok, map[string]any{"name": "no-prod-shell", "effect": "deny", "kind": "mcp_tool",
		"target": map[string]any{"server": "ops", "tool": "shell_*"}}); code != 201 {
		t.Fatalf("%d %v", code, out)
	}
	model := map[string]any{"subject": map[string]any{"type": "agent", "id": "rate-agent-" + uuid.NewString()},
		"action": map[string]any{"name": "model/invoke"}, "resource": map[string]any{"type": "model", "id": "openai/gpt-4o"}}
	for i := 0; i < 2; i++ {
		if ok, reason, ctx := agwEval(t, api, cred, model); !ok || reason != "policy_allow" || ctx["ttl_seconds"].(float64) != 0 {
			t.Fatalf("call %d: %v %s %v", i, ok, reason, ctx)
		}
	}
	if ok, reason, _ := agwEval(t, api, cred, model); ok || reason != "rate_limited" {
		t.Fatalf("3rd call: %v %s", ok, reason)
	}

	// Hints: the mode and the deny targets, nothing else.
	code, raw, _ := agwPDP(t, api, "GET", "/v1/policy-hints", cred, nil, nil)
	var h services.AgentGatewayPolicyHints
	_ = json.Unmarshal(raw, &h)
	if code != 200 || h.Mode != "observe" || len(h.DenyTargets) != 1 || h.DenyTargets[0].Tool != "shell_*" || strings.Contains(string(raw), "no-prod-shell") {
		t.Fatalf("hints: %d %s", code, raw)
	}

	// Per-gateway rate limit.
	svc.WithRateLimit(1, 1)
	t.Cleanup(func() { svc.WithRateLimit(500, 1000) })
	agwPDP(t, api, "GET", "/v1/policy-hints", cred, nil, nil)
	if code, _, hdr := agwPDP(t, api, "GET", "/v1/policy-hints", cred, nil, nil); code != 429 || hdr.Get("Retry-After") == "" {
		t.Fatalf("per-gateway limit: %d", code)
	}
	svc.WithRateLimit(500, 1000)

	// The decision log is append-only; retention removes only old rows.
	svc.FlushDecisions()
	if err := db.Exec(`UPDATE agent_gateway_decision SET decision = 'allow' WHERE workspace_id = ?`, a.ws).Error; err == nil ||
		!strings.Contains(err.Error(), "append-only") {
		t.Fatalf("update allowed: %v", err)
	}
	if err := db.Exec(`DELETE FROM agent_gateway_decision WHERE workspace_id = ?`, a.ws).Error; err == nil {
		t.Fatal("delete allowed")
	}
	var gw uuid.UUID
	db.Raw(`SELECT id FROM agent_gateway WHERE workspace_id = ? LIMIT 1`, a.ws).Scan(&gw)
	old := uuid.New()
	if err := db.Exec(`INSERT INTO agent_gateway_decision (id, workspace_id, gateway_id, source, decided_at, subject_id, action, kind, resource_id, decision)
		VALUES (?, ?, ?, 'cache', now() - interval '40 days', 'a', 'tools/call', 'mcp_tool', 's/t', 'allow')`, old, a.ws, gw).Error; err != nil {
		t.Fatal(err)
	}
	var total int64
	db.Raw(`SELECT count(*) FROM agent_gateway_decision WHERE workspace_id = ?`, a.ws).Scan(&total)
	deleted, err := svc.PurgeDecisions(context.Background(), a.ws)
	if err != nil || deleted != 1 {
		t.Fatalf("purge: %d %v", deleted, err)
	}
	var left int64
	db.Raw(`SELECT count(*) FROM agent_gateway_decision WHERE workspace_id = ?`, a.ws).Scan(&left)
	if left != total-1 {
		t.Fatalf("purge removed recent rows: %d of %d left", left, total)
	}
	// The purge setting alone cannot delete a recent row.
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`SET LOCAL authsec.gateway_decision_purge = 'on'`).Error; err != nil {
			return err
		}
		return tx.Exec(`DELETE FROM agent_gateway_decision WHERE workspace_id = ?`, a.ws).Error
	})
	if err == nil {
		t.Fatal("recent rows deleted under the purge setting")
	}
}
