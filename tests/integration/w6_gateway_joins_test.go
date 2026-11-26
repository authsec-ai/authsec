package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/modelprovider"
	"github.com/authsec-ai/authsec/services"
)

// W6 (SPEC-secops-backend-upgrade.md C3-C6, P15, P17) through the real
// routes and database: provider keys in Vault (never returned or logged),
// agent keys in the hints of the right gateway only, held calls with a
// named approver who is never the agent's human, per-minute DNS lookups and
// flow summaries, per-minute provider usage, the reconciliation labels and
// USAGE-02/03 alerts -- each workspace seeing only its own.

const w6ProviderSecret = "sk-proj-W6SECRETVALUE-0000000000000000"

func w6Hints(t *testing.T, api *p3OwnersAPI, cred string) services.AgentGatewayPolicyHints {
	t.Helper()
	code, raw, _ := agwPDP(t, api, "GET", "/v1/policy-hints", cred, nil, nil)
	if code != 200 {
		t.Fatalf("hints: %d %s", code, raw)
	}
	var h services.AgentGatewayPolicyHints
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	return h
}

func w6Gateway(t *testing.T, api *p3OwnersAPI, tok, name string) (string, string) {
	t.Helper()
	code, out := agwAdmin(t, api, "POST", "/gateways", tok, map[string]any{"name": name})
	if code != http.StatusCreated {
		t.Fatalf("gateway: %d %v", code, out)
	}
	d := agwData(t, out)
	return d["credential"].(string), d["gateway"].(map[string]any)["id"].(string)
}

func TestW6GatewayKeysVaultAndIsolation(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "w6-keys-a")
	b := p3NewGov(t, db, "w6-keys-b")
	p3Audit(t, db, a.ws, b.ws)
	mv := newMemVault()
	t.Cleanup(services.SetModelProviderVault(mv))
	var logs bytes.Buffer
	prevOut := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prevOut) })

	api := agwNewAPI(t, db)
	all := "governance:read governance:enforce"
	tokA := api.token(a.ws, a.author, a.authorMember, all)
	tokB := api.token(b.ws, b.author, b.authorMember, all)
	credA, _ := w6Gateway(t, api, tokA, "gw-a")
	credB, _ := w6Gateway(t, api, tokB, "gw-b")

	// Add: the response carries a fingerprint, never the key.
	req := httptest.NewRequest("POST", "/api/iga/v1/agent-runtime/gateway-provider-keys",
		strings.NewReader(`{"name":"openai-prod","provider":"openai","key":"`+w6ProviderSecret+`"}`))
	req.Header.Set("Authorization", "Bearer "+tokA)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.eng.ServeHTTP(w, req)
	if w.Code != http.StatusCreated || strings.Contains(w.Body.String(), "W6SECRETVALUE") {
		t.Fatalf("add: %d %s", w.Code, w.Body.String())
	}
	var added struct {
		Data services.AgentGatewayProviderKeyView `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &added)
	keyID := added.Data.ID.String()
	if !strings.HasPrefix(added.Data.KeyFingerprint, "...0000 sha256:") {
		t.Fatalf("fingerprint %q", added.Data.KeyFingerprint)
	}
	paths := mv.paths()
	if len(paths) != 1 || !strings.Contains(paths[0], "workspaces/"+a.ws.String()+"/agent-gateway/provider-keys/"+keyID+"-") {
		t.Fatalf("vault paths %v", paths)
	}
	firstPath := paths[0]
	// Lists and reads: never the key; another workspace's is 404.
	for _, p := range []string{"/gateway-provider-keys", "/gateway-provider-keys/" + keyID} {
		code, out := agwAdmin(t, api, "GET", p, tokA, nil)
		raw, _ := json.Marshal(out)
		if code != 200 || strings.Contains(string(raw), "W6SECRETVALUE") {
			t.Fatalf("read %s: %d %s", p, code, raw)
		}
	}
	for _, c := range []struct{ m, p string }{{"GET", "/gateway-provider-keys/" + keyID}, {"DELETE", "/gateway-provider-keys/" + keyID},
		{"POST", "/gateway-provider-keys/" + keyID + "/rotate"}} {
		if code, _ := agwAdmin(t, api, c.m, c.p, tokB, map[string]any{"key": "sk-other-workspace-key-000000"}); code != http.StatusNotFound {
			t.Fatalf("B %s %s: %d", c.m, c.p, code)
		}
	}
	if len(mv.paths()) != 1 {
		t.Fatalf("B's refused rotate wrote to Vault: %v", mv.paths())
	}

	// The gateway fetches its workspace's keys with its credential only.
	code, raw, hdr := agwPDP(t, api, "GET", "/v1/provider-keys", credA, nil, nil)
	if code != 200 || !strings.Contains(string(raw), w6ProviderSecret) || hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("A fetch: %d %s", code, raw)
	}
	if code, raw, _ = agwPDP(t, api, "GET", "/v1/provider-keys", credB, nil, nil); code != 200 || strings.Contains(string(raw), "W6SECRETVALUE") {
		t.Fatalf("B fetch: %d %s", code, raw)
	}
	if code, _, _ = agwPDP(t, api, "GET", "/v1/provider-keys", "agw_not-a-real-credential", nil, nil); code != 401 {
		t.Fatalf("unknown credential: %d", code)
	}

	// Rotate destroys the old path; revoke destroys the new one.
	if code, out := agwAdmin(t, api, "POST", "/gateway-provider-keys/"+keyID+"/rotate", tokA,
		map[string]any{"key": "sk-proj-W6ROTATED-111111111111111111"}); code != 200 {
		t.Fatalf("rotate: %d %v", code, out)
	}
	if p := mv.paths(); len(p) != 1 || p[0] == firstPath {
		t.Fatalf("after rotate %v", p)
	}
	if code, _ := agwAdmin(t, api, "DELETE", "/gateway-provider-keys/"+keyID, tokA, nil); code != 200 {
		t.Fatalf("revoke %d", code)
	}
	if p := mv.paths(); len(p) != 0 {
		t.Fatalf("after revoke %v", p)
	}
	if _, raw, _ = agwPDP(t, api, "GET", "/v1/provider-keys", credA, nil, nil); strings.Contains(string(raw), "W6ROTATED") {
		t.Fatal("a revoked key is still handed out")
	}

	// Agent keys: shown once, in the issuing workspace's hints only.
	code, out := agwAdmin(t, api, "POST", "/gateway-agent-keys", tokA, map[string]any{"name": "billing"})
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("unbound agent key: %d %v", code, out)
	}
	code, out = agwAdmin(t, api, "POST", "/gateway-agent-keys", tokA, map[string]any{"name": "billing",
		"spiffe_id": "spiffe://acme/ns/prod/sa/billing", "principal_user_id": a.author.String()})
	if code != http.StatusCreated {
		t.Fatalf("issue: %d %v", code, out)
	}
	d := agwData(t, out)
	agk := d["key"].(string)
	akID := d["agent_key"].(map[string]any)["id"].(string)
	if !strings.HasPrefix(agk, "agk_") {
		t.Fatalf("agent key %q", agk)
	}
	if code, out = agwAdmin(t, api, "GET", "/gateway-agent-keys", tokA, nil); code != 200 {
		t.Fatal(code)
	}
	if raw, _ := json.Marshal(out); strings.Contains(string(raw), agk) || strings.Contains(string(raw), services.HashAgentGatewayAgentKey(agk)) {
		t.Fatal("list shows the key or its hash")
	}
	ha, hb := w6Hints(t, api, credA), w6Hints(t, api, credB)
	if len(ha.AgentKeys) != 1 || ha.AgentKeys[0].KeySHA256 != services.HashAgentGatewayAgentKey(agk) ||
		ha.AgentKeys[0].SPIFFEID != "spiffe://acme/ns/prod/sa/billing" || len(hb.AgentKeys) != 0 {
		t.Fatalf("hints A %+v B %+v", ha.AgentKeys, hb.AgentKeys)
	}
	if code, _ := agwAdmin(t, api, "DELETE", "/gateway-agent-keys/"+akID, tokB, nil); code != http.StatusNotFound {
		t.Fatalf("B revokes A's agent key: %d", code)
	}
	if code, _ := agwAdmin(t, api, "DELETE", "/gateway-agent-keys/"+akID, tokA, nil); code != 200 {
		t.Fatalf("revoke agent key: %d", code)
	}
	if h := w6Hints(t, api, credA); len(h.AgentKeys) != 0 {
		t.Fatalf("revoked key still in hints: %+v", h.AgentKeys)
	}

	// No key value in logs, governance events or audit rows.
	if strings.Contains(logs.String(), "W6SECRETVALUE") || strings.Contains(logs.String(), "W6ROTATED") || strings.Contains(logs.String(), agk) {
		t.Fatal("a key reached the log")
	}
	var n int64
	db.Raw(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND (payload::text LIKE '%W6SECRET%' OR payload::text LIKE '%W6ROTATED%')`, a.ws).Scan(&n)
	if n != 0 {
		t.Fatal("a key reached the governance events")
	}
	db.Raw(`SELECT count(*) FROM audit_events WHERE (COALESCE(new_values::text,'') || COALESCE(old_values::text,'')) LIKE '%W6SECRET%'`).Scan(&n)
	if n != 0 {
		t.Fatal("a key reached the audit log")
	}
}

func TestW6GatewayHoldsApproverAndExpiry(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "w6-holds-a")
	b := p3NewGov(t, db, "w6-holds-b")
	p3Audit(t, db, a.ws, b.ws)
	api := agwNewAPI(t, db)
	all := "governance:read governance:enforce governance:approve"
	tokA := api.token(a.ws, a.author, a.authorMember, all)
	tokB := api.token(b.ws, b.author, b.authorMember, all)
	decider, deciderMember := a.member("decider-"+a.ws.String()[:8]+"@w6.test", "Dee Decider", "active")
	other, otherMember := a.member("other-"+a.ws.String()[:8]+"@w6.test", "Otto Other", "active")
	tokDecider := api.token(a.ws, decider, deciderMember, all)
	tokOther := api.token(a.ws, other, otherMember, all)
	credA, _ := w6Gateway(t, api, tokA, "gw-hold-a")
	credB, _ := w6Gateway(t, api, tokB, "gw-hold-b")

	// The agent acts for the author.
	code, out := agwAdmin(t, api, "POST", "/gateway-agent-keys", tokA, map[string]any{"name": "payer", "client_id": "payer-agent",
		"spiffe_id": "spiffe://acme/ns/prod/sa/payer", "principal_user_id": a.author.String()})
	if code != http.StatusCreated {
		t.Fatalf("issue: %d %v", code, out)
	}
	// A policy that holds payments above 100.
	code, out = agwAdmin(t, api, "POST", "/tool-policies", tokA, map[string]any{"name": "payments", "effect": "allow",
		"kind": "mcp_tool", "subject": map[string]any{"client_id": "payer-agent"}, "target": map[string]any{"server": "pay", "tool": "pay"},
		"conditions": map[string]any{"arg_bounds": map[string]any{"on_violation": "hold", "hold_minutes": 30,
			"fields": []any{map[string]any{"path": "amount", "type": "number", "max": 100}}}}})
	if code != http.StatusCreated {
		t.Fatalf("policy: %d %v", code, out)
	}
	policyID := agwData(t, out)["id"].(string)
	// The PDP hands the bounds to the gateway with the allow.
	ok, _, ctx := agwEval(t, api, credA, map[string]any{"subject": map[string]any{"type": "agent", "id": "payer-agent"},
		"action": map[string]any{"name": "tools/call"}, "resource": map[string]any{"type": "mcp_tool", "id": "pay/pay"}})
	if !ok || ctx["arg_bounds"] == nil {
		t.Fatalf("decision context %v", ctx)
	}

	digest := "sha256:" + strings.Repeat("cd", 32)
	hold := func(cred string) (int, map[string]any) {
		body := map[string]any{"subject": map[string]any{"type": "agent", "id": "payer-agent"},
			"action": map[string]any{"name": "tools/call"}, "resource": map[string]any{"type": "mcp_tool", "id": "pay/pay"},
			"args_digest": digest, "run_id": "run-w6", "policy_id": policyID,
			"violations":  []any{map[string]any{"path": "amount", "rule": "max"}},
			"held_values": map[string]any{"amount": 5000, "note": "NOT-BOUNDED-SECRET"}}
		code, raw, _ := agwPDP(t, api, "POST", "/v1/holds", cred, body, nil)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		return code, m
	}
	code, t1 := hold(credA)
	if code != http.StatusCreated || t1["state"] != "pending" {
		t.Fatalf("hold: %d %v", code, t1)
	}
	h1 := t1["hold_id"].(string)
	// B's gateway cannot hold under A's policy, nor see A's hold.
	if code, _ := hold(credB); code == http.StatusCreated {
		t.Fatal("B held a call under A's policy")
	}
	if code, _, _ := agwPDP(t, api, "GET", "/v1/holds/"+h1, credB, nil, nil); code != http.StatusNotFound {
		t.Fatalf("B reads A's hold: %d", code)
	}
	if code, _ := agwAdmin(t, api, "GET", "/gateway-holds/"+h1, tokB, nil); code != http.StatusNotFound {
		t.Fatalf("B admin reads A's hold: %d", code)
	}
	// The approver sees the bounded value; an unbounded one is not kept.
	code, out = agwAdmin(t, api, "GET", "/gateway-holds/"+h1, tokA, nil)
	hv := agwData(t, out)
	if code != 200 || hv["held_values"].(map[string]any)["amount"] != float64(5000) || hv["held_values"].(map[string]any)["note"] != nil {
		t.Fatalf("hold view: %d %v", code, hv)
	}
	// The decision log has the ask with paths, never the values.
	var asks []struct {
		Decision   string
		Reason     string
		Violations string
		RunID      string
	}
	db.Raw(`SELECT decision, reason, violations::text AS violations, run_id FROM agent_gateway_decision
	         WHERE workspace_id = ? AND hold_id IS NOT NULL`, a.ws).Scan(&asks)
	if len(asks) != 1 || asks[0].Decision != "ask" || asks[0].Reason != "argument_held" || asks[0].RunID != "run-w6" ||
		!strings.Contains(asks[0].Violations, `"amount"`) {
		t.Fatalf("ask rows %+v", asks)
	}
	var leaked int64
	db.Raw(`SELECT count(*) FROM agent_gateway_decision WHERE workspace_id = ? AND
	         (subject::text || resource::text || COALESCE(violations::text, '')) ~ '5000|NOT-BOUNDED'`, a.ws).Scan(&leaked)
	if leaked != 0 {
		t.Fatal("a held value reached the decision log")
	}
	db.Raw(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = 'gateway.ask_needed' AND payload::text NOT LIKE '%5000%'`, a.ws).Scan(&leaked)
	if leaked != 1 {
		t.Fatalf("ask_needed events: %d", leaked)
	}
	// The agent's own human cannot approve.
	if code, out := agwAdmin(t, api, "POST", "/gateway-holds/"+h1+"/decide", tokA, map[string]any{"decision": "approve"}); code != http.StatusForbidden ||
		!strings.Contains(mustJSONString(out), "approver_is_principal") {
		t.Fatalf("principal approves: %d %v", code, out)
	}
	// With a responder group naming the decider, only the decider decides.
	p3exec(t, db, `INSERT INTO responder_group_member (workspace_id, group_id, user_id, role, state, accepted_at)
		SELECT workspace_id, id, ?, 'lead', 'accepted', now() FROM responder_group WHERE workspace_id = ? AND is_default`, decider, a.ws)
	code, t2 := hold(credA)
	h2 := t2["hold_id"].(string)
	if code != http.StatusCreated || t2["approver_user_id"] != decider.String() {
		t.Fatalf("named approver: %d %v", code, t2)
	}
	if code, out := agwAdmin(t, api, "POST", "/gateway-holds/"+h2+"/decide", tokOther, map[string]any{"decision": "approve"}); code != http.StatusForbidden ||
		!strings.Contains(mustJSONString(out), "not_a_decider") {
		t.Fatalf("non-decider: %d %v", code, out)
	}
	if code, out := agwAdmin(t, api, "POST", "/gateway-holds/"+h2+"/decide", tokB, map[string]any{"decision": "approve"}); code != http.StatusNotFound {
		t.Fatalf("B decides A's hold: %d %v", code, out)
	}
	if code, out := agwAdmin(t, api, "POST", "/gateway-holds/"+h2+"/decide", tokDecider, map[string]any{"decision": "approve", "reason": "ok"}); code != 200 {
		t.Fatalf("decider approves: %d %v", code, out)
	}
	// The gateway consumes it once, for the same call only.
	consume := func(d string) int {
		code, _, _ := agwPDP(t, api, "POST", "/v1/holds/"+h2+"/consume", credA, map[string]any{"subject_id": "payer-agent",
			"resource_id": "pay/pay", "args_digest": d}, nil)
		return code
	}
	if c := consume("sha256:" + strings.Repeat("ee", 32)); c != http.StatusConflict {
		t.Fatalf("other arguments consume: %d", c)
	}
	if c := consume(digest); c != 200 {
		t.Fatalf("consume: %d", c)
	}
	if c := consume(digest); c != http.StatusConflict {
		t.Fatalf("second consume: %d", c)
	}
	var values *string
	db.Raw(`SELECT held_values::text FROM agent_gateway_hold WHERE workspace_id = ? AND id = ?`, a.ws, h2).Scan(&values)
	if values != nil {
		t.Fatal("held values kept after the call went through")
	}
	// Expiry: an expired hold cannot be decided and loses its values.
	p3exec(t, db, `UPDATE agent_gateway_hold SET expires_at = now() - interval '1 minute' WHERE workspace_id = ? AND id = ?`, a.ws, h1)
	if code, out := agwAdmin(t, api, "POST", "/gateway-holds/"+h1+"/decide", tokDecider, map[string]any{"decision": "approve"}); code != http.StatusConflict ||
		!strings.Contains(mustJSONString(out), "hold_expired") {
		t.Fatalf("expired decide: %d %v", code, out)
	}
	db.Raw(`SELECT held_values::text FROM agent_gateway_hold WHERE workspace_id = ? AND id = ?`, a.ws, h1).Scan(&values)
	if values != nil {
		t.Fatal("expired hold kept its values")
	}
	if code, _, _ := agwPDP(t, api, "GET", "/v1/holds/"+h1, credA, nil, nil); code != 200 {
		t.Fatalf("status: %d", code)
	}
	// B lists none of A's holds.
	if code, out := agwAdmin(t, api, "GET", "/gateway-holds", tokB, nil); code != 200 || len(out["data"].([]any)) != 0 {
		t.Fatalf("B holds: %d %v", code, out)
	}
}

/* ------------------------------------ joins --------------------------------- */

type w6FlowLogs struct {
	mu    sync.Mutex
	query string
	rows  [][]cwltypes.ResultField
}

func (f *w6FlowLogs) StartQuery(_ context.Context, in *cloudwatchlogs.StartQueryInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.query = aws.ToString(in.QueryString)
	return &cloudwatchlogs.StartQueryOutput{QueryId: aws.String("q1")}, nil
}

func (f *w6FlowLogs) GetQueryResults(context.Context, *cloudwatchlogs.GetQueryResultsInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetQueryResultsOutput, error) {
	return &cloudwatchlogs.GetQueryResultsOutput{Status: cwltypes.QueryStatusComplete, Results: f.rows}, nil
}

func (f *w6FlowLogs) StopQuery(context.Context, *cloudwatchlogs.StopQueryInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StopQueryOutput, error) {
	return &cloudwatchlogs.StopQueryOutput{}, nil
}

func flowRow(minute time.Time, src, dst, eni string, bytes, pkts int) []cwltypes.ResultField {
	f := func(k, v string) cwltypes.ResultField {
		return cwltypes.ResultField{Field: aws.String(k), Value: aws.String(v)}
	}
	return []cwltypes.ResultField{f("minute", minute.UTC().Format("2006-01-02 15:04:05.000")), f("srcAddr", src), f("dstAddr", dst),
		f("interfaceId", eni), f("bytes_out", itoa(int64(bytes))), f("pkts", itoa(int64(pkts)))}
}

func TestW6DNSLookupRowsEgressAndFlows(t *testing.T) {
	db := igaDB(t)
	a := newP1aEnv(t, db, "w6-dns-a")
	b := newP1aEnv(t, db, "w6-dns-b")
	t.Cleanup(func() {
		for _, ws := range []uuid.UUID{a.ws, b.ws} {
			db.Exec(`DELETE FROM agent_finding WHERE workspace_id = ?`, ws)
			db.Exec(`DELETE FROM cloud_dns_cursor WHERE workspace_id = ?`, ws)
			db.Exec(`DELETE FROM agent_dns_lookup WHERE workspace_id = ?`, ws)
			db.Exec(`DELETE FROM agent_flow_summary WHERE workspace_id = ?`, ws)
			db.Exec(`DELETE FROM agent_join_setting WHERE workspace_id = ?`, ws)
		}
	})
	ctx := context.Background()
	joins := services.NewAgentRuntimeJoinService(db)
	group := "arn:aws:logs:us-east-1:429418377036:log-group:/vpc/flows"
	if _, _, err := joins.PutSettings(ctx, a.ws, uuid.New(), services.AgentJoinSettingsInput{
		EgressHosts:   []string{"api.slack.com", "API.OPENAI.COM"},
		FlowLogGroups: []services.AgentFlowLogGroup{{ConnectorID: a.conn, LogGroup: group}}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := joins.PutSettings(ctx, b.ws, uuid.New(), services.AgentJoinSettingsInput{
		FlowLogGroups: []services.AgentFlowLogGroup{{ConnectorID: a.conn, LogGroup: group}}}); err == nil {
		t.Fatal("B named A's connector")
	}
	st, _ := joins.Settings(ctx, a.ws)
	if strings.Join(st.EgressHosts, ",") != "api.slack.com" || len(st.FlowLogGroups) != 1 || st.FlowLogGroups[0].Region != "us-east-1" {
		t.Fatalf("settings %+v", st)
	}

	now := time.Now().UTC().Truncate(time.Second)
	at := now.Add(-2 * time.Hour)
	logsA := &dnsLogs{records: []dnsLookup{
		{"10.0.1.30", "i-0abc123def456", "vpc-0a1b2c3d", "api.openai.com.", at},
		{"10.0.1.30", "i-0abc123def456", "vpc-0a1b2c3d", "api.slack.com.", at},
		{"10.0.1.30", "i-0abc123def456", "vpc-0a1b2c3d", "internal.payroll.example.", at},
	}}
	out := dnsScan(t, db, a, logsA, now)
	if out.DNSTrafficFindings != 1 {
		t.Fatalf("findings %d (the egress host must not make one)", out.DNSTrafficFindings)
	}
	type lookupRow struct {
		QueryName        string
		HostKind         string
		Provider         string
		SrcIP            string
		HolderWorkloadID *uuid.UUID
		ObservedAt       time.Time
		Queries          int64
	}
	var rows []lookupRow
	db.Raw(`SELECT query_name, host_kind, provider, src_ip, holder_workload_id, observed_at, queries FROM agent_dns_lookup
	         WHERE workspace_id = ? ORDER BY query_name`, a.ws).Scan(&rows)
	if len(rows) != 2 || rows[0].QueryName != "api.openai.com" || rows[0].HostKind != "provider" || rows[0].Provider != "openai" ||
		rows[1].QueryName != "api.slack.com" || rows[1].HostKind != "egress" || rows[0].HolderWorkloadID == nil ||
		!rows[0].ObservedAt.Equal(at.Truncate(time.Minute)) || rows[0].Queries != 1 {
		t.Fatalf("lookup rows %+v", rows)
	}
	var nB int64
	db.Raw(`SELECT count(*) FROM agent_dns_lookup WHERE workspace_id = ?`, b.ws).Scan(&nB)
	if nB != 0 {
		t.Fatal("B has A's lookups")
	}

	// Flows: an answer address from a lookup is the only destination read.
	minute := now.Add(-90 * time.Minute).Truncate(time.Minute)
	p3exec(t, db, `INSERT INTO agent_dns_lookup (workspace_id, connector_id, source, region, observed_at, src_ip, query_name, host_kind,
	                   provider, answer_ip, queries, holder_workload_id, holder_ref)
	               VALUES (?, ?, 'route53', 'us-east-1', ?, '10.0.1.30', 'api.openai.com', 'provider', 'openai', '162.159.140.245', 1, ?, 'workload:x')`,
		a.ws, a.conn, minute, rows[0].HolderWorkloadID)
	fl := &w6FlowLogs{rows: [][]cwltypes.ResultField{
		flowRow(minute, "10.0.1.30", "162.159.140.245", "eni-0123456789abcdef0", 4096, 12),
		flowRow(minute, "10.0.1.30", "8.8.8.8", "eni-0123456789abcdef0", 99, 1), // not a listed destination: dropped
	}}
	res, err := joins.CollectFlows(ctx, a.ws, a.conn, "us-east-1", fl, func(context.Context, time.Duration) error { return nil })
	if err != nil || res.Rows != 1 || res.Destinations != 1 {
		t.Fatalf("collect: %+v %v", res, err)
	}
	if !strings.Contains(fl.query, `"162.159.140.245"`) || strings.Contains(fl.query, "8.8.8.8") {
		t.Fatalf("flow query %s", fl.query)
	}
	var flows []struct {
		DstHost          string
		Provider         string
		BytesOut         int64
		HolderWorkloadID *uuid.UUID
	}
	db.Raw(`SELECT dst_host, provider, bytes_out, holder_workload_id FROM agent_flow_summary WHERE workspace_id = ?`, a.ws).Scan(&flows)
	if len(flows) != 1 || flows[0].DstHost != "api.openai.com" || flows[0].Provider != "openai" || flows[0].BytesOut != 4096 ||
		flows[0].HolderWorkloadID == nil || *flows[0].HolderWorkloadID != *rows[0].HolderWorkloadID {
		t.Fatalf("flows %+v", flows)
	}
	// B has no flow-log groups: nothing read, nothing stored.
	resB, err := joins.CollectFlows(ctx, b.ws, b.conn, "us-east-1", fl, nil)
	db.Raw(`SELECT count(*) FROM agent_flow_summary WHERE workspace_id = ?`, b.ws).Scan(&nB)
	if err != nil || resB.LogGroups != 0 || nB != 0 {
		t.Fatalf("B flows %+v %v %d", resB, err, nB)
	}
}

/* ------------------------------ usage and reconcile ------------------------- */

type w6UsageFake struct {
	t      *testing.T
	bucket time.Time
	widths []string
	keys   []string
}

func (f *w6UsageFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	switch r.URL.Path {
	case "/v1/organization/usage/completions":
		f.widths = append(f.widths, q.Get("bucket_width"))
		f.keys = append(f.keys, q["api_key_ids"]...)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"start_time": f.bucket.Unix(),
			"results": []any{map[string]any{"input_tokens": 120, "output_tokens": 30, "num_model_requests": 2,
				"api_key_id": "key_active", "project_id": "proj_1", "model": "gpt-5.1"}}}}, "has_more": false})
	case "/v1/organization/usage/embeddings":
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{}, "has_more": false})
	case "/v1/organization/costs":
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"start_time": f.bucket.Truncate(24 * time.Hour).Unix(),
			"results": []any{map[string]any{"amount": map[string]any{"value": 1.25, "currency": "usd"}, "api_key_id": "key_active",
				"project_id": "proj_1"}}}}, "has_more": false})
	default:
		f.t.Errorf("unexpected provider call %s", r.URL.Path)
		http.NotFound(w, r)
	}
}

func w6Connection(t *testing.T, db *gorm.DB, mv *memVault, ws uuid.UUID, actor uuid.UUID) uuid.UUID {
	id := uuid.New()
	ref := services.ModelProviderSecretPath(ws, id, "w6")
	_ = mv.WriteSecret(ref, map[string]interface{}{"admin_key": "sk-admin-w6-000000000000000000"})
	p3exec(t, db, `INSERT INTO model_provider_connection (id, workspace_id, provider, secret_ref, key_fingerprint, org_id, status, created_by)
		VALUES (?, ?, 'openai', ?, '...0000 sha256:000000000000', ?, 'active', ?)`, id, ws, ref, "org-"+id.String()[:8], actor)
	return id
}

func TestW6UsageMinutesAndCost(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "w6-usage-a")
	mv := newMemVault()
	t.Cleanup(services.SetModelProviderVault(mv))
	now := time.Now().UTC()
	fake := &w6UsageFake{t: t, bucket: now.Add(-20 * time.Minute).Truncate(time.Minute)}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	t.Cleanup(modelprovider.OverrideBaseURLsForTest(srv.URL+"/v1", srv.URL+"/v1"))
	conn := w6Connection(t, db, mv, a.ws, a.author)
	p3exec(t, db, `INSERT INTO model_provider_key (workspace_id, connection_id, provider_key_id, key_hint, last_used_at)
		VALUES (?, ?, 'key_active', 'sk-...abcd', now() - interval '1 hour'), (?, ?, 'key_idle', '', now() - interval '10 days')`,
		a.ws, conn, a.ws, conn)
	res, err := services.NewModelProviderService(db).SyncUsageMinutes(context.Background(), a.ws, conn)
	if err != nil || res.Rows != 1 || res.CostRows != 1 || res.Keys != 1 {
		t.Fatalf("sync: %+v %v", res, err)
	}
	if strings.Join(fake.widths, ",") != "1m" || strings.Join(fake.keys, ",") != "key_active" {
		t.Fatalf("usage asked %v for %v", fake.widths, fake.keys)
	}
	var rows []struct {
		Resolution  string
		BucketStart time.Time
		Requests    *int64
		KeyHint     string
		CostUSD     *float64
	}
	db.Raw(`SELECT resolution, bucket_start, requests, key_hint, cost_usd::float8 AS cost_usd FROM model_provider_usage_minute
	         WHERE workspace_id = ? ORDER BY resolution`, a.ws).Scan(&rows)
	if len(rows) != 2 || rows[0].Resolution != "1d" || rows[0].CostUSD == nil || *rows[0].CostUSD != 1.25 ||
		rows[1].Resolution != "1m" || !rows[1].BucketStart.Equal(fake.bucket) || rows[1].Requests == nil || *rows[1].Requests != 2 ||
		rows[1].KeyHint != "sk-...abcd" {
		t.Fatalf("rows %+v", rows)
	}
}

func TestW6UsageReconciliationLabelsAndAlerts(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "w6-rec-a")
	b := p3NewGov(t, db, "w6-rec-b")
	mv := newMemVault()
	t.Cleanup(services.SetModelProviderVault(mv))
	ctx := context.Background()
	now := time.Now().UTC()
	m := func(ago int) time.Time { return now.Add(-time.Duration(ago) * time.Minute).Truncate(time.Minute) }
	usage := func(ws, conn uuid.UUID, key string, at time.Time) {
		p3exec(t, db, `INSERT INTO model_provider_usage_minute (workspace_id, connection_id, provider, provider_key_id, bucket_start,
			resolution, requests, input_tokens, output_tokens) VALUES (?, ?, 'openai', ?, ?, '1m', 3, 100, 20)`, ws, conn, key, at)
	}
	connA := w6Connection(t, db, mv, a.ws, a.author)
	connB := w6Connection(t, db, mv, b.ws, b.author)
	gw := uuid.New()
	pk := uuid.New()
	p3exec(t, db, `INSERT INTO agent_gateway_provider_key (id, workspace_id, name, provider, secret_ref, key_fingerprint, provider_key_id,
		connection_id, created_by) VALUES (?, ?, 'obs', 'openai', 'kv/x', '...x', 'key_obs', ?, ?)`, pk, a.ws, connA, a.author)
	// observed: provider usage and a gateway call with the key in the minute.
	usage(a.ws, connA, "key_obs", m(60))
	p3exec(t, db, `INSERT INTO agent_gateway_decision (workspace_id, gateway_id, record_type, source, decided_at, subject_id, action, kind,
		resource_id, resource, decision, reason, provider_key_ref, run_id, model_version)
		VALUES (?, ?, 'outcome', 'pdp', ?, 'agk:x', 'model/invoke', 'model', 'openai/gpt-5.1', '{"provider":"openai","model":"gpt-5.1"}',
		        'allow', 'upstream_completed', ?, 'run-1', 'gpt-5.1-2026')`, a.ws, gw, m(60).Add(20*time.Second), pk)
	// outside_use: usage nobody explains.
	usage(a.ws, connA, "key_out", m(50))
	// bypass with a key: usage and an estate lookup in the minute.
	workload := uuid.New()
	usage(a.ws, connA, "key_byp", m(40))
	lookup := func(ws uuid.UUID, provider string, at time.Time, holder *uuid.UUID) {
		p3exec(t, db, `INSERT INTO agent_dns_lookup (workspace_id, connector_id, source, observed_at, src_ip, query_name, host_kind, provider,
			queries, holder_workload_id) VALUES (?, ?, 'route53', ?, '10.0.0.5', ?, 'provider', ?, 2, ?)`,
			ws, a.conn, at, "api."+provider+".com", provider, holder)
	}
	lookup(a.ws, "openai", m(40), &workload)
	// bypass without a key: estate traffic, no usage, no gateway call.
	lookup(a.ws, "anthropic", m(30), nil)
	// B: outside use of its own key.
	usage(b.ws, connB, "key_b", m(50))

	rec := services.NewUsageReconcileService(db)
	res, err := rec.ReconcileWorkspace(ctx, a.ws)
	if err != nil || res.Observed != 1 || res.OutsideUse != 1 || res.Bypass != 2 || res.AlertsOpened != 3 {
		t.Fatalf("A: %+v %v", res, err)
	}
	rows, err := rec.List(ctx, a.ws, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]services.UsageReconciliationRow{}
	for _, r := range rows {
		got[r.Provider+"/"+r.KeyRef] = r
	}
	if got["openai/key_obs"].Label != "observed" || got["openai/key_obs"].GatewayCalls != 1 ||
		got["openai/key_out"].Label != "outside_use" || got["openai/key_out"].AlertID == nil ||
		got["openai/key_byp"].Label != "bypass" || got["openai/key_byp"].DNSLookups != 2 ||
		!strings.Contains(string(got["openai/key_byp"].WorkloadIDs), workload.String()) ||
		got["anthropic/"].Label != "bypass" || len(rows) != 4 {
		t.Fatalf("labels %+v", got)
	}
	for _, r := range rows {
		if r.Label != "observed" && !strings.Contains(string(r.Evidence), `"table"`) {
			t.Fatalf("no evidence on %+v", r)
		}
	}
	if strings.Contains(string(got["openai/key_out"].Evidence), "agent_dns_lookup") ||
		!strings.Contains(string(got["openai/key_byp"].Evidence), "agent_dns_lookup") {
		t.Fatalf("evidence %s / %s", got["openai/key_out"].Evidence, got["openai/key_byp"].Evidence)
	}
	type alertRow struct {
		Detection    string
		SubjectLabel string
		Severity     string
		EventCount   int
		DedupeKey    string
	}
	alerts := func(ws uuid.UUID) []alertRow {
		var out []alertRow
		db.Raw(`SELECT detection, subject_label, severity, event_count, dedupe_key FROM agent_alert
		         WHERE workspace_id = ? AND detection LIKE 'USAGE-%' ORDER BY dedupe_key`, ws).Scan(&out)
		return out
	}
	al := alerts(a.ws)
	if len(al) != 3 || al[0].Detection != "USAGE-02" || al[0].Severity != "high" || al[0].SubjectLabel != "provider_key" ||
		al[1].Detection != "USAGE-03" || al[2].Detection != "USAGE-03" {
		t.Fatalf("alerts %+v", al)
	}
	if services.AgentAlertOutcomeClass("USAGE-02") != services.AgentAlertClassSignal ||
		services.AgentAlertOutcomeClass("USAGE-03") != services.AgentAlertClassSignal {
		t.Fatal("USAGE alerts are not signals")
	}
	var deliveries int64
	db.Raw(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = 'agent_alert.opened' AND payload->>'detection' LIKE 'USAGE-%'`, a.ws).Scan(&deliveries)
	if deliveries != 3 {
		t.Fatalf("alert opened events %d", deliveries)
	}
	// Running again changes nothing.
	if res, err = rec.ReconcileWorkspace(ctx, a.ws); err != nil || res.AlertsOpened != 0 {
		t.Fatalf("rerun %+v %v", res, err)
	}
	if al2 := alerts(a.ws); len(al2) != 3 || al2[0].EventCount != 1 {
		t.Fatalf("rerun alerts %+v", al2)
	}
	// A gateway call later explains the outside use: the label moves to observed.
	pk2 := uuid.New()
	p3exec(t, db, `INSERT INTO agent_gateway_provider_key (id, workspace_id, name, provider, secret_ref, key_fingerprint, provider_key_id,
		connection_id, created_by) VALUES (?, ?, 'out', 'openai', 'kv/y', '...y', 'key_out', ?, ?)`, pk2, a.ws, connA, a.author)
	p3exec(t, db, `INSERT INTO agent_gateway_decision (workspace_id, gateway_id, record_type, source, decided_at, subject_id, action, kind,
		resource_id, resource, decision, reason, provider_key_ref)
		VALUES (?, ?, 'outcome', 'pdp', ?, 'agk:x', 'model/invoke', 'model', 'openai/gpt-5.1', '{"provider":"openai"}', 'allow',
		        'upstream_completed', ?)`, a.ws, gw, m(50).Add(5*time.Second), pk2)
	if _, err = rec.ReconcileWorkspace(ctx, a.ws); err != nil {
		t.Fatal(err)
	}
	rows, _ = rec.List(ctx, a.ws, "outside_use", nil, nil)
	if len(rows) != 0 {
		t.Fatalf("still outside use: %+v", rows)
	}
	// B sees only its own.
	if res, err = rec.ReconcileWorkspace(ctx, b.ws); err != nil || res.OutsideUse != 1 || res.Bypass != 0 || res.Observed != 0 {
		t.Fatalf("B %+v %v", res, err)
	}
	rowsB, _ := rec.List(ctx, b.ws, "", nil, nil)
	if len(rowsB) != 1 || rowsB[0].KeyRef != "key_b" {
		t.Fatalf("B rows %+v", rowsB)
	}
	if al := alerts(b.ws); len(al) != 1 || al[0].Detection != "USAGE-02" {
		t.Fatalf("B alerts %+v", al)
	}
}

func TestW6RemoveGatewayRulesForAgent(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "w6-rm-a")
	b := p3NewGov(t, db, "w6-rm-b")
	p3Audit(t, db, a.ws, b.ws)
	api := agwNewAPI(t, db)
	all := "governance:read governance:enforce"
	tokA := api.token(a.ws, a.author, a.authorMember, all)
	tokB := api.token(b.ws, b.author, b.authorMember, all)
	for _, tok := range []string{tokA, tokB} {
		if code, out := agwAdmin(t, api, "POST", "/gateway-agent-keys", tok, map[string]any{"name": "retiring", "client_id": "retiring-agent",
			"spiffe_id": "spiffe://acme/retiring"}); code != http.StatusCreated {
			t.Fatalf("issue %d %v", code, out)
		}
		if code, out := agwAdmin(t, api, "POST", "/tool-policies", tok, map[string]any{"name": "retiring-allow", "effect": "allow",
			"kind": "mcp_tool", "subject": map[string]any{"client_id": "retiring-agent"}, "target": map[string]any{"server": "s"}}); code != http.StatusCreated {
			t.Fatalf("policy %d %v", code, out)
		}
	}
	svc := services.AgentGatewayServiceFor(db)
	res, err := svc.RemoveGatewayRulesForAgent(context.Background(), a.ws, "retiring-agent")
	if err != nil || res.AgentKeysRevoked != 1 || res.PoliciesDisabled != 1 {
		t.Fatalf("remove %+v %v", res, err)
	}
	var live int64
	db.Raw(`SELECT count(*) FROM agent_gateway_agent_key WHERE workspace_id = ? AND revoked_at IS NULL`, b.ws).Scan(&live)
	db.Raw(`SELECT count(*) + ? FROM agent_tool_policy WHERE workspace_id = ? AND enabled`, live, b.ws).Scan(&live)
	if live != 2 {
		t.Fatalf("B's key and policy touched: %d", live)
	}
	if res, err = svc.RemoveGatewayRulesForAgent(context.Background(), a.ws, "retiring-agent"); err != nil || res.AgentKeysRevoked != 0 || res.PoliciesDisabled != 0 {
		t.Fatalf("second remove %+v %v", res, err)
	}
}
