package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/agentcore"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/services"
)

// AS-138: every R2 and R3 mutation route, called over HTTP as a workspace
// member, writes its audit_events row. The R1a walker (TestP3T320) cannot
// reach them -- they need an AWS role with an R2 binding, approvers distinct
// from requesters, and a runtime policy with a held decision -- so this walks
// them on the access-policy lab, which has all of that.
func TestP3R2R3RoutesAudited(t *testing.T) {
	l := newAPLab(t)
	p3R23Gates(t, l.db)
	p3Audit(t, l.db, l.ws)
	api := p3NewOwnersAPI(t, l.db)
	const prefix = "/api/iga/v1/policy"
	tokenOf := func(perms ...string) string {
		user := l.memberWith(perms...)
		var mem string
		if err := l.db.Raw(`SELECT id::text FROM workspace_memberships WHERE workspace_id = ? AND user_id = ?`, l.ws, user).Row().Scan(&mem); err != nil {
			t.Fatal(err)
		}
		scopes := ""
		for i, p := range perms {
			if i > 0 {
				scopes += " "
			}
			scopes += p
		}
		return api.token(l.ws, user, uuid.MustParse(mem), scopes)
	}
	author := tokenOf("governance:read", "governance:author", "governance:enforce")
	approver := tokenOf("governance:read", "governance:approve", "governance:grant")
	call := func(tok, method, path string, body any) map[string]any {
		t.Helper()
		code, resp := api.call(method, path, tok, body)
		if code < 200 || code > 299 {
			t.Fatalf("%s %s: %d %v", method, path, code, resp)
		}
		p3WaitAudit(t, l.db, l.ws, method, prefix+path)
		return resp
	}
	reason := map[string]any{"reason": "audit walk"}

	// R2 temporary grants: request, approve, revoke; request another, reject.
	role := l.role("AuditedGrantRole")
	grant := func(action string) string {
		resp := call(author, http.MethodPost, "/temporary-grants", map[string]any{"identity_account_id": role.String(),
			"actions": []string{action}, "resources": []string{"arn:aws:s3:::acme/*"}, "duration_minutes": 60, "reason": "audit walk"})
		return digs(resp, "data", "id")
	}
	g1 := grant("s3:GetObject")
	call(approver, http.MethodPost, "/temporary-grants/"+g1+"/approve", reason)
	call(author, http.MethodPost, "/temporary-grants/"+g1+"/revoke", reason)
	g2 := grant("s3:PutObject")
	call(approver, http.MethodPost, "/temporary-grants/"+g2+"/reject", reason)

	// R2 session revocations: request, approve, lift; request another, reject.
	revoke := func(name string) string {
		r := l.role(name)
		resp := call(author, http.MethodPost, "/session-revocations", map[string]any{"identity_account_id": r.String(), "reason": "audit walk"})
		return digs(resp, "data", "id")
	}
	r1 := revoke("AuditedRevokedRole")
	call(approver, http.MethodPost, "/session-revocations/"+r1+"/approve", reason)
	call(author, http.MethodPost, "/session-revocations/"+r1+"/revoke", reason)
	r2 := revoke("AuditedRejectedRole")
	call(approver, http.MethodPost, "/session-revocations/"+r2+"/reject", reason)

	// R3 runtime policies: create, approve v1; v2 rejected; v3 withdrawn.
	const spiffe = "spiffe://audit.test/agent"
	gateway := "arn:aws:bedrock-agentcore:us-east-1:" + testAccount + ":gateway/gw-audit"
	intent := func(tool string) json.RawMessage {
		return json.RawMessage(`{"kind":"runtime_controls","subjects":[{"spiffe_id":"` + spiffe + `"}],
			"tools":[{"tool":"lookup"},{"tool":"` + tool + `","require_approval":true,"approval_reason":"needs a human"}],
			"gateways":[{"gateway_arn":"` + gateway + `","policy_engine_id":"pe-audit"}]}`)
	}
	resp := call(author, http.MethodPost, "/runtime/policies", map[string]any{"name": "audited runtime", "intent": intent("search")})
	pol := digs(resp, "data", "id")
	hashOf := func(no string) string {
		_, got := api.call(http.MethodGet, "/runtime/policies/"+pol, author, nil)
		raw, _ := json.Marshal(got)
		var v struct {
			Data struct {
				Versions []struct {
					VersionNo  int    `json:"version_no"`
					IntentHash string `json:"intent_hash"`
				} `json:"versions"`
			} `json:"data"`
		}
		_ = json.Unmarshal(raw, &v)
		for _, x := range v.Data.Versions {
			if x.VersionNo == atoiT(t, no) {
				return x.IntentHash
			}
		}
		t.Fatalf("no version %s of %s", no, pol)
		return ""
	}
	call(approver, http.MethodPost, "/runtime/policies/"+pol+"/versions/1/approve", map[string]any{"intent_hash": hashOf("1")})
	call(author, http.MethodPost, "/runtime/policies/"+pol+"/versions", map[string]any{"base_version_no": 1, "intent": intent("fetch")})
	call(approver, http.MethodPost, "/runtime/policies/"+pol+"/versions/2/reject", map[string]any{"intent_hash": hashOf("2"), "reason": "no"})
	call(author, http.MethodPost, "/runtime/policies/"+pol+"/versions", map[string]any{"base_version_no": 2, "intent": intent("browse")})
	call(author, http.MethodPost, "/runtime/policies/"+pol+"/versions/3/withdraw", reason)

	// AgentCore push of the approved version (a fake AgentCore; production
	// installs none, DECISION R3-11).
	services.SetRuntimeAgentCoreFactory(func(context.Context, uuid.UUID, string, string) (agentcore.Client, error) {
		return agentcore.NewFake(), nil
	})
	t.Cleanup(func() { services.SetRuntimeAgentCoreFactory(nil) })
	call(author, http.MethodPost, "/runtime/policies/"+pol+"/agentcore/push", map[string]any{"gateway_arn": gateway})

	// R3 holds: an agent's call that needs a human, approved; another rejected.
	svc := services.NewGovR3(l.db)
	ag := services.RuntimeAgent{SpiffeID: spiffe, HumanUserID: l.user}
	hold := func(key string) string {
		d, err := svc.Decide(context.Background(), l.ws, ag, services.RuntimeDecideRequest{Tool: "search", IdempotencyKey: key,
			Arguments: json.RawMessage(`{"q":"` + key + `"}`)})
		if err != nil || d.Decision != igagov.RuntimeHold || d.Hold == nil {
			t.Fatalf("held decision: %+v %v", d, err)
		}
		return d.Hold.ID.String()
	}
	call(approver, http.MethodPost, "/runtime/holds/"+hold("h-1")+"/approve", reason)
	call(approver, http.MethodPost, "/runtime/holds/"+hold("h-2")+"/reject", reason)

	// R3 settings, routing proofs and broker roles.
	call(author, http.MethodPut, "/runtime/settings", map[string]any{"retention_days": 30})
	resp = call(author, http.MethodPost, "/runtime/routing-proofs", map[string]any{
		"gateway_arn": "arn:aws:bedrock-agentcore:us-east-1:" + testAccount + ":gateway/gw-audit", "method": "customer_attestation",
		"statement": "Only the gateway reaches the tools."})
	call(author, http.MethodPost, "/runtime/routing-proofs/"+digs(resp, "data", "id")+"/revoke", reason)
	resp = call(author, http.MethodPost, "/runtime/broker-roles", map[string]any{"connector_id": l.conn.ID.String(),
		"role_arn": "arn:aws:iam::" + testAccount + ":role/AuditedBroker"})
	call(author, http.MethodPost, "/runtime/broker-roles/"+digs(resp, "data", "id")+"/disable", reason)
}

func atoiT(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Fatalf("not a number: %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n
}
