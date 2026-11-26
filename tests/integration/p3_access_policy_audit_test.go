package integration

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Every access-policy mutation route, called over HTTP as the console calls
// it, answers 2xx and writes an audit_events row for its request (CLAUDE.md
// rule 11). The R1a walker (TestP3T320EveryMutationAudited) cannot run these
// (they need a fake AWS account with a template v2 binding), so it lists them
// as audited here.
func TestAccessPolicyRoutesAudited(t *testing.T) {
	l := newAPLab(t)
	p3Audit(t, l.db, l.ws)
	api := p3NewOwnersAPI(t, l.db)
	role := l.role("ApAuditedRole")
	admin := l.memberWith("governance:read", "governance:enforce")
	var memID string
	if err := l.db.Raw(`SELECT id::text FROM workspace_memberships WHERE workspace_id = ? AND user_id = ?`, l.ws, admin).Row().Scan(&memID); err != nil {
		t.Fatal(err)
	}
	mem := uuid.MustParse(memID)
	tok := api.token(l.ws, admin, mem, "governance:read governance:enforce")
	const prefix = "/api/iga/v1/policy"
	end := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	intent := func(access ...string) map[string]any {
		return map[string]any{"effect": "block", "resource": map[string]any{"resource_id": l.bucket.String()},
			"roles": []map[string]any{{"identity_account_id": role.String()}}, "access": access, "ends_at": end}
	}
	call := func(method, path string, body any) map[string]any {
		t.Helper()
		code, resp := api.call(method, path, tok, body) // the helper adds the prefix
		if code < 200 || code > 299 {
			t.Fatalf("%s %s: %d %v", method, path, code, resp)
		}
		return resp
	}
	audited := func(method, route string) {
		t.Helper()
		p3WaitAudit(t, l.db, l.ws, method, prefix+route)
	}

	body := intent("read")
	body["name"], body["reason"] = "audited policy", "walker"
	resp := call(http.MethodPost, "/access-policies", body)
	id := digs(resp, "data", "id")
	audited(http.MethodPost, "/access-policies")
	pid := uuid.MustParse(id)
	l.run(pid)

	edit := intent("read", "write")
	edit["name"], edit["reason"], edit["base_version_no"] = "audited policy", "widen", 1
	call(http.MethodPost, "/access-policies/"+id+"/versions", edit)
	audited(http.MethodPost, "/access-policies/"+id+"/versions")
	l.run(pid)

	for _, step := range []string{"pause", "resume", "end"} {
		call(http.MethodPost, "/access-policies/"+id+"/"+step, map[string]any{"reason": "walker " + step})
		audited(http.MethodPost, "/access-policies/"+id+"/"+step)
		l.run(pid)
	}

	call(http.MethodDelete, "/access-policies/"+id, nil)
	audited(http.MethodDelete, "/access-policies/"+id)
}
