//go:build integration

package flows

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/sessiontoken"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
)

const agentActionsBase = "/authsec/uflow/agent/actions"

// agentActionSingleApproval makes every evaluated action in ws pending for a
// single approval.
func agentActionSingleApproval(t *testing.T, ws uuid.UUID) {
	t.Helper()
	mustExec(t, `INSERT INTO agent_guard_settings (id, workspace_id, auto_approve_below, require_approval_above,
	               require_multi_approval_above, require_biometric, created_at, updated_at)
	             VALUES ($1, $2, 0, 0, 1000, false, 0, 0)
	             ON CONFLICT (workspace_id) DO UPDATE SET auto_approve_below = 0, require_approval_above = 0,
	               require_multi_approval_above = 1000, require_biometric = false`, uuid.New(), ws)
}

// evaluatePending evaluates an action with token and returns its pending id.
func evaluatePending(t *testing.T, a *Tenant, token string) string {
	t.Helper()
	w := testsupport.Get(t).Do("POST", agentActionsBase+"/evaluate", map[string]interface{}{
		"client_id":  a.WS.ClientID.String(),
		"agent_id":   "agent-" + emailSafeNonce(),
		"action":     "TRANSFER_MONEY",
		"resource":   "billing.invoices",
		"user_email": a.EndUser.Email,
	}, token)
	assertStatus(t, w, http.StatusOK)
	var ev struct {
		ActionReqID string `json:"action_req_id"`
		Status      string `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &ev); err != nil || ev.ActionReqID == "" || ev.Status != "pending" {
		t.Fatalf("evaluate: want a pending request, got %s", w.Body.String())
	}
	return ev.ActionReqID
}

func agentActionDecisions(t *testing.T, actionReqID string) int64 {
	t.Helper()
	return countWhere(t, "agent_action_decisions d JOIN agent_action_requests r ON r.id = d.action_request_id", "r.action_req_id = ?", actionReqID)
}

// Agent action guard: a request lives in the evaluating user's workspace.
// Another workspace can neither poll it nor decide it (404), and the owning
// workspace's poll, approval and audit trail work on the scoped layer.
func Test_AgentAction_ScopedToWorkspace(t *testing.T) {
	env := testsupport.Get(t)
	a, b := TwoTenants(t)
	agentActionSingleApproval(t, a.WS.WorkspaceID)

	id := evaluatePending(t, a, a.EndUserToken)
	poll := agentActionsBase + "/status?action_req_id=" + url.QueryEscape(id)

	// B cannot see or decide A's request.
	w := env.Do("GET", poll, nil, b.EndUserToken)
	if !strings.Contains(w.Body.String(), "not_found") {
		t.Fatalf("B polled A's request: %s", w.Body.String())
	}
	assertCount(t, 0, "agent_action_requests", "action_req_id = ? AND last_polled_at IS NOT NULL", id)
	for _, tok := range []string{b.EndUserToken, b.AdminToken} {
		w = env.Do("POST", agentActionsBase+"/respond", map[string]interface{}{"action_req_id": id, "approved": true}, tok)
		assertStatus(t, w, http.StatusNotFound)
	}
	if n := agentActionDecisions(t, id); n != 0 {
		t.Fatalf("B's response recorded %d decisions", n)
	}

	// A's principal polls it pending, approves it, and polls it approved.
	w = env.Do("GET", poll, nil, a.EndUserToken)
	if !strings.Contains(w.Body.String(), `"pending"`) {
		t.Fatalf("A's poll: %s", w.Body.String())
	}
	w = env.Do("POST", agentActionsBase+"/respond", map[string]interface{}{"action_req_id": id, "approved": true, "biometric_verified": true}, a.EndUserToken)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"success":true`) {
		t.Fatalf("A's approval: %d %s", w.Code, w.Body.String())
	}
	w = env.Do("GET", poll, nil, a.EndUserToken)
	if !strings.Contains(w.Body.String(), `"approved"`) {
		t.Fatalf("A's poll after approval: %s", w.Body.String())
	}
	assertCount(t, 1, "agent_action_audit_log", "workspace_id = ? AND final_status = 'approved'", a.WS.WorkspaceID)
	// The client's biometric_verified is its own claim: never recorded as verified.
	assertCount(t, 0, "agent_action_decisions d JOIN agent_action_requests r ON r.id = d.action_request_id",
		"r.action_req_id = ? AND d.biometric_verified", id)
}

// F3: deciding an agent action takes the principal the action is on behalf
// of, or a member holding governance:approve, signed in as a person. Another
// member, and the agent's own SDK token, are refused and record nothing.
func Test_AgentAction_RespondRequiresPrincipalOrApprover(t *testing.T) {
	env := testsupport.Get(t)
	a, _ := TwoTenants(t)
	agentActionSingleApproval(t, a.WS.WorkspaceID)

	// The agent evaluates with the principal's SDK token.
	agentTok, err := testsupport.MintClassToken(sessiontoken.SDK, testsupport.UserTokenParams{
		UserID: a.EndUser.UserID, WorkspaceID: a.WS.WorkspaceID, Email: a.EndUser.Email})
	if err != nil {
		t.Fatal(err)
	}
	id := evaluatePending(t, a, agentTok)
	respond := func(tok string, approved bool) *httptest.ResponseRecorder {
		return env.Do("POST", agentActionsBase+"/respond", map[string]interface{}{
			"action_req_id": id, "approved": approved, "biometric_verified": true}, tok)
	}

	// The agent cannot approve (or deny) its own action.
	assertStatus(t, respond(agentTok, true), http.StatusForbidden)
	assertStatus(t, respond(agentTok, false), http.StatusForbidden)

	// Another member of the workspace, without governance:approve.
	other, err := AddEndUserWithRole(config.DB, a.WS, emailSafeNonce()+"o")
	if err != nil {
		t.Fatal(err)
	}
	otherTok := env.MustAsUser(other.UserID, a.WS.WorkspaceID, other.Email)
	assertStatus(t, respond(otherTok, true), http.StatusForbidden)
	assertStatus(t, respond(otherTok, false), http.StatusForbidden)

	// The workspace admin, before holding governance:approve.
	assertStatus(t, respond(a.AdminToken, true), http.StatusForbidden)
	if n := agentActionDecisions(t, id); n != 0 {
		t.Fatalf("refused callers recorded %d decisions", n)
	}
	assertCount(t, 1, "agent_action_requests", "action_req_id = ? AND status = 'pending'", id)

	// Holding governance:approve, the admin decides.
	mustExec(t, `INSERT INTO role_permissions (role_id, permission_id)
	             SELECT $1, id FROM permissions WHERE resource = 'governance' AND action = 'approve' AND workspace_id IS NULL
	             ON CONFLICT DO NOTHING`, a.WS.AdminRoleID)
	w := respond(a.AdminToken, true)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"success":true`) {
		t.Fatalf("approver's approval: %d %s", w.Code, w.Body.String())
	}
	assertCount(t, 1, "agent_action_requests", "action_req_id = ? AND status = 'approved'", id)
	assertCount(t, 0, "agent_action_decisions d JOIN agent_action_requests r ON r.id = d.action_request_id",
		"r.action_req_id = ? AND d.biometric_verified", id)
}
