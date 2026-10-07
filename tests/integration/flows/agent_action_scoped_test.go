//go:build integration

package flows

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
)

// Agent action guard: a request lives in the evaluating user's workspace.
// Another workspace can neither poll it nor decide it, and the owning
// workspace's poll, approval and audit trail work on the scoped layer.
func Test_AgentAction_ScopedToWorkspace(t *testing.T) {
	env := testsupport.Get(t)
	a, b := TwoTenants(t)
	// Never auto-approve in A, single approval.
	mustExec(t, `INSERT INTO agent_guard_settings (id, workspace_id, auto_approve_below, require_approval_above,
	               require_multi_approval_above, require_biometric, created_at, updated_at)
	             VALUES ($1, $2, 0, 0, 1000, false, 0, 0)
	             ON CONFLICT (workspace_id) DO UPDATE SET auto_approve_below = 0, require_approval_above = 0,
	               require_multi_approval_above = 1000, require_biometric = false`, uuid.New(), a.WS.WorkspaceID)

	const base = "/authsec/uflow/agent/actions"
	w := env.Do("POST", base+"/evaluate", map[string]interface{}{
		"client_id":  a.WS.ClientID.String(),
		"agent_id":   "agent-" + emailSafeNonce(),
		"action":     "TRANSFER_MONEY",
		"resource":   "billing.invoices",
		"user_email": a.EndUser.Email,
	}, a.EndUserToken)
	assertStatus(t, w, http.StatusOK)
	var ev struct {
		ActionReqID string `json:"action_req_id"`
		Status      string `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &ev); err != nil || ev.ActionReqID == "" || ev.Status != "pending" {
		t.Fatalf("evaluate: want a pending request, got %s", w.Body.String())
	}
	poll := base + "/status?action_req_id=" + url.QueryEscape(ev.ActionReqID)

	// B cannot see or decide A's request.
	w = env.Do("GET", poll, nil, b.EndUserToken)
	if !strings.Contains(w.Body.String(), "not_found") {
		t.Fatalf("B polled A's request: %s", w.Body.String())
	}
	assertCount(t, 0, "agent_action_requests", "action_req_id = ? AND last_polled_at IS NOT NULL", ev.ActionReqID)
	w = env.Do("POST", base+"/respond", map[string]interface{}{"action_req_id": ev.ActionReqID, "approved": true}, b.EndUserToken)
	if strings.Contains(w.Body.String(), `"success":true`) {
		t.Fatalf("B decided A's request: %s", w.Body.String())
	}
	assertCount(t, 0, "agent_action_decisions d JOIN agent_action_requests r ON r.id = d.action_request_id", "r.action_req_id = ?", ev.ActionReqID)

	// A polls it pending, approves it, and polls it approved.
	w = env.Do("GET", poll, nil, a.EndUserToken)
	if !strings.Contains(w.Body.String(), `"pending"`) {
		t.Fatalf("A's poll: %s", w.Body.String())
	}
	w = env.Do("POST", base+"/respond", map[string]interface{}{"action_req_id": ev.ActionReqID, "approved": true}, a.EndUserToken)
	if !strings.Contains(w.Body.String(), `"success":true`) {
		t.Fatalf("A's approval: %d %s", w.Code, w.Body.String())
	}
	w = env.Do("GET", poll, nil, a.EndUserToken)
	if !strings.Contains(w.Body.String(), `"approved"`) {
		t.Fatalf("A's poll after approval: %s", w.Body.String())
	}
	assertCount(t, 1, "agent_action_audit_log", "workspace_id = ? AND final_status = 'approved'", a.WS.WorkspaceID)
}
