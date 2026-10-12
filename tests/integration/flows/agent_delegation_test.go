//go:build integration

package flows

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/authsec-ai/authsec/internal/testsupport/fakes"
	"github.com/google/uuid"
)

// seedAIAgent inserts an active ai_agent application (resource_servers row)
// in the workspace and returns its id.
func seedAIAgent(t *testing.T, ws *WorkspaceScenario, n string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	mustExec(t, `INSERT INTO resource_servers (id, workspace_id, name, public_base_url, resource_uri,
			application_type, agent_type, status, state)
		VALUES (?, ?, ?, ?, ?, 'ai_agent', 'mcp-agent', 'ready', 'ready')`,
		id, ws.WorkspaceID, "agent-"+n, "https://agent-"+n+".example", "https://agent-"+n+".example/mcp")
	return id
}

// AS-045: a delegation policy that names an agent (client_id) of the caller's
// workspace is created; another workspace's agent is not found.
func Test_DelegationPolicy_WithAgentClientID(t *testing.T) {
	a, b := TwoTenants(t)
	n := emailSafeNonce()
	agentA := seedAIAgent(t, a.WS, n+"a")
	agentB := seedAIAgent(t, b.WS, n+"b")
	env := testsupport.Get(t)

	w := env.Do(http.MethodPost, "/authsec/uflow/delegation-policies", map[string]interface{}{
		"role_name":           "admin",
		"agent_type":          "mcp-agent",
		"client_id":           agentA.String(),
		"allowed_permissions": []string{"external-service:read"},
	}, a.AdminToken)
	if w.Code != http.StatusCreated {
		t.Fatalf("create with own agent: want 201, got %d (%s)", w.Code, w.Body.String())
	}
	AssertRowCount(t, "delegation_policies", "client_id", agentA, 1)

	// Updating it to another workspace's agent is refused and leaves it as is.
	var policyID string
	if err := config.DB.Raw(`SELECT id::text FROM delegation_policies WHERE client_id = ?`, agentA).Scan(&policyID).Error; err != nil {
		t.Fatal(err)
	}
	AssertCrossTenantNotFound(t, http.MethodPut, "/authsec/uflow/delegation-policies/"+policyID,
		map[string]interface{}{"client_id": agentB.String()}, a.AdminToken)
	AssertRowCount(t, "delegation_policies", "client_id", agentA, 1)

	// Creating one for B's agent from A is not found, and writes nothing.
	AssertCrossTenantNotFound(t, http.MethodPost, "/authsec/uflow/delegation-policies", map[string]interface{}{
		"role_name":  "viewer",
		"agent_type": "mcp-agent",
		"client_id":  agentB.String(),
	}, a.AdminToken)
	AssertRowCount(t, "delegation_policies", "client_id", agentB, 0)
}

// AS-046: an ai_agent created through the API carries an agent_type, so
// provision-identity gets past its precondition (it then needs the embedded
// SPIRE control plane, which is off here: 503, not 400).
func Test_AIAgent_CreateSetsAgentType(t *testing.T) {
	env := testsupport.Get(t)
	ws := seedWorkspace(t, emailSafeNonce())
	tok := env.MustAsAdmin(ws.AdminUserID, ws.WorkspaceID, ws.AdminEmail)
	fakeMCP := fakes.NewMCPResourceServer(mcpFlowTools, mcpFlowScopes)
	defer fakeMCP.Close()

	w := env.Do(http.MethodPost, "/authsec/applications", map[string]interface{}{
		"name":             fmt.Sprintf("agent-%s", nonce(t)),
		"public_base_url":  fakeMCP.URL(),
		"application_type": "ai_agent",
	}, tok)
	if w.Code != http.StatusCreated {
		t.Fatalf("create ai_agent: %d %s", w.Code, w.Body.String())
	}
	id, _ := parseBody(t, w)["id"].(string)
	waitForScanIdle(t, id)
	if got := scalar(t, `SELECT agent_type FROM resource_servers WHERE id = ?`, id); got != "mcp-agent" {
		t.Fatalf("agent_type = %q, want mcp-agent", got)
	}

	w = env.Do(http.MethodPost, "/authsec/uflow/admin/agents/"+id+"/provision-identity",
		map[string]interface{}{"parent_id": "spiffe://example.org/agent"}, tok)
	if w.Code == http.StatusBadRequest {
		t.Fatalf("provision-identity still refuses the agent: %s", w.Body.String())
	}
	assertStatus(t, w, http.StatusServiceUnavailable)

	// An MCP server gets no agent_type.
	w = env.Do(http.MethodPost, "/authsec/applications", map[string]interface{}{
		"name":            fmt.Sprintf("mcp-%s", nonce(t)),
		"public_base_url": fakeMCP.URL() + "/other",
	}, tok)
	if w.Code != http.StatusCreated {
		t.Fatalf("create mcp_server: %d %s", w.Code, w.Body.String())
	}
	mcpID, _ := parseBody(t, w)["id"].(string)
	waitForScanIdle(t, mcpID)
	if got := scalar(t, `SELECT agent_type FROM resource_servers WHERE id = ?`, mcpID); got != "" {
		t.Fatalf("mcp_server agent_type = %q, want NULL", got)
	}
}
