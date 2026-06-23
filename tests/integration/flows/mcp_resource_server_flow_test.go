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

// tools and scopes used by the fake MCP server across all MCP flow tests.
var (
	mcpFlowTools  = []map[string]interface{}{{"name": "tool1", "description": "A tool"}}
	mcpFlowScopes = []string{"read:data"}
)

// Test_MCP_RegisterDiscoverActivate exercises the full happy-path for MCP
// resource server registration, rescan (tool/scope discovery), and scope-matrix
// retrieval (§5.3 of the agent identity plan).
func Test_MCP_RegisterDiscoverActivate(t *testing.T) {
	env := testsupport.Get(t)

	// Seed a workspace with an admin user.
	ws, err := SeedWorkspaceWithAdmin(config.DB, nonce(t))
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}

	// Start the fake MCP resource server.
	fakeMCP := fakes.NewMCPResourceServer(mcpFlowTools, mcpFlowScopes)
	defer fakeMCP.Close()

	// Mint an admin token for the seeded workspace admin.
	adminTok := env.MustAsAdmin(ws.AdminUserID, ws.WorkspaceID, ws.AdminEmail)

	// POST /authsec/applications — register the MCP resource server.
	rsName := fmt.Sprintf("test-rs-%s", nonce(t))
	createBody := map[string]interface{}{
		"name":                rsName,
		"public_base_url":     fakeMCP.URL(),
		"protected_base_path": "/mcp",
	}
	createResp := env.Do(http.MethodPost, "/authsec/applications", createBody, adminTok)
	if createResp.Code != http.StatusCreated {
		t.Fatalf("POST /authsec/applications: want 201, got %d; body: %s",
			createResp.Code, createResp.Body.String())
	}

	var createResult map[string]interface{}
	if code := testsupport.JSON(t, createResp, &createResult); code != http.StatusCreated {
		t.Fatalf("decode create response: status %d", code)
	}

	// Extract rs_id from the response.
	rsIDRaw, ok := createResult["id"]
	if !ok {
		// Some handlers nest under a "resource_server" key.
		if nested, hasNested := createResult["resource_server"].(map[string]interface{}); hasNested {
			rsIDRaw = nested["id"]
			ok = true
		}
	}
	if !ok || rsIDRaw == nil {
		t.Fatalf("POST /authsec/applications response missing 'id' field; body: %v", createResult)
	}
	rsIDStr, _ := rsIDRaw.(string)
	if _, err := uuid.Parse(rsIDStr); err != nil {
		t.Fatalf("rs_id %q is not a valid UUID: %v", rsIDStr, err)
	}

	// Wait for the background DiscoverAndSync goroutine (triggered by Create) to
	// release the scan lock before calling rescan. Without this the rescan gets 409
	// "rescan already in progress".
	waitForScanIdle(t, rsIDStr)

	// POST /authsec/applications/:id/rescan — trigger discovery.
	rescanPath := fmt.Sprintf("/authsec/applications/%s/rescan", rsIDStr)
	rescanResp := env.Do(http.MethodPost, rescanPath, nil, adminTok)
	if rescanResp.Code != http.StatusOK {
		t.Fatalf("POST %s: want 200, got %d; body: %s",
			rescanPath, rescanResp.Code, rescanResp.Body.String())
	}

	// GET /authsec/applications/:id/scope-matrix — check scope matrix.
	matrixPath := fmt.Sprintf("/authsec/applications/%s/scope-matrix", rsIDStr)
	matrixResp := env.Do(http.MethodGet, matrixPath, nil, adminTok)
	if matrixResp.Code != http.StatusOK {
		t.Fatalf("GET %s: want 200, got %d; body: %s",
			matrixPath, matrixResp.Code, matrixResp.Body.String())
	}
}

// Test_MCP_NonAdminCreate asserts that a non-admin user cannot register a new
// MCP resource server (expects HTTP 403).
func Test_MCP_NonAdminCreate(t *testing.T) {
	env := testsupport.Get(t)

	// Seed a workspace and pick up a non-admin user.
	ws, err := SeedWorkspaceWithAdmin(config.DB, nonce(t))
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin: %v", err)
	}
	endUser, err := AddEndUserWithRole(config.DB, ws, nonce(t))
	if err != nil {
		t.Fatalf("AddEndUserWithRole: %v", err)
	}

	// Mint a token for the non-admin user (no "admin" role).
	userTok := env.MustAsUser(endUser.UserID, ws.WorkspaceID, endUser.Email)

	createBody := map[string]interface{}{
		"name":                "forbidden-rs-" + nonce(t),
		"public_base_url":     "http://localhost:9999",
		"protected_base_path": "/mcp",
	}
	resp := env.Do(http.MethodPost, "/authsec/applications", createBody, userTok)
	if resp.Code != http.StatusForbidden {
		t.Errorf("POST /authsec/applications with non-admin token: want 403, got %d; body: %s",
			resp.Code, resp.Body.String())
	}
}

// Test_MCP_CrossWorkspaceRS asserts that an admin from workspace B cannot
// access a resource server that belongs to workspace A (expects HTTP 404).
func Test_MCP_CrossWorkspaceRS(t *testing.T) {
	env := testsupport.Get(t)

	// Seed workspace A and register a resource server inside it.
	wsA, err := SeedWorkspaceWithAdmin(config.DB, nonce(t)+"a")
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin (A): %v", err)
	}

	fakeMCP := fakes.NewMCPResourceServer(mcpFlowTools, mcpFlowScopes)
	defer fakeMCP.Close()

	adminTokA := env.MustAsAdmin(wsA.AdminUserID, wsA.WorkspaceID, wsA.AdminEmail)

	createBody := map[string]interface{}{
		"name":                "rs-wsa-" + nonce(t),
		"public_base_url":     fakeMCP.URL(),
		"protected_base_path": "/mcp",
	}
	createResp := env.Do(http.MethodPost, "/authsec/applications", createBody, adminTokA)
	if createResp.Code != http.StatusCreated {
		t.Fatalf("POST /authsec/applications (workspace A): want 201, got %d; body: %s",
			createResp.Code, createResp.Body.String())
	}

	var createResult map[string]interface{}
	testsupport.JSON(t, createResp, &createResult)

	rsIDRaw, ok := createResult["id"]
	if !ok {
		if nested, hasNested := createResult["resource_server"].(map[string]interface{}); hasNested {
			rsIDRaw = nested["id"]
			ok = true
		}
	}
	if !ok || rsIDRaw == nil {
		t.Fatalf("could not extract rs_id from workspace A create response; body: %v", createResult)
	}
	wsARSID, _ := rsIDRaw.(string)

	// Seed workspace B and have its admin try to access workspace A's RS.
	wsB, err := SeedWorkspaceWithAdmin(config.DB, nonce(t)+"b")
	if err != nil {
		t.Fatalf("SeedWorkspaceWithAdmin (B): %v", err)
	}
	adminTokB := env.MustAsAdmin(wsB.AdminUserID, wsB.WorkspaceID, wsB.AdminEmail)

	matrixPath := fmt.Sprintf("/authsec/applications/%s/scope-matrix", wsARSID)
	resp := env.Do(http.MethodGet, matrixPath, nil, adminTokB)
	if resp.Code != http.StatusNotFound {
		t.Errorf("GET %s with workspace B admin: want 404, got %d; body: %s",
			matrixPath, resp.Code, resp.Body.String())
	}
}
