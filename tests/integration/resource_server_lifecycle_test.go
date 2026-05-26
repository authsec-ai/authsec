//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// ── Mock MCP server helpers ───────────────────────────────────────────────────

// mcpServerConfig controls what the mock MCP server returns.
type mcpServerConfig struct {
	// PRM
	prmEnabled      bool
	scopesSupported []string

	// Tools
	tools []map[string]string // []{"name":…,"description":…}

	// If true, tools/list returns an RPC error (simulates hard failure)
	toolsListError bool
}

// newMockMCPServer starts a test HTTP server that responds to MCP protocol messages.
// The caller must call srv.Close() when done.
func newMockMCPServer(cfg mcpServerConfig) *httptest.Server {
	sessionID := uuid.New().String()

	mux := http.NewServeMux()

	// PRM endpoint
	mux.HandleFunc("/.well-known/", func(w http.ResponseWriter, r *http.Request) {
		if !cfg.prmEnabled {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		prm := map[string]interface{}{
			"resource":              "http://test-rs",
			"authorization_servers": []string{"http://auth.test"},
			"scopes_supported":      cfg.scopesSupported,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(prm)
	})

	// MCP endpoint — handles initialize, notifications/initialized, tools/list
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      *int            `json:"id,omitempty"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		switch req.Method {
		case "initialize":
			w.Header().Set("Mcp-Session", sessionID)
			w.Header().Set("Content-Type", "application/json")
			result, _ := json.Marshal(map[string]interface{}{
				"protocolVersion": "2025-03-26",
				"capabilities":    map[string]interface{}{},
				"serverInfo":      map[string]interface{}{"name": "mock-mcp", "version": "0.1"},
			})
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result":  json.RawMessage(result),
			})

		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)

		case "tools/list":
			if cfg.toolsListError {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      req.ID,
					"error":   map[string]interface{}{"code": -32603, "message": "internal server error"},
				})
				return
			}
			tools := make([]map[string]interface{}, 0, len(cfg.tools))
			for _, t := range cfg.tools {
				tools = append(tools, map[string]interface{}{
					"name":        t["name"],
					"description": t["description"],
				})
			}
			result, _ := json.Marshal(map[string]interface{}{"tools": tools})
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result":  json.RawMessage(result),
			})

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	return httptest.NewServer(mux)
}

// ── Test helpers ──────────────────────────────────────────────────────────────

// createTestRS inserts a resource server directly and returns it.
func createTestRS(t *testing.T, name, publicBaseURL string) *models.ResourceServer {
	t.Helper()
	secret := "sec_testonly"
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	require.NoError(t, err)

	rs := &models.ResourceServer{
		ID:                      uuid.New(),
		WorkspaceID:             testTenantID,
		Name:                    name,
		PublicBaseURL:           publicBaseURL,
		ProtectedBasePath:       "/mcp",
		ResourceURI:             publicBaseURL + "/mcp",
		RegistrationModes:       []string{"dcr", "cimd", "prereg"},
		IntrospectionSecretHash: string(hash),
		Active:                  true,
		Status:                  "pending_scan",
		ScanGeneration:          0,
	}
	require.NoError(t, config.DB.Create(rs).Error)
	t.Cleanup(func() {
		config.DB.Unscoped().Where("id = ?", rs.ID).Delete(&models.ResourceServer{})
	})
	return rs
}

// reloadRS re-fetches the RS from DB to get the latest column values.
func reloadRS(t *testing.T, id uuid.UUID) *models.ResourceServer {
	t.Helper()
	var rs models.ResourceServer
	require.NoError(t, config.DB.Unscoped().First(&rs, "id = ?", id).Error)
	return &rs
}

// toolCount returns the number of mcp_tools rows for the RS.
func toolCount(t *testing.T, rsID uuid.UUID) int {
	t.Helper()
	var n int64
	config.DB.Model(&models.MCPTool{}).Where("resource_server_id = ?", rsID).Count(&n)
	return int(n)
}

// toolCountAtGen returns tools for RS at a specific generation.
func toolCountAtGen(t *testing.T, rsID uuid.UUID, gen int) int {
	t.Helper()
	var n int64
	config.DB.Model(&models.MCPTool{}).
		Where("resource_server_id = ? AND last_scan_generation = ?", rsID, gen).Count(&n)
	return int(n)
}

// scopeCount returns auto-discovered oauth_scopes for the RS.
func autoScopeCount(t *testing.T, rsID uuid.UUID) int {
	t.Helper()
	var n int64
	config.DB.Model(&models.OAuthScope{}).
		Where("resource_server_id = ? AND is_auto_discovered = true", rsID).Count(&n)
	return int(n)
}

func newService() *services.ResourceServerService {
	return services.NewResourceServerService(config.DB)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// T2: Full scan success advances last_successful_generation, status=ready.
func TestDiscoverAndSync_FullScanSuccess(t *testing.T) {
	srv := newMockMCPServer(mcpServerConfig{
		prmEnabled:      true,
		scopesSupported: []string{"tools:weather:read", "tools:weather:list"},
		tools: []map[string]string{
			{"name": "get_weather", "description": "Get current weather"},
		},
	})
	defer srv.Close()

	rs := createTestRS(t, "test-full-scan-"+uuid.New().String()[:8], srv.URL)

	svc := newService()
	result, err := svc.DiscoverAndSync(context.Background(), rs)

	require.NoError(t, err)
	assert.Equal(t, 1, result.ToolsAdded)
	assert.Equal(t, 0, result.ToolsRemoved)
	assert.Equal(t, 2, result.ScopesAdded)
	assert.Empty(t, result.FailureReason)

	fresh := reloadRS(t, rs.ID)
	assert.Equal(t, "ready", fresh.Status)
	assert.Equal(t, 1, fresh.ScanGeneration)
	assert.Equal(t, 1, fresh.LastSuccessfulGeneration)
	require.NotNil(t, fresh.LastScanStatus)
	assert.Equal(t, "success", *fresh.LastScanStatus)
	assert.False(t, fresh.ScanInProgress)
	assert.NotNil(t, fresh.LastScanCompletedAt)

	assert.Equal(t, 1, toolCount(t, rs.ID))
	assert.Equal(t, 1, toolCountAtGen(t, rs.ID, 1))
	assert.Equal(t, 2, autoScopeCount(t, rs.ID))
}

// T3: Stale tool removed on rescan.
func TestDiscoverAndSync_StaleToolRemovedOnRescan(t *testing.T) {
	srv1 := newMockMCPServer(mcpServerConfig{
		prmEnabled:      true,
		scopesSupported: []string{"tools:a:read", "tools:b:read"},
		tools: []map[string]string{
			{"name": "tool_a", "description": "Tool A"},
			{"name": "tool_b", "description": "Tool B"},
		},
	})
	defer srv1.Close()

	rs := createTestRS(t, "test-stale-"+uuid.New().String()[:8], srv1.URL)
	svc := newService()

	// First scan: 2 tools
	_, err := svc.DiscoverAndSync(context.Background(), rs)
	require.NoError(t, err)
	assert.Equal(t, 2, toolCount(t, rs.ID))

	// Reload RS for second scan (ScanGeneration must be current)
	rs = reloadRS(t, rs.ID)

	// Second scan: only tool_a remains; tool_b removed from server.
	// We need a new mock server that returns only tool_a but uses the same URL
	// structure, so we update the RS URL to a new server.
	srv2 := newMockMCPServer(mcpServerConfig{
		prmEnabled:      true,
		scopesSupported: []string{"tools:a:read"},
		tools: []map[string]string{
			{"name": "tool_a", "description": "Tool A"},
		},
	})
	defer srv2.Close()

	// Point RS at the new server
	config.DB.Model(rs).Updates(map[string]interface{}{
		"public_base_url": srv2.URL,
		"resource_uri":    srv2.URL + "/mcp",
	})
	rs.PublicBaseURL = srv2.URL

	result, err := svc.DiscoverAndSync(context.Background(), rs)
	require.NoError(t, err)

	assert.Equal(t, 1, result.ToolsUpdated) // tool_a updated
	assert.Equal(t, 1, result.ToolsRemoved) // tool_b removed
	assert.Equal(t, 1, toolCount(t, rs.ID))

	fresh := reloadRS(t, rs.ID)
	assert.Equal(t, 2, fresh.LastSuccessfulGeneration)
	assert.Equal(t, "ready", fresh.Status)
}

// T9: Partial scan (PRM nil) — last_successful_generation NOT advanced, stale tools preserved.
func TestDiscoverAndSync_PartialScanPRMUnavailable(t *testing.T) {
	// First do a full scan to establish generation=1
	fullSrv := newMockMCPServer(mcpServerConfig{
		prmEnabled:      true,
		scopesSupported: []string{"tools:x:read"},
		tools: []map[string]string{
			{"name": "tool_x", "description": "Tool X"},
		},
	})
	defer fullSrv.Close()

	rs := createTestRS(t, "test-partial-"+uuid.New().String()[:8], fullSrv.URL)
	svc := newService()

	_, err := svc.DiscoverAndSync(context.Background(), rs)
	require.NoError(t, err)

	rs = reloadRS(t, rs.ID)
	assert.Equal(t, 1, rs.LastSuccessfulGeneration)

	// Now run a partial scan: PRM disabled, tools still available
	partialSrv := newMockMCPServer(mcpServerConfig{
		prmEnabled: false, // PRM returns 404 → discovered.PRM == nil
		tools: []map[string]string{
			{"name": "tool_x", "description": "Tool X"},
		},
	})
	defer partialSrv.Close()

	config.DB.Model(rs).Updates(map[string]interface{}{
		"public_base_url": partialSrv.URL,
		"resource_uri":    partialSrv.URL + "/mcp",
	})
	rs.PublicBaseURL = partialSrv.URL

	result, err := svc.DiscoverAndSync(context.Background(), rs)
	require.NoError(t, err) // partial scan is not an error

	assert.NotEmpty(t, result.Warnings)
	assert.Contains(t, result.Warnings[0], "PRM unavailable")
	assert.Empty(t, result.FailureReason)

	fresh := reloadRS(t, rs.ID)
	// Serving pointer must NOT have advanced
	assert.Equal(t, 1, fresh.LastSuccessfulGeneration, "last_successful_generation must not advance on partial scan")
	assert.Equal(t, 2, fresh.ScanGeneration, "scan_generation increments even on partial")
	assert.Equal(t, "degraded", fresh.Status)
	require.NotNil(t, fresh.LastScanStatus)
	assert.Equal(t, "partial", *fresh.LastScanStatus, "partial exclusively means serving pointer not advanced")

	// Old tool (gen=1) must still be present — old snapshot intact
	assert.Equal(t, 1, toolCountAtGen(t, rs.ID, 1))

	// Scopes must be untouched
	assert.Equal(t, 1, autoScopeCount(t, rs.ID))
}

// T11: Hard failure (tools/list error) — status=degraded, last_scan_status=failure.
func TestDiscoverAndSync_HardFailure(t *testing.T) {
	fullSrv := newMockMCPServer(mcpServerConfig{
		prmEnabled:      true,
		scopesSupported: []string{"tools:x:read"},
		tools: []map[string]string{
			{"name": "tool_x", "description": "Tool X"},
		},
	})
	defer fullSrv.Close()

	rs := createTestRS(t, "test-failure-"+uuid.New().String()[:8], fullSrv.URL)
	svc := newService()

	// Establish generation=1 first
	_, err := svc.DiscoverAndSync(context.Background(), rs)
	require.NoError(t, err)

	rs = reloadRS(t, rs.ID)
	prevGen := rs.LastSuccessfulGeneration

	// Now fail: tools/list returns RPC error
	failSrv := newMockMCPServer(mcpServerConfig{
		prmEnabled:     true,
		toolsListError: true,
	})
	defer failSrv.Close()

	config.DB.Model(rs).Updates(map[string]interface{}{
		"public_base_url": failSrv.URL,
		"resource_uri":    failSrv.URL + "/mcp",
	})
	rs.PublicBaseURL = failSrv.URL

	result, err := svc.DiscoverAndSync(context.Background(), rs)
	require.Error(t, err)
	assert.NotEmpty(t, result.FailureReason)

	fresh := reloadRS(t, rs.ID)
	assert.Equal(t, "degraded", fresh.Status)
	require.NotNil(t, fresh.LastScanStatus)
	assert.Equal(t, "failure", *fresh.LastScanStatus)
	assert.NotNil(t, fresh.LastScanError)
	assert.False(t, fresh.ScanInProgress, "scan lock must be released on failure")

	// Serving pointer must NOT have moved
	assert.Equal(t, prevGen, fresh.LastSuccessfulGeneration,
		"last_successful_generation must not change after hard failure")
}

// T15: Concurrent rescan returns ErrScanInProgress (409 at service level).
func TestDiscoverAndSync_ConcurrentRescanBlocked(t *testing.T) {
	rs := createTestRS(t, "test-concurrent-"+uuid.New().String()[:8], "http://localhost:9999")
	svc := newService()

	// Manually set scan_in_progress=true with a recent timestamp to simulate an active scan
	now := time.Now().UTC()
	config.DB.Model(rs).Updates(map[string]interface{}{
		"scan_in_progress":     true,
		"last_scan_started_at": now,
		"scan_generation":      1,
	})

	// Reload so the in-memory struct is current
	rs = reloadRS(t, rs.ID)

	result, err := svc.DiscoverAndSync(context.Background(), rs)
	require.Error(t, err)
	assert.ErrorIs(t, err, services.ErrScanInProgress)
	assert.Equal(t, services.ErrScanInProgress.Error(), result.FailureReason)
}

// T15b: A superseded scan's failure path must not clear the newer scan's lock.
// Regression test for the P0 bug: markScanFailed without a generation guard
// could set scan_in_progress=false even when a newer scan owned the lock.
func TestDiscoverAndSync_SupersededScanDoesNotClearNewerLock(t *testing.T) {
	rs := createTestRS(t, "test-superseded-"+uuid.New().String()[:8], "http://localhost:9997")
	svc := newService()

	// Simulate: scan A claimed gen=3, then scan B stole the lock and advanced to gen=4.
	// scan B is still running (scan_in_progress=true, gen=4).
	config.DB.Model(rs).Updates(map[string]interface{}{
		"scan_in_progress":     true,
		"scan_generation":      4,
		"last_scan_started_at": time.Now().UTC(),
	})
	rs = reloadRS(t, rs.ID)

	// Directly invoke markScanFailed as scan A would (generation=3, the superseded one).
	// It must NOT clear scan_in_progress because gen=4 != gen=3.
	svc.ExposedMarkScanFailed(rs, 3, "superseded scan error")

	fresh := reloadRS(t, rs.ID)
	assert.True(t, fresh.ScanInProgress,
		"markScanFailed for a superseded generation must not clear the newer scan's lock")
	assert.Equal(t, 4, fresh.ScanGeneration,
		"scan_generation must not be modified by a superseded scan's failure path")
}

// T16: Stale lock (>10 min) is stolen by a new scan.
func TestDiscoverAndSync_StaleLockRecovery(t *testing.T) {
	srv := newMockMCPServer(mcpServerConfig{
		prmEnabled:      true,
		scopesSupported: []string{"tools:z:read"},
		tools: []map[string]string{
			{"name": "tool_z", "description": "Tool Z"},
		},
	})
	defer srv.Close()

	rs := createTestRS(t, "test-stale-lock-"+uuid.New().String()[:8], srv.URL)
	svc := newService()

	// Simulate a crashed scan: scan_in_progress=true, started 15 minutes ago
	staleTime := time.Now().UTC().Add(-15 * time.Minute)
	config.DB.Model(rs).Updates(map[string]interface{}{
		"scan_in_progress":     true,
		"last_scan_started_at": staleTime,
		"scan_generation":      5,
	})
	rs = reloadRS(t, rs.ID)

	// New scan should steal the stale lock and succeed
	result, err := svc.DiscoverAndSync(context.Background(), rs)
	require.NoError(t, err)
	assert.Equal(t, 1, result.ToolsAdded)

	fresh := reloadRS(t, rs.ID)
	assert.False(t, fresh.ScanInProgress)
	assert.Equal(t, "ready", fresh.Status)
	assert.Equal(t, 6, fresh.ScanGeneration, "lock steal must increment generation")
	assert.Equal(t, 6, fresh.LastSuccessfulGeneration)
}

// T12: SDKPolicy returns 503 when no scan has ever succeeded.
func TestSDKPolicy_503BeforeAnySuccessfulScan(t *testing.T) {
	secret := "sec_sdktest_" + uuid.New().String()[:8]
	hash, _ := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)

	rs := &models.ResourceServer{
		ID:                       uuid.New(),
		WorkspaceID:              testTenantID,
		Name:                     "sdk-policy-test-" + uuid.New().String()[:8],
		PublicBaseURL:            "https://localhost:9998",
		ProtectedBasePath:        "/mcp",
		ResourceURI:              fmt.Sprintf("https://localhost:9998/mcp/%s", uuid.New()),
		RegistrationModes:        []string{"dcr"},
		IntrospectionSecretHash:  string(hash),
		Active:                   true,
		Status:                   "pending_scan",
		ScanGeneration:           0,
		LastSuccessfulGeneration: 0,
	}
	require.NoError(t, config.DB.Create(rs).Error)
	t.Cleanup(func() {
		config.DB.Unscoped().Where("id = ?", rs.ID).Delete(&models.ResourceServer{})
	})

	req, _ := http.NewRequest(http.MethodGet,
		"/authsec/resource-servers/"+rs.ID.String()+"/sdk-policy", nil)
	req.SetBasicAuth(rs.ID.String(), secret)

	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	assert.Equal(t, "pending_scan", body["status"])
}

// T13/T10: SDKPolicy returns 200 with last-good snapshot during degraded state.
func TestSDKPolicy_ServesLastGoodSnapshotWhenDegraded(t *testing.T) {
	srv := newMockMCPServer(mcpServerConfig{
		prmEnabled:      true,
		scopesSupported: []string{"tools:snap:read"},
		tools: []map[string]string{
			{"name": "snap_tool", "description": "Snapshot tool"},
		},
	})
	defer srv.Close()

	secret := "sec_sdksnap_" + uuid.New().String()[:8]
	hash, _ := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)

	rs := createTestRS(t, "sdk-snap-"+uuid.New().String()[:8], srv.URL)
	// Overwrite the hash so we know the secret for BasicAuth
	config.DB.Model(rs).Update("introspection_secret_hash", string(hash))
	rs.IntrospectionSecretHash = string(hash)

	// First: run a successful scan to establish gen=1 snapshot
	svc := newService()
	_, err := svc.DiscoverAndSync(context.Background(), rs)
	require.NoError(t, err)

	// Now degrade the RS (simulate a subsequent failed scan)
	config.DB.Model(rs).Updates(map[string]interface{}{
		"status":           "degraded",
		"scan_generation":  2,
		"last_scan_status": "failure",
		// last_successful_generation stays at 1
	})

	// SDKPolicy must still return 200 and serve gen=1 tools
	req, _ := http.NewRequest(http.MethodGet,
		"/authsec/resource-servers/"+rs.ID.String()+"/sdk-policy", nil)
	req.SetBasicAuth(rs.ID.String(), secret)

	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)

	tools, ok := body["tools"].(map[string]interface{})
	assert.True(t, ok)
	_, hasSnapTool := tools["snap_tool"]
	assert.True(t, hasSnapTool, "last successful snapshot must be served even when RS is degraded")
}

// T14: GetScopeMatrix filters tools by last_successful_generation.
func TestGetScopeMatrix_FiltersToolsByLastSuccessfulGeneration(t *testing.T) {
	srv := newMockMCPServer(mcpServerConfig{
		prmEnabled:      true,
		scopesSupported: []string{"tools:gen:read"},
		tools: []map[string]string{
			{"name": "gen_tool", "description": "Gen tool"},
		},
	})
	defer srv.Close()

	rs := createTestRS(t, "scope-matrix-gen-"+uuid.New().String()[:8], srv.URL)
	svc := newService()

	// Run full scan → gen=1, last_successful_generation=1
	_, err := svc.DiscoverAndSync(context.Background(), rs)
	require.NoError(t, err)

	// Manually inject a "staged" tool at gen=2 (simulates a partial scan that didn't advance serving pointer)
	stagedTool := models.MCPTool{
		ID:                 uuid.New(),
		WorkspaceID:        testTenantID,
		ResourceServerID:   rs.ID,
		Name:               "staged_tool_gen2",
		LastScanGeneration: 2,
	}
	config.DB.Create(&stagedTool)
	t.Cleanup(func() { config.DB.Unscoped().Delete(&stagedTool) })

	// GetScopeMatrix should return only gen=1 tool, not the staged gen=2 tool
	resp := doAdminRequest(http.MethodGet,
		"/authsec/resource-servers/"+rs.ID.String()+"/scope-matrix", nil)

	assert.Equal(t, http.StatusOK, resp.Code)

	rsInfo, ok := resp.JSON["resource_server"].(map[string]interface{})
	require.True(t, ok)

	// Verify lifecycle fields are present in response
	assert.Equal(t, "ready", rsInfo["status"])
	assert.EqualValues(t, 1, rsInfo["last_successful_generation"])
	assert.EqualValues(t, 1, rsInfo["scan_generation"])
	assert.Equal(t, "success", rsInfo["last_scan_status"])

	// Verify tool filtering
	tools, _ := resp.JSON["tools"].([]interface{})
	assert.Len(t, tools, 1, "should return only gen=1 tool, not staged gen=2 tool")
	if len(tools) == 1 {
		toolObj, _ := tools[0].(map[string]interface{})
		assert.Equal(t, "gen_tool", toolObj["name"])
	}
}

// T22: scopes_supported is not wiped when PRM is unavailable.
func TestDiscoverAndSync_ScopesNotWipedOnPRMFailure(t *testing.T) {
	fullSrv := newMockMCPServer(mcpServerConfig{
		prmEnabled:      true,
		scopesSupported: []string{"tools:preserve:read"},
		tools: []map[string]string{
			{"name": "preserve_tool", "description": "Preserve tool"},
		},
	})
	defer fullSrv.Close()

	rs := createTestRS(t, "test-preserve-"+uuid.New().String()[:8], fullSrv.URL)
	svc := newService()

	// Full scan establishes scopes_supported
	_, err := svc.DiscoverAndSync(context.Background(), rs)
	require.NoError(t, err)

	rs = reloadRS(t, rs.ID)
	require.NotEmpty(t, rs.ScopesSupported)
	originalScopes := []string(rs.ScopesSupported)

	// Partial scan: PRM unavailable
	partialSrv := newMockMCPServer(mcpServerConfig{
		prmEnabled: false,
		tools: []map[string]string{
			{"name": "preserve_tool", "description": "Preserve tool"},
		},
	})
	defer partialSrv.Close()
	config.DB.Model(rs).Updates(map[string]interface{}{
		"public_base_url": partialSrv.URL,
		"resource_uri":    partialSrv.URL + "/mcp",
	})
	rs.PublicBaseURL = partialSrv.URL

	_, err = svc.DiscoverAndSync(context.Background(), rs)
	require.NoError(t, err) // partial scan is not an error

	fresh := reloadRS(t, rs.ID)
	assert.Equal(t, originalScopes, []string(fresh.ScopesSupported),
		"scopes_supported must not be modified when PRM is unavailable")
}

// T17: Discovery URL uses PublicBaseURL + ProtectedBasePath, not bare PublicBaseURL.
func TestDiscoverAndSync_UsesCorrectResourceURI(t *testing.T) {
	// Track which paths were actually requested
	var requestedPaths []string
	var pathsMux http.ServeMux

	pathsMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		requestedPaths = append(requestedPaths, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	})

	// Correct MCP endpoint at /myapp/mcp
	pathsMux.HandleFunc("/myapp/mcp", func(w http.ResponseWriter, r *http.Request) {
		requestedPaths = append(requestedPaths, r.URL.Path)
		var req struct {
			Method string `json:"method"`
			ID     *int   `json:"id,omitempty"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		switch req.Method {
		case "initialize":
			w.Header().Set("Mcp-Session", "sess-uri-test")
			result, _ := json.Marshal(map[string]interface{}{
				"protocolVersion": "2025-03-26",
				"capabilities":    map[string]interface{}{},
				"serverInfo":      map[string]interface{}{"name": "uri-test"},
			})
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": json.RawMessage(result),
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			result, _ := json.Marshal(map[string]interface{}{"tools": []interface{}{}})
			json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0", "id": req.ID,
				"result": json.RawMessage(result),
			})
		}
	})

	server := httptest.NewServer(&pathsMux)
	defer server.Close()

	rs := createTestRS(t, "uri-test-"+uuid.New().String()[:8], server.URL)
	config.DB.Model(rs).Update("protected_base_path", "/myapp/mcp")
	rs.ProtectedBasePath = "/myapp/mcp"

	svc := newService()
	_, _ = svc.DiscoverAndSync(context.Background(), rs)

	// The MCP initialize must have been sent to /myapp/mcp, NOT /
	mcpHit := false
	for _, p := range requestedPaths {
		if strings.HasPrefix(p, "/myapp/mcp") {
			mcpHit = true
		}
	}
	assert.True(t, mcpHit, "MCP discovery must target PublicBaseURL+ProtectedBasePath; got paths: %v", requestedPaths)
}
