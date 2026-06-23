package fakes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
)

// MCPResourceServer is a request-scoped fake MCP resource server.
// It serves:
//
//	GET /.well-known/oauth-protected-resource  → PRM JSON
//	POST /mcp                                  → JSON-RPC (initialize, tools/list)
type MCPResourceServer struct {
	mu      sync.Mutex
	server  *httptest.Server
	tools   []map[string]interface{}
	scopes  []string
	failRPC bool // if true, /mcp returns a JSON-RPC error
	prmNil  bool // if true, PRM endpoint returns empty object (partial scan)
	auth401 bool // if true, PRM endpoint returns 401 + WWW-Authenticate
}

// NewMCPResourceServer starts a fake MCP server with the given tools and scopes.
func NewMCPResourceServer(tools []map[string]interface{}, scopes []string) *MCPResourceServer {
	rs := &MCPResourceServer{tools: tools, scopes: scopes}
	rs.server = httptest.NewServer(rs)
	return rs
}

// URL returns the base URL of the fake MCP server.
func (rs *MCPResourceServer) URL() string { return rs.server.URL }

// SetFailRPC makes the JSON-RPC endpoint return an error on the next call.
func (rs *MCPResourceServer) SetFailRPC(v bool) { rs.mu.Lock(); rs.failRPC = v; rs.mu.Unlock() }

// SetPRMNil makes the PRM endpoint return an empty object (simulates partial scan).
func (rs *MCPResourceServer) SetPRMNil(v bool) { rs.mu.Lock(); rs.prmNil = v; rs.mu.Unlock() }

// SetAuth401 makes the PRM endpoint return 401 + WWW-Authenticate.
func (rs *MCPResourceServer) SetAuth401(v bool) { rs.mu.Lock(); rs.auth401 = v; rs.mu.Unlock() }

// Close shuts the server down.
func (rs *MCPResourceServer) Close() { rs.server.Close() }

func (rs *MCPResourceServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rs.mu.Lock()
	failRPC := rs.failRPC
	prmNil := rs.prmNil
	auth401 := rs.auth401
	rs.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")

	switch r.URL.Path {
	case "/.well-known/oauth-protected-resource":
		if auth401 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mcp"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if prmNil {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		prm := map[string]interface{}{
			"resource":              rs.server.URL + "/mcp",
			"authorization_servers": []string{rs.server.URL},
			"scopes_supported":      rs.scopes,
		}
		_ = json.NewEncoder(w).Encode(prm)

	case "/mcp":
		if failRPC {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"error":   map[string]interface{}{"code": -32603, "message": "internal error"},
			})
			return
		}
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)

		switch method {
		case "initialize":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req["id"],
				"result": map[string]interface{}{
					"protocolVersion": "2024-11-05",
					"serverInfo":      map[string]string{"name": "fake-mcp", "version": "0.1"},
					"capabilities":    map[string]interface{}{"tools": map[string]bool{"listChanged": false}},
				},
			})
		case "tools/list":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req["id"],
				"result":  map[string]interface{}{"tools": rs.tools},
			})
		default:
			w.WriteHeader(http.StatusBadRequest)
		}

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}
