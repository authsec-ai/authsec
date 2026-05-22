package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrProtectedServer is returned when discovery hits an MCP endpoint that
// responds with HTTP 401 + RFC 9728 bearer challenge (WWW-Authenticate with
// resource_metadata). Semantically: the server is alive and properly protected
// by OAuth, but we cannot call tools/list unauthenticated. Callers should treat
// this as a successful "server is reachable and protected" outcome and commit
// a zero-tool scan rather than a hard failure.
var ErrProtectedServer = errors.New("mcp server is protected (401 with bearer challenge)")

const (
	maxResponseSize    = 5 * 1024 * 1024 // 5MB
	connectTimeout     = 10 * time.Second
	requestTimeout     = 30 * time.Second
	mcpProtocolVersion = "2025-03-26"
)

// Client discovers tools and scopes from MCP servers.
type Client struct {
	httpClient  *http.Client
	bearerToken string // optional; when set, injected as Authorization: Bearer <token>
}

// NewClient creates an MCP discovery client with SSRF-safe transport.
func NewClient() *Client {
	transport := &http.Transport{
		DialContext:         ssrfSafeDialer(),
		TLSHandshakeTimeout: connectTimeout,
	}
	return &Client{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   requestTimeout,
		},
	}
}

// WithBearerToken returns a copy of the client that attaches the given bearer
// token to MCP requests (initialize, tools/list, notifications/initialized).
// Empty token returns the same client unchanged. The token is never persisted
// — it lives only in this client's memory for the duration of the request.
func (c *Client) WithBearerToken(token string) *Client {
	token = strings.TrimSpace(token)
	if token == "" {
		return c
	}
	clone := *c
	clone.bearerToken = token
	return &clone
}

// Discover performs full MCP server discovery: PRM fetch + tools/list.
func (c *Client) Discover(ctx context.Context, baseURL string) (*DiscoveryResult, error) {
	result := &DiscoveryResult{}

	prm, err := c.FetchPRM(ctx, baseURL)
	if err != nil {
		// PRM is optional per spec — log and continue
		fmt.Printf("[MCP_DISCOVERY] PRM fetch failed for %s: %v\n", baseURL, err)
	} else {
		result.PRM = prm
	}

	tools, err := c.DiscoverTools(ctx, baseURL)
	if err != nil {
		return result, fmt.Errorf("tools/list failed: %w", err)
	}
	result.Tools = tools

	return result, nil
}

// FetchPRM fetches Protected Resource Metadata (RFC 9728) from the MCP server.
func (c *Client) FetchPRM(ctx context.Context, baseURL string) (*ProtectedResourceMetadata, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	// Try path-specific first, then root
	prmURLs := []string{
		fmt.Sprintf("%s://%s/.well-known/oauth-protected-resource%s", parsed.Scheme, parsed.Host, parsed.Path),
	}
	if parsed.Path != "" && parsed.Path != "/" {
		prmURLs = append(prmURLs, fmt.Sprintf("%s://%s/.well-known/oauth-protected-resource", parsed.Scheme, parsed.Host))
	}

	for _, prmURL := range prmURLs {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, prmURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		if err != nil {
			continue
		}

		var prm ProtectedResourceMetadata
		if err := json.Unmarshal(body, &prm); err != nil {
			continue
		}
		return &prm, nil
	}

	return nil, fmt.Errorf("PRM not found at any well-known URI for %s", baseURL)
}

// DiscoverTools calls MCP initialize + tools/list via Streamable HTTP.
func (c *Client) DiscoverTools(ctx context.Context, baseURL string) ([]Tool, error) {
	mcpEndpoint := strings.TrimRight(baseURL, "/")

	// Step 1: Initialize
	sessionID, err := c.mcpInitialize(ctx, mcpEndpoint)
	if err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}

	// Step 2: tools/list (paginated)
	var allTools []Tool
	var cursor string
	reqID := 2

	for {
		params := map[string]interface{}{}
		if cursor != "" {
			params["cursor"] = cursor
		}

		resp, err := c.mcpRequest(ctx, mcpEndpoint, sessionID, reqID, "tools/list", params)
		if err != nil {
			return allTools, fmt.Errorf("tools/list: %w", err)
		}
		reqID++

		var result toolsListResult
		if err := json.Unmarshal(resp.Result, &result); err != nil {
			return allTools, fmt.Errorf("parse tools/list: %w", err)
		}

		allTools = append(allTools, result.Tools...)

		if result.NextCursor == "" {
			break
		}
		cursor = result.NextCursor
	}

	return allTools, nil
}

func (c *Client) mcpInitialize(ctx context.Context, endpoint string) (string, error) {
	initParams := map[string]interface{}{
		"protocolVersion": mcpProtocolVersion,
		"capabilities":    map[string]interface{}{},
		"clientInfo": map[string]interface{}{
			"name":    "authsec-discovery",
			"version": "1.0.0",
		},
	}

	resp, err := c.mcpRawRequest(ctx, endpoint, "", 1, "initialize", initParams)
	if err != nil {
		return "", err
	}

	// Extract session ID from Mcp-Session header
	sessionID := resp.Header.Get("Mcp-Session")

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("read initialize response: %w", err)
	}

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return "", fmt.Errorf("parse initialize response: %w", err)
	}
	if rpcResp.Error != nil {
		return "", fmt.Errorf("initialize error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	// Send initialized notification
	notif := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}
	notifBody, _ := json.Marshal(notif)
	notifReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(notifBody))
	notifReq.Header.Set("Content-Type", "application/json")
	notifReq.Header.Set("Accept", "application/json")
	if sessionID != "" {
		notifReq.Header.Set("Mcp-Session", sessionID)
	}
	if c.bearerToken != "" {
		notifReq.Header.Set("Authorization", "Bearer "+c.bearerToken)
	}
	notifResp, err := c.httpClient.Do(notifReq)
	if err == nil {
		notifResp.Body.Close()
	}

	return sessionID, nil
}

func (c *Client) mcpRequest(ctx context.Context, endpoint, sessionID string, id int, method string, params interface{}) (*jsonRPCResponse, error) {
	resp, err := c.mcpRawRequest(ctx, endpoint, sessionID, id, method, params)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	return &rpcResp, nil
}

func (c *Client) mcpRawRequest(ctx context.Context, endpoint, sessionID string, id int, method string, params interface{}) (*http.Response, error) {
	rpcReq := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	}

	body, err := json.Marshal(rpcReq)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if sessionID != "" {
		req.Header.Set("Mcp-Session", sessionID)
	}
	if c.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearerToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		resp.Body.Close()
		// RFC 9728 bearer challenge: protected server, reachable and well-formed.
		// Treat as a distinct outcome so the caller can commit a zero-tool scan
		// rather than mark the RS as failed.
		if strings.Contains(strings.ToLower(wwwAuth), "bearer") {
			return nil, ErrProtectedServer
		}
		return nil, fmt.Errorf("HTTP 401 from %s %s", method, endpoint)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d from %s %s", resp.StatusCode, method, endpoint)
	}

	return resp, nil
}

// ssrfSafeDialer rejects connections to private/loopback IPs.
func ssrfSafeDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: connectTimeout}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid address: %w", err)
		}

		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, fmt.Errorf("DNS lookup failed: %w", err)
		}

		for _, ip := range ips {
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				return nil, fmt.Errorf("connection to private/loopback IP %s is not allowed (SSRF protection)", ip)
			}
		}

		return dialer.DialContext(ctx, network, addr)
	}
}
