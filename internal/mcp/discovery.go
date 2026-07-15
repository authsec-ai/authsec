package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
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

// ProtectedServerError carries the RFC 9728 metadata URL advertised by a
// parsed Bearer challenge. It unwraps to ErrProtectedServer for callers that
// only need the protected/reachable classification.
type ProtectedServerError struct {
	ResourceMetadataURL string
}

func (e *ProtectedServerError) Error() string { return ErrProtectedServer.Error() }
func (e *ProtectedServerError) Unwrap() error { return ErrProtectedServer }

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
	if c.bearerToken != "" {
		// MCP requires clients to prefer resource_metadata from a parsed 401
		// challenge. Probe without the token only when well-known discovery did
		// not yield valid metadata; the real tools/list call still uses the
		// caller's one-shot token below.
		probe := *c
		probe.bearerToken = ""
		_, probeErr := probe.DiscoverTools(ctx, baseURL)
		var protectedErr *ProtectedServerError
		if errors.As(probeErr, &protectedErr) && protectedErr.ResourceMetadataURL != "" {
			// A challenge URL is authoritative over an earlier well-known
			// document because it can advertise changed metadata.
			result.PRM = c.prmFromProtectedError(ctx, baseURL, probeErr)
		}
	}

	tools, err := c.DiscoverTools(ctx, baseURL)
	if err != nil {
		var protectedErr *ProtectedServerError
		if errors.As(err, &protectedErr) && protectedErr.ResourceMetadataURL != "" {
			result.PRM = c.prmFromProtectedError(ctx, baseURL, err)
		}
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
	resourcePath := parsed.EscapedPath()
	if resourcePath == "/" {
		resourcePath = ""
	}
	prmURLs := []string{
		fmt.Sprintf("%s://%s/.well-known/oauth-protected-resource%s", parsed.Scheme, parsed.Host, resourcePath),
	}
	if parsed.Path != "" && parsed.Path != "/" {
		prmURLs = append(prmURLs, fmt.Sprintf("%s://%s/.well-known/oauth-protected-resource", parsed.Scheme, parsed.Host))
	}

	for _, prmURL := range prmURLs {
		if prm, err := c.fetchPRMURL(ctx, prmURL, baseURL); err == nil {
			return prm, nil
		}
	}

	return nil, fmt.Errorf("PRM not found at any well-known URI for %s", baseURL)
}

func (c *Client) prmFromProtectedError(ctx context.Context, resourceURI string, discoveryErr error) *ProtectedResourceMetadata {
	var protectedErr *ProtectedServerError
	if !errors.As(discoveryErr, &protectedErr) || protectedErr.ResourceMetadataURL == "" {
		return nil
	}
	prm, err := c.fetchPRMURL(ctx, protectedErr.ResourceMetadataURL, resourceURI)
	if err != nil {
		return nil
	}
	return prm
}

func (c *Client) fetchPRMURL(ctx context.Context, metadataURL, expectedResource string) (*ProtectedResourceMetadata, error) {
	parsed, err := url.Parse(metadataURL)
	if err != nil || parsed == nil {
		return nil, fmt.Errorf("invalid protected resource metadata URL")
	}
	allowLocalHTTP := os.Getenv("MCP_ALLOW_LOOPBACK") == "true" &&
		parsed.Scheme == "http" &&
		(parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1")
	if (parsed.Scheme != "https" && !allowLocalHTTP) || parsed.Host == "" {
		return nil, fmt.Errorf("invalid protected resource metadata URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("protected resource metadata returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, err
	}
	var prm ProtectedResourceMetadata
	if err := json.Unmarshal(body, &prm); err != nil {
		return nil, err
	}
	// RFC 9728 section 3.3 requires an identical resource identifier.
	if prm.Resource == "" || prm.Resource != expectedResource {
		return nil, fmt.Errorf("protected resource metadata resource mismatch")
	}
	return &prm, nil
}

// DiscoverTools calls MCP initialize + tools/list via Streamable HTTP.
func (c *Client) DiscoverTools(ctx context.Context, baseURL string) ([]Tool, error) {
	mcpEndpoint := baseURL

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

	// MCP Streamable HTTP uses Mcp-Session-Id for stateful sessions.
	sessionID := resp.Header.Get("Mcp-Session-Id")

	rpcResp, err := readJSONRPCResponse(resp, 1)
	if err != nil {
		return "", fmt.Errorf("parse initialize response: %w", err)
	}
	if rpcResp.Error != nil {
		return "", fmt.Errorf("initialize error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}
	var initializeResult struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(rpcResp.Result, &initializeResult); err != nil {
		return "", fmt.Errorf("parse initialize protocol version: %w", err)
	}
	if initializeResult.ProtocolVersion != mcpProtocolVersion {
		return "", fmt.Errorf("MCP server negotiated unsupported protocol version %q", initializeResult.ProtocolVersion)
	}

	// Send initialized notification
	notif := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}
	notifBody, _ := json.Marshal(notif)
	notifReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(notifBody))
	notifReq.Header.Set("Content-Type", "application/json")
	notifReq.Header.Set("Accept", "application/json, text/event-stream")
	notifReq.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
	if sessionID != "" {
		notifReq.Header.Set("Mcp-Session-Id", sessionID)
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
	rpcResp, err := readJSONRPCResponse(resp, id)
	if err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	return rpcResp, nil
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
	req.Header.Set("Accept", "application/json, text/event-stream")
	if method != "initialize" {
		req.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
	}
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	if c.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearerToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		wwwAuth := resp.Header.Values("WWW-Authenticate")
		resp.Body.Close()
		// Parse top-level authentication challenges so quoted Basic realms cannot
		// masquerade as Bearer. MCP prefers resource_metadata from the Bearer
		// challenge and falls back to well-known discovery when it is absent.
		if metadataURL, ok := bearerResourceMetadataURL(wwwAuth); ok {
			return nil, &ProtectedServerError{ResourceMetadataURL: metadataURL}
		}
		return nil, fmt.Errorf("HTTP 401 from %s %s", method, endpoint)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d from %s %s", resp.StatusCode, method, endpoint)
	}

	return resp, nil
}

func readJSONRPCResponse(resp *http.Response, expectedID int) (*jsonRPCResponse, error) {
	defer resp.Body.Close()
	if !strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		if err != nil {
			return nil, fmt.Errorf("read response: %w", err)
		}
		var rpcResp jsonRPCResponse
		if err := json.Unmarshal(body, &rpcResp); err != nil {
			return nil, err
		}
		if !isExpectedJSONRPCResponse(&rpcResp, expectedID) {
			return nil, fmt.Errorf("JSON-RPC response id did not match request %d", expectedID)
		}
		return &rpcResp, nil
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), maxResponseSize)
	dataLines := make([]string, 0, 2)
	bytesRead := 0
	flush := func() *jsonRPCResponse {
		if len(dataLines) == 0 {
			return nil
		}
		payload := strings.Join(dataLines, "\n")
		dataLines = dataLines[:0]
		var rpcResp jsonRPCResponse
		if json.Unmarshal([]byte(payload), &rpcResp) != nil {
			return nil
		}
		if !isExpectedJSONRPCResponse(&rpcResp, expectedID) {
			return nil
		}
		return &rpcResp
	}
	for scanner.Scan() {
		line := scanner.Text()
		bytesRead += len(line) + 1
		if bytesRead > maxResponseSize {
			return nil, fmt.Errorf("SSE response exceeded %d bytes", maxResponseSize)
		}
		if line == "" {
			if rpcResp := flush(); rpcResp != nil {
				return rpcResp, nil
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if rpcResp := flush(); rpcResp != nil {
		return rpcResp, nil
	}
	return nil, fmt.Errorf("SSE response contained no JSON-RPC result")
}

func isExpectedJSONRPCResponse(response *jsonRPCResponse, expectedID int) bool {
	return response.ID != nil &&
		*response.ID == expectedID &&
		response.Method == "" &&
		(response.Result != nil || response.Error != nil)
}

func bearerResourceMetadataURL(headerValues []string) (string, bool) {
	sawBearer := false
	for _, headerValue := range headerValues {
		currentScheme := ""
		for _, segment := range splitAuthHeaderSegments(headerValue) {
			segment = strings.TrimSpace(segment)
			if segment == "" {
				continue
			}
			parameterText := segment
			if _, _, isParameter := cutAuthParameter(segment); !isParameter {
				space := strings.IndexAny(segment, " \t")
				if space >= 0 {
					currentScheme = strings.TrimSpace(segment[:space])
					parameterText = strings.TrimSpace(segment[space+1:])
				} else {
					currentScheme = segment
					parameterText = ""
				}
			}
			if !strings.EqualFold(currentScheme, "Bearer") {
				continue
			}
			sawBearer = true
			if parameterText == "" {
				return "", true
			}
			name, rawValue, found := cutAuthParameter(parameterText)
			if !found || !strings.EqualFold(name, "resource_metadata") {
				continue
			}
			value := rawValue
			if strings.HasPrefix(value, `"`) {
				unquoted, err := strconv.Unquote(value)
				if err != nil {
					return "", false
				}
				value = unquoted
			}
			return value, true
		}
	}
	return "", sawBearer
}

func cutAuthParameter(value string) (string, string, bool) {
	name, rawValue, found := strings.Cut(value, "=")
	if !found {
		return "", "", false
	}
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, " \t") {
		return "", "", false
	}
	return name, strings.TrimSpace(rawValue), true
}

func splitAuthHeaderSegments(value string) []string {
	segments := make([]string, 0, 4)
	start := 0
	inQuotes := false
	escaped := false
	for index, r := range value {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' && inQuotes {
			escaped = true
			continue
		}
		if r == '"' {
			inQuotes = !inQuotes
			continue
		}
		if r == ',' && !inQuotes {
			segments = append(segments, value[start:index])
			start = index + 1
		}
	}
	segments = append(segments, value[start:])
	return segments
}

// ssrfSafeDialer rejects connections to private/loopback IPs.
// Set MCP_ALLOW_LOOPBACK=true to bypass the check (integration-test use only).
func ssrfSafeDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	allowLoopback := os.Getenv("MCP_ALLOW_LOOPBACK") == "true"
	dialer := &net.Dialer{Timeout: connectTimeout}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if allowLoopback {
			return dialer.DialContext(ctx, network, addr)
		}

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
