package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/authsec-ai/authsec/internal/agentgateway"
)

// MCP Streamable HTTP reverse proxy (spec §7). The 2026-07-28 revision
// mirrors the JSON-RPC method and target into Mcp-Method / Mcp-Name
// (SEP-2243; modelcontextprotocol.io/specification/draft/basic/transports/
// streamable-http, "Request Metadata"). This proxy processes the body, so it
// MUST reject a header that does not match it (400, JSON-RPC -32020
// HeaderMismatch); it decides on the body's values. Older clients send no
// such headers; the body is parsed either way.

// JSON-RPC error codes.
const (
	rpcParseError     = -32700
	rpcInvalidRequest = -32600
	rpcInternalError  = -32603
	// rpcHeaderMismatch is MCP's HeaderMismatch (-32001 in SEP-2243,
	// reassigned to -32020 by #2907).
	rpcHeaderMismatch = -32020
	// RPCPolicyDenied is AuthSec's refusal of a tool call (an application
	// code outside the JSON-RPC reserved range).
	RPCPolicyDenied = -31001
)

// Forwarded agent headers. Authorization, X-Api-Key, cookies and the agent
// key are never forwarded: no token passthrough (the upstream's
// credentials come from the configuration). Accept-Encoding is not
// forwarded so the transport decompresses what the parsers read.
var mcpForwardHeaders = map[string]bool{
	"Accept": true, "Content-Type": true, "Mcp-Protocol-Version": true, "Mcp-Method": true, "Mcp-Name": true,
	"Mcp-Session-Id": true, "Last-Event-Id": true, "User-Agent": true,
}

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcNamedParams struct {
	Name      string          `json:"name"`
	URI       string          `json:"uri"`
	Arguments json.RawMessage `json:"arguments"`
}

func (m rpcMessage) isRequest() bool {
	return m.Method != "" && len(m.ID) > 0 && string(m.ID) != "null"
}

func (m rpcMessage) named() (rpcNamedParams, error) {
	var p rpcNamedParams
	if len(m.Params) == 0 {
		return p, nil
	}
	err := json.Unmarshal(m.Params, &p)
	return p, err
}

// nameTarget is the body value Mcp-Name mirrors, and whether the method has one.
func nameTarget(method string, p rpcNamedParams) (string, bool) {
	switch method {
	case "tools/call", "prompts/get":
		return p.Name, true
	case "resources/read":
		return p.URI, true
	}
	return "", false
}

var errHeaderMismatch = errors.New("header mismatch")

// DecodeHeaderValue decodes MCP's Base64 sentinel (=?base64?…?=); any other
// value is literal.
func DecodeHeaderValue(v string) (string, error) {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "=?base64?") && strings.HasSuffix(v, "?=") && len(v) >= len("=?base64?")+len("?=") {
		raw, err := base64.StdEncoding.Strict().DecodeString(v[len("=?base64?") : len(v)-len("?=")])
		if err != nil {
			return "", fmt.Errorf("%w: invalid base64 value", errHeaderMismatch)
		}
		return string(raw), nil
	}
	return v, nil
}

// CheckMCPHeaders validates Mcp-Method and Mcp-Name against the body.
func CheckMCPHeaders(h http.Header, m rpcMessage, p rpcNamedParams) error {
	hm, hasMethod := strings.TrimSpace(h.Get("Mcp-Method")), h.Get("Mcp-Method") != ""
	if hasMethod && hm != m.Method {
		return fmt.Errorf("%w: Mcp-Method header value %q does not match body value %q", errHeaderMismatch, hm, m.Method)
	}
	target, named := nameTarget(m.Method, p)
	raw := h.Get("Mcp-Name")
	if !named {
		return nil
	}
	if raw == "" {
		if hasMethod {
			return fmt.Errorf("%w: Mcp-Name header is required for %s", errHeaderMismatch, m.Method)
		}
		return nil
	}
	hn, err := DecodeHeaderValue(raw)
	if err != nil {
		return err
	}
	if hn != target {
		return fmt.Errorf("%w: Mcp-Name header value %q does not match body value %q", errHeaderMismatch, hn, target)
	}
	return nil
}

func rpcErrorBody(id json.RawMessage, code int, msg string, data any) map[string]any {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	e := map[string]any{"code": code, "message": msg}
	if data != nil {
		e["data"] = data
	}
	return map[string]any{"jsonrpc": "2.0", "id": id, "error": e}
}

func writeRPCError(w http.ResponseWriter, status int, id json.RawMessage, code int, msg string, data any) {
	writeJSON(w, status, rpcErrorBody(id, code, msg, data))
}

// mcpCall is one tools/call in a request body.
type mcpCall struct {
	msg  rpcMessage
	req  agentgateway.Request
	deny *Decision
}

func denyData(d Decision) map[string]any {
	m := map[string]any{"reason": d.Reason, "source": d.Source}
	if d.DecisionID != "" {
		m["decision_id"] = d.DecisionID
	}
	if d.PolicyID != "" {
		m["policy_id"] = d.PolicyID
	}
	return m
}

// decideToolCall applies pinning and then the PDP to one tools/call.
func (g *Gateway) decideToolCall(r *http.Request, s *MCPServer, subj agentgateway.Request, name string, args json.RawMessage, rid string) (agentgateway.Request, Decision, error) {
	digest, err := agentgateway.DigestArguments(args)
	if err != nil {
		return agentgateway.Request{}, Decision{}, fmt.Errorf("arguments are not valid JSON: %w", err)
	}
	req := subj
	req.Kind, req.Server, req.ServerURL, req.Tool = agentgateway.KindMCPTool, s.Name, s.URL, name
	req.ArgsDigest, req.RequestID, req.GatewayVersion = digest, rid, Version
	if *s.PinTools {
		state, pin := g.pins.Check(s.Name, name)
		switch {
		case state == PinChanged:
			req.DefinitionHash = pin.Pending
			d := Decision{Allowed: false, Reason: agentgateway.ReasonToolDefinitionChanged, Source: SourceGateway}
			g.up.Decision(req, d, "")
			return req, d, nil
		case state == PinUnknown && s.RequirePinned:
			d := Decision{Allowed: false, Reason: agentgateway.ReasonToolNotPinned, Source: SourceGateway}
			g.up.Decision(req, d, "")
			return req, d, nil
		case state == PinOK:
			req.DefinitionHash = pin.Hash
		}
	}
	return req, g.pdp.Decide(r.Context(), req), nil
}

func (g *Gateway) mcpHandler(s *MCPServer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subj, err := g.identify(r)
		if err != nil {
			writeRPCError(w, http.StatusUnauthorized, nil, rpcInvalidRequest, "an AuthSec agent credential is required", nil)
			return
		}
		switch r.Method {
		case http.MethodPost:
		case http.MethodGet, http.MethodDelete:
			// Pre-2026-07-28 standalone streams and session termination:
			// nothing to decide, passed through.
			g.forwardMCP(w, r, s, nil, false)
			return
		default:
			w.Header().Set("Allow", "POST, GET, DELETE")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, g.cfg.Limits.MaxBodyBytes))
		if err != nil {
			writeRPCError(w, http.StatusRequestEntityTooLarge, nil, rpcInvalidRequest, "request body too large", nil)
			return
		}
		trimmed := bytes.TrimSpace(body)
		var msgs []rpcMessage
		batch := len(trimmed) > 0 && trimmed[0] == '['
		if batch {
			err = json.Unmarshal(trimmed, &msgs)
		} else {
			var m rpcMessage
			err = json.Unmarshal(trimmed, &m)
			msgs = []rpcMessage{m}
		}
		if err != nil || len(msgs) == 0 {
			writeRPCError(w, http.StatusBadRequest, nil, rpcParseError, "the body must be a JSON-RPC message", nil)
			return
		}
		rid := newRequestID()
		var calls []mcpCall
		denied := false
		for _, m := range msgs {
			p, perr := m.named()
			if perr != nil {
				writeRPCError(w, http.StatusBadRequest, m.ID, rpcInvalidRequest, "params must be an object", nil)
				return
			}
			if !batch {
				if err := CheckMCPHeaders(r.Header, m, p); err != nil {
					writeRPCError(w, http.StatusBadRequest, m.ID, rpcHeaderMismatch, strings.TrimPrefix(err.Error(), errHeaderMismatch.Error()+": "), nil)
					return
				}
			}
			if m.Method != "tools/call" {
				continue
			}
			if p.Name == "" {
				writeRPCError(w, http.StatusBadRequest, m.ID, rpcInvalidRequest, "tools/call needs params.name", nil)
				return
			}
			req, d, derr := g.decideToolCall(r, s, subj, p.Name, p.Arguments, rid)
			if derr != nil {
				writeRPCError(w, http.StatusBadRequest, m.ID, rpcInvalidRequest, derr.Error(), nil)
				return
			}
			c := mcpCall{msg: m, req: req}
			if !d.Allowed {
				dd := d
				c.deny = &dd
				denied = true
				log.Printf("[agent-gateway] mcp deny agent=%s server=%s tool=%s reason=%s source=%s",
					subj.SubjectID, s.Name, p.Name, d.Reason, d.Source)
			}
			calls = append(calls, c)
		}
		if denied {
			if !batch {
				d := calls[0].deny
				writeRPCError(w, http.StatusOK, calls[0].msg.ID, RPCPolicyDenied,
					"AuthSec policy denied this tool call ("+d.Reason+")", denyData(*d))
				return
			}
			// A batch (protocol versions before 2025-06-18) is refused whole:
			// every request in it gets an error, nothing is forwarded.
			var out []map[string]any
			for _, m := range msgs {
				if !m.isRequest() {
					continue
				}
				var data any
				for _, c := range calls {
					if string(c.msg.ID) == string(m.ID) && c.deny != nil {
						data = denyData(*c.deny)
					}
				}
				out = append(out, rpcErrorBody(m.ID, RPCPolicyDenied,
					"AuthSec policy denied a tool call in this batch; nothing was executed", data))
			}
			writeJSON(w, http.StatusOK, out)
			return
		}
		listing := !batch && msgs[0].Method == "tools/list" && *s.PinTools
		g.forwardMCP(w, r, s, body, listing)
	})
}

// forwardMCP sends the request upstream with the server's configured
// headers and streams the response back; listing tees a tools/list response
// into the pin store.
func (g *Gateway) forwardMCP(w http.ResponseWriter, r *http.Request, s *MCPServer, body []byte, listing bool) {
	target := s.URL
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	up, err := http.NewRequestWithContext(r.Context(), r.Method, target, rd)
	if err != nil {
		writeRPCError(w, http.StatusBadGateway, nil, rpcInternalError, "bad upstream request", nil)
		return
	}
	copyHeaders(up.Header, r.Header, mcpForwardHeaders)
	for k, v := range s.Headers {
		up.Header.Set(k, v)
	}
	resp, err := g.upstream.Do(up)
	if err != nil {
		log.Printf("[agent-gateway] mcp upstream server=%s err=%v", s.Name, err)
		writeRPCError(w, http.StatusBadGateway, nil, rpcInternalError, "the MCP server could not be reached", nil)
		return
	}
	defer resp.Body.Close()
	var tee io.Writer
	var buf *boundedBuffer
	var sse *sseParser
	if listing && resp.StatusCode == http.StatusOK {
		if isEventStream(resp.Header.Get("Content-Type")) {
			sse = newSSEParser(8<<20, func(data []byte) { g.observeToolsList(s, data) })
			tee = sse
		} else {
			buf = &boundedBuffer{max: 8 << 20}
			tee = buf
		}
	}
	if err := copyResponse(w, resp, tee); err != nil {
		log.Printf("[agent-gateway] mcp stream server=%s err=%v", s.Name, err)
	}
	if sse != nil {
		sse.Close()
	}
	if buf != nil && !buf.overflow {
		g.observeToolsList(s, buf.buf.Bytes())
	}
}

// observeToolsList pins the tool definitions of a tools/list response.
func (g *Gateway) observeToolsList(s *MCPServer, raw []byte) {
	var resp struct {
		Result *struct {
			Tools []json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	if json.Unmarshal(raw, &resp) != nil || resp.Result == nil {
		return
	}
	for _, t := range resp.Result.Tools {
		name, h, err := ToolDefinitionHash(t)
		if err != nil {
			continue
		}
		if g.pins.Observe(s.Name, name, h) {
			log.Printf("[agent-gateway] tool definition changed server=%s tool=%s pending=%s: calls refused until approved",
				s.Name, name, h)
		}
	}
}
