// Package connectoradapters holds the typed provider adapters the connector
// broker uses to perform outbound SaaS calls. Each adapter fixes the provider's
// base URL + method for a given action — there is NO caller-supplied URL, which
// is the SSRF guard. The broker injects the credential; the agent never sees it.
package connectoradapters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	defaultTimeout      = 15 * time.Second
	maxResponseBytes    = 1 << 20 // 1 MiB cap on provider responses
	maxRequestBodyBytes = 1 << 20
)

// Credential is the resolved secret material the broker injects. Adapters read
// only what they need (e.g. an OAuth access token). It is never logged or
// returned to the caller.
type Credential struct {
	AccessToken string
	TokenType   string // e.g. "Bearer"
	// Extra holds any additional provider-specific secret fields.
	Extra map[string]string
}

// Request is a typed action invocation: the action key + the caller's validated
// input. The adapter maps it onto a fixed provider endpoint.
type Request struct {
	ActionKey string
	Input     map[string]interface{}
}

// Result is the redacted provider outcome returned to the caller. It never
// contains credential material.
type Result struct {
	StatusCode int             `json:"status_code"`
	OK         bool            `json:"ok"`
	Body       json.RawMessage `json:"body,omitempty"`
	Note       string          `json:"note,omitempty"`
}

// Adapter implements a provider's action set. Implementations must NOT accept a
// caller-supplied URL; the endpoint + method are fixed per action.
type Adapter interface {
	// Key is the adapter_key stored on connector_actions (e.g. "slack").
	Key() string
	// Execute performs the action's fixed provider call with the injected
	// credential and returns a redacted result.
	Execute(ctx context.Context, cred Credential, req Request) (*Result, error)
}

// registry maps adapter_key → Adapter. Curated + compiled-in; no dynamic
// registration from user input.
var registry = map[string]Adapter{}

// Register adds an adapter to the registry. Called from adapter init().
func Register(a Adapter) { registry[a.Key()] = a }

// Get returns the adapter for a key, or false if unknown.
func Get(key string) (Adapter, bool) {
	a, ok := registry[key]
	return a, ok
}

// doJSON performs the fixed outbound HTTP call with a timeout, size cap, and
// JSON body, returning a redacted Result. The endpoint is adapter-fixed — this
// helper never takes a caller URL.
func doJSON(ctx context.Context, method, endpoint string, cred Credential, payload interface{}) (*Result, error) {
	var bodyReader io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		if len(b) > maxRequestBodyBytes {
			return nil, fmt.Errorf("request body exceeds cap")
		}
		bodyReader = bytes.NewReader(b)
	}

	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	tokenType := cred.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}
	if cred.AccessToken != "" {
		req.Header.Set("Authorization", tokenType+" "+cred.AccessToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("provider call: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	result := &Result{StatusCode: resp.StatusCode, OK: resp.StatusCode < 400}
	if json.Valid(raw) {
		result.Body = raw
	} else if len(raw) > 0 {
		result.Note = string(raw)
	}
	return result, nil
}

// requiredString pulls a required string field from the typed input.
func requiredString(in map[string]interface{}, key string) (string, error) {
	v, ok := in[key]
	if !ok {
		return "", fmt.Errorf("missing required field %q", key)
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("field %q must be a non-empty string", key)
	}
	return s, nil
}

// optionalString pulls an optional string field (empty if absent).
func optionalString(in map[string]interface{}, key string) string {
	if v, ok := in[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
