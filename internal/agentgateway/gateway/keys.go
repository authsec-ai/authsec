package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/internal/agentgateway"
)

// Keys the gateway gets from AuthSec (W6).
//
// Provider keys: with provider_keys: authsec (the default) the gateway
// fetches the model provider keys AuthSec holds for it
// (GET /pdp/v1/provider-keys, agw_ credential) and keeps them in this
// process's memory for the ttl AuthSec gives, never on disk and never in a
// log line. A fetch that fails while a cached key is still valid keeps the
// cached key; once it lapses, model calls fail (503) until a fetch works.
//
// Agent keys: AuthSec-issued agent keys arrive in the policy hints
// (agent_keys: hash and bound workload identity). A key is accepted only
// together with the workload identity it is bound to (identify).

// AgentKeyHint is one AuthSec-issued agent key as the hints carry it.
type AgentKeyHint struct {
	ID         string   `json:"id"`
	ClientID   string   `json:"client_id"`
	KeySHA256  string   `json:"key_sha256"`
	SPIFFEID   string   `json:"spiffe_id,omitempty"`
	WorkloadID string   `json:"workload_id,omitempty"`
	IdentityID string   `json:"identity_id,omitempty"`
	Labels     []string `json:"labels,omitempty"`
	AgentID    string   `json:"agent_id,omitempty"`
}

// ProviderSecret is one fetched provider key (memory only).
type ProviderSecret struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Provider      string `json:"provider"`
	Key           string `json:"key"`
	Fingerprint   string `json:"fingerprint"`
	ProviderKeyID string `json:"provider_key_id,omitempty"`
}

// providerSecrets is GET /pdp/v1/provider-keys.
type providerSecrets struct {
	Keys       []ProviderSecret `json:"keys"`
	TTLSeconds int              `json:"ttl_seconds"`
}

// maxProviderKeyTTL bounds how long a fetched key is kept, whatever AuthSec says.
const maxProviderKeyTTL = 10 * time.Minute

var errProviderKeys = errors.New("provider keys unavailable")

// ProviderKeyStore holds the fetched provider keys in memory.
type ProviderKeyStore struct {
	pdp     *PDPClient
	mu      sync.Mutex
	keys    []ProviderSecret
	expires time.Time
	now     func() time.Time
}

func newProviderKeyStore(pdp *PDPClient) *ProviderKeyStore {
	return &ProviderKeyStore{pdp: pdp, now: time.Now}
}

// fetch reads the keys from AuthSec.
func (s *ProviderKeyStore) fetch(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := s.pdp.newRequest(ctx, http.MethodGet, "/pdp/v1/provider-keys", nil)
	if err != nil {
		return err
	}
	resp, err := s.pdp.hc.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", errProviderKeys, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		// The body is a message, never a key; still, only the status is logged.
		return fmt.Errorf("%w: status %d", errProviderKeys, resp.StatusCode)
	}
	var out providerSecrets
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("%w: bad response", errProviderKeys)
	}
	ttl := time.Duration(out.TTLSeconds) * time.Second
	if ttl <= 0 || ttl > maxProviderKeyTTL {
		ttl = maxProviderKeyTTL
	}
	s.keys, s.expires = out.Keys, s.now().Add(ttl)
	return nil
}

// Key returns the key for an upstream: by name or id when sel is set, else
// the only key of provider. It refreshes an expired set first.
func (s *ProviderKeyStore) Key(ctx context.Context, provider, sel string) (ProviderSecret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.now().Before(s.expires) {
		if err := s.fetch(ctx); err != nil {
			log.Printf("[agent-gateway] provider keys fetch failed: %v", err)
			return ProviderSecret{}, err
		}
	}
	var match []ProviderSecret
	for _, k := range s.keys {
		switch {
		case sel != "" && (k.ID == sel || strings.EqualFold(k.Name, sel)):
			return k, nil
		case sel == "" && strings.EqualFold(k.Provider, provider):
			match = append(match, k)
		}
	}
	if sel == "" && len(match) == 1 {
		return match[0], nil
	}
	if sel == "" && len(match) > 1 {
		return ProviderSecret{}, fmt.Errorf("%w: AuthSec holds %d keys for %s; name one in provider_key", errProviderKeys, len(match), provider)
	}
	return ProviderSecret{}, fmt.Errorf("%w: AuthSec holds no key for this upstream", errProviderKeys)
}

// Warm fetches once (startup); a failure is logged, calls retry.
func (s *ProviderKeyStore) Warm(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.fetch(ctx); err != nil {
		log.Printf("[agent-gateway] provider keys not fetched yet: %v", err)
	}
}

// Len is how many keys are held (tests, health).
func (s *ProviderKeyStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.keys)
}

/* ------------------------------------ holds --------------------------------- */

// HoldTicket is AuthSec's answer about a hold.
type HoldTicket struct {
	HoldID         string    `json:"hold_id"`
	State          string    `json:"state"`
	ExpiresAt      time.Time `json:"expires_at"`
	ApproverUserID string    `json:"approver_user_id,omitempty"`
	DecisionReason string    `json:"decision_reason,omitempty"`
}

// holdRequest is POST /pdp/v1/holds.
type holdRequest struct {
	Subject    *agentgateway.Entity          `json:"subject"`
	Action     *agentgateway.Action          `json:"action"`
	Resource   *agentgateway.Entity          `json:"resource"`
	ArgsDigest string                        `json:"args_digest"`
	RunID      string                        `json:"run_id,omitempty"`
	RequestID  string                        `json:"request_id,omitempty"`
	PolicyID   string                        `json:"policy_id"`
	Violations []agentgateway.BoundViolation `json:"violations"`
	HeldValues map[string]json.RawMessage    `json:"held_values,omitempty"`
}

var errHold = errors.New("hold failed")

func (c *PDPClient) holdCall(ctx context.Context, method, path string, body any) (HoldTicket, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := c.newRequest(ctx, method, path, body)
	if err != nil {
		return HoldTicket{}, 0, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return HoldTicket{}, 0, fmt.Errorf("%w: %v", errHold, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var t HoldTicket
	if resp.StatusCode >= 300 {
		return t, resp.StatusCode, fmt.Errorf("%w: status %d", errHold, resp.StatusCode)
	}
	if err := json.Unmarshal(raw, &t); err != nil || t.HoldID == "" {
		return t, resp.StatusCode, fmt.Errorf("%w: bad response", errHold)
	}
	return t, resp.StatusCode, nil
}

// CreateHold asks AuthSec to hold a call (the held values go to AuthSec
// only, for the approver).
func (c *PDPClient) CreateHold(ctx context.Context, r agentgateway.Request, policyID string, v []agentgateway.BoundViolation, held map[string]json.RawMessage) (HoldTicket, error) {
	e := r.ToAuthZEN()
	t, _, err := c.holdCall(ctx, http.MethodPost, "/pdp/v1/holds", holdRequest{Subject: e.Subject, Action: e.Action,
		Resource: e.Resource, ArgsDigest: r.ArgsDigest, RunID: r.RunID, RequestID: r.RequestID, PolicyID: policyID,
		Violations: v, HeldValues: held})
	return t, err
}

// HoldStatus reads a hold.
func (c *PDPClient) HoldStatus(ctx context.Context, id string) (HoldTicket, error) {
	t, _, err := c.holdCall(ctx, http.MethodGet, "/pdp/v1/holds/"+id, nil)
	return t, err
}

// ConsumeHold lets an approved hold's call through once.
func (c *PDPClient) ConsumeHold(ctx context.Context, id string, r agentgateway.Request) (HoldTicket, int, error) {
	return c.holdCall(ctx, http.MethodPost, "/pdp/v1/holds/"+id+"/consume", map[string]string{
		"subject_id": r.SubjectID, "resource_id": r.ResourceID(), "args_digest": r.ArgsDigest, "run_id": r.RunID})
}
