package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/internal/agentgateway"
)

// Tool-definition pinning (spec §4 "tool rug pull"): every tool definition a
// server returns from tools/list is hashed (sha256 of its RFC 8785 form,
// without _meta). The first hash seen for (server, tool) is pinned (trust on
// first use) unless the configuration pre-pins one. A later, different hash
// is kept as pending and the tool is refused (tool_definition_changed) until
// an operator approves the new hash on the local admin API or in the pin
// file.

// Pin states.
const (
	PinUnknown = "unknown"
	PinOK      = "ok"
	PinChanged = "changed"
)

// Pin is one tool's pinned definition.
type Pin struct {
	Server    string    `json:"server"`
	Tool      string    `json:"tool"`
	Hash      string    `json:"hash"`
	Pending   string    `json:"pending,omitempty"`
	PinnedAt  time.Time `json:"pinned_at"`
	ChangedAt time.Time `json:"changed_at,omitempty"`
}

// PinStore holds the pins, optionally persisted to a JSON file.
type PinStore struct {
	mu   sync.Mutex
	path string
	pins map[string]*Pin
	now  func() time.Time
}

func pinKey(server, tool string) string { return server + "\x1f" + tool }

// NewPinStore loads path (when set and present).
func NewPinStore(path string) (*PinStore, error) {
	s := &PinStore{path: path, pins: map[string]*Pin{}, now: time.Now}
	if path == "" {
		return s, nil
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read pin store: %w", err)
	}
	var list []Pin
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("parse pin store: %w", err)
	}
	for i := range list {
		p := list[i]
		s.pins[pinKey(p.Server, p.Tool)] = &p
	}
	return s, nil
}

// Seed pre-approves a hash (from the configuration).
func (s *PinStore) Seed(server, tool, hash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := pinKey(server, tool)
	if p, ok := s.pins[k]; ok && p.Hash == hash {
		return
	}
	s.pins[k] = &Pin{Server: server, Tool: tool, Hash: hash, PinnedAt: s.now().UTC()}
}

// saveLocked writes the file atomically (caller holds mu).
func (s *PinStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	list := make([]Pin, 0, len(s.pins))
	for _, p := range s.pins {
		list = append(list, *p)
	}
	sort.Slice(list, func(i, j int) bool {
		return pinKey(list[i].Server, list[i].Tool) < pinKey(list[j].Server, list[j].Tool)
	})
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".pins-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

// Observe records a definition seen in tools/list; it reports whether the
// hash differs from the pinned one (a change).
func (s *PinStore) Observe(server, tool, hash string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := pinKey(server, tool)
	p, ok := s.pins[k]
	switch {
	case !ok:
		s.pins[k] = &Pin{Server: server, Tool: tool, Hash: hash, PinnedAt: s.now().UTC()}
	case p.Hash == hash:
		if p.Pending == "" {
			return false
		}
		// The server went back to the approved definition.
		p.Pending = ""
	case p.Pending == hash:
		return true
	default:
		p.Pending, p.ChangedAt = hash, s.now().UTC()
	}
	_ = s.saveLocked()
	return ok && p.Pending != ""
}

// Check is the state of a tool before a call.
func (s *PinStore) Check(server, tool string) (string, Pin) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pins[pinKey(server, tool)]
	if !ok {
		return PinUnknown, Pin{}
	}
	if p.Pending != "" {
		return PinChanged, *p
	}
	return PinOK, *p
}

// Approve pins hash (default: the pending one) as the tool's definition.
func (s *PinStore) Approve(server, tool, hash string) (Pin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pins[pinKey(server, tool)]
	if !ok {
		return Pin{}, fmt.Errorf("no pin for %s/%s", server, tool)
	}
	if hash == "" {
		hash = p.Pending
	}
	if hash == "" {
		return *p, nil
	}
	if !agentgateway.ValidDigest(hash) {
		return Pin{}, fmt.Errorf("hash must be sha256:<64 hex>")
	}
	if hash != p.Hash && hash != p.Pending {
		return Pin{}, fmt.Errorf("hash is neither the pinned nor the pending definition")
	}
	p.Hash, p.Pending, p.PinnedAt = hash, "", s.now().UTC()
	return *p, s.saveLocked()
}

// List returns every pin.
func (s *PinStore) List() []Pin {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Pin, 0, len(s.pins))
	for _, p := range s.pins {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return pinKey(out[i].Server, out[i].Tool) < pinKey(out[j].Server, out[j].Tool) })
	return out
}

// ToolDefinitionHash hashes one tool definition: sha256 of the RFC 8785 form
// of the object without _meta. It returns the tool's name too.
func ToolDefinitionHash(def json.RawMessage) (string, string, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(def, &m); err != nil {
		return "", "", err
	}
	var name string
	if err := json.Unmarshal(m["name"], &name); err != nil || name == "" {
		return "", "", fmt.Errorf("tool without a name")
	}
	delete(m, "_meta")
	raw, err := json.Marshal(m)
	if err != nil {
		return "", "", err
	}
	h, err := agentgateway.DigestArguments(raw)
	return name, h, err
}
