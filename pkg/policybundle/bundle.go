// Package policybundle implements the signed binary policy container format
// (.aspol). The container holds a deterministic binary representation of:
//
//   - A header with format version, compiler info, and backend targeting
//   - The canonical source document with hashes
//   - A rule-to-native-control map
//   - A backend-specific native plan (OPA Wasm, launcher params, etc.)
//   - A local decision artifact (optional OPA Wasm + scoped data)
//   - A dependency declaration (runtime ABI, builtins, adapter versions)
//   - A probe plan for post-activation verification
//
// Serialization uses JSON encoding with deterministic key ordering. The
// container is SHA-256 hashed for integrity. Maximum container size is 16 MiB.
package policybundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// MaxBundleSize is the maximum allowed bundle size in bytes (16 MiB).
const MaxBundleSize = 16 << 20

var (
	ErrBundleTooLarge  = errors.New("policybundle: bundle exceeds 16 MiB limit")
	ErrInvalidBundle   = errors.New("policybundle: invalid bundle structure")
	ErrHashMismatch    = errors.New("policybundle: content hash does not match")
)

// Bundle is the top-level policy container.
type Bundle struct {
	Header        Header        `json:"header"`
	Source        Source        `json:"source"`
	RuleMap       []RuleMapEntry `json:"rule_map"`
	NativePlan    json.RawMessage `json:"native_plan"`
	LocalDecision *LocalDecision `json:"local_decision,omitempty"`
	Dependencies  Dependencies  `json:"dependencies"`
	ProbePlan     ProbePlan     `json:"probe_plan"`
}

// Header identifies the bundle format and targeting.
type Header struct {
	FormatVersion    string `json:"format_version"`    // "aspol.v1"
	CompilerBuild    string `json:"compiler_build"`
	SchemaVersions   []string `json:"schema_versions"`
	WorkloadTarget   string `json:"workload_target"`
	Backend          string `json:"backend"`           // "authsec" or "openshell"
	Profile          string `json:"profile"`
	CapabilityDigest string `json:"capability_digest"`
}

// Source is the canonical policy document with integrity hashes.
type Source struct {
	JSON             json.RawMessage `json:"json"`
	AuthoredModules  []SourceModule  `json:"authored_modules,omitempty"`
	GeneratedRego    string          `json:"generated_rego,omitempty"`
	SourceHashes     SourceHashes    `json:"source_hashes"`
}

// SourceModule is one authored or generated module included in the bundle.
type SourceModule struct {
	Name     string `json:"name"`
	Language string `json:"language"`
	Source   string `json:"source"`
	Hash     string `json:"hash"` // SHA-256 of source
}

// SourceHashes provides integrity verification for the source document.
type SourceHashes struct {
	DocumentSHA256 string `json:"document_sha256"`
	RegoSHA256     string `json:"rego_sha256,omitempty"`
	ModuleHashes   map[string]string `json:"module_hashes,omitempty"`
}

// RuleMapEntry maps a policy rule to its backend-specific native controls.
type RuleMapEntry struct {
	RuleID            string   `json:"rule_id"`
	Primitive         string   `json:"primitive"`
	NativeControls    []string `json:"native_controls"`
	ResourceDecisions []string `json:"resource_decisions,omitempty"`
}

// LocalDecision holds the OPA Wasm artifact for local policy evaluation.
type LocalDecision struct {
	OPAWasm    []byte         `json:"opa_wasm,omitempty"`
	ScopedData json.RawMessage `json:"scoped_data,omitempty"`
}

// Dependencies declares the runtime requirements for the bundle.
type Dependencies struct {
	RuntimeABI       string            `json:"runtime_abi"`
	Builtins         []string          `json:"builtins,omitempty"`
	AdapterVersions  map[string]string `json:"adapter_versions,omitempty"`
	RequiredControls []string          `json:"required_controls"`
}

// ProbePlan defines post-activation verification checks.
type ProbePlan struct {
	Probes []Probe `json:"probes"`
}

// Probe is one verification check to run after bundle activation.
type Probe struct {
	ID       string         `json:"id"`
	Type     string         `json:"type"` // "active", "passive", "connectivity"
	Target   string         `json:"target"`
	Expected string         `json:"expected"`
	Params   map[string]any `json:"params,omitempty"`
}

// Serialize encodes the bundle to deterministic JSON bytes.
func (b *Bundle) Serialize() ([]byte, error) {
	data, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("policybundle: marshal: %w", err)
	}
	if len(data) > MaxBundleSize {
		return nil, ErrBundleTooLarge
	}
	return data, nil
}

// Deserialize decodes a bundle from JSON bytes.
func Deserialize(data []byte) (*Bundle, error) {
	if len(data) > MaxBundleSize {
		return nil, ErrBundleTooLarge
	}
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("policybundle: unmarshal: %w", err)
	}
	if b.Header.FormatVersion == "" {
		return nil, ErrInvalidBundle
	}
	return &b, nil
}

// SHA256 computes the SHA-256 hash of the serialized bundle.
func (b *Bundle) SHA256() (string, error) {
	data, err := b.Serialize()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// ComputeSourceHashes computes SHA-256 hashes for all source components.
func ComputeSourceHashes(docJSON []byte, rego string, modules []SourceModule) SourceHashes {
	docSum := sha256.Sum256(docJSON)
	h := SourceHashes{
		DocumentSHA256: hex.EncodeToString(docSum[:]),
	}
	if rego != "" {
		regoSum := sha256.Sum256([]byte(rego))
		h.RegoSHA256 = hex.EncodeToString(regoSum[:])
	}
	if len(modules) > 0 {
		h.ModuleHashes = make(map[string]string, len(modules))
		names := make([]string, 0, len(modules))
		for _, m := range modules {
			names = append(names, m.Name)
		}
		sort.Strings(names)
		for _, name := range names {
			for _, m := range modules {
				if m.Name == name {
					sum := sha256.Sum256([]byte(m.Source))
					h.ModuleHashes[name] = hex.EncodeToString(sum[:])
					break
				}
			}
		}
	}
	return h
}
