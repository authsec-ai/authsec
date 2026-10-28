package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/authsec-ai/authsec/internal/runtimepolicy/compile"
	"github.com/authsec-ai/authsec/internal/runtimepolicy/profiles"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// ErrOpenShellUnsupported is returned by OpenShell compilation methods until
// a pinned OpenShell build has been qualified and integrated.
var ErrOpenShellUnsupported = errors.New("openshell: compilation not available — no pinned OpenShell build qualified")

// PolicyCompiler compiles V2 documents into backend-specific artifacts.
// It delegates to the compile package for validation and rule translation,
// then adds backend-specific processing.
type PolicyCompiler struct {
	reg       *profiles.Registry
	validator *PolicyV2Validator
}

// NewPolicyCompiler creates a new compiler with the given profile registry.
func NewPolicyCompiler(reg *profiles.Registry) *PolicyCompiler {
	if reg == nil {
		reg = &profiles.Registry{}
	}
	return &PolicyCompiler{reg: reg, validator: NewPolicyV2Validator()}
}

// CompileResult is the output of backend-specific compilation.
type CompileResult struct {
	CanonicalHash    string                   `json:"canonical_hash"`
	ArtifactSHA256   string                   `json:"artifact_sha256"`
	RuleMap          []compile.V2RuleMapEntry  `json:"rule_map"`
	NativePlan       json.RawMessage          `json:"native_plan,omitempty"`
	TypedControlPlan json.RawMessage          `json:"typed_control_plan,omitempty"`
	CapabilityDigest string                   `json:"capability_digest"`
	Unsupported      []compile.V2FieldError   `json:"unsupported,omitempty"`
	BackendProfile   string                   `json:"backend_profile"`
	CompilerVersion  string                   `json:"compiler_version"`
}

// CompilerVersion is the build identifier for this compiler.
const CompilerVersion = "authsec.compiler.v2.0"

// Compile compiles a validated V2 document for its designated backend.
// It performs capability negotiation, rule-to-artifact mapping, and plan hashing.
func (c *PolicyCompiler) Compile(ctx context.Context, cat compile.Catalog, workspaceID uuid.UUID, revision int, doc models.RuntimePolicyV2Document) (*CompileResult, error) {
	// Validate the document.
	result := compile.ValidateV2(doc)
	if !result.Valid {
		return nil, &StatusError{
			Status:  422,
			Code:    "validation_failed",
			Message: fmt.Sprintf("%d validation error(s)", len(result.Errors)),
			Extra:   map[string]any{"errors": result.Errors},
		}
	}

	// Check backend compatibility.
	backendErrs := c.validator.CheckBackendCompatibility(doc)

	// Compile using the compile package.
	v2Result, err := compile.CompileV2(ctx, c.reg, cat, workspaceID, revision, doc)
	if err != nil {
		return nil, statusFrom(err)
	}

	profile := doc.Enforcement.Profile
	if profile == "" {
		profile = defaultProfileForBackend(doc.Enforcement.Backend)
	}

	// Build backend-specific native plan.
	nativePlan, err := buildNativePlan(doc.Enforcement.Backend, v2Result)
	if err != nil {
		return nil, err
	}

	// Compute plan hash from the native plan + rule map.
	planHash := computePlanHash(v2Result.RuleMap, nativePlan)

	return &CompileResult{
		CanonicalHash:    v2Result.CanonicalHash,
		ArtifactSHA256:   planHash,
		RuleMap:          v2Result.RuleMap,
		NativePlan:       nativePlan,
		TypedControlPlan: v2Result.TypedControlPlan,
		CapabilityDigest: v2Result.CapabilityDigest,
		Unsupported:      backendErrs,
		BackendProfile:   profile,
		CompilerVersion:  CompilerVersion,
	}, nil
}

// OpenShellRuleMapping maps a canonical rule ID to its OpenShell-native
// control references. This is a stub type that will be populated once real
// OpenShell compilation is available.
type OpenShellRuleMapping struct {
	RuleID         string   `json:"rule_id"`
	NativeControls []string `json:"native_controls"` // OpenShell control IDs
	Supported      bool     `json:"supported"`
	Reason         string   `json:"reason,omitempty"`
}

// CompileForOpenShell compiles a V2 policy document targeting the OpenShell (B)
// backend. It translates typed controls to OpenShell native format and retains
// rule ID mapping for traceability. This is a stub: it returns
// ErrOpenShellUnsupported until a pinned OpenShell build is qualified.
func (c *PolicyCompiler) CompileForOpenShell(ctx context.Context, doc json.RawMessage, rules []json.RawMessage) (*CompileResult, error) {
	_ = ctx
	_ = doc
	_ = rules
	return nil, ErrOpenShellUnsupported
}

// MapRulesForOpenShell generates per-rule OpenShell native control mappings
// from canonical rule definitions. This is a stub: it returns
// ErrOpenShellUnsupported until a pinned OpenShell build is qualified.
func (c *PolicyCompiler) MapRulesForOpenShell(rules []json.RawMessage) ([]OpenShellRuleMapping, error) {
	_ = rules
	return nil, ErrOpenShellUnsupported
}

// buildNativePlan generates backend-specific plan artifacts.
func buildNativePlan(backend string, v2Result *compile.CompileV2Result) (json.RawMessage, error) {
	switch backend {
	case models.EnforcementBackendAuthSec:
		// AuthSec native plan: typed control plan is primary; OPA is optional
		// and only included when gateway broker rules are present.
		plan := map[string]any{
			"backend":            "authsec",
			"typed_control_plan": json.RawMessage(v2Result.TypedControlPlan),
			"controls":           json.RawMessage(v2Result.Controls),
		}
		// OPA fields are optional — only for gateway broker decisions.
		if v2Result.Rego != "" {
			plan["rego"] = v2Result.Rego
			plan["data"] = v2Result.Data
			plan["entry_point"] = v2Result.Semantic.EntryPoint
		}
		raw, err := json.Marshal(plan)
		if err != nil {
			return nil, err
		}
		return raw, nil

	case models.EnforcementBackendOpenShell:
		// OpenShell native plan is a stub — real compilation requires
		// a pinned OpenShell build which is not yet available.
		plan := map[string]any{
			"backend":     "openshell",
			"status":      "stub",
			"controls":    json.RawMessage(v2Result.Controls),
			"rule_map":    v2Result.RuleMap,
			"message":     "OpenShell compilation requires a qualified build",
		}
		raw, err := json.Marshal(plan)
		if err != nil {
			return nil, err
		}
		return raw, nil

	default:
		return nil, &StatusError{Status: 422, Code: "unknown_backend", Message: "unknown enforcement backend: " + backend}
	}
}

func computePlanHash(ruleMap []compile.V2RuleMapEntry, controls json.RawMessage) string {
	data := map[string]any{
		"rule_map": ruleMap,
		"controls": json.RawMessage(controls),
		"version":  CompilerVersion,
	}
	raw, _ := json.Marshal(data)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func defaultProfileForBackend(backend string) string {
	switch backend {
	case models.EnforcementBackendAuthSec:
		return "linux-managed-v1"
	case models.EnforcementBackendOpenShell:
		return "linux-managed-v1"
	default:
		return "linux-managed-v1"
	}
}
