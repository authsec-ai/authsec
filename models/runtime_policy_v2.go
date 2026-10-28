package models

// Runtime policy V2 document types. These are the JSON schema types stored as
// JSONB in RuntimePolicyRevision.Document. They are not GORM models; they
// define the wire format for the authsec.runtime.v2 policy schema.
//
// V2 adds backend-agnostic rules, per-backend compilation, escalation configs,
// decision modules, rule provenance, and primitive coverage tracking.

// RuntimePolicyV2Document is the top-level V2 policy document. It replaces the
// V1 compile.Document for policies that need backend selection, escalation, or
// the expanded primitive catalog.
type RuntimePolicyV2Document struct {
	Name                  string              `json:"name"`
	Format                string              `json:"format"` // "authsec.runtime.v2"
	Targets               PolicyV2TargetSet   `json:"targets"`
	DefaultEffect         string              `json:"default_effect"` // "deny" required
	Enforcement           PolicyEnforcement    `json:"enforcement"`
	Rules                 []PolicyV2Rule       `json:"rules"`
	Escalations           []PolicyEscalation   `json:"escalations,omitempty"`
	DecisionModules       []PolicyDecisionModule `json:"decision_modules,omitempty"`
	RequiredControls      []string             `json:"required_controls"`
	OptionalControls      []string             `json:"optional_controls,omitempty"`
	EvidenceGraphRevision int64                `json:"evidence_graph_revision"`
	Mode                  string               `json:"mode,omitempty"`
	AuthoredModules       []AuthoredModule     `json:"authored_modules,omitempty"`
}

// PolicyV2TargetSet extends V1 targets with selector support and workload
// identity qualifiers.
type PolicyV2TargetSet struct {
	WorkloadIDs               []string            `json:"workload_ids"`
	IncludeFutureIncarnations bool                `json:"include_future_incarnations"`
	BoundedFutureApproval     bool                `json:"bounded_future_approval,omitempty"`
	Selectors                 []PolicyV2Selector  `json:"selectors,omitempty"`
}

// PolicyV2Selector matches workloads by attribute rather than explicit ID.
type PolicyV2Selector struct {
	RuntimeKind string            `json:"runtime_kind,omitempty"` // "linux", "k8s"
	Namespace   string            `json:"namespace,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Archetype   string            `json:"archetype,omitempty"`
}

// PolicyEnforcement specifies the enforcement backend and mode for this policy.
type PolicyEnforcement struct {
	Backend string `json:"backend"`           // "authsec", "openshell"
	Mode    string `json:"mode"`              // "observe", "shadow", "enforce"
	Profile string `json:"profile,omitempty"` // e.g. "linux-managed-v1", "k8s-admission-v1"
}

// PolicyV2Rule is a backend-agnostic rule using the canonical primitive catalog.
// Each rule references a primitive (e.g. file.read, network.connect) and
// specifies constraints that the compiler translates to backend-specific controls.
type PolicyV2Rule struct {
	ID             string                 `json:"id"`
	Primitive      string                 `json:"primitive"`                // canonical primitive id
	Resource       string                 `json:"resource,omitempty"`       // resource UUID or path
	Actions        []string               `json:"actions,omitempty"`        // sub-actions within primitive
	Constraints    map[string]interface{} `json:"constraints,omitempty"`    // primitive-specific constraints
	Effect         string                 `json:"effect"`                   // "allow", "deny", "require_approval"
	EscalationRef  string                 `json:"escalation_ref,omitempty"` // named escalation config
	Required       bool                   `json:"required"`                 // must be enforceable
	EvidenceRefs   []string               `json:"evidence_refs,omitempty"`  // observation evidence IDs
	Explanation    string                 `json:"explanation,omitempty"`    // human-readable reason
	Provenance     *RuleProvenance        `json:"provenance,omitempty"`     // origin tracking
}

// RuleProvenance tracks where a rule came from: manual authoring, candidate
// generation, or evidence-based suggestion.
type RuleProvenance struct {
	Source          string `json:"source"`                     // "manual", "candidate", "evidence"
	CandidateID     string `json:"candidate_id,omitempty"`    // if generated
	EvidenceWindow  string `json:"evidence_window,omitempty"` // observation time range
	GeneratorVersion string `json:"generator_version,omitempty"`
}

// PolicyEscalation is a named escalation configuration referenced by rules
// with effect "require_approval". Multiple rules can share an escalation config.
type PolicyEscalation struct {
	Name             string   `json:"name"`
	Enabled          bool     `json:"enabled"`
	ApproverGroupIDs []string `json:"approver_group_ids"`
	MinApprovals     int      `json:"min_approvals,omitempty"`
	MFAProvider      string   `json:"mfa_provider,omitempty"`  // "authnull", "totp", "webauthn"
	MFALevel         string   `json:"mfa_level,omitempty"`     // "possession", "biometric"
	MaxUses          int      `json:"max_uses,omitempty"`      // 0 = unlimited
	MaxTTLSeconds    int      `json:"max_ttl_seconds,omitempty"`
	SelfApproval     string   `json:"self_approval,omitempty"` // "deny", "allow", "require_mfa"
	TimeoutSeconds   int      `json:"timeout_seconds,omitempty"`
}

// PolicyDecisionModule is a named decision logic module that augments the
// standard allow/deny/require_approval pipeline. Decision modules are
// evaluated after rule matching and can add obligations or modify effects.
type PolicyDecisionModule struct {
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`                 // "opa_constraint", "rate_limit", "time_window"
	Parameters map[string]interface{} `json:"parameters,omitempty"`
	Priority   int                    `json:"priority,omitempty"`
}

// AuthoredModule is a user-written constraint module that participates in
// policy evaluation. These are validated and versioned alongside the policy
// document.
type AuthoredModule struct {
	Name     string `json:"name"`
	Language string `json:"language"` // "rego"
	Source   string `json:"source"`
	Hash     string `json:"hash,omitempty"` // SHA-256 of source
}

// Valid enforcement backends.
const (
	EnforcementBackendAuthSec   = "authsec"
	EnforcementBackendOpenShell = "openshell"
)

// V2 enforcement modes for the policy-level enforcement config.
// EnforcementModeObserve is already declared in enforcement_plan.go.
const (
	V2EnforcementModeShadow  = "shadow"
	V2EnforcementModeEnforce = "enforce"
)

// ValidEnforcementBackends returns the allowed enforcement backend values.
func ValidEnforcementBackends() []string {
	return []string{EnforcementBackendAuthSec, EnforcementBackendOpenShell}
}

// ValidV2EnforcementModes returns the allowed V2 policy enforcement mode values.
func ValidV2EnforcementModes() []string {
	return []string{EnforcementModeObserve, V2EnforcementModeShadow, V2EnforcementModeEnforce}
}
