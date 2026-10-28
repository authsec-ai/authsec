package compile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/authsec-ai/authsec/internal/runtimepolicy/opa"
	"github.com/authsec-ai/authsec/internal/runtimepolicy/profiles"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

const (
	// FormatV2 is the V2 policy schema identifier.
	FormatV2 = "authsec.runtime.v2"

	// ControlsSchemaV2 is the V2 controls artifact version.
	ControlsSchemaV2 = "authsec.controls.v2"
)

// V2FieldError is a validation error with a JSON pointer to the offending field.
type V2FieldError struct {
	Pointer string `json:"pointer"` // e.g. "/rules/0/primitive"
	Code    string `json:"code"`
	Message string `json:"message"`
}

// V2ValidationResult collects all V2 document validation errors.
type V2ValidationResult struct {
	Valid  bool           `json:"valid"`
	Errors []V2FieldError `json:"errors"`
}

// CompileV2Result is the output of V2 compilation for a specific backend.
type CompileV2Result struct {
	CanonicalHash    string          `json:"canonical_hash"`
	ArtifactSHA256   string          `json:"artifact_sha256"`
	RuleMap          []V2RuleMapEntry `json:"rule_map"`
	NativePlan       json.RawMessage `json:"native_plan"`
	CapabilityDigest string          `json:"capability_digest"`
	Unsupported      []V2FieldError  `json:"unsupported,omitempty"`

	// Typed control plan — primary artifact for AuthSec native enforcement.
	// OPA Rego is only generated when gateway broker rules are present.
	TypedControlPlan json.RawMessage `json:"typed_control_plan,omitempty"`

	// Standard compilation outputs carried forward from V1.
	// These are only populated when HasGatewayBrokerRules() is true.
	Rego         string
	Data         map[string]any
	Controls     json.RawMessage
	Semantic     SemanticReport
	Canonical    []byte
	ContentHash  string
	TargetDigest string
	Manifest     []ManifestEntry
}

// V2RuleMapEntry maps a V2 rule to its backend-specific native controls.
type V2RuleMapEntry struct {
	RuleID         string   `json:"rule_id"`
	Primitive      string   `json:"primitive"`
	NativeControls []string `json:"native_controls"`
	Decisions      []string `json:"resource_decisions,omitempty"`
}

// ParseV2 decodes and validates a V2 document. Unknown JSON fields are rejected.
func ParseV2(raw []byte) (models.RuntimePolicyV2Document, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc models.RuntimePolicyV2Document
	if err := dec.Decode(&doc); err != nil {
		return models.RuntimePolicyV2Document{}, &Error{Code: "invalid_document", Message: err.Error()}
	}
	if dec.More() {
		return models.RuntimePolicyV2Document{}, &Error{Code: "invalid_document", Message: "trailing data after the document"}
	}
	if err := staticV2(doc); err != nil {
		return models.RuntimePolicyV2Document{}, err
	}
	return doc, nil
}

// ValidateV2 performs full structural and semantic validation on a V2 document.
// It returns field-specific errors with JSON pointers.
func ValidateV2(doc models.RuntimePolicyV2Document) V2ValidationResult {
	var errs []V2FieldError

	// Format validation.
	if doc.Format != FormatV2 {
		errs = append(errs, V2FieldError{Pointer: "/format", Code: "invalid_format", Message: "format must be " + FormatV2})
	}
	if doc.Name == "" {
		errs = append(errs, V2FieldError{Pointer: "/name", Code: "required", Message: "name is required"})
	}
	if doc.DefaultEffect != "deny" {
		errs = append(errs, V2FieldError{Pointer: "/default_effect", Code: "invalid_value", Message: "default_effect must be deny"})
	}

	// Enforcement validation.
	errs = append(errs, validateEnforcement(doc.Enforcement)...)

	// Target validation.
	if len(doc.Targets.WorkloadIDs) == 0 && len(doc.Targets.Selectors) == 0 {
		errs = append(errs, V2FieldError{Pointer: "/targets", Code: "scope_required", Message: "at least one workload_id or selector is required"})
	}
	if doc.Targets.IncludeFutureIncarnations && !doc.Targets.BoundedFutureApproval {
		errs = append(errs, V2FieldError{Pointer: "/targets/include_future_incarnations", Code: "future_incarnations_unbounded", Message: "requires bounded_future_approval"})
	}

	// Rule validation: unique IDs, valid primitives, effect compatibility, escalation refs.
	errs = append(errs, validateV2Rules(doc)...)

	// Escalation validation.
	errs = append(errs, validateEscalations(doc)...)

	// Decision module validation.
	errs = append(errs, validateDecisionModules(doc.DecisionModules)...)

	// Authored module validation.
	errs = append(errs, validateAuthoredModules(doc.AuthoredModules)...)

	return V2ValidationResult{Valid: len(errs) == 0, Errors: errs}
}

// CompileV2 compiles a validated V2 document for a specific backend. It
// translates primitive-based rules to backend-specific controls and generates
// the compilation outputs.
func CompileV2(ctx context.Context, reg *profiles.Registry, cat Catalog, workspaceID uuid.UUID, revision int, doc models.RuntimePolicyV2Document) (*CompileV2Result, error) {
	result := ValidateV2(doc)
	if !result.Valid {
		return nil, &Error{
			Code:    "validation_failed",
			Message: fmt.Sprintf("%d validation error(s)", len(result.Errors)),
			Details: map[string]any{"errors": result.Errors},
		}
	}

	profile := doc.Enforcement.Profile
	if profile == "" {
		profile = defaultProfileForBackend(doc.Enforcement.Backend)
	}
	if reg != nil && !reg.Known(profile) {
		return nil, &Error{Code: "unknown_profile", Message: "profile is not in the certified registry"}
	}

	// Compute canonical hash.
	canonical, hash, err := CanonicalV2(doc)
	if err != nil {
		return nil, err
	}

	// Resolve workload targets.
	manifest := make([]ManifestEntry, 0, len(doc.Targets.WorkloadIDs))
	for _, id := range doc.Targets.WorkloadIDs {
		wid, err := uuid.Parse(id)
		if err != nil {
			return nil, &Error{Code: "unresolved_target", Message: "workload id is not a uuid"}
		}
		w, err := cat.ResolveWorkload(ctx, workspaceID, wid)
		if err != nil {
			return nil, mapResolve(err, "workload")
		}
		if len(w.RuntimeInstanceIDs) == 0 {
			manifest = append(manifest, ManifestEntry{WorkloadID: wid.String()})
			continue
		}
		for _, inst := range w.RuntimeInstanceIDs {
			manifest = append(manifest, ManifestEntry{WorkloadID: wid.String(), RuntimeInstanceID: inst.String()})
		}
	}

	// Translate V2 rules to V1 rules for OPA data generation.
	v1Rules, ruleMap, err := translateRules(ctx, cat, workspaceID, doc.Rules)
	if err != nil {
		return nil, err
	}

	// Build OPA data.
	dataRules := make([]map[string]any, 0, len(v1Rules))
	reports := make([]RuleReport, 0, len(v1Rules))
	controls := newControls(profile, reg)

	for i, rule := range v1Rules {
		row := map[string]any{
			"id": rule.ID, "action": rule.Action, "effect": rule.Effect,
		}
		if rule.Adapter != "" {
			row["adapter"] = rule.Adapter
		}
		rep := RuleReport{
			ID: rule.ID, OPAEntryPoint: opa.Query,
			EnforcementAdapter:    adapterFor(rule.Action),
			RequiredCapabilities:  capabilitiesFor(rule),
			UnsupportedDimensions: []string{},
		}

		switch rule.Action {
		case "network.connect":
			if rule.ResourceID != "" {
				n, err := resolveRuleResource(ctx, cat, workspaceID, rule.ResourceID)
				if err != nil {
					return nil, err
				}
				row["resource_id"] = rule.ResourceID
				scope := map[string]any{"address": n.Address, "port": n.Port, "protocol": n.Protocol, "resource_id": rule.ResourceID}
				rep.NativeScope = scope
				controls.Egress = append(controls.Egress, egressRule{RuleID: rule.ID, ResourceID: rule.ResourceID, Address: n.Address, Port: n.Port, Protocol: n.Protocol, Effect: rule.Effect})
			}
		case "file.read", "file.write":
			if rule.Path != "" {
				row["path"] = rule.Path
				rep.NativeScope = map[string]any{"path": rule.Path, "baseline": controls.Filesystem.Baseline}
				controls.Filesystem.Paths = append(controls.Filesystem.Paths, pathRule{RuleID: rule.ID, Path: rule.Path, Effect: rule.Effect})
			}
		case "exec":
			rep.NativeScope = map[string]any{"privilege": "drop", "no_new_privs": true}
			controls.Exec = append(controls.Exec, idEffect{RuleID: rule.ID, Effect: rule.Effect})
		case "secret.read":
			if rule.Adapter != "" && rule.ResourceID != "" {
				ok, err := cat.BrokerConfigured(ctx, workspaceID, rule.Adapter)
				if err != nil {
					return nil, err
				}
				if !ok {
					return nil, &Error{Code: "broker_not_configured", Message: "adapter " + rule.Adapter + " is not a configured broker path"}
				}
				n, err := resolveRuleResource(ctx, cat, workspaceID, rule.ResourceID)
				if err != nil {
					return nil, err
				}
				row["resource_id"] = rule.ResourceID
				rep.NativeScope = map[string]any{"adapter": rule.Adapter, "resource_id": rule.ResourceID, "broker_path": n.BrokerPath}
				controls.Broker = append(controls.Broker, brokerRule{RuleID: rule.ID, ResourceID: rule.ResourceID, Adapter: rule.Adapter, Effect: rule.Effect})
			}
		case "admission":
			rep.NativeScope = map[string]any{"source": "verified_input"}
			controls.Admission = append(controls.Admission, idEffect{RuleID: rule.ID, Effect: rule.Effect})
		}
		_ = i
		dataRules = append(dataRules, row)
		reports = append(reports, rep)
	}

	guard, err := cat.Guardrails(ctx, workspaceID, parseIDs(doc.Targets.WorkloadIDs))
	if err != nil {
		return nil, err
	}
	composition := append([]string{"a new allow never releases existing quarantine"}, guard...)

	body, err := json.Marshal(controls)
	if err != nil {
		return nil, err
	}

	data := map[string]any{
		"policy_revision": revision,
		"content_hash":    hash,
		"targets":         map[string]any{"workload_ids": append([]string(nil), doc.Targets.WorkloadIDs...)},
		"rules":           dataRules,
	}

	// Compute capability digest from controls.
	capDigest := computeCapabilityDigest(controls)

	// Build the typed control plan — primary artifact for native enforcement.
	typedPlanJSON, err := BuildTypedPlan(doc, ruleMap, profile)
	if err != nil {
		return nil, err
	}

	out := &CompileV2Result{
		CanonicalHash:    hash,
		ArtifactSHA256:   hash, // Same as canonical for inline compilation; signed bundle overrides this.
		RuleMap:          ruleMap,
		CapabilityDigest: capDigest,
		TypedControlPlan: typedPlanJSON,
		Controls:         body,
		Semantic: SemanticReport{
			Rules: reports, Composition: composition, Warnings: []string{},
			Unsupported: []Unsupported{}, EntryPoint: opa.Query,
		},
		Canonical: canonical, ContentHash: hash,
		TargetDigest: digestManifest(manifest), Manifest: manifest,
	}

	// OPA Rego and data are only generated when gateway broker rules are present.
	// Native enforcement uses the typed control plan directly.
	if HasGatewayBrokerRules(doc) {
		out.Rego = opa.Template()
		out.Data = data
	}

	return out, nil
}

// CanonicalV2 is the deterministic JSON representation of a V2 document.
func CanonicalV2(doc models.RuntimePolicyV2Document) ([]byte, string, error) {
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:]), nil
}

// --- static validation ---

func staticV2(doc models.RuntimePolicyV2Document) error {
	if doc.Format != FormatV2 {
		return &Error{Code: "invalid_format", Message: "format must be " + FormatV2}
	}
	if doc.Name == "" {
		return &Error{Code: "invalid_document", Message: "name is required"}
	}
	if doc.DefaultEffect != "deny" {
		return &Error{Code: "invalid_document", Message: "default_effect must be deny"}
	}
	if len(doc.Targets.WorkloadIDs) == 0 && len(doc.Targets.Selectors) == 0 {
		return &Error{Code: "scope_required", Message: "applicability scope must be explicit workload ids or selectors"}
	}
	if doc.Targets.IncludeFutureIncarnations && !doc.Targets.BoundedFutureApproval {
		return &Error{Code: "future_incarnations_unbounded", Message: "include_future_incarnations requires an explicit bounded approval"}
	}
	seen := map[string]bool{}
	for _, rule := range doc.Rules {
		if rule.ID == "" || seen[rule.ID] {
			return &Error{Code: "invalid_document", Message: "each rule needs its own id"}
		}
		seen[rule.ID] = true
		if !models.IsValidPrimitive(rule.Primitive) {
			return &Error{Code: "unknown_primitive", Message: "unsupported primitive " + rule.Primitive}
		}
		switch rule.Effect {
		case "allow", "deny", "require_approval":
		default:
			return &Error{Code: "invalid_document", Message: "unsupported effect " + rule.Effect}
		}
	}
	return nil
}

func validateEnforcement(e models.PolicyEnforcement) []V2FieldError {
	var errs []V2FieldError
	valid := false
	for _, b := range models.ValidEnforcementBackends() {
		if b == e.Backend {
			valid = true
			break
		}
	}
	if !valid {
		errs = append(errs, V2FieldError{Pointer: "/enforcement/backend", Code: "invalid_backend", Message: "backend must be one of: authsec, openshell"})
	}
	validMode := false
	for _, m := range models.ValidV2EnforcementModes() {
		if m == e.Mode {
			validMode = true
			break
		}
	}
	if !validMode {
		errs = append(errs, V2FieldError{Pointer: "/enforcement/mode", Code: "invalid_mode", Message: "mode must be one of: observe, shadow, enforce"})
	}
	return errs
}

func validateV2Rules(doc models.RuntimePolicyV2Document) []V2FieldError {
	var errs []V2FieldError
	seen := map[string]bool{}
	escalationNames := map[string]bool{}
	for _, esc := range doc.Escalations {
		escalationNames[esc.Name] = true
	}

	for i, rule := range doc.Rules {
		prefix := fmt.Sprintf("/rules/%d", i)

		if rule.ID == "" {
			errs = append(errs, V2FieldError{Pointer: prefix + "/id", Code: "required", Message: "rule id is required"})
		} else if seen[rule.ID] {
			errs = append(errs, V2FieldError{Pointer: prefix + "/id", Code: "duplicate", Message: "duplicate rule id " + rule.ID})
		}
		seen[rule.ID] = true

		if !models.IsValidPrimitive(rule.Primitive) {
			errs = append(errs, V2FieldError{Pointer: prefix + "/primitive", Code: "unknown_primitive", Message: "unsupported primitive " + rule.Primitive})
		}

		switch rule.Effect {
		case "allow", "deny", "require_approval":
		default:
			errs = append(errs, V2FieldError{Pointer: prefix + "/effect", Code: "invalid_effect", Message: "unsupported effect " + rule.Effect})
		}

		// Escalation ref validation.
		if rule.EscalationRef != "" {
			if rule.Effect != "require_approval" {
				errs = append(errs, V2FieldError{Pointer: prefix + "/escalation_ref", Code: "escalation_effect_mismatch", Message: "escalation_ref only applies to require_approval rules"})
			}
			if !escalationNames[rule.EscalationRef] {
				errs = append(errs, V2FieldError{Pointer: prefix + "/escalation_ref", Code: "unresolved_escalation", Message: "escalation " + rule.EscalationRef + " is not defined"})
			}
		}

		// Effect compatibility per primitive type.
		errs = append(errs, checkPrimitiveEffectCompatibility(prefix, rule)...)
	}
	return errs
}

func checkPrimitiveEffectCompatibility(prefix string, rule models.PolicyV2Rule) []V2FieldError {
	var errs []V2FieldError
	primitives := models.CatalogPrimitives()
	for _, p := range primitives {
		if p.ID == rule.Primitive {
			effectAllowed := false
			for _, e := range p.Effects {
				if e == rule.Effect {
					effectAllowed = true
					break
				}
			}
			if !effectAllowed {
				errs = append(errs, V2FieldError{
					Pointer: prefix + "/effect",
					Code:    "effect_not_supported",
					Message: fmt.Sprintf("primitive %s does not support effect %s", rule.Primitive, rule.Effect),
				})
			}
			break
		}
	}
	return errs
}

func validateEscalations(doc models.RuntimePolicyV2Document) []V2FieldError {
	var errs []V2FieldError
	seen := map[string]bool{}
	for i, esc := range doc.Escalations {
		prefix := fmt.Sprintf("/escalations/%d", i)
		if esc.Name == "" {
			errs = append(errs, V2FieldError{Pointer: prefix + "/name", Code: "required", Message: "escalation name is required"})
		} else if seen[esc.Name] {
			errs = append(errs, V2FieldError{Pointer: prefix + "/name", Code: "duplicate", Message: "duplicate escalation name " + esc.Name})
		}
		seen[esc.Name] = true

		if esc.Enabled && len(esc.ApproverGroupIDs) == 0 {
			errs = append(errs, V2FieldError{Pointer: prefix + "/approver_group_ids", Code: "required_when_enabled", Message: "enabled escalation must have approver groups"})
		}
		if esc.MaxTTLSeconds < 0 {
			errs = append(errs, V2FieldError{Pointer: prefix + "/max_ttl_seconds", Code: "invalid_value", Message: "max_ttl_seconds must be non-negative"})
		}
		if esc.MaxUses < 0 {
			errs = append(errs, V2FieldError{Pointer: prefix + "/max_uses", Code: "invalid_value", Message: "max_uses must be non-negative"})
		}
		switch esc.SelfApproval {
		case "", "deny", "allow", "require_mfa":
		default:
			errs = append(errs, V2FieldError{Pointer: prefix + "/self_approval", Code: "invalid_value", Message: "self_approval must be one of: deny, allow, require_mfa"})
		}

		// Check if any rules reference a disabled escalation.
		if !esc.Enabled {
			for j, rule := range doc.Rules {
				if rule.EscalationRef == esc.Name {
					errs = append(errs, V2FieldError{
						Pointer: fmt.Sprintf("/rules/%d/escalation_ref", j),
						Code:    "disabled_escalation",
						Message: "rule references disabled escalation " + esc.Name,
					})
				}
			}
		}
	}
	return errs
}

func validateDecisionModules(modules []models.PolicyDecisionModule) []V2FieldError {
	var errs []V2FieldError
	seen := map[string]bool{}
	for i, m := range modules {
		prefix := fmt.Sprintf("/decision_modules/%d", i)
		if m.Name == "" {
			errs = append(errs, V2FieldError{Pointer: prefix + "/name", Code: "required", Message: "decision module name is required"})
		} else if seen[m.Name] {
			errs = append(errs, V2FieldError{Pointer: prefix + "/name", Code: "duplicate", Message: "duplicate decision module name " + m.Name})
		}
		seen[m.Name] = true
		switch m.Type {
		case "opa_constraint", "rate_limit", "time_window":
		default:
			errs = append(errs, V2FieldError{Pointer: prefix + "/type", Code: "invalid_type", Message: "unsupported decision module type " + m.Type})
		}
	}
	return errs
}

func validateAuthoredModules(modules []models.AuthoredModule) []V2FieldError {
	var errs []V2FieldError
	seen := map[string]bool{}
	for i, m := range modules {
		prefix := fmt.Sprintf("/authored_modules/%d", i)
		if m.Name == "" {
			errs = append(errs, V2FieldError{Pointer: prefix + "/name", Code: "required", Message: "authored module name is required"})
		} else if seen[m.Name] {
			errs = append(errs, V2FieldError{Pointer: prefix + "/name", Code: "duplicate", Message: "duplicate authored module name " + m.Name})
		}
		seen[m.Name] = true
		if m.Language != "rego" {
			errs = append(errs, V2FieldError{Pointer: prefix + "/language", Code: "unsupported_language", Message: "only rego modules are supported"})
		}
		if m.Source == "" {
			errs = append(errs, V2FieldError{Pointer: prefix + "/source", Code: "required", Message: "module source is required"})
		}
	}
	return errs
}

// --- rule translation ---

// translateRules converts V2 primitive-based rules to V1 action-based rules
// for backward-compatible OPA evaluation.
func translateRules(ctx context.Context, cat Catalog, workspaceID uuid.UUID, v2Rules []models.PolicyV2Rule) ([]Rule, []V2RuleMapEntry, error) {
	v1Rules := make([]Rule, 0, len(v2Rules))
	ruleMap := make([]V2RuleMapEntry, 0, len(v2Rules))

	for _, r := range v2Rules {
		v1Rule, controls, err := primitiveToV1Rule(r)
		if err != nil {
			return nil, nil, err
		}
		v1Rules = append(v1Rules, v1Rule)
		ruleMap = append(ruleMap, V2RuleMapEntry{
			RuleID:         r.ID,
			Primitive:      r.Primitive,
			NativeControls: controls,
		})
	}
	return v1Rules, ruleMap, nil
}

// primitiveToV1Rule maps a V2 primitive rule to a V1 action rule.
func primitiveToV1Rule(r models.PolicyV2Rule) (Rule, []string, error) {
	v1 := Rule{
		ID:     r.ID,
		Effect: r.Effect,
	}

	var controls []string

	switch r.Primitive {
	case models.PrimitiveFileRead:
		v1.Action = "file.read"
		if path, ok := r.Constraints["path"].(string); ok {
			v1.Path = path
		} else if r.Resource != "" {
			v1.Path = r.Resource
		}
		controls = []string{"filesystem"}

	case models.PrimitiveFileWrite:
		v1.Action = "file.write"
		if path, ok := r.Constraints["path"].(string); ok {
			v1.Path = path
		} else if r.Resource != "" {
			v1.Path = r.Resource
		}
		controls = []string{"filesystem"}

	case models.PrimitiveProcessHarden:
		v1.Action = "exec"
		controls = []string{"exec", "privilege"}

	case models.PrimitiveProcessExec:
		v1.Action = "exec"
		controls = []string{"exec"}

	case models.PrimitiveNetworkConnect:
		v1.Action = "network.connect"
		if rid, ok := r.Constraints["resource_id"].(string); ok {
			v1.ResourceID = rid
		} else if r.Resource != "" {
			v1.ResourceID = r.Resource
		}
		controls = []string{"egress"}

	case models.PrimitiveUnixSocket:
		v1.Action = "file.read" // Unix sockets use filesystem controls.
		if path, ok := r.Constraints["path"].(string); ok {
			v1.Path = path
		} else if r.Resource != "" {
			v1.Path = r.Resource
		}
		controls = []string{"filesystem"}

	case models.PrimitiveSecretRead:
		v1.Action = "secret.read"
		if rid, ok := r.Constraints["resource_id"].(string); ok {
			v1.ResourceID = rid
		} else if r.Resource != "" {
			v1.ResourceID = r.Resource
		}
		if adapter, ok := r.Constraints["adapter"].(string); ok {
			v1.Adapter = adapter
		}
		controls = []string{"secret"}

	case models.PrimitiveLLMInvoke:
		v1.Action = "network.connect"
		if rid, ok := r.Constraints["resource_id"].(string); ok {
			v1.ResourceID = rid
		} else if r.Resource != "" {
			v1.ResourceID = r.Resource
		}
		controls = []string{"egress", "gateway"}

	case models.PrimitiveGitHubOperation:
		v1.Action = "network.connect"
		if rid, ok := r.Constraints["resource_id"].(string); ok {
			v1.ResourceID = rid
		} else if r.Resource != "" {
			v1.ResourceID = r.Resource
		}
		controls = []string{"egress", "gateway"}

	case models.PrimitiveDeviceOpen:
		v1.Action = "file.read"
		if path, ok := r.Constraints["path"].(string); ok {
			v1.Path = path
		} else if r.Resource != "" {
			v1.Path = r.Resource
		}
		controls = []string{"filesystem", "cgroup_device"}

	case models.PrimitiveDBOperation:
		v1.Action = "network.connect"
		if rid, ok := r.Constraints["resource_id"].(string); ok {
			v1.ResourceID = rid
		} else if r.Resource != "" {
			v1.ResourceID = r.Resource
		}
		controls = []string{"egress", "gateway"}

	case models.PrimitiveRemoteSession:
		v1.Action = "network.connect"
		if rid, ok := r.Constraints["resource_id"].(string); ok {
			v1.ResourceID = rid
		} else if r.Resource != "" {
			v1.ResourceID = r.Resource
		}
		controls = []string{"egress", "gateway"}

	default:
		return Rule{}, nil, &Error{Code: "unknown_primitive", Message: "unsupported primitive " + r.Primitive}
	}

	return v1, controls, nil
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

func computeCapabilityDigest(controls controlsDoc) string {
	controlNames := map[string]bool{}
	if len(controls.Filesystem.Paths) > 0 {
		controlNames["filesystem"] = true
	}
	if len(controls.Egress) > 0 {
		controlNames["egress"] = true
	}
	if len(controls.Exec) > 0 {
		controlNames["exec"] = true
	}
	if len(controls.Admission) > 0 {
		controlNames["admission"] = true
	}
	if len(controls.Broker) > 0 {
		controlNames["secret"] = true
	}
	names := make([]string, 0, len(controlNames))
	for n := range controlNames {
		names = append(names, n)
	}
	sort.Strings(names)
	raw, _ := json.Marshal(names)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
