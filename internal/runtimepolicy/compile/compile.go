// Package compile turns an authsec.runtime.v1 document into Rego data and an
// adapter-neutral controls artifact. Custom Rego is rejected. H2 and K3
// consume the artifact; this package does not apply it.
package compile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/authsec-ai/authsec/internal/runtimepolicy/opa"
	"github.com/authsec-ai/authsec/internal/runtimepolicy/profiles"
	"github.com/google/uuid"
)

const (
	// ControlsSchema is the artifact version. A later version is a new file.
	ControlsSchema = "authsec.controls.v1"
	FormatV1       = "authsec.runtime.v1"
)

// Document is the typed policy. Unknown JSON fields are rejected so a custom
// module cannot hide beside the rules.
type Document struct {
	Name                  string    `json:"name"`
	Format                string    `json:"format"`
	Targets               TargetSet `json:"targets"`
	Profile               string    `json:"profile"`
	DefaultEffect         string    `json:"default_effect"`
	Rules                 []Rule    `json:"rules"`
	RequiredControls      []string  `json:"required_controls"`
	OptionalControls      []string  `json:"optional_controls,omitempty"`
	EvidenceGraphRevision int64     `json:"evidence_graph_revision"`
	Mode                  string    `json:"mode,omitempty"`
	IdentityWide          bool      `json:"identity_wide,omitempty"`
	Rego                  string    `json:"rego,omitempty"`
}

// TargetSet is the applicability scope. It is explicit workload ids. A selector
// is not expanded here.
type TargetSet struct {
	WorkloadIDs               []string `json:"workload_ids"`
	IncludeFutureIncarnations bool     `json:"include_future_incarnations"`
	BoundedFutureApproval     bool     `json:"bounded_future_approval,omitempty"`
	Selector                  string   `json:"selector,omitempty"`
}

// Rule is one typed rule. Adapter is set for require_approval.
type Rule struct {
	ID         string `json:"id"`
	Action     string `json:"action"`
	ResourceID string `json:"resource_id,omitempty"`
	Path       string `json:"path,omitempty"`
	Effect     string `json:"effect"`
	Adapter    string `json:"adapter,omitempty"`
}

// NativeResource is the immutable endpoint or secret a resource id resolved to.
type NativeResource struct {
	ID              uuid.UUID
	ReferenceStatus string
	NativeKind      string
	Address         string
	Port            int
	Protocol        string
	BrokerPath      string
}

// WorkloadTarget is one workload and the incarnations that exist now.
type WorkloadTarget struct {
	ID                 uuid.UUID
	RuntimeInstanceIDs []uuid.UUID
}

// Catalog resolves graph ids inside one workspace.
type Catalog interface {
	ResolveResource(ctx context.Context, workspaceID, resourceID uuid.UUID) (NativeResource, error)
	ResolveWorkload(ctx context.Context, workspaceID, workloadID uuid.UUID) (WorkloadTarget, error)
	BrokerConfigured(ctx context.Context, workspaceID uuid.UUID, adapter string) (bool, error)
	Guardrails(ctx context.Context, workspaceID uuid.UUID, workloadIDs []uuid.UUID) ([]string, error)
}

var (
	// ErrUnresolved is an id this workspace does not have.
	ErrUnresolved = errors.New("unresolved")
	// ErrCrossWorkspace is an id that exists in another workspace.
	ErrCrossWorkspace = errors.New("cross_workspace")
	// ErrNoNative is a resource whose reference_status cannot yield a native target.
	ErrNoNative = errors.New("no_native_target")
)

// Error is a validation failure with a stable code.
type Error struct {
	Code    string
	Message string
	Details map[string]any
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Result is the two outputs of one document, plus the semantic report.
type Result struct {
	Rego         string
	Data         map[string]any
	Controls     json.RawMessage
	Semantic     SemanticReport
	Canonical    []byte
	ContentHash  string
	TargetDigest string
	Manifest     []ManifestEntry
}

// ManifestEntry is one resolved target incarnation.
type ManifestEntry struct {
	WorkloadID        string `json:"workload_id"`
	RuntimeInstanceID string `json:"runtime_instance_id,omitempty"`
	Native            any    `json:"native,omitempty"`
}

// SemanticReport is one row per rule.
type SemanticReport struct {
	Rules       []RuleReport  `json:"rules"`
	Composition []string      `json:"composition"`
	Warnings    []string      `json:"warnings"`
	Unsupported []Unsupported `json:"unsupported"`
	EntryPoint  string        `json:"opa_entry_point"`
}

// RuleReport describes how one rule is evaluated and enforced.
type RuleReport struct {
	ID                    string   `json:"id"`
	OPAEntryPoint         string   `json:"opa_entry_point"`
	EnforcementAdapter    string   `json:"enforcement_adapter"`
	NativeScope           any      `json:"native_scope"`
	UnsupportedDimensions []string `json:"unsupported_dimensions"`
	RequiredCapabilities  []string `json:"required_capabilities"`
}

// Unsupported is a required control a target digest cannot enforce.
type Unsupported struct {
	Control string `json:"control"`
	Digest  string `json:"digest"`
	Profile string `json:"profile"`
}

// TargetRef is one publication target's certified digest.
type TargetRef struct {
	WorkloadID       uuid.UUID
	CapabilityDigest string
	Profile          string
}

// Parse decodes a document and rejects custom Rego and unknown fields.
func Parse(raw []byte) (Document, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return Document{}, &Error{Code: "invalid_document", Message: err.Error()}
	}
	if dec.More() {
		return Document{}, &Error{Code: "invalid_document", Message: "trailing data after the document"}
	}
	if err := doc.static(); err != nil {
		return Document{}, err
	}
	return doc, nil
}

func (d Document) static() error {
	if d.Rego != "" || d.Format != FormatV1 {
		return &Error{Code: "custom_rego_not_supported", Message: "P0 accepts only authsec.runtime.v1 typed templates."}
	}
	if d.Name == "" {
		return &Error{Code: "invalid_document", Message: "name is required"}
	}
	if d.DefaultEffect != "deny" {
		return &Error{Code: "invalid_document", Message: "default_effect must be deny"}
	}
	if d.Profile == "" {
		return &Error{Code: "invalid_document", Message: "profile is required"}
	}
	if d.Targets.Selector != "" {
		return &Error{Code: "selector_not_expanded", Message: "a broad selector must be expanded into explicit workload incarnations before validation"}
	}
	if len(d.Targets.WorkloadIDs) == 0 {
		return &Error{Code: "scope_required", Message: "applicability scope must be explicit workload ids"}
	}
	if d.Targets.IncludeFutureIncarnations && !d.Targets.BoundedFutureApproval {
		return &Error{Code: "future_incarnations_unbounded", Message: "include_future_incarnations requires an explicit bounded approval"}
	}
	if d.IdentityWide {
		return &Error{Code: "shared_use_review", Message: "identity-wide controls require the shared-use review before they can be validated"}
	}
	seen := map[string]bool{}
	for _, rule := range d.Rules {
		if rule.ID == "" || seen[rule.ID] {
			return &Error{Code: "invalid_document", Message: "each rule needs its own id"}
		}
		seen[rule.ID] = true
		if !knownAction(rule.Action) {
			return &Error{Code: "invalid_document", Message: "unsupported action " + rule.Action}
		}
		switch rule.Effect {
		case "allow", "deny", "require_approval":
		default:
			return &Error{Code: "invalid_document", Message: "unsupported effect " + rule.Effect}
		}
		if rule.Effect == "require_approval" && rule.Adapter == "" {
			return &Error{Code: "broker_not_configured", Message: "require_approval needs an adapter"}
		}
	}
	return nil
}

func knownAction(a string) bool {
	switch a {
	case "network.connect", "file.read", "file.write", "exec", "secret.read", "admission":
		return true
	default:
		return false
	}
}

// Compile resolves the document and emits Rego, data and the controls artifact.
func Compile(ctx context.Context, reg *profiles.Registry, cat Catalog, workspaceID uuid.UUID, revision int, doc Document) (*Result, error) {
	if err := doc.static(); err != nil {
		return nil, err
	}
	if reg == nil || !reg.Known(doc.Profile) {
		return nil, &Error{Code: "unknown_profile", Message: "profile is not in the certified registry"}
	}
	canonical, hash, err := Canonical(doc)
	if err != nil {
		return nil, err
	}
	manifest := make([]ManifestEntry, 0, len(doc.Targets.WorkloadIDs))
	var nativeByResource = map[string]NativeResource{}
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
	dataRules := make([]map[string]any, 0, len(doc.Rules))
	reports := make([]RuleReport, 0, len(doc.Rules))
	controls := newControls(doc.Profile, reg)
	for _, rule := range doc.Rules {
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
			n, err := resolveRuleResource(ctx, cat, workspaceID, rule.ResourceID)
			if err != nil {
				return nil, err
			}
			if n.Address == "" || n.Port == 0 || n.Protocol == "" {
				return nil, &Error{Code: "unresolved_endpoint", Message: "resource " + rule.ResourceID + " has no address, port and protocol",
					Details: map[string]any{"resource_id": rule.ResourceID}}
			}
			nativeByResource[rule.ResourceID] = n
			row["resource_id"] = rule.ResourceID
			scope := map[string]any{"address": n.Address, "port": n.Port, "protocol": n.Protocol, "resource_id": rule.ResourceID}
			rep.NativeScope = scope
			controls.Egress = append(controls.Egress, egressRule{RuleID: rule.ID, ResourceID: rule.ResourceID, Address: n.Address, Port: n.Port, Protocol: n.Protocol, Effect: rule.Effect})
		case "file.read", "file.write":
			if rule.Path == "" {
				return nil, &Error{Code: "invalid_document", Message: "file rule needs a path"}
			}
			row["path"] = rule.Path
			rep.NativeScope = map[string]any{"path": rule.Path, "baseline": controls.Filesystem.Baseline}
			controls.Filesystem.Paths = append(controls.Filesystem.Paths, pathRule{RuleID: rule.ID, Path: rule.Path, Effect: rule.Effect})
		case "exec":
			rep.NativeScope = map[string]any{"privilege": "drop", "no_new_privs": true}
			controls.Exec = append(controls.Exec, idEffect{RuleID: rule.ID, Effect: rule.Effect})
		case "secret.read":
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
		case "admission":
			rep.NativeScope = map[string]any{"source": "verified_input"}
			controls.Admission = append(controls.Admission, idEffect{RuleID: rule.ID, Effect: rule.Effect})
		}
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
	return &Result{
		Rego: opa.Template(), Data: data, Controls: body,
		Semantic: SemanticReport{
			Rules: reports, Composition: composition, Warnings: []string{},
			Unsupported: []Unsupported{}, EntryPoint: opa.Query,
		},
		Canonical: canonical, ContentHash: hash,
		TargetDigest: digestManifest(manifest), Manifest: manifest,
	}, nil
}

func resolveRuleResource(ctx context.Context, cat Catalog, ws uuid.UUID, id string) (NativeResource, error) {
	rid, err := uuid.Parse(id)
	if err != nil {
		return NativeResource{}, &Error{Code: "unresolved_endpoint", Message: "resource id is not a uuid"}
	}
	n, err := cat.ResolveResource(ctx, ws, rid)
	if err != nil {
		return NativeResource{}, mapResolve(err, "resource")
	}
	if n.ReferenceStatus == "referenced" || n.ReferenceStatus == "" {
		return NativeResource{}, &Error{Code: "unresolved_endpoint", Message: "resource reference_status cannot give a native target",
			Details: map[string]any{"resource_id": id, "reference_status": n.ReferenceStatus}}
	}
	return n, nil
}

func mapResolve(err error, what string) error {
	switch {
	case errors.Is(err, ErrCrossWorkspace):
		return &Error{Code: "cross_workspace", Message: what + " belongs to another workspace"}
	case errors.Is(err, ErrNoNative):
		return &Error{Code: "unresolved_endpoint", Message: what + " has no native target"}
	case errors.Is(err, ErrUnresolved):
		return &Error{Code: "unresolved_endpoint", Message: what + " is not in this workspace"}
	default:
		return err
	}
}

// CheckEnforceable reports controls a target digest cannot enforce. mode=enforce
// returns an error A7 maps to 422. mode=observe returns the report and a nil error.
func CheckEnforceable(reg *profiles.Registry, doc Document, targets []TargetRef) (SemanticReport, error) {
	if reg == nil {
		return SemanticReport{}, &Error{Code: "unknown_profile", Message: "no profile registry"}
	}
	mode := doc.Mode
	if mode == "" {
		mode = "observe"
	}
	need := requiredControls(doc)
	optional := map[string]bool{}
	for _, c := range doc.OptionalControls {
		optional[c] = true
	}
	var unsupported []Unsupported
	if len(targets) == 0 && mode == "enforce" && len(need) > 0 {
		unsupported = append(unsupported, Unsupported{Control: need[0], Digest: "", Profile: doc.Profile})
	}
	for _, t := range targets {
		profile := t.Profile
		if profile == "" {
			profile = doc.Profile
		}
		for _, control := range need {
			if optional[control] {
				continue
			}
			if !reg.Supports(profile, t.CapabilityDigest, control) {
				unsupported = append(unsupported, Unsupported{Control: control, Digest: t.CapabilityDigest, Profile: profile})
			}
		}
	}
	report := SemanticReport{
		Unsupported: unsupported,
		Composition: []string{"a new allow never releases existing quarantine"},
		EntryPoint:  opa.Query,
		Warnings:    []string{},
		Rules:       []RuleReport{},
	}
	if mode == "enforce" && len(unsupported) > 0 {
		return report, &Error{
			Code: "unsupported_control",
			Message: fmt.Sprintf("required control %s is not certified for digest %s",
				unsupported[0].Control, unsupported[0].Digest),
			Details: map[string]any{"control": unsupported[0].Control, "digest": unsupported[0].Digest},
		}
	}
	return report, nil
}

func requiredControls(doc Document) []string {
	set := map[string]bool{}
	for _, c := range doc.RequiredControls {
		set[c] = true
	}
	for _, rule := range doc.Rules {
		for _, c := range capabilitiesFor(rule) {
			set[c] = true
		}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func capabilitiesFor(rule Rule) []string {
	switch rule.Action {
	case "network.connect":
		return []string{"egress"}
	case "file.read", "file.write":
		return []string{"filesystem"}
	case "exec":
		return []string{"exec", "privilege"}
	case "secret.read":
		return []string{"secret"}
	case "admission":
		return []string{"admission"}
	default:
		return nil
	}
}

func adapterFor(action string) string {
	switch action {
	case "network.connect":
		return "egress"
	case "file.read", "file.write":
		return "filesystem"
	case "exec":
		return "exec"
	case "secret.read":
		return "broker"
	case "admission":
		return "admission"
	default:
		return ""
	}
}

// Canonical is the JSON whose sha256 is the revision content hash.
func Canonical(doc Document) ([]byte, string, error) {
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:]), nil
}

func digestManifest(entries []ManifestEntry) string {
	raw, _ := json.Marshal(entries)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func parseIDs(ids []string) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if u, err := uuid.Parse(id); err == nil {
			out = append(out, u)
		}
	}
	return out
}

type controlsDoc struct {
	Schema     string       `json:"schema"`
	Profile    string       `json:"profile"`
	Filesystem fsControls   `json:"filesystem"`
	Egress     []egressRule `json:"egress"`
	Exec       []idEffect   `json:"exec"`
	Admission  []idEffect   `json:"admission"`
	Broker     []brokerRule `json:"broker"`
}

type fsControls struct {
	Baseline profiles.FilesystemBaseline `json:"baseline"`
	Paths    []pathRule                  `json:"paths"`
}

type pathRule struct {
	RuleID string `json:"rule_id"`
	Path   string `json:"path"`
	Effect string `json:"effect"`
}

type egressRule struct {
	RuleID     string `json:"rule_id"`
	ResourceID string `json:"resource_id"`
	Address    string `json:"address"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
	Effect     string `json:"effect"`
}

type idEffect struct {
	RuleID string `json:"rule_id"`
	Effect string `json:"effect"`
}

type brokerRule struct {
	RuleID     string `json:"rule_id"`
	ResourceID string `json:"resource_id"`
	Adapter    string `json:"adapter"`
	Effect     string `json:"effect"`
}

func newControls(profile string, reg *profiles.Registry) controlsDoc {
	base, _ := reg.Baseline(profile)
	if base.Loaders == nil {
		base.Loaders = map[string]string{}
	}
	if base.Libraries == nil {
		base.Libraries = []string{}
	}
	if base.Certificates == nil {
		base.Certificates = []string{}
	}
	if base.ReadonlyConfig == nil {
		base.ReadonlyConfig = []string{}
	}
	return controlsDoc{
		Schema: ControlsSchema, Profile: profile,
		Filesystem: fsControls{Baseline: base, Paths: []pathRule{}},
		Egress:     []egressRule{}, Exec: []idEffect{}, Admission: []idEffect{}, Broker: []brokerRule{},
	}
}
