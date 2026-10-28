package compile

import (
	"encoding/json"

	"github.com/authsec-ai/authsec/models"
)

const (
	// TypedPlanSchema is the schema identifier for the typed control plan.
	TypedPlanSchema = "authsec.typed.v1"
)

// TypedControlPlan is the backend-agnostic enforcement instruction set.
// It replaces OPA Rego as the primary compilation artifact for AuthSec
// native enforcement. OPA Rego is only generated for gateway broker controls.
type TypedControlPlan struct {
	Schema      string             `json:"schema"`
	Profile     string             `json:"profile"`
	Rules       []TypedControlRule `json:"rules"`
	Defaults    TypedDefaults      `json:"defaults"`
	Escalations []TypedEscalation  `json:"escalations,omitempty"`
}

// TypedControlRule is a single enforcement instruction derived from a policy rule.
type TypedControlRule struct {
	RuleID         string            `json:"rule_id"`
	Primitive      string            `json:"primitive"`
	Effect         string            `json:"effect"`
	Resource       string            `json:"resource,omitempty"`
	Actions        []string          `json:"actions,omitempty"`
	Constraints    map[string]any    `json:"constraints,omitempty"`
	NativeControls []string          `json:"native_controls"`
	EscalationRef  string            `json:"escalation_ref,omitempty"`
	Required       bool              `json:"required"`
	EvidenceRefs   []string          `json:"evidence_refs,omitempty"`
}

// TypedDefaults holds the default policy decision.
type TypedDefaults struct {
	Effect string `json:"effect"` // always "deny"
}

// TypedEscalation is a named escalation config carried in the typed plan.
type TypedEscalation struct {
	Name             string   `json:"name"`
	Enabled          bool     `json:"enabled"`
	ApproverGroupIDs []string `json:"approver_group_ids,omitempty"`
	MFAProvider      string   `json:"mfa_provider,omitempty"`
	MaxUses          int      `json:"max_uses,omitempty"`
	MaxTTLSeconds    int      `json:"max_ttl_seconds,omitempty"`
	SelfApproval     string   `json:"self_approval,omitempty"`
	TimeoutSeconds   int      `json:"timeout_seconds,omitempty"`
}

// GatewayBrokerPrimitives are primitives that require OPA for gateway broker decisions.
var GatewayBrokerPrimitives = map[string]bool{
	models.PrimitiveLLMInvoke:        true,
	models.PrimitiveGitHubOperation:  true,
	models.PrimitiveDBOperation:      true,
	models.PrimitiveRemoteSession:    true,
	models.PrimitiveSecretRead:       true,
}

// BuildTypedPlan constructs the typed control plan from a V2 document
// and its compilation artifacts.
func BuildTypedPlan(doc models.RuntimePolicyV2Document, ruleMap []V2RuleMapEntry, profile string) (json.RawMessage, error) {
	ruleIndex := make(map[string]V2RuleMapEntry, len(ruleMap))
	for _, rm := range ruleMap {
		ruleIndex[rm.RuleID] = rm
	}

	rules := make([]TypedControlRule, 0, len(doc.Rules))
	for _, r := range doc.Rules {
		rm := ruleIndex[r.ID]
		rule := TypedControlRule{
			RuleID:         r.ID,
			Primitive:      r.Primitive,
			Effect:         r.Effect,
			Resource:       r.Resource,
			Constraints:    r.Constraints,
			NativeControls: rm.NativeControls,
			EscalationRef:  r.EscalationRef,
			Required:       r.Required,
			EvidenceRefs:   r.EvidenceRefs,
		}
		if r.Actions != nil {
			rule.Actions = r.Actions
		}
		rules = append(rules, rule)
	}

	escalations := make([]TypedEscalation, 0, len(doc.Escalations))
	for _, esc := range doc.Escalations {
		escalations = append(escalations, TypedEscalation{
			Name:             esc.Name,
			Enabled:          esc.Enabled,
			ApproverGroupIDs: esc.ApproverGroupIDs,
			MFAProvider:      esc.MFAProvider,
			MaxUses:          esc.MaxUses,
			MaxTTLSeconds:    esc.MaxTTLSeconds,
			SelfApproval:     esc.SelfApproval,
			TimeoutSeconds:   esc.TimeoutSeconds,
		})
	}

	plan := TypedControlPlan{
		Schema:      TypedPlanSchema,
		Profile:     profile,
		Rules:       rules,
		Defaults:    TypedDefaults{Effect: doc.DefaultEffect},
		Escalations: escalations,
	}

	return json.Marshal(plan)
}

// HasGatewayBrokerRules returns true if any rule in the document maps to a
// gateway-dependent primitive that requires OPA for brokered decisions.
func HasGatewayBrokerRules(doc models.RuntimePolicyV2Document) bool {
	for _, rule := range doc.Rules {
		if GatewayBrokerPrimitives[rule.Primitive] {
			return true
		}
	}
	return false
}
