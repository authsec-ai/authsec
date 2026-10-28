package services

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// OPASimulationService provides server-side OPA evaluation for testing and simulation.
type OPASimulationService struct {
	db *gorm.DB
}

// NewOPASimulationService creates a new simulation service.
func NewOPASimulationService(db *gorm.DB) *OPASimulationService {
	return &OPASimulationService{db: db}
}

// SimulationInput is the decision input for policy testing.
type SimulationInput struct {
	Principal   string `json:"principal"`
	WorkloadID  string `json:"workload_id"`
	ExecutionID string `json:"execution_id,omitempty"`
	Primitive   string `json:"primitive"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
}

// SimulationOutput is the decision output.
type SimulationOutput struct {
	Decision     string   `json:"decision"` // "allow", "deny", "require_approval"
	MatchedRules []string `json:"matched_rules"`
	Reasons      []string `json:"reasons"`
	Obligations  []any    `json:"obligations,omitempty"`
}

// Evaluate runs a policy decision against the current revision of a policy.
func (s *OPASimulationService) Evaluate(ctx context.Context, wsID uuid.UUID, policyID uuid.UUID, input SimulationInput) (*SimulationOutput, error) {
	// Load the policy document.
	var docJSON string
	err := s.db.WithContext(ctx).Raw(`
		SELECT rev.document::text
		FROM runtime_policies rp
		JOIN runtime_policy_revisions rev ON rev.policy_id = rp.id
			AND rev.workspace_id = rp.workspace_id
			AND rev.revision = rp.current_draft_revision
		WHERE rp.workspace_id = ? AND rp.id = ?
	`, wsID, policyID).Scan(&docJSON).Error
	if err != nil {
		return nil, fmt.Errorf("opa_simulation: load policy: %w", err)
	}
	if docJSON == "" {
		return nil, fmt.Errorf("opa_simulation: policy not found")
	}

	// Parse rules from the document.
	var doc struct {
		Rules []struct {
			ID        string `json:"id"`
			Primitive string `json:"primitive"`
			Resource  string `json:"resource"`
			Action    string `json:"action"`
			Effect    string `json:"effect"`
		} `json:"rules"`
		DefaultEffect string `json:"default_effect"`
	}
	if err := json.Unmarshal([]byte(docJSON), &doc); err != nil {
		return nil, fmt.Errorf("opa_simulation: parse document: %w", err)
	}

	// Simple rule matching (in production, this would use the compiled OPA Wasm).
	output := &SimulationOutput{
		Decision: doc.DefaultEffect,
	}
	if output.Decision == "" {
		output.Decision = "deny"
	}

	for _, rule := range doc.Rules {
		if matchesRule(rule.Primitive, rule.Resource, input) {
			output.MatchedRules = append(output.MatchedRules, rule.ID)
			output.Decision = rule.Effect
			output.Reasons = append(output.Reasons,
				fmt.Sprintf("Rule %s: %s on %s → %s", rule.ID, rule.Primitive, rule.Resource, rule.Effect),
			)
		}
	}

	if len(output.MatchedRules) == 0 {
		output.Reasons = append(output.Reasons, "No matching rules; default effect applied")
	}

	return output, nil
}

func matchesRule(primitive, resource string, input SimulationInput) bool {
	if primitive != "" && primitive != input.Primitive {
		return false
	}
	if resource != "" && resource != "*" && resource != input.Resource {
		return false
	}
	return true
}

// ReplayRecordedRequests replays a set of recorded inputs and returns results.
func (s *OPASimulationService) ReplayRecordedRequests(ctx context.Context, wsID, policyID uuid.UUID, inputs []SimulationInput) ([]SimulationOutput, error) {
	var outputs []SimulationOutput
	for _, input := range inputs {
		out, err := s.Evaluate(ctx, wsID, policyID, input)
		if err != nil {
			outputs = append(outputs, SimulationOutput{
				Decision: "error",
				Reasons:  []string{err.Error()},
			})
			continue
		}
		outputs = append(outputs, *out)
	}
	return outputs, nil
}
