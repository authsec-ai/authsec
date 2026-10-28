package services

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/authsec-ai/authsec/internal/runtimepolicy/compile"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// TypedReplayService evaluates policy decisions using the typed control plan
// instead of OPA. This is the TRD v1.1 replacement for OPA simulation in
// native enforcement: the same normalized IR used by the compiler produces
// allow/deny/require_approval decisions without requiring an OPA evaluator.
type TypedReplayService struct {
	db *gorm.DB
}

// NewTypedReplayService creates a typed replay service.
func NewTypedReplayService(db *gorm.DB) *TypedReplayService {
	return &TypedReplayService{db: db}
}

// Evaluate runs a typed replay evaluation against a policy's current revision.
func (s *TypedReplayService) Evaluate(ctx context.Context, wsID, policyID uuid.UUID, input SimulationInput) (*SimulationOutput, error) {
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
		return nil, fmt.Errorf("typed_replay: load policy: %w", err)
	}
	if docJSON == "" {
		return nil, fmt.Errorf("typed_replay: policy not found")
	}

	var doc models.RuntimePolicyV2Document
	if err := json.Unmarshal([]byte(docJSON), &doc); err != nil {
		return nil, fmt.Errorf("typed_replay: parse document: %w", err)
	}

	return TypedEval(doc, input), nil
}

// ReplayBatch evaluates multiple inputs against a policy.
func (s *TypedReplayService) ReplayBatch(ctx context.Context, wsID, policyID uuid.UUID, inputs []SimulationInput) ([]SimulationOutput, error) {
	// Load policy once.
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
		return nil, fmt.Errorf("typed_replay: load policy: %w", err)
	}

	var doc models.RuntimePolicyV2Document
	if err := json.Unmarshal([]byte(docJSON), &doc); err != nil {
		return nil, fmt.Errorf("typed_replay: parse document: %w", err)
	}

	outputs := make([]SimulationOutput, len(inputs))
	for i, input := range inputs {
		outputs[i] = *TypedEval(doc, input)
	}
	return outputs, nil
}

// TypedEval evaluates a single input against a V2 document using the typed
// control plan rules. It produces the same SimulationOutput shape as OPA
// evaluation, enabling transparent replacement.
func TypedEval(doc models.RuntimePolicyV2Document, input SimulationInput) *SimulationOutput {
	output := &SimulationOutput{
		Decision:     doc.DefaultEffect,
		MatchedRules: []string{},
		Reasons:      []string{},
	}
	if output.Decision == "" {
		output.Decision = "deny"
	}

	// Effect precedence: deny > require_approval > allow.
	// Track the highest-precedence matched effect.
	bestPrecedence := -1

	for _, rule := range doc.Rules {
		if !typedRuleMatches(rule, input) {
			continue
		}
		output.MatchedRules = append(output.MatchedRules, rule.ID)
		p := effectPrecedence(rule.Effect)
		if p > bestPrecedence {
			bestPrecedence = p
			output.Decision = rule.Effect
		}
		output.Reasons = append(output.Reasons,
			fmt.Sprintf("Rule %s: %s on %s → %s", rule.ID, rule.Primitive, rule.Resource, rule.Effect),
		)
	}

	if len(output.MatchedRules) == 0 {
		output.Reasons = append(output.Reasons, "No matching rules; default effect applied")
	}

	return output
}

// typedRuleMatches checks if a V2 rule matches the given input.
func typedRuleMatches(rule models.PolicyV2Rule, input SimulationInput) bool {
	// Match primitive.
	if rule.Primitive != "" && rule.Primitive != input.Primitive {
		return false
	}

	// Match resource (supports glob patterns for file paths).
	if rule.Resource != "" && rule.Resource != "*" && rule.Resource != input.Resource {
		// Try path-based glob matching for file primitives.
		if isFileSystemPrimitive(rule.Primitive) {
			matched, _ := filepath.Match(rule.Resource, input.Resource)
			if !matched {
				// Also check prefix matching for directory rules.
				if !strings.HasPrefix(input.Resource, rule.Resource) {
					return false
				}
			}
		} else {
			return false
		}
	}

	// Match action if specified in constraints.
	if input.Action != "" {
		if actionConstraint, ok := rule.Constraints["action"].(string); ok {
			if actionConstraint != "*" && actionConstraint != input.Action {
				return false
			}
		}
	}

	// Match constraints path if present.
	if pathConstraint, ok := rule.Constraints["path"].(string); ok {
		if pathConstraint != "*" && pathConstraint != input.Resource {
			matched, _ := filepath.Match(pathConstraint, input.Resource)
			if !matched && !strings.HasPrefix(input.Resource, pathConstraint) {
				return false
			}
		}
	}

	return true
}

// isFileSystemPrimitive returns true for primitives that operate on file paths.
func isFileSystemPrimitive(primitive string) bool {
	switch primitive {
	case models.PrimitiveFileRead, models.PrimitiveFileWrite,
		models.PrimitiveUnixSocket, models.PrimitiveDeviceOpen:
		return true
	}
	return false
}

// effectPrecedence returns the precedence of an effect (higher = stronger).
func effectPrecedence(effect string) int {
	switch effect {
	case "deny":
		return 2
	case "require_approval":
		return 1
	case "allow":
		return 0
	default:
		return -1
	}
}

// IsV2Document checks if a raw JSON document is a V2 format by inspecting
// the format field.
func IsV2Document(raw string) bool {
	var peek struct {
		Format string `json:"format"`
	}
	_ = json.Unmarshal([]byte(raw), &peek)
	return peek.Format == compile.FormatV2
}
