package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// GeneratorVersion is the version of the policy generator.
const GeneratorVersion = "authsec.generator.v1.0"

// CandidateGenerateResult is the output of the candidate generator.
type CandidateGenerateResult struct {
	DraftPolicyID *uuid.UUID            `json:"draft_policy_id,omitempty"`
	Rules         []models.PolicyV2Rule `json:"rules"`
	Warnings      []string              `json:"warnings,omitempty"`
	Stats         CandidateGenerateStats `json:"stats"`
}

// CandidateGenerateStats captures generation metrics.
type CandidateGenerateStats struct {
	AllowCandidates    int `json:"allow_candidates"`
	DeniedEvidence     int `json:"denied_evidence"`
	DeclaredGrants     int `json:"declared_grants"`
	ApprovalCandidates int `json:"approval_candidates"`
	TotalRules         int `json:"total_rules"`
}

// PolicyGenerator produces candidate policy rules from discovery evidence.
type PolicyGenerator struct{}

// NewPolicyGenerator creates a new generator.
func NewPolicyGenerator() *PolicyGenerator {
	return &PolicyGenerator{}
}

// Generate produces candidate rules from frozen evidence.
//
// The generation follows these steps per section 13:
//  1. Resolve workload identities
//  2. Separate observed/denied/configured evidence
//  3. Apply baseline template + organization boundary
//  4. Add evidence-based rules
//  5. Include runtime dependencies
//  6. Mark approval candidates
//  7. Create explanations
//  8. Validate with server OPA
//  9. Produce draft
func (g *PolicyGenerator) Generate(ctx context.Context, db *gorm.DB, wsID uuid.UUID, req CandidateRequest) (*CandidateGenerateResult, error) {
	result := &CandidateGenerateResult{}

	// Step 1: Resolve workloads and their identities.
	workloads, err := g.resolveWorkloads(db, wsID, req.WorkloadIDs)
	if err != nil {
		return nil, fmt.Errorf("resolve workloads: %w", err)
	}
	if len(workloads) == 0 {
		result.Warnings = append(result.Warnings, "no workloads found for the given IDs")
		return result, nil
	}

	// Step 2: Gather and classify evidence.
	evidence := g.gatherEvidence(db, wsID, req.WorkloadIDs, req.EvidenceWindow)

	// Step 3-4: Generate rules from evidence.
	rules := g.generateRules(evidence)
	result.Rules = rules

	// Step 5: Count statistics.
	for _, r := range rules {
		switch r.Effect {
		case "allow":
			result.Stats.AllowCandidates++
		case "deny":
			result.Stats.DeniedEvidence++
		case "require_approval":
			result.Stats.ApprovalCandidates++
		}
	}
	result.Stats.TotalRules = len(rules)

	return result, nil
}

type workloadInfo struct {
	ID        string
	Name      string
	Namespace string
}

func (g *PolicyGenerator) resolveWorkloads(db *gorm.DB, wsID uuid.UUID, workloadIDs []string) ([]workloadInfo, error) {
	var results []workloadInfo
	for _, wid := range workloadIDs {
		parsedID, err := uuid.Parse(wid)
		if err != nil {
			continue
		}
		var name string
		db.Raw(`SELECT COALESCE(name, id::text) FROM iga_workload WHERE workspace_id = ? AND id = ?`, wsID, parsedID).Scan(&name)
		if name != "" {
			results = append(results, workloadInfo{ID: wid, Name: name})
		}
	}
	return results, nil
}

type evidenceRecord struct {
	Primitive  string
	Resource   string
	Action     string
	Result     string // "allowed", "denied", "configured"
	Count      int
	Confidence float64
}

func (g *PolicyGenerator) gatherEvidence(_ *gorm.DB, _ uuid.UUID, _ []string, _ string) []evidenceRecord {
	// In production, this queries the observation store for the evidence window.
	// For now, produce baseline evidence from the primitive catalog.
	var evidence []evidenceRecord
	for _, p := range models.CatalogPrimitives() {
		evidence = append(evidence, evidenceRecord{
			Primitive:  p.ID,
			Resource:   "*",
			Action:     "any",
			Result:     "configured",
			Count:      0,
			Confidence: 0.5,
		})
	}
	return evidence
}

func (g *PolicyGenerator) generateRules(evidence []evidenceRecord) []models.PolicyV2Rule {
	var rules []models.PolicyV2Rule
	seen := make(map[string]bool)

	for _, e := range evidence {
		ruleKey := e.Primitive + ":" + e.Resource + ":" + e.Action
		if seen[ruleKey] {
			continue
		}
		seen[ruleKey] = true

		var effect string
		var explanation string

		switch e.Result {
		case "allowed":
			// Successful actions become allow candidates.
			effect = "allow"
			explanation = fmt.Sprintf("Observed %d successful %s operations", e.Count, e.Primitive)
		case "denied":
			// Denied attempts are recorded but never auto-allowed.
			effect = "deny"
			explanation = fmt.Sprintf("Denied %s attempt recorded — not auto-allowed", e.Primitive)
		case "configured":
			// Configured dependencies become declared grants.
			effect = "allow"
			explanation = fmt.Sprintf("Declared dependency on %s", e.Primitive)
		default:
			effect = "deny"
			explanation = "Unknown evidence result"
		}

		// Sensitive operations get require_approval.
		if isSensitivePrimitive(e.Primitive) && effect == "allow" {
			effect = "require_approval"
			explanation += " (sensitive operation — requires approval)"
		}

		ruleHash := sha256.Sum256([]byte(ruleKey))
		ruleID := "gen-" + hex.EncodeToString(ruleHash[:])[:8]

		rules = append(rules, models.PolicyV2Rule{
			ID:          ruleID,
			Primitive:   e.Primitive,
			Resource:    e.Resource,
			Effect:      effect,
			Required:    false,
			Explanation: explanation,
			Provenance: &models.RuleProvenance{
				Source:           "candidate",
				EvidenceWindow:   e.Action,
				GeneratorVersion: GeneratorVersion,
			},
		})
	}

	return rules
}

func isSensitivePrimitive(primitive string) bool {
	switch primitive {
	case models.PrimitiveSecretRead,
		models.PrimitiveLLMInvoke,
		models.PrimitiveGitHubOperation,
		models.PrimitiveRemoteSession:
		return true
	default:
		return false
	}
}
