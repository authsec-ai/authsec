package services

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

/* agent_rules_engine.go is the AI agent rules engine: four if/else rules on
   the six features (agent_rules_features.go) decide the clear workloads, and
   the unclear ones go to the agent review service (agent_review_queue.go).
   Checked in order, the first match wins:

     Rule 1  no loop, fan_out <= 1, no cross-workload trigger      NON_AI_WORKLOAD
     Rule 2  no loop, db_before_model, fan_out <= 2, no trigger    AI_AGENT_SUSPECTED (RAG)
     Rule 3  loop and fan_out >= 3                                 AI_AGENT_CONFIRMED (autonomous)
     Rule 4  loop and a cross-workload trigger                     AI_AGENT_CONFIRMED (multi-agent)

   Unclear, queued for the agent instead:

     contradicting_evidence  model-provider DNS traffic but no model call in CloudTrail
     intermittent_pattern    a loop in fewer than half of the windows
     borderline_features     no rule matches
     (shared_role            several workloads on the role: agent_review_queue.go)

   It runs for an AI workload whose role has exactly one workload (a shared
   role is the queue's), at the end of inference, and only while the review
   service is configured. It writes nothing of AuthSec's own: not
   classification, not suggestions, not labels. Its verdict lives in
   cloud_workload.attrs.agent_review (decided_by "rules"), and a confirmed or
   suspected agent is a sighting (metadata.origin AgentRulesSightingOrigin) on
   the Agents list. It never overwrites the review service: a workload the
   service holds or decided in the last AgentReviewRequeueAfter is left alone. */

// Labels the rules engine and the review service write.
const (
	AgentLabelNonAI     = "NON_AI_WORKLOAD"
	AgentLabelSuspected = "AI_AGENT_SUSPECTED"
	AgentLabelConfirmed = "AI_AGENT_CONFIRMED"
)

// Reasons the rules engine queues a workload for the review service.
const (
	AgentReviewReasonContradicting = "contradicting_evidence"
	AgentReviewReasonIntermittent  = "intermittent_pattern"
	AgentReviewReasonBorderline    = "borderline_features"
)

// AgentRulesSightingOrigin marks the rules engine's sightings (metadata.origin).
const AgentRulesSightingOrigin = "aws_agent_rules"

// agentRulesLookback is how far back a workload's events are read, and the
// most events read for one workload (the newest).
const (
	agentRulesLookback  = AgentRuntimeWindowDays * 24 * time.Hour
	agentRulesMaxEvents = 5000
)

// AgentRuleDecision is the engine's answer for one workload: a label (Rule
// set), or a reason to ask the review service (Reason set).
type AgentRuleDecision struct {
	Label   string
	Pattern string
	Rule    string
	Reason  string
}

// decideAgentRules applies the rules to one workload's features. contradicts:
// model-provider network traffic was seen for it although CloudTrail shows no
// model call.
func decideAgentRules(f AgentRuleFeatures, contradicts bool) AgentRuleDecision {
	if contradicts && f.AICalls == 0 {
		return AgentRuleDecision{Reason: AgentReviewReasonContradicting}
	}
	if f.LoopsDetected && f.LoopWindows*2 < f.Windows {
		return AgentRuleDecision{Reason: AgentReviewReasonIntermittent}
	}
	switch {
	case !f.LoopsDetected && f.FanOut <= 1 && !f.CrossWorkloadTriggers:
		return AgentRuleDecision{Label: AgentLabelNonAI, Pattern: "simple_ai_call", Rule: "rule_1_simple_ai_call"}
	case !f.LoopsDetected && f.SequenceOrdering == OrderingDBBeforeModel && f.FanOut <= 2 && !f.CrossWorkloadTriggers:
		return AgentRuleDecision{Label: AgentLabelSuspected, Pattern: "rag_pipeline", Rule: "rule_2_rag_pipeline"}
	case f.LoopsDetected && f.FanOut >= 3:
		return AgentRuleDecision{Label: AgentLabelConfirmed, Pattern: "autonomous_agent", Rule: "rule_3_autonomous_agent"}
	case f.LoopsDetected && f.CrossWorkloadTriggers:
		return AgentRuleDecision{Label: AgentLabelConfirmed, Pattern: "multi_agent_system", Rule: "rule_4_multi_agent_system"}
	}
	return AgentRuleDecision{Reason: AgentReviewReasonBorderline}
}

// agentReviewFreeSQL: the workload has no review, or one that ended and is
// the rules engine's own or older than the requeue period. Pending and
// in-progress reviews, and the service's recent verdicts, are never touched.
const agentReviewFreeSQL = `(attrs->'agent_review' IS NULL
	OR (attrs->'agent_review'->>'status' IN ('decided', 'failed')
	  AND (attrs->'agent_review'->'verdict'->>'decided_by' = 'rules'
	    OR COALESCE(attrs->'agent_review'->>'decided_at', attrs->'agent_review'->>'requested_at',
	                '-infinity')::timestamptz < ?)))`

const rulesDecideSQL = `UPDATE cloud_workload
	SET attrs = jsonb_set(attrs, '{agent_review}',
		COALESCE(attrs->'agent_review', '{}'::jsonb) || jsonb_build_object(
			'status', 'decided', 'verdict', ?::jsonb, 'decided_at', ?::timestamptz,
			'attempts', 0, 'last_error', '', 'retry_after', NULL,
			'lease_owner', '', 'lease_expires_at', NULL))
	WHERE workspace_id = ? AND connector_id = ? AND id = ? AND ` + agentReviewFreeSQL

const rulesQueueSQL = `UPDATE cloud_workload
	SET attrs = jsonb_set(attrs, '{agent_review}',
		COALESCE(attrs->'agent_review', '{}'::jsonb) || jsonb_build_object(
			'status', 'pending', 'reason', ?::text, 'context', ?::jsonb,
			'requested_at', ?::timestamptz, 'attempts', 0, 'last_error', '',
			'retry_after', NULL, 'lease_owner', '', 'lease_expires_at', NULL))
	WHERE workspace_id = ? AND connector_id = ? AND id = ? AND ` + agentReviewFreeSQL

// applyAgentRules runs the rules engine over this pass's AI workloads, in the
// inference transaction. It returns the fingerprints of the agents it
// reported, which the AWS agents mirror keeps (retireAWSAgents).
func (s *AgentRuntimeService) applyAgentRules(tx *gorm.DB, ws uuid.UUID, conn arConnector, ais []*AIWorkload,
	now time.Time, res *AgentInferenceResult) (map[string]bool, error) {
	reported := map[string]bool{}
	if !agentReviewQueueEnabled() {
		return reported, nil
	}
	cutoff := now.Add(-AgentReviewRequeueAfter)
	for _, ai := range ais {
		w := ai.single()
		if w == nil || ai.SharedRole {
			continue // a shared role is the queue's; an identity others assume has no single workload
		}
		events, err := loadRuleEvents(tx, ws, ai.Identity.ID, now)
		if err != nil {
			return reported, err
		}
		f := computeAgentRuleFeatures(events)
		contradicts := len(ai.NetworkTraffic) > 0 && ai.win.Calls == 0 && ai.win.Denied == 0
		if f.Windows == 0 && !contradicts {
			continue // no CloudTrail event recorded for it yet: nothing to decide on
		}
		d := decideAgentRules(f, contradicts)
		if d.Reason != "" {
			ctx, _ := json.Marshal(map[string]any{"decided_by": "rules", "features": f,
				"role_arn": ai.Identity.ARN, "network_findings": len(ai.NetworkTraffic)})
			r := tx.Exec(rulesQueueSQL, d.Reason, string(ctx), now, ws, conn.ID, w.ID, cutoff)
			if r.Error != nil {
				return reported, fmt.Errorf("queue %s: %w", w.NativeID, r.Error)
			}
			res.RulesQueued += int(r.RowsAffected)
			continue
		}
		verdict, _ := json.Marshal(map[string]any{"label": d.Label, "pattern": d.Pattern, "rule": d.Rule,
			"decided_by": "rules", "features": f, "published_to_discovered_agents": d.Label != AgentLabelNonAI,
			"decided_at": now})
		r := tx.Exec(rulesDecideSQL, string(verdict), now, ws, conn.ID, w.ID, cutoff)
		if r.Error != nil {
			return reported, fmt.Errorf("decide %s: %w", w.NativeID, r.Error)
		}
		if r.RowsAffected == 0 {
			continue // the review service holds or recently decided it
		}
		res.RulesDecided++
		if d.Label == AgentLabelNonAI || w.isAgent() {
			continue // a classified workload is the mirror's to list
		}
		fp := AWSAgentFingerprint(conn.ScopeID, w.RuntimeKind, w.NativeID)
		if _, _, err := repositories.NewDiscoveryRepository(tx).UpsertSighting(rulesSighting(ws, conn, w, ai, d, f, now)); err != nil {
			return reported, fmt.Errorf("report %s: %w", w.NativeID, err)
		}
		reported[fp] = true
	}
	return reported, nil
}

// loadRuleEvents reads an identity's newest CloudTrail events in the lookback,
// oldest first.
func loadRuleEvents(tx *gorm.DB, ws, identity uuid.UUID, now time.Time) ([]ruleEvent, error) {
	var rows []struct {
		OccurredAt  time.Time
		Kind        string
		EventSource string
		EventName   string
		ModelID     string
	}
	if err := tx.Raw(`SELECT occurred_at, kind,
			COALESCE(attrs->>'event_source', '') AS event_source,
			COALESCE(attrs->>'event_name', '') AS event_name,
			COALESCE(attrs->'request_facts'->>'model_id', '') AS model_id
		FROM agent_activity_event
		WHERE workspace_id = ? AND identity_id = ? AND source IN ('cloudtrail', 'cloudtrail_data')
		  AND occurred_at >= ?
		ORDER BY occurred_at DESC LIMIT ?`, ws, identity, now.Add(-agentRulesLookback), agentRulesMaxEvents).
		Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("read activity: %w", err)
	}
	out := make([]ruleEvent, 0, len(rows))
	for i := len(rows) - 1; i >= 0; i-- {
		r := rows[i]
		ai := r.Kind == "model_call" || isSageMakerInvocation(r.EventSource, r.EventName)
		e := ruleEvent{At: r.OccurredAt, Service: ruleServiceOf(r.EventSource), Name: r.EventName, AI: ai}
		if ai {
			e.ModelID = r.ModelID
		}
		out = append(out, e)
	}
	return out, nil
}

func rulesSighting(ws uuid.UUID, conn arConnector, w *arWorkload, ai *AIWorkload, d AgentRuleDecision,
	f AgentRuleFeatures, now time.Time) *models.DiscoveredAgent {
	archetype := models.AgentArchetypeHybrid
	switch d.Pattern {
	case "autonomous_agent", "multi_agent_system":
		archetype = models.AgentArchetypeAutonomous
	case "rag_pipeline":
		archetype = models.AgentArchetypeDelegated
	}
	meta, _ := json.Marshal(map[string]any{
		"provider": models.CloudProviderAWS, "account_id": conn.ScopeID, "connector_id": conn.ID,
		"region": w.Region, "runtime_kind": w.RuntimeKind, "native_id": w.NativeID,
		"cloud_workload_id": w.ID, "role_arn": ai.Identity.ARN,
		"origin": AgentRulesSightingOrigin, "label": d.Label, "rule": d.Rule, "pattern": d.Pattern,
		"decided_by": "rules", "features": f,
	})
	name := w.Name
	if name == "" {
		name = w.NativeID
	}
	return &models.DiscoveredAgent{
		ID: uuid.New(), WorkspaceID: ws, Source: models.DiscoverySourceAWS,
		Fingerprint: AWSAgentFingerprint(conn.ScopeID, w.RuntimeKind, w.NativeID),
		DisplayName: name, Metadata: meta,
		DeploymentOrigin: models.DeploymentOriginUnknown,
		Archetype:        archetype,
		EvidenceMode:     models.EvidenceInferred,
		Status:           models.DiscoveredAgentUnregistered,
		RuntimeStatus:    models.RuntimeStatusUnknown, RuntimeObservedAt: &now,
		FirstSeenAt: now, LastSeenAt: now, SightingCount: 1,
		CreatedBy: "aws-agent-rules",
	}
}
