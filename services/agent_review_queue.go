package services

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

/* agent_review_queue.go hands the AI workloads inference cannot attribute to
   the AWS agent review service (authsec-aws-agent-discovery), through
   cloud_workload.attrs.agent_review:

     shared_role        -- an AI workload's role has several workloads; each
                           candidate workload gets status "pending", reason
                           "shared_role"
     ai_network_traffic -- model-provider DNS lookups from a Lambda network
                           interface several functions share (subject
                           kind "workload_set", resolved false); each
                           candidate gets reason "unattributed_dns"

   The service claims a pending row, investigates its CloudTrail and network
   logs, and writes the verdict back to the same key (status "decided" or
   "failed"); a confirmed or suspected agent is reported through
   POST /authsec/discovery/sightings. AuthSec never classifies on its verdict:
   classification stays a person's (SPEC-agent-runtime-visibility.md §3).

   A workload is queued only when it has no review yet, or its last one ended
   (decided or failed) more than AgentReviewRequeueAfter ago; pending and
   in-progress rows are the service's and are left alone. The scan carries
   agent_review over every upsert (workloadAttrsMerge).

   Queueing runs only where the service can work: when AGENT_REVIEW_SERVICE_TOKEN
   is set, the token it uses for AWS keys (agent_review_keys.go). */

// AgentReviewRequeueAfter is how long a finished review stands before an
// unattributed workload is queued again.
const AgentReviewRequeueAfter = 7 * 24 * time.Hour

// Agent review reasons, as the service reads them.
const (
	AgentReviewReasonSharedRole      = "shared_role"
	AgentReviewReasonUnattributedDNS = "unattributed_dns"
)

// AgentReviewSightingOrigin marks the sightings the review service reports
// (metadata.origin), with the fingerprint AWSAgentFingerprint gives the
// workload: the AWS agents mirror leaves them alone while their workload is
// in the inventory (retireAWSAgents).
const AgentReviewSightingOrigin = "aws_agent_review"

// AgentReviewServiceTokenEnv names the agent review service's token.
const AgentReviewServiceTokenEnv = "AGENT_REVIEW_SERVICE_TOKEN"

// agentReviewQueueEnabled reports whether a review service is configured.
func agentReviewQueueEnabled() bool { return os.Getenv(AgentReviewServiceTokenEnv) != "" }

// agentReviewRequest is one finding's candidates, queued with one reason.
type agentReviewRequest struct {
	Reason    string
	Context   map[string]any
	Workloads []uuid.UUID
}

// unresolvedDNSFinding is an open ai_network_traffic finding as stored.
type unresolvedDNSFinding struct {
	ID         uuid.UUID
	SubjectKey string
	Subject    json.RawMessage
}

// agentReviewRequests turns this pass's shared-role drafts and the open
// unresolved DNS findings into review requests. Pure, for the tests.
func agentReviewRequests(drafts []findingDraft, dns []unresolvedDNSFinding) []agentReviewRequest {
	var out []agentReviewRequest
	for _, d := range drafts {
		if d.Kind != FindingSharedRole {
			continue
		}
		var ids []uuid.UUID
		if wls, ok := d.Subject["workloads"].([]map[string]any); ok {
			for _, w := range wls {
				if id, ok := w["cloud_workload_id"].(uuid.UUID); ok && id != uuid.Nil {
					ids = append(ids, id)
				}
			}
		}
		ids = sortedUUIDs(ids)
		if len(ids) < 2 {
			continue // EKS service accounts alone: nothing in cloud_workload to review
		}
		ctx := map[string]any{"finding_kind": FindingSharedRole, "subject_key": d.SubjectKey,
			"role_arn": d.Subject["arn"], "candidates": len(ids)}
		if calls, ok := d.Evidence["model_calls"].(map[string]any); ok {
			ctx["models"] = calls["models"]
			ctx["last_call_at"] = calls["last_call_at"]
		}
		out = append(out, agentReviewRequest{Reason: AgentReviewReasonSharedRole, Context: ctx, Workloads: ids})
	}
	for _, f := range dns {
		var subj struct {
			Kind       string `json:"kind"`
			Resolved   *bool  `json:"resolved"`
			Region     string `json:"region"`
			ENI        string `json:"eni_id"`
			Candidates []struct {
				CloudWorkloadID uuid.UUID `json:"cloud_workload_id"`
			} `json:"candidates"`
		}
		if err := json.Unmarshal(f.Subject, &subj); err != nil || subj.Kind != "workload_set" ||
			subj.Resolved == nil || *subj.Resolved {
			continue
		}
		var ids []uuid.UUID
		for _, c := range subj.Candidates {
			if c.CloudWorkloadID != uuid.Nil {
				ids = append(ids, c.CloudWorkloadID)
			}
		}
		ids = sortedUUIDs(ids)
		if len(ids) == 0 {
			continue
		}
		out = append(out, agentReviewRequest{Reason: AgentReviewReasonUnattributedDNS,
			Context: map[string]any{"finding_kind": FindingAINetworkTraffic, "finding_id": f.ID,
				"subject_key": f.SubjectKey, "region": subj.Region, "eni_id": subj.ENI, "candidates": len(ids)},
			Workloads: ids})
	}
	return out
}

// queueAgentReviewSQL sets a workload's review to pending unless the service
// holds it or decided it recently. It keeps the previous verdict (the
// service flags a changed classification against it) and resets the claim
// bookkeeping.
const queueAgentReviewSQL = `UPDATE cloud_workload
	SET attrs = jsonb_set(attrs, '{agent_review}',
		COALESCE(attrs->'agent_review', '{}'::jsonb) || jsonb_build_object(
			'status', 'pending', 'reason', ?::text, 'context', ?::jsonb,
			'requested_at', ?::timestamptz, 'attempts', 0, 'last_error', '',
			'retry_after', NULL, 'lease_owner', '', 'lease_expires_at', NULL))
	WHERE workspace_id = ? AND connector_id = ? AND id IN ?
	  AND (attrs->'agent_review' IS NULL
	    OR (attrs->'agent_review'->>'status' IN ('decided', 'failed')
	      AND COALESCE(attrs->'agent_review'->>'decided_at', attrs->'agent_review'->>'requested_at',
	                   '-infinity')::timestamptz < ?))`

// queueAgentReviews queues this connector's unattributed AI workloads for
// the review service, in the inference transaction. It returns how many
// workloads it queued.
func queueAgentReviews(tx *gorm.DB, ws, connectorID uuid.UUID, drafts []findingDraft, now time.Time) (int, error) {
	if !agentReviewQueueEnabled() {
		return 0, nil
	}
	var dns []unresolvedDNSFinding
	if err := tx.Table("agent_finding").Select("id, subject_key, subject").
		Where("workspace_id = ? AND connector_id = ? AND kind = ? AND state = ?",
			ws, connectorID, FindingAINetworkTraffic, FindingOpen).
		Scan(&dns).Error; err != nil {
		return 0, fmt.Errorf("read network findings: %w", err)
	}
	queued := 0
	for _, r := range agentReviewRequests(drafts, dns) {
		ctx, _ := json.Marshal(r.Context)
		res := tx.Exec(queueAgentReviewSQL, r.Reason, string(ctx), now, ws, connectorID, r.Workloads,
			now.Add(-AgentReviewRequeueAfter))
		if res.Error != nil {
			return queued, fmt.Errorf("queue agent review (%s): %w", r.Reason, res.Error)
		}
		queued += int(res.RowsAffected)
	}
	return queued, nil
}

func sortedUUIDs(ids []uuid.UUID) []uuid.UUID {
	seen := map[uuid.UUID]bool{}
	out := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
