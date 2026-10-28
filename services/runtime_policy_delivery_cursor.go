package services

import (
	"encoding/base64"
	"encoding/json"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type desiredStateEntry struct {
	desiredState
	DeliveryCursor int64 `json:"delivery_cursor"`
}

func cursorBuildRef(a planArtifact) desiredArtifact {
	return desiredArtifact{URL: cursorRefBase + a.ID, SHA256: a.SHA256}
}

var cursorRefBase = "/api/iga/v2/policy-artifacts/"

func loadDesiredSinceCursor(tx *gorm.DB, ws, collector uuid.UUID, cursor int64) ([]desiredStateEntry, int64, error) {
	var rows []struct {
		Delivery int64
		Graph    int64
		PubID    uuid.UUID
		Phase    string
		Plan     string
		Workload string
	}
	q := `SELECT t.desired_delivery_revision AS delivery, rev.graph_revision AS graph,
		p.id AS pub_id, COALESCE(p.rollout_plan->>'phase', 'complete') AS phase,
		p.rollout_plan::text AS plan, t.workload_id::text AS workload
		FROM runtime_policy_targets t
		JOIN runtime_policy_publications p ON p.workspace_id = t.workspace_id AND p.id = t.publication_id
		JOIN runtime_policy_revisions rev ON rev.workspace_id = p.workspace_id
		  AND rev.policy_id = p.policy_id AND rev.revision = p.revision
		WHERE t.workspace_id = ? AND t.collector_id = ? AND t.desired_delivery_revision > ?
		ORDER BY t.desired_delivery_revision ASC`
	if err := tx.Raw(q, ws, collector, cursor).Scan(&rows).Error; err != nil {
		return nil, cursor, err
	}
	var entries []desiredStateEntry
	maxCursor := cursor
	for _, row := range rows {
		if !desiredVisible(row.Phase, row.Plan, row.Workload) {
			continue
		}
		var plan rolloutPlan
		if json.Unmarshal([]byte(row.Plan), &plan) != nil {
			continue
		}
		bundle, okB := plan.Artifacts["opa_bundle"]
		controls, okC := plan.Artifacts["controls"]
		manifest, okM := plan.Artifacts["manifest"]
		if !okB || !okC || !okM {
			continue
		}
		manifestRaw, err := base64.StdEncoding.DecodeString(manifest.Body)
		if err != nil {
			continue
		}
		doc := desiredState{
			WorkloadID:     row.Workload,
			Revision:       row.Delivery,
			GraphRevision:  row.Graph,
			ManifestID:     row.PubID.String(),
			PolicyFormat:   models.RuntimePolicyFormatV1,
			OPABundle:      cursorBuildRef(bundle),
			Controls:       cursorBuildRef(controls),
			SignedManifest: string(manifestRaw),
			Mode:           plan.Mode,
			Revoked:        plan.Revoked,
		}
		entries = append(entries, desiredStateEntry{desiredState: doc, DeliveryCursor: row.Delivery})
		if row.Delivery > maxCursor {
			maxCursor = row.Delivery
		}
	}
	return entries, maxCursor, nil
}
