package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/authsec-ai/authsec/internal/runtimepolicy/rollout"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/pkg/collectorcontract"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const inlineArtifactLimit = 64 << 10

// rolloutPlan is stored in the 043 publications.rollout_plan column.
// Phase and the signed artifact bytes live here so delivery does not need
// a new table. A missing phase means complete: that publication is desired
// immediately, which is what a 043 row inserted before A7 already means.
type rolloutPlan struct {
	Phase       string   `json:"phase,omitempty"`
	LeasedUntil string   `json:"leased_until,omitempty"`
	LeaseOwner  string   `json:"lease_owner,omitempty"`
	Canary      []string `json:"canary_workload_ids,omitempty"`
	Window      int      `json:"window_seconds,omitempty"`
	Threshold   int      `json:"failure_threshold,omitempty"`
	Started     string   `json:"started_at,omitempty"`
	// Mode is the wire mode (observe, enforce, or revoked). publications.mode
	// stays observe|enforce; a revoke is mode "revoked" here and on the manifest.
	Mode    string `json:"mode,omitempty"`
	Revoked bool   `json:"revoked,omitempty"`
	// Reason is set when a canary window ends with no receipts.
	Reason    string                  `json:"pause_reason,omitempty"`
	Artifacts map[string]planArtifact `json:"artifacts,omitempty"`
}

type planArtifact struct {
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
	Body   string `json:"body"`
}

func (p rolloutPlan) phase() string {
	if p.Phase == "" {
		return "complete"
	}
	return p.Phase
}

type desiredArtifact struct {
	URL         string `json:"url"`
	SHA256      string `json:"sha256"`
	RegoVersion string `json:"rego_version,omitempty"`
	Body        string `json:"body,omitempty"`
}

type desiredState struct {
	Revision       int64           `json:"revision"`
	GraphRevision  int64           `json:"graph_revision"`
	ManifestID     string          `json:"manifest_id"`
	PolicyFormat   string          `json:"policy_format"`
	OPABundle      desiredArtifact `json:"opa_bundle"`
	Controls       desiredArtifact `json:"controls"`
	SignedManifest string          `json:"signed_manifest"`
	// Mode, Revoked, and Quarantine are additive. Quarantine is unsigned: it
	// reflects an accepted quarantine link at sync time and does not rewrite
	// the signed manifest.
	Mode       string `json:"mode,omitempty"`
	Revoked    bool   `json:"revoked,omitempty"`
	Quarantine bool   `json:"quarantine,omitempty"`
}

// GetRollout reports per-target §15.2 state for the latest publication.
func (s *RuntimePolicyService) GetRollout(ctx context.Context, ws, policyID uuid.UUID) (int, []byte, error) {
	var rows []struct {
		TargetID    uuid.UUID
		WorkloadID  uuid.UUID
		CollectorID uuid.UUID
		Delivery    int64
		Required    string
		Phase       string
		Controls    string
		Error       string
	}
	err := s.db.WithContext(ctx).Raw(`SELECT DISTINCT ON (t.id)
		t.id AS target_id, t.workload_id, t.collector_id, t.desired_delivery_revision AS delivery,
		t.required_controls::text AS required, COALESCE(p.rollout_plan->>'phase', 'complete') AS phase,
		COALESCE(r.control_status::text, '') AS controls, COALESCE(r.error, '') AS error
		FROM runtime_policy_targets t
		JOIN runtime_policy_publications p ON p.workspace_id = t.workspace_id AND p.id = t.publication_id
		LEFT JOIN runtime_policy_receipts r
		  ON r.workspace_id = t.workspace_id AND r.target_id = t.id AND r.delivery_revision = t.desired_delivery_revision
		WHERE t.workspace_id = ? AND p.policy_id = ?
		  AND p.id = (
		    SELECT id FROM runtime_policy_publications
		    WHERE workspace_id = ? AND policy_id = ? ORDER BY created_at DESC LIMIT 1
		  )
		ORDER BY t.id, r.observed_at DESC NULLS LAST`, ws, policyID, ws, policyID).Scan(&rows).Error
	if err != nil {
		return 0, nil, statusFrom(err)
	}
	if len(rows) == 0 {
		var n int64
		if err := s.db.WithContext(ctx).Raw(`SELECT count(*) FROM runtime_policies WHERE workspace_id = ? AND id = ?`, ws, policyID).Scan(&n).Error; err != nil {
			return 0, nil, statusFrom(err)
		}
		if n == 0 {
			return 0, nil, statusErr(http.StatusNotFound, "not_found", "Not found.")
		}
	}
	targets := make([]map[string]any, 0, len(rows))
	aggregate := map[string]int{}
	protected := 0
	for _, row := range rows {
		var required []string
		_ = json.Unmarshal([]byte(row.Required), &required)
		receiptState, controls := parseReceiptStatus(row.Controls)
		if row.Error != "" {
			receiptState = rollout.Failed
		}
		state := rollout.TargetState(row.Phase, receiptState, required, controls)
		ok := rollout.Protected(required, controls)
		if ok {
			protected++
		}
		aggregate[state]++
		targets = append(targets, map[string]any{
			"target_id": row.TargetID, "workload_id": row.WorkloadID, "collector_id": row.CollectorID,
			"desired_delivery_revision": row.Delivery, "state": state, "protected": ok,
			"phase": row.Phase,
		})
	}
	aggregate["protected"] = protected
	out, _ := json.Marshal(map[string]any{"data": map[string]any{
		"policy_id": policyID, "targets": targets, "aggregate": aggregate,
	}})
	return http.StatusOK, out, nil
}

// ReadPolicyArtifact returns the bytes of one artifact when this collector's
// current desired publication, or the publication named by its latest
// receipt, contains that artifact. A historical target that is neither still
// desired nor the latest receipt is not found, so a rolled-back collector can
// still fetch the bundle it is running.
//
// The lookup matches the artifact id inside rollout_plan. That is an
// unindexed jsonb scan; 048 does not add an expression index for it.
func ReadPolicyArtifact(db *gorm.DB, ws, collector, id uuid.UUID) (body []byte, kind, sum string, err error) {
	var rows []struct{ Plan string }
	qerr := db.Raw(`SELECT p.rollout_plan::text AS plan
		FROM runtime_policy_publications p
		JOIN runtime_policy_targets t
		  ON t.workspace_id = p.workspace_id AND t.publication_id = p.id AND t.collector_id = ?
		WHERE p.workspace_id = ?
		  AND (
		    p.rollout_plan->'artifacts'->'opa_bundle'->>'id' = ?
		    OR p.rollout_plan->'artifacts'->'controls'->>'id' = ?
		    OR p.rollout_plan->'artifacts'->'manifest'->>'id' = ?
		  )
		  AND (
		    p.id = (
		      SELECT p2.id
		      FROM runtime_policy_targets t2
		      JOIN runtime_policy_publications p2
		        ON p2.workspace_id = t2.workspace_id AND p2.id = t2.publication_id
		      WHERE t2.workspace_id = p.workspace_id AND t2.collector_id = ?
		        AND (
		          COALESCE(p2.rollout_plan->>'phase', 'complete') NOT IN ('canary', 'paused')
		          OR EXISTS (
		            SELECT 1
		            FROM jsonb_array_elements_text(COALESCE(p2.rollout_plan->'canary_workload_ids', '[]'::jsonb)) c(wid)
		            WHERE c.wid = t2.workload_id::text
		          )
		        )
		      ORDER BY t2.desired_delivery_revision DESC
		      LIMIT 1
		    )
		    OR p.id = (
		      SELECT r.publication_id
		      FROM runtime_policy_receipts r
		      JOIN runtime_policy_targets t3
		        ON t3.workspace_id = r.workspace_id AND t3.id = r.target_id
		      WHERE r.workspace_id = p.workspace_id AND t3.collector_id = ?
		      ORDER BY r.observed_at DESC
		      LIMIT 1
		    )
		  )
		LIMIT 1`, collector, ws, id.String(), id.String(), id.String(), collector, collector).Scan(&rows).Error
	if qerr != nil {
		return nil, "", "", qerr
	}
	if len(rows) == 0 {
		return nil, "", "", ErrCollectorNotFound
	}
	var plan rolloutPlan
	if json.Unmarshal([]byte(rows[0].Plan), &plan) != nil {
		return nil, "", "", ErrCollectorNotFound
	}
	for name, art := range plan.Artifacts {
		if art.ID != id.String() {
			continue
		}
		raw, decErr := base64.StdEncoding.DecodeString(art.Body)
		if decErr != nil || len(raw) == 0 {
			return nil, "", "", ErrCollectorNotFound
		}
		return raw, name, art.SHA256, nil
	}
	return nil, "", "", ErrCollectorNotFound
}

func loadDesiredBestEffort(tx *gorm.DB, ws, collector uuid.UUID, inline bool) (json.RawMessage, error) {
	if err := tx.Exec("SAVEPOINT policy_desired").Error; err != nil {
		return nil, err
	}
	raw, err := loadDesired(tx, ws, collector, inline)
	if err != nil {
		_ = tx.Exec("ROLLBACK TO SAVEPOINT policy_desired").Error
		return nil, err
	}
	if err := tx.Exec("RELEASE SAVEPOINT policy_desired").Error; err != nil {
		return nil, err
	}
	return raw, nil
}

func loadDesired(tx *gorm.DB, ws, collector uuid.UUID, inline bool) (json.RawMessage, error) {
	var rows []struct {
		Delivery int64
		Graph    int64
		PubID    uuid.UUID
		Phase    string
		Plan     string
		Workload string
	}
	err := tx.Raw(`SELECT t.desired_delivery_revision AS delivery, rev.graph_revision AS graph,
		p.id AS pub_id, COALESCE(p.rollout_plan->>'phase', 'complete') AS phase, p.rollout_plan::text AS plan, t.workload_id::text AS workload
		FROM runtime_policy_targets t
		JOIN runtime_policy_publications p ON p.workspace_id = t.workspace_id AND p.id = t.publication_id
		JOIN runtime_policy_revisions rev ON rev.workspace_id = p.workspace_id AND rev.policy_id = p.policy_id AND rev.revision = p.revision
		WHERE t.workspace_id = ? AND t.collector_id = ?
		ORDER BY t.desired_delivery_revision DESC`, ws, collector).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	var chosen *struct {
		Delivery int64
		Graph    int64
		PubID    uuid.UUID
		Phase    string
		Plan     string
		Workload string
	}
	for i := range rows {
		row := rows[i]
		if !desiredVisible(row.Phase, row.Plan, row.Workload) {
			continue
		}
		chosen = &row
		break
	}
	if chosen == nil {
		return json.RawMessage("null"), nil
	}
	var plan rolloutPlan
	if err := json.Unmarshal([]byte(chosen.Plan), &plan); err != nil {
		return json.RawMessage("null"), nil
	}
	bundle, okB := plan.Artifacts["opa_bundle"]
	controls, okC := plan.Artifacts["controls"]
	manifest, okM := plan.Artifacts["manifest"]
	if !okB || !okC || !okM {
		return json.RawMessage("null"), nil
	}
	bundleRaw, err := base64.StdEncoding.DecodeString(bundle.Body)
	if err != nil {
		return nil, err
	}
	controlsRaw, err := base64.StdEncoding.DecodeString(controls.Body)
	if err != nil {
		return nil, err
	}
	manifestRaw, err := base64.StdEncoding.DecodeString(manifest.Body)
	if err != nil {
		return nil, err
	}
	putBody := inline && len(bundleRaw)+len(controlsRaw) <= inlineArtifactLimit
	doc := desiredState{
		Revision: chosen.Delivery, GraphRevision: chosen.Graph, ManifestID: chosen.PubID.String(),
		PolicyFormat: models.RuntimePolicyFormatV1,
		OPABundle: desiredArtifact{
			URL: "/api/iga/v2/policy-artifacts/" + bundle.ID, SHA256: bundle.SHA256, RegoVersion: "v1",
		},
		Controls: desiredArtifact{
			URL: "/api/iga/v2/policy-artifacts/" + controls.ID, SHA256: controls.SHA256,
		},
		SignedManifest: string(manifestRaw),
		Mode:           plan.Mode,
		Revoked:        plan.Revoked,
	}
	var quarantined []struct{ N int }
	if err := tx.Raw(`SELECT 1 AS n FROM runtime_policy_targets t
		WHERE t.workspace_id = ? AND t.publication_id = ? AND t.collector_id = ?
		  AND (
		    EXISTS (
		      SELECT 1 FROM discovered_agent_workloads w
		      JOIN discovered_agents a ON a.workspace_id = w.workspace_id AND a.id = w.discovered_agent_id
		      WHERE w.workspace_id = t.workspace_id AND w.workload_id = t.workload_id
		        AND w.link_state = 'accepted' AND a.status = 'quarantined'
		    )
		    OR EXISTS (
		      SELECT 1 FROM agent_policies p
		      JOIN discovered_agent_workloads w
		        ON w.workspace_id = p.workspace_id AND w.discovered_agent_id = p.discovered_agent_id
		      WHERE p.workspace_id = t.workspace_id AND w.workload_id = t.workload_id
		        AND p.enabled AND p.desired_state = 'quarantined' AND w.link_state = 'accepted'
		    )
		  )
		LIMIT 1`, ws, chosen.PubID, collector).Scan(&quarantined).Error; err != nil {
		return nil, err
	}
	doc.Quarantine = len(quarantined) == 1
	if putBody {
		doc.OPABundle.Body = bundle.Body
		doc.Controls.Body = controls.Body
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func desiredVisible(phase, plan, workload string) bool {
	switch phase {
	case "canary", "paused":
		var body struct {
			Canary []string `json:"canary_workload_ids"`
		}
		_ = json.Unmarshal([]byte(plan), &body)
		for _, id := range body.Canary {
			if id == workload {
				return true
			}
		}
		return false
	case "rest", "complete", "revoked", "rolled_back":
		return true
	default:
		return false
	}
}

func recordReceiptsBestEffort(tx *gorm.DB, p *models.CollectorPrincipal, req *collectorcontract.SyncRequest) error {
	if p == nil || req == nil || len(req.Applied) == 0 {
		return nil
	}
	if err := tx.Exec("SAVEPOINT policy_receipts").Error; err != nil {
		return err
	}
	if err := recordReceipts(tx, p, req); err != nil {
		_ = tx.Exec("ROLLBACK TO SAVEPOINT policy_receipts").Error
		return err
	}
	return tx.Exec("RELEASE SAVEPOINT policy_receipts").Error
}

func recordReceipts(tx *gorm.DB, p *models.CollectorPrincipal, req *collectorcontract.SyncRequest) error {
	for _, ap := range req.Applied {
		wid, err := uuid.Parse(ap.WorkloadID)
		if err != nil {
			continue
		}
		var targets []struct {
			ID       uuid.UUID
			PubID    uuid.UUID
			PolicyID uuid.UUID
			Graph    int64
		}
		err = tx.Raw(`SELECT t.id, pub.policy_id, pub.id AS pub_id, rev.graph_revision AS graph
			FROM runtime_policy_targets t
			JOIN runtime_policy_publications pub ON pub.workspace_id = t.workspace_id AND pub.id = t.publication_id
			JOIN runtime_policy_revisions rev ON rev.workspace_id = pub.workspace_id AND rev.policy_id = pub.policy_id AND rev.revision = pub.revision
			WHERE t.workspace_id = ? AND t.collector_id = ? AND t.workload_id = ? AND t.desired_delivery_revision = ?`,
			p.WorkspaceID, p.CollectorID, wid, ap.DeliveryRevision).Scan(&targets).Error
		if err != nil {
			return err
		}
		reported := ap.Controls
		if reported == nil {
			reported = []collectorcontract.ControlReceipt{}
		}
		statusRaw, _ := json.Marshal(struct {
			ReceiptState string                             `json:"receipt_state"`
			Controls     []collectorcontract.ControlReceipt `json:"controls"`
		}{ReceiptState: ap.State, Controls: reported})
		hashes := make([]string, 0, len(reported))
		errText := ""
		if rollout.MapControlState(ap.State) == rollout.Failed {
			errText = ap.State
		}
		for _, c := range reported {
			if c.ArtifactSHA256 != "" {
				hashes = append(hashes, c.ArtifactSHA256)
			}
			if rollout.MapControlState(c.State) == rollout.Failed {
				errText = "failed"
			}
		}
		hashJSON, _ := json.Marshal(hashes)
		observed := ap.ObservedAt
		for _, t := range targets {
			// Skip when the latest receipt for this target and revision already
			// has the same generation, state, and controls. Receipts are
			// append-only, so an unchanged sync must not insert another row.
			if err := tx.Exec(`INSERT INTO runtime_policy_receipts
				(id, workspace_id, target_id, publication_id, policy_id, delivery_revision, runtime_generation, control_status, artifact_hashes, error, observed_at, graph_revision)
				SELECT ?, ?, ?, ?, ?, ?, ?, CAST(? AS jsonb), CAST(? AS jsonb), ?, COALESCE(NULLIF(?, '')::timestamptz, now()), ?
				WHERE NOT EXISTS (
					SELECT 1 FROM (
						SELECT runtime_generation, control_status
						FROM runtime_policy_receipts
						WHERE workspace_id = ? AND target_id = ? AND delivery_revision = ?
						ORDER BY observed_at DESC
						LIMIT 1
					) latest
					WHERE latest.runtime_generation = ?
					  AND latest.control_status = CAST(? AS jsonb)
				)`,
				uuid.New(), p.WorkspaceID, t.ID, t.PubID, t.PolicyID, ap.DeliveryRevision, ap.RuntimeGeneration,
				string(statusRaw), string(hashJSON), errText, observed, t.Graph,
				p.WorkspaceID, t.ID, ap.DeliveryRevision, ap.RuntimeGeneration, string(statusRaw),
			).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

// parseReceiptStatus reads the wrapper written by recordReceipts, or a legacy
// control array from a receipt stored before that wrapper.
func parseReceiptStatus(raw string) (string, []rollout.Control) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" {
		return "", nil
	}
	if strings.HasPrefix(raw, "{") {
		var wrap struct {
			ReceiptState string `json:"receipt_state"`
			Controls     []struct {
				Kind  string `json:"kind"`
				State string `json:"state"`
			} `json:"controls"`
		}
		if json.Unmarshal([]byte(raw), &wrap) == nil {
			controls := make([]rollout.Control, 0, len(wrap.Controls))
			for _, c := range wrap.Controls {
				controls = append(controls, rollout.Control{Kind: c.Kind, State: c.State})
			}
			return wrap.ReceiptState, controls
		}
	}
	var reported []struct {
		Kind  string `json:"kind"`
		State string `json:"state"`
	}
	if json.Unmarshal([]byte(raw), &reported) != nil {
		return "", nil
	}
	controls := make([]rollout.Control, 0, len(reported))
	for _, c := range reported {
		controls = append(controls, rollout.Control{Kind: c.Kind, State: c.State})
	}
	return "", controls
}
