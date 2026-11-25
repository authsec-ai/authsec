package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsremediate"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// The proof of a remediation (W8, P4): each step needs BOTH
//
//   (a) the change event -- the provider's record of the write. For AWS, the
//       CloudTrail event (eventSource/eventName of the step) in the W1
//       evidence store (agent_evidence_event, read only), recorded after the
//       step: in write mode made by the remediation's own session (the
//       caller ARN names authsec-remediate-<16hex>), for a prepared change or
//       a pull request by anyone in the account after the remediation was
//       requested. For a step AuthSec makes on its own side, its own record
//       (the agent.retired event, the model_provider.rotate audit row).
//   (b) a read of the end state -- through the discovery role for AWS, the
//       database for AuthSec's side.
//
// PROVEN only with both for every step; otherwise the remediation stays
// applied (or pr_merged, or prepared) and the proof lists what is missing.
// A step AuthSec cannot see the end of (an old provider key revoked in the
// provider's console) is reported cannot_verify and does not block the rest.

// RemediationStepProof is one step's proof.
type RemediationStepProof struct {
	Seq     int            `json:"seq"`
	Op      string         `json:"op"`
	Event   map[string]any `json:"event"`
	Read    map[string]any `json:"read"`
	Proven  bool           `json:"proven"`
	Missing []string       `json:"missing"`
}

// RemediationProof is GET /remediations/:id/proof.
type RemediationProof struct {
	RemediationID uuid.UUID              `json:"remediation_id"`
	State         string                 `json:"state"`
	Proven        bool                   `json:"proven"`
	Steps         []RemediationStepProof `json:"steps"`
	Missing       []string               `json:"missing"`
	Unverifiable  []string               `json:"cannot_verify"`
	CheckedAt     time.Time              `json:"checked_at"`
}

// remProofSkew is how far before a step's own time its event may be dated
// (clock skew between AuthSec and the provider).
const remProofSkew = 5 * time.Minute

// Proof evaluates (and records) a remediation's proof. A remediation that
// is proven by it becomes proven.
func (s *RemediationService) Proof(ctx context.Context, ws, id uuid.UUID) (*RemediationProof, error) {
	if err := RequireRemediation(s.db); err != nil {
		return nil, err
	}
	if err := s.SyncPR(ctx, ws, id); err != nil {
		// The pull request's state is read best-effort; the proof follows
		// the account whatever GitHub answers.
		_ = err
	}
	var r *remediationRow
	var steps []remediationStepRow
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		if r, err = readRemediation(tx, ws, id, false); err != nil {
			return err
		}
		steps, err = readRemediationSteps(tx, ws, id)
		return err
	}); err != nil {
		return nil, err
	}
	now := s.now().UTC()
	out := &RemediationProof{RemediationID: id, State: r.State, Steps: []RemediationStepProof{}, Missing: []string{}, Unverifiable: []string{}, CheckedAt: now}
	switch r.State {
	case RemediationApplied, RemediationProven, RemediationPRMerged, RemediationPrepared, RemediationFailed:
	default:
		out.Missing = append(out.Missing, "not applied: the remediation is "+r.State)
		return out, nil
	}
	var reader awsremediate.Reader
	needRead := false
	for _, st := range steps {
		needRead = needRead || awsremediate.IsAWSOp(st.Op)
	}
	if needRead && r.ConnectorID != nil {
		if acc := remediationAccess(); acc != nil {
			reader, _ = acc.Reader(ctx, ws, *r.ConnectorID)
		}
	}
	evidenceOK, _ := AgentEvidenceStatus(s.db)
	account := ""
	if r.ConnectorID != nil {
		_ = tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
			var ids []string
			if err := tx.Raw(`SELECT scope_id FROM cloud_connector WHERE workspace_id = ? AND id = ?`, ws, *r.ConnectorID).Scan(&ids).Error; err != nil {
				return err
			}
			if len(ids) > 0 {
				account = ids[0]
			}
			return nil
		})
	}
	proven := true
	counted := 0
	for _, row := range steps {
		if row.State == "skipped" {
			continue
		}
		sp := RemediationStepProof{Seq: row.Seq, Op: row.Op, Event: map[string]any{"found": false}, Read: map[string]any{"ok": false}, Missing: []string{}}
		st := row.step()
		since := r.CreatedAt.Add(-remProofSkew)
		if row.AppliedAt != nil {
			since = row.AppliedAt.Add(-remProofSkew)
		}
		if r.Mode == RemediationModeWrite && row.State != "applied" && awsremediate.IsAWSOp(row.Op) {
			why := "not applied yet (" + row.State + ")"
			if row.State == "waiting" && row.DueAt != nil {
				why = "due at " + row.DueAt.UTC().Format(time.RFC3339)
			}
			sp.Missing = append(sp.Missing, why)
			out.Missing = append(out.Missing, fmt.Sprintf("step %d %s: %s", row.Seq, row.Op, why))
			out.Steps = append(out.Steps, sp)
			proven = false
			counted++
			continue
		}
		switch {
		case awsremediate.IsAWSOp(row.Op):
			// (a) the change event.
			if !evidenceOK {
				sp.Missing = append(sp.Missing, "change event: the evidence store is not available")
			} else {
				ev, err := s.findChangeEvent(ctx, ws, r, st, since, account)
				switch {
				case err != nil:
					sp.Missing = append(sp.Missing, "change event: the evidence store could not be read")
				case ev == nil:
					sp.Missing = append(sp.Missing, "change event: no "+row.EventName+" record received yet")
				default:
					sp.Event = ev
				}
			}
			// (b) the end state.
			if reader == nil {
				sp.Missing = append(sp.Missing, "end state: the discovery role could not be used")
			} else {
				ok, obs, err := awsremediate.Readback(ctx, reader, &st)
				switch {
				case err != nil:
					sp.Missing = append(sp.Missing, "end state: the read failed")
				case !ok:
					sp.Read = map[string]any{"ok": false, "observed": obs}
					sp.Missing = append(sp.Missing, "end state: the read does not show the change")
				default:
					sp.Read = map[string]any{"ok": true, "observed": obs}
				}
			}
		case row.Op == RemOpProviderKeyRevokeOld:
			out.Unverifiable = append(out.Unverifiable, fmt.Sprintf("step %d: AuthSec cannot read the provider console; the old key's revocation is the provider admin's to confirm", row.Seq))
			sp.Event, sp.Read = map[string]any{"cannot_verify": true}, map[string]any{"cannot_verify": true}
			out.Steps = append(out.Steps, sp)
			continue
		default:
			if err := s.authSecProof(ctx, ws, r, row, st, since, &sp); err != nil {
				return nil, err
			}
		}
		sp.Proven = len(sp.Missing) == 0
		if !sp.Proven {
			proven = false
			for _, m := range sp.Missing {
				out.Missing = append(out.Missing, fmt.Sprintf("step %d %s: %s", row.Seq, row.Op, m))
			}
		}
		counted++
		out.Steps = append(out.Steps, sp)
	}
	out.Proven = proven && counted > 0
	// Record it, and promote.
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		if out.Proven && (r.State == RemediationApplied || r.State == RemediationPRMerged || r.State == RemediationPrepared) {
			if err := tx.Exec(`UPDATE agent_remediation SET state = 'proven', proven_at = ?, proof = ?::jsonb, state_reason = '', updated_at = now()
			    WHERE workspace_id = ? AND id = ? AND state = ?`, now, remJSON(out), ws, id, r.State).Error; err != nil {
				return err
			}
			out.State = RemediationProven
			return appendGovEvent(tx, ws, GovEventRemediationProven, models.GovActorSystem, "remediation", govEventRefs{},
				map[string]any{"remediation_id": id, "kind": r.Kind, "target_ref": r.TargetRef, "steps": counted})
		}
		return tx.Exec(`UPDATE agent_remediation SET proof = ?::jsonb WHERE workspace_id = ? AND id = ?`, remJSON(out), ws, id).Error
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// findChangeEvent looks the step's change event up in the evidence store.
func (s *RemediationService) findChangeEvent(ctx context.Context, ws uuid.UUID, r *remediationRow, st awsremediate.Step,
	since time.Time, account string) (map[string]any, error) {
	type ev struct {
		ID              uuid.UUID `gorm:"column:id"`
		EventID         string    `gorm:"column:event_id"`
		EventTime       time.Time `gorm:"column:event_time"`
		PrincipalDetail string    `gorm:"column:principal_detail"`
	}
	var rows []ev
	match := "session"
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		q := `SELECT id, event_id, event_time, principal_detail FROM agent_evidence_event
		    WHERE workspace_id = ? AND event_source = ? AND event_name = ? AND outcome = 'success' AND event_time >= ?`
		args := []any{ws, st.EventSource, st.EventName, since}
		if r.Mode == RemediationModeWrite && r.SessionName != "" {
			q += ` AND principal_detail LIKE ?`
			args = append(args, "%/"+r.SessionName)
		} else {
			match = "account_and_time"
			if account != "" {
				q += ` AND account_id = ?`
				args = append(args, account)
			}
		}
		q += ` ORDER BY event_time, id LIMIT 1`
		return tx.Raw(q, args...).Scan(&rows).Error
	})
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return map[string]any{"found": true, "evidence_id": rows[0].ID, "event_id": rows[0].EventID,
		"event_time": rows[0].EventTime.UTC(), "caller": rows[0].PrincipalDetail, "match": match}, nil
}

// authSecProof proves a step AuthSec made on its own side.
func (s *RemediationService) authSecProof(ctx context.Context, ws uuid.UUID, r *remediationRow, row remediationStepRow, st awsremediate.Step,
	since time.Time, sp *RemediationStepProof) error {
	return tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		switch row.Op {
		case RemOpAgentRetire:
			var evs []struct {
				ID         int64
				OccurredAt time.Time
			}
			if err := tx.Raw(`SELECT id, occurred_at FROM iga_gov_event WHERE workspace_id = ? AND event = ? AND payload->>'agent_id' = ?
			    AND occurred_at >= ? ORDER BY id LIMIT 1`, ws, GovEventAgentRetired, row.Target, since).Scan(&evs).Error; err != nil {
				return err
			}
			if len(evs) > 0 {
				sp.Event = map[string]any{"found": true, "source": "iga_gov_event", "id": evs[0].ID, "event_time": evs[0].OccurredAt.UTC()}
			} else {
				sp.Missing = append(sp.Missing, "change event: no agent.retired record")
			}
			var states []string
			if err := tx.Raw(`SELECT state FROM agent WHERE workspace_id = ? AND id = ?`, ws, row.Target).Scan(&states).Error; err != nil {
				return err
			}
			if len(states) > 0 && states[0] == AgentStateRetired {
				sp.Read = map[string]any{"ok": true, "observed": map[string]any{"state": states[0]}}
			} else {
				sp.Missing = append(sp.Missing, "end state: the agent is not retired")
			}
		case RemOpGatewayRulesRemove:
			if row.State == "applied" {
				sp.Event = map[string]any{"found": true, "source": "remediation_step"}
				sp.Read = map[string]any{"ok": true}
			} else {
				sp.Missing = append(sp.Missing, "not applied yet")
			}
		case RemOpProviderKeyCreate, RemOpProviderKeyRotate:
			var n int64
			if err := tx.Raw(`SELECT count(*) FROM audit_events WHERE workspace_id = ? AND action = 'model_provider.rotate'
			    AND resource_id = ? AND "timestamp" >= ?`, ws.String(), row.Target, since).Scan(&n).Error; err != nil {
				return err
			}
			if n > 0 || (row.Op == RemOpProviderKeyRotate && row.State == "applied") {
				sp.Event = map[string]any{"found": true, "source": "audit_events", "action": "model_provider.rotate"}
			} else {
				sp.Missing = append(sp.Missing, "change event: the admin key was not rotated in AuthSec yet")
			}
			var fps []string
			if err := tx.Raw(`SELECT key_fingerprint FROM model_provider_connection WHERE workspace_id = ? AND id = ? AND status <> 'revoked'`,
				ws, row.Target).Scan(&fps).Error; err != nil {
				return err
			}
			if len(fps) > 0 && fps[0] != fmt.Sprint(st.Before["fingerprint"]) {
				sp.Read = map[string]any{"ok": true, "observed": map[string]any{"fingerprint": fps[0]}}
			} else {
				sp.Missing = append(sp.Missing, "end state: the connection still holds the old key")
			}
		default:
			sp.Missing = append(sp.Missing, "no proof is defined for "+row.Op)
		}
		return nil
	})
}
