package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
)

// Drift (§8.8) and unknown-outcome resolution (§8.1 steps 2 and 5; T3.16).
//
// drift_check reads the role and its boundary through the discovery role,
// as an enforcement observer: the control's sequence is read BEFORE the
// readback and the posture is written only by the transaction that wins the
// compare-and-swap; a lost swap discards the read and reads again. It NEVER
// writes AWS: R1a does not auto-reconcile (Re-apply is a new plan and
// approval; Accept drift closes the deployment).

// Drift classifications (§8.8).
const (
	DriftBoundaryReplaced    = "boundary_replaced"
	DriftDocumentChanged     = "document_changed"
	DriftArtifactDeleted     = "artifact_deleted"
	DriftAttachedElsewhere   = "artifact_attached_elsewhere"
	DriftTargetGone          = "target_gone"
	DriftLateMutation        = "late_mutation_suspected"
	unknownResolvedConflict  = "conflict"
	unknownVerdictApplied    = AttemptResolvedApplied
	unknownVerdictNotApplied = AttemptResolvedNotApplied
)

func rawSHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// driftReason classifies a live read of a verified deployment's role.
func driftReason(p igagov.Plan, live igagov.LiveRead, cl igagov.Classification) string {
	roleID := ""
	for _, f := range p.Facts {
		if f.Kind == igagov.FactRole {
			roleID = f.Before
		}
	}
	if live.Role == nil || (roleID != "" && live.Role.RoleID != roleID) {
		return DriftTargetGone
	}
	switch p.DesiredAttachment {
	case igagov.AttachmentPresent:
		arn := *p.DesiredBoundaryARN
		pol, read := live.Policies[arn]
		if read && pol == nil && isAuthSecPolicyARN(arn) {
			return DriftArtifactDeleted
		}
		if live.Role.BoundaryARN != arn {
			return DriftBoundaryReplaced
		}
		if pol != nil {
			if h, err := pol.DocumentHash(); err == nil && p.DesiredDocumentHash != nil && h != *p.DesiredDocumentHash {
				return DriftDocumentChanged
			}
			for _, e := range pol.AttachmentSet {
				if !(e.Kind == "role" && e.ID == live.Role.RoleID && e.Usage == igagov.UsageBoundary) {
					return DriftAttachedElsewhere
				}
			}
		}
	case igagov.AttachmentAbsent:
		if live.Role.BoundaryARN != "" {
			return DriftBoundaryReplaced
		}
	}
	if cl.Reason == igagov.ConflictConsumersChanged {
		return DriftAttachedElsewhere
	}
	return DriftBoundaryReplaced
}

func isAuthSecPolicyARN(arn string) bool {
	return ownedBy(arn) == ArtifactOwnedDirect
}

// DriftHandler is the drift_check job of a verified deployment.
func (s *GovDeployments) DriftHandler(ctx context.Context, run *PolicyJobRun) error {
	if run.Job.SubjectID == nil {
		return PolicyJobAbandon("drift_check needs a deployment subject")
	}
	ws := run.Job.WorkspaceID
	db := run.DB().WithContext(ctx)
	d, err := s.loadDeployment(db, ws, *run.Job.SubjectID)
	if err != nil {
		var ge *GovError
		if errors.As(err, &ge) {
			return PolicyJobAbandon("deployment not found")
		}
		return err
	}
	if d.State != models.GovDeployVerified || d.Delivery != igagov.DeliveryDirect {
		return nil
	}
	plan, err := loadGovPlan(run.DB(), ws, d.PlanID)
	if err != nil {
		return err
	}
	ctl, err := s.loadControl(db, ws, d.ControlID)
	if err != nil {
		return err
	}
	return s.recordDrift(ctx, run, *d, plan, *ctl, "", igagov.LiveRead{})
}

// recordDrift is the drift observer. reason "" means: read and classify;
// a clean read only stamps the ledger's last_readback_at.
func (s *GovDeployments) recordDrift(ctx context.Context, run *PolicyJobRun, d models.IGAGovDeployment, p igagov.Plan, ctl models.IGAGovControl, _ string, _ igagov.LiveRead) error {
	ws := d.WorkspaceID
	clean, retired := false, false
	_, err := s.observe(ctx, run, func(ctx context.Context) (*govObservation, error) {
		db := run.DB().WithContext(ctx)
		cur, err := s.loadDeployment(db, ws, d.ID)
		if err != nil {
			return nil, err
		}
		if cur.State != models.GovDeployVerified && cur.State != models.GovDeployAppliedUnverified {
			return nil, nil // undone, superseded or already drifted meanwhile
		}
		seen, cstate, err := controlSeen(db, ws, d.ControlID)
		if err != nil {
			return nil, err
		}
		if cstate == "removed" {
			return nil, nil // a retired control is fenced: nothing to observe
		}
		if err := s.hook("before_read", d.ControlID, nil); err != nil {
			return nil, err
		}
		live, cl, err := s.readPlan(ctx, run, *cur, p, ctl)
		if err != nil {
			return nil, err
		}
		if cl.Class == igagov.ClassAfter {
			clean = true
			return nil, nil
		}
		reason := driftReason(p, live, cl)
		sub := ""
		if late, err := s.lateMutation(db, ws, d.ControlID, live); err != nil {
			return nil, err
		} else if late != nil {
			sub, reason = reason, DriftLateMutation
		}
		retired = reason == DriftTargetGone
		o := &govObservation{Dep: *cur, ControlID: d.ControlID, Seen: seen, InForce: inForce(live), Writer: "drift_check",
			Retire: retired}
		o.Step2 = func(tx *gorm.DB, newSeq int64) error {
			if err := setStateTx(tx, *cur, []string{models.GovDeployVerified, models.GovDeployAppliedUnverified},
				map[string]any{"state": models.GovDeployDrifted, "state_reason": reason}); err != nil {
				return err
			}
			ledger := "drifted"
			if reason == DriftArtifactDeleted {
				ledger = "lost"
			}
			if err := tx.Exec(`UPDATE iga_gov_artifact SET state = ?, last_readback_at = now(), updated_at = now()
				WHERE workspace_id = ? AND control_id = ? AND state IN ('present','drifted')`, ledger, ws, d.ControlID).Error; err != nil {
				return err
			}
			payload := map[string]any{"classification": reason, "detail": sub, "facts": cl.Facts, "conflicts": cl.Conflicts,
				"enforcement_seq": newSeq, "boundary": inForce(live),
				"next_actions": []string{"re_apply (a new plan and approval)", "accept_drift"}}
			if reason == DriftAttachedElsewhere {
				payload["severity"] = "high"
				payload["note"] = "AuthSec does not detach its policy from the other entity; undo and re-apply are restricted to role-only plans."
			}
			if err := s.sysEvent(tx, *cur, GovEventDeploymentDrifted, payload); err != nil {
				return err
			}
			if reason == DriftLateMutation {
				if err := s.sysEvent(tx, *cur, GovEventDriftLateMutation, map[string]any{"underlying": sub,
					"note": "A change matching an earlier unknown request appeared; nothing was re-applied or reverted."}); err != nil {
					return err
				}
			}
			if reason == DriftTargetGone {
				return s.sysEvent(tx, *cur, GovEventControlRoleGone, map[string]any{"control_id": d.ControlID, "reason": "role_gone"})
			}
			return nil
		}
		return o, nil
	})
	if err != nil {
		return err
	}
	if clean {
		return run.InTx(ctx, func(tx *gorm.DB) error {
			return tx.Exec(`UPDATE iga_gov_artifact SET last_readback_at = now() WHERE workspace_id = ? AND control_id = ?
				AND state = 'present'`, ws, d.ControlID).Error
		})
	}
	// target_gone: the role's findings are superseded (§2.2), after posture.
	if retired {
		return run.InTx(ctx, func(tx *gorm.DB) error {
			return tx.Exec(`UPDATE iga_gov_finding SET status = 'superseded', status_changed_at = now(), excepted_until = NULL
				WHERE workspace_id = ? AND role_id = ? AND status <> 'superseded'`, ws, ctl.RoleID).Error
		})
	}
	return nil
}

// lateMutation is §8.1 step 5: an unknown attempt on the control in the last
// 24 h whose document is the boundary now in force.
func (s *GovDeployments) lateMutation(db *gorm.DB, ws, control uuid.UUID, live igagov.LiveRead) (*models.IGAGovAttempt, error) {
	bf := inForce(live)
	if bf == nil {
		return nil, nil
	}
	var atts []models.IGAGovAttempt
	if err := db.Raw(`SELECT a.* FROM iga_gov_attempt a JOIN iga_gov_deployment d ON d.workspace_id = a.workspace_id AND d.id = a.deployment_id
		WHERE a.workspace_id = ? AND d.control_id = ? AND a.status = 'unknown' AND a.dispatched_at > ? AND a.document_hash = ?
		ORDER BY a.dispatched_at DESC LIMIT 1`, ws, control, s.now().Add(-LateMutationWatch), bf.DocHash).Scan(&atts).Error; err != nil {
		return nil, err
	}
	if len(atts) == 0 {
		return nil, nil
	}
	return &atts[0], nil
}

/* ----------------------------- resolve_unknown ------------------------------ */

type unknownReading struct {
	AttemptID  string    `json:"attempt_id"`
	Resolution string    `json:"resolution"`
	ReadAt     time.Time `json:"read_at"`
	Trail      string    `json:"trail"`
}

// ResolveUnknownHandler is §8.1 step 2: after settle_after, two readings at
// least 5 minutes apart (each recorded as an event), consistent with each
// other and with the enforcement session's CloudTrail events, resolve the
// attempt (applied / not_applied) and return the deployment to applying
// (the deploy job resumes or recognises the op). Anything else makes the
// deployment outcome_unresolved, which still holds the role.
//
// DECISION (T3.16): an op a read cannot see (TagPolicy, a version delete;
// igagov ResolvedUnobservable) is resolved from CloudTrail when the session
// shows it, and otherwise as not_applied: the op is idempotent or
// recognisable (§8.5), so the new attempt that follows is safe.
func (s *GovDeployments) ResolveUnknownHandler(ctx context.Context, run *PolicyJobRun) error {
	if run.Job.SubjectID == nil {
		return PolicyJobAbandon("resolve_unknown needs a deployment subject")
	}
	ws := run.Job.WorkspaceID
	db := run.DB().WithContext(ctx)
	d, err := s.loadDeployment(db, ws, *run.Job.SubjectID)
	if err != nil {
		var ge *GovError
		if errors.As(err, &ge) {
			return PolicyJobAbandon("deployment not found")
		}
		return err
	}
	if d.State != models.GovDeployOutcomeUnknown {
		return nil
	}
	now := s.now()
	if d.SettleAfter != nil && now.Before(*d.SettleAfter) {
		return PolicyJobRetryLater(d.SettleAfter.Sub(now), "settle_after not reached")
	}
	plan, err := loadGovPlan(run.DB(), ws, d.PlanID)
	if err != nil {
		return err
	}
	exec, err := s.executor()
	if err != nil {
		return PolicyJobRetryLater(5*time.Minute, err.Error())
	}
	rd, err := exec.ClassifyUnknown(ctx, run, *d, plan)
	if err != nil {
		if isLeaseErr(err) {
			return err
		}
		if errors.Is(err, ErrAttemptState) {
			return nil
		}
		return PolicyJobRetryLater(time.Minute, "unknown-outcome read failed: "+err.Error())
	}
	ctl, err := s.loadControl(db, ws, d.ControlID)
	if err != nil {
		return err
	}
	verdict, err := s.trailVerdict(ctx, *d, *ctl, rd.Attempt)
	if err != nil {
		return err
	}
	this := unknownReading{AttemptID: rd.Attempt.ID.String(), Resolution: rd.Resolution.Resolution, ReadAt: now.UTC(), Trail: verdict}
	prev, err := s.lastReading(db, *d, rd.Attempt.ID)
	if err != nil {
		return err
	}
	if err := run.InTx(ctx, func(tx *gorm.DB) error {
		return s.sysEvent(tx, *d, GovEventUnknownReading, map[string]any{"attempt_id": this.AttemptID, "resolution": this.Resolution,
			"read_at": this.ReadAt, "trail": this.Trail, "classification": rd.Resolution.Classification})
	}); err != nil {
		return err
	}
	if prev == nil || now.Sub(prev.ReadAt) < DefaultUnknownReadingGap {
		wait := DefaultUnknownReadingGap
		if prev != nil {
			wait = DefaultUnknownReadingGap - now.Sub(prev.ReadAt)
		}
		return PolicyJobRetryLater(wait, "a second reading is taken 5 minutes after the first")
	}
	res := ""
	switch {
	case this.Resolution == unknownResolvedConflict || prev.Resolution != this.Resolution:
	case this.Resolution == igagov.ResolvedUnobservable:
		res = unknownVerdictNotApplied
		if verdict != "" {
			res = verdict
		}
	case verdict != "" && verdict != this.Resolution:
	default:
		res = this.Resolution
	}
	if res == "" {
		return s.markUnresolved(ctx, run, *d, prev, this)
	}
	att := rd.Attempt
	if err := s.attempts.ResolveUnknown(ctx, run, &att, res); err != nil {
		return err
	}
	return run.InTx(ctx, func(tx *gorm.DB) error {
		return enqueueJobTx(tx, ws, "deploy", d.ID, s.now())
	})
}

func (s *GovDeployments) lastReading(db *gorm.DB, d models.IGAGovDeployment, attempt uuid.UUID) (*unknownReading, error) {
	var rows []json.RawMessage
	if err := db.Raw(`SELECT payload FROM iga_gov_event WHERE workspace_id = ? AND deployment_id = ? AND event = ?
		AND payload->>'attempt_id' = ?
		AND id > COALESCE((SELECT max(id) FROM iga_gov_event WHERE workspace_id = ? AND deployment_id = ? AND event = ?), 0)
		ORDER BY id DESC LIMIT 1`, d.WorkspaceID, d.ID, GovEventUnknownReading, attempt.String(),
		d.WorkspaceID, d.ID, GovEventDeploymentResolveReq).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	var r unknownReading
	if err := json.Unmarshal(rows[0], &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// trailVerdict reads the enforcement session's CloudTrail events for the
// attempt's operation: a success means applied, only errors mean not
// applied, none means no evidence ("").
func (s *GovDeployments) trailVerdict(ctx context.Context, d models.IGAGovDeployment, ctl models.IGAGovControl, att models.IGAGovAttempt) (string, error) {
	tr := s.envNow().Trail
	if tr == nil {
		return "", nil
	}
	from := s.now().Add(-time.Hour)
	if att.SignedAt != nil {
		from = att.SignedAt.Add(-time.Minute)
	}
	evs, err := tr.EnforcementSessionEvents(ctx, d.WorkspaceID, ctl.ConnectorID, "authsec-enforce-"+roleSessionHex(d.ID), from, s.now())
	if err != nil {
		return "", nil // CloudTrail unavailable: no evidence either way
	}
	seen, ok := false, false
	for _, e := range evs {
		if e.EventName != att.Operation {
			continue
		}
		seen = true
		if e.ErrorCode == "" {
			ok = true
		}
	}
	switch {
	case ok:
		return unknownVerdictApplied, nil
	case seen:
		return unknownVerdictNotApplied, nil
	}
	return "", nil
}

func (s *GovDeployments) markUnresolved(ctx context.Context, run *PolicyJobRun, d models.IGAGovDeployment, prev *unknownReading, this unknownReading) error {
	err := run.InTx(ctx, func(tx *gorm.DB) error {
		if err := setStateTx(tx, d, []string{models.GovDeployOutcomeUnknown}, map[string]any{"state": models.GovDeployOutcomeUnresolved,
			"state_reason": DepReasonOutcomeUnresolvable + ": readings " + prev.Resolution + " then " + this.Resolution +
				", CloudTrail " + orNone(this.Trail)}); err != nil {
			return err
		}
		return s.sysEvent(tx, d, GovEventDeploymentUnresolved, map[string]any{"readings": []unknownReading{*prev, this},
			"choices":     []string{"reread", "accept_observed", "emergency_undo"},
			"assigned_to": "the policy owner and every holder of governance:enforce"})
	})
	if errors.Is(err, errStateMoved) {
		return nil
	}
	return err
}

func orNone(s string) string {
	if s == "" {
		return "no event"
	}
	return s
}

// ObservationEnforcementTrail is the default GovEnforcementTrail: the
// CloudTrail events stored as cloud_observation evidence whose session name
// is the enforcement session's. DECISION (T3.16): events of the enforcement
// role are stored only when the scanner attributed them to an identity of
// the connector; when none is stored the check gives no evidence either way
// and the two consistent readings decide.
type ObservationEnforcementTrail struct{ DB *gorm.DB }

// EnforcementSessionEvents implements GovEnforcementTrail.
func (t ObservationEnforcementTrail) EnforcementSessionEvents(ctx context.Context, ws, connectorID uuid.UUID, sessionName string, from, to time.Time) ([]GovTrailEvent, error) {
	var rows []struct {
		ObservedAt     time.Time
		SanitizedFacts json.RawMessage
	}
	if err := t.DB.WithContext(ctx).Raw(`SELECT observed_at, sanitized_facts FROM cloud_observation
		WHERE workspace_id = ? AND connector_id = ? AND source_api = 'cloudtrail:LookupEvents'
		  AND sanitized_facts->>'session_name' = ? AND observed_at BETWEEN ? AND ?`, ws, connectorID, sessionName, from, to).
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]GovTrailEvent, 0, len(rows))
	for _, r := range rows {
		var f map[string]any
		_ = json.Unmarshal(r.SanitizedFacts, &f)
		name, _ := f["event_name"].(string)
		code, _ := f["error_code"].(string)
		out = append(out, GovTrailEvent{EventTime: r.ObservedAt, EventName: name, ErrorCode: code})
	}
	return out, nil
}
