package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsenforce"
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
	if d.Delivery != igagov.DeliveryDirect {
		return nil
	}
	switch d.State {
	case models.GovDeployVerified:
	case models.GovDeployQueued, models.GovDeployApplying, models.GovDeployOutcomeUnknown, models.GovDeployOutcomeUnresolved:
		return nil // in flight: the deploy / resolve_unknown job owns the live state
	default:
		// Review P1-7, §8.1 step 5: for 24 h after an unknown attempt the
		// CONTROL is watched whatever this deployment's state (the scheduler
		// picks the control's latest applied deployment, or the attempt's
		// own when none applied).
		watched, err := lateWatchActive(db, ws, d.ControlID, s.now())
		if err != nil || !watched {
			return err
		}
	}
	plan, err := loadGovPlan(run.DB(), ws, d.PlanID)
	if err != nil {
		return err
	}
	ctl, err := s.loadControl(db, ws, d.ControlID)
	if err != nil {
		return err
	}
	if d.State != models.GovDeployVerified {
		return s.lateWatch(ctx, run, *d, plan, *ctl)
	}
	return s.recordDrift(ctx, run, *d, plan, *ctl, "", igagov.LiveRead{})
}

// lateWatchActive reports whether the control had an unknown attempt
// dispatched within LateMutationWatch of now.
func lateWatchActive(db *gorm.DB, ws, control uuid.UUID, now time.Time) (bool, error) {
	var n int64
	err := db.Raw(`SELECT count(*) FROM iga_gov_attempt a JOIN iga_gov_deployment d ON d.workspace_id = a.workspace_id AND d.id = a.deployment_id
		WHERE a.workspace_id = ? AND d.control_id = ? AND a.status = 'unknown' AND a.dispatched_at > ?`, ws, control, now.Add(-LateMutationWatch)).Scan(&n).Error
	return n > 0, err
}

// lateWatch is §8.1 step 5 for a deployment that is not verified (applied
// but unverified, drifted, undone, superseded, failed, blocked, recovered):
// a live read of the role; a change matching an unknown request by
// operation and target is reported once per (deployment, attempt) as
// drift.late_mutation_suspected. DECISION (P1-7): only a verified
// deployment moves to drifted (recordDrift); for any other state the
// report is the event (with the deployment's state), never a state change,
// a re-apply or a revert.
func (s *GovDeployments) lateWatch(ctx context.Context, run *PolicyJobRun, d models.IGAGovDeployment, plan igagov.Plan, ctl models.IGAGovControl) error {
	live, _, err := s.readPlan(ctx, run, d, plan, ctl)
	if err != nil {
		return err
	}
	var anchor *igagov.Plan
	if d.AppliedAt != nil {
		anchor = &plan
	}
	late, err := s.lateMutation(ctx, run, d.WorkspaceID, ctl, live, anchor)
	if err != nil || late == nil {
		return err
	}
	var seen int64
	if err := run.DB().WithContext(ctx).Raw(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND deployment_id = ? AND event = ?
		AND payload->>'attempt_id' = ?`, d.WorkspaceID, d.ID, GovEventDriftLateMutation, late.Attempt.ID.String()).Scan(&seen).Error; err != nil {
		return err
	}
	if seen > 0 {
		return nil
	}
	return run.InTx(ctx, func(tx *gorm.DB) error {
		return s.event(tx, d, GovEventDriftLateMutation, late.payload(d.State))
	})
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
		var late *lateMatch
		if late, err = s.lateMutation(ctx, run, ws, ctl, live, &p); err != nil {
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
			if err := s.event(tx, *cur, GovEventDeploymentDrifted, payload); err != nil {
				return err
			}
			if reason == DriftLateMutation {
				pl := late.payload(models.GovDeployVerified)
				pl["underlying"] = sub
				if err := s.event(tx, *cur, GovEventDriftLateMutation, pl); err != nil {
					return err
				}
			}
			if reason == DriftTargetGone {
				return s.event(tx, *cur, GovEventControlRoleGone, map[string]any{"control_id": d.ControlID, "reason": "role_gone"})
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

// lateMatch is an unknown attempt whose effect a live read shows.
type lateMatch struct {
	Attempt models.IGAGovAttempt
	Target  string
	Effect  string
}

func (m *lateMatch) payload(state string) map[string]any {
	return map[string]any{"attempt_id": m.Attempt.ID.String(), "attempt_deployment_id": m.Attempt.DeploymentID,
		"operation": m.Attempt.Operation, "target": m.Target, "effect": m.Effect, "deployment_state": state,
		"note": "A change matching an earlier unknown request appeared; nothing was re-applied or reverted."}
}

// lateMutation is §8.1 step 5, matched by OPERATION AND TARGET (review
// P1-7), not only by document hash: an unknown attempt on the control in
// the last LateMutationWatch (resolved not_applied, or never resolved) whose
// effect the live read shows -- PutRolePermissionsBoundary: the role's
// boundary is that ARN; DeleteRolePermissionsBoundary: the role has none;
// CreatePolicy / CreatePolicyVersion: that policy's default document is the
// request's; DeletePolicy: that policy is gone -- and that the anchor's
// post-state (the deployment whose state is "the latest verified state";
// nil: none applied) does not explain. An attempt resolved `applied` is not
// late: its effect is the record. Ops a read cannot see (TagPolicy,
// DeletePolicyVersion) change no boundary fact and are not watched by read.
func (s *GovDeployments) lateMutation(ctx context.Context, run *PolicyJobRun, ws uuid.UUID, ctl models.IGAGovControl, live igagov.LiveRead, anchor *igagov.Plan) (*lateMatch, error) {
	db := run.DB().WithContext(ctx)
	var atts []models.IGAGovAttempt
	if err := db.Raw(`SELECT a.* FROM iga_gov_attempt a JOIN iga_gov_deployment d ON d.workspace_id = a.workspace_id AND d.id = a.deployment_id
		WHERE a.workspace_id = ? AND d.control_id = ? AND a.status = 'unknown' AND a.dispatched_at > ?
		  AND (a.resolved_as IS NULL OR a.resolved_as = 'not_applied')
		ORDER BY a.dispatched_at DESC`, ws, ctl.ID, s.now().Add(-LateMutationWatch)).Scan(&atts).Error; err != nil {
		return nil, err
	}
	plans := map[uuid.UUID]igagov.Plan{}
	for _, a := range atts {
		var dep models.IGAGovDeployment
		if err := db.Where("workspace_id = ? AND id = ?", ws, a.DeploymentID).Take(&dep).Error; err != nil {
			return nil, err
		}
		p, ok := plans[dep.PlanID]
		if !ok {
			var err error
			if p, err = LoadIGAGovPlan(db, ws, dep.PlanID); err != nil {
				return nil, err
			}
			plans[dep.PlanID] = p
		}
		if a.OpSeq >= len(p.Ops) {
			continue
		}
		req, err := awsenforce.NewRequest(p.Ops[a.OpSeq], dep.ID, "")
		if err != nil {
			continue // a version selector: not visible to a read
		}
		if anchor == nil && laterAttemptDone(db, a) {
			continue // no applied state to compare with; a retry made this effect
		}
		m, err := s.lateEffect(ctx, run, ctl, live, req, anchor)
		if err != nil {
			return nil, err
		}
		if m != nil {
			m.Attempt = a
			return m, nil
		}
	}
	return nil, nil
}

// laterAttemptDone reports whether a later attempt of the same op of the
// same deployment completed with the op done.
func laterAttemptDone(db *gorm.DB, a models.IGAGovAttempt) bool {
	var n int64
	db.Raw(`SELECT count(*) FROM iga_gov_attempt WHERE workspace_id = ? AND deployment_id = ? AND op_seq = ? AND attempt_no > ?
		AND status = 'completed' AND outcome IN ('ok','recognised_done','not_needed')`, a.WorkspaceID, a.DeploymentID, a.OpSeq, a.AttemptNo).Scan(&n)
	return n > 0
}

// lateEffect: does live show req's effect, unexplained by the anchor?
func (s *GovDeployments) lateEffect(ctx context.Context, run *PolicyJobRun, ctl models.IGAGovControl, live igagov.LiveRead, req awsenforce.Request, anchor *igagov.Plan) (*lateMatch, error) {
	desiredARN, desiredDoc, replaced, present := "", "", "", false
	deletes := false
	if anchor != nil {
		present = anchor.DesiredAttachment == igagov.AttachmentPresent
		if anchor.DesiredBoundaryARN != nil {
			desiredARN = *anchor.DesiredBoundaryARN
		}
		if anchor.DesiredDocumentHash != nil {
			desiredDoc = *anchor.DesiredDocumentHash
		}
		if anchor.ReplacedBoundaryARN != nil {
			replaced = *anchor.ReplacedBoundaryARN
		}
		deletes = anchor.ArtifactDisposition == igagov.DispositionDelete
	}
	policy := func(arn string) (*igagov.LivePolicy, bool, error) {
		if lp, ok := live.Policies[arn]; ok {
			return lp, true, nil
		}
		env := s.envNow()
		if env.AWS == nil {
			return nil, false, nil
		}
		var lp *igagov.LivePolicy
		err := run.External(ctx, 0, func(ctx context.Context) error {
			disc, err := env.AWS.DiscoveryIAM(ctx, ctl.WorkspaceID, ctl.ConnectorID)
			if err != nil {
				return err
			}
			lp, _, err = awsenforce.ReadPolicy(ctx, disc, arn)
			return err
		})
		if err != nil {
			return nil, false, err
		}
		live.Policies[arn] = lp
		return lp, true, nil
	}
	docOf := func(lp *igagov.LivePolicy) string {
		if lp == nil {
			return ""
		}
		h, err := lp.DocumentHash()
		if err != nil {
			return ""
		}
		return h
	}
	role := live.Role
	switch req.Op {
	case igagov.OpPutRolePermissionsBoundary:
		if role != nil && role.BoundaryARN == req.PolicyARN && !(present && desiredARN == req.PolicyARN) {
			return &lateMatch{Target: req.RoleName, Effect: "boundary " + req.PolicyARN + " attached"}, nil
		}
	case igagov.OpDeleteRolePermissionsBoundary:
		if role != nil && role.BoundaryARN == "" && (anchor == nil || present) {
			return &lateMatch{Target: req.RoleName, Effect: "boundary removed"}, nil
		}
	case igagov.OpCreatePolicy, igagov.OpCreatePolicyVersion:
		arn := req.PolicyARN
		if req.Op == igagov.OpCreatePolicy {
			arn = arnPartitionPrefix(ctl.RoleARN) + ":iam::" + ctl.AccountID + ":policy" + req.Path + req.PolicyName
		}
		lp, read, err := policy(arn)
		if err != nil {
			return nil, err
		}
		if read && lp != nil && docOf(lp) == req.DocumentHash && !(present && desiredARN == arn && desiredDoc == req.DocumentHash) {
			return &lateMatch{Target: arn, Effect: "default document " + req.DocumentHash}, nil
		}
	case igagov.OpDeletePolicy:
		lp, read, err := policy(req.PolicyARN)
		if err != nil {
			return nil, err
		}
		if read && lp == nil && anchor != nil && !(deletes && replaced == req.PolicyARN && desiredARN != req.PolicyARN) &&
			!(!present && deletes && replaced == req.PolicyARN) {
			return &lateMatch{Target: req.PolicyARN, Effect: "policy deleted"}, nil
		}
	}
	return nil, nil
}

// arnPartitionPrefix is "arn:<partition>" of an ARN ("arn:aws" by default).
func arnPartitionPrefix(arn string) string {
	if p := strings.SplitN(arn, ":", 3); len(p) == 3 && p[0] == "arn" && p[1] != "" {
		return "arn:" + p[1]
	}
	return "arn:aws"
}

/* ----------------------------- resolve_unknown ------------------------------ */

type unknownReading struct {
	AttemptID   string    `json:"attempt_id"`
	Resolution  string    `json:"resolution"`
	ReadAt      time.Time `json:"read_at"`
	Trail       string    `json:"trail"`
	TrailDetail string    `json:"trail_detail,omitempty"`
}

// trailUnreadable is the CloudTrail verdict when the enforcement session's
// events could not be read (no reader, an API error, an incomplete lookup).
const trailUnreadable = "unknown"

// ResolveUnknownHandler is §8.1 step 2: after settle_after, two readings at
// least 5 minutes apart (each recorded as an event), consistent with each
// other and with the enforcement session's CloudTrail events, resolve the
// attempt (applied / not_applied) and return the deployment to applying
// (the deploy job resumes or recognises the op). Anything else makes the
// deployment outcome_unresolved, which still holds the role.
//
// Review P1-7: the CloudTrail verdict comes from cloudtrail:LookupEvents of
// the enforcement session for the op and its target (trailVerdict):
// applied (a matching event AWS applied), not_applied (only refused
// matching events), "" (no matching event) or unknown (the trail could not
// be read). The decision:
//
//	readings disagree, or a conflict                 -> outcome_unresolved
//	op a read cannot see (TagPolicy, a version
//	delete; igagov ResolvedUnobservable)             -> CloudTrail ONLY:
//	                                                    applied / not_applied,
//	                                                    else outcome_unresolved
//	                                                    (never not_applied by
//	                                                    default)
//	trail unknown                                    -> applied readings
//	                                                    resolve applied (the
//	                                                    live state shows the
//	                                                    effect); not_applied
//	                                                    readings are
//	                                                    outcome_unresolved
//	trail applied / not_applied disagreeing          -> outcome_unresolved
//	otherwise                                        -> the readings' verdict
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
			// No unresolved unknown attempt holds this outcome_unknown
			// deployment (review P1-5): returning would leave it in flight
			// forever. The deploy job takes it back and re-reads live state.
			err := run.InTx(ctx, func(tx *gorm.DB) error {
				if err := s.rereadWithoutAttemptTx(tx, *d); err != nil {
					return err
				}
				return s.event(tx, *d, GovEventDeploymentRequeued, map[string]any{"kind": "deploy", "state": models.GovDeployApplying,
					"reason": "outcome_unknown with no unresolved unknown attempt; the deploy job re-reads live state"})
			})
			if errors.Is(err, errStateMoved) {
				return nil
			}
			return err
		}
		return PolicyJobRetryLater(time.Minute, "unknown-outcome read failed: "+err.Error())
	}
	ctl, err := s.loadControl(db, ws, d.ControlID)
	if err != nil {
		return err
	}
	verdict, trailDetail, err := s.trailVerdict(ctx, run.DB(), *d, *ctl, rd.Attempt, plan)
	if err != nil {
		return err
	}
	this := unknownReading{AttemptID: rd.Attempt.ID.String(), Resolution: rd.Resolution.Resolution, ReadAt: now.UTC(), Trail: verdict,
		TrailDetail: trailDetail}
	prev, err := s.lastReading(db, *d, rd.Attempt.ID)
	if err != nil {
		return err
	}
	if err := run.InTx(ctx, func(tx *gorm.DB) error {
		return s.event(tx, *d, GovEventUnknownReading, map[string]any{"attempt_id": this.AttemptID, "resolution": this.Resolution,
			"read_at": this.ReadAt, "trail": this.Trail, "trail_detail": this.TrailDetail, "classification": rd.Resolution.Classification})
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
		if verdict == unknownVerdictApplied || verdict == unknownVerdictNotApplied {
			res = verdict
		}
	case verdict == trailUnreadable:
		if this.Resolution == unknownVerdictApplied {
			res = unknownVerdictApplied
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

// trailVerdict looks up the enforcement session's CloudTrail events of the
// attempt's operation (review P1-7): events of the session
// authsec-enforce-<deployment 16hex>, named as the op, in the attempt's
// window (from its signing, less a minute of clock skew, but never before an
// earlier attempt of the same op answered -- that one's events are not this
// one's), on the op's TARGET and with this attempt's request hash (a version
// delete matches its version id). A matching event AWS applied -> applied;
// only refused ones -> not_applied; none -> "" (no evidence); a lookup that
// fails -> unknown with the reason.
func (s *GovDeployments) trailVerdict(ctx context.Context, db *gorm.DB, d models.IGAGovDeployment, ctl models.IGAGovControl, att models.IGAGovAttempt, plan igagov.Plan) (string, string, error) {
	tr := s.envNow().Trail
	if tr == nil {
		return trailUnreadable, "no CloudTrail reader is configured", nil
	}
	if att.OpSeq < 0 || att.OpSeq >= len(plan.Ops) || att.SignedAt == nil {
		return trailUnreadable, "the attempt names no op of the plan", nil
	}
	op := plan.Ops[att.OpSeq]
	from := att.SignedAt.Add(-time.Minute)
	var prev []time.Time
	if err := db.WithContext(ctx).Raw(`SELECT completed_at FROM iga_gov_attempt WHERE workspace_id = ? AND deployment_id = ? AND op_seq = ?
		AND attempt_no < ? AND status = 'completed' ORDER BY completed_at DESC LIMIT 1`,
		d.WorkspaceID, d.ID, att.OpSeq, att.AttemptNo).Scan(&prev).Error; err != nil {
		return "", "", err
	}
	if len(prev) == 1 && prev[0].After(from) {
		from = prev[0]
	}
	evs, err := tr.EnforcementSessionEvents(ctx, d.WorkspaceID, ctl.ConnectorID, GovTrailQuery{
		SessionName: awsenforce.DeploymentSessionName(d.ID), EventName: att.Operation, From: from, To: s.now()})
	if err != nil {
		return trailUnreadable, truncate(err.Error(), 500), nil
	}
	applied, refused := false, false
	for _, ev := range evs {
		version := ""
		if op.Op == igagov.OpDeletePolicyVersion {
			if version = ev.VersionID; version == "" {
				continue
			}
		}
		req, err := awsenforce.NewRequest(op, d.ID, version)
		if err != nil {
			continue
		}
		if h, err := req.Hash(); err != nil || h != att.RequestHash || !req.MatchesTrail(ev) {
			continue
		}
		if ev.Applied() {
			applied = true
		} else {
			refused = true
		}
	}
	switch {
	case applied:
		return unknownVerdictApplied, "", nil
	case refused:
		return unknownVerdictNotApplied, "", nil
	}
	return "", fmt.Sprintf("%d %s event(s) of the session, none for this request", len(evs), att.Operation), nil
}

func (s *GovDeployments) markUnresolved(ctx context.Context, run *PolicyJobRun, d models.IGAGovDeployment, prev *unknownReading, this unknownReading) error {
	err := run.InTx(ctx, func(tx *gorm.DB) error {
		if err := setStateTx(tx, d, []string{models.GovDeployOutcomeUnknown}, map[string]any{"state": models.GovDeployOutcomeUnresolved,
			"state_reason": DepReasonOutcomeUnresolvable + ": readings " + prev.Resolution + " then " + this.Resolution +
				", CloudTrail " + orNone(this.Trail) + trailNote(this.TrailDetail)}); err != nil {
			return err
		}
		return s.event(tx, d, GovEventDeploymentUnresolved, map[string]any{"readings": []unknownReading{*prev, this},
			"choices":     []string{"reread", "accept_observed", "emergency_undo"},
			"assigned_to": "the policy owner and every holder of governance:enforce"})
	})
	if errors.Is(err, errStateMoved) {
		return nil
	}
	return err
}

func orNone(s string) string {
	switch s {
	case "":
		return "no event"
	case trailUnreadable:
		return "unreadable"
	}
	return s
}

func trailNote(detail string) string {
	if detail == "" {
		return ""
	}
	return " (" + detail + ")"
}
