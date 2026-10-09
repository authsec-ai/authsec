package services

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// The rollout's jobs (§8.1 job table, §8.6, §2.6; T3.15):
//
//   - observe_tick: enqueued by the evaluator for every rollout in observe,
//     canary or expand when a publication's evaluation completes (dedupe
//     rollout:<id>:rev:<rev>, EnqueueObserveTicksTx), and every 10 minutes
//     for rollouts in canary, expand or paused (dedupe rollout:<id>:periodic,
//     the observe_tick_periodic schedule: deployment states move without a
//     publication). observe reads the targets' activity evidence at the
//     tick's revision (EvaluateObservation); canary evaluates the gates
//     (EvaluateCanary over RolloutDeploymentFacts); expand settles; paused
//     notices an undone canary.
//   - refresh_activity: the scheduler enqueues it once per (connector,
//     observe_evidence_required_after) of every observing rollout, to run at
//     that time. It queues a scan of the connector through the existing scan
//     queue (cloud_scan_run queued, trigger refresh_activity) unless a scan
//     requested at or after that time already exists, then follows it: a
//     published one completes the job (its report arrives as ordinary
//     evidence of the next revision, whose observe_tick decides); a queued
//     or running one hands the job back for 10 minutes; DECISION R12: after
//     3 failed refresh scans the job is abandoned (observation then waits
//     for the next ordinary scan; elapsed time never ends it).

// Refresh limits.
const (
	RolloutRefreshRecheck  = 10 * time.Minute
	RolloutRefreshMaxScans = 3
	RolloutScanTrigger     = "refresh_activity"
)

// EnqueueObserveTicksTx is the evaluator's hook (§8.6 "on each
// publication"): one observe_tick per rollout of the workspace in observe,
// canary or expand, at rev, in the evaluation's transaction.
func EnqueueObserveTicksTx(tx *gorm.DB, ws uuid.UUID, rev int64) error {
	return tx.Exec(`INSERT INTO iga_gov_job (workspace_id, kind, subject_id, rev, dedupe_key)
		SELECT r.workspace_id, 'observe_tick', r.id, ?, 'rollout:' || r.id::text || ':rev:' || ?
		  FROM iga_gov_rollout r
		 WHERE r.workspace_id = ? AND r.stage IN ('observe','canary','expand')
		ON CONFLICT (workspace_id, kind, dedupe_key) WHERE status IN ('queued','running') DO NOTHING`, rev, fmt.Sprint(rev), ws).Error
}

// dueRolloutTicks is the observe_tick_periodic schedule's subjects.
func dueRolloutTicks(ctx context.Context, db *gorm.DB, now time.Time) ([]ScheduledPolicyJob, error) {
	var rows []struct {
		WorkspaceID uuid.UUID
		ID          uuid.UUID
	}
	if err := db.Raw(`SELECT workspace_id, id FROM iga_gov_rollout WHERE stage IN ('canary','expand','paused')`).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]ScheduledPolicyJob, 0, len(rows))
	for _, r := range rows {
		id := r.ID
		out = append(out, ScheduledPolicyJob{WorkspaceID: r.WorkspaceID, SubjectID: &id, DedupeKey: "rollout:" + id.String() + ":periodic"})
	}
	return out, nil
}

// RegisterRolloutJobs installs observe_tick and refresh_activity on w and
// the periodic observe_tick schedule on its scheduler.
func RegisterRolloutJobs(w *PolicyJobWorker, r *GovRollout) {
	w.Register(PolicyJobKind{Kind: repositories.GovJobObserveTick, Handler: r.ObserveTickHandler,
		Backoff: func(n int) time.Duration { return time.Duration(n) * time.Minute }})
	w.Register(PolicyJobKind{Kind: repositories.GovJobRefreshActivity, Handler: r.RefreshActivityHandler,
		Backoff: func(n int) time.Duration { return time.Duration(n) * 5 * time.Minute }})
	w.Scheduler().Add(PolicyJobSchedule{Name: "observe_tick_periodic", Kind: repositories.GovJobObserveTick,
		Every: RolloutPeriodicTick, Due: dueRolloutTicks})
}

/* ------------------------------ observe_tick ------------------------------ */

// ObserveTickHandler is the observe_tick job.
func (r *GovRollout) ObserveTickHandler(ctx context.Context, run *PolicyJobRun) error {
	job := run.Job
	if job.SubjectID == nil {
		return PolicyJobAbandon("observe_tick without a rollout")
	}
	ws := job.WorkspaceID
	db := run.DB().WithContext(ctx)
	var ros []models.IGAGovRollout
	if err := db.Where("workspace_id = ? AND id = ?", ws, *job.SubjectID).Limit(1).Find(&ros).Error; err != nil {
		return err
	}
	if len(ros) == 0 {
		return PolicyJobAbandon("the rollout no longer exists")
	}
	var v models.IGAGovPolicyVersion
	if err := db.Where("workspace_id = ? AND id = ?", ws, ros[0].VersionID).Take(&v).Error; err != nil {
		return err
	}
	rc, err := r.loadVersionCtx(db, ws, v, false)
	if err != nil {
		return err
	}
	var rev int64
	if job.Rev != nil {
		rev = *job.Rev
	}
	switch rc.Rollout.Stage {
	case models.GovRolloutObserve:
		if rev == 0 {
			return nil
		}
		return r.tickObserve(ctx, run, rc, rev)
	case models.GovRolloutCanary:
		return r.tickCanary(ctx, run, rc, rev)
	case models.GovRolloutExpand:
		return r.locked(ctx, run, rc, models.GovRolloutExpand, func(tx *gorm.DB, rc *govRolloutCtx) error {
			return r.settleTx(tx, ws, rc)
		})
	case models.GovRolloutPaused:
		return r.tickPaused(ctx, run, rc)
	}
	return nil
}

// locked re-reads the rollout under its lock inside the job's fenced
// transaction and runs fn only if it is still in stage.
func (r *GovRollout) locked(ctx context.Context, run *PolicyJobRun, rc0 *govRolloutCtx, stage string, fn func(tx *gorm.DB, rc *govRolloutCtx) error) error {
	return run.InTx(ctx, func(tx *gorm.DB) error {
		var v models.IGAGovPolicyVersion
		if err := tx.Where("workspace_id = ? AND id = ?", rc0.Version.WorkspaceID, rc0.Version.ID).Clauses(lockForUpdate()).Take(&v).Error; err != nil {
			return err
		}
		rc, err := r.loadVersionCtx(tx, v.WorkspaceID, v, true)
		if err != nil {
			return err
		}
		if rc.Rollout == nil || rc.Rollout.Stage != stage {
			return nil
		}
		return fn(tx, rc)
	})
}

// observationTargets reads, per target, the report the removal was proposed
// from (DECISION R4) and the newest report at rev with the removed
// services' last attempts.
func (r *GovRollout) observationTargets(db *gorm.DB, ws uuid.UUID, rc *govRolloutCtx, rev int64) ([]igagov.ObservationTarget, error) {
	out := []igagov.ObservationTarget{}
	for _, t := range rc.Targets {
		// This subject's removals (an owner's scoped retain keeps its
		// service for that owner's roles only).
		removed := map[string]bool{}
		for _, x := range rc.Intent.ForSubject(t.Control.IdentityAccountID.String()).Remove {
			removed[x.Service] = true
		}
		ot := igagov.ObservationTarget{RoleID: t.Control.RoleID, EvidenceReportAt: rc.Version.CreatedAt.UTC(),
			LastAttempts: map[string]*time.Time{}}
		var base []*time.Time
		if err := db.Raw(`SELECT max(report_generated_at) FROM iga_gov_activity_evidence
			WHERE workspace_id = ? AND rev = ? AND identity_account_id = ? AND state = ?`,
			ws, rc.Version.EvidenceRev, t.Control.IdentityAccountID, igagov.EvidenceCollected).Scan(&base).Error; err != nil {
			return nil, err
		}
		if len(base) == 1 && base[0] != nil {
			ot.EvidenceReportAt = base[0].UTC()
		}
		var rows []models.IGAGovActivityEvidence
		if err := db.Where("workspace_id = ? AND rev = ? AND identity_account_id = ?", ws, rev, t.Control.IdentityAccountID).
			Find(&rows).Error; err != nil {
			return nil, err
		}
		for _, e := range rows {
			if e.State != igagov.EvidenceCollected || e.ReportGeneratedAt == nil {
				continue
			}
			if ot.ReportGeneratedAt == nil || e.ReportGeneratedAt.After(*ot.ReportGeneratedAt) {
				g := e.ReportGeneratedAt.UTC()
				ot.ReportGeneratedAt = &g
			}
			if removed[e.Service] {
				ot.LastAttempts[e.Service] = e.LastAuthenticatedAt
			}
		}
		out = append(out, ot)
	}
	return out, nil
}

func (r *GovRollout) tickObserve(ctx context.Context, run *PolicyJobRun, rc *govRolloutCtx, rev int64) error {
	ws := rc.Version.WorkspaceID
	if rc.Version.Status != "in_review" && rc.Version.Status != "approved" {
		return nil
	}
	if g := rolloutResults(rc.Rollout); g.Observation != nil && g.Observation.Rev > rev {
		return nil // a newer revision was already read
	}
	if rc.Rollout.ObserveUntil == nil {
		return PolicyJobAbandon("the rollout has no observe_until")
	}
	targets, err := r.observationTargets(run.DB().WithContext(ctx), ws, rc, rev)
	if err != nil {
		return err
	}
	now := r.now().UTC()
	res := igagov.EvaluateObservation(*rc.Rollout.ObserveUntil, now, targets)
	return r.locked(ctx, run, rc, models.GovRolloutObserve, func(tx *gorm.DB, rc *govRolloutCtx) error {
		ro := rc.Rollout
		g := rolloutResults(ro)
		if g.Observation != nil && g.Observation.Rev > rev {
			return nil
		}
		g.Observation = &GovRolloutObservation{Rev: rev, EvaluatedAt: now, Result: res}
		switch {
		case len(res.BackToDraft) > 0:
			if err := r.saveTx(tx, ro, g); err != nil {
				return err
			}
			return r.backToDraftTx(tx, ws, rc, res.BackToDraft)
		case res.Complete:
			ro.Stage = models.GovRolloutAwaitingApproval
			if err := r.saveTx(tx, ro, g); err != nil {
				return err
			}
			return appendGovEvent(tx, ws, GovEventRolloutObservationCompleted, models.GovActorSystem, "rollout", rc.refs(nil),
				map[string]any{"rollout_id": ro.ID, "rev": rev, "required_after": res.RequiredAfter, "version_status": rc.Version.Status})
		default:
			if err := r.saveTx(tx, ro, g); err != nil {
				return err
			}
			return appendGovEvent(tx, ws, GovEventRolloutObservationChecked, models.GovActorSystem, "rollout", rc.refs(nil),
				map[string]any{"rollout_id": ro.ID, "rev": rev, "awaiting_report": res.AwaitingReport, "needs_refresh": res.NeedsRefresh,
					"observe_until": ro.ObserveUntil, "required_after": res.RequiredAfter})
		}
	})
}

// backToDraftTx is DECISION R2: the version goes back to draft (approval
// revoked, owner review cancelled) and the rollout pauses naming the attempt.
func (r *GovRollout) backToDraftTx(tx *gorm.DB, ws uuid.UUID, rc *govRolloutCtx, attempts []igagov.AttemptDuringObservation) error {
	var parts []string
	for _, a := range attempts {
		parts = append(parts, fmt.Sprintf("%s was attempted during observation on %s", a.Service, a.At.UTC().Format("2006-01-02")))
	}
	sort.Strings(parts)
	reason := strings.Join(parts, "; ")
	now := r.now().UTC()
	if err := tx.Exec(`UPDATE iga_gov_policy_version SET status = 'draft', status_changed_at = ?
		WHERE workspace_id = ? AND id = ? AND status IN ('in_review','approved')`, now, ws, rc.Version.ID).Error; err != nil {
		return err
	}
	if err := tx.Exec(`UPDATE iga_gov_approval SET revoked_at = ?, revoked_reason = ?
		WHERE workspace_id = ? AND version_id = ? AND decision = 'approve' AND revoked_at IS NULL`,
		now, "version back to draft: "+reason, ws, rc.Version.ID).Error; err != nil {
		return err
	}
	if err := r.reviews.CancelReviewTx(tx, ws, rc.Version.ID, uuid.Nil, "version back to draft: "+reason); err != nil {
		return err
	}
	if err := appendGovEvent(tx, ws, GovEventRolloutReturnedToDraft, models.GovActorSystem, "rollout", rc.refs(nil), map[string]any{
		"rollout_id": rc.Rollout.ID, "version_no": rc.Version.VersionNo, "previous_status": rc.Version.Status,
		"attempts": attempts, "reason": reason}); err != nil {
		return err
	}
	return r.pauseTx(tx, ws, uuid.Nil, rc, GovPauseReturnedToDraft, reason, nil)
}

func sameGateOutcomes(a *GovRolloutCanary, b GovRolloutCanary) bool {
	if a == nil || a.State != b.State || len(a.Gates) != len(b.Gates) || len(a.Accepted) != len(b.Accepted) {
		return false
	}
	for i := range a.Gates {
		if a.Gates[i].Gate != b.Gates[i].Gate || a.Gates[i].Outcome != b.Gates[i].Outcome || a.Gates[i].Reason != b.Gates[i].Reason {
			return false
		}
	}
	return true
}

func (r *GovRollout) tickCanary(ctx context.Context, run *PolicyJobRun, rc *govRolloutCtx, rev int64) error {
	ws := rc.Version.WorkspaceID
	g := rolloutResults(rc.Rollout)
	if g.Canary == nil {
		return nil
	}
	depID := g.Canary.DeploymentID
	ev, err := r.evaluateGates(ctx, run.DB().WithContext(ctx), ws, rc, depID, rev)
	if err != nil {
		var ge *GovError
		if errors.As(err, &ge) && ge.Status == http.StatusNotFound {
			return PolicyJobAbandon("the canary deployment no longer exists")
		}
		return err
	}
	preps := map[uuid.UUID]*govPrepared{}
	refused := map[uuid.UUID]GovRolloutRefusal{}
	advance := ev.facts.AppliedAt != nil && !ev.result.Pause && ev.passes(nil) && healthyState(ev.facts.State)
	if advance && len(rc.Targets) > 1 {
		ct, err := rc.canary()
		if err != nil {
			return err
		}
		for _, t := range rc.Targets {
			if t.Target.ID == ct.Target.ID {
				continue
			}
			p, err := r.prepare(ctx, ws, rc, t)
			if err != nil {
				rf, ok := refusalOf(t, err)
				if !ok {
					return err
				}
				refused[t.Target.ID] = rf
				continue
			}
			preps[t.Target.ID] = p
		}
	}
	return r.locked(ctx, run, rc, models.GovRolloutCanary, func(tx *gorm.DB, rc *govRolloutCtx) error {
		ro := rc.Rollout
		gg := rolloutResults(ro)
		changed := !sameGateOutcomes(gg.Canary, ev.canary)
		gg.Canary = &ev.canary
		if ev.facts.AppliedAt != nil {
			mu := ev.facts.AppliedAt.UTC().Add(time.Duration(ev.hours) * time.Hour)
			ro.CanaryMinUntil = &mu
		}
		var undo []uuid.UUID
		if ev.facts.AppliedAt != nil {
			undo = []uuid.UUID{depID}
		}
		switch {
		case ev.facts.State == models.GovDeployUndone:
			ro.Stage = models.GovRolloutUndone
			if err := r.saveTx(tx, ro, gg); err != nil {
				return err
			}
			return appendGovEvent(tx, ws, GovEventRolloutUndone, models.GovActorSystem, "rollout", rc.refs(&depID),
				map[string]any{"rollout_id": ro.ID, "deployment_id": depID})
		case ev.facts.State == models.GovDeployFailed:
			if err := r.saveTx(tx, ro, gg); err != nil {
				return err
			}
			return r.pauseTx(tx, ws, uuid.Nil, rc, GovPauseDeploymentFailed, "the canary deployment failed: "+ev.facts.StateReason, undo)
		case ev.facts.State == models.GovDeployDrifted:
			if err := r.saveTx(tx, ro, gg); err != nil {
				return err
			}
			return r.pauseTx(tx, ws, uuid.Nil, rc, GovPauseDrifted, "the canary drifted", undo)
		case ev.facts.AppliedAt != nil && ev.result.Pause:
			if err := r.saveTx(tx, ro, gg); err != nil {
				return err
			}
			var failed []string
			for _, gr := range ev.result.Gates {
				if gr.Outcome == igagov.OutcomeFailed {
					failed = append(failed, gr.Gate+" ("+gr.Reason+")")
				}
			}
			if err := appendGovEvent(tx, ws, GovEventRolloutGatesEvaluated, models.GovActorSystem, "rollout", rc.refs(&depID),
				map[string]any{"rollout_id": ro.ID, "rev": rev, "gates": ev.result.Gates, "unexpected_failures": ev.result.UnexpectedFailures,
					"application_health": ev.result.ApplicationHealth, "restriction": ev.result.Restriction}); err != nil {
				return err
			}
			return r.pauseTx(tx, ws, uuid.Nil, rc, GovPauseGateFailed, "canary gate failed: "+strings.Join(failed, ", "), undo)
		case advance:
			if err := appendGovEvent(tx, ws, GovEventRolloutGatesEvaluated, models.GovActorSystem, "rollout", rc.refs(&depID),
				map[string]any{"rollout_id": ro.ID, "rev": rev, "gates": ev.result.Gates, "accepted": ev.canary.Accepted, "pass": true}); err != nil {
				return err
			}
			_, _, err := r.advanceTx(tx, ws, uuid.Nil, rc, gg, preps, refused, "gates passed")
			return err
		default:
			if err := r.saveTx(tx, ro, gg); err != nil {
				return err
			}
			if !changed {
				return nil
			}
			return appendGovEvent(tx, ws, GovEventRolloutGatesEvaluated, models.GovActorSystem, "rollout", rc.refs(&depID),
				map[string]any{"rollout_id": ro.ID, "rev": rev, "state": ev.facts.State, "gates": ev.result.Gates,
					"not_available": ev.result.NotAvailable, "accepted": ev.canary.Accepted, "pass": false})
		}
	})
}

// healthyState: a canary that may advance (applied and not failed, drifted
// or undone).
func healthyState(s string) bool {
	switch s {
	case models.GovDeployAppliedUnverified, models.GovDeployVerified:
		return true
	}
	return false
}

// tickPaused marks the rollout undone once every applied deployment of the
// version has been undone (T3.16's undo after "Undo canary").
func (r *GovRollout) tickPaused(ctx context.Context, run *PolicyJobRun, rc *govRolloutCtx) error {
	ds, err := r.versionDeployments(run.DB().WithContext(ctx), rc.Version.WorkspaceID, rc.Version.ID)
	if err != nil {
		return err
	}
	undone, live := 0, 0
	for _, d := range ds {
		switch {
		case d.State == models.GovDeployUndone:
			undone++
		case d.AppliedAt != nil && d.State != models.GovDeployFailed && d.State != models.GovDeploySuperseded:
			live++
		}
	}
	if undone == 0 || live > 0 {
		return nil
	}
	return r.locked(ctx, run, rc, models.GovRolloutPaused, func(tx *gorm.DB, rc *govRolloutCtx) error {
		ro := rc.Rollout
		ro.Stage = models.GovRolloutUndone
		if err := r.saveTx(tx, ro, rolloutResults(ro)); err != nil {
			return err
		}
		return appendGovEvent(tx, rc.Version.WorkspaceID, GovEventRolloutUndone, models.GovActorSystem, "rollout", rc.refs(nil),
			map[string]any{"rollout_id": ro.ID, "undone_deployments": undone})
	})
}

/* ---------------------------- refresh_activity ---------------------------- */

// RefreshActivityHandler is the refresh_activity job (§2.6; DECISION R12).
// It decides on the EVIDENCE, not on scan times (Access Advisor may answer
// with a report generated before the scan asked): the job completes when no
// observing rollout on the connector waits for this time any more, or when
// every such rollout's targets have, in the latest complete evaluation, a
// report generated at or after it. Otherwise it waits for a scan in flight
// or for a published refresh scan's evaluation, and queues a refresh scan
// when there is none (at most RolloutRefreshMaxScans).
func (r *GovRollout) RefreshActivityHandler(ctx context.Context, run *PolicyJobRun) error {
	job := run.Job
	if job.SubjectID == nil {
		return PolicyJobAbandon("refresh_activity without a connector")
	}
	i := strings.LastIndex(job.DedupeKey, ":after:")
	if i < 0 {
		return PolicyJobAbandon("refresh_activity dedupe key names no time")
	}
	after, err := time.Parse(time.RFC3339, job.DedupeKey[i+len(":after:"):])
	if err != nil {
		return PolicyJobAbandon("refresh_activity dedupe key time: " + err.Error())
	}
	ws, conn := job.WorkspaceID, *job.SubjectID
	db := run.DB().WithContext(ctx)
	// The identities of the observing rollouts' targets on this connector
	// that need a report generated at or after `after`.
	var identities []uuid.UUID
	if err := db.Raw(`SELECT DISTINCT c.identity_account_id FROM iga_gov_rollout r
		JOIN iga_gov_target t ON t.workspace_id = r.workspace_id AND t.version_id = r.version_id
		JOIN iga_gov_control c ON c.workspace_id = t.workspace_id AND c.id = t.control_id
		WHERE r.workspace_id = ? AND r.stage = 'observe' AND c.connector_id = ?
		  AND date_trunc('second', r.observe_evidence_required_after) <= ?`, ws, conn, after).Scan(&identities).Error; err != nil {
		return err
	}
	if len(identities) == 0 {
		return nil // nothing observing on this connector needs it any more
	}
	var fresh []uuid.UUID
	if err := db.Raw(`SELECT DISTINCT e.identity_account_id FROM iga_gov_activity_evidence e
		WHERE e.workspace_id = ? AND e.identity_account_id IN ? AND e.state = 'collected' AND e.report_generated_at >= ?
		  AND e.rev = (SELECT max(rev) FROM iga_gov_evaluation WHERE workspace_id = ? AND status = 'complete')`,
		ws, identities, after, ws).Scan(&fresh).Error; err != nil {
		return err
	}
	stale := len(identities) - len(fresh)
	if stale <= 0 {
		return nil // every target has a fresh report: observe_tick decides
	}
	var runs []models.CloudScanRun
	if err := db.Where("workspace_id = ? AND connector_id = ? AND (status IN ('queued','running') OR (trigger = ? AND requested_at >= ?))",
		ws, conn, RolloutScanTrigger, after).Order("requested_at DESC").Find(&runs).Error; err != nil {
		return err
	}
	refreshes := 0
	for _, x := range runs {
		switch x.Status {
		case models.CloudScanRunQueued, models.CloudScanRunRunning:
			return PolicyJobRetryLater(RolloutRefreshRecheck, "a scan of the connector is in flight")
		case models.CloudScanRunPublished:
			var evaluated int64
			if err := db.Raw(`SELECT count(*) FROM iga_publication p JOIN iga_gov_evaluation e ON e.workspace_id = p.workspace_id AND e.rev = p.rev
				WHERE p.workspace_id = ? AND p.scan_run_id = ? AND e.status IN ('complete','failed','superseded')`, ws, x.ID).
				Scan(&evaluated).Error; err != nil {
				return err
			}
			if evaluated == 0 {
				return PolicyJobRetryLater(RolloutRefreshRecheck, "the refresh scan's publication is not evaluated yet")
			}
		}
		if x.Trigger == RolloutScanTrigger {
			refreshes++
		}
	}
	if refreshes >= RolloutRefreshMaxScans {
		return PolicyJobAbandon(fmt.Sprintf("%d refresh scans brought no report generated after %s; observation waits for the next scan",
			refreshes, after.Format(time.RFC3339)))
	}
	if r.now().Before(after) {
		return PolicyJobRetryLater(after.Sub(r.now()), "the required report time has not come")
	}
	err = run.InTx(ctx, func(tx *gorm.DB) error {
		qr, err := repositories.NewCloudScanRunRepository(tx).Enqueue(ws, conn, RolloutScanTrigger)
		if err != nil {
			return err
		}
		return appendGovEvent(tx, ws, GovEventRolloutRefreshQueued, models.GovActorSystem, "rollout", govEventRefs{}, map[string]any{
			"connector_id": conn, "scan_run_id": qr.ID, "required_after": after, "targets_waiting": stale})
	})
	if errors.Is(err, repositories.ErrScanAlreadyLive) {
		return PolicyJobRetryLater(RolloutRefreshRecheck, "a scan of the connector is in flight")
	}
	if err != nil {
		return err
	}
	return PolicyJobRetryLater(RolloutRefreshRecheck, "waiting for the refresh scan")
}

/* -------------------------------- notices --------------------------------- */

// notifyTx queues the canary_gate notice of a paused rollout: the policy
// owner and the version's author on every channel that reaches them, and
// the workspace webhook (resent on every pause).
func (r *GovRollout) notifyTx(tx *gorm.DB, ws uuid.UUID, rc *govRolloutCtx) error {
	if t, err := GovWorkspaceWebhookTarget(tx, ws); err != nil {
		return err
	} else if t != nil {
		if _, err := EnqueueGovNotificationTx(tx, ws, GovNoticeCanaryGate, rc.Rollout.ID, GovChannelWebhook,
			GovRecipientWorkspaceWebhook, true); err != nil {
			return err
		}
	}
	users := []uuid.UUID{rc.Version.CreatedBy}
	if rc.Policy.OwnerUserID != nil && *rc.Policy.OwnerUserID != rc.Version.CreatedBy {
		users = append(users, *rc.Policy.OwnerUserID)
	}
	email := govChannels(tx, ws).EmailEnabled
	for _, u := range users {
		if email {
			if _, err := EnqueueGovNotificationTx(tx, ws, GovNoticeCanaryGate, rc.Rollout.ID, GovChannelEmail, GovUserRecipient(u), true); err != nil {
				return err
			}
		}
		for _, ch := range govExtraChannels() {
			ok, err := ch.Reaches(tx, ws, u)
			if err != nil {
				return err
			}
			if ok {
				if _, err := EnqueueGovNotificationTx(tx, ws, GovNoticeCanaryGate, rc.Rollout.ID, ch.Channel(), GovUserRecipient(u), true); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func init() {
	RegisterGovNoticeSubject(GovNoticeCanaryGate, GovNoticeSubject{Render: renderRolloutNotice})
}

func renderRolloutNotice(db *gorm.DB, n *models.IGAGovNotification, user *uuid.UUID) (*GovNotice, error) {
	var ros []models.IGAGovRollout
	if err := db.Where("workspace_id = ? AND id = ?", n.WorkspaceID, n.SubjectID).Limit(1).Find(&ros).Error; err != nil {
		return nil, err
	}
	if len(ros) == 0 {
		return nil, GovNotifyPermanent(errors.New("the rollout no longer exists"))
	}
	ro := ros[0]
	var v models.IGAGovPolicyVersion
	if err := db.Where("workspace_id = ? AND id = ?", n.WorkspaceID, ro.VersionID).Take(&v).Error; err != nil {
		return nil, err
	}
	var p models.IGAGovPolicy
	if err := db.Where("workspace_id = ? AND id = ?", n.WorkspaceID, v.PolicyID).Take(&p).Error; err != nil {
		return nil, err
	}
	g := rolloutResults(&ro)
	reason := ro.PausedReason
	if g.Pause != nil {
		reason = g.Pause.Reason
	}
	link := govConsoleLink("/iga/policy/policies/" + p.ID.String())
	if user == nil {
		doc := map[string]any{"type": "iga.policy.rollout", "version": 1, "workspace_id": n.WorkspaceID.String(),
			"rollout_id": ro.ID.String(), "stage": ro.Stage, "policy_id": p.ID.String(), "policy_name": p.Name,
			"version_no": v.VersionNo, "reason": reason, "pause": g.Pause, "undo_offered": g.UndoOffered}
		if link != "" {
			doc["link"] = link
		}
		return &GovNotice{Webhook: doc, Title: "Rollout paused: " + p.Name, Link: link}, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "The rollout of policy %q (version %d) is %s.\n\n%s\n", p.Name, v.VersionNo, ro.Stage, reason)
	if len(g.UndoOffered) > 0 {
		fmt.Fprintf(&b, "\nUndo canary is offered for the applied change; open the policy to undo it or resume the rollout.\n")
	}
	if link != "" {
		fmt.Fprintf(&b, "\nOpen the policy:\n  %s\n", link)
	}
	fmt.Fprintf(&b, "\nRollout ID: %s\n\nRegards,\nAuthSec Team\n", ro.ID)
	lines := []string{reason}
	if len(g.UndoOffered) > 0 {
		lines = append(lines, "Undo canary is offered")
	}
	return &GovNotice{Subject: fmt.Sprintf("Rollout of %s %s", p.Name, ro.Stage), Text: b.String(),
		Title: "Rollout of " + p.Name + " " + ro.Stage, Lines: lines, Link: link}, nil
}
