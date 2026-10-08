package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// Finding evaluation inside the projection job (SPEC-iga-phase3-policy.md
// §2.5, §8.2, T3.06).
//
// After a publication commits and while the pipeline barrier is still held,
// the projection job evaluates the revision it published:
//
//	ev := iga_gov_evaluation(N)              inserted running in the publication tx
//	complete | superseded                 -> no-op (replay)
//	a newer revision's evaluation complete,
//	  or a newer publication exists        -> N superseded
//	failed                                -> fenced failed -> running, attempts + 1
//	snapshot under the barrier, igagov.Evaluate in memory, then ONE fenced
//	transaction in the shared lock order (§8.7):
//	  evidence rows; controls FOR UPDATE (account_id, role_id); posture route
//	  facts (account_id, role_id, service); findings (fingerprint) via
//	  igagov.PlanFindingUpdates; results; evaluation complete; enqueue
//	  evaluate_owner_rules(N); one iga_gov_event
//	40P01 / 40001: retried, at most 3 attempts, 50-500 ms jittered backoff
//	any error or the budget (60 s)        -> failed(reason), nothing else
//
// An evaluation failure NEVER fails the projection job: EvaluateRevision
// returns an outcome, never an error the job acts on.

// Evaluation outcomes, as EvaluateRevision reports them.
const (
	EvalOutcomeComplete   = "complete"
	EvalOutcomeNoop       = "noop"       // already complete or superseded
	EvalOutcomeSuperseded = "superseded" // a newer revision won
	EvalOutcomeFailed     = "failed"
	EvalOutcomeFenceLost  = "fence_lost" // the job or barrier is no longer ours: nothing written
	EvalOutcomeNoRow      = "no_row"     // nothing to evaluate (gate off when published)
)

// Evaluation defaults (§2.5, §8.2).
const (
	DefaultEvaluationBudget = 60 * time.Second
	evalTxMaxAttempts       = 3
)

// EvalFence proves, inside a transaction, that the caller still owns the
// projection job and holds the pipeline barrier. Every evaluation write is
// fenced on it.
type EvalFence func(tx *gorm.DB) error

// EvalHook is a test seam: called at named stages (after_snapshot,
// after_evaluate, results_half -- inside the write transaction, after half
// the results -- and done:<outcome> once the step has finished) with the
// transaction when there is one; an error it returns fails the evaluation
// exactly as a real error would (done's is ignored).
type EvalHook func(stage string, rev int64, tx *gorm.DB) error

// GovEvaluator runs the §8.2 evaluation step.
type GovEvaluator struct {
	db     *gorm.DB
	repo   repositories.IGAGovEvaluationRepository
	events repositories.IGAGovEventRepository
	budget time.Duration
	hook   EvalHook
	sleep  func(ctx context.Context, d time.Duration) error
}

// NewGovEvaluator builds the evaluator with the §8.2 defaults.
func NewGovEvaluator(db *gorm.DB) *GovEvaluator {
	return &GovEvaluator{
		db: db, repo: repositories.NewIGAGovEvaluationRepository(),
		events: repositories.NewIGAGovEventRepository(db),
		budget: DefaultEvaluationBudget,
		sleep: func(ctx context.Context, d time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(d):
				return nil
			}
		},
	}
}

// WithBudget sets the evaluation's time budget (tests).
func (e *GovEvaluator) WithBudget(d time.Duration) *GovEvaluator {
	if d > 0 {
		e.budget = d
	}
	return e
}

// WithHook installs a test hook.
func (e *GovEvaluator) WithHook(h EvalHook) *GovEvaluator { e.hook = h; return e }

func (e *GovEvaluator) stage(name string, rev int64, tx *gorm.DB) error {
	if e.hook == nil {
		return nil
	}
	return e.hook(name, rev, tx)
}

// InsertRunningTx inserts iga_gov_evaluation(rev, running, attempts 1) in
// the publication transaction (§8.2 step 1).
func (e *GovEvaluator) InsertRunningTx(tx *gorm.DB, ws uuid.UUID, rev int64) error {
	_, err := e.repo.InsertRunningTx(tx, ws, rev)
	return err
}

// EvaluateRevision is the step. It never returns an error the projection
// job should act on: the outcome is logged and reported.
func (e *GovEvaluator) EvaluateRevision(ctx context.Context, ws uuid.UUID, rev int64, fence EvalFence) string {
	outcome, err := e.evaluate(ctx, ws, rev, fence)
	if err != nil {
		log.Printf("[policy] evaluation of workspace %s rev %d: %s: %v", ws, rev, outcome, err)
	}
	_ = e.stage("done:"+outcome, rev, nil) // test seam: a crash after the step, before the release
	return outcome
}

func isFenceLoss(err error) bool {
	return errors.Is(err, repositories.ErrProjectionLeaseLost) || errors.Is(err, repositories.ErrPipelineLost)
}

func (e *GovEvaluator) evaluate(ctx context.Context, ws uuid.UUID, rev int64, fence EvalFence) (string, error) {
	// 1. Decide, in one fenced transaction: no-op, supersede, retry or go.
	var decision string
	err := e.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := fence(tx); err != nil {
			return err
		}
		ev, err := e.repo.GetTx(tx, ws, rev, true)
		if err != nil {
			return err
		}
		if ev == nil {
			// Published while the gate was off, or by a build without the
			// step: the row is inserted now (DECISION E2), so a revision
			// published before the gate turned on is still evaluated once.
			if _, err := e.repo.InsertRunningTx(tx, ws, rev); err != nil {
				return err
			}
			if ev, err = e.repo.GetTx(tx, ws, rev, true); err != nil || ev == nil {
				return fmt.Errorf("evaluation row for rev %d: %v", rev, err)
			}
		}
		switch ev.Status {
		case models.GovEvalComplete, models.GovEvalSuperseded:
			decision = EvalOutcomeNoop
			return nil
		}
		newer, err := e.repo.NewerCompleteTx(tx, ws, rev)
		if err != nil {
			return err
		}
		var latest int64
		if err := tx.Raw(`SELECT COALESCE(max(rev), 0) FROM iga_publication WHERE workspace_id = ?`, ws).Scan(&latest).Error; err != nil {
			return err
		}
		if newer || latest > rev {
			// A newer revision's evaluation won, or rev N's graph is no
			// longer the published one (DECISION E3): N cannot be read.
			if _, err := e.repo.SupersedeTx(tx, ws, rev); err != nil {
				return err
			}
			decision = EvalOutcomeSuperseded
			return e.appendEvent(tx, ws, "evaluation_superseded", map[string]any{"rev": rev, "latest_rev": latest})
		}
		if ev.Status == models.GovEvalFailed {
			ok, err := e.repo.RetryTx(tx, ws, rev)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("evaluation rev %d: failed -> running was refused", rev)
			}
		}
		decision = "go"
		return nil
	})
	if err != nil {
		if isFenceLoss(err) {
			return EvalOutcomeFenceLost, err
		}
		// The decision could not be made; record nothing we cannot fence.
		return e.fail(ws, rev, fence, fmt.Errorf("prepare: %w", err))
	}
	if decision != "go" {
		return decision, nil
	}

	// 2. Compute, inside the budget.
	bctx, cancel := context.WithTimeout(ctx, e.budget)
	defer cancel()
	out, gs, err := e.compute(bctx, ws, rev)
	if err == nil {
		err = e.write(bctx, ws, rev, fence, out, gs)
	}
	if err != nil {
		if isFenceLoss(err) {
			return EvalOutcomeFenceLost, err
		}
		if errors.Is(err, errEvalNotRunning) {
			return EvalOutcomeNoop, nil
		}
		if bctx.Err() != nil && errors.Is(bctx.Err(), context.DeadlineExceeded) {
			err = fmt.Errorf("evaluation exceeded its %s budget: %w", e.budget, err)
		}
		return e.fail(ws, rev, fence, err)
	}
	e.prune(ctx, ws)
	return EvalOutcomeComplete, nil
}

func (e *GovEvaluator) compute(ctx context.Context, ws uuid.UUID, rev int64) (igagov.Evaluation, *govSnapshot, error) {
	gs, err := loadGovSnapshot(ctx, e.db, ws, rev, nil)
	if err != nil {
		return igagov.Evaluation{}, nil, fmt.Errorf("snapshot: %w", err)
	}
	if err := e.stage("after_snapshot", rev, nil); err != nil {
		return igagov.Evaluation{}, nil, err
	}
	if err := ctx.Err(); err != nil {
		return igagov.Evaluation{}, nil, err
	}
	out, err := igagov.Evaluate(gs.Snap)
	if err != nil {
		return igagov.Evaluation{}, nil, fmt.Errorf("evaluate: %w", err)
	}
	if err := e.stage("after_evaluate", rev, nil); err != nil {
		return igagov.Evaluation{}, nil, err
	}
	return out, gs, ctx.Err()
}

// fail records failed(reason) in its own fenced transaction, on a fresh
// context: the budget's may already be spent. Nothing else is written.
func (e *GovEvaluator) fail(ws uuid.UUID, rev int64, fence EvalFence, cause error) (string, error) {
	reason := cause.Error()
	if len(reason) > 2000 {
		reason = reason[:2000]
	}
	fctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := e.db.WithContext(fctx).Transaction(func(tx *gorm.DB) error {
		if err := fence(tx); err != nil {
			return err
		}
		ok, err := e.repo.FailTx(tx, ws, rev, reason)
		if err != nil || !ok {
			return err
		}
		return e.appendEvent(tx, ws, "evaluation_failed", map[string]any{"rev": rev, "reason": reason})
	})
	if err != nil {
		if isFenceLoss(err) {
			return EvalOutcomeFenceLost, err
		}
		return EvalOutcomeFailed, fmt.Errorf("%v; recording the failure: %w", cause, err)
	}
	return EvalOutcomeFailed, cause
}

// write is §8.2's one transaction, retried on deadlock or serialization
// failure at most evalTxMaxAttempts times with jittered backoff inside the
// budget.
func (e *GovEvaluator) write(ctx context.Context, ws uuid.UUID, rev int64, fence EvalFence, out igagov.Evaluation, gs *govSnapshot) error {
	var err error
	for attempt := 1; attempt <= evalTxMaxAttempts; attempt++ {
		err = e.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			return e.writeTx(tx, ws, rev, fence, out, gs)
		})
		if err == nil {
			return nil
		}
		if st := sqlState(err); st != "40P01" && st != "40001" {
			return err
		}
		if attempt == evalTxMaxAttempts {
			break
		}
		backoff := 50*time.Millisecond + time.Duration(rand.Int63n(int64(450*time.Millisecond)))
		if serr := e.sleep(ctx, backoff); serr != nil {
			return fmt.Errorf("%v; retry cut short: %w", err, serr)
		}
	}
	return fmt.Errorf("after %d attempts: %w", evalTxMaxAttempts, err)
}

// errEvalNotRunning stops the write when the row left running (a concurrent
// replay finished first): nothing is written.
var errEvalNotRunning = errors.New("evaluation is no longer running")

func (e *GovEvaluator) writeTx(tx *gorm.DB, ws uuid.UUID, rev int64, fence EvalFence, out igagov.Evaluation, gs *govSnapshot) error {
	if err := fence(tx); err != nil {
		return err
	}
	ev, err := e.repo.GetTx(tx, ws, rev, true)
	if err != nil {
		return err
	}
	if ev == nil || ev.Status != models.GovEvalRunning {
		return errEvalNotRunning
	}

	// Evidence (new rows only; frozen once complete).
	evidence := make([]models.IGAGovActivityEvidence, 0, len(out.Evidence))
	for _, a := range out.Evidence {
		iid, err := uuid.Parse(a.IdentityAccountID)
		if err != nil {
			return fmt.Errorf("evidence identity %q: %w", a.IdentityAccountID, err)
		}
		evidence = append(evidence, models.IGAGovActivityEvidence{
			WorkspaceID: ws, Rev: rev, IdentityAccountID: iid, RoleID: a.RoleID, Service: a.Service,
			State: a.State, Reason: a.Reason, LastAuthenticatedAt: a.LastAuthenticatedAt,
			ReportGeneratedAt: a.ReportGeneratedAt, GrantObservedSince: a.GrantObservedSince,
			GrantAgeBasis: a.GrantAgeBasis, TrackingFrom: a.TrackingFrom, ScanRunID: uuidPtr(a.ScanRunID),
			RouteUsage: a.RouteUsage,
		})
	}
	if err := e.repo.InsertEvidenceTx(tx, evidence); err != nil {
		return fmt.Errorf("activity evidence: %w", err)
	}

	// §8.7 lock order 1: the workspace's live controls.
	var controls []uuid.UUID
	if err := tx.Raw(`SELECT id FROM iga_gov_control WHERE workspace_id = ? AND state <> 'removed'
	                   ORDER BY account_id, role_id FOR UPDATE`, ws).Scan(&controls).Error; err != nil {
		return fmt.Errorf("lock controls: %w", err)
	}

	// 3. Posture route facts only, never enforcement facts.
	posture, err := e.updatePostureRoutes(tx, ws, rev, gs)
	if err != nil {
		return err
	}

	// 4. Findings, in fingerprint order.
	locked, err := e.repo.LockFindingsTx(tx, ws)
	if err != nil {
		return fmt.Errorf("lock findings: %w", err)
	}
	byFP := make(map[string]models.IGAGovFinding, len(locked))
	stored := make([]igagov.StoredFinding, 0, len(locked))
	for _, f := range locked {
		byFP[f.Fingerprint] = f
		sf := igagov.StoredFinding{Fingerprint: f.Fingerprint, Kind: f.Kind, DetailKey: f.DetailKey,
			Status: f.Status, LastEvaluatedRev: f.LastEvaluatedRev, ExceptedUntil: f.ExceptedUntil}
		if f.RoleID != nil {
			sf.RoleID = *f.RoleID
		}
		stored = append(stored, sf)
	}
	plan := igagov.PlanFindingUpdates(out, stored, posture)
	at := out.EvaluatedAt
	var results []models.IGAGovFindingResult
	counts := map[string]int{}
	for _, u := range plan {
		var id uuid.UUID
		if u.Insert {
			f := u.Finding
			row := &models.IGAGovFinding{
				WorkspaceID: ws, Fingerprint: f.Fingerprint, Kind: f.Kind, Family: f.Family, Severity: f.Severity,
				Confidence: f.Confidence, IdentityAccountID: uuidPtr(f.IdentityAccountID), WorkloadID: uuidPtr(f.WorkloadID),
				ConnectorID: uuidPtr(f.ConnectorID), DetailKey: f.DetailKey, Detail: json.RawMessage(f.Detail),
				Status: u.Status, FirstSeenRev: u.FirstSeenRev, LastEvaluatedRev: u.LastEvaluatedRev,
				FirstSeenAt: at, LastEvaluatedAt: at, StatusChangedAt: at,
			}
			if f.RoleID != "" {
				rid := f.RoleID
				row.RoleID = &rid
			}
			if err := e.repo.InsertFindingTx(tx, row); err != nil {
				return fmt.Errorf("insert finding %s: %w", f.Fingerprint, err)
			}
			id = row.ID
			counts["inserted"]++
		} else {
			cur, ok := byFP[u.Fingerprint]
			if !ok {
				return fmt.Errorf("planned update of unknown finding %s", u.Fingerprint)
			}
			id = cur.ID
			upd := repositories.FindingEvalUpdate{Rev: rev, Status: u.Status, StatusChanged: u.StatusChanged,
				ClearException: u.ClearException, At: at}
			if u.Finding != nil {
				upd.Condition = &repositories.FindingCondition{Severity: u.Finding.Severity,
					Confidence: u.Finding.Confidence, Detail: u.Finding.Detail}
			}
			if err := e.repo.UpdateFindingTx(tx, ws, id, upd); err != nil {
				return fmt.Errorf("update finding %s: %w", u.Fingerprint, err)
			}
			if u.StatusChanged {
				counts["to_"+u.Status]++
			}
		}
		if u.HasResult && u.Finding != nil {
			results = append(results, models.IGAGovFindingResult{WorkspaceID: ws, Rev: rev, FindingID: id,
				Severity: u.Finding.Severity, Confidence: u.Finding.Confidence, Detail: json.RawMessage(u.Finding.Detail),
				EvidenceScanRunID: uuidPtr(u.Finding.EvidenceScanRunID)})
		}
	}
	// Results, in two halves with a test seam between them: a failure after
	// half the results are written must leave none (A32).
	half := len(results) / 2
	if err := e.repo.InsertResultsTx(tx, results[:half]); err != nil {
		return fmt.Errorf("finding results: %w", err)
	}
	if err := e.stage("results_half", rev, tx); err != nil {
		return err
	}
	if err := e.repo.InsertResultsTx(tx, results[half:]); err != nil {
		return fmt.Errorf("finding results: %w", err)
	}

	// Complete, the owner-rules job, and one event.
	if ok, err := e.repo.CompleteTx(tx, ws, rev); err != nil || !ok {
		if err == nil {
			err = errEvalNotRunning
		}
		return err
	}
	if err := tx.Exec(`INSERT INTO iga_gov_job (workspace_id, kind, rev, dedupe_key)
	                   VALUES (?, 'evaluate_owner_rules', ?, ?)
	                   ON CONFLICT (workspace_id, kind, dedupe_key) WHERE status IN ('queued','running') DO NOTHING`,
		ws, rev, fmt.Sprintf("rev:%d", rev)).Error; err != nil {
		return fmt.Errorf("enqueue evaluate_owner_rules: %w", err)
	}
	// The publication hook (p3-wire, item 4; §2.8 "Revalidation, not silent
	// recompilation", §8.3, A59): every version still in review is
	// recompiled against this revision (compile_plans: new current plans; an
	// impact change reopens its owner review) and every approved version's
	// approved plans are revalidated (an unchanged rescan records an
	// `unchanged` revalidation and touches nothing else).
	//
	// DECISION W4: enqueued HERE, in the evaluation's own transaction right
	// after it is marked complete -- not after the commit -- so a completed
	// evaluation and its compile jobs are one fact: a crash between the two
	// can neither leave a complete evaluation whose versions were never
	// rechecked nor queue a recompile against a revision whose findings were
	// rolled back. The job runs later, outside the barrier, on the worker
	// (live reads are never made under the pipeline barrier). One open job
	// per version (dedupe version:<id>): a version already queued keeps its
	// job, which will read the newest evidence when it runs. "AWS
	// publication": every Phase 3 control is an AWS role and any revision can
	// change a role's evidence (a new consumer arrives through another
	// connector's scan), so every completed evaluation triggers it; a version
	// with no target has nothing to compile and is skipped.
	var versions []uuid.UUID
	if err := tx.Raw(`SELECT v.id FROM iga_gov_policy_version v
	                   WHERE v.workspace_id = ? AND v.status IN ('in_review','approved')
	                     AND EXISTS (SELECT 1 FROM iga_gov_target t WHERE t.workspace_id = v.workspace_id AND t.version_id = v.id)
	                   ORDER BY v.id`, ws).Scan(&versions).Error; err != nil {
		return fmt.Errorf("open versions: %w", err)
	}
	for _, vid := range versions {
		r := rev
		created, err := EnqueueCompilePlansTx(tx, ws, vid, &r)
		if err != nil {
			return fmt.Errorf("enqueue compile_plans %s: %w", vid, err)
		}
		if created {
			counts["compile_plans"]++
		}
	}
	counts["results"] = len(results)
	counts["evidence"] = len(evidence)
	return e.appendEvent(tx, ws, "evaluation_completed", map[string]any{"rev": rev, "counts": counts,
		"skipped_roles": len(out.Skipped), "unknown_conditions": len(out.Unknown)})
}

// updatePostureRoutes writes the route facts of every posture row of the
// workspace from the role connector's run in rev N's manifest, under the
// §8.7 order (account_id, role_id, service), and returns every row's
// outcome as PostgreSQL now derives it -- from these route facts and the
// enforcement facts already committed (§8.7 "Delayed evaluation").
func (e *GovEvaluator) updatePostureRoutes(tx *gorm.DB, ws uuid.UUID, rev int64, gs *govSnapshot) (map[igagov.PostureKey]string, error) {
	var rows []struct {
		AccountID   string
		RoleID      string
		Service     string
		EvidenceRev int64
	}
	if err := tx.Raw(`SELECT account_id, role_id, service, evidence_rev FROM iga_gov_service_posture
	                   WHERE workspace_id = ? ORDER BY account_id, role_id, service FOR UPDATE`, ws).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("lock posture: %w", err)
	}
	roles := map[string]igagov.RoleSnapshot{}
	for _, r := range gs.Snap.Roles {
		roles[r.RoleID] = r
	}
	out := map[igagov.PostureKey]string{}
	for _, p := range rows {
		r, present := roles[p.RoleID]
		if present && p.EvidenceRev <= rev {
			runID := gs.Snap.Manifest[r.PartitionKey]
			var ev *igagov.ResourcePolicyEvidence
			var regions []string
			if run, ok := gs.Snap.Runs[runID]; ok && r.PartitionKey != "" {
				ev, regions = run.ResourcePolicy, run.EnabledRegions
			} else {
				runID = ""
			}
			ra := igagov.AnalyzeRoutes(p.Service, igagov.RoleRef{RoleID: r.RoleID, ARN: r.ARN, Name: r.Name,
				AccountID: r.AccountID, Partition: r.Partition}, ev, regions)
			routes, err := json.Marshal(ra.RemainingRoutes())
			if err != nil {
				return nil, err
			}
			var scan *uuid.UUID
			if ev != nil {
				scan = uuidPtr(runID)
			}
			if ra.State != igagov.RouteStateNotAnalysed && scan == nil {
				// 051 iga_gov_sp_evidence_chk: a route conclusion names its scan.
				return nil, fmt.Errorf("posture %s/%s: route state %s without a scan", p.RoleID, p.Service, ra.State)
			}
			if err := tx.Exec(`UPDATE iga_gov_service_posture
			                      SET route_state = ?, routes = ?::jsonb, evidence_rev = ?, evidence_scan_run_id = ?, assessed_at = now()
			                    WHERE workspace_id = ? AND account_id = ? AND role_id = ? AND service = ? AND evidence_rev <= ?`,
				ra.State, string(routes), rev, scan, ws, p.AccountID, p.RoleID, p.Service, rev).Error; err != nil {
				return nil, fmt.Errorf("posture %s/%s route facts: %w", p.RoleID, p.Service, err)
			}
		}
	}
	var outcomes []struct {
		RoleID  string
		Service string
		Outcome string
	}
	if err := tx.Raw(`SELECT role_id, service, outcome FROM iga_gov_service_posture WHERE workspace_id = ?`, ws).
		Scan(&outcomes).Error; err != nil {
		return nil, fmt.Errorf("posture outcomes: %w", err)
	}
	for _, o := range outcomes {
		out[igagov.PostureKey{RoleID: o.RoleID, Service: o.Service}] = o.Outcome
	}
	return out, nil
}

func (e *GovEvaluator) appendEvent(tx *gorm.DB, ws uuid.UUID, event string, payload map[string]any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return e.events.AppendTx(tx, &models.IGAGovEvent{WorkspaceID: ws, Event: event,
		ActorKind: models.GovActorSystem, ActorID: "evaluator", Payload: raw})
}

// prune drops the evidence and results of complete evaluations outside the
// retention (§2.5): best effort, outside the evaluation's transaction.
func (e *GovEvaluator) prune(ctx context.Context, ws uuid.UUID) {
	settings, err := repositories.NewIGAGovSettingsRepository(e.db.WithContext(ctx)).Get(ws)
	if err != nil {
		log.Printf("[policy] prune %s: settings: %v", ws, err)
		return
	}
	if err := e.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		_, err := e.repo.PruneTx(tx, ws, settings.EvidenceRetentionRevs)
		return err
	}); err != nil {
		log.Printf("[policy] prune %s: %v", ws, err)
	}
}

func uuidPtr(s string) *uuid.UUID {
	if s == "" {
		return nil
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return nil
	}
	return &id
}
