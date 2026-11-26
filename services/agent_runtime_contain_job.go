package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentcontain"
	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/models"
)

// The agent_contain job (policy job worker, §8.1 fencing): one job per
// containment (dedupe agent_containment:<id>), which
//
//	previewed   -> binding gate (template v2; EnableWorkloadContainment for
//	               the workload level and IAM users) -> containing, or failed
//	containing  -> records each step with its exact before-state, THEN
//	               applies it and reads it back -> contained |
//	               partially_contained | failed
//	contained / partially_contained
//	            -> behavioural verdict after the grace (verified_at), and a
//	               read-back of every applied step every 15 minutes (drift is
//	               reported, never re-applied: R2-18)
//	releasing   -> restores every step, newest first, to its recorded
//	               before-state (the session revocation at its time, P3-3)
//	               -> released
//	released    -> the deferred restore when pending_restore_at is due.
//
// Every write is fenced on the job (run.InTx) and on the containment's state,
// so a release that lands while the job applies steps is picked up by the
// next run, which restores whatever was applied -- including a step whose
// write had no answer (pending: restores are idempotent set-to-value).

const (
	containCheckEvery = 15 * time.Minute
	containRetry      = time.Minute
)

type containJob struct {
	s   *AgentContain
	run *PolicyJobRun
	ws  uuid.UUID
	row *AgentContainment
	// forceCleanup: restoreDue removes the AuthSec policy of every policy
	// step that never took effect (the failed-outcome path), whatever its
	// step state, and ignores a deferred restore time.
	forceCleanup bool
}

// Handler is the agent_contain job. A release requested while the job runs
// cannot move the running job's run_after (Release only pulls forward a
// queued job), so a long wait the run ends with is cut to a second when the
// containment has meanwhile moved to releasing.
func (s *AgentContain) Handler(ctx context.Context, run *PolicyJobRun) error {
	var started string
	err := s.handle(ctx, run, &started)
	var rl *policyJobRetryLater
	if errors.As(err, &rl) && rl.after > 5*time.Second && started != "" && started != agentcontain.StateReleasing && run.Job.SubjectID != nil {
		var state string
		ws := run.Job.WorkspaceID
		if rerr := run.ReadTx(ctx, func(tx *gorm.DB) error {
			row, err := loadContainment(tx, ws, *run.Job.SubjectID, false)
			if err == nil {
				state = row.State
			}
			return err
		}); rerr == nil && state == agentcontain.StateReleasing {
			return PolicyJobRetryLater(time.Second, "release requested; running it now")
		}
	}
	return err
}

func (s *AgentContain) handle(ctx context.Context, run *PolicyJobRun, started *string) error {
	if run.Job.SubjectID == nil {
		return PolicyJobAbandon("agent_contain needs a containment subject")
	}
	// TENANT-EXEMPT: the 151 schema check reads the Postgres catalog only.
	if ok, why := AgentContainStatus(s.db); !ok {
		return PolicyJobRetryLater(10*time.Minute, why)
	}
	ws := run.Job.WorkspaceID
	var row *AgentContainment
	err := run.ReadTx(ctx, func(tx *gorm.DB) error {
		var err error
		row, err = loadContainment(tx, ws, *run.Job.SubjectID, false)
		return err
	})
	if err != nil {
		var ge *GovError
		if errors.As(err, &ge) {
			return PolicyJobAbandon("containment not found")
		}
		return err
	}
	*started = row.State
	j := &containJob{s: s, run: run, ws: ws, row: row}
	switch row.State {
	case agentcontain.StatePreviewed:
		return j.start(ctx)
	case agentcontain.StateContaining:
		return j.apply(ctx)
	case agentcontain.StateContained, agentcontain.StatePartial:
		return j.check(ctx)
	case agentcontain.StateReleasing:
		return j.release(ctx)
	case agentcontain.StateReleased:
		return j.deferred(ctx)
	}
	return nil
}

func (j *containJob) now() time.Time { return j.s.now().UTC() }

// event appends a system event of the containment (the vocabulary scan
// reads its third argument, as for appendGovEvent).
func (j *containJob) event(tx *gorm.DB, ws uuid.UUID, name string, payload map[string]any) error {
	if payload == nil {
		payload = map[string]any{}
	}
	payload["containment_id"] = j.row.ID
	return appendGovEvent(tx, ws, name, models.GovActorSystem, "policy-worker", govEventRefs{}, payload)
}

// moveTx changes the state from `from`, fenced on it (0 rows: someone moved
// it -- a release -- and the next run reloads).
func (j *containJob) moveTx(tx *gorm.DB, from, to string, set map[string]any) error {
	if set == nil {
		set = map[string]any{}
	}
	set["state"], set["updated_at"] = to, j.now()
	res := tx.Model(&AgentContainment{}).Where("workspace_id = ? AND id = ? AND state = ?", j.ws, j.row.ID, from).Updates(set)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected != 1 {
		return errStateMoved
	}
	return nil
}

func (j *containJob) settled(err error) error {
	if errors.Is(err, errStateMoved) {
		return PolicyJobRetryLater(time.Second, "the containment's state moved; reloading")
	}
	return err
}

// note records why the job is waiting, on the containment.
func (j *containJob) note(ctx context.Context, reason string) {
	_ = j.run.InTx(ctx, func(tx *gorm.DB) error {
		return tx.Model(&AgentContainment{}).Where("workspace_id = ? AND id = ?", j.ws, j.row.ID).
			Updates(map[string]any{"state_reason": truncateReason(reason), "updated_at": j.now()}).Error
	})
}

func truncateReason(s string) string {
	if len(s) > 1000 {
		return s[:1000] + "..."
	}
	return s
}

func (j *containJob) preview() agentcontain.Preview {
	var p agentcontain.Preview
	_ = json.Unmarshal(j.row.Preview, &p)
	return p
}

// engineRun is the engine's view of the containment.
func (j *containJob) engineRun() agentcontain.Run {
	p := j.preview()
	sub := p.Subject
	sub.Kind, sub.ARN, sub.UniqueID = j.row.IdentityKind, j.row.IdentityARN, j.row.UniqueID
	if sub.Name == "" {
		sub.Name = agentcontain.IdentityNameOf(j.row.IdentityARN)
	}
	if sub.AccountID == "" || sub.Partition == "" {
		part, _, _, acct, _, _ := agentcontain.ARNParts(j.row.IdentityARN)
		sub.AccountID, sub.Partition = acct, part
	}
	return agentcontain.Run{ContainmentID: j.row.ID, WorkspaceRef: GovWorkspaceRef(j.ws), Level: j.row.Level, Subject: sub,
		Cutoff: j.row.CreatedAt.UTC().Truncate(time.Second), Now: j.s.now}
}

// features are the enforcement v2 features the containment needs.
func (j *containJob) features() []string {
	switch {
	case j.row.Level == agentcontain.LevelWorkload:
		return []string{awsenforce.FeatureWorkloadContainment}
	case j.row.IdentityKind == agentcontain.IdentityUser:
		return []string{EnforcementFeatureGrants, awsenforce.FeatureWorkloadContainment}
	}
	return []string{EnforcementFeatureGrants}
}

/* ---------------------------------- start ---------------------------------- */

func (j *containJob) start(ctx context.Context) error {
	for _, f := range j.features() {
		if err := r2BindingGate(ctx, j.run, j.ws, j.row.ConnectorID, f); err != nil {
			if isLeaseErr(err) {
				return err
			}
			code, msg := errCode(err)
			return j.fail(ctx, agentcontain.StatePreviewed, code, msg)
		}
	}
	err := j.run.InTx(ctx, func(tx *gorm.DB) error {
		if err := j.moveTx(tx, agentcontain.StatePreviewed, agentcontain.StateContaining, map[string]any{"state_reason": ""}); err != nil {
			return err
		}
		return j.event(tx, j.ws, GovEventContainmentStarted, map[string]any{"level": j.row.Level, "identity_arn": j.row.IdentityARN})
	})
	if err != nil {
		return j.settled(err)
	}
	j.row.State = agentcontain.StateContaining
	return j.apply(ctx)
}

func (j *containJob) fail(ctx context.Context, from, code, detail string) error {
	err := j.run.InTx(ctx, func(tx *gorm.DB) error {
		if err := j.moveTx(tx, from, agentcontain.StateFailed, map[string]any{"state_reason": truncateReason(code + ": " + detail)}); err != nil {
			return err
		}
		return j.event(tx, j.ws, GovEventContainmentFailed, map[string]any{"from": from, "reason": code, "detail": detail})
	})
	return j.settled(err)
}

/* ---------------------------------- apply ---------------------------------- */

// open is the engine for this run: the enforcement session (one per run,
// never cached) and the discovery reads.
func (j *containJob) open(ctx context.Context) (*agentcontain.Engine, error) {
	acc := agentContainAccess()
	if acc == nil {
		return nil, PolicyJobRetryLater(5*time.Minute, errContainNotConfigured.Message)
	}
	var aws agentcontain.AWS
	err := j.run.External(ctx, 0, func(ctx context.Context) error {
		var err error
		aws, err = acc.Open(ctx, j.ws, j.row.ConnectorID, j.row.ID)
		return err
	})
	if err != nil {
		if isLeaseErr(err) {
			return nil, err
		}
		_, msg := errCode(err)
		j.note(ctx, "enforcement session: "+msg)
		return nil, PolicyJobRetryLater(2*time.Minute, "enforcement session: "+msg)
	}
	return &agentcontain.Engine{AWS: aws, Run: j.engineRun()}, nil
}

func (j *containJob) steps(ctx context.Context) ([]AgentContainmentStep, error) {
	var out []AgentContainmentStep
	err := j.run.ReadTx(ctx, func(tx *gorm.DB) error {
		var err error
		out, err = loadSteps(tx, j.ws, j.row.ID)
		return err
	})
	return out, err
}

// planned lists the containment's steps in order (the access keys of a user
// are read live).
func (j *containJob) planned(ctx context.Context, eng *agentcontain.Engine) ([]agentcontain.Step, error) {
	if j.row.Level == agentcontain.LevelWorkload {
		p := j.preview()
		return agentcontain.WorkloadSteps(p.Level(agentcontain.LevelWorkload)), nil
	}
	out := eng.Run.IAMSteps()
	if j.row.Level == agentcontain.LevelIdentity && j.row.IdentityKind == agentcontain.IdentityUser {
		var keys []agentcontain.Step
		err := j.run.External(ctx, 0, func(ctx context.Context) error {
			var err error
			keys, err = agentcontain.AccessKeySteps(ctx, eng.AWS, eng.Run.Subject.Name)
			return err
		})
		if err != nil {
			return nil, err
		}
		out = append(out, keys...)
	}
	return out, nil
}

func jsonOrEmpty(b json.RawMessage) json.RawMessage {
	if len(b) == 0 {
		return json.RawMessage(`{}`)
	}
	return b
}

func (j *containJob) apply(ctx context.Context) error {
	eng, err := j.open(ctx)
	if err != nil {
		return err
	}
	have, err := j.steps(ctx)
	if err != nil {
		return err
	}
	// The role must still be the incarnation the containment was requested
	// for (a role recreated under the same name is another identity).
	if rr, ok := eng.AWS.(containRoleReader); ok && len(have) == 0 && j.row.IdentityKind == agentcontain.IdentityRole && j.row.UniqueID != "" {
		var live string
		err := j.run.External(ctx, 0, func(ctx context.Context) error {
			var err error
			live, err = rr.RoleID(ctx, agentcontain.IdentityNameOf(j.row.IdentityARN))
			return err
		})
		switch {
		case err != nil && isLeaseErr(err):
			return err
		case err != nil:
			j.note(ctx, "reading the role: "+err.Error())
			return PolicyJobRetryLater(containRetry, err.Error())
		case live != j.row.UniqueID:
			return j.fail(ctx, agentcontain.StateContaining, R2ReasonRoleGone, "the role is gone or was recreated (RoleId "+live+")")
		}
	}
	plan, err := j.planned(ctx, eng)
	if err != nil {
		if isLeaseErr(err) {
			return err
		}
		j.note(ctx, "reading the user's access keys: "+err.Error())
		return PolicyJobRetryLater(containRetry, err.Error())
	}
	// Write-ahead: every planned step is recorded with its exact before-state
	// before any of it is applied. A recorded step's before is never re-read.
	known := map[string]bool{}
	seq := 0
	for _, h := range have {
		known[h.Kind+"\x1f"+h.Target] = true
		if h.Seq >= seq {
			seq = h.Seq + 1
		}
	}
	for _, ps := range plan {
		st := ps
		if known[st.Kind+"\x1f"+st.Target] {
			continue
		}
		state := agentcontain.StepPending
		if len(st.Before) == 0 {
			var skip bool
			err := j.run.External(ctx, 0, func(ctx context.Context) error {
				var err error
				skip, err = eng.Before(ctx, &st)
				return err
			})
			var se *agentcontain.StepError
			switch {
			case err != nil && isLeaseErr(err):
				return err
			case errors.As(err, &se):
				state, st.Error = agentcontain.StepFailed, se.Error()
			case err != nil:
				j.note(ctx, "reading the before-state of "+st.Target+": "+err.Error())
				return PolicyJobRetryLater(containRetry, err.Error())
			case skip:
				state = agentcontain.StepSkipped
			}
		}
		row := AgentContainmentStep{ID: uuid.New(), WorkspaceID: j.ws, ContainmentID: j.row.ID, Seq: seq, Kind: st.Kind, Target: st.Target,
			Region: st.Region, Before: jsonOrEmpty(st.Before), After: json.RawMessage(`{}`), State: state, Error: st.Error,
			RestoreAfter: st.RestoreAfter, CreatedAt: j.now(), UpdatedAt: j.now()}
		seq++
		insert := func(r AgentContainmentStep) error {
			return j.run.InTx(ctx, func(tx *gorm.DB) error {
				if err := tx.Create(&r).Error; err != nil {
					return err
				}
				if r.State == agentcontain.StepFailed {
					return j.event(tx, j.ws, GovEventContainmentStepFailed, map[string]any{"kind": r.Kind, "target": r.Target, "error": r.Error})
				}
				return nil
			})
		}
		if err := insert(row); err != nil {
			if !isUniqueViolation(err, "uq_agent_containment_step_live_target") {
				return err
			}
			// Another live containment holds this target: its before-state is
			// that containment's change, not the workload's own. Refuse the
			// step (nothing was written to AWS) and name the holder.
			holder := j.liveHolder(ctx, st.Kind, st.Target)
			row.ID, row.State = uuid.New(), agentcontain.StepFailed
			row.Before, row.Error = json.RawMessage(`{}`), "target already held by containment "+holder
			if err := insert(row); err != nil {
				return err
			}
		}
	}
	steps, err := j.steps(ctx)
	if err != nil {
		return err
	}
	for i := range steps {
		if steps[i].State != agentcontain.StepPending {
			continue
		}
		// A release may have landed meanwhile: stop applying.
		var cur *AgentContainment
		if err := j.run.ReadTx(ctx, func(tx *gorm.DB) error {
			var err error
			cur, err = loadContainment(tx, j.ws, j.row.ID, false)
			return err
		}); err != nil {
			return err
		}
		if cur.State != agentcontain.StateContaining {
			return PolicyJobRetryLater(time.Second, "the containment's state moved; reloading")
		}
		st := steps[i].engineStep()
		err := j.run.External(ctx, 0, func(ctx context.Context) error { return eng.Apply(ctx, &st) })
		var se *agentcontain.StepError
		switch {
		case err != nil && isLeaseErr(err):
			return err
		case errors.As(err, &se):
			if err := j.stepUpdate(ctx, steps[i].ID, map[string]any{"state": agentcontain.StepFailed, "error": truncateReason(se.Error())},
				func(tx *gorm.DB) error {
					return j.event(tx, j.ws, GovEventContainmentStepFailed, map[string]any{"kind": st.Kind, "target": st.Target, "error": se.Error()})
				}); err != nil {
				return err
			}
		case err != nil:
			_ = j.stepUpdate(ctx, steps[i].ID, map[string]any{"error": truncateReason(err.Error())}, nil)
			j.note(ctx, "applying "+st.Kind+" "+st.Target+": "+err.Error())
			return PolicyJobRetryLater(containRetry, err.Error())
		default:
			now := j.now()
			if err := j.stepUpdate(ctx, steps[i].ID, map[string]any{"state": agentcontain.StepApplied, "after": string(jsonOrEmpty(st.After)),
				"error": "", "applied_at": now}, func(tx *gorm.DB) error {
				return j.event(tx, j.ws, GovEventContainmentStepApplied, map[string]any{"kind": st.Kind, "target": st.Target,
					"before": json.RawMessage(jsonOrEmpty(st.Before)), "after": json.RawMessage(jsonOrEmpty(st.After))})
			}); err != nil {
				return err
			}
		}
	}
	steps, err = j.steps(ctx)
	if err != nil {
		return err
	}
	es := make([]agentcontain.Step, 0, len(steps))
	for _, s := range steps {
		es = append(es, s.engineStep())
	}
	outcome := agentcontain.Outcome(es)
	if outcome == agentcontain.StateContaining {
		return PolicyJobRetryLater(containRetry, "steps still pending")
	}
	if outcome == agentcontain.StateFailed {
		// Nothing was applied, but a failed policy step may have created the
		// AuthSec policy. A failed containment cannot be released, so it is
		// not left failed until every such policy is gone: a refused or
		// transient cleanup retries (the steps keep restore_failed, which
		// still counts as holding the policy).
		holds := false
		for _, s := range steps {
			holds = holds || agentcontain.HoldsPolicy(s.engineStep())
		}
		if holds {
			eng, err := j.open(ctx)
			if err != nil {
				return err
			}
			j.forceCleanup = true
			_, err = j.restoreDue(ctx, eng, steps, j.now())
			j.forceCleanup = false
			if err != nil {
				return err
			}
			if steps, err = j.steps(ctx); err != nil {
				return err
			}
			for _, s := range steps {
				if agentcontain.HoldsPolicy(s.engineStep()) {
					j.note(ctx, "removing the AuthSec policy of a failed containment: "+s.Error)
					return PolicyJobRetryLater(5*time.Minute, "the AuthSec policy "+s.Target+" could not be removed yet")
				}
			}
		}
	}
	now := j.now()
	err = j.run.InTx(ctx, func(tx *gorm.DB) error {
		set := map[string]any{"state_reason": ""}
		name := GovEventContainmentFailed
		switch outcome {
		case agentcontain.StateContained:
			set["contained_at"], name = now, GovEventContainmentContained
		case agentcontain.StatePartial:
			set["contained_at"], name = now, GovEventContainmentPartial
		default:
			set["state_reason"] = "no change could be applied"
		}
		if err := j.moveTx(tx, agentcontain.StateContaining, outcome, set); err != nil {
			return err
		}
		return j.event(tx, j.ws, name, map[string]any{"level": j.row.Level, "steps": stepSummary(steps)})
	})
	if err != nil {
		return j.settled(err)
	}
	if outcome == agentcontain.StateFailed {
		return nil
	}
	return PolicyJobRetryLater(agentcontain.VerifyGrace+30*time.Second, "verifying after the grace period")
}

// liveHolder names the other live containment holding (kind, target), for the
// refusal text; "another containment" when it cannot be read.
func (j *containJob) liveHolder(ctx context.Context, kind, target string) string {
	holder := "another containment"
	_ = j.run.ReadTx(ctx, func(tx *gorm.DB) error {
		var rows []AgentContainmentStep
		if err := tx.Where("workspace_id = ? AND kind = ? AND target = ? AND containment_id <> ? AND state IN ?", j.ws, kind, target, j.row.ID,
			[]string{agentcontain.StepPending, agentcontain.StepApplied, agentcontain.StepRestoring, agentcontain.StepRestoreFailed}).
			Limit(1).Find(&rows).Error; err == nil && len(rows) > 0 {
			holder = rows[0].ContainmentID.String()
		}
		return nil
	})
	return holder
}

func stepSummary(steps []AgentContainmentStep) []map[string]any {
	out := make([]map[string]any, 0, len(steps))
	for _, s := range steps {
		out = append(out, map[string]any{"kind": s.Kind, "target": s.Target, "state": s.State, "error": s.Error})
	}
	return out
}

// stepUpdate updates one step (fenced) and runs then (its event) in the same
// transaction when set.
func (j *containJob) stepUpdate(ctx context.Context, stepID uuid.UUID, set map[string]any, then func(tx *gorm.DB) error) error {
	set["updated_at"] = j.now()
	if a, ok := set["after"].(string); ok {
		set["after"] = gorm.Expr("?::jsonb", a)
	}
	return j.run.InTx(ctx, func(tx *gorm.DB) error {
		if err := tx.Model(&AgentContainmentStep{}).Where("workspace_id = ? AND containment_id = ? AND id = ?", j.ws, j.row.ID, stepID).
			Updates(set).Error; err != nil {
			return err
		}
		if then == nil {
			return nil
		}
		return then(tx)
	})
}

/* ---------------------------------- check ---------------------------------- */

// check is the contained containment's periodic run: the behavioural verdict
// once the grace has passed, and the read-back of every applied step.
func (j *containJob) check(ctx context.Context) error {
	now := j.now()
	if err := j.verdict(ctx, now); err != nil {
		return err
	}
	steps, err := j.steps(ctx)
	if err != nil {
		return err
	}
	applied := false
	for _, s := range steps {
		if s.State == agentcontain.StepApplied {
			applied = true
		}
	}
	if !applied {
		return PolicyJobRetryLater(containCheckEvery, "contained; nothing to read back")
	}
	eng, err := j.open(ctx)
	if err != nil {
		var rl *policyJobRetryLater
		if errors.As(err, &rl) {
			return PolicyJobRetryLater(containCheckEvery, rl.reason)
		}
		return err
	}
	var drift []map[string]any
	for _, s := range steps {
		if s.State != agentcontain.StepApplied {
			continue
		}
		st := s.engineStep()
		var in bool
		var detail string
		err := j.run.External(ctx, 0, func(ctx context.Context) error {
			var err error
			in, detail, err = eng.Readback(ctx, &st)
			return err
		})
		if err != nil {
			if isLeaseErr(err) {
				return err
			}
			return PolicyJobRetryLater(containCheckEvery, "read-back failed: "+err.Error())
		}
		if !in {
			drift = append(drift, map[string]any{"kind": s.Kind, "target": s.Target, "read": detail})
		}
	}
	prev := map[string]json.RawMessage{}
	_ = json.Unmarshal(j.row.Verification, &prev)
	raw, _ := json.Marshal(map[string]any{"drift": drift, "read_back_at": now})
	if drift == nil {
		raw, _ = json.Marshal(map[string]any{"drift": []any{}, "read_back_at": now})
	}
	err = j.run.InTx(ctx, func(tx *gorm.DB) error {
		if err := tx.Model(&AgentContainment{}).Where("workspace_id = ? AND id = ?", j.ws, j.row.ID).
			Updates(map[string]any{"verification": gorm.Expr("verification || ?::jsonb", string(raw)), "updated_at": now}).Error; err != nil {
			return err
		}
		if len(drift) > 0 && string(prev["drift"]) != containJSON(drift) {
			return j.event(tx, j.ws, GovEventContainmentDrifted, map[string]any{"drift": drift,
				"note": "AuthSec does not re-apply a change undone outside AuthSec; release and contain again."})
		}
		return nil
	})
	if err != nil {
		return err
	}
	return PolicyJobRetryLater(containCheckEvery, "contained; read back every 15 minutes")
}

// verdict decides the behavioural verification once the grace has passed:
// verified only on CloudTrail evidence that events after contained_at +
// VerifyGrace were received for the connector (never on the timer alone);
// unverifiable when no event can be attributed to the contained workloads
// (final), or when no evidence arrived within VerifyGiveUp. The second kind
// is re-checked on every run: a weekly scan's cursor or a stream event that
// later passes the cutoff turns it into verified (the note is removed). The
// event sink can still flip a verified containment to not effective.
func (j *containJob) verdict(ctx context.Context, now time.Time) error {
	if j.row.VerifiedAt != nil || j.row.Effective != nil || j.row.ContainedAt == nil {
		return nil
	}
	c := containedOf(*j.row)
	if !now.After(c.CutOff()) {
		return nil
	}
	var prev struct {
		Unverifiable *struct {
			Final bool `json:"final"`
		} `json:"unverifiable"`
	}
	_ = json.Unmarshal(j.row.Verification, &prev)
	noted := prev.Unverifiable != nil
	if noted && prev.Unverifiable.Final {
		return nil
	}
	if bad, why := c.Unverifiable(); bad {
		return j.markUnverifiable(ctx, now, why, true)
	}
	var covered bool
	var how string
	if err := j.run.ReadTx(ctx, func(tx *gorm.DB) error {
		var err error
		covered, how, err = containEvidenceCovers(tx, j.ws, j.row.ConnectorID, c.CutOff())
		return err
	}); err != nil {
		return err
	}
	if !covered {
		if noted || now.Before(c.ContainedAt.Add(agentcontain.VerifyGiveUp)) {
			return nil // keep waiting for CloudTrail evidence
		}
		return j.markUnverifiable(ctx, now, "No CloudTrail events were received for this account after the containment (neither the event stream nor every region's CloudTrail read reached it), so no call by the identity could have been seen. It is checked again whenever new events arrive.", false)
	}
	return j.run.InTx(ctx, func(tx *gorm.DB) error {
		raw, _ := json.Marshal(map[string]any{"evidence": how})
		res := tx.Model(&AgentContainment{}).Where("workspace_id = ? AND id = ? AND state IN ? AND effective IS NULL", j.ws, j.row.ID,
			[]string{agentcontain.StateContained, agentcontain.StatePartial}).
			Updates(map[string]any{"verified_at": now, "effective": true, "updated_at": now,
				"verification": gorm.Expr("(verification - 'unverifiable') || ?::jsonb", string(raw))})
		if res.Error != nil || res.RowsAffected == 0 {
			return res.Error
		}
		return j.event(tx, j.ws, GovEventContainmentVerified, map[string]any{"grace_seconds": int(agentcontain.VerifyGrace.Seconds()),
			"evidence": how,
			"note":     "CloudTrail events newer than the grace period were received and none was a successful call by the identity; a later-delivered event can still mark it not effective."})
	})
}

func (j *containJob) markUnverifiable(ctx context.Context, now time.Time, why string, final bool) error {
	return j.run.InTx(ctx, func(tx *gorm.DB) error {
		raw, _ := json.Marshal(map[string]any{"unverifiable": map[string]any{"reason": why, "at": now, "final": final}})
		res := tx.Model(&AgentContainment{}).Where("workspace_id = ? AND id = ? AND state IN ? AND effective IS NULL", j.ws, j.row.ID,
			[]string{agentcontain.StateContained, agentcontain.StatePartial}).
			Updates(map[string]any{"updated_at": now, "verification": gorm.Expr("verification || ?::jsonb", string(raw))})
		if res.Error != nil || res.RowsAffected == 0 {
			return res.Error
		}
		return j.event(tx, j.ws, GovEventContainmentUnverifiable, map[string]any{"reason": why, "final": final})
	})
}

// containEvidenceCovers reports whether CloudTrail events from after cut were
// received for the connector: the event stream's newest event time
// (agent_event_stream.last_event_time, migration 149) is past cut, or EVERY
// region the connector reads has a general read cursor
// (cloud_trail_cursor.read_to, migration 147) past cut that did not skip it
// (a capped read must reach back to cut). One region is not enough: a call
// can be made, and logged, in any region the connector reads.
func containEvidenceCovers(tx *gorm.DB, ws, connectorID uuid.UUID, cut time.Time) (bool, string, error) {
	var n int64
	if err := tx.Table("agent_event_stream").Where("workspace_id = ? AND connector_id = ? AND revoked_at IS NULL AND last_event_time >= ?", ws, connectorID, cut).
		Count(&n).Error; err != nil {
		return false, "", err
	}
	if n > 0 {
		return true, "event_stream", nil
	}
	var conns []models.CloudConnector
	if err := tx.Where("workspace_id = ? AND id = ?", ws, connectorID).Limit(1).Find(&conns).Error; err != nil {
		return false, "", err
	}
	if len(conns) == 0 {
		return false, "", nil
	}
	var cursors []struct {
		Region      string
		ReadTo      time.Time
		Partial     bool
		CoveredFrom time.Time
	}
	if err := tx.Table("cloud_trail_cursor").Select("region, read_to, partial, covered_from").
		Where("workspace_id = ? AND connector_id = ? AND stream = ?", ws, connectorID, "general").Find(&cursors).Error; err != nil {
		return false, "", err
	}
	past := map[string]bool{}
	for _, c := range cursors {
		past[c.Region] = !c.ReadTo.Before(cut) && (!c.Partial || !c.CoveredFrom.After(cut))
	}
	regions := conns[0].AWSAttrs().Regions
	if len(regions) == 0 {
		// No recorded selection: every region the scan has a cursor for.
		for r := range past {
			regions = append(regions, r)
		}
	}
	if len(regions) == 0 {
		return false, "", nil
	}
	for _, r := range regions {
		if !past[r] {
			return false, "", nil
		}
	}
	return true, "cloudtrail_read", nil
}

func containJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

/* --------------------------------- release --------------------------------- */

// restoreDue restores every step that is due (newest first) and reports
// whether any restore failed for good.
func (j *containJob) restoreDue(ctx context.Context, eng *agentcontain.Engine, steps []AgentContainmentStep, now time.Time) (bool, error) {
	failed := false
	for i := len(steps) - 1; i >= 0; i-- {
		s := steps[i]
		cleanup := agentcontain.NeedsCleanup(s.engineStep()) || (j.forceCleanup && agentcontain.HoldsPolicy(s.engineStep()))
		switch s.State {
		case agentcontain.StepPending, agentcontain.StepApplied, agentcontain.StepRestoring, agentcontain.StepRestoreFailed:
		default:
			if !cleanup {
				continue
			}
		}
		if !cleanup && s.RestoreAfter != nil && now.Before(*s.RestoreAfter) {
			continue
		}
		if s.State != agentcontain.StepRestoring && !cleanup {
			if err := j.stepUpdate(ctx, s.ID, map[string]any{"state": agentcontain.StepRestoring}, nil); err != nil {
				return failed, err
			}
		}
		st := s.engineStep()
		if !cleanup {
			st.State = agentcontain.StepRestoring
		}
		err := j.run.External(ctx, 0, func(ctx context.Context) error { return eng.Restore(ctx, &st) })
		var se *agentcontain.StepError
		switch {
		case err != nil && isLeaseErr(err):
			return failed, err
		case errors.As(err, &se):
			failed = true
			if err := j.stepUpdate(ctx, s.ID, map[string]any{"state": agentcontain.StepRestoreFailed, "error": truncateReason(se.Error())}, nil); err != nil {
				return failed, err
			}
		case err != nil:
			_ = j.stepUpdate(ctx, s.ID, map[string]any{"state": agentcontain.StepRestoreFailed, "error": truncateReason(err.Error())}, nil)
			return failed, PolicyJobRetryLater(containRetry, "restoring "+s.Kind+" "+s.Target+": "+err.Error())
		default:
			name := GovEventContainmentStepRestored
			if s.Kind == agentcontain.StepSessionRevoke && j.row.State == agentcontain.StateReleased {
				name = GovEventContainmentRevocationEnded
			}
			note := st.Error
			if cleanup {
				// Keep why the step failed; the policy it may have left is gone.
				note = truncateReason(s.Error + " (AuthSec policy cleaned up on release)")
			}
			if err := j.stepUpdate(ctx, s.ID, map[string]any{"state": agentcontain.StepRestored, "restored_at": now, "error": note},
				func(tx *gorm.DB) error {
					return j.event(tx, j.ws, name, map[string]any{"kind": s.Kind, "target": s.Target,
						"before": json.RawMessage(jsonOrEmpty(s.Before)), "note": note})
				}); err != nil {
				return failed, err
			}
		}
	}
	return failed, nil
}

func (j *containJob) needsAWS(steps []AgentContainmentStep, now time.Time) bool {
	for _, s := range steps {
		if agentcontain.NeedsCleanup(s.engineStep()) {
			return true
		}
		switch s.State {
		case agentcontain.StepPending, agentcontain.StepApplied, agentcontain.StepRestoring, agentcontain.StepRestoreFailed:
			if s.RestoreAfter == nil || !now.Before(*s.RestoreAfter) {
				return true
			}
		}
	}
	return false
}

func (j *containJob) release(ctx context.Context) error {
	now := j.now()
	steps, err := j.steps(ctx)
	if err != nil {
		return err
	}
	if j.needsAWS(steps, now) {
		eng, err := j.open(ctx)
		if err != nil {
			return err
		}
		failed, err := j.restoreDue(ctx, eng, steps, now)
		if err != nil {
			return err
		}
		if steps, err = j.steps(ctx); err != nil {
			return err
		}
		if failed {
			j.note(ctx, "some changes could not be restored yet; retrying")
		}
	}
	es := make([]agentcontain.Step, 0, len(steps))
	for _, s := range steps {
		es = append(es, s.engineStep())
	}
	done, next := agentcontain.ReleaseDone(es, now)
	if !done {
		return PolicyJobRetryLater(5*time.Minute, "release not complete")
	}
	err = j.run.InTx(ctx, func(tx *gorm.DB) error {
		set := map[string]any{"released_at": now, "state_reason": "", "pending_restore_at": next}
		if err := j.moveTx(tx, agentcontain.StateReleasing, agentcontain.StateReleased, set); err != nil {
			return err
		}
		pl := map[string]any{"steps": stepSummary(steps)}
		if next != nil {
			pl["deferred_until"] = *next
			pl["note"] = "The session revocation stays until then: sessions issued before the containment remain refused (P3-3)."
		}
		return j.event(tx, j.ws, GovEventContainmentReleased, pl)
	})
	if err != nil {
		return j.settled(err)
	}
	if next != nil {
		return PolicyJobRetryLater(time.Until(*next)+time.Second, "session revocation removed at "+next.Format(time.RFC3339))
	}
	return nil
}

// deferred removes the session revocation of a released containment at its time.
func (j *containJob) deferred(ctx context.Context) error {
	if j.row.PendingRestoreAt == nil {
		return nil
	}
	now := j.now()
	if now.Before(*j.row.PendingRestoreAt) {
		return PolicyJobRetryLater(j.row.PendingRestoreAt.Sub(now)+time.Second, "deferred restore not due yet")
	}
	steps, err := j.steps(ctx)
	if err != nil {
		return err
	}
	if j.needsAWS(steps, now) {
		eng, err := j.open(ctx)
		if err != nil {
			return err
		}
		if _, err := j.restoreDue(ctx, eng, steps, now); err != nil {
			return err
		}
		if steps, err = j.steps(ctx); err != nil {
			return err
		}
	}
	es := make([]agentcontain.Step, 0, len(steps))
	for _, s := range steps {
		es = append(es, s.engineStep())
	}
	done, next := agentcontain.ReleaseDone(es, now)
	if !done {
		return PolicyJobRetryLater(5*time.Minute, "deferred restore not complete")
	}
	if err := j.run.InTx(ctx, func(tx *gorm.DB) error {
		return tx.Model(&AgentContainment{}).Where("workspace_id = ? AND id = ? AND state = ?", j.ws, j.row.ID, agentcontain.StateReleased).
			Updates(map[string]any{"pending_restore_at": next, "updated_at": now}).Error
	}); err != nil {
		return err
	}
	if next != nil {
		return PolicyJobRetryLater(next.Sub(now)+time.Second, "next deferred restore")
	}
	return nil
}

/* ------------------------------ jobs, schedule ----------------------------- */

// RegisterAgentContainJobs installs the agent_contain handler and its
// schedule: every 10 minutes each open containment (and each released one
// with a deferred restore) gets its job, so a lost job never leaves a
// containment half-applied or a release unfinished.
func RegisterAgentContainJobs(w *PolicyJobWorker, db *gorm.DB) {
	s := NewAgentContain(db)
	w.Register(PolicyJobKind{Kind: GovJobAgentContain, Handler: s.Handler,
		Backoff: func(n int) time.Duration { return time.Duration(n) * time.Minute }})
	w.Scheduler().Add(PolicyJobSchedule{Name: GovJobAgentContain, Kind: GovJobAgentContain, Every: 10 * time.Minute, Due: dueContainments})
}

func dueContainments(ctx context.Context, db *gorm.DB, now time.Time) ([]ScheduledPolicyJob, error) {
	// TENANT-EXEMPT: the 151 schema check reads the Postgres catalog only.
	if ok, _ := agentContainSchemaStatus(db); !ok {
		return nil, nil
	}
	var rows []struct {
		WorkspaceID uuid.UUID
		ID          uuid.UUID
	}
	// TENANT-EXEMPT: the scheduler's due scan spans every workspace (rows
	// carry workspace_id); each job runs under RLS for its row's workspace.
	if err := db.WithContext(ctx).Model(&AgentContainment{}).Select("workspace_id, id").
		Where("state IN ? OR (state = ? AND pending_restore_at IS NOT NULL AND pending_restore_at <= ?)",
			agentcontain.LiveStates, agentcontain.StateReleased, now).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("agent containment due scan: %w", err)
	}
	out := make([]ScheduledPolicyJob, 0, len(rows))
	for _, r := range rows {
		id := r.ID
		out = append(out, ScheduledPolicyJob{WorkspaceID: r.WorkspaceID, SubjectID: &id, DedupeKey: "agent_containment:" + id.String()})
	}
	return out, nil
}
