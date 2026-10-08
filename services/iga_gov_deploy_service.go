package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// The deployment state machine (SPEC-iga-phase3-policy.md §2.8, §8.1, §8.4,
// §8.5, §8.7-§8.10; T3.16). T3.15 (rollout) CREATES apply deployments in
// `queued` and enqueues one `deploy` job per deployment; everything from the
// deploy job on is here:
//
//	deploy          queued -> (paused policy: wait) -> authority (usable
//	                approval + revalidation for apply; the approval naming the
//	                plan for undo / remove_control; emergency) -> binding fresh
//	                -> applying -> IGAGovAWSExecutor.ExecutePlan (T3.10) ->
//	                applied_unverified (+ verify) | blocked | failed |
//	                outcome_unknown (+ resolve_unknown at settle_after) |
//	                retry later. Intended ledger rows of a stopped run are
//	                settled from completed_ops.
//	verify          four dimensions (iga_gov_verify.go); verified ONLY when
//	                artifact AND graph pass -- never by elapsed time (A55).
//	drift_check     an enforcement observer; never writes AWS (§8.8).
//	resolve_unknown two readings 5 min apart after settle_after, consistent
//	                with CloudTrail -> resolved (back to applying) or
//	                outcome_unresolved (operator, §8.1 step 3).
//
// Posture, findings, history and the control epoch are written only through
// the enforcement observer (iga_gov_deploy_observer.go), in the shared lock
// order control -> deployment/artifact -> posture -> findings.
//
// Delivery: direct only. A deployment whose delivery is iac_pr or export is
// handed to the GovDeliveryHandler registered for it (T3.17 plugs in with
// RegisterGovDeliveryHandler); without one it is blocked
// (delivery_not_available) so it never holds its control.

// Deployment reasons this file names.
const (
	GovOutcomeOverdue = "overdue"
	DepReasonPolicyPaused         = "policy_paused"
	DepReasonDeliveryUnavailable  = "delivery_not_available"
	DepReasonApprovalMissingPlan  = "approval_does_not_name_plan"
	DepReasonOutcomeUnresolvable  = "outcome_unresolvable"
	DepReasonBindingUnavailable   = "binding_unavailable"
	DepReasonEmergency            = "emergency"
	DefaultVerifyDeadline         = 60 * time.Minute
	DefaultVerifyEvery            = 10 * time.Minute
	DefaultUnknownReadingGap      = 5 * time.Minute
	DefaultBindingSelfTestMaxAge  = time.Hour
	govDeployObserverMaxAttempts  = 3
	govDeployObserverMaxCASRounds = 5
)

// Event names (vocabulary: iga_gov_event_vocabulary.go).
const (
	GovEventDeploymentStarted     = "deployment.started"
	GovEventDeploymentBlocked     = "deployment.blocked"
	GovEventDeploymentFailed      = "deployment.failed"
	GovEventDeploymentApplied     = "deployment.applied"
	GovEventDeploymentVerified    = "deployment.verified"
	GovEventDeploymentUndone      = "deployment.undone"
	GovEventDeploymentSuperseded  = "deployment.superseded"
	GovEventDeploymentDrifted     = "deployment.drifted"
	GovEventDeploymentUnresolved  = "deployment.outcome_unresolved"
	GovEventDeploymentRecovered   = "deployment.recovered"
	GovEventDeploymentResolveReq  = "deployment.resolve_requested"
	GovEventLedgerSettled         = "deployment.ledger_settled"
	GovEventUnknownReading        = "deployment.unknown_reading"
	GovEventVerificationRecorded  = "verification.recorded"
	GovEventPostureChanged        = "posture.outcome_changed"
	GovEventFindingPostureStatus  = "finding.posture_status"
	GovEventValidationDeclared    = "validation.declared"
	GovEventHealthReported        = "health_report.created"
	GovEventUndoRequested         = "undo.requested"
	GovEventEmergencyUndo         = "undo.emergency"
	GovEventRoleOnlyRecoveryPlan  = "undo.role_only_recovery_compiled"
	GovEventControlRemovalReq     = "control.removal_requested"
	GovEventControlRemoved        = "control.removed"
	GovEventControlRoleGone       = "control.role_gone"
	GovEventDriftLateMutation     = "drift.late_mutation_suspected"
	GovEventAcceptObservedOpened  = "deployment.accept_observed_opened"
)

/* --------------------------------- seams ---------------------------------- */

// GovBindingGate proves, before a direct deployment starts, that the
// account's enforcement binding is verified with a self-test younger than
// an hour (§3.6, T3.09 EnsureFresh). It returns nil or an error whose
// *GovError / *EnforcementError code names why (binding_not_verified,
// binding_partial, enforcement_not_enabled). Production:
// NewEnforcementBindingDeployGate (cloud_enforcement_deploy_gate.go, outside
// the iga_* files because it reads the binding table).
type GovBindingGate func(ctx context.Context, ws, connectorID uuid.UUID) error

// GovTrailEvent is one CloudTrail event of the enforcement session.
type GovTrailEvent struct {
	EventTime time.Time
	EventName string
	ErrorCode string
}

// GovEnforcementTrail reads the CloudTrail events of one deployment's
// enforcement session (authsec-enforce-<deployment 16hex>) for §8.1 step 2.
type GovEnforcementTrail interface {
	EnforcementSessionEvents(ctx context.Context, ws, connectorID uuid.UUID, sessionName string, from, to time.Time) ([]GovTrailEvent, error)
}

// GovDeployEnv is what the deployment jobs need from outside the database.
type GovDeployEnv struct {
	AWS     IGAGovAWS
	Binding GovBindingGate
	Trail   GovEnforcementTrail
}

var (
	govDeployEnvMu sync.RWMutex
	govDeployEnv   GovDeployEnv
)

// SetGovDeployEnv installs the process-wide deployment environment
// (cmd/main.go, when the enforcement binding service can be built).
func SetGovDeployEnv(e GovDeployEnv) {
	govDeployEnvMu.Lock()
	govDeployEnv = e
	govDeployEnvMu.Unlock()
}

func currentGovDeployEnv() GovDeployEnv {
	govDeployEnvMu.RLock()
	defer govDeployEnvMu.RUnlock()
	return govDeployEnv
}

// GovDeliveryHandler is T3.17's plug-in for iac_pr / export deployments:
// Start moves a queued deployment on (awaiting_merge / awaiting_apply);
// Verify classifies awaiting_apply against live state with igagov.Classify
// (the same classifier as direct delivery) and returns the deployment's next
// state. Both run inside the deploy / verify job (run is the fence).
type GovDeliveryHandler interface {
	Start(ctx context.Context, run *PolicyJobRun, dep models.IGAGovDeployment, plan igagov.Plan) error
	Verify(ctx context.Context, run *PolicyJobRun, dep models.IGAGovDeployment, plan igagov.Plan) error
}

var (
	govDeliveryMu       sync.RWMutex
	govDeliveryHandlers = map[string]GovDeliveryHandler{}
)

// RegisterGovDeliveryHandler installs the handler of a delivery (iac_pr,
// export). nil removes it.
func RegisterGovDeliveryHandler(delivery string, h GovDeliveryHandler) {
	govDeliveryMu.Lock()
	defer govDeliveryMu.Unlock()
	if h == nil {
		delete(govDeliveryHandlers, delivery)
		return
	}
	govDeliveryHandlers[delivery] = h
}

func govDeliveryHandler(delivery string) GovDeliveryHandler {
	govDeliveryMu.RLock()
	defer govDeliveryMu.RUnlock()
	return govDeliveryHandlers[delivery]
}

/* -------------------------------- service --------------------------------- */

// GovDeployments is the deployment state machine.
type GovDeployments struct {
	db        *gorm.DB
	env       GovDeployEnv
	attempts  *IGAGovAttemptLog
	authoring *GovAuthoring
	now       func() time.Time
	sleep     func(ctx context.Context, d time.Duration) error

	// Executor customises the T3.10 executor each job builds (tests: no
	// sleeps, fault injection).
	Executor func(e *IGAGovAWSExecutor)
	// ObserverHook is a test seam called inside an enforcement observer's
	// transaction at "after_cas" (the control's swap won) and before its
	// readback at "before_read"; an error aborts the attempt.
	ObserverHook func(stage string, controlID uuid.UUID, tx *gorm.DB) error
}

// NewGovDeployments builds the service over db with env (zero env: the
// process-wide one, read at call time).
func NewGovDeployments(db *gorm.DB, env *GovDeployEnv) *GovDeployments {
	s := &GovDeployments{db: db, now: time.Now, sleep: sleepCtx}
	if env != nil {
		s.env = *env
	}
	s.attempts = NewIGAGovAttemptLog(db)
	s.authoring = NewGovAuthoring(db, ProcessGovLiveReader())
	return s
}

// WithClock replaces the clock (tests); the attempt log and approval checks
// use it too.
func (s *GovDeployments) WithClock(now func() time.Time) *GovDeployments {
	s.now = now
	s.attempts.WithClock(now)
	s.authoring.now = now
	return s
}

// WithSleep replaces the backoff sleep (tests).
func (s *GovDeployments) WithSleep(f func(ctx context.Context, d time.Duration) error) *GovDeployments {
	s.sleep = f
	return s
}

// WithAuthoring replaces the authoring service (tests: a live reader).
func (s *GovDeployments) WithAuthoring(a *GovAuthoring) *GovDeployments {
	s.authoring = a
	return s
}

func (s *GovDeployments) envNow() GovDeployEnv {
	e := s.env
	if e.AWS == nil && e.Binding == nil && e.Trail == nil {
		e = currentGovDeployEnv()
	}
	if e.Trail == nil {
		e.Trail = ObservationEnforcementTrail{DB: s.db}
	}
	return e
}

func (s *GovDeployments) executor() (*IGAGovAWSExecutor, error) {
	env := s.envNow()
	if env.AWS == nil {
		return nil, errors.New("AWS enforcement access is not configured in this build")
	}
	e := NewIGAGovAWSExecutor(s.db, s.attempts, env.AWS).WithClock(s.now)
	if s.Executor != nil {
		s.Executor(e)
	}
	return e, nil
}

// Register installs the deploy, verify, drift_check and resolve_unknown
// handlers on w (replacing drift_check's no-op).
func (s *GovDeployments) Register(w *PolicyJobWorker) {
	w.Register(PolicyJobKind{Kind: repositories.GovJobDeploy, Handler: s.DeployHandler,
		Backoff: func(n int) time.Duration { return time.Duration(n) * time.Minute }})
	w.Register(PolicyJobKind{Kind: repositories.GovJobVerify, Handler: s.VerifyHandler})
	w.Register(PolicyJobKind{Kind: repositories.GovJobDriftCheck, Handler: s.DriftHandler})
	w.Register(PolicyJobKind{Kind: repositories.GovJobResolveUnknown, Handler: s.ResolveUnknownHandler})
}

/* ------------------------------- small reads ------------------------------- */

func (s *GovDeployments) loadDeployment(db *gorm.DB, ws, id uuid.UUID) (*models.IGAGovDeployment, error) {
	var d models.IGAGovDeployment
	if err := db.Where("workspace_id = ? AND id = ?", ws, id).Take(&d).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, GovNotFound()
		}
		return nil, err
	}
	return &d, nil
}

func (s *GovDeployments) loadControl(db *gorm.DB, ws, id uuid.UUID) (*models.IGAGovControl, error) {
	var c models.IGAGovControl
	if err := db.Where("workspace_id = ? AND id = ?", ws, id).Take(&c).Error; err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *GovDeployments) loadPlanRow(db *gorm.DB, ws, id uuid.UUID) (*models.IGAGovPlan, error) {
	var p models.IGAGovPlan
	if err := db.Where("workspace_id = ? AND id = ?", ws, id).Take(&p).Error; err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *GovDeployments) policyOfVersion(db *gorm.DB, ws, versionID uuid.UUID) (uuid.UUID, string, error) {
	var row struct {
		PolicyID  uuid.UUID
		Lifecycle string
	}
	err := db.Raw(`SELECT p.id AS policy_id, p.lifecycle FROM iga_gov_policy_version v
		JOIN iga_gov_policy p ON p.workspace_id = v.workspace_id AND p.id = v.policy_id
		WHERE v.workspace_id = ? AND v.id = ?`, ws, versionID).Scan(&row).Error
	return row.PolicyID, row.Lifecycle, err
}

func depRefs(d models.IGAGovDeployment, policy uuid.UUID) govEventRefs {
	dep, ver := d.ID, d.VersionID
	r := govEventRefs{DeploymentID: &dep, VersionID: &ver}
	if policy != uuid.Nil {
		r.PolicyID = &policy
	}
	return r
}

func (s *GovDeployments) sysEvent(tx *gorm.DB, d models.IGAGovDeployment, name string, payload map[string]any) error {
	pol, _, err := s.policyOfVersion(tx, d.WorkspaceID, d.VersionID)
	if err != nil {
		return err
	}
	return appendGovEvent(tx, d.WorkspaceID, name, models.GovActorSystem, "policy-worker", depRefs(d, pol), payload)
}

// setState moves a deployment from one of from to state, fenced on the job
// and on the expected state (0 rows: someone else moved it -> errStateMoved).
var errStateMoved = errors.New("the deployment's state moved meanwhile")

func setStateTx(tx *gorm.DB, d models.IGAGovDeployment, from []string, set map[string]any) error {
	set["updated_at"] = gorm.Expr("now()")
	res := tx.Model(&models.IGAGovDeployment{}).Where("workspace_id = ? AND id = ? AND state IN ?", d.WorkspaceID, d.ID, from).Updates(set)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected != 1 {
		return errStateMoved
	}
	return nil
}

func enqueueJobTx(tx *gorm.DB, ws uuid.UUID, kind string, subject uuid.UUID, runAfter time.Time) error {
	id := subject
	_, err := repositories.NewIGAGovJobRepository(tx).EnqueueTx(tx, &models.IGAGovJob{WorkspaceID: ws, Kind: kind, SubjectID: &id,
		DedupeKey: "deployment:" + subject.String(), RunAfter: runAfter})
	return err
}

// EnqueueDeployTx queues the deploy job of a deployment (T3.15 calls it for
// the deployments it creates; the undo and remove-control routes call it).
func EnqueueDeployTx(tx *gorm.DB, ws, deploymentID uuid.UUID) error {
	return enqueueJobTx(tx, ws, repositories.GovJobDeploy, deploymentID, time.Now())
}

/* --------------------------------- deploy ---------------------------------- */

// DeployHandler is the deploy job (§8.4, §8.5).
func (s *GovDeployments) DeployHandler(ctx context.Context, run *PolicyJobRun) error {
	if run.Job.SubjectID == nil {
		return PolicyJobAbandon("deploy needs a deployment subject")
	}
	ws := run.Job.WorkspaceID
	d, err := s.loadDeployment(run.DB().WithContext(ctx), ws, *run.Job.SubjectID)
	if err != nil {
		var ge *GovError
		if errors.As(err, &ge) {
			return PolicyJobAbandon("deployment not found")
		}
		return err
	}
	switch d.State {
	case models.GovDeployQueued:
		if err := s.start(ctx, run, d); err != nil {
			return err
		}
		if d.State != models.GovDeployApplying {
			return nil
		}
	case models.GovDeployApplying, models.GovDeployOutcomeUnknown:
	default:
		return nil // nothing for the deploy job in this state
	}
	if d.Delivery != igagov.DeliveryDirect {
		return nil // handed to the delivery handler in start
	}
	plan, err := loadGovPlan(run.DB(), ws, d.PlanID)
	if err != nil {
		return err
	}
	exec, err := s.executor()
	if err != nil {
		return PolicyJobRetryLater(5*time.Minute, err.Error())
	}
	out, err := exec.ExecutePlan(ctx, run, *d, plan)
	if err != nil {
		return err
	}
	return s.applyOutcome(ctx, run, *d, plan, out)
}

// start is queued -> applying (or blocked / waiting): the policy is not
// paused, the deployment's authority holds (§2.8), revalidation when the
// approved evidence is stale, and the binding is fresh.
func (s *GovDeployments) start(ctx context.Context, run *PolicyJobRun, d *models.IGAGovDeployment) error {
	db := run.DB().WithContext(ctx)
	ws := d.WorkspaceID
	_, lifecycle, err := s.policyOfVersion(db, ws, d.VersionID)
	if err != nil {
		return err
	}
	if lifecycle == "paused" {
		// §2.4: no new deployment starts while paused; it stays queued.
		return PolicyJobRetryLater(5*time.Minute, DepReasonPolicyPaused)
	}
	plan, err := s.loadPlanRow(db, ws, d.PlanID)
	if err != nil {
		return err
	}
	var revID *uuid.UUID
	if code, msg, detail, rv, err := s.authority(ctx, run, *d, *plan); err != nil {
		return err
	} else if code != "" {
		return s.block(ctx, run, d, code, msg, detail, nil)
	} else {
		revID = rv
	}
	if d.Delivery == igagov.DeliveryDirect {
		if g := s.envNow().Binding; g != nil {
			if err := g(ctx, ws, mustControlConnector(db, ws, d.ControlID)); err != nil {
				code, msg := DepReasonBindingUnavailable, err.Error()
				var ge *GovError
				var ee *EnforcementError
				switch {
				case errors.As(err, &ge):
					code, msg = ge.Code, ge.Message
				case errors.As(err, &ee):
					code, msg = ee.Code, ee.Message
				}
				return s.block(ctx, run, d, code, msg, nil, nil)
			}
		}
	} else if govDeliveryHandler(d.Delivery) == nil {
		return s.block(ctx, run, d, DepReasonDeliveryUnavailable,
			"Delivery "+d.Delivery+" is not available in this build (T3.17).", nil, nil)
	}
	next := models.GovDeployApplying
	if d.Delivery != igagov.DeliveryDirect {
		next = models.GovDeployQueued // the delivery handler moves it
	}
	err = run.InTx(ctx, func(tx *gorm.DB) error {
		set := map[string]any{"state": next, "state_reason": ""}
		if revID != nil {
			set["revalidation_id"], set["revalidation_result"] = *revID, models.GovRevalidationUnchanged
		}
		if err := setStateTx(tx, *d, []string{models.GovDeployQueued}, set); err != nil {
			return err
		}
		return s.sysEvent(tx, *d, GovEventDeploymentStarted, map[string]any{"kind": d.Kind, "delivery": d.Delivery,
			"plan_id": d.PlanID, "revalidation_id": revID, "emergency": d.ApprovalID == nil})
	})
	if errors.Is(err, errStateMoved) {
		return nil
	}
	if err != nil {
		return err
	}
	d.State = next
	if d.Delivery != igagov.DeliveryDirect {
		p, err := loadGovPlan(run.DB(), ws, d.PlanID)
		if err != nil {
			return err
		}
		return govDeliveryHandler(d.Delivery).Start(ctx, run, *d, p)
	}
	return nil
}

func mustControlConnector(db *gorm.DB, ws, control uuid.UUID) uuid.UUID {
	var id uuid.UUID
	db.Raw(`SELECT connector_id FROM iga_gov_control WHERE workspace_id = ? AND id = ?`, ws, control).Scan(&id)
	return id
}

// authority is §2.8's check before a deployment starts. It returns a block
// code (and message, detail) when the deployment may not proceed, or the
// unchanged revalidation it relies on.
//
// DECISION (T3.16): apply deployments use T3.13's UsableApproval, and when
// it answers revalidation_required the deploy job revalidates (fenced,
// T3.11's revalidate) and asks again; material_change / revalidation_blocked
// block the deployment with the changes. Undo, role-only recovery,
// split_revert and remove_control are authorised by the approval naming the
// plan's hash (§8.9: expiry and revocation do not disable undo; a
// remove_control plan restores a recorded baseline and its precondition is
// the artifact_state, so its safety is the live classification, not
// evidence freshness, which T3.11 cannot recompile for that intent), or by
// governance:emergency (emergency_by + reason, enforced by 051).
func (s *GovDeployments) authority(ctx context.Context, run *PolicyJobRun, d models.IGAGovDeployment, p models.IGAGovPlan) (string, string, map[string]any, *uuid.UUID, error) {
	if d.ApprovalID == nil {
		return "", "", nil, nil, nil // emergency: 051 iga_gov_pd_authority_chk
	}
	if d.Kind != igagov.PlanApply {
		var ap models.IGAGovApproval
		if err := run.DB().WithContext(ctx).Where("workspace_id = ? AND id = ?", d.WorkspaceID, *d.ApprovalID).Take(&ap).Error; err != nil {
			return "", "", nil, nil, err
		}
		if ap.Decision != "approve" || !containsStr(ap.PlanHashes, p.PlanHash) {
			return GovCodeApprovalRequired, "The approval does not name this plan.", map[string]any{"approval_id": ap.ID, "plan_id": p.ID}, nil, nil
		}
		if d.Kind == igagov.PlanRemoveControl && (ap.RevokedAt != nil || !s.now().Before(ap.ExpiresAt)) {
			return GovCodeApprovalExpired, "The approval of this control removal is no longer in force.", map[string]any{"approval_id": ap.ID}, nil, nil
		}
		return "", "", nil, nil, nil
	}
	ua, err := s.authoring.UsableApproval(ctx, d.WorkspaceID, d.VersionID, []uuid.UUID{d.PlanID})
	var ge *GovError
	if err != nil && errors.As(err, &ge) && ge.Code == GovCodeRevalidationNeeded {
		call := func(ctx context.Context, fn func(ctx context.Context) error) error { return run.External(ctx, 0, fn) }
		rv, rerr := s.authoring.revalidate(ctx, d.WorkspaceID, d.PlanID, call, run.InTx)
		if rerr != nil {
			if errors.As(rerr, &ge) {
				return ge.Code, ge.Message, ge.Detail, nil, nil
			}
			return "", "", nil, nil, rerr
		}
		switch rv.Revalidation.Result {
		case models.GovRevalidationMaterialChange:
			return GovCodeMaterialChange, "Revalidation found a material change; a new approval is needed.",
				map[string]any{"revalidation_id": rv.Revalidation.ID, "changes": rv.Changes}, nil, nil
		case models.GovRevalidationBlocked:
			return GovCodeRevalidationBlocked, rv.Revalidation.BlockedReason,
				map[string]any{"revalidation_id": rv.Revalidation.ID}, nil, nil
		}
		ua, err = s.authoring.UsableApproval(ctx, d.WorkspaceID, d.VersionID, []uuid.UUID{d.PlanID})
	}
	if err != nil {
		if errors.As(err, &ge) {
			return ge.Code, ge.Message, ge.Detail, nil, nil
		}
		return "", "", nil, nil, err
	}
	if ua.Approval.ID != *d.ApprovalID {
		return GovCodeApprovalInvalid, "The deployment names another approval than the one in force.",
			map[string]any{"approval_id": ua.Approval.ID}, nil, nil
	}
	return "", "", nil, ua.Revalidations[d.PlanID], nil
}

// block moves a queued or applying deployment to blocked (§8.4), settling
// intended ledger rows.
func (s *GovDeployments) block(ctx context.Context, run *PolicyJobRun, d *models.IGAGovDeployment, code, msg string, detail map[string]any, cl *igagov.Classification) error {
	return s.stop(ctx, run, d, models.GovDeployBlocked, code, msg, detail, cl)
}

func (s *GovDeployments) stop(ctx context.Context, run *PolicyJobRun, d *models.IGAGovDeployment, state, code, msg string, detail map[string]any, cl *igagov.Classification) error {
	reason := code
	if msg != "" {
		reason = code + ": " + msg
	}
	err := run.InTx(ctx, func(tx *gorm.DB) error {
		if err := tx.Exec(`SELECT id FROM iga_gov_control WHERE workspace_id = ? AND id = ? FOR UPDATE`, d.WorkspaceID, d.ControlID).Error; err != nil {
			return err
		}
		if err := setStateTx(tx, *d, []string{models.GovDeployQueued, models.GovDeployApplying}, map[string]any{
			"state": state, "state_reason": truncate(reason, 2000)}); err != nil {
			return err
		}
		if err := s.settleLedgerTx(tx, *d); err != nil {
			return err
		}
		name := GovEventDeploymentBlocked
		if state == models.GovDeployFailed {
			name = GovEventDeploymentFailed
		}
		payload := map[string]any{"code": code, "message": msg, "detail": detail}
		if cl != nil {
			payload["classification"] = cl
		}
		return s.sysEvent(tx, *d, name, payload)
	})
	if errors.Is(err, errStateMoved) {
		return nil
	}
	if err == nil {
		d.State = state
	}
	return err
}

// settleLedgerTx settles the `intended` ledger rows a stopped run left
// (§8.5 "a crash at any point leaves either an intended row or a consistent
// one"; T3.16: a run that STOPPED must not leave one). DECISION: an
// intended row becomes present when the op that creates its artifact is in
// completed_ops (CreatePolicy for boundary_policy, PutRolePermissionsBoundary
// for boundary_attachment) -- the artifact exists in AWS and AuthSec owns
// it -- and removed otherwise (it was never created).
func (s *GovDeployments) settleLedgerTx(tx *gorm.DB, d models.IGAGovDeployment) error {
	var rows []models.IGAGovArtifact
	if err := tx.Where("workspace_id = ? AND control_id = ? AND last_deployment_id = ? AND state = 'intended'",
		d.WorkspaceID, d.ControlID, d.ID).Order("id").Clauses(lockForUpdate()).Find(&rows).Error; err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	var cur models.IGAGovDeployment
	if err := tx.Where("id = ?", d.ID).Take(&cur).Error; err != nil {
		return err
	}
	var done []struct {
		Operation string `json:"operation"`
		Outcome   string `json:"outcome"`
	}
	_ = json.Unmarshal(cur.CompletedOps, &done)
	did := map[string]bool{}
	for _, o := range done {
		if OpDone(o.Outcome) {
			did[o.Operation] = true
		}
	}
	var settled []map[string]any
	for _, r := range rows {
		to := ArtifactRemoved
		switch r.Kind {
		case ArtifactBoundaryPolicy:
			if did[igagov.OpCreatePolicy] {
				to = ArtifactPresent
			}
		case ArtifactBoundaryAttachment:
			if did[igagov.OpPutRolePermissionsBoundary] {
				to = ArtifactPresent
			}
		}
		if err := tx.Exec(`UPDATE iga_gov_artifact SET state = ?, updated_at = now() WHERE id = ?`, to, r.ID).Error; err != nil {
			return err
		}
		settled = append(settled, map[string]any{"kind": r.Kind, "native_arn": r.NativeARN, "to": to})
	}
	return s.sysEvent(tx, d, GovEventLedgerSettled, map[string]any{"rows": settled})
}

// applyOutcome maps T3.10's DeployOutcome to the state machine (the report
// notes at the top of iga_gov_aws_executor.go).
func (s *GovDeployments) applyOutcome(ctx context.Context, run *PolicyJobRun, d models.IGAGovDeployment, plan igagov.Plan, out *DeployOutcome) error {
	ws := d.WorkspaceID
	cl := out.Last
	if cl == nil {
		cl = out.Start
	}
	switch out.Result {
	case DeployApplied:
		return s.applied(ctx, run, d, plan, out)
	case DeployBlocked:
		return s.block(ctx, run, &d, out.Reason, out.Detail, nil, cl)
	case DeployFailed:
		return s.stop(ctx, run, &d, models.GovDeployFailed, out.Reason, out.Detail, nil, cl)
	case DeployOutcomeUnknown, DeployHold:
		at := s.now()
		if out.SettleAfter != nil {
			at = *out.SettleAfter
		}
		return run.InTx(ctx, func(tx *gorm.DB) error {
			return enqueueJobTx(tx, ws, repositories.GovJobResolveUnknown, d.ID, at)
		})
	case DeployRetryLater:
		after := out.RetryAfter
		if after <= 0 {
			after = 30 * time.Second
		}
		return PolicyJobRetryLater(after, out.Reason+": "+out.Detail)
	case DeployRefused:
		if out.Reason == DeployReasonNotApplying {
			return nil
		}
		return s.stop(ctx, run, &d, models.GovDeployFailed, out.Reason, out.Detail, nil, cl)
	}
	return fmt.Errorf("unknown deploy result %q", out.Result)
}

// applied: applying -> applied_unverified with verify_deadline_at, the
// control's baseline recorded at its first applied deployment (§2.3, probe
// DB30) and the control active; verify enqueued.
func (s *GovDeployments) applied(ctx context.Context, run *PolicyJobRun, d models.IGAGovDeployment, plan igagov.Plan, out *DeployOutcome) error {
	at := s.now().UTC()
	if out.Readback != nil && !out.Readback.ReadAt.IsZero() {
		at = out.Readback.ReadAt.UTC()
	}
	deadline := at.Add(DefaultVerifyDeadline)
	err := run.InTx(ctx, func(tx *gorm.DB) error {
		var c models.IGAGovControl
		if err := tx.Where("workspace_id = ? AND id = ?", d.WorkspaceID, d.ControlID).Clauses(lockForUpdate()).Take(&c).Error; err != nil {
			return err
		}
		if c.BaselineCapturedAt == nil && c.State != "removed" {
			var pre struct {
				ArtifactState igagov.ArtifactStateFacts `json:"artifact_state"`
			}
			_ = json.Unmarshal(plan.Precondition, &pre)
			if err := tx.Exec(`UPDATE iga_gov_control SET baseline_captured_at = ?, baseline_boundary_arn = ?, baseline_document_hash = ?,
				updated_at = now() WHERE id = ?`, at, pre.ArtifactState.BoundaryARN, pre.ArtifactState.BoundaryDocumentHash, c.ID).Error; err != nil {
				return err
			}
		}
		if c.State == "planned" && d.Kind == igagov.PlanApply {
			if err := tx.Exec(`UPDATE iga_gov_control SET state = 'active', updated_at = now() WHERE id = ?`, c.ID).Error; err != nil {
				return err
			}
		}
		if err := setStateTx(tx, d, []string{models.GovDeployApplying}, map[string]any{"state": models.GovDeployAppliedUnverified,
			"state_reason": "", "applied_at": at, "verify_deadline_at": deadline}); err != nil {
			return err
		}
		if err := enqueueJobTx(tx, d.WorkspaceID, repositories.GovJobVerify, d.ID, at); err != nil {
			return err
		}
		return s.sysEvent(tx, d, GovEventDeploymentApplied, map[string]any{"applied_at": at, "verify_deadline_at": deadline,
			"readback": out.Readback, "ops": out.Ops})
	})
	if errors.Is(err, errStateMoved) {
		return nil
	}
	return err
}

/* -------------------------------- gate facts ------------------------------- */

// DeploymentGateFacts is the read T3.15 evaluates rollout gates from
// (§8.6): the deployment's state, its four verification dimensions as last
// recorded, and the canary gates the verify job computed with
// igagov.EvaluateCanary over the deployment's window (stored in the
// application_health row's evidence).
type DeploymentGateFacts struct {
	DeploymentID      uuid.UUID                   `json:"deployment_id"`
	ControlID         uuid.UUID                   `json:"control_id"`
	Kind              string                      `json:"kind"`
	State             string                      `json:"state"`
	StateReason       string                      `json:"state_reason"`
	AppliedAt         *time.Time                  `json:"applied_at,omitempty"`
	VerifiedAt        *time.Time                  `json:"verified_at,omitempty"`
	VerifyDeadlineAt  *time.Time                  `json:"verify_deadline_at,omitempty"`
	Overdue           bool                        `json:"overdue"`
	Dimensions        map[string]GovDimensionFact `json:"dimensions"`
	Gates             []igagov.GateResult         `json:"gates"`
	UnexpectedFailure []igagov.UnexpectedFailure  `json:"unexpected_failures"`
	Validations       []igagov.ValidationResult   `json:"validations"`
	ServiceRestrict   map[string]string           `json:"service_restriction"`
	CheckedAt         map[string]time.Time            `json:"checked_at"`
}

// GovDimensionFact is one dimension's last result.
type GovDimensionFact struct {
	Outcome     string `json:"outcome"`
	Attribution string `json:"attribution"`
	Reason      string `json:"reason,omitempty"`
}

// DeploymentGateFacts reads the gate facts of a deployment of workspace ws
// (GovNotFound for another workspace's id). Dimensions not yet checked are
// absent from Dimensions; Gates is empty until the verify job has run.
func (s *GovDeployments) DeploymentGateFacts(ctx context.Context, ws, deploymentID uuid.UUID) (*DeploymentGateFacts, error) {
	db := s.db.WithContext(ctx)
	d, err := s.loadDeployment(db, ws, deploymentID)
	if err != nil {
		return nil, err
	}
	out := &DeploymentGateFacts{DeploymentID: d.ID, ControlID: d.ControlID, Kind: d.Kind, State: d.State, StateReason: d.StateReason,
		AppliedAt: d.AppliedAt, VerifiedAt: d.VerifiedAt, VerifyDeadlineAt: d.VerifyDeadlineAt,
		Dimensions: map[string]GovDimensionFact{}, Gates: []igagov.GateResult{}, UnexpectedFailure: []igagov.UnexpectedFailure{},
		Validations: []igagov.ValidationResult{}, ServiceRestrict: map[string]string{}, CheckedAt: map[string]time.Time{}}
	var vs []models.IGAGovVerification
	if err := db.Where("workspace_id = ? AND deployment_id = ?", ws, d.ID).Find(&vs).Error; err != nil {
		return nil, err
	}
	for _, v := range vs {
		var ev struct {
			Reason string `json:"reason"`
			Canary *igagov.CanaryResult
		}
		_ = json.Unmarshal(v.Evidence, &ev)
		out.Dimensions[v.Dimension] = GovDimensionFact{Outcome: v.Outcome, Attribution: v.Attribution, Reason: ev.Reason}
		out.CheckedAt[v.Dimension] = v.CheckedAt
		if v.Dimension == "graph" && v.Outcome == GovOutcomeOverdue {
			out.Overdue = true
		}
		if v.Dimension == "application_health" && ev.Canary != nil {
			out.Gates = ev.Canary.Gates
			out.UnexpectedFailure = ev.Canary.UnexpectedFailures
			out.Validations = ev.Canary.Validations
			out.ServiceRestrict = ev.Canary.ServiceRestriction
		}
	}
	if d.State == models.GovDeployAppliedUnverified && d.VerifyDeadlineAt != nil && s.now().After(*d.VerifyDeadlineAt) {
		out.Overdue = true
	}
	return out, nil
}

func roleSessionHex(id uuid.UUID) string {
	return strings.ReplaceAll(id.String(), "-", "")[:16]
}

// loadGovPlan is LoadIGAGovPlan plus what verification and posture need
// beyond the executor's fields: the impact (removed / retained services,
// routes), the named scan and the unanalysed set.
func loadGovPlan(db *gorm.DB, ws, planID uuid.UUID) (igagov.Plan, error) {
	var row models.IGAGovPlan
	if err := db.Where("workspace_id = ? AND id = ?", ws, planID).First(&row).Error; err != nil {
		return igagov.Plan{}, err
	}
	return fullPlanFromRow(row)
}

func fullPlanFromRow(row models.IGAGovPlan) (igagov.Plan, error) {
	p, err := PlanFromRow(row)
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(row.Impact, &p.Impact); err != nil {
		return p, fmt.Errorf("plan %s impact: %w", row.ID, err)
	}
	_ = json.Unmarshal(row.Unanalysed, &p.Unanalysed)
	if row.ResourcePolicyScanRunID != nil {
		s := row.ResourcePolicyScanRunID.String()
		p.ResourcePolicyScanRunID = &s
	}
	return p, nil
}
