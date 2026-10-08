package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// IGAGovAWSExecutor is T3.10's direct-delivery executor
// (SPEC-iga-phase3-policy.md §3.5, §4.4, §8.1, §8.5, §2.8, §8.7 artifact
// readback): it runs ONE deployment's compiled plan against AWS and reports
// what happened, for the deployment state machine (T3.16) to act on.
//
//	ExecutePlan = Recover (§8.1, always first)
//	            → discovery-role read → igagov.Classify
//	                before / intermediate → run the ops from NextOp
//	                after                 → (trailing invisible ops) → readback
//	                conflict              → blocked, with the classifier's reason
//	            → per op: a fresh read + Classify (the op must still be due),
//	              the ledger rows of NEW artifacts written `intended` (once),
//	              the enforcement role assumed (once per run, never cached),
//	              version selectors resolved against a fresh read with every
//	              chosen version archived in iga_gov_document first, document
//	              bodies from iga_gov_document, the request hash taken after
//	              ${deployment_id} substitution, and the call made inside
//	              IGAGovAttemptLog.Execute (write-ahead, SDK retries off),
//	              its answer classified by igagov.ClassifyOpResponse; no
//	              answer → unknown, never re-sent
//	            → readback: two discovery reads, both `after` with the same
//	              artifact_state; then, in one fenced transaction, the
//	              iga_gov_artifact ledger and the archived boundary document.
//
// It never changes iga_gov_deployment.state itself except through the
// attempt log (dispatched without an answer → outcome_unknown): moving the
// deployment to applied_unverified, blocked or failed is T3.16's, from the
// returned DeployOutcome.
type IGAGovAWSExecutor struct {
	db       *gorm.DB
	attempts *IGAGovAttemptLog
	aws      IGAGovAWS
	events   repositories.IGAGovEventRepository
	now      func() time.Time
	sleep    func(ctx context.Context, d time.Duration) error

	// ReadbackGap separates the two readback reads (IAM is eventually
	// consistent); default 2 s.
	ReadbackGap time.Duration
	// ReadbackRounds is how many pairs of reads may be taken before the
	// readback is reported not yet settled; default 3.
	ReadbackRounds int
	// MaxOpAttempts bounds retryable answers per op (§8.5: at most 5
	// attempts within 15 minutes); default 5.
	MaxOpAttempts int
	// RetryBase is the first backoff after a retryable answer; it doubles
	// per retryable answer (±20 % jitter, capped at 5 min); default 30 s.
	RetryBase time.Duration
	// ConsistencyWindow is how long an op AWS answered `ok` may stay
	// invisible to reads before the state is treated as changed; default
	// 2 min.
	ConsistencyWindow time.Duration
	// FaultBeforeOp is fault injection for tests (A13, A27, A58): a non-nil
	// error stops the run before op opSeq is prepared, as a killed worker
	// would. Never set in production.
	FaultBeforeOp func(opSeq int, op igagov.Op) error
	// BindingCheck is re-run before EACH dispatch (review P1-8): the
	// enforcement client is assumed once per run, so revoking the binding
	// (or a self-test turning it partial) mid-run must stop the run before
	// its next request. A cheap database read of the binding (production:
	// NewEnforcementBindingDispatchCheck); nil checks nothing. A *GovError /
	// *EnforcementError stops the run as blocked with its code; any other
	// error fails the try (the job retries, nothing was sent).
	BindingCheck func(ctx context.Context, ws, connectorID uuid.UUID) error
}

// IGAGovAWS is the executor's access to AWS for a control's connector
// (AWSEnforcementAccess in production).
type IGAGovAWS interface {
	DiscoveryIAM(ctx context.Context, ws, connectorID uuid.UUID) (awsenforce.DiscoveryIAM, error)
	EnforcementIAM(ctx context.Context, ws, connectorID, deploymentID uuid.UUID) (awsenforce.IAM, error)
}

// NewIGAGovAWSExecutor builds the executor.
func NewIGAGovAWSExecutor(db *gorm.DB, attempts *IGAGovAttemptLog, aws IGAGovAWS) *IGAGovAWSExecutor {
	return &IGAGovAWSExecutor{db: db, attempts: attempts, aws: aws, events: repositories.NewIGAGovEventRepository(db),
		now: time.Now, sleep: sleepCtx}
}

// WithClock replaces the clock (tests).
func (e *IGAGovAWSExecutor) WithClock(now func() time.Time) *IGAGovAWSExecutor {
	e.now = now
	return e
}

// WithSleep replaces the readback wait (tests).
func (e *IGAGovAWSExecutor) WithSleep(f func(ctx context.Context, d time.Duration) error) *IGAGovAWSExecutor {
	e.sleep = f
	return e
}

func (e *IGAGovAWSExecutor) readbackGap() time.Duration {
	if e.ReadbackGap > 0 {
		return e.ReadbackGap
	}
	return 2 * time.Second
}

func (e *IGAGovAWSExecutor) readbackRounds() int {
	if e.ReadbackRounds > 0 {
		return e.ReadbackRounds
	}
	return 3
}

func (e *IGAGovAWSExecutor) maxOpAttempts() int {
	if e.MaxOpAttempts > 0 {
		return e.MaxOpAttempts
	}
	return 5
}

func (e *IGAGovAWSExecutor) retryBase() time.Duration {
	if e.RetryBase > 0 {
		return e.RetryBase
	}
	return 30 * time.Second
}

func (e *IGAGovAWSExecutor) consistencyWindow() time.Duration {
	if e.ConsistencyWindow > 0 {
		return e.ConsistencyWindow
	}
	return 2 * time.Minute
}

/* --------------------------------- outcome --------------------------------- */

// Deploy results: what one ExecutePlan run established. T3.16 maps them to
// deployment states.
const (
	// DeployApplied: every op done and the readback shows the plan's after
	// state on two reads; the ledger is written. T3.16: applied_unverified,
	// verify_deadline_at = applied_at + 60 min, enqueue verify.
	DeployApplied = "applied"
	// DeployBlocked: live state is not what the plan expects (a classifier
	// conflict, a readback conflict, a terminal answer that proves the
	// artifact changed, discovery_unavailable). Reason names it; Start /
	// Readback carry the diff.
	DeployBlocked = "blocked"
	// DeployFailed: a terminal answer (binding_partial, role_gone,
	// artifact_owned_elsewhere, retries exhausted, a missing document).
	DeployFailed = "failed"
	// DeployOutcomeUnknown: a request may have reached AWS without an
	// answer; the attempt log has already moved the deployment to
	// outcome_unknown with SettleAfter. Nothing is re-sent.
	DeployOutcomeUnknown = "outcome_unknown"
	// DeployHold: an earlier unknown attempt is unresolved; nothing was done
	// (resolve_unknown, §8.1 step 2, comes first).
	DeployHold = "hold"
	// DeployRetryLater: nothing is wrong yet but the run cannot finish now
	// (throttled, a discovery read failed, AWS not yet consistent); hand the
	// job back after RetryAfter.
	DeployRetryLater = "retry_later"
	// DeployRefused: the plan cannot be executed directly (ineligible,
	// IaC/export only, split kinds, not the deployment's plan, the
	// deployment not applying). Nothing was read or written.
	DeployRefused = "refused"
)

// Reasons the executor itself names (besides igagov's conflict reasons and
// ClassifyOpResponse's terminal reasons, and the binding's error codes).
const (
	DeployReasonIneligible         = "plan_ineligible"
	DeployReasonNotDirect          = "not_direct_delivery"
	DeployReasonPlanMismatch       = "plan_mismatch"
	DeployReasonNotApplying        = "deployment_not_applying"
	DeployReasonUnknownPending     = "outcome_unknown_pending"
	DeployReasonNoAnswer           = "dispatched_without_answer"
	DeployReasonReadFailed         = "discovery_read_failed"
	DeployReasonAwaitConsistency   = "awaiting_consistency"
	DeployReasonNotVisible         = "completed_op_not_visible"
	DeployReasonReadbackNotSettled = "readback_not_settled"
	DeployReasonThrottled          = "throttled"
	DeployReasonRetriesExhausted   = "retries_exhausted"
	DeployReasonDocumentMissing    = "document_not_archived"
	DeployReasonVersionUnarchived  = "version_document_not_archived"
	DeployReasonOpUnresolvable     = "op_unresolvable"
)

// DeployOpRecord is what happened to one op (or one version of a version
// selector) in this run.
type DeployOpRecord struct {
	OpSeq     int        `json:"op_seq"`
	Operation string     `json:"operation"`
	VersionID string     `json:"version_id,omitempty"`
	Outcome   string     `json:"outcome"`
	Basis     string     `json:"basis"` // attempt | live_read | selector
	AttemptID *uuid.UUID `json:"attempt_id,omitempty"`
	AttemptNo int        `json:"attempt_no,omitempty"`
	Request   string     `json:"request_hash,omitempty"`
	RequestID string     `json:"request_id,omitempty"`
	ErrorCode string     `json:"error_code,omitempty"`
	Reason    string     `json:"reason,omitempty"`
}

// Op record bases.
const (
	OpBasisAttempt  = "attempt"
	OpBasisLiveRead = "live_read"
	OpBasisSelector = "selector"
)

// DeployLedgerChange is one iga_gov_artifact row the readback wrote.
type DeployLedgerChange struct {
	Kind      string `json:"kind"`
	NativeARN string `json:"native_arn"`
	From      string `json:"from"`
	To        string `json:"to"`
}

// DeployReadback is the readback that passed (or the last one taken).
type DeployReadback struct {
	Reads                []igagov.Classification   `json:"reads"`
	State                igagov.ArtifactStateFacts `json:"artifact_state"`
	StateHash            string                    `json:"state_hash"`
	BoundaryDocumentHash *string                   `json:"boundary_document_hash"`
	ReadAt               time.Time                 `json:"read_at"`
	Ledger               []DeployLedgerChange      `json:"ledger"`
}

// DeployOutcome is ExecutePlan's structured result.
type DeployOutcome struct {
	Result string `json:"result"`
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
	// Recovery is what Recover found (continue, reprepare, outcome_unknown,
	// hold).
	Recovery string `json:"recovery"`
	// Start is the first classification of this run.
	Start *igagov.Classification `json:"start,omitempty"`
	// Last is the classification that stopped the run, when it was not Start.
	Last     *igagov.Classification `json:"last,omitempty"`
	Ops      []DeployOpRecord       `json:"ops"`
	Readback *DeployReadback        `json:"readback,omitempty"`
	// SettleAfter is set for outcome_unknown and hold.
	SettleAfter *time.Time `json:"settle_after,omitempty"`
	// RetryAfter is set for retry_later.
	RetryAfter time.Duration `json:"retry_after,omitempty"`
	// Attempt is the unknown or held attempt.
	Attempt *models.IGAGovAttempt `json:"attempt,omitempty"`
}

/* ------------------------------- plan loading ------------------------------ */

// LoadIGAGovPlan reads a stored plan back into the compiler's form, with its
// ops and its classifier facts (iga_gov_plan.diff.facts, DECISION D32).
func LoadIGAGovPlan(db *gorm.DB, ws, planID uuid.UUID) (igagov.Plan, error) {
	var row models.IGAGovPlan
	if err := db.Where("workspace_id = ? AND id = ?", ws, planID).First(&row).Error; err != nil {
		return igagov.Plan{}, err
	}
	return PlanFromRow(row)
}

// PlanFromRow converts an iga_gov_plan row.
func PlanFromRow(row models.IGAGovPlan) (igagov.Plan, error) {
	p := igagov.Plan{ControlID: row.ControlID.String(), Kind: row.Kind, Delivery: row.Delivery, Eligibility: row.Eligibility,
		IneligibleReason: row.IneligibleReason, Basis: row.Basis, BasisReadAt: row.BasisReadAt, Precondition: row.Precondition,
		PreconditionHash: row.PreconditionHash, BeforeDocumentHash: row.BeforeDocumentHash, DesiredAttachment: row.DesiredAttachment,
		DesiredBoundaryARN: row.DesiredBoundaryARN, DesiredDocumentHash: row.DesiredDocumentHash,
		ReplacedBoundaryARN: row.ReplacedBoundaryARN, ArtifactDisposition: row.ArtifactDisposition, EvidenceRev: row.EvidenceRev,
		FirstAttachment: row.FirstAttachment, ImpactHash: row.ImpactHash, PlanHash: row.PlanHash, MaterialHash: row.MaterialHash}
	if err := json.Unmarshal(row.Operations, &p.Ops); err != nil {
		return igagov.Plan{}, fmt.Errorf("plan %s operations: %w", row.ID, err)
	}
	if err := json.Unmarshal(row.Diff, &p.Diff); err != nil {
		return igagov.Plan{}, fmt.Errorf("plan %s diff: %w", row.ID, err)
	}
	if facts, err := igagov.FactsFromDiff(row.Diff); err == nil {
		p.Facts = facts
	} else if row.Eligibility != igagov.EligibilityIneligible {
		return igagov.Plan{}, fmt.Errorf("plan %s: %w", row.ID, err)
	}
	return p, nil
}

/* -------------------------------- execution -------------------------------- */

// run is one ExecutePlan call's state.
type execRun struct {
	e    *IGAGovAWSExecutor
	run  *PolicyJobRun
	dep  models.IGAGovDeployment
	plan igagov.Plan
	ctl  models.IGAGovControl
	role string // role name

	disc awsenforce.DiscoveryIAM
	iam  awsenforce.IAM

	out       *DeployOutcome
	completed map[int]bool
	intended  bool
}

// errStop ends a run with the outcome already set on out.
var errStop = errors.New("stop")

// ExecutePlan runs one deployment's plan (see the type's comment). It is the
// deploy job's AWS step for direct delivery; T3.16 calls it with the
// deployment in `applying` (or `outcome_unknown`, which it reports as hold
// or after resolution continues). An error is returned only for a lost or
// short lease, a database failure or a fault injected by a test: the job is
// then retried by the worker and the next run starts with Recover.
func (e *IGAGovAWSExecutor) ExecutePlan(ctx context.Context, run *PolicyJobRun, dep models.IGAGovDeployment, plan igagov.Plan) (*DeployOutcome, error) {
	out := &DeployOutcome{Ops: []DeployOpRecord{}}
	rec, err := e.attempts.Recover(ctx, run, dep.WorkspaceID, dep.ID)
	if err != nil {
		return nil, err
	}
	out.Recovery = rec.Action
	switch rec.Action {
	case RecoveryOutcomeUnknown:
		out.Result, out.Reason, out.SettleAfter, out.Attempt = DeployOutcomeUnknown, DeployReasonNoAnswer, rec.SettleAfter, rec.Attempt
		return out, nil
	case RecoveryHold:
		out.Result, out.Reason, out.SettleAfter, out.Attempt = DeployHold, DeployReasonUnknownPending, rec.SettleAfter, rec.Attempt
		return out, nil
	}
	if reason, detail := refuseDirect(dep, plan); reason != "" {
		out.Result, out.Reason, out.Detail = DeployRefused, reason, detail
		return out, nil
	}
	var cur models.IGAGovDeployment
	if err := e.db.Where("workspace_id = ? AND id = ?", dep.WorkspaceID, dep.ID).First(&cur).Error; err != nil {
		return nil, err
	}
	if cur.State != "applying" {
		out.Result, out.Reason, out.Detail = DeployRefused, DeployReasonNotApplying, "deployment is "+cur.State
		return out, nil
	}
	var ctl models.IGAGovControl
	if err := e.db.Where("workspace_id = ? AND id = ?", dep.WorkspaceID, dep.ControlID).First(&ctl).Error; err != nil {
		return nil, err
	}
	x := &execRun{e: e, run: run, dep: cur, plan: plan, ctl: ctl, role: roleNameOfARN(ctl.RoleARN), out: out}
	if err := x.discovery(ctx); err != nil {
		return x.finish(err)
	}
	if x.completed, err = x.loadCompleted(); err != nil {
		return nil, err
	}
	return x.finish(x.execute(ctx))
}

func (x *execRun) finish(err error) (*DeployOutcome, error) {
	if errors.Is(err, errStop) {
		return x.out, nil
	}
	if err != nil {
		return nil, err
	}
	return x.out, nil
}

func (x *execRun) stop(result, reason, detail string) error {
	x.out.Result, x.out.Reason, x.out.Detail = result, reason, detail
	return errStop
}

// refuseDirect is what ExecutePlan never runs: another deployment's plan, a
// plan that is not direct, a split kind (IaC-only, §11), an ineligible plan.
func refuseDirect(dep models.IGAGovDeployment, p igagov.Plan) (string, string) {
	switch {
	case p.ControlID != dep.ControlID.String() || p.Kind != dep.Kind || p.Delivery != dep.Delivery:
		return DeployReasonPlanMismatch, fmt.Sprintf("plan %s/%s/%s, deployment %s/%s/%s", p.ControlID, p.Kind, p.Delivery,
			dep.ControlID, dep.Kind, dep.Delivery)
	case p.Kind == igagov.PlanSplit || p.Kind == igagov.PlanSplitRevert:
		return DeployReasonNotDirect, p.Kind + " plans are delivered by IaC or export only (§11)"
	case p.Delivery != igagov.DeliveryDirect:
		return DeployReasonNotDirect, "delivery " + p.Delivery
	case p.Eligibility == igagov.EligibilityIaCOnly:
		return DeployReasonNotDirect, "the plan is iac_only (a customer boundary is never written directly, §3.3)"
	case !p.Eligible():
		return DeployReasonIneligible, p.IneligibleReason
	case len(p.Facts) == 0:
		return DeployReasonIneligible, "the plan has no classifier facts"
	}
	for _, op := range p.Ops {
		if _, err := awsenforce.NewRequest(op, uuid.Nil, versionPlaceholder(op)); err != nil {
			return DeployReasonOpUnresolvable, err.Error()
		}
	}
	return "", ""
}

// versionPlaceholder stands in for a selector's version when checking that
// an op is sendable at all.
func versionPlaceholder(op igagov.Op) string {
	if op.Op == igagov.OpDeletePolicyVersion {
		return "v0"
	}
	return ""
}

func roleNameOfARN(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 {
		return arn[i+1:]
	}
	return arn
}

// enforcementCode maps an access error to the outcome it stops the run with.
func (x *execRun) accessStop(err error) error {
	var ee *EnforcementError
	if errors.As(err, &ee) {
		switch ee.Code {
		case EnfCodeDiscoveryUnavailable:
			return x.stop(DeployBlocked, ee.Code, ee.Message)
		case EnfCodeUnavailable:
			return x.stop(DeployRetryLater, ee.Code, ee.Message)
		default:
			return x.stop(DeployFailed, ee.Code, ee.Message)
		}
	}
	return err
}

func (x *execRun) discovery(ctx context.Context) error {
	d, err := x.e.aws.DiscoveryIAM(ctx, x.dep.WorkspaceID, x.ctl.ConnectorID)
	if err != nil {
		return x.accessStop(err)
	}
	x.disc = d
	return nil
}

// enforcement assumes the enforcement role once per run, inside the lease
// margin. Credentials live only in this run.
func (x *execRun) enforcement(ctx context.Context) error {
	if x.iam != nil {
		return nil
	}
	var c awsenforce.IAM
	err := x.run.External(ctx, 0, func(ctx context.Context) error {
		var err error
		c, err = x.e.aws.EnforcementIAM(ctx, x.dep.WorkspaceID, x.ctl.ConnectorID, x.dep.ID)
		return err
	})
	if err != nil {
		if isLeaseErr(err) {
			return err
		}
		return x.accessStop(err)
	}
	x.iam = c
	return nil
}

func isLeaseErr(err error) bool {
	return errors.Is(err, repositories.ErrPolicyJobLeaseLost) || errors.Is(err, repositories.ErrPolicyJobLeaseShort)
}

// read is one discovery-role read for the plan, fenced (run.External).
func (x *execRun) read(ctx context.Context) (igagov.LiveRead, awsenforce.ReadDetail, error) {
	var live igagov.LiveRead
	var detail awsenforce.ReadDetail
	err := x.run.External(ctx, 0, func(ctx context.Context) error {
		var err error
		live, detail, err = awsenforce.ReadForPlan(ctx, x.disc, x.role, x.plan, x.e.now())
		return err
	})
	if err != nil {
		if isLeaseErr(err) {
			return live, detail, err
		}
		x.out.RetryAfter = 30 * time.Second
		return live, detail, x.stop(DeployRetryLater, DeployReasonReadFailed, err.Error())
	}
	return live, detail, nil
}

func (x *execRun) classify(ctx context.Context) (igagov.Classification, error) {
	live, _, err := x.read(ctx)
	if err != nil {
		return igagov.Classification{}, err
	}
	cl, err := igagov.Classify(x.plan, live)
	if err != nil {
		return igagov.Classification{}, err
	}
	if x.out.Start == nil {
		c := cl
		x.out.Start = &c
	}
	return cl, nil
}

func (x *execRun) execute(ctx context.Context) error {
	ops := x.plan.Ops
	cursor := 0
	for {
		cl, err := x.classify(ctx)
		if err != nil {
			return err
		}
		if cl.Class == igagov.ClassConflict {
			c := cl
			x.out.Last = &c
			return x.stop(DeployBlocked, cl.Reason, conflictDetail(cl))
		}
		k := cl.NextOp
		if k < cursor {
			// The read shows an earlier prefix than this run reached: only
			// ops a read cannot see may lie between.
			for j := k; j < cursor; j++ {
				if igagov.OpObservable(ops[j]) {
					return x.notVisible(ctx, j, cl)
				}
			}
			k = cursor
		}
		if err := x.recognise(ctx, k); err != nil {
			return err
		}
		if k >= len(ops) {
			break
		}
		op := ops[k]
		if x.completed[k] {
			if igagov.OpObservable(op) {
				// AWS answered ok for it in an earlier run, yet a read does
				// not show it: never re-send (A26: no duplicate default
				// change); wait for consistency or report the change.
				return x.notVisible(ctx, k, cl)
			}
			if op.Op != igagov.OpDeletePolicyVersion {
				cursor = k + 1 // an idempotent op already done (TagPolicy)
				continue
			}
			// A version selector is always re-resolved: a partly done
			// all_non_default left versions.
		}
		if err := x.runOp(ctx, k); err != nil {
			return err
		}
		x.completed[k] = true
		cursor = k + 1
	}
	return x.readback(ctx)
}

func conflictDetail(cl igagov.Classification) string {
	parts := make([]string, 0, len(cl.Conflicts))
	for _, c := range cl.Conflicts {
		parts = append(parts, fmt.Sprintf("%s: expected %q or %q, observed %q", c.Key, c.Before, c.After, c.Observed))
	}
	return strings.Join(parts, "; ")
}

// notVisible handles an op this deployment completed (AWS answered) that a
// read does not show: within ConsistencyWindow of its answer it is IAM's
// eventual consistency (retry later, never re-send); after it the state was
// changed by someone else (blocked).
func (x *execRun) notVisible(ctx context.Context, opSeq int, cl igagov.Classification) error {
	var at []struct{ CompletedAt time.Time }
	if err := x.e.db.Raw(`SELECT completed_at FROM iga_gov_attempt
		WHERE workspace_id = ? AND deployment_id = ? AND op_seq = ? AND status = 'completed'
		  AND outcome IN ('ok','recognised_done','not_needed') ORDER BY completed_at DESC LIMIT 1`,
		x.dep.WorkspaceID, x.dep.ID, opSeq).Scan(&at).Error; err != nil {
		return err
	}
	c := cl
	x.out.Last = &c
	detail := fmt.Sprintf("op %d (%s) was completed but a read does not show it", opSeq, x.plan.Ops[opSeq].Op)
	if len(at) == 1 && x.e.now().Sub(at[0].CompletedAt) < x.e.consistencyWindow() {
		x.out.RetryAfter = 15 * time.Second
		return x.stop(DeployRetryLater, DeployReasonAwaitConsistency, detail)
	}
	return x.stop(DeployBlocked, DeployReasonNotVisible, detail)
}

/* ------------------------------ completed ops ------------------------------ */

func (x *execRun) loadCompleted() (map[int]bool, error) {
	var rows []struct{ CompletedOps json.RawMessage }
	if err := x.e.db.Raw(`SELECT completed_ops FROM iga_gov_deployment WHERE workspace_id = ? AND id = ?`,
		x.dep.WorkspaceID, x.dep.ID).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := map[int]bool{}
	if len(rows) == 0 {
		return out, nil
	}
	var entries []struct {
		OpSeq   int    `json:"op_seq"`
		Outcome string `json:"outcome"`
	}
	if err := json.Unmarshal(rows[0].CompletedOps, &entries); err != nil {
		return nil, fmt.Errorf("deployment %s completed_ops: %w", x.dep.ID, err)
	}
	for _, e := range entries {
		if OpDone(e.Outcome) {
			out[e.OpSeq] = true
		}
	}
	return out, nil
}

// appendCompleted records an op done WITHOUT a new attempt (recognised from a
// read, or a selector with nothing to do) in completed_ops, with an event, in
// one fenced transaction. DECISION (T3.10): completed_ops entries are
// {op_seq, operation, attempt_id, outcome} (T3.08); these carry attempt_id
// null -- or the resolved unknown attempt whose effect the read shows -- and
// basis live_read / selector, because no request was sent for them.
func (x *execRun) appendCompleted(ctx context.Context, rec DeployOpRecord) error {
	entry, err := json.Marshal([]map[string]any{{"op_seq": rec.OpSeq, "operation": rec.Operation, "attempt_id": rec.AttemptID,
		"outcome": rec.Outcome, "basis": rec.Basis}})
	if err != nil {
		return err
	}
	event := "deployment.op_recognised"
	if rec.Outcome == AttemptOutcomeNotNeeded {
		event = "deployment.op_not_needed"
	}
	return x.run.InTx(ctx, func(tx *gorm.DB) error {
		if err := tx.Exec(`UPDATE iga_gov_deployment SET completed_ops = completed_ops || ?::jsonb, updated_at = now()
			WHERE workspace_id = ? AND id = ?`, string(entry), x.dep.WorkspaceID, x.dep.ID).Error; err != nil {
			return err
		}
		return x.event(tx, event, map[string]any{"op_seq": rec.OpSeq, "operation": rec.Operation, "outcome": rec.Outcome,
			"basis": rec.Basis, "attempt_id": rec.AttemptID, "reason": rec.Reason})
	})
}

// recognise records every op before k that the read shows done and
// completed_ops lacks as recognised_done (A25: the replacement classifies
// the post-state; the op is not re-sent).
func (x *execRun) recognise(ctx context.Context, k int) error {
	for j := 0; j < k && j < len(x.plan.Ops); j++ {
		if x.completed[j] {
			continue
		}
		rec := DeployOpRecord{OpSeq: j, Operation: x.plan.Ops[j].Op, Outcome: AttemptOutcomeRecognisedDone, Basis: OpBasisLiveRead,
			Reason: "the live read shows the op's effect"}
		if !igagov.OpObservable(x.plan.Ops[j]) {
			rec.Reason = "it precedes, in the op order, an op the live read shows done"
		}
		var ids []struct{ ID uuid.UUID }
		if err := x.e.db.Raw(`SELECT id FROM iga_gov_attempt WHERE workspace_id = ? AND deployment_id = ? AND op_seq = ?
			AND status = 'unknown' AND resolved_as = 'applied' ORDER BY attempt_no DESC LIMIT 1`,
			x.dep.WorkspaceID, x.dep.ID, j).Scan(&ids).Error; err != nil {
			return err
		}
		if len(ids) == 1 {
			id := ids[0].ID
			rec.AttemptID = &id
			rec.Reason = "the unknown attempt was resolved applied and the live read shows its effect"
		}
		if err := x.appendCompleted(ctx, rec); err != nil {
			return err
		}
		x.completed[j] = true
		x.out.Ops = append(x.out.Ops, rec)
	}
	return nil
}

/* ----------------------------------- ops ----------------------------------- */

func (x *execRun) runOp(ctx context.Context, k int) error {
	op := x.plan.Ops[k]
	if f := x.e.FaultBeforeOp; f != nil {
		if err := f(k, op); err != nil {
			return err
		}
	}
	if err := x.markIntended(ctx); err != nil {
		return err
	}
	if err := x.enforcement(ctx); err != nil {
		return err
	}
	if op.Op == igagov.OpDeletePolicyVersion {
		return x.runVersionDeletes(ctx, k)
	}
	req, err := awsenforce.NewRequest(op, x.dep.ID, "")
	if err != nil {
		return x.stop(DeployFailed, DeployReasonOpUnresolvable, err.Error())
	}
	doc := ""
	if req.SendsDocument() {
		var ok bool
		if doc, ok, err = x.document(req.DocumentHash); err != nil {
			return err
		} else if !ok {
			return x.stop(DeployFailed, DeployReasonDocumentMissing, "document "+req.DocumentHash+" is not in iga_gov_document")
		}
	}
	return x.attempt(ctx, k, req, doc, req.DocumentHash)
}

// document returns the canonical text of an archived document.
func (x *execRun) document(hash string) (string, bool, error) {
	var docs []models.IGAGovDocument
	if err := x.e.db.Where("workspace_id = ? AND document_hash = ?", x.dep.WorkspaceID, hash).Limit(1).Find(&docs).Error; err != nil {
		return "", false, err
	}
	if len(docs) == 0 {
		return "", false, nil
	}
	return docs[0].Canonical, true, nil
}

// runVersionDeletes resolves a DeletePolicyVersion selector against a fresh
// discovery read (D46) and deletes each chosen version, each its own attempt
// under the op's op_seq, AFTER its document is confirmed in iga_gov_document
// (§3.2, §8.5: "the adapter refuses otherwise"). Nothing chosen: the op is
// not needed (recorded without an attempt).
//
// DECISION (T3.10): an all_non_default selector that resolves to several
// versions makes one attempt per version under the same op_seq (attempt_no
// increasing, the version in the request and its hash); the op is done when
// a fresh resolution chooses nothing, so a partly done selector is resumed by
// re-resolving, never by trusting completed_ops.
func (x *execRun) runVersionDeletes(ctx context.Context, k int) error {
	op := x.plan.Ops[k]
	var versions []awsenforce.VersionToDelete
	err := x.run.External(ctx, 0, func(ctx context.Context) error {
		var err error
		versions, err = awsenforce.ResolveVersionSelector(ctx, x.disc, op)
		return err
	})
	if err != nil {
		if isLeaseErr(err) {
			return err
		}
		x.out.RetryAfter = 30 * time.Second
		return x.stop(DeployRetryLater, DeployReasonReadFailed, err.Error())
	}
	if len(versions) == 0 {
		rec := DeployOpRecord{OpSeq: k, Operation: op.Op, Outcome: AttemptOutcomeNotNeeded, Basis: OpBasisSelector,
			Reason: fmt.Sprintf("selector %s chose no version", op.Select)}
		if err := x.appendCompleted(ctx, rec); err != nil {
			return err
		}
		x.out.Ops = append(x.out.Ops, rec)
		return nil
	}
	for _, v := range versions {
		hash, err := x.archive(ctx, v.Document)
		if err != nil {
			if isLeaseErr(err) {
				return err
			}
			return x.stop(DeployFailed, DeployReasonVersionUnarchived,
				fmt.Sprintf("%s %s: %v; the version was not deleted", op.PolicyARN, v.VersionID, err))
		}
		req, err := awsenforce.NewRequest(op, x.dep.ID, v.VersionID)
		if err != nil {
			return x.stop(DeployFailed, DeployReasonOpUnresolvable, err.Error())
		}
		if err := x.attempt(ctx, k, req, "", hash); err != nil {
			return err
		}
	}
	return nil
}

// archive inserts a document read from AWS into iga_gov_document (insert-once,
// hash-verified by its trigger) in a fenced transaction and confirms it is
// there; it returns the document's hash.
func (x *execRun) archive(ctx context.Context, text string) (string, error) {
	c, h, err := igagov.CanonicalDocument(text)
	if err != nil {
		return "", err
	}
	err = x.run.InTx(ctx, func(tx *gorm.DB) error {
		return archiveDocumentTx(tx, x.dep.WorkspaceID, string(c), h)
	})
	return h, err
}

func archiveDocumentTx(tx *gorm.DB, ws uuid.UUID, canonical, hash string) error {
	if err := tx.Exec(`INSERT INTO iga_gov_document (workspace_id, document_hash, canonical, document)
		VALUES (?, ?, ?, ?::jsonb) ON CONFLICT (workspace_id, document_hash) DO NOTHING`, ws, hash, canonical, canonical).Error; err != nil {
		return err
	}
	var n int64
	if err := tx.Raw(`SELECT count(*) FROM iga_gov_document WHERE workspace_id = ? AND document_hash = ?`, ws, hash).Scan(&n).Error; err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("document %s is not archived", hash)
	}
	return nil
}

// answerNote carries ClassifyOpResponse's reason out of the call goroutine.
type answerNote struct {
	mu     sync.Mutex
	reason string
}

func (n *answerNote) set(r string) { n.mu.Lock(); n.reason = r; n.mu.Unlock() }
func (n *answerNote) get() string  { n.mu.Lock(); defer n.mu.Unlock(); return n.reason }

// attempt sends one request inside the write-ahead attempt lifecycle and
// turns its result into the run's next step.
func (x *execRun) attempt(ctx context.Context, k int, req awsenforce.Request, doc, docHash string) error {
	var retryable int64
	if err := x.e.db.Raw(`SELECT count(*) FROM iga_gov_attempt WHERE workspace_id = ? AND deployment_id = ? AND op_seq = ?
		AND outcome = 'retryable'`, x.dep.WorkspaceID, x.dep.ID, k).Scan(&retryable).Error; err != nil {
		return err
	}
	if int(retryable) >= x.e.maxOpAttempts() {
		return x.stop(DeployFailed, DeployReasonRetriesExhausted,
			fmt.Sprintf("op %d (%s) was refused as retryable %d times", k, req.Op, retryable))
	}
	reqHash, err := req.Hash()
	if err != nil {
		return err
	}
	note := &answerNote{}
	call := func(cctx context.Context) (AttemptAnswer, error) {
		resp := awsenforce.Send(cctx, x.iam, req, doc)
		if resp.Kind == igagov.RespNoAnswer {
			return AttemptAnswer{}, fmt.Errorf("no answer from AWS: %v", resp.Err)
		}
		var live igagov.LiveRead
		if resp.Kind == igagov.RespError {
			// The recognition column of §8.5 needs the state after the
			// answer. DECISION (T3.10): this read is part of the call (its
			// timeout bounds it) and is not separately fenced: it only
			// classifies the answer, which Complete then records under the
			// fence. A failed read classifies with no state (never
			// recognised, never retried on that basis).
			if l, _, err := awsenforce.ReadForPlan(cctx, x.disc, x.role, x.plan, x.e.now()); err == nil {
				live = l
			}
		}
		oc := igagov.ClassifyOpResponse(x.plan, k, resp.Kind, resp.ErrorCode, live)
		if oc.Outcome == igagov.OutcomeUnknown {
			return AttemptAnswer{}, fmt.Errorf("%s (%s): AWS may have applied the request", oc.Reason, resp.ErrorCode)
		}
		note.set(oc.Reason)
		msg := resp.Message
		if oc.Reason != "" && oc.Reason != resp.ErrorCode {
			msg = oc.Reason + ": " + msg
		}
		return AttemptAnswer{Outcome: oc.Outcome, RequestID: resp.RequestID, ErrorCode: resp.ErrorCode, ErrorMessage: msg}, nil
	}
	var pre func(ctx context.Context) error
	if chk := x.e.BindingCheck; chk != nil {
		pre = func(ctx context.Context) error { return chk(ctx, x.dep.WorkspaceID, x.ctl.ConnectorID) }
	}
	res, err := x.e.attempts.ExecuteChecked(ctx, x.run, AttemptRequest{WorkspaceID: x.dep.WorkspaceID, DeploymentID: x.dep.ID,
		OpSeq: k, Operation: req.Op, RequestHash: reqHash, DocumentHash: docHash}, pre, call)
	if err != nil {
		if errors.Is(err, ErrDispatchRefused) {
			return x.bindingStop(err, k, req.Op)
		}
		return err
	}
	attID := res.Attempt.ID
	rec := DeployOpRecord{OpSeq: k, Operation: req.Op, VersionID: req.VersionID, Basis: OpBasisAttempt, AttemptID: &attID,
		AttemptNo: res.Attempt.AttemptNo, Request: reqHash}
	if res.Unknown {
		rec.Outcome = igagov.OutcomeUnknown
		if res.CallErr != nil {
			rec.Reason = res.CallErr.Error()
		}
		x.out.Ops = append(x.out.Ops, rec)
		a := res.Attempt
		x.out.Attempt, x.out.SettleAfter = &a, res.SettleAfter
		return x.stop(DeployOutcomeUnknown, DeployReasonNoAnswer, fmt.Sprintf("op %d (%s): %s", k, req.Op, rec.Reason))
	}
	ans := res.Answer
	rec.Outcome, rec.RequestID, rec.ErrorCode, rec.Reason = ans.Outcome, ans.RequestID, ans.ErrorCode, note.get()
	x.out.Ops = append(x.out.Ops, rec)
	switch ans.Outcome {
	case AttemptOutcomeOK, AttemptOutcomeRecognisedDone, AttemptOutcomeNotNeeded:
		return nil
	case AttemptOutcomeRetryable:
		x.out.RetryAfter = x.e.backoff(int(retryable) + 1)
		return x.stop(DeployRetryLater, DeployReasonThrottled, fmt.Sprintf("op %d (%s): %s", k, req.Op, ans.ErrorCode))
	default:
		reason := rec.Reason
		if reason == "" {
			reason = ans.ErrorCode
		}
		detail := fmt.Sprintf("op %d (%s): %s %s", k, req.Op, ans.ErrorCode, ans.ErrorMessage)
		if strings.HasPrefix(reason, "blocked") {
			return x.stop(DeployBlocked, reason, detail)
		}
		return x.stop(DeployFailed, reason, detail)
	}
}

// bindingStop ends the run when the binding check refused op k's dispatch.
// DECISION (review P1-8): the run stops as blocked with the binding's code
// (binding_not_verified -- revoked included, the detail names the state --,
// binding_partial, enforcement_not_enabled), exactly as the start gate
// blocks a deployment whose binding is not usable; the stopped deployment
// releases the role with its ledger settled. A refusal that is not a
// binding verdict (a database error) is returned: the job retries and the
// next run re-checks before anything is sent.
func (x *execRun) bindingStop(err error, k int, op string) error {
	var ge *GovError
	var ee *EnforcementError
	code, msg := "", ""
	switch {
	case errors.As(err, &ge):
		code, msg = ge.Code, ge.Message
		if st, ok := ge.Detail["state"]; ok {
			msg = fmt.Sprintf("%s (binding %v)", msg, st)
		}
	case errors.As(err, &ee):
		code, msg = ee.Code, ee.Message
		if st, ok := ee.Detail["state"]; ok {
			msg = fmt.Sprintf("%s (binding %v)", msg, st)
		}
	default:
		return err
	}
	return x.stop(DeployBlocked, code, fmt.Sprintf("op %d (%s) was not sent: %s", k, op, msg))
}

// backoff is the jittered exponential delay after the n-th retryable answer.
func (e *IGAGovAWSExecutor) backoff(n int) time.Duration {
	d := e.retryBase()
	for i := 1; i < n && d < 5*time.Minute; i++ {
		d *= 2
	}
	if d > 5*time.Minute {
		d = 5 * time.Minute
	}
	j := 0.8 + 0.4*rand.Float64()
	return time.Duration(float64(d) * j)
}

/* --------------------------------- ledger ---------------------------------- */

// Artifact ledger kinds and states (051 iga_gov_artifact).
const (
	ArtifactBoundaryPolicy     = "boundary_policy"
	ArtifactBoundaryAttachment = "boundary_attachment"
	ArtifactIntended           = "intended"
	ArtifactPresent            = "present"
	ArtifactRemoved            = "removed"
	ArtifactReleased           = "released"
	ArtifactOwnedDirect        = "authsec_direct"
	ArtifactOwnedCustomerIaC   = "customer_iac"
)

func ownedBy(policyARN string) string {
	if strings.Contains(policyARN, ":policy"+igagov.AuthSecPolicyPath) {
		return ArtifactOwnedDirect
	}
	return ArtifactOwnedCustomerIaC
}

type ledgerRow struct {
	ID        uuid.UUID
	NativeARN string
	State     string
}

func liveLedgerRow(tx *gorm.DB, ws, control uuid.UUID, kind string) (*ledgerRow, error) {
	var rows []ledgerRow
	if err := tx.Raw(`SELECT id, native_arn, state FROM iga_gov_artifact
		WHERE workspace_id = ? AND control_id = ? AND kind = ? AND state IN ('intended','present','drifted')
		FOR UPDATE`, ws, control, kind).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

// markIntended writes, once per run and before the first op, an `intended`
// ledger row for every artifact this plan creates that the ledger does not
// yet record (§8.5: "written intended before its first op").
//
// DECISION (T3.10): only NEW artifacts get an intended row. An artifact the
// ledger already records (`present`) keeps its row unchanged until readback,
// so a crash leaves either an intended row or the previous consistent one.
// When the control's live boundary_policy row names ANOTHER policy (a
// role-only recovery installing a -u policy while the shared one is still
// `present`), the new row is written at readback in the same transaction
// that releases the shared one, because uq_iga_gov_artifact_live allows one
// live row per (control, kind).
func (x *execRun) markIntended(ctx context.Context) error {
	if x.intended {
		return nil
	}
	p := x.plan
	if p.DesiredAttachment != igagov.AttachmentPresent || p.DesiredBoundaryARN == nil || p.DesiredDocumentHash == nil {
		x.intended = true
		return nil
	}
	err := x.run.InTx(ctx, func(tx *gorm.DB) error {
		ws := x.dep.WorkspaceID
		var written []string
		pol, err := liveLedgerRow(tx, ws, x.ctl.ID, ArtifactBoundaryPolicy)
		if err != nil {
			return err
		}
		if pol == nil {
			if err := x.insertArtifact(tx, ArtifactBoundaryPolicy, *p.DesiredBoundaryARN, ArtifactIntended, p.DesiredDocumentHash, ""); err != nil {
				return err
			}
			written = append(written, ArtifactBoundaryPolicy)
		}
		att, err := liveLedgerRow(tx, ws, x.ctl.ID, ArtifactBoundaryAttachment)
		if err != nil {
			return err
		}
		if att == nil {
			if err := x.insertArtifact(tx, ArtifactBoundaryAttachment, x.ctl.RoleARN, ArtifactIntended, p.DesiredDocumentHash, ""); err != nil {
				return err
			}
			written = append(written, ArtifactBoundaryAttachment)
		}
		if len(written) == 0 {
			return nil
		}
		return x.event(tx, "deployment.ledger_intended", map[string]any{"kinds": written, "boundary_arn": *p.DesiredBoundaryARN})
	})
	if err == nil {
		x.intended = true
	}
	return err
}

func (x *execRun) insertArtifact(tx *gorm.DB, kind, arn, state string, docHash *string, version string) error {
	owner := ownedBy(arn)
	if kind == ArtifactBoundaryAttachment && x.plan.DesiredBoundaryARN != nil {
		owner = ownedBy(*x.plan.DesiredBoundaryARN)
	}
	row := models.IGAGovArtifact{ID: uuid.New(), WorkspaceID: x.dep.WorkspaceID, ControlID: x.ctl.ID, Kind: kind, NativeARN: arn,
		OwnedBy: owner, State: state, DocumentHash: docHash, AWSVersionID: version, LastDeploymentID: x.dep.ID, UpdatedAt: x.e.now()}
	return tx.Create(&row).Error
}

/* -------------------------------- readback --------------------------------- */

// readback is §8.5 "after the last op": two discovery reads, each classified
// against the plan; both must be `after` with the same artifact_state. A
// conflict on either is blocked with the diff; a known intermediate state
// (IAM not yet consistent) is retried for ReadbackRounds pairs, then
// reported not settled (retry later; the ops are never re-sent).
func (x *execRun) readback(ctx context.Context) error {
	var last []igagov.Classification
	for round := 0; round < x.e.readbackRounds(); round++ {
		if round > 0 {
			if err := x.e.sleep(ctx, x.e.readbackGap()); err != nil {
				return err
			}
		}
		live1, _, err := x.read(ctx)
		if err != nil {
			return err
		}
		c1, err := igagov.Classify(x.plan, live1)
		if err != nil {
			return err
		}
		if err := x.e.sleep(ctx, x.e.readbackGap()); err != nil {
			return err
		}
		live2, detail2, err := x.read(ctx)
		if err != nil {
			return err
		}
		c2, err := igagov.Classify(x.plan, live2)
		if err != nil {
			return err
		}
		last = []igagov.Classification{c1, c2}
		for _, c := range last {
			if c.Class == igagov.ClassConflict {
				cc := c
				x.out.Last = &cc
				x.out.Readback = &DeployReadback{Reads: last, ReadAt: live2.ReadAt}
				return x.stop(DeployBlocked, c.Reason, "readback: "+conflictDetail(c))
			}
		}
		if c1.Class != igagov.ClassAfter || c2.Class != igagov.ClassAfter {
			continue
		}
		st1, err := igagov.ArtifactState(live1)
		if err != nil {
			return err
		}
		st2, err := igagov.ArtifactState(live2)
		if err != nil {
			return err
		}
		h1, err := igagov.StatePreconditionHash(st1)
		if err != nil {
			return err
		}
		h2, err := igagov.StatePreconditionHash(st2)
		if err != nil {
			return err
		}
		if h1 != h2 {
			continue
		}
		rb := &DeployReadback{Reads: last, State: st2, StateHash: h2, BoundaryDocumentHash: st2.BoundaryDocumentHash, ReadAt: live2.ReadAt}
		if err := x.writeLedger(ctx, live2, detail2, rb); err != nil {
			return err
		}
		x.out.Readback = rb
		x.out.Result = DeployApplied
		return nil
	}
	x.out.Readback = &DeployReadback{Reads: last}
	x.out.RetryAfter = 30 * time.Second
	return x.stop(DeployRetryLater, DeployReasonReadbackNotSettled, "the readback did not show the plan's after state on two consecutive reads")
}

// writeLedger is §8.5's "Ledger after readback", in one fenced transaction:
// the boundary document in force archived, then the artifact rows by the
// plan's attachment and disposition:
//
//	present + keep           desired boundary_policy present; boundary_attachment present
//	present + delete         replaced policy removed; desired present (owner by path); attachment present
//	present + retain_shared  replaced (shared) policy released; the new policy present; attachment present
//	absent  + delete         replaced policy removed; attachment removed
//	absent  + retain_shared  replaced policy released; attachment removed
//
// Every row it touches gets last_readback_at / last_readback_hash (the
// artifact_state hash, igagov.StatePreconditionHash) and last_deployment_id.
func (x *execRun) writeLedger(ctx context.Context, live igagov.LiveRead, detail awsenforce.ReadDetail, rb *DeployReadback) error {
	p := x.plan
	return x.run.InTx(ctx, func(tx *gorm.DB) error {
		ws := x.dep.WorkspaceID
		now := x.e.now()
		if arn := rb.State.BoundaryARN; arn != nil {
			if pol := live.Policies[*arn]; pol != nil {
				c, h, err := igagov.CanonicalDocument(pol.DefaultDocument)
				if err != nil {
					return err
				}
				if err := archiveDocumentTx(tx, ws, string(c), h); err != nil {
					return err
				}
			}
		}
		set := func(kind, arn, to string, doc *string, version string) error {
			row, err := liveLedgerRow(tx, ws, x.ctl.ID, kind)
			if err != nil {
				return err
			}
			change := DeployLedgerChange{Kind: kind, NativeARN: arn, To: to}
			if row != nil && row.NativeARN != arn {
				if to == ArtifactRemoved || to == ArtifactReleased {
					// The ledger's live row is another artifact: leave it.
					rb.Ledger = append(rb.Ledger, DeployLedgerChange{Kind: kind, NativeARN: arn, From: "none", To: "none (not in the ledger)"})
					return nil
				}
				// A live row for another policy the plan did not name: it is
				// no longer this control's artifact.
				if err := tx.Exec(`UPDATE iga_gov_artifact SET state = 'released', last_readback_at = ?, last_readback_hash = ?,
					last_deployment_id = ?, updated_at = ? WHERE id = ?`, now, rb.StateHash, x.dep.ID, now, row.ID).Error; err != nil {
					return err
				}
				rb.Ledger = append(rb.Ledger, DeployLedgerChange{Kind: kind, NativeARN: row.NativeARN, From: row.State, To: ArtifactReleased})
				row = nil
			}
			switch {
			case row != nil:
				change.From = row.State
				q := `UPDATE iga_gov_artifact SET state = ?, last_readback_at = ?, last_readback_hash = ?, last_deployment_id = ?, updated_at = ?`
				args := []any{to, now, rb.StateHash, x.dep.ID, now}
				if to == ArtifactPresent {
					q += `, document_hash = ?, aws_version_id = ?, owned_by = ?`
					owner := ownedBy(arn)
					if kind == ArtifactBoundaryAttachment && p.DesiredBoundaryARN != nil {
						owner = ownedBy(*p.DesiredBoundaryARN)
					}
					args = append(args, doc, version, owner)
				}
				q += ` WHERE id = ?`
				args = append(args, row.ID)
				if err := tx.Exec(q, args...).Error; err != nil {
					return err
				}
			case to == ArtifactPresent:
				change.From = "none"
				r := models.IGAGovArtifact{ID: uuid.New(), WorkspaceID: ws, ControlID: x.ctl.ID, Kind: kind, NativeARN: arn,
					OwnedBy: ownedBy(arn), State: to, DocumentHash: doc, AWSVersionID: version, LastReadbackAt: &now,
					LastReadbackHash: rb.StateHash, LastDeploymentID: x.dep.ID, UpdatedAt: now}
				if kind == ArtifactBoundaryAttachment && p.DesiredBoundaryARN != nil {
					r.OwnedBy = ownedBy(*p.DesiredBoundaryARN)
				}
				if err := tx.Create(&r).Error; err != nil {
					return err
				}
			default:
				change.From, change.To = "none", "none (not in the ledger)"
			}
			rb.Ledger = append(rb.Ledger, change)
			return nil
		}
		disposed := func() error {
			if p.ReplacedBoundaryARN == nil || p.ArtifactDisposition == igagov.DispositionKeep {
				return nil
			}
			to := ArtifactRemoved
			if p.ArtifactDisposition == igagov.DispositionRetainShared {
				to = ArtifactReleased
			}
			return set(ArtifactBoundaryPolicy, *p.ReplacedBoundaryARN, to, nil, "")
		}
		if err := disposed(); err != nil {
			return err
		}
		switch p.DesiredAttachment {
		case igagov.AttachmentPresent:
			arn := *p.DesiredBoundaryARN
			doc := rb.State.BoundaryDocumentHash
			if err := set(ArtifactBoundaryPolicy, arn, ArtifactPresent, doc, detail.DefaultVersion[arn]); err != nil {
				return err
			}
			if err := set(ArtifactBoundaryAttachment, x.ctl.RoleARN, ArtifactPresent, doc, ""); err != nil {
				return err
			}
		case igagov.AttachmentAbsent:
			if err := set(ArtifactBoundaryAttachment, x.ctl.RoleARN, ArtifactRemoved, nil, ""); err != nil {
				return err
			}
		}
		return x.event(tx, "deployment.readback", map[string]any{"plan_kind": p.Kind, "state_hash": rb.StateHash,
			"boundary_arn": rb.State.BoundaryARN, "boundary_document_hash": rb.State.BoundaryDocumentHash, "ledger": rb.Ledger})
	})
}

func (x *execRun) event(tx *gorm.DB, name string, payload map[string]any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	dep := x.dep.ID
	return x.e.events.AppendTx(tx, &models.IGAGovEvent{WorkspaceID: x.dep.WorkspaceID, Event: name, ActorKind: models.GovActorSystem,
		ActorID: "policy-worker", DeploymentID: &dep, VersionID: &x.dep.VersionID, Payload: raw})
}

/* ------------------------------ unknown outcome ----------------------------- */

// UnknownReading is one discovery read classified for a deployment's
// unresolved unknown attempt (§8.1 step 2).
type UnknownReading struct {
	Attempt    models.IGAGovAttempt `json:"attempt"`
	Resolution igagov.OpResolution  `json:"resolution"`
	ReadAt     time.Time            `json:"read_at"`
}

// ClassifyUnknown reads live state once and classifies the deployment's open
// unknown attempt with igagov.ResolveUnknownOp: applied (the state after the
// op), not_applied (the state before it), unobservable_idempotent (TagPolicy,
// a version delete: a read cannot tell; CloudTrail decides) or conflict. It
// writes nothing. T3.16's resolve_unknown job takes two such readings 5
// minutes apart after settle_after, checks the enforcement session's
// CloudTrail events, and then calls IGAGovAttemptLog.ResolveUnknown.
func (e *IGAGovAWSExecutor) ClassifyUnknown(ctx context.Context, run *PolicyJobRun, dep models.IGAGovDeployment, plan igagov.Plan) (*UnknownReading, error) {
	att, err := e.attempts.OpenAttempt(e.db, dep.WorkspaceID, dep.ID)
	if err != nil {
		return nil, err
	}
	if att == nil || att.Status != models.GovAttemptUnknown {
		return nil, fmt.Errorf("%w: deployment %s has no unresolved unknown attempt", ErrAttemptState, dep.ID)
	}
	var ctl models.IGAGovControl
	if err := e.db.Where("workspace_id = ? AND id = ?", dep.WorkspaceID, dep.ControlID).First(&ctl).Error; err != nil {
		return nil, err
	}
	x := &execRun{e: e, run: run, dep: dep, plan: plan, ctl: ctl, role: roleNameOfARN(ctl.RoleARN), out: &DeployOutcome{}}
	if err := x.discovery(ctx); err != nil {
		if errors.Is(err, errStop) {
			return nil, fmt.Errorf("%s: %s", x.out.Reason, x.out.Detail)
		}
		return nil, err
	}
	live, _, err := x.read(ctx)
	if err != nil {
		if errors.Is(err, errStop) {
			return nil, fmt.Errorf("%s: %s", x.out.Reason, x.out.Detail)
		}
		return nil, err
	}
	res, err := igagov.ResolveUnknownOp(plan, att.OpSeq, live)
	if err != nil {
		return nil, err
	}
	return &UnknownReading{Attempt: *att, Resolution: res, ReadAt: live.ReadAt}, nil
}
