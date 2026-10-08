package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// Rollout (SPEC-iga-phase3-policy.md §2.6 fresh-report rule, §5 stages 8,
// 10, 12, 13, §7.5 rollout routes, §8.6 observation and canary; T3.15;
// L-12; scenarios A6, A10, A16/A49, A18, A24, A28, A62).
//
// One iga_gov_rollout per version (051 UNIQUE version_id):
//
//	start (in review or approved, owner gate passes)        -> observe
//	observe_tick: a removed service attempted after the
//	  version's evidence report                              -> paused (version back to draft)
//	observe_tick: observe_until passed AND every target has
//	  a report generated >= observe_until + 4 h              -> awaiting_approval
//	start (approved, observed)                               -> canary (one deployment, the canary target)
//	gates (observe_tick on each publication + every 10 min):
//	  a gate failed                                          -> paused, Undo canary offered
//	  every gate passed (or not_available AND accepted)      -> single target: complete
//	                                                            several: expand (one deployment per other target)
//	POST rollout/expand (accept_not_available)               -> the same, with gate_not_available acceptances
//	expand: every deployment terminal                        -> complete (all verified) | partial
//	pause / resume                                            -> paused <-> the stage it was paused from
//	the applied canary undone (T3.16)                        -> undone
//
// THE BOUNDARY WITH T3.16: this file creates deployment rows (state
// queued -- 051's name for "pending" -- linked to the rollout's version, the
// approved plan, the approval and the unchanged revalidation UsableApproval
// returned) and enqueues one `deploy` job per deployment (dedupe
// deployment:<id>). Everything from the deploy job on (executor, states,
// verification, drift, undo) is T3.16's. The gates read deployment facts
// through RolloutDeploymentFacts, which T3.16 implements; until it is wired
// the built-in GovRowDeploymentFacts reads the rows and has no CloudTrail,
// so every canary's trail-based gates read not_available and nothing
// expands without an approver's acceptance (fail closed).
//
// DECISIONS (T3.15):
//   - R1: gate_results is a structured document (051 leaves its shape open):
//     {observation, canary, pause: {from, kind, reason, at}, undo_offered:
//     [{deployment_id, path}], expansion: {deployments, refused}}. The stage a
//     paused rollout resumes to is pause.from (051 has no column for it).
//   - R2: "sends the version back to draft" (§8.6) is: version status draft,
//     its live approval revoked, its open owner review cancelled; the rollout
//     is kept, paused with pause.kind returned_to_draft and the attempt named
//     ("sqs was attempted during observation on <date>"). Resume refuses it;
//     start on the re-proposed version restarts observation on the same row.
//   - R3: observation starts from a version in review or approved, after the
//     owner gate (CheckGate) passes; enforcement_mode findings_only refuses a
//     direct or iac_pr delivery already there (enforcement_not_enabled), the
//     binding is checked only where deployments are created (canary, expand).
//     The canary starts only from awaiting_approval (observed) with the
//     version approved; an approved version is still observed first.
//   - R4: the evidence report a removal was proposed from is the newest
//     report_generated_at of the role's collected evidence at the version's
//     evidence_rev (the version's created_at when none). An observe_tick
//     whose rev is older than the last one recorded is a no-op.
//   - R5: canary choice. The canary is the target flagged is_canary (the
//     intent's rollout.canary_target); with none flagged a single target is
//     its own canary and several are 409 canary_not_chosen. A shared role
//     needs every consumer's owner acknowledgement (T3.12
//     CanaryAcknowledgement; an exception does not count): 409
//     canary_not_acknowledged. With two or more targets, a role whose
//     identity grants include AdministratorAccess or an Allow of "*",
//     "iam:*" or "organizations:*" (the plan bundle's grants, read from
//     iga_statement_revision by content hash) is 409 canary_admin_role; a
//     single target is the whole rollout, so the rule does not apply.
//   - R6: expansion is automatic when every gate passes; a not_available
//     gate needs POST rollout/expand with accept_not_available, by a member
//     who holds governance:approve and is not the version's author (§8.6
//     "the approver may accept"). Each acceptance is a gate_not_available
//     row bound to the rollout, stage canary and the canary window
//     [applied_at, applied_at + canary_hours]; item_hash is the sha256 of
//     the gate result accepted. An accepted gate that later FAILS still
//     pauses.
//   - R7: a deployment refused at creation (UsableApproval 409, binding,
//     enforcement mode, a deployment in flight on the role) is recorded in
//     gate_results.expansion.refused and counts as a failed target: the
//     rollout ends partial (E-05). The expand route answers 409 only when no
//     deployment could be created at all (the first refusal: e.g.
//     material_change with its changes).
//   - R8: when an approved plan's evidence is stale, UsableApproval's
//     revalidation_required makes the rollout call Revalidate once and ask
//     again; a material change is 409 material_change with the changes.
//   - R9: pausing stops the rollout from evaluating and creating
//     deployments, and holds its queued apply deployments: the deploy job
//     consults RolloutPausedForDeployment and leaves them queued (retry
//     later) while paused; resume brings their deploy jobs forward. A
//     deployment already applying finishes. Resume after a gate failure goes
//     back to canary; a gate that still fails pauses again at the next tick.
//   - R10: the canary window starts at the canary deployment's applied_at;
//     canary_hours is GovCanaryHours (the intent's rollout.canary_hours, else
//     the settings'), the same function the verify job's window uses.
//   - R13 (review P1-9): the automatic tick and the manual expand apply one
//     canary-health rule (canaryHealthy), and both read the gates inside the
//     transaction that acts on them, with the canary deployment and its
//     verification rows locked FOR SHARE. A single-target rollout completes
//     only once its deployment is verified (§8.4: complete means the change
//     is proven); with its gates passed it waits in canary.
//   - R14 (review P3): a gate_not_available acceptance is bound to the
//     rollout AND its version (057's FK) and is unique per (rollout, gate,
//     window); the gates match acceptances by gate and by the whole window
//     [window_start, window_end].

// Rollout error codes.
const (
	GovCodeObservationIncomplete = "observation_incomplete"
	GovCodeGatesNotPassed        = "gates_not_passed"
	// GovCodeDeploymentInFlight ("deployment_in_flight") is T3.16's
	// (iga_gov_deploy_routes.go); the rollout uses the same code.
	GovCodeEnforcementNotEnabled = "enforcement_not_enabled"
	GovCodeCanaryNotAcknowledged = "canary_not_acknowledged"
	GovCodeCanaryAdminRole       = "canary_admin_role"
	GovCodeCanaryNotChosen       = "canary_not_chosen"
	GovCodeRolloutPaused         = "rollout_paused"
	GovCodeRolloutNotStarted     = "rollout_not_started"
	GovCodeRolloutConflict       = "rollout_conflict"
	GovCodePolicyPaused          = "policy_paused"
)

// Rollout events (T3.15).
const (
	GovEventRolloutObservationStarted   = "rollout.observation_started"
	GovEventRolloutObservationChecked   = "rollout.observation_checked"
	GovEventRolloutObservationCompleted = "rollout.observation_completed"
	GovEventRolloutReturnedToDraft      = "rollout.returned_to_draft"
	GovEventRolloutCanaryStarted        = "rollout.canary_started"
	GovEventRolloutDeploymentCreated    = "rollout.deployment_created"
	GovEventRolloutDeploymentRefused    = "rollout.deployment_refused"
	GovEventRolloutGatesEvaluated       = "rollout.gates_evaluated"
	GovEventRolloutGateAccepted         = "rollout.gate_accepted"
	GovEventRolloutPaused               = "rollout.paused"
	GovEventRolloutResumed              = "rollout.resumed"
	GovEventRolloutExpanded             = "rollout.expanded"
	GovEventRolloutCompleted            = "rollout.completed"
	GovEventRolloutPartial              = "rollout.partial"
	GovEventRolloutUndone               = "rollout.undone"
	GovEventRolloutRefreshQueued        = "rollout.activity_refresh_queued"
	GovEventRolloutRemoveControlStarted = "rollout.remove_control_started"
)

// Pause kinds (gate_results.pause.kind).
const (
	GovPauseManual           = "manual"
	GovPauseGateFailed       = "gate_failed"
	GovPauseDeploymentFailed = "deployment_failed"
	GovPauseDrifted          = "drifted"
	GovPauseReturnedToDraft  = "returned_to_draft"
)

// RolloutPeriodicTick is how often a rollout in canary, expand or paused is
// re-evaluated without a publication (deployment states move between them).
const RolloutPeriodicTick = 10 * time.Minute

/* ------------------------------------------------------------------------- */
/*                    Deployment facts (the T3.16 contract)                   */
/* ------------------------------------------------------------------------- */

// RolloutDeploymentGateFacts is what the rollout needs to know about one
// deployment to decide its gates (§8.6) and whether it is finished.
type RolloutDeploymentGateFacts struct {
	DeploymentID uuid.UUID `json:"deployment_id"`
	// State and StateReason are iga_gov_deployment.state / state_reason.
	State       string `json:"state"`
	StateReason string `json:"state_reason"`
	// AppliedAt is when the change took effect (nil: not applied).
	AppliedAt *time.Time `json:"applied_at,omitempty"`
	// Dimensions is §8.7's verification result per dimension (artifact,
	// graph, application_health, restriction); a missing key is not yet
	// assessed.
	Dimensions map[string]igagov.DimensionResult `json:"dimensions"`
	// Gates are the five §8.6 gates as T3.16's last verify run computed
	// them (empty until a verify job ran). When present they are
	// authoritative, with UnexpectedFailures from the same run.
	Gates              []igagov.GateResult        `json:"gates"`
	UnexpectedFailures []igagov.UnexpectedFailure `json:"unexpected_failures"`
	// Canary is raw evidence for the window from AppliedAt, used only when
	// Gates is empty (the built-in GovRowDeploymentFacts): RoleID,
	// AppliedAt, RemovesServices, Removed, Retained, Events (CloudTrail
	// management events of the role's sessions, T3.04 attribution),
	// Validations (declared, with items), Reports (owner health reports),
	// Trail (the CloudTrail reads covering the window, CapHit when the
	// 10,000-event cap stopped one), PublishedAfterApply and
	// ArtifactOutcome. Now and CanaryHours are set by the rollout and the
	// gates are igagov.EvaluateCanary(*Canary). With neither, the gates
	// read awaiting evidence and nothing advances.
	Canary *igagov.CanaryInput `json:"-"`
}

// RolloutDeploymentFacts is the narrow seam T3.16 implements
// (DeploymentGateFacts) and the integration merge wires with
// SetGovRolloutDeploymentFacts. A deployment of another workspace is
// GovNotFound. db is the handle to read through: the rollout passes the
// transaction it acts in, so the gates it decides on are the ones it read
// under its locks (no read-then-act gap); nil reads through the
// implementation's own handle.
type RolloutDeploymentFacts interface {
	DeploymentGateFacts(ctx context.Context, db *gorm.DB, ws, deploymentID uuid.UUID) (*RolloutDeploymentGateFacts, error)
}

var (
	govRolloutFactsMu sync.RWMutex
	govRolloutFacts   RolloutDeploymentFacts
)

// SetGovRolloutDeploymentFacts installs the process-wide deployment facts
// (T3.16's implementation, at startup) and returns a restore function. nil
// restores the built-in GovRowDeploymentFacts.
func SetGovRolloutDeploymentFacts(f RolloutDeploymentFacts) (restore func()) {
	govRolloutFactsMu.Lock()
	prev := govRolloutFacts
	govRolloutFacts = f
	govRolloutFactsMu.Unlock()
	return func() {
		govRolloutFactsMu.Lock()
		govRolloutFacts = prev
		govRolloutFactsMu.Unlock()
	}
}

func currentGovRolloutFacts(db *gorm.DB) RolloutDeploymentFacts {
	govRolloutFactsMu.RLock()
	defer govRolloutFactsMu.RUnlock()
	if govRolloutFacts != nil {
		return govRolloutFacts
	}
	return &GovRowDeploymentFacts{DB: db}
}

// GovRowDeploymentFacts reads a deployment's facts from the rows 051 holds:
// the deployment, its verification dimensions, owner health reports and
// declared validations with their items; the removed and retained services
// from the version's intent; a publication after applied_at. CloudTrail
// events and reads come from Trail (nil: none, so the trail-based gates are
// not_available). It is the default until T3.16's facts are wired, and the
// fake the tests drive (Trail injected).
type GovRowDeploymentFacts struct {
	DB    *gorm.DB
	Trail func(ws, deploymentID uuid.UUID) ([]igagov.TrailEvent, []igagov.TrailRead)
}

// DeploymentGateFacts implements RolloutDeploymentFacts.
func (f *GovRowDeploymentFacts) DeploymentGateFacts(ctx context.Context, h *gorm.DB, ws, deploymentID uuid.UUID) (*RolloutDeploymentGateFacts, error) {
	if h == nil {
		h = f.DB
	}
	db := h.WithContext(ctx)
	var d models.IGAGovDeployment
	if err := db.Where("workspace_id = ? AND id = ?", ws, deploymentID).Take(&d).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, GovNotFound()
		}
		return nil, err
	}
	out := &RolloutDeploymentGateFacts{DeploymentID: d.ID, State: d.State, StateReason: d.StateReason,
		AppliedAt: d.AppliedAt, Dimensions: map[string]igagov.DimensionResult{}}
	var vs []models.IGAGovVerification
	if err := db.Where("workspace_id = ? AND deployment_id = ?", ws, d.ID).Find(&vs).Error; err != nil {
		return nil, err
	}
	for _, v := range vs {
		out.Dimensions[v.Dimension] = igagov.DimensionResult{Outcome: v.Outcome, Attribution: v.Attribution}
	}
	var c models.IGAGovControl
	if err := db.Where("workspace_id = ? AND id = ?", ws, d.ControlID).Take(&c).Error; err != nil {
		return nil, err
	}
	var v models.IGAGovPolicyVersion
	if err := db.Where("workspace_id = ? AND id = ?", ws, d.VersionID).Take(&v).Error; err != nil {
		return nil, err
	}
	var p models.IGAGovPlan
	if err := db.Where("workspace_id = ? AND id = ?", ws, d.PlanID).Take(&p).Error; err != nil {
		return nil, err
	}
	in := igagov.CanaryInput{RoleID: c.RoleID, ArtifactOutcome: out.Dimensions["artifact"].Outcome}
	if d.AppliedAt != nil {
		in.AppliedAt = d.AppliedAt.UTC()
	}
	if intent, err := storedRightSize(v); err == nil {
		for _, r := range intent.Remove {
			in.Removed = append(in.Removed, r.Service)
		}
		for _, r := range intent.Retain {
			// DECISION R11: a retained service "with activity in the qualified
			// interval" is one retained on observed activity; whether its
			// calls are data events only is the catalog's (T3.16 fills it).
			in.Retained = append(in.Retained, igagov.RetainedService{Service: r.Service,
				ActiveInQualifiedInterval: r.Basis == igagov.RetainObserved})
		}
	}
	in.RemovesServices = p.DesiredAttachment == "present" && len(in.Removed) > 0
	var reports []models.IGAGovHealthReport
	if err := db.Where("workspace_id = ? AND deployment_id = ?", ws, d.ID).Find(&reports).Error; err != nil {
		return nil, err
	}
	for _, r := range reports {
		in.Reports = append(in.Reports, igagov.HealthReport{Kind: r.Kind, Service: r.Service, CreatedAt: r.CreatedAt})
	}
	var vals []models.IGAGovValidation
	if err := db.Where("workspace_id = ? AND deployment_id = ?", ws, d.ID).Order("created_at, id").Find(&vals).Error; err != nil {
		return nil, err
	}
	for _, val := range vals {
		var items []models.IGAGovValidationItem
		if err := db.Where("workspace_id = ? AND validation_id = ?", ws, val.ID).Order("action").Find(&items).Error; err != nil {
			return nil, err
		}
		gv := igagov.Validation{ID: val.ID.String(), RoleID: val.RoleID, SessionName: val.SessionName,
			WindowStart: val.WindowStart, WindowEnd: val.WindowEnd}
		for _, it := range items {
			gv.Items = append(gv.Items, igagov.ValidationItem{Action: it.Action, Expected: it.Expected})
		}
		in.Validations = append(in.Validations, gv)
	}
	if d.AppliedAt != nil {
		var n int64
		if err := db.Raw(`SELECT count(*) FROM iga_publication WHERE workspace_id = ? AND published_at > ?`, ws, *d.AppliedAt).
			Scan(&n).Error; err != nil {
			return nil, err
		}
		in.PublishedAfterApply = n > 0
	}
	if f.Trail != nil {
		in.Events, in.Trail = f.Trail(ws, d.ID)
	}
	out.Canary = &in
	return out, nil
}

/* ------------------------------------------------------------------------- */
/*                                The service                                 */
/* ------------------------------------------------------------------------- */

// GovBindingCheck is the J3 gate a direct deployment needs (T3.09's
// EnforcementBindingService.RequireVerified).
type GovBindingCheck interface {
	RequireVerified(ws, connectorID uuid.UUID) error
}

// GovRollout is §7.5's rollout and §8.6's observe_tick / refresh_activity.
type GovRollout struct {
	db        *gorm.DB
	live      LiveReader
	reviews   *IGAGovOwnerReviewService
	facts     RolloutDeploymentFacts
	binding   GovBindingCheck
	now       func() time.Time
	authorFor func(db *gorm.DB) *GovAuthoring
}

// NewGovRollout builds the service. live is the discovery-role reader
// Revalidate needs (nil: a stale plan cannot be revalidated here).
func NewGovRollout(db *gorm.DB, live LiveReader) *GovRollout {
	r := &GovRollout{db: db, live: live, reviews: NewIGAGovOwnerReviewService(db), now: time.Now,
		binding: NewEnforcementBindingService(db, nil, awsdiscovery.CallbackConfig{}, "")}
	return r
}

// WithClock sets the clock (tests).
func (r *GovRollout) WithClock(now func() time.Time) *GovRollout {
	r.now = now
	r.reviews.now = now
	return r
}

// WithFacts makes this service read f instead of the process-wide facts.
func (r *GovRollout) WithFacts(f RolloutDeploymentFacts) *GovRollout { r.facts = f; return r }

// WithBinding replaces the binding gate (tests).
func (r *GovRollout) WithBinding(b GovBindingCheck) *GovRollout { r.binding = b; return r }

func (r *GovRollout) deploymentFacts() RolloutDeploymentFacts {
	if r.facts != nil {
		return r.facts
	}
	return currentGovRolloutFacts(r.db)
}

func (r *GovRollout) authoring(db *gorm.DB) *GovAuthoring {
	if r.authorFor != nil {
		return r.authorFor(db)
	}
	return NewGovAuthoring(db, r.live).WithClock(r.now)
}

/* ------------------------------ gate_results ------------------------------ */

// GovRolloutPause is gate_results.pause.
type GovRolloutPause struct {
	From   string    `json:"from"`
	Kind   string    `json:"kind"`
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
}

// GovRolloutUndoOffer is one deployment the paused rollout offers to undo.
type GovRolloutUndoOffer struct {
	DeploymentID uuid.UUID `json:"deployment_id"`
	Path         string    `json:"path"`
}

// GovRolloutObservation is gate_results.observation.
type GovRolloutObservation struct {
	Rev         int64                      `json:"rev"`
	EvaluatedAt time.Time                  `json:"evaluated_at"`
	Result      igagov.ObservationResult   `json:"result"`
	Targets     []igagov.ObservationTarget `json:"-"`
}

// GovRolloutCanary is gate_results.canary.
type GovRolloutCanary struct {
	DeploymentID       uuid.UUID                  `json:"deployment_id"`
	State              string                     `json:"state"`
	Rev                int64                      `json:"rev,omitempty"`
	EvaluatedAt        time.Time                  `json:"evaluated_at"`
	WindowStart        *time.Time                 `json:"window_start,omitempty"`
	WindowEnd          *time.Time                 `json:"window_end,omitempty"`
	Gates              []igagov.GateResult        `json:"gates"`
	Accepted           []string                   `json:"accepted"`
	Pass               bool                       `json:"pass"`
	NotAvailable       []string                   `json:"not_available"`
	ApplicationHealth  igagov.DimensionResult     `json:"application_health"`
	Restriction        igagov.DimensionResult     `json:"restriction"`
	UnexpectedFailures []igagov.UnexpectedFailure `json:"unexpected_failures"`
}

// GovRolloutRefusal is one target no deployment could be created for.
type GovRolloutRefusal struct {
	TargetID uuid.UUID      `json:"target_id"`
	RoleID   string         `json:"role_id"`
	Code     string         `json:"code"`
	Message  string         `json:"message"`
	Detail   map[string]any `json:"detail,omitempty"`
}

// GovRolloutExpansion is gate_results.expansion.
type GovRolloutExpansion struct {
	At          time.Time           `json:"at"`
	Deployments []uuid.UUID         `json:"deployments"`
	Refused     []GovRolloutRefusal `json:"refused"`
}

// GovRolloutResults is iga_gov_rollout.gate_results (DECISION R1).
type GovRolloutResults struct {
	Observation *GovRolloutObservation `json:"observation,omitempty"`
	Canary      *GovRolloutCanary      `json:"canary,omitempty"`
	Pause       *GovRolloutPause       `json:"pause,omitempty"`
	UndoOffered []GovRolloutUndoOffer  `json:"undo_offered,omitempty"`
	Expansion   *GovRolloutExpansion   `json:"expansion,omitempty"`
}

func rolloutResults(ro *models.IGAGovRollout) GovRolloutResults {
	var g GovRolloutResults
	if len(ro.GateResults) > 0 {
		_ = json.Unmarshal(ro.GateResults, &g)
	}
	return g
}

/* ------------------------------- loading ---------------------------------- */

type govRolloutTarget struct {
	Target  models.IGAGovTarget
	Control models.IGAGovControl
	Plan    *models.IGAGovPlan // current apply plan
}

type govRolloutCtx struct {
	Policy  models.IGAGovPolicy
	Version models.IGAGovPolicyVersion
	Intent  igagov.RightSizeIntent
	Rollout *models.IGAGovRollout
	Targets []govRolloutTarget
}

func (rc *govRolloutCtx) refs(dep *uuid.UUID) govEventRefs {
	p, v := rc.Policy.ID, rc.Version.ID
	return govEventRefs{PolicyID: &p, VersionID: &v, DeploymentID: dep}
}

func (rc *govRolloutCtx) canary() (*govRolloutTarget, error) {
	for i := range rc.Targets {
		if rc.Targets[i].Target.IsCanary {
			return &rc.Targets[i], nil
		}
	}
	if len(rc.Targets) == 1 {
		return &rc.Targets[0], nil
	}
	return nil, govConflict(GovCodeCanaryNotChosen, "Choose the canary target in the policy's rollout settings (a new version).",
		map[string]any{"targets": len(rc.Targets)})
}

// loadVersionCtx reads a version, its intent, targets with controls and
// current apply plans, and its rollout (locked FOR UPDATE when lock).
func (r *GovRollout) loadVersionCtx(db *gorm.DB, ws uuid.UUID, v models.IGAGovPolicyVersion, lock bool) (*govRolloutCtx, error) {
	rc := &govRolloutCtx{Version: v}
	if err := db.Where("workspace_id = ? AND id = ?", ws, v.PolicyID).Take(&rc.Policy).Error; err != nil {
		return nil, err
	}
	intent, err := storedRightSize(v)
	if err != nil {
		return nil, err
	}
	rc.Intent = intent
	var ts []models.IGAGovTarget
	if err := db.Where("workspace_id = ? AND version_id = ?", ws, v.ID).Order("id").Find(&ts).Error; err != nil {
		return nil, err
	}
	plans, err := currentApplyPlans(db, ws, v.ID)
	if err != nil {
		return nil, err
	}
	for _, t := range ts {
		var c models.IGAGovControl
		if err := db.Where("workspace_id = ? AND id = ?", ws, t.ControlID).Take(&c).Error; err != nil {
			return nil, err
		}
		gt := govRolloutTarget{Target: t, Control: c}
		if p, ok := plans[t.ID]; ok {
			pp := p
			gt.Plan = &pp
		}
		rc.Targets = append(rc.Targets, gt)
	}
	sort.SliceStable(rc.Targets, func(i, j int) bool { return rc.Targets[i].Control.RoleID < rc.Targets[j].Control.RoleID })
	q := db.Where("workspace_id = ? AND version_id = ?", ws, v.ID)
	if lock {
		q = q.Clauses(lockForUpdate())
	}
	var ros []models.IGAGovRollout
	if err := q.Limit(1).Find(&ros).Error; err != nil {
		return nil, err
	}
	if len(ros) == 1 {
		rc.Rollout = &ros[0]
	}
	return rc, nil
}

// policyVersionFor picks the version a rollout route acts on: versionNo when
// given; otherwise, for start, the newest version in review or approved;
// for the other routes, the version of the policy's active rollout (a
// stage other than complete, partial or undone), newest first.
func (r *GovRollout) policyVersionFor(db *gorm.DB, ws, policyID uuid.UUID, versionNo *int, forStart bool) (*models.IGAGovPolicyVersion, error) {
	var pol models.IGAGovPolicy
	if err := db.Where("workspace_id = ? AND id = ?", ws, policyID).Take(&pol).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, GovNotFound()
		}
		return nil, err
	}
	var vs []models.IGAGovPolicyVersion
	switch {
	case versionNo != nil:
		if err := db.Where("workspace_id = ? AND policy_id = ? AND version_no = ?", ws, policyID, *versionNo).Limit(1).Find(&vs).Error; err != nil {
			return nil, err
		}
		if len(vs) == 0 {
			return nil, GovNotFound()
		}
	case forStart:
		if err := db.Where("workspace_id = ? AND policy_id = ? AND status IN ('in_review','approved')", ws, policyID).
			Order("version_no DESC").Limit(1).Find(&vs).Error; err != nil {
			return nil, err
		}
		if len(vs) == 0 {
			return nil, govConflict(GovCodeVersionConflict, "The policy has no version in review or approved to roll out.", nil)
		}
	default:
		if err := db.Raw(`SELECT v.* FROM iga_gov_policy_version v
			JOIN iga_gov_rollout r ON r.workspace_id = v.workspace_id AND r.version_id = v.id
			WHERE v.workspace_id = ? AND v.policy_id = ? AND r.stage NOT IN ('complete','partial','undone')
			ORDER BY v.version_no DESC LIMIT 1`, ws, policyID).Scan(&vs).Error; err != nil {
			return nil, err
		}
		if len(vs) == 0 {
			return nil, govConflict(GovCodeRolloutNotStarted, "The policy has no rollout in progress.", nil)
		}
	}
	return &vs[0], nil
}

/* ------------------------------ write helpers ----------------------------- */

func (r *GovRollout) saveTx(tx *gorm.DB, ro *models.IGAGovRollout, g GovRolloutResults) error {
	raw, err := json.Marshal(g)
	if err != nil {
		return err
	}
	ro.GateResults = raw
	ro.UpdatedAt = r.now()
	return tx.Model(&models.IGAGovRollout{}).Where("workspace_id = ? AND id = ?", ro.WorkspaceID, ro.ID).
		Updates(map[string]any{"stage": ro.Stage, "observe_until": ro.ObserveUntil,
			"observe_evidence_required_after": ro.ObserveEvidenceRequiredAfter, "canary_started_at": ro.CanaryStartedAt,
			"canary_min_until": ro.CanaryMinUntil, "gate_results": raw, "paused_reason": ro.PausedReason,
			"updated_at": ro.UpdatedAt}).Error
}

func actorPair(actor uuid.UUID) (string, string) {
	if actor == uuid.Nil {
		return models.GovActorSystem, "rollout"
	}
	return models.GovActorUser, actor.String()
}

// govAsGovError maps the binding service's refusal to the §7 envelope.
func govAsGovError(err error) error {
	var ee *EnforcementError
	if errors.As(err, &ee) {
		return govErr(ee.Status, ee.Code, ee.Message, ee.Detail)
	}
	return err
}

// deliveryAllowed is enforcement_mode's rule: findings_only refuses direct
// and iac_pr (409 enforcement_not_enabled); export always proceeds.
func (r *GovRollout) deliveryAllowed(db *gorm.DB, ws uuid.UUID, delivery string) error {
	if delivery == igagov.DeliveryExport {
		return nil
	}
	set, err := repositories.NewIGAGovSettingsRepository(db).Get(ws)
	if err != nil {
		return err
	}
	if set.EnforcementMode != models.GovModeEnforce {
		return govConflict(GovCodeEnforcementNotEnabled, "This workspace is findings-only; switch Policy settings to enforce before a "+
			delivery+" rollout.", map[string]any{"enforcement_mode": set.EnforcementMode, "delivery": delivery})
	}
	return nil
}

func (r *GovRollout) settings(db *gorm.DB, ws uuid.UUID) (*models.IGAGovSettings, error) {
	return repositories.NewIGAGovSettingsRepository(db).Get(ws)
}

// canaryHours is the version's canary length: GovCanaryHours, the one rule
// the verify job's window uses too.
func (r *GovRollout) canaryHours(db *gorm.DB, rc *govRolloutCtx) (int, error) {
	return GovCanaryHours(db, rc.Version.WorkspaceID, rc.Version.ID)
}

func policyUsable(p models.IGAGovPolicy) error {
	switch p.Lifecycle {
	case "archived":
		return govConflict(GovCodePolicyArchived, "The policy is archived and read-only.", nil)
	case "paused":
		return govConflict(GovCodePolicyPaused, "The policy is paused; resume it before rolling out.", nil)
	}
	return nil
}

/* --------------------------------- start ---------------------------------- */

// GovRolloutView is GET /policies/:id/rollout and every rollout mutation's
// response.
type GovRolloutView struct {
	Rollout     models.IGAGovRollout      `json:"rollout"`
	Results     GovRolloutResults         `json:"results"`
	PolicyID    uuid.UUID                 `json:"policy_id"`
	VersionNo   int                       `json:"version_no"`
	Version     string                    `json:"version_status"`
	Deployments []GovRolloutDeployment    `json:"deployments"`
	Acceptances []models.IGAGovAcceptance `json:"acceptances"`
	// Actions are what the console may offer now: undo_canary (with the
	// deployments in results.undo_offered), resume, expand.
	Actions []string `json:"actions"`
}

// GovRolloutDeployment is one deployment of the rolled-out version.
type GovRolloutDeployment struct {
	ID        uuid.UUID  `json:"id"`
	TargetID  uuid.UUID  `json:"target_id"`
	RoleID    string     `json:"role_id"`
	Canary    bool       `json:"canary"`
	State     string     `json:"state"`
	AppliedAt *time.Time `json:"applied_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// GovRolloutStartInput is POST /policies/:id/rollout/start.
type GovRolloutStartInput struct {
	VersionNo *int   `json:"version_no"`
	Reason    string `json:"reason"`
}

// Start is POST /policies/:id/rollout/start: observation for a version in
// review or approved (owner gate first), or the canary once the version is
// approved and observed (§7.5). DECISION R3.
func (r *GovRollout) Start(ctx context.Context, ws, actor, policyID uuid.UUID, in GovRolloutStartInput) (*GovRolloutView, error) {
	db := r.db.WithContext(ctx)
	v, err := r.policyVersionFor(db, ws, policyID, in.VersionNo, true)
	if err != nil {
		return nil, err
	}
	if pi, perr := igagov.ParseIntent(v.Intent); perr == nil && pi.Kind == igagov.IntentRemoveControl {
		return r.startRemoveControl(ctx, ws, actor, *v, in.Reason)
	}
	rc, err := r.loadVersionCtx(db, ws, *v, false)
	if err != nil {
		return nil, err
	}
	if rc.Rollout != nil && rc.Rollout.Stage == models.GovRolloutAwaitingApproval {
		return r.startCanary(ctx, ws, actor, *v, in.Reason)
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`SELECT 1 FROM iga_gov_policy WHERE workspace_id = ? AND id = ? FOR UPDATE`, ws, policyID).Error; err != nil {
			return err
		}
		var cur models.IGAGovPolicyVersion
		if err := tx.Where("workspace_id = ? AND id = ?", ws, v.ID).Clauses(lockForUpdate()).Take(&cur).Error; err != nil {
			return err
		}
		rc, err := r.loadVersionCtx(tx, ws, cur, true)
		if err != nil {
			return err
		}
		if err := policyUsable(rc.Policy); err != nil {
			return err
		}
		if cur.Status != "in_review" && cur.Status != "approved" {
			return govConflict(GovCodeVersionConflict, "Only a version in review or approved can be rolled out.", map[string]any{"status": cur.Status})
		}
		restart := false
		if ro := rc.Rollout; ro != nil {
			g := rolloutResults(ro)
			switch {
			case ro.Stage == models.GovRolloutPaused && g.Pause != nil && g.Pause.Kind == GovPauseReturnedToDraft:
				restart = true
			case ro.Stage == models.GovRolloutObserve:
				return govConflict(GovCodeObservationIncomplete, "Observation is still running for this version.",
					map[string]any{"observe_until": ro.ObserveUntil, "observe_evidence_required_after": ro.ObserveEvidenceRequiredAfter,
						"observation": g.Observation})
			case ro.Stage == models.GovRolloutPaused:
				return govConflict(GovCodeRolloutPaused, "The rollout is paused; resume it.", map[string]any{"pause": g.Pause})
			default:
				return govConflict(GovCodeRolloutConflict, "The rollout of this version has already started.", map[string]any{"stage": ro.Stage})
			}
		}
		if err := r.reviews.CheckGate(tx, ws, cur.ID); err != nil {
			return err
		}
		for _, t := range rc.Targets {
			if t.Plan == nil {
				return govUnprocessable(GovCodeTargetIneligible, "A target has no compiled apply plan.", map[string]any{"target_id": t.Target.ID})
			}
			if err := r.deliveryAllowed(tx, ws, t.Plan.Delivery); err != nil {
				return err
			}
		}
		days := rc.Intent.ObservationDays
		if days < igagov.MinObservationDays || days > igagov.MaxObservationDays {
			set, err := r.settings(tx, ws)
			if err != nil {
				return err
			}
			days = set.DefaultObservationDays
		}
		now := r.now().UTC()
		until := now.Add(time.Duration(days) * 24 * time.Hour)
		after := igagov.ObserveEvidenceRequiredAfter(until)
		ro := rc.Rollout
		if ro == nil {
			ro = &models.IGAGovRollout{ID: uuid.New(), WorkspaceID: ws, VersionID: cur.ID, Stage: models.GovRolloutObserve,
				GateResults: json.RawMessage(`{}`), UpdatedAt: now}
			if err := tx.Create(ro).Error; err != nil {
				if isUniqueViolation(err, "version_id") {
					return govConflict(GovCodeRolloutConflict, "The rollout of this version was started at the same time.", nil)
				}
				return err
			}
		}
		ro.Stage, ro.ObserveUntil, ro.ObserveEvidenceRequiredAfter = models.GovRolloutObserve, &until, &after
		ro.CanaryStartedAt, ro.CanaryMinUntil, ro.PausedReason = nil, nil, ""
		if err := r.saveTx(tx, ro, GovRolloutResults{}); err != nil {
			return err
		}
		ak, aid := actorPair(actor)
		return appendGovEvent(tx, ws, GovEventRolloutObservationStarted, ak, aid, rc.refs(nil), map[string]any{
			"rollout_id": ro.ID, "version_no": cur.VersionNo, "observation_days": days, "observe_until": until,
			"observe_evidence_required_after": after, "restart": restart, "reason": in.Reason})
	})
	if err != nil {
		return nil, err
	}
	return r.view(db, ws, *v)
}

// startCanary is start's second form: the version is approved and observed.
func (r *GovRollout) startCanary(ctx context.Context, ws, actor uuid.UUID, v models.IGAGovPolicyVersion, reason string) (*GovRolloutView, error) {
	db := r.db.WithContext(ctx)
	rc, err := r.loadVersionCtx(db, ws, v, false)
	if err != nil {
		return nil, err
	}
	if err := policyUsable(rc.Policy); err != nil {
		return nil, err
	}
	ct, err := rc.canary()
	if err != nil {
		return nil, err
	}
	if err := r.checkCanaryChoice(db, ws, rc, ct); err != nil {
		return nil, err
	}
	prep, err := r.prepare(ctx, ws, rc, *ct)
	if err != nil {
		return nil, err
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		var cur models.IGAGovPolicyVersion
		if err := tx.Where("workspace_id = ? AND id = ?", ws, v.ID).Clauses(lockForUpdate()).Take(&cur).Error; err != nil {
			return err
		}
		rc, err := r.loadVersionCtx(tx, ws, cur, true)
		if err != nil {
			return err
		}
		if rc.Rollout == nil || rc.Rollout.Stage != models.GovRolloutAwaitingApproval {
			return govConflict(GovCodeRolloutConflict, "The rollout moved on; read it again.", nil)
		}
		if err := r.reviews.CheckGate(tx, ws, cur.ID); err != nil {
			return err
		}
		ct, err := rc.canary()
		if err != nil {
			return err
		}
		dep, err := r.createDeploymentTx(tx, ws, actor, rc, *ct, prep)
		if err != nil {
			return err
		}
		hours, err := r.canaryHours(tx, rc)
		if err != nil {
			return err
		}
		now := r.now().UTC()
		minUntil := now.Add(time.Duration(hours) * time.Hour)
		ro := rc.Rollout
		ro.Stage, ro.CanaryStartedAt, ro.CanaryMinUntil = models.GovRolloutCanary, &now, &minUntil
		g := rolloutResults(ro)
		g.Canary = &GovRolloutCanary{DeploymentID: dep.ID, State: dep.State, EvaluatedAt: now, Gates: []igagov.GateResult{},
			Accepted: []string{}, NotAvailable: []string{}, UnexpectedFailures: []igagov.UnexpectedFailure{}}
		if err := r.saveTx(tx, ro, g); err != nil {
			return err
		}
		ak, aid := actorPair(actor)
		return appendGovEvent(tx, ws, GovEventRolloutCanaryStarted, ak, aid, rc.refs(&dep.ID), map[string]any{
			"rollout_id": ro.ID, "deployment_id": dep.ID, "target_id": ct.Target.ID, "role_id": ct.Control.RoleID,
			"canary_hours": hours, "single_target": len(rc.Targets) == 1, "reason": reason})
	})
	if err != nil {
		return nil, err
	}
	return r.view(db, ws, v)
}

// checkCanaryChoice is §8.6's canary rule (DECISION R5).
func (r *GovRollout) checkCanaryChoice(db *gorm.DB, ws uuid.UUID, rc *govRolloutCtx, ct *govRolloutTarget) error {
	ack, err := r.reviews.CanaryAcknowledgement(db, ws, rc.Version.ID, ct.Target.ID)
	if err != nil {
		return err
	}
	if ack.Shared && !ack.Acknowledged {
		return govConflict(GovCodeCanaryNotAcknowledged,
			"This role is shared: every consuming workload's owner must acknowledge in the review before it can be the canary (an exception does not count).",
			map[string]any{"target_id": ct.Target.ID, "role_id": ct.Control.RoleID, "missing_user_ids": ack.Missing,
				"unowned_workload_ids": ack.Unowned})
	}
	if len(rc.Targets) < 2 || ct.Plan == nil {
		return nil
	}
	admin, why, err := adminLevelRole(db, ws, ct.Plan.EvidenceBundleID)
	if err != nil {
		return err
	}
	if admin {
		return govConflict(GovCodeCanaryAdminRole, "A role with administration-level statements cannot be the canary; choose another target.",
			map[string]any{"target_id": ct.Target.ID, "role_id": ct.Control.RoleID, "grants": why})
	}
	return nil
}

// adminLevelRole reads the plan bundle's grants: AdministratorAccess, or an
// Allow statement whose Action is "*", "iam:*" or "organizations:*".
func adminLevelRole(db *gorm.DB, ws, bundleID uuid.UUID) (bool, []string, error) {
	facts, err := bundleFacts(db, ws, bundleID)
	if err != nil {
		return false, nil, err
	}
	var why []string
	var hashes []string
	for _, g := range facts.Grants {
		if strings.HasSuffix(g.PolicyARN, ":policy/AdministratorAccess") {
			why = append(why, g.PolicyARN)
		}
		if g.StatementHash != "" {
			hashes = append(hashes, g.StatementHash)
		}
	}
	if len(hashes) > 0 {
		var stmts []json.RawMessage
		if err := db.Raw(`SELECT DISTINCT statement FROM iga_statement_revision WHERE workspace_id = ? AND content_hash IN ?`,
			ws, hashes).Scan(&stmts).Error; err != nil {
			return false, nil, err
		}
		for _, raw := range stmts {
			var st struct {
				Effect string          `json:"Effect"`
				Action json.RawMessage `json:"Action"`
			}
			if json.Unmarshal(raw, &st) != nil || !strings.EqualFold(st.Effect, "Allow") {
				continue
			}
			var acts []string
			var one string
			if json.Unmarshal(st.Action, &one) == nil {
				acts = []string{one}
			} else {
				_ = json.Unmarshal(st.Action, &acts)
			}
			for _, a := range acts {
				if isAdminLevelAction(a) {
					why = append(why, a)
				}
			}
		}
	}
	return len(why) > 0, why, nil
}

/* ------------------------------ deployments ------------------------------- */

// govPrepared is a target's approval check made before the transaction
// (Revalidate reads AWS and commits on its own).
type govPrepared struct {
	usable *GovUsableApproval
}

// prepare is the per-deployment approval check (§2.8, DECISION R8):
// UsableApproval; on revalidation_required, Revalidate once and ask again;
// a material change is 409 material_change with its changes.
func (r *GovRollout) prepare(ctx context.Context, ws uuid.UUID, rc *govRolloutCtx, t govRolloutTarget) (*govPrepared, error) {
	if t.Plan == nil {
		return nil, govUnprocessable(GovCodeTargetIneligible, "The target has no compiled apply plan.", map[string]any{"target_id": t.Target.ID})
	}
	if t.Plan.Eligibility == igagov.EligibilityIneligible {
		return nil, govUnprocessable(GovCodeTargetIneligible, "The target's plan is ineligible.",
			map[string]any{"target_id": t.Target.ID, "reason": t.Plan.IneligibleReason})
	}
	a := r.authoring(r.db)
	ua, err := a.UsableApproval(ctx, ws, rc.Version.ID, []uuid.UUID{t.Plan.ID})
	var ge *GovError
	if errors.As(err, &ge) && ge.Code == GovCodeRevalidationNeeded {
		if r.live == nil {
			return nil, err
		}
		rv, rerr := a.Revalidate(ctx, ws, t.Plan.ID)
		if rerr != nil {
			return nil, rerr
		}
		if rv.Revalidation.Result == models.GovRevalidationMaterialChange {
			return nil, govConflict(GovCodeMaterialChange, "Revalidation found a material change; a new approval is needed.",
				map[string]any{"plan_id": t.Plan.ID, "revalidation_id": rv.Revalidation.ID, "changes": rv.Changes})
		}
		ua, err = a.UsableApproval(ctx, ws, rc.Version.ID, []uuid.UUID{t.Plan.ID})
	}
	if err != nil {
		return nil, err
	}
	return &govPrepared{usable: ua}, nil
}

// createDeploymentTx inserts one queued deployment for the target's apply
// plan and its deploy job, in tx. The approval is re-checked inside tx
// (UsableApproval over tx); the revalidation relied on is the one it
// returns. The mode and binding are checked here too.
func (r *GovRollout) createDeploymentTx(tx *gorm.DB, ws, actor uuid.UUID, rc *govRolloutCtx, t govRolloutTarget, prep *govPrepared) (*models.IGAGovDeployment, error) {
	if t.Plan == nil {
		return nil, govUnprocessable(GovCodeTargetIneligible, "The target has no compiled apply plan.", map[string]any{"target_id": t.Target.ID})
	}
	if err := r.deliveryAllowed(tx, ws, t.Plan.Delivery); err != nil {
		return nil, err
	}
	if t.Plan.Delivery == igagov.DeliveryDirect {
		if err := r.binding.RequireVerified(ws, t.Control.ConnectorID); err != nil {
			return nil, govAsGovError(err)
		}
	}
	ua, err := r.authoring(tx).UsableApproval(tx.Statement.Context, ws, rc.Version.ID, []uuid.UUID{t.Plan.ID})
	if err != nil {
		return nil, err
	}
	_ = prep
	var inflight []uuid.UUID
	if err := tx.Raw(`SELECT id FROM iga_gov_deployment WHERE workspace_id = ? AND control_id = ?
		AND state IN ('queued','applying','outcome_unknown','outcome_unresolved','awaiting_merge','awaiting_apply')`, ws, t.Control.ID).
		Scan(&inflight).Error; err != nil {
		return nil, err
	}
	if len(inflight) > 0 {
		return nil, govConflict(GovCodeDeploymentInFlight, "Another change to this role is in flight.",
			map[string]any{"deployment_id": inflight[0], "role_id": t.Control.RoleID})
	}
	now := r.now().UTC()
	apID := ua.Approval.ID
	dep := &models.IGAGovDeployment{ID: uuid.New(), WorkspaceID: ws, VersionID: rc.Version.ID, PlanID: t.Plan.ID,
		ControlID: t.Control.ID, ApprovalID: &apID, Kind: t.Plan.Kind, Delivery: t.Plan.Delivery, State: models.GovDeployQueued,
		CompletedOps: json.RawMessage(`[]`), CreatedAt: now, UpdatedAt: now}
	if rv := ua.Revalidations[t.Plan.ID]; rv != nil {
		id, res := *rv, models.GovRevalidationUnchanged
		dep.RevalidationID, dep.RevalidationResult = &id, &res
	}
	if err := tx.Create(dep).Error; err != nil {
		if isUniqueViolation(err, "uq_iga_gov_deployment_inflight") {
			return nil, govConflict(GovCodeDeploymentInFlight, "Another change to this role is in flight.", map[string]any{"role_id": t.Control.RoleID})
		}
		return nil, err
	}
	if err := enqueueRolloutDeployTx(tx, ws, dep.ID); err != nil {
		return nil, err
	}
	ak, aid := actorPair(actor)
	if err := appendGovEvent(tx, ws, GovEventRolloutDeploymentCreated, ak, aid, rc.refs(&dep.ID), map[string]any{
		"rollout_id": rc.Rollout.ID, "deployment_id": dep.ID, "target_id": t.Target.ID, "role_id": t.Control.RoleID,
		"plan_id": t.Plan.ID, "approval_id": apID, "delivery": dep.Delivery, "revalidation_id": dep.RevalidationID,
		"canary": t.Target.IsCanary || len(rc.Targets) == 1}); err != nil {
		return nil, err
	}
	return dep, nil
}

// enqueueRolloutDeployTx queues the deploy job of a deployment the rollout
// created (dedupe deployment:<id>). MERGE NOTE: T3.16's
// services.EnqueueDeployTx(tx, ws, depID) is the same contract; at the
// integration merge this body becomes a call to it.
func enqueueRolloutDeployTx(tx *gorm.DB, ws, depID uuid.UUID) error {
	// T3.16's deploy job (same dedupe deployment:<id>).
	return EnqueueDeployTx(tx, ws, depID)
}

/* ---------------------------- remove_control ------------------------------ */

// GovRemoveControlStarter starts the deployments of an approved
// remove_control version (§8.10): removals have no observation and no
// canary. T3.16's services.StartRemoveControlDeployments is wired here at
// the integration merge (SetGovRemoveControlStarter); without it, starting
// a remove_control version is 409 remove_control_not_available.
type GovRemoveControlStarter func(ctx context.Context, db *gorm.DB, ws, actor, versionID uuid.UUID) error

var (
	govRemoveControlMu      sync.RWMutex
	govRemoveControlStarter GovRemoveControlStarter
)

// SetGovRemoveControlStarter installs the remove_control starter and
// returns a restore function.
func SetGovRemoveControlStarter(f GovRemoveControlStarter) (restore func()) {
	govRemoveControlMu.Lock()
	prev := govRemoveControlStarter
	govRemoveControlStarter = f
	govRemoveControlMu.Unlock()
	return func() {
		govRemoveControlMu.Lock()
		govRemoveControlStarter = prev
		govRemoveControlMu.Unlock()
	}
}

// GovCodeRemoveControlUnavailable: no remove_control starter in this build.
const GovCodeRemoveControlUnavailable = "remove_control_not_available"

// startRemoveControl hands an approved remove_control version to T3.16.
func (r *GovRollout) startRemoveControl(ctx context.Context, ws, actor uuid.UUID, v models.IGAGovPolicyVersion, reason string) (*GovRolloutView, error) {
	db := r.db.WithContext(ctx)
	var pol models.IGAGovPolicy
	if err := db.Where("workspace_id = ? AND id = ?", ws, v.PolicyID).Take(&pol).Error; err != nil {
		return nil, err
	}
	if pol.Lifecycle == "archived" {
		return nil, govConflict(GovCodePolicyArchived, "The policy is archived and read-only.", nil)
	}
	if v.Status != "approved" {
		return nil, govConflict(GovCodeApprovalRequired, "A remove_control version starts once it is approved.", map[string]any{"status": v.Status})
	}
	govRemoveControlMu.RLock()
	start := govRemoveControlStarter
	govRemoveControlMu.RUnlock()
	if start == nil {
		return nil, govConflict(GovCodeRemoveControlUnavailable, "Removing AuthSec control is not available in this build.", nil)
	}
	if err := start(ctx, db, ws, actor, v.ID); err != nil {
		return nil, err
	}
	if err := db.Transaction(func(tx *gorm.DB) error {
		ak, aid := actorPair(actor)
		p, vid := v.PolicyID, v.ID
		return appendGovEvent(tx, ws, GovEventRolloutRemoveControlStarted, ak, aid, govEventRefs{PolicyID: &p, VersionID: &vid},
			map[string]any{"version_no": v.VersionNo, "reason": reason})
	}); err != nil {
		return nil, err
	}
	out := &GovRolloutView{PolicyID: v.PolicyID, VersionNo: v.VersionNo, Version: v.Status, Deployments: []GovRolloutDeployment{},
		Acceptances: []models.IGAGovAcceptance{}, Actions: []string{}}
	if err := db.Raw(`SELECT d.id, t.id AS target_id, c.role_id, false AS canary, d.state, d.applied_at, d.created_at
		FROM iga_gov_deployment d
		JOIN iga_gov_control c ON c.workspace_id = d.workspace_id AND c.id = d.control_id
		LEFT JOIN iga_gov_target t ON t.workspace_id = d.workspace_id AND t.version_id = d.version_id AND t.control_id = d.control_id
		WHERE d.workspace_id = ? AND d.version_id = ? ORDER BY d.created_at, d.id`, ws, v.ID).Scan(&out.Deployments).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func refusalOf(t govRolloutTarget, err error) (GovRolloutRefusal, bool) {
	var ge *GovError
	if !errors.As(err, &ge) {
		return GovRolloutRefusal{}, false
	}
	return GovRolloutRefusal{TargetID: t.Target.ID, RoleID: t.Control.RoleID, Code: ge.Code, Message: ge.Message, Detail: ge.Detail}, true
}

/* ------------------------------ gates ------------------------------------- */

// canaryDeployment is the version's latest deployment on the canary target.
func (r *GovRollout) versionDeployments(db *gorm.DB, ws, versionID uuid.UUID) ([]models.IGAGovDeployment, error) {
	var ds []models.IGAGovDeployment
	err := db.Where("workspace_id = ? AND version_id = ? AND kind = 'apply'", ws, versionID).Order("created_at, id").Find(&ds).Error
	return ds, err
}

// gateEval is one evaluation of the canary's gates.
type gateEval struct {
	facts    *RolloutDeploymentGateFacts
	result   igagov.CanaryResult
	hours    int
	accepted map[string]bool
	canary   GovRolloutCanary
}

// gateItemHash is the item_hash of an accepted gate result (DECISION R6).
func gateItemHash(g igagov.GateResult) string {
	raw, _ := json.Marshal(map[string]any{"gate": g.Gate, "outcome": g.Outcome, "reason": g.Reason, "evidence": g.Evidence})
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// evaluateGates reads the canary deployment's facts through db and runs
// §8.6's gates over its window, with the accepted not_available gates of
// that window (matched by rollout, version, gate and the whole window).
// The decisions that act on the result call it with their transaction,
// after lockCanaryFactsTx.
func (r *GovRollout) evaluateGates(ctx context.Context, db *gorm.DB, ws uuid.UUID, rc *govRolloutCtx, depID uuid.UUID, rev int64) (*gateEval, error) {
	f, err := r.deploymentFacts().DeploymentGateFacts(ctx, db, ws, depID)
	if err != nil {
		return nil, err
	}
	hours, err := r.canaryHours(db, rc)
	if err != nil {
		return nil, err
	}
	now := r.now().UTC()
	ev := &gateEval{facts: f, hours: hours, accepted: map[string]bool{}}
	ev.canary = GovRolloutCanary{DeploymentID: depID, State: f.State, Rev: rev, EvaluatedAt: now, Gates: []igagov.GateResult{},
		Accepted: []string{}, NotAvailable: []string{}, UnexpectedFailures: []igagov.UnexpectedFailure{}}
	if f.AppliedAt == nil {
		return ev, nil
	}
	switch {
	case len(f.Gates) > 0:
		ev.result = canaryResultOf(f)
	case f.Canary != nil:
		in := *f.Canary
		in.AppliedAt, in.Now, in.CanaryHours = f.AppliedAt.UTC(), now, hours
		if in.ArtifactOutcome == "" {
			in.ArtifactOutcome = f.Dimensions["artifact"].Outcome
		}
		ev.result = igagov.EvaluateCanary(in)
	}
	ws0 := f.AppliedAt.UTC()
	we := ws0.Add(time.Duration(hours) * time.Hour)
	ev.canary.WindowStart, ev.canary.WindowEnd = &ws0, &we
	var accs []models.IGAGovAcceptance
	if rc.Rollout != nil {
		if err := db.Where("workspace_id = ? AND rollout_id = ? AND version_id = ? AND kind = ? AND stage = 'canary' AND window_start = ? AND window_end = ?",
			ws, rc.Rollout.ID, rc.Version.ID, models.GovAcceptGateNotAvailable, ws0, we).Find(&accs).Error; err != nil {
			return nil, err
		}
	}
	for _, a := range accs {
		ev.accepted[a.ItemKey] = true
	}
	ev.canary.Gates = ev.result.Gates
	ev.canary.NotAvailable = ev.result.NotAvailable
	ev.canary.ApplicationHealth, ev.canary.Restriction = ev.result.ApplicationHealth, ev.result.Restriction
	ev.canary.UnexpectedFailures = ev.result.UnexpectedFailures
	for _, g := range ev.result.Gates {
		if g.Outcome == igagov.OutcomeNotAvailable && ev.accepted[g.Gate] {
			ev.canary.Accepted = append(ev.canary.Accepted, g.Gate)
		}
	}
	ev.canary.Pass = ev.passes(nil)
	return ev, nil
}

// canaryResultOf is the gate result of facts whose gates T3.16's verify
// run computed: pass when all passed, pause when any failed.
func canaryResultOf(f *RolloutDeploymentGateFacts) igagov.CanaryResult {
	res := igagov.CanaryResult{Gates: append([]igagov.GateResult(nil), f.Gates...), Pass: true, NotAvailable: []string{},
		UnexpectedFailures: append([]igagov.UnexpectedFailure{}, f.UnexpectedFailures...),
		ApplicationHealth:  f.Dimensions["application_health"], Restriction: f.Dimensions["restriction"]}
	for _, g := range res.Gates {
		if g.Outcome != igagov.OutcomePassed {
			res.Pass = false
		}
		if g.Outcome == igagov.OutcomeFailed {
			res.Pause = true
		}
		if g.Outcome == igagov.OutcomeNotAvailable {
			res.NotAvailable = append(res.NotAvailable, g.Gate)
		}
	}
	return res
}

// passes: every gate passed, or is not_available and accepted (by a row,
// or in extra -- the gates being accepted now).
func (ev *gateEval) passes(extra map[string]bool) bool {
	if ev.facts.AppliedAt == nil || len(ev.result.Gates) == 0 {
		return false
	}
	for _, g := range ev.result.Gates {
		switch {
		case g.Outcome == igagov.OutcomePassed:
		case g.Outcome == igagov.OutcomeNotAvailable && (ev.accepted[g.Gate] || extra[g.Gate]):
		default:
			return false
		}
	}
	return true
}

func (ev *gateEval) failing(extra map[string]bool) []igagov.GateResult {
	out := []igagov.GateResult{}
	for _, g := range ev.result.Gates {
		if g.Outcome == igagov.OutcomePassed || (g.Outcome == igagov.OutcomeNotAvailable && (ev.accepted[g.Gate] || extra[g.Gate])) {
			continue
		}
		out = append(out, g)
	}
	return out
}

/* ------------------------------ pause / resume ---------------------------- */

// GovRolloutReasonInput is the {reason} body of pause and resume.
type GovRolloutReasonInput struct {
	Reason string `json:"reason"`
}

// Pause is POST /policies/:id/rollout/pause (DECISION R9).
func (r *GovRollout) Pause(ctx context.Context, ws, actor, policyID uuid.UUID, reason string) (*GovRolloutView, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, GovBadParam("reason", "Pausing a rollout needs a reason.")
	}
	return r.mutateActive(ctx, ws, policyID, func(tx *gorm.DB, rc *govRolloutCtx) error {
		ro := rc.Rollout
		switch ro.Stage {
		case models.GovRolloutObserve, models.GovRolloutAwaitingApproval, models.GovRolloutCanary, models.GovRolloutExpand:
		case models.GovRolloutPaused:
			return govConflict(GovCodeRolloutPaused, "The rollout is already paused.", nil)
		default:
			return govConflict(GovCodeRolloutConflict, "The rollout has finished.", map[string]any{"stage": ro.Stage})
		}
		return r.pauseTx(tx, ws, actor, rc, GovPauseManual, strings.TrimSpace(reason), nil)
	})
}

// Resume is POST /policies/:id/rollout/resume: back to the stage it was
// paused from. A rollout whose version went back to draft is restarted by
// start on the re-proposed version, not resumed.
func (r *GovRollout) Resume(ctx context.Context, ws, actor, policyID uuid.UUID, reason string) (*GovRolloutView, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, GovBadParam("reason", "Resuming a rollout needs a reason.")
	}
	return r.mutateActive(ctx, ws, policyID, func(tx *gorm.DB, rc *govRolloutCtx) error {
		ro := rc.Rollout
		if ro.Stage != models.GovRolloutPaused {
			return govConflict(GovCodeRolloutConflict, "The rollout is not paused.", map[string]any{"stage": ro.Stage})
		}
		if err := policyUsable(rc.Policy); err != nil {
			return err
		}
		g := rolloutResults(ro)
		if g.Pause == nil || g.Pause.From == "" || g.Pause.Kind == GovPauseReturnedToDraft {
			return govConflict(GovCodeVersionConflict, "The version went back to draft; propose it again and start a new observation.",
				map[string]any{"pause": g.Pause})
		}
		from := g.Pause.From
		ro.Stage, ro.PausedReason = from, ""
		prev := g.Pause
		g.Pause, g.UndoOffered = nil, nil
		if err := r.saveTx(tx, ro, g); err != nil {
			return err
		}
		// The deployments the pause held go now, not at their next recheck.
		if err := tx.Exec(`UPDATE iga_gov_job SET run_after = now()
			WHERE workspace_id = ? AND kind = 'deploy' AND status = 'queued' AND run_after > now()
			  AND subject_id IN (SELECT id FROM iga_gov_deployment WHERE workspace_id = ? AND version_id = ?
			                       AND kind = 'apply' AND state = 'queued')`, ws, ws, ro.VersionID).Error; err != nil {
			return err
		}
		ak, aid := actorPair(actor)
		return appendGovEvent(tx, ws, GovEventRolloutResumed, ak, aid, rc.refs(nil), map[string]any{
			"rollout_id": ro.ID, "stage": from, "paused": prev, "reason": strings.TrimSpace(reason)})
	})
}

// mutateActive runs fn on the policy's active rollout, locked, then
// returns the view.
func (r *GovRollout) mutateActive(ctx context.Context, ws, policyID uuid.UUID, fn func(tx *gorm.DB, rc *govRolloutCtx) error) (*GovRolloutView, error) {
	db := r.db.WithContext(ctx)
	v, err := r.policyVersionFor(db, ws, policyID, nil, false)
	if err != nil {
		return nil, err
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		var cur models.IGAGovPolicyVersion
		if err := tx.Where("workspace_id = ? AND id = ?", ws, v.ID).Clauses(lockForUpdate()).Take(&cur).Error; err != nil {
			return err
		}
		rc, err := r.loadVersionCtx(tx, ws, cur, true)
		if err != nil {
			return err
		}
		if rc.Rollout == nil {
			return govConflict(GovCodeRolloutNotStarted, "The policy has no rollout in progress.", nil)
		}
		return fn(tx, rc)
	})
	if err != nil {
		return nil, err
	}
	return r.view(db, ws, *v)
}

// pauseTx pauses rc's rollout with kind and reason, offering undo of the
// given applied deployments, and notifies (canary_gate) unless manual.
func (r *GovRollout) pauseTx(tx *gorm.DB, ws, actor uuid.UUID, rc *govRolloutCtx, kind, reason string, undo []uuid.UUID) error {
	ro := rc.Rollout
	g := rolloutResults(ro)
	now := r.now().UTC()
	g.Pause = &GovRolloutPause{From: ro.Stage, Kind: kind, Reason: reason, At: now}
	if kind == GovPauseReturnedToDraft {
		g.Pause.From = ""
	}
	g.UndoOffered = nil
	for _, id := range undo {
		g.UndoOffered = append(g.UndoOffered, GovRolloutUndoOffer{DeploymentID: id, Path: "/deployments/" + id.String() + "/undo"})
	}
	ro.Stage, ro.PausedReason = models.GovRolloutPaused, kind+": "+reason
	if err := r.saveTx(tx, ro, g); err != nil {
		return err
	}
	ak, aid := actorPair(actor)
	if err := appendGovEvent(tx, ws, GovEventRolloutPaused, ak, aid, rc.refs(nil), map[string]any{
		"rollout_id": ro.ID, "from": g.Pause.From, "kind": kind, "reason": reason, "undo_offered": undo}); err != nil {
		return err
	}
	if kind != GovPauseManual {
		return r.notifyTx(tx, ws, rc)
	}
	return nil
}

/* ------------------------------ expand ------------------------------------ */

// GovGateAcceptInput is one accept_not_available item.
type GovGateAcceptInput struct {
	Gate   string `json:"gate"`
	Reason string `json:"reason"`
}

// GovRolloutExpandInput is POST /policies/:id/rollout/expand.
type GovRolloutExpandInput struct {
	AcceptNotAvailable []GovGateAcceptInput `json:"accept_not_available"`
	Reason             string               `json:"reason"`
}

// Expand is POST /policies/:id/rollout/expand (§7.5, DECISIONS R6, R7):
// the canary's gates must pass, a not_available gate only with an
// acceptance named in the body (stored as a gate_not_available row); then
// each other target gets its deployment (single target: complete).
func (r *GovRollout) Expand(ctx context.Context, ws, actor, policyID uuid.UUID, in GovRolloutExpandInput) (*GovRolloutView, error) {
	db := r.db.WithContext(ctx)
	extra := map[string]bool{}
	for i, a := range in.AcceptNotAvailable {
		if strings.TrimSpace(a.Reason) == "" || a.Gate == "" {
			return nil, GovBadParam(fmt.Sprintf("accept_not_available[%d]", i), "Each accepted gate needs a gate and a reason.")
		}
		if extra[a.Gate] {
			return nil, GovBadParam(fmt.Sprintf("accept_not_available[%d]", i), "A gate is accepted twice.")
		}
		extra[a.Gate] = true
	}
	v, err := r.policyVersionFor(db, ws, policyID, nil, false)
	if err != nil {
		return nil, err
	}
	if len(extra) > 0 {
		if v.CreatedBy == actor {
			return nil, govErr(http.StatusForbidden, GovCodeSelfApproval, "You authored this version; another approver must accept unavailable gates.", nil)
		}
		ok, err := holdsPermission(db, ws, actor, "governance", "approve")
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, govErr(http.StatusForbidden, "forbidden", "Accepting an unavailable gate needs governance:approve.", nil)
		}
	}
	rc, err := r.loadVersionCtx(db, ws, *v, false)
	if err != nil {
		return nil, err
	}
	if rc.Rollout == nil || rc.Rollout.Stage != models.GovRolloutCanary {
		st := ""
		if rc.Rollout != nil {
			st = rc.Rollout.Stage
		}
		return nil, govConflict(GovCodeRolloutConflict, "Only a rollout in canary can expand.", map[string]any{"stage": st})
	}
	if err := policyUsable(rc.Policy); err != nil {
		return nil, err
	}
	g := rolloutResults(rc.Rollout)
	if g.Canary == nil {
		return nil, govConflict(GovCodeGatesNotPassed, "The canary has no deployment.", nil)
	}
	depID := g.Canary.DeploymentID
	// A first look outside the transaction: refuse early (no AWS reads for
	// the other targets' approvals) when the canary cannot expand. The
	// decision itself is taken again below, on facts read under lock in the
	// transaction that acts on it.
	pre, err := r.evaluateGates(ctx, db, ws, rc, depID, 0)
	if err != nil {
		return nil, err
	}
	if err := expandRefusal(pre, in, extra); err != nil {
		return nil, err
	}
	preps := map[uuid.UUID]*govPrepared{}
	refused := map[uuid.UUID]GovRolloutRefusal{}
	ct, err := rc.canary()
	if err != nil {
		return nil, err
	}
	for _, t := range rc.Targets {
		if t.Target.ID == ct.Target.ID {
			continue
		}
		p, err := r.prepare(ctx, ws, rc, t)
		if err != nil {
			rf, ok := refusalOf(t, err)
			if !ok {
				return nil, err
			}
			refused[t.Target.ID] = rf
			continue
		}
		preps[t.Target.ID] = p
	}
	var firstRefusal error
	err = db.Transaction(func(tx *gorm.DB) error {
		var cur models.IGAGovPolicyVersion
		if err := tx.Where("workspace_id = ? AND id = ?", ws, v.ID).Clauses(lockForUpdate()).Take(&cur).Error; err != nil {
			return err
		}
		rc, err := r.loadVersionCtx(tx, ws, cur, true)
		if err != nil {
			return err
		}
		if rc.Rollout == nil || rc.Rollout.Stage != models.GovRolloutCanary {
			return govConflict(GovCodeRolloutConflict, "The rollout moved on; read it again.", nil)
		}
		if err := policyUsable(rc.Policy); err != nil {
			return err
		}
		if gg := rolloutResults(rc.Rollout); gg.Canary == nil || gg.Canary.DeploymentID != depID {
			return govConflict(GovCodeRolloutConflict, "The rollout moved on; read it again.", nil)
		}
		// The decision: gates read here, under lock, and acted on in this
		// transaction (DECISION R13).
		if err := lockCanaryFactsTx(tx, ws, depID); err != nil {
			return err
		}
		ev, err := r.evaluateGates(ctx, tx, ws, rc, depID, 0)
		if err != nil {
			return err
		}
		if err := expandRefusal(ev, in, extra); err != nil {
			return err
		}
		ak, aid := actorPair(actor)
		now := r.now().UTC()
		for _, a := range in.AcceptNotAvailable {
			if ev.accepted[a.Gate] {
				continue // already accepted for this window: one row per (rollout, gate, window)
			}
			var gr igagov.GateResult
			for _, x := range ev.result.Gates {
				if x.Gate == a.Gate {
					gr = x
				}
			}
			stage := models.GovRolloutCanary
			rid := rc.Rollout.ID
			row := models.IGAGovAcceptance{ID: uuid.New(), WorkspaceID: ws, Kind: models.GovAcceptGateNotAvailable, ItemKey: a.Gate,
				ItemHash: gateItemHash(gr), VersionID: cur.ID, RolloutID: &rid, Stage: &stage,
				WindowStart: ev.canary.WindowStart, WindowEnd: ev.canary.WindowEnd, Reason: strings.TrimSpace(a.Reason),
				AcceptedBy: actor, AcceptedAt: now}
			if err := tx.Create(&row).Error; err != nil {
				if isUniqueViolation(err, "uq_iga_gov_acceptance_gate") {
					return govConflict(GovCodeRolloutConflict, "This gate was accepted for this window at the same time; read the rollout again.",
						map[string]any{"gate": a.Gate})
				}
				return err
			}
			if err := appendGovEvent(tx, ws, GovEventRolloutGateAccepted, ak, aid, rc.refs(&depID), map[string]any{
				"acceptance_id": row.ID, "rollout_id": rid, "gate": a.Gate, "item_hash": row.ItemHash, "gate_reason": gr.Reason,
				"window_start": row.WindowStart, "window_end": row.WindowEnd, "reason": row.Reason}); err != nil {
				return err
			}
			ev.accepted[a.Gate] = true
		}
		ev.canary.Accepted = []string{}
		for _, gr := range ev.result.Gates {
			if gr.Outcome == igagov.OutcomeNotAvailable && ev.accepted[gr.Gate] {
				ev.canary.Accepted = append(ev.canary.Accepted, gr.Gate)
			}
		}
		ev.canary.Pass = true
		gg := rolloutResults(rc.Rollout)
		gg.Canary = &ev.canary
		var created int
		created, firstRefusal, err = r.advanceTx(tx, ws, actor, rc, gg, preps, refused, in.Reason)
		if err != nil {
			return err
		}
		if created == 0 && firstRefusal != nil && len(rc.Targets) > 1 {
			return firstRefusal
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return r.view(db, ws, *v)
}

// expandRefusal is the manual expand's check of an evaluation: the canary
// is applied; every gate named for acceptance is not_available now; and the
// canary is healthy by the same rule the automatic tick applies
// (canaryHealthy: healthy state, no failed gate, every gate passed or
// accepted).
func expandRefusal(ev *gateEval, in GovRolloutExpandInput, extra map[string]bool) error {
	if ev.facts.AppliedAt == nil {
		return govConflict(GovCodeGatesNotPassed, "The canary is not applied yet.", map[string]any{"state": ev.facts.State, "gates": []any{}})
	}
	for i, a := range in.AcceptNotAvailable {
		ok := false
		for _, gr := range ev.result.Gates {
			if gr.Gate == a.Gate && gr.Outcome == igagov.OutcomeNotAvailable {
				ok = true
			}
		}
		if !ok {
			return GovBadParam(fmt.Sprintf("accept_not_available[%d].gate", i), "Only a gate that is not_available now can be accepted.")
		}
	}
	if !healthyState(ev.facts.State) {
		return govConflict(GovCodeGatesNotPassed, "The canary deployment is "+ev.facts.State+"; the rollout cannot expand from it.",
			map[string]any{"state": ev.facts.State, "state_reason": ev.facts.StateReason, "gates": ev.result.Gates})
	}
	if !canaryHealthy(ev, extra) {
		return govConflict(GovCodeGatesNotPassed, "The canary's gates have not passed.", map[string]any{"gates": ev.failing(extra),
			"not_available": ev.result.NotAvailable, "accepted": ev.canary.Accepted})
	}
	return nil
}

// advanceTx moves a canary whose gates passed on: a single target
// completes; several expand (one deployment per other target, refusals
// recorded), then settles. It returns how many deployments it created and
// the first refusal as an error.
func (r *GovRollout) advanceTx(tx *gorm.DB, ws, actor uuid.UUID, rc *govRolloutCtx, g GovRolloutResults,
	preps map[uuid.UUID]*govPrepared, refused map[uuid.UUID]GovRolloutRefusal, reason string) (int, error, error) {
	ro := rc.Rollout
	ak, aid := actorPair(actor)
	if len(rc.Targets) <= 1 {
		// §8.4 / DECISION R13: the single target's canary is the whole
		// rollout, and the rollout is complete only once that deployment is
		// verified; with its gates passed it waits in canary (the periodic
		// tick completes it when the verify job proves it).
		var states []string
		if err := tx.Raw(`SELECT state FROM iga_gov_deployment WHERE workspace_id = ? AND id = ?`, ws, g.Canary.DeploymentID).
			Scan(&states).Error; err != nil {
			return 0, nil, err
		}
		if len(states) != 1 || states[0] != models.GovDeployVerified {
			return 0, nil, r.saveTx(tx, ro, g)
		}
		ro.Stage = models.GovRolloutComplete
		if err := r.saveTx(tx, ro, g); err != nil {
			return 0, nil, err
		}
		return 0, nil, appendGovEvent(tx, ws, GovEventRolloutCompleted, ak, aid, rc.refs(nil), map[string]any{
			"rollout_id": ro.ID, "single_target": true, "accepted_gates": g.Canary.Accepted, "reason": reason})
	}
	ct, err := rc.canary()
	if err != nil {
		return 0, nil, err
	}
	exp := &GovRolloutExpansion{At: r.now().UTC(), Deployments: []uuid.UUID{}, Refused: []GovRolloutRefusal{}}
	var first error
	for _, t := range rc.Targets {
		if t.Target.ID == ct.Target.ID {
			continue
		}
		var derr error
		if rf, ok := refused[t.Target.ID]; ok {
			exp.Refused = append(exp.Refused, rf)
			derr = govConflict(rf.Code, rf.Message, rf.Detail)
		} else {
			// A savepoint per target: a refusal inside createDeploymentTx
			// (e.g. the in-flight index) must not abort the others.
			sp := "rollout_target_" + strings.ReplaceAll(t.Target.ID.String(), "-", "")
			if err := tx.SavePoint(sp).Error; err != nil {
				return 0, nil, err
			}
			dep, err := r.createDeploymentTx(tx, ws, actor, rc, t, preps[t.Target.ID])
			if err != nil {
				rf, ok := refusalOf(t, err)
				if !ok {
					return 0, nil, err
				}
				if err := tx.RollbackTo(sp).Error; err != nil {
					return 0, nil, err
				}
				exp.Refused = append(exp.Refused, rf)
				derr = err
			} else {
				exp.Deployments = append(exp.Deployments, dep.ID)
			}
		}
		if derr != nil {
			if first == nil {
				first = derr
			}
			rf := exp.Refused[len(exp.Refused)-1]
			if err := appendGovEvent(tx, ws, GovEventRolloutDeploymentRefused, ak, aid, rc.refs(nil), map[string]any{
				"rollout_id": ro.ID, "target_id": rf.TargetID, "role_id": rf.RoleID, "code": rf.Code, "detail": rf.Detail}); err != nil {
				return 0, nil, err
			}
		}
	}
	g.Expansion = exp
	ro.Stage = models.GovRolloutExpand
	if err := r.saveTx(tx, ro, g); err != nil {
		return 0, nil, err
	}
	if err := appendGovEvent(tx, ws, GovEventRolloutExpanded, ak, aid, rc.refs(nil), map[string]any{
		"rollout_id": ro.ID, "deployments": exp.Deployments, "refused": len(exp.Refused), "accepted_gates": g.Canary.Accepted,
		"reason": reason}); err != nil {
		return 0, nil, err
	}
	if err := r.settleTx(tx, ws, rc); err != nil {
		return 0, nil, err
	}
	return len(exp.Deployments), first, nil
}

// settleTx ends an expanding rollout once every deployment is terminal:
// complete when all verified and none refused, partial otherwise (E-05).
func (r *GovRollout) settleTx(tx *gorm.DB, ws uuid.UUID, rc *govRolloutCtx) error {
	ro := rc.Rollout
	if ro.Stage != models.GovRolloutExpand {
		return nil
	}
	ds, err := r.versionDeployments(tx, ws, rc.Version.ID)
	if err != nil {
		return err
	}
	latest := map[uuid.UUID]models.IGAGovDeployment{}
	for _, d := range ds {
		latest[d.ControlID] = d
	}
	g := rolloutResults(ro)
	verified, failed, pending := 0, 0, 0
	for _, d := range latest {
		switch d.State {
		case models.GovDeployVerified:
			verified++
		case models.GovDeployFailed, models.GovDeployUndone, models.GovDeploySuperseded, models.GovDeployDrifted, models.GovDeployRecovered:
			failed++
		default:
			pending++
		}
	}
	if g.Expansion != nil {
		failed += len(g.Expansion.Refused)
	}
	if pending > 0 {
		return nil
	}
	name := GovEventRolloutCompleted
	ro.Stage = models.GovRolloutComplete
	if failed > 0 {
		ro.Stage, name = models.GovRolloutPartial, GovEventRolloutPartial
	}
	if err := r.saveTx(tx, ro, g); err != nil {
		return err
	}
	return appendGovEvent(tx, ws, name, models.GovActorSystem, "rollout", rc.refs(nil), map[string]any{
		"rollout_id": ro.ID, "verified": verified, "failed": failed})
}

/* ------------------------------- reads ------------------------------------ */

// Get is GET /policies/:id/rollout[?version_no]: the policy's active
// rollout, else the newest version's rollout.
func (r *GovRollout) Get(ctx context.Context, ws, policyID uuid.UUID, versionNo *int) (*GovRolloutView, error) {
	db := r.db.WithContext(ctx)
	v, err := r.policyVersionFor(db, ws, policyID, versionNo, false)
	if err != nil {
		var ge *GovError
		if !errors.As(err, &ge) || ge.Code != GovCodeRolloutNotStarted || versionNo != nil {
			return nil, err
		}
		var vs []models.IGAGovPolicyVersion
		if err := db.Raw(`SELECT v.* FROM iga_gov_policy_version v
			JOIN iga_gov_rollout r ON r.workspace_id = v.workspace_id AND r.version_id = v.id
			WHERE v.workspace_id = ? AND v.policy_id = ? ORDER BY v.version_no DESC LIMIT 1`, ws, policyID).Scan(&vs).Error; err != nil {
			return nil, err
		}
		if len(vs) == 0 {
			return nil, govErr(http.StatusNotFound, GovCodeRolloutNotStarted, "The policy has no rollout.", nil)
		}
		v = &vs[0]
	}
	return r.view(db, ws, *v)
}

func (r *GovRollout) view(db *gorm.DB, ws uuid.UUID, v models.IGAGovPolicyVersion) (*GovRolloutView, error) {
	var cur models.IGAGovPolicyVersion
	if err := db.Where("workspace_id = ? AND id = ?", ws, v.ID).Take(&cur).Error; err != nil {
		return nil, err
	}
	var ros []models.IGAGovRollout
	if err := db.Where("workspace_id = ? AND version_id = ?", ws, v.ID).Limit(1).Find(&ros).Error; err != nil {
		return nil, err
	}
	if len(ros) == 0 {
		return nil, govErr(http.StatusNotFound, GovCodeRolloutNotStarted, "This version has no rollout.", nil)
	}
	out := &GovRolloutView{Rollout: ros[0], Results: rolloutResults(&ros[0]), PolicyID: cur.PolicyID, VersionNo: cur.VersionNo,
		Version: cur.Status, Deployments: []GovRolloutDeployment{}, Acceptances: []models.IGAGovAcceptance{}, Actions: []string{}}
	if err := db.Raw(`SELECT d.id, t.id AS target_id, c.role_id, t.is_canary AS canary, d.state, d.applied_at, d.created_at
		FROM iga_gov_deployment d
		JOIN iga_gov_control c ON c.workspace_id = d.workspace_id AND c.id = d.control_id
		JOIN iga_gov_target t ON t.workspace_id = d.workspace_id AND t.version_id = d.version_id AND t.control_id = d.control_id
		WHERE d.workspace_id = ? AND d.version_id = ? AND d.kind = 'apply' ORDER BY d.created_at, d.id`, ws, v.ID).
		Scan(&out.Deployments).Error; err != nil {
		return nil, err
	}
	if err := db.Where("workspace_id = ? AND rollout_id = ?", ws, ros[0].ID).Order("accepted_at, id").Find(&out.Acceptances).Error; err != nil {
		return nil, err
	}
	switch ros[0].Stage {
	case models.GovRolloutPaused:
		if p := out.Results.Pause; p != nil && p.Kind != GovPauseReturnedToDraft {
			out.Actions = append(out.Actions, "resume")
		}
		if len(out.Results.UndoOffered) > 0 {
			out.Actions = append(out.Actions, "undo_canary")
		}
	case models.GovRolloutCanary:
		out.Actions = append(out.Actions, "expand", "pause")
	case models.GovRolloutAwaitingApproval:
		out.Actions = append(out.Actions, "start", "pause")
	case models.GovRolloutObserve, models.GovRolloutExpand:
		out.Actions = append(out.Actions, "pause")
	}
	return out, nil
}

// RolloutPausedForDeployment reports whether the rollout that created an
// apply deployment is paused (DECISION R9). The deploy job consults it
// before starting a queued deployment (and again, under the rollout row's
// lock, in the transaction that starts it: rolloutHoldsDeploymentTx); an
// undo or control removal of the version is never held.
func RolloutPausedForDeployment(db *gorm.DB, ws, deploymentID uuid.UUID) (bool, error) {
	var n int64
	err := db.Raw(`SELECT count(*) FROM iga_gov_rollout r JOIN iga_gov_deployment d
		ON d.workspace_id = r.workspace_id AND d.version_id = r.version_id
		WHERE d.workspace_id = ? AND d.id = ? AND d.kind = 'apply' AND r.stage = 'paused'`, ws, deploymentID).Scan(&n).Error
	return n > 0, err
}
