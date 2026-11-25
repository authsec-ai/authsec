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
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentcontain"
	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/awsremediate"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// Remediation (SPEC-secops-backend-upgrade.md W8, P5, C11; decision 2).
//
// A remediation is one change to the customer's estate that ends a risk:
// remove a grant, rotate a secret, an IAM user's key or a provider admin key
// AuthSec holds, retire an agent, or revert a policy to a snapshot (W9). It
// is requested with its target (POST /remediations); AuthSec then computes
//
//   - its steps, each with the exact before-state read now (kept so a
//     revert can restore it) and the intended after-state;
//   - its collateral: which other principals, workloads and agents lose
//     what (a shared role, a customer-managed policy attached elsewhere);
//   - its mode: WRITE only when the account has a verified remediation role
//     (decision 2) and the target is not managed as code; IAC_PR when the
//     target belongs to a CloudFormation stack or carries Terraform hints
//     and the account has an IaC source; PREPARED otherwise -- the exact
//     API calls, documents and CLI commands, never a write;
//   - the prepared change, in every mode.
//
// Applying is tier 4 (POST /remediations/:id/apply): the caller must hold
// governance:remediate NOW (read from the database); a write then needs a
// second person holding governance:approve, through the generic pending
// change (kind remediation.apply) -- unless no other member holds it, when
// it runs alone as break-glass with a review due in 24 h (decision 4). A
// pull request is opened at once: its review by the code owners is the
// second person (an ask to them). After a write AuthSec reads every step
// back; the remediation is PROVEN only with both the change event (the
// CloudTrail record of the write, from the W1 evidence store, made by the
// remediation's own session) and a read of the end state, else it stays
// APPLIED with what is missing (GET /remediations/:id/proof).
//
// Every statement runs under row-level security for the token's workspace;
// another workspace's remediation is 404.

// Kinds.
const (
	RemediationRemoveGrant       = "remove_grant"
	RemediationRotateSecret      = "rotate_secret"
	RemediationRotateIAMKey      = "rotate_iam_key"
	RemediationRotateProviderKey = "rotate_provider_key"
	RemediationRetireAgent       = "retire_agent"
	RemediationRevertSnapshot    = "revert_snapshot"
)

// RemediationKinds lists the kinds.
var RemediationKinds = []string{RemediationRemoveGrant, RemediationRotateSecret, RemediationRotateIAMKey,
	RemediationRotateProviderKey, RemediationRetireAgent, RemediationRevertSnapshot}

// States.
const (
	RemediationDraft            = "draft"
	RemediationPrepared         = "prepared"
	RemediationAwaitingApproval = "awaiting_approval"
	RemediationApplying         = "applying"
	RemediationApplied          = "applied"
	RemediationProven           = "proven"
	RemediationFailed           = "failed"
	RemediationPROpen           = "pr_open"
	RemediationPRMerged         = "pr_merged"
	// RemediationPRClosed: the pull request was closed unmerged; the
	// decision is open again (apply opens a new one, or cancel).
	RemediationPRClosed  = "pr_closed"
	RemediationCancelled = "cancelled"
)

// Modes.
const (
	RemediationModeWrite    = "write"
	RemediationModePrepared = "prepared"
	RemediationModeIaCPR    = "iac_pr"
)

// Non-AWS steps.
const (
	RemOpProviderKeyRotate    = "provider_key_rotate"
	RemOpProviderKeyCreate    = "provider_key_create"
	RemOpProviderKeyRevokeOld = "provider_key_revoke_old"
	RemOpGatewayRulesRemove   = "gateway_rules_remove"
	RemOpAgentRetire          = "agent_retire"
	remSourceAuthSec          = "authsec"
)

// Mode reasons.
const (
	RemReasonNoRole          = "remediation_role_not_connected"
	RemReasonIaCNoSource     = "managed_as_code_no_source"
	RemReasonRotationOff     = "rotation_not_configured"
	RemReasonNoHandover      = "no_handover_secret"
	RemReasonHandoverUntag   = "handover_secret_not_tagged"
	RemReasonKeyLimit        = "access_key_limit"
	RemReasonProviderNoWrite = "provider_cannot_create_keys"
	RemReasonPrepareOnly     = "provider_prepared_only"
	RemReasonReaderMissing   = "discovery_role_unavailable"
)

// Error codes.
const (
	GovCodeRemediationUnavailable = "remediation_unavailable"
	RemCodeOpen                   = "remediation_open"
	RemCodeState                  = "remediation_state"
	RemCodeRemediateRequired      = "remediate_permission_required"
	RemCodePrepared               = "remediation_prepared_only"
	RemCodeGrantNotFound          = "grant_not_found"
	RemCodeUnsupported            = "remediation_unsupported"
	RemCodeTargetNotFound         = "target_not_found"
	PendingChangeKindRemediation  = "remediation.apply"
	maxRemediationReason          = 2000
	remediationDefaultGraceHours  = 24
)

// Event names (category remediation).
const (
	GovCatRemediation                  = "remediation"
	GovObjRemediation                  = "remediation"
	GovEventRemediationRequested       = "remediation.requested"
	GovEventRemediationApplyRequested  = "remediation.apply_requested"
	GovEventRemediationApproved        = "remediation.approved"
	GovEventRemediationBreakGlass      = "remediation.break_glass"
	GovEventRemediationApplied         = "remediation.applied"
	GovEventRemediationStepApplied     = "remediation.step_applied"
	GovEventRemediationFailed          = "remediation.failed"
	GovEventRemediationProven          = "remediation.proven"
	GovEventRemediationCancelled       = "remediation.cancelled"
	GovEventRemediationAskNeeded       = "remediation.ask_needed"
	GovEventRemediationPROpened        = "remediation.pr_opened"
	GovEventRemediationPRMerged        = "remediation.pr_merged"
	GovEventRemediationPRClosed        = "remediation.pr_closed"
	GovEventRemediationBindingCreated  = "remediation_binding.created"
	GovEventRemediationBindingVerified = "remediation_binding.verified"
	GovEventRemediationBindingFailed   = "remediation_binding.failed"
	GovEventRemediationBindingRevoked  = "remediation_binding.revoked"
)

var remediationVocabulary = []GovEventKind{
	{GovEventRemediationRequested, GovCatRemediation, GovObjRemediation, "A remediation was requested; its steps, collateral, mode and prepared change were computed."},
	{GovEventRemediationApplyRequested, GovCatRemediation, GovObjRemediation, "Applying a remediation (tier 4) waits for a second person with governance:approve."},
	{GovEventRemediationApproved, GovCatRemediation, GovObjRemediation, "A second person approved a remediation's write; it runs now."},
	{GovEventRemediationBreakGlass, GovCatRemediation, GovObjRemediation, "A remediation was applied without a second person (no other approver); a review is due within 24 hours."},
	{GovEventRemediationApplied, GovCatRemediation, GovObjRemediation, "A remediation's writes were made and read back (proof may still miss the change event)."},
	{GovEventRemediationStepApplied, GovCatRemediation, GovObjRemediation, "A deferred remediation step ran (an old access key deactivated after its grace)."},
	{GovEventRemediationFailed, GovCatRemediation, GovObjRemediation, "A remediation step was refused or failed; the steps before it stay applied with their before-state."},
	{GovEventRemediationProven, GovCatRemediation, GovObjRemediation, "A remediation is proven: every change event was received and a read shows the end state."},
	{GovEventRemediationCancelled, GovCatRemediation, GovObjRemediation, "A remediation was cancelled before it changed anything."},
	{GovEventRemediationAskNeeded, GovCatRemediation, GovObjRemediation, "A person must act on a remediation (code owners, a provider console step, a closed pull request); an ask once W4 lands."},
	{GovEventRemediationPROpened, GovCatRemediation, GovObjRemediation, "A remediation of a resource managed as code was opened as a pull request for its code owners."},
	{GovEventRemediationPRMerged, GovCatRemediation, GovObjRemediation, "A remediation's pull request was merged; the proof follows from the account."},
	{GovEventRemediationPRClosed, GovCatRemediation, GovObjRemediation, "A remediation's pull request was closed unmerged; the decision is open again."},
	{GovEventRemediationBindingCreated, GovCatRemediation, "", "A remediation role setup was started for an account (ExternalId minted)."},
	{GovEventRemediationBindingVerified, GovCatRemediation, "", "A remediation role was assumed with its ExternalId in the account: remediations of the account can write."},
	{GovEventRemediationBindingFailed, GovCatRemediation, "", "A remediation role could not be verified."},
	{GovEventRemediationBindingRevoked, GovCatRemediation, "", "A remediation role binding was revoked: remediations of the account are prepared again."},
}

func init() { GovEventVocabulary = append(GovEventVocabulary, remediationVocabulary...) }

// RemediationSchemaHead is the migration remediation needs.
const RemediationSchemaHead = "230"

var remediationGate = &agentSchemaGate{head: RemediationSchemaHead, relations: []string{
	"cloud_remediation_binding", "agent_remediation", "agent_remediation_step", "pending_change"},
	columns: [][2]string{{"agent_remediation", "lease_until"}}}

// RemediationStatus is whether remediation can run (migration 230).
func RemediationStatus(db *gorm.DB) (bool, string) { return remediationGate.status(db) }

// RequireRemediation is nil while remediation can run, else the 503.
func RequireRemediation(db *gorm.DB) error {
	if ok, reason := RemediationStatus(db); !ok {
		return govErr(http.StatusServiceUnavailable, GovCodeRemediationUnavailable,
			"Remediation is not available on this server.", map[string]any{"reason": reason})
	}
	return nil
}

// RemediationCapabilities is /capabilities' remediation block.
func RemediationCapabilities(db *gorm.DB) map[string]any {
	ok, reason := RemediationStatus(db)
	return map[string]any{"available": ok, "reason": nullable(reason), "kinds": RemediationKinds, "writers": RemediationWriters}
}

/* ---------------------------------- types ---------------------------------- */

// RemediationTarget names what a remediation acts on.
type RemediationTarget struct {
	Provider string         `json:"provider"`
	Ref      string         `json:"ref"`
	Detail   map[string]any `json:"detail,omitempty"`
}

// RemediationRequest is POST /remediations.
type RemediationRequest struct {
	Kind   string
	Target RemediationTarget
	CaseID *uuid.UUID
	Reason string
}

// CollateralPrincipal is a principal that loses something.
type CollateralPrincipal struct {
	ARN    string `json:"arn"`
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
}

// CollateralWorkload is a workload running as a principal that loses
// something.
type CollateralWorkload struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	RuntimeKind string    `json:"runtime_kind"`
	IdentityARN string    `json:"identity_arn"`
}

// RemediationCollateral is who else loses what.
type RemediationCollateral struct {
	Summary        string                `json:"summary"`
	Loses          []string              `json:"loses"`
	Principals     []CollateralPrincipal `json:"principals"`
	Workloads      []CollateralWorkload  `json:"workloads"`
	Agents         []uuid.UUID           `json:"agents"`
	SharedIdentity bool                  `json:"shared_identity"`
	Notes          []string              `json:"notes"`
}

// RemediationIaC is the IaC detection of a target.
type RemediationIaC struct {
	Managed  bool       `json:"managed"`
	Tool     string     `json:"tool,omitempty"`
	Stack    string     `json:"stack,omitempty"`
	Evidence string     `json:"evidence,omitempty"`
	SourceID *uuid.UUID `json:"source_id,omitempty"`
}

// RemediationStepView is one step as the API shows it.
type RemediationStepView struct {
	Seq         int             `json:"seq"`
	Op          string          `json:"op"`
	Target      string          `json:"target"`
	EventSource string          `json:"event_source"`
	EventName   string          `json:"event_name"`
	Before      json.RawMessage `json:"before"`
	After       json.RawMessage `json:"after"`
	Readback    json.RawMessage `json:"readback"`
	State       string          `json:"state"`
	Error       string          `json:"error"`
	DueAt       *time.Time      `json:"due_at"`
	AppliedAt   *time.Time      `json:"applied_at"`
}

// RemediationPR is a remediation's pull request.
type RemediationPR struct {
	Number int    `json:"number"`
	URL    string `json:"url"`
	Branch string `json:"branch"`
	State  string `json:"state"`
}

// RemediationView is a remediation as the API shows it.
type RemediationView struct {
	ID              uuid.UUID             `json:"id"`
	Kind            string                `json:"kind"`
	Target          RemediationTarget     `json:"target"`
	TargetKind      string                `json:"target_kind"`
	ConnectorID     *uuid.UUID            `json:"connector_id"`
	AgentID         *uuid.UUID            `json:"agent_id"`
	CaseID          *uuid.UUID            `json:"case_id"`
	State           string                `json:"state"`
	StateReason     string                `json:"state_reason"`
	Mode            string                `json:"mode"`
	ModeReason      string                `json:"mode_reason"`
	Reason          string                `json:"reason"`
	RequestedBy     uuid.UUID             `json:"requested_by"`
	ApprovedBy      *uuid.UUID            `json:"approved_by"`
	PendingChangeID *uuid.UUID            `json:"pending_change_id"`
	BreakGlass      bool                  `json:"break_glass"`
	Collateral      json.RawMessage       `json:"collateral"`
	Prepared        json.RawMessage       `json:"prepared"`
	IaC             json.RawMessage       `json:"iac"`
	Proof           json.RawMessage       `json:"proof"`
	Error           string                `json:"error"`
	SessionName     string                `json:"session_name"`
	PR              *RemediationPR        `json:"pull_request"`
	Asks            json.RawMessage       `json:"asks"`
	CreatedAt       time.Time             `json:"created_at"`
	UpdatedAt       time.Time             `json:"updated_at"`
	ApplyRequested  *time.Time            `json:"apply_requested_at"`
	AppliedAt       *time.Time            `json:"applied_at"`
	ProvenAt        *time.Time            `json:"proven_at"`
	CancelledAt     *time.Time            `json:"cancelled_at"`
	Steps           []RemediationStepView `json:"steps,omitempty"`
}

type remediationRow struct {
	ID              uuid.UUID  `gorm:"column:id"`
	Kind            string     `gorm:"column:kind"`
	TargetProvider  string     `gorm:"column:target_provider"`
	TargetKind      string     `gorm:"column:target_kind"`
	TargetRef       string     `gorm:"column:target_ref"`
	TargetDetail    string     `gorm:"column:target_detail"`
	ConnectorID     *uuid.UUID `gorm:"column:connector_id"`
	AgentID         *uuid.UUID `gorm:"column:agent_id"`
	CaseID          *uuid.UUID `gorm:"column:case_id"`
	State           string     `gorm:"column:state"`
	StateReason     string     `gorm:"column:state_reason"`
	Mode            string     `gorm:"column:mode"`
	ModeReason      string     `gorm:"column:mode_reason"`
	Reason          string     `gorm:"column:reason"`
	RequestedBy     uuid.UUID  `gorm:"column:requested_by"`
	ApprovedBy      *uuid.UUID `gorm:"column:approved_by"`
	PendingChangeID *uuid.UUID `gorm:"column:pending_change_id"`
	BreakGlass      bool       `gorm:"column:break_glass"`
	Collateral      string     `gorm:"column:collateral"`
	Prepared        string     `gorm:"column:prepared"`
	IaC             string     `gorm:"column:iac"`
	Proof           string     `gorm:"column:proof"`
	Error           string     `gorm:"column:error"`
	SessionName     string     `gorm:"column:session_name"`
	PlanHash        string     `gorm:"column:plan_hash"`
	IaCSourceID     *uuid.UUID `gorm:"column:iac_source_id"`
	PRNumber        *int       `gorm:"column:pr_number"`
	PRURL           string     `gorm:"column:pr_url"`
	PRBranch        string     `gorm:"column:pr_branch"`
	PRState         string     `gorm:"column:pr_state"`
	PRCount         int        `gorm:"column:pr_count"`
	Asks            string     `gorm:"column:asks"`
	ApplyRequested  *time.Time `gorm:"column:apply_requested_at"`
	AppliedAt       *time.Time `gorm:"column:applied_at"`
	ProvenAt        *time.Time `gorm:"column:proven_at"`
	CancelledAt     *time.Time `gorm:"column:cancelled_at"`
	CreatedAt       time.Time  `gorm:"column:created_at"`
	UpdatedAt       time.Time  `gorm:"column:updated_at"`
}

const remediationCols = `id, kind, target_provider, target_kind, target_ref, target_detail::text AS target_detail, connector_id,
	agent_id, case_id, state, state_reason, mode, mode_reason, reason, requested_by, approved_by, pending_change_id, break_glass,
	collateral::text AS collateral, prepared::text AS prepared, iac::text AS iac, proof::text AS proof, error, session_name,
	plan_hash, iac_source_id, pr_number, pr_url, pr_branch, pr_state, pr_count, asks::text AS asks, apply_requested_at,
	applied_at, proven_at, cancelled_at, created_at, updated_at`

type remediationStepRow struct {
	ID          uuid.UUID  `gorm:"column:id"`
	Seq         int        `gorm:"column:seq"`
	Op          string     `gorm:"column:op"`
	Target      string     `gorm:"column:target"`
	EventSource string     `gorm:"column:event_source"`
	EventName   string     `gorm:"column:event_name"`
	Before      string     `gorm:"column:before"`
	After       string     `gorm:"column:after"`
	Readback    string     `gorm:"column:readback"`
	State       string     `gorm:"column:state"`
	Error       string     `gorm:"column:error"`
	DueAt       *time.Time `gorm:"column:due_at"`
	AppliedAt   *time.Time `gorm:"column:applied_at"`
}

const remediationStepCols = `id, seq, op, target, event_source, event_name, before::text AS before, after::text AS after,
	readback::text AS readback, state, error, due_at, applied_at`

func rawOr(s, d string) json.RawMessage {
	if strings.TrimSpace(s) == "" {
		return json.RawMessage(d)
	}
	return json.RawMessage(s)
}

func (r remediationRow) view() RemediationView {
	v := RemediationView{ID: r.ID, Kind: r.Kind, TargetKind: r.TargetKind, ConnectorID: r.ConnectorID, AgentID: r.AgentID,
		CaseID: r.CaseID, State: r.State, StateReason: r.StateReason, Mode: r.Mode, ModeReason: r.ModeReason, Reason: r.Reason,
		RequestedBy: r.RequestedBy, ApprovedBy: r.ApprovedBy, PendingChangeID: r.PendingChangeID, BreakGlass: r.BreakGlass,
		Collateral: rawOr(r.Collateral, "{}"), Prepared: rawOr(r.Prepared, "{}"), IaC: rawOr(r.IaC, "{}"), Proof: rawOr(r.Proof, "{}"),
		Error: r.Error, SessionName: r.SessionName, Asks: rawOr(r.Asks, "[]"), CreatedAt: r.CreatedAt.UTC(), UpdatedAt: r.UpdatedAt.UTC(),
		ApplyRequested: utcPtr(r.ApplyRequested), AppliedAt: utcPtr(r.AppliedAt), ProvenAt: utcPtr(r.ProvenAt), CancelledAt: utcPtr(r.CancelledAt)}
	v.Target = RemediationTarget{Provider: r.TargetProvider, Ref: r.TargetRef}
	_ = json.Unmarshal([]byte(r.TargetDetail), &v.Target.Detail)
	if r.PRNumber != nil {
		v.PR = &RemediationPR{Number: *r.PRNumber, URL: r.PRURL, Branch: r.PRBranch, State: r.PRState}
	}
	return v
}

func (s remediationStepRow) view() RemediationStepView {
	return RemediationStepView{Seq: s.Seq, Op: s.Op, Target: s.Target, EventSource: s.EventSource, EventName: s.EventName,
		Before: rawOr(s.Before, "{}"), After: rawOr(s.After, "{}"), Readback: rawOr(s.Readback, "{}"), State: s.State, Error: s.Error,
		DueAt: utcPtr(s.DueAt), AppliedAt: utcPtr(s.AppliedAt)}
}

// step is the engine's view of a stored step.
func (s remediationStepRow) step() awsremediate.Step {
	st := awsremediate.Step{Seq: s.Seq, Op: s.Op, Target: s.Target, EventSource: s.EventSource, EventName: s.EventName,
		Before: map[string]any{}, After: map[string]any{}, DueAt: s.DueAt}
	_ = json.Unmarshal([]byte(s.Before), &st.Before)
	_ = json.Unmarshal([]byte(s.After), &st.After)
	return st
}

func readRemediation(tx *gorm.DB, ws, id uuid.UUID, lock bool) (*remediationRow, error) {
	q := `SELECT ` + remediationCols + ` FROM agent_remediation WHERE workspace_id = ? AND id = ?`
	if lock {
		q += ` FOR UPDATE`
	}
	var rows []remediationRow
	if err := tx.Raw(q, ws, id).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, GovNotFound()
	}
	return &rows[0], nil
}

func readRemediationSteps(tx *gorm.DB, ws, id uuid.UUID) ([]remediationStepRow, error) {
	var rows []remediationStepRow
	err := tx.Raw(`SELECT `+remediationStepCols+` FROM agent_remediation_step WHERE workspace_id = ? AND remediation_id = ? ORDER BY seq`,
		ws, id).Scan(&rows).Error
	return rows, err
}

func remJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

/* --------------------------------- service --------------------------------- */

// RemediationService serves remediations.
type RemediationService struct {
	db  *gorm.DB
	now func() time.Time
}

// NewRemediationService builds the service.
func NewRemediationService(db *gorm.DB) *RemediationService {
	return &RemediationService{db: db, now: time.Now}
}

// WithClock replaces the clock (tests).
func (s *RemediationService) WithClock(now func() time.Time) *RemediationService {
	s.now = now
	return s
}

// RemediationFilter narrows GET /remediations.
type RemediationFilter struct {
	State, Kind string
	CaseID      *uuid.UUID
	Limit       int
}

// List lists the workspace's remediations, newest first.
func (s *RemediationService) List(ctx context.Context, ws uuid.UUID, f RemediationFilter) ([]RemediationView, error) {
	if err := RequireRemediation(s.db); err != nil {
		return nil, err
	}
	if f.Kind != "" && !validRemediationKind(f.Kind) {
		return nil, GovBadParam("kind", "kind must be one of "+strings.Join(RemediationKinds, ", ")+".")
	}
	if f.Limit <= 0 || f.Limit > MaxGovPage {
		f.Limit = 50
	}
	var rows []remediationRow
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		q := `SELECT ` + remediationCols + ` FROM agent_remediation WHERE workspace_id = ?`
		args := []any{ws}
		if f.State != "" {
			q += ` AND state = ?`
			args = append(args, f.State)
		}
		if f.Kind != "" {
			q += ` AND kind = ?`
			args = append(args, f.Kind)
		}
		if f.CaseID != nil {
			q += ` AND case_id = ?`
			args = append(args, *f.CaseID)
		}
		q += ` ORDER BY created_at DESC, id LIMIT ?`
		args = append(args, f.Limit)
		return tx.Raw(q, args...).Scan(&rows).Error
	})
	if err != nil {
		return nil, err
	}
	out := make([]RemediationView, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.view())
	}
	return out, nil
}

// Get reads one remediation with its steps; another workspace's is 404.
func (s *RemediationService) Get(ctx context.Context, ws, id uuid.UUID) (*RemediationView, error) {
	if err := RequireRemediation(s.db); err != nil {
		return nil, err
	}
	var v RemediationView
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		r, err := readRemediation(tx, ws, id, false)
		if err != nil {
			return err
		}
		v = r.view()
		steps, err := readRemediationSteps(tx, ws, id)
		if err != nil {
			return err
		}
		v.Steps = make([]RemediationStepView, 0, len(steps))
		for _, st := range steps {
			v.Steps = append(v.Steps, st.view())
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func validRemediationKind(k string) bool {
	for _, x := range RemediationKinds {
		if x == k {
			return true
		}
	}
	return false
}

/* --------------------------------- planning -------------------------------- */

// remPlan is what Create computes.
type remPlan struct {
	id                  uuid.UUID
	kind                string
	targetProvider      string
	targetKind          string
	targetRef           string
	detail              map[string]any
	connectorID         *uuid.UUID
	agentID             *uuid.UUID
	account, partition  string
	steps               []awsremediate.Step
	askSteps            map[int]RemediationAsk // seq -> ask raised at creation
	collateral          RemediationCollateral
	iac                 RemediationIaC
	forcePrepared       string // a reason this can only be prepared
	awsSteps            bool
	notes               []string
	mode, modeReason    string
	iacSourceID         *uuid.UUID
	previousFingerprint string
}

// remIdentity is a cloud_identity row.
type remIdentity struct {
	ID          uuid.UUID `gorm:"column:id"`
	ConnectorID uuid.UUID `gorm:"column:connector_id"`
	Kind        string    `gorm:"column:kind"`
	NativeID    string    `gorm:"column:native_id"`
	Name        string    `gorm:"column:name"`
	Attrs       string    `gorm:"column:attrs"`
}

func (r remIdentity) attrs() models.AWSIdentityAttrs {
	var a models.AWSIdentityAttrs
	_ = json.Unmarshal([]byte(r.Attrs), &a)
	return a
}

func remIdentityByARN(tx *gorm.DB, ws uuid.UUID, arn string) (*remIdentity, error) {
	var rows []remIdentity
	if err := tx.Raw(`SELECT id, connector_id, kind, native_id, name, attrs::text AS attrs FROM cloud_identity
	    WHERE workspace_id = ? AND native_id = ? LIMIT 1`, ws, arn).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

func remConnectorForAccount(tx *gorm.DB, ws uuid.UUID, account string) (*uuid.UUID, error) {
	var ids []uuid.UUID
	if err := tx.Raw(`SELECT id FROM cloud_connector WHERE workspace_id = ? AND provider = 'aws' AND scope_kind = 'account'
	    AND scope_id = ? AND status = 'active' ORDER BY created_at LIMIT 1`, ws, account).Scan(&ids).Error; err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}
	return &ids[0], nil
}

// remPolicyDoc is a stored cloud_policy document (discovery's last read).
func remPolicyDoc(tx *gorm.DB, ws uuid.UUID, nativeID string) (string, bool, error) {
	var docs []string
	if err := tx.Raw(`SELECT document::text FROM cloud_policy WHERE workspace_id = ? AND native_id = ? AND document IS NOT NULL
	    ORDER BY last_seen_at DESC LIMIT 1`, ws, nativeID).Scan(&docs).Error; err != nil {
		return "", false, err
	}
	if len(docs) == 0 {
		return "", false, nil
	}
	return docs[0], true, nil
}

// remWorkloadsOn lists the workloads running as an identity, and the W7
// agents they belong to.
func remWorkloadsOn(tx *gorm.DB, ws uuid.UUID, identityID uuid.UUID, arn string) ([]CollateralWorkload, []uuid.UUID, error) {
	var wls []CollateralWorkload
	if err := tx.Raw(`SELECT id, name, runtime_kind, ? AS identity_arn FROM cloud_workload WHERE workspace_id = ? AND identity_id = ?
	    ORDER BY name, id LIMIT 200`, arn, ws, identityID).Scan(&wls).Error; err != nil {
		return nil, nil, err
	}
	var agents []uuid.UUID
	if remHasRelation(tx, "agent_alias") {
		if err := tx.Raw(`SELECT DISTINCT al.agent_id FROM agent_alias al
		    JOIN iga_workload w ON w.workspace_id = al.workspace_id AND al.source_table = 'iga_workload' AND al.source_id = w.id::text
		   WHERE al.workspace_id = ? AND w.execution_role_arn = ? ORDER BY al.agent_id`, ws, arn).Scan(&agents).Error; err != nil {
			return nil, nil, err
		}
	}
	return wls, agents, nil
}

func remHasRelation(tx *gorm.DB, rel string) bool {
	var n int64
	// TENANT-EXEMPT: reads the Postgres catalog only (to_regclass), no workspace data.
	_ = tx.Raw(`SELECT count(*) FROM pg_class WHERE oid = to_regclass(?)`, "public."+rel).Scan(&n).Error
	return n > 0
}

// remHolders lists the principals a managed policy is attached to.
func remHolders(tx *gorm.DB, ws uuid.UUID, policyARN string) ([]CollateralPrincipal, error) {
	var out []CollateralPrincipal
	err := tx.Raw(`SELECT DISTINCT ci.native_id AS arn, ci.kind AS kind, 'holds_policy' AS reason
	    FROM cloud_policy cp
	    JOIN cloud_policy_attachment pa ON pa.workspace_id = cp.workspace_id AND pa.policy_row_id = cp.id
	    JOIN cloud_identity ci ON ci.workspace_id = pa.workspace_id AND ci.id = pa.principal_identity_id
	   WHERE cp.workspace_id = ? AND cp.native_id = ? AND pa.attachment_kind = 'attached' ORDER BY ci.native_id`, ws, policyARN).Scan(&out).Error
	return out, err
}

// detectIaC reads a target's tags: a CloudFormation stack (the
// aws:cloudformation:stack-name tag CloudFormation puts on what it creates)
// or Terraform hints (tags naming Terraform).
func detectIaC(tags map[string]string) RemediationIaC {
	if s := tags["aws:cloudformation:stack-name"]; s != "" {
		return RemediationIaC{Managed: true, Tool: "cloudformation", Stack: s, Evidence: "tag aws:cloudformation:stack-name"}
	}
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		lk, lv := strings.ToLower(k), strings.ToLower(tags[k])
		switch {
		case strings.HasPrefix(lk, "terraform") || strings.HasPrefix(lk, "tf:") || strings.HasPrefix(lk, "tf_"):
			return RemediationIaC{Managed: true, Tool: "terraform", Evidence: "tag " + k}
		case (lk == "managedby" || lk == "managed_by" || lk == "managed-by" || lk == "provisioner" || lk == "iac") && strings.Contains(lv, "terraform"):
			return RemediationIaC{Managed: true, Tool: "terraform", Evidence: "tag " + k + "=" + tags[k]}
		}
	}
	return RemediationIaC{}
}

func detailString(d map[string]any, k string) string {
	if d == nil {
		return ""
	}
	switch v := d[k].(type) {
	case string:
		return strings.TrimSpace(v)
	}
	return ""
}

func detailInt(d map[string]any, k string, def int) (int, bool) {
	if d == nil || d[k] == nil {
		return def, true
	}
	switch v := d[k].(type) {
	case float64:
		if v != float64(int(v)) {
			return 0, false
		}
		return int(v), true
	case int:
		return v, true
	case string:
		n, err := strconv.Atoi(v)
		return n, err == nil
	}
	return 0, false
}

func isAWSARN(s string) bool { return strings.HasPrefix(s, "arn:aws") }

// Create plans a remediation (POST /remediations): steps, collateral, mode
// and the prepared change. Nothing is written to the customer.
func (s *RemediationService) Create(ctx context.Context, ws, actor uuid.UUID, req RemediationRequest) (*RemediationView, error) {
	if err := RequireRemediation(s.db); err != nil {
		return nil, err
	}
	if !validRemediationKind(req.Kind) {
		return nil, GovBadParam("kind", "kind must be one of "+strings.Join(RemediationKinds, ", ")+".")
	}
	reason, err := checkReason("reason", req.Reason, maxRemediationReason)
	if err != nil {
		return nil, err
	}
	req.Target.Ref = strings.TrimSpace(req.Target.Ref)
	if req.Target.Ref == "" || len(req.Target.Ref) > 2048 {
		return nil, GovBadParam("target.ref", "target.ref is required: the ARN or id of what to remediate.")
	}
	if req.Target.Detail == nil {
		req.Target.Detail = map[string]any{}
	}
	if raw, _ := json.Marshal(req.Target.Detail); len(raw) > 16384 {
		return nil, GovBadParam("target.detail", "target.detail is too large.")
	}
	p := &remPlan{id: uuid.New(), kind: req.Kind, targetRef: req.Target.Ref, detail: req.Target.Detail, askSteps: map[int]RemediationAsk{}}
	switch req.Target.Provider {
	case "", "aws":
		p.targetProvider = "aws"
	case "azure", "k8s", "model_provider", "authsec":
		p.targetProvider = req.Target.Provider
	default:
		return nil, GovBadParam("target.provider", "target.provider must be aws, azure, k8s, model_provider or authsec.")
	}
	// The DB part of planning, then the live reads (outside the
	// transaction), then the mode.
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		if req.CaseID != nil && remHasRelation(tx, "agent_case") {
			var n int64
			if err := tx.Raw(`SELECT count(*) FROM agent_case WHERE workspace_id = ? AND id = ?`, ws, *req.CaseID).Scan(&n).Error; err != nil {
				return err
			}
			if n == 0 {
				return GovBadParam("case_id", "case_id names no case of this workspace.")
			}
		}
		return s.planDB(ctx, tx, ws, p)
	}); err != nil {
		return nil, err
	}
	if err := s.planLive(ctx, ws, p); err != nil {
		return nil, err
	}
	if err := s.decideMode(ctx, ws, p); err != nil {
		return nil, err
	}
	for i := range p.steps {
		p.steps[i].Seq = i + 1
	}
	prepared := remPrepared(p)
	planHash := remPlanHash(p.steps)
	state := RemediationDraft
	if p.mode == RemediationModePrepared {
		state = RemediationPrepared
	}
	session := ""
	if p.mode == RemediationModeWrite && p.awsSteps {
		session = awsremediate.SessionName(p.id.String())
	}
	var out *RemediationView
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		err := tx.Exec(`INSERT INTO agent_remediation (id, workspace_id, kind, target_provider, target_kind, target_ref, target_detail,
		        connector_id, agent_id, case_id, state, mode, mode_reason, reason, requested_by, collateral, prepared, iac, session_name,
		        plan_hash, iac_source_id)
		    VALUES (?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?::jsonb, ?, ?, ?)`,
			p.id, ws, p.kind, p.targetProvider, p.targetKind, p.targetRef, remJSON(p.detail), p.connectorID, p.agentID, req.CaseID,
			state, p.mode, p.modeReason, reason, actor, remJSON(p.collateral), remJSON(prepared), remJSON(p.iac), session,
			planHash, p.iacSourceID).Error
		if isUniqueViolation(err, "uq_agent_remediation_open") {
			var ids []uuid.UUID
			_ = tx.Raw(`SELECT id FROM agent_remediation WHERE workspace_id = ? AND kind = ? AND target_ref = ?
			    AND state IN ('draft','prepared','awaiting_approval','applying','pr_open','pr_closed') LIMIT 1`, ws, p.kind, p.targetRef).Scan(&ids).Error
			detail := map[string]any{}
			if len(ids) > 0 {
				detail["remediation_id"] = ids[0]
			}
			return govConflict(RemCodeOpen, "An open remediation of this kind exists for this target.", detail)
		}
		if err != nil {
			return err
		}
		var asks []map[string]any
		for _, st := range p.steps {
			stepState := "pending"
			if ask, ok := p.askSteps[st.Seq]; ok {
				ask.RemediationID, ask.CaseID, ask.RequestedBy = p.id, req.CaseID, actor
				ref, err := remediationAsks().CreateAsk(tx, ws, ask)
				if err != nil {
					return err
				}
				asks = append(asks, map[string]any{"ref": ref, "role": ask.Role, "reason": ask.Reason, "seq": st.Seq})
				stepState = "asked"
			}
			if err := insertRemediationStep(tx, ws, p.id, st, stepState); err != nil {
				return err
			}
		}
		if len(asks) > 0 {
			if err := tx.Exec(`UPDATE agent_remediation SET asks = ?::jsonb WHERE workspace_id = ? AND id = ?`, remJSON(asks), ws, p.id).Error; err != nil {
				return err
			}
		}
		if err := appendGovEvent(tx, ws, GovEventRemediationRequested, models.GovActorUser, actor.String(), govEventRefs{}, map[string]any{
			"remediation_id": p.id, "kind": p.kind, "target_ref": p.targetRef, "mode": p.mode, "mode_reason": p.modeReason,
			"case_id": req.CaseID, "steps": len(p.steps), "collateral_summary": p.collateral.Summary}); err != nil {
			return err
		}
		r, err := readRemediation(tx, ws, p.id, false)
		if err != nil {
			return err
		}
		v := r.view()
		steps, err := readRemediationSteps(tx, ws, p.id)
		if err != nil {
			return err
		}
		for _, st := range steps {
			v.Steps = append(v.Steps, st.view())
		}
		out = &v
		return nil
	})
	return out, err
}

func insertRemediationStep(tx *gorm.DB, ws, id uuid.UUID, st awsremediate.Step, state string) error {
	return tx.Exec(`INSERT INTO agent_remediation_step (workspace_id, remediation_id, seq, op, target, event_source, event_name,
	        before, after, state, due_at)
	    VALUES (?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?, ?)`,
		ws, id, st.Seq, st.Op, st.Target, st.EventSource, st.EventName, remJSON(st.Before), remJSON(st.After), state, st.DueAt).Error
}

func remPlanHash(steps []awsremediate.Step) string {
	b, _ := json.Marshal(steps)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// remPrepared is the prepared change of every step.
func remPrepared(p *remPlan) map[string]any {
	var steps []any
	for _, st := range p.steps {
		if awsremediate.IsAWSOp(st.Op) {
			steps = append(steps, awsremediate.Prepare(st))
			continue
		}
		steps = append(steps, map[string]any{"seq": st.Seq, "op": st.Op, "description": remNonAWSDescription(st)})
	}
	if steps == nil {
		steps = []any{}
	}
	notes := append([]string{}, p.notes...)
	if p.mode == RemediationModePrepared && p.awsSteps {
		notes = append(notes, "AuthSec will not write this change ("+p.modeReason+"). Run the steps in order; AuthSec proves the change "+
			"from its CloudTrail record and a read of the end state (GET /remediations/:id/proof).")
	}
	return map[string]any{"steps": steps, "notes": notes}
}

func remNonAWSDescription(st awsremediate.Step) string {
	switch st.Op {
	case RemOpProviderKeyCreate:
		return "Create a new admin key for the organisation in the provider's console, then give it to AuthSec with " +
			"POST /api/iga/v1/agent-runtime/model-providers/" + st.Target + "/rotate (AuthSec stores it in Vault and destroys the old one)."
	case RemOpProviderKeyRevokeOld:
		return "After AuthSec reports the new key in use, revoke the old admin key (" + fmt.Sprint(st.Before["fingerprint"]) + ") in the provider's console."
	case RemOpProviderKeyRotate:
		return "AuthSec rotates the admin key through the provider's API and stores the new one in Vault."
	case RemOpGatewayRulesRemove:
		return "Remove the agent's gateway rules."
	case RemOpAgentRetire:
		return "Mark the agent retired in AuthSec (every alias with it)."
	}
	return st.Op
}

/* ------------------------------ per-kind (DB) ------------------------------ */

func (s *RemediationService) planDB(ctx context.Context, tx *gorm.DB, ws uuid.UUID, p *remPlan) error {
	switch p.kind {
	case RemediationRotateProviderKey:
		return s.planProviderKeyDB(tx, ws, p)
	case RemediationRetireAgent:
		return s.planRetireDB(tx, ws, p)
	case RemediationRevertSnapshot:
		return s.planRevertDB(tx, ws, p)
	}
	// AWS targets by ARN.
	if p.targetProvider != "aws" {
		return s.planNonAWSGrant(p)
	}
	if !isAWSARN(p.targetRef) {
		return GovBadParam("target.ref", "target.ref must be an AWS ARN.")
	}
	p.partition, p.account = awsremediate.ARNAccount(p.targetRef)
	if p.account == "" {
		return GovBadParam("target.ref", "target.ref must be an AWS ARN with an account.")
	}
	conn, err := remConnectorForAccount(tx, ws, p.account)
	if err != nil {
		return err
	}
	if conn == nil {
		// Not an account of this workspace: nothing to remediate here.
		return GovNotFound()
	}
	p.connectorID = conn
	switch p.kind {
	case RemediationRemoveGrant:
		return s.planRemoveGrantDB(tx, ws, p)
	case RemediationRotateSecret:
		if !strings.Contains(p.targetRef, ":secretsmanager:") || !strings.Contains(p.targetRef, ":secret:") {
			return GovBadParam("target.ref", "target.ref must be a Secrets Manager secret ARN.")
		}
		p.targetKind = "secret"
		p.collateral.Notes = append(p.collateral.Notes, "Consumers of the secret must read it from Secrets Manager (not a cached copy) to pick up the rotated value.")
		return nil
	case RemediationRotateIAMKey:
		id, err := remIdentityByARN(tx, ws, p.targetRef)
		if err != nil {
			return err
		}
		pr, perr := awsremediate.PrincipalOf(p.targetRef)
		if perr != nil || pr.Kind != awsremediate.PrincipalUser {
			return GovBadParam("target.ref", "target.ref must be an IAM user ARN.")
		}
		if id == nil {
			return GovNotFound()
		}
		p.targetKind = "iam_user"
		if detailString(p.detail, "access_key_id") == "" {
			return GovBadParam("target.detail.access_key_id", "target.detail.access_key_id is required: the key to replace.")
		}
		if h := detailString(p.detail, "handover_secret_arn"); h != "" {
			if _, acct := awsremediate.ARNAccount(h); acct != p.account || !strings.Contains(h, ":secretsmanager:") {
				return GovBadParam("target.detail.handover_secret_arn", "The handover secret must be a Secrets Manager secret in the user's account.")
			}
		}
		if g, ok := detailInt(p.detail, "grace_hours", remediationDefaultGraceHours); !ok || g < 1 || g > 168 {
			return GovBadParam("target.detail.grace_hours", "grace_hours must be 1..168.")
		}
		wls, agents, err := remWorkloadsOn(tx, ws, id.ID, id.NativeID)
		if err != nil {
			return err
		}
		p.collateral.Workloads, p.collateral.Agents = nonNilWL(wls), nonNilIDs(agents)
		p.collateral.Notes = append(p.collateral.Notes,
			"Every consumer of the old key must switch to the new one (read from the handover secret) before the old key is deactivated.")
		return nil
	}
	return nil
}

func nonNilWL(w []CollateralWorkload) []CollateralWorkload {
	if w == nil {
		return []CollateralWorkload{}
	}
	return w
}

func nonNilIDs(a []uuid.UUID) []uuid.UUID {
	if a == nil {
		return []uuid.UUID{}
	}
	return a
}

// planNonAWSGrant is remove_grant on Azure or Kubernetes: prepared only.
func (s *RemediationService) planNonAWSGrant(p *remPlan) error {
	if p.kind != RemediationRemoveGrant {
		return govErr(http.StatusUnprocessableEntity, RemCodeUnsupported, "Only remove_grant is offered on "+p.targetProvider+" (prepared).", nil)
	}
	p.forcePrepared = RemReasonPrepareOnly
	switch p.targetProvider {
	case "azure":
		if !strings.Contains(strings.ToLower(p.targetRef), "/providers/microsoft.authorization/roleassignments/") {
			return GovBadParam("target.ref", "target.ref must be an Azure role assignment id.")
		}
		p.targetKind = "azure_role_assignment"
		p.notes = append(p.notes, "Delete the role assignment (needs the AuthSec Remediation custom role, deploy/remediation/azure-remediation-role.json):",
			"az role assignment delete --ids '"+strings.ReplaceAll(p.targetRef, "'", "")+"'")
	case "k8s":
		ns, name, subject := detailString(p.detail, "namespace"), p.targetRef, detailString(p.detail, "subject")
		if subject == "" {
			return GovBadParam("target.detail.subject", "target.detail.subject is required: the subject (kind/namespace/name) to remove from the binding.")
		}
		p.targetKind = "k8s_binding_subject"
		kind := "rolebinding"
		if ns == "" {
			kind = "clusterrolebinding"
		}
		cmd := "kubectl get " + kind + " " + name
		if ns != "" {
			cmd += " -n " + ns
		}
		p.notes = append(p.notes, "Remove subject "+subject+" from "+kind+" "+name+" (needs deploy/remediation/k8s-remediation-clusterrole.yaml):",
			cmd+" -o json | jq 'del(.subjects[] | select((.kind + \"/\" + (.namespace // \"\") + \"/\" + .name) == \""+subject+"\"))' | kubectl replace -f -")
	}
	p.collateral.Summary = "Prepared only: AuthSec does not write to " + p.targetProvider + " in this release."
	return nil
}

func (s *RemediationService) planRemoveGrantDB(tx *gorm.DB, ws uuid.UUID, p *remPlan) error {
	if strings.Contains(p.targetRef, ":policy/") {
		// Rewrite a statement of a customer-managed policy.
		if strings.HasPrefix(strings.SplitN(p.targetRef, ":policy/", 2)[1], "authsec/") {
			return govErr(http.StatusUnprocessableEntity, RemCodeUnsupported, "AuthSec's own policies are removed by the feature that made them.", nil)
		}
		if _, acct := awsremediate.ARNAccount(p.targetRef); acct == "aws" {
			return govErr(http.StatusUnprocessableEntity, RemCodeUnsupported, "An AWS managed policy cannot be rewritten; detach it from the principal instead.", nil)
		}
		if detailString(p.detail, "statement_sid") == "" && p.detail["statement_index"] == nil {
			return GovBadParam("target.detail.statement_sid", "Name the statement to remove (statement_sid or statement_index).")
		}
		p.targetKind = "managed_policy"
		holders, err := remHolders(tx, ws, p.targetRef)
		if err != nil {
			return err
		}
		p.collateral.Principals = holders
		for _, h := range holders {
			id, err := remIdentityByARN(tx, ws, h.ARN)
			if err != nil {
				return err
			}
			if id != nil {
				wls, agents, err := remWorkloadsOn(tx, ws, id.ID, id.NativeID)
				if err != nil {
					return err
				}
				p.collateral.Workloads = append(p.collateral.Workloads, wls...)
				p.collateral.Agents = append(p.collateral.Agents, agents...)
			}
		}
		if len(holders) > 1 {
			p.collateral.Notes = append(p.collateral.Notes, fmt.Sprintf("The policy is attached to %d principals: every one of them loses the statement.", len(holders)))
		}
		if doc, ok, err := remPolicyDoc(tx, ws, p.targetRef); err != nil {
			return err
		} else if ok {
			p.detail["_stored_document"] = doc
		}
		return nil
	}
	pr, err := awsremediate.PrincipalOf(p.targetRef)
	if err != nil {
		return GovBadParam("target.ref", "target.ref must be an IAM role, user or customer-managed policy ARN.")
	}
	id, err := remIdentityByARN(tx, ws, p.targetRef)
	if err != nil {
		return err
	}
	if id == nil {
		return GovNotFound()
	}
	p.targetKind = "iam_" + pr.Kind
	p.iac = detectIaC(id.attrs().Tags)
	wls, agents, err := remWorkloadsOn(tx, ws, id.ID, id.NativeID)
	if err != nil {
		return err
	}
	p.collateral.Principals = []CollateralPrincipal{{ARN: id.NativeID, Kind: id.Kind, Reason: "target"}}
	p.collateral.Workloads, p.collateral.Agents = nonNilWL(wls), nonNilIDs(agents)
	p.collateral.SharedIdentity = len(wls) > 1 || len(agents) > 1
	if p.collateral.SharedIdentity {
		p.collateral.Notes = append(p.collateral.Notes, fmt.Sprintf("%d workloads (%d agents) run as %s: all of them lose the grant.", len(wls), len(agents), pr.Name))
	}
	switch {
	case detailString(p.detail, "policy_arn") != "":
		pa := detailString(p.detail, "policy_arn")
		if strings.Contains(pa, ":policy/authsec/") {
			return govErr(http.StatusUnprocessableEntity, RemCodeUnsupported, "AuthSec's own policies are removed by the feature that made them.", nil)
		}
		if doc, ok, err := remPolicyDoc(tx, ws, pa); err != nil {
			return err
		} else if ok {
			p.detail["_stored_document"] = doc
		}
	case detailString(p.detail, "inline_policy") != "":
		if detailString(p.detail, "statement_sid") == "" && p.detail["statement_index"] == nil {
			return GovBadParam("target.detail.statement_sid", "Name the statement to remove (statement_sid or statement_index).")
		}
		if doc, ok, err := remPolicyDoc(tx, ws, "inline:"+p.targetRef+":"+detailString(p.detail, "inline_policy")); err != nil {
			return err
		} else if ok {
			p.detail["_stored_document"] = doc
		}
	default:
		return GovBadParam("target.detail", "Name the grant: policy_arn (a managed policy to detach) or inline_policy with statement_sid.")
	}
	return nil
}

func (s *RemediationService) planProviderKeyDB(tx *gorm.DB, ws uuid.UUID, p *remPlan) error {
	if p.targetProvider != "model_provider" {
		return GovBadParam("target.provider", "rotate_provider_key targets a model_provider connection.")
	}
	cid, err := uuid.Parse(p.targetRef)
	if err != nil {
		return GovBadParam("target.ref", "target.ref must be a model provider connection id.")
	}
	var rows []struct {
		Provider       string
		KeyFingerprint string
		Status         string
	}
	if err := tx.Raw(`SELECT provider, key_fingerprint, status FROM model_provider_connection WHERE workspace_id = ? AND id = ?`, ws, cid).
		Scan(&rows).Error; err != nil {
		return err
	}
	if len(rows) == 0 {
		return GovNotFound()
	}
	if rows[0].Status == ModelProviderRevoked {
		return govConflict("model_provider_revoked", "The connection is revoked; there is no key to rotate.", nil)
	}
	p.targetKind = "provider_admin_key"
	p.previousFingerprint = rows[0].KeyFingerprint
	before := map[string]any{"provider": rows[0].Provider, "fingerprint": rows[0].KeyFingerprint}
	p.collateral.Notes = append(p.collateral.Notes, "Usage sync of this organisation pauses between the old key's revocation and the new key's storage.")
	if providerKeyRotator(rows[0].Provider) != nil {
		p.steps = append(p.steps, awsremediate.Step{Op: RemOpProviderKeyRotate, Target: cid.String(), EventSource: remSourceAuthSec,
			EventName: "model_provider.rotate", Before: before, After: map[string]any{"fingerprint_changed": true}})
		return nil
	}
	p.forcePrepared = RemReasonProviderNoWrite
	p.steps = append(p.steps,
		awsremediate.Step{Op: RemOpProviderKeyCreate, Target: cid.String(), EventSource: remSourceAuthSec, EventName: "model_provider.rotate",
			Before: before, After: map[string]any{"fingerprint_changed": true}},
		awsremediate.Step{Op: RemOpProviderKeyRevokeOld, Target: cid.String(), Before: before, After: map[string]any{"old_key_revoked": true}})
	p.askSteps[1] = RemediationAsk{Role: "provider_admin", Reason: "provider_key_create", Choices: []string{"done", "not_mine"},
		Question: "Create a new " + rows[0].Provider + " admin key in the provider console and give it to AuthSec (rotate the connection); AuthSec cannot create provider keys."}
	p.askSteps[2] = RemediationAsk{Role: "provider_admin", Reason: "provider_key_revoke_old", Choices: []string{"done", "not_mine"},
		Question: "Once AuthSec reports the new key in use, revoke the old " + rows[0].Provider + " admin key (" + rows[0].KeyFingerprint + ") in the provider console."}
	return nil
}

func (s *RemediationService) planRetireDB(tx *gorm.DB, ws uuid.UUID, p *remPlan) error {
	if p.targetProvider != "authsec" {
		return GovBadParam("target.provider", "retire_agent targets an AuthSec agent id (provider authsec).")
	}
	aid, err := uuid.Parse(p.targetRef)
	if err != nil {
		return GovBadParam("target.ref", "target.ref must be an agent id.")
	}
	if !remHasRelation(tx, "agent") {
		return govErr(http.StatusServiceUnavailable, GovCodeRemediationUnavailable, "Agents (W7) are not available on this server.", nil)
	}
	a, err := loadAgent(tx, ws, aid, false)
	if err != nil {
		return err
	}
	if a.State != AgentStateActive && a.State != AgentStateDeletedAtSource {
		return govConflict("agent_ended", "The agent has already ended.", map[string]any{"state": a.State})
	}
	p.agentID, p.targetKind = &aid, "agent"
	arns := map[string]bool{}
	var execARNs []string
	if err := tx.Raw(`SELECT DISTINCT w.execution_role_arn FROM agent_alias al
	    JOIN iga_workload w ON w.workspace_id = al.workspace_id AND al.source_table = 'iga_workload' AND al.source_id = w.id::text
	   WHERE al.workspace_id = ? AND al.agent_id = ? AND w.execution_role_arn <> ''`, ws, aid).Scan(&execARNs).Error; err != nil {
		return err
	}
	for _, a := range execARNs {
		arns[a] = true
	}
	if l, ok := p.detail["identity_arns"].([]any); ok {
		for _, x := range l {
			if sx, ok := x.(string); ok && strings.TrimSpace(sx) != "" {
				arns[strings.TrimSpace(sx)] = true
			}
		}
	}
	list := make([]string, 0, len(arns))
	for a := range arns {
		list = append(list, a)
	}
	sort.Strings(list)
	var ids []remIdentity
	for _, arn := range list {
		id, err := remIdentityByARN(tx, ws, arn)
		if err != nil {
			return err
		}
		if id == nil {
			return GovBadParam("target.detail.identity_arns", "An identity of the agent is not one of this workspace's: "+arn)
		}
		if p.connectorID != nil && *p.connectorID != id.ConnectorID {
			return govErr(http.StatusUnprocessableEntity, RemCodeUnsupported, "The agent's identities are in more than one account; retire it once per account.", nil)
		}
		c := id.ConnectorID
		p.connectorID = &c
		ids = append(ids, *id)
	}
	p.partition, p.account = "aws", ""
	if len(ids) > 0 {
		p.partition, p.account = awsremediate.ARNAccount(ids[0].NativeID)
	}
	short := agentcontain.Short(p.id)
	for _, id := range ids {
		pr, err := awsremediate.PrincipalOf(id.NativeID)
		if err != nil {
			continue
		}
		wls, agents, err := remWorkloadsOn(tx, ws, id.ID, id.NativeID)
		if err != nil {
			return err
		}
		p.collateral.Principals = append(p.collateral.Principals, CollateralPrincipal{ARN: id.NativeID, Kind: id.Kind, Reason: "blocked"})
		p.collateral.Workloads = append(p.collateral.Workloads, wls...)
		for _, x := range agents {
			if x != aid {
				p.collateral.SharedIdentity = true
				p.collateral.Agents = append(p.collateral.Agents, x)
			}
		}
		if len(wls) > 1 {
			p.collateral.SharedIdentity = true
		}
		if pr.Kind == awsremediate.PrincipalUser {
			// Keys are listed live (planLive); a marker step per user.
			p.detail["_users"] = append(remStrings(p.detail["_users"]), id.NativeID)
		}
		name := awsremediate.RetirePolicyName(id.attrs().UniqueID, short)
		arn := awsremediate.PolicyARN(p.partition, p.account, awsdiscovery.RemediationPolicyPath, name)
		doc, _, err := agentcontain.DenyAllDocument()
		if err != nil {
			return err
		}
		cp, err := awsremediate.CreatePolicyStep(arn, awsdiscovery.RemediationPolicyPath, name, doc,
			map[string]string{"ManagedBy": "AuthSec", "authsec:remediation": p.id.String()})
		if err != nil {
			return err
		}
		p.steps = append(p.steps, cp, awsremediate.AttachStep(pr, arn))
		p.awsSteps = true
	}
	if p.collateral.SharedIdentity {
		p.collateral.Notes = append(p.collateral.Notes, "Another workload or agent runs as a blocked identity: it stops too.")
	}
	p.steps = append(p.steps,
		awsremediate.Step{Op: RemOpGatewayRulesRemove, Target: aid.String(), Before: map[string]any{}, After: map[string]any{"removed": true}},
		awsremediate.Step{Op: RemOpAgentRetire, Target: aid.String(), EventSource: remSourceAuthSec, EventName: GovEventAgentRetired,
			Before: map[string]any{"state": a.State}, After: map[string]any{"state": AgentStateRetired}})
	p.collateral.Loses = []string{"*"}
	return nil
}

func remStrings(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		var out []string
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// remSnapshotBody is a policy_text snapshot of a cloud_policy (W9).
type remSnapshotBody struct {
	Type        string          `json:"type"`
	ID          uuid.UUID       `json:"id"`
	ConnectorID uuid.UUID       `json:"connector_id"`
	PolicyKind  string          `json:"policy_kind"`
	NativeID    string          `json:"native_id"`
	Name        string          `json:"name"`
	HolderARN   string          `json:"holder_arn"`
	Document    json.RawMessage `json:"document"`
}

func (s *RemediationService) planRevertDB(tx *gorm.DB, ws uuid.UUID, p *remPlan) error {
	if !strings.HasPrefix(p.targetRef, "cloud_policy:") {
		return GovBadParam("target.ref", "target.ref must be a policy_text snapshot stable id of an AWS policy (cloud_policy:<id>).")
	}
	asOf, err := time.Parse("2006-01-02", detailString(p.detail, "as_of"))
	if err != nil {
		return GovBadParam("target.detail.as_of", "target.detail.as_of is required: the date (YYYY-MM-DD) whose policy text to restore.")
	}
	if !remHasRelation(tx, "iga_snapshot") {
		return govErr(http.StatusServiceUnavailable, GovCodeRemediationUnavailable, "Snapshots (W9) are not available on this server.", nil)
	}
	snaps, err := latestSnapshots(tx, ws, SnapshotKindPolicyText, []string{p.targetRef}, asOf)
	if err != nil {
		return err
	}
	snap, ok := snaps[p.targetRef]
	if !ok {
		return GovNotFound()
	}
	if snap.Absent || snap.Redacted {
		return govConflict("snapshot_unusable", "The policy was absent or its snapshot redacted on that date.", nil)
	}
	var body remSnapshotBody
	if err := json.Unmarshal(snap.Body, &body); err != nil || body.Type != "cloud_policy" || len(body.Document) == 0 || string(body.Document) == "null" {
		return govConflict("snapshot_unusable", "The snapshot does not carry a policy document.", nil)
	}
	p.detail["_snapshot_document"] = string(body.Document)
	p.detail["_snapshot_date"] = snap.Date
	p.partition, p.account = awsremediate.ARNAccount(strings.TrimPrefix(body.NativeID, "inline:"))
	conn, err := remConnectorForAccount(tx, ws, p.account)
	if err != nil {
		return err
	}
	if conn == nil {
		return GovNotFound()
	}
	p.connectorID = conn
	switch body.PolicyKind {
	case "managed":
		p.targetKind = "managed_policy"
		p.detail["_policy_arn"] = body.NativeID
		holders, err := remHolders(tx, ws, body.NativeID)
		if err != nil {
			return err
		}
		p.collateral.Principals = holders
		if doc, ok, err := remPolicyDoc(tx, ws, body.NativeID); err != nil {
			return err
		} else if ok {
			p.detail["_stored_document"] = doc
		}
	case "inline":
		p.targetKind = "inline_policy"
		if body.HolderARN == "" {
			return govConflict("snapshot_unusable", "The snapshot does not name the inline policy's holder.", nil)
		}
		p.detail["_holder_arn"], p.detail["_policy_name"] = body.HolderARN, body.Name
		id, err := remIdentityByARN(tx, ws, body.HolderARN)
		if err != nil {
			return err
		}
		if id != nil {
			p.iac = detectIaC(id.attrs().Tags)
			p.collateral.Principals = []CollateralPrincipal{{ARN: id.NativeID, Kind: id.Kind, Reason: "target"}}
			wls, agents, err := remWorkloadsOn(tx, ws, id.ID, id.NativeID)
			if err != nil {
				return err
			}
			p.collateral.Workloads, p.collateral.Agents = nonNilWL(wls), nonNilIDs(agents)
		}
		if doc, ok, err := remPolicyDoc(tx, ws, body.NativeID); err != nil {
			return err
		} else if ok {
			p.detail["_stored_document"] = doc
		}
	default:
		return govConflict("snapshot_unusable", "The snapshot's policy kind is not managed or inline.", nil)
	}
	p.collateral.Notes = append(p.collateral.Notes, "Reverting restores the document of "+snap.Date+"; any statement added since is removed.")
	return nil
}

/* ------------------------------ per-kind (live) ---------------------------- */

// planLive reads the target now (discovery role) and builds the AWS steps.
// Without a reader (no discovery role, or access not configured) the
// stored discovery documents are used, and the remediation can only be
// prepared.
func (s *RemediationService) planLive(ctx context.Context, ws uuid.UUID, p *remPlan) error {
	var r awsremediate.Reader
	if p.connectorID != nil && (p.targetProvider == "aws" || p.kind == RemediationRetireAgent || p.kind == RemediationRevertSnapshot) {
		if acc := remediationAccess(); acc != nil {
			if rr, err := acc.Reader(ctx, ws, *p.connectorID); err == nil {
				r = rr
			}
		}
	}
	stored := detailString(p.detail, "_stored_document")
	delete(p.detail, "_stored_document")
	readErr := func(err error) error {
		if awsremediate.IsNotFound(err) {
			return govErr(http.StatusNotFound, RemCodeTargetNotFound, "The target no longer exists in AWS.", nil)
		}
		return govErr(http.StatusBadGateway, EnfCodeDiscoveryUnavailable, "The target could not be read through the discovery role.", nil)
	}
	switch p.kind {
	case RemediationRemoveGrant:
		if p.targetProvider != "aws" {
			return nil
		}
		p.awsSteps = true
		if p.targetKind == "managed_policy" {
			ver, doc := "", stored
			var versions []awsremediate.PolicyVersion
			if r != nil {
				v, d, err := r.GetDefaultPolicyVersion(ctx, p.targetRef)
				if err != nil {
					return readErr(err)
				}
				ver, doc = v, d
				if versions, err = r.ListPolicyVersions(ctx, p.targetRef); err != nil {
					return readErr(err)
				}
			}
			if doc == "" {
				return govConflict(RemCodeGrantNotFound, "The policy's document is not known; let discovery read the account first.", nil)
			}
			idx, _ := detailInt(p.detail, "statement_index", -1)
			newDoc, removed, err := awsremediate.RemoveStatement(doc, detailString(p.detail, "statement_sid"), idx)
			if errors.Is(err, awsremediate.ErrStatementNotFound) {
				return govConflict(RemCodeGrantNotFound, "The statement is not in the policy's default version.", nil)
			}
			if err != nil {
				return GovBadParam("target.ref", "The policy document could not be read: "+err.Error())
			}
			if newDoc == "" {
				return govErr(http.StatusUnprocessableEntity, RemCodeUnsupported, "That is the policy's only statement: detach the policy from each principal instead.", nil)
			}
			p.collateral.Loses = removed.Actions
			if len(versions) >= 5 {
				oldest := remOldestNonDefault(versions)
				if oldest != nil {
					od, err := r.GetPolicyVersion(ctx, p.targetRef, oldest.ID)
					if err != nil {
						return readErr(err)
					}
					st, err := awsremediate.DeletePolicyVersionStep(p.targetRef, oldest.ID, od)
					if err != nil {
						return err
					}
					p.steps = append(p.steps, st)
					p.notes = append(p.notes, "The policy has five versions: the oldest non-default one ("+oldest.ID+") is deleted first; its document is kept.")
				}
			}
			if ver == "" {
				p.forcePrepared = RemReasonReaderMissing
			}
			st, err := awsremediate.PolicyVersionStep(p.targetRef, ver, doc, newDoc)
			if err != nil {
				return err
			}
			p.steps = append(p.steps, st)
			p.collateral.Summary = fmt.Sprintf("%d principal(s) holding the policy lose %s.", len(p.collateral.Principals), strings.Join(removed.Actions, ", "))
			return nil
		}
		pr, _ := awsremediate.PrincipalOf(p.targetRef)
		if pa := detailString(p.detail, "policy_arn"); pa != "" {
			doc := stored
			if r != nil {
				attached, err := r.ListAttachedPolicies(ctx, pr)
				if err != nil {
					return readErr(err)
				}
				found := false
				for _, a := range attached {
					found = found || a == pa
				}
				if !found {
					return govConflict(RemCodeGrantNotFound, "The policy is not attached to the principal.", nil)
				}
				if !strings.HasPrefix(pa, "arn:aws:iam::aws:") {
					if _, d, err := r.GetDefaultPolicyVersion(ctx, pa); err == nil {
						doc = d
					}
				}
			} else {
				p.forcePrepared = RemReasonReaderMissing
			}
			p.collateral.Loses = awsremediate.DocumentActions(doc)
			if len(p.collateral.Loses) == 0 {
				p.collateral.Loses = []string{"every permission of " + pa}
			}
			p.steps = append(p.steps, awsremediate.DetachStep(pr, pa))
			p.collateral.Summary = fmt.Sprintf("%s loses %s (policy %s).", pr.Name, strings.Join(p.collateral.Loses, ", "), pa)
			return nil
		}
		name := detailString(p.detail, "inline_policy")
		doc := stored
		if r != nil {
			d, found, err := r.GetInlinePolicy(ctx, pr, name)
			if err != nil {
				return readErr(err)
			}
			if !found {
				return govConflict(RemCodeGrantNotFound, "The principal has no inline policy of that name.", nil)
			}
			doc = d
		} else {
			p.forcePrepared = RemReasonReaderMissing
		}
		if doc == "" {
			return govConflict(RemCodeGrantNotFound, "The inline policy's document is not known; let discovery read the account first.", nil)
		}
		idx, _ := detailInt(p.detail, "statement_index", -1)
		newDoc, removed, err := awsremediate.RemoveStatement(doc, detailString(p.detail, "statement_sid"), idx)
		if errors.Is(err, awsremediate.ErrStatementNotFound) {
			return govConflict(RemCodeGrantNotFound, "The statement is not in the inline policy.", nil)
		}
		if err != nil {
			return GovBadParam("target.detail", "The inline policy document could not be read: "+err.Error())
		}
		p.collateral.Loses = removed.Actions
		var st awsremediate.Step
		if newDoc == "" {
			st, err = awsremediate.DeleteInlineStep(pr, name, doc)
		} else {
			st, err = awsremediate.PutInlineStep(pr, name, doc, newDoc)
		}
		if err != nil {
			return err
		}
		p.steps = append(p.steps, st)
		p.collateral.Summary = fmt.Sprintf("%s loses %s (inline policy %s).", pr.Name, strings.Join(removed.Actions, ", "), name)
		return nil
	case RemediationRotateSecret:
		p.awsSteps = true
		info := &awsremediate.SecretInfo{ARN: p.targetRef}
		if r != nil {
			i, err := r.DescribeSecret(ctx, p.targetRef)
			if err != nil {
				return readErr(err)
			}
			info = i
			if info.ARN == "" {
				info.ARN = p.targetRef
			}
		} else {
			p.forcePrepared = RemReasonReaderMissing
		}
		if !info.RotationEnabled && p.forcePrepared == "" {
			p.forcePrepared = RemReasonRotationOff
		}
		p.steps = append(p.steps, awsremediate.RotateSecretStep(*info))
		p.collateral.Summary = "The secret's value is replaced by its own rotation; AuthSec never reads it."
		return nil
	case RemediationRotateIAMKey:
		p.awsSteps = true
		pr, _ := awsremediate.PrincipalOf(p.targetRef)
		old := detailString(p.detail, "access_key_id")
		handover := detailString(p.detail, "handover_secret_arn")
		grace, _ := detailInt(p.detail, "grace_hours", remediationDefaultGraceHours)
		var keys []awsremediate.AccessKey
		if r != nil {
			k, err := r.ListAccessKeys(ctx, pr.Name)
			if err != nil {
				return readErr(err)
			}
			keys = k
			found := false
			for _, x := range keys {
				found = found || x.ID == old
			}
			if !found {
				return govConflict(RemCodeGrantNotFound, "The user has no access key with that id.", nil)
			}
			if len(keys) >= 2 {
				p.forcePrepared = RemReasonKeyLimit
				p.notes = append(p.notes, "The user already has two access keys (the IAM limit): delete the unused one before rotating.")
			}
			if handover != "" && p.forcePrepared == "" {
				info, err := r.DescribeSecret(ctx, handover)
				if err != nil {
					return govErr(http.StatusUnprocessableEntity, RemCodeTargetNotFound, "The handover secret could not be read.", nil)
				}
				if info.Tags[awsdiscovery.RemediationKeyHandoverTag] != "true" {
					p.forcePrepared = RemReasonHandoverUntag
					p.notes = append(p.notes, "Tag the handover secret "+awsdiscovery.RemediationKeyHandoverTag+"=true to let AuthSec write the new key into it (and only it).")
				}
			}
		} else {
			p.forcePrepared = RemReasonReaderMissing
		}
		if handover == "" && p.forcePrepared == "" {
			p.forcePrepared = RemReasonNoHandover
			p.notes = append(p.notes, "Name a Secrets Manager secret (tagged "+awsdiscovery.RemediationKeyHandoverTag+"=true) as handover_secret_arn: "+
				"AuthSec hands a new key over only through a secret store, never in a response.")
		}
		rot := awsremediate.RotateKeyStep(pr, old, handover, keys)
		rot.Before["grace_hours"] = grace
		p.steps = append(p.steps, rot, awsremediate.DeactivateKeyStep(pr, old, nil))
		p.collateral.Summary = fmt.Sprintf("Key %s of %s is replaced; the old key stops working %d hour(s) after the new one is handed over.", old, pr.Name, grace)
		return nil
	case RemediationRetireAgent:
		users := remStrings(p.detail["_users"])
		delete(p.detail, "_users")
		if r == nil && p.awsSteps {
			p.forcePrepared = RemReasonReaderMissing
		}
		var keySteps []awsremediate.Step
		for _, u := range users {
			pr, _ := awsremediate.PrincipalOf(u)
			if r == nil {
				p.notes = append(p.notes, "List and deactivate every access key of "+pr.Name+" (aws iam list-access-keys --user-name "+pr.Name+").")
				continue
			}
			keys, err := r.ListAccessKeys(ctx, pr.Name)
			if err != nil {
				return readErr(err)
			}
			for _, k := range keys {
				if k.Active {
					keySteps = append(keySteps, awsremediate.DeactivateKeyStep(pr, k.ID, nil))
				}
			}
		}
		// Keys first: a retired agent's keys stop before its identity is blocked.
		p.steps = append(keySteps, p.steps...)
		p.collateral.Summary = fmt.Sprintf("The agent's %d identity(ies) are blocked by an AuthSec deny, their active keys deactivated, its gateway rules removed and the agent retired.",
			len(p.collateral.Principals))
		return nil
	case RemediationRevertSnapshot:
		p.awsSteps = true
		snapDoc := detailString(p.detail, "_snapshot_document")
		delete(p.detail, "_snapshot_document")
		switch p.targetKind {
		case "managed_policy":
			arn := detailString(p.detail, "_policy_arn")
			ver, cur := "", stored
			var versions []awsremediate.PolicyVersion
			if r != nil {
				v, d, err := r.GetDefaultPolicyVersion(ctx, arn)
				if err != nil {
					return readErr(err)
				}
				ver, cur = v, d
				if versions, err = r.ListPolicyVersions(ctx, arn); err != nil {
					return readErr(err)
				}
			} else {
				p.forcePrepared = RemReasonReaderMissing
			}
			if cur != "" && awsremediate.SameDocument(cur, snapDoc) {
				return govConflict("nothing_to_revert", "The policy already has the snapshot's document.", nil)
			}
			if len(versions) >= 5 {
				if oldest := remOldestNonDefault(versions); oldest != nil {
					od, err := r.GetPolicyVersion(ctx, arn, oldest.ID)
					if err != nil {
						return readErr(err)
					}
					st, err := awsremediate.DeletePolicyVersionStep(arn, oldest.ID, od)
					if err != nil {
						return err
					}
					p.steps = append(p.steps, st)
				}
			}
			if cur == "" {
				cur = `{"Version":"2012-10-17","Statement":[]}`
			}
			st, err := awsremediate.PolicyVersionStep(arn, ver, cur, snapDoc)
			if err != nil {
				return err
			}
			p.steps = append(p.steps, st)
			p.collateral.Loses = remActionsLost(cur, snapDoc)
		case "inline_policy":
			holder, name := detailString(p.detail, "_holder_arn"), detailString(p.detail, "_policy_name")
			pr, err := awsremediate.PrincipalOf(holder)
			if err != nil {
				return govConflict("snapshot_unusable", "The snapshot's holder is not an IAM role or user.", nil)
			}
			cur := stored
			if r != nil {
				d, found, err := r.GetInlinePolicy(ctx, pr, name)
				if err != nil {
					return readErr(err)
				}
				cur = ""
				if found {
					cur = d
				}
			} else {
				p.forcePrepared = RemReasonReaderMissing
			}
			if cur != "" && awsremediate.SameDocument(cur, snapDoc) {
				return govConflict("nothing_to_revert", "The inline policy already has the snapshot's document.", nil)
			}
			st, err := awsremediate.PutInlineStep(pr, name, cur, snapDoc)
			if err != nil {
				return err
			}
			p.steps = append(p.steps, st)
			p.collateral.Loses = remActionsLost(cur, snapDoc)
		}
		p.collateral.Summary = "The policy text of " + detailString(p.detail, "_snapshot_date") + " is restored."
		return nil
	}
	return nil
}

func remOldestNonDefault(vs []awsremediate.PolicyVersion) *awsremediate.PolicyVersion {
	var out *awsremediate.PolicyVersion
	for i := range vs {
		v := vs[i]
		if v.IsDefault {
			continue
		}
		if out == nil || v.Created.Before(out.Created) || (v.Created.Equal(out.Created) && v.ID < out.ID) {
			out = &vs[i]
		}
	}
	return out
}

// remActionsLost lists the allowed actions of from that to does not allow.
func remActionsLost(from, to string) []string {
	keep := map[string]bool{}
	for _, a := range awsremediate.DocumentActions(to) {
		keep[a] = true
	}
	out := []string{}
	for _, a := range awsremediate.DocumentActions(from) {
		if !keep[a] {
			out = append(out, a)
		}
	}
	return out
}

// decideMode picks write, iac_pr or prepared.
func (s *RemediationService) decideMode(ctx context.Context, ws uuid.UUID, p *remPlan) error {
	if p.collateral.Principals == nil {
		p.collateral.Principals = []CollateralPrincipal{}
	}
	if p.collateral.Workloads == nil {
		p.collateral.Workloads = []CollateralWorkload{}
	}
	if p.collateral.Agents == nil {
		p.collateral.Agents = []uuid.UUID{}
	}
	if p.collateral.Loses == nil {
		p.collateral.Loses = []string{}
	}
	if p.collateral.Notes == nil {
		p.collateral.Notes = []string{}
	}
	switch {
	case p.forcePrepared != "":
		p.mode, p.modeReason = RemediationModePrepared, p.forcePrepared
		return nil
	case !p.awsSteps:
		// AuthSec-side only (a retire without AWS identities, a provider
		// key a registered rotator handles).
		p.mode = RemediationModeWrite
		return nil
	}
	if p.iac.Managed && (p.kind == RemediationRemoveGrant || p.kind == RemediationRevertSnapshot) && p.connectorID != nil {
		tgt, err := resolveRemediationIaC(ctx, s.db, ws, *p.connectorID, p.iac.Tool)
		if err != nil {
			return err
		}
		if tgt != nil {
			id := tgt.SourceID
			p.iac.SourceID, p.iacSourceID = &id, &id
			p.mode = RemediationModeIaCPR
			return nil
		}
		p.mode, p.modeReason = RemediationModePrepared, RemReasonIaCNoSource
		what := "Terraform"
		if p.iac.Tool == "cloudformation" {
			what = "CloudFormation stack " + p.iac.Stack
		}
		p.notes = append(p.notes, "The target is managed by "+what+" ("+p.iac.Evidence+"): change it in its source, or map an IaC source for this account to get a pull request.")
		return nil
	}
	if p.connectorID == nil {
		p.mode, p.modeReason = RemediationModePrepared, RemReasonNoRole
		return nil
	}
	b, err := liveRemediationBinding(ctx, s.db, ws, *p.connectorID)
	if err != nil {
		return err
	}
	if b == nil || b.State != RemediationBindingVerified || remediationAccess() == nil {
		p.mode, p.modeReason = RemediationModePrepared, RemReasonNoRole
		return nil
	}
	p.mode = RemediationModeWrite
	return nil
}
