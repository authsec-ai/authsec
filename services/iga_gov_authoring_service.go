package services

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	"gorm.io/gorm/clause"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// Policy authoring (SPEC-iga-phase3-policy.md §2.1-§2.4, §2.7, §7.3; T3.11):
// policies, immutable versions, one live control per role, targets, and
// proposals from findings, from a template and from Discovery context. The
// compiler half (propose, plans, compile_plans, revalidation) is
// iga_gov_compile_service.go; approval (T3.13) is iga_gov_approval_service.go.
//
// Every mutation writes iga_gov_event in its own transaction; the
// controllers add auditAdminMutation. The workspace is always the caller's;
// another workspace's id is not found (404), never forbidden.

/* ------------------------------------------------------------------------- */
/*                       Live reads (T3.10 provides them)                      */
/* ------------------------------------------------------------------------- */

// LiveReadRequest asks for one discovery-role read of a role for
// compilation (§3.5, §8.3).
type LiveReadRequest struct {
	WorkspaceID uuid.UUID
	// ConnectorID is the role's AWS connector: its discovery role is the
	// credential (§4.4).
	ConnectorID uuid.UUID
	AccountID   string
	RoleARN     string
	// RoleID is the control's incarnation. The reader returns what AWS has
	// under RoleARN; the compiler compares the RoleIds (§2.2), so the reader
	// must not filter on it.
	RoleID string
	// PolicyARNs are managed policies to read in addition to the role's own
	// boundary (which the reader always reads): AuthSec's boundary name for
	// the role, so a policy already holding that name is never adopted
	// silently (compile.go D48). A policy that does not exist is recorded as
	// a nil entry in LiveRead.Policies (NoSuchEntity).
	PolicyARNs []string
}

// LiveReader is the discovery-role live read the compiler needs (§3.5):
// GetRole, ListAttachedRolePolicies, ListRolePolicies + GetRolePolicy for the
// role, and GetPolicy, GetPolicyVersion (default), ListPolicyVersions and
// ListEntitiesForPolicy (every usage type) for its boundary and for every
// ARN in PolicyARNs. T3.10's awsenforce implements it; tests use a fake.
//
// Contract: LiveRead.Role is nil when GetRole answers NoSuchEntity; every
// policy read is a key of LiveRead.Policies (nil value = NoSuchEntity);
// ReadAt is when the read finished. Role.Continuity is filled by the caller
// from iga_identity_accounts, not by the reader. Any error means the read
// failed (503 discovery_unavailable); it is never a partial read.
type LiveReader interface {
	ReadRole(ctx context.Context, req LiveReadRequest) (igagov.LiveRead, error)
}

var (
	govLiveMu     sync.RWMutex
	govLiveReader LiveReader
)

// SetGovLiveReader installs the process-wide live reader (cmd/main.go wires
// T3.10's implementation at startup). nil uninstalls it.
func SetGovLiveReader(r LiveReader) {
	govLiveMu.Lock()
	govLiveReader = r
	govLiveMu.Unlock()
}

// DefaultGovLiveReader is the process-wide live reader, or nil.
func DefaultGovLiveReader() LiveReader {
	govLiveMu.RLock()
	defer govLiveMu.RUnlock()
	return govLiveReader
}

// processLiveReader reads through whatever process-wide reader is installed
// at call time (the job worker is built before T3.10's reader may be set).
type processLiveReader struct{}

func (processLiveReader) ReadRole(ctx context.Context, req LiveReadRequest) (igagov.LiveRead, error) {
	r := DefaultGovLiveReader()
	if r == nil {
		return igagov.LiveRead{}, errors.New("live reads are not configured in this build")
	}
	return r.ReadRole(ctx, req)
}

// ProcessGovLiveReader is a LiveReader that always uses the process-wide
// reader installed at call time.
func ProcessGovLiveReader() LiveReader { return processLiveReader{} }

/* ------------------------------------------------------------------------- */
/*                Hooks for owner review (T3.12) and notices                   */
/* ------------------------------------------------------------------------- */

// GovPlanSummary is one current plan of a version, as the hooks see it.
type GovPlanSummary struct {
	PlanID            uuid.UUID     `json:"plan_id"`
	TargetID          uuid.UUID     `json:"target_id"`
	ControlID         uuid.UUID     `json:"control_id"`
	IdentityAccountID uuid.UUID     `json:"identity_account_id"`
	RoleID            string        `json:"role_id"`
	Kind              string        `json:"kind"`
	Eligibility       string        `json:"eligibility"`
	ImpactHash        string        `json:"impact_hash"`
	Impact            igagov.Impact `json:"impact"`
	PlanHash          string        `json:"plan_hash"`
	MaterialHash      string        `json:"material_hash"`
}

// GovProposedVersion is what OnProposed receives: a version that was just
// compiled and moved to in_review (or recompiled while in review).
type GovProposedVersion struct {
	WorkspaceID uuid.UUID
	PolicyID    uuid.UUID
	VersionID   uuid.UUID
	VersionNo   int
	ActorID     uuid.UUID
	Intent      igagov.RightSizeIntent
	// ApplyPlans are the version's current apply plans, one per target.
	ApplyPlans []GovPlanSummary
	// Reproposed is true when the version was already in review.
	Reproposed bool
}

// GovApprovalCheck is what OwnerGate receives inside the approval
// transaction, after the hashes matched and before anything is written.
type GovApprovalCheck struct {
	WorkspaceID uuid.UUID
	PolicyID    uuid.UUID
	VersionID   uuid.UUID
	ApproverID  uuid.UUID
	Intent      igagov.RightSizeIntent
	ApplyPlans  []GovPlanSummary
	// ImpactHashes are the sorted apply impact hashes the approval binds.
	ImpactHashes []string
}

// GovImpactChange is a target whose impact_hash changed after a version was
// proposed: by a recompile (compile_plans) or a material-change
// revalidation. T3.12 reopens the owner review for the owners and consumers
// that are new (§2.8 L-03, L-14).
type GovImpactChange struct {
	WorkspaceID   uuid.UUID
	PolicyID      uuid.UUID
	VersionID     uuid.UUID
	TargetID      uuid.UUID
	OldImpactHash string
	NewImpactHash string
	OldImpact     igagov.Impact
	NewImpact     igagov.Impact
	// Source is "recompile" or "revalidation".
	Source string
}

// GovAuthoringHooks are the seams later tasks fill. Every hook runs inside
// the caller's transaction (tx) and its error rolls the mutation back. A nil
// hook is a no-op (OwnerGate nil: no owner gate, which is this build).
type GovAuthoringHooks struct {
	// OnProposed (T3.12): create or reopen the owner review and queue the
	// owner notices for a version just proposed.
	OnProposed func(tx *gorm.DB, p GovProposedVersion) error
	// OwnerGate (T3.12): the §7.5 owner checks at approval. Return a
	// *GovError (409 review_incomplete / age_unconfirmed / route_unconfirmed)
	// to refuse; any other error is a 500.
	OwnerGate func(tx *gorm.DB, c GovApprovalCheck) error
	// OnImpactChanged (T3.12): reopen the review for new owners/consumers.
	OnImpactChanged func(tx *gorm.DB, c GovImpactChange) error
	// OnVersionClosed (T3.12, notices): a version left review for good
	// (withdrawn, rejected, superseded). Its open owner review is already
	// cancelled by the caller.
	OnVersionClosed func(tx *gorm.DB, ws, versionID uuid.UUID, status string) error
	// OnApproved (T3.14/T3.15 notices): a version was approved.
	OnApproved func(tx *gorm.DB, ws, versionID, approvalID uuid.UUID) error
}

var (
	govHooksMu sync.RWMutex
	govHooks   GovAuthoringHooks
)

// SetGovAuthoringHooks installs the process-wide hooks (T3.12 wires its
// owner review here at startup). Tests restore the previous value.
func SetGovAuthoringHooks(h GovAuthoringHooks) GovAuthoringHooks {
	govHooksMu.Lock()
	defer govHooksMu.Unlock()
	prev := govHooks
	govHooks = h
	return prev
}

func currentGovHooks() GovAuthoringHooks {
	govHooksMu.RLock()
	defer govHooksMu.RUnlock()
	return govHooks
}

/* ------------------------------------------------------------------------- */
/*                                The service                                 */
/* ------------------------------------------------------------------------- */

// GovAuthoring is the authoring, compile and approval service.
type GovAuthoring struct {
	db       *gorm.DB
	targets  *GovTargets
	live     LiveReader
	events   repositories.IGAGovEventRepository
	jobs     repositories.IGAGovJobRepository
	settings repositories.IGAGovSettingsRepository
	now      func() time.Time
	hooks    func() GovAuthoringHooks
}

// NewGovAuthoring builds the service. live may be nil: compilation then
// answers 503 discovery_unavailable.
func NewGovAuthoring(db *gorm.DB, live LiveReader) *GovAuthoring {
	return &GovAuthoring{db: db, targets: NewGovTargets(db), live: live,
		events: repositories.NewIGAGovEventRepository(db), jobs: repositories.NewIGAGovJobRepository(db),
		settings: repositories.NewIGAGovSettingsRepository(db), now: time.Now, hooks: currentGovHooks}
}

// WithClock sets the clock of the service and its bundle builder (tests).
func (a *GovAuthoring) WithClock(now func() time.Time) *GovAuthoring {
	a.now = now
	a.targets.WithClock(now)
	return a
}

// WithHooks makes this service use h instead of the process-wide hooks.
func (a *GovAuthoring) WithHooks(h GovAuthoringHooks) *GovAuthoring {
	a.hooks = func() GovAuthoringHooks { return h }
	return a
}

// GovWorkspaceRef is the opaque authsec:workspace tag value (§3.2) of a
// workspace: the compiler's ControlRef.WorkspaceRef, and what T3.10's
// executor must write on every boundary it creates. DECISION A1: the spec
// says "opaque workspace ref" without a definition; it is a stable,
// non-reversible digest of the workspace id, so a tag read in another
// account never reveals the id.
func GovWorkspaceRef(ws uuid.UUID) string {
	sum := sha256.Sum256([]byte("authsec.igagov.workspace_ref.v1\x1f" + ws.String()))
	return "ws-" + hex.EncodeToString(sum[:])[:20]
}

func (a *GovAuthoring) event(tx *gorm.DB, ws uuid.UUID, name, actorKind, actorID string, policy, version *uuid.UUID, payload map[string]any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return a.events.AppendTx(tx, &models.IGAGovEvent{WorkspaceID: ws, Event: name, ActorKind: actorKind, ActorID: actorID,
		PolicyID: policy, VersionID: version, Payload: raw})
}

func userActor(id uuid.UUID) (string, string) { return models.GovActorUser, id.String() }

/* ------------------------------------------------------------------------- */
/*                               Error helpers                                */
/* ------------------------------------------------------------------------- */

// Authoring error codes (§7.12).
const (
	GovCodeTargetNotSupported  = "target_not_supported"
	GovCodeTargetIneligible    = "target_ineligible"
	GovCodeEvidenceUntrusted   = "evidence_untrusted"
	GovCodeRoleControlled      = "role_controlled_by_policy"
	GovCodePolicyControlsRoles = "policy_controls_roles"
	GovCodeVersionConflict     = "version_conflict"
	GovCodeInvalidIntent       = "invalid_intent"
	GovCodeDiscoveryUnavail    = "discovery_unavailable"
	GovCodePolicyArchived      = "policy_archived"
	GovCodePolicyNameTaken     = "policy_name_taken"
	GovCodeNothingToRemove     = "nothing_to_remove"
	GovCodeFindingNotUsable    = "finding_not_actionable"
)

func govConflict(code, msg string, detail map[string]any) *GovError {
	return govErr(http.StatusConflict, code, msg, detail)
}

func govUnprocessable(code, msg string, detail map[string]any) *GovError {
	return govErr(http.StatusUnprocessableEntity, code, msg, detail)
}

func errRoleControlled(policyID, controlID uuid.UUID, roleID string) *GovError {
	return govConflict(GovCodeRoleControlled, "Another policy already controls this role; edit that policy instead.",
		map[string]any{"policy_id": policyID, "control_id": controlID, "role_id": roleID})
}

/* ------------------------------------------------------------------------- */
/*                               Read models                                  */
/* ------------------------------------------------------------------------- */

// GovTargetView is one target of a version.
type GovTargetView struct {
	ID                uuid.UUID `json:"id"`
	ControlID         uuid.UUID `json:"control_id"`
	IdentityAccountID uuid.UUID `json:"identity_account_id"`
	AccountID         string    `json:"account_id"`
	RoleID            string    `json:"role_id"`
	RoleARN           string    `json:"role_arn"`
	IsCanary          bool      `json:"is_canary"`
	ControlState      string    `json:"control_state"`
	// Eligibility is the current apply plan's, null before compilation.
	Eligibility      *string `json:"eligibility"`
	IneligibleReason string  `json:"ineligible_reason"`
}

// GovVersionView is a version with its targets.
type GovVersionView struct {
	ID              uuid.UUID       `json:"id"`
	PolicyID        uuid.UUID       `json:"policy_id"`
	No              int             `json:"no"`
	Status          string          `json:"status"`
	Intent          json.RawMessage `json:"intent"`
	IntentHash      string          `json:"intent_hash"`
	CatalogVersion  int             `json:"catalog_version"`
	EvidenceRev     int64           `json:"evidence_rev"`
	CreatedBy       uuid.UUID       `json:"created_by"`
	CreatedAt       time.Time       `json:"created_at"`
	StatusChangedAt time.Time       `json:"status_changed_at"`
	Targets         []GovTargetView `json:"targets"`
}

// GovPolicyView is a policy in a list or its detail.
type GovPolicyView struct {
	ID             uuid.UUID       `json:"id"`
	Name           string          `json:"name"`
	Purpose        string          `json:"purpose"`
	Family         string          `json:"family"`
	Provider       string          `json:"provider"`
	Lifecycle      string          `json:"lifecycle"`
	OwnerUserID    *uuid.UUID      `json:"owner"`
	Status         *string         `json:"status"`
	ScopeSummary   string          `json:"scope_summary"`
	LastVerifiedAt *time.Time      `json:"last_verified_at"`
	NextAction     string          `json:"next_action"`
	CreatedBy      uuid.UUID       `json:"created_by"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
	CurrentVersion *GovVersionView `json:"current_version,omitempty"`
	// ApprovedVersionNo is the version currently approved, if any.
	ApprovedVersionNo *int            `json:"approved_version_no,omitempty"`
	Controls          []GovControlRow `json:"controls,omitempty"`
}

// GovControlRow is one control of a policy.
type GovControlRow struct {
	ID                uuid.UUID `json:"id"`
	AccountID         string    `json:"account_id"`
	RoleID            string    `json:"role_id"`
	RoleARN           string    `json:"role_arn"`
	IdentityAccountID uuid.UUID `json:"identity_account_id"`
	BoundaryPolicyARN string    `json:"boundary_policy_arn"`
	State             string    `json:"state"`
}

// nextAction is the policy's next step from its lifecycle and current
// version (§7.3 next_action). Owner review, rollout and deployment states
// refine it in T3.12 / T3.15 / T3.16.
func nextAction(lifecycle string, status *string) string {
	if lifecycle == "archived" {
		return "none"
	}
	if status == nil {
		return "create_version"
	}
	switch *status {
	case "draft":
		return "propose"
	case "in_review":
		return "approve"
	case "approved":
		return "rollout"
	}
	return "create_version"
}

func scopeSummary(n int) string {
	if n == 1 {
		return "1 role"
	}
	return fmt.Sprintf("%d roles", n)
}

// GovPolicyFilter filters GET /policies.
type GovPolicyFilter struct {
	Family, Provider, Status, Lifecycle, Q, Cursor string
	Limit                                          int
}

var (
	govFamilies   = map[string]bool{"governance": true, "cloud_access": true, "time_bound": true, "runtime": true}
	govLifecycles = map[string]bool{"active": true, "paused": true, "archived": true}
	govVStatuses  = map[string]bool{"draft": true, "in_review": true, "approved": true, "superseded": true, "withdrawn": true, "rejected": true}
)

type policyListRow struct {
	models.IGAGovPolicy
	VStatus *string
	Roles   int
}

// ListPolicies is GET /policies: Phase 3 policies only (never legacy agent
// policies, §7.10), ordered by name, cursor-paged.
func (a *GovAuthoring) ListPolicies(ctx context.Context, ws uuid.UUID, f GovPolicyFilter) ([]GovPolicyView, *string, error) {
	if f.Family != "" && !govFamilies[f.Family] {
		return nil, nil, GovBadParam("family", "Unknown family.")
	}
	if f.Provider != "" && f.Provider != "aws" {
		return nil, nil, GovBadParam("provider", "Unknown provider.")
	}
	if f.Lifecycle != "" && !govLifecycles[f.Lifecycle] {
		return nil, nil, GovBadParam("lifecycle", "Unknown lifecycle.")
	}
	if f.Status != "" && !govVStatuses[f.Status] {
		return nil, nil, GovBadParam("status", "Unknown status.")
	}
	limit := f.Limit
	if limit <= 0 || limit > MaxGovPage {
		limit = MaxGovPage
	}
	q := a.db.WithContext(ctx).Table("iga_gov_policy p").
		Select(`p.*, v.status AS v_status,
		        (SELECT count(*) FROM iga_gov_target t WHERE t.workspace_id = p.workspace_id AND t.version_id = p.current_version_id) AS roles`).
		Joins("LEFT JOIN iga_gov_policy_version v ON v.workspace_id = p.workspace_id AND v.id = p.current_version_id").
		Where("p.workspace_id = ?", ws)
	if f.Family != "" {
		q = q.Where("p.family = ?", f.Family)
	}
	if f.Provider != "" {
		q = q.Where("p.provider = ?", f.Provider)
	}
	if f.Lifecycle != "" {
		q = q.Where("p.lifecycle = ?", f.Lifecycle)
	}
	if f.Status != "" {
		q = q.Where("v.status = ?", f.Status)
	}
	if f.Q != "" {
		q = q.Where("p.name ILIKE ?", "%"+strings.NewReplacer("%", `\%`, "_", `\_`).Replace(f.Q)+"%")
	}
	if f.Cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(f.Cursor)
		parts := strings.SplitN(string(raw), "\x1f", 2)
		if err != nil || len(parts) != 2 {
			return nil, nil, govErr(http.StatusBadRequest, "cursor_invalid", "The cursor is not valid.", map[string]any{"parameter": "cursor"})
		}
		id, err := uuid.Parse(parts[1])
		if err != nil {
			return nil, nil, govErr(http.StatusBadRequest, "cursor_invalid", "The cursor is not valid.", map[string]any{"parameter": "cursor"})
		}
		q = q.Where("(p.name, p.id) > (?, ?)", parts[0], id)
	}
	var rows []policyListRow
	if err := q.Order("p.name, p.id").Limit(limit + 1).Scan(&rows).Error; err != nil {
		return nil, nil, err
	}
	var next *string
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		c := base64.RawURLEncoding.EncodeToString([]byte(last.Name + "\x1f" + last.ID.String()))
		next = &c
	}
	out := make([]GovPolicyView, 0, len(rows))
	for _, r := range rows {
		out = append(out, policyView(r.IGAGovPolicy, r.VStatus, r.Roles))
	}
	return out, next, nil
}

func policyView(p models.IGAGovPolicy, status *string, roles int) GovPolicyView {
	return GovPolicyView{ID: p.ID, Name: p.Name, Purpose: p.Purpose, Family: p.Family, Provider: p.Provider,
		Lifecycle: p.Lifecycle, OwnerUserID: p.OwnerUserID, Status: status, ScopeSummary: scopeSummary(roles),
		NextAction: nextAction(p.Lifecycle, status), CreatedBy: p.CreatedBy, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}
}

func (a *GovAuthoring) loadPolicy(db *gorm.DB, ws, id uuid.UUID, lock bool) (*models.IGAGovPolicy, error) {
	var p models.IGAGovPolicy
	q := db.Where("workspace_id = ? AND id = ?", ws, id)
	if lock {
		q = q.Clauses(lockForUpdate())
	}
	if err := q.Take(&p).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, GovNotFound()
		}
		return nil, err
	}
	return &p, nil
}

func (a *GovAuthoring) loadVersion(db *gorm.DB, ws, policyID uuid.UUID, no int, lock bool) (*models.IGAGovPolicyVersion, error) {
	var v models.IGAGovPolicyVersion
	q := db.Where("workspace_id = ? AND policy_id = ? AND version_no = ?", ws, policyID, no)
	if lock {
		q = q.Clauses(lockForUpdate())
	}
	if err := q.Take(&v).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, GovNotFound()
		}
		return nil, err
	}
	return &v, nil
}

func (a *GovAuthoring) versionView(db *gorm.DB, v models.IGAGovPolicyVersion) (GovVersionView, error) {
	out := GovVersionView{ID: v.ID, PolicyID: v.PolicyID, No: v.VersionNo, Status: v.Status, Intent: v.Intent,
		IntentHash: v.IntentHash, CatalogVersion: v.CatalogVersion, EvidenceRev: v.EvidenceRev, CreatedBy: v.CreatedBy,
		CreatedAt: v.CreatedAt, StatusChangedAt: v.StatusChangedAt, Targets: []GovTargetView{}}
	err := db.Raw(`SELECT t.id, t.control_id, c.identity_account_id, c.account_id, c.role_id, c.role_arn, t.is_canary,
	                      c.state AS control_state, p.eligibility, COALESCE(p.ineligible_reason, '') AS ineligible_reason
	                 FROM iga_gov_target t
	                 JOIN iga_gov_control c ON c.workspace_id = t.workspace_id AND c.id = t.control_id
	                 LEFT JOIN iga_gov_plan p ON p.workspace_id = t.workspace_id AND p.target_id = t.id
	                                         AND p.kind = 'apply' AND p.superseded_at IS NULL
	                WHERE t.workspace_id = ? AND t.version_id = ?
	                ORDER BY c.account_id, c.role_id`, v.WorkspaceID, v.ID).Scan(&out.Targets).Error
	return out, err
}

// GetPolicy is GET /policies/:id: the policy, its current version with
// targets, its controls and the approved version.
func (a *GovAuthoring) GetPolicy(ctx context.Context, ws, id uuid.UUID) (*GovPolicyView, error) {
	db := a.db.WithContext(ctx)
	p, err := a.loadPolicy(db, ws, id, false)
	if err != nil {
		return nil, err
	}
	var status *string
	var cur *GovVersionView
	roles := 0
	if p.CurrentVersionID != nil {
		var v models.IGAGovPolicyVersion
		if err := db.Where("workspace_id = ? AND id = ?", ws, *p.CurrentVersionID).Take(&v).Error; err != nil {
			return nil, err
		}
		vv, err := a.versionView(db, v)
		if err != nil {
			return nil, err
		}
		status, cur, roles = &v.Status, &vv, len(vv.Targets)
	}
	out := policyView(*p, status, roles)
	out.CurrentVersion = cur
	var approved []int
	if err := db.Raw(`SELECT version_no FROM iga_gov_policy_version WHERE workspace_id = ? AND policy_id = ? AND status = 'approved'`,
		ws, id).Scan(&approved).Error; err != nil {
		return nil, err
	}
	if len(approved) == 1 {
		out.ApprovedVersionNo = &approved[0]
	}
	out.Controls = []GovControlRow{}
	if err := db.Raw(`SELECT id, account_id, role_id, role_arn, identity_account_id, boundary_policy_arn, state
	                    FROM iga_gov_control WHERE workspace_id = ? AND policy_id = ? ORDER BY account_id, role_id, created_at`,
		ws, id).Scan(&out.Controls).Error; err != nil {
		return nil, err
	}
	return &out, nil
}

// ListVersions is GET /policies/:id/versions, newest first.
func (a *GovAuthoring) ListVersions(ctx context.Context, ws, policyID uuid.UUID) ([]GovVersionView, error) {
	db := a.db.WithContext(ctx)
	if _, err := a.loadPolicy(db, ws, policyID, false); err != nil {
		return nil, err
	}
	var vs []models.IGAGovPolicyVersion
	if err := db.Where("workspace_id = ? AND policy_id = ?", ws, policyID).Order("version_no DESC").Find(&vs).Error; err != nil {
		return nil, err
	}
	out := make([]GovVersionView, 0, len(vs))
	for _, v := range vs {
		vv, err := a.versionView(db, v)
		if err != nil {
			return nil, err
		}
		out = append(out, vv)
	}
	return out, nil
}

// GetVersion is GET /policies/:id/versions/:no.
func (a *GovAuthoring) GetVersion(ctx context.Context, ws, policyID uuid.UUID, no int) (*GovVersionView, error) {
	db := a.db.WithContext(ctx)
	v, err := a.loadVersion(db, ws, policyID, no, false)
	if err != nil {
		return nil, err
	}
	vv, err := a.versionView(db, *v)
	return &vv, err
}

/* ------------------------------------------------------------------------- */
/*                         Policy mutations (§7.3)                            */
/* ------------------------------------------------------------------------- */

// GovPolicyPatch is PATCH /policies/:id. A nil field is unchanged;
// ClearOwner sets owner_user_id to null.
type GovPolicyPatch struct {
	Name        *string
	Purpose     *string
	OwnerUserID *uuid.UUID
	ClearOwner  bool
}

// PatchPolicy updates name, purpose and owner. Before and after are
// returned for the audit row.
func (a *GovAuthoring) PatchPolicy(ctx context.Context, ws, actor, id uuid.UUID, p GovPolicyPatch) (before, after *models.IGAGovPolicy, err error) {
	if p.Name != nil && strings.TrimSpace(*p.Name) == "" {
		return nil, nil, GovBadParam("name", "name cannot be empty.")
	}
	err = a.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		pol, err := a.loadPolicy(tx, ws, id, true)
		if err != nil {
			return err
		}
		if pol.Lifecycle == "archived" {
			return govConflict(GovCodePolicyArchived, "The policy is archived and read-only.", nil)
		}
		b := *pol
		before = &b
		upd := map[string]any{"updated_at": a.now()}
		if p.Name != nil {
			pol.Name = strings.TrimSpace(*p.Name)
			upd["name"] = pol.Name
		}
		if p.Purpose != nil {
			pol.Purpose = *p.Purpose
			upd["purpose"] = pol.Purpose
		}
		if p.ClearOwner {
			pol.OwnerUserID = nil
			upd["owner_user_id"] = nil
		} else if p.OwnerUserID != nil {
			if ok, err := activeMember(tx, ws, *p.OwnerUserID); err != nil {
				return err
			} else if !ok {
				return GovBadParam("owner_user_id", "The owner must be an active member of this workspace.")
			}
			pol.OwnerUserID = p.OwnerUserID
			upd["owner_user_id"] = *p.OwnerUserID
		}
		if err := tx.Model(&models.IGAGovPolicy{}).Where("workspace_id = ? AND id = ?", ws, id).Updates(upd).Error; err != nil {
			if isUniqueViolation(err, "") {
				return govConflict(GovCodePolicyNameTaken, "Another policy has this name.", map[string]any{"name": pol.Name})
			}
			return err
		}
		k, aid := userActor(actor)
		after = pol
		return a.event(tx, ws, "policy_updated", k, aid, &id, nil, map[string]any{"name": pol.Name, "purpose": pol.Purpose,
			"owner_user_id": pol.OwnerUserID})
	})
	return before, after, err
}

// SetLifecycle is POST /policies/:id/pause | /resume (§2.4): active <->
// paused, with a mandatory reason. Deployments read the lifecycle (T3.15).
func (a *GovAuthoring) SetLifecycle(ctx context.Context, ws, actor, id uuid.UUID, to, reason string) (*models.IGAGovPolicy, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, GovBadParam("reason", "A reason is required.")
	}
	var out *models.IGAGovPolicy
	err := a.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		pol, err := a.loadPolicy(tx, ws, id, true)
		if err != nil {
			return err
		}
		from := map[string]string{"paused": "active", "active": "paused"}[to]
		if pol.Lifecycle != from {
			return govConflict(GovCodeVersionConflict, fmt.Sprintf("The policy is %s.", pol.Lifecycle),
				map[string]any{"lifecycle": pol.Lifecycle})
		}
		if err := tx.Model(&models.IGAGovPolicy{}).Where("workspace_id = ? AND id = ?", ws, id).
			Updates(map[string]any{"lifecycle": to, "updated_at": a.now()}).Error; err != nil {
			return err
		}
		pol.Lifecycle = to
		out = pol
		k, aid := userActor(actor)
		name := "policy_paused"
		if to == "active" {
			name = "policy_resumed"
		}
		return a.event(tx, ws, name, k, aid, &id, nil, map[string]any{"reason": reason})
	})
	return out, err
}

// ArchivePolicy is POST /policies/:id/archive: refused with 409
// policy_controls_roles while any control is active or being removed.
// DECISION A2: planned controls (no artifact ever applied) are released
// (state removed) by the archive, and draft / in-review versions are
// withdrawn, so an archived policy holds no role and no pending decision.
func (a *GovAuthoring) ArchivePolicy(ctx context.Context, ws, actor, id uuid.UUID, reason string) (*models.IGAGovPolicy, error) {
	var out *models.IGAGovPolicy
	err := a.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		pol, err := a.loadPolicy(tx, ws, id, true)
		if err != nil {
			return err
		}
		if pol.Lifecycle == "archived" {
			return govConflict(GovCodePolicyArchived, "The policy is already archived.", nil)
		}
		var live []GovControlRow
		if err := tx.Raw(`SELECT id, account_id, role_id, role_arn, identity_account_id, boundary_policy_arn, state
		                    FROM iga_gov_control WHERE workspace_id = ? AND policy_id = ? AND state IN ('active','removing')
		                    FOR UPDATE`, ws, id).Scan(&live).Error; err != nil {
			return err
		}
		if len(live) > 0 {
			return govConflict(GovCodePolicyControlsRoles,
				"AuthSec still controls roles of this policy; remove AuthSec control first.", map[string]any{"controls": live})
		}
		var open []models.IGAGovPolicyVersion
		if err := tx.Where("workspace_id = ? AND policy_id = ? AND status IN ('draft','in_review','approved')", ws, id).
			Find(&open).Error; err != nil {
			return err
		}
		for _, v := range open {
			if err := a.closeVersionTx(tx, actor, v, "withdrawn", "policy archived", nil); err != nil {
				return err
			}
		}
		if err := tx.Exec(`UPDATE iga_gov_control SET state = 'removed', updated_at = ? WHERE workspace_id = ? AND policy_id = ? AND state = 'planned'`,
			a.now(), ws, id).Error; err != nil {
			return err
		}
		if err := tx.Model(&models.IGAGovPolicy{}).Where("workspace_id = ? AND id = ?", ws, id).
			Updates(map[string]any{"lifecycle": "archived", "updated_at": a.now()}).Error; err != nil {
			return err
		}
		pol.Lifecycle = "archived"
		out = pol
		k, aid := userActor(actor)
		return a.event(tx, ws, "policy_archived", k, aid, &id, nil, map[string]any{"reason": reason})
	})
	return out, err
}

// closeVersionTx moves a draft / in-review / approved version to a closed
// status (withdrawn, rejected or superseded): its live approval is revoked,
// its open owner review cancelled, the findings it put under review go back
// to open, and its planned controls no other open version uses are
// released (§7.3 withdraw).
func (a *GovAuthoring) closeVersionTx(tx *gorm.DB, actor uuid.UUID, v models.IGAGovPolicyVersion, status, reason string, extra map[string]any) error {
	now := a.now()
	if err := tx.Model(&models.IGAGovPolicyVersion{}).Where("workspace_id = ? AND id = ?", v.WorkspaceID, v.ID).
		Updates(map[string]any{"status": status, "status_changed_at": now}).Error; err != nil {
		return err
	}
	if err := tx.Exec(`UPDATE iga_gov_approval SET revoked_at = ?, revoked_reason = ?
	                    WHERE workspace_id = ? AND version_id = ? AND decision = 'approve' AND revoked_at IS NULL`,
		now, "version "+status+": "+reason, v.WorkspaceID, v.ID).Error; err != nil {
		return err
	}
	// T3.12's hook first (CancelReviewTx), while the review is still open;
	// then the fallback that cancels any review left open.
	if h := a.hooks().OnVersionClosed; h != nil {
		if err := h(tx, v.WorkspaceID, v.ID, status); err != nil {
			return err
		}
	}
	if err := tx.Exec(`UPDATE iga_gov_owner_review SET status = 'cancelled', closed_at = ?
	                    WHERE workspace_id = ? AND version_id = ? AND status IN ('open','reopened')`, now, v.WorkspaceID, v.ID).Error; err != nil {
		return err
	}
	if status != "superseded" {
		if ids := intentFindingIDs(v.Intent); len(ids) > 0 {
			if err := tx.Exec(`UPDATE iga_gov_finding SET status = 'open', status_changed_at = ?
			                    WHERE workspace_id = ? AND id IN ? AND status = 'under_review'`, now, v.WorkspaceID, ids).Error; err != nil {
				return err
			}
		}
		// Planned controls of this version that no other open version of the
		// policy targets are released (§7.3 "unused planned controls").
		if err := tx.Exec(`UPDATE iga_gov_control c SET state = 'removed', updated_at = ?
		                    WHERE c.workspace_id = ? AND c.state = 'planned'
		                      AND c.id IN (SELECT control_id FROM iga_gov_target WHERE workspace_id = ? AND version_id = ?)
		                      AND NOT EXISTS (SELECT 1 FROM iga_gov_target t JOIN iga_gov_policy_version ov
		                                        ON ov.workspace_id = t.workspace_id AND ov.id = t.version_id
		                                       WHERE t.workspace_id = c.workspace_id AND t.control_id = c.id AND ov.id <> ?
		                                         AND ov.status IN ('draft','in_review','approved'))`,
			now, v.WorkspaceID, v.WorkspaceID, v.ID, v.ID).Error; err != nil {
			return err
		}
	}
	payload := map[string]any{"version_no": v.VersionNo, "reason": reason}
	for k, x := range extra {
		payload[k] = x
	}
	k, aid := userActor(actor)
	return a.event(tx, v.WorkspaceID, "version_"+status, k, aid, &v.PolicyID, &v.ID, payload)
}

func intentFindingIDs(raw json.RawMessage) []uuid.UUID {
	var in struct {
		FindingIDs []string `json:"finding_ids"`
	}
	_ = json.Unmarshal(raw, &in)
	var out []uuid.UUID
	for _, s := range in.FindingIDs {
		if id, err := uuid.Parse(s); err == nil {
			out = append(out, id)
		}
	}
	return out
}

// WithdrawVersion is POST /policies/:id/versions/:no/withdraw (§7.3). An
// approved version can be withdrawn only while no deployment of it is in
// flight (DECISION A3; deployments are T3.16's, the check reads them).
func (a *GovAuthoring) WithdrawVersion(ctx context.Context, ws, actor, policyID uuid.UUID, no int, reason string) (*models.IGAGovPolicyVersion, error) {
	var out *models.IGAGovPolicyVersion
	err := a.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := a.loadPolicy(tx, ws, policyID, true); err != nil {
			return err
		}
		v, err := a.loadVersion(tx, ws, policyID, no, true)
		if err != nil {
			return err
		}
		switch v.Status {
		case "draft", "in_review", "approved":
		default:
			return govConflict(GovCodeVersionConflict, "Only a draft, in-review or approved version can be withdrawn.",
				map[string]any{"status": v.Status})
		}
		var inflight int64
		if err := tx.Raw(`SELECT count(*) FROM iga_gov_deployment WHERE workspace_id = ? AND version_id = ?
		                    AND state IN ('queued','applying','outcome_unknown','outcome_unresolved','awaiting_merge','awaiting_apply')`,
			ws, v.ID).Scan(&inflight).Error; err != nil {
			return err
		}
		if inflight > 0 {
			return govConflict("deployment_in_flight", "A deployment of this version is in flight.", map[string]any{"deployments": inflight})
		}
		if err := a.closeVersionTx(tx, actor, *v, "withdrawn", reason, nil); err != nil {
			return err
		}
		v.Status = "withdrawn"
		out = v
		return nil
	})
	return out, err
}

/* ------------------------------------------------------------------------- */
/*                              New versions                                  */
/* ------------------------------------------------------------------------- */

// intentProblems renders igagov.ValidateIntent's errors as 422 invalid_intent.
func intentProblems(err error) error {
	var ie igagov.IntentErrors
	if errors.As(err, &ie) {
		return govUnprocessable(GovCodeInvalidIntent, "The intent is not valid.", map[string]any{"errors": []igagov.IntentError(ie)})
	}
	return govUnprocessable(GovCodeInvalidIntent, "The intent is not valid.", map[string]any{"errors": []igagov.IntentError{
		{Field: "", Code: "invalid", Message: err.Error()}}})
}

// parseRightSize parses and validates a version intent. DECISION A4: the
// versions route authors right_size_services intents only; remove_control
// versions are made by POST /policies/:id/remove-control (§7.7) and
// dedicated_identity versions by the isolation flow (§11, T3.17).
func parseRightSize(raw json.RawMessage) (*igagov.RightSizeIntent, []byte, string, error) {
	in, err := igagov.ParseIntent(raw)
	if err != nil {
		return nil, nil, "", intentProblems(err)
	}
	if in.Kind != igagov.IntentRightSizeServices {
		return nil, nil, "", govUnprocessable(GovCodeInvalidIntent, "This route creates right_size_services versions only.",
			map[string]any{"errors": []igagov.IntentError{{Field: "kind", Code: "not_supported_here",
				Message: in.Kind + " versions are created by their own flow"}}})
	}
	canon, hash, err := igagov.CanonicalIntent(in)
	if err != nil {
		return nil, nil, "", intentProblems(err)
	}
	return in.RightSize, canon, hash, nil
}

type subjectIdentity struct {
	ID           uuid.UUID
	AccountKind  string
	SourceKey    string
	ImmutableKey string
	Continuity   string
	Lifecycle    string
	Provider     string
	DisplayName  string
	Attrs        json.RawMessage `gorm:"column:provider_attrs"`
}

func (s subjectIdentity) arn() string { return nativeOfSourceKey(s.SourceKey) }

func (s subjectIdentity) attrs() roleAttrs {
	var r roleAttrs
	_ = json.Unmarshal(s.Attrs, &r)
	if r.Tags == nil {
		r.Tags = map[string]string{}
	}
	return r
}

// connectorForAccount is the workspace's AWS connector of an account.
func connectorForAccount(db *gorm.DB, ws uuid.UUID, account string) (uuid.UUID, error) {
	c, err := repositories.NewCloudConnectorRepository(db).GetByScope(ws, "aws", account)
	if errors.Is(err, repositories.ErrCloudConnectorNotFound) {
		return uuid.Nil, nil
	}
	if err != nil {
		return uuid.Nil, err
	}
	return c.ID, nil
}

// bindSubjectsTx freezes an intent's subjects into controls of the policy
// (§2.7): each subject must be a live, eligible AWS role of the workspace
// with that RoleId; its live control is reused when this policy owns it,
// a new planned control is created on first use, and a role another policy
// controls is 409 role_controlled_by_policy (§2.3, A20). Live controls of
// the roles are locked first, and the unique live-control index catches a
// concurrent claim.
func (a *GovAuthoring) bindSubjectsTx(tx *gorm.DB, ws, policyID uuid.UUID, subjects []igagov.Subject) ([]models.IGAGovControl, error) {
	var problems []map[string]any
	var out []models.IGAGovControl
	for i, s := range subjects {
		var idents []subjectIdentity
		if err := tx.Raw(`SELECT id, account_kind, source_key, immutable_key, continuity, lifecycle, provider, display_name, provider_attrs
		                    FROM iga_identity_accounts WHERE workspace_id = ? AND id = ?`, ws, s.IdentityAccountID).Scan(&idents).Error; err != nil {
			return nil, err
		}
		field := fmt.Sprintf("subjects[%d]", i)
		if len(idents) != 1 {
			problems = append(problems, map[string]any{"subject": field, "role_id": s.RoleID, "reasons": []string{"not_found"}})
			continue
		}
		id := idents[0]
		at := id.attrs()
		var reasons []string
		switch {
		case id.Provider != "aws":
			reasons = append(reasons, "provider_not_supported:"+id.Provider)
		case id.Lifecycle != models.IGALifecycleActive:
			reasons = append(reasons, "identity_retired")
		case id.ImmutableKey != s.RoleID || govARNField(id.arn(), 4) != s.AccountID:
			reasons = append(reasons, "subject_does_not_match_identity")
		}
		reasons = append(reasons, RoleIneligibility(id.AccountKind, id.Continuity, id.ImmutableKey, at.Path, at.Tags)...)
		if len(reasons) > 0 {
			problems = append(problems, map[string]any{"subject": field, "role_id": s.RoleID, "reasons": reasons})
			continue
		}
		var live []models.IGAGovControl
		if err := tx.Where("workspace_id = ? AND account_id = ? AND role_id = ? AND state <> 'removed'", ws, s.AccountID, s.RoleID).
			Clauses(lockForUpdate()).Find(&live).Error; err != nil {
			return nil, err
		}
		lcs := make([]igagov.LiveControl, 0, len(live))
		for _, c := range live {
			lcs = append(lcs, igagov.LiveControl{ID: c.ID.String(), PolicyID: c.PolicyID.String(), AccountID: c.AccountID, RoleID: c.RoleID, State: c.State})
		}
		got, err := igagov.ResolveControl(lcs, s.AccountID, s.RoleID, policyID.String())
		var rc *igagov.ErrRoleControlledByPolicy
		if errors.As(err, &rc) {
			return nil, errRoleControlled(uuid.MustParse(rc.PolicyID), uuid.MustParse(rc.ControlID), s.RoleID)
		}
		if err != nil {
			return nil, err
		}
		if got != nil {
			for _, c := range live {
				if c.ID.String() == got.ID {
					out = append(out, c)
				}
			}
			continue
		}
		conn, err := connectorForAccount(tx, ws, s.AccountID)
		if err != nil {
			return nil, err
		}
		if conn == uuid.Nil {
			problems = append(problems, map[string]any{"subject": field, "role_id": s.RoleID, "reasons": []string{"no_connector_for_account"}})
			continue
		}
		identID := uuid.MustParse(s.IdentityAccountID)
		arn := id.arn()
		c := models.IGAGovControl{ID: uuid.New(), WorkspaceID: ws, ConnectorID: conn, AccountID: s.AccountID, RoleID: s.RoleID,
			RoleARN: arn, IdentityAccountID: identID, PolicyID: policyID,
			BoundaryPolicyARN: igagov.AuthSecBoundaryARN(arnPartition(arn), s.AccountID, s.RoleID),
			State:             models.GovControlPlanned, CreatedAt: a.now(), UpdatedAt: a.now()}
		if err := tx.Create(&c).Error; err != nil {
			if isUniqueViolation(err, "uq_iga_gov_control_live") {
				var other models.IGAGovControl
				if e := tx.Where("workspace_id = ? AND account_id = ? AND role_id = ? AND state <> 'removed'", ws, s.AccountID, s.RoleID).
					Take(&other).Error; e == nil {
					return nil, errRoleControlled(other.PolicyID, other.ID, s.RoleID)
				}
				return nil, govConflict(GovCodeRoleControlled, "Another policy already controls this role.", map[string]any{"role_id": s.RoleID})
			}
			return nil, err
		}
		out = append(out, c)
	}
	if len(problems) > 0 {
		return nil, govUnprocessable(GovCodeTargetIneligible, "Some targets cannot be controlled.", map[string]any{"targets": problems})
	}
	return out, nil
}

func arnPartition(arn string) string {
	if p := govARNField(arn, 1); p != "" {
		return p
	}
	return "aws"
}

// insertVersionTx inserts version no with its targets (one per control;
// the canary is the intent's canary target, else the first) and points the
// policy's current version at it.
func (a *GovAuthoring) insertVersionTx(tx *gorm.DB, ws, policyID, actor uuid.UUID, no int, intent *igagov.RightSizeIntent,
	canon []byte, hash string, controls []models.IGAGovControl) (*models.IGAGovPolicyVersion, []models.IGAGovTarget, error) {
	now := a.now()
	v := models.IGAGovPolicyVersion{ID: uuid.New(), WorkspaceID: ws, PolicyID: policyID, VersionNo: no, Intent: canon,
		IntentHash: hash, CatalogVersion: igagov.CatalogVersion, EvidenceRev: intent.EvidenceRev, Status: "draft",
		CreatedBy: actor, CreatedAt: now, StatusChangedAt: now}
	if err := tx.Create(&v).Error; err != nil {
		if strings.Contains(err.Error(), "iga_gov_policy_version_workspace_id_evidence_rev_fkey") || strings.Contains(err.Error(), "SQLSTATE 23503") {
			return nil, nil, govUnprocessable(GovCodeInvalidIntent, "The intent's evidence revision is not a publication of this workspace.",
				map[string]any{"errors": []igagov.IntentError{{Field: "evidence_rev", Code: "unknown_revision", Message: "no such publication"}}})
		}
		if isUniqueViolation(err, "") {
			return nil, nil, govConflict(GovCodeVersionConflict, "Another version was created at the same time.", nil)
		}
		return nil, nil, err
	}
	canary := ""
	if intent.Rollout != nil {
		canary = intent.Rollout.CanaryTarget
	}
	sort.Slice(controls, func(i, j int) bool { return controls[i].RoleID < controls[j].RoleID })
	if canary == "" && len(controls) > 0 {
		canary = controls[0].RoleID
	}
	var targets []models.IGAGovTarget
	for _, c := range controls {
		t := models.IGAGovTarget{ID: uuid.New(), WorkspaceID: ws, VersionID: v.ID, PolicyID: policyID, ControlID: c.ID,
			Provider: "aws", IsCanary: c.RoleID == canary, CreatedAt: now}
		if err := tx.Create(&t).Error; err != nil {
			return nil, nil, err
		}
		targets = append(targets, t)
	}
	if err := tx.Model(&models.IGAGovPolicy{}).Where("workspace_id = ? AND id = ?", ws, policyID).
		Updates(map[string]any{"current_version_id": v.ID, "updated_at": now}).Error; err != nil {
		return nil, nil, err
	}
	return &v, targets, nil
}

// CreateVersion is POST /policies/:id/versions: a new draft from {intent,
// base_version_no}. base_version_no must be the policy's newest version
// (else 409 version_conflict, never a silent overwrite). Editing never
// changes a version (049 trigger, A7): it creates the next one. DECISION A5:
// a newer draft makes an older draft or in-review version obsolete, so it
// is withdrawn in the same transaction; an approved version stays approved
// (and deployable) until the new one is approved, which supersedes it.
// The approval of the old version never applies to the new one: approvals
// are rows of their version.
func (a *GovAuthoring) CreateVersion(ctx context.Context, ws, actor, policyID uuid.UUID, baseNo int, raw json.RawMessage) (*GovVersionView, error) {
	// Another workspace's policy is 404 before anything about the body.
	if _, err := a.loadPolicy(a.db.WithContext(ctx), ws, policyID, false); err != nil {
		return nil, err
	}
	if _, _, _, err := parseRightSize(raw); err != nil {
		return nil, err
	}
	var out *GovVersionView
	err := a.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		out, err = a.CreateVersionTx(tx, ws, actor, policyID, baseNo, raw)
		return err
	})
	return out, err
}

// CreateVersionTx is CreateVersion inside the caller's transaction: the seam
// T3.12's owner review uses when an owner's "retain" response creates the
// next version (see RetainVersionTx). The actor is recorded as the version's
// author (created_by), so §2.10's "never one they authored" applies to them.
func (a *GovAuthoring) CreateVersionTx(tx *gorm.DB, ws, actor, policyID uuid.UUID, baseNo int, raw json.RawMessage) (*GovVersionView, error) {
	intent, canon, hash, err := parseRightSize(raw)
	if err != nil {
		return nil, err
	}
	pol, err := a.loadPolicy(tx, ws, policyID, true)
	if err != nil {
		return nil, err
	}
	if pol.Lifecycle == "archived" {
		return nil, govConflict(GovCodePolicyArchived, "The policy is archived and read-only.", nil)
	}
	var latest models.IGAGovPolicyVersion
	if err := tx.Where("workspace_id = ? AND policy_id = ?", ws, policyID).Order("version_no DESC").Limit(1).Take(&latest).Error; err != nil {
		return nil, err
	}
	if baseNo != latest.VersionNo {
		return nil, govConflict(GovCodeVersionConflict, "The policy has a newer version; re-read it and edit that.",
			map[string]any{"base_version_no": baseNo, "current_version_no": latest.VersionNo, "current_status": latest.Status})
	}
	controls, err := a.bindSubjectsTx(tx, ws, policyID, intent.Subjects)
	if err != nil {
		return nil, err
	}
	// Insert the new version BEFORE withdrawing the older draft, so the
	// planned controls both use stay referenced by an open version and are
	// not released by the withdrawal.
	v, _, err := a.insertVersionTx(tx, ws, policyID, actor, latest.VersionNo+1, intent, canon, hash, controls)
	if err != nil {
		return nil, err
	}
	if latest.Status == "draft" || latest.Status == "in_review" {
		if err := a.closeVersionTx(tx, actor, latest, "withdrawn", fmt.Sprintf("replaced by version %d", latest.VersionNo+1), nil); err != nil {
			return nil, err
		}
	}
	if err := a.markFindingsUnderReview(tx, ws, intent.FindingIDs); err != nil {
		return nil, err
	}
	k, aid := userActor(actor)
	if err := a.event(tx, ws, "version_created", k, aid, &policyID, &v.ID, map[string]any{"version_no": v.VersionNo,
		"base_version_no": baseNo, "intent_hash": hash}); err != nil {
		return nil, err
	}
	vv, err := a.versionView(tx, *v)
	return &vv, err
}

// RetainVersionTx creates the next version of the policy of versionID with
// each retain item moved from remove to retain (basis owner, with reason and
// review date): what an owner's "retain" response produces (§7.4, A5).
// T3.12's GovReviewAuthoringHook.OwnerResponseTx adapter calls it; actor is
// the responding owner. 422 nothing_to_remove when nothing would be removed.
func (a *GovAuthoring) RetainVersionTx(tx *gorm.DB, ws, actor, versionID uuid.UUID, items []igagov.RetainEntry) (*GovVersionView, error) {
	var v models.IGAGovPolicyVersion
	if err := tx.Where("workspace_id = ? AND id = ?", ws, versionID).Take(&v).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, GovNotFound()
		}
		return nil, err
	}
	in, err := storedRightSize(v)
	if err != nil {
		return nil, err
	}
	keep := map[string]igagov.RetainEntry{}
	for _, it := range items {
		it.Basis = igagov.RetainOwner
		keep[it.Service] = it
	}
	var remove []igagov.RemoveEntry
	for _, e := range in.Remove {
		if _, ok := keep[e.Service]; !ok {
			remove = append(remove, e)
		}
	}
	if len(remove) == 0 {
		return nil, govUnprocessable(GovCodeNothingToRemove, "Retaining these services leaves nothing to remove.", nil)
	}
	in.Remove = remove
	var retain []igagov.RetainEntry
	for _, e := range in.Retain {
		if _, ok := keep[e.Service]; !ok {
			retain = append(retain, e)
		}
	}
	for _, it := range keep {
		retain = append(retain, it)
	}
	sort.Slice(retain, func(i, j int) bool { return retain[i].Service < retain[j].Service })
	in.Retain = retain
	raw, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	var latest int
	if err := tx.Raw(`SELECT max(version_no) FROM iga_gov_policy_version WHERE workspace_id = ? AND policy_id = ?`, ws, v.PolicyID).
		Scan(&latest).Error; err != nil {
		return nil, err
	}
	return a.CreateVersionTx(tx, ws, actor, v.PolicyID, latest, raw)
}

func (a *GovAuthoring) markFindingsUnderReview(tx *gorm.DB, ws uuid.UUID, ids []string) error {
	var u []uuid.UUID
	for _, s := range ids {
		if id, err := uuid.Parse(s); err == nil {
			u = append(u, id)
		}
	}
	if len(u) == 0 {
		return nil
	}
	return tx.Exec(`UPDATE iga_gov_finding SET status = 'under_review', status_changed_at = ?
	                 WHERE workspace_id = ? AND id IN ? AND status IN ('open','reopened')`, a.now(), ws, u).Error
}

func activeMember(db *gorm.DB, ws, user uuid.UUID) (bool, error) {
	var n int64
	err := db.Raw(`SELECT count(*) FROM workspace_memberships WHERE workspace_id = ? AND user_id = ? AND status = 'active'`, ws, user).Scan(&n).Error
	return n > 0, err
}

/* ------------------------------------------------------------------------- */
/*                                Proposals                                   */
/* ------------------------------------------------------------------------- */

// ProposalRequest is POST /proposals (§7.3): exactly one of From (findings),
// Template + Keys, or Context (a Discovery object or graph relationship).
type ProposalRequest struct {
	From *struct {
		FindingIDs []string `json:"finding_ids"`
	} `json:"from"`
	Template string      `json:"template"`
	Keys     []TargetKey `json:"keys"`
	Context  *struct {
		ObjectID string `json:"object_id"`
	} `json:"context"`
	Name     string `json:"name"`
	Purpose  string `json:"purpose"`
	Delivery string `json:"delivery"`
}

// IndependentGrant is a grant of a removed service beyond the selected
// context (§7.3, A52): the change removes the service for the role whichever
// policy grants it, and the grant itself stays declared (A9).
type IndependentGrant struct {
	RoleID         string   `json:"role_id"`
	PolicyARN      string   `json:"policy_arn"`
	AssignmentKind string   `json:"assignment_kind"`
	StatementKey   string   `json:"statement_key"`
	Services       []string `json:"services"`
}

// ProposalRoute is a resource-policy route of a removed service in the
// preview; BoundaryApplies is true when the boundary limits it (role ARN).
type ProposalRoute struct {
	igagov.Route
	RoleID          string `json:"role_id"`
	BoundaryApplies bool   `json:"boundary_applies"`
}

// ProposalContext is the graph object a proposal was opened from.
type ProposalContext struct {
	ObjectKind string    `json:"object_kind"`
	ObjectID   uuid.UUID `json:"object_id"`
	PolicyARN  string    `json:"policy_arn,omitempty"`
}

// ProposalEvidence is one target's evidence bundle.
type ProposalEvidence struct {
	IdentityAccountID uuid.UUID    `json:"identity_account_id"`
	RoleID            string       `json:"role_id"`
	BundleID          uuid.UUID    `json:"bundle_id"`
	BundleHash        string       `json:"bundle_hash"`
	Trust             string       `json:"trust"`
	TrustReasons      []string     `json:"trust_reasons"`
	Gaps              []igagov.Gap `json:"gaps"`
}

// ProposalRecommendation is what the new-policy flow renders (§7.3, §9.3).
type ProposalRecommendation struct {
	QualifiedDays        int                  `json:"qualified_days"`
	Retain               []igagov.RetainEntry `json:"retain"`
	Remove               []igagov.RemoveEntry `json:"remove"`
	Consumers            []ConsumerView       `json:"consumers"`
	IndependentGrants    []IndependentGrant   `json:"independent_grants"`
	ResourcePolicyRoutes []ProposalRoute      `json:"resource_policy_routes"`
	Warnings             []string             `json:"warnings"`
	Context              *ProposalContext     `json:"context,omitempty"`
}

// ProposalResult is the POST /proposals response body.
type ProposalResult struct {
	Policy struct {
		ID       uuid.UUID `json:"id"`
		Name     string    `json:"name"`
		Family   string    `json:"family"`
		Provider string    `json:"provider"`
	} `json:"policy"`
	Version struct {
		ID         uuid.UUID       `json:"id"`
		No         int             `json:"no"`
		Status     string          `json:"status"`
		Intent     json.RawMessage `json:"intent"`
		IntentHash string          `json:"intent_hash"`
	} `json:"version"`
	// Evidence is the first target's bundle (§7.3 shape); EvidenceTargets
	// lists every target's.
	Evidence        ProposalEvidence       `json:"evidence"`
	EvidenceTargets []ProposalEvidence     `json:"evidence_targets"`
	Recommendation  ProposalRecommendation `json:"recommendation"`
	EvaluatedRev    int64                  `json:"-"`
}

type proposalRole struct {
	target   ResolvedTarget
	findings map[string]uuid.UUID // service -> finding id (from findings)
	prelim   igagov.Bundle
	basis    *bundleBasis
	final    igagov.Bundle
	stored   *StoredBundle
}

// CreateProposal is POST /proposals: it resolves the targets (§2.12),
// builds their evidence bundles, recommends the removal (services with a
// qualified no-attempt basis and a known grant age that are not a dependency
// of the role's workload context), and creates the policy, its planned
// controls, version 1 (draft) and its targets in one transaction.
//
// DECISION A6: a version has ONE removal list for all its subjects (§2.7),
// so a multi-role proposal removes the services every role can remove
// (the intersection); services only some roles could lose are listed in
// warnings. From findings, the removal is further limited to the findings'
// services (unused_service findings only).
func (a *GovAuthoring) CreateProposal(ctx context.Context, ws, actor uuid.UUID, req ProposalRequest) (*ProposalResult, error) {
	forms := 0
	if req.From != nil {
		forms++
	}
	if req.Template != "" || len(req.Keys) > 0 {
		forms++
	}
	if req.Context != nil {
		forms++
	}
	if forms != 1 {
		return nil, GovBadParam("body", "Send exactly one of {from: {finding_ids}}, {template, keys} or {context: {object_id}}.")
	}
	switch req.Delivery {
	case "", igagov.DeliveryDirect, igagov.DeliveryIaCPR, igagov.DeliveryExport:
	default:
		return nil, GovBadParam("delivery", "delivery must be direct, iac_pr or export.")
	}
	db := a.db.WithContext(ctx)
	var keys []TargetKey
	wanted := map[uuid.UUID]map[string]uuid.UUID{} // identity -> service -> finding
	switch {
	case req.From != nil:
		if len(req.From.FindingIDs) == 0 || len(req.From.FindingIDs) > MaxTargetKeys*20 {
			return nil, GovBadParam("from.finding_ids", "Send 1 to 1000 finding ids.")
		}
		var ids []uuid.UUID
		for i, s := range req.From.FindingIDs {
			id, err := uuid.Parse(s)
			if err != nil {
				return nil, GovBadParam(fmt.Sprintf("from.finding_ids[%d]", i), "Must be a uuid.")
			}
			ids = append(ids, id)
		}
		var fs []models.IGAGovFinding
		if err := db.Where("workspace_id = ? AND id IN ?", ws, ids).Find(&fs).Error; err != nil {
			return nil, err
		}
		if len(fs) != len(uniqueUUIDs(ids)) {
			return nil, GovNotFound()
		}
		var bad []map[string]any
		for _, f := range fs {
			if f.Kind != igagov.KindUnusedService || f.IdentityAccountID == nil || (f.Status != "open" && f.Status != "reopened") {
				bad = append(bad, map[string]any{"finding_id": f.ID, "kind": f.Kind, "status": f.Status})
				continue
			}
			if wanted[*f.IdentityAccountID] == nil {
				wanted[*f.IdentityAccountID] = map[string]uuid.UUID{}
				keys = append(keys, TargetKey{ObjectID: f.IdentityAccountID.String()})
			}
			wanted[*f.IdentityAccountID][f.DetailKey] = f.ID
		}
		if len(bad) > 0 {
			return nil, govUnprocessable(GovCodeFindingNotUsable,
				"Only open unused_service findings can seed a right-size proposal.", map[string]any{"findings": bad})
		}
	case req.Context != nil:
		keys = []TargetKey{{ObjectID: req.Context.ObjectID}}
	default:
		if req.Template != igagov.IntentRightSizeServices {
			return nil, GovBadParam("template", "template must be right_size_services in this release.")
		}
		keys = req.Keys
	}
	if err := ValidateTargetKeys(keys); err != nil {
		return nil, err
	}
	resolved, err := a.targets.Resolve(ctx, ws, keys)
	if err != nil {
		return nil, err
	}
	roles, ctxObj, err := a.checkResolved(db, ws, resolved)
	if err != nil {
		return nil, err
	}
	for _, r := range roles {
		r.findings = wanted[r.target.Identity.ID]
	}

	// Recommendation from the evidence: a preliminary bundle per role (no
	// removal yet) gives the activity facts.
	var problems []map[string]any
	var removeSets [][]string
	for _, r := range roles {
		b, _, basis, err := a.targets.buildBasis(ctx, ws, r.target.Identity.ID, nil)
		if err != nil {
			if ge := bundleBuildError(err, r.target.Identity.RoleID); ge != nil {
				return nil, ge
			}
			return nil, err
		}
		r.prelim, r.basis = b, basis
		set := removableServices(b.Facts, basis)
		if r.findings != nil {
			var keep []string
			for _, s := range set {
				if _, ok := r.findings[s]; ok {
					keep = append(keep, s)
				}
			}
			set = keep
		}
		if len(set) == 0 {
			problems = append(problems, map[string]any{"role_id": r.target.Identity.RoleID, "reason": "no service has a qualified no-attempt basis"})
		}
		removeSets = append(removeSets, set)
	}
	if len(problems) > 0 {
		return nil, govUnprocessable(GovCodeNothingToRemove, "There is no service AuthSec can recommend removing.", map[string]any{"targets": problems})
	}
	remove := intersect(removeSets)
	warnings := []string{}
	for i, set := range removeSets {
		for _, s := range set {
			if !containsStr(remove, s) {
				warnings = append(warnings, fmt.Sprintf("not_common:%s:%s", roles[i].target.Identity.RoleID, s))
			}
		}
	}
	if len(remove) == 0 {
		return nil, govUnprocessable(GovCodeNothingToRemove, "The selected roles have no removable service in common.",
			map[string]any{"warnings": warnings})
	}

	// The bundles the plans will compile from.
	for _, r := range roles {
		b, _, basis, err := a.targets.buildBasis(ctx, ws, r.target.Identity.ID, remove)
		if err != nil {
			if ge := bundleBuildError(err, r.target.Identity.RoleID); ge != nil {
				return nil, ge
			}
			return nil, err
		}
		r.final, r.basis = b, basis
		if b.Trust == igagov.TrustUntrusted {
			ue := StoredBundle{Hash: b.Hash, Trust: b.Trust, TrustReasons: b.TrustReasons, Facts: b.Facts}.UntrustedError()
			ue.Detail["role_id"] = r.target.Identity.RoleID
			return nil, ue
		}
	}
	k, aid := userActor(actor)
	for _, r := range roles {
		sb, err := a.targets.storeBundle(ctx, ws, r.target.Identity.ID, r.final, k, aid)
		if err != nil {
			return nil, err
		}
		r.stored = sb
	}
	settings, err := a.settings.Get(ws)
	if err != nil {
		return nil, err
	}
	intent, rec := a.recommend(ws, roles, remove, settings, req.Delivery, ctxObj)
	rec.Warnings = append(rec.Warnings, warnings...)
	rec.Context = ctxObj
	if err := igagov.ValidateIntent(igagov.Intent{Kind: igagov.IntentRightSizeServices, RightSize: &intent}); err != nil {
		return nil, fmt.Errorf("igagov: the recommended intent is invalid: %w", err)
	}
	canon, hash, err := igagov.CanonicalIntent(igagov.Intent{Kind: igagov.IntentRightSizeServices, RightSize: &intent})
	if err != nil {
		return nil, err
	}

	res := &ProposalResult{Recommendation: rec}
	for _, r := range roles {
		res.EvidenceTargets = append(res.EvidenceTargets, ProposalEvidence{IdentityAccountID: r.target.Identity.ID,
			RoleID: r.target.Identity.RoleID, BundleID: r.stored.ID, BundleHash: r.stored.Hash, Trust: r.stored.Trust,
			TrustReasons: r.stored.TrustReasons, Gaps: r.stored.Facts.Gaps})
		if r.stored.Facts.Sources[0].Rev > res.EvaluatedRev {
			res.EvaluatedRev = r.stored.Facts.Sources[0].Rev
		}
	}
	res.Evidence = res.EvidenceTargets[0]
	name := strings.TrimSpace(req.Name)
	explicit := name != ""
	if !explicit {
		name = "Right-size " + roles[0].target.Identity.Name
		if len(roles) > 1 {
			name += fmt.Sprintf(" and %d more", len(roles)-1)
		}
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		final := name
		for n := 2; ; n++ {
			var taken int64
			if err := tx.Raw(`SELECT count(*) FROM iga_gov_policy WHERE workspace_id = ? AND name = ?`, ws, final).Scan(&taken).Error; err != nil {
				return err
			}
			if taken == 0 {
				break
			}
			if explicit {
				return govConflict(GovCodePolicyNameTaken, "Another policy has this name.", map[string]any{"name": final})
			}
			final = fmt.Sprintf("%s (%d)", name, n)
		}
		now := a.now()
		pol := models.IGAGovPolicy{ID: uuid.New(), WorkspaceID: ws, Name: final, Purpose: req.Purpose, Family: "cloud_access",
			Provider: "aws", Lifecycle: "active", CreatedBy: actor, CreatedAt: now, UpdatedAt: now}
		if err := tx.Create(&pol).Error; err != nil {
			if isUniqueViolation(err, "") {
				return govConflict(GovCodePolicyNameTaken, "Another policy has this name.", map[string]any{"name": final})
			}
			return err
		}
		controls, err := a.bindSubjectsTx(tx, ws, pol.ID, intent.Subjects)
		if err != nil {
			return err
		}
		v, _, err := a.insertVersionTx(tx, ws, pol.ID, actor, 1, &intent, canon, hash, controls)
		if err != nil {
			return err
		}
		if err := a.markFindingsUnderReview(tx, ws, intent.FindingIDs); err != nil {
			return err
		}
		res.Policy.ID, res.Policy.Name, res.Policy.Family, res.Policy.Provider = pol.ID, pol.Name, pol.Family, pol.Provider
		res.Version.ID, res.Version.No, res.Version.Status, res.Version.Intent, res.Version.IntentHash = v.ID, 1, v.Status, canon, hash
		var bundles []string
		for _, e := range res.EvidenceTargets {
			bundles = append(bundles, e.BundleID.String())
		}
		if err := a.event(tx, ws, "policy_created", k, aid, &pol.ID, nil, map[string]any{"name": pol.Name, "family": pol.Family}); err != nil {
			return err
		}
		return a.event(tx, ws, "proposal_created", k, aid, &pol.ID, &v.ID, map[string]any{"version_no": 1, "intent_hash": hash,
			"source": proposalSource(req), "bundles": bundles, "remove": remove, "finding_ids": intent.FindingIDs})
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func proposalSource(req ProposalRequest) string {
	switch {
	case req.From != nil:
		return "findings"
	case req.Context != nil:
		return "context"
	}
	return "template"
}

// bundleBuildError maps a bundle that cannot be built to 422
// evidence_untrusted (no complete evaluation, or the role is not in it).
func bundleBuildError(err error, roleID string) *GovError {
	if errors.Is(err, ErrNoCompleteEvaluation) || errors.Is(err, errRoleNotEvaluated) {
		return govUnprocessable(GovCodeEvidenceUntrusted, "There is no complete evaluation of this role to build evidence from.",
			map[string]any{"role_id": roleID, "reasons": []string{reasonOf(err)}, "sources": []any{}})
	}
	return nil
}

// checkResolved turns resolved keys into proposal roles: Kubernetes and
// other unsupported keys are 422 target_not_supported (with the
// prerequisite), unresolved or ineligible ones 422 target_ineligible, and a
// role another policy controls 409 role_controlled_by_policy (A20).
func (a *GovAuthoring) checkResolved(db *gorm.DB, ws uuid.UUID, rs []ResolvedTarget) ([]*proposalRole, *ProposalContext, error) {
	var unsupported, ineligible []map[string]any
	var controlled *GovError
	var out []*proposalRole
	seen := map[uuid.UUID]bool{}
	var ctxObj *ProposalContext
	for _, r := range rs {
		switch {
		case r.Status == TargetNotSupported:
			unsupported = append(unsupported, map[string]any{"key": r.Key, "prerequisite": r.Prerequisite, "reason": r.Reason})
			continue
		case r.Status != TargetResolved:
			ineligible = append(ineligible, map[string]any{"key": r.Key, "status": r.Status, "reasons": []string{r.Reason}})
			continue
		case !r.Eligible:
			ineligible = append(ineligible, map[string]any{"key": r.Key, "status": r.Status, "role_id": r.Identity.RoleID,
				"reasons": r.IneligibleReasons})
			continue
		case r.Control != nil && controlled == nil:
			controlled = errRoleControlled(r.Control.PolicyID, r.Control.ID, r.Identity.RoleID)
			continue
		}
		if r.Context != nil && ctxObj == nil {
			ctxObj = &ProposalContext{ObjectKind: r.Context.ObjectKind, ObjectID: r.Context.ObjectID}
			arn, err := contextPolicyARN(db, ws, *r.Context)
			if err != nil {
				return nil, nil, err
			}
			ctxObj.PolicyARN = arn
		}
		if seen[r.Identity.ID] {
			continue
		}
		seen[r.Identity.ID] = true
		out = append(out, &proposalRole{target: r})
	}
	switch {
	case len(unsupported) > 0:
		return nil, nil, govUnprocessable(GovCodeTargetNotSupported, "Some targets are not supported in this release.",
			map[string]any{"targets": unsupported, "prerequisite": unsupported[0]["prerequisite"]})
	case len(ineligible) > 0:
		return nil, nil, govUnprocessable(GovCodeTargetIneligible, "Some targets cannot be controlled.", map[string]any{"targets": ineligible})
	case controlled != nil:
		return nil, nil, controlled
	}
	sort.Slice(out, func(i, j int) bool { return out[i].target.Identity.RoleID < out[j].target.Identity.RoleID })
	return out, ctxObj, nil
}

// contextPolicyARN is the policy a graph-edge context names: an assignment's
// policy, or the policy of a grant's assignment. A workload or relationship
// names none.
func contextPolicyARN(db *gorm.DB, ws uuid.UUID, c TargetContext) (string, error) {
	var arns []string
	var err error
	switch c.ObjectKind {
	case "assignment":
		err = db.Raw(`SELECT p.native_ref FROM iga_policy_assignment a JOIN iga_policy p ON p.workspace_id = a.workspace_id AND p.id = a.policy_id
		               WHERE a.workspace_id = ? AND a.id = ?`, ws, c.ObjectID).Scan(&arns).Error
	case "grant":
		err = db.Raw(`SELECT p.native_ref FROM iga_access_edges e
		                JOIN iga_policy_assignment a ON a.workspace_id = e.workspace_id AND a.id = e.assignment_id
		                JOIN iga_policy p ON p.workspace_id = a.workspace_id AND p.id = a.policy_id
		               WHERE e.workspace_id = ? AND e.id = ?`, ws, c.ObjectID).Scan(&arns).Error
	}
	if err != nil || len(arns) == 0 {
		return "", err
	}
	return arns[0], nil
}

// dependencyContexts are the §3.7 contexts of a role's consumers.
func dependencyContexts(consumers []ConsumerView) []igagov.DependencyContext {
	var out []igagov.DependencyContext
	seen := map[string]bool{}
	for _, c := range consumers {
		if ctx, ok := igagov.DependencyContextFor(c.RuntimeKind, c.Relationship); ok && !seen[ctx] {
			seen[ctx] = true
			out = append(out, igagov.DependencyContext{Context: ctx})
		}
	}
	return out
}

// removableServices are the services a removal can be justified for
// (§3.4 (1)), from the bundle's activity facts: collected, no attempt for at
// least MinQualifiedDays, a known grant age, and not a dependency.
func removableServices(f igagov.BundleFacts, basis *bundleBasis) []string {
	ctxs := dependencyContexts(basis.Consumers)
	var out []string
	for _, a := range f.Activity {
		if a.State != igagov.EvidenceCollected || a.Outcome != igagov.QualNoAttempt || a.QualifiedDays < igagov.MinQualifiedDays {
			continue
		}
		if a.GrantAgeBasis != igagov.GrantAgeObservedSinceChange && a.GrantAgeBasis != igagov.GrantAgePredatesObservation {
			continue
		}
		if _, dep := igagov.IsDependency(a.Service, ctxs); dep {
			continue
		}
		out = append(out, a.Service)
	}
	sort.Strings(out)
	return out
}

// recommend builds the intent and the recommendation from the final bundles.
func (a *GovAuthoring) recommend(ws uuid.UUID, roles []*proposalRole, remove []string, settings *models.IGAGovSettings, delivery string, ctxObj *ProposalContext) (igagov.RightSizeIntent, ProposalRecommendation) {
	rec := ProposalRecommendation{Retain: []igagov.RetainEntry{}, Remove: []igagov.RemoveEntry{}, Consumers: []ConsumerView{},
		IndependentGrants: []IndependentGrant{}, ResourcePolicyRoutes: []ProposalRoute{}, Warnings: []string{}}
	in := igagov.RightSizeIntent{Kind: igagov.IntentRightSizeServices, ObservationDays: settings.DefaultObservationDays,
		Delivery: delivery}
	if in.ObservationDays < igagov.MinObservationDays || in.ObservationDays > igagov.MaxObservationDays {
		in.ObservationDays = 7
	}
	rm := map[string]bool{}
	for _, s := range remove {
		rm[s] = true
	}
	type agg struct {
		days       int
		predates   bool
		usage      string
		state      string
		routes     []igagov.IntentRoute
		routeKeys  map[string]bool
		qualifiedN int
	}
	removed := map[string]*agg{}
	retained := map[string]igagov.RetainEntry{}
	customerBoundary := false
	findingIDs := map[string]bool{}
	seenConsumer := map[string]bool{}
	for _, r := range roles {
		id := r.target.Identity
		in.Subjects = append(in.Subjects, igagov.Subject{IdentityAccountID: id.ID.String(), RoleID: id.RoleID, AccountID: id.AccountID})
		if r.final.Facts.Sources[0].Rev > in.EvidenceRev {
			in.EvidenceRev = r.final.Facts.Sources[0].Rev
		}
		for _, c := range r.basis.Consumers {
			k := c.WorkloadID.String() + c.Relationship
			if !seenConsumer[k] {
				seenConsumer[k] = true
				rec.Consumers = append(rec.Consumers, c)
			}
		}
		if len(r.basis.Consumers) > 1 {
			rec.Warnings = append(rec.Warnings, fmt.Sprintf("shared_role: %d workloads run as %s", len(r.basis.Consumers), id.Name))
		}
		if n := r.final.Facts.ConsumersUnresolved; n > 0 {
			rec.Warnings = append(rec.Warnings, fmt.Sprintf("consumers_unresolved: %d workloads of %s could not be resolved", n, id.Name))
		}
		if b := currentBoundary(r.basis); b != "" && !strings.Contains(b, ":policy"+igagov.AuthSecPolicyPath) {
			customerBoundary = true
		}
		ctxs := dependencyContexts(r.basis.Consumers)
		ref := igagov.RoleRef{RoleID: id.RoleID, ARN: id.ARN, Name: id.Name, AccountID: id.AccountID, Partition: arnPartition(id.ARN)}
		for _, act := range r.final.Facts.Activity {
			if rm[act.Service] {
				g := removed[act.Service]
				if g == nil {
					g = &agg{days: act.QualifiedDays, routeKeys: map[string]bool{}}
					removed[act.Service] = g
				}
				if act.QualifiedDays < g.days {
					g.days = act.QualifiedDays
				}
				g.predates = g.predates || act.GrantAgeBasis == igagov.GrantAgePredatesObservation
				var run *igagov.ResourcePolicyEvidence
				var regions []string
				if r.basis.HasRun {
					run, regions = r.basis.Run.ResourcePolicy, r.basis.Run.EnabledRegions
				}
				ra := igagov.AnalyzeRoutes(act.Service, ref, run, regions)
				g.usage = worseUsage(g.usage, ra.Usage)
				g.state = worseState(g.state, ra.State)
				if ra.Usage != igagov.RouteUsageNoneObserved {
					for _, rt := range ra.Routes {
						ir := igagov.IntentRoute{Resource: rt.Resource, Principal: rt.Principal, Form: rt.Form}
						if ir.Resource != "" {
							ir.Form = ""
						}
						key := ir.Resource + "|" + ir.Principal + "|" + ir.Form
						if !g.routeKeys[key] {
							g.routeKeys[key] = true
							g.routes = append(g.routes, ir)
						}
					}
				}
				if r.findings != nil {
					if fid, ok := r.findings[act.Service]; ok {
						findingIDs[fid.String()] = true
					}
				}
				continue
			}
			if _, done := retained[act.Service]; done {
				continue
			}
			if dep, isDep := igagov.IsDependency(act.Service, ctxs); isDep {
				retained[act.Service] = igagov.RetainEntry{Service: act.Service, Basis: igagov.RetainDependency, Catalog: dep.Catalog}
				continue
			}
			switch {
			case act.LastAuthenticatedAt != nil:
				retained[act.Service] = igagov.RetainEntry{Service: act.Service, Basis: igagov.RetainObserved, LastAttempt: *act.LastAuthenticatedAt}
			default:
				reason := "granted; " + act.Outcome
				if act.State != igagov.EvidenceCollected {
					reason = "granted, not in the activity report"
				}
				retained[act.Service] = igagov.RetainEntry{Service: act.Service, Basis: igagov.RetainUnreviewed, Reason: reason}
			}
		}
		for _, g := range r.final.Facts.Grants {
			var svcs []string
			for _, s := range g.Services {
				if rm[s] {
					svcs = append(svcs, s)
				}
			}
			if len(svcs) == 0 || (ctxObj != nil && ctxObj.PolicyARN != "" && g.PolicyARN == ctxObj.PolicyARN) {
				continue
			}
			rec.IndependentGrants = append(rec.IndependentGrants, IndependentGrant{RoleID: id.RoleID, PolicyARN: g.PolicyARN,
				AssignmentKind: g.AssignmentKind, StatementKey: g.StatementKey, Services: svcs})
		}
		for _, rt := range r.final.Facts.Routes {
			rec.ResourcePolicyRoutes = append(rec.ResourcePolicyRoutes, ProposalRoute{Route: rt, RoleID: id.RoleID,
				BoundaryApplies: rt.Effect == igagov.RouteEffectLimited})
		}
		// Findings this proposal addresses (template and context: the
		// role's open unused_service findings of the removed services).
		if r.findings == nil {
			var fids []uuid.UUID
			_ = a.db.Raw(`SELECT id FROM iga_gov_finding WHERE workspace_id = ? AND identity_account_id = ? AND kind = ?
			               AND detail_key IN ? AND status IN ('open','reopened')`,
				ws, id.ID, igagov.KindUnusedService, remove).Scan(&fids)
			for _, f := range fids {
				findingIDs[f.String()] = true
			}
		}
	}
	for _, s := range remove {
		g := removed[s]
		e := igagov.RemoveEntry{Service: s, Basis: igagov.RemoveNoAttempt, QualifiedDays: g.days,
			GrantAgeBasis: igagov.GrantAgeObservedSinceChange, RouteUsage: g.usage, RouteState: g.state}
		if g.predates {
			e.GrantAgeBasis = igagov.GrantAgePredatesObservation
			rec.Warnings = append(rec.Warnings, "age_unverified: "+s+" was granted before AuthSec's first scan; owners will be asked to confirm")
		}
		if g.usage != igagov.RouteUsageNoneObserved {
			e.Routes = g.routes
			if g.state == igagov.RouteStateNoneObserved && len(e.Routes) == 0 {
				e.RouteState = ""
			}
		}
		if e.RouteState != "" && e.RouteState != igagov.RouteStateNoneObserved && len(e.Routes) == 0 {
			e.RouteState = ""
		}
		if rec.QualifiedDays == 0 || g.days < rec.QualifiedDays {
			rec.QualifiedDays = g.days
		}
		in.Remove = append(in.Remove, e)
	}
	keys := make([]string, 0, len(retained))
	for s := range retained {
		keys = append(keys, s)
	}
	sort.Strings(keys)
	for _, s := range keys {
		in.Retain = append(in.Retain, retained[s])
	}
	if in.Retain == nil {
		in.Retain = []igagov.RetainEntry{}
	}
	if in.Delivery == "" {
		in.Delivery = igagov.DeliveryDirect
		if customerBoundary {
			// DECISION A7: a customer-owned boundary is never edited by
			// AuthSec in AWS (§3.3), so its proposals default to export.
			in.Delivery = igagov.DeliveryExport
		}
	}
	if len(in.Subjects) > 0 {
		in.Rollout = &igagov.RolloutIntent{CanaryTarget: in.Subjects[0].RoleID}
		if h := settings.CanaryHours; h >= igagov.MinCanaryHours && h <= igagov.MaxCanaryHours {
			in.Rollout.CanaryHours = h
		}
	}
	for f := range findingIDs {
		in.FindingIDs = append(in.FindingIDs, f)
	}
	sort.Strings(in.FindingIDs)
	rec.Remove, rec.Retain = in.Remove, in.Retain
	return in, rec
}

// currentBoundary is the role's boundary at the evaluated revision ("" =
// none), from the snapshot's boundary assignment.
func currentBoundary(b *bundleBasis) string {
	for _, a := range b.Role.Assignments {
		if a.Kind != igagov.AssignBoundary {
			continue
		}
		for _, iv := range a.Intervals {
			if iv.To == nil {
				return a.PolicyARN
			}
		}
	}
	return ""
}

func lockForUpdate() clause.Expression { return clause.Locking{Strength: "UPDATE"} }

var usageRank = map[string]int{"": 0, igagov.RouteUsageNoneObserved: 1, igagov.RouteUsageConfirmRequired: 2}
var stateRank = map[string]int{"": 0, igagov.RouteStateNoneObserved: 1, igagov.RouteStateBypassKnown: 2,
	igagov.RouteStateEffectUnknown: 3, igagov.RouteStateNotAnalysed: 4}

func worseUsage(a, b string) string {
	if usageRank[b] > usageRank[a] {
		return b
	}
	return a
}

func worseState(a, b string) string {
	if stateRank[b] > stateRank[a] {
		return b
	}
	return a
}

func intersect(sets [][]string) []string {
	if len(sets) == 0 {
		return nil
	}
	count := map[string]int{}
	for _, s := range sets {
		for _, x := range sortedUniqueStrings(s) {
			count[x]++
		}
	}
	var out []string
	for x, n := range count {
		if n == len(sets) {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

func sortedUniqueStrings(in []string) []string {
	m := map[string]bool{}
	var out []string
	for _, s := range in {
		if !m[s] {
			m[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func uniqueUUIDs(in []uuid.UUID) []uuid.UUID {
	m := map[uuid.UUID]bool{}
	var out []uuid.UUID
	for _, x := range in {
		if !m[x] {
			m[x] = true
			out = append(out, x)
		}
	}
	return out
}
