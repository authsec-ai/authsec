package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
)

// The §7.6 / §7.7 route services (T3.16): deployments read, operator
// resolution of an outcome_unresolved deployment, undo / emergency undo with
// the attachment-set check and role-only recovery plans, validations,
// health reports, and removing AuthSec control. Every mutation writes its
// iga_gov_event in the same transaction; the controller writes the audit row.

// Route error codes (§7.12).
const (
	GovCodeNotLatestDeployment   = "not_latest_deployment"
	GovCodeDeploymentInFlight    = "deployment_in_flight"
	GovCodeOutcomeUnknownPending = "outcome_unknown_pending"
	GovCodeConsumersChanged      = "artifact_consumers_changed"
	GovCodeChangedOutside        = "artifact_changed_outside_authsec"
	GovCodeOwnedElsewhere        = "artifact_owned_elsewhere"
	GovCodeActionNotMappable     = "action_not_mappable"
	GovCodeSessionNotUnique      = "session_not_unique"
	GovCodeNotUndoable           = "not_undoable"
	GovCodeNotUnresolved         = "not_unresolved"
	GovCodeEmergencyUndoUnavail  = "emergency_undo_unavailable"
	GovCodeNotConsumerOwner      = "not_consumer_owner"
	GovCodeNoArtifactToRemove    = "no_artifact_to_remove"
	GovCodeControlNotInPolicy    = "control_not_in_policy"
)

var reValidationAction = regexp.MustCompile(`^[a-z0-9-]+:[A-Za-z0-9]+$`)

/* ---------------------------------- reads ---------------------------------- */

// GovDeploymentFilter is GET /deployments' filter.
type GovDeploymentFilter struct {
	PolicyID *uuid.UUID
	State    string
	Account  string
	Kind     string
	Cursor   string
	Limit    int
}

// GovDeploymentView is one deployment row in a list.
type GovDeploymentView struct {
	models.IGAGovDeployment
	PolicyID  uuid.UUID `json:"policy_id"`
	VersionNo int       `json:"version_no"`
	AccountID string    `json:"account_id"`
	RoleID    string    `json:"role_id"`
	RoleARN   string    `json:"role_arn"`
}

// ListDeployments is GET /deployments (cursor by id, limit <= 200). An
// outcome_unresolved deployment is listed first (§8.1 step 3).
func (s *GovDeployments) ListDeployments(ctx context.Context, ws uuid.UUID, f GovDeploymentFilter) ([]GovDeploymentView, *string, error) {
	if f.Limit <= 0 || f.Limit > MaxGovPage {
		f.Limit = MaxGovPage
	}
	q := `SELECT d.*, v.policy_id, v.version_no, c.account_id, c.role_id, c.role_arn
	        FROM iga_gov_deployment d
	        JOIN iga_gov_policy_version v ON v.workspace_id = d.workspace_id AND v.id = d.version_id
	        JOIN iga_gov_control c ON c.workspace_id = d.workspace_id AND c.id = d.control_id
	       WHERE d.workspace_id = ?`
	args := []any{ws}
	if f.PolicyID != nil {
		q += ` AND v.policy_id = ?`
		args = append(args, *f.PolicyID)
	}
	if f.State != "" {
		q += ` AND d.state = ?`
		args = append(args, f.State)
	}
	if f.Account != "" {
		q += ` AND c.account_id = ?`
		args = append(args, f.Account)
	}
	if f.Kind != "" {
		q += ` AND d.kind = ?`
		args = append(args, f.Kind)
	}
	if f.Cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(f.Cursor)
		parts := strings.SplitN(string(raw), "|", 2)
		if err != nil || len(parts) != 2 {
			return nil, nil, govErr(http.StatusBadRequest, "cursor_invalid", "The cursor is not valid.", map[string]any{"parameter": "cursor"})
		}
		if _, err := uuid.Parse(parts[1]); err != nil {
			return nil, nil, govErr(http.StatusBadRequest, "cursor_invalid", "The cursor is not valid.", map[string]any{"parameter": "cursor"})
		}
		q += ` AND ((CASE WHEN d.state = 'outcome_unresolved' THEN 0 ELSE 1 END)::text || '|' || d.id::text) > ?`
		args = append(args, string(raw))
	}
	q += ` ORDER BY (CASE WHEN d.state = 'outcome_unresolved' THEN 0 ELSE 1 END), d.id LIMIT ?`
	args = append(args, f.Limit+1)
	var rows []GovDeploymentView
	if err := s.db.WithContext(ctx).Raw(q, args...).Scan(&rows).Error; err != nil {
		return nil, nil, err
	}
	var next *string
	if len(rows) > f.Limit {
		rows = rows[:f.Limit]
		last := rows[len(rows)-1]
		k := "1"
		if last.State == models.GovDeployOutcomeUnresolved {
			k = "0"
		}
		c := base64.RawURLEncoding.EncodeToString([]byte(k + "|" + last.ID.String()))
		next = &c
	}
	if rows == nil {
		rows = []GovDeploymentView{}
	}
	return rows, next, nil
}

// GovDeploymentDetail is GET /deployments/:id (§7.6).
type GovDeploymentDetail struct {
	Deployment     models.IGAGovDeployment          `json:"deployment"`
	Plan           models.IGAGovPlan                `json:"plan"`
	Attempts       []models.IGAGovAttempt           `json:"attempts"`
	Verifications  []models.IGAGovVerification      `json:"verifications"`
	ServiceOutcome []models.IGAGovServiceOutcome    `json:"service_outcomes"`
	Validations    []GovValidationView              `json:"validations"`
	HealthReports  []models.IGAGovHealthReport      `json:"health_reports"`
	Ledger         []models.IGAGovArtifact          `json:"ledger"`
	Revalidations  []models.IGAGovRevalidation      `json:"revalidations"`
	Acceptances    []models.IGAGovAcceptance        `json:"acceptances"`
	Migrations     []models.IGAGovWorkloadMigration `json:"migrations"`
	BundleID       uuid.UUID                        `json:"evidence_bundle_id"`
	GateFacts      *DeploymentGateFacts             `json:"gate_facts"`
}

// GovValidationView is a validation with its items.
type GovValidationView struct {
	models.IGAGovValidation
	Items []models.IGAGovValidationItem `json:"items"`
}

// GetDeployment is GET /deployments/:id.
func (s *GovDeployments) GetDeployment(ctx context.Context, ws, id uuid.UUID) (*GovDeploymentDetail, error) {
	db := s.db.WithContext(ctx)
	d, err := s.loadDeployment(db, ws, id)
	if err != nil {
		return nil, err
	}
	out := &GovDeploymentDetail{Deployment: *d}
	p, err := s.loadPlanRow(db, ws, d.PlanID)
	if err != nil {
		return nil, err
	}
	out.Plan, out.BundleID = *p, p.EvidenceBundleID
	where := "workspace_id = ? AND deployment_id = ?"
	for _, q := range []struct {
		dst   any
		order string
	}{{&out.Attempts, "op_seq, attempt_no"}, {&out.Verifications, "dimension"}, {&out.ServiceOutcome, "service"},
		{&out.HealthReports, "created_at, id"}} {
		if err := db.Where(where, ws, d.ID).Order(q.order).Find(q.dst).Error; err != nil {
			return nil, err
		}
	}
	if err := db.Where("workspace_id = ? AND control_id = ?", ws, d.ControlID).Order("kind, updated_at").Find(&out.Ledger).Error; err != nil {
		return nil, err
	}
	if err := db.Where("workspace_id = ? AND plan_id = ?", ws, d.PlanID).Order("created_at").Find(&out.Revalidations).Error; err != nil {
		return nil, err
	}
	if err := db.Where("workspace_id = ? AND version_id = ?", ws, d.VersionID).Order("accepted_at").Find(&out.Acceptances).Error; err != nil {
		return nil, err
	}
	if err := db.Where("workspace_id = ? AND plan_id = ?", ws, d.PlanID).Order("subject_arn").Find(&out.Migrations).Error; err != nil {
		return nil, err
	}
	vs, items, err := loadValidations(db, *d)
	if err != nil {
		return nil, err
	}
	out.Validations = []GovValidationView{}
	for _, v := range vs {
		out.Validations = append(out.Validations, GovValidationView{IGAGovValidation: v, Items: items[v.ID]})
	}
	if out.GateFacts, err = s.DeploymentGateFacts(ctx, ws, d.ID); err != nil {
		return nil, err
	}
	return out, nil
}

/* ----------------------------------- live ---------------------------------- */

// liveClassify reads the role for plan through the discovery role (a route,
// outside any job) and classifies it.
func (s *GovDeployments) liveClassify(ctx context.Context, ctl models.IGAGovControl, p igagov.Plan) (igagov.LiveRead, igagov.Classification, error) {
	env := s.envNow()
	if env.AWS == nil {
		return igagov.LiveRead{}, igagov.Classification{}, govErr(http.StatusServiceUnavailable, GovCodeDiscoveryUnavail,
			"AWS cannot be read through the discovery role right now.", map[string]any{"reason": "AWS access is not configured in this build"})
	}
	disc, err := env.AWS.DiscoveryIAM(ctx, ctl.WorkspaceID, ctl.ConnectorID)
	if err != nil {
		return igagov.LiveRead{}, igagov.Classification{}, govErr(http.StatusServiceUnavailable, GovCodeDiscoveryUnavail,
			"AWS cannot be read through the discovery role right now.", map[string]any{"reason": err.Error()})
	}
	live, _, err := awsenforce.ReadForPlan(ctx, disc, roleNameOfARN(ctl.RoleARN), p, s.now())
	if err != nil {
		return igagov.LiveRead{}, igagov.Classification{}, govErr(http.StatusServiceUnavailable, GovCodeDiscoveryUnavail,
			"AWS cannot be read through the discovery role right now.", map[string]any{"reason": err.Error()})
	}
	cl, err := igagov.Classify(p, live)
	return live, cl, err
}

// inFlightCheck answers 409 when the control has a deployment in flight:
// outcome_unknown_pending for an unknown / unresolved outcome (§8.1),
// deployment_in_flight otherwise.
func inFlightCheck(db *gorm.DB, ws, control uuid.UUID) error {
	var rows []models.IGAGovDeployment
	if err := db.Where("workspace_id = ? AND control_id = ? AND state IN ?", ws, control,
		[]string{"queued", "applying", "outcome_unknown", "outcome_unresolved", "awaiting_merge", "awaiting_apply"}).Find(&rows).Error; err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	r := rows[0]
	if r.State == models.GovDeployOutcomeUnknown || r.State == models.GovDeployOutcomeUnresolved {
		return govConflict(GovCodeOutcomeUnknownPending, "An earlier change on this role has no established outcome; conflicting work waits.",
			map[string]any{"deployment_id": r.ID, "state": r.State, "settle_after": r.SettleAfter})
	}
	return govConflict(GovCodeDeploymentInFlight, "Another change on this role is in flight.", map[string]any{"deployment_id": r.ID, "state": r.State})
}

/* ----------------------------------- undo ---------------------------------- */

// GovUndoRequest is POST /deployments/:id/undo and /emergency-undo.
type GovUndoRequest struct {
	// PlanID names a role-only recovery plan compiled when the undo was
	// blocked by artifact_consumers_changed (its 409 detail.recovery_plan_id).
	PlanID *uuid.UUID `json:"plan_id"`
	Reason string     `json:"reason"`
}

// Undo is §8.9: undo the latest non-undone deployment of a control to its
// recorded before-state with the undo plan approved with it (or, with
// emergency, without the approval reference). The live state is classified
// first with the same classifier the executor uses: a changed artifact is
// 409 artifact_changed_outside_authsec (A15), a changed attachment set is
// 409 artifact_consumers_changed with a role-only recovery plan compiled and
// stored (A35) -- whose hash is not in the original approval, so it needs
// its own approval or governance:emergency.
func (s *GovDeployments) Undo(ctx context.Context, ws, actor, depID uuid.UUID, req GovUndoRequest, emergency bool) (*models.IGAGovDeployment, error) {
	db := s.db.WithContext(ctx)
	if emergency && strings.TrimSpace(req.Reason) == "" {
		return nil, GovBadParam("reason", "An emergency undo needs a reason.")
	}
	d, err := s.loadDeployment(db, ws, depID)
	if err != nil {
		return nil, err
	}
	if d.Kind != igagov.PlanApply {
		return nil, govConflict(GovCodeNotUndoable, "Only an apply deployment is undone; an undo is not undone again.", map[string]any{"kind": d.Kind})
	}
	if err := inFlightCheck(db, ws, d.ControlID); err != nil {
		return nil, err
	}
	var deps []models.IGAGovDeployment
	if err := db.Where("workspace_id = ? AND control_id = ?", ws, d.ControlID).Find(&deps).Error; err != nil {
		return nil, err
	}
	latest := latestUndoable(deps)
	if latest == nil || latest.ID != d.ID {
		detail := map[string]any{"deployment_id": d.ID}
		if latest != nil {
			detail["latest_deployment_id"] = latest.ID
		}
		return nil, govConflict(GovCodeNotLatestDeployment, "Only the latest deployment of this role can be undone; undo in order.", detail)
	}
	ctl, err := s.loadControl(db, ws, d.ControlID)
	if err != nil {
		return nil, err
	}
	var ap models.IGAGovApproval
	if d.ApprovalID != nil {
		if err := db.Where("workspace_id = ? AND id = ?", ws, *d.ApprovalID).Take(&ap).Error; err != nil {
			return nil, err
		}
	}
	var undo models.IGAGovPlan
	if req.PlanID != nil {
		if err := db.Where("workspace_id = ? AND id = ? AND control_id = ? AND kind = 'undo' AND version_id = ?",
			ws, *req.PlanID, d.ControlID, d.VersionID).Take(&undo).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, GovNotFound()
			}
			return nil, err
		}
	} else {
		var ps []models.IGAGovPlan
		if err := db.Where("workspace_id = ? AND version_id = ? AND control_id = ? AND kind = 'undo' AND delivery = ?",
			ws, d.VersionID, d.ControlID, d.Delivery).Order("created_at DESC").Find(&ps).Error; err != nil {
			return nil, err
		}
		for _, p := range ps {
			if d.ApprovalID == nil || containsStr(ap.PlanHashes, p.PlanHash) {
				undo = p
				break
			}
		}
		if undo.ID == uuid.Nil {
			return nil, govConflict(GovCodePlanChanged, "No undo plan of this deployment is named by its approval.", nil)
		}
	}
	if !emergency && (d.ApprovalID == nil || !containsStr(ap.PlanHashes, undo.PlanHash)) {
		return nil, govConflict(GovCodeApprovalRequired,
			"This plan is not named by the deployment's approval; it needs its own approval or an emergency undo.",
			map[string]any{"plan_id": undo.ID})
	}
	plan, err := fullPlanFromRow(undo)
	if err != nil {
		return nil, err
	}
	live, cl, err := s.liveClassify(ctx, *ctl, plan)
	if err != nil {
		return nil, err
	}
	if cl.Class != igagov.ClassBefore {
		detail := map[string]any{"classification": cl}
		switch cl.Reason {
		case igagov.ConflictConsumersChanged:
			rp, err := s.roleOnlyRecovery(ctx, ws, actor, *d, undo, *ctl, live)
			if err != nil {
				return nil, err
			}
			if rp != nil {
				detail["recovery_plan_id"] = rp.ID
				detail["recovery_plan"] = rp
			}
			return nil, govConflict(GovCodeConsumersChanged, "AuthSec's policy is now used by another entity; undoing would change it too. "+
				"A role-only recovery plan that never touches the shared policy was prepared; it needs its own approval.", detail)
		case igagov.ConflictOwnedElsewhere:
			return nil, govConflict(GovCodeOwnedElsewhere, "The artifact belongs to another workspace.", detail)
		case "":
			return nil, govConflict(GovCodePlanChanged, "The role is not in the state the undo starts from.", detail)
		}
		code := GovCodeChangedOutside
		if cl.Reason == igagov.ConflictRoleGone || cl.Reason == igagov.ConflictRoleRecreated {
			code = GovCodePlanChanged
		}
		return nil, govConflict(code, "The role's boundary changed outside AuthSec since the deployment; the undo is blocked.", detail)
	}
	nd := models.IGAGovDeployment{ID: uuid.New(), WorkspaceID: ws, VersionID: d.VersionID, PlanID: undo.ID, ControlID: d.ControlID,
		Kind: igagov.PlanUndo, Delivery: undo.Delivery, State: models.GovDeployQueued, CompletedOps: json.RawMessage("[]")}
	name := GovEventUndoRequested
	if emergency {
		nd.EmergencyBy, nd.EmergencyReason, name = &actor, strings.TrimSpace(req.Reason), GovEventEmergencyUndo
	} else {
		nd.ApprovalID = d.ApprovalID
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&nd).Error; err != nil {
			if isUniqueViolation(err, "uq_iga_gov_deployment_inflight") {
				return govConflict(GovCodeDeploymentInFlight, "Another change on this role started meanwhile.", nil)
			}
			return err
		}
		if err := EnqueueDeployTx(tx, ws, nd.ID); err != nil {
			return err
		}
		pol, _, err := s.policyOfVersion(tx, ws, d.VersionID)
		if err != nil {
			return err
		}
		k, a := userActor(actor)
		payload := map[string]any{"undoes_deployment_id": d.ID, "plan_id": undo.ID, "disposition": undo.ArtifactDisposition,
			"reason": nd.EmergencyReason}
		if emergency {
			payload["notify"] = "approvers and owners"
		}
		return appendGovEvent(tx, ws, name, k, a, depRefs(nd, pol), payload)
	})
	if err != nil {
		return nil, err
	}
	return &nd, nil
}

// latestUndoable is the latest non-undone applied apply deployment.
func latestUndoable(deps []models.IGAGovDeployment) *models.IGAGovDeployment {
	var best *models.IGAGovDeployment
	for i := range deps {
		x := &deps[i]
		if x.AppliedAt == nil || x.Kind == igagov.PlanUndo {
			continue
		}
		switch x.State {
		case models.GovDeployVerified, models.GovDeployAppliedUnverified, models.GovDeployDrifted, models.GovDeploySuperseded:
		default:
			continue
		}
		if best == nil || x.AppliedAt.After(*best.AppliedAt) {
			best = x
		}
	}
	return best
}

// evidenceOf rebuilds a stored plan's evidence reference from its bundle.
func evidenceOf(db *gorm.DB, ws uuid.UUID, p models.IGAGovPlan) (igagov.EvidenceRef, error) {
	var b models.IGAGovEvidenceBundle
	if err := db.Where("workspace_id = ? AND id = ?", ws, p.EvidenceBundleID).Take(&b).Error; err != nil {
		return igagov.EvidenceRef{}, err
	}
	var facts igagov.BundleFacts
	if err := json.Unmarshal(b.Facts, &facts); err != nil {
		return igagov.EvidenceRef{}, err
	}
	gaps, err := bundleGapRefs(facts)
	if err != nil {
		return igagov.EvidenceRef{}, err
	}
	ref := igagov.EvidenceRef{Bundle: igagov.Bundle{Facts: facts, Canonical: []byte(b.Canonical), Hash: b.BundleHash, Trust: b.Trust, GapRefs: gaps},
		EvidenceRev: p.EvidenceRev}
	if p.ResourcePolicyScanRunID != nil {
		ref.ScanRunID = p.ResourcePolicyScanRunID.String()
	}
	return ref, nil
}

// storeSidePlanTx stores a plan that must not displace the target's current
// plans (a role-only recovery or a control removal compiled outside a
// proposal): its documents first, then the row, already superseded_at its
// creation. DECISION (T3.16): "current" (uq_iga_gov_plan_current) is the
// proposal's apply/undo pair the approval binds; a side plan is deployed only
// by a deployment that names it, so it is stored non-current.
func storeSidePlanTx(tx *gorm.DB, ws, versionID, targetID, controlID, bundleID uuid.UUID, p igagov.Plan, now time.Time, current bool) (*models.IGAGovPlan, error) {
	if err := p.CheckStorable(); err != nil {
		return nil, err
	}
	for _, d := range p.Documents {
		if err := tx.Exec(`INSERT INTO iga_gov_document (workspace_id, document_hash, canonical, document)
			VALUES (?, ?, ?, ?::jsonb) ON CONFLICT (workspace_id, document_hash) DO NOTHING`, ws, d.Hash, d.Canonical, d.Canonical).Error; err != nil {
			return nil, err
		}
	}
	row, err := planRow(ws, versionID, models.IGAGovTarget{ID: targetID, ControlID: controlID}, bundleID, p)
	if err != nil {
		return nil, err
	}
	row.CreatedAt = now
	if !current {
		row.SupersededAt = &now
	}
	if err := tx.Create(&row).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

// roleOnlyRecovery compiles and stores §8.9's role-only recovery plan for a
// blocked undo (nil when the compiler refuses one: not needed or not
// available, recorded in the event).
func (s *GovDeployments) roleOnlyRecovery(ctx context.Context, ws, actor uuid.UUID, d models.IGAGovDeployment, undo models.IGAGovPlan, ctl models.IGAGovControl, live igagov.LiveRead) (*models.IGAGovPlan, error) {
	db := s.db.WithContext(ctx)
	up, err := fullPlanFromRow(undo)
	if err != nil {
		return nil, err
	}
	ev, err := evidenceOf(db, ws, undo)
	if err != nil {
		return nil, err
	}
	earlier := ""
	if undo.DesiredDocumentHash != nil {
		var docs []string
		_ = db.Raw(`SELECT canonical FROM iga_gov_document WHERE workspace_id = ? AND document_hash = ?`, ws, *undo.DesiredDocumentHash).Scan(&docs)
		if len(docs) == 1 {
			earlier = docs[0]
		}
	}
	owned, err := s.authoring.ownedPolicyARNs(db, ws, ctl.ID)
	if err != nil {
		return nil, err
	}
	// The -u policy, if it may exist, is read too.
	uarn, _ := igagov.RecoveryPolicyARN(arnPartition(ctl.RoleARN), ctl.AccountID, ctl.RoleID, d.ID.String())
	if _, ok := live.Policies[uarn]; !ok && s.envNow().AWS != nil {
		if disc, err := s.envNow().AWS.DiscoveryIAM(ctx, ws, ctl.ConnectorID); err == nil {
			if lp, _, err := awsenforce.ReadPolicy(ctx, disc, uarn); err == nil {
				live.Policies[uarn] = lp
			}
		}
	}
	ref := igagov.ControlRef{ID: ctl.ID.String(), PolicyID: ctl.PolicyID.String(), AccountID: ctl.AccountID, RoleID: ctl.RoleID,
		WorkspaceRef: GovWorkspaceRef(ws), OwnedPolicyARNs: owned}
	rp, err := igagov.CompileRoleOnlyRecovery(igagov.RecoveryInput{Control: ref, Undo: up, UndoneDeploymentID: d.ID.String(),
		EarlierDocument: earlier, Live: live, Evidence: ev})
	if err != nil {
		return nil, err
	}
	var out *models.IGAGovPlan
	err = db.Transaction(func(tx *gorm.DB) error {
		pol, _, err := s.policyOfVersion(tx, ws, d.VersionID)
		if err != nil {
			return err
		}
		k, a := userActor(actor)
		if !rp.Eligible() {
			return appendGovEvent(tx, ws, GovEventRoleOnlyRecoveryPlan, k, a, depRefs(d, pol),
				map[string]any{"eligible": false, "reason": rp.IneligibleReason})
		}
		row, err := storeSidePlanTx(tx, ws, d.VersionID, undo.TargetID, ctl.ID, undo.EvidenceBundleID, rp, s.now(), false)
		if err != nil {
			return err
		}
		out = row
		return appendGovEvent(tx, ws, GovEventRoleOnlyRecoveryPlan, k, a, depRefs(d, pol), map[string]any{"eligible": true,
			"plan_id": row.ID, "plan_hash": row.PlanHash, "desired_attachment": row.DesiredAttachment,
			"disposition": row.ArtifactDisposition, "replaced_boundary_arn": row.ReplacedBoundaryARN})
	})
	return out, err
}

/* ---------------------------------- resolve -------------------------------- */

// GovResolveRequest is POST /deployments/:id/resolve.
type GovResolveRequest struct {
	Action string `json:"action"`
	Reason string `json:"reason"`
	// VersionNo names the approved "accept observed state" version whose
	// deployment takes over the role (the second accept_observed call).
	VersionNo *int `json:"version_no"`
}

// Resolve is §8.1 step 3 for an outcome_unresolved deployment:
//
//   - reread: back to outcome_unknown and step 2 again (two new readings);
//   - accept_observed: the first call creates a draft version with the same
//     intent and proposes it (plans compiled from what is in AWS now; owner
//     review opened); the role stays held. Once that version is approved, a
//     call naming it (version_no) performs the ATOMIC HANDOFF: the
//     unresolved deployment becomes recovered naming its successor, and the
//     successor (the approved apply plan) is inserted naming it back, in one
//     transaction (deferred FKs, probes DB133-DB135);
//   - emergency_undo (governance:emergency): the version's undo plan, when
//     the observed state is exactly the apply's post-state (the undo's
//     precondition), handed off the same way with emergency_by.
//
// 409 outcome_unknown_pending while outcome_unknown before settle_after.
//
// Review P1-5: a deployment stuck in `applying` is resolved here too
// (resolveApplying, iga_gov_deploy_sweep.go): reread re-queues its deploy
// job; accept_observed / emergency_undo first declare it outcome_unresolved
// (it keeps holding the role) and then proceed as above. A reread of an
// unresolved deployment with no unresolved unknown attempt (an exhausted
// deploy job, an operator's declaration) returns it to applying with its
// deploy job queued.
func (s *GovDeployments) Resolve(ctx context.Context, ws, actor, depID uuid.UUID, req GovResolveRequest) (any, error) {
	db := s.db.WithContext(ctx)
	d, err := s.loadDeployment(db, ws, depID)
	if err != nil {
		return nil, err
	}
	switch req.Action {
	case "reread", "accept_observed", "emergency_undo":
	default:
		return nil, GovBadParam("action", "action must be reread, accept_observed or emergency_undo.")
	}
	if strings.TrimSpace(req.Reason) == "" {
		return nil, GovBadParam("reason", "A reason is required.")
	}
	if d.State == models.GovDeployOutcomeUnknown && d.SettleAfter != nil && s.now().Before(*d.SettleAfter) {
		return nil, govConflict(GovCodeOutcomeUnknownPending, "The earlier request may still reach AWS; wait until settle_after.",
			map[string]any{"settle_after": d.SettleAfter})
	}
	if d.State != models.GovDeployOutcomeUnresolved && d.State != models.GovDeployApplying &&
		!(req.Action == "reread" && d.State == models.GovDeployOutcomeUnknown) {
		return nil, govConflict(GovCodeNotUnresolved, "Only a deployment whose outcome is unresolved, or that is stuck applying, is resolved here.",
			map[string]any{"state": d.State})
	}
	if d.State == models.GovDeployApplying {
		if err := s.resolveApplying(ctx, *d, actor, req); err != nil {
			return nil, err
		}
		if req.Action == "reread" {
			return s.loadDeployment(db, ws, d.ID)
		}
		if d, err = s.loadDeployment(db, ws, d.ID); err != nil {
			return nil, err
		}
	}
	pol, _, err := s.policyOfVersion(db, ws, d.VersionID)
	if err != nil {
		return nil, err
	}
	k, a := userActor(actor)
	switch req.Action {
	case "reread":
		open, err := s.attempts.OpenAttempt(db, ws, d.ID)
		if err != nil {
			return nil, err
		}
		err = db.Transaction(func(tx *gorm.DB) error {
			if open == nil || open.Status != models.GovAttemptUnknown {
				if err := appendGovEvent(tx, ws, GovEventDeploymentResolveReq, k, a, depRefs(*d, pol),
					map[string]any{"action": req.Action, "reason": req.Reason, "from_state": d.State}); err != nil {
					return err
				}
				return s.rereadWithoutAttemptTx(tx, *d)
			}
			if d.State == models.GovDeployOutcomeUnresolved {
				if err := setStateTx(tx, *d, []string{models.GovDeployOutcomeUnresolved}, map[string]any{"state": models.GovDeployOutcomeUnknown,
					"state_reason": "re-read requested"}); err != nil {
					return err
				}
			}
			if err := appendGovEvent(tx, ws, GovEventDeploymentResolveReq, k, a, depRefs(*d, pol),
				map[string]any{"action": req.Action, "reason": req.Reason}); err != nil {
				return err
			}
			return enqueueJobTx(tx, ws, "resolve_unknown", d.ID, s.now())
		})
		if errors.Is(err, errStateMoved) {
			return nil, govConflict(GovCodeNotUnresolved, "The deployment moved meanwhile.", nil)
		}
		if err != nil {
			return nil, err
		}
		return s.loadDeployment(db, ws, d.ID)
	case "emergency_undo":
		var undo []models.IGAGovPlan
		if err := db.Where("workspace_id = ? AND version_id = ? AND control_id = ? AND kind = 'undo' AND superseded_at IS NULL",
			ws, d.VersionID, d.ControlID).Find(&undo).Error; err != nil {
			return nil, err
		}
		if d.Kind != igagov.PlanApply || len(undo) != 1 {
			return nil, govConflict(GovCodeEmergencyUndoUnavail, "No undo plan of this deployment exists.", nil)
		}
		ctl, err := s.loadControl(db, ws, d.ControlID)
		if err != nil {
			return nil, err
		}
		up, err := fullPlanFromRow(undo[0])
		if err != nil {
			return nil, err
		}
		_, cl, err := s.liveClassify(ctx, *ctl, up)
		if err != nil {
			return nil, err
		}
		if cl.Class != igagov.ClassBefore {
			return nil, govConflict(GovCodeEmergencyUndoUnavail,
				"The role is not in the state the undo starts from; re-read, or accept the observed state.", map[string]any{"classification": cl})
		}
		succ := models.IGAGovDeployment{ID: uuid.New(), WorkspaceID: ws, VersionID: d.VersionID, PlanID: undo[0].ID, ControlID: d.ControlID,
			Kind: igagov.PlanUndo, Delivery: undo[0].Delivery, State: models.GovDeployQueued, CompletedOps: json.RawMessage("[]"),
			EmergencyBy: &actor, EmergencyReason: strings.TrimSpace(req.Reason)}
		if err := s.Handoff(ctx, *d, &succ, actor, req.Action); err != nil {
			return nil, err
		}
		return succ, nil
	}
	// accept_observed
	if req.VersionNo == nil {
		var v models.IGAGovPolicyVersion
		if err := db.Where("workspace_id = ? AND id = ?", ws, d.VersionID).Take(&v).Error; err != nil {
			return nil, err
		}
		var maxNo int
		if err := db.Raw(`SELECT max(version_no) FROM iga_gov_policy_version WHERE workspace_id = ? AND policy_id = ?`, ws, pol).Scan(&maxNo).Error; err != nil {
			return nil, err
		}
		nv, err := s.authoring.CreateVersion(ctx, ws, actor, pol, maxNo, v.Intent)
		if err != nil {
			return nil, err
		}
		res, err := s.authoring.Propose(ctx, ws, actor, pol, nv.No)
		if err != nil {
			return nil, err
		}
		if err := db.Transaction(func(tx *gorm.DB) error {
			return appendGovEvent(tx, ws, GovEventAcceptObservedOpened, k, a, depRefs(*d, pol), map[string]any{"version_no": nv.No,
				"reason": req.Reason, "note": "The role stays held until this version is approved and its deployment takes over."})
		}); err != nil {
			return nil, err
		}
		return res, nil
	}
	var v models.IGAGovPolicyVersion
	if err := db.Where("workspace_id = ? AND policy_id = ? AND version_no = ?", ws, pol, *req.VersionNo).Take(&v).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, GovNotFound()
		}
		return nil, err
	}
	var ap []models.IGAGovPlan
	if err := db.Where("workspace_id = ? AND version_id = ? AND control_id = ? AND kind = 'apply' AND superseded_at IS NULL",
		ws, v.ID, d.ControlID).Find(&ap).Error; err != nil {
		return nil, err
	}
	if len(ap) != 1 {
		return nil, govConflict(GovCodePlanChanged, "That version has no plan for this role.", nil)
	}
	ua, err := s.authoring.UsableApproval(ctx, ws, v.ID, []uuid.UUID{ap[0].ID})
	if err != nil {
		return nil, err
	}
	succ := models.IGAGovDeployment{ID: uuid.New(), WorkspaceID: ws, VersionID: v.ID, PlanID: ap[0].ID, ControlID: d.ControlID,
		ApprovalID: &ua.Approval.ID, Kind: igagov.PlanApply, Delivery: ap[0].Delivery, State: models.GovDeployQueued,
		CompletedOps: json.RawMessage("[]")}
	if rv := ua.Revalidations[ap[0].ID]; rv != nil {
		r := models.GovRevalidationUnchanged
		succ.RevalidationID, succ.RevalidationResult = rv, &r
	}
	if err := s.Handoff(ctx, *d, &succ, actor, req.Action); err != nil {
		return nil, err
	}
	return succ, nil
}

// Handoff is §8.1 step 4: in ONE transaction the unresolved deployment
// becomes recovered naming its successor and the successor is inserted
// naming it back on the same control (both FKs checked at commit), then its
// deploy job is queued. Only an outcome_unresolved deployment is released.
func (s *GovDeployments) Handoff(ctx context.Context, unresolved models.IGAGovDeployment, succ *models.IGAGovDeployment, actor uuid.UUID, why string) error {
	ws := unresolved.WorkspaceID
	succ.RecoversDeploymentID = &unresolved.ID
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`SELECT id FROM iga_gov_control WHERE workspace_id = ? AND id = ? FOR UPDATE`, ws, unresolved.ControlID).Error; err != nil {
			return err
		}
		if err := setStateTx(tx, unresolved, []string{models.GovDeployOutcomeUnresolved}, map[string]any{"state": models.GovDeployRecovered,
			"recovered_by_deployment_id": succ.ID, "state_reason": "recovered by deployment " + succ.ID.String() + " (" + why + ")"}); err != nil {
			if errors.Is(err, errStateMoved) {
				return govConflict(GovCodeNotUnresolved, "The deployment is no longer unresolved.", nil)
			}
			return err
		}
		if err := tx.Create(succ).Error; err != nil {
			return err
		}
		if err := EnqueueDeployTx(tx, ws, succ.ID); err != nil {
			return err
		}
		pol, _, err := s.policyOfVersion(tx, ws, unresolved.VersionID)
		if err != nil {
			return err
		}
		k, a := userActor(actor)
		return appendGovEvent(tx, ws, GovEventDeploymentRecovered, k, a, depRefs(unresolved, pol), map[string]any{"successor_id": succ.ID,
			"action": why, "successor_kind": succ.Kind})
	})
}

/* -------------------------------- validations ------------------------------- */

// GovValidationItemInput is one declared action.
type GovValidationItemInput struct {
	Action   string `json:"action"`
	Expected string `json:"expected"`
}

// GovValidationRequest is POST /deployments/:id/validations.
type GovValidationRequest struct {
	Items               []GovValidationItemInput `json:"items"`
	Correlation         string                   `json:"correlation"`
	DedicatedWorkloadID *uuid.UUID               `json:"dedicated_workload_id"`
	WindowStart         time.Time                `json:"window_start"`
	WindowEnd           time.Time                `json:"window_end"`
	Note                string                   `json:"note"`
}

// DeclareValidation is §8.7's declared validation: role_id from the
// deployment's control, an authsec-validate-<12hex> session for
// assumed_session, the dedicated workload's name (unique in the workspace)
// for dedicated_workload; every action must map to a CloudTrail event
// (422 action_not_mappable).
func (s *GovDeployments) DeclareValidation(ctx context.Context, ws, actor, depID uuid.UUID, req GovValidationRequest) (*GovValidationView, error) {
	db := s.db.WithContext(ctx)
	d, err := s.loadDeployment(db, ws, depID)
	if err != nil {
		return nil, err
	}
	if len(req.Items) == 0 {
		return nil, GovBadParam("items", "At least one action is declared.")
	}
	seen := map[string]bool{}
	for i, it := range req.Items {
		ns, _, ok := igagov.SplitAction(it.Action)
		if !reValidationAction.MatchString(it.Action) || !ok {
			return nil, govUnprocessable(GovCodeActionNotMappable, "The action cannot be matched to CloudTrail events.",
				map[string]any{"index": i, "action": it.Action})
		}
		if _, ok := igagov.ActionForEvent(ns+".amazonaws.com", strings.SplitN(it.Action, ":", 2)[1]); !ok {
			return nil, govUnprocessable(GovCodeActionNotMappable, "The action cannot be matched to CloudTrail events.",
				map[string]any{"index": i, "action": it.Action})
		}
		if it.Expected != igagov.ExpectDenied && it.Expected != igagov.ExpectAllowed {
			return nil, GovBadParam("items", "expected must be denied or allowed.")
		}
		if seen[it.Action] {
			return nil, GovBadParam("items", "An action is declared twice.")
		}
		seen[it.Action] = true
	}
	if !req.WindowEnd.After(req.WindowStart) {
		return nil, GovBadParam("window_end", "The window must end after it starts.")
	}
	ctl, err := s.loadControl(db, ws, d.ControlID)
	if err != nil {
		return nil, err
	}
	v := models.IGAGovValidation{ID: uuid.New(), WorkspaceID: ws, DeploymentID: d.ID, CreatedBy: actor, RoleID: ctl.RoleID,
		Correlation: req.Correlation, WindowStart: req.WindowStart.UTC(), WindowEnd: req.WindowEnd.UTC(), Note: req.Note, Result: "pending"}
	switch req.Correlation {
	case "assumed_session":
		b := make([]byte, 6)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		v.SessionName = "authsec-validate-" + hex.EncodeToString(b)
	case "dedicated_workload":
		if req.DedicatedWorkloadID == nil {
			return nil, GovBadParam("dedicated_workload_id", "A dedicated workload is named.")
		}
		var w []struct {
			ID          uuid.UUID
			DisplayName string
		}
		if err := db.Raw(`SELECT id, display_name FROM iga_workload WHERE workspace_id = ? AND id = ?`, ws, *req.DedicatedWorkloadID).Scan(&w).Error; err != nil {
			return nil, err
		}
		if len(w) == 0 {
			return nil, GovNotFound()
		}
		var dup int64
		if err := db.Raw(`SELECT count(*) FROM iga_workload WHERE workspace_id = ? AND id <> ? AND display_name = ? AND lifecycle = 'active'`,
			ws, w[0].ID, w[0].DisplayName).Scan(&dup).Error; err != nil {
			return nil, err
		}
		if dup > 0 {
			return nil, govUnprocessable(GovCodeSessionNotUnique, "Another workload uses the same session name; its calls could not be told apart.",
				map[string]any{"session_name": w[0].DisplayName})
		}
		v.SessionName, v.DedicatedWorkloadID = w[0].DisplayName, req.DedicatedWorkloadID
	default:
		return nil, GovBadParam("correlation", "correlation must be assumed_session or dedicated_workload.")
	}
	out := &GovValidationView{IGAGovValidation: v}
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&v).Error; err != nil {
			if isUniqueViolation(err, "uq_iga_gov_validation_session") || strings.Contains(err.Error(), "iga_gov_vr_correlation_chk") ||
				strings.Contains(err.Error(), "session_name") {
				return govUnprocessable(GovCodeSessionNotUnique, "The session name cannot identify this test uniquely.", map[string]any{"session_name": v.SessionName})
			}
			return err
		}
		sort.Slice(req.Items, func(i, j int) bool { return req.Items[i].Action < req.Items[j].Action })
		for _, it := range req.Items {
			row := models.IGAGovValidationItem{WorkspaceID: ws, ValidationID: v.ID, Action: it.Action, Expected: it.Expected,
				Result: "pending", Evidence: json.RawMessage("{}")}
			if err := tx.Create(&row).Error; err != nil {
				return err
			}
			out.Items = append(out.Items, row)
		}
		pol, _, err := s.policyOfVersion(tx, ws, d.VersionID)
		if err != nil {
			return err
		}
		k, a := userActor(actor)
		return appendGovEvent(tx, ws, GovEventValidationDeclared, k, a, depRefs(*d, pol), map[string]any{"validation_id": v.ID,
			"session_name": v.SessionName, "correlation": v.Correlation, "items": req.Items, "window_start": v.WindowStart, "window_end": v.WindowEnd})
	})
	if err != nil {
		return nil, err
	}
	out.IGAGovValidation = v
	return out, nil
}

// ListValidations is GET /deployments/:id/validations.
func (s *GovDeployments) ListValidations(ctx context.Context, ws, depID uuid.UUID) ([]GovValidationView, error) {
	db := s.db.WithContext(ctx)
	d, err := s.loadDeployment(db, ws, depID)
	if err != nil {
		return nil, err
	}
	vs, items, err := loadValidations(db, *d)
	if err != nil {
		return nil, err
	}
	out := []GovValidationView{}
	for _, v := range vs {
		out = append(out, GovValidationView{IGAGovValidation: v, Items: items[v.ID]})
	}
	return out, nil
}

/* ------------------------------- health reports ----------------------------- */

// GovHealthReportRequest is POST /deployments/:id/health-reports.
type GovHealthReportRequest struct {
	Kind    string `json:"kind"`
	Service string `json:"service"`
	Detail  string `json:"detail"`
	Channel string `json:"-"`
}

// CreateHealthReport records an owner's report. Allowed for an owner of a
// consumer of the role (a workload in the plan's impact, or the role's
// identity) or a holder of governance:author (isAuthor).
func (s *GovDeployments) CreateHealthReport(ctx context.Context, ws, actor, depID uuid.UUID, req GovHealthReportRequest, isAuthor bool) (*models.IGAGovHealthReport, error) {
	db := s.db.WithContext(ctx)
	d, err := s.loadDeployment(db, ws, depID)
	if err != nil {
		return nil, err
	}
	if req.Kind != igagov.ReportProblem && req.Kind != igagov.ReportWorking {
		return nil, GovBadParam("kind", "kind must be problem or working.")
	}
	if req.Kind == igagov.ReportProblem && strings.TrimSpace(req.Detail) == "" {
		return nil, GovBadParam("detail", "A problem report needs a description.")
	}
	if !isAuthor {
		p, err := s.loadPlanRow(db, ws, d.PlanID)
		if err != nil {
			return nil, err
		}
		ctl, err := s.loadControl(db, ws, d.ControlID)
		if err != nil {
			return nil, err
		}
		var im igagov.Impact
		_ = json.Unmarshal(p.Impact, &im)
		wl := []uuid.UUID{}
		for _, c := range im.Consumers {
			if id, err := uuid.Parse(c.WorkloadID); err == nil {
				wl = append(wl, id)
			}
		}
		var n int64
		if err := db.Raw(`SELECT count(*) FROM iga_gov_owner WHERE workspace_id = ? AND user_id = ?
			AND ((object_kind = 'workload' AND workload_id IN ?) OR (object_kind = 'identity_account' AND identity_account_id = ?))`,
			ws, actor, append(wl, uuid.Nil), ctl.IdentityAccountID).Scan(&n).Error; err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, govErr(http.StatusForbidden, GovCodeNotConsumerOwner, "Only an owner of a consumer of this role, or an author, can report.", nil)
		}
	}
	ch := req.Channel
	if ch == "" {
		ch = "ui"
	}
	hr := models.IGAGovHealthReport{ID: uuid.New(), WorkspaceID: ws, DeploymentID: d.ID, ReportedBy: actor, Kind: req.Kind,
		Service: strings.ToLower(strings.TrimSpace(req.Service)), Detail: strings.TrimSpace(req.Detail), Channel: ch, CreatedAt: s.now().UTC()}
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&hr).Error; err != nil {
			return err
		}
		pol, _, err := s.policyOfVersion(tx, ws, d.VersionID)
		if err != nil {
			return err
		}
		k, a := userActor(actor)
		return appendGovEvent(tx, ws, GovEventHealthReported, k, a, depRefs(*d, pol), map[string]any{"report_id": hr.ID,
			"kind": hr.Kind, "service": hr.Service, "channel": hr.Channel})
	})
	if err != nil {
		return nil, err
	}
	return &hr, nil
}

// ListHealthReports is GET /deployments/:id/health-reports.
func (s *GovDeployments) ListHealthReports(ctx context.Context, ws, depID uuid.UUID) ([]models.IGAGovHealthReport, error) {
	db := s.db.WithContext(ctx)
	d, err := s.loadDeployment(db, ws, depID)
	if err != nil {
		return nil, err
	}
	out := []models.IGAGovHealthReport{}
	err = db.Where("workspace_id = ? AND deployment_id = ?", ws, d.ID).Order("created_at, id").Find(&out).Error
	return out, err
}

// GovForbidden is a 403 forbidden in the §7 envelope.
func GovForbidden(msg string) *GovError { return govErr(http.StatusForbidden, "forbidden", msg, nil) }
