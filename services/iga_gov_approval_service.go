package services

import (
	"context"
	"encoding/json"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
)

// Approval (SPEC-iga-phase3-policy.md §2.8, §2.10, §7.5; T3.13): a decision
// bound to the intent, every target's impact, the plan and material hashes
// of every apply and undo plan, and one iga_gov_acceptance row per accepted
// uncertainty; separation of duties (the author never decides, for every
// role including admins); invalidation (a decision is refused when any
// bound hash changed since the approver loaded it, and an approval stops
// being usable when the version, the plans, the approver or time move on).

// Approval error codes (§7.12).
const (
	GovCodeSelfApproval        = "self_approval"
	GovCodePlanChanged         = "plan_changed"
	GovCodeImpactChanged       = "impact_changed"
	GovCodeResidualsNotAccept  = "residuals_not_accepted"
	GovCodeGapsNotAccepted     = "evidence_gaps_not_accepted"
	GovCodeApprovalExpired     = "approval_expired"
	GovCodeApprovalRequired    = "approval_required"
	GovCodeApprovalInvalid     = "approval_invalid"
	GovCodeRevalidationNeeded  = "revalidation_required"
	GovCodeRevalidationBlocked = "revalidation_blocked"
	GovCodeMaterialChange      = "material_change"
)

// GovAcceptanceInput is one accepted item in an approval body.
type GovAcceptanceInput struct {
	Kind     string `json:"kind"`
	PlanID   string `json:"plan_id"`
	ItemKey  string `json:"item_key"`
	ItemHash string `json:"item_hash"`
	Reason   string `json:"reason"`
}

// GovApproveRequest is POST /policies/:id/versions/:no/approve. Every hash
// must equal its current value (GET .../plans "hashes"), and every
// acceptance item of the plans must be accepted once.
type GovApproveRequest struct {
	IntentHash     string               `json:"intent_hash"`
	ImpactHashes   []string             `json:"impact_hashes"`
	PlanHashes     []string             `json:"plan_hashes"`
	MaterialHashes []string             `json:"material_hashes"`
	Acceptances    []GovAcceptanceInput `json:"acceptances"`
	Reason         string               `json:"reason"`
	// Channel is ui (this route) or slack (T3.14); not read from JSON.
	Channel string `json:"-"`
}

// GovApprovalResult is the approval and its acceptance rows.
type GovApprovalResult struct {
	Approval    models.IGAGovApproval     `json:"approval"`
	Acceptances []models.IGAGovAcceptance `json:"acceptances"`
	Version     GovVersionView            `json:"version"`
}

func sortedCopy(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

func sameMultiset(a, b []string) bool {
	x, y := sortedCopy(a), sortedCopy(b)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// liveApproval is the version's unrevoked approve decision, or nil.
func liveApproval(db *gorm.DB, ws, versionID uuid.UUID) (*models.IGAGovApproval, error) {
	var as []models.IGAGovApproval
	if err := db.Where("workspace_id = ? AND version_id = ? AND decision = 'approve' AND revoked_at IS NULL", ws, versionID).
		Find(&as).Error; err != nil {
		return nil, err
	}
	if len(as) == 0 {
		return nil, nil
	}
	return &as[0], nil
}

// holdsPermission is §2.8's re-check that the approver "still holds
// governance:approve", read from the database rather than a token
// (DECISION A11). The role/permission tables are platform authorization,
// not IGA data: the query lives in workspace_permission_check.go, outside
// the IGA files, the way humanActor's membership check lives in the
// controllers.
func holdsPermission(db *gorm.DB, ws, user uuid.UUID, resource, action string) (bool, error) {
	return WorkspaceUserHoldsPermission(db, ws, user, resource, action)
}

// Approve records an approval (§7.5). In one transaction, with the version
// row locked: the version must be in review; the approver must not be its
// author (403 self_approval, for every role); every target must have an
// eligible current apply plan; the intent, impact, plan and material hashes
// must equal the current ones (409 impact_changed / plan_changed); the
// owner gate (T3.12's hook) must pass; every unanalysed item and every
// bundle gap must be accepted exactly once (409 residuals_not_accepted /
// evidence_gaps_not_accepted); then the approval and one acceptance row per
// item are inserted, the version becomes approved and the previously
// approved version of the policy is superseded (its approval revoked).
func (a *GovAuthoring) Approve(ctx context.Context, ws, approver, policyID uuid.UUID, no int, req GovApproveRequest) (*GovApprovalResult, error) {
	if req.Channel == "" {
		req.Channel = "ui"
	}
	if req.IntentHash == "" || req.ImpactHashes == nil || req.PlanHashes == nil || req.MaterialHashes == nil {
		return nil, GovBadParam("body", "intent_hash, impact_hashes, plan_hashes and material_hashes are required (GET .../plans gives them).")
	}
	for i, x := range req.Acceptances {
		if x.Kind != GovAcceptUnanalysed && x.Kind != GovAcceptGap {
			return nil, GovBadParam(fmt.Sprintf("acceptances[%d].kind", i), "kind must be unanalysed_form or evidence_gap.")
		}
		if strings.TrimSpace(x.Reason) == "" {
			return nil, GovBadParam(fmt.Sprintf("acceptances[%d].reason", i), "Each accepted item needs a reason.")
		}
		if _, err := uuid.Parse(x.PlanID); err != nil {
			return nil, GovBadParam(fmt.Sprintf("acceptances[%d].plan_id", i), "plan_id must be a uuid.")
		}
	}
	var out GovApprovalResult
	err := a.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		pol, err := a.loadPolicy(tx, ws, policyID, true)
		if err != nil {
			return err
		}
		if pol.Lifecycle == "archived" {
			return govConflict(GovCodePolicyArchived, "The policy is archived and read-only.", nil)
		}
		v, err := a.loadVersion(tx, ws, policyID, no, true)
		if err != nil {
			return err
		}
		if v.CreatedBy == approver {
			return govErr(http.StatusForbidden, GovCodeSelfApproval, "You authored this version; another approver must decide.", nil)
		}
		if v.Status != "in_review" {
			return govConflict(GovCodeVersionConflict, "Only a version in review can be approved.", map[string]any{"status": v.Status})
		}
		plans, err := currentPlans(tx, ws, v.ID)
		if err != nil {
			return err
		}
		ts, cs, err := a.versionTargets(tx, ws, v.ID)
		if err != nil {
			return err
		}
		var applies []GovPlanSummary
		var ineligible []map[string]any
		for _, t := range ts {
			found := false
			for _, p := range plans {
				// T3.16: a remove_control version's forward plan is its
				// remove_control plan (§8.10 "follows the normal approve path").
				if p.TargetID == t.ID && (p.Kind == igagov.PlanApply || p.Kind == igagov.PlanRemoveControl) {
					found = true
					if p.Eligibility == igagov.EligibilityIneligible {
						ineligible = append(ineligible, map[string]any{"target_id": t.ID, "role_id": p.RoleID, "reason": p.IneligibleReason})
					}
					applies = append(applies, summary(p.IGAGovPlan, cs[t.ID]))
				}
			}
			if !found {
				ineligible = append(ineligible, map[string]any{"target_id": t.ID, "role_id": cs[t.ID].RoleID, "reason": "not_compiled"})
			}
		}
		if len(ineligible) > 0 {
			return govUnprocessable(GovCodeTargetIneligible, "Some targets have no eligible plan.", map[string]any{"targets": ineligible})
		}
		cur := approvalHashes(*v, plans)
		if req.IntentHash != cur.IntentHash {
			return govConflict(GovCodePlanChanged, "The intent changed since you loaded it; review the current version.",
				map[string]any{"current": cur})
		}
		if !sameMultiset(req.ImpactHashes, cur.ImpactHashes) {
			return govConflict(GovCodeImpactChanged, "Who or what this change affects changed since you loaded it; review it again.",
				map[string]any{"current": cur})
		}
		if !sameMultiset(req.PlanHashes, cur.PlanHashes) || !sameMultiset(req.MaterialHashes, cur.MaterialHashes) {
			return govConflict(GovCodePlanChanged, "The plan changed since you loaded it; review the new plan.", map[string]any{"current": cur})
		}
		// T3.16: a remove_control version has no right-size intent; the owner
		// gate receives the zero intent and the plans.
		var intent igagov.RightSizeIntent
		if !isRemoveControlVersion(*v) {
			if intent, err = storedRightSize(*v); err != nil {
				return err
			}
		}
		if h := a.hooks().OwnerGate; h != nil {
			if err := h(tx, GovApprovalCheck{WorkspaceID: ws, PolicyID: policyID, VersionID: v.ID, ApproverID: approver,
				Intent: intent, ApplyPlans: applies, ImpactHashes: cur.ImpactHashes}); err != nil {
				return err
			}
		}
		items, err := requiredAcceptances(tx, ws, plans)
		if err != nil {
			return err
		}
		accepted, err := matchAcceptances(items, req.Acceptances)
		if err != nil {
			return err
		}
		bundleOf := map[uuid.UUID]uuid.UUID{}
		for _, p := range plans {
			bundleOf[p.ID] = p.EvidenceBundleID
		}
		for i := range accepted {
			// The accepted item binds its plan's bundle (051 FK).
			accepted[i].bundleID = bundleOf[accepted[i].item.PlanID]
		}
		settings, err := a.settings.Get(ws)
		if err != nil {
			return err
		}
		days := settings.ApprovalValidDays
		if days < 1 {
			days = 7
		}
		now := a.now()
		var rev int64
		for _, p := range plans {
			if p.EvidenceRev > rev {
				rev = p.EvidenceRev
			}
		}
		// Supersede the previously approved version first: at most one
		// approved version per policy (049 partial unique index).
		var prev []models.IGAGovPolicyVersion
		if err := tx.Where("workspace_id = ? AND policy_id = ? AND status = 'approved' AND id <> ?", ws, policyID, v.ID).
			Clauses(lockForUpdate()).Find(&prev).Error; err != nil {
			return err
		}
		for _, pv := range prev {
			if err := a.closeVersionTx(tx, approver, pv, "superseded", fmt.Sprintf("version %d approved", no), nil); err != nil {
				return err
			}
		}
		ap := models.IGAGovApproval{ID: uuid.New(), WorkspaceID: ws, VersionID: v.ID, Decision: "approve", DecidedBy: approver,
			Channel: req.Channel, IntentHash: cur.IntentHash, ImpactHashes: pq.StringArray(cur.ImpactHashes),
			PlanHashes: pq.StringArray(cur.PlanHashes), MaterialHashes: pq.StringArray(cur.MaterialHashes), EvidenceRev: rev,
			Reason: req.Reason, ExpiresAt: now.Add(time.Duration(days) * 24 * time.Hour), DecidedAt: now}
		if err := tx.Create(&ap).Error; err != nil {
			if isUniqueViolation(err, "uq_iga_gov_approval_live") {
				return govConflict(GovCodeVersionConflict, "This version was approved at the same time by someone else.", nil)
			}
			return err
		}
		k, aid := userActor(approver)
		out.Acceptances = []models.IGAGovAcceptance{}
		for _, it := range accepted {
			pid, bid := it.item.PlanID, it.bundleID
			row := models.IGAGovAcceptance{ID: uuid.New(), WorkspaceID: ws, Kind: it.item.Kind, ItemKey: it.item.ItemKey,
				ItemHash: it.item.ItemHash, VersionID: v.ID, ApprovalID: &ap.ID, PlanID: &pid, EvidenceBundleID: &bid,
				Reason: strings.TrimSpace(it.reason), AcceptedBy: approver, AcceptedAt: now}
			if err := tx.Create(&row).Error; err != nil {
				return err
			}
			out.Acceptances = append(out.Acceptances, row)
			if err := a.event(tx, ws, "acceptance_recorded", k, aid, &policyID, &v.ID, map[string]any{"acceptance_id": row.ID,
				"kind": row.Kind, "item_key": row.ItemKey, "item_hash": row.ItemHash, "plan_id": pid, "evidence_bundle_id": bid,
				"approval_id": ap.ID, "reason": row.Reason}); err != nil {
				return err
			}
		}
		if err := tx.Model(&models.IGAGovPolicyVersion{}).Where("workspace_id = ? AND id = ?", ws, v.ID).
			Updates(map[string]any{"status": "approved", "status_changed_at": now}).Error; err != nil {
			return err
		}
		if err := a.event(tx, ws, "version_approved", k, aid, &policyID, &v.ID, map[string]any{"approval_id": ap.ID,
			"version_no": no, "channel": ap.Channel, "plan_hashes": cur.PlanHashes, "material_hashes": cur.MaterialHashes,
			"impact_hashes": cur.ImpactHashes, "acceptances": len(out.Acceptances), "expires_at": ap.ExpiresAt}); err != nil {
			return err
		}
		if h := a.hooks().OnApproved; h != nil {
			if err := h(tx, ws, v.ID, ap.ID); err != nil {
				return err
			}
		}
		out.Approval = ap
		nv, err := a.loadVersion(tx, ws, policyID, no, false)
		if err != nil {
			return err
		}
		out.Version, err = a.versionView(tx, *nv)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

type acceptedItem struct {
	item     GovAcceptanceItem
	bundleID uuid.UUID
	reason   string
}

// matchAcceptances checks the body's acceptances against the required items:
// an item not required (or with a stale hash) is 409 plan_changed; a
// duplicate is 400; a missing unanalysed item is 409 residuals_not_accepted
// and a missing gap 409 evidence_gaps_not_accepted, each listing every
// missing item.
func matchAcceptances(items []GovAcceptanceItem, in []GovAcceptanceInput) ([]acceptedItem, error) {
	key := func(kind, plan, k string) string { return kind + "\x1f" + plan + "\x1f" + k }
	req := map[string]GovAcceptanceItem{}
	for _, it := range items {
		req[key(it.Kind, it.PlanID.String(), it.ItemKey)] = it
	}
	got := map[string]GovAcceptanceInput{}
	for i, x := range in {
		pid, _ := uuid.Parse(x.PlanID)
		k := key(x.Kind, pid.String(), x.ItemKey)
		if _, dup := got[k]; dup {
			return nil, GovBadParam(fmt.Sprintf("acceptances[%d]", i), "An item is accepted twice.")
		}
		it, ok := req[k]
		if !ok || it.ItemHash != x.ItemHash {
			return nil, govConflict(GovCodePlanChanged, "An accepted item is not (or no longer) part of the plan; review the current plan.",
				map[string]any{"acceptance": x, "current_items": items})
		}
		got[k] = x
	}
	var missingResidual, missingGap []GovAcceptanceItem
	var out []acceptedItem
	for _, it := range items {
		x, ok := got[key(it.Kind, it.PlanID.String(), it.ItemKey)]
		if !ok {
			if it.Kind == GovAcceptUnanalysed {
				missingResidual = append(missingResidual, it)
			} else {
				missingGap = append(missingGap, it)
			}
			continue
		}
		out = append(out, acceptedItem{item: it, reason: x.Reason})
	}
	if len(missingResidual) > 0 {
		return nil, govConflict(GovCodeResidualsNotAccept, "Every unanalysed item must be accepted, one by one, with a reason.",
			map[string]any{"missing": missingResidual, "missing_gaps": missingGap})
	}
	if len(missingGap) > 0 {
		return nil, govConflict(GovCodeGapsNotAccepted, "Every evidence gap must be accepted, one by one, with a reason.",
			map[string]any{"missing": missingGap})
	}
	return out, nil
}

// Reject records a rejection (§7.5): a reason is required, the author
// cannot reject (403 self_approval), and the version must be in review.
// The rejection binds the hashes current at the time.
func (a *GovAuthoring) Reject(ctx context.Context, ws, approver, policyID uuid.UUID, no int, reason string) (*models.IGAGovApproval, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, GovBadParam("reason", "A rejection needs a reason.")
	}
	var out models.IGAGovApproval
	err := a.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := a.loadPolicy(tx, ws, policyID, true); err != nil {
			return err
		}
		v, err := a.loadVersion(tx, ws, policyID, no, true)
		if err != nil {
			return err
		}
		if v.CreatedBy == approver {
			return govErr(http.StatusForbidden, GovCodeSelfApproval, "You authored this version; another approver must decide.", nil)
		}
		if v.Status != "in_review" {
			return govConflict(GovCodeVersionConflict, "Only a version in review can be rejected.", map[string]any{"status": v.Status})
		}
		plans, err := currentPlans(tx, ws, v.ID)
		if err != nil {
			return err
		}
		cur := approvalHashes(*v, plans)
		now := a.now()
		out = models.IGAGovApproval{ID: uuid.New(), WorkspaceID: ws, VersionID: v.ID, Decision: "reject", DecidedBy: approver,
			Channel: "ui", IntentHash: cur.IntentHash, ImpactHashes: pq.StringArray(cur.ImpactHashes),
			PlanHashes: pq.StringArray(cur.PlanHashes), MaterialHashes: pq.StringArray(cur.MaterialHashes), EvidenceRev: v.EvidenceRev,
			Reason: strings.TrimSpace(reason), ExpiresAt: now, DecidedAt: now}
		if err := tx.Create(&out).Error; err != nil {
			return err
		}
		return a.closeVersionTx(tx, approver, *v, "rejected", out.Reason, map[string]any{"approval_id": out.ID})
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// GovApprovalQueueItem is one row of GET /approvals.
type GovApprovalQueueItem struct {
	PolicyID     uuid.UUID  `json:"policy_id"`
	PolicyName   string     `json:"policy_name"`
	VersionID    uuid.UUID  `json:"version_id"`
	VersionNo    int        `json:"version_no"`
	Status       string     `json:"status"`
	AuthorID     uuid.UUID  `json:"author_id"`
	ProposedAt   time.Time  `json:"proposed_at"`
	Targets      int        `json:"targets"`
	ApprovalID   *uuid.UUID `json:"approval_id,omitempty"`
	Decision     *string    `json:"decision,omitempty"`
	DecidedAt    *time.Time `json:"decided_at,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	RevokeReason *string    `json:"revoked_reason,omitempty"`
}

// ListApprovals is GET /approvals?status: pending (default) are versions in
// review the caller did not author (§2.10: the author never decides);
// decided are the caller's own decisions. Cursor-paged by id.
func (a *GovAuthoring) ListApprovals(ctx context.Context, ws, caller uuid.UUID, status, cursor string, limit int) ([]GovApprovalQueueItem, *string, error) {
	if limit <= 0 || limit > MaxGovPage {
		limit = MaxGovPage
	}
	after := ""
	if cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil {
			return nil, nil, govErr(http.StatusBadRequest, "cursor_invalid", "The cursor is not valid.", map[string]any{"parameter": "cursor"})
		}
		if _, err := uuid.Parse(string(raw)); err != nil {
			return nil, nil, govErr(http.StatusBadRequest, "cursor_invalid", "The cursor is not valid.", map[string]any{"parameter": "cursor"})
		}
		after = string(raw)
	}
	db := a.db.WithContext(ctx)
	var rows []GovApprovalQueueItem
	var err error
	switch status {
	case "", "pending":
		q := `SELECT p.id AS policy_id, p.name AS policy_name, v.id AS version_id, v.version_no, v.status, v.created_by AS author_id,
		             v.status_changed_at AS proposed_at,
		             (SELECT count(*) FROM iga_gov_target t WHERE t.workspace_id = v.workspace_id AND t.version_id = v.id) AS targets
		        FROM iga_gov_policy_version v JOIN iga_gov_policy p ON p.workspace_id = v.workspace_id AND p.id = v.policy_id
		       WHERE v.workspace_id = ? AND v.status = 'in_review' AND v.created_by <> ? AND p.lifecycle <> 'archived'`
		args := []any{ws, caller}
		if after != "" {
			q += ` AND v.id > ?`
			args = append(args, after)
		}
		err = db.Raw(q+` ORDER BY v.id LIMIT ?`, append(args, limit+1)...).Scan(&rows).Error
	case "decided":
		q := `SELECT p.id AS policy_id, p.name AS policy_name, v.id AS version_id, v.version_no, v.status, v.created_by AS author_id,
		             v.status_changed_at AS proposed_at,
		             (SELECT count(*) FROM iga_gov_target t WHERE t.workspace_id = v.workspace_id AND t.version_id = v.id) AS targets,
		             a.id AS approval_id, a.decision, a.decided_at, a.revoked_at, a.revoked_reason AS revoke_reason
		        FROM iga_gov_approval a
		        JOIN iga_gov_policy_version v ON v.workspace_id = a.workspace_id AND v.id = a.version_id
		        JOIN iga_gov_policy p ON p.workspace_id = v.workspace_id AND p.id = v.policy_id
		       WHERE a.workspace_id = ? AND a.decided_by = ?`
		args := []any{ws, caller}
		if after != "" {
			q += ` AND a.id > ?`
			args = append(args, after)
		}
		err = db.Raw(q+` ORDER BY a.id LIMIT ?`, append(args, limit+1)...).Scan(&rows).Error
	default:
		return nil, nil, GovBadParam("status", "status must be pending or decided.")
	}
	if err != nil {
		return nil, nil, err
	}
	var next *string
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1].VersionID.String()
		if status == "decided" && rows[len(rows)-1].ApprovalID != nil {
			last = rows[len(rows)-1].ApprovalID.String()
		}
		c := base64.RawURLEncoding.EncodeToString([]byte(last))
		next = &c
	}
	if rows == nil {
		rows = []GovApprovalQueueItem{}
	}
	return rows, next, nil
}

/* ------------------------------------------------------------------------- */
/*                Is an approval still usable? (T3.15 / T3.16)                 */
/* ------------------------------------------------------------------------- */

// GovUsableApproval is an approval a deployment may rely on, with, per plan,
// the unchanged revalidation it relies on when its evidence is not fresh.
type GovUsableApproval struct {
	Approval models.IGAGovApproval
	// Revalidations maps plan id -> the unchanged revalidation relied on
	// (nil when the plan's evidence is fresh): what the deployment records
	// as revalidation_id / revalidation_result.
	Revalidations map[uuid.UUID]*uuid.UUID
}

// UsableApproval is §2.8's rule for deploying planIDs of a version, the hook
// T3.15 / T3.16 call before every deployment starts: the version is
// approved with a live (unrevoked) approval that has not expired (409
// approval_expired); the approver is still an active member who holds
// governance:approve and is not the author (409 approval_invalid with the
// reason; P-10); the intent is unchanged; every plan deployed is a current
// plan whose plan_hash the approval names (409 plan_changed); and each
// plan's evidence is fresh or its latest revalidation is unchanged and
// itself fresh (409 revalidation_required / material_change /
// revalidation_blocked). DECISION A12: "its latest revalidation is
// unchanged" (§2.8) is read as a revalidation against the evidence current
// now -- made after the approval, naming the newest scan, from a bundle
// under 24 hours -- so a scan published after the last revalidation needs
// another one. It writes nothing.
func (a *GovAuthoring) UsableApproval(ctx context.Context, ws, versionID uuid.UUID, planIDs []uuid.UUID) (*GovUsableApproval, error) {
	db := a.db.WithContext(ctx)
	var v models.IGAGovPolicyVersion
	if err := db.Where("workspace_id = ? AND id = ?", ws, versionID).Take(&v).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, GovNotFound()
		}
		return nil, err
	}
	ap, err := liveApproval(db, ws, v.ID)
	if err != nil {
		return nil, err
	}
	if v.Status != "approved" || ap == nil {
		return nil, govConflict(GovCodeApprovalRequired, "This version has no approval in force.", map[string]any{"status": v.Status})
	}
	if !a.now().Before(ap.ExpiresAt) {
		return nil, govConflict(GovCodeApprovalExpired, "The approval has expired; approve again.", map[string]any{"approval_id": ap.ID,
			"expired_at": ap.ExpiresAt})
	}
	if ap.IntentHash != v.IntentHash {
		return nil, govConflict(GovCodePlanChanged, "The intent differs from the approved one.", map[string]any{"approval_id": ap.ID})
	}
	var reasons []string
	if ap.DecidedBy == v.CreatedBy {
		reasons = append(reasons, "approver_is_author")
	}
	if ok, err := activeMember(db, ws, ap.DecidedBy); err != nil {
		return nil, err
	} else if !ok {
		reasons = append(reasons, "approver_not_active_member")
	}
	if ok, err := holdsPermission(db, ws, ap.DecidedBy, "governance", "approve"); err != nil {
		return nil, err
	} else if !ok {
		reasons = append(reasons, "approver_lacks_governance_approve")
	}
	if len(reasons) > 0 {
		return nil, govConflict(GovCodeApprovalInvalid, "The approver can no longer approve this version; approve again.",
			map[string]any{"approval_id": ap.ID, "reasons": reasons})
	}
	out := &GovUsableApproval{Approval: *ap, Revalidations: map[uuid.UUID]*uuid.UUID{}}
	for _, id := range planIDs {
		var p models.IGAGovPlan
		if err := db.Where("workspace_id = ? AND id = ? AND version_id = ?", ws, id, v.ID).Take(&p).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, GovNotFound()
			}
			return nil, err
		}
		if p.SupersededAt != nil || !containsStr(ap.PlanHashes, p.PlanHash) {
			return nil, govConflict(GovCodePlanChanged, "This plan is not the approved plan.", map[string]any{"plan_id": p.ID})
		}
		fresh, why, err := a.EvidenceFreshness(ctx, ws, p.ID)
		if err != nil {
			return nil, err
		}
		if fresh {
			out.Revalidations[p.ID] = nil
			continue
		}
		var rv []models.IGAGovRevalidation
		if err := db.Where("workspace_id = ? AND plan_id = ? AND approved_material_hash = ?", ws, p.ID, p.MaterialHash).
			Order("created_at DESC, id DESC").Limit(1).Find(&rv).Error; err != nil {
			return nil, err
		}
		// The revalidation relied on must itself be fresh: made after the
		// approval, against the newest scan, from a bundle under 24 hours.
		var rvStale []string
		if len(rv) == 1 {
			if rvStale, err = a.staleness(db, ws, p.ControlID, rv[0].EvidenceBundleID, rv[0].ResourcePolicyScanRunID); err != nil {
				return nil, err
			}
		}
		switch {
		case len(rv) == 0 || rv[0].CreatedAt.Before(ap.DecidedAt) || len(rvStale) > 0:
			return nil, govConflict(GovCodeRevalidationNeeded, "The approved evidence is no longer fresh; revalidate first.",
				map[string]any{"plan_id": p.ID, "reasons": why})
		case rv[0].Result == models.GovRevalidationMaterialChange:
			return nil, govConflict(GovCodeMaterialChange, "Revalidation found a material change; a new approval is needed.",
				map[string]any{"plan_id": p.ID, "revalidation_id": rv[0].ID, "changes": rv[0].Changes})
		case rv[0].Result == models.GovRevalidationBlocked:
			return nil, govConflict(GovCodeRevalidationBlocked, "The latest revalidation is blocked.",
				map[string]any{"plan_id": p.ID, "revalidation_id": rv[0].ID, "reason": rv[0].BlockedReason})
		}
		id := rv[0].ID
		out.Revalidations[p.ID] = &id
	}
	return out, nil
}

// isRemoveControlVersion reports whether a version's intent is remove_control.
func isRemoveControlVersion(v models.IGAGovPolicyVersion) bool {
	var k struct {
		Kind string `json:"kind"`
	}
	return json.Unmarshal(v.Intent, &k) == nil && k.Kind == igagov.IntentRemoveControl
}
