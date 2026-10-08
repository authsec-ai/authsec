package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// Compiling plans (SPEC-iga-phase3-policy.md §2.8, §2.11, §8.3; T3.11):
// propose (a fresh bundle and a live read per target, the compiler, apply
// and undo plans persisted one-to-one with their documents first), the
// plans read, the compile_plans job, and revalidation of an approved plan
// (§2.8 "Revalidation, not silent recompilation"), which T3.15 / T3.16 call
// before a deployment whose evidence is no longer fresh.

// compiledTarget is one target compiled in memory.
type compiledTarget struct {
	Target  models.IGAGovTarget
	Control models.IGAGovControl
	Bundle  igagov.Bundle
	// BundleID is set once the bundle is stored.
	BundleID uuid.UUID
	Plans    igagov.TargetPlans
	ReadAt   time.Time
}

// compileBlock is why a target could not be compiled at all (as opposed to
// compiling to an ineligible plan): the evidence is untrusted, the live read
// failed, or the compiler refused its inputs. Bundle is set when the bundle
// was built (a revalidation records a blocked row against it).
type compileBlock struct {
	Err    *GovError
	Bundle *igagov.Bundle
	// Reason is the one-line blocked_reason of a revalidation row.
	Reason string
}

// liveCaller runs a live read: directly for a request, inside the job's
// lease margin (PolicyJobRun.External) for the compile_plans job.
type liveCaller func(ctx context.Context, call func(ctx context.Context) error) error

func directCall(ctx context.Context, call func(ctx context.Context) error) error { return call(ctx) }

// accountServicesOf are the namespaces in the role's activity report.
// DECISION A8: igagov.ProveFirstAttachment's accountServices (D30) are the
// services the role's activity report lists -- every service its identity
// policies grant -- so the unanalysed set names the uncollected forms of
// the services this role can reach, plus resources in other accounts (A34:
// "ecr repository policies, resources in other accounts").
func accountServicesOf(f igagov.BundleFacts) []string {
	out := []string{}
	for _, a := range f.Activity {
		out = append(out, a.Service)
	}
	return sortedUniqueStrings(out)
}

func removedServices(in igagov.RightSizeIntent) []string {
	var out []string
	for _, e := range in.Remove {
		out = append(out, e.Service)
	}
	return sortedUniqueStrings(out)
}

// GovControlRef is the compiler's ControlRef of a control of workspace ws:
// the ONE place the authsec:workspace tag value is chosen
// (GovWorkspaceRef). The compiled ops carry it as the tag the executor
// writes, and every later compile and recovery compares a live policy's tag
// with it, so ownership checks and the tag written are the same value by
// construction (p3-wire, item 2).
func GovControlRef(ws uuid.UUID, c models.IGAGovControl, owned []string) igagov.ControlRef {
	return igagov.ControlRef{ID: c.ID.String(), PolicyID: c.PolicyID.String(), AccountID: c.AccountID, RoleID: c.RoleID,
		WorkspaceRef: GovWorkspaceRef(ws), OwnedPolicyARNs: owned}
}

func (a *GovAuthoring) ownedPolicyARNs(db *gorm.DB, ws, control uuid.UUID) ([]string, error) {
	var out []string
	err := db.Raw(`SELECT native_arn FROM iga_gov_artifact WHERE workspace_id = ? AND control_id = ? AND kind = 'boundary_policy'
	                 AND state IN ('intended','present','drifted') ORDER BY native_arn`, ws, control).Scan(&out).Error
	return out, err
}

// compileOne builds the target's bundle (§2.11) at the latest complete
// evaluation, reads the role live through the discovery role (§3.5) and
// compiles the apply plan and the undo plan derived from its artifact delta
// (§8.3). Nothing is written except by the caller.
func (a *GovAuthoring) compileOne(ctx context.Context, ws uuid.UUID, intent igagov.RightSizeIntent, t models.IGAGovTarget,
	c models.IGAGovControl, call liveCaller) (*compiledTarget, *compileBlock, error) {
	db := a.db.WithContext(ctx)
	b, src, basis, err := a.targets.buildBasis(ctx, ws, c.IdentityAccountID, removedServices(intent))
	if err != nil {
		if ge := bundleBuildError(err, c.RoleID); ge != nil {
			return nil, &compileBlock{Err: ge, Reason: "evidence_unavailable: " + reasonOf(err)}, nil
		}
		return nil, nil, err
	}
	if b.Trust == igagov.TrustUntrusted {
		ue := StoredBundle{Hash: b.Hash, Trust: b.Trust, TrustReasons: b.TrustReasons, Facts: b.Facts}.UntrustedError()
		ue.Detail["role_id"] = c.RoleID
		return nil, &compileBlock{Err: ue, Bundle: &b, Reason: "evidence_untrusted: " + strings.Join(b.TrustReasons, "; ")}, nil
	}
	if a.live == nil {
		return nil, &compileBlock{Bundle: &b, Reason: "discovery_unavailable: live reads are not configured",
			Err: govErr(http.StatusServiceUnavailable, GovCodeDiscoveryUnavail, "AWS cannot be read through the discovery role right now.",
				map[string]any{"reason": "live reads are not configured in this build", "role_id": c.RoleID})}, nil
	}
	var cont []string
	if err := db.Raw(`SELECT continuity FROM iga_identity_accounts WHERE workspace_id = ? AND id = ?`, ws, c.IdentityAccountID).
		Scan(&cont).Error; err != nil {
		return nil, nil, err
	}
	var live igagov.LiveRead
	req := LiveReadRequest{WorkspaceID: ws, ConnectorID: c.ConnectorID, AccountID: c.AccountID, RoleARN: c.RoleARN, RoleID: c.RoleID,
		PolicyARNs: []string{igagov.AuthSecBoundaryARN(arnPartition(c.RoleARN), c.AccountID, c.RoleID)}}
	if err := call(ctx, func(ctx context.Context) error {
		var e error
		live, e = a.live.ReadRole(ctx, req)
		return e
	}); err != nil {
		if errors.Is(err, repositories.ErrPolicyJobLeaseLost) {
			return nil, nil, err
		}
		return nil, &compileBlock{Bundle: &b, Reason: "discovery_unavailable: " + err.Error(),
			Err: govErr(http.StatusServiceUnavailable, GovCodeDiscoveryUnavail, "AWS cannot be read through the discovery role right now.",
				map[string]any{"reason": err.Error(), "role_id": c.RoleID})}, nil
	}
	if live.Role != nil && len(cont) == 1 && cont[0] == igagov.ContinuityRecognition {
		live.Role.Continuity = igagov.ContinuityRecognition
	}
	if live.ReadAt.IsZero() {
		live.ReadAt = a.now()
	}
	owned, err := a.ownedPolicyARNs(db, ws, c.ID)
	if err != nil {
		return nil, nil, err
	}
	in := igagov.TargetInput{
		Control:            GovControlRef(ws, c, owned),
		Intent:             intent,
		Live:               live,
		Evidence:           igagov.EvidenceRef{Bundle: b, EvidenceRev: src.Rev, ScanRunID: src.ConnectorRun},
		AccountServices:    accountServicesOf(b.Facts),
		DependencyContexts: dependencyContexts(basis.Consumers),
	}
	if basis.HasRun {
		in.ScanEvidence, in.EnabledRegions = basis.Run.ResourcePolicy, basis.Run.EnabledRegions
	}
	plans, err := igagov.CompileTarget(in)
	if err != nil {
		var ce *igagov.CompileError
		if !errors.As(err, &ce) {
			return nil, nil, err
		}
		detail := map[string]any{"role_id": c.RoleID, "target_id": t.ID, "reasons": ce.Reasons, "compile_code": ce.Code}
		switch ce.Code {
		case igagov.ErrCodeEvidenceUntrusted:
			return nil, &compileBlock{Bundle: &b, Reason: "evidence_untrusted: " + strings.Join(ce.Reasons, "; "),
				Err: govUnprocessable(GovCodeEvidenceUntrusted, "The evidence for this role is not trustworthy enough to compile a change.", detail)}, nil
		case igagov.ErrCodeLiveIncomplete:
			return nil, &compileBlock{Bundle: &b, Reason: "discovery_unavailable: " + strings.Join(ce.Reasons, "; "),
				Err: govErr(http.StatusServiceUnavailable, GovCodeDiscoveryUnavail, "The live read of this role was incomplete.", detail)}, nil
		case igagov.ErrCodeInvalidIntent:
			return nil, &compileBlock{Bundle: &b, Reason: "invalid_intent: " + strings.Join(ce.Reasons, "; "),
				Err: govUnprocessable(GovCodeInvalidIntent, "The intent is not valid for this role.", detail)}, nil
		}
		return nil, &compileBlock{Bundle: &b, Reason: ce.Code + ": " + strings.Join(ce.Reasons, "; "),
			Err: govUnprocessable(GovCodeTargetIneligible, "This target cannot be compiled.", map[string]any{"targets": []any{detail}})}, nil
	}
	// T3.17: an iac_pr target whose form is not supported in its mapped
	// source is compiled as export, with the reason (§8.11, decided here).
	if plans, err = a.withIaCFallback(ctx, ws, c, in, plans); err != nil {
		if errors.Is(err, repositories.ErrPolicyJobLeaseLost) {
			return nil, nil, err
		}
		return nil, &compileBlock{Bundle: &b, Reason: GovCodeIaCUnavailable + ": " + err.Error(),
			Err: govErr(http.StatusServiceUnavailable, GovCodeIaCUnavailable, "The mapped IaC source could not be read.",
				map[string]any{"reason": err.Error(), "role_id": c.RoleID})}, nil
	}
	return &compiledTarget{Target: t, Control: c, Bundle: b, Plans: plans, ReadAt: live.ReadAt}, nil, nil
}

// versionTargets lists a version's targets with their controls.
func (a *GovAuthoring) versionTargets(db *gorm.DB, ws, versionID uuid.UUID) ([]models.IGAGovTarget, map[uuid.UUID]models.IGAGovControl, error) {
	var ts []models.IGAGovTarget
	if err := db.Where("workspace_id = ? AND version_id = ?", ws, versionID).Order("id").Find(&ts).Error; err != nil {
		return nil, nil, err
	}
	cs := map[uuid.UUID]models.IGAGovControl{}
	for _, t := range ts {
		var c models.IGAGovControl
		if err := db.Where("workspace_id = ? AND id = ?", ws, t.ControlID).Take(&c).Error; err != nil {
			return nil, nil, err
		}
		cs[t.ID] = c
	}
	return ts, cs, nil
}

// GovCodeTargetDeployed refuses to recompile or revalidate (and so to
// supersede) the plans of a target that already carries a deployment of
// its version (fix/p3-appr P0-2).
const GovCodeTargetDeployed = "target_deployed"

// govDeployedStates are the states of a FORWARD deployment (apply, split,
// remove_control) in which its role carries -- or may carry -- the
// deployment's change in AWS; govInFlightStates are those of any deployment
// (an undo included) that is changing the role right now.
var (
	govDeployedStates = []string{models.GovDeployApplying, models.GovDeployOutcomeUnknown, models.GovDeployOutcomeUnresolved,
		models.GovDeployRecovered, models.GovDeployAwaitingMerge, models.GovDeployAwaitingApply, models.GovDeployAppliedUnverified,
		models.GovDeployVerified, models.GovDeployDrifted}
	govInFlightStates = []string{models.GovDeployApplying, models.GovDeployOutcomeUnknown, models.GovDeployOutcomeUnresolved,
		models.GovDeployAwaitingMerge, models.GovDeployAwaitingApply}
)

// deployedTargets is the set of a version's targets that already carry a
// deployment of that version (other than `except`): a forward deployment in
// govDeployedStates, or any deployment in govInFlightStates.
//
// fix/p3-appr (P0-2, SPEC §2.8 "revalidation before stale deployments",
// §8.3, A59): such a target's live state now includes this version's own
// change (the AuthSec boundary it installed, its own document), so a
// recompile against it differs from the approved plan for a reason that is
// not a material change -- the precondition, the ops ([] "already in
// place") and first_attachment all reflect AuthSec's own write. Its approved
// plan is therefore never recompiled, revalidated or superseded: the
// compile_plans job and a re-proposal skip it, and revalidate refuses it
// (409 target_deployed). DECISION: a queued, blocked or failed deployment
// has changed nothing (a queued one is revalidated by the deploy job when
// it starts); a verified undo returned the role to its before-state (the
// forward deployment is then `undone`), so the target is revalidated again
// before a re-apply.
func deployedTargets(db *gorm.DB, ws, versionID, except uuid.UUID) (map[uuid.UUID]bool, error) {
	var ids []uuid.UUID
	if err := db.Raw(`SELECT DISTINCT p.target_id FROM iga_gov_deployment d
		JOIN iga_gov_plan p ON p.workspace_id = d.workspace_id AND p.id = d.plan_id
		WHERE d.workspace_id = ? AND d.version_id = ? AND d.id <> ?
		  AND ((d.kind IN ('apply','split','remove_control') AND d.state IN ?) OR d.state IN ?)`,
		ws, versionID, except, govDeployedStates, govInFlightStates).Scan(&ids).Error; err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}

// compileForVersion compiles one target of a stored version in memory, by
// the version's intent kind: right_size_services (compileOne) or
// dedicated_identity (compileIsolationOne, fix/p3-appr P1-10). Other kinds
// (remove_control) are not recompiled here.
func (a *GovAuthoring) compileForVersion(ctx context.Context, ws uuid.UUID, v models.IGAGovPolicyVersion, t models.IGAGovTarget,
	c models.IGAGovControl, call liveCaller) (*compiledTarget, *compileBlock, error) {
	pi, err := igagov.ParseIntent(v.Intent)
	if err != nil {
		return nil, nil, fmt.Errorf("version %s intent: %w", v.ID, err)
	}
	if pi.Kind == igagov.IntentDedicatedIdentity && pi.DedicatedIdentity != nil {
		return a.compileIsolationOne(ctx, ws, *pi.DedicatedIdentity, t, c, call)
	}
	intent, err := storedRightSize(v)
	if err != nil {
		return nil, nil, err
	}
	return a.compileOne(ctx, ws, intent, t, c, call)
}

func storedRightSize(v models.IGAGovPolicyVersion) (igagov.RightSizeIntent, error) {
	in, err := igagov.ParseIntent(v.Intent)
	if err != nil {
		return igagov.RightSizeIntent{}, fmt.Errorf("version %s intent: %w", v.ID, err)
	}
	if in.Kind != igagov.IntentRightSizeServices {
		return igagov.RightSizeIntent{}, govUnprocessable(GovCodeInvalidIntent, "Only right_size_services versions are compiled here.",
			map[string]any{"kind": in.Kind})
	}
	return *in.RightSize, nil
}

// planRow renders a compiled plan as an iga_gov_plan row.
func planRow(ws, versionID uuid.UUID, t models.IGAGovTarget, bundleID uuid.UUID, p igagov.Plan) (models.IGAGovPlan, error) {
	marshal := func(v any) (json.RawMessage, error) {
		b, err := json.Marshal(v)
		return json.RawMessage(b), err
	}
	impact, err := marshal(p.Impact)
	if err != nil {
		return models.IGAGovPlan{}, err
	}
	ops, err := marshal(p.Ops)
	if err != nil {
		return models.IGAGovPlan{}, err
	}
	diff, err := marshal(p.Diff)
	if err != nil {
		return models.IGAGovPlan{}, err
	}
	un, err := marshal(p.Unanalysed)
	if err != nil {
		return models.IGAGovPlan{}, err
	}
	row := models.IGAGovPlan{ID: uuid.New(), WorkspaceID: ws, VersionID: versionID, TargetID: t.ID, ControlID: t.ControlID,
		Kind: p.Kind, Delivery: p.Delivery, Eligibility: p.Eligibility, IneligibleReason: p.IneligibleReason, Basis: p.Basis,
		BasisReadAt: p.BasisReadAt, Precondition: json.RawMessage(p.Precondition), PreconditionHash: p.PreconditionHash,
		BeforeDocumentHash: p.BeforeDocumentHash, DesiredAttachment: p.DesiredAttachment, DesiredBoundaryARN: p.DesiredBoundaryARN,
		DesiredDocumentHash: p.DesiredDocumentHash, ReplacedBoundaryARN: p.ReplacedBoundaryARN, ArtifactDisposition: p.ArtifactDisposition,
		EvidenceBundleID: bundleID, EvidenceRev: p.EvidenceRev, FirstAttachment: p.FirstAttachment, Unanalysed: un,
		Impact: impact, ImpactHash: p.ImpactHash, Operations: ops, Diff: diff, PlanHash: p.PlanHash, MaterialHash: p.MaterialHash}
	if p.ResourcePolicyScanRunID != nil {
		id, err := uuid.Parse(*p.ResourcePolicyScanRunID)
		if err != nil {
			return models.IGAGovPlan{}, fmt.Errorf("plan scan run %q: %w", *p.ResourcePolicyScanRunID, err)
		}
		row.ResourcePolicyScanRunID = &id
	}
	return row, nil
}

// persistTargetTx stores one compiled target: every document the plans read
// or will write (iga_gov_document, insert-once) BEFORE the plans that
// reference them, then supersedes the target's current plans and inserts the
// apply plan and its undo plan (one-to-one; an ineligible apply has none).
func (a *GovAuthoring) persistTargetTx(tx *gorm.DB, ws, versionID uuid.UUID, ct *compiledTarget) (apply, undo *models.IGAGovPlan, err error) {
	docs := map[string]string{}
	for _, p := range []*igagov.Plan{&ct.Plans.Apply, ct.Plans.Undo} {
		if p == nil {
			continue
		}
		if err := p.CheckStorable(); err != nil {
			return nil, nil, err
		}
		for _, d := range p.Documents {
			docs[d.Hash] = d.Canonical
		}
	}
	hashes := make([]string, 0, len(docs))
	for h := range docs {
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)
	for _, h := range hashes {
		if err := tx.Exec(`INSERT INTO iga_gov_document (workspace_id, document_hash, canonical, document)
		                    VALUES (?, ?, ?, ?::jsonb) ON CONFLICT (workspace_id, document_hash) DO NOTHING`,
			ws, h, docs[h], docs[h]).Error; err != nil {
			return nil, nil, err
		}
	}
	if err := tx.Exec(`UPDATE iga_gov_plan SET superseded_at = ? WHERE workspace_id = ? AND target_id = ? AND superseded_at IS NULL`,
		a.now(), ws, ct.Target.ID).Error; err != nil {
		return nil, nil, err
	}
	ar, err := planRow(ws, versionID, ct.Target, ct.BundleID, ct.Plans.Apply)
	if err != nil {
		return nil, nil, err
	}
	ar.CreatedAt = a.now()
	if err := tx.Create(&ar).Error; err != nil {
		return nil, nil, err
	}
	apply = &ar
	if ct.Plans.Undo != nil {
		ur, err := planRow(ws, versionID, ct.Target, ct.BundleID, *ct.Plans.Undo)
		if err != nil {
			return nil, nil, err
		}
		ur.CreatedAt = a.now()
		if err := tx.Create(&ur).Error; err != nil {
			return nil, nil, err
		}
		undo = &ur
	}
	return apply, undo, nil
}

// storeCompiled persists each compiled target's bundle (insert-once, its own
// transaction; an identical bundle is reused).
func (a *GovAuthoring) storeCompiled(ctx context.Context, ws uuid.UUID, cts []*compiledTarget, actorKind, actorID string) error {
	for _, ct := range cts {
		sb, err := a.targets.storeBundle(ctx, ws, ct.Control.IdentityAccountID, ct.Bundle, actorKind, actorID)
		if err != nil {
			return err
		}
		ct.BundleID = sb.ID
	}
	return nil
}

// currentApplyImpacts maps target -> current apply plan (impact hash and
// impact), for change detection on a recompile.
func currentApplyPlans(db *gorm.DB, ws, versionID uuid.UUID) (map[uuid.UUID]models.IGAGovPlan, error) {
	var ps []models.IGAGovPlan
	if err := db.Where("workspace_id = ? AND version_id = ? AND kind = 'apply' AND superseded_at IS NULL", ws, versionID).
		Find(&ps).Error; err != nil {
		return nil, err
	}
	out := map[uuid.UUID]models.IGAGovPlan{}
	for _, p := range ps {
		out[p.TargetID] = p
	}
	return out, nil
}

func summary(p models.IGAGovPlan, c models.IGAGovControl) GovPlanSummary {
	var im igagov.Impact
	_ = json.Unmarshal(p.Impact, &im)
	return GovPlanSummary{PlanID: p.ID, TargetID: p.TargetID, ControlID: p.ControlID, IdentityAccountID: c.IdentityAccountID,
		RoleID: c.RoleID, Kind: p.Kind, Eligibility: p.Eligibility, ImpactHash: p.ImpactHash, Impact: im, PlanHash: p.PlanHash,
		MaterialHash: p.MaterialHash}
}

// impactChangesTx calls OnImpactChanged for every target whose apply
// impact_hash differs from before.
func (a *GovAuthoring) impactChangesTx(tx *gorm.DB, ws, policyID, versionID uuid.UUID, before map[uuid.UUID]models.IGAGovPlan,
	after map[uuid.UUID]*models.IGAGovPlan, source string) error {
	h := a.hooks().OnImpactChanged
	for tid, np := range after {
		old, ok := before[tid]
		if !ok || np == nil || old.ImpactHash == np.ImpactHash {
			continue
		}
		var oi, ni igagov.Impact
		_ = json.Unmarshal(old.Impact, &oi)
		_ = json.Unmarshal(np.Impact, &ni)
		if err := a.event(tx, ws, "impact_changed", models.GovActorSystem, "", &policyID, &versionID, map[string]any{
			"target_id": tid, "old_impact_hash": old.ImpactHash, "new_impact_hash": np.ImpactHash, "source": source}); err != nil {
			return err
		}
		if h != nil {
			if err := h(tx, GovImpactChange{WorkspaceID: ws, PolicyID: policyID, VersionID: versionID, TargetID: tid,
				OldImpactHash: old.ImpactHash, NewImpactHash: np.ImpactHash, OldImpact: oi, NewImpact: ni, Source: source}); err != nil {
				return err
			}
		}
	}
	return nil
}

/* ------------------------------------------------------------------------- */
/*                                  Propose                                   */
/* ------------------------------------------------------------------------- */

// ProposeResult is POST /policies/:id/versions/:no/propose's response.
type ProposeResult struct {
	Version GovVersionView `json:"version"`
	Plans   *GovPlansView  `json:"plans"`
}

// Propose compiles a draft (or re-compiles an in-review) version from live
// reads and fresh bundles and moves it to in_review (§7.3). Any target that
// cannot be compiled answers its error (422 evidence_untrusted, 503
// discovery_unavailable), and any ineligible apply plan answers 422
// target_ineligible listing every target's reasons; in both cases nothing
// is written (DECISION A9: the route is all-or-nothing; the compile_plans
// job, by contrast, stores ineligible plans so the reason stays visible).
func (a *GovAuthoring) Propose(ctx context.Context, ws, actor, policyID uuid.UUID, no int) (*ProposeResult, error) {
	db := a.db.WithContext(ctx)
	pol, err := a.loadPolicy(db, ws, policyID, false)
	if err != nil {
		return nil, err
	}
	if pol.Lifecycle == "archived" {
		return nil, govConflict(GovCodePolicyArchived, "The policy is archived and read-only.", nil)
	}
	v, err := a.loadVersion(db, ws, policyID, no, false)
	if err != nil {
		return nil, err
	}
	if v.Status != "draft" && v.Status != "in_review" {
		return nil, govConflict(GovCodeVersionConflict, "Only a draft or in-review version can be proposed; edit creates a new version.",
			map[string]any{"status": v.Status})
	}
	// T3.17: a dedicated_identity version compiles split / split_revert.
	if pi, perr := igagov.ParseIntent(v.Intent); perr == nil && pi.Kind == igagov.IntentDedicatedIdentity {
		return a.proposeIsolation(ctx, ws, actor, policyID, no, v, *pi.DedicatedIdentity)
	}
	intent, err := storedRightSize(*v)
	if err != nil {
		return nil, err
	}
	ts, cs, err := a.versionTargets(db, ws, v.ID)
	if err != nil {
		return nil, err
	}
	// fix/p3-appr (P0-2): a re-proposal (in review again after a material
	// change) keeps the plans of targets that already carry a deployment.
	deployed, err := deployedTargets(db, ws, v.ID, uuid.Nil)
	if err != nil {
		return nil, err
	}
	var cts []*compiledTarget
	var ineligible []map[string]any
	for _, t := range ts {
		if deployed[t.ID] {
			continue
		}
		ct, blk, err := a.compileOne(ctx, ws, intent, t, cs[t.ID], directCall)
		if err != nil {
			return nil, err
		}
		if blk != nil {
			return nil, blk.Err
		}
		if !ct.Plans.Apply.Eligible() {
			ineligible = append(ineligible, map[string]any{"target_id": t.ID, "role_id": ct.Control.RoleID,
				"reasons": ct.Plans.Apply.Refusals, "ineligible_reason": ct.Plans.Apply.IneligibleReason})
		}
		cts = append(cts, ct)
	}
	if len(ineligible) > 0 {
		return nil, govUnprocessable(GovCodeTargetIneligible, "Some targets are not eligible for this change.", map[string]any{"targets": ineligible})
	}
	k, aid := userActor(actor)
	if err := a.storeCompiled(ctx, ws, cts, k, aid); err != nil {
		return nil, err
	}
	var out ProposeResult
	err = db.Transaction(func(tx *gorm.DB) error {
		cur, err := a.loadVersion(tx, ws, policyID, no, true)
		if err != nil {
			return err
		}
		if cur.Status != v.Status {
			return govConflict(GovCodeVersionConflict, "The version changed while it was being compiled.", map[string]any{"status": cur.Status})
		}
		before, err := currentApplyPlans(tx, ws, v.ID)
		if err != nil {
			return err
		}
		after := map[uuid.UUID]*models.IGAGovPlan{}
		var applies []GovPlanSummary
		var planIDs []uuid.UUID
		for _, ct := range cts {
			ap, up, err := a.persistTargetTx(tx, ws, v.ID, ct)
			if err != nil {
				return err
			}
			after[ct.Target.ID] = ap
			applies = append(applies, summary(*ap, ct.Control))
			planIDs = append(planIDs, ap.ID)
			if up != nil {
				planIDs = append(planIDs, up.ID)
			}
		}
		for _, t := range ts {
			if p, ok := before[t.ID]; ok && deployed[t.ID] {
				applies = append(applies, summary(p, cs[t.ID])) // kept as approved
			}
		}
		reproposed := cur.Status == "in_review"
		if !reproposed {
			if err := tx.Model(&models.IGAGovPolicyVersion{}).Where("workspace_id = ? AND id = ?", ws, v.ID).
				Updates(map[string]any{"status": "in_review", "status_changed_at": a.now()}).Error; err != nil {
				return err
			}
		} else if err := a.impactChangesTx(tx, ws, policyID, v.ID, before, after, "recompile"); err != nil {
			return err
		}
		if err := a.event(tx, ws, "version_proposed", k, aid, &policyID, &v.ID, map[string]any{"version_no": no,
			"plan_ids": planIDs, "reproposed": reproposed}); err != nil {
			return err
		}
		if h := a.hooks().OnProposed; h != nil {
			if err := h(tx, GovProposedVersion{WorkspaceID: ws, PolicyID: policyID, VersionID: v.ID, VersionNo: no, ActorID: actor,
				Intent: intent, ApplyPlans: applies, Reproposed: reproposed}); err != nil {
				return err
			}
		}
		nv, err := a.loadVersion(tx, ws, policyID, no, false)
		if err != nil {
			return err
		}
		vv, err := a.versionView(tx, *nv)
		if err != nil {
			return err
		}
		out.Version = vv
		pv, err := a.plansView(tx, ws, *nv)
		out.Plans = pv
		return err
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

/* ------------------------------------------------------------------------- */
/*                                 Plans read                                 */
/* ------------------------------------------------------------------------- */

// GovAcceptanceItem is one uncertainty the approver must accept item by
// item (§2.8, §3.4): an unanalysed form of an apply plan, or a gap of the
// plan's evidence bundle. Approval echoes kind, plan_id, item_key and
// item_hash with a reason.
type GovAcceptanceItem struct {
	Kind     string    `json:"kind"`
	PlanID   uuid.UUID `json:"plan_id"`
	RoleID   string    `json:"role_id"`
	ItemKey  string    `json:"item_key"`
	ItemHash string    `json:"item_hash"`
	Detail   any       `json:"detail"`
}

// GovPlanView is one stored plan with its documents.
type GovPlanView struct {
	models.IGAGovPlan
	RoleID          string          `json:"role_id"`
	RoleARN         string          `json:"role_arn"`
	BeforeDocument  json.RawMessage `json:"before_document"`
	DesiredDocument json.RawMessage `json:"desired_document"`
	Gaps            []igagov.Gap    `json:"gaps"`
}

// GovApprovalHashes are the values an approval must echo (§7.5).
type GovApprovalHashes struct {
	IntentHash     string   `json:"intent_hash"`
	ImpactHashes   []string `json:"impact_hashes"`
	PlanHashes     []string `json:"plan_hashes"`
	MaterialHashes []string `json:"material_hashes"`
}

// GovPlansView is GET /policies/:id/versions/:no/plans.
type GovPlansView struct {
	VersionNo       int                 `json:"version_no"`
	Status          string              `json:"status"`
	Plans           []GovPlanView       `json:"plans"`
	AcceptanceItems []GovAcceptanceItem `json:"acceptance_items"`
	Hashes          GovApprovalHashes   `json:"hashes"`
}

// Plans is GET /policies/:id/versions/:no/plans: every target's current
// apply and undo plan.
func (a *GovAuthoring) Plans(ctx context.Context, ws, policyID uuid.UUID, no int) (*GovPlansView, error) {
	db := a.db.WithContext(ctx)
	v, err := a.loadVersion(db, ws, policyID, no, false)
	if err != nil {
		return nil, err
	}
	return a.plansView(db, ws, *v)
}

func (a *GovAuthoring) plansView(db *gorm.DB, ws uuid.UUID, v models.IGAGovPolicyVersion) (*GovPlansView, error) {
	plans, err := currentPlans(db, ws, v.ID)
	if err != nil {
		return nil, err
	}
	out := &GovPlansView{VersionNo: v.VersionNo, Status: v.Status, Plans: []GovPlanView{}, AcceptanceItems: []GovAcceptanceItem{}}
	items, err := requiredAcceptances(db, ws, plans)
	if err != nil {
		return nil, err
	}
	out.AcceptanceItems = items
	out.Hashes = approvalHashes(v, plans)
	for _, p := range plans {
		pv := GovPlanView{IGAGovPlan: p.IGAGovPlan, RoleID: p.RoleID, RoleARN: p.RoleARN, Gaps: []igagov.Gap{}}
		for _, x := range []struct {
			h   *string
			dst *json.RawMessage
		}{{p.BeforeDocumentHash, &pv.BeforeDocument}, {p.DesiredDocumentHash, &pv.DesiredDocument}} {
			if x.h == nil {
				continue
			}
			var docs []string
			if err := db.Raw(`SELECT canonical FROM iga_gov_document WHERE workspace_id = ? AND document_hash = ?`, ws, *x.h).
				Scan(&docs).Error; err != nil {
				return nil, err
			}
			if len(docs) == 1 {
				*x.dst = json.RawMessage(docs[0])
			}
		}
		facts, err := bundleFacts(db, ws, p.EvidenceBundleID)
		if err != nil {
			return nil, err
		}
		pv.Gaps = append(pv.Gaps, facts.Gaps...)
		out.Plans = append(out.Plans, pv)
	}
	return out, nil
}

type planWithRole struct {
	models.IGAGovPlan
	RoleID  string
	RoleARN string
}

// currentPlans are a version's current (not superseded) plans with their
// role, apply before undo per target.
func currentPlans(db *gorm.DB, ws, versionID uuid.UUID) ([]planWithRole, error) {
	var ps []models.IGAGovPlan
	if err := db.Where("workspace_id = ? AND version_id = ? AND superseded_at IS NULL", ws, versionID).
		Order("target_id, kind").Find(&ps).Error; err != nil {
		return nil, err
	}
	out := make([]planWithRole, 0, len(ps))
	for _, p := range ps {
		var c models.IGAGovControl
		if err := db.Where("workspace_id = ? AND id = ?", ws, p.ControlID).Take(&c).Error; err != nil {
			return nil, err
		}
		out = append(out, planWithRole{IGAGovPlan: p, RoleID: c.RoleID, RoleARN: c.RoleARN})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].RoleID != out[j].RoleID {
			return out[i].RoleID < out[j].RoleID
		}
		return out[i].Kind < out[j].Kind // apply < undo
	})
	return out, nil
}

// bundleFacts re-reads and re-verifies a stored bundle (ParseBundle).
func bundleFacts(db *gorm.DB, ws, id uuid.UUID) (igagov.BundleFacts, error) {
	var b models.IGAGovEvidenceBundle
	if err := db.Where("workspace_id = ? AND id = ?", ws, id).Take(&b).Error; err != nil {
		return igagov.BundleFacts{}, err
	}
	f, _, _, err := igagov.ParseBundle([]byte(b.Canonical), b.BundleHash)
	return f, err
}

func bundleGapRefs(f igagov.BundleFacts) ([]igagov.GapRef, error) {
	out := []igagov.GapRef{}
	for _, g := range f.Gaps {
		h, err := igagov.GapHash(g)
		if err != nil {
			return nil, err
		}
		out = append(out, igagov.GapRef{Key: g.Key, Hash: h})
	}
	return out, nil
}

// Acceptance kinds (051).
const (
	GovAcceptUnanalysed = "unanalysed_form"
	GovAcceptGap        = "evidence_gap"
)

// requiredAcceptances lists every item an approval must accept: each
// unanalysed item of each current apply plan and each gap of its bundle.
// DECISION A10: the items are bound to the APPLY plan. An undo plan is
// derived from its apply with the same bundle and never has unanalysed
// items of its own, so its gaps are the apply's, accepted once.
func requiredAcceptances(db *gorm.DB, ws uuid.UUID, plans []planWithRole) ([]GovAcceptanceItem, error) {
	out := []GovAcceptanceItem{}
	for _, p := range plans {
		// T3.17: a dedicated-identity version's split plan carries the §11
		// unanalysed items (KMS grants, SCPs/RCPs, standalone tasks, ...),
		// accepted item by item like an apply plan's; its split_revert
		// derives from it with the same bundle.
		if (p.Kind != igagov.PlanApply && p.Kind != igagov.PlanSplit) || p.Eligibility == igagov.EligibilityIneligible {
			continue
		}
		var un []igagov.UnanalysedItem
		if err := json.Unmarshal(p.Unanalysed, &un); err != nil {
			return nil, err
		}
		for _, it := range un {
			h, err := igagov.UnanalysedItemHash(it)
			if err != nil {
				return nil, err
			}
			out = append(out, GovAcceptanceItem{Kind: GovAcceptUnanalysed, PlanID: p.ID, RoleID: p.RoleID, ItemKey: it.Key, ItemHash: h, Detail: it})
		}
		facts, err := bundleFacts(db, ws, p.EvidenceBundleID)
		if err != nil {
			return nil, err
		}
		for _, g := range facts.Gaps {
			h, err := igagov.GapHash(g)
			if err != nil {
				return nil, err
			}
			out = append(out, GovAcceptanceItem{Kind: GovAcceptGap, PlanID: p.ID, RoleID: p.RoleID, ItemKey: g.Key, ItemHash: h, Detail: g})
		}
	}
	return out, nil
}

// approvalHashes are the current values an approval binds (§2.8): the
// intent hash, every target's (apply) impact hash, and the sorted plan and
// material hashes of every apply and undo plan.
func approvalHashes(v models.IGAGovPolicyVersion, plans []planWithRole) GovApprovalHashes {
	h := GovApprovalHashes{IntentHash: v.IntentHash, ImpactHashes: []string{}, PlanHashes: []string{}, MaterialHashes: []string{}}
	for _, p := range plans {
		if p.Kind == igagov.PlanApply || p.Kind == igagov.PlanSplit { // T3.17: split plans are forward plans too
			h.ImpactHashes = append(h.ImpactHashes, p.ImpactHash)
		}
		h.PlanHashes = append(h.PlanHashes, p.PlanHash)
		h.MaterialHashes = append(h.MaterialHashes, p.MaterialHash)
	}
	sort.Strings(h.ImpactHashes)
	sort.Strings(h.PlanHashes)
	sort.Strings(h.MaterialHashes)
	return h
}

/* ------------------------------------------------------------------------- */
/*                             compile_plans job                              */
/* ------------------------------------------------------------------------- */

// EnqueueCompilePlansTx queues an asynchronous recompile of a version (one
// open job per version). The publication hook calls it for every in-review
// and approved version in the evaluation's completing transaction
// (GovEvaluator.writeTx, p3-wire DECISION W4).
func EnqueueCompilePlansTx(tx *gorm.DB, ws, versionID uuid.UUID, rev *int64) (bool, error) {
	return repositories.NewIGAGovJobRepository(tx).EnqueueTx(tx, &models.IGAGovJob{WorkspaceID: ws,
		Kind: repositories.GovJobCompilePlans, SubjectID: &versionID, Rev: rev, DedupeKey: "version:" + versionID.String()})
}

// CompilePlansHandler is the compile_plans job (§8.1, §8.3): an in-review
// version is recompiled against fresh evidence and live reads (new current
// plans, previous ones superseded; an impact change reopens the owner review
// through OnImpactChanged); an approved version is never recompiled -- each
// target's approved apply plan is revalidated instead (§2.8). Any other
// status abandons the job.
func (a *GovAuthoring) CompilePlansHandler(ctx context.Context, run *PolicyJobRun) error {
	if run.Job.SubjectID == nil {
		return PolicyJobAbandon("compile_plans needs a version subject")
	}
	ws := run.Job.WorkspaceID
	db := run.DB().WithContext(ctx)
	var v models.IGAGovPolicyVersion
	if err := db.Where("workspace_id = ? AND id = ?", ws, *run.Job.SubjectID).Take(&v).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return PolicyJobAbandon("version not found")
		}
		return err
	}
	call := func(ctx context.Context, fn func(ctx context.Context) error) error { return run.External(ctx, 0, fn) }
	switch v.Status {
	case "approved":
		// fix/p3-appr (P0-2, §2.8): revalidation is "before stale
		// deployments" -- only the forward plans (apply, split) of targets
		// with no deployment of this version yet. A deployed target's plan
		// is never revalidated or superseded: its role now carries this
		// version's own change.
		var plans []models.IGAGovPlan
		if err := db.Where("workspace_id = ? AND version_id = ? AND kind IN ? AND superseded_at IS NULL", ws, v.ID,
			[]string{igagov.PlanApply, igagov.PlanSplit}).Find(&plans).Error; err != nil {
			return err
		}
		deployed, err := deployedTargets(db, ws, v.ID, uuid.Nil)
		if err != nil {
			return err
		}
		ids := make([]uuid.UUID, 0, len(plans))
		for _, p := range plans {
			if !deployed[p.TargetID] {
				ids = append(ids, p.ID)
			}
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
		for _, id := range ids {
			if _, err := a.revalidate(ctx, ws, id, call, run.InTx); err != nil {
				var ge *GovError
				if errors.As(err, &ge) {
					// The plan stopped being the approved one meanwhile
					// (an earlier target's material change revoked it).
					break
				}
				return err
			}
		}
		return nil
	case "in_review":
		return a.recompile(ctx, ws, v, call, run.InTx)
	}
	return PolicyJobAbandon("version is " + v.Status)
}

type txRunner func(ctx context.Context, fn func(tx *gorm.DB) error) error

func (a *GovAuthoring) plainTx(ctx context.Context, fn func(tx *gorm.DB) error) error {
	return a.db.WithContext(ctx).Transaction(fn)
}

// recompile recompiles an in-review version in the background: blocked
// targets fail the job (retried with backoff); ineligible plans are stored.
func (a *GovAuthoring) recompile(ctx context.Context, ws uuid.UUID, v models.IGAGovPolicyVersion, call liveCaller, inTx txRunner) error {
	intent, err := storedRightSize(v)
	if err != nil {
		return PolicyJobAbandon(err.Error())
	}
	ts, cs, err := a.versionTargets(a.db.WithContext(ctx), ws, v.ID)
	if err != nil {
		return err
	}
	// fix/p3-appr (P0-2): targets that already carry a deployment of this
	// version (in review again after a material change elsewhere) keep
	// their plans.
	deployed, err := deployedTargets(a.db.WithContext(ctx), ws, v.ID, uuid.Nil)
	if err != nil {
		return err
	}
	var cts []*compiledTarget
	for _, t := range ts {
		if deployed[t.ID] {
			continue
		}
		ct, blk, err := a.compileOne(ctx, ws, intent, t, cs[t.ID], call)
		if err != nil {
			return err
		}
		if blk != nil {
			return fmt.Errorf("compile %s: %s", cs[t.ID].RoleID, blk.Reason)
		}
		cts = append(cts, ct)
	}
	if err := a.storeCompiled(ctx, ws, cts, models.GovActorSystem, "compile_plans"); err != nil {
		return err
	}
	return inTx(ctx, func(tx *gorm.DB) error {
		var cur models.IGAGovPolicyVersion
		if err := tx.Where("workspace_id = ? AND id = ?", ws, v.ID).Clauses(lockForUpdate()).Take(&cur).Error; err != nil {
			return err
		}
		if cur.Status != "in_review" {
			return nil // decided meanwhile; nothing to recompile
		}
		before, err := currentApplyPlans(tx, ws, v.ID)
		if err != nil {
			return err
		}
		after := map[uuid.UUID]*models.IGAGovPlan{}
		var ids []uuid.UUID
		for _, ct := range cts {
			ap, up, err := a.persistTargetTx(tx, ws, v.ID, ct)
			if err != nil {
				return err
			}
			after[ct.Target.ID] = ap
			ids = append(ids, ap.ID)
			if up != nil {
				ids = append(ids, up.ID)
			}
		}
		if err := a.impactChangesTx(tx, ws, v.PolicyID, v.ID, before, after, "recompile"); err != nil {
			return err
		}
		return a.event(tx, ws, "plans_recompiled", models.GovActorSystem, "compile_plans", &v.PolicyID, &v.ID,
			map[string]any{"version_no": v.VersionNo, "plan_ids": ids})
	})
}

/* ------------------------------------------------------------------------- */
/*                                Revalidation                                */
/* ------------------------------------------------------------------------- */

// GovChange is one named material change (§2.8 "each reported by name").
type GovChange struct {
	Item   string `json:"item"`
	Before any    `json:"before,omitempty"`
	After  any    `json:"after,omitempty"`
}

// GovRevalidation is a revalidation's outcome.
type GovRevalidation struct {
	Revalidation models.IGAGovRevalidation `json:"revalidation"`
	Changes      []GovChange               `json:"changes"`
	// NewPlanIDs are the recompiled plans stored on material_change (apply,
	// then undo), now the target's current plans.
	NewPlanIDs []uuid.UUID `json:"new_plan_ids"`
}

// Revalidate is §2.8's revalidation of an APPROVED plan (apply or undo),
// the hook T3.15 / T3.16 call when a deployment is about to start and the
// approved evidence is no longer fresh (see EvidenceFreshness): it builds a
// new bundle, recompiles the same intent against it IN MEMORY, and inserts
// one iga_gov_revalidation row:
//
//   - unchanged: the recompiled material_hash equals the approved one; the
//     approved plan, its bundle, the approval and its acceptances are
//     untouched (the deployment records the revalidation it relied on);
//   - material_change: the changes are named; the recompiled plans are
//     stored as the target's new current plans (superseding the approved
//     ones), the approval is revoked and the version returns to in_review
//     for a new approval (with its own acceptances); an impact change calls
//     OnImpactChanged (T3.12 reopens the review for new owners);
//   - blocked: the new evidence is untrusted, the role is now ineligible, or
//     the live read failed; nothing is recompiled or stored but the row.
//
// The plan must be one the version's live approval names (409 plan_changed
// otherwise), and its target must not already carry a deployment of the
// version (409 target_deployed, fix/p3-appr P0-2: the role then includes
// this version's own change, which is never a material change). A
// dedicated-identity version's split / split_revert plans are recompiled
// with CompileSplit (fix/p3-appr P1-10). Without any complete evaluation there is no bundle to record
// against, and an error is returned instead of a row.
func (a *GovAuthoring) Revalidate(ctx context.Context, ws, planID uuid.UUID) (*GovRevalidation, error) {
	return a.revalidate(ctx, ws, planID, directCall, a.plainTx)
}

func (a *GovAuthoring) revalidate(ctx context.Context, ws, planID uuid.UUID, call liveCaller, inTx txRunner) (*GovRevalidation, error) {
	db := a.db.WithContext(ctx)
	var p models.IGAGovPlan
	if err := db.Where("workspace_id = ? AND id = ?", ws, planID).Take(&p).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, GovNotFound()
		}
		return nil, err
	}
	var v models.IGAGovPolicyVersion
	if err := db.Where("workspace_id = ? AND id = ?", ws, p.VersionID).Take(&v).Error; err != nil {
		return nil, err
	}
	appr, err := liveApproval(db, ws, v.ID)
	if err != nil {
		return nil, err
	}
	if v.Status != "approved" || appr == nil || !containsStr(appr.PlanHashes, p.PlanHash) || p.SupersededAt != nil {
		return nil, govConflict("plan_changed", "This plan is not the approved plan of its version.",
			map[string]any{"plan_id": p.ID, "version_status": v.Status})
	}
	// fix/p3-appr (P0-2): never revalidate (and so never supersede) the
	// plan of a target that already carries a deployment of this version.
	if dep, err := deployedTargets(db, ws, v.ID, uuid.Nil); err != nil {
		return nil, err
	} else if dep[p.TargetID] {
		return nil, govConflict(GovCodeTargetDeployed, "This target already carries a deployment of this version; its approved plan is not revalidated.",
			map[string]any{"plan_id": p.ID, "target_id": p.TargetID})
	}
	var t models.IGAGovTarget
	if err := db.Where("workspace_id = ? AND id = ?", ws, p.TargetID).Take(&t).Error; err != nil {
		return nil, err
	}
	var c models.IGAGovControl
	if err := db.Where("workspace_id = ? AND id = ?", ws, p.ControlID).Take(&c).Error; err != nil {
		return nil, err
	}
	// fix/p3-appr (P1-10): a dedicated-identity version (split /
	// split_revert) is recompiled in memory like a right-size one.
	ct, blk, err := a.compileForVersion(ctx, ws, v, t, c, call)
	if err != nil {
		return nil, err
	}
	var built igagov.Bundle
	var np *igagov.Plan
	reason := ""
	readAt := a.now()
	switch {
	case blk != nil && blk.Bundle == nil:
		return nil, blk.Err
	case blk != nil:
		built, reason = *blk.Bundle, blk.Reason
	default:
		built, readAt = ct.Bundle, ct.ReadAt
		switch {
		case !ct.Plans.Apply.Eligible():
			reason = "target_ineligible: " + ct.Plans.Apply.IneligibleReason
		case p.Kind == igagov.PlanApply || p.Kind == igagov.PlanSplit:
			np = &ct.Plans.Apply
		case (p.Kind == igagov.PlanUndo || p.Kind == igagov.PlanSplitRevert) && ct.Plans.Undo != nil:
			np = ct.Plans.Undo
		default:
			reason = "plan_kind_not_recompiled: " + p.Kind
		}
	}
	sb, err := a.targets.storeBundle(ctx, ws, c.IdentityAccountID, built, models.GovActorSystem, "revalidation")
	if err != nil {
		return nil, err
	}
	src := built.Facts.Sources[0]
	rv := models.IGAGovRevalidation{ID: uuid.New(), WorkspaceID: ws, PlanID: p.ID, ApprovedMaterialHash: p.MaterialHash,
		EvidenceBundleID: sb.ID, EvidenceRev: src.Rev, BasisReadAt: readAt, Changes: json.RawMessage("[]"), CreatedAt: a.now()}
	if id, err := uuid.Parse(src.ConnectorRun); err == nil {
		rv.ResourcePolicyScanRunID = &id
	}
	out := &GovRevalidation{Changes: []GovChange{}, NewPlanIDs: []uuid.UUID{}}
	if np != nil {
		mh := np.MaterialHash
		rv.MaterialHash = &mh
		if mh == p.MaterialHash {
			rv.Result = models.GovRevalidationUnchanged
		} else {
			rv.Result = models.GovRevalidationMaterialChange
			oldFacts, err := bundleFacts(db, ws, p.EvidenceBundleID)
			if err != nil {
				return nil, err
			}
			oldGaps, err := bundleGapRefs(oldFacts)
			if err != nil {
				return nil, err
			}
			out.Changes = MaterialChanges(p, oldGaps, *np)
			raw, err := json.Marshal(out.Changes)
			if err != nil {
				return nil, err
			}
			rv.Changes = raw
		}
	} else {
		rv.Result, rv.BlockedReason = models.GovRevalidationBlocked, reason
	}
	err = inTx(ctx, func(tx *gorm.DB) error {
		if rv.Result == models.GovRevalidationMaterialChange {
			// The approved plan must still be current: a concurrent
			// revalidation may have superseded it already.
			var cur models.IGAGovPlan
			if err := tx.Where("workspace_id = ? AND id = ?", ws, p.ID).Clauses(lockForUpdate()).Take(&cur).Error; err != nil {
				return err
			}
			if cur.SupersededAt != nil {
				return govConflict("plan_changed", "The approved plan was superseded meanwhile.", map[string]any{"plan_id": p.ID})
			}
			// fix/p3-appr (P0-2): nor may a deployment of this target have
			// started meanwhile -- its plan is then never superseded.
			if dep, err := deployedTargets(tx, ws, v.ID, uuid.Nil); err != nil {
				return err
			} else if dep[p.TargetID] {
				return govConflict(GovCodeTargetDeployed, "A deployment of this target started meanwhile; its approved plan is kept.",
					map[string]any{"plan_id": p.ID, "target_id": p.TargetID})
			}
		}
		if err := tx.Create(&rv).Error; err != nil {
			return err
		}
		if err := a.event(tx, ws, "plan_revalidated", models.GovActorSystem, "revalidation", &v.PolicyID, &v.ID, map[string]any{
			"plan_id": p.ID, "revalidation_id": rv.ID, "result": rv.Result, "changes": out.Changes,
			"blocked_reason": rv.BlockedReason, "evidence_bundle_id": sb.ID}); err != nil {
			return err
		}
		if rv.Result != models.GovRevalidationMaterialChange {
			return nil
		}
		// Material change: the recompiled plans become the current plans,
		// the approval is revoked and the version needs a new one.
		ct.BundleID = sb.ID
		before, err := currentApplyPlans(tx, ws, v.ID)
		if err != nil {
			return err
		}
		ap, up, err := a.persistTargetTx(tx, ws, v.ID, ct)
		if err != nil {
			return err
		}
		out.NewPlanIDs = append(out.NewPlanIDs, ap.ID)
		if up != nil {
			out.NewPlanIDs = append(out.NewPlanIDs, up.ID)
		}
		var names []string
		for _, ch := range out.Changes {
			names = append(names, ch.Item)
		}
		if err := tx.Exec(`UPDATE iga_gov_approval SET revoked_at = ?, revoked_reason = ? WHERE workspace_id = ? AND id = ? AND revoked_at IS NULL`,
			a.now(), "material_change: "+strings.Join(names, ","), ws, appr.ID).Error; err != nil {
			return err
		}
		if err := tx.Model(&models.IGAGovPolicyVersion{}).Where("workspace_id = ? AND id = ?", ws, v.ID).
			Updates(map[string]any{"status": "in_review", "status_changed_at": a.now()}).Error; err != nil {
			return err
		}
		if err := a.event(tx, ws, "approval_revoked", models.GovActorSystem, "revalidation", &v.PolicyID, &v.ID, map[string]any{
			"approval_id": appr.ID, "reason": "material_change", "changes": names}); err != nil {
			return err
		}
		return a.impactChangesTx(tx, ws, v.PolicyID, v.ID, before, map[uuid.UUID]*models.IGAGovPlan{t.ID: ap}, "revalidation")
	})
	if err != nil {
		return nil, err
	}
	out.Revalidation = rv
	return out, nil
}

// MaterialChanges names what differs between a stored plan (with its
// bundle's gap refs) and a recompiled one, over exactly the material inputs
// of §2.8: control and incarnation (precondition), kind and delivery,
// desired attachment / ARN / document, replaced policy and disposition, ops,
// each part of the impact, first attachment, the unanalysed set and the gap
// set. Evidence identifiers are never a change.
func MaterialChanges(old models.IGAGovPlan, oldGaps []igagov.GapRef, n igagov.Plan) []GovChange {
	var out []GovChange
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	add := func(item string, before, after any) {
		out = append(out, GovChange{Item: item, Before: before, After: after})
	}
	if old.ControlID.String() != n.ControlID {
		add("control", old.ControlID.String(), n.ControlID)
	}
	if old.Kind != n.Kind || old.Delivery != n.Delivery {
		add("kind_delivery", old.Kind+"/"+old.Delivery, n.Kind+"/"+n.Delivery)
	}
	if old.DesiredAttachment != n.DesiredAttachment {
		add("desired_attachment", old.DesiredAttachment, n.DesiredAttachment)
	}
	if str(old.DesiredBoundaryARN) != str(n.DesiredBoundaryARN) {
		add("desired_boundary_arn", str(old.DesiredBoundaryARN), str(n.DesiredBoundaryARN))
	}
	if str(old.DesiredDocumentHash) != str(n.DesiredDocumentHash) {
		add("desired_document", str(old.DesiredDocumentHash), str(n.DesiredDocumentHash))
	}
	if str(old.ReplacedBoundaryARN) != str(n.ReplacedBoundaryARN) {
		add("replaced_policy", str(old.ReplacedBoundaryARN), str(n.ReplacedBoundaryARN))
	}
	if old.ArtifactDisposition != n.ArtifactDisposition {
		add("disposition", old.ArtifactDisposition, n.ArtifactDisposition)
	}
	if old.PreconditionHash != n.PreconditionHash {
		add("precondition", old.PreconditionHash, n.PreconditionHash)
	}
	newOps, _ := json.Marshal(n.Ops)
	if !jsonEqual(old.Operations, newOps) {
		add("ops", json.RawMessage(old.Operations), json.RawMessage(newOps))
	}
	var oi igagov.Impact
	_ = json.Unmarshal(old.Impact, &oi)
	o, ni := oi.Normalized(), n.Impact.Normalized()
	for _, part := range []struct {
		item string
		a, b any
	}{
		{"consumers", o.Consumers, ni.Consumers}, {"owners", o.OwnerUserIDs, ni.OwnerUserIDs},
		{"removed_services", o.Removed, ni.Removed}, {"retained_services", o.Retained, ni.Retained},
		{"statement_revisions", o.StatementRevisions, ni.StatementRevisions}, {"routes", o.Routes, ni.Routes},
		{"restored_services", o.Restored, ni.Restored},
	} {
		if !reflect.DeepEqual(part.a, part.b) {
			add(part.item, part.a, part.b)
		}
	}
	if old.FirstAttachment != n.FirstAttachment {
		add("first_attachment", old.FirstAttachment, n.FirstAttachment)
	}
	var ou []igagov.UnanalysedItem
	_ = json.Unmarshal(old.Unanalysed, &ou)
	if !sameUnanalysed(ou, n.Unanalysed) {
		add("unanalysed", ou, n.Unanalysed)
	}
	if !sameGaps(oldGaps, n.GapRefs) {
		add("gaps", oldGaps, n.GapRefs)
	}
	if len(out) == 0 && old.MaterialHash != n.MaterialHash {
		add("other", old.MaterialHash, n.MaterialHash)
	}
	return out
}

func jsonEqual(a, b []byte) bool {
	ca, err1 := igagov.Canonicalize(a)
	cb, err2 := igagov.Canonicalize(b)
	if err1 != nil || err2 != nil {
		return bytes.Equal(a, b)
	}
	return bytes.Equal(ca, cb)
}

func sameUnanalysed(a, b []igagov.UnanalysedItem) bool {
	key := func(in []igagov.UnanalysedItem) string {
		var ks []string
		for _, x := range in {
			ks = append(ks, x.Key+"|"+x.Form+"|"+x.Reason)
		}
		sort.Strings(ks)
		return strings.Join(ks, "\n")
	}
	return key(a) == key(b)
}

func sameGaps(a, b []igagov.GapRef) bool {
	key := func(in []igagov.GapRef) string {
		var ks []string
		for _, x := range in {
			ks = append(ks, x.Key+"|"+x.Hash)
		}
		sort.Strings(ks)
		return strings.Join(ks, "\n")
	}
	return key(a) == key(b)
}

// EvidenceFreshness reports whether an approved plan's evidence is still
// fresh (§2.8): its bundle was built less than 24 hours ago AND the scan it
// named is still the newest published scan of the role's connector. A plan
// whose evidence is not fresh must be revalidated (Revalidate) before a
// deployment starts; reasons name why.
func (a *GovAuthoring) EvidenceFreshness(ctx context.Context, ws, planID uuid.UUID) (fresh bool, reasons []string, err error) {
	db := a.db.WithContext(ctx)
	var p models.IGAGovPlan
	if err := db.Where("workspace_id = ? AND id = ?", ws, planID).Take(&p).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil, GovNotFound()
		}
		return false, nil, err
	}
	reasons, err = a.staleness(db, ws, p.ControlID, p.EvidenceBundleID, p.ResourcePolicyScanRunID)
	return err == nil && len(reasons) == 0, reasons, err
}

// staleness lists why evidence (a bundle and the scan it named) is no
// longer fresh for a control: the bundle is older than 24 hours, or a newer
// scan of the role's connector was published.
func (a *GovAuthoring) staleness(db *gorm.DB, ws, controlID, bundleID uuid.UUID, scan *uuid.UUID) ([]string, error) {
	facts, err := bundleFacts(db, ws, bundleID)
	if err != nil {
		return nil, err
	}
	reasons := []string{}
	if built, err := time.Parse(time.RFC3339Nano, facts.BuiltAt); err != nil || a.now().Sub(built) > igagov.DefaultTrustRules().MaxSourceAge {
		reasons = append(reasons, "bundle_older_than_24h")
	}
	var c models.IGAGovControl
	if err := db.Where("workspace_id = ? AND id = ?", ws, controlID).Take(&c).Error; err != nil {
		return nil, err
	}
	var newest []uuid.UUID
	if err := db.Raw(`SELECT id FROM cloud_scan_run WHERE workspace_id = ? AND connector_id = ? AND status = 'published'
	                   ORDER BY generation DESC, published_at DESC LIMIT 1`, ws, c.ConnectorID).Scan(&newest).Error; err != nil {
		return nil, err
	}
	if len(newest) == 1 && (scan == nil || *scan != newest[0]) {
		reasons = append(reasons, "newer_scan_published")
	}
	return reasons, nil
}
