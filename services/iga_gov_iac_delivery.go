package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/internal/iacpr"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// IaC and export delivery (SPEC-iga-phase3-policy.md §1.1 J1/J2, §8.4 iac_pr
// and export branches, §8.11; T3.17).
//
//   - Compile time (GovAuthoring.compileOne / ProposeIsolation): a plan
//     whose intent asks for iac_pr is rendered against its mapped source
//     (iacpr.Render); a form AuthSec cannot change mechanically is recompiled
//     as export with the reason in diff.notes ("iac_fallback:<reason>: ...").
//     The decision is never made after a PR is opened.
//   - Deliver (called by the deploy job for delivery iac_pr / export; the
//     deploy job is T3.16's): export -> awaiting_apply with the deadline;
//     iac_pr -> render with the deployment id, open the branch and PR through
//     the GitHub App, record proposed_sha -> awaiting_merge.
//   - Sync (the iac_sync job, every 10 min per open change): head moved after
//     AuthSec opened it -> changed_after_review; first approving review ->
//     reviewed_sha; merged -> merged_sha / merged_at, awaiting_apply with
//     apply_deadline_at = merged_at + iac_apply_hours; check runs and
//     deployments of merged_sha -> apply_run_ref; closed unmerged -> failed.
//   - ObserveApply (iac_sync for J2 after merge and for J1; T3.16's verify
//     may call it too): the single classifier (igagov.Classify) on a
//     discovery-role read. before / intermediate -> stays awaiting_apply
//     ("2 of 3 changes visible"), overdue after the deadline, never failed;
//     after, including the disposition and, for isolation, every migration
//     row moved -> applied_unverified; conflict or a recreated role ->
//     failed: unexpected_state with the diff.
//
// DECISION (T3.17, scheduling of J1): §8.1's iac_sync runs "per open IaC
// change"; an export deployment has no iac_gov_iac_change row, so the
// scheduler also runs iac_sync for every awaiting_apply deployment without
// an open change, subject = the deployment, dedupe iac:<deployment id>.

// GovIaC event names (deployment lifecycle).
const (
	GovEventIaCPROpened       = "iac.pr_opened"
	GovEventIaCChangedReview  = "iac.changed_after_review"
	GovEventIaCReviewed       = "iac.reviewed"
	GovEventIaCMerged         = "iac.merged"
	GovEventIaCClosed         = "iac.closed_unmerged"
	GovEventIaCBlocked        = "iac.blocked"
	GovEventIaCApplyRun       = "iac.apply_run"
	GovEventIaCApplyPending   = "iac.apply_pending"
	GovEventIaCAppliedOutside = "iac.applied_outside_authsec"
	GovEventIaCUnexpected     = "iac.unexpected_state"
	GovEventExportReady       = "export.awaiting_apply"
	GovEventIaCPRStep         = "iac.pr_step"
	GovEventIaCPRUpdated      = "iac.pr_updated"
	GovEventIaCPRSuperseded   = "iac.pr_superseded"
	GovEventIaCOpenFailed     = "iac.pr_open_failed"
)

// Notes and reasons.
const (
	IaCFallbackNotePrefix  = "iac_fallback:"
	IaCReasonSourceMissing = "iac_source_missing"
	IaCReasonUnavailable   = "iac_unavailable"
	IaCReasonUnexpected    = "unexpected_state"
	IaCReasonClosed        = "pr_closed_unmerged"
	IaCReasonFormChanged   = "iac_form_changed"
	IaCReasonAppliedOut    = "applied_outside_authsec"
)

/* ------------------------- process-wide GitHub adapter --------------------- */

var (
	govIaCMu     sync.RWMutex
	govIaCGitHub iacpr.GitHub
)

// SetGovIaCGitHub installs the process-wide PR adapter (nil uninstalls).
func SetGovIaCGitHub(g iacpr.GitHub) {
	govIaCMu.Lock()
	govIaCGitHub = g
	govIaCMu.Unlock()
}

// DefaultGovIaCGitHub is the process-wide PR adapter, or nil.
func DefaultGovIaCGitHub() iacpr.GitHub {
	govIaCMu.RLock()
	defer govIaCMu.RUnlock()
	return govIaCGitHub
}

/* --------------------------------- service -------------------------------- */

// GovIaCDelivery delivers iac_pr and export deployments.
type GovIaCDelivery struct {
	db        *gorm.DB
	github    iacpr.GitHub
	live      LiveReader
	migration GovMigrationClients
	states    GovDeploymentStates
	now       func() time.Time
}

// NewGovIaCDelivery builds the service. github and live may be nil (the
// process-wide ones are read at call time).
func NewGovIaCDelivery(db *gorm.DB, github iacpr.GitHub, live LiveReader) *GovIaCDelivery {
	return &GovIaCDelivery{db: db, github: github, live: live, states: DefaultGovDeploymentStates{}, now: time.Now}
}

// WithStates installs T3.16's transition implementation.
func (d *GovIaCDelivery) WithStates(s GovDeploymentStates) *GovIaCDelivery { d.states = s; return d }

// WithClock sets the clock (tests).
func (d *GovIaCDelivery) WithClock(now func() time.Time) *GovIaCDelivery { d.now = now; return d }

// WithMigrationClients sets how migration evidence is read.
func (d *GovIaCDelivery) WithMigrationClients(m GovMigrationClients) *GovIaCDelivery {
	d.migration = m
	return d
}

func (d *GovIaCDelivery) gh() iacpr.GitHub {
	if d.github != nil {
		return d.github
	}
	return DefaultGovIaCGitHub()
}

func (d *GovIaCDelivery) reader() LiveReader {
	if d.live != nil {
		return d.live
	}
	return DefaultGovLiveReader()
}

func (d *GovIaCDelivery) migrationClients() GovMigrationClients {
	if d.migration != nil {
		return d.migration
	}
	return DefaultGovMigrationClients()
}

/* ------------------------------ loading ----------------------------------- */

type iacDep struct {
	dep     models.IGAGovDeployment
	planRow models.IGAGovPlan
	plan    igagov.Plan
	control models.IGAGovControl
	docs    map[string]string
}

func roleTarget(c models.IGAGovControl) iacpr.RoleTarget {
	name := c.RoleARN[strings.LastIndex(c.RoleARN, "/")+1:]
	return iacpr.RoleTarget{Name: name, ARN: c.RoleARN, RoleID: c.RoleID, AccountID: c.AccountID, Partition: arnPartition(c.RoleARN)}
}

// planDocuments loads every archived document a plan's facts name.
func planDocuments(db *gorm.DB, ws uuid.UUID, p igagov.Plan) (map[string]string, error) {
	set := map[string]bool{}
	for _, f := range p.Facts {
		if f.Kind == igagov.FactPolicyDocument {
			for _, v := range []string{f.Before, f.After} {
				if strings.HasPrefix(v, "sha256:") {
					set[v] = true
				}
			}
		}
	}
	for _, h := range []*string{p.BeforeDocumentHash, p.DesiredDocumentHash} {
		if h != nil {
			set[*h] = true
		}
	}
	for _, op := range p.Ops {
		if strings.HasPrefix(op.DocumentHash, "sha256:") {
			set[op.DocumentHash] = true
		}
		if strings.HasPrefix(op.TrustPolicyHash, "sha256:") {
			set[op.TrustPolicyHash] = true
		}
	}
	out := map[string]string{}
	for _, d := range p.Documents {
		out[d.Hash] = d.Canonical
	}
	var hs []string
	for h := range set {
		if _, ok := out[h]; !ok {
			hs = append(hs, h)
		}
	}
	if len(hs) == 0 {
		return out, nil
	}
	var rows []models.IGAGovDocument
	if err := db.Where("workspace_id = ? AND document_hash IN ?", ws, hs).Find(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.DocumentHash] = r.Canonical
	}
	return out, nil
}

func (d *GovIaCDelivery) load(db *gorm.DB, ws, depID uuid.UUID) (*iacDep, error) {
	x := &iacDep{}
	if err := db.Where("workspace_id = ? AND id = ?", ws, depID).Take(&x.dep).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, GovNotFound()
		}
		return nil, err
	}
	if err := db.Where("workspace_id = ? AND id = ?", ws, x.dep.PlanID).Take(&x.planRow).Error; err != nil {
		return nil, err
	}
	p, err := PlanFromRow(x.planRow)
	if err != nil {
		return nil, err
	}
	x.plan = p
	if err := db.Where("workspace_id = ? AND id = ?", ws, x.dep.ControlID).Take(&x.control).Error; err != nil {
		return nil, err
	}
	if x.docs, err = planDocuments(db, ws, p); err != nil {
		return nil, err
	}
	return x, nil
}

func (d *GovIaCDelivery) applyHours(db *gorm.DB, ws uuid.UUID) time.Duration {
	s := models.DefaultIGAGovSettings(ws)
	var rows []models.IGAGovSettings
	if db.Where("workspace_id = ?", ws).Find(&rows).Error == nil && len(rows) == 1 {
		s = rows[0]
	}
	h := s.IaCApplyHours
	if h <= 0 {
		h = 24
	}
	return time.Duration(h) * time.Hour
}

/* --------------------------- form decision -------------------------------- */

// GovIaCForm is the outcome of rendering a plan against the mapped sources.
type GovIaCForm struct {
	Source    *models.IGAGovIaCSource `json:"source,omitempty"`
	Repo      iacpr.RepoRef           `json:"-"`
	CommitSHA string                  `json:"commit_sha,omitempty"`
	Change    *iacpr.Change           `json:"change,omitempty"`
	Fallback  *iacpr.Fallback         `json:"fallback,omitempty"`
}

// IaCRepoRef resolves an IaC source's repository through its GitHub
// discovery source's installation, and refuses (409) a channel AuthSec must
// not write through (review P2, IaC source checks):
//
//   - iac_installation_unverified: the discovery source's installation id is
//     not the installation of its VERIFIED integration (iga_integrations:
//     status active, verified_at set, the same installation_id) -- the token
//     minted for the PR is for exactly the installation the workspace
//     verified;
//   - iac_repository_not_selected: the mapped repository is not one of the
//     discovery source's selected repositories.
//
// The host is the verified integration's ProviderHost (GitHub Enterprise
// Server: the PR adapter calls https://<host>/api/v3).
func IaCRepoRef(db *gorm.DB, ws uuid.UUID, src models.IGAGovIaCSource) (iacpr.RepoRef, error) {
	ch, err := LoadIaCGitHubChannel(db, ws, src.DiscoverySourceID)
	if err != nil {
		if errors.Is(err, ErrIaCSourceChannelNotFound) {
			return iacpr.RepoRef{}, govConflict(GovCodeIaCSourceMissing, "The IaC source's GitHub discovery source no longer exists.",
				map[string]any{"source_id": src.ID, "discovery_source_id": src.DiscoverySourceID})
		}
		return iacpr.RepoRef{}, err
	}
	in, err := verifiedIaCIntegration(db, ws, ch)
	if err != nil {
		return iacpr.RepoRef{}, err
	}
	if !ch.RepositorySelected(src.Repository) {
		return iacpr.RepoRef{}, govConflict(GovCodeIaCRepoNotSelected, "The mapped repository is not selected by its GitHub discovery source.",
			map[string]any{"source_id": src.ID, "repository": src.Repository, "discovery_source_id": src.DiscoverySourceID})
	}
	host := in.ProviderHost
	if host == "" {
		host = ch.ProviderHost
	}
	return iacpr.RepoRef{WorkspaceID: ws.String(), IntegrationID: ch.IntegrationID, InstallationID: *in.InstallationID,
		ProviderHost: host, FullName: src.Repository}, nil
}

// verifiedIaCIntegration is the channel's integration when it is verified
// and bound to the same installation the channel names.
func verifiedIaCIntegration(db *gorm.DB, ws uuid.UUID, ch *IaCGitHubChannel) (*models.IGAIntegration, error) {
	in, err := loadIaCIntegration(db, ws, ch.IntegrationID)
	if err != nil {
		return nil, err
	}
	why := ""
	switch {
	case in == nil:
		why = "integration_missing"
	case in.Status != "active" || in.VerifiedAt == nil:
		why = "integration_not_verified"
	case in.InstallationID == nil || *in.InstallationID == "" || *in.InstallationID != ch.InstallationID:
		why = "installation_mismatch"
	}
	if why != "" {
		return nil, govConflict(GovCodeIaCInstallUnverified, "The GitHub installation of this IaC source is not the verified installation of its integration.",
			map[string]any{"reason": why, "integration_id": ch.IntegrationID, "discovery_source_id": ch.SourceID})
	}
	return in, nil
}

// DecideIaCForm renders a plan against every IaC source mapped to the
// control's account (§8.11): exactly one source must locate the role and
// render the change; otherwise the most specific fallback is returned.
func DecideIaCForm(ctx context.Context, db *gorm.DB, gh iacpr.GitHub, ws uuid.UUID, c models.IGAGovControl, p igagov.Plan,
	docs map[string]string, deploymentID string, keepNewRole bool) (*GovIaCForm, error) {
	var srcs []models.IGAGovIaCSource
	if err := db.Where("workspace_id = ? AND connector_id = ?", ws, c.ConnectorID).Order("created_at, id").Find(&srcs).Error; err != nil {
		return nil, err
	}
	// Review P2: a J2 target without a mapped source is a visible 409
	// iac_source_missing (Export stays an explicit choice of the intent),
	// and an unconfigured PR adapter (e.g. a process started with
	// AUTHSEC_DISABLE_POLICY_WORKER and no IaC adapters) is a 503 -- neither
	// silently becomes export.
	if len(srcs) == 0 {
		return nil, govConflict(GovCodeIaCSourceMissing, "No IaC source is mapped for this account; map one under Policy > Setup, or choose Export.",
			map[string]any{"account_id": c.AccountID, "connector_id": c.ConnectorID, "role_id": c.RoleID})
	}
	if gh == nil {
		return nil, govErr(http.StatusServiceUnavailable, GovCodeIaCUnavailable, "Pull requests are not configured in this process.",
			map[string]any{"role_id": c.RoleID})
	}
	var ok []*GovIaCForm
	var fbs []*iacpr.Fallback
	for i := range srcs {
		s := srcs[i]
		repo, err := IaCRepoRef(db, ws, s)
		if err != nil {
			return nil, err
		}
		snap, err := gh.ReadDirectory(ctx, repo, s.BaseBranch, s.Directory)
		if err != nil {
			return nil, fmt.Errorf("read %s/%s: %w", s.Repository, s.Directory, err)
		}
		rm, err := iacpr.ParseRoleMatch(s.RoleMatch)
		if err != nil {
			return nil, err
		}
		ch, err := iacpr.Render(iacpr.Request{Source: iacpr.Source{Format: s.Format, Directory: s.Directory, RoleMatch: rm},
			Files: snap.Files, Role: roleTarget(c), Plan: p, Documents: docs, DeploymentID: deploymentID, KeepNewRole: keepNewRole})
		if fb := iacpr.AsFallback(err); fb != nil {
			fbs = append(fbs, fb)
			continue
		}
		if err != nil {
			return nil, err
		}
		ok = append(ok, &GovIaCForm{Source: &s, Repo: repo, CommitSHA: snap.CommitSHA, Change: ch})
	}
	switch {
	case len(ok) == 1:
		return ok[0], nil
	case len(ok) > 1:
		var where []string
		for _, f := range ok {
			where = append(where, f.Source.Repository+"/"+f.Source.Directory)
		}
		return &GovIaCForm{Fallback: &iacpr.Fallback{Reason: iacpr.ReasonRoleAmbiguous,
			Detail: "the role is declared in more than one mapped source: " + strings.Join(where, ", ")}}, nil
	}
	// The most specific reason: anything beats "not found".
	best := fbs[0]
	for _, f := range fbs {
		if best.Reason == iacpr.ReasonRoleNotFound && f.Reason != iacpr.ReasonRoleNotFound {
			best = f
		}
	}
	return &GovIaCForm{Fallback: best}, nil
}

// iacFallbackNote is the diff note recording a compile-time fallback.
func iacFallbackNote(fb *iacpr.Fallback) string {
	return IaCFallbackNotePrefix + fb.Reason + ": " + fb.Detail
}

// IaCFallbackOf reads a plan's compile-time fallback from its notes.
func IaCFallbackOf(p igagov.Plan) *iacpr.Fallback {
	for _, n := range p.Diff.Notes {
		if strings.HasPrefix(n, IaCFallbackNotePrefix) {
			rest := strings.TrimPrefix(n, IaCFallbackNotePrefix)
			reason, detail, _ := strings.Cut(rest, ": ")
			return &iacpr.Fallback{Reason: reason, Detail: detail}
		}
	}
	return nil
}

// iacTargetFallback is the compile-time decision for a right-size target
// whose intent asks for iac_pr: nil when the apply plan renders against its
// mapped source.
func (a *GovAuthoring) iacTargetFallback(ctx context.Context, ws uuid.UUID, c models.IGAGovControl, p igagov.Plan) (*iacpr.Fallback, error) {
	docs := map[string]string{}
	for _, d := range p.Documents {
		docs[d.Hash] = d.Canonical
	}
	extra, err := planDocuments(a.db.WithContext(ctx), ws, p)
	if err != nil {
		return nil, err
	}
	for k, v := range extra {
		docs[k] = v
	}
	f, err := DecideIaCForm(ctx, a.db.WithContext(ctx), a.iacGitHub(), ws, c, p, docs, "", false)
	if err != nil {
		return nil, err
	}
	return f.Fallback, nil
}

func (a *GovAuthoring) iacGitHub() iacpr.GitHub { return DefaultGovIaCGitHub() }

// withIaCFallback recompiles a target as export when its iac_pr form is not
// supported (§8.11: "decided at compile time (iac_only -> Export)").
func (a *GovAuthoring) withIaCFallback(ctx context.Context, ws uuid.UUID, c models.IGAGovControl, in igagov.TargetInput,
	plans igagov.TargetPlans) (igagov.TargetPlans, error) {
	if in.Intent.Delivery != igagov.DeliveryIaCPR || !plans.Apply.Eligible() {
		return plans, nil
	}
	fb, err := a.iacTargetFallback(ctx, ws, c, plans.Apply)
	if err != nil || fb == nil {
		return plans, err
	}
	in.Intent.Delivery = igagov.DeliveryExport
	out, err := igagov.CompileTarget(in)
	if err != nil {
		return plans, err
	}
	note := iacFallbackNote(fb)
	out.Apply.Diff.Notes = append(out.Apply.Diff.Notes, note)
	if out.Undo != nil {
		out.Undo.Diff.Notes = append(out.Undo.Diff.Notes, note)
	}
	return out, nil
}

/* -------------------------------- deliver --------------------------------- */

// GovIaCOutcome is what one Deliver / Sync / ObserveApply did.
type GovIaCOutcome struct {
	DeploymentID uuid.UUID               `json:"deployment_id"`
	State        string                  `json:"state"`
	Reason       string                  `json:"reason,omitempty"`
	ChangeID     *uuid.UUID              `json:"iac_change_id,omitempty"`
	PR           *iacpr.PullRequest      `json:"pr,omitempty"`
	Form         *GovIaCForm             `json:"form,omitempty"`
	Class        *igagov.Classification  `json:"classification,omitempty"`
	Overdue      bool                    `json:"overdue,omitempty"`
	Migrations   []GovMigrationCheck     `json:"migrations,omitempty"`
	Description  *iacpr.Description      `json:"description,omitempty"`
	ChangeRow    *models.IGAGovIaCChange `json:"iac_change,omitempty"`
}

// Deliver is the deploy step of an iac_pr or export deployment in
// `queued` (§8.4, §8.11). It is idempotent: a deployment already past
// queued is returned as it is; a PR already opened for the branch is reused.
func (d *GovIaCDelivery) Deliver(ctx context.Context, run *PolicyJobRun, ws, depID uuid.UUID) (*GovIaCOutcome, error) {
	db := d.db.WithContext(ctx)
	x, err := d.load(db, ws, depID)
	if err != nil {
		return nil, err
	}
	out := &GovIaCOutcome{DeploymentID: depID, State: x.dep.State}
	if x.dep.Delivery != igagov.DeliveryIaCPR && x.dep.Delivery != igagov.DeliveryExport {
		return nil, fmt.Errorf("deployment %s is delivered %s, not by IaC or export", depID, x.dep.Delivery)
	}
	if x.dep.State != "queued" {
		return out, nil
	}
	if blocked, err := d.precheck(ctx, run, ws, x); err != nil || blocked != nil {
		return blocked, err
	}
	now := d.now().UTC()
	desc := iacpr.Describe(x.plan, roleTarget(x.control), nil)
	out.Description = &desc

	if x.dep.Delivery == igagov.DeliveryExport {
		deadline := now.Add(d.applyHours(db, ws))
		err := run.InTx(ctx, func(tx *gorm.DB) error {
			if err := d.ensureMigrationRows(tx, ws, x); err != nil {
				return err
			}
			if err := d.states.TransitionTx(tx, GovDeploymentTransition{WorkspaceID: ws, DeploymentID: depID, From: []string{"queued"},
				To: "awaiting_apply", Reason: "awaiting_your_apply", ApplyDeadlineAt: &deadline}); err != nil {
				return err
			}
			refs, err := govDeploymentRefs(tx, ws, x.dep)
			if err != nil {
				return err
			}
			return appendGovEvent(tx, ws, GovEventExportReady, models.GovActorSystem, "iac_delivery", refs, map[string]any{
				"plan_id": x.planRow.ID, "plan_hash": x.plan.PlanHash, "apply_deadline_at": deadline, "effect": desc.Effect})
		})
		if err != nil {
			return nil, err
		}
		out.State, out.Reason = "awaiting_apply", "awaiting_your_apply"
		return out, nil
	}

	// iac_pr.
	gh := d.gh()
	if gh == nil {
		return nil, govErr(http.StatusServiceUnavailable, GovCodeIaCUnavailable, "Pull requests are not configured in this build.", nil)
	}
	var existing []models.IGAGovIaCChange
	if err := db.Where("workspace_id = ? AND deployment_id = ?", ws, depID).Find(&existing).Error; err != nil {
		return nil, err
	}
	if len(existing) == 1 && existing[0].State != "opening" {
		out.ChangeRow = &existing[0]
		return out, nil
	}
	keep, err := d.keepNewRole(db, ws, x)
	if err != nil {
		return nil, err
	}
	var form *GovIaCForm
	if err := run.External(ctx, 0, func(ctx context.Context) error {
		f, err := DecideIaCForm(ctx, d.db.WithContext(ctx), gh, ws, x.control, x.plan, x.docs, depID.String(), keep)
		form = f
		return err
	}); err != nil {
		// A visible setup refusal (the source was removed, its installation
		// is no longer the verified one, its repository is no longer
		// selected) blocks the deployment with that code; anything else is
		// retried.
		var ge *GovError
		if errors.As(err, &ge) && ge.Status == http.StatusConflict {
			return d.blockQueued(ctx, run, ws, x, ge.Code+": "+ge.Message, map[string]any{"reason": ge.Code, "detail": ge.Detail})
		}
		return nil, err
	}
	out.Form = form
	if form.Fallback != nil {
		// The source no longer renders as approved: never improvise a
		// different change; block for a new plan (DECISION T3.17).
		reason := IaCReasonFormChanged + ": " + form.Fallback.Reason + ": " + form.Fallback.Detail
		o, err := d.blockQueued(ctx, run, ws, x, reason, map[string]any{"reason": form.Fallback.Reason, "detail": form.Fallback.Detail})
		if o != nil {
			o.Form = form
		}
		return o, err
	}
	ch, err := LoadIaCGitHubChannel(db, ws, form.Source.DiscoverySourceID)
	if err != nil {
		return nil, err
	}
	in, err := loadIaCIntegration(db, ws, ch.IntegrationID)
	if err != nil {
		return nil, err
	}
	if in == nil || len(iacpr.MissingPermissions(permMap(in.GrantedPermissions))) > 0 {
		missing := iacpr.MissingPermissions(map[string]string{})
		if in != nil {
			missing = iacpr.MissingPermissions(permMap(in.GrantedPermissions))
		}
		return nil, PolicyJobRetryLater(30*time.Minute, GovCodeIaCPermissionMissing+": "+strings.Join(missing, ", "))
	}
	if form.Change.Empty() {
		deadline := now.Add(d.applyHours(db, ws))
		err := run.InTx(ctx, func(tx *gorm.DB) error {
			if err := d.ensureMigrationRows(tx, ws, x); err != nil {
				return err
			}
			if len(existing) == 1 {
				if err := tx.Model(&models.IGAGovIaCChange{}).Where("workspace_id = ? AND id = ? AND state = 'opening'", ws, existing[0].ID).
					Updates(map[string]any{"state": "failed", "updated_at": now}).Error; err != nil {
					return err
				}
			}
			return d.states.TransitionTx(tx, GovDeploymentTransition{WorkspaceID: ws, DeploymentID: depID, From: []string{"queued"},
				To: "awaiting_apply", Reason: "already_in_source", ApplyDeadlineAt: &deadline})
		})
		if err != nil {
			return nil, err
		}
		out.State, out.Reason = "awaiting_apply", "already_in_source"
		return out, nil
	}

	// Crash safety (review P2): the intent is recorded before every write
	// GitHub keeps, and everything GitHub keeps is findable by the branch
	// name, which is the deployment's. The `opening` row is committed before
	// the first call; the commit is recorded as proposed_sha before the
	// branch is created (StepRef), and an event records the branch before
	// the PR is created (StepPull). A run that dies anywhere in between is
	// resumed by the retried deploy job or by iac_sync's recovery of an
	// `opening` change: OpenPullRequest finds the PR, or the branch at the
	// recorded commit, and creates only what is missing.
	branch := "authsec/" + depID.String()
	var change models.IGAGovIaCChange
	if len(existing) == 1 {
		change = existing[0]
	} else {
		change = models.IGAGovIaCChange{ID: uuid.New(), WorkspaceID: ws, DeploymentID: depID, SourceID: form.Source.ID, Branch: branch,
			State: "opening", UpdatedAt: now}
		if err := run.InTx(ctx, func(tx *gorm.DB) error { return tx.Create(&change).Error }); err != nil {
			return nil, err
		}
	}
	full := iacpr.Describe(x.plan, roleTarget(x.control), form.Change)
	out.Description = &full
	var pr iacpr.PullRequest
	openErr := run.External(ctx, 0, func(ctx context.Context) error {
		var err error
		pr, err = gh.OpenPullRequest(ctx, form.Repo, iacpr.PullRequestInput{BaseBranch: form.Source.BaseBranch, BaseSHA: form.CommitSHA,
			Branch: change.Branch, Title: full.Title, Body: full.Body, CommitMessage: iacCommitMessage(full, x.plan, depID),
			Files: form.Change.Files, ResumeSHA: change.ProposedSHA, OnStep: d.recordStep(run, ws, x, change.ID, "opening")})
		return err
	})
	if errors.Is(openErr, iacpr.ErrBranchConflict) {
		// The deployment's branch holds a commit AuthSec did not make: never
		// reused or overwritten; the deployment is blocked, the change failed.
		o, err := d.blockQueued(ctx, run, ws, x, "iac_branch_conflict: "+openErr.Error(), map[string]any{"reason": "iac_branch_conflict",
			"branch": change.Branch, "iac_change_id": change.ID})
		if err == nil {
			err = run.InTx(ctx, func(tx *gorm.DB) error {
				return tx.Model(&models.IGAGovIaCChange{}).Where("workspace_id = ? AND id = ? AND state = 'opening'", ws, change.ID).
					Updates(map[string]any{"state": "failed", "updated_at": d.now().UTC()}).Error
			})
		}
		return o, err
	}
	if openErr != nil {
		return nil, openErr
	}
	out.PR = &pr
	err = run.InTx(ctx, func(tx *gorm.DB) error {
		n := pr.Number
		if err := tx.Model(&models.IGAGovIaCChange{}).Where("workspace_id = ? AND id = ? AND state = 'opening'", ws, change.ID).
			Updates(map[string]any{"state": "open", "pr_number": &n, "pr_url": pr.URL, "proposed_sha": pr.HeadSHA, "updated_at": now}).Error; err != nil {
			return err
		}
		if err := d.ensureMigrationRows(tx, ws, x); err != nil {
			return err
		}
		if err := d.states.TransitionTx(tx, GovDeploymentTransition{WorkspaceID: ws, DeploymentID: depID, From: []string{"queued"},
			To: "awaiting_merge", Reason: "pr_open"}); err != nil {
			return err
		}
		refs, err := govDeploymentRefs(tx, ws, x.dep)
		if err != nil {
			return err
		}
		var files []string
		for _, f := range form.Change.Files {
			files = append(files, f.Path)
		}
		return appendGovEvent(tx, ws, GovEventIaCPROpened, models.GovActorSystem, "iac_delivery", refs, map[string]any{
			"iac_change_id": change.ID, "repository": form.Source.Repository, "pr_number": pr.Number, "pr_url": pr.URL,
			"proposed_sha": pr.HeadSHA, "base_sha": form.CommitSHA, "files": files, "location": form.Change.Location,
			"plan_hash": x.plan.PlanHash, "resumed": len(existing) == 1})
	})
	if err != nil {
		return nil, err
	}
	if err := db.Where("id = ?", change.ID).Take(&change).Error; err != nil {
		return nil, err
	}
	out.ChangeID, out.ChangeRow, out.State = &change.ID, &change, "awaiting_merge"
	return out, nil
}

// iacCommitMessage is the PR commit's message; it names the plan hash and
// the deployment, so a resumed attempt recognises its own commit.
func iacCommitMessage(desc iacpr.Description, p igagov.Plan, depID uuid.UUID) string {
	return desc.Title + "\n\nPlan hash: " + p.PlanHash + "\nAuthSec deployment: " + depID.String()
}

// recordStep is PullRequestInput.OnStep: the intent of the next GitHub
// write, committed (fenced) before it is made. StepRef records the commit as
// the change's proposed_sha while the change is `opening` (the resume key);
// every step is an iac.pr_step event.
func (d *GovIaCDelivery) recordStep(run *PolicyJobRun, ws uuid.UUID, x *iacDep, changeID uuid.UUID, changeState string) func(context.Context, string, string) error {
	return func(ctx context.Context, step, sha string) error {
		return run.InTx(ctx, func(tx *gorm.DB) error {
			if step == iacpr.StepRef && changeState == "opening" {
				res := tx.Model(&models.IGAGovIaCChange{}).Where("workspace_id = ? AND id = ? AND state = 'opening'", ws, changeID).
					Updates(map[string]any{"proposed_sha": sha, "updated_at": d.now().UTC()})
				if res.Error != nil {
					return res.Error
				}
				if res.RowsAffected != 1 {
					return fmt.Errorf("iac change %s is no longer opening", changeID)
				}
			}
			refs, err := govDeploymentRefs(tx, ws, x.dep)
			if err != nil {
				return err
			}
			return appendGovEvent(tx, ws, GovEventIaCPRStep, models.GovActorSystem, "iac_delivery", refs, map[string]any{
				"iac_change_id": changeID, "step": step, "sha": sha, "change_state": changeState})
		})
	}
}

// blockQueued moves a queued iac_pr deployment to blocked with the reason.
func (d *GovIaCDelivery) blockQueued(ctx context.Context, run *PolicyJobRun, ws uuid.UUID, x *iacDep, reason string, payload map[string]any) (*GovIaCOutcome, error) {
	err := run.InTx(ctx, func(tx *gorm.DB) error {
		if err := d.states.TransitionTx(tx, GovDeploymentTransition{WorkspaceID: ws, DeploymentID: x.dep.ID, From: []string{"queued"},
			To: "blocked", Reason: reason}); err != nil {
			return err
		}
		refs, err := govDeploymentRefs(tx, ws, x.dep)
		if err != nil {
			return err
		}
		return appendGovEvent(tx, ws, GovEventIaCBlocked, models.GovActorSystem, "iac_delivery", refs, payload)
	})
	if err != nil {
		return nil, err
	}
	return &GovIaCOutcome{DeploymentID: x.dep.ID, State: "blocked", Reason: reason}, nil
}

// precheck classifies the live state against the plan before anything is
// proposed (§8.4 "queued -> live state changed -> blocked"): a conflict --
// for an undo of a split copy, the copy now used by another role
// (artifact_consumers_changed, A60) -- blocks the deployment with the
// classifier's reason and diff; no PR is opened and no export offered.
// Without a live reader the check is skipped (the apply-time
// classification still applies).
func (d *GovIaCDelivery) precheck(ctx context.Context, run *PolicyJobRun, ws uuid.UUID, x *iacDep) (*GovIaCOutcome, error) {
	r := d.reader()
	if r == nil {
		return nil, nil
	}
	var live igagov.LiveRead
	if err := run.External(ctx, 0, func(ctx context.Context) error {
		var err error
		live, err = r.ReadRole(ctx, LiveReadRequest{WorkspaceID: ws, ConnectorID: x.control.ConnectorID, AccountID: x.control.AccountID,
			RoleARN: x.control.RoleARN, RoleID: x.control.RoleID, PolicyARNs: awsenforce.PolicyARNsFor(x.plan, "")})
		if err != nil || x.plan.Diff.Split == nil {
			return err
		}
		nr := x.plan.Diff.Split.NewRoleARN
		nl, err := r.ReadRole(ctx, LiveReadRequest{WorkspaceID: ws, ConnectorID: x.control.ConnectorID, AccountID: x.control.AccountID, RoleARN: nr})
		if err != nil {
			return err
		}
		live.Roles = map[string]*igagov.LiveRole{nr: nl.Role}
		return nil
	}); err != nil {
		return nil, err
	}
	if x.plan.Diff.Split != nil {
		// Bindings are read by the migration evidence after delivery; here
		// the subject is taken at its before value.
		live.Bindings = map[string]string{}
		for _, f := range x.plan.Facts {
			if f.Kind == igagov.FactBinding {
				live.Bindings[f.Subject] = f.Before
			}
		}
	}
	cl, err := igagov.Classify(x.plan, live)
	if err != nil {
		return nil, err
	}
	if cl.Class != igagov.ClassConflict {
		return nil, nil
	}
	err = run.InTx(ctx, func(tx *gorm.DB) error {
		if err := d.states.TransitionTx(tx, GovDeploymentTransition{WorkspaceID: ws, DeploymentID: x.dep.ID, From: []string{"queued"},
			To: "blocked", Reason: cl.Reason}); err != nil {
			return err
		}
		refs, err := govDeploymentRefs(tx, ws, x.dep)
		if err != nil {
			return err
		}
		return appendGovEvent(tx, ws, GovEventIaCBlocked, models.GovActorSystem, "iac_delivery", refs, map[string]any{
			"reason": cl.Reason, "diff": cl.Conflicts, "stage": "precondition"})
	})
	if err != nil {
		return nil, err
	}
	return &GovIaCOutcome{DeploymentID: x.dep.ID, State: "blocked", Reason: cl.Reason, Class: &cl}, nil
}

/* ---------------------------------- sync ---------------------------------- */

// SyncHandler is the iac_sync job: subject = an iga_gov_iac_change (J2) or
// an awaiting_apply deployment without one (J1, DECISION above).
func (d *GovIaCDelivery) SyncHandler(ctx context.Context, run *PolicyJobRun) error {
	if run.Job.SubjectID == nil {
		return PolicyJobAbandon("iac_sync without a subject")
	}
	ws, id := run.Job.WorkspaceID, *run.Job.SubjectID
	var n int64
	if err := d.db.WithContext(ctx).Model(&models.IGAGovIaCChange{}).Where("workspace_id = ? AND id = ?", ws, id).Count(&n).Error; err != nil {
		return err
	}
	var err error
	if n == 1 {
		_, err = d.Sync(ctx, run, ws, id)
	} else {
		_, err = d.ObserveApply(ctx, run, ws, id)
	}
	var ge *GovError
	if errors.As(err, &ge) && ge.Status == http.StatusNotFound {
		return PolicyJobAbandon("subject gone")
	}
	return err
}

// Sync reads a PR's state and moves the deployment (§8.11 J2).
func (d *GovIaCDelivery) Sync(ctx context.Context, run *PolicyJobRun, ws, changeID uuid.UUID) (*GovIaCOutcome, error) {
	db := d.db.WithContext(ctx)
	var ch models.IGAGovIaCChange
	if err := db.Where("workspace_id = ? AND id = ?", ws, changeID).Take(&ch).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, GovNotFound()
		}
		return nil, err
	}
	x, err := d.load(db, ws, ch.DeploymentID)
	if err != nil {
		return nil, err
	}
	out := &GovIaCOutcome{DeploymentID: ch.DeploymentID, State: x.dep.State, ChangeID: &ch.ID}
	if ch.State == "opening" {
		return d.recoverOpening(ctx, run, ws, ch, x)
	}
	if ch.PRNumber == nil {
		out.ChangeRow = &ch
		return out, nil
	}
	if ch.State == "open" || ch.State == "changed_after_review" {
		gh := d.gh()
		if gh == nil {
			return nil, govErr(http.StatusServiceUnavailable, GovCodeIaCUnavailable, "Pull requests are not configured in this build.", nil)
		}
		var src models.IGAGovIaCSource
		if err := db.Where("workspace_id = ? AND id = ?", ws, ch.SourceID).Take(&src).Error; err != nil {
			return nil, err
		}
		repo, err := IaCRepoRef(db, ws, src)
		if err != nil {
			return nil, err
		}
		var st iacpr.PullRequestState
		if err := run.External(ctx, 0, func(ctx context.Context) error {
			var err error
			st, err = gh.PullRequestState(ctx, repo, *ch.PRNumber)
			return err
		}); err != nil {
			return nil, err
		}
		now := d.now().UTC()
		refreshable := false
		err = run.InTx(ctx, func(tx *gorm.DB) error {
			refreshable = false
			refs, err := govDeploymentRefs(tx, ws, x.dep)
			if err != nil {
				return err
			}
			set := map[string]any{"updated_at": now}
			if ch.ReviewedSHA == "" && st.FirstApprovalSHA != "" {
				set["reviewed_sha"] = st.FirstApprovalSHA
				if err := appendGovEvent(tx, ws, GovEventIaCReviewed, models.GovActorSystem, "iac_sync", refs, map[string]any{
					"iac_change_id": ch.ID, "reviewed_sha": st.FirstApprovalSHA, "proposed_sha": ch.ProposedSHA}); err != nil {
					return err
				}
			}
			switch {
			case st.Merged:
				mergedAt := now
				if st.MergedAt != nil {
					mergedAt = st.MergedAt.UTC()
				}
				set["state"], set["merged_sha"], set["merged_at"] = "merged", st.MergedSHA, mergedAt
				if len(st.ApplyRuns) > 0 {
					set["apply_run_ref"] = st.ApplyRuns[0].Ref
				}
				if err := tx.Model(&models.IGAGovIaCChange{}).Where("workspace_id = ? AND id = ?", ws, ch.ID).Updates(set).Error; err != nil {
					return err
				}
				deadline := mergedAt.Add(d.applyHours(tx, ws))
				if err := d.states.TransitionTx(tx, GovDeploymentTransition{WorkspaceID: ws, DeploymentID: x.dep.ID,
					From: []string{"awaiting_merge"}, To: "awaiting_apply", Reason: "merged_awaiting_apply", ApplyDeadlineAt: &deadline}); err != nil {
					return err
				}
				return appendGovEvent(tx, ws, GovEventIaCMerged, models.GovActorSystem, "iac_sync", refs, map[string]any{
					"iac_change_id": ch.ID, "merged_sha": st.MergedSHA, "merged_at": mergedAt, "apply_deadline_at": deadline,
					"changed_after_review": ch.State == "changed_after_review", "apply_runs": st.ApplyRuns})
			case st.State == "closed":
				set["state"] = "closed"
				if err := tx.Model(&models.IGAGovIaCChange{}).Where("workspace_id = ? AND id = ?", ws, ch.ID).Updates(set).Error; err != nil {
					return err
				}
				if err := d.states.TransitionTx(tx, GovDeploymentTransition{WorkspaceID: ws, DeploymentID: x.dep.ID,
					From: []string{"awaiting_merge"}, To: "failed", Reason: IaCReasonClosed}); err != nil {
					return err
				}
				return appendGovEvent(tx, ws, GovEventIaCClosed, models.GovActorSystem, "iac_sync", refs, map[string]any{
					"iac_change_id": ch.ID, "pr_number": *ch.PRNumber})
			default:
				if st.HeadSHA != "" && st.HeadSHA != ch.ProposedSHA && ch.State == "open" && st.HeadSHA == lastUpdateIntent(tx, ws, ch.ID) {
					// AuthSec's own update, whose completion was not recorded.
					set["proposed_sha"] = st.HeadSHA
					refreshable = true
				} else if st.HeadSHA != "" && st.HeadSHA != ch.ProposedSHA && ch.State == "open" {
					set["state"] = "changed_after_review"
					if err := appendGovEvent(tx, ws, GovEventIaCChangedReview, models.GovActorSystem, "iac_sync", refs, map[string]any{
						"iac_change_id": ch.ID, "proposed_sha": ch.ProposedSHA, "head_sha": st.HeadSHA}); err != nil {
						return err
					}
				}
				if st.HeadSHA == ch.ProposedSHA && ch.State == "open" {
					refreshable = true
				}
				return tx.Model(&models.IGAGovIaCChange{}).Where("workspace_id = ? AND id = ?", ws, ch.ID).Updates(set).Error
			}
		})
		if err != nil {
			return nil, err
		}
		if refreshable && x.dep.State == "awaiting_merge" {
			if err := d.refreshOpen(ctx, run, ws, ch, x, st, repo, src); err != nil {
				return nil, err
			}
		}
	} else if ch.State == "merged" {
		// The apply run of merged_sha may be reported later.
		if err := d.refreshApplyRun(ctx, run, ws, ch, x); err != nil {
			return nil, err
		}
	}
	cur, err := d.load(db, ws, ch.DeploymentID)
	if err != nil {
		return nil, err
	}
	if cur.dep.State == "awaiting_apply" {
		o, err := d.ObserveApply(ctx, run, ws, ch.DeploymentID)
		if err != nil {
			return nil, err
		}
		o.ChangeID = &ch.ID
		var fresh models.IGAGovIaCChange
		if db.Where("id = ?", ch.ID).Take(&fresh).Error == nil {
			o.ChangeRow = &fresh
		}
		return o, nil
	}
	var fresh models.IGAGovIaCChange
	if err := db.Where("id = ?", ch.ID).Take(&fresh).Error; err != nil {
		return nil, err
	}
	out.State, out.ChangeRow = cur.dep.State, &fresh
	return out, nil
}

func (d *GovIaCDelivery) refreshApplyRun(ctx context.Context, run *PolicyJobRun, ws uuid.UUID, ch models.IGAGovIaCChange, x *iacDep) error {
	if ch.ApplyRunRef != "" || ch.PRNumber == nil || d.gh() == nil {
		return nil
	}
	db := d.db.WithContext(ctx)
	var src models.IGAGovIaCSource
	if err := db.Where("workspace_id = ? AND id = ?", ws, ch.SourceID).Take(&src).Error; err != nil {
		return err
	}
	repo, err := IaCRepoRef(db, ws, src)
	if err != nil {
		return err
	}
	var st iacpr.PullRequestState
	if err := run.External(ctx, 0, func(ctx context.Context) error {
		var err error
		st, err = d.gh().PullRequestState(ctx, repo, *ch.PRNumber)
		return err
	}); err != nil {
		return err
	}
	if len(st.ApplyRuns) == 0 {
		return nil
	}
	return run.InTx(ctx, func(tx *gorm.DB) error {
		if err := tx.Model(&models.IGAGovIaCChange{}).Where("workspace_id = ? AND id = ?", ws, ch.ID).
			Updates(map[string]any{"apply_run_ref": st.ApplyRuns[0].Ref, "updated_at": d.now().UTC()}).Error; err != nil {
			return err
		}
		refs, err := govDeploymentRefs(tx, ws, x.dep)
		if err != nil {
			return err
		}
		return appendGovEvent(tx, ws, GovEventIaCApplyRun, models.GovActorSystem, "iac_sync", refs, map[string]any{
			"iac_change_id": ch.ID, "apply_runs": st.ApplyRuns})
	})
}

/* ----------------------- opening recovery and PR update -------------------- */

// GovIaCOpeningLimit bounds how long a change may stay `opening` while
// retries fail: after it, the deployment fails (iac.pr_open_failed) instead
// of holding the role forever.
const GovIaCOpeningLimit = 24 * time.Hour

// recoverOpening is iac_sync for a change still `opening` (review P2): the
// run that was opening it died or exhausted its attempts. While the
// deployment is queued, Deliver resumes it from what was recorded and what
// GitHub shows by branch name; a deployment that left queued, or a change
// that cannot be opened for GovIaCOpeningLimit, ends `failed` -- an
// `opening` row never lasts forever.
func (d *GovIaCDelivery) recoverOpening(ctx context.Context, run *PolicyJobRun, ws uuid.UUID, ch models.IGAGovIaCChange, x *iacDep) (*GovIaCOutcome, error) {
	var cause string
	if x.dep.State == "queued" {
		o, err := d.Deliver(ctx, run, ws, ch.DeploymentID)
		if err == nil {
			o.ChangeID = &ch.ID
			return o, nil
		}
		if errors.Is(err, repositories.ErrPolicyJobLeaseLost) || d.now().UTC().Sub(ch.UpdatedAt) < GovIaCOpeningLimit {
			return nil, err
		}
		cause = err.Error()
	} else {
		cause = "the deployment is " + x.dep.State + ", not queued"
	}
	now := d.now().UTC()
	err := run.InTx(ctx, func(tx *gorm.DB) error {
		if err := tx.Model(&models.IGAGovIaCChange{}).Where("workspace_id = ? AND id = ? AND state = 'opening'", ws, ch.ID).
			Updates(map[string]any{"state": "failed", "updated_at": now}).Error; err != nil {
			return err
		}
		if x.dep.State == "queued" {
			if err := d.states.TransitionTx(tx, GovDeploymentTransition{WorkspaceID: ws, DeploymentID: x.dep.ID, From: []string{"queued"},
				To: "failed", Reason: "pr_open_failed: " + cause}); err != nil {
				return err
			}
		}
		refs, err := govDeploymentRefs(tx, ws, x.dep)
		if err != nil {
			return err
		}
		return appendGovEvent(tx, ws, GovEventIaCOpenFailed, models.GovActorSystem, "iac_sync", refs, map[string]any{
			"iac_change_id": ch.ID, "branch": ch.Branch, "proposed_sha": ch.ProposedSHA, "cause": cause})
	})
	if err != nil {
		return nil, err
	}
	var fresh models.IGAGovIaCChange
	if err := d.db.WithContext(ctx).Where("id = ?", ch.ID).Take(&fresh).Error; err != nil {
		return nil, err
	}
	cur, err := d.load(d.db.WithContext(ctx), ws, ch.DeploymentID)
	if err != nil {
		return nil, err
	}
	return &GovIaCOutcome{DeploymentID: ch.DeploymentID, State: cur.dep.State, Reason: cur.dep.StateReason, ChangeID: &ch.ID, ChangeRow: &fresh}, nil
}

// lastUpdateIntent is the commit of the latest PR-update intent recorded for
// an open change (iac.pr_step, change_state open): a head equal to it is
// AuthSec's own update whose completion was not recorded, not a change
// after review.
func lastUpdateIntent(db *gorm.DB, ws, changeID uuid.UUID) string {
	var shas []string
	db.Raw(`SELECT payload->>'sha' FROM iga_gov_event WHERE workspace_id = ? AND event = ? AND payload->>'iac_change_id' = ?
		AND payload->>'change_state' = 'open' AND payload->>'step' = ? ORDER BY id DESC LIMIT 1`,
		ws, GovEventIaCPRStep, changeID.String(), iacpr.StepRef).Scan(&shas)
	if len(shas) == 1 {
		return shas[0]
	}
	return ""
}

// refreshOpen is the PR update path (review P2) for an `open` change whose
// head is still AuthSec's:
//
//   - the deployment's plan was recompiled: a current plan of the same
//     target and kind with the SAME plan hash (revalidated, unchanged)
//     keeps the PR; a different hash (or none) means what the PR proposes is
//     no longer approved -- AuthSec closes the PR with the reason and the
//     deployment is blocked (plan_changed); a new approval opens a new one;
//   - the approved plan is re-rendered against the base branch's current
//     head (and the description regenerated): a source that no longer
//     renders it closes the PR and blocks (iac_form_changed); a rendering or
//     description that differs from the PR's updates the SAME branch and PR
//     (rebased on the new base) and records the new proposed_sha.
//
// DECISION (review P2): "close and reopen" is used only when the approved
// change itself is gone; a moved base or improved description is an
// update, so reviewers keep one PR and its history.
func (d *GovIaCDelivery) refreshOpen(ctx context.Context, run *PolicyJobRun, ws uuid.UUID, ch models.IGAGovIaCChange, x *iacDep,
	st iacpr.PullRequestState, repo iacpr.RepoRef, src models.IGAGovIaCSource) error {
	db := d.db.WithContext(ctx)
	gh := d.gh()
	closeAndBlock := func(reason string, payload map[string]any) error {
		comment := "AuthSec closed this pull request: " + reason + ". The approved change can no longer be delivered from it; " +
			"a new approval will open a new pull request."
		if err := run.External(ctx, 0, func(ctx context.Context) error { return gh.ClosePullRequest(ctx, repo, *ch.PRNumber, comment) }); err != nil {
			return err
		}
		now := d.now().UTC()
		return run.InTx(ctx, func(tx *gorm.DB) error {
			if err := tx.Model(&models.IGAGovIaCChange{}).Where("workspace_id = ? AND id = ? AND state = 'open'", ws, ch.ID).
				Updates(map[string]any{"state": "closed", "updated_at": now}).Error; err != nil {
				return err
			}
			if err := d.states.TransitionTx(tx, GovDeploymentTransition{WorkspaceID: ws, DeploymentID: x.dep.ID,
				From: []string{"awaiting_merge"}, To: "blocked", Reason: reason}); err != nil {
				return err
			}
			refs, err := govDeploymentRefs(tx, ws, x.dep)
			if err != nil {
				return err
			}
			payload["iac_change_id"], payload["pr_number"], payload["reason"] = ch.ID, *ch.PRNumber, reason
			return appendGovEvent(tx, ws, GovEventIaCPRSuperseded, models.GovActorSystem, "iac_sync", refs, payload)
		})
	}
	if x.planRow.SupersededAt != nil {
		var cur []models.IGAGovPlan
		if err := db.Where("workspace_id = ? AND target_id = ? AND kind = ? AND superseded_at IS NULL", ws, x.planRow.TargetID, x.planRow.Kind).
			Find(&cur).Error; err != nil {
			return err
		}
		if len(cur) != 1 || cur[0].PlanHash != x.planRow.PlanHash {
			now := ""
			if len(cur) == 1 {
				now = cur[0].PlanHash
			}
			return closeAndBlock(GovCodePlanChanged, map[string]any{"approved_plan_hash": x.planRow.PlanHash, "current_plan_hash": now})
		}
	}
	keep, err := d.keepNewRole(db, ws, x)
	if err != nil {
		return err
	}
	var form *GovIaCForm
	var head iacpr.Snapshot
	if err := run.External(ctx, 0, func(ctx context.Context) error {
		f, err := DecideIaCForm(ctx, db, gh, ws, x.control, x.plan, x.docs, x.dep.ID.String(), keep)
		if err != nil {
			return err
		}
		form = f
		head, err = gh.ReadDirectory(ctx, repo, ch.Branch, src.Directory)
		return err
	}); err != nil {
		var ge *GovError
		if errors.As(err, &ge) && ge.Status == http.StatusConflict {
			return closeAndBlock(IaCReasonFormChanged+": "+ge.Code, map[string]any{"detail": ge.Detail})
		}
		return err
	}
	if form.Fallback != nil {
		return closeAndBlock(IaCReasonFormChanged+": "+form.Fallback.Reason, map[string]any{"detail": form.Fallback.Detail})
	}
	if form.Source == nil || form.Source.ID != src.ID || form.Change.Empty() {
		return nil // the role moved to another source, or the base already holds the change: leave the PR to its reviewers
	}
	desc := iacpr.Describe(x.plan, roleTarget(x.control), form.Change)
	filesDiffer := false
	for _, f := range form.Change.Files {
		if head.Files[f.Path] != f.After {
			filesDiffer = true
		}
	}
	descDiffer := st.Title != desc.Title || st.Body != desc.Body
	if !filesDiffer && !descDiffer {
		return nil
	}
	var pr iacpr.PullRequest
	if err := run.External(ctx, 0, func(ctx context.Context) error {
		var err error
		pr, err = gh.UpdatePullRequest(ctx, repo, *ch.PRNumber, iacpr.PullRequestInput{BaseBranch: src.BaseBranch, BaseSHA: form.CommitSHA,
			Branch: ch.Branch, Title: desc.Title, Body: desc.Body, CommitMessage: iacCommitMessage(desc, x.plan, x.dep.ID),
			Files: form.Change.Files, OnStep: d.recordStep(run, ws, x, ch.ID, "open")})
		return err
	}); err != nil {
		return err
	}
	now := d.now().UTC()
	return run.InTx(ctx, func(tx *gorm.DB) error {
		if err := tx.Model(&models.IGAGovIaCChange{}).Where("workspace_id = ? AND id = ? AND state = 'open'", ws, ch.ID).
			Updates(map[string]any{"proposed_sha": pr.HeadSHA, "updated_at": now}).Error; err != nil {
			return err
		}
		refs, err := govDeploymentRefs(tx, ws, x.dep)
		if err != nil {
			return err
		}
		return appendGovEvent(tx, ws, GovEventIaCPRUpdated, models.GovActorSystem, "iac_sync", refs, map[string]any{
			"iac_change_id": ch.ID, "pr_number": *ch.PRNumber, "previous_sha": ch.ProposedSHA, "proposed_sha": pr.HeadSHA,
			"base_sha": form.CommitSHA, "files_changed": filesDiffer, "description_changed": descDiffer, "plan_hash": x.plan.PlanHash})
	})
}

/* ------------------------------ observe apply ------------------------------ */

// GovApplyProgress is the artifact verification row's evidence while a J1 /
// J2 deployment waits for the customer's apply.
type GovApplyProgress struct {
	Class     string              `json:"class"`
	Visible   int                 `json:"visible"`
	Total     int                 `json:"total"`
	Overdue   bool                `json:"overdue"`
	Deadline  *time.Time          `json:"apply_deadline_at"`
	Seen      []igagov.FactResult `json:"visible_facts"`
	Awaited   []igagov.FactResult `json:"awaited_facts"`
	Conflicts []igagov.FactResult `json:"conflicts"`
	Reason    string              `json:"reason,omitempty"`
	Summary   string              `json:"summary"`
}

func progressOf(c igagov.Classification, deadline *time.Time, overdue bool) GovApplyProgress {
	p := GovApplyProgress{Class: c.Class, Visible: c.Visible, Total: c.Total, Overdue: overdue, Deadline: deadline,
		Seen: []igagov.FactResult{}, Awaited: []igagov.FactResult{}, Conflicts: c.Conflicts, Reason: c.Reason}
	for _, f := range c.Facts {
		if !f.Changes() || f.OnlyBefore {
			continue
		}
		if f.At == igagov.AtAfter {
			p.Seen = append(p.Seen, f)
		} else if f.At == igagov.AtBefore {
			p.Awaited = append(p.Awaited, f)
		}
	}
	if p.Conflicts == nil {
		p.Conflicts = []igagov.FactResult{}
	}
	p.Summary = fmt.Sprintf("%d of %d changes visible in AWS", c.Visible, c.Total)
	if overdue {
		p.Summary += "; overdue"
	}
	return p
}

// ObserveApply classifies an awaiting_apply deployment's live state (§8.11).
func (d *GovIaCDelivery) ObserveApply(ctx context.Context, run *PolicyJobRun, ws, depID uuid.UUID) (*GovIaCOutcome, error) {
	db := d.db.WithContext(ctx)
	x, err := d.load(db, ws, depID)
	if err != nil {
		return nil, err
	}
	out := &GovIaCOutcome{DeploymentID: depID, State: x.dep.State}
	if x.dep.State != "awaiting_apply" {
		return out, nil
	}
	r := d.reader()
	if r == nil {
		return nil, govErr(http.StatusServiceUnavailable, GovCodeDiscoveryUnavail, "Live reads are not configured in this build.", nil)
	}
	split := x.plan.Kind == igagov.PlanSplit || x.plan.Kind == igagov.PlanSplitRevert
	var live igagov.LiveRead
	if err := run.External(ctx, 0, func(ctx context.Context) error {
		var err error
		live, err = r.ReadRole(ctx, LiveReadRequest{WorkspaceID: ws, ConnectorID: x.control.ConnectorID, AccountID: x.control.AccountID,
			RoleARN: x.control.RoleARN, RoleID: x.control.RoleID, PolicyARNs: awsenforce.PolicyARNsFor(x.plan, "")})
		if err != nil {
			return err
		}
		if !split {
			return nil
		}
		live.Roles = map[string]*igagov.LiveRole{}
		nr := x.plan.Diff.Split.NewRoleARN
		nl, err := r.ReadRole(ctx, LiveReadRequest{WorkspaceID: ws, ConnectorID: x.control.ConnectorID, AccountID: x.control.AccountID, RoleARN: nr})
		if err != nil {
			return err
		}
		live.Roles[nr] = nl.Role
		return nil
	}); err != nil {
		return nil, err
	}
	if split {
		newRoleID := ""
		if nr := live.Roles[x.plan.Diff.Split.NewRoleARN]; nr != nil {
			newRoleID = nr.RoleID
		}
		checks, bindings, err := d.checkMigrations(ctx, run, ws, x, newRoleID)
		if err != nil {
			return nil, err
		}
		out.Migrations = checks
		live.Bindings = bindings
	}
	cl, err := igagov.Classify(x.plan, live)
	if err != nil {
		return nil, err
	}
	out.Class = &cl
	now := d.now().UTC()
	overdue := x.dep.ApplyDeadlineAt != nil && now.After(*x.dep.ApplyDeadlineAt)
	prog := progressOf(cl, x.dep.ApplyDeadlineAt, overdue)
	err = run.InTx(ctx, func(tx *gorm.DB) error {
		refs, err := govDeploymentRefs(tx, ws, x.dep)
		if err != nil {
			return err
		}
		switch cl.Class {
		case igagov.ClassBefore, igagov.ClassIntermediate:
			outcome := "awaiting_evidence"
			if overdue {
				outcome = "overdue"
			}
			changed, err := upsertArtifactVerification(tx, ws, depID, outcome, prog)
			if err != nil {
				return err
			}
			reason := "awaiting_apply: " + prog.Summary
			if err := tx.Model(&models.IGAGovDeployment{}).Where("workspace_id = ? AND id = ? AND state = 'awaiting_apply'", ws, depID).
				Updates(map[string]any{"state_reason": reason, "updated_at": now}).Error; err != nil {
				return err
			}
			out.State, out.Reason, out.Overdue = "awaiting_apply", reason, overdue
			if changed {
				return appendGovEvent(tx, ws, GovEventIaCApplyPending, models.GovActorSystem, "iac_sync", refs, map[string]any{
					"class": cl.Class, "visible": cl.Visible, "total": cl.Total, "overdue": overdue, "summary": prog.Summary})
			}
			return nil
		case igagov.ClassAfter:
			verifyBy := now.Add(GovVerifyDeadline)
			if err := d.states.TransitionTx(tx, GovDeploymentTransition{WorkspaceID: ws, DeploymentID: depID, From: []string{"awaiting_apply"},
				To: "applied_unverified", Reason: IaCReasonAppliedOut, AppliedAt: &now, VerifyDeadlineAt: &verifyBy}); err != nil {
				return err
			}
			if err := tx.Model(&models.IGAGovIaCChange{}).Where("workspace_id = ? AND deployment_id = ? AND state = 'merged'", ws, depID).
				Updates(map[string]any{"state": "applied", "updated_at": now}).Error; err != nil {
				return err
			}
			if err := d.recordLedgerTx(tx, ws, x, now); err != nil {
				return err
			}
			if _, err := upsertArtifactVerification(tx, ws, depID, "awaiting_evidence", prog); err != nil {
				return err
			}
			out.State, out.Reason = "applied_unverified", IaCReasonAppliedOut
			return appendGovEvent(tx, ws, GovEventIaCAppliedOutside, models.GovActorSystem, "iac_sync", refs, map[string]any{
				"message": "applied outside AuthSec, matched by role, attachment and document hash",
				"role_id": x.control.RoleID, "desired_boundary_arn": x.plan.DesiredBoundaryARN,
				"desired_document_hash": x.plan.DesiredDocumentHash, "facts": prog.Seen, "delivery": x.dep.Delivery})
		default:
			reason := IaCReasonUnexpected + ": " + cl.Reason
			if err := d.states.TransitionTx(tx, GovDeploymentTransition{WorkspaceID: ws, DeploymentID: depID, From: []string{"awaiting_apply"},
				To: "failed", Reason: reason}); err != nil {
				return err
			}
			// DECISION (T3.17): the change was merged and the pipeline applied
			// something, so the iac_change row ends `applied` (053 allows
			// `failed` only before a merge; a `merged` row would be synced
			// forever); the deployment carries failed: unexpected_state.
			if err := tx.Model(&models.IGAGovIaCChange{}).Where("workspace_id = ? AND deployment_id = ? AND state = 'merged'", ws, depID).
				Updates(map[string]any{"state": "applied", "updated_at": now}).Error; err != nil {
				return err
			}
			if _, err := upsertArtifactVerification(tx, ws, depID, "failed", prog); err != nil {
				return err
			}
			out.State, out.Reason = "failed", reason
			return appendGovEvent(tx, ws, GovEventIaCUnexpected, models.GovActorSystem, "iac_sync", refs, map[string]any{
				"reason": cl.Reason, "diff": cl.Conflicts, "message": "what was applied is not what was reviewed"})
		}
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// upsertArtifactVerification writes the deployment's artifact dimension;
// true when the progress (class, visible count, overdue) changed.
func upsertArtifactVerification(tx *gorm.DB, ws, depID uuid.UUID, outcome string, prog GovApplyProgress) (bool, error) {
	raw, err := json.Marshal(prog)
	if err != nil {
		return false, err
	}
	var prev []models.IGAGovVerification
	if err := tx.Where("workspace_id = ? AND deployment_id = ? AND dimension = 'artifact'", ws, depID).Find(&prev).Error; err != nil {
		return false, err
	}
	changed := true
	if len(prev) == 1 {
		var p GovApplyProgress
		if json.Unmarshal(prev[0].Evidence, &p) == nil && prev[0].Outcome == outcome && p.Class == prog.Class &&
			p.Visible == prog.Visible && p.Overdue == prog.Overdue {
			changed = false
		}
	}
	err = tx.Exec(`INSERT INTO iga_gov_verification (workspace_id, deployment_id, dimension, outcome, evidence, checked_at)
		VALUES (?, ?, 'artifact', ?, ?::jsonb, now())
		ON CONFLICT (deployment_id, dimension) DO UPDATE SET outcome = EXCLUDED.outcome, evidence = EXCLUDED.evidence, checked_at = now()`,
		ws, depID, outcome, string(raw)).Error
	return changed, err
}

// recordLedgerTx writes the customer_iac ledger rows of an applied J1/J2
// deployment (§8.5 ledger table; §11 dedicated_role / workload_binding).
func (d *GovIaCDelivery) recordLedgerTx(tx *gorm.DB, ws uuid.UUID, x *iacDep, now time.Time) error {
	p := x.plan
	settle := func(kind, keepARN, state string, keepMore ...string) error {
		keep := pq.StringArray(append([]string{keepARN}, keepMore...))
		return tx.Exec(`UPDATE iga_gov_artifact SET state = ?, last_deployment_id = ?, last_readback_at = ?, updated_at = ?
			WHERE workspace_id = ? AND control_id = ? AND kind = ? AND state IN ('intended','present','drifted') AND native_arn <> ALL(?)`,
			state, x.dep.ID, now, now, ws, x.control.ID, kind, keep).Error
	}
	present := func(kind, arn string, doc *string) error {
		var n int64
		if err := tx.Model(&models.IGAGovArtifact{}).Where("workspace_id = ? AND control_id = ? AND kind = ? AND native_arn = ? AND state IN ('intended','present','drifted')",
			ws, x.control.ID, kind, arn).Count(&n).Error; err != nil {
			return err
		}
		if n > 0 {
			return tx.Model(&models.IGAGovArtifact{}).Where("workspace_id = ? AND control_id = ? AND kind = ? AND native_arn = ? AND state IN ('intended','present','drifted')",
				ws, x.control.ID, kind, arn).Updates(map[string]any{"state": "present", "document_hash": doc, "last_deployment_id": x.dep.ID,
				"last_readback_at": now, "updated_at": now, "owned_by": "customer_iac"}).Error
		}
		return tx.Create(&models.IGAGovArtifact{ID: uuid.New(), WorkspaceID: ws, ControlID: x.control.ID, Kind: kind, NativeARN: arn,
			OwnedBy: "customer_iac", State: "present", DocumentHash: doc, LastReadbackAt: &now, LastDeploymentID: x.dep.ID, UpdatedAt: now}).Error
	}
	switch p.Kind {
	case igagov.PlanSplit:
		dsp := p.Diff.Split
		// DECISION (review P1-12 (d)): the ledger keeps ONE workload_binding
		// per control (051 uq_iga_gov_artifact_live), named by the intent's
		// binding_ref: for an ECS task role the native binding is the task
		// definition's taskRoleArn, which every subject service follows. The
		// per-service state is the migration rows (one per service).
		return firstErr(settle("dedicated_role", dsp.NewRoleARN, "released"), present("dedicated_role", dsp.NewRoleARN, nil),
			settle("workload_binding", dsp.SubjectARN, "released"), present("workload_binding", dsp.SubjectARN, nil))
	case igagov.PlanSplitRevert:
		dsp := p.Diff.Split
		if err := tx.Exec(`UPDATE iga_gov_workload_migration SET state = 'reverted' WHERE workspace_id = ? AND control_id = ?
			AND subject_arn = ANY(?) AND to_role_arn = ? AND plan_id <> ?`, ws, x.control.ID, pq.StringArray(dsp.Subjects()), dsp.NewRoleARN,
			x.planRow.ID).Error; err != nil {
			return err
		}
		return firstErr(settle("dedicated_role", "", "removed"), settle("workload_binding", "", "removed"))
	}
	disposed := "released"
	if p.ArtifactDisposition == igagov.DispositionDelete {
		disposed = "removed"
	}
	if p.DesiredAttachment == igagov.AttachmentAbsent {
		return firstErr(settle("boundary_policy", "", disposed), settle("boundary_attachment", "", "removed"))
	}
	arn := *p.DesiredBoundaryARN
	return firstErr(settle("boundary_policy", arn, disposed), present("boundary_policy", arn, p.DesiredDocumentHash),
		settle("boundary_attachment", arn, "removed"), present("boundary_attachment", arn, nil))
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

/* ------------------------------ isolation hook ----------------------------- */

// keepNewRole: a split_revert leaves the new role when something other than
// its subject runs as it now (§11).
func (d *GovIaCDelivery) keepNewRole(db *gorm.DB, ws uuid.UUID, x *iacDep) (bool, error) {
	if x.plan.Kind != igagov.PlanSplitRevert || x.plan.Diff.Split == nil {
		return false, nil
	}
	keys, err := workloadsExecutingAsARN(db, ws, x.plan.Diff.Split.NewRoleARN)
	if err != nil {
		return false, err
	}
	pred := subjectPredicate(x.plan.Diff.Split.SubjectKind, x.plan.Diff.Split.SubjectARN, x.plan.Diff.Split.FromWorkloadKeys, nil)
	for _, k := range keys {
		if !pred(k) {
			return true, nil
		}
	}
	return false, nil
}
