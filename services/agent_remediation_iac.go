package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentcontain"
	"github.com/authsec-ai/authsec/internal/iacpr"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// Remediation of a resource managed as code (W8, IaC). A target that belongs
// to a CloudFormation stack (its aws:cloudformation:stack-name tag) or
// carries Terraform hints is never written: a write would drift from the
// source and be undone by the next deploy. When the account has an IaC
// source (iga_gov_iac_source, the same GitHub App path access policies use),
// applying the remediation opens a pull request carrying the exact change
// (the prepared steps and documents) for the code owners, and raises an ask
// to them. A merged pull request is followed by the proof from the account
// (the change event and the end state). A pull request CLOSED UNMERGED
// reopens the decision (state pr_closed, a new ask): the remediation can be
// applied again (a new pull request) or cancelled -- unlike an access
// policy's IaC deployment, which fails (iga_gov_iac_delivery.go keeps that
// behaviour; the two are separate code paths).
//
// The pull request adds one file, <directory>/authsec-remediation-<8hex>.json;
// AuthSec does not rewrite the customer's templates. Merging the file alone
// changes nothing in AWS: the code owners edit their source in the same pull
// request, and the proof only follows the account.

// RemediationIaCTarget is where a remediation's pull request goes.
type RemediationIaCTarget struct {
	SourceID   uuid.UUID
	Repo       iacpr.RepoRef
	BaseBranch string
	Directory  string
	Format     string
}

var remediationIaC = struct {
	sync.RWMutex
	resolve func(ctx context.Context, db *gorm.DB, ws, connectorID uuid.UUID, format string) (*RemediationIaCTarget, error)
}{}

// SetRemediationIaCResolver replaces how an account's IaC source is found
// (tests); nil restores production. It returns the undo.
func SetRemediationIaCResolver(f func(ctx context.Context, db *gorm.DB, ws, connectorID uuid.UUID, format string) (*RemediationIaCTarget, error)) (restore func()) {
	remediationIaC.Lock()
	prev := remediationIaC.resolve
	remediationIaC.resolve = f
	remediationIaC.Unlock()
	return func() { SetRemediationIaCResolver(prev) }
}

// resolveRemediationIaC is the account's IaC source of the format, or nil
// when it has none usable (the remediation is then prepared).
func resolveRemediationIaC(ctx context.Context, db *gorm.DB, ws, connectorID uuid.UUID, format string) (*RemediationIaCTarget, error) {
	remediationIaC.RLock()
	f := remediationIaC.resolve
	remediationIaC.RUnlock()
	if f != nil {
		return f(ctx, db, ws, connectorID, format)
	}
	var out *RemediationIaCTarget
	err := tenancy.InWorkspaceRead(ctx, db, ws, func(tx *gorm.DB) error {
		var srcs []models.IGAGovIaCSource
		if err := tx.Where("workspace_id = ? AND connector_id = ? AND format = ?", ws, connectorID, format).
			Order("created_at").Limit(1).Find(&srcs).Error; err != nil {
			return err
		}
		if len(srcs) == 0 {
			return nil
		}
		repo, err := IaCRepoRef(tx, ws, srcs[0])
		if err != nil {
			log.Printf("[remediation] workspace %s: IaC source %s unusable: %v", ws, srcs[0].ID, err)
			return nil
		}
		out = &RemediationIaCTarget{SourceID: srcs[0].ID, Repo: repo, BaseBranch: srcs[0].BaseBranch,
			Directory: srcs[0].Directory, Format: srcs[0].Format}
		return nil
	})
	return out, err
}

// remediationPRBody renders the pull request.
func remediationPRBody(r *remediationRow) (title, body, file string) {
	short := agentcontain.Short(r.ID)
	title = fmt.Sprintf("AuthSec remediation %s: %s on %s", short, r.Kind, r.TargetRef)
	if len(title) > 250 {
		title = title[:250]
	}
	var prep map[string]any
	_ = json.Unmarshal([]byte(r.Prepared), &prep)
	var b strings.Builder
	fmt.Fprintf(&b, "AuthSec remediation `%s` (%s) asks the code owners of this resource to make the change below in this source.\n\n", r.ID, r.Kind)
	fmt.Fprintf(&b, "**Target:** `%s`\n\n**Why:** %s\n\n", r.TargetRef, r.Reason)
	fmt.Fprintf(&b, "**Collateral:** see `%s`.\n\n", "authsec-remediation-"+short+".json")
	b.WriteString("The file in this pull request carries the exact API calls and policy documents. Merging the file alone changes nothing: " +
		"edit your template in this pull request so the deployed state matches. AuthSec proves the change from the account " +
		"(its CloudTrail record and a read of the end state). Closing this pull request unmerged reopens the decision in AuthSec.\n")
	doc := map[string]any{"remediation_id": r.ID, "kind": r.Kind, "target": r.TargetRef, "reason": r.Reason,
		"prepared": prep, "collateral": json.RawMessage(rawOr(r.Collateral, "{}"))}
	raw, _ := json.MarshalIndent(doc, "", "  ")
	return title, b.String(), string(raw) + "\n"
}

// openRemediationPR opens the pull request of an iac_pr remediation (state
// draft or pr_closed) and raises the ask to the code owners.
func (s *RemediationService) openRemediationPR(ctx context.Context, ws, actor uuid.UUID, r *remediationRow) (*RemediationView, error) {
	if r.ConnectorID == nil {
		return nil, govConflict(RemCodeState, "The remediation names no account.", nil)
	}
	var iac RemediationIaC
	_ = json.Unmarshal([]byte(r.IaC), &iac)
	tgt, err := resolveRemediationIaC(ctx, s.db, ws, *r.ConnectorID, iac.Tool)
	if err != nil {
		return nil, err
	}
	if tgt == nil {
		return nil, govConflict("iac_unavailable", "The account's IaC source is no longer usable; cancel and request the remediation again (it will be prepared).", nil)
	}
	gh := DefaultGovIaCGitHub()
	if gh == nil {
		return nil, govConflict("iac_unavailable", "Pull requests are not configured on this server.", nil)
	}
	base := tgt.BaseBranch
	if base == "" {
		base = "main"
	}
	snap, err := gh.ReadDirectory(ctx, tgt.Repo, base, tgt.Directory)
	if err != nil {
		return nil, govConflict("iac_unavailable", "The IaC repository could not be read.", nil)
	}
	title, body, content := remediationPRBody(r)
	dir := strings.Trim(tgt.Directory, "/")
	path := "authsec-remediation-" + agentcontain.Short(r.ID) + ".json"
	if dir != "" {
		path = dir + "/" + path
	}
	branch := fmt.Sprintf("authsec/remediation-%s-%d", agentcontain.Short(r.ID), r.PRCount+1)
	pr, err := gh.OpenPullRequest(ctx, tgt.Repo, iacpr.PullRequestInput{BaseBranch: base, BaseSHA: snap.CommitSHA, Branch: branch,
		Title: title, Body: body, CommitMessage: title, Files: []iacpr.FileChange{{Path: path, After: content, New: true}}})
	if err != nil {
		return nil, govConflict("iac_unavailable", "The pull request could not be opened.", map[string]any{"error": err.Error()})
	}
	now := s.now().UTC()
	var out *RemediationView
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		cur, err := readRemediation(tx, ws, r.ID, true)
		if err != nil {
			return err
		}
		if cur.State != RemediationDraft && cur.State != RemediationPRClosed {
			return govConflict(RemCodeState, "The remediation changed meanwhile.", map[string]any{"state": cur.State})
		}
		ref, err := remediationAsks().CreateAsk(tx, ws, RemediationAsk{RemediationID: r.ID, CaseID: r.CaseID, Role: "code_owners",
			Reason: "pr_review", Link: pr.URL, Choices: []string{"merge", "close"}, RequestedBy: actor,
			Question: "Review and merge the AuthSec remediation pull request (edit your source so the deployed state matches), or close it to reopen the decision."})
		if err != nil {
			return err
		}
		if err := tx.Exec(`UPDATE agent_remediation SET state = 'pr_open', state_reason = '', pr_number = ?, pr_url = ?, pr_branch = ?,
		        pr_state = 'open', pr_count = pr_count + 1, iac_source_id = ?, apply_requested_at = ?,
		        asks = asks || ?::jsonb, updated_at = now() WHERE workspace_id = ? AND id = ?`,
			pr.Number, pr.URL, branch, tgt.SourceID, now, remJSON([]map[string]any{{"ref": ref, "role": "code_owners", "reason": "pr_review", "pr": pr.Number}}),
			ws, r.ID).Error; err != nil {
			return err
		}
		if err := appendGovEvent(tx, ws, GovEventRemediationPROpened, models.GovActorUser, actor.String(), govEventRefs{}, map[string]any{
			"remediation_id": r.ID, "pr_number": pr.Number, "pr_url": pr.URL, "repository": tgt.Repo.FullName}); err != nil {
			return err
		}
		x, err := readRemediation(tx, ws, r.ID, false)
		if err != nil {
			return err
		}
		v := x.view()
		out = &v
		return nil
	})
	return out, err
}

// SyncPR reads an open pull request: merged -> pr_merged (the proof follows
// from the account); closed unmerged -> pr_closed, the decision reopened
// with a new ask. Another state is left as it is.
func (s *RemediationService) SyncPR(ctx context.Context, ws, id uuid.UUID) error {
	var r *remediationRow
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		r, err = readRemediation(tx, ws, id, false)
		return err
	}); err != nil {
		return err
	}
	if r.State != RemediationPROpen || r.PRNumber == nil || r.ConnectorID == nil {
		return nil
	}
	var iac RemediationIaC
	_ = json.Unmarshal([]byte(r.IaC), &iac)
	tgt, err := resolveRemediationIaC(ctx, s.db, ws, *r.ConnectorID, iac.Tool)
	if err != nil || tgt == nil {
		return err
	}
	gh := DefaultGovIaCGitHub()
	if gh == nil {
		return nil
	}
	st, err := gh.PullRequestState(ctx, tgt.Repo, *r.PRNumber)
	if err != nil {
		return err
	}
	if !st.Merged && st.State != "closed" {
		return nil
	}
	return tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		cur, err := readRemediation(tx, ws, id, true)
		if err != nil {
			return err
		}
		if cur.State != RemediationPROpen || cur.PRNumber == nil || *cur.PRNumber != *r.PRNumber {
			return nil
		}
		if st.Merged {
			at := s.now().UTC()
			if st.MergedAt != nil {
				at = st.MergedAt.UTC()
			}
			if err := tx.Exec(`UPDATE agent_remediation SET state = 'pr_merged', pr_state = 'merged', applied_at = ?, updated_at = now()
			    WHERE workspace_id = ? AND id = ?`, at, ws, id).Error; err != nil {
				return err
			}
			return appendGovEvent(tx, ws, GovEventRemediationPRMerged, models.GovActorSystem, "remediation", govEventRefs{}, map[string]any{
				"remediation_id": id, "pr_number": *r.PRNumber, "merged_sha": st.MergedSHA})
		}
		ref, err := remediationAsks().CreateAsk(tx, ws, RemediationAsk{RemediationID: id, CaseID: cur.CaseID, Role: "remediator",
			Reason: "pr_closed", Link: cur.PRURL, Choices: []string{"apply_again", "cancel"}, RequestedBy: cur.RequestedBy,
			Question: "The remediation's pull request was closed unmerged. Decide again: open a new pull request (apply) or cancel the remediation."})
		if err != nil {
			return err
		}
		if err := tx.Exec(`UPDATE agent_remediation SET state = 'pr_closed', pr_state = 'closed',
		        state_reason = 'pull request closed unmerged: the decision is open again', asks = asks || ?::jsonb, updated_at = now()
		    WHERE workspace_id = ? AND id = ?`,
			remJSON([]map[string]any{{"ref": ref, "role": "remediator", "reason": "pr_closed", "pr": *r.PRNumber}}), ws, id).Error; err != nil {
			return err
		}
		return appendGovEvent(tx, ws, GovEventRemediationPRClosed, models.GovActorSystem, "remediation", govEventRefs{}, map[string]any{
			"remediation_id": id, "pr_number": *r.PRNumber, "reopened": true, "at": time.Now().UTC()})
	})
}
