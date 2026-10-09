package integration

// Review fixes for T3.17 (REVIEW-FIXLIST P2 GitHub / IaC source checks /
// export approval): PR creation is crash-safe and an `opening` change is
// recovered by iac_sync (never left opening forever); an open PR is updated
// in place when the approved change re-renders differently against a moved
// base, and closed by AuthSec when the source no longer renders it; the
// mapped repository must be selected by its discovery source and the
// installation must be the verified integration's; a J2 target without a
// source is 409 iac_source_missing and a process without the PR adapter is
// 503 iac_unavailable (never a silent export); export refuses an expired
// approval. Everything runs through the real services, Postgres and
// iacpr.Fake. Prefixed p3x.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/iacpr"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// p3xApproved is an approved iac_pr apply of ExclRole (exclusive customer
// boundary narrowed in place) with its queued deployment.
func p3xApproved(t *testing.T, name string) (*p3iLab, string, uuid.UUID) {
	l := newP3iLab(t, name)
	excl := l.role("ExclRole", "AROAEXCLROLE0002", p3iReport())
	team := l.customerPolicy("TeamBoundary", p3iTeamDoc, roleUse("ExclRole", "AROAEXCLROLE0002", igagov.UsageBoundary))
	l.setBoundary(excl, team)
	l.publish()
	l.mapSource(iacpr.FormatTerraform, "iam", map[string]string{"iam/main.tf": p3iTF(p3iTeamDoc)})
	l.grantWrite()
	policy, _ := l.propose(igagov.DeliveryIaCPR, "AROAEXCLROLE0002")
	l.approveAll(policy, 1)
	return l, policy, l.deploy(policy, 1, "apply")
}

func (l *p3iLab) p3xEvents(name string, dep uuid.UUID) int64 {
	return l.count(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = ? AND deployment_id = ?`, l.ws, name, dep)
}

func (l *p3iLab) p3xSync(change uuid.UUID) error {
	return l.delivery.SyncHandler(context.Background(), l.run(repositories.GovJobIaCSync, change))
}

// P2: the process dies between POST git/refs and POST pulls. The commit was
// recorded (proposed_sha, iac.pr_step) before the branch was created; the
// change stays `opening` and is scheduled; iac_sync resumes it: the branch
// is reused (no second commit or branch) and only the PR is created.
func TestP3IaCFixCrashBetweenRefAndPullIsRecovered(t *testing.T) {
	l, _, dep := p3xApproved(t, "p3x-crash")
	l.gh.CrashAfter[iacpr.StepRef] = true
	_, err := l.delivery.Deliver(context.Background(), l.run(repositories.GovJobDeploy, dep), l.ws, dep)
	if !errors.Is(err, iacpr.ErrInjectedCrash) {
		t.Fatalf("deliver: %v", err)
	}
	ch := l.change(dep)
	branch := "authsec/" + dep.String()
	if ch.State != "opening" || ch.PRNumber != nil || ch.ProposedSHA == "" || ch.ProposedSHA != l.gh.Head(l.repo, branch) ||
		l.gh.PRCount(l.repo) != 0 || l.dep(dep).State != "queued" {
		t.Fatalf("after the crash: change %+v head %s PRs %d dep %s", ch, l.gh.Head(l.repo, branch), l.gh.PRCount(l.repo), l.dep(dep).State)
	}
	if l.p3xEvents(services.GovEventIaCPRStep, dep) < 1 {
		t.Fatal("the intent before the branch write was not recorded")
	}
	jobs, err := services.DefaultPolicyJobSchedules()[1].Due(context.Background(), l.db, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	scheduled := false
	for _, j := range jobs {
		scheduled = scheduled || (j.SubjectID != nil && *j.SubjectID == ch.ID)
	}
	if !scheduled {
		t.Fatal("the opening change is not scheduled for iac_sync")
	}
	if err := l.p3xSync(ch.ID); err != nil {
		t.Fatalf("iac_sync recovery: %v", err)
	}
	ch2 := l.change(dep)
	if ch2.State != "open" || ch2.PRNumber == nil || ch2.ProposedSHA != ch.ProposedSHA || l.gh.PRCount(l.repo) != 1 ||
		l.gh.Calls["CreateRef"] != 1 || l.gh.Calls["CreatePull"] != 1 || l.dep(dep).State != "awaiting_merge" {
		t.Fatalf("recovered: change %+v PRs %d calls %v dep %s", ch2, l.gh.PRCount(l.repo), l.gh.Calls, l.dep(dep).State)
	}
	if l.p3xEvents(services.GovEventIaCPROpened, dep) != 1 {
		t.Fatal("pr_opened not recorded once")
	}
}

// P2: a branch AuthSec did not create is never reused (blocked, change
// failed); an `opening` change that cannot be opened for 24 h fails the
// deployment instead of holding the role forever.
func TestP3IaCFixOpeningNeverForever(t *testing.T) {
	l, _, dep := p3xApproved(t, "p3x-conflict")
	l.gh.Seed(l.repo, "authsec/"+dep.String(), map[string]string{"iam/main.tf": "# someone else's branch\n"})
	out := l.deliver(dep)
	if out.State != "blocked" || !strings.HasPrefix(out.Reason, "iac_branch_conflict") || l.change(dep).State != "failed" || l.gh.PRCount(l.repo) != 0 {
		t.Fatalf("branch conflict: %+v change %s", out, l.change(dep).State)
	}

}

func TestP3IaCFixOpeningTimesOut(t *testing.T) {
	l2, _, dep2 := p3xApproved(t, "p3x-timeout")
	l2.gh.Fail["OpenPullRequest"] = errors.New("github: 502 bad gateway")
	if _, err := l2.delivery.Deliver(context.Background(), l2.run(repositories.GovJobDeploy, dep2), l2.ws, dep2); err == nil {
		t.Fatal("deliver succeeded")
	}
	ch := l2.change(dep2)
	// Within the limit, iac_sync retries (the error is returned, nothing failed).
	l2.gh.Fail["OpenPullRequest"] = errors.New("github: 502 bad gateway")
	if err := l2.p3xSync(ch.ID); err == nil || l2.change(dep2).State != "opening" || l2.dep(dep2).State != "queued" {
		t.Fatalf("within the limit: %v %s %s", err, l2.change(dep2).State, l2.dep(dep2).State)
	}
	l2.clock = l2.clock.Add(services.GovIaCOpeningLimit + time.Hour)
	l2.gh.Fail["OpenPullRequest"] = errors.New("github: 502 bad gateway")
	if err := l2.p3xSync(ch.ID); err != nil {
		t.Fatalf("past the limit: %v", err)
	}
	if d := l2.dep(dep2); d.State != "failed" || !strings.HasPrefix(d.StateReason, "pr_open_failed") || l2.change(dep2).State != "failed" ||
		l2.p3xEvents(services.GovEventIaCOpenFailed, dep2) != 1 {
		t.Fatalf("past the limit: %s %q change %s", d.State, d.StateReason, l2.change(dep2).State)
	}
}

// P2: the PR update path. The base branch moves under an open PR: iac_sync
// re-renders the approved change on the new base and updates the SAME PR
// (new head recorded as proposed_sha, not "changed after review"); a second
// sync changes nothing. When the source stops rendering the approved change,
// AuthSec closes its PR with the reason and the deployment is blocked.
func TestP3IaCFixOpenPRIsUpdatedOrClosed(t *testing.T) {
	l, _, dep := p3xApproved(t, "p3x-update")
	out := l.deliver(dep)
	if out.State != "awaiting_merge" {
		t.Fatalf("deliver %+v", out)
	}
	first := l.change(dep)
	tf, _ := l.gh.File(l.repo, "main", "iam/main.tf")
	l.gh.Seed(l.repo, "main", map[string]string{"iam/main.tf": "# Owned by the platform team.\n" + tf})
	if err := l.p3xSync(first.ID); err != nil {
		t.Fatal(err)
	}
	ch := l.change(dep)
	prTF, _ := l.gh.PRFile(l.repo, *first.PRNumber, "iam/main.tf")
	if ch.State != "open" || ch.ProposedSHA == first.ProposedSHA || ch.ProposedSHA != l.gh.Head(l.repo, first.Branch) ||
		l.gh.PRCount(l.repo) != 1 || !strings.HasPrefix(prTF, "# Owned by the platform team.\n") ||
		l.p3xEvents(services.GovEventIaCPRUpdated, dep) != 1 {
		t.Fatalf("update: change %+v PRs %d events %d\n%s", ch, l.gh.PRCount(l.repo), l.p3xEvents(services.GovEventIaCPRUpdated, dep), prTF)
	}
	if !strings.Contains(prTF, "aws:RequestedRegion") || strings.Contains(p3iPolicyDoc(t, prTF, "team"), "sqs") {
		t.Fatalf("the updated PR does not carry the approved narrowing:\n%s", prTF)
	}
	if err := l.p3xSync(first.ID); err != nil {
		t.Fatal(err)
	}
	if l.p3xEvents(services.GovEventIaCPRUpdated, dep) != 1 || l.change(dep).State != "open" {
		t.Fatal("an unchanged rendering updated the PR again")
	}
	// The customer rewrites the boundary in the source: the approved change
	// no longer renders; AuthSec closes its PR and blocks.
	broken := strings.Replace(tf, `"Sid": "NoIAM"`, `"Sid": "NoIAMChanged"`, 1)
	if broken == tf {
		t.Fatal("test source not edited")
	}
	l.gh.Seed(l.repo, "main", map[string]string{"iam/main.tf": broken})
	if err := l.p3xSync(first.ID); err != nil {
		t.Fatal(err)
	}
	if d := l.dep(dep); d.State != "blocked" || !strings.HasPrefix(d.StateReason, services.IaCReasonFormChanged) || l.change(dep).State != "closed" ||
		l.gh.PRState(l.repo, *first.PRNumber) != "closed" || len(l.gh.PRComments(l.repo, *first.PRNumber)) != 1 ||
		l.p3xEvents(services.GovEventIaCPRSuperseded, dep) != 1 {
		t.Fatalf("close: %s %q change %s PR %s", d.State, d.StateReason, l.change(dep).State, l.gh.PRState(l.repo, *first.PRNumber))
	}
}

// P2 IaC source checks.
func TestP3IaCFixSourceChecks(t *testing.T) {
	l := newP3iLab(t, "p3x-sources")
	// One iac_pr proposal for UseRole, compiled again under each condition (a
	// refused compile writes nothing, so the version stays a draft).
	l.roleAndPublish("UseRole", "AROAUSEROLE0001")
	code, body := l.call(l.author, http.MethodPost, "/proposals", map[string]any{"template": "right_size_services",
		"keys": []any{map[string]any{"provider": "aws", "role_id": "AROAUSEROLE0001"}}, "delivery": igagov.DeliveryIaCPR})
	pol := l.must(code, body, http.StatusCreated, "POST /proposals")["policy"].(map[string]any)["id"].(string)
	proposeCode := func(string) (int, map[string]any) {
		return l.call(l.author, http.MethodPost, "/policies/"+pol+"/versions/1/propose", nil)
	}
	// No IaC source for a J2 target: a visible 409, not a silent export
	// (export stays an explicit choice: TestP3IaCFixExportRefusesExpiredApproval).
	if code, body := proposeCode(igagov.DeliveryIaCPR); code != http.StatusConflict || digs(body, "error", "code") != services.GovCodeIaCSourceMissing {
		t.Fatalf("no source: %d %v", code, body)
	}

	// The repository must be one the discovery source selects.
	l.gh.Seed(l.repo, "main", map[string]string{"iam/main.tf": "# empty\n"})
	p3exec(t, l.db, `UPDATE discovery_sources SET config = config || '{"repositories":{"mode":"selected","include":["acme/other"]}}'::jsonb WHERE id = ?`, l.ds)
	base := "/aws/connectors/" + l.a.conn.String() + "/iac-sources"
	src := map[string]any{"format": "terraform", "discovery_source_id": l.ds.String(), "repository": l.repo, "directory": "iam"}
	if code, body := l.discCall(http.MethodPost, base, l.author, "governance:enforce", src); code != http.StatusUnprocessableEntity ||
		digs(body, "error", "code") != services.GovCodeIaCRepoNotSelected {
		t.Fatalf("unselected repository mapped: %d %v", code, body)
	}
	p3exec(t, l.db, `UPDATE discovery_sources SET config = jsonb_set(config, '{repositories,include}', to_jsonb(ARRAY['acme/other', ?::text])) WHERE id = ?`,
		strings.ToUpper(l.repo), l.ds)
	code, body = l.discCall(http.MethodPost, base, l.author, "governance:enforce", src)
	l.must(code, body, http.StatusCreated, "selected repository")
	l.grantWrite()
	// Deselected later: compile refuses visibly.
	p3exec(t, l.db, `UPDATE discovery_sources SET config = jsonb_set(config, '{repositories,include}', '["acme/other"]'::jsonb) WHERE id = ?`, l.ds)
	if code, body := proposeCode(igagov.DeliveryIaCPR); code != http.StatusConflict || digs(body, "error", "code") != services.GovCodeIaCRepoNotSelected {
		t.Fatalf("deselected repository: %d %v", code, body)
	}
	p3exec(t, l.db, `UPDATE discovery_sources SET config = config || '{"repositories":{"mode":"all"}}'::jsonb WHERE id = ?`, l.ds)

	// The token's installation must be the verified integration's.
	var inst string
	l.db.Raw(`SELECT installation_id FROM iga_integrations WHERE id = ?`, l.integ).Scan(&inst)
	p3exec(t, l.db, `UPDATE iga_integrations SET installation_id = 'other-installation' WHERE id = ?`, l.integ)
	if code, body := proposeCode(igagov.DeliveryIaCPR); code != http.StatusConflict || digs(body, "error", "code") != services.GovCodeIaCInstallUnverified ||
		digs(body, "error", "detail", "reason") != "installation_mismatch" {
		t.Fatalf("installation mismatch: %d %v", code, body)
	}
	p3exec(t, l.db, `UPDATE iga_integrations SET installation_id = ?, status = 'disconnected', verified_at = NULL WHERE id = ?`, inst, l.integ)
	if code, body := proposeCode(igagov.DeliveryIaCPR); code != http.StatusConflict || digs(body, "error", "detail", "reason") != "integration_not_verified" {
		t.Fatalf("unverified integration: %d %v", code, body)
	}
	p3exec(t, l.db, `UPDATE iga_integrations SET status = 'active', verified_at = now() WHERE id = ?`, l.integ)

	// GitHub Enterprise Server: the verified integration's host is the API host.
	p3exec(t, l.db, `UPDATE iga_integrations SET provider_host = 'ghe.acme.test' WHERE id = ?`, l.integ)
	var row models.IGAGovIaCSource
	if err := l.db.Where("workspace_id = ?", l.ws).Take(&row).Error; err != nil {
		t.Fatal(err)
	}
	ref, err := services.IaCRepoRef(l.db, l.ws, row)
	if err != nil || ref.ProviderHost != "ghe.acme.test" || iacpr.APIBase(ref.ProviderHost, "") != "https://ghe.acme.test/api/v3" || ref.InstallationID != inst {
		t.Fatalf("GHES repo ref %+v %v", ref, err)
	}

	// AUTHSEC_DISABLE_POLICY_WORKER (no PR adapter in this process): 503,
	// never a silent export.
	services.SetGovIaCGitHub(nil)
	if code, body := proposeCode(igagov.DeliveryIaCPR); code != http.StatusServiceUnavailable || digs(body, "error", "code") != services.GovCodeIaCUnavailable {
		t.Fatalf("no adapter: %d %v", code, body)
	}
	services.SetGovIaCGitHub(l.gh)
}

// P2: export refuses an expired approval exactly as a deployment does.
func TestP3IaCFixExportRefusesExpiredApproval(t *testing.T) {
	l := newP3iLab(t, "p3x-export")
	pol, _ := l.propose(igagov.DeliveryExport, l.roleAndPublish("UseRole", "AROAUSEROLE0001"))
	l.approveAll(pol, 1)
	path := fmt.Sprintf("/policies/%s/versions/1/export", pol)
	if code, body := l.call(l.author, http.MethodGet, path, nil); code != http.StatusOK {
		t.Fatalf("export: %d %v", code, body)
	}
	// The approval's lifetime ends (clock moved past expires_at).
	p3exec(t, l.db, `UPDATE iga_gov_approval SET expires_at = now() - interval '1 minute' WHERE workspace_id = ? AND version_id = ?`, l.ws, l.versionID(pol, 1))
	if code, body := l.call(l.author, http.MethodGet, path, nil); code != http.StatusConflict || digs(body, "error", "code") != services.GovCodeApprovalExpired {
		t.Fatalf("expired approval exported: %d %v", code, body)
	}
}
