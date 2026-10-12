package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// T3.17 (SPEC-iga-phase3-policy.md §1.1 J1/J2, §3.3, §3.4, §7.3, §7.9,
// §8.4, §8.11; scenarios A4, A31, A60, A64): IaC sources and the GitHub
// permission request, the compile-time supported-form decision with its
// fallback to export, PR delivery of structure-preserving narrowing and of
// a split copy, iac_sync (merge, awaiting_apply, deadline, unexpected
// state), export delivery, and undo of a split copy through a revert PR.
//
// Safeguards (mutation-checked, see the report): merge is not apply (merged
// -> awaiting_apply, never applied_unverified); overdue is not failed; a
// conflict fails with the diff; intermediate states are not failures; the
// form decision falls back at compile time; the precondition check blocks an
// undo whose copy gained a user; the permission check holds PR delivery.

const p3iTeamDoc = `{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid": "Compute", "Effect": "Allow", "Action": ["ec2:DescribeP3a", "s3:DescribeP3a", "sqs:DescribeP3a"], "Resource": "*",
     "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}},
    {"Sid": "Queues", "Effect": "Allow", "Action": "sqs:DescribeP3a", "Resource": "arn:aws:sqs:*:*:refunds"},
    {"Sid": "NoIAM", "Effect": "Deny", "Action": "iam:*", "Resource": "*"}
  ]
}`

const p3iNotActionDoc = `{"Version":"2012-10-17","Statement":[{"Sid":"All","Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`

func p3iTF(sharedDocHeredoc string) string {
	trust := `jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole" }] })`
	return `# Roles of the refund platform.
resource "aws_iam_role" "excl" {
  name                 = "ExclRole"
  assume_role_policy   = ` + trust + `
  permissions_boundary = aws_iam_policy.team.arn
}

resource "aws_iam_policy" "team" {
  name   = "TeamBoundary"
  policy = jsonencode(` + p3iTeamDoc + `)
}

resource "aws_iam_role" "shared" {
  name                 = "SharedRole"
  assume_role_policy   = ` + trust + `
  permissions_boundary = aws_iam_policy.shared.arn
}

resource "aws_iam_role" "other" {
  name                 = "OtherRole"
  assume_role_policy   = ` + trust + `
  permissions_boundary = aws_iam_policy.shared.arn
}

resource "aws_iam_policy" "shared" {
  name   = "SharedBoundary"
  policy = <<EOF
` + sharedDocHeredoc + `
EOF
}
`
}

func p3iReport() map[string]*time.Time {
	return map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil, "ec2": nil}
}

// IaC sources (§7.9): validation, the GitHub permission request, the
// envelope, events and audit, 404 for another connector, 403 without
// governance:enforce, and a source with PRs cannot be deleted.
func TestP3T317IaCSourcesAndPermissionRequest(t *testing.T) {
	l := newP3iLab(t, "p3-t317-sources")
	l.gh.Seed(l.repo, "main", map[string]string{"iam/main.tf": "# empty\n"})
	base := "/aws/connectors/" + l.a.conn.String() + "/iac-sources"
	body := map[string]any{"format": "terraform", "discovery_source_id": l.ds.String(), "repository": l.repo, "directory": "iam",
		"role_match": map[string]any{"rules": []any{map[string]any{"role_name": "Refund*", "resource": "aws_iam_role.refund"}}}}

	for name, c := range map[string]struct {
		mut  func(map[string]any)
		code int
	}{
		"bad format":     {func(b map[string]any) { b["format"] = "pulumi" }, http.StatusBadRequest},
		"escape":         {func(b map[string]any) { b["directory"] = "../secrets" }, http.StatusBadRequest},
		"bad repository": {func(b map[string]any) { b["repository"] = "no-slash" }, http.StatusBadRequest},
		"bad role_match": {func(b map[string]any) {
			b["role_match"] = map[string]any{"rules": []any{map[string]any{"role_name": "*x*", "resource": "r"}}}
		}, http.StatusBadRequest},
		"not github": {func(b map[string]any) { b["discovery_source_id"] = uuid.NewString() }, http.StatusUnprocessableEntity},
	} {
		b := map[string]any{}
		for k, v := range body {
			b[k] = v
		}
		c.mut(b)
		if code, resp := l.discCall(http.MethodPost, base, l.author, "governance:enforce", b); code != c.code {
			t.Errorf("%s: %d %v, want %d", name, code, resp, c.code)
		}
	}
	if code, _ := l.discCall(http.MethodPost, base, l.author, "governance:read", body); code != http.StatusForbidden {
		t.Fatalf("without governance:enforce: %d", code)
	}
	if code, _ := l.discCall(http.MethodGet, "/aws/connectors/"+uuid.NewString()+"/iac-sources", l.author, "governance:enforce", nil); code != http.StatusNotFound {
		t.Fatalf("another connector: %d", code)
	}

	code, resp := l.discCall(http.MethodPost, base, l.author, "governance:enforce", body)
	d := l.must(code, resp, http.StatusCreated, "create")
	perm := d["permissions"].(map[string]any)
	if perm["state"] != "pending_grant" || fmt.Sprint(perm["missing"]) != "[contents:write pull_requests:write]" ||
		!strings.Contains(fmt.Sprint(perm["url"]), "/settings/installations/") || perm["requested"] != true {
		t.Fatalf("permissions %v", perm)
	}
	var req string
	l.db.Raw(`SELECT requested_permissions::text FROM iga_integrations WHERE id = ?`, l.integ).Scan(&req)
	if !strings.Contains(req, `"contents": "write"`) || !strings.Contains(req, `"pull_requests": "write"`) || !strings.Contains(req, `"metadata": "read"`) {
		t.Fatalf("requested_permissions %s", req)
	}
	if l.events(services.GovEventIaCSourceCreated) != 1 || l.events(services.GovEventIaCPermissionRequest) != 1 || !l.waitAudits("create_iac_source", 1) {
		t.Fatalf("events %d/%d audits %d", l.events(services.GovEventIaCSourceCreated), l.events(services.GovEventIaCPermissionRequest), l.audits("create_iac_source"))
	}
	// A second source on the same installation does not request again.
	b2 := map[string]any{"format": "cloudformation", "discovery_source_id": l.ds.String(), "repository": l.repo, "directory": "cfn"}
	code, resp = l.discCall(http.MethodPost, base, l.author, "governance:enforce", b2)
	l.must(code, resp, http.StatusCreated, "second source")
	if l.events(services.GovEventIaCPermissionRequest) != 1 {
		t.Fatal("permissions requested twice")
	}
	l.grantWrite()
	code, resp = l.discCall(http.MethodGet, base, l.author, "governance:enforce", nil)
	list := resp["data"].([]any)
	if code != http.StatusOK || len(list) != 2 || dig(list[0], "permissions", "state") != "granted" || resp["meta"] == nil {
		t.Fatalf("list %d %v", code, resp)
	}
	sid := d["id"].(string)
	// In use: a change references it.
	src := uuid.MustParse(sid)
	pol, _ := l.propose(igagov.DeliveryExport, l.roleAndPublish("UseRole", "AROAUSEROLE0001"))
	l.approveAll(pol, 1)
	dep := l.deploy(pol, 1, "apply")
	p3exec(t, l.db, `INSERT INTO iga_gov_iac_change (workspace_id, deployment_id, source_id, branch) VALUES (?, ?, ?, 'b')`, l.ws, dep, src)
	if code, resp := l.discCall(http.MethodDelete, base+"/"+sid, l.author, "governance:enforce", nil); code != http.StatusConflict || digs(resp, "error", "code") != services.GovCodeIaCSourceInUse {
		t.Fatalf("delete in use: %d %v", code, resp)
	}
	p3exec(t, l.db, `DELETE FROM iga_gov_iac_change WHERE deployment_id = ?`, dep)
	if code, _ := l.discCall(http.MethodDelete, base+"/"+sid, l.author, "governance:enforce", nil); code != http.StatusOK {
		t.Fatalf("delete: %d", code)
	}
	if l.events(services.GovEventIaCSourceDeleted) != 1 || !l.waitAudits("delete_iac_source", 1) {
		t.Fatal("delete not recorded")
	}
	if code, _ := l.discCall(http.MethodDelete, base+"/"+sid, l.author, "governance:enforce", nil); code != http.StatusNotFound {
		t.Fatal("second delete not 404")
	}
}

// roleAndPublish adds a role with the standard report and publishes.
func (l *p3iLab) roleAndPublish(name, roleID string) string {
	l.role(name, roleID, p3iReport())
	l.publish()
	return roleID
}

// A4 + A31 + A60 + A64 through PRs: an exclusive customer boundary is
// narrowed in place (Sids, conditions and Deny kept); a shared boundary gets
// a split copy for this role only; a NotAction boundary is ineligible. Merge
// is not apply (held pipeline: awaiting_apply, overdue after the deadline,
// never failed); a hand-edited apply fails unexpected_state with the diff.
// The split copy is applied, then undone through a revert PR: mid-way (role
// re-pointed, copy not yet deleted) is awaiting_apply "1 of 2", the copy's
// deletion completes it, and a pipeline that attaches a third policy fails.
func TestP3T317CustomerBoundaryPRs(t *testing.T) {
	l := newP3iLab(t, "p3-t317-a4")
	excl := l.role("ExclRole", "AROAEXCLROLE0001", p3iReport())
	shared := l.role("SharedRole", "AROASHAREDROLE01", p3iReport())
	team := l.customerPolicy("TeamBoundary", p3iTeamDoc, roleUse("ExclRole", "AROAEXCLROLE0001", igagov.UsageBoundary))
	sh := l.customerPolicy("SharedBoundary", p3iTeamDoc, roleUse("SharedRole", "AROASHAREDROLE01", igagov.UsageBoundary),
		roleUse("OtherRole", "AROAOTHERROLE001", igagov.UsageBoundary))
	l.setBoundary(excl, team)
	l.setBoundary(shared, sh)
	l.publish()
	l.mapSource(iacpr.FormatTerraform, "iam", map[string]string{"iam/main.tf": p3iTF(p3iTeamDoc), "README.md": "infra"})

	// Exclusive: narrowed in place through a PR.
	ep, eplans := l.propose(igagov.DeliveryIaCPR, "AROAEXCLROLE0001")
	ea := p3iPlan(t, eplans, "apply")
	if ea["delivery"] != "iac_pr" || ea["eligibility"] != "iac_only" || ea["desired_boundary_arn"] != team || p3iNotes(ea) != "" {
		t.Fatalf("exclusive apply %v (notes %s)", ea, p3iNotes(ea))
	}
	l.approveAll(ep, 1)
	edep := l.deploy(ep, 1, "apply")
	// The App has not been granted write yet: PR delivery waits.
	if _, err := l.delivery.Deliver(context.Background(), l.run(repositories.GovJobDeploy, edep), l.ws, edep); err == nil ||
		!strings.Contains(err.Error(), services.GovCodeIaCPermissionMissing) {
		t.Fatalf("deliver without write: %v", err)
	}
	if l.dep(edep).State != "queued" || l.gh.PRCount(l.repo) != 0 {
		t.Fatal("a PR was opened without the write grant")
	}
	l.grantWrite()
	out := l.deliver(edep)
	if out.State != "awaiting_merge" || out.PR == nil || l.dep(edep).State != "awaiting_merge" {
		t.Fatalf("deliver: %+v", out)
	}
	ch := l.change(edep)
	if ch.State != "open" || ch.ProposedSHA == "" || *ch.PRNumber != out.PR.Number || ch.Branch != "authsec/"+edep.String() {
		t.Fatalf("iac change %+v", ch)
	}
	// Idempotent: a second deliver opens nothing.
	if again := l.deliver(edep); again.State != "awaiting_merge" || l.gh.PRCount(l.repo) != 1 {
		t.Fatalf("second deliver %+v, %d PRs", again, l.gh.PRCount(l.repo))
	}
	tf, _ := l.gh.PRFile(l.repo, out.PR.Number, "iam/main.tf")
	doc := p3iPolicyDoc(t, tf, "TeamBoundary")
	if h, _ := igagov.DocumentHash(doc); h != ea["desired_document_hash"] {
		t.Fatalf("PR document %s, plan %v\n%s", h, ea["desired_document_hash"], tf)
	}
	for _, want := range []string{`"Sid": "Compute"`, `"aws:RequestedRegion": "us-east-1"`, `"Sid": "NoIAM"`, `"Effect": "Deny"`,
		"# Roles of the refund platform.", `permissions_boundary = aws_iam_policy.team.arn`} {
		if !strings.Contains(tf, want) {
			t.Errorf("PR lost %s", want)
		}
	}
	if tb := p3iBlock(tf, `resource "aws_iam_policy" "team"`); strings.Contains(tb, "sqs:") || strings.Contains(tb, `"Queues"`) || tb == "" {
		t.Errorf("sqs not removed from the boundary:\n%s", tf)
	}
	if title, prBody := l.gh.PRBody(l.repo, out.PR.Number); !strings.Contains(title, "ExclRole") ||
		!strings.Contains(prBody, ea["plan_hash"].(string)) || !strings.Contains(prBody, "Does not change actions or resources within kept services") ||
		!strings.Contains(prBody, "Merging is not applying") {
		t.Fatalf("PR %q\n%s", title, prBody)
	}
	// Review, then the head moves: reviewed_sha kept, changed_after_review.
	l.gh.Approve(l.repo, out.PR.Number)
	l.sync(ch.ID)
	l.gh.PushToPR(l.repo, out.PR.Number, map[string]string{"iam/notes.md": "edited after review"})
	l.sync(ch.ID)
	ch = l.change(edep)
	if ch.ReviewedSHA != out.PR.HeadSHA || ch.State != "changed_after_review" {
		t.Fatalf("review tracking %+v", ch)
	}
	// A31: merge while the pipeline is held -> awaiting_apply, not applied.
	mergedAt := l.clock
	l.gh.Merge(l.repo, out.PR.Number, mergedAt)
	l.gh.AddRun(l.repo, l.gh.Head(l.repo, "main"), iacpr.ApplyRun{Ref: "check_run:77", Name: "terraform apply", Status: "queued"})
	s := l.sync(ch.ID)
	d := l.dep(edep)
	if d.State != "awaiting_apply" || s.Class == nil || s.Class.Class != igagov.ClassBefore || d.ApplyDeadlineAt == nil ||
		!d.ApplyDeadlineAt.Equal(mergedAt.Add(24*time.Hour).Truncate(time.Microsecond)) {
		t.Fatalf("after merge: %s %v %+v", d.State, d.ApplyDeadlineAt, s.Class)
	}
	ch = l.change(edep)
	if ch.State != "merged" || ch.MergedSHA == "" || ch.MergedAt == nil || ch.ApplyRunRef != "check_run:77" {
		t.Fatalf("merged change %+v", ch)
	}
	if o, ev := l.verification(edep); o != "awaiting_evidence" || ev["summary"] != "0 of 1 changes visible in AWS" {
		t.Fatalf("verification %s %v", o, ev)
	}
	// Past the deadline: overdue, still awaiting_apply, never failed.
	l.clock = l.clock.Add(25 * time.Hour)
	if o := l.observe(edep); o.State != "awaiting_apply" || !o.Overdue {
		t.Fatalf("overdue: %+v", o)
	}
	if o, _ := l.verification(edep); o != "overdue" || l.dep(edep).State != "awaiting_apply" || !strings.Contains(l.dep(edep).StateReason, "overdue") {
		t.Fatalf("overdue verification %s, deployment %s", o, l.dep(edep).State)
	}
	// The pipeline applies a hand-edited document: failed unexpected_state
	// with the diff.
	edited := strings.Replace(p3iTeamDoc, `"sqs:DescribeP3a"],`, `"sqs:DescribeP3a", "kms:Decrypt"],`, 1)
	l.livePolicy(team, &igagov.LivePolicy{ARN: team, Path: "/", Name: "TeamBoundary", Tags: map[string]string{}, DefaultDocument: edited,
		VersionCount: 2, AttachmentSet: []igagov.AttachedEntity{roleUse("ExclRole", "AROAEXCLROLE0001", igagov.UsageBoundary)}})
	o := l.observe(edep)
	if o.State != "failed" || !strings.HasPrefix(l.dep(edep).StateReason, services.IaCReasonUnexpected) || o.Class.Class != igagov.ClassConflict ||
		len(o.Class.Conflicts) != 1 || o.Class.Conflicts[0].Kind != igagov.FactPolicyDocument {
		t.Fatalf("hand-edited apply: %+v / %+v", o, o.Class)
	}
	if v, ev := l.verification(edep); v != "failed" || len(ev["conflicts"].([]any)) != 1 {
		t.Fatalf("diff not recorded: %s %v", v, ev)
	}
	if !p3iHas(l.depEvents(edep), services.GovEventIaCUnexpected) || l.change(edep).State != "applied" {
		t.Fatal("unexpected_state not recorded")
	}

	// Shared: a split copy for this role only.
	sp, splans := l.propose(igagov.DeliveryIaCPR, "AROASHAREDROLE01")
	sa := p3iPlan(t, splans, "apply")
	copyARN := sh + "-AROASHAREDROLE01"
	if sa["delivery"] != "iac_pr" || sa["desired_boundary_arn"] != copyARN || sa["replaced_boundary_arn"] != sh {
		t.Fatalf("shared apply %v", sa)
	}
	l.approveAll(sp, 1)
	sdep := l.deploy(sp, 1, "apply")
	sout := l.deliver(sdep)
	stf, _ := l.gh.PRFile(l.repo, sout.PR.Number, "iam/main.tf")
	base, _ := l.gh.File(l.repo, "main", "iam/main.tf")
	if !strings.Contains(stf, `name   = "SharedBoundary-AROASHAREDROLE01"`) ||
		!strings.Contains(p3iBlock(stf, `resource "aws_iam_role" "shared"`), "permissions_boundary = aws_iam_policy.sharedboundary_aroasharedrole01.arn") {
		t.Fatalf("split PR:\n%s", stf)
	}
	for _, unchanged := range []string{`resource "aws_iam_policy" "shared"`, `resource "aws_iam_role" "other"`} {
		if p3iBlock(stf, unchanged) != p3iBlock(base, unchanged) || p3iBlock(base, unchanged) == "" {
			t.Fatalf("%s changed by the split PR", unchanged)
		}
	}
	if h, _ := igagov.DocumentHash(p3iPolicyDoc(t, stf, "SharedBoundary-AROASHAREDROLE01")); h != sa["desired_document_hash"] {
		t.Fatal("copy document is not the plan's")
	}
	l.gh.Merge(l.repo, sout.PR.Number, l.clock)
	l.sync(l.change(sdep).ID)
	// The pipeline applies the split exactly.
	narrowed := p3iDocByHash(t, l, sa["desired_document_hash"].(string))
	l.livePolicy(copyARN, &igagov.LivePolicy{ARN: copyARN, Path: "/", Name: "SharedBoundary-AROASHAREDROLE01", Tags: map[string]string{},
		DefaultDocument: narrowed, VersionCount: 1, AttachmentSet: []igagov.AttachedEntity{roleUse("SharedRole", "AROASHAREDROLE01", igagov.UsageBoundary)}})
	l.livePolicy(sh, &igagov.LivePolicy{ARN: sh, Path: "/", Name: "SharedBoundary", Tags: map[string]string{}, DefaultDocument: p3iTeamDoc,
		VersionCount: 1, AttachmentSet: []igagov.AttachedEntity{roleUse("OtherRole", "AROAOTHERROLE001", igagov.UsageBoundary)}})
	l.setBoundary(shared, copyARN)
	if o := l.observe(sdep); o.State != "applied_unverified" {
		t.Fatalf("split applied: %+v %+v", o, o.Class)
	}
	d = l.dep(sdep)
	if d.AppliedAt == nil || d.VerifyDeadlineAt == nil || d.StateReason != services.IaCReasonAppliedOut ||
		l.count(`SELECT count(*) FROM iga_gov_job WHERE workspace_id = ? AND kind = 'verify' AND dedupe_key = ?`, l.ws, "deployment:"+sdep.String()) != 1 ||
		l.change(sdep).State != "applied" {
		t.Fatalf("applied_unverified: %+v", d)
	}
	var ledger []string
	l.db.Raw(`SELECT kind || ' ' || native_arn || ' ' || owned_by || ' ' || state FROM iga_gov_artifact WHERE workspace_id = ? AND control_id = ? ORDER BY kind`,
		l.ws, d.ControlID).Scan(&ledger)
	if strings.Join(ledger, ";") != "boundary_attachment "+copyARN+" customer_iac present;boundary_policy "+copyARN+" customer_iac present" {
		t.Fatalf("ledger %v", ledger)
	}
	var msg string
	l.db.Raw(`SELECT payload->>'message' FROM iga_gov_event WHERE deployment_id = ? AND event = ?`, sdep, services.GovEventIaCAppliedOutside).Scan(&msg)
	if msg != "applied outside AuthSec, matched by role, attachment and document hash" {
		t.Fatalf("event %q", msg)
	}
	l.settle(sdep, "verified")

	// A60: undo of the split copy through a revert PR.
	splans = l.plans(sp, 1)
	su := p3iPlan(t, splans, "undo")
	if su["desired_boundary_arn"] != sh || su["replaced_boundary_arn"] != copyARN || su["artifact_disposition"] != "delete" {
		t.Fatalf("undo plan %v", su)
	}
	udep := l.deploy(sp, 1, "undo")
	uout := l.deliver(udep)
	if uout.State != "awaiting_merge" {
		t.Fatalf("undo deliver %+v", uout)
	}
	utf, _ := l.gh.PRFile(l.repo, uout.PR.Number, "iam/main.tf")
	if strings.Contains(utf, "SharedBoundary-AROASHAREDROLE01") ||
		!strings.Contains(p3iBlock(utf, `resource "aws_iam_role" "shared"`), "permissions_boundary = aws_iam_policy.shared.arn") ||
		p3iBlock(utf, `resource "aws_iam_policy" "shared"`) != p3iBlock(base, `resource "aws_iam_policy" "shared"`) {
		t.Fatalf("revert PR:\n%s", utf)
	}
	l.gh.Merge(l.repo, uout.PR.Number, l.clock)
	l.sync(l.change(udep).ID)
	// A64: the pipeline re-points the role and is held before deleting the
	// copy: intermediate, awaiting_apply, not verified and not failed.
	l.setBoundary(shared, sh)
	l.livePolicy(copyARN, &igagov.LivePolicy{ARN: copyARN, Path: "/", Name: "SharedBoundary-AROASHAREDROLE01", Tags: map[string]string{},
		DefaultDocument: narrowed, VersionCount: 1, AttachmentSet: []igagov.AttachedEntity{}})
	l.livePolicy(sh, &igagov.LivePolicy{ARN: sh, Path: "/", Name: "SharedBoundary", Tags: map[string]string{}, DefaultDocument: p3iTeamDoc,
		VersionCount: 1, AttachmentSet: []igagov.AttachedEntity{roleUse("OtherRole", "AROAOTHERROLE001", igagov.UsageBoundary),
			roleUse("SharedRole", "AROASHAREDROLE01", igagov.UsageBoundary)}})
	o = l.observe(udep)
	if o.State != "awaiting_apply" || o.Class.Class != igagov.ClassIntermediate || o.Class.Visible != 1 || o.Class.Total != 2 {
		t.Fatalf("mid-way: %+v %+v", o, o.Class)
	}
	if v, ev := l.verification(udep); v != "awaiting_evidence" || ev["summary"] != "1 of 2 changes visible in AWS" || len(ev["awaited_facts"].([]any)) != 1 {
		t.Fatalf("mid-way verification %s %v", v, ev)
	}
	// The copy is deleted: applied_unverified only now.
	l.livePolicy(copyARN, nil)
	if o := l.observe(udep); o.State != "applied_unverified" {
		t.Fatalf("undo finished: %+v %+v", o, o.Class)
	}
	ledger = nil
	l.db.Raw(`SELECT kind || ' ' || native_arn || ' ' || state FROM iga_gov_artifact WHERE workspace_id = ? AND control_id = ? AND state = 'present' ORDER BY kind`,
		l.ws, d.ControlID).Scan(&ledger)
	if strings.Join(ledger, ";") != "boundary_attachment "+sh+" present;boundary_policy "+sh+" present" {
		t.Fatalf("undo ledger %v", ledger)
	}

	// A64, separately: a pipeline that attaches a third policy fails with
	// the diff. Re-apply (a second version's split) and undo again.
	t.Run("third policy", func(t *testing.T) {
		l.settle(udep, "undone")
		l.setBoundary(shared, copyARN)
		l.livePolicy(copyARN, &igagov.LivePolicy{ARN: copyARN, Path: "/", Name: "SharedBoundary-AROASHAREDROLE01", Tags: map[string]string{},
			DefaultDocument: narrowed, VersionCount: 1, AttachmentSet: []igagov.AttachedEntity{roleUse("SharedRole", "AROASHAREDROLE01", igagov.UsageBoundary)}})
		l.livePolicy(sh, &igagov.LivePolicy{ARN: sh, Path: "/", Name: "SharedBoundary", Tags: map[string]string{}, DefaultDocument: p3iTeamDoc,
			VersionCount: 1, AttachmentSet: []igagov.AttachedEntity{roleUse("OtherRole", "AROAOTHERROLE001", igagov.UsageBoundary)}})
		dep2 := l.deploy(sp, 1, "undo")
		// Export of the same undo has no PR: the customer applies the step list.
		p3exec(t, l.db, `UPDATE iga_gov_deployment SET state = 'awaiting_apply', apply_deadline_at = now() + interval '1 day' WHERE id = ?`, dep2)
		third := l.customerPolicy("PipelineBoundary", p3iTeamDoc, roleUse("SharedRole", "AROASHAREDROLE01", igagov.UsageBoundary))
		l.setBoundary(shared, third)
		o := l.observe(dep2)
		if o.State != "failed" || !strings.HasPrefix(l.dep(dep2).StateReason, services.IaCReasonUnexpected) || o.Class.Conflicts[0].Kind != igagov.FactRoleBoundary ||
			o.Class.Conflicts[0].Observed != third {
			t.Fatalf("third policy: %+v %+v", o, o.Class)
		}
	})

	// A60: if the copy is attached to a third role first, the undo is
	// blocked (artifact_consumers_changed) before any PR, and the role-only
	// recovery is retain_shared.
	t.Run("copy gained a user", func(t *testing.T) {
		l.setBoundary(shared, copyARN)
		l.livePolicy(copyARN, &igagov.LivePolicy{ARN: copyARN, Path: "/", Name: "SharedBoundary-AROASHAREDROLE01", Tags: map[string]string{},
			DefaultDocument: narrowed, VersionCount: 1, AttachmentSet: []igagov.AttachedEntity{roleUse("SharedRole", "AROASHAREDROLE01", igagov.UsageBoundary),
				roleUse("ThirdRole", "AROATHIRDROLE001", igagov.UsageBoundary)}})
		prs := l.gh.PRCount(l.repo)
		dep3 := l.deploy(sp, 1, "undo")
		o := l.deliver(dep3)
		if o.State != "blocked" || o.Reason != igagov.ConflictConsumersChanged || l.dep(dep3).State != "blocked" || l.gh.PRCount(l.repo) != prs {
			t.Fatalf("undo with a third user: %+v", o)
		}
		up, err := services.LoadIGAGovPlan(l.db, l.ws, l.dep(dep3).PlanID)
		if err != nil {
			t.Fatal(err)
		}
		var c models.IGAGovControl
		l.db.Where("id = ?", l.dep(dep3).ControlID).Take(&c)
		live, _ := l.live.ReadRole(context.Background(), services.LiveReadRequest{RoleARN: shared, PolicyARNs: []string{copyARN, sh}})
		var row models.IGAGovPlan
		l.db.Where("id = ?", l.dep(dep3).PlanID).Take(&row)
		var bundle models.IGAGovEvidenceBundle
		l.db.Where("id = ?", row.EvidenceBundleID).Take(&bundle)
		facts, trust, reasons, err := igagov.ParseBundle([]byte(bundle.Canonical), bundle.BundleHash)
		if err != nil {
			t.Fatal(err)
		}
		b := igagov.Bundle{Facts: facts, Canonical: []byte(bundle.Canonical), Hash: bundle.BundleHash, Trust: trust, TrustReasons: reasons}
		rec, err := igagov.CompileRoleOnlyRecovery(igagov.RecoveryInput{Control: igagov.ControlRef{ID: c.ID.String(), PolicyID: c.PolicyID.String(),
			AccountID: c.AccountID, RoleID: c.RoleID, WorkspaceRef: services.GovWorkspaceRef(l.ws)}, Undo: up, UndoneDeploymentID: sdep.String(),
			Live: live, Evidence: igagov.EvidenceRef{Bundle: b, EvidenceRev: row.EvidenceRev, ScanRunID: row.ResourcePolicyScanRunID.String()}})
		if err != nil {
			t.Fatal(err)
		}
		if rec.ArtifactDisposition != igagov.DispositionRetainShared || rec.ReplacedBoundaryARN == nil || *rec.ReplacedBoundaryARN != copyARN {
			t.Fatalf("role-only recovery %+v", rec)
		}
	})
}

// A4: a customer boundary whose Allow uses NotAction cannot be narrowed by
// structure-preserving removal: ineligible (§3.4), whatever the delivery.
// (Its own lab: the Access Advisor fake reads two roles per scan.)
func TestP3T317NotActionBoundaryIneligible(t *testing.T) {
	l := newP3iLab(t, "p3-t317-notaction")
	nota := l.role("NotActRole", "AROANOTACTROLE01", p3iReport())
	nb := l.customerPolicy("NotActBoundary", p3iNotActionDoc, roleUse("NotActRole", "AROANOTACTROLE01", igagov.UsageBoundary))
	l.setBoundary(nota, nb)
	l.publish()
	l.mapSource(iacpr.FormatTerraform, "iam", map[string]string{"iam/main.tf": p3iTF(p3iTeamDoc)})
	code, body := l.call(l.author, http.MethodPost, "/proposals", map[string]any{"template": "right_size_services",
		"keys": []any{map[string]any{"provider": "aws", "role_id": "AROANOTACTROLE01"}}, "delivery": "iac_pr"})
	np := l.must(code, body, http.StatusCreated, "proposal")["policy"].(map[string]any)["id"].(string)
	code, body = l.call(l.author, http.MethodPost, fmt.Sprintf("/policies/%s/versions/1/propose", np), nil)
	if code != http.StatusUnprocessableEntity || !strings.Contains(fmt.Sprint(body), igagov.RefuseNotNarrowable) {
		t.Fatalf("NotAction boundary: %d %v", code, body)
	}
}

// p3iBlock returns a top-level block's text, from its header to the
// closing brace at column 0.
func p3iBlock(src, header string) string {
	i := strings.Index(src, header)
	if i < 0 {
		return ""
	}
	j := strings.Index(src[i:], "\n}\n")
	if j < 0 {
		return src[i:]
	}
	return src[i : i+j+3]
}

// p3iPolicyDoc reads the literal document of the aws_iam_policy named name
// in rendered Terraform (through the same reader the renderer trusts).
func p3iPolicyDoc(t *testing.T, tf, name string) string {
	t.Helper()
	i := strings.Index(tf, `"`+name+`"`)
	if i < 0 {
		t.Fatalf("no policy %s in\n%s", name, tf)
	}
	blkStart := strings.LastIndex(tf[:i], "resource ")
	blk := p3iBlock(tf[blkStart:], tf[blkStart:blkStart+strings.Index(tf[blkStart:], "{")+1])
	p := strings.Index(blk, "policy = ")
	if p < 0 {
		p = strings.Index(blk, "policy   = ")
	}
	expr := strings.TrimSpace(blk[strings.Index(blk[p:], "=")+p+1 : strings.LastIndex(blk, "}")])
	if strings.HasPrefix(expr, "jsonencode(") {
		expr = strings.TrimSuffix(strings.TrimPrefix(expr, "jsonencode("), ")")
	} else if strings.HasPrefix(expr, "<<") {
		lines := strings.Split(expr, "\n")
		expr = strings.Join(lines[1:len(lines)-1], "\n")
	}
	expr = strings.ReplaceAll(expr, "$${", "${")
	var v any
	if err := json.Unmarshal([]byte(expr), &v); err != nil {
		t.Fatalf("policy %s is not JSON: %v\n%s", name, err, expr)
	}
	raw, _ := json.Marshal(v)
	return string(raw)
}

func p3iDocByHash(t *testing.T, l *p3iLab, h string) string {
	t.Helper()
	var docs []string
	l.db.Raw(`SELECT canonical FROM iga_gov_document WHERE workspace_id = ? AND document_hash = ?`, l.ws, h).Scan(&docs)
	if len(docs) != 1 {
		t.Fatalf("document %s not archived", h)
	}
	return docs[0]
}

// A31 (module-defined role) + J1 export + A64 (stepwise apply): a role
// declared inside a registry module is offered export only, with
// iac_form_unsupported, decided at compile time; the export artifact holds
// the document and the AWS CLI / Terraform steps; the export deployment
// awaits the customer's apply, shows "2 of 3 changes visible" while the
// policy exists but is not attached, and reaches applied_unverified when
// the attachment appears.
func TestP3T317ModuleRoleExportAndJ1(t *testing.T) {
	l := newP3iLab(t, "p3-t317-a31")
	roleARN := l.role("ModRole", "AROAMODROLE00001", p3iReport())
	l.publish()
	l.mapSource(iacpr.FormatTerraform, "stack", map[string]string{"stack/main.tf": `module "mod_role" {
  source    = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  version   = "5.30.0"
  role_name = "ModRole"
}
`})
	l.grantWrite()
	policy, plans := l.propose(igagov.DeliveryIaCPR, "AROAMODROLE00001")
	ap := p3iPlan(t, plans, "apply")
	if ap["delivery"] != "export" || !strings.Contains(p3iNotes(ap), "iac_fallback:"+iacpr.ReasonFormUnsupported+": role ModRole is defined inside a module") {
		t.Fatalf("module role: delivery %v notes %s", ap["delivery"], p3iNotes(ap))
	}
	if up := p3iPlan(t, plans, "undo"); up["delivery"] != "export" {
		t.Fatalf("undo delivery %v", up["delivery"])
	}
	// Export before approval: 409.
	if code, body := l.call(l.author, http.MethodGet, "/policies/"+policy+"/versions/1/export", nil); code != http.StatusConflict ||
		digs(body, "error", "code") != services.GovCodeVersionNotApproved {
		t.Fatalf("export before approval: %d %v", code, body)
	}
	l.approveAll(policy, 1)
	dep := l.deploy(policy, 1, "apply")
	out := l.deliver(dep)
	d := l.dep(dep)
	if out.State != "awaiting_apply" || d.State != "awaiting_apply" || d.ApplyDeadlineAt == nil || l.gh.PRCount(l.repo) != 0 ||
		!p3iHas(l.depEvents(dep), services.GovEventExportReady) {
		t.Fatalf("export deliver: %+v %+v", out, d)
	}
	code, body := l.call(l.author, http.MethodGet, "/policies/"+policy+"/versions/1/export", nil)
	ex := l.must(code, body, http.StatusOK, "export")
	var art map[string]any
	for _, x := range ex["plans"].([]any) {
		if x.(map[string]any)["kind"] == "apply" {
			art = x.(map[string]any)
		}
	}
	cli := fmt.Sprint(dig(art, "artifact", "aws_cli"))
	if art["deployment_id"] != dep.String() || !strings.Contains(cli, "aws iam create-policy --policy-name AuthSecBoundary-AROAMODROLE00001 --path /authsec/") ||
		!strings.Contains(cli, "aws iam put-role-permissions-boundary --role-name ModRole") || !strings.Contains(cli, "Key=authsec:change,Value="+dep.String()) ||
		!strings.Contains(digs(art, "artifact", "terraform"), `resource "aws_iam_policy"`) || dig(art, "artifact", "iac_fallback", "reason") != iacpr.ReasonFormUnsupported ||
		len(dig(art, "artifact", "documents").(map[string]any)) != 1 {
		t.Fatalf("export artifact %v", art)
	}
	// The downloadable artifact of one plan.
	req := httptest.NewRequest(http.MethodGet, "/api/iga/v1/policy/policies/"+policy+"/versions/1/export?download="+art["plan_id"].(string), nil)
	req.Header.Set("Authorization", "Bearer "+l.token(l.ws, l.author, p3aAllScopes))
	w := httptest.NewRecorder()
	l.eng.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Disposition"), "attachment") || !strings.Contains(w.Body.String(), "aws_cli") {
		t.Fatalf("download: %d %s %s", w.Code, w.Header().Get("Content-Disposition"), w.Body.String())
	}

	// The customer creates the policy with its tags (as the CLI says) but
	// has not attached it: 2 of 3 changes visible, awaiting_apply.
	arn := ap["desired_boundary_arn"].(string)
	var c models.IGAGovControl
	l.db.Where("id = ?", d.ControlID).Take(&c)
	tags := map[string]string{igagov.TagManagedBy: igagov.TagManagedByValue, igagov.TagWorkspace: services.GovWorkspaceRef(l.ws),
		igagov.TagControl: c.ID.String(), igagov.TagPolicy: c.PolicyID.String(), igagov.TagChange: dep.String()}
	l.livePolicy(arn, &igagov.LivePolicy{ARN: arn, Path: "/authsec/", Name: "AuthSecBoundary-AROAMODROLE00001", Tags: tags,
		DefaultDocument: p3iDocByHash(t, l, ap["desired_document_hash"].(string)), VersionCount: 1, AttachmentSet: []igagov.AttachedEntity{}})
	o := l.observe(dep)
	if o.State != "awaiting_apply" || o.Class.Class != igagov.ClassIntermediate || o.Class.Visible != 2 || o.Class.Total != 3 {
		t.Fatalf("stepwise: %+v %+v", o, o.Class)
	}
	if !strings.Contains(l.dep(dep).StateReason, "2 of 3 changes visible") {
		t.Fatalf("state reason %q", l.dep(dep).StateReason)
	}
	// Observing again changes nothing and writes no second progress event.
	l.observe(dep)
	if n := l.count(`SELECT count(*) FROM iga_gov_event WHERE deployment_id = ? AND event = ?`, dep, services.GovEventIaCApplyPending); n != 1 {
		t.Fatalf("%d progress events", n)
	}
	l.setBoundary(roleARN, arn)
	l.livePolicy(arn, &igagov.LivePolicy{ARN: arn, Path: "/authsec/", Name: "AuthSecBoundary-AROAMODROLE00001", Tags: tags,
		DefaultDocument: p3iDocByHash(t, l, ap["desired_document_hash"].(string)), VersionCount: 1,
		AttachmentSet: []igagov.AttachedEntity{roleUse("ModRole", "AROAMODROLE00001", igagov.UsageBoundary)}})
	if o := l.observe(dep); o.State != "applied_unverified" {
		t.Fatalf("applied: %+v %+v", o, o.Class)
	}
	// The scheduler stops syncing it, and the J1 sync path (subject = the
	// deployment) is a no-op now.
	if err := l.delivery.SyncHandler(context.Background(), l.run(repositories.GovJobIaCSync, dep)); err != nil {
		t.Fatal(err)
	}
	var errNF *services.GovError
	if _, err := l.delivery.ObserveApply(context.Background(), l.run(repositories.GovJobIaCSync, uuid.New()), l.ws, uuid.New()); !errors.As(err, &errNF) {
		t.Fatalf("unknown deployment: %v", err)
	}
}

// A PR closed without merging fails the deployment; the scheduler syncs
// open changes and awaiting_apply exports; another workspace's deployment
// is not found.
func TestP3T317ClosedPRAndScheduling(t *testing.T) {
	l := newP3iLab(t, "p3-t317-closed")
	excl := l.role("ExclRole", "AROAEXCLROLE0002", p3iReport())
	team := l.customerPolicy("TeamBoundary", p3iTeamDoc, roleUse("ExclRole", "AROAEXCLROLE0002", igagov.UsageBoundary))
	l.setBoundary(excl, team)
	l.publish()
	l.mapSource(iacpr.FormatTerraform, "iam", map[string]string{"iam/main.tf": strings.Replace(p3iTF(p3iTeamDoc), `"ExclRole"`, `"ExclRole"`, 1)})
	l.grantWrite()
	policy, _ := l.propose(igagov.DeliveryIaCPR, "AROAEXCLROLE0002")
	l.approveAll(policy, 1)
	dep := l.deploy(policy, 1, "apply")
	out := l.deliver(dep)
	jobs, err := services.DefaultPolicyJobSchedules()[1].Due(context.Background(), l.db, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, j := range jobs {
		found = found || (j.WorkspaceID == l.ws && *j.SubjectID == *out.ChangeID && j.DedupeKey == "iac:"+out.ChangeID.String())
	}
	if !found {
		t.Fatalf("open change not scheduled: %+v", jobs)
	}
	l.gh.Close(l.repo, out.PR.Number)
	if err := l.delivery.SyncHandler(context.Background(), l.run(repositories.GovJobIaCSync, *out.ChangeID)); err != nil {
		t.Fatal(err)
	}
	if d := l.dep(dep); d.State != "failed" || d.StateReason != services.IaCReasonClosed || l.change(dep).State != "closed" {
		t.Fatalf("closed: %+v", d)
	}
	if _, err := l.delivery.Deliver(context.Background(), l.run(repositories.GovJobDeploy, dep), uuid.New(), dep); err == nil {
		t.Fatal("another workspace's deployment was delivered")
	}
}
