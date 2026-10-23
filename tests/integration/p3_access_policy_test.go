package integration

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/internal/awsenforce/enforcetest"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// Access policies (decision 2026-10-13): an admin blocks or allows roles on
// an S3 bucket; AuthSec attaches an AuthSec-owned policy per role and keeps
// it in place. Over the fake AWS account with a verified template v2
// binding: create and apply (no approver), readback, an edit that leaves no
// gap, pause and resume, re-apply after a detach outside AuthSec, end, the
// quota and account refusals, and another workspace's 404.

type apLab struct {
	*dLab
	svc      *services.GovAccess
	bucket   uuid.UUID
	foreign  uuid.UUID // a bucket only another account's scan names
	identity map[string]uuid.UUID
}

func newAPLab(t *testing.T) *apLab {
	t.Helper()
	d := newDLab(t)
	// Gates: IGA_POLICY (verified), then R2.
	pg := services.NewPolicyGate(true, p3GraphOn(t, d.db))
	if err := pg.Verify(d.db); err != nil {
		t.Fatal(err)
	}
	prevP := services.PolicyGateState()
	services.SetPolicyGate(pg)
	r2 := services.NewPolicyR2Gate(true)
	if err := r2.Verify(d.db); err != nil {
		t.Fatalf("R2 gate: %v (the integration database must be at 137)", err)
	}
	prevR2 := services.PolicyR2GateState()
	services.SetPolicyR2Gate(r2)
	prevEnv := currentEnvForTest()
	services.SetGovDeployEnv(d.env)
	t.Cleanup(func() {
		services.SetGovDeployEnv(prevEnv)
		services.SetPolicyR2Gate(prevR2)
		services.SetPolicyGate(prevP)
	})
	if ok, why := services.AccessPoliciesStatus(d.db); !ok {
		t.Fatalf("access policies unavailable: %s", why)
	}

	// The account's stack on template v2 (attach / detach under /authsec/),
	// and the binding's self-test proving the grants capabilities.
	// (The fake cannot parse v2's Fn::If sections; its one statement access
	// policies use is added to the v1 policy as the v2 template writes it.)
	d.fake.Policy.Statements = append(d.fake.Policy.Statements, enforcetest.Statement{Sid: "AttachOnlyAuthSecPolicies", Effect: "Allow",
		Action:    []string{"iam:AttachRolePolicy", "iam:DetachRolePolicy"},
		Resource:  []string{"arn:aws:iam::" + testAccount + ":role/*"},
		Condition: map[string]map[string][]string{"ArnLike": {"iam:PolicyARN": {"arn:aws:iam::" + testAccount + ":policy/authsec/*"}}}})
	caps := `{}`
	for i, c := range awsenforce.V2CapabilitiesFor(awsenforce.FeatureTemporaryGrants) {
		sep := ","
		if i == 0 {
			caps = "{"
			sep = ""
		}
		caps += sep + `"` + c + `":{"status":"ok","checked_at":"2026-10-14T00:00:00Z"}`
	}
	caps += "}"
	p3exec(t, d.db, `UPDATE cloud_enforcement_binding SET template_version = ?, capabilities = capabilities || ?::jsonb
		WHERE workspace_id = ? AND connector_id = ?`, awsdiscovery.EnforcementTemplateVersionV2, caps, d.ws, d.conn.ID)

	l := &apLab{dLab: d, svc: services.NewGovAccess(d.db), identity: map[string]uuid.UUID{}}
	l.bucket = l.resource("arn:aws:s3:::acme-invoices", &d.conn.ID)
	l.foreign = l.resource("arn:aws:s3:::someone-elses-bucket", nil)
	return l
}

func currentEnvForTest() services.GovDeployEnv { return services.GovDeployEnv{} }

// resource inserts an S3 bucket resource, named by conn's scan when set.
func (l *apLab) resource(arn string, conn *uuid.UUID) uuid.UUID {
	l.t.Helper()
	return l.resourceOf(arn, "s3_bucket", conn)
}

// resourceOf inserts a Discovery resource of kind, named by conn's scan when set.
func (l *apLab) resourceOf(arn, kind string, conn *uuid.UUID) uuid.UUID {
	l.t.Helper()
	id := uuid.New()
	p3exec(l.t, l.db, `INSERT INTO iga_resources (id, workspace_id, resource_kind, display_name, provider, source_key)
		VALUES (?, ?, ?, ?, 'aws', ?)`, id, l.ws, kind, arn, "aws\x1fref\x1f"+arn+"\x1f"+id.String())
	if conn != nil {
		p3exec(l.t, l.db, `INSERT INTO iga_object_support (workspace_id, resource_id, connector_id, partition_key, state)
			VALUES (?, ?, ?, ?, 'current')`, l.ws, id, *conn, "aws:"+testAccount)
	}
	return id
}

// role adds a role to the fake account and its Discovery identity.
func (l *apLab) role(name string) uuid.UUID {
	l.t.Helper()
	r := l.fake.AddRole(name, "/", nil)
	id := uuid.New()
	arn := l.fake.RoleARNOf(r)
	p3exec(l.t, l.db, `INSERT INTO iga_identity_accounts (id, workspace_id, account_kind, provider, source_key, continuity, immutable_key, display_name, provider_attrs)
		VALUES (?, ?, ?, 'aws', ?, 'immutable', ?, ?, '{"path":"/"}'::jsonb)`,
		id, l.ws, models.CloudIdentityIAMRole, "aws\x1fidentity\x1f"+arn, r.RoleID, name)
	l.identity[name] = id
	return id
}

// run drives every open deployment row of the policy through its temp_grant
// job until none moves (each run is one claimed job, as the worker runs it).
func (l *apLab) run(policy uuid.UUID) {
	l.t.Helper()
	r2 := services.NewGovR2(l.db)
	for pass := 0; pass < 8; pass++ {
		var rows []models.IGAGovTempGrant
		if err := l.db.Where("workspace_id = ? AND policy_id = ? AND state IN ?", l.ws, policy,
			[]string{models.R2StateApproved, models.R2StateDeploying, models.R2StateExpiring, models.R2StateOutcomeUnknown}).
			Find(&rows).Error; err != nil {
			l.t.Fatal(err)
		}
		if len(rows) == 0 {
			return
		}
		for _, g := range rows {
			l.runRow(r2, g.ID)
		}
	}
	l.t.Fatalf("deployments of %s did not settle", policy)
}

// check runs one job of an active row (the 10-minute drift check).
func (l *apLab) runRow(r2 *services.GovR2, id uuid.UUID) error {
	l.t.Helper()
	repo := repositories.NewIGAGovJobRepository(l.db)
	p3exec(l.t, l.db, `UPDATE iga_gov_job SET status = 'complete', completed_at = now(), lease_owner = '', lease_expires_at = NULL
		WHERE workspace_id = ? AND kind = 'temp_grant' AND status IN ('queued','running')`, l.ws)
	sub := id
	if _, err := repo.EnqueueTx(l.db, &models.IGAGovJob{WorkspaceID: l.ws, Kind: repositories.GovJobTempGrant, SubjectID: &sub,
		DedupeKey: "temporary_grant:" + id.String(), RunAfter: time.Now().Add(-time.Hour)}); err != nil {
		l.t.Fatal(err)
	}
	j := p3ClaimOwn(l.t, l.db, l.ws, "worker-ap", 2*time.Minute, time.Now(), repositories.GovJobTempGrant)
	if j == nil {
		l.t.Fatalf("no temp_grant job for %s", id)
	}
	err := r2.TempGrantHandler(context.Background(), services.NewPolicyJobRun(l.db, *j, "worker-ap"))
	p3exec(l.t, l.db, `UPDATE iga_gov_job SET status = 'complete', completed_at = now(), lease_owner = '', lease_expires_at = NULL
		WHERE id = ? AND status = 'running'`, j.ID)
	if err != nil && !isRetryLater(err) {
		l.t.Fatalf("temp_grant %s: %v", id, err)
	}
	return err
}

func (l *apLab) attachedAuthSec(role string) []string {
	var out []string
	for _, a := range l.fake.AttachedOf(role) {
		if strings.Contains(a, ":policy/authsec/AuthSecAccess-") {
			out = append(out, a)
		}
	}
	return out
}

func apCode(err error) string {
	var ge *services.GovError
	if errors.As(err, &ge) {
		return ge.Code
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestAccessPolicyLifecycle(t *testing.T) {
	l := newAPLab(t)
	ctx := context.Background()
	a := l.role("ApInvoiceReader")
	b := l.role("ApBatchJob")
	end := time.Now().Add(time.Hour)

	intent := igagov.AccessIntent{Effect: "block", Resource: igagov.AccessResource{ResourceID: l.bucket.String(), Prefix: "invoices/"},
		Roles: []igagov.AccessRole{{IdentityAccountID: a.String()}}, Access: []string{"read"}, EndsAt: &end}

	// Preview stores nothing and shows the sentence and the document.
	pv, err := l.svc.Preview(ctx, l.ws, intent)
	if err != nil || len(pv.Blockers) != 0 || !strings.Contains(pv.Sentence, "Block read on s3://acme-invoices/invoices/*") ||
		len(pv.Documents) != 1 || !strings.Contains(string(pv.Documents[0].Document), `"Effect":"Deny"`) {
		t.Fatalf("preview: %+v %v", pv, err)
	}
	var n int64
	l.db.Model(&models.IGAGovPolicy{}).Where("workspace_id = ? AND family = 'time_bound'", l.ws).Count(&n)
	if n != 0 {
		t.Fatalf("preview stored %d policies", n)
	}
	// The warnings, exactly and in order: an allow, a block of a folder
	// (and of one too long to guard every fragment), a block of writes.
	const (
		allowNeeds  = "If the bucket is in another AWS account, its bucket policy must allow the role as well."
		listRoot    = "To keep the folder's keys from being listed, these roles also cannot list the bucket root or a prefix that starts like the folder."
		listPartial = "The folder name is too long to block listing of every leading fragment of it; a list request for a short fragment of the name is not blocked."
		otherPaths  = "This changes only the chosen roles. Other roles, users, groups and bucket policies are unchanged."
	)
	allowIn := intent
	allowIn.Effect, allowIn.Resource.Prefix = "allow", ""
	longIn := intent
	longIn.Resource.Prefix = strings.Repeat("abcdefghij", 5) + "_reports_/"
	writeIn := intent
	writeIn.Access = []string{"write"}
	for _, c := range []struct {
		name string
		in   igagov.AccessIntent
		pv   *services.AccessPreview
		want []services.AccessIssue
	}{
		{"block read folder", intent, pv, []services.AccessIssue{{Code: "list_root_blocked", Message: listRoot}, {Code: "other_paths", Message: otherPaths}}},
		{"allow read bucket", allowIn, nil, []services.AccessIssue{{Code: "allow_needs_bucket_policy", Message: allowNeeds}, {Code: "other_paths", Message: otherPaths}}},
		{"block read long folder", longIn, nil, []services.AccessIssue{{Code: "list_root_blocked", Message: listRoot},
			{Code: "list_partial_prefix", Message: listPartial}, {Code: "other_paths", Message: otherPaths}}},
		{"block write folder", writeIn, nil, []services.AccessIssue{{Code: "other_paths", Message: otherPaths}}},
	} {
		got := c.pv
		if got == nil {
			if got, err = l.svc.Preview(ctx, l.ws, c.in); err != nil || len(got.Blockers) != 0 {
				t.Fatalf("%s preview: %+v %v", c.name, got, err)
			}
		}
		if !reflect.DeepEqual(got.Warnings, c.want) {
			t.Errorf("%s warnings:\n got %+v\nwant %+v", c.name, got.Warnings, c.want)
		}
	}

	// Create and apply: no approver; the job attaches and verifies.
	v, err := l.svc.Create(ctx, l.ws, l.user, services.AccessPolicyRequest{AccessIntent: intent, Name: "Block invoice reads", Reason: "incident 42"})
	if err != nil || v.Status != services.AccessStatusApplying || v.VersionNo != 1 {
		t.Fatalf("create: %+v %v", v, err)
	}
	if _, err := l.svc.Create(ctx, l.ws, l.user, services.AccessPolicyRequest{AccessIntent: intent, Name: "Block invoice reads", Reason: "again"}); apCode(err) != services.GovCodeNameTaken {
		t.Fatalf("duplicate name: %v", err)
	}
	l.run(v.ID)
	if got := l.attachedAuthSec("ApInvoiceReader"); len(got) != 1 || !strings.HasSuffix(got[0], "-v1") {
		t.Fatalf("attached after apply: %v", got)
	}
	_, _, doc, tags, ok := l.fake.PolicyState(l.attachedAuthSec("ApInvoiceReader")[0])
	if !ok || !strings.Contains(doc, `"Effect":"Deny"`) || !strings.Contains(doc, "acme-invoices/invoices/*") ||
		tags["authsec:policy"] != v.ID.String() || tags["authsec:managed-by"] == "" {
		t.Fatalf("policy in AWS: %s %v", doc, tags)
	}
	if v, err = l.svc.Get(ctx, l.ws, v.ID); err != nil || v.Status != services.AccessStatusActive || v.Deployments[0].VerifiedAt == nil {
		t.Fatalf("after apply: %+v %v", v, err)
	}
	if r := v.Resource; r.ResourceType != "s3_bucket" || r.Bucket == "" || r.Name != r.Bucket || r.Region != "" || r.Provider != "aws" {
		t.Fatalf("S3 resource view: %+v", r)
	}

	// Edit: version 2 (read + write, both roles) is attached before version
	// 1 is removed, so access never comes back in between.
	intent.Access = []string{"read", "write"}
	intent.Roles = append(intent.Roles, igagov.AccessRole{IdentityAccountID: b.String()})
	if _, err := l.svc.Edit(ctx, l.ws, l.user, v.ID, services.AccessPolicyRequest{AccessIntent: intent, Name: "Block invoice reads",
		Reason: "widen", BaseVersionNo: 0}); apCode(err) != services.GovCodeVersionConflict {
		t.Fatalf("stale edit: %v", err)
	}
	v, err = l.svc.Edit(ctx, l.ws, l.user, v.ID, services.AccessPolicyRequest{AccessIntent: intent, Name: "Block invoice reads",
		Reason: "widen", BaseVersionNo: 1})
	if err != nil || v.VersionNo != 2 {
		t.Fatalf("edit: %+v %v", v, err)
	}
	r2 := services.NewGovR2(l.db)
	var v2rows []models.IGAGovTempGrant
	l.db.Where("workspace_id = ? AND policy_id = ? AND state = ?", l.ws, v.ID, models.R2StateApproved).Find(&v2rows)
	for _, g := range v2rows {
		l.runRow(r2, g.ID) // deploy
		l.runRow(r2, g.ID) // verify (present)
	}
	if got := l.attachedAuthSec("ApInvoiceReader"); len(got) != 2 {
		t.Fatalf("both versions should be attached during the switch: %v", got)
	}
	l.run(v.ID)
	if got := l.attachedAuthSec("ApInvoiceReader"); len(got) != 1 || !strings.HasSuffix(got[0], "-v2") {
		t.Fatalf("after edit: %v", got)
	}
	if got := l.attachedAuthSec("ApBatchJob"); len(got) != 1 {
		t.Fatalf("second role after edit: %v", got)
	}

	// Drift: detached by hand -> re-applied by the next check.
	arn := l.attachedAuthSec("ApInvoiceReader")[0]
	l.fake.Detach("ApInvoiceReader", arn)
	var row models.IGAGovTempGrant
	l.db.Where("workspace_id = ? AND policy_arn = ? AND state = ?", l.ws, arn, models.R2StateActive).Take(&row)
	l.runRow(r2, row.ID)
	if got := l.attachedAuthSec("ApInvoiceReader"); len(got) != 1 {
		t.Fatalf("not re-applied: %v", got)
	}
	evs, _ := l.svc.Events(ctx, l.ws, v.ID)
	seen := map[string]bool{}
	for _, e := range evs {
		seen[e.Event] = true
	}
	for _, want := range []string{services.GovEventAccessCreated, services.GovEventAccessApplied, services.GovEventAccessConfirmed,
		services.GovEventAccessEdited, services.GovEventAccessRemoved, services.GovEventAccessDrifted, services.GovEventAccessReapplied} {
		if !seen[want] {
			t.Errorf("event %s missing (have %v)", want, seen)
		}
	}

	// Pause removes it; Resume puts it back.
	if v, err = l.svc.Pause(ctx, l.ws, l.user, v.ID, services.AccessReasonRequest{Reason: "maintenance"}); err != nil {
		t.Fatal(err)
	}
	l.run(v.ID)
	if got := append(l.attachedAuthSec("ApInvoiceReader"), l.attachedAuthSec("ApBatchJob")...); len(got) != 0 {
		t.Fatalf("still attached after pause: %v", got)
	}
	if v, _ = l.svc.Get(ctx, l.ws, v.ID); v.Status != services.AccessStatusPaused {
		t.Fatalf("paused: %s", v.Status)
	}
	if v, err = l.svc.Resume(ctx, l.ws, l.user, v.ID, services.AccessReasonRequest{Reason: "back"}); err != nil {
		t.Fatal(err)
	}
	l.run(v.ID)
	if v, _ = l.svc.Get(ctx, l.ws, v.ID); v.Status != services.AccessStatusActive || len(l.attachedAuthSec("ApBatchJob")) != 1 {
		t.Fatalf("resumed: %s %v", v.Status, l.attachedAuthSec("ApBatchJob"))
	}

	// End removes it for good and keeps the record.
	if v, err = l.svc.End(ctx, l.ws, l.user, v.ID, services.AccessReasonRequest{Reason: "incident closed"}); err != nil {
		t.Fatal(err)
	}
	l.run(v.ID)
	if v, _ = l.svc.Get(ctx, l.ws, v.ID); v.Status != services.AccessStatusEnded || len(l.attachedAuthSec("ApInvoiceReader")) != 0 {
		t.Fatalf("ended: %s %v", v.Status, l.attachedAuthSec("ApInvoiceReader"))
	}
	if _, err := l.svc.Pause(ctx, l.ws, l.user, v.ID, services.AccessReasonRequest{Reason: "x"}); apCode(err) != services.GovCodePolicyEnded {
		t.Fatalf("pause after end: %v", err)
	}
	// The ended AWS policies are deleted.
	for _, d := range v.Deployments {
		if _, _, _, _, ok := l.fake.PolicyState(d.AWSPolicyARN); ok {
			t.Errorf("%s still exists", d.AWSPolicyARN)
		}
	}
}

func TestAccessPolicyRefusals(t *testing.T) {
	l := newAPLab(t)
	ctx := context.Background()
	a := l.role("ApRefusedRole")
	end := time.Now().Add(time.Hour)
	base := func() igagov.AccessIntent {
		return igagov.AccessIntent{Effect: "allow", Resource: igagov.AccessResource{ResourceID: l.bucket.String()},
			Roles: []igagov.AccessRole{{IdentityAccountID: a.String()}}, Access: []string{"read"}, EndsAt: &end}
	}
	req := func(in igagov.AccessIntent) services.AccessPolicyRequest {
		return services.AccessPolicyRequest{AccessIntent: in, Name: "refusal " + uuid.NewString()[:8], Reason: "test"}
	}
	in := base()
	in.EndsAt = nil
	if _, err := l.svc.Create(ctx, l.ws, l.user, req(in)); apCode(err) != services.GovCodeAccessInvalid {
		t.Errorf("allow without end: %v", err)
	}
	in = base()
	in.Access = []string{"all"}
	if _, err := l.svc.Create(ctx, l.ws, l.user, req(in)); apCode(err) != services.GovCodeAccessInvalid {
		t.Errorf("allow all: %v", err)
	}
	in = base()
	in.Resource.ResourceID = l.foreign.String()
	if _, err := l.svc.Create(ctx, l.ws, l.user, req(in)); apCode(err) != services.GovCodeRoleNotInAccount {
		t.Errorf("bucket not seen in the role's account: %v", err)
	}
	in = base()
	in.Resource.ResourceID = uuid.NewString()
	if _, err := l.svc.Create(ctx, l.ws, l.user, req(in)); apCode(err) != services.GovCodeResourceNotFound {
		t.Errorf("unknown resource: %v", err)
	}
	// Ten managed policies attached: refused before anything is written.
	for i := 0; i < 10; i++ {
		p := l.fake.AddPolicy("/", "Filler"+uuid.NewString()[:6], nil, `{"Version":"2012-10-17","Statement":[]}`)
		l.fake.AttachPermissions("ApRefusedRole", p.ARN)
	}
	if _, err := l.svc.Create(ctx, l.ws, l.user, req(base())); apCode(err) != services.GovCodeRolePolicyQuota {
		t.Errorf("quota: %v", err)
	}
	// A template v1 binding refuses.
	p3exec(t, l.db, `UPDATE cloud_enforcement_binding SET template_version = ? WHERE workspace_id = ? AND connector_id = ?`,
		awsdiscovery.EnforcementTemplateVersion, l.ws, l.conn.ID)
	pv, err := l.svc.Preview(ctx, l.ws, base())
	if err != nil || len(pv.Blockers) == 0 || pv.Blockers[0].Code != services.GovCodeBindingTemplateV1 {
		t.Errorf("v1 binding: %+v %v", pv, err)
	}
	var n int64
	l.db.Model(&models.IGAGovPolicy{}).Where("workspace_id = ? AND family = 'time_bound'", l.ws).Count(&n)
	if n != 0 {
		t.Errorf("refusals stored %d policies", n)
	}

	// Another workspace's policy is 404 on every read and write.
	other := p3NewGov(t, l.db, "ap-other")
	pid := uuid.New()
	p3exec(t, l.db, `INSERT INTO iga_gov_policy (id, workspace_id, name, family, provider, created_by) VALUES (?, ?, 'theirs', 'time_bound', 'aws', ?)`,
		pid, other.ws, other.author)
	if _, err := l.svc.Get(ctx, l.ws, pid); apCode(err) != "not_found" {
		t.Errorf("cross-workspace get: %v", err)
	}
	if _, err := l.svc.End(ctx, l.ws, l.user, pid, services.AccessReasonRequest{Reason: "x"}); apCode(err) != "not_found" {
		t.Errorf("cross-workspace end: %v", err)
	}
	if _, err := l.svc.Events(ctx, l.ws, pid); apCode(err) != "not_found" {
		t.Errorf("cross-workspace events: %v", err)
	}
	if list, _, err := l.svc.List(ctx, l.ws, services.AccessListQuery{}); err != nil || len(list) != 0 {
		t.Errorf("list shows another workspace's policy: %v %v", list, err)
	}
}

// Admin ownership mode: the owner gate passes and no owner review opens.
func TestOwnershipAdminMode(t *testing.T) {
	restore := services.SetGovOwnershipMode(services.GovOwnershipAdmin)
	defer restore()
	if services.GovOwnershipEnabled() {
		t.Fatal("admin mode still runs the owner flow")
	}
	h := services.GovAdminModeAuthoringHooks()
	if h.OwnerGate == nil || h.OwnerGate(nil, services.GovApprovalCheck{}) != nil {
		t.Fatal("the admin-mode owner gate must exist and pass")
	}
	if h.OnProposed == nil || h.OnProposed(nil, services.GovProposedVersion{}) != nil {
		t.Fatal("the admin-mode OnProposed must be a no-op")
	}
}

// End takes effect now: an active row's open job (the 10-minute check,
// queued for later) is pulled forward instead of the removal waiting for it.
func TestAccessPolicyEndRunsNow(t *testing.T) {
	l := newAPLab(t)
	ctx := context.Background()
	a := l.role("ApEndNowRole")
	end := time.Now().Add(time.Hour)
	v, err := l.svc.Create(ctx, l.ws, l.user, services.AccessPolicyRequest{Name: "end now", Reason: "test",
		AccessIntent: igagov.AccessIntent{Effect: "block", Resource: igagov.AccessResource{ResourceID: l.bucket.String()},
			Roles: []igagov.AccessRole{{IdentityAccountID: a.String()}}, Access: []string{"read"}, EndsAt: &end}})
	if err != nil {
		t.Fatal(err)
	}
	l.run(v.ID)
	var row models.IGAGovTempGrant
	if err := l.db.Where("workspace_id = ? AND policy_id = ?", l.ws, v.ID).Take(&row).Error; err != nil {
		t.Fatal(err)
	}
	// What the worker leaves behind for an active row: its job, queued for the next check.
	p3exec(t, l.db, `UPDATE iga_gov_job SET status = 'complete', completed_at = now() WHERE workspace_id = ? AND kind = 'temp_grant' AND status IN ('queued','running')`, l.ws)
	p3exec(t, l.db, `INSERT INTO iga_gov_job (workspace_id, kind, subject_id, dedupe_key, status, run_after, max_attempts)
		VALUES (?, 'temp_grant', ?, ?, 'queued', now() + interval '10 minutes', 5)`, l.ws, row.ID, "temporary_grant:"+row.ID.String())
	if _, err := l.svc.End(ctx, l.ws, l.user, v.ID, services.AccessReasonRequest{Reason: "done"}); err != nil {
		t.Fatal(err)
	}
	var late int64
	l.db.Model(&models.IGAGovJob{}).Where("workspace_id = ? AND kind = 'temp_grant' AND subject_id = ? AND status = 'queued' AND run_after > now() + interval '1 minute'",
		l.ws, row.ID).Count(&late)
	if late != 0 {
		t.Fatal("End left the removal waiting for the next 10-minute check")
	}
}

// A deployment that fails after attaching is taken out of AWS before it ends
// failed. Before, a policy whose AuthSec document was changed outside AuthSec
// failed its re-apply and stayed attached to the role for good: a failed row
// is never worked again, and End, Pause and Delete skip it.
func TestAccessPolicyFailedRowIsRemoved(t *testing.T) {
	l := newAPLab(t)
	ctx := context.Background()
	a := l.role("ApEditedOutside")
	end := time.Now().Add(time.Hour)
	v, err := l.svc.Create(ctx, l.ws, l.user, services.AccessPolicyRequest{Name: "edited outside", Reason: "t",
		AccessIntent: igagov.AccessIntent{Effect: "block", Resource: igagov.AccessResource{ResourceID: l.bucket.String()},
			Roles: []igagov.AccessRole{{IdentityAccountID: a.String()}}, Access: []string{"read"}, EndsAt: &end}})
	if err != nil {
		t.Fatal(err)
	}
	l.run(v.ID)
	att := l.attachedAuthSec("ApEditedOutside")
	if len(att) != 1 {
		t.Fatalf("attached: %v", att)
	}
	// Someone rewrites AuthSec's policy (a new default version).
	l.fake.SetDefaultDocument(att[0], `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`)
	var row models.IGAGovTempGrant
	l.db.Where("workspace_id = ? AND policy_arn = ?", l.ws, att[0]).Take(&row)
	l.runRow(services.NewGovR2(l.db), row.ID)

	if got := l.attachedAuthSec("ApEditedOutside"); len(got) != 0 {
		t.Fatalf("the failed deployment's policy is still attached: %v", got)
	}
	l.db.Where("workspace_id = ? AND id = ?", l.ws, row.ID).Take(&row)
	if row.State != models.R2StateFailed || !strings.Contains(row.StateReason, "document_changed") || row.Drift != services.R2ReasonDocumentChanged {
		t.Fatalf("row: state %s, reason %q, drift %q", row.State, row.StateReason, row.Drift)
	}
	// The edited policy holds versions AuthSec did not write: it is left in
	// place, detached, for its owner.
	if _, _, _, _, ok := l.fake.PolicyState(att[0]); !ok {
		t.Fatal("a policy with versions AuthSec did not write was deleted")
	}
}

// End during a re-apply: the job notices the row moved and runs again at once
// to remove the policy, instead of re-scheduling the 10-minute check with the
// policy just put back on the role.
func TestAccessPolicyEndDuringReapply(t *testing.T) {
	l := newAPLab(t)
	ctx := context.Background()
	a := l.role("ApEndRace")
	end := time.Now().Add(time.Hour)
	v, err := l.svc.Create(ctx, l.ws, l.user, services.AccessPolicyRequest{Name: "end race", Reason: "t",
		AccessIntent: igagov.AccessIntent{Effect: "block", Resource: igagov.AccessResource{ResourceID: l.bucket.String()},
			Roles: []igagov.AccessRole{{IdentityAccountID: a.String()}}, Access: []string{"read"}, EndsAt: &end}})
	if err != nil {
		t.Fatal(err)
	}
	l.run(v.ID)
	arn := l.attachedAuthSec("ApEndRace")[0]
	var row models.IGAGovTempGrant
	l.db.Where("workspace_id = ? AND policy_arn = ?", l.ws, arn).Take(&row)
	l.fake.Detach("ApEndRace", arn)
	// The admin ends the policy while the re-apply's attach is in flight.
	l.fake.AfterApply["iam:AttachRolePolicy"] = func(context.Context) error {
		delete(l.fake.AfterApply, "iam:AttachRolePolicy")
		_, err := l.svc.End(ctx, l.ws, l.user, v.ID, services.AccessReasonRequest{Reason: "now"})
		return err
	}
	err = l.runRow(services.NewGovR2(l.db), row.ID)
	if err == nil || !strings.Contains(err.Error(), "state moved") {
		t.Fatalf("the re-apply after End answered %v; want an immediate rerun", err)
	}
	l.run(v.ID)
	if got := l.attachedAuthSec("ApEndRace"); len(got) != 0 {
		t.Fatalf("still attached after End: %v", got)
	}
}

// Another workspace's policy is 404 on every write too (Edit, Pause, Resume,
// Delete, End), and is left as it was; a preview naming another workspace's
// role is refused as not found.
func TestAccessPolicyCrossWorkspaceWrites(t *testing.T) {
	l := newAPLab(t)
	ctx := context.Background()
	mine := l.role("ApMineRole")
	end := time.Now().Add(time.Hour)
	in := igagov.AccessIntent{Effect: "block", Resource: igagov.AccessResource{ResourceID: l.bucket.String()},
		Roles: []igagov.AccessRole{{IdentityAccountID: mine.String()}}, Access: []string{"read"}, EndsAt: &end}

	other := p3NewGov(t, l.db, "ap-other-writes")
	pid := uuid.New()
	p3exec(t, l.db, `INSERT INTO iga_gov_policy (id, workspace_id, name, family, provider, created_by, lifecycle) VALUES (?, ?, 'theirs', 'time_bound', 'aws', ?, 'active')`,
		pid, other.ws, other.author)
	notFound := func(name string, err error) {
		t.Helper()
		var ge *services.GovError
		if !errors.As(err, &ge) || ge.Status != 404 {
			t.Errorf("%s on another workspace's policy: %v, want 404", name, err)
		}
	}
	_, err := l.svc.Edit(ctx, l.ws, l.user, pid, services.AccessPolicyRequest{AccessIntent: in, Name: "mine now", Reason: "x", BaseVersionNo: 1})
	notFound("edit", err)
	_, err = l.svc.Pause(ctx, l.ws, l.user, pid, services.AccessReasonRequest{Reason: "x"})
	notFound("pause", err)
	_, err = l.svc.Resume(ctx, l.ws, l.user, pid, services.AccessReasonRequest{Reason: "x"})
	notFound("resume", err)
	notFound("delete", l.svc.Delete(ctx, l.ws, l.user, pid))
	var pol models.IGAGovPolicy
	if err := l.db.Where("id = ?", pid).Take(&pol).Error; err != nil || pol.Name != "theirs" || pol.Lifecycle != "active" || pol.DeletedAt != nil {
		t.Fatalf("another workspace's policy changed: %+v %v", pol, err)
	}

	// A role of another workspace in my preview: not found, nothing about it shown.
	theirRole := uuid.New()
	p3exec(t, l.db, `INSERT INTO iga_identity_accounts (id, workspace_id, account_kind, provider, source_key, continuity, immutable_key, display_name, provider_attrs)
		VALUES (?, ?, ?, 'aws', ?, 'immutable', ?, 'TheirSecretRole', '{"path":"/"}'::jsonb)`,
		theirRole, other.ws, models.CloudIdentityIAMRole, "aws\x1fidentity\x1farn:aws:iam::111111111111:role/TheirSecretRole", "AROATHEIRS")
	in.Roles = []igagov.AccessRole{{IdentityAccountID: theirRole.String()}}
	pv, err := l.svc.Preview(ctx, l.ws, in)
	code := previewCode(pv, err)
	if code == "" || (pv != nil && strings.Contains(pv.Sentence, "TheirSecretRole")) {
		t.Fatalf("preview with another workspace's role: %q %+v", code, pv)
	}
	if _, err := l.svc.Create(ctx, l.ws, l.user, services.AccessPolicyRequest{AccessIntent: in, Name: "x", Reason: "x"}); err == nil {
		t.Fatal("created a policy on another workspace's role")
	} else {
		var ge *services.GovError
		if !errors.As(err, &ge) || ge.Status != 404 {
			t.Errorf("create with another workspace's role: %v, want 404", err)
		}
	}
}
