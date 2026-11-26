package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// Access policies on a Secrets Manager secret (block only): the secret is
// picked through its ARN or a "<name>-??????" selector row, the document
// denies every secret of that name in the account, the deployment runs on the
// same job as S3 and DynamoDB, an allow is refused, and the name must be
// listed by the last complete scan of the secret's account and region.

// secretScan publishes a scan of the lab's connector whose Secrets Manager
// coverage for region is state, listing arns.
func (l *apLab) secretScan(region, state string, arns ...string) {
	l.t.Helper()
	run := uuid.New()
	p3exec(l.t, l.db, `INSERT INTO cloud_scan_run (id, workspace_id, connector_id, generation, status, published_at)
		VALUES (?, ?, ?, (SELECT COALESCE(max(generation), 0) + 1 FROM cloud_scan_run WHERE workspace_id = ? AND connector_id = ?), 'published', now())`,
		run, l.ws, l.conn.ID, l.ws, l.conn.ID)
	reason := ""
	if state != "complete" {
		reason = "test"
	}
	p3exec(l.t, l.db, `INSERT INTO cloud_resource_policy_coverage (workspace_id, connector_id, scan_run_id, resource_form, region, state,
		enumerated, read_ok, reason) VALUES (?, ?, ?, 'secretsmanager_secret', ?, ?, ?, ?, ?)`,
		l.ws, l.conn.ID, run, region, state, len(arns), len(arns), reason)
	for _, a := range arns {
		p3exec(l.t, l.db, `INSERT INTO cloud_resource_policy_observation (workspace_id, scan_run_id, resource_form, region, resource_arn,
			policy_present, read_at) VALUES (?, ?, 'secretsmanager_secret', ?, ?, false, now())`, l.ws, run, region, a)
	}
}

func secretARN(acct, name string) string {
	return "arn:aws:secretsmanager:us-east-1:" + acct + ":secret:" + name
}

func TestAccessPolicySecretsManagerLifecycle(t *testing.T) {
	l := newAPLab(t)
	ctx := context.Background()
	reader := l.role("SecretReader")
	l.secretScan("us-east-1", "complete", secretARN(testAccount, "prod/db-AbCdEf"), secretARN(testAccount, "prod/dbx-AbCdEf"))
	sel := l.resourceOf(secretARN(testAccount, "prod/db-??????"), "selector", &l.conn.ID)
	end := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	in := igagov.AccessIntent{Effect: "block", Resource: igagov.AccessResource{ResourceID: sel.String()},
		Roles: []igagov.AccessRole{{IdentityAccountID: reader.String()}}, Access: []string{"read"}, EndsAt: &end}

	pv, err := l.svc.Preview(ctx, l.ws, in)
	if err != nil || len(pv.Blockers) != 0 || len(pv.Documents) != 1 ||
		!strings.Contains(pv.Sentence, "Block read on Secrets Manager secret prod/db (us-east-1, account "+testAccount+")") {
		t.Fatalf("preview: %+v %v", pv, err)
	}
	exact := igagov.SecretTarget{Partition: "aws", Region: "us-east-1", Account: testAccount, Secret: "prod/db", Suffix: "AbCdEf"}
	want, _, _, _, err := igagov.AccessDocument("block", []string{"read"}, exact, nil, &end)
	if err != nil || string(pv.Documents[0].Document) != string(want) {
		t.Fatalf("preview document:\n got %s\nwant %s (%v)", pv.Documents[0].Document, want, err)
	}
	var codes []string
	for _, w := range pv.Warnings {
		codes = append(codes, w.Code)
	}
	if got := strings.Join(codes, ","); got != "read_copies_blocked,value_check_not_covered,copies_not_covered,same_name_covered,other_paths" {
		t.Fatalf("warnings: %s", got)
	}

	v, err := l.svc.Create(ctx, l.ws, l.user, services.AccessPolicyRequest{AccessIntent: in, Name: "Block db secret", Reason: "incident 9"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	l.run(v.ID)
	att := l.attachedAuthSec("SecretReader")
	if len(att) != 1 || !strings.HasSuffix(att[0], "-v1") {
		t.Fatalf("attached: %v", att)
	}
	_, _, doc, tags, ok := l.fake.PolicyState(att[0])
	if !ok || doc != string(want) || tags["authsec:policy"] != v.ID.String() {
		t.Fatalf("policy in AWS: %s %v", doc, tags)
	}
	if v, err = l.svc.Get(ctx, l.ws, v.ID); err != nil || v.Status != services.AccessStatusActive {
		t.Fatalf("after apply: %+v %v", v, err)
	}
	if r := v.Resource; r.ResourceType != igagov.AccessTypeSecretsManagerSecret || r.Name != "prod/db" || r.Region != "us-east-1" ||
		r.AccountID != testAccount || r.Kind != "selector" || r.Bucket != "" {
		t.Fatalf("resource view: %+v", r)
	}

	// Detached by hand: the next check re-attaches it.
	r2 := services.NewGovR2(l.db)
	var row models.IGAGovTempGrant
	l.db.Where("workspace_id = ? AND policy_arn = ? AND state = ?", l.ws, att[0], models.R2StateActive).Take(&row)
	l.fake.Detach("SecretReader", att[0])
	l.runRow(r2, row.ID)
	if got := l.attachedAuthSec("SecretReader"); len(got) != 1 {
		t.Fatalf("not re-applied: %v", got)
	}

	// Edit to block write and delete: version 2 adds the overwrite statement.
	in.Access = []string{"write", "delete"}
	if v, err = l.svc.Edit(ctx, l.ws, l.user, v.ID, services.AccessPolicyRequest{AccessIntent: in, Name: "Block db secret",
		Reason: "writes too", BaseVersionNo: 1}); err != nil {
		t.Fatalf("edit: %v", err)
	}
	l.run(v.ID)
	att = l.attachedAuthSec("SecretReader")
	if len(att) != 1 || !strings.HasSuffix(att[0], "-v2") {
		t.Fatalf("after edit: %v", att)
	}
	_, _, doc, _, _ = l.fake.PolicyState(att[0])
	if !strings.Contains(doc, `"AuthSecAccessOverwrite"`) || strings.Contains(doc, "GetSecretValue") {
		t.Fatalf("v2 document: %s", doc)
	}
	// An edit to an allow is refused.
	allow := in
	allow.Effect = "allow"
	if _, err := l.svc.Edit(ctx, l.ws, l.user, v.ID, services.AccessPolicyRequest{AccessIntent: allow, Name: "Block db secret",
		Reason: "allow", BaseVersionNo: 2}); apCode(err) != services.GovCodeAccessInvalid {
		t.Fatalf("edit to allow: %v", err)
	}

	if _, err := l.svc.End(ctx, l.ws, l.user, v.ID, services.AccessReasonRequest{Reason: "done"}); err != nil {
		t.Fatal(err)
	}
	l.run(v.ID)
	if v, _ = l.svc.Get(ctx, l.ws, v.ID); v.Status != services.AccessStatusEnded || len(l.attachedAuthSec("SecretReader")) != 0 {
		t.Fatalf("ended: %s %v", v.Status, l.attachedAuthSec("SecretReader"))
	}
	for _, d := range v.Deployments {
		if _, _, _, _, ok := l.fake.PolicyState(d.AWSPolicyARN); ok {
			t.Errorf("%s still exists", d.AWSPolicyARN)
		}
	}
}

func TestAccessPolicySecretsManagerRefusals(t *testing.T) {
	l := newAPLab(t)
	ctx := context.Background()
	role := l.role("SecretRefusedRole")
	l.secretScan("us-east-1", "complete", secretARN(testAccount, "prod/db-AbCdEf"))
	db := l.resourceOf(secretARN(testAccount, "prod/db-AbCdEf"), "secretsmanager_secret", &l.conn.ID)
	star := l.resourceOf(secretARN(testAccount, "prod/db-*"), "selector", &l.conn.ID)
	all := l.resourceOf(secretARN(testAccount, "*"), "selector", &l.conn.ID)
	partial := l.resourceOf(secretARN(testAccount, "prod/db"), "selector", &l.conn.ID)
	misread := l.resourceOf(secretARN(testAccount, "prod/db-backup"), "selector", &l.conn.ID)
	gone := l.resourceOf(secretARN(testAccount, "old/db-AbCdEf"), "secretsmanager_secret", &l.conn.ID)
	stale := l.resourceOf(secretARN(testAccount, "stale-AbCdEf"), "secretsmanager_secret", nil)
	end := time.Now().Add(time.Hour)
	intent := func(effect string, res uuid.UUID, access ...string) igagov.AccessIntent {
		return igagov.AccessIntent{Effect: effect, Resource: igagov.AccessResource{ResourceID: res.String()},
			Roles: []igagov.AccessRole{{IdentityAccountID: role.String()}}, Access: access, EndsAt: &end}
	}
	withPrefix := intent("block", db, "read")
	withPrefix.Resource.Prefix = "x/"
	for _, c := range []struct {
		name string
		in   igagov.AccessIntent
		code string
	}{
		{"a prefix on a secret", withPrefix, services.GovCodeAccessInvalid},
		{"a name pattern", intent("block", star, "read"), services.GovCodeResourceNotSupported},
		{"every secret", intent("block", all, "read"), services.GovCodeResourceNotSupported},
		{"an ARN without the suffix", intent("block", partial, "read"), services.GovCodeResourceNotSupported},
		{"an allow", intent("allow", db, "read"), services.GovCodeAccessInvalid},
		{"allow all", intent("allow", db, "all"), services.GovCodeAccessInvalid},
		{"a secret no current scan sees", intent("block", stale, "read"), services.GovCodeResourceNotCurrent},
		{"a name the complete scan does not list", intent("block", gone, "read"), services.GovCodeResourceNotCurrent},
		{"a partial ARN read as a shorter name", intent("block", misread, "read"), services.GovCodeResourceNotCurrent},
	} {
		if got := previewCode(l.svc.Preview(ctx, l.ws, c.in)); got != c.code {
			t.Errorf("%s: preview %s, want %s", c.name, got, c.code)
		}
		if _, err := l.svc.Create(ctx, l.ws, l.user, services.AccessPolicyRequest{AccessIntent: c.in, Name: "r " + uuid.NewString()[:8], Reason: "t"}); apCode(err) != c.code {
			t.Errorf("%s: create %v, want %s", c.name, err, c.code)
		}
	}
	var n int64
	l.db.Model(&models.IGAGovPolicy{}).Where("workspace_id = ? AND family = 'time_bound'", l.ws).Count(&n)
	if n != 0 {
		t.Fatalf("refusals stored %d policies", n)
	}

	// A region without a complete scan: the block passes with a warning.
	west := l.resourceOf("arn:aws:secretsmanager:us-west-2:"+testAccount+":secret:app-AbCdEf", "secretsmanager_secret", &l.conn.ID)
	l.secretScan("us-west-2", "partial")
	pv, err := l.svc.Preview(ctx, l.ws, intent("block", west, "read"))
	if err != nil || len(pv.Blockers) != 0 || !hasWarning(pv, services.GovCodeExistenceNotVerified) {
		t.Fatalf("unverified region: %+v %v", pv, err)
	}
	// Another account's secret (no scan of that account): a block passes,
	// unverified; an allow is refused.
	theirs := l.resourceOf(secretARN("111122223333", "theirs-AbCdEf"), "secretsmanager_secret", &l.conn.ID)
	pv, err = l.svc.Preview(ctx, l.ws, intent("block", theirs, "read"))
	if err != nil || len(pv.Blockers) != 0 || !strings.Contains(pv.Sentence, "account 111122223333") || !hasWarning(pv, services.GovCodeExistenceNotVerified) {
		t.Fatalf("cross-account block: %+v %v", pv, err)
	}

	// Another workspace's secret row and policy are 404.
	other := p3NewGov(t, l.db, "sm-other")
	foreign := uuid.New()
	p3exec(t, l.db, `INSERT INTO iga_resources (id, workspace_id, resource_kind, display_name, provider, source_key)
		VALUES (?, ?, 'secretsmanager_secret', ?, 'aws', ?)`, foreign, other.ws, secretARN(testAccount, "prod/db-AbCdEf"), "aws\x1fref\x1fforeign-sm")
	if got := previewCode(l.svc.Preview(ctx, l.ws, intent("block", foreign, "read"))); got != services.GovCodeResourceNotFound {
		t.Errorf("another workspace's secret, preview: %s", got)
	}
	if _, err := l.svc.Create(ctx, l.ws, l.user, services.AccessPolicyRequest{AccessIntent: intent("block", foreign, "read"), Name: "x", Reason: "t"}); apCode(err) != services.GovCodeResourceNotFound {
		t.Errorf("another workspace's secret, create: %v", err)
	}
	pid := uuid.New()
	p3exec(t, l.db, `INSERT INTO iga_gov_policy (id, workspace_id, name, family, provider, created_by) VALUES (?, ?, 'theirs', 'time_bound', 'aws', ?)`,
		pid, other.ws, other.author)
	if _, err := l.svc.Get(ctx, l.ws, pid); apCode(err) != "not_found" {
		t.Errorf("another workspace's policy, get: %v", err)
	}
	if _, err := l.svc.End(ctx, l.ws, l.user, pid, services.AccessReasonRequest{Reason: "x"}); apCode(err) != "not_found" {
		t.Errorf("another workspace's policy, end: %v", err)
	}
	if list, _, err := l.svc.List(ctx, l.ws, services.AccessListQuery{}); err != nil || len(list) != 0 {
		t.Errorf("list shows another workspace's policy: %v %v", list, err)
	}
}

func hasWarning(pv *services.AccessPreview, code string) bool {
	for _, w := range pv.Warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}
