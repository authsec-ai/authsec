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

// Access policies on a DynamoDB table, over the same fake account as S3: the
// table is picked through any Discovery row that points at it (here an index
// selector), the document is the table target's, the deployment runs on the
// same job (apply, re-apply after a detach, edit, end), and the account rules
// follow the table ARN: a block may name a table in another account, an
// allow may not.

func TestAccessPolicyDynamoDBLifecycle(t *testing.T) {
	l := newAPLab(t)
	ctx := context.Background()
	reader := l.role("DdbOrdersReader")
	tableARN := "arn:aws:dynamodb:us-east-1:" + testAccount + ":table/orders"
	index := l.resourceOf(tableARN+"/index/*", "selector", &l.conn.ID)
	end := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	in := igagov.AccessIntent{Effect: "block", Resource: igagov.AccessResource{ResourceID: index.String()},
		Roles: []igagov.AccessRole{{IdentityAccountID: reader.String()}}, Access: []string{"read"}, EndsAt: &end}

	pv, err := l.svc.Preview(ctx, l.ws, in)
	if err != nil || len(pv.Blockers) != 0 || len(pv.Documents) != 1 ||
		!strings.Contains(pv.Sentence, "Block read on DynamoDB table orders (us-east-1, account "+testAccount+")") {
		t.Fatalf("preview: %+v %v", pv, err)
	}
	target := igagov.DynamoTableTarget{Partition: "aws", Region: "us-east-1", Account: testAccount, Table: "orders"}
	want, _, _, _, err := igagov.AccessDocument("block", []string{"read"}, target, nil, &end)
	if err != nil || string(pv.Documents[0].Document) != string(want) {
		t.Fatalf("preview document:\n got %s\nwant %s (%v)", pv.Documents[0].Document, want, err)
	}
	var codes []string
	for _, w := range pv.Warnings {
		codes = append(codes, w.Code)
	}
	if got := strings.Join(codes, ","); got != "return_values_blocked,partiql_writes_blocked,condition_failure_values_not_covered,copies_not_covered,other_paths" {
		t.Fatalf("warnings: %s", got)
	}

	v, err := l.svc.Create(ctx, l.ws, l.user, services.AccessPolicyRequest{AccessIntent: in, Name: "Block order reads", Reason: "incident 7"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	l.run(v.ID)
	att := l.attachedAuthSec("DdbOrdersReader")
	if len(att) != 1 || !strings.HasSuffix(att[0], "-v1") {
		t.Fatalf("attached: %v", att)
	}
	_, _, doc, tags, ok := l.fake.PolicyState(att[0])
	if !ok || doc != string(want) || tags["authsec:policy"] != v.ID.String() {
		t.Fatalf("policy in AWS: %s %v", doc, tags)
	}
	if v, err = l.svc.Get(ctx, l.ws, v.ID); err != nil || v.Status != services.AccessStatusActive || v.Deployments[0].VerifiedAt == nil {
		t.Fatalf("after apply: %+v %v", v, err)
	}
	if r := v.Resource; r.ResourceType != igagov.AccessTypeDynamoDBTable || r.Name != "orders" || r.Region != "us-east-1" ||
		r.ARN != tableARN || r.AccountID != testAccount || r.Bucket != "" || r.Prefix != "" || r.Kind != "selector" {
		t.Fatalf("resource view: %+v", r)
	}

	// Detached by hand: the next check re-attaches it.
	r2 := services.NewGovR2(l.db)
	var row models.IGAGovTempGrant
	l.db.Where("workspace_id = ? AND policy_arn = ? AND state = ?", l.ws, att[0], models.R2StateActive).Take(&row)
	l.fake.Detach("DdbOrdersReader", att[0])
	l.runRow(r2, row.ID)
	if got := l.attachedAuthSec("DdbOrdersReader"); len(got) != 1 {
		t.Fatalf("not re-applied: %v", got)
	}

	// Edit to an allow of read and write: version 2 replaces version 1.
	in.Effect, in.Access = "allow", []string{"read", "write"}
	if v, err = l.svc.Edit(ctx, l.ws, l.user, v.ID, services.AccessPolicyRequest{AccessIntent: in, Name: "Block order reads",
		Reason: "now allow", BaseVersionNo: 1}); err != nil {
		t.Fatalf("edit: %v", err)
	}
	l.run(v.ID)
	att = l.attachedAuthSec("DdbOrdersReader")
	if len(att) != 1 || !strings.HasSuffix(att[0], "-v2") {
		t.Fatalf("after edit: %v", att)
	}
	_, _, doc, _, _ = l.fake.PolicyState(att[0])
	if !strings.Contains(doc, `"AuthSecAccessRead"`) || !strings.Contains(doc, `"AuthSecAccessItems"`) || strings.Contains(doc, "BatchWriteItem") {
		t.Fatalf("v2 document: %s", doc)
	}

	if _, err := l.svc.End(ctx, l.ws, l.user, v.ID, services.AccessReasonRequest{Reason: "done"}); err != nil {
		t.Fatal(err)
	}
	l.run(v.ID)
	if v, _ = l.svc.Get(ctx, l.ws, v.ID); v.Status != services.AccessStatusEnded || len(l.attachedAuthSec("DdbOrdersReader")) != 0 {
		t.Fatalf("ended: %s %v", v.Status, l.attachedAuthSec("DdbOrdersReader"))
	}
	for _, d := range v.Deployments {
		if _, _, _, _, ok := l.fake.PolicyState(d.AWSPolicyARN); ok {
			t.Errorf("%s still exists", d.AWSPolicyARN)
		}
	}
}

func TestAccessPolicyDynamoDBRefusals(t *testing.T) {
	l := newAPLab(t)
	ctx := context.Background()
	role := l.role("DdbRefusedRole")
	tbl := func(acct, name string) string { return "arn:aws:dynamodb:us-east-1:" + acct + ":table/" + name }
	orders := l.resourceOf(tbl(testAccount, "orders"), "dynamodb_table", &l.conn.ID)
	theirs := l.resourceOf(tbl("111122223333", "theirs"), "dynamodb_table", &l.conn.ID)
	pattern := l.resourceOf(tbl(testAccount, "ord*"), "selector", &l.conn.ID)
	global := l.resourceOf("arn:aws:dynamodb::"+testAccount+":global-table/orders", "selector", &l.conn.ID)
	stale := l.resourceOf(tbl(testAccount, "stale"), "dynamodb_table", nil)
	end := time.Now().Add(time.Hour)
	intent := func(effect string, res uuid.UUID, access ...string) igagov.AccessIntent {
		return igagov.AccessIntent{Effect: effect, Resource: igagov.AccessResource{ResourceID: res.String()},
			Roles: []igagov.AccessRole{{IdentityAccountID: role.String()}}, Access: access, EndsAt: &end}
	}
	withPrefix := intent("block", orders, "read")
	withPrefix.Resource.Prefix = "x/"
	for _, c := range []struct {
		name string
		in   igagov.AccessIntent
		code string
	}{
		{"a prefix on a table", withPrefix, services.GovCodeAccessInvalid},
		{"a pattern", intent("block", pattern, "read"), services.GovCodeResourceNotSupported},
		{"a global-table ARN", intent("block", global, "read"), services.GovCodeResourceNotSupported},
		{"an allow on another account's table", intent("allow", theirs, "read"), services.GovCodeResourceOtherAccount},
		{"a table no current scan sees", intent("block", stale, "read"), services.GovCodeResourceNotCurrent},
		{"allow all", intent("allow", orders, "all"), services.GovCodeAccessInvalid},
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

	// A block of another account's table is allowed: an identity Deny works
	// in any account.
	pv, err := l.svc.Preview(ctx, l.ws, intent("block", theirs, "read"))
	if err != nil || len(pv.Blockers) != 0 || !strings.Contains(pv.Sentence, "account 111122223333") {
		t.Fatalf("cross-account block: %+v %v", pv, err)
	}

	// Another workspace's table row and policy are 404.
	other := p3NewGov(t, l.db, "ddb-other")
	foreign := uuid.New()
	p3exec(t, l.db, `INSERT INTO iga_resources (id, workspace_id, resource_kind, display_name, provider, source_key)
		VALUES (?, ?, 'dynamodb_table', ?, 'aws', ?)`, foreign, other.ws, tbl(testAccount, "secret"), "aws\x1fref\x1fforeign")
	if got := previewCode(l.svc.Preview(ctx, l.ws, intent("block", foreign, "read"))); got != services.GovCodeResourceNotFound {
		t.Errorf("another workspace's table, preview: %s", got)
	}
	if _, err := l.svc.Create(ctx, l.ws, l.user, services.AccessPolicyRequest{AccessIntent: intent("block", foreign, "read"), Name: "x", Reason: "t"}); apCode(err) != services.GovCodeResourceNotFound {
		t.Errorf("another workspace's table, create: %v", err)
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

// previewCode is the refusal a preview reports: its error, else its first
// blocker (a preview returns the plan's refusals as blockers).
func previewCode(pv *services.AccessPreview, err error) string {
	if err != nil {
		return apCode(err)
	}
	if pv != nil && len(pv.Blockers) > 0 {
		return pv.Blockers[0].Code
	}
	return ""
}
