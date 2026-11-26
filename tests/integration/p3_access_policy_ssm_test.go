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

// Access policies on an SSM parameter (block only): the parameter is picked
// through its Discovery row, a read block also denies listing every path
// above it, the deployment runs on the same job as the other AWS types, and
// an allow is refused.

func ssmARN(acct, name string) string {
	return "arn:aws:ssm:us-east-1:" + acct + ":parameter/" + name
}

func TestAccessPolicySSMLifecycle(t *testing.T) {
	l := newAPLab(t)
	ctx := context.Background()
	reader := l.role("ParamReader")
	res := l.resourceOf(ssmARN(testAccount, "prod/db/password"), "ssm_parameter", &l.conn.ID)
	end := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	in := igagov.AccessIntent{Effect: "block", Resource: igagov.AccessResource{ResourceID: res.String()},
		Roles: []igagov.AccessRole{{IdentityAccountID: reader.String()}}, Access: []string{"read"}, EndsAt: &end}

	pv, err := l.svc.Preview(ctx, l.ws, in)
	if err != nil || len(pv.Blockers) != 0 || len(pv.Documents) != 1 ||
		!strings.Contains(pv.Sentence, "Block read on SSM parameter /prod/db/password (us-east-1, account "+testAccount+")") {
		t.Fatalf("preview: %+v %v", pv, err)
	}
	target := igagov.SSMParameterTarget{Partition: "aws", Region: "us-east-1", Account: testAccount, Param: "prod/db/password"}
	want, _, _, _, err := igagov.AccessDocument("block", []string{"read"}, target, nil, &end)
	if err != nil || string(pv.Documents[0].Document) != string(want) {
		t.Fatalf("preview document:\n got %s\nwant %s (%v)", pv.Documents[0].Document, want, err)
	}
	var codes []string
	for _, w := range pv.Warnings {
		codes = append(codes, w.Code)
	}
	if got := strings.Join(codes, ","); got != "path_listing_blocked,history_blocked,copies_not_covered,other_paths" {
		t.Fatalf("warnings: %s", got)
	}

	v, err := l.svc.Create(ctx, l.ws, l.user, services.AccessPolicyRequest{AccessIntent: in, Name: "Block db password", Reason: "incident 11"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	l.run(v.ID)
	att := l.attachedAuthSec("ParamReader")
	if len(att) != 1 || !strings.HasSuffix(att[0], "-v1") {
		t.Fatalf("attached: %v", att)
	}
	if _, _, doc, _, ok := l.fake.PolicyState(att[0]); !ok || doc != string(want) {
		t.Fatalf("policy in AWS: %s", doc)
	}
	if v, err = l.svc.Get(ctx, l.ws, v.ID); err != nil || v.Status != services.AccessStatusActive {
		t.Fatalf("after apply: %+v %v", v, err)
	}
	if r := v.Resource; r.ResourceType != igagov.AccessTypeSSMParameter || r.Name != "/prod/db/password" || r.Region != "us-east-1" || r.AccountID != testAccount {
		t.Fatalf("resource view: %+v", r)
	}

	// Detached by hand: the next check re-attaches it.
	r2 := services.NewGovR2(l.db)
	var row models.IGAGovTempGrant
	l.db.Where("workspace_id = ? AND policy_arn = ? AND state = ?", l.ws, att[0], models.R2StateActive).Take(&row)
	l.fake.Detach("ParamReader", att[0])
	l.runRow(r2, row.ID)
	if got := l.attachedAuthSec("ParamReader"); len(got) != 1 {
		t.Fatalf("not re-applied: %v", got)
	}

	// Edit to block write: version 2 has no path statement.
	in.Access = []string{"write"}
	if v, err = l.svc.Edit(ctx, l.ws, l.user, v.ID, services.AccessPolicyRequest{AccessIntent: in, Name: "Block db password",
		Reason: "writes", BaseVersionNo: 1}); err != nil {
		t.Fatalf("edit: %v", err)
	}
	l.run(v.ID)
	att = l.attachedAuthSec("ParamReader")
	if len(att) != 1 || !strings.HasSuffix(att[0], "-v2") {
		t.Fatalf("after edit: %v", att)
	}
	if _, _, doc, _, _ := l.fake.PolicyState(att[0]); !strings.Contains(doc, "ssm:PutParameter") || strings.Contains(doc, "GetParametersByPath") {
		t.Fatalf("v2 document: %s", doc)
	}
	allow := in
	allow.Effect = "allow"
	if _, err := l.svc.Edit(ctx, l.ws, l.user, v.ID, services.AccessPolicyRequest{AccessIntent: allow, Name: "Block db password",
		Reason: "allow", BaseVersionNo: 2}); apCode(err) != services.GovCodeAccessInvalid {
		t.Fatalf("edit to allow: %v", err)
	}

	if _, err := l.svc.End(ctx, l.ws, l.user, v.ID, services.AccessReasonRequest{Reason: "done"}); err != nil {
		t.Fatal(err)
	}
	l.run(v.ID)
	if v, _ = l.svc.Get(ctx, l.ws, v.ID); v.Status != services.AccessStatusEnded || len(l.attachedAuthSec("ParamReader")) != 0 {
		t.Fatalf("ended: %s %v", v.Status, l.attachedAuthSec("ParamReader"))
	}
}

func TestAccessPolicySSMRefusals(t *testing.T) {
	l := newAPLab(t)
	ctx := context.Background()
	role := l.role("ParamRefusedRole")
	param := l.resourceOf(ssmARN(testAccount, "prod/db"), "ssm_parameter", &l.conn.ID)
	pattern := l.resourceOf(ssmARN(testAccount, "prod/*"), "selector", &l.conn.ID)
	stale := l.resourceOf(ssmARN(testAccount, "stale"), "ssm_parameter", nil)
	end := time.Now().Add(time.Hour)
	intent := func(effect string, res uuid.UUID, access ...string) igagov.AccessIntent {
		return igagov.AccessIntent{Effect: effect, Resource: igagov.AccessResource{ResourceID: res.String()},
			Roles: []igagov.AccessRole{{IdentityAccountID: role.String()}}, Access: access, EndsAt: &end}
	}
	withPrefix := intent("block", param, "read")
	withPrefix.Resource.Prefix = "x/"
	for _, c := range []struct {
		name string
		in   igagov.AccessIntent
		code string
	}{
		{"a prefix on a parameter", withPrefix, services.GovCodeAccessInvalid},
		{"a pattern", intent("block", pattern, "read"), services.GovCodeResourceNotSupported},
		{"an allow", intent("allow", param, "read"), services.GovCodeAccessInvalid},
		{"a parameter no current scan sees", intent("block", stale, "read"), services.GovCodeResourceNotCurrent},
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

	// Another workspace's parameter row and policy are 404.
	other := p3NewGov(t, l.db, "ssm-other")
	foreign := uuid.New()
	p3exec(t, l.db, `INSERT INTO iga_resources (id, workspace_id, resource_kind, display_name, provider, source_key)
		VALUES (?, ?, 'ssm_parameter', ?, 'aws', ?)`, foreign, other.ws, ssmARN(testAccount, "prod/db"), "aws\x1fref\x1fforeign-ssm")
	if got := previewCode(l.svc.Preview(ctx, l.ws, intent("block", foreign, "read"))); got != services.GovCodeResourceNotFound {
		t.Errorf("another workspace's parameter, preview: %s", got)
	}
	if _, err := l.svc.Create(ctx, l.ws, l.user, services.AccessPolicyRequest{AccessIntent: intent("block", foreign, "read"), Name: "x", Reason: "t"}); apCode(err) != services.GovCodeResourceNotFound {
		t.Errorf("another workspace's parameter, create: %v", err)
	}
	pid := uuid.New()
	p3exec(t, l.db, `INSERT INTO iga_gov_policy (id, workspace_id, name, family, provider, created_by) VALUES (?, ?, 'theirs', 'time_bound', 'aws', ?)`,
		pid, other.ws, other.author)
	if _, err := l.svc.Get(ctx, l.ws, pid); apCode(err) != "not_found" {
		t.Errorf("another workspace's policy, get: %v", err)
	}
	if list, _, err := l.svc.List(ctx, l.ws, services.AccessListQuery{}); err != nil || len(list) != 0 {
		t.Errorf("list shows another workspace's policy: %v %v", list, err)
	}
}
