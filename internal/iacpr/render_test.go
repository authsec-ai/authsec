package iacpr

import (
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/igagov"
)

const acct = "429418377036"

func arnPolicy(path, name string) string { return "arn:aws:iam::" + acct + ":policy" + path + name }

const customerDoc = `{"Version":"2012-10-17","Statement":[
 {"Sid":"Compute","Effect":"Allow","Action":["ec2:Describe*","sqs:SendMessage","s3:GetObject"],"Resource":"*",
  "Condition":{"StringEquals":{"aws:RequestedRegion":"eu-west-1"}}},
 {"Sid":"QueuesOnly","Effect":"Allow","Action":"sqs:*","Resource":"arn:aws:sqs:*:*:refunds"},
 {"Sid":"NoIAM","Effect":"Deny","Action":"iam:*","Resource":"*"}]}`

func hashOf(t *testing.T, doc string) (string, string) {
	t.Helper()
	c, h, err := igagov.CanonicalDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(c), h
}

// narrowPlan builds the facts of an in-place narrowing of TeamBoundary.
func narrowPlan(t *testing.T, remove ...string) (igagov.Plan, map[string]string) {
	t.Helper()
	bc, bh := hashOf(t, customerDoc)
	nc, nh, _, ref, err := igagov.NarrowCustomerBoundary(customerDoc, remove)
	if err != nil || ref != nil {
		t.Fatalf("narrow: %v %v", err, ref)
	}
	arn := arnPolicy("/", "TeamBoundary")
	p := igagov.Plan{Kind: igagov.PlanApply, Delivery: igagov.DeliveryIaCPR, PlanHash: "sha256:plan",
		Facts: []igagov.Fact{
			{Key: "role_boundary", Kind: igagov.FactRoleBoundary, Before: arn, After: arn},
			{Key: "policy_document:" + arn, Kind: igagov.FactPolicyDocument, Subject: arn, Before: bh, After: nh},
		}}
	return p, map[string]string{bh: bc, nh: string(nc)}
}

const tfMain = `terraform {
  required_version = ">= 1.5"
}

# The refund worker's role.
resource "aws_iam_role" "refund" {
  name                 = "RefundTaskRole"
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  permissions_boundary = aws_iam_policy.team_boundary.arn
}

resource "aws_iam_policy" "team_boundary" {
  name = "TeamBoundary"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Compute"
        Effect   = "Allow"
        Action   = ["ec2:Describe*", "sqs:SendMessage", "s3:GetObject"]
        Resource = "*"
        Condition = { StringEquals = { "aws:RequestedRegion" = "eu-west-1" } }
      },
      { Sid = "QueuesOnly", Effect = "Allow", Action = "sqs:*", Resource = "arn:aws:sqs:*:*:refunds" },
      { Sid = "NoIAM", Effect = "Deny", Action = "iam:*", Resource = "*" },
    ]
  })
}
`

func role() RoleTarget {
	return RoleTarget{Name: "RefundTaskRole", ARN: "arn:aws:iam::" + acct + ":role/RefundTaskRole", RoleID: "AROAEXAMPLE", AccountID: acct}
}

func TestTerraformNarrowInPlaceKeepsSidsAndConditions(t *testing.T) {
	p, docs := narrowPlan(t, "sqs")
	ch, err := Render(Request{Source: Source{Format: FormatTerraform, Directory: "infra"},
		Files: map[string]string{"infra/main.tf": tfMain}, Role: role(), Plan: p, Documents: docs})
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Files) != 1 {
		t.Fatalf("files %+v", ch.Files)
	}
	out := ch.Files[0].After
	// Re-parse what was written: the document now equals the narrowed one.
	bs, err := parseTerraform("main.tf", out)
	if err != nil {
		t.Fatalf("rendered Terraform does not parse: %v\n%s", err, out)
	}
	var doc string
	for _, b := range bs {
		if b.address() == "aws_iam_policy.team_boundary" {
			doc, _, err = policyDocument(b.attr("policy").Raw)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	h, _ := igagov.DocumentHash(doc)
	if h != p.Facts[1].After {
		t.Fatalf("rendered document hash %s, want %s\n%s", h, p.Facts[1].After, out)
	}
	for _, want := range []string{`"Sid": "Compute"`, `"aws:RequestedRegion": "eu-west-1"`, `"Sid": "NoIAM"`, "# The refund worker's role."} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in\n%s", want, out)
		}
	}
	if strings.Contains(out, "sqs:") || strings.Contains(out, "QueuesOnly") {
		t.Errorf("sqs not removed:\n%s", out)
	}
	if !strings.Contains(out, "permissions_boundary = aws_iam_policy.team_boundary.arn") {
		t.Errorf("role edited:\n%s", out)
	}
}

func TestTerraformFallbacks(t *testing.T) {
	p, docs := narrowPlan(t, "sqs")
	cases := map[string]struct {
		files  map[string]string
		reason string
	}{
		"registry module": {map[string]string{"m/main.tf": `module "refund_role" {
  source    = "terraform-aws-modules/iam/aws//modules/iam-assumable-role"
  role_name = "RefundTaskRole"
}
`}, ReasonFormUnsupported},
		"for_each": {map[string]string{"m/main.tf": `resource "aws_iam_role" "r" {
  for_each = toset(["RefundTaskRole"])
  name = "RefundTaskRole"
  assume_role_policy = "{}"
}
`}, ReasonFormUnsupported},
		"twice": {map[string]string{"m/a.tf": "resource \"aws_iam_role\" \"a\" {\n  name = \"RefundTaskRole\"\n}\n",
			"m/b.tf": "resource \"aws_iam_role\" \"b\" {\n  name = \"RefundTaskRole\"\n}\n"}, ReasonRoleAmbiguous},
		"absent":     {map[string]string{"m/a.tf": "resource \"aws_iam_role\" \"a\" {\n  name = \"Other\"\n}\n"}, ReasonRoleNotFound},
		"terragrunt": {map[string]string{"m/terragrunt.hcl": "include {}\n", "m/a.tf": tfMain}, ReasonGeneratedSource},
		"data document": {map[string]string{"m/a.tf": strings.Replace(tfMain, "policy = jsonencode({", "policy = data.aws_iam_policy_document.b.json\n  x = jsonencode({", 1)},
			ReasonFormUnsupported},
	}
	for name, c := range cases {
		_, err := Render(Request{Source: Source{Format: FormatTerraform, Directory: "m"}, Files: c.files, Role: role(), Plan: p, Documents: docs})
		f := AsFallback(err)
		if f == nil || f.Reason != c.reason {
			t.Errorf("%s: %v, want %s", name, err, c.reason)
		}
	}
}

func TestTerraformSplitCopyLeavesSharedUntouched(t *testing.T) {
	bc, bh := hashOf(t, customerDoc)
	nc, nh, _, _, _ := igagov.NarrowCustomerBoundary(customerDoc, []string{"sqs"})
	shared, cp := arnPolicy("/", "TeamBoundary"), arnPolicy("/", "TeamBoundary-AROAEXAMPLE")
	p := igagov.Plan{Kind: igagov.PlanApply, Delivery: igagov.DeliveryIaCPR, Facts: []igagov.Fact{
		{Key: "role_boundary", Kind: igagov.FactRoleBoundary, Before: shared, After: cp},
		{Key: "policy_document:" + cp, Kind: igagov.FactPolicyDocument, Subject: cp, Before: igagov.ValueAbsent, After: nh},
		{Key: "policy_document:" + shared, Kind: igagov.FactPolicyDocument, Subject: shared, Before: bh, After: bh},
	}}
	ch, err := Render(Request{Source: Source{Format: FormatTerraform, Directory: "infra"}, Files: map[string]string{"infra/main.tf": tfMain},
		Role: role(), Plan: p, Documents: map[string]string{bh: bc, nh: string(nc)}})
	if err != nil {
		t.Fatal(err)
	}
	out := ch.Files[0].After
	if !strings.Contains(out, `resource "aws_iam_policy" "teamboundary-aroaexample"`) && !strings.Contains(out, `"teamboundary_aroaexample"`) {
		t.Fatalf("no copy:\n%s", out)
	}
	if !strings.Contains(out, "permissions_boundary = aws_iam_policy.teamboundary_aroaexample.arn") {
		t.Fatalf("role not re-pointed:\n%s", out)
	}
	if !strings.Contains(out, tfMain[strings.Index(tfMain, `resource "aws_iam_policy" "team_boundary"`):]) {
		t.Fatalf("shared policy changed:\n%s", out)
	}
	if _, err := parseTerraform("x.tf", out); err != nil {
		t.Fatal(err)
	}
}
