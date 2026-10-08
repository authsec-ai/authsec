package iacpr

import (
	"encoding/json"
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

const cfnStackSrc = `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  # The refund worker.
  RefundRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: RefundTaskRole
      PermissionsBoundary: !Ref TeamBoundary
  TeamBoundary:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      ManagedPolicyName: TeamBoundary
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Sid: Compute
            Effect: Allow
            Action: ["ec2:Describe*", "sqs:SendMessage", "s3:GetObject"]
            Resource: "*"
            Condition:
              StringEquals:
                aws:RequestedRegion: eu-west-1
          - Sid: QueuesOnly
            Effect: Allow
            Action: sqs:*
            Resource: arn:aws:sqs:*:*:refunds
          - Sid: NoIAM
            Effect: Deny
            Action: iam:*
            Resource: "*"
`

func TestCloudFormationNarrowInPlace(t *testing.T) {
	p, docs := narrowPlan(t, "sqs")
	ch, err := Render(Request{Source: Source{Format: FormatCloudFormation, Directory: "cfn"},
		Files: map[string]string{"cfn/stack.yaml": cfnStackSrc}, Role: role(), Plan: p, Documents: docs})
	if err != nil {
		t.Fatal(err)
	}
	out := ch.Files[0].After
	tpl, err := parseCFN("x", out)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range tpl.resources() {
		if r.LogicalID == "TeamBoundary" {
			v, err := cfnLiteral(mapGet(r.Props, "PolicyDocument"))
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := jsonMarshal(v)
			if h, _ := igagov.DocumentHash(raw); h != p.Facts[1].After {
				t.Fatalf("document %s\n%s", raw, out)
			}
		}
	}
	if !strings.Contains(out, "PermissionsBoundary: !Ref TeamBoundary") || !strings.Contains(out, "# The refund worker.") ||
		!strings.Contains(out, `Version: "2012-10-17"`) {
		t.Fatalf("template:\n%s", out)
	}
}

func TestCloudFormationFallbacks(t *testing.T) {
	p, docs := narrowPlan(t, "sqs")
	for name, c := range map[string]struct {
		src, reason string
	}{
		"transform": {"Transform: AWS::Serverless-2016-10-31\n" + cfnStackSrc, ReasonGeneratedSource},
		"computed":  {strings.Replace(cfnStackSrc, "RoleName: RefundTaskRole", "RoleName: !Sub '${AWS::StackName}-x'", 1), ReasonFormUnsupported},
		"absent":    {strings.Replace(cfnStackSrc, "RoleName: RefundTaskRole", "RoleName: Other", 1), ReasonRoleNotFound},
	} {
		_, err := Render(Request{Source: Source{Format: FormatCloudFormation, Directory: "cfn"},
			Files: map[string]string{"cfn/stack.yaml": c.src}, Role: role(), Plan: p, Documents: docs})
		if f := AsFallback(err); f == nil || f.Reason != c.reason {
			t.Errorf("%s: %v, want %s", name, err, c.reason)
		}
	}
}

const tfSplit = `resource "aws_iam_role" "src" {
  name               = "SharedRole"
  assume_role_policy = jsonencode({ Version = "2012-10-17" })
}

resource "aws_lambda_function" "fn" {
  function_name = "refund-fn"
  role          = aws_iam_role.src.arn
}

resource "aws_lambda_alias" "live" {
  function_name    = aws_lambda_function.fn.function_name
  function_version = aws_lambda_function.fn.version
}
`

func splitPlans() (igagov.Plan, igagov.Plan) {
	src, nr := "arn:aws:iam::"+acct+":role/SharedRole", "arn:aws:iam::"+acct+":role/refund-fn-role"
	fn := "arn:aws:lambda:us-east-1:" + acct + ":function:refund-fn"
	d := &igagov.SplitDetail{SourceRoleARN: src, NewRoleARN: nr, SubjectKind: igagov.SubjectLambdaFunction, SubjectARN: fn}
	split := igagov.Plan{Kind: igagov.PlanSplit, Delivery: igagov.DeliveryIaCPR, Diff: igagov.PlanDiff{Split: d},
		Ops: []igagov.Op{{Op: igagov.OpCreateRole, RoleARN: nr, Path: "/"}, {Op: igagov.OpAttachRolePolicy, RoleARN: nr, PolicyARN: "arn:aws:iam::" + acct + ":policy/Work"},
			{Op: igagov.OpBindSubject, SubjectARN: fn, RoleARN: nr}}}
	revert := igagov.Plan{Kind: igagov.PlanSplitRevert, Delivery: igagov.DeliveryIaCPR, Diff: igagov.PlanDiff{Split: d},
		Ops: []igagov.Op{{Op: igagov.OpBindSubject, SubjectARN: fn, RoleARN: src}, {Op: igagov.OpDeleteRole, RoleARN: nr, OnlyIfUnused: true}}}
	return split, revert
}

func TestTerraformSplitAndRevert(t *testing.T) {
	split, revert := splitPlans()
	r := RoleTarget{Name: "SharedRole", ARN: "arn:aws:iam::" + acct + ":role/SharedRole", AccountID: acct}
	ch, err := Render(Request{Source: Source{Format: FormatTerraform, Directory: "m"}, Files: map[string]string{"m/main.tf": tfSplit}, Role: r, Plan: split})
	if err != nil {
		t.Fatal(err)
	}
	after := ch.Files[0].After
	if !strings.Contains(after, `resource "aws_iam_role" "refund_fn_role"`) || !strings.Contains(after, "role          = aws_iam_role.refund_fn_role.arn") ||
		!strings.Contains(after, "publish = true") || !strings.Contains(after, `policy_arn = "arn:aws:iam::`+acct+`:policy/Work"`) {
		t.Fatalf("split:\n%s", after)
	}
	rv, err := Render(Request{Source: Source{Format: FormatTerraform, Directory: "m"}, Files: map[string]string{"m/main.tf": after}, Role: r, Plan: revert})
	if err != nil {
		t.Fatal(err)
	}
	back := rv.Files[0].After
	if strings.Contains(back, "refund_fn_role") || !strings.Contains(back, "role          = aws_iam_role.src.arn") {
		t.Fatalf("revert:\n%s", back)
	}
	keep, err := Render(Request{Source: Source{Format: FormatTerraform, Directory: "m"}, Files: map[string]string{"m/main.tf": after}, Role: r, Plan: revert, KeepNewRole: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(keep.Files[0].After, `resource "aws_iam_role" "refund_fn_role"`) {
		t.Fatal("KeepNewRole removed the role")
	}
	// A pinned alias version would not move: not mechanical.
	pinned := strings.Replace(tfSplit, "function_version = aws_lambda_function.fn.version", `function_version = "3"`, 1)
	if _, err := Render(Request{Source: Source{Format: FormatTerraform, Directory: "m"}, Files: map[string]string{"m/main.tf": pinned}, Role: r, Plan: split}); AsFallback(err) == nil {
		t.Fatalf("pinned alias: %v", err)
	}
	// CloudFormation sources get the step list.
	if _, err := Render(Request{Source: Source{Format: FormatCloudFormation, Directory: "m"}, Files: map[string]string{"m/s.yaml": cfnStackSrc}, Role: r, Plan: split}); AsFallback(err) == nil {
		t.Fatal("CloudFormation split rendered")
	}
}

func jsonMarshal(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}
