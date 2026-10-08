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

const splitTrust = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
const splitInline = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::refunds/*"}]}`

const tfSplit = `resource "aws_iam_role" "src" {
  name               = "SharedRole"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }] })
  inline_policy {
    name   = "refund-inline"
    policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = "s3:GetObject", Resource = "arn:aws:s3:::refunds/*" }] })
  }
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

// splitPlansFor builds a split and its revert for one subject kind, with
// the approved trust and inline documents archived.
func splitPlansFor(t *testing.T, kind string, subjects ...string) (igagov.Plan, igagov.Plan, map[string]string) {
	t.Helper()
	tc, th := hashOf(t, splitTrust)
	ic, ih := hashOf(t, splitInline)
	src, nr := "arn:aws:iam::"+acct+":role/SharedRole", "arn:aws:iam::"+acct+":role/refund-fn-role"
	d := &igagov.SplitDetail{SourceRoleARN: src, NewRoleARN: nr, SubjectKind: kind, SubjectARN: subjects[0]}
	if len(subjects) > 1 {
		d.SubjectARNs = subjects
	}
	split := igagov.Plan{Kind: igagov.PlanSplit, Delivery: igagov.DeliveryIaCPR, PlanHash: "sha256:split", Diff: igagov.PlanDiff{Split: d},
		Ops: []igagov.Op{{Op: igagov.OpCreateRole, RoleARN: nr, Path: "/", TrustPolicyHash: th},
			{Op: igagov.OpAttachRolePolicy, RoleARN: nr, PolicyARN: "arn:aws:iam::" + acct + ":policy/Work"},
			{Op: igagov.OpPutRolePolicy, RoleARN: nr, InlineName: "refund-inline", DocumentHash: ih}}}
	revert := igagov.Plan{Kind: igagov.PlanSplitRevert, Delivery: igagov.DeliveryIaCPR, Diff: igagov.PlanDiff{Split: d},
		Ops: []igagov.Op{{Op: igagov.OpDeleteRole, RoleARN: nr, OnlyIfUnused: true}}}
	for _, s := range subjects {
		split.Ops = append(split.Ops, igagov.Op{Op: igagov.OpBindSubject, SubjectARN: s, RoleARN: nr})
		revert.Ops = append(revert.Ops, igagov.Op{Op: igagov.OpBindSubject, SubjectARN: s, RoleARN: src})
	}
	return split, revert, map[string]string{th: tc, ih: ic}
}

func splitPlans(t *testing.T) (igagov.Plan, igagov.Plan, map[string]string) {
	return splitPlansFor(t, igagov.SubjectLambdaFunction, "arn:aws:lambda:us-east-1:"+acct+":function:refund-fn")
}

func sharedRole() RoleTarget {
	return RoleTarget{Name: "SharedRole", ARN: "arn:aws:iam::" + acct + ":role/SharedRole", AccountID: acct}
}

func TestTerraformSplitAndRevert(t *testing.T) {
	split, revert, docs := splitPlans(t)
	r := sharedRole()
	tf := func(files string, p igagov.Plan, keep bool) (*Change, error) {
		return Render(Request{Source: Source{Format: FormatTerraform, Directory: "m"}, Files: map[string]string{"m/main.tf": files}, Role: r,
			Plan: p, Documents: docs, KeepNewRole: keep})
	}
	ch, err := tf(tfSplit, split, false)
	if err != nil {
		t.Fatal(err)
	}
	after := ch.Files[0].After
	if !strings.Contains(after, `resource "aws_iam_role" "refund_fn_role"`) || !strings.Contains(after, "role          = aws_iam_role.refund_fn_role.arn") ||
		!strings.Contains(after, "publish = true") || !strings.Contains(after, `policy_arn = "arn:aws:iam::`+acct+`:policy/Work"`) {
		t.Fatalf("split:\n%s", after)
	}
	// The new role's trust and inline documents are the approved ones.
	nb := p3Block(after, `resource "aws_iam_role" "refund_fn_role"`)
	for _, want := range []string{"lambda.amazonaws.com", "arn:aws:s3:::refunds/*", "refund-inline"} {
		if !strings.Contains(nb, want) {
			t.Fatalf("new role lacks %s:\n%s", want, nb)
		}
	}
	rv, err := tf(after, revert, false)
	if err != nil {
		t.Fatal(err)
	}
	back := rv.Files[0].After
	if strings.Contains(back, "refund_fn_role") || !strings.Contains(back, "role          = aws_iam_role.src.arn") {
		t.Fatalf("revert:\n%s", back)
	}
	keep, err := tf(after, revert, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(keep.Files[0].After, `resource "aws_iam_role" "refund_fn_role"`) {
		t.Fatal("KeepNewRole removed the role")
	}
	// A pinned alias version would not move: not mechanical.
	pinned := strings.Replace(tfSplit, "function_version = aws_lambda_function.fn.version", `function_version = "3"`, 1)
	if _, err := tf(pinned, split, false); AsFallback(err) == nil {
		t.Fatalf("pinned alias: %v", err)
	}
}

func p3Block(src, header string) string {
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

// P1-12 (b): the PR is rendered from the approved archived documents; a
// source that no longer says what was approved is never rendered.
func TestTerraformSplitRendersApprovedDocumentsOnly(t *testing.T) {
	split, _, docs := splitPlans(t)
	r := sharedRole()
	render := func(src string, d map[string]string) error {
		_, err := Render(Request{Source: Source{Format: FormatTerraform, Directory: "m"}, Files: map[string]string{"m/main.tf": src}, Role: r,
			Plan: split, Documents: d})
		return err
	}
	for name, c := range map[string]struct {
		src    string
		reason string
	}{
		"trust differs":  {strings.Replace(tfSplit, `Service = "lambda.amazonaws.com"`, `Service = "ec2.amazonaws.com"`, 1), ReasonSourceDiffers},
		"inline differs": {strings.Replace(tfSplit, `arn:aws:s3:::refunds/*`, `arn:aws:s3:::*`, 1), ReasonSourceDiffers},
		"extra inline": {strings.Replace(tfSplit, "  inline_policy {\n", "  inline_policy {\n    name = \"extra\"\n    policy = jsonencode({})\n  }\n  inline_policy {\n", 1),
			ReasonSourceDiffers},
		"inline missing": {tfSplit[:strings.Index(tfSplit, "  inline_policy {")] + "}\n" + tfSplit[strings.Index(tfSplit, "resource \"aws_lambda_function\""):], ReasonSourceDiffers},
		"boundary added": {strings.Replace(tfSplit, "  inline_policy {\n", "  permissions_boundary = \"arn:aws:iam::"+acct+":policy/Other\"\n  inline_policy {\n", 1),
			ReasonSourceDiffers},
	} {
		if f := AsFallback(render(c.src, docs)); f == nil || f.Reason != c.reason {
			t.Errorf("%s: %v, want %s", name, f, c.reason)
		}
	}
	if f := AsFallback(render(tfSplit, map[string]string{})); f == nil || f.Reason != ReasonDocumentNotArchived {
		t.Errorf("no archived documents: %v", f)
	}
	// A computed trust policy (a data source) is not copied: the approved
	// document is rendered.
	computed := strings.Replace(tfSplit, `assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }] })`,
		"assume_role_policy = data.aws_iam_policy_document.trust.json", 1)
	ch, err := Render(Request{Source: Source{Format: FormatTerraform, Directory: "m"}, Files: map[string]string{"m/main.tf": computed}, Role: r,
		Plan: split, Documents: docs})
	if err != nil {
		t.Fatal(err)
	}
	nb := p3Block(ch.Files[0].After, `resource "aws_iam_role" "refund_fn_role"`)
	if strings.Contains(nb, "data.aws_iam_policy_document") || !strings.Contains(nb, "lambda.amazonaws.com") {
		t.Fatalf("computed trust copied instead of the approved document:\n%s", nb)
	}
}

const tfECS = `resource "aws_iam_role" "src" {
  name               = "SharedRole"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }] })
  inline_policy {
    name   = "refund-inline"
    policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = "s3:GetObject", Resource = "arn:aws:s3:::refunds/*" }] })
  }
}

resource "aws_ecs_task_definition" "refund" {
  family        = "refund-agent"
  task_role_arn = aws_iam_role.src.arn
}

resource "aws_ecs_service" "a" {
  name            = "refund-agent"
  task_definition = aws_ecs_task_definition.refund.arn
}

resource "aws_ecs_service" "b" {
  name            = "refund-replay"
  task_definition = aws_ecs_task_definition.refund.arn
}
`

// P1-12 (d): every ECS service of the family is a subject; the task
// definition moves once and both services move with it.
func TestTerraformSplitECSEveryService(t *testing.T) {
	svc := func(n string) string { return "arn:aws:ecs:us-east-1:" + acct + ":service/payments/" + n }
	split, _, docs := splitPlansFor(t, igagov.SubjectECSService, svc("refund-agent"), svc("refund-replay"))
	ch, err := Render(Request{Source: Source{Format: FormatTerraform, Directory: "m"}, Files: map[string]string{"m/main.tf": tfECS}, Role: sharedRole(),
		Plan: split, Documents: docs})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ch.Files[0].After, "task_role_arn = aws_iam_role.refund_fn_role.arn") ||
		!strings.Contains(strings.Join(ch.Summary, ";"), "refund-agent, refund-replay") {
		t.Fatalf("ECS:\n%s\n%v", ch.Files[0].After, ch.Summary)
	}
	one, _, _ := splitPlansFor(t, igagov.SubjectECSService, svc("refund-agent"))
	if _, err := Render(Request{Source: Source{Format: FormatTerraform, Directory: "m"}, Files: map[string]string{"m/main.tf": tfECS}, Role: sharedRole(),
		Plan: one, Documents: docs}); AsFallback(err) == nil {
		t.Fatalf("a task definition shared with a non-subject service rendered: %v", err)
	}
}

const cfnSplitSrc = `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Shared:
    Type: AWS::IAM::Role
    Properties:
      RoleName: SharedRole
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::429418377036:policy/Work
      Policies:
        - PolicyName: refund-inline
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action: s3:GetObject
                Resource: arn:aws:s3:::refunds/*
  Fn:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: refund-fn
      Role: !GetAtt Shared.Arn
  FnV1:
    Type: AWS::Lambda::Version
    Properties:
      FunctionName: !Ref Fn
  Live:
    Type: AWS::Lambda::Alias
    Properties:
      Name: live
      FunctionName: !Ref Fn
      FunctionVersion: !GetAtt FnV1.Version
  Task:
    Type: AWS::ECS::TaskDefinition
    Properties:
      Family: refund-agent
      TaskRoleArn: !GetAtt Shared.Arn
  Svc:
    Type: AWS::ECS::Service
    Properties:
      ServiceName: refund-agent
      TaskDefinition: !Ref Task
  Prof:
    Type: AWS::IAM::InstanceProfile
    Properties:
      Roles: [!Ref Shared]
  LT:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateData:
        IamInstanceProfile:
          Arn: !GetAtt Prof.Arn
  Group:
    Type: AWS::AutoScaling::AutoScalingGroup
    Properties:
      AutoScalingGroupName: refund-asg
      LaunchTemplate:
        LaunchTemplateId: !Ref LT
        Version: !GetAtt LT.LatestVersionNumber
`

// P1-12 (e): CloudFormation sources render the split (and its revert) from
// the approved documents for every supported compute type.
func TestCloudFormationSplitAndRevert(t *testing.T) {
	for kind, subject := range map[string]string{
		igagov.SubjectLambdaFunction: "arn:aws:lambda:us-east-1:" + acct + ":function:refund-fn",
		igagov.SubjectECSService:     "arn:aws:ecs:us-east-1:" + acct + ":service/payments/refund-agent",
		igagov.SubjectEC2ASG:         "arn:aws:autoscaling:us-east-1:" + acct + ":autoScalingGroup:x:autoScalingGroupName/refund-asg",
	} {
		split, revert, docs := splitPlansFor(t, kind, subject)
		req := Request{Source: Source{Format: FormatCloudFormation, Directory: "cfn"}, Files: map[string]string{"cfn/stack.yaml": cfnSplitSrc},
			Role: sharedRole(), Plan: split, Documents: docs}
		ch, err := Render(req)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		out := ch.Files[0].After
		tpl, err := parseCFN("x", out)
		if err != nil {
			t.Fatal(err)
		}
		nr, ok := tpl.resource("refundfnrole")
		if !ok {
			t.Fatalf("%s: no new role:\n%s", kind, out)
		}
		if h, _ := cfnDocHash(mapGet(nr.Props, "AssumeRolePolicyDocument")); h != split.Ops[0].TrustPolicyHash {
			t.Fatalf("%s: trust not the approved document:\n%s", kind, out)
		}
		pol := mapGet(nr.Props, "Policies").Content[0]
		if h, _ := cfnDocHash(mapGet(pol, "PolicyDocument")); h != split.Ops[2].DocumentHash {
			t.Fatalf("%s: inline not the approved document:\n%s", kind, out)
		}
		switch kind {
		case igagov.SubjectLambdaFunction:
			if !strings.Contains(out, "Role: !GetAtt refundfnrole.Arn") || !strings.Contains(out, "FunctionVersion: !GetAtt FnVersionrefundfnrole.Version") {
				t.Fatalf("lambda:\n%s", out)
			}
		case igagov.SubjectECSService:
			if !strings.Contains(out, "TaskRoleArn: !GetAtt refundfnrole.Arn") {
				t.Fatalf("ecs:\n%s", out)
			}
		case igagov.SubjectEC2ASG:
			if !strings.Contains(out, "Arn: !GetAtt refundfnroleProfile.Arn") || !strings.Contains(out, "AutoScalingRollingUpdate") {
				t.Fatalf("asg:\n%s", out)
			}
		}
		// The revert re-points the subject and removes what the split added.
		rv, err := Render(Request{Source: req.Source, Files: map[string]string{"cfn/stack.yaml": out}, Role: sharedRole(), Plan: revert, Documents: docs})
		if err != nil {
			t.Fatalf("%s revert: %v", kind, err)
		}
		back := rv.Files[0].After
		if strings.Contains(back, "RoleName: refund-fn-role") || strings.Contains(back, "refundfnroleProfile:") {
			t.Fatalf("%s revert kept the role:\n%s", kind, back)
		}
		// A source whose trust differs from the approved one is not rendered.
		bad := req
		bad.Files = map[string]string{"cfn/stack.yaml": strings.Replace(cfnSplitSrc, "Service: lambda.amazonaws.com", "Service: ec2.amazonaws.com", 1)}
		if f := AsFallback(func() error { _, err := Render(bad); return err }()); f == nil || f.Reason != ReasonSourceDiffers {
			t.Fatalf("%s: differing CFN trust: %v", kind, f)
		}
	}
}

func jsonMarshal(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

// P1-12 (a): the split's PR text never claims that no permission changes
// without the effective-access qualification (§11, §9.7).
func TestSplitDescriptionQualifiesEffectiveAccess(t *testing.T) {
	split, revert, docs := splitPlans(t)
	split.Diff.Split.Compatibility = []igagov.CompatibilityItem{{Kind: igagov.CompatResourcePolicy, Resource: "arn:aws:sqs:us-east-1:" + acct + ":q",
		Handling: igagov.HandlingOwnerConfirm}}
	split.Unanalysed = []igagov.UnanalysedItem{{Key: "kms_grants"}, {Key: "lambda_version_without_alias:3"}}
	ch, err := Render(Request{Source: Source{Format: FormatTerraform, Directory: "m"}, Files: map[string]string{"m/main.tf": tfSplit}, Role: sharedRole(),
		Plan: split, Documents: docs})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []igagov.Plan{split, revert} {
		d := Describe(p, sharedRole(), ch)
		low := strings.ToLower(d.Body)
		for _, banned := range []string{"no permission is removed", "no permission change", "for anyone", "authorization unchanged"} {
			if strings.Contains(low, banned) {
				t.Fatalf("%s description makes an absolute claim (%q):\n%s", p.Kind, banned, d.Body)
			}
		}
		if p.Kind == igagov.PlanSplit {
			for _, want := range []string{"same identity policies", "not evaluated effective access", "does not follow unless updated",
				"1 confirmed by the owner", "KMS grants", "version 3 (behind no alias)"} {
				if !strings.Contains(d.Body, want) {
					t.Fatalf("split description lacks %q:\n%s", want, d.Body)
				}
			}
		}
	}
	a, err := Export(split, sharedRole(), docs, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(a.Description.Effect), "no permission") {
		t.Fatalf("export effect: %s", a.Description.Effect)
	}
}
