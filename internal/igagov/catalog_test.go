package igagov

import (
	"strings"
	"testing"
	"time"
)

func TestDependencies(t *testing.T) {
	cases := []struct {
		name string
		ctxs []DependencyContext
		want string // service@context, comma-joined
	}{
		{"lambda keeps logs", []DependencyContext{{Context: CtxLambdaExecution}}, "logs@lambda-execution@1"},
		{"lambda with tracing keeps xray", []DependencyContext{{Context: CtxLambdaExecution, TracingActive: true}},
			"logs@lambda-execution@1,xray@lambda-execution@1"},
		{"ecs task execution", []DependencyContext{{Context: CtxECSTaskExecution}}, "ecr@ecs-task-execution@1,logs@ecs-task-execution@1"},
		{"ecs task execution with secrets", []DependencyContext{{Context: CtxECSTaskExecution, ReferencesSecrets: true}},
			"ecr@ecs-task-execution@1,kms@ecs-task-execution@1,logs@ecs-task-execution@1,secretsmanager@ecs-task-execution@1,ssm@ecs-task-execution@1"},
		{"ecs task role keeps nothing", []DependencyContext{{Context: CtxECSTaskRole}}, ""},
		{"ec2 instance role keeps nothing", []DependencyContext{{Context: CtxEC2InstanceRole}}, ""},
		{"bedrock agent", []DependencyContext{{Context: CtxBedrockAgent}},
			"bedrock@bedrock-agent@1,bedrock-agentcore@bedrock-agent@1,logs@bedrock-agent@1"},
		{"kms via service", []DependencyContext{{Context: CtxKMSViaService}}, "kms@kms-via-service@1"},
		{"union, first context in order names it", []DependencyContext{{Context: CtxLambdaExecution}, {Context: CtxECSTaskExecution}},
			"ecr@ecs-task-execution@1,logs@ecs-task-execution@1"},
		{"unknown context ignored", []DependencyContext{{Context: "nope"}}, ""},
	}
	for _, c := range cases {
		var got []string
		for _, d := range Dependencies(c.ctxs) {
			got = append(got, d.Service+"@"+d.Catalog)
		}
		if strings.Join(got, ",") != c.want {
			t.Errorf("%s: got %v want %s", c.name, got, c.want)
		}
	}
	if _, ok := IsDependency("logs", []DependencyContext{{Context: CtxLambdaExecution}}); !ok {
		t.Error("a Lambda role keeps logs")
	}
	if _, ok := IsDependency("sqs", []DependencyContext{{Context: CtxLambdaExecution}}); ok {
		t.Error("sqs is not a Lambda dependency")
	}
}

func TestDependencyContextFor(t *testing.T) {
	cases := map[[2]string]string{
		{"lambda_function", RelExecutesAs}:            CtxLambdaExecution,
		{"ecs_task_definition", RelTaskExecutionRole}: CtxECSTaskExecution,
		{"ecs_task_definition", RelExecutesAs}:        CtxECSTaskRole,
		{"ec2_instance", RelExecutesAs}:               CtxEC2InstanceRole,
		{"bedrock_agent", RelExecutesAs}:              CtxBedrockAgent,
		{"bedrock_agentcore_runtime", RelExecutesAs}:  CtxAgentCoreRuntime,
		{"bedrock_agentcore_gateway", RelExecutesAs}:  CtxAgentCoreRuntime,
	}
	for in, want := range cases {
		if got, ok := DependencyContextFor(in[0], in[1]); !ok || got != want {
			t.Errorf("%v: %s %v", in, got, ok)
		}
	}
	if _, ok := DependencyContextFor("lambda_function", RelTaskExecutionRole); ok {
		t.Error("no row for a Lambda task_execution_role")
	}
}

func TestParseDependencyRef(t *testing.T) {
	if c, v, err := ParseDependencyRef("ecs-task-execution@1"); err != nil || c != CtxECSTaskExecution || v != 1 {
		t.Fatalf("%s %d %v", c, v, err)
	}
	for _, bad := range []string{"ecs-task-execution", "ecs-task-execution@2", "nope@1", "@1", "x@y"} {
		if _, _, err := ParseDependencyRef(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if DependencyRef(CtxLambdaExecution) != "lambda-execution@1" || CatalogLabel() != "catalog@1" {
		t.Fatal("catalog labels")
	}
}

func TestTrackingStart(t *testing.T) {
	d := func(y int, m time.Month, dd int) time.Time { return time.Date(y, m, dd, 0, 0, 0, 0, time.UTC) }
	cases := []struct {
		svc     string
		regions []string
		want    time.Time
		ok      bool
		reason  string
	}{
		{"sqs", []string{"us-east-1"}, d(2015, 10, 1), true, ""},
		{"sqs", []string{"us-east-1", "us-east-2", "eu-west-1"}, d(2017, 10, 27), true, ""},
		{"sqs", []string{"us-east-1", "il-central-1"}, d(2023, 8, 1), true, ""},
		{"sqs", []string{"us-east-1", "xx-nowhere-1"}, time.Time{}, false, "region_not_tracked:xx-nowhere-1"},
		{"notaservice", []string{"us-east-1"}, time.Time{}, false, "service_not_in_tracking_catalog"},
		{"sqs", nil, time.Time{}, false, "no_enabled_regions"},
	}
	for _, c := range cases {
		got, ok, reason := TrackingStart(c.svc, c.regions)
		if ok != c.ok || !got.Equal(c.want) || reason != c.reason {
			t.Errorf("%s %v: %v %v %q", c.svc, c.regions, got, ok, reason)
		}
	}
}

func TestFormsCatalog(t *testing.T) {
	// Collected forms are exactly 056's resource_form CHECK list (§3.9).
	collected := map[string]bool{}
	for _, f := range AllForms() {
		if f.State == FormCollected {
			collected[f.Name] = true
		}
	}
	want := []string{"s3_bucket", "s3_directory_bucket", "s3_access_point", "s3_multi_region_access_point",
		"s3_object_lambda_access_point", "kms_key", "sqs_queue", "sns_topic", "lambda_function",
		"lambda_function_version", "lambda_alias", "lambda_layer_version", "secretsmanager_secret"}
	if len(collected) != len(want) {
		t.Fatalf("collected forms %v", collected)
	}
	for _, w := range want {
		if !collected[w] {
			t.Errorf("collected form %s missing", w)
		}
	}
	if f, ok := LookupForm("ecr_repository"); !ok || f.State != FormUncollected || f.Namespace != "ecr" {
		t.Fatal("ECR repositories are uncollected in R1a")
	}
	var lam []string
	for _, f := range FormsForNamespace("lambda") {
		lam = append(lam, f.Name)
	}
	if strings.Join(lam, ",") != "lambda_alias,lambda_function,lambda_function_version,lambda_layer_version" {
		t.Fatalf("lambda forms %v", lam)
	}
	if len(FormsForNamespace("ec2")) != 0 {
		t.Fatal("EC2 has no policy-bearing form in the catalog")
	}
}

func TestEscalationsGranted(t *testing.T) {
	st := func(js string) Statement {
		d, err := DecodePolicyDocument(`{"Statement":` + js + `}`)
		if err != nil {
			t.Fatal(err)
		}
		return d.Statements[0]
	}
	cases := []struct {
		js   string
		want string
	}{
		{`{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}`, "iam:PassRole"},
		{`{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::1:role/x"}`, ""},
		{`{"Effect":"Allow","Action":"iam:CreateRole","Resource":"arn:aws:iam::1:role/x"}`, "iam:Create*"},
		{`{"Effect":"Allow","Action":"iam:*","Resource":"*"}`,
			"iam:Attach*,iam:Create*,iam:PassRole,iam:Put*Policy,iam:UpdateAssumeRolePolicy"},
		{`{"Effect":"Allow","Action":"iam:Get*","Resource":"*"}`, ""},
		{`{"Effect":"Allow","Action":"iam:PutRolePolicy","Resource":"arn:x"}`, "iam:Put*Policy"},
		{`{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}`, "sts:AssumeRole"},
		{`{"Effect":"Allow","Action":"lambda:UpdateFunctionCode","NotResource":"arn:x"}`, "lambda:UpdateFunctionCode"},
		{`{"Effect":"Deny","Action":"*","Resource":"*"}`, ""},
		{`{"Effect":"Allow","NotAction":["iam:*","sts:*","lambda:*"],"Resource":"*"}`, ""},
		{`{"Effect":"Allow","NotAction":"s3:*","Resource":"*"}`,
			"iam:Attach*,iam:Create*,iam:PassRole,iam:Put*Policy,iam:UpdateAssumeRolePolicy,lambda:UpdateFunctionCode,sts:AssumeRole"},
	}
	for _, c := range cases {
		if got := strings.Join(EscalationsGranted(st(c.js)), ","); got != c.want {
			t.Errorf("%s: got %q want %q", c.js, got, c.want)
		}
	}
}
