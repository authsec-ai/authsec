package igagov

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// CatalogVersion is the version of every catalog in this file (§3.7,
// `catalog@N`; iga_gov_policy_version.catalog_version). A newer catalog never
// widens or narrows a deployed boundary; it changes new compilations only
// (C-03). Bump it whenever any table below changes meaning.
const CatalogVersion = 1

// CatalogLabel renders the version as the spec writes it: "catalog@1".
func CatalogLabel() string { return "catalog@" + strconv.Itoa(CatalogVersion) }

/* ---------------------------- dependency catalog -------------------------- */

// Dependency contexts (§3.7 dependency catalog, "Context (from the graph)").
// Each is cited as "<context>@<catalog version>", e.g. "ecs-task-execution@1"
// (§2.7 retain basis "dependency").
const (
	CtxLambdaExecution  = "lambda-execution"
	CtxECSTaskExecution = "ecs-task-execution"
	CtxECSTaskRole      = "ecs-task-role"
	CtxEC2InstanceRole  = "ec2-instance-profile"
	CtxBedrockAgent     = "bedrock-agent"
	CtxAgentCoreRuntime = "agentcore-runtime"
	CtxKMSViaService    = "kms-via-service"
)

// DependencyContext is one way a role is used, as the graph shows it, with
// the conditional facts the catalog needs (§3.7).
type DependencyContext struct {
	Context string
	// TracingActive: a Lambda's TracingConfig.Mode is Active (retain xray).
	TracingActive bool
	// ReferencesSecrets: an ECS task definition references secrets (retain
	// secretsmanager, ssm, kms).
	ReferencesSecrets bool
}

// Dependency is one service the catalog says to always retain, with the
// catalog reference a retain entry cites and a human reason.
type Dependency struct {
	Service string `json:"service"`
	Catalog string `json:"catalog"`
	Reason  string `json:"reason"`
}

type depRule struct {
	always      []string
	tracing     []string
	secrets     []string
	description string
}

// dependencyCatalog is §3.7's dependency table as data. ECS task roles and
// EC2 instance-profile roles retain nothing: their only implicit need,
// sts:GetCallerIdentity, requires no permission and cannot be denied by a
// boundary.
var dependencyCatalog = map[string]depRule{
	CtxLambdaExecution:  {always: []string{"logs"}, tracing: []string{"xray"}, description: "Lambda execution role"},
	CtxECSTaskExecution: {always: []string{"ecr", "logs"}, secrets: []string{"kms", "secretsmanager", "ssm"}, description: "ECS task execution role"},
	CtxECSTaskRole:      {description: "ECS task role"},
	CtxEC2InstanceRole:  {description: "EC2 instance profile role"},
	CtxBedrockAgent:     {always: []string{"bedrock", "bedrock-agentcore", "logs"}, description: "Bedrock agent role"},
	CtxAgentCoreRuntime: {always: []string{"bedrock", "bedrock-agentcore", "logs"}, description: "AgentCore runtime role"},
	CtxKMSViaService:    {always: []string{"kms"}, description: "statement using kms:ViaService"},
}

// DependencyContextFor maps a graph workload's runtime_kind and the
// relationship it has to the role (executes_as, task_execution_role) to a
// dependency context (§3.7). ok=false when the catalog has no row for it.
func DependencyContextFor(runtimeKind, relationship string) (string, bool) {
	switch {
	case runtimeKind == "lambda_function" && relationship == RelExecutesAs:
		return CtxLambdaExecution, true
	case runtimeKind == "ecs_task_definition" && relationship == RelTaskExecutionRole:
		return CtxECSTaskExecution, true
	case runtimeKind == "ecs_task_definition" && relationship == RelExecutesAs:
		return CtxECSTaskRole, true
	case runtimeKind == "ec2_instance" && relationship == RelExecutesAs:
		return CtxEC2InstanceRole, true
	case runtimeKind == "bedrock_agent" && relationship == RelExecutesAs:
		return CtxBedrockAgent, true
	case (runtimeKind == "bedrock_agentcore_runtime" || runtimeKind == "bedrock_agentcore_gateway") && relationship == RelExecutesAs:
		return CtxAgentCoreRuntime, true
	}
	return "", false
}

// DependencyRef renders a context as a retain entry's catalog reference.
func DependencyRef(context string) string {
	return context + "@" + strconv.Itoa(CatalogVersion)
}

// ParseDependencyRef checks a "<context>@<version>" reference against the
// catalog: a known context and a version no newer than this catalog.
func ParseDependencyRef(ref string) (context string, version int, err error) {
	i := strings.LastIndexByte(ref, '@')
	if i <= 0 {
		return "", 0, fmt.Errorf("catalog reference %q is not <context>@<version>", ref)
	}
	context = ref[:i]
	version, err = strconv.Atoi(ref[i+1:])
	if err != nil || version < 1 || version > CatalogVersion {
		return "", 0, fmt.Errorf("catalog reference %q names an unknown catalog version", ref)
	}
	if _, ok := dependencyCatalog[context]; !ok {
		return "", 0, fmt.Errorf("catalog reference %q names an unknown context", ref)
	}
	return context, version, nil
}

// Dependencies returns every service the dependency catalog retains for a
// role's contexts (§3.7 "D"), one entry per service (the first context in
// sorted order names it), sorted by service.
func Dependencies(ctxs []DependencyContext) []Dependency {
	sorted := append([]DependencyContext{}, ctxs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Context < sorted[j].Context })
	seen := map[string]bool{}
	var out []Dependency
	add := func(ctx, svc, why string) {
		if seen[svc] {
			return
		}
		seen[svc] = true
		out = append(out, Dependency{Service: svc, Catalog: DependencyRef(ctx), Reason: why})
	}
	for _, c := range sorted {
		rule, ok := dependencyCatalog[c.Context]
		if !ok {
			continue
		}
		for _, s := range rule.always {
			add(c.Context, s, rule.description)
		}
		if c.TracingActive {
			for _, s := range rule.tracing {
				add(c.Context, s, rule.description+" with active tracing")
			}
		}
		if c.ReferencesSecrets {
			for _, s := range rule.secrets {
				add(c.Context, s, rule.description+" referencing secrets")
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Service < out[j].Service })
	return out
}

// IsDependency reports whether service is in D for these contexts (§3.4 (1):
// a removal must not be a dependency of the workload context).
func IsDependency(service string, ctxs []DependencyContext) (Dependency, bool) {
	for _, d := range Dependencies(ctxs) {
		if d.Service == service {
			return d, true
		}
	}
	return Dependency{}, false
}

/* ----------------------------- tracking catalog --------------------------- */

// TrackingDocumentedAt is when the tracking data below was taken from the AWS
// IAM User Guide, "Refine permissions in AWS using last accessed information
// › Where AWS tracks last accessed information".
var TrackingDocumentedAt = time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)

func day(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

// regionTrackingStart is the AWS table of the date each Region began
// tracking service last accessed information. A Region absent from it "does
// not yet provide last accessed information".
var regionTrackingStart = map[string]time.Time{
	"us-east-2":      day(2017, time.October, 27),
	"us-east-1":      day(2015, time.October, 1),
	"us-west-1":      day(2015, time.October, 1),
	"us-west-2":      day(2015, time.October, 1),
	"af-south-1":     day(2020, time.April, 22),
	"ap-east-1":      day(2019, time.April, 24),
	"ap-south-2":     day(2022, time.November, 22),
	"ap-southeast-3": day(2021, time.December, 13),
	"ap-southeast-4": day(2023, time.January, 23),
	"ap-south-1":     day(2016, time.June, 27),
	"ap-northeast-3": day(2018, time.February, 11),
	"ap-northeast-2": day(2016, time.January, 6),
	"ap-southeast-1": day(2015, time.October, 1),
	"ap-southeast-2": day(2015, time.October, 1),
	"ap-northeast-1": day(2015, time.October, 1),
	"ca-central-1":   day(2017, time.October, 28),
	"eu-central-1":   day(2015, time.October, 1),
	"eu-west-1":      day(2015, time.October, 1),
	"eu-west-2":      day(2017, time.October, 28),
	"eu-south-1":     day(2020, time.April, 28),
	"eu-west-3":      day(2017, time.December, 18),
	"eu-south-2":     day(2022, time.November, 15),
	"eu-north-1":     day(2018, time.December, 12),
	"eu-central-2":   day(2022, time.November, 8),
	"il-central-1":   day(2023, time.August, 1),
	"me-south-1":     day(2019, time.July, 29),
	"me-central-1":   day(2022, time.August, 30),
	"sa-east-1":      day(2015, time.December, 11),
	"us-gov-east-1":  day(2023, time.July, 1),
	"us-gov-west-1":  day(2023, time.July, 1),
}

// trackedServices lists the service namespaces the tracking catalog covers
// for service-level last accessed information. AWS documents service-level
// tracking per Region, not per service, so this list is AuthSec's explicit
// allowlist of the IAM service namespaces R1a will reason about; adding one
// is a catalog change (bump CatalogVersion). The value is a service-specific
// start later than every Region's (zero = the Region dates alone; none is
// recorded in catalog@1). A namespace absent from this table yields
// `unreviewed`, never `unused_service` (§3.7).
var trackedServices = map[string]time.Time{
	"acm": {}, "apigateway": {}, "athena": {}, "autoscaling": {}, "backup": {},
	"bedrock": {}, "cloudformation": {}, "cloudfront": {}, "cloudtrail": {},
	"cloudwatch": {}, "codebuild": {}, "codecommit": {}, "codedeploy": {},
	"codepipeline": {}, "cognito-idp": {}, "dynamodb": {}, "ec2": {}, "ecr": {},
	"ecs": {}, "eks": {}, "elasticache": {}, "elasticfilesystem": {},
	"elasticloadbalancing": {}, "es": {}, "events": {}, "firehose": {}, "glue": {},
	"iam": {}, "kinesis": {}, "kms": {}, "lambda": {}, "logs": {}, "rds": {},
	"redshift": {}, "route53": {}, "s3": {}, "sagemaker": {}, "secretsmanager": {},
	"ses": {}, "sns": {}, "sqs": {}, "ssm": {}, "states": {}, "sts": {},
	"xray": {},
}

// TrackingStart is §2.6's catalog.tracking_start(S, region set): the latest
// tracking start over the account's enabled Regions (attempts in a Region
// that started tracking later are invisible before that date), raised to the
// service's own start when it has one. ok=false, with the reason, when S is
// not in the catalog or a Region in the set does not provide last accessed
// information at all — both make S `unreviewed` (DECISION D7).
func TrackingStart(service string, regions []string) (time.Time, bool, string) {
	svcStart, ok := trackedServices[service]
	if !ok {
		return time.Time{}, false, "service_not_in_tracking_catalog"
	}
	if len(regions) == 0 {
		return time.Time{}, false, "no_enabled_regions"
	}
	start := svcStart
	for _, r := range sortedUnique(regions) {
		rs, ok := regionTrackingStart[r]
		if !ok {
			return time.Time{}, false, "region_not_tracked:" + r
		}
		if rs.After(start) {
			start = rs
		}
	}
	return start, true, ""
}

/* -------------------------- policy-bearing forms -------------------------- */

// Form collection states (§3.7).
const (
	FormCollected   = "collected"
	FormUncollected = "uncollected"
)

// Form scopes (§3.9 "Scope" column).
const (
	ScopeRegion  = "region"
	ScopeAccount = "account"
)

// PolicyBearingForm is a resource form that can carry a resource-based
// policy (§3.7). Name equals cloud_resource_policy_coverage.resource_form for
// collected forms (056 CHECK); Namespace is the IAM action namespace its
// policy grants.
type PolicyBearingForm struct {
	Name      string
	Namespace string
	State     string
	Scope     string
}

// FormsDocumentedAt is when the policy-bearing forms list was taken from
// AWS's "AWS services that work with IAM" (resource-based policies column).
var FormsDocumentedAt = time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)

// policyBearingForms is §3.7's forms catalog. Collected forms are exactly
// §3.9's table (and 056's resource_form CHECK); the rest are uncollected in
// R1a and appear as `unanalysed` wherever a proof would need them.
var policyBearingForms = []PolicyBearingForm{
	{"s3_bucket", "s3", FormCollected, ScopeAccount},
	{"s3_directory_bucket", "s3express", FormCollected, ScopeRegion},
	{"s3_access_point", "s3", FormCollected, ScopeRegion},
	{"s3_multi_region_access_point", "s3", FormCollected, ScopeAccount},
	{"s3_object_lambda_access_point", "s3-object-lambda", FormCollected, ScopeRegion},
	{"kms_key", "kms", FormCollected, ScopeRegion},
	{"sqs_queue", "sqs", FormCollected, ScopeRegion},
	{"sns_topic", "sns", FormCollected, ScopeRegion},
	{"lambda_function", "lambda", FormCollected, ScopeRegion},
	{"lambda_function_version", "lambda", FormCollected, ScopeRegion},
	{"lambda_alias", "lambda", FormCollected, ScopeRegion},
	{"lambda_layer_version", "lambda", FormCollected, ScopeRegion},
	{"secretsmanager_secret", "secretsmanager", FormCollected, ScopeRegion},

	{"ecr_repository", "ecr", FormUncollected, ScopeRegion},
	{"ecr_registry", "ecr", FormUncollected, ScopeRegion},
	{"events_event_bus", "events", FormUncollected, ScopeRegion},
	{"apigateway_rest_api", "execute-api", FormUncollected, ScopeRegion},
	{"glue_data_catalog", "glue", FormUncollected, ScopeRegion},
	{"backup_vault", "backup", FormUncollected, ScopeRegion},
	{"opensearch_domain", "es", FormUncollected, ScopeRegion},
	{"logs_resource_policy", "logs", FormUncollected, ScopeRegion},
	{"logs_destination", "logs", FormUncollected, ScopeRegion},
	{"dynamodb_table", "dynamodb", FormUncollected, ScopeRegion},
	{"dynamodb_stream", "dynamodb", FormUncollected, ScopeRegion},
	{"kinesis_stream", "kinesis", FormUncollected, ScopeRegion},
	{"efs_file_system", "elasticfilesystem", FormUncollected, ScopeRegion},
	{"glacier_vault", "glacier", FormUncollected, ScopeRegion},
	{"codeartifact_domain", "codeartifact", FormUncollected, ScopeRegion},
	{"codeartifact_repository", "codeartifact", FormUncollected, ScopeRegion},
	{"ses_identity", "ses", FormUncollected, ScopeRegion},
	{"serverlessrepo_application", "serverlessrepo", FormUncollected, ScopeRegion},
}

// FormsForNamespace returns the policy-bearing forms whose policies grant
// actions of namespace ns, sorted by name.
func FormsForNamespace(ns string) []PolicyBearingForm {
	var out []PolicyBearingForm
	for _, f := range policyBearingForms {
		if f.Namespace == ns {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// LookupForm returns a form by name.
func LookupForm(name string) (PolicyBearingForm, bool) {
	for _, f := range policyBearingForms {
		if f.Name == name {
			return f, true
		}
	}
	return PolicyBearingForm{}, false
}

// AllForms returns the whole forms catalog sorted by name.
func AllForms() []PolicyBearingForm {
	out := append([]PolicyBearingForm{}, policyBearingForms...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

/* ---------------------------- escalation catalog -------------------------- */

// EscalationAction is one pattern that makes a statement a broad_grant
// (§3.7). OnWildcardResource: only when the statement's Resource is "*".
type EscalationAction struct {
	Pattern            string
	OnWildcardResource bool
}

var escalationCatalog = []EscalationAction{
	{"iam:PassRole", true},
	{"iam:Create*", false},
	{"iam:Attach*", false},
	{"iam:Put*Policy", false},
	{"iam:UpdateAssumeRolePolicy", false},
	{"sts:AssumeRole", true},
	{"lambda:UpdateFunctionCode", true},
}

// EscalationActions returns the escalation catalog (§3.7).
func EscalationActions() []EscalationAction {
	return append([]EscalationAction{}, escalationCatalog...)
}

// EscalationsGranted returns the escalation patterns an Allow statement
// grants (§2.5 broad_grant, §3.7), sorted. An Action pattern counts when it
// can match some action the escalation pattern matches ("iam:*", "iam:C*",
// "iam:CreateRole" all grant "iam:Create*"). A NotAction statement grants an
// escalation unless a NotAction entry excludes it whole (the same pattern,
// "*" or "<ns>:*"), which is conservative: it may report an escalation a
// finer exclusion actually removes, never miss one.
func EscalationsGranted(st Statement) []string {
	if st.Effect != EffectAllow {
		return nil
	}
	wild := st.ResourceIsWildcard()
	var out []string
	for _, e := range escalationCatalog {
		if e.OnWildcardResource && !wild {
			continue
		}
		granted := false
		if st.IsNotAction {
			granted = true
			ens, _, _ := SplitAction(e.Pattern)
			for _, n := range st.NotAction {
				if strings.EqualFold(n, e.Pattern) || patternCoversWholeNamespace(n, ens) {
					granted = false
					break
				}
			}
		} else {
			for _, p := range st.Action {
				if globsIntersect(p, e.Pattern) {
					granted = true
					break
				}
			}
		}
		if granted {
			out = append(out, e.Pattern)
		}
	}
	sort.Strings(out)
	return out
}
