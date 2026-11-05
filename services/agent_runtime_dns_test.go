package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53resolver"
	r53rtypes "github.com/aws/aws-sdk-go-v2/service/route53resolver/types"
	"github.com/aws/smithy-go"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
)

// SPEC-agent-runtime-visibility.md §11: what the DNS read claims and to whom
// it attributes lookups, without a database. The write, the resolve and
// workspace isolation are in tests/integration/ar_dns_traffic_test.go.

type dnsFakeResolver struct {
	configs []r53rtypes.ResolverQueryLogConfig
	assocs  []r53rtypes.ResolverQueryLogConfigAssociation
	err     error
}

func (f *dnsFakeResolver) ListResolverQueryLogConfigs(context.Context, *route53resolver.ListResolverQueryLogConfigsInput, ...func(*route53resolver.Options)) (*route53resolver.ListResolverQueryLogConfigsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &route53resolver.ListResolverQueryLogConfigsOutput{ResolverQueryLogConfigs: f.configs}, nil
}

func (f *dnsFakeResolver) ListResolverQueryLogConfigAssociations(context.Context, *route53resolver.ListResolverQueryLogConfigAssociationsInput, ...func(*route53resolver.Options)) (*route53resolver.ListResolverQueryLogConfigAssociationsOutput, error) {
	return &route53resolver.ListResolverQueryLogConfigAssociationsOutput{ResolverQueryLogConfigAssociations: f.assocs}, nil
}

func dnsConfig(id, dest string) r53rtypes.ResolverQueryLogConfig {
	return r53rtypes.ResolverQueryLogConfig{Id: aws.String(id), Name: aws.String(id), DestinationArn: aws.String(dest)}
}

func dnsAssoc(config, vpc string) r53rtypes.ResolverQueryLogConfigAssociation {
	return r53rtypes.ResolverQueryLogConfigAssociation{ResolverQueryLogConfigId: aws.String(config), ResourceId: aws.String(vpc),
		Status: r53rtypes.ResolverQueryLogConfigAssociationStatusActive}
}

func dnsScanRegion(t *testing.T, r *dnsFakeResolver) *WorkloadSnapshot {
	t.Helper()
	s := (&AWSWorkloadScanner{}).WithDNSAPIs(func(string) DNSClients { return DNSClients{Resolver: r} })
	out := &WorkloadSnapshot{Surfaces: map[string]models.SurfaceCoverage{}, Errors: map[string]string{}}
	s.scanDNSQueryLogs(context.Background(), uuid.New(), &IAMSnapshot{ConnectorID: uuid.New()},
		arnScope{account: "111122223333"}, "us-east-1", out)
	return out
}

// A role without the new permission: the surface says denied, names the call
// and AWS's code and the template fact -- and nothing else is affected.
func TestDNSPermissionMissingIsCoverageNotFailure(t *testing.T) {
	out := dnsScanRegion(t, &dnsFakeResolver{err: &smithy.OperationError{ServiceID: "Route53Resolver",
		OperationName: "ListResolverQueryLogConfigs",
		Err:           &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized"}}})
	cov := out.Surfaces["dns-query-logs:us-east-1"]
	if cov.State != models.CloudCoverageDenied || cov.API != "route53resolver:ListResolverQueryLogConfigs" ||
		cov.ErrorCode != "AccessDeniedException" {
		t.Fatalf("coverage %+v", cov)
	}
	if !strings.Contains(cov.Error, "discovery template "+awsdiscovery.DNSQueryLogTemplateVersion) ||
		!strings.Contains(cov.Error, "reports no template version") {
		t.Errorf("the template fact is missing: %s", cov.Error)
	}
	if out.Surfaces[models.SurfaceDNSBlindSpots].State != models.CloudCoverageUnsupported {
		t.Error("the blind-spot entry must be reported whenever the DNS read ran")
	}
	if len(out.Errors) != 0 || out.DNSTrafficFindings != 0 {
		t.Errorf("a denied DNS read must not reach Errors (%v) or write findings", out.Errors)
	}
	// A stack already on the DNS template gets no such note.
	if c := withDNSTemplateNote(models.SurfaceCoverage{State: models.CloudCoverageDenied, ErrorCode: "AccessDeniedException", Error: "x"},
		awsdiscovery.DNSQueryLogTemplateVersion); c.Error != "x" {
		t.Errorf("note on a current stack: %s", c.Error)
	}
}

// S3 and Firehose destinations are listed, reported unsupported and never
// read; a log group in another account cannot be queried either.
func TestDNSUnsupportedDestinationsAreNotRead(t *testing.T) {
	out := dnsScanRegion(t, &dnsFakeResolver{
		configs: []r53rtypes.ResolverQueryLogConfig{
			dnsConfig("to-s3", "arn:aws:s3:::dns-logs"),
			dnsConfig("to-firehose", "arn:aws:firehose:us-east-1:111122223333:deliverystream/dns"),
			dnsConfig("other-account", "arn:aws:logs:us-east-1:999988887777:log-group:shared-dns"),
			dnsConfig("idle", "arn:aws:logs:us-east-1:111122223333:log-group:idle"),
		},
		assocs: []r53rtypes.ResolverQueryLogConfigAssociation{
			dnsAssoc("to-s3", "vpc-0aaa1111"), dnsAssoc("to-firehose", "vpc-0bbb2222"), dnsAssoc("other-account", "vpc-0ccc3333"),
		},
	})
	main := out.Surfaces["dns-query-logs:us-east-1"]
	unread := out.Surfaces["dns-query-logs-unread:us-east-1"]
	if main.State != models.CloudCoverageUnsupported || !strings.Contains(main.Error, "destinations AuthSec does not read") {
		t.Errorf("main surface %+v", main)
	}
	if unread.State != models.CloudCoverageUnsupported || unread.Count != 3 ||
		!strings.Contains(unread.Error, "vpc-0aaa1111") || !strings.Contains(unread.Error, "unsupported destination (s3)") ||
		!strings.Contains(unread.Error, "unsupported destination (firehose)") || !strings.Contains(unread.Error, "account 999988887777") {
		t.Errorf("unread surface %+v", unread)
	}
	if strings.Contains(unread.Error, "idle") {
		t.Error("a configuration logging no VPC here is not a coverage gap")
	}

	none := dnsScanRegion(t, &dnsFakeResolver{})
	if c := none.Surfaces["dns-query-logs:us-east-1"]; c.State != models.CloudCoverageUnsupported ||
		!strings.Contains(c.Error, "enable Resolver query logging") {
		t.Errorf("no query logging: %+v", c)
	}
}

func TestDNSPlanReadsEachLogGroupOnce(t *testing.T) {
	configs := []awsdiscovery.QueryLogConfig{
		{ID: "a", DestinationARN: "arn:aws:logs:us-east-1:111122223333:log-group:dns:*", DestinationKind: awsdiscovery.DNSDestinationCloudWatchLogs,
			DestinationRegion: "us-east-1", DestinationAccount: "111122223333",
			Associations: []awsdiscovery.QueryLogAssociation{{VPCID: "vpc-2", Status: "ACTIVE"}}},
		{ID: "b", DestinationARN: "arn:aws:logs:us-east-1:111122223333:log-group:dns", DestinationKind: awsdiscovery.DNSDestinationCloudWatchLogs,
			DestinationRegion: "us-east-1", DestinationAccount: "111122223333",
			Associations: []awsdiscovery.QueryLogAssociation{{VPCID: "vpc-1", Status: "ACTIVE"}}},
		{ID: "c", DestinationARN: "arn:aws:logs:eu-west-1:111122223333:log-group:dns", DestinationKind: awsdiscovery.DNSDestinationCloudWatchLogs,
			DestinationRegion: "eu-west-1", DestinationAccount: "111122223333",
			Associations: []awsdiscovery.QueryLogAssociation{{VPCID: "vpc-3", Status: "ACTIVE"}}},
	}
	groups, unread := planDNSDestinations(configs, "us-east-1", "111122223333")
	if len(groups) != 1 || groups[0].ARN != "arn:aws:logs:us-east-1:111122223333:log-group:dns" ||
		strings.Join(groups[0].VPCs, ",") != "vpc-1,vpc-2" || len(unread) != 1 || !strings.Contains(unread[0].Reason, "eu-west-1") {
		t.Fatalf("groups %+v unread %+v", groups, unread)
	}
}

func dnsTestInventory() dnsInventory {
	role := uuid.New()
	ws := []*dnsWorkload{
		{ID: uuid.New(), RuntimeKind: models.WorkloadEC2Instance, NativeID: "i-0abc123def456", Name: "web-1", Region: "us-east-1",
			IdentityID: &role, IdentityARN: "arn:aws:iam::111122223333:role/web"},
		{ID: uuid.New(), RuntimeKind: models.WorkloadLambdaFunction, NativeID: "arn:aws:lambda:us-east-1:111122223333:function:summarise",
			Name: "summarise", Region: "us-east-1"},
		{ID: uuid.New(), RuntimeKind: models.WorkloadLambdaFunction, NativeID: "arn:aws:lambda:us-east-1:111122223333:function:summarise-v2",
			Name: "summarise-v2", Region: "us-east-1"},
		{ID: uuid.New(), RuntimeKind: models.WorkloadECSTaskDefinition, NativeID: "arn:aws:ecs:us-east-1:111122223333:task-definition/ledger:7",
			Name: "ledger", Region: "us-east-1"},
	}
	inv := dnsInventory{byNative: map[string]*dnsWorkload{}}
	for _, w := range ws {
		inv.byNative[w.RuntimeKind+"\x1f"+w.NativeID] = w
		if w.RuntimeKind == models.WorkloadLambdaFunction {
			inv.lambdas = append(inv.lambdas, w)
		}
	}
	// longest first, as loadDNSInventory orders them
	inv.lambdas[0], inv.lambdas[1] = inv.lambdas[1], inv.lambdas[0]
	return inv
}

func TestDNSAttribution(t *testing.T) {
	inv := dnsTestInventory()
	agg := func(src, inst string) awsdiscovery.DNSLookupAggregate {
		return awsdiscovery.DNSLookupAggregate{SrcAddr: src, InstanceID: inst, VPCID: "vpc-0a1b2c3d", Domain: "api.openai.com", Provider: "openai", Queries: 1}
	}
	cases := []struct {
		name string
		a    awsdiscovery.DNSLookupAggregate
		attr dnsSourceAttr
		key  string
		how  string
		pod  string
	}{
		{"ec2 by srcids.instance", agg("10.0.1.30", "i-0abc123def456"), dnsSourceAttr{},
			"workload:ec2_instance:us-east-1:i-0abc123def456", "srcids_instance", ""},
		{"lambda by interface", agg("10.0.1.10", ""), dnsSourceAttr{ENI: &awsdiscovery.ENIInfo{Kind: awsdiscovery.ENIKindLambda, LambdaFunctionHint: "summarise-v2"}},
			"workload:lambda_function:us-east-1:arn:aws:lambda:us-east-1:111122223333:function:summarise-v2", "eni_lambda", ""},
		{"lambda by legacy interface name", agg("10.0.1.11", ""), dnsSourceAttr{ENI: &awsdiscovery.ENIInfo{Kind: awsdiscovery.ENIKindLambda, LambdaFunctionHint: "summarise-0f2c9a"}},
			"workload:lambda_function:us-east-1:arn:aws:lambda:us-east-1:111122223333:function:summarise", "eni_lambda", ""},
		{"lambda not in inventory", agg("10.0.1.12", ""), dnsSourceAttr{ENI: &awsdiscovery.ENIInfo{Kind: awsdiscovery.ENIKindLambda, LambdaFunctionHint: "ghost"}},
			"workload:lambda_function:us-east-1:arn:aws:lambda:us-east-1:111122223333:function:ghost", "eni_lambda", ""},
		{"ecs task", agg("10.0.1.20", ""), dnsSourceAttr{ENI: &awsdiscovery.ENIInfo{Kind: awsdiscovery.ENIKindECSTask, ID: "eni-ecs"},
			ECSTask: &awsdiscovery.ECSTaskRef{TaskARN: "t1", TaskDefinitionARN: "arn:aws:ecs:us-east-1:111122223333:task-definition/ledger:7"}},
			"workload:ecs_task_definition:us-east-1:arn:aws:ecs:us-east-1:111122223333:task-definition/ledger:7", "eni_ecs_task", ""},
		{"eks pod on a node", agg("10.0.1.31", "i-0abc123def456"), dnsSourceAttr{ENI: &awsdiscovery.ENIInfo{Kind: awsdiscovery.ENIKindInstance,
			InstanceID: "i-0abc123def456", PrimaryIP: false}},
			"workload:ec2_instance:us-east-1:i-0abc123def456", "srcids_instance", "unresolved"},
		{"eks cni interface", agg("10.0.1.40", ""), dnsSourceAttr{ENI: &awsdiscovery.ENIInfo{Kind: awsdiscovery.ENIKindEKSPod, InstanceID: "i-0abc123def456"}},
			"workload:ec2_instance:us-east-1:i-0abc123def456", "eni_instance", "unresolved"},
		{"ecs task not found", agg("10.0.1.21", ""), dnsSourceAttr{ENI: &awsdiscovery.ENIInfo{Kind: awsdiscovery.ENIKindECSTask, ID: "eni-gone"}},
			"vpc:us-east-1:vpc-0a1b2c3d", "unattributed", ""},
		{"nothing holds the address", agg("10.0.9.9", ""), dnsSourceAttr{},
			"vpc:us-east-1:vpc-0a1b2c3d", "unattributed", ""},
		{"lookup failed", agg("10.0.9.8", ""), dnsSourceAttr{Err: "ec2:DescribeNetworkInterfaces AccessDenied"},
			"vpc:us-east-1:vpc-0a1b2c3d", "unattributed", ""},
	}
	for _, c := range cases {
		s := attributeDNSLookups(c.a, c.attr, inv, "us-east-1", "111122223333", "aws")
		if s.Key != c.key || s.Attribution.How != c.how || s.Attribution.PodLevel != c.pod {
			t.Errorf("%s: key %q how %q pod %q", c.name, s.Key, s.Attribution.How, s.Attribution.PodLevel)
		}
	}
	ec2 := attributeDNSLookups(agg("10.0.1.30", "i-0abc123def456"), dnsSourceAttr{}, inv, "us-east-1", "111122223333", "aws")
	if ec2.IdentityID == nil || ec2.Subject["identity_arn"] != "arn:aws:iam::111122223333:role/web" || ec2.Attribution.Confidence != "query_time" {
		t.Errorf("ec2 subject %+v", ec2)
	}
	unknown := attributeDNSLookups(agg("10.0.9.9", ""), dnsSourceAttr{}, inv, "us-east-1", "111122223333", "aws")
	if unknown.Subject["kind"] != "vpc" || unknown.IdentityID != nil ||
		!strings.Contains(unknown.Attribution.Note, "model traffic from an unknown source in VPC vpc-0a1b2c3d") {
		t.Errorf("unknown subject %+v", unknown)
	}
}

// The evidence document: counts add across scans, providers and the control
// flag are derived, and it holds only the listed hosts it was given.
func TestDNSEvidenceMerges(t *testing.T) {
	t0 := time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)
	var first dnsTrafficDoc
	first.add(awsdiscovery.DNSLookupAggregate{SrcAddr: "10.0.1.5", VPCID: "vpc-1", Domain: "bedrock-runtime.us-east-1.amazonaws.com",
		Provider: "aws_bedrock", Control: true, Queries: 2, FirstSeen: t0, LastSeen: t0.Add(time.Hour)}, dnsSourceAttr{})
	first.finish()
	if !first.ControlOnly || first.Queries != 2 {
		t.Fatalf("first %+v", first)
	}
	var second dnsTrafficDoc
	second.add(awsdiscovery.DNSLookupAggregate{SrcAddr: "10.0.1.5", VPCID: "vpc-1", Domain: "api.openai.com", Provider: "openai",
		Queries: 3, FirstSeen: t0.Add(2 * time.Hour), LastSeen: t0.Add(3 * time.Hour)}, dnsSourceAttr{})
	second.add(awsdiscovery.DNSLookupAggregate{SrcAddr: "10.0.1.5", VPCID: "vpc-1", Domain: "bedrock-runtime.us-east-1.amazonaws.com",
		Provider: "aws_bedrock", Control: true, Queries: 1, FirstSeen: t0.Add(2 * time.Hour), LastSeen: t0.Add(2 * time.Hour)}, dnsSourceAttr{})
	second.finish()
	merged := first.merge(&second)
	if merged.Queries != 6 || merged.ControlOnly || strings.Join(merged.Providers, ",") != "aws_bedrock,openai" ||
		!merged.FirstSeen.Equal(t0) || !merged.LastSeen.Equal(t0.Add(3*time.Hour)) {
		t.Fatalf("merged %+v", merged)
	}
	if len(merged.Domains) != 2 || merged.Domains[1].Domain != "bedrock-runtime.us-east-1.amazonaws.com" || merged.Domains[1].Queries != 3 {
		t.Errorf("domains %+v", merged.Domains)
	}
	if len(merged.Sources) != 1 || merged.Sources[0].Queries != 6 {
		t.Errorf("sources %+v", merged.Sources)
	}
	if len(merged.Limitations) == 0 || merged.Source != "route53_resolver_query_logs" {
		t.Error("limitations and source must travel with the evidence")
	}
}

func TestDNSCoverage(t *testing.T) {
	g := func(n string) dnsLogGroup { return dnsLogGroup{ARN: n} }
	whole := dnsLogGroupRead{Group: g("a"), Read: awsdiscovery.DNSQueryRead{Settled: true}}
	if c := dnsCoverage([]dnsLogGroupRead{whole, {Group: g("b"), Skipped: true, Read: awsdiscovery.DNSQueryRead{Settled: true}}}, nil, nil); c.State != models.CloudCoverageReached || c.Count != 2 {
		t.Errorf("whole reads: %+v", c)
	}
	truncated := dnsLogGroupRead{Group: g("t"), Read: awsdiscovery.DNSQueryRead{Settled: true, Truncated: true}}
	lapsed := dnsLogGroupRead{Group: g("l"), Read: awsdiscovery.DNSQueryRead{Settled: true, Window: awsdiscovery.DNSWindow{Lapsed: true}}}
	failed := dnsLogGroupRead{Group: g("f"), Err: errors.New("logs:StartQuery: boom")}
	c := dnsCoverage([]dnsLogGroupRead{whole, truncated, lapsed, failed}, []dnsLogGroup{g("over-cap")}, nil)
	if c.State != models.CloudCoveragePartial || c.Count != 3 || !strings.Contains(c.Error, "1 of 5 log groups read whole") ||
		!strings.Contains(c.Error, "row limit") || !strings.Contains(c.Error, "only the last") || !strings.Contains(c.Error, "per-scan cap") ||
		!strings.Contains(c.Error, "f: logs:StartQuery: boom") {
		t.Errorf("partial: %+v", c)
	}
	if c := dnsCoverage([]dnsLogGroupRead{failed}, nil, nil); c.State != models.CloudCoverageDenied || !strings.Contains(c.Error, "1 of 1 log groups could not be read") {
		t.Errorf("all failed: %+v", c)
	}
	if c := dnsCoverage([]dnsLogGroupRead{whole}, nil, errors.New("db down")); c.State != models.CloudCoverageDenied {
		t.Errorf("write failed: %+v", c)
	}
}

func TestDNSKillSwitch(t *testing.T) {
	t.Setenv(envDNSQueryLogs, "off")
	out := dnsScanRegion(t, &dnsFakeResolver{err: errors.New("must not be called")})
	if c := out.Surfaces["dns-query-logs:us-east-1"]; c.State != models.CloudCoverageNotSelected {
		t.Fatalf("kill switch: %+v", c)
	}
}

func TestDNSFindingKindIsListable(t *testing.T) {
	if !FindingKinds[FindingAINetworkTraffic] || !findingKindsOutsideInference[FindingAINetworkTraffic] {
		t.Fatal("ai_network_traffic must be a listable kind the inference pass leaves alone")
	}
}
