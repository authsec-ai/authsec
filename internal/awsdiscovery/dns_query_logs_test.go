package awsdiscovery

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/route53resolver"
	r53rtypes "github.com/aws/aws-sdk-go-v2/service/route53resolver/types"
	"github.com/aws/smithy-go"
)

// The model-endpoint list: exact hosts, suffix families, case and the
// trailing dot -- and nothing that merely contains a provider's name.
func TestDNSModelEndpointMatching(t *testing.T) {
	match := map[string]string{
		"api.openai.com.":                               "openai",
		"API.OpenAI.com":                                "openai",
		"my-resource.openai.azure.com.":                 "azure_openai",
		"a.b.openai.azure.com":                          "azure_openai",
		"api.anthropic.com.":                            "anthropic",
		"generativelanguage.googleapis.com.":            "google_gemini",
		"aiplatform.googleapis.com.":                    "google_vertex",
		"us-central1-aiplatform.googleapis.com.":        "google_vertex",
		"europe-west4.aiplatform.googleapis.com.":       "google_vertex",
		"api.mistral.ai.":                               "mistral",
		"api.cohere.com.":                               "cohere",
		"api.cohere.ai.":                                "cohere",
		"api.groq.com.":                                 "groq",
		"openrouter.ai.":                                "openrouter",
		"api-inference.huggingface.co.":                 "huggingface",
		"router.huggingface.co.":                        "huggingface",
		"api.together.xyz.":                             "together",
		"api.fireworks.ai.":                             "fireworks",
		"api.deepseek.com.":                             "deepseek",
		"api.x.ai.":                                     "xai",
		"bedrock-runtime.us-east-1.amazonaws.com.":      "aws_bedrock",
		"bedrock-runtime-fips.us-west-2.amazonaws.com.": "aws_bedrock",
	}
	for name, provider := range match {
		ep, _, ok := MatchModelEndpoint(name)
		if !ok || ep.Provider != provider {
			t.Errorf("%q: matched %v %q, want %q", name, ok, ep.Provider, provider)
		}
	}
	for _, name := range []string{
		"openai.com.", "api.openai.com.evil.example.", "notapi.openai.com.", "xapi.openai.com.",
		"openai.azure.com.", "api.anthropic.com.cn.", "chat.openai.com.", "openrouter.ai.example.com.",
		"bedrock.us-east-1.amazonaws.com.", "bedrock-agent-runtime.us-east-1.amazonaws.com.",
		"s3.amazonaws.com.", "www.google.com.", "api..openai.com.", "", "api.openai.com..", "api.x.ai.evil.",
	} {
		if ep, _, ok := MatchModelEndpoint(name); ok {
			t.Errorf("%q matched %q; must not", name, ep.Provider)
		}
	}
	if ep, _ := ModelEndpoints, 0; ep[len(ep)-1].Provider != "aws_bedrock" || !ep[len(ep)-1].Control {
		t.Fatal("bedrock-runtime must be on the list as the control")
	}
}

// The in-query filter and the per-row check are the same list: the Insights
// regex (read with Go's RE2, which shares the syntax used) admits exactly
// what MatchModelEndpoint admits, so the query never returns -- and AuthSec
// never sees -- a domain the list does not name.
func TestDNSInsightsFilterAgreesWithTheList(t *testing.T) {
	pattern := ModelEndpointInsightsRegex()
	re := regexp.MustCompile(pattern)
	for _, name := range []string{
		"api.openai.com.", "API.OPENAI.COM.", "x.openai.azure.com.", "us-east5-aiplatform.googleapis.com.",
		"bedrock-runtime.eu-west-1.amazonaws.com.", "www.example.com.", "api.openai.com.evil.", "openai.azure.com.",
		"s3.us-east-1.amazonaws.com.", "api.anthropic.com", "router.huggingface.co.",
	} {
		_, _, listed := MatchModelEndpoint(name)
		if got := re.MatchString(name); got != listed {
			t.Errorf("%q: insights filter %v, list %v", name, got, listed)
		}
	}
	q := ModelEndpointQuery()
	for _, must := range []string{
		"| filter query_name like /" + pattern + "/",
		"coalesce(srcids.instance, \"-\") as src_instance",
		"stats count(*) as queries, min(@timestamp) as first_seen, max(@timestamp) as last_seen by srcaddr, src_instance, vpc, query_name",
		"| limit 10000",
	} {
		if !strings.Contains(q, must) {
			t.Errorf("query lacks %q:\n%s", must, q)
		}
	}
	if strings.Contains(pattern, "(?:") {
		t.Error("the pattern uses a non-capturing group, which Logs Insights may not accept")
	}
}

func TestDNSDestinationOf(t *testing.T) {
	for arn, want := range map[string][3]string{
		"arn:aws:logs:us-east-1:111122223333:log-group:/r53/queries":   {DNSDestinationCloudWatchLogs, "us-east-1", "111122223333"},
		"arn:aws:logs:us-east-1:111122223333:log-group:/r53/queries:*": {DNSDestinationCloudWatchLogs, "us-east-1", "111122223333"},
		"arn:aws:s3:::dns-logs-bucket":                                 {DNSDestinationS3, "", ""},
		"arn:aws:firehose:us-east-1:111122223333:deliverystream/dns":   {DNSDestinationFirehose, "us-east-1", "111122223333"},
		"nonsense": {DNSDestinationUnknown, "", ""},
	} {
		k, r, a := DNSDestinationOf(arn)
		if [3]string{k, r, a} != want {
			t.Errorf("%s: %s %s %s, want %v", arn, k, r, a, want)
		}
	}
	c := QueryLogConfig{DestinationARN: "arn:aws:logs:us-east-1:111122223333:log-group:/r53/queries:*"}
	if c.LogGroupIdentifier() != "arn:aws:logs:us-east-1:111122223333:log-group:/r53/queries" {
		t.Errorf("log group identifier %q keeps the :*", c.LogGroupIdentifier())
	}
}

/* ------------------------------------ fakes --------------------------------- */

type fakeResolver struct {
	configs []r53rtypes.ResolverQueryLogConfig
	assocs  []r53rtypes.ResolverQueryLogConfigAssociation
	err     error
}

func (f *fakeResolver) ListResolverQueryLogConfigs(context.Context, *route53resolver.ListResolverQueryLogConfigsInput, ...func(*route53resolver.Options)) (*route53resolver.ListResolverQueryLogConfigsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &route53resolver.ListResolverQueryLogConfigsOutput{ResolverQueryLogConfigs: f.configs}, nil
}

func (f *fakeResolver) ListResolverQueryLogConfigAssociations(context.Context, *route53resolver.ListResolverQueryLogConfigAssociationsInput, ...func(*route53resolver.Options)) (*route53resolver.ListResolverQueryLogConfigAssociationsOutput, error) {
	return &route53resolver.ListResolverQueryLogConfigAssociationsOutput{ResolverQueryLogConfigAssociations: f.assocs}, nil
}

type fakeInsights struct {
	rows    [][]cwltypes.ResultField
	polls   int
	running int // polls that report Running before Complete
	status  cwltypes.QueryStatus
	start   *cloudwatchlogs.StartQueryInput
	stopped bool
	err     error
}

func (f *fakeInsights) StartQuery(_ context.Context, in *cloudwatchlogs.StartQueryInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error) {
	f.start = in
	if f.err != nil {
		return nil, f.err
	}
	return &cloudwatchlogs.StartQueryOutput{QueryId: aws.String("q-1")}, nil
}

func (f *fakeInsights) GetQueryResults(context.Context, *cloudwatchlogs.GetQueryResultsInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetQueryResultsOutput, error) {
	f.polls++
	if f.polls <= f.running {
		return &cloudwatchlogs.GetQueryResultsOutput{Status: cwltypes.QueryStatusRunning}, nil
	}
	st := f.status
	if st == "" {
		st = cwltypes.QueryStatusComplete
	}
	return &cloudwatchlogs.GetQueryResultsOutput{Status: st, Results: f.rows,
		Statistics: &cwltypes.QueryStatistics{RecordsScanned: 1000, RecordsMatched: 3, BytesScanned: 5e6}}, nil
}

func (f *fakeInsights) StopQuery(context.Context, *cloudwatchlogs.StopQueryInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StopQueryOutput, error) {
	f.stopped = true
	return &cloudwatchlogs.StopQueryOutput{}, nil
}

func dnsRow(src, inst, vpc, name, n, first, last string) []cwltypes.ResultField {
	f := func(k, v string) cwltypes.ResultField {
		return cwltypes.ResultField{Field: aws.String(k), Value: aws.String(v)}
	}
	return []cwltypes.ResultField{f("srcaddr", src), f("src_instance", inst), f("vpc", vpc), f("query_name", name),
		f("queries", n), f("first_seen", first), f("last_seen", last)}
}

func noSleep(context.Context, time.Duration) error { return nil }

/* ------------------------------------ reads --------------------------------- */

func TestDNSConfigsListsDestinationsAndActiveVPCs(t *testing.T) {
	r := &fakeResolver{
		configs: []r53rtypes.ResolverQueryLogConfig{
			{Id: aws.String("rqlc-cw"), Name: aws.String("cw"), DestinationArn: aws.String("arn:aws:logs:us-east-1:111122223333:log-group:dns:*")},
			{Id: aws.String("rqlc-s3"), Name: aws.String("s3"), DestinationArn: aws.String("arn:aws:s3:::dns-bucket")},
		},
		assocs: []r53rtypes.ResolverQueryLogConfigAssociation{
			{ResolverQueryLogConfigId: aws.String("rqlc-cw"), ResourceId: aws.String("vpc-0b"), Status: r53rtypes.ResolverQueryLogConfigAssociationStatusActive},
			{ResolverQueryLogConfigId: aws.String("rqlc-cw"), ResourceId: aws.String("vpc-0a"), Status: r53rtypes.ResolverQueryLogConfigAssociationStatusActive},
			{ResolverQueryLogConfigId: aws.String("rqlc-cw"), ResourceId: aws.String("vpc-0c"), Status: r53rtypes.ResolverQueryLogConfigAssociationStatusFailed,
				Error: r53rtypes.ResolverQueryLogConfigAssociationErrorAccessDenied},
			{ResolverQueryLogConfigId: aws.String("rqlc-s3"), ResourceId: aws.String("vpc-0d"), Status: r53rtypes.ResolverQueryLogConfigAssociationStatusActive},
			{ResolverQueryLogConfigId: aws.String("rqlc-gone"), ResourceId: aws.String("vpc-0e"), Status: r53rtypes.ResolverQueryLogConfigAssociationStatusActive},
		},
	}
	configs, err := NewDNSQueryLogReader(r, nil).Configs(context.Background())
	if err != nil || len(configs) != 2 {
		t.Fatalf("configs %+v err %v", configs, err)
	}
	cw, s3 := configs[0], configs[1]
	if cw.DestinationKind != DNSDestinationCloudWatchLogs || strings.Join(cw.ActiveVPCs(), ",") != "vpc-0a,vpc-0b" {
		t.Errorf("cloudwatch config %+v active %v", cw, cw.ActiveVPCs())
	}
	if len(cw.Associations) != 3 || cw.Associations[2].Error != "ACCESS_DENIED" {
		t.Errorf("associations %+v", cw.Associations)
	}
	if s3.DestinationKind != DNSDestinationS3 || strings.Join(s3.ActiveVPCs(), ",") != "vpc-0d" {
		t.Errorf("s3 config %+v", s3)
	}
}

func TestDNSConfigsNamesARefusedCall(t *testing.T) {
	denied := &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized"}
	_, err := NewDNSQueryLogReader(&fakeResolver{err: denied}, nil).Configs(context.Background())
	if CallName(err) != "route53resolver:ListResolverQueryLogConfigs" || AWSErrorCode(err) != "AccessDeniedException" {
		t.Fatalf("err %v: call %q code %q", err, CallName(err), AWSErrorCode(err))
	}
}

func TestDNSWindow(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	to := now.Add(-DNSIngestDelay)
	first := DNSWindowFor(time.Time{}, now)
	if !first.To.Equal(to) || !first.From.Equal(to.Add(-24*time.Hour)) || first.Lapsed || first.Empty() {
		t.Errorf("first read %+v", first)
	}
	since := to.Add(-3 * time.Hour)
	next := DNSWindowFor(since, now)
	if !next.From.Equal(since) || next.Lapsed {
		t.Errorf("next read %+v", next)
	}
	old := to.Add(-9 * 24 * time.Hour)
	lapsed := DNSWindowFor(old, now)
	if !lapsed.Lapsed || !lapsed.From.Equal(to.Add(-DNSMaxReadWindow)) || !lapsed.Since.Equal(old) {
		t.Errorf("lapsed read %+v", lapsed)
	}
	if !DNSWindowFor(to, now).Empty() {
		t.Error("a window read to its mark must be empty")
	}
}

// Only listed names survive the read; case variants merge; the window is
// asked of AWS as [From, To) in whole seconds; statistics are kept.
func TestDNSReadKeepsOnlyListedDomains(t *testing.T) {
	ins := &fakeInsights{running: 2, rows: [][]cwltypes.ResultField{
		dnsRow("10.0.1.5", "i-0abc123def456", "vpc-0a1b2c3d", "api.openai.com.", "4", "2026-11-05 08:00:00.000", "2026-11-05 09:00:00.000"),
		dnsRow("10.0.1.5", "i-0abc123def456", "vpc-0a1b2c3d", "API.OPENAI.COM.", "1", "2026-11-05 07:00:00.000", "2026-11-05 07:00:00.000"),
		dnsRow("10.0.2.9", "-", "vpc-0a1b2c3d", "api.anthropic.com.", "2", "2026-11-05 10:00:00.000", "2026-11-05 10:30:00.000"),
		// A row the filter should never have returned: dropped, not kept.
		dnsRow("10.0.2.9", "-", "vpc-0a1b2c3d", "internal.corp.example.", "9", "2026-11-05 10:00:00.000", "2026-11-05 10:00:00.000"),
	}}
	w := DNSWindowFor(time.Time{}, time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC))
	read, err := NewDNSQueryLogReader(nil, ins).WithSleep(noSleep).ReadModelEndpointLookups(context.Background(), "arn:aws:logs:us-east-1:1:log-group:dns", w)
	if err != nil || !read.Settled {
		t.Fatalf("read %+v err %v", read, err)
	}
	if aws.ToInt64(ins.start.StartTime) != w.From.Unix() || aws.ToInt64(ins.start.EndTime) != w.To.Unix()-1 ||
		aws.ToString(ins.start.QueryString) != ModelEndpointQuery() || ins.start.LogGroupIdentifiers[0] != "arn:aws:logs:us-east-1:1:log-group:dns" {
		t.Errorf("start query %+v", ins.start)
	}
	if read.Dropped != 1 || len(read.Aggregates) != 2 {
		t.Fatalf("aggregates %+v dropped %d", read.Aggregates, read.Dropped)
	}
	a, b := read.Aggregates[0], read.Aggregates[1]
	if a.Domain != "api.openai.com" || a.Queries != 5 || a.InstanceID != "i-0abc123def456" ||
		!a.FirstSeen.Equal(time.Date(2026, 11, 5, 7, 0, 0, 0, time.UTC)) || !a.LastSeen.Equal(time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)) {
		t.Errorf("openai aggregate %+v", a)
	}
	if b.Domain != "api.anthropic.com" || b.InstanceID != "" || b.Provider != "anthropic" {
		t.Errorf("anthropic aggregate %+v", b)
	}
	for _, agg := range read.Aggregates {
		if strings.Contains(agg.Domain, "corp") {
			t.Fatalf("an unlisted domain was kept: %+v", agg)
		}
	}
	if read.BytesScanned != 5e6 || read.Truncated || read.Partial() {
		t.Errorf("statistics / partial %+v", read)
	}
}

func TestDNSReadTruncatedAndIncomplete(t *testing.T) {
	rows := make([][]cwltypes.ResultField, DNSResultLimit)
	for i := range rows {
		rows[i] = dnsRow("10.0.0.1", "-", "vpc-0a1b2c3d", "api.openai.com.", "1", "2026-11-05 08:00:00.000", "2026-11-05 08:00:00.000")
	}
	w := DNSWindowFor(time.Time{}, time.Now())
	read, err := NewDNSQueryLogReader(nil, &fakeInsights{rows: rows}).WithSleep(noSleep).ReadModelEndpointLookups(context.Background(), "lg", w)
	if err != nil || !read.Truncated || !read.Partial() {
		t.Fatalf("a read at the row limit must be truncated: %v %+v", err, read.Truncated)
	}

	failed := &fakeInsights{status: cwltypes.QueryStatusFailed}
	read, err = NewDNSQueryLogReader(nil, failed).WithSleep(noSleep).ReadModelEndpointLookups(context.Background(), "lg", w)
	if !errors.Is(err, ErrDNSQueryIncomplete) || read.Settled {
		t.Fatalf("failed query: %v settled %v", err, read.Settled)
	}

	slow := &fakeInsights{running: 1 << 30}
	r := NewDNSQueryLogReader(nil, slow).WithSleep(noSleep)
	r.wait = 0
	read, err = r.ReadModelEndpointLookups(context.Background(), "lg", w)
	if !errors.Is(err, ErrDNSQueryIncomplete) || read.Settled || !slow.stopped {
		t.Fatalf("a query past the deadline must be stopped and claim nothing: %v %v %v", err, read.Settled, slow.stopped)
	}

	limit := &fakeInsights{err: &smithy.GenericAPIError{Code: "LimitExceededException", Message: "too many"}}
	_, err = NewDNSQueryLogReader(nil, limit).ReadModelEndpointLookups(context.Background(), "lg", w)
	if !errors.Is(err, ErrThrottled) || CallName(err) != "logs:StartQuery" {
		t.Fatalf("concurrent-query limit must read as throttled: %v", err)
	}
}

/* --------------------------------- attribution ------------------------------ */

type fakeENI struct {
	enis []ec2types.NetworkInterface
	in   *ec2.DescribeNetworkInterfacesInput
}

func (f *fakeENI) DescribeNetworkInterfaces(_ context.Context, in *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	f.in = in
	return &ec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: f.enis}, nil
}

func eni(id, desc, primary string, ifType ec2types.NetworkInterfaceType, instance string, secondary ...string) ec2types.NetworkInterface {
	n := ec2types.NetworkInterface{NetworkInterfaceId: aws.String(id), Description: aws.String(desc), VpcId: aws.String("vpc-0a1b2c3d"),
		PrivateIpAddress: aws.String(primary), InterfaceType: ifType,
		PrivateIpAddresses: []ec2types.NetworkInterfacePrivateIpAddress{{PrivateIpAddress: aws.String(primary), Primary: aws.Bool(true)}}}
	for _, s := range secondary {
		n.PrivateIpAddresses = append(n.PrivateIpAddresses, ec2types.NetworkInterfacePrivateIpAddress{PrivateIpAddress: aws.String(s), Primary: aws.Bool(false)})
	}
	if instance != "" {
		n.Attachment = &ec2types.NetworkInterfaceAttachment{InstanceId: aws.String(instance)}
	}
	return n
}

type fakeECSTasks struct{}

func (fakeECSTasks) ListClusters(context.Context, *ecs.ListClustersInput, ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	return &ecs.ListClustersOutput{ClusterArns: []string{"arn:aws:ecs:us-east-1:1:cluster/c"}}, nil
}
func (fakeECSTasks) ListTasks(context.Context, *ecs.ListTasksInput, ...func(*ecs.Options)) (*ecs.ListTasksOutput, error) {
	return &ecs.ListTasksOutput{TaskArns: []string{"arn:aws:ecs:us-east-1:1:task/c/t1"}}, nil
}
func (fakeECSTasks) DescribeTasks(context.Context, *ecs.DescribeTasksInput, ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	return &ecs.DescribeTasksOutput{Tasks: []ecstypes.Task{{TaskArn: aws.String("arn:aws:ecs:us-east-1:1:task/c/t1"),
		TaskDefinitionArn: aws.String("arn:aws:ecs:us-east-1:1:task-definition/ledger:7"),
		Attachments: []ecstypes.Attachment{{Type: aws.String("ElasticNetworkInterface"),
			Details: []ecstypes.KeyValuePair{{Name: aws.String("networkInterfaceId"), Value: aws.String("eni-ecs")}}}}}}}, nil
}

func TestDNSAttributionClassifiesInterfaces(t *testing.T) {
	f := &fakeENI{enis: []ec2types.NetworkInterface{
		eni("eni-lambda", "AWS Lambda VPC ENI-summarise", "10.0.1.10", ec2types.NetworkInterfaceTypeLambda, ""),
		eni("eni-ecs", "arn:aws:ecs:us-east-1:1:attachment/0b5c", "10.0.1.20", ec2types.NetworkInterfaceTypeInterface, ""),
		eni("eni-node", "", "10.0.1.30", ec2types.NetworkInterfaceTypeInterface, "i-0abc123def456", "10.0.1.31"),
		eni("eni-cni", "aws-K8S-i-0abc123def456", "10.0.1.40", ec2types.NetworkInterfaceTypeInterface, "i-0abc123def456"),
		eni("eni-nat", "Interface for NAT Gateway nat-1", "10.0.1.50", ec2types.NetworkInterfaceTypeNatGateway, ""),
	}}
	r := NewDNSAttributionReader(f, fakeECSTasks{})
	got, err := r.NetworkInterfaces(context.Background(), "vpc-0a1b2c3d",
		[]string{"10.0.1.10", "10.0.1.20", "10.0.1.30", "10.0.1.31", "10.0.1.40", "10.0.1.50", "10.0.9.9"})
	if err != nil {
		t.Fatal(err)
	}
	if v := f.in.Filters; len(v) != 2 || aws.ToString(v[1].Name) != "vpc-id" || v[1].Values[0] != "vpc-0a1b2c3d" {
		t.Errorf("filters %+v: the lookup must be confined to the VPC", v)
	}
	want := map[string]string{"10.0.1.10": ENIKindLambda, "10.0.1.20": ENIKindECSTask, "10.0.1.30": ENIKindInstance,
		"10.0.1.31": ENIKindInstance, "10.0.1.40": ENIKindEKSPod, "10.0.1.50": ENIKindOther}
	for ip, kind := range want {
		if got[ip].Kind != kind {
			t.Errorf("%s: kind %q, want %q", ip, got[ip].Kind, kind)
		}
	}
	if _, ok := got["10.0.9.9"]; ok {
		t.Error("an address no interface holds must be absent")
	}
	if got["10.0.1.10"].LambdaFunctionHint != "summarise" || got["10.0.1.31"].PrimaryIP || !got["10.0.1.30"].PrimaryIP ||
		got["10.0.1.31"].InstanceID != "i-0abc123def456" {
		t.Errorf("details %+v / %+v / %+v", got["10.0.1.10"], got["10.0.1.30"], got["10.0.1.31"])
	}
	tasks, err := r.ECSTasksByENI(context.Background(), []string{"eni-ecs"})
	if err != nil || tasks["eni-ecs"].TaskDefinitionARN != "arn:aws:ecs:us-east-1:1:task-definition/ledger:7" {
		t.Fatalf("ecs task %+v err %v", tasks, err)
	}
}
