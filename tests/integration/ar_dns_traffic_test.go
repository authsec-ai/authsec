package integration

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/route53resolver"
	r53rtypes "github.com/aws/aws-sdk-go-v2/service/route53resolver/types"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/services"
)

// SPEC-agent-runtime-visibility.md §11 through the real scanner and database:
// model-provider lookups in Route 53 Resolver query logs become
// ai_network_traffic findings attributed to the EC2 instance (srcids.instance),
// the Lambda (its VPC network interface) or, for an address nothing explains,
// the VPC; no other domain is stored; a second scan reads only the new window
// and counts nothing twice; a finding quiet for 30 days of gap-free reads is
// resolved, and one whose reads have a gap is not; the inference pass leaves
// the kind alone -- and two workspaces holding the same account see only
// their own findings and cursors, under row-level security too.

const dnsLogGroup = "arn:aws:logs:us-east-1:429418377036:log-group:/aws/route53/queries"

// dnsLookup is one query-log record.
type dnsLookup struct {
	src, instance, vpc, name string
	at                       time.Time
}

// dnsLogs is a Logs Insights stand-in that does what the real query does: it
// keeps the records in [StartTime, EndTime] whose query_name matches the
// query's own `like /.../` filter, and aggregates them per (srcaddr,
// src_instance, vpc, query_name). It records every window asked of it.
type dnsLogs struct {
	mu      sync.Mutex
	records []dnsLookup
	windows [][2]int64
	results map[string][][]cwltypes.ResultField
	n       int
}

var dnsLikeFilter = regexp.MustCompile(`filter query_name like /(.*)/\n`)

func (f *dnsLogs) StartQuery(_ context.Context, in *cloudwatchlogs.StartQueryInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := dnsLikeFilter.FindStringSubmatch(aws.ToString(in.QueryString))
	if m == nil {
		panic("the query has no query_name filter")
	}
	re := regexp.MustCompile(m[1])
	from, to := aws.ToInt64(in.StartTime), aws.ToInt64(in.EndTime)
	f.windows = append(f.windows, [2]int64{from, to})
	type key struct{ src, inst, vpc, name string }
	type agg struct {
		n           int
		first, last time.Time
	}
	groups := map[key]*agg{}
	for _, r := range f.records {
		if r.at.Unix() < from || r.at.Unix() > to || !re.MatchString(r.name) {
			continue
		}
		inst := r.instance
		if inst == "" {
			inst = "-"
		}
		k := key{r.src, inst, r.vpc, r.name}
		g := groups[k]
		if g == nil {
			g = &agg{first: r.at, last: r.at}
			groups[k] = g
		}
		g.n++
		if r.at.Before(g.first) {
			g.first = r.at
		}
		if r.at.After(g.last) {
			g.last = r.at
		}
	}
	var rows [][]cwltypes.ResultField
	field := func(k, v string) cwltypes.ResultField {
		return cwltypes.ResultField{Field: aws.String(k), Value: aws.String(v)}
	}
	for k, g := range groups {
		rows = append(rows, []cwltypes.ResultField{
			field("srcaddr", k.src), field("src_instance", k.inst), field("vpc", k.vpc), field("query_name", k.name),
			field("queries", strconv.Itoa(g.n)),
			field("first_seen", g.first.UTC().Format("2006-01-02 15:04:05.000")),
			field("last_seen", g.last.UTC().Format("2006-01-02 15:04:05.000")),
		})
	}
	f.n++
	id := "q-" + strconv.Itoa(f.n)
	if f.results == nil {
		f.results = map[string][][]cwltypes.ResultField{}
	}
	f.results[id] = rows
	return &cloudwatchlogs.StartQueryOutput{QueryId: aws.String(id)}, nil
}

func (f *dnsLogs) GetQueryResults(_ context.Context, in *cloudwatchlogs.GetQueryResultsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetQueryResultsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &cloudwatchlogs.GetQueryResultsOutput{Status: cwltypes.QueryStatusComplete, Results: f.results[aws.ToString(in.QueryId)],
		Statistics: &cwltypes.QueryStatistics{RecordsScanned: float64(len(f.records)), BytesScanned: 4096}}, nil
}

func (f *dnsLogs) StopQuery(context.Context, *cloudwatchlogs.StopQueryInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StopQueryOutput, error) {
	return &cloudwatchlogs.StopQueryOutput{}, nil
}

type dnsResolver struct{}

func (dnsResolver) ListResolverQueryLogConfigs(context.Context, *route53resolver.ListResolverQueryLogConfigsInput, ...func(*route53resolver.Options)) (*route53resolver.ListResolverQueryLogConfigsOutput, error) {
	return &route53resolver.ListResolverQueryLogConfigsOutput{ResolverQueryLogConfigs: []r53rtypes.ResolverQueryLogConfig{
		{Id: aws.String("rqlc-1"), Name: aws.String("vpc-dns"), DestinationArn: aws.String(dnsLogGroup + ":*")},
		{Id: aws.String("rqlc-2"), Name: aws.String("archive"), DestinationArn: aws.String("arn:aws:s3:::dns-archive")},
	}}, nil
}

func (dnsResolver) ListResolverQueryLogConfigAssociations(context.Context, *route53resolver.ListResolverQueryLogConfigAssociationsInput, ...func(*route53resolver.Options)) (*route53resolver.ListResolverQueryLogConfigAssociationsOutput, error) {
	return &route53resolver.ListResolverQueryLogConfigAssociationsOutput{ResolverQueryLogConfigAssociations: []r53rtypes.ResolverQueryLogConfigAssociation{
		{ResolverQueryLogConfigId: aws.String("rqlc-1"), ResourceId: aws.String("vpc-0a1b2c3d"), Status: r53rtypes.ResolverQueryLogConfigAssociationStatusActive},
		{ResolverQueryLogConfigId: aws.String("rqlc-2"), ResourceId: aws.String("vpc-0eeeeeee"), Status: r53rtypes.ResolverQueryLogConfigAssociationStatusActive},
	}}, nil
}

// dnsENIs: 10.0.1.10 is the summarise Lambda's interface; 10.0.1.30 the
// web-1 instance's; 10.0.9.9 is held by nothing.
type dnsENIs struct{}

func (dnsENIs) DescribeNetworkInterfaces(_ context.Context, in *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	all := map[string]ec2types.NetworkInterface{
		"10.0.1.10": {NetworkInterfaceId: aws.String("eni-lambda"), Description: aws.String("AWS Lambda VPC ENI-summarise"),
			InterfaceType: ec2types.NetworkInterfaceTypeLambda, VpcId: aws.String("vpc-0a1b2c3d"), PrivateIpAddress: aws.String("10.0.1.10"),
			PrivateIpAddresses: []ec2types.NetworkInterfacePrivateIpAddress{{PrivateIpAddress: aws.String("10.0.1.10"), Primary: aws.Bool(true)}}},
		"10.0.1.30": {NetworkInterfaceId: aws.String("eni-web"), VpcId: aws.String("vpc-0a1b2c3d"), PrivateIpAddress: aws.String("10.0.1.30"),
			InterfaceType: ec2types.NetworkInterfaceTypeInterface, Attachment: &ec2types.NetworkInterfaceAttachment{InstanceId: aws.String("i-0abc123def456")},
			PrivateIpAddresses: []ec2types.NetworkInterfacePrivateIpAddress{{PrivateIpAddress: aws.String("10.0.1.30"), Primary: aws.Bool(true)}}},
	}
	var out []ec2types.NetworkInterface
	for _, f := range in.Filters {
		if aws.ToString(f.Name) != "addresses.private-ip-address" {
			continue
		}
		for _, ip := range f.Values {
			if n, ok := all[ip]; ok {
				out = append(out, n)
			}
		}
	}
	return &ec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: out}, nil
}

type dnsNoECS struct{}

func (dnsNoECS) ListClusters(context.Context, *ecs.ListClustersInput, ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	return &ecs.ListClustersOutput{}, nil
}
func (dnsNoECS) ListTasks(context.Context, *ecs.ListTasksInput, ...func(*ecs.Options)) (*ecs.ListTasksOutput, error) {
	return &ecs.ListTasksOutput{}, nil
}
func (dnsNoECS) DescribeTasks(context.Context, *ecs.DescribeTasksInput, ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	return &ecs.DescribeTasksOutput{}, nil
}

func dnsScan(t *testing.T, db *gorm.DB, e p1aEnv, logs *dnsLogs, now time.Time) *services.WorkloadSnapshot {
	t.Helper()
	l, ec, c, p := populatedWorkloads()
	out, err := services.NewAWSWorkloadScanner(db, e.svc).WithWorkloadAPIs(l, ec, c, p).
		WithCloudTrailAPI(&p1aTrail{}).WithTrailClock(func() time.Time { return now }).
		WithDNSAPIs(func(string) services.DNSClients {
			return services.DNSClients{Resolver: dnsResolver{}, Logs: logs, ENI: dnsENIs{}, ECS: dnsNoECS{}}
		}).
		WithDNSClock(func() time.Time { return now }, func(context.Context, time.Duration) error { return nil }).
		ScanFromSnapshot(context.Background(), e.ws, e.snap)
	if err != nil {
		t.Fatalf("workload scan: %v", err)
	}
	if len(out.Warnings) > 0 {
		t.Fatalf("scan warnings: %v", out.Warnings)
	}
	return out
}

type dnsFindingRow struct {
	ID         uuid.UUID
	SubjectKey string
	IdentityID *uuid.UUID
	Subject    []byte
	Evidence   []byte
	State      string
	FirstSeen  time.Time
	LastSeen   time.Time
}

func dnsFindings(t *testing.T, db *gorm.DB, ws uuid.UUID) map[string]dnsFindingRow {
	t.Helper()
	var rows []dnsFindingRow
	if err := db.Raw(`SELECT id, subject_key, identity_id, subject, evidence, state, first_seen, last_seen
	                    FROM agent_finding WHERE workspace_id = ? AND kind = 'ai_network_traffic'`, ws).Scan(&rows).Error; err != nil {
		t.Fatal(err)
	}
	out := map[string]dnsFindingRow{}
	for _, r := range rows {
		out[r.SubjectKey] = r
	}
	return out
}

type dnsEvidenceDoc struct {
	Providers []string `json:"providers"`
	Queries   int64    `json:"queries"`
	Domains   []struct {
		Domain  string `json:"domain"`
		Queries int64  `json:"queries"`
	} `json:"domains"`
	Sources []struct {
		SrcAddr string `json:"srcaddr"`
		ENIID   string `json:"eni_id"`
	} `json:"sources"`
	Attribution struct {
		How string `json:"how"`
	} `json:"attribution"`
}

func dnsDoc(t *testing.T, r dnsFindingRow) dnsEvidenceDoc {
	t.Helper()
	var d dnsEvidenceDoc
	if err := json.Unmarshal(r.Evidence, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

const (
	dnsEC2Key    = "workload:ec2_instance:us-east-1:i-0abc123def456"
	dnsLambdaKey = "workload:lambda_function:us-east-1:arn:aws:lambda:us-east-1:429418377036:function:summarise"
	dnsVPCKey    = "vpc:us-east-1:vpc-0a1b2c3d"
)

func TestDNSTrafficFindingsAreAttributedCumulativeAndWorkspaceScoped(t *testing.T) {
	db := igaDB(t)
	a := newP1aEnv(t, db, "dns-traffic-a")
	b := newP1aEnv(t, db, "dns-traffic-b")
	t.Cleanup(func() {
		for _, ws := range []uuid.UUID{a.ws, b.ws} {
			db.Exec(`DELETE FROM agent_finding WHERE workspace_id = ?`, ws)
			db.Exec(`DELETE FROM cloud_dns_cursor WHERE workspace_id = ?`, ws)
		}
	})

	now := time.Now().UTC().Truncate(time.Second)
	at := now.Add(-2 * time.Hour)
	logsA := &dnsLogs{records: []dnsLookup{
		{"10.0.1.30", "i-0abc123def456", "vpc-0a1b2c3d", "api.openai.com.", at},
		{"10.0.1.30", "i-0abc123def456", "vpc-0a1b2c3d", "api.openai.com.", at.Add(time.Minute)},
		{"10.0.1.30", "i-0abc123def456", "vpc-0a1b2c3d", "bedrock-runtime.us-east-1.amazonaws.com.", at},
		{"10.0.1.10", "", "vpc-0a1b2c3d", "api.anthropic.com.", at},
		{"10.0.9.9", "", "vpc-0a1b2c3d", "my-res.openai.azure.com.", at},
		// Never stored: not a model host.
		{"10.0.1.30", "i-0abc123def456", "vpc-0a1b2c3d", "internal.payroll.example.", at},
		{"10.0.1.10", "", "vpc-0a1b2c3d", "api.openai.com.evil.example.", at},
		// Before the first read's 24 hours: not read.
		{"10.0.1.30", "i-0abc123def456", "vpc-0a1b2c3d", "api.openai.com.", now.Add(-30 * time.Hour)},
	}}
	logsB := &dnsLogs{records: []dnsLookup{
		{"10.0.1.30", "i-0abc123def456", "vpc-0a1b2c3d", "api.mistral.ai.", at},
	}}

	out := dnsScan(t, db, a, logsA, now)
	if out.DNSTrafficFindings != 3 {
		t.Fatalf("A wrote %d DNS findings, want 3", out.DNSTrafficFindings)
	}
	if cov := out.Surfaces["dns-query-logs:us-east-1"]; cov.State != "reached" || cov.Count != 1 {
		t.Fatalf("dns coverage %+v", cov)
	}
	if cov := out.Surfaces["dns-query-logs-unread:us-east-1"]; cov.State != "unsupported" || !strings.Contains(cov.Error, "s3") {
		t.Fatalf("unread coverage %+v", cov)
	}
	dnsScan(t, db, b, logsB, now)

	fa := dnsFindings(t, db, a.ws)
	if len(fa) != 3 {
		t.Fatalf("A findings %v", fa)
	}
	ec2, lambda, vpc := fa[dnsEC2Key], fa[dnsLambdaKey], fa[dnsVPCKey]
	var role uuid.UUID
	if err := db.Raw(`SELECT id FROM cloud_identity WHERE workspace_id = ? AND native_id = ?`, a.ws, instanceRoleARN).
		Row().Scan(&role); err != nil {
		t.Fatal(err)
	}
	if ec2.IdentityID == nil || *ec2.IdentityID != role || ec2.State != "open" || !ec2.FirstSeen.Equal(at) || !ec2.LastSeen.Equal(at.Add(time.Minute)) {
		t.Fatalf("ec2 finding %+v (role %s)", ec2, role)
	}
	d := dnsDoc(t, ec2)
	if d.Queries != 3 || strings.Join(d.Providers, ",") != "aws_bedrock,openai" || d.Attribution.How != "srcids_instance" {
		t.Fatalf("ec2 evidence %+v", d)
	}
	if lambda.State != "open" || dnsDoc(t, lambda).Attribution.How != "eni_lambda" || dnsDoc(t, lambda).Sources[0].ENIID != "eni-lambda" {
		t.Fatalf("lambda finding %+v / %s", lambda, lambda.Evidence)
	}
	if vpc.IdentityID != nil || !strings.Contains(string(vpc.Subject), `"kind": "vpc"`) && !strings.Contains(string(vpc.Subject), `"kind":"vpc"`) {
		t.Fatalf("vpc finding %+v / %s", vpc, vpc.Subject)
	}
	// No other domain anywhere: not in evidence, not in subjects.
	var leaked int64
	if err := db.Raw(`SELECT count(*) FROM agent_finding WHERE workspace_id = ? AND
	                   (evidence::text LIKE '%payroll%' OR evidence::text LIKE '%evil%' OR subject::text LIKE '%payroll%')`,
		a.ws).Row().Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("other domains stored: %d (%v)", leaked, err)
	}

	var cursor struct {
		ReadTo      time.Time
		CoveredFrom time.Time
		Partial     bool
		LogGroupArn string
	}
	if err := db.Raw(`SELECT read_to, covered_from, partial, log_group_arn FROM cloud_dns_cursor WHERE workspace_id = ?`, a.ws).
		Row().Scan(&cursor.ReadTo, &cursor.CoveredFrom, &cursor.Partial, &cursor.LogGroupArn); err != nil {
		t.Fatal(err)
	}
	mark := now.Add(-awsdiscovery.DNSIngestDelay)
	if !cursor.ReadTo.Equal(mark) || !cursor.CoveredFrom.Equal(mark.Add(-24*time.Hour)) || cursor.Partial || cursor.LogGroupArn != dnsLogGroup {
		t.Fatalf("cursor %+v", cursor)
	}

	// The inference pass does not resolve DNS findings it did not open.
	if _, err := services.NewAgentRuntimeService(db).RunAgentInference(context.Background(), a.ws, a.conn); err != nil {
		t.Fatalf("inference: %v", err)
	}
	if f := dnsFindings(t, db, a.ws)[dnsEC2Key]; f.State != "open" {
		t.Fatalf("inference resolved a DNS finding: %+v", f)
	}
	list, _, err := services.NewAgentRuntimeService(db).ListFindings(context.Background(), a.ws,
		services.FindingListFilter{Kind: services.FindingAINetworkTraffic})
	if err != nil || len(list) != 3 {
		t.Fatalf("list by kind: %d %v", len(list), err)
	}

	// A second scan an hour later reads only the new hour: nothing counted
	// twice, a new lookup added.
	logsA.records = append(logsA.records, dnsLookup{"10.0.1.30", "i-0abc123def456", "vpc-0a1b2c3d", "api.openai.com.", now.Add(10 * time.Minute)})
	dnsScan(t, db, a, logsA, now.Add(time.Hour))
	if w := logsA.windows[1]; w[0] != mark.Unix() || w[1] != now.Add(time.Hour-awsdiscovery.DNSIngestDelay).Unix()-1 {
		t.Fatalf("second window %v, want from the mark", w)
	}
	if d := dnsDoc(t, dnsFindings(t, db, a.ws)[dnsEC2Key]); d.Queries != 4 {
		t.Fatalf("second scan: queries %d, want 4", d.Queries)
	}

	// Isolation: B's same account holds only B's lookup.
	fb := dnsFindings(t, db, b.ws)
	if len(fb) != 1 || fb[dnsEC2Key].ID == ec2.ID || strings.Join(dnsDoc(t, fb[dnsEC2Key]).Providers, ",") != "mistral" {
		t.Fatalf("B findings %v", fb)
	}
	listB, _, err := services.NewAgentRuntimeService(db).ListFindings(context.Background(), b.ws, services.FindingListFilter{})
	if err != nil || len(listB) != 1 {
		t.Fatalf("B lists %d findings (%v), want its one", len(listB), err)
	}
	err = tenancy.InWorkspaceRead(context.Background(), db, b.ws, func(tx *gorm.DB) error {
		var findingsA, cursorsA, cursorsAll int64
		if err := tx.Raw(`SELECT count(*) FROM agent_finding WHERE workspace_id = ?`, a.ws).Row().Scan(&findingsA); err != nil {
			return err
		}
		if err := tx.Raw(`SELECT count(*) FROM cloud_dns_cursor WHERE workspace_id = ?`, a.ws).Row().Scan(&cursorsA); err != nil {
			return err
		}
		if err := tx.Raw(`SELECT count(*) FROM cloud_dns_cursor`).Row().Scan(&cursorsAll); err != nil {
			return err
		}
		if findingsA != 0 || cursorsA != 0 || cursorsAll != 1 {
			t.Errorf("B's transaction sees A's findings %d, A's cursors %d, cursors %d (want 0, 0, 1)", findingsA, cursorsA, cursorsAll)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("B's transaction: %v", err)
	}
}

// Resolution: 30 days without a lookup, read without a gap, resolves; a gap
// (a log group unread for longer than the 7-day cap) keeps it open.
func TestDNSTrafficFindingResolvesOnlyAfterThirtyGapFreeDays(t *testing.T) {
	db := igaDB(t)
	a := newP1aEnv(t, db, "dns-resolve-a")
	b := newP1aEnv(t, db, "dns-resolve-b")
	t.Cleanup(func() {
		for _, ws := range []uuid.UUID{a.ws, b.ws} {
			db.Exec(`DELETE FROM agent_finding WHERE workspace_id = ?`, ws)
			db.Exec(`DELETE FROM cloud_dns_cursor WHERE workspace_id = ?`, ws)
		}
	})
	now := time.Now().UTC().Truncate(time.Second)
	lookup := []dnsLookup{{"10.0.1.30", "i-0abc123def456", "vpc-0a1b2c3d", "api.groq.com.", now.Add(-time.Hour)}}

	// A: a scan every 6 days.
	logsA := &dnsLogs{records: lookup}
	for day := 0; day <= 24; day += 6 {
		dnsScan(t, db, a, logsA, now.Add(time.Duration(day)*24*time.Hour))
		if f := dnsFindings(t, db, a.ws)[dnsEC2Key]; f.State != "open" {
			t.Fatalf("day %d: resolved too early", day)
		}
	}
	dnsScan(t, db, a, logsA, now.Add(31*24*time.Hour))
	if f := dnsFindings(t, db, a.ws)[dnsEC2Key]; f.State != "resolved" {
		t.Fatalf("after 31 gap-free days: %s", f.State)
	}

	// B: one scan, then nothing for 40 days -- the read lapsed, so the 30
	// days were not all read and "no traffic" is not claimed.
	logsB := &dnsLogs{records: lookup}
	dnsScan(t, db, b, logsB, now)
	dnsScan(t, db, b, logsB, now.Add(40*24*time.Hour))
	if f := dnsFindings(t, db, b.ws)[dnsEC2Key]; f.State != "open" {
		t.Fatalf("a gap must keep the finding open: %s", f.State)
	}
	var partial bool
	var reason string
	if err := db.Raw(`SELECT partial, partial_reason FROM cloud_dns_cursor WHERE workspace_id = ?`, b.ws).
		Row().Scan(&partial, &reason); err != nil || !partial || reason != "lapsed" {
		t.Fatalf("lapsed cursor partial %v reason %q (%v)", partial, reason, err)
	}
	windows := append([][2]int64(nil), logsB.windows...)
	sort.Slice(windows, func(i, j int) bool { return windows[i][0] < windows[j][0] })
	if span := windows[1][1] + 1 - windows[1][0]; span != int64(awsdiscovery.DNSMaxReadWindow/time.Second) {
		t.Fatalf("lapsed window spans %ds, want the 7-day cap", span)
	}
}
