package awsdiscovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
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

// DNS-based detection of direct model-provider calls
// (SPEC-agent-runtime-visibility.md §11).
//
// A workload that calls OpenAI, Anthropic, Google, Mistral... directly leaves
// nothing in CloudTrail. It does leave a DNS lookup of the provider's API
// host, and Route 53 Resolver query logging records every lookup a VPC makes
// through the Amazon-provided resolver, with the source address and -- for an
// EC2 instance -- the instance id. This file reads those logs:
//
//   - which VPCs are logged and where (route53resolver:
//     ListResolverQueryLogConfigs + ListResolverQueryLogConfigAssociations);
//   - for a CloudWatch Logs destination, ONLY the lookups of the model-endpoint
//     list (ModelEndpoints), filtered inside the Logs Insights query itself, so
//     no other DNS data ever leaves the customer's account, aggregated by
//     (srcaddr, srcids.instance, vpc_id, query_name);
//   - the network interface that holds each source address now
//     (ec2:DescribeNetworkInterfaces), and for an ECS task interface the task
//     (ecs:ListClusters/ListTasks/DescribeTasks), so the caller can attribute
//     the traffic to a workload.
//
// S3 and Firehose destinations are listed but never read (unsupported). Every
// row a query returns is checked against ModelEndpoints again before it is
// kept: a name outside the list is dropped, not stored and not named.

// ResolverQueryLogAPI is the slice of Route 53 Resolver the DNS read uses.
type ResolverQueryLogAPI interface {
	ListResolverQueryLogConfigs(ctx context.Context, in *route53resolver.ListResolverQueryLogConfigsInput, opts ...func(*route53resolver.Options)) (*route53resolver.ListResolverQueryLogConfigsOutput, error)
	ListResolverQueryLogConfigAssociations(ctx context.Context, in *route53resolver.ListResolverQueryLogConfigAssociationsInput, opts ...func(*route53resolver.Options)) (*route53resolver.ListResolverQueryLogConfigAssociationsOutput, error)
}

// LogsInsightsAPI is the slice of CloudWatch Logs the DNS read uses.
type LogsInsightsAPI interface {
	StartQuery(ctx context.Context, in *cloudwatchlogs.StartQueryInput, opts ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error)
	GetQueryResults(ctx context.Context, in *cloudwatchlogs.GetQueryResultsInput, opts ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetQueryResultsOutput, error)
	StopQuery(ctx context.Context, in *cloudwatchlogs.StopQueryInput, opts ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StopQueryOutput, error)
}

// NetworkInterfaceAPI resolves a private address to the interface holding it.
type NetworkInterfaceAPI interface {
	DescribeNetworkInterfaces(ctx context.Context, in *ec2.DescribeNetworkInterfacesInput, opts ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
}

// ECSTaskAPI resolves an ECS task interface to its task.
type ECSTaskAPI interface {
	ListClusters(ctx context.Context, in *ecs.ListClustersInput, opts ...func(*ecs.Options)) (*ecs.ListClustersOutput, error)
	ListTasks(ctx context.Context, in *ecs.ListTasksInput, opts ...func(*ecs.Options)) (*ecs.ListTasksOutput, error)
	DescribeTasks(ctx context.Context, in *ecs.DescribeTasksInput, opts ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error)
}

// NewResolverQueryLogClient builds a real Route 53 Resolver client.
func NewResolverQueryLogClient(cfg aws.Config) ResolverQueryLogAPI {
	return route53resolver.NewFromConfig(cfg)
}

// NewLogsInsightsClient builds a real CloudWatch Logs client.
func NewLogsInsightsClient(cfg aws.Config) LogsInsightsAPI { return cloudwatchlogs.NewFromConfig(cfg) }

// NewNetworkInterfaceClient builds a real EC2 client for interface lookups.
func NewNetworkInterfaceClient(cfg aws.Config) NetworkInterfaceAPI { return ec2.NewFromConfig(cfg) }

// NewECSTaskClient builds a real ECS client for task lookups.
func NewECSTaskClient(cfg aws.Config) ECSTaskAPI { return ecs.NewFromConfig(cfg) }

/* ----------------------------- the domain list ----------------------------- */

// ModelEndpoint is one model provider's API host, or family of hosts.
type ModelEndpoint struct {
	// Provider is a stable key: openai, azure_openai, anthropic...
	Provider string
	// Display is the host as a person writes it ("*.openai.azure.com").
	Display string
	// Pattern is the host as a regular expression over a lower-case name
	// without its trailing dot, unanchored. Written in the subset Go's RE2 and
	// CloudWatch Logs Insights share (no look-around, no non-capturing
	// groups), because the same text is both the in-query filter and the
	// check each returned row passes again here.
	Pattern string
	// Control marks Amazon Bedrock's runtime endpoint: AWS's own model API,
	// whose calls CloudTrail already shows. Reported, flagged as the control
	// that DNS and CloudTrail agree.
	Control bool
}

// label is one DNS label; subdomain is one or more labels and a dot.
const (
	dnsLabel     = `[a-z0-9-]+`
	dnsSubdomain = `(` + dnsLabel + `\.)+`
)

// ModelEndpoints is the model-endpoint domain list. Exact hosts, and suffix
// families written as one or more labels before the provider's zone. Vertex
// AI's regional hosts are "<region>-aiplatform.googleapis.com" -- not a
// subdomain of aiplatform.googleapis.com -- so that family also admits a
// "<label>-" prefix (googleapis.com is Google's zone: every name in it is
// Google's).
var ModelEndpoints = []ModelEndpoint{
	{Provider: "openai", Display: "api.openai.com", Pattern: `api\.openai\.com`},
	{Provider: "azure_openai", Display: "*.openai.azure.com", Pattern: dnsSubdomain + `openai\.azure\.com`},
	{Provider: "anthropic", Display: "api.anthropic.com", Pattern: `api\.anthropic\.com`},
	{Provider: "google_gemini", Display: "generativelanguage.googleapis.com", Pattern: `generativelanguage\.googleapis\.com`},
	{Provider: "google_vertex", Display: "*.aiplatform.googleapis.com",
		Pattern: `(` + dnsSubdomain + `|` + dnsLabel + `-)?aiplatform\.googleapis\.com`},
	{Provider: "mistral", Display: "api.mistral.ai", Pattern: `api\.mistral\.ai`},
	{Provider: "cohere", Display: "api.cohere.com", Pattern: `api\.cohere\.com`},
	{Provider: "cohere", Display: "api.cohere.ai", Pattern: `api\.cohere\.ai`},
	{Provider: "groq", Display: "api.groq.com", Pattern: `api\.groq\.com`},
	{Provider: "openrouter", Display: "openrouter.ai", Pattern: `openrouter\.ai`},
	{Provider: "huggingface", Display: "api-inference.huggingface.co", Pattern: `api-inference\.huggingface\.co`},
	{Provider: "huggingface", Display: "router.huggingface.co", Pattern: `router\.huggingface\.co`},
	{Provider: "together", Display: "api.together.xyz", Pattern: `api\.together\.xyz`},
	{Provider: "fireworks", Display: "api.fireworks.ai", Pattern: `api\.fireworks\.ai`},
	{Provider: "deepseek", Display: "api.deepseek.com", Pattern: `api\.deepseek\.com`},
	{Provider: "xai", Display: "api.x.ai", Pattern: `api\.x\.ai`},
	{Provider: "aws_bedrock", Display: "bedrock-runtime.*.amazonaws.com",
		Pattern: `bedrock-runtime(-fips)?\.` + dnsLabel + `\.amazonaws\.com`, Control: true},
}

var modelEndpointMatchers = func() []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(ModelEndpoints))
	for i, e := range ModelEndpoints {
		out[i] = regexp.MustCompile(`^(` + e.Pattern + `)$`)
	}
	return out
}()

// dnsNameChars is every character a host name on the list can hold.
var dnsNameChars = regexp.MustCompile(`^[a-z0-9.-]+$`)

// NormalizeDNSName lower-cases a query name and drops ONE trailing dot (the
// resolver logs fully qualified names). "" when it is not a plausible host.
func NormalizeDNSName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimSuffix(n, ".")
	if n == "" || len(n) > 253 || !dnsNameChars.MatchString(n) || strings.Contains(n, "..") {
		return ""
	}
	return n
}

// MatchModelEndpoint reports whether a query name is on the model-endpoint
// list, and which entry. The name is returned normalised.
func MatchModelEndpoint(name string) (ModelEndpoint, string, bool) {
	n := NormalizeDNSName(name)
	if n == "" {
		return ModelEndpoint{}, "", false
	}
	for i, re := range modelEndpointMatchers {
		if re.MatchString(n) {
			return ModelEndpoints[i], n, true
		}
	}
	return ModelEndpoint{}, "", false
}

// ModelEndpointInsightsRegex is the whole list as one Logs Insights regular
// expression over query_name: case-insensitive, anchored, the trailing dot
// optional.
func ModelEndpointInsightsRegex() string {
	alts := make([]string, len(ModelEndpoints))
	for i, e := range ModelEndpoints {
		alts[i] = e.Pattern
	}
	return `(?i)^(` + strings.Join(alts, "|") + `)\.?$`
}

// Logs Insights result field names of ModelEndpointQuery.
const (
	dnsFieldSrcAddr   = "srcaddr"
	dnsFieldInstance  = "src_instance"
	dnsFieldVPC       = "vpc"
	dnsFieldQueryName = "query_name"
	dnsFieldQueries   = "queries"
	dnsFieldFirstSeen = "first_seen"
	dnsFieldLastSeen  = "last_seen"
	// dnsNone stands in for an absent field: Logs Insights drops an event from
	// a stats group when a by-field is missing, and a Lambda's or a Fargate
	// task's lookups carry no srcids.instance -- exactly the ones that matter.
	dnsNone = "-"
)

// ModelEndpointQuery is the Logs Insights query a DNS read runs: only lookups
// of the model-endpoint list, aggregated per source and name. Nothing else in
// the log group is returned.
func ModelEndpointQuery() string { return modelEndpointQuery("") }

// ModelEndpointQueryFor is ModelEndpointQuery restricted to the lines
// CloudWatch Logs RECEIVED in w ([From, To) by @ingestionTime). Windows are
// cut by ingestion time, not event time, so a line that arrives after a read
// has passed its event time is still read, once, by the read whose window
// holds its arrival (as long as it is no later than DNSLateArrival).
func ModelEndpointQueryFor(w DNSWindow) string {
	return modelEndpointQuery("\n| filter @ingestionTime >= " + strconv.FormatInt(w.From.UnixMilli(), 10) +
		" and @ingestionTime < " + strconv.FormatInt(w.To.UnixMilli(), 10))
}

func modelEndpointQuery(ingestFilter string) string {
	return "fields @timestamp, query_name" +
		", coalesce(srcaddr, \"" + dnsNone + "\") as " + dnsFieldSrcAddr +
		", coalesce(srcids.instance, \"" + dnsNone + "\") as " + dnsFieldInstance +
		", coalesce(vpc_id, \"" + dnsNone + "\") as " + dnsFieldVPC +
		ingestFilter +
		"\n| filter query_name like /" + ModelEndpointInsightsRegex() + "/" +
		"\n| stats count(*) as " + dnsFieldQueries +
		", min(@timestamp) as " + dnsFieldFirstSeen +
		", max(@timestamp) as " + dnsFieldLastSeen +
		" by " + dnsFieldSrcAddr + ", " + dnsFieldInstance + ", " + dnsFieldVPC + ", " + dnsFieldQueryName +
		"\n| limit " + strconv.Itoa(DNSResultLimit)
}

/* ------------------------- query logging configuration ---------------------- */

// Destination kinds of a query logging configuration.
const (
	DNSDestinationCloudWatchLogs = "cloudwatch_logs"
	DNSDestinationS3             = "s3"
	DNSDestinationFirehose       = "firehose"
	DNSDestinationUnknown        = "unknown"
)

// QueryLogAssociation is one VPC's association with a configuration.
type QueryLogAssociation struct {
	VPCID  string
	Status string
	// Error is AWS's association error code (ACTION_NEEDED / FAILED), "" else.
	Error string
}

// QueryLogConfig is one Resolver query logging configuration seen from this
// account and region, with the VPCs of this account logged through it.
type QueryLogConfig struct {
	ID, ARN, Name, OwnerID, Status, ShareStatus string
	DestinationARN                              string
	// DestinationKind is a DNSDestination* value.
	DestinationKind                       string
	DestinationRegion, DestinationAccount string
	Associations                          []QueryLogAssociation
}

// ActiveVPCs are the VPCs whose lookups the configuration is logging now.
func (c QueryLogConfig) ActiveVPCs() []string {
	var out []string
	for _, a := range c.Associations {
		if a.Status == string(r53rtypes.ResolverQueryLogConfigAssociationStatusActive) {
			out = append(out, a.VPCID)
		}
	}
	sort.Strings(out)
	return out
}

// LogGroupIdentifier is the destination as Logs Insights takes it: the ARN
// without a trailing ":*".
func (c QueryLogConfig) LogGroupIdentifier() string {
	return strings.TrimSuffix(c.DestinationARN, ":*")
}

// DNSDestinationOf classifies a destination ARN and reads its region and
// account (empty for S3, whose bucket ARNs carry neither).
func DNSDestinationOf(arn string) (kind, region, account string) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 || parts[0] != "arn" {
		return DNSDestinationUnknown, "", ""
	}
	region, account = parts[3], parts[4]
	switch {
	case parts[2] == "logs" && strings.HasPrefix(parts[5], "log-group:"):
		return DNSDestinationCloudWatchLogs, region, account
	case parts[2] == "s3":
		return DNSDestinationS3, region, account
	case parts[2] == "firehose" && strings.HasPrefix(parts[5], "deliverystream/"):
		return DNSDestinationFirehose, region, account
	}
	return DNSDestinationUnknown, region, account
}

// DNSQueryLogReader reads one region's query logging and its logs.
type DNSQueryLogReader struct {
	resolver ResolverQueryLogAPI
	logs     LogsInsightsAPI
	sleep    func(context.Context, time.Duration) error
	wait     time.Duration
}

// NewDNSQueryLogReader builds a reader; either client may be nil.
func NewDNSQueryLogReader(r ResolverQueryLogAPI, l LogsInsightsAPI) *DNSQueryLogReader {
	return &DNSQueryLogReader{resolver: r, logs: l, sleep: sleepCtx, wait: dnsQueryWait}
}

// WithSleep replaces the polling delay (tests).
func (r *DNSQueryLogReader) WithSleep(f func(context.Context, time.Duration) error) *DNSQueryLogReader {
	r.sleep = f
	return r
}

// errNoResolverClient: the reader was built without a Resolver client.
var errNoResolverClient = errors.New("no route53resolver client")

// Configs lists the region's query logging configurations and the VPC
// associations of this account. A failed listing returns its error, named.
func (r *DNSQueryLogReader) Configs(ctx context.Context) ([]QueryLogConfig, error) {
	if r.resolver == nil {
		return nil, errNoResolverClient
	}
	byID := map[string]*QueryLogConfig{}
	var order []string
	var next *string
	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, fmt.Errorf("%w: resolver query log configs", errTooManyPages)
		}
		resp, err := r.resolver.ListResolverQueryLogConfigs(ctx, &route53resolver.ListResolverQueryLogConfigsInput{NextToken: next})
		if err != nil {
			return nil, listErr("route53resolver:ListResolverQueryLogConfigs", err)
		}
		for _, c := range resp.ResolverQueryLogConfigs {
			id := aws.ToString(c.Id)
			if id == "" || byID[id] != nil {
				continue
			}
			dest := aws.ToString(c.DestinationArn)
			kind, region, account := DNSDestinationOf(dest)
			byID[id] = &QueryLogConfig{
				ID: id, ARN: aws.ToString(c.Arn), Name: aws.ToString(c.Name), OwnerID: aws.ToString(c.OwnerId),
				Status: string(c.Status), ShareStatus: string(c.ShareStatus),
				DestinationARN: dest, DestinationKind: kind, DestinationRegion: region, DestinationAccount: account,
			}
			order = append(order, id)
		}
		if aws.ToString(resp.NextToken) == "" {
			break
		}
		next = resp.NextToken
	}
	next = nil
	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, fmt.Errorf("%w: resolver query log config associations", errTooManyPages)
		}
		resp, err := r.resolver.ListResolverQueryLogConfigAssociations(ctx,
			&route53resolver.ListResolverQueryLogConfigAssociationsInput{NextToken: next})
		if err != nil {
			return nil, listErr("route53resolver:ListResolverQueryLogConfigAssociations", err)
		}
		for _, a := range resp.ResolverQueryLogConfigAssociations {
			c := byID[aws.ToString(a.ResolverQueryLogConfigId)]
			if c == nil {
				continue // a configuration this account cannot list
			}
			assoc := QueryLogAssociation{VPCID: aws.ToString(a.ResourceId), Status: string(a.Status)}
			if a.Error != r53rtypes.ResolverQueryLogConfigAssociationErrorNone {
				assoc.Error = string(a.Error)
			}
			c.Associations = append(c.Associations, assoc)
		}
		if aws.ToString(resp.NextToken) == "" {
			break
		}
		next = resp.NextToken
	}
	out := make([]QueryLogConfig, 0, len(order))
	for _, id := range order {
		c := byID[id]
		sort.Slice(c.Associations, func(i, j int) bool { return c.Associations[i].VPCID < c.Associations[j].VPCID })
		out = append(out, *c)
	}
	return out, nil
}

/* ---------------------------------- windows --------------------------------- */

const (
	// DNSFirstReadWindow is how far back a log group's first read reaches.
	DNSFirstReadWindow = 24 * time.Hour
	// DNSMaxReadWindow caps one read: Logs Insights is charged per GB
	// scanned, and a log group unread for longer is read for its last seven
	// days, the gap before them recorded (Lapsed), never claimed.
	DNSMaxReadWindow = 7 * 24 * time.Hour
	// DNSIngestDelay is how long a read waits before claiming an interval:
	// Resolver delivers query logs to CloudWatch Logs within minutes.
	DNSIngestDelay = 10 * time.Minute
	// DNSLateArrival is how much later than its event time a query-log line
	// may reach CloudWatch Logs and still be read. Each read selects lines by
	// ARRIVAL (@ingestionTime) in its window, and searches event time from
	// DNSLateArrival before the window, so a line up to this late is read
	// exactly once; a later one is missed (late-data policy, spec §11.2). It
	// costs DNSLateArrival more data scanned per read.
	DNSLateArrival = 2 * time.Hour
	// DNSResultLimit is the query's row limit (the Logs Insights maximum
	// per page): reaching it means groups may be missing (Truncated).
	DNSResultLimit = 10000
	// dnsQueryWait bounds how long one query may run before it is stopped.
	dnsQueryWait = 2 * time.Minute
	// dnsPollInterval is the delay between GetQueryResults polls.
	dnsPollInterval = 2 * time.Second
	// dnsMaxResultPages bounds GetQueryResults pagination (10 x 10,000).
	dnsMaxResultPages = 10
)

// DNSWindow is the interval one read covers: [From, To), whole seconds.
type DNSWindow struct {
	// Since is the previous read's high-water mark; zero on a first read.
	Since time.Time
	From  time.Time
	To    time.Time
	// Lapsed: Since was older than DNSMaxReadWindow; [Since, From) is not read.
	Lapsed bool
}

// Empty reports a window with nothing to read yet.
func (w DNSWindow) Empty() bool { return !w.From.Before(w.To) }

// DNSWindowFor is the next window of a log group whose last read ended at
// since (zero for none), as of now.
func DNSWindowFor(since, now time.Time) DNSWindow {
	to := now.UTC().Add(-DNSIngestDelay).Truncate(time.Second)
	w := DNSWindow{Since: since.UTC(), To: to}
	switch {
	case since.IsZero():
		w.From = to.Add(-DNSFirstReadWindow)
	case to.Sub(since) > DNSMaxReadWindow:
		w.From, w.Lapsed = to.Add(-DNSMaxReadWindow), true
	default:
		w.From = since.UTC()
	}
	return w
}

/* ---------------------------------- the read -------------------------------- */

// DNSLookupAggregate is one (source, VPC, model host) group of a window.
type DNSLookupAggregate struct {
	SrcAddr    string
	InstanceID string
	VPCID      string
	// Domain is the normalised host; Provider and Control from its entry.
	Domain    string
	Provider  string
	Control   bool
	Queries   int64
	FirstSeen time.Time
	LastSeen  time.Time
}

// DNSQueryRead is one log group's read of one window.
type DNSQueryRead struct {
	LogGroup   string
	Window     DNSWindow
	Aggregates []DNSLookupAggregate
	// Dropped counts returned rows whose name was not on the list after all;
	// they are discarded without being stored or named.
	Dropped int
	// Truncated: the row limit was reached, so groups may be missing.
	Truncated bool
	// Settled: the query completed; a failed read claims nothing.
	Settled                                      bool
	RecordsScanned, RecordsMatched, BytesScanned float64
}

// Partial reports a settled read that does not speak for its whole window.
func (r DNSQueryRead) Partial() bool { return r.Settled && (r.Truncated || r.Window.Lapsed) }

var (
	errNoLogsClient = errors.New("no cloudwatch logs client")
	// ErrDNSQueryIncomplete: Logs Insights did not finish the query (failed,
	// cancelled, timed out, or still running at our deadline).
	ErrDNSQueryIncomplete = errors.New("the Logs Insights query did not complete")
)

// ReadModelEndpointLookups runs ModelEndpointQuery over one log group for one
// window and returns the aggregates. A query still running at the deadline is
// stopped and reported, never half-read.
func (r *DNSQueryLogReader) ReadModelEndpointLookups(ctx context.Context, logGroup string, w DNSWindow) (DNSQueryRead, error) {
	read := DNSQueryRead{LogGroup: logGroup, Window: w}
	if r.logs == nil {
		return read, errNoLogsClient
	}
	if w.Empty() {
		read.Settled = true
		return read, nil
	}
	start, err := r.logs.StartQuery(ctx, &cloudwatchlogs.StartQueryInput{
		LogGroupIdentifiers: []string{logGroup},
		// Event time: from DNSLateArrival before the window (late lines) to
		// its end; the query keeps only lines that ARRIVED in [From, To).
		StartTime:   aws.Int64(w.From.Add(-DNSLateArrival).Unix()),
		EndTime:     aws.Int64(w.To.Unix() - 1),
		QueryString: aws.String(ModelEndpointQueryFor(w)),
		Limit:       aws.Int32(DNSResultLimit),
	})
	if err != nil {
		return read, logsErr("logs:StartQuery", err)
	}
	id := aws.ToString(start.QueryId)
	deadline := time.Now().Add(r.wait)
	var out *cloudwatchlogs.GetQueryResultsOutput
	for {
		out, err = r.logs.GetQueryResults(ctx, &cloudwatchlogs.GetQueryResultsInput{QueryId: aws.String(id)})
		if err != nil {
			r.stop(id)
			return read, logsErr("logs:GetQueryResults", err)
		}
		switch out.Status {
		case cwltypes.QueryStatusComplete:
		case cwltypes.QueryStatusScheduled, cwltypes.QueryStatusRunning:
			if time.Now().After(deadline) {
				r.stop(id)
				return read, fmt.Errorf("logs:GetQueryResults: %w: still %s after %s", ErrDNSQueryIncomplete, out.Status, r.wait)
			}
			if serr := r.sleep(ctx, dnsPollInterval); serr != nil {
				r.stop(id)
				return read, serr
			}
			continue
		default:
			return read, fmt.Errorf("logs:GetQueryResults: %w: %s", ErrDNSQueryIncomplete, out.Status)
		}
		break
	}
	if s := out.Statistics; s != nil {
		read.RecordsScanned, read.RecordsMatched, read.BytesScanned = s.RecordsScanned, s.RecordsMatched, s.BytesScanned
	}
	rows := out.Results
	for page := 1; aws.ToString(out.NextToken) != ""; page++ {
		if page >= dnsMaxResultPages {
			read.Truncated = true
			break
		}
		out, err = r.logs.GetQueryResults(ctx, &cloudwatchlogs.GetQueryResultsInput{QueryId: aws.String(id), NextToken: out.NextToken})
		if err != nil {
			return read, logsErr("logs:GetQueryResults", err)
		}
		rows = append(rows, out.Results...)
	}
	if len(rows) >= DNSResultLimit {
		read.Truncated = true
	}
	read.Aggregates, read.Dropped = parseDNSRows(rows)
	read.Settled = true
	return read, nil
}

// stop asks Logs Insights to stop a query we no longer wait for, so it stops
// costing the customer. Best effort, on its own short deadline.
func (r *DNSQueryLogReader) stop(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = r.logs.StopQuery(ctx, &cloudwatchlogs.StopQueryInput{QueryId: aws.String(id)})
}

// logsErr names a CloudWatch Logs failure; LimitExceededException (too many
// concurrent queries) is a throttle, not a refusal.
func logsErr(call string, err error) error {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && apiErr.ErrorCode() == "LimitExceededException" {
		return &namedCallError{call: call, raw: err,
			classified: fmt.Errorf("%w: %s", ErrThrottled, apiErr.ErrorMessage())}
	}
	return listErr(call, err)
}

var (
	instanceIDPattern = regexp.MustCompile(`^i-[0-9a-f]{8,17}$`)
	vpcIDPattern      = regexp.MustCompile(`^vpc-[0-9a-f]{8,17}$`)
)

// parseDNSRows turns Logs Insights rows into aggregates, keeping only names
// on the list (normalised, so case variants merge) and well-formed ids.
func parseDNSRows(rows [][]cwltypes.ResultField) ([]DNSLookupAggregate, int) {
	type key struct{ src, inst, vpc, domain string }
	byKey := map[key]*DNSLookupAggregate{}
	var order []key
	dropped := 0
	for _, row := range rows {
		f := map[string]string{}
		for _, c := range row {
			f[aws.ToString(c.Field)] = aws.ToString(c.Value)
		}
		ep, domain, ok := MatchModelEndpoint(f[dnsFieldQueryName])
		if !ok {
			dropped++
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(f[dnsFieldQueries]), 10, 64)
		if err != nil || n <= 0 {
			dropped++
			continue
		}
		k := key{src: cleanIP(f[dnsFieldSrcAddr]), inst: cleanID(f[dnsFieldInstance], instanceIDPattern),
			vpc: cleanID(f[dnsFieldVPC], vpcIDPattern), domain: domain}
		first, _ := ParseInsightsTime(f[dnsFieldFirstSeen])
		last, _ := ParseInsightsTime(f[dnsFieldLastSeen])
		a := byKey[k]
		if a == nil {
			a = &DNSLookupAggregate{SrcAddr: k.src, InstanceID: k.inst, VPCID: k.vpc, Domain: domain,
				Provider: ep.Provider, Control: ep.Control}
			byKey[k] = a
			order = append(order, k)
		}
		a.Queries += n
		if !first.IsZero() && (a.FirstSeen.IsZero() || first.Before(a.FirstSeen)) {
			a.FirstSeen = first
		}
		if last.After(a.LastSeen) {
			a.LastSeen = last
		}
	}
	out := make([]DNSLookupAggregate, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.VPCID != b.VPCID {
			return a.VPCID < b.VPCID
		}
		if a.SrcAddr != b.SrcAddr {
			return a.SrcAddr < b.SrcAddr
		}
		if a.InstanceID != b.InstanceID {
			return a.InstanceID < b.InstanceID
		}
		return a.Domain < b.Domain
	})
	return out, dropped
}

func cleanIP(s string) string {
	s = strings.TrimSpace(s)
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return ""
}

func cleanID(s string, re *regexp.Regexp) string {
	s = strings.TrimSpace(s)
	if re.MatchString(s) {
		return s
	}
	return ""
}

// ParseInsightsTime reads a Logs Insights timestamp ("2026-11-05
// 10:00:00.000", UTC), RFC 3339, or epoch milliseconds.
func ParseInsightsTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"2006-01-02 15:04:05.000", "2006-01-02 15:04:05", time.RFC3339Nano} {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return t.UTC(), nil
		}
	}
	if ms, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.UnixMilli(ms).UTC(), nil
	}
	return time.Time{}, fmt.Errorf("unrecognised Logs Insights timestamp %q", s)
}

/* -------------------------------- attribution ------------------------------- */

// Kinds of network interface a source address can be on.
const (
	ENIKindLambda   = "lambda"
	ENIKindECSTask  = "ecs_task"
	ENIKindEKSPod   = "eks_pod" // a VPC CNI interface: the address is a pod's
	ENIKindInstance = "instance"
	ENIKindOther    = "other"
)

// lambdaENIPrefix is how Lambda describes the interfaces it creates.
const lambdaENIPrefix = "AWS Lambda VPC ENI"

// ENIInfo is the network interface holding one private address NOW. An
// address is reused once its interface is gone, so this is scan-time
// evidence, not proof of who made a lookup days ago.
type ENIInfo struct {
	ID               string
	VPCID            string
	Kind             string
	Description      string
	InterfaceType    string
	RequesterID      string
	RequesterManaged bool
	// InstanceID is the instance the interface is attached to, if any.
	InstanceID string
	// AttachTime is when the interface was attached, when AWS reports it.
	AttachTime *time.Time
	// SubnetID and SecurityGroupIDs (sorted) identify which Lambda functions a
	// Lambda interface can stand for.
	SubnetID         string
	SecurityGroupIDs []string
	// PrimaryIP: the address is the interface's primary private address.
	PrimaryIP bool
	// LambdaFunctionHint is what follows "AWS Lambda VPC ENI-": the function
	// that created the interface (Lambda shares one interface across the
	// functions with the same subnets and security groups).
	LambdaFunctionHint string
	// ECSAttachmentARN is an ECS task interface's attachment.
	ECSAttachmentARN string
}

// DNSAttributionReader resolves source addresses to interfaces and tasks.
type DNSAttributionReader struct {
	eni NetworkInterfaceAPI
	ecs ECSTaskAPI
}

// NewDNSAttributionReader builds a reader; either client may be nil.
func NewDNSAttributionReader(e NetworkInterfaceAPI, c ECSTaskAPI) *DNSAttributionReader {
	return &DNSAttributionReader{eni: e, ecs: c}
}

// dnsAddressBatch is how many addresses one DescribeNetworkInterfaces asks for.
const dnsAddressBatch = 100

var errNoENIClient = errors.New("no ec2 client to resolve network interfaces")

// NetworkInterfaces maps each private address of one VPC to the interface
// holding it now. An address no interface holds is absent from the map.
func (r *DNSAttributionReader) NetworkInterfaces(ctx context.Context, vpcID string, ips []string) (map[string]ENIInfo, error) {
	out := map[string]ENIInfo{}
	if len(ips) == 0 {
		return out, nil
	}
	if r.eni == nil {
		return out, errNoENIClient
	}
	want := map[string]bool{}
	for _, ip := range ips {
		want[ip] = true
	}
	sorted := append([]string(nil), ips...)
	sort.Strings(sorted)
	for i := 0; i < len(sorted); i += dnsAddressBatch {
		batch := sorted[i:min(i+dnsAddressBatch, len(sorted))]
		filters := []ec2types.Filter{{Name: aws.String("addresses.private-ip-address"), Values: batch}}
		if vpcID != "" {
			filters = append(filters, ec2types.Filter{Name: aws.String("vpc-id"), Values: []string{vpcID}})
		}
		var next *string
		for page := 0; ; page++ {
			if page >= maxPages {
				return out, fmt.Errorf("%w: network interfaces", errTooManyPages)
			}
			resp, err := r.eni.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{Filters: filters, NextToken: next})
			if err != nil {
				return out, listErr("ec2:DescribeNetworkInterfaces", err)
			}
			for _, ni := range resp.NetworkInterfaces {
				info := eniInfo(ni)
				primary := aws.ToString(ni.PrivateIpAddress)
				for _, a := range ni.PrivateIpAddresses {
					ip := aws.ToString(a.PrivateIpAddress)
					if !want[ip] {
						continue
					}
					e := info
					e.PrimaryIP = ip == primary || aws.ToBool(a.Primary)
					out[ip] = e
				}
				if want[primary] {
					if _, ok := out[primary]; !ok {
						e := info
						e.PrimaryIP = true
						out[primary] = e
					}
				}
			}
			if aws.ToString(resp.NextToken) == "" {
				break
			}
			next = resp.NextToken
		}
	}
	return out, nil
}

// eniInfo classifies one interface by what AWS says about it.
func eniInfo(ni ec2types.NetworkInterface) ENIInfo {
	desc := aws.ToString(ni.Description)
	e := ENIInfo{
		ID: aws.ToString(ni.NetworkInterfaceId), VPCID: aws.ToString(ni.VpcId),
		Description: truncateText(desc, 200), InterfaceType: string(ni.InterfaceType),
		RequesterID: aws.ToString(ni.RequesterId), RequesterManaged: aws.ToBool(ni.RequesterManaged),
		Kind: ENIKindOther,
	}
	if ni.Attachment != nil {
		e.InstanceID = aws.ToString(ni.Attachment.InstanceId)
		e.AttachTime = ni.Attachment.AttachTime
	}
	e.SubnetID = aws.ToString(ni.SubnetId)
	for _, g := range ni.Groups {
		if id := aws.ToString(g.GroupId); id != "" {
			e.SecurityGroupIDs = append(e.SecurityGroupIDs, id)
		}
	}
	sort.Strings(e.SecurityGroupIDs)
	switch {
	case strings.HasPrefix(desc, lambdaENIPrefix) || ni.InterfaceType == ec2types.NetworkInterfaceTypeLambda:
		e.Kind = ENIKindLambda
		hint := strings.TrimPrefix(desc, lambdaENIPrefix)
		hint = strings.TrimLeft(hint, "-: ")
		e.LambdaFunctionHint = hint
	case isECSAttachment(desc):
		e.Kind, e.ECSAttachmentARN = ENIKindECSTask, desc
	case strings.HasPrefix(desc, "aws-K8S-"):
		e.Kind = ENIKindEKSPod
	case e.InstanceID != "":
		e.Kind = ENIKindInstance
	}
	return e
}

// isECSAttachment: ECS describes a task's interface by its attachment ARN.
func isECSAttachment(desc string) bool {
	parts := strings.SplitN(desc, ":", 6)
	return len(parts) == 6 && parts[0] == "arn" && parts[2] == "ecs" && strings.HasPrefix(parts[5], "attachment/")
}

func truncateText(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ECSTaskRef is the running task an interface belongs to.
type ECSTaskRef struct {
	TaskARN, ClusterARN, TaskDefinitionARN string
}

const (
	// dnsECSClusterCap and dnsECSTaskCap bound the task search.
	dnsECSClusterCap = 100
	dnsECSTaskCap    = 5000
	dnsECSDescribe   = 100
)

var errNoECSClient = errors.New("no ecs client to resolve task interfaces")

// ECSTasksByENI finds the RUNNING task of each interface id. A task that has
// stopped since the lookup is not found: its interface is gone too.
func (r *DNSAttributionReader) ECSTasksByENI(ctx context.Context, eniIDs []string) (map[string]ECSTaskRef, error) {
	out := map[string]ECSTaskRef{}
	if len(eniIDs) == 0 {
		return out, nil
	}
	if r.ecs == nil {
		return out, errNoECSClient
	}
	want := map[string]bool{}
	for _, id := range eniIDs {
		want[id] = true
	}
	var clusters []string
	var next *string
	for page := 0; ; page++ {
		if page >= maxPages {
			return out, fmt.Errorf("%w: ecs clusters", errTooManyPages)
		}
		resp, err := r.ecs.ListClusters(ctx, &ecs.ListClustersInput{NextToken: next})
		if err != nil {
			return out, listErr("ecs:ListClusters", err)
		}
		clusters = append(clusters, resp.ClusterArns...)
		if aws.ToString(resp.NextToken) == "" || len(clusters) >= dnsECSClusterCap {
			break
		}
		next = resp.NextToken
	}
	examined := 0
	for _, cluster := range clusters {
		if len(out) == len(want) || examined >= dnsECSTaskCap {
			break
		}
		next = nil
		for page := 0; page < maxPages && examined < dnsECSTaskCap; page++ {
			resp, err := r.ecs.ListTasks(ctx, &ecs.ListTasksInput{Cluster: aws.String(cluster),
				DesiredStatus: ecstypes.DesiredStatusRunning, NextToken: next})
			if err != nil {
				return out, listErr("ecs:ListTasks", err)
			}
			arns := resp.TaskArns
			examined += len(arns)
			for i := 0; i < len(arns); i += dnsECSDescribe {
				batch := arns[i:min(i+dnsECSDescribe, len(arns))]
				d, err := r.ecs.DescribeTasks(ctx, &ecs.DescribeTasksInput{Cluster: aws.String(cluster), Tasks: batch})
				if err != nil {
					return out, listErr("ecs:DescribeTasks", err)
				}
				for _, t := range d.Tasks {
					for _, att := range t.Attachments {
						for _, kv := range att.Details {
							if aws.ToString(kv.Name) == "networkInterfaceId" && want[aws.ToString(kv.Value)] {
								out[aws.ToString(kv.Value)] = ECSTaskRef{TaskARN: aws.ToString(t.TaskArn),
									ClusterARN: aws.ToString(t.ClusterArn), TaskDefinitionARN: aws.ToString(t.TaskDefinitionArn)}
							}
						}
					}
				}
			}
			if aws.ToString(resp.NextToken) == "" {
				break
			}
			next = resp.NextToken
		}
	}
	return out, nil
}
