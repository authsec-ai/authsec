package awsdiscovery

import (
	"context"
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
)

// VPC flow-log reader (SPEC-secops-backend-upgrade.md C4, W6).
//
// When a connector names the CloudWatch Logs log group its VPC flow logs
// are delivered to (agent_join_setting.flow_log_groups), this reads, per
// minute, the traffic from the estate to the addresses that model provider
// and egress hosts resolved to (taken from the stored DNS lookups): bytes
// and packets per source address, interface and destination. The address
// list is in the Logs Insights query itself, so no other flow is read. The
// default (version 2) flow-log format is assumed: srcAddr, dstAddr, bytes,
// packets, interfaceId.

// MaxFlowDestinations bounds the addresses one read filters on.
const MaxFlowDestinations = 200

// FlowMinute is one minute of one source's traffic to one destination.
type FlowMinute struct {
	Minute    time.Time
	SrcAddr   string
	ENI       string
	DstAddr   string
	BytesOut  int64
	Packets   int64
	Partial   bool
	LogGroup  string
	Truncated bool
}

// FlowRead is one log group's read of one window.
type FlowRead struct {
	LogGroup  string
	Window    DNSWindow
	Rows      []FlowMinute
	Truncated bool
	Settled   bool
}

// FlowLogReader reads flow logs with Logs Insights.
type FlowLogReader struct {
	logs  LogsInsightsAPI
	sleep func(context.Context, time.Duration) error
	wait  time.Duration
}

// NewFlowLogReader builds a reader.
func NewFlowLogReader(l LogsInsightsAPI) *FlowLogReader {
	return &FlowLogReader{logs: l, sleep: sleepCtx, wait: dnsQueryWait}
}

// WithSleep replaces the polling delay (tests).
func (r *FlowLogReader) WithSleep(f func(context.Context, time.Duration) error) *FlowLogReader {
	r.sleep = f
	return r
}

var eniPattern = regexp.MustCompile(`^eni-[0-9a-f]{8,17}$`)

// FlowQueryFor is the window's query restricted to the destinations.
func FlowQueryFor(w DNSWindow, dsts []string) string {
	quoted := make([]string, 0, len(dsts))
	for _, d := range dsts {
		quoted = append(quoted, strconv.Quote(d))
	}
	return "fields @timestamp, srcAddr, dstAddr, bytes, packets, interfaceId, datefloor(@timestamp, 1m) as minute" +
		"\n| filter @ingestionTime >= " + strconv.FormatInt(w.From.UnixMilli(), 10) +
		" and @ingestionTime < " + strconv.FormatInt(w.To.UnixMilli(), 10) +
		"\n| filter dstAddr in [" + strings.Join(quoted, ", ") + "]" +
		"\n| stats sum(bytes) as bytes_out, sum(packets) as pkts by minute, srcAddr, dstAddr, interfaceId" +
		"\n| limit " + strconv.Itoa(DNSResultLimit)
}

// CleanDestinations keeps valid, distinct addresses (sorted), at most
// MaxFlowDestinations.
func CleanDestinations(ips []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, ip := range ips {
		p := net.ParseIP(strings.TrimSpace(ip))
		if p == nil {
			continue
		}
		s := p.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	if len(out) > MaxFlowDestinations {
		out = out[:MaxFlowDestinations]
	}
	return out
}

// ReadFlows runs FlowQueryFor over one log group. No destinations: nothing
// is read (settled, empty).
func (r *FlowLogReader) ReadFlows(ctx context.Context, logGroup string, w DNSWindow, dsts []string) (FlowRead, error) {
	read := FlowRead{LogGroup: logGroup, Window: w}
	dsts = CleanDestinations(dsts)
	if w.Empty() || len(dsts) == 0 {
		read.Settled = true
		return read, nil
	}
	if r.logs == nil {
		return read, errNoLogsClient
	}
	allowed := map[string]bool{}
	for _, d := range dsts {
		allowed[d] = true
	}
	start, err := r.logs.StartQuery(ctx, &cloudwatchlogs.StartQueryInput{
		LogGroupIdentifiers: []string{logGroup},
		StartTime:           aws.Int64(w.From.Add(-DNSLateArrival).Unix()),
		EndTime:             aws.Int64(w.To.Unix() - 1),
		QueryString:         aws.String(FlowQueryFor(w, dsts)),
		Limit:               aws.Int32(DNSResultLimit),
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
			return read, logsErr("logs:GetQueryResults", err)
		}
		if out.Status == cwltypes.QueryStatusComplete {
			break
		}
		if out.Status != cwltypes.QueryStatusScheduled && out.Status != cwltypes.QueryStatusRunning {
			return read, fmt.Errorf("logs:GetQueryResults: %w: %s", ErrDNSQueryIncomplete, out.Status)
		}
		if time.Now().After(deadline) {
			_, _ = r.logs.StopQuery(context.Background(), &cloudwatchlogs.StopQueryInput{QueryId: aws.String(id)})
			return read, fmt.Errorf("logs:GetQueryResults: %w: still %s after %s", ErrDNSQueryIncomplete, out.Status, r.wait)
		}
		if serr := r.sleep(ctx, dnsPollInterval); serr != nil {
			return read, serr
		}
	}
	rows := out.Results
	if len(rows) >= DNSResultLimit {
		read.Truncated = true
	}
	for _, row := range rows {
		f := map[string]string{}
		for _, c := range row {
			f[aws.ToString(c.Field)] = aws.ToString(c.Value)
		}
		dst := cleanIP(f["dstAddr"])
		if !allowed[dst] {
			continue // only the listed destinations are ever kept
		}
		minute, err := ParseInsightsTime(f["minute"])
		if err != nil {
			continue
		}
		b, _ := strconv.ParseFloat(strings.TrimSpace(f["bytes_out"]), 64)
		p, _ := strconv.ParseFloat(strings.TrimSpace(f["pkts"]), 64)
		read.Rows = append(read.Rows, FlowMinute{Minute: minute.UTC().Truncate(time.Minute), SrcAddr: cleanIP(f["srcAddr"]),
			ENI: cleanID(f["interfaceId"], eniPattern), DstAddr: dst, BytesOut: int64(b), Packets: int64(p), LogGroup: logGroup})
	}
	read.Settled = true
	return read, nil
}
