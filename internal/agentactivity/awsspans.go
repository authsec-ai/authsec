package agentactivity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/smithy-go"
)

// AgentCore observability spans (spec §4.2): CloudWatch Logs Insights over
// the aws/spans log group, where AgentCore (and X-Ray Transaction Search)
// writes one JSON span record per log event.
//
// UNVERIFIED against a lab account: the record shape (OTLP-like, attributes
// as a flat object, kind/status as names) and that cloud.resource_id carries
// the runtime ARN. The parser accepts both the flat and the OTLP list form.

// AWSSpansLogGroup is the log group spans are read from.
const AWSSpansLogGroup = "aws/spans"

// AWSSpansQuery selects GenAI / agent / MCP span records, oldest first; the
// limit is appended.
const AWSSpansQuery = `fields @timestamp, @ingestionTime, @message
| filter @message like /gen_ai|openinference|traceloop|mcp\./
| sort @ingestionTime asc`

// SpanLateArrival is how much later than its event time a span may reach
// aws/spans and still be read. A read selects spans by ARRIVAL
// (@ingestionTime) in [Since, Until) and searches event time from
// SpanLateArrival before Since, so a span up to this late is read once by the
// read whose window holds its arrival; a later one is missed.
const SpanLateArrival = 2 * time.Hour

// spansQueryFor is AWSSpansQuery restricted to spans that arrived in
// [since, until), oldest arrival first.
func spansQueryFor(since, until time.Time, limit int) string {
	return strings.Replace(AWSSpansQuery, "\n| sort",
		fmt.Sprintf("\n| filter @ingestionTime >= %d and @ingestionTime < %d\n| sort", since.UnixMilli(), until.UnixMilli()), 1) +
		fmt.Sprintf("\n| limit %d", limit)
}

// Span reader defaults (spec §8).
const (
	DefaultSpanQueryLimit  = 1000
	MaxSpanQueryLimit      = 10000
	DefaultSpanPollEvery   = time.Second
	DefaultSpanPollTimeout = 60 * time.Second
)

// Coverage states of the span reader (agent_activity_cursor.state).
const (
	SpanStateReached           = "reached"
	SpanStatePartial           = "partial"
	SpanStatePermissionMissing = "permission_missing"
	SpanStateNotConfigured     = "not_configured"
	SpanStateError             = "error"
)

// LogsInsightsAPI is the part of the CloudWatch Logs client the reader uses.
type LogsInsightsAPI interface {
	StartQuery(ctx context.Context, in *cloudwatchlogs.StartQueryInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error)
	GetQueryResults(ctx context.Context, in *cloudwatchlogs.GetQueryResultsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetQueryResultsOutput, error)
	StopQuery(ctx context.Context, in *cloudwatchlogs.StopQueryInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StopQueryOutput, error)
}

// NewLogsInsightsClient builds the client for one region's config.
func NewLogsInsightsClient(cfg aws.Config) LogsInsightsAPI { return cloudwatchlogs.NewFromConfig(cfg) }

// SpanQuery is one read window.
type SpanQuery struct {
	Since, Until time.Time
	Limit        int
	PollEvery    time.Duration
	PollTimeout  time.Duration
	// Sleep replaces the poll wait (tests).
	Sleep func(context.Context, time.Duration) error
}

// SpanRead is what one read returned.
type SpanRead struct {
	Spans   []Span
	Records int // result rows
	Invalid int // rows whose @message was not a span record
	// Last is the newest arrival (@ingestionTime, else @timestamp) read; zero when none.
	Last time.Time
	// CapHit: the query returned Limit rows, so the window may hold more.
	CapHit bool
}

// ErrSpanQueryTimeout: the query did not finish within PollTimeout.
var ErrSpanQueryTimeout = errors.New("logs insights query did not finish in time")

// ReadAWSSpans runs one Logs Insights query over aws/spans for the window.
func ReadAWSSpans(ctx context.Context, api LogsInsightsAPI, q SpanQuery) (SpanRead, error) {
	var out SpanRead
	if q.Limit <= 0 {
		q.Limit = DefaultSpanQueryLimit
	}
	if q.Limit > MaxSpanQueryLimit {
		q.Limit = MaxSpanQueryLimit
	}
	if q.PollEvery <= 0 {
		q.PollEvery = DefaultSpanPollEvery
	}
	if q.PollTimeout <= 0 {
		q.PollTimeout = DefaultSpanPollTimeout
	}
	sleep := q.Sleep
	if sleep == nil {
		sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
	started, err := api.StartQuery(ctx, &cloudwatchlogs.StartQueryInput{
		LogGroupNames: []string{AWSSpansLogGroup},
		// Event time reaches SpanLateArrival back; the query keeps only spans
		// that ARRIVED in [Since, Until).
		StartTime:   aws.Int64(q.Since.Add(-SpanLateArrival).Unix()),
		EndTime:     aws.Int64(q.Until.Unix()),
		QueryString: aws.String(spansQueryFor(q.Since, q.Until, q.Limit)),
		Limit:       aws.Int32(int32(q.Limit)),
	})
	if err != nil {
		return out, fmt.Errorf("logs:StartQuery: %w", err)
	}
	id := aws.ToString(started.QueryId)
	deadline := time.Now().Add(q.PollTimeout)
	for {
		res, err := api.GetQueryResults(ctx, &cloudwatchlogs.GetQueryResultsInput{QueryId: aws.String(id)})
		if err != nil {
			return out, fmt.Errorf("logs:GetQueryResults: %w", err)
		}
		switch res.Status {
		case cwltypes.QueryStatusComplete:
			out = readRows(res.Results, q.Limit)
			return out, nil
		case cwltypes.QueryStatusFailed, cwltypes.QueryStatusCancelled, cwltypes.QueryStatusTimeout:
			return out, fmt.Errorf("logs insights query %s", strings.ToLower(string(res.Status)))
		}
		if time.Now().After(deadline) {
			stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, _ = api.StopQuery(stopCtx, &cloudwatchlogs.StopQueryInput{QueryId: aws.String(id)})
			cancel()
			return out, ErrSpanQueryTimeout
		}
		if err := sleep(ctx, q.PollEvery); err != nil {
			return out, err
		}
	}
}

// insightsTime is the format of @timestamp in Logs Insights results (UTC).
const insightsTime = "2006-01-02 15:04:05.000"

func readRows(rows [][]cwltypes.ResultField, limit int) SpanRead {
	var out SpanRead
	out.Records = len(rows)
	out.CapHit = len(rows) >= limit
	for _, row := range rows {
		var ts, arrived time.Time
		var msg string
		for _, f := range row {
			switch aws.ToString(f.Field) {
			case "@timestamp":
				if t, err := time.Parse(insightsTime, aws.ToString(f.Value)); err == nil {
					ts = t.UTC()
				}
			case "@ingestionTime":
				if t, err := time.Parse(insightsTime, aws.ToString(f.Value)); err == nil {
					arrived = t.UTC()
				}
			case "@message":
				msg = aws.ToString(f.Value)
			}
		}
		// Last is the newest ARRIVAL read: the cursor is an arrival time.
		mark := arrived
		if mark.IsZero() {
			mark = ts
		}
		if mark.After(out.Last) {
			out.Last = mark
		}
		sp, err := ParseAWSSpanRecord([]byte(msg))
		if err != nil {
			out.Invalid++
			continue
		}
		if sp.Start.IsZero() && sp.End.IsZero() {
			sp.Start = ts
		}
		out.Spans = append(out.Spans, sp)
	}
	return out
}

type awsSpanRecord struct {
	Resource struct {
		Attributes json.RawMessage `json:"attributes"`
	} `json:"resource"`
	Scope struct {
		Name string `json:"name"`
	} `json:"scope"`
	jsonSpan
}

// ParseAWSSpanRecord parses one aws/spans record.
func ParseAWSSpanRecord(raw []byte) (Span, error) {
	var r awsSpanRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return Span{}, fmt.Errorf("%w: %v", ErrBadOTLP, err)
	}
	if r.TraceID == "" || r.SpanID == "" {
		return Span{}, fmt.Errorf("%w: span record without traceId or spanId", ErrBadOTLP)
	}
	sp, err := r.jsonSpan.span()
	if err != nil {
		return Span{}, err
	}
	res, err := attributesOf(r.Resource.Attributes)
	if err != nil {
		return Span{}, err
	}
	sp.Resource, sp.Scope = res, r.Scope.Name
	return sp, nil
}

// SpanReadState maps a read failure to a coverage state and the AWS error
// code: a refused call is permission_missing; a missing log group (no
// Transaction Search / AgentCore observability) not_configured.
func SpanReadState(err error) (state, code string) {
	if err == nil {
		return SpanStateReached, ""
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		code = api.ErrorCode()
		switch code {
		case "AccessDeniedException", "AccessDenied", "UnauthorizedOperation", "UnrecognizedClientException":
			return SpanStatePermissionMissing, code
		case "ResourceNotFoundException":
			return SpanStateNotConfigured, code
		}
		return SpanStateError, code
	}
	return SpanStateError, ""
}
