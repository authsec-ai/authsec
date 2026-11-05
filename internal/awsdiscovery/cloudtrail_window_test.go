package awsdiscovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/authsec-ai/authsec/internal/agentruntime"
)

// windowTrail is a CloudTrail that honours StartTime, EndTime and an
// EventSource LookupAttribute, returns events newest first in pages of
// pageSize, and remembers every input it was asked.
type windowTrail struct {
	events   []cttypes.Event
	pageSize int
	err      error
	inputs   []cloudtrail.LookupEventsInput
}

func (f *windowTrail) LookupEvents(_ context.Context, in *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	f.inputs = append(f.inputs, *in)
	if f.err != nil {
		return nil, f.err
	}
	var match []cttypes.Event
	for _, e := range f.events {
		t := aws.ToTime(e.EventTime)
		if in.StartTime != nil && t.Before(*in.StartTime) || in.EndTime != nil && t.After(*in.EndTime) {
			continue
		}
		if len(in.LookupAttributes) == 1 && in.LookupAttributes[0].AttributeKey == cttypes.LookupAttributeKeyEventSource &&
			aws.ToString(e.EventSource) != aws.ToString(in.LookupAttributes[0].AttributeValue) {
			continue
		}
		match = append(match, e)
	}
	sort.SliceStable(match, func(i, j int) bool { return aws.ToTime(match[i].EventTime).After(aws.ToTime(match[j].EventTime)) })
	size := f.pageSize
	if size == 0 {
		size = lookupEventsPerPage
	}
	start := 0
	if in.NextToken != nil {
		fmt.Sscanf(*in.NextToken, "%d", &start)
	}
	end := start + size
	out := &cloudtrail.LookupEventsOutput{}
	if end < len(match) {
		out.NextToken = aws.String(fmt.Sprint(end))
	} else {
		end = len(match)
	}
	out.Events = match[start:end]
	return out, nil
}

func (f *windowTrail) DescribeTrails(context.Context, *cloudtrail.DescribeTrailsInput, ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
	return &cloudtrail.DescribeTrailsOutput{}, nil
}

func (f *windowTrail) GetTrailStatus(context.Context, *cloudtrail.GetTrailStatusInput, ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
	return &cloudtrail.GetTrailStatusOutput{}, nil
}

var windowNow = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func trailEvt(id, source, name string, at time.Time, extra map[string]any) cttypes.Event {
	rec := map[string]any{
		"eventID": id, "eventSource": source, "eventName": name, "eventType": "AwsApiCall",
		"eventTime": at.UTC().Format(time.RFC3339),
		"userIdentity": map[string]any{
			"type": "AssumedRole", "principalId": "AROAEXAMPLE:fn", "arn": "arn:aws:sts::1:assumed-role/r/fn",
			"sessionContext": map[string]any{"sessionIssuer": map[string]any{
				"type": "Role", "principalId": "AROAEXAMPLE", "arn": "arn:aws:iam::1:role/r"}},
		},
	}
	for k, v := range extra {
		rec[k] = v
	}
	raw, _ := json.Marshal(rec)
	return cttypes.Event{EventId: aws.String(id), EventSource: aws.String(source), EventName: aws.String(name),
		EventTime: aws.Time(at), CloudTrailEvent: aws.String(string(raw))}
}

func readerAt(api CloudTrailAPI) *CloudTrailReader {
	return NewCloudTrailReader(api).WithClock(func() time.Time { return windowNow })
}

// A first read covers the 90 days LookupEvents can reach and settles up to
// the delivery delay; the general pass is unfiltered, the focused pass asks
// for bedrock.amazonaws.com only.
func TestReadWindowFirstReadCoversNinetyDays(t *testing.T) {
	api := &windowTrail{events: []cttypes.Event{
		trailEvt("old", agentruntime.SourceBedrock, "Converse", windowNow.Add(-80*24*time.Hour), nil),
		trailEvt("s3", "s3.amazonaws.com", "GetObject", windowNow.Add(-time.Hour), nil),
	}}
	r := readerAt(api)

	general, err := r.ReadWindow(context.Background(), TrailWindowRequest{Stream: TrailStreamGeneral})
	if err != nil || !general.Settled || general.Partial {
		t.Fatalf("general = settled %v partial %v err %v", general.Settled, general.Partial, err)
	}
	if want := windowNow.Add(-TrailLookbackLimit + trailLookbackMargin); !general.WindowFrom.Equal(want) || !general.CoveredFrom.Equal(want) {
		t.Fatalf("window from %s covered from %s, want %s", general.WindowFrom, general.CoveredFrom, want)
	}
	if want := windowNow.Add(-TrailIngestDelay); !general.ReadTo.Equal(want) {
		t.Fatalf("read_to %s, want %s (the delivery delay)", general.ReadTo, want)
	}
	if len(general.Records) != 2 || len(api.inputs[0].LookupAttributes) != 0 {
		t.Fatalf("general read %d records with attributes %v", len(general.Records), api.inputs[0].LookupAttributes)
	}

	bedrock, err := r.ReadWindow(context.Background(), TrailWindowRequest{Stream: TrailStreamBedrock})
	if err != nil || len(bedrock.Records) != 1 || bedrock.Records[0].Event.EventID != "old" {
		t.Fatalf("bedrock pass = %d records, err %v; want the one Bedrock event", len(bedrock.Records), err)
	}
	attrs := api.inputs[1].LookupAttributes
	if len(attrs) != 1 || attrs[0].AttributeKey != cttypes.LookupAttributeKeyEventSource ||
		aws.ToString(attrs[0].AttributeValue) != "bedrock.amazonaws.com" {
		t.Fatalf("focused pass attributes = %+v", attrs)
	}
	if !bedrock.Counts(windowNow.Add(-80 * 24 * time.Hour)) {
		t.Fatal("a first read must count an event 80 days old (weekly connectors, §5.1)")
	}
}

// From a mark, the focused pass starts at it; the general pass still reaches
// back the legacy 48 hours (R1b), but counts only after the mark; a mark
// older than 48 hours (a weekly connector) is read from.
func TestReadWindowFromAMark(t *testing.T) {
	since := windowNow.Add(-6 * time.Hour)
	api := &windowTrail{events: []cttypes.Event{
		trailEvt("before", "s3.amazonaws.com", "GetObject", windowNow.Add(-10*time.Hour), nil),
		trailEvt("at", "s3.amazonaws.com", "GetObject", since, nil),
		trailEvt("inside", "s3.amazonaws.com", "GetObject", windowNow.Add(-time.Hour), nil),
		trailEvt("unsettled", "s3.amazonaws.com", "GetObject", windowNow.Add(-5*time.Minute), nil),
	}}
	r := readerAt(api)
	general, err := r.ReadWindow(context.Background(), TrailWindowRequest{Stream: TrailStreamGeneral, Since: since})
	if err != nil {
		t.Fatal(err)
	}
	if !aws.ToTime(api.inputs[0].StartTime).Equal(windowNow.Add(-TrailLegacyWindow)) {
		t.Fatalf("general StartTime %s, want now-48h", aws.ToTime(api.inputs[0].StartTime))
	}
	if len(general.Records) != 4 {
		t.Fatalf("read %d records, want all 4 (evidence is recorded for every event read)", len(general.Records))
	}
	for id, want := range map[string]bool{"before": false, "at": false, "inside": true, "unsettled": false} {
		var at time.Time
		for _, rec := range general.Records {
			if rec.Event.EventID == id {
				at = rec.Event.EventTime
			}
		}
		if got := general.Counts(at); got != want {
			t.Errorf("Counts(%s) = %v, want %v", id, got, want)
		}
	}
	if !general.LegacyReached() || general.LegacyCount() != 4 {
		t.Fatalf("legacy reached %v count %d", general.LegacyReached(), general.LegacyCount())
	}

	weekly := windowNow.Add(-7 * 24 * time.Hour)
	if _, err := r.ReadWindow(context.Background(), TrailWindowRequest{Stream: TrailStreamGeneral, Since: weekly}); err != nil {
		t.Fatal(err)
	}
	if !aws.ToTime(api.inputs[1].StartTime).Equal(weekly) {
		t.Fatalf("weekly StartTime %s, want the mark %s", aws.ToTime(api.inputs[1].StartTime), weekly)
	}
	if _, err := r.ReadWindow(context.Background(), TrailWindowRequest{Stream: TrailStreamBedrock, Since: since}); err != nil {
		t.Fatal(err)
	}
	if !aws.ToTime(api.inputs[2].StartTime).Equal(since) {
		t.Fatalf("bedrock StartTime %s, want the mark", aws.ToTime(api.inputs[2].StartTime))
	}
}

// The cap: what was read is kept, the window is partial from the oldest
// second reached, nothing before it is counted, and the read still settles.
func TestReadWindowCapIsPartial(t *testing.T) {
	var events []cttypes.Event
	for i := 0; i < maxBedrockTrailPages+5; i++ {
		events = append(events, trailEvt(fmt.Sprintf("e%d", i), agentruntime.SourceBedrock, "Converse",
			windowNow.Add(-time.Hour-time.Duration(i)*time.Minute), nil))
	}
	api := &windowTrail{events: events, pageSize: 1}
	read, err := readerAt(api).ReadWindow(context.Background(), TrailWindowRequest{Stream: TrailStreamBedrock})
	if !errors.Is(err, ErrTooManyPages) {
		t.Fatalf("err = %v, want ErrTooManyPages", err)
	}
	if !read.Settled || !read.CapHit || !read.Partial || read.Pages != maxBedrockTrailPages {
		t.Fatalf("settled %v cap %v partial %v pages %d", read.Settled, read.CapHit, read.Partial, read.Pages)
	}
	oldest := windowNow.Add(-time.Hour - time.Duration(maxBedrockTrailPages-1)*time.Minute)
	if !read.Oldest.Equal(oldest) || !read.CoveredFrom.Equal(oldest.Add(time.Second)) {
		t.Fatalf("oldest %s covered from %s; want %s and a second after", read.Oldest, read.CoveredFrom, oldest)
	}
	if read.Counts(oldest) || read.Counts(read.WindowFrom.Add(time.Hour)) {
		t.Fatal("the unread gap (and its boundary second) must never be counted")
	}
	if !read.Counts(windowNow.Add(-time.Hour)) {
		t.Fatal("the covered part must be counted")
	}
}

// A mark older than the 90-day limit leaves a gap no read can fill: partial.
func TestReadWindowLapsedMarkIsPartial(t *testing.T) {
	read, err := readerAt(&windowTrail{}).ReadWindow(context.Background(),
		TrailWindowRequest{Stream: TrailStreamBedrock, Since: windowNow.Add(-120 * 24 * time.Hour)})
	if err != nil || !read.Lapsed || !read.Partial || !read.Settled {
		t.Fatalf("lapsed %v partial %v settled %v err %v", read.Lapsed, read.Partial, read.Settled, err)
	}
	if read.WindowFrom.Before(windowNow.Add(-TrailLookbackLimit)) {
		t.Fatalf("window from %s is past the 90-day limit", read.WindowFrom)
	}
}

// A failed read claims nothing: not settled, nothing counted.
func TestReadWindowFailureClaimsNothing(t *testing.T) {
	api := &windowTrail{err: errors.New("boom")}
	read, err := readerAt(api).ReadWindow(context.Background(), TrailWindowRequest{Stream: TrailStreamGeneral})
	if err == nil || read.Settled || read.Partial || read.Counts(windowNow.Add(-time.Hour)) {
		t.Fatalf("settled %v partial %v err %v", read.Settled, read.Partial, err)
	}
	if read.LegacyReached() {
		t.Fatal("a failed read never reached the legacy window")
	}
}

// Within a scan's delivery delay of the last mark nothing new is claimed:
// read_to never moves backwards.
func TestReadWindowNeverMovesTheMarkBack(t *testing.T) {
	since := windowNow.Add(-5 * time.Minute)
	read, err := readerAt(&windowTrail{}).ReadWindow(context.Background(), TrailWindowRequest{Stream: TrailStreamBedrock, Since: since})
	if err != nil || !read.ReadTo.Equal(since) || !read.CoveredFrom.Equal(since) {
		t.Fatalf("read_to %s covered_from %s err %v, want both at the mark", read.ReadTo, read.CoveredFrom, err)
	}
}

// Both passes return Bedrock events: one event, once.
func TestMergeTrailRecordsDedupesAcrossPasses(t *testing.T) {
	a := TrailRecordFrom(trailEvt("x", agentruntime.SourceBedrock, "Converse", windowNow, nil))
	b := TrailRecordFrom(trailEvt("y", "s3.amazonaws.com", "GetObject", windowNow, nil))
	got := MergeTrailRecords([]TrailRecord{a, b}, []TrailRecord{a})
	if len(got) != 2 {
		t.Fatalf("merged %d records, want 2", len(got))
	}
}

// Normalisation goes through agentruntime.ParseCloudTrailRecord; a record
// missing its id and name takes LookupEvents' typed fields; a completion
// record's token counts are read.
func TestTrailRecordFromNormalises(t *testing.T) {
	rec := TrailRecordFrom(trailEvt("c1", agentruntime.SourceBedrock, "ConverseStream", windowNow, map[string]any{
		"eventType":         "AwsServiceEvent",
		"requestParameters": map[string]any{"modelId": "anthropic.claude"},
		"serviceEventDetails": map[string]any{
			"usage": map[string]any{"inputTokens": 12, "outputTokens": 30},
		},
	}))
	if rec.Event.EventType != "AwsServiceEvent" || rec.Event.IsModelCall() {
		t.Fatalf("completion record = %+v; it is not a model call", rec.Event)
	}
	if rec.Tokens != 42 {
		t.Fatalf("tokens = %d, want 42", rec.Tokens)
	}
	if a := rec.Event.Attribution(); a.How != agentruntime.AttributionSessionIssuer || a.UniqueID != "AROAEXAMPLE" {
		t.Fatalf("attribution = %+v", a)
	}

	bare := TrailRecordFrom(cttypes.Event{EventId: aws.String("b1"), EventName: aws.String("DeleteObject"),
		EventSource: aws.String("s3.amazonaws.com"), EventTime: aws.Time(windowNow),
		CloudTrailEvent: aws.String(`{"errorCode":"AccessDenied"}`)})
	if bare.Event.EventID != "b1" || bare.Event.EventName != "DeleteObject" || !bare.Event.AuthorizationDenied ||
		!bare.Event.EventTime.Equal(windowNow) {
		t.Fatalf("bare record = %+v", bare.Event)
	}
	if bare.Trail.ErrorCode != "AccessDenied" {
		t.Fatalf("the legacy shape changed: %+v", bare.Trail)
	}
}
