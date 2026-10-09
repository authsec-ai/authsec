package awsdiscovery

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// endlessTrail always has another page of 50 events: a busy account whose
// last 48 hours hold more events than one scan reads.
type endlessTrail struct{ calls int }

func (e *endlessTrail) LookupEvents(_ context.Context, _ *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	e.calls++
	events := make([]cttypes.Event, lookupEventsPerPage)
	for i := range events {
		events[i] = cttypes.Event{EventId: aws.String(strconv.Itoa(e.calls*1000 + i))}
	}
	return &cloudtrail.LookupEventsOutput{Events: events, NextToken: aws.String("more")}, nil
}

func (e *endlessTrail) DescribeTrails(context.Context, *cloudtrail.DescribeTrailsInput, ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
	return &cloudtrail.DescribeTrailsOutput{}, nil
}

func (e *endlessTrail) GetTrailStatus(context.Context, *cloudtrail.GetTrailStatusInput, ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
	return &cloudtrail.GetTrailStatusOutput{}, nil
}

// Reaching the cap keeps what was read and reports ErrTooManyPages — a partial
// read the caller must not mistake for a refusal.
func TestRecentEventsStopsAtTheCapAsPartial(t *testing.T) {
	api := &endlessTrail{}
	events, err := NewCloudTrailReader(api).RecentEvents(context.Background())
	if !errors.Is(err, ErrTooManyPages) {
		t.Fatalf("expected ErrTooManyPages, got %v", err)
	}
	if want := maxTrailPages * lookupEventsPerPage; len(events) != want || api.calls != maxTrailPages {
		t.Fatalf("read %d events in %d calls, want %d in %d", len(events), api.calls, want, maxTrailPages)
	}
	if errors.Is(err, ErrNotAssumable) {
		t.Fatal("a page cap must never look like an access refusal")
	}
}
