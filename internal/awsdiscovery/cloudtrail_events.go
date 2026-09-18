package awsdiscovery

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// CloudTrail management events: WHO actually called WHAT, including calls
// AWS denied. iam:GenerateServiceLastAccessedDetails (activity.go) answers
// "has this identity touched this SERVICE, ever" from a rolling window AWS
// maintains for you; it cannot show a single call, cannot show a denied
// attempt, and cannot show WHICH other identity was assuming a shared role
// when it happened. CloudTrail is the source that can, at the cost this file
// is built around: LookupEvents is account-wide, not identity-scoped, and
// there is no server-side filter for "calls made while assuming role R".
//
// WHAT THIS FILE DOES NOT CLAIM. Matching an event back to a scanned identity
// is done by comparing Event.Username against the identity's own name -- the
// same heuristic CloudTrail's own console search box uses, not a guaranteed
// join. For an assumed role, Username is the SESSION's display form (for
// example "AssumedRole/MyRole/session-name" or just "session-name",
// inconsistently across event sources), not the role's ARN, so a match here
// is evidence worth recording, never proof of identity the way an IAM-issued
// ARN is. Every event this reader returns is kept exactly because it could
// not be silently and confidently attributed, and the caller decides what
// counts as a match.
//
// WHY BOUNDED. LookupEvents has no documented hard rate limit as generous as
// most list calls, and an account's default trail can hold ninety days of
// management events -- reading all of it every scan does not scale with
// account age. lookupWindow and maxPages bound one call to a recent slice,
// the same trade activity.go's own header makes explicit for the wider
// CloudTrail upgrade this is a first, narrower step toward.

// CloudTrailAPI is the slice of CloudTrail this package uses.
type CloudTrailAPI interface {
	LookupEvents(ctx context.Context, in *cloudtrail.LookupEventsInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)

	// DescribeTrails/GetTrailStatus answer a different question than
	// LookupEvents: not "what happened", but "is anything capturing what
	// happens at all". RecentEvents returning nothing is ambiguous between a
	// quiet account and a blind one -- these two calls are what tells the two
	// apart. Granted in the role template from the start; this file is the
	// first caller.
	DescribeTrails(ctx context.Context, in *cloudtrail.DescribeTrailsInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error)
	GetTrailStatus(ctx context.Context, in *cloudtrail.GetTrailStatusInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error)
}

// NewCloudTrailClient builds a real CloudTrail client.
func NewCloudTrailClient(cfg aws.Config) CloudTrailAPI { return cloudtrail.NewFromConfig(cfg) }

// lookupWindow bounds LookupEvents to a recent slice rather than however much
// history the account's trail retains.
const lookupWindow = 48 * time.Hour

// TrailEvent is one CloudTrail management event, reduced to what a reader
// needs to decide whether it is evidence of one of THIS scan's identities
// acting -- including a call AWS denied, which
// GenerateServiceLastAccessedDetails cannot show at all.
type TrailEvent struct {
	EventID     string
	EventName   string
	EventSource string
	EventTime   time.Time
	// Username is CloudTrail's own field, kept verbatim -- see the file header
	// on why it is a hint for the caller to match, not a resolved identity.
	Username string
	// ErrorCode is set when AWS denied or otherwise rejected the call. Absent
	// entirely for a normal successful event, not merely empty, so a caller
	// can tell "no error recorded" from "recorded and empty".
	ErrorCode string
	Denied    bool
}

// CloudTrailReader reads recent management events for one region.
type CloudTrailReader struct {
	api CloudTrailAPI
}

// NewCloudTrailReader constructs a reader over the given API.
func NewCloudTrailReader(api CloudTrailAPI) *CloudTrailReader {
	return &CloudTrailReader{api: api}
}

// RecentEvents lists management events from the last lookupWindow, across at
// most maxPages of up to 50 events each.
//
// No LookupAttributes filter is applied: CloudTrail permits only one, and
// filtering by Username would mean one call per identity for an account that
// may have hundreds, where this unfiltered call costs the same regardless of
// how many identities it ends up matching.
func (r *CloudTrailReader) RecentEvents(ctx context.Context) ([]TrailEvent, error) {
	if r.api == nil {
		return nil, nil
	}
	now := time.Now()
	start := now.Add(-lookupWindow)

	var out []TrailEvent
	var next *string
	for page := 0; ; page++ {
		if page >= maxPages {
			return out, fmt.Errorf("%w: cloudtrail events", errTooManyPages)
		}
		resp, err := r.api.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
			StartTime: aws.Time(start), EndTime: aws.Time(now), NextToken: next,
		})
		if err != nil {
			return out, classify(err)
		}
		for _, e := range resp.Events {
			out = append(out, trailEventFrom(e))
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			return out, nil
		}
		next = resp.NextToken
	}
}

// trailEventFrom normalises one SDK event. The error code is read out of the
// embedded CloudTrailEvent JSON: LookupEvents' own typed fields do not surface
// it, only the raw event record does.
func trailEventFrom(e cttypes.Event) TrailEvent {
	out := TrailEvent{
		EventID:     aws.ToString(e.EventId),
		EventName:   aws.ToString(e.EventName),
		EventSource: aws.ToString(e.EventSource),
		Username:    aws.ToString(e.Username),
	}
	if e.EventTime != nil {
		out.EventTime = *e.EventTime
	}
	if code := errorCodeFromRawEvent(aws.ToString(e.CloudTrailEvent)); code != "" {
		out.ErrorCode = code
		out.Denied = true
	}
	return out
}

// errorCodeFromRawEvent extracts errorCode from the raw event JSON without a
// full unmarshal into a struct this package would otherwise need to keep in
// step with CloudTrail's own record schema. A cheap, deliberately narrow
// scan for one field; anything more is scope the wider CloudTrail upgrade
// owns, not this reader.
func errorCodeFromRawEvent(raw string) string {
	const key = `"errorCode":"`
	i := strings.Index(raw, key)
	if i < 0 {
		return ""
	}
	rest := raw[i+len(key):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// TrailStatus is one trail's configuration plus whether it is actually
// logging right now. IsLogging is nil when GetTrailStatus itself failed for
// a trail DescribeTrails could see -- a trail we cannot get the status of is
// still worth recording as evidence, and nil keeps that failure from being
// misread as a confirmed "not logging".
type TrailStatus struct {
	NativeID                   string // trail ARN
	Name                       string
	HomeRegion                 string
	IsMultiRegionTrail         bool
	IsOrganizationTrail        bool
	IncludeGlobalServiceEvents bool
	LogFileValidationEnabled   bool
	IsLogging                  *bool
}

// Trails describes every trail visible in this region and whether each is
// actually logging.
//
// IncludeShadowTrails is set false: a shadow trail is the same trail's
// config replicated into every other Region, and this reader already runs
// once per Region as part of the wider scan -- including shadow trails would
// report the same organization trail's logging state once per Region on top
// of the one Region call that already reports it for real.
func (r *CloudTrailReader) Trails(ctx context.Context) ([]TrailStatus, error) {
	if r.api == nil {
		return nil, nil
	}
	resp, err := r.api.DescribeTrails(ctx,
		&cloudtrail.DescribeTrailsInput{IncludeShadowTrails: aws.Bool(false)})
	if err != nil {
		return nil, classify(err)
	}
	out := make([]TrailStatus, 0, len(resp.TrailList))
	for _, t := range resp.TrailList {
		ts := TrailStatus{
			NativeID:                   aws.ToString(t.TrailARN),
			Name:                       aws.ToString(t.Name),
			HomeRegion:                 aws.ToString(t.HomeRegion),
			IsMultiRegionTrail:         aws.ToBool(t.IsMultiRegionTrail),
			IsOrganizationTrail:        aws.ToBool(t.IsOrganizationTrail),
			IncludeGlobalServiceEvents: aws.ToBool(t.IncludeGlobalServiceEvents),
			LogFileValidationEnabled:   aws.ToBool(t.LogFileValidationEnabled),
		}
		// GetTrailStatus takes a name OR an arn; the ARN always resolves, a
		// bare name does not for an organization trail replicated from
		// another account, so the ARN is preferred whenever DescribeTrails
		// returned one.
		id := ts.Name
		if ts.NativeID != "" {
			id = ts.NativeID
		}
		if statusResp, serr := r.api.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: aws.String(id)}); serr == nil {
			logging := aws.ToBool(statusResp.IsLogging)
			ts.IsLogging = &logging
		}
		out = append(out, ts)
	}
	return out, nil
}
