package awsdiscovery

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/authsec-ai/authsec/internal/agentruntime"
)

// Windowed CloudTrail reads (SPEC-agent-runtime-visibility.md §5.1, P1a).
//
// RecentEvents reads a fixed 48 hours. A connector scanned weekly therefore
// never saw five of its seven days. ReadWindow reads instead from the previous
// read's high-water mark (the caller keeps it, per connector, region and
// stream: cloud_trail_cursor), bounded by the 90 days LookupEvents can look
// back; a first read covers the full 90 days up to its page cap.
//
// What a read may CLAIM is narrower than what it read:
//
//   - read_to lags the read by TrailIngestDelay: CloudTrail delivers events
//     to LookupEvents minutes after they happen, so an interval that ended a
//     moment ago is not yet whole. Events after read_to are returned (and the
//     caller records them as evidence, idempotently by event id) but are not
//     counted until a later read settles them.
//   - LookupEvents returns the newest events first. A read that stops at its
//     page cap has covered [covered_from, read_to] and NOT [window_from,
//     covered_from): Partial, with covered_from saying how far back it got.
//     The gap is never claimed and never re-read.
//   - a high-water mark older than the 90-day limit leaves [mark, limit)
//     unreadable: Partial for the same reason.
//   - a read that FAILED (denied, throttled past the retries, a network
//     error) claims nothing at all: Settled is false, the caller keeps its
//     mark, and the next read starts from it again.
//
// Two streams, each with its own mark and page cap: TrailStreamGeneral, the
// unfiltered pass the scan always made (it still reaches back at least
// lookupWindow, the 48 hours R1b's evidence reads assume), and
// TrailStreamBedrock, the focused pass filtered to bedrock.amazonaws.com --
// one LookupAttribute per call is what the API allows. An event both passes
// return is deduplicated by event id (MergeTrailRecords).

// Read streams (cloud_trail_cursor.stream).
const (
	TrailStreamGeneral = "general"
	TrailStreamBedrock = "bedrock"
)

const (
	// TrailLookbackLimit is how far back LookupEvents can read: the last 90
	// days of management events.
	TrailLookbackLimit = 90 * 24 * time.Hour
	// trailLookbackMargin keeps a first read's StartTime inside the limit
	// while the read is in flight.
	trailLookbackMargin = 5 * time.Minute
	// TrailIngestDelay is how long after an event's time a read waits before
	// claiming the interval holding it. CloudTrail documents delivery "within
	// 15 minutes of an API call" on average; events later than that are read
	// on the next scan, never lost (the next read starts at read_to).
	TrailIngestDelay = 15 * time.Minute
	// maxBedrockTrailPages is the focused pass's own page cap: 10,000 Bedrock
	// management events per region per scan.
	maxBedrockTrailPages = 200
)

// TrailWindowRequest is one windowed read.
type TrailWindowRequest struct {
	// Stream is TrailStreamGeneral or TrailStreamBedrock.
	Stream string
	// Since is the previous successful read's read_to; zero for a first read.
	Since time.Time
}

// TrailRecord is one event as both shapes its readers use: the legacy
// TrailEvent (cloud_observation, R1b) and the normalised agentruntime.Event
// (model-call evidence, sinks). Tokens is the token count the record states,
// 0 when it states none.
type TrailRecord struct {
	Trail  TrailEvent
	Event  agentruntime.Event
	Tokens int64
}

// TrailWindowRead is what one ReadWindow call read and what it may claim.
type TrailWindowRead struct {
	Stream string
	// Records are every event returned, newest first as AWS returned them.
	Records []TrailRecord
	// LookupFrom / LookupTo are the StartTime and EndTime asked of AWS.
	LookupFrom, LookupTo time.Time
	// Since is the request's high-water mark (zero on a first read).
	Since time.Time
	// WindowFrom is where this read's claim starts: Since, or the 90-day
	// limit when Since is zero or older than it.
	WindowFrom time.Time
	// CoveredFrom is how far back the read actually reached inside the
	// window: WindowFrom unless the page cap stopped it first.
	CoveredFrom time.Time
	// ReadTo is the new high-water mark: LookupTo less TrailIngestDelay, never
	// before WindowFrom.
	ReadTo time.Time
	// Oldest is the oldest event time returned (zero when none was).
	Oldest time.Time
	// CapHit: the page cap stopped the read. Lapsed: Since was older than the
	// 90-day limit. Partial: either left part of [WindowFrom, ReadTo] unread.
	CapHit, Lapsed, Partial bool
	Pages                   int
	// Settled is false when the read failed for any reason but the cap: it
	// claims nothing, and the caller must not move its mark.
	Settled bool
}

// Counts reports whether an event at t lies in what this read settled: after
// the previous mark, inside the covered part of the window, not after
// ReadTo. Exactly the events a cumulative aggregate may add once.
func (r TrailWindowRead) Counts(t time.Time) bool {
	if !r.Settled || t.IsZero() {
		return false
	}
	if !r.Since.IsZero() && !t.After(r.Since) {
		return false
	}
	return !t.Before(r.CoveredFrom) && !t.After(r.ReadTo)
}

// ReachedBack reports whether the read covered everything from `from` to
// LookupTo: settled, and either not capped or capped only after reaching
// back to `from`. The legacy cloudtrail-events surface (R1b) asks it for the
// last lookupWindow.
func (r TrailWindowRead) ReachedBack(from time.Time) bool {
	if !r.Settled {
		return false
	}
	if !r.CapHit {
		return !r.LookupFrom.After(from)
	}
	return !r.Oldest.IsZero() && r.Oldest.Before(from)
}

// TrailEvents is the read in its legacy shape.
func (r TrailWindowRead) TrailEvents() []TrailEvent {
	out := make([]TrailEvent, 0, len(r.Records))
	for _, rec := range r.Records {
		out = append(out, rec.Trail)
	}
	return out
}

// WithClock replaces the reader's clock (tests).
func (r *CloudTrailReader) WithClock(now func() time.Time) *CloudTrailReader {
	r.now = now
	return r
}

func (r *CloudTrailReader) clock() time.Time {
	if r.now != nil {
		return r.now().UTC()
	}
	return time.Now().UTC()
}

// ReadWindow reads one stream from its high-water mark (see the file
// comment). The error is the read's: ErrTooManyPages when the cap stopped it
// (Settled, Partial or not), the classified AWS error otherwise (not
// Settled). What was read is returned either way.
func (r *CloudTrailReader) ReadWindow(ctx context.Context, req TrailWindowRequest) (TrailWindowRead, error) {
	now := r.clock()
	read := TrailWindowRead{Stream: req.Stream, Since: req.Since.UTC(), LookupTo: now}
	if r.api == nil {
		return read, nil
	}

	limit := now.Add(-TrailLookbackLimit + trailLookbackMargin).Truncate(time.Second)
	switch {
	case read.Since.IsZero():
		read.WindowFrom = limit
	case read.Since.Before(limit):
		read.WindowFrom, read.Lapsed = limit, true
	default:
		read.WindowFrom = read.Since
	}
	read.ReadTo = now.Add(-TrailIngestDelay).Truncate(time.Second)
	if read.ReadTo.Before(read.WindowFrom) {
		read.ReadTo = read.WindowFrom
	}

	in := &cloudtrail.LookupEventsInput{}
	maxPages := maxTrailPages
	read.LookupFrom = read.WindowFrom
	switch req.Stream {
	case TrailStreamBedrock:
		maxPages = maxBedrockTrailPages
		in.LookupAttributes = []cttypes.LookupAttribute{{
			AttributeKey:   cttypes.LookupAttributeKeyEventSource,
			AttributeValue: aws.String(agentruntime.SourceBedrock),
		}}
	default:
		// The general pass still reads at least the last lookupWindow: R1b's
		// action evidence reads every reached cloudtrail-events surface as
		// [scan - 48 h, scan] (services/iga_gov_r1b_evidence.go). Events
		// before WindowFrom are evidence, never counted (Counts).
		if floor := now.Add(-lookupWindow); floor.Before(read.LookupFrom) {
			read.LookupFrom = floor
		}
	}
	in.StartTime, in.EndTime = aws.Time(read.LookupFrom), aws.Time(now)

	var readErr error
	for {
		if read.Pages >= maxPages {
			read.CapHit = true
			readErr = fmt.Errorf("%w: read the first %d %s CloudTrail events since %s; more exist",
				ErrTooManyPages, maxPages*lookupEventsPerPage, req.Stream, read.LookupFrom.Format(time.RFC3339))
			break
		}
		resp, err := r.api.LookupEvents(ctx, in)
		if err != nil {
			readErr = classify(err)
			break
		}
		read.Pages++
		for _, e := range resp.Events {
			rec := TrailRecordFrom(e)
			if t := rec.Event.EventTime; !t.IsZero() && (read.Oldest.IsZero() || t.Before(read.Oldest)) {
				read.Oldest = t
			}
			read.Records = append(read.Records, rec)
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			break
		}
		next := *in
		next.NextToken = resp.NextToken
		in = &next
	}

	read.Settled = readErr == nil || read.CapHit
	read.CoveredFrom = read.WindowFrom
	if read.CapHit {
		// The events at the oldest second read may straddle the cap: claim
		// only the seconds after it.
		frontier := read.ReadTo
		if !read.Oldest.IsZero() {
			frontier = read.Oldest.Truncate(time.Second).Add(time.Second)
		}
		if frontier.After(read.CoveredFrom) {
			read.CoveredFrom = frontier
		}
		if read.CoveredFrom.After(read.ReadTo) {
			read.CoveredFrom = read.ReadTo
		}
	}
	read.Partial = read.Lapsed || read.CoveredFrom.After(read.WindowFrom)
	if !read.Settled {
		read.Partial = false
	}
	return read, readErr
}

// MergeTrailRecords concatenates reads, keeping the first record of every
// event id (an event both passes returned is one event). Records with no
// event id cannot be matched and are all kept.
func MergeTrailRecords(reads ...[]TrailRecord) []TrailRecord {
	seen := map[string]bool{}
	var out []TrailRecord
	for _, recs := range reads {
		for _, rec := range recs {
			id := rec.Event.EventID
			if id == "" {
				id = rec.Trail.EventID
			}
			if id != "" {
				if seen[id] {
					continue
				}
				seen[id] = true
			}
			out = append(out, rec)
		}
	}
	return out
}

// TrailRecordFrom normalises one LookupEvents result into both shapes.
func TrailRecordFrom(e cttypes.Event) TrailRecord {
	raw := aws.ToString(e.CloudTrailEvent)
	trail := trailEventFrom(e)
	return TrailRecord{Trail: trail, Event: normaliseTrailEvent(e, raw, trail), Tokens: tokensFromRecord(raw)}
}

// normaliseTrailEvent parses the CloudTrailEvent JSON through
// agentruntime.ParseCloudTrailRecord, filling what the record omits from
// LookupEvents' own typed fields (a record CloudTrail writes always carries
// them; a truncated or test record may not). A record that is not JSON at all
// still yields an Event with the typed fields and no identity: it can be
// dispatched, never attributed.
func normaliseTrailEvent(e cttypes.Event, raw string, trail TrailEvent) agentruntime.Event {
	ev, err := agentruntime.ParseCloudTrailRecord([]byte(raw))
	if err != nil {
		var m map[string]json.RawMessage
		if json.Unmarshal([]byte(raw), &m) == nil && m != nil {
			fill := func(key, val string) {
				if _, ok := m[key]; !ok && val != "" {
					b, _ := json.Marshal(val)
					m[key] = b
				}
			}
			fill("eventID", aws.ToString(e.EventId))
			fill("eventName", aws.ToString(e.EventName))
			fill("eventSource", aws.ToString(e.EventSource))
			if e.EventTime != nil {
				fill("eventTime", e.EventTime.UTC().Format(time.RFC3339))
			}
			if b, merr := json.Marshal(m); merr == nil {
				ev, err = agentruntime.ParseCloudTrailRecord(b)
			}
		}
	}
	if err != nil {
		ev = agentruntime.Event{}
	}
	if ev.EventID == "" {
		ev.EventID = aws.ToString(e.EventId)
	}
	if ev.EventName == "" {
		ev.EventName = aws.ToString(e.EventName)
	}
	if ev.EventSource == "" {
		ev.EventSource = aws.ToString(e.EventSource)
	}
	if ev.EventTime.IsZero() && e.EventTime != nil {
		ev.EventTime = e.EventTime.UTC()
	}
	if ev.ErrorCode == "" && trail.ErrorCode != "" {
		ev.ErrorCode = trail.ErrorCode
		ev.AuthorizationDenied = AuthorizationErrorCodes[trail.ErrorCode]
	}
	return ev
}

// tokenSections are the parts of a record token counts are read from, in
// order. UNVERIFIED against a lab call (spec §5.1): Bedrock's
// stream-completion records and InvokeModel/Converse records are documented
// to carry usage in additionalEventData / serviceEventDetails /
// responseElements under these names, but no recorded fixture confirms it.
// A record stating none contributes 0, never a guess.
var tokenSections = []string{"serviceEventDetails", "additionalEventData", "responseElements"}

// tokensFromRecord is the token count one record states: totalTokens, else
// inputTokens + outputTokens (or the *TokenCount forms), at most three
// levels into the first section that states any. 0 when none does.
func tokensFromRecord(raw string) int64 {
	if raw == "" || !strings.Contains(raw, "oken") {
		return 0
	}
	var rec map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &rec) != nil {
		return 0
	}
	for _, section := range tokenSections {
		var v any
		if b, ok := rec[section]; !ok || json.Unmarshal(b, &v) != nil {
			continue
		}
		if n, ok := tokensIn(v, 0); ok {
			return n
		}
	}
	return 0
}

func tokensIn(v any, depth int) (int64, bool) {
	obj, ok := v.(map[string]any)
	if !ok || depth > 3 {
		return 0, false
	}
	num := func(keys ...string) (int64, bool) {
		for _, k := range keys {
			if f, ok := obj[k].(float64); ok && f >= 0 {
				return int64(f), true
			}
		}
		return 0, false
	}
	if n, ok := num("totalTokens", "totalTokenCount"); ok {
		return n, true
	}
	in, okIn := num("inputTokens", "inputTokenCount")
	out, okOut := num("outputTokens", "outputTokenCount")
	if okIn || okOut {
		return in + out, true
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic when two nested objects state counts
	for _, k := range keys {
		if n, ok := tokensIn(obj[k], depth+1); ok {
			return n, true
		}
	}
	return 0, false
}

// TrailLegacyWindow is the window the cloudtrail-events surface has always
// spoken for, and the one R1b reads it as: the last 48 hours of the general
// pass.
const TrailLegacyWindow = lookupWindow

// LegacyReached reports whether the read covered the last TrailLegacyWindow.
func (r TrailWindowRead) LegacyReached() bool {
	return r.ReachedBack(r.LookupTo.Add(-lookupWindow))
}

// LegacyCount is the number of events read from the last TrailLegacyWindow:
// the cloudtrail-events surface's count.
func (r TrailWindowRead) LegacyCount() int {
	from := r.LookupTo.Add(-lookupWindow)
	n := 0
	for _, rec := range r.Records {
		if !rec.Event.EventTime.Before(from) {
			n++
		}
	}
	return n
}
