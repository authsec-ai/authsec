package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// Model-call evidence (SPEC-agent-runtime-visibility.md §5.1, P1a).
//
// One region's CloudTrail reads -- the general pass and the focused Bedrock
// pass, each from its own high-water mark (cloud_trail_cursor) -- are folded
// into one cloud_usage row per identity: source 'cloudtrail', service
// 'bedrock', attrs an agentruntime.ModelCallUsage, cumulative over every
// window read. The pure half (aggregateModelCalls, mergeModelCallDoc) decides
// what counts; the write half (trailEvidenceStore.Record) lands the rows and
// moves the cursors in ONE transaction, under row-level security for the
// workspace and the scan's fence, so a window is counted exactly once: either
// both the counts and the new mark commit, or neither does.
//
// What counts:
//
//   - a model call is a real API call (eventType AwsApiCall) to a Bedrock
//     inference operation (agentruntime.Event.IsModelCall). A streaming call's
//     completion record (AwsServiceEvent, same name) is not a call; its token
//     counts are read when it states them.
//   - calls (no error), denied (an authorization refusal: with the tag-gated
//     template in deny mode these are the untagged AI workloads, §5.4) and
//     errors (anything else) are kept apart; refused calls are evidence too.
//   - a Bedrock event counts only inside the Bedrock pass's settled window,
//     every other event only inside the general pass's. Each window starts
//     awsdiscovery.TrailLateLookback BEFORE its stream's previous mark (late
//     CloudTrail deliveries), so an event already counted is skipped by its
//     eventID (cloud_trail_seen_event, kept seenEventRetention) and no event is
//     added twice across scans; an event both passes returned is one event
//     (awsdiscovery.MergeTrailRecords).
//   - every count is also kept per UTC day (modelCallDoc.Days, at most
//     maxModelCallDays): the suggestion rule and the findings read the last
//     AgentRuntimeWindowDays days, not the all-time totals (spec §5.1, §5.3).
//   - other_services: the other event sources the same identity called
//     successfully in the general window -- the "acted on other resources"
//     evidence inference reads (§5.3). Recorded only for an identity that has
//     (or now gets) a model-call row; it never creates one.
//   - attribution is by the record's own identity, exactly as the scan
//     attributes its observations (trailAttribution): the session issuer's ARN
//     with the RoleId incarnation check, or an IAM user's ARN. Never a name.
//   - session names are UNVERIFIED weak evidence only (§10, §5.2): capped,
//     never used to attribute anything.
//
// Coverage: each row keeps, per region, the windows merged into it
// (covered_from / covered_to / partial), and the top-level covered_from /
// covered_to is the interval EVERY region it names was read over (the latest
// start, the earliest end); partial is set when any read inside it left a
// gap, so "no calls" is never claimed for an interval nobody read.

// maxModelCallSessionNames caps ModelCallUsage.SessionNames.
const maxModelCallSessionNames = 20

const (
	// maxModelCallDays is how many UTC days of per-day buckets a row keeps.
	maxModelCallDays = 90
	// AgentRuntimeWindowDays is the window the suggestion rule and the
	// findings evaluate (spec §5.3 "in the same window"): the last 30 UTC
	// days including today.
	AgentRuntimeWindowDays = 30
	// seenEventRetention is how long a counted event's id is kept. It only has
	// to outlive awsdiscovery.TrailLateLookback.
	seenEventRetention = 7 * 24 * time.Hour
)

// modelCallDayBucket is one UTC day of one identity's evidence.
type modelCallDayBucket struct {
	Calls         int            `json:"calls"`
	Errors        int            `json:"errors"`
	Denied        int            `json:"denied"`
	Models        map[string]int `json:"models,omitempty"`
	OtherServices map[string]int `json:"other_services,omitempty"`
}

func modelCallDayKey(t time.Time) string { return t.UTC().Format("2006-01-02") }

// windowedUsage is the document's evidence over the last
// AgentRuntimeWindowDays days up to now: the day buckets summed, the
// cumulative fields (tokens, first/last call, coverage, session names) kept.
// A document with no day buckets (written before they existed) has no
// windowed evidence. Pure.
func (d modelCallDoc) windowedUsage(now time.Time) agentruntime.ModelCallUsage {
	u := d.ModelCallUsage
	u.Calls, u.Errors, u.Denied = 0, 0, 0
	u.Models, u.OtherServices = nil, nil
	cutoff := modelCallDayKey(now.UTC().AddDate(0, 0, -(AgentRuntimeWindowDays - 1)))
	days := d.Days
	if len(days) == 0 {
		days = d.legacyDays(now)
	}
	for day, b := range days {
		if day < cutoff || b == nil {
			continue
		}
		u.Calls += b.Calls
		u.Errors += b.Errors
		u.Denied += b.Denied
		for k, n := range b.Models {
			u.Models = addModelCallCount(u.Models, k, n)
		}
		for k, n := range b.OtherServices {
			u.OtherServices = addModelCallCount(u.OtherServices, k, n)
		}
	}
	return u
}

// legacyDays are the buckets of a document written before day buckets existed
// (its counts are cumulative with no dates). It never overstates the window:
//   - first call inside the window: every cumulative count is inside it, kept
//     whole in the bucket of that day;
//   - otherwise, a last call inside it: only "a call was made in the window"
//     is known, so one call (or, with no successful call, one refusal) is
//     kept in the bucket of the last call's day; no other-service evidence is
//     claimed.
//
// A document with neither date has none. Pure.
func (d modelCallDoc) legacyDays(now time.Time) map[string]*modelCallDayBucket {
	if d.Calls+d.Errors+d.Denied == 0 && len(d.OtherServices) == 0 {
		return nil
	}
	cutoff := modelCallDayKey(now.UTC().AddDate(0, 0, -(AgentRuntimeWindowDays - 1)))
	if d.FirstCallAt != nil && modelCallDayKey(*d.FirstCallAt) >= cutoff {
		return map[string]*modelCallDayBucket{modelCallDayKey(*d.FirstCallAt): {
			Calls: d.Calls, Errors: d.Errors, Denied: d.Denied,
			Models: mergeModelCallCounts(nil, d.Models), OtherServices: mergeModelCallCounts(nil, d.OtherServices)}}
	}
	if d.LastCallAt != nil && modelCallDayKey(*d.LastCallAt) >= cutoff {
		b := &modelCallDayBucket{}
		if d.Calls > 0 {
			b.Calls = 1
		} else if d.Denied > 0 {
			b.Denied = 1
		} else {
			return nil
		}
		return map[string]*modelCallDayBucket{modelCallDayKey(*d.LastCallAt): b}
	}
	return nil
}

// pruneDays drops buckets older than maxModelCallDays.
func (d *modelCallDoc) pruneDays(now time.Time) {
	cutoff := modelCallDayKey(now.UTC().AddDate(0, 0, -(maxModelCallDays - 1)))
	for day := range d.Days {
		if day < cutoff {
			delete(d.Days, day)
		}
	}
	if len(d.Days) == 0 {
		d.Days = nil
	}
}

// streamingModelCalls are the operations whose completion record
// (AwsServiceEvent) carries the call's token counts. For these the AwsApiCall
// record's own counts, if any, are not added, so a call is never counted twice.
var streamingModelCalls = map[string]bool{
	"InvokeModelWithResponseStream": true,
	"ConverseStream":                true,
	"RetrieveAndGenerateStream":     true,
}

// modelCallIdentity is what an event resolved to: the cloud_identity row and
// its immutable id (RoleId / AIDA...) when known.
type modelCallIdentity struct {
	ID       uuid.UUID
	UniqueID string
}

// modelCallResolver resolves an event's attribution within the connector.
type modelCallResolver func(agentruntime.Attribution) (modelCallIdentity, bool)

// modelCallDelta is one identity's evidence from one region's windows.
type modelCallDelta struct {
	Identity modelCallIdentity
	Usage    agentruntime.ModelCallUsage
	// ModelActivity: a model-call record (call, error or denial) was counted.
	// Only such a delta creates a row.
	ModelActivity bool
	// Days is the same evidence per UTC day (modelCallDayKey).
	Days map[string]*modelCallDayBucket
	// LastSuccessAt is the newest SUCCESSFUL model call (a refused or failed
	// one never sets it): cloud_usage.last_used_at.
	LastSuccessAt *time.Time
	// EventIDs are the CloudTrail ids of the events this delta counted, kept
	// in cloud_trail_seen_event so a re-read never counts them again.
	EventIDs map[string]time.Time
}

func (d *modelCallDelta) day(t time.Time) *modelCallDayBucket {
	if d.Days == nil {
		d.Days = map[string]*modelCallDayBucket{}
	}
	k := modelCallDayKey(t)
	b := d.Days[k]
	if b == nil {
		b = &modelCallDayBucket{}
		d.Days[k] = b
	}
	return b
}

func (d *modelCallDelta) counted(id string, t time.Time) {
	if id == "" {
		return
	}
	if d.EventIDs == nil {
		d.EventIDs = map[string]time.Time{}
	}
	d.EventIDs[id] = t.UTC()
}

// trailCoverage is one region's coverage on a row.
type trailCoverage struct {
	CoveredFrom time.Time `json:"covered_from"`
	CoveredTo   time.Time `json:"covered_to"`
	Partial     bool      `json:"partial"`
}

// modelCallDoc is the stored attrs: the shared contract plus the incarnation
// it describes and the per-region coverage behind the top-level one. Readers
// that decode agentruntime.ModelCallUsage ignore the two extra keys.
type modelCallDoc struct {
	agentruntime.ModelCallUsage
	IdentityUniqueID string                   `json:"identity_unique_id,omitempty"`
	Regions          map[string]trailCoverage `json:"regions,omitempty"`
	// LastSuccessAt: the newest successful model call (LastCallAt is the
	// newest attempt of any outcome).
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	// Days are the per-UTC-day buckets (at most maxModelCallDays).
	Days map[string]*modelCallDayBucket `json:"days,omitempty"`
}

func isModelCallSource(src string) bool {
	return src == agentruntime.SourceBedrock || (agentruntime.Event{EventSource: src, EventType: "AwsApiCall"}).IsModelCall()
}

// rootModelCallDelta is the model calls one region's records attribute to the
// account's root user (userIdentity.type Root). Root has no inventory
// identity, so these never reach a usage row; they raise the §5.2 step-4
// finding (an AI workload on human credentials) on their own.
type rootModelCallDelta struct {
	AccountID             string
	Calls, Denied, Errors int
	LastCallAt            *time.Time
	EventIDs              map[string]time.Time
}

// rootFindingKey is the agent_finding subject_key of a connector's root
// model-call finding.
func rootFindingKey(connectorID uuid.UUID) string { return "root:" + connectorID.String() }

// aggregateRootModelCalls counts the root user's model calls under the same
// windows and event-id rules as aggregateModelCalls. Pure; nil when none.
func aggregateRootModelCalls(general, bedrock awsdiscovery.TrailWindowRead, records []awsdiscovery.TrailRecord) *rootModelCallDelta {
	var out *rootModelCallDelta
	for _, rec := range records {
		ev := rec.Event
		if ev.PrincipalType != "Root" || !ev.IsModelCall() {
			continue
		}
		window := general
		if ev.EventSource == agentruntime.SourceBedrock {
			window = bedrock
		}
		if !window.Counts(ev.EventTime) {
			continue
		}
		if ev.EventID == "" && !window.Since.IsZero() && !ev.EventTime.After(window.Since) {
			continue
		}
		if out == nil {
			out = &rootModelCallDelta{AccountID: ev.AccountID}
		}
		switch {
		case ev.ErrorCode == "":
			out.Calls++
		case ev.AuthorizationDenied:
			out.Denied++
		default:
			out.Errors++
		}
		out.LastCallAt = laterCall(out.LastCallAt, ev.EventTime)
		if ev.EventID != "" {
			if out.EventIDs == nil {
				out.EventIDs = map[string]time.Time{}
			}
			out.EventIDs[ev.EventID] = ev.EventTime.UTC()
		}
	}
	return out
}

// upsertRootFinding opens (or extends) the connector's root model-call
// finding. The counts accumulate over the reads; inference resolves it once
// its last call is older than the evaluation window.
func upsertRootFinding(tx *gorm.DB, w modelCallWrite, now time.Time) error {
	r := w.Root
	last := now
	if r.LastCallAt != nil {
		last = *r.LastCallAt
	}
	subj, _ := json.Marshal(map[string]any{"kind": "root", "name": "Root user",
		"arn": "arn:aws:iam::" + r.AccountID + ":root"})
	ev, _ := json.Marshal(map[string]any{"calls": r.Calls, "denied": r.Denied, "errors": r.Errors,
		"last_call_at": last, "window_days": AgentRuntimeWindowDays,
		"note": "Model calls made with the account's root user: an AI workload on human credentials."})
	return tx.Exec(`INSERT INTO agent_finding
		  (workspace_id, connector_id, kind, subject_key, identity_id, subject, evidence, state,
		   first_seen, last_seen, resolved_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, NULL, ?::jsonb, ?::jsonb, 'open', ?, ?, NULL, ?, ?)
		ON CONFLICT (workspace_id, kind, subject_key) DO UPDATE SET
		  subject = excluded.subject,
		  evidence = excluded.evidence || jsonb_build_object(
		      'calls',  CASE WHEN agent_finding.state = 'resolved' THEN 0 ELSE COALESCE((agent_finding.evidence->>'calls')::bigint, 0) END  + ?,
		      'denied', CASE WHEN agent_finding.state = 'resolved' THEN 0 ELSE COALESCE((agent_finding.evidence->>'denied')::bigint, 0) END + ?,
		      'errors', CASE WHEN agent_finding.state = 'resolved' THEN 0 ELSE COALESCE((agent_finding.evidence->>'errors')::bigint, 0) END + ?,
		      'last_call_at', CASE WHEN agent_finding.state = 'resolved' THEN excluded.evidence->'last_call_at'
		          ELSE to_jsonb(GREATEST((agent_finding.evidence->>'last_call_at')::timestamptz,
		                                 (excluded.evidence->>'last_call_at')::timestamptz)) END),
		  state = 'open', resolved_at = NULL,
		  last_seen = GREATEST(agent_finding.last_seen, excluded.last_seen), updated_at = excluded.updated_at`,
		w.WorkspaceID, w.ConnectorID, FindingHumanCredentials, rootFindingKey(w.ConnectorID),
		string(subj), string(ev), last, last, now, now, r.Calls, r.Denied, r.Errors).Error
}

// aggregateModelCalls folds one region's records (both passes, deduplicated)
// into per-identity deltas. Pure.
func aggregateModelCalls(
	general, bedrock awsdiscovery.TrailWindowRead,
	records []awsdiscovery.TrailRecord, resolve modelCallResolver,
) map[uuid.UUID]*modelCallDelta {
	out := map[uuid.UUID]*modelCallDelta{}
	delta := func(ev agentruntime.Event) *modelCallDelta {
		att := ev.Attribution()
		if att.How == "" || resolve == nil {
			return nil
		}
		id, ok := resolve(att)
		if !ok || id.ID == uuid.Nil {
			return nil
		}
		d := out[id.ID]
		if d == nil {
			if id.UniqueID == "" {
				id.UniqueID = att.UniqueID
			}
			d = &modelCallDelta{Identity: id}
			out[id.ID] = d
		}
		return d
	}
	for _, rec := range records {
		ev := rec.Event
		window := general
		if ev.EventSource == agentruntime.SourceBedrock {
			window = bedrock
		}
		if !window.Counts(ev.EventTime) {
			continue
		}
		// An event with no id cannot be deduplicated across the overlapping
		// reads: it counts only after the previous mark, as before them.
		if ev.EventID == "" && !window.Since.IsZero() && !ev.EventTime.After(window.Since) {
			continue
		}
		switch {
		case ev.IsModelCall():
			d := delta(ev)
			if d == nil {
				continue
			}
			d.ModelActivity = true
			d.counted(ev.EventID, ev.EventTime)
			u := &d.Usage
			day := d.day(ev.EventTime)
			switch {
			case ev.ErrorCode == "":
				u.Calls++
				day.Calls++
				if model := ev.RequestFacts[agentruntime.FactModelID]; model != "" {
					u.Models = addModelCallCount(u.Models, model, 1)
					day.Models = addModelCallCount(day.Models, model, 1)
				}
				u.Endpoints = addModelCallCount(u.Endpoints, ev.EventSource, 1)
				d.LastSuccessAt = laterCall(d.LastSuccessAt, ev.EventTime)
			case ev.AuthorizationDenied:
				u.Denied++
				day.Denied++
			default:
				u.Errors++
				day.Errors++
			}
			if !streamingModelCalls[ev.EventName] {
				u.Tokens += rec.Tokens
			}
			u.FirstCallAt = earlierCall(u.FirstCallAt, ev.EventTime)
			u.LastCallAt = laterCall(u.LastCallAt, ev.EventTime)
			u.SessionNames = addModelCallSession(u.SessionNames, ev.SessionName)
		case !ev.IsAPICall() && isModelCallSource(ev.EventSource) && streamingModelCalls[ev.EventName]:
			// The stream-completion record: not a call; its tokens only.
			if rec.Tokens > 0 {
				if d := delta(ev); d != nil {
					d.Usage.Tokens += rec.Tokens
					d.counted(ev.EventID, ev.EventTime)
				}
			}
		case isModelCallSource(ev.EventSource):
			// Bedrock's control plane (ListFoundationModels, ...): neither a
			// model call nor "another service".
		case ev.IsAPICall() && ev.ErrorCode == "" && ev.EventSource != "":
			if d := delta(ev); d != nil {
				d.Usage.OtherServices = addModelCallCount(d.Usage.OtherServices, ev.EventSource, 1)
				d.day(ev.EventTime).OtherServices = addModelCallCount(d.day(ev.EventTime).OtherServices, ev.EventSource, 1)
				d.counted(ev.EventID, ev.EventTime)
			}
		}
	}
	for id, d := range out {
		if !d.ModelActivity && len(d.Usage.OtherServices) == 0 && d.Usage.Tokens == 0 {
			delete(out, id)
			continue
		}
		// A day bucket created for a token-only completion record holds no
		// counts; keep none of those.
		for k, b := range d.Days {
			if b.Calls == 0 && b.Errors == 0 && b.Denied == 0 && len(b.OtherServices) == 0 {
				delete(d.Days, k)
			}
		}
	}
	return out
}

// modelCallCoverage is what one region's reads let a row claim about model
// calls: the Bedrock pass's settled window. ok is false when that pass
// claims nothing (it failed), and the rows' coverage is then left as it was.
func modelCallCoverage(general, bedrock awsdiscovery.TrailWindowRead) (trailCoverage, bool) {
	if !bedrock.Settled {
		return trailCoverage{}, false
	}
	return trailCoverage{
		CoveredFrom: bedrock.CoveredFrom,
		CoveredTo:   bedrock.ReadTo,
		// The general pass's gap is a gap in other_services.
		Partial: bedrock.Partial || (general.Settled && general.Partial),
	}, true
}

// mergeModelCallDoc adds one region's delta and coverage (either may be nil)
// to a row's stored doc. A delta from another incarnation of the identity
// (its unique id differs from the one the doc records) starts the doc afresh:
// a role recreated under the same ARN is another principal. Pure.
func mergeModelCallDoc(prev modelCallDoc, d *modelCallDelta, region string, cov *trailCoverage) modelCallDoc {
	doc := prev
	if d != nil && d.Identity.UniqueID != "" {
		if doc.IdentityUniqueID != "" && doc.IdentityUniqueID != d.Identity.UniqueID {
			doc = modelCallDoc{}
		}
		doc.IdentityUniqueID = d.Identity.UniqueID
	}
	u := &doc.ModelCallUsage
	if d != nil {
		du := d.Usage
		u.Calls += du.Calls
		u.Errors += du.Errors
		u.Denied += du.Denied
		u.Tokens += du.Tokens
		u.Models = mergeModelCallCounts(u.Models, du.Models)
		u.Endpoints = mergeModelCallCounts(u.Endpoints, du.Endpoints)
		u.OtherServices = mergeModelCallCounts(u.OtherServices, du.OtherServices)
		for _, name := range du.SessionNames {
			u.SessionNames = addModelCallSession(u.SessionNames, name)
		}
		if du.FirstCallAt != nil {
			u.FirstCallAt = earlierCall(u.FirstCallAt, *du.FirstCallAt)
		}
		if du.LastCallAt != nil {
			u.LastCallAt = laterCall(u.LastCallAt, *du.LastCallAt)
		}
		if d.LastSuccessAt != nil {
			doc.LastSuccessAt = laterCall(doc.LastSuccessAt, *d.LastSuccessAt)
		}
		if len(d.Days) > 0 {
			if len(doc.Days) == 0 {
				// Evidence written before day buckets existed keeps what the
				// window can still claim of it (legacyDays).
				doc.Days = doc.legacyDays(time.Now())
			}
			days := make(map[string]*modelCallDayBucket, len(doc.Days)+len(d.Days))
			for k, b := range doc.Days {
				c := *b
				c.Models = mergeModelCallCounts(nil, b.Models)
				c.OtherServices = mergeModelCallCounts(nil, b.OtherServices)
				days[k] = &c
			}
			for k, b := range d.Days {
				c := days[k]
				if c == nil {
					c = &modelCallDayBucket{}
					days[k] = c
				}
				c.Calls += b.Calls
				c.Errors += b.Errors
				c.Denied += b.Denied
				c.Models = mergeModelCallCounts(c.Models, b.Models)
				c.OtherServices = mergeModelCallCounts(c.OtherServices, b.OtherServices)
			}
			doc.Days = days
		}
	}
	if cov != nil && region != "" {
		regions := make(map[string]trailCoverage, len(doc.Regions)+1)
		for k, v := range doc.Regions {
			regions[k] = v
		}
		c := *cov
		if was, ok := regions[region]; ok {
			if was.CoveredFrom.Before(c.CoveredFrom) {
				c.CoveredFrom = was.CoveredFrom
			}
			if was.CoveredTo.After(c.CoveredTo) {
				c.CoveredTo = was.CoveredTo
			}
			// Sticky: a gap once left in this region is never read later.
			c.Partial = c.Partial || was.Partial
		}
		regions[region] = c
		doc.Regions = regions
	}
	doc.recomputeCoverage()
	return doc
}

// pruneRegions drops the coverage of regions the connector no longer reads: a
// deselected region's old window would otherwise freeze the top-level
// coverage (the intersection over every region named) for good.
func (doc *modelCallDoc) pruneRegions(current []string) {
	if len(current) == 0 || len(doc.Regions) == 0 {
		return
	}
	keep := make(map[string]bool, len(current))
	for _, r := range current {
		keep[r] = true
	}
	regions := make(map[string]trailCoverage, len(doc.Regions))
	for r, c := range doc.Regions {
		if keep[r] {
			regions[r] = c
		}
	}
	doc.Regions = regions
	doc.recomputeCoverage()
}

// recomputeCoverage sets the top-level coverage: what holds in EVERY region
// the document names.
func (doc *modelCallDoc) recomputeCoverage() {
	u := &doc.ModelCallUsage
	u.CoveredFrom, u.CoveredTo, u.Partial = nil, nil, false
	for _, c := range doc.Regions {
		from, to := c.CoveredFrom, c.CoveredTo
		if u.CoveredFrom == nil || from.After(*u.CoveredFrom) {
			u.CoveredFrom = &from
		}
		if u.CoveredTo == nil || to.Before(*u.CoveredTo) {
			u.CoveredTo = &to
		}
		u.Partial = u.Partial || c.Partial
	}
	if u.CoveredFrom != nil && u.CoveredTo != nil && u.CoveredFrom.After(*u.CoveredTo) {
		// The regions' windows do not overlap: nothing is known for all of
		// them at once.
		u.Partial = true
	}
}

func addModelCallCount(m map[string]int, k string, n int) map[string]int {
	if m == nil {
		m = map[string]int{}
	}
	m[k] += n
	return m
}

func mergeModelCallCounts(into, from map[string]int) map[string]int {
	for k, n := range from {
		into = addModelCallCount(into, k, n)
	}
	return into
}

func addModelCallSession(names []string, name string) []string {
	if name == "" || len(names) >= maxModelCallSessionNames {
		return names
	}
	for _, n := range names {
		if n == name {
			return names
		}
	}
	return append(names, name)
}

func earlierCall(cur *time.Time, t time.Time) *time.Time {
	if t.IsZero() || (cur != nil && !t.Before(*cur)) {
		return cur
	}
	t = t.UTC()
	return &t
}

func laterCall(cur *time.Time, t time.Time) *time.Time {
	if t.IsZero() || (cur != nil && !t.After(*cur)) {
		return cur
	}
	t = t.UTC()
	return &t
}

/* ---------------------------------------------------------------------------- */
/*                                    Writes                                    */
/* ---------------------------------------------------------------------------- */

// errTrailCursorMoved: the stored mark is not the one this read started from
// (another run moved it, or the read did not know it). Counting the read now
// would add a window twice; the whole write is refused instead.
var errTrailCursorMoved = errors.New("cloudtrail cursor moved since it was read")

// trailCursor is one stored mark.
type trailCursor struct {
	Stream string
	ReadTo time.Time
}

// trailEvidenceStore lands model-call evidence and CloudTrail cursors, each
// call in one transaction under row-level security for its workspace and,
// when the scan has one, its fence.
type trailEvidenceStore struct {
	db    *gorm.DB
	fence *repositories.ScanFence
}

// Cursors reads one region's marks, by stream; a stream never read has none.
func (st trailEvidenceStore) Cursors(ctx context.Context, ws, connectorID uuid.UUID, region string) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	var rows []trailCursor
	err := tenancy.InWorkspaceRead(ctx, st.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT stream, read_to FROM cloud_trail_cursor
		                WHERE workspace_id = ? AND connector_id = ? AND region = ?`,
			ws, connectorID, region).Scan(&rows).Error
	})
	for _, r := range rows {
		out[r.Stream] = r.ReadTo.UTC()
	}
	return out, err
}

// modelCallWrite is one region's evidence to land.
type modelCallWrite struct {
	WorkspaceID, ConnectorID uuid.UUID
	Generation               int
	Region                   string
	// Reads by stream, with each read's error (nil, ErrTooManyPages, or the
	// failure that left it unsettled).
	Reads  map[string]awsdiscovery.TrailWindowRead
	Errors map[string]error
	Deltas map[uuid.UUID]*modelCallDelta
	// Root: the root user's model calls in this write (nil: none).
	Root *rootModelCallDelta
	// CurrentRegions are the connector's regions now; coverage recorded for
	// any other region is dropped from the rows. Empty: nothing is dropped.
	CurrentRegions []string
}

type modelCallUsageRow struct {
	ID         uuid.UUID
	IdentityID uuid.UUID
	Attrs      []byte
	// IdentityAttrs are the cloud_identity's attrs now: the incarnation the
	// row's document must describe.
	IdentityAttrs []byte
}

// SeenEvents returns the ids of the connector's events already counted whose
// time is not before from: what an overlapping read must skip. Zero from
// returns none (a first read overlaps nothing).
func (st trailEvidenceStore) SeenEvents(ctx context.Context, ws, connectorID uuid.UUID, from time.Time) (map[string]bool, error) {
	out := map[string]bool{}
	if from.IsZero() {
		return out, nil
	}
	var ids []string
	err := tenancy.InWorkspaceRead(ctx, st.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT event_id FROM cloud_trail_seen_event
		                WHERE workspace_id = ? AND connector_id = ? AND event_time >= ?`,
			ws, connectorID, from).Scan(&ids).Error
	})
	for _, id := range ids {
		out[id] = true
	}
	return out, err
}

// TrackedFrom is the time of the oldest counted event whose id is kept for
// the connector (nil: none is). Events counted before id tracking existed
// have no row.
func (st trailEvidenceStore) TrackedFrom(ctx context.Context, ws, connectorID uuid.UUID) (*time.Time, error) {
	var rows []struct{ T *time.Time }
	err := tenancy.InWorkspaceRead(ctx, st.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT min(event_time) AS t FROM cloud_trail_seen_event
		                WHERE workspace_id = ? AND connector_id = ?`, ws, connectorID).Scan(&rows).Error
	})
	if err != nil || len(rows) == 0 || rows[0].T == nil {
		return nil, err
	}
	t := rows[0].T.UTC()
	return &t, nil
}

// countFloored returns the read with its counting window raised to the floor
// below which an event may already have been counted WITHOUT its id being
// kept: events counted before id tracking existed (the code that wrote them
// counted every event after the previous mark and kept no ids). Reads overlap
// the previous mark by awsdiscovery.TrailLateLookback, but only over the
// range ids are kept for:
//
//	no id kept for the connector yet      floor = the mark: count t > mark
//	oldest kept id at time m              floor = clamp(m, mark-lookback, mark)
//
// Every event at or after m was counted, if at all, by code that kept its id,
// so the id decides; an event before m may have been counted without one, so
// it counts only after the mark. A first read (no mark) has nothing counted
// before it. Only the counting copy is floored; the stored coverage is not.
func countFloored(r awsdiscovery.TrailWindowRead, tracked *time.Time) awsdiscovery.TrailWindowRead {
	if r.Since.IsZero() {
		return r
	}
	floor := r.Since
	if tracked != nil {
		floor = *tracked
		if floor.After(r.Since) {
			floor = r.Since
		}
		if lo := r.Since.Add(-awsdiscovery.TrailLateLookback); floor.Before(lo) {
			floor = lo
		}
	}
	if from := floor.Add(time.Nanosecond); r.CoveredFrom.Before(from) {
		r.CoveredFrom = from
	}
	return r
}

// unseenRecords drops the records whose event id was already counted.
func unseenRecords(records []awsdiscovery.TrailRecord, seen map[string]bool) []awsdiscovery.TrailRecord {
	if len(seen) == 0 {
		return records
	}
	out := make([]awsdiscovery.TrailRecord, 0, len(records))
	for _, rec := range records {
		id := rec.Event.EventID
		if id == "" {
			id = rec.Trail.EventID
		}
		if id != "" && seen[id] {
			continue
		}
		out = append(out, rec)
	}
	return out
}

// Record lands one region's evidence: every cloud_usage model-call row of the
// connector merged with this region's deltas and coverage, new rows for
// identities seen calling a model for the first time, and the settled
// streams' marks moved -- or, when any of it fails, nothing. Returns the rows
// written.
func (st trailEvidenceStore) Record(ctx context.Context, w modelCallWrite) (int, error) {
	written := 0
	cov, covOK := modelCallCoverage(w.Reads[awsdiscovery.TrailStreamGeneral], w.Reads[awsdiscovery.TrailStreamBedrock])
	// TENANT-EXEMPT: the 147-149 schema check reads the Postgres catalog only.
	rootFindings, _ := AgentRuntimeStatus(st.db)
	err := tenancy.InWorkspace(ctx, st.db, w.WorkspaceID, func(tx *gorm.DB) error {
		return repositories.RunFenced(tx, st.fence, func(tx *gorm.DB) error {
			written = 0
			// 1. The marks this write moves must be the ones the reads began
			// at. Locked, so a concurrent writer waits and then fails here.
			var stored []trailCursor
			if err := tx.Raw(`SELECT stream, read_to FROM cloud_trail_cursor
			                   WHERE workspace_id = ? AND connector_id = ? AND region = ?
			                   FOR UPDATE`, w.WorkspaceID, w.ConnectorID, w.Region).Scan(&stored).Error; err != nil {
				return err
			}
			marks := map[string]time.Time{}
			for _, c := range stored {
				marks[c.Stream] = c.ReadTo.UTC()
			}
			for stream, read := range w.Reads {
				if read.Settled && !marks[stream].Equal(read.Since) {
					return fmt.Errorf("%w: %s %s: stored %s, read from %s", errTrailCursorMoved,
						w.Region, stream, marks[stream].Format(time.RFC3339), read.Since.Format(time.RFC3339))
				}
			}

			// 2. Merge into the connector's existing rows.
			var rows []modelCallUsageRow
			if err := tx.Raw(`SELECT u.id, u.identity_id, u.attrs, i.attrs AS identity_attrs
			                    FROM cloud_usage u
			                    LEFT JOIN cloud_identity i ON i.workspace_id = u.workspace_id AND i.id = u.identity_id
			                   WHERE u.workspace_id = ? AND u.connector_id = ? AND u.source = ? AND u.service = ?
			                   FOR UPDATE OF u`, w.WorkspaceID, w.ConnectorID,
				agentruntime.UsageSource, agentruntime.UsageService).Scan(&rows).Error; err != nil {
				return err
			}
			var covp *trailCoverage
			if covOK {
				covp = &cov
			}
			now := time.Now().UTC()
			seen := map[uuid.UUID]bool{}
			for _, row := range rows {
				seen[row.IdentityID] = true
				d := w.Deltas[row.IdentityID]
				var prev modelCallDoc
				if len(row.Attrs) > 0 {
					if err := json.Unmarshal(row.Attrs, &prev); err != nil {
						prev = modelCallDoc{} // unreadable: rebuilt from here
					}
				}
				// The identity was recreated under the same ARN since the
				// document was written: it describes another principal, so it
				// starts afresh now, not at the next model call.
				reset := false
				current := ""
				if len(row.IdentityAttrs) > 0 {
					ci := models.CloudIdentity{Attrs: row.IdentityAttrs}
					current = ci.AWSAttrs().UniqueID
				}
				if current != "" && prev.IdentityUniqueID != "" && prev.IdentityUniqueID != current {
					prev, reset = modelCallDoc{}, true
				}
				if d == nil && covp == nil && !reset {
					continue
				}
				doc := mergeModelCallDoc(prev, d, w.Region, covp)
				if current != "" {
					doc.IdentityUniqueID = current
				}
				doc.pruneRegions(w.CurrentRegions)
				doc.pruneDays(now)
				attrs, err := json.Marshal(doc)
				if err != nil {
					return err
				}
				// last_used_at is the newest SUCCESSFUL call: a refused or
				// failed one never sets it. A reset clears the predecessor's.
				lastUsed := "COALESCE(?, last_used_at)"
				if reset {
					lastUsed = "?"
				}
				if err := tx.Exec(`UPDATE cloud_usage
				                      SET attrs = ?::jsonb, last_used_at = `+lastUsed+`, last_seen_generation = ?,
				                          last_seen_at = ?, row_updated_at = ?
				                    WHERE workspace_id = ? AND id = ?`,
					string(attrs), doc.LastSuccessAt, w.Generation, now, now, w.WorkspaceID, row.ID).Error; err != nil {
					return err
				}
				written++
			}

			// 3. Identities seen calling a model for the first time.
			ids := make([]uuid.UUID, 0, len(w.Deltas))
			for id, d := range w.Deltas {
				if !seen[id] && d.ModelActivity {
					ids = append(ids, id)
				}
			}
			sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
			for _, id := range ids {
				doc := mergeModelCallDoc(modelCallDoc{}, w.Deltas[id], w.Region, covp)
				doc.pruneDays(now)
				attrs, err := json.Marshal(doc)
				if err != nil {
					return err
				}
				// Plain INSERT: a row that appeared since the lock above is a
				// concurrent writer, and the whole write must fail rather than
				// overwrite it.
				if err := tx.Exec(`INSERT INTO cloud_usage
				                      (id, workspace_id, connector_id, identity_id, service, source,
				                       last_used_at, attrs, last_seen_generation,
				                       first_seen_at, last_seen_at, row_updated_at)
				                   VALUES (?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?)`,
					uuid.New(), w.WorkspaceID, w.ConnectorID, id,
					agentruntime.UsageService, agentruntime.UsageSource,
					doc.LastSuccessAt, string(attrs), w.Generation, now, now, now).Error; err != nil {
					return err
				}
				written++
			}

			// 3b. The events counted, so an overlapping read skips them; and
			// the ids past their retention dropped.
			if err := recordSeenEvents(tx, w, now); err != nil {
				return err
			}
			// 3c. The root user's model calls (§5.2 step 4), once 148 is there.
			if w.Root != nil && rootFindings {
				if err := upsertRootFinding(tx, w, now); err != nil {
					return err
				}
			}

			// 4. Move the settled streams' marks; record a failed attempt.
			streams := make([]string, 0, len(w.Reads))
			for stream := range w.Reads {
				streams = append(streams, stream)
			}
			sort.Strings(streams)
			for _, stream := range streams {
				read := w.Reads[stream]
				if !read.Settled {
					rerr := w.Errors[stream]
					if rerr == nil {
						continue // nothing was asked of AWS
					}
					if err := tx.Exec(`UPDATE cloud_trail_cursor
					                      SET last_error = ?, last_attempt_at = ?, updated_at = ?
					                    WHERE workspace_id = ? AND connector_id = ? AND region = ? AND stream = ?`,
						truncateTrailError(rerr.Error()), now, now,
						w.WorkspaceID, w.ConnectorID, w.Region, stream).Error; err != nil {
						return err
					}
					continue
				}
				if err := tx.Exec(`INSERT INTO cloud_trail_cursor
				                      (workspace_id, connector_id, region, stream, window_from, covered_from,
				                       read_to, partial, pages, events, last_error, last_attempt_at, updated_at)
				                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?)
				                   ON CONFLICT (workspace_id, connector_id, region, stream) DO UPDATE
				                      SET window_from = EXCLUDED.window_from, covered_from = EXCLUDED.covered_from,
				                          read_to = EXCLUDED.read_to, partial = EXCLUDED.partial,
				                          pages = EXCLUDED.pages, events = EXCLUDED.events, last_error = '',
				                          last_attempt_at = EXCLUDED.last_attempt_at, updated_at = EXCLUDED.updated_at`,
					w.WorkspaceID, w.ConnectorID, w.Region, stream, read.WindowFrom, read.CoveredFrom,
					read.ReadTo, read.Partial, read.Pages, len(read.Records), now, now).Error; err != nil {
					return err
				}
			}
			return nil
		})
	})
	if err != nil {
		return 0, err
	}
	return written, nil
}

// recordSeenEvents stores the ids of every event the write counted that is
// still inside the retention, and deletes the connector's older ones.
func recordSeenEvents(tx *gorm.DB, w modelCallWrite, now time.Time) error {
	keep := now.Add(-seenEventRetention)
	ids := make([]string, 0)
	times := map[string]time.Time{}
	sets := make([]map[string]time.Time, 0, len(w.Deltas)+1)
	for _, d := range w.Deltas {
		sets = append(sets, d.EventIDs)
	}
	if w.Root != nil {
		sets = append(sets, w.Root.EventIDs)
	}
	for _, set := range sets {
		for id, at := range set {
			if at.Before(keep) {
				continue
			}
			if _, dup := times[id]; !dup {
				ids = append(ids, id)
			}
			times[id] = at
		}
	}
	sort.Strings(ids)
	for start := 0; start < len(ids); start += 500 {
		end := start + 500
		if end > len(ids) {
			end = len(ids)
		}
		args := make([]any, 0, (end-start)*5)
		values := ""
		for i, id := range ids[start:end] {
			if i > 0 {
				values += ","
			}
			values += "(?, ?, ?, ?, ?)"
			args = append(args, w.WorkspaceID, w.ConnectorID, id, times[id], now)
		}
		if err := tx.Exec(`INSERT INTO cloud_trail_seen_event (workspace_id, connector_id, event_id, event_time, seen_at)
		                   VALUES `+values+` ON CONFLICT DO NOTHING`, args...).Error; err != nil {
			return err
		}
	}
	return tx.Exec(`DELETE FROM cloud_trail_seen_event
	                 WHERE workspace_id = ? AND connector_id = ? AND event_time < ?`,
		w.WorkspaceID, w.ConnectorID, keep).Error
}

func truncateTrailError(s string) string {
	if len(s) > 500 {
		return s[:500]
	}
	return s
}

// modelCallResolverFrom adapts the scan's attribution matcher (the same one
// its observations use) to agentruntime attributions. agentruntime never
// produces the legacy username hint, so a model call is never tied to an
// identity by a name.
func modelCallResolverFrom(resolve func(awsdiscovery.Attribution) (*models.CloudIdentity, bool)) modelCallResolver {
	if resolve == nil {
		return nil
	}
	return func(att agentruntime.Attribution) (modelCallIdentity, bool) {
		switch att.How {
		case agentruntime.AttributionSessionIssuer, agentruntime.AttributionPrincipalARN:
		default:
			return modelCallIdentity{}, false
		}
		id, ok := resolve(awsdiscovery.Attribution{How: att.How, ARN: att.ARN, UniqueID: att.UniqueID})
		if !ok || id == nil {
			return modelCallIdentity{}, false
		}
		return modelCallIdentity{ID: id.ID, UniqueID: id.AWSAttrs().UniqueID}, true
	}
}
