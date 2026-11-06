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
//     every other event only inside the general pass's. Each window starts at
//     its stream's previous mark, so no event is added twice across scans; an
//     event both passes returned is one event (awsdiscovery.MergeTrailRecords).
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
}

func isModelCallSource(src string) bool {
	return src == agentruntime.SourceBedrock || (agentruntime.Event{EventSource: src, EventType: "AwsApiCall"}).IsModelCall()
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
		switch {
		case ev.IsModelCall():
			d := delta(ev)
			if d == nil {
				continue
			}
			d.ModelActivity = true
			u := &d.Usage
			switch {
			case ev.ErrorCode == "":
				u.Calls++
				if model := ev.RequestFacts[agentruntime.FactModelID]; model != "" {
					u.Models = addModelCallCount(u.Models, model, 1)
				}
				u.Endpoints = addModelCallCount(u.Endpoints, ev.EventSource, 1)
			case ev.AuthorizationDenied:
				u.Denied++
			default:
				u.Errors++
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
				}
			}
		case isModelCallSource(ev.EventSource):
			// Bedrock's control plane (ListFoundationModels, ...): neither a
			// model call nor "another service".
		case ev.IsAPICall() && ev.ErrorCode == "" && ev.EventSource != "":
			if d := delta(ev); d != nil {
				d.Usage.OtherServices = addModelCallCount(d.Usage.OtherServices, ev.EventSource, 1)
			}
		}
	}
	for id, d := range out {
		if !d.ModelActivity && len(d.Usage.OtherServices) == 0 && d.Usage.Tokens == 0 {
			delete(out, id)
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
//
// The live_* keys (written by the live sink, agent_runtime_live.go) are kept
// as they are, except that once every region a live call was seen in is
// covered up to that region's latest live call, the live counters are
// cleared: the scan now counts those calls exactly (live_last_call_at stays).
func mergeModelCallDoc(prev modelCallDoc, d *modelCallDelta, region string, cov *trailCoverage) modelCallDoc {
	doc := prev
	if d != nil {
		doc = modelCallDocFor(prev, d.Identity.UniqueID)
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
	// The top-level coverage is what holds in EVERY region the row names.
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
	if liveCoveredByScan(doc) {
		u.LiveCalls, u.LiveDenied, u.LiveModels, u.LiveRegions = 0, 0, nil, nil
	}
	return doc
}

// modelCallDocFor is prev as the doc of the incarnation uniqueID: a doc that
// records another incarnation starts afresh (a role recreated under the same
// ARN is another principal). An unknown uniqueID keeps prev. Pure.
func modelCallDocFor(prev modelCallDoc, uniqueID string) modelCallDoc {
	doc := prev
	if uniqueID != "" {
		if doc.IdentityUniqueID != "" && doc.IdentityUniqueID != uniqueID {
			doc = modelCallDoc{}
		}
		doc.IdentityUniqueID = uniqueID
	}
	return doc
}

// liveCoveredByScan reports whether the doc has live counts and every region
// they were seen in is read by the scan up to that region's latest live call.
func liveCoveredByScan(doc modelCallDoc) bool {
	u := doc.ModelCallUsage
	if u.LiveCalls == 0 && u.LiveDenied == 0 && len(u.LiveModels) == 0 {
		return false
	}
	if len(u.LiveRegions) == 0 {
		return false
	}
	for region, last := range u.LiveRegions {
		c, ok := doc.Regions[region]
		if !ok || c.CoveredTo.Before(last) {
			return false
		}
	}
	return true
}

// modelCallUsageLockKey serialises the writers of one connector's model-call
// rows: the scan's Record and the live sink. Each takes it first in its
// transaction, so neither inserts a row the other is about to insert.
func modelCallUsageLockKey(ws, connectorID uuid.UUID) string {
	return "agent_model_call_usage:" + ws.String() + ":" + connectorID.String()
}

func lockModelCallUsage(tx *gorm.DB, ws, connectorID uuid.UUID) error {
	return tx.Exec(`SELECT pg_advisory_xact_lock(hashtext(?))`, modelCallUsageLockKey(ws, connectorID)).Error
}

// modelCallLastUsed is the row's last_used_at: the latest model call, exact
// or seen live.
func modelCallLastUsed(u agentruntime.ModelCallUsage) *time.Time {
	if u.LiveLastCallAt == nil {
		return u.LastCallAt
	}
	return laterCall(u.LastCallAt, *u.LiveLastCallAt)
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
}

type modelCallUsageRow struct {
	ID         uuid.UUID
	IdentityID uuid.UUID
	Attrs      []byte
}

// Record lands one region's evidence: every cloud_usage model-call row of the
// connector merged with this region's deltas and coverage, new rows for
// identities seen calling a model for the first time, and the settled
// streams' marks moved -- or, when any of it fails, nothing. Returns the rows
// written.
func (st trailEvidenceStore) Record(ctx context.Context, w modelCallWrite) (int, error) {
	written := 0
	cov, covOK := modelCallCoverage(w.Reads[awsdiscovery.TrailStreamGeneral], w.Reads[awsdiscovery.TrailStreamBedrock])
	err := tenancy.InWorkspace(ctx, st.db, w.WorkspaceID, func(tx *gorm.DB) error {
		return repositories.RunFenced(tx, st.fence, func(tx *gorm.DB) error {
			written = 0
			// 0. One writer of the connector's model-call rows at a time (the
			// live sink is the other).
			if err := lockModelCallUsage(tx, w.WorkspaceID, w.ConnectorID); err != nil {
				return err
			}
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
			if err := tx.Raw(`SELECT id, identity_id, attrs FROM cloud_usage
			                   WHERE workspace_id = ? AND connector_id = ? AND source = ? AND service = ?
			                   FOR UPDATE`, w.WorkspaceID, w.ConnectorID,
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
				if d == nil && covp == nil {
					continue
				}
				var prev modelCallDoc
				if len(row.Attrs) > 0 {
					if err := json.Unmarshal(row.Attrs, &prev); err != nil {
						prev = modelCallDoc{} // unreadable: rebuilt from here
					}
				}
				doc := mergeModelCallDoc(prev, d, w.Region, covp)
				attrs, err := json.Marshal(doc)
				if err != nil {
					return err
				}
				if err := tx.Exec(`UPDATE cloud_usage
				                      SET attrs = ?::jsonb, last_used_at = COALESCE(?, last_used_at), last_seen_generation = ?,
				                          last_seen_at = ?, row_updated_at = ?
				                    WHERE workspace_id = ? AND id = ?`,
					string(attrs), modelCallLastUsed(doc.ModelCallUsage), w.Generation, now, now, w.WorkspaceID, row.ID).Error; err != nil {
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
					modelCallLastUsed(doc.ModelCallUsage), string(attrs), w.Generation, now, now, now).Error; err != nil {
					return err
				}
				written++
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
