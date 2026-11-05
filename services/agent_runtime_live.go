package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/tenancy"
	repositories "github.com/authsec-ai/authsec/repository"
)

// Live discovery (lab 2026-11-05). With the event stream on, detections and
// containment verification ran on streamed events, but a NEW AI workload only
// appeared at the next scan: model-call evidence (cloud_usage, source
// 'cloudtrail', service 'bedrock') was written only by the scan (P1a,
// agent_runtime_evidence.go).
//
// The "agent_runtime_live" EventSink records live evidence from every
// dispatched model call (agentruntime.Event.IsModelCall: a success or an
// authorization denial; other errors are not evidence of an AI workload):
//
//   - attribution is the scan's own (trailIdentityMatcher, with its
//     incarnation check, adapted by modelCallResolverFrom): the session
//     issuer's ARN and RoleId, or an IAM user's ARN, of THIS connector. An
//     event naming no identity in the inventory (a role created since the
//     last scan) is left to the next scan and is not marked seen;
//   - idempotent by eventID per workspace (agent_live_event_seen, migration
//     152): the poller and the stream dispatch the same events. Its own table
//     rather than agent_alert_event_seen, which the alert sink fills for the
//     events IT processed: sharing it would make whichever sink ran first
//     hide the event from the other. Rows are purged after 8 days;
//   - the exact counts (calls, denied, models, coverage, ...) are never
//     touched: the sink adds live_calls / live_denied / live_models /
//     live_last_call_at / live_regions (agentruntime.ModelCallUsage). An event
//     inside the scan's coverage of its region is not counted (the scan
//     counts it exactly); the scan clears the live counters once it covers
//     every live region (mergeModelCallDoc). A row the sink creates is the
//     scan's row from then on;
//   - isAIWorkload counts live evidence, so the resolver
//     (agentRuntimeResolver, which reads cloud_usage on every call) labels a
//     newly seen identity an AI workload at once, and the detections D1-D8
//     apply to it: this sink is registered BEFORE the alert and containment
//     sinks, so the same batch is already evaluated against the new label;
//   - after recording, inference (RunAgentInference) runs for the connector
//     asynchronously, at most once per 60 s per (workspace, connector) per
//     process, with one trailing run for events recorded meanwhile; its
//     errors are logged. Suggestions still need a scan: other_services (the
//     "acted on other resources" evidence) is only read from the trail by
//     the scan.
//
// Every statement runs in one transaction under row-level security for the
// workspace (tenancy.InWorkspace), which also takes the connector's
// model-call lock (lockModelCallUsage) shared with the scan's write.

// Sink name and limits.
const (
	AgentLiveSinkName = "agent_runtime_live"

	// AgentLiveSeenRetention is how long a counted eventID is remembered.
	AgentLiveSeenRetention = 8 * 24 * time.Hour
	agentLivePurgeEvery    = time.Hour

	// AgentLiveInferenceDebounce bounds inference runs per (workspace,
	// connector) per process.
	AgentLiveInferenceDebounce = 60 * time.Second
	agentLiveInferenceTimeout  = 2 * time.Minute
)

// AgentLiveSink is the "agent_runtime_live" agentruntime.EventSink.
type AgentLiveSink struct {
	db       *gorm.DB
	now      func() time.Time
	infer    func(ctx context.Context, ws, connectorID uuid.UUID) error
	debounce *agentLiveDebouncer

	purgeMu   sync.Mutex
	lastPurge map[uuid.UUID]time.Time
}

// NewAgentLiveSink builds the sink over db.
func NewAgentLiveSink(db *gorm.DB) *AgentLiveSink {
	return &AgentLiveSink{
		db: db, now: time.Now,
		infer: func(ctx context.Context, ws, connectorID uuid.UUID) error {
			_, err := NewAgentRuntimeService(db).RunAgentInference(ctx, ws, connectorID)
			return err
		},
		debounce:  newAgentLiveDebouncer(AgentLiveInferenceDebounce),
		lastPurge: map[uuid.UUID]time.Time{},
	}
}

// WithInference replaces the inference run and its debounce interval (tests).
func (s *AgentLiveSink) WithInference(f func(ctx context.Context, ws, connectorID uuid.UUID) error, interval time.Duration) *AgentLiveSink {
	s.infer = f
	s.debounce = newAgentLiveDebouncer(interval)
	return s
}

// WithClock replaces the wall clock (tests).
func (s *AgentLiveSink) WithClock(now func() time.Time) *AgentLiveSink {
	s.now = now
	return s
}

// RegisterAgentLiveSink registers the sink (cmd/main.go). It must come before
// the alert and containment sinks, so they see the label it makes.
func RegisterAgentLiveSink(db *gorm.DB) {
	agentruntime.RegisterSink(NewAgentLiveSink(db))
}

// Name implements agentruntime.EventSink.
func (s *AgentLiveSink) Name() string { return AgentLiveSinkName }

// Process implements agentruntime.EventSink: it records the live evidence
// and, when anything was counted, schedules inference for the connector.
func (s *AgentLiveSink) Process(ctx context.Context, workspaceID, connectorID uuid.UUID, events []agentruntime.Event) error {
	n, err := s.Record(ctx, workspaceID, connectorID, events)
	if err != nil {
		return fmt.Errorf("agent live evidence: %w", err)
	}
	if n > 0 {
		if s.infer != nil {
			s.debounce.trigger(workspaceID.String()+"/"+connectorID.String(), func() { s.runInference(workspaceID, connectorID) })
		}
		s.maybePurge(ctx, workspaceID)
	}
	return nil
}

func (s *AgentLiveSink) runInference(ws, connectorID uuid.UUID) {
	ctx, cancel := context.WithTimeout(context.Background(), agentLiveInferenceTimeout)
	defer cancel()
	if err := s.infer(ctx, ws, connectorID); err != nil {
		log.Printf("[agent-live] inference ws=%s connector=%s: %v", ws, connectorID, err)
	}
}

// liveModelCall: an event the sink may count -- a model call that succeeded
// or was refused, with an id, a time and an attribution.
func liveModelCall(e agentruntime.Event) bool {
	return e.EventID != "" && !e.EventTime.IsZero() && e.IsModelCall() &&
		(e.ErrorCode == "" || e.AuthorizationDenied) && e.Attribution().How != ""
}

// agentLiveDelta is one identity's new live events of a batch.
type agentLiveDelta struct {
	identity modelCallIdentity
	events   []agentruntime.Event
}

// Record lands the batch's live evidence and returns how many events it
// counted (new, attributed, and past the scan's coverage).
func (s *AgentLiveSink) Record(ctx context.Context, workspaceID, connectorID uuid.UUID, events []agentruntime.Event) (int, error) {
	if workspaceID == uuid.Nil || connectorID == uuid.Nil {
		return 0, nil
	}
	var calls []agentruntime.Event
	arns := map[string]bool{}
	for _, e := range events {
		if liveModelCall(e) {
			calls = append(calls, e)
			arns[e.Attribution().ARN] = true
		}
	}
	if len(calls) == 0 {
		return 0, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	now := s.now().UTC()
	counted := 0
	err := tenancy.InWorkspace(ctx, s.db, workspaceID, func(tx *gorm.DB) error {
		counted = 0
		if err := lockModelCallUsage(tx, workspaceID, connectorID); err != nil {
			return err
		}
		match, err := trailIdentityMatcher(repositories.NewCloudIdentityRepository(tx), workspaceID, connectorID, sortedKeys(arns), nil)
		if err != nil {
			return fmt.Errorf("attribution: %w", err)
		}
		resolve := modelCallResolverFrom(match)
		deltas := map[uuid.UUID]*agentLiveDelta{}
		var order []uuid.UUID
		dup := map[string]bool{}
		for _, e := range calls {
			if dup[e.EventID] {
				continue
			}
			dup[e.EventID] = true
			att := e.Attribution()
			id, ok := resolve(att)
			if !ok || id.ID == uuid.Nil {
				continue // not in the inventory: the next scan's to count
			}
			if id.UniqueID == "" {
				id.UniqueID = att.UniqueID
			}
			res := tx.Exec(`INSERT INTO agent_live_event_seen (workspace_id, event_id, connector_id, identity_id, event_time, seen_at)
			                VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (workspace_id, event_id) DO NOTHING`,
				workspaceID, truncate(e.EventID, 128), connectorID, id.ID, e.EventTime.UTC(), now)
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected != 1 {
				continue // already counted (the other path)
			}
			d := deltas[id.ID]
			if d == nil {
				d = &agentLiveDelta{identity: id}
				deltas[id.ID] = d
				order = append(order, id.ID)
			}
			d.events = append(d.events, e)
		}
		sort.Slice(order, func(i, j int) bool { return order[i].String() < order[j].String() })
		for _, idID := range order {
			n, err := recordLiveModelCalls(tx, workspaceID, connectorID, deltas[idID], now)
			if err != nil {
				return fmt.Errorf("identity %s: %w", idID, err)
			}
			counted += n
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return counted, nil
}

// recordLiveModelCalls merges one identity's live events into its model-call
// row, creating the row when the identity has none. tx holds the connector's
// model-call lock.
func recordLiveModelCalls(tx *gorm.DB, ws, connectorID uuid.UUID, d *agentLiveDelta, now time.Time) (int, error) {
	var rows []modelCallUsageRow
	if err := tx.Raw(`SELECT id, identity_id, attrs FROM cloud_usage
	                   WHERE workspace_id = ? AND connector_id = ? AND identity_id = ? AND source = ? AND service = ?
	                   FOR UPDATE`, ws, connectorID, d.identity.ID,
		agentruntime.UsageSource, agentruntime.UsageService).Scan(&rows).Error; err != nil {
		return 0, err
	}
	var prev modelCallDoc
	if len(rows) == 1 && len(rows[0].Attrs) > 0 {
		if err := json.Unmarshal(rows[0].Attrs, &prev); err != nil {
			prev = modelCallDoc{} // unreadable: rebuilt from here, as the scan does
		}
	}
	doc, n := mergeLiveModelCalls(prev, d.identity, d.events)
	if n == 0 {
		return 0, nil
	}
	attrs, err := json.Marshal(doc)
	if err != nil {
		return 0, err
	}
	if len(rows) == 1 {
		return n, tx.Exec(`UPDATE cloud_usage
		                      SET attrs = ?::jsonb, last_used_at = GREATEST(last_used_at, ?), last_seen_at = ?, row_updated_at = ?
		                    WHERE workspace_id = ? AND id = ?`,
			string(attrs), doc.LiveLastCallAt, now, now, ws, rows[0].ID).Error
	}
	// A new row is as current as its identity (its generation).
	return n, tx.Exec(`INSERT INTO cloud_usage
	                      (id, workspace_id, connector_id, identity_id, service, source,
	                       last_used_at, attrs, last_seen_generation,
	                       first_seen_at, last_seen_at, row_updated_at)
	                   SELECT ?, ?, ?, ?, ?, ?, ?, ?::jsonb,
	                          COALESCE((SELECT last_seen_generation FROM cloud_identity WHERE workspace_id = ? AND id = ?), 0),
	                          ?, ?, ?`,
		uuid.New(), ws, connectorID, d.identity.ID, agentruntime.UsageService, agentruntime.UsageSource,
		modelCallLastUsed(doc.ModelCallUsage), string(attrs), ws, d.identity.ID, now, now, now).Error
}

// mergeLiveModelCalls adds live events to a row's doc and returns it with the
// number of events counted. A doc of another incarnation starts afresh (as in
// mergeModelCallDoc); an event inside the scan's coverage of its region is
// skipped (the scan counts it exactly). The exact counts are never changed.
// Pure.
func mergeLiveModelCalls(prev modelCallDoc, id modelCallIdentity, events []agentruntime.Event) (modelCallDoc, int) {
	doc := modelCallDocFor(prev, id.UniqueID)
	u := &doc.ModelCallUsage
	n := 0
	for _, e := range events {
		if c, ok := doc.Regions[e.Region]; ok && !e.EventTime.After(c.CoveredTo) {
			continue
		}
		n++
		if e.ErrorCode == "" {
			u.LiveCalls++
			if model := e.RequestFacts[agentruntime.FactModelID]; model != "" {
				u.LiveModels = addModelCallCount(u.LiveModels, model, 1)
			}
		} else {
			u.LiveDenied++
		}
		at := e.EventTime.UTC()
		u.LiveLastCallAt = laterCall(u.LiveLastCallAt, at)
		if u.LiveRegions == nil {
			u.LiveRegions = map[string]time.Time{}
		}
		if was, ok := u.LiveRegions[e.Region]; !ok || at.After(was) {
			u.LiveRegions[e.Region] = at
		}
	}
	return doc, n
}

// maybePurge deletes the workspace's counted eventIDs older than
// AgentLiveSeenRetention, at most once per agentLivePurgeEvery per process.
func (s *AgentLiveSink) maybePurge(ctx context.Context, ws uuid.UUID) {
	now := s.now()
	s.purgeMu.Lock()
	if last, ok := s.lastPurge[ws]; ok && now.Sub(last) < agentLivePurgeEvery {
		s.purgeMu.Unlock()
		return
	}
	s.lastPurge[ws] = now
	s.purgeMu.Unlock()
	if _, err := s.PurgeSeen(ctx, ws, now.Add(-AgentLiveSeenRetention)); err != nil {
		log.Printf("[agent-live] purge workspace=%s: %v", ws, err)
	}
}

// PurgeSeen deletes the workspace's counted eventIDs seen before cutoff.
func (s *AgentLiveSink) PurgeSeen(ctx context.Context, ws uuid.UUID, cutoff time.Time) (int64, error) {
	var n int64
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		res := tx.Exec(`DELETE FROM agent_live_event_seen WHERE workspace_id = ? AND seen_at < ?`, ws, cutoff)
		n = res.RowsAffected
		return res.Error
	})
	return n, err
}

/* ------------------------------- the debounce ------------------------------- */

// agentLiveDebouncer runs a key's function at most once per interval: the
// first trigger runs at once; triggers within the interval, or during a run,
// collapse into ONE trailing run once the interval has passed. Runs are
// asynchronous; a panic in one is logged.
type agentLiveDebouncer struct {
	mu       sync.Mutex
	interval time.Duration
	keys     map[string]*agentLiveDebounceState
}

type agentLiveDebounceState struct {
	last      time.Time // when the latest run started
	scheduled bool      // a run is waiting to start
	running   bool
	dirty     bool // triggered while running
}

func newAgentLiveDebouncer(interval time.Duration) *agentLiveDebouncer {
	return &agentLiveDebouncer{interval: interval, keys: map[string]*agentLiveDebounceState{}}
}

// trigger asks for a run of key; it never blocks.
func (d *agentLiveDebouncer) trigger(key string, run func()) {
	d.mu.Lock()
	st := d.keys[key]
	if st == nil {
		st = &agentLiveDebounceState{}
		d.keys[key] = st
	}
	switch {
	case st.scheduled:
		d.mu.Unlock()
		return // the waiting run starts later and sees what this trigger recorded
	case st.running:
		st.dirty = true
		d.mu.Unlock()
		return
	}
	st.scheduled = true
	wait := time.Duration(0)
	if !st.last.IsZero() {
		wait = time.Until(st.last.Add(d.interval))
	}
	d.mu.Unlock()
	go d.fire(key, st, wait, run)
}

func (d *agentLiveDebouncer) fire(key string, st *agentLiveDebounceState, wait time.Duration, run func()) {
	if wait > 0 {
		t := time.NewTimer(wait)
		<-t.C
	}
	d.mu.Lock()
	st.scheduled, st.running, st.last = false, true, time.Now()
	d.mu.Unlock()
	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[agent-live] debounced run %s: panic: %v", key, r)
			}
		}()
		run()
	}()
	d.mu.Lock()
	st.running = false
	again := st.dirty
	st.dirty = false
	d.mu.Unlock()
	if again {
		d.trigger(key, run)
	}
}
