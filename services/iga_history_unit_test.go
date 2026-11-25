package services

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// W9 metric math, variant selection and chain functions, without a database.

func TestHistoryPercentile(t *testing.T) {
	if !math.IsNaN(percentile(nil, 0.5)) {
		t.Fatal("percentile of nothing must be NaN")
	}
	cases := []struct {
		vals []float64
		p    float64
		want float64
	}{
		{[]float64{5}, 0.5, 5},
		{[]float64{1, 2, 3, 4}, 0.5, 2.5},
		{[]float64{1, 2, 3, 4, 5}, 0.5, 3},
		{[]float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 0.9, 9.1},
		{[]float64{10, 20}, 0, 10},
		{[]float64{10, 20}, 1, 20},
	}
	for _, c := range cases {
		if got := percentile(c.vals, c.p); math.Abs(got-c.want) > 1e-9 {
			t.Errorf("percentile(%v, %v) = %v, want %v", c.vals, c.p, got, c.want)
		}
	}
}

func TestHistoryDurationStats(t *testing.T) {
	var m MetricResult
	durationStats(&m, []float64{300, -5, 60, 120, math.NaN()})
	if *m.N != 4 || *m.Median != 90 || *m.Value != 90 {
		t.Fatalf("stats: n=%v median=%v value=%v", *m.N, *m.Median, *m.Value)
	}
	// p90 of [0, 60, 120, 300]: 0.9*3 = 2.7 -> 120 + 0.7*180.
	if *m.P90 != 246 {
		t.Fatalf("p90 = %v", *m.P90)
	}
	var empty MetricResult
	durationStats(&empty, nil)
	if *empty.N != 0 || empty.Median != nil || empty.Value != nil {
		t.Fatalf("empty stats: %+v", empty)
	}
}

func TestHistoryUnprovenBuckets(t *testing.T) {
	b := bucketAges([]float64{10, 3599, 3600, 86399, 86400, 7*86400 - 1, 7 * 86400, 30 * 86400})
	want := map[string]float64{ageUnder1h: 2, age1hTo24h: 2, age1dTo7d: 2, ageOver7d: 2}
	for k, v := range want {
		if b[k] != v {
			t.Errorf("bucket %s = %v, want %v (%v)", k, b[k], v, b)
		}
	}
	if z := bucketAges(nil); len(z) != 4 || z[ageOver7d] != 0 {
		t.Fatalf("empty buckets must all be present: %v", z)
	}
}

func TestHistoryShare(t *testing.T) {
	if share(1, 0) != nil {
		t.Fatal("share of nothing must be nil")
	}
	if *share(1, 3) != 0.3333 {
		t.Fatalf("share(1,3) = %v", *share(1, 3))
	}
}

func TestHistoryPreviousSameDefinition(t *testing.T) {
	cur := MetricResult{ID: "x", Status: MetricAvailable, Value: fptr(3), Definition: MetricDefinition{ID: "x", Version: 2}}
	same := MetricResult{ID: "x", Status: MetricAvailable, Value: fptr(5), Definition: MetricDefinition{ID: "x", Version: 2},
		Previous: &MetricResult{ID: "nested"}}
	got := withPrevious(cur, &same)
	if got.Previous == nil || *got.Previous.Value != 5 || got.Previous.Previous != nil {
		t.Fatalf("previous under the same definition must be kept, without nesting: %+v", got.Previous)
	}
	other := MetricResult{ID: "x", Status: MetricAvailable, Value: fptr(5), Definition: MetricDefinition{ID: "x", Version: 1}}
	got = withPrevious(cur, &other)
	if got.Previous.Status != MetricUnavailable || got.Previous.Value != nil || !strings.HasPrefix(got.Previous.Reason, "definition_changed") {
		t.Fatalf("previous under another definition must not be compared: %+v", got.Previous)
	}
	if withPrevious(cur, nil).Previous != nil {
		t.Fatal("no previous given")
	}
}

func TestHistorySOCVariantsFromProbe(t *testing.T) {
	base := staticSchemaProbe{
		"agent_alert": true, "agent_alert.created_at": true, "agent_alert.identity_id": true, "agent_alert.state": true,
		"agent_alert.state_changed_at": true, "agent_alert.workload_ids": true,
		"agent_containment": true, "agent_containment.identity_id": true, "agent_containment.level": true,
		"agent_containment.state": true, "agent_containment.created_at": true, "agent_containment.contained_at": true,
		"agent_containment.workload_ids": true, "agent_containment.effective": true,
		"agent_activity_event": true, "agent_activity_event.identity_id": true, "agent_activity_event.action": true,
		"agent_activity_event.outcome": true, "agent_activity_event.occurred_at": true,
	}
	v := probeSOC(base)
	if !v.alert || !v.containment || !v.activity || v.ackCol || v.resolvedCol || v.caseAssign || v.proofState || v.caseOutcome || v.alertOutcome {
		t.Fatalf("today's schema: %+v", v)
	}
	// Today: outcome mix is unavailable, the rest available.
	for _, id := range SOCMetricIDs {
		r := socUnavailableReason(id, v)
		if (id == SOCOutcomeMix) != (r != "") {
			t.Errorf("%s: reason %q", id, r)
		}
	}
	if socDefinition(SOCTimeToFirstAction, v).Version != 1 || socDefinition(SOCUnprovenStops, v).Version != 1 {
		t.Fatal("today's definitions are version 1")
	}

	// After W3 / F8 / W2 merge, the expected columns light the metrics up
	// under new definition versions.
	merged := staticSchemaProbe{}
	for k, val := range base {
		merged[k] = val
	}
	for _, k := range []string{"agent_alert.acknowledged_at", "agent_alert.resolved_at", "agent_alert.outcome",
		"agent_case", "agent_case.id", "agent_case.assigned_at", "agent_case.outcome", "agent_case.closed_at",
		"agent_case_alert", "agent_case_alert.alert_id", "agent_case_alert.case_id", "agent_containment.proof_state"} {
		merged[k] = true
	}
	m := probeSOC(merged)
	if !m.ackCol || !m.resolvedCol || !m.caseAssign || !m.proofState || !m.caseOutcome || !m.alertOutcome {
		t.Fatalf("merged schema: %+v", m)
	}
	if socUnavailableReason(SOCOutcomeMix, m) != "" {
		t.Fatal("outcome mix must light up with case outcomes")
	}
	if a, b := socDefinition(SOCTimeToFirstAction, v), socDefinition(SOCTimeToFirstAction, m); a.Version == b.Version || a.Text == b.Text {
		t.Fatalf("a different source must be a different definition: %+v %+v", a, b)
	}
	if socDefinition(SOCUnprovenStops, m).Version != 2 || socDefinition(SOCTimeToResolve, m).Version != 2 {
		t.Fatal("merged definitions are version 2")
	}

	// Nothing at all: every metric unavailable with a reason.
	none := probeSOC(staticSchemaProbe{})
	for _, id := range SOCMetricIDs {
		if socUnavailableReason(id, none) == "" {
			t.Errorf("%s must be unavailable without sources", id)
		}
	}
}

func TestHistoryPostureVariants(t *testing.T) {
	v := probePosture(staticSchemaProbe{})
	if v.responder || v.crownJewel || v.capability {
		t.Fatalf("no W1/W7 sources: %+v", v)
	}
	w := probePosture(staticSchemaProbe{"agent": true, "agent.workspace_id": true, "agent.responder_group_id": true,
		"iga_resources": true, "iga_resources.crown_jewel": true,
		"agent_capability_state": true, "agent_capability_state.capability": true, "agent_capability_state.state": true})
	if !w.responder || !w.crownJewel || !w.capability || w.agentEnded {
		t.Fatalf("W1/W7 sources: %+v", w)
	}
	if postureDefinition(PostureCapabilityCoverage, v).Version == postureDefinition(PostureCapabilityCoverage, w).Version {
		t.Fatal("capability coverage changes definition with its source")
	}
}

func TestHistoryWindows(t *testing.T) {
	for _, p := range []string{"", "7d", "30d", "90d"} {
		if _, ok := parsePeriod(p); !ok {
			t.Errorf("period %q", p)
		}
	}
	if _, ok := parsePeriod("1y"); ok {
		t.Fatal("1y is not a period")
	}
	cur, prev, ok := monthWindow("2026-03")
	if !ok || cur.From != time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC) || cur.To != time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC) ||
		prev.From != time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC) || prev.To != cur.From {
		t.Fatalf("month: %+v %+v", cur, prev)
	}
	if _, _, ok := monthWindow("2026-13"); ok {
		t.Fatal("bad month accepted")
	}
}

func TestHistoryChains(t *testing.T) {
	ws, other := uuid.New(), uuid.New()
	day := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	a := snapshotRowChain(ws, "", day, "inventory", "iga_workload:1", strings.Repeat("a", 64))
	if len(a) != 64 || a == snapshotRowChain(other, "", day, "inventory", "iga_workload:1", strings.Repeat("a", 64)) {
		t.Fatal("a row chain is bound to its workspace")
	}
	if a == snapshotRowChain(ws, a, day, "inventory", "iga_workload:1", strings.Repeat("a", 64)) {
		t.Fatal("a row chain covers its predecessor")
	}
	rows := [][3]string{{"inventory", "b", "h2"}, {"inventory", "a", "h1"}}
	rev := [][3]string{{"inventory", "a", "h1"}, {"inventory", "b", "h2"}}
	if snapshotContentHash(rows) != snapshotContentHash(rev) {
		t.Fatal("content hash must not depend on row order")
	}
	if snapshotContentHash(rows) == snapshotContentHash(rows[:1]) {
		t.Fatal("content hash covers every row")
	}
	d1 := snapshotDayChain(ws, "", day, "c", 2, "{}")
	if d1 == snapshotDayChain(ws, "", day, "c", 3, "{}") || d1 == snapshotDayChain(ws, "x", day, "c", 2, "{}") {
		t.Fatal("a day chain covers its counts and predecessor")
	}
	// Canonical bodies: key order and spacing do not change the hash.
	_, h1, err := canonicalBody([]byte(`{"b": 1, "a": "x"}`))
	if err != nil {
		t.Fatal(err)
	}
	_, h2, _ := canonicalBody([]byte(`{"a":"x","b":1}`))
	if h1 != h2 {
		t.Fatal("canonical hash must ignore key order")
	}
}

func TestHistoryExportParams(t *testing.T) {
	p, err := exportParams(map[string]any{"from": "2026-01-01", "to": "2026-02-01", "kinds": []string{"alert", "snapshot_days"}})
	if err != nil || len(p.Kinds) != 2 || !p.From.Before(p.To) {
		t.Fatalf("valid params: %+v %v", p, err)
	}
	all, err := exportParams(json.RawMessage(`{"from":"2026-01-01","to":"2026-01-02"}`))
	if err != nil || len(all.Kinds) != len(PopulationKinds) {
		t.Fatalf("default kinds: %+v %v", all, err)
	}
	bad := []map[string]any{
		{"from": "2026-02-01", "to": "2026-01-01"},
		{"from": "2024-01-01", "to": "2026-01-01"},
		{"from": "nope", "to": "2026-01-01"},
		{"from": "2026-01-01", "to": "2026-01-02", "kinds": []string{"passwords"}},
	}
	for _, b := range bad {
		if _, err := exportParams(b); err == nil {
			t.Errorf("accepted %v", b)
		}
	}
}
