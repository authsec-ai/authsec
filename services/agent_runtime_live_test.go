package services

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/agentruntime"
)

var liveT0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func liveEvent(id, region string, at time.Time, errorCode string) agentruntime.Event {
	return agentruntime.Event{EventID: id, EventTime: at, EventSource: agentruntime.SourceBedrock, EventName: "Converse",
		EventType: "AwsApiCall", Region: region, ErrorCode: errorCode,
		AuthorizationDenied: errorCode == "AccessDeniedException",
		SessionIssuerARN:    "arn:aws:iam::111111111111:role/r", SessionIssuerPrincipalID: "AROAR",
		RequestFacts: map[string]string{agentruntime.FactModelID: "anthropic.claude"}}
}

func TestAgentLiveModelCallFilter(t *testing.T) {
	ok := liveEvent("1", "us-east-1", liveT0, "")
	denied := liveEvent("2", "us-east-1", liveT0, "AccessDeniedException")
	throttled := liveEvent("3", "us-east-1", liveT0, "ThrottlingException")
	completion := liveEvent("4", "us-east-1", liveT0, "")
	completion.EventType = "AwsServiceEvent"
	unattributed := liveEvent("5", "us-east-1", liveT0, "")
	unattributed.SessionIssuerARN = ""
	notimed := liveEvent("6", "us-east-1", time.Time{}, "")
	other := liveEvent("7", "us-east-1", liveT0, "")
	other.EventSource, other.EventName = "s3.amazonaws.com", "GetObject"
	for _, c := range []struct {
		name string
		e    agentruntime.Event
		want bool
	}{{"success", ok, true}, {"denied", denied, true}, {"throttled", throttled, false},
		{"stream completion", completion, false}, {"unattributed", unattributed, false},
		{"no time", notimed, false}, {"not a model call", other, false}} {
		if got := liveModelCall(c.e); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// Live events past the scan's coverage of their region are counted live; the
// exact counts never change.
func TestAgentLiveMergeCountsOnlyPastCoverage(t *testing.T) {
	prev := modelCallDoc{IdentityUniqueID: "AROAR", Regions: map[string]trailCoverage{
		"us-east-1": {CoveredFrom: liveT0.Add(-24 * time.Hour), CoveredTo: liveT0}}}
	prev.Calls, prev.Models = 7, map[string]int{"anthropic.claude": 7}
	events := []agentruntime.Event{
		liveEvent("a", "us-east-1", liveT0.Add(-time.Minute), ""),                       // covered: the scan's
		liveEvent("b", "us-east-1", liveT0.Add(time.Minute), ""),                        // live call
		liveEvent("c", "us-east-1", liveT0.Add(2*time.Minute), "AccessDeniedException"), // live denial
		liveEvent("d", "eu-west-1", liveT0.Add(-time.Hour), ""),                         // region never read
	}
	doc, n := mergeLiveModelCalls(prev, modelCallIdentity{ID: uuid.New(), UniqueID: "AROAR"}, events)
	if n != 3 {
		t.Fatalf("counted %d, want 3", n)
	}
	u := doc.ModelCallUsage
	if u.Calls != 7 || u.Models["anthropic.claude"] != 7 || u.Denied != 0 {
		t.Fatalf("exact counts changed: %+v", u)
	}
	if u.LiveCalls != 2 || u.LiveDenied != 1 || u.LiveModels["anthropic.claude"] != 2 {
		t.Fatalf("live counts: %+v", u)
	}
	if u.LiveLastCallAt == nil || !u.LiveLastCallAt.Equal(liveT0.Add(2*time.Minute)) {
		t.Fatalf("live_last_call_at %v", u.LiveLastCallAt)
	}
	if !u.LiveRegions["us-east-1"].Equal(liveT0.Add(2*time.Minute)) || !u.LiveRegions["eu-west-1"].Equal(liveT0.Add(-time.Hour)) {
		t.Fatalf("live regions %v", u.LiveRegions)
	}
	if !isAIWorkload(agentruntime.ModelCallUsage{LiveCalls: 1}) || !isAIWorkload(agentruntime.ModelCallUsage{LiveDenied: 1}) ||
		isAIWorkload(agentruntime.ModelCallUsage{}) {
		t.Fatal("isAIWorkload must count live evidence")
	}
}

func TestAgentLiveMergeNewIncarnationStartsAfresh(t *testing.T) {
	prev := modelCallDoc{IdentityUniqueID: "AROAOLD"}
	prev.Calls = 9
	doc, n := mergeLiveModelCalls(prev, modelCallIdentity{UniqueID: "AROANEW"}, []agentruntime.Event{liveEvent("x", "us-east-1", liveT0, "")})
	if n != 1 || doc.IdentityUniqueID != "AROANEW" || doc.Calls != 0 || doc.LiveCalls != 1 {
		t.Fatalf("another incarnation's doc: %+v", doc)
	}
}

// The scan's merge keeps the live keys it does not own and clears the live
// counters only once every live region is covered past its latest live call.
func TestAgentLiveScanMergeKeepsThenClearsLive(t *testing.T) {
	prev := modelCallDoc{IdentityUniqueID: "AROAR"}
	prev, _ = mergeLiveModelCalls(prev, modelCallIdentity{UniqueID: "AROAR"}, []agentruntime.Event{
		liveEvent("1", "us-east-1", liveT0, ""), liveEvent("2", "eu-west-1", liveT0.Add(time.Minute), "")})
	// Stored and read back as Record does.
	raw, err := json.Marshal(prev)
	if err != nil {
		t.Fatal(err)
	}
	var stored modelCallDoc
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.LiveCalls != 2 || stored.LiveRegions["eu-west-1"].IsZero() {
		t.Fatalf("live keys lost in storage: %s", raw)
	}
	cov := func(to time.Time) *trailCoverage {
		return &trailCoverage{CoveredFrom: liveT0.Add(-time.Hour), CoveredTo: to}
	}
	d := &modelCallDelta{Identity: modelCallIdentity{UniqueID: "AROAR"}, ModelActivity: true,
		Usage: agentruntime.ModelCallUsage{Calls: 1}}
	// us-east-1 covered past its live call; eu-west-1 never read: kept.
	doc := mergeModelCallDoc(stored, d, "us-east-1", cov(liveT0.Add(5*time.Minute)))
	if doc.Calls != 1 || doc.LiveCalls != 2 || doc.LiveModels["anthropic.claude"] != 2 {
		t.Fatalf("scan merge dropped live keys: %+v", doc.ModelCallUsage)
	}
	// eu-west-1 covered, but not yet up to its live call: kept.
	doc = mergeModelCallDoc(doc, nil, "eu-west-1", cov(liveT0))
	if doc.LiveCalls != 2 {
		t.Fatalf("cleared before the live call was covered: %+v", doc.ModelCallUsage)
	}
	// Both covered past their live calls: cleared, the time kept.
	doc = mergeModelCallDoc(doc, nil, "eu-west-1", cov(liveT0.Add(10*time.Minute)))
	if doc.LiveCalls != 0 || doc.LiveDenied != 0 || doc.LiveModels != nil || doc.LiveRegions != nil {
		t.Fatalf("live counters not cleared: %+v", doc.ModelCallUsage)
	}
	if doc.LiveLastCallAt == nil || !doc.LiveLastCallAt.Equal(liveT0.Add(time.Minute)) || doc.Calls != 1 {
		t.Fatalf("live_last_call_at or exact counts lost: %+v", doc.ModelCallUsage)
	}
	if lu := modelCallLastUsed(doc.ModelCallUsage); lu == nil || !lu.Equal(liveT0.Add(time.Minute)) {
		t.Fatalf("last used %v", lu)
	}
}

// At most one run per interval: a burst of triggers is one run now and one
// trailing run after the interval.
func TestAgentLiveDebounce(t *testing.T) {
	const interval = 150 * time.Millisecond
	d := newAgentLiveDebouncer(interval)
	var mu sync.Mutex
	var runs []time.Time
	run := func() {
		mu.Lock()
		runs = append(runs, time.Now())
		mu.Unlock()
	}
	for i := 0; i < 5; i++ {
		d.trigger("ws/conn", run)
		time.Sleep(5 * time.Millisecond)
	}
	other := make(chan struct{}, 1)
	d.trigger("ws/other", func() { other <- struct{}{} })
	select {
	case <-other:
	case <-time.After(time.Second):
		t.Fatal("another key waited on this one")
	}
	time.Sleep(3 * interval)
	mu.Lock()
	defer mu.Unlock()
	if len(runs) != 2 {
		t.Fatalf("%d runs, want 2 (one now, one trailing)", len(runs))
	}
	if gap := runs[1].Sub(runs[0]); gap < interval-10*time.Millisecond {
		t.Fatalf("runs %v apart, want at least %v", gap, interval)
	}
}
