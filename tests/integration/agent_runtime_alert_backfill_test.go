package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/agentruntime"
)

// Backfill grouping (lab 2026-11-05): a scan's history arriving in one batch
// must not open one alert per dedupe window. Findings on events older than
// 24 h go into ONE alert per (identity, detection) per batch; recent events
// keep the per-window dedupe; events older than 7 days still raise nothing.
func TestAgentRuntimeAlertBackfillGroupedPerBatch(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "ar-backfill-a")
	b := p3NewGov(t, db, "ar-backfill-b")
	r := arSetup(t, db)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	const role = "arn:aws:iam::111111111111:role/history-agent"
	r.set(a.ws, role, agentruntime.Subject{IdentityID: uuid.New(), ConnectorID: a.conn, Label: agentruntime.LabelAIWorkload, Name: "history-agent"})
	r.set(b.ws, role, agentruntime.Subject{IdentityID: uuid.New(), ConnectorID: b.conn, Label: agentruntime.LabelAIWorkload, Name: "history-agent"})

	read := func(id string, ago time.Duration) agentruntime.Event {
		return arEvent(id, role, "secretsmanager.amazonaws.com", "GetSecretValue", now.Add(-ago))
	}
	// One batch, as a first scan reads it: 10 days back (no alert), five
	// reads between 6 days and 30 h ago, hours apart (five dedupe windows),
	// and two recent reads 2.5 h apart.
	batch := []agentruntime.Event{read("bf-0", 240*time.Hour)}
	for i, ago := range []time.Duration{144 * time.Hour, 100 * time.Hour, 72 * time.Hour, 48 * time.Hour, 30 * time.Hour} {
		batch = append(batch, read(fmt.Sprintf("bf-%d", i+1), ago))
	}
	batch = append(batch, read("bf-r1", 3*time.Hour), read("bf-r2", 30*time.Minute))
	if err := agentruntime.Dispatch(ctx, a.ws, a.conn, batch); err != nil {
		t.Fatal(err)
	}
	rows := arAlerts(t, db, a.ws)
	counts := map[int]int{}
	for _, row := range rows {
		if row.Detection != "D1" {
			t.Fatalf("unexpected alert %+v", row)
		}
		counts[row.EventCount]++
	}
	// One backfill alert with the five old reads; the two recent reads are
	// more than the 1 h window apart, so each opens its own (unchanged).
	if len(rows) != 3 || counts[5] != 1 || counts[1] != 2 {
		t.Fatalf("alerts %+v, want one of 5 events and two of 1", rows)
	}
	// Workspace B never sees A's alerts.
	if got := arAlerts(t, db, b.ws); len(got) != 0 {
		t.Fatalf("workspace B has %d alerts", len(got))
	}

	// A later batch of other old history for B opens one alert there too.
	var older []agentruntime.Event
	for i := 0; i < 4; i++ {
		older = append(older, read(fmt.Sprintf("bf-b%d", i), time.Duration(30+10*i)*time.Hour))
	}
	if err := agentruntime.Dispatch(ctx, b.ws, b.conn, older); err != nil {
		t.Fatal(err)
	}
	if got := arAlerts(t, db, b.ws); len(got) != 1 || got[0].EventCount != 4 {
		t.Fatalf("workspace B alerts %+v, want one of 4 events", got)
	}
	if got := arAlerts(t, db, a.ws); len(got) != 3 {
		t.Fatalf("workspace A alerts changed: %+v", got)
	}
}
