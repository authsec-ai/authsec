package integration

// The §5.1 read contract itself (T6.1, B16, B23), against real PostgreSQL:
// one REPEATABLE READ snapshot per request, optional work in savepoints, the
// revision check, and signed cursors.

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/services"
)

// B23 (first clause): an OPTIONAL query that times out is rolled back to its
// savepoint, reported unknown, and the transaction goes on in the same
// snapshot. Removing the savepoint makes the next query fail.
func TestP2ReadOptionalTimeoutKeepsTheSnapshot(t *testing.T) {
	l := newP2Lab(t, "p2-read-optional", true)
	l.scanAndProject(oneLambda(l))
	r := igaread.NewReader(l.db, []byte("k")).WithBudget(800 * time.Millisecond)

	err := r.Read(context.Background(), l.ws, igaread.Pin{}, func(q *igaread.Query) error {
		ok, err := q.Optional(func(tx *gorm.DB) error { return tx.Exec(`SELECT pg_sleep(2)`).Error })
		if err != nil {
			t.Fatalf("a timed-out optional query must not be an error: %v", err)
		}
		if ok {
			t.Fatal("pg_sleep(2) inside half of an 800ms budget reported success")
		}
		var n int64
		if err := q.DB().Raw(`SELECT count(*) FROM iga_workload WHERE workspace_id = ?`, q.WS).Row().Scan(&n); err != nil {
			t.Fatalf("the query after a rolled-back savepoint failed: %v", err)
		}
		if n != 1 {
			t.Fatalf("workloads = %d after the savepoint rollback, want 1", n)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
}

// B23 (third clause): a MANDATORY query past the deadline is 504, nothing
// partial.
func TestP2ReadMandatoryTimeoutIs504(t *testing.T) {
	l := newP2Lab(t, "p2-read-mandatory", true)
	l.scanAndProject(oneLambda(l))
	r := igaread.NewReader(l.db, []byte("k")).WithBudget(300 * time.Millisecond)
	err := r.Read(context.Background(), l.ws, igaread.Pin{}, func(q *igaread.Query) error {
		return q.DB().Exec(`SELECT pg_sleep(2)`).Error
	})
	e := igaread.AsError(err)
	if e == nil || e.Status != 504 || e.Code != "query_timeout" {
		t.Fatalf("mandatory query past the deadline = %v, want 504 query_timeout", err)
	}
}

// Revision pinning: rev=N current is served; N no longer current is 409
// revision_stale with the current revision named; a cursor from an older
// revision is the same 409.
func TestP2ReadRevisionStale(t *testing.T) {
	l := newP2Lab(t, "p2-read-rev", true)
	a := oneLambda(l)
	l.scanAndProject(a)
	r := igaread.NewReader(l.db, []byte("k"))

	var first int64
	if err := r.Read(context.Background(), l.ws, igaread.Pin{}, func(q *igaread.Query) error {
		if q.Rev == nil {
			t.Fatal("no revision after a projection")
		}
		first = q.Rev.Rev
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	l.scanAndProject(a)

	err := r.Read(context.Background(), l.ws, igaread.Pin{Rev: &first}, func(*igaread.Query) error { return nil })
	e := igaread.AsError(err)
	if e == nil || e.Status != 409 || e.Code != "revision_stale" {
		t.Fatalf("rev=%d after a newer publication = %v, want 409 revision_stale", first, err)
	}
	if e.Extra["requested_rev"] != first || e.Extra["current_rev"] != first+1 {
		t.Fatalf("409 body = %v, want requested %d current %d", e.Extra, first, first+1)
	}
	err = r.Read(context.Background(), l.ws, igaread.Pin{CursorRev: &first}, func(*igaread.Query) error { return nil })
	if e := igaread.AsError(err); e == nil || e.Code != "revision_stale" {
		t.Fatalf("a cursor from rev %d = %v, want 409 revision_stale", first, err)
	}
}

// B16: a read in flight when a publication commits sees only the old
// revision -- its revision and its rows come from one snapshot.
func TestP2ReadDoesNotStraddleAPublication(t *testing.T) {
	l := newP2Lab(t, "p2-read-straddle", true)
	a := oneLambda(l)
	l.scanAndProject(a)
	r := igaread.NewReader(l.db, []byte("k"))

	err := r.Read(context.Background(), l.ws, igaread.Pin{}, func(q *igaread.Query) error {
		var before int64
		q.DB().Raw(`SELECT count(*) FROM iga_publication WHERE workspace_id = ?`, q.WS).Row().Scan(&before)
		// A second role and a rescan publish while this snapshot is open.
		a.role("LateRole", "AROALATEROLE00000001")
		l.scanAndProject(a)
		var pubs, roles int64
		q.DB().Raw(`SELECT count(*) FROM iga_publication WHERE workspace_id = ?`, q.WS).Row().Scan(&pubs)
		q.DB().Raw(`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = ? AND display_name = 'LateRole'`, q.WS).Row().Scan(&roles)
		if pubs != before || roles != 0 {
			t.Fatalf("snapshot saw the later publication: publications %d -> %d, LateRole rows %d", before, pubs, roles)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var roles int64
	l.db.Raw(`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = ? AND display_name = 'LateRole'`, l.ws).Row().Scan(&roles)
	if roles != 1 {
		t.Fatalf("after the read, LateRole rows = %d, want 1 (the publication did commit)", roles)
	}
}

// Cursors: a tampered, foreign-workspace, other-route, other-filter or
// other-sort cursor is 400 cursor_invalid; the genuine one opens.
func TestP2ReadCursorBinding(t *testing.T) {
	r := igaread.NewReader(nil, []byte("secret"))
	ws := uuid.New()
	vals := url.Values{"account": {"220171243705"}, "q": {"tools"}}
	ctx := igaread.CursorContext{WS: ws, Route: "workloads", Filter: igaread.FilterHash(vals), Sort: "name"}
	tok := r.SignCursor(igaread.Cursor{WS: ws, Rev: 7, Route: "workloads", Filter: ctx.Filter, Sort: "name", ID: uuid.New()})

	if c, err := r.OpenCursor(tok, ctx); err != nil || c.Rev != 7 {
		t.Fatalf("genuine cursor: %v %v", c, err)
	}
	reordered := url.Values{"q": {"tools"}, "account": {"220171243705"}, "limit": {"5"}}
	if igaread.FilterHash(reordered) != ctx.Filter {
		t.Fatal("the filter hash depends on parameter order or on limit")
	}
	body, sig, _ := strings.Cut(tok, ".")
	tampered := body[:len(body)-2] + "AA." + sig
	cases := map[string]struct {
		tok string
		ctx igaread.CursorContext
	}{
		"tampered":  {tampered, ctx},
		"workspace": {tok, igaread.CursorContext{WS: uuid.New(), Route: ctx.Route, Filter: ctx.Filter, Sort: ctx.Sort}},
		"route":     {tok, igaread.CursorContext{WS: ws, Route: "identities", Filter: ctx.Filter, Sort: ctx.Sort}},
		"filter":    {tok, igaread.CursorContext{WS: ws, Route: ctx.Route, Filter: igaread.FilterHash(url.Values{"q": {"other"}}), Sort: ctx.Sort}},
		"sort":      {tok, igaread.CursorContext{WS: ws, Route: ctx.Route, Filter: ctx.Filter, Sort: "-name"}},
		"garbage":   {"not-a-cursor", ctx},
	}
	for name, tc := range cases {
		if _, err := r.OpenCursor(tc.tok, tc.ctx); err == nil || err.Status != 400 || err.Code != "cursor_invalid" {
			t.Errorf("%s cursor = %v, want 400 cursor_invalid", name, err)
		}
	}
	other := igaread.NewReader(nil, []byte("another-secret"))
	if _, err := other.OpenCursor(tok, ctx); err == nil || err.Code != "cursor_invalid" {
		t.Errorf("a cursor signed with another key = %v, want cursor_invalid", err)
	}
}

// T6.9: with the switch off or misconfigured every graph read is 503
// graph_unavailable with the reason -- never an empty 200 the console would
// render as "nothing here". /capabilities still answers.
func TestP2ReadGraphUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name string
		gate *services.GraphProjectionGate
		mode string
	}{
		{"off", services.NewGraphProjectionGate(false, ""), services.GraphProjectionOff},
		{"misconfigured", services.NewGraphProjectionGate(true, ""), services.GraphProjectionMisconfigured},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := newP2Lab(t, "p2-read-503-"+tc.name, false)
			l.gate = tc.gate
			api := l.api()
			code, body := api.get("/workloads")
			mustStatus(t, "GET /workloads", code, body, 503)
			if errCode(body) != "graph_unavailable" || digs(body, "error", "graph_projection") != tc.mode {
				t.Fatalf("503 body = %v, want graph_unavailable / %s", body, tc.mode)
			}
			if code, body := api.get("/capabilities"); code != 200 || digs(body, "data", "graph_projection") != tc.mode {
				t.Fatalf("/capabilities = %d %v", code, body)
			}
		})
	}
}
