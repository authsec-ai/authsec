package integration

// Helpers for the Changes suites (T5.4, §5.3 Changes): read a route through
// the real route table, follow its cursors, pick events, and check each
// event's revision against the publication of its run (D-26).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// changesPath is an object's Changes route.
func changesPath(refType string, id uuid.UUID, kv ...string) string {
	seg := map[string]string{"workload": "workloads", "identity": "identities", "resource": "resources"}[refType]
	return "/" + seg + "/" + id.String() + "/changes" + qs(kv...)
}

// changesGet calls a Changes route and requires 200.
func changesGet(t *testing.T, api *readAPI, path string) map[string]any {
	t.Helper()
	code, body := api.get(path)
	mustStatus(t, "GET "+path, code, body, http.StatusOK)
	return body
}

// changesAll reads every page of an object's Changes (limit 200), following
// next_cursor, and returns the events in order.
func changesAll(t *testing.T, api *readAPI, refType string, id uuid.UUID, kind string) []map[string]any {
	t.Helper()
	var out []map[string]any
	cursor := ""
	for page := 0; page < 50; page++ {
		kv := []string{"kind", kind, "limit", "200"}
		if cursor != "" {
			kv = append(kv, "cursor", cursor)
		}
		body := changesGet(t, api, changesPath(refType, id, kv...))
		for _, e := range digl(body, "data") {
			out = append(out, e.(map[string]any))
		}
		cursor = digs(body, "meta", "next_cursor")
		if cursor == "" {
			return out
		}
	}
	t.Fatalf("Changes of %s %s did not end within 50 pages", refType, id)
	return nil
}

// changesPick returns the events of one type whose field (a detail key, or
// "subject") equals want; want "" matches any.
func changesPick(events []map[string]any, event, field, want string) []map[string]any {
	var out []map[string]any
	for _, e := range events {
		if digs(e, "event") != event {
			continue
		}
		if want != "" {
			got := digs(e, "subject")
			if field != "subject" {
				got = digs(e, "detail", field)
			}
			if got != want {
				continue
			}
		}
		out = append(out, e)
	}
	return out
}

// changesOne requires exactly one matching event.
func changesOne(t *testing.T, events []map[string]any, event, field, want string) map[string]any {
	t.Helper()
	got := changesPick(events, event, field, want)
	if len(got) != 1 {
		t.Fatalf("%s with %s=%s: %d events, want 1; all events: %s", event, field, want, len(got), changesDump(events))
	}
	return got[0]
}

// changesDump renders events compactly for failure messages.
func changesDump(events []map[string]any) string {
	var b strings.Builder
	for _, e := range events {
		b.WriteString("\n  ")
		b.WriteString(digs(e, "at"))
		b.WriteString(" ")
		b.WriteString(digs(e, "event"))
		b.WriteString(" ")
		b.WriteString(digs(e, "subject"))
		if r := digs(e, "reason"); r != "" {
			b.WriteString(" (" + r + ")")
		}
		if v := digs(e, "via"); v != "" {
			b.WriteString(" via " + v)
		}
	}
	return b.String()
}

// changesRunRev is the revision of the publication of a run.
func changesRunRev(t *testing.T, l *p2Lab, runID uuid.UUID) int64 {
	t.Helper()
	var rev int64
	if err := l.db.Raw(`SELECT rev FROM iga_publication WHERE workspace_id = ? AND scan_run_id = ?`,
		l.ws, runID).Row().Scan(&rev); err != nil {
		t.Fatalf("publication of run %s: %v", runID, err)
	}
	return rev
}

// changesAssertAttributed requires every event to name its revision and run,
// and the revision to be the one that published that run (D-26: a start or an
// end joins to its pass's publication exactly).
func changesAssertAttributed(t *testing.T, l *p2Lab, events []map[string]any) {
	t.Helper()
	pubs := map[string]int64{}
	var rows []struct {
		ScanRunID uuid.UUID
		Rev       int64
	}
	l.db.Raw(`SELECT scan_run_id, rev FROM iga_publication WHERE workspace_id = ?`, l.ws).Scan(&rows)
	for _, r := range rows {
		pubs[refOf("cloud_scan_run", r.ScanRunID)] = r.Rev
	}
	for _, e := range events {
		run, rev := digs(e, "run"), num(e, "rev")
		if run == "" || rev < 1 {
			raw, _ := json.Marshal(e)
			t.Errorf("event without its run or revision: %s", raw)
			continue
		}
		if want, ok := pubs[run]; !ok || want != rev {
			t.Errorf("%s %s: rev %d, but %s was published at rev %d (found %v)",
				digs(e, "event"), digs(e, "subject"), rev, run, want, ok)
		}
	}
}

// changesIDOf reads one id with a query, failing the test when there is none.
func changesIDOf(t *testing.T, l *p2Lab, q string, args ...any) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := l.db.Raw(q, args...).Row().Scan(&id); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return id
}

// changesIdentity is the live (else the newest) identity with a display name.
func changesIdentity(t *testing.T, l *p2Lab, name string) uuid.UUID {
	t.Helper()
	return changesIDOf(t, l, `SELECT id FROM iga_identity_accounts WHERE workspace_id = ? AND provider = 'aws'
	                           AND display_name = ? ORDER BY (lifecycle = 'active') DESC, first_seen_at DESC, id LIMIT 1`,
		l.ws, name)
}

// changesPolicy is the live (else the newest) policy with a display name.
func changesPolicy(t *testing.T, l *p2Lab, name string) uuid.UUID {
	t.Helper()
	return changesIDOf(t, l, `SELECT id FROM iga_policy WHERE workspace_id = ? AND provider = 'aws'
	                           AND display_name = ? ORDER BY (lifecycle = 'active') DESC, first_seen_at DESC, id LIMIT 1`,
		l.ws, name)
}

// changesManaged defines a customer-managed policy with its OWN PolicyId: the
// fake derives an unset one from the ARN's length and last byte, so two names
// of one length ending alike (ToolboxRead, ArchiveRead) would share a
// PolicyId -- one policy incarnation, one assignment -- which AWS never does.
func changesManaged(a *p2Account, name, doc string) string {
	arn := a.managed(name, doc)
	sum := sha256.Sum256([]byte(arn))
	a.iam.policyIDs[arn] = "ANPA" + strings.ToUpper(hex.EncodeToString(sum[:8]))
	return arn
}

// changesStrings reads a JSON array of strings.
func changesStrings(v any) []string {
	xs, _ := v.([]any)
	out := []string{}
	for _, x := range xs {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
