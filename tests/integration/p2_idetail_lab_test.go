package integration

// Shared plumbing for the identity and external-principal detail tests (T6.3,
// §5.3 Identities and External principals). Every fixture is built through
// the P2-0 lab -- the REAL scan worker and projector over the AWS fakes --
// and read back through the REAL route table (l.api()). Rows are inserted
// directly only for states the fakes cannot produce, and each such test says
// so. Everything here is prefixed idetail.

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// idetailSecondLab is another workspace over the SAME database, gate and run
// repository as l -- for E14's cross-workspace 404s. It does not call
// scanRuns again: that clears cloud_scan_run globally, which would take l's
// published runs with it.
func idetailSecondLab(t *testing.T, l *p2Lab, name string) *p2Lab {
	t.Helper()
	ws := newWorkspace(t, l.db, name)
	l2 := &p2Lab{t: t, db: l.db, ws: ws, gate: l.gate, runs: l.runs}
	t.Cleanup(l2.cleanup)
	return l2
}

// idetailGet calls a route and requires 200.
func idetailGet(t *testing.T, api *readAPI, path string) map[string]any {
	t.Helper()
	code, body := api.get(path)
	mustStatus(t, "GET "+path, code, body, 200)
	return body
}

// idetailIdentityID is the ACTIVE AWS identity with this name.
func idetailIdentityID(t *testing.T, l *p2Lab, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := l.db.Raw(`SELECT id FROM iga_identity_accounts
	                     WHERE workspace_id = ? AND provider = 'aws' AND display_name = ? AND lifecycle = 'active'`,
		l.ws, name).Row().Scan(&id); err != nil {
		t.Fatalf("identity %s: %v", name, err)
	}
	return id
}

// idetailExternalID is the external principal of this issuer and subject.
func idetailExternalID(t *testing.T, l *p2Lab, issuer, subject string) uuid.UUID {
	t.Helper()
	ep, ok := trustNode(l, issuer, subject)
	if !ok {
		t.Fatalf("no external principal %s / %s", issuer, subject)
	}
	return ep.ID
}

// idetailByRef finds the item whose dig(item, path...) equals want.
func idetailByRef(t *testing.T, items []any, want string, path ...any) map[string]any {
	t.Helper()
	for _, it := range items {
		if digs(it, path...) == want {
			return it.(map[string]any)
		}
	}
	raw, _ := json.Marshal(items)
	t.Fatalf("no item with %v = %q in %s", path, want, raw)
	return nil
}

// idetailPolicy finds a policy by name in a policies array.
func idetailPolicy(t *testing.T, policies []any, name string) map[string]any {
	t.Helper()
	return idetailByRef(t, policies, name, "name")
}

// idetailNames lists dig(item, path...) over items.
func idetailNames(items []any, path ...any) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, digs(it, path...))
	}
	return out
}

// idetailJSON renders a value for a failure message.
func idetailJSON(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}
