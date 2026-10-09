package integration

// B1 (SPEC-iga-phase2-graph.md §7.3; §7.1 E5): two workloads share one role.
// Through the REAL scan worker and projector.

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// B1: two Lambdas in ONE region run as ONE role. The graph has one identity
// and TWO executes_as edges -- one per workload -- and an unchanged rescan
// keeps both ids.
//
// Both Lambdas share the region, so both edges live in the SAME executes_as
// partition and point at the SAME target endpoint: only the source segment of
// the relationship key (§2.4, RelationshipKey) keeps them apart. A key missing
// it makes the second upsert land on the first edge's live row (the partial
// unique index uq_iga_relationship_live) and one workload silently loses its
// execution identity.
//
// Safeguard (mutation-checked): RelationshipKey names the source endpoint.
func TestP2BdbTwoWorkloadsShareOneRole(t *testing.T) {
	l := newP2Lab(t, "p2-bdb-b1", true)
	a := l.account(accountA)
	role := a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	a.attach("SharedToolRole", a.managed("TicketRead", docTicketRead))
	listsFunctions(a, "us-east-1", "ticket-tools", role, "refund-tools", role)
	l.scanAndProject(a)

	if n := l.count(`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = ? AND provider = 'aws'
	                  AND account_kind = 'iam_role' AND display_name = 'SharedToolRole'`, l.ws); n != 1 {
		t.Fatalf("SharedToolRole identities = %d, want ONE (the role shown twice?)", n)
	}
	roleID := bdbIdentity(t, l, "SharedToolRole")

	type edge struct {
		ID        uuid.UUID
		Workload  string
		Source    uuid.UUID
		Target    uuid.UUID
		State     string
		SourceKey string
	}
	read := func() map[string]edge {
		var rows []edge
		l.db.Raw(`SELECT r.id, w.display_name AS workload, r.source_workload_id AS source,
		                 r.target_identity_account_id AS target, r.state, r.source_key
		            FROM iga_relationship r JOIN iga_workload w ON w.workspace_id = r.workspace_id AND w.id = r.source_workload_id
		           WHERE r.workspace_id = ? AND r.relationship_type = 'executes_as'`, l.ws).Scan(&rows)
		out := map[string]edge{}
		for _, r := range rows {
			if _, dup := out[r.Workload]; dup {
				t.Fatalf("two executes_as rows for %s: %+v", r.Workload, rows)
			}
			out[r.Workload] = r
		}
		if len(rows) != 2 {
			t.Fatalf("executes_as rows = %d, want TWO, one per workload: %+v", len(rows), rows)
		}
		return out
	}
	first := read()
	tt, rt := first["ticket-tools"], first["refund-tools"]
	if tt.ID == uuid.Nil || rt.ID == uuid.Nil {
		t.Fatalf("executes_as by workload = %+v, want ticket-tools and refund-tools", first)
	}
	if tt.ID == rt.ID || tt.Source == rt.Source || tt.SourceKey == rt.SourceKey {
		t.Errorf("the two edges share an id, a source or a key: %+v / %+v", tt, rt)
	}
	for _, e := range []edge{tt, rt} {
		if e.Target != roleID || e.State != models.RelCurrent {
			t.Errorf("%s executes_as = %+v, want current, to SharedToolRole %s", e.Workload, e, roleID)
		}
	}

	// An unchanged rescan confirms both in place: same ids, both current.
	time.Sleep(10 * time.Millisecond)
	l.scanAndProject(a)
	again := read()
	for name, before := range first {
		after := again[name]
		if after.ID != before.ID || after.State != models.RelCurrent {
			t.Errorf("%s after an unchanged rescan = %+v, want the same edge %s, current", name, after, before.ID)
		}
	}
	if n := l.count(`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = ? AND provider = 'aws'
	                  AND display_name = 'SharedToolRole'`, l.ws); n != 1 {
		t.Errorf("SharedToolRole identities after the rescan = %d, want 1", n)
	}
}
