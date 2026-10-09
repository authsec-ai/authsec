package integration

// P2-0 (SPEC-iga-phase2-graph.md §6.3): one Lambda -> its role -> one attached
// managed policy -> its statements -> grants -> resource references, through
// the REAL worker and projector with the switch on. One test per scenario row;
// each names the safeguard whose removal must make it fail (recorded in
// .claude/specs/P2-EVIDENCE.md).

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

const (
	docTicketRead = `{"Version":"2012-10-17","Statement":[{"Sid":"ReadTickets","Effect":"Allow",` +
		`"Action":"s3:GetObject","Resource":"arn:aws:s3:::support-tickets/*"}]}`
	docToolboxRead = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Action":"s3:GetObject","Resource":"arn:aws:s3:::support-tickets/*"}]}`
)

// shape is every graph id and first_seen_at, for "an unchanged rescan changes
// nothing".
type shapeRow struct {
	Kind      string
	ID        uuid.UUID
	FirstSeen *time.Time
}

func (l *p2Lab) shape() map[uuid.UUID]shapeRow {
	var rows []shapeRow
	l.db.Raw(`
		SELECT 'identity' AS kind, id, first_seen_at AS first_seen FROM iga_identity_accounts WHERE workspace_id = ? AND provider = 'aws'
		UNION ALL SELECT 'workload', id, first_seen_at FROM iga_workload WHERE workspace_id = ?
		UNION ALL SELECT 'policy', id, first_seen_at FROM iga_policy WHERE workspace_id = ?
		UNION ALL SELECT 'statement', id, first_seen_at FROM iga_entitlements WHERE workspace_id = ? AND provider = 'aws'
		UNION ALL SELECT 'resource', id, first_seen_at FROM iga_resources WHERE workspace_id = ? AND provider = 'aws'
		UNION ALL SELECT 'assignment', id, valid_from FROM iga_policy_assignment WHERE workspace_id = ?
		UNION ALL SELECT 'grant', id, valid_from FROM iga_access_edges WHERE workspace_id = ? AND provider = 'aws'
		UNION ALL SELECT 'relationship', id, valid_from FROM iga_relationship WHERE workspace_id = ?
		UNION ALL SELECT 'external_principal', id, first_seen_at FROM iga_external_principal WHERE workspace_id = ?`,
		l.ws, l.ws, l.ws, l.ws, l.ws, l.ws, l.ws, l.ws, l.ws).Scan(&rows)
	out := make(map[uuid.UUID]shapeRow, len(rows))
	for _, r := range rows {
		out[r.ID] = r
	}
	return out
}

// oneLambda is the P2-0 slice: Lambda -> refund role -> TicketRead.
func oneLambda(l *p2Lab) *p2Account {
	a := l.account(accountA)
	role := a.role("refund-lambda-role", "AROA5XK7QEXAMPLE")
	a.attach("refund-lambda-role", a.managed("TicketRead", docTicketRead))
	a.lambda("us-east-1", "refund-processor", role)
	return a
}

// Scenario 1. Unchanged rescan: ids and first_seen_at stable, no duplicate
// rows, no new revision. And T4.9: zero projected edges without evidence.
func TestP2UnchangedRescan(t *testing.T) {
	l := newP2Lab(t, "p2-unchanged", true)
	a := oneLambda(l)
	l.scanAndProject(a)

	before := l.shape()
	revisions := l.count(`SELECT count(*) FROM iga_statement_revision WHERE workspace_id = ?`, l.ws)
	events := l.count(`SELECT count(*) FROM iga_lifecycle_event WHERE workspace_id = ?`, l.ws)
	var lastSeen1 time.Time
	l.db.Raw(`SELECT last_seen_at FROM iga_identity_accounts WHERE workspace_id = ? AND provider='aws'`, l.ws).Scan(&lastSeen1)
	if len(before) == 0 || revisions != 1 {
		t.Fatalf("setup: %d graph rows, %d revisions; want a projected slice with one revision", len(before), revisions)
	}
	// Two relationships since T4.7 (§4.12's table): executes_as, and the
	// role's trust document's can_assume from the external principal
	// aws_service lambda.amazonaws.com -- which must be as stable as the rest.
	for kind, want := range map[string]int{"identity": 1, "workload": 1, "policy": 1, "statement": 1,
		"resource": 1, "assignment": 1, "grant": 1, "relationship": 2, "external_principal": 1} {
		got := 0
		for _, r := range before {
			if r.Kind == kind {
				got++
			}
		}
		if got != want {
			t.Errorf("%s rows = %d, want %d", kind, got, want)
		}
	}

	time.Sleep(10 * time.Millisecond)
	l.scanAndProject(a)

	after := l.shape()
	if len(after) != len(before) {
		t.Fatalf("row count %d -> %d: a rescan of an unchanged account duplicated rows", len(before), len(after))
	}
	for id, b := range before {
		got, ok := after[id]
		if !ok {
			t.Errorf("%s %s disappeared on an unchanged rescan", b.Kind, id)
			continue
		}
		if b.FirstSeen != nil && got.FirstSeen != nil && !got.FirstSeen.Equal(*b.FirstSeen) {
			t.Errorf("%s %s first_seen moved %s -> %s", b.Kind, id, b.FirstSeen, got.FirstSeen)
		}
	}
	if n := l.count(`SELECT count(*) FROM iga_statement_revision WHERE workspace_id = ?`, l.ws); n != revisions {
		t.Errorf("revisions %d -> %d: an unchanged statement gained a revision", revisions, n)
	}
	if n := l.count(`SELECT count(*) FROM iga_lifecycle_event WHERE workspace_id = ?`, l.ws); n != events {
		t.Errorf("lifecycle events %d -> %d on an unchanged rescan", events, n)
	}
	var lastSeen2 time.Time
	l.db.Raw(`SELECT last_seen_at FROM iga_identity_accounts WHERE workspace_id = ? AND provider='aws'`, l.ws).Scan(&lastSeen2)
	if !lastSeen2.After(lastSeen1) {
		t.Error("last_seen_at did not advance: the rescan did not actually re-confirm")
	}
	if n := l.count(`SELECT count(*) FROM iga_publication WHERE workspace_id = ?`, l.ws); n != 2 {
		t.Errorf("%d publications, want 2 (one per run)", n)
	}

	// T4.9: every projected edge has evidence, counted PER EDGE.
	for what, q := range map[string]string{
		"grant": `SELECT count(*) FROM iga_access_edges g WHERE g.workspace_id = ? AND g.provider = 'aws'
		          AND NOT EXISTS (SELECT 1 FROM iga_access_edge_evidence e WHERE e.access_edge_id = g.id)`,
		"assignment": `SELECT count(*) FROM iga_policy_assignment a WHERE a.workspace_id = ?
		          AND NOT EXISTS (SELECT 1 FROM iga_assignment_evidence e WHERE e.assignment_id = a.id)`,
		"relationship": `SELECT count(*) FROM iga_relationship r WHERE r.workspace_id = ?
		          AND NOT EXISTS (SELECT 1 FROM iga_relationship_evidence e WHERE e.relationship_id = r.id)`,
	} {
		if n := l.count(q, l.ws); n != 0 {
			t.Errorf("%d %s edges have no evidence (T4.9 requires zero)", n, what)
		}
	}
	_ = models.RelCurrent
}
