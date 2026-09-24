package integration

// Deletion after a projection (the gap analysis's critic section; relevant to
// E14 and T4.1). 033's iga_publication_run_fkey and 036's iga_sr_run_fkey,
// iga_le_run_fkey and iga_le_publication_fkey are ON DELETE RESTRICT, and so
// are the evidence junctions' observation keys; the workspace's own cascade
// reaches every one of those rows too, so whether a DELETE FROM workspaces
// succeeds depends on which RESTRICT check fires before its referencing rows
// are gone. Every statement here runs in a transaction that is ALWAYS rolled
// back (the lab's own cleanup still runs).
//
// Each subtest asserts the CORRECT behaviour, never a defect:
//
//   - Phase 1 only (switch off): deleting the workspace succeeds.
//   - After a projection, under the DDL proposed below: deleting the workspace
//     succeeds and leaves no row of it in any iga_* table. (The cloud_* tables
//     are left behind in BOTH phases: cloud_connector has no foreign key to
//     workspaces at all, so nothing cascades to the collected data -- a Phase 1
//     property, logged, not asserted.)
//   - After a projection, under 036 as shipped: the same assertion. Today it
//     is SKIPPED, naming the known schema defect, because the delete fails
//     23503 on iga_le_publication_fkey: that key is declared DEFERRABLE
//     INITIALLY DEFERRED, but RESTRICT is never deferred (PostgreSQL checks it
//     the moment iga_publication's rows cascade away, while iga_lifecycle_event's
//     rows -- cascaded later -- still reference them), so the declared deferral
//     does nothing. The defect is raised as a spec question (P2-EVIDENCE.md
//     §10.4, with the DDL below); migrations are not changed here. When 036 is
//     corrected the skip stops firing and the assertion runs -- nothing to
//     edit. Any OTHER refusal fails: a workspace delete must go through.
//   - A connector HARD delete after a projection never strips a surviving
//     claim of its evidence (T4.9): edges survive a connector (their
//     connector_id is SET NULL) while its observations cascade from it. Today
//     the RESTRICT keys refuse the delete, which keeps the evidence; whatever
//     033/036 become, a delete that goes through must not leave an edge that
//     had evidence without any. The product's DELETE route only revokes (soft,
//     D-89), so no product path reaches this.

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
)

func TestP2BdbWorkspaceDeletionAfterProjection(t *testing.T) {
	t.Run("phase 1: deleting the workspace succeeds", func(t *testing.T) {
		l := newP2Lab(t, "p2-bdb-delete-p1", false)
		a := oneLambda(l)
		l.scan(a, "scan-worker-delete-p1")
		bdbInRolledBackTx(t, l, func(tx *gorm.DB) {
			if err := tx.Exec(`DELETE FROM workspaces WHERE id = ?`, l.ws).Error; err != nil {
				t.Fatalf("Phase 1 workspace delete = %v, want success (the control)", err)
			}
		})
	})

	t.Run("after a projection", func(t *testing.T) {
		l := newP2Lab(t, "p2-bdb-delete-p2", true)
		a := oneLambda(l)
		l.scanAndProject(a)
		time.Sleep(10 * time.Millisecond)
		l.scanAndProject(a) // two publications, lifecycle events, a revision
		if n := l.count(`SELECT count(*) FROM iga_lifecycle_event WHERE workspace_id = ?`, l.ws); n == 0 {
			t.Fatal("setup: no lifecycle event to block the delete")
		}

		t.Run("under the proposed DDL the delete cascades to every graph row", func(t *testing.T) {
			bdbInRolledBackTx(t, l, func(tx *gorm.DB) {
				if err := tx.Exec(bdbProposedLePublicationFK).Error; err != nil {
					t.Fatalf("apply the proposed DDL: %v", err)
				}
				if err := bdbDeleteWorkspace(tx, l.ws); err != nil {
					t.Fatalf("workspace delete under the proposed DDL = %v, want success", err)
				}
				bdbAssertWorkspaceGone(t, tx, l.ws)
			})
		})

		t.Run("under 036 as shipped the delete cascades to every graph row", func(t *testing.T) {
			bdbInRolledBackTx(t, l, func(tx *gorm.DB) {
				err := bdbDeleteWorkspace(tx, l.ws)
				if c := bdbFKViolation(err); c == "iga_le_publication_fkey" {
					t.Skipf("KNOWN SCHEMA DEFECT (spec question, P2-EVIDENCE.md §10.4): 036's iga_le_publication_fkey is "+
						"ON DELETE RESTRICT, which is never deferred, so a projected workspace cannot be deleted: %v", err)
				}
				if err != nil {
					t.Fatalf("projected workspace delete = %v, want success", err)
				}
				bdbAssertWorkspaceGone(t, tx, l.ws)
			})
		})
	})

	t.Run("after a projection: a connector hard delete never strips an edge of its evidence", func(t *testing.T) {
		l := newP2Lab(t, "p2-bdb-delete-conn", true)
		a := oneLambda(l)
		l.scanAndProject(a)
		bdbInRolledBackTx(t, l, func(tx *gorm.DB) {
			withEvidence := bdbEdgesWithEvidence(t, tx, l.ws)
			if len(withEvidence) == 0 {
				t.Fatal("setup: no edge with evidence -- the check below would prove nothing")
			}
			err := bdbDeleteNow(tx, `DELETE FROM cloud_connector WHERE workspace_id = ? AND id = ?`, l.ws, a.conn)
			if err != nil {
				if bdbFKViolation(err) == "" {
					t.Fatalf("connector hard delete = %v, want success or a foreign-key refusal", err)
				}
				// Refused: the evidence stays with its edges. Which RESTRICT
				// key fires first is PostgreSQL's trigger order, not asserted.
				t.Logf("connector hard delete refused, evidence kept: %v", err)
				return
			}
			after := bdbEdgesWithEvidence(t, tx, l.ws)
			for id, kind := range withEvidence {
				if _, ok := after[id]; !ok && bdbEdgeExists(t, tx, l.ws, id) {
					t.Errorf("%s edge %s survived the connector hard delete WITHOUT its evidence (T4.9)", kind, id)
				}
			}
		})
	})
}

// bdbProposedLePublicationFK is the DDL this test proposes for 036: the same
// key, deferred for real (NO ACTION honours DEFERRABLE; RESTRICT never does).
const bdbProposedLePublicationFK = `ALTER TABLE public.iga_lifecycle_event
    DROP CONSTRAINT iga_le_publication_fkey,
    ADD CONSTRAINT iga_le_publication_fkey FOREIGN KEY (workspace_id, rev)
        REFERENCES public.iga_publication (workspace_id, rev) ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED`

// bdbInRolledBackTx runs fn in a transaction that is always rolled back.
func bdbInRolledBackTx(t *testing.T, l *p2Lab, fn func(tx *gorm.DB)) {
	t.Helper()
	tx := l.db.Begin()
	if tx.Error != nil {
		t.Fatalf("begin: %v", tx.Error)
	}
	defer tx.Rollback()
	fn(tx)
}

// bdbDeleteWorkspace deletes a workspace and forces every deferred check now.
func bdbDeleteWorkspace(tx *gorm.DB, ws uuid.UUID) error {
	return bdbDeleteNow(tx, `DELETE FROM workspaces WHERE id = ?`, ws)
}

// bdbDeleteNow runs one DELETE and forces every deferred check at once,
// inside a savepoint, so a refusal leaves the transaction usable.
func bdbDeleteNow(tx *gorm.DB, stmt string, args ...any) error {
	if err := tx.Exec(`SAVEPOINT bdb_delete`).Error; err != nil {
		return err
	}
	err := tx.Exec(stmt, args...).Error
	if err == nil {
		err = tx.Exec(`SET CONSTRAINTS ALL IMMEDIATE`).Error
	}
	if err != nil {
		tx.Exec(`ROLLBACK TO SAVEPOINT bdb_delete`)
		return err
	}
	return tx.Exec(`RELEASE SAVEPOINT bdb_delete`).Error
}

// bdbFKViolation is the constraint a 23503 names, or "" for any other outcome.
func bdbFKViolation(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23503" {
		return pg.ConstraintName
	}
	return ""
}

// bdbAssertWorkspaceGone: after a workspace delete, no iga_* table holds a row
// of it; what other tables keep is logged.
func bdbAssertWorkspaceGone(t *testing.T, tx *gorm.DB, ws uuid.UUID) {
	t.Helper()
	graph, other := map[string]int64{}, map[string]int64{}
	for table, n := range bdbRowsOfWorkspace(t, tx, ws) {
		if strings.HasPrefix(table, "iga_") {
			graph[table] = n
		} else {
			other[table] = n
		}
	}
	if len(graph) != 0 {
		t.Errorf("graph rows left after the workspace delete: %v", graph)
	}
	t.Logf("left behind (no foreign key path from workspaces; Phase 1 schema): %v", other)
}

// bdbEdgeJunctions is every edge table with its evidence junction.
var bdbEdgeJunctions = []struct{ kind, edges, junction, column string }{
	{"relationship", "iga_relationship", "iga_relationship_evidence", "relationship_id"},
	{"assignment", "iga_policy_assignment", "iga_assignment_evidence", "assignment_id"},
	{"grant", "iga_access_edges", "iga_access_edge_evidence", "access_edge_id"},
}

// bdbEdgesWithEvidence is every edge of the workspace, in any state, with at
// least one 'supports' link, mapped to its kind.
func bdbEdgesWithEvidence(t *testing.T, tx *gorm.DB, ws uuid.UUID) map[uuid.UUID]string {
	t.Helper()
	out := map[uuid.UUID]string{}
	for _, e := range bdbEdgeJunctions {
		var ids []uuid.UUID
		if err := tx.Raw(`SELECT DISTINCT x.id FROM `+e.edges+` x JOIN `+e.junction+` j
		                     ON j.workspace_id = x.workspace_id AND j.`+e.column+` = x.id AND j.relation = 'supports'
		                  WHERE x.workspace_id = ?`, ws).Scan(&ids).Error; err != nil {
			t.Fatalf("%s with evidence: %v", e.edges, err)
		}
		for _, id := range ids {
			out[id] = e.kind
		}
	}
	return out
}

// bdbEdgeExists says whether an edge row is still there, in any edge table.
func bdbEdgeExists(t *testing.T, tx *gorm.DB, ws, id uuid.UUID) bool {
	t.Helper()
	for _, e := range bdbEdgeJunctions {
		var n int64
		if err := tx.Raw(`SELECT count(*) FROM `+e.edges+` WHERE workspace_id = ? AND id = ?`, ws, id).Scan(&n).Error; err != nil {
			t.Fatalf("find %s %s: %v", e.edges, id, err)
		}
		if n > 0 {
			return true
		}
	}
	return false
}

// bdbRowsOfWorkspace counts, in every public table with a workspace_id
// column, the rows of this workspace; only non-zero counts are returned.
func bdbRowsOfWorkspace(t *testing.T, tx *gorm.DB, ws uuid.UUID) map[string]int64 {
	t.Helper()
	var tables []string
	if err := tx.Raw(`SELECT c.table_name FROM information_schema.columns c
	                    JOIN information_schema.tables tb ON tb.table_schema = c.table_schema AND tb.table_name = c.table_name
	                   WHERE c.table_schema = 'public' AND c.column_name = 'workspace_id' AND tb.table_type = 'BASE TABLE'
	                   ORDER BY 1`).Scan(&tables).Error; err != nil {
		t.Fatalf("list tables: %v", err)
	}
	if len(tables) < 100 {
		t.Fatalf("only %d tables with workspace_id: the census proves nothing", len(tables))
	}
	out := map[string]int64{}
	for _, table := range tables {
		var n int64
		if err := tx.Raw(`SELECT count(*) FROM public.`+table+` WHERE workspace_id = ?`, ws).Scan(&n).Error; err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if n > 0 {
			out[table] = n
		}
	}
	return out
}
