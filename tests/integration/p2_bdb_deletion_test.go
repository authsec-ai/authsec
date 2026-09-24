package integration

// Workspace deletion after a projection (the gap analysis's critic section;
// relevant to E14 and T4.1). 033's iga_publication_run_fkey and 036's
// iga_sr_run_fkey, iga_le_run_fkey and iga_le_publication_fkey are ON DELETE
// RESTRICT, and so are the evidence junctions' observation keys; the
// workspace's own cascade reaches every one of those rows too, so whether a
// DELETE FROM workspaces succeeds depends on which RESTRICT check fires before
// its referencing rows are gone.
//
// Measured here, against the real 036 schema, every statement in a
// transaction that is ALWAYS rolled back (the lab's own cleanup still runs):
//
//   - Phase 1 only (switch off): deleting the workspace succeeds.
//   - After a projection: it FAILS, 23503 on iga_le_publication_fkey. That key
//     is declared DEFERRABLE INITIALLY DEFERRED, but RESTRICT is never deferred
//     (PostgreSQL checks it the moment iga_publication's rows cascade away,
//     while iga_lifecycle_event's rows -- cascaded later -- still reference
//     them), so the declared deferral does nothing.
//   - With that one key re-declared ON DELETE NO ACTION DEFERRABLE INITIALLY
//     DEFERRED (the check waits for the end of the transaction, by which time
//     the workspace cascade has removed the events), the deletion succeeds and
//     leaves no row of the workspace in any iga_* table. (The cloud_* tables
//     are left behind in BOTH phases: cloud_connector has no foreign key to
//     workspaces at all, so nothing cascades to the collected data -- a Phase 1
//     property, logged here and reported, not asserted.)
//   - A connector HARD delete after a projection fails too (23503 on an
//     evidence junction's observation key): its observations cascade from the
//     connector, while the edges that cite them survive it (their connector_id
//     is SET NULL). The product's DELETE route only revokes (soft), so this is
//     reported, not proposed.
//
// THIS TEST RECORDS A SCHEMA DEFECT (reported as a spec question; migrations
// are not changed here). When 036 is corrected, the "blocked today" assertion
// below fails: delete it, and the proof half already asserts the corrected
// behaviour.

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

		// Blocked today.
		bdbInRolledBackTx(t, l, func(tx *gorm.DB) {
			err := bdbDeleteWorkspace(tx, l.ws)
			if c := bdbFKViolation(err); c != "iga_le_publication_fkey" {
				t.Errorf("projected workspace delete = %v; want it refused by iga_le_publication_fkey (the recorded defect -- "+
					"if 036 was corrected, remove this assertion)", err)
			}
		})

		// The proposed DDL, applied inside the rolled-back transaction: the
		// delete succeeds and cascades to every row of the workspace.
		bdbInRolledBackTx(t, l, func(tx *gorm.DB) {
			if err := tx.Exec(bdbProposedLePublicationFK).Error; err != nil {
				t.Fatalf("apply the proposed DDL: %v", err)
			}
			if err := bdbDeleteWorkspace(tx, l.ws); err != nil {
				t.Fatalf("workspace delete under the proposed DDL = %v, want success", err)
			}
			graph, other := map[string]int64{}, map[string]int64{}
			for table, n := range bdbRowsOfWorkspace(t, tx, l.ws) {
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
		})
	})

	t.Run("after a projection: a connector hard delete is refused", func(t *testing.T) {
		l := newP2Lab(t, "p2-bdb-delete-conn", true)
		a := oneLambda(l)
		l.scanAndProject(a)
		bdbInRolledBackTx(t, l, func(tx *gorm.DB) {
			err := tx.Exec(`DELETE FROM cloud_connector WHERE workspace_id = ? AND id = ?`, l.ws, a.conn).Error
			switch c := bdbFKViolation(err); c {
			case "iga_access_edge_evidence_obs_fkey", "iga_relationship_evidence_obs_fkey", "iga_ae_obs_fkey":
			default:
				t.Errorf("connector hard delete = %v; want it refused by an evidence junction's observation key", err)
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

// bdbDeleteWorkspace deletes a workspace and forces every deferred check now,
// inside a savepoint, so a refusal leaves the transaction usable.
func bdbDeleteWorkspace(tx *gorm.DB, ws uuid.UUID) error {
	if err := tx.Exec(`SAVEPOINT bdb_delete`).Error; err != nil {
		return err
	}
	err := tx.Exec(`DELETE FROM workspaces WHERE id = ?`, ws).Error
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
