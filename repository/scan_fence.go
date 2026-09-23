package repositories

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ErrScanFenceLost means an inventory write was attempted by a worker that no
// longer owns its scan run -- it was superseded, and its writes must not land.
var ErrScanFenceLost = errors.New("scan fence lost: run reclaimed by another worker")

// ScanFence identifies the run a set of inventory writes belongs to.
//
// SPEC-iga-phase2-graph.md §2.10A, part 3. The pipeline barrier stops a NEW
// scan from starting while a projection is pending, and cancelling a
// superseded scanner's context stops its work promptly -- but NEITHER
// establishes that a superseded worker has actually stopped writing. Its
// context.Context is not threaded through every collector, and even a
// context-aware write can already be in flight when cancellation is observed.
//
// So the fence is the correctness half: every inventory mutation validates, IN
// THE SAME TRANSACTION AS THE WRITE, that this worker still owns the run --
// against the very row cloud_scan_run.Claim bumps when it reclaims. Cancellation
// for promptness, the fence for correctness; neither substitutes for the other.
type ScanFence struct {
	RunID        uuid.UUID
	Owner        string
	LeaseVersion int64
}

// assertScanFence refuses the caller unless the run still carries its owner and
// lease version.
//
// FOR SHARE is load-bearing, not decoration. Claim reclaims a run with
// FOR UPDATE SKIP LOCKED and then bumps lease_version; a plain SELECT here could
// read the old version, pass, and let the write land in the gap before the
// reclaim commits. FOR SHARE serializes the two:
//
//   - if this check locks the row first, the reclaim's FOR UPDATE waits, and
//     this write commits under the ownership it verified;
//   - if the reclaim commits first, this check reads the NEW version, fails,
//     and the write is refused.
func assertScanFence(tx *gorm.DB, f ScanFence) error {
	var one int
	row := tx.Raw(
		`SELECT 1 FROM cloud_scan_run
		  WHERE id = ? AND lease_owner = ? AND lease_version = ?
		  FOR SHARE`,
		f.RunID, f.Owner, f.LeaseVersion,
	).Row()
	if err := row.Scan(&one); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: run=%s owner=%s version=%d",
				ErrScanFenceLost, f.RunID, f.Owner, f.LeaseVersion)
		}
		return err
	}
	return nil
}

// runFenced runs fn against db when no fence is set, and otherwise inside one
// transaction that first asserts the fence.
//
// One helper, used by every fenced mutation, so the "check ownership in the
// same transaction as the write" rule cannot be applied inconsistently.
func runFenced(db *gorm.DB, fence *ScanFence, fn func(tx *gorm.DB) error) error {
	if fence == nil {
		return fn(db)
	}
	return db.Transaction(func(tx *gorm.DB) error {
		if err := assertScanFence(tx, *fence); err != nil {
			return err
		}
		return fn(tx)
	})
}

// runFencedTx is runFenced for a mutation that must be atomic on its own --
// the multi-table deletes of ReconcileGeneration. It ALWAYS opens a
// transaction, and asserts the fence inside it when one is set.
//
// Deletes are fenced exactly like upserts (§2.10A). Without it a superseded
// worker could still reach its reconcile step and delete rows the CURRENT
// owner had just written at the same generation.
func runFencedTx(db *gorm.DB, fence *ScanFence, fn func(tx *gorm.DB) error) error {
	return db.Transaction(func(tx *gorm.DB) error {
		if fence != nil {
			if err := assertScanFence(tx, *fence); err != nil {
				return err
			}
		}
		return fn(tx)
	})
}

// MigrationHead reports the highest successfully-applied master migration, or
// 0 when that cannot be determined.
//
// Read from migration_logs rather than from the files on disk: what matters is
// what the DATABASE has, not what the binary shipped with. A MISSING
// migration_logs is not an error -- a database migrated by psql rather than by
// the runner has no such table, and treating that as a failure would conflate
// "cannot tell" with "too old". Callers pair this with HasRelation, which is
// the ground truth.
func MigrationHead(db *gorm.DB) (int, error) {
	var exists bool
	if err := db.Raw(`SELECT to_regclass('public.migration_logs') IS NOT NULL`).
		Scan(&exists).Error; err != nil {
		return 0, err
	}
	if !exists {
		return 0, nil
	}
	var head *int
	if err := db.Raw(
		`SELECT max(version) FROM migration_logs WHERE db_type = 'master' AND success = true`,
	).Scan(&head).Error; err != nil {
		return 0, err
	}
	if head == nil {
		return 0, nil
	}
	return *head, nil
}

// HasRelation reports whether a table or view exists in the public schema.
//
// This is the GROUND TRUTH for a schema precondition: a bookkeeping table can
// be absent, stale, or written by a different tool, but the relation the code
// is about to query either exists or does not.
func HasRelation(db *gorm.DB, name string) (bool, error) {
	var exists bool
	err := db.Raw(`SELECT to_regclass(?) IS NOT NULL`, "public."+name).Scan(&exists).Error
	return exists, err
}

// HasColumn reports whether public.<table> has <column>. The partner of
// HasRelation, for checks that a migration applied COMPLETELY -- an applied
// but incomplete migration is invisible to a relation check (§9).
func HasColumn(db *gorm.DB, table, column string) (bool, error) {
	var n int64
	err := db.Raw(`SELECT count(*) FROM information_schema.columns
	               WHERE table_schema = 'public' AND table_name = ? AND column_name = ?`,
		table, column).Scan(&n).Error
	return n > 0, err
}
