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
