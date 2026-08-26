package services

import (
	"log"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// SoDScanWorker runs the detective half of separation of duties.
//
// The preventive check inside the provisioning transaction stops NEW conflicts. This
// catches the rest: conflicts that predate a rule, grants made through a path that
// does not call the check yet, and rules an admin has just written against access that
// already exists. Without it, adding a rule would only ever govern the future.
//
// Like the expiry worker, it can only ever REPORT — it never revokes. Remediation is a
// human decision (revoke, or accept with a documented reason), because auto-revoking on
// an SoD hit would let a mistyped rule take down production access.
type SoDScanWorker struct {
	db       *gorm.DB
	sod      SoDManager
	interval time.Duration
}

// NewSoDScanWorker constructs a SoDScanWorker.
func NewSoDScanWorker(db *gorm.DB, interval time.Duration) *SoDScanWorker {
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	return &SoDScanWorker{db: db, sod: NewSoDManager(db), interval: interval}
}

// Start launches the scan loop.
//
// Hours, not minutes: the preventive check already covers anything new, so this is
// catching up on history rather than watching a live stream. A full pass expands every
// subject's capabilities, which is the most expensive read in the governance plane.
func (w *SoDScanWorker) Start() {
	go func() {
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()
		for range ticker.C {
			w.RunOnce()
		}
	}()
}

// RunOnce scans every workspace. Exported so an operator can trigger a pass and so
// tests do not have to wait on a ticker.
func (w *SoDScanWorker) RunOnce() {
	var workspaceIDs []uuid.UUID
	if err := w.db.Table("workspaces").Pluck("id", &workspaceIDs).Error; err != nil {
		log.Printf("sod scan: could not enumerate workspaces: %v", err)
		return
	}
	for _, ws := range workspaceIDs {
		res, err := w.sod.Scan(ws)
		if err != nil {
			// Per-workspace, so one tenant's bad data cannot stall every other tenant's
			// scan.
			log.Printf("sod scan: workspace %s: %v", ws, err)
			continue
		}
		if res.ViolationsNew > 0 || res.ViolationsCleared > 0 {
			log.Printf("sod scan: workspace %s subjects=%d rules=%d open=%d new=%d cleared=%d",
				ws, res.SubjectsScanned, res.RulesEvaluated,
				res.ViolationsOpen, res.ViolationsNew, res.ViolationsCleared)
		}
	}
}
