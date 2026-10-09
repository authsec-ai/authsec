package services

import (
	"log"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// JMLWorker reconciles human access against birthright policy on a timer.
//
// Reconciliation rather than event consumption, because `scim_events` is an HTTP audit
// log with no semantic payload — see LifecycleManager. That makes this worker the ONLY
// trigger, which is fine: it is idempotent, so a missed pass costs latency rather than
// correctness, and it catches changes made through any path rather than only SCIM.
//
// Five minutes, not hours. The leaver half is a security control: a deactivated user
// keeping access is the failure this exists to prevent, and every minute of delay is a
// minute of access somebody should not have. The joiner half tolerates the same latency
// happily.
type JMLWorker struct {
	db       *gorm.DB
	oauth    *OAuthASService
	interval time.Duration
}

// NewJMLWorker constructs a JMLWorker.
func NewJMLWorker(db *gorm.DB, interval time.Duration) *JMLWorker {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &JMLWorker{db: db, oauth: NewOAuthASService(db), interval: interval}
}

// Start launches the reconcile loop.
func (w *JMLWorker) Start() {
	go func() {
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()
		for range ticker.C {
			w.RunOnce()
		}
	}()
}

// RunOnce reconciles every workspace. Exported so an operator can trigger a pass and so
// tests need not wait on a ticker.
func (w *JMLWorker) RunOnce() {
	var workspaceIDs []uuid.UUID
	if err := w.db.Table("workspaces").Pluck("id", &workspaceIDs).Error; err != nil {
		log.Printf("jml reconcile: could not enumerate workspaces: %v", err)
		return
	}
	lm := NewLifecycleManager(w.db, w.oauth)

	for _, ws := range workspaceIDs {
		res, err := lm.Reconcile(ws, ReconcileOptions{ActorLabel: "jml reconcile"})
		if err != nil {
			// Per-workspace, so one tenant's bad data cannot stall every other tenant.
			log.Printf("jml reconcile: workspace %s: %v", ws, err)
			continue
		}
		// Only log when something happened, or a 5-minute tick across every workspace
		// would bury the passes that mattered.
		if res.GrantsCreated > 0 || res.LeaversProcessed > 0 || res.StaleRevoked > 0 || len(res.Errors) > 0 {
			log.Printf("jml reconcile: workspace %s users=%d granted=%d leavers=%d "+
				"bindings_revoked=%d tokens_revoked=%d stale_flagged=%d stale_revoked=%d "+
				"orphaned_agents=%d errors=%d",
				ws, res.UsersScanned, res.GrantsCreated, res.LeaversProcessed,
				res.BindingsRevoked, res.TokensRevoked, res.StaleFlagged,
				res.StaleRevoked, res.OrphanedAgents, len(res.Errors))
		}
		for _, e := range res.Errors {
			log.Printf("jml reconcile: workspace %s: %s", ws, e)
		}
	}
}
