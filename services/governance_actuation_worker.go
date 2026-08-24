package services

import (
	"log"
	"time"

	"gorm.io/gorm"
)

// LeaseReaper returns actuation work abandoned by a dead agent to the queue.
//
// WHY THIS IS NECESSARY
// An agent leases an instruction, then its pod is evicted mid-apply. Without a reaper
// that instruction stays 'leased' forever and the quarantine it carried is never
// enforced — while the console shows enforcement as merely pending. Silence would look
// identical to progress.
//
// The reaper is also where an instruction becomes terminal: once it has burned its
// attempts it flips to 'failed' with a reason, so an operator sees a NetworkPolicy the
// cluster will never accept rather than watching it loop.
type LeaseReaper struct {
	am       ActuationManager
	interval time.Duration
}

// NewLeaseReaper constructs a LeaseReaper.
func NewLeaseReaper(db *gorm.DB, interval time.Duration) *LeaseReaper {
	if interval <= 0 {
		interval = time.Minute
	}
	return &LeaseReaper{am: NewActuationManager(db), interval: interval}
}

// Start launches the reap loop.
//
// A minute, because the lease TTL is two: reaping much slower than the lease would leave
// enforcement stalled for longer than necessary, and much faster would risk reclaiming
// work from an agent that is simply slow.
func (w *LeaseReaper) Start() {
	go func() {
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()
		for range ticker.C {
			n, err := w.am.ReclaimExpiredLeases()
			if err != nil {
				log.Printf("actuation lease reaper: %v", err)
				continue
			}
			if n > 0 {
				log.Printf("actuation lease reaper: returned %d abandoned instruction(s) to the queue", n)
			}
		}
	}()
}
