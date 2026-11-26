package services

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/monitoring"
)

// The audit governance jobs (one goroutine each, started by
// InstallAuditGovernance from cmd/main.go):
//
//	anchor + retention   daily: anchor every chain, then purge per workspace
//	                     and record class (AUTHSEC_DISABLE_AUDIT_RETENTION=true
//	                     stops the purge; anchoring keeps running)
//	operator baseline    hourly (AUTHSEC_DISABLE_OPERATOR_BASELINE=true)
//	write-failure replay every 5 minutes (AUTHSEC_DISABLE_AUDIT_REPLAY=true)

const auditReplayMaxAttempts = 20

// AuditWriteFailureView is a recorded write failure.
type AuditWriteFailureView struct {
	ID          uuid.UUID  `json:"id"`
	Event       JSONText   `json:"event"`
	Error       string     `json:"error"`
	Attempts    int        `json:"attempts"`
	State       string     `json:"state"`
	CreatedAt   time.Time  `json:"created_at"`
	ReplayedAt  *time.Time `json:"replayed_at,omitempty"`
	ReplayedSeq *int64     `json:"replayed_seq,omitempty"`
}

// WriteFailures lists the workspace's audit write failures, newest first.
func (s *AuditGovService) WriteFailures(ctx context.Context, ws uuid.UUID) ([]AuditWriteFailureView, error) {
	var out []AuditWriteFailureView
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT id, event::text AS event, error, attempts, state, created_at, replayed_at, replayed_seq
		               FROM audit_write_failure WHERE workspace_id = ? ORDER BY created_at DESC LIMIT 500`, ws).Scan(&out).Error
	})
	if out == nil {
		out = []AuditWriteFailureView{}
	}
	return out, err
}

type failureRow struct {
	ID          uuid.UUID
	WorkspaceID *uuid.UUID
	Event       string
	Attempts    int
	NotifiedAt  *time.Time
}

// replayOne re-inserts one failed event into its chain (its original
// timestamp is kept; its link is assigned now). It records the outcome.
func replayOne(tx *gorm.DB, f failureRow) error {
	var ev monitoring.AuditEvent
	if err := json.Unmarshal([]byte(f.Event), &ev); err != nil {
		return tx.Exec(`UPDATE audit_write_failure SET state = 'dead', error = ?, updated_at = now() WHERE id = ?`,
			"replay: event is not decodable: "+err.Error(), f.ID).Error
	}
	ev.ID, ev.Seq, ev.PrevHash, ev.Hash = 0, nil, nil, nil
	if f.WorkspaceID != nil && ev.WorkspaceID != f.WorkspaceID.String() {
		ev.WorkspaceID = f.WorkspaceID.String()
	}
	sp := tx.SavePoint("replay")
	if sp.Error != nil {
		return sp.Error
	}
	if err := monitoring.WriteAuditTx(tx, &ev); err != nil {
		if rb := tx.RollbackTo("replay"); rb.Error != nil {
			return rb.Error
		}
		state := "pending"
		if f.Attempts+1 >= auditReplayMaxAttempts {
			state = "dead"
		}
		msg := err.Error()
		if len(msg) > 2000 {
			msg = msg[:2000]
		}
		return tx.Exec(`UPDATE audit_write_failure SET attempts = attempts + 1, state = ?, error = ?, updated_at = now() WHERE id = ?`,
			state, msg, f.ID).Error
	}
	return tx.Exec(`UPDATE audit_write_failure SET state = 'replayed', replayed_at = now(), replayed_seq = ?, updated_at = now() WHERE id = ?`,
		ev.Seq, f.ID).Error
}

// ReplayWorkspaceFailures announces new write failures of the workspace (a
// governance event each) and replays the pending ones into the chain.
func (s *AuditGovService) ReplayWorkspaceFailures(ctx context.Context, ws uuid.UUID) error {
	return tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var rows []failureRow
		if err := tx.Raw(`SELECT id, workspace_id, event::text AS event, attempts, notified_at FROM audit_write_failure
		                  WHERE workspace_id = ? AND (state = 'pending' OR notified_at IS NULL) ORDER BY created_at LIMIT 200 FOR UPDATE SKIP LOCKED`, ws).
			Scan(&rows).Error; err != nil {
			return err
		}
		for _, f := range rows {
			if f.NotifiedAt == nil {
				if err := appendGovEvent(tx, ws, GovEventAuditWriteFailed, models.GovActorSystem, "", govEventRefs{},
					map[string]any{"failure_id": f.ID, "attempts": f.Attempts}); err != nil {
					return err
				}
				if err := tx.Exec(`UPDATE audit_write_failure SET notified_at = now() WHERE workspace_id = ? AND id = ?`, ws, f.ID).Error; err != nil {
					return err
				}
			}
			if err := replayOne(tx, f); err != nil {
				return err
			}
		}
		return nil
	})
}

// ReplayAllFailures runs ReplayWorkspaceFailures for every workspace with
// pending failures, then replays the platform failures.
func (s *AuditGovService) ReplayAllFailures(ctx context.Context) error {
	var wss []uuid.UUID
	// TENANT-EXEMPT: the replay job runs across workspaces; this lists workspace ids with pending failures only, each replayed in its own workspace transaction.
	if err := s.db.WithContext(ctx).Raw(`SELECT DISTINCT workspace_id FROM audit_write_failure
	        WHERE workspace_id IS NOT NULL AND (state = 'pending' OR notified_at IS NULL)`).Scan(&wss).Error; err != nil {
		return err
	}
	var first error
	for _, ws := range wss {
		if err := s.ReplayWorkspaceFailures(ctx, ws); err != nil && first == nil {
			first = err
		}
	}
	// TENANT-EXEMPT: platform failures (events with no live workspace) have no tenant.
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var rows []failureRow
		if err := tx.Raw(`SELECT id, workspace_id, event::text AS event, attempts, notified_at FROM audit_write_failure
		                  WHERE workspace_id IS NULL AND state = 'pending' ORDER BY created_at LIMIT 200 FOR UPDATE SKIP LOCKED`).
			Scan(&rows).Error; err != nil {
			return err
		}
		for _, f := range rows {
			if err := replayOne(tx, f); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil && first == nil {
		first = err
	}
	return first
}

// BaselineAll runs the operator baseline for every workspace.
func (s *AuditGovService) BaselineAll(ctx context.Context) error {
	wss, _, err := s.auditChains(ctx)
	if err != nil {
		return err
	}
	var first error
	for _, ws := range wss {
		if _, err := s.BaselineWorkspace(ctx, ws); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func every(ctx context.Context, d time.Duration, name string, fn func(context.Context) error) {
	for {
		if err := fn(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[audit-governance] %s: %v", name, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(d):
		}
	}
}

// InstallAuditGovernance starts the audit governance jobs. It replaces the
// old daily DELETE of every workspace's audit events older than 90 days.
func InstallAuditGovernance(db *gorm.DB) {
	ctx := context.Background()
	if RequireAuditGovernance(db) != nil {
		log.Printf("[audit-governance] jobs not started: migrations 167-169 are not applied")
		return
	}
	s := NewAuditGovService(db)
	retention := os.Getenv("AUTHSEC_DISABLE_AUDIT_RETENTION") != "true"
	go every(ctx, 24*time.Hour, "anchor and retention", func(ctx context.Context) error {
		if err := s.AnchorAll(ctx); err != nil {
			log.Printf("[audit-governance] anchor: %v", err)
		}
		if !retention {
			return nil
		}
		return s.PurgeAll(ctx)
	})
	if os.Getenv("AUTHSEC_DISABLE_OPERATOR_BASELINE") != "true" {
		go every(ctx, time.Hour, "operator baseline", s.BaselineAll)
	}
	if os.Getenv("AUTHSEC_DISABLE_AUDIT_REPLAY") != "true" {
		go every(ctx, 5*time.Minute, "write-failure replay", s.ReplayAllFailures)
	}
}
