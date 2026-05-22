package services

import (
	"context"
	"log"
	"time"

	"github.com/authsec-ai/authsec/models"
	"gorm.io/gorm"
)

// HydraReconciler walks AuthSec OAuth client rows whose sync_status is not
// "active" and re-attempts the Hydra side. This closes the half-sync gap
// described in the v4 plan §6 — AuthSec is the authorization source of truth,
// Hydra runs the protocol, and if the two diverge the reconciler converges
// them rather than leaving the operator with a permanent broken state.
//
// Driving rules:
//   - sync_status='sync_error' — Hydra create/update failed previously. The
//     reconciler looks up the row in Hydra; if absent, it creates it; if
//     present, it flips sync_status back to 'active'.
//   - sync_status='pending_delete' — AuthSec wants the row gone but Hydra
//     delete failed. The reconciler retries the delete; on success the
//     AuthSec row is soft-deleted.
//
// The loop is intentionally simple and stateless — every interval re-reads
// from the DB. It runs in-process so we don't add a new component to the
// dev/local-k8s stack.
type HydraReconciler struct {
	db       *gorm.DB
	interval time.Duration
}

// NewHydraReconciler constructs a reconciler with the given polling interval.
// A zero interval defaults to five minutes.
func NewHydraReconciler(db *gorm.DB, interval time.Duration) *HydraReconciler {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &HydraReconciler{db: db, interval: interval}
}

// Run blocks until ctx is cancelled, ticking on r.interval. It logs but does
// not return errors — convergence failures stay logged and are retried on
// the next tick.
func (r *HydraReconciler) Run(ctx context.Context) {
	log.Printf("[HydraReconciler] starting; interval=%s", r.interval)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	// First pass immediately so a restart picks up any in-flight failures
	// without waiting for the first interval.
	r.tick(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Printf("[HydraReconciler] stopping: %v", ctx.Err())
			return
		case <-ticker.C:
			r.tick(ctx)
		}
	}
}

func (r *HydraReconciler) tick(ctx context.Context) {
	var rows []models.MCPOAuthClient
	if err := r.db.WithContext(ctx).
		Where("sync_status IN ?", []string{models.MCPClientSyncError, models.MCPClientSyncPendingDelete}).
		Limit(100).
		Find(&rows).Error; err != nil {
		log.Printf("[HydraReconciler] tick query failed: %v", err)
		return
	}
	if len(rows) == 0 {
		return
	}

	log.Printf("[HydraReconciler] tick: %d row(s) to reconcile", len(rows))
	for i := range rows {
		row := &rows[i]
		switch row.SyncStatus {
		case models.MCPClientSyncError:
			r.reconcileSyncError(ctx, row)
		case models.MCPClientSyncPendingDelete:
			r.reconcilePendingDelete(ctx, row)
		}
	}
}

// reconcileSyncError checks Hydra for the client. If present we mark the row
// active. If absent we re-create it using the metadata stored in AuthSec.
// On failure we record the error string and leave sync_status untouched so a
// future tick retries.
func (r *HydraReconciler) reconcileSyncError(ctx context.Context, row *models.MCPOAuthClient) {
	if existing, err := hydraAdminGetClient(row.HydraClientID); err == nil && existing != nil {
		r.markActive(ctx, row, "hydra client present; converged on read")
		return
	}

	c := hydraClient{
		ClientID:      row.HydraClientID,
		ClientName:    row.ClientName,
		GrantTypes:    []string(row.GrantTypes),
		RedirectURIs:  []string(row.RedirectURIs),
		ResponseTypes: []string(row.ResponseTypes),
		TokenEndpoint: row.TokenEndpointAuthMethod,
		Scope:         row.Scope,
	}
	if err := hydraAdminCreateClient(c); err != nil {
		r.markError(ctx, row, "recreate failed: "+err.Error())
		return
	}
	r.markActive(ctx, row, "hydra client recreated")
}

// reconcilePendingDelete retries the Hydra delete. On success the AuthSec row
// is soft-deleted (the migration uses gorm.DeletedAt). On failure we keep the
// pending_delete status with the latest error string.
func (r *HydraReconciler) reconcilePendingDelete(ctx context.Context, row *models.MCPOAuthClient) {
	if err := hydraAdminDeleteClient(row.HydraClientID); err != nil {
		r.markError(ctx, row, "delete retry failed: "+err.Error())
		return
	}
	if err := r.db.WithContext(ctx).Delete(row).Error; err != nil {
		log.Printf("[HydraReconciler] soft-delete failed for client_id=%s: %v", row.ClientID, err)
		return
	}
	log.Printf("[HydraReconciler] pending_delete converged for client_id=%s", row.ClientID)
}

func (r *HydraReconciler) markActive(ctx context.Context, row *models.MCPOAuthClient, reason string) {
	if err := r.db.WithContext(ctx).Model(row).Updates(map[string]interface{}{
		"sync_status":        models.MCPClientSyncActive,
		"sync_last_error":    gorm.Expr("NULL"),
		"sync_last_error_at": gorm.Expr("NULL"),
	}).Error; err != nil {
		log.Printf("[HydraReconciler] failed to mark active client_id=%s: %v", row.ClientID, err)
		return
	}
	log.Printf("[HydraReconciler] reconciled client_id=%s: %s", row.ClientID, reason)
}

func (r *HydraReconciler) markError(ctx context.Context, row *models.MCPOAuthClient, msg string) {
	now := time.Now()
	if err := r.db.WithContext(ctx).Model(row).Updates(map[string]interface{}{
		"sync_last_error":    msg,
		"sync_last_error_at": now,
	}).Error; err != nil {
		log.Printf("[HydraReconciler] failed to record error for client_id=%s: %v", row.ClientID, err)
		return
	}
	log.Printf("[HydraReconciler] client_id=%s reconcile failed: %s", row.ClientID, msg)
}
