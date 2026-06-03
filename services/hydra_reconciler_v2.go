package services

import (
	"context"
	"log"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"gorm.io/gorm"
)

// HydraReconcilerV2 converges mcp_oauth_clients rows whose sync_status drifted
// from active. Two cases it handles:
//
//	sync_status='sync_error'    → retry create/update against Hydra; on success
//	                              flip back to 'active'.
//	sync_status='pending_delete' → retry Hydra delete; on success soft-delete
//	                              the master row.
//
// Started from cmd/main.go via NewHydraReconcilerV2(db, interval).Run(ctx).
// Safe to disable with env AUTHSEC_DISABLE_HYDRA_RECONCILER_V2=true (first
// rollout should set this until the dance is verified).
type HydraReconcilerV2 struct {
	db       *gorm.DB
	interval time.Duration
}

func NewHydraReconcilerV2(db *gorm.DB, interval time.Duration) *HydraReconcilerV2 {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &HydraReconcilerV2{db: db, interval: interval}
}

// Run loops until ctx is cancelled. First tick is immediate; subsequent ticks
// follow the configured interval.
func (r *HydraReconcilerV2) Run(ctx context.Context) {
	t := time.NewTicker(r.interval)
	defer t.Stop()
	r.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.tick(ctx)
		}
	}
}

func (r *HydraReconcilerV2) tick(ctx context.Context) {
	var rows []models.MCPOAuthClient
	if err := r.db.Where("sync_status IN ?", []string{"sync_error", "pending_delete"}).
		Limit(50).Find(&rows).Error; err != nil {
		log.Printf("hydra_reconciler_v2: query failed: %v", err)
		return
	}
	for i := range rows {
		select {
		case <-ctx.Done():
			return
		default:
		}
		row := &rows[i]
		switch row.SyncStatus {
		case "sync_error":
			r.reconcileSyncError(ctx, row)
		case "pending_delete":
			r.reconcilePendingDelete(ctx, row)
		}
	}
}

func (r *HydraReconcilerV2) reconcileSyncError(_ context.Context, row *models.MCPOAuthClient) {
	if _, err := hydraClientGetForUpdate(row.HydraClientID); err == nil {
		r.markActive(row, "client exists in hydra")
		return
	}
	if err := hydraAdminCreateClient(rebuildHydraClientPayload(row)); err != nil {
		r.markError(row, "create retry: "+err.Error())
		return
	}
	r.markActive(row, "recreated in hydra")
}

func (r *HydraReconcilerV2) reconcilePendingDelete(_ context.Context, row *models.MCPOAuthClient) {
	if err := hydraAdminDeleteClient(row.HydraClientID); err != nil {
		r.markError(row, "delete retry: "+err.Error())
		return
	}
	now := time.Now()
	if err := r.db.Model(row).Updates(map[string]interface{}{
		"deleted_at":  now,
		"sync_status": "active",
		"updated_at":  now,
	}).Error; err != nil {
		log.Printf("hydra_reconciler_v2: soft-delete write failed for client %s: %v", row.ClientID, err)
	}
}

func (r *HydraReconcilerV2) markActive(row *models.MCPOAuthClient, reason string) {
	now := time.Now()
	if err := r.db.Model(row).Updates(map[string]interface{}{
		"sync_status":         "active",
		"sync_last_error":     gorm.Expr("NULL"),
		"sync_last_error_at":  gorm.Expr("NULL"),
		"updated_at":          now,
	}).Error; err != nil {
		log.Printf("hydra_reconciler_v2: markActive write failed for client %s: %v", row.ClientID, err)
	}
	_ = reason // logged for observability if desired
}

func (r *HydraReconcilerV2) markError(row *models.MCPOAuthClient, msg string) {
	now := time.Now()
	if err := r.db.Model(row).Updates(map[string]interface{}{
		"sync_status":         "sync_error",
		"sync_last_error":     msg,
		"sync_last_error_at":  now,
		"updated_at":          now,
	}).Error; err != nil {
		log.Printf("hydra_reconciler_v2: markError write failed for client %s: %v", row.ClientID, err)
	}
}

// Convenience for cmd/main.go to use the package-level DB if it likes.
func StartHydraReconcilerV2(ctx context.Context) {
	r := NewHydraReconcilerV2(config.DB, 5*time.Minute)
	go r.Run(ctx)
}
