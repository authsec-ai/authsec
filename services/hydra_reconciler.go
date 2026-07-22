package services

import (
	"context"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/utils"
	"github.com/google/uuid"
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
// It also launches a background goroutine that marks stale DCR clients
// (no token in DCR_STALE_DAYS days, default 30) as pending_delete daily.
func (r *HydraReconciler) Run(ctx context.Context) {
	log.Printf("[HydraReconciler] starting; interval=%s", r.interval)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	// Launch background housekeeping goroutines alongside the main reconcile loop.
	go r.runStaleDCRCleanup(ctx)
	go r.runPendingApprovalExpiry(ctx)
	go r.runAccessRequestExpiryAndReminder(ctx)
	go r.runPRMOverrideReverify(ctx)

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

// runStaleDCRCleanup runs once immediately on startup and then every 24h.
// It marks DCR clients that have never issued a token (or whose last token
// was issued more than DCR_STALE_DAYS days ago) as pending_delete so the
// main reconciler loop can clean them up from Hydra.
func (r *HydraReconciler) runStaleDCRCleanup(ctx context.Context) {
	staleDays := 30
	if v := os.Getenv("DCR_STALE_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			staleDays = n
		}
	}
	log.Printf("[HydraReconciler] stale DCR cleanup: staleDays=%d", staleDays)

	cleanup := func() {
		cutoff := time.Now().AddDate(0, 0, -staleDays)
		var staleClients []models.MCPOAuthClient
		// A client is stale only if it was CREATED before the cutoff AND it has
		// either never issued a token or not issued one since the cutoff. The
		// created_at gate is essential: without it a freshly-registered DCR
		// client (last_token_issued_at IS NULL) is reaped the instant the next
		// cleanup runs — including at every backend boot — even though it's
		// seconds old. Young clients are never stale, regardless of token history.
		if err := r.db.WithContext(ctx).Where(
			"registration_type = 'dcr' AND sync_status = ? AND created_at < ? AND (last_token_issued_at IS NULL OR last_token_issued_at < ?)",
			models.MCPClientSyncActive,
			cutoff,
			cutoff,
		).Find(&staleClients).Error; err != nil {
			log.Printf("[HydraReconciler] stale DCR query failed: %v", err)
			return
		}
		if len(staleClients) == 0 {
			return
		}
		log.Printf("[HydraReconciler] stale DCR cleanup: marking %d client(s) pending_delete (cutoff=%s)", len(staleClients), cutoff.Format(time.RFC3339))
		for i := range staleClients {
			c := &staleClients[i]
			if err := r.db.WithContext(ctx).Model(c).Update("sync_status", models.MCPClientSyncPendingDelete).Error; err != nil {
				log.Printf("[HydraReconciler] stale DCR: failed to mark pending_delete client_id=%s: %v", c.ClientID, err)
			} else {
				log.Printf("[HydraReconciler] stale DCR: marked pending_delete client_id=%s", c.ClientID)
			}
		}
	}

	// Run once immediately, then every 24 hours.
	cleanup()
	dailyTicker := time.NewTicker(24 * time.Hour)
	defer dailyTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-dailyTicker.C:
			cleanup()
		}
	}
}

// runPendingApprovalExpiry auto-expires pending_approval registrations that
// have been sitting unanswered for more than PENDING_APPROVAL_TTL_DAYS days
// (default 7). This bounds the drip-DoS where DCR-minted fresh client_ids
// accumulate junk pending rows in a victim workspace's Clients page.
// The rows are set to "revoked" rather than deleted so the workspace admin
// can still see what was denied rather than having rows silently vanish.
func (r *HydraReconciler) runPendingApprovalExpiry(ctx context.Context) {
	ttlDays := 7
	if v := os.Getenv("PENDING_APPROVAL_TTL_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			ttlDays = n
		}
	}
	log.Printf("[HydraReconciler] pending approval expiry: ttlDays=%d", ttlDays)

	expire := func() {
		cutoff := time.Now().AddDate(0, 0, -ttlDays)
		result := r.db.WithContext(ctx).
			Model(&models.ResourceServerClientRegistration{}).
			Where("status = 'pending_approval' AND created_at < ?", cutoff).
			Update("status", "revoked")
		if result.Error != nil {
			log.Printf("[HydraReconciler] pending approval expiry query failed: %v", result.Error)
			return
		}
		if result.RowsAffected > 0 {
			log.Printf("[HydraReconciler] pending approval expiry: expired %d row(s) (cutoff=%s)", result.RowsAffected, cutoff.Format(time.RFC3339))
		}
	}

	expire()
	dailyTicker := time.NewTicker(24 * time.Hour)
	defer dailyTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-dailyTicker.C:
			expire()
		}
	}
}

// runAccessRequestExpiryAndReminder runs hourly and does two things:
//
//  1. Flips pending access_requests whose expires_at has passed to 'expired'.
//  2. Sends an email warning to workspace admins for requests expiring within
//     the next 24 hours (pre-expiry reminder, Journey B finding 6).
func (r *HydraReconciler) runAccessRequestExpiryAndReminder(ctx context.Context) {
	log.Printf("[HydraReconciler] access_request expiry+reminder goroutine started")

	run := func() {
		now := time.Now().UTC()

		// ── 1. expire stale pending rows ─────────────────────────────────────
		res := r.db.WithContext(ctx).Exec(`
			UPDATE access_requests
			SET status='expired', updated_at=?
			WHERE status='pending' AND expires_at IS NOT NULL AND expires_at <= ?`,
			now, now,
		)
		if res.Error != nil {
			log.Printf("[HydraReconciler] access_request expiry update failed: %v", res.Error)
		} else if res.RowsAffected > 0 {
			log.Printf("[HydraReconciler] access_request expiry: expired %d row(s)", res.RowsAffected)
		}

		// ── 2. find requests expiring in the next 24 hours ───────────────────
		warn := now.Add(24 * time.Hour)
		type arRow struct {
			ID                uuid.UUID
			WorkspaceID       uuid.UUID
			ResourceServerID  uuid.UUID
			RequestedByClient string
			RequestedScopes   string
			ExpiresAt         time.Time
		}
		var rows []arRow
		if err := r.db.WithContext(ctx).Raw(`
			SELECT id, workspace_id, resource_server_id,
			       requested_by_client, requested_scopes, expires_at
			FROM access_requests
			WHERE status='pending'
			  AND expires_at IS NOT NULL
			  AND expires_at > ? AND expires_at <= ?`,
			now, warn,
		).Scan(&rows).Error; err != nil {
			log.Printf("[HydraReconciler] access_request reminder query failed: %v", err)
			return
		}

		if len(rows) == 0 {
			return
		}

		// Collect RS names.
		rsIDs := make([]uuid.UUID, 0, len(rows))
		for _, row := range rows {
			rsIDs = append(rsIDs, row.ResourceServerID)
		}
		type rsRow struct {
			ID   uuid.UUID
			Name string
		}
		var rsList []rsRow
		r.db.WithContext(ctx).Raw("SELECT id, name FROM resource_servers WHERE id IN ?", rsIDs).Scan(&rsList)
		rsNames := make(map[uuid.UUID]string, len(rsList))
		for _, rs := range rsList {
			rsNames[rs.ID] = rs.Name
		}

		selfIssuer := ""
		if config.AppConfig != nil {
			selfIssuer = config.AppConfig.OAuthBaseURL()
		}

		for _, row := range rows {
			rsName := rsNames[row.ResourceServerID]
			if rsName == "" {
				rsName = row.ResourceServerID.String()
			}

			// Load workspace admins.
			type adminEmail struct{ Email string }
			var admins []adminEmail
			r.db.WithContext(ctx).Raw(`
				SELECT DISTINCT u.email
				FROM users u
				JOIN role_bindings rb ON u.id = rb.user_id AND rb.workspace_id = ?
				JOIN roles ro ON rb.role_id = ro.id AND ro.workspace_id = ?
				WHERE u.active = true AND u.workspace_id = ?
				  AND LOWER(ro.name) IN ('admin', 'administrator', 'owner', 'super_admin')`,
				row.WorkspaceID, row.WorkspaceID, row.WorkspaceID,
			).Scan(&admins)

			statusURL := selfIssuer + "/oauth/access-requests/" + row.ID.String()
			for _, a := range admins {
				_ = utils.SendAccessRequestNotificationEmail(
					a.Email, row.ID.String(),
					row.RequestedByClient, rsName, row.RequestedScopes,
					statusURL, row.ExpiresAt, true,
				)
			}
			log.Printf("[HydraReconciler] access_request pre-expiry reminder sent for req=%s (expires=%s)",
				row.ID, row.ExpiresAt.Format(time.RFC3339))
		}
	}

	run()
	hourlyTicker := time.NewTicker(time.Hour)
	defer hourlyTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-hourlyTicker.C:
			run()
		}
	}
}

// runPRMOverrideReverify runs hourly and re-attempts the real PRM fetch for any
// resource server on a manual override (plan §7): success auto-replaces the
// override; expiry without success flags metadata_stale.
func (r *HydraReconciler) runPRMOverrideReverify(ctx context.Context) {
	svc := NewResourceServerOnboardingService(r.db)
	run := func() {
		replaced, staled := svc.ReverifyManualPRMOverrides(ctx)
		if replaced > 0 || staled > 0 {
			log.Printf("[HydraReconciler] PRM reverify: replaced=%d staled=%d", replaced, staled)
		}
	}
	run()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
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
