//go:build integration

package flows

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

// AS-037: a DCR client used only through native grants (no
// last_token_issued_at stamp) must not be reaped as stale; an unused one is.
func Test_StaleDCRCleanup_KeepsClientsWithRecentNativeTokens(t *testing.T) {
	n := nonce(t)
	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	rs, err := AddResourceServer(config.DB, ws, "https://"+n+".example.com", n)
	if err != nil {
		t.Fatalf("rs: %v", err)
	}
	used, err := AddServiceAccountWithScopes(config.DB, ws, rs, n+"u")
	if err != nil {
		t.Fatalf("sa used: %v", err)
	}
	idle, err := AddServiceAccountWithScopes(config.DB, ws, rs, n+"i")
	if err != nil {
		t.Fatalf("sa idle: %v", err)
	}
	old := time.Now().AddDate(0, 0, -60)
	for _, id := range []uuid.UUID{used.ClientID, idle.ClientID} {
		config.DB.Exec(`UPDATE mcp_oauth_clients SET registration_type = 'dcr', sync_status = 'active', created_at = ?, last_token_issued_at = NULL WHERE id = ?`, old, id)
	}
	if err := config.DB.Exec(`INSERT INTO native_tokens (jti, iss, workspace_id, token_family, subject_type, subject_id, client_id, resource_server_id, aud, scope, issued_at, expires_at)
		VALUES (gen_random_uuid(), 'https://issuer.test', ?, 'm2m', 'service_account', ?, ?, ?, ?, 'read', now() - interval '1 day', now())`,
		ws.WorkspaceID, used.SAID, used.ClientIDString, rs.RSID, rs.ResourceURI).Error; err != nil {
		t.Fatalf("native token: %v", err)
	}

	r := services.NewHydraReconciler(config.DB, time.Minute)
	if _, err := r.MarkStaleDCRClients(context.Background(), 30); err != nil {
		t.Fatalf("mark stale: %v", err)
	}
	status := func(id uuid.UUID) string {
		var s string
		config.DB.Raw(`SELECT sync_status FROM mcp_oauth_clients WHERE id = ?`, id).Scan(&s)
		return s
	}
	if s := status(used.ClientID); s != "active" {
		t.Errorf("client with a recent native token was marked %q", s)
	}
	if s := status(idle.ClientID); s != "pending_delete" {
		t.Errorf("idle client should be pending_delete, got %q", s)
	}
}

// AS-037: a periodic job runs on one replica at a time.
func Test_RunAsLeader_IsExclusive(t *testing.T) {
	ctx := context.Background()
	var runs int32
	release := make(chan struct{})
	started := make(chan struct{})
	go services.RunAsLeader(ctx, config.DB, "test-exclusive", func() {
		atomic.AddInt32(&runs, 1)
		close(started)
		<-release
	})
	<-started
	services.RunAsLeader(ctx, config.DB, "test-exclusive", func() { atomic.AddInt32(&runs, 1) })
	if got := atomic.LoadInt32(&runs); got != 1 {
		t.Fatalf("second replica ran while the first held the lock: runs=%d", got)
	}
	close(release)
	time.Sleep(200 * time.Millisecond)
	services.RunAsLeader(ctx, config.DB, "test-exclusive", func() { atomic.AddInt32(&runs, 1) })
	if got := atomic.LoadInt32(&runs); got != 2 {
		t.Fatalf("lock was not released: runs=%d", got)
	}
}

// AS-096: expired replay-guard and revocation rows are pruned; live ones stay.
func Test_ReplayCachePrune_RemovesOnlyExpiredRows(t *testing.T) {
	n := nonce(t)
	rows := []struct {
		jti string
		exp time.Time
	}{{n + "-old", time.Now().Add(-3 * time.Hour)}, {n + "-live", time.Now().Add(time.Hour)}}
	for _, row := range rows {
		for _, q := range []string{
			`INSERT INTO client_assertion_replay_cache (client_id, jti, expires_at) VALUES (?, ?, ?)`,
			`INSERT INTO id_jag_replay_cache (iss, jti, expires_at) VALUES (?, ?, ?)`,
			`INSERT INTO revoked_tokens (iss, kind, jti, expires_at) VALUES (?, 'access_token', ?, ?)`,
		} {
			if err := config.DB.Exec(q, "prune-"+n, row.jti, row.exp).Error; err != nil {
				t.Fatalf("seed: %v", err)
			}
		}
		if err := config.DB.Exec(`INSERT INTO revoked_session_tokens (jti, expires_at) VALUES (?, ?)`, row.jti, row.exp).Error; err != nil {
			t.Fatalf("seed revoked_session_tokens: %v", err)
		}
	}

	r := services.NewHydraReconciler(config.DB, time.Minute)
	if _, err := r.PruneReplayCaches(context.Background()); err != nil {
		t.Fatalf("prune: %v", err)
	}
	for _, table := range []string{"client_assertion_replay_cache", "id_jag_replay_cache", "revoked_tokens", "revoked_session_tokens"} {
		var old, live int64
		config.DB.Table(table).Where("jti = ?", n+"-old").Count(&old)
		config.DB.Table(table).Where("jti = ?", n+"-live").Count(&live)
		if old != 0 {
			t.Errorf("%s: expired row not pruned", table)
		}
		if live != 1 {
			t.Errorf("%s: live row removed (count %d)", table, live)
		}
	}
}
