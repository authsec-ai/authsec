package integration

// Ingest token triggers (046): the database itself marks a token with a source
// source_bound, and revokes a source's tokens when the source is deleted -- by
// any path, including raw SQL and code that predates 044 -- so a bound token
// never becomes a workspace-wide one. The application's own DeleteSource
// (revoke, then delete) is unchanged; see TestP2IngestTokenSourceDeletionRevokes.

import (
	"testing"
	"time"

	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// rawToken inserts a token as pre-044 code (or anyone writing the table
// directly) would: source_bound stated explicitly, false. Returns the
// plaintext and the row id.
func rawToken(t *testing.T, db *gorm.DB, ws uuid.UUID, src *uuid.UUID) (string, uuid.UUID) {
	t.Helper()
	plain, err := repositories.GenerateDiscoveryIngestToken()
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	if err := db.Exec(`INSERT INTO discovery_ingest_tokens
	        (id, workspace_id, discovery_source_id, token_hash, token_prefix, label, created_by, source_bound)
	    VALUES (?, ?, ?, ?, ?, 'raw', 'pre-044', false)`,
		id, ws, src, repositories.HashDiscoveryIngestToken(plain), plain[:8]).Error; err != nil {
		t.Fatalf("raw insert: %v", err)
	}
	return plain, id
}

// (a) A token with a source is source_bound whatever the writer said, and
// stays bound; a token without one is left alone.
func TestP2IngestTokenTriggerMarksBound(t *testing.T) {
	l := newIngestLab(t)

	_, boundID := rawToken(t, l.db, l.wsA, &l.srcA1)
	if r, _ := ingestTokenByID(t, l.db, boundID); !r.SourceBound || r.DiscoverySourceID == nil {
		t.Errorf("raw insert of a bound token with source_bound=false: %+v, want source_bound true", r)
	}
	_, wsID := rawToken(t, l.db, l.wsA, nil)
	if r, _ := ingestTokenByID(t, l.db, wsID); r.SourceBound {
		t.Errorf("raw insert of an unbound token: %+v, want source_bound false", r)
	}

	// An UPDATE cannot clear it: not while the token has a source ...
	if err := l.db.Exec(`UPDATE discovery_ingest_tokens SET source_bound = false WHERE id = ?`, boundID).Error; err != nil {
		t.Fatal(err)
	}
	if r, _ := ingestTokenByID(t, l.db, boundID); !r.SourceBound {
		t.Error("UPDATE cleared source_bound on a token with a source")
	}
	// ... nor after it has lost it (revoked, as the CHECK requires): it
	// stays a bound token of a deleted source, never a workspace token.
	if err := l.db.Exec(`UPDATE discovery_ingest_tokens SET revoked_at = now(), discovery_source_id = NULL
	    WHERE id = ?`, boundID).Error; err != nil {
		t.Fatal(err)
	}
	if err := l.db.Exec(`UPDATE discovery_ingest_tokens SET source_bound = false WHERE id = ?`, boundID).Error; err != nil {
		t.Fatal(err)
	}
	if r, _ := ingestTokenByID(t, l.db, boundID); !r.SourceBound {
		t.Error("UPDATE cleared source_bound on a revoked token of a deleted source")
	}

	// Binding an unbound token to a source by UPDATE binds it.
	if err := l.db.Exec(`UPDATE discovery_ingest_tokens SET discovery_source_id = ? WHERE id = ?`,
		l.srcA2, wsID).Error; err != nil {
		t.Fatal(err)
	}
	if r, _ := ingestTokenByID(t, l.db, wsID); !r.SourceBound {
		t.Error("UPDATE setting discovery_source_id left source_bound false")
	}

	// Mint is unaffected.
	_, minted := l.mintRow(l.wsA, nil, nil)
	if r, _ := ingestTokenByID(t, l.db, minted); r.SourceBound || r.DiscoverySourceID != nil {
		t.Errorf("a minted workspace token: %+v, want unbound", r)
	}
}

// (b) Deleting a source with raw SQL -- no application, no revoke first --
// leaves every token bound to it revoked and source_bound, never workspace
// wide; an earlier revocation keeps its time; other tokens are untouched.
func TestP2IngestTokenTriggerRevokesOnRawSourceDelete(t *testing.T) {
	l := newIngestLab(t)
	repo := repositories.NewDiscoveryIngestTokenRepository(l.db)

	plainBound, boundID := rawToken(t, l.db, l.wsA, &l.srcA1)
	_, mintedID := l.mintRow(l.wsA, &l.srcA1, nil)
	_, earlierID := l.mintRow(l.wsA, &l.srcA1, nil)
	earlier, err := l.tokens.Revoke(l.wsA, earlierID)
	if err != nil {
		t.Fatal(err)
	}
	plainWS, wsID := l.mintRow(l.wsA, nil, nil)
	plainOther, otherID := l.mintRow(l.wsA, &l.srcA2, nil)
	if v, err := repo.Verify(plainBound); err != nil || v == nil {
		t.Fatalf("setup: the raw bound token does not verify: %+v %v", v, err)
	}

	if err := l.db.Exec(`DELETE FROM discovery_sources WHERE workspace_id = ? AND id = ?`, l.wsA, l.srcA1).Error; err != nil {
		t.Fatalf("raw delete of a source with live bound tokens: %v", err)
	}

	for _, id := range []uuid.UUID{boundID, mintedID, earlierID} {
		r, found := ingestTokenByID(t, l.db, id)
		if !found {
			t.Fatalf("token %s was deleted with its source", id)
		}
		if r.DiscoverySourceID != nil || !r.SourceBound || r.RevokedAt == nil {
			t.Errorf("token %s after a raw source delete: source %v bound %v revoked %v, want NULL/true/set",
				id, r.DiscoverySourceID, r.SourceBound, r.RevokedAt)
		}
	}
	if r, _ := ingestTokenByID(t, l.db, earlierID); r.RevokedAt == nil || !r.RevokedAt.Equal(*earlier.RevokedAt) {
		t.Errorf("an already-revoked token's revoked_at moved: %v -> %v", earlier.RevokedAt, r.RevokedAt)
	}
	// Never workspace-wide: refused by Verify and by the ingress in every mode
	// that checks, whatever source the call names.
	if v, err := repo.Verify(plainBound); err != nil || v != nil {
		t.Errorf("verify a token of a raw-deleted source: %+v %v, want nil", v, err)
	}
	t.Setenv(services.DiscoveryIngestAuthEnv, "enforce")
	for _, src := range []*uuid.UUID{nil, &l.srcA2} {
		if code, body := l.post("/sightings", plainBound, ingestRoutes[1].body(l.wsA, src, "")); code != 401 {
			t.Errorf("enforce, source %v, with a raw-deleted source's token: %d %v, want 401", src, code, body)
		}
	}
	// Untouched: the workspace token and the token of another source.
	for id, plain := range map[uuid.UUID]string{wsID: plainWS, otherID: plainOther} {
		if r, _ := ingestTokenByID(t, l.db, id); r.RevokedAt != nil {
			t.Errorf("token %s was revoked by deleting another source", id)
		}
		if code, body := l.post("/sightings", plain, ingestRoutes[1].body(l.wsA, &l.srcA2, "")); !is2xx(code) {
			t.Errorf("surviving token %s: %d %v", id, code, body)
		}
	}
}

// (b), the rollout window itself: a bound token written while (a) did not yet
// exist -- source_bound false -- is still revoked and marked bound when its
// source is deleted without the application. Built inside a transaction with
// (a) disabled, and rolled back.
func TestP2IngestTokenTriggerCoversPreTriggerRows(t *testing.T) {
	l := newIngestLab(t)
	tx := l.db.Begin()
	if tx.Error != nil {
		t.Fatal(tx.Error)
	}
	defer tx.Rollback()
	if err := tx.Exec(`ALTER TABLE discovery_ingest_tokens DISABLE TRIGGER discovery_ingest_tokens_mark_bound`).Error; err != nil {
		t.Fatal(err)
	}
	_, id := rawToken(t, tx, l.wsA, &l.srcA1)
	if r, _ := ingestTokenByID(t, tx, id); r.SourceBound {
		t.Fatalf("setup: %+v, want a bound token with source_bound false", r)
	}
	if err := tx.Exec(`ALTER TABLE discovery_ingest_tokens ENABLE TRIGGER discovery_ingest_tokens_mark_bound`).Error; err != nil {
		t.Fatal(err)
	}
	if err := tx.Exec(`DELETE FROM discovery_sources WHERE id = ?`, l.srcA1).Error; err != nil {
		t.Fatalf("raw delete: %v", err)
	}
	r, found := ingestTokenByID(t, tx, id)
	if !found || r.DiscoverySourceID != nil || !r.SourceBound || r.RevokedAt == nil {
		t.Errorf("pre-trigger bound token after a raw source delete: %+v (found %v), want NULL source, bound, revoked", r, found)
	}
	var wide int64
	if err := tx.Raw(`SELECT count(*) FROM discovery_ingest_tokens WHERE id = ?
	    AND discovery_source_id IS NULL AND NOT source_bound AND revoked_at IS NULL`, id).Scan(&wide).Error; err != nil {
		t.Fatal(err)
	}
	if wide != 0 {
		t.Error("a bound token became a live workspace-wide token")
	}
}

// The application's DeleteSource (revoke in the transaction, then delete)
// still works with the trigger, and is idempotent with it: the app's
// revoked_at is the one kept, and a second delete is a clean not-found.
func TestP2IngestTokenTriggerAppDeleteSourceIdempotent(t *testing.T) {
	l := newIngestLab(t)
	_, id := l.mintRow(l.wsA, &l.srcA1, nil)
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(l.db))

	before := time.Now()
	if _, err := disco.DeleteSource(l.wsA, l.srcA1); err != nil {
		t.Fatalf("app delete source: %v", err)
	}
	r, found := ingestTokenByID(t, l.db, id)
	if !found || r.DiscoverySourceID != nil || !r.SourceBound || r.RevokedAt == nil {
		t.Fatalf("token after the app delete: %+v (found %v)", r, found)
	}
	if r.RevokedAt.Before(before.Add(-time.Minute)) {
		t.Errorf("revoked_at %v predates the delete", r.RevokedAt)
	}
	if _, err := disco.DeleteSource(l.wsA, l.srcA1); err == nil {
		t.Error("deleting the deleted source again succeeded")
	}
	again, _ := ingestTokenByID(t, l.db, id)
	if again.RevokedAt == nil || !again.RevokedAt.Equal(*r.RevokedAt) || !again.SourceBound {
		t.Errorf("a second delete moved the token: %+v -> %+v", r, again)
	}
}
