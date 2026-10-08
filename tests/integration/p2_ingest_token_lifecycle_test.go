package integration

// Ingest token lifecycle (044): deleting a discovery source revokes, never
// deletes, the tokens bound to it; a bound token whose source is gone is never
// valid; tokens may expire; and a deployment that is not enforcing says so.

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/controllers/shared"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"gorm.io/gorm"
)

type ingestTokenRow struct {
	ID                uuid.UUID
	DiscoverySourceID *uuid.UUID
	SourceBound       bool
	RevokedAt         *time.Time
	ExpiresAt         *time.Time
	LastUsedAt        *time.Time
}

func ingestTokenByID(t *testing.T, db *gorm.DB, id uuid.UUID) (ingestTokenRow, bool) {
	t.Helper()
	var rows []ingestTokenRow
	if err := db.Raw(`SELECT id, discovery_source_id, source_bound, revoked_at, expires_at, last_used_at
	    FROM discovery_ingest_tokens WHERE id = ?`, id).Scan(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		return ingestTokenRow{}, false
	}
	return rows[0], true
}

func (l *ingestLab) mintRow(ws uuid.UUID, src *uuid.UUID, expiresAt *time.Time) (string, uuid.UUID) {
	l.t.Helper()
	row, plain, err := l.tokens.Mint(ws, src, "lifecycle", "kh-test", expiresAt)
	if err != nil {
		l.t.Fatalf("mint: %v", err)
	}
	return plain, row.ID
}

// Deleting a source revokes its bound tokens in the same transaction and keeps
// them: revoked, source_bound, no source. They stop working; unbound tokens
// and tokens bound to other sources do not.
func TestP2IngestTokenSourceDeletionRevokes(t *testing.T) {
	l := newIngestLab(t)
	repo := repositories.NewDiscoveryIngestTokenRepository(l.db)

	tokBound, boundID := l.mintRow(l.wsA, &l.srcA1, nil)
	_, earlierID := l.mintRow(l.wsA, &l.srcA1, nil)
	earlier, err := l.tokens.Revoke(l.wsA, earlierID)
	if err != nil {
		t.Fatal(err)
	}
	tokWS, wsID := l.mintRow(l.wsA, nil, nil)
	tokOther, otherID := l.mintRow(l.wsA, &l.srcA2, nil)

	// Mint records the binding.
	for id, want := range map[uuid.UUID]bool{boundID: true, earlierID: true, wsID: false, otherID: true} {
		if r, _ := ingestTokenByID(t, l.db, id); r.SourceBound != want {
			t.Errorf("token %s: source_bound %v after mint, want %v", id, r.SourceBound, want)
		}
	}
	t.Setenv(services.DiscoveryIngestAuthEnv, "enforce")
	if code, body := l.post("/sightings", tokBound, ingestRoutes[1].body(l.wsA, &l.srcA1, "")); !is2xx(code) {
		t.Fatalf("bound token before the delete: %d %v", code, body)
	}

	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(l.db))
	if _, err := disco.DeleteSource(l.wsA, l.srcA1); err != nil {
		t.Fatalf("delete source: %v", err)
	}
	var srcLeft int64
	l.db.Table("discovery_sources").Where("id = ?", l.srcA1).Count(&srcLeft)
	if srcLeft != 0 {
		t.Fatal("the source was not deleted")
	}

	// Kept, revoked, unbound from the deleted row but still marked bound.
	for _, id := range []uuid.UUID{boundID, earlierID} {
		r, found := ingestTokenByID(t, l.db, id)
		if !found {
			t.Fatalf("token %s was deleted with its source", id)
		}
		if r.DiscoverySourceID != nil || !r.SourceBound || r.RevokedAt == nil {
			t.Errorf("token %s after the delete: source %v bound %v revoked %v, want NULL/true/set",
				id, r.DiscoverySourceID, r.SourceBound, r.RevokedAt)
		}
	}
	// A token revoked before the delete keeps when it was revoked.
	if r, _ := ingestTokenByID(t, l.db, earlierID); r.RevokedAt == nil || !r.RevokedAt.Equal(*earlier.RevokedAt) {
		t.Errorf("an already-revoked token's revoked_at moved: %v -> %v", earlier.RevokedAt, r.RevokedAt)
	}
	// Untouched: the workspace token and the token bound to another source.
	for _, id := range []uuid.UUID{wsID, otherID} {
		if r, _ := ingestTokenByID(t, l.db, id); r.RevokedAt != nil {
			t.Errorf("token %s was revoked by deleting another source", id)
		}
	}

	// The deleted source's token is refused, everywhere and in every shape of
	// call: as a bound token it never widens to the workspace.
	if v, err := repo.Verify(tokBound); err != nil || v != nil {
		t.Errorf("verify a token of a deleted source: %+v %v, want nil", v, err)
	}
	for _, r := range ingestRoutes {
		if code, body := l.post(r.path, tokBound, r.body(l.wsA, nil, "kh-a-other")); code != http.StatusUnauthorized {
			t.Errorf("enforce %s with a deleted source's token: %d %v, want 401", r.path, code, body)
		}
	}
	if code, body := l.post("/sightings", tokWS, ingestRoutes[1].body(l.wsA, &l.srcA2, "")); !is2xx(code) {
		t.Errorf("workspace token after another source's delete: %d %v", code, body)
	}
	if code, body := l.post("/sightings", tokOther, ingestRoutes[1].body(l.wsA, &l.srcA2, "")); !is2xx(code) {
		t.Errorf("token bound to a surviving source: %d %v", code, body)
	}
	t.Setenv(services.DiscoveryIngestAuthEnv, "warn")
	before := platform.DiscoveryIngestAuthCounts()
	if code, body := l.post("/sightings", tokBound, ingestRoutes[1].body(l.wsA, nil, "")); !is2xx(code) {
		t.Errorf("warn with a deleted source's token: %d %v, want accepted", code, body)
	}
	after := platform.DiscoveryIngestAuthCounts()
	if after["accepted_unauthenticated_invalid"]-before["accepted_unauthenticated_invalid"] != 1 ||
		after["accepted_token"] != before["accepted_token"] {
		t.Errorf("warn did not count a deleted source's token as invalid: %v -> %v", before, after)
	}

	// The list says what happened.
	list, err := l.tokens.List(l.wsA)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, r := range list {
		switch r.ID {
		case boundID:
			seen++
			if !r.SourceDeleted || !r.SourceBound || r.RevokedAt == nil || r.DiscoverySourceID != nil {
				t.Errorf("listed token of a deleted source: %+v", r)
			}
		case wsID, otherID:
			seen++
			if r.SourceDeleted || r.RevokedAt != nil {
				t.Errorf("listed surviving token: %+v", r)
			}
		}
	}
	if seen != 3 {
		t.Errorf("list showed %d of the 3 tokens", seen)
	}

	// The table refuses the state the delete path avoids: an unrevoked bound
	// token without a source.
	if err := l.db.Exec(`UPDATE discovery_ingest_tokens SET discovery_source_id = NULL WHERE id = ?`, otherID).Error; err == nil ||
		!strings.Contains(err.Error(), "discovery_ingest_tokens_bound_chk") {
		t.Errorf("unbinding a live bound token: %v, want discovery_ingest_tokens_bound_chk", err)
	}

	// Deleting a whole workspace still removes its tokens, live bound ones
	// included.
	wsC := newWorkspace(t, l.db, "kh-ingest-c")
	srcC := l.register(wsC, "kh-c1")
	_, cID := l.mintRow(wsC, &srcC, nil)
	if err := l.db.Exec(`DELETE FROM workspaces WHERE id = ?`, wsC).Error; err != nil {
		t.Fatalf("delete a workspace with a live bound token: %v", err)
	}
	if _, found := ingestTokenByID(t, l.db, cID); found {
		t.Error("a deleted workspace's token survived")
	}
}

// Defense in depth: a bound token whose source is NULL is refused by Verify
// even if it is somehow not revoked. The CHECK makes that row impossible, so
// it is built inside a transaction with the CHECK dropped, and rolled back.
func TestP2IngestTokenBoundWithoutSourceNeverVerifies(t *testing.T) {
	l := newIngestLab(t)
	plain, id := l.mintRow(l.wsA, &l.srcA1, nil)

	tx := l.db.Begin()
	if tx.Error != nil {
		t.Fatal(tx.Error)
	}
	defer tx.Rollback()
	if err := tx.Exec(`ALTER TABLE discovery_ingest_tokens DROP CONSTRAINT discovery_ingest_tokens_bound_chk`).Error; err != nil {
		t.Fatal(err)
	}
	if err := tx.Exec(`UPDATE discovery_ingest_tokens SET discovery_source_id = NULL WHERE id = ?`, id).Error; err != nil {
		t.Fatal(err)
	}
	r, _ := ingestTokenByID(t, tx, id)
	if r.DiscoverySourceID != nil || !r.SourceBound || r.RevokedAt != nil {
		t.Fatalf("setup: %+v, want an unrevoked bound token with no source", r)
	}

	if v, err := repositories.NewDiscoveryIngestTokenRepository(tx).Verify(plain); err != nil || v != nil {
		t.Errorf("verify an unrevoked bound token with no source: %+v %v, want nil", v, err)
	}
	svc := services.NewDiscoveryIngestTokens(tx)
	anySource := func() (*uuid.UUID, error) { return &l.srcA2, nil }
	for _, mode := range []services.DiscoveryIngestAuthMode{services.IngestAuthEnforce, services.IngestAuthWarn} {
		d, err := svc.Authorize(mode, plain, l.wsA, anySource)
		if err != nil {
			t.Fatal(err)
		}
		want := services.IngestRejectUnauthenticated
		if mode == services.IngestAuthWarn {
			want = services.IngestAcceptUnauthenticated
		}
		if d.Outcome != want || d.Token != nil {
			t.Errorf("%s: outcome %v token %v, want %v and no token", mode, d.Outcome, d.Token, want)
		}
	}
}

// An expired token is refused exactly like a revoked one: 401 in enforce,
// accepted-and-counted as invalid in warn, never attributed.
func TestP2IngestTokenExpiry(t *testing.T) {
	l := newIngestLab(t)
	repo := repositories.NewDiscoveryIngestTokenRepository(l.db)
	soon := time.Now().Add(time.Hour)
	tokLive, liveID := l.mintRow(l.wsA, nil, &soon)
	tokOld, oldID := l.mintRow(l.wsA, &l.srcA1, &soon)
	tokNever, _ := l.mintRow(l.wsA, nil, nil)

	t.Setenv(services.DiscoveryIngestAuthEnv, "enforce")
	for _, tok := range []string{tokLive, tokOld, tokNever} {
		if code, body := l.post("/sightings", tok, ingestRoutes[1].body(l.wsA, &l.srcA1, "")); !is2xx(code) {
			t.Fatalf("an unexpired token: %d %v", code, body)
		}
	}

	// Expire one (a mint cannot set a past expiry).
	if err := l.db.Exec(`UPDATE discovery_ingest_tokens SET expires_at = now() - interval '1 second', last_used_at = NULL WHERE id = ?`, oldID).Error; err != nil {
		t.Fatal(err)
	}
	if v, err := repo.Verify(tokOld); err != nil || v != nil {
		t.Errorf("verify an expired token: %+v %v, want nil", v, err)
	}
	for _, r := range ingestRoutes {
		if code, body := l.post(r.path, tokOld, r.body(l.wsA, &l.srcA1, "kh-a1")); code != http.StatusUnauthorized ||
			body["error"] != "ingest token required" {
			t.Errorf("enforce %s with an expired token: %d %v, want 401", r.path, code, body)
		}
	}
	if code, body := l.post("/sightings", tokLive, ingestRoutes[1].body(l.wsA, &l.srcA1, "")); !is2xx(code) {
		t.Errorf("an unexpired token beside an expired one: %d %v", code, body)
	}

	t.Setenv(services.DiscoveryIngestAuthEnv, "warn")
	before := platform.DiscoveryIngestAuthCounts()
	if code, body := l.post("/sightings", tokOld, ingestRoutes[1].body(l.wsA, &l.srcA1, "")); !is2xx(code) {
		t.Errorf("warn with an expired token: %d %v, want accepted", code, body)
	}
	after := platform.DiscoveryIngestAuthCounts()
	if after["accepted_unauthenticated_invalid"]-before["accepted_unauthenticated_invalid"] != 1 ||
		after["accepted_token"] != before["accepted_token"] {
		t.Errorf("warn did not count an expired token as invalid: %v -> %v", before, after)
	}
	if r, _ := ingestTokenByID(t, l.db, oldID); r.LastUsedAt != nil {
		t.Error("an expired token's last_used_at was written")
	}

	// The list shows the expiry and whether it has passed.
	list, err := l.tokens.List(l.wsA)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range list {
		switch r.ID {
		case oldID:
			if !r.Expired || r.ExpiresAt == nil {
				t.Errorf("listed expired token: expired %v expires_at %v", r.Expired, r.ExpiresAt)
			}
		case liveID:
			if r.Expired || r.ExpiresAt == nil || r.ExpiresAt.Sub(soon).Abs() > time.Millisecond {
				t.Errorf("listed live token: expired %v expires_at %v, want false and %v", r.Expired, r.ExpiresAt, soon)
			}
		default:
			if r.Expired || r.ExpiresAt != nil {
				t.Errorf("listed never-expiring token %s: expired %v expires_at %v", r.ID, r.Expired, r.ExpiresAt)
			}
		}
	}
	// Revoking an expired token still works and keeps it expired.
	rev, err := l.tokens.Revoke(l.wsA, oldID)
	if err != nil || rev.RevokedAt == nil || !rev.Expired {
		t.Errorf("revoke an expired token: %+v %v", rev, err)
	}
}

// Mint validates the expiry: in the future, at most two years away.
func TestP2IngestTokenMintExpiryValidation(t *testing.T) {
	l := newIngestLab(t)
	now := time.Now()
	for _, c := range []struct {
		name string
		at   time.Time
		ok   bool
	}{
		{"in the past", now.Add(-time.Minute), false},
		{"now", now, false},
		{"beyond two years", now.Add(repositories.MaxIngestTokenLifetime + time.Hour), false},
		{"just inside two years", now.Add(repositories.MaxIngestTokenLifetime - time.Hour), true},
		{"tomorrow", now.Add(24 * time.Hour), true},
	} {
		at := c.at
		row, _, err := l.tokens.Mint(l.wsA, nil, c.name, "kh-test", &at)
		if c.ok {
			if err != nil || row.ExpiresAt == nil || row.ExpiresAt.Sub(at).Abs() > time.Microsecond {
				t.Errorf("%s: %+v %v, want minted with that expiry", c.name, row, err)
				continue
			}
			if stored, _ := ingestTokenByID(t, l.db, row.ID); stored.ExpiresAt == nil || !stored.ExpiresAt.Equal(*row.ExpiresAt) {
				t.Errorf("%s: stored expires_at %v, returned %v", c.name, stored.ExpiresAt, row.ExpiresAt)
			}
		} else if err != repositories.ErrIngestTokenExpiry {
			t.Errorf("%s: %v, want ErrIngestTokenExpiry", c.name, err)
		}
	}
	var refusedRows int64
	l.db.Table("discovery_ingest_tokens").Where("workspace_id = ? AND label IN ?", l.wsA,
		[]string{"in the past", "now", "beyond two years"}).Count(&refusedRows)
	if refusedRows != 0 {
		t.Errorf("%d refused mints were stored", refusedRows)
	}

	// Through the endpoint.
	const base = "/authsec/discovery/ingest-tokens"
	admin := l.jwtFor(l.wsA, "discovery:admin")
	for _, c := range []struct {
		name string
		body map[string]any
	}{
		{"past", map[string]any{"expires_at": now.Add(-time.Hour).Format(time.RFC3339)}},
		{"beyond two years", map[string]any{"expires_at": now.AddDate(2, 1, 0).Format(time.RFC3339)}},
		{"not a timestamp", map[string]any{"expires_at": "tomorrow"}},
	} {
		if code, body, _ := l.do(http.MethodPost, base, admin, c.body); code != http.StatusBadRequest {
			t.Errorf("mint, expires_at %s: %d %v, want 400", c.name, code, body)
		}
	}
	exp := now.Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
	code, minted, raw := l.do(http.MethodPost, base, admin, map[string]any{
		"expires_at": exp.Format(time.RFC3339), "discovery_source_id": l.srcA1.String(), "label": "expiring"})
	if code != http.StatusCreated {
		t.Fatalf("mint with an expiry: %d %s", code, raw)
	}
	if got, _ := time.Parse(time.RFC3339Nano, minted["expires_at"].(string)); !got.Equal(exp) ||
		minted["source_bound"] != true || minted["expired"] != false {
		t.Errorf("mint response: %s", raw)
	}
	code, minted, raw = l.do(http.MethodPost, base, admin, nil)
	if code != http.StatusCreated || minted["expires_at"] != nil || minted["source_bound"] != false {
		t.Errorf("mint without an expiry: %d %s", code, raw)
	}

	// The list carries the lifecycle fields on every row, and still no
	// credential.
	code, list, raw := l.do(http.MethodGet, base, admin, nil)
	toks, _ := list["tokens"].([]any)
	if code != http.StatusOK || len(toks) == 0 {
		t.Fatalf("list: %d %s", code, raw)
	}
	for _, tk := range toks {
		m := tk.(map[string]any)
		for _, k := range []string{"expires_at", "expired", "source_bound", "source_deleted", "revoked_at"} {
			if _, has := m[k]; !has {
				t.Errorf("listed token %v has no %s", m["id"], k)
			}
		}
		if _, has := m["token_hash"]; has {
			t.Errorf("listed token %v carries its hash", m["id"])
		}
		if m["label"] == "expiring" {
			if got, _ := time.Parse(time.RFC3339Nano, m["expires_at"].(string)); !got.Equal(exp) || m["expired"] != false {
				t.Errorf("listed expiring token: %v", m)
			}
		}
	}
}

func discoveryIngestEnforcedGauge(t *testing.T) map[string]float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, mf := range mfs {
		if mf.GetName() != "discovery_ingest_auth_enforced" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "mode" {
					out[lp.GetValue()] = m.GetGauge().GetValue()
				}
			}
		}
	}
	return out
}

func captureLog(t *testing.T, f func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	f()
	return buf.String()
}

func ingestAuthHealthCheck(t *testing.T) map[string]any {
	t.Helper()
	if config.AppConfig == nil {
		config.AppConfig = &config.Config{}
		t.Cleanup(func() { config.AppConfig = nil })
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/authsec/uflow/health", nil)
	(&shared.HealthController{}).ComprehensiveHealthCheck(c)
	var body struct {
		Checks map[string]map[string]any `json:"checks"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("health body: %v %s", err, w.Body.String())
	}
	return body.Checks["discovery_ingest_auth"]
}

// Not enforcing is loud: a startup banner, discovery_ingest_auth_enforced = 0,
// and the health check says so. The default stays warn.
func TestP2IngestAuthNotEnforcedIsLoud(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Setenv(services.DiscoveryIngestAuthEnv, "")
	if st := services.CurrentDiscoveryIngestAuthStatus(); st.Mode != services.IngestAuthWarn || st.Enforced || st.Warning == "" {
		t.Errorf("default status: %+v, want warn, not enforced, with a warning", st)
	}

	for _, c := range []struct {
		env, mode string
		enforced  bool
	}{
		{"", "warn", false},
		{"off", "off", false},
		{"enforce", "enforce", true},
		{"warn", "warn", false},
	} {
		t.Setenv(services.DiscoveryIngestAuthEnv, c.env)
		out := captureLog(t, platform.LogDiscoveryIngestAuthMode)
		if !strings.Contains(out, "discovery ingress auth mode: "+c.mode) {
			t.Errorf("%q: startup log %q does not name the mode", c.env, out)
		}
		if banner := strings.Contains(out, "WARNING") && strings.Contains(out, services.DiscoveryIngestAuthEnv+"=enforce"); banner == c.enforced {
			t.Errorf("%q: banner %v, want %v; log:\n%s", c.env, banner, !c.enforced, out)
		}

		want := 0.0
		if c.enforced {
			want = 1
		}
		if g := discoveryIngestEnforcedGauge(t); len(g) != 1 || g[c.mode] != want {
			t.Errorf("%q: discovery_ingest_auth_enforced %v, want only {mode=%q} = %v", c.env, g, c.mode, want)
		}

		h := ingestAuthHealthCheck(t)
		if h == nil || h["mode"] != c.mode || h["enforced"] != c.enforced || h["healthy"] != true {
			t.Errorf("%q: health discovery_ingest_auth %v", c.env, h)
		}
		if _, warned := h["warning"]; warned == c.enforced {
			t.Errorf("%q: health warning present %v, want %v", c.env, warned, !c.enforced)
		}
	}
}
