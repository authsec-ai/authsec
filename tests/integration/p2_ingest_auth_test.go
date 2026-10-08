package integration

// Discovery ingress authentication (Kubernetes hardening item 1): ingest
// tokens are minted by a discovery:admin for the caller's own workspace, stored
// as sha256 only, and checked on every discovery ingress route under
// IGA_DISCOVERY_INGEST_AUTH = off | warn | enforce.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/middlewares"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const ingestJWTSecret = "kh-ingest-auth-jwt-secret"

type ingestLab struct {
	t        *testing.T
	db       *gorm.DB
	eng      *gin.Engine
	wsA, wsB uuid.UUID
	// srcA1/srcA2 are two self-registered sources of workspace A; srcB1 is B's.
	srcA1, srcA2, srcB1 uuid.UUID
	tokens              *services.DiscoveryIngestTokens
}

// newIngestLab builds two workspaces, registers agents in them with auth off,
// and an engine mounting the ingress handlers exactly as routes.go does (no
// AuthMiddleware) beside the token admin routes behind the production
// AuthMiddleware and permission middleware.
func newIngestLab(t *testing.T) *ingestLab {
	t.Helper()
	db := igaDB(t)
	gin.SetMode(gin.TestMode)
	t.Setenv("JWT_SDK_SECRET", ingestJWTSecret)
	t.Setenv("JWT_DEF_SECRET", ingestJWTSecret+"-default")
	t.Setenv("AUTH_EXPECT_ISS", "authsec-ai/auth-manager")
	t.Setenv("REQUIRE_SERVER_AUTH", "true")
	t.Setenv(services.GraphProjectionEnv, "off")
	t.Setenv(services.DiscoveryIngestAuthEnv, "off")

	l := &ingestLab{t: t, db: db, tokens: services.NewDiscoveryIngestTokens(db)}
	l.wsA = newWorkspace(t, db, "kh-ingest-a")
	l.wsB = newWorkspace(t, db, "kh-ingest-b")

	ctl := platform.NewDiscoveryController(db)
	eng := gin.New()
	ingress := eng.Group("/authsec/discovery")
	ingress.POST("/sightings", ctl.ReportSighting)
	ingress.POST("/agent-registration", ctl.RegisterAgent)
	ingress.POST("/lifecycle", ctl.ReportLifecycleEvent)
	ingress.POST("/rbac-snapshot", ctl.ReportRBACSnapshot)
	ingress.POST("/resync-manifest", ctl.ReportResyncManifest)
	admin := eng.Group("/authsec/discovery")
	admin.Use(middlewares.AuthMiddleware())
	platform.MountDiscoveryIngestTokenRoutes(admin, ctl, middlewares.Require)
	l.eng = eng

	l.srcA1 = l.register(l.wsA, "kh-a1")
	l.srcA2 = l.register(l.wsA, "kh-a2")
	l.srcB1 = l.register(l.wsB, "kh-b1")
	return l
}

func (l *ingestLab) register(ws uuid.UUID, instance string) uuid.UUID {
	l.t.Helper()
	code, body := l.post("/agent-registration", "", regBody(ws, instance))
	if code != http.StatusCreated {
		l.t.Fatalf("register %s: %d %v", instance, code, body)
	}
	id, err := uuid.Parse(body["discovery_source_id"].(string))
	if err != nil {
		l.t.Fatal(err)
	}
	return id
}

func (l *ingestLab) do(method, path, bearer string, body any) (int, map[string]any, string) {
	l.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	l.eng.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out, w.Body.String()
}

func (l *ingestLab) post(route, bearer string, body any) (int, map[string]any) {
	code, out, _ := l.do(http.MethodPost, "/authsec/discovery"+route, bearer, body)
	return code, out
}

// mint is a token through the service, as the admin endpoint mints it.
func (l *ingestLab) mint(ws uuid.UUID, src *uuid.UUID) (string, uuid.UUID) {
	l.t.Helper()
	row, plain, err := l.tokens.Mint(ws, src, "test", "kh-test", nil)
	if err != nil {
		l.t.Fatalf("mint: %v", err)
	}
	return plain, row.ID
}

// jwtFor is an admin session token for a workspace with the given scopes.
func (l *ingestLab) jwtFor(ws uuid.UUID, scope string) string {
	l.t.Helper()
	claims := jwt.MapClaims{
		"iss":          "authsec-ai/auth-manager",
		"exp":          time.Now().Add(time.Hour).Unix(),
		"workspace_id": ws.String(),
		"user_id":      uuid.NewString(),
	}
	if scope != "" {
		claims["scope"] = scope
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(ingestJWTSecret))
	if err != nil {
		l.t.Fatal(err)
	}
	return s
}

func regBody(ws uuid.UUID, instance string) map[string]any {
	return map[string]any{
		"workspace_id": ws.String(), "kind": "k8s_webhook",
		"instance_id": instance, "cluster_name": "cluster-" + instance,
	}
}

// ingestRoute is one ingress route with a well-formed body for workspace ws
// whose call resolves to source src (registration: the instance that owns it).
type ingestRoute struct {
	path string
	body func(ws uuid.UUID, src *uuid.UUID, instance string) map[string]any
}

func withSource(m map[string]any, src *uuid.UUID) map[string]any {
	if src != nil {
		m["discovery_source_id"] = src.String()
	}
	return m
}

var ingestRoutes = []ingestRoute{
	{"/agent-registration", func(ws uuid.UUID, _ *uuid.UUID, instance string) map[string]any {
		return regBody(ws, instance)
	}},
	{"/sightings", func(ws uuid.UUID, src *uuid.UUID, _ string) map[string]any {
		return withSource(map[string]any{"workspace_id": ws.String(), "source": "k8s_webhook",
			"fingerprint": "kh-fp-" + uuid.NewString()[:8], "display_name": "kh agent"}, src)
	}},
	{"/lifecycle", func(ws uuid.UUID, src *uuid.UUID, _ string) map[string]any {
		return withSource(map[string]any{"workspace_id": ws.String(), "source": "k8s_webhook",
			"fingerprint": "kh-fp-gone", "event": "deleted"}, src)
	}},
	{"/resync-manifest", func(ws uuid.UUID, src *uuid.UUID, _ string) map[string]any {
		return withSource(map[string]any{"workspace_id": ws.String(), "source": "k8s_webhook",
			"cluster": "cluster-kh-a1", "complete": false, "namespaces": []string{"default"},
			"fingerprints": []string{}}, src)
	}},
	{"/rbac-snapshot", func(ws uuid.UUID, src *uuid.UUID, _ string) map[string]any {
		return withSource(map[string]any{"workspace_id": ws.String(), "source": "k8s_webhook",
			"cluster": "cluster-kh-a1", "scan_kind": "full", "complete": false}, src)
	}},
}

func is2xx(code int) bool { return code >= 200 && code < 300 }

func sortedKeys(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// The matrix: every ingress route, every mode, every kind of credential.
func TestP2IngestAuthMatrix(t *testing.T) {
	l := newIngestLab(t)

	tokA, _ := l.mint(l.wsA, nil)
	tokA1, _ := l.mint(l.wsA, &l.srcA1)
	tokA2, _ := l.mint(l.wsA, &l.srcA2)
	tokB, _ := l.mint(l.wsB, nil)
	tokRevoked, revokedID := l.mint(l.wsA, nil)
	if _, err := l.tokens.Revoke(l.wsA, revokedID); err != nil {
		t.Fatal(err)
	}
	unknown, err := repositories.GenerateDiscoveryIngestToken() // well-formed, never minted
	if err != nil {
		t.Fatal(err)
	}

	const (
		ok   = 0 // 2xx
		u401 = http.StatusUnauthorized
		f403 = http.StatusForbidden
	)
	cases := []struct {
		name               string
		bearer             string
		off, warn, enforce int
	}{
		{"no token", "", ok, ok, u401},
		{"unknown token", unknown, ok, ok, u401},
		{"malformed token", "not-an-ingest-token", ok, ok, u401},
		{"revoked token", tokRevoked, ok, ok, u401},
		{"other workspace's token", tokB, ok, f403, f403},
		{"token bound to another source", tokA2, ok, ok, u401},
		{"token bound to this source", tokA1, ok, ok, ok},
		{"workspace token", tokA, ok, ok, ok},
	}

	// Accepted bodies are the handlers' own: the same keys with a token in
	// enforce as with auth off.
	offKeys := map[string]string{}
	for _, mode := range []string{"off", "warn", "enforce"} {
		t.Setenv(services.DiscoveryIngestAuthEnv, mode)
		for _, r := range ingestRoutes {
			for _, c := range cases {
				want := map[string]int{"off": c.off, "warn": c.warn, "enforce": c.enforce}[mode]
				code, body := l.post(r.path, c.bearer, r.body(l.wsA, &l.srcA1, "kh-a1"))
				label := mode + " " + r.path + " " + c.name
				switch want {
				case ok:
					if !is2xx(code) {
						t.Errorf("%s: %d %v, want 2xx", label, code, body)
						continue
					}
					if mode == "off" && c.bearer == "" {
						offKeys[r.path] = sortedKeys(body)
					} else if got := sortedKeys(body); offKeys[r.path] != "" && got != offKeys[r.path] {
						t.Errorf("%s: accepted body keys %q, want the unauthenticated body's %q", label, got, offKeys[r.path])
					}
				case u401:
					if code != u401 || len(body) != 1 || body["error"] != "ingest token required" {
						t.Errorf("%s: %d %v, want 401 {\"error\":\"ingest token required\"}", label, code, body)
					}
				case f403:
					if code != f403 {
						t.Errorf("%s: %d %v, want 403", label, code, body)
					}
				}
			}
		}
	}

	// A bound token on a call that names NO source does not resolve to its
	// source; nor does a registration that would create a new one.
	t.Setenv(services.DiscoveryIngestAuthEnv, "enforce")
	for _, r := range ingestRoutes[1:] {
		if code, body := l.post(r.path, tokA1, r.body(l.wsA, nil, "")); code != u401 {
			t.Errorf("enforce %s, bound token, no source named: %d %v, want 401", r.path, code, body)
		}
		if code, body := l.post(r.path, tokA, r.body(l.wsA, nil, "")); !is2xx(code) {
			t.Errorf("enforce %s, workspace token, no source named: %d %v, want 2xx", r.path, code, body)
		}
	}
	if code, body := l.post("/agent-registration", tokA1, regBody(l.wsA, "kh-a-new")); code != u401 {
		t.Errorf("enforce registration of a NEW instance with a bound token: %d %v, want 401", code, body)
	}
	if code, body := l.post("/agent-registration", tokA, regBody(l.wsA, "kh-a-new")); code != http.StatusCreated {
		t.Errorf("enforce registration of a new instance with a workspace token: %d %v, want 201", code, body)
	}

	// enforce does not tell an unauthenticated caller which workspaces exist:
	// an unknown workspace is 401 like a known one, and a real token for a
	// made-up workspace is 403.
	ghost := uuid.New()
	if code, body := l.post("/sightings", "", ingestRoutes[1].body(ghost, nil, "")); code != u401 {
		t.Errorf("enforce, no token, unknown workspace: %d %v, want 401", code, body)
	}
	if code, body := l.post("/sightings", tokA, ingestRoutes[1].body(ghost, nil, "")); code != f403 {
		t.Errorf("enforce, real token, unknown workspace: %d %v, want 403", code, body)
	}
	// A body workspace that is not a uuid stays the 400 it always was.
	if code, _ := l.post("/sightings", tokA, map[string]any{"workspace_id": "nope", "source": "k8s_webhook", "fingerprint": "x"}); code != http.StatusBadRequest {
		t.Errorf("malformed workspace: %d, want 400", code)
	}

	// An authenticated call is attributed to its token: last_used_at moved.
	var used int64
	l.db.Table("discovery_ingest_tokens").
		Where("token_hash = ? AND last_used_at IS NOT NULL", sha256Hex(tokA)).Count(&used)
	if used != 1 {
		t.Errorf("the workspace token's last_used_at was not recorded")
	}
}

// warn mode accepts an unauthenticated call but counts it.
func TestP2IngestAuthWarnCounts(t *testing.T) {
	l := newIngestLab(t)
	t.Setenv(services.DiscoveryIngestAuthEnv, "warn")
	before := platform.DiscoveryIngestAuthCounts()
	tokA, _ := l.mint(l.wsA, nil)
	for _, r := range ingestRoutes {
		if code, body := l.post(r.path, "", r.body(l.wsA, &l.srcA1, "kh-a1")); !is2xx(code) {
			t.Fatalf("warn %s without a token: %d %v", r.path, code, body)
		}
		if code, body := l.post(r.path, tokA, r.body(l.wsA, &l.srcA1, "kh-a1")); !is2xx(code) {
			t.Fatalf("warn %s with a token: %d %v", r.path, code, body)
		}
	}
	after := platform.DiscoveryIngestAuthCounts()
	n := int64(len(ingestRoutes))
	if got := after["accepted_unauthenticated_missing"] - before["accepted_unauthenticated_missing"]; got != n {
		t.Errorf("accepted_unauthenticated_missing grew by %d, want %d", got, n)
	}
	if got := after["accepted_token"] - before["accepted_token"]; got != n {
		t.Errorf("accepted_token grew by %d, want %d", got, n)
	}
	// An unknown workspace is not counted against a workspace that does not
	// exist: the call is the 400 it always was, and nothing is recorded.
	before = platform.DiscoveryIngestAuthCounts()
	if code, _ := l.post("/sightings", "", ingestRoutes[1].body(uuid.New(), nil, "")); code != http.StatusBadRequest {
		t.Errorf("warn, unknown workspace: %d, want 400", code)
	}
	after = platform.DiscoveryIngestAuthCounts()
	if after["accepted_unauthenticated_missing"] != before["accepted_unauthenticated_missing"] {
		t.Errorf("an unknown workspace's call was counted")
	}
}

func TestP2IngestAuthModeFromEnv(t *testing.T) {
	for raw, want := range map[string]services.DiscoveryIngestAuthMode{
		"": services.IngestAuthWarn, "warn": services.IngestAuthWarn, " OFF ": services.IngestAuthOff,
		"Enforce": services.IngestAuthEnforce, "enforced": services.IngestAuthEnforce, "on": services.IngestAuthEnforce,
	} {
		t.Setenv(services.DiscoveryIngestAuthEnv, raw)
		if got := services.DiscoveryIngestAuthModeFromEnv(); got != want {
			t.Errorf("%q -> %q, want %q", raw, got, want)
		}
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Mint, list, revoke at the repository: the plaintext is returned once and
// only its sha256 is stored; a list never reads a hash.
func TestP2IngestTokenStore(t *testing.T) {
	l := newIngestLab(t)
	row, plain, err := l.tokens.Mint(l.wsA, &l.srcA1, "  lab  ", "kh-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(plain, "aid_") || len(plain) != 47 {
		t.Errorf("token %q: want aid_ + 43 base64url characters", plain)
	}
	if row.TokenPrefix != plain[:8] || row.Label != "lab" {
		t.Errorf("row prefix %q label %q", row.TokenPrefix, row.Label)
	}

	// What is on disk: the hash of the token, nothing that contains it.
	var stored map[string]any
	if err := l.db.Raw(`SELECT * FROM discovery_ingest_tokens WHERE id = ?`, row.ID).Scan(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if stored["token_hash"] != sha256Hex(plain) {
		t.Errorf("token_hash %v, want sha256(token)", stored["token_hash"])
	}
	for col, v := range stored {
		if s, ok := v.(string); ok && strings.Contains(s, plain[8:]) {
			t.Errorf("column %s holds the token", col)
		}
	}

	// Another mint never repeats a token.
	_, plain2, _ := l.tokens.Mint(l.wsA, nil, "", "kh-test", nil)
	if plain2 == plain {
		t.Error("two mints returned the same token")
	}

	// List: the workspace's tokens, no hash, never another workspace's.
	_, _, _ = l.tokens.Mint(l.wsB, nil, "", "kh-test", nil)
	list, err := l.tokens.List(l.wsA)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("list A: %d tokens, want 2", len(list))
	}
	for _, r := range list {
		if r.TokenHash != "" || r.WorkspaceID != l.wsA {
			t.Errorf("listed row %s: hash %q workspace %s", r.ID, r.TokenHash, r.WorkspaceID)
		}
	}

	// Binding to another workspace's source is refused.
	if _, _, err := l.tokens.Mint(l.wsA, &l.srcB1, "", "kh-test", nil); err != repositories.ErrIngestTokenSourceNotFound {
		t.Errorf("mint A bound to B's source: %v, want ErrIngestTokenSourceNotFound", err)
	}

	// Verify finds a live token; revocation is a timestamp, kept, and stops it.
	repo := repositories.NewDiscoveryIngestTokenRepository(l.db)
	if v, err := repo.Verify(plain); err != nil || v == nil || v.ID != row.ID || v.TokenHash != "" {
		t.Fatalf("verify live: %+v %v", v, err)
	}
	if _, err := l.tokens.Revoke(l.wsB, row.ID); err != repositories.ErrIngestTokenNotFound {
		t.Errorf("revoke A's token as B: %v, want not found", err)
	}
	if v, _ := repo.Verify(plain); v == nil {
		t.Fatal("a revoke by another workspace stopped the token")
	}
	r1, err := l.tokens.Revoke(l.wsA, row.ID)
	if err != nil || r1.RevokedAt == nil {
		t.Fatalf("revoke: %+v %v", r1, err)
	}
	r2, _ := l.tokens.Revoke(l.wsA, row.ID)
	if r2 == nil || r2.RevokedAt == nil || !r2.RevokedAt.Equal(*r1.RevokedAt) {
		t.Errorf("a second revoke moved revoked_at")
	}
	if v, err := repo.Verify(plain); err != nil || v != nil {
		t.Errorf("verify revoked: %+v %v, want nil", v, err)
	}
	if v, _ := repo.Verify(plain[:46] + "A"); v != nil {
		t.Error("verify accepted a different token")
	}
}

// last_used_at is written at most once a minute per token.
func TestP2IngestTokenLastUsedThrottle(t *testing.T) {
	l := newIngestLab(t)
	repo := repositories.NewDiscoveryIngestTokenRepository(l.db)
	plain, id := l.mint(l.wsA, nil)
	lastUsed := func() *time.Time {
		var r struct{ LastUsedAt *time.Time }
		l.db.Raw(`SELECT last_used_at FROM discovery_ingest_tokens WHERE id = ?`, id).Scan(&r)
		return r.LastUsedAt
	}
	if lastUsed() != nil {
		t.Fatal("a new token has a last_used_at")
	}
	if v, _ := repo.Verify(plain); v == nil {
		t.Fatal("verify")
	}
	first := lastUsed()
	if first == nil {
		t.Fatal("first use not recorded")
	}
	time.Sleep(20 * time.Millisecond)
	for i := 0; i < 3; i++ {
		_, _ = repo.Verify(plain)
	}
	if again := lastUsed(); again == nil || !again.Equal(*first) {
		t.Errorf("last_used_at moved within the minute: %v -> %v", first, again)
	}
	// A minute later it moves again.
	l.db.Exec(`UPDATE discovery_ingest_tokens SET last_used_at = now() - interval '61 seconds' WHERE id = ?`, id)
	stale := lastUsed()
	_, _ = repo.Verify(plain)
	if moved := lastUsed(); moved == nil || !moved.After(*stale) {
		t.Errorf("last_used_at did not move after a minute: %v -> %v", stale, moved)
	}
	// Through the ingress, too: an enforce call within the minute does not
	// write it again.
	t.Setenv(services.DiscoveryIngestAuthEnv, "enforce")
	cur := lastUsed()
	if code, body := l.post("/sightings", plain, ingestRoutes[1].body(l.wsA, &l.srcA1, "")); !is2xx(code) {
		t.Fatalf("sighting: %d %v", code, body)
	}
	if after := lastUsed(); after == nil || !after.Equal(*cur) {
		t.Errorf("an ingress call within the minute wrote last_used_at: %v -> %v", cur, after)
	}
}

// The admin endpoints: authenticated, discovery:admin, workspace from the
// caller's token, never the body.
func TestP2IngestTokenAdminEndpoints(t *testing.T) {
	l := newIngestLab(t)
	const base = "/authsec/discovery/ingest-tokens"
	adminA := l.jwtFor(l.wsA, "discovery:admin")
	adminB := l.jwtFor(l.wsB, "discovery:admin")

	for _, c := range []struct {
		name, bearer string
		want         int
	}{
		{"no session", "", http.StatusUnauthorized},
		{"an ingest token is not a session", "aid_" + strings.Repeat("A", 43), http.StatusUnauthorized},
		{"no scope", l.jwtFor(l.wsA, ""), http.StatusForbidden},
		{"discovery:read only", l.jwtFor(l.wsA, "discovery:read"), http.StatusForbidden},
	} {
		for _, m := range []struct{ method, path string }{
			{http.MethodPost, base}, {http.MethodGet, base}, {http.MethodDelete, base + "/" + uuid.NewString()},
		} {
			if code, body, _ := l.do(m.method, m.path, c.bearer, map[string]any{}); code != c.want {
				t.Errorf("%s %s, %s: %d %v, want %d", m.method, m.path, c.name, code, body, c.want)
			}
		}
	}

	// Naming B in the body is refused as not found: AuthMiddleware rejects any
	// body workspace other than the token's (ADR-0001 §4.1).
	if code, _, raw := l.do(http.MethodPost, base, adminA, map[string]any{"workspace_id": l.wsB.String(), "label": "prod"}); code != http.StatusNotFound {
		t.Fatalf("mint naming another workspace: %d %s, want 404", code, raw)
	}
	// Mint as A: the token is A's.
	code, minted, raw := l.do(http.MethodPost, base, adminA, map[string]any{"label": "prod"})
	if code != http.StatusCreated {
		t.Fatalf("mint: %d %s", code, raw)
	}
	plain, _ := minted["token"].(string)
	if !strings.HasPrefix(plain, "aid_") || minted["token_prefix"] != plain[:8] ||
		minted["workspace_id"] != l.wsA.String() || minted["label"] != "prod" || minted["id"] == nil {
		t.Errorf("mint response %s", raw)
	}
	if _, has := minted["token_hash"]; has {
		t.Error("mint response carries the hash")
	}
	id := minted["id"].(string)

	// An empty body is an unbound token; binding to A's source works, to B's
	// is not found.
	if code, _, raw := l.do(http.MethodPost, base, adminA, nil); code != http.StatusCreated {
		t.Errorf("mint, empty body: %d %s", code, raw)
	}
	if code, body, _ := l.do(http.MethodPost, base, adminA, map[string]any{"discovery_source_id": l.srcA1.String()}); code != http.StatusCreated || body["discovery_source_id"] != l.srcA1.String() {
		t.Errorf("mint bound to A's source: %d %v", code, body)
	}
	if code, body, _ := l.do(http.MethodPost, base, adminA, map[string]any{"discovery_source_id": l.srcB1.String()}); code != http.StatusNotFound {
		t.Errorf("mint bound to B's source as A: %d %v, want 404", code, body)
	}
	if code, _, _ := l.do(http.MethodPost, base, adminA, map[string]any{"discovery_source_id": "nope"}); code != http.StatusBadRequest {
		t.Errorf("mint with a malformed source id: %d, want 400", code)
	}

	// The minted token works on the ingress in enforce.
	t.Setenv(services.DiscoveryIngestAuthEnv, "enforce")
	if code, body := l.post("/sightings", plain, ingestRoutes[1].body(l.wsA, &l.srcA1, "")); !is2xx(code) {
		t.Errorf("sighting with the minted token: %d %v", code, body)
	}

	// List: A's three, no plaintext, no hash; B sees none of them.
	code, list, raw := l.do(http.MethodGet, base, adminA, nil)
	toks, _ := list["tokens"].([]any)
	if code != http.StatusOK || len(toks) != 3 {
		t.Fatalf("list A: %d %s", code, raw)
	}
	if strings.Contains(raw, plain) || strings.Contains(raw, sha256Hex(plain)) || strings.Contains(raw, "token_hash") || strings.Contains(raw, `"token"`) {
		t.Errorf("list carries a credential: %s", raw)
	}
	if _, _, rawB := l.do(http.MethodGet, base, adminB, nil); strings.Contains(rawB, id) {
		t.Errorf("B's list shows A's token: %s", rawB)
	}

	// Revoke: B cannot reach A's token; A can, and the token stops working.
	if code, _, _ := l.do(http.MethodDelete, base+"/"+id, adminB, nil); code != http.StatusNotFound {
		t.Errorf("revoke A's token as B: %d, want 404", code)
	}
	if code, body := l.post("/sightings", plain, ingestRoutes[1].body(l.wsA, &l.srcA1, "")); !is2xx(code) {
		t.Errorf("B's revoke attempt stopped A's token: %d %v", code, body)
	}
	code, rev, raw := l.do(http.MethodDelete, base+"/"+id, adminA, nil)
	if code != http.StatusOK || rev["revoked_at"] == nil || strings.Contains(raw, "token_hash") {
		t.Errorf("revoke: %d %s", code, raw)
	}
	if code, body := l.post("/sightings", plain, ingestRoutes[1].body(l.wsA, &l.srcA1, "")); code != http.StatusUnauthorized {
		t.Errorf("revoked token on the ingress: %d %v, want 401", code, body)
	}
	if code, _, _ := l.do(http.MethodDelete, base+"/not-a-uuid", adminA, nil); code != http.StatusBadRequest {
		t.Errorf("revoke malformed id: %d, want 400", code)
	}
}
