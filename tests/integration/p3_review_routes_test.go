package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/internal/notify"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/monitoring"
	"github.com/authsec-ai/authsec/services"
)

// T3.12 / T3.20 routes through the production chain (routes.SetupIGARoutes
// with the real AuthMiddleware and permission middleware): §7.4 reviews and
// §7.8 settings, incl. the legacy channel copy and a signed webhook notice.

func p3Audit(t *testing.T, db *gorm.DB, wss ...uuid.UUID) {
	t.Helper()
	p3MetricsOnce.Do(func() {
		if monitoring.GetLogger() == nil {
			monitoring.InitMetrics()
		}
	})
	prev := config.AuditLogger
	config.AuditLogger = monitoring.NewAuditLogger(db)
	t.Cleanup(func() {
		config.AuditLogger = prev
		for _, ws := range wss {
			db.Exec(`DELETE FROM audit_events WHERE workspace_id = ?`, ws.String())
		}
	})
}

// p3WaitAudit waits for the audit_events row of one request (written
// asynchronously by the audit logger).
func p3WaitAudit(t *testing.T, db *gorm.DB, ws uuid.UUID, method, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var n int64
		db.Raw(`SELECT count(*) FROM audit_events WHERE workspace_id = ? AND method = ? AND path = ?`, ws.String(), method, path).Scan(&n)
		if n > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no audit_events row for %s %s in %s", method, path, ws)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (g *p3Gov) membershipOf(user uuid.UUID) uuid.UUID {
	g.t.Helper()
	var ids []uuid.UUID
	if err := g.db.Raw(`SELECT id FROM workspace_memberships WHERE workspace_id = ? AND user_id = ?`, g.ws, user).Scan(&ids).Error; err != nil || len(ids) != 1 {
		g.t.Fatalf("membership of %s: %v %v", user, ids, err)
	}
	return ids[0]
}

func (a *p3OwnersAPI) raw(method, path, bearer string) (int, http.Header, []byte) {
	a.t.Helper()
	req := httptest.NewRequest(method, "/api/iga/v1/policy"+path, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	a.eng.ServeHTTP(w, req)
	return w.Code, w.Header(), w.Body.Bytes()
}

// §7.4 routes: member reads (mine), the owner-or-governance:read rule,
// respond by owners only, exception by approvers who are not the author,
// remind by authors, 404 for another workspace's review on every route,
// review_closed after the exception; each mutation an event and an
// audit_events row.
func TestP3T312ReviewRoutes(t *testing.T) {
	db := igaDB(t)
	api := p3NewOwnersAPI(t, db)
	g := p3NewGov(t, db, "p3notify-review-routes")
	other := p3NewGov(t, db, "p3notify-review-routes-other")
	p3Audit(t, db, g.ws, other.ws)
	svc := services.NewIGAGovOwnerReviewService(db)

	role, rid := g.identity("RouteRole", nil)
	w1 := g.workload("route-agent", &role, models.RelTypeExecutesAs)
	w2 := g.workload("route-batch", &role, models.RelTypeExecutesAs)
	u1, m1 := g.member("u1-routes@p3notify.test", "Una One", "active")
	u2, m2 := g.member("u2-routes@p3notify.test", "Uli Two", "active")
	outsider, mo := g.member("out-routes@p3notify.test", "Otto Out", "active")
	p3Manual(t, db, g, models.GovObjectWorkload, w1, u1, models.GovOwnerAccountable)
	p3Manual(t, db, g, models.GovObjectWorkload, w2, u2, models.GovOwnerAccountable)
	rev := g.reviewVersion(nil, 1, map[string]string{"sqs": igagov.GrantAgePredatesObservation},
		p3RevTarget{identity: role, roleID: rid, name: "RouteRole", removed: []string{"sqs"}, retained: []string{"s3"}})
	sync, err := svc.OpenReview(context.Background(), g.ws, rev.version, g.author)
	if err != nil {
		t.Fatal(err)
	}
	rp := "/reviews/" + sync.ReviewID.String()

	t1 := api.token(g.ws, u1, m1, "")
	t2 := api.token(g.ws, u2, m2, "")
	tOut := api.token(g.ws, outsider, mo, "")
	reader := api.token(g.ws, outsider, mo, "governance:read")
	approver := api.token(g.ws, g.approver, g.membershipOf(g.approver), "governance:read governance:approve")
	author := api.token(g.ws, g.author, g.authorMember, "governance:read governance:author governance:approve")
	service := api.token(g.ws, uuid.New(), uuid.Nil, "governance:read governance:approve governance:author")
	otherTok := api.token(other.ws, other.author, other.authorMember, "governance:read governance:approve governance:author")

	// GET /reviews?mine=true: the owner's own list.
	code, body := api.call(http.MethodGet, "/reviews?mine=true", t1, nil)
	if code != http.StatusOK || len(body["data"].([]any)) != 1 || dig(body, "data", 0, "asked") != true || dig(body, "data", 0, "owners_asked") != float64(2) {
		t.Fatalf("mine: %d %v", code, body)
	}
	if code, body := api.call(http.MethodGet, "/reviews?mine=true", tOut, nil); code != http.StatusOK || len(body["data"].([]any)) != 0 {
		t.Fatalf("outsider mine: %d %v", code, body)
	}
	if code, _ := api.call(http.MethodGet, "/reviews?mine=true", service, nil); code != http.StatusForbidden {
		t.Fatalf("mine with a service token: %d", code)
	}
	// All reviews needs governance:read.
	if code, body := api.call(http.MethodGet, "/reviews", t1, nil); code != http.StatusForbidden || errCode(body) == "" {
		t.Fatalf("list without governance:read: %d %v", code, body)
	}
	if code, body := api.call(http.MethodGet, "/reviews?status=open,reopened", reader, nil); code != http.StatusOK || len(body["data"].([]any)) != 1 {
		t.Fatalf("list as reader: %d %v", code, body)
	}
	if code, body := api.call(http.MethodGet, "/reviews?status=bogus", reader, nil); code != http.StatusBadRequest {
		t.Fatalf("bad status: %d %v", code, body)
	}
	// GET /reviews/:id: an owner without any permission; a non-owner needs
	// governance:read; another workspace (or a bad id) is 404.
	code, body = api.call(http.MethodGet, rp, t1, nil)
	if code != http.StatusOK || dig(body, "data", "viewer_is_owner") != true || digs(body, "data", "requested", "age_confirmations", 0, "service") != "sqs" ||
		dig(body, "data", "my_response") == nil || digs(body, "data", "gate", "code") != "review_incomplete" {
		t.Fatalf("GET as owner: %d %v", code, body)
	}
	if code, _ := api.call(http.MethodGet, rp, tOut, nil); code != http.StatusForbidden {
		t.Fatalf("GET as a non-owner without governance:read: %d", code)
	}
	if code, body := api.call(http.MethodGet, rp, reader, nil); code != http.StatusOK || dig(body, "data", "viewer_is_owner") != false {
		t.Fatalf("GET as reader: %d %v", code, body)
	}
	for _, p := range []string{rp, "/reviews/not-a-uuid", "/reviews/" + uuid.NewString()} {
		if code, body := api.call(http.MethodGet, p, otherTok, nil); code != http.StatusNotFound || errCode(body) != "not_found" {
			t.Fatalf("GET %s from another workspace: %d %v", p, code, body)
		}
	}
	// Respond: owners only; strict bodies.
	if code, body := api.call(http.MethodPost, rp+"/respond", tOut, map[string]any{"response": "acknowledge"}); code != http.StatusForbidden || errCode(body) != "not_review_owner" {
		t.Fatalf("respond as non-owner: %d %v", code, body)
	}
	if code, body := api.call(http.MethodPost, rp+"/respond", t1, map[string]any{"response": "acknowledge", "workspace_id": other.ws}); code != http.StatusBadRequest {
		t.Fatalf("unknown body member: %d %v", code, body)
	}
	if code, body := api.call(http.MethodPost, rp+"/respond", t1, map[string]any{"response": "retain"}); code != http.StatusBadRequest || digs(body, "error", "detail", "parameter") != "retain_items" {
		t.Fatalf("retain without items: %d %v", code, body)
	}
	code, body = api.call(http.MethodPost, rp+"/respond", t1, map[string]any{"response": "acknowledge",
		"age_confirmations": []map[string]any{{"service": "sqs", "confirmed": true}}, "comment": "fine by me"})
	if code != http.StatusOK || digs(body, "data", "review_status") != "open" || digs(body, "data", "response", "response") != "acknowledge" {
		t.Fatalf("respond: %d %v", code, body)
	}
	// Remind: authors; reminds u2 only.
	if code, _ := api.call(http.MethodPost, rp+"/remind", t1, nil); code != http.StatusForbidden {
		t.Fatalf("remind without governance:author: %d", code)
	}
	code, body = api.call(http.MethodPost, rp+"/remind", author, nil)
	if code != http.StatusOK || len(body["data"].(map[string]any)["reminded_user_ids"].([]any)) != 1 || digs(body, "data", "reminded_user_ids", 0) != u2.String() {
		t.Fatalf("remind: %d %v", code, body)
	}
	// Exception: approvers who did not author the version.
	if code, body := api.call(http.MethodPost, rp+"/exception", author, map[string]any{"reason": "x"}); code != http.StatusForbidden || errCode(body) != "self_approval" {
		t.Fatalf("author's exception: %d %v", code, body)
	}
	if code, _ := api.call(http.MethodPost, rp+"/exception", reader, map[string]any{"reason": "x"}); code != http.StatusForbidden {
		t.Fatalf("exception without governance:approve: %d", code)
	}
	if code, body := api.call(http.MethodPost, rp+"/exception", approver, map[string]any{}); code != http.StatusBadRequest {
		t.Fatalf("exception without reason: %d %v", code, body)
	}
	// Another workspace: 404 on every mutation, and nothing written there.
	for p, b := range map[string]any{"/respond": map[string]any{"response": "acknowledge"}, "/remind": nil, "/exception": map[string]any{"reason": "x"}} {
		if code, body := api.call(http.MethodPost, rp+p, otherTok, b); code != http.StatusNotFound || errCode(body) != "not_found" {
			t.Fatalf("POST %s from another workspace: %d %v", p, code, body)
		}
	}
	code, body = api.call(http.MethodPost, rp+"/exception", approver, map[string]any{"reason": "Uli is away; Una confirmed"})
	if code != http.StatusOK || digs(body, "data", "status") != "excepted" {
		t.Fatalf("exception: %d %v", code, body)
	}
	if code, body := api.call(http.MethodPost, rp+"/respond", t2, map[string]any{"response": "acknowledge"}); code != http.StatusConflict || errCode(body) != "review_closed" {
		t.Fatalf("respond after the exception: %d %v", code, body)
	}
	if code, body := api.call(http.MethodPost, rp+"/remind", author, nil); code != http.StatusConflict || errCode(body) != "review_closed" {
		t.Fatalf("remind after the exception: %d %v", code, body)
	}
	// Events and audit.
	var names []string
	for _, e := range g.eventsNamed("review.") {
		names = append(names, e.Event)
		if e.PolicyID == nil || *e.PolicyID != rev.policy || e.VersionID == nil || *e.VersionID != rev.version {
			t.Fatalf("event %s without its policy/version", e.Event)
		}
	}
	if strings.Join(names, ",") != "review.opened,review.responded,review.reminded,review.excepted" {
		t.Fatalf("review events %v", names)
	}
	var otherEvents int64
	db.Raw(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ?`, other.ws).Scan(&otherEvents)
	if otherEvents != 0 {
		t.Fatalf("refused cross-workspace calls wrote %d events", otherEvents)
	}
	for _, p := range []string{"/respond", "/remind", "/exception"} {
		p3WaitAudit(t, db, g.ws, http.MethodPost, "/api/iga/v1/policy"+rp+p)
	}
}

/* ------------------------------- settings --------------------------------- */

// p3ChannelStore is an in-memory GovNotificationChannelStore: what the
// pending DDL's implementation will hold, so the copy, the API and the
// webhook target are tested now.
type p3ChannelStore struct {
	mu   sync.Mutex
	rows map[uuid.UUID]services.GovNotificationChannels
}

func (s *p3ChannelStore) Available() (bool, string) { return true, "" }
func (s *p3ChannelStore) GetTx(_ *gorm.DB, ws uuid.UUID) (*services.GovNotificationChannels, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.rows[ws]
	if !ok {
		return nil, false, nil
	}
	return &c, true, nil
}
func (s *p3ChannelStore) SaveTx(_ *gorm.DB, ws uuid.UUID, ch services.GovNotificationChannels) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[ws] = ch
	return nil
}

func p3LegacyRow(t *testing.T, db *gorm.DB, ws uuid.UUID) string {
	t.Helper()
	var s []string
	db.Raw(`SELECT row_to_json(x)::text FROM governance_notification_settings x WHERE workspace_id = ?`, ws).Scan(&s)
	if len(s) != 1 {
		return ""
	}
	return s[0]
}

// §7.8 settings: defaults; enforce needs a reason; ranges, unknown fields
// and stale writes refused; channels unavailable until the DDL lands; with
// a store, the legacy channel addresses are COPIED on first read (the
// legacy row unchanged), PUT stores them without echoing the secret, email
// off makes an owner's delivery fail at once, and the workspace webhook is
// sent signed.
func TestP3T320Settings(t *testing.T) {
	db := igaDB(t)
	api := p3NewOwnersAPI(t, db)
	g := p3NewGov(t, db, "p3notify-settings")
	other := p3NewGov(t, db, "p3notify-settings-other")
	p3Audit(t, db, g.ws, other.ws)
	reader := api.token(g.ws, g.author, g.authorMember, "governance:read")
	enforcer := api.token(g.ws, g.author, g.authorMember, "governance:read governance:enforce")
	service := api.token(g.ws, uuid.New(), uuid.Nil, "governance:read governance:enforce")
	otherTok := api.token(other.ws, other.author, other.authorMember, "governance:read governance:enforce")

	code, body := api.call(http.MethodGet, "/settings", reader, nil)
	if code != http.StatusOK || digs(body, "data", "enforcement_mode") != "findings_only" || dig(body, "data", "saved") != false ||
		dig(body, "data", "owner_review_days") != float64(3) || dig(body, "data", "notifications", "available") != false ||
		digs(body, "data", "notifications", "reason") == "" || dig(body, "data", "notifications", "email_enabled") != true {
		t.Fatalf("GET defaults: %d %v", code, body)
	}
	if code, _ := api.call(http.MethodPut, "/settings", reader, map[string]any{"canary_hours": 24}); code != http.StatusForbidden {
		t.Fatalf("PUT with governance:read: %d", code)
	}
	if code, _ := api.call(http.MethodPut, "/settings", service, map[string]any{"canary_hours": 24}); code != http.StatusForbidden {
		t.Fatalf("PUT with a service token: %d", code)
	}
	if code, body := api.call(http.MethodPut, "/settings", enforcer, map[string]any{"enforcement_mode": "enforce"}); code != http.StatusBadRequest ||
		digs(body, "error", "detail", "parameter") != "reason" {
		t.Fatalf("enforce without reason: %d %v", code, body)
	}
	code, body = api.call(http.MethodPut, "/settings", enforcer, map[string]any{"enforcement_mode": "enforce", "reason": "pilot account approved by CAB-112",
		"workspace_id": nil})
	if code != http.StatusBadRequest {
		t.Fatalf("unknown member accepted: %d %v", code, body)
	}
	code, body = api.call(http.MethodPut, "/settings", enforcer, map[string]any{"enforcement_mode": "enforce", "reason": "pilot account approved by CAB-112"})
	if code != http.StatusOK || digs(body, "data", "enforcement_mode") != "enforce" || dig(body, "data", "saved") != true {
		t.Fatalf("enforce: %d %v", code, body)
	}
	stamp := digs(body, "data", "updated_at")
	for name, b := range map[string]map[string]any{
		"range":   {"owner_review_days": 31},
		"range2":  {"evidence_retention_revs": 4},
		"mode":    {"enforcement_mode": "yolo"},
		"unknown": {"bogus": 1},
	} {
		if code, body := api.call(http.MethodPut, "/settings", enforcer, b); code != http.StatusBadRequest {
			t.Fatalf("%s: %d %v", name, code, body)
		}
	}
	if code, body := api.call(http.MethodPut, "/settings", enforcer, map[string]any{"canary_hours": 24, "expected_updated_at": "2001-01-01T00:00:00Z"}); code != http.StatusConflict ||
		errCode(body) != "version_conflict" {
		t.Fatalf("stale write: %d %v", code, body)
	}
	if code, body := api.call(http.MethodPut, "/settings", enforcer, map[string]any{"canary_hours": 24, "expected_updated_at": stamp}); code != http.StatusOK ||
		dig(body, "data", "canary_hours") != float64(24) {
		t.Fatalf("fresh write: %d %v", code, body)
	}
	if code, body := api.call(http.MethodPut, "/settings", enforcer, map[string]any{"notifications": map[string]any{"webhook_url": "https://hooks.example.test/a"}}); code != http.StatusConflict ||
		errCode(body) != "notification_settings_unavailable" {
		t.Fatalf("channels without a store: %d %v", code, body)
	}
	// The other workspace still reads its own defaults.
	if code, body := api.call(http.MethodGet, "/settings", otherTok, nil); code != http.StatusOK || digs(body, "data", "enforcement_mode") != "findings_only" {
		t.Fatalf("other workspace: %d %v", code, body)
	}
	ev := g.eventsNamed("settings.")
	var p map[string]any
	_ = json.Unmarshal(ev[0].Payload, &p)
	if len(ev) != 2 || p["reason"] != "pilot account approved by CAB-112" || dig(p, "enforcement_mode_changed", "to") != "enforce" {
		t.Fatalf("settings events: %d %s", len(ev), ev[0].Payload)
	}
	p3WaitAudit(t, db, g.ws, http.MethodPut, "/api/iga/v1/policy/settings")

	// With a channel store: the legacy channel addresses are copied, never moved.
	store := &p3ChannelStore{rows: map[uuid.UUID]services.GovNotificationChannels{}}
	t.Cleanup(services.SetGovNotificationChannelStore(store))
	p3exec(t, db, `INSERT INTO governance_notification_settings (workspace_id, webhook_url, webhook_secret, email_enabled)
		VALUES (?, 'https://hooks.customer.test/legacy', 'legacy-secret', false)`, g.ws)
	legacyBefore := p3LegacyRow(t, db, g.ws)
	for i := 0; i < 2; i++ {
		code, body = api.call(http.MethodGet, "/settings", reader, nil)
		if code != http.StatusOK || dig(body, "data", "notifications", "available") != true || digs(body, "data", "notifications", "source") != "legacy_copy" ||
			digs(body, "data", "notifications", "webhook_url") != "https://hooks.customer.test/legacy" ||
			dig(body, "data", "notifications", "webhook_secret_set") != true || dig(body, "data", "notifications", "email_enabled") != false ||
			dig(body, "data", "notifications", "copied_from_legacy_at") == nil {
			t.Fatalf("GET %d after the copy: %d %v", i, code, body)
		}
		if strings.Contains(string(mustJSONRaw(body)), "legacy-secret") {
			t.Fatal("GET /settings returned the webhook secret")
		}
	}
	if n := len(g.eventsNamed(services.GovEventSettingsChannelsCopied)); n != 1 {
		t.Fatalf("copy events: %d", n)
	}
	if after := p3LegacyRow(t, db, g.ws); after == "" || after != legacyBefore {
		t.Fatalf("the legacy row changed or moved:\nbefore %s\nafter  %s", legacyBefore, after)
	}
	if code, body := api.call(http.MethodGet, "/settings", otherTok, nil); code != http.StatusOK || digs(body, "data", "notifications", "source") != "default" {
		t.Fatalf("a workspace without a legacy row: %d %v", code, body)
	}
	if n := len(other.eventsNamed(services.GovEventSettingsChannelsCopied)); n != 0 {
		t.Fatalf("copy events in a workspace without a legacy row: %d", n)
	}
	// PUT channels: https only; the secret is stored, never echoed or logged.
	if code, body := api.call(http.MethodPut, "/settings", enforcer, map[string]any{"notifications": map[string]any{"webhook_url": "http://hooks.example.test"}}); code != http.StatusBadRequest {
		t.Fatalf("http webhook: %d %v", code, body)
	}

	// A signed webhook notice for a review, and an owner email disabled.
	var mu sync.Mutex
	var got []p3RecordedHTTP
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, p3RecordedHTTP{Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(), Body: raw})
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	code, body = api.call(http.MethodPut, "/settings", enforcer, map[string]any{"notifications": map[string]any{
		"webhook_url": srv.URL + "/authsec", "webhook_secret": "whsec-phase3"}})
	if code != http.StatusOK || digs(body, "data", "notifications", "source") != "phase3" || dig(body, "data", "notifications", "webhook_secret_set") != true {
		t.Fatalf("PUT channels: %d %v", code, body)
	}
	for _, e := range g.eventsNamed("settings.") {
		if strings.Contains(string(e.Payload), "whsec-phase3") || strings.Contains(string(e.Payload), "legacy-secret") {
			t.Fatalf("a settings event carries a webhook secret: %s", e.Payload)
		}
	}
	role, rid := g.identity("WebhookRole", nil)
	wl := g.workload("webhook-agent", &role, models.RelTypeExecutesAs)
	u1, _ := g.member("u1-webhook@p3notify.test", "Una One", "active")
	p3Manual(t, db, g, models.GovObjectWorkload, wl, u1, models.GovOwnerAccountable)
	rev := g.reviewVersion(nil, 1, map[string]string{"sqs": igagov.GrantAgeObservedSinceChange},
		p3RevTarget{identity: role, roleID: rid, name: "WebhookRole", removed: []string{"sqs"}})
	svc := services.NewIGAGovOwnerReviewService(db)
	sync, err := svc.OpenReview(context.Background(), g.ws, rev.version, g.author)
	if err != nil {
		t.Fatal(err)
	}
	// Email is off (copied from legacy) and no other channel reaches u1:
	// the owner's delivery fails at once and blocks.
	var r models.IGAGovOwnerResponse
	db.Where("review_id = ? AND user_id = ?", sync.ReviewID, u1).Take(&r)
	if r.Delivery != "failed" {
		t.Fatalf("delivery with email off: %s", r.Delivery)
	}
	ge := wantGov(t, svc.CheckGate(db, g.ws, rev.version), "review_incomplete")
	if got := strings.Join(blockerKinds(t, ge), ","); got != "delivery_failed" {
		t.Fatalf("blockers %s", got)
	}
	w := p3NotifyWorker(db, &p3Outbox{}, &notify.Webhook{Client: srv.Client()})
	p3Drain(t, w)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0].Method != http.MethodPost || got[0].Path != "/authsec" {
		t.Fatalf("webhook requests: %+v", got)
	}
	if sig := got[0].Header.Get(notify.SignatureHeader); sig != notify.Sign("whsec-phase3", got[0].Body) {
		t.Fatalf("webhook signature %q", sig)
	}
	var doc map[string]any
	if err := json.Unmarshal(got[0].Body, &doc); err != nil || doc["type"] != "iga.policy.owner_review" || doc["review_id"] != sync.ReviewID.String() ||
		doc["policy_id"] != rev.policy.String() || doc["workspace_id"] != g.ws.String() {
		t.Fatalf("webhook body %s (%v)", got[0].Body, err)
	}
	var wn models.IGAGovNotification
	db.Where("subject_id = ? AND channel = 'webhook'", sync.ReviewID).Take(&wn)
	if wn.State != "sent" || wn.Recipient != services.GovRecipientWorkspaceWebhook {
		t.Fatalf("webhook notice %+v", wn)
	}
}

func mustJSONRaw(v any) []byte {
	raw, _ := json.Marshal(v)
	return raw
}
