package integration

import (
	"bytes"
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

	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/safehttp"
	"github.com/authsec-ai/authsec/services"
)

// Agent runtime alerts (SPEC-agent-runtime-visibility.md §5.7, §10 Q3):
// alerts are raised per workspace from dispatched events, deduplicated and
// idempotent by event id; workspace B can neither read nor change workspace
// A's alerts or SIEM endpoints (404, exactly like an unknown id); a SIEM
// delivery is signed with the endpoint's secret.

// arResolver resolves (workspace, role ARN) to a subject.
type arResolver struct {
	mu   sync.Mutex
	subj map[string]agentruntime.Subject
}

func (r *arResolver) Resolve(_ context.Context, ws, _ uuid.UUID, a agentruntime.Attribution) (agentruntime.Subject, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.subj[ws.String()+"|"+a.ARN], nil
}

func (r *arResolver) set(ws uuid.UUID, arn string, s agentruntime.Subject) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.subj[ws.String()+"|"+arn] = s
}

// arSetup installs the alert sink and a resolver for the test only.
func arSetup(t *testing.T, db *gorm.DB) *arResolver {
	t.Helper()
	agentruntime.ResetSinks()
	t.Cleanup(agentruntime.ResetSinks)
	r := &arResolver{subj: map[string]agentruntime.Subject{}}
	agentruntime.SetResolver(r)
	agentruntime.RegisterSink(services.NewAgentAlertSink(db))
	return r
}

func arEvent(id, roleARN, source, name string, at time.Time) agentruntime.Event {
	return agentruntime.Event{EventID: id, EventTime: at, EventSource: source, EventName: name, EventType: "AwsApiCall",
		AccountID: "111111111111", Region: "us-east-1", SourceIP: "203.0.113.20",
		PrincipalType: "AssumedRole", PrincipalARN: roleARN + "-session", SessionIssuerType: "Role",
		SessionIssuerARN: roleARN, SessionIssuerPrincipalID: "AROA" + strings.ToUpper(id)}
}

type arAlertRow struct {
	ID         uuid.UUID
	Detection  string
	Severity   string
	EventCount int
	State      string
	Evidence   string
}

func arAlerts(t *testing.T, db *gorm.DB, ws uuid.UUID) []arAlertRow {
	t.Helper()
	var rows []arAlertRow
	if err := db.Raw(`SELECT id, detection, severity, event_count, state, evidence::text AS evidence
	                    FROM agent_alert WHERE workspace_id = ? ORDER BY created_at`, ws).Scan(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

// arCall calls /api/iga/v1/agent-runtime<path> through the production chain.
func arCall(t *testing.T, api *p3OwnersAPI, method, path, tok string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader = http.NoBody
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, "/api/iga/v1/agent-runtime"+path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	api.eng.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestAgentRuntimeAlertsPerWorkspaceAndIsolation(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "ar-alerts-a")
	b := p3NewGov(t, db, "ar-alerts-b")
	p3Audit(t, db, a.ws, b.ws)
	r := arSetup(t, db)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	const role = "arn:aws:iam::111111111111:role/order-agent"
	idA, idB := uuid.New(), uuid.New()
	r.set(a.ws, role, agentruntime.Subject{IdentityID: idA, ConnectorID: a.conn, Label: agentruntime.LabelAIWorkload, Name: "order-agent"})
	r.set(b.ws, role, agentruntime.Subject{IdentityID: idB, ConnectorID: b.conn, Label: agentruntime.LabelAgent, Name: "order-agent"})
	const humanRole = "arn:aws:iam::111111111111:role/human-admin"
	r.set(a.ws, humanRole, agentruntime.Subject{IdentityID: uuid.New(), ConnectorID: a.conn, Label: ""})

	read := arEvent("ev-a1", role, "secretsmanager.amazonaws.com", "GetSecretValue", now.Add(-20*time.Minute))
	if err := agentruntime.Dispatch(ctx, a.ws, a.conn, []agentruntime.Event{read,
		arEvent("ev-h1", humanRole, "secretsmanager.amazonaws.com", "GetSecretValue", now.Add(-20*time.Minute))}); err != nil {
		t.Fatal(err)
	}
	// The same event again (the poller after the stream): counted once.
	if err := agentruntime.Dispatch(ctx, a.ws, a.conn, []agentruntime.Event{read}); err != nil {
		t.Fatal(err)
	}
	// Ten minutes later, inside the 1 h window: the alert is extended.
	if err := agentruntime.Dispatch(ctx, a.ws, a.conn, []agentruntime.Event{
		arEvent("ev-a2", role, "secretsmanager.amazonaws.com", "GetSecretValue", now.Add(-10*time.Minute))}); err != nil {
		t.Fatal(err)
	}
	// Workspace B: the same CloudTrail event id is its own event.
	if err := agentruntime.Dispatch(ctx, b.ws, b.conn, []agentruntime.Event{
		arEvent("ev-a1", role, "iam.amazonaws.com", "CreateAccessKey", now.Add(-5*time.Minute))}); err != nil {
		t.Fatal(err)
	}

	as, bs := arAlerts(t, db, a.ws), arAlerts(t, db, b.ws)
	if len(as) != 1 || as[0].Detection != "D1" || as[0].Severity != "high" || as[0].EventCount != 2 || as[0].State != "open" {
		t.Fatalf("workspace A alerts: %+v", as)
	}
	if !strings.Contains(as[0].Evidence, "ev-a1") || !strings.Contains(as[0].Evidence, "ev-a2") || strings.Contains(as[0].Evidence, "ev-h1") {
		t.Errorf("workspace A evidence: %s", as[0].Evidence)
	}
	if len(bs) != 1 || bs[0].Detection != "D2" || bs[0].EventCount != 1 {
		t.Fatalf("workspace B alerts: %+v", bs)
	}
	var opened int64
	db.Raw(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = 'agent_alert.opened' AND payload->>'alert_id' = ?`,
		a.ws, as[0].ID.String()).Scan(&opened)
	if opened != 1 {
		t.Errorf("agent_alert.opened events for A's alert: %d", opened)
	}

	api := p3NewOwnersAPI(t, db)
	all := "governance:read governance:enforce"
	tokA := api.token(a.ws, a.author, a.authorMember, all)
	tokB := api.token(b.ws, b.author, b.authorMember, all)
	tokReader := api.token(a.ws, a.author, a.authorMember, "discovery:read")
	aID, bID := as[0].ID.String(), bs[0].ID.String()

	// Reads: each workspace sees its own alert only.
	if code, body := arCall(t, api, http.MethodGet, "/alerts", tokA, nil); code != http.StatusOK || len(digl(body, "data")) != 1 || digs(body, "data", 0, "id") != aID {
		t.Fatalf("A lists: %d %v", code, body)
	}
	if code, body := arCall(t, api, http.MethodGet, "/alerts?detection=D1", tokB, nil); code != http.StatusOK || len(digl(body, "data")) != 0 {
		t.Fatalf("B lists D1: %d %v", code, body)
	}
	if code, body := arCall(t, api, http.MethodGet, "/alerts/"+aID, tokReader, nil); code != http.StatusOK || digs(body, "data", "detection") != "D1" {
		t.Fatalf("A reads with discovery:read: %d %v", code, body)
	}
	// B cannot read, acknowledge or resolve A's alert: 404 like an unknown id.
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/alerts/" + aID},
		{http.MethodPost, "/alerts/" + aID + "/acknowledge"},
		{http.MethodPost, "/alerts/" + aID + "/resolve"},
		{http.MethodGet, "/alerts/" + uuid.NewString()},
	} {
		if code, body := arCall(t, api, c.method, c.path, tokB, map[string]any{"reason": "not mine"}); code != http.StatusNotFound {
			t.Errorf("B %s %s: %d %v, want 404", c.method, c.path, code, body)
		}
	}
	// A read-only token cannot change an alert.
	if code, _ := arCall(t, api, http.MethodPost, "/alerts/"+aID+"/acknowledge", tokReader, nil); code != http.StatusForbidden {
		t.Errorf("discovery:read acknowledges: %d, want 403", code)
	}
	if got := arAlerts(t, db, a.ws); got[0].State != "open" {
		t.Fatalf("A's alert changed by another workspace: %+v", got[0])
	}

	// A acknowledges, then resolves; resolving writes agent_alert.resolved.
	if code, body := arCall(t, api, http.MethodPost, "/alerts/"+aID+"/acknowledge", tokA, map[string]any{"reason": "looking"}); code != http.StatusOK || digs(body, "data", "state") != "acknowledged" {
		t.Fatalf("A acknowledges: %d %v", code, body)
	}
	if code, body := arCall(t, api, http.MethodPost, "/alerts/"+aID+"/resolve", tokA, map[string]any{"reason": "expected rotation"}); code != http.StatusOK || digs(body, "data", "state") != "resolved" {
		t.Fatalf("A resolves: %d %v", code, body)
	}
	if code, body := arCall(t, api, http.MethodPost, "/alerts/"+aID+"/resolve", tokA, nil); code != http.StatusConflict {
		t.Errorf("resolving twice: %d %v, want 409", code, body)
	}
	var resolved int64
	db.Raw(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = 'agent_alert.resolved' AND payload->>'alert_id' = ?`,
		a.ws, aID).Scan(&resolved)
	if resolved != 1 {
		t.Errorf("agent_alert.resolved events: %d", resolved)
	}
	p3WaitAudit(t, db, a.ws, http.MethodPost, "/api/iga/v1/agent-runtime/alerts/"+aID+"/resolve")
	// B's own alert is untouched by all of it.
	if got := arAlerts(t, db, b.ws); len(got) != 1 || got[0].ID.String() != bID || got[0].State != "open" {
		t.Fatalf("workspace B after A's changes: %+v", got)
	}

	// After resolving, the next secret read opens a NEW alert.
	if err := agentruntime.Dispatch(ctx, a.ws, a.conn, []agentruntime.Event{
		arEvent("ev-a3", role, "secretsmanager.amazonaws.com", "GetSecretValue", now.Add(-time.Minute))}); err != nil {
		t.Fatal(err)
	}
	if got := arAlerts(t, db, a.ws); len(got) != 2 || got[1].State != "open" || got[1].EventCount != 1 {
		t.Fatalf("after resolve: %+v", got)
	}

	// Settings are per workspace: A turns D1 off; B still alerts on D1.
	if code, body := arCall(t, api, http.MethodPut, "/alert-settings", tokA, map[string]any{
		"detections": map[string]any{"D1": map[string]any{"enabled": false}}}); code != http.StatusOK {
		t.Fatalf("A puts settings: %d %v", code, body)
	}
	if code, body := arCall(t, api, http.MethodGet, "/alert-settings", tokB, nil); code != http.StatusOK || dig(body, "data", "saved") != false {
		t.Fatalf("B's settings changed by A: %d %v", code, body)
	}
	if err := agentruntime.Dispatch(ctx, a.ws, a.conn, []agentruntime.Event{
		arEvent("ev-a4", role, "secretsmanager.amazonaws.com", "BatchGetSecretValue", now.Add(3*time.Hour))}); err != nil {
		t.Fatal(err)
	}
	if got := arAlerts(t, db, a.ws); len(got) != 2 || got[1].EventCount != 1 {
		t.Fatalf("D1 off still alerted: %+v", got)
	}
}

// A SIEM endpoint receives the opened alert, signed with its secret; B can
// neither list nor delete A's endpoint.
func TestAgentRuntimeAlertSIEMDeliverySigned(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "ar-siem-a")
	b := p3NewGov(t, db, "ar-siem-b")
	r := arSetup(t, db)
	ctx := context.Background()
	t.Cleanup(services.SetAgentAlertVault(newMemVault()))

	type received struct {
		sig, ts, delivery string
		body              []byte
	}
	got := make(chan received, 4)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		got <- received{req.Header.Get(services.AgentAlertSIEMSignatureHeader), req.Header.Get(services.AgentAlertSIEMTimestampHeader),
			req.Header.Get(services.AgentAlertSIEMDeliveryHeader), body}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	// Still dialled through safehttp (loopback allowed for the test server
	// only by MCP_ALLOW_LOOPBACK), trusting the test server's certificate.
	t.Setenv("MCP_ALLOW_LOOPBACK", "true")
	tlsCfg := srv.Client().Transport.(*http.Transport).TLSClientConfig
	t.Cleanup(services.SetAgentAlertSIEMClient(&http.Client{Timeout: 10 * time.Second,
		Transport: &http.Transport{DialContext: safehttp.DialContext, TLSClientConfig: tlsCfg}}))

	svc := services.NewAgentAlertService(db)
	ep, secret, err := svc.CreateSIEMEndpoint(ctx, a.ws, a.author, srv.URL+"/hook", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) < 32 || !ep.SecretSet {
		t.Fatalf("endpoint %+v secret length %d", ep, len(secret))
	}
	// Never returned after creation.
	eps, err := svc.ListSIEMEndpoints(ctx, a.ws)
	if err != nil || len(eps) != 1 {
		t.Fatalf("A lists: %v %+v", err, eps)
	}
	if raw, _ := json.Marshal(eps); strings.Contains(string(raw), secret) {
		t.Fatal("the list returns the secret")
	}
	// Workspace B sees and deletes nothing of A's.
	if bl, err := svc.ListSIEMEndpoints(ctx, b.ws); err != nil || len(bl) != 0 {
		t.Fatalf("B lists A's endpoints: %v %+v", err, bl)
	}
	if err := svc.DeleteSIEMEndpoint(ctx, b.ws, ep.ID); err == nil || !strings.Contains(err.Error(), "not_found") {
		t.Fatalf("B deletes A's endpoint: %v", err)
	}
	if _, err := svc.TestSIEMEndpoint(ctx, b.ws, ep.ID); err == nil || !strings.Contains(err.Error(), "not_found") {
		t.Fatalf("B tests A's endpoint: %v", err)
	}

	const role = "arn:aws:iam::111111111111:role/siem-agent"
	r.set(a.ws, role, agentruntime.Subject{IdentityID: uuid.New(), ConnectorID: a.conn, Label: agentruntime.LabelSuggestedAgent, Name: "siem-agent"})
	ev := arEvent("ev-siem-1", role, "secretsmanager.amazonaws.com", "GetSecretValue", time.Now().UTC().Add(-time.Minute))
	ev.RequestFacts = map[string]string{agentruntime.FactSecretID: "prod/do-not-leak"}
	if err := agentruntime.Dispatch(ctx, a.ws, a.conn, []agentruntime.Event{ev}); err != nil {
		t.Fatal(err)
	}
	alerts := arAlerts(t, db, a.ws)
	if len(alerts) != 1 {
		t.Fatalf("alerts %+v", alerts)
	}
	if _, err := services.NewAgentAlertDeliverer(db).DeliverDue(ctx); err != nil {
		t.Logf("deliver (other workspaces' rows may fail): %v", err)
	}
	var rec received
	select {
	case rec = <-got:
	case <-time.After(15 * time.Second):
		t.Fatal("the SIEM endpoint received nothing")
	}
	if rec.sig != services.SignAgentAlertSIEM(secret, rec.ts, rec.body) {
		t.Fatalf("signature %q does not verify over timestamp %q", rec.sig, rec.ts)
	}
	var p services.AgentAlertSIEMPayload
	if err := json.Unmarshal(rec.body, &p); err != nil {
		t.Fatal(err)
	}
	if p.Type != services.AgentAlertSIEMType || p.Alert.ID != alerts[0].ID || p.Alert.WorkspaceID != a.ws || p.Alert.Detection != "D1" ||
		len(p.Evidence) != 1 || p.Evidence[0].EventID != "ev-siem-1" || p.DeliveryID != rec.delivery {
		t.Fatalf("payload %s", rec.body)
	}
	if strings.Contains(string(rec.body), "do-not-leak") {
		t.Fatalf("the SIEM payload names the secret: %s", rec.body)
	}
	var status string
	db.Raw(`SELECT status FROM agent_alert_delivery WHERE workspace_id = ? AND alert_id = ? AND channel = 'siem'`, a.ws, alerts[0].ID).Scan(&status)
	if status != "sent" {
		t.Errorf("delivery status %q, want sent", status)
	}

	// A test POST is signed the same way.
	res, err := svc.TestSIEMEndpoint(ctx, a.ws, ep.ID)
	if err != nil || !res.Delivered {
		t.Fatalf("test delivery: %+v %v", res, err)
	}
	rec = <-got
	if rec.sig != services.SignAgentAlertSIEM(secret, rec.ts, rec.body) || !strings.Contains(string(rec.body), services.AgentAlertSIEMTestType) {
		t.Fatalf("test delivery %q %s", rec.sig, rec.body)
	}

	// Deleting the endpoint: it is gone from the list, and B's alerts never
	// queue a delivery to it.
	if err := svc.DeleteSIEMEndpoint(ctx, a.ws, ep.ID); err != nil {
		t.Fatal(err)
	}
	if eps, _ := svc.ListSIEMEndpoints(ctx, a.ws); len(eps) != 0 {
		t.Fatalf("deleted endpoint listed: %+v", eps)
	}
	var crossed int64
	db.Raw(`SELECT count(*) FROM agent_alert_delivery WHERE endpoint_id = ? AND workspace_id <> ?`, ep.ID, a.ws).Scan(&crossed)
	if crossed != 0 {
		t.Fatalf("%d deliveries to A's endpoint from another workspace", crossed)
	}
}
