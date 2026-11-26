//go:build integration

package flows

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

// Agent runtime event stream (SPEC-agent-runtime-visibility.md §5.6, §5.9):
// the ingest decides workspace and connector from the event secret alone.
//   - A's secret cannot write into B: an event for B's account sent with A's
//     secret is refused (403), counted on A's stream, and nothing reaches B;
//     a workspace named in the body changes nothing.
//   - A forged, unknown, missing or revoked secret is 401; an old secret
//     after rotation is 401.
//   - A retried event is handed to the sinks once.
//   - A's admin cannot read, rotate, revoke or fetch the stack of B's stream
//     (404), and B's stream is unchanged afterwards.

// recordingSink records what Dispatch hands it, per workspace.
type recordingSink struct {
	mu     sync.Mutex
	events map[uuid.UUID][]string
}

func (s *recordingSink) Name() string { return "test-recording-sink" }

func (s *recordingSink) Process(_ context.Context, ws, _ uuid.UUID, evs []agentruntime.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range evs {
		s.events[ws] = append(s.events[ws], e.EventID)
	}
	return nil
}

func (s *recordingSink) of(ws uuid.UUID) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.events[ws]...)
}

func cloudTrailEvent(account, eventID string, extra string) string {
	return fmt.Sprintf(`{"version":"0","id":%q,"detail-type":"AWS API Call via CloudTrail","source":"aws.bedrock",
		"account":%q,"region":"us-east-1","time":"2026-11-05T10:00:00Z"%s,
		"detail":{"eventID":%q,"eventTime":"2026-11-05T10:00:00Z","eventSource":"bedrock.amazonaws.com",
		"eventName":"Converse","eventType":"AwsApiCall","recipientAccountId":%q,"awsRegion":"us-east-1",
		"userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::%s:assumed-role/app/fn",
		"sessionContext":{"sessionIssuer":{"type":"Role","arn":"arn:aws:iam::%s:role/app","principalId":"AROAEXAMPLE"}}}}}`,
		uuid.NewString(), account, extra, eventID, account, account, account)
}

func postEvents(t *testing.T, secret, body string) *httptest.ResponseRecorder {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, "/authsec/ingest/aws/events", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set(services.AgentEventSecretHeader, secret)
	}
	w := httptest.NewRecorder()
	testsupport.Get(t).Router.ServeHTTP(w, req)
	return w
}

func enableStream(t *testing.T, token string, connector uuid.UUID) string {
	t.Helper()
	w := testsupport.Get(t).Do("POST", "/authsec/discovery/aws/connectors/"+connector.String()+"/event-stream", map[string]any{}, token)
	if w.Code != http.StatusOK {
		t.Fatalf("enable event stream: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Data struct {
			Secret string `json:"secret"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || !strings.HasPrefix(out.Data.Secret, "aev_") {
		t.Fatalf("enable event stream: no secret (%v)", err)
	}
	return out.Data.Secret
}

func Test_Isolation_AgentEventStream(t *testing.T) {
	a, b := TwoTenants(t)
	env := testsupport.Get(t)
	sink := &recordingSink{events: map[uuid.UUID][]string{}}
	agentruntime.RegisterSink(sink)
	t.Cleanup(agentruntime.ResetSinks)

	for _, tn := range []*Tenant{a, b} {
		if err := config.DB.Exec(`
			INSERT INTO role_permissions (role_id, permission_id)
			SELECT ?, id FROM permissions WHERE workspace_id IS NULL
			ON CONFLICT DO NOTHING`, tn.WS.AdminRoleID).Error; err != nil {
			t.Fatalf("grant permissions: %v", err)
		}
	}
	const acctA, acctB = "111111111111", "222222222222"
	connA, connB := uuid.New(), uuid.New()
	for _, c := range []struct {
		id   uuid.UUID
		ws   uuid.UUID
		acct string
	}{{connA, a.WS.WorkspaceID, acctA}, {connB, b.WS.WorkspaceID, acctB}} {
		if err := config.DB.Exec(`INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, status, auth_ref)
			VALUES (?, ?, 'aws', 'account', ?, 'active', 'vault://aws/test')`, c.id, c.ws, c.acct).Error; err != nil {
			t.Fatalf("seed connector: %v", err)
		}
	}
	secretA := enableStream(t, a.AdminToken, connA)
	secretB := enableStream(t, b.AdminToken, connB)

	// The secret is stored only as its hash.
	assertCount(t, 0, "agent_event_stream", "secret_hash = ? OR secret_prefix = ?", secretA, secretA)
	assertCount(t, 1, "agent_event_stream", "secret_hash = ?", services.HashAgentEventSecret(secretA))

	// ---- A's secret cannot write into B.
	evB := uuid.NewString()
	bodyB := cloudTrailEvent(acctB, evB, fmt.Sprintf(`,"workspace_id":%q,"connector_id":%q`, b.WS.WorkspaceID, connB))
	if w := postEvents(t, secretA, bodyB); w.Code != http.StatusForbidden {
		t.Fatalf("B's account with A's secret: %d %s, want 403", w.Code, w.Body.String())
	}
	assertCount(t, 0, "agent_event_seen", "event_id = ?", evB)
	if got := sink.of(b.WS.WorkspaceID); len(got) != 0 {
		t.Fatalf("B's workspace received %v through A's secret", got)
	}
	assertCount(t, 1, "agent_event_stream", "connector_id = ? AND rejected_count = 1", connA)
	assertCount(t, 1, "agent_event_stream", "connector_id = ? AND rejected_count = 0 AND received_count = 0", connB)

	// A mixed batch: A's event is taken under A, B's is refused.
	evA := uuid.NewString()
	mixed := "[" + cloudTrailEvent(acctA, evA, "") + "," + cloudTrailEvent(acctB, uuid.NewString(), "") + "]"
	if w := postEvents(t, secretA, mixed); w.Code != http.StatusAccepted {
		t.Fatalf("mixed batch: %d %s, want 202", w.Code, w.Body.String())
	}
	assertCount(t, 1, "agent_event_seen", "event_id = ? AND workspace_id = ? AND connector_id = ?", evA, a.WS.WorkspaceID, connA)
	assertCount(t, 0, "agent_event_seen", "workspace_id = ?", b.WS.WorkspaceID)
	if got := sink.of(a.WS.WorkspaceID); len(got) != 1 || got[0] != evA {
		t.Fatalf("A's sink got %v, want [%s]", got, evA)
	}

	// B's own secret is B's: the same B event is accepted under B.
	if w := postEvents(t, secretB, bodyB); w.Code != http.StatusAccepted {
		t.Fatalf("B's event with B's secret: %d %s", w.Code, w.Body.String())
	}
	assertCount(t, 1, "agent_event_seen", "event_id = ? AND workspace_id = ? AND connector_id = ?", evB, b.WS.WorkspaceID, connB)

	// ---- Forged and missing credentials.
	forged, _ := services.GenerateAgentEventSecret()
	for name, sec := range map[string]string{
		"missing": "", "forged": forged, "malformed": "aev_short", "a bearer token": a.AdminToken,
	} {
		if w := postEvents(t, sec, cloudTrailEvent(acctA, uuid.NewString(), "")); w.Code != http.StatusUnauthorized {
			t.Errorf("%s secret: %d, want 401", name, w.Code)
		}
	}

	// ---- Dedupe: a retried event goes to the sinks once.
	evDup := uuid.NewString()
	one := cloudTrailEvent(acctA, evDup, "")
	for i := 0; i < 2; i++ {
		if w := postEvents(t, secretA, one); w.Code != http.StatusAccepted {
			t.Fatalf("delivery %d: %d %s", i+1, w.Code, w.Body.String())
		}
	}
	if w := postEvents(t, secretA, "["+one+","+one+"]"); w.Code != http.StatusAccepted {
		t.Fatalf("duplicate in one batch: %d %s", w.Code, w.Body.String())
	}
	n := 0
	for _, id := range sink.of(a.WS.WorkspaceID) {
		if id == evDup {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("event dispatched %d times, want 1", n)
	}
	assertCount(t, 1, "agent_event_seen", "event_id = ?", evDup)

	// ---- Admin isolation: A cannot touch B's stream.
	base := "/authsec/discovery/aws/connectors/" + connB.String() + "/event-stream"
	assertCrossTenant404(t, "GET", base, nil, a.AdminToken)
	assertCrossTenant404(t, "POST", base, map[string]any{}, a.AdminToken)
	assertCrossTenant404(t, "DELETE", base, nil, a.AdminToken)
	assertCrossTenant404(t, "GET", base+"/template", nil, a.AdminToken)
	if w := postEvents(t, secretB, cloudTrailEvent(acctB, uuid.NewString(), "")); w.Code != http.StatusAccepted {
		t.Fatalf("B's secret after A's attempts: %d, want 202 (rotated or revoked by A?)", w.Code)
	}
	if w := env.Do("GET", base, nil, b.AdminToken); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"state":"active"`) {
		t.Fatalf("B reading its own stream: %d %s", w.Code, w.Body.String())
	}

	// ---- Rotation and revocation.
	newA := enableStream(t, a.AdminToken, connA)
	if w := postEvents(t, secretA, cloudTrailEvent(acctA, uuid.NewString(), "")); w.Code != http.StatusUnauthorized {
		t.Errorf("old secret after rotation: %d, want 401", w.Code)
	}
	if w := postEvents(t, newA, cloudTrailEvent(acctA, uuid.NewString(), "")); w.Code != http.StatusAccepted {
		t.Errorf("new secret after rotation: %d, want 202", w.Code)
	}
	if w := env.Do("DELETE", "/authsec/discovery/aws/connectors/"+connA.String()+"/event-stream", nil, a.AdminToken); w.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	if w := postEvents(t, newA, cloudTrailEvent(acctA, uuid.NewString(), "")); w.Code != http.StatusUnauthorized {
		t.Errorf("revoked secret: %d, want 401", w.Code)
	}

	// The model access template is static and per workspace only by its
	// auth; it never names another workspace.
	if w := env.Do("GET", "/authsec/discovery/aws/templates/model-access?mode=deny&form=policy", nil, a.AdminToken); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), "/authsec/") {
		t.Fatalf("model access template: %d", w.Code)
	}
	if w := env.Do("GET", "/authsec/discovery/aws/templates/model-access?mode=deny&form=boundary", nil, a.AdminToken); w.Code != http.StatusBadRequest {
		t.Fatalf("boundary form: %d, want 400", w.Code)
	}
}

// Events in the agent_event_seen purge carry the workspace: purging A never
// touches B's rows.
func Test_AgentEventSeen_PurgeIsPerWorkspace(t *testing.T) {
	a, b := TwoTenants(t)
	connA, connB := uuid.New(), uuid.New()
	for _, c := range []struct{ id, ws uuid.UUID }{{connA, a.WS.WorkspaceID}, {connB, b.WS.WorkspaceID}} {
		if err := config.DB.Exec(`INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, status, auth_ref)
			VALUES (?, ?, 'aws', 'account', '333333333333', 'active', 'vault://aws/test')`, c.id, c.ws).Error; err != nil {
			t.Fatalf("seed connector: %v", err)
		}
		if err := config.DB.Exec(`INSERT INTO agent_event_stream (connector_id, workspace_id, secret_hash, secret_prefix)
			VALUES (?, ?, ?, 'aev_test')`, c.id, c.ws, services.HashAgentEventSecret(uuid.NewString())).Error; err != nil {
			t.Fatalf("seed stream: %v", err)
		}
		if err := config.DB.Exec(`INSERT INTO agent_event_seen (workspace_id, connector_id, event_id, received_at)
			VALUES (?, ?, ?, now() - interval '30 days')`, c.ws, c.id, uuid.NewString()).Error; err != nil {
			t.Fatalf("seed seen: %v", err)
		}
	}
	svc := services.NewAgentRuntimeIngestService(config.DB)
	n, err := svc.PurgeSeen(context.Background(), a.WS.WorkspaceID, time.Now().Add(-14*24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("purge A: %d %v", n, err)
	}
	assertCount(t, 0, "agent_event_seen", "workspace_id = ?", a.WS.WorkspaceID)
	assertCount(t, 1, "agent_event_seen", "workspace_id = ?", b.WS.WorkspaceID)
}
