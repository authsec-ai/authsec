package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/modelprovider"
	"github.com/authsec-ai/authsec/services"
)

// Model provider usage (SPEC-agent-runtime-provider-usage.md): a workspace
// connects an OpenAI organisation with an admin key that is stored in Vault
// and never returned; the sync stores keys and hourly usage; a key used in
// the last 7 days that no AWS name ties to raises unaccounted_model_usage;
// a weak link resolves it; workspace B can neither read nor change A's
// connection (404); revoking destroys the key.

const (
	provKeyA = "sk-admin-WORKSPACEA-0123456789abcdefghij"
	provKeyB = "sk-admin-WORKSPACEB-0123456789abcdefghij"
)

// provFake is a fake OpenAI Admin API: the organisation, projects, keys and
// usage depend on the admin key; anything but the read endpoints fails.
type provFake struct {
	t      *testing.T
	mu     sync.Mutex
	bucket time.Time
	refuse map[string]bool
}

func (f *provFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		f.t.Errorf("non-GET provider call %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.mu.Lock()
	refused := f.refuse[key]
	f.mu.Unlock()
	if (key != provKeyA && key != provKeyB) || refused {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"Incorrect API key provided"}}`))
		return
	}
	org, proj, keys := "org-a", "proj_a", []any{
		map[string]any{"id": "key_linked", "name": "support-bot", "redacted_value": "sk-...aaaa", "created_at": 1700000000,
			"owner": map[string]any{"type": "service_account", "service_account": map[string]any{"id": "svc_1", "name": "support"}}},
		map[string]any{"id": "key_shadow", "name": "shadow-runner", "redacted_value": "sk-...bbbb", "created_at": 1700000000,
			"owner": map[string]any{"type": "user", "user": map[string]any{"id": "user_1", "name": "Dev"}}},
	}
	if key == provKeyB {
		org, proj, keys = "org-b", "proj_b", []any{map[string]any{"id": "key_b", "name": "billing-cron", "created_at": 1700000000}}
	}
	w.Header().Set("openai-organization", org)
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	switch r.URL.Path {
	case "/v1/organization/projects":
		_ = enc.Encode(map[string]any{"data": []any{map[string]any{"id": proj, "name": "Agents"}}, "has_more": false, "last_id": proj})
	case "/v1/organization/projects/" + proj + "/api_keys":
		_ = enc.Encode(map[string]any{"data": keys, "has_more": false})
	case "/v1/organization/usage/completions":
		var results []any
		for _, k := range keys {
			id := k.(map[string]any)["id"]
			results = append(results, map[string]any{"api_key_id": id, "project_id": proj, "model": "gpt-5",
				"input_tokens": 1000, "output_tokens": 200, "input_cached_tokens": 0, "num_model_requests": 4})
		}
		_ = enc.Encode(map[string]any{"data": []any{map[string]any{"start_time": f.bucket.Unix(), "results": results}}, "has_more": false})
	case "/v1/organization/usage/embeddings":
		_ = enc.Encode(map[string]any{"data": []any{}, "has_more": false})
	case "/v1/organization/audit_logs":
		// Audit logging not enabled for the organisation.
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"message":"audit logs are not enabled"}}`))
	default:
		f.t.Errorf("provider call outside the read list: %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func provCall(t *testing.T, api *p3OwnersAPI, method, path, tok string, body any) (int, string, map[string]any) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "/api/iga/v1/agent-runtime"+path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	api.eng.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, w.Body.String(), out
}

type provFinding struct {
	ID                   uuid.UUID
	SubjectKey           string
	State                string
	ConnectorID          *uuid.UUID
	ProviderConnectionID *uuid.UUID
	Evidence             string
}

func provFindings(t *testing.T, db *gorm.DB, ws uuid.UUID) []provFinding {
	t.Helper()
	var rows []provFinding
	if err := db.Raw(`SELECT id, subject_key, state, connector_id, provider_connection_id, evidence::text AS evidence
	                    FROM agent_finding WHERE workspace_id = ? AND kind = 'unaccounted_model_usage' ORDER BY subject_key`, ws).Scan(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestAgentRuntimeModelProviderUsageAndIsolation(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "ar-prov-a")
	b := p3NewGov(t, db, "ar-prov-b")
	p3Audit(t, db, a.ws, b.ws)
	mv := newMemVault()
	t.Cleanup(services.SetModelProviderVault(mv))
	ctx := context.Background()
	now := time.Now().UTC()
	fake := &provFake{t: t, bucket: now.Truncate(time.Hour).Add(-2 * time.Hour), refuse: map[string]bool{}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	t.Cleanup(modelprovider.OverrideBaseURLsForTest(srv.URL+"/v1", srv.URL+"/v1"))

	// Workspace A's AWS estate: a Lambda whose env-var NAME names the
	// support-bot key (a weak link); nothing names shadow-runner.
	p3exec(t, db, `INSERT INTO cloud_workload (workspace_id, connector_id, runtime_kind, native_id, name, region, attrs, last_seen_generation)
		VALUES (?, ?, 'lambda_function', 'arn:aws:lambda:us-east-1:111111111111:function:support', 'support', 'us-east-1',
		        '{"env_var_names":["SUPPORT_BOT_OPENAI_KEY","LOG_LEVEL"]}'::jsonb, 1)`, a.ws, a.conn)

	api := p3NewOwnersAPI(t, db)
	all := "governance:read governance:enforce discovery:read"
	tokA := api.token(a.ws, a.author, a.authorMember, all)
	tokB := api.token(b.ws, b.author, b.authorMember, all)
	tokReader := api.token(a.ws, a.author, a.authorMember, "discovery:read")

	// A refused key is 422 and stores nothing.
	if code, _, body := provCall(t, api, http.MethodPost, "/model-providers", tokA, map[string]any{
		"provider": "openai", "admin_key": "sk-admin-NOT-A-REAL-KEY-000000000000"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("refused key: %d %v", code, body)
	}
	// A read-only token cannot connect.
	if code, _, _ := provCall(t, api, http.MethodPost, "/model-providers", tokReader, map[string]any{
		"provider": "openai", "admin_key": provKeyA}); code != http.StatusForbidden {
		t.Fatalf("discovery:read connects: %d", code)
	}
	code, raw, body := provCall(t, api, http.MethodPost, "/model-providers", tokA, map[string]any{
		"provider": "openai", "admin_key": provKeyA, "display_name": "Acme OpenAI"})
	if code != http.StatusCreated || digs(body, "data", "org_id") != "org-a" || digs(body, "data", "status") != "active" {
		t.Fatalf("A connects: %d %v", code, body)
	}
	if strings.Contains(raw, "WORKSPACEA") || strings.Contains(raw, "admin_key") {
		t.Fatalf("the connect response carries the key: %s", raw)
	}
	if fp := digs(body, "data", "key_fingerprint"); fp != services.ModelProviderKeyFingerprint(provKeyA) {
		t.Fatalf("fingerprint %q", fp)
	}
	connA, _ := uuid.Parse(digs(body, "data", "id"))
	// One live connection per organisation.
	if code, _, body := provCall(t, api, http.MethodPost, "/model-providers", tokA, map[string]any{
		"provider": "openai", "admin_key": provKeyA}); code != http.StatusConflict || digs(body, "error", "code") != "model_provider_exists" {
		t.Fatalf("second connection of one org: %d %v", code, body)
	}
	code, _, body = provCall(t, api, http.MethodPost, "/model-providers", tokB, map[string]any{"provider": "openai", "admin_key": provKeyB})
	if code != http.StatusCreated {
		t.Fatalf("B connects: %d %v", code, body)
	}
	connB, _ := uuid.Parse(digs(body, "data", "id"))

	// The key is in Vault under A's path; the row holds only the path.
	var refA string
	db.Raw(`SELECT secret_ref FROM model_provider_connection WHERE id = ?`, connA).Scan(&refA)
	if !strings.HasPrefix(refA, "kv/data/secret/workspaces/"+a.ws.String()+"/agent-runtime/model-provider-"+connA.String()) {
		t.Fatalf("secret_ref %q", refA)
	}
	if sec, err := mv.ReadSecret(refA); err != nil || sec["admin_key"] != provKeyA {
		t.Fatalf("vault: %v", err)
	}
	var leaked int64
	db.Raw(`SELECT count(*) FROM model_provider_connection WHERE row_to_json(model_provider_connection.*)::text LIKE '%WORKSPACE%'`).Scan(&leaked)
	if leaked != 0 {
		t.Fatal("an admin key reached the database")
	}

	// The worker: both connections are due, each synced in its workspace.
	svc := services.NewModelProviderService(db)
	if n, err := svc.SyncDue(ctx); err != nil || n < 2 {
		t.Fatalf("sync due: %d %v", n, err)
	}
	var keysA, usageA int64
	db.Raw(`SELECT count(*) FROM model_provider_key WHERE workspace_id = ? AND connection_id = ?`, a.ws, connA).Scan(&keysA)
	db.Raw(`SELECT count(*) FROM model_provider_usage WHERE workspace_id = ? AND connection_id = ?`, a.ws, connA).Scan(&usageA)
	if keysA != 2 || usageA != 2 {
		t.Fatalf("A keys %d usage %d", keysA, usageA)
	}
	fa := provFindings(t, db, a.ws)
	if len(fa) != 1 || !strings.HasSuffix(fa[0].SubjectKey, ":key_shadow") || fa[0].State != "open" || fa[0].ConnectorID != nil ||
		fa[0].ProviderConnectionID == nil || *fa[0].ProviderConnectionID != connA || !strings.Contains(fa[0].Evidence, `"requests": 4`) {
		t.Fatalf("A findings: %+v", fa)
	}
	if fb := provFindings(t, db, b.ws); len(fb) != 1 || !strings.HasSuffix(fb[0].SubjectKey, ":key_b") {
		t.Fatalf("B findings: %+v", fb)
	}
	// A second sync of the same window changes no counts (upsert).
	if _, err := svc.SyncConnection(ctx, a.ws, connA); err != nil {
		t.Fatal(err)
	}
	db.Raw(`SELECT count(*) FROM model_provider_usage WHERE workspace_id = ? AND connection_id = ?`, a.ws, connA).Scan(&usageA)
	var tokensA int64
	db.Raw(`SELECT sum(input_tokens) FROM model_provider_usage WHERE workspace_id = ? AND connection_id = ?`, a.ws, connA).Scan(&tokensA)
	if usageA != 2 || tokensA != 2000 {
		t.Fatalf("after re-sync: %d rows, %d tokens", usageA, tokensA)
	}

	// Reads: keys with links and the unaccounted flag; usage by model.
	code, _, body = provCall(t, api, http.MethodGet, "/model-providers/"+connA.String()+"/keys", tokReader, nil)
	if code != http.StatusOK || len(digl(body, "data")) != 2 {
		t.Fatalf("A keys: %d %v", code, body)
	}
	for _, k := range digl(body, "data") {
		m := k.(map[string]any)
		switch m["provider_key_id"] {
		case "key_linked":
			if m["unaccounted"] != false || len(m["links"].([]any)) != 1 || dig(m, "links", 0, "strength") != "weak" ||
				dig(m, "links", 0, "via") != "env_var_name" {
				t.Errorf("linked key: %v", m)
			}
		case "key_shadow":
			if m["unaccounted"] != true || len(m["links"].([]any)) != 0 || m["requests_7d"] != float64(4) {
				t.Errorf("shadow key: %v", m)
			}
		}
	}
	code, _, body = provCall(t, api, http.MethodGet, "/model-providers/"+connA.String()+"/usage?group_by=model", tokReader, nil)
	if code != http.StatusOK || len(digl(body, "data")) != 1 || digs(body, "data", 0, "group") != "gpt-5" || dig(body, "data", 0, "requests") != float64(8) {
		t.Fatalf("A usage by model: %d %v", code, body)
	}
	if code, _, _ := provCall(t, api, http.MethodGet, "/model-providers/"+connA.String()+"/usage?group_by=secret", tokReader, nil); code != http.StatusBadRequest {
		t.Errorf("bad group_by: %d", code)
	}
	// The findings route lists the new kind, workspace by workspace.
	code, _, body = provCall(t, api, http.MethodGet, "/findings?kind=unaccounted_model_usage", tokA, nil)
	if code != http.StatusOK || len(digl(body, "data")) != 1 || dig(body, "data", 0, "connector_id") != nil {
		t.Fatalf("A findings route: %d %v", code, body)
	}

	// B can neither read nor change A's connection: 404 like an unknown id.
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/model-providers/" + connA.String()},
		{http.MethodGet, "/model-providers/" + connA.String() + "/keys"},
		{http.MethodGet, "/model-providers/" + connA.String() + "/usage"},
		{http.MethodPost, "/model-providers/" + connA.String() + "/sync"},
		{http.MethodPost, "/model-providers/" + connA.String() + "/rotate"},
		{http.MethodDelete, "/model-providers/" + connA.String()},
		{http.MethodGet, "/model-providers/" + uuid.NewString()},
	} {
		if code, _, body := provCall(t, api, c.method, c.path, tokB, map[string]any{"admin_key": provKeyB}); code != http.StatusNotFound {
			t.Errorf("B %s %s: %d %v, want 404", c.method, c.path, code, body)
		}
	}
	if code, _, body := provCall(t, api, http.MethodGet, "/model-providers", tokB, nil); code != http.StatusOK ||
		len(digl(body, "data")) != 1 || digs(body, "data", 0, "id") != connB.String() {
		t.Fatalf("B lists: %d %v", code, body)
	}
	var stA string
	db.Raw(`SELECT status FROM model_provider_connection WHERE id = ?`, connA).Scan(&stA)
	if stA != "active" {
		t.Fatalf("A's connection changed by B: %s", stA)
	}

	// A weak link appears for shadow-runner: the finding resolves.
	p3exec(t, db, `INSERT INTO cloud_workload (workspace_id, connector_id, runtime_kind, native_id, name, region, attrs, last_seen_generation)
		VALUES (?, ?, 'lambda_function', 'arn:aws:lambda:us-east-1:111111111111:function:runner', 'runner', 'us-east-1',
		        '{"env_var_names":["SHADOW_RUNNER_TOKEN"]}'::jsonb, 1)`, a.ws, a.conn)
	if res, err := svc.SyncConnection(ctx, a.ws, connA); err != nil || res.FindingsResolved != 1 || !res.AuditUnavailable {
		t.Fatalf("re-sync with link: %+v %v", res, err)
	}
	if fa := provFindings(t, db, a.ws); len(fa) != 1 || fa[0].State != "resolved" || !strings.Contains(fa[0].Evidence, "linked") {
		t.Fatalf("A finding after link: %+v", fa)
	}

	// The provider refuses B's key: B's connection is error and unscheduled.
	fake.mu.Lock()
	fake.refuse[provKeyB] = true
	fake.mu.Unlock()
	if _, err := svc.SyncConnection(ctx, b.ws, connB); !modelprovider.IsAuth(err) {
		t.Fatalf("refused sync: %v", err)
	}
	var stB struct {
		Status     string
		NextSyncAt *time.Time
		LastError  string
	}
	db.Raw(`SELECT status, next_sync_at, last_error FROM model_provider_connection WHERE id = ?`, connB).Scan(&stB)
	if stB.Status != "error" || stB.NextSyncAt != nil || strings.Contains(stB.LastError, "WORKSPACEB") {
		t.Fatalf("B after refusal: %+v", stB)
	}
	// A manual sync is queued, not before 5 minutes after the attempt.
	if code, _, body := provCall(t, api, http.MethodPost, "/model-providers/"+connB.String()+"/sync", tokB, nil); code != http.StatusAccepted || dig(body, "data", "queued") != true {
		t.Fatalf("B queues a sync: %d %v", code, body)
	}

	// A revokes: revoked, key destroyed, findings resolved, no more syncs.
	code, raw, body = provCall(t, api, http.MethodDelete, "/model-providers/"+connA.String(), tokA, nil)
	if code != http.StatusOK || digs(body, "data", "status") != "revoked" || strings.Contains(raw, "WORKSPACEA") {
		t.Fatalf("A revokes: %d %v", code, body)
	}
	if _, err := mv.ReadSecret(refA); err == nil {
		t.Fatal("the revoked key is still in Vault")
	}
	if _, err := svc.SyncConnection(ctx, a.ws, connA); err == nil {
		t.Fatal("a revoked connection synced")
	}
	p3WaitAudit(t, db, a.ws, http.MethodPost, "/api/iga/v1/agent-runtime/model-providers")
	p3WaitAudit(t, db, a.ws, http.MethodDelete, "/api/iga/v1/agent-runtime/model-providers/"+connA.String())
	var auditLeak int64
	db.Raw(`SELECT count(*) FROM audit_events WHERE workspace_id = ? AND row_to_json(audit_events.*)::text LIKE '%WORKSPACEA%'`, a.ws.String()).Scan(&auditLeak)
	if auditLeak != 0 {
		t.Fatal("an admin key reached the audit log")
	}
}
