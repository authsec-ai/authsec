package integration

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/smithy-go"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/internal/agentactivity"
	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/services"
)

// Agent runtime activity timeline (SPEC-agent-runtime-activity.md): the
// CloudTrail sink writes labelled identities only, once; the table is
// append-only; an OTLP token of workspace A can only ever write into A (and
// cannot attribute to B's workloads); the timeline and trace APIs are
// isolated; AgentCore spans are attributed to the runtime and move a cursor.

type actFixture struct {
	*p3Gov
	identity uuid.UUID
	roleARN  string
	workload uuid.UUID
	runtime  uuid.UUID
	rtARN    string
}

func actNewFixture(t *testing.T, db *gorm.DB, name string) *actFixture {
	t.Helper()
	g := p3NewGov(t, db, name)
	f := &actFixture{p3Gov: g, identity: uuid.New(), workload: uuid.New(), runtime: uuid.New()}
	f.roleARN = "arn:aws:iam::111111111111:role/act-" + g.ws.String()[:8]
	f.rtARN = "arn:aws:bedrock-agentcore:us-east-1:111111111111:runtime/travel-" + g.ws.String()[:8]
	p3exec(t, db, `INSERT INTO cloud_identity (id, workspace_id, connector_id, kind, native_id, name) VALUES (?, ?, ?, 'iam_role', ?, 'act-role')`,
		f.identity, g.ws, g.conn, f.roleARN)
	p3exec(t, db, `INSERT INTO cloud_workload (id, workspace_id, connector_id, identity_id, runtime_kind, native_id, name, region)
		VALUES (?, ?, ?, ?, 'lambda_function', ?, 'book-flight', 'us-east-1')`,
		f.workload, g.ws, g.conn, f.identity, "arn:aws:lambda:us-east-1:111111111111:function:book-flight")
	p3exec(t, db, `INSERT INTO cloud_workload (id, workspace_id, connector_id, identity_id, runtime_kind, native_id, name, region)
		VALUES (?, ?, ?, ?, 'bedrock_agentcore_runtime', ?, 'travel', 'us-east-1')`,
		f.runtime, g.ws, g.conn, f.identity, f.rtARN)
	return f
}

type actRow struct {
	Source, Kind, Action, ResourceRef, Outcome, ProviderEventID, TraceID string
	IdentityID, WorkloadID, ConnectorID                                  *uuid.UUID
	OnBehalfOf                                                           *string
	Attrs                                                                string
}

func actRows(t *testing.T, db *gorm.DB, ws uuid.UUID) []actRow {
	t.Helper()
	var rows []actRow
	if err := db.Raw(`SELECT source, kind, action, resource_ref, outcome, provider_event_id, trace_id, identity_id, workload_id,
	                         connector_id, on_behalf_of, attrs::text AS attrs
	                    FROM agent_activity_event WHERE workspace_id = ? ORDER BY occurred_at, provider_event_id`, ws).Scan(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestAgentActivitySinkLabelledOnlyAndIdempotent(t *testing.T) {
	db := igaDB(t)
	a := actNewFixture(t, db, "act-sink-a")
	b := actNewFixture(t, db, "act-sink-b")
	agentruntime.ResetSinks()
	t.Cleanup(agentruntime.ResetSinks)
	r := &arResolver{subj: map[string]agentruntime.Subject{}}
	agentruntime.SetResolver(r)
	agentruntime.RegisterSink(services.NewAgentActivitySink(db))
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	const human = "arn:aws:iam::111111111111:role/human-admin"
	const possible = "arn:aws:iam::111111111111:role/maybe-ai"
	possibleID := uuid.New()
	r.set(a.ws, a.roleARN, agentruntime.Subject{IdentityID: a.identity, ConnectorID: a.conn, WorkloadIDs: []uuid.UUID{a.workload}, Label: agentruntime.LabelAIWorkload})
	r.set(a.ws, human, agentruntime.Subject{IdentityID: uuid.New(), ConnectorID: a.conn, Label: ""})
	r.set(a.ws, possible, agentruntime.Subject{IdentityID: possibleID, ConnectorID: a.conn, Label: "possible_ai_workload"})
	r.set(b.ws, a.roleARN, agentruntime.Subject{IdentityID: b.identity, ConnectorID: b.conn, Label: agentruntime.LabelAgent})

	conv := arEvent("act-ev-1", a.roleARN, "bedrock.amazonaws.com", "Converse", now.Add(-30*time.Minute))
	conv.RequestFacts = map[string]string{agentruntime.FactModelID: "anthropic.claude-3-haiku"}
	s3 := arEvent("act-ev-2", a.roleARN, "s3.amazonaws.com", "GetObject", now.Add(-20*time.Minute))
	s3.EventCategory, s3.Resources = "Data", []string{"arn:aws:s3:::bucket/key"}
	denied := arEvent("act-ev-3", a.roleARN, "secretsmanager.amazonaws.com", "GetSecretValue", now.Add(-10*time.Minute))
	denied.ErrorCode, denied.AuthorizationDenied = "AccessDenied", true
	completion := arEvent("act-ev-4", a.roleARN, "bedrock.amazonaws.com", "ConverseStream", now.Add(-9*time.Minute))
	completion.EventType = "AwsServiceEvent"
	humanEv := arEvent("act-ev-h", human, "s3.amazonaws.com", "ListBuckets", now.Add(-5*time.Minute))
	possibleEv := arEvent("act-ev-p", possible, "lambda.amazonaws.com", "Invoke", now.Add(-4*time.Minute))
	tooOld := arEvent("act-ev-old", a.roleARN, "s3.amazonaws.com", "GetObject", now.AddDate(0, 0, -100))

	if err := agentruntime.Dispatch(ctx, a.ws, a.conn, []agentruntime.Event{conv, s3, denied, completion, humanEv, possibleEv, tooOld}); err != nil {
		t.Fatal(err)
	}
	// The same events again (the poller after the stream): stored once.
	if err := agentruntime.Dispatch(ctx, a.ws, a.conn, []agentruntime.Event{conv, s3}); err != nil {
		t.Fatal(err)
	}
	// Workspace B: the same CloudTrail event id is its own row.
	if err := agentruntime.Dispatch(ctx, b.ws, b.conn, []agentruntime.Event{conv}); err != nil {
		t.Fatal(err)
	}

	as := actRows(t, db, a.ws)
	if len(as) != 4 {
		t.Fatalf("workspace A rows: %d %+v", len(as), as)
	}
	want := []struct{ id, source, kind, outcome, ref string }{
		{"act-ev-1", "cloudtrail", "model_call", "success", "anthropic.claude-3-haiku"},
		{"act-ev-2", "cloudtrail_data", "data_access", "success", "arn:aws:s3:::bucket/key"},
		{"act-ev-3", "cloudtrail", "cloud_action", "denied", ""},
		{"act-ev-p", "cloudtrail", "cloud_action", "success", ""},
	}
	for i, w := range want {
		g := as[i]
		if g.ProviderEventID != w.id || g.Source != w.source || g.Kind != w.kind || g.Outcome != w.outcome || g.ResourceRef != w.ref {
			t.Errorf("row %d: %+v, want %+v", i, g, w)
		}
	}
	if as[0].IdentityID == nil || *as[0].IdentityID != a.identity || as[0].WorkloadID == nil || *as[0].WorkloadID != a.workload ||
		as[0].ConnectorID == nil || *as[0].ConnectorID != a.conn || as[0].Action != "bedrock:Converse" {
		t.Errorf("attribution: %+v", as[0])
	}
	if as[3].IdentityID == nil || *as[3].IdentityID != possibleID || as[3].WorkloadID != nil {
		t.Errorf("possible_ai_workload row: %+v", as[3])
	}
	for _, g := range as {
		if g.ProviderEventID == "act-ev-h" || g.ProviderEventID == "act-ev-4" || g.ProviderEventID == "act-ev-old" {
			t.Errorf("stored an event that must not be: %s", g.ProviderEventID)
		}
	}
	bs := actRows(t, db, b.ws)
	if len(bs) != 1 || bs[0].IdentityID == nil || *bs[0].IdentityID != b.identity || !strings.Contains(bs[0].Attrs, `"subject_label": "agent"`) {
		t.Fatalf("workspace B rows: %+v", bs)
	}
}

func TestAgentActivityAppendOnlyAndRetention(t *testing.T) {
	db := igaDB(t)
	a := actNewFixture(t, db, "act-append")
	ctx := context.Background()
	old := time.Now().UTC().AddDate(0, 0, -10)
	p3exec(t, db, `INSERT INTO agent_activity_event (workspace_id, source, kind, occurred_at, outcome, provider_event_id)
		VALUES (?, 'cloudtrail', 'cloud_action', ?, 'success', 'act-old'), (?, 'cloudtrail', 'cloud_action', now(), 'success', 'act-new')`,
		a.ws, old, a.ws)
	if err := db.Exec(`UPDATE agent_activity_event SET outcome = 'denied' WHERE workspace_id = ?`, a.ws).Error; err == nil ||
		!strings.Contains(err.Error(), "append-only") {
		t.Fatalf("UPDATE was not refused: %v", err)
	}
	if err := db.Exec(`DELETE FROM agent_activity_event WHERE workspace_id = ?`, a.ws).Error; err == nil ||
		!strings.Contains(err.Error(), "append-only") {
		t.Fatalf("an unflagged DELETE was not refused: %v", err)
	}
	svc := services.NewAgentActivityService(db)
	// Default retention (90 days) keeps both.
	if n, err := svc.PurgeWorkspace(ctx, a.ws); err != nil || n != 0 {
		t.Fatalf("purge at 90 days: %d %v", n, err)
	}
	if _, err := svc.UpdateSettings(ctx, a.ws, a.author, 0); err == nil {
		t.Error("retention 0 accepted")
	}
	if s, err := svc.UpdateSettings(ctx, a.ws, a.author, 7); err != nil || s.RetentionDays != 7 {
		t.Fatalf("settings: %+v %v", s, err)
	}
	if n, err := svc.PurgeWorkspace(ctx, a.ws); err != nil || n != 1 {
		t.Fatalf("purge at 7 days: %d %v", n, err)
	}
	if rows := actRows(t, db, a.ws); len(rows) != 1 || rows[0].ProviderEventID != "act-new" {
		t.Fatalf("after purge: %+v", rows)
	}
}

/* ---------------------------------- OTLP ---------------------------------- */

func otlpEngine(db *gorm.DB, svc *services.AgentOTLPService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	eng := gin.New()
	eng.POST(services.AgentOTLPIngestPath, platform.NewAgentOTLPIngestController(db).WithService(svc).IngestTraces)
	return eng
}

func otlpPost(eng *gin.Engine, token, ctype, enc string, body []byte, bearer bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, services.AgentOTLPIngestPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", ctype)
	if enc != "" {
		req.Header.Set("Content-Encoding", enc)
	}
	if token != "" {
		if bearer {
			req.Header.Set("Authorization", "Bearer "+token)
		} else {
			req.Header.Set(services.AgentOTLPTokenHeader, token)
		}
	}
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)
	return w
}

func otlpJSON(traceID, spanID string, resource string) []byte {
	return []byte(`{"resourceSpans":[{"resource":{"attributes":[` + resource + `]},"scopeSpans":[{"scope":{"name":"t"},"spans":[
	 {"traceId":"` + traceID + `","spanId":"` + spanID + `","name":"chat","kind":3,
	  "startTimeUnixNano":"` + itoa(time.Now().Add(-time.Minute).UnixNano()) + `",
	  "attributes":[{"key":"gen_ai.operation.name","value":{"stringValue":"chat"}},
	                {"key":"gen_ai.request.model","value":{"stringValue":"gpt-4o"}},
	                {"key":"gen_ai.input.messages","value":{"stringValue":"PLANTED-SECRET-PROMPT"}}]},
	 {"traceId":"` + traceID + `","spanId":"aaaaaaaaaaaaaaaa","name":"GET /","kind":2,
	  "attributes":[{"key":"http.method","value":{"stringValue":"GET"}}]}]}]}]}`)
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func int64String(n int64) string { return strconv.FormatInt(n, 10) }

func TestAgentActivityOTLPTokenIsolation(t *testing.T) {
	db := igaDB(t)
	a := actNewFixture(t, db, "act-otlp-a")
	b := actNewFixture(t, db, "act-otlp-b")
	ctx := context.Background()
	svc := services.NewAgentOTLPService(db)
	_, tokA, err := svc.CreateToken(ctx, a.ws, a.author.String(), "collector A", 30)
	if err != nil {
		t.Fatal(err)
	}
	infoB, tokB, err := svc.CreateToken(ctx, b.ws, b.author.String(), "collector B", 0)
	if err != nil {
		t.Fatal(err)
	}
	eng := otlpEngine(db, svc)
	const traceA = "11111111111111111111111111111111"

	// A's token, whose resource attributes name B's workload and B's role:
	// the rows land in A, unattributed -- a body can never reach B.
	res := `{"key":"authsec.workload_id","value":{"stringValue":"` + b.workload.String() + `"}},
	        {"key":"authsec.identity_arn","value":{"stringValue":"` + b.roleARN + `"}}`
	if w := otlpPost(eng, tokA, "application/json", "", otlpJSON(traceA, "1111111111111111", res), true); w.Code != http.StatusOK {
		t.Fatalf("A posts: %d %s", w.Code, w.Body.String())
	}
	// A's own workload, by faas.name in A's account: attributed.
	res = `{"key":"cloud.account.id","value":{"stringValue":"111111111111"}},{"key":"faas.name","value":{"stringValue":"book-flight"}}`
	w := otlpPost(eng, tokA, "application/json", "", otlpJSON(traceA, "2222222222222222", res), false)
	if w.Code != http.StatusOK || w.Header().Get("X-AuthSec-Accepted") != "1" || w.Header().Get("X-AuthSec-Ignored") != "1" {
		t.Fatalf("A posts again: %d %v %s", w.Code, w.Header(), w.Body.String())
	}
	// A retry is a duplicate.
	if w := otlpPost(eng, tokA, "application/json", "", otlpJSON(traceA, "2222222222222222", res), true); w.Code != http.StatusOK || w.Header().Get("X-AuthSec-Accepted") != "0" {
		t.Fatalf("retry: %d %v", w.Code, w.Header())
	}

	as, bs := actRows(t, db, a.ws), actRows(t, db, b.ws)
	if len(as) != 2 || len(bs) != 0 {
		t.Fatalf("rows: A=%d B=%d", len(as), len(bs))
	}
	for _, r := range as {
		if strings.Contains(r.Attrs, "PLANTED-SECRET-PROMPT") {
			t.Fatalf("prompt stored: %s", r.Attrs)
		}
		if r.Source != "otlp" || r.Kind != "model_call" || r.TraceID != traceA {
			t.Errorf("row: %+v", r)
		}
	}
	if as[0].WorkloadID != nil || as[0].IdentityID != nil {
		t.Errorf("B's workload attributed through A's token: %+v", as[0])
	}
	if as[1].WorkloadID == nil || *as[1].WorkloadID != a.workload || as[1].IdentityID == nil || *as[1].IdentityID != a.identity {
		t.Errorf("A's own workload not attributed: %+v", as[1])
	}

	// Protobuf + gzip with B's token, naming the AgentCore runtime ARN.
	tid, _ := hex.DecodeString("33333333333333333333333333333333")
	sid, _ := hex.DecodeString("3333333333333333")
	td := &tracepb.TracesData{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{Key: "cloud.resource_id",
			Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: b.rtARN + "/runtime-endpoint/DEFAULT"}}}}},
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{TraceId: tid, SpanId: sid, Name: "invoke_agent travel",
			StartTimeUnixNano: uint64(time.Now().Add(-time.Minute).UnixNano()),
			Attributes: []*commonpb.KeyValue{{Key: "gen_ai.operation.name",
				Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "invoke_agent"}}}}}}}},
	}}}
	raw, _ := proto.Marshal(td)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	if w := otlpPost(eng, tokB, "application/x-protobuf", "gzip", gz.Bytes(), true); w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/x-protobuf" {
		t.Fatalf("B posts protobuf: %d %s", w.Code, w.Body.String())
	}
	bs = actRows(t, db, b.ws)
	if len(bs) != 1 || bs[0].Kind != "agent_step" || bs[0].WorkloadID == nil || *bs[0].WorkloadID != b.runtime {
		t.Fatalf("B's protobuf row: %+v", bs)
	}
	if n := len(actRows(t, db, a.ws)); n != 2 {
		t.Fatalf("B's post changed A: %d", n)
	}

	// Refusals.
	if w := otlpPost(eng, "", "application/json", "", otlpJSON(traceA, "4444444444444444", ""), true); w.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d", w.Code)
	}
	if w := otlpPost(eng, "aot_"+strings.Repeat("A", 43), "application/json", "", otlpJSON(traceA, "4444444444444444", ""), true); w.Code != http.StatusUnauthorized {
		t.Errorf("unknown token: %d", w.Code)
	}
	if w := otlpPost(eng, tokA, "text/plain", "", []byte("x"), true); w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain: %d", w.Code)
	}
	if w := otlpPost(eng, tokA, "application/json", "", []byte("{not json"), true); w.Code != http.StatusBadRequest {
		t.Errorf("bad json: %d", w.Code)
	}
	if w := otlpPost(eng, tokA, "application/json", "", bytes.Repeat([]byte(" "), services.AgentOTLPMaxBodyBytes+1), true); w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize: %d", w.Code)
	}
	// A cannot revoke B's token (not found); B revokes its own, then it is refused.
	if _, err := svc.RevokeToken(ctx, a.ws, infoB.ID); err == nil {
		t.Error("A revoked B's token")
	}
	if _, err := svc.RevokeToken(ctx, b.ws, infoB.ID); err != nil {
		t.Fatal(err)
	}
	if w := otlpPost(eng, tokB, "application/json", "", otlpJSON(traceA, "5555555555555555", ""), true); w.Code != http.StatusUnauthorized {
		t.Errorf("revoked token: %d", w.Code)
	}
	// Per-token rate limit.
	limited := otlpEngine(db, services.NewAgentOTLPService(db).WithRateLimit(0.001, 1))
	codes := []int{}
	for i := 0; i < 2; i++ {
		codes = append(codes, otlpPost(limited, tokA, "application/json", "", otlpJSON(traceA, "6666666666666666", ""), true).Code)
	}
	if codes[0] != http.StatusOK || codes[1] != http.StatusTooManyRequests {
		t.Errorf("rate limit: %v", codes)
	}
}

/* ------------------------------ timeline API ------------------------------ */

func TestAgentActivityTimelineAPIIsolation(t *testing.T) {
	db := igaDB(t)
	a := actNewFixture(t, db, "act-api-a")
	b := actNewFixture(t, db, "act-api-b")
	p3Audit(t, db, a.ws, b.ws)
	const trace = "77777777777777777777777777777777"
	now := time.Now().UTC().Add(-time.Hour)
	for i, s := range []struct{ span, parent, kind string }{
		{"7777777777777771", "", "agent_step"}, {"7777777777777772", "7777777777777771", "model_call"},
		{"7777777777777773", "7777777777777771", "tool_call"}, {"7777777777777774", "7777777777777773", "model_call"},
	} {
		p3exec(t, db, `INSERT INTO agent_activity_event (workspace_id, identity_id, workload_id, source, kind, occurred_at, outcome,
			trace_id, span_id, parent_span_id, provider_event_id, action) VALUES (?, ?, ?, 'otlp', ?, ?, 'success', ?, ?, ?, ?, 'x')`,
			a.ws, a.identity, a.workload, s.kind, now.Add(time.Duration(i)*time.Second), trace, s.span, s.parent, trace+":"+s.span)
	}
	p3exec(t, db, `INSERT INTO agent_activity_event (workspace_id, identity_id, source, kind, occurred_at, outcome, provider_event_id)
		VALUES (?, ?, 'cloudtrail', 'cloud_action', ?, 'denied', 'act-b-1')`, b.ws, b.identity, now)

	api := p3NewOwnersAPI(t, db)
	readA := api.token(a.ws, a.author, a.authorMember, "discovery:read")
	adminA := api.token(a.ws, a.author, a.authorMember, "discovery:read discovery:admin")
	readB := api.token(b.ws, b.author, b.authorMember, "discovery:read")
	adminB := api.token(b.ws, b.author, b.authorMember, "discovery:read discovery:admin")

	code, body := arCall(t, api, http.MethodGet, "/activity?limit=3", readA, nil)
	if code != http.StatusOK || len(digl(body, "data")) != 3 || digs(body, "meta", "next_cursor") == "" {
		t.Fatalf("A lists: %d %v", code, body)
	}
	if digs(body, "data", 0, "span_id") != "7777777777777774" {
		t.Errorf("not newest first: %v", digl(body, "data"))
	}
	code, body = arCall(t, api, http.MethodGet, "/activity?limit=3&cursor="+digs(body, "meta", "next_cursor"), readA, nil)
	if code != http.StatusOK || len(digl(body, "data")) != 1 || digs(body, "meta", "next_cursor") != "" {
		t.Fatalf("A page 2: %d %v", code, body)
	}
	if code, body := arCall(t, api, http.MethodGet, "/activity?kind=model_call&identity_id="+a.identity.String(), readA, nil); code != http.StatusOK || len(digl(body, "data")) != 2 {
		t.Fatalf("A filters: %d %v", code, body)
	}
	if code, _ := arCall(t, api, http.MethodGet, "/activity?kind=bogus", readA, nil); code != http.StatusBadRequest {
		t.Errorf("bad kind: %d", code)
	}
	// B sees only its own row, even naming A's identity.
	if code, body := arCall(t, api, http.MethodGet, "/activity", readB, nil); code != http.StatusOK || len(digl(body, "data")) != 1 || digs(body, "data", 0, "provider_event_id") != "act-b-1" {
		t.Fatalf("B lists: %d %v", code, body)
	}
	if code, body := arCall(t, api, http.MethodGet, "/activity?identity_id="+a.identity.String(), readB, nil); code != http.StatusOK || len(digl(body, "data")) != 0 {
		t.Fatalf("B lists A's identity: %d %v", code, body)
	}
	// The trace as a tree for A; 404 for B.
	code, body = arCall(t, api, http.MethodGet, "/activity/traces/"+trace, readA, nil)
	if code != http.StatusOK || dig(body, "data", "count") != float64(4) || len(digl(body, "data", "spans")) != 1 ||
		len(digl(body, "data", "spans", 0, "children")) != 2 || len(digl(body, "data", "spans", 0, "children", 1, "children")) != 1 {
		t.Fatalf("A trace: %d %v", code, body)
	}
	if code, _ := arCall(t, api, http.MethodGet, "/activity/traces/"+trace, readB, nil); code != http.StatusNotFound {
		t.Errorf("B reads A's trace: %d, want 404", code)
	}

	// Tokens: discovery:read cannot create; admin can; B cannot revoke A's.
	if code, _ := arCall(t, api, http.MethodPost, "/otlp-tokens", readA, map[string]any{"label": "x"}); code != http.StatusForbidden {
		t.Errorf("read token creates: %d, want 403", code)
	}
	code, body = arCall(t, api, http.MethodPost, "/otlp-tokens", adminA, map[string]any{"label": "collector", "expires_in_days": 30})
	if code != http.StatusCreated || !strings.HasPrefix(digs(body, "data", "token"), "aot_") {
		t.Fatalf("A creates token: %d %v", code, body)
	}
	tokID := digs(body, "data", "token_info", "id")
	if code, body := arCall(t, api, http.MethodGet, "/otlp-tokens", readA, nil); code != http.StatusOK || len(digl(body, "data")) != 1 ||
		dig(body, "data", 0, "token") != nil || dig(body, "data", 0, "token_hash") != nil || len(digs(body, "data", 0, "token_prefix")) != 8 {
		t.Fatalf("A lists tokens: %d %v", code, body)
	}
	if code, body := arCall(t, api, http.MethodGet, "/otlp-tokens", readB, nil); code != http.StatusOK || len(digl(body, "data")) != 0 {
		t.Fatalf("B lists tokens: %d %v", code, body)
	}
	if code, _ := arCall(t, api, http.MethodDelete, "/otlp-tokens/"+tokID, adminB, nil); code != http.StatusNotFound {
		t.Errorf("B revokes A's token: %d, want 404", code)
	}
	if code, body := arCall(t, api, http.MethodDelete, "/otlp-tokens/"+tokID, adminA, nil); code != http.StatusOK || digs(body, "data", "state") != "revoked" {
		t.Errorf("A revokes: %d %v", code, body)
	}
	// Settings and coverage.
	if code, body := arCall(t, api, http.MethodPut, "/activity/settings", adminA, map[string]any{"retention_days": 30}); code != http.StatusOK || dig(body, "data", "retention_days") != float64(30) {
		t.Fatalf("A settings: %d %v", code, body)
	}
	if code, body := arCall(t, api, http.MethodGet, "/activity/settings", readB, nil); code != http.StatusOK || dig(body, "data", "retention_days") != float64(90) {
		t.Fatalf("B settings: %d %v", code, body)
	}
	if code, body := arCall(t, api, http.MethodGet, "/activity/coverage", readA, nil); code != http.StatusOK || dig(body, "data", "retention_days") != float64(30) {
		t.Fatalf("A coverage: %d %v", code, body)
	}
}

/* ------------------------------ AgentCore spans ----------------------------- */

type actLogs struct {
	err  error
	rows [][]cwltypes.ResultField
	q    *cloudwatchlogs.StartQueryInput
}

func (f *actLogs) StartQuery(_ context.Context, in *cloudwatchlogs.StartQueryInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error) {
	f.q = in
	if f.err != nil {
		return nil, f.err
	}
	return &cloudwatchlogs.StartQueryOutput{QueryId: aws.String("q")}, nil
}

func (f *actLogs) GetQueryResults(context.Context, *cloudwatchlogs.GetQueryResultsInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetQueryResultsOutput, error) {
	return &cloudwatchlogs.GetQueryResultsOutput{Status: cwltypes.QueryStatusComplete, Results: f.rows}, nil
}

func (f *actLogs) StopQuery(context.Context, *cloudwatchlogs.StopQueryInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StopQueryOutput, error) {
	return &cloudwatchlogs.StopQueryOutput{}, nil
}

func TestAgentActivityAgentCoreSpansCursor(t *testing.T) {
	db := igaDB(t)
	a := actNewFixture(t, db, "act-spans-a")
	b := actNewFixture(t, db, "act-spans-b")
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	ts := now.Add(-2 * time.Hour)
	msg := `{"resource":{"attributes":{"cloud.resource_id":"` + a.rtARN + `/runtime-endpoint/DEFAULT"}},"traceId":"88888888888888888888888888888888",
	  "spanId":"8888888888888888","name":"chat","kind":"CLIENT","startTimeUnixNano":` + int64String(ts.UnixNano()) + `,
	  "attributes":{"gen_ai.operation.name":"chat","gen_ai.request.model":"anthropic.claude","gen_ai.input.messages":"PLANTED-SECRET-PROMPT"}}`
	// A span naming B's runtime, read through A's connector: unattributed.
	foreign := strings.Replace(strings.Replace(msg, a.rtARN, b.rtARN, 1), `"spanId":"8888888888888888"`, `"spanId":"8888888888888889"`, 1)
	logs := &actLogs{rows: [][]cwltypes.ResultField{
		{{Field: aws.String("@timestamp"), Value: aws.String(ts.Format("2006-01-02 15:04:05.000"))}, {Field: aws.String("@message"), Value: aws.String(msg)}},
		{{Field: aws.String("@timestamp"), Value: aws.String(ts.Format("2006-01-02 15:04:05.000"))}, {Field: aws.String("@message"), Value: aws.String(foreign)}},
	}}
	apiFor := func(context.Context, uuid.UUID, uuid.UUID, string) (agentactivity.LogsInsightsAPI, error) {
		return logs, nil
	}
	col := services.NewAgentSpanCollector(db).WithClock(func() time.Time { return now })
	res, err := col.Collect(ctx, a.ws, a.conn, "us-east-1", apiFor)
	if err != nil || res.State != "reached" || res.Inserted != 2 {
		t.Fatalf("collect: %+v %v", res, err)
	}
	if aws.ToInt64(logs.q.StartTime) != now.Add(-services.AgentSpanFirstWindow-agentactivity.SpanLateArrival).Unix() {
		t.Errorf("first window: %d", aws.ToInt64(logs.q.StartTime))
	}
	rows := actRows(t, db, a.ws)
	if len(rows) != 2 || rows[0].Source != "agentcore_span" {
		t.Fatalf("rows: %+v", rows)
	}
	var own, other *actRow
	for i := range rows {
		if strings.Contains(rows[i].Attrs, "PLANTED-SECRET-PROMPT") {
			t.Fatalf("prompt stored: %s", rows[i].Attrs)
		}
		if strings.HasSuffix(rows[i].ProviderEventID, "8888888888888888") {
			own = &rows[i]
		} else {
			other = &rows[i]
		}
	}
	if own == nil || own.WorkloadID == nil || *own.WorkloadID != a.runtime || own.IdentityID == nil || *own.IdentityID != a.identity {
		t.Errorf("own runtime span: %+v", own)
	}
	if other == nil || other.WorkloadID != nil || other.ConnectorID == nil || *other.ConnectorID != a.conn {
		t.Errorf("B's runtime attributed through A's connector: %+v", other)
	}
	if len(actRows(t, db, b.ws)) != 0 {
		t.Fatal("rows written into B")
	}
	// The cursor moved to now - lag; the next read starts there.
	res, err = services.NewAgentSpanCollector(db).WithClock(func() time.Time { return now.Add(10 * time.Minute) }).
		Collect(ctx, a.ws, a.conn, "us-east-1", apiFor)
	if err != nil || res.State != "reached" || res.Inserted != 0 || aws.ToInt64(logs.q.StartTime) != now.Add(-services.AgentSpanIngestLag-agentactivity.SpanLateArrival).Unix() {
		t.Fatalf("second collect: %+v %v start=%d", res, err, aws.ToInt64(logs.q.StartTime))
	}
	// A refused read: permission_missing on the cursor, never an error.
	denied := &actLogs{err: &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized to perform logs:StartQuery"}}
	res, err = services.NewAgentSpanCollector(db).WithClock(func() time.Time { return now.Add(time.Hour) }).
		Collect(ctx, a.ws, a.conn, "eu-west-1", func(context.Context, uuid.UUID, uuid.UUID, string) (agentactivity.LogsInsightsAPI, error) {
			return denied, nil
		})
	if err != nil || res.State != "permission_missing" {
		t.Fatalf("denied: %+v %v", res, err)
	}
	var st struct {
		State     string
		ErrorCode string
		CursorAt  *time.Time
	}
	db.Raw(`SELECT state, error_code, cursor_at FROM agent_activity_cursor WHERE workspace_id = ? AND connector_id = ? AND region = 'eu-west-1'`,
		a.ws, a.conn).Scan(&st)
	if st.State != "permission_missing" || st.ErrorCode != "AccessDeniedException" || st.CursorAt != nil {
		t.Errorf("cursor after denial: %+v", st)
	}
	var bCursors int64
	db.Raw(`SELECT count(*) FROM agent_activity_cursor WHERE workspace_id = ?`, b.ws).Scan(&bCursors)
	if bCursors != 0 {
		t.Errorf("cursor rows in B: %d", bCursors)
	}
}
