package integration

// Agent runtime inference on AWS (SPEC-agent-runtime-visibility.md §5.2,
// §5.3, §5.5, §10 Q1/Q2) against a real database: model-call evidence in
// cloud_usage becomes AI workloads, a suggestion (dedicated role) or a
// shared-role finding (several workloads), long-lived-key and model-key-secret
// findings; Confirm classifies through the existing decision transaction and
// closes the suggestion with it; Dismiss is final for the incarnation; the
// Agents list mirror and the subject resolver. Every route is exercised from
// two workspaces: A never reads, confirms or dismisses B's rows (404).
//
// Needs IGA_TEST_DSN (skipped otherwise), like the rest of this package.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	platform "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// arWorld is one workspace's seeded AWS account.
type arWorld struct {
	ws, conn   uuid.UUID
	account    string
	role       uuid.UUID // dedicated role: one Lambda, model calls + S3
	roleARN    string
	workload   uuid.UUID // iga_workload of the dedicated Lambda
	shared     uuid.UUID // role with two Lambdas and model calls
	user       uuid.UUID // IAM user calling a model
	human      uuid.UUID // verified member
	membership uuid.UUID
}

func arExec(t *testing.T, db *gorm.DB, q string, args ...any) {
	t.Helper()
	if err := db.Exec(q, args...).Error; err != nil {
		t.Fatalf("%s: %v", strings.SplitN(strings.TrimSpace(q), "\n", 2)[0], err)
	}
}

func arSeedWorld(t *testing.T, db *gorm.DB, name string) *arWorld {
	t.Helper()
	w := &arWorld{ws: newWorkspace(t, db, name), conn: uuid.New(), account: fmt.Sprintf("%012d", rand.Int63n(1e12))}
	t.Cleanup(func() {
		for _, tbl := range []string{"agent_finding", "agent_suggestion", "iga_workload_classification", "iga_classification_clock",
			"iga_object_support", "iga_workload", "discovered_agents", "cloud_usage", "cloud_secret", "cloud_permission",
			"cloud_resource", "cloud_workload", "cloud_identity", "cloud_connector"} {
			db.Exec(`DELETE FROM `+tbl+` WHERE workspace_id = ?`, w.ws)
		}
	})
	arExec(t, db, `INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, status, auth_ref)
		VALUES (?, ?, 'aws', 'account', ?, 'active', 'vault://aws/test')`, w.conn, w.ws, w.account)

	identity := func(kind, path, uniqueID string) (uuid.UUID, string) {
		id := uuid.New()
		arn := "arn:aws:iam::" + w.account + ":" + path
		attrs, _ := json.Marshal(map[string]string{"unique_id": uniqueID})
		arExec(t, db, `INSERT INTO cloud_identity (id, workspace_id, connector_id, kind, native_id, name, attrs)
			VALUES (?, ?, ?, ?, ?, ?, ?::jsonb)`, id, w.ws, w.conn, kind, arn, path[strings.LastIndex(path, "/")+1:], string(attrs))
		return id, arn
	}
	lambda := func(role uuid.UUID, fn string, envNames []string) uuid.UUID {
		cw := models.CloudWorkload{RuntimeKind: models.WorkloadLambdaFunction, Region: "us-east-1",
			NativeID: "arn:aws:lambda:us-east-1:" + w.account + ":function:" + fn}
		attrs, _ := json.Marshal(models.AWSWorkloadAttrs{EnvVarNames: envNames})
		arExec(t, db, `INSERT INTO cloud_workload (workspace_id, connector_id, identity_id, runtime_kind, native_id, name, region, attrs)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?::jsonb)`, w.ws, w.conn, role, cw.RuntimeKind, cw.NativeID, fn, cw.Region, string(attrs))
		gid := uuid.New()
		arExec(t, db, `INSERT INTO iga_workload (id, workspace_id, runtime_kind, display_name, region, source_key, classification)
			VALUES (?, ?, ?, ?, 'us-east-1', ?, 'unclassified')`, gid, w.ws, cw.RuntimeKind, fn, igagraph.WorkloadKey(cw, "", w.account))
		arExec(t, db, `INSERT INTO iga_object_support (workspace_id, workload_id, connector_id, partition_key)
			VALUES (?, ?, ?, 'ar-test')`, w.ws, gid, w.conn)
		return gid
	}
	usage := func(identity uuid.UUID, u agentruntime.ModelCallUsage) {
		attrs, _ := json.Marshal(u)
		arExec(t, db, `INSERT INTO cloud_usage (workspace_id, connector_id, identity_id, service, source, attrs, last_used_at)
			VALUES (?, ?, ?, ?, ?, ?::jsonb, now())`, w.ws, w.conn, identity, agentruntime.UsageService, agentruntime.UsageSource, string(attrs))
	}

	w.role, w.roleARN = identity(models.CloudIdentityIAMRole, "role/support-bot-role", "AROA"+name)
	w.workload = lambda(w.role, "support-bot-"+name, []string{"LANGCHAIN_API_KEY", "PATH"})
	usage(w.role, agentruntime.ModelCallUsage{Calls: 12, Models: map[string]int{"anthropic.claude": 12},
		OtherServices: map[string]int{"s3.amazonaws.com": 4, "secretsmanager.amazonaws.com": 1}, SessionNames: []string{"support-bot-" + name}})

	w.shared, _ = identity(models.CloudIdentityIAMRole, "role/shared-"+name, "AROASHARED"+name)
	lambda(w.shared, "refunds-"+name, nil)
	lambda(w.shared, "orders-"+name, nil)
	usage(w.shared, agentruntime.ModelCallUsage{Calls: 5, OtherServices: map[string]int{"dynamodb.amazonaws.com": 2}})

	w.user, _ = identity(models.CloudIdentityIAMUser, "user/dev-"+name, "AIDA"+name)
	arExec(t, db, `INSERT INTO cloud_secret (workspace_id, connector_id, identity_id, kind, native_id, created_at, status)
		VALUES (?, ?, ?, 'access_key', ?, now() - interval '400 days', 'active')`, w.ws, w.conn, w.user, "AKIA"+strings.ToUpper(name)+"0000000000")
	usage(w.user, agentruntime.ModelCallUsage{Calls: 2})

	secret := uuid.New()
	arExec(t, db, `INSERT INTO cloud_resource (id, workspace_id, connector_id, kind, native_id, name)
		VALUES (?, ?, ?, 'secretsmanager_secret', ?, 'openai-api-key')`, secret, w.ws, w.conn,
		"arn:aws:secretsmanager:us-east-1:"+w.account+":secret:openai-api-key-AbCdEf")
	arExec(t, db, `INSERT INTO cloud_permission (workspace_id, connector_id, identity_id, resource_id, effect, actions, scope_kind, native_id)
		VALUES (?, ?, ?, ?, 'allow', ARRAY['secretsmanager:GetSecretValue'], 'resource', 'inline:read-key#0')`, w.ws, w.conn, w.role, secret)

	name1 := "Priya " + name
	w.human, w.membership = classMember(t, db, w.ws, &name1, "priya-"+name+"@test.local", "active")
	return w
}

// arAPI is the real route table over the database, with the token's workspace
// and claims set as AuthMiddleware sets them, and a permission recorder.
type arAPI struct {
	t        *testing.T
	eng      *gin.Engine
	ws       uuid.UUID
	claims   map[string]string
	lastPerm string
}

func newARAPI(t *testing.T, db *gorm.DB) *arAPI {
	gin.SetMode(gin.TestMode)
	a := &arAPI{t: t, claims: map[string]string{}}
	eng := gin.New()
	g := eng.Group("/api/iga/v1")
	g.Use(func(c *gin.Context) {
		if a.ws != uuid.Nil {
			tenancy.Set(c, tenancy.Context{WorkspaceID: a.ws, PrincipalKind: "user"})
		}
		for k, v := range a.claims {
			c.Set(k, v)
		}
		a.lastPerm = ""
		c.Next()
	})
	ctl := platform.NewAgentRuntimeControllerWith(db, nil)
	platform.RegisterAgentRuntimeRoutes(g, ctl, func(resource, action string) gin.HandlerFunc {
		return func(c *gin.Context) { a.lastPerm = resource + ":" + action; c.Next() }
	})
	a.eng = eng
	return a
}

func (a *arAPI) as(w *arWorld) *arAPI {
	a.ws = w.ws
	a.claims = map[string]string{"user_id": w.human.String(), "workspace_membership_id": w.membership.String(), "client_id": "console"}
	return a
}

func (a *arAPI) do(method, path string, body any) (int, map[string]any) {
	a.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "/api/iga/v1"+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	a.eng.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			a.t.Fatalf("%s %s: %d, not JSON: %s", method, path, rec.Code, rec.Body.String())
		}
	}
	return rec.Code, out
}

func arData(body map[string]any) []any {
	l, _ := body["data"].([]any)
	return l
}

func arSuggestionID(t *testing.T, db *gorm.DB, ws, workload uuid.UUID) (uuid.UUID, string) {
	t.Helper()
	var rows []struct {
		ID    uuid.UUID
		State string
	}
	db.Raw(`SELECT id, state FROM agent_suggestion WHERE workspace_id = ? AND workload_id = ?`, ws, workload).Scan(&rows)
	if len(rows) != 1 {
		t.Fatalf("suggestions for workload %s: %d, want 1", workload, len(rows))
	}
	return rows[0].ID, rows[0].State
}

func TestAgentRuntimeInferenceAndIsolation(t *testing.T) {
	db := igaDB(t)
	a := arSeedWorld(t, db, "ara")
	b := arSeedWorld(t, db, "arb")
	ctx := context.Background()
	svc := services.NewAgentRuntimeService(db)

	for _, w := range []*arWorld{a, b} {
		res, err := svc.RunAgentInference(ctx, w.ws, w.conn)
		if err != nil {
			t.Fatalf("inference: %v", err)
		}
		if res.AIWorkloads != 3 || res.SuggestionsNew != 1 {
			t.Fatalf("inference result %+v: want 3 AI workloads and 1 new suggestion", res)
		}
	}
	// Inference of A's connector under B's workspace touches nothing.
	if res, err := svc.RunAgentInference(ctx, b.ws, a.conn); err != nil || res.AIWorkloads != 0 {
		t.Fatalf("cross-workspace inference: %+v %v", res, err)
	}

	// The dedicated Lambda is a pending suggestion; the shared role is a
	// finding and no suggestion (§10 Q1).
	sugA, state := arSuggestionID(t, db, a.ws, a.workload)
	if state != services.SuggestionPending {
		t.Fatalf("A's suggestion state %q", state)
	}
	sugB, _ := arSuggestionID(t, db, b.ws, b.workload)
	var kinds []string
	db.Raw(`SELECT kind FROM agent_finding WHERE workspace_id = ? AND state = 'open' ORDER BY kind`, a.ws).Pluck("kind", &kinds)
	// ai_config_hint: the support bot's LANGCHAIN_API_KEY env var name.
	if strings.Join(kinds, ",") != "ai_config_hint,long_lived_key,model_key_secret,shared_role" {
		t.Fatalf("A's open findings: %v", kinds)
	}
	var sharedSuggestions int64
	db.Raw(`SELECT count(*) FROM agent_suggestion s JOIN cloud_workload cw ON cw.workspace_id = s.workspace_id
		WHERE s.workspace_id = ? AND cw.identity_id = ? AND s.identity_id = cw.identity_id`, a.ws, a.shared).Scan(&sharedSuggestions)
	if sharedSuggestions != 0 {
		t.Fatalf("a shared role got %d suggestions", sharedSuggestions)
	}

	api := newARAPI(t, db).as(a)

	// Reads: A sees only A's rows.
	code, body := api.do(http.MethodGet, "/agent-runtime/ai-workloads", nil)
	if code != 200 || len(arData(body)) != 3 || api.lastPerm != "discovery:read" {
		t.Fatalf("A's AI workloads: %d %v (perm %s)", code, body, api.lastPerm)
	}
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), b.roleARN) || !strings.Contains(string(raw), a.roleARN) {
		t.Fatalf("A's AI workloads leak B's or miss A's: %s", raw)
	}
	if code, body = api.do(http.MethodGet, "/agent-runtime/ai-workloads?label=suggested_agent", nil); code != 200 || len(arData(body)) != 1 {
		t.Fatalf("suggested agents: %d %v", code, body)
	}
	if code, _ = api.do(http.MethodGet, "/agent-runtime/ai-workloads?connector_id="+b.conn.String(), nil); code != 200 {
		t.Fatalf("B's connector id as a filter: %d", code)
	} else if _, body = api.do(http.MethodGet, "/agent-runtime/ai-workloads?connector_id="+b.conn.String(), nil); len(arData(body)) != 0 {
		t.Fatalf("A filtering on B's connector sees %v", body)
	}
	if code, _ = api.do(http.MethodGet, "/agent-runtime/ai-workloads?label=robot", nil); code != 400 {
		t.Fatalf("bad label: %d", code)
	}
	code, body = api.do(http.MethodGet, "/agent-runtime/suggestions?state=pending", nil)
	if l := arData(body); code != 200 || len(l) != 1 || l[0].(map[string]any)["id"] != sugA.String() {
		t.Fatalf("A's suggestions: %d %v", code, body)
	}
	code, body = api.do(http.MethodGet, "/agent-runtime/findings?kind=shared_role", nil)
	if code != 200 || len(arData(body)) != 1 {
		t.Fatalf("A's shared-role findings: %d %v", code, body)
	}
	raw, _ = json.Marshal(body)
	if strings.Contains(string(raw), b.ws.String()) || strings.Contains(string(raw), b.account) {
		t.Fatalf("A's findings leak B's: %s", raw)
	}
	if code, _ = api.do(http.MethodGet, "/agent-runtime/findings?kind=everything", nil); code != 400 {
		t.Fatalf("bad kind: %d", code)
	}

	// Decisions on B's suggestion from A are 404, and change nothing.
	op := uuid.NewString()
	if code, body = api.do(http.MethodPost, "/agent-runtime/suggestions/"+sugB.String()+"/confirm",
		map[string]any{"operation_id": op, "version": 0}); code != 404 {
		t.Fatalf("A confirming B's suggestion: %d %v", code, body)
	}
	if code, body = api.do(http.MethodPost, "/agent-runtime/suggestions/"+sugB.String()+"/dismiss",
		map[string]any{"reason": "not mine"}); code != 404 {
		t.Fatalf("A dismissing B's suggestion: %d %v", code, body)
	}
	if _, st := arSuggestionID(t, db, b.ws, b.workload); st != services.SuggestionPending {
		t.Fatalf("B's suggestion after A's attempts: %q", st)
	}
	var bClass string
	db.Raw(`SELECT classification FROM iga_workload WHERE id = ?`, b.workload).Scan(&bClass)
	if bClass != models.ClassificationUnclassified {
		t.Fatalf("B's workload after A's confirm: %q", bClass)
	}

	// Confirm: classification and the suggestion in one transaction.
	code, body = api.do(http.MethodPost, "/agent-runtime/suggestions/"+sugA.String()+"/confirm",
		map[string]any{"operation_id": op, "version": 0, "purpose": "Customer support"})
	if code != 200 || api.lastPerm != "iga:review" {
		t.Fatalf("confirm: %d %v (perm %s)", code, body, api.lastPerm)
	}
	var row struct {
		Classification string
		State          string
		DecisionID     *uuid.UUID
	}
	db.Raw(`SELECT w.classification, s.state, s.decision_id FROM agent_suggestion s
		JOIN iga_workload w ON w.workspace_id = s.workspace_id AND w.id = s.workload_id WHERE s.id = ?`, sugA).Scan(&row)
	if row.Classification != models.ClassificationClassified || row.State != services.SuggestionConfirmed || row.DecisionID == nil {
		t.Fatalf("after confirm: %+v", row)
	}
	// A retry with the same operation is the stored outcome.
	if code, body = api.do(http.MethodPost, "/agent-runtime/suggestions/"+sugA.String()+"/confirm",
		map[string]any{"operation_id": op, "version": 0, "purpose": "Customer support"}); code != 200 {
		t.Fatalf("confirm retry: %d %v", code, body)
	}
	// A stale version is the classify contract's 409, and leaves the suggestion.
	if code, _ = api.do(http.MethodPost, "/agent-runtime/suggestions/"+sugA.String()+"/confirm",
		map[string]any{"operation_id": uuid.NewString(), "version": 0}); code != 409 {
		t.Fatalf("stale confirm: %d", code)
	}

	// Dismiss B's as B: final for the incarnation, even after a rescan.
	api.as(b)
	if code, body = api.do(http.MethodPost, "/agent-runtime/suggestions/"+sugB.String()+"/dismiss",
		map[string]any{"reason": "a fixed pipeline, not an agent"}); code != 200 {
		t.Fatalf("B dismissing its suggestion: %d %v", code, body)
	}
	if code, _ = api.do(http.MethodPost, "/agent-runtime/suggestions/"+sugB.String()+"/dismiss", map[string]any{}); code != 400 {
		t.Fatalf("dismiss without a reason: %d", code)
	}
	if _, err := svc.RunAgentInference(ctx, b.ws, b.conn); err != nil {
		t.Fatal(err)
	}
	if _, st := arSuggestionID(t, db, b.ws, b.workload); st != services.SuggestionDismissed {
		t.Fatalf("B's dismissed suggestion after a rescan: %q", st)
	}

	// The next inference mirrors A's classified agent into the Agents list.
	if _, err := svc.RunAgentInference(ctx, a.ws, a.conn); err != nil {
		t.Fatal(err)
	}
	var mirrored []struct {
		Fingerprint  string
		EvidenceMode string
		Status       string
	}
	db.Raw(`SELECT fingerprint, evidence_mode, status FROM discovered_agents WHERE workspace_id = ? AND source = 'aws'`, a.ws).Scan(&mirrored)
	if len(mirrored) != 1 || mirrored[0].EvidenceMode != models.EvidenceInferred || mirrored[0].Status != models.DiscoveredAgentUnregistered ||
		!strings.HasPrefix(mirrored[0].Fingerprint, "aws:"+a.account+":lambda_function:") {
		t.Fatalf("A's mirrored agents: %+v", mirrored)
	}
	var bMirrored int64
	db.Raw(`SELECT count(*) FROM discovered_agents WHERE workspace_id = ? AND source = 'aws'`, b.ws).Scan(&bMirrored)
	if bMirrored != 0 {
		t.Fatalf("B has %d mirrored agents, want 0 (nothing classified)", bMirrored)
	}

	// The resolver: A's role is an agent's in A, and names nothing in B.
	r := services.NewAgentRuntimeResolver(db)
	sub, err := r.Resolve(ctx, a.ws, a.conn, agentruntime.Attribution{How: agentruntime.AttributionSessionIssuer, ARN: a.roleARN, UniqueID: "AROAara"})
	if err != nil || sub.IdentityID != a.role || sub.Label != agentruntime.LabelAgent || sub.SharedRole || len(sub.WorkloadIDs) != 1 {
		t.Fatalf("resolve A's role in A: %+v %v", sub, err)
	}
	if sub, err = r.Resolve(ctx, b.ws, b.conn, agentruntime.Attribution{How: agentruntime.AttributionSessionIssuer, ARN: a.roleARN}); err != nil || sub.IdentityID != uuid.Nil {
		t.Fatalf("resolve A's role in B: %+v %v", sub, err)
	}
	if sub, _ = r.Resolve(ctx, a.ws, a.conn, agentruntime.Attribution{How: agentruntime.AttributionSessionIssuer, ARN: a.roleARN, UniqueID: "AROAOTHER"}); sub.IdentityID != uuid.Nil {
		t.Fatalf("another incarnation resolved: %+v", sub)
	}
}
