package integration

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	platformCtrl "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/tenancy"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// SecOps W1: the evidence store (every principal, idempotent across the
// stream, the poller and a backfill), retention by class skipping pinned
// rows, source heartbeats and COV-01, capability states and tier-3 gap
// declarations, the Azure and Kubernetes collectors' authentication, and
// cross-workspace isolation of every read.

func evSetup(t *testing.T, db *gorm.DB) {
	t.Helper()
	if ok, reason := services.AgentEvidenceStatus(db); !ok {
		t.Skipf("migration 170 not present: %s", reason)
	}
	agentruntime.ResetSinks()
	t.Cleanup(agentruntime.ResetSinks)
	agentruntime.RegisterSink(services.NewAgentEvidenceSink(db))
}

func evEvent(id, principalARN, source, name string, at time.Time) agentruntime.Event {
	return agentruntime.Event{EventID: id, EventTime: at, EventSource: source, EventName: name, EventType: "AwsApiCall",
		AccountID: "111111111111", Region: "us-east-1", PrincipalType: "IAMUser", PrincipalARN: principalARN,
		ErrorMessage: "secret message never stored"}
}

func evCount(t *testing.T, db *gorm.DB, q string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := db.Raw(q, args...).Scan(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

func TestAgentEvidenceIdempotentAllPrincipalsIsolated(t *testing.T) {
	db := igaDB(t)
	evSetup(t, db)
	a := p3NewGov(t, db, "ev-a")
	b := p3NewGov(t, db, "ev-b")
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	human := "arn:aws:iam::111111111111:user/alice"
	batch := []agentruntime.Event{
		evEvent("ev-1", human, "s3.amazonaws.com", "ListBuckets", now.Add(-time.Minute)),
		evEvent("ev-2", "arn:aws:iam::111111111111:user/ci", "ec2.amazonaws.com", "DescribeInstances", now.Add(-2*time.Minute)),
	}
	stream := agentruntime.WithDelivery(ctx, agentruntime.Delivery{Kind: agentruntime.DeliveryAWSStream})
	poll := agentruntime.WithDelivery(ctx, agentruntime.Delivery{Kind: agentruntime.DeliveryCloudTrailPoll,
		Ref: services.HeartbeatRef(a.conn) + "/region/us-east-1"})
	if err := agentruntime.Dispatch(stream, a.ws, a.conn, batch); err != nil {
		t.Fatal(err)
	}
	// The poller later reads the same events plus one more: stored once.
	if err := agentruntime.Dispatch(poll, a.ws, a.conn, append(batch,
		evEvent("ev-3", human, "iam.amazonaws.com", "CreateAccessKey", now.Add(-3*time.Minute)))); err != nil {
		t.Fatal(err)
	}
	// Workspace B: the same CloudTrail id is its own event.
	if err := agentruntime.Dispatch(stream, b.ws, b.conn, batch[:1]); err != nil {
		t.Fatal(err)
	}
	if n := evCount(t, db, `SELECT count(*) FROM agent_evidence_event WHERE workspace_id = ?`, a.ws); n != 3 {
		t.Fatalf("workspace A rows %d, want 3 (unlabelled principals included, duplicates once)", n)
	}
	if n := evCount(t, db, `SELECT count(*) FROM agent_evidence_event WHERE workspace_id = ? AND event_id IN ('ev-1','ev-2') AND source = 'aws_stream'`, a.ws); n != 2 {
		t.Errorf("first path must be kept as the source: %d", n)
	}
	if n := evCount(t, db, `SELECT count(*) FROM agent_evidence_event WHERE workspace_id = ? AND event_id = 'ev-3' AND source = 'cloudtrail_poll' AND record_class = 'elevated'`, a.ws); n != 1 {
		t.Errorf("ev-3 from the poller, elevated: %d", n)
	}
	if n := evCount(t, db, `SELECT count(*) FROM agent_evidence_event WHERE workspace_id = ? AND body::text LIKE '%never stored%'`, a.ws); n != 0 {
		t.Error("an error message reached the stored body")
	}
	if n := evCount(t, db, `SELECT count(*) FROM source_heartbeat WHERE workspace_id = ? AND source_kind IN ('aws_stream','cloudtrail_poll')`, a.ws); n != 2 {
		t.Errorf("heartbeats %d, want the stream's and the region poll's", n)
	}

	svc := services.NewAgentEvidenceService(db)
	rows, _, err := svc.List(ctx, a.ws, services.AgentEvidenceFilter{Principal: human}, "", 0)
	if err != nil || len(rows) != 2 {
		t.Fatalf("A principal filter: %v %d", err, len(rows))
	}
	page, next, err := svc.List(ctx, a.ws, services.AgentEvidenceFilter{}, "", 2)
	if err != nil || len(page) != 2 || next == "" {
		t.Fatalf("page 1: %v %d %q", err, len(page), next)
	}
	page2, _, err := svc.List(ctx, a.ws, services.AgentEvidenceFilter{}, next, 2)
	if err != nil || len(page2) != 1 || page2[0].EventID != "ev-3" {
		t.Fatalf("page 2: %v %+v", err, page2)
	}
	from := now.Add(-150 * time.Second)
	if win, _, _ := svc.List(ctx, a.ws, services.AgentEvidenceFilter{From: &from}, "", 0); len(win) != 2 {
		t.Errorf("from filter: %d", len(win))
	}
	// Isolation: B sees only its own row, whatever the filter names.
	brows, _, err := svc.List(ctx, b.ws, services.AgentEvidenceFilter{}, "", 0)
	if err != nil || len(brows) != 1 || brows[0].ConnectorID == nil || *brows[0].ConnectorID != b.conn {
		t.Fatalf("B rows: %v %+v", err, brows)
	}
	if bp, _, _ := svc.List(ctx, b.ws, services.AgentEvidenceFilter{Principal: "arn:aws:iam::111111111111:user/ci"}, "", 0); len(bp) != 0 {
		t.Error("B must not see A's principal")
	}
}

func TestAgentEvidenceRetentionSkipsPinned(t *testing.T) {
	db := igaDB(t)
	if ok, reason := services.AgentEvidenceStatus(db); !ok {
		t.Skipf("migration 170 not present: %s", reason)
	}
	a := p3NewGov(t, db, "ev-ret")
	ctx := context.Background()
	old := time.Now().UTC().Add(-100 * 24 * time.Hour)
	sink := services.NewAgentEvidenceSink(db).WithClock(func() time.Time { return old })
	if err := sink.Process(ctx, a.ws, a.conn, []agentruntime.Event{
		evEvent("r-plain", "arn:aws:iam::111111111111:user/a", "ec2.amazonaws.com", "DescribeInstances", old),
		evEvent("r-pinned", "arn:aws:iam::111111111111:user/a", "ec2.amazonaws.com", "DescribeVpcs", old),
		evEvent("r-elevated", "arn:aws:iam::111111111111:user/a", "secretsmanager.amazonaws.com", "GetSecretValue", old),
	}); err != nil {
		t.Fatal(err)
	}
	var pinned []uuid.UUID
	db.Raw(`SELECT id FROM agent_evidence_event WHERE workspace_id = ? AND event_id = 'r-pinned'`, a.ws).Scan(&pinned)
	if err := tenancy.InWorkspace(ctx, db, a.ws, func(tx *gorm.DB) error {
		n, err := services.PinAgentEvidence(tx, a.ws, pinned, 1)
		if err == nil && n != 1 {
			err = fmt.Errorf("pinned %d rows", n)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	n, err := services.NewAgentEvidenceService(db).Purge(ctx, a.ws)
	if err != nil || n != 1 {
		t.Fatalf("purge: %v deleted %d, want 1", err, n)
	}
	var left []string
	db.Raw(`SELECT event_id FROM agent_evidence_event WHERE workspace_id = ? ORDER BY event_id`, a.ws).Scan(&left)
	if strings.Join(left, ",") != "r-elevated,r-pinned" {
		t.Fatalf("left %v: the pinned and the elevated (1 y) rows must stay", left)
	}
	// A shorter elevated retention than default is refused; a valid change applies.
	if _, err := services.NewAgentEvidenceService(db).SetRetention(ctx, a.ws, a.author, map[string]int{"elevated": 60}); err == nil {
		t.Error("elevated shorter than default must be refused")
	}
	if _, err := services.NewAgentEvidenceService(db).SetRetention(ctx, a.ws, a.author, map[string]int{"elevated": 95}); err != nil {
		t.Fatal(err)
	}
	if n, _ := services.NewAgentEvidenceService(db).Purge(ctx, a.ws); n != 1 {
		t.Errorf("after elevated=95d, the 100-day elevated row goes: %d", n)
	}
}

func TestCoverageSilenceRaisesAndResolvesCOV01(t *testing.T) {
	db := igaDB(t)
	if ok, reason := services.AgentEvidenceStatus(db); !ok {
		t.Skipf("migration 170 not present: %s", reason)
	}
	a := p3NewGov(t, db, "ev-cov")
	b := p3NewGov(t, db, "ev-cov-b")
	ctx := context.Background()
	p3exec(t, db, `INSERT INTO agent_event_stream (connector_id, workspace_id, secret_hash, secret_prefix, created_at, silent_after)
		VALUES (?, ?, ?, 'aev_test', now() - interval '10 hours', interval '6 hours')`, a.conn, a.ws, strings.Repeat("a", 64))
	cov := services.NewAgentCoverageService(db)
	for i := 0; i < 2; i++ {
		if _, err := cov.EvaluateSources(ctx, a.ws); err != nil {
			t.Fatal(err)
		}
	}
	if n := evCount(t, db, `SELECT count(*) FROM agent_alert WHERE workspace_id = ? AND detection = 'COV-01' AND state = 'open' AND subject_label = 'source'`, a.ws); n != 1 {
		t.Fatalf("open COV-01 alerts %d, want exactly 1", n)
	}
	if n := evCount(t, db, `SELECT count(*) FROM source_heartbeat WHERE workspace_id = ? AND state = 'silent'`, a.ws); n != 1 {
		t.Fatalf("silent heartbeats %d", n)
	}
	// B sees no alert and no heartbeat of A.
	if _, err := cov.EvaluateSources(ctx, b.ws); err != nil {
		t.Fatal(err)
	}
	if hb, _ := cov.Sources(ctx, b.ws); len(hb) != 0 {
		t.Errorf("B sources %+v", hb)
	}
	alerts, _, err := services.NewAgentAlertService(db).List(ctx, b.ws, services.AgentAlertFilter{}, "", 0)
	if err != nil || len(alerts) != 0 {
		t.Errorf("B alerts %v %d", err, len(alerts))
	}
	// The stream delivers again: resolved, and the gap is queued for a backfill.
	p3exec(t, db, `UPDATE agent_event_stream SET last_received_at = now() WHERE connector_id = ?`, a.conn)
	if _, err := cov.EvaluateSources(ctx, a.ws); err != nil {
		t.Fatal(err)
	}
	if n := evCount(t, db, `SELECT count(*) FROM agent_alert WHERE workspace_id = ? AND detection = 'COV-01' AND state = 'resolved'`, a.ws); n != 1 {
		t.Fatalf("resolved COV-01 %d", n)
	}
	if n := evCount(t, db, `SELECT count(*) FROM agent_trail_backfill WHERE workspace_id = ? AND cause = 'gap' AND connector_id = ?`, a.ws, a.conn); n != 1 {
		t.Errorf("gap backfills %d", n)
	}
	if n := evCount(t, db, `SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event IN ('agent_alert.opened','agent_alert.resolved') AND payload->>'detection' = 'COV-01'`, a.ws); n != 2 {
		t.Errorf("gov events %d", n)
	}
}

func evGrantApprove(t *testing.T, db *gorm.DB, ws, user uuid.UUID) {
	t.Helper()
	p3exec(t, db, `INSERT INTO role_permissions (role_id, permission_id)
		SELECT m.role_id, p.id FROM workspace_memberships m, permissions p
		 WHERE m.workspace_id = ? AND m.user_id = ? AND p.full_permission_string = 'governance:approve' AND p.workspace_id IS NULL
		ON CONFLICT DO NOTHING`, ws, user)
}

func TestCoverageCapabilitiesAndTier3Declare(t *testing.T) {
	db := igaDB(t)
	if ok, reason := services.AgentEvidenceStatus(db); !ok {
		t.Skipf("migration 170 not present: %s", reason)
	}
	a := p3NewGov(t, db, "ev-cap-a")
	b := p3NewGov(t, db, "ev-cap-b")
	ctx := context.Background()
	cov := services.NewAgentCoverageService(db)
	if err := cov.ComputeCapabilities(ctx, a.ws); err != nil {
		t.Fatal(err)
	}
	states, err := cov.Capabilities(ctx, a.ws, services.CoverageCapabilitiesFilter{})
	if err != nil || len(states) != 13 {
		t.Fatalf("states %v %d", err, len(states))
	}
	byCap := map[string]services.AgentCapabilityState{}
	for _, s := range states {
		byCap[s.Capability] = s
		if s.EstateScope != "111111111111" {
			t.Errorf("scope %q", s.EstateScope)
		}
	}
	c4 := byCap["C4"]
	if c4.State != "off" || c4.GapKind != "broken" || !strings.Contains(c4.Detail, "not implemented") {
		t.Fatalf("C4 %+v", c4)
	}
	// Nobody holds governance:approve: refused.
	if _, err := cov.Declare(ctx, a.ws, c4.ID, a.author, "accepted risk"); err == nil || !strings.Contains(err.Error(), "governance:approve") {
		t.Fatalf("no approver: %v", err)
	}
	evGrantApprove(t, db, a.ws, a.author)
	evGrantApprove(t, db, a.ws, a.approver)
	res, err := cov.Declare(ctx, a.ws, c4.ID, a.author, "flow logs out of scope this quarter")
	if err != nil || res.Declaration.State != "pending" || res.State.GapKind != "broken" {
		t.Fatalf("declare: %v %+v", err, res)
	}
	if _, err := cov.Declare(ctx, a.ws, c4.ID, a.approver, "again"); err == nil {
		t.Error("a second open request must be refused")
	}
	// Workspace B can neither see nor decide A's declaration.
	if _, err := cov.Decide(ctx, b.ws, res.Declaration.ID, b.approver, true, ""); err == nil || !strings.Contains(err.Error(), "Not found") {
		t.Errorf("B decides A's declaration: %v", err)
	}
	if _, err := cov.Declare(ctx, b.ws, c4.ID, b.author, "x"); err == nil || !strings.Contains(err.Error(), "Not found") {
		t.Errorf("B declares A's state: %v", err)
	}
	if bs, _ := cov.Capabilities(ctx, b.ws, services.CoverageCapabilitiesFilter{}); len(bs) != 0 {
		t.Errorf("B sees %d states before computing its own", len(bs))
	}
	// The requester never decides their own.
	if _, err := cov.Decide(ctx, a.ws, res.Declaration.ID, a.author, true, ""); err == nil || !strings.Contains(err.Error(), "second person") {
		t.Fatalf("self approval: %v", err)
	}
	out, err := cov.Decide(ctx, a.ws, res.Declaration.ID, a.approver, true, "agreed")
	if err != nil || out.Declaration.State != "applied" || out.State.GapKind != "declared" || out.State.DeclaredBy == nil || *out.State.DeclaredBy != a.author {
		t.Fatalf("approve: %v %+v", err, out)
	}
	// Recomputing keeps the declaration while the capability stays off.
	if err := cov.ComputeCapabilities(ctx, a.ws); err != nil {
		t.Fatal(err)
	}
	if again, _ := cov.Capabilities(ctx, a.ws, services.CoverageCapabilitiesFilter{Capability: "C4"}); len(again) != 1 || again[0].GapKind != "declared" {
		t.Fatalf("after recompute %+v", again)
	}

	// Break-glass: B's author is its only approver.
	evGrantApprove(t, db, b.ws, b.author)
	if err := cov.ComputeCapabilities(ctx, b.ws); err != nil {
		t.Fatal(err)
	}
	bc9, _ := cov.Capabilities(ctx, b.ws, services.CoverageCapabilitiesFilter{Capability: "C9"})
	if len(bc9) != 1 {
		t.Fatalf("B C9 %+v", bc9)
	}
	bg, err := cov.Declare(ctx, b.ws, bc9[0].ID, b.author, "single admin workspace")
	if err != nil || bg.Declaration.State != "applied" || !bg.Declaration.BreakGlass || bg.Declaration.ReviewDueAt == nil || bg.State.GapKind != "declared" {
		t.Fatalf("break-glass: %v %+v", err, bg)
	}
	if _, err := cov.Review(ctx, b.ws, bg.Declaration.ID, b.author); err == nil {
		t.Error("the declarer must not review their own break-glass")
	}
	if n := evCount(t, db, `SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = 'coverage.gap_declared_break_glass'`, b.ws); n != 1 {
		t.Errorf("break-glass events %d", n)
	}
	// /capabilities block: A's scopes only.
	_, scopes := services.CoverageCapabilitiesBlock(ctx, db, a.ws)
	if len(scopes) != 1 || scopes[0]["estate_scope"] != "111111111111" {
		t.Errorf("capabilities block %+v", scopes)
	}
}

/* ------------------------------- collectors ------------------------------- */

func evEngine(db *gorm.DB) *gin.Engine {
	gin.SetMode(gin.TestMode)
	eng := gin.New()
	platformCtrl.MountAgentCollectorIngestRoutes(eng.Group("/authsec"), platformCtrl.NewAgentEvidenceControllerWith(db))
	return eng
}

func evPost(eng *gin.Engine, path string, hdr map[string]string, body string) (int, string) {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func TestCollectorIngestAuthAndIsolation(t *testing.T) {
	db := igaDB(t)
	evSetup(t, db)
	a := p3NewGov(t, db, "ev-col-a")
	b := p3NewGov(t, db, "ev-col-b")
	ctx := context.Background()
	const tenant = "aaaaaaaa-1111-2222-3333-444444444444"
	azConn := uuid.New()
	p3exec(t, db, `INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, auth_ref)
		VALUES (?, ?, 'azure', 'tenant', ?, 'vault://w1/az')`, azConn, a.ws, tenant)
	col := services.NewCollectorService(db)
	if _, _, err := col.EnableOrRotateAzure(ctx, b.ws, azConn, "x"); err == nil {
		t.Fatal("B must not enable ingest on A's connector")
	}
	_, secret, err := col.EnableOrRotateAzure(ctx, a.ws, azConn, a.author.String())
	if err != nil {
		t.Fatal(err)
	}
	eng := evEngine(db)
	body := `{"workspace_id":"` + b.ws.String() + `","records":[
	  {"time":"2026-11-24T10:00:00Z","operationName":"Sign-in activity","category":"SignInLogs","tenantId":"` + tenant + `","resultType":"0",
	   "properties":{"id":"az-1","userId":"u-1","userPrincipalName":"alice@x"}},
	  {"time":"2026-11-24T10:00:00Z","operationName":"Sign-in activity","category":"SignInLogs","tenantId":"bbbbbbbb-0000-0000-0000-000000000000","resultType":"0",
	   "properties":{"id":"az-2","userId":"u-2"}}]}`
	if code, _ := evPost(eng, "/authsec/ingest/azure/events", nil, body); code != http.StatusUnauthorized {
		t.Errorf("no secret: %d", code)
	}
	wrong, _ := services.GenerateAzureEventSecret()
	if code, _ := evPost(eng, "/authsec/ingest/azure/events", map[string]string{services.AgentEventSecretHeader: wrong}, body); code != http.StatusUnauthorized {
		t.Errorf("wrong secret: %d", code)
	}
	code, out := evPost(eng, "/authsec/ingest/azure/events", map[string]string{services.AgentEventSecretHeader: secret}, body)
	if code != http.StatusAccepted || !strings.Contains(out, `"rejected_tenant":1`) {
		t.Fatalf("ingest: %d %s", code, out)
	}
	if n := evCount(t, db, `SELECT count(*) FROM agent_evidence_event WHERE workspace_id = ? AND source = 'azure_diag' AND event_id = 'az-1' AND principal = 'u-1'`, a.ws); n != 1 {
		t.Errorf("A azure rows %d", n)
	}
	if n := evCount(t, db, `SELECT count(*) FROM agent_evidence_event WHERE workspace_id = ?`, b.ws); n != 0 {
		t.Errorf("the body's workspace must be ignored: B has %d rows", n)
	}
	// Revoked: refused.
	if _, err := col.RevokeAzure(ctx, a.ws, azConn); err != nil {
		t.Fatal(err)
	}
	if code, _ := evPost(eng, "/authsec/ingest/azure/events", map[string]string{services.AgentEventSecretHeader: secret}, body); code != http.StatusUnauthorized {
		t.Errorf("revoked secret: %d", code)
	}

	// Kubernetes: a workspace-wide ingest token names its cluster; another
	// workspace's cluster is 404; a bad token 401; a bound token needs no header.
	srcA, srcB := uuid.New(), uuid.New()
	p3exec(t, db, `INSERT INTO discovery_sources (id, workspace_id, kind, display_name, cluster_name) VALUES (?, ?, 'k8s_webhook', 'a', 'ca')`, srcA, a.ws)
	p3exec(t, db, `INSERT INTO discovery_sources (id, workspace_id, kind, display_name, cluster_name) VALUES (?, ?, 'k8s_webhook', 'b', 'cb')`, srcB, b.ws)
	repo := repositories.NewDiscoveryIngestTokenRepository(db)
	_, wide, err := repo.Mint(a.ws, nil, "w1", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, bound, err := repo.Mint(a.ws, &srcA, "w1b", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	audit := `{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[
	  {"auditID":"k-1","stage":"ResponseComplete","verb":"get","user":{"username":"system:serviceaccount:ns:agent"},
	   "objectRef":{"resource":"secrets","namespace":"ns","name":"db"},"responseStatus":{"code":200},
	   "requestReceivedTimestamp":"2026-11-24T10:00:00Z"}]}`
	if code, _ := evPost(eng, "/authsec/ingest/k8s/audit", map[string]string{"Authorization": "Bearer nope"}, audit); code != http.StatusUnauthorized {
		t.Errorf("bad token: %d", code)
	}
	if code, _ := evPost(eng, "/authsec/ingest/k8s/audit", map[string]string{"Authorization": "Bearer " + wide,
		services.K8sAuditSourceHeader: srcB.String()}, audit); code != http.StatusNotFound {
		t.Errorf("another workspace's cluster: %d", code)
	}
	if code, out := evPost(eng, "/authsec/ingest/k8s/audit", map[string]string{"Authorization": "Bearer " + wide,
		services.K8sAuditSourceHeader: srcA.String()}, audit); code != http.StatusAccepted {
		t.Fatalf("own cluster: %d %s", code, out)
	}
	if code, out := evPost(eng, "/authsec/ingest/k8s/audit", map[string]string{"Authorization": "Bearer " + bound}, audit); code != http.StatusAccepted {
		t.Fatalf("bound token: %d %s", code, out)
	}
	if n := evCount(t, db, `SELECT count(*) FROM agent_evidence_event WHERE workspace_id = ? AND provider = 'k8s' AND event_id = 'k-1' AND record_class = 'elevated'`, a.ws); n != 1 {
		t.Errorf("k8s rows %d (one, stored once, elevated: a secrets read)", n)
	}
	if n := evCount(t, db, `SELECT count(*) FROM source_heartbeat WHERE workspace_id = ? AND source_kind = 'k8s_audit' AND connector_id = ?`, a.ws, srcA); n != 1 {
		t.Errorf("k8s heartbeat %d", n)
	}
	// A source holding an actuation credential cannot be spoken for by an ingest token.
	p3exec(t, db, `UPDATE discovery_sources SET actuation_token_hash = ? WHERE id = ?`, strings.Repeat("b", 64), srcA)
	if code, _ := evPost(eng, "/authsec/ingest/k8s/audit", map[string]string{"Authorization": "Bearer " + bound}, audit); code != http.StatusUnauthorized {
		t.Errorf("credentialed source via ingest token: %d", code)
	}
}

/* -------------------------------- backfill -------------------------------- */

type evBucket struct{ objects map[string][]byte }

func (f *evBucket) ListObjectsV2(_ context.Context, in *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	out := &s3.ListObjectsV2Output{}
	seen := map[string]bool{}
	for k := range f.objects {
		p := aws.ToString(in.Prefix)
		if !strings.HasPrefix(k, p) {
			continue
		}
		if in.Delimiter != nil {
			if i := strings.Index(k[len(p):], "/"); i >= 0 {
				cp := k[:len(p)+i+1]
				if !seen[cp] {
					seen[cp] = true
					out.CommonPrefixes = append(out.CommonPrefixes, s3types.CommonPrefix{Prefix: aws.String(cp)})
				}
				continue
			}
		}
		out.Contents = append(out.Contents, s3types.Object{Key: aws.String(k)})
	}
	return out, nil
}

func (f *evBucket) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	b, ok := f.objects[aws.ToString(in.Key)]
	if !ok {
		return nil, fmt.Errorf("NoSuchKey")
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(b))}, nil
}

func TestTrailBackfillFakeS3(t *testing.T) {
	db := igaDB(t)
	evSetup(t, db)
	a := p3NewGov(t, db, "ev-bf-a")
	b := p3NewGov(t, db, "ev-bf-b")
	ctx := context.Background()
	day := time.Now().UTC().Add(-48 * time.Hour).Truncate(24 * time.Hour)
	rec := func(id string, at time.Time) map[string]any {
		return map[string]any{"eventID": id, "eventName": "ListBuckets", "eventSource": "s3.amazonaws.com",
			"eventTime": at.Format(time.RFC3339), "recipientAccountId": "111111111111", "awsRegion": "us-east-1",
			"userIdentity": map[string]any{"type": "IAMUser", "arn": "arn:aws:iam::111111111111:user/x"}}
	}
	raw, _ := json.Marshal(map[string]any{"Records": []any{rec("bf-1", day.Add(time.Hour)), rec("bf-2", day.Add(2*time.Hour))}})
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	bucket := &evBucket{objects: map[string][]byte{
		"AWSLogs/111111111111/CloudTrail/us-east-1/" + day.Format("2006/01/02") + "/111111111111_CloudTrail_us-east-1_" +
			day.Add(2*time.Hour).Format("20060102T1504Z") + "_x.json.gz": gz.Bytes()}}
	locate := func(_ context.Context, ws, conn uuid.UUID, account string) (services.TrailBucketAPI, services.TrailLocation, error) {
		if ws != a.ws || conn != a.conn {
			return nil, services.TrailLocation{}, fmt.Errorf("unexpected connector")
		}
		return bucket, services.TrailLocation{Bucket: "trail", AccountID: account}, nil
	}
	svc := services.NewTrailBackfillService(db, locate)
	if _, err := svc.Request(ctx, b.ws, a.conn, b.author, day, day.Add(24*time.Hour)); err == nil || !strings.Contains(err.Error(), "Not found") {
		t.Fatalf("B backfilling A's connector: %v", err)
	}
	if _, err := svc.Request(ctx, a.ws, a.conn, a.author, day, day.Add(8*24*time.Hour)); err == nil {
		t.Error("a window over 7 days must be refused")
	}
	// The stream already delivered bf-1.
	stream := agentruntime.WithDelivery(ctx, agentruntime.Delivery{Kind: agentruntime.DeliveryAWSStream})
	if err := agentruntime.Dispatch(stream, a.ws, a.conn, []agentruntime.Event{evEvent("bf-1", "arn:aws:iam::111111111111:user/x", "s3.amazonaws.com", "ListBuckets", day.Add(time.Hour))}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		bf, err := svc.Request(ctx, a.ws, a.conn, a.author, day, day.Add(24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if ran, err := svc.Run(ctx, a.ws, bf.ID); err != nil || !ran {
			t.Fatalf("run: %v %v", ran, err)
		}
	}
	rows, _ := svc.List(ctx, a.ws)
	if len(rows) != 2 || rows[0].State != "done" || rows[0].EventsRead != 2 || rows[0].ObjectsRead != 1 {
		t.Fatalf("backfills %+v", rows)
	}
	if n := evCount(t, db, `SELECT count(*) FROM agent_evidence_event WHERE workspace_id = ? AND event_id IN ('bf-1','bf-2')`, a.ws); n != 2 {
		t.Errorf("rows %d, want 2 (idempotent across stream and backfills)", n)
	}
	if n := evCount(t, db, `SELECT count(*) FROM agent_evidence_event WHERE workspace_id = ? AND event_id = 'bf-2' AND source = 'trail_backfill'`, a.ws); n != 1 {
		t.Errorf("bf-2 from the backfill: %d", n)
	}
	if bl, _ := svc.List(ctx, b.ws); len(bl) != 0 {
		t.Errorf("B sees A's backfills: %d", len(bl))
	}
}
