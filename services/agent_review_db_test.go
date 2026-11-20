package services

// Database tests for the agent review queue and the AWS agents mirror's
// treatment of the service's sightings. They need a migrated schema at
// IGA_TEST_DSN and skip without it.

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

func reviewTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("IGA_TEST_DSN")
	if dsn == "" {
		t.Skip("IGA_TEST_DSN not set; skipping the agent review database tests")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() {
		if s, err := db.DB(); err == nil {
			_ = s.Close()
		}
	})
	return db
}

func reviewWorkspace(t *testing.T, db *gorm.DB) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if err := db.Exec(`INSERT INTO workspaces
		(id,name,slug,owner_user_id,workspace_type,workspace_domain,email,status,created_at,updated_at)
		VALUES (?,?,NULL,?,'team',?,?,'active',NOW(),NOW())`,
		id, "ws-agent-review", id, id.String()+".test", id.String()+"@test.local").Error; err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	t.Cleanup(func() {
		db.Exec(`DELETE FROM discovered_agents WHERE workspace_id = ?`, id)
		db.Exec(`DELETE FROM agent_finding WHERE workspace_id = ?`, id)
		db.Exec(`DELETE FROM cloud_workload WHERE workspace_id = ?`, id)
		db.Exec(`DELETE FROM cloud_connector WHERE workspace_id = ?`, id)
		db.Exec(`DELETE FROM workspaces WHERE id = ?`, id)
	})
	return id
}

func reviewConnector(t *testing.T, db *gorm.DB, ws uuid.UUID, account string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.Raw(`INSERT INTO cloud_connector (workspace_id, provider, scope_kind, scope_id, auth_ref, status)
		VALUES (?, 'aws', 'account', ?, 'kv/data/test', 'active') RETURNING id`, ws, account).Row().Scan(&id); err != nil {
		t.Fatalf("create connector: %v", err)
	}
	return id
}

func reviewWorkload(t *testing.T, db *gorm.DB, ws, conn uuid.UUID, native string, review map[string]any) uuid.UUID {
	t.Helper()
	attrs := map[string]any{"status": "Active"}
	if review != nil {
		attrs["agent_review"] = review
	}
	b, _ := json.Marshal(attrs)
	var id uuid.UUID
	if err := db.Raw(`INSERT INTO cloud_workload (workspace_id, connector_id, runtime_kind, native_id, name, region, attrs)
		VALUES (?, ?, 'lambda_function', ?, ?, 'us-east-1', ?::jsonb) RETURNING id`,
		ws, conn, native, native, string(b)).Row().Scan(&id); err != nil {
		t.Fatalf("create workload: %v", err)
	}
	return id
}

func reviewOf(t *testing.T, db *gorm.DB, id uuid.UUID) map[string]any {
	t.Helper()
	var raw string
	if err := db.Raw(`SELECT COALESCE(attrs->'agent_review', 'null'::jsonb)::text FROM cloud_workload WHERE id = ?`, id).
		Scan(&raw).Error; err != nil {
		t.Fatalf("read review: %v", err)
	}
	var out map[string]any
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func TestAgentReviewQueueSetsPendingOnlyWhereFree(t *testing.T) {
	db := reviewTestDB(t)
	t.Setenv(AgentReviewServiceTokenEnv, "svc")
	ws := reviewWorkspace(t, db)
	conn := reviewConnector(t, db, ws, "111122223333")
	now := time.Now().UTC()
	old := now.Add(-30 * 24 * time.Hour).Format(time.RFC3339)
	recent := now.Add(-24 * time.Hour).Format(time.RFC3339)

	fresh := reviewWorkload(t, db, ws, conn, "fn-fresh", nil)
	stale := reviewWorkload(t, db, ws, conn, "fn-stale", map[string]any{"status": "decided", "decided_at": old,
		"attempts": 0, "verdict": map[string]any{"label": "NON_AI_WORKLOAD"}})
	busy := reviewWorkload(t, db, ws, conn, "fn-busy", map[string]any{"status": "in_progress", "lease_owner": "w1:x", "attempts": 1})
	done := reviewWorkload(t, db, ws, conn, "fn-done", map[string]any{"status": "decided", "decided_at": recent})

	// Another workspace's workload, named in the same draft, stays untouched.
	ws2 := reviewWorkspace(t, db)
	conn2 := reviewConnector(t, db, ws2, "444455556666")
	foreign := reviewWorkload(t, db, ws2, conn2, "fn-foreign", nil)

	var queued int
	err := tenancy.InWorkspace(context.Background(), db, ws, func(tx *gorm.DB) error {
		var err error
		queued, err = queueAgentReviews(tx, ws, conn, []findingDraft{sharedRoleDraft(fresh, stale, busy, done, foreign)}, now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if queued != 2 {
		t.Fatalf("queued %d, want 2 (the fresh and the stale workload)", queued)
	}
	r := reviewOf(t, db, fresh)
	if r["status"] != "pending" || r["reason"] != AgentReviewReasonSharedRole || r["requested_at"] == nil {
		t.Errorf("fresh review = %v, want pending shared_role with requested_at", r)
	}
	if ctx, _ := r["context"].(map[string]any); ctx["role_arn"] != "arn:aws:iam::1:role/Shared" {
		t.Errorf("context = %v, want the shared role", r["context"])
	}
	r = reviewOf(t, db, stale)
	if r["status"] != "pending" || r["attempts"] != float64(0) {
		t.Errorf("stale review = %v, want pending again with attempts reset", r)
	}
	if v, _ := r["verdict"].(map[string]any); v["label"] != "NON_AI_WORKLOAD" {
		t.Error("the previous verdict must survive the re-request (the service compares against it)")
	}
	if reviewOf(t, db, busy)["status"] != "in_progress" {
		t.Error("a review the service holds must be left alone")
	}
	if reviewOf(t, db, done)["status"] != "decided" {
		t.Error("a review decided yesterday must not be queued again")
	}
	if reviewOf(t, db, foreign) != nil {
		t.Error("another workspace's workload must never be touched")
	}
}

func TestAgentReviewQueueReadsUnresolvedDNSFindings(t *testing.T) {
	db := reviewTestDB(t)
	t.Setenv(AgentReviewServiceTokenEnv, "svc")
	ws := reviewWorkspace(t, db)
	conn := reviewConnector(t, db, ws, "111122223333")
	a := reviewWorkload(t, db, ws, conn, "fn-a", nil)
	b := reviewWorkload(t, db, ws, conn, "fn-b", nil)
	subj, _ := json.Marshal(map[string]any{"kind": "workload_set", "resolved": false, "region": "us-east-1",
		"eni_id": "eni-1", "candidates": []map[string]any{{"cloud_workload_id": a}, {"cloud_workload_id": b}}})
	if err := db.Exec(`INSERT INTO agent_finding (workspace_id, connector_id, kind, subject_key, subject, evidence,
		state, first_seen, last_seen) VALUES (?, ?, 'ai_network_traffic', 'lambda_eni:us-east-1:eni-1', ?::jsonb, '{}'::jsonb,
		'open', now(), now())`, ws, conn, string(subj)).Error; err != nil {
		t.Fatalf("create finding: %v", err)
	}

	err := tenancy.InWorkspace(context.Background(), db, ws, func(tx *gorm.DB) error {
		_, err := queueAgentReviews(tx, ws, conn, nil, time.Now().UTC())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []uuid.UUID{a, b} {
		if r := reviewOf(t, db, id); r["status"] != "pending" || r["reason"] != AgentReviewReasonUnattributedDNS {
			t.Errorf("review = %v, want pending unattributed_dns", r)
		}
	}
}

func TestAWSAgentsMirrorKeepsTheReviewServiceSightings(t *testing.T) {
	db := reviewTestDB(t)
	ws := reviewWorkspace(t, db)
	account := "111122223333"
	connID := reviewConnector(t, db, ws, account)
	conn := arConnector{ID: connID, ScopeID: account}
	now := time.Now().UTC()

	sighting := func(native string, meta map[string]any) string {
		fp := AWSAgentFingerprint(account, models.WorkloadLambdaFunction, native)
		meta["connector_id"] = connID
		b, _ := json.Marshal(meta)
		if _, _, err := repositories.NewDiscoveryRepository(db).UpsertSighting(&models.DiscoveredAgent{
			ID: uuid.New(), WorkspaceID: ws, Source: models.DiscoverySourceAWS, Fingerprint: fp,
			DisplayName: native, Metadata: b, DeploymentOrigin: models.DeploymentOriginUnknown,
			EvidenceMode: models.EvidenceInferred, Status: models.DiscoveredAgentUnregistered,
			RuntimeStatus: models.RuntimeStatusUnknown, RuntimeObservedAt: &now,
			FirstSeenAt: now, LastSeenAt: now, SightingCount: 1, CreatedBy: "test",
		}); err != nil {
			t.Fatalf("sighting: %v", err)
		}
		return fp
	}
	reviewed := sighting("fn-reviewed", map[string]any{"origin": AgentReviewSightingOrigin})
	mirrored := sighting("fn-mirrored", map[string]any{})
	status := func(fp string) string {
		var s string
		db.Raw(`SELECT runtime_status FROM discovered_agents WHERE workspace_id = ? AND fingerprint = ?`, ws, fp).Scan(&s)
		return s
	}
	retire := func(present map[string]bool) {
		t.Helper()
		if err := tenancy.InWorkspace(context.Background(), db, ws, func(tx *gorm.DB) error {
			return retireAWSAgents(tx, repositories.NewDiscoveryRepository(tx), ws, conn, map[string]bool{}, present, now.Add(time.Second))
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Both workloads still in the inventory, neither classified.
	retire(map[string]bool{reviewed: true, mirrored: true})
	if status(reviewed) == models.RuntimeStatusGone {
		t.Error("the review service's sighting must stay while its workload is in the inventory")
	}
	if status(mirrored) != models.RuntimeStatusGone {
		t.Error("a mirrored agent no longer classified is still retired")
	}
	// The reviewed workload left the inventory.
	retire(map[string]bool{})
	if status(reviewed) != models.RuntimeStatusGone {
		t.Error("the review service's sighting is retired once its workload is gone")
	}
}

func reviewActivity(t *testing.T, db *gorm.DB, ws, conn, identity uuid.UUID, at time.Time, calls ...string) {
	t.Helper()
	for i, c := range calls {
		kind, src, name, model := "cloud_action", c, "Call", ""
		if c == "bedrock" {
			kind, src, name, model = "model_call", "bedrock", "InvokeModel", "anthropic.claude-3-sonnet"
		} else if n := len(c); n > 0 {
			for j := 0; j < n; j++ {
				if c[j] == ':' {
					src, name = c[:j], c[j+1:]
				}
			}
		}
		attrs, _ := json.Marshal(map[string]any{"event_source": src + ".amazonaws.com", "event_name": name,
			"request_facts": map[string]any{"model_id": model}})
		if err := db.Exec(`INSERT INTO agent_activity_event (workspace_id, connector_id, identity_id, source, kind,
			occurred_at, action, outcome, provider_event_id, attrs)
			VALUES (?, ?, ?, 'cloudtrail', ?, ?, ?, 'success', ?, ?::jsonb)`,
			ws, conn, identity, kind, at.Add(time.Duration(i)*time.Second), src+":"+name, uuid.NewString(), string(attrs)).Error; err != nil {
			t.Fatalf("activity: %v", err)
		}
	}
}

func TestAgentRulesDecideWithoutOverridingTheReviewService(t *testing.T) {
	db := reviewTestDB(t)
	t.Setenv(AgentReviewServiceTokenEnv, "svc")
	ws := reviewWorkspace(t, db)
	t.Cleanup(func() {
		_ = db.Transaction(func(tx *gorm.DB) error {
			tx.Exec(agentActivityRetentionPurge) // the append-only trigger lets retention delete
			return tx.Exec(`DELETE FROM agent_activity_event WHERE workspace_id = ?`, ws).Error
		})
	})
	account := "111122223333"
	connID := reviewConnector(t, db, ws, account)
	conn := arConnector{ID: connID, ScopeID: account}
	now := time.Now().UTC()

	agentW := reviewWorkload(t, db, ws, connID, "fn-agent", nil)
	busyW := reviewWorkload(t, db, ws, connID, "fn-busy", map[string]any{"status": "decided",
		"decided_at": now.Add(-time.Hour).Format(time.RFC3339), "verdict": map[string]any{"decided_by": "agent", "label": "UNKNOWN"}})
	edgeW := reviewWorkload(t, db, ws, connID, "fn-edge", nil)
	agentID, busyID, edgeID := uuid.New(), uuid.New(), uuid.New()
	// fn-agent: model -> DynamoDB -> model -> S3 -> model -> SNS (Rule 3).
	reviewActivity(t, db, ws, connID, agentID, now.Add(-2*time.Hour),
		"bedrock", "dynamodb:GetItem", "bedrock", "s3:PutObject", "bedrock", "sns:Publish")
	reviewActivity(t, db, ws, connID, busyID, now.Add(-2*time.Hour),
		"bedrock", "dynamodb:GetItem", "bedrock", "s3:PutObject", "bedrock", "sns:Publish")
	// fn-edge: a loop on one service only: no rule fits.
	reviewActivity(t, db, ws, connID, edgeID, now.Add(-2*time.Hour), "bedrock", "dynamodb:PutItem", "bedrock")

	ai := func(identity uuid.UUID, w uuid.UUID, native string) *AIWorkload {
		return &AIWorkload{Identity: AIIdentityRef{ID: identity, ARN: "arn:aws:iam::1:role/" + native},
			wls: []*arWorkload{{ID: w, ConnectorID: connID, RuntimeKind: models.WorkloadLambdaFunction, NativeID: native}}}
	}
	var res AgentInferenceResult
	var reported map[string]bool
	err := tenancy.InWorkspace(context.Background(), db, ws, func(tx *gorm.DB) error {
		var err error
		reported, err = (&AgentRuntimeService{}).applyAgentRules(tx, ws, conn,
			[]*AIWorkload{ai(agentID, agentW, "fn-agent"), ai(busyID, busyW, "fn-busy"), ai(edgeID, edgeW, "fn-edge")}, now, &res)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	r := reviewOf(t, db, agentW)
	v, _ := r["verdict"].(map[string]any)
	if r["status"] != "decided" || v["label"] != AgentLabelConfirmed || v["rule"] != "rule_3_autonomous_agent" || v["decided_by"] != "rules" {
		t.Errorf("fn-agent review = %v, want decided AI_AGENT_CONFIRMED by rule 3", r)
	}
	if feats, _ := v["features"].(map[string]any); feats["fan_out"] != float64(3) || feats["loops_detected"] != true {
		t.Errorf("features = %v, want fan_out 3 and a loop", v["features"])
	}
	fp := AWSAgentFingerprint(account, models.WorkloadLambdaFunction, "fn-agent")
	if !reported[fp] {
		t.Error("a rule-confirmed agent is reported as a sighting and kept by the mirror")
	}
	var origin string
	db.Raw(`SELECT metadata->>'origin' FROM discovered_agents WHERE workspace_id = ? AND fingerprint = ?`, ws, fp).Scan(&origin)
	if origin != AgentRulesSightingOrigin {
		t.Errorf("sighting origin = %q, want %q", origin, AgentRulesSightingOrigin)
	}
	if v, _ := reviewOf(t, db, busyW)["verdict"].(map[string]any); v["decided_by"] != "agent" {
		t.Error("the review service's verdict of an hour ago must not be overwritten by the rules")
	}
	if r := reviewOf(t, db, edgeW); r["status"] != "pending" || r["reason"] != AgentReviewReasonBorderline {
		t.Errorf("fn-edge review = %v, want pending borderline_features for the agent", r)
	}
	if res.RulesDecided != 1 || res.RulesQueued != 1 {
		t.Errorf("result = %+v, want 1 decided, 1 queued", res)
	}
}
