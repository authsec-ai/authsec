package integration

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/pkg/collectorcontract"
	"github.com/authsec-ai/authsec/routes"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestTRD2ITA6MigrationRehearsal(t *testing.T) {
	dsn := os.Getenv("IGA_TEST_DSN")
	if dsn == "" {
		t.Skip("IGA_TEST_DSN not set")
	}
	validate := filepath.Join(repoRoot(t), "scripts", "validate-043-runtime-policy.sql")
	mig := masterPath(t, "043_trd2_runtime_policy.sql")
	check := func(db *sql.DB) {
		t.Helper()
		if !constraintValidated(t, db, "runtime_policies_workspace_id_key") {
			t.Fatal("043 policy unique key is not valid")
		}
		if !constraintValidated(t, db, "runtime_policy_targets_workload_fkey") {
			t.Fatal("043 workload foreign key is not valid")
		}
	}
	t.Run("after_045", func(t *testing.T) {
		db := openFreshDB(t, dsn, "authsec_it_a6late")
		applyMasterWhere(t, db, func(base string) bool {
			ver := base
			if i := strings.IndexByte(base, '_'); i > 0 {
				ver = base[:i]
			}
			return ver != "043"
		})
		applyFile(t, db, mig)
		applyFile(t, db, mig)
		applyFile(t, db, validate)
		check(db)
	})
	t.Run("fresh", func(t *testing.T) {
		db := openFreshDB(t, dsn, "authsec_it_a6fresh")
		applyMaster(t, db, false)
		applyFile(t, db, mig)
		applyFile(t, db, validate)
		applyFile(t, db, validate)
		check(db)
	})
}

func TestTRD2ITA6RevisionTriggers(t *testing.T) {
	dsn := os.Getenv("IGA_TEST_DSN")
	if dsn == "" {
		t.Skip("IGA_TEST_DSN not set")
	}
	db := openPolicyDB(t, dsn)
	ws := uuid.New()
	execDB(t, db, `INSERT INTO workspaces (id, name) VALUES ($1, $2)`, ws, "a6-"+ws.String()[:8])
	policy, owner := uuid.New(), uuid.New()
	hash1 := strings.Repeat("a", 64)
	hash2 := strings.Repeat("b", 64)
	hash3 := strings.Repeat("d", 64)
	digest := strings.Repeat("c", 64)
	execDB(t, db, `INSERT INTO runtime_policies (id, workspace_id, name, owner_user_id, current_draft_revision, lifecycle)
		VALUES ($1, $2, $3, $4, 1, 'draft')`, policy, ws, "trig-"+policy.String()[:8], owner)
	rev := uuid.New()
	execDB(t, db, `INSERT INTO runtime_policy_revisions
		(id, workspace_id, policy_id, revision, document, content_hash, author_user_id, state, graph_revision, compiler_format)
		VALUES ($1, $2, $3, 1, '{"name":"t"}', $4, $5, 'draft', 1, 'authsec.runtime.v1')`,
		rev, ws, policy, hash1, owner)
	execDB(t, db, `UPDATE runtime_policy_revisions SET document = '{"name":"t2"}', content_hash = $2 WHERE id = $1`, rev, hash2)
	sim := uuid.New()
	execDB(t, db, `INSERT INTO runtime_policy_simulations
		(id, workspace_id, policy_id, revision, revision_hash, graph_revision, target_digest)
		VALUES ($1, $2, $3, 1, $4, 1, $5)`, sim, ws, policy, hash2, digest)
	appr := uuid.New()
	execDB(t, db, `INSERT INTO runtime_policy_approvals
		(id, workspace_id, policy_id, revision, revision_hash, simulation_id, target_digest, actor_user_id, reason)
		VALUES ($1, $2, $3, 1, $4, $5, $6, $7, 'because')`,
		appr, ws, policy, hash2, sim, digest, owner)
	execDB(t, db, `UPDATE runtime_policy_revisions SET document = '{"name":"t3"}', content_hash = $2 WHERE id = $1`, rev, hash3)
	var invalidated int
	if err := db.QueryRow(`SELECT count(*) FROM runtime_policy_approvals WHERE id = $1 AND invalidated_at IS NOT NULL`, appr).Scan(&invalidated); err != nil {
		t.Fatal(err)
	}
	if invalidated != 1 {
		t.Fatal("draft edit did not invalidate the approval")
	}
	execDB(t, db, `UPDATE runtime_policy_revisions SET state = 'validated' WHERE id = $1`, rev)
	execDB(t, db, `UPDATE runtime_policy_revisions SET graph_revision = 2 WHERE id = $1 AND state = 'validated'`, rev)
	if err := execErr(db, `UPDATE runtime_policy_revisions SET state = 'draft' WHERE id = $1`, rev); err == nil {
		t.Fatal("validated to draft was accepted")
	}
	if err := execErr(db, `UPDATE runtime_policy_revisions SET author_user_id = $2 WHERE id = $1`, rev, uuid.New()); err == nil {
		t.Fatal("author change was accepted")
	}
	if err := execErr(db, `UPDATE runtime_policy_revisions SET policy_id = $2 WHERE id = $1`, rev, uuid.New()); err == nil {
		t.Fatal("policy_id change was accepted")
	}
	if err := execErr(db, `UPDATE runtime_policy_revisions SET revision = 9 WHERE id = $1`, rev); err == nil {
		t.Fatal("revision number change was accepted")
	}
	if err := execErr(db, `UPDATE runtime_policy_revisions SET workspace_id = $2 WHERE id = $1`, rev, uuid.New()); err == nil {
		t.Fatal("workspace change was accepted")
	}
	if err := execErr(db, `UPDATE runtime_policy_revisions SET compiler_format = 'other' WHERE id = $1`, rev); err == nil {
		t.Fatal("compiler_format change was accepted")
	}
	execDB(t, db, `UPDATE runtime_policy_revisions SET state = 'simulated' WHERE id = $1`, rev)
	execDB(t, db, `UPDATE runtime_policy_revisions SET state = 'approved' WHERE id = $1`, rev)
	if err := execErr(db, `UPDATE runtime_policy_revisions SET state = 'draft' WHERE id = $1`, rev); err == nil {
		t.Fatal("approved to draft was accepted")
	}
	if err := execErr(db, `UPDATE runtime_policy_revisions SET document = '{"name":"no"}' WHERE id = $1`, rev); err == nil {
		t.Fatal("non-draft document update was accepted")
	}
	if err := execErr(db, `DELETE FROM runtime_policy_revisions WHERE id = $1`, rev); err == nil {
		t.Fatal("revision delete was accepted")
	}
	execDB(t, db, `UPDATE runtime_policy_revisions SET state = 'published' WHERE id = $1`, rev)
	execDB(t, db, `UPDATE runtime_policy_revisions SET state = 'superseded' WHERE id = $1`, rev)
	revoked := uuid.New()
	execDB(t, db, `INSERT INTO runtime_policy_revisions
		(id, workspace_id, policy_id, revision, document, content_hash, author_user_id, state, graph_revision, compiler_format)
		VALUES ($1, $2, $3, 2, '{"name":"pub"}', $4, $5, 'published', 1, 'authsec.runtime.v1')`,
		revoked, ws, policy, strings.Repeat("f", 64), owner)
	execDB(t, db, `UPDATE runtime_policy_revisions SET state = 'revoked' WHERE id = $1`, revoked)
	scope, integ, src, collector, wl := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	execDB(t, db, `INSERT INTO iga_estate_scopes (id, workspace_id, scope_kind) VALUES ($1, $2, 'aws_account')`, scope, ws)
	execDB(t, db, `INSERT INTO iga_integrations (id, workspace_id, provider, provider_host, app_registration_id)
		VALUES ($1, $2, 'github', 'github.com', $3)`, integ, ws, "app-"+integ.String()[:8])
	execDB(t, db, `INSERT INTO discovery_sources (id, workspace_id, kind, display_name) VALUES ($1, $2, 'k8s_webhook', 'a6')`, src, ws)
	execDB(t, db, `INSERT INTO collector_instances
		(id, workspace_id, discovery_source_id, estate_scope_id, integration_id, kind, installation_key_id, installation_public_key)
		VALUES ($1, $2, $3, $4, $5, 'k8s_collector', $6, $7)`,
		collector, ws, src, scope, integ, "key-"+collector.String()[:8], []byte("a6"))
	execDB(t, db, `INSERT INTO iga_workload (id, workspace_id, runtime_kind, source_key) VALUES ($1, $2, 'process', $3)`,
		wl, ws, "wl-"+wl.String()[:8])
	pub := uuid.New()
	execDB(t, db, `INSERT INTO runtime_policy_publications
		(id, workspace_id, policy_id, revision, revision_hash, author_user_id)
		VALUES ($1, $2, $3, 1, $4, $5)`, pub, ws, policy, hash1, owner)
	target := uuid.New()
	execDB(t, db, `INSERT INTO runtime_policy_targets
		(id, workspace_id, publication_id, workload_id, collector_id, desired_delivery_revision)
		VALUES ($1, $2, $3, $4, $5, 1)`, target, ws, pub, wl, collector)
	receipt := uuid.New()
	execDB(t, db, `INSERT INTO runtime_policy_receipts
		(id, workspace_id, target_id, publication_id, policy_id, delivery_revision)
		VALUES ($1, $2, $3, $4, $5, 1)`, receipt, ws, target, pub, policy)
	if err := execErr(db, `UPDATE runtime_policy_receipts SET error = 'changed' WHERE id = $1`, receipt); err == nil {
		t.Fatal("receipt update was accepted")
	}
	if err := execErr(db, `DELETE FROM runtime_policy_receipts WHERE id = $1`, receipt); err == nil {
		t.Fatal("receipt delete was accepted")
	}
	cap := strings.Repeat("e", 64)
	execDB(t, db, `INSERT INTO collector_capability_reports (workspace_id, collector_id, capability_digest, report)
		VALUES ($1, $2, $3, '{}')`, ws, collector, cap)
	execDB(t, db, `INSERT INTO collector_capability_reports (workspace_id, collector_id, capability_digest, report)
		VALUES ($1, $2, $3, '{"probe":true}')
		ON CONFLICT (workspace_id, collector_id, capability_digest) DO UPDATE SET report = EXCLUDED.report`,
		ws, collector, cap)
	var reports int
	if err := db.QueryRow(`SELECT count(*) FROM collector_capability_reports WHERE workspace_id = $1 AND collector_id = $2`, ws, collector).Scan(&reports); err != nil {
		t.Fatal(err)
	}
	if reports != 1 {
		t.Fatalf("capability reports = %d", reports)
	}
}

func TestTRD2ITA6WorkspaceCascade(t *testing.T) {
	dsn := os.Getenv("IGA_TEST_DSN")
	if dsn == "" {
		t.Skip("IGA_TEST_DSN not set")
	}
	db := openPolicyDB(t, dsn)
	ws := uuid.New()
	execDB(t, db, `INSERT INTO workspaces (id, name) VALUES ($1, $2)`, ws, "a6del-"+ws.String()[:8])
	policy, owner := uuid.New(), uuid.New()
	hash := strings.Repeat("a", 64)
	digest := strings.Repeat("b", 64)
	execDB(t, db, `INSERT INTO runtime_policies (id, workspace_id, name, owner_user_id, current_draft_revision, lifecycle)
		VALUES ($1, $2, $3, $4, 1, 'approved')`, policy, ws, "del-"+policy.String()[:8], owner)
	rev := uuid.New()
	execDB(t, db, `INSERT INTO runtime_policy_revisions
		(id, workspace_id, policy_id, revision, document, content_hash, author_user_id, state, graph_revision, compiler_format)
		VALUES ($1, $2, $3, 1, '{"name":"t"}', $4, $5, 'approved', 1, 'authsec.runtime.v1')`,
		rev, ws, policy, hash, owner)
	sim := uuid.New()
	execDB(t, db, `INSERT INTO runtime_policy_simulations
		(id, workspace_id, policy_id, revision, revision_hash, graph_revision, target_digest)
		VALUES ($1, $2, $3, 1, $4, 1, $5)`, sim, ws, policy, hash, digest)
	execDB(t, db, `INSERT INTO runtime_policy_approvals
		(id, workspace_id, policy_id, revision, revision_hash, simulation_id, target_digest, actor_user_id, reason)
		VALUES ($1, $2, $3, 1, $4, $5, $6, $7, 'because')`,
		uuid.New(), ws, policy, hash, sim, digest, owner)
	execDB(t, db, `INSERT INTO runtime_policy_audit (workspace_id, policy_id, actor_user_id, action, reason)
		VALUES ($1, $2, $3, 'approve', 'because')`, ws, policy, owner)
	scope, integ, src, collector, wl := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	execDB(t, db, `INSERT INTO iga_estate_scopes (id, workspace_id, scope_kind) VALUES ($1, $2, 'aws_account')`, scope, ws)
	execDB(t, db, `INSERT INTO iga_integrations (id, workspace_id, provider, provider_host, app_registration_id)
		VALUES ($1, $2, 'github', 'github.com', $3)`, integ, ws, "app-"+integ.String()[:8])
	execDB(t, db, `INSERT INTO discovery_sources (id, workspace_id, kind, display_name) VALUES ($1, $2, 'k8s_webhook', 'a6del')`, src, ws)
	execDB(t, db, `INSERT INTO collector_instances
		(id, workspace_id, discovery_source_id, estate_scope_id, integration_id, kind, installation_key_id, installation_public_key)
		VALUES ($1, $2, $3, $4, $5, 'linux_collector', $6, $7)`,
		collector, ws, src, scope, integ, "key-"+collector.String()[:8], []byte("a6"))
	execDB(t, db, `INSERT INTO iga_workload (id, workspace_id, runtime_kind, source_key) VALUES ($1, $2, 'process', $3)`,
		wl, ws, "wl-"+wl.String()[:8])
	pub := uuid.New()
	execDB(t, db, `INSERT INTO runtime_policy_publications
		(id, workspace_id, policy_id, revision, revision_hash, author_user_id)
		VALUES ($1, $2, $3, 1, $4, $5)`, pub, ws, policy, hash, owner)
	target := uuid.New()
	execDB(t, db, `INSERT INTO runtime_policy_targets
		(id, workspace_id, publication_id, workload_id, collector_id, desired_delivery_revision)
		VALUES ($1, $2, $3, $4, $5, 1)`, target, ws, pub, wl, collector)
	execDB(t, db, `INSERT INTO runtime_policy_receipts
		(id, workspace_id, target_id, publication_id, policy_id, delivery_revision)
		VALUES ($1, $2, $3, $4, $5, 1)`, uuid.New(), ws, target, pub, policy)
	if err := execErr(db, `DELETE FROM runtime_policy_receipts WHERE workspace_id = $1`, ws); err == nil {
		t.Fatal("direct receipt delete was accepted")
	}
	if err := execErr(db, `DELETE FROM runtime_policy_audit WHERE workspace_id = $1`, ws); err == nil {
		t.Fatal("direct audit delete was accepted")
	}
	if err := execErr(db, `DELETE FROM runtime_policy_revisions WHERE id = $1`, rev); err == nil {
		t.Fatal("direct non-draft revision delete was accepted")
	}
	execDB(t, db, `DELETE FROM workspaces WHERE id = $1`, ws)
	for _, table := range []string{
		"runtime_policies", "runtime_policy_revisions", "runtime_policy_simulations",
		"runtime_policy_approvals", "runtime_policy_publications", "runtime_policy_targets",
		"runtime_policy_receipts", "runtime_policy_audit",
	} {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM `+table+` WHERE workspace_id = $1`, ws).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("%s left %d rows", table, n)
		}
	}
	var left int
	if err := db.QueryRow(`SELECT count(*) FROM workspaces WHERE id = $1`, ws).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatal("workspace row survived")
	}
}

func TestTRD2ITA6CapabilityOnSync(t *testing.T) {
	dsn := os.Getenv("IGA_TEST_DSN")
	if dsn == "" {
		t.Skip("IGA_TEST_DSN not set")
	}
	db := openPolicyDB(t, dsn)
	g := openGorm(t, db)
	ws := uuid.New()
	execDB(t, db, `INSERT INTO workspaces (id, name) VALUES ($1, $2)`, ws, "a6cap-"+ws.String()[:8])
	scope, integ, src, collector := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	execDB(t, db, `INSERT INTO iga_estate_scopes (id, workspace_id, scope_kind) VALUES ($1, $2, 'aws_account')`, scope, ws)
	execDB(t, db, `INSERT INTO iga_integrations (id, workspace_id, provider, provider_host, app_registration_id)
		VALUES ($1, $2, 'github', 'github.com', $3)`, integ, ws, "app-"+integ.String()[:8])
	execDB(t, db, `INSERT INTO discovery_sources (id, workspace_id, kind, display_name) VALUES ($1, $2, 'k8s_webhook', 'a6cap')`, src, ws)
	execDB(t, db, `INSERT INTO collector_instances
		(id, workspace_id, discovery_source_id, estate_scope_id, integration_id, kind, installation_key_id, installation_public_key)
		VALUES ($1, $2, $3, $4, $5, 'linux_collector', $6, $7)`,
		collector, ws, src, scope, integ, "key-"+collector.String()[:8], []byte("a6"))
	digest := strings.Repeat("c", 64)
	epoch := uuid.New()
	p := &models.CollectorPrincipal{
		WorkspaceID: ws, CollectorID: collector, EstateScopeID: scope,
		DiscoverySourceID: src, IntegrationID: integ,
		Kind: models.CollectorKindLinux, Scopes: []string{models.CollectorScopeIngest},
	}
	accept := func(seq int64) {
		t.Helper()
		raw, err := json.Marshal(collectorcontract.SyncRequest{
			SchemaVersion: collectorcontract.SchemaVersion, BatchID: uuid.NewString(),
			CollectorEpoch: epoch.String(), Sequence: seq, SentAt: "2026-09-25T08:00:00Z",
			Capabilities: json.RawMessage(`{"probes":["filesystem"]}`), CapabilityDigest: digest,
			Objects: []collectorcontract.Object{}, Observations: []collectorcontract.Observation{},
			Applied: []collectorcontract.AppliedReceipt{}, Health: collectorcontract.Health{},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := services.NewCollectorSyncService(g, nil).Accept(p, raw); err != nil {
			t.Fatalf("sync %d: %v", seq, err)
		}
	}
	t.Setenv(services.EnvV2Policy, "1")
	accept(1)
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM collector_capability_reports WHERE workspace_id = $1 AND collector_id = $2 AND capability_digest = $3`,
		ws, collector, digest).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("reports = %d", n)
	}
	execDB(t, db, `UPDATE collector_capability_reports SET last_seen_at = '2000-01-01' WHERE workspace_id = $1`, ws)
	accept(2)
	var seen string
	if err := db.QueryRow(`SELECT last_seen_at::text FROM collector_capability_reports WHERE workspace_id = $1 AND capability_digest = $2`,
		ws, digest).Scan(&seen); err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(seen, "2000-") {
		t.Fatalf("last_seen_at was not refreshed: %s", seen)
	}
	if err := db.QueryRow(`SELECT count(*) FROM collector_capability_reports WHERE workspace_id = $1`, ws).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("repeat digest inserted a second row: %d", n)
	}
	t.Setenv(services.EnvV2Policy, "0")
	execDB(t, db, `UPDATE collector_capability_reports SET last_seen_at = '2000-01-01' WHERE workspace_id = $1`, ws)
	accept(3)
	if err := db.QueryRow(`SELECT last_seen_at::text FROM collector_capability_reports WHERE workspace_id = $1`, ws).Scan(&seen); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(seen, "2000-") {
		t.Fatal("flag-off sync wrote a capability report")
	}
	t.Setenv(services.EnvV2Policy, "1")
	execDB(t, db, `ALTER TABLE collector_capability_reports RENAME TO collector_capability_reports_hidden`)
	t.Cleanup(func() {
		_, _ = db.Exec(`ALTER TABLE IF EXISTS collector_capability_reports_hidden RENAME TO collector_capability_reports`)
	})
	accept(4)
	execDB(t, db, `ALTER TABLE collector_capability_reports_hidden RENAME TO collector_capability_reports`)
	if err := db.QueryRow(`SELECT count(*) FROM collector_batches WHERE workspace_id = $1`, ws).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Fatalf("a failed capability insert changed the sync outcome: batches=%d", n)
	}
}

func TestTRD2ITA6AdminFlow(t *testing.T) {
	dsn := os.Getenv("IGA_TEST_DSN")
	if dsn == "" {
		t.Skip("IGA_TEST_DSN not set")
	}
	t.Setenv(services.EnvV2Policy, "1")
	db := openPolicyDB(t, dsn)
	g := openGorm(t, db)
	ws, author, other := uuid.New(), uuid.New(), uuid.New()
	wl, dbRes, secRes := uuid.New(), uuid.New(), uuid.New()
	execDB(t, db, `INSERT INTO workspaces (id, name) VALUES ($1, $2)`, ws, "a6api-"+ws.String()[:8])
	execDB(t, db, `INSERT INTO users (id, email, workspace_id) VALUES ($1, $2, $3), ($4, $5, $3)`,
		author, author.String()+"@example.test", ws, other, other.String()+"@example.test")
	execDB(t, db, `INSERT INTO iga_workload (id, workspace_id, runtime_kind, source_key) VALUES ($1, $2, 'process', $3)`,
		wl, ws, "inv-"+wl.String()[:8])
	execDB(t, db, `INSERT INTO iga_resources (id, workspace_id, resource_kind, display_name, reference_status, native_kind, kind_metadata)
		VALUES ($1, $2, 'endpoint', 'db', 'inventoried', 'tcp', '{"address":"10.20.0.15","port":5432,"protocol":"tcp"}'),
		       ($3, $2, 'secret', 'secret', 'inventoried', 'secret', '{"broker_path":"authnull-broker"}')`,
		dbRes, ws, secRes)
	execDB(t, db, `INSERT INTO runtime_policy_settings (workspace_id, configured_brokers)
		VALUES ($1, '["authnull-broker"]')`, ws)
	scope, integ, src, collector := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	execDB(t, db, `INSERT INTO iga_estate_scopes (id, workspace_id, scope_kind) VALUES ($1, $2, 'aws_account')`, scope, ws)
	execDB(t, db, `INSERT INTO iga_integrations (id, workspace_id, provider, provider_host, app_registration_id)
		VALUES ($1, $2, 'github', 'github.com', $3)`, integ, ws, "app-"+integ.String()[:8])
	execDB(t, db, `INSERT INTO discovery_sources (id, workspace_id, kind, display_name) VALUES ($1, $2, 'k8s_webhook', 'a6api')`, src, ws)
	execDB(t, db, `INSERT INTO collector_instances
		(id, workspace_id, discovery_source_id, estate_scope_id, integration_id, kind, installation_key_id, installation_public_key)
		VALUES ($1, $2, $3, $4, $5, 'linux_collector', $6, $7)`,
		collector, ws, src, scope, integ, "key-"+collector.String()[:8], []byte("a6"))
	execDB(t, db, `INSERT INTO collector_capability_reports (workspace_id, collector_id, capability_digest)
		VALUES ($1, $2, $3)`, ws, collector, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	gin.SetMode(gin.TestMode)
	r := gin.New()
	routes.MountRuntimePolicy(r, g, func(c *gin.Context) {
		c.Set("claims", jwt.MapClaims{"scope": c.GetHeader("X-Test-Scope")})
		c.Set("workspace_id", ws.String())
		c.Set("user_id", c.GetHeader("X-Test-User"))
		c.Next()
	})
	doc := []byte(`{
	  "name": "invoice ` + wl.String()[:8] + `",
	  "format": "authsec.runtime.v1",
	  "targets": {"workload_ids": ["` + wl.String() + `"], "include_future_incarnations": false},
	  "profile": "linux-managed-v1",
	  "default_effect": "deny",
	  "mode": "observe",
	  "rules": [
	    {"id": "db-connect", "action": "network.connect", "resource_id": "` + dbRes.String() + `", "effect": "allow"},
	    {"id": "invoice-files", "action": "file.read", "path": "/srv/invoices/**", "effect": "allow"},
	    {"id": "database-secret", "action": "secret.read", "resource_id": "` + secRes.String() + `", "effect": "require_approval", "adapter": "authnull-broker"}
	  ],
	  "required_controls": ["filesystem", "egress"],
	  "evidence_graph_revision": 184
	}`)
	base := "/api/iga/v2/runtime-policies"
	created := callPolicy(t, r, http.MethodPost, base, author, "runtime_policy:write", "create-1", "", doc)
	if created.Code != http.StatusCreated {
		t.Fatalf("create %d %s", created.Code, created.Body.String())
	}
	replay := callPolicy(t, r, http.MethodPost, base, author, "runtime_policy:write", "create-1", "", doc)
	if replay.Code != created.Code || replay.Body.String() != created.Body.String() {
		t.Fatalf("replay %d %s", replay.Code, replay.Body.String())
	}
	conflict := callPolicy(t, r, http.MethodPost, base, author, "runtime_policy:write", "create-1", "", bytes.Replace(doc, []byte("invoice "), []byte("other "), 1))
	if conflict.Code != http.StatusConflict {
		t.Fatalf("idempotency conflict %d %s", conflict.Code, conflict.Body.String())
	}
	var createdBody struct {
		ETag string `json:"etag"`
		Data struct {
			PolicyID uuid.UUID `json:"policy_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createdBody); err != nil {
		t.Fatal(err)
	}
	path := base + "/" + createdBody.Data.PolicyID.String()
	if missing := callPolicy(t, r, http.MethodPut, path+"/draft", author, "runtime_policy:write", "draft-miss", "", doc); missing.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing If-Match %d", missing.Code)
	}
	edited := bytes.Replace(doc, []byte(`"invoice-files"`), []byte(`"invoice-files-2"`), 1)
	var wg sync.WaitGroup
	var first, second *httptest.ResponseRecorder
	wg.Add(2)
	go func() {
		defer wg.Done()
		first = callPolicy(t, r, http.MethodPut, path+"/draft", author, "runtime_policy:write", "race-a", createdBody.ETag, edited)
	}()
	go func() {
		defer wg.Done()
		second = callPolicy(t, r, http.MethodPut, path+"/draft", author, "runtime_policy:write", "race-b", createdBody.ETag, edited)
	}()
	wg.Wait()
	codes := map[int]int{first.Code: 1, second.Code: 1}
	if codes[http.StatusOK] != 1 || codes[http.StatusPreconditionFailed] != 1 {
		t.Fatalf("concurrent put codes %d %s | %d %s", first.Code, first.Body.String(), second.Code, second.Body.String())
	}
	winner := first
	if second.Code == http.StatusOK {
		winner = second
	}
	var putBody struct {
		ETag string `json:"etag"`
	}
	if err := json.Unmarshal(winner.Body.Bytes(), &putBody); err != nil {
		t.Fatal(err)
	}
	validated := callPolicy(t, r, http.MethodPost, path+"/validate", author, "runtime_policy:write", "val-1", putBody.ETag, []byte(`{}`))
	if validated.Code != http.StatusOK {
		t.Fatalf("validate %d %s", validated.Code, validated.Body.String())
	}
	var valBody struct {
		ETag string `json:"etag"`
		Data struct {
			ContentHash  string `json:"content_hash"`
			TargetDigest string `json:"target_digest"`
		} `json:"data"`
	}
	if err := json.Unmarshal(validated.Body.Bytes(), &valBody); err != nil {
		t.Fatal(err)
	}
	execDB(t, db, `UPDATE runtime_policy_revisions SET state = 'simulated' WHERE policy_id = $1 AND state = 'validated'`, createdBody.Data.PolicyID)
	execDB(t, db, `UPDATE runtime_policies SET lifecycle = 'simulated' WHERE id = $1`, createdBody.Data.PolicyID)
	sim := uuid.New()
	execDB(t, db, `INSERT INTO runtime_policy_simulations
		(id, workspace_id, policy_id, revision, revision_hash, graph_revision, target_digest)
		VALUES ($1, $2, $3, 2, $4, 184, $5)`, sim, ws, createdBody.Data.PolicyID, valBody.Data.ContentHash, valBody.Data.TargetDigest)
	bad := `{"revision_hash":"` + valBody.Data.ContentHash + `","simulation_id":"` + sim.String() + `","target_digest":"` + strings.Repeat("f", 64) + `","reason":"no"}`
	if resp := callPolicy(t, r, http.MethodPost, path+"/approvals", other, "runtime_policy:approve", "appr-bad", valBody.ETag, []byte(bad)); resp.Code != http.StatusConflict {
		t.Fatalf("bad digest %d %s", resp.Code, resp.Body.String())
	}
	execDB(t, db, `UPDATE runtime_policy_settings SET second_approver_required = true WHERE workspace_id = $1`, ws)
	self := `{"revision_hash":"` + valBody.Data.ContentHash + `","simulation_id":"` + sim.String() + `","target_digest":"` + valBody.Data.TargetDigest + `","reason":"self","mfa_context":{"method":"present"}}`
	if resp := callPolicy(t, r, http.MethodPost, path+"/approvals", author, "runtime_policy:approve", "appr-self", valBody.ETag, []byte(self)); resp.Code != http.StatusForbidden {
		t.Fatalf("self approve %d %s", resp.Code, resp.Body.String())
	}
	okBody := `{"revision_hash":"` + valBody.Data.ContentHash + `","simulation_id":"` + sim.String() + `","target_digest":"` + valBody.Data.TargetDigest + `","reason":"reviewed","mfa_context":{"method":"present"}}`
	if resp := callPolicy(t, r, http.MethodPost, path+"/approvals", other, "runtime_policy:approve", "appr-ok", valBody.ETag, []byte(okBody)); resp.Code != http.StatusCreated {
		t.Fatalf("approve %d %s", resp.Code, resp.Body.String())
	}
	again := bytes.Replace(edited, []byte(`"database-secret"`), []byte(`"database-secret-2"`), 1)
	if resp := callPolicy(t, r, http.MethodPut, path+"/draft", author, "runtime_policy:write", "draft-after", valBody.ETag, again); resp.Code != http.StatusOK {
		t.Fatalf("edit after approve %d %s", resp.Code, resp.Body.String())
	}
	var live, audits int
	if err := db.QueryRow(`SELECT count(*) FROM runtime_policy_approvals WHERE policy_id = $1 AND invalidated_at IS NULL`, createdBody.Data.PolicyID).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 0 {
		t.Fatal("approval survived a draft edit")
	}
	if err := db.QueryRow(`SELECT count(*) FROM runtime_policy_audit WHERE policy_id = $1`, createdBody.Data.PolicyID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits < 4 {
		t.Fatalf("audit rows = %d", audits)
	}
}

func callPolicy(t *testing.T, r http.Handler, method, path string, user uuid.UUID, scope, key, match string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("X-Test-Scope", scope)
	req.Header.Set("X-Test-User", user.String())
	req.Header.Set("Idempotency-Key", key)
	if match != "" {
		req.Header.Set("If-Match", match)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func openPolicyDB(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	raw, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Ping(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	return raw
}
