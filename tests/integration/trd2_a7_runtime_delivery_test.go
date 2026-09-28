package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/runtimepolicy/profiles"
	"github.com/authsec-ai/authsec/internal/runtimepolicy/sign"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/pkg/collectorcontract"
	"github.com/authsec-ai/authsec/routes"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	a7GoodDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	a7BadDigest  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func TestTRD2ITA7ObserveDelivery(t *testing.T) {
	env := newA7(t, a7GoodDigest, false)
	doc := a7Doc(env.wl, "observe-"+env.wl.String()[:8], "/var/app/data", []string{"filesystem"})
	path, etag, hash, digest := a7Approve(t, env, doc)
	body := []byte(`{"mode":"observe","reason":"ship"}`)
	pub := callPolicy(t, env.r, http.MethodPost, path+"/publications", env.author, "runtime_policy:enforce", "pub-1", etag, body)
	if pub.Code != http.StatusCreated {
		t.Fatalf("publish %d %s", pub.Code, pub.Body.String())
	}
	replay := callPolicy(t, env.r, http.MethodPost, path+"/publications", env.author, "runtime_policy:enforce", "pub-1", etag, body)
	if replay.Code != pub.Code || replay.Body.String() != pub.Body.String() {
		t.Fatalf("publish replay %d %s", replay.Code, replay.Body.String())
	}
	clash := callPolicy(t, env.r, http.MethodPost, path+"/publications", env.author, "runtime_policy:enforce", "pub-1", etag, []byte(`{"mode":"observe","reason":"other"}`))
	if clash.Code != http.StatusConflict {
		t.Fatalf("publish idempotency %d %s", clash.Code, clash.Body.String())
	}
	var published struct {
		Data struct {
			DeliveryRevision int64  `json:"delivery_revision"`
			ContentHash      string `json:"content_hash"`
		} `json:"data"`
	}
	if err := json.Unmarshal(pub.Body.Bytes(), &published); err != nil {
		t.Fatal(err)
	}
	if published.Data.ContentHash != hash || published.Data.DeliveryRevision < 1 {
		t.Fatalf("publication %+v hash %s", published.Data, hash)
	}
	desired := a7Desired(t, a7Sync(t, env, 1, nil))
	if desired.Revision != published.Data.DeliveryRevision || desired.PolicyFormat != models.RuntimePolicyFormatV1 {
		t.Fatalf("desired %+v", desired)
	}
	if desired.OPABundle.RegoVersion != "v1" || desired.OPABundle.SHA256 == "" || desired.Controls.SHA256 == "" || desired.SignedManifest == "" {
		t.Fatalf("desired artifacts %+v", desired)
	}
	manifest, err := sign.VerifyManifest(desired.SignedManifest, map[string]*ecdsa.PublicKey{"current": env.pub})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.PolicyRevisionHash != hash || manifest.TargetDigest != digest {
		t.Fatalf("manifest hash %s digest %s want %s %s", manifest.PolicyRevisionHash, manifest.TargetDigest, hash, digest)
	}
	bundle := a7Download(t, env, desired.OPABundle.URL, env.principal())
	if err := sign.VerifyBundle(bundle, map[string]*ecdsa.PublicKey{"current": env.pub}); err != nil {
		t.Fatal(err)
	}
	other := env.principal()
	other.CollectorID = uuid.New()
	if rec := a7DownloadStatus(t, env, desired.OPABundle.URL, other); rec.Code != http.StatusNotFound {
		t.Fatalf("non-target download %d %s", rec.Code, rec.Body.String())
	}
	foreign := env.principal()
	foreign.WorkspaceID = uuid.New()
	if rec := a7DownloadStatus(t, env, desired.OPABundle.URL, foreign); rec.Code != http.StatusNotFound {
		t.Fatalf("other workspace download %d %s", rec.Code, rec.Body.String())
	}
	rev := callPolicy(t, env.r, http.MethodPost, path+"/revoke", env.author, "runtime_policy:enforce", "revoke-1", etag, []byte(`{"reason":"stop"}`))
	if rev.Code != http.StatusCreated {
		t.Fatalf("revoke %d %s", rev.Code, rev.Body.String())
	}
	var epoch int64
	var phase string
	if err := env.db.QueryRow(`SELECT revocation_epoch, COALESCE(rollout_plan->>'phase','') FROM runtime_policy_publications
		WHERE workspace_id = $1 ORDER BY created_at DESC LIMIT 1`, env.ws).Scan(&epoch, &phase); err != nil {
		t.Fatal(err)
	}
	if epoch != 1 || phase != "revoked" {
		t.Fatalf("epoch %d phase %s", epoch, phase)
	}
	again := a7Desired(t, a7Sync(t, env, 2, nil))
	if again.Revision <= desired.Revision {
		t.Fatalf("revoked delivery %d did not advance past %d", again.Revision, desired.Revision)
	}
}

func TestTRD2ITA7CanaryRollback(t *testing.T) {
	env := newA7(t, a7GoodDigest, false)
	doc := a7Doc(env.wl, "canary-"+env.wl.String()[:8], "/var/app/one", []string{"filesystem"})
	path, etag, firstHash, _ := a7Approve(t, env, doc)
	first := callPolicy(t, env.r, http.MethodPost, path+"/publications", env.author, "runtime_policy:enforce", "canary-pub-1", etag, []byte(`{"mode":"observe"}`))
	if first.Code != http.StatusCreated {
		t.Fatalf("first publish %d %s", first.Code, first.Body.String())
	}
	edited := a7Doc(env.wl, "canary-"+env.wl.String()[:8], "/var/app/two", []string{"filesystem"})
	put := callPolicy(t, env.r, http.MethodPut, path+"/draft", env.author, "runtime_policy:write", "canary-draft", etag, edited)
	if put.Code != http.StatusOK {
		t.Fatalf("draft %d %s", put.Code, put.Body.String())
	}
	var putBody struct {
		ETag string `json:"etag"`
	}
	if err := json.Unmarshal(put.Body.Bytes(), &putBody); err != nil {
		t.Fatal(err)
	}
	validated := callPolicy(t, env.r, http.MethodPost, path+"/validate", env.author, "runtime_policy:write", "canary-val", putBody.ETag, []byte(`{}`))
	if validated.Code != http.StatusOK {
		t.Fatalf("validate edited draft %d %s", validated.Code, validated.Body.String())
	}
	var valBody struct {
		ETag string `json:"etag"`
	}
	if err := json.Unmarshal(validated.Body.Bytes(), &valBody); err != nil {
		t.Fatal(err)
	}
	etag = a7FinishApproval(t, env, path, valBody.ETag, "canary-2")
	if missing := callPolicy(t, env.r, http.MethodPost, path+"/rollback", env.author, "runtime_policy:enforce", "rb-miss", "", []byte(`{}`)); missing.Code != http.StatusPreconditionRequired {
		t.Fatalf("rollback without If-Match %d %s", missing.Code, missing.Body.String())
	}
	secondBody := []byte(`{"mode":"observe","canary_workload_ids":["` + env.wl.String() + `"],"window_seconds":86400,"failure_threshold":1}`)
	second := callPolicy(t, env.r, http.MethodPost, path+"/publications", env.author, "runtime_policy:enforce", "canary-pub-2", etag, secondBody)
	if second.Code != http.StatusCreated {
		t.Fatalf("canary publish %d %s", second.Code, second.Body.String())
	}
	var canary struct {
		Data struct {
			DeliveryRevision int64 `json:"delivery_revision"`
		} `json:"data"`
	}
	if err := json.Unmarshal(second.Body.Bytes(), &canary); err != nil {
		t.Fatal(err)
	}
	a7Sync(t, env, 1, []collectorcontract.AppliedReceipt{{
		WorkloadID: env.wl.String(), DeliveryRevision: canary.Data.DeliveryRevision,
		RuntimeGeneration: "managed-run-1", State: "failed",
		Controls: []collectorcontract.ControlReceipt{{
			Kind: "tetragon.file_open_deny", State: "failed", ArtifactSHA256: strings.Repeat("ab", 32), Test: "open",
		}},
		ObservedAt: "2026-09-28T08:00:00Z",
	}})
	if err := services.NewRolloutWorker(env.g).Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	var phase string
	if err := env.db.QueryRow(`SELECT rollout_plan->>'phase' FROM runtime_policy_publications
		WHERE workspace_id = $1 AND rollout_plan->>'phase' = 'paused'`, env.ws).Scan(&phase); err != nil {
		t.Fatal(err)
	}
	rolled := callPolicy(t, env.r, http.MethodPost, path+"/rollback", env.author, "runtime_policy:enforce", "rb-1", etag, []byte(`{"reason":"pause"}`))
	if rolled.Code != http.StatusCreated {
		t.Fatalf("rollback %d %s", rolled.Code, rolled.Body.String())
	}
	var back struct {
		Data struct {
			DeliveryRevision int64  `json:"delivery_revision"`
			RolloutPhase     string `json:"rollout_phase"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rolled.Body.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back.Data.DeliveryRevision <= canary.Data.DeliveryRevision || back.Data.RolloutPhase != "rest" {
		t.Fatalf("rollback %+v", back.Data)
	}
	desired := a7Desired(t, a7Sync(t, env, 2, nil))
	if desired.Revision != back.Data.DeliveryRevision {
		t.Fatalf("desired %d want %d", desired.Revision, back.Data.DeliveryRevision)
	}
	manifest, err := sign.VerifyManifest(desired.SignedManifest, map[string]*ecdsa.PublicKey{"current": env.pub})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.PolicyRevisionHash != firstHash {
		t.Fatalf("rollback signed %s want %s", manifest.PolicyRevisionHash, firstHash)
	}
}

func TestTRD2ITA7EnforceAndQuarantine(t *testing.T) {
	reg, err := profiles.Load()
	if err != nil {
		t.Fatal(err)
	}
	if reg.Supports("linux-managed-v1", a7GoodDigest, "filesystem") {
		t.Fatal("production registry accepted a test digest")
	}
	env := newA7(t, a7BadDigest, true)
	path, etag, _, _ := a7Approve(t, env, a7Doc(env.wl, "enf-"+env.wl.String()[:8], "/var/app/data", []string{"filesystem", "egress"}))
	off := callPolicy(t, env.r, http.MethodPost, path+"/publications", env.author, "runtime_policy:enforce", "enf-off", etag, []byte(`{"mode":"enforce"}`))
	if off.Code != http.StatusForbidden || !strings.Contains(off.Body.String(), "enforce_disabled") {
		t.Fatalf("flag off %d %s", off.Code, off.Body.String())
	}
	t.Setenv(services.EnvV2Enforce, "1")
	bad := callPolicy(t, env.r, http.MethodPost, path+"/publications", env.author, "runtime_policy:enforce", "enf-bad", etag, []byte(`{"mode":"enforce"}`))
	if bad.Code != http.StatusUnprocessableEntity || !strings.Contains(bad.Body.String(), "unsupported_control") || !strings.Contains(bad.Body.String(), "semantic_report") {
		t.Fatalf("unsupported %d %s", bad.Code, bad.Body.String())
	}
	execDB(t, env.db, `UPDATE collector_instances SET capability_digest = $2 WHERE id = $1`, env.collector, a7GoodDigest)
	execDB(t, env.db, `UPDATE collector_capability_reports SET capability_digest = $2 WHERE collector_id = $1`, env.collector, a7GoodDigest)
	ok := callPolicy(t, env.r, http.MethodPost, path+"/publications", env.author, "runtime_policy:enforce", "enf-ok", etag, []byte(`{"mode":"enforce"}`))
	if ok.Code != http.StatusCreated {
		t.Fatalf("enforce publish %d %s", ok.Code, ok.Body.String())
	}
	var published struct {
		Data struct {
			DeliveryRevision int64 `json:"delivery_revision"`
		} `json:"data"`
	}
	if err := json.Unmarshal(ok.Body.Bytes(), &published); err != nil {
		t.Fatal(err)
	}
	one := collectorcontract.ControlReceipt{Kind: "tetragon.file_open_deny", State: "verified", ArtifactSHA256: strings.Repeat("ab", 32), Test: "open"}
	two := collectorcontract.ControlReceipt{Kind: "linux.netns_egress", State: "verified", ArtifactSHA256: strings.Repeat("cd", 32), Test: "egress"}
	a7Sync(t, env, 1, []collectorcontract.AppliedReceipt{{
		WorkloadID: env.wl.String(), DeliveryRevision: published.Data.DeliveryRevision,
		RuntimeGeneration: "run-1", State: "verified", Controls: []collectorcontract.ControlReceipt{one},
		ObservedAt: "2026-09-28T08:00:00Z",
	}})
	if a7Protected(t, env, path) {
		t.Fatal("one verified control marked the target protected")
	}
	a7Sync(t, env, 2, []collectorcontract.AppliedReceipt{{
		WorkloadID: env.wl.String(), DeliveryRevision: published.Data.DeliveryRevision,
		RuntimeGeneration: "run-2", State: "verified", Controls: []collectorcontract.ControlReceipt{one, two},
		ObservedAt: "2026-09-28T09:00:00Z",
	}})
	if !a7Protected(t, env, path) {
		t.Fatal("both required controls verified but the target is not protected")
	}

	q := newA7(t, a7GoodDigest, false)
	agent := uuid.New()
	execDB(t, q.db, `INSERT INTO discovered_agents (id, workspace_id, source, fingerprint, status)
		VALUES ($1, $2, 'k8s_webhook', $3, 'quarantined')`, agent, q.ws, "fp-"+agent.String()[:8])
	execDB(t, q.db, `INSERT INTO discovered_agent_workloads
		(workspace_id, discovered_agent_id, workload_id, link_strength, link_state)
		VALUES ($1, $2, $3, 'weak', 'accepted')`, q.ws, agent, q.wl)
	qpath, qetag, _, _ := a7Approve(t, q, a7Doc(q.wl, "quar-"+q.wl.String()[:8], "/var/app/data", []string{"filesystem"}))
	qpub := callPolicy(t, q.r, http.MethodPost, qpath+"/publications", q.author, "runtime_policy:enforce", "quar-pub", qetag, []byte(`{"mode":"observe"}`))
	if qpub.Code != http.StatusCreated {
		t.Fatalf("quarantine publish %d %s", qpub.Code, qpub.Body.String())
	}
	manifest, err := sign.VerifyManifest(a7Desired(t, a7Sync(t, q, 1, nil)).SignedManifest, map[string]*ecdsa.PublicKey{"current": q.pub})
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Targets) != 1 || manifest.Targets[0].Effect != "deny" || manifest.Targets[0].Source != "quarantine" {
		t.Fatalf("precedence %+v", manifest.Targets)
	}
}

func TestTRD2ITA7CandidateAndPreconditions(t *testing.T) {
	env := newA7(t, a7GoodDigest, false)
	req := []byte(`{"workload_ids":["` + env.wl.String() + `"],"graph_revision":1,"window":{"start":"2026-09-01T00:00:00Z","end":"2026-09-08T00:00:00Z"}}`)
	base := "/api/iga/v2/runtime-policies"
	created := callPolicy(t, env.r, http.MethodPost, base+"/candidates", env.author, "runtime_policy:write", "cand-1", "", req)
	var createdPartial struct {
		Data struct {
			Partial bool `json:"partial"`
		} `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createdPartial); err != nil {
		t.Fatal(err)
	}
	if created.Code != http.StatusCreated || !createdPartial.Data.Partial {
		t.Fatalf("candidate %d %s", created.Code, created.Body.String())
	}
	replay := callPolicy(t, env.r, http.MethodPost, base+"/candidates", env.author, "runtime_policy:write", "cand-1", "", req)
	if replay.Body.String() != created.Body.String() {
		t.Fatal("candidate replay changed")
	}
	again := callPolicy(t, env.r, http.MethodPost, base+"/candidates", env.author, "runtime_policy:write", "cand-2", "", req)
	if again.Code != http.StatusOK {
		t.Fatalf("regeneration %d %s", again.Code, again.Body.String())
	}
	var body struct {
		ETag string `json:"etag"`
		Data struct {
			PolicyID uuid.UUID `json:"policy_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	path := base + "/" + body.Data.PolicyID.String()
	got := callPolicy(t, env.r, http.MethodGet, path, env.author, "runtime_policy:read", "", "", nil)
	if got.Code != http.StatusOK {
		t.Fatalf("get candidate %d %s", got.Code, got.Body.String())
	}
	var view struct {
		Data struct {
			Policy struct {
				Name string `json:"name"`
			} `json:"policy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	edited := a7Doc(env.wl, view.Data.Policy.Name, "/var/app/edited", nil)
	if put := callPolicy(t, env.r, http.MethodPut, path+"/draft", env.author, "runtime_policy:write", "cand-edit", body.ETag, edited); put.Code != http.StatusOK {
		t.Fatalf("admin edit %d %s", put.Code, put.Body.String())
	}
	kept := callPolicy(t, env.r, http.MethodPost, base+"/candidates", env.author, "runtime_policy:write", "cand-3", "", req)
	if kept.Code != http.StatusConflict || !strings.Contains(kept.Body.String(), "admin_revision_preserved") {
		t.Fatalf("overwrite %d %s", kept.Code, kept.Body.String())
	}

	doc := a7Doc(env.wl, "pre-"+env.wl.String()[:8], "/var/app/data", []string{"filesystem"})
	ppath, petag := a7CreateValidated(t, env, doc)
	if missing := callPolicy(t, env.r, http.MethodPost, ppath+"/simulations", env.author, "runtime_policy:write", "sim-miss", "", []byte(`{}`)); missing.Code != http.StatusPreconditionRequired {
		t.Fatalf("simulation without If-Match %d", missing.Code)
	}
	if wrong := callPolicy(t, env.r, http.MethodPost, ppath+"/simulations", env.author, "runtime_policy:write", "sim-bad", "0-"+strings.Repeat("ab", 32), []byte(`{}`)); wrong.Code != http.StatusPreconditionFailed {
		t.Fatalf("simulation If-Match %d %s", wrong.Code, wrong.Body.String())
	}
	sim := callPolicy(t, env.r, http.MethodPost, ppath+"/simulations", env.author, "runtime_policy:write", "sim-1", petag, []byte(`{"graph_revision":1,"event_window":{"start":"2026-09-01T00:00:00Z","end":"2026-09-08T00:00:00Z"}}`))
	if sim.Code != http.StatusCreated {
		t.Fatalf("simulation %d %s", sim.Code, sim.Body.String())
	}
	var simBody struct {
		Data struct {
			SimulationID uuid.UUID `json:"simulation_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(sim.Body.Bytes(), &simBody); err != nil {
		t.Fatal(err)
	}
	read := callPolicy(t, env.r, http.MethodGet, "/api/iga/v2/runtime-policies/simulations/"+simBody.Data.SimulationID.String(), env.author, "runtime_policy:read", "", "", nil)
	if read.Code != http.StatusOK || !strings.Contains(read.Body.String(), simBody.Data.SimulationID.String()) {
		t.Fatalf("get simulation %d %s", read.Code, read.Body.String())
	}
}

func TestTRD2ITA7FlagOffSync(t *testing.T) {
	dsn := os.Getenv("IGA_TEST_DSN")
	if dsn == "" {
		t.Skip("IGA_TEST_DSN not set")
	}
	t.Setenv(services.EnvV2Policy, "0")
	db := openPolicyDB(t, dsn)
	g := openGorm(t, db)
	ws := uuid.New()
	execDB(t, db, `INSERT INTO workspaces (id, name) VALUES ($1, $2)`, ws, "a7off-"+ws.String()[:8])
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM workspaces WHERE id = $1`, ws) })
	scope, integ, src, collector := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	a7Collector(t, db, ws, scope, integ, src, collector, a7GoodDigest)
	p := &models.CollectorPrincipal{
		WorkspaceID: ws, CollectorID: collector, EstateScopeID: scope,
		DiscoverySourceID: src, IntegrationID: integ,
		Kind: models.CollectorKindLinux, Scopes: []string{models.CollectorScopeIngest},
	}
	raw := a7Accept(t, g, p, 1, nil)
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body["desired"] != nil {
		t.Fatalf("flag-off desired %#v", body["desired"])
	}
	for _, key := range []string{"receipt_id", "accepted_sequence", "receipt_state", "projection_state", "published_graph_revision", "mapping_url", "desired", "next_sync_seconds"} {
		if _, ok := body[key]; !ok {
			t.Fatalf("missing %s in %s", key, raw)
		}
	}
	if len(body) != 8 {
		t.Fatalf("flag-off receipt gained fields: %s", raw)
	}
}

func TestTRD2ITA7CollectorList(t *testing.T) {
	dsn := os.Getenv("IGA_TEST_DSN")
	if dsn == "" {
		t.Skip("IGA_TEST_DSN not set")
	}
	t.Setenv(services.EnvV2Ingest, "1")
	t.Setenv(services.EnvCollectorResponseKey, "a7-list-key")
	db := openPolicyDB(t, dsn)
	g := openGorm(t, db)
	ws, user := uuid.New(), uuid.New()
	execDB(t, db, `INSERT INTO workspaces (id, name) VALUES ($1, $2)`, ws, "a7list-"+ws.String()[:8])
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM workspaces WHERE id = $1`, ws) })
	execDB(t, db, `INSERT INTO users (id, email, workspace_id) VALUES ($1, $2, $3)`, user, user.String()+"@example.test", ws)
	a, b := uuid.New(), uuid.New()
	if a.String() > b.String() {
		a, b = b, a
	}
	scope, integ, src := uuid.New(), uuid.New(), uuid.New()
	a7Collector(t, db, ws, scope, integ, src, a, a7GoodDigest)
	scope2, integ2, src2 := uuid.New(), uuid.New(), uuid.New()
	execDB(t, db, `INSERT INTO iga_estate_scopes (id, workspace_id, scope_kind) VALUES ($1, $2, 'aws_account')`, scope2, ws)
	execDB(t, db, `INSERT INTO iga_integrations (id, workspace_id, provider, provider_host, app_registration_id)
		VALUES ($1, $2, 'github', 'github.com', $3)`, integ2, ws, "app-"+integ2.String()[:8])
	execDB(t, db, `INSERT INTO discovery_sources (id, workspace_id, kind, display_name) VALUES ($1, $2, 'k8s_webhook', 'a7b')`, src2, ws)
	execDB(t, db, `INSERT INTO collector_instances
		(id, workspace_id, discovery_source_id, estate_scope_id, integration_id, kind, installation_key_id, installation_public_key)
		VALUES ($1, $2, $3, $4, $5, 'k8s_collector', $6, $7)`,
		b, ws, src2, scope2, integ2, "key-"+b.String()[:8], []byte("a7"))
	policy, owner := uuid.New(), uuid.New()
	hash := strings.Repeat("a", 64)
	execDB(t, db, `INSERT INTO runtime_policies (id, workspace_id, name, owner_user_id, current_draft_revision, lifecycle)
		VALUES ($1, $2, $3, $4, 1, 'published')`, policy, ws, "list-"+policy.String()[:8], owner)
	execDB(t, db, `INSERT INTO runtime_policy_revisions
		(id, workspace_id, policy_id, revision, document, content_hash, author_user_id, state, graph_revision, compiler_format)
		VALUES ($1, $2, $3, 1, '{"name":"t"}', $4, $5, 'published', 1, 'authsec.runtime.v1')`,
		uuid.New(), ws, policy, hash, owner)
	pub := uuid.New()
	execDB(t, db, `INSERT INTO runtime_policy_publications
		(id, workspace_id, policy_id, revision, revision_hash, author_user_id)
		VALUES ($1, $2, $3, 1, $4, $5)`, pub, ws, policy, hash, owner)
	wl := uuid.New()
	execDB(t, db, `INSERT INTO iga_workload (id, workspace_id, runtime_kind, source_key) VALUES ($1, $2, 'process', $3)`, wl, ws, "wl-"+wl.String()[:8])
	target := uuid.New()
	execDB(t, db, `INSERT INTO runtime_policy_targets
		(id, workspace_id, publication_id, workload_id, collector_id, desired_delivery_revision)
		VALUES ($1, $2, $3, $4, $5, 7)`, target, ws, pub, wl, a)
	execDB(t, db, `INSERT INTO runtime_policy_receipts
		(id, workspace_id, target_id, publication_id, policy_id, delivery_revision)
		VALUES ($1, $2, $3, $4, $5, 4)`, uuid.New(), ws, target, pub, policy)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	routes.MountCollectorV2(r, g, routes.NewCollectorController(g), func(c *gin.Context) {
		c.Set("claims", jwt.MapClaims{"scope": c.GetHeader("X-Test-Scope")})
		c.Set("workspace_id", ws.String())
		c.Set("user_id", user.String())
		c.Next()
	})
	page := callPolicy(t, r, http.MethodGet, "/api/iga/v2/collectors?limit=1", user, "discovery:read", "", "", nil)
	if page.Code != http.StatusOK {
		t.Fatalf("list %d %s", page.Code, page.Body.String())
	}
	var listed struct {
		Data []struct {
			ID              uuid.UUID `json:"id"`
			Kind            string    `json:"kind"`
			DesiredRevision *int64    `json:"desired_revision"`
			AppliedRevision *int64    `json:"applied_revision"`
		} `json:"data"`
		Next string `json:"next_cursor"`
	}
	if err := json.Unmarshal(page.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Data) != 1 || listed.Data[0].ID != a || listed.Next == "" {
		t.Fatalf("page %+v", listed)
	}
	if listed.Data[0].DesiredRevision == nil || *listed.Data[0].DesiredRevision != 7 || listed.Data[0].AppliedRevision == nil || *listed.Data[0].AppliedRevision != 4 {
		t.Fatalf("revisions desired %v applied %v", listed.Data[0].DesiredRevision, listed.Data[0].AppliedRevision)
	}
	filtered := callPolicy(t, r, http.MethodGet, "/api/iga/v2/collectors?kind=k8s_collector", user, "discovery:read", "", "", nil)
	if filtered.Code != http.StatusOK || !strings.Contains(filtered.Body.String(), b.String()) || strings.Contains(filtered.Body.String(), a.String()) {
		t.Fatalf("filter %d %s", filtered.Code, filtered.Body.String())
	}
	missing := callPolicy(t, r, http.MethodGet, "/api/iga/v2/collectors/"+integ.String(), user, "discovery:read", "", "", nil)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("non-collector %d %s", missing.Code, missing.Body.String())
	}
}

func TestTRD2ITA7WorkspaceCascade(t *testing.T) {
	dsn := os.Getenv("IGA_TEST_DSN")
	if dsn == "" {
		t.Skip("IGA_TEST_DSN not set")
	}
	db := openPolicyDB(t, dsn)
	ws := uuid.New()
	execDB(t, db, `INSERT INTO workspaces (id, name) VALUES ($1, $2)`, ws, "a7del-"+ws.String()[:8])
	policy, owner := uuid.New(), uuid.New()
	hash := strings.Repeat("e", 64)
	execDB(t, db, `INSERT INTO runtime_policies (id, workspace_id, name, owner_user_id, current_draft_revision, lifecycle)
		VALUES ($1, $2, $3, $4, 1, 'published')`, policy, ws, "del-"+policy.String()[:8], owner)
	execDB(t, db, `INSERT INTO runtime_policy_revisions
		(id, workspace_id, policy_id, revision, document, content_hash, author_user_id, state, graph_revision, compiler_format)
		VALUES ($1, $2, $3, 1, '{"name":"t"}', $4, $5, 'published', 1, 'authsec.runtime.v1')`,
		uuid.New(), ws, policy, hash, owner)
	scope, integ, src, collector, wl := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	a7Collector(t, db, ws, scope, integ, src, collector, a7GoodDigest)
	execDB(t, db, `INSERT INTO iga_workload (id, workspace_id, runtime_kind, source_key) VALUES ($1, $2, 'process', $3)`, wl, ws, "wl-"+wl.String()[:8])
	pub := uuid.New()
	execDB(t, db, `INSERT INTO runtime_policy_publications
		(id, workspace_id, policy_id, revision, revision_hash, author_user_id, rollout_plan)
		VALUES ($1, $2, $3, 1, $4, $5, '{"phase":"complete","artifacts":{"opa_bundle":{"id":"x","sha256":"y","body":"YQ=="}}}'::jsonb)`,
		pub, ws, policy, hash, owner)
	target := uuid.New()
	execDB(t, db, `INSERT INTO runtime_policy_targets
		(id, workspace_id, publication_id, workload_id, collector_id, desired_delivery_revision)
		VALUES ($1, $2, $3, $4, $5, 1)`, target, ws, pub, wl, collector)
	receipt := uuid.New()
	execDB(t, db, `INSERT INTO runtime_policy_receipts
		(id, workspace_id, target_id, publication_id, policy_id, delivery_revision)
		VALUES ($1, $2, $3, $4, $5, 1)`, receipt, ws, target, pub, policy)
	if err := execErr(db, `UPDATE runtime_policy_receipts SET error = 'x' WHERE id = $1`, receipt); err == nil {
		t.Fatal("receipt update was accepted")
	}
	execDB(t, db, `DELETE FROM workspaces WHERE id = $1`, ws)
	for _, table := range []string{"runtime_policy_publications", "runtime_policy_targets", "runtime_policy_receipts"} {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM `+table+` WHERE workspace_id = $1`, ws).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("%s left %d rows", table, n)
		}
	}
}

type a7Env struct {
	db        *sql.DB
	g         *gorm.DB
	ws        uuid.UUID
	author    uuid.UUID
	wl        uuid.UUID
	collector uuid.UUID
	scope     uuid.UUID
	integ     uuid.UUID
	src       uuid.UUID
	r         http.Handler
	pub       *ecdsa.PublicKey
}

func (e *a7Env) principal() *models.CollectorPrincipal {
	return &models.CollectorPrincipal{
		WorkspaceID: e.ws, CollectorID: e.collector, EstateScopeID: e.scope,
		DiscoverySourceID: e.src, IntegrationID: e.integ,
		Kind: models.CollectorKindLinux, Scopes: []string{models.CollectorScopeIngest, models.CollectorScopePolicyRead},
	}
}

func newA7(t *testing.T, digest string, testDigests bool) *a7Env {
	t.Helper()
	dsn := os.Getenv("IGA_TEST_DSN")
	if dsn == "" {
		t.Skip("IGA_TEST_DSN not set")
	}
	t.Setenv(services.EnvV2Policy, "1")
	db := openPolicyDB(t, dsn)
	g := openGorm(t, db)
	ws, author, wl := uuid.New(), uuid.New(), uuid.New()
	execDB(t, db, `INSERT INTO workspaces (id, name) VALUES ($1, $2)`, ws, "a7-"+ws.String()[:8])
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM workspaces WHERE id = $1`, ws) })
	execDB(t, db, `INSERT INTO users (id, email, workspace_id) VALUES ($1, $2, $3)`, author, author.String()+"@example.test", ws)
	execDB(t, db, `INSERT INTO iga_workload (id, workspace_id, runtime_kind, source_key) VALUES ($1, $2, 'process', $3)`, wl, ws, "wl-"+wl.String()[:8])
	scope, integ, src, collector := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	a7Collector(t, db, ws, scope, integ, src, collector, digest)
	pub := a7SigningKey(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	auth := func(c *gin.Context) {
		c.Set("claims", jwt.MapClaims{"scope": c.GetHeader("X-Test-Scope")})
		c.Set("workspace_id", ws.String())
		c.Set("user_id", c.GetHeader("X-Test-User"))
		c.Next()
	}
	if testDigests {
		reg, err := profiles.Load()
		if err != nil {
			t.Fatal(err)
		}
		routes.MountRuntimePolicyService(r, services.NewRuntimePolicyServiceWithRegistry(g, reg.WithTestDigests()), auth)
	} else {
		routes.MountRuntimePolicy(r, g, auth)
	}
	return &a7Env{
		db: db, g: g, ws: ws, author: author, wl: wl, collector: collector,
		scope: scope, integ: integ, src: src, r: r, pub: pub,
	}
}

func a7Collector(t *testing.T, db *sql.DB, ws, scope, integ, src, collector uuid.UUID, digest string) {
	t.Helper()
	execDB(t, db, `INSERT INTO iga_estate_scopes (id, workspace_id, scope_kind) VALUES ($1, $2, 'aws_account')`, scope, ws)
	execDB(t, db, `INSERT INTO iga_integrations (id, workspace_id, provider, provider_host, app_registration_id)
		VALUES ($1, $2, 'github', 'github.com', $3)`, integ, ws, "app-"+integ.String()[:8])
	execDB(t, db, `INSERT INTO discovery_sources (id, workspace_id, kind, display_name) VALUES ($1, $2, 'k8s_webhook', $3)`, src, ws, "a7-"+src.String()[:8])
	execDB(t, db, `INSERT INTO collector_instances
		(id, workspace_id, discovery_source_id, estate_scope_id, integration_id, kind, installation_key_id, installation_public_key)
		VALUES ($1, $2, $3, $4, $5, 'linux_collector', $6, $7)`,
		collector, ws, src, scope, integ, "key-"+collector.String()[:8], []byte("a7"))
	execDB(t, db, `INSERT INTO collector_capability_reports (workspace_id, collector_id, capability_digest)
		VALUES ($1, $2, $3)`, ws, collector, digest)
}

func a7SigningKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "policy-key.pem")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(services.EnvPolicySigningKeyPEM, path)
	t.Setenv(services.EnvPolicySigningKeyID, "current")
	return &key.PublicKey
}

func a7Doc(wl uuid.UUID, name, path string, controls []string) []byte {
	if controls == nil {
		controls = []string{}
	}
	rules := []any{}
	if path != "" {
		rules = append(rules, map[string]any{"id": "files", "action": "file.read", "path": path, "effect": "allow"})
	}
	raw, err := json.Marshal(map[string]any{
		"name": name, "format": models.RuntimePolicyFormatV1,
		"targets":                 map[string]any{"workload_ids": []string{wl.String()}, "include_future_incarnations": false},
		"profile":                 "linux-managed-v1",
		"default_effect":          "deny",
		"mode":                    "observe",
		"rules":                   rules,
		"required_controls":       controls,
		"evidence_graph_revision": 1,
	})
	if err != nil {
		panic(err)
	}
	return raw
}

func a7Approve(t *testing.T, env *a7Env, doc []byte) (string, string, string, string) {
	t.Helper()
	path, etag := a7CreateValidated(t, env, doc)
	etag = a7FinishApproval(t, env, path, etag, "appr")
	var hash, digest string
	if err := env.db.QueryRow(`SELECT r.content_hash, s.target_digest
		FROM runtime_policy_revisions r
		JOIN runtime_policy_simulations s ON s.workspace_id = r.workspace_id AND s.policy_id = r.policy_id AND s.revision_hash = r.content_hash
		WHERE r.workspace_id = $1 ORDER BY s.created_at DESC LIMIT 1`, env.ws).Scan(&hash, &digest); err != nil {
		t.Fatal(err)
	}
	return path, etag, hash, digest
}

func a7CreateValidated(t *testing.T, env *a7Env, doc []byte) (string, string) {
	t.Helper()
	base := "/api/iga/v2/runtime-policies"
	created := callPolicy(t, env.r, http.MethodPost, base, env.author, "runtime_policy:write", "create-"+uuid.NewString(), "", doc)
	if created.Code != http.StatusCreated {
		t.Fatalf("create %d %s", created.Code, created.Body.String())
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
	validated := callPolicy(t, env.r, http.MethodPost, path+"/validate", env.author, "runtime_policy:write", "val-"+uuid.NewString(), createdBody.ETag, []byte(`{}`))
	if validated.Code != http.StatusOK {
		t.Fatalf("validate %d %s", validated.Code, validated.Body.String())
	}
	var valBody struct {
		ETag string `json:"etag"`
	}
	if err := json.Unmarshal(validated.Body.Bytes(), &valBody); err != nil {
		t.Fatal(err)
	}
	return path, valBody.ETag
}

func a7FinishApproval(t *testing.T, env *a7Env, path, etag, prefix string) string {
	t.Helper()
	sim := callPolicy(t, env.r, http.MethodPost, path+"/simulations", env.author, "runtime_policy:write", prefix+"-sim", etag, []byte(`{"graph_revision":1,"event_window":{"start":"2026-09-01T00:00:00Z","end":"2026-09-08T00:00:00Z"}}`))
	if sim.Code != http.StatusCreated {
		t.Fatalf("simulate %d %s", sim.Code, sim.Body.String())
	}
	var simBody struct {
		ETag string `json:"etag"`
		Data struct {
			SimulationID uuid.UUID `json:"simulation_id"`
			ContentHash  string    `json:"revision_hash"`
			TargetDigest string    `json:"target_digest"`
		} `json:"data"`
	}
	if err := json.Unmarshal(sim.Body.Bytes(), &simBody); err != nil {
		t.Fatal(err)
	}
	approve := []byte(`{"revision_hash":"` + simBody.Data.ContentHash + `","simulation_id":"` + simBody.Data.SimulationID.String() + `","target_digest":"` + simBody.Data.TargetDigest + `","reason":"reviewed","mfa_context":{"method":"present"}}`)
	ok := callPolicy(t, env.r, http.MethodPost, path+"/approvals", env.author, "runtime_policy:approve", prefix+"-ok", simBody.ETag, approve)
	if ok.Code != http.StatusCreated {
		t.Fatalf("approve %d %s", ok.Code, ok.Body.String())
	}
	var approved struct {
		ETag string `json:"etag"`
	}
	if err := json.Unmarshal(ok.Body.Bytes(), &approved); err != nil {
		t.Fatal(err)
	}
	return approved.ETag
}

type a7DesiredDoc struct {
	Revision       int64  `json:"revision"`
	PolicyFormat   string `json:"policy_format"`
	SignedManifest string `json:"signed_manifest"`
	OPABundle      struct {
		URL         string `json:"url"`
		SHA256      string `json:"sha256"`
		RegoVersion string `json:"rego_version"`
	} `json:"opa_bundle"`
	Controls struct {
		URL    string `json:"url"`
		SHA256 string `json:"sha256"`
	} `json:"controls"`
}

func a7Sync(t *testing.T, env *a7Env, seq int64, applied []collectorcontract.AppliedReceipt) []byte {
	t.Helper()
	if applied == nil {
		applied = []collectorcontract.AppliedReceipt{}
	}
	return a7Accept(t, env.g, env.principal(), seq, applied)
}

func a7Accept(t *testing.T, g *gorm.DB, p *models.CollectorPrincipal, seq int64, applied []collectorcontract.AppliedReceipt) []byte {
	t.Helper()
	if applied == nil {
		applied = []collectorcontract.AppliedReceipt{}
	}
	epoch := uuid.NewString()
	if seq > 1 {
		var stored struct{ Epoch string }
		if err := g.Raw(`SELECT COALESCE(epoch::text, '') AS epoch FROM collector_instances WHERE id = ?`, p.CollectorID).Scan(&stored).Error; err != nil {
			t.Fatal(err)
		}
		if stored.Epoch == "" {
			t.Fatalf("collector %s has no epoch before sequence %d", p.CollectorID, seq)
		}
		epoch = stored.Epoch
	}
	raw, err := json.Marshal(collectorcontract.SyncRequest{
		SchemaVersion: collectorcontract.SchemaVersion, BatchID: uuid.NewString(),
		CollectorEpoch: epoch, Sequence: seq, SentAt: "2026-09-28T08:00:00Z",
		Objects: []collectorcontract.Object{}, Observations: []collectorcontract.Observation{},
		Applied: applied, Health: collectorcontract.Health{},
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := services.NewCollectorSyncService(g, nil).Accept(p, raw)
	if err != nil {
		t.Fatalf("sync %d: %v", seq, err)
	}
	return body
}

func a7Desired(t *testing.T, raw []byte) a7DesiredDoc {
	t.Helper()
	var wrap struct {
		Desired *a7DesiredDoc `json:"desired"`
	}
	if err := json.Unmarshal(raw, &wrap); err != nil {
		t.Fatal(err)
	}
	if wrap.Desired == nil {
		t.Fatalf("desired is null: %s", raw)
	}
	return *wrap.Desired
}

func a7Download(t *testing.T, env *a7Env, artifactURL string, p *models.CollectorPrincipal) []byte {
	t.Helper()
	rec := a7DownloadStatus(t, env, artifactURL, p)
	if rec.Code != http.StatusOK {
		t.Fatalf("download %d %s", rec.Code, rec.Body.String())
	}
	return rec.Body.Bytes()
}

func a7DownloadStatus(t *testing.T, env *a7Env, artifactURL string, p *models.CollectorPrincipal) *httptest.ResponseRecorder {
	t.Helper()
	t.Setenv(services.EnvCollectorResponseKey, "a7-artifact-key")
	ctl := routes.NewCollectorController(env.g)
	if ctl == nil {
		t.Fatal("collector controller unavailable")
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/iga/v2/policy-artifacts/:id", func(c *gin.Context) {
		c.Set(middlewares.CtxCollectorPrincipal, p)
		c.Next()
	}, ctl.PolicyArtifact)
	req := httptest.NewRequest(http.MethodGet, artifactURL, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func a7Protected(t *testing.T, env *a7Env, path string) bool {
	t.Helper()
	rec := callPolicy(t, env.r, http.MethodGet, path+"/rollouts", env.author, "runtime_policy:read", "", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("rollout %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Data struct {
			Targets []struct {
				Protected bool `json:"protected"`
			} `json:"targets"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Data.Targets) == 0 {
		t.Fatalf("no rollout targets: %s", rec.Body.String())
	}
	return body.Data.Targets[0].Protected
}
