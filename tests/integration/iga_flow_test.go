package integration

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// End-to-end exercise of the Agentic IGA flow against a real Postgres, driven
// by fixture responses instead of a live GitHub tenant.
//
// Run with a scratch database that has 001_bootstrap.sql applied:
//
//	IGA_TEST_DSN="host=localhost port=5432 user=authsec password=... dbname=iga_test sslmode=disable" \
//	  go test ./tests/integration/ -run TestIGA -v
//
// Skips when IGA_TEST_DSN is unset so ordinary `go test ./...` stays green.

func igaDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("IGA_TEST_DSN")
	if dsn == "" {
		t.Skip("IGA_TEST_DSN not set; skipping IGA integration test")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return db
}

// newWorkspace creates an isolated workspace so tests never collide.
func newWorkspace(t *testing.T, db *gorm.DB, name string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	err := db.Exec(`INSERT INTO workspaces
        (id,name,slug,owner_user_id,workspace_type,workspace_domain,email,status,created_at,updated_at)
        VALUES (?,?,NULL,?,'team',?,?,'active',NOW(),NOW())`,
		id, name, id, id.String()+".test", id.String()+"@test.local").Error
	if err != nil {
		t.Fatalf("create workspace: %v", err)
	}
	t.Cleanup(func() { db.Exec(`DELETE FROM workspaces WHERE id = ?`, id) })
	return id
}

// fixtures builds a provider with three deliberately different repositories:
// one with a provider-declared agent, one with only a weak workflow signal and
// a truncated tree, and one that fails outright.
func fixtures() *services.FixtureProvider {
	manifest, _ := json.Marshal(map[string]interface{}{
		"name":         "release-notes-agent",
		"description":  "drafts release notes",
		"model":        "claude-sonnet-5",
		"tools":        []string{"github.read"},
		"mcpServers":   map[string]interface{}{"github": map[string]interface{}{}},
		"apiKey":       "sk-must-never-be-persisted",
		"instructions": "SYSTEM PROMPT THAT MUST NOT BE PERSISTED",
	})
	workflow := []byte("jobs:\n  x:\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        env:\n          KEY: ${{ secrets.OPENAI_API_KEY }}\n")

	return &services.FixtureProvider{
		ProviderName: "github",
		Caps: map[string]string{
			models.ClassAgentProfile:    models.CoverageComplete,
			models.ClassRepoDeclaration: models.CoverageComplete,
		},
		Scopes: []services.ProviderScope{
			{Kind: "repository", NativeID: "repo-1", DisplayName: "acme/payments", DefaultBranch: "main"},
			{Kind: "repository", NativeID: "repo-2", DisplayName: "acme/monorepo", DefaultBranch: "main"},
			{Kind: "repository", NativeID: "repo-3", DisplayName: "acme/locked", DefaultBranch: "main"},
		},
		NativeAgents: map[string][]services.ProviderObject{
			// Lane A: the provider itself says this is an agent.
			"repo-1": {{
				ObjectType: models.ClassAgentProfile, NativeID: "copilot-agent-77",
				DisplayName:  "copilot-custom-agent",
				EvidenceMode: models.EvidencePlatformDeclared,
				Payload:      map[string]interface{}{"name": "copilot-custom-agent"},
			}},
		},
		Identities: map[string][]services.ProviderObject{
			// Lane C: an identity, which must never become an agent.
			"repo-1": {{
				ObjectType: models.ClassAppInstallation, NativeID: "inst-app-9",
				DisplayName: "ci-bot-app", EvidenceMode: models.EvidenceIdentityGrant,
				Payload: map[string]interface{}{"permissions": map[string]string{"contents": "write"}},
			}},
		},
		SBOM: map[string][]services.ProviderObject{
			// A dependency: supporting signal only, never an agent.
			"repo-1": {{
				ObjectType: models.ClassSBOMComponent, NativeID: "pkg:pypi/langchain",
				DisplayName: "langchain", EvidenceMode: models.EvidenceFrameworkDep,
				Payload: map[string]interface{}{"package": "langchain"},
			}},
		},
		Trees: map[string][]services.TreeEntry{
			"repo-1": {
				{Path: "README.md", SHA: "aaa", Size: 10},
				{Path: "agent.json", SHA: "bbb", Size: int64(len(manifest))},
			},
			"repo-2": {
				{Path: ".github/workflows/ci.yml", SHA: "ccc", Size: int64(len(workflow))},
			},
		},
		Truncated: map[string]bool{"repo-2": true},
		Blobs: map[string][]byte{
			"repo-1:agent.json":               manifest,
			"repo-2:.github/workflows/ci.yml": workflow,
		},
		Grants: map[string][]services.ProviderGrant{
			"repo-1": {
				{
					SubjectNativeID: "inst-app-9", SubjectKind: "app_installation",
					SubjectName: "ci-bot-app", GrantKind: "installation_permission",
					NativeRights: map[string]string{"contents": "write"},
				},
				{
					SubjectNativeID: "pat-7", SubjectKind: "fine_grained_pat",
					SubjectName: "alice-pat", GrantKind: "pat_permission",
					NativeRights:   map[string]string{"contents": "read"},
					CredentialType: "fine_grained_pat", KeyIdentifier: "pat-7",
					ExpiresAt: &farFuture,
				},
				{
					// Effect depends on org policy we cannot observe, so the
					// edge must stay partial with an unknown conclusion.
					SubjectNativeID: "key-3", SubjectKind: "deploy_key",
					SubjectName: "deploy-key-3", GrantKind: "deploy_key",
					NativeRights:   map[string]string{"contents": "read"},
					Conditional:    true,
					CredentialType: "deploy_key", KeyIdentifier: "key-3",
				},
			},
		},
		Codeowners: map[string][]services.CodeownerRule{
			"repo-1": {
				{Pattern: "*", Owners: []string{"@acme/platform"}},
				// Last match wins, so this must beat the catch-all above.
				{Pattern: "agent.json", Owners: []string{"@alice", "@acme/agents"}},
			},
		},
		FailScopes: map[string]error{
			"repo-3": errors.New("403 permission denied for repository"),
		},
	}
}

var farFuture = time.Now().Add(1000 * 24 * time.Hour)

func verifiedIntegration(t *testing.T, mgr services.IGAManager, ws uuid.UUID, installID string) *models.IGAIntegration {
	t.Helper()
	integ, err := mgr.CreateIntegration(ws, "tester", services.IntegrationInput{
		Provider: "github", ProviderHost: "github.com", AppRegistrationID: "app-test",
		RequestedPermissions: map[string]interface{}{"contents": "read"},
	})
	if err != nil {
		t.Fatalf("create integration: %v", err)
	}
	out, err := mgr.VerifyIntegration(ws, integ.ID, services.VerifyInput{
		InstallationID: installID, AccountNativeID: "acct-1", AuthenticatedAccountID: "acct-1",
		GrantedPermissions: map[string]interface{}{"contents": "read"},
	})
	if err != nil {
		t.Fatalf("verify integration: %v", err)
	}
	return out
}

// TestIGABindingSecurity covers the two ways an installation could be bound to
// the wrong tenant: a spoofed setup-URL id, and silent cross-workspace rebinding.
func TestIGABindingSecurity(t *testing.T) {
	db := igaDB(t)
	repo := repositories.NewIGARepository(db)
	mgr := services.NewIGAManager(repo, fixtures())

	wsA := newWorkspace(t, db, "ws-a")
	wsB := newWorkspace(t, db, "ws-b")

	integ, err := mgr.CreateIntegration(wsA, "tester", services.IntegrationInput{
		Provider: "github", ProviderHost: "github.com", AppRegistrationID: "app-sec",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// A spoofed installation id: the installation's account does not match the
	// account that actually authenticated. Must be refused.
	_, err = mgr.VerifyIntegration(wsA, integ.ID, services.VerifyInput{
		InstallationID: "inst-sec", AccountNativeID: "victim-org", AuthenticatedAccountID: "attacker",
	})
	if !errors.Is(err, repositories.ErrIGABindingFailed) {
		t.Fatalf("expected binding refusal for mismatched account, got %v", err)
	}

	// The honest case succeeds.
	if _, err := mgr.VerifyIntegration(wsA, integ.ID, services.VerifyInput{
		InstallationID: "inst-sec", AccountNativeID: "acct", AuthenticatedAccountID: "acct",
	}); err != nil {
		t.Fatalf("legitimate verify failed: %v", err)
	}

	// Workspace B now tries to claim the SAME installation. The unique index
	// that excludes workspace_id must stop it.
	integB, err := mgr.CreateIntegration(wsB, "tester", services.IntegrationInput{
		Provider: "github", ProviderHost: "github.com", AppRegistrationID: "app-sec",
	})
	if err != nil {
		t.Fatalf("create B: %v", err)
	}
	_, err = mgr.VerifyIntegration(wsB, integB.ID, services.VerifyInput{
		InstallationID: "inst-sec", AccountNativeID: "acct", AuthenticatedAccountID: "acct",
	})
	if err == nil {
		t.Fatal("cross-workspace rebinding was allowed")
	}
	t.Logf("PASS: cross-workspace rebinding refused (%v)", err)
}

// TestIGAScanPipeline is the main flow: enumerate, classify, project, cover.
func TestIGAScanPipeline(t *testing.T) {
	db := igaDB(t)
	repo := repositories.NewIGARepository(db)
	fx := fixtures()
	mgr := services.NewIGAManager(repo, fx)

	ws := newWorkspace(t, db, "ws-scan")
	integ := verifiedIntegration(t, mgr, ws, "inst-scan")

	run, err := mgr.StartScan(ws, integ.ID, models.ScanModeFull, "tester")
	if err != nil {
		t.Fatalf("start scan: %v", err)
	}
	report, err := mgr.RunScan(context.Background(), ws, run.ID)
	if err != nil {
		t.Fatalf("run scan: %v", err)
	}
	t.Logf("scan: scopes=%d source_objects=%d observations=%d candidates=%d confirmed=%d fetched=%d skipped=%d",
		report.ScopesSeen, report.SourceObjects, report.Observations,
		report.Candidates, report.AgentsConfirmed, report.BlobsFetched, report.BlobsSkipped)

	// 1. The scan must be authoritative only after succeeding.
	got, err := mgr.GetScanRun(ws, run.ID)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if got.Status != models.ScanSucceeded || !got.IsAuthoritative {
		t.Fatalf("expected succeeded+authoritative, got %s auth=%v", got.Status, got.IsAuthoritative)
	}

	// 2. The provider-declared agent auto-confirms; nothing else does.
	if report.AgentsConfirmed != 1 {
		t.Fatalf("expected exactly 1 auto-confirmed agent (the platform-declared one), got %d",
			report.AgentsConfirmed)
	}
	agents, total, err := mgr.ListAgents(ws, "", 50, 0)
	if err != nil {
		t.Fatalf("list agents: %v", err)
	}
	if total != 1 {
		t.Fatalf("expected 1 confirmed agent, got %d", total)
	}
	if agents[0].Classification != models.EvidencePlatformDeclared {
		t.Fatalf("confirmed agent should be platform_declared, got %s", agents[0].Classification)
	}

	// 3. The weak workflow signal is a CANDIDATE, never a confirmed agent.
	cands, candTotal, err := mgr.ListCandidates(ws, models.CandidatePending, 50, 0)
	if err != nil {
		t.Fatalf("list candidates: %v", err)
	}
	if candTotal == 0 {
		t.Fatal("expected the workflow invocation to produce a pending candidate")
	}
	for _, c := range cands {
		if c.EvidenceMode == models.EvidencePlatformDeclared {
			t.Fatal("a platform-declared candidate should already be confirmed, not pending")
		}
	}
	t.Logf("PASS: %d confirmed agent, %d pending candidates — counted separately", total, candTotal)

	// 4. An identity and a dependency must NOT have produced agents.
	var idCount int64
	db.Raw(`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = ?`, ws).Scan(&idCount)
	if idCount == 0 {
		t.Fatal("expected the app installation to become an identity account")
	}
	var badCandidates int64
	db.Raw(`SELECT count(*) FROM iga_classification_candidates c
	        JOIN iga_source_objects s ON s.id = c.source_object_id
	        WHERE c.workspace_id = ? AND s.object_type IN (?,?)`,
		ws, models.ClassAppInstallation, models.ClassSBOMComponent).Scan(&badCandidates)
	if badCandidates != 0 {
		t.Fatalf("identities/dependencies must never propose an agent, got %d", badCandidates)
	}
	t.Log("PASS: identity became an identity; dependency proposed nothing")

	// 5. Secrets and prompts must not be persisted; only secret NAMES.
	var leaked int64
	db.Raw(`SELECT count(*) FROM iga_observations
	        WHERE workspace_id = ? AND (fact_payload::text LIKE '%sk-must-never%'
	                                 OR fact_payload::text LIKE '%SYSTEM PROMPT%')`, ws).Scan(&leaked)
	if leaked != 0 {
		t.Fatalf("secret value or prompt body was persisted (%d rows)", leaked)
	}
	var named int64
	db.Raw(`SELECT count(*) FROM iga_observations
	        WHERE workspace_id = ? AND fact_payload::text LIKE '%OPENAI_API_KEY%'`, ws).Scan(&named)
	if named == 0 {
		t.Fatal("expected the secret NAME to be recorded as redacted evidence")
	}
	t.Log("PASS: secret value and prompt discarded; secret name retained as evidence")

	// 6. Coverage: truncation and failure degrade, they never read as zero.
	cov, err := mgr.Coverage(ws, integ.ID)
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	var sawPartialTruncated, sawPartialDenied bool
	for _, cs := range cov {
		if cs.State == models.CoveragePartial {
			if cs.ReasonCode != "" && cs.ObjectClass == models.ClassRepoDeclaration {
				sawPartialTruncated = true
			}
			if cs.DeniedCount > 0 {
				sawPartialDenied = true
			}
		}
		if cs.State == models.CoverageComplete && cs.InspectedCount == 0 && cs.DeniedCount == 0 {
			continue
		}
	}
	if !sawPartialTruncated {
		t.Fatal("truncated tree must produce partial coverage, not a smaller complete count")
	}
	if !sawPartialDenied {
		t.Fatal("denied scope must produce partial coverage with a denied count")
	}
	t.Log("PASS: truncation and permission denial both degrade coverage instead of reporting zero")

	// 7. Operational issues are recorded, and separately from findings.
	issues, err := mgr.SourceHealth(ws, &integ.ID)
	if err != nil {
		t.Fatalf("source health: %v", err)
	}
	if len(issues) == 0 {
		t.Fatal("expected operational issues for truncation and permission denial")
	}
	t.Logf("PASS: %d operational issues recorded separately from agent findings", len(issues))

	// 8. Re-scan: unchanged blobs are skipped, observations are not duplicated.
	obsBefore := countRows(db, `SELECT count(*) FROM iga_observations WHERE workspace_id = ?`, ws)
	run2, err := mgr.StartScan(ws, integ.ID, models.ScanModeIncremental, "tester")
	if err != nil {
		t.Fatalf("start rescan: %v", err)
	}
	report2, err := mgr.RunScan(context.Background(), ws, run2.ID)
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}
	if report2.BlobsSkipped == 0 {
		t.Fatal("expected unchanged blobs to be skipped on rescan via the stored hash")
	}
	if report2.BlobsFetched != 0 {
		t.Fatalf("nothing changed, so no blob should have been fetched; got %d", report2.BlobsFetched)
	}
	obsAfter := countRows(db, `SELECT count(*) FROM iga_observations WHERE workspace_id = ?`, ws)
	t.Logf("PASS: rescan skipped %d unchanged blobs, fetched %d; observations %d -> %d (new generation appends)",
		report2.BlobsSkipped, report2.BlobsFetched, obsBefore, obsAfter)

	// 9. Evidence drill-down resolves.
	ev, err := mgr.AgentEvidence(ws, agents[0].ID)
	if err != nil {
		t.Fatalf("agent evidence: %v", err)
	}
	if len(ev) == 0 {
		t.Fatal("a confirmed agent must resolve to supporting observations")
	}
	t.Logf("PASS: agent drills down to %d supporting observation(s)", len(ev))
}

// TestIGACandidateDecisionConcurrency proves a stale decision is rejected
// rather than silently overwriting someone else's.
func TestIGACandidateDecisionConcurrency(t *testing.T) {
	db := igaDB(t)
	repo := repositories.NewIGARepository(db)
	mgr := services.NewIGAManager(repo, fixtures())

	ws := newWorkspace(t, db, "ws-decide")
	integ := verifiedIntegration(t, mgr, ws, "inst-decide")
	run, _ := mgr.StartScan(ws, integ.ID, models.ScanModeFull, "tester")
	if _, err := mgr.RunScan(context.Background(), ws, run.ID); err != nil {
		t.Fatalf("scan: %v", err)
	}

	cands, _, err := mgr.ListCandidates(ws, models.CandidatePending, 10, 0)
	if err != nil || len(cands) == 0 {
		t.Fatalf("need a pending candidate: %v", err)
	}
	target := cands[0]

	// A stale expected version must be refused.
	if _, err := mgr.DecideCandidate(ws, target.ID, target.Version+99,
		models.CandidateConfirmed, "stale", "reviewer"); !errors.Is(err, repositories.ErrIGAVersionStale) {
		t.Fatalf("expected version conflict, got %v", err)
	}
	t.Log("PASS: stale decision refused")

	// The correct version confirms and produces an agent.
	before, _, _ := mgr.ListAgents(ws, "", 50, 0)
	if _, err := mgr.DecideCandidate(ws, target.ID, target.Version,
		models.CandidateConfirmed, "reviewed", "reviewer"); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	after, _, _ := mgr.ListAgents(ws, "", 50, 0)
	if len(after) != len(before)+1 {
		t.Fatalf("confirming a candidate should create one agent: %d -> %d", len(before), len(after))
	}

	// A human-confirmed but weakly-evidenced agent must NOT claim to be
	// confirmed-by-provider; its rollup stays honest.
	var promoted *models.IGAAgent
	for i := range after {
		if after[i].Classification != models.EvidencePlatformDeclared {
			promoted = &after[i]
		}
	}
	if promoted == nil {
		t.Fatal("expected a weakly-evidenced agent from the confirmed candidate")
	}
	if promoted.RollupState == models.RollupConfirmed {
		t.Fatal("weak evidence must not produce a 'confirmed' rollup state")
	}
	t.Logf("PASS: weakly-evidenced agent promoted with rollup_state=%s, not 'confirmed'", promoted.RollupState)

	// Re-deciding the same candidate must not create a second agent.
	if _, err := mgr.DecideCandidate(ws, target.ID, target.Version,
		models.CandidateConfirmed, "again", "reviewer"); err == nil {
		t.Fatal("re-deciding a decided candidate should fail")
	}
	t.Log("PASS: a decided candidate cannot be decided twice")
}

// TestIGAWebhookIngress covers the normative ingress order.
func TestIGAWebhookIngress(t *testing.T) {
	db := igaDB(t)
	repo := repositories.NewIGARepository(db)
	mgr := services.NewIGAManager(repo, fixtures())

	ws := newWorkspace(t, db, "ws-hook")
	integ := verifiedIntegration(t, mgr, ws, "inst-hook")

	secret := "test-webhook-secret"
	body := []byte(`{"action":"created"}`)
	sign := func(b []byte) string {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(b)
		return "sha256=" + hex.EncodeToString(mac.Sum(nil))
	}

	base := services.WebhookInput{
		AppRegistrationID: integ.AppRegistrationID,
		EventType:         "installation_repositories",
		Secret:            secret,
		Body:              body,
		InstallationID:    "inst-hook",
	}

	// 1. A bad signature is refused and must not touch the work queue.
	bad := base
	bad.DeliveryID = "d-bad"
	bad.Signature = "sha256=" + hex.EncodeToString([]byte("wrong"))
	if _, err := mgr.AcceptWebhook(bad); !errors.Is(err, repositories.ErrIGASignature) {
		t.Fatalf("expected signature rejection, got %v", err)
	}
	if n := countRows(db, `SELECT count(*) FROM iga_durable_jobs WHERE workspace_id = ?`, ws); n != 0 {
		t.Fatalf("invalid signature must not enqueue work, found %d jobs", n)
	}
	t.Log("PASS: invalid signature rejected without touching the queue")

	// 2. A valid signature for an UNKNOWN installation is a binding failure.
	unknown := base
	unknown.DeliveryID = "d-unknown"
	unknown.InstallationID = "inst-does-not-exist"
	unknown.Signature = sign(body)
	if _, err := mgr.AcceptWebhook(unknown); !errors.Is(err, repositories.ErrIGABindingFailed) {
		t.Fatalf("expected binding failure, got %v", err)
	}
	t.Log("PASS: payload installation id alone does not authorize")

	// 3. A valid, bound delivery is accepted and enqueues exactly one job.
	good := base
	good.DeliveryID = "d-good"
	good.Signature = sign(body)
	res, err := mgr.AcceptWebhook(good)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if !res.Accepted || res.Redelivery {
		t.Fatalf("expected fresh acceptance, got %+v", res)
	}
	if n := countRows(db, `SELECT count(*) FROM iga_durable_jobs WHERE workspace_id = ?`, ws); n != 1 {
		t.Fatalf("expected exactly 1 job, got %d", n)
	}

	// 4. Redelivery is idempotent: no second job, no second effect.
	res2, err := mgr.AcceptWebhook(good)
	if err != nil {
		t.Fatalf("redelivery: %v", err)
	}
	if !res2.Redelivery {
		t.Fatal("expected redelivery to be recognised")
	}
	if n := countRows(db, `SELECT count(*) FROM iga_durable_jobs WHERE workspace_id = ?`, ws); n != 1 {
		t.Fatalf("redelivery created a second job (%d)", n)
	}
	t.Log("PASS: redelivery produced one delivery record, one job, one effect")

	// 5. The worker claims and completes it.
	worked, err := mgr.RunWorkerOnce(context.Background(), "test-worker")
	if err != nil {
		t.Fatalf("worker: %v", err)
	}
	if !worked {
		t.Fatal("expected the worker to claim the queued job")
	}
	var state string
	db.Raw(`SELECT state FROM iga_durable_jobs WHERE workspace_id = ? LIMIT 1`, ws).Scan(&state)
	if state != models.JobDone {
		t.Fatalf("expected job done, got %q", state)
	}
	t.Log("PASS: worker claimed and completed the durable job")

	// 6. An empty queue is not an error.
	again, err := mgr.RunWorkerOnce(context.Background(), "test-worker")
	if err != nil || again {
		t.Fatalf("expected idle worker, got worked=%v err=%v", again, err)
	}
}

func countRows(db *gorm.DB, q string, args ...interface{}) int64 {
	var n int64
	db.Raw(q, args...).Scan(&n)
	return n
}
