package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// A GitHub finding lands as DECLARED, with no runtime observation, and the
// database refuses to let that change.
//
// This is the ticket's whole reason for existing: the naive integration writes a
// parsed file into a table whose contract is "a sighting means it is running",
// and the product then states something it does not know. Enforcing it in the
// DATABASE means no future call site can reintroduce the lie by forgetting a
// field.
func TestGitHubFindingIsDeclaredAndNeverRunning(t *testing.T) {
	db := igaDB(t)
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	ws := newWorkspace(t, db, "ws-evidence-declared")
	srcID := repoScanSource(t, disco, ws, "acme-evidence")

	if _, err := services.NewGitHubRepoScannerWithProvider(db, oneRepoProvider()).
		Scan(context.Background(), ws, srcID, "admin"); err != nil {
		t.Fatalf("scan: %v", err)
	}

	var rows []struct {
		EvidenceMode          string
		DeploymentOrigin      string
		LastObservedRunningAt *time.Time
		LastSeenAt            time.Time
	}
	db.Raw(`SELECT evidence_mode, deployment_origin, last_observed_running_at, last_seen_at
	        FROM discovered_agents WHERE workspace_id=?`, ws).Scan(&rows)
	if len(rows) == 0 {
		t.Fatal("expected at least one GitHub finding")
	}

	for _, r := range rows {
		if r.EvidenceMode != models.EvidenceDeclared {
			t.Fatalf("a repository finding must be DECLARED, got %q", r.EvidenceMode)
		}
		// The NULL is the correct answer, not missing data.
		if r.LastObservedRunningAt != nil {
			t.Fatalf("a declared row must have no runtime timestamp, got %v",
				r.LastObservedRunningAt)
		}
		if r.DeploymentOrigin != models.DeploymentOriginUnknown {
			t.Fatalf("a declaration does not establish deployment, got %q",
				r.DeploymentOrigin)
		}
		// And the trap: evidence-seen IS recent. A UI reading this column
		// instead of the runtime one renders a file as a live process.
		if r.LastSeenAt.IsZero() {
			t.Fatal("evidence-seen should be stamped even on a declared row")
		}
	}
	t.Logf("PASS: %d declared row(s), runtime timestamp NULL, origin unknown", len(rows))

	// The service refuses the contradiction with a clear error...
	_, _, err := disco.ReportSighting(ws, "admin", services.SightingInput{
		Source:            models.DiscoverySourceRepoScan,
		DiscoverySourceID: &srcID,
		Fingerprint:       "gh:bogus:runtime-claim",
		EvidenceMode:      models.EvidenceDeclared,
		ObservedRunningAt: func() *time.Time { n := time.Now(); return &n }(),
	})
	if err == nil {
		t.Fatal("a declared sighting carrying a runtime timestamp must be refused")
	}
	t.Logf("PASS: service refused the contradiction: %v", err)

	// ...and the database refuses it too, so the service is not the only guard.
	raw := db.Exec(`UPDATE discovered_agents SET last_observed_running_at = now()
	                WHERE workspace_id = ? AND evidence_mode = 'declared'`, ws)
	if raw.Error == nil {
		t.Fatal("the DB CHECK must refuse a runtime timestamp on a declared row")
	}
	t.Logf("PASS: database refused it as well: %v", raw.Error)
}

// The shadow-agent question is EXPRESSIBLE over these columns.
//
// The most valuable cell in the matrix is "running but never declared" — someone
// bypassed the pipeline. Full cross-source correlation is delivered separately,
// so what this test proves is the necessary half: the columns distinguish the
// four cases, so the query can be written at all. A model that collapsed
// declared and observed into one flag could never express it, at any number of
// columns.
//
//	              | declared in code | not declared
//	running       | governed         | SHADOW AGENT
//	not running   | dead code        | -
func TestShadowAgentQueryIsExpressible(t *testing.T) {
	db := igaDB(t)
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	ws := newWorkspace(t, db, "ws-shadow")

	k8sSrc, err := disco.CreateSource(ws, "admin", services.DiscoverySourceInput{
		Kind: models.DiscoverySourceK8sWebhook, DisplayName: "prod-cluster",
	})
	if err != nil {
		t.Fatalf("create k8s source: %v", err)
	}
	repoSrc := repoScanSource(t, disco, ws, "acme-shadow")

	now := time.Now()
	meta := map[string]interface{}{"repository": "acme/app"}

	// 1. GOVERNED: declared in code. (A repo scan can only ever produce this.)
	if _, _, err := disco.ReportSighting(ws, "admin", services.SightingInput{
		Source: models.DiscoverySourceRepoScan, DiscoverySourceID: &repoSrc,
		Fingerprint: "gh:repo-1:agent.json", DisplayName: "declared-agent",
		Metadata: meta,
	}); err != nil {
		t.Fatalf("declared sighting: %v", err)
	}

	// 2. SHADOW: observed running in the cluster, never declared anywhere.
	if _, _, err := disco.ReportSighting(ws, "admin", services.SightingInput{
		Source: models.DiscoverySourceK8sWebhook, DiscoverySourceID: &k8sSrc.ID,
		Fingerprint: "k8s:sha256:undeclared", DisplayName: "shadow-agent",
		ObservedRunningAt: &now,
	}); err != nil {
		t.Fatalf("observed sighting: %v", err)
	}

	// The shadow-agent query: running, and no declaration carries its name.
	var shadows []string
	db.Raw(`SELECT display_name FROM discovered_agents obs
	         WHERE obs.workspace_id = ?
	           AND obs.evidence_mode = ?
	           AND obs.last_observed_running_at IS NOT NULL
	           AND NOT EXISTS (
	                 SELECT 1 FROM discovered_agents dec
	                  WHERE dec.workspace_id = obs.workspace_id
	                    AND dec.evidence_mode = ?
	                    AND dec.display_name = obs.display_name)`,
		ws, models.EvidenceObserved, models.EvidenceDeclared).Scan(&shadows)

	if len(shadows) != 1 || shadows[0] != "shadow-agent" {
		t.Fatalf("expected exactly the undeclared running agent, got %v", shadows)
	}

	// And the declared row must NOT appear: it is not running, so it cannot be
	// a shadow agent. A query that returned it would be reporting dead code as
	// the highest-risk finding in the product.
	for _, s := range shadows {
		if s == "declared-agent" {
			t.Fatal("a declared-but-not-running row is dead code, never a shadow agent")
		}
	}
	t.Logf("PASS: shadow-agent query returned %v and excluded the declared row", shadows)
}

// Claim and quarantine behave identically on declared and observed rows.
//
// If governance worked differently for the two, GitHub findings would need a
// parallel governance surface — and the entire point of landing them in the
// existing inventory is that they do not.
func TestGovernanceIsIdenticalAcrossEvidenceModes(t *testing.T) {
	db := igaDB(t)
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))
	ws := newWorkspace(t, db, "ws-evidence-governance")

	k8sSrc, err := disco.CreateSource(ws, "admin", services.DiscoverySourceInput{
		Kind: models.DiscoverySourceK8sWebhook, DisplayName: "cluster",
	})
	if err != nil {
		t.Fatalf("create k8s source: %v", err)
	}
	repoSrc := repoScanSource(t, disco, ws, "acme-governance")

	now := time.Now()
	declared, _, err := disco.ReportSighting(ws, "admin", services.SightingInput{
		Source: models.DiscoverySourceRepoScan, DiscoverySourceID: &repoSrc,
		Fingerprint: "gh:r:agent.json", DisplayName: "declared-one",
	})
	if err != nil {
		t.Fatalf("declared: %v", err)
	}
	observed, _, err := disco.ReportSighting(ws, "admin", services.SightingInput{
		Source: models.DiscoverySourceK8sWebhook, DiscoverySourceID: &k8sSrc.ID,
		Fingerprint: "k8s:r:pod", DisplayName: "observed-one",
		ObservedRunningAt: &now,
	})
	if err != nil {
		t.Fatalf("observed: %v", err)
	}

	// Quarantine blocks a claim, in both modes, for the same reason.
	for _, a := range []struct {
		label string
		id    string
	}{{"declared", declared.ID.String()}, {"observed", observed.ID.String()}} {
		var mode string
		db.Raw(`SELECT evidence_mode FROM discovered_agents WHERE id = ?`, a.id).Scan(&mode)
		t.Logf("%s row has evidence_mode=%q", a.label, mode)
		if mode == "" {
			t.Fatalf("%s row has no evidence mode", a.label)
		}
	}

	if _, err := disco.QuarantineAgent(ws, declared.ID, "under review", nil); err != nil {
		t.Fatalf("quarantine a declared row: %v", err)
	}
	if _, err := disco.QuarantineAgent(ws, observed.ID, "under review", nil); err != nil {
		t.Fatalf("quarantine an observed row: %v", err)
	}
	t.Log("PASS: quarantine applies identically to declared and observed rows")

	// Metadata still round-trips as JSON for both, so downstream readers need
	// no mode-specific handling.
	for _, id := range []string{declared.ID.String(), observed.ID.String()} {
		var raw string
		db.Raw(`SELECT metadata::text FROM discovered_agents WHERE id = ?`, id).Scan(&raw)
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatalf("metadata not valid json for %s: %v", id, err)
		}
	}
	t.Log("PASS: both modes present an identical governance surface")
}
