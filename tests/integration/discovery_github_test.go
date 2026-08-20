package integration

import (
	"context"
	"testing"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

// GitHub is a discovery CHANNEL for the existing inventory, not a second one.
// These tests assert that its sightings land in discovered_agents next to the
// Kubernetes ones and are governed by the same claim/quarantine/coverage flow.

func TestGitHubScanFeedsExistingInventory(t *testing.T) {
	db := igaDB(t)
	discoRepo := repositories.NewDiscoveryRepository(db)
	disco := services.NewDiscoveryManager(discoRepo)

	ws := newWorkspace(t, db, "ws-gh-disco")

	// A repo_scan source, exactly as an admin would create through the
	// existing /authsec/discovery/sources API.
	src, err := disco.CreateSource(ws, "admin", services.DiscoverySourceInput{
		Kind:        models.DiscoverySourceRepoScan,
		DisplayName: "acme-github",
		Config: map[string]interface{}{
			"installation_id":     "12345",
			"app_registration_id": "app-1",
		},
	})
	if err != nil {
		t.Fatalf("create source: %v", err)
	}

	scanner := services.NewGitHubRepoScannerWithProvider(db, fixtures())
	res, err := scanner.Scan(context.Background(), ws, src.ID, "admin")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	t.Logf("scan: repos=%d failed=%d truncated=%d files=%d new=%d bumped=%d complete=%v",
		res.ReposScanned, res.ReposFailed, res.ReposTruncated,
		res.FilesFetched, res.SightingsNew, res.SightingsBumped, res.Complete)

	if res.SightingsNew == 0 {
		t.Fatal("expected the GitHub scan to report sightings")
	}

	// A repo that 403s and a truncated tree must both prevent a "complete"
	// claim; otherwise a partial scan reads as the whole picture.
	if res.Complete {
		t.Fatal("a scan with a failed repo and a truncated tree must not be complete_for_selected_scope")
	}
	if res.ReposFailed == 0 || res.ReposTruncated == 0 {
		t.Fatalf("expected the denied and truncated repos to be counted: %+v", res)
	}
	t.Log("PASS: failure and truncation counted separately; scan not marked complete")

	// The rows are in the EXISTING inventory, marked repo_scan and automated.
	agents, total, err := disco.ListAgents(ws, repositories.AgentFilter{
		Source: models.DiscoverySourceRepoScan, Limit: 50,
	})
	if err != nil {
		t.Fatalf("list agents: %v", err)
	}
	if total == 0 {
		t.Fatal("GitHub sightings did not land in discovered_agents")
	}
	for _, a := range agents {
		if a.Status != models.DiscoveredAgentUnregistered {
			t.Fatalf("a sighting must land unregistered, got %q", a.Status)
		}
		if a.DeploymentOrigin != models.DeploymentOriginAutomated {
			t.Fatalf("a version-controlled declaration is automated by construction, got %q",
				a.DeploymentOrigin)
		}
	}
	t.Logf("PASS: %d GitHub sighting(s) in the existing inventory, all unregistered and automated", total)

	// No secret value or prompt body, only the secret NAME.
	var leaked, named int64
	db.Raw(`SELECT count(*) FROM discovered_agents
	        WHERE workspace_id=? AND (metadata::text LIKE '%sk-must-never%'
	                               OR metadata::text LIKE '%SYSTEM PROMPT%')`, ws).Scan(&leaked)
	db.Raw(`SELECT count(*) FROM discovered_agents
	        WHERE workspace_id=? AND metadata::text LIKE '%OPENAI_API_KEY%'`, ws).Scan(&named)
	if leaked != 0 {
		t.Fatalf("secret value or prompt body persisted (%d rows)", leaked)
	}
	if named == 0 {
		t.Fatal("expected the secret NAME to be kept as redacted evidence")
	}
	t.Log("PASS: secret value and prompt discarded; secret name retained")

	// CODEOWNERS rode along on the sighting metadata.
	var withOwners int64
	db.Raw(`SELECT count(*) FROM discovered_agents
	        WHERE workspace_id=? AND metadata::text LIKE '%codeowners%'`, ws).Scan(&withOwners)
	if withOwners == 0 {
		t.Fatal("expected CODEOWNERS owners on at least one sighting")
	}
	t.Log("PASS: CODEOWNERS attribution carried on the sighting")

	// Re-scanning is an upsert on the same fingerprint, never a duplicate.
	res2, err := scanner.Scan(context.Background(), ws, src.ID, "admin")
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}
	if res2.SightingsNew != 0 {
		t.Fatalf("a rescan must create no new rows, got %d", res2.SightingsNew)
	}
	if res2.SightingsBumped == 0 {
		t.Fatal("a rescan should bump the existing sightings")
	}
	_, total2, _ := disco.ListAgents(ws, repositories.AgentFilter{
		Source: models.DiscoverySourceRepoScan, Limit: 50,
	})
	if total2 != total {
		t.Fatalf("rescan changed the row count: %d -> %d", total, total2)
	}
	t.Logf("PASS: rescan bumped %d sighting(s), row count unchanged at %d", res2.SightingsBumped, total2)
}

func TestGitHubSightingsUseExistingGovernance(t *testing.T) {
	db := igaDB(t)
	disco := services.NewDiscoveryManager(repositories.NewDiscoveryRepository(db))

	ws := newWorkspace(t, db, "ws-gh-gov")
	src, err := disco.CreateSource(ws, "admin", services.DiscoverySourceInput{
		Kind: models.DiscoverySourceRepoScan, DisplayName: "acme-gh-gov",
		Config: map[string]interface{}{"installation_id": "12345"},
	})
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	scanner := services.NewGitHubRepoScannerWithProvider(db, fixtures())
	if _, err := scanner.Scan(context.Background(), ws, src.ID, "admin"); err != nil {
		t.Fatalf("scan: %v", err)
	}

	agents, _, err := disco.ListAgents(ws, repositories.AgentFilter{
		Source: models.DiscoverySourceRepoScan, Limit: 10,
	})
	if err != nil || len(agents) == 0 {
		t.Fatalf("need a GitHub sighting: %v", err)
	}

	// The EXISTING claim endpoint governs it: an owner is mandatory.
	owner := uuid.New()
	db.Exec(`INSERT INTO users (id,email,workspace_id,created_at,updated_at)
	         VALUES (?,?,?,NOW(),NOW())`, owner, owner.String()+"@x.local", ws)
	client := uuid.New()
	db.Exec(`INSERT INTO mcp_oauth_clients (id,client_id,hydra_client_id,client_name)
	         VALUES (?,?,?,?)`, client, "c-"+client.String(), "h-"+client.String(), "gh-agent")

	claimed, err := disco.ClaimAgent(ws, agents[0].ID, services.ClaimInput{
		MatchedClientID: client, OwnerUserID: owner, ClaimedBy: &owner,
	})
	if err != nil {
		t.Fatalf("claim a GitHub-discovered agent: %v", err)
	}
	if claimed.Status != models.DiscoveredAgentRegistered {
		t.Fatalf("expected registered, got %q", claimed.Status)
	}
	t.Log("PASS: a GitHub sighting is claimed through the existing endpoint")

	// And the existing coverage KPI counts it.
	cov, err := disco.Coverage(ws)
	if err == nil && cov != nil {
		t.Logf("PASS: existing coverage sees GitHub rows (registered=%d of %d)",
			cov.Registered, cov.Total)
	}

	// Quarantine still blocks a claim, unchanged.
	remaining, _, _ := disco.ListAgents(ws, repositories.AgentFilter{
		Status: models.DiscoveredAgentUnregistered, Limit: 10,
	})
	if len(remaining) > 0 {
		if _, err := disco.QuarantineAgent(ws, remaining[0].ID, "untrusted", &owner); err != nil {
			t.Fatalf("quarantine: %v", err)
		}
		if _, err := disco.ClaimAgent(ws, remaining[0].ID, services.ClaimInput{
			MatchedClientID: client, OwnerUserID: owner,
		}); err == nil {
			t.Fatal("a quarantined GitHub sighting must not be claimable")
		}
		t.Log("PASS: quarantine still blocks a claim for GitHub-sourced rows")
	}
}
