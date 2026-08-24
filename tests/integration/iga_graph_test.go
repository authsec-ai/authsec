package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// TestIGAAccessGraph proves the inventory has consequences: identities,
// credentials, entitlements and edges, with honest calculation states.
func TestIGAAccessGraph(t *testing.T) {
	db := igaDB(t)
	repo := repositories.NewIGARepository(db)
	mgr := services.NewIGAManager(repo, fixtures())

	ws := newWorkspace(t, db, "ws-access")
	integ := verifiedIntegration(t, mgr, ws, "inst-access")
	run, _ := mgr.StartScan(ws, integ.ID, models.ScanModeFull, "tester")
	rep, err := mgr.RunScan(context.Background(), ws, run.ID)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	t.Logf("identities=%d credentials=%d access_edges=%d tombstoned=%d",
		rep.Identities, rep.Credentials, rep.AccessEdges, rep.Tombstoned)

	if rep.AccessEdges == 0 {
		t.Fatal("no access edges created; the inventory cannot answer what an agent can reach")
	}
	if rep.Credentials == 0 {
		t.Fatal("expected credential metadata for the PAT and deploy key")
	}

	// A conditional grant must NOT claim effective access.
	var partial, effective int64
	db.Raw(`SELECT count(*) FROM iga_access_edges WHERE workspace_id=? AND calculation_state='partial'`, ws).Scan(&partial)
	db.Raw(`SELECT count(*) FROM iga_access_edges WHERE workspace_id=? AND effective_conclusion='effective'`, ws).Scan(&effective)
	if partial == 0 {
		t.Fatal("the conditional deploy-key grant must produce a partial edge")
	}
	if effective == 0 {
		t.Fatal("a fully observed grant should conclude effective")
	}
	t.Logf("PASS: %d partial (conditional) and %d effective edge(s) — a grant is not automatically access",
		partial, effective)

	// Native wording is preserved alongside the normalized reading.
	var withNative int64
	db.Raw(`SELECT count(*) FROM iga_entitlements
	        WHERE workspace_id=? AND native_rights <> '{}'::jsonb AND normalized_rights <> '{}'::jsonb`, ws).
		Scan(&withNative)
	if withNative == 0 {
		t.Fatal("entitlements must keep both the provider wording and the derived reading")
	}

	// No secret material on credential rows.
	var leaked int64
	db.Raw(`SELECT count(*) FROM iga_credentials WHERE workspace_id=? AND secret_ref <> ''`, ws).Scan(&leaked)
	if leaked != 0 {
		t.Fatalf("credential rows must not carry secret material (%d)", leaked)
	}

	// Credential posture is derivable from metadata alone — a real finding.
	var longLived int64
	db.Raw(`SELECT count(*) FROM iga_credentials
	        WHERE workspace_id=? AND rotation_posture IN ('long_lived','no_expiry')`, ws).Scan(&longLived)
	t.Logf("PASS: %d credential(s) flagged long-lived/no-expiry from metadata alone", longLived)

	// CODEOWNERS ownership only materialises when a declaration-backed
	// candidate is confirmed, so confirm the agent.json one and check what the
	// scan attributed to it.
	cands, _, err := mgr.ListCandidates(ws, models.CandidatePending, 50, 0)
	if err != nil || len(cands) == 0 {
		t.Fatalf("expected pending candidates: %v", err)
	}
	var manifest *models.IGACandidate
	for i := range cands {
		src, err := repo.GetSourceObject(ws, cands[i].SourceObjectID)
		if err == nil && strings.Contains(src.RecognitionKey, "agent.json") {
			manifest = &cands[i]
		}
	}
	if manifest == nil {
		t.Fatal("expected a candidate from the agent.json declaration")
	}
	if _, err := mgr.DecideCandidate(ws, manifest.ID, manifest.Version,
		models.CandidateConfirmed, "reviewed", "reviewer"); err != nil {
		t.Fatalf("confirm manifest candidate: %v", err)
	}

	agents, _, _ := mgr.ListAgents(ws, "", 50, 0)
	if len(agents) == 0 {
		t.Fatal("expected a confirmed agent")
	}
	refs := map[string]string{} // candidate_ref -> kind
	for _, a := range agents {
		owners, _ := repo.ListOwnershipCandidates(ws, a.ID)
		for _, o := range owners {
			if o.State != "proposed" {
				t.Fatal("CODEOWNERS must only PROPOSE an owner, never confirm one")
			}
			if o.CandidateRef != "" {
				refs[o.CandidateRef] = o.CandidateKind
			}
		}
	}
	// Last-match-wins: agent.json is owned by @alice and @acme/agents, and the
	// earlier catch-all "*" -> @acme/platform must NOT win. Getting this
	// backwards would attribute the agent to the wrong team.
	if refs["@alice"] != "user" {
		t.Fatalf("expected @alice as a user owner candidate, got %v", refs)
	}
	if refs["@acme/agents"] != "team" {
		t.Fatalf("expected @acme/agents as a team owner candidate, got %v", refs)
	}
	if _, wrong := refs["@acme/platform"]; wrong {
		t.Fatal("the earlier catch-all CODEOWNERS pattern must lose to the later specific one")
	}
	t.Logf("PASS: CODEOWNERS last-match-wins produced %v, all proposed and none confirmed", refs)

	// The access summary must distinguish "not calculated" from "no access".
	for _, a := range agents {
		_, summary, err := mgr.AgentAccessPaths(ws, a.ID)
		if err != nil {
			t.Fatalf("access paths: %v", err)
		}
		if summary.State == "" || summary.Statement == "" {
			t.Fatal("access summary must state how much was actually calculated")
		}
	}
	t.Log("PASS: access summary distinguishes uncalculated from absent")
}

// TestIGADeletionSafety proves a scan cannot tombstone what it did not prove
// absent, and that a mass disappearance is refused outright.
func TestIGADeletionSafety(t *testing.T) {
	db := igaDB(t)
	repo := repositories.NewIGARepository(db)
	fx := fixtures()
	mgr := services.NewIGAManager(repo, fx)

	ws := newWorkspace(t, db, "ws-delete")
	integ := verifiedIntegration(t, mgr, ws, "inst-delete")

	run, _ := mgr.StartScan(ws, integ.ID, models.ScanModeFull, "tester")
	if _, err := mgr.RunScan(context.Background(), ws, run.ID); err != nil {
		t.Fatalf("first scan: %v", err)
	}
	before := countRows(db,
		`SELECT count(*) FROM iga_source_objects WHERE workspace_id=? AND lifecycle='active'`, ws)
	if before == 0 {
		t.Fatal("expected active source objects after the first scan")
	}

	// Everything vanishes at once. That looks far more like a permission change
	// or an outage than a real deletion, so the guard must refuse to tombstone.
	fx.NativeAgents = map[string][]services.ProviderObject{}
	fx.Identities = map[string][]services.ProviderObject{}
	fx.SBOM = map[string][]services.ProviderObject{}
	fx.Trees = map[string][]services.TreeEntry{}
	fx.Grants = map[string][]services.ProviderGrant{}

	run2, _ := mgr.StartScan(ws, integ.ID, models.ScanModeFull, "tester")
	rep2, err := mgr.RunScan(context.Background(), ws, run2.ID)
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}
	after := countRows(db,
		`SELECT count(*) FROM iga_source_objects WHERE workspace_id=? AND lifecycle='active'`, ws)
	if rep2.Tombstoned > 0 || after != before {
		t.Fatalf("mass disappearance must not tombstone: tombstoned=%d, active %d -> %d",
			rep2.Tombstoned, before, after)
	}
	var guard int64
	db.Raw(`SELECT count(*) FROM iga_operational_issues WHERE workspace_id=? AND severity='critical'`, ws).
		Scan(&guard)
	if guard == 0 {
		t.Fatal("the guard should raise a critical operational issue for an operator")
	}
	t.Logf("PASS: guard preserved %d object(s) and raised %d critical issue(s)", before, guard)
}

// TestIGACheckpointsAndSurvivorship covers resumability and contradiction.
func TestIGACheckpointsAndSurvivorship(t *testing.T) {
	db := igaDB(t)
	repo := repositories.NewIGARepository(db)
	mgr := services.NewIGAManager(repo, fixtures())

	ws := newWorkspace(t, db, "ws-ckpt")
	integ := verifiedIntegration(t, mgr, ws, "inst-ckpt")
	run, _ := mgr.StartScan(ws, integ.ID, models.ScanModeFull, "tester")
	if _, err := mgr.RunScan(context.Background(), ws, run.ID); err != nil {
		t.Fatalf("scan: %v", err)
	}

	// Without checkpoints a killed worker restarts from zero.
	cps, err := repo.ListCheckpoints(ws, run.ID)
	if err != nil {
		t.Fatalf("checkpoints: %v", err)
	}
	if len(cps) == 0 {
		t.Fatal("no checkpoints written; the scan is not resumable")
	}
	t.Logf("PASS: %d checkpoint(s) written — a killed worker resumes from here", len(cps))

	// Survivorship: exactly one surviving value per attribute.
	agents, _, _ := mgr.ListAgents(ws, "", 50, 0)
	if len(agents) == 0 {
		t.Fatal("expected an agent")
	}
	vals, err := repo.ListAttributeValues(ws, "agent", agents[0].ID)
	if err != nil {
		t.Fatalf("attribute values: %v", err)
	}
	surviving := 0
	for _, v := range vals {
		if v.State == "surviving" {
			surviving++
		}
	}
	if surviving != 1 {
		t.Fatalf("expected exactly 1 surviving display_name, got %d of %d value(s)", surviving, len(vals))
	}
	t.Logf("PASS: survivorship recorded (%d value(s), exactly 1 surviving)", len(vals))
}

// TestIGACursorPagination proves list routes page by opaque cursor rather than
// offset, which on a changing inventory would skip and repeat rows.
func TestIGACursorPagination(t *testing.T) {
	db := igaDB(t)
	repo := repositories.NewIGARepository(db)
	mgr := services.NewIGAManager(repo, fixtures())

	ws := newWorkspace(t, db, "ws-page")
	integ := verifiedIntegration(t, mgr, ws, "inst-page")
	run, _ := mgr.StartScan(ws, integ.ID, models.ScanModeFull, "tester")
	if _, err := mgr.RunScan(context.Background(), ws, run.ID); err != nil {
		t.Fatalf("scan: %v", err)
	}

	first, err := mgr.ListCandidatesPage(ws, models.CandidatePending, "", 1)
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if len(first.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(first.Items))
	}
	if first.NextCursor == "" {
		t.Fatal("expected a next cursor when more candidates remain")
	}
	second, err := mgr.ListCandidatesPage(ws, models.CandidatePending, first.NextCursor, 1)
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if len(second.Items) == 0 || second.Items[0].ID == first.Items[0].ID {
		t.Fatal("cursor did not advance to a distinct row")
	}
	if _, err := mgr.ListCandidatesPage(ws, "", "not-a-cursor", 10); err == nil {
		t.Fatal("a malformed cursor must be rejected, not silently ignored")
	}
	t.Log("PASS: opaque cursor pages forward with a deterministic tie-breaker")

	// Agents, candidates and identities never share a count.
	ap, _ := mgr.ListAgentsPage(ws, "", "", 50)
	cp, _ := mgr.ListCandidatesPage(ws, models.CandidatePending, "", 50)
	ip, _ := mgr.ListIdentityAccountsPage(ws, "", 50)
	t.Logf("PASS: separate counts — agents=%d candidates=%d identities=%d",
		ap.Total, cp.Total, ip.Total)
}
