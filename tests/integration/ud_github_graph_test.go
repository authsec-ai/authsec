package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/ghgraph"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// The GitHub half of the unified inventory (ud/gh): every GitHub IGA scan, and
// every repo-scan run, projected into the shared iga_* tables as KEYED rows --
// upserted, supported, reconciled -- while the legacy GitHub rows and the
// screens that read them stay exactly as they were.
//
// Real PostgreSQL (IGA_TEST_DSN, at 042) and the fixture provider; nothing
// reaches GitHub.

const ghWorkflow = "name: Release agent\njobs:\n  x:\n    steps:\n      - uses: anthropics/claude-code-action@v1\n"

// ghGraphFixture is two repositories with every kind the projection writes:
// two deploy keys (read and write) and a Copilot agent in acme/payments, one
// read-only deploy key in acme/tools, and an agent-invoking workflow in each.
func ghGraphFixture() *services.FixtureProvider {
	key := func(id, title string, right string) services.ProviderGrant {
		return services.ProviderGrant{
			SubjectNativeID: id, SubjectKind: "deploy_key", SubjectName: title,
			GrantKind: "deploy_key", NativeRights: map[string]string{"contents": right},
			CredentialType: "deploy_key", KeyIdentifier: id,
		}
	}
	return &services.FixtureProvider{
		ProviderName: "github",
		Caps: map[string]string{
			models.ClassAgentProfile:    models.CoverageComplete,
			models.ClassRepoDeclaration: models.CoverageComplete,
		},
		Scopes: []services.ProviderScope{
			{Kind: "repository", NativeID: "R_pay", NodeID: "R_pay", DisplayName: "acme/payments", DefaultBranch: "main"},
			{Kind: "repository", NativeID: "R_tools", NodeID: "R_tools", DisplayName: "acme/tools", DefaultBranch: "trunk", Archived: true},
		},
		NativeAgents: map[string][]services.ProviderObject{
			"R_pay": {{
				ObjectType: models.ClassAgentProfile, NativeID: "cp-1", DisplayName: "triage-agent",
				EvidenceMode: models.EvidencePlatformDeclared,
				Payload: map[string]interface{}{
					"name": "triage-agent", "description": "triages issues",
					"declared_tools": []string{"github.read"},
				},
			}},
		},
		Identities: map[string][]services.ProviderObject{
			// The legacy pipeline's per-scope installation identity.
			"R_pay":   {{ObjectType: models.ClassAppInstallation, NativeID: "inst-gh", DisplayName: "installation inst-gh"}},
			"R_tools": {{ObjectType: models.ClassAppInstallation, NativeID: "inst-gh", DisplayName: "installation inst-gh"}},
		},
		Trees: map[string][]services.TreeEntry{
			"R_pay":   {{Path: ".github/workflows/agent.yml", SHA: "sha-pay", Size: int64(len(ghWorkflow))}},
			"R_tools": {{Path: ".github/workflows/bot.yml", SHA: "sha-tools", Size: int64(len(ghWorkflow))}},
		},
		Blobs: map[string][]byte{
			"R_pay:.github/workflows/agent.yml": []byte(ghWorkflow),
			"R_tools:.github/workflows/bot.yml": []byte(ghWorkflow),
		},
		Grants: map[string][]services.ProviderGrant{
			"R_pay":   {key("10", "deploy-ro", "read"), key("11", "deploy-rw", "write")},
			"R_tools": {key("20", "tools-ro", "read")},
		},
		FailScopes: map[string]error{},
	}
}

func ghGateOn() *services.GraphProjectionGate  { return services.NewGraphProjectionGate(true, "") }
func ghGateOff() *services.GraphProjectionGate { return services.NewGraphProjectionGate(false, "") }

func ghManager(db *gorm.DB, fx services.IGAProvider, gate *services.GraphProjectionGate, installs ...string) services.IGAManager {
	return services.NewIGAManager(repositories.NewIGARepository(db), fx, ownedInstall(installs...),
		services.WithGitHubGraph(services.NewGitHubGraphProjector(db, gate)))
}

func ghScan(t *testing.T, mgr services.IGAManager, ws, integID uuid.UUID) (uuid.UUID, *services.ScanReport) {
	t.Helper()
	run, err := mgr.StartScan(ws, integID, models.ScanModeFull, "tester")
	if err != nil {
		t.Fatalf("start scan: %v", err)
	}
	rep, err := mgr.RunScan(context.Background(), ws, run.ID)
	if err != nil {
		t.Fatalf("run scan: %v", err)
	}
	for _, is := range rep.Issues {
		if strings.Contains(is, "graph projection") {
			t.Fatalf("graph projection failed: %s", is)
		}
	}
	return run.ID, rep
}

// ghRow is one keyed node, as the assertions read it.
type ghRow struct {
	ID        uuid.UUID
	SourceKey string
	Kind      string
	Name      string
	Lifecycle string
	Attrs     string
}

func ghNodes(t *testing.T, db *gorm.DB, table, kindCol string, ws uuid.UUID) map[string]ghRow {
	t.Helper()
	var rows []ghRow
	// iga_entitlements carries neither a name nor provider_attrs.
	cols := "display_name AS name, provider_attrs::text AS attrs"
	if table == "iga_entitlements" {
		cols = "'' AS name, '{}' AS attrs"
	}
	if err := db.Raw(`SELECT id, source_key, `+kindCol+` AS kind, lifecycle, `+cols+`
	                    FROM `+table+`
	                   WHERE workspace_id = ? AND provider = 'github' AND source_key <> ''
	                   ORDER BY source_key, lifecycle`, ws).Scan(&rows).Error; err != nil {
		t.Fatalf("read %s: %v", table, err)
	}
	out := map[string]ghRow{}
	for _, r := range rows {
		k := r.SourceKey
		if r.Lifecycle != models.IGALifecycleActive {
			k += "#" + r.Lifecycle + "#" + r.ID.String()
		}
		if _, dup := out[k]; dup {
			t.Fatalf("%s: two live rows for %q", table, r.SourceKey)
		}
		out[k] = r
	}
	return out
}

func ghKey(kind string, parts ...string) string { return ghgraph.Key("github.com", kind, parts...) }

func ghAttrs(t *testing.T, raw string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("provider_attrs %q: %v", raw, err)
	}
	return m
}

// supportOf reads an object's support rows from one integration.
func supportOf(t *testing.T, db *gorm.DB, ws uuid.UUID, col string, id uuid.UUID) []models.IGAObjectSupport {
	t.Helper()
	var out []models.IGAObjectSupport
	if err := db.Where("workspace_id = ? AND "+col+" = ?", ws, id).Find(&out).Error; err != nil {
		t.Fatalf("read support: %v", err)
	}
	return out
}

func requireSupport(t *testing.T, db *gorm.DB, ws uuid.UUID, col string, id, integID, runID uuid.UUID, state string) {
	t.Helper()
	s := supportOf(t, db, ws, col, id)
	if len(s) != 1 {
		t.Fatalf("%s %s: %d support rows, want exactly 1", col, id, len(s))
	}
	if s[0].IntegrationID == nil || *s[0].IntegrationID != integID || s[0].ConnectorID != nil || s[0].DiscoverySourceID != nil {
		t.Fatalf("%s %s: support names %+v, want only integration %s", col, id, s[0], integID)
	}
	if s[0].State != state {
		t.Fatalf("%s %s: support state %q, want %q", col, id, s[0].State, state)
	}
	if state == models.RelCurrent && (s[0].LastConfirmedScanRunID == nil || *s[0].LastConfirmedScanRunID != runID) {
		t.Fatalf("%s %s: last confirmed by %v, want scan run %s", col, id, s[0].LastConfirmedScanRunID, runID)
	}
}

type ghEdge struct {
	ID                     uuid.UUID
	SourceKey              string
	State                  string
	SubjectIdentityID      uuid.UUID `gorm:"column:subject_identity_account_id"`
	EntitlementID          uuid.UUID
	ResourceID             uuid.UUID
	IntegrationID          uuid.UUID
	LastConfirmedScanRunID uuid.UUID
	CalculationState       string
	EffectiveConclusion    string
	EndedReason            string
}

func ghEdges(t *testing.T, db *gorm.DB, ws uuid.UUID) []ghEdge {
	t.Helper()
	var out []ghEdge
	if err := db.Raw(`SELECT id, source_key, state, subject_identity_account_id, entitlement_id, resource_id,
	                         integration_id, last_confirmed_scan_run_id, calculation_state,
	                         effective_conclusion, ended_reason
	                    FROM iga_access_edges
	                   WHERE workspace_id = ? AND provider = 'github' AND source_key <> ''
	                   ORDER BY source_key, state`, ws).Scan(&out).Error; err != nil {
		t.Fatalf("read edges: %v", err)
	}
	return out
}

// TestUDGitHubScanProjectsEachKindOnce: one scan writes every kind exactly once,
// keyed, supported, scoped; a second scan duplicates nothing and reconfirms all
// of it -- including the workflows whose blobs the second scan skipped.
func TestUDGitHubScanProjectsEachKindOnce(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ud-gh-once")
	mgr := ghManager(db, ghGraphFixture(), ghGateOn(), "inst-gh")
	integ := verifiedIntegration(t, mgr, ws, "inst-gh")

	legacyBefore := countRows(db, `SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = ? AND source_key = ''`, ws)
	run1, rep := ghScan(t, mgr, ws, integ.ID)
	if rep.Graph == nil || !rep.Graph.Projected {
		t.Fatalf("the scan report carries no graph projection: %+v", rep.Graph)
	}

	check := func(run uuid.UUID) {
		t.Helper()
		res := ghNodes(t, db, "iga_resources", "resource_kind", ws)
		ids := ghNodes(t, db, "iga_identity_accounts", "account_kind", ws)
		wls := ghNodes(t, db, "iga_workload", "runtime_kind", ws)
		sts := ghNodes(t, db, "iga_entitlements", "native_grant_kind", ws)

		want := map[string]map[string]string{
			"resource": {
				ghKey("repository", "R_pay"):   ghgraph.KindRepository,
				ghKey("repository", "R_tools"): ghgraph.KindRepository,
			},
			"identity": {
				ghKey("app_installation", "inst-gh"): ghgraph.KindAppInstallation,
				ghKey("deploy_key", "10"):            ghgraph.KindDeployKey,
				ghKey("deploy_key", "11"):            ghgraph.KindDeployKey,
				ghKey("deploy_key", "20"):            ghgraph.KindDeployKey,
			},
			"workload": {
				ghKey("copilot_agent", "R_pay", "cp-1"):                           ghgraph.KindCopilotAgent,
				ghKey("actions_workflow", "R_pay", ".github/workflows/agent.yml"): ghgraph.KindActionsWorkflow,
				ghKey("actions_workflow", "R_tools", ".github/workflows/bot.yml"): ghgraph.KindActionsWorkflow,
			},
			"statement": {
				ghKey("deploy_key_grant", "10"): "deploy_key",
				ghKey("deploy_key_grant", "11"): "deploy_key",
				ghKey("deploy_key_grant", "20"): "deploy_key",
			},
		}
		for name, got := range map[string]map[string]ghRow{"resource": res, "identity": ids, "workload": wls, "statement": sts} {
			if len(got) != len(want[name]) {
				t.Fatalf("%s: %d keyed rows, want %d: %v", name, len(got), len(want[name]), got)
			}
			for k, kind := range want[name] {
				r, ok := got[k]
				if !ok || r.Kind != kind || r.Lifecycle != models.IGALifecycleActive {
					t.Fatalf("%s %q: got %+v, want one active %s", name, k, r, kind)
				}
			}
		}

		// Scope keys, and the repository facts the contract names.
		pay := ghAttrs(t, res[ghKey("repository", "R_pay")].Attrs)
		tools := ghAttrs(t, res[ghKey("repository", "R_tools")].Attrs)
		if pay["full_name"] != "acme/payments" || pay["node_id"] != "R_pay" || pay["default_branch"] != "main" ||
			pay["archived"] != false || tools["archived"] != true || tools["default_branch"] != "trunk" {
			t.Fatalf("repository attrs: %v / %v", pay, tools)
		}
		for name, rows := range map[string]map[string]ghRow{"resource": res, "identity": ids, "workload": wls} {
			for k, r := range rows {
				a := ghAttrs(t, r.Attrs)
				if a["scope_kind"] != "github_org" || a["scope_id"] != "acct" || a["scope_label"] != "acct" {
					t.Fatalf("%s %q: scope keys %v", name, k, a)
				}
				if _, ok := a["sub_scope"]; !ok {
					t.Fatalf("%s %q: no sub_scope key", name, k)
				}
			}
		}
		if a := ghAttrs(t, ids[ghKey("app_installation", "inst-gh")].Attrs); a["sub_scope"] != nil {
			t.Fatalf("the installation is not in a repository, sub_scope = %v", a["sub_scope"])
		}
		if a := ghAttrs(t, wls[ghKey("copilot_agent", "R_pay", "cp-1")].Attrs); a["sub_scope"] != "acme/payments" {
			t.Fatalf("copilot agent sub_scope = %v", a["sub_scope"])
		}

		// The readable native id the inventory shows, per kind.
		for _, c := range []struct {
			rows map[string]ghRow
			key  string
			want string
		}{
			{res, ghKey("repository", "R_pay"), "acme/payments"},
			{ids, ghKey("app_installation", "inst-gh"), "inst-gh"},
			{ids, ghKey("deploy_key", "20"), "acme/tools/keys/20"},
			{wls, ghKey("copilot_agent", "R_pay", "cp-1"), "acme/payments/triage-agent"},
			{wls, ghKey("actions_workflow", "R_tools", ".github/workflows/bot.yml"), "acme/tools/.github/workflows/bot.yml"},
		} {
			if got := ghAttrs(t, c.rows[c.key].Attrs)["native_id"]; got != c.want {
				t.Fatalf("%q native_id = %v, want %q", c.key, got, c.want)
			}
		}

		// Statements say GitHub's own right.
		for k, right := range map[string]string{"10": "read", "11": "write", "20": "read"} {
			var native string
			db.Raw(`SELECT native_rights->>'contents' FROM iga_entitlements WHERE id = ?`,
				sts[ghKey("deploy_key_grant", k)].ID).Scan(&native)
			if native != right {
				t.Fatalf("deploy key %s: native contents %q, want %q", k, native, right)
			}
		}

		// Every node is supported by the integration, confirmed by this run.
		for col, rows := range map[string]map[string]ghRow{
			"resource_id": res, "identity_account_id": ids, "workload_id": wls, "entitlement_id": sts,
		} {
			for _, r := range rows {
				requireSupport(t, db, ws, col, r.ID, integ.ID, run, models.RelCurrent)
			}
		}

		// One grant per deploy key: key -> statement, ON the repository.
		edges := ghEdges(t, db, ws)
		if len(edges) != 3 {
			t.Fatalf("%d keyed grants, want 3: %+v", len(edges), edges)
		}
		for _, e := range edges {
			keyID := e.SourceKey[strings.LastIndex(e.SourceKey, ghgraph.Sep)+1:]
			repo := "R_pay"
			if keyID == "20" {
				repo = "R_tools"
			}
			if e.State != models.RelCurrent || e.SubjectIdentityID != ids[ghKey("deploy_key", keyID)].ID ||
				e.EntitlementID != sts[ghKey("deploy_key_grant", keyID)].ID ||
				e.ResourceID != res[ghKey("repository", repo)].ID ||
				e.IntegrationID != integ.ID || e.LastConfirmedScanRunID != run ||
				e.CalculationState != "complete" || e.EffectiveConclusion != "effective" {
				t.Fatalf("grant %s: %+v", e.SourceKey, e)
			}
		}

		// Keyed credentials, one per key, held by its identity.
		var creds []struct {
			SourceKey         string
			IdentityAccountID uuid.UUID
			Lifecycle         string
		}
		db.Raw(`SELECT source_key, identity_account_id, lifecycle FROM iga_credentials
		         WHERE workspace_id = ? AND provider = 'github' AND source_key <> '' ORDER BY source_key`, ws).Scan(&creds)
		if len(creds) != 3 {
			t.Fatalf("%d keyed credentials, want 3", len(creds))
		}
		for _, c := range creds {
			keyID := c.SourceKey[strings.LastIndex(c.SourceKey, ghgraph.Sep)+1:]
			if c.Lifecycle != "active" || c.IdentityAccountID != ids[ghKey("deploy_key", keyID)].ID {
				t.Fatalf("credential %q: %+v", c.SourceKey, c)
			}
		}
	}
	check(run1)

	// The legacy writer is untouched: it still writes its own unkeyed rows,
	// one installation per scope, as it always did.
	legacyAfter := countRows(db, `SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = ? AND source_key = ''`, ws)
	if legacyAfter <= legacyBefore {
		t.Fatalf("the legacy writer wrote no identities (%d -> %d)", legacyBefore, legacyAfter)
	}

	// Second scan: nothing duplicates, everything is reconfirmed by run 2 --
	// including the workflows, whose unchanged blobs were skipped, not fetched.
	run2, rep2 := ghScan(t, mgr, ws, integ.ID)
	if rep2.BlobsSkipped == 0 {
		t.Fatal("setup: the second scan was meant to skip unchanged workflow blobs")
	}
	check(run2)
	if rep2.Graph.Reconcile == nil || rep2.Graph.Reconcile.SupportEnded != 0 || rep2.Graph.Reconcile.ObjectsRetired != 0 {
		t.Fatalf("an unchanged rescan ended or retired something: %+v", rep2.Graph.Reconcile)
	}
	if got := countRows(db, `SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = ? AND source_key = ''`, ws); got <= legacyAfter {
		t.Fatalf("the legacy writer's own duplication changed (%d -> %d); it must be left exactly as it was", legacyAfter, got)
	}
}

// TestUDGitHubDroppedRepositoryRetires: a repository missing from a complete
// scan's listing has its rows ended and retired, and nothing else moves.
func TestUDGitHubDroppedRepositoryRetires(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ud-gh-drop")
	fx := ghGraphFixture()
	mgr := ghManager(db, fx, ghGateOn(), "inst-gh-drop")
	integ := verifiedIntegration(t, mgr, ws, "inst-gh-drop")
	ghScan(t, mgr, ws, integ.ID)

	fx.Scopes = fx.Scopes[:1] // acme/tools is no longer granted
	run2, rep := ghScan(t, mgr, ws, integ.ID)

	gone := map[string]string{
		ghKey("repository", "R_tools"):                                    "iga_resources",
		ghKey("deploy_key", "20"):                                         "iga_identity_accounts",
		ghKey("deploy_key_grant", "20"):                                   "iga_entitlements",
		ghKey("actions_workflow", "R_tools", ".github/workflows/bot.yml"): "iga_workload",
	}
	for key, table := range gone {
		var rows []struct {
			ID            uuid.UUID
			Lifecycle     string
			RetiredReason string
		}
		db.Raw(`SELECT id, lifecycle, retired_reason FROM `+table+` WHERE workspace_id = ? AND source_key = ?`, ws, key).Scan(&rows)
		if len(rows) != 1 || rows[0].Lifecycle != models.IGALifecycleRetired || rows[0].RetiredReason != models.RetiredUnsupported {
			t.Fatalf("%s %q after the repository was dropped: %+v, want one row retired unsupported", table, key, rows)
		}
		col := map[string]string{"iga_resources": "resource_id", "iga_identity_accounts": "identity_account_id",
			"iga_entitlements": "entitlement_id", "iga_workload": "workload_id"}[table]
		s := supportOf(t, db, ws, col, rows[0].ID)
		if len(s) != 1 || s[0].State != models.RelEnded || s[0].EndedReason != models.EndedNotSeen {
			t.Fatalf("%q support: %+v, want ended not_seen", key, s)
		}
	}
	for _, e := range ghEdges(t, db, ws) {
		ended := strings.HasSuffix(e.SourceKey, ghgraph.Sep+"20")
		if ended != (e.State == models.RelEnded) {
			t.Fatalf("grant %q state %q after dropping acme/tools", e.SourceKey, e.State)
		}
	}
	var lc string
	db.Raw(`SELECT lifecycle FROM iga_credentials WHERE workspace_id = ? AND source_key = ?`,
		ws, ghgraph.DeployKeyCredentialKey("github.com", "20")).Scan(&lc)
	if lc != "revoked" {
		t.Fatalf("the dropped deploy key's credential is %q, want revoked", lc)
	}

	// Everything in acme/payments, and the installation, still stands.
	for _, k := range []string{ghKey("repository", "R_pay")} {
		if r := ghNodes(t, db, "iga_resources", "resource_kind", ws)[k]; r.Lifecycle != models.IGALifecycleActive {
			t.Fatalf("%q: %+v", k, r)
		}
	}
	ids := ghNodes(t, db, "iga_identity_accounts", "account_kind", ws)
	for _, k := range []string{ghKey("app_installation", "inst-gh-drop"), ghKey("deploy_key", "10"), ghKey("deploy_key", "11")} {
		requireSupport(t, db, ws, "identity_account_id", ids[k].ID, integ.ID, run2, models.RelCurrent)
	}
	if rep.Graph.Reconcile.ObjectsRetired != 4 {
		t.Fatalf("retired %d objects, want 4 (repository, key, statement, workflow)", rep.Graph.Reconcile.ObjectsRetired)
	}

	// Legacy GitHub rows are never retired by the graph -- none of them has
	// support, which is exactly why the reconciler must not look at them.
	if n := countRows(db, `SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = ? AND source_key = '' AND lifecycle <> 'active'`, ws) +
		countRows(db, `SELECT count(*) FROM iga_resources WHERE workspace_id = ? AND source_key = '' AND lifecycle <> 'active'`, ws) +
		countRows(db, `SELECT count(*) FROM iga_entitlements WHERE workspace_id = ? AND source_key = '' AND lifecycle <> 'active'`, ws) +
		countRows(db, `SELECT count(*) FROM iga_access_edges WHERE workspace_id = ? AND source_key = '' AND state <> 'current'`, ws); n != 0 {
		t.Fatalf("%d legacy GitHub rows were changed by the graph reconciler", n)
	}

	// Granted again: a new live incarnation, the retired one kept as history.
	fx.Scopes = ghGraphFixture().Scopes
	run3, _ := ghScan(t, mgr, ws, integ.ID)
	res := ghNodes(t, db, "iga_resources", "resource_kind", ws)
	live := res[ghKey("repository", "R_tools")]
	if live.Lifecycle != models.IGALifecycleActive || len(res) != 3 {
		t.Fatalf("re-granted repository: live %+v among %d rows", live, len(res))
	}
	requireSupport(t, db, ws, "resource_id", live.ID, integ.ID, run3, models.RelCurrent)
}

// failingListing is a provider whose repository listing fails: the scan
// itself fails, before reading anything.
type failingListing struct{ *services.FixtureProvider }

func (f failingListing) ListScopes(context.Context, services.ProviderContext) ([]services.ProviderScope, error) {
	return nil, errors.New("503 listing unavailable")
}

// TestUDGitHubPartialScanOnlyStales: a repository the scan could not read, and
// a scan that failed outright, mark what they could not confirm STALE -- never
// ended, never retired -- and a later complete scan makes it current again.
func TestUDGitHubPartialScanOnlyStales(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ud-gh-partial")
	fx := ghGraphFixture()
	mgr := ghManager(db, fx, ghGateOn(), "inst-gh-partial")
	integ := verifiedIntegration(t, mgr, ws, "inst-gh-partial")
	run1, _ := ghScan(t, mgr, ws, integ.ID)

	// acme/payments now answers 403 to everything inside it, AND its write key
	// is gone. The scan cannot tell those apart, so neither may be ended.
	fx.FailScopes["R_pay"] = errors.New("403 permission denied for repository")
	fx.Grants["R_pay"] = fx.Grants["R_pay"][:1]
	run2, rep := ghScan(t, mgr, ws, integ.ID)
	if rep.Graph.Reconcile.SupportEnded != 0 || rep.Graph.Reconcile.EdgesEnded != 0 || rep.Graph.Reconcile.ObjectsRetired != 0 {
		t.Fatalf("a partial reading ended something: %+v", rep.Graph.Reconcile)
	}

	ids := ghNodes(t, db, "iga_identity_accounts", "account_kind", ws)
	wls := ghNodes(t, db, "iga_workload", "runtime_kind", ws)
	sts := ghNodes(t, db, "iga_entitlements", "native_grant_kind", ws)
	res := ghNodes(t, db, "iga_resources", "resource_kind", ws)
	stale := []struct {
		col string
		id  uuid.UUID
	}{
		{"identity_account_id", ids[ghKey("deploy_key", "10")].ID},
		{"identity_account_id", ids[ghKey("deploy_key", "11")].ID},
		{"entitlement_id", sts[ghKey("deploy_key_grant", "11")].ID},
		{"workload_id", wls[ghKey("copilot_agent", "R_pay", "cp-1")].ID},
		{"workload_id", wls[ghKey("actions_workflow", "R_pay", ".github/workflows/agent.yml")].ID},
	}
	for _, s := range stale {
		if s.id == uuid.Nil {
			t.Fatalf("a node the partial scan could not see is no longer live: %+v", s)
		}
		requireSupport(t, db, ws, s.col, s.id, integ.ID, run1, models.RelStale)
	}
	// What the scan DID read stays current: the listing still returned the
	// repository, and acme/tools was read in full.
	requireSupport(t, db, ws, "resource_id", res[ghKey("repository", "R_pay")].ID, integ.ID, run2, models.RelCurrent)
	requireSupport(t, db, ws, "identity_account_id", ids[ghKey("deploy_key", "20")].ID, integ.ID, run2, models.RelCurrent)
	for _, e := range ghEdges(t, db, ws) {
		want := models.RelStale
		if strings.HasSuffix(e.SourceKey, ghgraph.Sep+"20") {
			want = models.RelCurrent
		}
		if e.State != want {
			t.Fatalf("grant %q: %q, want %q", e.SourceKey, e.State, want)
		}
	}

	// A scan that fails outright stales everything still current; it ends
	// nothing.
	failing := ghManager(db, failingListing{fx}, ghGateOn(), "inst-gh-partial")
	run3, err := failing.StartScan(ws, integ.ID, models.ScanModeFull, "tester")
	if err != nil {
		t.Fatalf("start failing scan: %v", err)
	}
	if _, err := failing.RunScan(context.Background(), ws, run3.ID); err == nil {
		t.Fatal("setup: the failing listing should fail the scan")
	}
	if n := countRows(db, `SELECT count(*) FROM iga_object_support WHERE workspace_id = ? AND integration_id = ? AND state <> 'stale'`, ws, integ.ID); n != 0 {
		t.Fatalf("after a failed scan %d support rows are not stale", n)
	}
	if n := countRows(db, `SELECT count(*) FROM iga_access_edges WHERE workspace_id = ? AND integration_id = ? AND state <> 'stale'`, ws, integ.ID); n != 0 {
		t.Fatalf("after a failed scan %d grants are not stale", n)
	}
	if n := countRows(db, `SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = ? AND source_key <> '' AND lifecycle <> 'active'`, ws); n != 0 {
		t.Fatalf("a failed scan retired %d identities", n)
	}

	// Readable again: one complete scan revives the stale rows, and ends only
	// the key that really is gone.
	delete(fx.FailScopes, "R_pay")
	run4, _ := ghScan(t, mgr, ws, integ.ID)
	requireSupport(t, db, ws, "identity_account_id", ids[ghKey("deploy_key", "10")].ID, integ.ID, run4, models.RelCurrent)
	requireSupport(t, db, ws, "workload_id", wls[ghKey("copilot_agent", "R_pay", "cp-1")].ID, integ.ID, run4, models.RelCurrent)
	requireSupport(t, db, ws, "identity_account_id", ids[ghKey("deploy_key", "11")].ID, integ.ID, run4, models.RelEnded)
	if r := ghNodes(t, db, "iga_identity_accounts", "account_kind", ws)[ghKey("deploy_key", "11")]; r.ID != uuid.Nil {
		t.Fatalf("the removed write key is still live after a complete scan: %+v", r)
	}
}

// TestUDGitHubProjectionGateOff: with IGA_GRAPH_PROJECTION off nothing keyed
// is written, and the scan is exactly the legacy scan.
func TestUDGitHubProjectionGateOff(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ud-gh-off")
	mgr := ghManager(db, ghGraphFixture(), ghGateOff(), "inst-gh-off")
	integ := verifiedIntegration(t, mgr, ws, "inst-gh-off")
	_, rep := ghScan(t, mgr, ws, integ.ID)
	if rep.Graph != nil {
		t.Fatalf("switch off, yet the scan reports a graph projection: %+v", rep.Graph)
	}
	for _, table := range []string{"iga_identity_accounts", "iga_resources", "iga_entitlements", "iga_access_edges", "iga_credentials", "iga_workload"} {
		if n := countRows(db, `SELECT count(*) FROM `+table+` WHERE workspace_id = ? AND source_key <> ''`, ws); n != 0 {
			t.Fatalf("switch off, yet %s has %d keyed rows", table, n)
		}
	}
	if n := countRows(db, `SELECT count(*) FROM iga_object_support WHERE workspace_id = ?`, ws); n != 0 {
		t.Fatalf("switch off, yet %d support rows", n)
	}
	if n := countRows(db, `SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = ? AND source_key = ''`, ws); n == 0 {
		t.Fatal("setup: the legacy scan wrote nothing")
	}
}

// legacyView is everything the legacy GitHub screens read for a workspace,
// with ids and times removed so two workspaces compare.
func legacyView(t *testing.T, db *gorm.DB, mgr services.IGAManager, ws uuid.UUID) string {
	t.Helper()
	repo := repositories.NewIGARepository(db)
	page, err := mgr.ListIdentityAccountsPage(ws, "", 200)
	if err != nil {
		t.Fatalf("identity page: %v", err)
	}
	var lines []string
	for _, a := range page.Items {
		if a.SourceKey != "" {
			t.Fatalf("the legacy identity list returned a keyed row: %+v", a)
		}
		lines = append(lines, fmt.Sprintf("identity %s|%s|%s|%s|%s", a.DisplayName, a.AccountKind, a.IdentityBacking, a.Provider, a.Lifecycle))
		creds, err := repo.ListCredentialsFor(ws, a.ID)
		if err != nil {
			t.Fatalf("credentials: %v", err)
		}
		for _, c := range creds {
			lines = append(lines, fmt.Sprintf("  credential %s %s|%s|%s|%s", a.DisplayName, c.CredentialType, c.KeyIdentifier, c.Lifecycle, c.SourceKey))
		}
		paths, err := repo.ListAccessPaths(ws, a.ID)
		if err != nil {
			t.Fatalf("access paths: %v", err)
		}
		for _, p := range paths {
			l := fmt.Sprintf("  path %s %s|%s|%s|%s", a.DisplayName, p.Edge.PathKind, p.Edge.CalculationState, p.Edge.EffectiveConclusion, p.Edge.SourceKey)
			if p.Entitlement != nil {
				l += fmt.Sprintf("|ent %s %s %s", p.Entitlement.NativeGrantKind, p.Entitlement.NativeRights, p.Entitlement.SourceKey)
			}
			if p.Resource != nil {
				l += fmt.Sprintf("|res %s %s %s", p.Resource.ResourceKind, p.Resource.DisplayName, p.Resource.SourceKey)
			}
			lines = append(lines, l)
		}
	}
	agents, _, err := mgr.ListAgents(ws, "", 200, 0)
	if err != nil {
		t.Fatalf("agents: %v", err)
	}
	for _, ag := range agents {
		paths, sum, err := mgr.AgentAccessPaths(ws, ag.ID)
		if err != nil {
			t.Fatalf("agent paths: %v", err)
		}
		lines = append(lines, fmt.Sprintf("agent %s %s paths=%d state=%s", ag.DisplayName, ag.Classification, len(paths), sum.State))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// TestUDGitHubLegacyListsUnchanged: with the projection on, every legacy
// GitHub reader answers exactly what it answers with it off -- the keyed rows
// are there, and none of them appears.
func TestUDGitHubLegacyListsUnchanged(t *testing.T) {
	db := igaDB(t)
	on := newWorkspace(t, db, "ud-gh-legacy-on")
	off := newWorkspace(t, db, "ud-gh-legacy-off")
	mgrOn := ghManager(db, ghGraphFixture(), ghGateOn(), "inst-gh-legacy-on", "inst-gh-legacy-off")
	mgrOff := ghManager(db, ghGraphFixture(), ghGateOff(), "inst-gh-legacy-on", "inst-gh-legacy-off")
	integOn := verifiedIntegration(t, mgrOn, on, "inst-gh-legacy-on")
	integOff := verifiedIntegration(t, mgrOff, off, "inst-gh-legacy-off")
	for i := 0; i < 2; i++ {
		ghScan(t, mgrOn, on, integOn.ID)
		ghScan(t, mgrOff, off, integOff.ID)
	}
	if n := countRows(db, `SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = ? AND source_key <> ''`, on); n == 0 {
		t.Fatal("setup: the projection wrote no keyed identities")
	}

	gotOn, gotOff := legacyView(t, db, mgrOn, on), legacyView(t, db, mgrOff, off)
	if gotOn != gotOff {
		t.Fatalf("legacy GitHub readers differ with the projection on:\non:\n%s\noff:\n%s", gotOn, gotOff)
	}
	if gotOn == "" {
		t.Fatal("setup: the legacy readers returned nothing to compare")
	}

	// Asked directly about a keyed node, the legacy readers know nothing.
	repo := repositories.NewIGARepository(db)
	key := ghNodes(t, db, "iga_identity_accounts", "account_kind", on)[ghKey("deploy_key", "10")]
	if edges, err := repo.ListAccessEdges(on, key.ID); err != nil || len(edges) != 0 {
		t.Fatalf("legacy ListAccessEdges for a keyed identity: %d (%v)", len(edges), err)
	}
	if creds, err := repo.ListCredentialsFor(on, key.ID); err != nil || len(creds) != 0 {
		t.Fatalf("legacy ListCredentialsFor for a keyed identity: %d (%v)", len(creds), err)
	}
	if paths, err := repo.ListAccessPaths(on, key.ID); err != nil || len(paths) != 0 {
		t.Fatalf("legacy ListAccessPaths for a keyed identity: %d (%v)", len(paths), err)
	}
}

/* ------------------------------ repo scanner ------------------------------ */

// ghRepoScanFixture: two repositories, each declaring one agent workflow.
func ghRepoScanFixture() *services.FixtureProvider {
	return &services.FixtureProvider{
		ProviderName: "github",
		Scopes: []services.ProviderScope{
			{Kind: "repository", NativeID: "R_a", DisplayName: "acme/alpha", DefaultBranch: "main"},
			{Kind: "repository", NativeID: "R_b", DisplayName: "acme/beta", DefaultBranch: "main"},
		},
		Trees: map[string][]services.TreeEntry{
			"R_a": {{Path: ".github/workflows/agent.yml", SHA: "sha-a", Size: int64(len(ghWorkflow))}},
			"R_b": {{Path: ".github/workflows/agent.yml", SHA: "sha-b", Size: int64(len(ghWorkflow))}},
		},
		Blobs: map[string][]byte{
			"R_a:.github/workflows/agent.yml": []byte(ghWorkflow),
			"R_b:.github/workflows/agent.yml": []byte(ghWorkflow),
		},
		FailScopes: map[string]error{},
	}
}

// TestUDGitHubRepoScanDeclaredAgents: repo-scan sightings become
// github_declared_agent workloads supported by their discovery source, upserted
// by fingerprint; a complete run that no longer reports one retires it, and an
// incomplete run only stales.
func TestUDGitHubRepoScanDeclaredAgents(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ud-gh-reposcan")
	runs := repositories.NewDiscoveryScanRunRepository(db)
	fx := ghRepoScanFixture()
	srcID := newScanSource(t, db, ws, "acme-ud", map[string]interface{}{
		"installation_id": "777",
		"repositories":    map[string]interface{}{"mode": "all"},
	})
	worker := services.NewDiscoveryScanWorkerWithScanner(db,
		services.NewGitHubRepoScannerWithProvider(db, fx)).WithGraphProjection(ghGateOn())
	scan := func() *models.DiscoveryScanRun {
		t.Helper()
		run, err := services.EnqueueGitHubScan(db, ws, srcID, "alice")
		if err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		return drain(t, worker, runs, ws, run.ID, 10)
	}
	keyFor := func(repo string) string {
		return ghgraph.DeclaredAgentKey("github.com", "gh:"+repo+":.github/workflows/agent.yml")
	}
	workloads := func() map[string]ghRow { return ghNodes(t, db, "iga_workload", "runtime_kind", ws) }
	requireDeclared := func(key, state string) ghRow {
		t.Helper()
		w, ok := workloads()[key]
		if !ok || w.Kind != ghgraph.KindDeclaredAgent {
			t.Fatalf("no live declared workload %q: %v", key, workloads())
		}
		s := supportOf(t, db, ws, "workload_id", w.ID)
		if len(s) != 1 || s[0].DiscoverySourceID == nil || *s[0].DiscoverySourceID != srcID ||
			s[0].IntegrationID != nil || s[0].ConnectorID != nil || s[0].LastConfirmedSweepID != nil || s[0].State != state {
			t.Fatalf("declared workload %q support: %+v, want one %s row of source %s", key, s, state, srcID)
		}
		return w
	}

	first := scan()
	if first.Status != models.ScanRunSucceeded || !first.Complete {
		t.Fatalf("setup: run 1 %s complete=%v (%s)", first.Status, first.Complete, first.Error)
	}
	var found int64
	db.Raw(`SELECT count(*) FROM discovered_agents WHERE workspace_id = ? AND discovery_source_id = ? AND source = 'repo_scan'`, ws, srcID).Scan(&found)
	if found != 2 || len(workloads()) != 2 {
		t.Fatalf("%d discovered agents and %d declared workloads, want 2 and 2", found, len(workloads()))
	}
	a := requireDeclared(keyFor("R_a"), models.RelCurrent)
	attrs := ghAttrs(t, a.Attrs)
	if attrs["scope_kind"] != "github_org" || attrs["scope_id"] != "acme" || attrs["sub_scope"] != "acme/alpha" ||
		attrs["fingerprint"] != "gh:R_a:.github/workflows/agent.yml" || attrs["evidence_mode"] != "declared" ||
		attrs["native_id"] != "acme/alpha/.github/workflows/agent.yml" {
		t.Fatalf("declared workload attrs: %v", attrs)
	}
	requireDeclared(keyFor("R_b"), models.RelCurrent)

	// An unchanged rescan: no duplicate, still current.
	if second := scan(); second.Status != models.ScanRunSucceeded || !second.Complete {
		t.Fatalf("setup: run 2 %s complete=%v", second.Status, second.Complete)
	}
	if len(workloads()) != 2 {
		t.Fatalf("a rescan duplicated declared workloads: %v", workloads())
	}
	requireDeclared(keyFor("R_a"), models.RelCurrent)

	// acme/alpha unreadable: the run is incomplete, so alpha's agent -- which
	// it did not report -- is only stale.
	fx.FailScopes["R_a"] = errors.New("403 permission denied for repository")
	if third := scan(); third.Complete {
		t.Fatal("setup: run 3 should be incomplete")
	}
	requireDeclared(keyFor("R_a"), models.RelStale)
	requireDeclared(keyFor("R_b"), models.RelCurrent)

	// acme/alpha readable again but beta no longer granted, in a COMPLETE run:
	// alpha revives, beta's agent retires.
	delete(fx.FailScopes, "R_a")
	fx.Scopes = fx.Scopes[:1]
	if fourth := scan(); fourth.Status != models.ScanRunSucceeded || !fourth.Complete {
		t.Fatalf("setup: run 4 %s complete=%v", fourth.Status, fourth.Complete)
	}
	requireDeclared(keyFor("R_a"), models.RelCurrent)
	var gone []struct {
		ID            uuid.UUID
		Lifecycle     string
		RetiredReason string
	}
	db.Raw(`SELECT id, lifecycle, retired_reason FROM iga_workload WHERE workspace_id = ? AND source_key = ?`, ws, keyFor("R_b")).Scan(&gone)
	if len(gone) != 1 || gone[0].Lifecycle != models.IGALifecycleRetired || gone[0].RetiredReason != models.RetiredUnsupported {
		t.Fatalf("beta's declared agent after a complete run no longer reported it: %+v", gone)
	}
	if s := supportOf(t, db, ws, "workload_id", gone[0].ID); len(s) != 1 || s[0].State != models.RelEnded {
		t.Fatalf("beta's support: %+v, want ended", s)
	}
}

// TestUDGitHubRepoScanGateOff: with the switch off, a repo-scan run writes no
// graph rows at all.
func TestUDGitHubRepoScanGateOff(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ud-gh-reposcan-off")
	runs := repositories.NewDiscoveryScanRunRepository(db)
	srcID := newScanSource(t, db, ws, "acme-ud-off", map[string]interface{}{
		"installation_id": "778",
		"repositories":    map[string]interface{}{"mode": "all"},
	})
	worker := services.NewDiscoveryScanWorkerWithScanner(db,
		services.NewGitHubRepoScannerWithProvider(db, ghRepoScanFixture())).WithGraphProjection(ghGateOff())
	run, err := services.EnqueueGitHubScan(db, ws, srcID, "alice")
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if done := drain(t, worker, runs, ws, run.ID, 10); done.Status != models.ScanRunSucceeded || done.SightingsNew == 0 {
		t.Fatalf("setup: %s new=%d", done.Status, done.SightingsNew)
	}
	if n := countRows(db, `SELECT count(*) FROM iga_workload WHERE workspace_id = ?`, ws) +
		countRows(db, `SELECT count(*) FROM iga_object_support WHERE workspace_id = ?`, ws); n != 0 {
		t.Fatalf("switch off, yet %d graph rows", n)
	}
}
