package integration

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// GCP-4: trust edges, derived from the stored bindings. GCP-0 scenarios 10
// (impersonation, project-level Token Creator stored once), 13 (GitHub OIDC
// provider, unconditioned provider) and 14 (GKE Workload Identity, both forms).

const (
	gcp4Tester  = "user:tester@example.com"
	gcp4GitHub  = "principalSet://iam.googleapis.com/projects/" + gcp3Number + "/locations/global/workloadIdentityPools/iga-github/attribute.repository/o/r"
	gcp4Broad   = "principalSet://iam.googleapis.com/projects/" + gcp3Number + "/locations/global/workloadIdentityPools/broad/*"
	gcp4Direct  = "principal://iam.googleapis.com/projects/" + gcp3Number + "/locations/global/workloadIdentityPools/" + gcp3Project + ".svc.id.goog/subject/ns/iga/sa/direct-ksa"
	gcp4AppSAAt = "//iam.googleapis.com/projects/" + gcp3Project + "/serviceAccounts/1001"
)

func gcp4Fixture(f *fakeGCPDiscovery) {
	gcp3Fixture(f)
	f.predefinedRoles["roles/iam.serviceAccountTokenCreator"] = []string{"iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.signJwt"}
	f.predefinedRoles["roles/iam.serviceAccountUser"] = []string{"iam.serviceAccounts.actAs"}
	f.predefinedRoles["roles/iam.workloadIdentityUser"] = []string{"iam.serviceAccounts.getAccessToken"}
	// Scenario 10a: project-level Token Creator for a user.
	f.policies[0].bindings = append(f.policies[0].bindings,
		fakeGCPBinding{role: "roles/iam.serviceAccountTokenCreator", members: []string{gcp4Tester}},
		// Scenario 13b-ish: an unconditioned pool holding a role directly.
		fakeGCPBinding{role: "roles/viewer", members: []string{gcp4Broad}},
		// Scenario 14b: a direct GKE principal on the project.
		fakeGCPBinding{role: "roles/storage.objectViewer", members: []string{gcp4Direct}},
	)
	// The policy ON app-sa (Cloud Asset returns it as a ServiceAccount asset).
	f.policies = append(f.policies, fakeGCPPolicy{
		resource: gcp4AppSAAt, assetType: "iam.googleapis.com/ServiceAccount",
		project: "projects/" + gcp3Number, org: "organizations/7",
		bindings: []fakeGCPBinding{
			// Scenario 10b: SA-level Service Account User.
			{role: "roles/iam.serviceAccountUser", members: []string{"serviceAccount:" + gcp3Deployer}},
			// Scenario 13a: a GitHub workflow federating into app-sa.
			{role: "roles/iam.workloadIdentityUser", members: []string{gcp4GitHub}},
			// Scenario 14a: KSA -> GSA.
			{role: "roles/iam.workloadIdentityUser", members: []string{"serviceAccount:" + gcp3Project + ".svc.id.goog[iga/app-ksa]"}},
		},
	})
	f.wifPools[gcp3Project] = []fakeGCPPool{
		{id: "iga-github", providers: []fakeGCPProvider{{id: "github", issuer: "https://token.actions.githubusercontent.com", condition: "assertion.repository=='o/r'"}}},
		{id: "broad", providers: []fakeGCPProvider{{id: "gitlab-broad", issuer: "https://gitlab.com"}}},
	}
}

type gcp4Edge struct {
	models.CloudAssumeEdge
	attrs  models.GCPAssumeEdgeAttrs
	target models.CloudIdentity
}

func gcp4Edges(t *testing.T, db *gorm.DB, ws, connectorID uuid.UUID) []gcp4Edge {
	t.Helper()
	var rows []models.CloudAssumeEdge
	if err := db.Where("workspace_id = ? AND connector_id = ?", ws, connectorID).Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	out := make([]gcp4Edge, 0, len(rows))
	for _, r := range rows {
		e := gcp4Edge{CloudAssumeEdge: r}
		if err := json.Unmarshal(r.Attrs, &e.attrs); err != nil {
			t.Fatalf("attrs: %v", err)
		}
		if err := db.First(&e.target, "id = ?", r.IdentityID).Error; err != nil {
			t.Fatalf("target: %v", err)
		}
		out = append(out, e)
	}
	return out
}

func gcp4One(t *testing.T, edges []gcp4Edge, what string, pick func(gcp4Edge) bool) gcp4Edge {
	t.Helper()
	var got []gcp4Edge
	for _, e := range edges {
		if pick(e) {
			got = append(got, e)
		}
	}
	if len(got) != 1 {
		t.Fatalf("%s: %d edges, want 1", what, len(got))
	}
	return got[0]
}

func gcp4Scan(t *testing.T, db *gorm.DB, f *fakeGCPDiscovery, ws, connectorID uuid.UUID) models.ScanCoverage {
	t.Helper()
	snap, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return snap.Coverage
}

func TestGCP4_TrustEdges(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp4-edges")
	f := newFakeGCPDiscovery()
	defer f.Close()
	gcp4Fixture(f)
	connectorID := gcpScanConnector(t, db, ws, gcp3Project)
	cov := gcp4Scan(t, db, f, ws, connectorID)
	if got := cov.Surfaces["edges"]; got.State != models.CloudCoverageReached || got.Count == 0 {
		t.Fatalf("edges = %+v", got)
	}
	if cov.Status != models.ScanStatusComplete {
		t.Fatalf("status %q: %+v", cov.Status, cov.Surfaces)
	}
	edges := gcp4Edges(t, db, ws, connectorID)

	// 10a: project-level Token Creator is ONE edge, on the project row, via_scope.
	tc := gcp4One(t, edges, "tester token creator", func(e gcp4Edge) bool { return e.Subject == gcp4Tester })
	if tc.target.Kind != models.CloudIdentityGCPProject || tc.attrs.ViaScope != "projects/"+gcp3Project ||
		tc.Mechanism != models.AssumeMechanismGCPImpersonation || tc.SubjectKind != models.AssumeSubjectIdentity {
		t.Fatalf("token creator edge = %+v %+v (target %s)", tc.CloudAssumeEdge, tc.attrs, tc.target.Kind)
	}
	if len(tc.attrs.Capabilities) != 1 || tc.attrs.Capabilities[0] != "mint_token" {
		t.Fatalf("capabilities = %v", tc.attrs.Capabilities)
	}

	// 10b: deployer-sa -> app-sa via serviceAccountUser, on app-sa itself.
	su := gcp4One(t, edges, "deployer on app-sa", func(e gcp4Edge) bool {
		return e.Subject == "serviceAccount:"+gcp3Deployer && e.attrs.ViaScope == ""
	})
	if su.target.Kind != models.CloudIdentityGCPServiceAccount || su.target.Name == "" {
		t.Fatalf("SA-level edge target = %+v", su.target)
	}

	// 13a: GitHub workflow -> app-sa, ci_pipeline, issuer host, conditioned.
	gh := gcp4One(t, edges, "github into app-sa", func(e gcp4Edge) bool {
		return e.Subject == gcp4GitHub && e.target.Kind == models.CloudIdentityGCPServiceAccount
	})
	if gh.SubjectKind != models.AssumeSubjectCIPipeline || gh.Issuer == nil || *gh.Issuer != "token.actions.githubusercontent.com" ||
		gh.Mechanism != models.AssumeMechanismOIDCFederation || gh.attrs.Unconditioned || gh.attrs.AttributeCondition == "" {
		t.Fatalf("github edge = %+v %+v", gh.CloudAssumeEdge, gh.attrs)
	}

	// 13: a provider without a condition is flagged unconditioned.
	broad := gcp4One(t, edges, "broad pool principal", func(e gcp4Edge) bool { return e.attrs.Pool == "broad" })
	if !broad.attrs.Unconditioned || broad.target.Kind != models.CloudIdentityGCPFederated {
		t.Fatalf("broad edge = %+v %+v", broad.CloudAssumeEdge, broad.attrs)
	}

	// 14a/14b: both GKE forms carry the Kubernetes connector's string.
	ksa := gcp4One(t, edges, "KSA into app-sa", func(e gcp4Edge) bool {
		return e.K8sRef != nil && *e.K8sRef == "system:serviceaccount:iga:app-ksa" && e.target.Kind == models.CloudIdentityGCPServiceAccount
	})
	if ksa.SubjectKind != models.AssumeSubjectK8sSA || ksa.Mechanism != models.AssumeMechanismGKEWorkloadIdentity {
		t.Fatalf("KSA edge = %+v", ksa.CloudAssumeEdge)
	}
	gcp4One(t, edges, "direct GKE principal", func(e gcp4Edge) bool {
		return e.K8sRef != nil && *e.K8sRef == "system:serviceaccount:iga:direct-ksa"
	})

	// Every edge links to bindings that exist.
	for _, e := range edges {
		if len(e.attrs.SourcePermissionIDs) == 0 {
			t.Fatalf("edge %s has no source binding", e.Subject)
		}
		for _, id := range e.attrs.SourcePermissionIDs {
			var n int64
			db.Model(&models.CloudPermission{}).Where("workspace_id = ? AND id = ?", ws, id).Count(&n)
			if n != 1 {
				t.Fatalf("edge %s names missing binding %s", e.Subject, id)
			}
		}
	}
}

func TestGCP4_RemovedGrantRemovesEdge(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp4-edge-reconcile")
	f := newFakeGCPDiscovery()
	defer f.Close()
	gcp4Fixture(f)
	connectorID := gcpScanConnector(t, db, ws, gcp3Project)
	gcp4Scan(t, db, f, ws, connectorID)

	// Drop the tester's Token Creator.
	var kept []fakeGCPBinding
	for _, b := range f.policies[0].bindings {
		if len(b.members) == 1 && b.members[0] == gcp4Tester {
			continue
		}
		kept = append(kept, b)
	}
	f.policies[0].bindings = kept
	cov := gcp4Scan(t, db, f, ws, connectorID)
	if cov.Counters["assume_edges_removed"] < 1 {
		t.Fatalf("counters = %+v", cov.Counters)
	}
	for _, e := range gcp4Edges(t, db, ws, connectorID) {
		if e.Subject == gcp4Tester {
			t.Fatal("an edge outlived the binding it came from")
		}
	}
}

func TestGCP4_DeniedBindingsKeepEdges(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp4-edge-denied")
	f := newFakeGCPDiscovery()
	defer f.Close()
	gcp4Fixture(f)
	connectorID := gcpScanConnector(t, db, ws, gcp3Project)
	gcp4Scan(t, db, f, ws, connectorID)
	before := len(gcp4Edges(t, db, ws, connectorID))

	f.failBindings = 403 // a real denial, not a scope refusal
	cov := gcp4Scan(t, db, f, ws, connectorID)
	if cov.Surfaces["edges"].State == models.CloudCoverageReached {
		t.Fatal("edges must not be reached when the bindings were not")
	}
	if after := len(gcp4Edges(t, db, ws, connectorID)); after != before {
		t.Fatalf("edges %d -> %d after a denied bindings read", before, after)
	}
}

func TestGCP4_EdgeListIsWorkspaceScoped(t *testing.T) {
	db := igaDB(t)
	wsA := newWorkspace(t, db, "gcp4-iso-a")
	wsB := newWorkspace(t, db, "gcp4-iso-b")
	f := newFakeGCPDiscovery()
	defer f.Close()
	gcp4Fixture(f)
	connectorA := gcpScanConnector(t, db, wsA, gcp3Project)
	gcp4Scan(t, db, f, wsA, connectorA)

	repo := repositories.NewCloudGCPReadRepository(db)
	a, n, err := repo.ListEdges(wsA, repositories.GCPEdgeFilter{})
	if err != nil || n == 0 || a[0].IdentityName == "" {
		t.Fatalf("A edges = %d, %v", n, err)
	}
	if rows, n, _ := repo.ListEdges(wsB, repositories.GCPEdgeFilter{}); n != 0 || len(rows) != 0 {
		t.Fatalf("B sees %d of A's edges", n)
	}
	if rows, n, _ := repo.ListEdges(wsB, repositories.GCPEdgeFilter{IdentityIDs: []uuid.UUID{a[0].IdentityID}, ConnectorID: &connectorA}); n != 0 || len(rows) != 0 {
		t.Fatal("B read A's edges by identity id")
	}
	// "What can this become" by subject.
	sub, err := uuid.Parse(mustSubject(t, a[0].CloudAssumeEdge))
	if err != nil {
		t.Fatalf("edge has no subject identity: %v", err)
	}
	if rows, _, _ := repo.ListEdges(wsA, repositories.GCPEdgeFilter{SubjectIdentityID: &sub}); len(rows) == 0 {
		t.Fatal("subject filter returned nothing for a known subject")
	}
	if rows, _, _ := repo.ListEdges(wsB, repositories.GCPEdgeFilter{SubjectIdentityID: &sub}); len(rows) != 0 {
		t.Fatal("B read A's edges by subject")
	}
}

func mustSubject(t *testing.T, e models.CloudAssumeEdge) string {
	t.Helper()
	var a models.GCPAssumeEdgeAttrs
	if err := json.Unmarshal(e.Attrs, &a); err != nil {
		t.Fatal(err)
	}
	return a.SubjectIdentityID
}

// A deleted custom role grants nothing: its binding row keeps role_name with no
// actions, and no edge comes from it even though the role once had actAs.
func TestGCP4_DeletedRoleMakesNoEdge(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp4-deleted-role")
	f := newFakeGCPDiscovery()
	defer f.Close()
	gcp4Fixture(f)
	connectorID := gcpScanConnector(t, db, ws, gcp3Project)
	gcp4Scan(t, db, f, ws, connectorID)
	for _, e := range gcp4Edges(t, db, ws, connectorID) {
		for _, r := range e.attrs.Roles {
			if r == "projects/"+gcp3Project+"/roles/goneRole" {
				t.Fatalf("edge from a deleted role: %+v", e.CloudAssumeEdge)
			}
		}
	}
}

// Roles not readable (probe says so): edges are not derived and not reconciled,
// and binding rows keep the permissions they were last expanded to.
func TestGCP4_UnreadableRolesKeepEdgesAndActions(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp4-roles-unreadable")
	f := newFakeGCPDiscovery()
	defer f.Close()
	gcp4Fixture(f)
	connectorID := gcpScanConnector(t, db, ws, gcp3Project)
	gcp4Scan(t, db, f, ws, connectorID)
	edgesBefore := len(gcp4Edges(t, db, ws, connectorID))
	actionsOf := func() int {
		for _, p := range gcp3Perms(t, db, ws, connectorID) {
			if p.RoleName != nil && *p.RoleName == "projects/"+gcp3Project+"/roles/igaDeployer" {
				return len(p.Actions)
			}
		}
		return -1
	}
	if actionsOf() <= 0 {
		t.Fatal("igaDeployer was not expanded on the first scan")
	}

	if err := db.Exec(`UPDATE cloud_connector SET attrs = attrs || ?::jsonb WHERE id = ?`,
		`{"capability_profile":{"roles":{"can":false,"missing":["iam.roles.list","iam.roles.get"]}}}`, connectorID).Error; err != nil {
		t.Fatal(err)
	}
	cov := gcp4Scan(t, db, f, ws, connectorID)
	if got := cov.Surfaces["edges"].State; got != models.CloudCoverageNotSelected {
		t.Fatalf("edges = %q, want not_selected when roles were not read", got)
	}
	if after := len(gcp4Edges(t, db, ws, connectorID)); after != edgesBefore {
		t.Fatalf("edges %d -> %d with roles unreadable", edgesBefore, after)
	}
	if actionsOf() <= 0 {
		t.Fatal("an unreadable role erased the binding's stored permissions")
	}
}
