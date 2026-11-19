package integration

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// GCP-3: role catalog, bindings, conditions and resources, against a real
// database and a fake Google.
//
// These tests are written against the shipped scan: Cloud Asset's
// searchAllIamPolicies and the IAM role endpoints are the fake, everything
// downstream is real. The ones that matter most assert what is NOT deleted when
// the read was incomplete, because reconcile is a hard DELETE.

const (
	gcp3Project  = "proj-alpha"
	gcp3Number   = "829799656183"
	gcp3Policy   = "//cloudresourcemanager.googleapis.com/projects/" + gcp3Project
	gcp3Bucket   = "//storage.googleapis.com/projects/_/buckets/iga-public-iam-x"
	gcp3Contract = "contractor-sa@" + gcp3Project + ".iam.gserviceaccount.com"
	gcp3App      = "app-sa@" + gcp3Project + ".iam.gserviceaccount.com"
	gcp3Deployer = "deployer-sa@" + gcp3Project + ".iam.gserviceaccount.com"
	gcp3Expiring = `request.time < timestamp("2027-06-30T00:00:00Z")`
	gcp3Expired  = `request.time < timestamp("2026-01-01T00:00:00Z")`
	gcp3Deleted  = "deleted:serviceAccount:deleted-later-sa@" + gcp3Project + ".iam.gserviceaccount.com?uid=123456789"
	gcp3AgentSA  = "service-" + gcp3Number + "@gcp-sa-pubsub.iam.gserviceaccount.com"
	gcp3Pool     = "principalSet://iam.googleapis.com/projects/" + gcp3Number + "/locations/global/workloadIdentityPools/iga-github/*"
)

// gcp3Fixture seeds the fake with the live project's IAM shape.
func gcp3Fixture(f *fakeGCPDiscovery) {
	f.accounts[gcp3Project] = []fakeGCPAccount{
		account("1001", gcp3App), account("1002", gcp3Contract), account("1003", gcp3Deployer),
	}
	f.customRoles["projects/"+gcp3Project] = []fakeGCPRole{
		{name: "projects/" + gcp3Project + "/roles/igaDeployer", perms: []string{"iam.serviceAccounts.actAs", "run.services.update"}},
		{name: "projects/" + gcp3Project + "/roles/goneRole", deleted: true, stage: "DISABLED", perms: []string{"iam.serviceAccounts.actAs"}},
	}
	f.predefinedRoles["roles/storage.objectViewer"] = []string{"storage.objects.get", "storage.objects.list"}
	f.predefinedRoles["roles/bigquery.dataViewer"] = []string{"bigquery.tables.getData"}
	f.predefinedRoles["roles/pubsub.serviceAgent"] = []string{"pubsub.topics.publish"}
	f.policies = []fakeGCPPolicy{
		{
			resource: gcp3Policy, assetType: "cloudresourcemanager.googleapis.com/Project",
			project: "projects/" + gcp3Number, org: "organizations/7",
			bindings: []fakeGCPBinding{
				{role: "roles/owner", members: []string{"user:admin@example.com"}},
				{role: "roles/editor", members: []string{"serviceAccount:" + gcp3App}},
				{role: "roles/viewer", members: []string{gcp3Deleted, gcp3Pool}},
				{role: "projects/" + gcp3Project + "/roles/igaDeployer", members: []string{"serviceAccount:" + gcp3Deployer}},
				{role: "projects/" + gcp3Project + "/roles/goneRole", members: []string{"serviceAccount:" + gcp3Deployer}},
				{role: "projects/" + gcp3Project + "/roles/neverListed", members: []string{"serviceAccount:" + gcp3Deployer}},
				{role: "roles/storage.objectViewer", members: []string{"serviceAccount:" + gcp3Contract},
					condTitle: "until mid 2027", condDesc: "contractor window", condExpr: gcp3Expiring},
				{role: "roles/bigquery.dataViewer", members: []string{"serviceAccount:" + gcp3Contract},
					condTitle: "expired", condExpr: gcp3Expired},
				{role: "roles/pubsub.serviceAgent", members: []string{"serviceAccount:" + gcp3AgentSA}},
			},
		},
		{
			resource: gcp3Bucket, assetType: "storage.googleapis.com/Bucket",
			project: "projects/" + gcp3Number, org: "organizations/7",
			bindings: []fakeGCPBinding{{role: "roles/storage.objectViewer", members: []string{"allUsers"}}},
		},
	}
}

const (
	gcp3ProjectRows  = 10 // (binding, member) pairs on the project policy
	gcp3ResourceRows = 1
)

type gcp3Perm struct {
	models.CloudPermission
	attrs models.GCPPermissionAttrs
	ident models.CloudIdentity
}

func gcp3Perms(t *testing.T, db *gorm.DB, ws, connectorID uuid.UUID) []gcp3Perm {
	t.Helper()
	var rows []models.CloudPermission
	if err := db.Where("workspace_id = ? AND connector_id = ?", ws, connectorID).Find(&rows).Error; err != nil {
		t.Fatalf("load permissions: %v", err)
	}
	out := make([]gcp3Perm, 0, len(rows))
	for _, r := range rows {
		p := gcp3Perm{CloudPermission: r}
		if err := json.Unmarshal(r.Attrs, &p.attrs); err != nil {
			t.Fatalf("attrs of %s: %v", r.NativeID, err)
		}
		if err := db.First(&p.ident, "id = ?", r.IdentityID).Error; err != nil {
			t.Fatalf("identity of %s: %v", r.NativeID, err)
		}
		out = append(out, p)
	}
	return out
}

func gcp3Find(t *testing.T, rows []gcp3Perm, pick func(gcp3Perm) bool) []gcp3Perm {
	t.Helper()
	var out []gcp3Perm
	for _, r := range rows {
		if pick(r) {
			out = append(out, r)
		}
	}
	return out
}

func gcp3One(t *testing.T, rows []gcp3Perm, what string, pick func(gcp3Perm) bool) gcp3Perm {
	t.Helper()
	got := gcp3Find(t, rows, pick)
	if len(got) != 1 {
		t.Fatalf("%s: %d rows, want 1", what, len(got))
	}
	return got[0]
}

func gcp3Identity(t *testing.T, db *gorm.DB, ws, connectorID uuid.UUID, pick func(models.CloudIdentity) bool) []models.CloudIdentity {
	t.Helper()
	var out []models.CloudIdentity
	for _, i := range gcp2Identities(t, db, ws, connectorID) {
		if pick(i) {
			out = append(out, i)
		}
	}
	return out
}

func TestGCP3_BindingsRolesConditionsAndMembers(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp3-bindings")
	f := newFakeGCPDiscovery()
	defer f.Close()
	gcp3Fixture(f)

	connectorID := gcpScanConnector(t, db, ws, gcp3Project)
	snapshot, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	cov := snapshot.Coverage
	if cov.Status != models.ScanStatusComplete {
		t.Fatalf("status = %q: %+v", cov.Status, cov.Surfaces)
	}
	for _, s := range []string{"roles", "allow_bindings", "resource_iam"} {
		if cov.Surfaces[s].State != models.CloudCoverageReached {
			t.Errorf("%s = %+v, want reached", s, cov.Surfaces[s])
		}
	}
	if cov.Counters["allow_bindings_upserted"] != gcp3ProjectRows || cov.Counters["resource_iam_upserted"] != gcp3ResourceRows {
		t.Fatalf("counters = %+v", cov.Counters)
	}

	rows := gcp3Perms(t, db, ws, connectorID)
	if len(rows) != gcp3ProjectRows+gcp3ResourceRows {
		t.Fatalf("permission rows = %d, want %d", len(rows), gcp3ProjectRows+gcp3ResourceRows)
	}

	// ---- scenario 6: conditions kept verbatim, bounds extracted --------------
	contractor := gcp3Find(t, rows, func(p gcp3Perm) bool {
		return strings.HasPrefix(p.ident.NativeID, "//iam.googleapis.com/") && p.attrs.Member == "serviceAccount:"+gcp3Contract
	})
	if len(contractor) != 2 {
		t.Fatalf("contractor-sa rows = %d, want 2 (same member, two conditions)", len(contractor))
	}
	seen := map[string]string{}
	for _, p := range contractor {
		if p.ConstraintState != "conditional" || p.Condition == nil {
			t.Fatalf("contractor row must be conditional with a condition: %+v", p.CloudPermission)
		}
		var c struct{ Title, Description, Expression string }
		if err := json.Unmarshal([]byte(*p.Condition), &c); err != nil {
			t.Fatal(err)
		}
		if c.Expression != gcp3Expiring && c.Expression != gcp3Expired {
			t.Fatalf("CEL altered: %q", c.Expression)
		}
		if !strings.Contains(string(p.attrs.BindingRaw), strings.ReplaceAll(c.Expression, `"`, `\"`)) {
			t.Fatalf("binding_raw lost the CEL: %s", p.attrs.BindingRaw)
		}
		seen[*p.RoleName] = p.attrs.ExpiresAt
	}
	if seen["roles/storage.objectViewer"] != "2027-06-30T00:00:00Z" || seen["roles/bigquery.dataViewer"] != "2026-01-01T00:00:00Z" {
		t.Fatalf("expires_at = %+v", seen)
	}

	// ---- basic role: unexpanded and flagged ----------------------------------
	owner := gcp3One(t, rows, "owner", func(p gcp3Perm) bool { return *p.RoleName == "roles/owner" })
	if len(owner.Actions) != 0 || !owner.attrs.BasicRole || owner.attrs.RoleState != "basic" {
		t.Fatalf("owner = %+v %+v", owner.CloudPermission, owner.attrs)
	}
	if owner.ScopeKind != "account_wide" || owner.ResourceID != nil || owner.attrs.GCPScopeKind != "project" {
		t.Fatalf("project-level binding must be account_wide with no resource: %+v", owner.CloudPermission)
	}
	if owner.attrs.AttachedTo != gcp3Policy || len(owner.attrs.Ancestors) != 1 || owner.attrs.Ancestors[0] != "organizations/7" {
		t.Fatalf("provenance = %+v", owner.attrs)
	}
	if owner.Plane != "cloud" || owner.Effect != "allow" || owner.ConstraintState != "unconstrained" || owner.Condition != nil {
		t.Fatalf("owner = %+v", owner.CloudPermission)
	}

	// ---- scenario 7: custom role expanded; deleted/unknown kept and flagged --
	dep := gcp3One(t, rows, "igaDeployer", func(p gcp3Perm) bool { return strings.HasSuffix(*p.RoleName, "/igaDeployer") })
	if !contains(dep.Actions, "iam.serviceAccounts.actAs") || dep.attrs.RoleState != "expanded" || dep.Sensitivity != "high" {
		t.Fatalf("igaDeployer = %+v %+v", dep.CloudPermission, dep.attrs)
	}
	for _, name := range []string{"goneRole", "neverListed"} {
		p := gcp3One(t, rows, name, func(p gcp3Perm) bool { return strings.HasSuffix(*p.RoleName, "/"+name) })
		if len(p.Actions) != 0 || !p.attrs.RoleUnresolved || p.attrs.RoleState != "deleted" {
			t.Fatalf("%s must be kept, empty and flagged: %+v %+v", name, p.CloudPermission, p.attrs)
		}
	}

	// ---- scenario 3 and 9: member identities ---------------------------------
	agents := gcp3Identity(t, db, ws, connectorID, func(i models.CloudIdentity) bool { return i.Kind == models.CloudIdentityGCPServiceAgent })
	if len(agents) != 1 || agents[0].GCPAttrs().SAClass != "service_agent" {
		t.Fatalf("service agent identities = %+v", agents)
	}
	deleted := gcp3Identity(t, db, ws, connectorID, func(i models.CloudIdentity) bool { return i.Kind == models.CloudIdentityGCPDeleted })
	if len(deleted) != 1 || !deleted[0].GCPAttrs().Deleted || deleted[0].Enabled {
		t.Fatalf("deleted identities = %+v", deleted)
	}
	if got := gcp3Identity(t, db, ws, connectorID, func(i models.CloudIdentity) bool { return i.Kind == models.CloudIdentityGCPPublic }); len(got) != 1 {
		t.Fatalf("allUsers identities = %d", len(got))
	}
	if got := gcp3Identity(t, db, ws, connectorID, func(i models.CloudIdentity) bool { return i.Kind == models.CloudIdentityGCPFederated }); len(got) != 1 {
		t.Fatalf("federated identities = %d", len(got))
	}
	// A binding to a live service account resolves to its real row, not a copy.
	editor := gcp3One(t, rows, "editor", func(p gcp3Perm) bool { return *p.RoleName == "roles/editor" })
	if editor.ident.Kind != models.CloudIdentityGCPServiceAccount || editor.ident.GCPAttrs().UniqueID != "1001" {
		t.Fatalf("editor bound to %+v, want the real service account row", editor.ident)
	}
	if got := gcp3Identity(t, db, ws, connectorID, func(i models.CloudIdentity) bool { return i.GCPAttrs().Email == gcp3App }); len(got) != 1 {
		t.Fatalf("app-sa has %d identity rows, want 1", len(got))
	}

	// ---- scenario 8: resource-level binding -----------------------------------
	pub := gcp3One(t, rows, "allUsers", func(p gcp3Perm) bool { return p.ident.Kind == models.CloudIdentityGCPPublic })
	if pub.ScopeKind != "resource" || pub.ResourceID == nil || pub.attrs.GCPScopeKind != "resource" {
		t.Fatalf("resource binding = %+v %+v", pub.CloudPermission, pub.attrs)
	}
	if len(pub.attrs.Ancestors) == 0 || pub.attrs.Ancestors[0] != "projects/"+gcp3Number {
		t.Fatalf("resource ancestors = %v", pub.attrs.Ancestors)
	}
	var res models.CloudResource
	if err := db.First(&res, "id = ?", *pub.ResourceID).Error; err != nil {
		t.Fatal(err)
	}
	if res.Kind != "gcs_bucket" || res.NativeID != gcp3Bucket || res.Name != "iga-public-iam-x" ||
		res.Sensitivity != "med" || res.SensitivitySource != models.SensitivityFromHeuristic || res.IsExternal {
		t.Fatalf("resource = %+v", res)
	}
	var resources int64
	db.Model(&models.CloudResource{}).Where("workspace_id = ? AND connector_id = ?", ws, connectorID).Count(&resources)
	if resources != 1 {
		t.Fatalf("resources = %d: org/folder/project policies create no resource row", resources)
	}

	// ---- nothing planted reached any column; idempotent rescan ---------------
	nothingLeaked(t, db, ws, connectorID)
	if _, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatalf("rescan: %v", err)
	}
	if again := gcp3Perms(t, db, ws, connectorID); len(again) != len(rows) {
		t.Fatalf("rescan changed the row count: %d -> %d", len(rows), len(again))
	}
	nothingLeaked(t, db, ws, connectorID)
}

// A changed condition is a new row and the old one is reconciled away.
func TestGCP3_ChangedConditionReplacesTheRow(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp3-condition-change")
	f := newFakeGCPDiscovery()
	defer f.Close()
	gcp3Fixture(f)
	connectorID := gcpScanConnector(t, db, ws, gcp3Project)
	if _, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatal(err)
	}

	f.policies[0].bindings[6].condExpr = `request.time < timestamp("2028-12-31T00:00:00Z")`
	snap, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID)
	if err != nil || snap.Coverage.Status != models.ScanStatusComplete {
		t.Fatalf("rescan: %v %q", err, snap.Coverage.Status)
	}
	rows := gcp3Perms(t, db, ws, connectorID)
	if len(rows) != gcp3ProjectRows+gcp3ResourceRows {
		t.Fatalf("rows = %d: the old condition's row must be reconciled away", len(rows))
	}
	for _, p := range rows {
		if p.attrs.ExpiresAt == "2027-06-30T00:00:00Z" {
			t.Fatal("the stale condition survived")
		}
	}
}

// Scenario 5, in the fake only (the live project has no organization or folders):
// a folder binding is stored once, where it is attached, with its ancestor chain.
func TestGCP3_FolderBindingIsStoredOnceWithAncestors(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp3-folder")
	f := newFakeGCPDiscovery()
	defer f.Close()
	f.projects = []struct{ id, number string }{{"dev", "111"}, {"prod", "222"}}
	f.accounts["dev"] = []fakeGCPAccount{account("5", "folder-reader-sa@shared.iam.gserviceaccount.com")}
	f.predefinedRoles["roles/viewer"] = nil
	f.policies = []fakeGCPPolicy{
		{
			resource: "//cloudresourcemanager.googleapis.com/folders/42", assetType: "cloudresourcemanager.googleapis.com/Folder",
			folders: []string{"folders/42"}, org: "organizations/1",
			bindings: []fakeGCPBinding{{role: "roles/viewer", members: []string{"serviceAccount:folder-reader-sa@shared.iam.gserviceaccount.com"}}},
		},
		{
			// A bucket in a project the connector does not scan.
			resource: "//storage.googleapis.com/projects/_/buckets/elsewhere", assetType: "storage.googleapis.com/Bucket",
			project: "projects/999", org: "organizations/1",
			bindings: []fakeGCPBinding{{role: "roles/viewer", members: []string{"user:a@example.com"}}},
		},
	}
	connectorID := gcpOrgScanConnector(t, db, ws, "1")
	snap, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Coverage.Surfaces["allow_bindings"].State != models.CloudCoverageReached {
		t.Fatalf("surfaces: %+v", snap.Coverage.Surfaces)
	}
	rows := gcp3Perms(t, db, ws, connectorID)
	folder := gcp3One(t, rows, "folder binding", func(p gcp3Perm) bool { return p.attrs.GCPScopeKind == "folder" })
	if folder.ScopeKind != "account_wide" || folder.ResourceID != nil || folder.attrs.AttachedTo != "//cloudresourcemanager.googleapis.com/folders/42" {
		t.Fatalf("folder = %+v %+v", folder.CloudPermission, folder.attrs)
	}
	if strings.Join(folder.attrs.Ancestors, ",") != "organizations/1" {
		t.Fatalf("folder ancestors = %v (the folder itself is not its ancestor)", folder.attrs.Ancestors)
	}
	// Stored once: not copied to dev and prod.
	if n := len(gcp3Find(t, rows, func(p gcp3Perm) bool { return p.attrs.GCPScopeKind == "folder" })); n != 1 {
		t.Fatalf("folder binding rows = %d, want exactly 1", n)
	}
	var ext models.CloudResource
	if err := db.First(&ext, "workspace_id = ? AND native_id = ?", ws, "//storage.googleapis.com/projects/_/buckets/elsewhere").Error; err != nil {
		t.Fatal(err)
	}
	if !ext.IsExternal || ext.ResourceAccount != "999" {
		t.Fatalf("resource in an unscanned project = %+v, want external", ext)
	}
}

// A page ceiling is a read that stopped early: both surfaces are not reached and
// nothing -- permissions, resources, member rows -- is reconciled.
func TestGCP3_PageCapLeavesBothSurfacesNotReachedAndDeletesNothing(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp3-page-cap")
	f := newFakeGCPDiscovery()
	defer f.Close()
	gcp3Fixture(f)
	connectorID := gcpScanConnector(t, db, ws, gcp3Project)
	if _, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatal(err)
	}
	permsBefore := len(gcp3Perms(t, db, ws, connectorID))
	identitiesBefore := countIdentities(t, db, ws, connectorID)

	// Google now answers with one policy fewer, and never stops paging.
	f.policies = f.policies[:1]
	f.endlessBindings = true
	snap, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatal(err)
	}
	cov := snap.Coverage
	for _, s := range []string{"allow_bindings", "resource_iam"} {
		if cov.Surfaces[s].State == models.CloudCoverageReached {
			t.Errorf("%s = %+v: a capped read must not be reached", s, cov.Surfaces[s])
		}
	}
	if cov.Status != models.ScanStatusPartial {
		t.Fatalf("status = %q, want partial", cov.Status)
	}
	if got := len(gcp3Perms(t, db, ws, connectorID)); got != permsBefore {
		t.Fatalf("permissions %d -> %d: a capped scan reconciled", permsBefore, got)
	}
	if got := countIdentities(t, db, ws, connectorID); got != identitiesBefore {
		t.Fatalf("identities %d -> %d: a capped scan reconciled", identitiesBefore, got)
	}
}

func TestGCP3_DeniedBindingsReadDeletesNothing(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp3-denied")
	f := newFakeGCPDiscovery()
	defer f.Close()
	gcp3Fixture(f)
	connectorID := gcpScanConnector(t, db, ws, gcp3Project)
	if _, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatal(err)
	}
	permsBefore := len(gcp3Perms(t, db, ws, connectorID))
	identitiesBefore := countIdentities(t, db, ws, connectorID)

	f.failBindings = 403
	snap, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"allow_bindings", "resource_iam"} {
		if got := snap.Coverage.Surfaces[s].State; got != models.CloudCoverageDenied {
			t.Errorf("%s = %q, want denied", s, got)
		}
	}
	if len(gcp3Perms(t, db, ws, connectorID)) != permsBefore || countIdentities(t, db, ws, connectorID) != identitiesBefore {
		t.Fatal("a denied bindings read deleted rows")
	}
}

// Service-disabled and a probe-proven unreadable surface are not denials: the
// scan completes, but nothing about bindings or members is concluded.
func TestGCP3_UnreadableBindingsAreSkippedAndMemberRowsSurvive(t *testing.T) {
	for name, arrange := range map[string]func(*testing.T, *gorm.DB, uuid.UUID, *fakeGCPDiscovery){
		"cloud asset api disabled": func(_ *testing.T, _ *gorm.DB, _ uuid.UUID, f *fakeGCPDiscovery) {
			f.failBindings = 403
			f.failBindingsBody = "Cloud Asset API has not been used in project 1 before or it is disabled. SERVICE_DISABLED"
		},
		"token scopes refused by both APIs": func(_ *testing.T, _ *gorm.DB, _ uuid.UUID, f *fakeGCPDiscovery) {
			f.failBindings = 403
			f.failBindingsBody = "Provided scope(s) are not authorized"
			f.failRMPolicy = 403
		},
		"probe says unreadable": func(t *testing.T, db *gorm.DB, id uuid.UUID, _ *fakeGCPDiscovery) {
			if err := db.Exec(`UPDATE cloud_connector SET attrs = attrs || ?::jsonb WHERE id = ?`,
				`{"capability_profile":{"allow_bindings":{"can":false,"missing":["cloudasset.assets.searchAllIamPolicies"]}}}`, id).Error; err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			db := igaDB(t)
			ws := newWorkspace(t, db, "gcp3-skip-"+strings.ReplaceAll(name, " ", "-"))
			f := newFakeGCPDiscovery()
			defer f.Close()
			gcp3Fixture(f)
			connectorID := gcpScanConnector(t, db, ws, gcp3Project)
			if _, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID); err != nil {
				t.Fatal(err)
			}
			permsBefore := len(gcp3Perms(t, db, ws, connectorID))
			identitiesBefore := countIdentities(t, db, ws, connectorID)

			arrange(t, db, connectorID, f)
			snap, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID)
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range []string{"allow_bindings", "resource_iam"} {
				if got := snap.Coverage.Surfaces[s].State; got != models.CloudCoverageNotSelected {
					t.Errorf("%s = %q, want not_selected", s, got)
				}
			}
			if snap.Coverage.Status != models.ScanStatusComplete {
				t.Fatalf("an unreadable surface must not hold the scan at partial: %q", snap.Coverage.Status)
			}
			if got := len(gcp3Perms(t, db, ws, connectorID)); got != permsBefore {
				t.Fatalf("permissions %d -> %d", permsBefore, got)
			}
			if got := countIdentities(t, db, ws, connectorID); got != identitiesBefore {
				t.Fatalf("identities %d -> %d: member rows must be protected", identitiesBefore, got)
			}
		})
	}
}

// Seen live: Cloud Asset refuses the read-only scopes for searchAllIamPolicies.
// The hierarchy-level policies are then read through Resource Manager, and the
// scan says plainly that resource-level policies were not.
func TestGCP3_CloudAssetScopeRefusalFallsBackToResourceManager(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp3-rm-fallback")
	f := newFakeGCPDiscovery()
	defer f.Close()
	gcp3Fixture(f)
	connectorID := gcpScanConnector(t, db, ws, gcp3Project)
	// A first scan with Cloud Asset working leaves a resource-level row behind.
	if _, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatal(err)
	}

	f.failBindings = 403
	f.failBindingsBody = "Request had insufficient authentication scopes. ACCESS_TOKEN_SCOPE_INSUFFICIENT"
	snap, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatal(err)
	}
	cov := snap.Coverage
	if got := cov.Surfaces["allow_bindings"].State; got != models.CloudCoverageReached {
		t.Fatalf("allow_bindings = %+v, want reached through Resource Manager", cov.Surfaces["allow_bindings"])
	}
	if got := cov.Surfaces["resource_iam"]; got.State != models.CloudCoverageNotSelected || !strings.HasPrefix(got.Error, "not_readable") {
		t.Fatalf("resource_iam = %+v, want not_selected with a reason", got)
	}
	if cov.Status != models.ScanStatusComplete {
		t.Fatalf("status = %q", cov.Status)
	}
	rows := gcp3Perms(t, db, ws, connectorID)
	// The resource-level row from the first scan is neither refreshed nor deleted
	// (permissions are only reconciled when both surfaces were read), and the
	// principal that only a resource policy names survives.
	if len(rows) != gcp3ProjectRows+gcp3ResourceRows {
		t.Fatalf("rows = %d, want %d", len(rows), gcp3ProjectRows+gcp3ResourceRows)
	}
	if got := gcp3Identity(t, db, ws, connectorID, func(i models.CloudIdentity) bool { return i.Kind == models.CloudIdentityGCPPublic }); len(got) != 1 {
		t.Fatalf("allUsers identity = %d, want it protected", len(got))
	}
	// And the project-level conditions are still kept verbatim.
	found := 0
	for _, p := range rows {
		if p.Condition != nil && strings.Contains(*p.Condition, "2027-06-30") {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("expiring condition rows = %d, want 1", found)
	}
}

// A member that does not parse is a row that was not written: counted, never
// silently dropped, and the surfaces are not reached.
func TestGCP3_UnparseableMemberFailsTheSurfaces(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp3-unparsed")
	f := newFakeGCPDiscovery()
	defer f.Close()
	gcp3Fixture(f)
	connectorID := gcpScanConnector(t, db, ws, gcp3Project)
	if _, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatal(err)
	}
	before := len(gcp3Perms(t, db, ws, connectorID))

	f.policies[0].bindings = append(f.policies[0].bindings,
		fakeGCPBinding{role: "roles/viewer", members: []string{"someNewKind:wat@example.com", "user:ok@example.com"}})
	snap, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"allow_bindings", "resource_iam"} {
		if got := snap.Coverage.Surfaces[s].State; got == models.CloudCoverageReached {
			t.Errorf("%s reached despite an unparsed member", s)
		}
	}
	if snap.Coverage.Status != models.ScanStatusPartial {
		t.Fatalf("status = %q, want partial", snap.Coverage.Status)
	}
	// The member that did parse was written; nothing was reconciled.
	if got := len(gcp3Perms(t, db, ws, connectorID)); got != before+1 {
		t.Fatalf("rows %d -> %d, want +1 (the parseable member only)", before, got)
	}
}

// A roles.get that cannot be answered is not "the role is gone": the surface is
// not reached and the row says the role was unavailable, not deleted.
func TestGCP3_RoleReadFailureIsUnavailableNotDeleted(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp3-role-fail")
	f := newFakeGCPDiscovery()
	defer f.Close()
	gcp3Fixture(f)
	f.failRoleGet["roles/pubsub.serviceAgent"] = 403
	connectorID := gcpScanConnector(t, db, ws, gcp3Project)
	snap, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Coverage.Surfaces["roles"].State == models.CloudCoverageReached {
		t.Fatal("a refused roles.get must leave the roles surface not reached")
	}
	rows := gcp3Perms(t, db, ws, connectorID)
	p := gcp3One(t, rows, "service agent", func(p gcp3Perm) bool { return *p.RoleName == "roles/pubsub.serviceAgent" })
	if p.attrs.RoleState != "unavailable" || p.attrs.RoleUnresolved {
		t.Fatalf("row = %+v: could-not-ask must not read as a deleted role", p.attrs)
	}
}

// GCP rows stay out of the AWS-facing lists, and one workspace never sees
// another's rows.
func TestGCP3_ListsExcludeGCPAndAreWorkspaceScoped(t *testing.T) {
	db := igaDB(t)
	wsA := newWorkspace(t, db, "gcp3-iso-a")
	wsB := newWorkspace(t, db, "gcp3-iso-b")
	f := newFakeGCPDiscovery()
	defer f.Close()
	gcp3Fixture(f)
	connectorA := gcpScanConnector(t, db, wsA, gcp3Project)
	if _, err := gcpScanner(t, db, f).Scan(context.Background(), wsA, connectorA); err != nil {
		t.Fatal(err)
	}
	if len(gcp3Perms(t, db, wsA, connectorA)) == 0 {
		t.Fatal("seed produced no GCP permissions")
	}

	repo := repositories.NewCloudPermissionRepository(db)
	for _, ws := range []uuid.UUID{wsA, wsB} {
		perms, _, err := repo.ListPermissions(ws, repositories.CloudPermissionFilter{})
		if err != nil || len(perms) != 0 {
			t.Fatalf("workspace %s: ListPermissions = %d, %v (GCP rows belong to the GCP views)", ws, len(perms), err)
		}
		resources, _, err := repo.ListResources(ws, repositories.CloudPermissionFilter{})
		if err != nil || len(resources) != 0 {
			t.Fatalf("workspace %s: ListResources = %d, %v", ws, len(resources), err)
		}
	}
	var leaked int64
	db.Model(&models.CloudPermission{}).Where("workspace_id = ?", wsB).Count(&leaked)
	if leaked != 0 {
		t.Fatalf("workspace B holds %d permission rows from workspace A's scan", leaked)
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
