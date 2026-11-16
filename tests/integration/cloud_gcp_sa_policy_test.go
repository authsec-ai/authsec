package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/models"
)

// Before GCP-4: the policies ON service accounts (who may act as one, mint its
// tokens, or bind a GKE service account to it), read with the IAM API when Cloud
// Asset refuses the token's scopes -- as it does live -- and the per-family
// reconcile that lets those rows, and the hierarchy rows, be cleaned up even
// though resource_iam is never reached.

const gcp4KSA = "serviceAccount:" + gcp3Project + ".svc.id.goog[iga/app-ksa]"

func gcpRefuseCloudAsset(f *fakeGCPDiscovery) {
	f.failBindings = 403
	f.failBindingsBody = "Request had insufficient authentication scopes. ACCESS_TOKEN_SCOPE_INSUFFICIENT"
}

func TestGCPSAPolicy_ReadWhenCloudAssetRefuses(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-sa-policy")
	f := newFakeGCPDiscovery()
	defer f.Close()
	gcp3Fixture(f)
	gcpRefuseCloudAsset(f)
	f.predefinedRoles["roles/iam.serviceAccountUser"] = []string{"iam.serviceAccounts.actAs"}
	f.predefinedRoles["roles/iam.workloadIdentityUser"] = []string{"iam.serviceAccounts.getAccessToken"}
	f.saPolicies = map[string][]fakeGCPBinding{
		gcp3App: {
			{role: "roles/iam.serviceAccountUser", members: []string{"serviceAccount:" + gcp3Deployer}},
			{role: "roles/iam.workloadIdentityUser", members: []string{gcp4KSA}},
		},
	}
	connectorID := gcpScanConnector(t, db, ws, gcp3Project)
	snap, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatal(err)
	}
	cov := snap.Coverage
	if got := cov.Surfaces["sa_iam"]; got.State != models.CloudCoverageReached || got.Count != 2 {
		t.Fatalf("sa_iam = %+v, want reached with 2 rows", got)
	}
	if cov.Status != models.ScanStatusComplete {
		t.Fatalf("status = %q: %+v", cov.Status, cov.Surfaces)
	}

	rows := gcp3Perms(t, db, ws, connectorID)
	user := gcp3One(t, rows, "serviceAccountUser on app-sa", func(p gcp3Perm) bool {
		return p.RoleName != nil && *p.RoleName == "roles/iam.serviceAccountUser"
	})
	if user.ResourceID == nil || user.ScopeKind != "resource" || user.attrs.GCPScopeKind != models.GCPScopeResource {
		t.Fatalf("SA policy row must be resource-scoped: %+v %+v", user.CloudPermission, user.attrs)
	}
	if !strings.HasPrefix(user.attrs.AttachedTo, "//iam.googleapis.com/projects/"+gcp3Project+"/serviceAccounts/1001") {
		t.Fatalf("attached_to = %q, want app-sa's Cloud Asset name", user.attrs.AttachedTo)
	}
	// The holder is the real deployer-sa row, not a principal copy.
	if user.ident.Kind != models.CloudIdentityGCPServiceAccount {
		t.Fatalf("holder kind = %q, want the listed service account", user.ident.Kind)
	}
	var res models.CloudResource
	if err := db.First(&res, "id = ?", *user.ResourceID).Error; err != nil || res.Kind != "service_account" {
		t.Fatalf("resource = %+v, %v; want a service_account resource", res, err)
	}

	// The GKE Workload Identity member parsed and became an identity.
	gcp3One(t, rows, "workloadIdentityUser for the KSA", func(p gcp3Perm) bool {
		return p.RoleName != nil && *p.RoleName == "roles/iam.workloadIdentityUser" && p.attrs.Member == gcp4KSA
	})
}

func TestGCPSAPolicy_DeniedLeavesSurfaceNotReachedAndKeepsRows(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-sa-policy-denied")
	f := newFakeGCPDiscovery()
	defer f.Close()
	gcp3Fixture(f)
	gcpRefuseCloudAsset(f)
	f.predefinedRoles["roles/iam.serviceAccountUser"] = []string{"iam.serviceAccounts.actAs"}
	f.saPolicies = map[string][]fakeGCPBinding{
		gcp3App: {{role: "roles/iam.serviceAccountUser", members: []string{"serviceAccount:" + gcp3Deployer}}},
	}
	connectorID := gcpScanConnector(t, db, ws, gcp3Project)
	if _, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatal(err)
	}
	before := len(gcp3Perms(t, db, ws, connectorID))

	f.failSAPolicy = 403
	snap, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatal(err)
	}
	if got := snap.Coverage.Surfaces["sa_iam"].State; got == models.CloudCoverageReached {
		t.Fatal("a denied service-account policy read must not be reached")
	}
	if after := len(gcp3Perms(t, db, ws, connectorID)); after != before {
		t.Fatalf("rows %d -> %d: a denied read deleted rows", before, after)
	}
}

func TestGCPSAPolicy_PartialReconcileRemovesStaleFamiliesOnly(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-sa-policy-reconcile")
	f := newFakeGCPDiscovery()
	defer f.Close()
	gcp3Fixture(f)
	connectorID := gcpScanConnector(t, db, ws, gcp3Project)
	// Scan 1 with Cloud Asset working: the bucket's public binding is stored.
	if _, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatal(err)
	}

	// Scan 2: Cloud Asset refuses; one SA-level binding exists.
	gcpRefuseCloudAsset(f)
	f.predefinedRoles["roles/iam.serviceAccountUser"] = []string{"iam.serviceAccounts.actAs"}
	f.saPolicies = map[string][]fakeGCPBinding{
		gcp3App: {{role: "roles/iam.serviceAccountUser", members: []string{"serviceAccount:" + gcp3Deployer}}},
	}
	if _, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatal(err)
	}

	// Scan 3: the owner binding and the SA-level binding are removed in Google.
	pol := f.policies[0].bindings[1:] // drop roles/owner
	f.policies[0].bindings = pol
	f.saPolicies = map[string][]fakeGCPBinding{}
	snap, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Coverage.Status != models.ScanStatusComplete {
		t.Fatalf("status = %q", snap.Coverage.Status)
	}
	rows := gcp3Perms(t, db, ws, connectorID)
	has := func(role string) bool {
		for _, p := range rows {
			if p.RoleName != nil && *p.RoleName == role {
				return true
			}
		}
		return false
	}
	if has("roles/owner") {
		t.Fatal("a project binding removed in Google survived reconcile (hierarchy family was read)")
	}
	if has("roles/iam.serviceAccountUser") {
		t.Fatal("an SA-level binding removed in Google survived reconcile (sa_iam was read)")
	}
	// The bucket binding came from Cloud Asset, which was not read: kept.
	bucket := gcp3Find(t, rows, func(p gcp3Perm) bool { return p.attrs.AttachedTo == gcp3Bucket })
	if len(bucket) != 1 {
		t.Fatalf("bucket rows = %d, want 1 kept (resource_iam was not read)", len(bucket))
	}
	var saResources int64
	db.Model(&models.CloudResource{}).Where("workspace_id = ? AND connector_id = ? AND kind = ?", ws, connectorID, "service_account").Count(&saResources)
	if saResources != 0 {
		t.Fatalf("service_account resources = %d, want 0 once nothing binds on them", saResources)
	}
}
