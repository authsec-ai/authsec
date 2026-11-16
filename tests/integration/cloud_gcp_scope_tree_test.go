package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"google.golang.org/api/cloudresourcemanager/v3"
	"gorm.io/gorm"
)

// GCP-1: the scope-tree walk, against a real database and the fake GCP server
// in cloud_gcp_scan_test.go (which serves folders.list and a parent-aware
// projects:search when its folders / projectsByParent fields are set).

func storedScopeTree(t *testing.T, db *gorm.DB, ws, connectorID uuid.UUID) gcp.ScopeTree {
	t.Helper()
	var c models.CloudConnector
	if err := db.Where("workspace_id = ? AND id = ?", ws, connectorID).First(&c).Error; err != nil {
		t.Fatalf("load connector: %v", err)
	}
	raw := c.GCPAttrs().ScopeTree
	if len(raw) == 0 {
		t.Fatal("attrs.scope_tree was not stored")
	}
	var tree gcp.ScopeTree
	if err := json.Unmarshal(raw, &tree); err != nil {
		t.Fatalf("decode scope_tree: %v", err)
	}
	return tree
}

// The reason the walk exists: a project in a folder is invisible to a single
// "parent:organizations/N" search. The scan must read it, store the tree, and
// report the scope_tree surface reached.
func TestGCPScan_OrgScopedWalksFoldersAndStoresScopeTree(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-scan-scope-tree")
	f := newFakeGCPDiscovery()
	defer f.Close()

	f.folders = map[string][]*cloudresourcemanager.Folder{
		"organizations/123456789012": {{Name: "folders/10", DisplayName: "Eng", State: "ACTIVE"}},
	}
	f.projectsByParent = map[string][]struct{ id, number string }{
		"organizations/123456789012": {{"top-proj", "1"}},
		"folders/10":                 {{"nested-proj", "2"}},
	}
	for _, id := range []string{"top-proj", "nested-proj"} {
		f.accounts[id] = []fakeGCPAccount{account("uid-"+id, "svc@"+id+".iam.gserviceaccount.com")}
	}

	connectorID := gcpOrgScanConnector(t, db, ws, "123456789012")
	snapshot, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(snapshot.Projects) != 2 {
		t.Fatalf("read %d projects, want 2 -- the folder's project was missed", len(snapshot.Projects))
	}
	if got := countIdentities(t, db, ws, connectorID); got != 2 {
		t.Fatalf("identities = %d, want 2", got)
	}
	if snapshot.Coverage.Status != models.ScanStatusComplete {
		t.Fatalf("status = %q: %+v", snapshot.Coverage.Status, snapshot.Coverage.Surfaces)
	}
	if got := snapshot.Coverage.Surfaces["scope_tree"].State; got != models.CloudCoverageReached {
		t.Fatalf("scope_tree = %q, want reached", got)
	}

	tree := storedScopeTree(t, db, ws, connectorID)
	var folders, projects int
	for _, n := range tree.Nodes {
		switch n.Kind {
		case gcp.ScopeNodeFolder:
			folders++
		case gcp.ScopeNodeProject:
			projects++
		}
	}
	if folders != 1 || projects != 2 {
		t.Fatalf("stored tree has %d folders and %d projects, want 1 and 2: %+v", folders, projects, tree.Nodes)
	}
}

// A truncated tree is real data but not the whole estate: the scan reads what it
// found, stores the tree marked truncated, and reconciles nothing.
func TestGCPScan_TruncatedScopeTreeBlocksReconciliation(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-scan-scope-truncated")
	f := newFakeGCPDiscovery()
	defer f.Close()

	// A chain deeper than the hierarchy limit.
	f.folders = map[string][]*cloudresourcemanager.Folder{}
	parent := "organizations/123456789012"
	for d := 1; d <= gcp.MaxFolderDepth+1; d++ {
		id := fmt.Sprintf("%d", d)
		f.folders[parent] = []*cloudresourcemanager.Folder{{Name: "folders/" + id, State: "ACTIVE"}}
		parent = "folders/" + id
	}
	f.projectsByParent = map[string][]struct{ id, number string }{
		"organizations/123456789012": {{"top-proj", "1"}},
	}
	f.accounts["top-proj"] = []fakeGCPAccount{account("uid-1", "svc@top-proj.iam.gserviceaccount.com")}

	connectorID := gcpOrgScanConnector(t, db, ws, "123456789012")
	scanner := gcpScanner(t, db, f)

	snapshot, err := scanner.Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if snapshot.Coverage.Complete() || snapshot.Coverage.Status != models.ScanStatusPartial {
		t.Fatalf("status = %q, want partial for a truncated tree", snapshot.Coverage.Status)
	}
	if got := snapshot.Coverage.Surfaces["scope_tree"].State; got == models.CloudCoverageReached {
		t.Fatal("scope_tree reported reached for a truncated walk")
	}
	if got := countIdentities(t, db, ws, connectorID); got != 1 {
		t.Fatalf("identities = %d, want the 1 found in the readable part of the tree", got)
	}
	if tree := storedScopeTree(t, db, ws, connectorID); !tree.Truncated {
		t.Fatal("the stored tree must say it is truncated")
	}

	// The rule that matters: a second scan whose estate shrank must not delete
	// anything while the tree is still truncated.
	f.accounts["top-proj"] = nil
	again, err := scanner.Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}
	if again.Coverage.Complete() {
		t.Fatal("a truncated tree must never be Complete()")
	}
	if got := countIdentities(t, db, ws, connectorID); got != 1 {
		t.Fatalf("identities = %d, want 1 -- a truncated scan reconciled", got)
	}
}

// A denied folders.list is a failure to look: nothing is stored as a tree and
// nothing is reached.
func TestGCPScan_DeniedFolderListStoresNoTree(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-scan-scope-denied")
	f := newFakeGCPDiscovery()
	defer f.Close()
	f.foldersStatus = http.StatusForbidden

	connectorID := gcpOrgScanConnector(t, db, ws, "123456789012")
	snapshot, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if snapshot.Coverage.Complete() {
		t.Fatal("a scan that could not walk the hierarchy must not be Complete()")
	}
	var c models.CloudConnector
	if err := db.Where("workspace_id = ? AND id = ?", ws, connectorID).First(&c).Error; err != nil {
		t.Fatal(err)
	}
	if len(c.GCPAttrs().ScopeTree) != 0 {
		t.Fatal("a failed walk must not leave a scope tree behind")
	}
}

// Verify rewrites attrs from the typed struct; if scope_tree were not a typed
// field the round trip would drop it. The scan also records its trigger.
func TestGCPScan_ScopeTreeSurvivesAttrsRoundTripAndTriggerIsRecorded(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-scan-scope-roundtrip")
	f := newFakeGCPDiscovery()
	defer f.Close()
	f.projects = append(f.projects, struct{ id, number string }{"rt-proj", "7"})

	connectorID := gcpScanConnector(t, db, ws, "rt-proj")
	snapshot, err := gcpScanner(t, db, f).ScanWithTrigger(
		context.Background(), ws, connectorID, models.CloudScanTriggerScheduled)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if snapshot.Coverage.Trigger != models.CloudScanTriggerScheduled {
		t.Fatalf("coverage trigger = %q, want scheduled", snapshot.Coverage.Trigger)
	}

	var c models.CloudConnector
	if err := db.Where("workspace_id = ? AND id = ?", ws, connectorID).First(&c).Error; err != nil {
		t.Fatal(err)
	}
	if err := c.SetGCPAttrs(c.GCPAttrs()); err != nil { // what verify does
		t.Fatal(err)
	}
	if len(c.GCPAttrs().ScopeTree) == 0 {
		t.Fatal("scope_tree was dropped by an attrs round trip")
	}
}
