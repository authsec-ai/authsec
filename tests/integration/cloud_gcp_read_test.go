package integration

import (
	"context"
	"strings"
	"testing"

	repositories "github.com/authsec-ai/authsec/repository"
)

// The Google Cloud console reads (GET /gcp/identities, /gcp/bindings,
// /gcp/resources). They are the other half of the rule that keeps GCP rows out
// of the AWS lists, so they must return GCP rows -- and only the caller's.

func TestGCPRead_ListsGCPRowsWithNames(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "gcp-read")
	f := newFakeGCPDiscovery()
	defer f.Close()
	gcp3Fixture(f)
	connectorID := gcpScanConnector(t, db, ws, gcp3Project)
	if _, err := gcpScanner(t, db, f).Scan(context.Background(), ws, connectorID); err != nil {
		t.Fatalf("scan: %v", err)
	}
	repo := repositories.NewCloudGCPReadRepository(db)

	ids, total, err := repo.ListIdentities(ws, repositories.GCPIdentityFilter{})
	if err != nil || total == 0 || len(ids) == 0 {
		t.Fatalf("identities = %d/%d, %v", len(ids), total, err)
	}
	for _, i := range ids {
		if !strings.HasPrefix(i.Kind, "gcp_") {
			t.Fatalf("non-GCP identity kind %q in the GCP list", i.Kind)
		}
	}
	deleted, _, err := repo.ListIdentities(ws, repositories.GCPIdentityFilter{Kinds: []string{"gcp_deleted"}})
	if err != nil || len(deleted) != 1 {
		t.Fatalf("kind filter gcp_deleted = %d, %v", len(deleted), err)
	}

	bindings, btotal, err := repo.ListBindings(ws, repositories.GCPBindingFilter{})
	if err != nil || btotal != int64(gcp3ProjectRows+gcp3ResourceRows) {
		t.Fatalf("bindings = %d (total %d), %v; want %d", len(bindings), btotal, err, gcp3ProjectRows+gcp3ResourceRows)
	}
	var onResource int
	for _, b := range bindings {
		if b.IdentityKind == "" || b.IdentityNativeID == "" {
			t.Fatalf("binding %s has no holder name/kind", b.NativeID)
		}
		if b.ResourceID != nil {
			onResource++
			if b.ResourceKind == "" || b.ResourceNativeID == "" {
				t.Fatalf("resource binding %s has no resource name/kind", b.NativeID)
			}
		}
	}
	if onResource != gcp3ResourceRows {
		t.Fatalf("resource-level bindings = %d, want %d", onResource, gcp3ResourceRows)
	}

	// Narrowing by holder returns only that holder's rows.
	byHolder, _, err := repo.ListBindings(ws, repositories.GCPBindingFilter{IdentityID: &bindings[0].IdentityID})
	if err != nil || len(byHolder) == 0 {
		t.Fatalf("by identity = %d, %v", len(byHolder), err)
	}
	for _, b := range byHolder {
		if b.IdentityID != bindings[0].IdentityID {
			t.Fatal("identity filter returned another holder's binding")
		}
	}

	res, rtotal, err := repo.ListResources(ws, repositories.GCPIdentityFilter{})
	if err != nil || rtotal == 0 {
		t.Fatalf("resources = %d, %v", rtotal, err)
	}
	for _, r := range res {
		if r.BindingCount == 0 {
			t.Fatalf("resource %s has binding_count 0: it exists only because a binding names it", r.NativeID)
		}
	}
}

func TestGCPRead_IsWorkspaceScoped(t *testing.T) {
	db := igaDB(t)
	wsA := newWorkspace(t, db, "gcp-read-iso-a")
	wsB := newWorkspace(t, db, "gcp-read-iso-b")
	f := newFakeGCPDiscovery()
	defer f.Close()
	gcp3Fixture(f)
	connectorA := gcpScanConnector(t, db, wsA, gcp3Project)
	if _, err := gcpScanner(t, db, f).Scan(context.Background(), wsA, connectorA); err != nil {
		t.Fatal(err)
	}
	repo := repositories.NewCloudGCPReadRepository(db)

	aIDs, _, err := repo.ListIdentities(wsA, repositories.GCPIdentityFilter{})
	if err != nil || len(aIDs) == 0 {
		t.Fatalf("workspace A sees no identities: %v", err)
	}
	aBindings, _, _ := repo.ListBindings(wsA, repositories.GCPBindingFilter{})
	aResources, _, _ := repo.ListResources(wsA, repositories.GCPIdentityFilter{})
	if len(aBindings) == 0 || len(aResources) == 0 {
		t.Fatal("workspace A seed produced no bindings or resources")
	}

	// Workspace B, asking for everything, and asking by A's own ids.
	if rows, n, err := repo.ListIdentities(wsB, repositories.GCPIdentityFilter{}); err != nil || n != 0 || len(rows) != 0 {
		t.Fatalf("B sees %d of A's identities (%v)", n, err)
	}
	if rows, n, _ := repo.ListIdentities(wsB, repositories.GCPIdentityFilter{ID: &aIDs[0].ID, ConnectorID: &connectorA}); n != 0 || len(rows) != 0 {
		t.Fatal("B read A's identity by id")
	}
	if rows, n, _ := repo.ListBindings(wsB, repositories.GCPBindingFilter{}); n != 0 || len(rows) != 0 {
		t.Fatalf("B sees %d of A's bindings", n)
	}
	if rows, n, _ := repo.ListBindings(wsB, repositories.GCPBindingFilter{IdentityID: &aBindings[0].IdentityID, ConnectorID: &connectorA}); n != 0 || len(rows) != 0 {
		t.Fatal("B read A's bindings by identity id")
	}
	if rows, n, _ := repo.ListResources(wsB, repositories.GCPIdentityFilter{ID: &aResources[0].ID}); n != 0 || len(rows) != 0 {
		t.Fatal("B read A's resource by id")
	}
}
