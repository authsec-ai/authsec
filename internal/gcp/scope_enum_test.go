package gcp

import (
	"context"
	"testing"

	"github.com/authsec-ai/authsec/models"
)

// TestProbeScopeEnumeration_BothRoutesOpen is the ordinary case: a reader with
// the full P1 set can walk the tree either way.
func TestProbeScopeEnumeration_BothRoutesOpen(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()

	got := ProbeScopeEnumeration(context.Background(), f.rmClient(t), models.CloudScopeOrg, "123")
	if got.Via != ScopeEnumBoth {
		t.Errorf("via = %q, want %q", got.Via, ScopeEnumBoth)
	}
	if !got.RMList || !got.CAISearch {
		t.Errorf("expected both routes open, got %+v", got)
	}
	if got.Unknown {
		t.Error("a fully answered probe must not be unknown")
	}
	if !got.Usable() {
		t.Error("Usable() should be true when a route is open")
	}
}

// TestProbeScopeEnumeration_RoutesAreIndependent is the reason both are probed
// separately. resourcemanager.folders.list is granted per parent while a Cloud
// Asset search needs one permission across the scope, so a principal can hold
// either without the other -- and the two routes then give different answers
// to "what is under here".
func TestProbeScopeEnumeration_RoutesAreIndependent(t *testing.T) {
	caiOnly := newFakeProvisionServer()
	defer caiOnly.Close()
	caiOnly.deniedPermissions["resourcemanager.folders.list"] = true
	caiOnly.deniedPermissions["resourcemanager.projects.list"] = true

	got := ProbeScopeEnumeration(context.Background(), caiOnly.rmClient(t), models.CloudScopeOrg, "123")
	if got.Via != ScopeEnumCAISearch {
		t.Errorf("via = %q, want %q", got.Via, ScopeEnumCAISearch)
	}
	if got.RMList {
		t.Error("Resource Manager listing should be closed")
	}

	rmOnly := newFakeProvisionServer()
	defer rmOnly.Close()
	rmOnly.deniedPermissions["cloudasset.assets.searchAllResources"] = true

	got = ProbeScopeEnumeration(context.Background(), rmOnly.rmClient(t), models.CloudScopeOrg, "123")
	if got.Via != ScopeEnumRMList {
		t.Errorf("via = %q, want %q", got.Via, ScopeEnumRMList)
	}
	if got.CAISearch {
		t.Error("Cloud Asset search should be closed")
	}
}

// TestProbeScopeEnumeration_FolderListAloneIsEnough: either listing permission
// makes progress, so holding only one must not report the route closed.
func TestProbeScopeEnumeration_FolderListAloneIsEnough(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()
	f.deniedPermissions["resourcemanager.projects.list"] = true
	f.deniedPermissions["cloudasset.assets.searchAllResources"] = true

	got := ProbeScopeEnumeration(context.Background(), f.rmClient(t), models.CloudScopeOrg, "123")
	if !got.RMList {
		t.Errorf("folders.list alone should keep the Resource Manager route open, got %+v", got)
	}
}

// TestProbeScopeEnumeration_NoRouteIsKnownNotUnknown separates a reader that
// provably cannot enumerate from one we could not ask.
func TestProbeScopeEnumeration_NoRouteIsKnownNotUnknown(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()
	for _, p := range []string{
		"resourcemanager.folders.list",
		"resourcemanager.projects.list",
		"cloudasset.assets.searchAllResources",
	} {
		f.deniedPermissions[p] = true
	}

	got := ProbeScopeEnumeration(context.Background(), f.rmClient(t), models.CloudScopeOrg, "123")
	if got.Via != ScopeEnumNone {
		t.Errorf("via = %q, want %q", got.Via, ScopeEnumNone)
	}
	if got.Unknown {
		t.Error("a clean 'neither permission held' answer is known, not unknown")
	}
	if got.Usable() {
		t.Error("Usable() must be false when no route is open")
	}
}

// TestProbeScopeEnumeration_UnaskableIsUnknown: when neither check could run,
// via reads "none" but Unknown says why. Treating that as a closed tree would
// mark a working connector unenumerable on the strength of a probe that never
// happened.
func TestProbeScopeEnumeration_UnaskableIsUnknown(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()
	for _, p := range []string{
		"resourcemanager.folders.list",
		"cloudasset.assets.searchAllResources",
	} {
		f.rejectedPermissions[p] = true
	}

	got := ProbeScopeEnumeration(context.Background(), f.rmClient(t), models.CloudScopeOrg, "123")
	if !got.Unknown {
		t.Errorf("both checks rejected should be unknown, got %+v", got)
	}
	if got.Via != ScopeEnumNone {
		t.Errorf("via = %q, want %q alongside Unknown", got.Via, ScopeEnumNone)
	}
}

// TestHierarchyLimits_MatchGoogleDocumentedCeilings pins the recursion guards
// so a walk imports them rather than inventing its own.
func TestHierarchyLimits_MatchGoogleDocumentedCeilings(t *testing.T) {
	if MaxFolderDepth != 10 {
		t.Errorf("MaxFolderDepth = %d, want 10", MaxFolderDepth)
	}
	if MaxFoldersPerParent != 300 {
		t.Errorf("MaxFoldersPerParent = %d, want 300", MaxFoldersPerParent)
	}
}
