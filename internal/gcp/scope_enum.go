package gcp

import (
	"context"

	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v3"
)

/* scope_enum.go answers one question for a connector onboarded at an
   organization or a folder: can the reader actually see what is underneath it?

   Onboarding proves it can read the top scope and stops there. For a project
   that is the whole story. For an org it is barely the beginning — an org
   connector whose reader cannot enumerate folders or projects can read exactly
   one resource, and a scan built on it would report an almost empty estate
   without anything being wrong with the scan.

   This does not walk the tree. Walking is a scan concern and is bounded by
   MaxFolderDepth and MaxFoldersPerParent (scope.go). All onboarding owes
   discovery is whether the walk is possible at all, recorded before the first
   scan rather than inferred from its results. */

// How the reader is able to walk the scope tree below the onboarded scope.
const (
	// ScopeEnumNone: neither route works — or, when Unknown is set, neither
	// route could be checked. Read the flag, not just this value.
	ScopeEnumNone = "none"
	// ScopeEnumRMList: Resource Manager listing, parent by parent.
	// Authoritative and immediate, but one call per parent.
	ScopeEnumRMList = "rm_list"
	// ScopeEnumCAISearch: one Cloud Asset search across the whole scope.
	// Cheap and broad, but Cloud Asset lags reality.
	ScopeEnumCAISearch = "cai_search"
	// ScopeEnumBoth: either route is open, so a scan can use Cloud Asset for
	// breadth and fall back to Resource Manager where it needs authority.
	ScopeEnumBoth = "both"
)

// ScopeEnumeration is how, and whether, the reader can enumerate the tree
// below the onboarded scope.
type ScopeEnumeration struct {
	Via string `json:"via"`

	// RMList and CAISearch are kept as separate booleans rather than collapsed
	// into Via alone. A scan choosing a strategy needs to know which specific
	// route is open, not just that one of them is.
	RMList    bool `json:"rm_list"`
	CAISearch bool `json:"cai_search"`

	// Unknown is set when NEITHER route could be checked. Via reads "none" in
	// that case, and it means "we could not find out", not "there is no way
	// in" — the difference between a connector worth investigating and one
	// worth re-granting.
	Unknown bool `json:"unknown,omitempty"`
}

// Usable reports whether at least one enumeration route is open. An unknown
// result is not usable, but it is also not proof of the opposite.
func (s ScopeEnumeration) Usable() bool { return s.RMList || s.CAISearch }

// ProbeScopeEnumeration checks BOTH routes, independently.
//
// They really are independent. resourcemanager.folders.list is evaluated per
// parent, while a Cloud Asset search needs one permission across the whole
// scope — so a principal can hold either without the other, and the two routes
// can give different answers to "what is under here". Recording a single
// boolean would hide that, and a scan would find out the hard way.
//
// Neither check failing is recorded as unknown rather than as "no access",
// for the same reason everywhere else in this package: a question we could not
// ask has no answer, and inventing "no" for it produces a report that reads
// exactly like the truth while being wrong.
func ProbeScopeEnumeration(ctx context.Context, rm *cloudresourcemanager.Service, scopeKind, scopeID string) ScopeEnumeration {
	var out ScopeEnumeration

	rmAllowed, rmErr := testAllowedPermissions(ctx, rm, scopeKind, scopeID,
		[]string{"resourcemanager.folders.list", "resourcemanager.projects.list"})
	caiAllowed, caiErr := testAllowedPermissions(ctx, rm, scopeKind, scopeID,
		[]string{"cloudasset.assets.searchAllResources"})

	if rmErr == nil {
		// Either permission is enough to make progress: a folder-only listing
		// still walks the tree, and a project-only one still finds the leaves.
		out.RMList = containsString(rmAllowed, "resourcemanager.folders.list") ||
			containsString(rmAllowed, "resourcemanager.projects.list")
	}
	if caiErr == nil {
		out.CAISearch = containsString(caiAllowed, "cloudasset.assets.searchAllResources")
	}
	out.Unknown = rmErr != nil && caiErr != nil

	switch {
	case out.RMList && out.CAISearch:
		out.Via = ScopeEnumBoth
	case out.RMList:
		out.Via = ScopeEnumRMList
	case out.CAISearch:
		out.Via = ScopeEnumCAISearch
	default:
		out.Via = ScopeEnumNone
	}
	return out
}
