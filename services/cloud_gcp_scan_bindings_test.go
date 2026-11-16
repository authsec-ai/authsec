package services

import (
	"fmt"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/authsec-ai/authsec/models"
	"google.golang.org/api/cloudasset/v1"
)

func TestBindingScope(t *testing.T) {
	for kind, want := range map[string]string{
		models.CloudScopeOrg:     "organizations/1",
		models.CloudScopeFolder:  "folders/1",
		models.CloudScopeProject: "projects/1",
	} {
		got, err := gcpBindingScope(kind, "1")
		if err != nil || got != want {
			t.Errorf("%s: %q %v", kind, got, err)
		}
	}
	if _, err := gcpBindingScope("account", "1"); err == nil {
		t.Error("a non-GCP scope kind must be refused")
	}
}

// The same member holding the same role under two conditions must not collide.
func TestBindingNativeID_DistinguishesConditions(t *testing.T) {
	a := gcp.ParseCondition("a", "", `request.time < timestamp("2027-06-30T00:00:00Z")`)
	b := gcp.ParseCondition("b", "", `request.time < timestamp("2026-01-01T00:00:00Z")`)
	at := "//cloudresourcemanager.googleapis.com/projects/p"
	idA, idB := gcpBindingNativeID(at, "roles/x", a), gcpBindingNativeID(at, "roles/x", b)
	plain := gcpBindingNativeID(at, "roles/x", nil)
	if idA == idB || idA == plain || idB == plain {
		t.Fatalf("native ids collide: %q %q %q", idA, idB, plain)
	}
	if !strings.HasPrefix(plain, "//gcp/binding/") {
		t.Fatalf("native id is not namespaced: %q", plain)
	}
	if plain != gcpBindingNativeID(at, "roles/x", nil) {
		t.Fatal("native id must be stable across scans")
	}
}

func TestAncestors(t *testing.T) {
	// A project policy: its own project is not its ancestor.
	proj := &cloudasset.IamPolicySearchResult{
		Resource: "//cloudresourcemanager.googleapis.com/projects/my-proj", Project: "projects/123",
		Folders: []string{"folders/9"}, Organization: "organizations/7",
	}
	if got := gcpAncestors(proj, gcp.KindProject); strings.Join(got, ",") != "folders/9,organizations/7" {
		t.Fatalf("project ancestors = %v", got)
	}
	// A folder policy: itself excluded.
	folder := &cloudasset.IamPolicySearchResult{
		Resource: "//cloudresourcemanager.googleapis.com/folders/9",
		Folders:  []string{"folders/9", "folders/8"}, Organization: "organizations/7",
	}
	if got := gcpAncestors(folder, gcp.KindFolder); strings.Join(got, ",") != "folders/8,organizations/7" {
		t.Fatalf("folder ancestors = %v", got)
	}
	// An organization policy has none.
	org := &cloudasset.IamPolicySearchResult{
		Resource: "//cloudresourcemanager.googleapis.com/organizations/7", Organization: "organizations/7",
	}
	if got := gcpAncestors(org, gcp.KindOrganization); len(got) != 0 {
		t.Fatalf("org ancestors = %v", got)
	}
	// A resource: project first.
	bucket := &cloudasset.IamPolicySearchResult{
		Resource: "//storage.googleapis.com/projects/_/buckets/b", Project: "projects/123",
		Folders: []string{"folders/9"}, Organization: "organizations/7",
	}
	if got := gcpAncestors(bucket, gcp.KindGCSBucket); strings.Join(got, ",") != "projects/123,folders/9,organizations/7" {
		t.Fatalf("resource ancestors = %v", got)
	}
}

func TestProjectOutsideScope(t *testing.T) {
	known := []gcpProject{{ProjectID: "dev", Number: "1"}, {ProjectID: "prod", Number: "2"}}
	if gcpProjectOutsideScope("1", known) || gcpProjectOutsideScope("prod", known) {
		t.Fatal("scanned projects are inside, by number or id")
	}
	if !gcpProjectOutsideScope("999", known) {
		t.Fatal("an unmatched project is outside when every number is known")
	}
	partial := []gcpProject{{ProjectID: "dev"}}
	if gcpProjectOutsideScope("999", partial) {
		t.Fatal("with a number unknown, nothing is shown to be outside")
	}
	if gcpProjectOutsideScope("", known) || gcpProjectOutsideScope("999", nil) {
		t.Fatal("nothing to compare means not external")
	}
}

func TestPermissionSensitivity(t *testing.T) {
	cases := []struct {
		role    string
		actions []string
		kind    string
		want    string
	}{
		{"roles/owner", nil, gcp.KindProject, "high"},
		{"roles/editor", nil, gcp.KindProject, "high"},
		{"roles/storage.admin", []string{"storage.objects.delete"}, gcp.KindProject, "high"},
		{"projects/p/roles/igaDeployer", []string{"iam.serviceAccounts.actAs"}, gcp.KindProject, "high"},
		{"roles/viewer", nil, gcp.KindProject, "low"},
		{"roles/pubsub.viewer", []string{"pubsub.topics.get"}, gcp.KindPubSubTopic, "low"},
		{"roles/storage.objectViewer", []string{"storage.objects.get"}, gcp.KindGCSBucket, "med"},
		{"roles/pubsub.editor", []string{"pubsub.topics.update"}, gcp.KindProject, "med"},
		{"roles/secretmanager.secretAccessor", []string{"secretmanager.versions.access"}, gcp.KindSecret, "high"},
	}
	for _, c := range cases {
		if got := gcpPermissionSensitivity(c.role, c.actions, c.kind); got != c.want {
			t.Errorf("%s on %s = %s, want %s", c.role, c.kind, got, c.want)
		}
	}
}

// A binding member we could not parse is a row we did not write: unknown, which
// blocks Complete(); it is not denied (no role fixes it) and never reached.
func TestClassify_UnparsedMembersAndBindingPageCap(t *testing.T) {
	for name, err := range map[string]error{
		"unparsed": fmt.Errorf("%w: 2 member(s)", errGCPMembersUnparsed),
		"page cap": errGCPBindingsTruncated,
		"roles":    gcp.ErrRolePagesExceeded,
	} {
		if got := classifyGCPSurfaceError(err); got != models.CloudCoverageUnknown {
			t.Errorf("%s classified %q, want unknown", name, got)
		}
	}
}

// Both binding surfaces ride one read, so a cut-short read leaves both not
// reached and the report incomplete -- nothing reconciles.
func TestBindingSurfaces_FailTogetherAndBlockReconcile(t *testing.T) {
	accs := newGCPBindingAccs()
	accs.roles.observe(nil, 3)
	accs.allow.observe(errGCPBindingsTruncated, 10)
	accs.resource.observe(errGCPBindingsTruncated, 4)
	cov := coverageOf([]gcpNamedAcc{
		{surface: gcp.SurfaceIdentities, counter: "identities_upserted", acc: reachedAcc(1)},
		{surface: gcp.SurfaceRoles, counter: "roles_resolved", acc: accs.roles},
		{surface: gcp.SurfaceAllowBindings, counter: "allow_bindings_upserted", acc: accs.allow},
		{surface: gcp.SurfaceResourceIAM, counter: "resource_iam_upserted", acc: accs.resource},
	})
	if cov.Complete() {
		t.Fatal("a page-capped binding read must not be Complete()")
	}
	if gcpAllReached(cov, []string{gcp.SurfaceAllowBindings}) || gcpAllReached(cov, []string{gcp.SurfaceResourceIAM}) {
		t.Fatal("neither binding surface may be reached")
	}
	if gcpAllReached(cov, []string{gcp.SurfaceAllowBindings, gcp.SurfaceResourceIAM}) {
		t.Fatal("permissions must not reconcile")
	}
}

// The skip is sticky and does not block Complete: a probe-proven unreadable
// bindings surface leaves the rest of the scan reconcilable.
func TestBindingSurfacesSkippedDoNotBlockComplete(t *testing.T) {
	accs := newGCPBindingAccs()
	accs.roles.skipNotReadable("not_readable")
	accs.allow.skipNotReadable("not_readable")
	accs.resource.skipNotReadable("not_readable")
	cov := coverageOf([]gcpNamedAcc{
		{surface: gcp.SurfaceIdentities, counter: "identities_upserted", acc: reachedAcc(1)},
		{surface: gcp.SurfaceRoles, counter: "roles_resolved", acc: accs.roles},
		{surface: gcp.SurfaceAllowBindings, counter: "allow_bindings_upserted", acc: accs.allow},
		{surface: gcp.SurfaceResourceIAM, counter: "resource_iam_upserted", acc: accs.resource},
	})
	if !cov.Complete() {
		t.Fatalf("not_selected surfaces must not block Complete(): %+v", cov.Surfaces)
	}
	if gcpAllReached(cov, []string{gcp.SurfaceAllowBindings, gcp.SurfaceResourceIAM}) {
		t.Fatal("a skipped surface is not reached: permissions must not reconcile")
	}
}

// A denied/skipped bindings read must protect every member row, or the identities
// reconcile deletes them all.
func TestCredentialReconcileSkip_ProtectsMembersWhenBindingsNotReached(t *testing.T) {
	cov := func(state string) models.ScanCoverage {
		return models.ScanCoverage{Surfaces: map[string]models.SurfaceCoverage{
			gcp.SurfaceHMACKeys:      {State: models.CloudCoverageReached},
			gcp.SurfaceAPIKeys:       {State: models.CloudCoverageReached},
			gcp.SurfaceAllowBindings: {State: state},
			gcp.SurfaceResourceIAM:   {State: models.CloudCoverageReached},
		}}
	}
	reached := gcpCredentialReconcileSkip(cov(models.CloudCoverageReached))
	if len(reached.IdentityKinds)+len(reached.IdentityNativePrefixes) != 0 {
		t.Fatalf("bindings reached: nothing protected, got %+v", reached)
	}
	for _, state := range []string{models.CloudCoverageNotSelected, models.CloudCoverageUnknown, models.CloudCoverageDenied} {
		s := gcpCredentialReconcileSkip(cov(state))
		have := map[string]bool{}
		for _, k := range s.IdentityKinds {
			have[k] = true
		}
		for _, want := range gcpMemberIdentityKinds {
			if !have[want] {
				t.Errorf("%s: kind %s not protected", state, want)
			}
		}
		if len(s.IdentityNativePrefixes) == 0 || s.IdentityNativePrefixes[0] != "//gcp/principal/" {
			t.Errorf("%s: principal prefix not protected: %+v", state, s)
		}
		if have[models.CloudIdentityGCPServiceAccount] {
			t.Errorf("%s: real service accounts must still reconcile", state)
		}
	}
	// An absent surface was never attempted.
	s := gcpCredentialReconcileSkip(models.ScanCoverage{Surfaces: map[string]models.SurfaceCoverage{}})
	if len(s.IdentityKinds) < len(gcpMemberIdentityKinds) {
		t.Fatalf("absent bindings surface must protect member kinds: %+v", s)
	}
}

func TestBindingSurfacesProbeGating(t *testing.T) {
	attrs := models.GCPConnectorAttrs{CapabilityProfile: map[string]models.GCPSurfaceCapability{
		// The probe asks about searchAllResources for resource_iam, which the
		// collector never calls: it must not skip the surface.
		gcp.SurfaceResourceIAM:   {Can: false, Missing: []string{"cloudasset.assets.searchAllResources"}},
		gcp.SurfaceAllowBindings: {Can: false, Missing: []string{"cloudasset.assets.searchAllIamPolicies"}},
		gcp.SurfaceRoles:         {Can: false, Missing: []string{"iam.roles.get"}},
	}}
	if _, skip := gcpProbeSaysUnreadable(attrs, gcp.SurfaceResourceIAM); skip {
		t.Fatal("resource_iam gated on a permission its collector does not call")
	}
	if _, skip := gcpProbeSaysUnreadable(attrs, gcp.SurfaceAllowBindings); !skip {
		t.Fatal("a missing searchAllIamPolicies must skip allow_bindings")
	}
	if _, skip := gcpProbeSaysUnreadable(attrs, gcp.SurfaceRoles); !skip {
		t.Fatal("a missing roles.get is a permission the roles collector calls")
	}
}

func TestMissingQuotaProjectIsNotReached(t *testing.T) {
	accs := newGCPBindingAccs()
	accs.allow.fail(errGCPNoQuotaProject)
	if accs.allow.reachedEverything() {
		t.Fatal("a missing quota project must not read as reached")
	}
}
