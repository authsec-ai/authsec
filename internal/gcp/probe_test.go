package gcp

import (
	"context"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/models"
)

// TestProbeReaderCapabilities_AllSurfacesPresent pins the invariant the whole
// coverage story rests on: every surface appears in the profile, always. A
// surface that is simply absent is indistinguishable from one nobody thought
// to check, and a scan reading that row would have no way to tell "we looked
// and found nothing" from "we never looked".
func TestProbeReaderCapabilities_AllSurfacesPresent(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()

	got, err := ProbeReaderCapabilities(context.Background(), f.rmClient(t), models.CloudScopeProject, "p1")
	if err != nil {
		t.Fatalf("ProbeReaderCapabilities: %v", err)
	}
	for _, surface := range AllSurfaces {
		if _, ok := got.Surfaces[surface]; !ok {
			t.Errorf("surface %q missing from the profile", surface)
		}
	}
	if len(got.Surfaces) != len(AllSurfaces) {
		t.Errorf("profile has %d surfaces, want %d", len(got.Surfaces), len(AllSurfaces))
	}
}

// TestProbeReaderCapabilities_MissingPermissionIsNotUnknown separates the two
// negative answers. A permission the reader provably lacks makes the surface
// unreachable and NAMES what is missing; it must not be reported as unknown,
// which would imply we could not check.
func TestProbeReaderCapabilities_MissingPermissionIsNotUnknown(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()
	f.deniedPermissions["iam.serviceAccountKeys.list"] = true

	got, err := ProbeReaderCapabilities(context.Background(), f.rmClient(t), models.CloudScopeProject, "p1")
	if err != nil {
		t.Fatalf("ProbeReaderCapabilities: %v", err)
	}

	keys := got.Surfaces[SurfaceKeys]
	if keys.Can {
		t.Error("keys surface reported reachable despite a denied permission")
	}
	if keys.Unknown {
		t.Error("a provably denied permission must be Can=false, not Unknown -- unknown means we could not look")
	}
	if len(keys.Missing) != 1 || keys.Missing[0] != "iam.serviceAccountKeys.list" {
		t.Errorf("missing = %v, want exactly the denied permission", keys.Missing)
	}

	// A denial on one surface must not leak into another.
	if ids := got.Surfaces[SurfaceIdentities]; !ids.Can {
		t.Errorf("identities surface should be unaffected, got %+v", ids)
	}
}

// TestProbeReaderCapabilities_RejectedPermissionIsUnknownNotDenied is the
// three-state rule under load.
//
// testIamPermissions refuses the WHOLE call with 400 when a permission name
// does not apply to the resource type being tested -- it does not skip the
// name. Reporting that surface as unreachable would be a fabrication: we
// learned nothing about the reader's access. It must come back unknown, with
// a reason that points at our own permission list rather than at the
// customer's policy.
func TestProbeReaderCapabilities_RejectedPermissionIsUnknownNotDenied(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()
	f.rejectedPermissions["agentregistry.agents.list"] = true

	got, err := ProbeReaderCapabilities(context.Background(), f.rmClient(t), models.CloudScopeProject, "p1")
	if err != nil {
		t.Fatalf("ProbeReaderCapabilities: %v", err)
	}

	reg := got.Surfaces[SurfaceRegistry]
	if !reg.Unknown {
		t.Errorf("a rejected permission name must leave the surface unknown, got %+v", reg)
	}
	if reg.Can {
		t.Error("an unknown surface must not also claim to be reachable")
	}
	if reg.Reason != "permission_not_applicable_at_this_scope" {
		t.Errorf("reason = %q, want the 400-specific reason so an operator knows to look at our list, not their policy", reg.Reason)
	}

	// Every other surface still answered.
	if ids := got.Surfaces[SurfaceIdentities]; ids.Unknown {
		t.Error("one rejected surface must not make the rest unknown")
	}
}

// TestProbeReaderCapabilities_ZeroWriteAssertion is E4.3: the probe must
// actually notice a write permission rather than trusting that the granted
// roles are all named "viewer".
func TestProbeReaderCapabilities_ZeroWriteAssertion(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()
	// The fake allows everything it is not told to deny, so a bare run is the
	// worst case: the reader holds every write permission we ask about.
	got, err := ProbeReaderCapabilities(context.Background(), f.rmClient(t), models.CloudScopeProject, "p1")
	if err != nil {
		t.Fatalf("ProbeReaderCapabilities: %v", err)
	}
	if len(got.WriteHeld) == 0 {
		t.Fatal("probe reported no write permissions against a server that grants everything -- the write probe is not running")
	}
	if got.Clean() {
		t.Error("Clean() must be false when write permissions are held")
	}

	// And the clean case: deny every write permission, allow the rest.
	f2 := newFakeProvisionServer()
	defer f2.Close()
	for _, p := range writePermissionProbe {
		f2.deniedPermissions[p] = true
	}
	clean, err := ProbeReaderCapabilities(context.Background(), f2.rmClient(t), models.CloudScopeProject, "p1")
	if err != nil {
		t.Fatalf("ProbeReaderCapabilities: %v", err)
	}
	if len(clean.WriteHeld) != 0 {
		t.Errorf("write permissions held = %v, want none", clean.WriteHeld)
	}
	if !clean.Clean() {
		t.Error("Clean() must be true when nothing writable is held and the check ran")
	}
}

// TestProbeResult_CleanRequiresTheCheckToHaveRun guards against the quiet
// failure mode where a write probe that never completed reads as a pass. An
// empty result from a check that could not run has cleared nothing.
func TestProbeResult_CleanRequiresTheCheckToHaveRun(t *testing.T) {
	if (ProbeResult{WriteCheckUnknown: true}).Clean() {
		t.Error("a write check that could not run must not report clean")
	}
	if !(ProbeResult{}).Clean() {
		t.Error("no write permissions and a completed check is the clean case")
	}
}

// TestProbeReaderCapabilities_HeldIsDeduplicatedAndSorted keeps the recorded
// permission list stable. resourcemanager.projects.getIamPolicy is needed by
// two surfaces, so without dedup it would appear twice and the row would
// churn between writes for no reason.
func TestProbeReaderCapabilities_HeldIsDeduplicatedAndSorted(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()

	got, err := ProbeReaderCapabilities(context.Background(), f.rmClient(t), models.CloudScopeProject, "p1")
	if err != nil {
		t.Fatalf("ProbeReaderCapabilities: %v", err)
	}
	seen := map[string]bool{}
	for i, p := range got.Held {
		if seen[p] {
			t.Errorf("permission %q appears more than once in Held", p)
		}
		seen[p] = true
		if i > 0 && got.Held[i-1] > p {
			t.Errorf("Held is not sorted at index %d: %q before %q", i, got.Held[i-1], p)
		}
	}
	if !seen["resourcemanager.projects.getIamPolicy"] {
		t.Error("expected the permission shared by two surfaces to be recorded once")
	}
}

// TestProbeReaderCapabilities_RejectsMalformedScope proves the one case that
// IS an error rather than an unknown: a scope kind the probe cannot address at
// all is a caller bug, not something to report as a customer condition.
func TestProbeReaderCapabilities_RejectsMalformedScope(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()

	if _, err := ProbeReaderCapabilities(context.Background(), f.rmClient(t), "subscription", "s1"); err == nil {
		t.Fatal("expected an error for a scope kind GCP has no surface for")
	}
}

// TestChunkPermissions_RespectsTheBatchCeiling covers the documented
// 100-permission limit on one testIamPermissions call.
func TestChunkPermissions_RespectsTheBatchCeiling(t *testing.T) {
	big := make([]string, 250)
	for i := range big {
		big[i] = "perm"
	}
	chunks := chunkPermissions(big, testIamPermissionsBatchSize)
	if len(chunks) != 3 {
		t.Fatalf("250 permissions split into %d chunks, want 3", len(chunks))
	}
	total := 0
	for _, c := range chunks {
		if len(c) > testIamPermissionsBatchSize {
			t.Errorf("chunk of %d exceeds the %d ceiling", len(c), testIamPermissionsBatchSize)
		}
		total += len(c)
	}
	if total != len(big) {
		t.Errorf("chunking lost permissions: %d of %d", total, len(big))
	}

	// A list under the ceiling stays one call rather than becoming none.
	if got := chunkPermissions([]string{"a"}, 100); len(got) != 1 || len(got[0]) != 1 {
		t.Errorf("small list chunked to %v", got)
	}
}

// TestSurfacePermissions_EverySurfaceHasPermissions stops a surface being
// added to AllSurfaces without anything to probe, which would silently report
// it reachable (no permissions missing) forever.
func TestSurfacePermissions_EverySurfaceHasPermissions(t *testing.T) {
	for _, surface := range AllSurfaces {
		if len(surfacePermissions[surface]) == 0 {
			t.Errorf("surface %q has no permissions to probe, so it would always report reachable", surface)
		}
	}
}

/* -------------------------- quota project (ONB-5) ---------------------------- */

// TestQuotaProjectUsable_ProbesTheQuotaProjectNotTheScope is the point of the
// whole function. The reader project may sit outside the onboarded scope, and
// when it does the reader roles bound at the scope grant nothing on it -- so a
// probe aimed at the scope would report success while every Cloud Asset call
// still failed.
func TestQuotaProjectUsable_ProbesTheQuotaProjectNotTheScope(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()

	usable, known := QuotaProjectUsable(context.Background(), f.rmClient(t), "quota-proj")
	if !known {
		t.Fatal("probe should have been able to answer against a working server")
	}
	if !usable {
		t.Error("expected usable when the permission is held")
	}

	// The call must have been addressed to the quota project, not to whatever
	// scope happens to be onboarded.
	var sawQuotaProject bool
	for _, c := range f.recorded() {
		if strings.Contains(c, "/projects/quota-proj:testIamPermissions") {
			sawQuotaProject = true
		}
	}
	if !sawQuotaProject {
		t.Errorf("probe did not target the quota project; calls were %v", f.recorded())
	}
}

// TestQuotaProjectUsable_DeniedIsKnownAndUnusable covers the failure this
// exists to catch: the permission genuinely absent on the quota project.
func TestQuotaProjectUsable_DeniedIsKnownAndUnusable(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()
	f.deniedPermissions["serviceusage.services.use"] = true

	usable, known := QuotaProjectUsable(context.Background(), f.rmClient(t), "quota-proj")
	if !known {
		t.Error("a clean answer of 'not held' is known, not unknown")
	}
	if usable {
		t.Error("expected unusable when serviceusage.services.use is denied")
	}
}

// TestQuotaProjectUsable_UnansweredIsNotAFailure keeps could-not-check apart
// from does-not-hold. Marking a connector permanently limited on the strength
// of a probe that never ran would be as wrong as assuming it is fine.
func TestQuotaProjectUsable_UnansweredIsNotAFailure(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()
	f.rejectedPermissions["serviceusage.services.use"] = true

	usable, known := QuotaProjectUsable(context.Background(), f.rmClient(t), "quota-proj")
	if known {
		t.Error("a rejected check must report unknown")
	}
	if usable {
		t.Error("unknown must not report usable")
	}
}

// TestQuotaProjectUsable_EmptyIsADefiniteNo. No quota project at all is not an
// unanswerable question -- it is a definite failure, and Cloud Asset cannot
// bill against nothing.
func TestQuotaProjectUsable_EmptyIsADefiniteNo(t *testing.T) {
	f := newFakeProvisionServer()
	defer f.Close()

	usable, known := QuotaProjectUsable(context.Background(), f.rmClient(t), "")
	if !known || usable {
		t.Errorf("empty quota project: usable=%v known=%v, want false/true", usable, known)
	}
}
