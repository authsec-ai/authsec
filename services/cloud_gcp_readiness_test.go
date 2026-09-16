package services

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/authsec-ai/authsec/models"
)

// readyAttrs is the shape of a connector that has been probed and is fine.
// Tests below degrade one thing at a time from here, so each asserts the
// effect of exactly one condition.
func readyAttrs() models.GCPConnectorAttrs {
	profile := map[string]models.GCPSurfaceCapability{}
	for _, s := range gcp.AllSurfaces {
		profile[s] = models.GCPSurfaceCapability{Can: true}
	}
	enablement := map[string]string{}
	for _, a := range gcp.RequiredServices {
		enablement[a] = gcp.APIStateEnabled
	}
	enum, _ := json.Marshal(gcp.ScopeEnumeration{Via: gcp.ScopeEnumBoth, RMList: true, CAISearch: true})

	return models.GCPConnectorAttrs{
		CapabilityProfile: profile,
		APIEnablement:     enablement,
		ScopeEnumeration:  enum,
	}
}

func hasReason(reasons []string, prefix string) bool {
	for _, r := range reasons {
		if strings.HasPrefix(r, prefix) {
			return true
		}
	}
	return false
}

func TestDeriveGCPReadiness_FullyProbedConnectorIsReady(t *testing.T) {
	got, reasons := DeriveGCPReadiness(readyAttrs(), models.CloudConnectorActive)
	if got != models.GCPReadinessReady {
		t.Errorf("readiness = %q with reasons %v, want %q", got, reasons, models.GCPReadinessReady)
	}
	if len(reasons) != 0 {
		t.Errorf("ready must carry no reasons, got %v", reasons)
	}
}

// TestDeriveGCPReadiness_LaterPhaseSurfacesDoNotCountAgainstReady is the
// judgement call in this function worth pinning. Onboarding does not grant the
// P2/P5/P7 roles, so counting their surfaces would mark every correctly
// onboarded connector partial and make the field meaningless.
func TestDeriveGCPReadiness_LaterPhaseSurfacesDoNotCountAgainstReady(t *testing.T) {
	attrs := readyAttrs()
	for _, s := range []string{gcp.SurfaceDeny, gcp.SurfacePAB, gcp.SurfaceAgents, gcp.SurfaceRegistry, gcp.SurfaceLogs} {
		attrs.CapabilityProfile[s] = models.GCPSurfaceCapability{Can: false, Missing: []string{"something"}}
	}

	got, reasons := DeriveGCPReadiness(attrs, models.CloudConnectorActive)
	if got != models.GCPReadinessReady {
		t.Errorf("readiness = %q with reasons %v; later-phase surfaces must not block ready", got, reasons)
	}
}

func TestDeriveGCPReadiness_UnreachableP1SurfaceIsPartial(t *testing.T) {
	attrs := readyAttrs()
	attrs.CapabilityProfile[gcp.SurfaceIdentities] = models.GCPSurfaceCapability{
		Can: false, Missing: []string{"iam.serviceAccounts.list"},
	}

	got, reasons := DeriveGCPReadiness(attrs, models.CloudConnectorActive)
	if got != models.GCPReadinessPartial {
		t.Errorf("readiness = %q, want %q", got, models.GCPReadinessPartial)
	}
	if !hasReason(reasons, "surface_unreachable:"+gcp.SurfaceIdentities) {
		t.Errorf("reasons = %v, want the unreachable surface named", reasons)
	}
}

// TestDeriveGCPReadiness_UnknownSurfaceIsNeitherReadyNorBlocked is the
// three-state rule reaching the verdict. Unknown must not promise a scan we
// have no evidence can run, and must not refuse one on the strength of a
// question we failed to ask.
func TestDeriveGCPReadiness_UnknownSurfaceIsNeitherReadyNorBlocked(t *testing.T) {
	attrs := readyAttrs()
	attrs.CapabilityProfile[gcp.SurfaceAllowBindings] = models.GCPSurfaceCapability{
		Unknown: true, Reason: "permission_check_denied",
	}

	got, reasons := DeriveGCPReadiness(attrs, models.CloudConnectorActive)
	if got != models.GCPReadinessPartial {
		t.Errorf("readiness = %q, want %q for an unknown surface", got, models.GCPReadinessPartial)
	}
	if !hasReason(reasons, "surface_unknown:") {
		t.Errorf("reasons = %v, want the unknown surface distinguished from an unreachable one", reasons)
	}
	if hasReason(reasons, "surface_unreachable:") {
		t.Error("an unknown surface must not be reported as unreachable")
	}
}

// TestDeriveGCPReadiness_UnusableQuotaProjectBlocks: every Cloud Asset call
// bills against the quota project, so this takes down the whole P1 spine even
// though every permission the reader holds is correct.
func TestDeriveGCPReadiness_UnusableQuotaProjectBlocks(t *testing.T) {
	attrs := readyAttrs()
	attrs.CapabilityLimits = []string{models.GCPLimitQuotaProjectUnusable}

	got, reasons := DeriveGCPReadiness(attrs, models.CloudConnectorActive)
	if got != models.GCPReadinessBlocked {
		t.Errorf("readiness = %q, want %q", got, models.GCPReadinessBlocked)
	}
	if !hasReason(reasons, models.GCPLimitQuotaProjectUnusable) {
		t.Errorf("reasons = %v, want the quota limit named", reasons)
	}
}

func TestDeriveGCPReadiness_RevokedIsBlockedRegardlessOfEvidence(t *testing.T) {
	got, reasons := DeriveGCPReadiness(readyAttrs(), models.CloudConnectorRevoked)
	if got != models.GCPReadinessBlocked {
		t.Errorf("readiness = %q, want %q for a revoked connector", got, models.GCPReadinessBlocked)
	}
	if len(reasons) != 1 || reasons[0] != "connector_revoked" {
		t.Errorf("reasons = %v, want exactly connector_revoked", reasons)
	}
}

// TestDeriveGCPReadiness_NeverProbedIsPartialNotReady. An unprobed connector
// may be perfectly good, but nothing on the row justifies saying so.
func TestDeriveGCPReadiness_NeverProbedIsPartialNotReady(t *testing.T) {
	got, reasons := DeriveGCPReadiness(models.GCPConnectorAttrs{}, models.CloudConnectorActive)
	if got != models.GCPReadinessPartial {
		t.Errorf("readiness = %q, want %q", got, models.GCPReadinessPartial)
	}
	if !hasReason(reasons, "not_probed") {
		t.Errorf("reasons = %v, want not_probed", reasons)
	}
}

// TestDeriveGCPReadiness_DisabledAPIIsPartialAndUnknownAPIIsNotDisabled keeps
// the enablement states apart in the verdict, the same way they are kept apart
// on the row.
func TestDeriveGCPReadiness_DisabledAPIIsPartialAndUnknownAPIIsNotDisabled(t *testing.T) {
	attrs := readyAttrs()
	attrs.APIEnablement["cloudasset.googleapis.com"] = gcp.APIStateNotEnabled
	_, reasons := DeriveGCPReadiness(attrs, models.CloudConnectorActive)
	if !hasReason(reasons, "api_not_enabled:cloudasset.googleapis.com") {
		t.Errorf("reasons = %v, want the disabled API named", reasons)
	}

	attrs2 := readyAttrs()
	attrs2.APIEnablement["cloudasset.googleapis.com"] = gcp.APIStateUnknown
	_, reasons2 := DeriveGCPReadiness(attrs2, models.CloudConnectorActive)
	if !hasReason(reasons2, "api_state_unknown:cloudasset.googleapis.com") {
		t.Errorf("reasons = %v, want the unknown API distinguished from a disabled one", reasons2)
	}
	if hasReason(reasons2, "api_not_enabled:") {
		t.Error("an unknown API state must not be reported as disabled")
	}
}

// TestDeriveGCPReadiness_WritePermissionsSurfaceButDoNotBlock. A reader that
// can delete things is a security finding, not a capability gap -- refusing to
// read the estate would make it no safer -- but readiness is the field people
// look at, so it must not read as unqualified good news.
func TestDeriveGCPReadiness_WritePermissionsSurfaceButDoNotBlock(t *testing.T) {
	attrs := readyAttrs()
	attrs.WritePermissionsHeld = []string{"storage.objects.delete"}

	got, reasons := DeriveGCPReadiness(attrs, models.CloudConnectorActive)
	if got != models.GCPReadinessPartial {
		t.Errorf("readiness = %q, want %q", got, models.GCPReadinessPartial)
	}
	if !hasReason(reasons, "write_permissions_held") {
		t.Errorf("reasons = %v, want the write finding surfaced", reasons)
	}
}

// TestDeriveGCPReadiness_UnknownEnumerationIsNotAFailure: an enumeration probe
// that could not run must not be reported as a tree we cannot walk.
func TestDeriveGCPReadiness_UnknownEnumerationIsNotAFailure(t *testing.T) {
	attrs := readyAttrs()
	attrs.ScopeEnumeration, _ = json.Marshal(gcp.ScopeEnumeration{Via: gcp.ScopeEnumNone, Unknown: true})

	_, reasons := DeriveGCPReadiness(attrs, models.CloudConnectorActive)
	if hasReason(reasons, "scope_not_enumerable") {
		t.Errorf("reasons = %v; an unanswered enumeration probe is not proof the tree is unwalkable", reasons)
	}

	attrs2 := readyAttrs()
	attrs2.ScopeEnumeration, _ = json.Marshal(gcp.ScopeEnumeration{Via: gcp.ScopeEnumNone})
	_, reasons2 := DeriveGCPReadiness(attrs2, models.CloudConnectorActive)
	if !hasReason(reasons2, "scope_not_enumerable") {
		t.Errorf("reasons = %v, want a definite 'no route' reported", reasons2)
	}
}

/* ---------------------------- coverage skeleton ------------------------------ */

// TestNewGCPCoverageSkeleton_ListsEverySurfaceAsUnknown. Coverage used to be
// written as "{}", leaving the first scan to invent the surface list -- and a
// surface absent from that list is indistinguishable from one that was scanned
// and found nothing.
func TestNewGCPCoverageSkeleton_ListsEverySurfaceAsUnknown(t *testing.T) {
	cov := models.DecodeScanCoverage(NewGCPCoverageSkeleton())

	if len(cov.Surfaces) != len(gcp.AllSurfaces) {
		t.Fatalf("skeleton has %d surfaces, want %d", len(cov.Surfaces), len(gcp.AllSurfaces))
	}
	for _, s := range gcp.AllSurfaces {
		got, ok := cov.Surfaces[s]
		if !ok {
			t.Errorf("surface %q missing from the skeleton", s)
			continue
		}
		if got.State != models.CloudCoverageUnknown {
			t.Errorf("surface %q starts as %q, want %q", s, got.State, models.CloudCoverageUnknown)
		}
		if got.Count != 0 {
			t.Errorf("surface %q starts with count %d, want 0", s, got.Count)
		}
	}
	if cov.Generation != 0 {
		t.Errorf("generation = %d, want 0 before any scan", cov.Generation)
	}
}

// TestNewGCPCoverageSkeleton_IsNotComplete. An unscanned connector must never
// satisfy the gate that lets reconciliation age rows out; otherwise a
// brand-new connector could tombstone an estate it has not looked at.
func TestNewGCPCoverageSkeleton_IsNotComplete(t *testing.T) {
	if models.DecodeScanCoverage(NewGCPCoverageSkeleton()).Complete() {
		t.Error("a skeleton with every surface unknown must not report Complete()")
	}
}

/* ----------------------------- onboarding path ------------------------------- */

func TestGCPOnboardingPath_DistinguishesAllThree(t *testing.T) {
	cases := []struct {
		authMethod, provisionedVia, want string
	}{
		{GCPAuthMethodWIF, gcpProvisionedViaGoogleOAuth, models.GCPOnboardingPathOAuthDefault},
		{GCPAuthMethodWIF, "", models.GCPOnboardingPathManualWIF},
		{GCPAuthMethodJSONKey, "", models.GCPOnboardingPathManualKey},
		// A keyed connector is manual_key regardless of provenance: the
		// credential kind is the thing reporting cares about.
		{GCPAuthMethodJSONKey, gcpProvisionedViaGoogleOAuth, models.GCPOnboardingPathManualKey},
	}
	for _, tc := range cases {
		if got := gcpOnboardingPath(tc.authMethod, tc.provisionedVia); got != tc.want {
			t.Errorf("gcpOnboardingPath(%q, %q) = %q, want %q", tc.authMethod, tc.provisionedVia, got, tc.want)
		}
	}
}
