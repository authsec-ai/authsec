package services

import (
	"encoding/json"
	"sort"

	"github.com/authsec-ai/authsec/internal/gcp"
	"github.com/authsec-ai/authsec/models"
)

/* cloud_gcp_readiness.go turns the evidence onboarding gathered into the two
   things discovery reads before it starts: a coverage skeleton listing every
   surface, and a single verdict on whether this connector can be scanned.

   Both are DERIVED. Nothing here is a new source of truth — the capability
   profile, the API enablement map, the scope enumeration and the capability
   limits are the facts, and these two functions only summarise them. That
   matters because a stored verdict drifts from the evidence it was computed
   from, and then the console and the scheduler disagree about the same
   connector. Recomputing on every onboard and every verify costs nothing and
   cannot drift. */

// gcpP1Surfaces are the surfaces the first discovery phase cannot run without.
//
// The later-phase surfaces (deny, PAB, workloads, agents, registry, logs) are
// deliberately excluded from the readiness verdict: onboarding does not grant
// the roles behind them yet, so counting them would mark every correctly
// onboarded connector partial and make the field meaningless. They are still
// probed, and their state is still on the row — this is about what "ready"
// should mean today, not about hiding them.
var gcpP1Surfaces = []string{
	gcp.SurfaceIdentities,
	gcp.SurfaceKeys,
	gcp.SurfaceAllowBindings,
	gcp.SurfaceRoles,
	gcp.SurfaceResourceIAM,
}

// gcpP1APIs are the APIs those surfaces call. A P1 surface whose API is off fails
// at scan time no matter how complete the reader's permissions are.
var gcpP1APIs = []string{
	"cloudresourcemanager.googleapis.com",
	"iam.googleapis.com",
	"cloudasset.googleapis.com",
}

// NewGCPCoverageSkeleton builds the coverage blob a fresh connector starts
// with: every surface present, every one unknown, generation zero.
//
// Pre-creating it is the point. Coverage used to be written as an empty object,
// which left the first scan to invent the surface list — and a surface absent
// from that list is indistinguishable from one that was scanned and found
// nothing. Listing all of them up front, in a state that explicitly means "not
// looked at yet", makes the first scan an update rather than a creation and
// keeps an unscanned surface from ever reading as a clean one.
func NewGCPCoverageSkeleton() json.RawMessage {
	surfaces := make(map[string]models.SurfaceCoverage, len(gcp.AllSurfaces))
	for _, s := range gcp.AllSurfaces {
		surfaces[s] = models.SurfaceCoverage{State: models.CloudCoverageUnknown}
	}

	raw, err := json.Marshal(models.ScanCoverage{
		Generation: 0,
		Surfaces:   surfaces,
	})
	if err != nil {
		// Unreachable: the value is a plain map of plain structs. Falling back
		// to an empty object keeps the NOT NULL column satisfiable rather than
		// failing an onboarding over a marshal that cannot fail.
		return json.RawMessage("{}")
	}
	return raw
}

// DeriveGCPReadiness reduces the probe evidence to one verdict plus the
// reasons behind it.
//
// The ordering is deliberate: blocked beats partial, and the blocked checks
// are the ones where scanning cannot begin at all rather than merely returning
// less. A connector that cannot use its quota project is blocked even though
// every permission it holds is correct, because every Cloud Asset call it
// makes will fail.
//
// A surface whose probe came back UNKNOWN does not block and does not pass
// silently — it contributes a reason and caps the verdict at partial. Treating
// unknown as ready would promise a scan we have no evidence can run; treating
// it as blocked would refuse to scan on the strength of a question we failed
// to ask.
func DeriveGCPReadiness(attrs models.GCPConnectorAttrs, status string) (string, []string) {
	var reasons []string

	if status == models.CloudConnectorRevoked {
		return models.GCPReadinessBlocked, []string{"connector_revoked"}
	}
	if status == models.CloudConnectorError {
		reasons = append(reasons, "connector_in_error")
	}

	for _, limit := range attrs.CapabilityLimits {
		if limit == models.GCPLimitQuotaProjectUnusable {
			// Nothing Cloud-Asset-backed can run, which is the whole P1 spine.
			return models.GCPReadinessBlocked, append(reasons, models.GCPLimitQuotaProjectUnusable)
		}
	}

	if len(attrs.CapabilityProfile) == 0 {
		// Never probed. Not blocked — the connection itself may be perfectly
		// good — but nothing here justifies calling it ready either.
		return models.GCPReadinessPartial, append(reasons, "not_probed")
	}

	for _, surface := range gcpP1Surfaces {
		cap, ok := attrs.CapabilityProfile[surface]
		switch {
		case !ok:
			reasons = append(reasons, "surface_not_probed:"+surface)
		case cap.Unknown:
			reasons = append(reasons, "surface_unknown:"+surface)
		case !cap.Can:
			reasons = append(reasons, "surface_unreachable:"+surface)
		}
	}

	for _, api := range gcpP1APIs {
		switch attrs.APIEnablement[api] {
		case gcp.APIStateEnabled:
			// fine
		case gcp.APIStateNotEnabled:
			reasons = append(reasons, "api_not_enabled:"+api)
		default:
			// Absent or unknown. Not proof the API is off, so not a blocker,
			// but not evidence it is on either.
			reasons = append(reasons, "api_state_unknown:"+api)
		}
	}

	// A write permission on the reader is a security finding rather than a
	// capability gap, so it never blocks a scan — refusing to read an estate
	// makes it no safer. It is surfaced here because readiness is the field
	// most likely to be looked at, and a reader that can delete things should
	// not be reported as unqualified good news.
	if len(attrs.WritePermissionsHeld) > 0 {
		reasons = append(reasons, "write_permissions_held")
	}

	if enum := decodeScopeEnumeration(attrs.ScopeEnumeration); enum != nil && !enum.Usable() && !enum.Unknown {
		reasons = append(reasons, "scope_not_enumerable")
	}

	sort.Strings(reasons)
	if len(reasons) == 0 {
		return models.GCPReadinessReady, nil
	}
	return models.GCPReadinessPartial, reasons
}

func decodeScopeEnumeration(raw json.RawMessage) *gcp.ScopeEnumeration {
	if len(raw) == 0 {
		return nil
	}
	var e gcp.ScopeEnumeration
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil
	}
	return &e
}

// gcpOnboardingPath names how a connector was onboarded, from the two fields
// that between them imply it.
//
// Derived once at onboarding and then stored, rather than recomputed on read:
// the inputs are provenance and never change for a given connector, and a
// stored value keeps a later reader from having to know this rule at all.
func gcpOnboardingPath(authMethod, provisionedVia string) string {
	if authMethod == GCPAuthMethodJSONKey {
		return models.GCPOnboardingPathManualKey
	}
	if provisionedVia == gcpProvisionedViaGoogleOAuth {
		return models.GCPOnboardingPathOAuthDefault
	}
	return models.GCPOnboardingPathManualWIF
}

// gcpProvisionedViaGoogleOAuth is the value the Google Authentication path
// stamps on ProvisionedVia. Declared here so the two files that care about the
// string compare against one constant instead of two literals.
const gcpProvisionedViaGoogleOAuth = "google_oauth"
