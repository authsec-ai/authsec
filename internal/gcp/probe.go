// probe.go answers a question onboarding could not answer before: not "did the
// setup script run", but "what can this reader actually read".
//
// The connector row used to record the role set the script was SUPPOSED to
// grant, copied from a Go constant. That is an assumption, and it survives
// being wrong: a script the customer edited, a grant that silently failed, a
// role removed a month later, an org policy that blocks the binding -- all of
// them leave the recorded role set looking correct. A scan built on that row
// then reports "no service accounts found" when the truth was "we were never
// allowed to look".
//
// So every surface is probed live, with testIamPermissions, against the
// credential that will actually do the scanning. One call per surface, because
// a surface is the unit a scan phase is gated on; a single flat call would
// answer "some of these 40 permissions are missing" without saying which
// capability that costs.
//
// THE THREE-STATE RULE. A surface is reachable, provably unreachable, or
// unknown. Unknown is not a synonym for unreachable: testIamPermissions
// rejects permission names that do not apply to the resource type being
// tested, and refuses the whole call rather than skipping them, so one
// unrecognised name would otherwise turn a readable surface into a denied one.
// Anything the probe cannot answer is recorded as unknown and stays visible.
package gcp

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/authsec-ai/authsec/models"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/googleapi"
)

// Discovery surfaces, one per capability a scan phase is gated on.
const (
	SurfaceIdentities    = "identities"
	SurfaceKeys          = "keys"
	SurfaceAllowBindings = "allow_bindings"
	SurfaceRoles         = "roles"
	SurfaceDeny          = "deny"
	SurfacePAB           = "pab"
	SurfaceResourceIAM   = "resource_iam"
	SurfaceWorkloads     = "workloads"
	SurfaceAgents        = "agents"
	SurfaceRegistry      = "registry"
	SurfaceLogs          = "logs"
	SurfaceAuditConfigs  = "audit_configs"
	// SurfaceAPIs is not a discovery surface in its own right; it gates
	// whether the enablement state recorded on the connector can be trusted.
	// Without serviceusage.services.list every API reads as unknown.
	SurfaceAPIs = "apis"
)

// AllSurfaces is every surface in a fixed order, so a coverage skeleton and a
// capability profile always enumerate the same set in the same sequence.
var AllSurfaces = []string{
	SurfaceIdentities,
	SurfaceKeys,
	SurfaceAllowBindings,
	SurfaceRoles,
	SurfaceDeny,
	SurfacePAB,
	SurfaceResourceIAM,
	SurfaceWorkloads,
	SurfaceAgents,
	SurfaceRegistry,
	SurfaceLogs,
	SurfaceAuditConfigs,
	SurfaceAPIs,
}

// surfacePermissions maps each surface to the permissions a scan of it needs.
//
// These are the permissions behind the API calls each phase makes, not the
// roles that carry them: a customer may hold a permission through a custom
// role, and the reader may hold a role and still be blocked by a deny policy.
// Only the permission is worth asking about.
var surfacePermissions = map[string][]string{
	SurfaceIdentities: {"iam.serviceAccounts.list", "iam.serviceAccounts.get"},
	SurfaceKeys:       {"iam.serviceAccountKeys.list", "iam.serviceAccountKeys.get"},
	// searchAllIamPolicies is the one org-wide sweep the whole allow plane
	// rests on; getIamPolicy is the per-resource fallback when it is stale.
	SurfaceAllowBindings: {"cloudasset.assets.searchAllIamPolicies", "resourcemanager.projects.getIamPolicy"},
	SurfaceRoles:         {"iam.roles.list", "iam.roles.get"},
	SurfaceDeny:          {"iam.denypolicies.list", "iam.denypolicies.get"},
	SurfacePAB:           {"iam.policybindings.list", "iam.policybindings.get"},
	SurfaceResourceIAM:   {"cloudasset.assets.searchAllResources"},
	SurfaceWorkloads: {
		"compute.instances.list",
		"run.services.list",
		"cloudfunctions.functions.list",
		"container.clusters.list",
	},
	SurfaceAgents:   {"aiplatform.reasoningEngines.list"},
	SurfaceRegistry: {"agentregistry.agents.list"},
	// Data Access log entries sit behind a different permission from ordinary
	// ones. Holding the first without the second is the common case, and is
	// exactly what makes "unused" unprovable.
	SurfaceLogs: {"logging.logEntries.list", "logging.privateLogEntries.list"},
	// Audit configs arrive attached to the allow policy, so the permission is
	// getIamPolicy -- but only a role broad enough to return the auditConfigs
	// block actually surfaces them.
	SurfaceAuditConfigs: {"resourcemanager.projects.getIamPolicy"},
	SurfaceAPIs:         {"serviceusage.services.list"},
}

// writePermissionProbe is the zero-write assurance, asked as a question rather
// than asserted as a property of the role list.
//
// Reading the granted roles and observing that all of them are named "viewer"
// proves nothing: the customer's own policy may bind an admin role to the same
// service account, and nothing in onboarding would notice. Asking GCP directly
// which of these the reader holds is the only answer that survives that.
//
// The list is deliberately a representative sample of destructive permissions
// across the surfaces discovery touches, not an exhaustive enumeration of
// every write permission in Google Cloud -- which no list could be. A hit here
// is a definite finding; an empty result is strong evidence, not a proof.
var writePermissionProbe = []string{
	"iam.serviceAccounts.create",
	"iam.serviceAccounts.delete",
	"iam.serviceAccounts.update",
	"iam.serviceAccounts.setIamPolicy",
	"iam.serviceAccountKeys.create",
	"iam.serviceAccountKeys.delete",
	"iam.roles.create",
	"iam.roles.delete",
	"iam.roles.update",
	"iam.denypolicies.create",
	"iam.denypolicies.delete",
	"resourcemanager.projects.setIamPolicy",
	"resourcemanager.projects.delete",
	"resourcemanager.folders.setIamPolicy",
	"resourcemanager.organizations.setIamPolicy",
	"serviceusage.services.enable",
	"serviceusage.services.disable",
	"storage.buckets.delete",
	"storage.objects.delete",
	"compute.instances.delete",
	"container.clusters.delete",
	"secretmanager.versions.destroy",
	"bigquery.datasets.delete",
	"cloudkms.cryptoKeyVersions.destroy",
	"pubsub.topics.delete",
	"cloudsql.instances.delete",
	"run.services.delete",
	"cloudfunctions.functions.delete",
	"aiplatform.reasoningEngines.delete",
	"logging.sinks.delete",
}

// testIamPermissionsBatchSize is the documented ceiling on how many
// permissions one testIamPermissions call accepts. Live behaviour wins over
// this number if the two ever disagree; until then it is the chunk size.
const testIamPermissionsBatchSize = 100

// ProbeResult is one live capability probe.
type ProbeResult struct {
	// Surfaces is keyed by the Surface* constants and always contains an entry
	// for every surface in AllSurfaces -- an unprobeable surface is present
	// and marked unknown, never absent. A missing key would be
	// indistinguishable from a surface nobody thought to check.
	Surfaces map[string]models.GCPSurfaceCapability
	// Held is every probed permission the reader actually has, sorted.
	Held []string
	// WriteHeld is the subset of writePermissionProbe the reader holds. It
	// must be empty.
	WriteHeld []string
	// WriteCheckUnknown records that the write probe itself could not run, so
	// an empty WriteHeld is not mistaken for a clean bill of health.
	WriteCheckUnknown bool
	ProbedAt          time.Time
}

// Clean reports whether the probe found no write permission AND was able to
// look. Both halves matter: a probe that could not run has cleared nothing.
func (r ProbeResult) Clean() bool {
	return len(r.WriteHeld) == 0 && !r.WriteCheckUnknown
}

// ProbeReaderCapabilities runs the live probe with whatever credential rm was
// built from -- which must be the reader's, not an operator's, or the answer
// describes the wrong principal.
//
// It never fails the whole call for a surface it could not check. A probe is a
// report, and a report that refuses to exist because one line of it is
// unavailable is worse than one that says which line is missing. Only a
// malformed scope, which is a caller bug rather than a customer condition,
// returns an error.
func ProbeReaderCapabilities(ctx context.Context, rm *cloudresourcemanager.Service, scopeKind, scopeID string) (ProbeResult, error) {
	if _, err := scopeResourceName(scopeKind, scopeID); err != nil {
		return ProbeResult{}, err
	}

	result := ProbeResult{
		Surfaces: make(map[string]models.GCPSurfaceCapability, len(AllSurfaces)),
		ProbedAt: time.Now().UTC(),
	}

	held := map[string]bool{}

	for _, surface := range AllSurfaces {
		want := surfacePermissions[surface]
		allowed, err := testAllowedPermissions(ctx, rm, scopeKind, scopeID, want)
		if err != nil {
			result.Surfaces[surface] = models.GCPSurfaceCapability{
				Unknown: true,
				Reason:  probeFailureReason(err),
			}
			continue
		}

		var missing []string
		for _, p := range want {
			if containsString(allowed, p) {
				held[p] = true
			} else {
				missing = append(missing, p)
			}
		}
		result.Surfaces[surface] = models.GCPSurfaceCapability{
			Can:     len(missing) == 0,
			Missing: missing,
		}
	}

	result.WriteHeld, result.WriteCheckUnknown = probeWritePermissions(ctx, rm, scopeKind, scopeID)

	for p := range held {
		result.Held = append(result.Held, p)
	}
	sort.Strings(result.Held)

	return result, nil
}

// probeWritePermissions chunks the write deny-list and reports which of it the
// reader holds.
//
// A failed chunk is skipped rather than aborting the rest: a rejected
// permission name in one chunk must not hide a genuine write permission in
// another. Any skipped chunk sets unknown, so the caller can tell "none held"
// from "could not finish looking".
func probeWritePermissions(ctx context.Context, rm *cloudresourcemanager.Service, scopeKind, scopeID string) (held []string, unknown bool) {
	for _, chunk := range chunkPermissions(writePermissionProbe, testIamPermissionsBatchSize) {
		allowed, err := testAllowedPermissions(ctx, rm, scopeKind, scopeID, chunk)
		if err != nil {
			unknown = true
			continue
		}
		held = append(held, allowed...)
	}
	sort.Strings(held)
	return held, unknown
}

func chunkPermissions(all []string, size int) [][]string {
	if size <= 0 || len(all) <= size {
		return [][]string{all}
	}
	var out [][]string
	for i := 0; i < len(all); i += size {
		end := i + size
		if end > len(all) {
			end = len(all)
		}
		out = append(out, all[i:end])
	}
	return out
}

/* ------------------------- quota project (ONB-5) ---------------------------- */

// QuotaProjectUsable reports whether the reader holds serviceusage.services.use
// on quotaProject, which is what every Cloud Asset call needs in order to bill.
//
// This is probed against the QUOTA PROJECT SPECIFICALLY, not the onboarded
// scope, and the distinction is the whole point. The reader project is allowed
// to sit outside the scope being scanned: when it does, the reader roles bound
// at the scope grant nothing on the quota project, and every Cloud Asset call
// fails even though the scope itself is perfectly readable. Probing the scope
// would report success and tell us nothing about the case that actually
// breaks.
//
// The second return is whether the check could be made at all. As everywhere
// else in this file, could-not-check is not the same answer as does-not-hold:
// refusing to onboard on an unanswerable question would be as wrong as
// assuming the answer is yes.
func QuotaProjectUsable(ctx context.Context, rm *cloudresourcemanager.Service, quotaProject string) (usable, known bool) {
	if quotaProject == "" {
		return false, true
	}
	allowed, err := testAllowedPermissions(ctx, rm, models.CloudScopeProject, quotaProject, []string{"serviceusage.services.use"})
	if err != nil {
		return false, false
	}
	return containsString(allowed, "serviceusage.services.use"), true
}

// probeFailureReason turns a provider error into a short, sanitized label.
//
// The distinction it preserves is the one that matters to whoever reads the
// row: 400 means we asked a question this resource type does not understand,
// which is our problem and not evidence about the customer's access at all,
// while 403 means the check itself was refused, which is theirs and worth
// acting on. Both are unknown, for different reasons, and flattening them into
// one string would lose the only detail that says whether to look at our code
// or their policy.
func probeFailureReason(err error) string {
	// Constrained beats denied. Both are 403, and a surface blocked by a
	// perimeter or an org policy is unreachable BY DESIGN — recording it as a
	// denial would put it on the list of things to fix by granting a role.
	if code := ConstraintReasonCode(ClassifyConstraint(err)); code != "" {
		return code
	}
	var gerr *googleapi.Error
	if errors.As(err, &gerr) {
		switch gerr.Code {
		case 400:
			return "permission_not_applicable_at_this_scope"
		case 403:
			return "permission_check_denied"
		case 404:
			return "scope_not_found"
		case 429:
			return "throttled"
		}
	}
	return "permission_check_failed"
}
