package k8sgraph

import (
	"strings"

	"github.com/authsec-ai/authsec/models"
)

// The workload half of the Kubernetes graph.
//
// WHY THIS DOES NOT COME FROM THE RBAC SNAPSHOT
// The RBAC sweep lists Roles, Bindings and ServiceAccounts. It never looks at a
// Pod, so it knows which identities EXIST but nothing about which workload runs
// as one. That question -- "this agent runs as this ServiceAccount, which can
// read secrets" -- is the one the product is actually for.
//
// The control plane already holds the answer. discovered_agents carries
// provisioning_hints.identity_anchor in exactly the form the projector writes
// as a ServiceAccount's display name, "system:serviceaccount:<ns>:<name>", so
// the two join without a translation table.
//
// WHY THE SWEEP MUST NOT GOVERN THEIR LIFECYCLE
// An RBAC sweep that does not mention a Pod has not observed its absence -- it
// never looked. Retiring workloads from it would delete the entire workload
// inventory on the first sweep. Their authority is discovered_agents'
// runtime_status, maintained by the resync manifest, which is the mechanism
// that already exists for exactly this and must not acquire a second
// implementation.

// WorkloadSighting is one discovered agent, reduced to what the graph needs.
type WorkloadSighting struct {
	Fingerprint string
	DisplayName string
	Namespace   string

	// IdentityAnchor is "system:serviceaccount:<ns>:<name>" from the sighting's
	// provisioning hints: what the workload is CONFIGURED to run as.
	IdentityAnchor string
	// ObservedServiceAccount is what was actually seen running. When the two
	// disagree the entitlement is bound to an identity the workload does not
	// have, which is a finding, not a tie to break silently.
	ObservedServiceAccount string

	RuntimeStatus string
	Archetype     string
}

// Workload is a runtime object to upsert.
type Workload struct {
	SourceKey   string
	DisplayName string
	Namespace   string
	RuntimeKind string
	// Live is false once the agent is observed gone. The row is retired, never
	// deleted: "this workload existed and had this access" stays answerable.
	Live  bool
	Attrs map[string]any
}

// ExecutesAs is the workload -> identity edge.
//
// It claims CONFIGURED EXECUTION IDENTITY and nothing more (§2.3): not that the
// workload ran, and not that any request it made succeeded.
type ExecutesAs struct {
	SourceKey   string
	WorkloadKey string
	IdentityKey string
	// Basis is 'observed' when the agent saw the Pod's serviceAccountName, and
	// 'declared' when only the configured anchor is known. Kubernetes lets these
	// differ, and which one we have changes what the edge is worth.
	Basis string
	Live  bool
	// Mismatch marks a workload whose observed ServiceAccount differs from its
	// configured one.
	Mismatch bool
}

// WorkloadResult is the workload projection.
type WorkloadResult struct {
	Workloads  []Workload
	ExecutesAs []ExecutesAs
	// Unanchored names workloads with no resolvable ServiceAccount. Reported
	// rather than dropped: a workload whose identity we cannot determine is a
	// gap in the answer, not an absence of access.
	Unanchored []string
}

// WorkloadKey identifies a runtime object in one cluster.
func WorkloadKey(cluster, namespace, name string) string {
	return Key(cluster, "workload", namespace, name)
}

// AnchorToKey turns "system:serviceaccount:<ns>:<name>" into the identity key
// the RBAC projection writes for that ServiceAccount.
//
// Returns "" for anything else, including a bare name. A bare name cannot be
// resolved to a namespace, and guessing one would attach a workload to another
// namespace's identically-named ServiceAccount -- silently attributing one
// workload's access to a different principal.
func AnchorToKey(cluster, anchor string) string {
	parts := strings.Split(strings.TrimSpace(anchor), ":")
	if len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" {
		return ""
	}
	if parts[2] == "" || parts[3] == "" {
		return ""
	}
	return ServiceAccountKey(cluster, parts[2], parts[3])
}

// ProjectWorkloads maps discovered agents to workloads and their execution
// identities.
func ProjectWorkloads(cluster string, in []WorkloadSighting) WorkloadResult {
	var res WorkloadResult

	for i := range in {
		s := in[i]
		name := s.DisplayName
		if name == "" {
			name = s.Fingerprint
		}
		wKey := WorkloadKey(cluster, s.Namespace, name)

		// Gone is the only status that means the workload is not there. Stopped
		// and unknown both mean it may still exist, and retiring on either would
		// delete a workload that is merely scaled to zero.
		live := s.RuntimeStatus != models.RuntimeStatusGone

		res.Workloads = append(res.Workloads, Workload{
			SourceKey:   wKey,
			DisplayName: name,
			Namespace:   s.Namespace,
			RuntimeKind: "k8s_workload",
			Live:        live,
			Attrs: map[string]any{
				"cluster":        cluster,
				"namespace":      s.Namespace,
				"fingerprint":    s.Fingerprint,
				"runtime_status": s.RuntimeStatus,
				"archetype":      s.Archetype,
			},
		})

		// Prefer what was OBSERVED over what was configured: the question is
		// what the workload actually runs as. The anchor is the fallback.
		anchor, basis := s.ObservedServiceAccount, models.BasisObserved
		if AnchorToKey(cluster, anchor) == "" {
			anchor, basis = s.IdentityAnchor, models.BasisDeclared
		}
		idKey := AnchorToKey(cluster, anchor)
		if idKey == "" {
			res.Unanchored = append(res.Unanchored, wKey)
			continue
		}

		res.ExecutesAs = append(res.ExecutesAs, ExecutesAs{
			SourceKey:   RelKey(wKey, idKey),
			WorkloadKey: wKey,
			IdentityKey: idKey,
			Basis:       basis,
			Live:        live,
			Mismatch: s.ObservedServiceAccount != "" && s.IdentityAnchor != "" &&
				s.ObservedServiceAccount != s.IdentityAnchor,
		})
	}
	return res
}

// RelKey names a relationship by its endpoints and type.
func RelKey(sourceKey, targetKey string) string {
	return models.RelTypeExecutesAs + Sep + sourceKey + Sep + targetKey
}
