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
// WHY THE RBAC LISTS MUST NOT GOVERN THEIR LIFECYCLE
// An RBAC sweep that does not mention a Pod has not observed its absence -- it
// never looked. Retiring workloads from its object lists would delete the
// entire workload inventory on the first sweep. Their authority is
// discovered_agents: runtime_status, maintained by the resync manifest, and
// the row's presence at all. The sweep is only the OCCASION on which that
// inventory is read and reconciled -- a workload's support is confirmed when
// its sighting is live, and ends (on a complete sweep covering its namespace)
// when the sighting is gone or no longer there.

// WorkloadSighting is one discovered agent, reduced to what the graph needs.
type WorkloadSighting struct {
	Fingerprint string
	DisplayName string
	Namespace   string
	// WorkloadKind is metadata.kubernetes.workload_kind as the agent reported
	// it ("Deployment", "StatefulSet", ...). Empty when the sighting predates
	// the field.
	WorkloadKind string

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
	SourceKey string
	// LegacyKey is the key releases before the fingerprint key wrote for this
	// workload (cluster, namespace, display name). The service re-keys a row
	// still carrying it in place, so the workload keeps its id.
	LegacyKey   string
	Fingerprint string
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
	// Namespace is the WORKLOAD's namespace, which owns the edge's partition:
	// it is the workload's sighting that confirms or withdraws it.
	Namespace string
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

// WorkloadKey identifies a runtime object in one cluster by its sighting's
// fingerprint.
//
// NOT by display name. Two Deployments in one namespace may report the same
// display name, and a name key merged them into one row -- one agent's
// execution identity and access attributed to the other. The fingerprint is
// unique per workspace and source (discovered_agents_fingerprint_key) and
// stable across sightings, which is what a recognition key has to be.
func WorkloadKey(cluster, fingerprint string) string {
	return Key(cluster, "workload", fingerprint)
}

// LegacyWorkloadKey is the name-based key earlier releases wrote. Kept only so
// those rows can be found and re-keyed; nothing new is written under it.
func LegacyWorkloadKey(cluster, namespace, name string) string {
	return Key(cluster, "workload", namespace, name)
}

// ScopeKindCluster is provider_attrs.scope_kind for every Kubernetes row: the
// cluster is the scope, the namespace the sub-scope.
const ScopeKindCluster = "k8s_cluster"

// WithScope adds the unified-inventory scope keys to provider_attrs.
//
// scope_id and scope_label are both the cluster name -- Kubernetes has no
// separate stable id a person would recognise -- and sub_scope is the
// namespace, or JSON null for a cluster-scoped object (a User, a Group, a
// workload with no namespace). Existing keys are left as they are.
func WithScope(attrs map[string]any, cluster, namespace string) map[string]any {
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrs["scope_kind"] = ScopeKindCluster
	attrs["scope_id"] = cluster
	attrs["scope_label"] = cluster
	if namespace == "" {
		attrs["sub_scope"] = nil
	} else {
		attrs["sub_scope"] = namespace
	}
	return attrs
}

// RuntimeKind maps a sighting's workload kind to iga_workload.runtime_kind:
// k8s_<lower(kind)>, so "Deployment" is k8s_deployment and "CronJob" is
// k8s_cronjob. Anything that is not a plain Kubernetes kind name -- including
// no kind at all -- is k8s_workload rather than a runtime_kind nobody can
// filter on.
func RuntimeKind(workloadKind string) string {
	k := strings.ToLower(strings.TrimSpace(workloadKind))
	if k == "" {
		return "k8s_workload"
	}
	for _, r := range k {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return "k8s_workload"
		}
	}
	return "k8s_" + k
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
		wKey := WorkloadKey(cluster, s.Fingerprint)

		// Gone is the only status that means the workload is not there. Stopped
		// and unknown both mean it may still exist, and retiring on either would
		// delete a workload that is merely scaled to zero.
		live := s.RuntimeStatus != models.RuntimeStatusGone

		res.Workloads = append(res.Workloads, Workload{
			SourceKey:   wKey,
			LegacyKey:   LegacyWorkloadKey(cluster, s.Namespace, name),
			Fingerprint: s.Fingerprint,
			DisplayName: name,
			Namespace:   s.Namespace,
			RuntimeKind: RuntimeKind(s.WorkloadKind),
			Live:        live,
			Attrs: WithScope(map[string]any{
				"cluster":        cluster,
				"namespace":      s.Namespace,
				"fingerprint":    s.Fingerprint,
				"runtime_status": s.RuntimeStatus,
				"archetype":      s.Archetype,
				"workload_kind":  s.WorkloadKind,
			}, cluster, s.Namespace),
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
			Namespace:   s.Namespace,
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
	return RelKeyPrefix(sourceKey) + targetKey
}

// RelKeyPrefix is every RelKey whose source is this workload: what a re-key
// rewrites, so the edge follows its workload to the new key.
func RelKeyPrefix(sourceKey string) string {
	return models.RelTypeExecutesAs + Sep + sourceKey + Sep
}
