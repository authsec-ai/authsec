package k8sgraph

import (
	"sort"
	"strings"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// Partition is the evidence boundary reconciliation may never cross.
//
// SPEC-iga-phase2-graph §2.7: a row may be ENDED only when an authoritative
// read of the owning scope did not see it. The partition is that scope made
// explicit, so "did not see it" is decidable rather than assumed.
//
// Kubernetes has exactly two coverage dimensions, and they are not
// interchangeable:
//
//   - CLUSTER-SCOPED: ClusterRoles and ClusterRoleBindings. Readable only with
//     cluster-wide read. A sweep without it has not produced a smaller answer,
//     it has produced a different one -- cluster-scoped bindings are where the
//     dangerous grants live.
//   - PER-NAMESPACE: Roles, RoleBindings and ServiceAccounts in one namespace.
//     A sweep that read namespaces A and B proves nothing about C.
//
// Both are carried on the snapshot already (ClusterScoped, Namespaces), so the
// partition reads them rather than re-deriving them from what happened to
// arrive -- an empty namespace and an unread namespace look identical in the
// payload, and only one of them licenses a retirement.
type Partition struct {
	// SourceID is the discovery_sources row that observed this. Two agents
	// watching one cluster are two evidence streams, and one going blind must
	// not retire what the other can still see.
	SourceID uuid.UUID
	Cluster  string

	// Namespace is "" for the cluster-scoped partition.
	Namespace string

	// Class is the node class this partition owns: identity | policy |
	// entitlement | workload. Empty for edge partitions.
	Class string
	// Target is "" for nodes, else "assignment", "access_edge" or
	// "executes_as".
	Target string
}

// Key is the partition's stable identity and the value stamped on every row it
// owns. It is the conflict target for support upserts and the scope for every
// retirement query, so it must be unambiguous across clusters and sources.
//
// Frozen once deployed: changing the spelling orphans every support row written
// under the old one, and an orphaned support row reads as "nothing supports this
// object", which retires it.
func (p Partition) Key() string {
	target := p.Target
	if target == "" {
		target = "node"
	}
	scope := p.Namespace
	if scope == "" {
		scope = "-cluster-"
	}
	return strings.Join([]string{
		p.SourceID.String(), p.Cluster, scope, target, p.Class,
	}, "|")
}

// ClusterScoped reports whether this partition covers cluster-wide objects.
func (p Partition) ClusterScoped() bool { return p.Namespace == "" }

// Node classes and edge targets a partition may own.
const (
	ClassIdentity    = "identity"
	ClassPolicy      = "policy"
	ClassEntitlement = "entitlement"
	// ClassWorkload is spelled as models.ObjectWorkload so SupportColumn
	// resolves it to iga_object_support.workload_id.
	ClassWorkload = "workload"

	TargetAssignment = "assignment"
	TargetAccessEdge = "access_edge"
	// TargetExecutesAs owns the workload -> ServiceAccount edges in
	// iga_relationship, partitioned by the WORKLOAD's namespace.
	TargetExecutesAs = "executes_as"
)

// Scope is the sweep's coverage: what it looked at, and whether it finished.
//
// A separate type from the wire snapshot because reconciliation needs only
// these five facts, and passing the whole payload invites a future reader to
// decide absence from the object lists -- which is exactly the mistake the
// Complete flag exists to prevent.
type Scope struct {
	SourceID      uuid.UUID
	Cluster       string
	Generation    int64
	Complete      bool
	ClusterScoped bool
	Namespaces    []string
}

// ScopeOf lifts the coverage facts off a snapshot.
func ScopeOf(snap models.K8sRBACSnapshot, sourceID uuid.UUID, generation int64) Scope {
	ns := append([]string{}, snap.Namespaces...)
	sort.Strings(ns)
	return Scope{
		SourceID:      sourceID,
		Cluster:       snap.Cluster,
		Generation:    generation,
		Complete:      snap.Complete,
		ClusterScoped: snap.ClusterScoped,
		Namespaces:    ns,
	}
}

// Covers reports whether the sweep actually read this partition's scope.
//
// This is condition 2 of §2.7, and it is the one that makes a permissions
// outage read as an outage rather than as a cleanup.
func (s Scope) Covers(p Partition) bool {
	if p.SourceID != s.SourceID || p.Cluster != s.Cluster {
		return false
	}
	if p.ClusterScoped() {
		return s.ClusterScoped
	}
	for _, n := range s.Namespaces {
		if n == p.Namespace {
			return true
		}
	}
	return false
}

// CanEnd reports whether this sweep is entitled to retire rows in a partition.
//
// All of §2.7's conditions, restated for a pushed snapshot:
//
//  1. the sweep completed -- every LIST succeeded. One transient 403 would
//     otherwise delete a cluster's whole authorization model and restore it on
//     the next sweep, with a governance alert in between;
//  2. the sweep actually read this partition's scope (Covers);
//  3. the sweep named a scope at all -- a sweep with no namespaces and no
//     cluster read observed nothing and can prove nothing;
//  4. the caller holds this generation, which the service fences.
//
// Anything short of all four yields `stale`, never `ended`. Collapsing the two
// is the defect this function exists to make impossible.
func (s Scope) CanEnd(p Partition) bool {
	if !s.Complete {
		return false
	}
	if !s.ClusterScoped && len(s.Namespaces) == 0 {
		return false
	}
	return s.Covers(p)
}

// Partitions enumerates every partition this sweep is responsible for.
//
// NAMED FIELDS, ALWAYS. A positional literal silently mis-assigns the moment a
// field is added, and a mis-assigned partition key retires the wrong objects.
func Partitions(s Scope) []Partition {
	var out []Partition

	add := func(ns string) {
		for _, class := range []string{ClassIdentity, ClassPolicy, ClassEntitlement, ClassWorkload} {
			out = append(out, Partition{
				SourceID: s.SourceID, Cluster: s.Cluster, Namespace: ns, Class: class,
			})
		}
		for _, target := range []string{TargetAssignment, TargetAccessEdge, TargetExecutesAs} {
			out = append(out, Partition{
				SourceID: s.SourceID, Cluster: s.Cluster, Namespace: ns, Target: target,
			})
		}
	}

	// The cluster-scoped partition exists only if the sweep could read it.
	// Emitting it unconditionally would produce a partition the sweep cannot
	// cover, and reconciliation would mark it stale on every cycle forever.
	if s.ClusterScoped {
		add("")
	}
	for _, ns := range s.Namespaces {
		add(ns)
	}
	return out
}

// PartitionForRole returns the partition owning a Role or ClusterRole.
func PartitionForRole(s Scope, namespace string) Partition {
	return Partition{SourceID: s.SourceID, Cluster: s.Cluster, Namespace: namespace, Class: ClassPolicy}
}

// PartitionForIdentity returns the partition owning a ServiceAccount.
//
// A User or Group subject has no namespace -- Kubernetes does not scope them --
// so they belong to the cluster partition and are retired only by a sweep that
// could read cluster-wide.
func PartitionForIdentity(s Scope, namespace string) Partition {
	return Partition{SourceID: s.SourceID, Cluster: s.Cluster, Namespace: namespace, Class: ClassIdentity}
}

// PartitionForWorkload returns the partition owning a discovered workload.
//
// The evidence for a workload is the discovered-agent inventory, not the RBAC
// lists, but it is reconciled on the same sweep and under the same rule: its
// support ends only when a complete sweep that covered its namespace no longer
// finds it live in that inventory. A workload with no namespace belongs to the
// cluster partition.
func PartitionForWorkload(s Scope, namespace string) Partition {
	return Partition{SourceID: s.SourceID, Cluster: s.Cluster, Namespace: namespace, Class: ClassWorkload}
}

// PartitionForEdge returns the partition owning an assignment or grant.
//
// Keyed by the BINDING's namespace, not the role's: a RoleBinding in namespace A
// may reference a ClusterRole, and it is the binding that disappears when
// namespace A is swept.
func PartitionForEdge(s Scope, bindingNamespace, target string) Partition {
	return Partition{SourceID: s.SourceID, Cluster: s.Cluster, Namespace: bindingNamespace, Target: target}
}
