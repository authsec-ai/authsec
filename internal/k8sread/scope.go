package k8sread

import "github.com/authsec-ai/authsec/internal/k8sgraph"

// The two rules the flat access route (AccessFor) and the graph walk
// (igaread/traverse_k8s.go) must state identically, written once here --
// igaread imports this package, so both read the same function and cannot
// drift (D-112).

// Effective scope kinds (D-109): where a grant's rule applies.
const (
	ScopeNamespace = "namespace"
	ScopeCluster   = "cluster"
)

// BindingScope is where a rule reached through a binding applies (D-109):
// the binding's namespace for a RoleBinding -- of a Role or of a ClusterRole,
// so a ClusterRole's rule bound by a RoleBinding is confined to that
// namespace -- and the cluster for a ClusterRoleBinding. assignmentKey is the
// assignment's source key (k8sgraph.BindingKey + Sep + SubjectKey). A key
// that does not parse reads as cluster: never narrower than what is known.
func BindingScope(assignmentKey string) (kind, namespace string) {
	if k, ok := k8sgraph.ParseKey(assignmentKey); ok && k.Namespace != "" {
		return ScopeNamespace, k.Namespace
	}
	return ScopeCluster, ""
}

// ImplicitGroupKey reports whether a Kubernetes group identity's source key
// names a group the API server places subjects in implicitly (D-110,
// k8sgraph.ImplicitGroup).
func ImplicitGroupKey(sourceKey string) bool {
	k, ok := k8sgraph.ParseKey(sourceKey)
	return ok && k.Type == "group" && k8sgraph.ImplicitGroup(k.Name)
}
