package k8sread

import (
	"testing"

	"github.com/authsec-ai/authsec/internal/k8sgraph"
	"github.com/authsec-ai/authsec/models"
)

// D-109 from the keys the projection writes: a RoleBinding -- to a Role or a
// ClusterRole -- is its namespace's, a ClusterRoleBinding the cluster's, and a
// key that names no binding is never narrower than the cluster.
func TestBindingScope(t *testing.T) {
	sa := k8sgraph.ServiceAccountKey("c1", "shop", "checkout")
	group := k8sgraph.GroupKey("c1", "system:authenticated")
	rbToClusterRole := models.K8sBinding{Name: "rb", Namespace: "shop",
		RoleRef: models.K8sRoleRef{Kind: models.K8sKindClusterRole, Name: "secret-getter"}}
	crb := models.K8sBinding{Name: "crb", RoleRef: models.K8sRoleRef{Kind: models.K8sKindClusterRole, Name: "view"}}
	for _, tc := range []struct {
		key, kind, ns string
	}{
		{k8sgraph.BindingKey("c1", rbToClusterRole) + k8sgraph.Sep + sa, ScopeNamespace, "shop"},
		{k8sgraph.BindingKey("c1", rbToClusterRole) + k8sgraph.Sep + group, ScopeNamespace, "shop"},
		// A grant's own key (binding, subject, rule hash) reads the same.
		{k8sgraph.BindingKey("c1", rbToClusterRole) + k8sgraph.Sep + sa + k8sgraph.Sep + "abc", ScopeNamespace, "shop"},
		{k8sgraph.BindingKey("c1", crb) + k8sgraph.Sep + sa, ScopeCluster, ""},
		{"", ScopeCluster, ""},
		{"not-a-key", ScopeCluster, ""},
	} {
		if kind, ns := BindingScope(tc.key); kind != tc.kind || ns != tc.ns {
			t.Errorf("BindingScope(%q) = %s %q, want %s %q", tc.key, kind, ns, tc.kind, tc.ns)
		}
	}
}

func TestImplicitGroupKey(t *testing.T) {
	for name, want := range map[string]bool{
		"system:serviceaccounts":      true,
		"system:serviceaccounts:shop": true,
		"system:authenticated":        true,
		"system:masters":              false,
		"system:serviceaccount":       false,
		"developers":                  false,
	} {
		if got := ImplicitGroupKey(k8sgraph.GroupKey("c1", name)); got != want {
			t.Errorf("ImplicitGroupKey(group %s) = %v, want %v", name, got, want)
		}
	}
	// A User named like an implicit group is not a group.
	if ImplicitGroupKey(k8sgraph.SubjectKey("c1", models.K8sSubject{Kind: models.K8sSubjectUser, Name: "system:authenticated"})) {
		t.Error("a User named system:authenticated read as an implicit group")
	}
}
