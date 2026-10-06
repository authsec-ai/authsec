package k8sgraph

import (
	"testing"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// Every key the projection writes reads back to the object it was written for.
// The parser is tested against the formatters, never against literals, so a
// change to either side fails here rather than in a reader's namespace.
func TestParseKeyRoundTripsEveryFormatter(t *testing.T) {
	const c = "prod-east"
	sa := models.K8sSubject{Kind: models.K8sSubjectServiceAccount, Name: "research", Namespace: "iga-demo"}
	rb := models.K8sBinding{Name: "reads", Namespace: "iga-demo",
		RoleRef: models.K8sRoleRef{Kind: models.K8sKindClusterRole, Name: "secret-reader"}}
	crb := models.K8sBinding{Name: "admins", RoleRef: models.K8sRoleRef{Kind: models.K8sKindClusterRole, Name: "cluster-admin"}}
	role := models.K8sRole{Name: "pod-reader", Namespace: "iga-demo"}
	crole := models.K8sRole{Name: "secret-reader"}
	rule := models.K8sPolicyRule{Verbs: []string{"get"}, Resources: []string{"secrets"}}

	for name, tc := range map[string]struct {
		key  string
		want ObjectKey
	}{
		"service account":      {ServiceAccountKey(c, "iga-demo", "research"), ObjectKey{c, "serviceaccount", "iga-demo", "research"}},
		"user subject":         {SubjectKey(c, models.K8sSubject{Kind: models.K8sSubjectUser, Name: "alice"}), ObjectKey{c, "user", "", "alice"}},
		"group subject":        {SubjectKey(c, models.K8sSubject{Kind: models.K8sSubjectGroup, Name: "system:masters"}), ObjectKey{c, "group", "", "system:masters"}},
		"role":                 {RoleKey(c, role), ObjectKey{c, "role", "iga-demo", "pod-reader"}},
		"cluster role":         {RoleKey(c, crole), ObjectKey{c, "clusterrole", "", "secret-reader"}},
		"role rule":            {StatementKey(RoleKey(c, role), rule), ObjectKey{c, "role", "iga-demo", "pod-reader"}},
		"cluster role rule":    {StatementKey(RoleKey(c, crole), rule), ObjectKey{c, "clusterrole", "", "secret-reader"}},
		"role binding":         {BindingKey(c, rb) + Sep + SubjectKey(c, sa), ObjectKey{c, "rolebinding", "iga-demo", "reads"}},
		"cluster role binding": {BindingKey(c, crb) + Sep + SubjectKey(c, sa), ObjectKey{c, "clusterrolebinding", "", "admins"}},
		"workload":             {WorkloadKey(c, "fp-1"), ObjectKey{c, "workload", "", "fp-1"}},
		"legacy workload":      {LegacyWorkloadKey(c, "iga-demo", "agent"), ObjectKey{c, "workload", "iga-demo", "agent"}},
	} {
		got, ok := ParseKey(tc.key)
		if !ok || got != tc.want {
			t.Errorf("%s: ParseKey(%q) = %+v, %v; want %+v", name, tc.key, got, ok, tc.want)
		}
	}
	for _, bad := range []string{"", "aws" + Sep + "arn:aws:iam::1:role/x", Key(c, "secret", "a"), "k8s" + Sep + Sep + "user" + Sep + "x"} {
		if got, ok := ParseKey(bad); ok {
			t.Errorf("ParseKey(%q) = %+v, want not ok", bad, got)
		}
	}
}

// Every partition a sweep emits reads back to itself; keys no sweep writes do
// not read as partitions.
func TestParsePartitionKeyRoundTripsEveryPartition(t *testing.T) {
	src := uuid.New()
	for _, cl := range []string{"k3s-master", "odd|cluster"} {
		s := Scope{SourceID: src, Cluster: cl, ClusterScoped: true, Namespaces: []string{"a", "iga-demo"}}
		ps := Partitions(s)
		if len(ps) == 0 {
			t.Fatal("no partitions")
		}
		for _, p := range ps {
			got, ok := ParsePartitionKey(p.Key())
			if !ok || got != p {
				t.Errorf("ParsePartitionKey(%q) = %+v, %v; want %+v", p.Key(), got, ok, p)
			}
		}
	}
	legacy := Partition{SourceID: src, Cluster: "c", Target: "workload"}.Key()
	for _, bad := range []string{"", "iga-demo", "not-a-uuid|c|ns|node|identity", legacy, src.String() + "|c|ns|node|resource"} {
		if got, ok := ParsePartitionKey(bad); ok {
			t.Errorf("ParsePartitionKey(%q) = %+v, want not ok", bad, got)
		}
	}
}
