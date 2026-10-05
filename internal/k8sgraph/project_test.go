// Tests for the Kubernetes RBAC → graph mapping.
//
// This is the one part of the feature where a silent error produces a WRONG
// ANSWER rather than a crash: the graph would confidently report access that
// does not exist, or miss access that does, and nothing downstream could tell.
// Hence tests here and nowhere else in this change.
//
// The cases are the four that real clusters actually produce and that a naive
// mapping gets wrong:
//
//  1. a RoleBinding referencing a ClusterRole (the common case, not the edge case)
//  2. Group subjects, especially system:serviceaccounts
//  3. wildcards, which must be recorded and not expanded
//  4. a binding whose role is missing — honest partial, never a dropped edge
package k8sgraph

import (
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/models"
)

const cluster = "k3s-master"

func snapshot(roles []models.K8sRole, bindings []models.K8sBinding,
	sas []models.K8sServiceAccount) models.K8sRBACSnapshot {
	return models.K8sRBACSnapshot{
		Cluster: cluster, Complete: true, ClusterScoped: true,
		Roles: roles, Bindings: bindings, ServiceAccounts: sas,
	}
}

func sa(ns, name string) models.K8sServiceAccount {
	return models.K8sServiceAccount{
		Namespace: ns, Name: name,
		Anchor: "system:serviceaccount:" + ns + ":" + name,
	}
}

/* ------------------------- the ClusterRole indirection ------------------- */

// A namespaced RoleBinding pointing at a ClusterRole is how shared roles are
// normally granted. Resolving every roleRef as a namespaced Role would lose most
// real grants in a cluster.
func TestRoleBindingCanReferenceAClusterRole(t *testing.T) {
	res := Project(snapshot(
		[]models.K8sRole{{
			Kind: models.K8sKindClusterRole, Name: "secret-reader",
			Rules: []models.K8sPolicyRule{{
				APIGroups: []string{""}, Resources: []string{"secrets"},
				Verbs: []string{"get", "list"},
			}},
		}},
		[]models.K8sBinding{{
			Kind: models.K8sKindRoleBinding, Name: "read-secrets", Namespace: "prod",
			RoleRef:  models.K8sRoleRef{Kind: models.K8sKindClusterRole, Name: "secret-reader"},
			Subjects: []models.K8sSubject{{Kind: models.K8sSubjectServiceAccount, Name: "agent", Namespace: "prod"}},
		}},
		[]models.K8sServiceAccount{sa("prod", "agent")},
	))

	if len(res.Unresolved) != 0 {
		t.Fatalf("the ClusterRole should have resolved, got unresolved: %v", res.Unresolved)
	}
	if len(res.Edges) != 1 {
		t.Fatalf("want one grant edge, got %d", len(res.Edges))
	}
	e := res.Edges[0]
	if e.CalculationState != "complete" || e.EffectiveConclusion != "effective" {
		t.Errorf("a fully resolved chain is effective, got %s/%s",
			e.CalculationState, e.EffectiveConclusion)
	}
	// The role key must be the CLUSTER-scoped one. Resolving it as
	// "prod/secret-reader" would invent a namespaced role that does not exist.
	if !strings.Contains(e.PolicyKey, "clusterrole") {
		t.Errorf("roleRef resolved to the wrong scope: %q", e.PolicyKey)
	}
	if strings.Contains(e.PolicyKey, "prod") {
		t.Errorf("a ClusterRole reference must not be namespaced: %q", e.PolicyKey)
	}
}

// A Role and a ClusterRole may share a name. They are different objects and
// must not collide into one node.
func TestRoleAndClusterRoleWithTheSameNameAreDistinct(t *testing.T) {
	res := Project(snapshot(
		[]models.K8sRole{
			{Kind: models.K8sKindRole, Name: "reader", Namespace: "prod"},
			{Kind: models.K8sKindClusterRole, Name: "reader"},
		}, nil, nil,
	))
	if len(res.Policies) != 2 {
		t.Fatalf("want two distinct policies, got %d", len(res.Policies))
	}
	if res.Policies[0].SourceKey == res.Policies[1].SourceKey {
		t.Error("a namespaced Role and a ClusterRole of the same name collided into " +
			"one node; their access would be merged")
	}
}

/* --------------------------------- subjects ------------------------------ */

// A binding to system:serviceaccounts grants to EVERY ServiceAccount in the
// cluster. A mapping that only followed ServiceAccount subjects would show none
// of it — which is the single most over-reaching grant Kubernetes permits.
func TestGroupSubjectsAreNotDropped(t *testing.T) {
	res := Project(snapshot(
		[]models.K8sRole{{
			Kind: models.K8sKindClusterRole, Name: "cluster-admin",
			Rules: []models.K8sPolicyRule{{
				APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"},
			}},
		}},
		[]models.K8sBinding{{
			Kind: models.K8sKindClusterRoleBinding, Name: "oops",
			RoleRef:  models.K8sRoleRef{Kind: models.K8sKindClusterRole, Name: "cluster-admin"},
			Subjects: []models.K8sSubject{{Kind: models.K8sSubjectGroup, Name: "system:serviceaccounts"}},
		}},
		nil,
	))

	if len(res.Edges) != 1 {
		t.Fatalf("a Group subject must still produce a grant edge, got %d", len(res.Edges))
	}
	var group *Node
	for i := range res.Identities {
		if strings.Contains(res.Identities[i].SourceKey, "group") {
			group = &res.Identities[i]
		}
	}
	if group == nil {
		t.Fatal("the Group subject was not recorded as an identity; a cluster-admin " +
			"binding to it would be invisible")
	}
	if group.Attrs["grants_all_service_accounts"] != true {
		t.Error("system:serviceaccounts must be flagged as covering every " +
			"ServiceAccount — it looks unremarkable in a binding list otherwise")
	}
}

// A namespace-scoped variant is equally broad within its namespace.
func TestNamespacedServiceAccountGroupIsAlsoFlagged(t *testing.T) {
	if !isAllServiceAccountsGroup("system:serviceaccounts:prod") {
		t.Error("system:serviceaccounts:prod covers every SA in prod and must be flagged")
	}
	if isAllServiceAccountsGroup("developers") {
		t.Error("an ordinary group must not be flagged")
	}
}

// A User named "default" is not the "default" ServiceAccount.
func TestUserAndServiceAccountOfTheSameNameDoNotCollide(t *testing.T) {
	userKey := SubjectKey(cluster, models.K8sSubject{Kind: models.K8sSubjectUser, Name: "default"})
	saKey := SubjectKey(cluster, models.K8sSubject{
		Kind: models.K8sSubjectServiceAccount, Name: "default", Namespace: "default",
	})
	if userKey == saKey {
		t.Error("a User and a ServiceAccount of the same name produced one key; one " +
			"principal's access would be attributed to the other")
	}
}

/* -------------------------------- wildcards ------------------------------ */

// `*` is recorded, never expanded. An expansion is an interpretation with an
// expiry date — it would be wrong the moment a CRD is installed.
func TestWildcardsAreRecordedNotExpanded(t *testing.T) {
	res := Project(snapshot(
		[]models.K8sRole{{
			Kind: models.K8sKindClusterRole, Name: "admin",
			Rules: []models.K8sPolicyRule{{
				APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"},
			}},
		}}, nil, nil,
	))
	if len(res.Statements) != 1 {
		t.Fatalf("want one statement, got %d", len(res.Statements))
	}
	st := res.Statements[0]
	if !st.Wildcard {
		t.Error("a rule granting * must be flagged as a wildcard")
	}
	if len(st.Verbs) != 1 || st.Verbs[0] != "*" {
		t.Errorf("the verb must stay as *, got %v — expanding it would be wrong the "+
			"moment a new resource type exists", st.Verbs)
	}
}

// A rule narrowed by resourceNames is far weaker than the same rule without,
// and must not be flattened into it.
func TestResourceNamesAreKeptDistinct(t *testing.T) {
	broad := models.K8sPolicyRule{
		APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"},
	}
	narrow := models.K8sPolicyRule{
		APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"},
		ResourceNames: []string{"one-specific-secret"},
	}
	if StatementKey("role", broad) == StatementKey("role", narrow) {
		t.Error("a rule limited to named resources hashed the same as the unlimited " +
			"one; the graph would report read-any-secret for a read-one-secret grant")
	}
}

/* ---------------------------- statement identity ------------------------- */

// Rules have no identity of their own, so an index would reassign every edge
// when somebody inserts a rule at the top of the list.
func TestStatementIdentitySurvivesReordering(t *testing.T) {
	a := models.K8sPolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}
	b := models.K8sPolicyRule{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"list"}}

	first := Project(snapshot([]models.K8sRole{{
		Kind: models.K8sKindClusterRole, Name: "r", Rules: []models.K8sPolicyRule{a, b},
	}}, nil, nil))
	reordered := Project(snapshot([]models.K8sRole{{
		Kind: models.K8sKindClusterRole, Name: "r", Rules: []models.K8sPolicyRule{b, a},
	}}, nil, nil))

	keys := func(r Result) map[string]bool {
		out := map[string]bool{}
		for _, s := range r.Statements {
			out[s.StatementKey] = true
		}
		return out
	}
	k1, k2 := keys(first), keys(reordered)
	if len(k1) != 2 || len(k2) != 2 {
		t.Fatalf("want two statements each, got %d and %d", len(k1), len(k2))
	}
	for k := range k1 {
		if !k2[k] {
			t.Error("reordering a role's rules changed their identity; every edge " +
				"downstream would be rewritten by a cosmetic edit")
		}
	}
}

// Sorting inside a rule must not change its identity either.
func TestStatementIdentityIgnoresIntraRuleOrder(t *testing.T) {
	x := models.K8sPolicyRule{Verbs: []string{"get", "list"}, Resources: []string{"pods"}}
	y := models.K8sPolicyRule{Verbs: []string{"list", "get"}, Resources: []string{"pods"}}
	if StatementKey("r", x) != StatementKey("r", y) {
		t.Error("the same rule written with its verbs in a different order produced " +
			"two statements")
	}
}

/* ------------------------------- honesty --------------------------------- */

// A binding whose role is missing must yield an honest partial edge, not
// silence. A dropped edge reads as "no access", which is a stronger and wrong
// claim than "we could not resolve this".
func TestUnresolvedRoleYieldsAPartialEdgeNotSilence(t *testing.T) {
	res := Project(snapshot(
		nil, // the role is absent
		[]models.K8sBinding{{
			Kind: models.K8sKindClusterRoleBinding, Name: "dangling",
			RoleRef:  models.K8sRoleRef{Kind: models.K8sKindClusterRole, Name: "gone"},
			Subjects: []models.K8sSubject{{Kind: models.K8sSubjectServiceAccount, Name: "agent", Namespace: "prod"}},
		}},
		nil,
	))

	if len(res.Unresolved) != 1 {
		t.Errorf("the dangling reference must be reported, got %v", res.Unresolved)
	}
	if len(res.Edges) != 1 {
		t.Fatalf("want one partial edge, got %d — dropping it would read as 'no access'",
			len(res.Edges))
	}
	e := res.Edges[0]
	if e.CalculationState != "partial" || e.EffectiveConclusion != "unknown" {
		t.Errorf("an unresolved chain must be partial/unknown, got %s/%s",
			e.CalculationState, e.EffectiveConclusion)
	}
	// The honesty CHECK on iga_access_edges rejects a conclusion without a
	// complete calculation, so getting this backwards fails at the database.
	if e.EffectiveConclusion != "unknown" && e.CalculationState != "complete" {
		t.Error("this row would violate iga_access_edges_honesty_chk")
	}
}

// The bridge hazard, asserted rather than trusted to a comment.
func TestProjectionProducesNoAgentRows(t *testing.T) {
	res := Project(snapshot(
		[]models.K8sRole{{Kind: models.K8sKindClusterRole, Name: "r"}},
		[]models.K8sBinding{{
			Kind: models.K8sKindClusterRoleBinding, Name: "b",
			RoleRef:  models.K8sRoleRef{Kind: models.K8sKindClusterRole, Name: "r"},
			Subjects: []models.K8sSubject{{Kind: models.K8sSubjectServiceAccount, Name: "research-agent", Namespace: "prod"}},
		}},
		[]models.K8sServiceAccount{sa("prod", "research-agent")},
	))

	// Every identity this projector emits is an identity ACCOUNT. If a future
	// change adds an agent node here, the Kubernetes bridge's name matching
	// starts proposing correlations against rows we created ourselves.
	for _, n := range res.Identities {
		if strings.Contains(n.Kind, "agent") {
			t.Errorf("projector emitted an agent-shaped node (%s/%s); the discovery "+
				"bridge matches sightings against iga_agents by name and would "+
				"correlate against our own rows", n.Kind, n.SourceKey)
		}
	}
}

// Two ServiceAccounts of the same name in different namespaces are different
// identities.
func TestServiceAccountKeysAreNamespaced(t *testing.T) {
	if ServiceAccountKey(cluster, "prod", "agent") == ServiceAccountKey(cluster, "staging", "agent") {
		t.Error("the same ServiceAccount name in two namespaces produced one key")
	}
}

// Two clusters may run identically-named workloads. Their access must not merge.
func TestKeysAreClusterScoped(t *testing.T) {
	if ServiceAccountKey("prod-1", "ns", "a") == ServiceAccountKey("prod-2", "ns", "a") {
		t.Error("identically-named ServiceAccounts in two clusters produced one key")
	}
}

/* ------------------------------ unified inventory ------------------------- */

// Two workloads reporting the same display name in one namespace are two
// workloads. The name key merged them, and one's access read as the other's.
func TestWorkloadsWithTheSameNameKeepDistinctKeys(t *testing.T) {
	res := ProjectWorkloads(cluster, []WorkloadSighting{
		{Fingerprint: "fp-a", DisplayName: "agent", Namespace: "prod", RuntimeStatus: "running"},
		{Fingerprint: "fp-b", DisplayName: "agent", Namespace: "prod", RuntimeStatus: "running"},
	})
	if len(res.Workloads) != 2 {
		t.Fatalf("got %d workloads, want 2", len(res.Workloads))
	}
	a, b := res.Workloads[0], res.Workloads[1]
	if a.SourceKey == b.SourceKey {
		t.Errorf("same-name workloads share key %q", a.SourceKey)
	}
	if a.SourceKey != WorkloadKey(cluster, "fp-a") {
		t.Errorf("key = %q, want the fingerprint key", a.SourceKey)
	}
	if a.LegacyKey != LegacyWorkloadKey(cluster, "prod", "agent") {
		t.Errorf("legacy key = %q, want the old name key so the row can be re-keyed", a.LegacyKey)
	}
}

func TestRuntimeKindFollowsTheWorkloadKind(t *testing.T) {
	for in, want := range map[string]string{
		"Deployment":  "k8s_deployment",
		"StatefulSet": "k8s_statefulset",
		"DaemonSet":   "k8s_daemonset",
		"CronJob":     "k8s_cronjob",
		"Job":         "k8s_job",
		"Pod":         "k8s_pod",
		" Pod ":       "k8s_pod",
		"":            "k8s_workload",
		"weird kind":  "k8s_workload",
	} {
		if got := RuntimeKind(in); got != want {
			t.Errorf("RuntimeKind(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestInventoryScopeKeys(t *testing.T) {
	snap := snapshot(
		[]models.K8sRole{{Kind: models.K8sKindClusterRole, Name: "view",
			Rules: []models.K8sPolicyRule{{Verbs: []string{"get"}, Resources: []string{"pods"}}}}},
		[]models.K8sBinding{{Kind: models.K8sKindClusterRoleBinding, Name: "b",
			RoleRef:  models.K8sRoleRef{Kind: models.K8sKindClusterRole, Name: "view"},
			Subjects: []models.K8sSubject{{Kind: models.K8sSubjectUser, Name: "alice"}}}},
		[]models.K8sServiceAccount{sa("prod", "agent")},
	)
	res := Project(snap)
	byKey := map[string]Node{}
	for _, n := range res.Identities {
		byKey[n.SourceKey] = n
	}
	check := func(what string, attrs map[string]any, sub any) {
		t.Helper()
		if attrs["scope_kind"] != ScopeKindCluster || attrs["scope_id"] != cluster ||
			attrs["scope_label"] != cluster {
			t.Errorf("%s scope keys wrong: %v", what, attrs)
		}
		if v, ok := attrs["sub_scope"]; !ok || v != sub {
			t.Errorf("%s sub_scope = %v (present %v), want %v", what, v, ok, sub)
		}
	}
	saNode := byKey[ServiceAccountKey(cluster, "prod", "agent")]
	check("service account", saNode.Attrs, "prod")
	if saNode.Attrs["name"] != "agent" || saNode.Attrs["cluster"] != cluster {
		t.Errorf("existing service account attrs lost: %v", saNode.Attrs)
	}
	check("user", byKey[Key(cluster, "user", "alice")].Attrs, nil)

	w := ProjectWorkloads(cluster, []WorkloadSighting{{Fingerprint: "fp", Namespace: "prod"}})
	check("workload", w.Workloads[0].Attrs, "prod")
	if w.Workloads[0].Attrs["fingerprint"] != "fp" {
		t.Errorf("existing workload attrs lost: %v", w.Workloads[0].Attrs)
	}
}

// Every namespace a sweep covers owns a workload partition and an executes_as
// partition. Without them the reconciler never looks at either.
func TestPartitionsIncludeWorkloadsAndExecutesAs(t *testing.T) {
	sc := Scope{Cluster: cluster, Complete: true, ClusterScoped: true, Namespaces: []string{"a", "b"}}
	var classes, targets int
	for _, p := range Partitions(sc) {
		if p.Class == ClassWorkload {
			classes++
		}
		if p.Target == TargetExecutesAs {
			targets++
		}
	}
	// cluster + a + b
	if classes != 3 || targets != 3 {
		t.Errorf("workload partitions = %d, executes_as partitions = %d, want 3 and 3", classes, targets)
	}
	if !sc.CanEnd(PartitionForWorkload(sc, "a")) {
		t.Error("a complete sweep covering namespace a cannot end its workloads")
	}
}
