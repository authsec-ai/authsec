package integration

// The Kubernetes graph fixture for p2_k8s_graph_*_test.go: a cluster written
// through the REAL projection -- services.NewK8sRBACManager(...).Ingest with a
// snapshot and a discovered_agents sighting, the path the in-cluster agent's
// push takes -- into a P2 lab workspace, read back through the REAL §5.3 route
// table (readAPI) or the traversal's budget seam (graphDirect).
//
// The world (cluster kg-cluster, namespace iga-demo):
//
//	research-agent (Deployment)  --executes_as (observed)-->  SA iga-demo/research
//	SA research  <- ClusterRoleBinding research-reads-secrets   -> ClusterRole secret-reader
//	             <- RoleBinding iga-demo/research-secrets-ns     -> ClusterRole secret-reader
//	             <- RoleBinding iga-demo/research-pods           -> Role iga-demo/pod-reader
//	             <- RoleBinding iga-demo/dangling                -> Role iga-demo/missing (not in the sweep)
//	SA iga-demo/idle: no binding, no workload
//
//	secret-reader  get, list secrets
//	pod-reader     get pods; list, watch configmaps
//
// so the research SA holds four grants (two to one rule, through two
// bindings), and one binding that resolves to nothing.

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

const (
	k8sGraphCluster = "kg-cluster"
	k8sGraphNS      = "iga-demo"
)

// k8sGraphLab is a P2 lab with a Kubernetes discovery source.
type k8sGraphLab struct {
	*p2Lab
	src uuid.UUID
	mgr services.K8sRBACManager
	at  time.Time // the next sweep's observed_at
}

func newK8sGraphLab(t *testing.T, name string) *k8sGraphLab {
	t.Helper()
	l := newP2Lab(t, name, true)
	src := uuid.New()
	if err := l.db.Exec(`INSERT INTO discovery_sources (id, workspace_id, kind, display_name, cluster_name)
	                     VALUES (?, ?, ?, ?, ?)`, src, l.ws, models.DiscoverySourceK8sWebhook,
		"agent-"+src.String()[:8], k8sGraphCluster).Error; err != nil {
		t.Fatalf("discovery source: %v", err)
	}
	// Registered after the lab's own cleanup, so it runs first: the sweep,
	// the sighting and the source are not in the lab's table list. Deleting
	// the source cascades to the rows it supports.
	t.Cleanup(func() {
		for _, table := range []string{"discovered_agents", "iga_k8s_sweep", "discovery_sources"} {
			if err := l.db.Exec(`DELETE FROM `+table+` WHERE workspace_id = ?`, l.ws).Error; err != nil {
				t.Logf("cleanup %s: %v", table, err)
			}
		}
	})
	return &k8sGraphLab{
		p2Lab: l, src: src,
		mgr: services.NewK8sRBACManager(l.db, l.gate),
		at:  time.Now().UTC().Truncate(time.Second).Add(-2 * time.Hour),
	}
}

// agent records a discovered agent running as a ServiceAccount, as the
// admission webhook would.
func (k *k8sGraphLab) agent(name, namespace, anchor, kind string) {
	k.t.Helper()
	md := `{"cluster":{"name":"` + k8sGraphCluster + `"},"kubernetes":{"namespace":"` + namespace +
		`","workload_kind":"` + kind + `"},"provisioning_hints":{"identity_anchor":"` + anchor + `"}}`
	if err := k.db.Exec(`INSERT INTO discovered_agents
	    (workspace_id, source, discovery_source_id, fingerprint, display_name, metadata, status,
	     runtime_status, observed_service_account)
	    VALUES (?, ?, ?, ?, ?, ?::jsonb, 'unregistered', 'running', ?)`,
		k.ws, models.DiscoverySourceK8sWebhook, k.src, "fp-"+name, name, md, anchor).Error; err != nil {
		k.t.Fatalf("agent %s: %v", name, err)
	}
}

// k8sWorld is what one sweep reports.
type k8sWorld struct {
	complete, clusterScoped bool
	namespaces              []string
	// drop names bindings the sweep no longer sees.
	drop map[string]bool
	// crossNamespace adds a RoleBinding in iga-demo naming a ServiceAccount
	// of the namespace "other".
	crossNamespace bool
}

func k8sFullWorld() k8sWorld {
	return k8sWorld{complete: true, clusterScoped: true, namespaces: []string{k8sGraphNS}}
}

func (w k8sWorld) snapshot(k *k8sGraphLab, at time.Time) models.K8sRBACSnapshot {
	sa := func(name string) models.K8sSubject {
		return models.K8sSubject{Kind: models.K8sSubjectServiceAccount, Name: name, Namespace: k8sGraphNS}
	}
	bindings := []models.K8sBinding{
		{Kind: models.K8sKindClusterRoleBinding, Name: "research-reads-secrets",
			RoleRef:  models.K8sRoleRef{Kind: models.K8sKindClusterRole, Name: "secret-reader"},
			Subjects: []models.K8sSubject{sa("research")}},
		{Kind: models.K8sKindRoleBinding, Name: "research-secrets-ns", Namespace: k8sGraphNS,
			RoleRef:  models.K8sRoleRef{Kind: models.K8sKindClusterRole, Name: "secret-reader"},
			Subjects: []models.K8sSubject{sa("research")}},
		{Kind: models.K8sKindRoleBinding, Name: "research-pods", Namespace: k8sGraphNS,
			RoleRef:  models.K8sRoleRef{Kind: models.K8sKindRole, Name: "pod-reader"},
			Subjects: []models.K8sSubject{sa("research")}},
		{Kind: models.K8sKindRoleBinding, Name: "dangling", Namespace: k8sGraphNS,
			RoleRef:  models.K8sRoleRef{Kind: models.K8sKindRole, Name: "missing"},
			Subjects: []models.K8sSubject{sa("research")}},
	}
	if w.crossNamespace {
		bindings = append(bindings, models.K8sBinding{Kind: models.K8sKindRoleBinding, Name: "helper-pods", Namespace: k8sGraphNS,
			RoleRef:  models.K8sRoleRef{Kind: models.K8sKindRole, Name: "pod-reader"},
			Subjects: []models.K8sSubject{{Kind: models.K8sSubjectServiceAccount, Name: "helper", Namespace: "other"}}})
	}
	var kept []models.K8sBinding
	for _, b := range bindings {
		if !w.drop[b.Name] {
			kept = append(kept, b)
		}
	}
	return models.K8sRBACSnapshot{
		WorkspaceID: k.ws.String(), DiscoverySourceID: k.src.String(), Source: models.DiscoverySourceK8sWebhook,
		Cluster: k8sGraphCluster, ScanKind: "rbac",
		// Started half a minute before it was observed, so it starts after the
		// previous sweep (a minute earlier) finished: a sweep may end only what
		// was last confirmed BEFORE it started (the reconciler's fence).
		SweepStartedAt: at.Add(-30 * time.Second).Format(time.RFC3339), ObservedAt: at.Format(time.RFC3339),
		Complete: w.complete, ClusterScoped: w.clusterScoped, Namespaces: w.namespaces,
		ServiceAccounts: []models.K8sServiceAccount{
			{Name: "research", Namespace: k8sGraphNS, Anchor: "system:serviceaccount:" + k8sGraphNS + ":research"},
			{Name: "idle", Namespace: k8sGraphNS, Anchor: "system:serviceaccount:" + k8sGraphNS + ":idle"},
		},
		Roles: []models.K8sRole{
			{Kind: models.K8sKindClusterRole, Name: "secret-reader", Rules: []models.K8sPolicyRule{
				{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}},
			}},
			{Kind: models.K8sKindRole, Name: "pod-reader", Namespace: k8sGraphNS, Rules: []models.K8sPolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"list", "watch"}},
			}},
		},
		Bindings: kept,
	}
}

// sweep ingests one sweep of the world, a minute after the last.
func (k *k8sGraphLab) sweep(w k8sWorld) *services.K8sRBACResult {
	k.t.Helper()
	k.at = k.at.Add(time.Minute)
	res, err := k.mgr.Ingest(k.ws, w.snapshot(k, k.at))
	if err != nil {
		k.t.Fatalf("ingest: %v", err)
	}
	if !res.Accepted || !res.Reconciled {
		k.t.Fatalf("ingest not applied: %+v", res)
	}
	return res
}

// k8sGraphFixture is the world after one complete, cluster-wide sweep, with
// the refs the tests use.
type k8sGraphFixture struct {
	*k8sGraphLab
	workload, research, idle    string
	secretRule, podRule, cmRule string
	secretReader, podReader     string // policy refs
}

func newK8sGraphFixture(t *testing.T, name string) *k8sGraphFixture {
	t.Helper()
	k := newK8sGraphLab(t, name)
	k.agent("research-agent", k8sGraphNS, "system:serviceaccount:"+k8sGraphNS+":research", "Deployment")
	res := k.sweep(k8sFullWorld())
	if res.Workloads != 1 || res.ExecutesAs != 1 || res.Unresolved != 1 {
		t.Fatalf("fixture sweep = %+v, want one workload, one executes_as, one unresolved binding", res)
	}
	return k.fixture()
}

func (k *k8sGraphLab) fixture() *k8sGraphFixture {
	f := &k8sGraphFixture{k8sGraphLab: k}
	f.workload = refOf("workload", k.k8sID("iga_workload", "display_name = ?", "research-agent"))
	f.research = refOf("identity", k.k8sID("iga_identity_accounts", "display_name = ?", "system:serviceaccount:iga-demo:research"))
	f.idle = refOf("identity", k.k8sID("iga_identity_accounts", "display_name = ?", "system:serviceaccount:iga-demo:idle"))
	f.secretReader = refOf("policy", k.k8sID("iga_policy", "display_name = ?", "secret-reader"))
	f.podReader = refOf("policy", k.k8sID("iga_policy", "display_name = ?", "iga-demo/pod-reader"))
	f.secretRule = k.k8sRule("secret-reader", "secrets")
	f.podRule = k.k8sRule("iga-demo/pod-reader", "pods")
	f.cmRule = k.k8sRule("iga-demo/pod-reader", "configmaps")
	return f
}

// k8sID is the id of one live Kubernetes row.
func (k *k8sGraphLab) k8sID(table, where string, args ...any) uuid.UUID {
	k.t.Helper()
	var id uuid.UUID
	if err := k.db.Raw(`SELECT id FROM `+table+` WHERE workspace_id = ? AND provider = 'k8s' AND `+where+
		` ORDER BY (lifecycle = 'active') DESC LIMIT 1`, append([]any{k.ws}, args...)...).Row().Scan(&id); err != nil {
		k.t.Fatalf("no k8s %s where %s %v: %v", table, where, args, err)
	}
	return id
}

// k8sRule is the ref of a role's rule naming a resource.
func (k *k8sGraphLab) k8sRule(policy, resource string) string {
	k.t.Helper()
	var id uuid.UUID
	if err := k.db.Raw(`SELECT e.id FROM iga_entitlements e JOIN iga_policy p ON p.id = e.policy_id
	                     WHERE e.workspace_id = ? AND e.provider = 'k8s' AND p.display_name = ?
	                       AND jsonb_exists(e.native_rights->'resources', ?)
	                     LIMIT 1`, k.ws, policy, resource).Row().Scan(&id); err != nil {
		k.t.Fatalf("no rule of %s on %s: %v", policy, resource, err)
	}
	return refOf("statement", id)
}
