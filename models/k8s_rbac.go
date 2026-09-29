package models

// The Kubernetes RBAC snapshot, as posted by the in-cluster agent.
//
// This is a WIRE CONTRACT with a binary that upgrades on the customer's
// schedule, not ours. Fields may be added; none may change meaning. It mirrors
// iga-agent/internal/rbacscan exactly — the two are related only by these json
// tags, so a rename on either side is a silent break.
//
// Nothing here is stored as-is. The snapshot is projected into the shared
// iga_* graph under provider 'k8s'; these types exist only to decode it.

// K8sPolicyRule is one rule from a Role or ClusterRole.
//
// The fields are lists and the semantics are a cross product: every verb on
// every resource in every group. `*` is legal in all three, and ResourceNames —
// when present — narrows the rule to named instances, which makes it far weaker
// than the same rule without. Treating those as equivalent would overstate
// access badly, so the distinction is carried all the way into the graph.
type K8sPolicyRule struct {
	APIGroups       []string `json:"apiGroups,omitempty"`
	Resources       []string `json:"resources,omitempty"`
	Verbs           []string `json:"verbs,omitempty"`
	ResourceNames   []string `json:"resourceNames,omitempty"`
	NonResourceURLs []string `json:"nonResourceURLs,omitempty"`
}

// K8sRole is a namespaced Role or a cluster-scoped ClusterRole.
// Namespace empty means cluster-scoped.
type K8sRole struct {
	Kind      string          `json:"kind"`
	Name      string          `json:"name"`
	Namespace string          `json:"namespace,omitempty"`
	UID       string          `json:"uid,omitempty"`
	Rules     []K8sPolicyRule `json:"rules,omitempty"`
	// Aggregated marks a ClusterRole whose rules the controller fills in from
	// other roles. Its contents change without anyone editing it, which matters
	// when explaining why an agent's access changed.
	Aggregated bool `json:"aggregated,omitempty"`
}

// K8sSubject is who a binding grants to: ServiceAccount, User, or Group.
//
// The Group case is the one that catches people out — a binding to
// `system:serviceaccounts` grants to EVERY ServiceAccount in the cluster.
type K8sSubject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// K8sRoleRef is what a binding points at.
//
// Kind is Role or ClusterRole, and a namespaced RoleBinding may reference a
// ClusterRole — the ordinary way a shared role is granted inside one namespace.
// So the edge is never simply "RoleBinding → Role".
type K8sRoleRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// K8sBinding is a RoleBinding or ClusterRoleBinding.
type K8sBinding struct {
	Kind      string       `json:"kind"`
	Name      string       `json:"name"`
	Namespace string       `json:"namespace,omitempty"`
	UID       string       `json:"uid,omitempty"`
	RoleRef   K8sRoleRef   `json:"role_ref"`
	Subjects  []K8sSubject `json:"subjects,omitempty"`
}

// K8sServiceAccount is an identity a workload runs as.
//
// Secrets carries token secret NAMES only — never contents. The agent does not
// fetch them and this struct has nowhere to put one.
type K8sServiceAccount struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	UID       string   `json:"uid,omitempty"`
	Secrets   []string `json:"secrets,omitempty"`
	// Anchor is "system:serviceaccount:<ns>:<name>" — the same principal string
	// the sighting path emits as provisioning_hints.identity_anchor and the AWS
	// collector writes as cloud_assume_edge.k8s_ref, so all three join without a
	// translation table.
	Anchor string `json:"anchor"`
}

// K8sRBACSnapshot is one complete reading of a cluster's authorization model.
type K8sRBACSnapshot struct {
	WorkspaceID       string `json:"workspace_id"`
	Source            string `json:"source"`
	DiscoverySourceID string `json:"discovery_source_id,omitempty"`
	Cluster           string `json:"cluster"`
	ScanKind          string `json:"scan_kind"`

	SweepStartedAt string `json:"sweep_started_at"`
	ObservedAt     string `json:"observed_at"`

	// Complete is false when any list in the sweep failed. Nothing may be
	// retired from an incomplete snapshot: one transient 403 would otherwise
	// delete a cluster's whole authorization model and restore it next sweep,
	// with a governance alert in between.
	Complete bool `json:"complete"`

	// ClusterScoped is false when only namespaced objects could be read.
	// ClusterRoleBindings are where the dangerous grants live, so this is not a
	// smaller answer — it is a different one, and the graph must say so.
	ClusterScoped bool `json:"cluster_scoped"`

	Namespaces []string `json:"namespaces"`

	ServiceAccounts []K8sServiceAccount `json:"service_accounts"`
	Roles           []K8sRole           `json:"roles"`
	Bindings        []K8sBinding        `json:"bindings"`
}

// Kubernetes object kinds, as they appear on the wire.
const (
	K8sKindRole               = "Role"
	K8sKindClusterRole        = "ClusterRole"
	K8sKindRoleBinding        = "RoleBinding"
	K8sKindClusterRoleBinding = "ClusterRoleBinding"

	K8sSubjectServiceAccount = "ServiceAccount"
	K8sSubjectUser           = "User"
	K8sSubjectGroup          = "Group"
)

// Graph vocabulary for the Kubernetes provider. These are the values written
// into the shared iga_* columns, widened by migration 038 where a CHECK
// constrains them.
const (
	// policy_kind
	K8sPolicyKindRole        = "k8s_role"
	K8sPolicyKindClusterRole = "k8s_cluster_role"

	// assignment_kind
	K8sAssignmentRoleBinding        = "k8s_role_binding"
	K8sAssignmentClusterRoleBinding = "k8s_cluster_role_binding"

	// account_kind — not CHECK-constrained, but spelled once here.
	K8sAccountKindServiceAccount = "k8s_service_account"

	// resource_kind
	K8sResourceKind = "k8s_resource"

	// relationship_type, for workload → ServiceAccount.
	K8sRelationshipExecutesAs = "executes_as"
)
