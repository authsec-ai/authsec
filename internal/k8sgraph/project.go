// Package k8sgraph turns a Kubernetes RBAC snapshot into the shared iga_* graph
// under provider 'k8s'.
//
// A SIBLING OF internal/igagraph, NOT AN EDIT OF IT. That package is written
// against models.Cloud* and filters `provider = 'aws'` throughout; the tables it
// writes are provider-neutral by design (SPEC §1.5) but the projector is not.
// Rather than generalise a working AWS path under a Kubernetes deadline, this
// package mirrors its shape — recognition keys, continuity, honest calculation
// state — for the Kubernetes shapes.
//
// Nothing here opens a database connection. It maps a snapshot to rows; the
// service writes them. That split is what makes the mapping testable, and the
// mapping is where a silent error becomes a wrong answer about who can do what.
//
// # WHAT THIS DELIBERATELY DOES NOT DO
//
//   - It does not expand wildcards. A rule granting `*` on `*` is stored as
//     `*`, not as every verb on every resource that happens to exist today. The
//     rule is the fact; an expansion is an interpretation with an expiry date.
//   - It does not evaluate conditions, because Kubernetes RBAC has none — which
//     is worth saying, since the absence is what makes an observed binding
//     genuinely effective rather than merely configured.
//   - It writes NO iga_agents or iga_agent_instances rows. See the note on
//     Project.
package k8sgraph

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/authsec-ai/authsec/models"
)

// Sep is the unit separator joining source-key segments. The same one
// internal/igagraph uses, and for the same reason: it cannot occur in a
// Kubernetes name, namespace, or API group, so no join is ambiguous and no
// segment needs escaping.
const Sep = "\x1f"

// Key builds a namespaced source key: k8s ␟ cluster ␟ part ␟ part…
//
// THE ONLY PLACE A KEY IS FORMATTED. Two spellings of a key is the duplication
// bug wearing a different hat: the second spelling creates a second node that
// looks like a real one.
func Key(cluster string, parts ...string) string {
	return models.ProviderK8s + Sep + cluster + Sep + strings.Join(parts, Sep)
}

// RoleKey identifies a Role or ClusterRole.
//
// A namespaced Role and a ClusterRole may share a name — they are different
// objects in different scopes — so the kind and namespace are both in the key.
func RoleKey(cluster string, r models.K8sRole) string {
	if r.Namespace == "" {
		return Key(cluster, "clusterrole", r.Name)
	}
	return Key(cluster, "role", r.Namespace, r.Name)
}

// RoleRefKey resolves what a binding points AT, in the binding's own scope.
//
// The subtlety this exists for: a namespaced RoleBinding may reference either a
// Role in its own namespace or a cluster-wide ClusterRole. Resolving every
// roleRef as namespaced would miss most real grants, and resolving every one as
// cluster-scoped would invent roles that do not exist.
func RoleRefKey(cluster string, b models.K8sBinding) string {
	if b.RoleRef.Kind == models.K8sKindClusterRole {
		return Key(cluster, "clusterrole", b.RoleRef.Name)
	}
	// A Role reference is always resolved in the binding's own namespace;
	// Kubernetes offers no way to reference a Role in another one.
	return Key(cluster, "role", b.Namespace, b.RoleRef.Name)
}

// BindingKey identifies a RoleBinding or ClusterRoleBinding.
func BindingKey(cluster string, b models.K8sBinding) string {
	if b.Namespace == "" {
		return Key(cluster, "clusterrolebinding", b.Name)
	}
	return Key(cluster, "rolebinding", b.Namespace, b.Name)
}

// ServiceAccountKey identifies a ServiceAccount by its canonical principal.
func ServiceAccountKey(cluster, namespace, name string) string {
	return Key(cluster, "serviceaccount", namespace, name)
}

// SubjectKey identifies any binding subject.
//
// Users and Groups are NOT ServiceAccounts and must never collide with one: a
// User named "default" in a cluster with a `default` ServiceAccount is a
// different principal, and merging them would attribute one's access to the
// other.
func SubjectKey(cluster string, s models.K8sSubject) string {
	switch s.Kind {
	case models.K8sSubjectServiceAccount:
		return ServiceAccountKey(cluster, s.Namespace, s.Name)
	case models.K8sSubjectGroup:
		return Key(cluster, "group", s.Name)
	default:
		return Key(cluster, "user", s.Name)
	}
}

// StatementKey identifies one rule within a role, stably across sweeps.
//
// Rules are an ORDERED LIST with no identity of their own, so an index alone
// would reassign every downstream edge the moment somebody inserted a rule at
// the top. Hashing the rule's content instead means a rule keeps its identity
// wherever it moves in the list, and a genuinely changed rule becomes a new
// statement — which is the behaviour a reviewer expects.
func StatementKey(roleKey string, r models.K8sPolicyRule) string {
	h := sha256.New()
	// Sorted, so a cosmetic reordering inside one rule is not a new statement.
	for _, part := range [][]string{r.APIGroups, r.Resources, r.Verbs, r.ResourceNames, r.NonResourceURLs} {
		cp := append([]string(nil), part...)
		sort.Strings(cp)
		for _, v := range cp {
			_, _ = h.Write([]byte(v))
			_, _ = h.Write([]byte{0})
		}
		// Field separator, so ({verbs:[a]},{resources:[]}) and
		// ({verbs:[]},{resources:[a]}) cannot hash alike.
		_, _ = h.Write([]byte{1})
	}
	return roleKey + Sep + hex.EncodeToString(h.Sum(nil))[:16]
}

/* ------------------------------ the projection --------------------------- */

// Node is a graph vertex to upsert.
type Node struct {
	SourceKey   string
	Kind        string // account_kind | policy_kind | resource_kind
	DisplayName string
	Namespace   string
	// Attrs is written to provider_attrs. Structure only — never a value that
	// could be a credential.
	Attrs map[string]any
}

// Statement is one rule of a role, as an entitlement.
type Statement struct {
	PolicyKey    string
	StatementKey string
	Verbs        []string
	APIGroups    []string
	Resources    []string
	// ResourceNames narrows the rule to named instances. Kept distinct because a
	// rule with them is far weaker than the same rule without.
	ResourceNames   []string
	NonResourceURLs []string
	// Wildcard marks a rule granting `*` in any of group, resource or verb.
	// Surfaced rather than expanded, so the console can rank it without this
	// package guessing what `*` covers today.
	Wildcard bool
}

// Assignment binds a policy to a holder.
type Assignment struct {
	SourceKey  string
	PolicyKey  string
	HolderKey  string
	HolderKind string // ServiceAccount | User | Group
	Kind       string // k8s_role_binding | k8s_cluster_role_binding
	Namespace  string
}

// Edge is one subject→statement grant.
type Edge struct {
	SourceKey     string
	SubjectKey    string
	PolicyKey     string
	StatementKey  string
	AssignmentKey string
	// CalculationState is "complete" only when the whole chain resolved:
	// binding → roleRef → role → rule. A binding whose role is missing from the
	// snapshot is "partial", and its conclusion is "unknown".
	CalculationState string
	// EffectiveConclusion is "effective" for a resolved chain.
	//
	// That is a stronger claim than the AWS projector can make, and it is
	// defensible for exactly one reason: Kubernetes RBAC is PURELY ADDITIVE.
	// There are no deny rules and no conditions, so a rule reachable from a
	// subject is a rule the API server will honour. Nothing else in the snapshot
	// could take it away — missing data could only add MORE access, never remove
	// this. (Admission control can still refuse the action, but that is a
	// different layer and is not an authorization decision.)
	EffectiveConclusion string
}

// Result is everything one snapshot projects to.
type Result struct {
	Identities  []Node
	Policies    []Node
	Statements  []Statement
	Assignments []Assignment
	Edges       []Edge
	// Unresolved names bindings whose roleRef was not in the snapshot. Reported
	// rather than dropped: on a complete sweep it means a binding references a
	// role that does not exist (harmless but worth seeing), and on a partial one
	// it is the visible edge of what was missed.
	Unresolved []string
}

// Project maps a snapshot to graph rows.
//
// IT WRITES NO iga_agents OR iga_agent_instances, and that is a hard constraint
// rather than an omission. The Kubernetes bridge (services/iga_bridge_service.go)
// matches every discovered sighting against ALL active iga_agents by normalised
// display name. Rows written here would both fabricate self-correlations — a
// sighting matching a node this projector created from the same cluster — and
// break genuine ones, because a second candidate makes the match ambiguous and
// the bridge then proposes nothing. AWS avoids this for the same reason
// (SPEC §2.2, E16).
func Project(snap models.K8sRBACSnapshot) Result {
	cluster := snap.Cluster
	var res Result

	// --- identities ---------------------------------------------------------
	seenIdentity := map[string]bool{}
	addIdentity := func(key, kind, display, namespace string, attrs map[string]any) {
		if key == "" || seenIdentity[key] {
			return
		}
		seenIdentity[key] = true
		res.Identities = append(res.Identities, Node{
			SourceKey: key, Kind: kind, DisplayName: display,
			Namespace: namespace, Attrs: attrs,
		})
	}

	for _, sa := range snap.ServiceAccounts {
		addIdentity(
			ServiceAccountKey(cluster, sa.Namespace, sa.Name),
			models.K8sAccountKindServiceAccount,
			sa.Anchor,
			sa.Namespace,
			map[string]any{
				"cluster":   cluster,
				"namespace": sa.Namespace,
				"name":      sa.Name,
				"uid":       sa.UID,
				// Names only. The agent never reads the Secret.
				"token_secret_names": sa.Secrets,
			},
		)
	}

	// --- policies and their statements --------------------------------------
	roleByKey := map[string]models.K8sRole{}
	for _, r := range snap.Roles {
		key := RoleKey(cluster, r)
		roleByKey[key] = r

		kind := models.K8sPolicyKindRole
		if r.Namespace == "" {
			kind = models.K8sPolicyKindClusterRole
		}
		display := r.Name
		if r.Namespace != "" {
			display = r.Namespace + "/" + r.Name
		}
		res.Policies = append(res.Policies, Node{
			SourceKey: key, Kind: kind, DisplayName: display, Namespace: r.Namespace,
			Attrs: map[string]any{
				"cluster":   cluster,
				"namespace": r.Namespace,
				"name":      r.Name,
				"uid":       r.UID,
				// An aggregated ClusterRole's rules are maintained by the
				// controller, so its contents change with no edit to the object.
				// Worth surfacing when explaining why access changed.
				"aggregated": r.Aggregated,
			},
		})

		for _, rule := range r.Rules {
			res.Statements = append(res.Statements, Statement{
				PolicyKey:       key,
				StatementKey:    StatementKey(key, rule),
				Verbs:           rule.Verbs,
				APIGroups:       rule.APIGroups,
				Resources:       rule.Resources,
				ResourceNames:   rule.ResourceNames,
				NonResourceURLs: rule.NonResourceURLs,
				Wildcard:        hasWildcard(rule),
			})
		}
	}

	// --- bindings, and the edges they imply ---------------------------------
	for _, b := range snap.Bindings {
		bindingKey := BindingKey(cluster, b)
		roleKey := RoleRefKey(cluster, b)

		assignKind := models.K8sAssignmentRoleBinding
		if b.Namespace == "" {
			assignKind = models.K8sAssignmentClusterRoleBinding
		}

		role, roleResolved := roleByKey[roleKey]
		if !roleResolved {
			res.Unresolved = append(res.Unresolved, bindingKey+" -> "+roleKey)
		}

		for _, s := range b.Subjects {
			subjectKey := SubjectKey(cluster, s)

			// A User or Group subject is a principal we did not collect as an
			// object — Kubernetes has no User or Group objects to list. They are
			// still real holders of access, so they become identities here
			// rather than being dropped, which is what would otherwise hide a
			// cluster-admin binding to a group.
			if s.Kind != models.K8sSubjectServiceAccount {
				addIdentity(subjectKey, "k8s_"+strings.ToLower(s.Kind), s.Name, "",
					map[string]any{
						"cluster": cluster,
						"kind":    s.Kind,
						"name":    s.Name,
						// A binding to this group grants to every ServiceAccount
						// in the cluster. Flagged because it is the single most
						// over-reaching grant Kubernetes permits, and it looks
						// unremarkable in a list.
						"grants_all_service_accounts": s.Kind == models.K8sSubjectGroup &&
							isAllServiceAccountsGroup(s.Name),
					})
			} else {
				// A binding may name a ServiceAccount that does not exist, or one
				// in a namespace outside the swept scope. Record the identity so
				// the grant is not silently lost.
				addIdentity(subjectKey, models.K8sAccountKindServiceAccount,
					"system:serviceaccount:"+s.Namespace+":"+s.Name, s.Namespace,
					map[string]any{
						"cluster": cluster, "namespace": s.Namespace, "name": s.Name,
					})
			}

			res.Assignments = append(res.Assignments, Assignment{
				SourceKey:  bindingKey + Sep + subjectKey,
				PolicyKey:  roleKey,
				HolderKey:  subjectKey,
				HolderKind: s.Kind,
				Kind:       assignKind,
				Namespace:  b.Namespace,
			})

			if !roleResolved {
				// The chain stops here. One edge, honestly incomplete, rather
				// than none — a missing edge would read as "no access", which is
				// a stronger and wrong claim.
				res.Edges = append(res.Edges, Edge{
					SourceKey:           bindingKey + Sep + subjectKey,
					SubjectKey:          subjectKey,
					PolicyKey:           roleKey,
					AssignmentKey:       bindingKey + Sep + subjectKey,
					CalculationState:    "partial",
					EffectiveConclusion: "unknown",
				})
				continue
			}

			for _, rule := range role.Rules {
				stKey := StatementKey(roleKey, rule)
				res.Edges = append(res.Edges, Edge{
					SourceKey:     bindingKey + Sep + subjectKey + Sep + stKey,
					SubjectKey:    subjectKey,
					PolicyKey:     roleKey,
					StatementKey:  stKey,
					AssignmentKey: bindingKey + Sep + subjectKey,
					// The whole chain resolved, and Kubernetes RBAC is additive
					// with no deny — so this is effective, not merely configured.
					CalculationState:    "complete",
					EffectiveConclusion: "effective",
				})
			}
		}
	}

	return res
}

// hasWildcard reports whether a rule grants `*` in any dimension.
func hasWildcard(r models.K8sPolicyRule) bool {
	for _, set := range [][]string{r.APIGroups, r.Resources, r.Verbs} {
		for _, v := range set {
			if v == "*" {
				return true
			}
		}
	}
	return false
}

// isAllServiceAccountsGroup reports whether a group name covers every
// ServiceAccount in the cluster.
//
// `system:serviceaccounts` is all of them; `system:serviceaccounts:<ns>` is
// every one in that namespace. Both are far broader than they look in a binding
// list, which is why they are flagged rather than left for a reader to notice.
func isAllServiceAccountsGroup(name string) bool {
	return name == "system:serviceaccounts" ||
		strings.HasPrefix(name, "system:serviceaccounts:")
}
