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
//   - It does not EVALUATE access. A grant records what RBAC declares -- this
//     subject is bound to this rule -- and nothing more. Whether a request
//     would actually succeed also depends on admission control, token
//     automount and audiences, and resourceNames semantics, none of which is
//     read here. So every grant is basis 'declared', calculation_state
//     'partial', effective_conclusion 'unknown': honest about being a
//     configuration fact rather than an evaluated decision.
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
//
// Every Kubernetes grant is DECLARED, NOT EVALUATED: RBAC says what is
// allowed, but admission control, token automount and audiences, and
// resourceNames semantics are not evaluated, so no grant may claim to be
// effective. A resolved chain (binding → role → rule) carries a StatementKey;
// an unresolved one (the role was not in the snapshot) carries none. Both are
// calculation_state 'partial' and effective_conclusion 'unknown' -- the
// difference between them is the missing statement, not a stronger claim.
type Edge struct {
	SourceKey     string
	SubjectKey    string
	PolicyKey     string
	StatementKey  string
	AssignmentKey string
	// CalculationState is always GrantCalculation (see above).
	CalculationState string
	// EffectiveConclusion is always GrantConclusion (see above).
	EffectiveConclusion string
}

// Grant honesty for every Kubernetes access edge. The service writes these
// together; the access-edge honesty CHECK allows an 'unknown' conclusion from
// any calculation state.
const (
	GrantBasis       = models.BasisDeclared
	GrantCalculation = "partial"
	GrantConclusion  = "unknown"
)

// Membership is a ServiceAccount's membership of one of the groups Kubernetes
// puts every ServiceAccount in implicitly:
//
//	system:serviceaccounts          every ServiceAccount
//	system:serviceaccounts:<ns>     every ServiceAccount in <ns>
//	system:authenticated            every authenticated principal
//
// A binding to one of these groups grants to the ServiceAccount, and the
// snapshot never says so: Kubernetes has no membership objects to list. It is
// written as an iga_relationship member_of row (ServiceAccount → group) ONLY
// for groups some binding in the snapshot names -- a group nobody grants to
// adds nothing to anyone's access, and creating it would fill the graph with
// nodes that mean nothing.
type Membership struct {
	SourceKey string
	MemberKey string // the ServiceAccount identity
	GroupKey  string // the Group identity
	// Namespace is the ServiceAccount's namespace, which owns the row's
	// partition (see TargetMemberOf).
	Namespace string
}

// Implicit group names.
const (
	GroupAllServiceAccounts = "system:serviceaccounts"
	GroupAuthenticated      = "system:authenticated"
)

// NamespaceServiceAccountsGroup is the implicit group of every ServiceAccount
// in one namespace.
func NamespaceServiceAccountsGroup(ns string) string {
	return GroupAllServiceAccounts + ":" + ns
}

// GroupKey identifies a Group subject.
func GroupKey(cluster, name string) string {
	return SubjectKey(cluster, models.K8sSubject{Kind: models.K8sSubjectGroup, Name: name})
}

// MemberOfKey names a member_of relationship by its endpoints.
func MemberOfKey(memberKey, groupKey string) string {
	return models.RelTypeMemberOf + Sep + memberKey + Sep + groupKey
}

// Result is everything one snapshot projects to.
type Result struct {
	Identities  []Node
	Policies    []Node
	Statements  []Statement
	Assignments []Assignment
	Edges       []Edge
	Memberships []Membership
	// Unresolved names bindings whose roleRef was not in the snapshot, and
	// ServiceAccount subjects that cannot be placed in a namespace (one with no
	// namespace under a ClusterRoleBinding). Reported
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
		// Every identity carries the unified-inventory scope: the cluster, and
		// its namespace -- null for a User or Group, which Kubernetes does not
		// scope.
		res.Identities = append(res.Identities, Node{
			SourceKey: key, Kind: kind, DisplayName: display,
			Namespace: namespace, Attrs: WithScope(attrs, cluster, namespace),
		})
	}

	for _, sa := range snap.ServiceAccounts {
		attrs := map[string]any{
			"cluster":   cluster,
			"namespace": sa.Namespace,
			"name":      sa.Name,
			"uid":       sa.UID,
			// Names only. The agent never reads the Secret.
			"token_secret_names": sa.Secrets,
		}
		// The IRSA role annotation, when present: the AWS role a Pod running
		// as this account can assume. Absent rather than "" when there is
		// none, so a removed annotation leaves no stale value behind.
		if arn := strings.TrimSpace(sa.AWSRoleARN); arn != "" {
			attrs["aws_role_arn"] = arn
		}
		addIdentity(
			ServiceAccountKey(cluster, sa.Namespace, sa.Name),
			models.K8sAccountKindServiceAccount,
			sa.Anchor,
			sa.Namespace,
			attrs,
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
	namedGroups := map[string]bool{}
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
			if s.Kind == models.K8sSubjectServiceAccount && s.Namespace == "" {
				// Kubernetes resolves a RoleBinding's ServiceAccount subject
				// with no namespace in the RoleBinding's own namespace. Under a
				// ClusterRoleBinding there is no namespace to take and the API
				// server grants to nobody -- so it is unresolved, never the
				// phantom "system:serviceaccount::name".
				if b.Namespace == "" {
					res.Unresolved = append(res.Unresolved,
						bindingKey+" -> serviceaccount with no namespace: "+s.Name)
					continue
				}
				s.Namespace = b.Namespace
			}
			if s.Kind == models.K8sSubjectGroup {
				namedGroups[s.Name] = true
			}
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
					CalculationState:    GrantCalculation,
					EffectiveConclusion: GrantConclusion,
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
					// Resolved, but declared rather than evaluated: see Edge.
					CalculationState:    GrantCalculation,
					EffectiveConclusion: GrantConclusion,
				})
			}
		}
	}

	// --- implicit group membership -----------------------------------------
	// Every ServiceAccount identity this snapshot projects -- listed, or named
	// only by a binding -- belongs to the implicit groups. Written only for the
	// groups a binding names: those are the only ones that carry access, and
	// the only ones with a group node to point at.
	for _, id := range res.Identities {
		if id.Kind != models.K8sAccountKindServiceAccount || id.Namespace == "" {
			continue
		}
		for _, g := range []string{
			GroupAllServiceAccounts,
			NamespaceServiceAccountsGroup(id.Namespace),
			GroupAuthenticated,
		} {
			if !namedGroups[g] {
				continue
			}
			groupKey := GroupKey(cluster, g)
			res.Memberships = append(res.Memberships, Membership{
				SourceKey: MemberOfKey(id.SourceKey, groupKey),
				MemberKey: id.SourceKey,
				GroupKey:  groupKey,
				Namespace: id.Namespace,
			})
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
