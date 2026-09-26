package providers

import (
	"strings"

	igraph "github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

const k8sGroupRule = "k8s.serviceaccount.group.v1"

func normalizeKubernetes(in Input) (*Plan, error) {
	p := &Plan{}
	var sas []Object
	var bindings []Object
	for _, o := range in.Objects {
		switch o.Kind {
		case "k8s.service_account":
			sas = append(sas, o)
		case "k8s.role_binding", "k8s.cluster_role_binding":
			bindings = append(bindings, o)
		default:
			if err := k8sObject(p, in.EstateID, o); err != nil {
				return nil, err
			}
		}
	}
	for _, o := range sas {
		if err := k8sServiceAccount(p, in.EstateID, o); err != nil {
			return nil, err
		}
	}
	for _, o := range in.Objects {
		if o.Kind == "k8s.workload" || o.Kind == "k8s.pod" {
			if err := k8sExecutesAs(p, in.EstateID, o); err != nil {
				return nil, err
			}
		}
	}
	for _, o := range bindings {
		if err := k8sBinding(p, in.EstateID, o); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func k8sObject(p *Plan, estate string, o Object) error {
	switch o.Kind {
	case "k8s.workload", "k8s.pod":
		return k8sWorkload(p, estate, o)
	case "k8s.role":
		return k8sRole(p, estate, o, false)
	case "k8s.cluster_role":
		return k8sRole(p, estate, o, true)
	case "k8s.network_policy":
		key, err := igraph.KubernetesWorkloadKey(estate, "networking.k8s.io", "NetworkPolicy", str(o.Native, "namespace"), str(o.Native, "name"), "policy")
		if err != nil {
			return err
		}
		p.Policies = append(p.Policies, Policy{
			SourceKey: key, ImmutableKey: str(o.Native, "uid"),
			Continuity: continuity(str(o.Native, "uid")),
			Provider:   models.ProviderKubernetes, Kind: models.PolicyKindK8sNetwork,
			Name: str(o.Native, "name"), RightsSchema: models.RightsNetworkPolicy,
			Document: mustJSON(firstMap(o.Native, "spec")),
		})
	case "k8s.service", "k8s.pvc", "k8s.pv":
		kind := strings.TrimPrefix(o.Kind, "k8s.")
		key, err := igraph.KubernetesWorkloadKey(estate, str(o.Native, "apiGroup"), kind, str(o.Native, "namespace"), str(o.Native, "name"), kind)
		if err != nil {
			return err
		}
		p.Resources = append(p.Resources, Resource{
			SourceKey: key, Provider: models.ProviderKubernetes, Kind: kind,
			Name: str(o.Native, "name"), ReferenceStatus: models.ReferenceStatusInventoried,
			NativeKind: kind, Attrs: displayAttrs(o.Native, o.Attrs), Ref: o.Ref,
		})
	case "secret.reference":
		key, err := igraph.SecretRefKey("kubernetes", estate, str(o.Native, "namespace"), str(o.Native, "name"), str(o.Native, "key"))
		if err != nil {
			return err
		}
		p.Resources = append(p.Resources, Resource{
			SourceKey: key, Provider: models.ProviderKubernetes, Kind: "secret_reference",
			Name: str(o.Native, "name"), ReferenceStatus: models.ReferenceStatusReferenced,
			NativeKind: "secret", Attrs: displayAttrs(o.Native, o.Attrs), Ref: o.Ref,
		})
	}
	return nil
}

func k8sWorkload(p *Plan, estate string, o Object) error {
	group := str(o.Native, "apiGroup")
	if group == "" {
		group = "apps"
	}
	kind := str(o.Native, "kind")
	if kind == "" {
		kind = "Pod"
	}
	slot := str(o.Native, "slot")
	if slot == "" {
		slot = "0"
	}
	key, err := igraph.KubernetesWorkloadKey(estate, group, kind, str(o.Native, "namespace"), str(o.Native, "name"), slot)
	if err != nil {
		return err
	}
	uid := str(o.Native, "uid")
	p.Workloads = append(p.Workloads, Workload{
		SourceKey: key, ImmutableKey: uid, Continuity: continuity(uid),
		Provider: models.ProviderKubernetes, RuntimeKind: strings.ToLower(kind),
		Name: str(o.Native, "name"), Attrs: displayAttrs(o.Native, o.Attrs), Ref: o.Ref,
		DeclaredAWSRole: roleAnnotation(o.Native),
	})
	return nil
}

func k8sExecutesAs(p *Plan, estate string, o Object) error {
	wkey := workloadKey(p, o.Ref)
	if wkey == "" {
		return nil
	}
	ns := str(o.Native, "namespace")
	name := str(o.Native, "serviceAccountName")
	if name == "" {
		name = "default"
	}
	saKey, err := igraph.KubernetesServiceAccountKey(estate, ns, name)
	if err != nil {
		return err
	}
	sa, uid := findIdentity(p, saKey)
	if sa == nil {
		p.Identities = append(p.Identities, Identity{
			SourceKey: saKey, Continuity: models.ContinuityRecognitionOnly,
			Provider: models.ProviderKubernetes, Kind: models.AccountKindK8sSA,
			Name: name, State: models.AccountStateEnabled, Backing: "pending",
			Attrs: mustJSON(map[string]string{"resolution": "pending", "namespace": ns}),
		})
		p.Unresolved = append(p.Unresolved, "k8s-sa:"+ns+"/"+name)
		return nil
	}
	if uid == "" {
		p.Unresolved = append(p.Unresolved, "k8s-sa:"+ns+"/"+name)
		return nil
	}
	rel, err := igraph.SecretRefKey("kubernetes", "executes_as", ns, str(o.Native, "name"), name)
	if err != nil {
		return err
	}
	_ = rel
	rkey, err := relationKey("kubernetes", "executes_as", wkey, saKey)
	if err != nil {
		return err
	}
	p.Relationships = append(p.Relationships, Relationship{
		SourceKey: rkey, Type: models.RelTypeExecutesAs, Basis: models.BasisDeclared,
		FromWorkload: wkey, ToIdentity: saKey,
	})
	if arn := roleAnnotation(o.Native); arn != "" {
		p.Unresolved = append(p.Unresolved, "aws-role:"+arn)
	}
	return nil
}

func k8sServiceAccount(p *Plan, estate string, o Object) error {
	key, err := igraph.KubernetesServiceAccountKey(estate, str(o.Native, "namespace"), str(o.Native, "name"))
	if err != nil {
		return err
	}
	uid := str(o.Native, "uid")
	p.Identities = append(p.Identities, Identity{
		SourceKey: key, ImmutableKey: uid, Continuity: continuity(uid),
		Provider: models.ProviderKubernetes, Kind: models.AccountKindK8sSA,
		Name: str(o.Native, "name"), State: models.AccountStateEnabled,
		Backing: backing(uid), Attrs: displayAttrs(o.Native, o.Attrs), Ref: o.Ref,
	})
	if err := k8sStandardGroup(p, estate, "system:serviceaccounts"); err != nil {
		return err
	}
	if err := k8sStandardGroup(p, estate, "system:serviceaccounts:"+str(o.Native, "namespace")); err != nil {
		return err
	}
	for _, g := range []string{"system:serviceaccounts", "system:serviceaccounts:" + str(o.Native, "namespace")} {
		gkey, err := igraph.KubernetesServiceAccountKey(estate, clusterNS, g)
		if err != nil {
			return err
		}
		rkey, err := relationKey("kubernetes", "member_of", key, gkey)
		if err != nil {
			return err
		}
		p.Relationships = append(p.Relationships, Relationship{
			SourceKey: rkey, Type: models.RelTypeMemberOf, Basis: models.BasisDerived,
			DerivationRule: k8sGroupRule, FromIdentity: key, ToIdentity: gkey,
		})
	}
	return nil
}

func k8sStandardGroup(p *Plan, estate, name string) error {
	key, err := igraph.KubernetesServiceAccountKey(estate, clusterNS, name)
	if err != nil {
		return err
	}
	if _, _ = findIdentity(p, key); findIdentityExists(p, key) {
		return nil
	}
	p.Identities = append(p.Identities, Identity{
		SourceKey: key, Continuity: models.ContinuityRecognitionOnly,
		Provider: models.ProviderKubernetes, Kind: models.AccountKindK8sGroup,
		Name: name, State: models.AccountStateEnabled, Backing: "k8s",
		Attrs: mustJSON(map[string]string{"rule": k8sGroupRule}),
	})
	return nil
}

func k8sRole(p *Plan, estate string, o Object, cluster bool) error {
	ns := str(o.Native, "namespace")
	kind := "Role"
	polKind := models.PolicyKindK8sRole
	if cluster {
		ns = clusterNS
		kind = "ClusterRole"
		polKind = models.PolicyKindK8sClusterRole
	}
	key, err := igraph.KubernetesWorkloadKey(estate, "rbac.authorization.k8s.io", kind, ns, str(o.Native, "name"), "role")
	if err != nil {
		return err
	}
	uid := str(o.Native, "uid")
	rules := list(o.Native, "rules")
	agg := nested(o.Native, "aggregationRule") != nil || nested(o.Native, "aggregation_rule") != nil
	partial := agg && len(rules) == 0
	p.Policies = append(p.Policies, Policy{
		SourceKey: key, ImmutableKey: uid, Continuity: continuity(uid),
		Provider: models.ProviderKubernetes, Kind: polKind, Name: str(o.Native, "name"),
		RightsSchema: models.RightsK8sRBAC, Document: mustJSON(o.Native["rules"]), Partial: partial,
	})
	if partial {
		p.Unresolved = append(p.Unresolved, "k8s-aggregation:"+str(o.Native, "name"))
		return nil
	}
	for i, raw := range rules {
		rule, _ := raw.(map[string]any)
		rights := models.K8sRights{
			APIGroups: stringList(rule["apiGroups"]), Resources: stringList(rule["resources"]),
			Verbs: stringList(rule["verbs"]), ResourceNames: stringList(rule["resourceNames"]),
			NonResourceURLs: stringList(rule["nonResourceURLs"]),
		}
		skey := key + igraph.Sep + "rule" + igraph.Sep + asString(float64(i))
		p.Statements = append(p.Statements, Statement{
			SourceKey: skey, PolicyKey: key, NativeKind: "k8s_rule",
			Rights: mustJSON(rights), EffectAllow: true,
		})
	}
	return nil
}

func k8sBinding(p *Plan, estate string, o Object) error {
	ref := nested(o.Native, "roleRef")
	if ref == nil {
		ref = nested(o.Native, "role_ref")
	}
	roleKind := str(ref, "kind")
	roleNS := str(o.Native, "namespace")
	if roleKind == "ClusterRole" {
		roleNS = clusterNS
	}
	roleKey, err := igraph.KubernetesWorkloadKey(estate, "rbac.authorization.k8s.io", roleKind, roleNS, str(ref, "name"), "role")
	if err != nil {
		return err
	}
	scope := "namespace"
	assignKind := models.AssignmentK8sRoleBinding
	nsUID := str(o.Native, "namespace_uid")
	if o.Kind == "k8s.cluster_role_binding" {
		scope = "cluster"
		assignKind = models.AssignmentK8sClusterRoleBinding
		nsUID = ""
	}
	for _, raw := range list(o.Native, "subjects") {
		sub, _ := raw.(map[string]any)
		skind := str(sub, "kind")
		if skind == "User" {
			p.Unresolved = append(p.Unresolved, "k8s-user:"+str(sub, "name"))
			continue
		}
		if skind == "Group" {
			if err := ensureGroup(p, estate, str(sub, "name")); err != nil {
				return err
			}
		}
		holderNS := str(sub, "namespace")
		holderName := str(sub, "name")
		if skind == "Group" {
			holderNS = clusterNS
		}
		holder, err := igraph.KubernetesServiceAccountKey(estate, holderNS, holderName)
		if err != nil {
			return err
		}
		bkey, err := relationKey("kubernetes", assignKind, str(o.Native, "uid"), holder)
		if err != nil {
			return err
		}
		p.Assignments = append(p.Assignments, Assignment{
			SourceKey: bkey, PolicyKey: roleKey, HolderKey: holder, Kind: assignKind,
			ScopeKind: scope, NamespaceUID: nsUID, BindingUID: str(o.Native, "uid"),
		})
		stmts := statementsFor(p, roleKey)
		if len(stmts) == 0 && policyPartial(p, roleKey) {
			continue
		}
		for _, st := range stmts {
			gkey, err := relationKey("kubernetes", "grant", bkey, st)
			if err != nil {
				return err
			}
			p.Grants = append(p.Grants, Grant{
				SourceKey: gkey, AssignmentKey: bkey, StatementKey: st, HolderKey: holder,
				Calculation: models.CalcPartial, Conclusion: models.ConclusionUnknown,
			})
		}
	}
	return nil
}

const clusterNS = "_"

func ensureGroup(p *Plan, estate, name string) error {
	switch name {
	case "system:serviceaccounts", "system:authenticated", "system:unauthenticated", "system:masters", "system:nodes":
		return k8sStandardGroup(p, estate, name)
	default:
		if strings.HasPrefix(name, "system:serviceaccounts:") {
			return k8sStandardGroup(p, estate, name)
		}
		p.Unresolved = append(p.Unresolved, "k8s-group:"+name)
		return nil
	}
}

func findIdentity(p *Plan, key string) (*Identity, string) {
	for i := range p.Identities {
		if p.Identities[i].SourceKey == key {
			return &p.Identities[i], p.Identities[i].ImmutableKey
		}
	}
	return nil, ""
}

func findIdentityExists(p *Plan, key string) bool {
	id, _ := findIdentity(p, key)
	return id != nil
}

func statementsFor(p *Plan, policy string) []string {
	var out []string
	for _, s := range p.Statements {
		if s.PolicyKey == policy {
			out = append(out, s.SourceKey)
		}
	}
	return out
}

func policyPartial(p *Plan, key string) bool {
	for _, pol := range p.Policies {
		if pol.SourceKey == key {
			return pol.Partial
		}
	}
	return false
}

func continuity(uid string) string {
	if uid == "" {
		return models.ContinuityRecognitionOnly
	}
	return models.ContinuityImmutable
}

func backing(uid string) string {
	if uid == "" {
		return "pending"
	}
	return "k8s"
}

func roleAnnotation(native map[string]any) string {
	ann := nested(native, "annotations")
	if ann == nil {
		return ""
	}
	for _, k := range []string{"eks.amazonaws.com/role-arn", "iam.amazonaws.com/role"} {
		if v := str(ann, k); v != "" {
			return v
		}
	}
	return ""
}

func firstMap(m map[string]any, k string) any {
	if n := nested(m, k); n != nil {
		return n
	}
	return map[string]any{}
}

func relationKey(provider, rel string, parts ...string) (string, error) {
	esc := make([]string, 0, len(parts)+1)
	esc = append(esc, rel)
	for _, part := range parts {
		esc = append(esc, igraph.EscapeSegment(part))
	}
	return igraph.Key(provider, esc...), nil
}
