package integration

// Kubernetes hardening on the traversal routes (traverse_cross.go,
// traverse_k8s.go; D-108..D-111):
//
//   - IRSA / EKS Pod Identity: an AWS role's trust naming a ServiceAccount
//     resolves, at read time, to that ServiceAccount when the newest
//     projected sweep of exactly one cluster of the SAME workspace reported
//     the trust's OIDC issuer (Pod Identity: the association's cluster name,
//     unambiguously) and the subject names a live ServiceAccount of it. The
//     walk then crosses: workload -> SA -> can_assume (crosses_provider) ->
//     role -> grant -> statement -> target -> bucket, and back.
//   - Implicit groups: a ServiceAccount's member_of to
//     system:serviceaccounts[:<ns>] / system:authenticated is walked, and the
//     group's grants are its.
//   - effective_scope on every Kubernetes grant.
//   - A Kubernetes root never pins or reports the AWS rev.
//
// The EKS-like world: account A's role checkout-role trusts the EKS OIDC
// provider for system:serviceaccount:shop:checkout and reads
// s3://shop-orders/*; ghost-role trusts the same issuer for a ServiceAccount
// that does not exist, wild-role for system:serviceaccount:shop:* (a
// wildcard). The cluster (kg-cluster, namespace shop) has ServiceAccounts
// checkout and other; the Deployment checkout-api runs as checkout.

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

const (
	crossNS       = "shop"
	crossSA       = "system:serviceaccount:shop:checkout"
	crossBucket   = "arn:aws:s3:::shop-orders/*"
	crossOrderDoc = `{"Version":"2012-10-17","Statement":[{"Sid":"ReadOrders","Effect":"Allow",` +
		`"Action":"s3:GetObject","Resource":"` + crossBucket + `"}]}`
	crossOtherIssuer = "https://oidc.eks.us-east-1.amazonaws.com/id/0THERCLUSTER0000000000000000000"
)

// crossIRSA is an IRSA trust statement for one subject, under a condition
// operator (StringEquals, StringLike).
func crossIRSA(op, subject string) string {
	return `{"Effect":"Allow","Principal":{"Federated":"` + trustEKSProvider + `"},"Action":"sts:AssumeRoleWithWebIdentity",` +
		`"Condition":{"` + op + `":{"` + eksIssuerNoSch + `:sub":"` + subject + `"}}}`
}

// crossAWS builds account A's roles. eks, when not nil, answers the EKS
// surface (Pod Identity).
func crossAWS(t *testing.T, l *p2Lab, eks *fakeEKS) *p2Account {
	t.Helper()
	a := l.account(accountA)
	trustRole(a, "checkout-role", "AROACHECKOUTROLE0001", trustDoc(crossIRSA("StringEquals", crossSA)))
	a.attach("checkout-role", a.managed("ShopOrdersRead", crossOrderDoc))
	trustRole(a, "ghost-role", "AROAGHOSTROLEGHOST01", trustDoc(crossIRSA("StringEquals", "system:serviceaccount:shop:ghost")))
	trustRole(a, "wild-role", "AROAWILDROLEWILDRO01", trustDoc(crossIRSA("StringLike", "system:serviceaccount:shop:*")))
	if eks != nil {
		trustCycle(l, a, eks)
	} else {
		trustCycle(l, a, nil)
	}
	return a
}

// crossSnapshot is one complete sweep of the shop namespace from a source.
func crossSnapshot(k *k8sGraphLab, src uuid.UUID, at time.Time) models.K8sRBACSnapshot {
	sa := func(name string) models.K8sSubject {
		return models.K8sSubject{Kind: models.K8sSubjectServiceAccount, Name: name, Namespace: crossNS}
	}
	return models.K8sRBACSnapshot{
		WorkspaceID: k.ws.String(), DiscoverySourceID: src.String(), Source: models.DiscoverySourceK8sWebhook,
		Cluster: k8sGraphCluster, ScanKind: "rbac",
		SweepStartedAt: at.Add(-time.Minute).Format(time.RFC3339), ObservedAt: at.Format(time.RFC3339),
		Complete: true, ClusterScoped: true, Namespaces: []string{crossNS},
		ServiceAccounts: []models.K8sServiceAccount{
			{Name: "checkout", Namespace: crossNS, Anchor: crossSA},
			{Name: "other", Namespace: crossNS, Anchor: "system:serviceaccount:shop:other"},
		},
		Roles: []models.K8sRole{
			{Kind: models.K8sKindRole, Name: "cm-reader", Namespace: crossNS, Rules: []models.K8sPolicyRule{
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}},
			}},
			{Kind: models.K8sKindClusterRole, Name: "pod-viewer", Rules: []models.K8sPolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list"}},
			}},
			{Kind: models.K8sKindClusterRole, Name: "secret-getter", Rules: []models.K8sPolicyRule{
				{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
			}},
		},
		Bindings: []models.K8sBinding{
			{Kind: models.K8sKindRoleBinding, Name: "checkout-cm", Namespace: crossNS,
				RoleRef:  models.K8sRoleRef{Kind: models.K8sKindRole, Name: "cm-reader"},
				Subjects: []models.K8sSubject{sa("checkout")}},
			// A ClusterRole bound by a RoleBinding: its rule applies in shop
			// only (D-109).
			{Kind: models.K8sKindRoleBinding, Name: "checkout-secrets", Namespace: crossNS,
				RoleRef:  models.K8sRoleRef{Kind: models.K8sKindClusterRole, Name: "secret-getter"},
				Subjects: []models.K8sSubject{sa("checkout")}},
			// Every ServiceAccount of shop, through the implicit group (D-110).
			{Kind: models.K8sKindClusterRoleBinding, Name: "shop-sas-view-pods",
				RoleRef:  models.K8sRoleRef{Kind: models.K8sKindClusterRole, Name: "pod-viewer"},
				Subjects: []models.K8sSubject{{Kind: models.K8sSubjectGroup, Name: "system:serviceaccounts:" + crossNS}}},
		},
	}
}

// crossSweep ingests one sweep from src and records the issuer the agent
// reported on it (043's iga_k8s_sweep.oidc_issuer: written directly, as the
// ingest that stores it is another work item's).
func (k *k8sGraphLab) crossSweep(src uuid.UUID, issuer string) {
	k.t.Helper()
	k.at = k.at.Add(time.Minute)
	res, err := k.mgr.Ingest(k.ws, crossSnapshot(k, src, k.at))
	if err != nil || !res.Accepted || !res.Reconciled {
		k.t.Fatalf("ingest: %+v %v", res, err)
	}
	k.crossIssuer(src, issuer)
}

// crossIssuer sets the issuer every sweep of src reported.
func (k *k8sGraphLab) crossIssuer(src uuid.UUID, issuer string) {
	k.t.Helper()
	if err := k.db.Exec(`UPDATE iga_k8s_sweep SET oidc_issuer = ? WHERE workspace_id = ? AND discovery_source_id = ?`,
		issuer, k.ws, src).Error; err != nil {
		k.t.Fatalf("set issuer: %v", err)
	}
}

// crossSource adds another Kubernetes source naming the same cluster.
func (k *k8sGraphLab) crossSource() uuid.UUID {
	k.t.Helper()
	src := uuid.New()
	if err := k.db.Exec(`INSERT INTO discovery_sources (id, workspace_id, kind, display_name, cluster_name)
	                     VALUES (?, ?, ?, ?, ?)`, src, k.ws, models.DiscoverySourceK8sWebhook,
		"agent-"+src.String()[:8], k8sGraphCluster).Error; err != nil {
		k.t.Fatalf("discovery source: %v", err)
	}
	return src
}

// crossImplicitMember writes the member_of row the projection writes for a
// ServiceAccount of an implicit group some binding names (D-110; the
// projection side is another work item's): basis declared, in the
// ServiceAccount's own partition. Only when no live row exists, so this
// fixture and that projection never draw the membership twice.
func (k *k8sGraphLab) crossImplicitMember(saName, group string) {
	k.t.Helper()
	sa := k.k8sID("iga_identity_accounts", "display_name = ?", saName)
	grp := k.k8sID("iga_identity_accounts", "display_name = ?", group)
	var part string
	if err := k.db.Raw(`SELECT partition_key FROM iga_object_support WHERE workspace_id = ? AND identity_account_id = ?
	                     ORDER BY partition_key LIMIT 1`, k.ws, sa).Row().Scan(&part); err != nil {
		k.t.Fatalf("SA partition: %v", err)
	}
	if err := k.db.Exec(`INSERT INTO iga_relationship (workspace_id, relationship_type, source_identity_account_id,
	                         target_identity_account_id, basis, state, source_key, partition_key)
	                     SELECT ?, 'member_of', ?, ?, 'declared', 'current', ?, ?
	                      WHERE NOT EXISTS (SELECT 1 FROM iga_relationship
	                                         WHERE workspace_id = ? AND relationship_type = 'member_of'
	                                           AND source_identity_account_id = ? AND target_identity_account_id = ?
	                                           AND state <> 'ended')`,
		k.ws, sa, grp, "test-member-of-"+sa.String()+"-"+grp.String(), part, k.ws, sa, grp).Error; err != nil {
		k.t.Fatalf("member_of: %v", err)
	}
}

// crossWorld is the refs a cross test uses.
type crossWorld struct {
	*k8sGraphLab
	workload, sa, other, group     string
	cmRule, podRule, secretRule    string
	role, ghost, wild, bucket, ext string
	stmt                           string
}

// newCrossWorld builds the k8s side (one sweep, issuer as given) in a lab
// whose AWS side, when aws is true, is account A's roles.
func newCrossWorld(t *testing.T, name string, awsSide bool, issuer string) *crossWorld {
	t.Helper()
	k := newK8sGraphLab(t, name)
	w := &crossWorld{k8sGraphLab: k}
	if awsSide {
		crossAWS(t, k.p2Lab, nil)
		w.awsRefs()
	}
	k.agent("checkout-api", crossNS, crossSA, "Deployment")
	k.crossSweep(k.src, issuer)
	k.crossImplicitMember(crossSA, "system:serviceaccounts:"+crossNS)
	w.k8sRefs()
	return w
}

func (w *crossWorld) awsRefs() {
	t := w.t
	w.role, w.ghost, w.wild = graphIdentity(t, w.p2Lab, "checkout-role"), graphIdentity(t, w.p2Lab, "ghost-role"),
		graphIdentity(t, w.p2Lab, "wild-role")
	w.bucket = graphResource(t, w.p2Lab, crossBucket)
	w.stmt = graphStatementOf(t, w.p2Lab, "ShopOrdersRead")
	var id uuid.UUID
	if err := w.db.Raw(`SELECT id FROM iga_external_principal WHERE workspace_id = ? AND mechanism = 'oidc' AND subject_claim = ?`,
		w.ws, crossSA).Row().Scan(&id); err != nil {
		t.Fatalf("IRSA principal: %v", err)
	}
	w.ext = refOf("external_principal", id)
}

func (w *crossWorld) k8sRefs() {
	w.workload = refOf("workload", w.k8sID("iga_workload", "display_name = ?", "checkout-api"))
	w.sa = refOf("identity", w.k8sID("iga_identity_accounts", "display_name = ?", crossSA))
	w.other = refOf("identity", w.k8sID("iga_identity_accounts", "display_name = ?", "system:serviceaccount:shop:other"))
	w.group = refOf("identity", w.k8sID("iga_identity_accounts", "display_name = ?", "system:serviceaccounts:"+crossNS))
	w.cmRule = w.k8sRule("shop/cm-reader", "configmaps")
	w.podRule = w.k8sRule("pod-viewer", "pods")
	w.secretRule = w.k8sRule("secret-getter", "secrets")
}

/* --------------------------------- shapes ---------------------------------- */

// The crossing edge (D-108): the AWS can_assume edge's fields, drawn from a
// Kubernetes ServiceAccount, plus crosses_provider, via_principal and
// resolution -- closed, like every frozen shape.
var contractCrossEdge = contractObj(
	contractReq("claim", contractRef("relationship")),
	contractReq("kind", contractConst("can_assume")),
	contractReq("from", contractRef("identity")),
	contractReq("to", contractRef("identity")),
	contractReq("state", contractEdgeState),
	contractReq("basis", contractBasis),
	contractReq("mechanism", contractEnum("oidc_federation", "eks_pod_identity")),
	contractReq("closes_cycle", contractBool),
	contractReq("crosses_account", contractConst(false)),
	contractReq("last_confirmed_at", contractNullable(contractTime)),
	contractOpt("stale_reason", contractStaleReason),
	contractReq("limitations", contractLimitations),
	contractReq("crosses_provider", contractConst(true)),
	contractReq("via_principal", contractRef("external_principal")),
	contractReq("resolution", contractObj(
		contractReq("basis", contractConst("derived")),
		contractReq("rule", contractEnum("irsa_issuer_match", "pod_identity_cluster_match")),
	)),
)

// A mixed response's node or edge is checked by its provider's frozen shape;
// the crossing edge by its own.
var (
	contractMixedNode = contractFunc(func(path string, v any, errs *[]string) {
		if m, _ := v.(map[string]any); m["provider"] == "k8s" {
			contractK8sGraphNode.check(path, v, errs)
			return
		}
		contractGraphNode.check(path, v, errs)
	})
	contractMixedEdge = contractFunc(func(path string, v any, errs *[]string) {
		m, _ := v.(map[string]any)
		switch {
		case m["provider"] == "k8s":
			contractK8sGraphEdge.check(path, v, errs)
		case m["crosses_provider"] != nil:
			contractCrossEdge.check(path, v, errs)
		default:
			contractGraphEdge.check(path, v, errs)
		}
	})
	contractMixedMeta = contractObj(
		contractReq("rev", contractInt),
		contractReq("published_at", contractTime),
		contractReq("graph_state", contractConst("mixed")),
		contractReq("capabilities", contractConst(map[string]any{})),
		contractReq("budgets", contractObj(
			contractReq("nodes", contractConst(500)), contractReq("edges", contractConst(2000)),
			contractReq("assume_hops", contractConst(4)), contractReq("timeout_ms", contractConst(3000)),
			contractReq("neighbours_per_page", contractConst(100)), contractReq("paths", contractConst(200)),
		)),
		contractReq("limitations", contractConst([]any{
			map[string]any{"code": "effective_access_not_evaluated"},
			map[string]any{"code": "organizations_not_collected"},
			map[string]any{"code": "k8s_observations_not_recorded"},
		})),
	)
	contractMixedGraph = contractDetail(contractObj(
		contractReq("root", contractRef("workload", "identity", "external_principal", "statement", "resource")),
		contractReq("nodes", contractArrMin(1, contractMixedNode)),
		contractReq("edges", contractArr(contractMixedEdge)),
		contractReq("frontier", contractArr(contractFrontier)),
		contractReq("truncated", contractTruncated),
		contractReq("resolution_not_followed", contractNullable(contractBool)),
	), contractMixedMeta)
	contractMixedExpand = contractDetail(contractObj(
		contractReq("nodes", contractArr(contractMixedNode)),
		contractReq("edges", contractArr(contractMixedEdge)),
		contractReq("frontier", contractArr(contractFrontier)),
		contractReq("truncated", contractTruncated),
		contractReq("next_cursor", contractNullable(contractNonEmpty)),
	), contractMixedMeta)
	contractMixedPath = contractDetail(contractObj(
		contractReq("from", contractRef("workload", "identity", "external_principal", "statement", "resource")),
		contractReq("to", contractRef("workload", "identity", "external_principal", "statement", "resource")),
		contractReq("direction", contractNullable(contractEnum("forward", "reverse"))),
		contractReq("outcome", contractEnum("found", "none_exists", "not_found_within_budget")),
		contractReq("paths", contractArr(contractObj(
			contractReq("nodes", contractArrMin(2, contractMixedNode)),
			contractReq("edges", contractArrMin(1, contractMixedEdge)),
			contractReq("limitations", contractArr(contractAnyValue)),
		))),
		contractReq("more_paths", contractBool),
		contractReq("bound_by", contractNullable(contractEnum("nodes", "edges", "assume_hops", "time", "paths", "resolution_not_followed"))),
	), contractMixedMeta)
)

// crossEdges is the crossing edges of a response.
func crossEdges(es []graphEdge) []graphEdge {
	var out []graphEdge
	for _, e := range es {
		if dig(e.Raw, "crosses_provider") == true {
			out = append(out, e)
		}
	}
	return out
}

/* ---------------------------------- IRSA ----------------------------------- */

func TestP2K8sGraphCrossIRSA(t *testing.T) {
	k := newK8sGraphLab(t, "p2-k8s-cross-irsa")
	crossAWS(t, k.p2Lab, nil)
	w := &crossWorld{k8sGraphLab: k}
	w.awsRefs()
	api := k.api()

	// The AWS answers before any cluster exists.
	awsCalls := []string{
		"/graph" + k8sQS("root", w.role, "direction", "reverse"),
		"/graph" + k8sQS("root", w.role, "direction", "forward"),
		"/graph" + k8sQS("root", w.ghost, "direction", "reverse"),
		"/graph" + k8sQS("root", w.wild, "direction", "reverse"),
		"/graph" + k8sQS("root", w.bucket, "direction", "reverse"),
		"/graph" + k8sQS("root", w.ext, "direction", "forward"),
		"/graph/expand" + k8sQS("node", w.role, "edge", "can_assume", "direction", "reverse"),
		"/graph/path" + k8sQS("from", w.ext, "to", w.bucket),
	}
	before := map[string]string{}
	for _, p := range awsCalls {
		before[p] = graphRaw(t, graphGet(t, api, p))
	}
	unchanged := func(when string, calls []string) {
		t.Helper()
		for _, p := range calls {
			if got := graphRaw(t, graphGet(t, api, p)); got != before[p] {
				t.Errorf("%s: GET %s changed:\nbefore %s\nafter  %s", when, p, before[p], got)
			}
		}
	}
	noCrossing := func(when string) {
		t.Helper()
		fwd := graphGet(t, api, "/graph"+k8sQS("root", w.workload, "direction", "forward"))
		contractCheck(t, when+": GET /graph (k8s workload)", fwd, contractK8sGraph)
		if graphMentions(t, fwd, w.role) || len(crossEdges(graphEdges(t, digl(fwd, "data", "edges")))) != 0 {
			t.Errorf("%s: the workload's walk crosses into AWS: %v", when, fwd["data"])
		}
		p := graphGet(t, api, "/graph/path"+k8sQS("from", w.workload, "to", w.bucket))
		if digs(p, "data", "outcome") != "none_exists" {
			t.Errorf("%s: path workload -> bucket = %v, want none_exists", when, p["data"])
		}
	}

	// 1. The cluster arrives, its agent could not read the issuer: nothing
	//    resolves, and every AWS answer is byte-identical.
	k.agent("checkout-api", crossNS, crossSA, "Deployment")
	k.crossSweep(k.src, "")
	k.crossImplicitMember(crossSA, "system:serviceaccounts:"+crossNS)
	w.k8sRefs()
	unchanged("no issuer", awsCalls)
	noCrossing("no issuer")

	// 2. Another cluster's issuer: still nothing.
	k.crossIssuer(k.src, crossOtherIssuer)
	unchanged("issuer mismatch", awsCalls)
	noCrossing("issuer mismatch")

	// 3. The cluster's own issuer -- as its discovery document writes it,
	//    with a scheme and a trailing slash, where the trust has neither.
	k.crossIssuer(k.src, eksIssuerURL+"/")
	awsRev := dig(graphGet(t, api, awsCalls[1]), "meta", "rev")

	// Forward from the workload: across into AWS, to the bucket.
	fwd := graphGet(t, api, "/graph"+k8sQS("root", w.workload, "direction", "forward"))
	contractCheck(t, "GET /graph (workload across)", fwd, contractMixedGraph)
	nodes := graphNodes(t, digl(fwd, "data", "nodes"))
	for _, ref := range []string{w.workload, w.sa, w.role, w.stmt, w.bucket, w.group, w.podRule, w.cmRule, w.secretRule} {
		if nodes[ref] == nil {
			t.Errorf("forward from the workload lacks %s; nodes %v", ref, graphKeys(nodes))
		}
	}
	for _, ref := range []string{w.ghost, w.wild, w.ext, w.other} {
		if nodes[ref] != nil {
			t.Errorf("forward from the workload reaches %s", ref)
		}
	}
	es := graphEdges(t, digl(fwd, "data", "edges"))
	cx := crossEdges(es)
	if len(cx) != 1 || cx[0].Kind != "can_assume" || cx[0].From != w.sa || cx[0].To != w.role ||
		digs(cx[0].Raw, "via_principal") != w.ext || digs(cx[0].Raw, "resolution", "rule") != "irsa_issuer_match" ||
		digs(cx[0].Raw, "resolution", "basis") != "derived" || digs(cx[0].Raw, "mechanism") != "oidc_federation" ||
		cx[0].CrossesAccount {
		t.Fatalf("crossing edges = %+v, want one can_assume SA -> checkout-role via the IRSA principal", cx)
	}
	if _, has := cx[0].Raw["provider"]; has {
		t.Errorf("the crossing edge is the AWS claim; it carries provider %v", cx[0].Raw["provider"])
	}
	if nodes[w.sa]["provider"] != "k8s" || nodes[w.role]["provider"] != nil || digs(nodes[w.role], "arn") == "" {
		t.Errorf("the providers switch at the crossing: SA %v role %v", nodes[w.sa]["provider"], nodes[w.role])
	}
	if dig(fwd, "meta", "graph_state") != "mixed" || dig(fwd, "meta", "rev") != awsRev || awsRev == nil {
		t.Errorf("meta = %v, want mixed at the AWS rev %v", fwd["meta"], awsRev)
	}
	if dig(fwd, "data", "truncated") != nil || dig(fwd, "data", "resolution_not_followed") != false {
		t.Errorf("forward across: truncated %v resolution_not_followed %v, want a complete answer",
			dig(fwd, "data", "truncated"), dig(fwd, "data", "resolution_not_followed"))
	}
	// The AWS side of the walk is AWS's: the grant and target as always.
	if g := graphEdgesOfKind(es, "target"); len(g) != 1 || g[0].To != w.bucket {
		t.Errorf("targets = %+v, want the bucket", g)
	}

	// Reverse from the role: the ServiceAccount, and the workload running
	// as it -- the IRSA principal is not a node of it.
	rev := graphGet(t, api, "/graph"+k8sQS("root", w.role, "direction", "reverse"))
	contractCheck(t, "GET /graph (role reverse across)", rev, contractMixedGraph)
	rn := graphNodes(t, digl(rev, "data", "nodes"))
	if rn[w.sa] == nil || rn[w.workload] == nil || rn[w.ext] != nil || len(rn) != 3 {
		t.Errorf("reverse from the role = %v, want the role, the SA and the workload", graphKeys(rn))
	}
	if cx := crossEdges(graphEdges(t, digl(rev, "data", "edges"))); len(cx) != 1 || cx[0].From != w.sa || cx[0].To != w.role {
		t.Errorf("reverse crossing = %+v", cx)
	}
	if dig(rev, "meta", "graph_state") != "mixed" || dig(rev, "data", "resolution_not_followed") != false {
		t.Errorf("reverse meta %v resolution_not_followed %v", rev["meta"], dig(rev, "data", "resolution_not_followed"))
	}
	// The bucket, in reverse, reaches the workload through the crossing.
	br := graphGet(t, api, "/graph"+k8sQS("root", w.bucket, "direction", "reverse", "assume_hops", "4"))
	if graphNodes(t, digl(br, "data", "nodes"))[w.workload] == nil {
		t.Errorf("reverse from the bucket does not reach the workload: %v", br["data"])
	}

	// /graph/path, both orientations.
	p := graphGet(t, api, "/graph/path"+k8sQS("from", w.workload, "to", w.bucket))
	contractCheck(t, "GET /graph/path (workload -> bucket)", p, contractMixedPath)
	if digs(p, "data", "outcome") != "found" || digs(p, "data", "direction") != "forward" || len(digl(p, "data", "paths")) != 1 {
		t.Fatalf("path workload -> bucket = %v", p["data"])
	}
	pn, pe := digl(p, "data", "paths", 0, "nodes"), digl(p, "data", "paths", 0, "edges")
	wantNodes := []string{w.workload, w.sa, w.role, w.stmt, w.bucket}
	wantKinds := []string{"executes_as", "can_assume", "grant", "target"}
	for i := range wantNodes {
		if i >= len(pn) || digs(pn[i], "ref") != wantNodes[i] {
			t.Errorf("path node %d = %v, want %s", i, pn, wantNodes[i])
			break
		}
	}
	for i := range wantKinds {
		if i >= len(pe) || digs(pe[i], "kind") != wantKinds[i] {
			t.Errorf("path edge %d = %v, want %s", i, pe, wantKinds[i])
			break
		}
	}
	if len(pe) == 4 && dig(pe[1], "crosses_provider") != true {
		t.Errorf("the path's can_assume does not say it crosses: %v", pe[1])
	}
	back := graphGet(t, api, "/graph/path"+k8sQS("from", w.bucket, "to", w.workload))
	if digs(back, "data", "outcome") != "found" || digs(back, "data", "direction") != "reverse" {
		t.Errorf("path bucket -> workload = %v", back["data"])
	}
	if p := graphGet(t, api, "/graph/path"+k8sQS("from", w.workload, "to", w.ghost)); digs(p, "data", "outcome") != "none_exists" {
		t.Errorf("path workload -> ghost-role = %v, want none_exists", p["data"])
	}

	// /graph/expand, both ends of the crossing.
	ex := graphGet(t, api, "/graph/expand"+k8sQS("node", w.sa, "edge", "can_assume", "direction", "forward"))
	contractCheck(t, "GET /graph/expand (SA can_assume)", ex, contractMixedExpand)
	if es := graphEdges(t, digl(ex, "data", "edges")); len(es) != 1 || es[0].To != w.role || dig(es[0].Raw, "crosses_provider") != true {
		t.Errorf("expand SA can_assume = %v", ex["data"])
	}
	ex = graphGet(t, api, "/graph/expand"+k8sQS("node", w.role, "edge", "can_assume", "direction", "reverse"))
	contractCheck(t, "GET /graph/expand (role can_assume reverse)", ex, contractMixedExpand)
	if n := digl(ex, "data", "nodes"); len(n) != 1 || digs(n[0], "ref") != w.sa {
		t.Errorf("expand role can_assume reverse = %v, want the SA", ex["data"])
	}

	// The crossing is an assume hop: at assume_hops=0 it is the frontier,
	// counted, and the answer says the hop limit bound.
	h0 := graphGet(t, api, "/graph"+k8sQS("root", w.workload, "direction", "forward", "assume_hops", "0"))
	if graphMentions(t, h0, w.role) || digs(h0, "data", "truncated", "bound_by") != "assume_hops" {
		t.Errorf("assume_hops=0 = %v, want the role unwalked and assume_hops bound", h0["data"])
	}
	if f := graphFrontier(h0, w.sa, "can_assume"); f == nil || dig(f, "more", "count") != float64(1) || dig(f, "more", "exact") != true {
		t.Errorf("assume_hops=0 frontier = %v, want the SA's one can_assume", digl(h0, "data", "frontier"))
	}

	// The principal named as a root keeps its own edge, and displays its
	// read-time resolution -- not walked from there (D-105's rule).
	er := graphGet(t, api, "/graph"+k8sQS("root", w.ext, "direction", "forward"))
	contractCheck(t, "GET /graph (resolved principal root)", er, contractGraph)
	en := graphNodes(t, digl(er, "data", "nodes"))[w.ext]
	if digs(en, "resolution", "rule") != "irsa_issuer_match" || digs(en, "resolution", "resolved_to") != w.sa ||
		digs(en, "resolution", "basis") != "derived" || dig(er, "data", "resolution_not_followed") != true {
		t.Errorf("principal root = %v, want its read-time resolution to the SA, not followed", er["data"])
	}
	if es := graphEdges(t, digl(er, "data", "edges")); len(graphEdgesOfKind(es, "can_assume")) != 1 ||
		graphEdgesOfKind(es, "can_assume")[0].From != w.ext || len(crossEdges(es)) != 0 {
		t.Errorf("principal root edges = %+v, want its own can_assume from itself", es)
	}

	// The principal's detail says the same (D-108).
	dt := graphGet(t, api, "/external-principals/"+strings.TrimPrefix(w.ext, "external_principal:"))
	contractCheck(t, "GET /external-principals/:id (resolved at read time)", dt, contractExternalDetail)
	if digs(dt, "data", "resolution", "rule") != "irsa_issuer_match" || digs(dt, "data", "resolution", "resolved_to") != w.sa ||
		dig(dt, "data", "unresolved_reason") != nil {
		t.Errorf("principal detail = %v, want the read-time resolution and no unresolved_reason", dt["data"])
	}

	// What the crossing does not touch is still byte-identical: the ghost's
	// and the wildcard's trusts name no ServiceAccount of the cluster.
	unchanged("crossing in force", []string{awsCalls[2], awsCalls[3]})

	// rev: an AWS root pins it; a Kubernetes root ignores it, even when its
	// walk crosses (D-111).
	if code, b := api.get("/graph" + k8sQS("root", w.role, "direction", "reverse", "rev", "999")); code != http.StatusConflict {
		t.Errorf("AWS root at rev 999 = %d %v, want 409", code, b)
	}
	kr := graphGet(t, api, "/graph"+k8sQS("root", w.workload, "direction", "forward", "rev", "999"))
	if dig(kr, "meta", "rev") != awsRev || digs(kr, "meta", "graph_state") != "mixed" {
		t.Errorf("k8s root at rev 999 = %v, want 200, mixed at the AWS rev it read", kr["meta"])
	}
}

// The resolution is the workspace's own: a cluster of ANOTHER workspace that
// reports the trust's issuer resolves nothing here, even when this
// workspace's own cluster has a ServiceAccount of the same name.
func TestP2K8sGraphCrossStaysInItsWorkspace(t *testing.T) {
	theirs := newK8sGraphLab(t, "p2-k8s-cross-ws-theirs")
	ours := newK8sGraphLab(t, "p2-k8s-cross-ws-ours")
	crossAWS(t, ours.p2Lab, nil)
	w := &crossWorld{k8sGraphLab: ours}
	w.awsRefs()
	api := ours.api()
	before := graphRaw(t, graphGet(t, api, "/graph"+k8sQS("root", w.role, "direction", "reverse")))

	// Ours: the same cluster name and ServiceAccount, issuer unread.
	ours.agent("checkout-api", crossNS, crossSA, "Deployment")
	ours.crossSweep(ours.src, "")
	w.k8sRefs()
	// Theirs: the trust's issuer.
	theirs.crossSweep(theirs.src, eksIssuerURL)

	if got := graphRaw(t, graphGet(t, api, "/graph"+k8sQS("root", w.role, "direction", "reverse"))); got != before {
		t.Errorf("another workspace's sweep changed the role's reverse graph:\nbefore %s\nafter  %s", before, got)
	}
	fwd := graphGet(t, api, "/graph"+k8sQS("root", w.workload, "direction", "forward"))
	if graphMentions(t, fwd, w.role) {
		t.Errorf("the workload crosses on another workspace's issuer: %v", fwd["data"])
	}
	// Control: the same issuer on our own sweep crosses.
	ours.crossIssuer(ours.src, eksIssuerURL)
	if fwd = graphGet(t, api, "/graph"+k8sQS("root", w.workload, "direction", "forward")); !graphMentions(t, fwd, w.role) {
		t.Errorf("control: our own issuer does not cross: %v", fwd["data"])
	}
}

/* ------------------------------ Pod Identity -------------------------------- */

// crossPodEKS is one EKS cluster named like the agent's, with one Pod
// Identity association for shop/checkout to ledger-role.
func crossPodEKS(roleARN string) *fakeEKS {
	f := newFakeEKS()
	f.clusters[k8sGraphCluster] = eksIssuerURL
	f.associations[k8sGraphCluster] = []ekstypes.PodIdentityAssociation{{
		AssociationId:  aws.String("a-2222222222"),
		AssociationArn: aws.String("arn:aws:eks:us-east-1:" + accountA + ":podidentityassociation/" + k8sGraphCluster + "/a-2222222222"),
		ClusterName:    aws.String(k8sGraphCluster),
		Namespace:      aws.String(crossNS),
		ServiceAccount: aws.String("checkout"),
		RoleArn:        aws.String(roleARN),
	}}
	return f
}

func TestP2K8sGraphCrossPodIdentity(t *testing.T) {
	k := newK8sGraphLab(t, "p2-k8s-cross-pod")
	a := k.account(accountA)
	roleARN := trustRole(a, "ledger-role", "AROALEDGERROLE000001",
		trustDoc(trustAllow(`{"Service":"pods.eks.amazonaws.com"}`, "sts:AssumeRole")))
	a.attach("ledger-role", a.managed("ShopOrdersRead", crossOrderDoc))
	trustCycle(k.p2Lab, a, crossPodEKS(roleARN))
	role := graphIdentity(t, k.p2Lab, "ledger-role")
	api := k.api()
	before := graphRaw(t, graphGet(t, api, "/graph"+k8sQS("root", role, "direction", "reverse")))

	// The agent did not report an issuer: the association's cluster name is
	// the agent's, and one source sweeps it -- unambiguous.
	k.agent("checkout-api", crossNS, crossSA, "Deployment")
	k.crossSweep(k.src, "")
	w := &crossWorld{k8sGraphLab: k}
	w.k8sRefs()
	fwd := graphGet(t, api, "/graph"+k8sQS("root", w.workload, "direction", "forward"))
	contractCheck(t, "GET /graph (pod identity across)", fwd, contractMixedGraph)
	cx := crossEdges(graphEdges(t, digl(fwd, "data", "edges")))
	if len(cx) != 1 || cx[0].From != w.sa || cx[0].To != role || digs(cx[0].Raw, "mechanism") != "eks_pod_identity" ||
		digs(cx[0].Raw, "resolution", "rule") != "pod_identity_cluster_match" {
		t.Fatalf("pod identity crossing = %+v", cx)
	}
	if p := graphGet(t, api, "/graph/path"+k8sQS("from", w.workload, "to", graphResource(t, k.p2Lab, crossBucket))); digs(p, "data", "outcome") != "found" {
		t.Errorf("path workload -> bucket = %v", p["data"])
	}

	// The agent reports another issuer for that cluster: not that cluster.
	k.crossIssuer(k.src, crossOtherIssuer)
	if fwd = graphGet(t, api, "/graph"+k8sQS("root", w.workload, "direction", "forward")); graphMentions(t, fwd, role) {
		t.Errorf("pod identity crosses although the cluster's issuer differs: %v", fwd["data"])
	}
	k.crossIssuer(k.src, "")

	// A second source sweeps a cluster of the same name: ambiguous, nothing
	// resolves, and the role's reverse graph is what it was.
	second := k.crossSource()
	k.crossSweep(second, "")
	if fwd = graphGet(t, api, "/graph"+k8sQS("root", w.workload, "direction", "forward")); graphMentions(t, fwd, role) {
		t.Errorf("pod identity crosses although two sources sweep %s: %v", k8sGraphCluster, fwd["data"])
	}
	if got := graphRaw(t, graphGet(t, api, "/graph"+k8sQS("root", role, "direction", "reverse"))); got != before {
		t.Errorf("ambiguous pod identity changed the role's reverse graph:\nbefore %s\nafter  %s", before, got)
	}
}

/* ----------------------------- implicit groups ------------------------------ */

// D-110: a ServiceAccount's implicit group membership is walked, and what is
// granted to the group is on its chain, marked as implicit.
func TestP2K8sGraphImplicitGroups(t *testing.T) {
	w := newCrossWorld(t, "p2-k8s-implicit", false, "")
	api := w.api()

	fwd := graphGet(t, api, "/graph"+k8sQS("root", w.workload, "direction", "forward"))
	contractCheck(t, "GET /graph (implicit group)", fwd, contractK8sGraph)
	es := graphEdges(t, digl(fwd, "data", "edges"))
	m := graphEdgesOfKind(es, "member_of")
	if len(m) != 1 || m[0].From != w.sa || m[0].To != w.group || dig(m[0].Raw, "implicit_membership") != true ||
		digs(m[0].Raw, "provider") != "k8s" || digs(m[0].Raw, "basis") != "declared" {
		t.Fatalf("member_of = %+v, want SA -> system:serviceaccounts:shop, implicit", m)
	}
	var viaGroup bool
	for _, g := range graphEdgesOfKind(es, "grant") {
		if g.From == w.group && g.To == w.podRule {
			viaGroup = true
			if digs(g.Raw, "assignment", "name") != "shop-sas-view-pods" || digs(g.Raw, "effective_scope", "kind") != "cluster" {
				t.Errorf("group grant = %v", g.Raw)
			}
		}
	}
	if !viaGroup {
		t.Errorf("the group's grant is not on the workload's chain: %+v", es)
	}
	gn := graphNodes(t, digl(fwd, "data", "nodes"))[w.group]
	if digs(gn, "kind") != "k8s_group" || gn["sub_scope"] != nil {
		t.Errorf("group node = %v", gn)
	}

	// Reverse from the group's rule: the group, its member, the workload.
	rev := graphGet(t, api, "/graph"+k8sQS("root", w.podRule, "direction", "reverse"))
	contractCheck(t, "GET /graph (pod-viewer reverse)", rev, contractK8sGraph)
	rn := graphNodes(t, digl(rev, "data", "nodes"))
	if rn[w.group] == nil || rn[w.sa] == nil || rn[w.workload] == nil {
		t.Errorf("reverse from the group's rule = %v", graphKeys(rn))
	}

	// The path runs through the membership.
	p := graphGet(t, api, "/graph/path"+k8sQS("from", w.workload, "to", w.podRule))
	contractCheck(t, "GET /graph/path (implicit group)", p, contractK8sGraphPath)
	if digs(p, "data", "outcome") != "found" || len(digl(p, "data", "paths")) != 1 {
		t.Fatalf("path workload -> pod-viewer = %v", p["data"])
	}
	var kinds []string
	for _, e := range digl(p, "data", "paths", 0, "edges") {
		kinds = append(kinds, digs(e, "kind"))
	}
	if strings.Join(kinds, ",") != "executes_as,member_of,grant" {
		t.Errorf("path kinds = %v", kinds)
	}

	// Expansion: the group's members.
	ex := graphGet(t, api, "/graph/expand"+k8sQS("node", w.group, "edge", "member_of", "direction", "reverse"))
	contractCheck(t, "GET /graph/expand (group members)", ex, contractK8sGraphExpand)
	if n := digl(ex, "data", "nodes"); len(n) != 1 || digs(n[0], "ref") != w.sa {
		t.Errorf("group members = %v", ex["data"])
	}
}

/* ----------------------------- effective scope ------------------------------ */

// D-109: every Kubernetes grant says where its rule applies; a ClusterRole's
// rule reached through a RoleBinding applies in the binding's namespace, the
// same rule through a ClusterRoleBinding cluster-wide -- on the edge, since
// the rule node is one node whichever binding reaches it.
func TestP2K8sGraphEffectiveScope(t *testing.T) {
	f := newK8sGraphFixture(t, "p2-k8s-graph-scope")
	body := graphGet(t, f.api(), "/graph"+k8sQS("root", f.research, "direction", "forward"))
	want := map[string][2]any{
		"research-reads-secrets": {"cluster", nil},
		"research-secrets-ns":    {"namespace", k8sGraphNS},
		"research-pods":          {"namespace", k8sGraphNS},
	}
	n := 0
	for _, e := range graphEdgesOfKind(graphEdges(t, digl(body, "data", "edges")), "grant") {
		name := digs(e.Raw, "assignment", "name")
		w, ok := want[name]
		if !ok {
			t.Errorf("grant through %s", name)
			continue
		}
		n++
		if s, _ := dig(e.Raw, "effective_scope").(map[string]any); s == nil || s["kind"] != w[0] || s["namespace"] != w[1] {
			t.Errorf("grant via %s: effective_scope %v, want %v", name, dig(e.Raw, "effective_scope"), w)
		}
	}
	if n != 4 {
		t.Errorf("%d grants, want 4", n)
	}
	// The rule's own scope stays its role's: the ClusterRole is the cluster's.
	if rule := graphNodes(t, digl(body, "data", "nodes"))[f.secretRule]; rule["sub_scope"] != nil {
		t.Errorf("secret-reader rule sub_scope = %v, want null (a ClusterRole's)", rule["sub_scope"])
	}
}

/* ---------------------------------- rev ------------------------------------ */

// D-111: a Kubernetes root never pins or reports the AWS revision -- with or
// without a publication, any rev= is ignored, never 409.
func TestP2K8sGraphRevIgnored(t *testing.T) {
	f := newK8sGraphFixture(t, "p2-k8s-graph-rev")
	api := f.api()
	for _, p := range []string{
		"/graph" + k8sQS("root", f.workload, "direction", "forward", "rev", "7"),
		"/graph/expand" + k8sQS("node", f.research, "edge", "grant", "direction", "forward", "rev", "7"),
		"/graph/path" + k8sQS("from", f.workload, "to", f.secretRule, "rev", "7"),
	} {
		body := graphGet(t, api, p)
		if dig(body, "meta", "rev") != nil || dig(body, "meta", "published_at") != nil || digs(body, "meta", "graph_state") != "unrevisioned" {
			t.Errorf("GET %s meta = %v, want rev and published_at null, unrevisioned", p, body["meta"])
		}
	}
	// A root that does not exist is still the rev check's first (as before):
	// with no publication, any rev is stale.
	if code, b := api.get("/graph" + k8sQS("root", refOf("identity", uuid.New()), "direction", "forward", "rev", "7")); code != http.StatusConflict {
		t.Errorf("unknown root at rev 7 = %d %v, want 409", code, b)
	}

	// With a publication: the AWS root pins, the Kubernetes one does not.
	a := graphTeaching(t, f.p2Lab)
	f.scanAndProject(a)
	role := graphIdentity(t, f.p2Lab, "SharedToolRole")
	if code, b := api.get("/graph" + k8sQS("root", role, "direction", "forward", "rev", "999")); code != http.StatusConflict {
		t.Errorf("AWS root at rev 999 = %d %v, want 409", code, b)
	}
	body := graphGet(t, api, "/graph"+k8sQS("root", f.workload, "direction", "forward", "rev", "999"))
	if dig(body, "meta", "rev") != nil || digs(body, "meta", "graph_state") != "unrevisioned" {
		t.Errorf("k8s root beside a publication = %v", body["meta"])
	}
}

// graphKeys lists a node index's refs.
func graphKeys(m map[string]map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
