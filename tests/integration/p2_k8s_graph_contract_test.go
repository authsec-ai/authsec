package integration

// The Kubernetes additions to the traversal routes' contract, written in the
// frozen contract's shape language (p2_contract_shape_test.go) and CLOSED the
// same way: a field the routes add for Kubernetes and this file does not name
// fails. The frozen AWS shapes (p2_contract_schemas_test.go) are not touched:
// no AWS node or edge carries any field below, and every AWS response is
// checked against them unchanged.
//
// What a Kubernetes element is (traverse_k8s.go):
//
//	node   the AWS node's common fields, no account and no arn, plus provider
//	       "k8s", scope {kind k8s_cluster, id, label}, sub_scope (namespace or
//	       null); native_id on workloads and identities; k8s_rule on rules
//	edge   executes_as or grant, basis observed | declared, provider "k8s",
//	       never crosses an account; a grant carries policy, policy_ref,
//	       policy_kind and its binding (assignment)
//	meta   graph_state "unrevisioned", rev / published_at the AWS publication
//	       in the snapshot (null when none), limitations
//	       [effective_access_not_evaluated, k8s_observations_not_recorded]

import (
	"strings"
)

var (
	contractK8sScope = contractObj(
		contractReq("kind", contractConst("k8s_cluster")),
		contractReq("id", contractNonEmpty),
		contractReq("label", contractNonEmpty),
	)
	contractK8sGapState = contractEnum("not_swept", "incomplete", "namespaced_only", "namespace_not_swept", "unattributed")

	// stale_reason on a stale Kubernetes element: the sweep gap that left it
	// unconfirmed, in D-74's shape (account_id is the cluster, as the
	// inventory's k8s_sweep notes say it).
	contractK8sStaleReason = contractArr(contractObj(
		contractReq("account_id", contractStr),
		contractReq("surface", contractConst("k8s_sweep")),
		contractReq("state", contractK8sGapState),
		contractReq("since", contractNull),
	))

	contractK8sLimitation = contractFunc(func(path string, v any, errs *[]string) {
		m, _ := v.(map[string]any)
		code, _ := m["code"].(string)
		c := contractReq("code", contractConst(code))
		switch code {
		case "k8s_coverage_gap":
			contractObj(c, contractReq("cluster", contractNullable(contractNonEmpty)),
				contractReq("namespace", contractNullable(contractNonEmpty)), contractReq("state", contractK8sGapState),
				contractReq("observed_at", contractNullable(contractTime))).check(path, v, errs)
		case "k8s_unresolved_bindings":
			contractObj(c, contractReq("count", contractInt), contractReq("bindings", contractArrMin(1, contractNonEmpty)),
				contractReq("truncated", contractBool)).check(path, v, errs)
		default:
			contractFail(errs, path, "limitation %q is not a Kubernetes element's", code)
		}
	})

	contractK8sRule = contractObj(
		contractReq("verbs", contractArr(contractNonEmpty)),
		contractReq("api_groups", contractArr(contractStr)),
		contractReq("resources", contractArr(contractNonEmpty)),
		contractReq("resource_names", contractArr(contractNonEmpty)),
		contractReq("non_resource_urls", contractArr(contractNonEmpty)),
	)
)

// A Kubernetes graph node, by type.
var contractK8sGraphNode = contractFunc(func(path string, v any, errs *[]string) {
	m, _ := v.(map[string]any)
	ref, _ := m["ref"].(string)
	typ, _, _ := strings.Cut(ref, ":")
	common := []contractField{
		contractReq("ref", contractRef(typ)),
		contractReq("label", contractNonEmpty),
		contractReq("state", contractNodeState),
		contractReq("lifecycle", contractLifecycle),
		contractReq("last_confirmed_at", contractNullable(contractTime)),
		contractOpt("stale_reason", contractK8sStaleReason),
		contractReq("limitations", contractArr(contractK8sLimitation)),
		contractReq("provider", contractConst("k8s")),
		contractReq("scope", contractK8sScope),
		contractReq("sub_scope", contractNullable(contractNonEmpty)),
	}
	var more []contractField
	switch typ {
	case "workload":
		more = []contractField{contractReq("kind", contractConst("workload")),
			contractReq("runtime_kind", contractEnum("k8s_deployment", "k8s_statefulset", "k8s_daemonset",
				"k8s_cronjob", "k8s_job", "k8s_pod", "k8s_workload")),
			contractReq("native_id", contractNonEmpty)}
	case "identity":
		more = []contractField{contractReq("kind", contractEnum("k8s_service_account", "k8s_user", "k8s_group")),
			contractReq("native_id", contractNonEmpty),
			contractReq("restrictions", contractConst(map[string]any{"deny_statements": 0, "permissions_boundary": false})),
			contractReq("used_by_count", contractExact)}
	case "statement":
		more = []contractField{contractReq("kind", contractConst("statement")), contractReq("policy", contractNonEmpty),
			contractReq("policy_ref", contractRef("policy")), contractReq("effect", contractConst("allow")),
			contractReq("sid", contractConst("")), contractReq("group_key", contractNonEmpty),
			contractReq("exclusions", contractConst([]any{})), contractReq("k8s_rule", contractK8sRule)}
	default:
		contractFail(errs, path, "node type %q has no Kubernetes rows", typ)
		return
	}
	contractObj(append(common, more...)...).check(path, v, errs)
})

// A Kubernetes graph edge.
var contractK8sGraphEdge = contractFunc(func(path string, v any, errs *[]string) {
	m, _ := v.(map[string]any)
	kind, _ := m["kind"].(string)
	claimType := "relationship"
	from, to := contractRef("workload"), contractRef("identity")
	var more []contractField
	switch kind {
	case "executes_as":
	case "grant":
		claimType, from, to = "grant", contractRef("identity"), contractRef("statement")
		more = []contractField{
			contractReq("policy", contractNonEmpty), contractReq("policy_ref", contractRef("policy")),
			contractReq("policy_kind", contractEnum("k8s_role", "k8s_cluster_role")),
			contractReq("assignment", contractObj(
				contractReq("ref", contractRef("assignment")),
				contractReq("kind", contractEnum("k8s_role_binding", "k8s_cluster_role_binding")),
				contractReq("name", contractNonEmpty),
				contractReq("namespace", contractNullable(contractNonEmpty)),
			)),
		}
	default:
		contractFail(errs, path, "edge kind %q has no Kubernetes rows", kind)
		return
	}
	contractObj(append([]contractField{
		contractReq("claim", contractRef(claimType)),
		contractReq("kind", contractConst(kind)),
		contractReq("from", from),
		contractReq("to", to),
		contractReq("state", contractEdgeState),
		contractReq("basis", contractEnum("observed", "declared")),
		contractReq("closes_cycle", contractBool),
		contractReq("crosses_account", contractConst(false)),
		contractReq("last_confirmed_at", contractNullable(contractTime)),
		contractOpt("stale_reason", contractK8sStaleReason),
		contractReq("limitations", contractArr(contractK8sLimitation)),
		contractReq("provider", contractConst("k8s")),
	}, more...)...).check(path, v, errs)
})

// The Kubernetes traversal meta.
var contractK8sGraphMeta = contractObj(
	contractReq("rev", contractNullable(contractInt)),
	contractReq("published_at", contractNullable(contractTime)),
	contractReq("graph_state", contractConst("unrevisioned")),
	contractReq("capabilities", contractConst(map[string]any{})),
	contractReq("budgets", contractObj(
		contractReq("nodes", contractConst(500)), contractReq("edges", contractConst(2000)),
		contractReq("assume_hops", contractConst(4)), contractReq("timeout_ms", contractConst(3000)),
		contractReq("neighbours_per_page", contractConst(100)), contractReq("paths", contractConst(200)),
	)),
	contractReq("limitations", contractConst([]any{
		map[string]any{"code": "effective_access_not_evaluated"},
		map[string]any{"code": "k8s_observations_not_recorded"},
	})),
)

// The frontier of a Kubernetes traversal names only the two Kubernetes kinds.
var contractK8sFrontier = contractAll(contractFrontier, contractFunc(func(path string, v any, errs *[]string) {
	contractObj(
		contractReq("node", contractRef("workload", "identity", "statement")),
		contractReq("edge", contractEnum("executes_as", "grant")),
		contractReq("direction", contractEnum("forward", "reverse")),
		contractReq("more", contractAnyValue),
		contractReq("expand", contractStr),
	).check(path, v, errs)
}))

var contractK8sGraph = contractDetail(contractObj(
	contractReq("root", contractRef("workload", "identity", "statement")),
	contractReq("nodes", contractArrMin(1, contractK8sGraphNode)),
	contractReq("edges", contractArr(contractK8sGraphEdge)),
	contractReq("frontier", contractArr(contractK8sFrontier)),
	contractReq("truncated", contractTruncated),
	contractReq("resolution_not_followed", contractNullable(contractBool)),
), contractK8sGraphMeta)

var contractK8sGraphExpand = contractDetail(contractObj(
	contractReq("nodes", contractArr(contractK8sGraphNode)),
	contractReq("edges", contractArr(contractK8sGraphEdge)),
	contractReq("frontier", contractArr(contractK8sFrontier)),
	contractReq("truncated", contractTruncated),
	contractReq("next_cursor", contractNullable(contractNonEmpty)),
), contractK8sGraphMeta)

var contractK8sGraphPath = contractDetail(contractObj(
	contractReq("from", contractRef("workload", "identity", "statement")),
	contractReq("to", contractRef("workload", "identity", "statement")),
	contractReq("direction", contractNullable(contractEnum("forward", "reverse"))),
	contractReq("outcome", contractEnum("found", "none_exists", "not_found_within_budget")),
	contractReq("paths", contractArr(contractObj(
		contractReq("nodes", contractArrMin(2, contractK8sGraphNode)),
		contractReq("edges", contractArrMin(1, contractK8sGraphEdge)),
		contractReq("limitations", contractArr(contractK8sLimitation)),
	))),
	contractReq("more_paths", contractBool),
	contractReq("bound_by", contractNullable(contractEnum("nodes", "edges", "assume_hops", "time", "paths", "resolution_not_followed"))),
), contractK8sGraphMeta)
