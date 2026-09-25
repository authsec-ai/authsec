package integration

// The frozen §5 contract (SPEC-iga-phase2-graph.md §5.2, §5.3), written down
// field by field in the shape language of p2_contract_shape_test.go. Where §5
// is silent the P2-DECISIONS entry that settles a field is cited beside it; a
// field neither names is not in the contract, and the closed object shapes
// reject it.
//
// These shapes are the contract the console types are built from (§2.14.14):
// change one only together with the spec or a recorded decision.

import (
	"strings"
)

/* ------------------------------ shared pieces ------------------------------ */

var (
	contractLifecycle     = contractEnum("active", "retired")
	contractNodeState     = contractEnum("current", "stale", "ended") // D-1
	contractEdgeState     = contractEnum("current", "stale", "ended")
	contractGraphState    = contractEnum("published", "not_published")
	contractBasis         = contractEnum("declared", "derived", "asserted")
	contractRelType       = contractEnum("executes_as", "task_execution_role", "member_of", "can_assume")
	contractIdentityKind  = contractEnum("iam_role", "iam_user", "iam_group")
	contractRuntimeKind   = contractEnum("lambda_function", "ecs_task_definition", "ec2_instance", "bedrock_agent", "bedrock_agentcore_runtime", "bedrock_agentcore_gateway")
	contractPolicyKind    = contractEnum("aws_managed", "customer_managed", "inline")
	contractResourceKind  = contractEnum("exact", "selector", "external")                                             // D-16
	contractMechanism     = contractEnum("sts_assume_role", "oidc_federation", "saml_federation", "eks_pod_identity") // D-43
	contractExternalKind  = contractEnum("aws_account", "aws_principal", "aws_service", "oidc", "saml", "k8s_service_account")
	contractClassifyValue = contractEnum("provider_native_agent", "classified_agent", "unclassified")
	contractSurfaceState  = contractEnum("reached", "partial", "denied", "throttled", "not_selected", "unsupported", "not_configured", "unknown", "stale", "constrained", "revoked")

	// account is {id, label, connected} (§2.14.14); where the object may have
	// no stated account the field is contractNullable(contractAccount).
	contractAccount = contractObj(
		contractReq("id", contractAccountID),
		contractReq("label", contractNonEmpty),
		contractReq("connected", contractBool),
	)

	// {value, exact} (§5.3; D-17: value null only when not established).
	contractExact = contractFunc(func(path string, v any, errs *[]string) {
		contractObj(contractReq("value", contractNullable(contractInt)), contractReq("exact", contractBool)).check(path, v, errs)
		if m, ok := v.(map[string]any); ok && m["value"] == nil && m["exact"] == true {
			contractFail(errs, path, "an exact count must state its value")
		}
	})

	// meta.coverage[] (§5.2 list envelope).
	contractCoverageNote = contractObj(
		contractReq("account_id", contractAccountID),
		contractReq("surface", contractNonEmpty),
		contractReq("state", contractSurfaceState),
		contractReq("affects", contractNonEmpty),
	)

	// stale_reason (D-74), present on stale rows only.
	contractStaleReason = contractArr(contractObj(
		contractReq("account_id", contractStr),
		contractReq("surface", contractNonEmpty),
		contractReq("state", contractSurfaceState),
		contractReq("since", contractNullable(contractTime)),
	))

	// A facet chip (§5.2): value, label, count.
	contractFacetValue = contractObj(
		contractReq("value", contractNonEmpty),
		contractReq("label", contractNonEmpty),
		contractReq("count", contractInt),
	)
)

// contractAll checks every shape against the same value.
func contractAll(shapes ...contractShape) contractShape {
	return contractFunc(func(path string, v any, errs *[]string) {
		for _, s := range shapes {
			s.check(path, v, errs)
		}
	})
}

// contractTotalsRule is §2.14.14's: total is present only when total_known is
// true; total_at_least only when the count passed the cap (D-15).
var contractTotalsRule = contractFunc(func(path string, v any, errs *[]string) {
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	_, hasTotal := m["total"]
	if known, _ := m["total_known"].(bool); known != hasTotal {
		contractFail(errs, path, "total present=%v but total_known=%v", hasTotal, m["total_known"])
	}
	if _, has := m["total_at_least"]; has && m["total_known"] == true {
		contractFail(errs, path, "total_at_least beside total_known=true")
	}
})

// contractListMeta is the §5.2 list envelope's meta, plus a route's own
// fields (D-27 kind/history_begins, D-77 the tab's subject).
func contractListMeta(extra ...contractField) contractShape {
	base := contractObj(
		contractReq("rev", contractNullable(contractInt)),
		contractReq("published_at", contractNullable(contractTime)),
		contractReq("graph_state", contractGraphState),
		contractReq("next_cursor", contractNullable(contractNonEmpty)),
		contractReq("limit", contractInt),
		contractReq("total_known", contractBool),
		contractOpt("total", contractInt),
		contractOpt("total_at_least", contractInt),
		contractOpt("facets", contractMap(contractNullable(contractArr(contractFacetValue)))),
		contractReq("coverage", contractArr(contractCoverageNote)),
	)
	return contractAll(contractExtend(base, extra...), contractTotalsRule)
}

// contractDetailMeta is the §5.2 detail envelope's meta -- rev,
// published_at, graph_state and capabilities (§2.14.14: "meta.capabilities on
// detail responses"; D-83: can_classify on workload detail only).
func contractDetailMeta(extra ...contractField) contractShape {
	return contractExtend(contractObj(
		contractReq("rev", contractNullable(contractInt)),
		contractReq("published_at", contractNullable(contractTime)),
		contractReq("graph_state", contractGraphState),
		contractReq("capabilities", contractMap(contractBool)),
	), extra...)
}

// contractList / contractDetail are the two §5.2 envelopes.
func contractList(row contractShape, meta contractShape) contractShape {
	return contractObj(contractReq("data", contractArr(row)), contractReq("meta", meta))
}

func contractDetail(data contractShape, meta contractShape) contractShape {
	return contractObj(contractReq("data", data), contractReq("meta", meta))
}

// contractSection is one paged section of a multi-section tab (D-77).
func contractSection(item contractShape, min int) contractShape {
	return contractAll(contractObj(
		contractReq("items", contractArrMin(min, item)),
		contractReq("next_cursor", contractNullable(contractNonEmpty)),
		contractReq("total_known", contractBool),
		contractOpt("total", contractInt),
		contractOpt("total_at_least", contractInt),
	), contractTotalsRule)
}

/* ------------------------------- limitations ------------------------------- */

// contractLimitation is one limitation (§5.3 vocabulary) with exactly its
// code's own fields -- the SAME fields on /evidence, on every graph node and
// edge, and on paths (D-35: one function), so the console has one type per
// code.
var contractLimitation = contractFunc(func(path string, v any, errs *[]string) {
	m, ok := v.(map[string]any)
	if !ok {
		contractFail(errs, path, "want a limitation object, got %s", contractJSON(v))
		return
	}
	code, _ := m["code"].(string)
	c := contractReq("code", contractConst(code))
	refs := func(t string) contractShape { return contractArr(contractRef(t)) }
	var s contractShape
	switch code {
	case "effective_access_not_evaluated", "organizations_not_collected", "caller_permission_not_evaluated",
		"not_principal_unresolved", "activity_attempts_not_outcomes":
		s = contractObj(c)
	case "conditions_not_evaluated":
		s = contractObj(c, contractReq("keys", contractArr(contractNonEmpty)))
	case "negated_statement":
		s = contractObj(c, contractReq("negations", contractArrMin(1, contractEnum("NotAction", "NotResource"))))
	case "deny_statements_present":
		s = contractObj(c, contractReq("count", contractInt), contractReq("statements", refs("statement")),
			contractReq("truncated", contractBool))
	case "permissions_boundary_present":
		s = contractObj(c, contractReq("holder", contractBool), contractReq("policies", refs("policy")),
			contractReq("members", refs("identity")), contractReq("member_count", contractInt),
			contractReq("truncated", contractBool))
	case "resource_policy_not_projected", "resource_existence_not_verified", "selector_may_match_nothing":
		s = contractObj(c, contractReq("resources", contractArrMin(1, contractRef("resource"))))
	case "account_not_connected":
		s = contractObj(c, contractReq("accounts", contractArrMin(1, contractAccountID)))
	case "surface_stale", "surface_partial", "surface_denied":
		s = contractObj(c, contractReq("account_id", contractStr), contractReq("surface", contractNonEmpty),
			contractReq("state", contractSurfaceState), contractReq("since", contractNullable(contractTime)))
	default:
		contractFail(errs, path, "limitation code %q is not in the §5.3 vocabulary", code)
		return
	}
	s.check(path, v, errs)
})

var contractLimitations = contractArr(contractLimitation)

/* -------------------------------- workloads -------------------------------- */

// execution_role (§5.3 list row): resolved names the live executes_as
// identity; not_in_scan / not_in_inventory carry the ARN the workload names
// (§5.3 l.5853-5855: "execution_role_arn"); none carries nothing more.
var contractExecutionRole = contractFunc(func(path string, v any, errs *[]string) {
	m, _ := v.(map[string]any)
	state, _ := m["state"].(string)
	st := contractReq("state", contractConst(state))
	switch state {
	case "resolved":
		contractObj(st, contractReq("identity", contractNullable(contractRef("identity"))),
			contractReq("name", contractNullable(contractNonEmpty))).check(path, v, errs)
	case "not_in_scan", "not_in_inventory":
		contractObj(st, contractReq("execution_role_arn", contractNonEmpty)).check(path, v, errs)
	case "none":
		contractObj(st).check(path, v, errs)
	default:
		contractFail(errs, path, "execution_role.state %q", state)
	}
})

// The §5.3 workload list row.
var contractWorkloadRow = contractObj(
	contractReq("ref", contractRef("workload")),
	contractReq("name", contractNonEmpty),
	contractReq("runtime_kind", contractRuntimeKind),
	contractReq("arn", contractNonEmpty),
	contractReq("account", contractAccount), // never unknown for a workload (§2.14.10)
	contractReq("region", contractNullable(contractNonEmpty)),
	contractReq("classification", contractClassifyValue),
	contractReq("classification_version", contractInt),
	contractReq("execution_role", contractExecutionRole),
	contractReq("lifecycle", contractLifecycle),
	contractOpt("retired_reason", contractNonEmpty), // list rows: retired rows only
	contractReq("state", contractNodeState),
	contractOpt("stale_reason", contractStaleReason),
	contractReq("first_seen_at", contractTime),
	contractReq("last_confirmed_at", contractNullable(contractTime)),
	contractReq("instances", contractObj(contractReq("state", contractConst("not_collected")))),
)

// sources (§5.3 "the connectors whose support rows hold it, with state"): one
// support row each, the same shape on every detail route.
var contractSource = contractObj(
	contractReq("presence", contractRef("presence")),
	contractReq("integration", contractRef("cloud_connector")),
	contractReq("account", contractNullable(contractAccount)),
	contractReq("state", contractNodeState),
	contractReq("first_seen_at", contractTime),
	contractReq("last_confirmed_at", contractNullable(contractTime)),
	contractReq("ended_reason", contractNullable(contractNonEmpty)),
)

var contractDecidedBy = contractObj(
	contractReq("user_id", contractNonEmpty),
	contractReq("display", contractNonEmpty),
)

// GET /workloads/:id: the list fields plus continuity, provider_attrs (D-85),
// sources and the latest decision (§5.3).
var contractWorkloadDetail = contractExtend(contractWorkloadRow,
	contractReq("retired_reason", contractNullable(contractNonEmpty)), // details: always stated
	contractReq("continuity", contractEnum("immutable", "recognition_only")),
	contractReq("provider_attrs", contractObj(
		contractReq("status", contractNullable(contractStr)),
		contractReq("foundation_model", contractNullable(contractStr)),
		contractReq("env_var_names", contractNullable(contractArr(contractStr))),
		contractReq("gateway_targets", contractNullable(contractArr(contractObj(
			contractReq("id", contractStr), contractReq("name", contractStr),
			contractReq("status", contractStr), contractReq("type", contractStr))))),
	)),
	contractReq("sources", contractArrMin(1, contractSource)),
	contractReq("decision", contractNullable(contractObj(
		contractReq("id", contractNonEmpty),
		contractReq("operation_id", contractNonEmpty),
		contractReq("decision", contractEnum("classified_agent", "unclassified")),
		contractReq("purpose", contractNullable(contractStr)),
		contractReq("reason", contractNonEmpty),
		contractReq("decided_by", contractDecidedBy),
		contractReq("decided_at", contractTime),
	))),
)

// The identity brief every tab row names an identity with.
var contractIdentityBrief = contractObj(
	contractReq("ref", contractRef("identity")),
	contractReq("name", contractNonEmpty),
	contractReq("kind", contractIdentityKind),
	contractReq("arn", contractNonEmpty),
	contractReq("account", contractNullable(contractAccount)),
)

// The claim fields every relationship row carries.
func contractClaimRow(more ...contractField) contractShape {
	return contractExtend(contractObj(
		contractReq("claim", contractRef("relationship")),
		contractReq("type", contractRelType),
		contractReq("basis", contractBasis),
		contractReq("state", contractEdgeState),
		contractOpt("stale_reason", contractStaleReason),
		contractReq("valid_from", contractTime),
		contractOpt("valid_to", contractTime),
		contractOpt("ended_reason", contractNonEmpty),
		contractReq("last_confirmed_at", contractTime),
	), more...)
}

// A trust statement (§4.7 "Sid, else content hash"), as every can_assume row
// names it: used-by principals, referenced-by and may_assume alike.
var contractTrustStatement = contractObj(
	contractReq("key", contractNonEmpty),
	contractReq("sid", contractStr),
	contractReq("negated", contractBool),
)

// The subject a tab is about (D-77 tab meta).
var contractWorkloadSubject = contractObj(
	contractReq("ref", contractRef("workload")),
	contractReq("lifecycle", contractLifecycle),
	contractReq("retired_reason", contractNullable(contractNonEmpty)),
)

// GET /workloads/:id/identities (§5.3; D-77 sections).
var contractWorkloadIdentities = contractDetail(contractWorkloadIdentitiesData, contractWorkloadIdentitiesMeta)

// GET /workloads/:id/identities?section=<name> (D-77): that section alone.
func contractWorkloadIdentitiesSection(section string) contractShape {
	var drop []string
	for _, s := range []string{"execution", "other", "groups", "may_assume"} {
		if s != section {
			drop = append(drop, s)
		}
	}
	// execution_role_state and _arn come with the full tab only.
	drop = append(drop, "execution_role_state", "execution_role_arn")
	return contractDetail(contractWithout(contractWorkloadIdentitiesData, drop...), contractWorkloadIdentitiesMeta)
}

var contractWorkloadIdentitiesMeta = contractDetailMeta(
	contractReq("coverage", contractArr(contractCoverageNote)),
	contractReq("limit", contractInt),
	contractReq("workload", contractWorkloadSubject),
)

var contractWorkloadIdentitiesData = contractObj(
	contractReq("ref", contractRef("workload")),
	contractReq("execution", contractSection(contractClaimRow(
		contractReq("identity", contractIdentityBrief),
		contractReq("used_by_count", contractExact)), 0)),
	contractReq("execution_role_state", contractEnum("resolved", "not_in_scan", "not_in_inventory", "none")),
	contractReq("execution_role_arn", contractNullable(contractNonEmpty)),
	contractReq("other", contractSection(contractClaimRow(
		contractReq("identity", contractIdentityBrief),
		contractReq("used_by_count", contractExact)), 0)),
	contractReq("groups", contractSection(contractClaimRow(
		contractReq("identity", contractIdentityBrief),
		contractReq("via_identity", contractRef("identity"))), 0)),
	contractReq("may_assume", contractSection(contractClaimRow(
		contractReq("via_identity", contractRef("identity")),
		contractReq("target", contractIdentityBrief),
		contractReq("mechanism", contractMechanism),
		contractReq("statement", contractTrustStatement),
		contractReq("conditions", contractAnyValue)), 0)),
)

// A policy as a grant line or access row names it.
var contractPolicyBrief = contractObj(
	contractReq("ref", contractRef("policy")),
	contractReq("name", contractNonEmpty),
	contractReq("kind", contractPolicyKind),
)

// A statement as a grant line names it (§5.3 l.5869-5870; D-84 1-based index).
var contractStatementBrief = contractObj(
	contractReq("ref", contractRef("statement")),
	contractReq("sid", contractStr),
	contractReq("index", contractInt),
	contractReq("actions", contractArr(contractNonEmpty)),
	contractReq("not_actions", contractArr(contractNonEmpty)),
	contractReq("conditional", contractBool),
)

// A resource as a Resources-tab row names it (§5.3 l.5864-5865).
var contractResourceBrief = contractObj(
	contractReq("ref", contractRef("resource")),
	contractReq("text", contractNonEmpty),
	contractReq("kind", contractResourceKind),
	contractReq("type", contractNonEmpty),
	contractReq("service", contractNullable(contractNonEmpty)),
	contractReq("account", contractNullable(contractAccount)),
	contractReq("region", contractNullable(contractNonEmpty)),
)

var contractExclusion = contractObj(
	contractReq("ref", contractRef("resource")),
	contractReq("text", contractNonEmpty),
)

// GET /workloads/:id/resources (§5.3; D-77 list envelope, D-78 restrictions).
var contractWorkloadResources = contractList(
	contractObj(
		contractReq("resource", contractResourceBrief),
		contractReq("grants", contractArrMin(1, contractObj(
			contractReq("claim", contractRef("grant")),
			contractReq("via_identity", contractRef("identity")),
			contractReq("policy", contractPolicyBrief),
			contractReq("statement", contractStatementBrief),
			contractReq("target_mode", contractConst("resource")),
			contractReq("state", contractEdgeState),
			contractOpt("stale_reason", contractStaleReason),
			contractReq("valid_from", contractTime),
			contractOpt("valid_to", contractTime),
			contractOpt("ended_reason", contractNonEmpty),
			contractReq("last_confirmed_at", contractTime),
			contractReq("exclusions", contractArr(contractExclusion)),
		))),
		contractReq("restrictions", contractObj(
			contractReq("deny_statements", contractInt),
			contractReq("permissions_boundary", contractBool),
		)),
	),
	contractListMeta(contractReq("workload", contractWorkloadSubject)),
)

/* --------------------------------- changes --------------------------------- */

// One Changes event (§5.3 Changes; D-27's shape, D-27a attribution).
var contractChangeEvent = contractFunc(func(path string, v any, errs *[]string) {
	m, _ := v.(map[string]any)
	event, _ := m["event"].(string)
	var detail contractShape
	switch event {
	case "first_seen", "retired", "restored":
		detail = contractObj(contractReq("object", contractRef("workload", "identity", "resource", "statement", "policy")))
	case "relationship_started", "relationship_ended":
		detail = contractObj(contractReq("type", contractRelType), contractReq("source", contractRef("workload", "identity", "external_principal")),
			contractReq("target", contractRef("identity")), contractOpt("mechanism", contractMechanism), contractReq("state", contractEdgeState))
	case "policy_attached", "policy_detached":
		detail = contractObj(contractReq("policy", contractRef("policy")), contractReq("holder", contractRef("identity")),
			contractReq("assignment_kind", contractEnum("attached", "inline", "boundary")), contractReq("state", contractEdgeState))
	case "grant_started", "grant_ended":
		detail = contractObj(contractReq("policy", contractRef("policy")), contractReq("statement", contractRef("statement")),
			contractReq("holder", contractRef("identity")), contractReq("assignment", contractRef("assignment")),
			contractReq("state", contractEdgeState), contractReq("actions", contractArr(contractStr)),
			contractOpt("not_actions", contractArr(contractStr)), contractReq("targets", contractArr(contractRef("resource"))))
	case "statement_revised":
		detail = contractObj(contractReq("policy", contractRef("policy")), contractReq("statement", contractRef("statement")))
	case "statement_replaced":
		detail = contractObj(contractReq("policy", contractRef("policy")))
	case "coverage_changed":
		detail = contractObj(contractReq("integration", contractRef("cloud_connector")), contractReq("account_id", contractAccountID),
			contractReq("surface", contractNonEmpty))
	default:
		contractFail(errs, path, "event %q is not a §5.3 Changes event", event)
		return
	}
	idOK := contractFunc(func(p string, v any, errs *[]string) {
		if s, _ := v.(string); !strings.HasPrefix(s, event+":") {
			contractFail(errs, p, "want %q-prefixed id, got %s", event+":", contractJSON(v))
		}
	})
	remaining := contractArr(contractObj(
		contractReq("grant", contractRef("grant")), contractReq("state", contractEdgeState),
		contractReq("last_confirmed_at", contractTime), contractReq("policy", contractRef("policy")),
		contractReq("statement", contractRef("statement")), contractReq("targets", contractArr(contractRef("resource")))))
	paths := contractArr(contractObj(contractReq("target", contractRef("resource")),
		contractReq("remains", contractEnum("current", "stale", "none"))))
	contractObj(
		contractReq("id", idOK),
		contractReq("event", contractConst(event)),
		contractReq("at", contractTime),
		contractReq("rev", contractNullable(contractInt)),
		contractReq("run", contractNullable(contractRef("cloud_scan_run"))),
		contractReq("subject", contractNonEmpty),
		contractReq("claims", contractArrMin(1, contractNonEmpty)),
		contractReq("reason", contractNullable(contractNonEmpty)),
		contractOpt("via", contractRef("identity")),
		contractReq("detail", detail),
		contractOpt("before", contractAnyValue),
		contractOpt("after", contractAnyValue),
		contractOpt("remaining", remaining),
		contractOpt("paths", paths),
		contractReq("labels", contractMap(contractStr)),
	).check(path, v, errs)
})

var contractChanges = contractList(contractChangeEvent, contractListMeta(
	contractReq("kind", contractEnum("configuration", "coverage")),
	contractReq("history_begins", contractNullable(contractTime)),
))

/* ------------------------------ classification ----------------------------- */

var contractHistoryItem = contractObj(
	contractReq("id", contractNonEmpty),
	contractReq("operation_id", contractNonEmpty),
	contractReq("decision", contractEnum("classified_agent", "unclassified")),
	contractReq("previous", contractClassifyValue),
	contractReq("purpose", contractNullable(contractStr)),
	contractReq("reason", contractNonEmpty),
	contractReq("decided_by", contractDecidedBy),
	contractReq("decided_at", contractTime),
	contractReq("against_version", contractInt),
	contractReq("result_version", contractInt),
	contractReq("undoes_decision_id", contractNullable(contractNonEmpty)),
)

// POST /workloads/:id/classification 200 (§5.5).
var contractClassifyOK = contractObj(contractReq("data", contractObj(
	contractReq("classification", contractEnum("classified_agent", "unclassified")),
	contractReq("classification_version", contractInt),
	contractReq("decision", contractObj(
		contractReq("id", contractNonEmpty),
		contractReq("operation_id", contractNonEmpty),
		contractReq("decided_by", contractDecidedBy),
		contractReq("decided_at", contractTime),
		contractReq("reason", contractNonEmpty),
		contractReq("purpose", contractNullable(contractStr)),
	)),
	contractReq("replayed", contractBool),
)))

/* -------------------------------- identities ------------------------------- */

// The identity list row (§5.3: name, kind, ARN, account, used_by_count,
// last_confirmed_at; §2.14.14 ref and region; D-1 state).
var contractIdentityRow = contractObj(
	contractReq("ref", contractRef("identity")),
	contractReq("name", contractNonEmpty),
	contractReq("kind", contractIdentityKind),
	contractReq("arn", contractNonEmpty),
	contractReq("account", contractAccount), // never unknown for a collected identity
	contractReq("region", contractConst("global")),
	contractReq("used_by_count", contractExact),
	contractReq("lifecycle", contractLifecycle),
	contractOpt("retired_reason", contractNonEmpty),
	contractReq("state", contractNodeState),
	contractOpt("stale_reason", contractStaleReason),
	contractReq("last_confirmed_at", contractNullable(contractTime)),
)

// GET /identities/:id: the list fields plus continuity, immutable_key,
// provider_attrs (D-85), credentials for users (D-86) and sources.
func contractIdentityDetailData(kind string) contractShape {
	attrs := []contractField{
		contractReq("path", contractNullable(contractStr)), // null when not recorded (D-102d)
		contractReq("tags", contractMap(contractStr)),
		contractReq("permissions_boundary_arn", contractNullable(contractNonEmpty)),
	}
	// The trust flags are on EVERY kind (D-85, one shape: D-102d). Only a role
	// has a trust policy (D-44), so only a role's may be a bool -- null when
	// the projector wrote none, never a false it did not read; a user's or
	// group's is null, stated, never absent.
	trustFlag := contractNull
	if kind == "iam_role" {
		trustFlag = contractNullable(contractBool)
	}
	attrs = append(attrs, contractReq("trust_has_deny", trustFlag), contractReq("trust_has_not_principal", trustFlag))
	more := []contractField{
		contractReq("retired_reason", contractNullable(contractNonEmpty)), // details: always stated
		contractReq("first_seen_at", contractTime),
		contractReq("continuity", contractEnum("immutable", "recognition_only")),
		contractReq("immutable_key", contractStr),
		contractReq("provider_attrs", contractObj(attrs...)),
		contractReq("sources", contractArrMin(1, contractSource)),
	}
	if kind == "iam_user" {
		more = append(more, contractReq("credentials", contractArr(contractObj(
			contractReq("key_id", contractNonEmpty),
			contractReq("status", contractEnum("Active", "Inactive")),
			contractReq("lifecycle", contractEnum("active", "expired", "revoked", "rotated")),
			contractReq("created_at", contractNullable(contractTime)),
			contractReq("last_used_at", contractNullable(contractTime)),
			contractReq("last_seen_at", contractNullable(contractTime)),
		))))
	}
	return contractExtend(contractIdentityRow, more...)
}

func contractIdentityDetail(kind string) contractShape {
	return contractDetail(contractIdentityDetailData(kind), contractDetailMeta(contractReq("coverage", contractArr(contractCoverageNote))))
}

// The identity a tab is about.
var contractIdentitySubject = contractObj(
	contractReq("ref", contractRef("identity")),
	contractReq("name", contractNonEmpty),
	contractReq("kind", contractIdentityKind),
	contractReq("lifecycle", contractLifecycle),
	contractReq("state", contractNodeState),
	contractOpt("retired_reason", contractNonEmpty),
)

// A principal of a role (identity or external principal), as Used by names it.
var contractPrincipalBrief = contractObj(
	contractReq("ref", contractRef("identity", "external_principal")),
	contractReq("name", contractNonEmpty),
	contractReq("kind", contractEnum("iam_role", "iam_user", "iam_group", "aws_account", "aws_principal", "aws_service", "oidc", "saml", "k8s_service_account")),
	contractReq("arn", contractNullable(contractNonEmpty)),
	contractReq("account", contractNullable(contractAccount)),
)

// GET /identities/:id/used-by (§5.3; D-77): workloads and principals for a
// role, members for a group.
func contractUsedBy(kind string) contractShape {
	return contractDetail(contractUsedByData(kind), contractUsedByMeta)
}

// GET /identities/:id/used-by?section=<name> (D-77): that section alone.
func contractUsedBySection(kind, section string) contractShape {
	var drop []string
	for _, s := range []string{"workloads", "principals", "members"} {
		if s != section {
			drop = append(drop, s)
		}
	}
	return contractDetail(contractWithout(contractUsedByData(kind), drop...), contractUsedByMeta)
}

var contractUsedByMeta = contractDetailMeta(contractReq("coverage", contractArr(contractCoverageNote)))

func contractUsedByData(kind string) contractShape {
	fields := []contractField{contractReq("identity", contractIdentitySubject)}
	switch kind {
	case "iam_role":
		fields = append(fields,
			contractReq("workloads", contractSection(contractClaimRow(contractReq("workload", contractObj(
				contractReq("ref", contractRef("workload")), contractReq("name", contractNonEmpty),
				contractReq("runtime_kind", contractRuntimeKind), contractReq("arn", contractNonEmpty),
				contractReq("account", contractAccount), contractReq("region", contractNullable(contractNonEmpty))))), 0)),
			contractReq("principals", contractSection(contractClaimRow(
				contractReq("principal", contractPrincipalBrief),
				contractReq("mechanism", contractMechanism),
				contractReq("statement", contractTrustStatement),
				contractReq("conditions", contractAnyValue)), 0)))
	case "iam_group":
		fields = append(fields, contractReq("members", contractSection(contractClaimRow(
			contractReq("member", contractIdentityBrief)), 0)))
	}
	return contractObj(fields...)
}

// One statement of the Permissions tab (§5.3 l.5910-5914).
var contractPermissionStatement = contractObj(
	contractReq("ref", contractRef("statement")),
	contractReq("sid", contractStr),
	contractReq("index", contractInt),
	contractReq("effect", contractEnum("allow", "deny")),
	contractReq("actions", contractArr(contractNonEmpty)),
	contractReq("not_actions", contractArr(contractNonEmpty)),
	contractReq("targets", contractArr(contractObj(
		contractReq("ref", contractRef("resource")),
		contractReq("claim", contractRef("target")),
		contractReq("text", contractNonEmpty),
		contractReq("kind", contractResourceKind),
		contractReq("mode", contractEnum("resource", "not_resource")),
	))),
	contractReq("condition", contractAnyValue),
	contractReq("grant", contractNullable(contractRef("grant"))),
	contractReq("grant_state", contractNullable(contractEdgeState)),
	contractReq("revision_count", contractInt),
	contractReq("state", contractNodeState),
	contractOpt("stale_reason", contractStaleReason),
)

var contractPermissionPolicy = contractObj(
	contractReq("ref", contractRef("policy")),
	contractReq("name", contractNonEmpty),
	contractReq("kind", contractPolicyKind),
	contractReq("assignment", contractObj(
		contractReq("claim", contractRef("assignment")),
		contractReq("kind", contractEnum("attached", "inline", "boundary")),
		contractReq("via_group", contractNullable(contractRef("identity"))),
		contractReq("state", contractEdgeState),
		contractOpt("stale_reason", contractStaleReason),
		contractReq("valid_from", contractTime),
		contractOpt("valid_to", contractTime),
		contractOpt("ended_reason", contractNonEmpty),
	)),
	contractReq("statements", contractArr(contractPermissionStatement)),
)

// GET /identities/:id/permissions (§5.3; D-77 unpaged with a cap, D-86
// activity).
var contractPermissions = contractDetail(
	contractObj(
		contractReq("identity", contractIdentitySubject),
		contractReq("policies", contractArr(contractPermissionPolicy)),
		contractReq("boundary", contractObj(contractReq("policy", contractNullable(contractPermissionPolicy)))),
		contractReq("inherited", contractArr(contractObj(
			contractReq("group", contractRef("identity")),
			contractReq("name", contractNonEmpty),
			contractReq("membership", contractClaimRow()),
			contractReq("policies", contractArr(contractPermissionPolicy)),
		))),
		contractReq("activity", contractObj(
			contractReq("source", contractConst("access_advisor")),
			contractReq("state", contractEnum("collected", "not_collected")),
			contractReq("tracking_note", contractNonEmpty),
			contractReq("services", contractNullable(contractArr(contractObj(
				contractReq("namespace", contractNonEmpty),
				contractReq("last_authenticated_attempt", contractNullable(contractTime)),
			)))),
			contractReq("reason", contractNullable(contractNonEmpty)),
		)),
		contractReq("truncated", contractBool),
	),
	contractDetailMeta(contractReq("coverage", contractArr(contractCoverageNote))),
)

/* ---------------------------- external principals -------------------------- */

// A recorded resolution (§2.12, §5.3; D-87): the same object on the detail
// and on a graph node; what was not recorded is null.
var contractResolution = contractObj(
	contractReq("state", contractEnum("active", "suspended", "pending_reconfirmation")),
	contractReq("basis", contractEnum("derived", "asserted")),
	contractReq("rule", contractNullable(contractNonEmpty)),
	contractReq("resolved_to", contractNullable(contractRef("identity", "workload"))),
	contractReq("resolved_by", contractNullable(contractNonEmpty)),
)

// GET /external-principals/:id (§5.3; D-87 resolution and labels).
var contractExternalDetail = contractDetail(
	contractObj(
		contractReq("ref", contractRef("external_principal")),
		contractReq("name", contractNonEmpty),
		contractReq("mechanism", contractExternalKind),
		contractReq("issuer", contractNonEmpty),
		contractReq("subject", contractNonEmpty),
		contractReq("account", contractNullable(contractAccount)),
		contractReq("account_connected", contractNullable(contractBool)),
		contractReq("resolution", contractNullable(contractResolution)),
		// null exactly when a resolution is in force (idetail_external.go).
		contractReq("unresolved_reason", contractNullable(contractEnum("wildcard", "service_principal",
			"account_not_connected", "account_principal", "not_in_inventory"))),
		contractReq("lifecycle", contractLifecycle),
		contractReq("retired_reason", contractNullable(contractNonEmpty)), // details: always stated
		contractReq("state", contractNodeState),
		contractOpt("stale_reason", contractStaleReason),
		contractReq("first_seen_at", contractTime),
		contractReq("last_seen_at", contractTime),
		contractReq("last_confirmed_at", contractNullable(contractTime)),
	),
	contractDetailMeta(contractReq("coverage", contractArr(contractCoverageNote))),
)

// GET /external-principals/:id/referenced-by (§5.3; D-77 list envelope).
var contractReferencedBy = contractList(
	contractClaimRow(
		contractReq("target", contractIdentityBrief),
		contractReq("mechanism", contractMechanism),
		contractReq("statement", contractTrustStatement),
		contractReq("conditions", contractAnyValue),
	),
	contractListMeta(),
)

/* -------------------------------- resources -------------------------------- */

// The resource list row (§5.3 l.5939-5941; D-16 type, D-17 counts).
var contractResourceRow = contractObj(
	contractReq("ref", contractRef("resource")),
	contractReq("text", contractNonEmpty),
	contractReq("kind", contractResourceKind),
	contractReq("type", contractNonEmpty),
	contractReq("service", contractNullable(contractNonEmpty)),
	contractReq("account", contractNullable(contractAccount)),
	contractReq("region", contractNullable(contractNonEmpty)),
	contractReq("named_by_count", contractExact),
	contractReq("excluded_by_count", contractExact),
	contractReq("lifecycle", contractLifecycle),
	contractOpt("retired_reason", contractNonEmpty),
	contractReq("state", contractNodeState),
	contractOpt("stale_reason", contractStaleReason),
	contractReq("last_confirmed_at", contractNullable(contractTime)),
)

// GET /resources/:id (§5.3 l.5943-5946; D-19 resource_policy).
var contractResourceDetail = contractDetail(
	contractExtend(contractResourceRow,
		contractReq("retired_reason", contractNullable(contractNonEmpty)), // details: always stated
		contractReq("existence", contractConst("not_verified")),
		contractReq("resource_policy", contractObj(
			contractReq("read", contractBool),
			contractReq("has_deny", contractNullable(contractBool)),
		)),
		contractReq("sources", contractArrMin(1, contractSource)),
	),
	contractDetailMeta(contractReq("coverage", contractArr(contractCoverageNote))),
)

// A restriction statement of the Access tab (excluded_by, deny_statements_naming).
var contractRestrictionStatement = contractObj(
	contractReq("policy", contractPolicyBrief),
	contractReq("statement", contractStatementBrief),
	contractReq("holders", contractArr(contractRef("identity"))),
	contractReq("holders_more", contractBool),
)

// A claim as an Access row names it: the claim, its state, since when.
func contractAccessClaim(typ string) contractShape {
	return contractObj(
		contractReq("claim", contractRef(typ)),
		contractReq("state", contractEdgeState),
		contractReq("valid_from", contractTime),
	)
}

// GET /resources/:id/access (§5.3 l.5948-5954; D-18 via groups, D-77).
var contractResourceAccess = contractObj(
	contractReq("data", contractObj(
		contractReq("access", contractArr(contractObj(
			contractReq("holder", contractIdentityBrief),
			// D-18: a member's row through a group names the group and the
			// membership the grant reaches the member by.
			contractReq("via_group", contractNullable(contractObj(
				contractReq("ref", contractRef("identity")),
				contractReq("name", contractNonEmpty),
				contractReq("membership", contractAccessClaim("relationship")),
			))),
			contractReq("policy", contractPolicyBrief),
			contractReq("statement", contractStatementBrief),
			contractReq("grant", contractAccessClaim("grant")),
			contractReq("state", contractEdgeState),
		))),
		contractReq("excluded_by", contractArr(contractRestrictionStatement)),
		contractReq("excluded_by_more", contractBool),
		contractReq("deny_statements_naming", contractArr(contractRestrictionStatement)),
		contractReq("deny_statements_naming_more", contractBool),
	)),
	contractReq("meta", contractListMeta()),
)

/* ---------------------------------- graph ---------------------------------- */

var contractRestrictions = contractObj(
	contractReq("deny_statements", contractInt),
	contractReq("permissions_boundary", contractBool),
)

// A graph node (§5.3 l.5967-5973), by kind.
var contractGraphNode = contractFunc(func(path string, v any, errs *[]string) {
	m, _ := v.(map[string]any)
	ref, _ := m["ref"].(string)
	typ, _, _ := strings.Cut(ref, ":")
	common := []contractField{
		contractReq("ref", contractRef(typ)),
		contractReq("label", contractNonEmpty),
		contractReq("state", contractNodeState),
		contractReq("lifecycle", contractLifecycle),
		contractReq("last_confirmed_at", contractNullable(contractTime)),
		contractOpt("stale_reason", contractStaleReason),
		contractReq("limitations", contractLimitations),
	}
	var more []contractField
	switch typ {
	case "workload":
		more = []contractField{contractReq("kind", contractConst("workload")), contractReq("account", contractAccount),
			contractReq("arn", contractNonEmpty), contractReq("runtime_kind", contractRuntimeKind)}
	case "identity":
		more = []contractField{contractReq("kind", contractIdentityKind), contractReq("account", contractAccount),
			contractReq("arn", contractNonEmpty), contractReq("restrictions", contractRestrictions),
			contractReq("used_by_count", contractExact)}
	case "statement":
		// No account: statements have none (D-36).
		more = []contractField{contractReq("kind", contractConst("statement")), contractReq("policy", contractNonEmpty),
			contractReq("policy_ref", contractRef("policy")), contractReq("effect", contractEnum("allow", "deny")),
			contractReq("sid", contractStr), contractReq("index", contractInt), contractReq("group_key", contractNonEmpty),
			contractReq("exclusions", contractArr(contractExclusion))}
	case "resource":
		more = []contractField{contractReq("kind", contractResourceKind), contractReq("account", contractNullable(contractAccount)),
			contractReq("text", contractNonEmpty), contractReq("type", contractNonEmpty)}
	case "external_principal":
		more = []contractField{contractReq("kind", contractConst("external_principal")),
			contractReq("account", contractNullable(contractAccount)), contractReq("mechanism", contractExternalKind),
			contractReq("issuer", contractNonEmpty), contractReq("subject", contractNonEmpty),
			contractOpt("resolution", contractResolution)}
	default:
		contractFail(errs, path, "node type %q is not a traversal node (§5.4)", typ)
		return
	}
	contractObj(append(common, more...)...).check(path, v, errs)
})

// A graph edge (§5.3 l.5974-5978; §5.4 closes_cycle, crosses_account; D-35).
var contractGraphEdge = contractFunc(func(path string, v any, errs *[]string) {
	m, _ := v.(map[string]any)
	kind, _ := m["kind"].(string)
	claimType := "relationship"
	var more []contractField
	switch kind {
	case "executes_as", "task_execution_role", "member_of":
	case "can_assume":
		more = append(more, contractReq("mechanism", contractMechanism))
	case "grant":
		claimType = "grant"
		more = append(more, contractReq("policy", contractNonEmpty))
	case "target":
		claimType = "target"
		more = append(more, contractReq("mode", contractConst("resource")))
	default:
		contractFail(errs, path, "edge kind %q is not a §5.4 edge", kind)
		return
	}
	contractObj(append([]contractField{
		contractReq("claim", contractRef(claimType)),
		contractReq("kind", contractConst(kind)),
		contractReq("from", contractRef("workload", "identity", "external_principal", "statement", "resource")),
		contractReq("to", contractRef("identity", "statement", "resource")),
		contractReq("state", contractEdgeState),
		contractReq("basis", contractBasis),
		contractReq("closes_cycle", contractBool),
		contractReq("crosses_account", contractBool),
		contractReq("last_confirmed_at", contractNullable(contractTime)),
		contractOpt("stale_reason", contractStaleReason),
		contractReq("limitations", contractLimitations),
	}, more...)...).check(path, v, errs)
})

var contractFrontier = contractAll(contractObj(
	contractReq("node", contractRef("workload", "identity", "external_principal", "statement", "resource")),
	contractReq("edge", contractRelTypeOrGraph),
	contractReq("direction", contractEnum("forward", "reverse")),
	contractReq("more", contractFunc(func(path string, v any, errs *[]string) {
		contractObj(contractReq("count", contractNullable(contractInt)), contractReq("exact", contractBool)).check(path, v, errs)
		// §5.4: exact only when counted; an uncounted more is {null, false}.
		if m, ok := v.(map[string]any); ok && (m["count"] == nil) != (m["exact"] == false) {
			contractFail(errs, path, "want {count: n, exact: true} or {count: null, exact: false}, got %s", contractJSON(v))
		}
	})),
	contractReq("expand", contractStr),
), contractFunc(func(path string, v any, errs *[]string) {
	// §5.3's example, character for character: the call that expands THIS
	// entry -- its node, edge and direction, the ref's colon unescaped --
	// carrying the request's include_ended when it asked for ended claims
	// (D-12), so the expansion shows what the canvas shows.
	want := "/api/iga/v1/graph/expand?node=" + digs(v, "node") + "&edge=" + digs(v, "edge") + "&direction=" + digs(v, "direction")
	if got := digs(v, "expand"); got != want && got != want+contractIncludeEnded {
		contractFail(errs, path+".expand", "want %q, got %q", want, got)
	}
}))

// contractIncludeEnded is the suffix a frontier's expand call carries when the
// request asked for ended claims.
const contractIncludeEnded = "&include_ended=true"

var contractRelTypeOrGraph = contractEnum("executes_as", "task_execution_role", "member_of", "can_assume", "grant", "target")

// truncated.bound_by: §5.4's four budgets and nothing else -- a resolution in
// force the walk shows but does not follow is not a budget, and /graph says it
// in its additive resolution_not_followed (D-105, superseding D-101's /graph
// half).
var contractTruncated = contractNullable(contractObj(contractReq("bound_by",
	contractEnum("nodes", "edges", "assume_hops", "time"))))

// The graph routes' meta (§5.3 l.5983; D-35 meta limitations).
var contractGraphMeta = contractDetailMeta(
	contractReq("budgets", contractObj(
		contractReq("nodes", contractConst(500)), contractReq("edges", contractConst(2000)),
		contractReq("assume_hops", contractConst(4)), contractReq("timeout_ms", contractConst(3000)),
		contractReq("neighbours_per_page", contractConst(100)), contractReq("paths", contractConst(200)),
	)),
	contractReq("limitations", contractConst([]any{
		map[string]any{"code": "effective_access_not_evaluated"},
		map[string]any{"code": "organizations_not_collected"},
	})),
)

// GET /graph (§5.3).
var contractGraph = contractDetail(contractObj(
	contractReq("root", contractRef("workload", "identity", "external_principal", "statement", "resource")),
	contractReq("nodes", contractArrMin(1, contractGraphNode)),
	contractReq("edges", contractArr(contractGraphEdge)),
	contractReq("frontier", contractArr(contractFrontier)),
	contractReq("truncated", contractTruncated),
	// Additive (D-105): true, false, or null when the time budget bound first.
	contractReq("resolution_not_followed", contractNullable(contractBool)),
), contractGraphMeta)

// GET /graph/expand (D-35).
var contractGraphExpand = contractDetail(contractObj(
	contractReq("nodes", contractArr(contractGraphNode)),
	contractReq("edges", contractArr(contractGraphEdge)),
	contractReq("frontier", contractArr(contractFrontier)),
	contractReq("truncated", contractTruncated),
	contractReq("next_cursor", contractNullable(contractNonEmpty)),
), contractGraphMeta)

// GET /graph/path (§5.4 outcomes; D-35 shape).
var contractGraphPath = contractDetail(contractObj(
	contractReq("from", contractRef("workload", "identity", "external_principal", "statement", "resource")),
	contractReq("to", contractRef("workload", "identity", "external_principal", "statement", "resource")),
	// The orientation the paths run in; null when none was found (the
	// route's additive field, graph_path.go).
	contractReq("direction", contractNullable(contractEnum("forward", "reverse"))),
	contractReq("outcome", contractEnum("found", "none_exists", "not_found_within_budget")),
	contractReq("paths", contractArr(contractObj(
		contractReq("nodes", contractArrMin(2, contractGraphNode)),
		contractReq("edges", contractArrMin(1, contractGraphEdge)),
		contractReq("limitations", contractLimitations),
	))),
	contractReq("more_paths", contractBool),
	// §5.4's budgets, plus the path budget and D-101's resolution_not_followed.
	contractReq("bound_by", contractNullable(contractEnum("nodes", "edges", "assume_hops", "time", "paths", "resolution_not_followed"))),
), contractGraphMeta)

/* --------------------------------- evidence -------------------------------- */

var contractEvidenceFact = contractObj(
	contractReq("source_api", contractNonEmpty),
	contractReq("account_id", contractAccountID),
	contractReq("region", contractNullable(contractNonEmpty)),
	contractReq("observed_in_run", contractRef("cloud_scan_run")),
	contractReq("last_confirmed_at", contractTime),
	contractReq("fact", contractNonEmpty),
	contractOpt("policy_version", contractNullable(contractStr)),
	contractOpt("statement_excerpt", contractAnyValue),
	contractOpt("policy", contractPolicyBrief),
	contractOpt("statement", contractObj(contractReq("ref", contractRef("statement")),
		contractReq("sid", contractStr), contractReq("index", contractNullable(contractInt)))),
)

// One claim's evidence (§5.3 Evidence; D-80 freshness and raw).
var contractEvidenceData = contractObj(
	contractReq("claim", contractObj(
		contractReq("ref", contractFunc(func(path string, v any, errs *[]string) {
			if s, _ := v.(string); strings.HasPrefix(s, "coverage:") {
				contractCoverageRef.check(path, v, errs)
				return
			}
			contractRef("workload", "identity", "external_principal", "resource", "policy", "statement",
				"relationship", "assignment", "grant", "target", "presence").check(path, v, errs)
		})),
		contractReq("sentence", contractNonEmpty),
	)),
	contractReq("status", contractObj(
		contractReq("basis", contractNullable(contractBasis)),
		contractReq("lifecycle", contractEdgeState),
		contractReq("collection", contractEnum("complete", "partial", "stale")),
		contractReq("effective_access", contractConst("not_evaluated")), // D-20
	)),
	contractReq("facts", contractArr(contractEvidenceFact)),
	contractReq("freshness", contractObj(
		contractReq("first_seen_at", contractNullable(contractTime)),
		contractReq("last_confirmed_at", contractNullable(contractTime)),
		contractReq("stale_since", contractNullable(contractTime)),
		contractReq("valid_to", contractNullable(contractTime)),
		contractReq("ended_reason", contractNullable(contractNonEmpty)),
	)),
	contractReq("limitations", contractArrMin(1, contractLimitation)),
	contractReq("raw", contractNullable(contractArr(contractObj(
		contractReq("observation", contractNonEmpty),
		contractReq("source_api", contractNonEmpty),
		contractReq("sanitized_facts", contractAnyValue),
	)))),
)

var contractEvidence = contractDetail(contractEvidenceData, contractDetailMeta())

// Several claims (D-79): data in request order, and the summary sentence.
var contractEvidenceMany = contractDetail(contractArrMin(2, contractEvidenceData), contractDetailMeta(
	contractReq("summary", contractNullable(contractObj(contractReq("sentence", contractNonEmpty)))),
))

/* ------------------------ lookup, pipeline, coverage ----------------------- */

// GET /lookup (D-81).
var contractLookup = contractDetail(contractObj(
	contractReq("ref", contractRef("identity", "workload")),
	contractReq("lifecycle", contractLifecycle),
), contractDetailMeta())

// GET /capabilities (§5.3 example; D-11).
var contractCapabilities = contractObj(contractReq("data", contractObj(
	contractReq("graph_projection", contractEnum("on", "off", "misconfigured")),
	contractReq("reason", contractNullable(contractNonEmpty)),
	contractReq("features", contractObj(
		contractReq("workloads", contractBool), contractReq("identities", contractBool),
		contractReq("resources", contractBool), contractReq("graph", contractBool),
		contractReq("evidence", contractBool), contractReq("changes", contractBool),
		contractReq("classification", contractBool), contractReq("coverage", contractBool),
	)),
	contractReq("schema_head", contractNullable(contractNonEmpty)),
)))

var contractRunRef = contractRef("cloud_scan_run")

// latest_run (§5.3 /pipeline example; D-55 queued_at, D-91 finished_at, D-92
// waiting_on and error): its times by status.
var contractLatestRun = contractFunc(func(path string, v any, errs *[]string) {
	m, _ := v.(map[string]any)
	status, _ := m["status"].(string)
	fields := []contractField{contractReq("ref", contractRunRef), contractReq("status", contractConst(status))}
	switch status {
	case "queued":
		fields = append(fields, contractReq("queued_at", contractTime), contractReq("waiting_on", contractNullable(contractRunRef)))
	case "running":
		fields = append(fields, contractReq("started_at", contractNullable(contractTime)))
	case "published":
		fields = append(fields, contractReq("started_at", contractNullable(contractTime)),
			contractReq("published_at", contractNullable(contractTime)))
	case "failed", "abandoned":
		fields = append(fields, contractReq("started_at", contractNullable(contractTime)),
			contractReq("finished_at", contractTime), contractReq("error", contractNullable(contractStr)))
	default:
		contractFail(errs, path, "latest_run.status %q", status)
		return
	}
	contractObj(fields...).check(path, v, errs)
})

// GET /pipeline (§5.3 example; D-55, D-56, D-59, D-92).
var contractPipeline = contractDetail(contractObj(
	contractReq("barrier", contractObj(
		contractReq("state", contractEnum("idle", "collecting", "projecting")),
		contractReq("scan_run", contractNullable(contractRunRef)),
		contractReq("since", contractNullable(contractTime)),
		contractReq("integration", contractNullable(contractRef("cloud_connector"))),
		contractReq("account_id", contractNullable(contractAccountID)),
		contractReq("label", contractNullable(contractNonEmpty)),
		contractReq("started_at", contractNullable(contractTime)),
	)),
	contractReq("accounts", contractArrMin(1, contractObj(
		contractReq("integration", contractRef("cloud_connector")),
		contractReq("account_id", contractAccountID),
		contractReq("label", contractNonEmpty),
		contractReq("connector_status", contractEnum("active", "error", "revoked")),
		contractReq("state", contractNonEmpty),
		contractReq("latest_run", contractNullable(contractLatestRun)),
		contractReq("projection", contractNullable(contractObj(
			contractReq("status", contractNonEmpty),
			contractReq("rev", contractNullable(contractInt)),
			contractReq("attempts", contractInt),
			contractReq("last_error", contractNullable(contractStr)),
			contractReq("retrying", contractBool),
		))),
		contractReq("last_published_rev", contractNullable(contractInt)),
	))),
	contractReq("current_rev", contractNullable(contractInt)),
	contractReq("current_published_at", contractNullable(contractTime)),
), contractDetailMeta())

// One surface of GET /coverage (§5.3 l.5790-5794; D-58, D-71, D-72).
var contractCoverageSurface = contractObj(
	contractReq("surface", contractNonEmpty),
	contractReq("state", contractSurfaceState),
	contractReq("count", contractNullable(contractInt)),
	contractReq("error_code", contractNullable(contractNonEmpty)),
	contractReq("api", contractNullable(contractNonEmpty)),
	contractReq("error", contractNullable(contractStr)),
	contractReq("since", contractNullable(contractTime)),
	contractReq("since_run", contractNullable(contractRunRef)),
	contractReq("prevents", contractNullable(contractEnum("surface_stale", "surface_partial", "surface_denied", "organizations_not_collected"))),
	contractReq("run", contractRunRef),
	contractReq("ref", contractCoverageRef),
	contractReq("fix", contractNullable(contractNonEmpty)),
	contractReq("items", contractNullable(contractArr(contractObj(
		contractReq("policy", contractNonEmpty), contractReq("version", contractStr), contractReq("error", contractNonEmpty))))),
	contractReq("truncated", contractBool),
)

var contractCoverage = contractDetail(contractArr(contractObj(
	contractReq("account", contractAccount),
	contractReq("integration", contractRef("cloud_connector")),
	contractReq("connector_status", contractEnum("active", "error", "revoked")),
	contractReq("runs", contractArrMin(1, contractRunRef)),
	contractReq("surfaces", contractArrMin(1, contractCoverageSurface)),
	contractReq("template", contractObj(
		contractReq("deployed", contractNullable(contractNonEmpty)),
		contractReq("current", contractNonEmpty),
		contractReq("outdated", contractNullable(contractBool)),
	)),
)), contractDetailMeta())

/* ---------------------------------- errors --------------------------------- */

// contractError is the §5.2 error envelope for one code, with the code's own
// fields (§5.1 revision_stale, §5.5 classification_conflict, D-9 ...).
func contractError(code string, extra ...contractField) contractShape {
	return contractObj(contractReq("error", contractObj(append([]contractField{
		contractReq("code", contractConst(code)),
		contractReq("message", contractNonEmpty),
	}, extra...)...)))
}

// §5.1's revision_stale payload, exactly.
func contractRevisionStale(requested, current int64) contractShape {
	return contractError("revision_stale",
		contractReq("requested_rev", contractConst(requested)),
		contractReq("current_rev", contractConst(current)),
		contractReq("current_published_at", contractTime))
}
