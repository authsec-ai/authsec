package services

import (
	"net/http"
	"strings"
)

// Governance tiers (SPEC-secops-backend-upgrade.md P3, W5): one static map
// from every write action of the agent runtime, governance, audit, history,
// evidence, identity, classification and gateway surfaces to its tier, and
// from every write route of those surfaces to its action. The tier guard
// (controllers/platform/governance_tier_guard.go) reads it on every request
// of those surfaces; a write route missing from it is refused (fail closed),
// and controllers/platform/governance_tiers_test.go walks the mounted routes
// and fails when one is missing.
//
//	tier 0  read, raise a classification, close a case or resolve an alert with
//	        an outcome, export one case, write a note. The route's right as
//	        today (governance:read, discovery:read, or more).
//	tier 1  contain (stop), open/assign cases, ask, routine configuration.
//	        The route's right as today (governance:author / enforce, ...).
//	tier 2  side effects on the customer beyond a stop (a wider stop:
//	        identity-level containment; suspending an operator). A person
//	        (never an automation identity) with the route's right
//	        (governance:enforce or governance:emergency as today).
//	tier 3  loosening: release a hold, change or disable a detection rule,
//	        suppress, lower a classification or risk class, declare a coverage
//	        gap, loosen a gateway's fail mode, bulk export, shorten audit
//	        retention, lift a suspension -- and every decision on such a
//	        request (approve, reject, review). A second person (second_person.go).
//	tier 4  remediation writes to the customer's cloud: governance:remediate.
//
// An automation identity (middlewares.IsAutomationIdentity) may perform
// tier-0 and tier-1 actions only.
//
// LoosensTo marks an action whose tier depends on its direction: tightening
// (or no change) is its Tier, loosening is LoosensTo. The route stays open to
// the lower tier; the service decides the direction and applies the
// second-person rule (CheckTier3Requester, BreakGlassAllowed) when it loosens.

// GovTier is an action's tier (0..4).
type GovTier int

// The tiers.
const (
	GovTier0 GovTier = 0
	GovTier1 GovTier = 1
	GovTier2 GovTier = 2
	GovTier3 GovTier = 3
	GovTier4 GovTier = 4
)

// GovAction is one action's tier.
type GovAction struct {
	Tier      GovTier `json:"tier"`
	LoosensTo GovTier `json:"loosens_to,omitempty"`
}

// Tier helpers for the table below.
var (
	gt0  = GovAction{Tier: GovTier0}
	gt1  = GovAction{Tier: GovTier1}
	gt2  = GovAction{Tier: GovTier2}
	gt3  = GovAction{Tier: GovTier3}
	gt4  = GovAction{Tier: GovTier4}
	gt03 = GovAction{Tier: GovTier0, LoosensTo: GovTier3}
	gt13 = GovAction{Tier: GovTier1, LoosensTo: GovTier3}
)

// Actions named outside the route table (a handler calls RequireTier for
// them itself).
const (
	GovActionContainIdentity  = "agent_containment.create_identity"
	GovActionRemediationApply = "remediation.apply"
)

// govActions is the action -> tier map.
var govActions = map[string]GovAction{
	// Agent runtime: suggested agents, containment.
	"agent_runtime.suggestion.confirm": gt1,
	"agent_runtime.suggestion.dismiss": gt1,
	"agent_containment.preview":        gt0, // a read with a body
	"agent_containment.create":         gt1,
	GovActionContainIdentity:           gt2, // stops every workload on the role and revokes its sessions
	// DECISION (W5): releasing a containment is tier 1 as today. Releasing a
	// case's hold on a stop is tier 3 and is W2's (agent_containment_hold).
	"agent_containment.release": gt1,

	// Alerts, detection rules, suppressions, SIEM delivery.
	"agent_alert.acknowledge":          gt1,
	"agent_alert.resolve":              gt0, // close with an outcome
	"agent_alert.reopen":               gt1,
	"agent_alert.rules.change":         gt13,
	"agent_alert.rules.approve":        gt3,
	"agent_alert.rules.reject":         gt3,
	"agent_alert.suppression.request":  gt3,
	"agent_alert.suppression.renew":    gt3,
	"agent_alert.suppression.approve":  gt3,
	"agent_alert.suppression.reject":   gt3,
	"agent_alert.suppression.end":      gt1, // tightens
	"agent_alert.siem_endpoint.create": gt1,
	"agent_alert.siem_endpoint.delete": gt1,
	"agent_alert.siem_endpoint.test":   gt1,

	// Cases.
	"agent_case.open":           gt1,
	"agent_case.assign":         gt1,
	"agent_case.note":           gt0,
	"agent_case.split":          gt1,
	"agent_case.alerts.move":    gt1,
	"agent_case.severity.raise": gt0,
	"agent_case.close":          gt0,
	"agent_case.reopen":         gt1,
	"agent_case.export":         gt0, // one case

	// Model providers, activity, gateways.
	"model_provider.connect":             gt1,
	"model_provider.rotate":              gt1,
	"model_provider.revoke":              gt1,
	"model_provider.sync":                gt1,
	"agent_activity.settings.change":     gt1,
	"agent_activity.otlp_token.create":   gt1,
	"agent_activity.otlp_token.revoke":   gt1,
	"agent_gateway.create":               gt1,
	"agent_gateway.rename":               gt1,
	"agent_gateway.rotate":               gt1,
	"agent_gateway.revoke":               gt1,
	"agent_gateway.runtime.change":       gt13, // fail mode / cache cap (F5)
	"agent_gateway.settings.change":      gt1,
	"agent_gateway.tool_policy.create":   gt1,
	"agent_gateway.tool_policy.update":   gt1,
	"agent_gateway.tool_policy.delete":   gt1,
	"agent_gateway.tool_policy.evaluate": gt0, // a read with a body

	// Pending changes (F5) and the approvals inbox.
	"pending_change.approve": gt3,
	"pending_change.reject":  gt3,
	"approvals.review":       gt3,

	// Evidence and coverage (W1).
	"agent_evidence.retention.change":    gt1,
	"agent_evidence.backfill.request":    gt1,
	"agent_evidence.azure_ingest.create": gt1,
	"agent_evidence.azure_ingest.revoke": gt1,
	"coverage.gap.declare":               gt3,
	"coverage.declaration.approve":       gt3,
	"coverage.declaration.reject":        gt3,
	"coverage.declaration.review":        gt3,

	// Agent identity, classification, responder groups (W7).
	"agent_identity.retire":          gt1,
	"agent_identity.merge":           gt1,
	"agent_identity.transfer":        gt1,
	"agent_identity.not_an_agent":    gt1,
	"agent_identity.purpose.set":     gt1,
	"agent_identity.risk_class.set":  gt03,
	"agent_identity.deployer.record": gt1,
	"agent_change.approve":           gt3,
	"agent_change.reject":            gt3,
	"agent_change.withdraw":          gt1,
	"resource_classification.set":    gt03,
	"responder_group.create":         gt1,
	"responder_group.update":         gt1,
	"responder_group.delete":         gt1,
	"responder_group.member.add":     gt1,
	"responder_group.member.remove":  gt1,
	"responder_group.accept":         gt1,
	"responder_group.delegate":       gt1,
	"responder_group.scope.add":      gt1,
	"responder_group.scope.remove":   gt1,
	"responder_group.handover":       gt1,

	// History (W9).
	"history.hold.place":        gt1, // keeps more
	"history.hold.release":      gt3,
	"history.snapshot.redact":   gt3,
	"history.export.bulk":       gt3,
	"history_approval.approve":  gt3,
	"history_approval.reject":   gt3,
	"history_approval.withdraw": gt1,
	"history_approval.review":   gt3,

	// Audit governance and operators (F7 / P18).
	"audit.retention.change":   gt13,
	"audit.legal_hold.place":   gt1,
	"audit.legal_hold.release": gt3,
	"audit.change.approve":     gt3,
	"audit.change.reject":      gt3,
	"audit.change.review":      gt3,
	"operator.suspend":         gt2,
	"operator.unsuspend":       gt3,

	// Containment holds, probes and narrowing (W2). Releasing a case's hold
	// loosens the stop: tier 3 with a second person (release requests).
	"agent_containment.hold.add":               gt1,
	"agent_containment.hold.release":           gt3,
	"agent_containment.release_request.decide": gt3,
	"agent_containment.release_request.review": gt3,
	"agent_containment.probe":                  gt1,
	"agent_containment.narrow":                 gt1,

	// Asks (W4): a person answers (never an automation identity); loosening
	// the due-time policy is tier 3.
	"agent_ask.create":         gt1,
	"agent_ask.answer":         gt2,
	"agent_ask.confirm":        gt2,
	"agent_ask.not_mine":       gt2,
	"agent_ask.withdraw":       gt1,
	"agent_ask.policy.change":  gt13,
	"agent_case.ticket.create": gt1,
	"integration.ask.set":      gt1,
	"integration.ask.delete":   gt1,

	// Gateway keys, holds and joins (W6). Deciding a held call is a decision
	// (a person, the hold's named approver).
	"agent_gateway.provider_key.add":    gt1,
	"agent_gateway.provider_key.rotate": gt1,
	"agent_gateway.provider_key.delete": gt1,
	"agent_gateway.agent_key.issue":     gt1,
	"agent_gateway.agent_key.rotate":    gt1,
	"agent_gateway.agent_key.delete":    gt1,
	"agent_gateway.hold.decide":         gt3,
	"agent_join.settings.change":        gt1,

	// Remediation (W8): preparing, binding and cancelling change nothing in
	// the customer's cloud; applying writes to it.
	"remediation.prepare":        gt1,
	"remediation.cancel":         gt1,
	"remediation.binding.set":    gt1,
	"remediation.binding.verify": gt1,
	"remediation.binding.revoke": gt1,
	GovActionRemediationApply:    gt4,
}

const (
	igaV1 = "/api/iga/v1"
	arV1  = igaV1 + "/agent-runtime"
)

// govRouteActions maps "METHOD fullpath" (gin's route path) of every write
// route of the tiered surfaces to its action.
var govRouteActions = map[string]string{
	"POST " + arV1 + "/suggestions/:id/confirm":  "agent_runtime.suggestion.confirm",
	"POST " + arV1 + "/suggestions/:id/dismiss":  "agent_runtime.suggestion.dismiss",
	"POST " + arV1 + "/containments/preview":     "agent_containment.preview",
	"POST " + arV1 + "/containments":             "agent_containment.create",
	"POST " + arV1 + "/containments/:id/release": "agent_containment.release",

	"POST " + arV1 + "/alerts/:id/acknowledge":              "agent_alert.acknowledge",
	"POST " + arV1 + "/alerts/:id/resolve":                  "agent_alert.resolve",
	"POST " + arV1 + "/alerts/:id/reopen":                   "agent_alert.reopen",
	"PUT " + arV1 + "/alert-settings":                       "agent_alert.rules.change",
	"POST " + arV1 + "/alert-settings/versions/:id/approve": "agent_alert.rules.approve",
	"POST " + arV1 + "/alert-settings/versions/:id/reject":  "agent_alert.rules.reject",
	"POST " + arV1 + "/suppressions":                        "agent_alert.suppression.request",
	"POST " + arV1 + "/suppressions/:id/approve":            "agent_alert.suppression.approve",
	"POST " + arV1 + "/suppressions/:id/reject":             "agent_alert.suppression.reject",
	"POST " + arV1 + "/suppressions/:id/renew":              "agent_alert.suppression.renew",
	"POST " + arV1 + "/suppressions/:id/end":                "agent_alert.suppression.end",
	"POST " + arV1 + "/siem-endpoints":                      "agent_alert.siem_endpoint.create",
	"DELETE " + arV1 + "/siem-endpoints/:id":                "agent_alert.siem_endpoint.delete",
	"POST " + arV1 + "/siem-endpoints/:id/test":             "agent_alert.siem_endpoint.test",

	"POST " + arV1 + "/cases":              "agent_case.open",
	"POST " + arV1 + "/cases/:id/assign":   "agent_case.assign",
	"POST " + arV1 + "/cases/:id/notes":    "agent_case.note",
	"POST " + arV1 + "/cases/:id/split":    "agent_case.split",
	"POST " + arV1 + "/cases/:id/alerts":   "agent_case.alerts.move",
	"POST " + arV1 + "/cases/:id/severity": "agent_case.severity.raise",
	"POST " + arV1 + "/cases/:id/close":    "agent_case.close",
	"POST " + arV1 + "/cases/:id/reopen":   "agent_case.reopen",
	"POST " + arV1 + "/cases/:id/export":   "agent_case.export",

	"POST " + arV1 + "/model-providers":            "model_provider.connect",
	"POST " + arV1 + "/model-providers/:id/rotate": "model_provider.rotate",
	"DELETE " + arV1 + "/model-providers/:id":      "model_provider.revoke",
	"POST " + arV1 + "/model-providers/:id/sync":   "model_provider.sync",

	"PUT " + arV1 + "/activity/settings":  "agent_activity.settings.change",
	"POST " + arV1 + "/otlp-tokens":       "agent_activity.otlp_token.create",
	"DELETE " + arV1 + "/otlp-tokens/:id": "agent_activity.otlp_token.revoke",

	"POST " + arV1 + "/gateways":               "agent_gateway.create",
	"PATCH " + arV1 + "/gateways/:id":          "agent_gateway.rename",
	"POST " + arV1 + "/gateways/:id/rotate":    "agent_gateway.rotate",
	"DELETE " + arV1 + "/gateways/:id":         "agent_gateway.revoke",
	"PUT " + arV1 + "/gateways/:id/runtime":    "agent_gateway.runtime.change",
	"PUT " + arV1 + "/gateway-settings":        "agent_gateway.settings.change",
	"POST " + arV1 + "/tool-policies":          "agent_gateway.tool_policy.create",
	"POST " + arV1 + "/tool-policies/evaluate": "agent_gateway.tool_policy.evaluate",
	"PUT " + arV1 + "/tool-policies/:id":       "agent_gateway.tool_policy.update",
	"DELETE " + arV1 + "/tool-policies/:id":    "agent_gateway.tool_policy.delete",

	"POST " + igaV1 + "/pending-changes/:id/approve": "pending_change.approve",
	"POST " + igaV1 + "/pending-changes/:id/reject":  "pending_change.reject",
	"POST " + igaV1 + "/approvals/reviews/:kind/:id": "approvals.review",

	"PUT " + arV1 + "/evidence/retention":                  "agent_evidence.retention.change",
	"POST " + arV1 + "/backfill":                           "agent_evidence.backfill.request",
	"POST " + arV1 + "/azure/connectors/:id/ingest":        "agent_evidence.azure_ingest.create",
	"DELETE " + arV1 + "/azure/connectors/:id/ingest":      "agent_evidence.azure_ingest.revoke",
	"PUT " + igaV1 + "/coverage/capabilities/:id/declare":  "coverage.gap.declare",
	"POST " + igaV1 + "/coverage/declarations/:id/approve": "coverage.declaration.approve",
	"POST " + igaV1 + "/coverage/declarations/:id/reject":  "coverage.declaration.reject",
	"POST " + igaV1 + "/coverage/declarations/:id/review":  "coverage.declaration.review",

	"POST " + igaV1 + "/agent-identities/:id/retire":             "agent_identity.retire",
	"POST " + igaV1 + "/agent-identities/:id/merge":              "agent_identity.merge",
	"POST " + igaV1 + "/agent-identities/:id/transfer":           "agent_identity.transfer",
	"POST " + igaV1 + "/agent-identities/:id/not-an-agent":       "agent_identity.not_an_agent",
	"PUT " + igaV1 + "/agent-identities/:id/purpose":             "agent_identity.purpose.set",
	"PUT " + igaV1 + "/agent-identities/:id/risk-class":          "agent_identity.risk_class.set",
	"POST " + igaV1 + "/agent-identities/:id/deployers":          "agent_identity.deployer.record",
	"POST " + igaV1 + "/agent-changes/:id/approve":               "agent_change.approve",
	"POST " + igaV1 + "/agent-changes/:id/reject":                "agent_change.reject",
	"POST " + igaV1 + "/agent-changes/:id/withdraw":              "agent_change.withdraw",
	"PUT " + igaV1 + "/resources/:id/classification":             "resource_classification.set",
	"POST " + igaV1 + "/responder-groups":                        "responder_group.create",
	"PATCH " + igaV1 + "/responder-groups/:id":                   "responder_group.update",
	"DELETE " + igaV1 + "/responder-groups/:id":                  "responder_group.delete",
	"POST " + igaV1 + "/responder-groups/:id/members":            "responder_group.member.add",
	"DELETE " + igaV1 + "/responder-groups/:id/members/:user_id": "responder_group.member.remove",
	"POST " + igaV1 + "/responder-groups/:id/accept":             "responder_group.accept",
	"POST " + igaV1 + "/responder-groups/:id/delegate":           "responder_group.delegate",
	"POST " + igaV1 + "/responder-groups/:id/scopes":             "responder_group.scope.add",
	"DELETE " + igaV1 + "/responder-groups/:id/scopes/:scope_id": "responder_group.scope.remove",
	"POST " + igaV1 + "/responder-groups/:id/handover":           "responder_group.handover",

	"POST " + igaV1 + "/snapshots/hold":                 "history.hold.place",
	"POST " + igaV1 + "/snapshots/holds":                "history.hold.place",
	"POST " + igaV1 + "/snapshots/holds/:id/release":    "history.hold.release",
	"POST " + igaV1 + "/snapshots/:id/redact":           "history.snapshot.redact",
	"POST " + igaV1 + "/exports":                        "history.export.bulk",
	"POST " + igaV1 + "/history-approvals/:id/approve":  "history_approval.approve",
	"POST " + igaV1 + "/history-approvals/:id/reject":   "history_approval.reject",
	"POST " + igaV1 + "/history-approvals/:id/withdraw": "history_approval.withdraw",
	"POST " + igaV1 + "/history-approvals/:id/review":   "history_approval.review",

	"PUT " + igaV1 + "/audit/retention":                "audit.retention.change",
	"POST " + igaV1 + "/audit/legal-holds":             "audit.legal_hold.place",
	"POST " + igaV1 + "/audit/legal-holds/:id/release": "audit.legal_hold.release",
	"POST " + igaV1 + "/audit/changes/:id/approve":     "audit.change.approve",
	"POST " + igaV1 + "/audit/changes/:id/reject":      "audit.change.reject",
	"POST " + igaV1 + "/audit/changes/:id/review":      "audit.change.review",
	"POST /authsec/admin/operators/:id/suspend":        "operator.suspend",
	"POST /authsec/admin/operators/:id/unsuspend":      "operator.unsuspend",

	"POST " + arV1 + "/containments/:id/holds":                         "agent_containment.hold.add",
	"POST " + arV1 + "/containments/:id/holds/:case/release":           "agent_containment.hold.release",
	"POST " + arV1 + "/containments/:id/release-requests/:rid/approve": "agent_containment.release_request.decide",
	"POST " + arV1 + "/containments/:id/release-requests/:rid/reject":  "agent_containment.release_request.decide",
	"POST " + arV1 + "/containments/:id/release-requests/:rid/review":  "agent_containment.release_request.review",
	"POST " + arV1 + "/containments/:id/probe":                         "agent_containment.probe",
	"POST " + arV1 + "/containments/:id/narrow":                        "agent_containment.narrow",

	"POST " + arV1 + "/asks":                                "agent_ask.create",
	"POST " + arV1 + "/asks/:id/answer":                     "agent_ask.answer",
	"POST " + arV1 + "/asks/:id/confirm":                    "agent_ask.confirm",
	"POST " + arV1 + "/asks/:id/not-mine":                   "agent_ask.not_mine",
	"POST " + arV1 + "/asks/:id/withdraw":                   "agent_ask.withdraw",
	"PUT " + arV1 + "/asks/policy":                          "agent_ask.policy.change",
	"POST " + arV1 + "/cases/:id/tickets":                   "agent_case.ticket.create",
	"PUT " + igaV1 + "/integrations/ticketing/:provider":    "integration.ask.set",
	"DELETE " + igaV1 + "/integrations/ticketing/:provider": "integration.ask.delete",
	"PUT " + igaV1 + "/integrations/paging/:provider":       "integration.ask.set",
	"DELETE " + igaV1 + "/integrations/paging/:provider":    "integration.ask.delete",

	"POST " + arV1 + "/gateway-provider-keys":            "agent_gateway.provider_key.add",
	"POST " + arV1 + "/gateway-provider-keys/:id/rotate": "agent_gateway.provider_key.rotate",
	"DELETE " + arV1 + "/gateway-provider-keys/:id":      "agent_gateway.provider_key.delete",
	"POST " + arV1 + "/gateway-agent-keys":               "agent_gateway.agent_key.issue",
	"POST " + arV1 + "/gateway-agent-keys/:id/rotate":    "agent_gateway.agent_key.rotate",
	"DELETE " + arV1 + "/gateway-agent-keys/:id":         "agent_gateway.agent_key.delete",
	"POST " + arV1 + "/gateway-holds/:id/decide":         "agent_gateway.hold.decide",
	"PUT " + arV1 + "/join-settings":                     "agent_join.settings.change",

	"POST " + igaV1 + "/remediations":                     "remediation.prepare",
	"POST " + igaV1 + "/remediations/:id/apply":           GovActionRemediationApply,
	"POST " + igaV1 + "/remediations/:id/cancel":          "remediation.cancel",
	"POST " + igaV1 + "/remediations/bindings":            "remediation.binding.set",
	"POST " + igaV1 + "/remediations/bindings/:id/verify": "remediation.binding.verify",
	"DELETE " + igaV1 + "/remediations/bindings/:id":      "remediation.binding.revoke",
}

// GovTieredSurfaces are the path prefixes of the tiered surfaces: every write
// route under one of them must be in the route table.
var GovTieredSurfaces = []string{
	arV1 + "/",
	igaV1 + "/pending-changes",
	igaV1 + "/approvals",
	igaV1 + "/coverage/",
	igaV1 + "/audit/",
	"/authsec/admin/operators/",
	igaV1 + "/snapshots",
	igaV1 + "/exports",
	igaV1 + "/history-approvals",
	igaV1 + "/metrics/",
	igaV1 + "/reports/",
	igaV1 + "/agent-identities",
	igaV1 + "/agent-changes",
	igaV1 + "/resources/:id/classification",
	igaV1 + "/responder-groups",
	igaV1 + "/directory/",
	igaV1 + "/agent-hygiene/",
	igaV1 + "/remediations",
	igaV1 + "/integrations/ticketing",
	igaV1 + "/integrations/paging",
}

// GovActionFor returns an action's tier.
func GovActionFor(name string) (GovAction, bool) {
	a, ok := govActions[name]
	return a, ok
}

// GovRouteAction returns the action of a route (gin's full path); ok is false
// for a route the table does not name.
func GovRouteAction(method, fullPath string) (string, bool) {
	a, ok := govRouteActions[strings.ToUpper(method)+" "+fullPath]
	return a, ok
}

// GovIsWriteMethod reports whether method changes anything (every method but
// GET, HEAD and OPTIONS).
func GovIsWriteMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// GovInTieredSurface reports whether a route path is in a tiered surface.
func GovInTieredSurface(fullPath string) bool {
	for _, p := range GovTieredSurfaces {
		if fullPath == strings.TrimSuffix(p, "/") || strings.HasPrefix(fullPath, p) {
			return true
		}
	}
	return false
}

// GovRouteTable returns a copy of the route -> action table (tests, docs).
func GovRouteTable() map[string]string {
	out := make(map[string]string, len(govRouteActions))
	for k, v := range govRouteActions {
		out[k] = v
	}
	return out
}

// GovActionTable returns a copy of the action -> tier map (tests, docs).
func GovActionTable() map[string]GovAction {
	out := make(map[string]GovAction, len(govActions))
	for k, v := range govActions {
		out[k] = v
	}
	return out
}
