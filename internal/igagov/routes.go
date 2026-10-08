package igagov

import (
	"sort"
	"strings"
)

// This file is §3.4's resource-policy route analysis ("what the evidence
// covers"), shared by finding evaluation (route_usage on
// iga_gov_activity_evidence, route facts of iga_gov_service_posture), the
// evidence bundle (routes and gaps) and the compiler. It is not one of
// §4.2's listed files; it exists so the three callers cannot disagree
// (DECISION D12).

// Route usage (048 iga_gov_activity_evidence.route_usage).
const (
	RouteUsageNoneObserved    = "none_observed"
	RouteUsageConfirmRequired = "confirm_required"
)

// Route state (051 route_state on outcome and posture).
const (
	RouteStateNoneObserved  = "none_observed"
	RouteStateBypassKnown   = "bypass_known"
	RouteStateEffectUnknown = "effect_unknown"
	RouteStateNotAnalysed   = "not_analysed"
)

// Route principals (§3.4) and per-route effects.
const (
	PrincipalRoleARN     = "role_arn"
	PrincipalRoleSession = "role_session"
	PrincipalWildcard    = "wildcard"

	// RouteEffectLimited: an Allow naming the role ARN; the boundary limits
	// it, so it is not a remaining route (it still needs confirmation).
	RouteEffectLimited       = "limited"
	RouteEffectBypassKnown   = RouteStateBypassKnown
	RouteEffectEffectUnknown = RouteStateEffectUnknown
	RouteEffectNotAnalysed   = RouteStateNotAnalysed
)

// Coverage states (056 cloud_resource_policy_coverage.state) and parse
// states (cloud_resource_policy_observation.parse_state).
const (
	CoverageComplete     = "complete"
	CoveragePartial      = "partial"
	CoverageDenied       = "denied"
	CoverageNotCollected = "not_collected"

	ParseParsed      = "parsed"
	ParseUnparseable = "unparseable"
)

// Route is one resource-policy route for a service, or one form/region the
// evidence could not analyse (Effect not_analysed; Resource empty).
type Route struct {
	Service   string `json:"service"`
	Form      string `json:"form,omitempty"`
	Region    string `json:"region,omitempty"`
	Resource  string `json:"resource,omitempty"`
	Principal string `json:"principal,omitempty"`
	Effect    string `json:"effect"`
	Reason    string `json:"reason,omitempty"`
}

// SortRoutes orders routes deterministically.
func SortRoutes(rs []Route) {
	sort.Slice(rs, func(i, j int) bool {
		a, b := rs[i], rs[j]
		for _, p := range [][2]string{{a.Service, b.Service}, {a.Resource, b.Resource}, {a.Form, b.Form},
			{a.Region, b.Region}, {a.Principal, b.Principal}, {a.Effect, b.Effect}, {a.Reason, b.Reason}} {
			if p[0] != p[1] {
				return p[0] < p[1]
			}
		}
		return false
	})
}

// CoverageRow is one cloud_resource_policy_coverage row of a scan.
type CoverageRow struct {
	Form   string `json:"form"`
	Region string `json:"region"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// ResourcePolicyObservation is one cloud_resource_policy_observation row of
// a scan, with its decoded document when a policy is present and parsed.
type ResourcePolicyObservation struct {
	Form          string
	Region        string
	ResourceARN   string
	PolicyPresent bool
	DocumentHash  string
	ParseState    string
	Document      *PolicyDocument
}

// ResourcePolicyEvidence is one scan's immutable resource-policy evidence
// (§3.9). A nil *ResourcePolicyEvidence means the run collected none.
type ResourcePolicyEvidence struct {
	Coverage     []CoverageRow
	Observations []ResourcePolicyObservation
}

// RoleRef identifies the role whose routes are analysed.
type RoleRef struct {
	RoleID    string
	ARN       string
	Name      string
	AccountID string
	Partition string // "aws" when empty
}

// RouteAnalysis is §3.4's two conclusions for one removed or evaluated
// namespace: route usage (is "no attempt" complete?) and route state (what
// would a removal achieve?), with every route and unanalysed form listed.
type RouteAnalysis struct {
	Service string  `json:"service"`
	Usage   string  `json:"route_usage"`
	State   string  `json:"route_state"`
	Routes  []Route `json:"routes"`
}

// RemainingRoutes are the routes that count for route_state (everything but
// role-ARN routes, which the boundary limits). It is empty exactly when State
// is none_observed (051 iga_gov_sp_routes_chk).
func (ra RouteAnalysis) RemainingRoutes() []Route {
	out := []Route{}
	for _, r := range ra.Routes {
		if r.Effect != RouteEffectLimited {
			out = append(out, r)
		}
	}
	return out
}

func (r RoleRef) partition() string {
	if r.Partition == "" {
		return "aws"
	}
	return r.Partition
}

// arnAccount returns the account field of an ARN ("" when absent, as for S3
// bucket ARNs).
func arnAccount(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return ""
	}
	return parts[4]
}

// classifyAWSPrincipal maps one AWS principal value to a route principal for
// this role, or "" when it is not one (another identity, or an account
// principal: an account delegates to identity policies, so it is within the
// report's scope, §3.4).
func classifyAWSPrincipal(v string, role RoleRef) string {
	switch {
	case v == "*":
		return PrincipalWildcard
	case v == role.ARN || (role.RoleID != "" && v == role.RoleID):
		return PrincipalRoleARN
	case role.Name != "" && strings.HasPrefix(v,
		"arn:"+role.partition()+":sts::"+role.AccountID+":assumed-role/"+role.Name+"/"):
		return PrincipalRoleSession
	}
	return ""
}

func principalLists(p *Principal, role RoleRef) bool {
	if p == nil {
		return false
	}
	for _, v := range p.Values["AWS"] {
		if classifyAWSPrincipal(v, role) != "" && v != "*" {
			return true
		}
		if v == role.AccountID || v == "arn:"+role.partition()+":iam::"+role.AccountID+":root" {
			return true
		}
	}
	return false
}

// statementRoutes returns the route principals an Allow statement grants
// namespace ns to, for this role.
func statementRoutes(st Statement, ns string, role RoleRef) []string {
	if st.Effect != EffectAllow || !st.GrantsNamespace(ns) {
		return nil
	}
	if st.NotPrincipal != nil {
		// Allow + NotPrincipal grants everyone not listed; unless this role
		// is listed, its effect for the role is not established.
		if principalLists(st.NotPrincipal, role) {
			return nil
		}
		return []string{PrincipalWildcard}
	}
	if st.Principal == nil {
		return nil
	}
	if st.Principal.Wildcard {
		return []string{PrincipalWildcard}
	}
	var out []string
	for _, v := range st.Principal.Values["AWS"] {
		if k := classifyAWSPrincipal(v, role); k != "" {
			out = append(out, k)
		}
	}
	return sortedUnique(out)
}

func effectFor(principal string) string {
	switch principal {
	case PrincipalRoleARN:
		return RouteEffectLimited
	case PrincipalRoleSession:
		return RouteEffectBypassKnown
	}
	return RouteEffectEffectUnknown
}

// AnalyzeRoutes is §3.4's route analysis of one namespace from ONE scan's
// observations and coverage (the role connector's run in the revision's
// manifest; never "current" rows):
//
//   - no evidence for the run → confirm_required, not_analysed;
//   - an uncollected form of the namespace, a collected form not complete in
//     every enabled Region (account-scoped forms: every row of the form
//     complete and at least one row), or an unparseable observed policy →
//     a not_analysed route naming it;
//   - an Allow granting the namespace to the role ARN (limited), a session of
//     the role (bypass_known) or "*" / {"AWS":"*"} / Allow+NotPrincipal
//     (effect_unknown) → a route naming the resource.
//
// DECISION D20. Usage is none_observed only with no route and nothing unanalysed. State
// takes the strongest remaining route: bypass_known, then effect_unknown,
// then not_analysed. Resources in other accounts are within the activity
// report's scope (they need an identity grant) and are skipped.
func AnalyzeRoutes(service string, role RoleRef, ev *ResourcePolicyEvidence, enabledRegions []string) RouteAnalysis {
	ra := RouteAnalysis{Service: service, Routes: []Route{}}
	if ev == nil {
		ra.Routes = append(ra.Routes, Route{Service: service, Effect: RouteEffectNotAnalysed, Reason: "no_resource_policy_coverage"})
		return ra.finish()
	}
	forms := FormsForNamespace(service)
	formNames := map[string]bool{}
	for _, f := range forms {
		formNames[f.Name] = true
		if f.State == FormUncollected {
			ra.Routes = append(ra.Routes, Route{Service: service, Form: f.Name, Effect: RouteEffectNotAnalysed, Reason: "form_not_collected"})
			continue
		}
		rows := map[string]CoverageRow{}
		for _, c := range ev.Coverage {
			if c.Form == f.Name {
				rows[c.Region] = c
			}
		}
		if f.Scope == ScopeAccount {
			if len(rows) == 0 {
				ra.Routes = append(ra.Routes, Route{Service: service, Form: f.Name, Effect: RouteEffectNotAnalysed, Reason: CoverageNotCollected})
			}
			for _, region := range sortedKeys(rows) {
				if c := rows[region]; c.State != CoverageComplete {
					ra.Routes = append(ra.Routes, Route{Service: service, Form: f.Name, Region: region, Effect: RouteEffectNotAnalysed, Reason: c.State})
				}
			}
			continue
		}
		for _, region := range sortedUnique(enabledRegions) {
			c, ok := rows[region]
			switch {
			case !ok:
				ra.Routes = append(ra.Routes, Route{Service: service, Form: f.Name, Region: region, Effect: RouteEffectNotAnalysed, Reason: CoverageNotCollected})
			case c.State != CoverageComplete:
				ra.Routes = append(ra.Routes, Route{Service: service, Form: f.Name, Region: region, Effect: RouteEffectNotAnalysed, Reason: c.State})
			}
		}
	}
	for _, ob := range ev.Observations {
		if !formNames[ob.Form] || !ob.PolicyPresent {
			continue
		}
		if acct := arnAccount(ob.ResourceARN); acct != "" && role.AccountID != "" && acct != role.AccountID {
			continue
		}
		if ob.ParseState == ParseUnparseable || ob.Document == nil {
			ra.Routes = append(ra.Routes, Route{Service: service, Form: ob.Form, Region: ob.Region, Resource: ob.ResourceARN,
				Effect: RouteEffectNotAnalysed, Reason: "policy_unparseable"})
			continue
		}
		seen := map[string]bool{}
		for _, st := range ob.Document.Statements {
			for _, p := range statementRoutes(st, service, role) {
				if seen[p] {
					continue
				}
				seen[p] = true
				ra.Routes = append(ra.Routes, Route{Service: service, Form: ob.Form, Region: ob.Region,
					Resource: ob.ResourceARN, Principal: p, Effect: effectFor(p)})
			}
		}
	}
	return ra.finish()
}

func (ra RouteAnalysis) finish() RouteAnalysis {
	SortRoutes(ra.Routes)
	ra.Usage = RouteUsageNoneObserved
	if len(ra.Routes) > 0 {
		ra.Usage = RouteUsageConfirmRequired
	}
	has := map[string]bool{}
	for _, r := range ra.Routes {
		has[r.Effect] = true
	}
	switch {
	case has[RouteEffectBypassKnown]:
		ra.State = RouteStateBypassKnown
	case has[RouteEffectEffectUnknown]:
		ra.State = RouteStateEffectUnknown
	case has[RouteEffectNotAnalysed]:
		ra.State = RouteStateNotAnalysed
	default:
		ra.State = RouteStateNoneObserved
	}
	return ra
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
