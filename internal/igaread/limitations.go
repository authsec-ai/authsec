package igaread

// The limitations vocabulary (SPEC-iga-phase2-graph.md §5.3 Evidence, T6.5;
// P2-DECISIONS D-21, D-22, D-35, D-58, D-88): what a claim does NOT establish.
//
// Every code has ONE exact condition, and a code whose condition does not hold
// never appears (§2.14.7 "never generic boilerplate"; E4 fails on "a
// limitation that does not apply"). The conditions are evaluated here, once,
// for every route that shows limitations: /evidence renders all of them, and
// the graph routes render the subset that needs no facts (D-35,
// FactFreeLimitations) from the SAME function, so an edge on the canvas and
// the evidence panel it opens can never disagree.
//
// Everything is read in the request's snapshot, one query per kind of input
// (§5.6) -- never per claim.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

// Limitation codes (§5.3), in the vocabulary table's order -- the order a
// claim's limitations are listed in.
const (
	LimEffectiveAccessNotEvaluated  = "effective_access_not_evaluated"
	LimConditionsNotEvaluated       = "conditions_not_evaluated"
	LimNegatedStatement             = "negated_statement"
	LimDenyStatementsPresent        = "deny_statements_present"
	LimPermissionsBoundaryPresent   = "permissions_boundary_present"
	LimOrganizationsNotCollected    = PreventsOrganizations
	LimResourcePolicyNotProjected   = "resource_policy_not_projected"
	LimResourceExistenceNotVerified = "resource_existence_not_verified"
	LimSelectorMayMatchNothing      = "selector_may_match_nothing"
	LimAccountNotConnected          = "account_not_connected"
	LimCallerPermissionNotEvaluated = "caller_permission_not_evaluated"
	LimNotPrincipalUnresolved       = "not_principal_unresolved"
	LimSurfaceStale                 = PreventsSurfaceStale
	LimSurfacePartial               = PreventsSurfacePartial
	LimSurfaceDenied                = PreventsSurfaceDenied
	LimActivityAttemptsNotOutcomes  = "activity_attempts_not_outcomes"
)

// limitationOrder ranks the codes by the §5.3 table. The three surface codes
// share a rank and sort among themselves by account, then surface.
var limitationOrder = map[string]int{
	LimEffectiveAccessNotEvaluated:  0,
	LimConditionsNotEvaluated:       1,
	LimNegatedStatement:             2,
	LimDenyStatementsPresent:        3,
	LimPermissionsBoundaryPresent:   4,
	LimOrganizationsNotCollected:    5,
	LimResourcePolicyNotProjected:   6,
	LimResourceExistenceNotVerified: 7,
	LimSelectorMayMatchNothing:      8,
	LimAccountNotConnected:          9,
	LimCallerPermissionNotEvaluated: 10,
	LimNotPrincipalUnresolved:       11,
	LimSurfaceStale:                 12,
	LimSurfacePartial:               12,
	LimSurfaceDenied:                12,
	LimActivityAttemptsNotOutcomes:  13,
}

// FactFreeLimitations are the codes D-35 puts on every graph node, edge and
// path: those decided by the claim's own rows and coverage, without reading
// its supporting observations. effective_access_not_evaluated and
// organizations_not_collected are stated once in the graph's meta instead.
var FactFreeLimitations = map[string]bool{
	LimAccountNotConnected:          true,
	LimSurfaceStale:                 true,
	LimSurfacePartial:               true,
	LimSurfaceDenied:                true,
	LimConditionsNotEvaluated:       true,
	LimNegatedStatement:             true,
	LimNotPrincipalUnresolved:       true,
	LimCallerPermissionNotEvaluated: true,
	LimDenyStatementsPresent:        true,
	LimPermissionsBoundaryPresent:   true,
}

// Limitation is one entry of a claim's limitations: {"code": ..., plus the
// code's own fields}. The fields per code:
//
//	conditions_not_evaluated         keys: the condition keys, sorted
//	negated_statement                negations: "NotAction" / "NotResource"
//	deny_statements_present          count, statements (refs, at most
//	                                 LimitationRefCap), truncated
//	permissions_boundary_present     holder (bool), policies (the holder's
//	                                 boundary policies), members, member_count
//	                                 (D-22: current group members with one)
//	resource_policy_not_projected,
//	resource_existence_not_verified,
//	selector_may_match_nothing       resources (refs)
//	account_not_connected            accounts (ids)
//	surface_*                        account_id, surface, state, since
//
// A map, so each code carries exactly its own fields; encoding/json writes the
// keys sorted, so the rendering is deterministic.
type Limitation map[string]any

// Code is the limitation's code.
func (l Limitation) Code() string { s, _ := l["code"].(string); return s }

// LimitationRefCap bounds the refs a limitation lists; its count stays exact.
const LimitationRefCap = 50

// limInput is everything a claim's limitations are decided from, filled by
// the claim loaders (evidence.go) from the claim's own rows.
type limInput struct {
	// grant marks an access claim: effective access is never evaluated, and
	// Deny statements and boundaries bear on it (§2.6).
	grant bool
	// relType is the relationship type of a relationship claim.
	relType string

	// stmt is the statement a grant or target claim is about.
	stmt *evStatement
	// named are the resources the claim names -- a grant's POSITIVE targets
	// (the implicit "*" of a NotResource statement included), a target
	// claim's resource, a resource's own presence.
	named []evTarget
	// policyTargets are the resources whose own resource policy bears on the
	// claim (§5.3 "the target has a resource policy that was read").
	policyTargets []evTarget

	// holder is the identity a grant is declared for, and its kind.
	holder     *uuid.UUID
	holderKind string

	// can_assume: the trust statement's Condition (NULL when it had none,
	// 031), its statement key, and the target role's provider_attrs flags
	// the trust projection wrote (D-44, D-88).
	trustConditions   json.RawMessage
	trustStatementKey string
	trustNotPrincipal bool
	trustNegated      []string

	// endpoints are the accounts the claim's endpoints are in, with whether
	// each is connected as this route reads it (D-3, D-89).
	endpoints []evEndpoint

	// parts are the partitions the claim stands on: an edge's own, a node's
	// support rows' (§4.10). Their required surfaces decide surface_* and
	// status.collection.
	parts []evPart
	// stale: the claim is stale -- the policy_documents fallback applies to
	// document-protected claims (docProtected) only then (D-74).
	stale        bool
	docProtected bool

	// coverage is a coverage claim's own surface.
	coverage *evCoverage

	// activity: the response carries Access Advisor facts (§2.14.8).
	activity bool
}

// evStatement is one statement (iga_entitlements, provider aws) as a claim
// uses it.
type evStatement struct {
	ID           uuid.UUID
	Sid          string
	Index        *int
	Effect       string
	Negated      bool
	Conditional  bool
	NativeRights json.RawMessage
	PolicyID     uuid.UUID
	PolicyName   string
	PolicyKind   string
	VersionID    string
	text         statementText
}

// label is how a sentence names the statement: its Sid, else its 1-based
// position (D-84).
func (s *evStatement) label() string {
	if s.Sid != "" {
		return s.Sid
	}
	if s.Index != nil {
		return fmt.Sprintf("%d", *s.Index+1)
	}
	return "without a Sid"
}

// evTarget is one statement target joined to its resource reference.
type evTarget struct {
	TargetID         uuid.UUID
	StatementID      uuid.UUID
	Mode             string
	Ordinal          int
	ResourceID       uuid.UUID
	Text             string
	ResourceKind     string
	Reference        string
	AccountID        string
	AccountConnected bool
}

func (t evTarget) selector() bool {
	return t.ResourceKind == "selector" || t.Reference == "selector"
}

func (t evTarget) exact() bool { return !t.selector() && t.Reference == "exact" }

// evEndpoint is one endpoint account of a claim.
type evEndpoint struct {
	account   string
	connected bool
}

// evPart is one partition a claim stands on: the connector and the
// partition key stamped on its row (§4.10, D-57).
type evPart struct {
	connector uuid.UUID
	key       string
}

// evCoverage is a coverage claim's surface in its run.
type evCoverage struct {
	run         uuid.UUID
	connector   uuid.UUID
	publishedAt time.Time
	surface     string
	state       string
}

/* ------------------------------ statement text ----------------------------- */

// statementText is what a statement's verbatim JSON says, read for sentences,
// condition keys and negations. native_rights is AWS's own statement (keys
// Action, NotAction, Resource, NotResource, Condition) or, when the collector
// had no raw form, models.NativeRights (actions, not_actions, resources,
// not_resources, condition).
type statementText struct {
	Actions, NotActions, Resources, NotResources []string
	Condition                                    json.RawMessage
}

func parseStatementText(raw json.RawMessage) statementText {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return statementText{}
	}
	pick := func(keys ...string) json.RawMessage {
		for _, k := range keys {
			if v, ok := m[k]; ok {
				return v
			}
		}
		return nil
	}
	cond := pick("Condition", "condition")
	if string(cond) == "null" {
		cond = nil
	}
	return statementText{
		Actions:      stringOrList(pick("Action", "actions")),
		NotActions:   stringOrList(pick("NotAction", "not_actions")),
		Resources:    stringOrList(pick("Resource", "resources")),
		NotResources: stringOrList(pick("NotResource", "not_resources")),
		Condition:    cond,
	}
}

// stringOrList reads an IAM element that is a string or a list of strings.
func stringOrList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many
	}
	return nil
}

// ConditionKeys lists the condition keys of an IAM Condition block (operator
// -> {key: value}), sorted and distinct. A block that is not that shape yields
// no keys; the statement is still conditional.
func ConditionKeys(cond json.RawMessage) []string {
	var ops map[string]map[string]json.RawMessage
	if err := json.Unmarshal(cond, &ops); err != nil {
		return []string{}
	}
	seen := map[string]bool{}
	out := []string{}
	for _, keys := range ops {
		for k := range keys {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}

func hasCondition(cond json.RawMessage) bool {
	s := strings.TrimSpace(string(cond))
	return s != "" && s != "null" && s != "{}"
}

/* ------------------------------- computation ------------------------------- */

// computeLimitationsAndCoverage decides every claim's limitations in one
// pass over the snapshot -- one query per input kind (holder groups, Deny
// statements, boundaries, members, resource policies, partition coverage),
// never per claim -- and returns the coverage the claims stand on, which
// status.collection is read from. codes restricts the result (nil = every
// code); a code outside it is neither computed nor returned.
func computeLimitationsAndCoverage(q *Query, accts *Accounts, ins []*limInput, codes map[string]bool) ([][]Limitation, *claimCoverage, error) {
	want := func(code string) bool { return codes == nil || codes[code] }
	out := make([][]Limitation, len(ins))

	restr, err := loadRestrictions(q, ins, want(LimDenyStatementsPresent), want(LimPermissionsBoundaryPresent))
	if err != nil {
		return nil, nil, err
	}
	var policyRead map[string]bool
	if want(LimResourcePolicyNotProjected) {
		if policyRead, err = loadResourcePoliciesRead(q, ins); err != nil {
			return nil, nil, err
		}
	}
	cov := &claimCoverage{gaps: map[int][]claimGap{}, unrecorded: map[int]bool{}, direct: map[int]string{}}
	if codes == nil || want(LimSurfaceStale) || want(LimSurfacePartial) || want(LimSurfaceDenied) {
		if cov, err = loadClaimCoverage(q, accts, ins); err != nil {
			return nil, nil, err
		}
	}
	gaps := cov.gaps

	for i, in := range ins {
		var ls []Limitation
		add := func(l Limitation) {
			if want(l.Code()) {
				ls = append(ls, l)
			}
		}

		// Always, on grants (and paths, which are the graph's).
		if in.grant {
			add(Limitation{"code": LimEffectiveAccessNotEvaluated})
		}

		// The statement or trust statement has a Condition; the keys listed.
		if in.stmt != nil && (in.stmt.Conditional || hasCondition(in.stmt.text.Condition)) {
			add(Limitation{"code": LimConditionsNotEvaluated, "keys": ConditionKeys(in.stmt.text.Condition)})
		}
		if in.relType == models.RelTypeCanAssume && hasCondition(in.trustConditions) {
			add(Limitation{"code": LimConditionsNotEvaluated, "keys": ConditionKeys(in.trustConditions)})
		}

		// NotAction or NotResource: the statement's own flag, or -- for a
		// trust edge, whose row has no column for it (031) -- the target
		// role's list of NotAction trust statements (D-88).
		if in.stmt != nil && in.stmt.Negated {
			negs := []string{}
			if len(in.stmt.text.NotActions) > 0 {
				negs = append(negs, "NotAction")
			}
			if len(in.stmt.text.NotResources) > 0 {
				negs = append(negs, "NotResource")
			}
			add(Limitation{"code": LimNegatedStatement, "negations": negs})
		}
		if in.relType == models.RelTypeCanAssume && in.trustStatementKey != "" && contains(in.trustNegated, in.trustStatementKey) {
			add(Limitation{"code": LimNegatedStatement, "negations": []string{"NotAction"}})
		}

		if in.grant && in.holder != nil {
			if d := restr.denyOf(*in.holder); len(d) > 0 {
				refs, trunc := capRefs(RefStatement, d)
				add(Limitation{"code": LimDenyStatementsPresent, "count": len(d), "statements": refs, "truncated": trunc})
			}
			if l := restr.boundaryOf(*in.holder, in.holderKind); l != nil {
				add(l)
			}
		}

		// Always, for AWS: every claim this route reads is an AWS claim
		// (a GitHub row is 404, D-6), and SCPs are never collected.
		add(Limitation{"code": LimOrganizationsNotCollected})

		if len(in.policyTargets) > 0 && policyRead != nil {
			var ids []uuid.UUID
			for _, t := range in.policyTargets {
				if policyRead[t.Text] {
					ids = append(ids, t.ResourceID)
				}
			}
			if len(ids) > 0 {
				refs, _ := capRefs(RefResource, uniqueIDs(ids))
				add(Limitation{"code": LimResourcePolicyNotProjected, "resources": refs})
			}
		}

		// Exact references and selectors, each by its own condition (D-21): a
		// statement naming both kinds carries both.
		var exact, selectors []uuid.UUID
		for _, t := range in.named {
			switch {
			case t.selector():
				selectors = append(selectors, t.ResourceID)
			case t.exact():
				exact = append(exact, t.ResourceID)
			}
		}
		if len(exact) > 0 {
			refs, _ := capRefs(RefResource, uniqueIDs(exact))
			add(Limitation{"code": LimResourceExistenceNotVerified, "resources": refs})
		}
		if len(selectors) > 0 {
			refs, _ := capRefs(RefResource, uniqueIDs(selectors))
			add(Limitation{"code": LimSelectorMayMatchNothing, "resources": refs})
		}

		var unconnected []string
		for _, e := range in.endpoints {
			if e.account != "" && !e.connected && !contains(unconnected, e.account) {
				unconnected = append(unconnected, e.account)
			}
		}
		if len(unconnected) > 0 {
			sort.Strings(unconnected)
			add(Limitation{"code": LimAccountNotConnected, "accounts": unconnected})
		}

		if in.relType == models.RelTypeCanAssume {
			add(Limitation{"code": LimCallerPermissionNotEvaluated})
			if in.trustNotPrincipal {
				add(Limitation{"code": LimNotPrincipalUnresolved})
			}
		}

		for _, g := range gaps[i] {
			add(Limitation{"code": g.code, "account_id": g.accountID, "surface": g.surface, "state": g.state, "since": g.since})
		}

		if in.activity {
			add(Limitation{"code": LimActivityAttemptsNotOutcomes})
		}

		sortLimitations(ls)
		if ls == nil {
			ls = []Limitation{}
		}
		out[i] = ls
	}
	return out, cov, nil
}

func sortLimitations(ls []Limitation) {
	sort.SliceStable(ls, func(i, j int) bool {
		ri, rj := limitationOrder[ls[i].Code()], limitationOrder[ls[j].Code()]
		if ri != rj {
			return ri < rj
		}
		ai, _ := ls[i]["account_id"].(string)
		aj, _ := ls[j]["account_id"].(string)
		if ai != aj {
			return ai < aj
		}
		si, _ := ls[i]["surface"].(string)
		sj, _ := ls[j]["surface"].(string)
		return si < sj
	})
}

func capRefs(refType string, ids []uuid.UUID) ([]string, bool) {
	out := make([]string, 0, len(ids))
	for i, id := range ids {
		if i == LimitationRefCap {
			return out, true
		}
		out = append(out, R(refType, id))
	}
	return out, false
}

func uniqueIDs(ids []uuid.UUID) []uuid.UUID {
	seen := map[uuid.UUID]bool{}
	out := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

/* ------------------------- Deny statements, boundaries ---------------------- */

// restrictions is what bears on a grant's holder (§2.6, D-22): the ACTIVE
// Deny statements the holder and its live groups hold through live
// attached/inline assignments, and the live boundary assignments of the
// holder and -- for a group -- of its current members.
type restrictions struct {
	groups   map[uuid.UUID][]uuid.UUID // holder -> its live groups (member_of, not ended)
	deny     map[uuid.UUID][]uuid.UUID // holder -> Deny statements held DIRECTLY
	boundary map[uuid.UUID][]uuid.UUID // identity -> boundary policies
	members  map[uuid.UUID][]uuid.UUID // group -> current member users
}

// denyOf is the Deny statements bearing on a holder: its own and its groups'
// (§5.3 "the holder (or its groups)"), distinct, sorted.
func (r *restrictions) denyOf(holder uuid.UUID) []uuid.UUID {
	all := append([]uuid.UUID{}, r.deny[holder]...)
	for _, g := range r.groups[holder] {
		all = append(all, r.deny[g]...)
	}
	return uniqueIDs(all)
}

// boundaryOf is permissions_boundary_present for a grant's holder, or nil:
// the holder's own boundary, and for a group-held grant, D-22's current
// members that have one -- the grant reaches them only through a restricted
// node (§2.6 l.549).
func (r *restrictions) boundaryOf(holder uuid.UUID, holderKind string) Limitation {
	own := uniqueIDs(r.boundary[holder])
	var members []uuid.UUID
	if holderKind == models.CloudIdentityIAMGroup {
		for _, m := range r.members[holder] {
			if len(r.boundary[m]) > 0 {
				members = append(members, m)
			}
		}
	}
	members = uniqueIDs(members)
	if len(own) == 0 && len(members) == 0 {
		return nil
	}
	pol, _ := capRefs(RefPolicy, own)
	mem, trunc := capRefs(RefIdentity, members)
	return Limitation{
		"code": LimPermissionsBoundaryPresent, "holder": len(own) > 0,
		"policies": pol, "members": mem, "member_count": len(members), "truncated": trunc,
	}
}

func loadRestrictions(q *Query, ins []*limInput, wantDeny, wantBoundary bool) (*restrictions, error) {
	r := &restrictions{
		groups: map[uuid.UUID][]uuid.UUID{}, deny: map[uuid.UUID][]uuid.UUID{},
		boundary: map[uuid.UUID][]uuid.UUID{}, members: map[uuid.UUID][]uuid.UUID{},
	}
	var holders, groupHolders []uuid.UUID
	for _, in := range ins {
		if in.grant && in.holder != nil {
			holders = append(holders, *in.holder)
			if in.holderKind == models.CloudIdentityIAMGroup {
				groupHolders = append(groupHolders, *in.holder)
			}
		}
	}
	holders = uniqueIDs(holders)
	if len(holders) == 0 || (!wantDeny && !wantBoundary) {
		return r, nil
	}
	tx := q.DB()

	if wantDeny {
		// The holders' live groups: member_of from the holder, not ended.
		var gs []struct{ Source, Target uuid.UUID }
		if err := tx.Raw(`SELECT r.source_identity_account_id AS source, r.target_identity_account_id AS target
		                    FROM iga_relationship r
		                   WHERE r.workspace_id = ? AND r.relationship_type = ?
		                     AND COALESCE(r.source_identity_account_id, r.source_workload_id) IN ?
		                     AND r.state <> 'ended'`,
			q.WS, models.RelTypeMemberOf, holders).Scan(&gs).Error; err != nil {
			return nil, err
		}
		bearers := append([]uuid.UUID{}, holders...)
		for _, g := range gs {
			r.groups[g.Source] = append(r.groups[g.Source], g.Target)
			bearers = append(bearers, g.Target)
		}
		// ACTIVE Deny statements of live attached/inline assignments -- a
		// boundary's statements cap, they are not Deny restrictions of the
		// holder (§2.6).
		var ds []struct{ Holder, Statement uuid.UUID }
		if err := tx.Raw(`SELECT DISTINCT pa.holder_identity_account_id AS holder, e.id AS statement
		                    FROM iga_policy_assignment pa
		                    JOIN iga_entitlements e ON e.workspace_id = pa.workspace_id AND e.policy_id = pa.policy_id
		                   WHERE pa.workspace_id = ? AND pa.holder_identity_account_id IN ?
		                     AND pa.state <> 'ended' AND pa.assignment_kind IN ?
		                     AND e.provider = 'aws' AND e.effect = ? AND e.lifecycle = ?`,
			q.WS, uniqueIDs(bearers), []string{models.CloudAttachmentAttached, models.CloudAttachmentInline},
			models.EffectDeny, models.IGALifecycleActive).Scan(&ds).Error; err != nil {
			return nil, err
		}
		for _, d := range ds {
			r.deny[d.Holder] = append(r.deny[d.Holder], d.Statement)
		}
	}

	if wantBoundary {
		bearers := append([]uuid.UUID{}, holders...)
		if len(groupHolders) > 0 {
			// D-22: a group-held grant reaches each CURRENT member.
			var ms []struct{ Source, Target uuid.UUID }
			if err := tx.Raw(`SELECT r.source_identity_account_id AS source, r.target_identity_account_id AS target
			                    FROM iga_relationship r
			                   WHERE r.workspace_id = ? AND r.relationship_type = ?
			                     AND r.target_identity_account_id IN ? AND r.state = ?`,
				q.WS, models.RelTypeMemberOf, uniqueIDs(groupHolders), models.RelCurrent).Scan(&ms).Error; err != nil {
				return nil, err
			}
			for _, m := range ms {
				r.members[m.Target] = append(r.members[m.Target], m.Source)
				bearers = append(bearers, m.Source)
			}
		}
		var bs []struct{ Holder, Policy uuid.UUID }
		if err := tx.Raw(`SELECT DISTINCT pa.holder_identity_account_id AS holder, pa.policy_id AS policy
		                    FROM iga_policy_assignment pa
		                    JOIN iga_policy p ON p.workspace_id = pa.workspace_id AND p.id = pa.policy_id
		                   WHERE pa.workspace_id = ? AND pa.holder_identity_account_id IN ?
		                     AND pa.assignment_kind = ? AND pa.state <> 'ended' AND p.provider = 'aws'`,
			q.WS, uniqueIDs(bearers), models.CloudAttachmentBoundary).Scan(&bs).Error; err != nil {
			return nil, err
		}
		for _, b := range bs {
			r.boundary[b.Holder] = append(r.boundary[b.Holder], b.Policy)
		}
	}
	return r, nil
}

/* ----------------------------- resource policies --------------------------- */

// loadResourcePoliciesRead reports, per resource reference text, whether a
// resource policy was READ for it and belongs to the current revision (D-19):
// an observation on the resource_policies surface whose subject is exactly the
// reference's ARN, first recorded by a run that published at or below the
// current revision. The policy itself is never projected (§1.4), so the
// grant's evaluation cannot account for it.
func loadResourcePoliciesRead(q *Query, ins []*limInput) (map[string]bool, error) {
	out := map[string]bool{}
	var texts []string
	for _, in := range ins {
		for _, t := range in.policyTargets {
			if !contains(texts, t.Text) {
				texts = append(texts, t.Text)
			}
		}
	}
	if len(texts) == 0 || q.Rev == nil {
		return out, nil
	}
	var read []string
	if err := q.DB().Raw(`SELECT DISTINCT o.subject_native_id
	                        FROM cloud_observation o
	                       WHERE o.workspace_id = ? AND o.surface = ? AND o.source_api IN ?
	                         AND o.subject_native_id IN ?
	                         AND EXISTS (SELECT 1 FROM iga_publication p
	                                      WHERE p.workspace_id = o.workspace_id AND p.scan_run_id = o.scan_run_id
	                                        AND p.rev <= ?)`,
		q.WS, models.SurfaceResourcePolicies, ResourcePolicySourceAPIs, texts, q.Rev.Rev).Scan(&read).Error; err != nil {
		return nil, err
	}
	for _, t := range read {
		out[t] = true
	}
	return out, nil
}

// ResourcePolicySourceAPIs are the calls a resource policy observation is
// recorded under (services/cloud_aws_permission_scan.go resourcePolicySourceAPI).
var ResourcePolicySourceAPIs = []string{"s3:GetBucketPolicy", "kms:GetKeyPolicy", "resource:GetPolicy"}

/* --------------------------- partitions and coverage ------------------------ */

// claimGap is one required surface (or scanner marker) a claim's partition
// was not reached on, in the run the current revision holds that partition
// from (D-57), with the limitation code it imposes (D-58).
type claimGap struct {
	code      string
	accountID string
	surface   string
	state     string
	since     any

	connector   uuid.UUID
	run         uuid.UUID
	publishedAt time.Time
}

// claimCoverage is the coverage every claim stands on.
type claimCoverage struct {
	gaps map[int][]claimGap
	// unrecorded: a partition of the claim has no watermark (or no run) this
	// snapshot can read, so nothing says it was reached.
	unrecorded map[int]bool
	// direct is a coverage claim's collection: its own surface's state.
	direct map[int]string
}

// collection is status.collection (D-80): complete when every required
// surface and scanner of the claim's partitions is reached; partial when any
// gap is partial; stale otherwise. A partition with no recorded watermark is
// not known to be complete: stale.
func (c *claimCoverage) collection(i int) string {
	if d, ok := c.direct[i]; ok {
		return d
	}
	gs := c.gaps[i]
	if len(gs) == 0 && !c.unrecorded[i] {
		return CollectionComplete
	}
	for _, g := range gs {
		if g.state == models.CloudCoveragePartial {
			return CollectionPartial
		}
	}
	return CollectionStale
}

// status.collection values (§2.14.9).
const (
	CollectionComplete = "complete"
	CollectionPartial  = "partial"
	CollectionStale    = "stale"
)

// surfaceCode is the surface_* code a surface's state imposes (D-58), or ""
// when it prevents nothing (reached, not_configured, unsupported) or imposes
// another code (organizations: organizations_not_collected, which every AWS
// claim already carries).
func surfaceCode(surface, state string) string {
	code, _ := Prevents(surface, state).(string)
	switch code {
	case LimSurfaceStale, LimSurfacePartial, LimSurfaceDenied:
		return code
	}
	return ""
}

// loadClaimCoverage reads, for every claim, the gaps of the partitions it
// stands on:
//
//   - the run is iga_projection_state.last_run_id for (connector, partition
//     key) -- the run the current revision was built from for that partition
//     (D-57), read in this snapshot;
//   - the partition is igagraph's own (Partitions over that run's coverage,
//     with the watermark's scope and connector), matched by KEY, so the read
//     side never re-derives which surfaces a partition requires;
//   - its gaps are partitionGaps' (the same rule D-74's stale_reason uses):
//     present required surfaces or scanner markers not reached, else absent
//     required surfaces (did not look); and for a STALE document-protected
//     claim with no such gap, the run's policy_documents when not reached
//     (D-74: an unreadable document protects its rows);
//   - the code is Prevents' (D-58); a required surface not reached whose
//     state prevents nothing there (not_configured, unsupported) is still a
//     required read that did not happen: surface_stale.
//
// A watermark whose key this build does not produce (a partition kind renamed
// since, D-60) cannot be scoped, and every surface of its run that is not
// reached is named -- an old gap shown is a claim of less, a hidden one a
// claim of more (coverageScope's rule).
//
// since is the start of the surface's unbroken streak in that state
// (coverageSince, D-72), OPTIONAL work.
func loadClaimCoverage(q *Query, accts *Accounts, ins []*limInput) (*claimCoverage, error) {
	out := &claimCoverage{gaps: map[int][]claimGap{}, unrecorded: map[int]bool{}, direct: map[int]string{}}
	type markRow struct {
		ConnectorID   uuid.UUID
		PartitionKey  string
		EstateScopeID uuid.UUID
		LastRunID     uuid.UUID
	}
	parts := map[evPart]bool{}
	for _, in := range ins {
		for _, p := range in.parts {
			parts[p] = true
		}
	}
	marks := map[evPart]markRow{}
	runs := map[uuid.UUID]*coverageRun{}
	if len(parts) > 0 {
		// One read of every watermark involved, on the (workspace_id,
		// connector_id, partition_key) key of iga_projection_state (033).
		values := make([]string, 0, len(parts))
		args := []any{q.WS}
		for p := range parts {
			values = append(values, "(?::uuid, ?::text)")
			args = append(args, p.connector, p.key)
		}
		var rows []markRow
		if err := q.DB().Raw(`SELECT ps.connector_id, ps.partition_key, ps.estate_scope_id, ps.last_run_id
		                        FROM iga_projection_state ps
		                       WHERE ps.workspace_id = ?
		                         AND (ps.connector_id, ps.partition_key) IN (VALUES `+strings.Join(values, ", ")+`)`,
			args...).Scan(&rows).Error; err != nil {
			return nil, err
		}
		runIDs := []uuid.UUID{}
		for _, m := range rows {
			marks[evPart{m.ConnectorID, m.PartitionKey}] = m
			runIDs = append(runIDs, m.LastRunID)
		}
		if len(runIDs) > 0 {
			var rs []coverageRun
			if err := q.DB().Raw(`SELECT r.id, r.connector_id, r.published_at, r.coverage
			                        FROM cloud_scan_run r WHERE r.workspace_id = ? AND r.id IN ?`,
				q.WS, uniqueIDs(runIDs)).Scan(&rs).Error; err != nil {
				return nil, err
			}
			for i := range rs {
				runs[rs[i].ID] = &rs[i]
			}
		}
	}

	// The partitions igagraph builds for each (scope, run), by key.
	built := map[string]map[string]igagraph.Partition{}
	partitionFor := func(m markRow, run *coverageRun, cov models.ScanCoverage) (igagraph.Partition, bool) {
		bk := m.EstateScopeID.String() + "|" + run.ID.String()
		byKey, ok := built[bk]
		if !ok {
			byKey = map[string]igagraph.Partition{}
			snap := &igagraph.Snapshot{
				ScopeID:  m.EstateScopeID,
				Run:      models.CloudScanRun{ID: run.ID, ConnectorID: run.ConnectorID},
				Coverage: cov.Surfaces,
			}
			for _, p := range igagraph.Partitions(snap) {
				byKey[p.Key()] = p
			}
			built[bk] = byKey
		}
		p, ok := byKey[m.PartitionKey]
		return p, ok
	}

	var sinceEntries []*CoverageSurface
	type gapRef struct{ claim, idx int }
	var refs []gapRef
	for i, in := range ins {
		seen := map[string]bool{}
		addGap := func(run *coverageRun, surface, state string) {
			key := run.ConnectorID.String() + "|" + surface
			if seen[key] {
				return
			}
			seen[key] = true
			code, _ := Prevents(surface, state).(string)
			if code == "" || code == LimOrganizationsNotCollected {
				code = LimSurfaceStale
			}
			acct := ""
			if c := accts.Connector(run.ConnectorID); c != nil {
				acct = c.AccountID
			}
			out.gaps[i] = append(out.gaps[i], claimGap{
				code: code, accountID: acct, surface: surface, state: state,
				connector: run.ConnectorID, run: run.ID, publishedAt: pubTime(*run),
			})
			refs = append(refs, gapRef{i, len(out.gaps[i]) - 1})
		}

		if in.coverage != nil {
			// A coverage claim is its own surface: the gap is the surface's
			// state when it prevents something (D-58), and its collection is
			// that state -- reached complete, partial partial, anything else
			// stale.
			switch in.coverage.state {
			case models.CloudCoverageReached:
				out.direct[i] = CollectionComplete
			case models.CloudCoveragePartial:
				out.direct[i] = CollectionPartial
			default:
				out.direct[i] = CollectionStale
			}
			if surfaceCode(in.coverage.surface, in.coverage.state) != "" {
				run := &coverageRun{ID: in.coverage.run, ConnectorID: in.coverage.connector, PublishedAt: &in.coverage.publishedAt}
				addGap(run, in.coverage.surface, in.coverage.state)
			}
			continue
		}

		if len(in.parts) == 0 {
			// Nothing names the partition the claim stands on (its connector
			// was deleted, say): it is not known to be complete.
			out.unrecorded[i] = true
		}
		var standing []*coverageRun
		for _, p := range in.parts {
			m, ok := marks[p]
			if !ok {
				out.unrecorded[i] = true
				continue
			}
			run := runs[m.LastRunID]
			if run == nil {
				out.unrecorded[i] = true
				continue
			}
			standing = append(standing, run)
			cov := models.DecodeScanCoverage(run.Coverage)
			part, known := partitionFor(m, run, cov)
			if !known {
				names := make([]string, 0, len(cov.Surfaces))
				for name := range cov.Surfaces {
					names = append(names, name)
				}
				sort.Strings(names)
				for _, name := range names {
					if st := cov.Surfaces[name].State; surfaceCode(name, st) != "" {
						addGap(run, name, st)
					}
				}
				continue
			}
			for _, g := range partitionGaps(part, cov, "") {
				addGap(run, g.surface, g.state)
			}
		}
		if len(out.gaps[i]) == 0 && in.stale && in.docProtected {
			for _, run := range standing {
				cov := models.DecodeScanCoverage(run.Coverage)
				if st, present := stateIn(cov, models.SurfacePolicyDocuments); present && st != models.CloudCoverageReached {
					addGap(run, models.SurfacePolicyDocuments, st)
				}
			}
		}
	}

	for _, r := range refs {
		g := &out.gaps[r.claim][r.idx]
		sinceEntries = append(sinceEntries, &CoverageSurface{
			Surface: g.surface, State: g.state,
			connectorID: g.connector, runID: g.run, publishedAt: g.publishedAt,
		})
	}
	if err := q.coverageSince(sinceEntries); err != nil {
		return nil, err
	}
	for k, r := range refs {
		out.gaps[r.claim][r.idx].since = sinceEntries[k].Since
	}
	return out, nil
}
