package igaread

// GET /api/iga/v1/identities/:id/permissions (§5.3 Identities, T6.3; §2.6,
// §2.14.8; D-12, D-22, D-77, D-84, D-86): which policies apply to the
// identity and what each statement declares -- ONE ROW PER STATEMENT, grouped
// by policy, never merged (§2.14.6).
//
//	policies   the identity's own attached and inline policies, each with the
//	           assignment that applies it; Allow statements name their GRANT
//	           (the iga_access_edges row of THAT assignment and statement),
//	           Deny statements carry effect "deny" and no grant (§2.6: a
//	           restriction, never access)
//	boundary   the permissions boundary, if any: a ceiling, NEVER a grant --
//	           it appears here only, and its statements never name one
//	inherited  for a user, each group it is a member of, with the GROUP's
//	           policies and the group's grants (nothing is copied onto the
//	           user, §2.6); assignment.via_group names the group
//	activity   Access Advisor, labelled per §2.14.8: attempts, not outcomes
//
// Unpaged, with a hard statement cap (D-77): truncated is true when it binds.
// One query per piece (assignments, statements, targets, grants, revision
// counts), never one per row (§5.6); revision counts are optional.

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
)

// PermissionsStatementCap bounds the statements one Permissions response
// renders (D-77). AWS bounds policies per principal and document size, so a
// real identity stays far below it; a response that reaches it says so with
// truncated: true rather than silently dropping the rest.
const PermissionsStatementCap = 1000

// IdentityPermissionsView is the /identities/:id/permissions data object.
type IdentityPermissionsView struct {
	Identity  IdentityHeader      `json:"identity"`
	Policies  []PermissionPolicy  `json:"policies"`
	Boundary  PermissionBoundary  `json:"boundary"`
	Inherited []InheritedPolicies `json:"inherited"`
	Activity  IdentityActivity    `json:"activity"`
	Truncated bool                `json:"truncated"`
}

// PermissionPolicy is one policy as it applies through one assignment.
type PermissionPolicy struct {
	Ref        string                `json:"ref"`
	Name       string                `json:"name"`
	Kind       string                `json:"kind"`
	Assignment PermissionAssignment  `json:"assignment"`
	Statements []PermissionStatement `json:"statements"`
}

// PermissionAssignment is the claim that the policy applies to the holder
// (§5.2 assignment): attached, inline or boundary; via_group is the group
// whose assignment it is on an inherited policy, else null.
type PermissionAssignment struct {
	Claim       string         `json:"claim"`
	Kind        string         `json:"kind"`
	ViaGroup    any            `json:"via_group"`
	State       string         `json:"state"`
	StaleReason *[]StaleReason `json:"stale_reason,omitempty"`
	ValidFrom   any            `json:"valid_from"`
	ValidTo     any            `json:"valid_to,omitempty"`
	EndedReason string         `json:"ended_reason,omitempty"`
}

// PermissionStatement is one statement (§5.3): index is 1-based (D-84);
// actions and not_actions verbatim; targets both modes, labelled; condition
// verbatim (recorded, never evaluated). grant is the grant of THIS
// assignment and statement for an Allow, null for a Deny and on a boundary;
// grant_state is that grant's own state (a grant can be stale under a
// current assignment). state is the statement's D-1 state: a statement whose
// document could not be read is stale, and says so, rather than reading as
// current. revision_count counts its recorded content revisions (only a
// Sid-keyed statement is revised in place, §2.6; null when the optional count
// did not finish).
type PermissionStatement struct {
	Ref           string             `json:"ref"`
	Sid           string             `json:"sid"`
	Index         *int               `json:"index"`
	Effect        string             `json:"effect"`
	Actions       []string           `json:"actions"`
	NotActions    []string           `json:"not_actions"`
	Targets       []PermissionTarget `json:"targets"`
	Condition     json.RawMessage    `json:"condition"`
	Grant         any                `json:"grant"`
	GrantState    *string            `json:"grant_state"`
	RevisionCount *int64             `json:"revision_count"`
	State         string             `json:"state"`
	StaleReason   *[]StaleReason     `json:"stale_reason,omitempty"`
}

// PermissionTarget is one resource a statement names: mode "resource" (a
// positive target) or "not_resource" (an EXCLUSION, never a destination; a
// NotResource statement also names the implicit "*" it excludes from).
type PermissionTarget struct {
	Ref   string `json:"ref"`
	Claim string `json:"claim"`
	Text  string `json:"text"`
	Kind  string `json:"kind"`
	Mode  string `json:"mode"`
}

// PermissionBoundary is the holder's permissions boundary (§2.6): a ceiling
// the holder's own grants are clipped to, never a grant itself. policy is
// null when none is assigned. AWS allows one boundary per principal; others
// lists any further LIVE boundary assignment -- e.g. a replaced boundary
// whose partition could not end it -- so no claim is silently dropped.
type PermissionBoundary struct {
	Policy *PermissionPolicy  `json:"policy"`
	Others []PermissionPolicy `json:"others,omitempty"`
}

// InheritedPolicies is one group a user belongs to, the membership claim
// that says so (marked stale when it is, D-18), and the group's policies.
type InheritedPolicies struct {
	Group      string             `json:"group"`
	Name       string             `json:"name"`
	Membership ClaimFields        `json:"membership"`
	Policies   []PermissionPolicy `json:"policies"`
}

// IdentityPermissions serves GET /identities/:id/permissions. Parameters:
// rev, and include_ended (D-12), which adds ended assignments and memberships
// with their ended grants. 404 exactly as GetIdentity.
func (r *Reader) IdentityPermissions(ctx context.Context, ws uuid.UUID, rawID string, vals url.Values) (any, error) {
	rev, perr := idetailParams(vals, "rev", "include_ended")
	if perr != nil {
		return nil, perr
	}
	includeEnded, perr := idetailIncludeEnded(vals)
	if perr != nil {
		return nil, perr
	}
	id, nerr := RouteID(RefIdentity, rawID)
	if nerr != nil {
		return nil, nerr
	}
	var out Envelope
	err := r.Read(ctx, ws, Pin{Rev: rev}, func(q *Query) error {
		if !q.Published() {
			return NotFound()
		}
		ident, err := idetailLoadIdentity(q, id)
		if err != nil {
			return err
		}
		if ident == nil {
			return NotFound()
		}
		accts, err := q.LoadAccounts()
		if err != nil {
			return err
		}
		data, err := idetailPermissions(q, accts, ident, idetailEdgeStates(includeEnded))
		if err != nil {
			return err
		}
		meta := IdentityTabMeta{DetailMeta: NewDetailMeta(q)}
		if meta.Coverage, err = idetailCoverage(q, accts, idetailSupportPairs, []any{q.WS, id},
			idetailPermissionSurfaces(ident.AccountKind)); err != nil {
			return err
		}
		out = Envelope{Data: data, Meta: meta}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// idetailPermissionSurfaces is what bears on Permissions: the holder's own
// listing (its attachments and inline documents come with it), for a user the
// group listing its inherited policies come through, the managed-policy
// listing, unreadable documents, the permission scan, and Access Advisor.
func idetailPermissionSurfaces(kind string) idetailSurfaces {
	w := idetailSurfaces{exact: map[string]string{
		models.SurfaceIAMPolicies:     "managed policies and their statements",
		models.SurfacePolicyDocuments: "statements of policy documents that could not be read",
		models.SurfacePermissionScan:  "this identity's policies, statements and grants",
		models.SurfaceActivity:        "Access Advisor activity",
	}, revoked: "this identity's permissions are no longer refreshed"}
	switch kind {
	case models.CloudIdentityIAMRole:
		w.exact[models.SurfaceIAMRoles] = "this role's attached and inline policies"
	case models.CloudIdentityIAMUser:
		w.exact[models.SurfaceIAMUsers] = "this user's attached and inline policies and its boundary"
		w.exact[models.SurfaceIAMGroups] = "policies inherited through groups"
	case models.CloudIdentityIAMGroup:
		w.exact[models.SurfaceIAMGroups] = "this group's attached and inline policies"
	}
	return w
}

/* --------------------------------- reads ---------------------------------- */

type idetailGroupScan struct {
	RelationshipClaimRow
	GroupID     uuid.UUID
	DisplayName string
	AccountID   string
}

type idetailAssignmentScan struct {
	ID                      uuid.UUID
	PolicyID                uuid.UUID
	HolderIdentityAccountID uuid.UUID
	AssignmentKind          string
	State                   string
	ValidFrom               time.Time
	ValidTo                 *time.Time
	EndedReason             string
	ConnectorID             *uuid.UUID
	PartitionKey            string
	PolicyName              string
	PolicyKind              string
}

type idetailStatementScan struct {
	ID              uuid.UUID
	PolicyID        uuid.UUID
	Sid             string
	StatementIndex  *int
	Effect          string
	NativeRights    json.RawMessage
	State           string
	LastConfirmedAt *time.Time
}

type idetailTargetScan struct {
	ID            uuid.UUID
	EntitlementID uuid.UUID
	TargetMode    string
	ResourceID    uuid.UUID
	DisplayName   string
	Kind          string
}

type idetailGrantScan struct {
	ID            uuid.UUID
	AssignmentID  uuid.UUID
	EntitlementID uuid.UUID
	State         string
}

// idetailPermissions reads and assembles the Permissions tab.
func idetailPermissions(q *Query, accts *Accounts, ident *idetailIdentityRow, states []string) (*IdentityPermissionsView, error) {
	out := &IdentityPermissionsView{Identity: ident.header(), Policies: []PermissionPolicy{},
		Inherited: []InheritedPolicies{}}

	// The user's groups: member_of FROM it, over the expression the
	// idx_iga_relationship_source index is built on.
	var groups []idetailGroupScan
	if ident.AccountKind == models.CloudIdentityIAMUser {
		if err := q.DB().Raw(`SELECT `+idetailClaimColumns+`, ia.id AS group_id, ia.display_name,
		                             `+IdentityAccountSQL+` AS account_id
		                        FROM iga_relationship r
		                        JOIN iga_identity_accounts ia
		                          ON ia.workspace_id = r.workspace_id AND ia.id = r.target_identity_account_id
		                       WHERE r.workspace_id = ? AND r.relationship_type = ?
		                         AND COALESCE(r.source_identity_account_id, r.source_workload_id) = ?
		                         AND r.state IN ? AND ia.provider = 'aws'
		                       ORDER BY lower(ia.display_name), (`+IdentityAccountSQL+` = ''), `+IdentityAccountSQL+`, ia.id, r.id`,
			q.WS, models.RelTypeMemberOf, ident.ID, states).Scan(&groups).Error; err != nil {
			return nil, err
		}
	}
	holders := []uuid.UUID{ident.ID}
	for _, g := range groups {
		holders = append(holders, g.GroupID)
	}

	// Every assignment of the holder and its groups (idx_iga_pa_holder), by
	// policy name; live before ended.
	var asg []idetailAssignmentScan
	if err := q.DB().Raw(`SELECT a.id, a.policy_id, a.holder_identity_account_id, a.assignment_kind, a.state,
	                             a.valid_from, a.valid_to, a.ended_reason, a.connector_id, a.partition_key,
	                             p.display_name AS policy_name, p.policy_kind
	                        FROM iga_policy_assignment a
	                        JOIN iga_policy p ON p.workspace_id = a.workspace_id AND p.id = a.policy_id
	                       WHERE a.workspace_id = ? AND a.holder_identity_account_id IN ? AND a.state IN ?
	                         AND p.provider = 'aws'
	                       ORDER BY lower(p.display_name), p.id, (a.state = 'current') DESC, (a.state = 'stale') DESC,
	                                a.valid_from DESC, a.id`,
		q.WS, holders, states).Scan(&asg).Error; err != nil {
		return nil, err
	}

	// Split by where each assignment renders. A boundary renders ONLY under
	// boundary, and only the holder's own: a boundary on a group (which AWS
	// does not allow) is not the user's ceiling and never a grant.
	var own, bounds []idetailAssignmentScan
	byGroup := map[uuid.UUID][]idetailAssignmentScan{}
	for _, a := range asg {
		switch {
		case a.HolderIdentityAccountID == ident.ID && a.AssignmentKind == models.AssignmentBoundary:
			bounds = append(bounds, a)
		case a.AssignmentKind == models.AssignmentBoundary:
		case a.HolderIdentityAccountID == ident.ID:
			own = append(own, a)
		default:
			byGroup[a.HolderIdentityAccountID] = append(byGroup[a.HolderIdentityAccountID], a)
		}
	}

	// boundary.policy is the boundary in force: current before stale before
	// ended (include_ended), newest first -- not the alphabetically first.
	sort.SliceStable(bounds, func(i, j int) bool {
		ri, rj := idetailStateRank(bounds[i].State), idetailStateRank(bounds[j].State)
		if ri != rj {
			return ri < rj
		}
		return bounds[i].ValidFrom.After(bounds[j].ValidFrom)
	})

	// The display order of every assignment: own, boundary, then each group's.
	ordered := append(append([]idetailAssignmentScan{}, own...), bounds...)
	for _, g := range groups {
		ordered = append(ordered, byGroup[g.GroupID]...)
	}
	stmts, err := idetailStatements(q, ordered)
	if err != nil {
		return nil, err
	}
	stmtIDs := make([]uuid.UUID, 0, len(stmts))
	for _, s := range stmts {
		stmtIDs = append(stmtIDs, s.ID)
	}
	targets, err := idetailTargets(q, stmtIDs)
	if err != nil {
		return nil, err
	}
	// Grants: ONLY through assignments that can grant -- never a boundary's
	// (§2.6), keyed by (assignment, statement) so a policy that is also
	// attached elsewhere can never lend a boundary its grant.
	var granting []uuid.UUID
	for _, a := range ordered {
		if a.AssignmentKind != models.AssignmentBoundary {
			granting = append(granting, a.ID)
		}
	}
	grants, err := idetailGrants(q, granting, stmtIDs, states)
	if err != nil {
		return nil, err
	}
	revisions, err := idetailRevisionCounts(q, stmtIDs)
	if err != nil {
		return nil, err
	}

	// stale_reason (D-74): stale statements (nodes), stale assignments and
	// memberships (claims).
	var staleStmts []StaleSubject
	for _, s := range stmts {
		if s.State == StateStale {
			staleStmts = append(staleStmts, StaleSubject{ID: s.ID})
		}
	}
	stmtReasons, err := NodeStaleReasons(q, accts, "entitlement_id", staleStmts)
	if err != nil {
		return nil, err
	}
	var staleClaims []ClaimStaleSubject
	for _, a := range ordered {
		if a.State == StateStale {
			staleClaims = append(staleClaims, ClaimStaleSubject{ID: a.ID, ConnectorID: a.ConnectorID, PartitionKey: a.PartitionKey})
		}
	}
	for _, g := range groups {
		if g.RelState == StateStale {
			staleClaims = append(staleClaims, g.staleSubject())
		}
	}
	claimReasons, err := ClaimStaleReasons(q, accts, staleClaims)
	if err != nil {
		return nil, err
	}

	byPolicy := map[uuid.UUID][]idetailStatementScan{}
	for _, s := range stmts {
		byPolicy[s.PolicyID] = append(byPolicy[s.PolicyID], s)
	}
	budget := PermissionsStatementCap
	render := func(a idetailAssignmentScan, viaGroup any) PermissionPolicy {
		p := PermissionPolicy{
			Ref: R(RefPolicy, a.PolicyID), Name: a.PolicyName, Kind: a.PolicyKind,
			Assignment: PermissionAssignment{
				Claim: R(RefAssignment, a.ID), Kind: a.AssignmentKind, ViaGroup: viaGroup, State: a.State,
				StaleReason: StaleReasonOf(a.State, a.ID, claimReasons), ValidFrom: T(a.ValidFrom),
			},
			Statements: []PermissionStatement{},
		}
		if a.State == StateEnded {
			p.Assignment.ValidTo, p.Assignment.EndedReason = TS(a.ValidTo), a.EndedReason
		}
		for _, s := range byPolicy[a.PolicyID] {
			if budget == 0 {
				out.Truncated = true
				break
			}
			budget--
			st := idetailRenderStatement(s, targets[s.ID], revisions, stmtReasons)
			// grants holds only Allow statements' grants of assignments that
			// can grant (idetailGrants, granting above): a Deny statement and
			// a boundary never find one here, whatever a defective row says.
			if g, ok := grants[idetailGrantKey{a.ID, s.ID}]; ok {
				st.Grant = R(RefGrant, g.ID)
				state := g.State
				st.GrantState = &state
			}
			p.Statements = append(p.Statements, st)
		}
		return p
	}

	for _, a := range own {
		out.Policies = append(out.Policies, render(a, nil))
	}
	for i, a := range bounds {
		p := render(a, nil)
		if i == 0 {
			out.Boundary.Policy = &p
		} else {
			out.Boundary.Others = append(out.Boundary.Others, p)
		}
	}
	for _, g := range groups {
		group := R(RefIdentity, g.GroupID)
		inh := InheritedPolicies{Group: group, Name: g.DisplayName, Membership: g.fields(claimReasons),
			Policies: []PermissionPolicy{}}
		for _, a := range byGroup[g.GroupID] {
			inh.Policies = append(inh.Policies, render(a, group))
		}
		out.Inherited = append(out.Inherited, inh)
	}

	act, err := idetailActivity(q, ident)
	if err != nil {
		return nil, err
	}
	out.Activity = act
	return out, nil
}

// idetailStateRank orders claim states: current, stale, ended.
func idetailStateRank(state string) int {
	switch state {
	case StateCurrent:
		return 0
	case StateStale:
		return 1
	}
	return 2
}

// idetailStatements reads the ACTIVE statements of every policy the ordered
// assignments apply, in display order (the policy's first appearance, then
// the stored statement_index, D-84), at most PermissionsStatementCap+1 rows --
// a bound on the query only: the render budget is what caps the response and
// says truncated, since one policy can render under several assignments.
func idetailStatements(q *Query, ordered []idetailAssignmentScan) ([]idetailStatementScan, error) {
	var values []string
	var args []any
	seen := map[uuid.UUID]bool{}
	for _, a := range ordered {
		if seen[a.PolicyID] {
			continue
		}
		seen[a.PolicyID] = true
		values = append(values, "(?::uuid, ?::int)")
		args = append(args, a.PolicyID, len(values))
	}
	if len(values) == 0 {
		return nil, nil
	}
	args = append(args, q.WS, PermissionsStatementCap+1)
	var rows []idetailStatementScan
	if err := q.DB().Raw(`SELECT e.id, e.policy_id, e.sid, e.statement_index, e.effect, e.native_rights,
	                             sup.state, sup.last_confirmed_at
	                        FROM iga_entitlements e
	                        JOIN (VALUES `+strings.Join(values, ", ")+`) AS o(policy_id, rank) ON o.policy_id = e.policy_id
	                        `+SupportLateral("e", "entitlement_id")+`
	                       WHERE e.workspace_id = ? AND e.provider = 'aws' AND e.lifecycle = 'active'
	                       ORDER BY o.rank, e.statement_index NULLS LAST, e.id
	                       LIMIT ?`, args...).Scan(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// idetailTargets reads every target of the statements, positive targets
// first, each list in the statement's own order (ordinal). kind is the D-16
// API kind, computed by the same ResourceKindSQL the resource list uses.
func idetailTargets(q *Query, stmtIDs []uuid.UUID) (map[uuid.UUID][]PermissionTarget, error) {
	out := map[uuid.UUID][]PermissionTarget{}
	if len(stmtIDs) == 0 {
		return out, nil
	}
	var rows []idetailTargetScan
	if err := q.DB().Raw(`SELECT t.id, t.entitlement_id, t.target_mode, r.id AS resource_id, r.display_name,
	                             `+ResourceKindSQL+` AS kind
	                        FROM iga_entitlement_target t
	                        JOIN iga_resources r ON r.workspace_id = t.workspace_id AND r.id = t.resource_id
	                       WHERE t.workspace_id = ? AND t.entitlement_id IN ? AND r.provider = 'aws'
	                       ORDER BY t.entitlement_id, (t.target_mode = 'resource') DESC, t.ordinal, t.id`,
		q.WS, stmtIDs).Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, t := range rows {
		out[t.EntitlementID] = append(out[t.EntitlementID], PermissionTarget{
			Ref: R(RefResource, t.ResourceID), Claim: R(RefTarget, t.ID),
			Text: t.DisplayName, Kind: t.Kind, Mode: t.TargetMode,
		})
	}
	return out, nil
}

type idetailGrantKey struct{ assignment, statement uuid.UUID }

// idetailGrants reads the grant of each (assignment, statement): the
// iga_access_edges row of that assignment and statement, joined to its
// statement with effect = 'allow' so a projector defect can never surface a
// Deny as access (§3 rule 7). Live before ended, newest first.
func idetailGrants(q *Query, assignments, stmtIDs []uuid.UUID, states []string) (map[idetailGrantKey]idetailGrantScan, error) {
	out := map[idetailGrantKey]idetailGrantScan{}
	if len(assignments) == 0 || len(stmtIDs) == 0 {
		return out, nil
	}
	var rows []idetailGrantScan
	if err := q.DB().Raw(`SELECT g.id, g.assignment_id, g.entitlement_id, g.state
	                        FROM iga_access_edges g
	                        JOIN iga_entitlements e ON e.workspace_id = g.workspace_id AND e.id = g.entitlement_id
	                       WHERE g.workspace_id = ? AND g.provider = 'aws'
	                         AND g.entitlement_id IN ? AND g.assignment_id IN ? AND g.state IN ?
	                         AND e.provider = 'aws' AND e.effect = 'allow'
	                       ORDER BY g.assignment_id, g.entitlement_id, (g.state = 'current') DESC,
	                                (g.state = 'stale') DESC, g.valid_from DESC, g.id`,
		q.WS, stmtIDs, assignments, states).Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, g := range rows {
		k := idetailGrantKey{g.AssignmentID, g.EntitlementID}
		if _, has := out[k]; !has {
			out[k] = g
		}
	}
	return out, nil
}

// idetailRevisionCounts counts each statement's recorded revisions, as
// OPTIONAL work: a count that does not finish leaves every revision_count
// null. (iga_statement_revision has no index on entitlement_id beyond the
// live-revision one; see the report's DDL proposal.)
func idetailRevisionCounts(q *Query, stmtIDs []uuid.UUID) (map[uuid.UUID]int64, error) {
	if len(stmtIDs) == 0 {
		return map[uuid.UUID]int64{}, nil
	}
	var rows []struct {
		EntitlementID uuid.UUID
		N             int64
	}
	ok, err := q.Optional(func(tx *gorm.DB) error {
		return tx.Raw(`SELECT entitlement_id, count(*) AS n FROM iga_statement_revision
		                WHERE workspace_id = ? AND entitlement_id IN ? GROUP BY entitlement_id`,
			q.WS, stmtIDs).Scan(&rows).Error
	})
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil // unknown: every revision_count renders null
	}
	out := map[uuid.UUID]int64{}
	for _, r := range rows {
		out[r.EntitlementID] = r.N
	}
	return out, nil
}

// idetailRenderStatement renders one statement row, without its grant.
func idetailRenderStatement(s idetailStatementScan, targets []PermissionTarget, revisions map[uuid.UUID]int64,
	reasons map[uuid.UUID][]StaleReason) PermissionStatement {
	actions, notActions, cond := StatementContent(s.NativeRights)
	st := PermissionStatement{
		Ref: R(RefStatement, s.ID), Sid: s.Sid, Index: StatementIndexOf(s.StatementIndex), Effect: s.Effect,
		Actions: actions, NotActions: notActions, Targets: targets, Condition: cond,
		State: s.State, StaleReason: StaleReasonOf(s.State, s.ID, reasons),
	}
	if st.Targets == nil {
		st.Targets = []PermissionTarget{}
	}
	if revisions != nil {
		n := revisions[s.ID]
		st.RevisionCount = &n
	}
	return st
}

// StatementContent reads a statement's actions, not_actions and condition
// from its stored native_rights -- the statement exactly as AWS returned it
// (igagraph's verbatim), parsed by the SAME awsdiscovery parser the projector
// read it with, so the tab can never show a different reading of it; or, for
// a statement stored in the fallback models.NativeRights shape, that shape.
// Lists are never nil; condition is null when the statement has none.
func StatementContent(raw json.RawMessage) (actions, notActions []string, condition json.RawMessage) {
	actions, notActions = []string{}, []string{}
	if stmts, _, err := awsdiscovery.ParsePolicyDocument(`{"Statement":[` + string(raw) + `]}`); err == nil && len(stmts) == 1 {
		st := stmts[0]
		actions = append(actions, st.Actions...)
		notActions = append(notActions, st.NotActions...)
		if st.Condition != "" {
			condition = json.RawMessage(st.Condition)
		}
		return actions, notActions, condition
	}
	var nr models.NativeRights
	if err := json.Unmarshal(raw, &nr); err == nil {
		actions = append(actions, nr.Actions...)
		notActions = append(notActions, nr.NotActions...)
		condition = NullableJSON(nr.Condition)
	}
	return actions, notActions, condition
}

/* -------------------------------- activity -------------------------------- */

// ActivityTrackingNote is the §2.14.8 label every activity block carries,
// stated once: what Access Advisor reports and, as importantly, what it does
// not. It never says "last used", "never used" or "unused".
const ActivityTrackingNote = "Last authenticated attempts reported by IAM Access Advisor " +
	"(iam:GenerateServiceLastAccessedDetails). An attempt is not an outcome: a request that was then " +
	"denied is still reported. The tracking period is at least 400 days, or shorter where the Region " +
	"began tracking more recently. Only access through identity-based policies is reported: access " +
	"allowed by resource-based policies, ACLs, AWS Organizations SCPs, permissions boundaries or session " +
	"policies never appears. Action-level data covers management events only. A null " +
	"last_authenticated_attempt means no attempt was reported in the available tracking period. " +
	"This is not authoritative (CloudTrail is) and is never on its own a reason to revoke access."

// Why activity is not collected for an identity (D-86: never "no attempts").
const (
	ActivityRetired       = "retired"             // the identity is not in the latest scan
	ActivityNotRead       = "not_read"            // the run the revision was built from did not read activity
	ActivityNotInScan     = "not_in_scan"         // no inventory row of this principal in that scan
	ActivityOutsideSample = "outside_sample"      // above the per-scan identity cap (T3.7)
	ActivityReportNotRead = "report_not_read"     // sampled, but no report of it is known to have been read
	ActivitySurfaceFailed = "surface_not_reached" // the activity surface was denied, throttled ...
)

// IdentityActivity is Access Advisor for one identity (§5.3, §2.14.8, D-86):
// state collected with services ([] when AWS reported none), or
// not_collected with services null and the reason -- an identity outside
// the capped sample, or a surface that was not reached, is not_collected,
// never "no attempts".
type IdentityActivity struct {
	Source       string            `json:"source"`
	State        string            `json:"state"`
	Reason       *string           `json:"reason"`
	TrackingNote string            `json:"tracking_note"`
	Services     []ActivityService `json:"services"`
}

// ActivityService is one service namespace and its last authenticated
// attempt; null is "No attempt reported in the available tracking period".
type ActivityService struct {
	Namespace                string `json:"namespace"`
	LastAuthenticatedAttempt any    `json:"last_authenticated_attempt"`
}

// Activity states (D-86).
const (
	ActivityCollected    = "collected"
	ActivityNotCollected = "not_collected"
)

// idetailActivity reads the identity's Access Advisor activity from
// cloud_usage (D-25), keyed to the run the current revision was built from:
//
//  1. a retired identity is not_collected: the principal a live cloud row
//     now describes may be its successor (a recreated role keeps the ARN);
//  2. the run is iga_projection_state's for the identity's own live support
//     row (current preferred), and its coverage's activity surface decides:
//     absent -> not read; reached -> collected; partial -> the capped sample
//     is named by capped_after (D-86, byte order of the ARN, which is Go's
//     string order): an ARN after it was not sampled; a sampled one counts
//     as collected only when that run's rows for it exist (a partial read
//     cannot tell "no services" from "report failed"); any other state ->
//     not collected;
//  3. the cloud row is the same principal: its ARN, its connector, and its
//     unique id when the graph holds one;
//  4. rows are those that run (or a later one) confirmed -- last_seen_generation
//     at or above the run's generation; an older row that run did not report
//     is not part of the revision's answer.
func idetailActivity(q *Query, ident *idetailIdentityRow) (IdentityActivity, error) {
	act := IdentityActivity{Source: "access_advisor", State: ActivityNotCollected, TrackingNote: ActivityTrackingNote}
	notCollected := func(reason string) (IdentityActivity, error) {
		act.Reason = &reason
		return act, nil
	}
	if ident.Lifecycle != models.IGALifecycleActive {
		return notCollected(ActivityRetired)
	}
	var runs []struct {
		ConnectorID uuid.UUID
		Generation  int
		Coverage    json.RawMessage
	}
	if err := q.DB().Raw(`SELECT s.connector_id, sr.generation, sr.coverage
	                        FROM iga_object_support s
	                        JOIN iga_projection_state ps ON ps.workspace_id = s.workspace_id
	                         AND ps.connector_id = s.connector_id AND ps.partition_key = s.partition_key
	                        JOIN cloud_scan_run sr ON sr.workspace_id = ps.workspace_id AND sr.id = ps.last_run_id
	                       WHERE s.workspace_id = ? AND s.identity_account_id = ? AND s.state <> 'ended'
	                       ORDER BY (s.state = 'current') DESC, sr.published_at DESC NULLS LAST, sr.id
	                       LIMIT 1`, q.WS, ident.ID).Scan(&runs).Error; err != nil {
		return act, err
	}
	if len(runs) == 0 {
		return notCollected(ActivityNotRead)
	}
	run := runs[0]
	surf, read := models.DecodeScanCoverage(run.Coverage).Surfaces[models.SurfaceActivity]
	if !read {
		return notCollected(ActivityNotRead)
	}
	arn := NativeOfKey(ident.SourceKey)
	var cloudIDs []uuid.UUID
	if err := q.DB().Raw(`SELECT ci.id FROM cloud_identity ci
	                       WHERE ci.workspace_id = ? AND ci.connector_id = ? AND ci.native_id = ?
	                         AND (? = '' OR COALESCE(ci.attrs->>'unique_id', '') = ?)`,
		q.WS, run.ConnectorID, arn, ident.ImmutableKey, ident.ImmutableKey).Scan(&cloudIDs).Error; err != nil {
		return act, err
	}
	if len(cloudIDs) == 0 {
		return notCollected(ActivityNotInScan)
	}
	switch surf.State {
	case models.CloudCoverageReached, models.CloudCoveragePartial:
	default:
		return notCollected(ActivitySurfaceFailed)
	}
	if surf.State == models.CloudCoveragePartial && surf.CappedAfter != "" && arn > surf.CappedAfter {
		return notCollected(ActivityOutsideSample)
	}
	var rows []struct {
		Service    string
		LastUsedAt *time.Time
	}
	if err := q.DB().Raw(`SELECT u.service, u.last_used_at FROM cloud_usage u
	                       WHERE u.workspace_id = ? AND u.identity_id = ? AND u.connector_id = ?
	                         AND u.source = ? AND u.last_seen_generation >= ?
	                       ORDER BY u.service`,
		q.WS, cloudIDs[0], run.ConnectorID, models.UsageSourceServiceLastAccessed, run.Generation).Scan(&rows).Error; err != nil {
		return act, err
	}
	if surf.State == models.CloudCoveragePartial && len(rows) == 0 {
		return notCollected(ActivityReportNotRead)
	}
	act.State, act.Services = ActivityCollected, make([]ActivityService, 0, len(rows))
	for _, r := range rows {
		act.Services = append(act.Services, ActivityService{Namespace: r.Service, LastAuthenticatedAttempt: TS(r.LastUsedAt)})
	}
	return act, nil
}
