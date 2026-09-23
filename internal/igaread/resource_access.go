package igaread

// GET /api/iga/v1/resources/:id/access (SPEC-iga-phase2-graph.md §5.3
// Resources, T6.3; D-12, D-17, D-18, D-62, D-77): who holds a GRANT whose
// statement names this reference as a POSITIVE target, and -- separately,
// never mixed into that list or its counts -- the statements that restrict it.
//
//	access                  one row per (holder, grant) whose statement names
//	                        the reference with mode = resource and effect
//	                        allow. A group-held grant is also one row per
//	                        member user of the group, with via_group (D-18).
//	                        Paged BY HOLDER: a holder's rows are never split
//	                        across pages (§2.14.6 "Resource › Access: one row
//	                        per (identity, statement), by identity").
//	excluded_by             Allow statements naming it in NotResource: they
//	                        EXCLUDE it; they grant "everything except" through
//	                        the implicit "*" selector, never this reference
//	                        (§5.4, B19).
//	deny_statements_naming  Deny statements naming it positively. A Deny
//	                        whose NotResource names it is in neither list: a
//	                        NotResource entry is always an exclusion (D-17).
//
// The list envelope (D-77): meta.limit, next_cursor and the optional total
// count HOLDERS, the unit the page is cut on. excluded_by and
// deny_statements_naming are not paged; each is capped at
// ResourceRestrictionCap statements (…_more says the cap bound), each
// statement's holders at ResourceRestrictionCap refs (holders_more).
//
// Every query is one statement per section (§5.6), never one per row, and
// every grant read joins iga_entitlements with effect = 'allow' (§3 rule 7):
// a projector defect cannot surface a Deny as access.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
)

// ResourceRestrictionCap bounds excluded_by and deny_statements_naming, and
// each of their statements' holders: at most this many, then a more flag.
const ResourceRestrictionCap = 100

// ResourceAccessView is data of GET /resources/:id/access.
type ResourceAccessView struct {
	Access                   []ResourceAccessRow   `json:"access"`
	ExcludedBy               []ResourceRestriction `json:"excluded_by"`
	ExcludedByMore           bool                  `json:"excluded_by_more"`
	DenyStatementsNaming     []ResourceRestriction `json:"deny_statements_naming"`
	DenyStatementsNamingMore bool                  `json:"deny_statements_naming_more"`
}

// ResourceAccessRow is one (holder, grant). state is the row's: the grant's,
// or for a member row the worse of the grant's and the membership's (ended >
// stale > current) -- a row is stale if either is stale, marked and never
// dropped (D-18).
type ResourceAccessRow struct {
	Holder    ResourceAccessHolder    `json:"holder"`
	ViaGroup  *ResourceAccessGroup    `json:"via_group"`
	Grant     ResourceAccessClaim     `json:"grant"`
	Policy    ResourceAccessPolicy    `json:"policy"`
	Statement ResourceAccessStatement `json:"statement"`
	State     string                  `json:"state"`
}

// ResourceAccessHolder is the identity a row is about.
type ResourceAccessHolder struct {
	Ref     string   `json:"ref"`
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`
	ARN     string   `json:"arn"`
	Account *Account `json:"account"`
}

// ResourceAccessGroup is via_group on a member row: the group that holds the
// grant, and the member_of claim (with its own state) that reaches the member.
type ResourceAccessGroup struct {
	Ref        string              `json:"ref"`
	Name       string              `json:"name"`
	Membership ResourceAccessClaim `json:"membership"`
}

// ResourceAccessClaim is a claim with its state: a grant, or a membership.
type ResourceAccessClaim struct {
	Claim     string `json:"claim"`
	State     string `json:"state"`
	ValidFrom any    `json:"valid_from"`
}

// ResourceAccessPolicy is the policy a statement belongs to.
type ResourceAccessPolicy struct {
	Ref  string `json:"ref"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// ResourceAccessStatement is one statement, as §5.3 renders statements
// everywhere: sid ("" when none), the 1-based index (D-84), and its Action /
// NotAction exactly as the document wrote them.
type ResourceAccessStatement struct {
	Ref         string   `json:"ref"`
	Sid         string   `json:"sid"`
	Index       *int     `json:"index"`
	Actions     []string `json:"actions"`
	NotActions  []string `json:"not_actions"`
	Conditional bool     `json:"conditional"`
}

// ResourceRestriction is one entry of excluded_by or deny_statements_naming:
// the statement, its policy, and the identities holding that policy -- refs,
// capped (holders_more).
type ResourceRestriction struct {
	Statement   ResourceAccessStatement `json:"statement"`
	Policy      ResourceAccessPolicy    `json:"policy"`
	Holders     []string                `json:"holders"`
	HoldersMore bool                    `json:"holders_more"`
}

// ResourceAccessRoute is the cursor route of one reference's Access (D-62):
// it carries the object, so a cursor for one resource cannot page another.
func ResourceAccessRoute(resourceID uuid.UUID) string {
	return "resources/" + resourceID.String() + "/access"
}

// rdetailAccessSort is the tab's one order (§2.14.6: by identity name; D-13:
// then account, unknown last, then id), bound into its cursor.
const rdetailAccessSort = "holder"

// rdetailAccessParams are the parameters the route accepts.
var rdetailAccessParams = map[string]bool{"limit": true, "cursor": true, "rev": true, "include_ended": true}

// rdetailAccessKey is Cursor.Key: the last holder's sort key, exactly as SQL
// computed it (lower() of the name, the unknown-account flag, the account).
type rdetailAccessKey struct {
	Name    string `json:"n"`
	NoAcct  int64  `json:"u"`
	Account string `json:"a"`
}

// ResourceAccess serves GET /resources/:id/access.
func (r *Reader) ResourceAccess(ctx context.Context, ws uuid.UUID, rawID string, vals url.Values) (any, error) {
	for name := range vals {
		if !rdetailAccessParams[name] {
			return nil, InvalidParameter(name, name+" is not a parameter of this route")
		}
	}
	limit := DefaultLimit
	if l := vals.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > MaxLimit {
			return nil, InvalidParameter("limit", fmt.Sprintf("limit must be 1-%d", MaxLimit))
		}
		limit = n
	}
	includeEnded := false
	switch vals.Get("include_ended") {
	case "", "false":
	case "true":
		includeEnded = true
	default:
		return nil, InvalidParameter("include_ended", "include_ended must be true or false")
	}
	rev, perr := ParseRev(vals)
	if perr != nil {
		return nil, perr
	}
	id, perr := RouteID(RefResource, rawID)
	if perr != nil {
		return nil, perr
	}

	filterHash := FilterHash(vals)
	pin := Pin{Rev: rev}
	var after *rdetailAccessAfter
	if tok := vals.Get("cursor"); tok != "" {
		c, cerr := r.OpenCursor(tok, CursorContext{WS: ws, Route: ResourceAccessRoute(id), Filter: filterHash, Sort: rdetailAccessSort})
		if cerr != nil {
			return nil, cerr
		}
		var k rdetailAccessKey
		if err := json.Unmarshal(c.Key, &k); err != nil {
			return nil, CursorInvalid("Malformed cursor.")
		}
		after = &rdetailAccessAfter{key: k, id: c.ID}
		pin.CursorRev = &c.Rev
	}

	// D-12: current and stale by default; include_ended adds ended rows.
	states := []string{StateCurrent, StateStale}
	if includeEnded {
		states = append(states, StateEnded)
	}

	var out Envelope
	err := r.Read(ctx, ws, pin, func(q *Query) error {
		if !q.Published() {
			return NotFound() // no object exists before the first publication (D-4)
		}
		rec, err := ResourceByID(q, id)
		if err != nil {
			return err
		}
		if rec == nil {
			return NotFound()
		}
		accts, err := q.LoadAccounts()
		if err != nil {
			return err
		}
		meta := NewListMeta(q, limit)

		// THE PAGE: one mandatory statement, limit+1 holders.
		sqlText, args := rdetailAccessPageSQL(q.WS, rec.ID, states, after, limit)
		var scans []rdetailAccessScan
		if err := q.DB().Raw(sqlText, args...).Scan(&scans).Error; err != nil {
			return err
		}
		rows, last, more := rdetailAccessRows(scans, accts, limit)
		if more {
			raw, err := json.Marshal(last.key)
			if err != nil {
				return err
			}
			tok := r.SignCursor(Cursor{WS: ws, Rev: q.Rev.Rev, Route: ResourceAccessRoute(rec.ID),
				Filter: filterHash, Sort: rdetailAccessSort, Key: raw, ID: last.id})
			meta.NextCursor = &tok
		}

		// The restrictions: mandatory -- a response that silently dropped a
		// Deny would read as broader access than the data declares.
		view := ResourceAccessView{Access: rows}
		if view.ExcludedBy, view.ExcludedByMore, err = rdetailRestrictions(q, rec.ID,
			models.TargetNotResource, models.EffectAllow, states); err != nil {
			return err
		}
		if view.DenyStatementsNaming, view.DenyStatementsNamingMore, err = rdetailRestrictions(q, rec.ID,
			models.TargetResource, models.EffectDeny, states); err != nil {
			return err
		}

		if meta.Coverage, err = ResourceCoverage(q, accts); err != nil {
			return err
		}

		// The total, in holders: optional (§5.2 Totals).
		var n int64
		ok, err := q.Optional(func(tx *gorm.DB) error {
			cte, cargs := rdetailAccessRowsCTE(q.WS, rec.ID, states)
			return tx.Raw(cte+`
			    SELECT count(*) FROM (
			        SELECT ia.id FROM iga_identity_accounts ia
			         WHERE ia.workspace_id = ? AND ia.provider = 'aws'
			           AND ia.id IN (SELECT holder_id FROM access_rows)
			         LIMIT ?) x`, append(cargs, q.WS, TotalCap+1)...).Row().Scan(&n)
		})
		if err != nil {
			return err
		}
		meta.SetTotal(n, ok)

		out = Envelope{Data: view, Meta: meta}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

/* ---------------------------------- access --------------------------------- */

// rdetailAccessAfter is a decoded cursor position: the last holder's key.
type rdetailAccessAfter struct {
	key rdetailAccessKey
	id  uuid.UUID
}

// rdetailAccessRowsCTE is the access rows as two CTEs, grants and rows, with
// their bind variables:
//
//	grants  every grant, in states, on an ALLOW statement naming the reference
//	        with mode = resource -- NEVER not_resource, which excludes
//	rows    each grant for its own holder, and for a group-held grant one row
//	        per member (member_of in states) whose membership period overlaps
//	        the grant's: a membership that ended before the grant began never
//	        carried it, and a row saying it did would claim access that never
//	        was (D-18)
//
// Statement lifecycle is not a condition: a live grant implies a live
// statement, and an ended grant on a retired statement is history
// include_ended asks for.
func rdetailAccessRowsCTE(ws, resourceID uuid.UUID, states []string) (string, []any) {
	return `WITH grants AS (
	    SELECT g.workspace_id, g.id AS grant_id, g.state AS grant_state, g.valid_from AS grant_valid_from,
	           g.valid_to AS grant_valid_to, g.subject_identity_account_id AS holder_id,
	           e.id AS statement_id, e.sid, e.statement_index, e.native_rights, e.conditional,
	           p.id AS policy_id, p.display_name AS policy_name, p.policy_kind
	      FROM iga_entitlement_target t
	      JOIN iga_entitlements e ON e.workspace_id = t.workspace_id AND e.id = t.entitlement_id
	      JOIN iga_policy p ON p.workspace_id = e.workspace_id AND p.id = e.policy_id
	      JOIN iga_access_edges g ON g.workspace_id = e.workspace_id AND g.entitlement_id = e.id
	     WHERE t.workspace_id = ? AND t.resource_id = ? AND t.target_mode = 'resource'
	       AND e.provider = 'aws' AND e.effect = 'allow' AND p.provider = 'aws'
	       AND g.provider = 'aws' AND g.subject_identity_account_id IS NOT NULL AND g.state IN ?),
	access_rows AS (
	    SELECT gr.workspace_id, gr.holder_id, gr.grant_id, gr.grant_state, gr.grant_valid_from,
	           gr.statement_id, gr.sid, gr.statement_index, gr.native_rights, gr.conditional,
	           gr.policy_id, gr.policy_name, gr.policy_kind,
	           NULL::uuid AS group_id, NULL::uuid AS membership_id, ''::text AS membership_state,
	           NULL::timestamptz AS membership_valid_from
	      FROM grants gr
	    UNION ALL
	    SELECT gr.workspace_id, m.source_identity_account_id, gr.grant_id, gr.grant_state, gr.grant_valid_from,
	           gr.statement_id, gr.sid, gr.statement_index, gr.native_rights, gr.conditional,
	           gr.policy_id, gr.policy_name, gr.policy_kind,
	           gr.holder_id, m.id, m.state, m.valid_from
	      FROM grants gr
	      JOIN iga_relationship m
	        ON m.workspace_id = gr.workspace_id AND m.relationship_type = '` + models.RelTypeMemberOf + `'
	       AND m.target_identity_account_id = gr.holder_id AND m.source_identity_account_id IS NOT NULL
	       AND m.state IN ?
	       AND m.valid_from < COALESCE(gr.grant_valid_to, 'infinity')
	       AND gr.grant_valid_from < COALESCE(m.valid_to, 'infinity'))
	`, []any{ws, resourceID, states, states}
}

// rdetailHolderKeySQL is a holder's sort key over iga_identity_accounts ia:
// (lower(name), unknown-account flag, account) -- D-13's name sort, unknown
// account last. No bind variables.
var rdetailHolderKeySQL = [3]string{
	`lower(ia.display_name)`,
	`(CASE WHEN ` + IdentityAccountSQL + ` = '' THEN 1 ELSE 0 END)`,
	IdentityAccountSQL,
}

// rdetailAccessPageSQL is the one page statement: limit+1 holders after the
// cursor's (holders CTE), then every row of each (the whole of a holder's rows
// is always on one page). Within a holder: direct rows before via-group rows,
// then policy name, statement index, and ids -- deterministic.
func rdetailAccessPageSQL(ws, resourceID uuid.UUID, states []string, after *rdetailAccessAfter, limit int) (string, []any) {
	cte, args := rdetailAccessRowsCTE(ws, resourceID, states)
	k := rdetailHolderKeySQL
	var b strings.Builder
	b.WriteString(cte)
	b.WriteString(`, holders AS (
	    SELECT ia.id, ` + k[0] + ` AS k0, ` + k[1] + ` AS k1, ` + k[2] + ` AS k2
	      FROM iga_identity_accounts ia
	     WHERE ia.workspace_id = ? AND ia.provider = 'aws' AND ia.id IN (SELECT holder_id FROM access_rows)`)
	args = append(args, ws)
	if after != nil {
		b.WriteString(`
	       AND (` + k[0] + `, ` + k[1] + `, ` + k[2] + `, ia.id) > (?::text, ?::int, ?::text, ?::uuid)`)
		args = append(args, after.key.Name, after.key.NoAcct, after.key.Account, after.id)
	}
	b.WriteString(`
	     ORDER BY k0, k1, k2, ia.id
	     LIMIT ?)
	SELECT h.k0, h.k1, h.k2,
	       ia.id AS holder_id, ia.display_name AS holder_name, ia.account_kind AS holder_kind,
	       ia.source_key AS holder_source_key, h.k2 AS holder_account,
	       rw.grant_id, rw.grant_state, rw.grant_valid_from,
	       rw.statement_id, rw.sid, rw.statement_index, rw.native_rights, rw.conditional,
	       rw.policy_id, rw.policy_name, rw.policy_kind,
	       rw.group_id, gi.display_name AS group_name,
	       rw.membership_id, rw.membership_state, rw.membership_valid_from
	  FROM holders h
	  JOIN iga_identity_accounts ia ON ia.workspace_id = ? AND ia.id = h.id
	  JOIN access_rows rw ON rw.holder_id = h.id
	  LEFT JOIN iga_identity_accounts gi ON gi.workspace_id = rw.workspace_id AND gi.id = rw.group_id
	 ORDER BY h.k0, h.k1, h.k2, h.id, (rw.group_id IS NOT NULL), lower(rw.policy_name), rw.policy_id,
	          rw.statement_index NULLS LAST, rw.statement_id, rw.group_id, rw.membership_valid_from, rw.grant_id`)
	args = append(args, limit+1, ws)
	return b.String(), args
}

// rdetailAccessScan is one row of the page statement.
type rdetailAccessScan struct {
	K0                  string
	K1                  int64
	K2                  string
	HolderID            uuid.UUID
	HolderName          string
	HolderKind          string
	HolderSourceKey     string
	HolderAccount       string
	GrantID             uuid.UUID
	GrantState          string
	GrantValidFrom      time.Time
	StatementID         uuid.UUID
	Sid                 string
	StatementIndex      *int
	NativeRights        json.RawMessage
	Conditional         bool
	PolicyID            uuid.UUID
	PolicyName          string
	PolicyKind          string
	GroupID             *uuid.UUID
	GroupName           *string
	MembershipID        *uuid.UUID
	MembershipState     string
	MembershipValidFrom *time.Time
}

// rdetailAccessRows renders the page: the rows of the first limit holders, the
// last kept holder's position, and whether a further holder exists.
func rdetailAccessRows(scans []rdetailAccessScan, accts *Accounts, limit int) ([]ResourceAccessRow, rdetailAccessAfter, bool) {
	out := []ResourceAccessRow{}
	var last rdetailAccessAfter
	holders := 0
	var prev uuid.UUID
	for _, s := range scans {
		if s.HolderID != prev {
			holders++
			if holders > limit {
				return out, last, true
			}
			prev = s.HolderID
			last = rdetailAccessAfter{key: rdetailAccessKey{Name: s.K0, NoAcct: s.K1, Account: s.K2}, id: s.HolderID}
		}
		row := ResourceAccessRow{
			Holder: ResourceAccessHolder{
				Ref: R(RefIdentity, s.HolderID), Name: s.HolderName, Kind: s.HolderKind,
				ARN: NativeOfKey(s.HolderSourceKey), Account: accts.Of(s.HolderAccount),
			},
			Grant:     ResourceAccessClaim{Claim: R(RefGrant, s.GrantID), State: s.GrantState, ValidFrom: T(s.GrantValidFrom)},
			Policy:    ResourceAccessPolicy{Ref: R(RefPolicy, s.PolicyID), Name: s.PolicyName, Kind: s.PolicyKind},
			Statement: rdetailStatement(s.StatementID, s.Sid, s.StatementIndex, s.NativeRights, s.Conditional),
			State:     s.GrantState,
		}
		if s.GroupID != nil && s.MembershipID != nil {
			name := ""
			if s.GroupName != nil {
				name = *s.GroupName
			}
			var from any
			if s.MembershipValidFrom != nil {
				from = T(*s.MembershipValidFrom)
			}
			row.ViaGroup = &ResourceAccessGroup{
				Ref: R(RefIdentity, *s.GroupID), Name: name,
				Membership: ResourceAccessClaim{Claim: R(RefRelationship, *s.MembershipID), State: s.MembershipState, ValidFrom: from},
			}
			row.State = rdetailWorseState(s.GrantState, s.MembershipState)
		}
		out = append(out, row)
	}
	return out, last, false
}

// rdetailWorseState is the row state of two claims that must both hold:
// ended if either ended, else stale if either is stale, else current (D-18).
func rdetailWorseState(a, b string) string {
	rank := func(s string) int {
		switch s {
		case StateEnded:
			return 2
		case StateStale:
			return 1
		}
		return 0
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

/* ------------------------------- restrictions ------------------------------ */

// rdetailRestrictions is one restriction section: the ACTIVE statements of
// this effect that name the reference with this target mode (at most
// ResourceRestrictionCap, then more), each with the identities that hold its
// policy through an assignment in states (at most ResourceRestrictionCap, then
// holders_more).
//
// The statement set is exactly what the Overview's counts count (active,
// provider aws, one row per statement by iga_et_key), so excluded_by and
// excluded_by_count agree (D-17). Holders come from ASSIGNMENTS, of every
// kind: a Deny statement is never a grant, and a Deny or an exclusion in a
// permissions boundary still bears on the identity it bounds -- leaving it out
// would make the access look broader than the data declares. Group holders
// are listed as the group.
func rdetailRestrictions(q *Query, resourceID uuid.UUID, mode, effect string, states []string) ([]ResourceRestriction, bool, error) {
	var stmts []struct {
		StatementID    uuid.UUID
		Sid            string
		StatementIndex *int
		NativeRights   json.RawMessage
		Conditional    bool
		PolicyID       uuid.UUID
		PolicyName     string
		PolicyKind     string
	}
	if err := q.DB().Raw(`SELECT e.id AS statement_id, e.sid, e.statement_index, e.native_rights, e.conditional,
	                             p.id AS policy_id, p.display_name AS policy_name, p.policy_kind
	                        FROM iga_entitlement_target t
	                        JOIN iga_entitlements e ON e.workspace_id = t.workspace_id AND e.id = t.entitlement_id
	                        JOIN iga_policy p ON p.workspace_id = e.workspace_id AND p.id = e.policy_id
	                       WHERE t.workspace_id = ? AND t.resource_id = ? AND t.target_mode = ?
	                         AND e.provider = 'aws' AND e.lifecycle = 'active' AND e.effect = ?
	                         AND p.provider = 'aws'
	                       ORDER BY lower(p.display_name), p.id, e.statement_index NULLS LAST, e.id
	                       LIMIT ?`,
		q.WS, resourceID, mode, effect, ResourceRestrictionCap+1).Scan(&stmts).Error; err != nil {
		return nil, false, err
	}
	more := len(stmts) > ResourceRestrictionCap
	if more {
		stmts = stmts[:ResourceRestrictionCap]
	}
	out := make([]ResourceRestriction, 0, len(stmts))
	if len(stmts) == 0 {
		return out, false, nil
	}
	ids := make([]uuid.UUID, len(stmts))
	for i, s := range stmts {
		ids[i] = s.StatementID
	}

	var holders []struct {
		StatementID uuid.UUID
		HolderID    uuid.UUID
	}
	k := rdetailHolderKeySQL
	if err := q.DB().Raw(`SELECT x.statement_id, x.holder_id FROM (
	                          SELECT d.statement_id, ia.id AS holder_id,
	                                 row_number() OVER (PARTITION BY d.statement_id
	                                                    ORDER BY `+k[0]+`, `+k[1]+`, `+k[2]+`, ia.id) AS n
	                            FROM (SELECT DISTINCT e.id AS statement_id, a.holder_identity_account_id AS holder_id
	                                    FROM iga_entitlements e
	                                    JOIN iga_policy_assignment a
	                                      ON a.workspace_id = e.workspace_id AND a.policy_id = e.policy_id
	                                   WHERE e.workspace_id = ? AND e.id IN ? AND a.state IN ?) d
	                            JOIN iga_identity_accounts ia
	                              ON ia.workspace_id = ? AND ia.id = d.holder_id AND ia.provider = 'aws') x
	                       WHERE x.n <= ?
	                       ORDER BY x.statement_id, x.n`,
		q.WS, ids, states, q.WS, ResourceRestrictionCap+1).Scan(&holders).Error; err != nil {
		return nil, false, err
	}
	byStmt := map[uuid.UUID][]string{}
	for _, h := range holders {
		byStmt[h.StatementID] = append(byStmt[h.StatementID], R(RefIdentity, h.HolderID))
	}
	for _, s := range stmts {
		hs := byStmt[s.StatementID]
		if hs == nil {
			hs = []string{}
		}
		hmore := len(hs) > ResourceRestrictionCap
		if hmore {
			hs = hs[:ResourceRestrictionCap]
		}
		out = append(out, ResourceRestriction{
			Statement:   rdetailStatement(s.StatementID, s.Sid, s.StatementIndex, s.NativeRights, s.Conditional),
			Policy:      ResourceAccessPolicy{Ref: R(RefPolicy, s.PolicyID), Name: s.PolicyName, Kind: s.PolicyKind},
			Holders:     hs,
			HoldersMore: hmore,
		})
	}
	return out, more, nil
}

/* -------------------------------- statements ------------------------------- */

// rdetailStatement renders a statement row. index is 1-based (D-84: stored
// statement_index + 1); actions and not_actions are read back from the stored
// verbatim statement.
func rdetailStatement(id uuid.UUID, sid string, index *int, native json.RawMessage, conditional bool) ResourceAccessStatement {
	var idx *int
	if index != nil {
		v := *index + 1
		idx = &v
	}
	actions, notActions := rdetailStatementActions(native)
	return ResourceAccessStatement{
		Ref: R(RefStatement, id), Sid: sid, Index: idx,
		Actions: actions, NotActions: notActions, Conditional: conditional,
	}
}

// rdetailStatementActions reads a statement's Action and NotAction back from
// iga_entitlements.native_rights -- the statement exactly as AWS returned it
// (§2.13 bet 1) -- through the SAME parser the collector and the projector
// read it with, so the tab can never render actions the graph did not act on.
// A stored value that is not an AWS statement is the models.NativeRights shape
// the projector's verbatim() falls back to. Both lists are [] rather than null
// when empty.
func rdetailStatementActions(native json.RawMessage) ([]string, []string) {
	nonNil := func(s []string) []string {
		if s == nil {
			return []string{}
		}
		return s
	}
	if len(native) > 0 {
		doc := `{"Statement":[` + string(native) + `]}`
		if stmts, _, err := awsdiscovery.ParsePolicyDocument(doc); err == nil && len(stmts) == 1 {
			return nonNil(stmts[0].Actions), nonNil(stmts[0].NotActions)
		}
		var nr models.NativeRights
		if err := json.Unmarshal(native, &nr); err == nil {
			return nonNil(nr.Actions), nonNil(nr.NotActions)
		}
	}
	return []string{}, []string{}
}
