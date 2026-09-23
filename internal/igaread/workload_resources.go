package igaread

// GET /api/iga/v1/workloads/:id/resources (SPEC-iga-phase2-graph.md §5.3,
// §2.14.6 "Detail tabs", §2.6, §3 rule 7; D-12, D-13, D-16, D-22, D-62, D-73,
// D-74, D-77, D-78, D-84): every resource the workload's execution identities
// hold a GRANT to -- one row per target, and under it one line per grant.
//
// Holders (D-78): the identities the workload's executes_as claims reach
// (current or stale), and the groups those identities are members of (§5.3
// "and their groups"; normally none, an IAM role cannot be a group member).
// NOT ECS's task_execution_role: that is the role ECS uses, not the task's
// identity (§2.2 l.359). No can_assume hop: a role the workload may assume is
// the Identities tab's may_assume, never access the workload holds.
//
// A grant is an iga_access_edges row joined to an ALLOW statement (§3 rule 7:
// every grant query re-checks effect, so a projector defect cannot surface a
// Deny as access). Positive targets only (target_mode = resource): a
// NotResource statement names what it EXCLUDES, never a destination, so it
// contributes only its implicit "*" row, with its exclusions listed on the
// grant line -- and no row ever ends at an excluded resource (B19). Two
// statements granting the same action are two lines, never merged (E3, E6).
//
// restrictions are holder-level (D-78): the Deny statements the row's
// holders hold (for a group-reached line, the group's too, D-22), and whether
// any of them has a permissions boundary. Whether a Deny's targets match this
// resource is NOT evaluated, and neither is the boundary's content: they are
// shown as restrictions to read, never subtracted from the grants.
//
// Paged by resource with the §5.2 list envelope (D-77): sort kind (the
// default: exact < selector < external, then name, then account, D-13) or
// name, - for descending; limit 1-200, default 100; a signed cursor whose
// route carries the workload (D-62). Grants within a resource are not paged
// (§5.3: bounded by the policies attached).

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

// WorkloadResourceRef is the resource of one row: {ref, text, kind, type,
// service, account, region} -- the resource list row's own expressions
// (ResourceColumns), so a reference reads the same here as on /resources.
type WorkloadResourceRef struct {
	Ref     string   `json:"ref"`
	Text    string   `json:"text"`
	Kind    string   `json:"kind"`
	Type    string   `json:"type"`
	Service *string  `json:"service"`
	Account *Account `json:"account"`
	Region  *string  `json:"region"`
}

// ResourceExclusion is one exclusion of a NotResource statement: the resource
// it names in NotResource, listed on the grant line of its "*" row.
type ResourceExclusion struct {
	Ref  string `json:"ref"`
	Text string `json:"text"`
}

// WorkloadGrantLine is one grant under a resource: the claim, the execution
// identity it reaches the workload through (via_identity) and -- when the
// grant is a group's -- the group (via_group), the policy and statement that
// declare it, the target mode (always resource: positive targets only), the
// statement's exclusions ([] unless it is a NotResource statement), and the
// grant's own state. A group-reached line is stale when either the grant or
// the membership is (D-18's rule): marked, never dropped.
type WorkloadGrantLine struct {
	Claim           string              `json:"claim"`
	ViaIdentity     string              `json:"via_identity"`
	ViaGroup        *string             `json:"via_group,omitempty"`
	Policy          PolicyBrief         `json:"policy"`
	Statement       StatementBrief      `json:"statement"`
	TargetMode      string              `json:"target_mode"`
	Exclusions      []ResourceExclusion `json:"exclusions"`
	State           string              `json:"state"`
	StaleReason     *[]StaleReason      `json:"stale_reason,omitempty"`
	ValidFrom       any                 `json:"valid_from"`
	ValidTo         any                 `json:"valid_to,omitempty"`
	EndedReason     string              `json:"ended_reason,omitempty"`
	LastConfirmedAt any                 `json:"last_confirmed_at"`
}

// WorkloadRestrictions are a row's holder-level restrictions (D-78).
type WorkloadRestrictions struct {
	DenyStatements      int  `json:"deny_statements"`
	PermissionsBoundary bool `json:"permissions_boundary"`
}

// WorkloadResourceRow is one row of the tab.
type WorkloadResourceRow struct {
	Resource     WorkloadResourceRef  `json:"resource"`
	Grants       []WorkloadGrantLine  `json:"grants"`
	Restrictions WorkloadRestrictions `json:"restrictions"`
}

// WorkloadResourcesMeta is the list envelope's meta (§5.2) and the workload
// the tab is about (retired or not, so an empty tab of a retired workload can
// say it has no current data).
type WorkloadResourcesMeta struct {
	ListMeta
	Workload WorkloadSubject `json:"workload"`
}

// workloadResourcesRoute is the tab's cursor route (D-62).
func workloadResourcesRoute(workloadID uuid.UUID) string {
	return "workloads/" + workloadID.String() + "/resources"
}

// workloadResourceScan is one page row: the resource record and its sort keys.
type workloadResourceScan struct {
	ResourceRecord
	K0 *string `gorm:"column:k0"`
	K1 *string `gorm:"column:k1"`
	K2 *string `gorm:"column:k2"`
	K3 *string `gorm:"column:k3"`
	K4 *string `gorm:"column:k4"`
	K5 *string `gorm:"column:k5"`
}

func (s workloadResourceScan) rowID() uuid.UUID { return s.ID }
func (s workloadResourceScan) sortKeys() []*string {
	return []*string{s.K0, s.K1, s.K2, s.K3, s.K4, s.K5}
}

// workloadGrantsFrom / workloadGrantsWhere are the grant path the tab is
// built on: a grant of a holder, in the asked-for states, to an ALLOW
// statement (rule 7), reached through an attached or inline assignment -- a
// boundary is never a grant (§2.6), so a grant row under one would be a
// projector defect and is not shown as access -- through a POSITIVE target
// (never NotResource). The page selects the targets' resources from it and
// the lines read every grant on it. Bind order of the WHERE: workspace,
// holders, states.
const (
	workloadGrantsFrom = `
	      FROM iga_access_edges g
	      JOIN iga_entitlements e
	        ON e.workspace_id = g.workspace_id AND e.id = g.entitlement_id
	       AND e.provider = 'aws' AND e.effect = 'allow'
	      JOIN iga_policy_assignment a
	        ON a.workspace_id = g.workspace_id AND a.id = g.assignment_id
	       AND a.assignment_kind <> 'boundary'
	      JOIN iga_entitlement_target t
	        ON t.workspace_id = e.workspace_id AND t.entitlement_id = e.id
	       AND t.target_mode = 'resource'`
	workloadGrantsWhere = `
	     WHERE g.workspace_id = ? AND g.provider = 'aws'
	       AND g.subject_identity_account_id IN ? AND g.state IN ?`
)

// workloadHolders is the tab's holder set (D-78).
type workloadHolders struct {
	exec []uuid.UUID // execution identities: executes_as targets, current or stale
	// memberOf is each group's member execution identities, with the
	// membership's state.
	memberOf map[uuid.UUID][]workloadMembership
	groupsOf map[uuid.UUID][]uuid.UUID // execution identity -> its groups
	all      []uuid.UUID               // exec ∪ groups: the grant subjects read
}

type workloadMembership struct {
	member uuid.UUID
	state  string
}

func (q *Query) workloadHolders(workloadID uuid.UUID) (*workloadHolders, error) {
	h := &workloadHolders{memberOf: map[uuid.UUID][]workloadMembership{}, groupsOf: map[uuid.UUID][]uuid.UUID{}}
	if err := q.DB().Raw(`SELECT DISTINCT r.target_identity_account_id
	                        FROM iga_relationship r
	                       WHERE r.workspace_id = ? AND r.relationship_type = ?
	                         AND COALESCE(r.source_identity_account_id, r.source_workload_id) = ?
	                         AND r.state IN ('current', 'stale')
	                       ORDER BY 1`, q.WS, models.RelTypeExecutesAs, workloadID).Scan(&h.exec).Error; err != nil {
		return nil, err
	}
	h.all = append(h.all, h.exec...)
	if len(h.exec) == 0 {
		return h, nil
	}
	var ms []struct {
		Member uuid.UUID
		Group  uuid.UUID
		State  string
	}
	if err := q.DB().Raw(`SELECT r.source_identity_account_id AS member, r.target_identity_account_id AS "group", r.state
	                        FROM iga_relationship r
	                       WHERE r.workspace_id = ? AND r.relationship_type = ?
	                         AND COALESCE(r.source_identity_account_id, r.source_workload_id) IN ?
	                         AND r.state IN ('current', 'stale')
	                       ORDER BY 2, 1`, q.WS, models.RelTypeMemberOf, h.exec).Scan(&ms).Error; err != nil {
		return nil, err
	}
	for _, m := range ms {
		if _, seen := h.memberOf[m.Group]; !seen {
			h.all = append(h.all, m.Group)
		}
		h.memberOf[m.Group] = append(h.memberOf[m.Group], workloadMembership{member: m.Member, state: m.State})
		h.groupsOf[m.Member] = append(h.groupsOf[m.Member], m.Group)
	}
	return h, nil
}

// workloadGrantRow is one grant to one of the page's resources.
type workloadGrantRow struct {
	ResourceID      uuid.UUID
	GrantID         uuid.UUID
	SubjectID       uuid.UUID
	State           string
	ValidFrom       time.Time
	ValidTo         *time.Time
	EndedReason     string
	LastConfirmedAt time.Time
	ConnectorID     *uuid.UUID
	PartitionKey    string
	StatementID     uuid.UUID
	Sid             string
	StatementIndex  *int
	NativeRights    json.RawMessage
	Conditional     bool
	PolicyID        uuid.UUID
	PolicyName      string
	PolicyKind      string
}

// WorkloadResources serves GET /api/iga/v1/workloads/:id/resources.
// Parameters: rev, sort (kind | name, - for descending), limit, cursor,
// include_ended (D-12).
func (r *Reader) WorkloadResources(ctx context.Context, ws uuid.UUID, rawID string, vals url.Values) (any, error) {
	if perr := RouteParams(vals, "rev", "sort", "limit", "cursor", "include_ended"); perr != nil {
		return nil, perr
	}
	p, perr := ParseListParams(vals, []string{"kind", "name"}, "kind", nil)
	if perr != nil {
		return nil, perr
	}
	includeEnded, perr := ParseIncludeEnded(vals)
	if perr != nil {
		return nil, perr
	}
	id, nerr := RouteID(RefWorkload, rawID)
	if nerr != nil {
		return nil, nerr
	}
	// The resource list's own sort components (D-13), so the tab and
	// /resources order references identically.
	keys := listsResources.keys[p.SortKey]
	route := workloadResourcesRoute(id)
	filter := FilterHash(vals)
	pin := Pin{Rev: p.Rev}
	var after *listsAfter
	if p.Cursor != "" {
		c, cerr := r.OpenCursor(p.Cursor, CursorContext{WS: ws, Route: route, Filter: filter, Sort: p.SortString()})
		if cerr != nil {
			return nil, cerr
		}
		if after, perr = listsDecodeCursor(c, keys); perr != nil {
			return nil, perr
		}
		pin.CursorRev = &c.Rev
	}
	states := EdgeStates(includeEnded)

	var out Envelope
	err := r.Read(ctx, ws, pin, func(q *Query) error {
		if !q.Published() {
			return NotFound() // D-4
		}
		w, err := q.LoadWorkload(id)
		if err != nil {
			return err
		}
		if w == nil {
			return NotFound()
		}
		accts, err := q.LoadAccounts()
		if err != nil {
			return err
		}
		meta := WorkloadResourcesMeta{
			ListMeta: NewListMeta(q, p.Limit),
			Workload: WorkloadSubject{Ref: R(RefWorkload, w.ID), Lifecycle: w.Lifecycle, RetiredReason: strPtr(w.RetiredReason)},
		}
		nodes, err := q.workloadNodeParts(w.ID)
		if err != nil {
			return err
		}
		// Coverage is MANDATORY, as on the lists: an empty tab over an
		// unread permission surface must not read as "no declared access".
		meta.Coverage = q.workloadCoverage(accts, &w.WorkloadRecord, nodes,
			workloadCoverageScope{Execution: true, Memberships: true, Permissions: true})

		h, err := q.workloadHolders(w.ID)
		if err != nil {
			return err
		}
		if len(h.all) == 0 {
			meta.SetTotal(0, true)
			out = Envelope{Data: []WorkloadResourceRow{}, Meta: meta}
			return nil
		}

		// THE PAGE: one mandatory statement over the resources the holders'
		// grants reach, keyset-paged on the resource list's sort.
		filters := []listsFilter{
			listsReadable("r", "resource_id", q.WS),
			{sql: `r.id IN (SELECT t.resource_id ` + workloadGrantsFrom + workloadGrantsWhere + `)`, args: []any{q.WS, h.all, states}},
		}
		spec := &listsSpec[workloadResourceScan]{columns: ResourceColumns, from: ResourceFrom, idCol: "r.id"}
		sqlText, args := listsPageSQL(spec, filters, keys, p.Desc, after, p.Limit)
		var rows []workloadResourceScan
		if err := q.DB().Raw(sqlText, args...).Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) > p.Limit {
			rows = rows[:p.Limit]
			last := rows[len(rows)-1]
			var key listsCursorKey
			for _, k := range last.sortKeys()[:len(keys)] {
				if k == nil {
					return errWorkloadNullSortKey
				}
				key.K = append(key.K, *k)
			}
			raw, err := json.Marshal(key)
			if err != nil {
				return err
			}
			tok := r.SignCursor(Cursor{WS: ws, Rev: q.Rev.Rev, Route: route, Filter: filter,
				Sort: p.SortString(), Key: raw, ID: last.ID})
			meta.NextCursor = &tok
		}

		data, err := q.workloadResourceRows(accts, h, rows, states)
		if err != nil {
			return err
		}

		n, known, err := q.CountUpTo(func(tx *gorm.DB) *gorm.DB {
			w, wargs := listsWhere(filters, "")
			return tx.Table("iga_resources r").Where(w, wargs...)
		})
		if err != nil {
			return err
		}
		meta.SetTotal(n, known)
		out = Envelope{Data: data, Meta: meta}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// workloadResourceRows builds the page's rows: every grant line of every page
// resource in ONE query, the NotResource exclusions of their statements in
// one, and the holders' Deny statements and boundaries in one each (§5.6: one
// query per piece, never one per row).
func (q *Query) workloadResourceRows(accts *Accounts, h *workloadHolders, page []workloadResourceScan, states []string) ([]WorkloadResourceRow, error) {
	out := make([]WorkloadResourceRow, 0, len(page))
	if len(page) == 0 {
		return out, nil
	}
	ids := make([]uuid.UUID, len(page))
	for i, r := range page {
		ids[i] = r.ID
	}
	var grants []workloadGrantRow
	if err := q.DB().Raw(`SELECT t.resource_id, g.id AS grant_id, g.subject_identity_account_id AS subject_id,
	                             g.state, g.valid_from, g.valid_to, g.ended_reason, g.last_confirmed_at,
	                             g.connector_id, g.partition_key,
	                             e.id AS statement_id, e.sid, e.statement_index, e.native_rights, e.conditional,
	                             p.id AS policy_id, p.display_name AS policy_name, p.policy_kind
	                       `+workloadGrantsFrom+`
	                        JOIN iga_policy p ON p.workspace_id = e.workspace_id AND p.id = e.policy_id
	                       `+workloadGrantsWhere+`
	                         AND t.resource_id IN ?
	                       ORDER BY t.resource_id, lower(p.display_name), e.statement_index NULLS FIRST, g.id`,
		q.WS, h.all, states, ids).Scan(&grants).Error; err != nil {
		return nil, err
	}

	// Exclusions of the statements on the page: their NotResource entries.
	stmtIDs := []uuid.UUID{}
	seenStmt := map[uuid.UUID]bool{}
	for _, g := range grants {
		if !seenStmt[g.StatementID] {
			seenStmt[g.StatementID] = true
			stmtIDs = append(stmtIDs, g.StatementID)
		}
	}
	exclusions := map[uuid.UUID][]ResourceExclusion{}
	if len(stmtIDs) > 0 {
		var ex []struct {
			EntitlementID uuid.UUID
			ResourceID    uuid.UUID
			DisplayName   string
		}
		if err := q.DB().Raw(`SELECT t.entitlement_id, r.id AS resource_id, r.display_name
		                        FROM iga_entitlement_target t
		                        JOIN iga_resources r ON r.workspace_id = t.workspace_id AND r.id = t.resource_id
		                       WHERE t.workspace_id = ? AND t.entitlement_id IN ? AND t.target_mode = ?
		                       ORDER BY t.entitlement_id, t.ordinal, r.id`,
			q.WS, stmtIDs, models.TargetNotResource).Scan(&ex).Error; err != nil {
			return nil, err
		}
		for _, e := range ex {
			exclusions[e.EntitlementID] = append(exclusions[e.EntitlementID], ResourceExclusion{Ref: R(RefResource, e.ResourceID), Text: e.DisplayName})
		}
	}

	// Holder-level restrictions (D-78): each holder's Deny statements (from
	// its live attached or inline policies), and whether it has a live
	// boundary. A boundary assignment is never a grant (§2.6).
	denyOf := map[uuid.UUID]map[uuid.UUID]bool{}
	var denies []struct {
		Holder      uuid.UUID
		StatementID uuid.UUID
	}
	if err := q.DB().Raw(`SELECT DISTINCT a.holder_identity_account_id AS holder, e.id AS statement_id
	                        FROM iga_policy_assignment a
	                        JOIN iga_entitlements e ON e.workspace_id = a.workspace_id AND e.policy_id = a.policy_id
	                       WHERE a.workspace_id = ? AND a.holder_identity_account_id IN ?
	                         AND a.assignment_kind IN ? AND a.state IN ('current', 'stale')
	                         AND e.provider = 'aws' AND e.effect = 'deny' AND e.lifecycle = 'active'`,
		q.WS, h.all, []string{models.AssignmentAttached, models.AssignmentInline}).Scan(&denies).Error; err != nil {
		return nil, err
	}
	for _, d := range denies {
		if denyOf[d.Holder] == nil {
			denyOf[d.Holder] = map[uuid.UUID]bool{}
		}
		denyOf[d.Holder][d.StatementID] = true
	}
	var bounded []uuid.UUID
	if err := q.DB().Raw(`SELECT DISTINCT a.holder_identity_account_id
	                        FROM iga_policy_assignment a
	                       WHERE a.workspace_id = ? AND a.holder_identity_account_id IN ?
	                         AND a.assignment_kind = ? AND a.state IN ('current', 'stale')`,
		q.WS, h.exec, models.AssignmentBoundary).Scan(&bounded).Error; err != nil {
		return nil, err
	}
	hasBoundary := map[uuid.UUID]bool{}
	for _, b := range bounded {
		hasBoundary[b] = true
	}

	// Lines: a grant held by an execution identity is one line; a grant held
	// by a group is one line per member execution identity (via_group).
	isExec := map[uuid.UUID]bool{}
	for _, e := range h.exec {
		isExec[e] = true
	}
	type line struct {
		g     workloadGrantRow
		via   uuid.UUID
		group *uuid.UUID
		state string
	}
	byResource := map[uuid.UUID][]line{}
	var staleEdges []EdgePartition
	for _, g := range grants {
		if g.State == StateStale {
			staleEdges = append(staleEdges, EdgePartition{ID: g.GrantID, ConnectorID: g.ConnectorID, PartitionKey: g.PartitionKey, Documents: true})
		}
		if isExec[g.SubjectID] {
			byResource[g.ResourceID] = append(byResource[g.ResourceID], line{g: g, via: g.SubjectID, state: g.State})
		}
		for _, m := range h.memberOf[g.SubjectID] {
			group := g.SubjectID
			st := g.State
			if st == StateCurrent && m.state == StateStale {
				st = StateStale
			}
			byResource[g.ResourceID] = append(byResource[g.ResourceID], line{g: g, via: m.member, group: &group, state: st})
		}
	}
	reasons, err := q.EdgeStaleReasons(accts, staleEdges)
	if err != nil {
		return nil, err
	}

	for _, rec := range page {
		row := WorkloadResourceRow{
			Resource: WorkloadResourceRef{
				Ref: R(RefResource, rec.ID), Text: rec.DisplayName, Kind: rec.Kind, Type: ResourceType(rec.DisplayName),
				Service: strPtr(rec.Service), Account: ResourceAccount(accts, rec.AccountID, rec.AccountConnected),
				Region: strPtr(rec.Region),
			},
			Grants: []WorkloadGrantLine{},
		}
		principals := map[uuid.UUID]bool{}
		for _, l := range byResource[rec.ID] {
			principals[l.via] = true
			actions, notActions := StatementActions(l.g.NativeRights)
			ex := exclusions[l.g.StatementID]
			if ex == nil {
				ex = []ResourceExclusion{}
			}
			gl := WorkloadGrantLine{
				Claim:       R(RefGrant, l.g.GrantID),
				ViaIdentity: R(RefIdentity, l.via),
				Policy:      PolicyBrief{Ref: R(RefPolicy, l.g.PolicyID), Name: l.g.PolicyName, Kind: l.g.PolicyKind},
				Statement: StatementBrief{Ref: R(RefStatement, l.g.StatementID), Sid: l.g.Sid,
					Index: APIStatementIndex(l.g.StatementIndex), Actions: actions, NotActions: notActions,
					Conditional: l.g.Conditional},
				TargetMode:      models.TargetResource,
				Exclusions:      ex,
				State:           l.state,
				ValidFrom:       T(l.g.ValidFrom),
				ValidTo:         workloadEndedAt(l.g.State, l.g.ValidTo),
				EndedReason:     l.g.EndedReason,
				LastConfirmedAt: T(l.g.LastConfirmedAt),
			}
			if l.group != nil {
				ref := R(RefIdentity, *l.group)
				gl.ViaGroup = &ref
			}
			if l.state == StateStale {
				rs := reasons[l.g.GrantID]
				if rs == nil {
					rs = []StaleReason{}
				}
				gl.StaleReason = &rs
			}
			row.Grants = append(row.Grants, gl)
		}
		// The row's holders: its lines' execution identities and their
		// groups (D-22: a Deny held by the group bears on its members).
		deny := map[uuid.UUID]bool{}
		for pr := range principals {
			for s := range denyOf[pr] {
				deny[s] = true
			}
			for _, g := range h.groupsOf[pr] {
				for s := range denyOf[g] {
					deny[s] = true
				}
			}
			if hasBoundary[pr] {
				row.Restrictions.PermissionsBoundary = true
			}
		}
		row.Restrictions.DenyStatements = len(deny)
		out = append(out, row)
	}
	return out, nil
}

// errWorkloadNullSortKey is a page row with no sort key value: the keyset would be
// undefined, so the request fails rather than issue a cursor that skips rows.
var errWorkloadNullSortKey = errors.New("igaread: workload resources page returned a NULL sort key")
