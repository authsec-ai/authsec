package igaread

// GET /api/iga/v1/workloads/:id/identities (SPEC-iga-phase2-graph.md §5.3,
// §2.14.6 "Detail tabs", §4.6; D-12, D-17, D-62, D-73, D-74, D-77): the
// identities the workload runs as, and what those identities reach.
//
//	execution   its executes_as claims -- the identity it runs as (§2.2)
//	other       ECS's task_execution_role: the role ECS itself uses to pull
//	            images and read secrets, NOT the task's own identity (§2.2)
//	groups      member_of claims of the execution identities (normally none:
//	            an IAM role cannot be a group member)
//	may_assume  can_assume claims whose SOURCE is an execution identity: roles
//	            whose trust policy names it (declared, never proven, §2.3)
//
// Beside them, execution_role_state -- the four-way state the projector writes
// on every pass (§4.6) -- and execution_role_arn when that state is not
// resolved, so the tab says "Runs as <arn> -- not read in the latest scan"
// rather than showing nothing. When the state is not_in_scan and a STALE
// executes_as row still exists (the role was not re-read), both are returned:
// the row, marked stale, and the state. Neither hides the other.
//
// A multi-section tab (D-77): the detail envelope, each section a page
// {items, next_cursor, total_known, total} under the §5.2 totals rule (D-15:
// total_at_least above 10 000, no total when unknown). ?section=<name>&cursor= returns
// that section alone; the cursor's route carries the workload and the section
// (D-62), so a cursor for one cannot page another. Each section is ordered by
// name, then account, then claim id (§2.14.6, D-13); the execution section
// puts current before stale first, so "the execution identity" leads.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

// Workload › Identities sections (D-77).
const (
	WorkloadSectionExecution = "execution"
	WorkloadSectionOther     = "other"
	WorkloadSectionGroups    = "groups"
	WorkloadSectionMayAssume = "may_assume"
)

var workloadIdentitySections = []string{WorkloadSectionExecution, WorkloadSectionOther, WorkloadSectionGroups, WorkloadSectionMayAssume}

// PagedSection is one paged section of a multi-section tab (D-77): {items,
// next_cursor, total_known, total}, under the list envelope's totals rule
// (§5.2 Totals, D-15, §2.14.14): total only when total_known; above TotalCap,
// total_known false and total_at_least; a count that timed out, total_known
// false and nothing else -- so "more than 10 000" and "not counted" never
// read alike. Set the three through SetTotal, never by hand.
type PagedSection[T any] struct {
	Items        []T     `json:"items"`
	NextCursor   *string `json:"next_cursor"`
	TotalKnown   bool    `json:"total_known"`
	Total        *int64  `json:"total,omitempty"`
	TotalAtLeast *int64  `json:"total_at_least,omitempty"`
}

// SetTotal records a section's counted total -- n rows counted with LIMIT
// TotalCap+1, known=false when the optional count timed out -- by the one
// rule ListMeta.SetTotal applies to a list, so a section and a list cannot
// state the same count differently.
func (s *PagedSection[T]) SetTotal(n int64, known bool) {
	var m ListMeta
	m.SetTotal(n, known)
	s.TotalKnown, s.Total, s.TotalAtLeast = m.TotalKnown, m.Total, m.TotalAtLeast
}

// WorkloadIdentityClaim is one item of execution, other and groups: the
// claim, its type, the identity at its far end, and the claim's own facts.
// via_identity is set on groups only: the execution identity that is the
// member. used_by_count (execution and other) counts the workloads using that
// identity, this one included (D-17: executes_as ∪ task_execution_role,
// current or stale -- the Used-by tab's predicate), as optional work.
type WorkloadIdentityClaim struct {
	Claim           string         `json:"claim"`
	Type            string         `json:"type"`
	Identity        IdentityBrief  `json:"identity"`
	ViaIdentity     *string        `json:"via_identity,omitempty"`
	Basis           string         `json:"basis"`
	State           string         `json:"state"`
	StaleReason     *[]StaleReason `json:"stale_reason,omitempty"`
	ValidFrom       any            `json:"valid_from"`
	ValidTo         any            `json:"valid_to,omitempty"`
	EndedReason     string         `json:"ended_reason,omitempty"`
	LastConfirmedAt any            `json:"last_confirmed_at"`
	UsedByCount     *Exact         `json:"used_by_count,omitempty"`
}

// WorkloadMayAssume is one may_assume item: a can_assume claim from an
// execution identity (via_identity) to the role whose trust policy names it
// (target), with the trust statement's key, its mechanism, and its
// conditions verbatim -- null when the statement had none. Conditions are
// recorded, never evaluated.
type WorkloadMayAssume struct {
	Claim           string          `json:"claim"`
	Type            string          `json:"type"`
	ViaIdentity     string          `json:"via_identity"`
	Target          IdentityBrief   `json:"target"`
	Mechanism       string          `json:"mechanism"`
	StatementKey    string          `json:"statement_key"`
	Conditions      json.RawMessage `json:"conditions"`
	Basis           string          `json:"basis"`
	State           string          `json:"state"`
	StaleReason     *[]StaleReason  `json:"stale_reason,omitempty"`
	ValidFrom       any             `json:"valid_from"`
	ValidTo         any             `json:"valid_to,omitempty"`
	EndedReason     string          `json:"ended_reason,omitempty"`
	LastConfirmedAt any             `json:"last_confirmed_at"`
}

// WorkloadIdentities is data of the tab. A section the request did not ask
// for (?section=) is absent; execution_role_state and _arn come with the full
// tab only.
type WorkloadIdentities struct {
	Ref                string                               `json:"ref"`
	Execution          *PagedSection[WorkloadIdentityClaim] `json:"execution,omitempty"`
	ExecutionRoleState *string                              `json:"execution_role_state,omitempty"`
	ExecutionRoleARN   json.RawMessage                      `json:"execution_role_arn,omitempty"`
	Other              *PagedSection[WorkloadIdentityClaim] `json:"other,omitempty"`
	Groups             *PagedSection[WorkloadIdentityClaim] `json:"groups,omitempty"`
	MayAssume          *PagedSection[WorkloadMayAssume]     `json:"may_assume,omitempty"`
}

// WorkloadSubject says which workload a tab is about and whether it is
// retired: a retired workload's tabs have no current data, and the console
// must say so rather than render an empty tab (§2.14.4, l.1237).
type WorkloadSubject struct {
	Ref           string  `json:"ref"`
	Lifecycle     string  `json:"lifecycle"`
	RetiredReason *string `json:"retired_reason"`
}

// WorkloadTabMeta is a detail-envelope tab's meta: the detail meta, the
// workload it is about, and the coverage of the partitions its rows rest on.
type WorkloadTabMeta struct {
	DetailMeta
	Workload WorkloadSubject `json:"workload"`
	Limit    int             `json:"limit"`
	Coverage []CoverageNote  `json:"coverage"`
}

// workloadIdentitiesRoute is the cursor route of one section of one
// workload's tab (D-62).
func workloadIdentitiesRoute(workloadID uuid.UUID, section string) string {
	return "workloads/" + workloadID.String() + "/identities/" + section
}

// workloadClaimRow is one relationship row with the identity at its far end.
type workloadClaimRow struct {
	ID               uuid.UUID
	RelationshipType string
	Basis            string
	State            string
	ValidFrom        time.Time
	ValidTo          *time.Time
	EndedReason      string
	LastConfirmedAt  time.Time
	ConnectorID      *uuid.UUID
	PartitionKey     string
	Mechanism        string
	StatementKey     string
	Conditions       json.RawMessage
	SourceID         uuid.UUID
	IdentityID       uuid.UUID
	DisplayName      string
	AccountKind      string
	SourceKey        string
	K0               string `gorm:"column:k0"`
	K1               string `gorm:"column:k1"`
	K2               string `gorm:"column:k2"`
	K3               string `gorm:"column:k3"`
}

// workloadSectionKey is a section's cursor position: the last row's sort key
// values (state rank, lower(name), no-account flag, account) as text.
type workloadSectionKey struct {
	K [4]string `json:"k"`
}

// workloadSection is one section's query: its relationship type and the
// sources whose claims it lists (the workload itself, or its execution
// identities).
type workloadSection struct {
	name    string
	relType string
	sources []uuid.UUID
	// byState puts current before stale before ended ahead of the name: the
	// execution section leads with the identity the workload runs as now.
	byState bool
}

// Sort components, all ascending, so a single row comparison is the keyset:
// (state rank, lower(name), no-account flag, account, claim id). Without
// byState the rank is the constant 0. The account is the far identity's own,
// from its ARN: never unknown for a collected identity, but ordered last if it
// ever is (D-13).
const (
	workloadClaimStateRankSQL = `(CASE r.state WHEN 'current' THEN 0 WHEN 'stale' THEN 1 ELSE 2 END)`
	workloadClaimFrom         = `iga_relationship r
	  JOIN iga_identity_accounts ia
	    ON ia.workspace_id = r.workspace_id AND ia.id = r.target_identity_account_id AND ia.provider = 'aws'`
)

func (s workloadSection) where() (string, []any) {
	// The COALESCE is the expression idx_iga_relationship_source is built on:
	// written any other way the index is not used (§5.6).
	return `r.workspace_id = ? AND r.relationship_type = ?
	    AND COALESCE(r.source_identity_account_id, r.source_workload_id) IN ?
	    AND r.state IN ?`, []any{s.relType, s.sources}
}

// page reads one page of the section after `after` (nil: the first page):
// limit+1 rows, so whether a next page exists is known without a count.
func (s workloadSection) page(q *Query, states []string, after *workloadSectionKey, afterID uuid.UUID, limit int) ([]workloadClaimRow, error) {
	// A constant rank, written as an expression: a bare integer in ORDER BY
	// would name an output column by position.
	rank := "CAST(0 AS int)"
	if s.byState {
		rank = workloadClaimStateRankSQL
	}
	acct := `(` + IdentityAccountSQL + `)`
	keys := []string{rank, `lower(ia.display_name)`, `(CASE WHEN ` + acct + ` = '' THEN 1 ELSE 0 END)`, acct}
	where, args := s.where()
	args = append([]any{q.WS}, append(args, states)...)
	sqlText := `SELECT r.id, r.relationship_type, r.basis, r.state, r.valid_from, r.valid_to, r.ended_reason,
	                   r.last_confirmed_at, r.connector_id, r.partition_key, r.mechanism, r.statement_key, r.conditions,
	                   COALESCE(r.source_identity_account_id, r.source_workload_id) AS source_id,
	                   ia.id AS identity_id, ia.display_name, ia.account_kind, ia.source_key,
	                   (` + keys[0] + `)::text AS k0, (` + keys[1] + `)::text AS k1,
	                   (` + keys[2] + `)::text AS k2, (` + keys[3] + `)::text AS k3
	              FROM ` + workloadClaimFrom + `
	             WHERE ` + where
	if after != nil {
		sqlText += `
	               AND ((` + keys[0] + `)::int, ` + keys[1] + `, (` + keys[2] + `)::int, ` + keys[3] + `, r.id)
	                 > (?::int, ?::text, ?::int, ?::text, ?::uuid)`
		args = append(args, after.K[0], after.K[1], after.K[2], after.K[3], afterID)
	}
	sqlText += `
	             ORDER BY ` + keys[0] + `, ` + keys[1] + `, ` + keys[2] + `, ` + keys[3] + `, r.id
	             LIMIT ?`
	args = append(args, limit+1)
	var rows []workloadClaimRow
	if err := q.DB().Raw(sqlText, args...).Scan(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// WorkloadIdentities serves GET /api/iga/v1/workloads/:id/identities.
// Parameters: rev, limit (1-200, default 100, per section), include_ended
// (D-12), section and cursor (D-77; a cursor needs its section).
func (r *Reader) WorkloadIdentities(ctx context.Context, ws uuid.UUID, rawID string, vals url.Values) (any, error) {
	if perr := RouteParams(vals, "rev", "limit", "include_ended", "section", "cursor"); perr != nil {
		return nil, perr
	}
	p, perr := ParseListParams(url.Values{"limit": vals["limit"], "rev": vals["rev"]}, []string{"name"}, "name", nil)
	if perr != nil {
		return nil, perr
	}
	includeEnded, perr := ParseIncludeEnded(vals)
	if perr != nil {
		return nil, perr
	}
	section := vals.Get("section")
	if section != "" && !contains(workloadIdentitySections, section) {
		return nil, InvalidParameter("section", fmt.Sprintf("section must be one of %v", workloadIdentitySections))
	}
	cursor := vals.Get("cursor")
	if cursor != "" && section == "" {
		return nil, InvalidParameter("section", "a cursor pages one section: pass the section it was issued for")
	}
	id, nerr := RouteID(RefWorkload, rawID)
	if nerr != nil {
		return nil, nerr
	}
	// The section is bound through the cursor's route (D-62), not its filter
	// hash: the full tab issues a section's first cursor without ?section=,
	// and the page it continues is asked for with it.
	filterVals := url.Values{}
	for k, v := range vals {
		if k != "section" {
			filterVals[k] = v
		}
	}
	filter := FilterHash(filterVals)
	pin := Pin{Rev: p.Rev}
	var after *workloadSectionKey
	var afterID uuid.UUID
	if cursor != "" {
		c, cerr := r.OpenCursor(cursor, CursorContext{WS: ws, Route: workloadIdentitiesRoute(id, section), Filter: filter})
		if cerr != nil {
			return nil, cerr
		}
		var k workloadSectionKey
		if err := json.Unmarshal(c.Key, &k); err != nil {
			return nil, CursorInvalid("Malformed cursor.")
		}
		after, afterID = &k, c.ID
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
		// The execution identities: the targets of the workload's LIVE
		// executes_as rows (current or stale). Groups and may_assume hang off
		// these, whatever include_ended says -- an ended executes_as names an
		// identity the workload no longer runs as.
		var exec []uuid.UUID
		if err := q.DB().Raw(`SELECT DISTINCT r.target_identity_account_id
		                        FROM iga_relationship r
		                       WHERE r.workspace_id = ? AND r.relationship_type = ?
		                         AND COALESCE(r.source_identity_account_id, r.source_workload_id) = ?
		                         AND r.state IN ('current', 'stale')`,
			q.WS, models.RelTypeExecutesAs, w.ID).Scan(&exec).Error; err != nil {
			return err
		}
		self := []uuid.UUID{w.ID}
		specs := map[string]workloadSection{
			WorkloadSectionExecution: {name: WorkloadSectionExecution, relType: models.RelTypeExecutesAs, sources: self, byState: true},
			WorkloadSectionOther:     {name: WorkloadSectionOther, relType: models.RelTypeTaskExecutionRole, sources: self},
			WorkloadSectionGroups:    {name: WorkloadSectionGroups, relType: models.RelTypeMemberOf, sources: exec},
			WorkloadSectionMayAssume: {name: WorkloadSectionMayAssume, relType: models.RelTypeCanAssume, sources: exec},
		}
		wanted := workloadIdentitySections
		if section != "" {
			wanted = []string{section}
		}

		// Each section's page: one mandatory statement per section (§5.6).
		pages := map[string][]workloadClaimRow{}
		next := map[string]*string{}
		for _, name := range wanted {
			s := specs[name]
			if len(s.sources) == 0 {
				pages[name] = nil
				continue
			}
			var a *workloadSectionKey
			if name == section {
				a = after
			}
			rows, err := s.page(q, states, a, afterID, p.Limit)
			if err != nil {
				return err
			}
			if len(rows) > p.Limit {
				rows = rows[:p.Limit]
				last := rows[len(rows)-1]
				raw, err := json.Marshal(workloadSectionKey{K: [4]string{last.K0, last.K1, last.K2, last.K3}})
				if err != nil {
					return err
				}
				tok := r.SignCursor(Cursor{WS: ws, Rev: q.Rev.Rev, Route: workloadIdentitiesRoute(id, name),
					Filter: filter, Key: raw, ID: last.ID})
				next[name] = &tok
			}
			pages[name] = rows
		}

		// Optional work: used_by_count per execution/other identity, the
		// section totals. A piece that times out is unknown, never guessed.
		var ids []uuid.UUID
		for _, name := range []string{WorkloadSectionExecution, WorkloadSectionOther} {
			for _, row := range pages[name] {
				ids = append(ids, row.IdentityID)
			}
		}
		var usedBy map[uuid.UUID]Exact
		usedByOK, err := q.Optional(func(tx *gorm.DB) error {
			var err error
			usedBy, err = UsedByCounts(tx, q.WS, ids)
			return err
		})
		if err != nil {
			return err
		}

		// stale_reason for every stale row shown (D-74).
		var staleEdges []EdgePartition
		for _, rows := range pages {
			for _, row := range rows {
				if row.State == StateStale {
					staleEdges = append(staleEdges, EdgePartition{ID: row.ID, ConnectorID: row.ConnectorID, PartitionKey: row.PartitionKey})
				}
			}
		}
		reasons, err := q.EdgeStaleReasons(accts, staleEdges)
		if err != nil {
			return err
		}

		data := WorkloadIdentities{Ref: R(RefWorkload, w.ID)}
		for _, name := range wanted {
			s := specs[name]
			// No sources: nothing to count, and the empty section's total is
			// exactly 0.
			total, known := int64(0), true
			if len(s.sources) > 0 {
				n, ok, err := q.CountUpTo(func(tx *gorm.DB) *gorm.DB {
					where, args := s.where()
					return tx.Table(workloadClaimFrom).Where(where, append([]any{q.WS}, append(args, states)...)...)
				})
				if err != nil {
					return err
				}
				total, known = n, ok
			}
			switch name {
			case WorkloadSectionMayAssume:
				sec := &PagedSection[WorkloadMayAssume]{Items: []WorkloadMayAssume{}, NextCursor: next[name]}
				sec.SetTotal(total, known)
				for _, row := range pages[name] {
					sec.Items = append(sec.Items, WorkloadMayAssume{
						Claim: R(RefRelationship, row.ID), Type: row.RelationshipType,
						ViaIdentity: R(RefIdentity, row.SourceID),
						Target:      workloadIdentityBriefOf(accts, row.IdentityID, row.DisplayName, row.AccountKind, row.SourceKey),
						Mechanism:   row.Mechanism, StatementKey: row.StatementKey, Conditions: workloadJSONOrNull(row.Conditions),
						Basis: row.Basis, State: row.State, StaleReason: StaleReasonOf(row.State, row.ID, reasons),
						ValidFrom: T(row.ValidFrom), ValidTo: workloadEndedAt(row.State, row.ValidTo), EndedReason: row.EndedReason,
						LastConfirmedAt: T(row.LastConfirmedAt),
					})
				}
				data.MayAssume = sec
			default:
				sec := &PagedSection[WorkloadIdentityClaim]{Items: []WorkloadIdentityClaim{}, NextCursor: next[name]}
				sec.SetTotal(total, known)
				for _, row := range pages[name] {
					item := WorkloadIdentityClaim{
						Claim: R(RefRelationship, row.ID), Type: row.RelationshipType,
						Identity: workloadIdentityBriefOf(accts, row.IdentityID, row.DisplayName, row.AccountKind, row.SourceKey),
						Basis:    row.Basis, State: row.State, StaleReason: StaleReasonOf(row.State, row.ID, reasons),
						ValidFrom: T(row.ValidFrom), ValidTo: workloadEndedAt(row.State, row.ValidTo), EndedReason: row.EndedReason,
						LastConfirmedAt: T(row.LastConfirmedAt),
					}
					if name == WorkloadSectionGroups {
						via := R(RefIdentity, row.SourceID)
						item.ViaIdentity = &via
					} else {
						c := Unknown()
						if n, ok := usedBy[row.IdentityID]; usedByOK && ok {
							c = n
						}
						item.UsedByCount = &c
					}
					sec.Items = append(sec.Items, item)
				}
				switch name {
				case WorkloadSectionExecution:
					data.Execution = sec
				case WorkloadSectionOther:
					data.Other = sec
				case WorkloadSectionGroups:
					data.Groups = sec
				}
			}
		}
		if section == "" {
			st := w.ExecutionRoleState
			data.ExecutionRoleState = &st
			// Present on every full tab, null when the state is resolved or
			// none: only the two middle states name a role no edge records.
			// (A RawMessage, so a JSON null is written rather than omitted.)
			data.ExecutionRoleARN = json.RawMessage("null")
			if st == models.ExecRoleNotInScan || st == models.ExecRoleNotInInventory {
				raw, err := json.Marshal(w.ExecutionRoleARN)
				if err != nil {
					return err
				}
				data.ExecutionRoleARN = raw
			}
		}

		nodes, err := q.workloadNodeParts(w.ID)
		if err != nil {
			return err
		}
		// may_assume rests on the trust documents of EVERY connected account,
		// not the workload's own: a can_assume edge is reconciled under the
		// connector that read the trusting role, and a role in any account may
		// name the execution identity (workloadTrustParts). Only when this
		// answer has a may_assume section with sources: with no execution
		// identity no trust document can name one -- which is also why a
		// retired workload (its executes_as ended with it) gets none.
		var trust []*workloadResolvedPart
		if len(exec) > 0 && contains(wanted, WorkloadSectionMayAssume) {
			if trust, err = q.workloadTrustParts(); err != nil {
				return err
			}
		}
		out = Envelope{Data: data, Meta: WorkloadTabMeta{
			DetailMeta: NewDetailMeta(q),
			Workload:   WorkloadSubject{Ref: R(RefWorkload, w.ID), Lifecycle: w.Lifecycle, RetiredReason: strPtr(w.RetiredReason)},
			Limit:      p.Limit,
			// The rows rest on the workload's execution partitions, its
			// identities' memberships and the trust documents can_assume is
			// read from; not_in_scan is explained by iam_roles there.
			Coverage: q.workloadCoverage(accts, &w.WorkloadRecord, nodes,
				workloadCoverageScope{Execution: true, Memberships: true, Trust: trust}),
		}}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// workloadJSONOrNull is a jsonb column as JSON: nil (null) when SQL NULL or JSON null.
func workloadJSONOrNull(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	return raw
}

// workloadEndedAt is valid_to on an ended row, and absent (nil) on a live one.
func workloadEndedAt(state string, validTo *time.Time) any {
	if state != StateEnded {
		return nil
	}
	return TS(validTo)
}
