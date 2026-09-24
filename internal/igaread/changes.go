package igaread

// Changes (SPEC-iga-phase2-graph.md §5.3 Changes, T5.4 read side; P2-DECISIONS
// D-26, D-27, D-28, D-62, D-67, D-68, D-69, D-70, D-77):
//
//	GET /api/iga/v1/{workloads|identities|resources}/:id/changes
//	    ?kind=configuration|coverage   (default configuration)
//	    &limit=1..200                   (default 50)
//	    &cursor=<signed>&rev=<n>
//
// Configuration changes and visibility changes never share a list (§2.14.6):
// kind=configuration returns every event type except coverage_changed;
// kind=coverage returns only coverage_changed.
//
// # The event (D-27)
//
// Every item of data is one event, newest first:
//
//	{
//	  "id":      "<event>:<uuid>",          stable; the keyset's (event, id)
//	  "event":   "policy_detached",
//	  "at":      "2026-09-21T14:02:00.123456Z",
//	  "rev":     42 | null,                 the revision that published it
//	  "run":     "cloud_scan_run:<uuid>" | null,
//	  "subject": "assignment:<uuid>",       the claim or object the event is about
//	  "claims":  ["assignment:<uuid>", "policy:<uuid>", "identity:<uuid>"],
//	  "reason":  "not_seen" | null,         lifecycle reason or ended_reason
//	  "via":     "identity:<uuid>",         workloads only: the execution identity
//	  "detail":  {...},                     typed fields per event, below
//	  "before":  {...}, "after": {...},     statement_revised, statement_replaced,
//	                                        coverage_changed only
//	  "remaining": [...], "paths": [...],   grant_ended, policy_detached only (D-28)
//	  "labels":  {"<ref>": "<name>", ...}   a name for every ref above
//	}
//
//	event                 source                              detail
//	first_seen            iga_lifecycle_event (036)           {object}
//	retired               iga_lifecycle_event, reason         {object}
//	                      unsupported|recreated|policy_recreated
//	restored              iga_lifecycle_event                 {object}
//	relationship_started  iga_relationship.valid_from         {type, source, target, mechanism, state}
//	relationship_ended    iga_relationship.valid_to, reason   same
//	policy_attached       iga_policy_assignment.valid_from    {policy, holder, assignment_kind, state}
//	policy_detached       iga_policy_assignment.valid_to      same, + remaining/paths
//	grant_started         iga_access_edges.valid_from         {policy, statement, holder, assignment,
//	grant_ended           iga_access_edges.valid_to           state, actions, not_actions, targets}
//	                                                          (+ remaining/paths on the end)
//	statement_revised     iga_statement_revision              {policy, statement};
//	                                                          before/after {statement, policy_version_id,
//	                                                          content_hash} (D-69)
//	statement_replaced    a Sid-less statement retired         {policy}; before/after {policy_version_id,
//	                      unsupported and a statement of the  statements: [{statement, content,
//	                      same policy began, in one run;      content_hash}]} (D-69; the version is
//	                      id derived from (policy, run)       null unless an observation proves it,
//	                                                          changesReplacementVersions)
//	coverage_changed      consecutive published runs'          {integration, account_id, surface};
//	                      coverage (D-70)                      before {state, recorded, run, coverage};
//	                                                          after {state, recorded, error_code, api,
//	                                                          error, prevents}
//
// at is rendered to the microsecond: with one timestamp per projection pass
// (D-26) it IS the publication's published_at, and the client may compare it
// with meta.history_begins exactly. rev and run of a start or end are
// recovered by joining at to iga_publication.published_at; an at that joins
// to no single publication (a row written before D-26) renders them null --
// never guessed. Lifecycle events carry their own rev and run; a revision its
// first_seen_run_id.
//
// # Which events belong to which object (D-68)
//
//	workload  its own lifecycle; its executes_as and task_execution_role
//	          starts and ends; and the assignment, grant, statement_revised
//	          and statement_replaced events of the identities it executes_as,
//	          ONLY while that edge was valid, each tagged via: identity:<id>
//	identity  its own lifecycle; every relationship it is either end of; the
//	          assignments and grants it holds; revisions and replacements of
//	          statements it holds a grant to, while that grant was valid
//	resource  its own lifecycle; grant events of Allow statements naming it
//	          positively, and revisions and replacements of statements naming
//	          it positively -- never through NotResource. A statement's
//	          targets are its CURRENT content's (D-27f).
//
// Group grants are not copied onto members (the member sees its member_of
// start and end); nothing walks can_assume.
//
// A grant is history of an Allow statement when its statement was Allow AS IT
// STOOD WHEN THE GRANT STARTED (D-27g, changesGrantWasAllow): a Sid-keyed
// Allow edited to Deny keeps its grant's start and end. What REMAINS (below)
// is judged at the current revision.
//
// # Remaining (D-28)
//
// A grant_ended or policy_detached (attached or inline) carries the holder's
// grants that REMAIN, at the current revision, on the same path: non-ended
// grants (current or stale, each with its state and last_confirmed_at) whose
// statements name the same positive target as the ended grant's statement
// (for a detach: as any statement granted through the detached assignment).
// paths states per target whether the path remains current, remains only
// stale, or none remains; "none" only when no grant, current or stale, is
// left. Matching is by reference: a selector and an exact ARN are different
// targets (matching is not evaluated).
//
// The envelope is §5.2's list envelope (D-77) with kind and D-70's
// history_begins (the object's first first_seen event; nothing earlier is
// claimed) added to meta; meta.coverage names the object's own partitions'
// gaps in the runs the current revision was built from (D-73).

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

// Changes kinds (§2.14.6: the two never share a list).
const (
	ChangesConfiguration = "configuration"
	ChangesCoverage      = "coverage"
)

// ChangesDefaultLimit is §5.3's "50 per page" (D-27; limit 1-200 accepted).
const ChangesDefaultLimit = 50

// Changes event names (§5.3 Changes).
const (
	ChangeFirstSeen           = "first_seen"
	ChangeRetired             = "retired"
	ChangeRestored            = "restored"
	ChangeRelationshipStarted = "relationship_started"
	ChangeRelationshipEnded   = "relationship_ended"
	ChangePolicyAttached      = "policy_attached"
	ChangePolicyDetached      = "policy_detached"
	ChangeGrantStarted        = "grant_started"
	ChangeGrantEnded          = "grant_ended"
	ChangeStatementRevised    = "statement_revised"
	ChangeStatementReplaced   = "statement_replaced"
	ChangeCoverageChanged     = "coverage_changed"
)

// Path states on a grant or assignment end (D-28).
const (
	PathRemainsCurrent = "current"
	PathRemainsStale   = "stale"
	PathRemainsNone    = "none"
)

// ChangesMeta is the Changes envelope's meta: §5.2's list meta, plus the kind
// served and D-70's history_begins.
type ChangesMeta struct {
	ListMeta
	Kind string `json:"kind"`
	// HistoryBegins is when the object was first seen (its first first_seen
	// lifecycle event); null when no such event exists. Nothing earlier is
	// claimed (§2.14.7 "History begins 12 Mar").
	HistoryBegins any `json:"history_begins"`
}

// ChangeEvent is one item of a Changes page (see the file comment).
type ChangeEvent struct {
	ID        string             `json:"id"`
	Event     string             `json:"event"`
	At        string             `json:"at"`
	Rev       *int64             `json:"rev"`
	Run       *string            `json:"run"`
	Subject   string             `json:"subject"`
	Claims    []string           `json:"claims"`
	Reason    *string            `json:"reason"`
	Via       *string            `json:"via,omitempty"`
	Detail    map[string]any     `json:"detail"`
	Before    any                `json:"before,omitempty"`
	After     any                `json:"after,omitempty"`
	Remaining *[]ChangeRemaining `json:"remaining,omitempty"`
	Paths     *[]ChangePath      `json:"paths,omitempty"`
	Labels    map[string]string  `json:"labels"`
}

// ChangeRemaining is one grant that remains on the ended claim's path (D-28).
type ChangeRemaining struct {
	Grant           string `json:"grant"`
	State           string `json:"state"`
	LastConfirmedAt any    `json:"last_confirmed_at"`
	Policy          string `json:"policy"`
	Statement       string `json:"statement"`
	// Targets are the ended claim's targets this grant's statement also names.
	Targets []string `json:"targets"`
}

// ChangePath is one target of an ended grant or assignment, and whether a
// path to it remains (D-28): current, stale (only stale grants remain), none.
type ChangePath struct {
	Target  string `json:"target"`
	Remains string `json:"remains"`
}

// ChangeTime renders an event time to the microsecond (the database's
// precision), UTC.
func ChangeTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000000Z07:00") }

/* ------------------------------ the route ------------------------------- */

// changesObject is one route's object type.
type changesObject struct {
	refType string // workload | identity | resource
	route   string // the route segment, for the cursor (D-62)
	table   string
	column  string // the object's iga_object_support / iga_lifecycle_event column
	class   string // igagraph's object class
	kindCol string // the partition kind column ("" for resources)
	regCol  string // the partition region column (workloads only)
}

var changesObjects = map[string]changesObject{
	RefWorkload: {refType: RefWorkload, route: "workloads", table: "iga_workload", column: "workload_id",
		class: models.ObjectWorkload, kindCol: "runtime_kind", regCol: "region"},
	RefIdentity: {refType: RefIdentity, route: "identities", table: "iga_identity_accounts", column: "identity_account_id",
		class: models.ObjectIdentity, kindCol: "account_kind"},
	RefResource: {refType: RefResource, route: "resources", table: "iga_resources", column: "resource_id",
		class: models.ObjectResource},
}

// changesParams are the route's parameters, validated.
type changesParams struct {
	kind   string
	limit  int
	cursor string
	rev    *int64
}

var changesAllowedParams = map[string]bool{"kind": true, "limit": true, "cursor": true, "rev": true}

func parseChangesParams(vals url.Values) (*changesParams, *Error) {
	for k := range vals {
		if !changesAllowedParams[k] {
			return nil, InvalidParameter(k, "unknown parameter "+k+": Changes accepts only kind, limit, cursor and rev")
		}
	}
	p := &changesParams{kind: ChangesConfiguration, limit: ChangesDefaultLimit, cursor: vals.Get("cursor")}
	if k := vals.Get("kind"); k != "" {
		if k != ChangesConfiguration && k != ChangesCoverage {
			return nil, InvalidParameter("kind", "kind must be configuration or coverage")
		}
		p.kind = k
	}
	if l := vals.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > MaxLimit {
			return nil, InvalidParameter("limit", fmt.Sprintf("limit must be 1-%d", MaxLimit))
		}
		p.limit = n
	}
	rev, e := ParseRev(vals)
	if e != nil {
		return nil, e
	}
	p.rev = rev
	return p, nil
}

// ChangesRoute is the cursor route of one object's Changes (D-62): it carries
// the object, so a cursor from another object's Changes is cursor_invalid.
func ChangesRoute(refType string, id uuid.UUID) string {
	return changesObjects[refType].route + "/" + id.String() + "/changes"
}

// changesCursorContext binds a cursor to the object and the kind. The filter
// hash is over the EFFECTIVE kind, so an absent kind and kind=configuration
// page the same list.
func changesCursorContext(ws uuid.UUID, refType string, id uuid.UUID, kind string) CursorContext {
	return CursorContext{WS: ws, Route: ChangesRoute(refType, id),
		Filter: FilterHash(url.Values{"kind": {kind}}), Sort: "-at"}
}

// changesKey is the keyset position (D-27): (at, event, id), all descending.
type changesKey struct {
	At    time.Time
	Event string
	ID    uuid.UUID
}

type changesCursorKey struct {
	At    string `json:"at"`
	Event string `json:"e"`
}

func (r *Reader) changesCursor(ws uuid.UUID, refType string, id uuid.UUID, kind string, rev int64, k changesKey) string {
	cc := changesCursorContext(ws, refType, id, kind)
	key, _ := json.Marshal(changesCursorKey{At: k.At.UTC().Format(time.RFC3339Nano), Event: k.Event})
	return r.SignCursor(Cursor{WS: ws, Rev: rev, Route: cc.Route, Filter: cc.Filter, Sort: cc.Sort, Key: key, ID: k.ID})
}

func decodeChangesKey(c *Cursor) (*changesKey, *Error) {
	var k changesCursorKey
	if err := json.Unmarshal(c.Key, &k); err != nil || k.Event == "" {
		return nil, CursorInvalid("Malformed cursor.")
	}
	at, err := time.Parse(time.RFC3339Nano, k.At)
	if err != nil {
		return nil, CursorInvalid("Malformed cursor.")
	}
	return &changesKey{At: at, Event: k.Event, ID: c.ID}, nil
}

// Changes serves one object's Changes tab. refType is the route's object type
// (workload, identity, resource); rawID the :id parameter.
//
// Order of checks (D-10): the id's form (404, §5.2) and the parameters (400)
// before the snapshot; the revision (409) inside it; then the object (404: not
// this workspace's, not a graph row, or nothing published -- D-4, no object
// can exist before the first publication). A retired object still has its
// Changes (§5.2 "Retired objects").
func (r *Reader) Changes(ctx context.Context, ws uuid.UUID, refType, rawID string, vals url.Values) (any, error) {
	obj, ok := changesObjects[refType]
	if !ok {
		return nil, fmt.Errorf("igaread: no Changes route for %q", refType)
	}
	id, e := RouteID(refType, rawID)
	if e != nil {
		return nil, e
	}
	p, e := parseChangesParams(vals)
	if e != nil {
		return nil, e
	}
	pin := Pin{Rev: p.rev}
	var after *changesKey
	if p.cursor != "" {
		c, e := r.OpenCursor(p.cursor, changesCursorContext(ws, refType, id, p.kind))
		if e != nil {
			return nil, e
		}
		if after, e = decodeChangesKey(c); e != nil {
			return nil, e
		}
		pin.CursorRev = &c.Rev
	}

	var out Envelope
	err := r.Read(ctx, ws, pin, func(q *Query) error {
		if !q.Published() {
			return NotFound()
		}
		node, err := changesLoadObject(q, obj, id)
		if err != nil {
			return err
		}
		if node == nil {
			return NotFound()
		}
		accts, err := q.LoadAccounts()
		if err != nil {
			return err
		}
		supports, err := changesSupports(q, obj, id)
		if err != nil {
			return err
		}
		meta := ChangesMeta{ListMeta: NewListMeta(q, p.limit), Kind: p.kind}
		if meta.HistoryBegins, err = changesHistoryBegins(q, obj, id); err != nil {
			return err
		}
		if meta.Coverage, err = changesMetaCoverage(q, accts, obj, node, supports); err != nil {
			return err
		}

		var inner string
		var args []any
		if p.kind == ChangesConfiguration {
			inner, args = changesConfigurationSQL(q.WS, obj, id)
		} else {
			lanes, err := changesLanes(q, obj, node, supports)
			if err != nil {
				return err
			}
			inner, args = changesCoverageSQL(q.WS, lanes)
		}

		var data []ChangeEvent
		var next *changesKey
		if inner == "" {
			data = []ChangeEvent{}
		} else {
			if data, next, err = changesPage(q, accts, obj, id, p.kind, inner, args, after, p.limit); err != nil {
				return err
			}
		}
		if next != nil {
			tok := r.changesCursor(q.WS, refType, id, p.kind, q.Rev.Rev, *next)
			meta.NextCursor = &tok
		}

		// The total is OPTIONAL (§5.2): a count that did not finish is
		// total_known: false, never a number that looks exact.
		var n int64
		known := true
		if inner != "" {
			known, err = q.Optional(func(tx *gorm.DB) error {
				return tx.Raw(`SELECT count(*) FROM (SELECT DISTINCT u.at, u.event, u.id FROM (`+inner+`) u LIMIT ?) t`,
					append(append([]any{}, args...), TotalCap+1)...).Row().Scan(&n)
			})
			if err != nil {
				return err
			}
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

/* ------------------------------ the object ------------------------------ */

// changesNode is the route's object as Changes needs it: whether it is a
// readable graph row, and the kind and region its partitions are chosen by.
type changesNode struct {
	ID     uuid.UUID
	Name   string
	Kind   string
	Region string
}

// changesLoadObject reads the object in the snapshot: this workspace's, an
// AWS row the projector owns (D-6), in any lifecycle. nil when it is not one.
func changesLoadObject(q *Query, obj changesObject, id uuid.UUID) (*changesNode, error) {
	kind, region := "''", "''"
	if obj.kindCol != "" {
		kind = "t." + obj.kindCol
	}
	if obj.regCol != "" {
		region = "t." + obj.regCol
	}
	var rows []changesNode
	if err := q.DB().Raw(`SELECT t.id, t.display_name AS name, `+kind+` AS kind, `+region+` AS region
	                        FROM `+obj.table+` t
	                       WHERE t.workspace_id = ? AND t.id = ? AND t.provider = 'aws'
	                         AND `+SupportedSQL("t", obj.column), q.WS, id).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, nil
	}
	return &rows[0], nil
}

// changesSupport is one support row of the object, with the watermark of its
// partition (the run the current revision holds that partition from).
type changesSupport struct {
	ID                 uuid.UUID
	ConnectorID        uuid.UUID
	PartitionKey       string
	State              string
	FirstSeenAt        time.Time
	LastConfirmedRunID *uuid.UUID
	EstateScopeID      *uuid.UUID
	LastRunID          *uuid.UUID
}

func changesSupports(q *Query, obj changesObject, id uuid.UUID) ([]changesSupport, error) {
	var rows []changesSupport
	err := q.DB().Raw(`SELECT s.id, s.connector_id, s.partition_key, s.state, s.first_seen_at, s.last_confirmed_run_id,
	                          ps.estate_scope_id, ps.last_run_id
	                     FROM iga_object_support s
	                     LEFT JOIN iga_projection_state ps
	                       ON ps.workspace_id = s.workspace_id AND ps.connector_id = s.connector_id
	                      AND ps.partition_key = s.partition_key
	                    WHERE s.workspace_id = ? AND s.`+obj.column+` = ?
	                    ORDER BY s.connector_id, s.id`, q.WS, id).Scan(&rows).Error
	return rows, err
}

// changesHistoryBegins is D-70's meta.history_begins: the object's first
// first_seen event, from the lifecycle history (never the node row, B24).
//
// min() over no rows is ONE row holding NULL, so the destination must be
// nullable: an object with no first_seen event (a row projected before the
// event log existed, or by any path that skipped it) renders null -- nothing
// earlier is claimed -- rather than failing the whole page.
func changesHistoryBegins(q *Query, obj changesObject, id uuid.UUID) (any, error) {
	var at sql.NullTime
	if err := q.DB().Raw(`SELECT min(le.occurred_at) FROM iga_lifecycle_event le
	                       WHERE le.workspace_id = ? AND le.`+obj.column+` = ? AND le.event = ?`,
		q.WS, id, models.LifecycleFirstSeen).Row().Scan(&at); err != nil {
		return nil, err
	}
	if !at.Valid {
		return nil, nil
	}
	return ChangeTime(at.Time), nil
}

// changesPartition is the partition igagraph put this support row in: the
// projector's own table and membership predicate (partitionOf), accepted only
// when its key IS the row's stored partition_key -- the read side never
// re-derives a partition from a key's text (D-57, D-60).
func changesPartition(obj changesObject, node *changesNode, s changesSupport) (igagraph.Partition, bool) {
	if s.EstateScopeID == nil {
		return igagraph.Partition{}, false
	}
	part, ok := partitionOf(obj.class, node.Kind, node.Region, *s.EstateScopeID, s.ConnectorID)
	if !ok || part.Key() != s.PartitionKey {
		return igagraph.Partition{}, false
	}
	return part, true
}

/* --------------------------- configuration SQL --------------------------- */

// Every branch yields the same columns, so the union pages as one list:
//
//	at, event, id    the keyset (D-27)
//	src              which table the row came from (lifecycle, relationship,
//	                 assignment, grant, revision, replacement)
//	via_id           workloads: the execution identity the event came through
//	reason           lifecycle reason, or ended_reason on an end
//	rev, run_id      when the row itself records them (lifecycle events,
//	                 revisions' first_seen_run_id)
//	policy_id        statement_replaced only: the policy the event is about.
//	                 Its id is DERIVED from (policy, run) -- one event per
//	                 (policy, run), D-27c -- so two replacements of one policy
//	                 in two runs are two ids (D-27: id is unique and stable)
const changesCols = `at, event, id, src, via_id, reason, rev, run_id, policy_id`

// changesReplacementID is statement_replaced's event id: derived from (policy,
// run) the way coverage_changed's is from (run, surface). Expects the policy
// id in e.policy_id and the run in le.scan_run_id.
const changesReplacementID = `md5(e.policy_id::text || ':' || le.scan_run_id::text)::uuid`

// changesGrantRevisionJoin and changesGrantWasAllow are rule 7 ("every grant
// query joins its statement with effect = 'allow'", §3 036) applied to
// HISTORY (D-27g): a grant is shown when its statement was an Allow statement
// AS IT STOOD WHEN THE GRANT STARTED -- the revision in force at g.valid_from
// -- never by the statement's current effect. A Sid-keyed statement keeps its
// id when edited (§2.6), effect included, so judging a past grant by the
// current effect would erase the grant's start and its end the moment an Allow
// is edited to Deny, and the access removal would carry no grant_ended and no
// remaining (D-28). The defence rule 7 exists for still holds: a grant row
// written for a statement that was Deny at the time is never shown.
//
// A statement with no revision covering that instant -- a Sid-less statement,
// whose key is its content hash, so its effect cannot change in place --
// falls back to its current effect. A covering revision whose verbatim
// statement names no Effect is not Allow. Revisions of one statement never
// overlap ([valid_from, valid_to), one live), so the join adds no rows.
// Expects the grant as g and its statement as e.
const changesGrantRevisionJoin = `LEFT JOIN iga_statement_revision gsr
	               ON gsr.workspace_id = g.workspace_id AND gsr.entitlement_id = g.entitlement_id
	              AND gsr.valid_from <= g.valid_from AND (gsr.valid_to IS NULL OR g.valid_from < gsr.valid_to)`

const changesGrantWasAllow = `CASE WHEN gsr.id IS NULL THEN e.effect
	           ELSE lower(COALESCE(gsr.statement->>'Effect', '')) END = '` + models.EffectAllow + `'`

// changesUnion collects a query's UNION ALL branches with their arguments in
// textual order.
type changesUnion struct {
	parts []string
	args  []any
}

func (u *changesUnion) add(sql string, args ...any) {
	u.parts = append(u.parts, sql)
	u.args = append(u.args, args...)
}

func (u *changesUnion) sql() (string, []any) {
	return strings.Join(u.parts, "\n UNION ALL \n"), u.args
}

// changesHolders is whose permission events an object's Changes shows, and
// when (D-68): an identity's own, always; or a workload's execution
// identities -- the targets of its executes_as edges -- only at instants one
// of those edges was valid (valid_from <= at <= valid_to, open-ended while
// live), each event tagged with the identity it came through.
type changesHolders struct {
	ws       uuid.UUID
	identity *uuid.UUID // an identity's own
	workload *uuid.UUID // a workload's execution identities
}

// in restricts a holder column to the holders.
func (h changesHolders) in(col string) (string, []any) {
	if h.identity != nil {
		return col + ` = ?`, []any{*h.identity}
	}
	return col + ` IN (SELECT ex.target_identity_account_id FROM iga_relationship ex
	                    WHERE ex.workspace_id = ? AND ex.relationship_type = '` + models.RelTypeExecutesAs + `'
	                      AND COALESCE(ex.source_identity_account_id, ex.source_workload_id) = ?
	                      AND ex.target_identity_account_id IS NOT NULL)`, []any{h.ws, *h.workload}
}

// during restricts an event time to the instants the holder in col was the
// workload's execution identity. Always true for an identity's own events.
func (h changesHolders) during(col, at string) (string, []any) {
	if h.workload == nil {
		return "true", nil
	}
	return `EXISTS (SELECT 1 FROM iga_relationship ex
	                 WHERE ex.workspace_id = ? AND ex.relationship_type = '` + models.RelTypeExecutesAs + `'
	                   AND COALESCE(ex.source_identity_account_id, ex.source_workload_id) = ?
	                   AND ex.target_identity_account_id = ` + col + `
	                   AND ex.valid_from <= ` + at + ` AND (ex.valid_to IS NULL OR ` + at + ` <= ex.valid_to))`,
		[]any{h.ws, *h.workload}
}

// via is the via_id column: the holder for a workload, NULL otherwise.
func (h changesHolders) via(col string) string {
	if h.workload != nil {
		return col
	}
	return "NULL::uuid"
}

// changesAllRelTypes is every relationship type this milestone writes; the
// IN list lets idx_iga_relationship_source / _target serve an identity's
// edges of every type.
var changesAllRelTypes = []string{models.RelTypeExecutesAs, models.RelTypeTaskExecutionRole,
	models.RelTypeMemberOf, models.RelTypeCanAssume}

// changesConfigurationSQL is the union of every dated row of the object's
// configuration history (§5.6 "Union of dated rows for the object").
func changesConfigurationSQL(ws uuid.UUID, obj changesObject, id uuid.UUID) (string, []any) {
	u := &changesUnion{}

	// Lifecycle: iga_lifecycle_event ONLY, never the node row -- lifecycle and
	// retired_reason on the row are overwritten by every later pass (B24).
	u.add(`SELECT le.occurred_at AS at, le.event::text AS event, le.id AS id, 'lifecycle'::text AS src,
	              NULL::uuid AS via_id, le.reason::text AS reason, le.rev::bigint AS rev, le.scan_run_id AS run_id,
	              NULL::uuid AS policy_id
	         FROM iga_lifecycle_event le
	        WHERE le.workspace_id = ? AND le.`+obj.column+` = ?`, ws, id)

	switch obj.refType {
	case RefWorkload:
		// Its own execution edges, by the expression idx_iga_relationship_source
		// is built on.
		u.add(changesRelationshipSQL(`r.relationship_type IN ? AND COALESCE(r.source_identity_account_id, r.source_workload_id) = ?`),
			ws, []string{models.RelTypeExecutesAs, models.RelTypeTaskExecutionRole}, id)
		changesPermissionBranches(u, changesHolders{ws: ws, workload: &id})
	case RefIdentity:
		u.add(changesRelationshipSQL(`r.relationship_type IN ? AND COALESCE(r.source_identity_account_id, r.source_workload_id) = ?`),
			ws, changesAllRelTypes, id)
		// Edges it is the TARGET of (a workload's executes_as, a member's
		// member_of, a trusted principal's can_assume) -- except an edge whose
		// source is also this identity, already listed above.
		u.add(changesRelationshipSQL(`r.relationship_type IN ? AND r.target_identity_account_id = ?
		                               AND COALESCE(r.source_identity_account_id, r.source_workload_id) IS DISTINCT FROM ?`),
			ws, changesAllRelTypes, id, id)
		changesPermissionBranches(u, changesHolders{ws: ws, identity: &id})
	case RefResource:
		changesResourceBranches(u, ws, id)
	}
	return u.sql()
}

// changesRelationshipSQL is one relationship branch: each row is a start at
// valid_from and, once ended, an end at valid_to with its ended_reason. It
// includes ended rows: ended is read exactly when a Changes view asks (§5.4).
// Binds: ws, then pred's arguments.
func changesRelationshipSQL(pred string) string {
	return `SELECT x.at, x.event, r.id, 'relationship'::text, NULL::uuid, x.reason, NULL::bigint, NULL::uuid, NULL::uuid
	          FROM iga_relationship r
	         CROSS JOIN LATERAL (VALUES (r.valid_from, '` + ChangeRelationshipStarted + `'::text, ''::text),
	                                    (r.valid_to, '` + ChangeRelationshipEnded + `'::text, r.ended_reason)) x(at, event, reason)
	         WHERE r.workspace_id = ? AND x.at IS NOT NULL AND ` + pred
}

// changesPermissionBranches adds the assignment, grant, revision and
// replacement events of the holders (an identity's own, or a workload's
// execution identities while they were).
func changesPermissionBranches(u *changesUnion, h changesHolders) {
	ws := h.ws

	// Assignment periods: attached at valid_from, detached at valid_to. A
	// reattach is a new row, so each period is its own pair (§2.6).
	in, inArgs := h.in("a.holder_identity_account_id")
	during, duringArgs := h.during("a.holder_identity_account_id", "x.at")
	u.add(`SELECT x.at, x.event, a.id, 'assignment'::text, `+h.via("a.holder_identity_account_id")+`, x.reason, NULL::bigint, NULL::uuid,
	              NULL::uuid
	         FROM iga_policy_assignment a
	        CROSS JOIN LATERAL (VALUES (a.valid_from, '`+ChangePolicyAttached+`'::text, ''::text),
	                                   (a.valid_to, '`+ChangePolicyDetached+`'::text, a.ended_reason)) x(at, event, reason)
	        WHERE a.workspace_id = ? AND x.at IS NOT NULL AND `+in+` AND `+during,
		append(append([]any{ws}, inArgs...), duringArgs...)...)

	// Grants: Allow statements only, as rule 7 requires even though no Deny
	// grant can exist (UpsertGrant refuses one) -- judged by the statement as
	// it was when the grant started (changesGrantWasAllow), so an Allow edited
	// to Deny keeps the history of the grant it had.
	in, inArgs = h.in("g.subject_identity_account_id")
	during, duringArgs = h.during("g.subject_identity_account_id", "x.at")
	u.add(`SELECT x.at, x.event, g.id, 'grant'::text, `+h.via("g.subject_identity_account_id")+`, x.reason, NULL::bigint, NULL::uuid,
	              NULL::uuid
	         FROM iga_access_edges g
	         JOIN iga_entitlements e ON e.workspace_id = g.workspace_id AND e.id = g.entitlement_id AND e.provider = 'aws'
	         `+changesGrantRevisionJoin+`
	        CROSS JOIN LATERAL (VALUES (g.valid_from, '`+ChangeGrantStarted+`'::text, ''::text),
	                                   (g.valid_to, '`+ChangeGrantEnded+`'::text, g.ended_reason)) x(at, event, reason)
	        WHERE g.workspace_id = ? AND g.provider = 'aws' AND g.assignment_id IS NOT NULL
	          AND `+changesGrantWasAllow+`
	          AND x.at IS NOT NULL AND `+in+` AND `+during,
		append(append([]any{ws}, inArgs...), duringArgs...)...)

	// held is the (statement, holder) pairs the holders hold or held a grant
	// to, driving the statement branches from the holders' grants.
	in, inArgs = h.in("g.subject_identity_account_id")
	held := `(SELECT DISTINCT g.entitlement_id, g.subject_identity_account_id AS holder
	            FROM iga_access_edges g
	           WHERE g.workspace_id = ? AND g.provider = 'aws' AND ` + in + `) hs`
	heldArgs := append([]any{ws}, inArgs...)
	// grantValid: that holder's grant to that statement was valid at `at`.
	grantValid := func(at string) (string, []any) {
		d, dArgs := h.during("hs.holder", at)
		return `EXISTS (SELECT 1 FROM iga_access_edges g2
		                 WHERE g2.workspace_id = e.workspace_id AND g2.provider = 'aws'
		                   AND g2.entitlement_id = e.id AND g2.subject_identity_account_id = hs.holder
		                   AND g2.valid_from <= ` + at + ` AND (g2.valid_to IS NULL OR ` + at + ` <= g2.valid_to))
		        AND ` + d, dArgs
	}

	// statement_revised: a Sid-keyed statement's revision with a predecessor
	// whose content differs, while the holder's grant to it was valid.
	gv, gvArgs := grantValid("sr.valid_from")
	heldStmts := `(SELECT g.entitlement_id FROM iga_access_edges g
	                WHERE g.workspace_id = ? AND g.provider = 'aws' AND ` + in + `)`
	u.add(`SELECT sr.valid_from, '`+ChangeStatementRevised+`'::text, sr.id, 'revision'::text, `+h.via("hs.holder")+`,
	              ''::text, NULL::bigint, sr.first_seen_run_id, NULL::uuid
	         FROM `+held+`
	         JOIN iga_entitlements e ON e.workspace_id = ? AND e.id = hs.entitlement_id AND e.provider = 'aws'
	         JOIN `+changesEditedRevisionsSQL(heldStmts)+` ON sr.entitlement_id = e.id
	        WHERE `+gv,
		append(append(append(append(append([]any{}, heldArgs...), ws, ws), heldArgs...)), gvArgs...)...)

	// statement_replaced: a Sid-less statement the holder held a grant to
	// retired unsupported in a run in which a statement of the same policy
	// began. One event per (policy, run), its id derived from both.
	gv, gvArgs = grantValid("le.occurred_at")
	u.add(`SELECT le.occurred_at, '`+ChangeStatementReplaced+`'::text, `+changesReplacementID+`, 'replacement'::text,
	              `+h.via("hs.holder")+`, ''::text, le.rev::bigint, le.scan_run_id, e.policy_id
	         FROM `+held+`
	         JOIN iga_entitlements e ON e.workspace_id = ? AND e.id = hs.entitlement_id AND e.provider = 'aws' AND e.sid = ''
	         JOIN iga_lifecycle_event le ON le.workspace_id = e.workspace_id AND le.entitlement_id = e.id
	                                    AND le.event = '`+models.LifecycleRetired+`' AND le.reason = '`+models.RetiredUnsupported+`'
	        WHERE `+changesBegunInRunSQL+` AND `+gv,
		append(append(append([]any{}, heldArgs...), ws), gvArgs...)...)
}

// changesEditedRevisionsSQL is the revisions (as sr) of the statements the
// subquery stmts selects whose immediate predecessor on the same statement,
// in (valid_from, id) order, has DIFFERENT content (D-27b): the first revision
// is not a revision event, and a restored statement's reopened revision with
// unchanged content is a restoration (its lifecycle event says so), not an
// edit.
//
// The predecessor comes from ONE window over those statements' revisions,
// never a lookup per revision: 036 indexes iga_statement_revision only on its
// live revision (uq_iga_statement_revision_live, valid_to IS NULL), so a
// per-row predecessor lookup is a scan of the table per revision -- T6.10
// measured 2.5 s for the 1 913 revisions of the statements naming "*", and a
// 504 for its Changes (§5.6: 500 ms). stmts is a parenthesised subquery
// returning entitlement ids. Binds: ws, then stmts' arguments.
func changesEditedRevisionsSQL(stmts string) string {
	return `(SELECT r.id, r.entitlement_id, r.valid_from, r.first_seen_run_id
	           FROM (SELECT r0.id, r0.entitlement_id, r0.valid_from, r0.first_seen_run_id, r0.content_hash,
	                        lag(r0.content_hash) OVER (PARTITION BY r0.entitlement_id ORDER BY r0.valid_from, r0.id) AS prev_hash
	                   FROM iga_statement_revision r0
	                  WHERE r0.workspace_id = ? AND r0.entitlement_id IN ` + stmts + `) r
	          WHERE r.prev_hash <> r.content_hash) sr`
}

// changesBegunInRunSQL: a statement of e's policy was first seen or restored
// in le's run -- "another began in the same policy in the same run". No bind
// variables.
const changesBegunInRunSQL = `EXISTS (SELECT 1 FROM iga_entitlements ne
	                 JOIN iga_lifecycle_event n ON n.workspace_id = ne.workspace_id AND n.entitlement_id = ne.id
	                WHERE ne.workspace_id = e.workspace_id AND ne.policy_id = e.policy_id AND ne.provider = 'aws'
	                  AND n.scan_run_id = le.scan_run_id
	                  AND n.event IN ('` + models.LifecycleFirstSeen + `', '` + models.LifecycleRestored + `'))`

// changesResourceBranches: grant events of Allow statements naming the
// resource positively, and revisions and replacements of any statement naming
// it positively (D-68). A NotResource target never makes an event here: it is
// an exclusion, not a destination (§2.6).
func changesResourceBranches(u *changesUnion, ws, id uuid.UUID) {
	naming := `(SELECT DISTINCT t.entitlement_id FROM iga_entitlement_target t
	             WHERE t.workspace_id = ? AND t.resource_id = ? AND t.target_mode = '` + models.TargetResource + `')`

	// Grants: Allow when they started (changesGrantWasAllow), as for holders.
	u.add(`SELECT x.at, x.event, g.id, 'grant'::text, NULL::uuid, x.reason, NULL::bigint, NULL::uuid, NULL::uuid
	         FROM iga_access_edges g
	         JOIN iga_entitlements e ON e.workspace_id = g.workspace_id AND e.id = g.entitlement_id AND e.provider = 'aws'
	         `+changesGrantRevisionJoin+`
	        CROSS JOIN LATERAL (VALUES (g.valid_from, '`+ChangeGrantStarted+`'::text, ''::text),
	                                   (g.valid_to, '`+ChangeGrantEnded+`'::text, g.ended_reason)) x(at, event, reason)
	        WHERE g.workspace_id = ? AND g.provider = 'aws' AND g.assignment_id IS NOT NULL
	          AND `+changesGrantWasAllow+`
	          AND x.at IS NOT NULL AND g.entitlement_id IN `+naming,
		ws, ws, id)

	u.add(`SELECT sr.valid_from, '`+ChangeStatementRevised+`'::text, sr.id, 'revision'::text, NULL::uuid,
	              ''::text, NULL::bigint, sr.first_seen_run_id, NULL::uuid
	         FROM `+naming+` hs
	         JOIN iga_entitlements e ON e.workspace_id = ? AND e.id = hs.entitlement_id AND e.provider = 'aws'
	         JOIN `+changesEditedRevisionsSQL(naming)+` ON sr.entitlement_id = e.id`,
		ws, id, ws, ws, ws, id)

	// Replacements: the ended statement named it ...
	u.add(`SELECT le.occurred_at, '`+ChangeStatementReplaced+`'::text, `+changesReplacementID+`, 'replacement'::text,
	              NULL::uuid, ''::text, le.rev::bigint, le.scan_run_id, e.policy_id
	         FROM `+naming+` hs
	         JOIN iga_entitlements e ON e.workspace_id = ? AND e.id = hs.entitlement_id AND e.provider = 'aws' AND e.sid = ''
	         JOIN iga_lifecycle_event le ON le.workspace_id = e.workspace_id AND le.entitlement_id = e.id
	                                    AND le.event = '`+models.LifecycleRetired+`' AND le.reason = '`+models.RetiredUnsupported+`'
	        WHERE `+changesBegunInRunSQL,
		ws, id, ws)
	// ... or a statement that began in its place names it.
	u.add(`SELECT le.occurred_at, '`+ChangeStatementReplaced+`'::text, `+changesReplacementID+`, 'replacement'::text,
	              NULL::uuid, ''::text, le.rev::bigint, le.scan_run_id, e.policy_id
	         FROM `+naming+` hs
	         JOIN iga_entitlements ne ON ne.workspace_id = ? AND ne.id = hs.entitlement_id AND ne.provider = 'aws'
	         JOIN iga_lifecycle_event n ON n.workspace_id = ne.workspace_id AND n.entitlement_id = ne.id
	                                   AND n.event IN ('`+models.LifecycleFirstSeen+`', '`+models.LifecycleRestored+`')
	         JOIN iga_entitlements e ON e.workspace_id = ne.workspace_id AND e.policy_id = ne.policy_id
	                                AND e.provider = 'aws' AND e.sid = ''
	         JOIN iga_lifecycle_event le ON le.workspace_id = e.workspace_id AND le.entitlement_id = e.id
	                                    AND le.scan_run_id = n.scan_run_id
	                                    AND le.event = '`+models.LifecycleRetired+`' AND le.reason = '`+models.RetiredUnsupported+`'`,
		ws, id, ws)
}

/* -------------------------------- paging -------------------------------- */

// changesRow is one event as the page query returns it.
type changesRow struct {
	At     time.Time
	Event  string
	ID     uuid.UUID
	Src    string
	ViaID  *uuid.UUID
	Reason string
	Rev    *int64
	RunID  *uuid.UUID
	// statement_replaced only: its policy (ID is derived from policy and run).
	PolicyID *uuid.UUID

	// coverage_changed only.
	ConnectorID uuid.UUID
	Surface     string
	State       string
	PrevState   string
	PrevRun     *uuid.UUID
	Detail      json.RawMessage
	PrevDetail  json.RawMessage
}

// changesPage reads one page: newest first, keyset on (at, event, id), all
// descending (D-27). DISTINCT ON keeps one row per event where two branches
// reach the same one (a workload's two execution identities at the instant
// one edge ends and the next begins).
func changesPage(q *Query, accts *Accounts, obj changesObject, id uuid.UUID, kind, inner string, args []any,
	after *changesKey, limit int) ([]ChangeEvent, *changesKey, error) {
	cols := `u.` + strings.ReplaceAll(changesCols, ", ", ", u.")
	if kind == ChangesCoverage {
		cols = `u.at, u.event, u.id, u.rev, u.run_id, u.connector_id, u.surface, u.state, u.prev_state, u.prev_run,
		        u.detail, u.prev_detail`
	}
	sqlText := `SELECT DISTINCT ON (u.at, u.event, u.id) ` + cols + ` FROM (` + inner + `) u`
	pageArgs := append([]any{}, args...)
	if after != nil {
		sqlText += ` WHERE (u.at, u.event, u.id) < (?::timestamptz, ?::text, ?::uuid)`
		pageArgs = append(pageArgs, after.At, after.Event, after.ID)
	}
	sqlText += ` ORDER BY u.at DESC, u.event DESC, u.id DESC LIMIT ?`
	pageArgs = append(pageArgs, limit+1)

	var rows []changesRow
	if err := q.DB().Raw(sqlText, pageArgs...).Scan(&rows).Error; err != nil {
		return nil, nil, err
	}
	var next *changesKey
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		next = &changesKey{At: last.At, Event: last.Event, ID: last.ID}
	}
	var data []ChangeEvent
	var err error
	if kind == ChangesCoverage {
		data, err = changesRenderCoverage(q, accts, rows)
	} else {
		data, err = changesRenderConfiguration(q, obj, id, rows)
	}
	if err != nil {
		return nil, nil, err
	}
	return data, next, nil
}

/* ---------------------- rendering configuration events ------------------- */

// changesRenderConfiguration turns a page of rows into events. Every lookup is
// batched over the page -- one query per source table, never one per row
// (§5.6).
func changesRenderConfiguration(q *Query, obj changesObject, objID uuid.UUID, rows []changesRow) ([]ChangeEvent, error) {
	out := make([]ChangeEvent, 0, len(rows))
	if len(rows) == 0 {
		return out, nil
	}
	ids := map[string][]uuid.UUID{}
	for _, r := range rows {
		ids[r.Src] = append(ids[r.Src], r.ID)
	}
	pubs, err := changesPublications(q, rows)
	if err != nil {
		return nil, err
	}
	rels, err := changesLoadRelationships(q, ids["relationship"])
	if err != nil {
		return nil, err
	}
	asgs, err := changesLoadAssignments(q, ids["assignment"])
	if err != nil {
		return nil, err
	}
	grants, err := changesLoadGrants(q, ids["grant"])
	if err != nil {
		return nil, err
	}
	revs, err := changesLoadRevisions(q, ids["revision"])
	if err != nil {
		return nil, err
	}
	repl, err := changesLoadReplacements(q, rows)
	if err != nil {
		return nil, err
	}

	// Statement targets: the page's grants' statements (detail.targets and the
	// ended grants' paths).
	stmtIDs := []uuid.UUID{}
	for _, g := range grants {
		stmtIDs = append(stmtIDs, g.EntitlementID)
	}
	targets, err := changesTargets(q, stmtIDs)
	if err != nil {
		return nil, err
	}
	rem, err := changesRemaining(q, rows, grants, asgs, targets)
	if err != nil {
		return nil, err
	}

	labels := newChangesLabels()
	objRef := R(obj.refType, objID)
	labels.add(obj.refType, objID)
	for _, r := range rows {
		ev := ChangeEvent{
			ID:     r.Event + ":" + r.ID.String(),
			Event:  r.Event,
			At:     ChangeTime(r.At),
			Detail: map[string]any{},
		}
		if r.Reason != "" {
			reason := r.Reason
			ev.Reason = &reason
		}
		ev.Rev, ev.Run = pubs.of(r)
		if r.ViaID != nil {
			via := R(RefIdentity, *r.ViaID)
			ev.Via = &via
			labels.add(RefIdentity, *r.ViaID)
		}
		claims := &changesClaims{labels: labels}
		switch r.Src {
		case "lifecycle":
			ev.Subject = objRef
			claims.add(obj.refType, objID)
			ev.Detail["object"] = objRef
		case "relationship":
			rel, ok := rels[r.ID]
			if !ok {
				return nil, fmt.Errorf("igaread: changes page names relationship %s the snapshot lacks", r.ID)
			}
			ev.Subject = claims.add(RefRelationship, rel.ID)
			srcType, srcID := rel.source()
			ev.Detail["type"] = rel.RelationshipType
			ev.Detail["source"] = claims.add(srcType, srcID)
			ev.Detail["target"] = claims.addPtr(RefIdentity, rel.TargetIdentityAccountID)
			if rel.Mechanism != "" {
				ev.Detail["mechanism"] = rel.Mechanism
			}
			ev.Detail["state"] = rel.State
			labels.relationship(rel.ID, srcType, srcID, rel.TargetIdentityAccountID)
		case "assignment":
			a, ok := asgs[r.ID]
			if !ok {
				return nil, fmt.Errorf("igaread: changes page names assignment %s the snapshot lacks", r.ID)
			}
			ev.Subject = claims.add(RefAssignment, a.ID)
			ev.Detail["policy"] = claims.add(RefPolicy, a.PolicyID)
			ev.Detail["holder"] = claims.add(RefIdentity, a.HolderIdentityAccountID)
			ev.Detail["assignment_kind"] = a.AssignmentKind
			ev.Detail["state"] = a.State
			labels.pair(RefAssignment, a.ID, RefPolicy, a.PolicyID, RefIdentity, a.HolderIdentityAccountID)
			if r.Event == ChangePolicyDetached && a.AssignmentKind != models.CloudAttachmentBoundary {
				ev.Remaining, ev.Paths = rem.forAssignment(a.ID, claims)
			}
		case "grant":
			g, ok := grants[r.ID]
			if !ok {
				return nil, fmt.Errorf("igaread: changes page names grant %s the snapshot lacks", r.ID)
			}
			ev.Subject = claims.add(RefGrant, g.ID)
			ev.Detail["policy"] = claims.add(RefPolicy, g.PolicyID)
			ev.Detail["statement"] = claims.add(RefStatement, g.EntitlementID)
			ev.Detail["holder"] = claims.add(RefIdentity, g.Holder)
			ev.Detail["assignment"] = claims.add(RefAssignment, g.AssignmentID)
			ev.Detail["state"] = g.State
			actions, notActions := changesActions(g.NativeRights)
			ev.Detail["actions"] = actions
			if len(notActions) > 0 {
				ev.Detail["not_actions"] = notActions
			}
			tg := []string{}
			for _, t := range targets[g.EntitlementID] {
				tg = append(tg, claims.add(RefResource, t))
			}
			ev.Detail["targets"] = tg
			labels.pair(RefGrant, g.ID, RefPolicy, g.PolicyID, RefIdentity, g.Holder)
			labels.pair(RefAssignment, g.AssignmentID, RefPolicy, g.PolicyID, RefIdentity, g.Holder)
			if r.Event == ChangeGrantEnded {
				ev.Remaining, ev.Paths = rem.forGrant(g.ID, claims)
			}
		case "revision":
			rv, ok := revs[r.ID]
			if !ok {
				return nil, fmt.Errorf("igaread: changes page names revision %s the snapshot lacks", r.ID)
			}
			// The SAME statement id before and after: a Sid-keyed edit is a
			// revision of one statement, never a new one (§2.6).
			ev.Subject = claims.add(RefStatement, rv.EntitlementID)
			ev.Detail["statement"] = ev.Subject
			ev.Detail["policy"] = claims.add(RefPolicy, rv.PolicyID)
			ev.Before = map[string]any{"statement": rawOrNull(rv.PrevStatement),
				"policy_version_id": rv.PrevVersion, "content_hash": rv.PrevHash}
			ev.After = map[string]any{"statement": rawOrNull(rv.Statement),
				"policy_version_id": rv.PolicyVersionID, "content_hash": rv.ContentHash}
		case "replacement":
			if r.PolicyID == nil {
				return nil, fmt.Errorf("igaread: changes page names replacement %s without its policy", r.ID)
			}
			rp := repl[changesReplKey{policy: *r.PolicyID, run: derefUUID(r.RunID)}]
			if rp == nil {
				rp = &changesReplacement{}
			}
			ev.Subject = claims.add(RefPolicy, *r.PolicyID)
			ev.Detail["policy"] = ev.Subject
			before, after := []map[string]any{}, []map[string]any{}
			for _, s := range rp.statements {
				item := map[string]any{"statement": claims.add(RefStatement, s.EntitlementID),
					"content": rawOrNull(s.NativeRights), "content_hash": s.ContentHash}
				if s.Event == models.LifecycleRetired {
					before = append(before, item)
				} else {
					after = append(after, item)
				}
			}
			// policy_version_id before and after (D-69): null unless proven
			// (changesReplacementVersions).
			ev.Before = map[string]any{"policy_version_id": rp.before, "statements": before}
			ev.After = map[string]any{"policy_version_id": rp.after, "statements": after}
		default:
			return nil, fmt.Errorf("igaread: unknown changes source %q", r.Src)
		}
		ev.Claims = claims.refs
		out = append(out, ev)
	}

	names, err := labels.load(q)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Labels = names.pick(out[i])
	}
	return out, nil
}

// changesClaims gathers an event's refs in order (the subject first), without
// repeats, and registers each for a label.
type changesClaims struct {
	refs   []string
	seen   map[string]bool
	labels *changesLabels
}

func (c *changesClaims) add(refType string, id uuid.UUID) string {
	ref := R(refType, id)
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	if !c.seen[ref] {
		c.seen[ref] = true
		c.refs = append(c.refs, ref)
	}
	c.labels.add(refType, id)
	return ref
}

// ref names a ref the event mentions outside its own claims (a remaining
// grant, its policy and statement, a path's target): labelled, not claimed.
func (c *changesClaims) ref(refType string, id uuid.UUID) string {
	c.labels.add(refType, id)
	return R(refType, id)
}

func (c *changesClaims) addPtr(refType string, id *uuid.UUID) any {
	if id == nil {
		return nil
	}
	return c.add(refType, *id)
}

func rawOrNull(raw json.RawMessage) any {
	if len(raw) == 0 || !json.Valid(raw) {
		return nil
	}
	return raw
}

func derefUUID(id *uuid.UUID) uuid.UUID {
	if id == nil {
		return uuid.Nil
	}
	return *id
}

// changesActions reads a statement's Action and NotAction verbatim (a string
// or a list), for "Grant ended s3:PutObject on support-tickets/*".
func changesActions(native json.RawMessage) (actions, notActions []string) {
	var st struct {
		Action    json.RawMessage `json:"Action"`
		NotAction json.RawMessage `json:"NotAction"`
	}
	_ = json.Unmarshal(native, &st)
	return stringOrList(st.Action), stringOrList(st.NotAction)
}

func stringOrList(raw json.RawMessage) []string {
	out := []string{}
	if len(raw) == 0 {
		return out
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return append(out, one)
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return append(out, many...)
	}
	return out
}

/* ---------------------------- publications ------------------------------ */

// changesPubs recovers each row's revision and run: a row that records them
// (lifecycle events, replacements) keeps its own; a revision has its run and
// looks up its revision; a start or end joins its time to the ONE publication
// with that published_at (D-26). A time shared by two publications, or by
// none, names nothing -- never a guess.
type changesPubs struct {
	byAt  map[int64]changesPub
	byRun map[uuid.UUID]int64
}

type changesPub struct {
	Rev   int64
	RunID uuid.UUID
}

func changesPublications(q *Query, rows []changesRow) (*changesPubs, error) {
	p := &changesPubs{byAt: map[int64]changesPub{}, byRun: map[uuid.UUID]int64{}}
	var ats []time.Time
	var runs []uuid.UUID
	for _, r := range rows {
		switch {
		case r.Rev != nil && r.RunID != nil:
		case r.RunID != nil:
			runs = append(runs, *r.RunID)
		default:
			ats = append(ats, r.At)
		}
	}
	if len(ats) > 0 {
		var found []struct {
			PublishedAt time.Time
			Rev         int64
			RunID       uuid.UUID
			N           int64
		}
		if err := q.DB().Raw(`SELECT published_at, min(rev) AS rev, (array_agg(scan_run_id))[1] AS run_id, count(*) AS n
		                        FROM iga_publication
		                       WHERE workspace_id = ? AND published_at IN ?
		                       GROUP BY published_at`, q.WS, ats).Scan(&found).Error; err != nil {
			return nil, err
		}
		for _, f := range found {
			if f.N == 1 {
				p.byAt[f.PublishedAt.UnixMicro()] = changesPub{Rev: f.Rev, RunID: f.RunID}
			}
		}
	}
	if len(runs) > 0 {
		var found []struct {
			ScanRunID uuid.UUID
			Rev       int64
		}
		if err := q.DB().Raw(`SELECT scan_run_id, rev FROM iga_publication WHERE workspace_id = ? AND scan_run_id IN ?`,
			q.WS, runs).Scan(&found).Error; err != nil {
			return nil, err
		}
		for _, f := range found {
			p.byRun[f.ScanRunID] = f.Rev
		}
	}
	return p, nil
}

// of is a row's (rev, run) as rendered.
func (p *changesPubs) of(r changesRow) (*int64, *string) {
	run := func(id uuid.UUID) *string {
		s := R(RefScanRun, id)
		return &s
	}
	switch {
	case r.Rev != nil && r.RunID != nil:
		rev := *r.Rev
		return &rev, run(*r.RunID)
	case r.RunID != nil:
		if rev, ok := p.byRun[*r.RunID]; ok {
			return &rev, run(*r.RunID)
		}
		return nil, run(*r.RunID)
	}
	if pub, ok := p.byAt[r.At.UnixMicro()]; ok {
		rev := pub.Rev
		return &rev, run(pub.RunID)
	}
	return nil, nil
}

/* ------------------------------ row loaders ------------------------------ */

type changesRel struct {
	ID                        uuid.UUID
	RelationshipType          string
	SourceIdentityAccountID   *uuid.UUID
	SourceWorkloadID          *uuid.UUID
	SourceExternalPrincipalID *uuid.UUID
	TargetIdentityAccountID   *uuid.UUID
	Mechanism                 string
	State                     string
}

// source is the one source endpoint that is set, as a typed ref's type and id.
func (r changesRel) source() (string, uuid.UUID) {
	switch {
	case r.SourceIdentityAccountID != nil:
		return RefIdentity, *r.SourceIdentityAccountID
	case r.SourceWorkloadID != nil:
		return RefWorkload, *r.SourceWorkloadID
	case r.SourceExternalPrincipalID != nil:
		return RefExternalPrincipal, *r.SourceExternalPrincipalID
	}
	return RefIdentity, uuid.Nil
}

func changesLoadRelationships(q *Query, ids []uuid.UUID) (map[uuid.UUID]changesRel, error) {
	out := map[uuid.UUID]changesRel{}
	if len(ids) == 0 {
		return out, nil
	}
	var rows []changesRel
	if err := q.DB().Raw(`SELECT id, relationship_type, source_identity_account_id, source_workload_id,
	                             source_external_principal_id, target_identity_account_id, mechanism, state
	                        FROM iga_relationship WHERE workspace_id = ? AND id IN ?`, q.WS, ids).Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.ID] = r
	}
	return out, nil
}

type changesAsg struct {
	ID                      uuid.UUID
	PolicyID                uuid.UUID
	HolderIdentityAccountID uuid.UUID
	AssignmentKind          string
	State                   string
}

func changesLoadAssignments(q *Query, ids []uuid.UUID) (map[uuid.UUID]changesAsg, error) {
	out := map[uuid.UUID]changesAsg{}
	if len(ids) == 0 {
		return out, nil
	}
	var rows []changesAsg
	if err := q.DB().Raw(`SELECT id, policy_id, holder_identity_account_id, assignment_kind, state
	                        FROM iga_policy_assignment WHERE workspace_id = ? AND id IN ?`, q.WS, ids).Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.ID] = r
	}
	return out, nil
}

type changesGrant struct {
	ID            uuid.UUID
	Holder        uuid.UUID
	EntitlementID uuid.UUID
	AssignmentID  uuid.UUID
	PolicyID      uuid.UUID
	State         string
	NativeRights  json.RawMessage
}

func changesLoadGrants(q *Query, ids []uuid.UUID) (map[uuid.UUID]changesGrant, error) {
	out := map[uuid.UUID]changesGrant{}
	if len(ids) == 0 {
		return out, nil
	}
	// The same Allow rule as the union that chose these ids
	// (changesGrantWasAllow): a grant the page names is always found here.
	var rows []changesGrant
	if err := q.DB().Raw(`SELECT g.id, g.subject_identity_account_id AS holder, g.entitlement_id, g.assignment_id,
	                             e.policy_id, g.state, e.native_rights
	                        FROM iga_access_edges g
	                        JOIN iga_entitlements e ON e.workspace_id = g.workspace_id AND e.id = g.entitlement_id
	                                               AND e.provider = 'aws'
	                        `+changesGrantRevisionJoin+`
	                       WHERE g.workspace_id = ? AND g.provider = 'aws' AND g.id IN ? AND `+changesGrantWasAllow,
		q.WS, ids).Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.ID] = r
	}
	return out, nil
}

type changesRevision struct {
	ID              uuid.UUID
	EntitlementID   uuid.UUID
	PolicyID        uuid.UUID
	Statement       json.RawMessage
	PolicyVersionID string
	ContentHash     string
	PrevStatement   json.RawMessage
	PrevVersion     string
	PrevHash        string
}

// changesLoadRevisions reads each revision with its immediate predecessor --
// the before and after of statement_revised (§5.3, E7a).
func changesLoadRevisions(q *Query, ids []uuid.UUID) (map[uuid.UUID]changesRevision, error) {
	out := map[uuid.UUID]changesRevision{}
	if len(ids) == 0 {
		return out, nil
	}
	var rows []changesRevision
	if err := q.DB().Raw(`SELECT sr.id, sr.entitlement_id, e.policy_id, sr.statement, sr.policy_version_id, sr.content_hash,
	                             prev.statement AS prev_statement, prev.policy_version_id AS prev_version,
	                             prev.content_hash AS prev_hash
	                        FROM iga_statement_revision sr
	                        JOIN iga_entitlements e ON e.workspace_id = sr.workspace_id AND e.id = sr.entitlement_id
	                                               AND e.provider = 'aws'
	                        JOIN LATERAL (SELECT p.statement, p.policy_version_id, p.content_hash
	                                        FROM iga_statement_revision p
	                                       WHERE p.workspace_id = sr.workspace_id AND p.entitlement_id = sr.entitlement_id
	                                         AND (p.valid_from, p.id) < (sr.valid_from, sr.id)
	                                       ORDER BY p.valid_from DESC, p.id DESC LIMIT 1) prev ON true
	                       WHERE sr.workspace_id = ? AND sr.id IN ?`, q.WS, ids).Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.ID] = r
	}
	return out, nil
}

type changesReplKey struct{ policy, run uuid.UUID }

type changesReplStatement struct {
	ScanRunID     uuid.UUID
	PolicyID      uuid.UUID
	EntitlementID uuid.UUID
	Event         string
	ContentHash   string
	NativeRights  json.RawMessage
}

// changesReplacement is one statement_replaced's content: the statements that
// ended and began, and the policy's version on each side (D-69) -- a string,
// or nil when the data does not prove one.
type changesReplacement struct {
	rev           int64 // the replacing run's revision (its lifecycle events')
	statements    []changesReplStatement
	before, after any
}

// changesLoadReplacements reads, for each statement_replaced on the page,
// every statement of the policy that ended (Sid-less, retired unsupported) and
// that began (first seen or restored) in the run. They are listed as they are,
// never paired: with several Sid-less statements changed in one run, nothing
// says which new one replaced which old one.
func changesLoadReplacements(q *Query, rows []changesRow) (map[changesReplKey]*changesReplacement, error) {
	out := map[changesReplKey]*changesReplacement{}
	var policies, runs []uuid.UUID
	for _, r := range rows {
		if r.Src == "replacement" && r.RunID != nil && r.PolicyID != nil {
			k := changesReplKey{policy: *r.PolicyID, run: *r.RunID}
			if out[k] == nil {
				// No revision (never, for a lifecycle row): no confirmation is
				// provably earlier, so "before" stays null.
				rp := &changesReplacement{rev: 0}
				if r.Rev != nil {
					rp.rev = *r.Rev
				}
				out[k] = rp
				policies = append(policies, k.policy)
				runs = append(runs, k.run)
			}
		}
	}
	if len(policies) == 0 {
		return out, nil
	}
	var found []changesReplStatement
	if err := q.DB().Raw(`SELECT le.scan_run_id, e.policy_id, le.entitlement_id, le.event, e.content_hash, e.native_rights
	                        FROM iga_entitlements e
	                        JOIN iga_lifecycle_event le ON le.workspace_id = e.workspace_id AND le.entitlement_id = e.id
	                       WHERE e.workspace_id = ? AND e.provider = 'aws' AND e.policy_id IN ? AND le.scan_run_id IN ?
	                         AND ((le.event = ? AND le.reason = ? AND e.sid = '') OR le.event IN ?)
	                       ORDER BY e.statement_index NULLS LAST, e.id`,
		q.WS, policies, runs, models.LifecycleRetired, models.RetiredUnsupported,
		[]string{models.LifecycleFirstSeen, models.LifecycleRestored}).Scan(&found).Error; err != nil {
		return nil, err
	}
	for _, s := range found {
		if rp := out[changesReplKey{policy: s.PolicyID, run: s.ScanRunID}]; rp != nil {
			rp.statements = append(rp.statements, s)
		}
	}
	if err := changesReplacementVersions(q, out, policies); err != nil {
		return nil, err
	}
	return out, nil
}

// changesObservedSubjectFact is the key under which the observation writer
// names, inside an observation's facts, the cloud_* row it was observed on:
// "policy:<cloud_policy id>" for a policy version (services.ObservedSubjectFact;
// igaread does not import services). It survives the row's deletion, which
// SETs NULL cloud_observation.policy_id.
const changesObservedSubjectFact = "observed_subject"

// changesReplacementVersions is D-69 for statement_replaced: the policy's
// default version before and after the run that replaced its statements.
//
// A Sid-less statement has no revision to carry a version
// (iga_statement_revision holds Sid-keyed statements only, §3 036) and the
// policy row keeps only its CURRENT version_id, so both sides come from the
// policy-version observations (D-66's source: the collector records one per
// version of a managed policy, its facts naming version_id):
//
//	after   the version the replacing run itself read
//	before  the version read by the runs that last confirmed the ended
//	        statements (their support rows' last_confirmed_run_id), when
//	        those were published before the replacing run -- the last read
//	        that still contained them. A statement restored since was
//	        confirmed again later, and its support row keeps only that.
//
// A run is proven to have read a version only when that version's
// observation was first recorded or last confirmed by that run, from a
// readable document: an observation keeps no other run. So a side renders
// null -- never a guess -- when no such observation exists (a policy whose
// version an older run read and a later run read again: the observation's
// last confirmation has moved on), when the runs read more than one version,
// or when the policy has no native id to observe it by. An inline policy has
// no versions in AWS and renders "" on both sides, as its statement
// revisions store.
func changesReplacementVersions(q *Query, out map[changesReplKey]*changesReplacement, policies []uuid.UUID) error {
	var pols []struct {
		ID         uuid.UUID
		PolicyKind string
		NativeRef  string
	}
	if err := q.DB().Raw(`SELECT id, policy_kind, native_ref FROM iga_policy
	                       WHERE workspace_id = ? AND provider = 'aws' AND id IN ?`, q.WS, policies).Scan(&pols).Error; err != nil {
		return err
	}
	native := map[uuid.UUID]string{}
	for _, p := range pols {
		if p.PolicyKind == models.PolicyKindInline {
			for k, rp := range out {
				if k.policy == p.ID {
					rp.before, rp.after = "", ""
				}
			}
			continue
		}
		if p.NativeRef != "" {
			native[p.ID] = p.NativeRef
		}
	}

	// The runs that last confirmed each ended statement, with their
	// publications' revisions: only a confirmation published BEFORE the
	// replacing run speaks for "before". A statement restored since has been
	// confirmed again after it, and its support row keeps only that last
	// confirmation -- the read before the replacement is then not retained.
	type confirmed struct {
		run uuid.UUID
		rev int64
	}
	var ended []uuid.UUID
	for _, rp := range out {
		for _, s := range rp.statements {
			if s.Event == models.LifecycleRetired {
				ended = append(ended, s.EntitlementID)
			}
		}
	}
	lastRead := map[uuid.UUID][]confirmed{} // statement -> runs that last confirmed it
	if len(ended) > 0 {
		var sup []struct {
			EntitlementID      uuid.UUID
			LastConfirmedRunID uuid.UUID
			Rev                int64
		}
		if err := q.DB().Raw(`SELECT DISTINCT s.entitlement_id, s.last_confirmed_run_id, p.rev
		                        FROM iga_object_support s
		                        JOIN iga_publication p ON p.workspace_id = s.workspace_id AND p.scan_run_id = s.last_confirmed_run_id
		                       WHERE s.workspace_id = ? AND s.entitlement_id IN ?`,
			q.WS, ended).Scan(&sup).Error; err != nil {
			return err
		}
		for _, s := range sup {
			lastRead[s.EntitlementID] = append(lastRead[s.EntitlementID], confirmed{s.LastConfirmedRunID, s.Rev})
		}
	}
	// before is, per event, the ended statements' confirmations published
	// before the replacing run.
	before := func(rp *changesReplacement) []uuid.UUID {
		var runs []uuid.UUID
		for _, s := range rp.statements {
			if s.Event != models.LifecycleRetired {
				continue
			}
			for _, c := range lastRead[s.EntitlementID] {
				if c.rev < rp.rev {
					runs = append(runs, c.run)
				}
			}
		}
		return runs
	}

	// Which run read which version of which policy: one query for the page.
	natives, runs := []string{}, []uuid.UUID{}
	seenN, seenR := map[string]bool{}, map[uuid.UUID]bool{}
	addRun := func(id uuid.UUID) {
		if !seenR[id] {
			seenR[id] = true
			runs = append(runs, id)
		}
	}
	for k, rp := range out {
		n, ok := native[k.policy]
		if !ok {
			continue
		}
		if !seenN[n] {
			seenN[n] = true
			natives = append(natives, n)
		}
		addRun(k.run)
		for _, run := range before(rp) {
			addRun(run)
		}
	}
	if len(natives) == 0 {
		return nil
	}
	var obs []struct {
		SubjectNativeID    string
		ScanRunID          uuid.UUID
		LastConfirmedRunID *uuid.UUID
		VersionID          *string
	}
	if err := q.DB().Raw(`SELECT o.subject_native_id, o.scan_run_id, o.last_confirmed_run_id,
	                             o.sanitized_facts->>'version_id' AS version_id
	                        FROM cloud_observation o
	                       WHERE o.workspace_id = ? AND o.subject_native_id IN ?
	                         AND (o.policy_id IS NOT NULL OR o.sanitized_facts->>? LIKE 'policy:%')
	                         AND COALESCE(o.sanitized_facts->>'document_error', '') = ''
	                         AND (o.scan_run_id IN ? OR o.last_confirmed_run_id IN ?)`,
		q.WS, natives, changesObservedSubjectFact, runs, runs).Scan(&obs).Error; err != nil {
		return err
	}
	type readKey struct {
		native string
		run    uuid.UUID
	}
	read := map[readKey]map[string]bool{} // (policy, run) -> versions that run read
	note := func(k readKey, v string) {
		if read[k] == nil {
			read[k] = map[string]bool{}
		}
		read[k][v] = true
	}
	for _, o := range obs {
		if o.VersionID == nil || *o.VersionID == "" {
			continue
		}
		note(readKey{o.SubjectNativeID, o.ScanRunID}, *o.VersionID)
		if o.LastConfirmedRunID != nil {
			note(readKey{o.SubjectNativeID, *o.LastConfirmedRunID}, *o.VersionID)
		}
	}
	// only is the one version the runs read, or nil.
	only := func(n string, runs []uuid.UUID) any {
		vs := map[string]bool{}
		for _, run := range runs {
			for v := range read[readKey{n, run}] {
				vs[v] = true
			}
		}
		if len(vs) != 1 {
			return nil
		}
		for v := range vs {
			return v
		}
		return nil
	}
	for k, rp := range out {
		n, ok := native[k.policy]
		if !ok {
			continue
		}
		rp.after = only(n, []uuid.UUID{k.run})
		rp.before = only(n, before(rp))
	}
	return nil
}

// changesTargets is each statement's POSITIVE targets (target_mode resource),
// in statement order. A statement's targets are its current content's
// (ReplaceTargets); a retired statement keeps its last.
func changesTargets(q *Query, stmts []uuid.UUID) (map[uuid.UUID][]uuid.UUID, error) {
	out := map[uuid.UUID][]uuid.UUID{}
	if len(stmts) == 0 {
		return out, nil
	}
	var rows []struct {
		EntitlementID uuid.UUID
		ResourceID    uuid.UUID
	}
	if err := q.DB().Raw(`SELECT DISTINCT t.entitlement_id, t.resource_id, t.ordinal
	                        FROM iga_entitlement_target t
	                       WHERE t.workspace_id = ? AND t.entitlement_id IN ? AND t.target_mode = ?
	                       ORDER BY t.entitlement_id, t.ordinal, t.resource_id`,
		q.WS, stmts, models.TargetResource).Scan(&rows).Error; err != nil {
		return nil, err
	}
	seen := map[[2]uuid.UUID]bool{}
	for _, r := range rows {
		k := [2]uuid.UUID{r.EntitlementID, r.ResourceID}
		if !seen[k] {
			seen[k] = true
			out[r.EntitlementID] = append(out[r.EntitlementID], r.ResourceID)
		}
	}
	return out, nil
}

/* ------------------------------- remaining ------------------------------- */

// changesRemainingSet is what D-28 needs for the page's ended grants and
// detached assignments.
type changesRemainingSet struct {
	endedTargets map[uuid.UUID][]uuid.UUID // ended grant or assignment -> its positive targets
	holder       map[uuid.UUID]uuid.UUID   // ended grant or assignment -> its holder
	candidates   map[uuid.UUID][]changesCandidate
}

type changesCandidate struct {
	ID              uuid.UUID
	Holder          uuid.UUID
	State           string
	LastConfirmedAt *time.Time
	AssignmentID    uuid.UUID
	EntitlementID   uuid.UUID
	PolicyID        uuid.UUID
	ResourceID      uuid.UUID
}

// changesRemaining reads, AT THE CURRENT REVISION (D-28), every holder's
// non-ended grants that name a target of the page's ended grants or detached
// assignments. Two queries for the whole page: the detached assignments'
// targets, and the candidates.
func changesRemaining(q *Query, rows []changesRow, grants map[uuid.UUID]changesGrant,
	asgs map[uuid.UUID]changesAsg, targets map[uuid.UUID][]uuid.UUID) (*changesRemainingSet, error) {
	set := &changesRemainingSet{endedTargets: map[uuid.UUID][]uuid.UUID{}, holder: map[uuid.UUID]uuid.UUID{},
		candidates: map[uuid.UUID][]changesCandidate{}}
	var detached []uuid.UUID
	for _, r := range rows {
		switch {
		case r.Src == "grant" && r.Event == ChangeGrantEnded:
			if g, ok := grants[r.ID]; ok {
				set.endedTargets[g.ID] = targets[g.EntitlementID]
				set.holder[g.ID] = g.Holder
			}
		case r.Src == "assignment" && r.Event == ChangePolicyDetached:
			if a, ok := asgs[r.ID]; ok && a.AssignmentKind != models.CloudAttachmentBoundary {
				detached = append(detached, a.ID)
				set.holder[a.ID] = a.HolderIdentityAccountID
				set.endedTargets[a.ID] = []uuid.UUID{}
			}
		}
	}
	if len(detached) > 0 {
		// The ended claim's targets are history: the grants that were Allow
		// grants through the assignment (changesGrantWasAllow). The remaining
		// candidates below are the CURRENT revision's, judged by the
		// statements' current effect.
		var at []struct {
			AssignmentID uuid.UUID
			ResourceID   uuid.UUID
		}
		if err := q.DB().Raw(`SELECT DISTINCT g.assignment_id, t.resource_id
		                        FROM iga_access_edges g
		                        JOIN iga_entitlements e ON e.workspace_id = g.workspace_id AND e.id = g.entitlement_id
		                                               AND e.provider = 'aws'
		                        `+changesGrantRevisionJoin+`
		                        JOIN iga_entitlement_target t ON t.workspace_id = g.workspace_id
		                                                     AND t.entitlement_id = g.entitlement_id AND t.target_mode = ?
		                       WHERE g.workspace_id = ? AND g.provider = 'aws' AND g.assignment_id IN ?
		                         AND `+changesGrantWasAllow+`
		                       ORDER BY g.assignment_id, t.resource_id`,
			models.TargetResource, q.WS, detached).Scan(&at).Error; err != nil {
			return nil, err
		}
		for _, r := range at {
			set.endedTargets[r.AssignmentID] = append(set.endedTargets[r.AssignmentID], r.ResourceID)
		}
	}
	holders, resources := []uuid.UUID{}, []uuid.UUID{}
	seenH, seenR := map[uuid.UUID]bool{}, map[uuid.UUID]bool{}
	for k, ts := range set.endedTargets {
		if h := set.holder[k]; !seenH[h] {
			seenH[h] = true
			holders = append(holders, h)
		}
		for _, t := range ts {
			if !seenR[t] {
				seenR[t] = true
				resources = append(resources, t)
			}
		}
	}
	if len(holders) == 0 || len(resources) == 0 {
		return set, nil
	}
	// The candidates are what remains NOW: non-ended grants of statements that
	// are Allow at the current revision (rule 7 as written).
	var cands []changesCandidate
	if err := q.DB().Raw(`SELECT g.id, g.subject_identity_account_id AS holder, g.state, g.last_confirmed_at,
	                             g.assignment_id, g.entitlement_id, e.policy_id, t.resource_id
	                        FROM iga_access_edges g
	                        JOIN iga_entitlements e ON e.workspace_id = g.workspace_id AND e.id = g.entitlement_id
	                                               AND e.provider = 'aws' AND e.effect = ?
	                        JOIN iga_entitlement_target t ON t.workspace_id = g.workspace_id
	                                                     AND t.entitlement_id = g.entitlement_id AND t.target_mode = ?
	                       WHERE g.workspace_id = ? AND g.provider = 'aws' AND g.assignment_id IS NOT NULL
	                         AND g.state IN ? AND g.subject_identity_account_id IN ? AND t.resource_id IN ?
	                       ORDER BY g.id, t.resource_id`,
		models.EffectAllow, models.TargetResource, q.WS, []string{models.RelCurrent, models.RelStale},
		holders, resources).Scan(&cands).Error; err != nil {
		return nil, err
	}
	for _, c := range cands {
		set.candidates[c.Holder] = append(set.candidates[c.Holder], c)
	}
	return set, nil
}

func (s *changesRemainingSet) forGrant(grant uuid.UUID, claims *changesClaims) (*[]ChangeRemaining, *[]ChangePath) {
	return s.build(grant, func(c changesCandidate) bool { return c.ID != grant }, claims)
}

func (s *changesRemainingSet) forAssignment(asg uuid.UUID, claims *changesClaims) (*[]ChangeRemaining, *[]ChangePath) {
	// A grant still reached through the detached assignment itself is not
	// another path (its assignment ended; it is at most stale on its way out).
	return s.build(asg, func(c changesCandidate) bool { return c.AssignmentID != asg }, claims)
}

// build is D-28 for one ended claim: the holder's remaining grants naming a
// target the claim named, and per target whether a current, only a stale, or
// no grant remains.
func (s *changesRemainingSet) build(ended uuid.UUID, keep func(changesCandidate) bool,
	claims *changesClaims) (*[]ChangeRemaining, *[]ChangePath) {
	remaining, paths := []ChangeRemaining{}, []ChangePath{}
	ts, ok := s.endedTargets[ended]
	if !ok {
		return &remaining, &paths
	}
	named := map[uuid.UUID]bool{}
	for _, t := range ts {
		named[t] = true
	}
	best := map[uuid.UUID]string{}
	byGrant := map[uuid.UUID]*ChangeRemaining{}
	order := []uuid.UUID{}
	for _, c := range s.candidates[s.holder[ended]] {
		if !keep(c) || !named[c.ResourceID] {
			continue
		}
		rm := byGrant[c.ID]
		if rm == nil {
			rm = &ChangeRemaining{
				Grant: claims.ref(RefGrant, c.ID), State: c.State, LastConfirmedAt: TS(c.LastConfirmedAt),
				Policy: claims.ref(RefPolicy, c.PolicyID), Statement: claims.ref(RefStatement, c.EntitlementID),
				Targets: []string{},
			}
			claims.labels.pair(RefGrant, c.ID, RefPolicy, c.PolicyID, RefIdentity, c.Holder)
			byGrant[c.ID] = rm
			order = append(order, c.ID)
		}
		rm.Targets = append(rm.Targets, claims.ref(RefResource, c.ResourceID))
		switch {
		case c.State == models.RelCurrent:
			best[c.ResourceID] = models.RelCurrent
		case best[c.ResourceID] == "":
			best[c.ResourceID] = c.State
		}
	}
	// Current before stale, then by grant id: a stable order.
	sort.SliceStable(order, func(i, j int) bool {
		a, b := byGrant[order[i]], byGrant[order[j]]
		if (a.State == models.RelCurrent) != (b.State == models.RelCurrent) {
			return a.State == models.RelCurrent
		}
		return a.Grant < b.Grant
	})
	for _, id := range order {
		remaining = append(remaining, *byGrant[id])
	}
	for _, t := range ts {
		state := PathRemainsNone
		switch best[t] {
		case models.RelCurrent:
			state = PathRemainsCurrent
		case models.RelStale:
			state = PathRemainsStale
		}
		paths = append(paths, ChangePath{Target: claims.ref(RefResource, t), Remains: state})
	}
	return &remaining, &paths
}

/* -------------------------------- labels -------------------------------- */

// changesLabels names every ref a page mentions, loaded once per type for the
// whole page. Claim refs (relationship, assignment, grant) are named from
// their endpoints: "<source> → <target>", "<policy> → <holder>".
type changesLabels struct {
	want  map[string]map[uuid.UUID]bool
	pairs map[string][2]string // claim ref -> the two refs it is named from
	names map[string]string
}

func newChangesLabels() *changesLabels {
	return &changesLabels{want: map[string]map[uuid.UUID]bool{}, pairs: map[string][2]string{}, names: map[string]string{}}
}

func (l *changesLabels) add(refType string, id uuid.UUID) {
	if id == uuid.Nil {
		return
	}
	if l.want[refType] == nil {
		l.want[refType] = map[uuid.UUID]bool{}
	}
	l.want[refType][id] = true
}

// pair names a claim from two refs (and asks for their names).
func (l *changesLabels) pair(claimType string, claim uuid.UUID, aType string, a uuid.UUID, bType string, b uuid.UUID) {
	l.add(aType, a)
	l.add(bType, b)
	l.pairs[R(claimType, claim)] = [2]string{R(aType, a), R(bType, b)}
}

func (l *changesLabels) relationship(id uuid.UUID, srcType string, src uuid.UUID, target *uuid.UUID) {
	if target == nil {
		return
	}
	l.pair(RefRelationship, id, srcType, src, RefIdentity, *target)
}

func (l *changesLabels) ids(refType string) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(l.want[refType]))
	for id := range l.want[refType] {
		out = append(out, id)
	}
	return out
}

// load reads the names: one query per object type on the page.
func (l *changesLabels) load(q *Query) (*changesLabels, error) {
	named := func(refType, sqlText string) error {
		ids := l.ids(refType)
		if len(ids) == 0 {
			return nil
		}
		var rows []struct {
			ID   uuid.UUID
			Name string
		}
		if err := q.DB().Raw(sqlText, q.WS, ids).Scan(&rows).Error; err != nil {
			return err
		}
		for _, r := range rows {
			l.names[R(refType, r.ID)] = r.Name
		}
		return nil
	}
	for refType, sqlText := range map[string]string{
		RefIdentity: `SELECT id, display_name AS name FROM iga_identity_accounts WHERE workspace_id = ? AND provider = 'aws' AND id IN ?`,
		RefWorkload: `SELECT id, display_name AS name FROM iga_workload WHERE workspace_id = ? AND provider = 'aws' AND id IN ?`,
		RefResource: `SELECT id, display_name AS name FROM iga_resources WHERE workspace_id = ? AND provider = 'aws' AND id IN ?`,
		RefPolicy:   `SELECT id, display_name AS name FROM iga_policy WHERE workspace_id = ? AND provider = 'aws' AND id IN ?`,
		// A statement is named by its Sid, else by its 1-based position (D-84).
		RefStatement: `SELECT id, CASE WHEN sid <> '' THEN sid
		                              WHEN statement_index IS NOT NULL THEN 'Statement ' || (statement_index + 1)::text
		                              ELSE 'Statement' END AS name
		                 FROM iga_entitlements WHERE workspace_id = ? AND provider = 'aws' AND id IN ?`,
	} {
		if err := named(refType, sqlText); err != nil {
			return nil, err
		}
	}
	if ids := l.ids(RefExternalPrincipal); len(ids) > 0 {
		var rows []struct {
			ID           uuid.UUID
			Mechanism    string
			Issuer       string
			SubjectClaim string
		}
		if err := q.DB().Raw(`SELECT id, mechanism, issuer, subject_claim FROM iga_external_principal
		                       WHERE workspace_id = ? AND id IN ?`, q.WS, ids).Scan(&rows).Error; err != nil {
			return nil, err
		}
		for _, r := range rows {
			l.names[R(RefExternalPrincipal, r.ID)] = changesExternalLabel(r.Mechanism, r.Issuer, r.SubjectClaim)
		}
	}
	for claim, ends := range l.pairs {
		a, b := l.names[ends[0]], l.names[ends[1]]
		if a != "" && b != "" {
			l.names[claim] = a + " → " + b
		}
	}
	return l, nil
}

// pick is the labels one event renders: a name for each of its refs that has
// one, including the remaining grants' and paths' refs.
func (l *changesLabels) pick(ev ChangeEvent) map[string]string {
	out := map[string]string{}
	add := func(ref string) {
		if n, ok := l.names[ref]; ok {
			out[ref] = n
		}
	}
	for _, ref := range ev.Claims {
		add(ref)
	}
	if ev.Via != nil {
		add(*ev.Via)
	}
	if ev.Remaining != nil {
		for _, rm := range *ev.Remaining {
			add(rm.Grant)
			add(rm.Policy)
			add(rm.Statement)
			for _, t := range rm.Targets {
				add(t)
			}
		}
	}
	if ev.Paths != nil {
		for _, p := range *ev.Paths {
			add(p.Target)
		}
	}
	return out
}

// changesExternalLabel names an external principal (D-87): an account by its
// id, the any-principal node as "any AWS principal", an AWS principal or
// service by what the trust policy named, a federated principal by issuer and
// subject, a Kubernetes service account as namespace/name.
func changesExternalLabel(mechanism, issuer, subject string) string {
	switch mechanism {
	case models.ExternalPrincipalAWSAccount:
		if subject == "*" {
			return "any AWS principal"
		}
		return subject
	case models.ExternalPrincipalAWSPrincipal, models.ExternalPrincipalAWSService:
		return subject
	case models.ExternalPrincipalK8sServiceAccount:
		s := strings.TrimPrefix(subject, "pod:")
		s = strings.TrimPrefix(s, "system:serviceaccount:")
		return strings.Replace(s, ":", "/", 1)
	}
	if subject == "" || subject == "*" {
		return issuer
	}
	return issuer + " " + subject
}
