package igaread

// Shared pieces of the identity and external-principal detail routes (T6.3,
// §5.3 Identities and External principals): the readable-identity load, the
// sources list, the tab envelope, per-object meta.coverage, D-74 stale_reason
// for claims (edges and assignments), section keyset paging, and the D-84
// statement index. Everything private is prefixed idetail: other detail
// routes are written in this package at the same time.

import (
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

/* ------------------------------ parameters -------------------------------- */

// idetailParams validates a detail or tab route's query string: every name
// must be one the route accepts (anything else is 400 invalid_parameter
// naming it, as D-75 has the lists do), and rev is parsed. Parameters are
// checked before the snapshot opens (D-10).
func idetailParams(vals url.Values, allowed ...string) (*int64, *Error) {
	for name := range vals {
		if !contains(allowed, name) {
			return nil, InvalidParameter(name, name+" is not a parameter of this route")
		}
	}
	return ParseRev(vals)
}

// idetailIncludeEnded reads include_ended (D-12): absent or "false" keeps the
// default lifecycle filter, current and stale; "true" adds ended rows.
func idetailIncludeEnded(vals url.Values) (bool, *Error) {
	switch vals.Get("include_ended") {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	}
	return false, InvalidParameter("include_ended", "include_ended must be true or false")
}

// idetailLimit reads a tab's limit: 1-200, default 100 (§5.2, D-77).
func idetailLimit(vals url.Values) (int, *Error) {
	l := vals.Get("limit")
	if l == "" {
		return DefaultLimit, nil
	}
	n, err := strconv.Atoi(l)
	if err != nil || n < 1 || n > MaxLimit {
		return 0, InvalidParameter("limit", fmt.Sprintf("limit must be 1-%d", MaxLimit))
	}
	return n, nil
}

// idetailEdgeStates is the lifecycle filter on a tab's claims (D-12): current
// and stale by default -- stale rows are returned and marked, never dropped --
// and ended ones only when asked for.
func idetailEdgeStates(includeEnded bool) []string {
	if includeEnded {
		return []string{StateCurrent, StateStale, StateEnded}
	}
	return []string{StateCurrent, StateStale}
}

// idetailFilterHash is the filter set a tab cursor binds to: include_ended
// only. The section and the object are in the cursor's ROUTE (D-62), so a
// first-page cursor issued with no section parameter is valid on the
// ?section=<name>&cursor= request that follows it.
func idetailFilterHash(includeEnded bool) string {
	return FilterHash(url.Values{"include_ended": {strconv.FormatBool(includeEnded)}})
}

/* ------------------------------- identities ------------------------------- */

// idetailIdentityRow is one identity as the detail routes read it: the list
// record plus the columns only the detail shows.
type idetailIdentityRow struct {
	IdentityRecord
	Continuity    string
	ProviderAttrs json.RawMessage
}

// idetailLoadIdentity reads the identity a detail route shows: this
// workspace's, provider 'aws', with at least one support row in ANY state
// (D-6) -- so a retired identity, whose supports have all ended, is readable
// (§5.2 "Retired objects"), while a GitHub row or an AWS row no projection
// pass supported is not. nil when there is none: the caller answers 404 with
// no hint (§5.2).
func idetailLoadIdentity(q *Query, id uuid.UUID) (*idetailIdentityRow, error) {
	var rows []idetailIdentityRow
	if err := q.DB().Raw(`SELECT `+IdentityColumns+`, ia.continuity, ia.provider_attrs
	                        FROM `+IdentityFrom+`
	                       WHERE ia.workspace_id = ? AND ia.id = ? AND ia.provider = 'aws'
	                         AND `+SupportedSQL("ia", "identity_account_id"),
		q.WS, id).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

// IdentityHeader names the identity a tab belongs to, so the console can say
// "this identity is retired; there is no current data" instead of rendering
// an empty tab as if nothing were there (§2.14.5, §5.2).
type IdentityHeader struct {
	Ref           string `json:"ref"`
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	Lifecycle     string `json:"lifecycle"`
	RetiredReason string `json:"retired_reason,omitempty"`
	State         string `json:"state"`
}

func (i *idetailIdentityRow) header() IdentityHeader {
	return IdentityHeader{Ref: R(RefIdentity, i.ID), Name: i.DisplayName, Kind: i.AccountKind,
		Lifecycle: i.Lifecycle, RetiredReason: i.RetiredReason, State: i.State}
}

// IdentityTabMeta is the detail envelope's meta (§5.2) with the object's own
// coverage (D-73: "detail responses carry entries for the object's own
// partitions") -- the identity detail and its multi-section tabs.
type IdentityTabMeta struct {
	DetailMeta
	Coverage []CoverageNote `json:"coverage"`
}

/* --------------------------------- sources -------------------------------- */

// SupportSource is one entry of a detail's sources (§5.3 "the connectors
// whose support rows hold it, with state"): one iga_object_support row, as
// the typed claim that names it (presence:<id>, D-65), the connector, the
// account that connector reads, and the row's own state and dates.
type SupportSource struct {
	Presence        string   `json:"presence"`
	Integration     string   `json:"integration"`
	Account         *Account `json:"account"`
	State           string   `json:"state"`
	FirstSeenAt     any      `json:"first_seen_at"`
	LastConfirmedAt any      `json:"last_confirmed_at"`
	EndedReason     *string  `json:"ended_reason"`
}

// SupportSources reads every support row of one node, in any state -- a
// retired node's sources are all ended, and saying so is the answer to "who
// stopped vouching for it" (E10). column is the node class's support column.
// Ordered by the connector's account, then the row id.
func SupportSources(q *Query, accts *Accounts, column string, id uuid.UUID) ([]SupportSource, error) {
	mustSupportColumn(column)
	var rows []struct {
		ID              uuid.UUID
		ConnectorID     uuid.UUID
		State           string
		FirstSeenAt     time.Time
		LastConfirmedAt *time.Time
		EndedReason     string
	}
	if err := q.DB().Raw(`SELECT s.id, s.connector_id, s.state, s.first_seen_at, s.last_confirmed_at, s.ended_reason
	                        FROM iga_object_support s
	                       WHERE s.workspace_id = ? AND s.`+column+` = ?
	                       ORDER BY s.id`, q.WS, id).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]SupportSource, 0, len(rows))
	for _, r := range rows {
		src := SupportSource{
			Presence:        R(RefPresence, r.ID),
			Integration:     R(RefConnector, r.ConnectorID),
			State:           r.State,
			FirstSeenAt:     T(r.FirstSeenAt),
			LastConfirmedAt: TS(r.LastConfirmedAt),
		}
		if c := accts.Connector(r.ConnectorID); c != nil {
			src.Account = accts.Of(c.AccountID)
		}
		if r.State == StateEnded {
			reason := r.EndedReason
			src.EndedReason = &reason
		}
		out = append(out, src)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return idetailAccountID(out[i].Account) < idetailAccountID(out[j].Account)
	})
	return out, nil
}

func idetailAccountID(a *Account) string {
	if a == nil {
		return "￿" // Unknown account last
	}
	return a.ID
}

/* ------------------------------ meta.coverage ----------------------------- */

// idetailSurfaces is which coverage surfaces bear on one response, and what
// each gap affects there (D-73's table, narrowed to one object). exact names
// a surface; regional names the prefix of a regional surface
// ("lambda" for lambda:<region>), whose affects text gets the region appended.
type idetailSurfaces struct {
	exact    map[string]string
	regional map[string]string
	// revoked is what a revoked account's "*" note says.
	revoked string
}

// idetailCoverage is meta.coverage for one object (D-73): every surface that
// a run the current revision was built from, for the object's own
// partitions, did not reach and that bears on this response, as {account_id,
// surface, state, affects}.
//
// pairs is a subquery yielding (connector_id, partition_key) -- the object's
// support rows, or an external principal's edges -- and pairArgs its bind
// variables. The runs are those iga_projection_state names for exactly those
// partitions (D-57), read in this snapshot, so the notes describe the runs
// the object's rows came from. Per account and surface the newest such run
// decides. reached and unsupported are not gaps; not_selected is reported
// stale (D-58: nobody looked, earlier results are kept and marked stale). A
// revoked account adds {account_id, surface: "*", state: "revoked"} (D-73,
// D-89). Mandatory: dropping it would present an incomplete answer as
// complete.
func idetailCoverage(q *Query, accts *Accounts, pairs string, pairArgs []any, want idetailSurfaces) ([]CoverageNote, error) {
	var runs []struct {
		ID          uuid.UUID
		ConnectorID uuid.UUID
		Coverage    json.RawMessage
	}
	args := append([]any{q.WS}, pairArgs...)
	args = append(args, q.WS)
	if err := q.DB().Raw(`SELECT sr.id, sr.connector_id, sr.coverage
	                        FROM cloud_scan_run sr
	                       WHERE sr.workspace_id = ?
	                         AND sr.id IN (SELECT ps.last_run_id
	                                         FROM iga_projection_state ps
	                                         JOIN (`+pairs+`) x
	                                           ON x.connector_id = ps.connector_id AND x.partition_key = ps.partition_key
	                                        WHERE ps.workspace_id = ?)
	                       ORDER BY sr.published_at DESC NULLS LAST, sr.requested_at DESC, sr.id`,
		args...).Scan(&runs).Error; err != nil {
		return nil, err
	}
	type key struct{ account, surface string }
	decided := map[key]bool{}
	notes := []CoverageNote{}
	accounts := map[string]bool{}
	for _, run := range runs { // newest first
		conn := accts.Connector(run.ConnectorID)
		if conn == nil {
			continue
		}
		accounts[conn.AccountID] = true
		cov := models.DecodeScanCoverage(run.Coverage)
		for surface, s := range cov.Surfaces {
			k := key{conn.AccountID, surface}
			if decided[k] {
				continue // a newer run already reported this surface
			}
			decided[k] = true
			state := s.State
			switch state {
			case models.CloudCoverageReached, models.CloudCoverageUnsupported:
				continue
			case models.CloudCoverageNotSelected:
				state = models.CloudCoverageStale
			}
			if affects := want.affects(surface); affects != "" {
				notes = append(notes, CoverageNote{AccountID: conn.AccountID, Surface: surface, State: state, Affects: affects})
			}
		}
	}
	for account := range accounts {
		if live := accts.ConnectorForAccount(account); live != nil && live.Status == models.CloudConnectorRevoked && want.revoked != "" {
			notes = append(notes, CoverageNote{AccountID: account, Surface: "*",
				State: models.CloudConnectorRevoked, Affects: want.revoked})
		}
	}
	sort.Slice(notes, func(i, j int) bool {
		if notes[i].AccountID != notes[j].AccountID {
			return notes[i].AccountID < notes[j].AccountID
		}
		return notes[i].Surface < notes[j].Surface
	})
	return notes, nil
}

func (w idetailSurfaces) affects(surface string) string {
	if a, ok := w.exact[surface]; ok {
		return a
	}
	if prefix, region, ok := strings.Cut(surface, ":"); ok && region != "" {
		if a, ok := w.regional[prefix]; ok {
			return a + " in " + region
		}
	}
	return ""
}

// idetailSupportPairs is the (connector_id, partition_key) subquery of one
// identity's support rows, for idetailCoverage.
const idetailSupportPairs = `SELECT s.connector_id, s.partition_key FROM iga_object_support s
                              WHERE s.workspace_id = ? AND s.identity_account_id = ?`

/* ----------------------------- claim staleness ---------------------------- */

// ClaimStaleSubject is one claim row for ClaimStaleReasons: its id and the
// partition membership it was written with (connector_id, partition_key), the
// same two columns reconciliation selects it by (§4.10). DocumentProtected
// marks a claim an unreadable policy document keeps stale (a grant, through
// its statement): when no required surface of its partition explains it, the
// run's policy_documents gap does (D-74 "a document-protected row names
// policy_documents") -- the rule NodeStaleReasons applies to statements.
type ClaimStaleSubject struct {
	ID                uuid.UUID
	ConnectorID       *uuid.UUID
	PartitionKey      string
	DocumentProtected bool
}

// ClaimStaleReasons computes D-74's stale_reason for claims -- relationships,
// assignments, grants -- the way NodeStaleReasons does for nodes: the run the
// claim's partition was last projected from (iga_projection_state, D-57, in
// this snapshot), and every required surface and scanner of that partition
// the run did not reach (the same partitionGaps rules).
//
// The partition is found by EQUALITY of its key: igagraph.Partitions is
// enumerated for the partition's scope, connector and every region the run
// reported, and the one whose Key() is the stored partition_key is the
// claim's. The key is never parsed (D-57 changed its format once already).
//
// since is the start of the surface's unbroken streak in that state over the
// connector's last StaleHistoryRuns published runs, read as OPTIONAL work --
// the same walk NodeStaleReasons reads; unknown is null, never a guess.
//
// Every subject is in the result ([] when nothing recorded explains it);
// callers pass only stale claims.
func ClaimStaleReasons(q *Query, accts *Accounts, subjects []ClaimStaleSubject) (map[uuid.UUID][]StaleReason, error) {
	out := map[uuid.UUID][]StaleReason{}
	if len(subjects) == 0 {
		return out, nil
	}
	conns, keys := []uuid.UUID{}, []string{}
	for _, s := range subjects {
		out[s.ID] = []StaleReason{}
		if s.ConnectorID != nil && s.PartitionKey != "" {
			conns = append(conns, *s.ConnectorID)
			keys = append(keys, s.PartitionKey)
		}
	}
	if len(conns) == 0 {
		return out, nil
	}
	type mark struct {
		ConnectorID   uuid.UUID
		PartitionKey  string
		EstateScopeID uuid.UUID
		LastRunID     uuid.UUID
	}
	var marks []mark
	if err := q.DB().Raw(`SELECT ps.connector_id, ps.partition_key, ps.estate_scope_id, ps.last_run_id
	                        FROM iga_projection_state ps
	                       WHERE ps.workspace_id = ? AND ps.connector_id IN ? AND ps.partition_key IN ?`,
		q.WS, conns, keys).Scan(&marks).Error; err != nil {
		return nil, err
	}
	type pk struct {
		conn uuid.UUID
		key  string
	}
	byPart := map[pk]mark{}
	runIDs := []uuid.UUID{}
	for _, m := range marks {
		byPart[pk{m.ConnectorID, m.PartitionKey}] = m
		runIDs = append(runIDs, m.LastRunID)
	}
	if len(runIDs) == 0 {
		return out, nil
	}
	var runs []staleRun
	if err := q.DB().Raw(`SELECT id, connector_id, published_at, coverage FROM cloud_scan_run
	                       WHERE workspace_id = ? AND id IN ?`, q.WS, runIDs).Scan(&runs).Error; err != nil {
		return nil, err
	}
	runByID := map[uuid.UUID]*staleRun{}
	for i := range runs {
		runs[i].decode()
		runByID[runs[i].ID] = &runs[i]
	}

	type pending struct {
		claim uuid.UUID
		run   *staleRun
		gap   surfaceGap
	}
	var found []pending
	partsOf := map[pk][]igagraph.Partition{}
	for _, s := range subjects {
		if s.ConnectorID == nil {
			continue
		}
		m, ok := byPart[pk{*s.ConnectorID, s.PartitionKey}]
		if !ok {
			continue // no watermark: nothing recorded explains it
		}
		run := runByID[m.LastRunID]
		if run == nil {
			continue
		}
		k := pk{*s.ConnectorID, s.PartitionKey}
		parts, seen := partsOf[k]
		if !seen {
			snap := &igagraph.Snapshot{ScopeID: m.EstateScopeID,
				Run: models.CloudScanRun{ConnectorID: *s.ConnectorID}, Coverage: run.cov.Surfaces}
			parts = igagraph.Partitions(snap)
			partsOf[k] = parts
		}
		for _, p := range parts {
			if p.Target == "" || p.Key() != s.PartitionKey {
				continue
			}
			class := ""
			if s.DocumentProtected {
				class = models.ObjectEntitlement
			}
			for _, g := range partitionGaps(p, run.cov, class) {
				found = append(found, pending{claim: s.ID, run: run, gap: g})
			}
			break
		}
	}
	if len(found) == 0 {
		return out, nil
	}

	histConns := []uuid.UUID{}
	seenConn := map[uuid.UUID]bool{}
	for _, f := range found {
		if !seenConn[f.run.ConnectorID] {
			seenConn[f.run.ConnectorID] = true
			histConns = append(histConns, f.run.ConnectorID)
		}
	}
	history, haveHistory, err := idetailStaleHistory(q, histConns)
	if err != nil {
		return nil, err
	}
	for _, f := range found {
		var since any
		if haveHistory {
			since = TS(streakSince(history[f.run.ConnectorID], f.run.ID, f.gap.surface, f.gap.state))
		}
		acct := ""
		if c := accts.Connector(f.run.ConnectorID); c != nil {
			acct = c.AccountID
		}
		out[f.claim] = append(out[f.claim], StaleReason{AccountID: acct, Surface: f.gap.surface, State: f.gap.state, Since: since})
	}
	for id := range out {
		rs := out[id]
		sort.Slice(rs, func(i, j int) bool {
			if rs[i].AccountID != rs[j].AccountID {
				return rs[i].AccountID < rs[j].AccountID
			}
			return rs[i].Surface < rs[j].Surface
		})
		out[id] = dedupeReasons(rs)
	}
	return out, nil
}

// idetailStaleHistory reads, as OPTIONAL work, each involved connector's
// recent published runs, bounded by the newest run any partition of it was
// projected from -- the since walk NodeStaleReasons reads (D-72's window).
// ok=false when it did not finish: every since is then null.
func idetailStaleHistory(q *Query, conns []uuid.UUID) (map[uuid.UUID][]staleRun, bool, error) {
	var hist []staleRun
	ok, err := q.Optional(func(tx *gorm.DB) error {
		return tx.Raw(`SELECT id, connector_id, published_at, coverage FROM (
		                   SELECT sr.id, sr.connector_id, sr.published_at, sr.coverage,
		                          row_number() OVER (PARTITION BY sr.connector_id
		                                             ORDER BY sr.published_at DESC, sr.id DESC) AS n
		                     FROM cloud_scan_run sr
		                    WHERE sr.workspace_id = ? AND sr.connector_id IN ? AND sr.published_at IS NOT NULL
		                      AND sr.published_at <= (
		                          SELECT max(pr.published_at)
		                            FROM iga_projection_state ps
		                            JOIN cloud_scan_run pr ON pr.workspace_id = ps.workspace_id AND pr.id = ps.last_run_id
		                           WHERE ps.workspace_id = sr.workspace_id AND ps.connector_id = sr.connector_id)) x
		                WHERE n <= ?
		                ORDER BY connector_id, published_at DESC, id DESC`,
			q.WS, conns, StaleHistoryRuns+1).Scan(&hist).Error
	})
	if err != nil || !ok {
		return nil, false, err
	}
	history := map[uuid.UUID][]staleRun{}
	for i := range hist {
		hist[i].decode()
		history[hist[i].ConnectorID] = append(history[hist[i].ConnectorID], hist[i])
	}
	return history, true, nil
}

/* ------------------------------ claim fields ------------------------------ */

// ClaimFields is what every claim row on these tabs carries about the claim
// itself: its typed reference and type, its basis (§2.3), its state (stale
// rows returned and marked, with D-74's stale_reason) and its period.
// valid_to and ended_reason appear only on ended rows (include_ended=true).
type ClaimFields struct {
	Claim           string         `json:"claim"`
	Type            string         `json:"type"`
	Basis           string         `json:"basis"`
	State           string         `json:"state"`
	StaleReason     *[]StaleReason `json:"stale_reason,omitempty"`
	ValidFrom       any            `json:"valid_from"`
	ValidTo         any            `json:"valid_to,omitempty"`
	EndedReason     string         `json:"ended_reason,omitempty"`
	LastConfirmedAt any            `json:"last_confirmed_at"`
}

// RelationshipClaimRow is the claim columns every tab query selects from
// iga_relationship as r.
type RelationshipClaimRow struct {
	RelID            uuid.UUID `gorm:"column:rel_id"`
	RelationshipType string
	Basis            string
	RelState         string `gorm:"column:rel_state"`
	ValidFrom        time.Time
	ValidTo          *time.Time
	EndedReason      string
	LastConfirmedAt  time.Time
	ConnectorID      *uuid.UUID
	PartitionKey     string
}

// idetailClaimColumns selects RelationshipClaimRow from iga_relationship as r.
const idetailClaimColumns = `r.id AS rel_id, r.relationship_type, r.basis, r.state AS rel_state,
       r.valid_from, r.valid_to, r.ended_reason, r.last_confirmed_at, r.connector_id, r.partition_key`

func (c RelationshipClaimRow) staleSubject() ClaimStaleSubject {
	return ClaimStaleSubject{ID: c.RelID, ConnectorID: c.ConnectorID, PartitionKey: c.PartitionKey}
}

func (c RelationshipClaimRow) fields(reasons map[uuid.UUID][]StaleReason) ClaimFields {
	f := ClaimFields{
		Claim:           R(RefRelationship, c.RelID),
		Type:            c.RelationshipType,
		Basis:           c.Basis,
		State:           c.RelState,
		StaleReason:     StaleReasonOf(c.RelState, c.RelID, reasons),
		ValidFrom:       T(c.ValidFrom),
		LastConfirmedAt: T(c.LastConfirmedAt),
	}
	if c.RelState == StateEnded {
		f.ValidTo = TS(c.ValidTo)
		f.EndedReason = c.EndedReason
	}
	return f
}

// idetailClaimReasons computes stale_reason for the stale claims among rows.
func idetailClaimReasons(q *Query, accts *Accounts, rows []RelationshipClaimRow) (map[uuid.UUID][]StaleReason, error) {
	var stale []ClaimStaleSubject
	for _, r := range rows {
		if r.RelState == StateStale {
			stale = append(stale, r.staleSubject())
		}
	}
	return ClaimStaleReasons(q, accts, stale)
}

/* ---------------------------- section paging ------------------------------ */

// Section is one paged section of a multi-section tab (D-77): {items,
// next_cursor, total_known, total}. total is present only when known;
// above TotalCap it is absent with total_at_least, as on the lists.
type Section struct {
	Items        any     `json:"items"`
	NextCursor   *string `json:"next_cursor"`
	TotalKnown   bool    `json:"total_known"`
	Total        *int64  `json:"total,omitempty"`
	TotalAtLeast *int64  `json:"total_at_least,omitempty"`
	// Limitations names what the section cannot show by construction, in
	// §5.3's limitation vocabulary (principals of a NotPrincipal trust).
	Limitations []string `json:"limitations,omitempty"`
}

func (s *Section) setTotal(n int64, known bool) {
	var m ListMeta
	m.SetTotal(n, known)
	s.TotalKnown, s.Total, s.TotalAtLeast = m.TotalKnown, m.Total, m.TotalAtLeast
}

// idetailNameKey is the D-13 "name, then account" position a tab row sorts
// by: lower(name), a flag that puts an unknown account LAST, the account id,
// then the claim id (every sort ends with id, §5.2). Carried in the cursor
// exactly as SQL computed it.
type idetailNameKey struct {
	Name    string `json:"n"`
	NoAcct  int    `json:"u"`
	Account string `json:"a"`
}

// idetailNameOrder builds the keyset pieces for a "name, then account, then
// id" order over nameExpr, accountExpr and idExpr (bind-variable free,
// never NULL): the three key columns to select (k0, k1, k2), the position
// predicate after a cursor, and the ORDER BY.
func idetailNameOrder(nameExpr, accountExpr, idExpr string) (cols, after, order string) {
	k0 := `lower(` + nameExpr + `)`
	k1 := `(CASE WHEN ` + accountExpr + ` = '' THEN 1 ELSE 0 END)`
	k2 := accountExpr
	cols = k0 + ` AS k0, ` + k1 + ` AS k1, ` + k2 + ` AS k2`
	after = `(` + k0 + `, ` + k1 + `, ` + k2 + `, ` + idExpr + `) > (?::text, ?::int, ?::text, ?::uuid)`
	order = k0 + `, ` + k1 + `, ` + k2 + `, ` + idExpr
	return cols, after, order
}

// TabKeyCols is the k0..k2 columns a paged tab query selects.
type TabKeyCols struct {
	K0 string `gorm:"column:k0"`
	K1 int    `gorm:"column:k1"`
	K2 string `gorm:"column:k2"`
}

func (k TabKeyCols) key() idetailNameKey {
	return idetailNameKey{Name: k.K0, NoAcct: k.K1, Account: k.K2}
}

// idetailAfter is a decoded tab cursor position.
type idetailAfter struct {
	key idetailNameKey
	id  uuid.UUID
}

func (a *idetailAfter) args() []any {
	return []any{a.key.Name, a.key.NoAcct, a.key.Account, a.id}
}

// idetailOpenCursor verifies a tab cursor against this request's context and
// decodes its position. The revision is checked by Read (Pin.CursorRev), so
// a cursor from an older revision is 409 revision_stale (§5.1).
func (r *Reader) idetailOpenCursor(token string, ws uuid.UUID, route, filter string) (*idetailAfter, *int64, *Error) {
	c, cerr := r.OpenCursor(token, CursorContext{WS: ws, Route: route, Filter: filter, Sort: idetailSort})
	if cerr != nil {
		return nil, nil, cerr
	}
	var k idetailNameKey
	if err := json.Unmarshal(c.Key, &k); err != nil {
		// Signed, so a malformed key means another build issued it.
		return nil, nil, CursorInvalid("Malformed cursor.")
	}
	rev := c.Rev
	return &idetailAfter{key: k, id: c.ID}, &rev, nil
}

// idetailSort is the one order these tabs page in (D-13 "name, then
// account"), bound into their cursors.
const idetailSort = "name"

// idetailNextCursor signs the cursor after a page's last row.
func (r *Reader) idetailNextCursor(q *Query, route, filter string, k idetailNameKey, id uuid.UUID) (*string, error) {
	raw, err := json.Marshal(k)
	if err != nil {
		return nil, err
	}
	tok := r.SignCursor(Cursor{WS: q.WS, Rev: q.Rev.Rev, Route: route, Filter: filter, Sort: idetailSort, Key: raw, ID: id})
	return &tok, nil
}

/* ------------------------------ statements -------------------------------- */

// StatementIndexOf is the API's statement index (D-84): 1-based, the stored
// statement_index + 1 -- the "statement 2" a person reads in the document.
// nil when the row has none. Ordering always uses the stored value.
func StatementIndexOf(stored *int) *int {
	if stored == nil {
		return nil
	}
	n := *stored + 1
	return &n
}
