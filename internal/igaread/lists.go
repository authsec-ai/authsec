package igaread

// The three inventory lists (§5.3, T6.2): GET /workloads, /identities and
// /resources, over the §5.2 common list behaviour.
//
// Every list page is ONE keyset-paged statement (§5.6): filters in SQL, never
// in Go after the page is read, so a search or a filter covers the whole
// inventory at the revision and never just the loaded page (§2.14.6). Totals,
// facets and per-row counts are OPTIONAL work in the same snapshot (§5.1): a
// piece that times out is reported unknown (total_known: false, a null facet,
// {value: null, exact: false}) and the page is still returned.
//
// Cursors bind to the workspace, the revision, the route, the filter hash and
// the sort (§5.1), plus the classification clock when the list filters or
// sorts on classification (§5.5). Nothing else a row shows moves within a
// revision: a resource's kind and its account's connectedness are the
// PROJECTED values (D-3, D-16), so the revision check covers them.
//
// The classification clock is read here by listsClassificationSeq: the
// classification task's igaread.ClassificationSeq is not in this tree, and
// the integrator should fold the two together.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

// List routes, as bound into their cursors.
const (
	ListRouteWorkloads  = "workloads"
	ListRouteIdentities = "identities"
	ListRouteResources  = "resources"
)

// Filter values beyond §5.2's common ones.
const (
	// RegionNotStated selects objects whose ARN states no region (§2.14.10).
	RegionNotStated = "not_stated"
	// ClassificationAgent is the Agents chip: provider-native or classified
	// (§2.14.6).
	ClassificationAgent = "agent"
	// UsedByWorkloads selects identities some workload uses (§5.3).
	UsedByWorkloads = "workloads"
)

// ListingClassificationChanged is the reason 409 listing_changed carries: a
// classification decision landed between two pages of a list that filters or
// sorts on classification (§5.5).
const ListingClassificationChanged = "classification_changed"

// ListWorkloads serves GET /api/iga/v1/workloads (§5.3 Agents & workloads).
func (r *Reader) ListWorkloads(ctx context.Context, ws uuid.UUID, vals url.Values) (any, error) {
	return listsRun(ctx, r, ws, vals, &listsWorkloads)
}

// ListIdentities serves GET /api/iga/v1/identities (§5.3 Identities).
func (r *Reader) ListIdentities(ctx context.Context, ws uuid.UUID, vals url.Values) (any, error) {
	return listsRun(ctx, r, ws, vals, &listsIdentities)
}

// ListResources serves GET /api/iga/v1/resources (§5.3 Resources).
func (r *Reader) ListResources(ctx context.Context, ws uuid.UUID, vals url.Values) (any, error) {
	return listsRun(ctx, r, ws, vals, &listsResources)
}

/* --------------------------------- engine ---------------------------------- */

// listsFilter is one active filter: a SQL predicate and its bind variables.
// facet names the facet the filter drives, so that facet's counts can leave it
// out ("each facet's counts apply every OTHER active filter", §5.2); "" for q,
// lifecycle and the workspace, which every facet applies.
type listsFilter struct {
	facet string
	sql   string
	args  []any
}

// listsKey is one sort component. Every expression is bind-variable free and
// never NULL (the keyset compares with = and <, which NULL defeats). numeric
// keys travel in the cursor as decimal strings and bind as bigint. fixed keys
// stay ascending whatever the direction: they are the "has no value" flags
// that keep an unknown account, a missing service or a never-confirmed row
// LAST in both directions (D-13).
type listsKey struct {
	sql     string
	numeric bool
	fixed   bool
}

// listsScope is what the request narrowed the list to, for meta.coverage
// (D-73): only the gaps that bear on THIS result are named.
type listsScope struct {
	accounts        []string // §5.2 account values, "unknown" verbatim; empty = all
	regions         []string // chosen region names; nil with regionNotStated false = all
	regionNotStated bool
	kinds           []string // workload runtime kinds / identity kinds; empty = all
}

// listsScan is a route's scanned row: its record plus the sort key values the
// page query selected as k0, k1 ...
type listsScan interface {
	rowID() uuid.UUID
	sortKeys() []*string
}

// Every scan struct carries the page query's sort key columns as K0..K5
// fields of its own: gorm skips the fields of an embedded UNEXPORTED struct, so
// they cannot come from a shared embedded type.

// listsMaxKeys is how many sort components a scan struct can carry.
const listsMaxKeys = 6

// listsFacet is one facet: a bind-variable-free value expression over the
// route's count FROM, and how its raw counts become chips.
type listsFacet struct {
	expr     string
	finalize func(counts map[string]int64, accts *Accounts) []FacetValue
}

// listsSpec is everything that differs between the three lists.
type listsSpec[S listsScan] struct {
	route   string
	sorts   []string
	defSort string
	params  map[string]bool // the route's own parameters, beyond §5.2's

	// columns and from are the page query's select list and FROM (with the
	// support and execution laterals); countFrom is the FROM totals and facets
	// count over. Filters and facets must only name countFrom's aliases.
	columns   string
	from      string
	countFrom string
	idCol     string

	keys    map[string][]listsKey // by sort key; id is always appended
	facets  map[string]listsFacet
	filters func(p *ListParams, ws uuid.UUID) ([]listsFilter, listsScope, bool, *Error)
	render  func(q *Query, accts *Accounts, rows []S) (any, error)
}

func (s *listsSpec[S]) facetNames() []string {
	out := make([]string, 0, len(s.facets))
	for name := range s.facets {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// listsCommonParams are §5.2's list parameters, plus provider (D-75), which
// every list accepts.
var listsCommonParams = map[string]bool{
	"q": true, "sort": true, "limit": true, "cursor": true, "facets": true,
	"lifecycle": true, "account": true, "rev": true, "provider": true,
}

// listsAfter is a decoded cursor position.
type listsAfter struct {
	keys     []any // bind values for the sort keys: string or int64
	id       uuid.UUID
	classSeq *int64
}

// listsCursorKey is Cursor.Key for these routes: the last row's sort key
// values.
type listsCursorKey struct {
	K []string `json:"k"`
}

// listsRun is the whole §5.2 list contract for one route. Parameters (400)
// are checked before the snapshot is opened (D-10); the revision (409) inside
// it, by Read.
func listsRun[S listsScan](ctx context.Context, r *Reader, ws uuid.UUID, vals url.Values, spec *listsSpec[S]) (any, error) {
	p, perr := ParseListParams(vals, spec.sorts, spec.defSort, spec.facetNames())
	if perr != nil {
		return nil, perr
	}
	for name := range vals {
		if !listsCommonParams[name] && !spec.params[name] {
			return nil, InvalidParameter(name, fmt.Sprintf("%s is not a parameter of this list", name))
		}
	}
	if perr := listsProvider(p); perr != nil {
		return nil, perr
	}
	filters, scope, classBound, perr := spec.filters(p, ws)
	if perr != nil {
		return nil, perr
	}
	// §5.5: a list whose filter OR sort involves classification binds its
	// cursor to the clock. Facets on classification do not (D-83).
	if p.SortKey == "classification" {
		classBound = true
	}
	keys := spec.keys[p.SortKey]
	filterHash := FilterHash(vals)

	pin := Pin{Rev: p.Rev}
	var after *listsAfter
	if p.Cursor != "" {
		c, cerr := r.OpenCursor(p.Cursor, CursorContext{WS: ws, Route: spec.route, Filter: filterHash, Sort: p.SortString()})
		if cerr != nil {
			return nil, cerr
		}
		if after, perr = listsDecodeCursor(c, keys); perr != nil {
			return nil, perr
		}
		pin.CursorRev = &c.Rev
	}

	var out Envelope
	err := r.Read(ctx, ws, pin, func(q *Query) error {
		meta := NewListMeta(q, p.Limit)
		if !q.Published() {
			// A distinct first-run state, never "no results" (§5.1).
			out = Envelope{Data: []any{}, Meta: meta}
			return nil
		}
		accts, err := q.LoadAccounts()
		if err != nil {
			return err
		}

		// The one binding §5.1's revision check does not cover, checked in
		// THIS snapshot: the clock the next page's rows are read at.
		var classSeq *int64
		if classBound {
			seq, err := listsClassificationSeq(q)
			if err != nil {
				return err
			}
			classSeq = &seq
			if after != nil && (after.classSeq == nil || *after.classSeq != seq) {
				return ListingChanged(ListingClassificationChanged)
			}
		}

		// THE PAGE: one mandatory statement.
		sqlText, args := listsPageSQL(spec, filters, keys, p.Desc, after, p.Limit)
		var rows []S
		if err := q.DB().Raw(sqlText, args...).Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) > p.Limit {
			rows = rows[:p.Limit]
			last := rows[len(rows)-1]
			var key listsCursorKey
			for _, k := range last.sortKeys()[:len(keys)] {
				if k == nil {
					return fmt.Errorf("igaread: %s page returned a NULL sort key", spec.route)
				}
				key.K = append(key.K, *k)
			}
			raw, err := json.Marshal(key)
			if err != nil {
				return err
			}
			tok := r.SignCursor(Cursor{WS: ws, Rev: q.Rev.Rev, Route: spec.route, Filter: filterHash,
				Sort: p.SortString(), Key: raw, ID: last.rowID(), ClassSeq: classSeq})
			meta.NextCursor = &tok
		}

		// Coverage is MANDATORY: dropping it would present an incomplete list
		// as complete, which is the one thing a partial banner exists to stop.
		if meta.Coverage, err = listsCoverage(q, accts, spec.route, scope); err != nil {
			return err
		}

		data, err := spec.render(q, accts, rows)
		if err != nil {
			return err
		}

		// Totals and facets: optional, over every filter (facets: every OTHER).
		n, known, err := q.CountUpTo(func(tx *gorm.DB) *gorm.DB {
			w, wargs := listsWhere(filters, "")
			return tx.Table(spec.countFrom).Where(w, wargs...)
		})
		if err != nil {
			return err
		}
		meta.SetTotal(n, known)
		if len(p.Facets) > 0 {
			meta.Facets = map[string][]FacetValue{}
			for _, name := range p.Facets {
				vals, err := listsFacetCounts(q, spec, filters, name, accts)
				if err != nil {
					return err
				}
				meta.Facets[name] = vals // nil (JSON null) when it timed out
			}
		}
		out = Envelope{Data: data, Meta: meta}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// listsWhere joins the filters, leaving out those of one facet ("" keeps all).
func listsWhere(filters []listsFilter, except string) (string, []any) {
	parts := make([]string, 0, len(filters))
	var args []any
	for _, f := range filters {
		if except != "" && f.facet == except {
			continue
		}
		parts = append(parts, "("+f.sql+")")
		args = append(args, f.args...)
	}
	return strings.Join(parts, " AND "), args
}

// listsPageSQL builds the one page statement: the filters, the keyset
// position after the cursor's row, the sort with id last (§5.2), and
// limit+1 rows so the presence of a next page is known without a count.
//
// A descending sort reverses every component but the fixed "no value" flags,
// id included, so paging never repeats or skips a row. When no component is
// fixed the keyset is a single row comparison, which an index on the same
// tuple serves as an index condition (the workload name sort on
// idx_iga_workload_list, §5.3); otherwise it is the equivalent lexicographic
// OR chain, one arm per component.
func listsPageSQL[S listsScan](spec *listsSpec[S], filters []listsFilter, keys []listsKey, desc bool, after *listsAfter, limit int) (string, []any) {
	var b strings.Builder
	b.WriteString("SELECT ")
	b.WriteString(spec.columns)
	for i, k := range keys {
		fmt.Fprintf(&b, ",\n       (%s)::text AS k%d", k.sql, i)
	}
	b.WriteString("\n  FROM ")
	b.WriteString(spec.from)
	w, args := listsWhere(filters, "")
	b.WriteString("\n WHERE ")
	b.WriteString(w)

	type comp struct {
		sql, mark string
		down      bool
		arg       any
	}
	comps := make([]comp, 0, len(keys)+1)
	mixed := false
	for i, k := range keys {
		c := comp{sql: k.sql, mark: "?::text", down: desc && !k.fixed}
		if k.numeric {
			c.mark = "?::bigint"
		}
		if after != nil {
			c.arg = after.keys[i]
		}
		if k.fixed && desc {
			mixed = true
		}
		comps = append(comps, c)
	}
	idc := comp{sql: spec.idCol, mark: "?::uuid", down: desc}
	if after != nil {
		idc.arg = after.id
	}
	comps = append(comps, idc)

	if after != nil {
		op := func(c comp) string {
			if c.down {
				return "<"
			}
			return ">"
		}
		if !mixed {
			cols, marks := make([]string, 0, len(comps)), make([]string, 0, len(comps))
			for _, c := range comps {
				cols, marks = append(cols, c.sql), append(marks, c.mark)
				args = append(args, c.arg)
			}
			fmt.Fprintf(&b, "\n   AND (%s) %s (%s)", strings.Join(cols, ", "), op(comps[0]), strings.Join(marks, ", "))
		} else {
			arms := make([]string, 0, len(comps))
			for i := range comps {
				var terms []string
				for j := 0; j < i; j++ {
					terms = append(terms, fmt.Sprintf("(%s) = %s", comps[j].sql, comps[j].mark))
					args = append(args, comps[j].arg)
				}
				terms = append(terms, fmt.Sprintf("(%s) %s %s", comps[i].sql, op(comps[i]), comps[i].mark))
				args = append(args, comps[i].arg)
				arms = append(arms, "("+strings.Join(terms, " AND ")+")")
			}
			fmt.Fprintf(&b, "\n   AND (%s)", strings.Join(arms, "\n        OR "))
		}
	}
	b.WriteString("\n ORDER BY ")
	for i, c := range comps {
		if i > 0 {
			b.WriteString(", ")
		}
		if c.down {
			b.WriteString(c.sql + " DESC")
		} else {
			b.WriteString(c.sql + " ASC")
		}
	}
	b.WriteString("\n LIMIT ?")
	args = append(args, limit+1)
	return b.String(), args
}

// listsDecodeCursor turns an opened cursor into bind values for the keyset.
// The cursor is HMAC-signed, so a malformed key means another build issued it:
// 400 cursor_invalid, like any cursor from another context.
func listsDecodeCursor(c *Cursor, keys []listsKey) (*listsAfter, *Error) {
	var k listsCursorKey
	if err := json.Unmarshal(c.Key, &k); err != nil || len(k.K) != len(keys) {
		return nil, CursorInvalid("Malformed cursor.")
	}
	a := &listsAfter{id: c.ID, classSeq: c.ClassSeq}
	for i, key := range keys {
		if key.numeric {
			n, err := strconv.ParseInt(k.K[i], 10, 64)
			if err != nil {
				return nil, CursorInvalid("Malformed cursor.")
			}
			a.keys = append(a.keys, n)
		} else {
			a.keys = append(a.keys, k.K[i])
		}
	}
	return a, nil
}

// listsFacetCounts counts one facet as OPTIONAL work, applying every OTHER
// active filter (§5.2): nil (JSON null) when it timed out (D-14).
func listsFacetCounts[S listsScan](q *Query, spec *listsSpec[S], filters []listsFilter, name string, accts *Accounts) ([]FacetValue, error) {
	f := spec.facets[name]
	w, args := listsWhere(filters, name)
	counts := map[string]int64{}
	ok, err := q.Optional(func(tx *gorm.DB) error {
		var rows []struct {
			V string
			N int64
		}
		if err := tx.Raw(`SELECT (`+f.expr+`)::text AS v, count(*) AS n FROM `+spec.countFrom+
			` WHERE `+w+` GROUP BY 1`, args...).Scan(&rows).Error; err != nil {
			return err
		}
		for _, r := range rows {
			counts[r.V] += r.N
		}
		return nil
	})
	if err != nil || !ok {
		return nil, err
	}
	return f.finalize(counts, accts), nil
}

// listsClassificationSeq is the workspace's classification clock (029), 0
// before the first decision, read inside the snapshot the page is read in.
func listsClassificationSeq(q *Query) (int64, error) {
	var seqs []int64
	if err := q.DB().Raw(`SELECT seq FROM iga_classification_clock WHERE workspace_id = ?`, q.WS).
		Scan(&seqs).Error; err != nil {
		return 0, err
	}
	if len(seqs) == 0 {
		return 0, nil
	}
	return seqs[0], nil
}

/* ------------------------------- sort pieces ------------------------------- */

func listsText(sql string) listsKey { return listsKey{sql: sql} }
func listsRank(sql string) listsKey { return listsKey{sql: sql, numeric: true} }

// listsNoValueLast is the fixed flag that keeps rows with no value for expr
// (”) after every row with one, in both directions (D-13).
func listsNoValueLast(expr string) listsKey {
	return listsKey{sql: "(CASE WHEN " + expr + " = '' THEN 1 ELSE 0 END)", numeric: true, fixed: true}
}

// listsAccountKeys sort on an account expression, unknown last in both
// directions (D-13).
func listsAccountKeys(expr string) []listsKey {
	return []listsKey{listsNoValueLast(expr), listsText(expr)}
}

// listsLastConfirmedKeys sort on D-1's derived last_confirmed_at, as integer
// microseconds so the cursor round-trips it exactly, never-confirmed last in
// both directions (D-13).
func listsLastConfirmedKeys() []listsKey {
	return []listsKey{
		{sql: "(CASE WHEN sup.last_confirmed_at IS NULL THEN 1 ELSE 0 END)", numeric: true, fixed: true},
		listsRank("COALESCE((extract(epoch FROM sup.last_confirmed_at) * 1000000)::bigint, 0)"),
	}
}

// listsJoin concatenates sort components.
func listsJoin(parts ...[]listsKey) []listsKey {
	var out []listsKey
	for _, p := range parts {
		out = append(out, p...)
	}
	if len(out) > listsMaxKeys {
		panic("igaread: a list sort has more components than listsKeys carries")
	}
	return out
}

func listsOne(k listsKey) []listsKey { return []listsKey{k} }

/* --------------------------- shared filter pieces -------------------------- */

// listsExact is one exact-match arm of q: an expression and the value q must
// equal there.
type listsExact struct {
	expr  string
	value string
}

// listsQ is §5.2's q (D-76): a case-insensitive substring of the display name
// with LIKE metacharacters escaped, OR an exact, case-sensitive match on any
// of exact (full ARN or pattern, provider id) -- and, when q is a 12-digit
// account id, on the object's own account (accountExpr; ” for an unknown
// account, which a 12-digit q can never equal). Always bind variables, never
// spliced.
func listsQ(p *ListParams, nameCol, accountExpr string, exact ...listsExact) []listsFilter {
	if p.Q == "" {
		return nil
	}
	parts := []string{"lower(" + nameCol + `) LIKE lower(?) ESCAPE '\'`}
	args := []any{"%" + EscapeLike(p.Q) + "%"}
	if isAccountID(p.Q) {
		exact = append(exact, listsExact{accountExpr, p.Q})
	}
	for _, e := range exact {
		parts = append(parts, e.expr+" = ?")
		args = append(args, e.value)
	}
	return []listsFilter{{sql: strings.Join(parts, " OR "), args: args}}
}

// listsQARN matches q as a full ARN against a node's source key, spelled the
// way igagraph keys it, so the unique source-key index can serve it.
func listsQARN(p *ListParams, sourceKeyCol string) listsExact {
	return listsExact{expr: sourceKeyCol, value: igagraph.Key("aws", p.Q)}
}

func listsLifecycle(p *ListParams, col string) []listsFilter {
	if p.Lifecycle == LifecycleAll {
		return nil
	}
	return []listsFilter{{sql: col + " = ?", args: []any{p.Lifecycle}}}
}

// listsAccount is §5.2's account filter over an account expression that is ”
// when the object states no account. Absent = every account INCLUDING unknown;
// choosing accounts excludes unknowns unless "unknown" is chosen too
// (§2.14.10).
func listsAccount(p *ListParams, expr string) []listsFilter {
	if len(p.Accounts) == 0 {
		return nil
	}
	var ids []string
	unknown := false
	for _, a := range p.Accounts {
		if a == AccountUnknown {
			unknown = true
		} else {
			ids = append(ids, a)
		}
	}
	var parts []string
	var args []any
	if len(ids) > 0 {
		parts = append(parts, expr+" IN ?")
		args = append(args, ids)
	}
	if unknown {
		parts = append(parts, expr+" = ''")
	}
	return []listsFilter{{facet: "account", sql: strings.Join(parts, " OR "), args: args}}
}

// listsProvider is D-75's provider filter: every graph row is AWS this phase,
// so aws selects everything and any other value is 400 -- never an empty list
// that reads as "this provider has nothing".
func listsProvider(p *ListParams) *Error {
	for _, v := range p.Raw["provider"] {
		if v = strings.TrimSpace(v); v != "" && v != models.ProviderAWS {
			return InvalidParameter("provider", "provider must be aws")
		}
	}
	return nil
}

// listsEnum reads a repeatable filter whose values must come from allowed.
// Repeated values are alternatives (OR), as for account.
func listsEnum(p *ListParams, param string, allowed ...string) ([]string, *Error) {
	var out []string
	for _, v := range p.Raw[param] {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if !contains(allowed, v) {
			return nil, InvalidParameter(param, fmt.Sprintf("%s must be one of %s", param, strings.Join(allowed, ", ")))
		}
		if !contains(out, v) {
			out = append(out, v)
		}
	}
	return out, nil
}

var listsRegionRE = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)

// listsRegions validates the region parameter: region names, and not_stated
// for objects whose ARN states none.
func listsRegions(p *ListParams) (names []string, notStated bool, perr *Error) {
	for _, v := range p.Raw["region"] {
		v = strings.TrimSpace(v)
		switch {
		case v == "":
		case v == RegionNotStated:
			notStated = true
		case listsRegionRE.MatchString(v):
			if !contains(names, v) {
				names = append(names, v)
			}
		default:
			return nil, false, InvalidParameter("region", "region must be an AWS region name or not_stated")
		}
	}
	return names, notStated, nil
}

// listsRegion is a region filter over a column that is ” when not stated.
func listsRegion(names []string, notStated bool, col string) []listsFilter {
	var parts []string
	var args []any
	if len(names) > 0 {
		parts = append(parts, col+" IN ?")
		args = append(args, names)
	}
	if notStated {
		parts = append(parts, col+" = ''")
	}
	if len(parts) == 0 {
		return nil
	}
	return []listsFilter{{facet: "region", sql: strings.Join(parts, " OR "), args: args}}
}

// listsIntegration is the integration filter (§2.14.10 "objects supported by
// this connector", D-75): a non-ended support row from one of the chosen
// connectors, named cloud_connector:<uuid> or by its bare UUID. Another
// workspace's connector matches no support row of this workspace, so it is an
// empty list, never a leak; a malformed value is 400.
func listsIntegration(p *ListParams, nodeAlias, column string) ([]listsFilter, *Error) {
	mustSupportColumn(column)
	var conns []uuid.UUID
	for _, v := range p.Raw["integration"] {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if id, err := uuid.Parse(v); err == nil {
			conns = append(conns, id)
			continue
		}
		ref, perr := ParseRefParam("integration", v, RefConnector)
		if perr != nil {
			return nil, InvalidParameter("integration", "integration must be cloud_connector:<id> or a connector id")
		}
		conns = append(conns, ref.ID)
	}
	if len(conns) == 0 {
		return nil, nil
	}
	return []listsFilter{{sql: `EXISTS (SELECT 1 FROM iga_object_support os
	      WHERE os.workspace_id = ` + nodeAlias + `.workspace_id AND os.` + column + ` = ` + nodeAlias + `.id
	        AND os.connector_id IN ? AND os.state <> 'ended')`, args: []any{conns}}}, nil
}

// listsIn is a plain IN filter over validated values.
func listsIn(facet, col string, values []string) []listsFilter {
	if len(values) == 0 {
		return nil
	}
	return []listsFilter{{facet: facet, sql: col + " IN ?", args: []any{values}}}
}

// listsReadable is D-6's base predicate of every list: this workspace, AWS,
// and supported by at least one projection pass.
func listsReadable(alias, column string, ws uuid.UUID) listsFilter {
	return listsFilter{sql: alias + ".workspace_id = ? AND " + alias + ".provider = 'aws' AND " + SupportedSQL(alias, column),
		args: []any{ws}}
}

/* ---------------------------------- facets --------------------------------- */

// listsFacetOrder sorts chips by count, then value, with the "no value" chip
// (unknown account, region not stated) last.
func listsFacetOrder(vals []FacetValue, last string) []FacetValue {
	sort.SliceStable(vals, func(i, j int) bool {
		if (vals[i].Value == last) != (vals[j].Value == last) {
			return vals[j].Value == last
		}
		if vals[i].Count != vals[j].Count {
			return vals[i].Count > vals[j].Count
		}
		return vals[i].Value < vals[j].Value
	})
	return vals
}

// listsLabelled finalizes an enum facet: its present values, labelled.
func listsLabelled(labels map[string]string) func(map[string]int64, *Accounts) []FacetValue {
	return func(counts map[string]int64, _ *Accounts) []FacetValue {
		out := []FacetValue{}
		for v, n := range counts {
			if v == "" {
				continue
			}
			label := labels[v]
			if label == "" {
				label = v
			}
			out = append(out, FacetValue{Value: v, Label: label, Count: n})
		}
		return listsFacetOrder(out, "")
	}
}

// listsAccountFacet finalizes the account facet (D-14, §2.14.10): one chip per
// account holding rows, one per live connected account even at 0, and ALWAYS
// "unknown" -- Unknown account is an option in the filter with its own count,
// even when it is 0.
func listsAccountFacet(counts map[string]int64, accts *Accounts) []FacetValue {
	all := map[string]int64{"": 0} // "" is Unknown account
	for id, n := range counts {
		all[id] += n
	}
	for _, c := range accts.All() {
		if _, ok := all[c.AccountID]; !ok && accts.Connected(c.AccountID) {
			all[c.AccountID] = 0
		}
	}
	out := make([]FacetValue, 0, len(all))
	for id, n := range all {
		if id == "" {
			out = append(out, FacetValue{Value: AccountUnknown, Label: "Unknown account", Count: n})
			continue
		}
		out = append(out, FacetValue{Value: id, Label: accts.Of(id).Label, Count: n})
	}
	return listsFacetOrder(out, AccountUnknown)
}

// listsRegionFacet: each stated region, and ALWAYS not_stated (D-14), even at
// 0 -- "Region not stated" follows the unknown-account rules (§2.14.10).
func listsRegionFacet(counts map[string]int64, _ *Accounts) []FacetValue {
	out := []FacetValue{{Value: RegionNotStated, Label: "Region not stated", Count: counts[""]}}
	for v, n := range counts {
		if v != "" {
			out = append(out, FacetValue{Value: v, Label: v, Count: n})
		}
	}
	return listsFacetOrder(out, RegionNotStated)
}

/* ------------------------------ meta.coverage ------------------------------ */

// listsCoverage is meta.coverage (§5.2, §2.14.14, D-73): every surface a run
// the current revision was built from intended to read and did not, that bears
// on THIS result, as {account_id, surface, state, affects}.
//
// The runs are the ones iga_projection_state names (D-57): each partition's
// last projected run, written in the publication's transaction, so this
// snapshot sees exactly the runs its graph came from. Per account and surface,
// the newest such run that reports the surface decides its state. Every state
// but reached is a gap, except unsupported (ours to build, not the customer's
// estate); not_selected is reported as stale -- nobody looked, earlier results
// are kept and marked stale (D-58, §2.14.13).
//
// Which surfaces bear on which list is listsAffects (D-73's table), narrowed
// by the request's account, region and kind filters. An account filter keeps
// the chosen accounts' notes; with "unknown" chosen (or no filter) every
// account's notes stay, since an object with no stated account may come from
// any of them. A revoked account in scope adds {account_id, surface: "*",
// state: "revoked"}: nothing of it is refreshed any more (D-73, D-89).
func listsCoverage(q *Query, accts *Accounts, list string, sc listsScope) ([]CoverageNote, error) {
	var runs []struct {
		ID          uuid.UUID
		ConnectorID uuid.UUID
		Coverage    json.RawMessage
	}
	if err := q.DB().Raw(`SELECT sr.id, sr.connector_id, sr.coverage
	                        FROM cloud_scan_run sr
	                       WHERE sr.workspace_id = ?
	                         AND sr.id IN (SELECT ps.last_run_id FROM iga_projection_state ps WHERE ps.workspace_id = ?)
	                       ORDER BY sr.published_at DESC NULLS LAST, sr.requested_at DESC, sr.id`,
		q.WS, q.WS).Scan(&runs).Error; err != nil {
		return nil, err
	}
	all := len(sc.accounts) == 0 || contains(sc.accounts, AccountUnknown)
	inScope := func(account string) bool { return all || contains(sc.accounts, account) }

	type key struct{ account, surface string }
	decided := map[key]bool{}
	notes := []CoverageNote{}
	for _, run := range runs { // newest first
		conn := accts.Connector(run.ConnectorID)
		if conn == nil || !inScope(conn.AccountID) {
			continue
		}
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
			if affects := listsAffects(list, surface, sc); affects != "" {
				notes = append(notes, CoverageNote{AccountID: conn.AccountID, Surface: surface, State: state, Affects: affects})
			}
		}
	}
	seen := map[string]bool{}
	for _, c := range accts.All() {
		if seen[c.AccountID] || !inScope(c.AccountID) {
			continue
		}
		seen[c.AccountID] = true
		// ConnectorForAccount prefers a live connector when the account was
		// connected twice, so only a wholly revoked account is noted.
		if live := accts.ConnectorForAccount(c.AccountID); live != nil && live.Status == models.CloudConnectorRevoked {
			notes = append(notes, CoverageNote{AccountID: c.AccountID, Surface: "*",
				State: models.CloudConnectorRevoked, Affects: listsRevokedAffects[list]})
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

// listsRevokedAffects is what a revoked account's "*" note says, per list.
var listsRevokedAffects = map[string]string{
	ListRouteWorkloads:  "all workloads of this account",
	ListRouteIdentities: "all identities of this account",
	ListRouteResources:  "resources named by this account's policies",
}

// listsWorkloadSurfaces maps a regional workload surface's prefix to the
// runtime kind it collects (the inverse of igagraph's workloadSurfacePrefix).
var listsWorkloadSurfaces = map[string]string{
	"lambda":             models.WorkloadLambdaFunction,
	"ecs":                models.WorkloadECSTaskDefinition,
	"ec2":                models.WorkloadEC2Instance,
	"bedrock-agents":     models.WorkloadBedrockAgent,
	"bedrock-agentcore":  models.WorkloadBedrockAgentCoreRT,
	"agentcore-gateways": models.WorkloadBedrockAgentCoreGW,
}

// listsRegionInScope says whether a regional surface bears on the region
// filter: every region without one; only the chosen regions with one.
func listsRegionInScope(sc listsScope, region string) bool {
	if sc.regions == nil && !sc.regionNotStated {
		return true
	}
	return contains(sc.regions, region)
}

func listsKindInScope(sc listsScope, kind string) bool {
	return len(sc.kinds) == 0 || contains(sc.kinds, kind)
}

// listsAffects is D-73's table: the affects text of one gap for one list, ""
// when the surface does not bear on it (or the request's filters rule it out).
//
//	workloads   <svc>:<region>, compute:<region>, workload_scan
//	identities  iam_roles, iam_users, iam_groups (by kind), permission_scan
//	resources   iam_policies, policy_documents, permission_scan
func listsAffects(list, surface string, sc listsScope) string {
	switch list {
	case ListRouteWorkloads:
		if surface == models.SurfaceWorkloadScan {
			return "all workloads"
		}
		prefix, region, ok := strings.Cut(surface, ":")
		if !ok || region == "" || !listsRegionInScope(sc, region) {
			return ""
		}
		if prefix+":" == models.SurfaceComputePrefix {
			return "workloads in " + region
		}
		if kind, ok := listsWorkloadSurfaces[prefix]; ok && listsKindInScope(sc, kind) {
			return "workloads of kind " + kind + " in " + region
		}
	case ListRouteIdentities:
		for surf, kind := range map[string]string{
			models.SurfaceIAMRoles:  models.CloudIdentityIAMRole,
			models.SurfaceIAMUsers:  models.CloudIdentityIAMUser,
			models.SurfaceIAMGroups: models.CloudIdentityIAMGroup,
		} {
			if surface == surf && listsKindInScope(sc, kind) {
				return "identities of kind " + kind
			}
		}
		if surface == models.SurfacePermissionScan {
			return "permissions and trust of identities"
		}
	case ListRouteResources:
		switch surface {
		case models.SurfaceIAMPolicies:
			return "resources named by managed policies"
		case models.SurfacePolicyDocuments:
			return "resources named by unreadable policy documents"
		case models.SurfacePermissionScan:
			return "all resources"
		}
	}
	return ""
}

/* ------------------------------ stale reasons ------------------------------ */

// listsStaleReasons computes D-74's stale_reason for the page's stale rows
// only; current and ended rows carry none.
func listsStaleReasons(q *Query, accts *Accounts, column string, subjects []StaleSubject, states []string) (map[uuid.UUID][]StaleReason, error) {
	var stale []StaleSubject
	for i, s := range subjects {
		if states[i] == StateStale {
			stale = append(stale, s)
		}
	}
	return NodeStaleReasons(q, accts, column, stale)
}

/* -------------------------------- workloads -------------------------------- */

type listsWorkloadScan struct {
	WorkloadRecord
	K0 *string `gorm:"column:k0"`
	K1 *string `gorm:"column:k1"`
	K2 *string `gorm:"column:k2"`
	K3 *string `gorm:"column:k3"`
	K4 *string `gorm:"column:k4"`
	K5 *string `gorm:"column:k5"`
}

func (s listsWorkloadScan) rowID() uuid.UUID    { return s.ID }
func (s listsWorkloadScan) sortKeys() []*string { return []*string{s.K0, s.K1, s.K2, s.K3, s.K4, s.K5} }

// listsWorkloadProviderID is the provider's own id for a workload (D-76): the
// ARN's resource id (after resource-type/ or resource-type:) -- an EC2
// instance id, a Bedrock agent id, a function name. No stored column holds it.
const listsWorkloadProviderID = `regexp_replace(substring(split_part(w.source_key, chr(31), 2)
             from '^arn:[^:]*:[^:]*:[^:]*:[^:]*:(.*)$'), '^[^/:]*[/:]', '')`

var listsWorkloadRuntimeKinds = []string{
	models.WorkloadLambdaFunction, models.WorkloadECSTaskDefinition, models.WorkloadEC2Instance,
	models.WorkloadBedrockAgent, models.WorkloadBedrockAgentCoreRT, models.WorkloadBedrockAgentCoreGW,
}

// Workload sorts (D-13): the name sort keeps §5.3's (lower(display_name), id)
// keyset on idx_iga_workload_list; every other sort is its key, then name,
// then id.
var listsWorkloadName = listsOne(listsText("lower(w.display_name)"))

var listsWorkloads = listsSpec[listsWorkloadScan]{
	route:   ListRouteWorkloads,
	sorts:   []string{"name", "account", "last_confirmed", "classification"},
	defSort: "name",
	params: map[string]bool{"region": true, "integration": true, "runtime_kind": true,
		"classification": true, "execution_role_state": true},
	columns: WorkloadColumns,
	from:    WorkloadFrom,
	countFrom: `iga_workload w
  LEFT JOIN iga_estate_scopes es ON es.workspace_id = w.workspace_id AND es.id = w.estate_scope_id`,
	idCol: "w.id",
	keys: map[string][]listsKey{
		"name":           listsWorkloadName,
		"account":        listsJoin(listsAccountKeys(WorkloadAccountSQL), listsWorkloadName),
		"last_confirmed": listsJoin(listsLastConfirmedKeys(), listsWorkloadName),
		"classification": listsJoin(listsOne(listsRank(WorkloadClassificationRankSQL)), listsWorkloadName),
	},
	facets: map[string]listsFacet{
		"account": {expr: WorkloadAccountSQL, finalize: listsAccountFacet},
		"runtime_kind": {expr: "w.runtime_kind", finalize: listsLabelled(map[string]string{
			models.WorkloadLambdaFunction:     "Lambda function",
			models.WorkloadECSTaskDefinition:  "ECS task definition",
			models.WorkloadEC2Instance:        "EC2 instance",
			models.WorkloadBedrockAgent:       "Bedrock agent",
			models.WorkloadBedrockAgentCoreRT: "AgentCore runtime",
			models.WorkloadBedrockAgentCoreGW: "AgentCore gateway",
		})},
		"classification": {expr: "w.classification", finalize: listsClassificationFacet},
		"region":         {expr: "w.region", finalize: listsRegionFacet},
	},
	filters: listsWorkloadFilters,
	render: func(q *Query, accts *Accounts, rows []listsWorkloadScan) (any, error) {
		subjects, states := make([]StaleSubject, len(rows)), make([]string, len(rows))
		for i, r := range rows {
			subjects[i], states[i] = r.StaleSubject(), r.State
		}
		reasons, err := listsStaleReasons(q, accts, "workload_id", subjects, states)
		if err != nil {
			return nil, err
		}
		out := make([]WorkloadRow, 0, len(rows))
		for _, r := range rows {
			out = append(out, r.Row(accts, StaleReasonOf(r.State, r.ID, reasons)))
		}
		return out, nil
	},
}

func listsWorkloadFilters(p *ListParams, ws uuid.UUID) ([]listsFilter, listsScope, bool, *Error) {
	sc := listsScope{accounts: p.Accounts}
	classBound := false
	fs := []listsFilter{listsReadable("w", "workload_id", ws)}
	fs = append(fs, listsLifecycle(p, "w.lifecycle")...)
	fs = append(fs, listsQ(p, "w.display_name", WorkloadAccountSQL,
		listsQARN(p, "w.source_key"), listsExact{listsWorkloadProviderID, p.Q})...)
	fs = append(fs, listsAccount(p, WorkloadAccountSQL)...)

	names, notStated, perr := listsRegions(p)
	if perr != nil {
		return nil, sc, false, perr
	}
	sc.regions, sc.regionNotStated = names, notStated
	fs = append(fs, listsRegion(names, notStated, "w.region")...)

	integ, perr := listsIntegration(p, "w", "workload_id")
	if perr != nil {
		return nil, sc, false, perr
	}
	fs = append(fs, integ...)

	kinds, perr := listsEnum(p, "runtime_kind", listsWorkloadRuntimeKinds...)
	if perr != nil {
		return nil, sc, false, perr
	}
	sc.kinds = kinds
	fs = append(fs, listsIn("runtime_kind", "w.runtime_kind", kinds)...)

	cls, perr := listsEnum(p, "classification", ClassificationAgent,
		models.ClassificationProviderAgent, models.ClassificationClassified, models.ClassificationUnclassified)
	if perr != nil {
		return nil, sc, false, perr
	}
	if len(cls) > 0 {
		classBound = true
		var values []string
		for _, c := range cls {
			if c == ClassificationAgent {
				values = append(values, models.ClassificationProviderAgent, models.ClassificationClassified)
			} else {
				values = append(values, c)
			}
		}
		fs = append(fs, listsIn("classification", "w.classification", values)...)
	}

	states, perr := listsEnum(p, "execution_role_state", models.ExecRoleResolved,
		models.ExecRoleNotInScan, models.ExecRoleNotInInventory, models.ExecRoleNone)
	if perr != nil {
		return nil, sc, false, perr
	}
	fs = append(fs, listsIn("", "w.execution_role_state", states)...)
	return fs, sc, classBound, nil
}

// listsClassificationFacet adds the Agents chip (provider-native or
// classified, §2.14.6) beside each classification.
func listsClassificationFacet(counts map[string]int64, accts *Accounts) []FacetValue {
	out := listsLabelled(map[string]string{
		models.ClassificationProviderAgent: "Provider-native agent",
		models.ClassificationClassified:    "Classified agent",
		models.ClassificationUnclassified:  "Unclassified",
	})(counts, accts)
	agents := counts[models.ClassificationProviderAgent] + counts[models.ClassificationClassified]
	return append([]FacetValue{{Value: ClassificationAgent, Label: "Agents (provider-native or classified)", Count: agents}}, out...)
}

/* -------------------------------- identities ------------------------------- */

type listsIdentityScan struct {
	IdentityRecord
	K0 *string `gorm:"column:k0"`
	K1 *string `gorm:"column:k1"`
	K2 *string `gorm:"column:k2"`
	K3 *string `gorm:"column:k3"`
	K4 *string `gorm:"column:k4"`
	K5 *string `gorm:"column:k5"`
}

func (s listsIdentityScan) rowID() uuid.UUID    { return s.ID }
func (s listsIdentityScan) sortKeys() []*string { return []*string{s.K0, s.K1, s.K2, s.K3, s.K4, s.K5} }

var listsIdentityKinds = []string{models.CloudIdentityIAMRole, models.CloudIdentityIAMUser, models.CloudIdentityIAMGroup}

// Identity sorts (D-13): name, then account (unknown last), then id.
var (
	listsIdentityName    = listsOne(listsText("lower(ia.display_name)"))
	listsIdentityAccount = listsAccountKeys(IdentityAccountSQL)
)

var listsIdentities = listsSpec[listsIdentityScan]{
	route:   ListRouteIdentities,
	sorts:   []string{"name", "kind", "account", "last_confirmed"},
	defSort: "name",
	// region is accepted and never filters: IAM is global (D-75).
	params:    map[string]bool{"kind": true, "used_by": true, "integration": true, "region": true},
	columns:   IdentityColumns,
	from:      IdentityFrom,
	countFrom: `iga_identity_accounts ia`,
	idCol:     "ia.id",
	keys: map[string][]listsKey{
		"name":           listsJoin(listsIdentityName, listsIdentityAccount),
		"kind":           listsJoin(listsOne(listsRank(IdentityKindRankSQL)), listsIdentityName, listsIdentityAccount),
		"account":        listsJoin(listsIdentityAccount, listsIdentityName),
		"last_confirmed": listsJoin(listsLastConfirmedKeys(), listsIdentityName, listsIdentityAccount),
	},
	facets: map[string]listsFacet{
		"account": {expr: IdentityAccountSQL, finalize: listsAccountFacet},
		"kind": {expr: "ia.account_kind", finalize: listsLabelled(map[string]string{
			models.CloudIdentityIAMRole:  "IAM role",
			models.CloudIdentityIAMUser:  "IAM user",
			models.CloudIdentityIAMGroup: "IAM group",
		})},
	},
	filters: listsIdentityFilters,
	render: func(q *Query, accts *Accounts, rows []listsIdentityScan) (any, error) {
		ids := make([]uuid.UUID, len(rows))
		subjects, states := make([]StaleSubject, len(rows)), make([]string, len(rows))
		for i, r := range rows {
			ids[i], subjects[i], states[i] = r.ID, r.StaleSubject(), r.State
		}
		var counts map[uuid.UUID]Exact
		ok, err := q.Optional(func(tx *gorm.DB) error {
			var err error
			counts, err = UsedByCounts(tx, q.WS, ids)
			return err
		})
		if err != nil {
			return nil, err
		}
		reasons, err := listsStaleReasons(q, accts, "identity_account_id", subjects, states)
		if err != nil {
			return nil, err
		}
		out := make([]IdentityRow, 0, len(rows))
		for _, r := range rows {
			used := Unknown()
			if c, has := counts[r.ID]; ok && has {
				used = c
			}
			out = append(out, r.Row(accts, used, StaleReasonOf(r.State, r.ID, reasons)))
		}
		return out, nil
	},
}

func listsIdentityFilters(p *ListParams, ws uuid.UUID) ([]listsFilter, listsScope, bool, *Error) {
	sc := listsScope{accounts: p.Accounts}
	// provider = 'aws' and supported: GitHub identities share the table (D-6).
	fs := []listsFilter{listsReadable("ia", "identity_account_id", ws)}
	fs = append(fs, listsLifecycle(p, "ia.lifecycle")...)
	// Provider id: the immutable key (RoleId AROA..., UserId AIDA..., GroupId AGPA...).
	fs = append(fs, listsQ(p, "ia.display_name", IdentityAccountSQL,
		listsQARN(p, "ia.source_key"), listsExact{"ia.immutable_key", p.Q})...)
	fs = append(fs, listsAccount(p, IdentityAccountSQL)...)

	// region: validated, never a filter -- IAM is global, and a region choice
	// never hides a global object (§2.14.10, D-75).
	if _, _, perr := listsRegions(p); perr != nil {
		return nil, sc, false, perr
	}

	integ, perr := listsIntegration(p, "ia", "identity_account_id")
	if perr != nil {
		return nil, sc, false, perr
	}
	fs = append(fs, integ...)

	kinds, perr := listsEnum(p, "kind", listsIdentityKinds...)
	if perr != nil {
		return nil, sc, false, perr
	}
	sc.kinds = kinds
	fs = append(fs, listsIn("kind", "ia.account_kind", kinds)...)

	used, perr := listsEnum(p, "used_by", UsedByWorkloads)
	if perr != nil {
		return nil, sc, false, perr
	}
	if len(used) > 0 {
		// The same relationships and states the Used by count and the Used-by
		// tab's workloads section count (UsedByTypes, D-17), so a row this
		// filter keeps never reads "0 workloads".
		fs = append(fs, listsFilter{sql: `EXISTS (SELECT 1 FROM iga_relationship ur
		      WHERE ur.workspace_id = ia.workspace_id AND ur.relationship_type IN ?
		        AND ur.target_identity_account_id = ia.id AND ur.state IN ('current', 'stale'))`, args: []any{UsedByTypes}})
	}
	return fs, sc, false, nil
}

/* -------------------------------- resources -------------------------------- */

type listsResourceScan struct {
	ResourceRecord
	K0 *string `gorm:"column:k0"`
	K1 *string `gorm:"column:k1"`
	K2 *string `gorm:"column:k2"`
	K3 *string `gorm:"column:k3"`
	K4 *string `gorm:"column:k4"`
	K5 *string `gorm:"column:k5"`
}

func (s listsResourceScan) rowID() uuid.UUID    { return s.ID }
func (s listsResourceScan) sortKeys() []*string { return []*string{s.K0, s.K1, s.K2, s.K3, s.K4, s.K5} }

// Resource sorts (D-13): kind by rank (the default), then name, then account
// (unknown last), then id; name, then account; service alphabetical with no
// service last.
var (
	listsResourceName    = listsOne(listsText("lower(r.display_name)"))
	listsResourceAccount = listsAccountKeys(ResourceAccountSQL)
)

var listsResources = listsSpec[listsResourceScan]{
	route:     ListRouteResources,
	sorts:     []string{"kind", "name", "service", "account"},
	defSort:   "kind",
	params:    map[string]bool{"region": true, "kind": true, "service": true, "integration": true},
	columns:   ResourceColumns,
	from:      ResourceFrom,
	countFrom: `iga_resources r`,
	idCol:     "r.id",
	keys: map[string][]listsKey{
		"kind": listsJoin(listsOne(listsRank(ResourceKindRankSQL)), listsResourceName, listsResourceAccount),
		"name": listsJoin(listsResourceName, listsResourceAccount),
		"service": listsJoin([]listsKey{listsNoValueLast(ResourceServiceSQL), listsText(ResourceServiceSQL)},
			listsResourceName, listsResourceAccount),
		"account": listsJoin(listsResourceAccount, listsResourceName),
	},
	facets: map[string]listsFacet{
		"kind": {expr: ResourceKindSQL, finalize: listsLabelled(map[string]string{
			ResourceExact: "Exact reference", ResourceSelector: "Selector", ResourceExternal: "External reference",
		})},
		"service": {expr: ResourceServiceSQL, finalize: listsLabelled(nil)},
		"account": {expr: ResourceAccountSQL, finalize: listsAccountFacet},
	},
	filters: listsResourceFilters,
	render: func(q *Query, accts *Accounts, rows []listsResourceScan) (any, error) {
		ids := make([]uuid.UUID, len(rows))
		subjects, states := make([]StaleSubject, len(rows)), make([]string, len(rows))
		for i, r := range rows {
			ids[i], subjects[i], states[i] = r.ID, r.StaleSubject(), r.State
		}
		var counts map[uuid.UUID]TargetCounts
		ok, err := q.Optional(func(tx *gorm.DB) error {
			var err error
			counts, err = ResourceTargetCounts(tx, q.WS, ids)
			return err
		})
		if err != nil {
			return nil, err
		}
		reasons, err := listsStaleReasons(q, accts, "resource_id", subjects, states)
		if err != nil {
			return nil, err
		}
		out := make([]ResourceRow, 0, len(rows))
		for _, r := range rows {
			named, excluded := Unknown(), Unknown()
			if c, has := counts[r.ID]; ok && has {
				named, excluded = c.NamedBy, c.ExcludedBy
			}
			out = append(out, r.Row(accts, named, excluded, StaleReasonOf(r.State, r.ID, reasons)))
		}
		return out, nil
	},
}

var listsServiceRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

func listsResourceFilters(p *ListParams, ws uuid.UUID) ([]listsFilter, listsScope, bool, *Error) {
	sc := listsScope{accounts: p.Accounts}
	// provider = 'aws' and supported: GitHub resources share the table (D-6).
	fs := []listsFilter{listsReadable("r", "resource_id", ws)}
	fs = append(fs, listsLifecycle(p, "r.lifecycle")...)
	// A resource's "full ARN or pattern" IS its display name; there is no
	// provider id for a reference.
	fs = append(fs, listsQ(p, "r.display_name", ResourceAccountSQL,
		listsExact{"r.display_name", p.Q})...)
	fs = append(fs, listsAccount(p, ResourceAccountSQL)...)

	names, notStated, perr := listsRegions(p)
	if perr != nil {
		return nil, sc, false, perr
	}
	sc.regions, sc.regionNotStated = names, notStated
	fs = append(fs, listsRegion(names, notStated, ResourceRegionSQL)...)

	integ, perr := listsIntegration(p, "r", "resource_id")
	if perr != nil {
		return nil, sc, false, perr
	}
	fs = append(fs, integ...)

	kinds, perr := listsEnum(p, "kind", ResourceExact, ResourceSelector, ResourceExternal)
	if perr != nil {
		return nil, sc, false, perr
	}
	fs = append(fs, listsIn("kind", ResourceKindSQL, kinds)...)

	var services []string
	for _, v := range p.Raw["service"] {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if !listsServiceRE.MatchString(v) {
			return nil, sc, false, InvalidParameter("service", "service must be an AWS service namespace, such as s3")
		}
		if !contains(services, v) {
			services = append(services, v)
		}
	}
	fs = append(fs, listsIn("service", ResourceServiceSQL, services)...)
	return fs, sc, false, nil
}
