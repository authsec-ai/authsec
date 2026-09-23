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
// sorts on classification (§5.5), plus the connected-account set when the
// resource kind orders or filters the list (see listsBinding).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// Reasons carried by 409 listing_changed.
const (
	// ListingClassificationChanged: a classification decision landed between
	// two pages of a list that filters or sorts on classification (§5.5).
	ListingClassificationChanged = "classification_changed"
	// ListingAccountsChanged: the workspace's connected accounts changed
	// between two pages of a resource list ordered or filtered by kind, whose
	// external/exact split depends on them (D-3, D-16).
	ListingAccountsChanged = "accounts_changed"
)

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

// listsKey is one sort component. Every expression is bind-variable free.
// numeric keys travel in the cursor as decimal strings and bind as bigint.
type listsKey struct {
	sql     string
	numeric bool
}

// listsBinding says what, beyond §5.1's fields, a list's cursor binds to.
type listsBinding struct {
	// classification: the list filters or sorts on classification, which is
	// not part of a revision, so its cursor carries the classification clock
	// and a decision between pages is 409 listing_changed (§5.5).
	classification bool
	// accounts: the list orders or filters on the resource kind, whose
	// external/exact split is computed at read time from the connected
	// accounts (D-3, D-16) and is not part of a revision either. Without this a
	// connector added between two pages would move rows across the page
	// boundary, repeating or skipping them.
	accounts bool
}

// listsScan is a route's scanned row: its record plus the sort key values the
// page query selected as k0, k1.
type listsScan interface {
	rowID() uuid.UUID
	sortKeys() []*string
}

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
	// support and execution laterals); countFrom is the bare FROM totals and
	// facets count over. Filters must only name countFrom's aliases.
	columns   string
	from      string
	countFrom string
	idCol     string

	keys    map[string][]listsKey // by sort key; id is always appended
	facets  map[string]listsFacet
	filters func(p *ListParams, ws uuid.UUID) ([]listsFilter, listsBinding, *Error)
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

// listsCommonParams are §5.2's list parameters.
var listsCommonParams = map[string]bool{
	"q": true, "sort": true, "limit": true, "cursor": true, "facets": true,
	"lifecycle": true, "account": true, "rev": true,
}

// listsAfter is a decoded cursor position.
type listsAfter struct {
	keys     []any // bind values for the sort keys: string or int64
	id       uuid.UUID
	classSeq *int64
	accounts string
}

// listsCursorKey is Cursor.Key for these routes: the last row's sort key
// values, and the connected-account digest when the list is bound to it.
type listsCursorKey struct {
	K []string `json:"k"`
	A string   `json:"a,omitempty"`
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
	filters, bind, perr := spec.filters(p, ws)
	if perr != nil {
		return nil, perr
	}
	if p.SortKey == "classification" {
		bind.classification = true
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

		// The bindings §5.1's revision check does not cover, checked in THIS
		// snapshot: the value the next page's rows are read at.
		var classSeq *int64
		if bind.classification {
			seq, err := listsClassificationSeq(q)
			if err != nil {
				return err
			}
			classSeq = &seq
			if after != nil && (after.classSeq == nil || *after.classSeq != seq) {
				return ListingChanged(ListingClassificationChanged)
			}
		}
		var digest string
		if bind.accounts {
			digest = listsAccountsDigest(accts)
			if after != nil && after.accounts != digest {
				return ListingChanged(ListingAccountsChanged)
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
			key := listsCursorKey{A: digest}
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
		if meta.Coverage, err = listsCoverage(q, accts, spec.route, p.Accounts); err != nil {
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
// A descending sort reverses the WHOLE tuple, id included, so the keyset is
// still a single row comparison and paging never repeats or skips a row.
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

	cols := make([]string, 0, len(keys)+1)
	for _, k := range keys {
		cols = append(cols, k.sql)
	}
	cols = append(cols, spec.idCol)
	if after != nil {
		marks := make([]string, 0, len(cols))
		for i, k := range keys {
			if k.numeric {
				marks = append(marks, "?::bigint")
			} else {
				marks = append(marks, "?::text")
			}
			args = append(args, after.keys[i])
		}
		marks = append(marks, "?::uuid")
		args = append(args, after.id)
		op := ">"
		if desc {
			op = "<"
		}
		fmt.Fprintf(&b, "\n   AND (%s) %s (%s)", strings.Join(cols, ", "), op, strings.Join(marks, ", "))
	}
	dir := " ASC"
	if desc {
		dir = " DESC"
	}
	b.WriteString("\n ORDER BY ")
	for i, c := range cols {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(c + dir)
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
	a := &listsAfter{id: c.ID, classSeq: c.ClassSeq, accounts: k.A}
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

// listsFacetCounts counts one facet as OPTIONAL work: nil (JSON null) when it
// timed out (D-14).
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

// listsAccountsDigest names the set of connected accounts (D-3), which the
// resource kind depends on.
func listsAccountsDigest(accts *Accounts) string {
	var ids []string
	seen := map[string]bool{}
	for _, c := range accts.All() {
		if accts.Connected(c.AccountID) && !seen[c.AccountID] {
			seen[c.AccountID] = true
			ids = append(ids, c.AccountID)
		}
	}
	sort.Strings(ids)
	h := sha256.Sum256([]byte(strings.Join(ids, ",")))
	return hex.EncodeToString(h[:8])
}

/* --------------------------- shared filter pieces -------------------------- */

// listsExact is one exact-match arm of q: an expression and the value q must
// equal there.
type listsExact struct {
	expr  string
	value string
}

// listsQ is §5.2's q: a case-insensitive substring of the display name with
// LIKE metacharacters escaped, OR an exact match on any of exact (full ARN or
// pattern, account id, provider id). Always bind variables, never spliced.
func listsQ(p *ListParams, nameCol string, exact ...listsExact) []listsFilter {
	if p.Q == "" {
		return nil
	}
	parts := []string{"lower(" + nameCol + `) LIKE lower(?) ESCAPE '\'`}
	args := []any{"%" + EscapeLike(p.Q) + "%"}
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

// listsRegion is a region filter: region names, or not_stated for objects whose
// ARN states none (region ”), over a column that is ” when not stated.
func listsRegion(p *ListParams, col string) ([]listsFilter, *Error) {
	var names []string
	notStated := false
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
			return nil, InvalidParameter("region", "region must be an AWS region name or not_stated")
		}
	}
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
		return nil, nil
	}
	return []listsFilter{{facet: "region", sql: strings.Join(parts, " OR "), args: args}}, nil
}

// listsIn is a plain IN filter over validated values.
func listsIn(facet, col string, values []string) []listsFilter {
	if len(values) == 0 {
		return nil
	}
	return []listsFilter{{facet: facet, sql: col + " IN ?", args: []any{values}}}
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

/* ------------------------------ meta.coverage ------------------------------ */

// listsCoverage is meta.coverage (§5.2, §2.14.14): every surface a run the
// current revision was built from intended to read and did not, that bears on
// this list, as {account_id, surface, state, affects}.
//
// The runs are the ones iga_projection_state names (D-57): each partition's
// last projected run, written in the publication's transaction, so this
// snapshot sees exactly the runs its graph came from. Per connector and
// surface, the newest such run that reports the surface decides its state. A
// surface is a gap when ScanCoverage.IntendedIncomplete says so: not_selected
// and unsupported are by design, not missing reads (D-58).
//
// An account filter narrows the notes to the chosen accounts; with "unknown"
// chosen (or no filter) every account's notes stay, since an object with no
// stated account may come from any of them.
func listsCoverage(q *Query, accts *Accounts, list string, accounts []string) ([]CoverageNote, error) {
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
	scope := map[string]bool{}
	all := len(accounts) == 0
	for _, a := range accounts {
		if a == AccountUnknown {
			all = true
		}
		scope[a] = true
	}

	type key struct{ account, surface string }
	decided := map[key]bool{}
	notes := []CoverageNote{}
	for _, run := range runs { // newest first
		conn := accts.Connector(run.ConnectorID)
		if conn == nil {
			continue
		}
		if !all && !scope[conn.AccountID] {
			continue
		}
		cov := models.DecodeScanCoverage(run.Coverage)
		gaps := cov.IntendedIncomplete()
		for surface, sc := range cov.Surfaces {
			k := key{conn.AccountID, surface}
			if decided[k] {
				continue // a newer run already reported this surface
			}
			decided[k] = true
			if _, gap := gaps[surface]; !gap {
				continue
			}
			if affects := listsAffects(list, surface); affects != "" {
				notes = append(notes, CoverageNote{AccountID: conn.AccountID, Surface: surface, State: sc.State, Affects: affects})
			}
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

// listsWorkloadAffects says what a workload-collection gap leaves out, or "".
func listsWorkloadAffects(surface string) string {
	if surface == models.SurfaceWorkloadScan {
		return "all workloads"
	}
	prefix, region, ok := strings.Cut(surface, ":")
	if !ok || region == "" {
		return ""
	}
	if prefix+":" == models.SurfaceComputePrefix {
		return "workloads in " + region
	}
	if kind, ok := listsWorkloadSurfaces[prefix]; ok {
		return "workloads of kind " + kind + " in " + region
	}
	return ""
}

// listsAffects is the affects text of one gap for one list, "" when the
// surface does not bear on it. The surfaces follow the partitions that
// project each list's rows (igagraph.Partitions).
func listsAffects(list, surface string) string {
	switch list {
	case ListRouteWorkloads:
		if surface == models.SurfaceIAMRoles {
			return "execution roles of workloads"
		}
		return listsWorkloadAffects(surface)
	case ListRouteIdentities:
		switch surface {
		case models.SurfaceIAMRoles:
			return "identities of kind " + models.CloudIdentityIAMRole
		case models.SurfaceIAMUsers:
			return "identities of kind " + models.CloudIdentityIAMUser
		case models.SurfaceIAMGroups:
			return "identities of kind " + models.CloudIdentityIAMGroup
		}
		if w := listsWorkloadAffects(surface); w != "" {
			return "used_by_count: " + w
		}
	case ListRouteResources:
		switch surface {
		case models.SurfaceIAMRoles:
			return "resources named by policies of identities of kind " + models.CloudIdentityIAMRole
		case models.SurfaceIAMUsers:
			return "resources named by policies of identities of kind " + models.CloudIdentityIAMUser
		case models.SurfaceIAMGroups:
			return "resources named by policies of identities of kind " + models.CloudIdentityIAMGroup
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

/* -------------------------------- workloads -------------------------------- */

type listsWorkloadScan struct {
	WorkloadRecord
	K0 *string `gorm:"column:k0"`
	K1 *string `gorm:"column:k1"`
}

func (s listsWorkloadScan) rowID() uuid.UUID    { return s.ID }
func (s listsWorkloadScan) sortKeys() []*string { return []*string{s.K0, s.K1} }

// listsWorkloadProviderID is the provider's own id for a workload: the ARN's
// resource id (after resource-type/ or resource-type:) -- an EC2 instance id, a
// Bedrock agent id, a function name. No stored column holds it.
const listsWorkloadProviderID = `regexp_replace(substring(split_part(w.source_key, chr(31), 2)
             from '^arn:[^:]*:[^:]*:[^:]*:[^:]*:(.*)$'), '^[^/:]*[/:]', '')`

// listsLastConfirmedKey sorts on D-1's last_confirmed_at, as integer
// microseconds so the cursor round-trips it exactly; never-confirmed sorts
// first.
func listsLastConfirmedKey() listsKey {
	return listsKey{sql: `COALESCE((extract(epoch FROM sup.last_confirmed_at) * 1000000)::bigint, 0)`, numeric: true}
}

var listsWorkloadRuntimeKinds = []string{
	models.WorkloadLambdaFunction, models.WorkloadECSTaskDefinition, models.WorkloadEC2Instance,
	models.WorkloadBedrockAgent, models.WorkloadBedrockAgentCoreRT, models.WorkloadBedrockAgentCoreGW,
}

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
		// (lower(display_name), id): idx_iga_workload_list (D-13).
		"name":           {{sql: "lower(w.display_name)"}},
		"account":        {{sql: WorkloadAccountSQL}, {sql: "lower(w.display_name)"}},
		"last_confirmed": {listsLastConfirmedKey(), {sql: "lower(w.display_name)"}},
		// idx_iga_workload_classification.
		"classification": {{sql: "w.classification"}, {sql: "lower(w.display_name)"}},
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
	render: func(_ *Query, accts *Accounts, rows []listsWorkloadScan) (any, error) {
		out := make([]WorkloadRow, 0, len(rows))
		for _, r := range rows {
			out = append(out, r.Row(accts))
		}
		return out, nil
	},
}

func listsWorkloadFilters(p *ListParams, ws uuid.UUID) ([]listsFilter, listsBinding, *Error) {
	var bind listsBinding
	fs := []listsFilter{{sql: "w.workspace_id = ? AND w.provider = 'aws'", args: []any{ws}}}
	fs = append(fs, listsLifecycle(p, "w.lifecycle")...)
	fs = append(fs, listsQ(p, "w.display_name", listsQARN(p, "w.source_key"),
		listsExact{WorkloadAccountSQL, p.Q}, listsExact{listsWorkloadProviderID, p.Q})...)
	fs = append(fs, listsAccount(p, WorkloadAccountSQL)...)

	regions, perr := listsRegion(p, "w.region")
	if perr != nil {
		return nil, bind, perr
	}
	fs = append(fs, regions...)

	// integration: "objects supported by this connector" (§2.14.10) -- a
	// non-ended support row of it. Another workspace's connector matches no
	// support row of this workspace, so it is an empty list, never a leak.
	var conns []uuid.UUID
	for _, v := range p.Raw["integration"] {
		if strings.TrimSpace(v) == "" {
			continue
		}
		ref, perr := ParseRefParam("integration", v, RefConnector)
		if perr != nil {
			return nil, bind, perr
		}
		conns = append(conns, ref.ID)
	}
	if len(conns) > 0 {
		fs = append(fs, listsFilter{sql: `EXISTS (SELECT 1 FROM iga_object_support os
		      WHERE os.workspace_id = w.workspace_id AND os.workload_id = w.id
		        AND os.connector_id IN ? AND os.state <> 'ended')`, args: []any{conns}})
	}

	kinds, perr := listsEnum(p, "runtime_kind", listsWorkloadRuntimeKinds...)
	if perr != nil {
		return nil, bind, perr
	}
	fs = append(fs, listsIn("runtime_kind", "w.runtime_kind", kinds)...)

	cls, perr := listsEnum(p, "classification", ClassificationAgent,
		models.ClassificationProviderAgent, models.ClassificationClassified, models.ClassificationUnclassified)
	if perr != nil {
		return nil, bind, perr
	}
	if len(cls) > 0 {
		bind.classification = true
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
		return nil, bind, perr
	}
	fs = append(fs, listsIn("", "w.execution_role_state", states)...)
	return fs, bind, nil
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

// listsRegionFacet: each stated region, and not_stated for objects whose ARN
// states none.
func listsRegionFacet(counts map[string]int64, _ *Accounts) []FacetValue {
	out := []FacetValue{}
	for v, n := range counts {
		if v == "" {
			out = append(out, FacetValue{Value: RegionNotStated, Label: "Region not stated", Count: n})
			continue
		}
		out = append(out, FacetValue{Value: v, Label: v, Count: n})
	}
	return listsFacetOrder(out, RegionNotStated)
}

/* -------------------------------- identities ------------------------------- */

type listsIdentityScan struct {
	IdentityRecord
	K0 *string `gorm:"column:k0"`
	K1 *string `gorm:"column:k1"`
}

func (s listsIdentityScan) rowID() uuid.UUID    { return s.ID }
func (s listsIdentityScan) sortKeys() []*string { return []*string{s.K0, s.K1} }

var listsIdentityKinds = []string{models.CloudIdentityIAMRole, models.CloudIdentityIAMUser, models.CloudIdentityIAMGroup}

var listsIdentities = listsSpec[listsIdentityScan]{
	route:     ListRouteIdentities,
	sorts:     []string{"name", "kind", "account", "last_confirmed"},
	defSort:   "name",
	params:    map[string]bool{"kind": true, "used_by": true},
	columns:   IdentityColumns,
	from:      IdentityFrom,
	countFrom: `iga_identity_accounts ia`,
	idCol:     "ia.id",
	keys: map[string][]listsKey{
		"name":           {{sql: "lower(ia.display_name)"}},
		"kind":           {{sql: "ia.account_kind"}, {sql: "lower(ia.display_name)"}},
		"account":        {{sql: IdentityAccountSQL}, {sql: "lower(ia.display_name)"}},
		"last_confirmed": {listsLastConfirmedKey(), {sql: "lower(ia.display_name)"}},
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
		ids := make([]uuid.UUID, 0, len(rows))
		for _, r := range rows {
			ids = append(ids, r.ID)
		}
		var counts map[uuid.UUID]int64
		ok, err := q.Optional(func(tx *gorm.DB) error {
			var err error
			counts, err = UsedByCounts(tx, q.WS, ids)
			return err
		})
		if err != nil {
			return nil, err
		}
		out := make([]IdentityRow, 0, len(rows))
		for _, r := range rows {
			used := Unknown()
			if ok {
				used = ExactOf(counts[r.ID])
			}
			out = append(out, r.Row(accts, used))
		}
		return out, nil
	},
}

func listsIdentityFilters(p *ListParams, ws uuid.UUID) ([]listsFilter, listsBinding, *Error) {
	// provider = 'aws': GitHub identities share the table (D-6).
	fs := []listsFilter{{sql: "ia.workspace_id = ? AND ia.provider = 'aws'", args: []any{ws}}}
	fs = append(fs, listsLifecycle(p, "ia.lifecycle")...)
	// Provider id: the immutable key (RoleId AROA..., UserId AIDA..., GroupId AGPA...).
	fs = append(fs, listsQ(p, "ia.display_name", listsQARN(p, "ia.source_key"),
		listsExact{IdentityAccountSQL, p.Q}, listsExact{"ia.immutable_key", p.Q})...)
	fs = append(fs, listsAccount(p, IdentityAccountSQL)...)

	kinds, perr := listsEnum(p, "kind", listsIdentityKinds...)
	if perr != nil {
		return nil, listsBinding{}, perr
	}
	fs = append(fs, listsIn("kind", "ia.account_kind", kinds)...)

	used, perr := listsEnum(p, "used_by", UsedByWorkloads)
	if perr != nil {
		return nil, listsBinding{}, perr
	}
	if len(used) > 0 {
		// The same relationships the Used by count and the Used-by tab's
		// workloads section count (UsedByTypes), so a row this filter keeps
		// never reads "0 workloads".
		fs = append(fs, listsFilter{sql: `EXISTS (SELECT 1 FROM iga_relationship ur
		      WHERE ur.workspace_id = ia.workspace_id AND ur.relationship_type IN ?
		        AND ur.target_identity_account_id = ia.id AND ur.state <> 'ended')`, args: []any{UsedByTypes}})
	}
	return fs, listsBinding{}, nil
}

/* -------------------------------- resources -------------------------------- */

type listsResourceScan struct {
	ResourceRecord
	K0 *string `gorm:"column:k0"`
	K1 *string `gorm:"column:k1"`
}

func (s listsResourceScan) rowID() uuid.UUID    { return s.ID }
func (s listsResourceScan) sortKeys() []*string { return []*string{s.K0, s.K1} }

// listsResourceKindOrder is the default order: exact reference, selector,
// external, then name (§2.14.6).
const listsResourceKindOrder = `(CASE ` + ResourceKindSQL + ` WHEN 'exact' THEN 0 WHEN 'selector' THEN 1 ELSE 2 END)`

var listsResources = listsSpec[listsResourceScan]{
	route:     ListRouteResources,
	sorts:     []string{"kind", "name", "service", "account"},
	defSort:   "kind",
	params:    map[string]bool{"region": true, "kind": true, "service": true},
	columns:   ResourceColumns,
	from:      ResourceFrom,
	countFrom: `iga_resources r`,
	idCol:     "r.id",
	keys: map[string][]listsKey{
		"kind":    {{sql: listsResourceKindOrder, numeric: true}, {sql: "lower(r.display_name)"}},
		"name":    {{sql: "lower(r.display_name)"}},
		"service": {{sql: ResourceServiceSQL}, {sql: "lower(r.display_name)"}},
		"account": {{sql: ResourceAccountSQL}, {sql: "lower(r.display_name)"}},
	},
	facets: map[string]listsFacet{
		"kind": {expr: ResourceKindSQL, finalize: listsLabelled(map[string]string{
			ResourceExact: "Exact reference", ResourceSelector: "Selector", ResourceExternal: "External",
		})},
		"service": {expr: ResourceServiceSQL, finalize: listsLabelled(nil)},
		"account": {expr: ResourceAccountSQL, finalize: listsAccountFacet},
	},
	filters: listsResourceFilters,
	render: func(q *Query, accts *Accounts, rows []listsResourceScan) (any, error) {
		ids := make([]uuid.UUID, 0, len(rows))
		for _, r := range rows {
			ids = append(ids, r.ID)
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
		out := make([]ResourceRow, 0, len(rows))
		for _, r := range rows {
			named, excluded := Unknown(), Unknown()
			if ok {
				c := counts[r.ID]
				named, excluded = ExactOf(c.NamedBy), ExactOf(c.ExcludedBy)
			}
			out = append(out, r.Row(accts, named, excluded))
		}
		return out, nil
	},
}

var listsServiceRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

func listsResourceFilters(p *ListParams, ws uuid.UUID) ([]listsFilter, listsBinding, *Error) {
	var bind listsBinding
	// provider = 'aws': GitHub resources share the table (D-6).
	fs := []listsFilter{{sql: "r.workspace_id = ? AND r.provider = 'aws'", args: []any{ws}}}
	fs = append(fs, listsLifecycle(p, "r.lifecycle")...)
	// A resource's "full ARN or pattern" IS its display name; there is no
	// provider id for a reference.
	fs = append(fs, listsQ(p, "r.display_name",
		listsExact{"r.display_name", p.Q}, listsExact{ResourceAccountSQL, p.Q})...)
	fs = append(fs, listsAccount(p, ResourceAccountSQL)...)

	regions, perr := listsRegion(p, ResourceRegionSQL)
	if perr != nil {
		return nil, bind, perr
	}
	fs = append(fs, regions...)

	kinds, perr := listsEnum(p, "kind", ResourceExact, ResourceSelector, ResourceExternal)
	if perr != nil {
		return nil, bind, perr
	}
	if len(kinds) > 0 {
		bind.accounts = true
		fs = append(fs, listsIn("kind", ResourceKindSQL, kinds)...)
	}
	if p.SortKey == "kind" {
		bind.accounts = true
	}

	var services []string
	for _, v := range p.Raw["service"] {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if !listsServiceRE.MatchString(v) {
			return nil, bind, InvalidParameter("service", "service must be an AWS service namespace, such as s3")
		}
		if !contains(services, v) {
			services = append(services, v)
		}
	}
	fs = append(fs, listsIn("service", ResourceServiceSQL, services)...)
	return fs, bind, nil
}
