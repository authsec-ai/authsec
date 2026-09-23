package igaread

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
)

// Envelope is every response body: {"data": ..., "meta": ...} (§5.2). Lists
// carry ListMeta, details DetailMeta; routes with their own meta (graph
// budgets) pass a map.
type Envelope struct {
	Data any `json:"data"`
	Meta any `json:"meta"`
}

// Graph states in meta.graph_state (§5.1).
const (
	GraphPublished    = "published"
	GraphNotPublished = "not_published"
)

// List paging bounds (§5.2).
const (
	DefaultLimit = 100
	MaxLimit     = 200
	// TotalCap: totals are counted with LIMIT TotalCap+1; beyond it the total
	// is not known and total_at_least is TotalCap.
	TotalCap = 10000
)

// FacetValue is one chip: the value, its label and how many rows choosing it
// would give with every OTHER active filter applied (§5.2).
type FacetValue struct {
	Value string `json:"value"`
	Label string `json:"label"`
	Count int64  `json:"count"`
}

// CoverageNote is one list-level coverage gap: a surface of an account that is
// not reached, and what it affects in this list (§5.2 list envelope).
type CoverageNote struct {
	AccountID string `json:"account_id"`
	Surface   string `json:"surface"`
	State     string `json:"state"`
	Affects   string `json:"affects"`
}

// ListMeta is the list envelope's meta (§5.2). Facets maps a facet name to its
// values, or to nil (JSON null) when its optional count timed out.
type ListMeta struct {
	Rev          *int64                  `json:"rev"`
	PublishedAt  *time.Time              `json:"published_at"`
	GraphState   string                  `json:"graph_state"`
	NextCursor   *string                 `json:"next_cursor"`
	Limit        int                     `json:"limit"`
	TotalKnown   bool                    `json:"total_known"`
	Total        *int64                  `json:"total,omitempty"`
	TotalAtLeast *int64                  `json:"total_at_least,omitempty"`
	Facets       map[string][]FacetValue `json:"facets,omitempty"`
	Coverage     []CoverageNote          `json:"coverage"`
}

// NewListMeta starts a list meta from the snapshot's revision.
func NewListMeta(q *Query, limit int) ListMeta {
	m := ListMeta{Limit: limit, Coverage: []CoverageNote{}}
	m.Stamp(q)
	return m
}

// Stamp sets rev, published_at and graph_state from the snapshot.
func (m *ListMeta) Stamp(q *Query) {
	if q.Rev == nil {
		m.Rev, m.PublishedAt, m.GraphState = nil, nil, GraphNotPublished
		return
	}
	rev, at := q.Rev.Rev, q.Rev.PublishedAt.UTC()
	m.Rev, m.PublishedAt, m.GraphState = &rev, &at, GraphPublished
}

// SetTotal records a counted total (at most TotalCap+1 rows counted).
func (m *ListMeta) SetTotal(n int64, known bool) {
	if !known {
		m.TotalKnown, m.Total = false, nil
		return
	}
	if n > TotalCap {
		atLeast := int64(TotalCap)
		m.TotalKnown, m.Total, m.TotalAtLeast = false, nil, &atLeast
		return
	}
	m.TotalKnown, m.Total = true, &n
}

// DetailMeta is the detail envelope's meta -- distinct from a list's, never a
// one-row list (§5.2).
type DetailMeta struct {
	Rev          *int64         `json:"rev"`
	PublishedAt  *time.Time     `json:"published_at"`
	GraphState   string         `json:"graph_state"`
	Capabilities map[string]any `json:"capabilities,omitempty"`
}

// NewDetailMeta stamps a detail meta from the snapshot.
func NewDetailMeta(q *Query) DetailMeta {
	d := DetailMeta{GraphState: GraphNotPublished}
	if q.Rev != nil {
		rev, at := q.Rev.Rev, q.Rev.PublishedAt.UTC()
		d.Rev, d.PublishedAt, d.GraphState = &rev, &at, GraphPublished
	}
	return d
}

// Lifecycle filter values (§5.2).
const (
	LifecycleActive  = "active"
	LifecycleRetired = "retired"
	LifecycleAll     = "all"
)

// AccountUnknown selects objects with no stated account (§2.14.10).
const AccountUnknown = "unknown"

// ListParams are the common list parameters (§5.2), validated.
type ListParams struct {
	Raw       url.Values
	Q         string
	SortKey   string // without the "-" prefix
	Desc      bool
	Limit     int
	Cursor    string
	Facets    []string
	Lifecycle string
	// Accounts are the account filter values, "unknown" included verbatim.
	// Empty means all accounts INCLUDING unknown.
	Accounts []string
	// Rev is the pinned revision, when the client sent one.
	Rev *int64
}

// SortString is the sort as bound into the cursor ("-name", "kind").
func (p *ListParams) SortString() string {
	if p.Desc {
		return "-" + p.SortKey
	}
	return p.SortKey
}

// ParseListParams validates the common parameters. sorts are the route's
// allowed sort keys (without "-"), def the default; facets the allowed facet
// names. Route-specific filters stay in Raw for the route to validate.
func ParseListParams(vals url.Values, sorts []string, def string, facets []string) (*ListParams, *Error) {
	p := &ListParams{Raw: vals, Limit: DefaultLimit, Lifecycle: LifecycleActive}

	if q := strings.TrimSpace(vals.Get("q")); q != "" {
		if len([]rune(q)) < 2 {
			return nil, InvalidParameter("q", "q needs at least 2 characters")
		}
		p.Q = q
	}

	s := vals.Get("sort")
	if s == "" {
		s = def
	}
	desc := strings.HasPrefix(s, "-")
	key := strings.TrimPrefix(s, "-")
	if !contains(sorts, key) {
		return nil, InvalidParameter("sort", fmt.Sprintf("sort must be one of %s, optionally prefixed with -", strings.Join(sorts, ", ")))
	}
	p.SortKey, p.Desc = key, desc

	if l := vals.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > MaxLimit {
			return nil, InvalidParameter("limit", fmt.Sprintf("limit must be 1-%d", MaxLimit))
		}
		p.Limit = n
	}

	p.Cursor = vals.Get("cursor")

	if f := vals.Get("facets"); f != "" {
		for _, name := range strings.Split(f, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if !contains(facets, name) {
				return nil, InvalidParameter("facets", fmt.Sprintf("facets must be drawn from %s", strings.Join(facets, ", ")))
			}
			if !contains(p.Facets, name) {
				p.Facets = append(p.Facets, name)
			}
		}
	}

	if lc := vals.Get("lifecycle"); lc != "" {
		switch lc {
		case LifecycleActive, LifecycleRetired, LifecycleAll:
			p.Lifecycle = lc
		default:
			return nil, InvalidParameter("lifecycle", "lifecycle must be active, retired or all")
		}
	}

	for _, a := range vals["account"] {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if a != AccountUnknown && !isAccountID(a) {
			return nil, InvalidParameter("account", "account must be a 12-digit account id or unknown")
		}
		if !contains(p.Accounts, a) {
			p.Accounts = append(p.Accounts, a)
		}
	}

	rev, perr := ParseRev(vals)
	if perr != nil {
		return nil, perr
	}
	p.Rev = rev
	return p, nil
}

// ParseRev reads the optional rev parameter.
func ParseRev(vals url.Values) (*int64, *Error) {
	r := vals.Get("rev")
	if r == "" {
		return nil, nil
	}
	n, err := strconv.ParseInt(r, 10, 64)
	if err != nil || n < 1 {
		return nil, InvalidParameter("rev", "rev must be a positive integer")
	}
	return &n, nil
}

// EscapeLike escapes LIKE metacharacters so q is matched as a literal
// substring (§5.2). Use with ESCAPE '\'.
func EscapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// CountUpTo counts the rows of a query, at most TotalCap+1, as OPTIONAL work:
// known=false when it timed out (§5.2 Totals). build receives the snapshot tx
// and returns the unpaged, unsorted query to count.
func (q *Query) CountUpTo(build func(tx *gorm.DB) *gorm.DB) (n int64, known bool, err error) {
	ok, err := q.Optional(func(tx *gorm.DB) error {
		sub := build(tx).Select("1").Limit(TotalCap + 1)
		return tx.Raw("SELECT count(*) FROM (?) AS t", sub).Row().Scan(&n)
	})
	if err != nil || !ok {
		return 0, false, err
	}
	return n, true, nil
}

func isAccountID(s string) bool {
	if len(s) != 12 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
