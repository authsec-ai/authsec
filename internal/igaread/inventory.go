package igaread

// The unified inventory (unified-discovery CONTRACT, "The API"):
//
//	GET /api/iga/v1/inventory/workloads
//	GET /api/iga/v1/inventory/identities
//	GET /api/iga/v1/inventory/resources
//
// One provider-neutral row for every workload, identity and resource AWS,
// Kubernetes and GitHub write into the shared iga_* tables. It sits beside the
// Phase 2 graph lists (lists.go), not inside them: those are AWS-only by
// contract (D-6, D-75) and are bound to a publication revision, which
// Kubernetes and GitHub do not have. What it shares with them is the §5.1/§5.2
// machinery -- one REPEATABLE READ, READ ONLY snapshot per request under one
// deadline (Read, with an empty Pin), the keyset page statement
// (listsPageSQL), signed cursors bound to workspace + route + filter hash +
// sort, the capped total and the optional facets -- so paging, totals and
// facets behave exactly as they do on the graph lists.
//
// A row is LISTED when, in the token's workspace:
//
//   - its provider is aws, k8s or github, and it is not a legacy GitHub IGA
//     row (provider github with source_key ''): those belong to the old GitHub
//     screens, which select exactly source_key = '';
//   - it has at least one iga_object_support row whose state is not ended,
//     from any of the three sources (connector_id, discovery_source_id,
//     integration_id) -- the provenance a projection writes and retires by;
//   - its lifecycle passes the lifecycle filter (active by default).
//
// state is current when any of its support rows is current, else stale.
//
// PUBLICATION STATE (B1). The inventory is not pinned to a revision, but it
// reports what a reader needs to tell a numbered AWS publication from a live
// Kubernetes write: meta.rev / meta.published_at (the AWS publication current
// in the request's snapshot, null when none; reported, never enforced),
// meta.graph_state over the FILTERED result, meta.coverage (the graph lists'
// AWS notes for the accounts in scope plus one note per Kubernetes cluster
// from its latest sweep), and per row graph_state and as_of.
//
// Scope: an AWS row's scope is derived from existing columns, through the SAME
// expressions the graph lists use (WorkloadAccountSQL, IdentityAccountSQL,
// ResourceAccountSQL), labelled from the workspace's connectors (LoadAccounts);
// its sub_scope is the region where it has one. A k8s or github row carries its
// scope in provider_attrs (scope_kind, scope_id, scope_label, sub_scope), and
// attrs is provider_attrs without those four keys.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/k8sread"
	"github.com/authsec-ai/authsec/models"
)

// Inventory routes, as bound into their cursors: distinct from the graph
// lists' "workloads", "identities" and "resources", so a cursor of one is
// never accepted by the other.
const (
	inventoryRouteWorkloads  = "inventory/workloads"
	inventoryRouteIdentities = "inventory/identities"
	inventoryRouteResources  = "inventory/resources"
)

// InventoryDefaultLimit is the page size when limit is absent (MaxLimit caps
// it, as on the graph lists).
const InventoryDefaultLimit = 50

// InventoryProviders are the providers the inventory lists.
var InventoryProviders = []string{models.ProviderAWS, models.ProviderK8s, models.ProviderGitHub}

// The provider_attrs keys a k8s or github row states its scope and native id
// in. They are the row's scope, sub_scope and native_id, never its attrs.
var inventoryScopeKeys = []string{"scope_kind", "scope_id", "scope_label", "sub_scope", "native_id"}

// inventoryScopeAWSAccount is an AWS row's scope kind.
const inventoryScopeAWSAccount = "aws_account"

// inventoryParams are every parameter the inventory lists accept; anything
// else is 400 invalid_parameter.
var inventoryParams = map[string]bool{
	"provider": true, "kind": true, "scope": true, "q": true, "lifecycle": true,
	"limit": true, "cursor": true, "facets": true, "sort": true,
}

// inventorySummaryParams are every parameter GET /inventory/summary accepts:
// the filters that apply to all three classes. kind is class-specific, and
// paging, sort and facets have no meaning for counts.
var inventorySummaryParams = map[string]bool{
	"provider": true, "scope": true, "q": true, "lifecycle": true,
}

// inventorySorts are the sort values: by name (then id), or most recently
// seen first (then id, descending).
var inventorySorts = []string{"name", "-last_seen"}

var inventoryFacetNames = []string{"provider", "kind", "scope"}

// ListInventoryWorkloads serves GET /api/iga/v1/inventory/workloads.
func (r *Reader) ListInventoryWorkloads(ctx context.Context, vals url.Values) (any, error) {
	return inventoryRun(ctx, r, vals, inventoryWorkloads)
}

// ListInventoryIdentities serves GET /api/iga/v1/inventory/identities.
func (r *Reader) ListInventoryIdentities(ctx context.Context, vals url.Values) (any, error) {
	return inventoryRun(ctx, r, vals, inventoryIdentities)
}

// ListInventoryResources serves GET /api/iga/v1/inventory/resources.
func (r *Reader) ListInventoryResources(ctx context.Context, vals url.Values) (any, error) {
	return inventoryRun(ctx, r, vals, inventoryResources)
}

/* --------------------------------- the rows -------------------------------- */

// InventoryScope is where a row lives: an AWS account, a Kubernetes cluster,
// a GitHub org or user.
type InventoryScope struct {
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	Label string `json:"label"`
}

// InventoryRow is one row of an inventory list, the same shape for every
// provider and every class.
type InventoryRow struct {
	Ref           string          `json:"ref"`
	Provider      string          `json:"provider"`
	Kind          string          `json:"kind"`
	Name          string          `json:"name"`
	NativeID      string          `json:"native_id"`
	Scope         *InventoryScope `json:"scope"`
	SubScope      *string         `json:"sub_scope"`
	Lifecycle     string          `json:"lifecycle"`
	RetiredReason *string         `json:"retired_reason"`
	State         string          `json:"state"`
	FirstSeenAt   any             `json:"first_seen_at"`
	LastSeenAt    any             `json:"last_seen_at"`
	Attrs         map[string]any  `json:"attrs"`
	// GraphState is "published" for an AWS row (it is in the current
	// publication) and "unrevisioned" for a Kubernetes or GitHub row (written
	// straight from a sweep or a scan, no publication number). Omitted for an
	// AWS row when the workspace has no publication: nothing can be claimed.
	GraphState string `json:"graph_state,omitempty"`
	// AsOf is the reading behind the row: an AWS row's publication time, the
	// observed_at of the Kubernetes sweep that last confirmed a row, the time of
	// the GitHub scan run that did. null when no confirming reading is recorded.
	AsOf any `json:"as_of"`
}

// InventoryPublication is the publication state an inventory response carries
// in its meta, shared by the lists and the summary.
type InventoryPublication struct {
	// Rev and PublishedAt are the AWS publication current in the snapshot, null
	// when none. Reported, not enforced: the inventory is not pinned.
	Rev         *int64     `json:"rev"`
	PublishedAt *time.Time `json:"published_at"`
	// GraphState is published | unrevisioned | mixed | not_published, over the
	// filtered result (inventoryGraphState). Omitted only when its probe timed
	// out: unknown is never guessed.
	GraphState *string `json:"graph_state,omitempty"`
	// Coverage: the graph lists' AWS notes for the accounts in scope, then one
	// k8s_sweep note per Kubernetes cluster in scope. [] when there is none.
	Coverage []InventoryCoverageNote `json:"coverage"`
}

// InventoryCoverageNote is a CoverageNote, plus the sweep time a Kubernetes
// cluster's note is read from. An AWS note carries no observed_at.
type InventoryCoverageNote struct {
	CoverageNote
	ObservedAt *time.Time `json:"observed_at,omitempty"`
}

// InventoryMeta is an inventory list's meta: the graph lists' paging, total
// and facets, and the publication state (nothing here is pinned to one).
type InventoryMeta struct {
	Limit        int                     `json:"limit"`
	NextCursor   *string                 `json:"next_cursor"`
	TotalKnown   bool                    `json:"total_known"`
	Total        *int64                  `json:"total,omitempty"`
	TotalAtLeast *int64                  `json:"total_at_least,omitempty"`
	Facets       map[string][]FacetValue `json:"facets,omitempty"`
	InventoryPublication
}

// inventoryRecord is one row as inventoryColumns reads it, plus the page
// query's sort keys.
type inventoryRecord struct {
	ID            uuid.UUID
	Provider      string
	Kind          string
	DisplayName   string
	NativeID      string
	ScopeKind     string
	ScopeID       string
	ScopeLabel    string
	SubScope      string
	Lifecycle     string
	RetiredReason string
	State         string
	FirstSeenAt   time.Time
	LastSeenAt    time.Time
	ProviderAttrs json.RawMessage
	AsOf          *time.Time
	K0            *string `gorm:"column:k0"`
	K1            *string `gorm:"column:k1"`
	K2            *string `gorm:"column:k2"`
	K3            *string `gorm:"column:k3"`
	K4            *string `gorm:"column:k4"`
	K5            *string `gorm:"column:k5"`
}

func (s inventoryRecord) rowID() uuid.UUID    { return s.ID }
func (s inventoryRecord) sortKeys() []*string { return []*string{s.K0, s.K1, s.K2, s.K3, s.K4, s.K5} }

// row renders the record. An AWS account is labelled as everywhere else
// (Accounts.Of: the connector's display name, else the id); a k8s or github
// scope by its scope_label, else its id.
func (s inventoryRecord) row(refType string, accts *Accounts, rev *Revision) (InventoryRow, error) {
	attrs := map[string]any{}
	if len(s.ProviderAttrs) > 0 {
		if err := json.Unmarshal(s.ProviderAttrs, &attrs); err != nil {
			return InventoryRow{}, fmt.Errorf("igaread: provider_attrs of %s:%s: %w", refType, s.ID, err)
		}
		if attrs == nil { // the JSON literal null
			attrs = map[string]any{}
		}
	}
	for _, k := range inventoryScopeKeys {
		delete(attrs, k)
	}
	var scope *InventoryScope
	if s.ScopeID != "" {
		scope = &InventoryScope{Kind: s.ScopeKind, ID: s.ScopeID, Label: s.ScopeLabel}
		if s.Provider == models.ProviderAWS {
			scope.Label = accts.Of(s.ScopeID).Label
		} else if scope.Label == "" {
			scope.Label = s.ScopeID
		}
	}
	graphState, asOf := "unrevisioned", TS(s.AsOf)
	if s.Provider == models.ProviderAWS {
		graphState, asOf = "", nil
		if rev != nil {
			graphState, asOf = GraphPublished, T(PublicationTime(rev.PublishedAt))
		}
	}
	return InventoryRow{
		GraphState:    graphState,
		AsOf:          asOf,
		Ref:           R(refType, s.ID),
		Provider:      s.Provider,
		Kind:          s.Kind,
		Name:          s.DisplayName,
		NativeID:      s.NativeID,
		Scope:         scope,
		SubScope:      strPtr(s.SubScope),
		Lifecycle:     s.Lifecycle,
		RetiredReason: strPtr(s.RetiredReason),
		State:         s.State,
		FirstSeenAt:   T(s.FirstSeenAt),
		LastSeenAt:    T(s.LastSeenAt),
		Attrs:         attrs,
	}, nil
}

/* --------------------------------- classes --------------------------------- */

// inventoryClass is what differs between the three inventory lists: the node
// table and its alias, its kind column, its support column and typed ref, and
// the AWS scope expressions (the graph lists' own, so an AWS row's account is
// the same here and there).
type inventoryClass struct {
	route   string
	refType string
	// list is the graph list of the same class (listsRoute*): its name selects
	// the coverage notes (listsCoverage) that bear on this class.
	list  string
	alias string
	// from is the node table, aliased, with the joins the AWS expressions need;
	// every filter and facet names only its aliases.
	from       string
	kindCol    string
	supportCol string
	// awsScope is the AWS account expression ('' when the row states none);
	// awsSubScope the AWS region expression ('' when none).
	awsScope    string
	awsSubScope string

	spec *listsSpec[inventoryRecord]
}

var (
	inventoryWorkloads = newInventoryClass(inventoryClass{
		route: inventoryRouteWorkloads, list: listsRouteWorkloads, refType: RefWorkload, alias: "w",
		from: `iga_workload w
  LEFT JOIN iga_estate_scopes es ON es.workspace_id = w.workspace_id AND es.id = w.estate_scope_id`,
		kindCol: "w.runtime_kind", supportCol: "workload_id",
		awsScope: WorkloadAccountSQL, awsSubScope: "w.region",
	})
	inventoryIdentities = newInventoryClass(inventoryClass{
		route: inventoryRouteIdentities, list: listsRouteIdentities, refType: RefIdentity, alias: "ia",
		from:    `iga_identity_accounts ia`,
		kindCol: "ia.account_kind", supportCol: "identity_account_id",
		// IAM is global: an AWS identity has an account and no region.
		awsScope: IdentityAccountSQL, awsSubScope: "''",
	})
	inventoryResources = newInventoryClass(inventoryClass{
		route: inventoryRouteResources, list: listsRouteResources, refType: RefResource, alias: "r",
		from:    `iga_resources r`,
		kindCol: "r.resource_kind", supportCol: "resource_id",
		// What the reference's ARN states (never the scanning connector's).
		awsScope: ResourceAccountSQL, awsSubScope: ResourceRegionSQL,
	})
)

// newInventoryClass builds the class's list spec: its columns, FROM, sort
// keys and facets, for listsPageSQL and listsFacetCounts.
func newInventoryClass(c inventoryClass) *inventoryClass {
	a := c.alias
	columns := a + `.id, ` + a + `.provider, ` + c.kindCol + ` AS kind, ` + a + `.display_name,
       ` + c.nativeSQL() + ` AS native_id,
       ` + c.scopeKindSQL() + ` AS scope_kind,
       ` + c.scopeIDSQL() + ` AS scope_id,
       ` + c.scopeLabelSQL() + ` AS scope_label,
       ` + c.subScopeSQL() + ` AS sub_scope,
       ` + a + `.lifecycle, ` + a + `.retired_reason, sup.state,
       ` + a + `.first_seen_at, ` + a + `.last_seen_at, ` + a + `.provider_attrs, asof.as_of`
	c.spec = &listsSpec[inventoryRecord]{
		route:   c.route,
		columns: columns,
		// SupportLateral is the graph lists' D-1 state: current if any support
		// row is current, else stale if any is stale. Every listed row has a
		// non-ended support row, so it is never ended here.
		from:      c.from + "\n  " + SupportLateral(a, c.supportCol) + "\n  " + c.asOfLateral(),
		countFrom: c.from,
		idCol:     a + ".id",
		keys: map[string][]listsKey{
			"name":      listsOne(listsText("lower(" + a + ".display_name)")),
			"last_seen": listsOne(listsRank("(extract(epoch FROM " + a + ".last_seen_at) * 1000000)::bigint")),
		},
		facets: map[string]listsFacet{
			"provider": {expr: a + ".provider", finalize: listsLabelled(inventoryProviderLabels)},
			"kind":     {expr: c.kindCol, finalize: listsLabelled(inventoryKindLabels)},
			// id ␟ kind ␟ label, so the chip can be labelled; finalized per id.
			"scope": {expr: c.scopeIDSQL() + " || chr(31) || " + c.scopeKindSQL() + " || chr(31) || " + c.scopeLabelSQL(),
				finalize: inventoryScopeFacet},
		},
	}
	return &c
}

// asOfLateral derives a Kubernetes or GitHub row's as_of (B1): the newest
// reading that confirmed it, over its non-ended support rows -- the
// observed_at of the Kubernetes sweep (last_confirmed_sweep_id) or the
// completion time of the GitHub scan run (last_confirmed_scan_run_id), else
// the run's start. An AWS row's as_of is the publication, so it is skipped
// here. NULL when no support row names a confirming reading. One probe on the
// (workspace_id, <support column>) prefix of the uq_iga_os_* indexes per page
// row; the count and facet statements do not join it.
func (c *inventoryClass) asOfLateral() string {
	return `LEFT JOIN LATERAL (
	        SELECT max(COALESCE(sw.observed_at, gr.completed_at, gr.started_at)) AS as_of
	          FROM iga_object_support s2
	          LEFT JOIN iga_k8s_sweep sw ON sw.workspace_id = s2.workspace_id AND sw.id = s2.last_confirmed_sweep_id
	          LEFT JOIN iga_scan_runs gr ON gr.workspace_id = s2.workspace_id AND gr.id = s2.last_confirmed_scan_run_id
	         WHERE ` + c.alias + `.provider <> 'aws' AND s2.workspace_id = ` + c.alias + `.workspace_id
	           AND s2.` + c.supportCol + ` = ` + c.alias + `.id AND s2.state <> 'ended') asof ON true`
}

// attr is a provider_attrs text value, ” when absent or null.
func (c *inventoryClass) attr(key string) string {
	return `COALESCE(` + c.alias + `.provider_attrs->>'` + key + `', '')`
}

func (c *inventoryClass) isAWS() string { return c.alias + `.provider = 'aws'` }

// scopeIDSQL is the row's scope id: the AWS account, or provider_attrs
// scope_id. ” when it has none. No bind variables.
func (c *inventoryClass) scopeIDSQL() string {
	return `(CASE WHEN ` + c.isAWS() + ` THEN ` + c.awsScope + ` ELSE ` + c.attr("scope_id") + ` END)`
}

func (c *inventoryClass) scopeKindSQL() string {
	return `(CASE WHEN ` + c.isAWS() + ` THEN (CASE WHEN ` + c.awsScope + ` <> '' THEN '` + inventoryScopeAWSAccount + `' ELSE '' END)
              ELSE ` + c.attr("scope_kind") + ` END)`
}

// scopeLabelSQL is a k8s or github row's scope_label; an AWS account is
// labelled from its connector after the read.
func (c *inventoryClass) scopeLabelSQL() string {
	return `(CASE WHEN ` + c.isAWS() + ` THEN '' ELSE ` + c.attr("scope_label") + ` END)`
}

func (c *inventoryClass) subScopeSQL() string {
	return `(CASE WHEN ` + c.isAWS() + ` THEN ` + c.awsSubScope + ` ELSE ` + c.attr("sub_scope") + ` END)`
}

// nativeSQL is the row's native id, computed in SQL so q matches exactly what
// the row shows:
//
//	aws     the source key's native segment, as NativeOfKey reads it: the ARN of
//	        a workload or identity, the reference text of a resource
//	k8s     provider_attrs.native_id when the projection states one, else the
//	        key's segments after k8s␟<cluster>␟<type>, joined by "/" --
//	        namespace/name, or name for a cluster-scoped object
//	github  provider_attrs.native_id when stated, else the key's last segment
//
// The separator (chr(31), igagraph.Sep) cannot occur in any segment.
func (c *inventoryClass) nativeSQL() string {
	a := c.alias
	last := `regexp_replace(` + a + `.source_key, '^.*' || chr(31), '')`
	return `(CASE WHEN ` + c.isAWS() + ` THEN ` + last + `
              WHEN ` + c.attr("native_id") + ` <> '' THEN ` + c.attr("native_id") + `
              WHEN ` + a + `.provider = 'k8s' THEN COALESCE(NULLIF(array_to_string((string_to_array(` + a + `.source_key, chr(31)))[4:], '/'), ''), ` + last + `)
              ELSE ` + last + ` END)`
}

// readable is the base predicate every page, total and facet applies: this
// workspace, the three providers, no legacy GitHub row, and at least one
// support row that has not ended, from any source.
func (c *inventoryClass) readable(ws uuid.UUID) listsFilter {
	a := c.alias
	return listsFilter{sql: a + `.workspace_id = ? AND ` + a + `.provider IN ?
	   AND NOT (` + a + `.provider = 'github' AND ` + a + `.source_key = '')
	   AND EXISTS (SELECT 1 FROM iga_object_support s0
	                WHERE s0.workspace_id = ` + a + `.workspace_id AND s0.` + c.supportCol + ` = ` + a + `.id
	                  AND s0.state <> 'ended')`,
		args: []any{ws, InventoryProviders}}
}

/* --------------------------------- engine ---------------------------------- */

// inventoryRun is one inventory list request. Parameters (400) are checked,
// and the cursor opened, before the snapshot is.
func inventoryRun(ctx context.Context, r *Reader, vals url.Values, c *inventoryClass) (any, error) {
	ws := workspaceIn(ctx)
	for name := range vals {
		if !inventoryParams[name] {
			return nil, InvalidParameter(name, fmt.Sprintf("%s is not a parameter of this list", name))
		}
	}
	if s := vals.Get("sort"); s != "" && !contains(inventorySorts, s) {
		return nil, InvalidParameter("sort", "sort must be name or -last_seen")
	}
	p, perr := ParseListParams(vals, []string{"name", "last_seen"}, "name", inventoryFacetNames)
	if perr != nil {
		return nil, perr
	}
	if vals.Get("limit") == "" {
		p.Limit = InventoryDefaultLimit
	}
	filters, req, perr := c.filters(p, ws)
	if perr != nil {
		return nil, perr
	}
	spec := c.spec
	keys := spec.keys[p.SortKey]
	filterHash := FilterHash(vals)

	var after *listsAfter
	if p.Cursor != "" {
		cur, cerr := r.OpenCursor(p.Cursor, CursorContext{WS: ws, Route: c.route, Filter: filterHash, Sort: p.SortString()})
		if cerr != nil {
			return nil, cerr
		}
		if after, perr = listsDecodeCursor(cur, keys); perr != nil {
			return nil, perr
		}
	}

	var out Envelope
	// No publication pin: Kubernetes and GitHub publish no revisions, so the
	// snapshot is the consistency unit.
	err := r.Read(ctx, Pin{}, func(q *Query) error {
		meta := InventoryMeta{Limit: p.Limit}
		accts, err := q.LoadAccounts()
		if err != nil {
			return err
		}

		// THE PAGE: one mandatory statement.
		sqlText, args := listsPageSQL(spec, filters, keys, p.Desc, after, p.Limit)
		var recs []inventoryRecord
		if err := q.DB().Raw(sqlText, args...).Scan(&recs).Error; err != nil {
			return err
		}
		if len(recs) > p.Limit {
			recs = recs[:p.Limit]
			last := recs[len(recs)-1]
			var key listsCursorKey
			for _, k := range last.sortKeys()[:len(keys)] {
				if k == nil {
					return fmt.Errorf("igaread: %s page returned a NULL sort key", c.route)
				}
				key.K = append(key.K, *k)
			}
			raw, err := json.Marshal(key)
			if err != nil {
				return err
			}
			tok := r.SignCursor(Cursor{WS: ws, Route: c.route, Filter: filterHash,
				Sort: p.SortString(), Key: raw, ID: last.ID})
			meta.NextCursor = &tok
		}
		data := make([]InventoryRow, 0, len(recs))
		for _, rec := range recs {
			row, err := rec.row(c.refType, accts, q.Rev)
			if err != nil {
				return err
			}
			data = append(data, row)
		}

		// Total and facets: optional, over every filter (facets: every OTHER).
		n, known, err := q.CountUpTo(c.countQuery(filters))
		if err != nil {
			return err
		}
		var total ListMeta
		total.SetTotal(n, known)
		meta.TotalKnown, meta.Total, meta.TotalAtLeast = total.TotalKnown, total.Total, total.TotalAtLeast
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
		pub, err := inventoryPublication(q, accts, req, []*inventoryClass{c}, [][]listsFilter{filters})
		if err != nil {
			return err
		}
		meta.InventoryPublication = pub
		out = Envelope{Data: data, Meta: meta}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// countQuery is the unpaged query the list's total, and the summary's count of
// this class, are taken over: the count FROM under every filter.
func (c *inventoryClass) countQuery(filters []listsFilter) func(tx *gorm.DB) *gorm.DB {
	return func(tx *gorm.DB) *gorm.DB {
		w, wargs := listsWhere(filters, "")
		return tx.Table(c.spec.countFrom).Where(w, wargs...)
	}
}

// inventoryRequest is what the validated parameters selected, for the
// publication state: the providers, scope ids and kinds asked for (empty =
// all).
type inventoryRequest struct {
	providers, scopes, kinds []string
}

// filters turns the validated parameters into SQL filters. provider must be
// one of InventoryProviders; kind and scope take any value (an unknown one is
// an empty list, not an error: kinds and scopes are data, not an enum). Each
// is tagged with its facet, so that facet's counts leave it out. The
// summary builds its three counts from these same filters, so a count and the
// total of its list cannot disagree.
func (c *inventoryClass) filters(p *ListParams, ws uuid.UUID) ([]listsFilter, *inventoryRequest, *Error) {
	fs := []listsFilter{c.readable(ws)}
	fs = append(fs, listsLifecycle(p, c.alias+".lifecycle")...)
	if p.Q != "" {
		like := "%" + EscapeLike(p.Q) + "%"
		fs = append(fs, listsFilter{
			sql:  `lower(` + c.alias + `.display_name) LIKE lower(?) ESCAPE '\' OR lower(` + c.nativeSQL() + `) LIKE lower(?) ESCAPE '\'`,
			args: []any{like, like},
		})
	}
	providers, perr := listsEnum(p, "provider", InventoryProviders...)
	if perr != nil {
		return nil, nil, perr
	}
	req := &inventoryRequest{providers: providers, scopes: inventoryValues(p, "scope"), kinds: inventoryValues(p, "kind")}
	fs = append(fs, listsIn("provider", c.alias+".provider", providers)...)
	fs = append(fs, listsIn("kind", c.kindCol, req.kinds)...)
	fs = append(fs, listsIn("scope", c.scopeIDSQL(), req.scopes)...)
	return fs, req, nil
}

// inventoryValues reads a repeatable free-text filter: trimmed, empty values
// dropped, repeats folded. Repeated values are alternatives (OR).
func inventoryValues(p *ListParams, param string) []string {
	var out []string
	for _, v := range p.Raw[param] {
		if v = strings.TrimSpace(v); v != "" && !contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

/* ---------------------------------- facets --------------------------------- */

var inventoryProviderLabels = map[string]string{
	models.ProviderAWS:    "AWS",
	models.ProviderK8s:    "Kubernetes",
	models.ProviderGitHub: "GitHub",
}

// inventoryKindLabels names the kinds the contract lists; any other kind is
// its own label.
var inventoryKindLabels = map[string]string{
	models.WorkloadLambdaFunction:       "Lambda function",
	models.WorkloadECSTaskDefinition:    "ECS task definition",
	models.WorkloadEC2Instance:          "EC2 instance",
	models.WorkloadBedrockAgent:         "Bedrock agent",
	models.WorkloadBedrockAgentCoreRT:   "AgentCore runtime",
	models.WorkloadBedrockAgentCoreGW:   "AgentCore gateway",
	models.CloudIdentityIAMRole:         "IAM role",
	models.CloudIdentityIAMUser:         "IAM user",
	models.CloudIdentityIAMGroup:        "IAM group",
	"k8s_deployment":                    "Kubernetes Deployment",
	"k8s_statefulset":                   "Kubernetes StatefulSet",
	"k8s_daemonset":                     "Kubernetes DaemonSet",
	"k8s_cronjob":                       "Kubernetes CronJob",
	"k8s_job":                           "Kubernetes Job",
	"k8s_pod":                           "Kubernetes Pod",
	"k8s_workload":                      "Kubernetes workload",
	models.K8sAccountKindServiceAccount: "Kubernetes service account",
	"k8s_user":                          "Kubernetes user",
	"k8s_group":                         "Kubernetes group",
	"github_copilot_agent":              "GitHub Copilot agent",
	"github_actions_workflow":           "GitHub Actions workflow",
	"github_declared_agent":             "Declared agent (GitHub)",
	"github_app_installation":           "GitHub App installation",
	"github_deploy_key":                 "GitHub deploy key",
	"github_repository":                 "GitHub repository",
}

// inventoryScopeFacet folds the scope facet's id ␟ kind ␟ label groups into one
// chip per scope id (the value the scope filter takes), labelled as the rows
// are. Rows with no scope have no chip.
func inventoryScopeFacet(counts map[string]int64, accts *Accounts) []FacetValue {
	byID := map[string]*FacetValue{}
	for v, n := range counts {
		parts := strings.SplitN(v, "\x1f", 3)
		if len(parts) != 3 || parts[0] == "" {
			continue
		}
		id, kind, label := parts[0], parts[1], parts[2]
		if kind == inventoryScopeAWSAccount {
			label = accts.Of(id).Label
		}
		fv := byID[id]
		if fv == nil {
			fv = &FacetValue{Value: id}
			byID[id] = fv
		}
		fv.Count += n
		if fv.Label == "" || (label != "" && label < fv.Label) {
			fv.Label = label // deterministic when two rows disagree
		}
	}
	out := make([]FacetValue, 0, len(byID))
	for _, fv := range byID {
		if fv.Label == "" {
			fv.Label = fv.Value
		}
		out = append(out, *fv)
	}
	return listsFacetOrder(out, "")
}

/* --------------------------------- summary --------------------------------- */

// InventorySummary is GET /api/iga/v1/inventory/summary (B2): one count per
// object type for the same filters as the three lists, in one snapshot.
type InventorySummary struct {
	Workloads  Exact `json:"workloads"`
	Identities Exact `json:"identities"`
	Resources  Exact `json:"resources"`
}

// InventorySummary serves GET /api/iga/v1/inventory/summary.
//
// The parameters are provider, scope, q and lifecycle (anything else is 400
// invalid_parameter), validated and turned into SQL by the lists' own filter
// builder, and each count is the list's total over the same FROM
// (countQuery) -- so a count and the total of its list cannot disagree. Each
// is counted with CountUpTo, the graph lists' capped, savepointed count: an
// exact value up to TotalCap, {value: TotalCap, exact: false} above it, and
// {value: null, exact: false} when that one count timed out -- the other two
// are unaffected. One REPEATABLE READ snapshot, one request deadline.
func (r *Reader) InventorySummary(ctx context.Context, vals url.Values) (any, error) {
	ws := workspaceIn(ctx)
	for name := range vals {
		if !inventorySummaryParams[name] {
			return nil, InvalidParameter(name, fmt.Sprintf("%s is not a parameter of this route", name))
		}
	}
	p, perr := ParseListParams(vals, []string{"name"}, "name", nil)
	if perr != nil {
		return nil, perr
	}
	classes := []*inventoryClass{inventoryWorkloads, inventoryIdentities, inventoryResources}
	filters := make([][]listsFilter, len(classes))
	var req *inventoryRequest
	for i, c := range classes {
		if filters[i], req, perr = c.filters(p, ws); perr != nil {
			return nil, perr
		}
	}

	var out Envelope
	err := r.Read(ctx, Pin{}, func(q *Query) error {
		accts, err := q.LoadAccounts()
		if err != nil {
			return err
		}
		var counts [3]Exact
		for i, c := range classes {
			n, known, err := q.CountUpTo(c.countQuery(filters[i]))
			if err != nil {
				return err
			}
			counts[i] = inventoryExact(n, known)
		}
		pub, err := inventoryPublication(q, accts, req, classes, filters)
		if err != nil {
			return err
		}
		out = Envelope{
			Data: InventorySummary{Workloads: counts[0], Identities: counts[1], Resources: counts[2]},
			Meta: pub,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// inventoryExact is a CountUpTo result as an ExactCount, by the rule
// ListMeta.SetTotal applies to a list's total: known and within TotalCap is
// exact; beyond it the cap is a lower bound; a timeout is unknown (null).
func inventoryExact(n int64, known bool) Exact {
	switch {
	case !known:
		return Unknown()
	case n > TotalCap:
		return Exact{Value: ptrInt64(TotalCap), Exact: false}
	default:
		return ExactOf(n)
	}
}

/* ----------------------------- publication state ---------------------------- */

// The graph states an inventory result can be in (meta.graph_state). published
// and not_published are the graph lists' own (GraphPublished,
// GraphNotPublished).
const (
	inventoryUnrevisioned = "unrevisioned"
	inventoryMixed        = "mixed"
)

// inventoryPublication is the meta every inventory response carries: the AWS
// publication current in the snapshot, the graph state of the filtered result
// and the coverage notes. classes and filters are parallel: one entry for a
// list, the three classes for the summary.
func inventoryPublication(q *Query, accts *Accounts, req *inventoryRequest, classes []*inventoryClass, filters [][]listsFilter) (InventoryPublication, error) {
	pub := InventoryPublication{Coverage: []InventoryCoverageNote{}}
	if q.Rev != nil {
		rev, at := q.Rev.Rev, PublicationTime(q.Rev.PublishedAt)
		pub.Rev, pub.PublishedAt = &rev, &at
	}
	var err error
	if pub.GraphState, err = inventoryGraphState(q, req, classes, filters); err != nil {
		return pub, err
	}
	aws, err := inventoryAWSNotes(q, accts, req, classes)
	if err != nil {
		return pub, err
	}
	k8s, err := inventoryK8sNotes(q, req)
	if err != nil {
		return pub, err
	}
	pub.Coverage = append(append(pub.Coverage, aws...), k8s...)
	return pub, nil
}

// inventoryGraphState is meta.graph_state, computed over the FILTERED result --
// the rows every filter leaves, not the page in hand:
//
//	published      every row is an AWS row and a publication exists
//	unrevisioned   no row is an AWS row (Kubernetes and GitHub only)
//	mixed          both kinds
//	not_published  AWS rows are selected and no publication exists
//
// How: at most one EXISTS statement per class, each probing "any AWS row" and
// "any other row" over the class's count FROM and filters -- so a result
// proves its kinds on the first matching row instead of counting, and the
// provider filter rules out a probe that cannot match without running it.
// The cost is bounded by the same index (workspace, provider, lifecycle) the
// total uses; an empty result scans no more than the count would. Probes are
// optional work (a savepoint, like the total): if one times out the state is
// unknown and omitted (nil), never guessed.
//
// An empty result has no rows to ask, so the filter's intent decides: AWS
// only -> published / not_published by the publication; Kubernetes / GitHub
// only -> unrevisioned; both selected -> the publication's state.
func inventoryGraphState(q *Query, req *inventoryRequest, classes []*inventoryClass, filters [][]listsFilter) (*string, error) {
	awsPossible := len(req.providers) == 0 || contains(req.providers, models.ProviderAWS)
	otherPossible := len(req.providers) == 0
	for _, v := range req.providers {
		otherPossible = otherPossible || v != models.ProviderAWS
	}

	var hasAWS, hasOther bool
	for i, c := range classes {
		needAWS, needOther := awsPossible && !hasAWS, otherPossible && !hasOther
		if !needAWS && !needOther {
			break
		}
		w, wargs := listsWhere(filters[i], "")
		probe := func(need bool, cond string, args *[]any) string {
			if !need {
				return "false"
			}
			*args = append(*args, wargs...)
			return "EXISTS (SELECT 1 FROM " + c.spec.countFrom + " WHERE " + w + " AND " + c.alias + ".provider " + cond + ")"
		}
		var args []any
		sqlText := "SELECT " + probe(needAWS, "= 'aws'", &args) + ", " + probe(needOther, "<> 'aws'", &args)
		var a, o bool
		ok, err := q.Optional(func(tx *gorm.DB) error {
			return tx.Raw(sqlText, args...).Row().Scan(&a, &o)
		})
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, nil
		}
		hasAWS, hasOther = hasAWS || a, hasOther || o
	}

	awsState := GraphNotPublished
	if q.Rev != nil {
		awsState = GraphPublished
	}
	state := awsState
	switch {
	case hasAWS && hasOther:
		state = inventoryMixed
	case hasAWS:
	case hasOther, !awsPossible:
		state = inventoryUnrevisioned
	}
	return &state, nil
}

// inventoryAWSNotes are the graph lists' coverage notes (listsCoverage) for
// the AWS accounts the request selects: every account of the workspace when
// no scope is chosen, only the chosen account ids when one is; none when the
// provider filter or the scope leaves AWS out. The summary spans three
// classes, so a surface that bears on several is one note whose affects names
// each, in class order.
func inventoryAWSNotes(q *Query, accts *Accounts, req *inventoryRequest, classes []*inventoryClass) ([]InventoryCoverageNote, error) {
	if len(req.providers) > 0 && !contains(req.providers, models.ProviderAWS) {
		return nil, nil
	}
	var accounts []string
	for _, v := range req.scopes {
		if isAccountID(v) {
			accounts = append(accounts, v)
		}
	}
	if len(req.scopes) > 0 && len(accounts) == 0 {
		return nil, nil // the scope names only non-AWS scopes
	}

	type key struct{ account, surface string }
	merged := map[key]*InventoryCoverageNote{}
	var order []key
	for _, c := range classes {
		notes, err := listsCoverage(q, accts, c.list, listsScope{accounts: accounts, kinds: req.kinds})
		if err != nil {
			return nil, err
		}
		for _, n := range notes {
			k := key{n.AccountID, n.Surface}
			if prev := merged[k]; prev != nil {
				if !strings.Contains(prev.Affects, n.Affects) {
					prev.Affects += "; " + n.Affects
				}
				continue
			}
			n := n
			merged[k] = &InventoryCoverageNote{CoverageNote: n}
			order = append(order, k)
		}
	}
	out := make([]InventoryCoverageNote, 0, len(order))
	for _, k := range order {
		out = append(out, *merged[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].AccountID != out[j].AccountID {
			return out[i].AccountID < out[j].AccountID
		}
		return out[i].Surface < out[j].Surface
	})
	return out, nil
}

// inventoryK8sSurface is a Kubernetes note's surface: the cluster's sweep.
const inventoryK8sSurface = "k8s_sweep"

// inventoryK8sNotes is one note per Kubernetes cluster in scope, from its
// latest APPLIED sweep (k8sread.LatestProjectedSweeps, the vocabulary and logic k8sread owns):
// state complete | namespaced_only | incomplete, or not_swept for a cluster
// whose agent registered and never delivered one. account_id is the cluster
// name -- the scope.id its rows carry. The scope filter narrows to the chosen
// clusters; the provider filter can leave Kubernetes out. Two agents reporting
// one cluster name are one scope: the newest sweep speaks for it.
func inventoryK8sNotes(q *Query, req *inventoryRequest) ([]InventoryCoverageNote, error) {
	if len(req.providers) > 0 && !contains(req.providers, models.ProviderK8s) {
		return nil, nil
	}
	kq := k8sread.New(q.DB(), q.WS)
	sweeps, err := kq.LatestSweeps()
	if err != nil {
		return nil, err
	}
	// The note describes the rows, and the rows come from the newest sweep that
	// was APPLIED. A newer sweep that arrived and was not applied (or failed to
	// apply) says nothing about them, so it does not speak here; a cluster with
	// no applied sweep has no rows and reads not_swept.
	projected, err := kq.LatestProjectedSweeps()
	if err != nil {
		return nil, err
	}
	byCluster := map[string]InventoryCoverageNote{}
	for _, cs := range sweeps {
		if len(req.scopes) > 0 && !contains(req.scopes, cs.Cluster) {
			continue
		}
		state, observed := k8sread.CoverageNone, (*time.Time)(nil)
		if sw, ok := projected[k8sread.SweepKey{SourceID: cs.SourceID, Cluster: cs.Cluster}]; ok {
			at := sw.ObservedAt.UTC().Truncate(time.Second)
			state, observed = sw.Coverage, &at
		}
		note := InventoryCoverageNote{
			CoverageNote: CoverageNote{AccountID: cs.Cluster, Surface: inventoryK8sSurface, State: state, Affects: k8sread.Affects(state)},
			ObservedAt:   observed,
		}
		if prev, ok := byCluster[cs.Cluster]; ok && !inventoryNewer(note.ObservedAt, prev.ObservedAt) {
			continue
		}
		byCluster[cs.Cluster] = note
	}
	out := make([]InventoryCoverageNote, 0, len(byCluster))
	for _, n := range byCluster {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AccountID < out[j].AccountID })
	return out, nil
}

// inventoryNewer reports whether a is a later sweep than b; a sweep beats none.
func inventoryNewer(a, b *time.Time) bool {
	switch {
	case a == nil:
		return false
	case b == nil:
		return true
	default:
		return a.After(*b)
	}
}
