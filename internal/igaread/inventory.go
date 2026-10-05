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
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

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

// inventorySorts are the sort values: by name (then id), or most recently
// seen first (then id, descending).
var inventorySorts = []string{"name", "-last_seen"}

var inventoryFacetNames = []string{"provider", "kind", "scope"}

// ListInventoryWorkloads serves GET /api/iga/v1/inventory/workloads.
func (r *Reader) ListInventoryWorkloads(ctx context.Context, ws uuid.UUID, vals url.Values) (any, error) {
	return inventoryRun(ctx, r, ws, vals, inventoryWorkloads)
}

// ListInventoryIdentities serves GET /api/iga/v1/inventory/identities.
func (r *Reader) ListInventoryIdentities(ctx context.Context, ws uuid.UUID, vals url.Values) (any, error) {
	return inventoryRun(ctx, r, ws, vals, inventoryIdentities)
}

// ListInventoryResources serves GET /api/iga/v1/inventory/resources.
func (r *Reader) ListInventoryResources(ctx context.Context, ws uuid.UUID, vals url.Values) (any, error) {
	return inventoryRun(ctx, r, ws, vals, inventoryResources)
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
}

// InventoryMeta is an inventory list's meta: the graph lists' paging, total
// and facets, without their revision and coverage (nothing here is pinned to
// a publication).
type InventoryMeta struct {
	Limit        int                     `json:"limit"`
	NextCursor   *string                 `json:"next_cursor"`
	TotalKnown   bool                    `json:"total_known"`
	Total        *int64                  `json:"total,omitempty"`
	TotalAtLeast *int64                  `json:"total_at_least,omitempty"`
	Facets       map[string][]FacetValue `json:"facets,omitempty"`
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
func (s inventoryRecord) row(refType string, accts *Accounts) (InventoryRow, error) {
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
	return InventoryRow{
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
	alias   string
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
		route: inventoryRouteWorkloads, refType: RefWorkload, alias: "w",
		from: `iga_workload w
  LEFT JOIN iga_estate_scopes es ON es.workspace_id = w.workspace_id AND es.id = w.estate_scope_id`,
		kindCol: "w.runtime_kind", supportCol: "workload_id",
		awsScope: WorkloadAccountSQL, awsSubScope: "w.region",
	})
	inventoryIdentities = newInventoryClass(inventoryClass{
		route: inventoryRouteIdentities, refType: RefIdentity, alias: "ia",
		from:    `iga_identity_accounts ia`,
		kindCol: "ia.account_kind", supportCol: "identity_account_id",
		// IAM is global: an AWS identity has an account and no region.
		awsScope: IdentityAccountSQL, awsSubScope: "''",
	})
	inventoryResources = newInventoryClass(inventoryClass{
		route: inventoryRouteResources, refType: RefResource, alias: "r",
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
       ` + a + `.first_seen_at, ` + a + `.last_seen_at, ` + a + `.provider_attrs`
	c.spec = &listsSpec[inventoryRecord]{
		route:   c.route,
		columns: columns,
		// SupportLateral is the graph lists' D-1 state: current if any support
		// row is current, else stale if any is stale. Every listed row has a
		// non-ended support row, so it is never ended here.
		from:      c.from + "\n  " + SupportLateral(a, c.supportCol),
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
func inventoryRun(ctx context.Context, r *Reader, ws uuid.UUID, vals url.Values, c *inventoryClass) (any, error) {
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
	filters, perr := c.filters(p, ws)
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
	err := r.Read(ctx, ws, Pin{}, func(q *Query) error {
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
			row, err := rec.row(c.refType, accts)
			if err != nil {
				return err
			}
			data = append(data, row)
		}

		// Total and facets: optional, over every filter (facets: every OTHER).
		n, known, err := q.CountUpTo(func(tx *gorm.DB) *gorm.DB {
			w, wargs := listsWhere(filters, "")
			return tx.Table(spec.countFrom).Where(w, wargs...)
		})
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
		out = Envelope{Data: data, Meta: meta}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// filters turns the validated parameters into SQL filters. provider must be
// one of InventoryProviders; kind and scope take any value (an unknown one is
// an empty list, not an error: kinds and scopes are data, not an enum). Each
// is tagged with its facet, so that facet's counts leave it out.
func (c *inventoryClass) filters(p *ListParams, ws uuid.UUID) ([]listsFilter, *Error) {
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
		return nil, perr
	}
	fs = append(fs, listsIn("provider", c.alias+".provider", providers)...)
	fs = append(fs, listsIn("kind", c.kindCol, inventoryValues(p, "kind"))...)
	fs = append(fs, listsIn("scope", c.scopeIDSQL(), inventoryValues(p, "scope"))...)
	return fs, nil
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
