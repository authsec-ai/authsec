package igaread

// Traversal (SPEC-iga-phase2-graph.md §5.3 Graph, §5.4; T6.4): GET /graph,
// /graph/expand and /graph/path.
//
// The traversal graph (§5.4) has five node types -- workloads, identities,
// external principals, statements and resource references -- and six edge
// kinds, each with a direction:
//
//	executes_as, task_execution_role  workload -> identity
//	member_of                         user -> group
//	can_assume                        principal -> role (who may assume it -> the role)
//	grant                             identity -> statement (Allow only)
//	target                            statement -> resource (mode = resource ONLY)
//
// A NotResource entry is an exclusion, never an edge in either direction: it
// is returned on its statement node as `exclusions`. Deny statements and
// boundaries are not edges either: identity nodes carry `restrictions`, and
// every path through a restricted node carries the matching limitation.
//
// The algorithm is §5.4's, in Go, inside the request's §5.1 snapshot: an
// iterative breadth-first search in which every LEVEL issues one query per
// edge kind for the whole frontier (traverse_edges.go), ordered by (edge kind,
// target source_key, id), then one query per node type for the nodes it
// reached (traverse_nodes.go). There is no recursive CTE: per-level batching
// lets the server stop exactly at a budget and describe the frontier it
// stopped at. Each level runs in a savepoint (Query.Optional), so a level that
// runs out of time is rolled back and the earlier levels are returned as
// `truncated: {bound_by: "time"}` (§5.1, B23, D-40) -- a controlled answer,
// never a 504. Only the root is mandatory.
//
// The server never states a completeness it did not establish (§5.4
// "Continuation", B17): a bound budget always shows as `truncated`, a frontier
// `more` count is exact only when it was counted inside the budget, and
// /graph/path says none_exists only when both frontiers were exhausted before
// any budget bound (D-38).

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

	"github.com/authsec-ai/authsec/models"
)

/* -------------------------------- vocabulary ------------------------------- */

// graphNodeTypes are the reference types a traversal may start from or reach
// (§5.4 "The traversal graph", D-39), in the order a level reads them. A
// policy is not a traversal node (its statements are), and a claim is not a
// node at all: either as a root is 400.
var graphNodeTypes = []string{RefWorkload, RefIdentity, RefExternalPrincipal, RefStatement, RefResource}

// Edge kinds (§5.4). The claim behind each: relationship (the first four and
// can_assume), grant, target.
const (
	GraphEdgeCanAssume         = models.RelTypeCanAssume
	GraphEdgeExecutesAs        = models.RelTypeExecutesAs
	GraphEdgeGrant             = "grant"
	GraphEdgeMemberOf          = models.RelTypeMemberOf
	GraphEdgeTarget            = "target"
	GraphEdgeTaskExecutionRole = models.RelTypeTaskExecutionRole
)

// graphEdgeKinds is the order a level issues its queries in: lexical, so a
// level's edges come out ordered by (edge kind, target source_key, id) exactly
// as §5.4 requires, and the same request always returns the same response.
var graphEdgeKinds = []string{
	GraphEdgeCanAssume, GraphEdgeExecutesAs, GraphEdgeGrant,
	GraphEdgeMemberOf, GraphEdgeTarget, GraphEdgeTaskExecutionRole,
}

// Directions (§5.4): forward answers "what can this reach, declared"; reverse
// "what reaches this".
const (
	GraphForward = "forward"
	GraphReverse = "reverse"
)

// Budget names, as truncated.bound_by and /graph/path's bound_by say them
// (§5.4 "Continuation"). paths is /graph/path's own: the path budget bound.
const (
	GraphBoundNodes      = "nodes"
	GraphBoundEdges      = "edges"
	GraphBoundAssumeHops = "assume_hops"
	GraphBoundTime       = "time"
	GraphBoundPaths      = "paths"
	// GraphBoundResolution is /graph/path's answer when the search did not
	// look through an external principal's resolution IN FORCE that could
	// connect the two ends (§2.12): the principal is terminal (§5.4), so the
	// path is not drawn -- and "none exists" would claim more than was
	// searched. /graph/path ONLY: §5.4's outcome table has no other way to
	// say it (D-105, raised). /graph never puts it in truncated -- nothing
	// bound -- and says it in resolution_not_followed instead.
	GraphBoundResolution = "resolution_not_followed"
)

// graphResolutionActive is iga_external_principal.resolution_state for a
// resolution in force (034); suspended and pending_reconfirmation are not.
const graphResolutionActive = "active"

/* --------------------------------- budgets --------------------------------- */

// GraphBudgets are the HARD per-request server budgets of §5.4 -- not the
// console's display defaults (150 nodes drawn, 2 assume hops). Time is the
// reader's request deadline (§5.1), with D-40's reserve.
type GraphBudgets struct {
	Nodes      int // nodes in one response
	Edges      int // edges in one response
	AssumeHops int // the ceiling on /graph's assume_hops, and /graph/path's hop limit
	Paths      int // paths /graph/path returns
	Neighbours int // neighbours per /graph/expand page
}

// DefaultGraphBudgets is §5.4's table. Production always uses it; tests reach
// the others through Reader.TraversalWith.
var DefaultGraphBudgets = GraphBudgets{Nodes: 500, Edges: 2000, AssumeHops: 4, Paths: 200, Neighbours: 100}

// DefaultAssumeHops is /graph's assume_hops when the request names none: the
// display default (§5.4, D-34), a starting depth -- never a ceiling on
// expansion, which is a new request from the frontier.
const DefaultAssumeHops = 2

// graphReserve is D-40's time reserve: the traverser does not START a level
// when less than a quarter of the request budget, and never less than 250 ms,
// remains -- so a traversal that ran long still has the time to render what
// it has (§5.1 "stops while it still has time to answer").
func graphReserve(budget time.Duration) time.Duration {
	r := budget / 4
	if r < 250*time.Millisecond {
		r = 250 * time.Millisecond
	}
	return r
}

// GraphTraversal serves the three traversal routes under one set of budgets.
type GraphTraversal struct {
	r *Reader
	b GraphBudgets
}

// Traversal is the production traversal: DefaultGraphBudgets under the
// reader's request budget.
func (r *Reader) Traversal() *GraphTraversal { return &GraphTraversal{r: r, b: DefaultGraphBudgets} }

// TraversalWith is the test seam: the same traversal under other budgets, so a
// test can make a node, edge, hop or path budget bind on a small fixture.
func (r *Reader) TraversalWith(b GraphBudgets) *GraphTraversal { return &GraphTraversal{r: r, b: b} }

// Graph serves GET /graph with the production budgets.
func (r *Reader) Graph(ctx context.Context, ws uuid.UUID, vals url.Values) (any, error) {
	return r.Traversal().Graph(ctx, ws, vals)
}

// ExpandGraph serves GET /graph/expand with the production budgets.
func (r *Reader) ExpandGraph(ctx context.Context, ws uuid.UUID, vals url.Values) (any, error) {
	return r.Traversal().Expand(ctx, ws, vals)
}

// GraphPath serves GET /graph/path with the production budgets.
func (r *Reader) GraphPath(ctx context.Context, ws uuid.UUID, vals url.Values) (any, error) {
	return r.Traversal().Path(ctx, ws, vals)
}

/* ------------------------------ response shapes ---------------------------- */

// GraphNode is one node of a traversal response (§5.3 Graph): {ref, kind,
// label, account, state} plus what its type carries. Fields a type does not
// have are omitted.
type GraphNode struct {
	Ref   string `json:"ref"`
	Kind  string `json:"kind"`
	Label string `json:"label"`
	// Account is {id, label, connected}, or null for Unknown account; it is
	// absent on statements, which have no account (D-36).
	Account         any            `json:"account,omitempty"`
	State           string         `json:"state"`
	Lifecycle       string         `json:"lifecycle,omitempty"`
	LastConfirmedAt any            `json:"last_confirmed_at"`
	StaleReason     *[]StaleReason `json:"stale_reason,omitempty"`

	// Workloads and identities.
	ARN         string `json:"arn,omitempty"`
	RuntimeKind string `json:"runtime_kind,omitempty"`

	// Identities: Deny statements and boundaries are not edges (§5.4); the
	// node carries them, holder-level (D-78). used_by_count is the list's
	// count, by the same function (§2.14.11 "a count on the identity node").
	Restrictions *GraphRestrictions `json:"restrictions,omitempty"`
	UsedByCount  *Exact             `json:"used_by_count,omitempty"`

	// External principals (§2.12, D-87).
	Mechanism  string         `json:"mechanism,omitempty"`
	Issuer     string         `json:"issuer,omitempty"`
	Subject    string         `json:"subject,omitempty"`
	Resolution map[string]any `json:"resolution,omitempty"`

	// Statements: the policy that declares it, its group_key (D-37) and its
	// NotResource exclusions -- never edges (§5.4). sid is always stated on a
	// statement, "" when it has none (§5.3's grant line: "sid": ""), never
	// absent (D-98); other node types have no sid.
	Policy     string            `json:"policy,omitempty"`
	PolicyRef  string            `json:"policy_ref,omitempty"`
	Effect     string            `json:"effect,omitempty"`
	Sid        *string           `json:"sid,omitempty"`
	Index      *int              `json:"index,omitempty"`
	GroupKey   string            `json:"group_key,omitempty"`
	Exclusions *[]GraphExclusion `json:"exclusions,omitempty"`

	// Resources: the reference text exactly as a statement wrote it, and its
	// typed kind (D-16).
	Text string `json:"text,omitempty"`
	Type string `json:"type,omitempty"`

	// Kubernetes nodes only (traverse_k8s.go), all additive and absent on
	// every AWS node, so an AWS response is what it always was. provider is
	// "k8s"; scope is the cluster ({kind: k8s_cluster, id, label}), sub_scope
	// the namespace (null for a cluster-scoped object), native_id the id a
	// person recognises (namespace/name) on workloads and identities -- the
	// unified inventory's own fields, read by its own expressions -- and
	// k8s_rule a statement's PolicyRule, verbatim. A Kubernetes node has no
	// account and no ARN: both are absent, as a statement's account is.
	Provider string         `json:"provider,omitempty"`
	Scope    *GraphScope    `json:"scope,omitempty"`
	SubScope *graphOptional `json:"sub_scope,omitempty"`
	NativeID string         `json:"native_id,omitempty"`
	K8sRule  *GraphK8sRule  `json:"k8s_rule,omitempty"`

	Limitations []GraphLimitation `json:"limitations"`

	provider  string // the node's provider (aws | k8s); "" for an external principal
	want      string // the provider the node is read as (aws | k8s); "" for a root: either
	typ       string
	id        uuid.UUID
	key       string // source_key
	acct      string // the node's own account id, "" when unknown
	connected bool   // its account is a connected account (D-3)

	stale          StaleSubject
	conditional    bool
	negated        bool
	text           statementText // statements: the verbatim statement, as /evidence parses it
	groupActions   []string      // statements: D-37's action half
	groupCondition string        // statements: the canonical Condition, "" for none
	notPrincipal   bool          // roles: the trust policy uses NotPrincipal (D-44)
	resolvedTo     string        // external principals: the target of a resolution IN FORCE (§2.12)
	policyKind     string        // Kubernetes statements: the role's policy_kind, for its grants
	// Identities: the Deny statements bearing on it as a holder (its own and
	// its live groups') and its OWN boundary policies, from loadRestrictions
	// -- the reader /evidence's grant limitations use (D-35).
	denyIDs          []uuid.UUID
	boundaryPolicies []uuid.UUID
	fetched          bool
}

// GraphRestrictions is an identity's restrictions (§5.4, D-78): how many Deny
// statements it holds -- directly or through its groups -- and whether it has
// a permissions boundary. Matching is not evaluated.
type GraphRestrictions struct {
	DenyStatements      int64 `json:"deny_statements"`
	PermissionsBoundary bool  `json:"permissions_boundary"`
}

// GraphExclusion is one NotResource entry of a statement: "all resources
// except <text>".
type GraphExclusion struct {
	Ref  string `json:"ref"`
	Text string `json:"text"`
}

// GraphEdge is one edge (§5.3 Graph): {claim, kind, from, to, state}, mode on
// targets, and closes_cycle / crosses_account on every edge. from and to are
// the claim's own endpoints, whichever direction it was traversed in.
type GraphEdge struct {
	Claim           string         `json:"claim"`
	Kind            string         `json:"kind"`
	From            string         `json:"from"`
	To              string         `json:"to"`
	State           string         `json:"state"`
	Mode            string         `json:"mode,omitempty"`
	Basis           string         `json:"basis"`
	Mechanism       string         `json:"mechanism,omitempty"`
	Policy          string         `json:"policy,omitempty"`
	ClosesCycle     bool           `json:"closes_cycle"`
	CrossesAccount  bool           `json:"crosses_account"`
	LastConfirmedAt any            `json:"last_confirmed_at"`
	StaleReason     *[]StaleReason `json:"stale_reason,omitempty"`

	// Kubernetes edges only, additive and absent on every AWS edge. provider
	// is "k8s". A Kubernetes grant names the binding it comes through and the
	// role whose rule it reaches -- "via RoleBinding X to Role Y" -- because
	// the binding, not the role, decides where the rule applies: a RoleBinding
	// of a ClusterRole grants its rules in the binding's namespace only.
	Provider   string           `json:"provider,omitempty"`
	PolicyRef  string           `json:"policy_ref,omitempty"`
	PolicyKind string           `json:"policy_kind,omitempty"`
	Assignment *GraphAssignment `json:"assignment,omitempty"`
	// EffectiveScope is where a Kubernetes grant's rule applies (D-109): the
	// binding's namespace for a RoleBinding -- of a Role or of a ClusterRole
	// alike -- and the cluster for a ClusterRoleBinding. The rule node's own
	// scope is its ROLE's, which for a ClusterRole is the cluster even when
	// every binding that reaches it is namespaced.
	EffectiveScope *GraphEffectiveScope `json:"effective_scope,omitempty"`
	// ImplicitMembership marks a Kubernetes member_of from a ServiceAccount
	// to a group the API server puts every ServiceAccount (or every
	// authenticated subject) in -- system:serviceaccounts,
	// system:serviceaccounts:<ns>, system:authenticated -- with no object
	// that declares it (D-110).
	ImplicitMembership bool `json:"implicit_membership,omitempty"`
	// The crossing (traverse_cross.go, D-108): a can_assume drawn from the
	// Kubernetes ServiceAccount an AWS trust's external principal resolves
	// to. crosses_provider is true; via_principal names the claim's declared
	// source; resolution is {basis, rule}. All absent on every other edge.
	CrossesProvider bool           `json:"crosses_provider,omitempty"`
	ViaPrincipal    string         `json:"via_principal,omitempty"`
	Resolution      map[string]any `json:"resolution,omitempty"`

	Limitations []GraphLimitation `json:"limitations"`

	side         string // the provider whose claim it is (aws | k8s); a crossing is aws's
	claimRef     Ref    // the claim, for Query.ClaimLimitations
	connectorID  *uuid.UUID
	partitionKey string
	// farCoverage: a crosses_account edge's far-account gaps (§5.4), the
	// graph's one addition to the claim's own limitations.
	farCoverage []GraphLimitation
}

// GraphMore is a frontier entry's count of neighbours the response does not
// contain: exact only when it was counted within the budget, else {count:
// null, exact: false} (§5.4) -- never a number that looks exact.
type GraphMore struct {
	Count *int64 `json:"count"`
	Exact bool   `json:"exact"`
}

// GraphFrontier is one node with unexpanded neighbours of one kind (§5.4
// "Continuation"), with the call that expands it.
type GraphFrontier struct {
	Node      string    `json:"node"`
	Edge      string    `json:"edge"`
	Direction string    `json:"direction"`
	More      GraphMore `json:"more"`
	Expand    string    `json:"expand"`
}

// GraphTruncated names the budget that bound (§5.4): nodes | edges |
// assume_hops | time, and nothing else -- null when none did. A resolution
// the walk did not follow is not a budget: GraphData.ResolutionNotFollowed
// says it (D-105).
type GraphTruncated struct {
	BoundBy string `json:"bound_by"`
}

// GraphData is /graph's data (§5.3 Graph).
type GraphData struct {
	Root      string          `json:"root"`
	Nodes     []*GraphNode    `json:"nodes"`
	Edges     []*GraphEdge    `json:"edges"`
	Frontier  []GraphFrontier `json:"frontier"`
	Truncated *GraphTruncated `json:"truncated"`
	// ResolutionNotFollowed is additive to §5.3's shape (D-105): true when
	// the walk passed an external principal's resolution IN FORCE (§2.12)
	// that it shows and does not walk (graphResolutionUnfollowed), so what
	// lies past it was not read; false when it passed none; null when that
	// was not established (the time budget bound first). It speaks of the
	// nodes this response holds, and never sets truncated: nothing bound.
	ResolutionNotFollowed *bool `json:"resolution_not_followed"`
}

// GraphExpandData is /graph/expand's data (D-35).
type GraphExpandData struct {
	Nodes      []*GraphNode    `json:"nodes"`
	Edges      []*GraphEdge    `json:"edges"`
	Frontier   []GraphFrontier `json:"frontier"`
	Truncated  *GraphTruncated `json:"truncated"`
	NextCursor *string         `json:"next_cursor"`
}

// GraphBudgetsMeta is meta.budgets: the hard budgets this response ran under
// (§5.3 example: nodes, edges, assume_hops, timeout_ms), plus the path and
// page budgets.
type GraphBudgetsMeta struct {
	Nodes      int   `json:"nodes"`
	Edges      int   `json:"edges"`
	AssumeHops int   `json:"assume_hops"`
	Paths      int   `json:"paths"`
	Neighbours int   `json:"neighbours_per_page"`
	TimeoutMS  int64 `json:"timeout_ms"`
}

// GraphMeta is the meta of every traversal response: the detail envelope's
// (a traversal answers about one object, never a one-row list; D-97
// capabilities, {} here), the budgets, and the limitations that hold for
// EVERY claim, stated once (D-35): effective access is never evaluated, and
// AWS Organizations is not collected.
type GraphMeta struct {
	DetailMeta
	Budgets     GraphBudgetsMeta  `json:"budgets"`
	Limitations []GraphLimitation `json:"limitations"`
}

// meta is a traversal response's meta, by the providers of the nodes the
// response holds: AWS only, as always;
// Kubernetes only, unrevisioned (graphK8sMeta); both -- a walk that crossed,
// or a /graph/path between the two -- mixed (graphMixedMeta).
func (g *GraphTraversal) meta(q *Query, t *graphTraversal) GraphMeta {
	m := GraphMeta{
		DetailMeta: NewDetailMeta(q),
		Budgets: GraphBudgetsMeta{
			Nodes: g.b.Nodes, Edges: g.b.Edges, AssumeHops: g.b.AssumeHops,
			Paths: g.b.Paths, Neighbours: g.b.Neighbours, TimeoutMS: g.r.budget.Milliseconds(),
		},
		Limitations: []GraphLimitation{
			{"code": graphLimEffectiveAccess},
			{"code": graphLimOrganizations},
		},
	}
	switch aws, k8s := t.sides(); {
	case aws && k8s:
		graphMixedMeta(&m)
	case k8s:
		graphK8sMeta(&m)
	}
	return m
}

// graphRevCheck applies a rev= parameter (§5.1) to a response that reads AWS
// rows: 409 when the snapshot's publication is not the one asked for. A
// Kubernetes root's response is not a publication's, and ignores it (D-111).
// It is checked in the snapshot it describes, after the root is read -- and
// before a 404 for a root that does not exist, as Read checked it before.
func graphRevCheck(q *Query, rev *int64) error {
	if rev != nil && (q.Rev == nil || q.Rev.Rev != *rev) {
		return RevisionStale(*rev, q.Rev)
	}
	return nil
}

/* -------------------------------- parameters ------------------------------- */

// graphCheckParams rejects any parameter the route does not define (400
// naming it, as the lists do, D-75) and any single-valued one given twice.
// account is accepted on every traversal route and repeatable: it applies to
// STARTING objects only, never to traversal (§5.4, §2.14.10) -- and these
// routes name their starting objects explicitly, so it narrows nothing. It is
// validated so a malformed value is still 400.
func graphCheckParams(vals url.Values, allowed ...string) *Error {
	ok := map[string]bool{"account": true, "rev": true}
	for _, a := range allowed {
		ok[a] = true
	}
	for name, vs := range vals {
		if !ok[name] {
			return InvalidParameter(name, name+" is not a parameter of this route")
		}
		if name != "account" && len(vs) > 1 {
			return InvalidParameter(name, name+" may be given once")
		}
	}
	for _, a := range vals["account"] {
		if a = strings.TrimSpace(a); a != AccountUnknown && !isAccountID(a) {
			return InvalidParameter("account", "account must be a 12-digit account id or unknown")
		}
	}
	return nil
}

// graphNodeParam parses a node reference parameter (root, node, from, to): a
// typed reference of a traversal node type. A policy or claim reference, a
// bare UUID or garbage is 400 invalid_parameter (D-39); a well-formed
// reference that is not this workspace's is 404, decided in the snapshot.
func graphNodeParam(vals url.Values, name string) (Ref, *Error) {
	raw := strings.TrimSpace(vals.Get(name))
	if raw == "" {
		return Ref{}, InvalidParameter(name, name+" is required")
	}
	return ParseRefParam(name, raw, graphNodeTypes...)
}

// graphDirection parses the required direction (D-35: 400 when absent).
func graphDirection(vals url.Values) (string, *Error) {
	switch d := vals.Get("direction"); d {
	case GraphForward, GraphReverse:
		return d, nil
	case "":
		return "", InvalidParameter("direction", "direction is required: forward or reverse")
	default:
		return "", InvalidParameter("direction", "direction must be forward or reverse")
	}
}

// graphIncludeEnded parses include_ended (D-12): ended edges are left out
// unless it is true.
func graphIncludeEnded(vals url.Values) (bool, *Error) {
	switch v := vals.Get("include_ended"); v {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, InvalidParameter("include_ended", "include_ended must be true or false")
	}
}

/* --------------------------------- the core -------------------------------- */

// graphTraversal is one request's traversal state, inside its snapshot:
// every node and edge the response will carry, in the order they were
// reached. Nothing is added to it except by a level that completed.
type graphTraversal struct {
	q      *Query
	b      GraphBudgets
	ended  bool
	accts  *Accounts
	budget time.Duration

	// provider is the (first) ROOT's provider: "" until the root is read,
	// then models.ProviderAWS or models.ProviderK8s. An external principal
	// root is AWS's: principals are the AWS trust graph's. Every edge is read
	// in the provider of the node it is read FROM (graphProviderSlot), so a
	// walk stays in its root's provider except across a crossing
	// (traverse_cross.go).
	provider string
	// k8s is the Kubernetes coverage, read once (traverse_k8s.go).
	k8s *graphK8sCoverage
	// cross is the read-time cross-provider resolutions, read once
	// (traverse_cross.go): with a Kubernetes root, or the first time a level
	// meets an external principal.
	cross *graphCross

	nodes   map[string]*GraphNode
	order   []*GraphNode
	edges   []*GraphEdge
	byClaim map[string]*GraphEdge

	// Far-account coverage, loaded once, the first time a level returns an
	// edge that crosses into a connected account.
	cov     map[string][]GraphLimitation
	covDone bool
}

func newGraphTraversal(q *Query, b GraphBudgets, budget time.Duration, ended bool) (*graphTraversal, error) {
	accts, err := q.LoadAccounts()
	if err != nil {
		return nil, err
	}
	return &graphTraversal{
		q: q, b: b, ended: ended, accts: accts, budget: budget,
		nodes: map[string]*GraphNode{}, byClaim: map[string]*GraphEdge{},
	}, nil
}

// The level mechanism -- graphLevel, its allowance and the re-arming of every
// statement -- is in traverse_level.go.

// node returns a node the traversal holds, or nil.
func (t *graphTraversal) node(ref string) *GraphNode { return t.nodes[ref] }

// readRoot reads the starting node, MANDATORY (§5.1: a graph request fails
// only when even its root cannot be read): nil when it is not a readable node
// of this workspace (404, no hint).
//
// A root is looked for among AWS's nodes (and external principals), then
// Kubernetes'; the first root read sets t.provider. An AWS root exists only
// in a published graph (D-4: nothing exists before the first publication), so
// without a publication it is 404 exactly as before. Kubernetes rows are not
// tied to a publication (they are written straight from a sweep), so a
// Kubernetes root is readable whether or not one exists. /graph/path's two
// ends may be of different providers: a path between them runs through a
// crossing (traverse_cross.go), or there is none.
//
// A Kubernetes root reads the request's cross-provider resolutions here, so
// its walk knows which ServiceAccounts can_assume leads out of.
func (t *graphTraversal) readRoot(ref Ref) (*GraphNode, error) {
	n := &GraphNode{typ: ref.Type, id: ref.ID, Ref: ref.String()}
	lv := t.mandatory()
	if err := t.fetchNodes(lv, []*GraphNode{n}); err != nil {
		return nil, err
	}
	if !n.fetched {
		return nil, nil
	}
	if n.side() == models.ProviderAWS && !t.q.Published() {
		return nil, nil
	}
	if t.provider == "" {
		t.provider = n.side()
	}
	if n.side() == models.ProviderK8s {
		if err := t.loadCross(lv); err != nil {
			return nil, err
		}
	}
	if err := t.decorateNodes(lv, []*GraphNode{n}); err != nil {
		return nil, err
	}
	if err := t.decorateLimitations(lv, []*GraphNode{n}, nil); err != nil {
		return nil, err
	}
	t.nodes[n.Ref] = n
	t.order = append(t.order, n)
	return n, nil
}

// graphReach is one row a level accepted: the edge, the node it was expanded
// from (near) and the node it leads to in the traversal's direction (far).
type graphReach struct {
	edge    *GraphEdge
	near    *GraphNode
	far     *GraphNode
	newEdge bool
}

// graphPair is one (node, edge kind) whose neighbours a response may not
// contain in full.
type graphPair struct {
	ref  string
	kind string
}

// graphKeyset is a position in one node's neighbours of one kind: the far
// node's source_key and the claim id (/graph/expand's cursor).
type graphKeyset struct {
	Key string
	ID  uuid.UUID
}

// graphStepOpts shapes one level.
type graphStepOpts struct {
	kinds    []string        // nil: every kind
	noAssume map[string]bool // nodes whose can_assume is not expanded (the hop limit)
	pageSize int             // > 0: accept at most this many rows (/graph/expand)
	after    *graphKeyset    // /graph/expand's cursor position
	// rediscover: the level may read edges the traversal already holds (the
	// other side of /graph/path found them). They cost no budget, so each
	// query reads that many rows more -- or a query filled with them would
	// leave NEW rows unread, and a side that was not exhausted would look
	// exhausted.
	rediscover bool
}

// graphStep is what one level found. Nothing in it is part of the traversal
// until commit: a level that runs out of time leaves the traversal as it was.
type graphStep struct {
	reaches  []graphReach
	newNodes []*GraphNode
	newEdges []*GraphEdge
	bound    string      // nodes | edges: a budget stopped the level
	cut      []graphPair // (near, kind) the level did not read in full
	more     bool        // pageSize bound: another row exists
	last     *graphKeyset
}

// graphUnit is one statement of a level: one edge kind, read in one
// provider, for the frontier nodes it is read from. A level issues, per kind
// in graphEdgeKinds order, its AWS unit, its crossing unit (forward
// can_assume from Kubernetes ServiceAccounts through their resolved
// principals, traverse_cross.go) and its Kubernetes unit -- so an AWS-only
// level issues exactly the one statement per kind it always did.
type graphUnit struct {
	kind   string
	side   string // the provider the spec is rendered for
	spec   *graphEdgeSpec
	groups map[string][]uuid.UUID
	nears  []*GraphNode
	cross  bool
}

// units is a level's statements for one kind.
func (t *graphTraversal) units(lv *graphLevel, frontier []*GraphNode, dir, kind string, opts graphStepOpts) ([]graphUnit, error) {
	spec := graphSpecFor(dir, kind)
	if spec == nil {
		return nil, nil
	}
	var out []graphUnit
	for _, side := range []string{models.ProviderAWS, models.ProviderK8s} {
		if graphSideHasKind(side, kind) {
			u := graphUnit{kind: kind, side: side, spec: spec, groups: map[string][]uuid.UUID{}}
			for _, n := range frontier {
				if n.side() != side {
					continue
				}
				if _, ok := spec.near[n.typ]; !ok {
					continue
				}
				if kind == GraphEdgeCanAssume && opts.noAssume[n.Ref] {
					continue
				}
				u.groups[n.typ] = append(u.groups[n.typ], n.id)
				u.nears = append(u.nears, n)
			}
			if len(u.nears) > 0 {
				out = append(out, u)
			}
		}
		if side != models.ProviderAWS || dir != GraphForward || kind != GraphEdgeCanAssume {
			continue
		}
		// The crossing, forward: a ServiceAccount's resolved principals'
		// can_assume edges, read as AWS's from the principals.
		var sas []*GraphNode
		for _, n := range frontier {
			if n.side() == models.ProviderK8s && n.typ == RefIdentity && !opts.noAssume[n.Ref] {
				sas = append(sas, n)
			}
		}
		if len(sas) == 0 {
			continue
		}
		if err := t.loadCross(lv); err != nil {
			return nil, err
		}
		var nears []*GraphNode
		for _, n := range sas {
			if t.crossAvailable(n.id) {
				nears = append(nears, n)
			}
		}
		if ps := t.crossPrincipals(nears); len(ps) > 0 {
			out = append(out, graphUnit{kind: kind, side: models.ProviderAWS, spec: spec, cross: true,
				groups: map[string][]uuid.UUID{RefExternalPrincipal: ps}, nears: nears})
		}
	}
	return out, nil
}

// step runs ONE breadth-first level from frontier in direction dir: per edge
// kind, in graphEdgeKinds order, one query per unit (graphUnit) for the whole
// frontier, each ordered by (target source_key, id); then one query per node
// type and provider for the nodes it reached, and their decorations. The
// node and edge budgets are checked row by row, so the level stops exactly
// where a budget binds, and every (node, kind) it did not read in full is
// named in cut.
//
// An edge the traversal already holds (the other side of /graph/path met it)
// is a re-discovery: it costs no budget, and its far node counts as reached.
func (t *graphTraversal) step(lv *graphLevel, frontier []*GraphNode, dir string, opts graphStepOpts) (*graphStep, error) {
	res := &graphStep{}
	staged := map[string]*GraphNode{}
	stagedEdges := map[string]*GraphEdge{}
	lookup := func(ref string) *GraphNode {
		if n := staged[ref]; n != nil {
			return n
		}
		return t.nodes[ref]
	}
	nodeCount, edgeCount := len(t.order), len(t.edges)

	kinds := opts.kinds
	if kinds == nil {
		kinds = graphEdgeKinds
	}
	for _, kind := range kinds {
		units, err := t.units(lv, frontier, dir, kind, opts)
		if err != nil {
			return nil, err
		}
		for _, u := range units {
			cutAll := func() {
				for _, n := range u.nears {
					res.cut = append(res.cut, graphPair{n.Ref, kind})
				}
			}
			if res.bound != "" {
				cutAll() // never queried: an earlier unit bound the level
				continue
			}
			// One row past the edge budget, so a level that would exceed it
			// knows. Within one query a claim appears once, so at most
			// len(t.edges) of its rows are re-discoveries.
			limit := t.b.Edges - edgeCount + 1
			if opts.rediscover {
				limit += len(t.edges)
			}
			if opts.pageSize > 0 && opts.pageSize+1 < limit {
				limit = opts.pageSize + 1
			}
			if limit < 1 {
				limit = 1
			}
			rows, err := t.queryEdges(lv, u.spec, u.side, u.groups, opts.after, limit)
			if err != nil {
				return nil, err
			}
			// The crossing in reverse: a role's can_assume from a resolved
			// principal is drawn from its ServiceAccount (traverse_cross.go).
			if u.side == models.ProviderAWS && kind == GraphEdgeCanAssume && dir == GraphReverse {
				for _, row := range rows {
					if row.FromType == RefExternalPrincipal {
						if err := t.loadCross(lv); err != nil {
							return nil, err
						}
						break
					}
				}
			}
			accepted := 0
			for _, row := range rows {
				if opts.pageSize > 0 && accepted == opts.pageSize {
					res.more = true
					break
				}
				farSide := u.side
				var crossing *graphCrossMatch
				principal := row.FromID
				if kind == GraphEdgeCanAssume && row.FromType == RefExternalPrincipal &&
					(u.cross || (dir == GraphReverse && !t.held(R(RefExternalPrincipal, row.FromID), staged))) {
					if m, ok := t.cross.match(row.FromID); ok {
						crossing = &m
						row.FromType, row.FromID = RefIdentity, m.identity
						if dir == GraphReverse {
							farSide = models.ProviderK8s
						}
					} else if u.cross {
						return nil, fmt.Errorf("igaread: crossing row %s has no resolution", row.ClaimID)
					}
				}
				claimRef := u.spec.claimRef(row.ClaimID)
				claim := claimRef.String()
				fromRef, toRef := R(row.FromType, row.FromID), R(row.ToType, row.ToID)
				nearRef, farRef, farType, farID := fromRef, toRef, row.ToType, row.ToID
				if dir == GraphReverse {
					nearRef, farRef, farType, farID = toRef, fromRef, row.FromType, row.FromID
				}
				near := lookup(nearRef)
				if near == nil {
					return nil, fmt.Errorf("igaread: %s row %s is not from the frontier", kind, claim)
				}
				if e := t.byClaim[claim]; e != nil {
					res.reaches = append(res.reaches, graphReach{edge: e, near: near, far: lookup(farRef)})
					accepted++
					continue
				}
				if e := stagedEdges[claim]; e != nil {
					res.reaches = append(res.reaches, graphReach{edge: e, near: near, far: lookup(farRef)})
					accepted++
					continue
				}
				if edgeCount >= t.b.Edges {
					res.bound = GraphBoundEdges
					break
				}
				far := lookup(farRef)
				if far == nil {
					if nodeCount >= t.b.Nodes {
						res.bound = GraphBoundNodes
						break
					}
					far = &GraphNode{typ: farType, id: farID, Ref: farRef, key: row.FarKey, want: farSide}
					staged[farRef] = far
					res.newNodes = append(res.newNodes, far)
					nodeCount++
				}
				e := row.edge(kind, claimRef, fromRef, toRef)
				e.side = u.side
				if crossing != nil {
					markCrossing(e, principal, *crossing)
				}
				stagedEdges[claim] = e
				res.newEdges = append(res.newEdges, e)
				edgeCount++
				res.reaches = append(res.reaches, graphReach{edge: e, near: near, far: far, newEdge: true})
				res.last = &graphKeyset{Key: row.FarKey, ID: row.ClaimID}
				accepted++
			}
			if res.bound != "" {
				cutAll()
			}
		}
	}

	// One query per node type (and provider) for what the level reached,
	// then their decorations, then the edges' own fields -- which need both
	// endpoints -- then, in one call per provider, their limitations (D-35).
	if err := t.fetchNodes(lv, res.newNodes); err != nil {
		return nil, err
	}
	for _, n := range res.newNodes {
		if !n.fetched {
			// The edge query checked the far node is readable in this same
			// snapshot; a miss here is a defect, never a node to guess at.
			return nil, fmt.Errorf("igaread: traversal reached %s but could not read it", n.Ref)
		}
	}
	if err := t.decorateNodes(lv, res.newNodes); err != nil {
		return nil, err
	}
	if err := t.decorateEdges(lv, res.newEdges, lookup); err != nil {
		return nil, err
	}
	if err := t.decorateLimitations(lv, res.newNodes, res.newEdges); err != nil {
		return nil, err
	}
	return res, nil
}

// commit makes a completed level part of the traversal.
func (t *graphTraversal) commit(s *graphStep) {
	for _, n := range s.newNodes {
		t.nodes[n.Ref] = n
		t.order = append(t.order, n)
	}
	for _, e := range s.newEdges {
		t.edges = append(t.edges, e)
		t.byClaim[e.Claim] = e
	}
}

// runLevel runs one level as OPTIONAL work (§5.1): ok=false when it ran out of
// time, in which case its savepoint was rolled back and nothing of it is kept.
func (t *graphTraversal) runLevel(frontier []*GraphNode, dir string, opts graphStepOpts) (*graphStep, bool, error) {
	var s *graphStep
	var lv *graphLevel
	ok, err := t.q.Optional(func(*gorm.DB) error {
		var err error
		lv = t.optionalLevel()
		s, err = t.step(lv, frontier, dir, opts)
		return err
	})
	if lv != nil {
		lv.done()
	}
	if err != nil || !ok {
		return nil, false, err
	}
	return s, true, nil
}

// timeLeft reports whether another level may START (D-40).
func (t *graphTraversal) timeLeft() bool { return t.q.Remaining() >= graphReserve(t.budget) }

// nearOf is the endpoint an edge was expanded FROM in direction dir.
func nearOf(e *GraphEdge, dir string) string {
	if dir == GraphReverse {
		return e.To
	}
	return e.From
}

// graphKindsFor is every edge kind that can lead out of a node of this type
// in this direction (§5.4's table). An external principal is terminal in
// reverse (nothing targets one), and a resource in forward.
func graphKindsFor(typ, dir string) []string {
	var out []string
	for _, k := range graphEdgeKinds {
		if s := graphSpecFor(dir, k); s != nil {
			if _, ok := s.near[typ]; ok {
				out = append(out, k)
			}
		}
	}
	return out
}

// kindsFor is graphKindsFor for one node's provider: a Kubernetes node has
// only the kinds the Kubernetes projection writes (graphK8sEdgeKinds), plus
// can_assume forward from a ServiceAccount an AWS trust's principal resolves
// to (the crossing), so it never names a frontier no row could fill -- a
// "Load more resources" under a rule that has no resource rows.
func (t *graphTraversal) kindsFor(n *GraphNode, dir string) []string {
	var out []string
	for _, k := range graphKindsFor(n.typ, dir) {
		switch {
		case graphSideHasKind(n.side(), k):
			out = append(out, k)
		case k == GraphEdgeCanAssume && dir == GraphForward && n.typ == RefIdentity && t.crossAvailable(n.id):
			out = append(out, k)
		}
	}
	return out
}

// frontier describes every (node, kind) the response may not contain in full
// (§5.4 "Continuation"): more = the kind's neighbours in this direction, under
// the same lifecycle filter, minus those the response carries. The counts are
// OPTIONAL work, capped at CountCap per node: counted inside the budget they
// are exact; a count that timed out, was over the cap, or was never attempted
// (known=false: the time budget already bound) is {count: null, exact:
// false}. A pair counted exactly at zero more is not a frontier entry.
func (t *graphTraversal) frontier(pairs []graphPair, dir string, known bool) ([]GraphFrontier, error) {
	if len(pairs) == 0 {
		return []GraphFrontier{}, nil
	}
	// Dedupe, then order by the node's place in the response, then by kind.
	pos := map[string]int{}
	for i, n := range t.order {
		pos[n.Ref] = i
	}
	kindPos := map[string]int{}
	for i, k := range graphEdgeKinds {
		kindPos[k] = i
	}
	seen := map[graphPair]bool{}
	var uniq []graphPair
	for _, p := range pairs {
		if !seen[p] {
			seen[p] = true
			uniq = append(uniq, p)
		}
	}
	graphSortPairs(uniq, pos, kindPos)

	var totals map[graphPair]*int64
	if known {
		byKind := map[string][]*GraphNode{}
		for _, p := range uniq {
			byKind[p.kind] = append(byKind[p.kind], t.nodes[p.ref])
		}
		var counted map[graphPair]*int64
		var lv *graphLevel
		ok, err := t.q.Optional(func(*gorm.DB) error {
			lv = t.optionalLevel()
			counted = map[graphPair]*int64{}
			for _, k := range graphEdgeKinds {
				if len(byKind[k]) == 0 {
					continue
				}
				c, err := t.countNeighbours(lv, dir, k, byKind[k])
				if err != nil {
					return err
				}
				for ref, n := range c {
					counted[graphPair{ref, k}] = n
				}
			}
			return nil
		})
		if lv != nil {
			lv.done()
		}
		if err != nil {
			return nil, err
		}
		if ok {
			totals = counted
		}
	}
	returned := map[graphPair]int64{}
	for _, e := range t.edges {
		returned[graphPair{nearOf(e, dir), e.Kind}]++
	}

	out := []GraphFrontier{}
	for _, p := range uniq {
		more := GraphMore{}
		if totals != nil {
			if total, ok := totals[p]; ok && total != nil {
				n := *total - returned[p]
				if n <= 0 {
					continue // counted: nothing the response lacks
				}
				more = GraphMore{Count: &n, Exact: true}
			}
		}
		out = append(out, GraphFrontier{
			Node: p.ref, Edge: p.kind, Direction: dir, More: more,
			Expand: t.expandURL(p.ref, p.kind, dir),
		})
	}
	return out, nil
}

// expandURL is the call that expands one frontier entry (§5.3 example), with
// the request's lifecycle filter carried over so the expansion shows the same
// edges.
func (t *graphTraversal) expandURL(ref, kind, dir string) string {
	u := "/api/iga/v1/graph/expand?node=" + ref + "&edge=" + kind + "&direction=" + dir
	if t.ended {
		u += "&include_ended=true"
	}
	return u
}

/* ---------------------------------- /graph -------------------------------- */

// graphVisit is where the breadth-first search first reached a node: its
// parent (the path that reached it) and the can_assume hops on that path.
type graphVisit struct {
	parent string
	hops   int
}

// Graph serves GET /graph?root=<ref>&direction=forward|reverse&assume_hops=N
// [&include_ended=true][&rev=N] (§5.3 Graph, §5.4; D-34, D-39).
//
// It walks every edge kind to the node and edge budgets; assume_hops (default
// 2, 0-4, above the hard budget is 400) limits only can_assume (D-34). An
// edge to a node already reached is returned, marked closes_cycle when that
// node is on the path that reached its source, and the node is never expanded
// again: a node reached twice is returned once, and the edges say how.
func (g *GraphTraversal) Graph(ctx context.Context, ws uuid.UUID, vals url.Values) (any, error) {
	if perr := graphCheckParams(vals, "root", "direction", "assume_hops", "include_ended"); perr != nil {
		return nil, perr
	}
	root, perr := graphNodeParam(vals, "root")
	if perr != nil {
		return nil, perr
	}
	dir, perr := graphDirection(vals)
	if perr != nil {
		return nil, perr
	}
	hops := DefaultAssumeHops
	if raw := vals.Get("assume_hops"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 || n > g.b.AssumeHops {
			return nil, InvalidParameter("assume_hops", fmt.Sprintf("assume_hops must be 0-%d; a further hop is an expansion from the frontier", g.b.AssumeHops))
		}
		hops = n
	}
	ended, perr := graphIncludeEnded(vals)
	if perr != nil {
		return nil, perr
	}
	rev, perr := ParseRev(vals)
	if perr != nil {
		return nil, perr
	}

	var out Envelope
	err := g.r.Read(ctx, ws, Pin{}, func(q *Query) error {
		// D-4 (no AWS object exists before the first publication) is
		// readRoot's: a Kubernetes root needs none -- and ignores rev (D-111).
		t, err := newGraphTraversal(q, g.b, g.r.budget, ended)
		if err != nil {
			return err
		}
		start, err := t.readRoot(root)
		if err != nil {
			return err
		}
		if start == nil || start.side() == models.ProviderAWS {
			if err := graphRevCheck(q, rev); err != nil {
				return err
			}
		}
		if start == nil {
			return NotFound()
		}
		data, err := t.breadthFirst(start, dir, hops)
		if err != nil {
			return err
		}
		out = Envelope{Data: data, Meta: g.meta(q, t)}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// breadthFirst is /graph's search from start.
func (t *graphTraversal) breadthFirst(start *GraphNode, dir string, maxHops int) (*GraphData, error) {
	visit := map[string]graphVisit{start.Ref: {}}
	onPath := func(target, from string) bool {
		// Is target on the path that reached from (from itself included)?
		for cur := from; cur != ""; cur = visit[cur].parent {
			if cur == target {
				return true
			}
		}
		return false
	}

	var pending []graphPair // (node, kind) the response may lack
	var stop string
	frontier := []*GraphNode{start}
	for len(frontier) > 0 {
		noAssume := map[string]bool{}
		for _, n := range frontier {
			if visit[n.Ref].hops >= maxHops {
				noAssume[n.Ref] = true // the hop limit: named in the frontier below
				for _, k := range t.kindsFor(n, dir) {
					if k == GraphEdgeCanAssume {
						pending = append(pending, graphPair{n.Ref, k})
					}
				}
			}
		}
		if !t.timeLeft() {
			stop = GraphBoundTime
			break
		}
		s, ok, err := t.runLevel(frontier, dir, graphStepOpts{noAssume: noAssume})
		if err != nil {
			return nil, err
		}
		if !ok {
			stop = GraphBoundTime
			break
		}
		t.commit(s)
		for _, r := range s.reaches {
			if !r.newEdge {
				continue
			}
			if _, seen := visit[r.far.Ref]; seen {
				r.edge.ClosesCycle = onPath(r.far.Ref, r.near.Ref)
				continue
			}
			h := visit[r.near.Ref].hops
			if r.edge.Kind == GraphEdgeCanAssume {
				h++
			}
			visit[r.far.Ref] = graphVisit{parent: r.near.Ref, hops: h}
		}
		pending = append(pending, s.cut...)
		frontier = s.newNodes
		if s.bound != "" {
			stop = s.bound
			break
		}
	}
	// Whatever is left in the frontier was never expanded.
	for _, n := range frontier {
		for _, k := range t.kindsFor(n, dir) {
			pending = append(pending, graphPair{n.Ref, k})
		}
	}

	front, err := t.frontier(pending, dir, stop != GraphBoundTime)
	if err != nil {
		return nil, err
	}
	var truncated *GraphTruncated
	switch {
	case stop != "":
		truncated = &GraphTruncated{BoundBy: stop}
	default:
		// The hop limit bound when a node at it has can_assume neighbours
		// the response lacks -- or might have (not counted in time): the
		// traversal did not look past it, so nothing may read as complete.
		for _, f := range front {
			if f.Edge == GraphEdgeCanAssume && visit[f.Node].hops >= maxHops {
				truncated = &GraphTruncated{BoundBy: GraphBoundAssumeHops}
				break
			}
		}
	}
	// An external principal's resolution IN FORCE is shown, never walked
	// (§5.4, D-87), so a walk that passed one did not look past it. That is
	// not a budget binding, so it is never truncated (§5.4 sets truncated
	// only when a budget binds, and its bound_by vocabulary is frozen): it is
	// said in resolution_not_followed beside it (D-105). A walk the time
	// budget stopped is not asked -- there is no time left to ask in -- and
	// says null: not established.
	var unfollowed *bool
	if stop != GraphBoundTime {
		u, known, err := t.graphResolutionUnfollowed(dir)
		if err != nil {
			return nil, err
		}
		switch {
		case known:
			unfollowed = &u
		case truncated == nil:
			// The check ran out of the time the request had left (D-40):
			// the time budget bound what this response could establish, so
			// it must not read as complete -- and the field stays null.
			truncated = &GraphTruncated{BoundBy: GraphBoundTime}
		}
	}
	return &GraphData{
		Root: start.Ref, Nodes: t.order, Edges: graphEdgesOrEmpty(t.edges),
		Frontier: front, Truncated: truncated, ResolutionNotFollowed: unfollowed,
	}, nil
}

// graphResolutionUnfollowed reports whether the traversal passed a resolution
// IN FORCE (resolution_state active, §2.12, D-41) that it did not follow --
// the two ends of it are one principal, and the walk saw only one of them:
//
//   - a principal it holds whose resolved node it does not hold (reverse:
//     what reaches that node was not walked; forward from a principal root:
//     what that node reaches was not walked);
//   - forward only: a node it holds that a principal it does NOT hold
//     resolves to, when that principal has can_assume edges under the
//     request's lifecycle filter -- nothing leads to a principal, so the walk
//     can never reach it, and what it may assume was not walked.
//
// The second is one OPTIONAL statement for the whole response: known=false
// when it did not finish, and the caller then claims nothing.
func (t *graphTraversal) graphResolutionUnfollowed(dir string) (unfollowed, known bool, err error) {
	var identities, workloads, principals []uuid.UUID
	for _, n := range t.order {
		switch n.typ {
		case RefExternalPrincipal:
			if n.resolvedTo != "" && t.nodes[n.resolvedTo] == nil {
				return true, true, nil
			}
			principals = append(principals, n.id) // walked: its edges are in hand
		case RefIdentity:
			identities = append(identities, n.id)
		case RefWorkload:
			workloads = append(workloads, n.id)
		}
	}
	if dir != GraphForward || len(identities)+len(workloads) == 0 {
		return false, true, nil
	}
	spec := graphSpecFor(GraphForward, GraphEdgeCanAssume)
	var ors []string
	args := []any{t.q.WS, graphResolutionActive}
	if len(identities) > 0 {
		ors = append(ors, "ep.resolved_identity_account_id IN ?")
		args = append(args, identities)
	}
	if len(workloads) > 0 {
		ors = append(ors, "ep.resolved_workload_id IN ?")
		args = append(args, workloads)
	}
	held := ""
	if len(principals) > 0 {
		held = "AND ep.id NOT IN ?"
		args = append(args, principals)
	}
	var found []uuid.UUID
	var lv *graphLevel
	ok, err := t.q.Optional(func(*gorm.DB) error {
		lv = t.optionalLevel()
		tx, err := lv.db()
		if err != nil {
			return err
		}
		// The principal's can_assume edges are AWS trust edges whatever the
		// traversal's provider: a principal resolved to a Kubernetes service
		// account (IRSA, EKS Pod Identity) is still a trust into AWS roles,
		// shown and never followed -- so its edges are read as AWS's.
		return tx.Raw(`SELECT ep.id FROM iga_external_principal ep
		                WHERE ep.workspace_id = ? AND ep.resolution_state = ?
		                  AND (`+strings.Join(ors, " OR ")+`) `+held+`
		                  AND EXISTS (SELECT 1 FROM `+graphRender(spec.from, models.ProviderAWS)+`
		                               WHERE e0.workspace_id = ep.workspace_id
		                                 AND e0.source_external_principal_id = ep.id
		                                 AND `+graphRender(graphPredicates(spec, t.ended), models.ProviderAWS)+`)
		                LIMIT 1`, args...).Scan(&found).Error
	})
	if lv != nil {
		lv.done()
	}
	if err != nil || !ok {
		return false, false, err
	}
	return len(found) > 0, true, nil
}

func graphEdgesOrEmpty(es []*GraphEdge) []*GraphEdge {
	if es == nil {
		return []*GraphEdge{}
	}
	return es
}

/* ------------------------------- /graph/expand ----------------------------- */

// graphExpandKey is an expansion cursor's position key: the last neighbour's
// source_key (the id is Cursor.ID, the claim's).
type graphExpandKey struct {
	K string `json:"k"`
}

// graphExpandSort is the one order an expansion pages in (§5.4).
const graphExpandSort = "far_key"

// GraphExpandRoute is an expansion's cursor route (D-62): the node, the edge
// kind and the direction, so a cursor for one expansion cannot page another.
func GraphExpandRoute(node, kind, dir string) string {
	return "graph/expand/" + node + "/" + kind + "/" + dir
}

// Expand serves GET /graph/expand?node=<ref>&edge=<kind>&direction=...
// [&cursor=][&include_ended=true][&rev=N]: one node's next neighbours of one
// kind, one step, Neighbours per page with a signed cursor for the rest (§5.3,
// D-35). assume_hops does not apply: expansion is how a traversal goes past
// the hop default (§2.14.11 "a starting depth, never a ceiling").
//
// An expansion has no path of its own beyond the node, so closes_cycle marks
// only an edge back to the node itself. Its frontier names the new
// neighbours' own unexpanded neighbours, so the canvas can show "+N".
func (g *GraphTraversal) Expand(ctx context.Context, ws uuid.UUID, vals url.Values) (any, error) {
	if perr := graphCheckParams(vals, "node", "edge", "direction", "cursor", "include_ended"); perr != nil {
		return nil, perr
	}
	node, perr := graphNodeParam(vals, "node")
	if perr != nil {
		return nil, perr
	}
	dir, perr := graphDirection(vals)
	if perr != nil {
		return nil, perr
	}
	kind := vals.Get("edge")
	if kind == "" {
		return nil, InvalidParameter("edge", "edge is required")
	}
	if !contains(graphEdgeKinds, kind) {
		return nil, InvalidParameter("edge", "edge must be one of "+strings.Join(graphEdgeKinds, ", "))
	}
	if !contains(graphKindsFor(node.Type, dir), kind) {
		return nil, InvalidParameter("edge", fmt.Sprintf("a %s has no %s edges in direction %s", node.Type, kind, dir))
	}
	ended, perr := graphIncludeEnded(vals)
	if perr != nil {
		return nil, perr
	}
	rev, perr := ParseRev(vals)
	if perr != nil {
		return nil, perr
	}
	cctx := CursorContext{WS: ws, Route: GraphExpandRoute(node.String(), kind, dir), Filter: FilterHash(vals), Sort: graphExpandSort}
	pin := Pin{}
	var after *graphKeyset
	if tok := vals.Get("cursor"); tok != "" {
		c, cerr := g.r.OpenCursor(tok, cctx)
		if cerr != nil {
			return nil, cerr
		}
		var k graphExpandKey
		if err := json.Unmarshal(c.Key, &k); err != nil {
			return nil, CursorInvalid("Malformed cursor.")
		}
		after = &graphKeyset{Key: k.K, ID: c.ID}
		// A Kubernetes node's cursor is unrevisioned (graphK8sCursorRev):
		// its rows are not a publication's, so a publication between two
		// pages does not make the cursor stale. An AWS cursor is pinned.
		if c.Rev != graphK8sCursorRev {
			cursorRev := c.Rev
			pin.CursorRev = &cursorRev
		}
	}

	var out Envelope
	err := g.r.Read(ctx, ws, pin, func(q *Query) error {
		t, err := newGraphTraversal(q, g.b, g.r.budget, ended)
		if err != nil {
			return err
		}
		start, err := t.readRoot(node)
		if err != nil {
			return err
		}
		if start == nil || start.side() == models.ProviderAWS {
			if err := graphRevCheck(q, rev); err != nil {
				return err
			}
		}
		if start == nil {
			return NotFound()
		}
		data := &GraphExpandData{Nodes: []*GraphNode{}, Edges: []*GraphEdge{}, Frontier: []GraphFrontier{}}
		// D-40, as /graph and /graph/path apply it: the page is a level, and
		// it is not STARTED with less than the reserve left -- a slow root
		// read must not leave a page begun that cannot finish.
		var s *graphStep
		ok := t.timeLeft()
		if ok {
			if s, ok, err = t.runLevel([]*GraphNode{start}, dir, graphStepOpts{
				kinds: []string{kind}, pageSize: g.b.Neighbours, after: after,
			}); err != nil {
				return err
			}
		}
		if !ok {
			// The page was not started, or ran out of time: nothing partial,
			// and the same call (same cursor) is the continuation.
			expand := t.expandURL(start.Ref, kind, dir)
			if tok := vals.Get("cursor"); tok != "" {
				expand += "&cursor=" + url.QueryEscape(tok)
			}
			data.Frontier = []GraphFrontier{{Node: start.Ref, Edge: kind, Direction: dir, Expand: expand}}
			data.Truncated = &GraphTruncated{BoundBy: GraphBoundTime}
			out = Envelope{Data: data, Meta: g.meta(q, t)}
			return nil
		}
		t.commit(s)
		seen := map[string]bool{}
		var pending []graphPair
		for _, r := range s.reaches {
			r.edge.ClosesCycle = r.far.Ref == start.Ref
			data.Edges = append(data.Edges, r.edge)
			if !seen[r.far.Ref] {
				seen[r.far.Ref] = true
				data.Nodes = append(data.Nodes, r.far)
				if r.far.Ref != start.Ref {
					for _, k := range t.kindsFor(r.far, dir) {
						pending = append(pending, graphPair{r.far.Ref, k})
					}
				}
			}
		}
		if s.bound != "" {
			// Only a test's budgets can bind here (a page is far below the
			// node and edge budgets); the node's own continuation is the
			// frontier and, when a row was accepted, the cursor.
			data.Truncated = &GraphTruncated{BoundBy: s.bound}
			pending = append(pending, s.cut...)
		}
		if (s.more || s.bound != "") && s.last != nil {
			key, _ := json.Marshal(graphExpandKey{K: s.last.Key})
			// A Kubernetes node's cursor is unrevisioned even when its page
			// crossed into AWS rows (D-111): keyset paging by (far key, claim)
			// neither repeats nor skips a row that did not change.
			crev := graphK8sCursorRev
			if start.side() == models.ProviderAWS {
				crev = q.Rev.Rev // readRoot: an AWS root exists only when published
			}
			tok := g.r.SignCursor(Cursor{WS: ws, Rev: crev, Route: cctx.Route, Filter: cctx.Filter,
				Sort: cctx.Sort, Key: key, ID: s.last.ID})
			data.NextCursor = &tok
		}
		front, err := t.frontier(pending, dir, true)
		if err != nil {
			return err
		}
		data.Frontier = front
		out = Envelope{Data: data, Meta: g.meta(q, t)}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
