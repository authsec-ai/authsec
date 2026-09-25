package integration

// Helpers for the T6.4 traversal suites (p2_graph_*_test.go): §5.4's /graph,
// /graph/expand and /graph/path over graphs the REAL scan worker and projector
// built (the P2-0 lab). Every helper is prefixed graph: other suites share the
// package.

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igaread"
)

// graphTeaching is §2.14.11's worked example in one account: ticket-tools and
// refund-tools both run as SharedToolRole, which TicketRead and ToolboxRead
// both grant s3:GetObject on support-tickets/*.
func graphTeaching(t *testing.T, l *p2Lab) *p2Account {
	t.Helper()
	a := l.account(accountA)
	role := a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	a.attach("SharedToolRole", a.managed("TicketRead", docTicketRead))
	a.attach("SharedToolRole", a.managed("ToolboxRead", docToolboxRead))
	listsFunctions(a, "us-east-1", "ticket-tools", role, "refund-tools", role)
	return a
}

// graphID is the id of one AWS graph row, found by its display name.
func graphID(t *testing.T, l *p2Lab, table, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	q := `SELECT id FROM ` + table + ` WHERE workspace_id = ? AND display_name = ?`
	if table != "iga_workload" {
		q += ` AND provider = 'aws'`
	}
	q += ` ORDER BY (lifecycle = 'active') DESC, created_at DESC LIMIT 1`
	if err := l.db.Raw(q, l.ws, name).Row().Scan(&id); err != nil {
		t.Fatalf("no %s named %q: %v", table, name, err)
	}
	return id
}

func graphWorkload(t *testing.T, l *p2Lab, name string) string {
	return refOf("workload", graphID(t, l, "iga_workload", name))
}

func graphIdentity(t *testing.T, l *p2Lab, name string) string {
	return refOf("identity", graphID(t, l, "iga_identity_accounts", name))
}

func graphResource(t *testing.T, l *p2Lab, text string) string {
	return refOf("resource", graphID(t, l, "iga_resources", text))
}

// graphStatementOf is the ref of a policy's active statement (the fixtures'
// policies have one statement each).
func graphStatementOf(t *testing.T, l *p2Lab, policy string) string {
	t.Helper()
	var id uuid.UUID
	if err := l.db.Raw(`SELECT e.id FROM iga_entitlements e JOIN iga_policy p ON p.id = e.policy_id
	                     WHERE e.workspace_id = ? AND e.provider = 'aws' AND p.display_name = ? AND e.lifecycle = 'active'
	                     ORDER BY e.created_at DESC LIMIT 1`, l.ws, policy).Row().Scan(&id); err != nil {
		t.Fatalf("no active statement of %q: %v", policy, err)
	}
	return refOf("statement", id)
}

// graphGet calls a traversal route through the real route table and requires
// 200.
func graphGet(t *testing.T, api *readAPI, path string) map[string]any {
	t.Helper()
	code, body := api.get(path)
	mustStatus(t, "GET "+path, code, body, 200)
	return body
}

// graphDirect calls a traversal route on the reader itself, under chosen
// budgets and request deadline (the budgets' test seam), and returns the
// status and JSON body exactly as the route would render them.
func graphDirect(t *testing.T, r *igaread.Reader, b igaread.GraphBudgets, ws uuid.UUID, route string, kv ...string) (int, map[string]any) {
	t.Helper()
	vals := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		vals.Add(kv[i], kv[i+1])
	}
	tr := r.TraversalWith(b)
	var res any
	var err error
	switch route {
	case "/graph":
		res, err = tr.Graph(context.Background(), ws, vals)
	case "/graph/expand":
		res, err = tr.Expand(context.Background(), ws, vals)
	case "/graph/path":
		res, err = tr.Path(context.Background(), ws, vals)
	default:
		t.Fatalf("no traversal route %s", route)
	}
	if err != nil {
		e := igaread.AsError(err)
		return e.Status, graphJSON(t, e.Body())
	}
	return 200, graphJSON(t, res)
}

// graphJSON round-trips a value through JSON, as the handler renders it.
func graphJSON(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

// graphNodes indexes a response's nodes by ref, failing on a ref returned
// twice: a node reached by several paths is returned ONCE (§5.4).
func graphNodes(t *testing.T, nodes []any) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, n := range nodes {
		m := n.(map[string]any)
		ref := digs(m, "ref")
		if _, dup := out[ref]; dup {
			t.Fatalf("node %s returned twice", ref)
		}
		out[ref] = m
	}
	return out
}

// graphEdge is one edge, flattened for assertions.
type graphEdge struct {
	Claim, Kind, From, To, State, Mode string
	ClosesCycle, CrossesAccount        bool
	Limitations                        []any
	Raw                                map[string]any
}

func graphEdges(t *testing.T, edges []any) []graphEdge {
	t.Helper()
	var out []graphEdge
	seen := map[string]bool{}
	for _, e := range edges {
		m := e.(map[string]any)
		ge := graphEdge{
			Claim: digs(m, "claim"), Kind: digs(m, "kind"), From: digs(m, "from"), To: digs(m, "to"),
			State: digs(m, "state"), Mode: digs(m, "mode"),
			ClosesCycle: dig(m, "closes_cycle") == true, CrossesAccount: dig(m, "crosses_account") == true,
			Limitations: digl(m, "limitations"), Raw: m,
		}
		if seen[ge.Claim] {
			t.Fatalf("edge %s returned twice", ge.Claim)
		}
		seen[ge.Claim] = true
		out = append(out, ge)
	}
	return out
}

// graphEdgesOfKind filters edges by kind.
func graphEdgesOfKind(es []graphEdge, kind string) []graphEdge {
	var out []graphEdge
	for _, e := range es {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// graphHasCode reports whether a limitations list carries a code.
func graphHasCode(ls []any, code string) bool {
	return graphLim(ls, code) != nil
}

// graphLim returns the first limitation with the code, or nil.
func graphLim(ls []any, code string) map[string]any {
	for _, l := range ls {
		if m, ok := l.(map[string]any); ok && m["code"] == code {
			return m
		}
	}
	return nil
}

// graphCodes lists a limitations list's codes, sorted.
func graphCodes(ls []any) []string {
	var out []string
	for _, l := range ls {
		out = append(out, digs(l, "code"))
	}
	sort.Strings(out)
	return out
}

// graphFrontier returns the frontier entry for (node, edge), or nil.
func graphFrontier(body map[string]any, node, edge string) map[string]any {
	for _, f := range digl(body, "data", "frontier") {
		if digs(f, "node") == node && digs(f, "edge") == edge {
			return f.(map[string]any)
		}
	}
	return nil
}

// graphRaw is a response body's canonical bytes (map keys sorted), for
// comparing two responses.
func graphRaw(t *testing.T, body map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return string(raw)
}

// graphRefsOfKind lists the refs of the nodes with a kind, in response order.
func graphRefsOfKind(nodes []any, kind string) []string {
	var out []string
	for _, n := range nodes {
		if digs(n, "kind") == kind {
			out = append(out, digs(n, "ref"))
		}
	}
	return out
}

// graphMentions reports whether a response mentions a ref anywhere -- as a
// node, an edge endpoint, a frontier entry, an exclusion or a restriction ref.
func graphMentions(t *testing.T, body map[string]any, ref string) bool {
	return strings.Contains(graphRaw(t, body), `"`+ref+`"`)
}

// graphItoa renders a revision for a query string.
func graphItoa(n int64) string { return strconv.FormatInt(n, 10) }
