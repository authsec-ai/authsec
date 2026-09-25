package integration

// The frozen §5 contract for everything that is NOT a 200 (SPEC-iga-phase2-
// graph.md §5.1, §5.2 "Errors, on every route", §5.5): each status and code on
// every route, in the ONE envelope {"error": {"code", "message", ...the
// code's own fields}} and nothing beside it; the precedence of the checks
// (D-10: 503, then 401, then 400); the not-yet-published state (§5.1, D-4);
// the classification decision's statuses (§5.5); and the 401/403 bodies the
// production middleware chain renders (D-9).
//
// Every sweep runs over one representative call of EVERY route of
// contractCases, so a route added to the table is swept too.

import (
	"encoding/base64"
	"encoding/json"
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	platform "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/routes"
	"github.com/authsec-ai/authsec/services"
)

// contractRepresentatives is the first case of each route, in table order.
func contractRepresentatives(cases []contractCase) []contractCase {
	seen := map[string]bool{}
	var out []contractCase
	for _, c := range cases {
		if !seen[c.route] {
			seen[c.route] = true
			out = append(out, c)
		}
	}
	return out
}

// contractWith appends query pairs to a path that may already have a query.
func contractWith(path string, kv ...string) string {
	q := qs(kv...)
	if strings.Contains(path, "?") {
		return path + "&" + strings.TrimPrefix(q, "?")
	}
	return path + q
}

// contractLiveRoutes report live state and are never pinned (D-82).
var contractLiveRoutes = map[string]bool{"GET /capabilities": true, "GET /pipeline": true}

func TestP2ContractErrorEnvelopes(t *testing.T) {
	f := contractLab(t)
	api := f.api
	reps := contractRepresentatives(contractCases(t, f))
	_, pipe := api.get("/pipeline")
	published := digs(pipe, "data", "current_published_at")

	// 400 invalid_parameter, naming the parameter: an unknown one is never
	// silently ignored (D-75, D-82) -- on every route, /capabilities included.
	t.Run("400 unknown parameter", func(t *testing.T) {
		for _, c := range reps {
			p := contractWith(c.path, "contract_bogus", "1")
			code, body := api.get(p)
			if code != http.StatusBadRequest {
				t.Errorf("%s = %d %s, want 400", p, code, contractJSON(body))
				continue
			}
			contractCheck(t, p, body, contractError("invalid_parameter", contractReq("parameter", contractConst("contract_bogus"))))
		}
	})

	// 400 invalid_parameter for a malformed or disallowed VALUE of a parameter
	// the route does define (§5.2 "a malformed or disallowed parameter"),
	// naming it: the §5.2 common list parameters, each route's own filters and
	// sections (§5.3, D-77), the graph routes' required and bounded ones (D-34,
	// D-35, D-39), /evidence's claim cap (D-79) and /lookup's cloud_ref (D-81).
	t.Run("400 malformed value", func(t *testing.T) {
		u := func(ref string) string { return refUUID(t, ref).String() }
		var tooMany []string
		for i := 0; i <= igaread.EvidenceMaxClaims; i++ {
			tooMany = append(tooMany, "claim", f.grantReadTickets)
		}
		for _, c := range []struct{ path, param string }{
			{"/workloads" + qs("q", "t"), "q"}, // §5.2: at least 2 characters
			{"/workloads" + qs("limit", "0"), "limit"},
			{"/workloads" + qs("limit", "201"), "limit"},
			{"/workloads" + qs("sort", "runtime_kind"), "sort"},
			{"/workloads" + qs("facets", "kind"), "facets"},
			{"/workloads" + qs("lifecycle", "ended"), "lifecycle"},
			{"/workloads" + qs("account", "4294183770"), "account"},
			{"/workloads" + qs("runtime_kind", "lambda"), "runtime_kind"},
			{"/workloads" + qs("classification", "agents"), "classification"},
			{"/workloads" + qs("execution_role_state", "unknown"), "execution_role_state"},
			{"/workloads" + qs("integration", "cloud_connector:x"), "integration"},
			{"/workloads" + qs("provider", "gcp"), "provider"}, // D-75
			{"/identities" + qs("kind", "role"), "kind"},
			{"/identities" + qs("used_by", "principals"), "used_by"},
			{"/identities" + qs("sort", "service"), "sort"},
			{"/resources" + qs("kind", "wildcard"), "kind"},
			{"/resources" + qs("sort", "classification"), "sort"},
			{"/resources" + qs("facets", "region"), "facets"},
			{"/workloads/" + u(f.lambda) + "/resources" + qs("sort", "account"), "sort"},
			{"/workloads/" + u(f.lambda) + "/resources" + qs("limit", "0"), "limit"},
			{"/workloads/" + u(f.lambda) + "/identities" + qs("section", "principals"), "section"},
			{"/identities/" + u(f.shared) + "/used-by" + qs("section", "members"), "section"}, // a role has no members
			{"/workloads/" + u(f.lambda) + "/changes" + qs("kind", "all"), "kind"},
			{"/workloads/" + u(f.lambda) + "/changes" + qs("limit", "201"), "limit"},
			{"/workloads/" + u(f.lambda) + "/classification" + qs("limit", "0"), "limit"},
			{"/resources/" + u(f.tickets) + "/access" + qs("limit", "201"), "limit"},
			{"/graph" + qs("root", f.lambda), "direction"}, // D-35: required
			{"/graph" + qs("root", f.lambda, "direction", "both"), "direction"},
			{"/graph" + qs("root", f.lambda, "direction", "forward", "assume_hops", "5"), "assume_hops"}, // D-34
			{"/graph" + qs("root", f.ticketRead, "direction", "forward"), "root"},                        // D-39: a policy is no root
			{"/graph" + qs("root", f.grantReadTickets, "direction", "forward"), "root"},                  // nor a claim
			{"/graph" + qs("direction", "forward"), "root"},
			{"/graph/expand" + qs("node", f.shared, "edge", "trusts", "direction", "forward"), "edge"},
			{"/graph/expand" + qs("node", f.shared, "edge", "can_assume"), "direction"},
			{"/graph/path" + qs("from", f.lambda), "to"},
			{"/graph/path" + qs("from", f.lambda, "to", f.lambda), "to"},
			{"/evidence", "claim"},
			{"/evidence" + qs(tooMany...), "claim"}, // D-79: at most 50
			{"/evidence" + qs("claim", f.grantReadTickets, "include", "facts"), "include"},
			{"/lookup", "cloud_ref"},
			{"/lookup" + qs("cloud_ref", f.lambda), "cloud_ref"}, // a graph ref is no Cloud Inventory row
			{"/coverage" + qs("account", "sandbox"), "account"},
		} {
			code, body := api.get(c.path)
			if code != http.StatusBadRequest {
				t.Errorf("%s = %d %s, want 400 naming %s", c.path, code, contractJSON(body), c.param)
				continue
			}
			contractCheck(t, c.path, body, contractError("invalid_parameter", contractReq("parameter", contractConst(c.param))))
		}
	})

	// 409 revision_stale: §5.1's one stale status and payload, exactly, on
	// every revision-bound route; the live routes refuse a pin with 400 (D-82).
	t.Run("409 revision_stale", func(t *testing.T) {
		for _, c := range reps {
			p := contractWith(c.path, "rev", "1")
			code, body := api.get(p)
			if contractLiveRoutes[c.route] {
				if code != http.StatusBadRequest {
					t.Errorf("%s = %d %s, want 400: live state is never pinned (D-82)", p, code, contractJSON(body))
					continue
				}
				contractCheck(t, p, body, contractError("invalid_parameter", contractReq("parameter", contractConst("rev"))))
				continue
			}
			if code != http.StatusConflict {
				t.Errorf("%s = %d %s, want 409", p, code, contractJSON(body))
				continue
			}
			contractCheck(t, p, body, contractRevisionStale(1, contractCurrentRev))
			if digs(body, "error", "current_published_at") != published {
				t.Errorf("%s current_published_at = %q, want %q -- the same rendering as everywhere (D-96)",
					p, digs(body, "error", "current_published_at"), published)
			}
			// The current rev is not stale: the same call pinned to it is 200.
			if code, body := api.get(contractWith(c.path, "rev", "4")); code != http.StatusOK {
				t.Errorf("%s pinned to the current rev = %d %s, want 200", c.path, code, contractJSON(body))
			}
		}
	})

	// 401 unauthenticated: no workspace in the token. It precedes a bad
	// parameter (D-10); /capabilities needs only a token, so it answers.
	t.Run("401 unauthenticated", func(t *testing.T) {
		api.asWorkspace(uuid.Nil)
		defer api.asWorkspace(f.l.ws)
		for _, c := range reps {
			if c.route == "GET /capabilities" {
				continue
			}
			p := contractWith(c.path, "contract_bogus", "1")
			code, body := api.get(p)
			if code != http.StatusUnauthorized {
				t.Errorf("%s = %d %s, want 401", p, code, contractJSON(body))
				continue
			}
			contractCheck(t, p, body, contractError("unauthenticated"))
		}
		code, body := api.do(http.MethodPost, "/workloads/"+refUUID(t, f.ecs).String()+"/classification", map[string]any{})
		if code != http.StatusUnauthorized || errCode(body) != "unauthenticated" {
			t.Errorf("POST classification with no workspace = %d %s, want 401", code, contractJSON(body))
		}
	})

	// 503 graph_unavailable with the switch off or misconfigured (§2.8,
	// T6.9), before anything else is looked at -- the token, the parameters
	// (D-10) -- and /capabilities says why, every feature false (D-11).
	for _, g := range []struct {
		mode   string
		gate   *services.GraphProjectionGate
		reason contractShape
	}{
		{"off", services.NewGraphProjectionGate(false, ""), contractNull},
		{"misconfigured", services.NewGraphProjectionGate(true, "schema head 035, want 036"), contractConst("schema head 035, want 036")},
	} {
		g := g
		t.Run("503 "+g.mode, func(t *testing.T) {
			lab := *f.l
			lab.gate = g.gate
			down := lab.api().asWorkspace(uuid.Nil)
			want := contractError("graph_unavailable",
				contractReq("graph_projection", contractConst(g.mode)), contractReq("reason", g.reason))
			for _, c := range reps {
				p := contractWith(c.path, "contract_bogus", "1")
				if c.route == "GET /capabilities" {
					continue
				}
				code, body := down.get(p)
				if code != http.StatusServiceUnavailable {
					t.Errorf("%s = %d %s, want 503", p, code, contractJSON(body))
					continue
				}
				contractCheck(t, p, body, want)
			}
			code, body := down.do(http.MethodPost, "/workloads/"+refUUID(t, f.ecs).String()+"/classification", map[string]any{})
			if code != http.StatusServiceUnavailable {
				t.Errorf("POST classification = %d %s, want 503", code, contractJSON(body))
			} else {
				contractCheck(t, "POST classification", body, want)
			}
			code, body = lab.api().get("/capabilities")
			mustStatus(t, "/capabilities", code, body, http.StatusOK)
			contractCheck(t, "/capabilities", body, contractCapabilities)
			if digs(body, "data", "graph_projection") != g.mode {
				t.Errorf("/capabilities = %s, want %s", contractJSON(body), g.mode)
			}
			for k, v := range dig(body, "data", "features").(map[string]any) {
				if v != false {
					t.Errorf("features.%s = %v with the switch %s, want false (D-11)", k, v, g.mode)
				}
			}
		})
	}

	// 404 not_found with no hint: an id of another type (D-5), a malformed
	// one, one that exists nowhere, and one that exists in ANOTHER workspace
	// all answer the same body, byte for byte (§5.2).
	t.Run("404 not_found", func(t *testing.T) {
		notFound := contractError("not_found")
		random := uuid.NewString()
		other := newWorkspace(t, f.l.db, "p2-contract-foreign")
		var want map[string]any
		for _, c := range reps {
			if !strings.Contains(c.route, ":id") {
				continue
			}
			id := strings.Split(strings.TrimPrefix(c.path, "/"), "/")[1]
			if i := strings.IndexByte(id, '?'); i >= 0 {
				id = id[:i]
			}
			// The same object's uuid under another type's reference (D-5).
			wrongType := "statement:" + id[strings.LastIndex(id, ":")+1:]
			for _, p := range []string{
				strings.Replace(c.path, id, random, 1),
				strings.Replace(c.path, id, wrongType, 1),
				strings.Replace(c.path, id, "not-a-uuid", 1),
			} {
				code, body := api.get(p)
				if code != http.StatusNotFound {
					t.Errorf("%s = %d %s, want 404", p, code, contractJSON(body))
					continue
				}
				contractCheck(t, p, body, notFound)
				if want == nil {
					want = body
				}
			}
			code, body := api.asWorkspace(other).get(c.path)
			api.asWorkspace(f.l.ws)
			if code != http.StatusNotFound || !reflect.DeepEqual(body, want) {
				t.Errorf("%s from another workspace = %d %s, want exactly %s", c.path, code, contractJSON(body), contractJSON(want))
			}
		}
		// The query-parameter forms: a well-formed ref that is not this
		// workspace's is 404 too (D-39, D-79, D-81).
		for _, p := range []string{
			"/graph" + qs("root", "workload:"+random, "direction", "forward"),
			"/graph/expand" + qs("node", "identity:"+random, "edge", "grant", "direction", "forward"),
			"/graph/path" + qs("from", "workload:"+random, "to", f.tickets),
			"/evidence" + qs("claim", "grant:"+random),
			"/evidence" + qs("claim", f.grantReadTickets, "claim", "grant:"+random),
			"/lookup" + qs("cloud_ref", "cloud_identity:"+random),
		} {
			code, body := api.get(p)
			if code != http.StatusNotFound {
				t.Errorf("%s = %d %s, want 404", p, code, contractJSON(body))
				continue
			}
			contractCheck(t, p, body, notFound)
		}
	})

	// 400 cursor_invalid for a cursor from another context; 409
	// revision_stale for one from an older revision (§5.1, D-7).
	t.Run("cursors", func(t *testing.T) {
		code, first := api.get("/workloads?limit=1")
		mustStatus(t, "first page", code, first, http.StatusOK)
		tok := digs(first, "meta", "next_cursor")
		if tok == "" {
			t.Fatalf("no next_cursor on a one-row page of four")
		}
		if code, body := api.get("/workloads" + qs("limit", "1", "cursor", tok)); code != http.StatusOK || len(digl(body, "data")) != 1 {
			t.Fatalf("second page = %d %s", code, contractJSON(body))
		}
		for _, p := range []string{
			"/workloads" + qs("cursor", "garbage"),
			"/identities" + qs("cursor", tok),                                   // another route
			"/workloads" + qs("cursor", tok, "runtime_kind", "lambda_function"), // another filter set
			"/workloads" + qs("cursor", tok, "sort", "-name"),                   // another sort
		} {
			code, body := api.get(p)
			if code != http.StatusBadRequest {
				t.Errorf("%s = %d %s, want 400 cursor_invalid", p, code, contractJSON(body))
				continue
			}
			contractCheck(t, p, body, contractError("cursor_invalid"))
		}
		// The same position, validly signed, from revision 1.
		stale := contractResign(t, tok, func(c map[string]any) { c["r"] = 1 })
		code, body := api.get("/workloads" + qs("limit", "1", "cursor", stale))
		if code != http.StatusConflict {
			t.Fatalf("a rev-1 cursor = %d %s, want 409", code, contractJSON(body))
		}
		contractCheck(t, "rev-1 cursor", body, contractRevisionStale(1, contractCurrentRev))
	})

	// 409 listing_changed: a list that filters on classification binds its
	// cursor to the classification clock (§5.5); a decision between pages
	// moves it. Last: it changes the estate.
	t.Run("409 listing_changed", func(t *testing.T) {
		code, first := api.get("/workloads" + qs("classification", "unclassified", "limit", "1"))
		mustStatus(t, "first page", code, first, http.StatusOK)
		tok := digs(first, "meta", "next_cursor")
		if tok == "" {
			t.Fatalf("no next_cursor: %s", contractJSON(first))
		}
		api.withClaims(classClaims(f.user, f.member))
		code, body := api.do(http.MethodPost, "/workloads/"+refUUID(t, f.ecs).String()+"/classification", map[string]any{
			"operation_id": uuid.NewString(), "decision": "classified_agent", "reason": "Runs ticket jobs", "expected_version": 0,
		})
		api.withClaims(map[string]string{})
		mustStatus(t, "decision", code, body, http.StatusOK)
		code, body = api.get("/workloads" + qs("classification", "unclassified", "limit", "1", "cursor", tok))
		if code != http.StatusConflict {
			t.Fatalf("next page after a decision = %d %s, want 409", code, contractJSON(body))
		}
		contractCheck(t, "listing_changed", body, contractError("listing_changed", contractReq("reason", contractConst("classification_changed"))))
	})
}

// contractResign decodes a cursor (its payload is plain JSON), edits it and
// signs it again with the suite's key -- a cursor the server itself could
// have issued, which a client cannot forge.
func contractResign(t *testing.T, tok string, edit func(map[string]any)) string {
	t.Helper()
	body, _, _ := strings.Cut(tok, ".")
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("cursor payload: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("cursor payload: %v", err)
	}
	edit(m)
	raw, _ = json.Marshal(m)
	var c igaread.Cursor
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("cursor: %v", err)
	}
	return igaread.NewReader(nil, readTestCursorKey).SignCursor(c)
}

// Nothing published yet (§5.1): lists and /coverage answer 200 with empty
// data and graph_state not_published -- never "no results" -- and no object
// exists, so every object route is 404 (D-4). A pinned rev is 409 with no
// current revision to name.
func TestP2ContractNotPublished(t *testing.T) {
	l := newP2Lab(t, "p2-contract-unpublished", true)
	l.account(accountA)
	api := l.api()
	unpublished := func(extra ...contractField) contractShape {
		return contractAll(contractListMeta(extra...), contractFunc(func(path string, v any, errs *[]string) {
			m, _ := v.(map[string]any)
			if m["rev"] != nil || m["published_at"] != nil || m["graph_state"] != "not_published" || m["next_cursor"] != nil {
				contractFail(errs, path, "want rev and published_at null, not_published, no next page: %s", contractJSON(v))
			}
		}))
	}
	for _, c := range []struct {
		path string
		row  contractShape
	}{
		{"/workloads", contractWorkloadRow},
		{"/identities", contractIdentityRow},
		{"/resources", contractResourceRow},
	} {
		code, body := api.get(c.path)
		mustStatus(t, c.path, code, body, http.StatusOK)
		contractCheck(t, c.path, body, contractObj(contractReq("data", contractArr(c.row)), contractReq("meta", unpublished())))
		if len(digl(body, "data")) != 0 {
			t.Errorf("%s data = %s, want []", c.path, contractJSON(body["data"]))
		}
		code, body = api.get(c.path + "?rev=1")
		if code != http.StatusConflict {
			t.Errorf("%s?rev=1 = %d %s, want 409", c.path, code, contractJSON(body))
			continue
		}
		contractCheck(t, c.path+"?rev=1", body, contractError("revision_stale",
			contractReq("requested_rev", contractConst(1)), contractReq("current_rev", contractNull),
			contractReq("current_published_at", contractNull)))
	}

	code, body := api.get("/coverage")
	mustStatus(t, "/coverage", code, body, http.StatusOK)
	contractCheck(t, "/coverage", body, contractCoverage)
	if len(digl(body, "data")) != 0 || digs(body, "meta", "graph_state") != "not_published" || dig(body, "meta", "rev") != nil {
		t.Errorf("/coverage = %s, want [] not_published (D-72)", contractJSON(body))
	}
	code, body = api.get("/pipeline")
	mustStatus(t, "/pipeline", code, body, http.StatusOK)
	contractCheck(t, "/pipeline", body, contractPipeline)
	if dig(body, "data", "current_rev") != nil || dig(body, "data", "current_published_at") != nil ||
		dig(body, "data", "accounts", 0, "last_published_rev") != nil {
		t.Errorf("/pipeline = %s, want no current rev and the account's first publication pending (D-56)", contractJSON(body))
	}

	id := uuid.NewString()
	for _, p := range []string{
		"/workloads/" + id, "/workloads/" + id + "/identities", "/workloads/" + id + "/resources",
		"/workloads/" + id + "/changes", "/workloads/" + id + "/classification",
		"/identities/" + id, "/identities/" + id + "/used-by", "/identities/" + id + "/permissions", "/identities/" + id + "/changes",
		"/external-principals/" + id, "/external-principals/" + id + "/referenced-by",
		"/resources/" + id, "/resources/" + id + "/access", "/resources/" + id + "/changes",
		"/graph" + qs("root", "workload:"+id, "direction", "forward"),
		"/graph/expand" + qs("node", "identity:"+id, "edge", "grant", "direction", "forward"),
		"/graph/path" + qs("from", "workload:"+id, "to", "resource:"+uuid.NewString()),
		"/evidence" + qs("claim", "grant:"+id),
		"/lookup" + qs("cloud_ref", "cloud_identity:"+id),
	} {
		code, body := api.get(p)
		if code != http.StatusNotFound {
			t.Errorf("%s before any publication = %d %s, want 404 (D-4)", p, code, contractJSON(body))
			continue
		}
		contractCheck(t, p, body, contractError("not_found"))
	}
}

// POST /workloads/:id/classification (§5.5): each outcome's status and body,
// field by field -- 200 and its replay, 409 with the current decision exactly
// as §5.5 shows it, the three 422s, 400, 403 and 404.
func TestP2ContractClassificationPost(t *testing.T) {
	f := contractLab(t)
	api := f.api
	path := "/workloads/" + refUUID(t, f.ecs).String() + "/classification"
	human := classClaims(f.user, f.member)
	post := func(claims map[string]string, p string, body map[string]any) (int, map[string]any) {
		api.withClaims(claims)
		defer api.withClaims(map[string]string{})
		return api.do(http.MethodPost, p, body)
	}

	op := uuid.NewString()
	req := map[string]any{"operation_id": op, "decision": "classified_agent", "purpose": "Ticket batch jobs",
		"reason": "Runs the ticket workers", "expected_version": 0, "undoes_decision_id": nil}
	code, body := post(human, path, req)
	mustStatus(t, "decision", code, body, http.StatusOK)
	contractCheck(t, "200", body, contractClassifyOK)
	if digs(body, "data", "classification") != "classified_agent" || num(body, "data", "classification_version") != 1 ||
		dig(body, "data", "replayed") != false || digs(body, "data", "decision", "operation_id") != op ||
		digs(body, "data", "decision", "decided_by", "display") != "Priya Shah" || digs(body, "data", "decision", "purpose") != "Ticket batch jobs" {
		t.Errorf("200 = %s", contractJSON(body))
	}
	decision := digs(body, "data", "decision", "id")

	// The retry of the same intent: the stored outcome, replayed.
	code, body = post(human, path, req)
	mustStatus(t, "replay", code, body, http.StatusOK)
	contractCheck(t, "replay", body, contractClassifyOK)
	if dig(body, "data", "replayed") != true || digs(body, "data", "decision", "id") != decision {
		t.Errorf("replay = %s, want the same decision, replayed", contractJSON(body))
	}

	// 409 classification_conflict: current is §5.5's example, key for key.
	code, body = post(human, path, map[string]any{"operation_id": uuid.NewString(), "decision": "classified_agent",
		"reason": "again", "expected_version": 0})
	if code != http.StatusConflict {
		t.Fatalf("stale version = %d %s, want 409", code, contractJSON(body))
	}
	contractCheck(t, "409", body, contractError("classification_conflict", contractReq("current", contractObj(
		contractReq("classification", contractConst("classified_agent")),
		contractReq("classification_version", contractConst(1)),
		contractReq("decided_by", contractDecidedBy),
		contractReq("decided_at", contractTime),
		contractReq("reason", contractConst("Runs the ticket workers")),
	))))

	for _, c := range []struct {
		name   string
		claims map[string]string
		path   string
		body   map[string]any
		status int
		shape  contractShape
	}{
		{"provider-native", human, "/workloads/" + refUUID(t, f.agent).String() + "/classification",
			map[string]any{"operation_id": uuid.NewString(), "decision": "classified_agent", "reason": "x", "expected_version": 0},
			http.StatusUnprocessableEntity, contractError("provider_native")},
		{"operation id reused", human, "/workloads/" + refUUID(t, f.orphan).String() + "/classification",
			map[string]any{"operation_id": op, "decision": "classified_agent", "reason": "x", "expected_version": 0},
			http.StatusUnprocessableEntity, contractError("operation_id_reused")},
		{"undo without the decision", human, path,
			map[string]any{"operation_id": uuid.NewString(), "decision": "unclassified", "reason": "x", "expected_version": 1},
			http.StatusUnprocessableEntity, contractError("invalid_decision")},
		{"missing reason", human, path,
			map[string]any{"operation_id": uuid.NewString(), "decision": "classified_agent", "expected_version": 1},
			http.StatusBadRequest, contractError("invalid_parameter", contractReq("parameter", contractConst("reason")))},
		{"not a verified human", map[string]string{}, path,
			map[string]any{"operation_id": uuid.NewString(), "decision": "classified_agent", "reason": "x", "expected_version": 1},
			http.StatusForbidden, contractError("forbidden")},
		{"no such workload", human, "/workloads/" + uuid.NewString() + "/classification",
			map[string]any{"operation_id": uuid.NewString(), "decision": "classified_agent", "reason": "x", "expected_version": 0},
			http.StatusNotFound, contractError("not_found")},
	} {
		code, body := post(c.claims, c.path, c.body)
		if code != c.status {
			t.Errorf("%s = %d %s, want %d", c.name, code, contractJSON(body), c.status)
			continue
		}
		contractCheck(t, c.name, body, c.shape)
	}

	// The permission the POST demands is iga:review; every read is iga:read
	// (§5.3). The route table is the production one.
	if p := api.requiredPermission(http.MethodPost, path); p != "iga:review" {
		t.Errorf("POST classification demands %q, want iga:review", p)
	}
	if p := api.requiredPermission(http.MethodGet, path); p != "iga:read" {
		t.Errorf("GET classification demands %q, want iga:read", p)
	}
}

// D-9, D-100: the PRODUCTION chain answers 401 and 403 in the §5.2 envelope,
// keeps the middlewares' headers and decisions, and passes an allowed request
// and a handler's own envelope through untouched -- while the Phase 1 routes
// beside it keep the shared middlewares' bodies.
//
// "Production" is meant literally: the engine is built by
// routes.SetupIGARoutes, the function SetupRoutes calls for the whole
// /api/iga/v1 surface, with the production AuthMiddleware() configured from
// the environment as cmd/main.go configures it -- never a copy of the wiring.
// Only the graph controller is the lab's (its database and switch). And
// contractSetupRoutesMountsIGA proves SetupRoutes reaches that function and
// that nothing else in the routes package mounts the graph catalogue, because
// SetupRoutes itself cannot be built without the whole platform.
func TestP2ContractAuthEnvelopes(t *testing.T) {
	contractSetupRoutesMountsIGA(t)
	l := newP2Lab(t, "p2-contract-auth", true)
	gin.SetMode(gin.TestMode)
	const secret = "p2-contract-jwt-secret"
	// middlewares.DefaultAuthConfig's inputs, as a deployment sets them.
	t.Setenv("JWT_SDK_SECRET", secret)
	t.Setenv("JWT_DEF_SECRET", secret+"-default")
	t.Setenv("AUTH_EXPECT_ISS", "authsec-ai/auth-manager")
	t.Setenv("REQUIRE_SERVER_AUTH", "true")
	eng := gin.New()
	ctl := platform.NewIGAGraphReadControllerWith(l.db, l.gate, readTestCursorKey)
	routes.SetupIGARoutes(eng, platform.NewIGAController(l.db), ctl)

	token := func(claims jwt.MapClaims) string {
		claims["iss"] = "authsec-ai/auth-manager"
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		claims["workspace_id"] = l.ws.String()
		claims["user_id"] = uuid.NewString()
		s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	call := func(method, path, bearer string) (*httptest.ResponseRecorder, map[string]any) {
		req := httptest.NewRequest(method, "/api/iga/v1"+path, nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		eng.ServeHTTP(w, req)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w, out
	}

	for _, c := range []struct {
		name, method, path, bearer string
		status                     int
		shape                      contractShape
		header                     bool // WWW-Authenticate kept
	}{
		{"no token", http.MethodGet, "/workloads", "", http.StatusUnauthorized, contractError("unauthenticated"), true},
		{"bad token", http.MethodGet, "/workloads", "not-a-jwt", http.StatusUnauthorized, contractError("unauthenticated"), true},
		{"no token, /capabilities", http.MethodGet, "/capabilities", "", http.StatusUnauthorized, contractError("unauthenticated"), true},
		{"no iga:read", http.MethodGet, "/workloads", token(jwt.MapClaims{}), http.StatusForbidden,
			contractError("forbidden", contractReq("required_permissions", contractConst([]any{"iga:read"}))), true},
		{"no iga:review", http.MethodPost, "/workloads/" + uuid.NewString() + "/classification", token(jwt.MapClaims{"scope": "iga:read"}),
			http.StatusForbidden, contractError("forbidden", contractReq("required_permissions", contractConst([]any{"iga:review"}))), true},
		// Allowed: the decision is the middleware's, unchanged, and the
		// handler's own envelope passes through verbatim (a 403 of its own:
		// no verified human; a 404 for an unknown workload).
		{"allowed read", http.MethodGet, "/workloads/" + uuid.NewString(), token(jwt.MapClaims{"scope": "iga:read"}),
			http.StatusNotFound, contractError("not_found"), false},
		{"allowed review, no human", http.MethodPost, "/workloads/" + uuid.NewString() + "/classification",
			token(jwt.MapClaims{"scope": "iga:read iga:review"}), http.StatusForbidden,
			contractError("forbidden", contractReq("message", contractConst("Classification decisions require a verified workspace member session."))), false},
	} {
		w, body := call(c.method, c.path, c.bearer)
		if w.Code != c.status {
			t.Errorf("%s: %d %s, want %d", c.name, w.Code, w.Body.String(), c.status)
			continue
		}
		if c.shape != nil {
			contractCheck(t, c.name, body, c.shape)
		} else if errCode(body) == "" {
			t.Errorf("%s: body %s is not the §5.2 envelope", c.name, w.Body.String())
		}
		if got := w.Header().Get("WWW-Authenticate") != ""; got != c.header {
			t.Errorf("%s: WWW-Authenticate present = %v, want %v", c.name, got, c.header)
		}
	}
	// And a 200 is untouched.
	w, body := call(http.MethodGet, "/workloads", token(jwt.MapClaims{"scope": "iga:read"}))
	if w.Code != http.StatusOK || digs(body, "meta", "graph_state") != "not_published" {
		t.Errorf("allowed list = %d %s, want 200 not_published", w.Code, w.Body.String())
	}

	// The Phase 1 routes on the same prefix keep the shared middlewares'
	// bodies (D-9 "The shared middleware's bodies do not change for Phase 1
	// /api/iga/v1 routes"): the envelope is the graph catalogue's own group's,
	// never the prefix's. Same decisions, their own shapes.
	for _, c := range []struct {
		name, bearer string
		status       int
		errText      string // the shared body's "error" string; "" for any
	}{
		{"Phase 1, no token", "", http.StatusUnauthorized, ""},
		{"Phase 1, no iga:read", token(jwt.MapClaims{}), http.StatusForbidden, "insufficient_scope"},
	} {
		w, body := call(http.MethodGet, "/agents", c.bearer)
		msg, isText := body["error"].(string)
		if w.Code != c.status || !isText || msg == "" || (c.errText != "" && msg != c.errText) {
			t.Errorf("%s: %d %s, want %d with the shared {\"error\": %q} body, not the graph envelope",
				c.name, w.Code, w.Body.String(), c.status, c.errText)
		}
	}

	// Each route's permission middleware is wrapped on its own (GraphRequire),
	// not only through the authentication wrapper: AuthMiddleware happens to
	// run the rest of the chain inside itself (c.Next), but an authenticator
	// in gin's usual style returns first -- and the permission middleware's
	// 403 (insufficient scope) and 401 (no claims at all) must still be the
	// §5.2 envelope, with its required_permissions.
	for _, c := range []struct {
		name   string
		claims jwt.MapClaims
		status int
		shape  contractShape
	}{
		{"scope missing", jwt.MapClaims{"workspace_id": l.ws.String(), "user_id": uuid.NewString()}, http.StatusForbidden,
			contractError("forbidden", contractReq("required_permissions", contractConst([]any{"iga:read"})))},
		{"no claims", nil, http.StatusUnauthorized, contractError("unauthenticated")},
	} {
		plain := gin.New()
		claims := c.claims
		platform.MountIGAGraphReadRoutes(plain, ctl, func(g *gin.Context) {
			if claims != nil {
				g.Set("claims", claims)
			}
		}, middlewares.Require)
		req := httptest.NewRequest(http.MethodGet, "/api/iga/v1/workloads", nil)
		rec := httptest.NewRecorder()
		plain.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != c.status {
			t.Errorf("%s behind a returning authenticator: %d %s, want %d", c.name, rec.Code, rec.Body.String(), c.status)
			continue
		}
		contractCheck(t, c.name+" behind a returning authenticator", out, c.shape)
	}
}

// contractSetupRoutesMountsIGA proves, from the routes package's own source,
// the one step TestP2ContractAuthEnvelopes cannot run: that SetupRoutes -- the
// router cmd/main.go serves, which cannot be built here without the whole
// platform -- mounts /api/iga/v1 by calling SetupIGARoutes, and that nothing
// else in the package mounts the graph catalogue. A second mount (the
// pre-D-100 RegisterIGAGraphReadRoutes on the shared group, say) would be
// production wiring the behavioural test never exercises -- exactly the
// regression D-100 fixed, compiling and passing unnoticed.
func contractSetupRoutesMountsIGA(t *testing.T) {
	t.Helper()
	dir := filepath.Join("..", "..", "routes")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the routes package: %v", err)
	}
	fset := gotoken.NewFileSet()
	callers := map[string][]string{} // callee -> the functions calling it, in source order
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					switch f := call.Fun.(type) {
					case *ast.Ident:
						callers[f.Name] = append(callers[f.Name], fn.Name.Name)
					case *ast.SelectorExpr:
						callers[f.Sel.Name] = append(callers[f.Sel.Name], fn.Name.Name)
					}
				}
				return true
			})
		}
	}
	for callee, want := range map[string][]string{
		"SetupIGARoutes":             {"SetupRoutes"},
		"MountIGAGraphReadRoutes":    {"SetupIGARoutes"},
		"RegisterIGAGraphReadRoutes": nil,
	} {
		if got := callers[callee]; !reflect.DeepEqual(got, want) {
			t.Errorf("routes package: %s is called from %v, want %v -- the graph catalogue must be mounted once, "+
				"by SetupIGARoutes, which SetupRoutes calls (D-100)", callee, got, want)
		}
	}
}
