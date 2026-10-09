package integration

// T6.4 route contract (§5.1, §5.2, D-4, D-10, D-35, D-39): roots are the five
// traversal node types; a policy or claim root is 400; a well-formed ref of
// another workspace is 404 with no hint; direction is required; the revision
// pin is honoured; the 503 gate applies.

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestP2GraphParametersAndRoots(t *testing.T) {
	l := newP2Lab(t, "p2-graph-params", true)
	a := graphTeaching(t, l)
	l.scanAndProject(a)
	api := l.api()
	ticket, role := graphWorkload(t, l, "ticket-tools"), graphIdentity(t, l, "SharedToolRole")
	res := graphResource(t, l, "arn:aws:s3:::support-tickets/*")
	var policy, grant uuid.UUID
	l.db.Raw(`SELECT id FROM iga_policy WHERE workspace_id = ? LIMIT 1`, l.ws).Row().Scan(&policy)
	l.db.Raw(`SELECT id FROM iga_access_edges WHERE workspace_id = ? AND provider = 'aws' LIMIT 1`, l.ws).Row().Scan(&grant)

	for name, path := range map[string]string{
		"policy root":         "/graph" + qs("root", refOf("policy", policy), "direction", "forward"),
		"claim root":          "/graph" + qs("root", refOf("grant", grant), "direction", "forward"),
		"bare uuid root":      "/graph" + qs("root", refUUID(t, ticket).String(), "direction", "forward"),
		"garbage root":        "/graph" + qs("root", "workload:not-a-uuid", "direction", "forward"),
		"no root":             "/graph" + qs("direction", "forward"),
		"no direction":        "/graph" + qs("root", ticket),
		"bad direction":       "/graph" + qs("root", ticket, "direction", "sideways"),
		"negative hops":       "/graph" + qs("root", ticket, "direction", "forward", "assume_hops", "-1"),
		"hops not a number":   "/graph" + qs("root", ticket, "direction", "forward", "assume_hops", "two"),
		"bad include_ended":   "/graph" + qs("root", ticket, "direction", "forward", "include_ended", "yes"),
		"unknown parameter":   "/graph" + qs("root", ticket, "direction", "forward", "limit", "10"),
		"root twice":          "/graph?root=" + ticket + "&root=" + role + "&direction=forward",
		"bad rev":             "/graph" + qs("root", ticket, "direction", "forward", "rev", "zero"),
		"policy path end":     "/graph/path" + qs("from", ticket, "to", refOf("policy", policy)),
		"path to itself":      "/graph/path" + qs("from", ticket, "to", ticket),
		"path include_ended":  "/graph/path" + qs("from", ticket, "to", res, "include_ended", "true"),
		"path without to":     "/graph/path" + qs("from", ticket),
		"policy expand node":  "/graph/expand" + qs("node", refOf("policy", policy), "edge", "grant", "direction", "forward"),
		"claim expand node":   "/graph/expand" + qs("node", refOf("grant", grant), "edge", "grant", "direction", "forward"),
		"bad expand cursor":   "/graph/expand" + qs("node", role, "edge", "grant", "direction", "forward", "cursor", "garbage"),
		"bad account":         "/graph" + qs("root", ticket, "direction", "forward", "account", "prod"),
		"assume_hops on path": "/graph/path" + qs("from", ticket, "to", res, "assume_hops", "2"),
	} {
		code, body := api.get(path)
		if code != http.StatusBadRequest {
			t.Errorf("%s: %d %v, want 400", name, code, body)
		}
		if c := errCode(body); c != "invalid_parameter" && c != "cursor_invalid" {
			t.Errorf("%s: code %q, want invalid_parameter (or cursor_invalid)", name, c)
		}
	}

	// Every node type is a legal root.
	var stmt uuid.UUID
	l.db.Raw(`SELECT id FROM iga_entitlements WHERE workspace_id = ? AND provider = 'aws' LIMIT 1`, l.ws).Row().Scan(&stmt)
	var ext uuid.UUID
	l.db.Raw(`SELECT id FROM iga_external_principal WHERE workspace_id = ? LIMIT 1`, l.ws).Row().Scan(&ext)
	for _, root := range []string{ticket, role, res, refOf("statement", stmt), refOf("external_principal", ext)} {
		for _, dir := range []string{"forward", "reverse"} {
			body := graphGet(t, api, "/graph"+qs("root", root, "direction", dir))
			if digs(body, "data", "root") != root || digs(body, "data", "nodes", 0, "ref") != root {
				t.Errorf("root %s %s: data = %v, want the root first", root, dir, body["data"])
			}
		}
	}
	// A well-formed ref that is not an object: 404, no hint.
	for _, path := range []string{
		"/graph" + qs("root", refOf("workload", uuid.New()), "direction", "forward"),
		"/graph/path" + qs("from", ticket, "to", refOf("resource", uuid.New())),
		"/graph/expand" + qs("node", refOf("identity", uuid.New()), "edge", "grant", "direction", "forward"),
	} {
		if code, body := api.get(path); code != 404 || errCode(body) != "not_found" {
			t.Errorf("%s = %d %v, want 404 not_found", path, code, body)
		}
	}

	// The revision pin (§5.1): current is 200, stale is 409.
	body := graphGet(t, api, "/graph"+qs("root", ticket, "direction", "forward"))
	rev := num(body, "meta", "rev")
	graphGet(t, api, "/graph"+qs("root", ticket, "direction", "forward", "rev", graphItoa(rev)))
	l.scanAndProject(a)
	for _, path := range []string{
		"/graph" + qs("root", ticket, "direction", "forward", "rev", graphItoa(rev)),
		"/graph/path" + qs("from", ticket, "to", res, "rev", graphItoa(rev)),
		"/graph/expand" + qs("node", role, "edge", "grant", "direction", "forward", "rev", graphItoa(rev)),
	} {
		if code, b := api.get(path); code != http.StatusConflict || errCode(b) != "revision_stale" {
			t.Errorf("%s = %d %v, want 409 revision_stale", path, code, b)
		}
	}
}

// E14 for the traversal routes: another workspace's refs are 404, with no
// hint; nothing is published yet is 404 too (D-4: no object exists before the
// first publication); the switch off is 503 (T6.9).
func TestP2GraphWorkspaceAndGates(t *testing.T) {
	// Every lab exists before any scans (see TestP2ListsRoutesPermissionsAndCrossWorkspace).
	home := newP2Lab(t, "p2-graph-home", true)
	other := newP2Lab(t, "p2-graph-other", true)
	off := newP2Lab(t, "p2-graph-off", false)
	t.Cleanup(func() { off.cleanup(); other.cleanup(); home.cleanup() })
	home.scanAndProject(graphTeaching(t, home))
	ticket := graphWorkload(t, home, "ticket-tools")
	res := graphResource(t, home, "arn:aws:s3:::support-tickets/*")

	// other has nothing published.
	for _, path := range []string{
		"/graph" + qs("root", ticket, "direction", "forward"),
		"/graph/path" + qs("from", ticket, "to", res),
	} {
		if code, b := other.api().get(path); code != 404 || errCode(b) != "not_found" {
			t.Errorf("unpublished workspace %s = %d %v, want 404", path, code, b)
		}
	}
	// other publishes its own graph; home's refs are still 404 there.
	b := other.account(accountB)
	b.role("OtherRole", "AROAOTHERROLEOTHERRO")
	listsFunctions(b, "us-east-1", "other-fn", b.roleARN("OtherRole"))
	other.scanAndProject(b)
	api := other.api()
	for _, path := range []string{
		"/graph" + qs("root", ticket, "direction", "forward"),
		"/graph/path" + qs("from", graphWorkload(t, other, "other-fn"), "to", res),
		"/graph/expand" + qs("node", ticket, "edge", "executes_as", "direction", "forward"),
	} {
		code, body := api.get(path)
		if code != 404 || errCode(body) != "not_found" {
			t.Errorf("%s from another workspace = %d %v, want 404 not_found", path, code, body)
		}
		if graphMentions(t, body, ticket) || graphMentions(t, body, res) {
			t.Errorf("%s: the 404 names the other workspace's object", path)
		}
	}

	if code, body := off.api().get("/graph" + qs("root", ticket, "direction", "forward")); code != 503 ||
		errCode(body) != "graph_unavailable" {
		t.Errorf("switch off = %d %v, want 503 graph_unavailable", code, body)
	}
	// /capabilities reports the graph feature exactly when it is usable (D-11).
	if _, body := home.api().get("/capabilities"); dig(body, "data", "features", "graph") != true {
		t.Errorf("capabilities = %v, want features.graph true with the switch on", body["data"])
	}
	if _, body := off.api().get("/capabilities"); dig(body, "data", "features", "graph") != false {
		t.Errorf("capabilities off = %v, want features.graph false", body["data"])
	}
}
