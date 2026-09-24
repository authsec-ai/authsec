package integration

// §7.1 E12 (changes during paging and exploration): the backend half,
// through the real list, used-by, expand and classification routes over the
// §7.1 lab with more than 200 workloads. The lab fixture generator is
// egatesFillersAs: 210 Lambdas beside the lab's own seven. What the console
// does with these answers -- the banner, data kept, Refresh restoring view
// and filters, the list restarting with a notice, the retried save closing as
// success -- is M3's Playwright run.

import (
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// egatesForgeCursor is cursor with one character of its signature replaced
// by a different base64url character, so the MAC it carries no longer
// verifies. Replacing the LAST two characters (with "xx", as two older tests
// did) is not a forgery every time: a 32-byte MAC is 43 characters whose last
// one carries only 4 bits, non-strict base64 ignores the other 2, and so the
// "forged" cursor decodes to the very same MAC in about 1 run of 1024 -- and
// is accepted. The third character from the end is signature, whole.
func egatesForgeCursor(cursor string) string {
	b := []byte(cursor)
	i := len(b) - 3
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

// egatesFillersAs ADDS n Lambda functions named <prefix>-NNN to a region's
// list, each running as roleARN.
func egatesFillersAs(a *egatesAcct, region, prefix string, n int, roleARN string) {
	egatesFillers(a, region, prefix, n)
	f := a.lambdas[region]
	for i := len(f.functions) - n; i < len(f.functions); i++ {
		f.functions[i].Role = aws.String(roleARN)
		f.functions[i].State = lambdatypes.StateActive
	}
}

// egatesStale asserts §5.1's 409 revision_stale naming both revisions, and
// that no page was served beside it.
func egatesStale(t *testing.T, what string, code int, body map[string]any, requested, current int64) {
	t.Helper()
	if code != http.StatusConflict || errCode(body) != "revision_stale" || num(body, "error", "requested_rev") != requested ||
		num(body, "error", "current_rev") != current || digs(body, "error", "current_published_at") == "" || body["data"] != nil {
		t.Errorf("%s = %d %s, want 409 revision_stale (requested %d, current %d) and no data", what, code, egatesJSON(body), requested, current)
	}
}

// E12. 217 workloads. Page the list; mid-way a new publication commits: the
// next page is 409 revision_stale -- pages of two revisions are never
// combined -- and a fresh walk at the new revision is whole. Exploration
// cursors (graph expand, a Used-by section) minted before a publication are
// stale after it. Separately, a classification lands between pages of the
// Agents filter and of the classification sort: 409 listing_changed. A
// decision retried after its response was lost replays (200, replayed:
// true), moves nothing, and does not break a cursor minted after the
// original; a real conflict is never shown as success.
//
// Safeguards (mutation-checked): a cursor carries its revision and is
// checked against the current one; a classification list's cursor carries
// the classification clock; a replay does not write.
func TestP2EgatesE12ChangesDuringPagingAndExploration(t *testing.T) {
	l := newP2Lab(t, "p2-egates-e12", true)
	a := egatesProduction(t, l)
	egatesFillersAs(a, egatesSecondary, "batch-tool", 210, a.roleARN(egatesSharedRole))
	egatesCycle(l, a)
	api := l.api()

	// Page the list, 100 at a time.
	p1 := egatesGet(t, api, "/workloads")
	if num(p1, "meta", "rev") != 1 || num(p1, "meta", "total") != 217 || len(digl(p1, "data")) != 100 {
		t.Fatalf("page one = rev %d total %d rows %d, want rev 1, 217 in all, 100 on the page",
			num(p1, "meta", "rev"), num(p1, "meta", "total"), len(digl(p1, "data")))
	}
	p2 := egatesGet(t, api, "/workloads"+qs("cursor", digs(p1, "meta", "next_cursor")))
	seen := map[string]bool{}
	for _, r := range append(digl(p1, "data"), digl(p2, "data")...) {
		if seen[digs(r, "ref")] {
			t.Fatalf("page two repeats %s", digs(r, "ref"))
		}
		seen[digs(r, "ref")] = true
	}
	if len(seen) != 200 || num(p2, "meta", "rev") != 1 || digs(p2, "meta", "next_cursor") == "" {
		t.Fatalf("pages one and two = %d distinct rows at rev %d, want 200 at rev 1 and a third page", len(seen), num(p2, "meta", "rev"))
	}
	// Exploration cursors minted at rev 1: the role's executes_as fan-out
	// (212 workloads run as it) and its Used-by workloads section.
	role := egatesIdentity(t, l, egatesSharedRole)
	exp := egatesGet(t, api, "/graph/expand"+qs("node", role, "edge", "executes_as", "direction", "reverse"))
	if len(digl(exp, "data", "edges")) != 100 || digs(exp, "data", "next_cursor") == "" {
		t.Fatalf("expand SharedToolRole executes_as = %d edges, cursor %v; want a page of 100 and a cursor",
			len(digl(exp, "data", "edges")), dig(exp, "data", "next_cursor"))
	}
	used := egatesGet(t, api, egatesRoute(t, role, "/used-by"))
	if num(used, "data", "workloads", "total") != 212 || digs(used, "data", "workloads", "next_cursor") == "" {
		t.Fatalf("used-by workloads = total %d cursor %v, want 212 and a cursor",
			num(used, "data", "workloads", "total"), dig(used, "data", "workloads", "next_cursor"))
	}

	// A new publication commits mid-way.
	egatesCycle(l, a)
	code, body := api.get("/workloads" + qs("cursor", digs(p2, "meta", "next_cursor")))
	egatesStale(t, "page three after a publication", code, body, 1, 2)
	code, body = api.get("/workloads" + qs("rev", "1"))
	egatesStale(t, "/workloads?rev=1 after a publication", code, body, 1, 2)
	code, body = api.get("/graph/expand" + qs("node", role, "edge", "executes_as", "direction", "reverse",
		"cursor", digs(exp, "data", "next_cursor")))
	egatesStale(t, "graph expand continuation after a publication", code, body, 1, 2)
	code, body = api.get(egatesRoute(t, role, "/used-by") + qs("section", "workloads", "cursor", digs(used, "data", "workloads", "next_cursor")))
	egatesStale(t, "used-by continuation after a publication", code, body, 1, 2)
	// Any other read the investigation pins to rev 1 -- a different evidence
	// claim, a graph re-rooted -- is paused the same way (§2.14.5 "When the
	// revision moves", step 2), never an answer from the newer revision.
	code, body = api.get("/evidence" + qs("claim", evidenceGrant(t, l, egatesSharedRole, egatesTicketRead, "ReadTickets"), "rev", "1"))
	egatesStale(t, "another evidence claim at the pinned revision", code, body, 1, 2)
	code, body = api.get("/graph" + qs("root", role, "direction", "reverse", "rev", "1"))
	egatesStale(t, "the graph at the pinned revision", code, body, 1, 2)
	// Refresh: a fresh walk at rev 2 is whole -- no repeat, no gap.
	walked := listsWalk(t, api, "/workloads", 100)
	refs := map[string]bool{}
	for _, r := range walked {
		refs[digs(r, "ref")] = true
	}
	if len(walked) != 217 || len(refs) != 217 {
		t.Errorf("a fresh walk at rev 2 = %d rows, %d distinct; want all 217 once", len(walked), len(refs))
	}

	// Classification between pages. A verified human classifies three
	// workloads, pages the Agents filter and the classification sort, and
	// classifies a fourth in between.
	name := "Priya Shah"
	user, member := classMember(t, l.db, l.ws, &name, "priya@egates.test", "active")
	api.withClaims(classClaims(user, member))
	var ids []uuid.UUID
	l.db.Raw(`SELECT id FROM iga_workload WHERE workspace_id = ? AND display_name LIKE 'batch-tool-%' ORDER BY display_name LIMIT 5`, l.ws).Scan(&ids)
	if len(ids) != 5 {
		t.Fatalf("setup: %d batch-tool workloads, want 5", len(ids))
	}
	// The Agents filter already holds the lab's provider-native agents
	// (Bedrock, AgentCore); the decisions add to them.
	native := num(egatesGet(t, api, "/workloads"+qs("classification", "agent")), "meta", "total")
	if native < 1 {
		t.Fatalf("setup: the Agents filter holds %d provider-native agents, want the lab's", native)
	}
	classify := func(w uuid.UUID, op uuid.UUID, expected int64) (int, map[string]any) {
		return api.do(http.MethodPost, "/workloads/"+w.String()+"/classification",
			classBody(op, models.ClassificationClassified, "Runs the support batch", expected, nil))
	}
	for i := 0; i < 3; i++ {
		if code, body := classify(ids[i], uuid.New(), 0); code != http.StatusOK || dig(body, "data", "replayed") != false {
			t.Fatalf("classify %s = %d %s", ids[i], code, egatesJSON(body))
		}
	}
	agents := egatesGet(t, api, "/workloads"+qs("classification", "agent", "limit", "2"))
	sorted := egatesGet(t, api, "/workloads"+qs("sort", "classification", "limit", "2"))
	if num(agents, "meta", "total") != native+3 || digs(agents, "meta", "next_cursor") == "" || digs(sorted, "meta", "next_cursor") == "" {
		t.Fatalf("the Agents filter = %s, want %d agents over several pages", egatesJSON(dig(agents, "meta")), native+3)
	}
	fourth := egatesClassifyOp{op: uuid.New(), workload: ids[3]}
	code, first := classify(fourth.workload, fourth.op, 0)
	if code != http.StatusOK || dig(first, "data", "replayed") != false {
		t.Fatalf("the decision between pages = %d %s", code, egatesJSON(first))
	}
	for what, next := range map[string]string{
		"Agents filter":       "/workloads" + qs("classification", "agent", "limit", "2", "cursor", digs(agents, "meta", "next_cursor")),
		"classification sort": "/workloads" + qs("sort", "classification", "limit", "2", "cursor", digs(sorted, "meta", "next_cursor")),
	} {
		code, body := api.get(next)
		if code != http.StatusConflict || errCode(body) != "listing_changed" || digs(body, "error", "reason") != "classification_changed" ||
			body["data"] != nil {
			t.Errorf("%s: the page after a decision = %d %s, want 409 listing_changed classification_changed", what, code, egatesJSON(body))
		}
	}
	// The list restarts: one more agent now.
	restart := egatesGet(t, api, "/workloads"+qs("classification", "agent", "limit", "2"))
	if num(restart, "meta", "total") != native+4 {
		t.Errorf("the restarted Agents filter = total %d, want %d", num(restart, "meta", "total"), native+4)
	}
	// A list that neither filters nor sorts on classification pages on.
	plain := egatesGet(t, api, "/workloads"+qs("limit", "2"))
	if code, body := api.get("/workloads" + qs("limit", "2", "cursor", digs(plain, "meta", "next_cursor"))); code != http.StatusOK {
		t.Errorf("an unclassified list's next page = %d %s, want 200", code, egatesJSON(body))
	}

	// The fourth decision's response is lost; the console retries the SAME
	// operation: 200, replayed, the stored outcome, and nothing moved -- the
	// cursor minted after the original still pages.
	state := func() (int64, int64, int64) {
		var v int64
		if err := l.db.Raw(`SELECT classification_version FROM iga_workload WHERE id = ?`, fourth.workload).Row().Scan(&v); err != nil {
			t.Fatalf("read the workload's classification version: %v", err)
		}
		return v, l.count(`SELECT count(*) FROM iga_workload_classification WHERE workspace_id = ?`, l.ws),
			l.count(`SELECT COALESCE(max(seq), 0) FROM iga_classification_clock WHERE workspace_id = ?`, l.ws)
	}
	v0, n0, seq0 := state()
	code, again := classify(fourth.workload, fourth.op, 0)
	if code != http.StatusOK || dig(again, "data", "replayed") != true ||
		digs(again, "data", "decision", "id") != digs(first, "data", "decision", "id") ||
		num(again, "data", "classification_version") != num(first, "data", "classification_version") {
		t.Errorf("the retried save = %d %s, want 200 replayed with the original decision %s", code, egatesJSON(again),
			digs(first, "data", "decision", "id"))
	}
	if v1, n1, seq1 := state(); v1 != v0 || n1 != n0 || seq1 != seq0 {
		t.Errorf("a replay wrote: version %d -> %d, decisions %d -> %d, clock %d -> %d", v0, v1, n0, n1, seq0, seq1)
	}
	if code, body := api.get("/workloads" + qs("classification", "agent", "limit", "2", "cursor", digs(restart, "meta", "next_cursor"))); code != http.StatusOK ||
		len(digl(body, "data")) == 0 {
		t.Errorf("the Agents filter's next page after a replay = %d %s, want 200 and its rows", code, egatesJSON(body))
	}
	// A real conflict is never shown as success: another operation against
	// the version the replay did not move is 409 with the current decision,
	// and the same operation id with other content is 422.
	code, conflict := classify(fourth.workload, uuid.New(), 0)
	if code != http.StatusConflict || errCode(conflict) != "classification_conflict" ||
		digs(conflict, "error", "current", "classification") != models.ClassificationClassified ||
		num(conflict, "error", "current", "classification_version") != num(first, "data", "classification_version") ||
		digs(conflict, "error", "current", "decided_by", "display") != name {
		t.Errorf("a stale decision = %d %s, want 409 classification_conflict carrying Priya's current decision", code, egatesJSON(conflict))
	}
	code, reused := api.do(http.MethodPost, "/workloads/"+fourth.workload.String()+"/classification",
		classBody(fourth.op, models.ClassificationClassified, "A different reason", 0, nil))
	if code != http.StatusUnprocessableEntity || errCode(reused) != "operation_id_reused" {
		t.Errorf("the operation id with other content = %d %s, want 422 operation_id_reused", code, egatesJSON(reused))
	}
}

// egatesClassifyOp is one classification operation of the scenario.
type egatesClassifyOp struct {
	op, workload uuid.UUID
}
