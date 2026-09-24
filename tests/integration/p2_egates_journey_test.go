package integration

// §7.1 E2-E5, the investigation scenarios, backend halves: the right
// workload among duplicates (E2), workload -> identity -> statements ->
// resource (E3), evidence and limitations (E4), and two workloads sharing one
// role (E5) -- every step through the real §5.3 routes over the §7.1 lab
// (p2_egates_lab_test.go). What each console must draw from these answers
// (breadcrumbs, the canvas, the Evidence panel's five parts in order, "shared
// with 1 other workload") is M3's Playwright run against real AWS.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/authsec-ai/authsec/models"
)

// egatesFillers ADDS n Lambda functions named <prefix>-NNN, running as no
// role, to a region's list (listsFunctions replaces the list).
func egatesFillers(a *egatesAcct, region, prefix string, n int) {
	f := a.lambdas[region]
	if f == nil {
		f = &fakeLambda{}
		a.lambdas[region] = f
	}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("%s-%03d", prefix, i)
		f.functions = append(f.functions, lambdatypes.FunctionConfiguration{
			FunctionArn:  aws.String("arn:aws:lambda:" + region + ":" + a.id + ":function:" + name),
			FunctionName: aws.String(name), State: lambdatypes.StateActive,
		})
	}
}

// E2. Two workloads named ticket-tools in two accounts, both beyond page one
// of the name-ordered list. q=ticket is server-side over the whole inventory
// and returns both, each with its own account and ARN; the account facet
// counts per account with every OTHER filter applied; opening B's shows B's
// ARN and account on every tab and nothing of A's.
//
// Safeguards (mutation-checked): the search runs in SQL over the revision, not
// over a loaded page; a detail route reads the id it was given, never a row
// found by name.
func TestP2EgatesE2RightWorkloadAmongDuplicates(t *testing.T) {
	l := newP2Lab(t, "p2-egates-e2", true)
	a := egatesProduction(t, l)
	b := egatesSandbox(t, l)
	// 120 functions that sort before "ticket-tools": page one (100 rows by
	// name) holds neither ticket-tools.
	egatesFillers(a, egatesSecondary, "aaa-filler", 120)
	egatesCycle(l, a)
	egatesCycle(l, b)
	api := l.api()

	page1 := egatesGet(t, api, "/workloads")
	if names := listsField(digl(page1, "data"), "name"); len(names) != 100 || strings.Join(names, ",") != strings.Join(egatesSorted(names), ",") {
		t.Fatalf("page one = %d rows %v, want 100 in name order", len(names), names)
	}
	for _, r := range digl(page1, "data") {
		if digs(r, "name") == "ticket-tools" {
			t.Fatal("setup: a ticket-tools is on page one; the search would prove nothing")
		}
	}
	if digs(page1, "meta", "next_cursor") == "" || num(page1, "meta", "total") != 128 {
		t.Fatalf("page one meta = %s, want a next cursor and 128 workloads in all", egatesJSON(dig(page1, "meta")))
	}

	wantA, wantB := egatesWorkload(t, l, "ticket-tools", accountA), egatesWorkload(t, l, "ticket-tools", accountB)
	for _, q := range []string{"ticket", "TICKET", "TiCkEt"} {
		body := egatesGet(t, api, "/workloads"+qs("q", q, "facets", "account"))
		rows := digl(body, "data")
		byRef := egatesRows(t, rows, "ref")
		ra, rb := byRef[wantA], byRef[wantB]
		if ra == nil || rb == nil {
			t.Fatalf("q=%s = %v, want both ticket-tools", q, listsField(rows, "ref"))
		}
		if digs(ra, "name") != "ticket-tools" || digs(ra, "account", "id") != accountA ||
			digs(ra, "arn") != "arn:aws:lambda:"+egatesPrimary+":"+accountA+":function:ticket-tools" ||
			digs(rb, "name") != "ticket-tools" || digs(rb, "account", "id") != accountB ||
			digs(rb, "arn") != "arn:aws:lambda:"+egatesPrimary+":"+accountB+":function:ticket-tools" ||
			digs(ra, "account", "label") == digs(rb, "account", "label") {
			t.Errorf("q=%s rows are not distinguishable by account and ARN: A %s, B %s", q, egatesJSON(ra), egatesJSON(rb))
		}
		// Everything the substring matches, and nothing else (ticket-worker
		// is A's ECS task definition).
		if names := egatesSorted(listsField(rows, "name")); strings.Join(names, ",") != "ticket-tools,ticket-tools,ticket-worker" {
			t.Errorf("q=%s names = %v, want the two ticket-tools and ticket-worker", q, names)
		}
		facet, ok := listsFacet(body, "account")
		if !ok || facet[accountA] != 2 || facet[accountB] != 1 || facet["unknown"] != 0 || len(facet) != 3 {
			t.Errorf("q=%s account facet = %v, want %s:2 %s:1 unknown:0", q, facet, accountA, accountB)
		}
		if num(body, "meta", "total") != 3 || dig(body, "meta", "total_known") != true {
			t.Errorf("q=%s total = %v", q, dig(body, "meta", "total"))
		}
	}
	// The account facet ignores the account filter itself (§5.2): the chip for
	// A still says what choosing A would give while B is chosen.
	onlyB := egatesGet(t, api, "/workloads"+qs("q", "ticket", "account", accountB, "facets", "account"))
	if refs := listsField(digl(onlyB, "data"), "ref"); len(refs) != 1 || refs[0] != wantB {
		t.Errorf("q=ticket&account=%s = %v, want only B's ticket-tools", accountB, refs)
	}
	if facet, _ := listsFacet(onlyB, "account"); facet[accountA] != 2 || facet[accountB] != 1 {
		t.Errorf("account facet under account=%s = %v, want the other filters only (A:2, B:1)", accountB, facet)
	}
	// An account id is an exact match on the object's own account (D-76).
	if refs := listsField(digl(egatesGet(t, api, "/workloads"+qs("q", accountB)), "data"), "ref"); len(refs) != 1 || refs[0] != wantB {
		t.Errorf("q=%s = %v, want B's one workload", accountB, refs)
	}

	// Opening B's: B's ARN and account throughout, none of A's objects.
	aOnly := []string{wantA, egatesIdentity(t, l, egatesSharedRole),
		refOf("policy", changesPolicy(t, l, egatesTicketRead)), refOf("policy", changesPolicy(t, l, egatesToolbox))}
	reader := egatesIdentity(t, l, "data-reader")
	detail := egatesGet(t, api, egatesRoute(t, wantB))
	if digs(detail, "data", "ref") != wantB || digs(detail, "data", "arn") != "arn:aws:lambda:"+egatesPrimary+":"+accountB+":function:ticket-tools" ||
		digs(detail, "data", "account", "id") != accountB || digs(detail, "data", "execution_role", "identity") != reader {
		t.Errorf("B's detail = %s", egatesJSON(detail))
	}
	if srcs := digl(detail, "data", "sources"); len(srcs) != 1 || digs(srcs[0], "account_id") != accountB ||
		digs(srcs[0], "integration") != refOf("cloud_connector", b.conn) {
		t.Errorf("B's sources = %s, want B's connector only", egatesJSON(srcs))
	}
	ids := egatesGet(t, api, egatesRoute(t, wantB, "/identities"))
	exec := digl(ids, "data", "execution", "items")
	if len(exec) != 1 || digs(exec[0], "identity", "ref") != reader ||
		digs(exec[0], "identity", "arn") != "arn:aws:iam::"+accountB+":role/data-reader" ||
		digs(exec[0], "identity", "account", "id") != accountB {
		t.Errorf("B's identities = %s, want data-reader in %s", egatesJSON(exec), accountB)
	}
	res := egatesGet(t, api, egatesRoute(t, wantB, "/resources"))
	rrows := digl(res, "data")
	if len(rrows) != 1 || digs(rrows[0], "resource", "text") != egatesTickets {
		t.Fatalf("B's resources = %s", egatesJSON(rrows))
	}
	if g := digl(rrows[0], "grants"); len(g) != 1 || digs(g[0], "via_identity") != reader ||
		digs(g[0], "policy", "name") != "SandboxTickets" {
		t.Errorf("B's grant lines = %s, want one, via data-reader, SandboxTickets", egatesJSON(g))
	}
	graph := egatesGet(t, api, "/graph"+qs("root", wantB, "direction", "forward"))
	for what, body := range map[string]map[string]any{"detail": detail, "identities": ids, "resources": res, "graph": graph} {
		raw := egatesJSON(body)
		for _, ref := range aOnly {
			if strings.Contains(raw, `"`+ref+`"`) {
				t.Errorf("B's %s mentions A's %s", what, ref)
			}
		}
	}
	for _, n := range digl(graph, "data", "nodes") {
		if digs(n, "kind") == "workload" && digs(n, "ref") != wantB {
			t.Errorf("B's graph draws another workload: %s", egatesJSON(n))
		}
	}
}

// E3. Open A's ticket-tools: its Identities tab returns SharedToolRole as the
// execution identity; its Resources tab returns support-tickets/* -- one
// selector -- with TWO grant lines (TicketRead's ReadTickets and ToolboxRead's
// Sid-less statement); the graph draws the same path, claim for claim; the
// path search finds both; and nothing says "can access". The ECS task
// definition shows §5.3's "other" section: its execution role is not the
// identity it runs as.
//
// Safeguards (mutation-checked): two statements granting the same action are
// two grant lines, never one.
func TestP2EgatesE3WorkloadIdentityStatementsResource(t *testing.T) {
	l := newP2Lab(t, "p2-egates-e3", true)
	a := egatesProduction(t, l)
	run := egatesCycle(l, a)
	pub := egatesPublicationOf(t, l, run.ID)
	api := l.api()
	w := egatesWorkload(t, l, "ticket-tools", accountA)
	role := egatesIdentity(t, l, egatesSharedRole)
	tickets := egatesResource(t, l, egatesTickets)
	ticketStmt, toolboxStmt := graphStatementOf(t, l, egatesTicketRead), graphStatementOf(t, l, egatesToolbox)
	var bodies []map[string]any

	// Database: executes_as to SharedToolRole, two grants, two statements,
	// one selector.
	if n := l.count(`SELECT count(*) FROM iga_relationship r JOIN iga_workload w ON w.id = r.source_workload_id
	                  WHERE r.workspace_id = ? AND r.relationship_type = 'executes_as' AND w.id = ? AND r.state = 'current'
	                    AND r.target_identity_account_id = ?`, l.ws, refUUID(t, w), refUUID(t, role)); n != 1 {
		t.Errorf("ticket-tools executes_as SharedToolRole rows = %d, want 1", n)
	}
	if n := l.count(`SELECT count(*) FROM iga_resources WHERE workspace_id = ? AND provider = 'aws' AND display_name = ?`,
		l.ws, egatesTickets); n != 1 {
		t.Errorf("support-tickets/* resources = %d, want one selector", n)
	}
	grants := l.grants()
	if len(grantsOf(grants, egatesTicketRead)) != 1 || len(grantsOf(grants, egatesToolbox)) != 1 {
		t.Errorf("grants = %+v, want one per policy", grants)
	}

	// Detail: the execution role, resolved.
	detail := egatesGet(t, api, egatesRoute(t, w))
	bodies = append(bodies, detail)
	egatesMeta(t, "workload detail", detail, pub.Rev, egatesMicro(pub.PublishedAt))
	if digs(detail, "data", "execution_role", "state") != "resolved" || digs(detail, "data", "execution_role", "identity") != role ||
		digs(detail, "data", "execution_role", "name") != egatesSharedRole {
		t.Errorf("detail execution_role = %s", egatesJSON(dig(detail, "data", "execution_role")))
	}

	// Identities: the execution identity, and nothing mislabelled as one.
	ids := egatesGet(t, api, egatesRoute(t, w, "/identities"))
	bodies = append(bodies, ids)
	exec := digl(ids, "data", "execution", "items")
	if len(exec) != 1 {
		t.Fatalf("execution = %s, want exactly SharedToolRole", egatesJSON(exec))
	}
	e := exec[0]
	if digs(e, "type") != models.RelTypeExecutesAs || digs(e, "identity", "ref") != role ||
		digs(e, "identity", "name") != egatesSharedRole || digs(e, "identity", "kind") != "iam_role" ||
		digs(e, "identity", "arn") != a.roleARN(egatesSharedRole) || digs(e, "identity", "account", "id") != accountA ||
		digs(e, "basis") != "declared" || digs(e, "state") != models.RelCurrent || digs(e, "valid_from") == "" ||
		digs(e, "last_confirmed_at") == "" || num(e, "used_by_count", "value") != 2 || dig(e, "used_by_count", "exact") != true ||
		!strings.HasPrefix(digs(e, "claim"), "relationship:") {
		t.Errorf("execution identity = %s", egatesJSON(e))
	}
	if digs(ids, "data", "execution_role_state") != "resolved" || dig(ids, "data", "execution_role_arn") != nil ||
		len(digl(ids, "data", "other", "items")) != 0 || len(digl(ids, "data", "groups", "items")) != 0 {
		t.Errorf("identities tab = %s", egatesJSON(dig(ids, "data")))
	}

	// Resources: one row per target, one line per grant.
	res := egatesGet(t, api, egatesRoute(t, w, "/resources"))
	bodies = append(bodies, res)
	rows := digl(res, "data")
	if len(rows) != 1 {
		t.Fatalf("resources = %s, want support-tickets/* only", egatesJSON(rows))
	}
	r := rows[0]
	if digs(r, "resource", "ref") != tickets || digs(r, "resource", "text") != egatesTickets ||
		digs(r, "resource", "kind") != "selector" || digs(r, "resource", "service") != "s3" ||
		dig(r, "resource", "account") != nil || dig(r, "resource", "region") != nil ||
		num(r, "restrictions", "deny_statements") != 0 || dig(r, "restrictions", "permissions_boundary") != false {
		t.Errorf("resource row = %s", egatesJSON(r))
	}
	lines := digl(r, "grants")
	if len(lines) != 2 {
		t.Fatalf("grant lines = %s, want TWO (TicketRead and ToolboxRead)", egatesJSON(lines))
	}
	lineOf := map[string]map[string]any{}
	for _, ln := range lines {
		lineOf[digs(ln, "policy", "name")] = ln.(map[string]any)
	}
	for policy, want := range map[string]struct{ sid, stmt string }{
		egatesTicketRead: {"ReadTickets", ticketStmt}, egatesToolbox: {"", toolboxStmt},
	} {
		ln := lineOf[policy]
		if ln == nil || digs(ln, "via_identity") != role || digs(ln, "policy", "kind") != "customer_managed" ||
			digs(ln, "statement", "ref") != want.stmt || digs(ln, "statement", "sid") != want.sid ||
			num(ln, "statement", "index") != 1 || strings.Join(wdetailStrings(dig(ln, "statement", "actions")), ",") != "s3:GetObject" ||
			len(digl(ln, "statement", "not_actions")) != 0 || dig(ln, "statement", "conditional") != false ||
			digs(ln, "target_mode") != "resource" || digs(ln, "state") != models.RelCurrent ||
			!strings.HasPrefix(digs(ln, "claim"), "grant:") {
			t.Errorf("%s grant line = %s, want sid %q statement %s via SharedToolRole", policy, egatesJSON(ln), want.sid, want.stmt)
		}
	}
	if digs(lineOf[egatesTicketRead], "claim") == digs(lineOf[egatesToolbox], "claim") {
		t.Error("the two grant lines share one claim: the grants were merged")
	}

	// The graph draws the same path, claim for claim.
	graph := egatesGet(t, api, "/graph"+qs("root", w, "direction", "forward"))
	bodies = append(bodies, graph)
	nodes := graphNodes(t, digl(graph, "data", "nodes"))
	edges := graphEdges(t, digl(graph, "data", "edges"))
	if ex := graphEdgesOfKind(edges, "executes_as"); len(ex) != 1 || ex[0].Claim != digs(e, "claim") || ex[0].To != role {
		t.Errorf("graph executes_as = %+v, want the Identities tab's claim %s", ex, digs(e, "claim"))
	}
	gotGrants := map[string]string{}
	for _, g := range graphEdgesOfKind(edges, "grant") {
		gotGrants[g.Claim] = g.To
	}
	for _, ln := range lines {
		if gotGrants[digs(ln, "claim")] != digs(ln, "statement", "ref") {
			t.Errorf("the graph has no grant %s -> %s that the Resources tab lists", digs(ln, "claim"), digs(ln, "statement", "ref"))
		}
	}
	if len(gotGrants) != 2 {
		t.Errorf("graph grants = %v, want the two", gotGrants)
	}
	for _, s := range []string{ticketStmt, toolboxStmt} {
		n := nodes[s]
		if n == nil || digs(n, "kind") != "statement" || digs(n, "label") != "s3:GetObject" {
			t.Errorf("statement node %s = %v", s, n)
		}
	}
	if k1, k2 := digs(nodes[ticketStmt], "group_key"), digs(nodes[toolboxStmt], "group_key"); k1 == "" || k1 != k2 {
		t.Errorf("group keys %q / %q, want one shared key (the canvas draws one line; the response keeps two)", k1, k2)
	}
	targets := graphEdgesOfKind(edges, "target")
	if len(targets) != 2 || targets[0].To != tickets || targets[1].To != tickets || targets[0].Mode != "resource" {
		t.Errorf("graph targets = %+v, want both statements -> the one selector", targets)
	}
	if digs(nodes[tickets], "kind") != "selector" {
		t.Errorf("resource node = %v", nodes[tickets])
	}
	path := egatesGet(t, api, "/graph/path"+qs("from", w, "to", tickets))
	bodies = append(bodies, path)
	if digs(path, "data", "outcome") != "found" || len(digl(path, "data", "paths")) != 2 ||
		dig(path, "data", "more_paths") != false || dig(path, "data", "bound_by") != nil {
		t.Errorf("path search = %s, want found, two paths", egatesJSON(dig(path, "data")))
	}
	for _, p := range digl(path, "data", "paths") {
		if kinds := listsField(digl(p, "edges"), "kind"); strings.Join(kinds, ",") != "executes_as,grant,target" {
			t.Errorf("a path's hops = %v, want executes_as, grant, target", kinds)
		}
	}
	// The identity side of the same answer.
	perms := egatesGet(t, api, egatesRoute(t, role, "/permissions"))
	bodies = append(bodies, perms)
	if pols := listsField(digl(perms, "data", "policies"), "name"); strings.Join(egatesSorted(pols), ",") != egatesTicketRead+","+egatesToolbox {
		t.Errorf("SharedToolRole permissions = %v, want TicketRead and ToolboxRead", pols)
	}
	access := egatesGet(t, api, egatesRoute(t, tickets, "/access"))
	bodies = append(bodies, access)
	if n := len(digl(access, "data", "access")); n != 2 {
		t.Errorf("support-tickets/* access rows = %d, want the two grants", n)
	}
	for i, b := range bodies {
		egatesNoAccessWording(t, fmt.Sprintf("response %d", i), b)
	}

	// §5.3 "other": the task definition runs as its task role; its execution
	// role (used by ECS to pull and log) is listed apart, never as execution.
	td := egatesWorkload(t, l, "ticket-worker", "")
	tdIDs := egatesGet(t, api, egatesRoute(t, td, "/identities"))
	if ex := digl(tdIDs, "data", "execution", "items"); len(ex) != 1 || digs(ex[0], "identity", "name") != "TicketTaskRole" {
		t.Errorf("ticket-worker execution = %s, want TicketTaskRole", egatesJSON(ex))
	}
	if other := digl(tdIDs, "data", "other", "items"); len(other) != 1 || digs(other[0], "type") != models.RelTypeTaskExecutionRole ||
		digs(other[0], "identity", "name") != "TicketExecRole" {
		t.Errorf("ticket-worker other = %s, want TicketExecRole as task_execution_role", egatesJSON(other))
	}
}

// E4. Evidence on each grant, on the selector, on priya's group grant, and
// finance/* › Access. Each answer carries the claim's sentence, its status
// (declared; effective access not evaluated), the facts that support it
// (attachment, policy version, Sid, excerpt), freshness, and exactly the
// limitations that apply: selector_may_match_nothing on selectors and never
// resource_existence_not_verified (D-21), permissions_boundary_present for
// priya on the ops grant (D-22), negated_statement on the NotResource grant.
// finance/* is only ever an exclusion: excluded_by, never access or a path.
//
// Safeguards (mutation-checked): exclusions are not destinations; a
// limitation is emitted only when its condition holds.
func TestP2EgatesE4EvidenceAndLimitations(t *testing.T) {
	l := newP2Lab(t, "p2-egates-e4", true)
	a := egatesProduction(t, l)
	a.attach(egatesSharedRole, a.managed("FinanceAll", evidenceDoc(
		`{"Sid":"AllButFinance","Effect":"Allow","Action":"s3:*","NotResource":"arn:aws:s3:::finance/*"}`)))
	run := egatesCycle(l, a)
	api := l.api()
	runRef := refOf("cloud_scan_run", run.ID)
	tickets := egatesResource(t, l, egatesTickets)
	finance := egatesResource(t, l, "arn:aws:s3:::finance/*")
	priya := egatesIdentity(t, l, "priya")

	// Database: every projected edge has evidence.
	for what, q := range map[string]string{
		"grants": `SELECT count(*) FROM iga_access_edges g WHERE g.workspace_id = ? AND g.provider = 'aws'
		           AND NOT EXISTS (SELECT 1 FROM iga_access_edge_evidence x WHERE x.workspace_id = g.workspace_id AND x.access_edge_id = g.id)`,
		"relationships": `SELECT count(*) FROM iga_relationship r WHERE r.workspace_id = ?
		           AND NOT EXISTS (SELECT 1 FROM iga_relationship_evidence x WHERE x.workspace_id = r.workspace_id AND x.relationship_id = r.id)`,
		"assignments": `SELECT count(*) FROM iga_policy_assignment p WHERE p.workspace_id = ?
		           AND NOT EXISTS (SELECT 1 FROM iga_assignment_evidence x WHERE x.workspace_id = p.workspace_id AND x.assignment_id = p.id)`,
	} {
		if n := l.count(q, l.ws); n != 0 {
			t.Errorf("%d %s have no evidence junction row", n, what)
		}
	}

	type grantCase struct {
		holder, policy, sid, sentence, excerptSid string
		codes                                     []string
	}
	for _, c := range []grantCase{
		{egatesSharedRole, egatesTicketRead, "ReadTickets",
			"SharedToolRole is granted s3:GetObject on support-tickets/* by TicketRead (statement ReadTickets).", "ReadTickets",
			[]string{"effective_access_not_evaluated", "organizations_not_collected", "selector_may_match_nothing"}},
		{egatesSharedRole, egatesToolbox, "",
			"SharedToolRole is granted s3:GetObject on support-tickets/* by ToolboxRead (statement 1).", "",
			[]string{"effective_access_not_evaluated", "organizations_not_collected", "selector_may_match_nothing"}},
		{egatesSharedRole, "FinanceAll", "AllButFinance",
			"SharedToolRole is granted s3:* on all resources except finance/* by FinanceAll (statement AllButFinance).", "AllButFinance",
			[]string{"effective_access_not_evaluated", "negated_statement", "organizations_not_collected", "selector_may_match_nothing"}},
		{"ops", "OpsRead", "ReadOps",
			"ops is granted s3:GetObject on ops-bucket/* by OpsRead (statement ReadOps).", "ReadOps",
			[]string{"effective_access_not_evaluated", "organizations_not_collected", "permissions_boundary_present", "selector_may_match_nothing"}},
	} {
		claim := evidenceGrant(t, l, c.holder, c.policy, c.sid)
		body := evidenceGet(t, api, claim)
		egatesNoAccessWording(t, "evidence "+c.policy, body)
		d := dig(body, "data")
		if digs(d, "claim", "ref") != claim || digs(d, "claim", "sentence") != c.sentence {
			t.Errorf("%s claim = %s, want %q", c.policy, egatesJSON(dig(d, "claim")), c.sentence)
		}
		if digs(d, "status", "basis") != "declared" || digs(d, "status", "lifecycle") != models.RelCurrent ||
			digs(d, "status", "collection") != "complete" || digs(d, "status", "effective_access") != "not_evaluated" {
			t.Errorf("%s status = %s", c.policy, egatesJSON(dig(d, "status")))
		}
		facts := digl(d, "facts")
		var attached, stmt map[string]any
		for _, f := range facts {
			m := f.(map[string]any)
			if dig(m, "statement_excerpt") != nil {
				stmt = m
			} else {
				attached = m
			}
			if digs(m, "account_id") != accountA || digs(m, "observed_in_run") != runRef ||
				digs(m, "source_api") != "iam:GetAccountAuthorizationDetails" || digs(m, "last_confirmed_at") == "" {
				t.Errorf("%s fact = %s, want account A, observed in %s", c.policy, egatesJSON(m), runRef)
			}
		}
		if len(facts) != 2 || attached == nil || stmt == nil ||
			digs(attached, "fact") != c.holder+" has "+c.policy+" attached" ||
			digs(stmt, "policy_version") != "v3" || digs(stmt, "policy", "name") != c.policy ||
			digs(stmt, "statement", "sid") != c.sid || digs(stmt, "statement_excerpt", "Sid") != c.excerptSid ||
			digs(stmt, "statement_excerpt", "Effect") != "Allow" {
			t.Errorf("%s facts = %s, want the attachment and the statement (version v3, Sid %q, excerpt)", c.policy, egatesJSON(facts), c.sid)
		}
		if digs(d, "freshness", "first_seen_at") == "" || digs(d, "freshness", "last_confirmed_at") == "" ||
			dig(d, "freshness", "stale_since") != nil || dig(d, "freshness", "valid_to") != nil {
			t.Errorf("%s freshness = %s", c.policy, egatesJSON(dig(d, "freshness")))
		}
		if got := egatesSorted(evidenceCodes(body)); strings.Join(got, ",") != strings.Join(c.codes, ",") {
			t.Errorf("%s limitations = %v, want exactly %v", c.policy, got, c.codes)
		}
		if dig(d, "raw") != nil {
			t.Errorf("%s raw = %v without include=raw, want null", c.policy, dig(d, "raw"))
		}
		if c.policy == "OpsRead" {
			pb := evidenceLim(body, "permissions_boundary_present")
			if pb == nil || dig(pb, "holder") != false || num(pb, "member_count") != 1 ||
				strings.Join(evidenceStrings(dig(pb, "members")), ",") != priya {
				t.Errorf("ops grant permissions_boundary_present = %s, want it for priya (a member, not the holder)", egatesJSON(pb))
			}
		}
		if c.policy == "FinanceAll" {
			if neg := evidenceLim(body, "negated_statement"); strings.Join(evidenceStrings(dig(neg, "negations")), ",") != "NotResource" {
				t.Errorf("negated_statement = %s, want NotResource", egatesJSON(neg))
			}
		}
	}
	// The raw record only on request.
	raw := evidenceGet(t, api, evidenceGrant(t, l, egatesSharedRole, egatesTicketRead, "ReadTickets"), "include", "raw")
	if len(digl(raw, "data", "raw")) == 0 {
		t.Errorf("include=raw returned no raw records: %s", egatesJSON(dig(raw, "data", "raw")))
	}

	// The selector, as a target claim and as a node.
	target := evidenceGet(t, api, evidenceTarget(t, l, egatesTicketRead, "ReadTickets", egatesTickets))
	if digs(target, "data", "claim", "sentence") != "Statement ReadTickets of TicketRead names support-tickets/*." ||
		strings.Join(egatesSorted(evidenceCodes(target)), ",") != "organizations_not_collected,selector_may_match_nothing" {
		t.Errorf("target evidence = %s", egatesJSON(dig(target, "data")))
	}
	node := evidenceGet(t, api, tickets)
	if strings.Join(egatesSorted(evidenceCodes(node)), ",") != "organizations_not_collected,selector_may_match_nothing" ||
		len(digl(node, "data", "facts")) != 2 {
		t.Errorf("selector evidence = %s, want its two naming statements as facts", egatesJSON(dig(node, "data")))
	}

	// finance/* › Access: an exclusion, never access.
	fin := egatesGet(t, api, egatesRoute(t, finance, "/access"))
	if len(digl(fin, "data", "access")) != 0 || num(fin, "meta", "total") != 0 {
		t.Errorf("finance/* access = %s, want none", egatesJSON(dig(fin, "data", "access")))
	}
	excl := digl(fin, "data", "excluded_by")
	if len(excl) != 1 || digs(excl[0], "statement", "sid") != "AllButFinance" || digs(excl[0], "policy", "name") != "FinanceAll" ||
		strings.Join(wdetailStrings(dig(excl[0], "holders")), ",") != egatesIdentity(t, l, egatesSharedRole) {
		t.Errorf("finance/* excluded_by = %s, want AllButFinance held by SharedToolRole", egatesJSON(excl))
	}
	if fd := egatesGet(t, api, egatesRoute(t, finance)); num(fd, "data", "named_by_count", "value") != 0 ||
		num(fd, "data", "excluded_by_count", "value") != 1 {
		t.Errorf("finance/* counts = named %v excluded %v, want 0 and 1",
			dig(fd, "data", "named_by_count"), dig(fd, "data", "excluded_by_count"))
	}
	w := egatesWorkload(t, l, "ticket-tools", accountA)
	if p := egatesGet(t, api, "/graph/path"+qs("from", w, "to", finance)); digs(p, "data", "outcome") != "none_exists" ||
		len(digl(p, "data", "paths")) != 0 {
		t.Errorf("path to finance/* = %s, want none_exists", egatesJSON(dig(p, "data")))
	}
	g := egatesGet(t, api, "/graph"+qs("root", w, "direction", "forward"))
	for _, e := range graphEdges(t, digl(g, "data", "edges")) {
		if e.To == finance {
			t.Errorf("the graph draws an edge to finance/*: %+v", e)
		}
	}
	if _, drawn := graphNodes(t, digl(g, "data", "nodes"))[finance]; drawn {
		t.Error("the graph draws finance/* as a node; it is an exclusion on its statement")
	}
	var excluded bool
	for _, n := range digl(g, "data", "nodes") {
		if digs(n, "sid") == "AllButFinance" {
			for _, x := range digl(n, "exclusions") {
				excluded = excluded || strings.Contains(egatesJSON(x), finance)
			}
		}
	}
	if !excluded {
		t.Error("AllButFinance's statement node does not list finance/* in exclusions")
	}
}

// E5. SharedToolRole › Used by lists both workloads (two executes_as rows to
// ONE identity); the role is one row in the identity list, and every count of
// its users says 2.
//
// Safeguards (mutation-checked): a relationship's key names its source
// workload, so the second executes_as does not overwrite the first.
func TestP2EgatesE5TwoWorkloadsShareOneRole(t *testing.T) {
	l := newP2Lab(t, "p2-egates-e5", true)
	a := egatesProduction(t, l)
	egatesCycle(l, a)
	api := l.api()
	role := egatesIdentity(t, l, egatesSharedRole)
	tt, rt := egatesWorkload(t, l, "ticket-tools", accountA), egatesWorkload(t, l, "refund-tools", accountA)

	if n := l.count(`SELECT count(*) FROM iga_relationship WHERE workspace_id = ? AND relationship_type = 'executes_as'
	                  AND target_identity_account_id = ? AND state = 'current'`, l.ws, refUUID(t, role)); n != 2 {
		t.Errorf("executes_as rows to SharedToolRole = %d, want 2", n)
	}
	used := egatesGet(t, api, egatesRoute(t, role, "/used-by"))
	items := digl(used, "data", "workloads", "items")
	got := map[string]map[string]any{}
	for _, it := range items {
		got[digs(it, "workload", "ref")] = it.(map[string]any)
	}
	if len(items) != 2 || got[tt] == nil || got[rt] == nil || num(used, "data", "workloads", "total") != 2 {
		t.Fatalf("used-by workloads = %s, want ticket-tools and refund-tools", egatesJSON(items))
	}
	for ref, it := range got {
		if digs(it, "type") != models.RelTypeExecutesAs || digs(it, "state") != models.RelCurrent ||
			digs(it, "workload", "account", "id") != accountA || !strings.HasPrefix(digs(it, "claim"), "relationship:") {
			t.Errorf("used-by %s = %s", ref, egatesJSON(it))
		}
	}
	if digs(got[tt], "claim") == digs(got[rt], "claim") {
		t.Error("both workloads carry one relationship claim")
	}
	// One role, counted once, used by two.
	list := egatesGet(t, api, "/identities"+qs("q", egatesSharedRole))
	if rows := digl(list, "data"); len(rows) != 1 || digs(rows[0], "ref") != role || num(rows[0], "used_by_count", "value") != 2 {
		t.Errorf("/identities?q=SharedToolRole = %s, want the role once, used by 2", egatesJSON(rows))
	}
	if d := egatesGet(t, api, egatesRoute(t, role)); num(d, "data", "used_by_count", "value") != 2 ||
		dig(d, "data", "used_by_count", "exact") != true {
		t.Errorf("identity detail used_by_count = %v, want {2, exact}", dig(d, "data", "used_by_count"))
	}
	for _, w := range []string{tt, rt} {
		ex := digl(egatesGet(t, api, egatesRoute(t, w, "/identities")), "data", "execution", "items")
		if len(ex) != 1 || digs(ex[0], "identity", "ref") != role || num(ex[0], "used_by_count", "value") != 2 {
			t.Errorf("%s execution = %s, want SharedToolRole used by 2 (\"shared with 1 other workload\")", w, egatesJSON(ex))
		}
	}
	if n := len(graphRefsOfKind(digl(egatesGet(t, api, "/graph"+qs("root", role, "direction", "reverse")), "data", "nodes"), "workload")); n != 2 {
		t.Errorf("the role's reverse graph draws %d workloads, want 2", n)
	}
}
