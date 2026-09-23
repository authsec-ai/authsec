package integration

// T6.3 -- GET /resources/:id/access (§5.3 Resources), through the REAL route
// table over graphs the REAL scan worker and projector built (the P2-0 lab).
// Gates: E3 (the selector named by two policies' statements: two lines for one
// holder), E6 (a detached grant ends; include_ended shows it), E4/B19 (a
// NotResource statement EXCLUDES: no access row, listed under excluded_by),
// B10 (a Deny is a restriction, never access), D-18 (a group-held grant is
// also a row per member, via_group), D-62 (a cursor pages only its own
// resource).

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

/* --------------------------------- helpers --------------------------------- */

// rdetailGet calls a route and requires 200.
func rdetailGet(t *testing.T, api *readAPI, path string) map[string]any {
	t.Helper()
	code, body := api.get(path)
	mustStatus(t, "GET "+path, code, body, 200)
	return body
}

// rdetailResource is a reference's typed ref, found by its text (the active
// object, else the newest retired one).
func rdetailResource(t *testing.T, l *p2Lab, text string) string {
	t.Helper()
	id, _ := l.resourceID(text)
	if id == uuid.Nil {
		t.Fatalf("setup: no resource reference %q in the graph", text)
	}
	return refOf("resource", id)
}

// rdetailIdentity is an active AWS identity's typed ref, by name.
func rdetailIdentity(t *testing.T, l *p2Lab, name string) string {
	t.Helper()
	var ids []uuid.UUID
	l.db.Raw(`SELECT id FROM iga_identity_accounts WHERE workspace_id = ? AND provider = 'aws'
	          AND display_name = ? AND lifecycle = 'active'`, l.ws, name).Scan(&ids)
	if len(ids) != 1 {
		t.Fatalf("setup: %d active identities named %q, want 1", len(ids), name)
	}
	return refOf("identity", ids[0])
}

// rdetailLines renders access rows, in order, as holder|policy|sid|via|state.
func rdetailLines(rows []any) []string {
	out := []string{}
	for _, r := range rows {
		via := "-"
		if dig(r, "via_group") != nil {
			via = "via " + digs(r, "via_group", "name")
		}
		out = append(out, strings.Join([]string{digs(r, "holder", "name"), digs(r, "policy", "name"),
			digs(r, "statement", "sid"), via, digs(r, "state")}, "|"))
	}
	return out
}

// rdetailRestrictionLines renders excluded_by / deny_statements_naming, in
// order, as policy|sid|holder refs.
func rdetailRestrictionLines(entries []any) []string {
	out := []string{}
	for _, e := range entries {
		var hs []string
		for _, h := range digl(e, "holders") {
			hs = append(hs, h.(string))
		}
		out = append(out, strings.Join([]string{digs(e, "policy", "name"), digs(e, "statement", "sid"),
			strings.Join(hs, ",")}, "|"))
	}
	return out
}

// rdetailGrantOf is the id of the grant an identity holds on a policy's
// statement with this Sid ("" for none), in any state, newest first.
func rdetailGrantOf(t *testing.T, l *p2Lab, holder, policy, sid string) string {
	t.Helper()
	var ids []uuid.UUID
	l.db.Raw(`SELECT g.id FROM iga_access_edges g
	            JOIN iga_entitlements e ON e.workspace_id = g.workspace_id AND e.id = g.entitlement_id
	            JOIN iga_policy p ON p.workspace_id = e.workspace_id AND p.id = e.policy_id
	            JOIN iga_identity_accounts ia ON ia.workspace_id = g.workspace_id AND ia.id = g.subject_identity_account_id
	           WHERE g.workspace_id = ? AND ia.display_name = ? AND p.display_name = ? AND e.sid = ?
	           ORDER BY g.valid_from DESC, g.id LIMIT 1`, l.ws, holder, policy, sid).Scan(&ids)
	if len(ids) != 1 {
		t.Fatalf("setup: no grant for %s on %s/%q", holder, policy, sid)
	}
	return refOf("grant", ids[0])
}

/* ---------------------------------- tests ---------------------------------- */

// E3 and E6, read side. The support-tickets/* selector is named by two
// policies' statements (TicketRead's ReadTickets and ToolboxRead's Sid-less
// statement), both held by SharedToolRole: two access rows for one holder --
// never merged -- and OtherRole's own row. Paged BY HOLDER: a holder's rows
// never straddle two pages. Then TicketRead is detached from SharedToolRole:
// its grant ends and leaves the default view, and include_ended brings it
// back, marked ended.
func TestP2RDetailAccessTwoStatementsOneHolder(t *testing.T) {
	l := newP2Lab(t, "p2-rdetail-e3", true)
	a := l.account(accountA)
	a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	a.role("OtherRole", "AROAOTHERROLEOTHERRO")
	ticket := a.managed("TicketRead", docTicketRead)
	a.attach("SharedToolRole", ticket)
	a.attach("OtherRole", ticket)
	a.attach("SharedToolRole", a.managed("ToolboxRead", docToolboxRead))
	// A second resource, for the cursor-binding check.
	a.attach("OtherRole", a.managed("ListTickets", `{"Version":"2012-10-17","Statement":[{"Sid":"List",`+
		`"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::support-tickets"}]}`))
	l.scanAndProject(a)
	api := l.api()

	tickets := rdetailResource(t, l, "arn:aws:s3:::support-tickets/*")
	shared := rdetailIdentity(t, l, "SharedToolRole")
	if perm := api.requiredPermission("GET", "/resources/"+tickets+"/access"); perm != "iga:read" {
		t.Errorf("/resources/:id/access demands %q, want iga:read", perm)
	}

	body := rdetailGet(t, api, "/resources/"+tickets+"/access")
	rows := digl(body, "data", "access")
	want := []string{
		"OtherRole|TicketRead|ReadTickets|-|current",
		"SharedToolRole|TicketRead|ReadTickets|-|current",
		"SharedToolRole|ToolboxRead||-|current",
	}
	if got := rdetailLines(rows); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("access =\n%s\nwant (one row per (holder, grant), by holder name, never merged)\n%s",
			strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	r := rows[1]
	if digs(r, "holder", "ref") != shared || digs(r, "holder", "kind") != "iam_role" ||
		digs(r, "holder", "arn") != a.roleARN("SharedToolRole") ||
		digs(r, "holder", "account", "id") != accountA || dig(r, "holder", "account", "connected") != true ||
		digs(r, "holder", "account", "label") != "acct-"+accountA {
		t.Errorf("holder = %v, want SharedToolRole with its ARN and connected account", dig(r, "holder"))
	}
	if g := rdetailGrantOf(t, l, "SharedToolRole", "TicketRead", "ReadTickets"); digs(r, "grant", "claim") != g ||
		digs(r, "grant", "state") != "current" || digs(r, "grant", "valid_from") == "" {
		t.Errorf("grant = %v, want %s current with valid_from", dig(r, "grant"), g)
	}
	if !strings.HasPrefix(digs(r, "policy", "ref"), "policy:") || digs(r, "policy", "kind") != "customer_managed" {
		t.Errorf("policy = %v, want a customer_managed policy ref", dig(r, "policy"))
	}
	st := dig(r, "statement")
	if !strings.HasPrefix(digs(st, "ref"), "statement:") || num(st, "index") != 1 ||
		fmt.Sprint(dig(st, "actions")) != "[s3:GetObject]" || fmt.Sprint(dig(st, "not_actions")) != "[]" ||
		dig(st, "conditional") != false {
		t.Errorf("statement = %v, want index 1 (1-based, D-84), actions [s3:GetObject], not_actions [], unconditional", st)
	}
	if dig(r, "via_group") != nil {
		t.Errorf("via_group = %v on a directly held grant, want null", dig(r, "via_group"))
	}
	if digs(rows[1], "statement", "ref") == digs(rows[2], "statement", "ref") ||
		digs(rows[1], "grant", "claim") == digs(rows[2], "grant", "claim") {
		t.Error("the two SharedToolRole rows share a statement or a grant: merged grants")
	}
	m := dig(body, "meta")
	if num(m, "total") != 2 || dig(m, "total_known") != true || num(m, "limit") != 100 ||
		dig(m, "next_cursor") != nil || digs(m, "graph_state") != "published" || num(m, "rev") != 1 {
		t.Errorf("meta = %v, want total 2 holders, limit 100, no next page, rev 1", m)
	}
	if cov, ok := dig(m, "coverage").([]any); !ok || len(cov) != 0 {
		t.Errorf("meta.coverage = %v, want [] after a clean scan", dig(m, "coverage"))
	}
	if ex := digl(body, "data", "excluded_by"); ex == nil || len(ex) != 0 || dig(body, "data", "excluded_by_more") != false {
		t.Errorf("excluded_by = %v, want [] (not null)", dig(body, "data", "excluded_by"))
	}
	if dn := digl(body, "data", "deny_statements_naming"); dn == nil || len(dn) != 0 {
		t.Errorf("deny_statements_naming = %v, want []", dig(body, "data", "deny_statements_naming"))
	}

	// Paged by holder: limit=1 is one HOLDER per page, all of its rows.
	p1 := rdetailGet(t, api, "/resources/"+tickets+"/access"+qs("limit", "1"))
	next, _ := dig(p1, "meta", "next_cursor").(string)
	if got := rdetailLines(digl(p1, "data", "access")); strings.Join(got, ",") != want[0] || next == "" {
		t.Fatalf("page 1 = %v cursor %q, want OtherRole's row and a cursor", got, next)
	}
	p2 := rdetailGet(t, api, "/resources/"+tickets+"/access"+qs("limit", "1", "cursor", next))
	if got := rdetailLines(digl(p2, "data", "access")); strings.Join(got, ",") != want[1]+","+want[2] ||
		dig(p2, "meta", "next_cursor") != nil {
		t.Errorf("page 2 = %v (cursor %v), want BOTH of SharedToolRole's rows and no further page", got, dig(p2, "meta", "next_cursor"))
	}
	// D-62: the cursor carries the resource -- it cannot page another one.
	bucket := rdetailResource(t, l, "arn:aws:s3:::support-tickets")
	if code, b := api.get("/resources/" + bucket + "/access" + qs("limit", "1", "cursor", next)); code != 400 || errCode(b) != "cursor_invalid" {
		t.Errorf("another resource's cursor = %d %v, want 400 cursor_invalid", code, b)
	}
	// ... nor a different filter set.
	if code, b := api.get("/resources/" + tickets + "/access" + qs("limit", "1", "include_ended", "true", "cursor", next)); code != 400 || errCode(b) != "cursor_invalid" {
		t.Errorf("cursor with include_ended added = %d %v, want 400 cursor_invalid", code, b)
	}

	// E6: detach TicketRead from SharedToolRole. The path remains through
	// ToolboxRead; the ended grant is not access any more.
	a.detach("SharedToolRole", ticket)
	l.scanAndProject(a)
	body = rdetailGet(t, api, "/resources/"+tickets+"/access")
	if got := rdetailLines(digl(body, "data", "access")); strings.Join(got, ",") != want[0]+","+want[2] {
		t.Errorf("access after the detach = %v, want OtherRole's row and SharedToolRole's ToolboxRead line", got)
	}
	ended := rdetailGet(t, api, "/resources/"+tickets+"/access"+qs("include_ended", "true"))
	wantEnded := []string{want[0], "SharedToolRole|TicketRead|ReadTickets|-|ended", want[2]}
	if got := rdetailLines(digl(ended, "data", "access")); strings.Join(got, ",") != strings.Join(wantEnded, ",") {
		t.Errorf("include_ended access = %v, want %v", got, wantEnded)
	}
	if r := digl(ended, "data", "access")[1]; digs(r, "grant", "state") != "ended" {
		t.Errorf("the detached grant = %v, want state ended", dig(r, "grant"))
	}
}

// E4 / B19, read side. AllButFinance allows s3:* with NotResource finance/*:
// its grant's destination is the implicit "*" selector, and finance/* is an
// EXCLUSION. finance/* › Access has no access row and lists the statement
// under excluded_by. The same policy's Deny with NotResource finance/* names
// finance/* in NEITHER list -- NotResource is always an exclusion -- while it
// does name "*" positively, so it is a Deny naming "*".
func TestP2RDetailNotResourceExcludes(t *testing.T) {
	l := newP2Lab(t, "p2-rdetail-notresource", true)
	a := l.account(accountA)
	a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	a.attach("SharedToolRole", a.managed("AllButFinance", `{"Version":"2012-10-17","Statement":[`+
		`{"Sid":"AllButFinance","Effect":"Allow","Action":"s3:*","NotResource":"arn:aws:s3:::finance/*"},`+
		`{"Sid":"NoDeletesOutsideFinance","Effect":"Deny","Action":"s3:DeleteObject","NotResource":"arn:aws:s3:::finance/*"},`+
		`{"Sid":"ReportsExceptDelete","Effect":"Allow","NotAction":"s3:DeleteObject","Resource":"arn:aws:s3:::reports/*",`+
		`"Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`))
	// OldExclusion also excludes finance/*, then is deleted: its statement
	// retires, and a retired statement is no restriction.
	old := a.managed("OldExclusion", `{"Version":"2012-10-17","Statement":[{"Sid":"Old","Effect":"Allow",`+
		`"Action":"s3:GetObject","NotResource":"arn:aws:s3:::finance/*"}]}`)
	a.attach("SharedToolRole", old)
	l.scanAndProject(a)
	a.detach("SharedToolRole", old)
	delete(a.iam.managedPolicies, old)
	l.scanAndProject(a)
	if n := l.count(`SELECT count(*) FROM iga_entitlements WHERE workspace_id = ? AND sid = 'Old' AND lifecycle = 'retired'`, l.ws); n != 1 {
		t.Fatalf("setup: OldExclusion's statement is not retired (%d)", n)
	}
	api := l.api()
	shared := rdetailIdentity(t, l, "SharedToolRole")

	finance := rdetailResource(t, l, "arn:aws:s3:::finance/*")
	body := rdetailGet(t, api, "/resources/"+finance+"/access")
	if rows := digl(body, "data", "access"); len(rows) != 0 {
		t.Errorf("finance/* access = %v, want none: a NotResource entry excludes, it never grants", rdetailLines(rows))
	}
	if num(body, "meta", "total") != 0 || dig(body, "meta", "total_known") != true {
		t.Errorf("meta = %v, want total 0: excluded_by is never counted as access", body["meta"])
	}
	if got := rdetailRestrictionLines(digl(body, "data", "excluded_by")); strings.Join(got, "\n") != "AllButFinance|AllButFinance|"+shared {
		t.Errorf("excluded_by = %v, want exactly the Allow statement, held by SharedToolRole", got)
	}
	ex := dig(body, "data", "excluded_by", 0, "statement")
	if num(ex, "index") != 1 || fmt.Sprint(dig(ex, "actions")) != "[s3:*]" || dig(body, "data", "excluded_by", 0, "holders_more") != false {
		t.Errorf("excluded_by statement = %v, want index 1 and actions [s3:*]", ex)
	}
	if got := rdetailRestrictionLines(digl(body, "data", "deny_statements_naming")); len(got) != 0 {
		t.Errorf("deny_statements_naming = %v, want none: the Deny's NotResource EXCLUDES finance/* (D-17)", got)
	}
	detail := rdetailGet(t, api, "/resources/"+finance)
	if num(detail, "data", "named_by_count", "value") != 0 || num(detail, "data", "excluded_by_count", "value") != 1 {
		t.Errorf("finance/* counts = %v / %v, want named 0, excluded 1", dig(detail, "data", "named_by_count"),
			dig(detail, "data", "excluded_by_count"))
	}

	// "*" is the destination: the Allow's grant is access there, and the Deny
	// names it positively.
	star := rdetailResource(t, l, "*")
	body = rdetailGet(t, api, "/resources/"+star+"/access")
	if got := rdetailLines(digl(body, "data", "access")); strings.Join(got, ",") != "SharedToolRole|AllButFinance|AllButFinance|-|current" {
		t.Errorf("* access = %v, want the one grant (never the Deny)", got)
	}
	if got := rdetailRestrictionLines(digl(body, "data", "deny_statements_naming")); strings.Join(got, ",") != "AllButFinance|NoDeletesOutsideFinance|"+shared {
		t.Errorf("* deny_statements_naming = %v, want the Deny statement", got)
	}
	if got := rdetailRestrictionLines(digl(body, "data", "excluded_by")); len(got) != 0 {
		t.Errorf("* excluded_by = %v, want none", got)
	}

	// A NotAction statement renders its NotAction, not its Action, and says
	// it is conditional.
	body = rdetailGet(t, api, "/resources/"+rdetailResource(t, l, "arn:aws:s3:::reports/*")+"/access")
	st := dig(body, "data", "access", 0, "statement")
	if digs(st, "sid") != "ReportsExceptDelete" || num(st, "index") != 3 || fmt.Sprint(dig(st, "actions")) != "[]" ||
		fmt.Sprint(dig(st, "not_actions")) != "[s3:DeleteObject]" || dig(st, "conditional") != true {
		t.Errorf("reports/* statement = %v, want index 3, actions [], not_actions [s3:DeleteObject], conditional", st)
	}
}

// B10, read side. A Deny statement naming b/* is listed under
// deny_statements_naming with its holder, and is never an access row -- even
// when a projector defect writes a grant on it: every access read joins the
// statement with effect = 'allow' (§3 rule 7). The fakes cannot produce that
// grant (UpsertGrant refuses it), so the test inserts it directly.
func TestP2RDetailDenyIsARestrictionNotAccess(t *testing.T) {
	l := newP2Lab(t, "p2-rdetail-deny", true)
	a := l.account(accountA)
	a.role("DenyRole", "AROADENYROLEDENYROLE")
	a.role("FormerRole", "AROAFORMERROLEFORMER")
	policy := a.managed("ReadButNotDelete", `{"Version":"2012-10-17","Statement":[`+
		`{"Sid":"Read","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"},`+
		`{"Sid":"NoDelete","Effect":"Deny","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::b/*"}]}`)
	a.attach("DenyRole", policy)
	a.attach("FormerRole", policy)
	l.scanAndProject(a)
	// FormerRole no longer holds the policy: its assignment ends, and it stops
	// being a holder of the Deny (the policy itself stays: DenyRole holds it).
	a.detach("FormerRole", policy)
	l.scanAndProject(a)
	api := l.api()
	holder := rdetailIdentity(t, l, "DenyRole")
	former := rdetailIdentity(t, l, "FormerRole")
	res := rdetailResource(t, l, "arn:aws:s3:::b/*")
	if got := rdetailRestrictionLines(digl(rdetailGet(t, api, "/resources/"+res+"/access"+qs("include_ended", "true")),
		"data", "deny_statements_naming")); strings.Join(got, ",") != "ReadButNotDelete|NoDelete|"+holder+","+former {
		t.Errorf("include_ended deny_statements_naming = %v, want the ended holder listed too", got)
	}

	check := func(when string) {
		t.Helper()
		body := rdetailGet(t, api, "/resources/"+res+"/access")
		if got := rdetailLines(digl(body, "data", "access")); strings.Join(got, ",") != "DenyRole|ReadButNotDelete|Read|-|current" {
			t.Errorf("%s: access = %v, want only the Allow statement's grant", when, got)
		}
		if got := rdetailRestrictionLines(digl(body, "data", "deny_statements_naming")); strings.Join(got, ",") != "ReadButNotDelete|NoDelete|"+holder {
			t.Errorf("%s: deny_statements_naming = %v, want the Deny with its holder", when, got)
		}
		if got := rdetailRestrictionLines(digl(body, "data", "excluded_by")); len(got) != 0 {
			t.Errorf("%s: excluded_by = %v, want none", when, got)
		}
		if num(body, "meta", "total") != 1 {
			t.Errorf("%s: total = %v, want 1 holder", when, dig(body, "meta", "total"))
		}
	}
	check("projected")

	// The defect: a grant on the Deny statement, through the same assignment.
	if err := l.db.Exec(`INSERT INTO iga_access_edges (workspace_id, subject_kind, subject_id, subject_identity_account_id,
	                         provider, entitlement_id, assignment_id, direction, path_kind, calculation_state,
	                         effective_conclusion, basis, state, source_key, partition_key, connector_id)
	                     SELECT g.workspace_id, g.subject_kind, g.subject_id, g.subject_identity_account_id, g.provider,
	                            (SELECT id FROM iga_entitlements WHERE workspace_id = g.workspace_id AND sid = 'NoDelete'),
	                            g.assignment_id, g.direction, g.path_kind, g.calculation_state, g.effective_conclusion,
	                            g.basis, g.state, g.source_key || '|defect', g.partition_key, g.connector_id
	                       FROM iga_access_edges g
	                       JOIN iga_entitlements e ON e.workspace_id = g.workspace_id AND e.id = g.entitlement_id
	                      WHERE g.workspace_id = ? AND e.sid = 'Read' AND g.state = 'current'`, l.ws).Error; err != nil {
		t.Fatalf("seed the defective Deny grant: %v", err)
	}
	if n := l.count(`SELECT count(*) FROM iga_access_edges g JOIN iga_entitlements e ON e.id = g.entitlement_id
	                  WHERE g.workspace_id = ? AND e.effect = 'deny'`, l.ws); n != 1 {
		t.Fatalf("setup: %d grants on the Deny statement, want the one seeded", n)
	}
	check("with a grant on the Deny statement")
}

// D-18. The ops group holds OpsRead; priya and bob are members, carol is not.
// ops-bucket/* › Access: the group's own row, and one row per member with
// via_group = ops and the membership claim. bob then leaves the group: his row
// leaves the default view, and include_ended shows it ended. A grant that
// BEGINS after bob left (LaterRead, attached one scan later) never gets a row
// for bob, even with include_ended: the periods never overlapped.
func TestP2RDetailGroupHeldGrantExpandsToMembers(t *testing.T) {
	l := newP2Lab(t, "p2-rdetail-group", true)
	a := l.account(accountA)
	s3aUser(a, "priya", "AIDAPRIYAPRIYAPRIYA1")
	s3aUser(a, "bob", "AIDABOBBOBBOBBOBBOB1")
	s3aUser(a, "carol", "AIDACAROLCAROLCAROL1")
	s3aGroup(a, "ops", "AGPAOPSOPSOPSOPSOPS1")
	s3aGroupAttach(t, a, "ops", a.managed("OpsRead", `{"Version":"2012-10-17","Statement":[{"Sid":"OpsRead",`+
		`"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::ops-bucket/*"}]}`))
	a.iam.userGroups["priya"] = []string{"ops"}
	a.iam.userGroups["bob"] = []string{"ops"}
	l.scanAndProject(a)
	api := l.api()
	ops := rdetailIdentity(t, l, "ops")
	res := rdetailResource(t, l, "arn:aws:s3:::ops-bucket/*")

	body := rdetailGet(t, api, "/resources/"+res+"/access")
	rows := digl(body, "data", "access")
	want := []string{
		"bob|OpsRead|OpsRead|via ops|current",
		"ops|OpsRead|OpsRead|-|current",
		"priya|OpsRead|OpsRead|via ops|current",
	}
	if got := rdetailLines(rows); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("access =\n%s\nwant the group's row and one per member, by holder name\n%s",
			strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	groupGrant := digs(rows[1], "grant", "claim")
	for _, i := range []int{0, 2} {
		r := rows[i]
		if digs(r, "holder", "kind") != "iam_user" || digs(r, "via_group", "ref") != ops ||
			digs(r, "grant", "claim") != groupGrant || digs(r, "via_group", "membership", "state") != "current" ||
			!strings.HasPrefix(digs(r, "via_group", "membership", "claim"), "relationship:") ||
			digs(r, "via_group", "membership", "valid_from") == "" {
			t.Errorf("member row %v: want an iam_user holder, via_group ops with its membership claim, and the group's grant", r)
		}
	}
	if num(body, "meta", "total") != 3 {
		t.Errorf("total = %v, want 3 holders", dig(body, "meta", "total"))
	}

	// bob leaves ops.
	a.iam.userGroups["bob"] = nil
	l.scanAndProject(a)
	body = rdetailGet(t, api, "/resources/"+res+"/access")
	if got := rdetailLines(digl(body, "data", "access")); strings.Join(got, ",") != want[1]+","+want[2] {
		t.Errorf("access after bob left = %v, want ops and priya only", got)
	}
	body = rdetailGet(t, api, "/resources/"+res+"/access"+qs("include_ended", "true"))
	rows = digl(body, "data", "access")
	if got := rdetailLines(rows); strings.Join(got, ",") != "bob|OpsRead|OpsRead|via ops|ended,"+want[1]+","+want[2] {
		t.Fatalf("include_ended access = %v, want bob's row back, ended", got)
	}
	if digs(rows[0], "grant", "state") != "current" || digs(rows[0], "via_group", "membership", "state") != "ended" {
		t.Errorf("bob's row: grant %v membership %v, want the grant current beside the ended membership",
			dig(rows[0], "grant", "state"), dig(rows[0], "via_group", "membership", "state"))
	}

	// A grant that began after bob left never reached him.
	s3aGroupAttach(t, a, "ops", a.managed("LaterRead", `{"Version":"2012-10-17","Statement":[{"Sid":"LaterRead",`+
		`"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::later-bucket/*"}]}`))
	l.scanAndProject(a)
	later := rdetailResource(t, l, "arn:aws:s3:::later-bucket/*")
	body = rdetailGet(t, api, "/resources/"+later+"/access"+qs("include_ended", "true"))
	if got := rdetailLines(digl(body, "data", "access")); strings.Join(got, ",") != "ops|LaterRead|LaterRead|-|current,priya|LaterRead|LaterRead|via ops|current" {
		t.Errorf("later-bucket/* include_ended access = %v, want ops and priya: bob's membership ended before the grant began", got)
	}
}

// The restriction caps. 101 Deny statements name capped/* (one policy, one
// holder), and one Deny statement naming crowded/* is held by 101 roles:
// deny_statements_naming carries the first 100 statements by policy and index
// with deny_statements_naming_more, and a statement's holders the first 100
// by name with holders_more -- never a list that looks complete.
func TestP2RDetailRestrictionCaps(t *testing.T) {
	l := newP2Lab(t, "p2-rdetail-caps", true)
	a := l.account(accountA)
	var stmts []string
	for i := 0; i < 101; i++ {
		stmts = append(stmts, fmt.Sprintf(`{"Sid":"D%03d","Effect":"Deny","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::capped/*"}`, i))
	}
	many := a.managed("ManyDenies", `{"Version":"2012-10-17","Statement":[`+strings.Join(stmts, ",")+`]}`)
	crowded := a.managed("OneDeny", `{"Version":"2012-10-17","Statement":[{"Sid":"Crowded","Effect":"Deny",`+
		`"Action":"s3:DeleteObject","Resource":"arn:aws:s3:::crowded/*"}]}`)
	for i := 0; i < 101; i++ {
		name := fmt.Sprintf("role-%03d", i)
		a.role(name, fmt.Sprintf("AROACAPS%012d", i))
		a.attach(name, crowded)
	}
	a.attach("role-000", many)
	l.scanAndProject(a)
	api := l.api()
	first := rdetailIdentity(t, l, "role-000")

	body := rdetailGet(t, api, "/resources/"+rdetailResource(t, l, "arn:aws:s3:::capped/*")+"/access")
	deny := digl(body, "data", "deny_statements_naming")
	if len(deny) != 100 || dig(body, "data", "deny_statements_naming_more") != true {
		t.Fatalf("deny_statements_naming = %d entries, more %v; want 100 and more", len(deny), dig(body, "data", "deny_statements_naming_more"))
	}
	if digs(deny[0], "statement", "sid") != "D000" || num(deny[0], "statement", "index") != 1 ||
		digs(deny[99], "statement", "sid") != "D099" {
		t.Errorf("order = %s … %s, want D000 (index 1) … D099: by policy, then statement index",
			digs(deny[0], "statement", "sid"), digs(deny[99], "statement", "sid"))
	}
	if hs := digl(deny[0], "holders"); len(hs) != 1 || hs[0] != first || dig(deny[0], "holders_more") != false {
		t.Errorf("D000 holders = %v (more %v), want [role-000]", hs, dig(deny[0], "holders_more"))
	}
	if rows := digl(body, "data", "access"); len(rows) != 0 {
		t.Errorf("access = %v, want none: Deny statements grant nothing", rdetailLines(rows))
	}

	body = rdetailGet(t, api, "/resources/"+rdetailResource(t, l, "arn:aws:s3:::crowded/*")+"/access")
	deny = digl(body, "data", "deny_statements_naming")
	if len(deny) != 1 || dig(body, "data", "deny_statements_naming_more") != false {
		t.Fatalf("crowded deny_statements_naming = %d entries, want 1", len(deny))
	}
	if hs := digl(deny[0], "holders"); len(hs) != 100 || dig(deny[0], "holders_more") != true || hs[0] != first ||
		hs[99] != rdetailIdentity(t, l, "role-099") {
		t.Errorf("Crowded holders = %d (more %v, first %v), want role-000 … role-099 and more",
			len(hs), dig(deny[0], "holders_more"), dig(deny[0], "holders", 0))
	}
}
