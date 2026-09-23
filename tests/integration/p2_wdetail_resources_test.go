package integration

// T6.3 -- GET /api/iga/v1/workloads/:id/resources (SPEC-iga-phase2-graph.md
// §5.3, §2.14.6, §2.6, §3 rule 7; D-12, D-13, D-16, D-22, D-62, D-77, D-78,
// D-84): one row per target the workload's execution identities hold a GRANT
// to, one line per grant. Gates: E3 (two grant lines on one selector), E6
// (detach one: one current line), B10 (Deny and boundary: restrictions, no
// grant), B19 (NotResource: the "*" row only, never the excluded resource).

import (
	"net/http"
	"strings"
	"testing"

	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// wdetailResources is a workload's Resources tab, required 200.
func wdetailResources(t *testing.T, api *readAPI, l *p2Lab, workload string, kv ...string) map[string]any {
	t.Helper()
	return wdetailGet(t, api, "/workloads/"+wdetailWorkload(t, l, workload).String()+"/resources"+qs(kv...))
}

// wdetailRowByText is the tab row whose resource text is text, or nil.
func wdetailRowByText(rows []any, text string) map[string]any {
	for _, r := range rows {
		if digs(r, "resource", "text") == text {
			m, _ := r.(map[string]any)
			return m
		}
	}
	return nil
}

// wdetailTexts is every row's resource text, in page order.
func wdetailTexts(rows []any) []string {
	out := []string{}
	for _, r := range rows {
		out = append(out, digs(r, "resource", "text"))
	}
	return out
}

// wdetailOneLambda is a lab with one Lambda running as one role holding the
// given customer-managed policies (name, document pairs).
func wdetailOneLambda(t *testing.T, name, roleName, roleID string, policies ...string) (*p2Lab, *p2Account) {
	t.Helper()
	l := newP2Lab(t, name, true)
	a := l.account(accountA)
	role := a.role(roleName, roleID)
	for i := 0; i+1 < len(policies); i += 2 {
		a.attach(roleName, a.managed(policies[i], policies[i+1]))
	}
	wdetailFunctions(a, "us-east-1", wdetailFn{name: "wd-fn", role: role})
	l.scanAndProject(a)
	return l, a
}

// E3 / E6 / B2 read side: TicketRead (Sid ReadTickets) and ToolboxRead (no
// Sid) both allow s3:GetObject on one selector -- ONE row, TWO grant lines,
// never merged. Detaching TicketRead leaves one current line; include_ended
// adds the ended one back, marked (D-12, UI5 "1 current · 1 ended").
func TestP2WdetailResourcesTwoLinesThenDetach(t *testing.T) {
	l, a := wdetailSharedLab(t, "p2-wdetail-res-e6")
	api := l.api()
	role := wdetailIdentity(t, l, "SharedToolRole")

	body := wdetailResources(t, api, l, "ticket-tools")
	rows := digl(body, "data")
	if len(rows) != 1 || num(body, "meta", "total") != 1 || dig(body, "meta", "total_known") != true {
		t.Fatalf("rows = %s, want exactly the one selector", wdetailJSON(body))
	}
	row := rows[0]
	res := dig(row, "resource")
	for field, want := range map[string]string{
		"text": "arn:aws:s3:::support-tickets/*", "kind": "selector", "type": "s3_object", "service": "s3",
	} {
		if got := digs(res, field); got != want {
			t.Errorf("resource.%s = %q, want %q", field, got, want)
		}
	}
	if rm := res.(map[string]any); rm["account"] != nil || rm["region"] != nil {
		t.Errorf("resource account/region = %v/%v, want null: an S3 ARN states neither", rm["account"], rm["region"])
	}
	lines := digl(row, "grants")
	if len(lines) != 2 {
		t.Fatalf("grant lines = %s, want two: two statements are never merged", wdetailJSON(lines))
	}
	bySid := map[string]any{}
	for _, g := range lines {
		bySid[digs(g, "statement", "sid")] = g
		if digs(g, "via_identity") != refOf("identity", role) || digs(g, "target_mode") != models.TargetResource ||
			digs(g, "state") != "current" || num(g, "statement", "index") != 1 ||
			strings.Join(wdetailStrings(dig(g, "statement", "actions")), ",") != "s3:GetObject" ||
			len(digl(g, "statement", "not_actions")) != 0 || dig(g, "statement", "conditional") != false ||
			len(digl(g, "exclusions")) != 0 || digs(g, "policy", "kind") != models.PolicyKindCustomerManaged ||
			!strings.HasPrefix(digs(g, "claim"), "grant:") || !strings.HasPrefix(digs(g, "statement", "ref"), "statement:") ||
			dig(g, "valid_from") == nil {
			t.Errorf("grant line = %s", wdetailJSON(g))
		}
		if gm := g.(map[string]any); gm["via_group"] != nil {
			t.Errorf("a directly held grant has via_group %v", gm["via_group"])
		}
	}
	if digs(bySid["ReadTickets"], "policy", "name") != "TicketRead" || digs(bySid[""], "policy", "name") != "ToolboxRead" {
		t.Errorf("lines by Sid = %s, want ReadTickets from TicketRead and a Sid-less one from ToolboxRead", wdetailJSON(bySid))
	}
	if dig(row, "restrictions", "deny_statements") != float64(0) || dig(row, "restrictions", "permissions_boundary") != false {
		t.Errorf("restrictions = %v, want none", dig(row, "restrictions"))
	}

	// E6: detach TicketRead and rescan.
	a.detach("SharedToolRole", a.policyARN("TicketRead"))
	l.scanAndProject(a)
	lines = digl(wdetailResources(t, api, l, "ticket-tools"), "data", 0, "grants")
	if len(lines) != 1 || digs(lines[0], "policy", "name") != "ToolboxRead" || digs(lines[0], "state") != "current" {
		t.Fatalf("after the detach = %s, want the one current ToolboxRead line", wdetailJSON(lines))
	}
	lines = digl(wdetailResources(t, api, l, "ticket-tools", "include_ended", "true"), "data", 0, "grants")
	states := map[string]string{}
	for _, g := range lines {
		states[digs(g, "policy", "name")] = digs(g, "state")
		if digs(g, "state") == "ended" && (dig(g, "valid_to") == nil || digs(g, "ended_reason") == "") {
			t.Errorf("an ended line without its end: %s", wdetailJSON(g))
		}
	}
	if len(lines) != 2 || states["TicketRead"] != "ended" || states["ToolboxRead"] != "current" {
		t.Errorf("include_ended lines = %s, want TicketRead ended and ToolboxRead current", wdetailJSON(lines))
	}
}

// B19 / E4 read side: a NotResource statement contributes its "*" row with
// its exclusions on the grant line -- and NO row ends at the excluded
// resource, although that resource is a projected node.
func TestP2WdetailResourcesNotResource(t *testing.T) {
	l, _ := wdetailOneLambda(t, "p2-wdetail-res-b19", "wide-role", "AROAWDETAILWIDEROLE1",
		"AllButFinance", `{"Version":"2012-10-17","Statement":[{"Sid":"AllExceptFinance","Effect":"Allow",`+
			`"Action":"s3:*","NotResource":"arn:aws:s3:::finance/*"}]}`)
	if n := l.count(`SELECT count(*) FROM iga_entitlement_target t JOIN iga_resources r
	                   ON r.workspace_id = t.workspace_id AND r.id = t.resource_id
	                  WHERE t.workspace_id = ? AND t.target_mode = 'not_resource' AND r.display_name = 'arn:aws:s3:::finance/*'`,
		l.ws); n != 1 {
		t.Fatalf("setup: finance/* is %d not_resource target(s), want 1 -- the exclusion must exist for this to prove anything", n)
	}
	api := l.api()
	body := wdetailResources(t, api, l, "wd-fn")
	rows := digl(body, "data")
	if wdetailRowByText(rows, "arn:aws:s3:::finance/*") != nil {
		t.Fatalf("a row ends at the EXCLUDED resource finance/*: %s", wdetailJSON(rows))
	}
	star := wdetailRowByText(rows, "*")
	if len(rows) != 1 || star == nil {
		t.Fatalf("rows = %v, want only the implicit * row", wdetailTexts(rows))
	}
	lines := digl(star, "grants")
	if len(lines) != 1 || digs(lines[0], "statement", "sid") != "AllExceptFinance" ||
		strings.Join(wdetailStrings(dig(lines[0], "statement", "actions")), ",") != "s3:*" {
		t.Fatalf("* row lines = %s", wdetailJSON(lines))
	}
	ex := digl(lines[0], "exclusions")
	finance, _ := l.resourceID("arn:aws:s3:::finance/*")
	if len(ex) != 1 || digs(ex[0], "text") != "arn:aws:s3:::finance/*" || digs(ex[0], "ref") != refOf("resource", finance) {
		t.Errorf("exclusions = %s, want finance/* by ref and text", wdetailJSON(ex))
	}
	if digs(star, "resource", "kind") != "selector" {
		t.Errorf("* kind = %q, want selector", digs(star, "resource", "kind"))
	}
}

// B10: a Deny statement and a permissions boundary are restrictions -- counted
// and flagged on the row, never a grant line, and the boundary's own targets
// are never rows. Grant rows under the Deny statement and under the boundary
// are then inserted directly (a projector defect the fakes cannot produce:
// the projector refuses both, §2.6, rule 7): the tab still shows neither.
func TestP2WdetailResourcesDenyAndBoundaryAreRestrictions(t *testing.T) {
	// Two Allow statements beside the one Deny, so a count that took the
	// wrong effect could not come out right by accident.
	l, a := wdetailOneLambda(t, "p2-wdetail-res-b10", "guarded-role", "AROAWDETAILGUARDED01",
		"TicketRead", docTicketRead, "ToolboxRead", docToolboxRead,
		"NoDeletes", `{"Version":"2012-10-17","Statement":[{"Sid":"NoDelete","Effect":"Deny",`+
			`"Action":"s3:DeleteObject","Resource":"arn:aws:s3:::support-tickets/*"}]}`)
	boundary := a.managed("ToolBoundary", s3aDoc("BoundaryOnly", "s3:*", "arn:aws:s3:::boundary-only/*"))
	s3aEditRole(t, a, "guarded-role", func(r *iamtypes.Role) { r.PermissionsBoundary = s3aBoundary(boundary) })
	l.scanAndProject(a)
	role := wdetailIdentity(t, l, "guarded-role")
	if n := l.count(`SELECT count(*) FROM iga_policy_assignment WHERE workspace_id = ? AND holder_identity_account_id = ?
	                  AND assignment_kind = 'boundary' AND state = 'current'`, l.ws, role); n != 1 {
		t.Fatalf("setup: %d current boundary assignments, want 1", n)
	}
	if n := l.count(`SELECT count(*) FROM iga_entitlements WHERE workspace_id = ? AND provider = 'aws' AND effect = 'deny'`, l.ws); n != 1 {
		t.Fatalf("setup: %d Deny statements, want 1", n)
	}

	api := l.api()
	check := func(stage string) {
		t.Helper()
		rows := digl(wdetailResources(t, api, l, "wd-fn"), "data")
		if len(rows) != 1 || digs(rows[0], "resource", "text") != "arn:aws:s3:::support-tickets/*" {
			t.Fatalf("%s: rows = %v, want only support-tickets/* -- never the boundary's boundary-only/*", stage, wdetailTexts(rows))
		}
		lines := digl(rows[0], "grants")
		policies := []string{}
		for _, g := range lines {
			policies = append(policies, digs(g, "policy", "name"))
		}
		if strings.Join(policies, ",") != "TicketRead,ToolboxRead" {
			t.Errorf("%s: lines from %v, want the two Allow lines only: a Deny is never a grant line", stage, policies)
		}
		if dig(rows[0], "restrictions", "deny_statements") != float64(1) || dig(rows[0], "restrictions", "permissions_boundary") != true {
			t.Errorf("%s: restrictions = %v, want deny_statements 1 and permissions_boundary true", stage, dig(rows[0], "restrictions"))
		}
	}
	check("as projected")

	// The defect rows: a grant on the Deny statement through its attached
	// assignment, and one on the boundary's statement through the boundary.
	for _, d := range []struct{ policy, kind string }{{"NoDeletes", "attached"}, {"ToolBoundary", "boundary"}} {
		var stmt, assignment uuid.UUID
		l.db.Raw(`SELECT e.id FROM iga_entitlements e JOIN iga_policy p ON p.workspace_id = e.workspace_id AND p.id = e.policy_id
		           WHERE e.workspace_id = ? AND p.display_name = ?`, l.ws, d.policy).Row().Scan(&stmt)
		l.db.Raw(`SELECT a.id FROM iga_policy_assignment a JOIN iga_policy p ON p.workspace_id = a.workspace_id AND p.id = a.policy_id
		           WHERE a.workspace_id = ? AND p.display_name = ? AND a.assignment_kind = ?`, l.ws, d.policy, d.kind).Row().Scan(&assignment)
		if stmt == uuid.Nil || assignment == uuid.Nil {
			t.Fatalf("setup: no statement/assignment for %s (%s)", d.policy, d.kind)
		}
		if err := l.db.Exec(`INSERT INTO iga_access_edges (workspace_id, subject_kind, subject_id, subject_identity_account_id,
		                           entitlement_id, direction, provider, assignment_id, source_key, partition_key, connector_id)
		                    VALUES (?, 'identity_account', ?, ?, ?, 'outbound', 'aws', ?, ?, 'wdetail-defect', ?)`,
			l.ws, role, role, stmt, assignment, "wdetail-defect-"+d.policy, a.conn).Error; err != nil {
			t.Fatalf("insert the %s defect grant: %v", d.policy, err)
		}
	}
	check("with a grant row on the Deny and on the boundary")
}

// Paged by resource (D-77): kind order exact < selector < external, then name
// (D-13, D-16); name order; descending; a cursor bound to its workload, sort,
// filters and revision (D-62, §5.1).
func TestP2WdetailResourcesPaging(t *testing.T) {
	l, a := wdetailOneLambda(t, "p2-wdetail-res-paging", "many-role", "AROAWDETAILMANYROLE1",
		"ManyTargets", `{"Version":"2012-10-17","Statement":[{"Sid":"Many","Effect":"Allow","Action":"s3:GetObject",`+
			`"Resource":["arn:aws:s3:::a-bucket/*","arn:aws:s3:::b-bucket","arn:aws:dynamodb:us-east-1:`+accountA+`:table/t1",`+
			`"arn:aws:kms:us-east-1:`+accountB+`:key/k1"]}]}`)
	// A second workload with the same role: the same rows, so only the
	// cursor's route can tell the two tabs apart.
	wdetailFunctions(a, "us-east-1", wdetailFn{name: "wd-fn", role: a.roleARN("many-role")},
		wdetailFn{name: "wd-twin", role: a.roleARN("many-role")})
	l.scanAndProject(a)
	api := l.api()
	route := "/workloads/" + wdetailWorkload(t, l, "wd-fn").String() + "/resources"
	twin := "/workloads/" + wdetailWorkload(t, l, "wd-twin").String() + "/resources"

	walk := func(kv ...string) []string {
		t.Helper()
		var texts []string
		cursor := ""
		for page := 0; page < 10; page++ {
			args := append([]string{"limit", "1"}, kv...)
			if cursor != "" {
				args = append(args, "cursor", cursor)
			}
			body := wdetailGet(t, api, route+qs(args...))
			rows := digl(body, "data")
			if len(rows) > 1 {
				t.Fatalf("page of %d rows at limit 1", len(rows))
			}
			texts = append(texts, wdetailTexts(rows)...)
			next, _ := dig(body, "meta", "next_cursor").(string)
			if next == "" {
				return texts
			}
			cursor = next
		}
		t.Fatal("paging did not end")
		return nil
	}
	exact := []string{"arn:aws:dynamodb:us-east-1:" + accountA + ":table/t1", "arn:aws:s3:::b-bucket"}
	kind := append(append(append([]string{}, exact...), "arn:aws:s3:::a-bucket/*"), "arn:aws:kms:us-east-1:"+accountB+":key/k1")
	if got := walk(); strings.Join(got, " ") != strings.Join(kind, " ") {
		t.Errorf("kind order = %v, want exact (dynamodb, b-bucket), then the selector, then the external key: %v", got, kind)
	}
	name := []string{"arn:aws:dynamodb:us-east-1:" + accountA + ":table/t1", "arn:aws:kms:us-east-1:" + accountB + ":key/k1",
		"arn:aws:s3:::a-bucket/*", "arn:aws:s3:::b-bucket"}
	if got := walk("sort", "name"); strings.Join(got, " ") != strings.Join(name, " ") {
		t.Errorf("name order = %v, want %v", got, name)
	}
	rev := make([]string, len(kind))
	for i := range kind {
		rev[i] = kind[len(kind)-1-i]
	}
	if got := walk("sort", "-kind"); strings.Join(got, " ") != strings.Join(rev, " ") {
		t.Errorf("-kind order = %v, want %v", got, rev)
	}

	// Each row is the resource list's reference: the external key names its
	// account, not connected; the table is exact in its region.
	rows := digl(wdetailGet(t, api, route), "data")
	kms := wdetailRowByText(rows, "arn:aws:kms:us-east-1:"+accountB+":key/k1")
	if digs(kms, "resource", "kind") != "external" || digs(kms, "resource", "account", "id") != accountB ||
		dig(kms, "resource", "account", "connected") != false || digs(kms, "resource", "type") != "kms_key" {
		t.Errorf("kms row = %s, want external in an unconnected account", wdetailJSON(dig(kms, "resource")))
	}
	table := wdetailRowByText(rows, "arn:aws:dynamodb:us-east-1:"+accountA+":table/t1")
	if digs(table, "resource", "kind") != "exact" || digs(table, "resource", "region") != "us-east-1" ||
		digs(table, "resource", "service") != "dynamodb" || digs(table, "resource", "account", "id") != a.id {
		t.Errorf("table row = %s", wdetailJSON(dig(table, "resource")))
	}

	first := wdetailGet(t, api, route+qs("limit", "1"))
	cur, _ := dig(first, "meta", "next_cursor").(string)
	if cur == "" || num(first, "meta", "total") != 4 {
		t.Fatalf("page 1 meta = %v, want a cursor and total 4", dig(first, "meta"))
	}
	for what, path := range map[string]string{
		"another sort":     route + qs("limit", "1", "sort", "name", "cursor", cur),
		"another filter":   route + qs("limit", "1", "include_ended", "true", "cursor", cur),
		"another workload": twin + qs("limit", "1", "cursor", cur),
		"a tampered one":   route + qs("limit", "1", "cursor", cur+"x"),
		"an unknown sort":  route + qs("sort", "service"),
	} {
		code, body := api.get(path)
		if code != http.StatusBadRequest {
			t.Errorf("cursor with %s = %d %s, want 400", what, code, wdetailJSON(body))
		}
	}
	l.scanAndProject(a)
	if code, body := api.get(route + qs("limit", "1", "cursor", cur)); code != http.StatusConflict || errCode(body) != "revision_stale" {
		t.Errorf("cursor after a new publication = %d %s, want 409 revision_stale", code, wdetailJSON(body))
	}
}

// Groups (§5.3 "and their groups", D-22): a grant held by a group the
// execution identity belongs to is a line with via_group, and the group's
// Deny statements count on the row. An IAM role cannot be a group member, so
// no scan produces this: the membership is inserted directly, the group, its
// policies and its grants come from the pipeline.
func TestP2WdetailGroupsAndGroupHeldGrants(t *testing.T) {
	l := newP2Lab(t, "p2-wdetail-groups", true)
	a := l.account(accountA)
	role := a.role("member-role", "AROAWDETAILMEMBER001")
	a.attach("member-role", a.managed("TicketRead", docTicketRead))
	s3aGroup(a, "ops", "AGPAWDETAILOPSGROUP1")
	s3aGroupAttach(t, a, "ops", a.managed("OpsList", s3aDoc("ListGroupBucket", "s3:ListBucket", "arn:aws:s3:::group-bucket")))
	s3aGroupAttach(t, a, "ops", a.managed("OpsNoPut", `{"Version":"2012-10-17","Statement":[{"Sid":"NoPut","Effect":"Deny",`+
		`"Action":"s3:PutObject","Resource":"*"}]}`))
	wdetailFunctions(a, "us-east-1", wdetailFn{name: "wd-fn", role: role})
	l.scanAndProject(a)
	roleID, group := wdetailIdentity(t, l, "member-role"), wdetailIdentity(t, l, "ops")
	if n := l.count(`SELECT count(*) FROM iga_access_edges WHERE workspace_id = ? AND subject_identity_account_id = ? AND state = 'current'`,
		l.ws, group); n != 1 {
		t.Fatalf("setup: the group holds %d current grants, want 1", n)
	}
	if err := l.db.Exec(`INSERT INTO iga_relationship (workspace_id, relationship_type, source_identity_account_id,
	                           target_identity_account_id, source_key, partition_key, connector_id)
	                    VALUES (?, 'member_of', ?, ?, 'wdetail-member-of', 'wdetail-member-of', ?)`,
		l.ws, roleID, group, a.conn).Error; err != nil {
		t.Fatalf("insert member_of: %v", err)
	}
	api := l.api()

	groups := digl(wdetailIdentities(t, api, l, "wd-fn"), "data", "groups", "items")
	if len(groups) != 1 || digs(groups[0], "type") != models.RelTypeMemberOf || digs(groups[0], "identity", "ref") != refOf("identity", group) ||
		digs(groups[0], "identity", "kind") != models.CloudIdentityIAMGroup || digs(groups[0], "via_identity") != refOf("identity", roleID) {
		t.Fatalf("groups = %s, want ops via member-role", wdetailJSON(groups))
	}

	rows := digl(wdetailResources(t, api, l, "wd-fn"), "data")
	gb := wdetailRowByText(rows, "arn:aws:s3:::group-bucket")
	if gb == nil {
		t.Fatalf("rows = %v, want group-bucket through the group", wdetailTexts(rows))
	}
	lines := digl(gb, "grants")
	if len(lines) != 1 || digs(lines[0], "via_identity") != refOf("identity", roleID) || digs(lines[0], "via_group") != refOf("identity", group) ||
		digs(lines[0], "policy", "name") != "OpsList" {
		t.Errorf("group-bucket lines = %s, want the group's grant via member-role and ops", wdetailJSON(lines))
	}
	for _, r := range rows {
		if dig(r, "restrictions", "deny_statements") != float64(1) {
			t.Errorf("%s restrictions = %v, want the group's Deny counted (D-22)", digs(r, "resource", "text"), dig(r, "restrictions"))
		}
	}
	if wdetailRowByText(rows, "arn:aws:s3:::support-tickets/*") == nil {
		t.Errorf("rows = %v, want the role's own support-tickets/* too", wdetailTexts(rows))
	}
}
