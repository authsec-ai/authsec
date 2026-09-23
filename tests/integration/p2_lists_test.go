package integration

// T6.2 -- the §5.3 lists (/workloads, /identities, /resources) and their §5.2
// common behaviour, through the REAL route table over graphs the REAL scan
// worker and projector built (the P2-0 lab). Gates: search finds a row beyond
// page one; facets include unknown; E2 (duplicate names across accounts); E12
// (the revision, or a classification, moves between pages).

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

/* --------------------------------- helpers --------------------------------- */

// listsFunctions makes a region's Lambda list exactly these functions, given as
// name, role ARN pairs.
func listsFunctions(a *p2Account, region string, nameRole ...string) {
	f := a.lambdas[region]
	if f == nil {
		f = &fakeLambda{}
		a.lambdas[region] = f
	}
	f.functions = nil
	for i := 0; i+1 < len(nameRole); i += 2 {
		name, role := nameRole[i], nameRole[i+1]
		f.functions = append(f.functions, lambdatypes.FunctionConfiguration{
			FunctionArn:  aws.String("arn:aws:lambda:" + region + ":" + a.id + ":function:" + name),
			FunctionName: aws.String(name), Role: aws.String(role), State: lambdatypes.StateActive,
		})
	}
}

// listsGet calls a list route and requires 200.
func listsGet(t *testing.T, api *readAPI, path string) map[string]any {
	t.Helper()
	code, body := api.get(path)
	mustStatus(t, "GET "+path, code, body, 200)
	return body
}

// listsWalk pages a list to its end (limit per page) and returns every row,
// failing on a repeated ref -- a keyset that repeats or skips is the defect a
// stable tiebreaker exists to prevent.
func listsWalk(t *testing.T, api *readAPI, route string, limit int, kv ...string) []any {
	t.Helper()
	var all []any
	seen := map[string]bool{}
	cursor := ""
	for page := 0; page < 1000; page++ {
		args := append([]string{"limit", fmt.Sprint(limit)}, kv...)
		if cursor != "" {
			args = append(args, "cursor", cursor)
		}
		body := listsGet(t, api, route+qs(args...))
		rows := digl(body, "data")
		if len(rows) > limit {
			t.Fatalf("%s page %d has %d rows, limit %d", route, page, len(rows), limit)
		}
		for _, r := range rows {
			ref := digs(r, "ref")
			if seen[ref] {
				t.Fatalf("%s: %s appears on two pages", route, ref)
			}
			seen[ref] = true
			all = append(all, r)
		}
		next, _ := dig(body, "meta", "next_cursor").(string)
		if next == "" {
			return all
		}
		if len(rows) != limit {
			t.Fatalf("%s page %d is short (%d of %d) but has a next cursor", route, page, len(rows), limit)
		}
		cursor = next
	}
	t.Fatalf("%s: paging did not end", route)
	return nil
}

// listsField is one string field of every row.
func listsField(rows []any, path ...any) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, digs(r, path...))
	}
	return out
}

// listsRowBy finds the row whose field equals value.
func listsRowBy(t *testing.T, rows []any, field, value string) map[string]any {
	t.Helper()
	for _, r := range rows {
		if digs(r, field) == value {
			return r.(map[string]any)
		}
	}
	t.Fatalf("no row with %s = %q in %v", field, value, listsField(rows, field))
	return nil
}

// listsFacet is one facet's chips as value -> count; ok=false when the facet
// is absent or null.
func listsFacet(body map[string]any, name string) (map[string]int64, bool) {
	vals, ok := dig(body, "meta", "facets", name).([]any)
	if !ok {
		return nil, false
	}
	out := map[string]int64{}
	for _, v := range vals {
		out[digs(v, "value")] = num(v, "count")
	}
	return out, true
}

// listsSameSet reports whether two string lists hold the same values.
func listsSameSet(a, b []string) bool {
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	return strings.Join(x, "\x00") == strings.Join(y, "\x00")
}

// listsDecide lands a classification decision the way §5.5 steps 5 does --
// the workload's classification and version, and the workspace's clock --
// standing in for POST /classification (T6.6), which is another task's route.
func listsDecide(t *testing.T, db *gorm.DB, ws, workload uuid.UUID) {
	t.Helper()
	if err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`UPDATE iga_workload SET classification = 'classified_agent',
		                          classification_version = classification_version + 1
		                    WHERE workspace_id = ? AND id = ?`, ws, workload).Error; err != nil {
			return err
		}
		return tx.Exec(`INSERT INTO iga_classification_clock (workspace_id, seq) VALUES (?, 1)
		                ON CONFLICT (workspace_id) DO UPDATE SET seq = iga_classification_clock.seq + 1`, ws).Error
	}); err != nil {
		t.Fatalf("decide: %v", err)
	}
}

/* ---------------------------------- tests ---------------------------------- */

// T6.2 gate: search is server-side over the WHOLE inventory at the revision,
// never a filter over the loaded page. 105 workloads, default limit 100: the
// one q names is not on page one, and q still finds it.
func TestP2ListsSearchFindsRowBeyondPageOne(t *testing.T) {
	l := newP2Lab(t, "p2-lists-search", true)
	a := l.account(accountA)
	role := a.role("refund-lambda-role", "AROA5XK7QEXAMPLE")
	var pairs []string
	for i := 0; i < 104; i++ {
		pairs = append(pairs, fmt.Sprintf("fn-%03d", i), role)
	}
	pairs = append(pairs, "zz-ticket-tools", role)
	listsFunctions(a, "us-east-1", pairs...)
	l.scanAndProject(a)
	api := l.api()

	body := listsGet(t, api, "/workloads")
	rows := digl(body, "data")
	if len(rows) != 100 || num(body, "meta", "limit") != 100 {
		t.Fatalf("page one = %d rows (limit %d), want the default 100", len(rows), num(body, "meta", "limit"))
	}
	for _, name := range listsField(rows, "name") {
		if name == "zz-ticket-tools" {
			t.Fatal("zz-ticket-tools is on page one: the fixture no longer puts it beyond the loaded page")
		}
	}
	if dig(body, "meta", "total_known") != true || num(body, "meta", "total") != 105 {
		t.Errorf("totals = %v / %v, want total_known with 105 found (> limit)", dig(body, "meta", "total_known"), dig(body, "meta", "total"))
	}
	cursor := digs(body, "meta", "next_cursor")
	if cursor == "" {
		t.Fatal("page one of 105 has no next_cursor")
	}

	// Case-insensitive substring, over everything.
	found := listsGet(t, api, "/workloads"+qs("q", "TICKET"))
	if names := listsField(digl(found, "data"), "name"); len(names) != 1 || names[0] != "zz-ticket-tools" {
		t.Fatalf("q=TICKET = %v, want exactly zz-ticket-tools from beyond page one", names)
	}
	if num(found, "meta", "total") != 1 || dig(found, "meta", "next_cursor") != nil {
		t.Errorf("q=TICKET meta = %v, want total 1 and no next page", dig(found, "meta"))
	}

	// Page two: the remaining five, and no cursor after it.
	page2 := listsGet(t, api, "/workloads"+qs("cursor", cursor))
	names := listsField(digl(page2, "data"), "name")
	if len(names) != 5 || names[4] != "zz-ticket-tools" || dig(page2, "meta", "next_cursor") != nil {
		t.Fatalf("page two = %v (next %v), want the last 5 ending at zz-ticket-tools", names, dig(page2, "meta", "next_cursor"))
	}
}

// The workload row, exactly as §5.3 shows it, and §5.2's q, sort and paging
// over it: LIKE metacharacters are literal, the exact arms match the full
// ARN, the account id and the provider id, and every sort pages without
// repeating or skipping a row.
func TestP2ListsWorkloadRowsSearchAndPaging(t *testing.T) {
	l := newP2Lab(t, "p2-lists-workloads", true)
	a := l.account(accountA, "us-east-1", "eu-central-1")
	role := a.role("refund-lambda-role", "AROA5XK7QEXAMPLE")
	listsFunctions(a, "us-east-1", "a_b-tool", role, "axb-tool", role, "bravo", role, "charlie", role, "delta", role)
	listsFunctions(a, "eu-central-1", "echo", role)
	l.scanAndProject(a)
	api := l.api()

	all := listsWalk(t, api, "/workloads", 2)
	want := []string{"a_b-tool", "axb-tool", "bravo", "charlie", "delta", "echo"}
	if got := listsField(all, "name"); !listsSameSet(got, want) {
		t.Fatalf("walk = %v, want every workload once: %v", got, want)
	}
	desc := listsWalk(t, api, "/workloads", 2, "sort", "-name")
	for i := range all {
		if digs(all[i], "ref") != digs(desc[len(desc)-1-i], "ref") {
			t.Fatalf("sort=-name is not the reverse of sort=name: %v vs %v", listsField(all, "name"), listsField(desc, "name"))
		}
	}

	// The §5.3 row.
	var roleID uuid.UUID
	if err := l.db.Raw(`SELECT id FROM iga_identity_accounts WHERE workspace_id = ? AND display_name = 'refund-lambda-role'`,
		l.ws).Row().Scan(&roleID); err != nil {
		t.Fatalf("role id: %v", err)
	}
	bravo := listsRowBy(t, all, "name", "bravo")
	arn := "arn:aws:lambda:us-east-1:" + accountA + ":function:bravo"
	for path, want := range map[string]any{
		"runtime_kind":            "lambda_function",
		"arn":                     arn,
		"region":                  "us-east-1",
		"classification":          "unclassified",
		"lifecycle":               "active",
		"state":                   "current",
		"execution_role.state":    "resolved",
		"execution_role.identity": refOf("identity", roleID),
		"execution_role.name":     "refund-lambda-role",
		"account.id":              accountA,
		"account.label":           "acct-" + accountA,
		"instances.state":         "not_collected",
	} {
		var keys []any
		for _, k := range strings.Split(path, ".") {
			keys = append(keys, k)
		}
		if got := dig(bravo, keys...); got != want {
			t.Errorf("bravo.%s = %v, want %v", path, got, want)
		}
	}
	if dig(bravo, "account", "connected") != true || num(bravo, "classification_version") != 0 ||
		digs(bravo, "first_seen_at") == "" || digs(bravo, "last_confirmed_at") == "" {
		t.Errorf("bravo = %v: want a connected account, version 0 and both timestamps", bravo)
	}
	if !strings.HasPrefix(digs(bravo, "ref"), "workload:") {
		t.Errorf("ref = %q, want a typed workload reference", digs(bravo, "ref"))
	}

	for _, tc := range []struct {
		name string
		kv   []string
		want []string
	}{
		// '_' is a LIKE wildcard: unescaped, a_b would also match axb-tool.
		{"like metacharacters are literal", []string{"q", "a_b"}, []string{"a_b-tool"}},
		{"case-insensitive", []string{"q", "A_B"}, []string{"a_b-tool"}},
		{"exact full ARN", []string{"q", arn}, []string{"bravo"}},
		{"exact account id", []string{"q", accountA}, want},
		{"region", []string{"region", "eu-central-1"}, []string{"echo"}},
		{"region not stated", []string{"region", "not_stated"}, nil},
		{"runtime kind", []string{"runtime_kind", "lambda_function"}, want},
		{"another runtime kind", []string{"runtime_kind", "ec2_instance"}, nil},
		{"execution role state", []string{"execution_role_state", "resolved"}, want},
		{"no unresolved roles", []string{"execution_role_state", "not_in_inventory"}, nil},
	} {
		rows := listsWalk(t, api, "/workloads", 100, tc.kv...)
		if got := listsField(rows, "name"); !listsSameSet(got, tc.want) {
			t.Errorf("%s (%v) = %v, want %v", tc.name, tc.kv, got, tc.want)
		}
	}

	body := listsGet(t, api, "/workloads"+qs("facets", "region,runtime_kind"))
	if f, _ := listsFacet(body, "region"); f["us-east-1"] != 5 || f["eu-central-1"] != 1 {
		t.Errorf("region facet = %v, want us-east-1 5, eu-central-1 1", f)
	}
	if f, _ := listsFacet(body, "runtime_kind"); f["lambda_function"] != 6 {
		t.Errorf("runtime_kind facet = %v", f)
	}
}

// E2: two workloads named ticket-tools in two accounts, running as two roles
// both named SharedToolRole. Search returns both, each with ITS account; the
// account facet counts per account and always offers unknown; the account
// filter separates them; the integration filter selects by supporting
// connector; paging one row at a time over identical names relies on the id
// tiebreaker.
func TestP2ListsDuplicateNamesAcrossAccounts(t *testing.T) {
	l := newP2Lab(t, "p2-lists-e2", true)
	a := l.account(accountA)
	b := l.account(accountB)
	for _, acct := range []*p2Account{a, b} {
		role := acct.role("SharedToolRole", "AROASHARED"+acct.id[:10])
		listsFunctions(acct, "us-east-1", "ticket-tools", role)
	}
	l.scanAndProject(a)
	l.scanAndProject(b)
	api := l.api()

	body := listsGet(t, api, "/workloads"+qs("q", "ticket", "facets", "account"))
	rows := digl(body, "data")
	if len(rows) != 2 {
		t.Fatalf("q=ticket = %d rows, want both ticket-tools", len(rows))
	}
	accts := listsField(rows, "account", "id")
	if !listsSameSet(accts, []string{accountA, accountB}) {
		t.Fatalf("accounts = %v, want one row per account", accts)
	}
	for _, r := range rows {
		acct := digs(r, "account", "id")
		if !strings.Contains(digs(r, "arn"), ":"+acct+":") {
			t.Errorf("row in %s carries ARN %s", acct, digs(r, "arn"))
		}
	}
	if digs(rows[0], "execution_role", "identity") == digs(rows[1], "execution_role", "identity") {
		t.Error("both workloads name the same execution identity: the two SharedToolRoles were merged")
	}
	f, ok := listsFacet(body, "account")
	if !ok || f[accountA] != 1 || f[accountB] != 1 {
		t.Errorf("account facet = %v, want 1 per account", f)
	}
	if n, present := f["unknown"]; !present || n != 0 {
		t.Errorf("account facet = %v, want unknown offered (count 0: a workload's account is always known)", f)
	}

	for _, tc := range []struct {
		kv   []string
		want []string
	}{
		{[]string{"account", accountA}, []string{accountA}},
		{[]string{"account", accountB}, []string{accountB}},
		{[]string{"account", accountA, "account", accountB}, []string{accountA, accountB}},
		{[]string{"account", "unknown"}, nil},
		{[]string{"integration", refOf("cloud_connector", a.conn)}, []string{accountA}},
		{[]string{"integration", refOf("cloud_connector", b.conn)}, []string{accountB}},
		// A connector no support row names -- another workspace's, or none:
		// an empty list, never a hint.
		{[]string{"integration", refOf("cloud_connector", uuid.New())}, nil},
	} {
		got := listsField(listsWalk(t, api, "/workloads", 100, tc.kv...), "account", "id")
		if !listsSameSet(got, tc.want) {
			t.Errorf("%v = accounts %v, want %v", tc.kv, got, tc.want)
		}
	}

	// Identical names, one row per page: only the id tiebreaker keeps the
	// second one from being skipped.
	if walked := listsWalk(t, api, "/workloads", 1, "q", "ticket"); len(walked) != 2 {
		t.Errorf("limit=1 over two identical names returned %d rows, want 2", len(walked))
	}

	ids := listsGet(t, api, "/identities"+qs("q", "SharedToolRole", "facets", "account"))
	irows := digl(ids, "data")
	if len(irows) != 2 || !listsSameSet(listsField(irows, "account", "id"), []string{accountA, accountB}) ||
		digs(irows[0], "arn") == digs(irows[1], "arn") {
		t.Errorf("identities q=SharedToolRole = %v, want two rows, distinct accounts and ARNs", irows)
	}
	if f, _ := listsFacet(ids, "account"); f[accountA] != 1 || f[accountB] != 1 {
		t.Errorf("identity account facet = %v", f)
	}
}

// Resources: the four D-16 kinds never conflated, the account a reference
// STATES (never the scanning account), D-17 counts, and facets that include
// unknown and apply every OTHER filter.
func TestP2ListsResourcesKindsAccountsAndFacets(t *testing.T) {
	l := newP2Lab(t, "p2-lists-resources", true)
	a := l.account(accountA)
	a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	a.attach("SharedToolRole", a.managed("TicketRead", docTicketRead))
	orders := "arn:aws:dynamodb:us-east-1:" + accountA + ":table/orders"
	partner := "arn:aws:dynamodb:us-east-1:999999999999:table/partner"
	// A selector in an account no connector reads: selector, never external,
	// with account.connected false (D-16).
	partners := "arn:aws:dynamodb:us-east-1:999999999999:table/*"
	a.attach("SharedToolRole", a.managed("Tables", `{"Version":"2012-10-17","Statement":[{"Sid":"Tables",`+
		`"Effect":"Allow","Action":"dynamodb:GetItem","Resource":["`+orders+`","`+partner+`","`+partners+`"]}]}`))
	a.attach("SharedToolRole", a.managed("AllButFinance", `{"Version":"2012-10-17","Statement":[{`+
		`"Sid":"AllButFinance","Effect":"Allow","Action":"s3:*","NotResource":"arn:aws:s3:::finance/*"}]}`))
	a.attach("SharedToolRole", a.managed("NoDeletes", `{"Version":"2012-10-17","Statement":[{`+
		`"Sid":"NoDeletes","Effect":"Deny","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::support-tickets/*"}]}`))
	l.scanAndProject(a)
	// A GitHub resource in the same workspace is never a graph row (D-6).
	if err := l.db.Exec(`INSERT INTO iga_resources (workspace_id, resource_kind, display_name, provider, source_key)
	                     VALUES (?, 'repository', 'acme/support-tickets', 'github', 'github␟repo␟1')`, l.ws).Error; err != nil {
		t.Fatalf("seed github resource: %v", err)
	}
	// Nor is an AWS reference no projection pass supports (D-6).
	if err := l.db.Exec(`INSERT INTO iga_resources (workspace_id, resource_kind, display_name, provider, source_key)
	                     VALUES (?, 's3_bucket', 'arn:aws:s3:::orphan', 'aws', 'aws' || chr(31) || 'ref' || chr(31) || 'arn:aws:s3:::orphan')`,
		l.ws).Error; err != nil {
		t.Fatalf("seed unsupported resource: %v", err)
	}
	api := l.api()

	body := listsGet(t, api, "/resources"+qs("facets", "kind,service,account"))
	rows := digl(body, "data")
	texts := listsField(rows, "text")
	unknowns := []string{"arn:aws:s3:::support-tickets/*", "*", "arn:aws:s3:::finance/*"}
	wantTexts := append([]string{orders, partner, partners}, unknowns...)
	if !listsSameSet(texts, wantTexts) {
		t.Fatalf("resources = %v, want %v (and never the GitHub or the unsupported row)", texts, wantTexts)
	}
	// Default order: exact reference, selector, external (§2.14.6).
	rank := map[string]int{"exact": 0, "selector": 1, "external": 2}
	for i := 1; i < len(rows); i++ {
		if rank[digs(rows[i-1], "kind")] > rank[digs(rows[i], "kind")] {
			t.Fatalf("default order = %v, want exact, then selector, then external", listsField(rows, "kind"))
		}
	}

	type want struct {
		kind, typ, service, account, region string
		connected                           bool
		named, excluded                     int64
	}
	for text, w := range map[string]want{
		orders:                           {"exact", "dynamodb_table", "dynamodb", accountA, "us-east-1", true, 1, 0},
		partner:                          {"external", "dynamodb_table", "dynamodb", "999999999999", "us-east-1", false, 1, 0},
		partners:                         {"selector", "dynamodb_table", "dynamodb", "999999999999", "us-east-1", false, 1, 0},
		"arn:aws:s3:::support-tickets/*": {"selector", "s3_object", "s3", "", "", false, 1, 0}, // the Deny is not counted
		"*":                              {"selector", "unknown", "", "", "", false, 1, 0},
		"arn:aws:s3:::finance/*":         {"selector", "s3_object", "s3", "", "", false, 0, 1},
	} {
		r := listsRowBy(t, rows, "text", text)
		if digs(r, "kind") != w.kind || digs(r, "type") != w.typ || digs(r, "service") != w.service ||
			digs(r, "account", "id") != w.account || digs(r, "region") != w.region {
			t.Errorf("%s = kind %v type %v service %v account %v region %v, want %+v", text,
				r["kind"], r["type"], r["service"], r["account"], r["region"], w)
		}
		if w.account == "" && r["account"] != nil {
			t.Errorf("%s states no account but reads %v: never the scanning account", text, r["account"])
		}
		if w.account != "" && dig(r, "account", "connected") != w.connected {
			t.Errorf("%s account.connected = %v, want %v", text, dig(r, "account", "connected"), w.connected)
		}
		if num(r, "named_by_count", "value") != w.named || dig(r, "named_by_count", "exact") != true ||
			num(r, "excluded_by_count", "value") != w.excluded {
			t.Errorf("%s counts = %v / %v, want named %d excluded %d", text, r["named_by_count"], r["excluded_by_count"], w.named, w.excluded)
		}
	}

	f, _ := listsFacet(body, "account")
	if f["unknown"] != 3 || f[accountA] != 1 || f["999999999999"] != 2 {
		t.Errorf("account facet = %v, want unknown 3 (the S3 and * references state no account), A 1, 999999999999 2", f)
	}
	if f, _ := listsFacet(body, "kind"); f["exact"] != 1 || f["selector"] != 4 || f["external"] != 1 {
		t.Errorf("kind facet = %v", f)
	}
	if f, _ := listsFacet(body, "service"); f["s3"] != 2 || f["dynamodb"] != 3 || len(f) != 2 {
		t.Errorf("service facet = %v, want s3 2, dynamodb 2 and no chip for '*'", f)
	}

	// Each facet applies every OTHER filter: under kind=selector the kind
	// facet still shows every kind, while the account facet counts selectors.
	sel := listsGet(t, api, "/resources"+qs("kind", "selector", "facets", "kind,account"))
	if n := len(digl(sel, "data")); n != 4 {
		t.Errorf("kind=selector = %d rows, want 4", n)
	}
	if f, _ := listsFacet(sel, "kind"); f["exact"] != 1 || f["selector"] != 4 || f["external"] != 1 {
		t.Errorf("kind facet under kind=selector = %v: a facet must not apply its own filter", f)
	}
	if f, _ := listsFacet(sel, "account"); f["unknown"] != 3 || f[accountA] != 0 || f["999999999999"] != 1 || len(f) != 3 {
		t.Errorf("account facet under kind=selector = %v, want unknown 3, 999999999999 1 and connected A at 0", f)
	}

	for _, tc := range []struct {
		kv   []string
		want []string
	}{
		{[]string{"account", "unknown"}, unknowns},
		// Choosing an account EXCLUDES unknowns (§2.14.10).
		{[]string{"account", accountA}, []string{orders}},
		{[]string{"account", accountA, "account", "unknown"}, append([]string{orders}, unknowns...)},
		{[]string{"region", "not_stated"}, unknowns},
		{[]string{"region", "us-east-1"}, []string{orders, partner, partners}},
		{[]string{"service", "dynamodb"}, []string{orders, partner, partners}},
		{[]string{"kind", "external"}, []string{partner}},
		{[]string{"kind", "exact", "kind", "external"}, []string{orders, partner}},
		// q as an account id: the references that STATE it; unknowns never match (D-76).
		{[]string{"q", "999999999999"}, []string{partner, partners}},
		{[]string{"q", partner}, []string{partner}},
		{[]string{"integration", refOf("cloud_connector", a.conn)}, wantTexts},
		{[]string{"integration", a.conn.String(), "provider", "aws"}, wantTexts},
		{[]string{"integration", uuid.NewString()}, nil},
		{[]string{"q", "support"}, []string{"arn:aws:s3:::support-tickets/*"}},
		// '*' is not a LIKE metacharacter, and matches only itself: every
		// reference whose text contains "/*", and never the bare "*".
		{[]string{"q", "/*"}, []string{"arn:aws:s3:::support-tickets/*", "arn:aws:s3:::finance/*", partners}},
	} {
		got := listsField(listsWalk(t, api, "/resources", 2, tc.kv...), "text")
		if !listsSameSet(got, tc.want) {
			t.Errorf("%v = %v, want %v", tc.kv, got, tc.want)
		}
	}

	// D-13 orders, walked ONE row per page so every keyset arm is exercised:
	// kind by rank; unknown account and no service LAST in both directions;
	// '-' reverses everything else, id included.
	st, fin, star := "arn:aws:s3:::support-tickets/*", "arn:aws:s3:::finance/*", "*"
	for _, tc := range []struct {
		sort string
		want []string
	}{
		{"kind", []string{orders, star, partners, fin, st, partner}},
		{"-kind", []string{partner, st, fin, partners, star, orders}},
		{"name", []string{star, orders, partners, partner, fin, st}},
		{"-name", []string{st, fin, partner, partners, orders, star}},
		{"account", []string{orders, partners, partner, star, fin, st}},
		{"-account", []string{partner, partners, orders, st, fin, star}},
		{"service", []string{orders, partners, partner, fin, st, star}},
		{"-service", []string{st, fin, partner, partners, orders, star}},
	} {
		got := listsField(listsWalk(t, api, "/resources", 1, "sort", tc.sort), "text")
		if strings.Join(got, " | ") != strings.Join(tc.want, " | ") {
			t.Errorf("sort=%s =\n  %v\nwant\n  %v", tc.sort, got, tc.want)
		}
	}
}

// Identities: kind, ARN, the account from the ARN, region global, and
// used_by_count over the same relationships as the used_by filter.
func TestP2ListsIdentities(t *testing.T) {
	l := newP2Lab(t, "p2-lists-identities", true)
	a := l.account(accountA)
	refund := a.role("refund-lambda-role", "AROA5XK7QEXAMPLE")
	shared := a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	a.role("IdleRole", "AROAIDLEROLEIDLEROLE")
	a.iam.users = append(a.iam.users, iamtypes.User{
		Arn: aws.String("arn:aws:iam::" + accountA + ":user/ci-deployer"), UserName: aws.String("ci-deployer"),
		UserId: aws.String("AIDACIDEPLOYER000001"), Path: aws.String("/"), CreateDate: ago(0),
	})
	a.iam.groups = append(a.iam.groups, iamtypes.GroupDetail{
		Arn: aws.String("arn:aws:iam::" + accountA + ":group/ops"), GroupName: aws.String("ops"),
		GroupId: aws.String("AGPAOPSOPSOPSOPSOPS1"), Path: aws.String("/"), CreateDate: ago(0),
	})
	listsFunctions(a, "us-east-1", "refund", refund, "t1", shared, "t2", shared)
	l.scanAndProject(a)
	if err := l.db.Exec(`INSERT INTO iga_identity_accounts (workspace_id, display_name, account_kind, provider, source_key)
	                     VALUES (?, 'SharedToolRole', 'github_user', 'github', 'github␟user␟1')`, l.ws).Error; err != nil {
		t.Fatalf("seed github identity: %v", err)
	}
	// An AWS row no projection pass supports is not a graph row either (D-6).
	if err := l.db.Exec(`INSERT INTO iga_identity_accounts (workspace_id, display_name, account_kind, provider, source_key)
	                     VALUES (?, 'OrphanRole', 'iam_role', 'aws', 'aws' || chr(31) || 'arn:aws:iam::`+accountA+`:role/OrphanRole')`,
		l.ws).Error; err != nil {
		t.Fatalf("seed unsupported identity: %v", err)
	}
	api := l.api()

	body := listsGet(t, api, "/identities"+qs("facets", "kind,account"))
	rows := digl(body, "data")
	all := []string{"refund-lambda-role", "SharedToolRole", "IdleRole", "ci-deployer", "ops"}
	if got := listsField(rows, "name"); !listsSameSet(got, all) {
		t.Fatalf("identities = %v (neither the GitHub row nor the unsupported AWS row may appear, D-6)", got)
	}
	if num(body, "meta", "total") != 5 {
		t.Errorf("total = %v, want 5: the D-6 rows must not be counted either", dig(body, "meta", "total"))
	}
	for name, used := range map[string]int64{"SharedToolRole": 2, "refund-lambda-role": 1, "IdleRole": 0, "ci-deployer": 0} {
		r := listsRowBy(t, rows, "name", name)
		if num(r, "used_by_count", "value") != used || dig(r, "used_by_count", "exact") != true {
			t.Errorf("%s used_by_count = %v, want {%d, exact}", name, r["used_by_count"], used)
		}
		if digs(r, "region") != "global" || digs(r, "account", "id") != accountA || digs(r, "state") != "current" {
			t.Errorf("%s = %v: want region global, account %s, state current", name, r, accountA)
		}
	}
	shr := listsRowBy(t, rows, "name", "SharedToolRole")
	if digs(shr, "kind") != "iam_role" || digs(shr, "arn") != shared || !strings.HasPrefix(digs(shr, "ref"), "identity:") {
		t.Errorf("SharedToolRole row = %v", shr)
	}
	if f, _ := listsFacet(body, "kind"); f["iam_role"] != 3 || f["iam_user"] != 1 || f["iam_group"] != 1 {
		t.Errorf("kind facet = %v", f)
	}

	for _, tc := range []struct {
		kv   []string
		want []string
	}{
		{[]string{"kind", "iam_user"}, []string{"ci-deployer"}},
		{[]string{"used_by", "workloads"}, []string{"refund-lambda-role", "SharedToolRole"}},
		{[]string{"q", "AROASHAREDTOOLROLE01"}, []string{"SharedToolRole"}}, // provider id
		{[]string{"q", shared}, []string{"SharedToolRole"}},                 // full ARN
		{[]string{"q", strings.ToLower(shared)}, nil},                       // exact arms are case-sensitive (D-76)
		{[]string{"q", accountA}, all},                                      // the identity's own account
		{[]string{"account", "unknown"}, nil},
		// region is accepted and never filters: IAM is global (D-75).
		{[]string{"region", "eu-west-1"}, all},
		{[]string{"region", "not_stated"}, all},
		{[]string{"provider", "aws"}, all},
		// integration: supported by that connector (D-75), typed or bare.
		{[]string{"integration", refOf("cloud_connector", a.conn)}, all},
		{[]string{"integration", a.conn.String()}, all},
		{[]string{"integration", uuid.NewString()}, nil},
	} {
		got := listsField(listsWalk(t, api, "/identities", 2, tc.kv...), "name")
		if !listsSameSet(got, tc.want) {
			t.Errorf("%v = %v, want %v", tc.kv, got, tc.want)
		}
	}
	// D-13: kind sorts by RANK (role < user < group), never alphabetically
	// (which would put iam_group first); -kind reverses the rank.
	if kinds := strings.Join(listsField(listsWalk(t, api, "/identities", 2, "sort", "kind"), "kind"), ","); kinds !=
		"iam_role,iam_role,iam_role,iam_user,iam_group" {
		t.Errorf("sort=kind = %s, want roles, then users, then groups", kinds)
	}
	if kinds := strings.Join(listsField(listsWalk(t, api, "/identities", 2, "sort", "-kind"), "kind"), ","); kinds !=
		"iam_group,iam_user,iam_role,iam_role,iam_role" {
		t.Errorf("sort=-kind = %s, want the rank reversed", kinds)
	}
}

// §5.1 cursors: a cursor from another filter set, sort or route is 400
// cursor_invalid; a tampered one is 400; limit may change between pages; a
// revision published between pages is 409 revision_stale (E12), and so is a
// stale rev parameter.
func TestP2ListsCursorBinding(t *testing.T) {
	l := newP2Lab(t, "p2-lists-cursor", true)
	a := l.account(accountA)
	role := a.role("refund-lambda-role", "AROA5XK7QEXAMPLE")
	listsFunctions(a, "us-east-1", "fn-1", role, "fn-2", role, "fn-3", role, "fn-4", role)
	l.scanAndProject(a)
	api := l.api()

	first := listsGet(t, api, "/workloads"+qs("limit", "1", "q", "fn"))
	cur := digs(first, "meta", "next_cursor")
	if cur == "" || num(first, "meta", "rev") != 1 {
		t.Fatalf("page one meta = %v, want rev 1 and a cursor", dig(first, "meta"))
	}
	body, sig, _ := strings.Cut(cur, ".")
	tampered := body[:len(body)-2] + "AA." + sig
	for name, path := range map[string]string{
		"another filter": "/workloads" + qs("limit", "1", "q", "other", "cursor", cur),
		"another sort":   "/workloads" + qs("limit", "1", "q", "fn", "sort", "-name", "cursor", cur),
		"another route":  "/identities" + qs("limit", "1", "q", "fn", "cursor", cur),
		"tampered":       "/workloads" + qs("limit", "1", "q", "fn", "cursor", tampered),
	} {
		code, b := api.get(path)
		if code != 400 || errCode(b) != "cursor_invalid" {
			t.Errorf("%s: %d %v, want 400 cursor_invalid", name, code, b)
		}
	}
	if b := listsGet(t, api, "/workloads"+qs("limit", "3", "q", "fn", "cursor", cur)); len(digl(b, "data")) != 3 {
		t.Errorf("a new limit on page two = %d rows, want 3", len(digl(b, "data")))
	}

	l.scanAndProject(a) // rev 2
	code, stale := api.get("/workloads" + qs("limit", "1", "q", "fn", "cursor", cur))
	mustStatus(t, "page two after a publication", code, stale, 409)
	if errCode(stale) != "revision_stale" || num(stale, "error", "requested_rev") != 1 ||
		num(stale, "error", "current_rev") != 2 || digs(stale, "error", "current_published_at") == "" {
		t.Errorf("409 body = %v, want revision_stale 1 -> 2 with current_published_at", stale)
	}
	if code, b := api.get("/workloads" + qs("rev", "1")); code != 409 || errCode(b) != "revision_stale" {
		t.Errorf("rev=1 after rev 2 = %d %v, want 409 revision_stale", code, b)
	}
	if b := listsGet(t, api, "/workloads"+qs("rev", "2")); num(b, "meta", "rev") != 2 {
		t.Errorf("rev=2 meta = %v", dig(b, "meta"))
	}
}

// Lists exclude retired objects unless lifecycle asks (§5.2): a recreated
// role's old incarnation and a deleted Lambda are listed under
// lifecycle=retired, with their reason, and never by default.
func TestP2ListsLifecycle(t *testing.T) {
	l := newP2Lab(t, "p2-lists-lifecycle", true)
	a := l.account(accountA)
	role := a.role("SharedToolRole", "AROASHAREDOLDOLDOLD1")
	listsFunctions(a, "us-east-1", "kept-fn", role, "gone-fn", role)
	l.scanAndProject(a)
	api := l.api()
	oldRef := digs(listsGet(t, api, "/identities"), "data", 0, "ref")

	role = a.role("SharedToolRole", "AROASHAREDNEWNEWNEW1") // deleted and recreated
	listsFunctions(a, "us-east-1", "kept-fn", role)         // gone-fn deleted
	l.scanAndProject(a)

	active := digl(listsGet(t, api, "/identities"), "data")
	if len(active) != 1 || digs(active[0], "ref") == oldRef || digs(active[0], "lifecycle") != "active" {
		t.Errorf("default identities = %v, want only the NEW SharedToolRole", active)
	}
	retired := digl(listsGet(t, api, "/identities"+qs("lifecycle", "retired")), "data")
	if len(retired) != 1 || digs(retired[0], "ref") != oldRef || digs(retired[0], "lifecycle") != "retired" ||
		digs(retired[0], "retired_reason") != "recreated" {
		t.Errorf("lifecycle=retired = %v, want the old incarnation, retired recreated", retired)
	}
	if n := len(digl(listsGet(t, api, "/identities"+qs("lifecycle", "all")), "data")); n != 2 {
		t.Errorf("lifecycle=all = %d identities, want both incarnations", n)
	}

	if names := listsField(digl(listsGet(t, api, "/workloads"), "data"), "name"); !listsSameSet(names, []string{"kept-fn"}) {
		t.Errorf("default workloads = %v, want kept-fn only", names)
	}
	gone := digl(listsGet(t, api, "/workloads"+qs("lifecycle", "retired")), "data")
	if len(gone) != 1 || digs(gone[0], "name") != "gone-fn" || digs(gone[0], "lifecycle") != "retired" {
		t.Errorf("retired workloads = %v, want gone-fn", gone)
	}
}

// §5.5 list consistency (E12): a list that filters or sorts on classification
// binds its cursor to the classification clock, and a decision between two
// pages is 409 listing_changed; a list that does neither is unaffected.
func TestP2ListsClassificationChangeBetweenPages(t *testing.T) {
	l := newP2Lab(t, "p2-lists-classification", true)
	a := l.account(accountA)
	role := a.role("refund-lambda-role", "AROA5XK7QEXAMPLE")
	listsFunctions(a, "us-east-1", "fn-1", role, "fn-2", role, "fn-3", role, "fn-4", role)
	l.scanAndProject(a)
	api := l.api()

	byClass := listsGet(t, api, "/workloads"+qs("classification", "unclassified", "limit", "2"))
	bySort := listsGet(t, api, "/workloads"+qs("sort", "classification", "limit", "2"))
	plain := listsGet(t, api, "/workloads"+qs("limit", "2"))
	target := refUUID(t, digs(byClass, "data", 0, "ref"))

	listsDecide(t, l.db, l.ws, target)

	for name, first := range map[string]map[string]any{"classification filter": byClass, "classification sort": bySort} {
		path := "/workloads" + qs("limit", "2", "cursor", digs(first, "meta", "next_cursor"))
		if name == "classification filter" {
			path += "&classification=unclassified"
		} else {
			path += "&sort=classification"
		}
		code, b := api.get(path)
		if code != 409 || errCode(b) != "listing_changed" || digs(b, "error", "reason") != "classification_changed" {
			t.Errorf("%s: next page after a decision = %d %v, want 409 listing_changed classification_changed", name, code, b)
		}
	}
	if code, b := api.get("/workloads" + qs("limit", "2", "cursor", digs(plain, "meta", "next_cursor"))); code != 200 {
		t.Errorf("a list that neither filters nor sorts on classification = %d %v, want 200", code, b)
	}

	agents := listsGet(t, api, "/workloads"+qs("classification", "agent", "facets", "classification"))
	if refs := listsField(digl(agents, "data"), "ref"); len(refs) != 1 || refs[0] != refOf("workload", target) {
		t.Errorf("classification=agent = %v, want the classified workload", refs)
	}
	if f, _ := listsFacet(agents, "classification"); f["agent"] != 1 || f["classified_agent"] != 1 || f["unclassified"] != 3 {
		t.Errorf("classification facet = %v, want agent 1, classified_agent 1, unclassified 3", f)
	}
}

// §5.1: nothing published yet is 200 with empty data and graph_state
// not_published -- a first-run state, never "no results" and never an error.
func TestP2ListsNotPublished(t *testing.T) {
	l := newP2Lab(t, "p2-lists-unpublished", true)
	api := l.api()
	for _, route := range []string{"/workloads", "/identities", "/resources"} {
		b := listsGet(t, api, route)
		if d, ok := b["data"].([]any); !ok || len(d) != 0 {
			t.Errorf("%s data = %v, want []", route, b["data"])
		}
		if digs(b, "meta", "graph_state") != "not_published" || dig(b, "meta", "rev") != nil {
			t.Errorf("%s meta = %v, want not_published with rev null", route, dig(b, "meta"))
		}
	}
}

// §5.2: anything malformed or disallowed is 400 invalid_parameter -- including
// a parameter the list does not have, so a typo never silently widens a list.
func TestP2ListsInvalidParameters(t *testing.T) {
	l := newP2Lab(t, "p2-lists-params", true)
	l.scanAndProject(oneLambda(l))
	api := l.api()
	for _, path := range []string{
		"/workloads" + qs("q", "a"),
		"/workloads" + qs("limit", "0"),
		"/workloads" + qs("limit", "201"),
		"/workloads" + qs("sort", "kind"),
		"/workloads" + qs("facets", "kind"),
		"/workloads" + qs("lifecycle", "gone"),
		"/workloads" + qs("account", "1234"),
		"/workloads" + qs("region", "mars-1"),
		"/workloads" + qs("runtime_kind", "k8s_pod"),
		"/workloads" + qs("classification", "maybe"),
		"/workloads" + qs("execution_role_state", "unknown"),
		"/workloads" + qs("integration", "not-a-ref"),
		"/workloads" + qs("integration", refOf("workload", uuid.New())),
		"/workloads" + qs("kind", "iam_role"),
		"/workloads" + qs("rev", "0"),
		"/identities" + qs("kind", "iam_bucket"),
		"/identities" + qs("used_by", "principals"),
		"/identities" + qs("sort", "service"),
		"/resources" + qs("kind", "discovered"),
		"/resources" + qs("service", "S3!"),
		"/resources" + qs("runtime_kind", "lambda_function"),
		// D-75: provider accepts only aws; integration is a connector, typed
		// or bare; region on identities is validated though it never filters.
		"/workloads" + qs("provider", "github"),
		"/identities" + qs("provider", "gcp"),
		"/resources" + qs("provider", "AWS"),
		"/identities" + qs("integration", "not-a-ref"),
		"/resources" + qs("integration", refOf("identity", uuid.New())),
		"/identities" + qs("region", "mars-1"),
		"/identities" + qs("execution_role_state", "resolved"),
	} {
		code, b := api.get(path)
		if code != 400 || errCode(b) != "invalid_parameter" {
			t.Errorf("GET %s = %d %v, want 400 invalid_parameter", path, code, b)
		}
	}
	if code, b := api.get("/workloads" + qs("cursor", "garbage")); code != 400 || errCode(b) != "cursor_invalid" {
		t.Errorf("a garbage cursor = %d %v, want 400 cursor_invalid", code, b)
	}
}
