package igaread

// Pure pieces of the list engine (lists.go, nodes.go). Everything that
// touches the database is proven end to end in tests/integration/p2_lists_*.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

func listsTestAccounts(conns ...ConnectorInfo) *Accounts {
	a := &Accounts{byAccount: map[string]*ConnectorInfo{}, byConnector: map[uuid.UUID]*ConnectorInfo{}}
	for i := range conns {
		c := &conns[i]
		a.byConnector[c.ID] = c
		a.byAccount[c.AccountID] = c
	}
	return a
}

// The account facet ALWAYS offers unknown, and every live connected account,
// even at 0 (D-14, §2.14.10); unknown sorts last.
func TestP2ListsAccountFacetOffersUnknownAndConnected(t *testing.T) {
	accts := listsTestAccounts(
		ConnectorInfo{ID: uuid.New(), AccountID: "111111111111", Label: "prod", Status: "active"},
		ConnectorInfo{ID: uuid.New(), AccountID: "222222222222", Label: "old", Status: models.CloudConnectorRevoked},
	)
	got := listsAccountFacet(map[string]int64{"333333333333": 2}, accts)
	byValue := map[string]FacetValue{}
	for _, v := range got {
		byValue[v.Value] = v
	}
	if u, ok := byValue["unknown"]; !ok || u.Count != 0 || u.Label != "Unknown account" {
		t.Errorf("facet = %+v, want unknown offered at 0", got)
	}
	if p, ok := byValue["111111111111"]; !ok || p.Count != 0 || p.Label != "prod" {
		t.Errorf("facet = %+v, want the connected account at 0 with its label", got)
	}
	if _, ok := byValue["222222222222"]; ok {
		t.Errorf("facet = %+v: a revoked connector's account with no rows is not a choice", got)
	}
	if x := byValue["333333333333"]; x.Count != 2 || x.Label != "333333333333" {
		t.Errorf("an unconnected account with rows = %+v, want its id as label", x)
	}
	if got[len(got)-1].Value != "unknown" {
		t.Errorf("facet order = %+v, want unknown last", got)
	}
	if got[0].Value != "333333333333" {
		t.Errorf("facet order = %+v, want the largest count first", got)
	}
}

// D-14: the region facet ALWAYS offers not_stated, even at 0, labelled, last.
func TestP2ListsRegionFacetAlwaysOffersNotStated(t *testing.T) {
	got := listsRegionFacet(map[string]int64{"us-east-1": 3}, nil)
	if len(got) != 2 || got[0].Value != "us-east-1" || got[1].Value != RegionNotStated ||
		got[1].Count != 0 || got[1].Label != "Region not stated" {
		t.Errorf("region facet = %+v, want us-east-1 then not_stated at 0", got)
	}
	got = listsRegionFacet(map[string]int64{"": 2}, nil)
	if len(got) != 1 || got[0].Value != RegionNotStated || got[0].Count != 2 {
		t.Errorf("region facet = %+v, want not_stated 2", got)
	}
}

// The workload name sort is ONE row comparison over (lower(name), id) in both
// directions -- the tuple idx_iga_workload_list serves (§5.3) -- and every
// sort ends with id (§5.2).
func TestP2ListsPageSQLNameKeysetIsARowComparison(t *testing.T) {
	spec := &listsWorkloads
	fs := []listsFilter{{sql: "w.workspace_id = ?", args: []any{uuid.New()}}}
	keys := spec.keys["name"]
	after := &listsAfter{keys: []any{"fn"}, id: uuid.New()}

	asc, args := listsPageSQL(spec, fs, keys, false, after, 10)
	if !strings.Contains(asc, "(lower(w.display_name), w.id) > (?::text, ?::uuid)") {
		t.Errorf("ascending keyset missing or malformed:\n%s", asc)
	}
	if !strings.Contains(asc, "ORDER BY lower(w.display_name) ASC, w.id ASC") {
		t.Errorf("ascending order must end with id:\n%s", asc)
	}
	if n := len(args); n != 4 || args[3] != 11 {
		t.Errorf("args = %v, want workspace, key, id, then limit+1", args)
	}
	desc, _ := listsPageSQL(spec, fs, keys, true, after, 10)
	if !strings.Contains(desc, "(lower(w.display_name), w.id) < (?::text, ?::uuid)") ||
		!strings.Contains(desc, "ORDER BY lower(w.display_name) DESC, w.id DESC") {
		t.Errorf("descending must reverse the whole tuple:\n%s", desc)
	}
	first, fargs := listsPageSQL(spec, fs, keys, false, nil, 10)
	if strings.Contains(first, ") > (") || len(fargs) != 2 {
		t.Errorf("a first page has no keyset:\n%s %v", first, fargs)
	}
}

// D-13: "unknown last in both directions". A descending account sort reverses
// everything BUT the no-value flag, so the keyset becomes the lexicographic OR
// chain with the flag ascending.
func TestP2ListsPageSQLNoValueFlagStaysAscending(t *testing.T) {
	spec := &listsIdentities
	fs := []listsFilter{{sql: "ia.workspace_id = ?", args: []any{uuid.New()}}}
	keys := spec.keys["account"] // flag, account, name
	after := &listsAfter{keys: []any{int64(0), "111111111111", "role"}, id: uuid.New()}

	desc, args := listsPageSQL(spec, fs, keys, true, after, 10)
	flag := keys[0].sql
	for _, want := range []string{
		"ORDER BY " + flag + " ASC, " + IdentityAccountSQL + " DESC, lower(ia.display_name) DESC, ia.id DESC",
		"((" + flag + ") > ?::bigint)",
		"((" + flag + ") = ?::bigint AND (" + IdentityAccountSQL + ") < ?::text)",
		"(lower(ia.display_name)) = ?::text AND (ia.id) < ?::uuid)",
	} {
		if !strings.Contains(desc, want) {
			t.Errorf("descending account sort lacks %q:\n%s", want, desc)
		}
	}
	// workspace, then 1+2+3+4 keyset binds, then limit+1.
	if n := len(args); n != 1+10+1 || args[1] != int64(0) || args[len(args)-1] != 11 {
		t.Errorf("args = %v", args)
	}
	asc, _ := listsPageSQL(spec, fs, keys, false, after, 10)
	if !strings.Contains(asc, "("+flag+", "+IdentityAccountSQL+", lower(ia.display_name), ia.id) > (") {
		t.Errorf("ascending: every component ascends, so one row comparison:\n%s", asc)
	}
}

// D-13's other orders: ranks, never alphabetical; name sorts carry the
// account; unknown/null last.
func TestP2ListsSortTuples(t *testing.T) {
	sqls := func(ks []listsKey) []string {
		var out []string
		for _, k := range ks {
			out = append(out, k.sql)
		}
		return out
	}
	for name, tc := range map[string]struct {
		keys []listsKey
		want []string
	}{
		"identities name":          {listsIdentities.keys["name"], []string{"lower(ia.display_name)", listsNoValueLast(IdentityAccountSQL).sql, IdentityAccountSQL}},
		"identities kind":          {listsIdentities.keys["kind"], []string{IdentityKindRankSQL, "lower(ia.display_name)", listsNoValueLast(IdentityAccountSQL).sql, IdentityAccountSQL}},
		"resources kind (default)": {listsResources.keys["kind"], []string{ResourceKindRankSQL, "lower(r.display_name)", listsNoValueLast(ResourceAccountSQL).sql, ResourceAccountSQL}},
		"resources service":        {listsResources.keys["service"], []string{listsNoValueLast(ResourceServiceSQL).sql, ResourceServiceSQL, "lower(r.display_name)", listsNoValueLast(ResourceAccountSQL).sql, ResourceAccountSQL}},
		"workloads classification": {listsWorkloads.keys["classification"], []string{WorkloadClassificationRankSQL, "lower(w.display_name)"}},
		"workloads name":           {listsWorkloads.keys["name"], []string{"lower(w.display_name)"}},
	} {
		if got := sqls(tc.keys); strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("%s = %v, want %v", name, got, tc.want)
		}
	}
	for _, k := range listsLastConfirmedKeys()[:1] {
		if !k.fixed {
			t.Error("the never-confirmed flag must stay ascending (nulls last in both directions)")
		}
	}
}

// Cursor keys: the right number of values, numeric ones as integers; anything
// else is cursor_invalid.
func TestP2ListsDecodeCursorKey(t *testing.T) {
	keys := listsResources.keys["name"] // name, flag (numeric), account
	raw, _ := json.Marshal(listsCursorKey{K: []string{"arn:aws:s3:::a/*", "1", ""}})
	a, err := listsDecodeCursor(&Cursor{Key: raw, ID: uuid.New()}, keys)
	if err != nil || a.keys[0] != "arn:aws:s3:::a/*" || a.keys[1] != int64(1) || a.keys[2] != "" {
		t.Fatalf("decode = %+v %v", a, err)
	}
	for name, k := range map[string]listsCursorKey{
		"too few":     {K: []string{"x", "1"}},
		"too many":    {K: []string{"x", "1", "", "y"}},
		"not numeric": {K: []string{"x", "one", ""}},
	} {
		raw, _ := json.Marshal(k)
		if _, err := listsDecodeCursor(&Cursor{Key: raw}, keys); err == nil || err.Code != "cursor_invalid" {
			t.Errorf("%s: %v, want cursor_invalid", name, err)
		}
	}
}

// D-73's table: each list names only its surfaces, narrowed by the request's
// filters, and says what the gap leaves out.
func TestP2ListsCoverageAffects(t *testing.T) {
	all := listsScope{}
	usEast := listsScope{regions: []string{"us-east-1"}}
	onlyNotStated := listsScope{regionNotStated: true}
	ec2 := listsScope{kinds: []string{models.WorkloadEC2Instance}}
	users := listsScope{kinds: []string{models.CloudIdentityIAMUser}}
	for _, tc := range []struct {
		list, surface string
		sc            listsScope
		want          string
	}{
		{ListRouteIdentities, "iam_users", all, "identities of kind iam_user"},
		{ListRouteIdentities, "iam_roles", all, "identities of kind iam_role"},
		{ListRouteIdentities, "iam_groups", all, "identities of kind iam_group"},
		{ListRouteIdentities, "iam_roles", users, ""},
		{ListRouteIdentities, "iam_users", users, "identities of kind iam_user"},
		{ListRouteIdentities, "permission_scan", users, "permissions and trust of identities"},
		{ListRouteIdentities, "lambda:eu-west-1", all, ""},
		{ListRouteIdentities, "policy_documents", all, ""},
		{ListRouteIdentities, "organizations", all, ""},
		{ListRouteWorkloads, "lambda:eu-west-1", all, "workloads of kind lambda_function in eu-west-1"},
		{ListRouteWorkloads, "lambda:eu-west-1", usEast, ""},
		{ListRouteWorkloads, "lambda:us-east-1", usEast, "workloads of kind lambda_function in us-east-1"},
		{ListRouteWorkloads, "lambda:us-east-1", onlyNotStated, ""},
		{ListRouteWorkloads, "lambda:us-east-1", ec2, ""},
		{ListRouteWorkloads, "ec2:us-east-1", ec2, "workloads of kind ec2_instance in us-east-1"},
		{ListRouteWorkloads, "agentcore-gateways:us-east-1", all, "workloads of kind bedrock_agentcore_gateway in us-east-1"},
		{ListRouteWorkloads, "compute:eu-west-1", ec2, "workloads in eu-west-1"},
		{ListRouteWorkloads, "compute:eu-west-1", usEast, ""},
		{ListRouteWorkloads, "workload_scan", usEast, "all workloads"},
		{ListRouteWorkloads, "iam_roles", all, ""},
		{ListRouteWorkloads, "activity", all, ""},
		{ListRouteResources, "iam_policies", all, "resources named by managed policies"},
		{ListRouteResources, "policy_documents", all, "resources named by unreadable policy documents"},
		{ListRouteResources, "permission_scan", all, "all resources"},
		{ListRouteResources, "iam_users", all, ""},
		{ListRouteResources, "lambda:eu-west-1", all, ""},
	} {
		if got := listsAffects(tc.list, tc.surface, tc.sc); got != tc.want {
			t.Errorf("%s / %s (%+v) = %q, want %q", tc.list, tc.surface, tc.sc, got, tc.want)
		}
	}
}

// §5.2 totals: counted up to 10 000; beyond, not known with total_at_least;
// a count that did not finish is not known, never a guess.
func TestP2ListsTotalsBeyondTheCap(t *testing.T) {
	var m ListMeta
	m.SetTotal(TotalCap+1, true)
	if m.TotalKnown || m.Total != nil || m.TotalAtLeast == nil || *m.TotalAtLeast != TotalCap {
		t.Errorf("10001 counted = %+v, want total_known false, total_at_least 10000", m)
	}
	m = ListMeta{}
	m.SetTotal(TotalCap, true)
	if !m.TotalKnown || m.Total == nil || *m.Total != TotalCap {
		t.Errorf("10000 counted = %+v, want known", m)
	}
	m = ListMeta{}
	m.SetTotal(0, false)
	if m.TotalKnown || m.Total != nil || m.TotalAtLeast != nil {
		t.Errorf("a timed-out count = %+v, want unknown with no number", m)
	}
}

// D-17: per-row counts are exact at or under 1000 and 1000+ above.
func TestP2ListsCappedCount(t *testing.T) {
	for n, want := range map[int64]Exact{0: ExactOf(0), 1000: ExactOf(1000), 1001: {Value: ptrInt64(1000), Exact: false}} {
		got := CappedCount(n)
		if got.Exact != want.Exact || *got.Value != *want.Value {
			t.Errorf("CappedCount(%d) = {%d %v}, want {%d %v}", n, *got.Value, got.Exact, *want.Value, want.Exact)
		}
	}
}

// D-16: an S3 object selector is typed as an object, never a bucket, and the
// execution_role object carries the fields its state has.
func TestP2ListsResourceTypeAndExecutionRole(t *testing.T) {
	for text, want := range map[string]string{
		"arn:aws:s3:::support-tickets/*":            "s3_object",
		"arn:aws:s3:::support-tickets":              "s3_bucket",
		"arn:aws:dynamodb:us-east-1:1:table/orders": "dynamodb_table",
		"*": "unknown",
	} {
		if got := ResourceType(text); got != want {
			t.Errorf("ResourceType(%q) = %q, want %q", text, got, want)
		}
	}
	id, name := uuid.New(), "SharedToolRole"
	if got := ExecutionRoleOf(models.ExecRoleResolved, "", &id, &name); got["identity"] != R(RefIdentity, id) || got["name"] != name {
		t.Errorf("resolved = %v", got)
	}
	if got := ExecutionRoleOf(models.ExecRoleResolved, "", nil, nil); got["identity"] != nil || got["name"] != nil {
		t.Errorf("resolved with no live edge = %v, want identity and name null, never a guess", got)
	}
	got := ExecutionRoleOf(models.ExecRoleNotInScan, "arn:aws:iam::1:role/x", nil, nil)
	if got["execution_role_arn"] != "arn:aws:iam::1:role/x" {
		t.Errorf("not_in_scan = %v, want the ARN it runs as", got)
	}
	if _, has := got["identity"]; has {
		t.Errorf("not_in_scan = %v names an identity", got)
	}
	if got := ExecutionRoleOf(models.ExecRoleNone, "", nil, nil); len(got) != 1 {
		t.Errorf("none = %v, want only its state", got)
	}
}

// D-74: a node's partition is igagraph's own (Partitions + Matches), and its
// gaps follow the documented order: present unreached surfaces and scanner
// markers; else absent surfaces as unknown; else, for document-protected
// classes, policy_documents.
func TestP2ListsPartitionOfAndGaps(t *testing.T) {
	scope, conn := uuid.New(), uuid.New()
	wl, ok := partitionOf(models.ObjectWorkload, models.WorkloadLambdaFunction, "eu-west-1", scope, conn)
	if !ok || strings.Join(wl.RequiredSurfaces, ",") != "lambda:eu-west-1" ||
		strings.Join(wl.RequiredScanners, ",") != "workload_scan,compute:eu-west-1" {
		t.Fatalf("lambda partition = %+v %v", wl, ok)
	}
	if _, ok := partitionOf(models.ObjectWorkload, models.WorkloadLambdaFunction, "", scope, conn); ok {
		t.Error("a workload with no region has no partition to explain it")
	}
	users, _ := partitionOf(models.ObjectIdentity, models.CloudIdentityIAMUser, "", scope, conn)
	if strings.Join(users.RequiredSurfaces, ",") != "iam_users" {
		t.Errorf("iam_user partition = %+v", users)
	}
	res, _ := partitionOf(models.ObjectResource, "", "", scope, conn)

	cov := func(kv ...string) models.ScanCoverage {
		c := models.ScanCoverage{Surfaces: map[string]models.SurfaceCoverage{}}
		for i := 0; i+1 < len(kv); i += 2 {
			c.Surfaces[kv[i]] = models.SurfaceCoverage{State: kv[i+1]}
		}
		return c
	}
	str := func(gs []surfaceGap) string {
		var out []string
		for _, g := range gs {
			out = append(out, g.surface+"="+g.state)
		}
		return strings.Join(out, ",")
	}
	for name, tc := range map[string]struct {
		got  []surfaceGap
		want string
	}{
		"denied surface":      {partitionGaps(wl, cov("lambda:eu-west-1", "denied"), models.ObjectWorkload), "lambda:eu-west-1=denied"},
		"scanner marker":      {partitionGaps(wl, cov("lambda:eu-west-1", "reached", "workload_scan", "denied"), models.ObjectWorkload), "workload_scan=denied"},
		"region not selected": {partitionGaps(wl, cov("compute:eu-west-1", "not_selected"), models.ObjectWorkload), "compute:eu-west-1=not_selected"},
		"absent means unknown": {partitionGaps(wl, cov("lambda:us-east-1", "reached"), models.ObjectWorkload),
			"lambda:eu-west-1=unknown"},
		"everything reached": {partitionGaps(users, cov("iam_users", "reached"), models.ObjectIdentity), ""},
		"document protected": {partitionGaps(res, cov("iam_roles", "reached", "iam_users", "reached", "iam_groups", "reached",
			"iam_policies", "reached", "policy_documents", "partial"), models.ObjectResource), "policy_documents=partial"},
		"identities are not document protected": {partitionGaps(users, cov("iam_users", "reached", "policy_documents", "partial"),
			models.ObjectIdentity), ""},
	} {
		if s := str(tc.got); s != tc.want {
			t.Errorf("%s: gaps = %q, want %q", name, s, tc.want)
		}
	}
}

// D-74 since: the start of the unbroken streak, walking back from the run
// the revision was built from; null when the window may cut the streak short.
func TestP2ListsStreakSince(t *testing.T) {
	at := func(d int) *time.Time { t := time.Date(2026, 9, d, 0, 0, 0, 0, time.UTC); return &t }
	run := func(d int, state string) staleRun {
		r := staleRun{ID: uuid.New(), PublishedAt: at(d)}
		r.cov = models.ScanCoverage{Surfaces: map[string]models.SurfaceCoverage{"iam_users": {State: state}}}
		return r
	}
	// newest first: a newer run (not the revision's), then the revision's run.
	runs := []staleRun{run(23, "reached"), run(22, "denied"), run(21, "denied"), run(20, "reached"), run(19, "denied")}
	if got := streakSince(runs, runs[1].ID, "iam_users", "denied"); got == nil || !got.Equal(*at(21)) {
		t.Errorf("since = %v, want 21 Sep (the streak 22, 21; broken on 20)", got)
	}
	if got := streakSince(runs, runs[4].ID, "iam_users", "denied"); got == nil || !got.Equal(*at(19)) {
		t.Errorf("since = %v, want the oldest run itself when history ends there", got)
	}
	if got := streakSince(runs, uuid.New(), "iam_users", "denied"); got != nil {
		t.Errorf("since for a run outside the window = %v, want null", got)
	}
	full := make([]staleRun, StaleHistoryRuns+1)
	for i := range full {
		full[i] = run(1, "denied")
	}
	if got := streakSince(full, full[0].ID, "iam_users", "denied"); got != nil {
		t.Errorf("a streak filling the window = %v, want null (it may begin earlier)", got)
	}
}
