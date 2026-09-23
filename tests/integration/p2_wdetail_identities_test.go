package integration

// T6.3 -- GET /api/iga/v1/workloads/:id/identities (SPEC-iga-phase2-graph.md
// §5.3, §2.14.6, §4.6; D-12, D-17, D-62, D-73, D-74, D-77): execution, other,
// groups and may_assume, each section paged, beside execution_role_state and
// its ARN. Gates: E3 (the execution identity), E5/B1 (two workloads, one
// role), "execution role states each worded" (every state with the data its
// sentence needs), all through the REAL scan worker and projector.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/authsec-ai/authsec/models"
)

// wdetailIdentities is the tab of a workload, required 200.
func wdetailIdentities(t *testing.T, api *readAPI, l *p2Lab, workload string, kv ...string) map[string]any {
	t.Helper()
	return wdetailGet(t, api, "/workloads/"+wdetailWorkload(t, l, workload).String()+"/identities"+qs(kv...))
}

// B1 / E5 / E3: two workloads in one region share one role -- ONE identity,
// two executes_as rows -- and each workload's tab names it as its execution
// identity with used_by_count {2, exact}. may_assume lists the roles whose
// trust policy names that role, with the trust statement's conditions
// verbatim (null when it has none) and the mechanism.
func TestP2WdetailIdentitiesSharedRoleAndMayAssume(t *testing.T) {
	l, a := wdetailSharedLab(t, "p2-wdetail-ids-shared")
	shared := a.roleARN("SharedToolRole")
	// Two roles trust SharedToolRole; one under a Condition. The lab's own
	// role() gives every role a Lambda trust, so the documents are replaced.
	trustRole(a, "data-reader", "AROAWDETAILDATAREAD1", trustDoc(trustAllow(`{"AWS":"`+shared+`"}`, "sts:AssumeRole")))
	trustRole(a, "audit-reader", "AROAWDETAILAUDITRD01", trustDoc(
		`{"Sid":"AuditOnly","Effect":"Allow","Principal":{"AWS":"`+shared+`"},"Action":"sts:AssumeRole",`+
			`"Condition":{"StringEquals":{"sts:ExternalId":"audit-2026"}}}`))
	l.scanAndProject(a)
	api := l.api()
	role := wdetailIdentity(t, l, "SharedToolRole")

	if n := l.count(`SELECT count(*) FROM iga_relationship WHERE workspace_id = ? AND relationship_type = 'executes_as'
	                  AND target_identity_account_id = ? AND state = 'current'`, l.ws, role); n != 2 {
		t.Fatalf("setup (B1): %d current executes_as rows to SharedToolRole, want 2", n)
	}
	if n := l.count(`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = ? AND provider = 'aws'
	                  AND display_name = 'SharedToolRole'`, l.ws); n != 1 {
		t.Fatalf("setup (B1): %d SharedToolRole identities, want ONE", n)
	}

	claims := map[string]bool{}
	for _, w := range []string{"ticket-tools", "refund-tools"} {
		body := wdetailIdentities(t, api, l, w)
		d := dig(body, "data")
		exec := digl(d, "execution", "items")
		if len(exec) != 1 {
			t.Fatalf("%s execution = %s, want the one executes_as", w, wdetailJSON(exec))
		}
		e := exec[0]
		claims[digs(e, "claim")] = true
		if digs(e, "type") != models.RelTypeExecutesAs || digs(e, "identity", "ref") != refOf("identity", role) ||
			digs(e, "identity", "name") != "SharedToolRole" || digs(e, "identity", "kind") != models.CloudIdentityIAMRole ||
			digs(e, "identity", "arn") != shared || digs(e, "identity", "account", "id") != a.id ||
			digs(e, "basis") != models.BasisDeclared || digs(e, "state") != "current" ||
			dig(e, "valid_from") == nil || dig(e, "last_confirmed_at") == nil {
			t.Errorf("%s execution item = %s", w, wdetailJSON(e))
		}
		if num(e, "used_by_count", "value") != 2 || dig(e, "used_by_count", "exact") != true {
			t.Errorf("%s used_by_count = %v, want {2, exact: true}: both workloads run as it", w, dig(e, "used_by_count"))
		}
		if digs(d, "execution_role_state") != models.ExecRoleResolved {
			t.Errorf("%s execution_role_state = %q, want resolved", w, digs(d, "execution_role_state"))
		}
		if m := d.(map[string]any); m["execution_role_arn"] != nil {
			t.Errorf("%s execution_role_arn = %v, want null when resolved", w, m["execution_role_arn"])
		} else if _, present := m["execution_role_arn"]; !present {
			t.Errorf("%s execution_role_arn is absent, want present and null", w)
		}
		for _, s := range []string{"other", "groups"} {
			if items, ok := dig(d, s, "items").([]any); !ok || len(items) != 0 || dig(d, s, "total_known") != true || num(d, s, "total") != 0 {
				t.Errorf("%s %s = %s, want an empty, counted section", w, s, wdetailJSON(dig(d, s)))
			}
		}

		may := digl(d, "may_assume", "items")
		if len(may) != 2 || num(d, "may_assume", "total") != 2 {
			t.Fatalf("%s may_assume = %s, want the two roles trusting SharedToolRole", w, wdetailJSON(dig(d, "may_assume")))
		}
		// Ordered by name: audit-reader, data-reader.
		audit, data := may[0], may[1]
		if digs(audit, "target", "name") != "audit-reader" || digs(data, "target", "name") != "data-reader" {
			t.Fatalf("%s may_assume order = %s, %s, want audit-reader then data-reader", w,
				digs(audit, "target", "name"), digs(data, "target", "name"))
		}
		for _, m := range may {
			if digs(m, "type") != models.RelTypeCanAssume || digs(m, "via_identity") != refOf("identity", role) ||
				digs(m, "mechanism") != models.MechanismSTSAssumeRole || digs(m, "state") != "current" ||
				digs(m, "target", "kind") != models.CloudIdentityIAMRole || digs(m, "target", "account", "id") != a.id ||
				!strings.HasPrefix(digs(m, "claim"), "relationship:") {
				t.Errorf("%s may_assume item = %s", w, wdetailJSON(m))
			}
		}
		if mm := data.(map[string]any); mm["conditions"] != nil {
			t.Errorf("data-reader conditions = %v, want null: its statement has no Condition", mm["conditions"])
		}
		if digs(audit, "conditions", "StringEquals", "sts:ExternalId") != "audit-2026" {
			t.Errorf("audit-reader conditions = %v, want the Condition verbatim", dig(audit, "conditions"))
		}
		if digs(body, "meta", "workload", "lifecycle") != models.IGALifecycleActive || num(body, "meta", "rev") != 2 {
			t.Errorf("%s meta = %v", w, dig(body, "meta"))
		}
	}
	if len(claims) != 2 {
		t.Errorf("the two workloads' execution claims = %v, want two distinct relationships to one identity", claims)
	}
}

// D-77 / D-62: each section pages on its own; ?section=<name>&cursor= returns
// that section alone, and a cursor is bound to its workload, its section, its
// filters and its revision.
func TestP2WdetailIdentitiesSectionPaging(t *testing.T) {
	l, a := wdetailSharedLab(t, "p2-wdetail-ids-paging")
	shared := a.roleARN("SharedToolRole")
	for _, n := range []string{"reader-a", "reader-b", "reader-c"} {
		trustRole(a, n, "AROAWDETAIL"+strings.ToUpper(strings.ReplaceAll(n, "-", ""))+"01", trustDoc(trustAllow(`{"AWS":"`+shared+`"}`, "sts:AssumeRole")))
	}
	l.scanAndProject(a)
	api := l.api()
	id := wdetailWorkload(t, l, "ticket-tools").String()
	base := "/workloads/" + id + "/identities"

	first := wdetailGet(t, api, base+qs("limit", "2"))
	if num(first, "meta", "limit") != 2 {
		t.Errorf("meta.limit = %d, want 2", num(first, "meta", "limit"))
	}
	may := dig(first, "data", "may_assume")
	names := []string{}
	for _, it := range digl(may, "items") {
		names = append(names, digs(it, "target", "name"))
	}
	cur, _ := dig(may, "next_cursor").(string)
	if strings.Join(names, ",") != "reader-a,reader-b" || cur == "" || num(may, "total") != 3 || dig(may, "total_known") != true {
		t.Fatalf("page 1 of may_assume = %s, want reader-a, reader-b, a cursor, total 3", wdetailJSON(may))
	}
	if dig(first, "data", "execution", "next_cursor") != nil {
		t.Errorf("execution next_cursor = %v, want none: one item", dig(first, "data", "execution", "next_cursor"))
	}

	next := wdetailGet(t, api, base+qs("limit", "2", "section", "may_assume", "cursor", cur))
	d := dig(next, "data").(map[string]any)
	for _, absent := range []string{"execution", "other", "groups", "execution_role_state", "execution_role_arn"} {
		if _, ok := d[absent]; ok {
			t.Errorf("?section=may_assume returned %q too; want that section alone", absent)
		}
	}
	items := digl(d, "may_assume", "items")
	if len(items) != 1 || digs(items[0], "target", "name") != "reader-c" || dig(d, "may_assume", "next_cursor") != nil {
		t.Fatalf("page 2 of may_assume = %s, want reader-c and no cursor", wdetailJSON(dig(d, "may_assume")))
	}
	// A section alone, without a cursor, is its first page.
	if its := digl(wdetailGet(t, api, base+qs("section", "execution")), "data", "execution", "items"); len(its) != 1 {
		t.Errorf("?section=execution = %s", wdetailJSON(its))
	}

	for name, tc := range map[string]struct {
		path, code string
		status     int
	}{
		"cursor without its section":   {base + qs("limit", "2", "cursor", cur), "invalid_parameter", http.StatusBadRequest},
		"cursor of another section":    {base + qs("limit", "2", "section", "groups", "cursor", cur), "cursor_invalid", http.StatusBadRequest},
		"cursor of another workload":   {"/workloads/" + wdetailWorkload(t, l, "refund-tools").String() + "/identities" + qs("limit", "2", "section", "may_assume", "cursor", cur), "cursor_invalid", http.StatusBadRequest},
		"cursor with other filters":    {base + qs("limit", "2", "section", "may_assume", "include_ended", "true", "cursor", cur), "cursor_invalid", http.StatusBadRequest},
		"a section that is not one":    {base + qs("section", "principals"), "invalid_parameter", http.StatusBadRequest},
		"include_ended not a boolean":  {base + qs("include_ended", "yes"), "invalid_parameter", http.StatusBadRequest},
		"limit out of range":           {base + qs("limit", "201"), "invalid_parameter", http.StatusBadRequest},
		"a parameter it does not take": {base + qs("sort", "name"), "invalid_parameter", http.StatusBadRequest},
	} {
		code, body := api.get(tc.path)
		if code != tc.status || errCode(body) != tc.code {
			t.Errorf("%s = %d %s, want %d %s", name, code, wdetailJSON(body), tc.status, tc.code)
		}
	}

	// A newer publication makes the cursor stale: 409, never a page of rev 3
	// continuing a page of rev 2.
	l.scanAndProject(a)
	code, body := api.get(base + qs("limit", "2", "section", "may_assume", "cursor", cur))
	if code != http.StatusConflict || errCode(body) != "revision_stale" {
		t.Errorf("cursor after a new publication = %d %s, want 409 revision_stale", code, wdetailJSON(body))
	}
}

// §4.6 / §2.14.7 "Execution role states each worded": every state reaches the
// tab with what its sentence needs -- the ARN for not_in_scan and
// not_in_inventory, nothing for none. not_in_scan with the old executes_as
// still held returns BOTH: the row, marked stale with why, and the state.
func TestP2WdetailExecutionRoleStates(t *testing.T) {
	l := newP2Lab(t, "p2-wdetail-exec-states", true)
	a := l.account(accountA)
	role := a.role("exec-role", "AROAWDETAILEXECROLE1")
	ghost := a.roleARN("GhostRole") // named by a function, held by no scan
	wdetailFunctions(a, "us-east-1",
		wdetailFn{name: "fn-resolved", role: role},
		wdetailFn{name: "fn-ghost", role: ghost},
		wdetailFn{name: "fn-none"})
	l.scanAndProject(a)
	api := l.api()

	type want struct {
		state   string
		arn     any // the tab's execution_role_arn: a string or nil
		items   int
		itemsSt string
	}
	check := func(stage string, cases map[string]want) {
		t.Helper()
		for fn, w := range cases {
			body := wdetailIdentities(t, api, l, fn)
			d := dig(body, "data").(map[string]any)
			if d["execution_role_state"] != w.state {
				t.Errorf("%s %s: execution_role_state = %v, want %s", stage, fn, d["execution_role_state"], w.state)
			}
			if arn, present := d["execution_role_arn"]; !present || arn != w.arn {
				t.Errorf("%s %s: execution_role_arn = %v (present %v), want %v", stage, fn, arn, present, w.arn)
			}
			items := digl(d, "execution", "items")
			if len(items) != w.items || (w.items == 1 && digs(items[0], "state") != w.itemsSt) {
				t.Errorf("%s %s: execution = %s, want %d item(s) %s", stage, fn, wdetailJSON(items), w.items, w.itemsSt)
			}
			// The detail says the same as the tab.
			er := dig(wdetailGet(t, api, "/workloads/"+wdetailWorkload(t, l, fn).String()), "data", "execution_role")
			if digs(er, "state") != w.state {
				t.Errorf("%s %s: detail execution_role = %v, want state %s", stage, fn, er, w.state)
			}
			if w.arn != nil && digs(er, "execution_role_arn") != w.arn {
				t.Errorf("%s %s: detail execution_role = %v, want the ARN %v", stage, fn, er, w.arn)
			}
		}
	}
	check("scan 1", map[string]want{
		"fn-resolved": {models.ExecRoleResolved, nil, 1, "current"},
		"fn-ghost":    {models.ExecRoleNotInInventory, ghost, 0, ""},
		"fn-none":     {models.ExecRoleNone, nil, 0, ""},
	})

	// Scan 2: the roles listing is denied. The role is not read, so the state
	// is not_in_scan WITH its ARN -- and the executes_as it already had is
	// kept, stale, not ended (a scan that could not look proves nothing).
	a.iam.fail["GetAccountAuthorizationDetails:Role"] = denied("iam:GetAccountAuthorizationDetails")
	l.scanAndProject(a)
	check("scan 2 (iam_roles denied)", map[string]want{
		"fn-resolved": {models.ExecRoleNotInScan, role, 1, "stale"},
		"fn-ghost":    {models.ExecRoleNotInInventory, ghost, 0, ""},
		"fn-none":     {models.ExecRoleNone, nil, 0, ""},
	})
	body := wdetailIdentities(t, api, l, "fn-resolved")
	item := digl(body, "data", "execution", "items")[0]
	reasons := digl(item, "stale_reason")
	found := false
	for _, r := range reasons {
		if digs(r, "surface") == models.SurfaceIAMRoles && digs(r, "state") == models.CloudCoverageDenied && digs(r, "account_id") == a.id {
			found = true
		}
	}
	if !found {
		t.Errorf("the stale executes_as stale_reason = %s, want iam_roles denied in %s", wdetailJSON(reasons), a.id)
	}
	// meta.coverage names the gap the sentence cites: "not read in the
	// latest scan" because iam_roles was denied.
	cov := false
	for _, c := range digl(body, "meta", "coverage") {
		if digs(c, "surface") == models.SurfaceIAMRoles && digs(c, "state") == models.CloudCoverageDenied &&
			digs(c, "account_id") == a.id && digs(c, "affects") != "" {
			cov = true
		}
	}
	if !cov {
		t.Errorf("meta.coverage = %s, want iam_roles denied with what it affects", wdetailJSON(dig(body, "meta", "coverage")))
	}
	// The detail carries the same gap for its execution role.
	detailCov := wdetailJSON(dig(wdetailGet(t, api, "/workloads/"+wdetailWorkload(t, l, "fn-resolved").String()), "meta", "coverage"))
	if !strings.Contains(detailCov, `"surface":"iam_roles"`) {
		t.Errorf("detail meta.coverage = %s, want iam_roles", detailCov)
	}
}

// ECS: the task role is the task's identity (execution); the task execution
// role is the role ECS itself uses (other) -- never the task's identity, so
// its permissions are not the workload's resources (§2.2, D-78).
func TestP2WdetailECSTaskExecutionRoleIsOther(t *testing.T) {
	l := newP2Lab(t, "p2-wdetail-ecs", true)
	a := l.account(accountA)
	app := a.role("BillingAppRole", "AROAWDETAILBILLAPP01")
	pull := a.role("ImagePullRole", "AROAWDETAILIMGPULL01")
	a.attach("BillingAppRole", a.managed("BillingRead", s3aDoc("ReadBilling", "s3:GetObject", "arn:aws:s3:::billing/*")))
	a.attach("ImagePullRole", a.managed("PullImages", s3aDoc("", "ecr:GetDownloadUrlForLayer", "*")))
	arn := "arn:aws:ecs:us-east-1:" + a.id + ":task-definition/billing:1"
	listsScanAndProjectECS(t, l, a, ecstypes.TaskDefinition{TaskDefinitionArn: aws.String(arn), Family: aws.String("billing"),
		TaskRoleArn: aws.String(app), ExecutionRoleArn: aws.String(pull), Status: ecstypes.TaskDefinitionStatusActive})
	api := l.api()
	var w string
	l.db.Raw(`SELECT id::text FROM iga_workload WHERE workspace_id = ? AND runtime_kind = ?`, l.ws, models.WorkloadECSTaskDefinition).Scan(&w)
	if w == "" {
		t.Fatal("setup: no ECS task definition projected")
	}

	d := dig(wdetailGet(t, api, "/workloads/"+w+"/identities"), "data")
	exec, other := digl(d, "execution", "items"), digl(d, "other", "items")
	if len(exec) != 1 || digs(exec[0], "identity", "name") != "BillingAppRole" {
		t.Errorf("execution = %s, want the task role", wdetailJSON(exec))
	}
	if len(other) != 1 || digs(other[0], "type") != models.RelTypeTaskExecutionRole || digs(other[0], "identity", "name") != "ImagePullRole" ||
		num(other[0], "used_by_count", "value") != 1 {
		t.Errorf("other = %s, want the task execution role, used by one workload", wdetailJSON(other))
	}

	rows := digl(wdetailGet(t, api, "/workloads/"+w+"/resources"), "data")
	var texts []string
	for _, r := range rows {
		texts = append(texts, digs(r, "resource", "text"))
	}
	if strings.Join(texts, ",") != "arn:aws:s3:::billing/*" {
		t.Errorf("resources = %v, want only the task role's billing/* -- never the task execution role's grants", texts)
	}
}
