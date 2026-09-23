package integration

// meta.coverage and stale rows on the §5.3 lists (§2.14.14 "for every gap
// that bears on this result", D-73, D-74, D-1): the gaps come from the runs
// the current revision was built from, only the ones that bear on THIS list
// and its filters are named, and a row whose support went stale says which
// surface of which account left it so.

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// listsNotes renders meta.coverage as "account|surface|state|affects" lines,
// sorted.
func listsNotes(body map[string]any) []string {
	var out []string
	for _, n := range digl(body, "meta", "coverage") {
		out = append(out, strings.Join([]string{digs(n, "account_id"), digs(n, "surface"),
			digs(n, "state"), digs(n, "affects")}, "|"))
	}
	sort.Strings(out)
	return out
}

// listsNote is one expected coverage line.
func listsNote(account, surface, state, affects string) string {
	return strings.Join([]string{account, surface, state, affects}, "|")
}

// listsRowStaleReasons renders a row's stale_reason as "account|surface|state|since".
func listsRowStaleReasons(row any) []string {
	var out []string
	for _, r := range digl(row, "stale_reason") {
		out = append(out, strings.Join([]string{digs(r, "account_id"), digs(r, "surface"),
			digs(r, "state"), digs(r, "since")}, "|"))
	}
	return out
}

func TestP2ListsCoverageAndStaleRows(t *testing.T) {
	l := newP2Lab(t, "p2-lists-coverage", true)

	// A: a Lambda in each of two selected regions, a role, and a policy that
	// alone names ticket-archive/*.
	a := l.account(accountA, "us-east-1", "eu-west-1")
	role := a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	ticket := a.managed("TicketRead", `{"Version":"2012-10-17","Statement":[{"Sid":"ReadTickets",`+
		`"Effect":"Allow","Action":"s3:GetObject","Resource":["arn:aws:s3:::support-tickets/*","arn:aws:s3:::ticket-archive/*"]}]}`)
	a.attach("SharedToolRole", ticket)
	a.attach("SharedToolRole", a.managed("ToolboxRead", docToolboxRead))
	listsFunctions(a, "us-east-1", "east-fn", role)
	listsFunctions(a, "eu-west-1", "west-fn", role)

	// B: a role and a user, us-east-1 only; the role's policy ALSO names
	// support-tickets/*, so that reference has one support row per account.
	b := l.account(accountB)
	b.role("OpsRole", "AROAOPSROLEOPSROLE01")
	opsRead := b.managed("OpsRead", docToolboxRead)
	b.attach("OpsRole", opsRead)
	b.iam.users = append(b.iam.users, iamtypes.User{
		Arn: aws.String("arn:aws:iam::" + accountB + ":user/ci-deployer"), UserName: aws.String("ci-deployer"),
		UserId: aws.String("AIDACIDEPLOYER000001"), Path: aws.String("/"), CreateDate: ago(0),
	})
	l.scanAndProject(a)
	l.scanAndProject(b)
	api := l.api()

	// Everything reached: no row is stale and the identity and resource lists
	// carry no gap (the workloads list names only the regions nobody selected,
	// checked below).
	for _, route := range []string{"/identities", "/resources"} {
		if notes := listsNotes(listsGet(t, api, route)); len(notes) != 0 {
			t.Errorf("%s coverage after clean scans = %v, want none", route, notes)
		}
	}

	// Then: A's eu-west-1 Lambda read is denied and TicketRead's document is
	// unreadable; B's user listing is denied while OpsRead is detached, so B's
	// support of support-tickets/* can only go stale, never end.
	a.lambdas["eu-west-1"].fail = denied("lambda:ListFunctions")
	a.iam.failPolicyVersion[ticket] = denied("iam:GetPolicyVersion")
	runA := l.scanAndProject(a)
	b.iam.fail["ListUsers"] = denied("iam:ListUsers")
	b.detach("OpsRole", opsRead)
	runB := l.scanAndProject(b)
	sinceA := runA.PublishedAt.UTC().Format(time.RFC3339)
	sinceB := runB.PublishedAt.UTC().Format(time.RFC3339)

	/* ------------------------------- workloads ------------------------------ */

	wl := listsGet(t, api, "/workloads")
	rows := digl(wl, "data")
	west, east := listsRowBy(t, rows, "name", "west-fn"), listsRowBy(t, rows, "name", "east-fn")
	// D-1: the denied region's support went stale, so the node is stale -- and
	// still listed, never dropped (a denied read closes nothing).
	if digs(west, "state") != "stale" || digs(west, "lifecycle") != "active" {
		t.Errorf("west-fn = state %v lifecycle %v, want stale and active", west["state"], west["lifecycle"])
	}
	if got, want := listsRowStaleReasons(west), []string{accountA + "|lambda:eu-west-1|denied|" + sinceA}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("west-fn stale_reason = %v, want %v (since = the run that began the streak)", got, want)
	}
	if digs(east, "state") != "current" {
		t.Errorf("east-fn state = %v, want current", east["state"])
	}
	if _, has := east["stale_reason"]; has {
		t.Errorf("east-fn carries stale_reason %v: only a stale row explains itself", east["stale_reason"])
	}

	// Unfiltered: A's denied region, plus one compute:<region> note per region
	// an account did not select (not_selected, reported stale: D-58, D-73).
	// Nothing of IAM or of policy documents: they do not bear on workloads.
	selected := map[string]map[string]bool{accountA: {"us-east-1": true, "eu-west-1": true}, accountB: {"us-east-1": true}}
	lambdaWest := listsNote(accountA, "lambda:eu-west-1", "denied", "workloads of kind lambda_function in eu-west-1")
	notes := listsNotes(wl)
	sawLambda, computes := false, map[string]int{}
	for _, n := range notes {
		if n == lambdaWest {
			sawLambda = true
			continue
		}
		parts := strings.Split(n, "|")
		region := strings.TrimPrefix(parts[1], "compute:")
		if !strings.HasPrefix(parts[1], "compute:") || parts[2] != "stale" || parts[3] != "workloads in "+region ||
			selected[parts[0]][region] {
			t.Errorf("unexpected workloads coverage note %q", n)
			continue
		}
		computes[parts[0]]++
	}
	if !sawLambda {
		t.Errorf("workloads coverage = %v, want %q", notes, lambdaWest)
	}
	if computes[accountA] == 0 || computes[accountB] != computes[accountA]+1 {
		t.Errorf("unselected-region notes = %v, want one per unselected region (B selected one region fewer than A)", computes)
	}

	for _, tc := range []struct {
		kv   []string
		want []string
	}{
		// Narrowed by region: only the chosen regions' surfaces bear on it.
		{[]string{"region", "us-east-1"}, nil},
		{[]string{"region", "eu-west-1", "account", accountA}, []string{lambdaWest}},
		// Narrowed by kind: a Lambda gap does not bear on EC2 instances, while
		// B's unselected eu-west-1 bears on every kind in eu-west-1.
		{[]string{"region", "eu-west-1", "runtime_kind", "ec2_instance"},
			[]string{listsNote(accountB, "compute:eu-west-1", "stale", "workloads in eu-west-1")}},
		// Narrowed by account: the other account's gaps are not this list's.
		{[]string{"region", "eu-west-1", "account", accountB},
			[]string{listsNote(accountB, "compute:eu-west-1", "stale", "workloads in eu-west-1")}},
		// A region filter of not_stated alone names no regional surface.
		{[]string{"region", "not_stated"}, nil},
	} {
		if got := listsNotes(listsGet(t, api, "/workloads"+qs(tc.kv...))); strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("/workloads %v coverage = %v, want %v", tc.kv, got, tc.want)
		}
	}

	/* ------------------------------- identities ----------------------------- */

	usersB := listsNote(accountB, "iam_users", "denied", "identities of kind iam_user")
	ids := listsGet(t, api, "/identities")
	if got := listsNotes(ids); strings.Join(got, ",") != usersB {
		t.Errorf("/identities coverage = %v, want exactly %q (a Lambda or document gap does not bear on identities)", got, usersB)
	}
	user := listsRowBy(t, digl(ids, "data"), "name", "ci-deployer")
	if digs(user, "state") != "stale" {
		t.Errorf("ci-deployer state = %v, want stale: its listing was denied", user["state"])
	}
	if got := listsRowStaleReasons(user); strings.Join(got, ",") != accountB+"|iam_users|denied|"+sinceB {
		t.Errorf("ci-deployer stale_reason = %v, want B's iam_users denied since %s", got, sinceB)
	}
	if r := listsRowBy(t, digl(ids, "data"), "name", "OpsRole"); digs(r, "state") != "current" {
		t.Errorf("OpsRole = %v, want current: a denied users read does not stale roles", r["state"])
	}
	for _, tc := range []struct {
		kv   []string
		want string
	}{
		{[]string{"kind", "iam_role"}, ""},      // a users gap does not bear on roles
		{[]string{"kind", "iam_user"}, usersB},  // it does on users
		{[]string{"account", accountA}, ""},     // nor on another account's identities
		{[]string{"account", accountB}, usersB}, // it does on its own
		// An object with no stated account may come from any account, so
		// choosing unknown keeps every account's gaps.
		{[]string{"account", "unknown"}, usersB},
	} {
		if got := strings.Join(listsNotes(listsGet(t, api, "/identities"+qs(tc.kv...))), ","); got != tc.want {
			t.Errorf("/identities %v coverage = %q, want %q", tc.kv, got, tc.want)
		}
	}

	/* ------------------------------- resources ------------------------------ */

	res := listsGet(t, api, "/resources")
	docsA := listsNote(accountA, "policy_documents", "partial", "resources named by unreadable policy documents")
	if got := listsNotes(res); strings.Join(got, ",") != docsA {
		t.Errorf("/resources coverage = %v, want exactly %q (D-73)", got, docsA)
	}
	archive := listsRowBy(t, digl(res, "data"), "text", "arn:aws:s3:::ticket-archive/*")
	if digs(archive, "state") != "stale" || digs(archive, "lifecycle") != "active" {
		t.Errorf("ticket-archive/* = %v / %v, want stale and active: only the unreadable policy names it", archive["state"], archive["lifecycle"])
	}
	if got := listsRowStaleReasons(archive); strings.Join(got, ",") != accountA+"|policy_documents|partial|"+sinceA {
		t.Errorf("ticket-archive/* stale_reason = %v, want A's policy_documents partial since %s", got, sinceA)
	}
	// D-1: current if ANY support row is current -- A's is (ToolboxRead still
	// names it) though B's went stale.
	tickets := listsRowBy(t, digl(res, "data"), "text", "arn:aws:s3:::support-tickets/*")
	if sup := l.supportOf("resource_id", refUUID(t, digs(tickets, "ref"))); sup[a.conn] != "current" || sup[b.conn] != "stale" {
		t.Fatalf("setup: support-tickets/* support = %v, want A current and B stale", sup)
	}
	if digs(tickets, "state") != "current" {
		t.Errorf("support-tickets/* = %v, want current: one current support row makes the node current", tickets["state"])
	}
	if _, has := tickets["stale_reason"]; has {
		t.Errorf("support-tickets/* carries stale_reason %v but is not stale", tickets["stale_reason"])
	}

	/* ------------------- which runs a list was built from ------------------- */

	// A's failures clear and a third scan reaches everything.
	a.lambdas["eu-west-1"].fail = nil
	delete(a.iam.failPolicyVersion, ticket)
	l.scanAndProject(a)
	// listsWatermark adds a watermark of one node class still naming A's
	// SECOND run: a partition the latest run no longer carries.
	listsWatermark := func(class string) {
		t.Helper()
		if err := l.db.Exec(`INSERT INTO iga_projection_state (workspace_id, estate_scope_id, connector_id, object_class,
		                            relationship_type, partition_key, last_run_id, last_generation, coverage_state, reconciled)
		                     SELECT workspace_id, estate_scope_id, connector_id, ?, '', ?, ?, last_generation, 'partial', true
		                       FROM iga_projection_state WHERE workspace_id = ? AND connector_id = ? LIMIT 1`,
			class, "lists-test|"+class, runA.ID, l.ws, a.conn).Error; err != nil {
			t.Fatalf("seed an older %s watermark: %v", class, err)
		}
	}
	// A lagging WORKLOAD watermark: the newer run that also built workloads
	// reports lambda:eu-west-1 reached, and the newest report decides; and a
	// workload partition's run is not what the resources list was built from.
	listsWatermark("workload")
	for route, kv := range map[string][]string{
		"/workloads": {"account", accountA, "region", "eu-west-1"},
		"/resources": {"account", accountA},
	} {
		if got := listsNotes(listsGet(t, api, route+qs(kv...))); len(got) != 0 {
			t.Errorf("%s %v coverage with a lagging workload watermark = %v, want none", route, kv, got)
		}
	}
	// A lagging RESOURCE watermark: that partition's references were built from
	// the second run, whose unreadable document therefore still bears on the
	// resources list (the newer run's silence about documents is not a report).
	listsWatermark("resource")
	if got := strings.Join(listsNotes(listsGet(t, api, "/resources"+qs("account", accountA))), ","); got != docsA {
		t.Errorf("/resources coverage with a lagging resource watermark = %q, want %q", got, docsA)
	}

	/* -------------------------------- revoked ------------------------------- */

	// D-73, D-89: a revoked account in scope is named as a whole ("*"), its
	// objects stay listed with their stored state, and its account reads as
	// not connected.
	if err := l.db.Exec(`UPDATE cloud_connector SET status = 'revoked' WHERE workspace_id = ? AND id = ?`, l.ws, b.conn).Error; err != nil {
		t.Fatalf("revoke B: %v", err)
	}
	ids = listsGet(t, api, "/identities"+qs("account", accountB))
	revoked := listsNote(accountB, "*", "revoked", "all identities of this account")
	if got := strings.Join(listsNotes(ids), ","); got != revoked+","+usersB {
		t.Errorf("/identities of revoked B coverage = %q, want %q and B's recorded gap", got, revoked+","+usersB)
	}
	if n := len(digl(ids, "data")); n != 2 {
		t.Errorf("revoked B's identities = %d rows, want both still listed", n)
	}
	for _, r := range digl(ids, "data") {
		if dig(r, "account", "connected") != false || digs(r, "account", "id") != accountB {
			t.Errorf("%s account = %v, want B, connected false", digs(r, "name"), dig(r, "account"))
		}
	}
	if got := strings.Join(listsNotes(listsGet(t, api, "/identities"+qs("account", accountA))), ","); got != "" {
		t.Errorf("/identities of A after B's revocation = %q, want none: B is not in scope", got)
	}
}
