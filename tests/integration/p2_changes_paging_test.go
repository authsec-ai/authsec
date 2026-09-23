package integration

// T5.4 Changes: paging (D-27), the §5.1 contract on this route (cursor
// binding, revision_stale), parameters, 404s, and kind=coverage (D-70).

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// changesManyPolicies attaches n policies, each granting one bucket, so one
// pass writes 2n+ events for the role -- all at ONE time (D-26), which is what
// makes the (event, id) tiebreak of the keyset carry the paging.
func changesManyPolicies(a *p2Account, role string, n int) {
	for i := 0; i < n; i++ {
		doc := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Sid":"Read%02d","Effect":"Allow",`+
			`"Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket-%02d/*"}]}`, i, i)
		a.attach(role, changesManaged(a, fmt.Sprintf("Policy%02d", i), doc))
	}
}

// Paging across > 50 events: 50 per page by default, a stable signed cursor,
// every event exactly once, strictly newest first by (at, event, id); the
// cursor is bound to the object and the kind (D-62), a forged one is 400, and
// a publication between pages is 409 revision_stale, as is a stale rev.
//
// Safeguard (mutation-checked): the cursor route carries the object.
func TestP2ChangesPaging(t *testing.T) {
	l := newP2Lab(t, "p2-changes-paging", true)
	a := l.account(accountA)
	a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	a.role("OtherRole", "AROAOTHERROLEOTHERRO")
	changesManyPolicies(a, "SharedToolRole", 30)
	l.scanAndProject(a)
	roleID := changesIdentity(t, l, "SharedToolRole")
	otherID := changesIdentity(t, l, "OtherRole")
	api := l.api()

	all := changesAll(t, api, "identity", roleID, "configuration")
	if len(all) <= 50 {
		t.Fatalf("setup: %d events, want more than one default page", len(all))
	}

	p1 := changesGet(t, api, changesPath("identity", roleID))
	if len(digl(p1, "data")) != 50 || num(p1, "meta", "limit") != 50 {
		t.Fatalf("first page = %d events, limit %d; want the default 50", len(digl(p1, "data")), num(p1, "meta", "limit"))
	}
	if dig(p1, "meta", "total_known") != true || num(p1, "meta", "total") != int64(len(all)) {
		t.Errorf("meta total = %v/%v, want %d known", dig(p1, "meta", "total_known"), dig(p1, "meta", "total"), len(all))
	}
	if digs(p1, "meta", "kind") != "configuration" || digs(p1, "meta", "graph_state") != "published" {
		t.Errorf("meta = %v, want kind configuration, graph published", dig(p1, "meta"))
	}
	cur := digs(p1, "meta", "next_cursor")
	if cur == "" {
		t.Fatal("first page has no next_cursor")
	}
	p2 := changesGet(t, api, changesPath("identity", roleID, "cursor", cur))
	again := changesGet(t, api, changesPath("identity", roleID, "cursor", cur))
	if digs(p2, "meta", "next_cursor") != "" {
		t.Errorf("second page has a next_cursor; want the end")
	}
	ids := func(b map[string]any) []string {
		var out []string
		for _, e := range digl(b, "data") {
			out = append(out, digs(e, "id"))
		}
		return out
	}
	if strings.Join(ids(p2), ",") != strings.Join(ids(again), ",") {
		t.Error("the same cursor returned two different pages")
	}
	paged := append(ids(p1), ids(p2)...)
	seen := map[string]bool{}
	for _, id := range paged {
		if seen[id] {
			t.Errorf("event %s on two pages", id)
		}
		seen[id] = true
	}
	var whole []string
	for _, e := range all {
		whole = append(whole, digs(e, "id"))
	}
	if strings.Join(paged, ",") != strings.Join(whole, ",") {
		t.Errorf("pages of 50 != one page of 200:\n%v\n%v", paged, whole)
	}
	// Strictly newest first by (at, event, id).
	for i := 1; i < len(all); i++ {
		pa, pe, pid := digs(all[i-1], "at"), digs(all[i-1], "event"), strings.SplitN(digs(all[i-1], "id"), ":", 2)[1]
		ca, ce, cid := digs(all[i], "at"), digs(all[i], "event"), strings.SplitN(digs(all[i], "id"), ":", 2)[1]
		if ca > pa || (ca == pa && (ce > pe || (ce == pe && cid >= pid))) {
			t.Errorf("event %d (%s %s %s) is not after event %d (%s %s %s) in (at, event, id) descending",
				i, ca, ce, cid, i-1, pa, pe, pid)
		}
	}
	changesAssertAttributed(t, l, all)

	// limit is accepted 1..200.
	if b := changesGet(t, api, changesPath("identity", roleID, "limit", "7")); len(digl(b, "data")) != 7 {
		t.Errorf("limit=7 returned %d events", len(digl(b, "data")))
	}

	// The cursor is this object's and this kind's (D-62).
	for name, path := range map[string]string{
		"another object": changesPath("identity", otherID, "cursor", cur),
		"another kind":   changesPath("identity", roleID, "kind", "coverage", "cursor", cur),
		"forged":         changesPath("identity", roleID, "cursor", cur[:len(cur)-2]+"xx"),
		"garbage":        changesPath("identity", roleID, "cursor", "not-a-cursor"),
	} {
		code, body := api.get(path)
		if code != http.StatusBadRequest || errCode(body) != "cursor_invalid" {
			t.Errorf("cursor from %s = %d %v, want 400 cursor_invalid", name, code, body)
		}
	}
	// An explicit kind=configuration pages the same list as the default.
	changesGet(t, api, changesPath("identity", roleID, "kind", "configuration", "cursor", cur))

	// A new publication between pages: 409 revision_stale, never a mixed list.
	rev := num(p1, "meta", "rev")
	l.scanAndProject(a)
	code, body := api.get(changesPath("identity", roleID, "cursor", cur))
	if code != http.StatusConflict || errCode(body) != "revision_stale" {
		t.Errorf("next page after a publication = %d %v, want 409 revision_stale", code, body)
	}
	code, body = api.get(changesPath("identity", roleID, "rev", fmt.Sprint(rev)))
	if code != http.StatusConflict || errCode(body) != "revision_stale" || num(body, "error", "current_rev") != rev+1 {
		t.Errorf("rev=%d after a publication = %d %v, want 409 naming rev %d", rev, code, body, rev+1)
	}
}

// Parameters and ids: an unknown parameter, a bad kind or limit is 400; a
// malformed id, another type's reference, another workspace's object, or a
// workspace with nothing published is 404 with no hint (§5.2, D-4, E14).
func TestP2ChangesParametersAndNotFound(t *testing.T) {
	l := newP2Lab(t, "p2-changes-params", true)
	a := oneLambda(l)
	l.scanAndProject(a)
	api := l.api()
	role := changesIdentity(t, l, "refund-lambda-role")
	wl := changesIDOf(t, l, `SELECT id FROM iga_workload WHERE workspace_id = ?`, l.ws)
	res, _ := l.resourceID("arn:aws:s3:::support-tickets/*")

	for _, q := range [][]string{{"kind", "everything"}, {"limit", "0"}, {"limit", "201"}, {"sort", "at"}, {"rev", "x"}} {
		code, body := api.get(changesPath("identity", role, q...))
		if code != http.StatusBadRequest || errCode(body) != "invalid_parameter" {
			t.Errorf("%v = %d %v, want 400 invalid_parameter", q, code, body)
		}
	}
	// The typed reference of the route's own type is accepted (D-5).
	changesGet(t, api, "/identities/"+refOf("identity", role)+"/changes")
	for _, path := range []string{
		"/identities/not-a-uuid/changes",
		"/identities/" + refOf("workload", wl) + "/changes",
		"/workloads/" + role.String() + "/changes",
		"/identities/" + uuid.NewString() + "/changes",
	} {
		code, body := api.get(path)
		if code != http.StatusNotFound || errCode(body) != "not_found" {
			t.Errorf("%s = %d %v, want 404", path, code, body)
		}
	}

	// Another workspace, with nothing published, asking for these ids.
	foreign := l.api().asWorkspace(newWorkspace(t, l.db, "p2-changes-params-other"))
	for refType, id := range map[string]uuid.UUID{"workload": wl, "identity": role, "resource": res} {
		code, body := foreign.get(changesPath(refType, id))
		if code != http.StatusNotFound || errCode(body) != "not_found" {
			t.Errorf("%s from another workspace = %d %v, want 404", refType, code, body)
		}
		// Positive control: the same ids from their own workspace resolve.
		changesGet(t, l.api(), changesPath(refType, id))
	}
	// And the 503 gate: the switch off answers graph_unavailable, before any
	// parameter or id is looked at.
	off := *l
	off.gate = services.NewGraphProjectionGate(false, "")
	code, body := off.api().get(changesPath("identity", role, "kind", "bogus"))
	if code != http.StatusServiceUnavailable || errCode(body) != "graph_unavailable" {
		t.Errorf("switch off = %d %v, want 503 graph_unavailable", code, body)
	}
	// And /capabilities says Changes is served while the switch is on (D-11).
	if code, body := api.get("/capabilities"); code != http.StatusOK || dig(body, "data", "features", "changes") != true {
		t.Errorf("/capabilities = %d %v, want features.changes true", code, body)
	}
	if code, body := off.api().get("/capabilities"); code != http.StatusOK || dig(body, "data", "features", "changes") != false {
		t.Errorf("/capabilities off = %d %v, want features.changes false", code, body)
	}
}

// kind=coverage (D-70): a surface going denied, then reached again, is two
// coverage_changed events on the role -- newest first, each with its run and
// the state before and after -- while kind=configuration shows no visibility
// event and no relationship ended (the outage made them stale, never ended).
// The envelope's meta.coverage names the gap while it lasts (D-73).
func TestP2ChangesCoverageKind(t *testing.T) {
	l := newP2Lab(t, "p2-changes-coverage", true)
	a := l.account(accountA)
	a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	a.attach("SharedToolRole", changesManaged(a, "TicketRead", docTicketRead))
	l.scanAndProject(a)
	roleID := changesIdentity(t, l, "SharedToolRole")
	api := l.api()

	a.iam.fail["GetAccountAuthorizationDetails:Role"] = denied("iam:GetAccountAuthorizationDetails")
	runDenied := l.scanAndProject(a)
	if s := models.DecodeScanCoverage(runDenied.Coverage).Surfaces[models.SurfaceIAMRoles].State; s != models.CloudCoverageDenied {
		t.Fatalf("setup: iam_roles = %q in the denied run, want denied", s)
	}
	mid := changesGet(t, api, changesPath("identity", roleID, "kind", "coverage"))
	var gap bool
	for _, c := range digl(mid, "meta", "coverage") {
		if digs(c, "surface") == models.SurfaceIAMRoles && digs(c, "state") == models.CloudCoverageDenied &&
			digs(c, "account_id") == accountA {
			gap = true
		}
	}
	if !gap {
		t.Errorf("meta.coverage during the outage = %v, want iam_roles denied for %s", dig(mid, "meta", "coverage"), accountA)
	}

	delete(a.iam.fail, "GetAccountAuthorizationDetails:Role")
	runBack := l.scanAndProject(a)

	cov := changesAll(t, api, "identity", roleID, "coverage")
	changesAssertAttributed(t, l, cov)
	var roles []map[string]any
	for _, e := range cov {
		if digs(e, "event") != "coverage_changed" {
			t.Errorf("kind=coverage returned %s", digs(e, "event"))
		}
		if digs(e, "detail", "surface") == models.SurfaceIAMRoles {
			roles = append(roles, e)
		}
	}
	if len(roles) != 2 {
		t.Fatalf("iam_roles coverage_changed = %d, want 2 (denied, then reached):%s", len(roles), changesDump(cov))
	}
	back, down := roles[0], roles[1]
	if digs(back, "before", "state") != models.CloudCoverageDenied || digs(back, "after", "state") != models.CloudCoverageReached ||
		digs(back, "run") != refOf("cloud_scan_run", runBack.ID) {
		t.Errorf("newest = %v -> %v in %s, want denied -> reached in %s",
			dig(back, "before"), dig(back, "after"), digs(back, "run"), runBack.ID)
	}
	if digs(down, "before", "state") != models.CloudCoverageReached || digs(down, "after", "state") != models.CloudCoverageDenied ||
		digs(down, "run") != refOf("cloud_scan_run", runDenied.ID) || digs(down, "after", "prevents") != "surface_denied" ||
		digs(down, "detail", "account_id") != accountA || digs(down, "subject") != "coverage:"+runDenied.ID.String()+":iam_roles" {
		t.Errorf("older = %v -> %v in %s (subject %s), want reached -> denied in %s preventing surface_denied",
			dig(down, "before"), dig(down, "after"), digs(down, "run"), digs(down, "subject"), runDenied.ID)
	}
	if digs(back, "after", "error_code") != "" || digs(down, "before", "run") == "" {
		t.Errorf("reached must carry no error, and before must name its run: %v / %v", dig(back, "after"), dig(down, "before"))
	}

	conf := changesAll(t, api, "identity", roleID, "configuration")
	for _, e := range conf {
		if digs(e, "event") == "coverage_changed" {
			t.Errorf("kind=configuration returned a coverage event: %v", e)
		}
		if strings.HasSuffix(digs(e, "event"), "_ended") || digs(e, "event") == "policy_detached" || digs(e, "event") == "retired" {
			t.Errorf("a denied read ended something: %s %s", digs(e, "event"), digs(e, "subject"))
		}
	}
}
