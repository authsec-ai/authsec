package integration

// T2.3 (SPEC-iga-phase2-graph.md §5.3, §2.14.13; D-57, D-58): GET
// /api/iga/v1/coverage, through the REAL worker and projector. Per account and
// surface, from the runs the current revision was built from: state, count,
// error_code, api, since, prevents, run -- and NEVER a guessed missing
// permission (E9).

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/smithy-go"

	"github.com/authsec-ai/authsec/models"
)

// s2AWSManagedPolicy is an AWS-managed policy the fixture attaches and then
// makes unreadable (D-51: after T3.1 only an AWS-managed document can fail to
// fetch).
const s2AWSManagedPolicy = "arn:aws:iam::aws:policy/S2ReadOnlyTickets"

func TestP2S2CoverageFromTheCurrentRevision(t *testing.T) {
	l := newP2Lab(t, "p2-s2-coverage", true)
	api := l.api()

	// Nothing published: 200, empty, not_published (§5.1) -- never an error,
	// never "no gaps".
	code, body := api.get("/coverage")
	mustStatus(t, "coverage before any publication", code, body, http.StatusOK)
	if len(digl(body, "data")) != 0 || digs(body, "meta", "graph_state") != "not_published" || dig(body, "meta", "rev") != nil {
		t.Fatalf("coverage before publication = %v", body)
	}

	// A: its Lambda read is DENIED, with the SDK's own operation error.
	a := oneLambda(l)
	a.lambdas["us-east-1"].fail = &smithy.OperationError{ServiceID: "Lambda", OperationName: "ListFunctions",
		Err: &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized to perform lambda:ListFunctions"}}
	runA1 := l.scanAndProject(a)

	accA := s2CoverageAccount(t, api, "", a)
	lam := s2Surface(t, accA, "lambda:us-east-1")
	if digs(lam, "state") != models.CloudCoverageDenied || digs(lam, "api") != "lambda:ListFunctions" ||
		digs(lam, "error_code") != "AccessDeniedException" || digs(lam, "prevents") != "surface_denied" ||
		digs(lam, "run") != refOf("cloud_scan_run", runA1.ID) ||
		digs(lam, "ref") != "coverage:"+runA1.ID.String()+":lambda:us-east-1" {
		t.Fatalf("A's denied Lambda surface = %v", lam)
	}
	if digs(lam, "since_run") != refOf("cloud_scan_run", runA1.ID) || digs(lam, "since") != s2TS(runA1.PublishedAt) {
		t.Fatalf("A's first denied run: since %v / since_run %v, want this run", dig(lam, "since"), dig(lam, "since_run"))
	}
	// Never a guessed permission: the call and the code, and nothing that names
	// a permission to grant.
	for k := range lam.(map[string]any) {
		if strings.Contains(k, "permission") || strings.Contains(k, "missing") {
			t.Fatalf("coverage carries %q: a guessed permission", k)
		}
	}
	// Reached: no call, no code, prevents nothing.
	roles := s2Surface(t, accA, models.SurfaceIAMRoles)
	if digs(roles, "state") != models.CloudCoverageReached || dig(roles, "api") != nil ||
		dig(roles, "error_code") != nil || dig(roles, "prevents") != nil || dig(roles, "fix") != nil {
		t.Fatalf("a reached surface = %v, want no api, error_code, prevents or fix", roles)
	}
	// Not selected: prevents nothing claimed, and the one fix the evidence
	// supports.
	if ns := s2Surface(t, accA, "compute:eu-west-1"); digs(ns, "state") != models.CloudCoverageNotSelected ||
		dig(ns, "prevents") != nil || digs(ns, "fix") != "change_regions" {
		t.Fatalf("an unselected region = %v", ns)
	}

	// B: clean compute, one UNREADABLE policy document (partial).
	b := l.account(accountB)
	b.role("reader-role", "AROAS2COVERAGEBBBBBB")
	b.iam.managedPolicies[s2AWSManagedPolicy] = docTicketRead
	b.attach("reader-role", s2AWSManagedPolicy)
	b.iam.failPolicyVersion[s2AWSManagedPolicy] = &smithy.OperationError{ServiceID: "IAM", OperationName: "GetPolicyVersion",
		Err: &smithy.GenericAPIError{Code: "AccessDenied", Message: "not authorized to perform iam:GetPolicyVersion"}}
	time.Sleep(5 * time.Millisecond)
	runB := l.scanAndProject(b)

	// THE CURRENT REVISION WAS BUILT FROM BOTH RUNS: A's part of the graph
	// still stands on A's run, though the revision was published by B's.
	code, body = api.get("/coverage")
	mustStatus(t, "coverage, two accounts", code, body, http.StatusOK)
	if num(body, "meta", "rev") != 2 || len(digl(body, "data")) != 2 {
		t.Fatalf("coverage at rev 2 = %v, want both accounts", body)
	}
	if lam := s2Surface(t, s2CoverageAccount(t, api, "", a), "lambda:us-east-1"); digs(lam, "run") != refOf("cloud_scan_run", runA1.ID) {
		t.Fatalf("A's surface at rev 2 = %v, want still A's run", lam)
	}
	accB := s2CoverageAccount(t, api, "", b)
	docs := s2Surface(t, accB, models.SurfacePolicyDocuments)
	if digs(docs, "state") != models.CloudCoveragePartial || digs(docs, "prevents") != "surface_partial" ||
		!strings.Contains(digs(docs, "error"), "S2ReadOnlyTickets") || digs(docs, "run") != refOf("cloud_scan_run", runB.ID) {
		t.Fatalf("B's unreadable document = %v, want partial naming S2ReadOnlyTickets", docs)
	}
	// The partial surface was not refused as a whole; no single call is named
	// for it (the failed call is in the document's own words).
	if dig(docs, "api") != nil || dig(docs, "error_code") != nil {
		t.Fatalf("a partial surface names one call %v / %v it did not fail as a whole", dig(docs, "api"), dig(docs, "error_code"))
	}
	if lam := s2Surface(t, accB, "lambda:us-east-1"); dig(lam, "prevents") != nil {
		t.Fatalf("B's clean Lambda surface = %v", lam)
	}

	// ?account= narrows; anything but an account id is 400; a stale rev 409.
	code, body = api.get("/coverage" + qs("account", b.id))
	mustStatus(t, "coverage?account=B", code, body, http.StatusOK)
	if rows := digl(body, "data"); len(rows) != 1 || digs(rows[0], "account", "id") != b.id {
		t.Fatalf("coverage?account=B = %v", body)
	}
	for _, bad := range []string{"unknown", "12345", "abcdefghijkl"} {
		if code, body := api.get("/coverage" + qs("account", bad)); code != http.StatusBadRequest || errCode(body) != "invalid_parameter" {
			t.Fatalf("coverage?account=%s = %d %v, want 400", bad, code, body)
		}
	}
	if code, body := api.get("/coverage" + qs("rev", "1")); code != http.StatusConflict || errCode(body) != "revision_stale" {
		t.Fatalf("coverage?rev=1 at rev 2 = %d %v, want 409 revision_stale", code, body)
	}

	// SINCE is the first run in the current state: A is still denied on its
	// next scan, then fixed.
	time.Sleep(5 * time.Millisecond)
	runA2 := l.scanAndProject(a)
	lam = s2Surface(t, s2CoverageAccount(t, api, "", a), "lambda:us-east-1")
	if digs(lam, "run") != refOf("cloud_scan_run", runA2.ID) || digs(lam, "since_run") != refOf("cloud_scan_run", runA1.ID) ||
		digs(lam, "since") != s2TS(runA1.PublishedAt) {
		t.Fatalf("A denied twice: run %v, since_run %v, since %v; want the latest run, since the first", dig(lam, "run"), dig(lam, "since_run"), dig(lam, "since"))
	}
	a.lambdas["us-east-1"].fail = nil
	time.Sleep(5 * time.Millisecond)
	runA3 := l.scanAndProject(a)
	lam = s2Surface(t, s2CoverageAccount(t, api, "", a), "lambda:us-east-1")
	if digs(lam, "state") != models.CloudCoverageReached || digs(lam, "since_run") != refOf("cloud_scan_run", runA3.ID) ||
		dig(lam, "prevents") != nil || dig(lam, "api") != nil {
		t.Fatalf("A fixed: %v, want reached since this run, prevents nothing", lam)
	}
}

/* --------------------------------- helpers -------------------------------- */

// s2CoverageAccount fetches /coverage and returns one account's entry.
func s2CoverageAccount(t *testing.T, api *readAPI, query string, a *p2Account) map[string]any {
	t.Helper()
	code, body := api.get("/coverage" + query)
	mustStatus(t, "GET /coverage", code, body, http.StatusOK)
	for _, acc := range digl(body, "data") {
		if digs(acc, "account", "id") == a.id {
			if digs(acc, "integration") != refOf("cloud_connector", a.conn) {
				t.Fatalf("coverage account %s names integration %q", a.id, digs(acc, "integration"))
			}
			m, _ := acc.(map[string]any)
			return m
		}
	}
	t.Fatalf("no /coverage entry for account %s: %v", a.id, body)
	return nil
}

func s2Surface(t *testing.T, acc map[string]any, surface string) any {
	t.Helper()
	for _, s := range digl(acc, "surfaces") {
		if digs(s, "surface") == surface {
			return s
		}
	}
	t.Fatalf("no surface %q in %v", surface, acc)
	return nil
}
