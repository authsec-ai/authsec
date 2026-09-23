package integration

// GET /evidence (T6.5, §5.3 Evidence, §2.14.7 the Evidence panel; D-20..D-24,
// D-65, D-66, D-79, D-80, E4, B19) over the E4 lab (p2_evidence_lab_test.go):
// the five parts, facts with their call and run, the raw record only on
// request, every claim type, and the contract errors.

import (
	"context"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/models"
)

// The grant of E4's worked example: the §5.3 sentence, the four status
// dimensions, the holder's entry and the policy version as facts -- each with
// its call, account, region, the CLAIM's run and confirmation time (D-24) --
// the policy version, Sid, 1-based index and the verbatim excerpt, and
// freshness. raw is null unless include=raw.
func TestP2EvidenceGrantFactsAndShape(t *testing.T) {
	e := evidenceE4Lab(t, "p2-evidence-grant")
	claim := evidenceGrant(t, e.l, "SharedToolRole", "TicketRead", "ReadTickets")
	body := evidenceGet(t, e.api, claim)
	d := dig(body, "data")

	if got := digs(d, "claim", "ref"); got != claim {
		t.Errorf("claim.ref = %q, want %q", got, claim)
	}
	if got, want := digs(d, "claim", "sentence"),
		"SharedToolRole is granted s3:GetObject on support-tickets/* by TicketRead (statement ReadTickets)."; got != want {
		t.Errorf("sentence = %q, want %q", got, want)
	}
	for k, want := range map[string]string{"basis": "declared", "lifecycle": "current", "collection": "complete",
		"effective_access": "not_evaluated"} {
		if got := digs(d, "status", k); got != want {
			t.Errorf("status.%s = %q, want %q", k, got, want)
		}
	}

	var lastConfirmed, runRef string
	var edge struct {
		LastConfirmedBy uuid.UUID
	}
	e.l.db.Raw(`SELECT last_confirmed_by FROM iga_access_edges WHERE id = ?`, refUUID(t, claim)).Scan(&edge)
	runRef = refOf("cloud_scan_run", edge.LastConfirmedBy)
	lastConfirmed = digs(d, "freshness", "last_confirmed_at")
	if lastConfirmed == "" || digs(d, "freshness", "first_seen_at") == "" {
		t.Errorf("freshness = %v, want first_seen_at and last_confirmed_at", dig(d, "freshness"))
	}
	for _, k := range []string{"stale_since", "valid_to", "ended_reason"} {
		if v := dig(d, "freshness", k); v != nil {
			t.Errorf("freshness.%s = %v, want null on a current claim", k, v)
		}
	}

	facts := digl(d, "facts")
	if len(facts) != 2 {
		t.Fatalf("facts = %s, want the holder's entry and the policy version", evidenceJSON(facts))
	}
	for _, f := range facts {
		if digs(f, "account_id") != accountA || dig(f, "region") != nil ||
			digs(f, "observed_in_run") != runRef || digs(f, "last_confirmed_at") != lastConfirmed {
			t.Errorf("fact %s: want account %s, region null, run %s and the claim's last_confirmed_at %s",
				evidenceJSON(f), accountA, runRef, lastConfirmed)
		}
		if digs(f, "source_api") != "iam:GetAccountAuthorizationDetails" {
			t.Errorf("fact %q source_api = %q, want the authorization-details call", digs(f, "fact"), digs(f, "source_api"))
		}
	}
	if got := digs(facts[0], "fact"); got != "SharedToolRole has TicketRead attached" {
		t.Errorf("first fact = %q, want the holder's attachment", got)
	}
	p := facts[1]
	if digs(p, "fact") != "Statement ReadTickets allows s3:GetObject on arn:aws:s3:::support-tickets/*" ||
		digs(p, "policy_version") != "v3" || digs(p, "policy", "name") != "TicketRead" ||
		digs(p, "policy", "kind") != "customer_managed" || digs(p, "statement", "sid") != "ReadTickets" ||
		num(p, "statement", "index") != 1 || digs(p, "statement_excerpt", "Sid") != "ReadTickets" ||
		digs(p, "statement_excerpt", "Resource") != "arn:aws:s3:::support-tickets/*" {
		t.Errorf("policy fact = %s, want version v3, statement ReadTickets (index 1) and its verbatim excerpt", evidenceJSON(p))
	}
	if raw := dig(d, "raw"); raw != nil {
		t.Errorf("raw = %v without include=raw, want null", raw)
	}
	if num(body, "meta", "rev") < 1 {
		t.Errorf("meta = %v, want the revision", dig(body, "meta"))
	}

	// include=raw: the stored sanitized_facts, one per fact, in fact order.
	body = evidenceGet(t, e.api, claim, "include", "raw")
	raws, facts := digl(body, "data", "raw"), digl(body, "data", "facts")
	if len(raws) != len(facts) || len(raws) != 2 {
		t.Fatalf("raw = %s, want one entry per fact", evidenceJSON(raws))
	}
	for i, r := range raws {
		if !strings.HasPrefix(digs(r, "observation"), "cloud_observation:") || digs(r, "source_api") != digs(facts[i], "source_api") {
			t.Errorf("raw[%d] = %s, want the observation and the fact's call", i, evidenceJSON(r))
		}
	}
	if digs(raws[0], "sanitized_facts", "native_id") != e.a.roleARN("SharedToolRole") ||
		digs(raws[1], "sanitized_facts", "version_id") != "v3" {
		t.Errorf("raw sanitized_facts = %s, want the role's entry and the policy version's", evidenceJSON(raws))
	}
}

// D-24: only the observations that bear on the claim type are facts. priya's
// credential report is linked by the junction to her grants (the projector
// links every observation of the holder), and it proves none of them.
func TestP2EvidenceFactsKeepOnlyBearingSources(t *testing.T) {
	e := evidenceE4Lab(t, "p2-evidence-sources")
	claim := evidenceGrant(t, e.l, "priya", "PriyaOwn", "OwnRead")
	if n := e.l.count(`SELECT count(*) FROM iga_access_edge_evidence j JOIN cloud_observation o ON o.id = j.observation_id
	                    WHERE j.access_edge_id = ? AND o.source_api = 'iam:GetCredentialReport'`, refUUID(t, claim)); n == 0 {
		t.Fatal("fixture: the junction does not link priya's credential report to her grant; the filter is untested")
	}
	for _, c := range []string{claim, evidenceRelationship(t, e.l, models.RelTypeMemberOf, "priya", "ops"),
		evidenceAssignment(t, e.l, "PriyaOwn", "priya")} {
		body := evidenceGet(t, e.api, c, "include", "raw")
		facts := digl(body, "data", "facts")
		if len(facts) == 0 {
			t.Errorf("%s: no facts", c)
		}
		for _, f := range facts {
			if digs(f, "source_api") == "iam:GetCredentialReport" {
				t.Errorf("%s: fact %q from the credential report, which proves no attachment or membership", c, digs(f, "fact"))
			}
		}
	}
	body := evidenceGet(t, e.api, evidenceRelationship(t, e.l, models.RelTypeMemberOf, "priya", "ops"))
	if got := digs(body, "data", "claim", "sentence"); got != "priya is a member of ops." {
		t.Errorf("member_of sentence = %q", got)
	}
	if facts := digl(body, "data", "facts"); len(facts) != 1 || digs(facts[0], "fact") != "The entry of priya lists group ops" {
		t.Errorf("member_of facts = %s, want priya's own entry", evidenceJSON(facts))
	}
}

// B19 / E4: the NotResource grant renders "all resources except finance/*",
// carries negated_statement, and its exclusion is a target claim that
// EXCLUDES finance/* -- never names it.
func TestP2EvidenceNotResourceGrant(t *testing.T) {
	e := evidenceE4Lab(t, "p2-evidence-b19")
	body := evidenceGet(t, e.api, evidenceGrant(t, e.l, "SharedToolRole", "FinanceAll", "AllButFinance"))
	if got, want := digs(body, "data", "claim", "sentence"),
		"SharedToolRole is granted s3:* on all resources except finance/* by FinanceAll (statement AllButFinance)."; got != want {
		t.Errorf("sentence = %q, want %q", got, want)
	}
	if evidenceLim(body, "negated_statement") == nil || evidenceLim(body, "selector_may_match_nothing") == nil {
		t.Errorf("limitations = %v, want negated_statement and selector_may_match_nothing (the implicit *)", evidenceCodes(body))
	}
	body = evidenceGet(t, e.api, evidenceTarget(t, e.l, "FinanceAll", "AllButFinance", "arn:aws:s3:::finance/*"))
	if got, want := digs(body, "data", "claim", "sentence"),
		"Statement AllButFinance of FinanceAll excludes finance/* (NotResource)."; got != want {
		t.Errorf("exclusion target sentence = %q, want %q", got, want)
	}
	if evidenceLim(body, "negated_statement") == nil {
		t.Errorf("exclusion target limitations = %v, want negated_statement", evidenceCodes(body))
	}
	body = evidenceGet(t, e.api, evidenceGrant(t, e.l, "SharedToolRole", "FinanceAll", "AllButIAM"))
	if got, want := digs(body, "data", "claim", "sentence"),
		"SharedToolRole is granted all actions except iam:* on scratch/* by FinanceAll (statement AllButIAM)."; got != want {
		t.Errorf("NotAction sentence = %q, want %q", got, want)
	}
}

// Every claim and object type: a sentence in §2.14.8 wording, a status, facts
// from the right source, freshness.
func TestP2EvidenceClaimTypes(t *testing.T) {
	e := evidenceE4Lab(t, "p2-evidence-types")
	l := e.l
	type want struct {
		sentence string
		apis     []string // the facts' source_api values, sorted
	}
	var support uuid.UUID
	if err := l.db.Raw(`SELECT s.id FROM iga_object_support s JOIN iga_identity_accounts ia ON ia.id = s.identity_account_id
	                     WHERE s.workspace_id = ? AND ia.display_name = 'SharedToolRole'`, l.ws).Row().Scan(&support); err != nil {
		t.Fatalf("fixture: SharedToolRole's support row: %v", err)
	}
	resID, _ := l.resourceID("arn:aws:s3:::support-tickets/*")
	auth := "iam:GetAccountAuthorizationDetails"
	cases := map[string]want{
		evidenceRelationship(t, l, models.RelTypeExecutesAs, "ticket-tools", "SharedToolRole"): {
			"ticket-tools is configured to run as SharedToolRole.", []string{"lambda:ListFunctions"}},
		evidenceRelationship(t, l, models.RelTypeCanAssume, "lambda.amazonaws.com", "SharedToolRole"): {
			"lambda.amazonaws.com may assume SharedToolRole.", []string{auth}},
		evidenceRelationship(t, l, models.RelTypeCanAssume, evidenceAccountC, "PartnerRole"): {
			evidenceAccountC + " may assume PartnerRole.", []string{auth}},
		evidenceAssignment(t, l, "TicketRead", "SharedToolRole"): {
			"TicketRead is attached to SharedToolRole.", []string{auth, auth}},
		evidenceAssignment(t, l, "PriyaOwn", "priya"): {
			"PriyaOwn is an inline policy of priya.", []string{auth, auth}},
		evidenceAssignment(t, l, "PowerUserAccess", "priya"): {
			"PowerUserAccess is the permissions boundary of priya.", []string{auth, "iam:GetPolicyVersion"}},
		evidenceTarget(t, l, "TicketRead", "ListTickets", "arn:aws:s3:::support-tickets"): {
			"Statement ListTickets of TicketRead names support-tickets.", []string{auth}},
		evidenceNode(t, l, "identity", "iga_identity_accounts", "SharedToolRole"): {
			"IAM role SharedToolRole is present in the scan of acct-" + accountA + " (" + accountA + ").", []string{auth}},
		refOf("presence", support): {
			"IAM role SharedToolRole is present in the scan of acct-" + accountA + " (" + accountA + ").", []string{auth}},
		evidenceNode(t, l, "workload", "iga_workload", "ticket-tools"): {
			"Lambda function ticket-tools is present in the scan of acct-" + accountA + " (" + accountA + ").", []string{"lambda:ListFunctions"}},
		evidenceNode(t, l, "policy", "iga_policy", "TicketRead"): {
			"Policy TicketRead is present in the scan of acct-" + accountA + " (" + accountA + ").", []string{auth}},
		evidenceStatementRef(t, l, "TicketRead", "ReadTickets"): {
			"Statement ReadTickets of TicketRead is present in the scan of acct-" + accountA + " (" + accountA + ").", []string{auth}},
		refOf("resource", resID): {
			"Resource reference arn:aws:s3:::support-tickets/* is present in the scan of acct-" + accountA + " (" + accountA + ").",
			[]string{auth, auth}}, // named by ReadTickets and ToolboxGet
		evidenceExternal(t, l, "lambda.amazonaws.com"): {
			"lambda.amazonaws.com is named by the trust policy of GuardedRole, PlainRole and SharedToolRole.",
			[]string{auth, auth, auth}},
	}
	for claim, w := range cases {
		body := evidenceGet(t, e.api, claim)
		d := dig(body, "data")
		if got := digs(d, "claim", "sentence"); got != w.sentence {
			t.Errorf("%s sentence = %q, want %q", claim, got, w.sentence)
		}
		if digs(d, "status", "lifecycle") != "current" || digs(d, "status", "collection") != "complete" ||
			digs(d, "status", "basis") != "declared" || digs(d, "status", "effective_access") != "not_evaluated" {
			t.Errorf("%s status = %v", claim, dig(d, "status"))
		}
		var apis []string
		for _, f := range digl(d, "facts") {
			apis = append(apis, digs(f, "source_api"))
			if digs(f, "observed_in_run") == "" || digs(f, "account_id") != accountA || digs(f, "fact") == "" {
				t.Errorf("%s fact %s: want a run, the account and a sentence", claim, evidenceJSON(f))
			}
		}
		if !reflect.DeepEqual(sortedCopy(apis), w.apis) {
			t.Errorf("%s facts' calls = %v, want %v:\n%s", claim, apis, w.apis, evidenceJSON(digl(d, "facts")))
		}
		for _, banned := range []string{"can access", "allowed", " uses ", "verified", "removed"} {
			if strings.Contains(strings.ToLower(digs(d, "claim", "sentence")), banned) {
				t.Errorf("%s sentence uses %q (§2.14.8)", claim, banned)
			}
		}
	}
	// The workload fact names its region; IAM facts none.
	body := evidenceGet(t, e.api, evidenceNode(t, l, "workload", "iga_workload", "ticket-tools"))
	if got := digs(body, "data", "facts", 0, "region"); got != "us-east-1" {
		t.Errorf("workload fact region = %q, want us-east-1", got)
	}
}

func sortedCopy(xs []string) []string {
	out := append([]string{}, xs...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// coverage:<run>:<surface>: what a run the revision was built from recorded
// for one surface (D-80); another run, or a surface it did not report, is 404.
func TestP2EvidenceCoverageClaim(t *testing.T) {
	e := evidenceE4Lab(t, "p2-evidence-coverage")
	claim := "coverage:" + e.run.ID.String() + ":" + models.SurfaceIAMRoles
	body := evidenceGet(t, e.api, claim)
	d := dig(body, "data")
	if got, want := digs(d, "claim", "sentence"), "The scan of acct-"+accountA+" recorded iam_roles as reached."; got != want {
		t.Errorf("sentence = %q, want %q", got, want)
	}
	if dig(d, "status", "basis") != nil || digs(d, "status", "collection") != "complete" || digs(d, "status", "lifecycle") != "current" {
		t.Errorf("status = %v, want basis null, current, complete", dig(d, "status"))
	}
	facts := digl(d, "facts")
	if len(facts) != 1 || digs(facts[0], "observed_in_run") != refOf("cloud_scan_run", e.run.ID) ||
		digs(facts[0], "account_id") != accountA || !strings.Contains(digs(facts[0], "fact"), "reached") {
		t.Errorf("facts = %s, want the run's own record", evidenceJSON(facts))
	}
	if got := evidenceCodes(body); !reflect.DeepEqual(got, []string{"organizations_not_collected"}) {
		t.Errorf("limitations = %v, want only organizations_not_collected: a reached surface prevents nothing", got)
	}
	// The organizations surface itself: unsupported, organizations_not_collected.
	body = evidenceGet(t, e.api, "coverage:"+e.run.ID.String()+":"+models.SurfaceOrganizations)
	if got := evidenceCodes(body); !reflect.DeepEqual(got, []string{"organizations_not_collected"}) {
		t.Errorf("organizations coverage limitations = %v", got)
	}
	for _, bad := range []string{
		"coverage:" + e.run.ID.String() + ":no_such_surface",
		"coverage:" + uuid.New().String() + ":" + models.SurfaceIAMRoles,
	} {
		if code, body := e.api.get("/evidence" + qs("claim", bad)); code != http.StatusNotFound || errCode(body) != "not_found" {
			t.Errorf("%s = %d %v, want 404", bad, code, body)
		}
	}
	// A superseded run: the next run is what the revision holds.
	next := evidenceCycle(e.l, e.a, evidenceFakes{})
	if code, _ := e.api.get("/evidence" + qs("claim", claim)); code != http.StatusNotFound {
		t.Errorf("coverage claim of a run the revision is no longer built from = %d, want 404", code)
	}
	evidenceGet(t, e.api, "coverage:"+next.ID.String()+":"+models.SurfaceIAMRoles)
}

// A denied surface as a coverage claim carries its own surface_denied.
func TestP2EvidenceCoverageClaimDenied(t *testing.T) {
	l := newP2Lab(t, "p2-evidence-coverage-denied", true)
	a := l.account(accountA)
	a.role("SoloRole", "AROASOLOROLESOLOROLE")
	a.iam.fail["GetAccountAuthorizationDetails:Group"] = denied("iam:GetAccountAuthorizationDetails")
	run := l.scanAndProject(a)
	body := evidenceGet(t, l.api(), "coverage:"+run.ID.String()+":"+models.SurfaceIAMGroups)
	lim := evidenceLim(body, "surface_denied")
	if lim == nil || digs(lim, "surface") != models.SurfaceIAMGroups || digs(lim, "account_id") != accountA {
		t.Fatalf("limitations = %s, want surface_denied on iam_groups", evidenceJSON(dig(body, "data", "limitations")))
	}
	if got := digs(body, "data", "status", "collection"); got != "stale" {
		t.Errorf("collection = %q, want stale", got)
	}
	if got := digs(body, "data", "facts", 0, "source_api"); got == "" {
		t.Errorf("fact = %v, want the failed call", dig(body, "data", "facts"))
	}
}

// §5.2: a malformed or disallowed ref or parameter is 400; a claim not in
// THIS workspace is 404 with no hint -- also when it exists in another one;
// a stale rev is 409 (§5.1).
func TestP2EvidenceErrors(t *testing.T) {
	other := newP2Lab(t, "p2-evidence-foreign", true)
	e := evidenceE4Lab(t, "p2-evidence-home")
	t.Cleanup(func() { other.cleanup(); e.l.cleanup() })
	b := other.account(accountB)
	b.role("OtherRole", "AROAOTHERROLEOTHERRO")
	b.attach("OtherRole", b.managed("OtherRead", s3aDoc("Other", "s3:GetObject", "arn:aws:s3:::other/*")))
	other.scanAndProject(b)
	oapi := other.api()

	home := []string{
		evidenceGrant(t, e.l, "SharedToolRole", "TicketRead", "ReadTickets"),
		evidenceAssignment(t, e.l, "TicketRead", "SharedToolRole"),
		evidenceRelationship(t, e.l, models.RelTypeExecutesAs, "ticket-tools", "SharedToolRole"),
		evidenceTarget(t, e.l, "TicketRead", "ListTickets", "arn:aws:s3:::support-tickets"),
		evidenceNode(t, e.l, "identity", "iga_identity_accounts", "SharedToolRole"),
		evidenceNode(t, e.l, "workload", "iga_workload", "ticket-tools"),
		evidenceNode(t, e.l, "policy", "iga_policy", "TicketRead"),
		evidenceStatementRef(t, e.l, "TicketRead", "ReadTickets"),
		evidenceExternal(t, e.l, "lambda.amazonaws.com"),
		"coverage:" + e.run.ID.String() + ":" + models.SurfaceIAMRoles,
		"grant:" + uuid.New().String(),
	}
	for _, c := range home {
		if code, body := oapi.get("/evidence" + qs("claim", c)); code != http.StatusNotFound || errCode(body) != "not_found" ||
			len(body) != 1 {
			t.Errorf("another workspace's %s = %d %v, want 404 not_found and nothing else", c, code, body)
		}
	}

	for name, path := range map[string]string{
		"no claim":            "/evidence",
		"malformed ref":       "/evidence" + qs("claim", "grant:not-a-uuid"),
		"untyped id":          "/evidence" + qs("claim", uuid.New().String()),
		"a run ref":           "/evidence" + qs("claim", "cloud_scan_run:"+e.run.ID.String()),
		"unknown parameter":   "/evidence" + qs("claim", home[0], "workspace", e.l.ws.String()),
		"include other":       "/evidence" + qs("claim", home[0], "include", "everything"),
		"bad rev":             "/evidence" + qs("claim", home[0], "rev", "zero"),
		"coverage no surface": "/evidence" + qs("claim", "coverage:"+e.run.ID.String()),
	} {
		if code, body := e.api.get(path); code != http.StatusBadRequest || errCode(body) != "invalid_parameter" {
			t.Errorf("%s: %s = %d %v, want 400 invalid_parameter", name, path, code, body)
		}
	}
	many := "/evidence?claim=" + home[0]
	for i := 0; i < 50; i++ {
		many += "&claim=" + home[0]
	}
	if code, body := e.api.get(many); code != http.StatusBadRequest || errCode(body) != "invalid_parameter" {
		t.Errorf("51 claims = %d %v, want 400 (D-79 bounds a request to 50)", code, body)
	}

	rev := num(evidenceGet(t, e.api, home[0]), "meta", "rev")
	evidenceGet(t, e.api, home[0], "rev", strconv.FormatInt(rev, 10))
	if code, body := e.api.get("/evidence" + qs("claim", home[0], "rev", strconv.FormatInt(rev+7, 10))); code != http.StatusConflict ||
		errCode(body) != "revision_stale" {
		t.Errorf("stale rev = %d %v, want 409 revision_stale", code, body)
	}
}

// D-79: claim repeated returns one entry per claim in request order, and a
// summary sentence only when every claim is a grant of one holder with one
// group key -- the canvas's "2 statements" edge. Any claim not found is 404.
func TestP2EvidenceGroupedGrants(t *testing.T) {
	e := evidenceE4Lab(t, "p2-evidence-grouped")
	read := evidenceGrant(t, e.l, "SharedToolRole", "TicketRead", "ReadTickets")
	toolbox := evidenceGrant(t, e.l, "SharedToolRole", "ToolboxRead", "ToolboxGet")
	list := evidenceGrant(t, e.l, "SharedToolRole", "TicketRead", "ListTickets")

	code, body := e.api.get("/evidence?claim=" + toolbox + "&claim=" + read)
	mustStatus(t, "grouped", code, body, http.StatusOK)
	data := digl(body, "data")
	if len(data) != 2 || digs(data[0], "claim", "ref") != toolbox || digs(data[1], "claim", "ref") != read {
		t.Fatalf("data = %s, want both claims in request order", evidenceJSON(data))
	}
	if got, want := digs(body, "meta", "summary", "sentence"),
		"SharedToolRole is granted s3:GetObject on support-tickets/* by 2 statements."; got != want {
		t.Errorf("summary = %q, want %q", got, want)
	}
	for _, d := range data {
		if len(digl(d, "facts")) == 0 || len(digl(d, "limitations")) == 0 {
			t.Errorf("each grant keeps its own evidence: %s", evidenceJSON(d))
		}
	}

	code, body = e.api.get("/evidence?claim=" + read + "&claim=" + list)
	mustStatus(t, "different statements", code, body, http.StatusOK)
	if len(digl(body, "data")) != 2 || dig(body, "meta", "summary") != nil {
		t.Errorf("different group keys: summary = %v, want none", dig(body, "meta", "summary"))
	}
	if code, body = e.api.get("/evidence?claim=" + read + "&claim=grant:" + uuid.New().String()); code != http.StatusNotFound {
		t.Errorf("one claim not found = %d %v, want 404 for the whole request", code, body)
	}
}

// An ENDED claim is still evidence: the panel opens on it with valid_to and
// ended_reason (§2.14.5, D-80).
func TestP2EvidenceEndedClaim(t *testing.T) {
	e := evidenceE4Lab(t, "p2-evidence-ended")
	claim := evidenceGrant(t, e.l, "PlainRole", "PlainRead", "PlainGet")
	e.a.detach("PlainRole", e.a.policyARN("PlainRead"))
	evidenceCycle(e.l, e.a, evidenceFakes{})
	body := evidenceGet(t, e.api, claim)
	d := dig(body, "data")
	if digs(d, "status", "lifecycle") != "ended" || digs(d, "freshness", "valid_to") == "" ||
		digs(d, "freshness", "ended_reason") == "" || dig(d, "freshness", "stale_since") != nil {
		t.Fatalf("ended grant = %s, want lifecycle ended with valid_to and ended_reason", evidenceJSON(d))
	}
}

// The route is behind the 503 gate like every graph read, and reported as a
// feature exactly when it is usable (D-11).
func TestP2EvidenceGateAndCapability(t *testing.T) {
	off := newP2Lab(t, "p2-evidence-off", false)
	code, body := off.api().get("/evidence" + qs("claim", "grant:"+uuid.New().String()))
	if code != http.StatusServiceUnavailable || errCode(body) != "graph_unavailable" {
		t.Errorf("projection off = %d %v, want 503 graph_unavailable", code, body)
	}
	if code, body := off.api().get("/capabilities"); code != http.StatusOK || dig(body, "data", "features", "evidence") != false {
		t.Errorf("off: features.evidence = %v, want false", dig(body, "data", "features", "evidence"))
	}
	on := newP2Lab(t, "p2-evidence-on", true)
	if code, body := on.api().get("/capabilities"); code != http.StatusOK || dig(body, "data", "features", "evidence") != true {
		t.Errorf("on: features.evidence = %v, want true", dig(body, "data", "features", "evidence"))
	}
	if perm := on.api().requiredPermission(http.MethodGet, "/evidence"+qs("claim", "grant:"+uuid.New().String())); perm != "iga:read" {
		t.Errorf("/evidence demands %q, want iga:read", perm)
	}
	// Nothing published: no claim exists yet (D-4).
	if code, body := on.api().get("/evidence" + qs("claim", "grant:"+uuid.New().String())); code != http.StatusNotFound {
		t.Errorf("nothing published = %d %v, want 404", code, body)
	}
}

// D-24: the junction is never pruned, so a policy whose document changed links
// BOTH versions' observations to the grant. Only the version the claim's last
// confirming run still confirmed is a fact; the superseded one is dropped.
func TestP2EvidenceFactsDropSupersededVersions(t *testing.T) {
	l := newP2Lab(t, "p2-evidence-versions", true)
	a := l.account(accountA)
	a.role("SharedToolRole", "AROASHAREDTOOLROLE01")
	arn := a.managed("TicketRead", s3aDoc("ReadTickets", "s3:GetObject", "arn:aws:s3:::support-tickets/*"))
	a.attach("SharedToolRole", arn)
	l.scanAndProject(a)
	claim := evidenceGrant(t, l, "SharedToolRole", "TicketRead", "ReadTickets")

	// A new default version: same Sid and grant, new content.
	a.iam.managedPolicies[arn] = evidenceDoc(
		`{"Sid":"ReadTickets","Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":"arn:aws:s3:::support-tickets/*"}`)
	a.iam.policyVersions[arn] = "v4"
	run2 := l.scanAndProject(a)
	if again := evidenceGrant(t, l, "SharedToolRole", "TicketRead", "ReadTickets"); again != claim {
		t.Fatalf("fixture: the grant was re-keyed (%s -> %s); a Sid-keyed statement keeps its grant", claim, again)
	}
	if n := l.count(`SELECT count(*) FROM iga_access_edge_evidence j JOIN cloud_observation o ON o.id = j.observation_id
	                  WHERE j.access_edge_id = ? AND o.surface = ?`, refUUID(t, claim), models.SurfaceIAMPolicies); n != 2 {
		t.Fatalf("fixture: %d policy-version links, want both versions' (the junction keeps the old one)", n)
	}

	body := evidenceGet(t, l.api(), claim, "include", "raw")
	var versions []string
	for i, f := range digl(body, "data", "facts") {
		if digs(f, "observed_in_run") != refOf("cloud_scan_run", run2.ID) {
			t.Errorf("fact %q run = %q, want the claim's last confirming run", digs(f, "fact"), digs(f, "observed_in_run"))
		}
		if dig(f, "policy_version") != nil {
			versions = append(versions, digs(f, "policy_version"))
			if got := digs(body, "data", "raw", i, "sanitized_facts", "document_hash"); got == "" {
				t.Errorf("raw for the policy fact has no document hash")
			}
		}
	}
	if !reflect.DeepEqual(versions, []string{"v4"}) {
		t.Fatalf("policy-version facts = %v, want only v4:\n%s", versions, evidenceJSON(digl(body, "data", "facts")))
	}
	if got := digs(body, "data", "claim", "sentence"); !strings.Contains(got, "s3:GetObject, s3:GetObjectVersion") {
		t.Errorf("sentence = %q, want the current content's actions", got)
	}
}

// D-35: the graph's limitations come from the SAME function as /evidence --
// ClaimLimitations restricted to the fact-free codes gives exactly the
// route's codes minus the ones that need facts or are stated once in meta.
func TestP2EvidenceClaimLimitationsMatchTheRoute(t *testing.T) {
	e := evidenceE4Lab(t, "p2-evidence-shared-fn")
	l := e.l
	claims := []string{
		evidenceGrant(t, l, "SharedToolRole", "TicketRead", "ListTickets"),
		evidenceGrant(t, l, "SharedToolRole", "FinanceAll", "AllButFinance"),
		evidenceGrant(t, l, "SharedToolRole", "ExternalKey", "Decrypt"),
		evidenceGrant(t, l, "priya", "PriyaOwn", "OwnRead"),
		evidenceGrant(t, l, "ops", "OpsRead", "ReadOps"),
		evidenceRelationship(t, l, models.RelTypeCanAssume, "SharedToolRole", "AssumerRole"),
		evidenceRelationship(t, l, models.RelTypeCanAssume, "ec2.amazonaws.com", "PartnerRole"),
		evidenceRelationship(t, l, models.RelTypeCanAssume, "lambda.amazonaws.com", "GuardedRole"),
		evidenceRelationship(t, l, models.RelTypeMemberOf, "priya", "ops"),
		evidenceTarget(t, l, "TicketRead", "ListTickets", "arn:aws:s3:::support-tickets"),
	}
	got := evidenceClaimLimitations(t, l, claims, igaread.FactFreeLimitations)
	for _, c := range claims {
		var want []string
		for _, code := range evidenceCodes(evidenceGet(t, e.api, c)) {
			if igaread.FactFreeLimitations[code] {
				want = append(want, code)
			}
		}
		var have []string
		for _, lim := range got[c] {
			have = append(have, lim.Code())
		}
		if !reflect.DeepEqual(have, want) {
			t.Errorf("%s: ClaimLimitations = %v, /evidence (fact-free) = %v", c, have, want)
		}
		if len(have) == 0 && c != claims[8] { // member_of (claims[8]) carries none of them
			t.Errorf("%s: no fact-free limitations; every claim but the membership carries some here", c)
		}
	}
	if _, ok := got["grant:"+uuid.New().String()]; ok {
		t.Errorf("an unknown ref must be absent")
	}
}

// evidenceClaimLimitations calls igaread.ClaimLimitations in one snapshot.
func evidenceClaimLimitations(t *testing.T, l *p2Lab, claims []string, codes map[string]bool) map[string][]igaread.Limitation {
	t.Helper()
	refs := make([]igaread.Ref, 0, len(claims))
	for _, c := range claims {
		r, err := igaread.ParseRef(c)
		if err != nil {
			t.Fatalf("ref %q: %v", c, err)
		}
		refs = append(refs, r)
	}
	var out map[string][]igaread.Limitation
	err := igaread.NewReader(l.db, readTestCursorKey).Read(context.Background(), l.ws, igaread.Pin{}, func(q *igaread.Query) error {
		accts, err := q.LoadAccounts()
		if err != nil {
			return err
		}
		out, err = q.ClaimLimitations(accts, refs, codes)
		return err
	})
	if err != nil {
		t.Fatalf("ClaimLimitations: %v", err)
	}
	return out
}
