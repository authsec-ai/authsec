package integration

// E4 / T6.5 gate: EACH limitation code of the §5.3 vocabulary has one fixture
// that produces it and one that does not (SPEC §6.1 T6.5; E4 "Fails if: a
// limitation that does not apply"). Everything below is collected by the real
// scan worker and projected by the real projector; the one state the fakes
// cannot produce (a GitHub-provider row, organizations_not_collected's only
// "does not") is inserted directly and says so.

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// evidenceLimCase is one code's pair: a claim that produces it (with its
// fields checked) and one that does not.
type evidenceLimCase struct {
	name     string
	code     string
	produces func(e *evidenceE4) string
	lacks    func(e *evidenceE4) string
	check    func(t *testing.T, e *evidenceE4, lim map[string]any)
}

func TestP2EvidenceLimitationVocabulary(t *testing.T) {
	e := evidenceE4Lab(t, "p2-evidence-vocab")
	l := e.l
	grant := func(holder, policy, sid string) func(*evidenceE4) string {
		return func(e *evidenceE4) string { return evidenceGrant(t, l, holder, policy, sid) }
	}
	rel := func(typ, src, dst string) func(*evidenceE4) string {
		return func(e *evidenceE4) string { return evidenceRelationship(t, l, typ, src, dst) }
	}
	resourceRef := func(text string) string {
		id, _ := l.resourceID(text)
		return refOf("resource", id)
	}
	identityRef := func(name string) string { return evidenceNode(t, l, "identity", "iga_identity_accounts", name) }

	cases := []evidenceLimCase{
		{name: "effective access on a grant, not on an assignment", code: "effective_access_not_evaluated",
			produces: grant("PlainRole", "PlainRead", "PlainGet"),
			lacks:    func(*evidenceE4) string { return evidenceAssignment(t, l, "PlainRead", "PlainRole") }},

		{name: "statement Condition", code: "conditions_not_evaluated",
			produces: grant("SharedToolRole", "TicketRead", "ListTickets"),
			lacks:    grant("SharedToolRole", "TicketRead", "ReadTickets"),
			check: func(t *testing.T, _ *evidenceE4, lim map[string]any) {
				if got := evidenceStrings(lim["keys"]); !reflect.DeepEqual(got, []string{"s3:prefix"}) {
					t.Errorf("keys = %v, want [s3:prefix]", got)
				}
			}},
		{name: "trust statement Condition", code: "conditions_not_evaluated",
			produces: rel(models.RelTypeCanAssume, "SharedToolRole", "AssumerRole"),
			lacks:    rel(models.RelTypeCanAssume, "lambda.amazonaws.com", "SharedToolRole"),
			check: func(t *testing.T, _ *evidenceE4, lim map[string]any) {
				if got := evidenceStrings(lim["keys"]); !reflect.DeepEqual(got, []string{"sts:ExternalId"}) {
					t.Errorf("keys = %v, want [sts:ExternalId]", got)
				}
			}},

		{name: "NotResource (B19)", code: "negated_statement",
			produces: grant("SharedToolRole", "FinanceAll", "AllButFinance"),
			lacks:    grant("PlainRole", "PlainRead", "PlainGet"),
			check: func(t *testing.T, _ *evidenceE4, lim map[string]any) {
				if got := evidenceStrings(lim["negations"]); !reflect.DeepEqual(got, []string{"NotResource"}) {
					t.Errorf("negations = %v, want [NotResource]", got)
				}
			}},
		{name: "NotAction", code: "negated_statement",
			produces: grant("SharedToolRole", "FinanceAll", "AllButIAM"),
			lacks:    grant("SharedToolRole", "TicketRead", "ReadTickets"),
			check: func(t *testing.T, _ *evidenceE4, lim map[string]any) {
				if got := evidenceStrings(lim["negations"]); !reflect.DeepEqual(got, []string{"NotAction"}) {
					t.Errorf("negations = %v, want [NotAction]", got)
				}
			}},
		{name: "trust NotAction (D-88)", code: "negated_statement",
			produces: rel(models.RelTypeCanAssume, "ec2.amazonaws.com", "PartnerRole"),
			lacks:    rel(models.RelTypeCanAssume, evidenceAccountC, "PartnerRole")},

		{name: "the holder's own Deny", code: "deny_statements_present",
			produces: grant("SharedToolRole", "TicketRead", "ReadTickets"),
			lacks:    grant("PlainRole", "PlainRead", "PlainGet"),
			check: func(t *testing.T, e *evidenceE4, lim map[string]any) {
				want := evidenceStatementRef(t, e.l, "GuardRails", "NoDeletes")
				if num(lim, "count") != 1 || !reflect.DeepEqual(evidenceStrings(lim["statements"]), []string{want}) {
					t.Errorf("deny = %s, want count 1 and [%s]", evidenceJSON(lim), want)
				}
			}},
		{name: "a Deny of the holder's group", code: "deny_statements_present",
			produces: grant("priya", "PriyaOwn", "OwnRead"),
			lacks:    grant("devs", "DevRead", "ReadDev"),
			check: func(t *testing.T, e *evidenceE4, lim map[string]any) {
				want := evidenceStatementRef(t, e.l, "OpsDeny", "NoBucketDeletes")
				if num(lim, "count") != 1 || !reflect.DeepEqual(evidenceStrings(lim["statements"]), []string{want}) {
					t.Errorf("deny = %s, want the group's one Deny %s", evidenceJSON(lim), want)
				}
			}},

		{name: "the holder's boundary", code: "permissions_boundary_present",
			produces: grant("priya", "PriyaOwn", "OwnRead"),
			lacks:    grant("PlainRole", "PlainRead", "PlainGet"),
			check: func(t *testing.T, e *evidenceE4, lim map[string]any) {
				pol := evidenceNode(t, e.l, "policy", "iga_policy", "PowerUserAccess")
				if lim["holder"] != true || !reflect.DeepEqual(evidenceStrings(lim["policies"]), []string{pol}) {
					t.Errorf("boundary = %s, want holder true and [%s]", evidenceJSON(lim), pol)
				}
			}},
		{name: "a current member's boundary on a group grant (D-22, E4 'for priya')", code: "permissions_boundary_present",
			produces: grant("ops", "OpsRead", "ReadOps"),
			lacks:    grant("devs", "DevRead", "ReadDev"),
			check: func(t *testing.T, e *evidenceE4, lim map[string]any) {
				priya := identityRef("priya")
				if lim["holder"] != false || num(lim, "member_count") != 1 ||
					!reflect.DeepEqual(evidenceStrings(lim["members"]), []string{priya}) {
					t.Errorf("boundary = %s, want holder false and member priya %s", evidenceJSON(lim), priya)
				}
			}},

		{name: "always, for AWS", code: "organizations_not_collected",
			produces: grant("PlainRole", "PlainRead", "PlainGet"),
			lacks:    nil}, // see TestP2EvidenceNonAWSRowIsNotFound: a non-AWS row has no evidence at all

		{name: "a target whose resource policy was read", code: "resource_policy_not_projected",
			produces: grant("SharedToolRole", "TicketRead", "ListTickets"),
			lacks:    grant("SharedToolRole", "TicketRead", "ReadTickets"),
			check: func(t *testing.T, _ *evidenceE4, lim map[string]any) {
				want := resourceRef("arn:aws:s3:::support-tickets")
				if got := evidenceStrings(lim["resources"]); !reflect.DeepEqual(got, []string{want}) {
					t.Errorf("resources = %v, want [%s]", got, want)
				}
			}},
		{name: "a target claim on a resource whose policy was read", code: "resource_policy_not_projected",
			produces: func(e *evidenceE4) string {
				return evidenceTarget(t, l, "TicketRead", "ListTickets", "arn:aws:s3:::support-tickets")
			},
			lacks: grant("PlainRole", "PlainRead", "PlainGet")},

		{name: "an exact reference", code: "resource_existence_not_verified",
			produces: grant("PlainRole", "PlainRead", "PlainGet"),
			lacks:    grant("SharedToolRole", "TicketRead", "ReadTickets"), // selector only (D-21)
			check: func(t *testing.T, _ *evidenceE4, lim map[string]any) {
				want := resourceRef("arn:aws:s3:::plain-bucket/report.csv")
				if got := evidenceStrings(lim["resources"]); !reflect.DeepEqual(got, []string{want}) {
					t.Errorf("resources = %v, want [%s]", got, want)
				}
			}},
		{name: "a selector", code: "selector_may_match_nothing",
			produces: grant("SharedToolRole", "TicketRead", "ReadTickets"),
			lacks:    grant("PlainRole", "PlainRead", "PlainGet"),
			check: func(t *testing.T, _ *evidenceE4, lim map[string]any) {
				want := resourceRef("arn:aws:s3:::support-tickets/*")
				if got := evidenceStrings(lim["resources"]); !reflect.DeepEqual(got, []string{want}) {
					t.Errorf("resources = %v, want [%s]", got, want)
				}
			}},
		{name: "the implicit * of a NotResource statement", code: "selector_may_match_nothing",
			produces: grant("SharedToolRole", "FinanceAll", "AllButFinance"),
			lacks:    grant("SharedToolRole", "ExternalKey", "Decrypt")},
		{name: "a selector's own presence", code: "selector_may_match_nothing",
			produces: func(*evidenceE4) string { return resourceRef("arn:aws:s3:::support-tickets/*") },
			lacks:    func(*evidenceE4) string { return resourceRef("arn:aws:s3:::plain-bucket/report.csv") }},

		{name: "a target in an unconnected account", code: "account_not_connected",
			produces: grant("SharedToolRole", "ExternalKey", "Decrypt"),
			lacks:    grant("PlainRole", "PlainRead", "PlainGet"),
			check: func(t *testing.T, _ *evidenceE4, lim map[string]any) {
				if got := evidenceStrings(lim["accounts"]); !reflect.DeepEqual(got, []string{evidenceAccountC}) {
					t.Errorf("accounts = %v, want [%s]", got, evidenceAccountC)
				}
			}},
		{name: "a trusted principal in an unconnected account", code: "account_not_connected",
			produces: rel(models.RelTypeCanAssume, evidenceAccountC, "PartnerRole"),
			lacks:    rel(models.RelTypeCanAssume, "lambda.amazonaws.com", "SharedToolRole")},

		{name: "can_assume", code: "caller_permission_not_evaluated",
			produces: rel(models.RelTypeCanAssume, "lambda.amazonaws.com", "SharedToolRole"),
			lacks:    rel(models.RelTypeMemberOf, "priya", "ops")},

		{name: "NotPrincipal in the trust policy", code: "not_principal_unresolved",
			produces: rel(models.RelTypeCanAssume, "lambda.amazonaws.com", "GuardedRole"),
			lacks:    rel(models.RelTypeCanAssume, "lambda.amazonaws.com", "SharedToolRole")},

		{name: "no Access Advisor facts on an identity", code: "activity_attempts_not_outcomes",
			produces: nil, // TestP2EvidenceActivityAttemptsNotOutcomes: the fakes report activity there
			lacks:    func(*evidenceE4) string { return identityRef("SharedToolRole") }},
	}

	for _, tc := range cases {
		t.Run(tc.code+"/"+tc.name, func(t *testing.T) {
			if tc.produces != nil {
				claim := tc.produces(e)
				body := evidenceGet(t, e.api, claim)
				lim := evidenceLim(body, tc.code)
				if lim == nil {
					t.Fatalf("%s: limitations %v lack %s:\n%s", claim, evidenceCodes(body), tc.code, evidenceJSON(body))
				}
				if tc.check != nil {
					tc.check(t, e, lim)
				}
			}
			if tc.lacks != nil {
				claim := tc.lacks(e)
				body := evidenceGet(t, e.api, claim)
				if lim := evidenceLim(body, tc.code); lim != nil {
					t.Fatalf("%s: carries %s, which does not apply: %v", claim, tc.code, evidenceCodes(body))
				}
			}
		})
	}
}

// evidenceStatementRef is the statement ref of policy's statement sid.
func evidenceStatementRef(t *testing.T, l *p2Lab, policy, sid string) string {
	t.Helper()
	var ids []uuid.UUID
	l.db.Raw(`SELECT e.id FROM iga_entitlements e JOIN iga_policy p ON p.workspace_id = e.workspace_id AND p.id = e.policy_id
	           WHERE e.workspace_id = ? AND p.display_name = ? AND e.sid = ? AND e.lifecycle = 'active'`,
		l.ws, policy, sid).Scan(&ids)
	if len(ids) != 1 {
		t.Fatalf("fixture: statements %s/%s = %v, want one", policy, sid, ids)
	}
	return refOf("statement", ids[0])
}

// The plain grant carries EXACTLY what applies to it, and nothing else: the
// strongest form of "a limitation that does not apply never appears".
func TestP2EvidencePlainGrantCarriesOnlyWhatApplies(t *testing.T) {
	e := evidenceE4Lab(t, "p2-evidence-plain")
	body := evidenceGet(t, e.api, evidenceGrant(t, e.l, "PlainRole", "PlainRead", "PlainGet"))
	want := []string{"effective_access_not_evaluated", "organizations_not_collected", "resource_existence_not_verified"}
	if got := evidenceCodes(body); !reflect.DeepEqual(got, want) {
		t.Fatalf("limitations = %v, want exactly %v", got, want)
	}
	body = evidenceGet(t, e.api, evidenceRelationship(t, e.l, models.RelTypeCanAssume, "lambda.amazonaws.com", "SharedToolRole"))
	want = []string{"organizations_not_collected", "caller_permission_not_evaluated"}
	if got := evidenceCodes(body); !reflect.DeepEqual(got, want) {
		t.Fatalf("plain can_assume limitations = %v, want exactly %v", got, want)
	}
}

// organizations_not_collected is "always, for AWS", so its only "does not" is
// a claim that is not AWS -- and such a row is not a graph row at all (D-6):
// 404, no evidence, no limitations. The fakes cannot produce a GitHub row, so
// it is inserted directly.
func TestP2EvidenceNonAWSRowIsNotFound(t *testing.T) {
	e := evidenceE4Lab(t, "p2-evidence-github")
	id := uuid.New()
	if err := e.l.db.Exec(`INSERT INTO iga_identity_accounts (id, workspace_id, display_name, account_kind, provider, source_key)
	                        VALUES (?, ?, 'octocat', 'github_user', 'github', ?)`,
		id, e.l.ws, "github\x1foctocat-"+id.String()).Error; err != nil {
		t.Fatalf("insert github identity: %v", err)
	}
	code, body := e.api.get("/evidence" + qs("claim", refOf("identity", id)))
	if code != http.StatusNotFound || errCode(body) != "not_found" || dig(body, "data") != nil {
		t.Fatalf("github identity = %d %v, want 404 not_found and no evidence", code, body)
	}
}

// surface_denied / surface_stale: a required surface of the claim's partition
// that the run the revision holds it from did not reach -- with the account,
// surface, state and since -- and never on a claim whose partitions were
// reached.
func TestP2EvidenceSurfaceLimitations(t *testing.T) {
	l := newP2Lab(t, "p2-evidence-surfaces", true)
	a := l.account(accountA)
	a.role("SoloRole", "AROASOLOROLESOLOROLE")
	a.attach("SoloRole", a.managed("SoloRead", s3aDoc("Solo", "s3:GetObject", "arn:aws:s3:::solo/*")))
	s3aGroup(a, "crew", "AGPACREWCREWCREWCREW")
	s3aGroupAttach(t, a, "crew", a.managed("CrewRead", s3aDoc("Crew", "s3:GetObject", "arn:aws:s3:::crew/*")))
	s3aUser(a, "kim", "AIDAKIMKIMKIMKIMKIM1")
	s3aJoin(a, "kim", "crew")
	l.scanAndProject(a)
	api := l.api()
	member := evidenceRelationship(t, l, models.RelTypeMemberOf, "kim", "crew")
	solo := evidenceGrant(t, l, "SoloRole", "SoloRead", "Solo")

	surfaceCodes := func(body map[string]any) []string {
		var out []string
		for _, c := range evidenceCodes(body) {
			if strings.HasPrefix(c, "surface_") {
				out = append(out, c)
			}
		}
		return out
	}
	body := evidenceGet(t, api, member)
	if got := surfaceCodes(body); len(got) != 0 || digs(body, "data", "status", "collection") != "complete" {
		t.Fatalf("reached member_of: surface codes %v, collection %q; want none, complete", got, digs(body, "data", "status", "collection"))
	}

	// Groups denied: member_of goes stale on iam_groups.
	a.iam.fail["GetAccountAuthorizationDetails:Group"] = denied("iam:GetAccountAuthorizationDetails")
	run2 := l.scanAndProject(a)
	body = evidenceGet(t, api, member)
	lim := evidenceLim(body, "surface_denied")
	if lim == nil || digs(lim, "surface") != models.SurfaceIAMGroups || digs(lim, "state") != models.CloudCoverageDenied ||
		digs(lim, "account_id") != accountA {
		t.Fatalf("stale member_of limitations = %s, want surface_denied iam_groups denied in %s", evidenceJSON(dig(body, "data", "limitations")), accountA)
	}
	if want := evidenceRunPublishedAt(t, l, run2.ID); digs(lim, "since") != want {
		t.Errorf("since = %q, want the run that first recorded the denial, published %s (D-72)", digs(lim, "since"), want)
	}
	pub2 := evidencePublishedAt(t, l, run2.ID)
	if got := digs(body, "data", "status", "lifecycle"); got != models.RelStale {
		t.Errorf("lifecycle = %q, want stale", got)
	}
	if got := digs(body, "data", "status", "collection"); got != "stale" {
		t.Errorf("collection = %q, want stale: a required surface was denied", got)
	}
	if got := digs(body, "data", "freshness", "stale_since"); got != pub2 {
		t.Errorf("stale_since = %q, want %s: the first publication that no longer confirmed it (D-23)", got, pub2)
	}
	// A role's presence stands on iam_roles alone: the groups denial is not
	// its gap. (A grant's partition requires every IAM listing, iam_groups
	// included -- §4.10 -- so SoloRead does carry it.)
	if got := surfaceCodes(evidenceGet(t, api, evidenceNode(t, l, "identity", "iga_identity_accounts", "SoloRole"))); len(got) != 0 {
		t.Errorf("SoloRole presence carries %v: iam_groups is not a surface its partition requires", got)
	}
	if lim := evidenceLim(evidenceGet(t, api, solo), "surface_denied"); lim == nil || digs(lim, "surface") != models.SurfaceIAMGroups {
		t.Errorf("SoloRead grant: surface_denied = %v, want iam_groups (the access-edge partition requires it)", lim)
	}

	// Groups back, the managed-policy listing throttled: the grant goes
	// stale on iam_policies, the membership is current again.
	delete(a.iam.fail, "GetAccountAuthorizationDetails:Group")
	a.iam.fail["GetAccountAuthorizationDetails:LocalManagedPolicy"] = throttled("iam:GetAccountAuthorizationDetails")
	l.scanAndProject(a)
	body = evidenceGet(t, api, solo)
	lim = evidenceLim(body, "surface_stale")
	if lim == nil || digs(lim, "surface") != models.SurfaceIAMPolicies || digs(lim, "state") != models.CloudCoverageThrottled {
		t.Fatalf("throttled grant limitations = %s, want surface_stale iam_policies throttled", evidenceJSON(dig(body, "data", "limitations")))
	}
	if got := surfaceCodes(evidenceGet(t, api, member)); len(got) != 0 {
		t.Errorf("re-read member_of carries %v, want none", got)
	}
}

// evidenceRunPublishedAt is when a run's collection was published
// (cloud_scan_run.published_at): what a coverage streak's since is (D-72).
func evidenceRunPublishedAt(t *testing.T, l *p2Lab, run uuid.UUID) string {
	t.Helper()
	var at time.Time
	if err := l.db.Raw(`SELECT published_at FROM cloud_scan_run WHERE workspace_id = ? AND id = ?`, l.ws, run).
		Row().Scan(&at); err != nil {
		t.Fatalf("run %s: %v", run, err)
	}
	return at.UTC().Format(time.RFC3339)
}

// evidencePublishedAt is the time of the publication a run's projection made
// (iga_publication.published_at): what stale_since is (D-23).
func evidencePublishedAt(t *testing.T, l *p2Lab, run uuid.UUID) string {
	t.Helper()
	var at time.Time
	if err := l.db.Raw(`SELECT published_at FROM iga_publication WHERE workspace_id = ? AND scan_run_id = ?`, l.ws, run).
		Row().Scan(&at); err != nil {
		t.Fatalf("publication of %s: %v", run, err)
	}
	return at.UTC().Format(time.RFC3339)
}

// A grant on a policy whose document could not be read this time is kept
// STALE (never ended), dated from the first publication that could not
// confirm it (D-23), and names the unreadable-documents surface (surface_partial
// policy_documents, D-74) -- while a current grant in the same run does not.
func TestP2EvidenceStaleGrantOnUnreadablePolicy(t *testing.T) {
	l := newP2Lab(t, "p2-evidence-unreadable", true)
	a := l.account(accountA)
	a.role("ReaderRole", "AROAREADERROLEREADE1")
	ro := s3aAWSManaged(a, "ReportsReadOnly", s3aDoc("ReadReports", "s3:GetObject", "arn:aws:s3:::reports/*"))
	a.attach("ReaderRole", ro)
	a.attach("ReaderRole", a.managed("OwnRead", s3aDoc("Own", "s3:GetObject", "arn:aws:s3:::own/*")))
	run1 := l.scanAndProject(a)
	api := l.api()
	stale := evidenceGrant(t, l, "ReaderRole", "ReportsReadOnly", "ReadReports")
	current := evidenceGrant(t, l, "ReaderRole", "OwnRead", "Own")

	a.iam.failPolicyVersion = map[string]error{ro: denied("iam:GetPolicyVersion")}
	run2 := l.scanAndProject(a)
	if s := s3aCoverage(run2)[models.SurfacePolicyDocuments]; s.State != models.CloudCoveragePartial {
		t.Fatalf("fixture: policy_documents = %+v, want partial", s)
	}

	body := evidenceGet(t, api, stale)
	if got := digs(body, "data", "status", "lifecycle"); got != models.RelStale {
		t.Fatalf("lifecycle = %q, want stale: the document could not be read, so nothing ended", got)
	}
	pub2 := evidencePublishedAt(t, l, run2.ID)
	if got := digs(body, "data", "freshness", "stale_since"); got != pub2 {
		t.Errorf("stale_since = %q, want %s", got, pub2)
	}
	lim := evidenceLim(body, "surface_partial")
	if since := evidenceRunPublishedAt(t, l, run2.ID); lim == nil || digs(lim, "surface") != models.SurfacePolicyDocuments ||
		digs(lim, "since") != since {
		t.Errorf("limitations = %s, want surface_partial policy_documents since %s", evidenceJSON(dig(body, "data", "limitations")), since)
	}
	if got := digs(body, "data", "status", "collection"); got != "partial" {
		t.Errorf("collection = %q, want partial", got)
	}
	// Its facts are the run that last confirmed it -- run 1, not run 2.
	facts := digl(body, "data", "facts")
	if len(facts) == 0 {
		t.Fatalf("a stale grant keeps its facts: %s", evidenceJSON(body))
	}
	for _, f := range facts {
		if digs(f, "observed_in_run") != refOf("cloud_scan_run", run1.ID) {
			t.Errorf("fact %q observed_in_run = %q, want the claim's last confirming run %s", digs(f, "fact"),
				digs(f, "observed_in_run"), run1.ID)
		}
	}

	body = evidenceGet(t, api, current)
	if got := digs(body, "data", "status", "lifecycle"); got != models.RelCurrent {
		t.Fatalf("OwnRead lifecycle = %q, want current", got)
	}
	for _, c := range evidenceCodes(body) {
		if strings.HasPrefix(c, "surface_") {
			t.Errorf("current OwnRead grant carries %s: the unreadable document is not its own", c)
		}
	}
	if got := digs(body, "data", "status", "collection"); got != "complete" {
		t.Errorf("OwnRead collection = %q, want complete", got)
	}
	if dig(body, "data", "freshness", "stale_since") != nil {
		t.Errorf("a current claim has stale_since %v", dig(body, "data", "freshness", "stale_since"))
	}
}

// activity_attempts_not_outcomes: an identity's presence evidence that
// carries Access Advisor facts says what they are -- attempts, not outcomes
// (§2.14.8) -- and those facts name their call.
func TestP2EvidenceActivityAttemptsNotOutcomes(t *testing.T) {
	l := newP2Lab(t, "p2-evidence-activity", true)
	a := l.account(accountA)
	a.role("ActiveRole", "AROAACTIVEROLEACTIV1")
	when := time.Now().Add(-48 * time.Hour).UTC().Truncate(time.Second)
	evidenceCycle(l, a, evidenceFakes{activity: []iamtypes.ServiceLastAccessed{
		{ServiceName: aws.String("Amazon S3"), ServiceNamespace: aws.String("s3"), LastAuthenticated: &when},
		{ServiceName: aws.String("Amazon SQS"), ServiceNamespace: aws.String("sqs")},
	}})
	if n := l.count(`SELECT count(*) FROM cloud_usage WHERE workspace_id = ?`, l.ws); n == 0 {
		t.Fatal("fixture: no Access Advisor rows were collected")
	}
	body := evidenceGet(t, l.api(), evidenceNode(t, l, "identity", "iga_identity_accounts", "ActiveRole"))
	if evidenceLim(body, "activity_attempts_not_outcomes") == nil {
		t.Fatalf("limitations = %v, want activity_attempts_not_outcomes", evidenceCodes(body))
	}
	var attempts, none int
	for _, f := range digl(body, "data", "facts") {
		if digs(f, "source_api") != "iam:GetServiceLastAccessedDetails" {
			continue
		}
		text := digs(f, "fact")
		for _, banned := range []string{"never used", "last used", "unused"} {
			if strings.Contains(strings.ToLower(text), banned) {
				t.Errorf("fact %q uses %q (§2.14.8)", text, banned)
			}
		}
		switch {
		case strings.Contains(text, "authenticated attempt") && strings.Contains(text, when.Format(time.RFC3339)):
			attempts++
		case strings.Contains(text, "no attempt") && strings.Contains(text, "tracking period"):
			none++
		}
	}
	if attempts != 1 || none != 1 {
		t.Fatalf("Access Advisor facts: %d attempts, %d none, want 1 and 1:\n%s", attempts, none, evidenceJSON(dig(body, "data", "facts")))
	}

	// A newer run rewrote the usage rows in place and is not projected yet:
	// they now describe a read the revision does not hold (D-25), so they are
	// not this revision's facts -- until that run publishes.
	if _, err := l.runs.Enqueue(l.ws, a.conn, "manual"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	w := services.NewAWSScanWorker(l.db, a.svc).WithOwner("evidence-activity-unprojected").WithGraphProjection(l.gate).
		WithScannerHook(evidenceHook(a, evidenceFakes{activity: []iamtypes.ServiceLastAccessed{
			{ServiceName: aws.String("Amazon S3"), ServiceNamespace: aws.String("s3"), LastAuthenticated: &when}}}))
	if worked, err := w.RunOnce(context.Background()); err != nil || !worked {
		t.Fatalf("scan: worked=%v err=%v", worked, err)
	}
	claim := evidenceNode(t, l, "identity", "iga_identity_accounts", "ActiveRole")
	body = evidenceGet(t, l.api(), claim)
	for _, f := range digl(body, "data", "facts") {
		if digs(f, "source_api") == "iam:GetServiceLastAccessedDetails" {
			t.Errorf("fact %q comes from usage an unpublished run rewrote", digs(f, "fact"))
		}
	}
	if evidenceLim(body, "activity_attempts_not_outcomes") != nil {
		t.Errorf("no Access Advisor fact is shown, so the limitation does not apply: %v", evidenceCodes(body))
	}
	l.project("evidence-activity-late")
	if evidenceLim(evidenceGet(t, l.api(), claim), "activity_attempts_not_outcomes") == nil {
		t.Errorf("once the run published, its Access Advisor facts are back")
	}
}
