package igagov

import (
	"testing"
)

const (
	acct     = "429418377036"
	roleARN  = "arn:aws:iam::429418377036:role/app/RefundTaskRole"
	roleID   = "AROAEXAMPLEREFUND01"
	roleName = "RefundTaskRole"
)

var refundRole = RoleRef{RoleID: roleID, ARN: roleARN, Name: roleName, AccountID: acct}
var regions = []string{"eu-west-1", "us-east-1"}

func mustDoc(t testing.TB, js string) *PolicyDocument {
	t.Helper()
	d, err := DecodePolicyDocument(js)
	if err != nil {
		t.Fatal(err)
	}
	return &d
}

// completeCoverage marks every collected form complete in every region (and
// account-scoped forms once).
func completeCoverage() []CoverageRow {
	var rows []CoverageRow
	for _, f := range AllForms() {
		if f.State != FormCollected {
			continue
		}
		if f.Scope == ScopeAccount {
			rows = append(rows, CoverageRow{Form: f.Name, Region: "us-east-1", State: CoverageComplete})
			continue
		}
		for _, r := range regions {
			rows = append(rows, CoverageRow{Form: f.Name, Region: r, State: CoverageComplete})
		}
	}
	return rows
}

func queue(t testing.TB, name, policy string) ResourcePolicyObservation {
	ob := ResourcePolicyObservation{Form: "sqs_queue", Region: "us-east-1",
		ResourceARN: "arn:aws:sqs:us-east-1:" + acct + ":" + name, ParseState: ParseParsed}
	if policy != "" {
		ob.PolicyPresent, ob.DocumentHash, ob.Document = true, "sha256:x", mustDoc(t, policy)
	}
	return ob
}

func TestAnalyzeRoutes(t *testing.T) {
	grant := func(principal string) string {
		return `{"Statement":[{"Effect":"Allow","Principal":` + principal + `,"Action":"sqs:ReceiveMessage","Resource":"*"}]}`
	}
	withCov := func(rows []CoverageRow, obs ...ResourcePolicyObservation) *ResourcePolicyEvidence {
		return &ResourcePolicyEvidence{Coverage: rows, Observations: obs}
	}
	partialRows := completeCoverage()
	for i := range partialRows {
		if partialRows[i].Form == "sqs_queue" && partialRows[i].Region == "eu-west-1" {
			partialRows[i].State, partialRows[i].Reason = CoveragePartial, "AccessDenied on 2 queues"
		}
	}
	var missingRegion []CoverageRow
	for _, r := range completeCoverage() {
		if !(r.Form == "sqs_queue" && r.Region == "eu-west-1") {
			missingRegion = append(missingRegion, r)
		}
	}
	cases := []struct {
		name      string
		svc       string
		ev        *ResourcePolicyEvidence
		usage     string
		state     string
		remaining int
	}{
		{"no evidence for the run", "sqs", nil, RouteUsageConfirmRequired, RouteStateNotAnalysed, 1},
		{"complete, no policy", "sqs", withCov(completeCoverage(), queue(t, "refunds", "")), RouteUsageNoneObserved, RouteStateNoneObserved, 0},
		{"A42 role ARN route: confirm, but limited by the boundary", "sqs",
			withCov(completeCoverage(), queue(t, "refunds", grant(`{"AWS":"`+roleARN+`"}`))), RouteUsageConfirmRequired, RouteStateNoneObserved, 0},
		{"RoleId principal counts as the role", "sqs",
			withCov(completeCoverage(), queue(t, "refunds", grant(`{"AWS":"`+roleID+`"}`))), RouteUsageConfirmRequired, RouteStateNoneObserved, 0},
		{"A43 session route: known bypass", "sqs",
			withCov(completeCoverage(), queue(t, "refunds", grant(`{"AWS":"arn:aws:sts::`+acct+`:assumed-role/`+roleName+`/worker-1"}`))),
			RouteUsageConfirmRequired, RouteStateBypassKnown, 1},
		{"wildcard principal with PrincipalArn condition: effect unknown", "sqs",
			withCov(completeCoverage(), queue(t, "refunds", `{"Statement":{"Effect":"Allow","Principal":"*","Action":"sqs:*","Resource":"*","Condition":{"ArnEquals":{"aws:PrincipalArn":"`+roleARN+`"}}}}`)),
			RouteUsageConfirmRequired, RouteStateEffectUnknown, 1},
		{"AWS * principal", "sqs", withCov(completeCoverage(), queue(t, "refunds", grant(`{"AWS":"*"}`))),
			RouteUsageConfirmRequired, RouteStateEffectUnknown, 1},
		{"account principal is within the report's scope", "sqs",
			withCov(completeCoverage(), queue(t, "refunds", grant(`{"AWS":"arn:aws:iam::`+acct+`:root"}`))), RouteUsageNoneObserved, RouteStateNoneObserved, 0},
		{"another role is not a route", "sqs",
			withCov(completeCoverage(), queue(t, "refunds", grant(`{"AWS":"arn:aws:iam::`+acct+`:role/Other"}`))), RouteUsageNoneObserved, RouteStateNoneObserved, 0},
		{"deny is not a route", "sqs",
			withCov(completeCoverage(), queue(t, "refunds", `{"Statement":{"Effect":"Deny","Principal":"*","Action":"sqs:*","Resource":"*"}}`)),
			RouteUsageNoneObserved, RouteStateNoneObserved, 0},
		{"a grant of another namespace is not a route", "sqs",
			withCov(completeCoverage(), queue(t, "refunds", `{"Statement":{"Effect":"Allow","Principal":"*","Action":"sns:Publish","Resource":"*"}}`)),
			RouteUsageNoneObserved, RouteStateNoneObserved, 0},
		{"allow + NotPrincipal not listing the role: effect unknown", "sqs",
			withCov(completeCoverage(), queue(t, "refunds", `{"Statement":{"Effect":"Allow","NotPrincipal":{"AWS":"arn:aws:iam::1:role/x"},"Action":"sqs:*","Resource":"*"}}`)),
			RouteUsageConfirmRequired, RouteStateEffectUnknown, 1},
		{"allow + NotPrincipal listing the role: no route", "sqs",
			withCov(completeCoverage(), queue(t, "refunds", `{"Statement":{"Effect":"Allow","NotPrincipal":{"AWS":"`+roleARN+`"},"Action":"sqs:*","Resource":"*"}}`)),
			RouteUsageNoneObserved, RouteStateNoneObserved, 0},
		{"A46 coverage partial in one region", "sqs", withCov(partialRows), RouteUsageConfirmRequired, RouteStateNotAnalysed, 1},
		{"no coverage row for an enabled region", "sqs", withCov(missingRegion), RouteUsageConfirmRequired, RouteStateNotAnalysed, 1},
		{"unparseable policy", "sqs", withCov(completeCoverage(), ResourcePolicyObservation{Form: "sqs_queue", Region: "us-east-1",
			ResourceARN: "arn:aws:sqs:us-east-1:" + acct + ":q", PolicyPresent: true, ParseState: ParseUnparseable}),
			RouteUsageConfirmRequired, RouteStateNotAnalysed, 1},
		{"uncollected form (ECR) is never empty", "ecr", withCov(completeCoverage()), RouteUsageConfirmRequired, RouteStateNotAnalysed, 2},
		{"no policy-bearing form (EC2)", "ec2", withCov(completeCoverage()), RouteUsageNoneObserved, RouteStateNoneObserved, 0},
		{"resource in another account is skipped", "sqs",
			withCov(completeCoverage(), ResourcePolicyObservation{Form: "sqs_queue", Region: "us-east-1", ResourceARN: "arn:aws:sqs:us-east-1:111122223333:q",
				PolicyPresent: true, ParseState: ParseParsed, Document: mustDoc(t, grant(`"*"`))}), RouteUsageNoneObserved, RouteStateNoneObserved, 0},
		{"session beats wildcard", "sqs", withCov(completeCoverage(),
			queue(t, "a", grant(`"*"`)), queue(t, "b", grant(`{"AWS":"arn:aws:sts::`+acct+`:assumed-role/`+roleName+`/s"}`))),
			RouteUsageConfirmRequired, RouteStateBypassKnown, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ra := AnalyzeRoutes(c.svc, refundRole, c.ev, regions)
			if ra.Usage != c.usage || ra.State != c.state || len(ra.RemainingRoutes()) != c.remaining {
				t.Fatalf("usage=%s state=%s remaining=%d routes=%+v", ra.Usage, ra.State, len(ra.RemainingRoutes()), ra.Routes)
			}
			if (ra.State == RouteStateNoneObserved) != (len(ra.RemainingRoutes()) == 0) {
				t.Fatal("051 iga_gov_sp_routes_chk would fail")
			}
		})
	}
}

// A39: a function with no function policy but an alias policy granting the
// role; an S3 access point policy granting the role. Both are observations of
// their own forms and the routes name the alias and the access point.
func TestAnalyzeRoutes_A39_LambdaAndS3Forms(t *testing.T) {
	alias := "arn:aws:lambda:us-east-1:" + acct + ":function:refund:live"
	ap := "arn:aws:s3:us-east-1:" + acct + ":accesspoint/exports"
	ev := &ResourcePolicyEvidence{Coverage: completeCoverage(), Observations: []ResourcePolicyObservation{
		{Form: "lambda_function", Region: "us-east-1", ResourceARN: "arn:aws:lambda:us-east-1:" + acct + ":function:refund", ParseState: ParseParsed},
		{Form: "lambda_alias", Region: "us-east-1", ResourceARN: alias, PolicyPresent: true, ParseState: ParseParsed,
			Document: mustDoc(t, `{"Statement":{"Effect":"Allow","Principal":{"AWS":"`+roleARN+`"},"Action":"lambda:InvokeFunction","Resource":"*"}}`)},
		{Form: "s3_access_point", Region: "us-east-1", ResourceARN: ap, PolicyPresent: true, ParseState: ParseParsed,
			Document: mustDoc(t, `{"Statement":{"Effect":"Allow","Principal":{"AWS":"`+roleARN+`"},"Action":"s3:GetObject","Resource":"*"}}`)},
	}}
	l := AnalyzeRoutes("lambda", refundRole, ev, regions)
	if len(l.Routes) != 1 || l.Routes[0].Resource != alias || l.Routes[0].Form != "lambda_alias" {
		t.Fatalf("lambda routes %+v", l.Routes)
	}
	s := AnalyzeRoutes("s3", refundRole, ev, regions)
	if len(s.Routes) != 1 || s.Routes[0].Resource != ap || s.Routes[0].Form != "s3_access_point" {
		t.Fatalf("s3 routes %+v", s.Routes)
	}
}

func TestSummarizeCoverage(t *testing.T) {
	if got := SummarizeCoverage(nil, regions); got != CoverageNotCollected {
		t.Fatal(got)
	}
	if got := SummarizeCoverage(&ResourcePolicyEvidence{Coverage: completeCoverage()}, regions); got != CoverageComplete {
		t.Fatal(got)
	}
	rows := completeCoverage()
	rows[0].State, rows[0].Reason = CoverageDenied, "AccessDenied"
	if got := SummarizeCoverage(&ResourcePolicyEvidence{Coverage: rows}, regions); got != CoveragePartial {
		t.Fatal(got)
	}
}
