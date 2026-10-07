package igagov

import (
	"strings"
	"testing"
	"time"
)

// Shared fixtures of the compiler, classifier and health tests.

const (
	ctlID      = "6f1c2a52-58e3-4bb6-9a2e-0f7d8f0b1c11"
	polID      = "7a2d3b63-69f4-4cc7-8b3f-1e8e9f0c2d22"
	wsRef      = "ws-7f3a"
	identityID = "c41d2f3a-1b2c-4d5e-8f90-a1b2c3d4e5f6"
	roleBID    = "AROAEXAMPLEROLEB0001"
	roleCID    = "AROAEXAMPLEROLEC0001"
	depID      = "d0e1f2a3-b4c5-4d6e-8f70-8192a3b4c5d6"
)

func authsecARN() string { return AuthSecBoundaryARN("aws", acct, roleID) }

func testControl() ControlRef {
	return ControlRef{ID: ctlID, PolicyID: polID, AccountID: acct, RoleID: roleID, WorkspaceRef: wsRef,
		OwnedPolicyARNs: []string{authsecARN()}}
}

func baseRole() LiveRole {
	return LiveRole{RoleID: roleID, ARN: roleARN, Name: roleName, Path: "/app/", AccountID: acct, Partition: "aws",
		Tags:            map[string]string{"team": "payments"},
		ManagedPolicies: []PolicyRef{{Ref: "arn:aws:iam::" + acct + ":policy/RefundAccess", DocumentHash: "sha256:" + strings.Repeat("1", 64)}},
		InlinePolicies:  []PolicyRef{{Ref: "refund-inline", DocumentHash: "sha256:" + strings.Repeat("2", 64)}},
		TrustPolicyHash: "sha256:" + strings.Repeat("3", 64)}
}

func roleB() LiveRole {
	return LiveRole{RoleID: roleBID, ARN: "arn:aws:iam::" + acct + ":role/ReportsRole", Name: "ReportsRole", Path: "/", AccountID: acct, Partition: "aws"}
}

// rmEntry is a justified removal.
func rmEntry(svc string) RemoveEntry {
	return RemoveEntry{Service: svc, Basis: RemoveNoAttempt, QualifiedDays: 112, GrantAgeBasis: GrantAgePredatesObservation}
}

func intentFor(delivery string, remove []string, retain ...RetainEntry) RightSizeIntent {
	in := RightSizeIntent{Kind: IntentRightSizeServices,
		Subjects:        []Subject{{IdentityAccountID: identityID, RoleID: roleID, AccountID: acct}},
		Retain:          append([]RetainEntry{{Service: "s3", Basis: RetainObserved, LastAttempt: "2026-09-28T10:02:00Z"}}, retain...),
		ObservationDays: 7, Delivery: delivery, EvidenceRev: 812}
	for _, s := range remove {
		in.Remove = append(in.Remove, rmEntry(s))
	}
	return in
}

type evOpts struct {
	coverage    []CoverageRow
	grants      []BundleGrant
	routes      []RouteAnalysis
	activity    []BundleActivity
	s3Attempt   time.Time
	consumers   []ImpactConsumer
	unresolved  int
	scanEv      *ResourcePolicyEvidence
	skipActFor  map[string]bool
	actOverride map[string]BundleActivity
}

// evidenceFor builds a trusted bundle (or partial, with gaps) for removing
// these services, with s3 retained and observed.
func evidenceFor(t testing.TB, remove []string, o evOpts) EvidenceRef {
	t.Helper()
	if o.coverage == nil {
		o.coverage = completeCoverage()
	}
	if o.s3Attempt.IsZero() {
		o.s3Attempt = daysAgo(1)
	}
	cov := &ResourcePolicyEvidence{Coverage: o.coverage}
	act := []BundleActivity{{Service: "s3", State: EvidenceCollected, Outcome: QualObserved, LastAuthenticatedAt: ts(tp(o.s3Attempt)),
		GrantAgeBasis: GrantAgePredatesObservation, QualifiedDays: 112}}
	for _, s := range remove {
		if o.skipActFor[s] {
			continue
		}
		a := BundleActivity{Service: s, State: EvidenceCollected, Outcome: QualNoAttempt, GrantAgeBasis: GrantAgePredatesObservation, QualifiedDays: 112}
		if ov, ok := o.actOverride[s]; ok {
			a = ov
		}
		act = append(act, a)
	}
	act = append(act, o.activity...)
	routes := o.routes
	if routes == nil {
		ev := o.scanEv
		if ev == nil {
			ev = cov
		}
		for _, s := range remove {
			routes = append(routes, AnalyzeRoutes(s, refundRole, ev, regions))
		}
	}
	grants := o.grants
	if grants == nil {
		grants = []BundleGrant{{PolicyARN: "arn:aws:iam::" + acct + ":policy/RefundAccess", AssignmentKind: AssignAttached,
			StatementKey: "RA#0", StatementHash: "sha256:" + strings.Repeat("4", 64), Services: append([]string{"s3"}, remove...)}}
	}
	consumers := o.consumers
	if consumers == nil {
		consumers = []ImpactConsumer{{WorkloadID: wl1, Relationship: RelExecutesAs}}
	}
	b, err := BuildBundle(BundleInput{
		BuiltAt: now,
		Sources: []BundleSourceInput{{Kind: SourceAWSPublication, Rev: 812, PublishedAt: now.Add(-3 * time.Hour), ConnectorID: connA,
			ConnectorRun: runA1, Authenticated: true, Ordered: true, ActivityReportGeneratedAt: tp(now.Add(-3 * time.Hour)),
			ResourcePolicyCoverage: SummarizeCoverage(cov, regions), ResourcePolicyRun: runA1}},
		Target:          BundleTarget{AccountID: acct, RoleID: roleID, RoleARN: roleARN},
		RemovedServices: remove, Grants: grants, Consumers: consumers, ConsumersUnresolved: o.unresolved,
		Owners: []string{"u1"}, Activity: act, RouteAnalyses: routes,
	}, DefaultTrustRules())
	if err != nil {
		t.Fatal(err)
	}
	return EvidenceRef{Bundle: b, EvidenceRev: 812, ScanRunID: runA1}
}

func mustCompile(t testing.TB, in TargetInput) TargetPlans {
	t.Helper()
	tp, err := CompileTarget(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := tp.Apply.CheckStorable(); err != nil {
		t.Fatal(err)
	}
	if tp.Undo != nil {
		if err := tp.Undo.CheckStorable(); err != nil {
			t.Fatal(err)
		}
	}
	return tp
}

// targetIn is a direct, first-attachment target removing the services, on
// a role with no boundary and complete resource-policy evidence.
func targetIn(t testing.TB, s *simAccount, delivery string, remove ...string) TargetInput {
	cov := &ResourcePolicyEvidence{Coverage: completeCoverage()}
	return TargetInput{Control: testControl(), Intent: intentFor(delivery, remove), Live: s.read(roleID, authsecARN()),
		Evidence: evidenceFor(t, remove, evOpts{}), ScanEvidence: cov, EnabledRegions: regions,
		AccountServices: []string{"s3", "sqs", "ec2", "ecr", "lambda"}}
}

func hasRefusal(p Plan, code string) bool {
	for _, r := range p.Refusals {
		if r.Code == code {
			return true
		}
	}
	return false
}

func opNames(p Plan) string {
	var out []string
	for _, o := range p.Ops {
		out = append(out, o.Op)
	}
	return strings.Join(out, ",")
}

func deref(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

// customerBoundary is A4's customer boundary: Sids, a condition and a Deny.
const customerBoundary = `{"Version":"2012-10-17","Statement":[
 {"Sid":"Compute","Effect":"Allow","Action":["ec2:Describe*","s3:GetObject","sqs:SendMessage"],"Resource":"*",
  "Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}},
 {"Sid":"Queues","Effect":"Allow","Action":"sqs:*","Resource":"arn:aws:sqs:*:*:*"},
 {"Sid":"NoIam","Effect":"Deny","Action":"iam:*","Resource":"*"}]}`

const teamBoundaryARN = "arn:aws:iam::" + acct + ":policy/boundaries/TeamBoundary"
