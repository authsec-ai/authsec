package igagov

import (
	"encoding/json"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	runA1 = "a1a1a1a1-0000-4000-8000-000000000001"
	runA3 = "a3a3a3a3-0000-4000-8000-000000000003"
	runB2 = "b2b2b2b2-0000-4000-8000-000000000002"
	connA = "ca000000-0000-4000-8000-00000000000a"
	connB = "cb000000-0000-4000-8000-00000000000b"
	acctB = "111122223333"
	wl1   = "w1000000-0000-4000-8000-000000000001"
	wl2   = "w2000000-0000-4000-8000-000000000002"
	idRef = "c41d2f3a-1b2c-4d5e-8f90-a1b2c3d4e5f6"
)

func stmt(t testing.TB, js string) Statement {
	t.Helper()
	d := mustDoc(t, `{"Statement":`+js+`}`)
	return d.Statements[0]
}

// roleFixture is RefundTaskRole: one attached policy (open-start at the
// connector's first scan) granting s3, sqs, sns and logs; a Lambda runs as
// it; s3 and logs used recently, sqs and sns never reported.
func roleFixture(t testing.TB, firstScan time.Time) RoleSnapshot {
	return RoleSnapshot{
		IdentityAccountID: idRef, RoleID: roleID, ARN: roleARN, Name: roleName, Path: "/app/",
		AccountID: acct, ConnectorID: connA, PartitionKey: "pA", CreatedAt: daysAgo(400),
		Assignments: []PolicyAssignment{{PolicyKey: "P1", PolicyARN: "arn:aws:iam::" + acct + ":policy/RefundAccess", Kind: AssignAttached,
			Intervals: []TimeRange{{From: firstScan}}}},
		Statements: []StatementRevision{{PolicyKey: "P1", StatementKey: "P1#0", Hash: "sha256:s1",
			Statement: stmt(t, `{"Effect":"Allow","Action":["s3:*","sqs:*","sns:*","logs:*"],"Resource":"*"}`), From: firstScan}},
		Activity: &ActivityReport{ScanRunID: runA1, State: EvidenceCollected, GeneratedAt: now.Add(-time.Hour), Services: []ServiceActivity{
			{Service: "s3", LastAuthenticatedAt: tp(daysAgo(1))}, {Service: "logs", LastAuthenticatedAt: tp(daysAgo(1))},
			{Service: "sqs"}, {Service: "sns"},
		}},
		Consumers: []Consumer{{WorkloadID: wl1, Relationship: RelExecutesAs}},
	}
}

func snapshotFixture(t testing.TB, firstScan time.Time, roles ...RoleSnapshot) Snapshot {
	return Snapshot{
		Rev: 1, EvaluatedAt: now,
		Manifest: map[string]string{"pA": runA1},
		Runs: map[string]RunEvidence{runA1: {RunID: runA1, ConnectorID: connA, AccountID: acct, ConnectorFirstPublishedAt: firstScan,
			EnabledRegions: regions, ResourcePolicy: &ResourcePolicyEvidence{Coverage: completeCoverage()}}},
		Roles:     roles,
		Workloads: []WorkloadSnapshot{{ID: wl1, Name: "refund-agent", RuntimeKind: "lambda_function", Stage: "production"}},
		Owners: []OwnerRecord{{ID: "o1", ObjectKind: OwnerObjectWorkload, WorkloadID: wl1, UserID: "u1", Role: OwnerAccountable,
			ReviewDueAt: tp(now.Add(90 * 24 * time.Hour))}},
	}
}

func mustEval(t testing.TB, s Snapshot) Evaluation {
	t.Helper()
	ev, err := Evaluate(s)
	if err != nil {
		t.Fatal(err)
	}
	checkStorageContract(t, ev)
	return ev
}

// checkStorageContract asserts the 048 CHECKs and enums on every row.
func checkStorageContract(t testing.TB, ev Evaluation) {
	t.Helper()
	for _, e := range ev.Evidence {
		if e.State != EvidenceCollected && e.State != EvidenceNotCollected {
			t.Fatalf("evidence state %q", e.State)
		}
		if e.State == EvidenceCollected && (e.ScanRunID == "" || e.ReportGeneratedAt == nil) {
			t.Fatalf("iga_gov_ae_scan_chk / collected_chk: %+v", e)
		}
		if e.RouteUsage == RouteUsageNoneObserved && e.ScanRunID == "" {
			t.Fatalf("iga_gov_ae_route_chk: %+v", e)
		}
		switch e.GrantAgeBasis {
		case GrantAgeObservedSinceChange, GrantAgePredatesObservation, GrantAgeUnknown:
		default:
			t.Fatalf("grant_age_basis %q", e.GrantAgeBasis)
		}
	}
	seen := map[string]bool{}
	for _, f := range ev.Findings {
		if seen[f.Fingerprint] {
			t.Fatalf("duplicate fingerprint %s", f.Fingerprint)
		}
		seen[f.Fingerprint] = true
		if f.Family != FamilyGovernance && f.Family != FamilyCloudAccess {
			t.Fatalf("family %q", f.Family)
		}
		switch f.Severity {
		case SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		default:
			t.Fatalf("severity %q", f.Severity)
		}
		switch f.Confidence {
		case ConfidenceQualified, ConfidenceAgeUnverified, ConfidenceNotApplicable:
		default:
			t.Fatalf("confidence %q", f.Confidence)
		}
		if (f.Confidence != ConfidenceNotApplicable) != (f.Kind == KindUnusedService) {
			t.Fatalf("only unused_service carries a confidence (§2.5): %+v", f)
		}
		want, _ := Fingerprint(f.Kind, f.RoleID, f.DetailKey)
		if want != f.Fingerprint {
			t.Fatal("fingerprint is not sha256(kind ␟ RoleId ␟ detail_key)")
		}
		if c, err := Canonicalize(f.Detail); err != nil || string(c) != string(f.Detail) {
			t.Fatal("detail is not canonical")
		}
		if f.Family == FamilyGovernance && f.EvidenceScanRunID != "" {
			t.Fatal("governance kinds carry no evidence run (048)")
		}
	}
}

func findingsOf(ev Evaluation, kind string) map[string]Finding {
	out := map[string]Finding{}
	for _, f := range ev.Findings {
		if f.Kind == kind {
			out[f.DetailKey] = f
		}
	}
	return out
}

func detailOf(t testing.TB, f Finding) map[string]any {
	var d map[string]any
	if err := json.Unmarshal(f.Detail, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// A36 (and §14.1 step 2): on the connector's first publication an old role
// gets unused_service for sqs and sns, age_unverified, interval from
// activity coverage alone, report time shown.
func TestEvaluate_A36_DayOneFinding(t *testing.T) {
	first := now.Add(-2 * time.Hour)
	ev := mustEval(t, snapshotFixture(t, first, roleFixture(t, first)))
	unused := findingsOf(ev, KindUnusedService)
	if len(unused) != 2 || unused["sqs"].Fingerprint == "" || unused["sns"].Fingerprint == "" {
		t.Fatalf("unused findings %v", unused)
	}
	for _, svc := range []string{"sqs", "sns"} {
		f := unused[svc]
		d := detailOf(t, f)
		if f.Confidence != ConfidenceAgeUnverified || d["grant_age_basis"] != GrantAgePredatesObservation ||
			d["qualified_days"].(float64) != 90 || d["verified_grant_from"] != nil || d["report_generated_at"] == nil ||
			d["scope"] != "identity_policies" || d["last_authenticated_at"] != nil || f.EvidenceScanRunID != runA1 {
			t.Fatalf("%s: %+v %s", svc, f, f.Detail)
		}
	}
	if len(ev.Evidence) != 4 {
		t.Fatalf("evidence rows %d", len(ev.Evidence))
	}
	for _, e := range ev.Evidence {
		// logs has uncollected policy-bearing forms (CloudWatch Logs
		// resource policies, destinations): use through them is unknown.
		wantUsage := RouteUsageNoneObserved
		if e.Service == "logs" {
			wantUsage = RouteUsageConfirmRequired
		}
		if e.ScanRunID != runA1 || e.RouteUsage != wantUsage || e.GrantAgeBasis != GrantAgePredatesObservation {
			t.Fatalf("evidence %+v", e)
		}
	}
	if b := findingsOf(ev, KindBroadGrant); len(b) != 1 || b["P1#0"].Severity != SeverityMedium {
		t.Fatalf("broad grant %v", b)
	}
	if len(findingsOf(ev, KindMissingOwner)) != 0 || len(findingsOf(ev, KindSharedRole)) != 0 {
		t.Fatal("unexpected governance findings")
	}
}

func TestEvaluate_A2_IntervalRules(t *testing.T) {
	first := daysAgo(200)
	t.Run("role created 10 days ago: not enough history", func(t *testing.T) {
		r := roleFixture(t, first)
		r.CreatedAt = daysAgo(10)
		r.Assignments[0].Intervals[0].From = daysAgo(10)
		r.Statements[0].From = daysAgo(10)
		ev := mustEval(t, snapshotFixture(t, first, r))
		if len(findingsOf(ev, KindUnusedService)) != 0 {
			t.Fatal("a 10-day-old role must not get an unused_service finding")
		}
		for _, a := range ev.Assessments {
			if a.Qualification.Service == "sqs" && (a.Qualification.Outcome != QualNotEnoughHistory || a.Qualification.QualifiedDays != 9) {
				t.Fatalf("sqs assessment %+v", a.Qualification)
			}
		}
	})
	t.Run("role outside the sample: activity_not_read", func(t *testing.T) {
		r := roleFixture(t, first)
		r.Activity = nil
		ev := mustEval(t, snapshotFixture(t, first, r))
		nr := findingsOf(ev, KindActivityNotRead)
		if len(nr) != 1 || detailOf(t, nr[""])["reason"] != "not_in_activity_sample" || nr[""].EvidenceScanRunID != runA1 {
			t.Fatalf("activity_not_read %v", nr)
		}
		if len(findingsOf(ev, KindUnusedService)) != 0 {
			t.Fatal("no absence conclusion without a report")
		}
		if len(ev.Evidence) != 4 {
			t.Fatalf("not_collected rows for the granted services: %+v", ev.Evidence)
		}
		for _, e := range ev.Evidence {
			if e.State != EvidenceNotCollected || e.RouteUsage != RouteUsageConfirmRequired || e.GrantAgeBasis != GrantAgeUnknown {
				t.Fatalf("%+v", e)
			}
		}
		if len(ev.Unknown) != 1 || ev.Unknown[0].Kind != KindUnusedService || ev.Unknown[0].DetailKey != "" {
			t.Fatalf("unknown %+v", ev.Unknown)
		}
	})
	t.Run("not workload-bound and unread: no activity_not_read", func(t *testing.T) {
		r := roleFixture(t, first)
		r.Activity, r.Consumers = nil, nil
		ev := mustEval(t, snapshotFixture(t, first, r))
		if len(findingsOf(ev, KindActivityNotRead)) != 0 {
			t.Fatal("activity_not_read is for workload-bound roles (§2.5)")
		}
	})
	t.Run("grant added 20 days ago to an old role: window starts at the grant", func(t *testing.T) {
		r := roleFixture(t, first)
		r.Statements[0].To = tp(daysAgo(20))
		r.Statements = append(r.Statements, StatementRevision{PolicyKey: "P1", StatementKey: "P1#0", Hash: "sha256:s2",
			Statement: stmt(t, `{"Effect":"Allow","Action":["s3:*","sns:*","logs:*"],"Resource":"*"}`), From: daysAgo(20)})
		r.Statements = append(r.Statements, StatementRevision{PolicyKey: "P1", StatementKey: "P1#1", Hash: "sha256:s3",
			Statement: stmt(t, `{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}`), From: daysAgo(20)})
		// sqs moved to a new statement 20 days ago, but statement P1#0 granted
		// it until then: P1#0's path ends exactly where P1#1's begins, so S was
		// continuously granted since before observation.
		ev := mustEval(t, snapshotFixture(t, first, r))
		if f := findingsOf(ev, KindUnusedService)["sqs"]; f.Confidence != ConfidenceAgeUnverified {
			t.Fatalf("continuous grant must stay open-start: %+v", f)
		}
		// Now a genuine new grant: sqs was not granted at all before.
		r2 := roleFixture(t, first)
		r2.Statements[0].Statement = stmt(t, `{"Effect":"Allow","Action":["s3:*","sns:*","logs:*"],"Resource":"*"}`)
		r2.Statements = append(r2.Statements, StatementRevision{PolicyKey: "P1", StatementKey: "P1#1", Hash: "sha256:s3",
			Statement: stmt(t, `{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}`), From: daysAgo(20)})
		ev = mustEval(t, snapshotFixture(t, first, r2))
		if _, ok := findingsOf(ev, KindUnusedService)["sqs"]; ok {
			t.Fatal("a 20-day-old grant has not enough history")
		}
		for _, a := range ev.Assessments {
			if a.Qualification.Service == "sqs" {
				if !a.Qualification.WindowStart.Equal(daysAgo(20)) || a.Qualification.GrantAgeBasis != GrantAgeObservedSinceChange {
					t.Fatalf("window must start at the grant: %+v", a.Qualification)
				}
			}
		}
		for _, e := range ev.Evidence {
			if e.Service == "sqs" && (e.GrantObservedSince == nil || !e.GrantObservedSince.Equal(daysAgo(20))) {
				t.Fatalf("grant_observed_since %+v", e)
			}
		}
	})
}

// A30: policy attached 120 days ago, its dynamodb statement added 10 days
// ago, no other path → grant_from 10 days ago, no unused_service.
func TestEvaluate_A30_GrantAgeByPath(t *testing.T) {
	first := daysAgo(200)
	r := roleFixture(t, first)
	r.Assignments = []PolicyAssignment{{PolicyKey: "P2", PolicyARN: "arn:aws:iam::" + acct + ":policy/Data", Kind: AssignAttached,
		Intervals: []TimeRange{{From: daysAgo(120)}}}}
	r.Statements = []StatementRevision{
		{PolicyKey: "P2", StatementKey: "P2#0", Hash: "h0", Statement: stmt(t, `{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}`), From: daysAgo(120)},
		{PolicyKey: "P2", StatementKey: "P2#1", Hash: "h1", Statement: stmt(t, `{"Effect":"Allow","Action":"dynamodb:*","Resource":"*"}`), From: daysAgo(10)},
	}
	r.Activity.Services = []ServiceActivity{{Service: "dynamodb"}, {Service: "s3"}}
	ev := mustEval(t, snapshotFixture(t, first, r))
	unused := findingsOf(ev, KindUnusedService)
	if _, ok := unused["dynamodb"]; ok {
		t.Fatal("dynamodb was granted 10 days ago: window < 30 days")
	}
	if f, ok := unused["s3"]; !ok || f.Confidence != ConfidenceQualified || detailOf(t, f)["qualified_days"].(float64) != 90 {
		t.Fatalf("s3 (attached 120 days ago, observed) %+v", f)
	}
	for _, e := range ev.Evidence {
		if e.Service == "dynamodb" && (e.GrantAgeBasis != GrantAgeObservedSinceChange || !e.GrantObservedSince.Equal(daysAgo(10))) {
			t.Fatalf("dynamodb grant_from %+v", e)
		}
	}
}

// A47: two accounts in one workspace. A publishes rev 1, B publishes rev 2.
// Rev 2's results for A's roles cite A's run from the manifest, B's roles
// B's run; no gap or absence claim is invented for either.
func TestEvaluate_A47_TwoAccounts(t *testing.T) {
	first := daysAgo(200)
	ra := roleFixture(t, first)
	rb := roleFixture(t, first)
	rb.RoleID, rb.IdentityAccountID, rb.ARN, rb.Name = "AROAEXAMPLEBBBBBB01", "d41d2f3a-1b2c-4d5e-8f90-a1b2c3d4e5f6", "arn:aws:iam::"+acctB+":role/B", "B"
	rb.AccountID, rb.ConnectorID, rb.PartitionKey = acctB, connB, "pB"
	rb.Activity = &ActivityReport{ScanRunID: runB2, State: EvidenceCollected, GeneratedAt: now.Add(-time.Hour),
		Services: []ServiceActivity{{Service: "sqs"}}}
	s := snapshotFixture(t, first, ra, rb)
	s.Rev = 2
	s.Manifest["pB"] = runB2
	s.Runs[runB2] = RunEvidence{RunID: runB2, ConnectorID: connB, AccountID: acctB, ConnectorFirstPublishedAt: first,
		EnabledRegions: regions, ResourcePolicy: &ResourcePolicyEvidence{Coverage: completeCoverage()}}
	ev := mustEval(t, s)
	for _, e := range ev.Evidence {
		want := runA1
		if e.RoleID == rb.RoleID {
			want = runB2
		}
		if e.ScanRunID != want || e.State != EvidenceCollected || (e.Service != "logs" && e.RouteUsage != RouteUsageNoneObserved) {
			t.Fatalf("evidence cites the wrong run or invents a gap: %+v", e)
		}
	}
	for _, f := range ev.Findings {
		if f.Family != FamilyCloudAccess {
			continue
		}
		want := runA1
		if f.RoleID == rb.RoleID {
			want = runB2
		}
		if f.EvidenceScanRunID != want {
			t.Fatalf("%s for %s cites %s", f.Kind, f.RoleID, f.EvidenceScanRunID)
		}
	}
	// A's rescan (run A3) is in a later manifest; a role whose cloud_usage
	// rows already belong to A3 while the manifest still names A1 is
	// not_collected (§2.5 generation check), never judged on the wrong run.
	ra2 := roleFixture(t, first)
	ra2.Activity.ScanRunID = runA3
	ev = mustEval(t, snapshotFixture(t, first, ra2))
	if len(findingsOf(ev, KindUnusedService)) != 0 || detailOf(t, findingsOf(ev, KindActivityNotRead)[""])["reason"] != "report_run_mismatch" {
		t.Fatalf("generation mismatch: %+v", ev.Findings)
	}
	// A partition absent from the manifest: not_collected, no evidence run.
	ra3 := roleFixture(t, first)
	ra3.PartitionKey = "pZ"
	ev = mustEval(t, snapshotFixture(t, first, ra3))
	f := findingsOf(ev, KindActivityNotRead)[""]
	if detailOf(t, f)["reason"] != "partition_not_in_manifest" || f.EvidenceScanRunID != "" {
		t.Fatalf("absent partition: %+v", f)
	}
	for _, e := range ev.Evidence {
		if e.ScanRunID != "" || e.State != EvidenceNotCollected {
			t.Fatalf("absent partition evidence %+v", e)
		}
	}
	// A run with no resource-policy coverage: confirm_required, never
	// none_observed.
	s = snapshotFixture(t, first, roleFixture(t, first))
	run := s.Runs[runA1]
	run.ResourcePolicy = nil
	s.Runs[runA1] = run
	ev = mustEval(t, s)
	for _, e := range ev.Evidence {
		if e.RouteUsage != RouteUsageConfirmRequired {
			t.Fatalf("no coverage must not conclude none_observed: %+v", e)
		}
	}
}

// A52: sqs:* in PolicyA and sqs:SendMessage in PolicyB. The finding lists
// both grants, and PolicyB's independent open-start path keeps the grant
// age unverified even though PolicyA's statement is new.
func TestEvaluate_A52_IndependentGrant(t *testing.T) {
	first := daysAgo(200)
	r := roleFixture(t, first)
	r.Assignments = []PolicyAssignment{
		{PolicyKey: "PA", PolicyARN: "arn:aws:iam::" + acct + ":policy/PolicyA", Kind: AssignAttached, Intervals: []TimeRange{{From: first}}},
		{PolicyKey: "PB", PolicyARN: "arn:aws:iam::" + acct + ":policy/PolicyB", Kind: AssignAttached, Intervals: []TimeRange{{From: first}}},
		{PolicyKey: "BND", PolicyARN: "arn:aws:iam::" + acct + ":policy/Boundary", Kind: AssignBoundary, Intervals: []TimeRange{{From: first}}},
	}
	r.Statements = []StatementRevision{
		{PolicyKey: "PA", StatementKey: "PA#0", Hash: "ha", Statement: stmt(t, `{"Effect":"Allow","Action":"sqs:*","Resource":"*"}`), From: daysAgo(10)},
		{PolicyKey: "PB", StatementKey: "PB#0", Hash: "hb", Statement: stmt(t, `{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-east-1:`+acct+`:q"}`), From: first},
		{PolicyKey: "BND", StatementKey: "BND#0", Hash: "hx", Statement: stmt(t, `{"Effect":"Allow","Action":"*","Resource":"*"}`), From: first},
	}
	r.Activity.Services = []ServiceActivity{{Service: "sqs"}}
	ev := mustEval(t, snapshotFixture(t, first, r))
	f, ok := findingsOf(ev, KindUnusedService)["sqs"]
	if !ok || f.Confidence != ConfidenceAgeUnverified {
		t.Fatalf("sqs finding %+v", f)
	}
	grants := detailOf(t, f)["grants"].([]any)
	if len(grants) != 2 || grants[0].(map[string]any)["policy_key"] != "PA" || grants[1].(map[string]any)["policy_key"] != "PB" {
		t.Fatalf("both independent grants must be listed: %v", grants)
	}
	// The boundary grants nothing: its Action "*" is not a broad grant.
	if b := findingsOf(ev, KindBroadGrant); len(b) != 1 || b["PA#0"].Fingerprint == "" {
		t.Fatalf("broad grants %v", b)
	}
}

func TestEvaluate_GovernanceKinds(t *testing.T) {
	first := daysAgo(200)
	t.Run("shared_role counts distinct workloads", func(t *testing.T) {
		r := roleFixture(t, first)
		r.Consumers = append(r.Consumers, Consumer{WorkloadID: wl1, Relationship: RelTaskExecutionRole})
		if len(findingsOf(mustEval(t, snapshotFixture(t, first, r)), KindSharedRole)) != 0 {
			t.Fatal("one workload with two relationships is not shared")
		}
		r.Consumers = append(r.Consumers, Consumer{WorkloadID: wl2, Relationship: RelExecutesAs}, Consumer{WorkloadID: "w3", Relationship: "member_of"})
		f := findingsOf(mustEval(t, snapshotFixture(t, first, r)), KindSharedRole)[""]
		if detailOf(t, f)["workload_count"].(float64) != 2 {
			t.Fatalf("shared %s", f.Detail)
		}
	})
	t.Run("missing_owner", func(t *testing.T) {
		r := roleFixture(t, first)
		r.UnmatchedOwnerTags = []string{"team=payments"}
		s := snapshotFixture(t, first, r)
		s.Owners = []OwnerRecord{{ID: "o2", ObjectKind: OwnerObjectIdentity, IdentityAccountID: idRef, UserID: "u2", Role: OwnerTechnical}}
		f, ok := findingsOf(mustEval(t, s), KindMissingOwner)[""]
		if !ok || f.Family != FamilyGovernance || !strings.Contains(string(f.Detail), "team=payments") {
			t.Fatalf("a technical owner is not accountable: %+v", f)
		}
		s.Owners = append(s.Owners, OwnerRecord{ID: "o3", ObjectKind: OwnerObjectIdentity, IdentityAccountID: idRef, UserID: "u3",
			Role: OwnerAccountable, ReviewDueAt: tp(now)})
		if len(findingsOf(mustEval(t, s), KindMissingOwner)) != 0 {
			t.Fatal("role's own accountable owner")
		}
		r.Consumers = nil
		s = snapshotFixture(t, first, r)
		s.Owners = nil
		if len(findingsOf(mustEval(t, s), KindMissingOwner)) != 0 {
			t.Fatal("missing_owner is for workload-bound roles")
		}
	})
	t.Run("missing_review_date", func(t *testing.T) {
		s := snapshotFixture(t, first, roleFixture(t, first))
		s.Owners[0].ReviewDueAt = nil
		s.Rules = []FindingRule{{ID: "r1", Kind: RuleRequireReviewDate, Enabled: true, Scope: RuleScope{RuntimeKinds: []string{"lambda_function"}}}}
		f, ok := findingsOf(mustEval(t, s), KindMissingReviewDate)[""]
		if !ok || f.Severity != SeverityLow || !strings.Contains(string(f.Detail), `"o1"`) {
			t.Fatalf("missing_review_date %+v", f)
		}
		s.Rules[0].Scope = RuleScope{RuntimeKinds: []string{"ec2_instance"}}
		if len(findingsOf(mustEval(t, s), KindMissingReviewDate)) != 0 {
			t.Fatal("rule scope does not match")
		}
		s.Rules[0].Scope, s.Rules[0].Enabled = RuleScope{}, false
		if len(findingsOf(mustEval(t, s), KindMissingReviewDate)) != 0 {
			t.Fatal("disabled rule")
		}
		s.Rules[0].Enabled = true
		s.Owners[0].ReviewDueAt = tp(now)
		if len(findingsOf(mustEval(t, s), KindMissingReviewDate)) != 0 {
			t.Fatal("review date set")
		}
	})
	t.Run("unused_window rule widens the window", func(t *testing.T) {
		s := snapshotFixture(t, first, roleFixture(t, first))
		s.Rules = []FindingRule{{ID: "r2", Kind: RuleUnusedWindow, Enabled: true, WindowDays: 150},
			{ID: "r3", Kind: RuleUnusedWindow, Enabled: true, WindowDays: 120}}
		f := findingsOf(mustEval(t, s), KindUnusedService)["sqs"]
		if d := detailOf(t, f); d["qualified_days"].(float64) != 150 || d["requested_window_days"].(float64) != 150 {
			t.Fatalf("window %s", f.Detail)
		}
	})
}

func TestEvaluate_BroadGrant(t *testing.T) {
	first := daysAgo(200)
	cases := []struct {
		js       string
		severity string
		reasons  string
	}{
		{`{"Effect":"Allow","Action":"*","Resource":"*"}`, SeverityHigh, "escalation,full_wildcard"},
		{`{"Effect":"Allow","Action":"s3:*","Resource":"*"}`, SeverityMedium, "service_wildcard"},
		{`{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::b/*"}`, "", ""},
		{`{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}`, SeverityHigh, "escalation"},
		{`{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}`, SeverityHigh, "escalation,not_action_on_all_resources"},
		{`{"Effect":"Deny","Action":"*","Resource":"*"}`, "", ""},
	}
	for _, c := range cases {
		r := roleFixture(t, first)
		r.Statements[0].Statement = stmt(t, c.js)
		f, ok := findingsOf(mustEval(t, snapshotFixture(t, first, r)), KindBroadGrant)["P1#0"]
		if c.severity == "" {
			if ok {
				t.Errorf("%s: unexpected broad grant", c.js)
			}
			continue
		}
		var reasons []string
		for _, x := range detailOf(t, f)["reasons"].([]any) {
			reasons = append(reasons, x.(string))
		}
		if !ok || f.Severity != c.severity || strings.Join(reasons, ",") != c.reasons {
			t.Errorf("%s: %+v %v", c.js, f.Severity, reasons)
		}
	}
	// A statement no longer live (revision ended) or a detached policy is
	// not a live grant.
	r := roleFixture(t, first)
	r.Statements[0].To = tp(daysAgo(1))
	if len(findingsOf(mustEval(t, snapshotFixture(t, first, r)), KindBroadGrant)) != 0 {
		t.Fatal("ended revision")
	}
	r = roleFixture(t, first)
	r.Assignments[0].Intervals[0].To = tp(daysAgo(1))
	if len(findingsOf(mustEval(t, snapshotFixture(t, first, r)), KindBroadGrant)) != 0 {
		t.Fatal("detached policy")
	}
}

// Stable keys: a later revision with the same facts, or a new revision of
// the same statement, keeps the same fingerprints; output is deterministic
// whatever the input order.
func TestEvaluate_StableAndDeterministic(t *testing.T) {
	first := daysAgo(200)
	s1 := snapshotFixture(t, first, roleFixture(t, first))
	ev1 := mustEval(t, s1)
	r := roleFixture(t, first)
	r.Statements[0].To = tp(daysAgo(5))
	r.Statements = append(r.Statements, StatementRevision{PolicyKey: "P1", StatementKey: "P1#0", Hash: "sha256:s1b",
		Statement: stmt(t, `{"Effect":"Allow","Action":["s3:*","sqs:*","sns:*","logs:*","kms:Decrypt"],"Resource":"*"}`), From: daysAgo(5)})
	s2 := snapshotFixture(t, first, r)
	s2.Rev = 2
	ev2 := mustEval(t, s2)
	fps := func(ev Evaluation) string {
		var out []string
		for _, f := range ev.Findings {
			out = append(out, f.Kind+":"+f.Fingerprint)
		}
		return strings.Join(out, ",")
	}
	if fps(ev1) != fps(ev2) {
		t.Fatalf("fingerprints moved across revisions:\n%s\n%s", fps(ev1), fps(ev2))
	}

	// Shuffle every input list: identical output.
	rng := rand.New(rand.NewSource(7))
	other := roleFixture(t, first)
	other.RoleID, other.IdentityAccountID, other.ARN, other.Name = "AROAEXAMPLEOTHER001", "e41d2f3a-1b2c-4d5e-8f90-a1b2c3d4e5f6", "arn:aws:iam::"+acct+":role/O", "O"
	other.Consumers = []Consumer{{WorkloadID: wl1, Relationship: RelExecutesAs}, {WorkloadID: wl2, Relationship: RelExecutesAs}}
	base := snapshotFixture(t, first, roleFixture(t, first), other)
	want := mustEval(t, base)
	for i := 0; i < 20; i++ {
		s := base
		s.Roles = append([]RoleSnapshot{}, base.Roles...)
		rng.Shuffle(len(s.Roles), func(a, b int) { s.Roles[a], s.Roles[b] = s.Roles[b], s.Roles[a] })
		for j := range s.Roles {
			svc := append([]ServiceActivity{}, s.Roles[j].Activity.Services...)
			rng.Shuffle(len(svc), func(a, b int) { svc[a], svc[b] = svc[b], svc[a] })
			act := *s.Roles[j].Activity
			act.Services = svc
			s.Roles[j].Activity = &act
			cons := append([]Consumer{}, s.Roles[j].Consumers...)
			rng.Shuffle(len(cons), func(a, b int) { cons[a], cons[b] = cons[b], cons[a] })
			s.Roles[j].Consumers = cons
		}
		if got := mustEval(t, s); !reflect.DeepEqual(got, want) {
			t.Fatal("output depends on input order")
		}
	}
}

func TestEvaluate_SkipsAndValidation(t *testing.T) {
	first := daysAgo(200)
	r := roleFixture(t, first)
	r.Path = "/aws-service-role/ecs.amazonaws.com/"
	ev := mustEval(t, snapshotFixture(t, first, r))
	if len(ev.Findings) != 0 || len(ev.Skipped) != 1 || len(ev.PresentRoles) != 1 {
		t.Fatalf("service-linked role %+v", ev)
	}
	bad := snapshotFixture(t, first, roleFixture(t, first), roleFixture(t, first))
	if _, err := Evaluate(bad); err == nil {
		t.Fatal("duplicate role accepted")
	}
	bad = snapshotFixture(t, first, roleFixture(t, first))
	bad.EvaluatedAt = time.Time{}
	if _, err := Evaluate(bad); err == nil {
		t.Fatal("missing evaluation time accepted")
	}
	bad = snapshotFixture(t, time.Time{}, roleFixture(t, first))
	if _, err := Evaluate(bad); err == nil {
		t.Fatal("run without its first publication time accepted")
	}
}

/* ---------------------- A21 and the finding lifecycle --------------------- */

func TestPlanFindingUpdates_A21_NoOlderOverwrite(t *testing.T) {
	first := daysAgo(200)
	ev := mustEval(t, snapshotFixture(t, first, roleFixture(t, first)))
	ev.Rev = 4
	sqs := findingsOf(ev, KindUnusedService)["sqs"]
	stored := []StoredFinding{{Fingerprint: sqs.Fingerprint, Kind: KindUnusedService, RoleID: roleID, DetailKey: "sqs",
		Status: StatusOpen, LastEvaluatedRev: 5}}
	for _, u := range PlanFindingUpdates(ev, stored, nil) {
		if u.Fingerprint == sqs.Fingerprint {
			t.Fatalf("rev 4 must not touch a finding evaluated at rev 5: %+v", u)
		}
	}
	stored[0].LastEvaluatedRev = 4
	for _, u := range PlanFindingUpdates(ev, stored, nil) {
		if u.Fingerprint == sqs.Fingerprint {
			t.Fatal("a replay of the same revision changes nothing")
		}
	}
	stored[0].LastEvaluatedRev = 3
	found := false
	for _, u := range PlanFindingUpdates(ev, stored, nil) {
		if u.Fingerprint == sqs.Fingerprint {
			found = true
			if u.Insert || u.LastEvaluatedRev != 4 || !u.HasResult || u.StatusChanged {
				t.Fatalf("%+v", u)
			}
		}
	}
	if !found {
		t.Fatal("rev 4 must update a finding evaluated at rev 3")
	}
}

func TestPlanFindingUpdates_Lifecycle(t *testing.T) {
	first := daysAgo(200)
	ev := mustEval(t, snapshotFixture(t, first, roleFixture(t, first)))
	ev.Rev = 10
	sqsFP := findingsOf(ev, KindUnusedService)["sqs"].Fingerprint
	goneFP, _ := Fingerprint(KindUnusedService, roleID, "ec2")
	otherFP, _ := Fingerprint(KindSharedRole, "AROAGONE00000000", "")
	soon, past := tp(now.Add(time.Hour)), tp(now.Add(-time.Hour))
	cases := []struct {
		name    string
		stored  StoredFinding
		posture map[PostureKey]string
		want    string
		skip    bool
		result  bool
	}{
		{"holds, open stays open", StoredFinding{Fingerprint: sqsFP, Kind: KindUnusedService, RoleID: roleID, DetailKey: "sqs", Status: StatusOpen}, nil, StatusOpen, false, true},
		{"holds again after cleared → reopened", StoredFinding{Fingerprint: sqsFP, Kind: KindUnusedService, RoleID: roleID, DetailKey: "sqs", Status: StatusCleared}, nil, StatusReopened, false, true},
		{"exception still valid", StoredFinding{Fingerprint: sqsFP, Kind: KindUnusedService, RoleID: roleID, DetailKey: "sqs", Status: StatusExcepted, ExceptedUntil: soon}, nil, StatusExcepted, false, true},
		{"exception lapsed → open", StoredFinding{Fingerprint: sqsFP, Kind: KindUnusedService, RoleID: roleID, DetailKey: "sqs", Status: StatusExcepted, ExceptedUntil: past}, nil, StatusOpen, false, true},
		{"under review stays", StoredFinding{Fingerprint: sqsFP, Kind: KindUnusedService, RoleID: roleID, DetailKey: "sqs", Status: StatusUnderReview}, nil, StatusUnderReview, false, true},
		{"posture removed → resolved", StoredFinding{Fingerprint: sqsFP, Kind: KindUnusedService, RoleID: roleID, DetailKey: "sqs", Status: StatusUnderReview},
			map[PostureKey]string{{roleID, "sqs"}: OutcomeRemoved}, StatusResolved, false, true},
		{"posture routes remain → mitigated", StoredFinding{Fingerprint: sqsFP, Kind: KindUnusedService, RoleID: roleID, DetailKey: "sqs", Status: StatusResolved},
			map[PostureKey]string{{roleID, "sqs"}: OutcomeExcludedRoutesRemain}, StatusMitigated, false, true},
		{"posture not_removed (drift/undo) → reopened", StoredFinding{Fingerprint: sqsFP, Kind: KindUnusedService, RoleID: roleID, DetailKey: "sqs", Status: StatusResolved},
			map[PostureKey]string{{roleID, "sqs"}: OutcomeNotRemoved}, StatusReopened, false, true},
		{"posture pending leaves it", StoredFinding{Fingerprint: sqsFP, Kind: KindUnusedService, RoleID: roleID, DetailKey: "sqs", Status: StatusUnderReview},
			map[PostureKey]string{{roleID, "sqs"}: OutcomePending}, StatusUnderReview, false, true},
		{"condition false → cleared", StoredFinding{Fingerprint: goneFP, Kind: KindUnusedService, RoleID: roleID, DetailKey: "ec2", Status: StatusOpen}, nil, StatusCleared, false, false},
		{"condition false while under review stays", StoredFinding{Fingerprint: goneFP, Kind: KindUnusedService, RoleID: roleID, DetailKey: "ec2", Status: StatusUnderReview}, nil, StatusUnderReview, false, false},
		{"role gone → superseded", StoredFinding{Fingerprint: otherFP, Kind: KindSharedRole, RoleID: "AROAGONE00000000", Status: StatusOpen}, nil, StatusSuperseded, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got *FindingUpdate
			for _, u := range PlanFindingUpdates(ev, []StoredFinding{c.stored}, c.posture) {
				if u.Fingerprint == c.stored.Fingerprint {
					u := u
					got = &u
				}
			}
			if got == nil {
				t.Fatal("no update planned")
			}
			if got.Status != c.want || got.HasResult != c.result || got.LastEvaluatedRev != 10 {
				t.Fatalf("%+v", *got)
			}
			if got.ClearException != (c.stored.Status == StatusExcepted && c.want != StatusExcepted) {
				t.Fatal("excepted_until must be cleared exactly when leaving excepted (048 exception_chk)")
			}
		})
	}

	// Indeterminate at N: a role whose report was not read keeps its
	// unused_service findings exactly as they are.
	r := roleFixture(t, first)
	r.Activity = nil
	ev2 := mustEval(t, snapshotFixture(t, first, r))
	ev2.Rev = 10
	stored := StoredFinding{Fingerprint: sqsFP, Kind: KindUnusedService, RoleID: roleID, DetailKey: "sqs", Status: StatusOpen, LastEvaluatedRev: 9}
	for _, u := range PlanFindingUpdates(ev2, []StoredFinding{stored}, nil) {
		if u.Fingerprint == sqsFP {
			t.Fatalf("unread activity must not clear an unused_service finding: %+v", u)
		}
	}
	// New findings are inserted open with first_seen_rev = N, in
	// fingerprint order.
	ups := PlanFindingUpdates(ev, nil, nil)
	if len(ups) != len(ev.Findings) {
		t.Fatalf("inserts %d", len(ups))
	}
	for i, u := range ups {
		if !u.Insert || u.Status != StatusOpen || u.FirstSeenRev != 10 || (i > 0 && ups[i-1].Fingerprint >= u.Fingerprint) {
			t.Fatalf("%+v", u)
		}
	}
}

func TestParseFindingRule(t *testing.T) {
	r, err := ParseFindingRule("r", RuleUnusedWindow, true, []byte(`{"stages":["production"]}`), []byte(`{"window_days":120}`))
	if err != nil || r.WindowDays != 120 || r.Scope.Stages[0] != "production" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := ParseFindingRule("r", RuleUnusedWindow, true, nil, []byte(`{"window_days":20}`)); err == nil {
		t.Fatal("window below 30 accepted")
	}
	if _, err := ParseFindingRule("r", "other", true, nil, nil); err == nil {
		t.Fatal("unknown kind accepted")
	}
	if _, err := ParseFindingRule("r", RuleRequireReviewDate, true, []byte(`[`), nil); err == nil {
		t.Fatal("bad scope accepted")
	}
}
