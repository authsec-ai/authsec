package igagov

import (
	"strings"
	"testing"
	"time"
)

var appliedAt = time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)

func at(h float64) time.Time { return appliedAt.Add(time.Duration(h * float64(time.Hour))) }

func ev(h float64, session, source, name, code, denial string) TrailEvent {
	return TrailEvent{EventTime: at(h), PrincipalID: roleID, SessionName: session, EventSource: source, EventName: name,
		ErrorCode: code, DenialPolicyType: denial}
}

// canaryBase: 48 h canary, s3 retained and active, sqs removed, full trail
// coverage, a publication after apply, the artifact verified.
func canaryBase(nowH float64) CanaryInput {
	return CanaryInput{RoleID: roleID, AppliedAt: appliedAt, Now: at(nowH), CanaryHours: 48, RemovesServices: true,
		Removed:             []string{"sqs"},
		Retained:            []RetainedService{{Service: "s3", ActiveInQualifiedInterval: true}},
		Trail:               []TrailRead{{From: at(-48), To: at(20)}, {From: at(10), To: at(60)}},
		PublishedAfterApply: true, ArtifactOutcome: OutcomePassed,
		Events: []TrailEvent{ev(5, "refund-fn", "s3.amazonaws.com", "ListBuckets", "", "")}}
}

func gate(r CanaryResult, name string) GateResult {
	for _, g := range r.Gates {
		if g.Gate == name {
			return g
		}
	}
	return GateResult{}
}

func TestCanary_AllPass(t *testing.T) {
	r := EvaluateCanary(canaryBase(50))
	if !r.Pass || r.Pause || len(r.NotAvailable) != 0 || r.ApplicationHealth.Outcome != OutcomePassed {
		t.Fatalf("%+v", r)
	}
	if r.Restriction.Outcome != OutcomeAwaitingEvidence || r.ServiceRestriction["sqs"] != RestrictionNotObserved {
		t.Fatalf("absence of a denial is never failure nor proof: %+v", r.Restriction)
	}
}

// A6: a denial on a retained service pauses the rollout.
func TestCanary_DeniedRetainedService_A6(t *testing.T) {
	in := canaryBase(50)
	in.Events = append(in.Events, ev(30, "refund-fn", "s3.amazonaws.com", "GetObject", "AccessDenied", "identity_policy"))
	r := EvaluateCanary(in)
	g := gate(r, GateNoUnexpectedFailures)
	if g.Outcome != OutcomeFailed || g.Reason != DeniedRetainedService || !r.Pause || r.ApplicationHealth.Outcome != OutcomeFailed {
		t.Fatalf("%+v", r)
	}
}

// A24: the workload calls a removed service it was not expected to use:
// the gate fails and the rollout pauses; the restriction dimension still
// reports the boundary-attributed denial beside it (D42), never folded in.
func TestCanary_UnexpectedRemovedServiceDenial_A24(t *testing.T) {
	in := canaryBase(50)
	in.Events = append(in.Events, ev(30, "refund-fn", "sqs.amazonaws.com", "SendMessage", "AccessDenied", DenialPermissionsBoundary))
	r := EvaluateCanary(in)
	if g := gate(r, GateNoUnexpectedFailures); g.Outcome != OutcomeFailed || g.Reason != DeniedRemovedService || !r.Pause || r.Pass {
		t.Fatalf("A24 gate: %+v", g)
	}
	if r.Restriction.Outcome != OutcomePassed || r.Restriction.Attribution != AttributionBoundary || r.ServiceRestriction["sqs"] != RestrictionObserved {
		t.Fatalf("restriction: %+v", r.Restriction)
	}
	// A denial on a removed service with another cause is "cause not attributed".
	in = canaryBase(50)
	in.Events = append(in.Events, ev(30, "refund-fn", "sqs.amazonaws.com", "SendMessage", "AccessDenied", "scp"))
	if r := EvaluateCanary(in); r.Restriction.Attribution != AttributionCauseUnknown || r.Restriction.Outcome == OutcomePassed {
		t.Fatalf("cause unknown: %+v", r.Restriction)
	}
}

// A28: a declared test does not mask an outage.
func TestCanary_ValidationDoesNotMaskOutage_A28(t *testing.T) {
	val := Validation{ID: "v1", RoleID: roleID, SessionName: "authsec-validate-0123456789ab", WindowStart: at(1), WindowEnd: at(3),
		Items: []ValidationItem{{Action: "sqs:ListQueues", Expected: ExpectDenied}, {Action: "s3:ListBuckets", Expected: ExpectAllowed}}}
	in := canaryBase(50)
	in.Validations = []Validation{val}
	in.Events = append(in.Events,
		ev(2, val.SessionName, "sqs.amazonaws.com", "ListQueues", "AccessDenied", DenialPermissionsBoundary),
		ev(2.5, val.SessionName, "s3.amazonaws.com", "ListBuckets", "", ""))
	r := EvaluateCanary(in)
	if !r.Pass || r.Validations[0].Result != "matched" || r.Restriction.Attribution != AttributionValidation {
		t.Fatalf("the declared denial is exempt: %+v", r)
	}
	// (a) The Lambda (another session) makes the same call → unexpected.
	a := in
	a.Events = append(append([]TrailEvent{}, in.Events...), ev(2, "refund-fn", "sqs.amazonaws.com", "ListQueues", "AccessDenied", DenialPermissionsBoundary))
	if g := gate(EvaluateCanary(a), GateNoUnexpectedFailures); g.Outcome != OutcomeFailed {
		t.Fatalf("(a): %+v", g)
	}
	// (b) The test session is denied an undeclared action → unexpected.
	b := in
	b.Events = append(append([]TrailEvent{}, in.Events...), ev(2, val.SessionName, "s3.amazonaws.com", "ListAllMyBuckets", "AccessDenied", DenialPermissionsBoundary))
	if g := gate(EvaluateCanary(b), GateNoUnexpectedFailures); g.Outcome != OutcomeFailed {
		t.Fatalf("(b): %+v", g)
	}
	// (c) A recreated role with the same session name does not match the
	// item; its events are another incarnation's, not this role's traffic.
	c := in
	other := ev(2, val.SessionName, "sqs.amazonaws.com", "ListQueues", "", "")
	other.PrincipalID = "AROAEXAMPLERECREATED1"
	c.Events = append(append([]TrailEvent{}, in.Events...), other)
	rc := EvaluateCanary(c)
	if rc.Validations[0].Items[0].OppositeEvents != 0 || !rc.Pass {
		t.Fatalf("(c): %+v", rc.Validations)
	}
	// A contradicted allowed item fails required_operations; a contradicted
	// denied item is a restriction failure.
	d := in
	d.Events = []TrailEvent{ev(2, val.SessionName, "sqs.amazonaws.com", "ListQueues", "", ""),
		ev(2.5, val.SessionName, "s3.amazonaws.com", "ListBuckets", "AccessDenied", "identity_policy")}
	rd := EvaluateCanary(d)
	if g := gate(rd, GateRequiredOperations); g.Outcome != OutcomeFailed {
		t.Fatalf("contradicted allowed: %+v", g)
	}
	if rd.Restriction.Outcome != OutcomeFailed || rd.ServiceRestriction["sqs"] != RestrictionContradicted || rd.Validations[0].Result != "contradicted" {
		t.Fatalf("contradicted denied: %+v", rd.Restriction)
	}
}

// A18: no traffic — boundary verified elsewhere; health awaiting, gates
// not_available once the window has elapsed.
func TestCanary_NoTraffic_A18(t *testing.T) {
	in := canaryBase(20)
	in.Events = nil
	r := EvaluateCanary(in)
	if g := gate(r, GateRequiredOperations); g.Outcome != OutcomeAwaitingEvidence {
		t.Fatalf("open window: %+v", g)
	}
	if g := gate(r, GateWindowElapsed); g.Outcome != OutcomeAwaitingEvidence || r.ApplicationHealth.Outcome != OutcomeAwaitingEvidence {
		t.Fatalf("%+v", r)
	}
	in.Now = at(50)
	r = EvaluateCanary(in)
	if g := gate(r, GateRequiredOperations); g.Outcome != OutcomeNotAvailable || strings.Join(g.Evidence, ",") != "s3" {
		t.Fatalf("elapsed: %+v", g)
	}
	if r.Pass || r.Pause || strings.Join(r.NotAvailable, ",") != GateRequiredOperations || r.ApplicationHealth.Outcome != OutcomeNotAvailable {
		t.Fatalf("%+v", r)
	}
	// An owner "working" report is success evidence; a data-event-only
	// service is not satisfied by management events.
	in.Reports = []HealthReport{{Kind: ReportWorking, Service: "s3", CreatedAt: at(10)}}
	if g := gate(EvaluateCanary(in), GateRequiredOperations); g.Outcome != OutcomePassed {
		t.Fatalf("working report: %+v", g)
	}
	in = canaryBase(50)
	in.Retained[0].DataEventsOnly = true
	if g := gate(EvaluateCanary(in), GateRequiredOperations); g.Outcome != OutcomeNotAvailable {
		t.Fatalf("data events only: %+v", g)
	}
}

func TestCanary_ProblemReportAndWindow(t *testing.T) {
	in := canaryBase(50)
	in.Reports = []HealthReport{{Kind: ReportProblem, Service: "s3", CreatedAt: at(3)}}
	if r := EvaluateCanary(in); gate(r, GateNoProblemReports).Outcome != OutcomeFailed || !r.Pause {
		t.Fatalf("%+v", r)
	}
	// A hole in the CloudTrail coverage: the window cannot be evaluated.
	in = canaryBase(50)
	in.Trail = []TrailRead{{From: at(-48), To: at(10)}, {From: at(20), To: at(60)}}
	r := EvaluateCanary(in)
	if g := gate(r, GateWindowElapsed); g.Outcome != OutcomeNotAvailable || g.Reason != "cloudtrail_coverage_gap" {
		t.Fatalf("gap: %+v", g)
	}
	if g := gate(r, GateNoUnexpectedFailures); g.Outcome != OutcomeNotAvailable {
		t.Fatalf("no failures but incomplete coverage: %+v", g)
	}
	in.Trail = []TrailRead{{From: at(-48), To: at(60), CapHit: true}}
	if g := gate(EvaluateCanary(in), GateWindowElapsed); g.Reason != "cloudtrail_event_cap_hit" {
		t.Fatalf("cap: %+v", g)
	}
	// A seen denial still fails even with incomplete coverage.
	in.Events = append(in.Events, ev(30, "refund-fn", "s3.amazonaws.com", "GetObject", "AccessDenied", ""))
	if g := gate(EvaluateCanary(in), GateNoUnexpectedFailures); g.Outcome != OutcomeFailed {
		t.Fatalf("%+v", g)
	}
	// No publication after apply yet.
	in = canaryBase(50)
	in.PublishedAfterApply = false
	if g := gate(EvaluateCanary(in), GateWindowElapsed); g.Outcome != OutcomeAwaitingEvidence {
		t.Fatalf("%+v", g)
	}
	// Restriction does not apply to absent/split plans.
	in.RemovesServices = false
	if r := EvaluateCanary(in); r.Restriction.Outcome != OutcomeNotApplicable {
		t.Fatalf("%+v", r.Restriction)
	}
	// Events before applied_at and from other roles are ignored.
	in = canaryBase(50)
	old := ev(-2, "refund-fn", "s3.amazonaws.com", "GetObject", "AccessDenied", "")
	foreign := ev(5, "refund-fn", "s3.amazonaws.com", "GetObject", "AccessDenied", "")
	foreign.PrincipalID = roleBID
	in.Events = append(in.Events, old, foreign)
	if r := EvaluateCanary(in); !r.Pass {
		t.Fatalf("%+v", r.Gates)
	}
}

func TestActionForEvent(t *testing.T) {
	for src, want := range map[string]string{"sqs.amazonaws.com": "sqs:ListQueues", "monitoring.amazonaws.com": "cloudwatch:ListQueues",
		"s3.amazonaws.com": "s3:ListQueues"} {
		if got, ok := ActionForEvent(src, "ListQueues"); !ok || got != want {
			t.Errorf("%s: %s", src, got)
		}
	}
	if _, ok := ActionForEvent("example.com", "X"); ok {
		t.Fatal("not an AWS endpoint")
	}
}

// §8.6 observation: the fresh-report rule.
func TestObservation_FreshReport(t *testing.T) {
	until := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	evAt := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	fresh := until.Add(5 * time.Hour)
	stale := until.Add(3 * time.Hour)
	tg := func(rep *time.Time, attempts map[string]*time.Time) ObservationTarget {
		return ObservationTarget{RoleID: roleID, EvidenceReportAt: evAt, ReportGeneratedAt: rep, LastAttempts: attempts}
	}
	if r := EvaluateObservation(until, until.Add(time.Hour), []ObservationTarget{tg(&stale, nil)}); r.Complete || !r.NeedsRefresh ||
		!r.RequiredAfter.Equal(until.Add(4*time.Hour)) {
		t.Fatalf("elapsed time alone never ends observation: %+v", r)
	}
	if r := EvaluateObservation(until, until.Add(6*time.Hour), []ObservationTarget{tg(&fresh, nil)}); !r.Complete {
		t.Fatalf("%+v", r)
	}
	if r := EvaluateObservation(until, until.Add(-time.Hour), []ObservationTarget{tg(&fresh, nil)}); r.Complete || r.NeedsRefresh {
		t.Fatalf("before observe_until: %+v", r)
	}
	attempt := evAt.Add(48 * time.Hour)
	old := evAt.Add(-time.Hour)
	r := EvaluateObservation(until, until.Add(6*time.Hour), []ObservationTarget{tg(&fresh, map[string]*time.Time{"sqs": &attempt, "ec2": &old, "sns": nil})})
	if r.Complete || len(r.BackToDraft) != 1 || r.BackToDraft[0].Service != "sqs" {
		t.Fatalf("attempt during observation: %+v", r)
	}
}
