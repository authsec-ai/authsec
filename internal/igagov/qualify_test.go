package igagov

import (
	"testing"
	"time"
)

var now = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func daysAgo(d float64) time.Time { return now.Add(-time.Duration(d * 24 * float64(time.Hour))) }
func tp(t time.Time) *time.Time   { return &t }

func open(from time.Time) Interval     { return Interval{From: from, OpenStart: true} }
func observed(from time.Time) Interval { return Interval{From: from} }
func ended(iv Interval, to time.Time) Interval {
	iv.To = &to
	return iv
}
func path(key string, comps ...[]Interval) GrantPath { return GrantPath{Key: key, Components: comps} }
func one(iv ...Interval) []Interval                  { return iv }

func trackedFrom() *time.Time { return tp(time.Date(2015, 10, 1, 0, 0, 0, 0, time.UTC)) }

func TestQualify_Scenarios(t *testing.T) {
	firstScan := daysAgo(0.1) // the connector's first scan: everything open-start
	gen := now.Add(-time.Hour)
	cases := []struct {
		name        string
		in          QualifyInput
		outcome     string
		days        int
		basis       string
		confidence  string
		windowStart *time.Time
	}{
		{
			name: "A2 role created 10 days ago: not enough history, no 90-day claim",
			in: QualifyInput{Service: "sqs", ReportGeneratedAt: gen, RoleCreatedAt: daysAgo(10), TrackingFrom: trackedFrom(),
				Paths: []GrantPath{path("p#s", one(open(firstScan)), one(open(firstScan)))}, At: now},
			outcome: QualNotEnoughHistory, days: 9, basis: GrantAgePredatesObservation, confidence: ConfidenceNotApplicable,
		},
		{
			name: "A2/A36 null last attempt, old role, first scan: day-one finding, age unverified",
			in: QualifyInput{Service: "sqs", ReportGeneratedAt: gen, RoleCreatedAt: daysAgo(400), TrackingFrom: trackedFrom(),
				Paths: []GrantPath{path("p#s", one(open(firstScan)), one(open(firstScan)))}, At: now},
			outcome: QualNoAttempt, days: 90, basis: GrantAgePredatesObservation, confidence: ConfidenceAgeUnverified,
		},
		{
			name: "A36 requested window 112 days on a 200-day-old role",
			in: QualifyInput{Service: "sqs", ReportGeneratedAt: gen, RoleCreatedAt: daysAgo(200), TrackingFrom: trackedFrom(),
				RequestedWindowDays: 112, Paths: []GrantPath{path("p#s", one(open(firstScan)), one(open(firstScan)))}, At: now},
			outcome: QualNoAttempt, days: 112, basis: GrantAgePredatesObservation, confidence: ConfidenceAgeUnverified,
		},
		{
			name: "A2 grant added 20 days ago to an old role: window starts at the grant",
			in: QualifyInput{Service: "sqs", ReportGeneratedAt: gen, RoleCreatedAt: daysAgo(400), TrackingFrom: trackedFrom(),
				Paths: []GrantPath{path("p#s", one(open(daysAgo(200))), one(observed(daysAgo(20))))}, At: now},
			outcome: QualNotEnoughHistory, days: 19, basis: GrantAgeObservedSinceChange, confidence: ConfidenceNotApplicable,
			windowStart: tp(daysAgo(20)),
		},
		{
			name: "grant added 45 days ago: qualified finding bounded by the grant",
			in: QualifyInput{Service: "sqs", ReportGeneratedAt: gen, RoleCreatedAt: daysAgo(400), TrackingFrom: trackedFrom(),
				Paths: []GrantPath{path("p#s", one(open(daysAgo(200))), one(observed(daysAgo(45))))}, At: now},
			outcome: QualNoAttempt, days: 44, basis: GrantAgeObservedSinceChange, confidence: ConfidenceQualified,
			windowStart: tp(daysAgo(45)),
		},
		{
			name: "A30 policy attached 120 days ago (observed), dynamodb statement added 10 days ago",
			in: QualifyInput{Service: "dynamodb", ReportGeneratedAt: gen, RoleCreatedAt: daysAgo(400), TrackingFrom: trackedFrom(),
				Paths: []GrantPath{path("p#s", one(observed(daysAgo(120))), one(observed(daysAgo(10))))}, At: now},
			outcome: QualNotEnoughHistory, days: 9, basis: GrantAgeObservedSinceChange, confidence: ConfidenceNotApplicable,
			windowStart: tp(daysAgo(10)),
		},
		{
			name: "A30 variant: attachment predates observation, statement observed 10 days ago",
			in: QualifyInput{Service: "dynamodb", ReportGeneratedAt: gen, RoleCreatedAt: daysAgo(400), TrackingFrom: trackedFrom(),
				Paths: []GrantPath{path("p#s", one(open(daysAgo(300))), one(observed(daysAgo(10))))}, At: now},
			outcome: QualNotEnoughHistory, days: 9, basis: GrantAgeObservedSinceChange, confidence: ConfidenceNotApplicable,
			windowStart: tp(daysAgo(10)),
		},
		{
			name: "an independent open-start path keeps the grant open-start (§2.6, A52)",
			in: QualifyInput{Service: "sqs", ReportGeneratedAt: gen, RoleCreatedAt: daysAgo(400), TrackingFrom: trackedFrom(),
				Paths: []GrantPath{
					path("A#s", one(open(daysAgo(300))), one(observed(daysAgo(10)))),
					path("B#s", one(open(daysAgo(300))), one(open(daysAgo(300)))),
				}, At: now},
			outcome: QualNoAttempt, days: 90, basis: GrantAgePredatesObservation, confidence: ConfidenceAgeUnverified,
		},
		{
			name: "a gap in every path after observation began starts a new verified interval",
			in: QualifyInput{Service: "sqs", ReportGeneratedAt: gen, RoleCreatedAt: daysAgo(400), TrackingFrom: trackedFrom(),
				Paths: []GrantPath{
					path("A#s", one(open(daysAgo(300))), one(ended(open(daysAgo(300)), daysAgo(50)))),
					path("B#s", one(observed(daysAgo(40))), one(observed(daysAgo(40)))),
				}, At: now},
			outcome: QualNoAttempt, days: 39, basis: GrantAgeObservedSinceChange, confidence: ConfidenceQualified,
			windowStart: tp(daysAgo(40)),
		},
		{
			name: "consecutive revisions that all grant S form one interval",
			in: QualifyInput{Service: "sqs", ReportGeneratedAt: gen, RoleCreatedAt: daysAgo(400), TrackingFrom: trackedFrom(),
				Paths: []GrantPath{path("A#s", one(open(daysAgo(300))),
					one(ended(open(daysAgo(300)), daysAgo(60)), observed(daysAgo(60))))}, At: now},
			outcome: QualNoAttempt, days: 90, basis: GrantAgePredatesObservation, confidence: ConfidenceAgeUnverified,
		},
		{
			name: "attempt inside the window: observed",
			in: QualifyInput{Service: "s3", ReportGeneratedAt: gen, LastAuthenticatedAt: tp(daysAgo(3)), RoleCreatedAt: daysAgo(400),
				TrackingFrom: trackedFrom(), Paths: []GrantPath{path("p#s", one(open(firstScan)), one(open(firstScan)))}, At: now},
			outcome: QualObserved, days: 90, basis: GrantAgePredatesObservation, confidence: ConfidenceNotApplicable,
		},
		{
			name: "attempt before the window: no attempt in the qualified interval",
			in: QualifyInput{Service: "s3", ReportGeneratedAt: gen, LastAuthenticatedAt: tp(daysAgo(120)), RoleCreatedAt: daysAgo(400),
				TrackingFrom: trackedFrom(), Paths: []GrantPath{path("p#s", one(open(firstScan)), one(open(firstScan)))}, At: now},
			outcome: QualNoAttempt, days: 90, basis: GrantAgePredatesObservation, confidence: ConfidenceAgeUnverified,
		},
		{
			name: "service not tracked: unreviewed",
			in: QualifyInput{Service: "glue", ReportGeneratedAt: gen, RoleCreatedAt: daysAgo(400), TrackingReason: "service_not_in_tracking_catalog",
				Paths: []GrantPath{path("p#s", one(open(firstScan)), one(open(firstScan)))}, At: now},
			outcome: QualUnreviewed, days: 90, basis: GrantAgePredatesObservation, confidence: ConfidenceNotApplicable,
		},
		{
			name: "no grant path holds now: unreviewed",
			in: QualifyInput{Service: "glue", ReportGeneratedAt: gen, RoleCreatedAt: daysAgo(400), TrackingFrom: trackedFrom(),
				Paths: []GrantPath{path("p#s", one(ended(open(daysAgo(300)), daysAgo(5))), one(open(daysAgo(300))))}, At: now},
			outcome: QualUnreviewed, days: 90, basis: GrantAgeUnknown, confidence: ConfidenceNotApplicable,
		},
		{
			name: "tracking start limits coverage",
			in: QualifyInput{Service: "sqs", ReportGeneratedAt: gen, RoleCreatedAt: daysAgo(400), TrackingFrom: tp(daysAgo(35)),
				Paths: []GrantPath{path("p#s", one(open(firstScan)), one(open(firstScan)))}, At: now},
			outcome: QualNoAttempt, days: 34, basis: GrantAgePredatesObservation, confidence: ConfidenceAgeUnverified,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q := Qualify(c.in)
			if q.Outcome != c.outcome || q.QualifiedDays != c.days || q.GrantAgeBasis != c.basis || q.Confidence != c.confidence {
				t.Fatalf("got outcome=%s days=%d basis=%s conf=%s (reason %q)", q.Outcome, q.QualifiedDays, q.GrantAgeBasis, q.Confidence, q.Reason)
			}
			if c.windowStart != nil && !q.WindowStart.Equal(*c.windowStart) {
				t.Fatalf("window start %v, want %v", q.WindowStart, *c.windowStart)
			}
			if !q.CoveredUntil.Equal(c.in.ReportGeneratedAt.Add(-4 * time.Hour)) {
				t.Fatalf("covered_until must be G − 4 h")
			}
			if c.outcome == QualNoAttempt && q.QualifiedDays < MinQualifiedDays {
				t.Fatal("a no_attempt outcome below 30 days")
			}
		})
	}
}

// The 30-day threshold, exactly at the edge.
func TestQualify_ThirtyDayEdge(t *testing.T) {
	gen := now
	for _, c := range []struct {
		grantAge time.Duration
		want     string
		days     int
	}{
		{30*24*time.Hour + ReportingLag, QualNoAttempt, 30},
		{30*24*time.Hour + ReportingLag - time.Second, QualNotEnoughHistory, 29},
	} {
		q := Qualify(QualifyInput{Service: "sqs", ReportGeneratedAt: gen, RoleCreatedAt: daysAgo(400), TrackingFrom: trackedFrom(),
			Paths: []GrantPath{path("p#s", one(open(daysAgo(300))), one(observed(gen.Add(-c.grantAge))))}, At: now})
		if q.Outcome != c.want || q.QualifiedDays != c.days {
			t.Errorf("grant age %v: %s/%d, want %s/%d", c.grantAge, q.Outcome, q.QualifiedDays, c.want, c.days)
		}
	}
}

func TestPathIntervals(t *testing.T) {
	// Intersection: the later start; open-start only if both are.
	p := path("x", one(open(daysAgo(100))), one(observed(daysAgo(10))))
	iv := PathIntervals(p)
	if len(iv) != 1 || iv[0].OpenStart || !iv[0].From.Equal(daysAgo(10)) {
		t.Fatalf("intersection %+v", iv)
	}
	p = path("x", one(open(daysAgo(100))), one(open(daysAgo(100))))
	if iv = PathIntervals(p); !iv[0].OpenStart {
		t.Fatal("both open-start → open-start")
	}
	// Disjoint components → no interval.
	p = path("x", one(ended(observed(daysAgo(100)), daysAgo(50))), one(observed(daysAgo(40))))
	if iv = PathIntervals(p); len(iv) != 0 {
		t.Fatalf("disjoint %+v", iv)
	}
	// A detach and re-attach splits the path.
	p = path("x", one(ended(open(daysAgo(100)), daysAgo(50)), observed(daysAgo(20))), one(open(daysAgo(100))))
	iv = PathIntervals(p)
	if len(iv) != 2 || !iv[0].OpenStart || iv[1].OpenStart || !iv[1].From.Equal(daysAgo(20)) {
		t.Fatalf("re-attach %+v", iv)
	}
	from, basis, ok := VerifiedGrantFrom([]GrantPath{p}, now)
	if !ok || basis != GrantAgeObservedSinceChange || !from.Equal(daysAgo(20)) {
		t.Fatalf("re-attach verified %v %s %v", from, basis, ok)
	}
	if _, _, ok := VerifiedGrantFrom(nil, now); ok {
		t.Fatal("no paths must be unreconstructable")
	}
}

func TestClampWindowDays(t *testing.T) {
	for in, want := range map[int]int{0: 90, 10: 30, 30: 30, 112: 112, 400: 400, 401: 400} {
		if got := ClampWindowDays(in); got != want {
			t.Errorf("ClampWindowDays(%d) = %d", in, got)
		}
	}
}
