package igagov

import (
	"sort"
	"time"
)

// §2.6 constants.
const (
	// ReportingLag: AWS says recent activity usually appears within 4 hours.
	ReportingLag = 4 * time.Hour
	// MinQualifiedDays: below this no unused_service is raised; the role
	// shows "Not enough history (N days)".
	MinQualifiedDays = 30
	// DefaultWindowDays, MinWindowDays, MaxWindowDays mirror
	// iga_gov_settings.default_window_days (055: DEFAULT 90, 30..400).
	DefaultWindowDays = 90
	MinWindowDays     = 30
	MaxWindowDays     = 400
)

// Qualification outcomes for one role × service (§2.6).
const (
	// QualObserved: an attempt was reported inside the window; retain with
	// basis "observed".
	QualObserved = "observed"
	// QualNoAttempt: no attempt reported in a window of at least
	// MinQualifiedDays; an unused_service condition.
	QualNoAttempt = "no_attempt"
	// QualNotEnoughHistory: no attempt, but the window is shorter than
	// MinQualifiedDays.
	QualNotEnoughHistory = "not_enough_history"
	// QualUnreviewed: the grant path cannot be reconstructed or the service
	// is not tracked; kept, never removed.
	QualUnreviewed = "unreviewed"
)

// Interval is one span during which a grant-path component held (DECISION
// D18: To is exclusive and touching intervals merge, so consecutive
// revisions form one interval). To is
// exclusive; nil means it still holds. OpenStart marks a component that
// already existed when AuthSec first looked (its interval begins at the
// connector's first published scan), so its true start is unknown (§2.6).
type Interval struct {
	From      time.Time  `json:"from"`
	To        *time.Time `json:"to"`
	OpenStart bool       `json:"open_start"`
}

func (iv Interval) contains(t time.Time) bool {
	return !t.Before(iv.From) && (iv.To == nil || t.Before(*iv.To))
}

// GrantPath is one way service S reaches role R (§2.6): the assignment of a
// policy to R and a revision run of a statement in that policy granting S.
// Each component is the set of intervals during which it held; the path
// holds only while every component holds.
type GrantPath struct {
	// Key names the path (policy and statement key) for explanations.
	Key        string       `json:"key"`
	Components [][]Interval `json:"components"`
}

func minEnd(a, b *time.Time) *time.Time {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	case a.Before(*b):
		return a
	}
	return b
}

// intersect two intervals: the later start, the earlier end; open-start only
// if both are (otherwise it starts at the latest start AuthSec observed).
func intersect(a, b Interval) (Interval, bool) {
	out := Interval{From: a.From, OpenStart: a.OpenStart && b.OpenStart}
	if b.From.After(out.From) {
		out.From = b.From
	}
	out.To = minEnd(a.To, b.To)
	if out.To != nil && !out.From.Before(*out.To) {
		return Interval{}, false
	}
	return out, true
}

// PathIntervals is §2.6's path interval: the intersection of the path's
// components (each a union of intervals). A path with no components holds
// nowhere.
func PathIntervals(p GrantPath) []Interval {
	if len(p.Components) == 0 {
		return nil
	}
	acc := normalizeIntervals(p.Components[0])
	for _, comp := range p.Components[1:] {
		var next []Interval
		for _, a := range acc {
			for _, b := range normalizeIntervals(comp) {
				if iv, ok := intersect(a, b); ok {
					next = append(next, iv)
				}
			}
		}
		acc = normalizeIntervals(next)
	}
	return acc
}

// normalizeIntervals sorts and merges overlapping or touching intervals.
// A merged interval keeps the start (and open-start flag) of its earliest
// member: if S was continuously held since an open-start, the run is
// open-start whatever later paths began inside it (§2.6).
func normalizeIntervals(in []Interval) []Interval {
	if len(in) == 0 {
		return nil
	}
	ivs := append([]Interval{}, in...)
	sort.SliceStable(ivs, func(i, j int) bool {
		if !ivs[i].From.Equal(ivs[j].From) {
			return ivs[i].From.Before(ivs[j].From)
		}
		return ivs[i].OpenStart && !ivs[j].OpenStart
	})
	out := []Interval{ivs[0]}
	for _, iv := range ivs[1:] {
		last := &out[len(out)-1]
		if last.To == nil || !iv.From.After(*last.To) {
			if last.To != nil && (iv.To == nil || iv.To.After(*last.To)) {
				last.To = iv.To
			}
			if iv.From.Equal(last.From) && iv.OpenStart {
				last.OpenStart = true
			}
			continue
		}
		out = append(out, iv)
	}
	return out
}

// GrantedIntervals is §2.6's "granted": the union of every path interval.
func GrantedIntervals(paths []GrantPath) []Interval {
	var all []Interval
	for _, p := range paths {
		all = append(all, PathIntervals(p)...)
	}
	return normalizeIntervals(all)
}

// CurrentGrant is §2.6's "current": the interval of granted that contains
// the evaluation time. ok=false when S is not granted at that time.
func CurrentGrant(paths []GrantPath, at time.Time) (Interval, bool) {
	for _, iv := range GrantedIntervals(paths) {
		if iv.contains(at) {
			return iv, true
		}
	}
	return Interval{}, false
}

// VerifiedGrantFrom is §2.6's verified_grant_from: null (with basis
// predates_observation) when the current interval is open-start, its start
// (observed_since_change) otherwise. ok=false when no path holds at `at`:
// the grant cannot be reconstructed and S is unreviewed (DECISION D8).
func VerifiedGrantFrom(paths []GrantPath, at time.Time) (from *time.Time, basis string, ok bool) {
	cur, ok := CurrentGrant(paths, at)
	if !ok {
		return nil, GrantAgeUnknown, false
	}
	if cur.OpenStart {
		return nil, GrantAgePredatesObservation, true
	}
	f := cur.From
	return &f, GrantAgeObservedSinceChange, true
}

// QualifyInput is everything §2.6 needs for one role R and service S.
type QualifyInput struct {
	Service string
	// ReportGeneratedAt is G, the report's JobCompletionDate (generated_at).
	ReportGeneratedAt time.Time
	// LastAuthenticatedAt is the report's last authenticated attempt; nil is
	// "no attempt reported", never "never used".
	LastAuthenticatedAt *time.Time
	// RoleCreatedAt is cloud_identity.created_at (IAM CreateDate).
	RoleCreatedAt time.Time
	// TrackingFrom is catalog.tracking_start(S, region set); nil when S is
	// not tracked (TrackingReason says why).
	TrackingFrom   *time.Time
	TrackingReason string
	// RequestedWindowDays is the window asked for (30..400; 0 = default 90).
	RequestedWindowDays int
	// Paths are S's grant paths to R.
	Paths []GrantPath
	// At is the evaluation time (the revision's publication time).
	At time.Time
}

// Qualification is §2.6's result for one role × service: the activity
// coverage, the grant continuity, the window and the outcome.
type Qualification struct {
	Service             string     `json:"service"`
	Outcome             string     `json:"outcome"`
	Reason              string     `json:"reason,omitempty"`
	ReportGeneratedAt   time.Time  `json:"report_generated_at"`
	LastAuthenticatedAt *time.Time `json:"last_authenticated_at"`
	CoveredUntil        time.Time  `json:"covered_until"`
	CoverageStart       time.Time  `json:"coverage_start"`
	RoleFrom            time.Time  `json:"role_from"`
	TrackingFrom        *time.Time `json:"tracking_from"`
	RequestedWindowDays int        `json:"requested_window_days"`
	VerifiedGrantFrom   *time.Time `json:"verified_grant_from"`
	GrantAgeBasis       string     `json:"grant_age_basis"`
	WindowStart         time.Time  `json:"window_start"`
	QualifiedDays       int        `json:"qualified_days"`
	Confidence          string     `json:"confidence"`
}

// ClampWindowDays applies the 055 bounds (30..400) and the default (90).
func ClampWindowDays(d int) int {
	switch {
	case d == 0:
		return DefaultWindowDays
	case d < MinWindowDays:
		return MinWindowDays
	case d > MaxWindowDays:
		return MaxWindowDays
	}
	return d
}

func maxTime(ts ...time.Time) time.Time {
	m := ts[0]
	for _, t := range ts[1:] {
		if t.After(m) {
			m = t
		}
	}
	return m
}

// wholeDays floors a duration to whole days; negative spans are 0.
func wholeDays(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int(d / (24 * time.Hour))
}

// Qualify computes §2.6 for one role × service:
//
//	covered_until  = G − reporting_lag
//	coverage_start = max(covered_until − window, role_from, tracking_from)
//	window_start   = verified_grant_from ? max(coverage_start, it) : coverage_start
//	qualified_days = covered_until − window_start
//
// Outcome: unreviewed when the service is untracked or no grant path holds at
// the evaluation time; observed when an attempt falls inside the window;
// not_enough_history when qualified_days < 30; otherwise no_attempt.
// Confidence is qualified for an observed grant start, age_unverified when
// the grant predates observation (§2.5).
func Qualify(in QualifyInput) Qualification {
	q := Qualification{
		Service:             in.Service,
		ReportGeneratedAt:   in.ReportGeneratedAt,
		LastAuthenticatedAt: in.LastAuthenticatedAt,
		RoleFrom:            in.RoleCreatedAt,
		TrackingFrom:        in.TrackingFrom,
		RequestedWindowDays: ClampWindowDays(in.RequestedWindowDays),
		Confidence:          ConfidenceNotApplicable,
	}
	q.CoveredUntil = in.ReportGeneratedAt.Add(-ReportingLag)
	windowFloor := q.CoveredUntil.Add(-time.Duration(q.RequestedWindowDays) * 24 * time.Hour)
	if in.TrackingFrom != nil {
		q.CoverageStart = maxTime(windowFloor, in.RoleCreatedAt, *in.TrackingFrom)
	} else {
		q.CoverageStart = maxTime(windowFloor, in.RoleCreatedAt)
	}

	from, basis, ok := VerifiedGrantFrom(in.Paths, in.At)
	q.GrantAgeBasis = basis
	q.VerifiedGrantFrom = from
	q.WindowStart = q.CoverageStart
	if from != nil && from.After(q.WindowStart) {
		q.WindowStart = *from
	}
	q.QualifiedDays = wholeDays(q.CoveredUntil.Sub(q.WindowStart))

	switch {
	case !ok:
		q.Outcome, q.Reason = QualUnreviewed, "grant_path_not_reconstructable"
		return q
	case in.TrackingFrom == nil:
		q.Outcome, q.Reason = QualUnreviewed, in.TrackingReason
		if q.Reason == "" {
			q.Reason = "service_not_in_tracking_catalog"
		}
		return q
	}
	if basis == GrantAgeObservedSinceChange {
		q.Confidence = ConfidenceQualified
	} else {
		q.Confidence = ConfidenceAgeUnverified
	}
	switch {
	case in.LastAuthenticatedAt != nil && !in.LastAuthenticatedAt.Before(q.WindowStart):
		q.Outcome = QualObserved
		q.Confidence = ConfidenceNotApplicable
	case q.QualifiedDays < MinQualifiedDays:
		q.Outcome = QualNotEnoughHistory
		q.Confidence = ConfidenceNotApplicable
	default:
		q.Outcome = QualNoAttempt
	}
	return q
}
