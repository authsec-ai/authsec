package services

import (
	"math"
	"sort"
	"strconv"
	"time"
)

// Metric math of the SOC, posture and CISO reports (W9), kept free of the
// database so it is unit-tested with plain values.

// Metric statuses.
const (
	MetricAvailable   = "available"
	MetricUnavailable = "unavailable"
)

// MetricDefinition is what a metric means. Version changes whenever the
// computation changes (a new source column, a different rule), so a value is
// only ever compared with a previous value of the same version.
type MetricDefinition struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
	Text    string `json:"text"`
}

// MetricCoverage is the share of the estate or data the metric could see.
// Share is nil when it is not known; Basis says what was counted.
type MetricCoverage struct {
	Share *float64 `json:"share"`
	Basis string   `json:"basis"`
	Note  string   `json:"note,omitempty"`
}

// MetricWindow is a half-open period [From, To).
type MetricWindow struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// MetricResult is one metric value with its definition, coverage and the
// previous period under the same definition.
type MetricResult struct {
	ID         string             `json:"id"`
	Label      string             `json:"label"`
	Unit       string             `json:"unit"`
	Status     string             `json:"status"`
	Reason     string             `json:"reason,omitempty"`
	Value      *float64           `json:"value"`
	Median     *float64           `json:"median,omitempty"`
	P90        *float64           `json:"p90,omitempty"`
	N          *int               `json:"n,omitempty"`
	Breakdown  map[string]float64 `json:"breakdown,omitempty"`
	Definition MetricDefinition   `json:"definition"`
	Coverage   MetricCoverage     `json:"coverage"`
	Window     *MetricWindow      `json:"window,omitempty"`
	AsOf       *time.Time         `json:"as_of,omitempty"`
	// Source is "live" (computed now) or "snapshot" (read from history).
	Source       string        `json:"source,omitempty"`
	SnapshotDate string        `json:"snapshot_date,omitempty"`
	Previous     *MetricResult `json:"previous,omitempty"`
}

func fptr(v float64) *float64 { return &v }
func iptr(v int) *int         { return &v }

// percentile is the p-th percentile (0..1) of sorted values by linear
// interpolation between closest ranks (the median of an even count is the
// mean of the middle two). NaN for no values.
func percentile(sorted []float64, p float64) float64 {
	n := len(sorted)
	if n == 0 {
		return math.NaN()
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 1 {
		return sorted[n-1]
	}
	pos := p * float64(n-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return sorted[lo]
	}
	frac := pos - float64(lo)
	return sorted[lo] + (sorted[hi]-sorted[lo])*frac
}

// durationStats fills Median, P90, N and Value (= median) from durations in
// seconds; negative durations (clock skew) count as zero.
func durationStats(m *MetricResult, secs []float64) {
	vals := make([]float64, 0, len(secs))
	for _, s := range secs {
		if math.IsNaN(s) {
			continue
		}
		if s < 0 {
			s = 0
		}
		vals = append(vals, s)
	}
	sort.Float64s(vals)
	m.N = iptr(len(vals))
	if len(vals) == 0 {
		return
	}
	med := round2(percentile(vals, 0.5))
	p90 := round2(percentile(vals, 0.9))
	m.Median, m.P90, m.Value = fptr(med), fptr(p90), fptr(med)
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

// Unproven-stop age buckets.
const (
	ageUnder1h = "under_1h"
	age1hTo24h = "1h_to_24h"
	age1dTo7d  = "1d_to_7d"
	ageOver7d  = "over_7d"
)

func unprovenBucket(age time.Duration) string {
	switch {
	case age < time.Hour:
		return ageUnder1h
	case age < 24*time.Hour:
		return age1hTo24h
	case age < 7*24*time.Hour:
		return age1dTo7d
	default:
		return ageOver7d
	}
}

// bucketAges counts ages (seconds) by unproven-stop bucket; every bucket is
// present, zero or not.
func bucketAges(secs []float64) map[string]float64 {
	out := map[string]float64{ageUnder1h: 0, age1hTo24h: 0, age1dTo7d: 0, ageOver7d: 0}
	for _, s := range secs {
		if s < 0 {
			s = 0
		}
		out[unprovenBucket(time.Duration(s*float64(time.Second)))]++
	}
	return out
}

// share is part/whole, nil when whole is zero.
func share(part, whole int64) *float64 {
	if whole <= 0 {
		return nil
	}
	return fptr(round4(float64(part) / float64(whole)))
}

func round4(v float64) float64 { return math.Round(v*10000) / 10000 }

// withPrevious attaches prev as cur's previous period. A previous value under
// another definition version is not comparable: it is replaced by an
// unavailable entry saying so.
func withPrevious(cur MetricResult, prev *MetricResult) MetricResult {
	if prev == nil {
		return cur
	}
	p := *prev
	p.Previous = nil
	if p.Status == MetricAvailable && p.Definition.Version != cur.Definition.Version {
		p = MetricResult{ID: p.ID, Label: p.Label, Unit: p.Unit, Status: MetricUnavailable,
			Reason:     "definition_changed: the previous period was measured under definition version " + itoa(p.Definition.Version),
			Definition: p.Definition, Coverage: p.Coverage, Window: p.Window, AsOf: p.AsOf, Source: p.Source, SnapshotDate: p.SnapshotDate}
	}
	cur.Previous = &p
	return cur
}

func itoa(n int) string { return strconv.Itoa(n) }

// metricUnavailable builds an unavailable metric.
func metricUnavailable(id, label, unit string, def MetricDefinition, reason string) MetricResult {
	return MetricResult{ID: id, Label: label, Unit: unit, Status: MetricUnavailable, Reason: reason, Definition: def,
		Coverage: MetricCoverage{Basis: "none", Note: "The metric's source is not recorded in this build."}}
}

// periodWindow is [to - d, to).
func periodWindow(to time.Time, d time.Duration) MetricWindow {
	return MetricWindow{From: to.Add(-d), To: to}
}

// parsePeriod maps 7d | 30d | 90d to a duration.
func parsePeriod(p string) (time.Duration, bool) {
	switch p {
	case "", "30d":
		return 30 * 24 * time.Hour, true
	case "7d":
		return 7 * 24 * time.Hour, true
	case "90d":
		return 90 * 24 * time.Hour, true
	}
	return 0, false
}

// monthWindow is the calendar month (UTC) of "YYYY-MM" and the one before.
func monthWindow(month string) (cur, prev MetricWindow, ok bool) {
	t, err := time.Parse("2006-01", month)
	if err != nil {
		return MetricWindow{}, MetricWindow{}, false
	}
	start := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	cur = MetricWindow{From: start, To: start.AddDate(0, 1, 0)}
	prev = MetricWindow{From: start.AddDate(0, -1, 0), To: start}
	return cur, prev, true
}

// socVariants is which optional sources the SOC metrics can read. Each
// combination is its own definition version, so a period is only compared
// with a previous period measured the same way.
type socVariants struct {
	alert        bool // agent_alert (150)
	containment  bool // agent_containment (151)
	ackCol       bool // agent_alert.acknowledged_at (F8)
	resolvedCol  bool // agent_alert.resolved_at (F8)
	caseAssign   bool // agent_case_alert(alert_id, case_id) + agent_case.assigned_at (W3)
	proofState   bool // agent_containment.proof_state (W2)
	caseOutcome  bool // agent_case.outcome + closed_at (W3)
	alertOutcome bool // agent_alert.outcome + resolved_at (F8)
	activity     bool // agent_activity_event (155)
}

func probeSOC(p SchemaProbe) socVariants {
	return socVariants{
		alert:        p.Has("agent_alert", "created_at", "identity_id", "state", "state_changed_at", "workload_ids"),
		containment:  p.Has("agent_containment", "identity_id", "level", "state", "created_at", "contained_at", "workload_ids", "effective"),
		ackCol:       p.Has("agent_alert", "acknowledged_at"),
		resolvedCol:  p.Has("agent_alert", "resolved_at"),
		caseAssign:   p.Has("agent_case_alert", "alert_id", "case_id") && p.Has("agent_case", "id", "assigned_at"),
		proofState:   p.Has("agent_containment", "proof_state"),
		caseOutcome:  p.Has("agent_case", "outcome", "closed_at"),
		alertOutcome: p.Has("agent_alert", "outcome", "resolved_at"),
		activity:     p.Has("agent_activity_event", "identity_id", "action", "outcome", "occurred_at"),
	}
}

// SOC metric ids.
const (
	SOCTimeToFirstAction   = "soc.time_to_first_action"
	SOCTimeToContain       = "soc.time_to_contain"
	SOCUnprovenStops       = "soc.unproven_stops"
	SOCTimeToResolve       = "soc.time_to_resolve"
	SOCOutcomeMix          = "soc.outcome_mix"
	SOCSuccessAfterRefusal = "soc.success_after_refusal"
)

// socDefinition is the definition of a SOC metric under the variants.
func socDefinition(id string, v socVariants) MetricDefinition {
	switch id {
	case SOCTimeToFirstAction:
		ver := 1
		text := "Seconds from an alert's creation to the first action on it: "
		if v.ackCol {
			ver++
			text += "acknowledged (acknowledged_at), "
		} else {
			text += "acknowledged (the alert's state time while acknowledged), "
		}
		if v.resolvedCol {
			text += "resolved (resolved_at), "
		} else {
			text += "resolved (state time once resolved; an acknowledgement before it is not kept, so the value is an upper bound), "
		}
		if v.caseAssign {
			ver += 2
			text += "assigned through its case, "
		}
		text += "or a stop started on its identity. Alerts created in the period; median and 90th percentile; alerts with no action yet are counted apart."
		return MetricDefinition{ID: id, Version: ver, Text: text}
	case SOCTimeToContain:
		return MetricDefinition{ID: id, Version: 1, Text: "Seconds from an alert's creation to the first stop that was applied at a level covering the alert's principal " +
			"(identity or key level on its identity, or workload level covering every workload the alert names; a model-level stop does not count) " +
			"and started after the alert. Alerts created in the period; median and 90th percentile; alerts contained only at a non-covering level and alerts not contained are counted apart."}
	case SOCUnprovenStops:
		if v.proofState {
			return MetricDefinition{ID: id, Version: 2, Text: "Stops started in the period that are live and whose proof state is applied, unproven or cannot_verify, by age since applied (under 1 h, 1-24 h, 1-7 d, over 7 d)."}
		}
		return MetricDefinition{ID: id, Version: 1, Text: "Stops started in the period that are live (contained or partially contained) and not shown effective by evidence received after them, by age since applied (under 1 h, 1-24 h, 1-7 d, over 7 d)."}
	case SOCTimeToResolve:
		if v.resolvedCol {
			return MetricDefinition{ID: id, Version: 2, Text: "Seconds from an alert's creation to its resolution (resolved_at). Alerts created in the period; median and 90th percentile; unresolved alerts counted apart."}
		}
		return MetricDefinition{ID: id, Version: 1, Text: "Seconds from an alert's creation to its resolution (the alert's state time once resolved). Alerts created in the period; median and 90th percentile; unresolved alerts counted apart."}
	case SOCOutcomeMix:
		if v.caseOutcome {
			return MetricDefinition{ID: id, Version: 1, Text: "Cases closed in the period by outcome code (true_positive, benign, false_positive, duplicate)."}
		}
		if v.alertOutcome {
			return MetricDefinition{ID: id, Version: 2, Text: "Alerts resolved in the period by outcome code (true_positive, benign, false_positive, duplicate)."}
		}
		return MetricDefinition{ID: id, Version: 0, Text: "Closed cases (or resolved alerts) in the period by outcome code."}
	case SOCSuccessAfterRefusal:
		return MetricDefinition{ID: id, Version: 1, Text: "Distinct (identity, action) pairs in the period where an action was denied and the same identity then performed the same action successfully within one hour (agent activity timeline)."}
	}
	return MetricDefinition{ID: id}
}

// socLabels names the SOC metrics and their units.
var socLabels = map[string][2]string{
	SOCTimeToFirstAction:   {"Time to first action", "seconds"},
	SOCTimeToContain:       {"Time to contain (covering level)", "seconds"},
	SOCUnprovenStops:       {"Unproven stops", "count"},
	SOCTimeToResolve:       {"Time to resolve", "seconds"},
	SOCOutcomeMix:          {"Outcome mix", "count"},
	SOCSuccessAfterRefusal: {"Success after refusal", "count"},
}

// SOCMetricIDs is the order the SOC report lists its metrics in.
var SOCMetricIDs = []string{SOCTimeToFirstAction, SOCTimeToContain, SOCUnprovenStops, SOCTimeToResolve, SOCOutcomeMix, SOCSuccessAfterRefusal}

// socUnavailableReason is why a SOC metric cannot be computed under v, or "".
func socUnavailableReason(id string, v socVariants) string {
	switch id {
	case SOCTimeToFirstAction, SOCTimeToResolve:
		if !v.alert {
			return "source_missing: agent_alert is not in this database"
		}
	case SOCTimeToContain:
		if !v.alert || !v.containment {
			return "source_missing: agent_alert or agent_containment is not in this database"
		}
	case SOCUnprovenStops:
		if !v.containment {
			return "source_missing: agent_containment is not in this database"
		}
	case SOCOutcomeMix:
		if !v.caseOutcome && !v.alertOutcome {
			return "source_missing: outcome codes are recorded by cases (agent_case.outcome, W3) or the alert lifecycle (agent_alert.outcome, F8), neither of which is in this database; resolution reasons are free text"
		}
	case SOCSuccessAfterRefusal:
		if !v.activity {
			return "source_missing: agent_activity_event is not in this database"
		}
	}
	return ""
}
