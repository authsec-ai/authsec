package services

import (
	"math"
	"sort"
	"time"
)

/* azure_cadence.go describes WHEN an identity signs in, not just how often --
   the PRD's "machine cadence" agent signal. A person signs in in bursts during
   their working day; a workload signs in on a schedule (a token lasts about an
   hour, so a service running continuously renews on a near-fixed interval) and
   at any hour.

   Computed from the sign-in times the aggregation already reads, per identity
   per resource, and stored on the usage row: never the raw times. Hours are UTC
   because the customer's time zone is not known; "around the clock" does not
   depend on which zone the day is counted in. */

const (
	// azureCadenceMinSignIns is the fewest sign-ins a pattern is read from;
	// below it the cadence is "insufficient", never a guess.
	azureCadenceMinSignIns = 5
	// azureCadenceRegularCV is the most the gaps between sign-ins may vary
	// (coefficient of variation: spread / average) and still be a schedule.
	azureCadenceRegularCV = 0.5
	// azureCadenceAroundTheClockHours is how many distinct hours of the day a
	// sign-in must fall in to call it around the clock.
	azureCadenceAroundTheClockHours = 12
)

// Cadence patterns.
const (
	CadenceRegular      = "regular"
	CadenceIrregular    = "irregular"
	CadenceInsufficient = "insufficient"
)

// azureCadence is the timing of one identity's sign-ins to one resource.
type azureCadence struct {
	Pattern string `json:"pattern"`
	// HoursActive is how many distinct UTC hours of the day it signed in in;
	// AroundTheClock is HoursActive >= 12.
	HoursActive    int  `json:"hours_active"`
	AroundTheClock bool `json:"around_the_clock"`
	DaysActive     int  `json:"days_active"`
	// MedianGapSeconds is the typical time between two sign-ins; GapVariation
	// how much the gaps differ (0 = clockwork).
	MedianGapSeconds int     `json:"median_gap_seconds,omitempty"`
	GapVariation     float64 `json:"gap_variation,omitempty"`
	// HourHistogram counts sign-ins per UTC hour of the day.
	HourHistogram [24]int `json:"hour_histogram"`
}

// cadenceOf reads the pattern out of a set of successful sign-in times.
func cadenceOf(times []time.Time) azureCadence {
	c := azureCadence{Pattern: CadenceInsufficient}
	days := map[string]bool{}
	for _, t := range times {
		u := t.UTC()
		c.HourHistogram[u.Hour()]++
		days[u.Format("2006-01-02")] = true
	}
	for _, n := range c.HourHistogram {
		if n > 0 {
			c.HoursActive++
		}
	}
	c.DaysActive = len(days)
	c.AroundTheClock = c.HoursActive >= azureCadenceAroundTheClockHours
	if len(times) < azureCadenceMinSignIns {
		return c
	}

	sorted := append([]time.Time(nil), times...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Before(sorted[j]) })
	gaps := make([]float64, 0, len(sorted)-1)
	for i := 1; i < len(sorted); i++ {
		if g := sorted[i].Sub(sorted[i-1]).Seconds(); g > 0 {
			gaps = append(gaps, g)
		}
	}
	if len(gaps) < azureCadenceMinSignIns-1 {
		return c
	}
	sort.Float64s(gaps)
	c.MedianGapSeconds = int(gaps[len(gaps)/2])
	mean := 0.0
	for _, g := range gaps {
		mean += g
	}
	mean /= float64(len(gaps))
	variance := 0.0
	for _, g := range gaps {
		variance += (g - mean) * (g - mean)
	}
	cv := math.Sqrt(variance/float64(len(gaps))) / mean
	c.GapVariation = math.Round(cv*100) / 100
	if cv <= azureCadenceRegularCV {
		c.Pattern = CadenceRegular
	} else {
		c.Pattern = CadenceIrregular
	}
	return c
}

// machineLike reports whether a cadence looks like a workload rather than a
// person: on a schedule, or active around the clock.
func (c azureCadence) machineLike() bool {
	return c.Pattern == CadenceRegular || c.AroundTheClock
}
