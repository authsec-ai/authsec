// Package precedence is the §13.4 resolution order.
//
// Quarantine or an explicit emergency deny wins. Then mandatory workspace
// guardrails, then target restrictions (runtime deny and enforcement plans),
// then an unexpired approved exception. A deny from any source is never
// replaced by an allow from another. The function is pure: callers load the
// facts and this package does not read agent_policies or enforcement_plans.
package precedence

import "time"

const (
	SourceQuarantine      = "quarantine"
	SourceEmergency       = "emergency"
	SourceGuardrail       = "guardrail"
	SourceRestriction     = "restriction"
	SourceEnforcementPlan = "enforcement_plan"
	SourceRuntimeDeny     = "runtime_deny"
	SourceException       = "exception"
	SourceRuntimeAllow    = "runtime_allow"
)

// Fact is one applicable decision. Expired facts are ignored.
type Fact struct {
	Source      string
	Effect      string
	Overridable bool
	Emergency   bool
	ExpiresAt   *time.Time
}

// Outcome is the single effect for a target.
type Outcome struct {
	Effect string
	Source string
	Reason string
}

// Resolve returns the winning effect. An empty input is default deny.
func Resolve(now time.Time, facts []Fact) Outcome {
	live := make([]Fact, 0, len(facts))
	for _, f := range facts {
		if f.ExpiresAt != nil && !f.ExpiresAt.After(now) {
			continue
		}
		live = append(live, f)
	}
	for _, f := range live {
		if f.Effect == "deny" && (f.Source == SourceQuarantine || f.Source == SourceEmergency || f.Emergency) {
			return Outcome{Effect: "deny", Source: sourceOr(f, SourceQuarantine), Reason: "quarantine_wins"}
		}
	}
	for _, f := range live {
		if f.Effect == "deny" && !f.Overridable && (f.Source == SourceGuardrail || f.Source == SourceEmergency) {
			return Outcome{Effect: "deny", Source: SourceGuardrail, Reason: "guardrail_deny"}
		}
	}
	for _, f := range live {
		if f.Effect == "deny" {
			return Outcome{Effect: "deny", Source: sourceOr(f, SourceRestriction), Reason: "deny_wins"}
		}
	}
	for _, f := range live {
		if f.Effect == "allow" && f.Source == SourceException {
			return Outcome{Effect: "allow", Source: SourceException, Reason: "approved_exception"}
		}
	}
	for _, f := range live {
		if f.Effect == "allow" {
			return Outcome{Effect: "allow", Source: sourceOr(f, SourceRuntimeAllow), Reason: "runtime_allow"}
		}
	}
	return Outcome{Effect: "deny", Source: "default", Reason: "default_deny"}
}

func sourceOr(f Fact, fallback string) string {
	if f.Source != "" {
		return f.Source
	}
	return fallback
}
