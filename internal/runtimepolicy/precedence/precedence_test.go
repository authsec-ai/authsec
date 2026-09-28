package precedence

import (
	"testing"
	"time"
)

func TestResolve(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	later := now.Add(time.Hour)
	past := now.Add(-time.Hour)
	cases := []struct {
		name   string
		facts  []Fact
		effect string
		source string
	}{
		{name: "empty is default deny", effect: "deny", source: "default"},
		{
			name:   "quarantine beats runtime allow",
			facts:  []Fact{{Source: SourceRuntimeAllow, Effect: "allow"}, {Source: SourceQuarantine, Effect: "deny", Emergency: true}},
			effect: "deny", source: SourceQuarantine,
		},
		{
			name:   "emergency deny beats exception",
			facts:  []Fact{{Source: SourceException, Effect: "allow"}, {Source: SourceEmergency, Effect: "deny", Emergency: true}},
			effect: "deny", source: SourceEmergency,
		},
		{
			name:   "guardrail deny beats exception allow",
			facts:  []Fact{{Source: SourceException, Effect: "allow"}, {Source: SourceGuardrail, Effect: "deny"}},
			effect: "deny", source: SourceGuardrail,
		},
		{
			name:   "runtime deny beats runtime allow",
			facts:  []Fact{{Source: SourceRuntimeAllow, Effect: "allow"}, {Source: SourceRuntimeDeny, Effect: "deny"}},
			effect: "deny", source: SourceRuntimeDeny,
		},
		{
			name:   "enforcement plan deny beats allow",
			facts:  []Fact{{Source: SourceRuntimeAllow, Effect: "allow"}, {Source: SourceEnforcementPlan, Effect: "deny"}},
			effect: "deny", source: SourceEnforcementPlan,
		},
		{
			name:   "unexpired exception allow",
			facts:  []Fact{{Source: SourceException, Effect: "allow", ExpiresAt: &later}},
			effect: "allow", source: SourceException,
		},
		{
			name:   "expired exception falls through to default deny",
			facts:  []Fact{{Source: SourceException, Effect: "allow", ExpiresAt: &past}},
			effect: "deny", source: "default",
		},
		{
			name:   "runtime allow when nothing denies",
			facts:  []Fact{{Source: SourceRuntimeAllow, Effect: "allow"}},
			effect: "allow", source: SourceRuntimeAllow,
		},
		{
			name:   "expired deny does not block an allow",
			facts:  []Fact{{Source: SourceRuntimeDeny, Effect: "deny", ExpiresAt: &past}, {Source: SourceRuntimeAllow, Effect: "allow"}},
			effect: "allow", source: SourceRuntimeAllow,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Resolve(now, tc.facts)
			if got.Effect != tc.effect || got.Source != tc.source {
				t.Fatalf("got %+v", got)
			}
		})
	}
}
