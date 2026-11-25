package services

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/agentruntime/detect"
)

// Unit tests of versioned detection rules (F6), the alert lifecycle (F8) and
// suppressions (P6) that need no database. The database paths are in
// tests/integration/agent_runtime_alert_rules_test.go.

func updated(t *testing.T, u AgentAlertSettingsUpdate) (AgentAlertSettings, AgentAlertSettings) {
	t.Helper()
	cur := DefaultAgentAlertSettings()
	next, err := u.apply(cur)
	if err != nil {
		t.Fatal(err)
	}
	return cur, next
}

func TestAgentAlertLooseningClassification(t *testing.T) {
	off, on := false, true
	n20, n5, m10, m2, k10, k2 := 20, 5, 10, 2, 10.0, 2.0
	low, high, none := "low", "high", ""
	d := func(m map[string]*AgentAlertDetectionUpdate) AgentAlertSettingsUpdate {
		return AgentAlertSettingsUpdate{Detections: m}
	}
	ival := func(v int) *int { return &v }
	bval := func(v bool) *bool { return &v }
	cases := []struct {
		name  string
		u     AgentAlertSettingsUpdate
		loose bool
	}{
		{"disable a detection", d(map[string]*AgentAlertDetectionUpdate{"D6": {Enabled: &off}}), true},
		{"enable (already on)", d(map[string]*AgentAlertDetectionUpdate{"D6": {Enabled: &on}}), false},
		{"raise D5 n", d(map[string]*AgentAlertDetectionUpdate{"D5": {N: &n20}}), true},
		{"lower D5 n", d(map[string]*AgentAlertDetectionUpdate{"D5": {N: &n5}}), false},
		{"widen D5 window", d(map[string]*AgentAlertDetectionUpdate{"D5": {Minutes: &m10}}), false},
		{"narrow D5 window", d(map[string]*AgentAlertDetectionUpdate{"D5": {Minutes: &m2}}), true},
		{"raise D6 k", d(map[string]*AgentAlertDetectionUpdate{"D6": {K: &k10}}), true},
		{"lower D6 k", d(map[string]*AgentAlertDetectionUpdate{"D6": {K: &k2}}), false},
		{"lower a severity", d(map[string]*AgentAlertDetectionUpdate{"D1": {Severity: &low}}), true},
		{"raise a severity", d(map[string]*AgentAlertDetectionUpdate{"D6": {Severity: &high}}), false},
		{"severity back to own", d(map[string]*AgentAlertDetectionUpdate{"D6": {Severity: &none}}), false},
		{"slack off", AgentAlertSettingsUpdate{SlackEnabled: bval(false)}, true},
		{"longer dedupe", AgentAlertSettingsUpdate{DedupeWindowMinutes: ival(120)}, true},
		{"shorter dedupe", AgentAlertSettingsUpdate{DedupeWindowMinutes: ival(30)}, false},
		{"shorter retention", AgentAlertSettingsUpdate{RetentionDays: ival(30)}, true},
		{"longer retention", AgentAlertSettingsUpdate{RetentionDays: ival(365)}, false},
		{"mixed", AgentAlertSettingsUpdate{RetentionDays: ival(365), SlackEnabled: bval(false)}, true},
	}
	for _, c := range cases {
		cur, next := updated(t, c.u)
		got := agentAlertLoosening(cur, next)
		if (len(got) > 0) != c.loose {
			t.Errorf("%s: loosening %v, want loose=%v", c.name, got, c.loose)
		}
	}
	// Turning a disabled detection back on is tightening.
	cur, next := updated(t, d(map[string]*AgentAlertDetectionUpdate{"D6": {Enabled: &off}}))
	if l := agentAlertLoosening(next, cur); len(l) != 0 {
		t.Errorf("re-enable is loosening: %v", l)
	}
	if !agentAlertSettingsEqual(cur, cur) || agentAlertSettingsEqual(cur, next) {
		t.Error("settings equality")
	}
}

func TestAgentAlertSettingsApplyDoesNotMutate(t *testing.T) {
	cur := DefaultAgentAlertSettings()
	off := false
	if _, err := (AgentAlertSettingsUpdate{Detections: map[string]*AgentAlertDetectionUpdate{"D1": {Enabled: &off}}}).apply(cur); err != nil {
		t.Fatal(err)
	}
	if !cur.Detections["D1"].Enabled {
		t.Fatal("apply changed the current settings' map")
	}
	bad := "critical"
	_, err := (AgentAlertSettingsUpdate{Detections: map[string]*AgentAlertDetectionUpdate{"D1": {Severity: &bad}}}).apply(cur)
	var ge *GovError
	if !errors.As(err, &ge) || ge.Status != http.StatusBadRequest {
		t.Fatalf("bad severity: %v", err)
	}
	if _, err := (AgentAlertSettingsUpdate{Reason: strings.Repeat("x", 1001)}).apply(cur); err == nil {
		t.Fatal("a 1001-character reason was accepted")
	}
}

func TestAgentAlertSeverityOverride(t *testing.T) {
	low := "low"
	_, next := updated(t, AgentAlertSettingsUpdate{Detections: map[string]*AgentAlertDetectionUpdate{"D6": {Severity: &low}}})
	fs := next.applySeverity([]detect.Finding{{Detection: detect.D6, Severity: detect.SeverityMedium},
		{Detection: detect.D1, Severity: detect.SeverityHigh}})
	if fs[0].Severity != detect.SeverityLow || fs[1].Severity != detect.SeverityHigh {
		t.Fatalf("override %+v", fs)
	}
	if detect.SeverityRank("low") >= detect.SeverityRank("medium") || !detect.ValidSeverity("low") || detect.ValidSeverity("critical") {
		t.Fatal("low severity rank")
	}
	f := AgentAlertFilter{Severity: "low"}
	if err := f.Validate(); err != nil {
		t.Fatalf("low filter: %v", err)
	}
	f = AgentAlertFilter{State: "reopened"}
	if err := f.Validate(); err != nil {
		t.Fatalf("reopened filter: %v", err)
	}
}

func TestAgentAlertTransitions(t *testing.T) {
	cases := []struct {
		from, to string
		ok, same bool
	}{
		{"open", "acknowledged", true, false},
		{"acknowledged", "acknowledged", true, true},
		{"reopened", "acknowledged", true, false},
		{"resolved", "acknowledged", false, false},
		{"open", "resolved", true, false},
		{"acknowledged", "resolved", true, false},
		{"reopened", "resolved", true, false},
		{"resolved", "resolved", false, false},
		{"resolved", "reopened", true, false},
		{"open", "reopened", false, false},
		{"acknowledged", "reopened", false, false},
	}
	for _, c := range cases {
		ok, same := agentAlertTransitionAllowed(c.from, c.to)
		if ok != c.ok || same != c.same {
			t.Errorf("%s -> %s: ok=%v same=%v", c.from, c.to, ok, same)
		}
	}
	for _, o := range []string{"true_positive", "benign", "false_positive", "duplicate"} {
		if !ValidAgentAlertOutcome(o) {
			t.Errorf("outcome %s refused", o)
		}
	}
	if ValidAgentAlertOutcome("fixed") || ValidAgentAlertOutcome("") {
		t.Error("free text accepted as an outcome")
	}
	// Resolve without an outcome is refused before any database access.
	s := NewAgentAlertService(nil)
	if _, err := s.Resolve(t.Context(), uuid.New(), uuid.New(), uuid.New(), "", "done"); err == nil || !strings.Contains(err.Error(), "outcome") {
		t.Fatalf("resolve without outcome: %v", err)
	}
	if _, err := s.Resolve(t.Context(), uuid.New(), uuid.New(), uuid.New(), "fixed", ""); err == nil {
		t.Fatal("resolve with a free-text outcome")
	}
	if _, err := s.Reopen(t.Context(), uuid.New(), uuid.New(), uuid.New(), "  "); err == nil {
		t.Fatal("reopen without a reason")
	}
}

func TestSucceededHarmNeverSuppressed(t *testing.T) {
	ok := agentruntime.Event{EventID: "e"}
	refused := agentruntime.Event{EventID: "r", ErrorCode: "AccessDenied", AuthorizationDenied: true}
	for _, id := range detect.All {
		harmful := detect.HarmfulOnSuccess(id)
		if got := detect.SucceededHarm(detect.Finding{Detection: id}, ok); got != harmful {
			t.Errorf("%s on a success: %v", id, got)
		}
		if detect.SucceededHarm(detect.Finding{Detection: id}, refused) {
			t.Errorf("%s on a refused call counted as a succeeded harm", id)
		}
		req := AgentAlertSuppressionRequest{IdentityID: uuid.New(), Detection: string(id), Reason: "noisy"}
		err := req.validate()
		var ge *GovError
		if harmful {
			if !errors.As(err, &ge) || ge.Code != GovCodeSuppressionNotAllowed {
				t.Errorf("suppression of %s: %v, want suppression_not_allowed", id, err)
			}
		} else if err != nil {
			t.Errorf("suppression of %s: %v", id, err)
		}
	}
	// The sink's match never runs a query for a harmful detection.
	if id, err := matchAgentAlertSuppression(nil, uuid.New(), uuid.New(), detect.D1, "", time.Now()); id != nil || err != nil {
		t.Fatalf("match D1: %v %v", id, err)
	}
}

func TestAgentAlertSuppressionRequestValidation(t *testing.T) {
	good := func() AgentAlertSuppressionRequest {
		return AgentAlertSuppressionRequest{IdentityID: uuid.New(), Detection: "D6", Reason: "known batch job"}
	}
	r := good()
	if err := r.validate(); err != nil || r.Days != AgentSuppressionDefaultDays {
		t.Fatalf("default days: %v %d", err, r.Days)
	}
	for name, mut := range map[string]func(*AgentAlertSuppressionRequest){
		"no identity":   func(r *AgentAlertSuppressionRequest) { r.IdentityID = uuid.Nil },
		"bad detection": func(r *AgentAlertSuppressionRequest) { r.Detection = "D9" },
		"no reason":     func(r *AgentAlertSuppressionRequest) { r.Reason = " " },
		"91 days":       func(r *AgentAlertSuppressionRequest) { r.Days = 91 },
		"negative days": func(r *AgentAlertSuppressionRequest) { r.Days = -1 },
		"bad digest":    func(r *AgentAlertSuppressionRequest) { r.InstanceDigest = "a b" },
	} {
		r := good()
		mut(&r)
		if err := r.validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	r = good()
	r.Days, r.InstanceDigest = 90, "sha256:abc"
	if err := r.validate(); err != nil {
		t.Fatalf("90 days with a digest: %v", err)
	}
}
