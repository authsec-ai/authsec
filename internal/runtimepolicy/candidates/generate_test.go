package candidates

import (
	"testing"
	"time"
)

func TestGenerateEligibleAllowAndPartialCoverage(t *testing.T) {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(BaselineWindow)
	obs := Observation{
		ID: "o1", WorkloadID: "w", RuntimeInstanceID: "rt", Executable: "invoice-worker",
		Environment: "prod", Action: "network.connect", Outcome: "success",
		ResourceID: "db", Address: "10.20.0.15", ObservedAt: start.Add(time.Hour),
	}
	in := Input{
		WorkloadIDs: []string{"w"}, GraphRevision: 184, WindowStart: start, WindowEnd: end,
		Observations: []Observation{obs},
		Declared: []Dependency{{
			WorkloadID: "w", ResourceID: "secret", BindingKind: "secret_ref", Action: "secret.read", Schedule: "cron",
		}},
		Coverage: []Coverage{{CollectorID: "c", Class: "process", State: "stale"}},
	}
	a, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	if a.InputHash != b.InputHash || len(a.Rules) != 1 || a.Rules[0].ResourceID != "db" || a.Rules[0].Effect != "allow" {
		t.Fatalf("rules = %+v", a.Rules)
	}
	if !a.Partial {
		t.Fatal("stale coverage was treated as complete")
	}
	if len(a.Rules) != len(b.Rules) || a.Rules[0].ID != b.Rules[0].ID {
		t.Fatal("same inputs were not hash-stable")
	}
	if len(a.Review) != 1 || a.Review[0].ResourceID != "secret" {
		t.Fatalf("secret was not kept for review: %+v", a.Review)
	}
	if len(a.UnobservedScheduled) != 1 || a.UnobservedScheduled[0] != "cron" {
		t.Fatalf("scheduled = %+v", a.UnobservedScheduled)
	}
	complete := in
	complete.Coverage = []Coverage{{CollectorID: "c", Class: "process", State: "complete"}}
	full, err := Generate(complete)
	if err != nil {
		t.Fatal(err)
	}
	if full.Partial || len(full.Rules) != len(a.Rules) {
		t.Fatalf("coverage changed the allow set: partial=%v rules=%d", full.Partial, len(full.Rules))
	}
}

func TestGenerateShadowIsNeverAnAllow(t *testing.T) {
	start := time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC)
	in := Input{
		WorkloadIDs: []string{"w"}, GraphRevision: 184, WindowStart: start, WindowEnd: start.Add(time.Hour),
		Observations: []Observation{{
			ID: "shadow", WorkloadID: "w", Action: "file.read", Outcome: "denied",
			Path: "/etc/shadow", ResourceID: "shadow", ObservedAt: start.Add(time.Minute),
		}},
		Coverage: []Coverage{{CollectorID: "c", Class: "file", State: "complete"}},
	}
	got, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 0 {
		t.Fatalf("shadow became an allow: %+v", got.Rules)
	}
	if len(got.Detections) != 1 || got.Detections[0].Kind != "sensitive_file_access" {
		t.Fatalf("detection = %+v", got.Detections)
	}
	if len(got.Denied) != 1 {
		t.Fatalf("denied = %+v", got.Denied)
	}
}

func TestGenerateRiskFiltersAndLimitedObservation(t *testing.T) {
	start := time.Date(2026, 9, 25, 8, 0, 0, 0, time.UTC)
	in := Input{
		WorkloadIDs: []string{"w"}, WindowStart: start, WindowEnd: start.Add(LimitedObservationWindow),
		Observations: []Observation{
			{ID: "inc", WorkloadID: "w", Action: "network.connect", Outcome: "success", ResourceID: "db", Incident: true, ObservedAt: start},
			{ID: "net", WorkloadID: "w", Action: "network.connect", Outcome: "success", ResourceID: "pub", Internet: true, ObservedAt: start},
			{ID: "wild", WorkloadID: "w", Action: "file.read", Outcome: "success", Path: "/tmp/*", Wildcard: true, ObservedAt: start},
			{ID: "priv", WorkloadID: "w", Action: "exec", Outcome: "success", Privilege: true, ObservedAt: start},
		},
		Coverage: []Coverage{{State: "complete", Class: "process", CollectorID: "c"}},
	}
	got, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	if !got.LimitedObservation {
		t.Fatal("five minute window was not labelled limited observation")
	}
	if len(got.Rules) != 0 || got.ExcludedIncidents != 1 || len(got.Review) != 3 {
		t.Fatalf("got rules=%d incidents=%d review=%d", len(got.Rules), got.ExcludedIncidents, len(got.Review))
	}
}

func TestGenerateMissingCoverageIsUnknownNotNarrower(t *testing.T) {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	in := Input{
		WorkloadIDs: []string{"w"}, WindowStart: start, WindowEnd: start.Add(BaselineWindow),
		Observations: []Observation{{
			ID: "o", WorkloadID: "w", Action: "file.read", Outcome: "success", Path: "/srv/invoices/a",
			ObservedAt: start.Add(time.Hour),
		}},
	}
	got, err := Generate(in)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Partial || got.Coverage[0].State != "unknown" || len(got.Rules) != 1 {
		t.Fatalf("partial=%v coverage=%+v rules=%d", got.Partial, got.Coverage, len(got.Rules))
	}
}

func TestInterpretPrivateEndpointAndShadow(t *testing.T) {
	db := Interpret(InterpretInput{Action: "connect", NativeKind: "tcp", Metadata: map[string]any{"address": "10.20.0.15"}})
	if db.Action != "network.connect" || db.Internet || db.Sensitive {
		t.Fatalf("db = %+v", db)
	}
	shadow := Interpret(InterpretInput{Action: "open", Metadata: map[string]any{"path": "/etc/shadow"}})
	if !shadow.Shadow || !shadow.Sensitive || shadow.Action != "file.read" {
		t.Fatalf("shadow = %+v", shadow)
	}
	pub := Interpret(InterpretInput{Action: "connect", Metadata: map[string]any{"address": "8.8.8.8"}})
	if !pub.Internet {
		t.Fatal("public address was treated as private")
	}
}
