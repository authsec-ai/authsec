package providers

import (
	"testing"
	"time"

	"github.com/authsec-ai/authsec/pkg/collectorcontract"
	"github.com/google/uuid"
)

// TestTetragonProcessExecWithActionDetail verifies that a process_exec
// observation carrying an ActionDetail normalises phase, result and source
// onto the Observed projection.
func TestTetragonProcessExecWithActionDetail(t *testing.T) {
	estate := "estate-action-1"
	obsID := uuid.New()
	plan, err := Normalize(Input{
		Provider: "linux", EstateID: estate, CollectorEpoch: uuid.New().String(),
		Objects: []Object{
			{Ref: "w", Kind: "linux.systemd_workload", Native: map[string]any{"unit": "nginx.service"}},
			{Ref: "id", Kind: "linux.local_account", Native: map[string]any{"uid": "1001", "user_namespace": "host"},
				Attrs:                map[string]any{"name": "www"},
				CredentialProvenance: &collectorcontract.CredentialProvenance{Method: "nss_passwd", Source: "/etc/passwd"},
			},
			{Ref: "f", Kind: "linux.file", Native: map[string]any{"path": "/var/log/nginx/access.log", "mount_namespace": "host"}},
		},
		Observations: []Observation{{
			ID: obsID, Kind: "runtime.process_exec", SubjectRef: "w", IdentityRef: "id", ResourceRef: "f",
			Runtime: map[string]any{
				"boot_id": "boot-x", "pid_namespace": "host", "pid": "42", "start_ticks": "100",
				"uid": "1001", "user_namespace": "host",
			},
			ObservedAt:  time.Now(),
			Outcome:     "success",
			Attribution: "kernel_process_credentials",
			ActionDetail: &collectorcontract.ActionDetail{
				Operation:    "process.exec",
				Phase:        collectorcontract.PhaseExec,
				Result:       collectorcontract.ResultSuccess,
				SourceSensor: collectorcontract.SourceTetragon,
			},
			Source: "tetragon",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Observed access must carry the ActionDetail fields.
	if len(plan.Observed) != 1 {
		t.Fatalf("expected 1 observed, got %d", len(plan.Observed))
	}
	obs := plan.Observed[0]
	if obs.Phase != collectorcontract.PhaseExec {
		t.Fatalf("phase: got %q, want %q", obs.Phase, collectorcontract.PhaseExec)
	}
	if obs.ResultDetail != collectorcontract.ResultSuccess {
		t.Fatalf("result: got %q, want %q", obs.ResultDetail, collectorcontract.ResultSuccess)
	}
	if obs.Source != collectorcontract.SourceTetragon {
		t.Fatalf("source: got %q, want %q", obs.Source, collectorcontract.SourceTetragon)
	}
	if obs.CredentialRef != "nss_passwd" {
		t.Fatalf("credential ref: got %q, want %q", obs.CredentialRef, "nss_passwd")
	}

	// Identity must carry credential provenance.
	var found bool
	for _, idn := range plan.Identities {
		if idn.Name == "www" && idn.CredentialProvenance != nil && idn.CredentialProvenance.Method == "nss_passwd" {
			found = true
		}
	}
	if !found {
		t.Fatal("identity www missing credential provenance")
	}

	// Binding must carry credential provenance.
	if len(plan.Bindings) == 0 {
		t.Fatal("expected at least 1 binding")
	}
	if plan.Bindings[0].CredentialProvenance == nil || plan.Bindings[0].CredentialProvenance.Method != "nss_passwd" {
		t.Fatalf("binding credential provenance: %+v", plan.Bindings[0].CredentialProvenance)
	}
}

// TestUIDOnDifferentHostsDoesNotMerge verifies that the same numeric UID
// on two different estates produces distinct identity keys, preventing
// cross-host identity collapse.
func TestUIDOnDifferentHostsDoesNotMerge(t *testing.T) {
	mk := func(estate string) *Plan {
		plan, err := Normalize(Input{
			Provider: "linux", EstateID: estate,
			Objects: []Object{{
				Ref: "a", Kind: "linux.local_account",
				Native: map[string]any{"uid": "1000", "user_namespace": "host"},
				Attrs:  map[string]any{"name": "deploy"},
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return plan
	}
	a := mk("estate-host-a")
	b := mk("estate-host-b")
	if len(a.Identities) != 1 || len(b.Identities) != 1 {
		t.Fatalf("identities a=%d b=%d", len(a.Identities), len(b.Identities))
	}
	if a.Identities[0].SourceKey == b.Identities[0].SourceKey {
		t.Fatalf("UID 1000 on different estates produced same key: %s", a.Identities[0].SourceKey)
	}
}

// TestPIDReuseCreatesNewRuntime verifies that the same PID with a different
// start_ticks value generates a distinct runtime key. This ensures that
// PID reuse after a process exits does not collapse two different process
// lifetimes into one.
func TestPIDReuseCreatesNewRuntime(t *testing.T) {
	estate := "estate-pid-reuse"
	epoch := uuid.New().String()

	mkObs := func(startTicks string) *Plan {
		plan, err := Normalize(Input{
			Provider: "linux", EstateID: estate, CollectorEpoch: epoch,
			Objects: []Object{
				{Ref: "w", Kind: "linux.systemd_workload", Native: map[string]any{"unit": "app.service"}},
			},
			Observations: []Observation{{
				ID: uuid.New(), Kind: "runtime.process_exec", SubjectRef: "w",
				Runtime: map[string]any{
					"boot_id": "boot-1", "pid_namespace": "host",
					"pid": "999", "start_ticks": startTicks,
				},
				ObservedAt: time.Now(), Outcome: "success",
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return plan
	}

	first := mkObs("50000")
	second := mkObs("60000")

	if len(first.Runtimes) != 1 || len(second.Runtimes) != 1 {
		t.Fatalf("runtimes first=%d second=%d", len(first.Runtimes), len(second.Runtimes))
	}
	if first.Runtimes[0].SourceKey == second.Runtimes[0].SourceKey {
		t.Fatalf("PID reuse collapsed: both runtimes have key %s", first.Runtimes[0].SourceKey)
	}
}

// TestReplayCreatesNoDuplicateEdges verifies that projecting the same
// observation twice produces identical plan entries, so the writer's
// ON CONFLICT clauses prevent duplicate rows. This is the idempotency
// property required for safe replay.
func TestReplayCreatesNoDuplicateEdges(t *testing.T) {
	estate := "estate-replay"
	epoch := uuid.New().String()
	obsID := uuid.New()
	now := time.Now()

	input := Input{
		Provider: "linux", EstateID: estate, CollectorEpoch: epoch,
		Objects: []Object{
			{Ref: "w", Kind: "linux.systemd_workload", Native: map[string]any{"unit": "sshd.service"}},
			{Ref: "u", Kind: "linux.local_account", Native: map[string]any{"uid": "0", "user_namespace": "host"},
				Attrs: map[string]any{"name": "root"}},
			{Ref: "f", Kind: "linux.file", Native: map[string]any{"path": "/etc/shadow", "mount_namespace": "host"}},
		},
		Observations: []Observation{{
			ID: obsID, Kind: "runtime.file_open", SubjectRef: "w", IdentityRef: "u", ResourceRef: "f",
			Runtime: map[string]any{
				"boot_id": "boot-r", "pid_namespace": "host", "pid": "1", "start_ticks": "1",
				"uid": "0", "user_namespace": "host",
			},
			ObservedAt:  now,
			Outcome:     "success",
			Attribution: "kernel_process_credentials",
			ActionDetail: &collectorcontract.ActionDetail{
				Phase:        collectorcontract.PhaseComplete,
				Result:       collectorcontract.ResultSuccess,
				SourceSensor: collectorcontract.SourceTetragon,
			},
		}},
	}

	first, err := Normalize(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Normalize(input)
	if err != nil {
		t.Fatal(err)
	}

	// Both projections must produce the same number of graph elements.
	if len(first.Runtimes) != len(second.Runtimes) {
		t.Fatalf("runtimes differ: %d vs %d", len(first.Runtimes), len(second.Runtimes))
	}
	if len(first.Bindings) != len(second.Bindings) {
		t.Fatalf("bindings differ: %d vs %d", len(first.Bindings), len(second.Bindings))
	}
	if len(first.Observed) != len(second.Observed) {
		t.Fatalf("observed differ: %d vs %d", len(first.Observed), len(second.Observed))
	}

	// Source keys must be identical so the writer's ON CONFLICT clauses fire.
	for i := range first.Runtimes {
		if first.Runtimes[i].SourceKey != second.Runtimes[i].SourceKey {
			t.Fatalf("runtime key mismatch at %d: %s vs %s", i, first.Runtimes[i].SourceKey, second.Runtimes[i].SourceKey)
		}
	}
	for i := range first.Observed {
		if first.Observed[i].Observation != second.Observed[i].Observation {
			t.Fatalf("observed observation id mismatch at %d", i)
		}
		if first.Observed[i].Phase != second.Observed[i].Phase {
			t.Fatalf("observed phase mismatch at %d: %s vs %s", i, first.Observed[i].Phase, second.Observed[i].Phase)
		}
	}
}
