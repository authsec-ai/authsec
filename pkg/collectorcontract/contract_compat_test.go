package collectorcontract

import (
	"encoding/json"
	"testing"
)

// TestOldFixtureWithoutNewFields verifies that the original golden fixture
// (no ActionDetail, no Source, no provenance) still decodes unchanged.
func TestOldFixtureWithoutNewFields(t *testing.T) {
	schema := compileSchema(t, "schema/agent_sync_request.schema.json")
	raw := readFixture(t, "testdata/sync_request_11_3.json")

	// JSON Schema validation must pass.
	mustValidate(t, schema, raw)

	// Go struct validation must pass.
	parsed, cerr := Validate(raw)
	if cerr != nil {
		t.Fatalf("validate old fixture: %+v", cerr)
	}

	// New fields should be nil/zero.
	for i, ob := range parsed.Observations {
		if ob.ActionDetail != nil {
			t.Fatalf("observations[%d].ActionDetail should be nil for old fixture", i)
		}
		if ob.Source != "" {
			t.Fatalf("observations[%d].Source should be empty for old fixture", i)
		}
	}
	for i, obj := range parsed.Objects {
		if obj.CredentialProvenance != nil {
			t.Fatalf("objects[%d].CredentialProvenance should be nil for old fixture", i)
		}
		if obj.MappingProvenance != nil {
			t.Fatalf("objects[%d].MappingProvenance should be nil for old fixture", i)
		}
	}

	// Round-trip: marshal back and confirm JSON equality.
	again, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, raw, again) {
		t.Fatalf("old fixture did not round-trip\n got %s", again)
	}
	mustValidate(t, schema, again)
}

// TestNewFixtureRoundTrips verifies the new fixture with ActionDetail,
// Source, and provenance fields round-trips through Go structs and schema.
func TestNewFixtureRoundTrips(t *testing.T) {
	schema := compileSchema(t, "schema/agent_sync_request.schema.json")
	raw := readFixture(t, "testdata/sync_request_action_detail.json")

	// JSON Schema validation.
	mustValidate(t, schema, raw)

	// Go struct validation.
	parsed, cerr := Validate(raw)
	if cerr != nil {
		t.Fatalf("validate new fixture: %+v", cerr)
	}

	// Verify ActionDetail fields parsed correctly.
	if len(parsed.Observations) < 2 {
		t.Fatal("expected at least 2 observations")
	}
	ob0 := parsed.Observations[0]
	if ob0.Source != "tetragon" {
		t.Fatalf("ob[0].Source = %q", ob0.Source)
	}
	if ob0.ActionDetail == nil {
		t.Fatal("ob[0].ActionDetail is nil")
	}
	if ob0.ActionDetail.Operation != "file.write" {
		t.Fatalf("ob[0].ActionDetail.Operation = %q", ob0.ActionDetail.Operation)
	}
	if ob0.ActionDetail.Phase != PhaseComplete {
		t.Fatalf("ob[0].ActionDetail.Phase = %q", ob0.ActionDetail.Phase)
	}
	if ob0.ActionDetail.Result != ResultSuccess {
		t.Fatalf("ob[0].ActionDetail.Result = %q", ob0.ActionDetail.Result)
	}
	if ob0.ActionDetail.SourceSensor != "tetragon" {
		t.Fatalf("ob[0].ActionDetail.SourceSensor = %q", ob0.ActionDetail.SourceSensor)
	}
	if ob0.ActionDetail.SourceSequence != 4201 {
		t.Fatalf("ob[0].ActionDetail.SourceSequence = %d", ob0.ActionDetail.SourceSequence)
	}
	if ob0.ActionDetail.Count != 1 {
		t.Fatalf("ob[0].ActionDetail.Count = %d", ob0.ActionDetail.Count)
	}

	// Second observation: denied with enforcement refs.
	ob1 := parsed.Observations[1]
	if ob1.ActionDetail == nil {
		t.Fatal("ob[1].ActionDetail is nil")
	}
	if ob1.ActionDetail.Result != ResultDenied {
		t.Fatalf("ob[1].ActionDetail.Result = %q", ob1.ActionDetail.Result)
	}
	if ob1.ActionDetail.Errno != 13 {
		t.Fatalf("ob[1].ActionDetail.Errno = %d", ob1.ActionDetail.Errno)
	}
	if len(ob1.ActionDetail.EnforcementRefs) != 1 {
		t.Fatalf("ob[1].ActionDetail.EnforcementRefs = %d", len(ob1.ActionDetail.EnforcementRefs))
	}
	ref := ob1.ActionDetail.EnforcementRefs[0]
	if ref.AssignmentID != "50000000-0000-4000-8000-000000000001" || ref.RuleID != "deny-outbound-db" || ref.ControlID != "ctl-net-001" {
		t.Fatalf("enforcement ref = %+v", ref)
	}

	// Verify provenance on objects.
	identity := parsed.Objects[1]
	if identity.CredentialProvenance == nil {
		t.Fatal("identity CredentialProvenance is nil")
	}
	if identity.CredentialProvenance.Method != "nss_passwd" {
		t.Fatalf("CredentialProvenance.Method = %q", identity.CredentialProvenance.Method)
	}
	if identity.MappingProvenance == nil {
		t.Fatal("identity MappingProvenance is nil")
	}
	if identity.MappingProvenance.Resolver != "sssd" {
		t.Fatalf("MappingProvenance.Resolver = %q", identity.MappingProvenance.Resolver)
	}

	// Round-trip.
	again, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, raw, again) {
		t.Fatalf("new fixture did not round-trip\n got %s", again)
	}
	mustValidate(t, schema, again)
}

// TestCapabilityDigestChanges verifies the capability digest shifts when
// new fields are claimed by a collector.
func TestCapabilityDigestChanges(t *testing.T) {
	base := NegotiatedCapability{}
	withAction := NegotiatedCapability{
		ActionDetailVersion: "1",
		ObservationFields:   []string{"action_detail", "source"},
	}
	d1, err := CapabilityDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := CapabilityDigest(withAction)
	if err != nil {
		t.Fatal(err)
	}
	if d1 == d2 {
		t.Fatal("capability digest should change when new fields are claimed")
	}
	if len(d1) != 64 || len(d2) != 64 {
		t.Fatalf("digests: %q %q", d1, d2)
	}

	// Deterministic: same input -> same digest.
	d3, _ := CapabilityDigest(withAction)
	if d2 != d3 {
		t.Fatal("capability digest not deterministic")
	}

	// Order-independent: fields sorted before hashing.
	reordered := NegotiatedCapability{
		ActionDetailVersion: "1",
		ObservationFields:   []string{"source", "action_detail"},
	}
	d4, _ := CapabilityDigest(reordered)
	if d2 != d4 {
		t.Fatal("capability digest should be order-independent")
	}
}

// TestPhaseResultConstants verifies the kind registry constants.
func TestPhaseResultConstants(t *testing.T) {
	for _, p := range KnownPhases() {
		if !KnownPhase(p) {
			t.Fatalf("KnownPhase(%q) = false", p)
		}
	}
	if KnownPhase("invalid") {
		t.Fatal("accepted invalid phase")
	}
	for _, r := range KnownResults() {
		if !KnownResult(r) {
			t.Fatalf("KnownResult(%q) = false", r)
		}
	}
	if KnownResult("invalid") {
		t.Fatal("accepted invalid result")
	}
}

// TestActionDetailSchemaRejectsInvalid verifies the JSON schema rejects
// bad phase/result values inside action_detail.
func TestActionDetailSchemaRejectsInvalid(t *testing.T) {
	schema := compileSchema(t, "schema/agent_sync_request.schema.json")

	// Bad phase value.
	badPhase := []byte(`{
		"schema_version":"2.0",
		"batch_id":"10000000-0000-4000-8000-000000000099",
		"collector_epoch":"20000000-0000-4000-8000-000000000001",
		"sequence":1,
		"sent_at":"2026-09-25T08:00:00Z",
		"objects":[{"ref":"o_w","kind":"linux.systemd_workload","native":{"unit":"x.service"}}],
		"observations":[{
			"event_id":"e1","kind":"runtime.process_exec","observed_at":"2026-09-25T08:00:00Z","outcome":"success",
			"action_detail":{"phase":"invalid_phase"}
		}],
		"applied":[],
		"health":{"events_lost":0,"queue_depth":0}
	}`)
	if err := validateSchema(schema, badPhase); err == nil {
		t.Fatal("schema accepted invalid phase")
	}

	// Bad result value.
	badResult := []byte(`{
		"schema_version":"2.0",
		"batch_id":"10000000-0000-4000-8000-000000000099",
		"collector_epoch":"20000000-0000-4000-8000-000000000001",
		"sequence":1,
		"sent_at":"2026-09-25T08:00:00Z",
		"objects":[{"ref":"o_w","kind":"linux.systemd_workload","native":{"unit":"x.service"}}],
		"observations":[{
			"event_id":"e1","kind":"runtime.process_exec","observed_at":"2026-09-25T08:00:00Z","outcome":"success",
			"action_detail":{"result":"bad_result"}
		}],
		"applied":[],
		"health":{"events_lost":0,"queue_depth":0}
	}`)
	if err := validateSchema(schema, badResult); err == nil {
		t.Fatal("schema accepted invalid result")
	}

	// Unknown field in action_detail should be rejected.
	unknownField := []byte(`{
		"schema_version":"2.0",
		"batch_id":"10000000-0000-4000-8000-000000000099",
		"collector_epoch":"20000000-0000-4000-8000-000000000001",
		"sequence":1,
		"sent_at":"2026-09-25T08:00:00Z",
		"objects":[{"ref":"o_w","kind":"linux.systemd_workload","native":{"unit":"x.service"}}],
		"observations":[{
			"event_id":"e1","kind":"runtime.process_exec","observed_at":"2026-09-25T08:00:00Z","outcome":"success",
			"action_detail":{"operation":"file.write","bogus_field":"x"}
		}],
		"applied":[],
		"health":{"events_lost":0,"queue_depth":0}
	}`)
	if err := validateSchema(schema, unknownField); err == nil {
		t.Fatal("schema accepted unknown field in action_detail")
	}
}
