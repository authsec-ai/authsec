package collectorcontract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestGoldenRoundTrip(t *testing.T) {
	reqSchema := compileSchema(t, "schema/agent_sync_request.schema.json")
	respSchema := compileSchema(t, "schema/agent_sync_response.schema.json")
	appliedSchema := compileSchema(t, "schema/applied_receipt.schema.json")

	reqRaw := readFixture(t, "testdata/sync_request_11_3.json")
	mustValidate(t, reqSchema, reqRaw)
	var req SyncRequest
	if err := json.Unmarshal(reqRaw, &req); err != nil {
		t.Fatal(err)
	}
	again, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, reqRaw, again) {
		t.Fatalf("request did not round-trip\n got %s", again)
	}
	mustValidate(t, reqSchema, again)
	parsed, cerr := Validate(reqRaw)
	if cerr != nil {
		t.Fatalf("validate golden request: %+v", cerr)
	}
	if parsed.Sequence != 7 || parsed.Objects[0].Kind != "linux.systemd_workload" {
		t.Fatalf("parsed request = %+v", parsed)
	}
	if _, ok := parsed.Objects[1].Native["uid"].(float64); !ok {
		t.Fatalf("uid type = %T", parsed.Objects[1].Native["uid"])
	}

	respRaw := readFixture(t, "testdata/sync_response_11_4.json")
	mustValidate(t, respSchema, respRaw)
	var resp SyncResponse
	if err := json.Unmarshal(respRaw, &resp); err != nil {
		t.Fatal(err)
	}
	respAgain, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, respRaw, respAgain) {
		t.Fatalf("response did not round-trip\n got %s", respAgain)
	}

	appliedRaw := readFixture(t, "testdata/applied_receipt_22_3.json")
	mustValidate(t, appliedSchema, appliedRaw)
	var applied AppliedReceipt
	if err := json.Unmarshal(appliedRaw, &applied); err != nil {
		t.Fatal(err)
	}
	appliedAgain, err := json.Marshal(applied)
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, appliedRaw, appliedAgain) {
		t.Fatalf("applied receipt did not round-trip\n got %s", appliedAgain)
	}

	// The server always sends receipt_state and desired null. The golden
	// example omits receipt_state and carries a future desired object.
	live := []byte(`{
		"receipt_id": "30000000-0000-4000-8000-000000000007",
		"accepted_sequence": 1,
		"receipt_state": "accepted",
		"projection_state": "queued",
		"published_graph_revision": 0,
		"mapping_url": "/api/iga/v2/receipts/30000000-0000-4000-8000-000000000007",
		"desired": null,
		"next_sync_seconds": 15
	}`)
	mustValidate(t, respSchema, live)
}

func TestNegativeFixtures(t *testing.T) {
	reqSchema := compileSchema(t, "schema/agent_sync_request.schema.json")

	secret := readFixture(t, "testdata/negative_secret.json")
	if err := validateSchema(reqSchema, secret); err == nil {
		t.Fatal("schema accepted a secret field")
	}
	if _, cerr := Validate(secret); cerr == nil || cerr.Kind != "invalid" {
		t.Fatalf("secret validate = %+v", cerr)
	} else if !strings.Contains(cerr.Error()+fieldText(cerr), "secret") && !hasMessage(cerr, "secret-like") {
		t.Fatalf("secret error = %+v", cerr)
	}
	if strings.Contains(fieldText(cerrOf(t, secret)), "CANARY-SECRET-DO-NOT-LEAK-1") {
		t.Fatal("validator echoed the secret value")
	}

	canonical := readFixture(t, "testdata/negative_canonical_id.json")
	if err := validateSchema(reqSchema, canonical); err == nil {
		t.Fatal("schema accepted canonical_id")
	}
	if _, cerr := Validate(canonical); cerr == nil || cerr.Kind != "invalid" || !hasMessage(cerr, "canonical") {
		t.Fatalf("canonical validate = %+v", cerr)
	}

	old := readFixture(t, "testdata/negative_schema_version.json")
	if err := validateSchema(reqSchema, old); err == nil {
		t.Fatal("schema accepted schema 1.0")
	}
	if _, cerr := Validate(old); cerr == nil || cerr.Kind != "upgrade" || len(cerr.Supported) != 1 || cerr.Supported[0] != SchemaVersion {
		t.Fatalf("upgrade validate = %+v", cerr)
	}
}

func TestPrivilegedKindForbidden(t *testing.T) {
	for _, kind := range []string{"assertion", "approval.grant", "ownership_record", "k8s.ownership"} {
		raw := []byte(`{
			"schema_version":"2.0",
			"batch_id":"10000000-0000-4000-8000-000000000011",
			"collector_epoch":"20000000-0000-4000-8000-000000000001",
			"sequence":1,
			"sent_at":"2026-09-25T08:00:00Z",
			"objects":[{"ref":"o_x","kind":"` + kind + `","native":{"name":"x"}}],
			"observations":[],
			"applied":[],
			"health":{"events_lost":0,"queue_depth":0}
		}`)
		_, cerr := Validate(raw)
		if cerr == nil || cerr.Kind != "forbidden" {
			t.Fatalf("%s: %+v", kind, cerr)
		}
	}
	if IsPrivilegedKind("linux.systemd_workload") || !KnownObjectKind("k8s.pod") || !KnownObservationKind("runtime.dns") || !KnownObservationKind("admission.actor") {
		t.Fatal("kind registry mismatch")
	}
	if IsPrivilegedKind("admission.actor") {
		t.Fatal("admission.actor is telemetry, not a privileged kind")
	}
}

func TestAdmissionPreviewAndHealthCounters(t *testing.T) {
	reqSchema := compileSchema(t, "schema/agent_sync_request.schema.json")
	raw := readFixture(t, "testdata/sync_request_admission.json")
	mustValidate(t, reqSchema, raw)
	parsed, cerr := Validate(raw)
	if cerr != nil {
		t.Fatalf("validate admission fixture: %+v", cerr)
	}
	if parsed.Observations[0].Kind != "admission.actor" || !parsed.Observations[0].Preview {
		t.Fatalf("observation = %+v", parsed.Observations[0])
	}
	h := parsed.Health
	if h.PartitionsPartial != 1 || h.PartitionsForbidden != 0 || h.PoisonIsolated != 2 || h.IdempotencyConflicts != 3 {
		t.Fatalf("health = %+v", h)
	}
	for _, kind := range []string{"k8s.cluster_role", "k8s.cluster_role_binding", "k8s.namespace", "k8s.node"} {
		if !ClusterScopedKind(kind) || !OpenClusterKind(kind) {
			t.Fatalf("%s should be open cluster inventory", kind)
		}
	}
	if !ClusterScopedKind("k8s.pv") || OpenClusterKind("k8s.pv") {
		t.Fatal("persistent volume still requires a star allowlist")
	}

	negative := []byte(`{
		"schema_version":"2.0",
		"batch_id":"10000000-0000-4000-8000-000000000352",
		"collector_epoch":"20000000-0000-4000-8000-000000000001",
		"sequence":1,
		"sent_at":"2026-09-25T08:00:00Z",
		"objects":[],
		"observations":[],
		"applied":[],
		"health":{"events_lost":0,"queue_depth":0,"partitions_partial":-1}
	}`)
	if err := validateSchema(reqSchema, negative); err == nil {
		t.Fatal("schema accepted a negative health counter")
	}
	if _, cerr := Validate(negative); cerr == nil || cerr.Kind != "invalid" || !hasMessage(cerr, "must be >= 0") {
		t.Fatalf("negative health = %+v", cerr)
	}
}

func TestObjectsDigestStable(t *testing.T) {
	objects := []Object{{Ref: "o_a", Kind: "linux.file", Native: map[string]any{"path": "/etc/passwd"}}}
	a, err := ObjectsDigest(objects)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ObjectsDigest(objects)
	if err != nil {
		t.Fatal(err)
	}
	if a != b || len(a) != 64 {
		t.Fatalf("digest %q %q", a, b)
	}
	objects[0].Native["path"] = "/etc/shadow"
	c, err := ObjectsDigest(objects)
	if err != nil {
		t.Fatal(err)
	}
	if c == a {
		t.Fatal("digest ignored native content")
	}
}

func TestSHA256SUMS(t *testing.T) {
	raw, err := os.ReadFile("SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) < 5 {
		t.Fatalf("manifest lines = %d", len(lines))
	}
	seen := map[string]bool{}
	for _, line := range lines {
		hash, name, ok := strings.Cut(line, "  ")
		if !ok || len(hash) != 64 {
			t.Fatalf("bad manifest line %q", line)
		}
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != hash {
			t.Fatalf("%s hash changed", name)
		}
		seen[name] = true
	}
	ver, err := os.ReadFile("VERSION")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(ver)) != PackageVersion {
		t.Fatalf("VERSION = %q", ver)
	}
	if !seen["VERSION"] || !seen["schema/agent_sync_request.schema.json"] || !seen["testdata/sync_request_11_3.json"] {
		t.Fatalf("manifest missing entries: %v", seen)
	}
}

func compileSchema(t *testing.T, path string) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	sch, err := c.Compile(path)
	if err != nil {
		t.Fatalf("compile %s: %v", path, err)
	}
	return sch
}

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustValidate(t *testing.T, sch *jsonschema.Schema, raw []byte) {
	t.Helper()
	if err := validateSchema(sch, raw); err != nil {
		t.Fatalf("schema: %v\n%s", err, raw)
	}
}

func validateSchema(sch *jsonschema.Schema, raw []byte) error {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	return sch.Validate(v)
}

func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var left, right any
	if err := json.Unmarshal(a, &left); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &right); err != nil {
		t.Fatal(err)
	}
	return reflect.DeepEqual(left, right)
}

func hasMessage(err *ContractError, needle string) bool {
	if err == nil {
		return false
	}
	for _, f := range err.Fields {
		if strings.Contains(f.Message, needle) || strings.Contains(f.Path, needle) {
			return true
		}
	}
	return false
}

func fieldText(err *ContractError) string {
	if err == nil {
		return ""
	}
	b, _ := json.Marshal(err.Fields)
	return string(b)
}

func cerrOf(t *testing.T, raw []byte) *ContractError {
	t.Helper()
	_, cerr := Validate(raw)
	if cerr == nil {
		t.Fatal("expected contract error")
	}
	return cerr
}
