package compile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/authsec-ai/authsec/internal/runtimepolicy/opa"
	"github.com/authsec-ai/authsec/internal/runtimepolicy/profiles"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const invoice = `{
  "name": "invoice-worker sandbox",
  "format": "authsec.runtime.v1",
  "targets": {
    "workload_ids": ["50000000-0000-4000-8000-000000000024"],
    "include_future_incarnations": false
  },
  "profile": "linux-managed-v1",
  "default_effect": "deny",
  "rules": [
    {"id": "db-connect", "action": "network.connect", "resource_id": "60000000-0000-4000-8000-000000000004", "effect": "allow"},
    {"id": "invoice-files", "action": "file.read", "path": "/srv/invoices/**", "effect": "allow"},
    {"id": "database-secret", "action": "secret.read", "resource_id": "60000000-0000-4000-8000-000000000009", "effect": "require_approval", "adapter": "authnull-broker"}
  ],
  "required_controls": ["filesystem", "egress"],
  "evidence_graph_revision": 184
}`

func TestGoldenInvoiceWorker(t *testing.T) {
	doc, err := Parse([]byte(invoice))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := profiles.Load()
	if err != nil {
		t.Fatal(err)
	}
	cat := invoiceCatalog{}
	res, err := Compile(context.Background(), reg, cat, uuid.New(), 2, doc)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rego != opa.Template() {
		t.Fatal("compiler rewrote the pinned template")
	}
	if len(res.Semantic.Rules) != 3 {
		t.Fatalf("semantic rules: %+v", res.Semantic.Rules)
	}
	for _, rule := range res.Semantic.Rules {
		if rule.OPAEntryPoint != opa.Query || rule.EnforcementAdapter == "" || rule.NativeScope == nil {
			t.Fatalf("rule report: %+v", rule)
		}
	}
	if !contains(res.Semantic.Composition, "a new allow never releases existing quarantine") {
		t.Fatalf("composition: %+v", res.Semantic.Composition)
	}
	var controls map[string]any
	if err := json.Unmarshal(res.Controls, &controls); err != nil {
		t.Fatal(err)
	}
	if controls["schema"] != ControlsSchema {
		t.Fatalf("schema %v", controls["schema"])
	}
	sch := compileSchema(t, filepath.Join("schema", "controls.v1.json"))
	var decoded any
	if err := json.Unmarshal(res.Controls, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(decoded); err != nil {
		t.Fatalf("controls artifact: %v\n%s", err, res.Controls)
	}
	fs := controls["filesystem"].(map[string]any)
	base := fs["baseline"].(map[string]any)
	loaders := base["loaders"].(map[string]any)
	if loaders["amd64"] == "" || loaders["arm64"] == "" {
		t.Fatalf("filesystem profile did not supply loaders: %v", base)
	}
	egress := controls["egress"].([]any)
	if len(egress) != 1 {
		t.Fatalf("egress: %v", egress)
	}
	row := egress[0].(map[string]any)
	if row["address"] != "10.20.0.15" || row["port"] != float64(5432) || row["protocol"] != "tcp" {
		t.Fatalf("endpoint: %v", row)
	}
	e := opa.NewEngine()
	d := e.Eval(context.Background(), "ws", "golden", res.Data, map[string]any{
		"action": "network.connect", "workload_id": "50000000-0000-4000-8000-000000000024",
		"resource_id": "60000000-0000-4000-8000-000000000004",
	})
	if d.Effect != "allow" {
		t.Fatalf("corpus allow: %+v", d)
	}
	d = e.Eval(context.Background(), "ws", "golden-deny", res.Data, map[string]any{
		"action": "file.read", "workload_id": "50000000-0000-4000-8000-000000000024",
		"native_target": map[string]any{"path": "/etc/shadow"},
	})
	if d.Effect != "deny" {
		t.Fatalf("corpus deny: %+v", d)
	}
}

func TestUnresolvedEndpoint(t *testing.T) {
	doc, err := Parse([]byte(invoice))
	if err != nil {
		t.Fatal(err)
	}
	doc.Rules = doc.Rules[:1]
	doc.Rules[0].ResourceID = uuid.NewString()
	reg, _ := profiles.Load()
	_, err = Compile(context.Background(), reg, invoiceCatalog{}, uuid.New(), 1, doc)
	if code(err) != "unresolved_endpoint" {
		t.Fatalf("got %v", err)
	}
}

func TestReferencedResourceHasNoNativeTarget(t *testing.T) {
	doc, err := Parse([]byte(invoice))
	if err != nil {
		t.Fatal(err)
	}
	doc.Rules = doc.Rules[:1]
	reg, _ := profiles.Load()
	_, err = Compile(context.Background(), reg, statusCatalog{status: "referenced"}, uuid.New(), 1, doc)
	if code(err) != "unresolved_endpoint" {
		t.Fatalf("got %v", err)
	}
}

func TestCrossWorkspaceResource(t *testing.T) {
	doc, err := Parse([]byte(invoice))
	if err != nil {
		t.Fatal(err)
	}
	doc.Rules = doc.Rules[:1]
	reg, _ := profiles.Load()
	_, err = Compile(context.Background(), reg, statusCatalog{status: "cross"}, uuid.New(), 1, doc)
	if code(err) != "cross_workspace" {
		t.Fatalf("got %v", err)
	}
}

func TestBrokerWithoutConfiguration(t *testing.T) {
	doc, err := Parse([]byte(invoice))
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := profiles.Load()
	_, err = Compile(context.Background(), reg, invoiceCatalog{noBroker: true}, uuid.New(), 1, doc)
	if code(err) != "broker_not_configured" {
		t.Fatalf("got %v", err)
	}
}

func TestCustomRegoRejected(t *testing.T) {
	raw := []byte(`{"name":"x","format":"authsec.runtime.v1","rego":"package p","targets":{"workload_ids":["50000000-0000-4000-8000-000000000024"],"include_future_incarnations":false},"profile":"linux-managed-v1","default_effect":"deny","rules":[],"required_controls":[],"evidence_graph_revision":1}`)
	_, err := Parse(raw)
	if code(err) != "custom_rego_not_supported" {
		t.Fatalf("got %v", err)
	}
}

func TestCheckEnforceable(t *testing.T) {
	doc, err := Parse([]byte(invoice))
	if err != nil {
		t.Fatal(err)
	}
	doc.Mode = "enforce"
	reg, _ := profiles.Load()
	wid := uuid.MustParse("50000000-0000-4000-8000-000000000024")
	_, err = CheckEnforceable(reg, doc, []TargetRef{{
		WorkloadID: wid, Profile: "linux-managed-v1",
		CapabilityDigest: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}})
	ce, ok := err.(*Error)
	if !ok || ce.Code != "unsupported_control" {
		t.Fatalf("got %v", err)
	}
	doc.Mode = "observe"
	report, err := CheckEnforceable(reg, doc, []TargetRef{{
		WorkloadID: wid, Profile: "linux-managed-v1",
		CapabilityDigest: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}})
	if err != nil || len(report.Unsupported) == 0 {
		t.Fatalf("observe should report and not fail: %v %+v", err, report)
	}
	doc.Mode = "enforce"
	if _, err := CheckEnforceable(reg, doc, []TargetRef{{
		WorkloadID: wid, Profile: "linux-managed-v1",
		CapabilityDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}}); err != nil {
		t.Fatal(err)
	}
}

type invoiceCatalog struct{ noBroker bool }

func (invoiceCatalog) ResolveResource(_ context.Context, _, id uuid.UUID) (NativeResource, error) {
	switch id.String() {
	case "60000000-0000-4000-8000-000000000004":
		return NativeResource{ID: id, ReferenceStatus: "inventoried", NativeKind: "endpoint", Address: "10.20.0.15", Port: 5432, Protocol: "tcp"}, nil
	case "60000000-0000-4000-8000-000000000009":
		return NativeResource{ID: id, ReferenceStatus: "inventoried", NativeKind: "secret", BrokerPath: "authnull-broker"}, nil
	default:
		return NativeResource{}, ErrUnresolved
	}
}

func (invoiceCatalog) ResolveWorkload(_ context.Context, _, id uuid.UUID) (WorkloadTarget, error) {
	if id.String() != "50000000-0000-4000-8000-000000000024" {
		return WorkloadTarget{}, ErrUnresolved
	}
	return WorkloadTarget{ID: id, RuntimeInstanceIDs: []uuid.UUID{uuid.MustParse("50000000-0000-4000-8000-000000000900")}}, nil
}

func (c invoiceCatalog) BrokerConfigured(context.Context, uuid.UUID, string) (bool, error) {
	return !c.noBroker, nil
}

func (invoiceCatalog) Guardrails(context.Context, uuid.UUID, []uuid.UUID) ([]string, error) {
	return []string{"quarantine policy invoice-hold remains in force"}, nil
}

type statusCatalog struct{ status string }

func (c statusCatalog) ResolveResource(_ context.Context, _, id uuid.UUID) (NativeResource, error) {
	if c.status == "cross" {
		return NativeResource{}, ErrCrossWorkspace
	}
	return NativeResource{ID: id, ReferenceStatus: c.status, Address: "10.0.0.1", Port: 1, Protocol: "tcp"}, nil
}
func (statusCatalog) ResolveWorkload(_ context.Context, _, id uuid.UUID) (WorkloadTarget, error) {
	return WorkloadTarget{ID: id}, nil
}
func (statusCatalog) BrokerConfigured(context.Context, uuid.UUID, string) (bool, error) {
	return true, nil
}
func (statusCatalog) Guardrails(context.Context, uuid.UUID, []uuid.UUID) ([]string, error) {
	return nil, nil
}

func code(err error) string {
	if err == nil {
		return ""
	}
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return err.Error()
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func compileSchema(t *testing.T, path string) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	sch, err := c.Compile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sch
}

func TestSchemaFileExists(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("schema", "controls.v1.json"))
	if err != nil || !json.Valid(b) {
		t.Fatal(err)
	}
}
