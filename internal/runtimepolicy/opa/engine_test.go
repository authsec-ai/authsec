package opa

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestVersionPin(t *testing.T) {
	if Version != "1.21.0" {
		t.Fatalf("version %s", Version)
	}
	if !strings.Contains(VersionFile(), Version) || !strings.Contains(VersionFile(), ImageDigest) {
		t.Fatalf("VERSION file does not record the pin:\n%s", VersionFile())
	}
}

func TestRestrictedCapabilitiesRejectIO(t *testing.T) {
	for _, name := range []string{"http.send", "net.lookup_ip_addr", "opa.runtime"} {
		src := "package authsec.runtime\nimport rego.v1\ndecision := " + name + " if true\n"
		err := CompileRestricted(src)
		if err == nil {
			t.Fatalf("%s was compiled; the sandbox must reject it", name)
		}
		if !strings.Contains(err.Error(), name) && !strings.Contains(err.Error(), "undefined") && !strings.Contains(err.Error(), "unsafe") {
			t.Fatalf("%s: error does not name the missing builtin: %v", name, err)
		}
	}
}

func TestTemplateCannotCallHTTP(t *testing.T) {
	if err := CompileRestricted(Template()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(Template(), "http.send") || strings.Contains(Template(), "opa.runtime") {
		t.Fatal("pinned template references an I/O builtin")
	}
}

func TestSection142Example(t *testing.T) {
	e := newEngine(ExampleContract())
	data := map[string]any{
		"target": map[string]any{
			"workload_id":       "50000000-0000-4000-8000-000000000024",
			"allowed_endpoints": []any{"60000000-0000-4000-8000-000000000004"},
			"policy_revision":   float64(2),
		},
	}
	allow := e.Eval(context.Background(), "ws", "ex", data, map[string]any{
		"action":      "network.connect",
		"workload_id": "50000000-0000-4000-8000-000000000024",
		"resource_id": "60000000-0000-4000-8000-000000000004",
	})
	if allow.Effect != "allow" || !contains(allow.ReasonCodes, "approved_endpoint") {
		t.Fatalf("allow decision: %+v", allow)
	}
	denyIn := e.Eval(context.Background(), "ws", "ex2", data, map[string]any{
		"action":      "network.connect",
		"workload_id": "50000000-0000-4000-8000-000000000024",
		"resource_id": "other",
	})
	if denyIn.Effect != "deny" || !contains(denyIn.ReasonCodes, "endpoint_not_allowed") {
		t.Fatalf("deny decision: %+v", denyIn)
	}
}

func TestUndefinedAndErrorDeny(t *testing.T) {
	e := newEngine("package authsec.runtime\nimport rego.v1\n")
	d := e.Eval(context.Background(), "ws", "empty", map[string]any{}, map[string]any{})
	if d.Effect != "deny" || !contains(d.ReasonCodes, "undefined_decision") {
		t.Fatalf("undefined: %+v", d)
	}
	broken := newEngine("package authsec.runtime\nimport rego.v1\ndecision := 1 if true\n")
	d = broken.Eval(context.Background(), "ws", "bad", map[string]any{}, map[string]any{})
	if d.Effect != "deny" || !contains(d.ReasonCodes, "type_mismatch") {
		t.Fatalf("type mismatch: %+v", d)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	d = NewEngine().Eval(cancelled, "ws", "stop", map[string]any{
		"policy_revision": float64(1),
		"targets":         map[string]any{"workload_ids": []any{}},
		"rules":           []any{},
	}, map[string]any{})
	if d.Effect == "allow" {
		t.Fatal("a cancelled evaluation was allow")
	}
}

func TestWorkspacesDoNotShareData(t *testing.T) {
	e := NewEngine()
	rule := map[string]any{"id": "db-connect", "action": "network.connect", "effect": "allow", "resource_id": "res-a"}
	dataA := map[string]any{
		"policy_revision": float64(1),
		"targets":         map[string]any{"workload_ids": []any{"wl"}},
		"rules":           []any{rule},
	}
	ruleB := map[string]any{"id": "db-connect", "action": "network.connect", "effect": "allow", "resource_id": "res-b"}
	dataB := map[string]any{
		"policy_revision": float64(1),
		"targets":         map[string]any{"workload_ids": []any{"wl"}},
		"rules":           []any{ruleB},
	}
	in := map[string]any{"action": "network.connect", "workload_id": "wl", "resource_id": "res-a"}
	a := e.Eval(context.Background(), "workspace-a", "1", dataA, in)
	b := e.Eval(context.Background(), "workspace-b", "1", dataB, in)
	if a.Effect != "allow" {
		t.Fatalf("workspace A should allow its own resource: %+v", a)
	}
	if b.Effect == "allow" {
		t.Fatalf("workspace B allowed workspace A's resource: %+v", b)
	}
}

func TestDecisionLogOmitsCanary(t *testing.T) {
	e := NewEngine()
	var buf bytes.Buffer
	e.SetLog(&buf)
	canary := "CANARY-SECRET-DO-NOT-LEAK-7"
	e.Eval(context.Background(), "ws", "log", map[string]any{
		"policy_revision": float64(1),
		"targets":         map[string]any{"workload_ids": []any{"wl"}},
		"rules":           []any{},
	}, map[string]any{
		"action": "network.connect", "workload_id": "wl", "resource_id": canary,
		"body": canary, "authorization": "Bearer " + canary,
	})
	if RedactForTest(buf.Bytes()) || strings.Contains(buf.String(), canary) {
		t.Fatalf("decision log leaked the canary: %s", buf.String())
	}
	if !strings.Contains(buf.String(), `"effect"`) {
		t.Fatalf("log was not a decision: %s", buf.String())
	}
}

func TestTypedTemplateDecisions(t *testing.T) {
	e := NewEngine()
	data := map[string]any{
		"policy_revision": float64(2),
		"targets":         map[string]any{"workload_ids": []any{"wl"}},
		"rules": []any{
			map[string]any{"id": "db", "action": "network.connect", "effect": "allow", "resource_id": "db1"},
			map[string]any{"id": "files", "action": "file.read", "effect": "allow", "path": "/srv/invoices/**"},
			map[string]any{"id": "secret", "action": "secret.read", "effect": "require_approval", "resource_id": "sec", "adapter": "authnull-broker"},
			map[string]any{"id": "noexec", "action": "exec", "effect": "deny"},
		},
	}
	cases := []struct {
		name   string
		input  map[string]any
		effect string
		reason string
	}{
		{"allow connect", map[string]any{"action": "network.connect", "workload_id": "wl", "resource_id": "db1"}, "allow", "rule_allow"},
		{"deny other connect", map[string]any{"action": "network.connect", "workload_id": "wl", "resource_id": "other"}, "deny", "default_deny"},
		{"allow file", map[string]any{"action": "file.read", "workload_id": "wl", "native_target": map[string]any{"path": "/srv/invoices/a.pdf"}}, "allow", "rule_allow"},
		{"deny shadow", map[string]any{"action": "file.read", "workload_id": "wl", "native_target": map[string]any{"path": "/etc/shadow"}}, "deny", "default_deny"},
		{"approval", map[string]any{"action": "secret.read", "workload_id": "wl", "resource_id": "sec"}, "require_approval", "approval_required"},
		{"leased", map[string]any{"action": "secret.read", "workload_id": "wl", "resource_id": "sec", "approval_lease": map[string]any{"id": "lease", "resource_id": "sec"}}, "allow", "approval_lease"},
		{"exec deny wins", map[string]any{"action": "exec", "workload_id": "wl"}, "deny", "explicit_deny"},
		{"quarantine", map[string]any{"action": "network.connect", "workload_id": "wl", "resource_id": "db1", "quarantined": true}, "deny", "quarantine"},
		{"outside", map[string]any{"action": "network.connect", "workload_id": "other", "resource_id": "db1"}, "deny", "outside_policy_scope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := e.Eval(context.Background(), "ws", tc.name, data, tc.input)
			if d.Effect != tc.effect || !contains(d.ReasonCodes, tc.reason) {
				t.Fatalf("got %+v", d)
			}
		})
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
