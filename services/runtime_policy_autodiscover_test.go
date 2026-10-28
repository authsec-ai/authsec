package services

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/runtimepolicy/candidates"
	"github.com/authsec-ai/authsec/internal/runtimepolicy/compile"
)

func TestParseActivityFacts(t *testing.T) {
	raw := []byte(`{"activity":[
		{"kind":"network","service":"github","action":"get","target":"api.github.com","detail":"/zen","outcome":"200","observed_at":"2026-09-29T19:17:12Z"},
		{"kind":"network","service":"grok","action":"get","target":"api.x.ai","detail":"/v1/models","outcome":"401","observed_at":"2026-09-29T19:17:12Z"},
		{"kind":"network","service":"x","action":"get","target":"api.x.com","detail":"/2/users/me","outcome":"401","observed_at":"2026-09-29T19:17:12Z"},
		{"kind":"file","action":"write","target":"/var/iga-activity/sample.txt","outcome":"ok","observed_at":"2026-09-29T19:17:12Z"},
		{"kind":"file","action":"read","target":"/var/iga-activity/sample.txt","outcome":"ok","observed_at":"2026-09-29T19:17:12Z"},
		{"kind":"file","action":"read","target":"","outcome":"ok"}
	]}`)
	facts := parseActivityFacts(raw)
	if len(facts) != 5 {
		t.Fatalf("facts = %d, want 5", len(facts))
	}
	want := []struct {
		action, outcome, path, address string
		internet                       bool
	}{
		{"network.connect", "success", "/zen", "api.github.com", true},
		{"network.connect", "denied", "/v1/models", "api.x.ai", true},
		{"network.connect", "denied", "/2/users/me", "api.x.com", true},
		{"file.write", "success", "/var/iga-activity/sample.txt", "", false},
		{"file.read", "success", "/var/iga-activity/sample.txt", "", false},
	}
	for i, w := range want {
		got := facts[i]
		if got.AccessAction != w.action || got.AccessOutcome != w.outcome || got.Path != w.path || got.Address != w.address || got.Internet != w.internet {
			t.Fatalf("fact %d = %+v, want %+v", i, got, w)
		}
	}
	if facts[0].SourceKey != "network:api.github.com/zen" || facts[0].Port != 443 || facts[0].Protocol != "tcp" {
		t.Fatalf("github endpoint %+v", facts[0])
	}
	if facts[3].Port != 0 || facts[3].Protocol != "" {
		t.Fatalf("file endpoint should not carry a port: %+v", facts[3])
	}
	if facts[3].SourceKey != "file:/var/iga-activity/sample.txt" {
		t.Fatalf("file source key %q", facts[3].SourceKey)
	}
	if facts[0].ObservedAt.IsZero() || facts[0].ObservedAt.After(time.Now().Add(time.Minute)) {
		t.Fatalf("observed_at %s", facts[0].ObservedAt)
	}
	if parseActivityFacts(nil) != nil {
		t.Fatal("empty metadata produced facts")
	}
}

func TestAssembleObservedDocument(t *testing.T) {
	gen := candidates.Result{
		InputHash: "abc",
		Rules: []candidates.Rule{
			{ID: "allow-file", Action: "file.read", ResourceID: "res-file", Path: "/var/iga-activity/sample.txt", Effect: "allow"},
			{ID: "allow-write", Action: "file.write", ResourceID: "res-file", Path: "/var/iga-activity/sample.txt", Effect: "allow"},
		},
		Review: []candidates.Record{
			{Action: "network.connect", ResourceID: "res-gh", Path: "/zen", Reasons: []string{"internet_destination"}},
		},
		Denied: []candidates.Record{
			{Action: "network.connect", ResourceID: "res-x", Path: "/2/users/me"},
			{Action: "network.connect", ResourceID: "res-grok", Path: "/v1/models"},
			{Action: "network.connect", ResourceID: "res-gh", Path: "/zen"},
		},
	}
	doc := assembleObservedDocument(gen, "workload-1", "observed-agent")
	if doc.Name != "observed-agent" || doc.Format != "authsec.runtime.v1" || doc.DefaultEffect != "deny" || doc.Mode != "observe" {
		t.Fatalf("document header %+v", doc)
	}
	if len(doc.Targets.WorkloadIDs) != 1 || doc.Targets.WorkloadIDs[0] != "workload-1" {
		t.Fatalf("targets %+v", doc.Targets)
	}
	if len(doc.Rules) != 5 {
		t.Fatalf("rules = %d, want 5 (duplicate review path must not add a second deny)", len(doc.Rules))
	}
	effects := map[string]string{}
	for _, rule := range doc.Rules {
		effects[rule.Action+" "+rule.Path] = rule.Effect
		if rule.Effect != "allow" && rule.Effect != "deny" {
			t.Fatalf("effect %s", rule.Effect)
		}
	}
	if effects["file.read /var/iga-activity/sample.txt"] != "allow" || effects["file.write /var/iga-activity/sample.txt"] != "allow" {
		t.Fatalf("file effects %+v", effects)
	}
	if effects["network.connect /zen"] != "deny" || effects["network.connect /v1/models"] != "deny" || effects["network.connect /2/users/me"] != "deny" {
		t.Fatalf("network effects %+v", effects)
	}
	controls := map[string]bool{}
	for _, c := range doc.RequiredControls {
		controls[c] = true
	}
	if !controls["filesystem"] || !controls["egress"] {
		t.Fatalf("controls %v", doc.RequiredControls)
	}
	raw, _, err := compile.Canonical(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compile.Parse(raw); err != nil {
		t.Fatal(err)
	}
	again := assembleObservedDocument(gen, "workload-1", "observed-agent")
	raw2, _, err := compile.Canonical(again)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(raw2) {
		t.Fatalf("document is not stable\n%s\n%s", raw, raw2)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded["rego"]; ok {
		t.Fatal("document included rego")
	}
}
