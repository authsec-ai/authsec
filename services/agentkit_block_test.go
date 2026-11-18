package services

import (
	"strings"
	"testing"
	"time"
)

const blockBase = `apiVersion: authsec.ai/v1
kind: AgentPolicy
agent:
  id: claude-code
# people wrote this
mode: monitor
network:
  default: allow
  deny:
filesystem:
  deny:
    - "{home}/.aws"
`

func TestAddDenyKeepsCommentsAndDedups(t *testing.T) {
	doc, changed, err := addDeny(blockBase, AgentKitBlock{Type: AgentKitBlockHost, Value: "evil.example.com", Port: 443})
	if err != nil || !changed {
		t.Fatalf("host: %v %v", changed, err)
	}
	if !strings.Contains(doc, "# people wrote this") || !strings.Contains(doc, "evil.example.com") || !strings.Contains(doc, "port: 443") {
		t.Fatalf("document:\n%s", doc)
	}
	if again, changed, _ := addDeny(doc, AgentKitBlock{Type: AgentKitBlockHost, Value: "evil.example.com", Port: 443}); changed || again != doc {
		t.Error("the same block twice changed the document")
	}
	if _, changed, _ := addDeny(doc, AgentKitBlock{Type: AgentKitBlockHost, Value: "evil.example.com"}); !changed {
		t.Error("an all-ports block is not the 443 block")
	}
	doc, changed, err = addDeny(doc, AgentKitBlock{Type: AgentKitBlockPath, Value: "{home}/.aws"})
	if err != nil || changed {
		t.Errorf("existing path: %v %v", changed, err)
	}
	doc, _, err = addDeny(doc, AgentKitBlock{Type: AgentKitBlockCommand, Value: "git push --force*"})
	if err != nil || !strings.Contains(doc, "commands:") || !strings.Contains(doc, "git push --force*") {
		t.Fatalf("command into a missing section: %v\n%s", err, doc)
	}
	if err := CheckAgentKitPolicy("claude-code", doc); err != nil {
		t.Errorf("result does not check: %v", err)
	}
}

func TestAddDenyRefusesOddShapes(t *testing.T) {
	for name, doc := range map[string]string{
		"deny is a map":  "network:\n  deny: {a: b}\n",
		"section scalar": "network: off\n",
		"not a mapping":  "- a\n- b\n",
	} {
		if _, _, err := addDeny(doc, AgentKitBlock{Type: AgentKitBlockHost, Value: "x.example.com"}); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestNewAndCopiedPolicyCheck(t *testing.T) {
	for _, id := range []string{"codex", "*"} {
		if err := CheckAgentKitPolicy(id, newAgentKitPolicy(id)); err != nil {
			t.Errorf("new policy for %s: %v", id, err)
		}
	}
	doc, err := setAgentID(strings.Replace(blockBase, "id: claude-code", "id: \"*\"\n  name: Everyone", 1), "aider")
	if err != nil || CheckAgentKitPolicy("aider", doc) != nil || strings.Contains(doc, "Everyone") {
		t.Errorf("copied default: %v\n%s", err, doc)
	}
}

func TestParseAgentKitEvent(t *testing.T) {
	ev, err := parseAgentKitEvent([16]byte{1}, [16]byte{2}, []byte(`{"ts":"2099-01-01T00:00:00Z","type":"detection","severity":"Critical","rule":"artex_present","agent":{"id":"x","pid":-3}}`), nowForTest())
	if err != nil {
		t.Fatal(err)
	}
	if ev.Severity != "high" || ev.AgentPID != 0 || !ev.ObservedAt.Equal(nowForTest()) {
		t.Errorf("event %+v", ev)
	}
	for _, raw := range []string{`[]`, `{"type":"process","ts":"2026-01-01T00:00:00Z"}`, `{"type":"decision"}`, `nope`, `{"type":"sensor","ts":"2026-01-01T00:00:00Z","note":"a\u0000b"}`} {
		if _, err := parseAgentKitEvent([16]byte{1}, [16]byte{2}, []byte(raw), nowForTest()); err == nil {
			t.Errorf("%s accepted", raw)
		}
	}
}

func nowForTest() time.Time { return time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC) }
