package services

import (
	"encoding/json"
	"strings"
	"testing"
)

// A secret value must never survive extraction, at ANY depth.
//
// This is the adversarial case that the previous code passed straight through:
// the manifest rule copied `tools` verbatim, so a credential nested inside an
// array of objects reached discovered_agents.metadata, iga_source_objects and
// iga_observations untouched. A top-level key check cannot see it — it sees
// only the key "tools" and waves the subtree through.
//
// The rule catalogue always DECLARED apiKey sensitive. Nothing enforced it.
func TestExtractRedactedStripsNestedSecretValues(t *testing.T) {
	const liveKey = "sk-live-MUST-NEVER-BE-PERSISTED"

	manifest, err := json.Marshal(map[string]interface{}{
		"name":  "billing-agent",
		"model": "gpt-4o",
		// The leak: a credential two levels down, inside an array of objects.
		"tools": []interface{}{
			map[string]interface{}{"name": "db", "apiKey": liveKey},
			map[string]interface{}{"name": "search", "api_key": liveKey},
			// Separator and case variants must all be caught.
			map[string]interface{}{"name": "mail", "APIKEY": liveKey},
			// Deeper still: a map inside a map inside the array.
			map[string]interface{}{
				"name": "vault",
				"auth": map[string]interface{}{
					"nested": map[string]interface{}{"token": liveKey},
				},
			},
		},
		"instructions": "SYSTEM PROMPT: you are a billing agent",
	})
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	rule, ok := DefaultRuleCatalog().MatchRule("agent.json")
	if !ok {
		t.Fatal("expected the catalogue to claim agent.json")
	}

	facts, secretRefs, err := rule.ExtractRedacted("agent.json", manifest)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if facts == nil {
		t.Fatal("expected facts from a well-formed manifest")
	}

	// The whole point: serialise exactly what would be persisted and assert the
	// value is nowhere in it. Checking individual fields would miss a new
	// verbatim-copy branch; checking the serialised blob cannot.
	blob, err := json.Marshal(facts)
	if err != nil {
		t.Fatalf("marshal facts: %v", err)
	}
	if strings.Contains(string(blob), liveKey) {
		t.Fatalf("SECRET VALUE PERSISTED in extracted facts: %s", blob)
	}
	if strings.Contains(string(blob), "SYSTEM PROMPT") {
		t.Fatalf("prompt body persisted in extracted facts: %s", blob)
	}

	// Redaction must not be destruction: the non-sensitive names are the
	// evidence, and they have to survive.
	if facts["name"] != "billing-agent" {
		t.Fatalf("the agent name must survive redaction, got %v", facts["name"])
	}
	if !strings.Contains(string(blob), "\"db\"") || !strings.Contains(string(blob), "\"vault\"") {
		t.Fatalf("tool NAMES must survive redaction: %s", blob)
	}
	// And the marker records that a credential was declared, which is the
	// finding: "this tool declares an apiKey" without the key.
	if !strings.Contains(string(blob), RedactedMarker) {
		t.Fatalf("expected the redaction marker to record the declared secret: %s", blob)
	}

	// The secret NAMES are still harvested as separate evidence.
	if len(secretRefs) == 0 {
		t.Log("note: no secret names harvested from this manifest shape")
	}
	t.Logf("PASS: value stripped at every depth, names kept — facts=%s", blob)
}

// Every rule gets the redaction floor, including one that declares no
// SensitiveKeys of its own.
//
// Per-rule keys are author-supplied, so relying on them alone means a new rule
// written next quarter can silently persist a credential. The floor makes a
// forgotten key a missing nicety instead of a breach.
func TestExtractRedactedAppliesBaselineToEveryRule(t *testing.T) {
	const liveKey = "ghp_MUST_NEVER_BE_PERSISTED"
	cat := DefaultRuleCatalog()

	if len(cat.Rules) == 0 {
		t.Fatal("empty catalogue")
	}

	for _, rule := range cat.Rules {
		// Feed every rule a JSON document carrying a nested credential. Rules
		// that cannot parse it simply return an error or nil facts, which is a
		// pass: nothing was extracted, so nothing could leak.
		payload, _ := json.Marshal(map[string]interface{}{
			"name": "probe",
			"tools": []interface{}{
				map[string]interface{}{"name": "t", "token": liveKey},
			},
			"env":         map[string]interface{}{"OPENAI_API_KEY": liveKey},
			"credentials": liveKey,
		})

		facts, _, err := rule.ExtractRedacted("agent.json", payload)
		if err != nil || facts == nil {
			continue
		}
		blob, _ := json.Marshal(facts)
		if strings.Contains(string(blob), liveKey) {
			t.Fatalf("rule %s@%s persisted a secret value: %s", rule.ID, rule.Version, blob)
		}
	}
	t.Logf("PASS: all %d catalogue rules redact a nested credential", len(cat.Rules))
}

// redactValue must preserve structure while stripping values, so the shape of
// the evidence still reads correctly to a reviewer.
func TestRedactValuePreservesShape(t *testing.T) {
	sensitive := sensitiveKeySet([]string{"custom_key"})

	in := map[string]interface{}{
		"keep": "visible",
		"list": []interface{}{
			map[string]interface{}{"keep": "yes", "token": "SECRET"},
		},
		"custom_key": "SECRET",
		"deep": map[string]interface{}{
			"deeper": map[string]interface{}{"password": "SECRET", "label": "fine"},
		},
	}

	out, ok := redactValue(in, sensitive).(map[string]interface{})
	if !ok {
		t.Fatal("expected a map back")
	}
	blob, _ := json.Marshal(out)
	if strings.Contains(string(blob), "SECRET") {
		t.Fatalf("value survived redaction: %s", blob)
	}
	if out["keep"] != "visible" {
		t.Fatalf("non-sensitive value must survive, got %v", out["keep"])
	}
	if out["custom_key"] != RedactedMarker {
		t.Fatalf("a rule-declared sensitive key must be redacted, got %v", out["custom_key"])
	}
	// Structure intact: the list is still a list of one object with its name.
	list, ok := out["list"].([]interface{})
	if !ok || len(list) != 1 {
		t.Fatalf("list structure lost: %v", out["list"])
	}
	first, ok := list[0].(map[string]interface{})
	if !ok || first["keep"] != "yes" || first["token"] != RedactedMarker {
		t.Fatalf("nested object not redacted in place: %v", list[0])
	}
	deep := out["deep"].(map[string]interface{})["deeper"].(map[string]interface{})
	if deep["password"] != RedactedMarker || deep["label"] != "fine" {
		t.Fatalf("deep redaction wrong: %v", deep)
	}
	t.Logf("PASS: shape preserved, values stripped — %s", blob)
}

// Key matching is case- and separator-insensitive, so apiKey, api_key, API-KEY
// and APIKEY are one key. A rule author writing any spelling gets all of them.
func TestSensitiveKeyMatchingIsNormalised(t *testing.T) {
	sensitive := sensitiveKeySet(nil)
	for _, spelling := range []string{"apiKey", "api_key", "API-KEY", "APIKEY", "Api_Key"} {
		if _, ok := sensitive[normalizeKey(spelling)]; !ok {
			t.Fatalf("spelling %q must be recognised as sensitive", spelling)
		}
	}
	// A legitimately-named field must NOT be swept up: over-redaction destroys
	// evidence just as surely as under-redaction leaks it.
	for _, safe := range []string{"name", "model", "repository", "path", "tools", "mcp_servers"} {
		if _, ok := sensitive[normalizeKey(safe)]; ok {
			t.Fatalf("field %q must stay visible; redacting it would destroy evidence", safe)
		}
	}
	t.Log("PASS: spelling variants caught, evidence fields untouched")
}
