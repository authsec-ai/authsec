package services

import (
	"strings"
	"testing"
)

// An overlay ADDS to the shipped vocabulary rather than replacing it.
//
// This is the property that keeps a customising workspace current: if an
// overlay stored the whole list, editing once would freeze that workspace on
// that day's tokens and it would silently stop receiving every marker shipped
// afterwards — a regression with no symptom.
func TestOverlayAddsWithoutFreezingTheBuiltInVocabulary(t *testing.T) {
	o := RuleCatalogOverlay{}
	o.Vocabularies.ActionMarkers.Add = []string{"mycorp/agent-action"}

	_, vocab := ApplyOverlay(o)

	if !contains(vocab.ActionMarkers, "mycorp/agent-action") {
		t.Fatal("the added marker is missing")
	}
	// Every shipped marker must survive.
	for _, builtin := range agentActionMarkers {
		if !contains(vocab.ActionMarkers, builtin) {
			t.Fatalf("overlay dropped built-in marker %q; a customised workspace "+
				"must still receive the patterns we ship", builtin)
		}
	}
	t.Logf("PASS: %d built-in markers preserved, 1 added", len(agentActionMarkers))
}

// Removal is supported, and is the only thing that drops a built-in.
func TestOverlayCanRemoveANoisyToken(t *testing.T) {
	o := RuleCatalogOverlay{}
	o.Vocabularies.FrameworkTokens.Remove = []string{"ollama"}

	_, vocab := ApplyOverlay(o)
	if contains(vocab.FrameworkTokens, "ollama") {
		t.Fatal("removed token is still present")
	}
	if !contains(vocab.FrameworkTokens, "langchain") {
		t.Fatal("removing one token must not disturb the others")
	}
	t.Log("PASS: one token removed, the rest intact")
}

// A custom rule points new globs at an EXISTING parser.
func TestCustomRuleReusesARegisteredExtractor(t *testing.T) {
	o := RuleCatalogOverlay{CustomRules: []CustomRule{{
		ID: "custom.bot-manifest", Extractor: "manifest",
		PathGlobs: []string{"bot.json", "*.bot.json"},
	}}}
	if err := o.Validate(); err != nil {
		t.Fatalf("valid custom rule rejected: %v", err)
	}
	cat, _ := ApplyOverlay(o)

	r, ok := cat.MatchRule("bot.json")
	if !ok || r.ID != "custom.bot-manifest" {
		t.Fatalf("custom rule did not claim its path, got %+v ok=%v", r, ok)
	}
	if r.Extract == nil {
		t.Fatal("a custom rule must be bound to a real parser, not left nil")
	}
	// Unstated evidence must default to the WEAKEST reading — a custom rule
	// cannot claim stronger evidence than it was configured to.
	if r.EvidenceMode != "framework_dependency" {
		t.Fatalf("unstated evidence_mode should default to the weakest, got %q", r.EvidenceMode)
	}
	t.Log("PASS: custom rule bound to the manifest parser, evidence defaulted to weakest")
}

// The catalogue is also the fetch budget, so a glob that matches everything is
// refused. Left in, it turns a scan of a large repository into a download of it.
func TestOverbroadGlobsAreRefused(t *testing.T) {
	for _, bad := range []string{"*", "**", "*.*", "", "a", "../etc/passwd"} {
		o := RuleCatalogOverlay{CustomRules: []CustomRule{{
			ID: "custom.toobroad", Extractor: "text", PathGlobs: []string{bad},
		}}}
		if err := o.Validate(); err == nil {
			t.Fatalf("glob %q should have been refused: it would make every scan "+
				"download the whole repository", bad)
		}
	}
	// A specific glob is fine.
	ok := RuleCatalogOverlay{CustomRules: []CustomRule{{
		ID: "custom.fine", Extractor: "text", PathGlobs: []string{"*.agentrc.yaml"},
	}}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("a specific glob was refused: %v", err)
	}
	t.Log("PASS: over-broad globs refused, specific ones accepted")
}

// A two-character token matches almost every file. The resulting inventory is
// noise, and an inventory nobody trusts gets ignored — at which point the real
// findings inside it are missed too.
func TestTooShortTokensAreRefused(t *testing.T) {
	o := RuleCatalogOverlay{}
	o.Vocabularies.FrameworkTokens.Add = []string{"ai"}
	if err := o.Validate(); err == nil {
		t.Fatal("a 2-character token should be refused")
	}
	o.Vocabularies.FrameworkTokens.Add = []string{"mycorp-agent-sdk"}
	if err := o.Validate(); err != nil {
		t.Fatalf("a specific token was refused: %v", err)
	}
	t.Log("PASS: short tokens refused")
}

// Config may only select a parser that exists, and may not shadow a built-in.
func TestUnknownExtractorAndBuiltInCollisionRefused(t *testing.T) {
	o := RuleCatalogOverlay{CustomRules: []CustomRule{{
		ID: "custom.x", Extractor: "eval-arbitrary-code", PathGlobs: []string{"thing.json"},
	}}}
	err := o.Validate()
	if err == nil || !strings.Contains(err.Error(), "unknown extractor") {
		t.Fatalf("an unregistered extractor must be refused, got %v", err)
	}

	o = RuleCatalogOverlay{CustomRules: []CustomRule{{
		ID: "workflow.agent-invocation", Extractor: "text", PathGlobs: []string{"thing.json"},
	}}}
	if err := o.Validate(); err == nil {
		t.Fatal("a custom rule must not shadow a built-in id")
	}

	o = RuleCatalogOverlay{Rules: map[string]RuleOverlay{"no.such.rule": {}}}
	if err := o.Validate(); err == nil {
		t.Fatal("tuning a rule that does not exist must be refused")
	}
	t.Log("PASS: unknown extractor, built-in collision and unknown rule all refused")
}

// Disabling a rule removes it from the effective catalogue entirely.
func TestDisablingARuleStopsItMatching(t *testing.T) {
	off := false
	o := RuleCatalogOverlay{Rules: map[string]RuleOverlay{
		"dependency.manifest": {Enabled: &off},
	}}
	cat, _ := ApplyOverlay(o)
	if _, ok := cat.MatchRule("requirements.txt"); ok {
		t.Fatal("a disabled rule must not claim paths")
	}
	// An overlay that only tweaks globs must NOT disable the rule — which is
	// why Enabled is a pointer rather than a plain bool.
	o2 := RuleCatalogOverlay{Rules: map[string]RuleOverlay{
		"dependency.manifest": {PathGlobs: StringDelta{Add: []string{"constraints.txt"}}},
	}}
	cat2, _ := ApplyOverlay(o2)
	if _, ok := cat2.MatchRule("requirements.txt"); !ok {
		t.Fatal("editing globs must not implicitly disable the rule")
	}
	if _, ok := cat2.MatchRule("constraints.txt"); !ok {
		t.Fatal("the added glob does not match")
	}
	t.Log("PASS: disable works; a glob-only edit leaves the rule enabled")
}

// The effective version must change when patterns change, and be stable when
// they do not — it is stamped on findings and drives the stale/rescan prompt.
func TestVersionTracksTheOverlayAndIsStable(t *testing.T) {
	base := DefaultRuleCatalog().Version

	plain, _ := ApplyOverlay(RuleCatalogOverlay{})
	if plain.Version != base {
		t.Fatalf("an empty overlay must not change the version, got %q", plain.Version)
	}

	o := RuleCatalogOverlay{}
	o.Vocabularies.ActionMarkers.Add = []string{"mycorp/agent-action"}
	a, _ := ApplyOverlay(o)
	if a.Version == base {
		t.Fatal("a customised catalogue must be distinguishable from the built-in one")
	}

	// Same overlay, recomputed: the hash must not drift, or every read would
	// mark every finding stale for no reason.
	b, _ := ApplyOverlay(o)
	if a.Version != b.Version {
		t.Fatalf("version is not stable: %q then %q", a.Version, b.Version)
	}

	o.Vocabularies.ActionMarkers.Add = append(o.Vocabularies.ActionMarkers.Add, "other/action")
	cc, _ := ApplyOverlay(o)
	if cc.Version == a.Version {
		t.Fatal("changing the patterns must change the version")
	}
	t.Logf("PASS: %s -> %s -> %s", base, a.Version, cc.Version)
}

// The dry run answers "would this path be picked up?" without a GitHub call.
func TestTestPathsExplainsMatchesAndMisses(t *testing.T) {
	res := TestPaths(RuleCatalogOverlay{}, []string{
		".github/workflows/ci.yml",
		"README.md",
		"node_modules/left-pad/package.json",
	})
	if !res[0].Matched || res[0].RuleID != "workflow.agent-invocation" {
		t.Fatalf("workflow should match: %+v", res[0])
	}
	if res[1].Matched || res[1].Reason == "" {
		t.Fatalf("an unmatched path must say why: %+v", res[1])
	}
	// Vendored paths are somebody else's code, and a repository that commits
	// its dependencies would otherwise contribute thousands of fetches.
	if res[2].Matched || !strings.Contains(res[2].Reason, "vendored") {
		t.Fatalf("vendored path should be excluded with a reason: %+v", res[2])
	}
	t.Log("PASS: dry run reports match, miss and vendored-skip with reasons")
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
