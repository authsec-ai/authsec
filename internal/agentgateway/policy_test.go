package agentgateway

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type fakeRL struct {
	left  map[string]int
	taken int
}

func (f *fakeRL) Take(policyID, key string, perMinute int) bool {
	f.taken++
	k := policyID + "|" + key
	if _, ok := f.left[k]; !ok {
		f.left[k] = perMinute
	}
	if f.left[k] == 0 {
		return false
	}
	f.left[k]--
	return true
}

func toolReq(agent, server, tool string) Request {
	return Request{Kind: KindMCPTool, Action: ActionToolsCall, SubjectID: agent, Server: server, Tool: tool, GatewayID: "g1"}
}

func pol(id, name, effect, kind string, t Target) Policy {
	return Policy{ID: id, Name: name, Effect: effect, Kind: kind, Target: t, Enabled: true}
}

var monday10 = time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC) // a Monday

func TestEvaluateOrder(t *testing.T) {
	req := toolReq("billing-agent", "github", "create_issue")
	allow := pol("a", "allow-github", EffectAllow, KindMCPTool, Target{Server: "github"})
	deny := pol("d", "deny-create", EffectDeny, KindMCPTool, Target{Server: "github", Tool: "create_*"})

	cases := []struct {
		name     string
		ps       []Policy
		mode     string
		allowed  bool
		reason   string
		policyID string
	}{
		{"no policy, observe", nil, ModeObserve, true, ReasonDefaultAllow, ""},
		{"no policy, enforce", nil, ModeEnforce, false, ReasonDefaultDeny, ""},
		{"allow", []Policy{allow}, ModeEnforce, true, ReasonPolicyAllow, "a"},
		{"deny wins over allow", []Policy{allow, deny}, ModeObserve, false, ReasonPolicyDeny, "d"},
		{"deny wins whatever the priority", []Policy{func() Policy { p := allow; p.Priority = 100; return p }(), deny}, ModeObserve, false, ReasonPolicyDeny, "d"},
		{"disabled deny ignored", []Policy{allow, func() Policy { p := deny; p.Enabled = false; return p }()}, ModeEnforce, true, ReasonPolicyAllow, "a"},
		{"other kind ignored", []Policy{pol("m", "model", EffectDeny, KindModel, Target{})}, ModeObserve, true, ReasonDefaultAllow, ""},
		{"deny_unlisted denies an unlisted tool", []Policy{func() Policy {
			p := pol("l", "only-search", EffectAllow, KindMCPTool, Target{Tool: "search"})
			p.DenyUnlisted = true
			p.Subject.ClientID = "billing-*"
			return p
		}()}, ModeObserve, false, ReasonNotAllowlisted, "l"},
		{"deny_unlisted for another agent does not apply", []Policy{func() Policy {
			p := pol("l", "only-search", EffectAllow, KindMCPTool, Target{Tool: "search"})
			p.DenyUnlisted = true
			p.Subject.ClientID = "support-*"
			return p
		}()}, ModeObserve, true, ReasonDefaultAllow, ""},
	}
	for _, c := range cases {
		ps := append([]Policy(nil), c.ps...)
		SortPolicies(ps)
		res := Evaluate(ps, req, c.mode, monday10, nil)
		if res.Allowed != c.allowed || res.Reason != c.reason || res.PolicyID != c.policyID {
			t.Errorf("%s: got allowed=%v reason=%s policy=%s", c.name, res.Allowed, res.Reason, res.PolicyID)
		}
	}
}

func TestEvaluateDeterministicNaming(t *testing.T) {
	req := toolReq("a", "s", "t")
	d1 := pol("2", "b-deny", EffectDeny, KindMCPTool, Target{})
	d2 := pol("1", "a-deny", EffectDeny, KindMCPTool, Target{})
	d3 := pol("3", "z-deny", EffectDeny, KindMCPTool, Target{})
	d3.Priority = 5
	for i := 0; i < 5; i++ {
		ps := []Policy{d1, d2, d3}
		if i%2 == 1 {
			ps = []Policy{d3, d2, d1}
		}
		SortPolicies(ps)
		if res := Evaluate(ps, req, ModeObserve, monday10, nil); res.PolicyID != "3" {
			t.Fatalf("highest priority deny must be named, got %s", res.PolicyID)
		}
	}
	ps := []Policy{d1, d2}
	SortPolicies(ps)
	if res := Evaluate(ps, req, ModeObserve, monday10, nil); res.PolicyID != "1" {
		t.Fatalf("ties by name: got %s", res.PolicyID)
	}
}

func TestEvaluateSubjectSelector(t *testing.T) {
	req := toolReq("billing-agent", "github", "x")
	req.IdentityID, req.WorkloadID, req.Labels = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", []string{"prod"}
	cases := []struct {
		sel   Selector
		match bool
	}{
		{Selector{}, true},
		{Selector{ClientID: "billing-agent"}, true},
		{Selector{ClientID: "billing-*"}, true},
		{Selector{ClientID: "support-*"}, false},
		{Selector{IdentityID: "11111111-1111-1111-1111-111111111111"}, true},
		{Selector{IdentityID: "33333333-1111-1111-1111-111111111111"}, false},
		{Selector{WorkloadID: "22222222-2222-2222-2222-222222222222", AgentLabel: "prod"}, true},
		{Selector{AgentLabel: "dev"}, false},
		{Selector{GatewayID: "g1"}, true},
		{Selector{GatewayID: "g2"}, false},
		{Selector{ClientID: "billing-agent", AgentLabel: "dev"}, false},
	}
	for i, c := range cases {
		if got := c.sel.MatchesSubject(req); got != c.match {
			t.Errorf("case %d %+v: got %v", i, c.sel, got)
		}
	}
}

func TestTargetMatching(t *testing.T) {
	tool := toolReq("a", "github", "create_issue")
	tool.ServerURL = "https://api.githubcopilot.com/mcp/"
	model := Request{Kind: KindModel, SubjectID: "a", Provider: "openai", Model: "gpt-4o-mini"}
	cases := []struct {
		t     Target
		r     Request
		match bool
	}{
		{Target{Kind: KindMCPTool}, tool, true},
		{Target{Kind: KindMCPTool, Server: "git*"}, tool, true},
		{Target{Kind: KindMCPTool, ServerURL: "https://*.githubcopilot.com/*"}, tool, true},
		{Target{Kind: KindMCPTool, Tool: "*issue"}, tool, true},
		{Target{Kind: KindMCPTool, Tool: "delete_*"}, tool, false},
		{Target{Kind: KindModel}, tool, false},
		{Target{Kind: KindModel, Provider: "OpenAI", Model: "gpt-4o*"}, model, true},
		{Target{Kind: KindModel, Provider: "anthropic"}, model, false},
		{Target{Kind: KindModel, Model: "gpt-4o"}, model, false},
	}
	for i, c := range cases {
		if got := c.t.Matches(c.r); got != c.match {
			t.Errorf("case %d: got %v", i, got)
		}
	}
}

func TestGlob(t *testing.T) {
	for _, c := range []struct {
		p, s string
		ok   bool
	}{
		{"", "x", true}, {"*", "", true}, {"a", "a", true}, {"a", "ab", false},
		{"a*", "abc", true}, {"*c", "abc", true}, {"a*c", "abc", true}, {"a*c", "ac", true},
		{"a*b*c", "axxbyyc", true}, {"a*b*c", "axxc", false}, {"a*a", "a", false}, {"*.*", "a.b", true},
	} {
		if Glob(c.p, c.s) != c.ok {
			t.Errorf("Glob(%q,%q) != %v", c.p, c.s, c.ok)
		}
	}
}

func TestTimeWindow(t *testing.T) {
	w := &TimeWindow{Days: []string{"mon", "tue"}, Start: "09:00", End: "17:00", Timezone: "Europe/Berlin"}
	p := Policy{Name: "n", Effect: EffectAllow, Kind: KindMCPTool, Conditions: Conditions{TimeWindow: w}}
	if errs := p.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	if !w.Active(monday10) { // 11:00 in Berlin
		t.Fatal("monday 11:00 Berlin is inside")
	}
	if w.Active(time.Date(2026, 11, 2, 16, 30, 0, 0, time.UTC)) { // 17:30 Berlin
		t.Fatal("17:30 Berlin is outside")
	}
	if w.Active(time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)) { // Wednesday
		t.Fatal("wednesday is outside")
	}
	night := &TimeWindow{Start: "22:00", End: "06:00"}
	if !night.Active(time.Date(2026, 11, 2, 23, 0, 0, 0, time.UTC)) || !night.Active(time.Date(2026, 11, 2, 5, 59, 0, 0, time.UTC)) ||
		night.Active(time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)) {
		t.Fatal("window across midnight")
	}

	// A deny inside its window denies; outside it falls through, and the
	// decision may be cached only until the next minute boundary.
	deny := pol("d", "weekday-deny", EffectDeny, KindMCPTool, Target{})
	deny.Conditions.TimeWindow = w
	now := monday10.Add(20 * time.Second)
	res := Evaluate([]Policy{deny}, toolReq("a", "s", "t"), ModeObserve, now, nil)
	if res.Allowed || res.TTLCap != 40*time.Second {
		t.Fatalf("inside: %+v", res)
	}
	res = Evaluate([]Policy{deny}, toolReq("a", "s", "t"), ModeObserve, time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC), nil)
	if !res.Allowed || res.Reason != ReasonDefaultAllow || res.TTLCap == 0 {
		t.Fatalf("outside: %+v", res)
	}
}

func TestRateCondition(t *testing.T) {
	allow := pol("a", "allow-3", EffectAllow, KindMCPTool, Target{})
	allow.Conditions.MaxCallsPerMinute = 3
	rl := &fakeRL{left: map[string]int{}}
	req := toolReq("a", "s", "t")
	for i := 0; i < 3; i++ {
		res := Evaluate([]Policy{allow}, req, ModeEnforce, monday10, rl)
		if !res.Allowed || res.Cacheable {
			t.Fatalf("call %d: %+v", i, res)
		}
	}
	res := Evaluate([]Policy{allow}, req, ModeEnforce, monday10, rl)
	if res.Allowed || res.Reason != ReasonRateLimited || res.PolicyID != "a" {
		t.Fatalf("4th call: %+v", res)
	}
	// Another agent has its own bucket.
	if res := Evaluate([]Policy{allow}, toolReq("b", "s", "t"), ModeEnforce, monday10, rl); !res.Allowed {
		t.Fatal("other agent limited")
	}
	// A second allow without a rate still allows past the limit.
	other := pol("b", "allow-any", EffectAllow, KindMCPTool, Target{})
	ps := []Policy{allow, other}
	SortPolicies(ps)
	if res := Evaluate(ps, req, ModeEnforce, monday10, rl); !res.Allowed || res.PolicyID != "b" {
		t.Fatalf("fallback allow: %+v", res)
	}
	// A dry run (nil limiter) never takes a token.
	before := rl.taken
	if res := Evaluate([]Policy{allow}, req, ModeEnforce, monday10, nil); !res.Allowed {
		t.Fatal("dry run refused")
	}
	if rl.taken != before {
		t.Fatal("dry run took a token")
	}
}

func TestValidate(t *testing.T) {
	bad := []Policy{
		{Name: "", Effect: EffectAllow, Kind: KindMCPTool},
		{Name: "x", Effect: "maybe", Kind: KindMCPTool},
		{Name: "x", Effect: EffectAllow, Kind: "agent"},
		{Name: "x", Effect: EffectAllow, Kind: KindModel, Target: Target{Tool: "t"}},
		{Name: "x", Effect: EffectAllow, Kind: KindMCPTool, Target: Target{Model: "m"}},
		{Name: "x", Effect: EffectDeny, Kind: KindMCPTool, DenyUnlisted: true},
		{Name: "x", Effect: EffectDeny, Kind: KindMCPTool, Conditions: Conditions{MaxCallsPerMinute: 5}},
		{Name: "x", Effect: EffectAllow, Kind: KindMCPTool, Conditions: Conditions{TimeWindow: &TimeWindow{Start: "9:00", End: "10:00"}}},
		{Name: "x", Effect: EffectAllow, Kind: KindMCPTool, Conditions: Conditions{TimeWindow: &TimeWindow{Days: []string{"funday"}}}},
		{Name: "x", Effect: EffectAllow, Kind: KindMCPTool, Conditions: Conditions{TimeWindow: &TimeWindow{Timezone: "Mars/Olympus"}}},
		{Name: "x", Effect: EffectAllow, Kind: KindMCPTool, Subject: Selector{IdentityID: "not-a-uuid"}},
	}
	for i, p := range bad {
		if errs := p.Validate(); len(errs) == 0 {
			t.Errorf("case %d accepted", i)
		}
	}
	good := Policy{Name: " ok ", Effect: EffectAllow, Kind: KindModel, Target: Target{Provider: "OpenAI", Model: "gpt-*"},
		Subject: Selector{IdentityID: "11111111-1111-1111-1111-111111111111"}, DenyUnlisted: true,
		Conditions: Conditions{MaxCallsPerMinute: 60, TimeWindow: &TimeWindow{Days: []string{"MON"}}}}
	if errs := good.Validate(); len(errs) > 0 {
		t.Fatal(errs)
	}
	if good.Name != "ok" || good.Target.Provider != "openai" || good.Conditions.TimeWindow.Days[0] != "mon" {
		t.Fatalf("not normalised: %+v", good)
	}
	if _, err := ParseConditions([]byte(`{"max_calls_per_minute": 5, "typo": 1}`)); err == nil {
		t.Fatal("unknown condition accepted")
	}
}

func TestDenyTargets(t *testing.T) {
	ps := []Policy{
		pol("1", "a", EffectDeny, KindMCPTool, Target{Server: "github", Tool: "delete_*"}),
		pol("2", "b", EffectAllow, KindMCPTool, Target{Server: "github"}),
		func() Policy {
			p := pol("3", "c", EffectDeny, KindModel, Target{Provider: "openai"})
			p.Enabled = false
			return p
		}(),
	}
	got := DenyTargets(ps)
	if len(got) != 1 || got[0].Tool != "delete_*" || got[0].Kind != KindMCPTool {
		t.Fatalf("%+v", got)
	}
	if !got[0].Matches(toolReq("x", "github", "delete_repo")) {
		t.Fatal("hint does not match its target")
	}
}

/* --------------------------------- AuthZEN -------------------------------- */

func TestFromAuthZENTool(t *testing.T) {
	raw := `{"subject":{"type":"agent","id":"billing-agent","properties":{"labels":["prod"],"identity_id":"11111111-1111-1111-1111-111111111111"}},
	 "action":{"name":"tools/call"},
	 "resource":{"type":"mcp_tool","id":"github/create_issue","properties":{"server":"github","tool":"create_issue","server_url":"https://x/mcp"}},
	 "context":{"args_digest":"sha256:` + strings.Repeat("a", 64) + `","request_id":"r1","prompt":"never kept"}}`
	var e EvaluationRequest
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		t.Fatal(err)
	}
	r, err := FromAuthZEN(e)
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != KindMCPTool || r.Server != "github" || r.Tool != "create_issue" || r.SubjectID != "billing-agent" ||
		r.Labels[0] != "prod" || r.RequestID != "r1" || r.ResourceID() != "github/create_issue" {
		t.Fatalf("%+v", r)
	}
	// Round trip through the gateway's side.
	back, err := FromAuthZEN(r.ToAuthZEN())
	if err != nil || CacheKeyForTest(back) != CacheKeyForTest(r) {
		t.Fatalf("round trip: %v %+v", err, back)
	}
}

// CacheKeyForTest compares requests field by field.
func CacheKeyForTest(r Request) string {
	b, _ := json.Marshal(r)
	return string(b)
}

func TestFromAuthZENModelAndErrors(t *testing.T) {
	ok := EvaluationRequest{Subject: &Entity{Type: "agent", ID: "a"}, Action: &Action{Name: ActionModelInvoke,
		Properties: map[string]any{"operation": "chat.completions"}}, Resource: &Entity{Type: "model", ID: "OpenAI/gpt-4o"}}
	r, err := FromAuthZEN(ok)
	if err != nil || r.Provider != "openai" || r.Model != "gpt-4o" || r.Operation != "chat.completions" {
		t.Fatalf("%v %+v", err, r)
	}
	// A model id may itself contain '/'.
	r, err = FromAuthZEN(EvaluationRequest{Subject: &Entity{Type: "agent", ID: "a"}, Action: &Action{Name: ActionModelInvoke},
		Resource: &Entity{Type: "model", ID: "bedrock/meta/llama-3"}})
	if err != nil || r.Provider != "bedrock" || r.Model != "meta/llama-3" {
		t.Fatalf("%v %+v", err, r)
	}
	bad := []EvaluationRequest{
		{},
		{Subject: &Entity{Type: "user", ID: "a"}, Action: &Action{Name: ActionToolsCall}, Resource: &Entity{Type: "mcp_tool", ID: "s/t"}},
		{Subject: &Entity{Type: "agent", ID: ""}, Action: &Action{Name: ActionToolsCall}, Resource: &Entity{Type: "mcp_tool", ID: "s/t"}},
		{Subject: &Entity{Type: "agent", ID: "a"}, Action: &Action{Name: "read"}, Resource: &Entity{Type: "mcp_tool", ID: "s/t"}},
		{Subject: &Entity{Type: "agent", ID: "a"}, Action: &Action{Name: ActionToolsCall}, Resource: &Entity{Type: "file", ID: "x"}},
		{Subject: &Entity{Type: "agent", ID: "a"}, Action: &Action{Name: ActionToolsCall}, Resource: &Entity{Type: "mcp_tool", ID: "only-server"}},
		{Subject: &Entity{Type: "agent", ID: "a"}, Action: &Action{Name: ActionToolsCall},
			Resource: &Entity{Type: "mcp_tool", ID: "a/b", Properties: map[string]any{"server": "c", "tool": "d"}}},
		{Subject: &Entity{Type: "agent", ID: "a", Properties: map[string]any{"identity_id": "nope"}}, Action: &Action{Name: ActionToolsCall}, Resource: &Entity{Type: "mcp_tool", ID: "s/t"}},
		{Subject: &Entity{Type: "agent", ID: "a"}, Action: &Action{Name: ActionToolsCall}, Resource: &Entity{Type: "mcp_tool", ID: "s/t"},
			Context: map[string]any{"args_digest": "md5:abc"}},
		{Subject: &Entity{Type: "agent", ID: "a"}, Action: &Action{Name: ActionModelInvoke, Properties: map[string]any{"operation": "fine_tune"}}, Resource: &Entity{Type: "model", ID: "p/m"}},
	}
	for i, e := range bad {
		if _, err := FromAuthZEN(e); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

func TestBatchExpandAndSemantics(t *testing.T) {
	raw := `{"subject":{"type":"agent","id":"a"},"action":{"name":"tools/call"},
	  "evaluations":[{"resource":{"type":"mcp_tool","id":"s/one"}},
	                 {"subject":{"type":"agent","id":"b"},"resource":{"type":"mcp_tool","id":"s/two"}}],
	  "options":{"evaluations_semantic":"deny_on_first_deny"}}`
	var b EvaluationsRequest
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		t.Fatal(err)
	}
	evals, single, err := b.Expand()
	if err != nil || single || len(evals) != 2 {
		t.Fatalf("%v %v %d", err, single, len(evals))
	}
	if evals[0].Subject.ID != "a" || evals[1].Subject.ID != "b" || evals[1].Action.Name != "tools/call" {
		t.Fatal("defaults not applied, or an evaluation's own key not kept")
	}
	if b.Semantic() != SemanticDenyOnFirstDeny || !Stop(b.Semantic(), false) || Stop(b.Semantic(), true) {
		t.Fatal("deny_on_first_deny")
	}
	if !Stop(SemanticPermitOnFirstPermit, true) || Stop(SemanticExecuteAll, false) {
		t.Fatal("semantics")
	}
	// No evaluations: a single (backwards compatible) evaluation.
	b2 := EvaluationsRequest{Subject: &Entity{Type: "agent", ID: "a"}}
	if evals, single, err := b2.Expand(); err != nil || !single || len(evals) != 1 {
		t.Fatal("single form")
	}
	bad := EvaluationsRequest{Options: &EvaluationsOptions{EvaluationsSemantic: "majority"}}
	if _, _, err := bad.Expand(); err == nil {
		t.Fatal("unknown semantic accepted")
	}
	big := EvaluationsRequest{Evaluations: make([]EvaluationRequest, MaxBatchEvaluations+1)}
	if _, _, err := big.Expand(); err == nil {
		t.Fatal("oversized batch accepted")
	}
	er := ErrorResponse(400, "x")
	if er.Decision || er.Context["error"].(map[string]any)["status"] != 400 {
		t.Fatal("per-evaluation error shape (§7.2.1)")
	}
}

func TestDigestArguments(t *testing.T) {
	a, err := DigestArguments(json.RawMessage(`{"b":1,"a":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := DigestArguments(json.RawMessage(`{ "a":"x", "b":1.0 }`))
	if a != b || !ValidDigest(a) {
		t.Fatalf("RFC 8785 digest not canonical: %s %s", a, b)
	}
	empty, _ := DigestArguments(nil)
	obj, _ := DigestArguments(json.RawMessage(`{}`))
	if empty != obj {
		t.Fatal("absent arguments digest as {}")
	}
}
