package igaread

// The agent-runtime decoration's builders (agent_runtime.go): when a node is
// decorated and with what, which containment bears on it, and which grant
// edges a containment marks. No database.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

var arModelActions = []string{"bedrock:*", "bedrock-agentcore:InvokeAgentRuntime", "bedrock-agentcore:InvokeGateway", "bedrock-mantle:*"}

func arTestFacts() (*AgentRuntimeFacts, uuid.UUID, uuid.UUID) {
	w, cw := uuid.New(), uuid.New()
	at := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	return &AgentRuntimeFacts{
		Label: "suggested_agent", AIWorkload: true, Calls: 12, Denied: 1, LastCallAt: &at,
		Models:         map[string]int{"m1": 1, "m2": 9, "m3": 3, "m4": 3, "m5": 2, "m6": 7},
		SingleWorkload: &w,
		Suggestion:     &AgentRuntimeSuggestion{ID: uuid.New(), State: "pending"},
		Workloads:      map[uuid.UUID]AgentRuntimeWorkloadFacts{w: {CloudWorkloadID: cw, Label: "suggested_agent"}},
	}, w, cw
}

func TestAgentRuntimeIdentityDecoration(t *testing.T) {
	f, _, _ := arTestFacts()
	v := agentRuntimeOfIdentity(f)
	if v == nil || v.Label == nil || *v.Label != "suggested_agent" {
		t.Fatalf("decoration = %+v, want suggested_agent", v)
	}
	if v.ModelCalls == nil || v.ModelCalls.Calls != 12 || v.ModelCalls.Denied != 1 || v.ModelCalls.LastCallAt != "2026-11-04T10:00:00Z" {
		t.Fatalf("model_calls = %+v", v.ModelCalls)
	}
	// Top five by calls, then by model id.
	var got []string
	for _, m := range v.ModelCalls.Models {
		got = append(got, m.Model)
	}
	if strings.Join(got, ",") != "m2,m6,m3,m4,m5" {
		t.Errorf("models = %v, want m2,m6,m3,m4,m5", got)
	}
	if v.OpenAlerts.Count != 0 || v.OpenAlerts.HighestSeverity != nil || v.Suggestion == nil || v.Suggestion.State != "pending" ||
		v.Containment != nil {
		t.Errorf("decoration = %+v", v)
	}
	raw, _ := json.Marshal(v)
	for _, k := range []string{`"label"`, `"model_calls"`, `"open_alerts":{"count":0,"highest_severity":null}`, `"open_findings":0`, `"suggestion"`, `"containment":null`} {
		if !strings.Contains(string(raw), k) {
			t.Errorf("JSON %s lacks %s", raw, k)
		}
	}
}

func TestAgentRuntimeAbsentWithNothingToSay(t *testing.T) {
	if agentRuntimeOfIdentity(nil) != nil || agentRuntimeOfWorkload(nil, uuid.New()) != nil {
		t.Fatal("no facts must give no decoration")
	}
	// An agent with no model calls, no pending suggestion, no alert, no
	// finding and no live containment: nothing to say.
	w := uuid.New()
	f := &AgentRuntimeFacts{Label: "agent", SingleWorkload: &w,
		Suggestion: &AgentRuntimeSuggestion{ID: uuid.New(), State: "dismissed"},
		Workloads: map[uuid.UUID]AgentRuntimeWorkloadFacts{w: {CloudWorkloadID: uuid.New(), Label: "agent",
			Suggestion: &AgentRuntimeSuggestion{ID: uuid.New(), State: "dismissed"}}}}
	if v := agentRuntimeOfIdentity(f); v != nil {
		t.Errorf("identity decoration = %+v, want none", v)
	}
	if v := agentRuntimeOfWorkload(f, w); v != nil {
		t.Errorf("workload decoration = %+v, want none", v)
	}
	// A workload the identity's facts do not name.
	if v := agentRuntimeOfWorkload(f, uuid.New()); v != nil {
		t.Errorf("unknown workload decoration = %+v, want none", v)
	}
}

func TestAgentRuntimePresenceTriggers(t *testing.T) {
	for name, f := range map[string]*AgentRuntimeFacts{
		"open alert":         {OpenAlerts: 2, HighestSeverity: "high"},
		"open finding":       {OpenFindings: 1},
		"pending suggest":    {Suggestion: &AgentRuntimeSuggestion{ID: uuid.New(), State: "pending"}},
		"live containment":   {Containments: []AgentRuntimeContainment{{ID: uuid.New(), Level: AgentContainLevelModel, State: "previewed"}}},
		"refused calls only": {AIWorkload: true, Denied: 3},
	} {
		v := agentRuntimeOfIdentity(f)
		if v == nil {
			t.Errorf("%s: no decoration", name)
			continue
		}
		if v.Label != nil {
			t.Errorf("%s: label = %q, want null (the rule gives none)", name, *v.Label)
		}
		if (v.ModelCalls != nil) != f.AIWorkload {
			t.Errorf("%s: model_calls = %+v", name, v.ModelCalls)
		}
	}
	v := agentRuntimeOfIdentity(&AgentRuntimeFacts{OpenAlerts: 2, HighestSeverity: "high"})
	if v.OpenAlerts.Count != 2 || v.OpenAlerts.HighestSeverity == nil || *v.OpenAlerts.HighestSeverity != "high" {
		t.Errorf("open_alerts = %+v", v.OpenAlerts)
	}
	// A workload-level containment is the workload's, not the role's.
	wl := &AgentRuntimeFacts{Containments: []AgentRuntimeContainment{{ID: uuid.New(), Level: AgentContainLevelWorkload, State: "contained", InForce: true}}}
	if v := agentRuntimeOfIdentity(wl); v != nil {
		t.Errorf("identity with a workload-level containment = %+v, want none", v)
	}
}

func TestAgentRuntimeWorkloadOnSharedRole(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	ca, cb := uuid.New(), uuid.New()
	contain := AgentRuntimeContainment{ID: uuid.New(), Level: AgentContainLevelWorkload, State: "contained", InForce: true, WorkloadIDs: []uuid.UUID{cb}}
	f := &AgentRuntimeFacts{Label: "ai_workload", AIWorkload: true, Calls: 5, OpenFindings: 1, OpenAlerts: 1, HighestSeverity: "medium",
		Workloads:    map[uuid.UUID]AgentRuntimeWorkloadFacts{a: {CloudWorkloadID: ca}, b: {CloudWorkloadID: cb}},
		Containments: []AgentRuntimeContainment{contain}}
	// The role is the AI workload; its candidates carry neither its calls,
	// nor its alerts or findings.
	if v := agentRuntimeOfWorkload(f, a); v != nil {
		t.Errorf("candidate on a shared role = %+v, want none", v)
	}
	v := agentRuntimeOfWorkload(f, b)
	if v == nil || v.Label != nil || v.ModelCalls != nil || v.OpenAlerts.Count != 0 || v.OpenFindings != 0 ||
		v.Containment == nil || v.Containment.ID != contain.ID || v.Containment.Level != AgentContainLevelWorkload {
		t.Errorf("contained candidate = %+v, want only its workload-level containment", v)
	}
	r := agentRuntimeOfIdentity(f)
	if r == nil || *r.Label != "ai_workload" || r.ModelCalls.Calls != 5 || r.OpenFindings != 1 || r.Containment != nil {
		t.Errorf("shared role = %+v", r)
	}
	// An identity-level containment bears on every workload on the role.
	f.Containments = append(f.Containments, AgentRuntimeContainment{ID: uuid.New(), Level: AgentContainLevelIdentity, State: "contained", InForce: true})
	if v := agentRuntimeOfWorkload(f, a); v == nil || v.Containment == nil || v.Containment.Level != AgentContainLevelIdentity {
		t.Errorf("candidate under an identity-level containment = %+v", v)
	}
}

func TestAgentRuntimeSingleWorkload(t *testing.T) {
	f, w, cw := arTestFacts()
	f.OpenAlerts, f.HighestSeverity, f.OpenFindings = 1, "high", 2
	f.Workloads[w] = AgentRuntimeWorkloadFacts{CloudWorkloadID: cw, Label: "agent",
		Suggestion: &AgentRuntimeSuggestion{ID: f.Suggestion.ID, State: "pending"}}
	v := agentRuntimeOfWorkload(f, w)
	if v == nil || *v.Label != "agent" || v.ModelCalls == nil || v.ModelCalls.Calls != 12 || v.OpenAlerts.Count != 1 ||
		v.OpenFindings != 2 || v.Suggestion == nil || v.Suggestion.ID != f.Suggestion.ID {
		t.Errorf("single workload = %+v", v)
	}
}

func TestAgentRuntimeContainmentChoice(t *testing.T) {
	prev := AgentRuntimeContainment{ID: uuid.New(), Level: AgentContainLevelIdentity, State: "previewed"}
	model := AgentRuntimeContainment{ID: uuid.New(), Level: AgentContainLevelModel, State: "contained", InForce: true}
	ident := AgentRuntimeContainment{ID: uuid.New(), Level: AgentContainLevelIdentity, State: "contained", InForce: true}
	// In force before a preview, whatever the level.
	if c := agentRuntimeContainmentFor([]AgentRuntimeContainment{prev, model}, nil); c == nil || c.ID != model.ID {
		t.Errorf("preview vs in force = %+v, want the model level in force", c)
	}
	if c := agentRuntimeContainmentFor([]AgentRuntimeContainment{model, ident}, nil); c == nil || c.ID != ident.ID {
		t.Errorf("model vs identity = %+v, want identity", c)
	}
	// Edges: in force only; identity before model.
	if c := agentRuntimeEdgeContainment([]AgentRuntimeContainment{prev}); c != nil {
		t.Errorf("a preview marks edges: %+v", c)
	}
	if c := agentRuntimeEdgeContainment([]AgentRuntimeContainment{model, ident}); c == nil || c.ID != ident.ID {
		t.Errorf("edge containment = %+v, want identity", c)
	}
	wl := AgentRuntimeContainment{ID: uuid.New(), Level: AgentContainLevelWorkload, State: "contained", InForce: true}
	if c := agentRuntimeEdgeContainment([]AgentRuntimeContainment{wl}); c != nil {
		t.Errorf("a workload-level containment marks the role's grants: %+v", c)
	}
}

func TestAgentRuntimeGrantContained(t *testing.T) {
	ident := &AgentRuntimeContainment{ID: uuid.New(), Level: AgentContainLevelIdentity, InForce: true}
	model := &AgentRuntimeContainment{ID: uuid.New(), Level: AgentContainLevelModel, InForce: true}
	for _, tc := range []struct {
		actions []string
		model   bool
	}{
		{[]string{"bedrock:InvokeModel"}, true},
		{[]string{"Bedrock:Converse*"}, true},
		{[]string{"bedrock:*"}, true},
		{[]string{"*"}, true},
		{[]string{"bed*"}, true},
		{[]string{"bedrock-agentcore:InvokeAgentRuntime"}, true},
		{[]string{"bedrock-agentcore:Get*"}, false},
		{[]string{"bedrock-mantle:CreateChatCompletion"}, true},
		{[]string{"s3:GetObject", "s3:PutObject"}, false},
		{[]string{"s3:*", "bedrock:ListFoundationModels"}, true},
		{[]string{"?3:*"}, false},
		{nil, false},
		// NotAction: all actions except ...
		{[]string{"!s3:*"}, true},
		{[]string{"!bedrock:*"}, true}, // still allows the AgentCore invoke actions
		{[]string{"!bedrock*"}, false},
		{[]string{"!*"}, false},
	} {
		if got := agentRuntimeGrantContained(model, tc.actions, arModelActions); got != tc.model {
			t.Errorf("model level, actions %v: contained = %v, want %v", tc.actions, got, tc.model)
		}
		if !agentRuntimeGrantContained(ident, tc.actions, arModelActions) {
			t.Errorf("identity level, actions %v: not contained", tc.actions)
		}
	}
	if agentRuntimeGrantContained(nil, []string{"*"}, arModelActions) {
		t.Error("no containment marks a grant")
	}
}

func TestIAMGlobs(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"s3:Get*", "s3:*Object", true},
		{"s3:Get*", "s3:Put*", false},
		{"*", "x", true},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"", "", true},
		{"*a", "*b", false},
		{"*a*", "*b*", true},
	} {
		if got := iamGlobsIntersect(tc.a, tc.b); got != tc.want {
			t.Errorf("intersect(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
		if got := iamGlobsIntersect(tc.b, tc.a); got != tc.want {
			t.Errorf("intersect(%q, %q) = %v, want %v", tc.b, tc.a, got, tc.want)
		}
	}
	for _, tc := range []struct {
		p, q string
		want bool
	}{
		{"bedrock:*", "bedrock:*", true},
		{"bedrock*", "bedrock-mantle:*", true},
		{"bedrock:Invoke*", "bedrock:*", false},
		{"*", "anything*", true},
		{"bedrock:?", "bedrock:*", false},
	} {
		if got := iamGlobCovers(tc.p, tc.q); got != tc.want {
			t.Errorf("covers(%q, %q) = %v, want %v", tc.p, tc.q, got, tc.want)
		}
	}
}

// A node without agent-runtime data renders exactly as before: the field is
// absent, not null; an edge without a containment has no contained.
func TestAgentRuntimeFieldsAbsent(t *testing.T) {
	n, _ := json.Marshal(&GraphNode{Ref: "identity:x", Kind: "iam_role", Label: "r", State: "current", Limitations: []GraphLimitation{}})
	e, _ := json.Marshal(&GraphEdge{Claim: "grant:x", Kind: "grant", Limitations: []GraphLimitation{}})
	if strings.Contains(string(n), "agent_runtime") || strings.Contains(string(e), "contained") {
		t.Errorf("node %s / edge %s carry agent-runtime fields", n, e)
	}
}

// decorateContained marks only AWS grant edges from a contained identity, by
// the statement's actions at model level.
func TestDecorateContained(t *testing.T) {
	c := &AgentRuntimeContainment{ID: uuid.New(), Level: AgentContainLevelModel, InForce: true}
	role := &GraphNode{Ref: "identity:r", arContain: c}
	other := &GraphNode{Ref: "identity:o"}
	bedrock := &GraphNode{Ref: "statement:b", groupActions: []string{"bedrock:InvokeModel"}}
	s3 := &GraphNode{Ref: "statement:s", groupActions: []string{"s3:GetObject"}}
	nodes := map[string]*GraphNode{role.Ref: role, other.Ref: other, bedrock.Ref: bedrock, s3.Ref: s3}
	edges := []*GraphEdge{
		{Kind: GraphEdgeGrant, From: role.Ref, To: bedrock.Ref, side: "aws"},
		{Kind: GraphEdgeGrant, From: role.Ref, To: s3.Ref, side: "aws"},
		{Kind: GraphEdgeGrant, From: other.Ref, To: bedrock.Ref, side: "aws"},
		{Kind: GraphEdgeGrant, From: role.Ref, To: bedrock.Ref, side: "k8s"},
		{Kind: GraphEdgeTarget, From: bedrock.Ref, To: "resource:x", side: "aws"},
	}
	tr := &graphTraversal{modelActions: arModelActions}
	tr.decorateContained(edges, func(ref string) *GraphNode { return nodes[ref] })
	want := []bool{true, false, false, false, false}
	for i, e := range edges {
		if (e.Contained != nil) != want[i] {
			t.Errorf("edge %d contained = %+v, want %v", i, e.Contained, want[i])
		}
	}
	if edges[0].Contained.ID != c.ID || edges[0].Contained.Level != AgentContainLevelModel {
		t.Errorf("contained = %+v", edges[0].Contained)
	}
	// Identity level: every grant of the identity.
	role.arContain = &AgentRuntimeContainment{ID: uuid.New(), Level: AgentContainLevelIdentity, InForce: true}
	edges[1].Contained = nil
	tr.decorateContained(edges[1:2], func(ref string) *GraphNode { return nodes[ref] })
	if edges[1].Contained == nil || edges[1].Contained.Level != AgentContainLevelIdentity {
		t.Errorf("identity level s3 grant = %+v", edges[1].Contained)
	}
}
