package services

import (
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/models"
)

// The graph source's facts (agent_runtime_graph.go) over in-memory state: the
// labels are the inference service's own (the AI-workloads list and the
// resolver), on the identity and on each of its workloads.

func arGraphState(ident *arIdentity, u *agentruntime.ModelCallUsage, wls ...*arWorkload) *agentRuntimeState {
	st := &agentRuntimeState{
		connectors: map[uuid.UUID]arConnector{}, identities: map[uuid.UUID]*arIdentity{ident.ID: ident},
		usage: map[uuid.UUID]*arUsage{}, workloads: map[uuid.UUID][]*arWorkload{ident.ID: wls},
		k8s: map[uuid.UUID][]string{}, saml: map[uuid.UUID]bool{},
		suggestions: map[uuid.UUID]*arSuggestion{}, openFindings: map[uuid.UUID]int{},
	}
	if u != nil {
		st.usage[ident.ID] = &arUsage{ID: uuid.New(), IdentityID: ident.ID, usage: *u}
	}
	return st
}

func arGraphIdent() *arIdentity {
	return &arIdentity{ID: uuid.New(), Kind: models.CloudIdentityIAMRole, NativeID: "arn:aws:iam::111122223333:role/bot"}
}

func TestAgentRuntimeGraphFactsLabels(t *testing.T) {
	acting := map[string]int{"s3.amazonaws.com": 4}
	t.Run("model calls only: ai_workload on the role and its one workload", func(t *testing.T) {
		ident, w := arGraphIdent(), arTestWorkload("bot", true, models.ClassificationUnclassified)
		u := arTestUsage(3, 0, nil)
		f := arGraphFacts(arGraphState(ident, &u, w), ident)
		if f.Label != agentruntime.LabelAIWorkload || !f.AIWorkload || f.Calls != 3 || f.SingleWorkload == nil || *f.SingleWorkload != *w.GraphID {
			t.Fatalf("facts = %+v", f)
		}
		if got := f.Workloads[*w.GraphID]; got.Label != agentruntime.LabelAIWorkload || got.CloudWorkloadID != w.ID {
			t.Errorf("workload facts = %+v", got)
		}
	})
	t.Run("acted on other services: suggested_agent, as the list says", func(t *testing.T) {
		ident, w := arGraphIdent(), arTestWorkload("bot", true, models.ClassificationUnclassified)
		u := arTestUsage(3, 0, acting)
		st := arGraphState(ident, &u, w)
		f := arGraphFacts(st, ident)
		ai := st.buildAIWorkload(ident, st.usage[ident.ID])
		if f.Label != agentruntime.LabelSuggestedAgent || f.Label != ai.Label || f.Workloads[*w.GraphID].Label != ai.Label {
			t.Errorf("labels = %q / %q, list says %q", f.Label, f.Workloads[*w.GraphID].Label, ai.Label)
		}
	})
	t.Run("dismissed: an AI workload again, with the suggestion shown", func(t *testing.T) {
		ident, w := arGraphIdent(), arTestWorkload("bot", true, models.ClassificationUnclassified)
		u := arTestUsage(3, 0, acting)
		st := arGraphState(ident, &u, w)
		sid := uuid.New()
		st.suggestions[*w.GraphID] = &arSuggestion{ID: sid, WorkloadID: *w.GraphID, State: SuggestionDismissed, Reason: "pipeline"}
		f := arGraphFacts(st, ident)
		if f.Label != agentruntime.LabelAIWorkload || f.Suggestion == nil || f.Suggestion.ID != sid ||
			f.Workloads[*w.GraphID].Suggestion == nil || f.Workloads[*w.GraphID].Suggestion.State != SuggestionDismissed {
			t.Errorf("facts = %+v", f)
		}
	})
	t.Run("classified agent: agent", func(t *testing.T) {
		ident, w := arGraphIdent(), arTestWorkload("bot", true, models.ClassificationClassified)
		u := arTestUsage(3, 0, acting)
		f := arGraphFacts(arGraphState(ident, &u, w), ident)
		if f.Label != agentruntime.LabelAgent || f.Workloads[*w.GraphID].Label != agentruntime.LabelAgent {
			t.Errorf("facts = %+v", f)
		}
	})
	t.Run("provider-native agent without model calls: agent, not an AI workload", func(t *testing.T) {
		ident, w := arGraphIdent(), arTestWorkload("bedrock-agent", true, models.ClassificationProviderAgent)
		f := arGraphFacts(arGraphState(ident, nil, w), ident)
		if f.Label != agentruntime.LabelAgent || f.AIWorkload || f.Workloads[*w.GraphID].Label != agentruntime.LabelAgent {
			t.Errorf("facts = %+v", f)
		}
	})
	t.Run("shared role: the role is the AI workload, its workloads have no label", func(t *testing.T) {
		ident := arGraphIdent()
		a, b := arTestWorkload("a", true, models.ClassificationUnclassified), arTestWorkload("b", true, models.ClassificationUnclassified)
		u := arTestUsage(3, 0, acting)
		f := arGraphFacts(arGraphState(ident, &u, a, b), ident)
		if f.Label != agentruntime.LabelAIWorkload || f.SingleWorkload != nil || f.Suggestion != nil {
			t.Errorf("facts = %+v", f)
		}
		if f.Workloads[*a.GraphID].Label != "" || f.Workloads[*b.GraphID].Label != "" {
			t.Errorf("candidate labels = %+v", f.Workloads)
		}
	})
	t.Run("an agent among a shared role's workloads: the role is an agent's (the resolver's rule)", func(t *testing.T) {
		ident := arGraphIdent()
		a, b := arTestWorkload("a", true, models.ClassificationProviderAgent), arTestWorkload("b", true, models.ClassificationUnclassified)
		u := arTestUsage(3, 0, nil)
		f := arGraphFacts(arGraphState(ident, &u, a, b), ident)
		if f.Label != agentruntime.LabelAgent || f.Workloads[*a.GraphID].Label != agentruntime.LabelAgent || f.Workloads[*b.GraphID].Label != "" {
			t.Errorf("facts = %+v", f)
		}
	})
	t.Run("no usage: no model-call evidence", func(t *testing.T) {
		ident, w := arGraphIdent(), arTestWorkload("bot", true, models.ClassificationUnclassified)
		u := arTestUsage(0, 0, acting)
		f := arGraphFacts(arGraphState(ident, &u, w), ident)
		if f.AIWorkload || f.Label != "" || f.Workloads[*w.GraphID].Label != "" {
			t.Errorf("facts = %+v", f)
		}
	})
}

func TestAgentRuntimeGraphContainmentFacts(t *testing.T) {
	cw := uuid.New()
	r := arContainRow{ID: uuid.New(), Level: "workload", State: "contained", WorkloadIDs: []string{cw.String(), "garbage"}}
	f := r.facts()
	if !f.InForce || len(f.WorkloadIDs) != 1 || f.WorkloadIDs[0] != cw {
		t.Errorf("facts = %+v", f)
	}
	for state, inForce := range map[string]bool{"previewed": false, "containing": true, "contained": true,
		"partially_contained": true, "releasing": true} {
		if got := (arContainRow{State: state}).facts().InForce; got != inForce {
			t.Errorf("%s: in force = %v, want %v", state, got, inForce)
		}
	}
	if (&arAlertCount{Rank: 2}).severity() != "high" || (&arAlertCount{Rank: 1}).severity() != "medium" || (&arAlertCount{}).severity() != "" {
		t.Error("alert severity ranks")
	}
}
