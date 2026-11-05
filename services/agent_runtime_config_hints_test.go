package services

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/models"
)

func TestAgentEnvVarNamesModelProviders(t *testing.T) {
	got := AgentEnvVarNames([]string{"GEMINI_API_KEY", "google_api_key", "AZURE_OPENAI_ENDPOINT", "MISTRAL_API_KEY",
		"COHERE_API_KEY", "GROQ_API_KEY", "OPENROUTER_API_KEY", "HF_TOKEN", "HuggingFaceHub_API_Token", "LLAMA_CLOUD_API_KEY",
		"OPENAI_ORG", "DB_PASSWORD", "AZURE_STORAGE_KEY", "PATH"})
	want := []string{"AZURE_OPENAI_ENDPOINT", "COHERE_API_KEY", "GEMINI_API_KEY", "GROQ_API_KEY", "HF_TOKEN",
		"HuggingFaceHub_API_Token", "LLAMA_CLOUD_API_KEY", "MISTRAL_API_KEY", "OPENROUTER_API_KEY", "google_api_key"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("AgentEnvVarNames = %v, want %v", got, want)
	}
}

func TestAILayerNames(t *testing.T) {
	got := AILayerNames([]string{"langchain-core", "numpy", "OpenAI-SDK", "mcp-tools", "pandas"})
	if want := []string{"OpenAI-SDK", "langchain-core", "mcp-tools"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("AILayerNames = %v, want %v", got, want)
	}
}

func hintWorkload(name string, attrs map[string]any, identity *uuid.UUID) *arWorkload {
	w := arTestWorkload(name, true, models.ClassificationUnclassified)
	raw, _ := json.Marshal(attrs)
	w.Attrs, w.IdentityID = raw, identity
	return w
}

// Hints are names only: env var names, layer names, readable model-key
// secrets. Values never appear.
func TestConfigHintsFor(t *testing.T) {
	role := uuid.New()
	w := hintWorkload("bot", map[string]any{"env_var_names": []string{"OPENAI_API_KEY", "PATH"},
		"layers": []string{"arn:aws:lambda:us-east-1:111122223333:layer:langchain-layer:3"}}, &role)
	secrets := &modelKeySecrets{known: true, list: []*modelKeySecret{
		{ARN: "arn:aws:secretsmanager:us-east-1:111122223333:secret:openai-key-AbCdEf", Name: "openai-key", Readers: []uuid.UUID{role}},
		{ARN: "arn:aws:secretsmanager:us-east-1:111122223333:secret:anthropic-x-AbCdEf", Name: "anthropic-x", Readers: []uuid.UUID{uuid.New()}},
	}}
	h := configHintsFor(w, secrets)
	if !reflect.DeepEqual(h.EnvVarNames, []string{"OPENAI_API_KEY"}) || !reflect.DeepEqual(h.LayerNames, []string{"langchain-layer"}) ||
		len(h.ModelKeys) != 1 || h.ModelKeys[0].Name != "openai-key" || !h.any() {
		t.Fatalf("hints %+v", h)
	}
	d := configHintDraft(w, "arn:aws:iam::111122223333:role/bot", h)
	if d.Kind != FindingAIConfigHint || d.SubjectKey != w.NativeID || d.IdentityID == nil || *d.IdentityID != role {
		t.Fatalf("draft %+v", d)
	}
	if h := configHintsFor(hintWorkload("plain", map[string]any{"env_var_names": []string{"PATH"}}, nil), nil); h.any() {
		t.Fatalf("a workload without hints: %+v", h)
	}
	if h := configHintsFor(hintWorkload("unread", map[string]any{"env_vars_unread": true}, nil), nil); h.any() || !h.EnvUnread {
		t.Fatalf("unread environment: %+v", h)
	}
}

func hintFinding(kind string, identity uuid.UUID) *arFinding {
	return &arFinding{ID: uuid.New(), Kind: kind, IdentityID: identity, Subject: json.RawMessage(`{}`), Evidence: json.RawMessage(`{}`)}
}

// possible_ai_workload: configuration hints and no model-call or network
// evidence. Never suggested; weaker than every other label.
func TestPossibleAIWorkloadLabels(t *testing.T) {
	acting := map[string]int{"s3.amazonaws.com": 3}
	one := func() []*arWorkload {
		return []*arWorkload{arTestWorkload("w", true, models.ClassificationUnclassified)}
	}

	t.Run("hints only is a possible AI workload, never suggested", func(t *testing.T) {
		r := arTestRole("r")
		st := arTestState(r, arTestUsage(0, 0, acting), one(), nil)
		st.hints = map[uuid.UUID][]*arFinding{r.ID: {hintFinding(FindingAIConfigHint, r.ID)}}
		ais := st.aiWorkloads()
		if len(ais) != 1 || ais[0].Label != agentruntime.LabelPossibleAIWorkload || ais[0].evidenced() || len(ais[0].ConfigHints) != 1 {
			t.Fatalf("got %+v", ais)
		}
		if sub := subjectFromState(st, r); sub.Label != agentruntime.LabelPossibleAIWorkload {
			t.Fatalf("resolver label %q", sub.Label)
		}
	})
	t.Run("hints with model calls stay an AI workload or suggestion", func(t *testing.T) {
		r := arTestRole("r")
		st := arTestState(r, arTestUsage(2, 0, acting), one(), nil)
		st.hints = map[uuid.UUID][]*arFinding{r.ID: {hintFinding(FindingAIConfigHint, r.ID)}}
		if l := st.aiWorkloads()[0].Label; l != agentruntime.LabelSuggestedAgent {
			t.Fatalf("label %q", l)
		}
	})
	t.Run("network traffic is an AI workload, not a suggestion", func(t *testing.T) {
		r := arTestRole("r")
		st := arTestState(r, arTestUsage(0, 0, acting), one(), nil)
		st.network = map[uuid.UUID][]*arFinding{r.ID: {hintFinding(FindingAINetworkTraffic, r.ID)}}
		ai := st.aiWorkloads()[0]
		if ai.Label != agentruntime.LabelAIWorkload || !ai.evidenced() || len(ai.NetworkTraffic) != 1 {
			t.Fatalf("got %+v", ai)
		}
		if sub := subjectFromState(st, r); sub.Label != agentruntime.LabelAIWorkload {
			t.Fatalf("resolver label %q", sub.Label)
		}
	})
	t.Run("a shared role with hints is possible", func(t *testing.T) {
		r := arTestRole("r")
		st := arTestState(r, arTestUsage(0, 0, nil), []*arWorkload{arTestWorkload("a", true, ""), arTestWorkload("b", true, "")}, nil)
		st.hints = map[uuid.UUID][]*arFinding{r.ID: {hintFinding(FindingAIConfigHint, r.ID)}}
		if l := st.aiWorkloads()[0].Label; l != agentruntime.LabelPossibleAIWorkload {
			t.Fatalf("label %q", l)
		}
	})
	t.Run("an agent stays an agent", func(t *testing.T) {
		r := arTestRole("r")
		st := arTestState(r, arTestUsage(0, 0, nil), []*arWorkload{arTestWorkload("w", true, models.ClassificationClassified)}, nil)
		st.hints = map[uuid.UUID][]*arFinding{r.ID: {hintFinding(FindingAIConfigHint, r.ID)}}
		if l := st.aiWorkloads()[0].Label; l != agentruntime.LabelAgent {
			t.Fatalf("label %q", l)
		}
	})
	t.Run("detections run for it, titled as possible", func(t *testing.T) {
		if !AgentAlertLabels[agentruntime.LabelPossibleAIWorkload] {
			t.Fatal("detections must apply to possible AI workloads")
		}
		title := agentAlertTitle(agentruntime.Subject{IdentityID: uuid.New(), Name: "bot", Label: agentruntime.LabelPossibleAIWorkload}, "D1")
		if !strings.HasSuffix(title, "(possible AI workload)") {
			t.Fatalf("title %q", title)
		}
	})
}
