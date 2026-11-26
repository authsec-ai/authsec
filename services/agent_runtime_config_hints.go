package services

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

/* agent_runtime_config_hints.go: "possible AI workload" from configuration
   hints. An agent that calls OpenAI, Anthropic or Google directly (no Bedrock)
   leaves no model-call evidence in CloudTrail; its configuration still names
   a model provider. Per workload of the connector, inference records an
   ai_config_hint finding (agent_finding; subject = the cloud_workload and its
   identity) listing which hints it has:

     - Lambda environment variable NAMES (never values; the collector drops
       them at parse time) matching AgentEnvVarNames: OPENAI_API_KEY,
       ANTHROPIC_API_KEY, GEMINI_API_KEY, GOOGLE_API_KEY, MISTRAL_API_KEY,
       COHERE_API_KEY, GROQ_API_KEY, OPENROUTER_API_KEY, HF_TOKEN, and the
       prefixes AZURE_OPENAI_, HUGGINGFACE, LANGCHAIN_, LANGSMITH_, LLAMA_,
       MCP_ (case-insensitive);
     - Lambda layer names matching a provider or framework (read from the
       workload's attrs "layers"; the collector does not store layers today,
       so this hint is empty until it does);
     - Secrets Manager secrets the workload's identity may read whose NAMES
       look like a model key (the model_key_secret logic,
       loadModelKeySecrets; declared grants, conditions not evaluated).

   ECS task definitions: the collector does not store container environment
   variable names (DescribeTaskDefinition's environment is not kept), so ECS
   workloads have no env hint until it does; no AWS call is added here.

   The finding is refreshed every inference run and resolved when the hints
   are gone -- but not when they are unknown: a finding resting on env names
   of a workload whose environment could not be read this run
   (env_vars_unread), or on model-key secrets in a run whose secret inventory
   was not read, stays open. A workload no longer collected is resolved.

   Labels (agent_runtime_inference.go): an identity with an open
   ai_config_hint finding and no model-call (or network) evidence is a
   possible_ai_workload. Names never decide a suggestion (§3, Q1): a possible
   AI workload is never suggested as an agent and gets no shared-role or
   credential findings; detections D1-D8 do apply to it. */

// aiLayerNamePattern matches Lambda layer names of model providers and agent
// frameworks.
var aiLayerNamePattern = regexp.MustCompile(`(?i)(openai|anthropic|claude|gemini|mistral|cohere|groq|openrouter|huggingface|langchain|langsmith|llama|mcp)`)

// AILayerNames are the layer names that suggest a model provider or agent
// framework.
func AILayerNames(names []string) []string {
	out := []string{}
	for _, n := range names {
		if aiLayerNamePattern.MatchString(n) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// configHints is one workload's configuration hints.
type configHints struct {
	EnvVarNames []string
	EnvUnread   bool
	LayerNames  []string
	ModelKeys   []modelKeySecret
}

func (h configHints) any() bool {
	return len(h.EnvVarNames)+len(h.LayerNames)+len(h.ModelKeys) > 0
}

// configHintsFor reads a workload's hints. secrets may be nil. Pure.
func configHintsFor(w *arWorkload, secrets *modelKeySecrets) configHints {
	attrs := (&models.CloudWorkload{Attrs: w.Attrs}).AWSAttrs()
	h := configHints{EnvVarNames: AgentEnvVarNames(attrs.EnvVarNames), EnvUnread: attrs.EnvVarsUnread,
		LayerNames: AILayerNames(workloadLayerNames(w.Attrs))}
	if w.IdentityID != nil {
		h.ModelKeys = secrets.readableBy(*w.IdentityID)
		sort.Slice(h.ModelKeys, func(i, j int) bool { return h.ModelKeys[i].ARN < h.ModelKeys[j].ARN })
	}
	return h
}

// configHintDraft is the ai_config_hint finding of one workload.
func configHintDraft(w *arWorkload, identityARN string, h configHints) findingDraft {
	keys := []map[string]string{}
	for _, s := range h.ModelKeys {
		keys = append(keys, map[string]string{"arn": s.ARN, "name": s.Name})
	}
	subject := map[string]any{"cloud_workload_id": w.ID, "name": w.Name, "runtime_kind": w.RuntimeKind,
		"native_id": w.NativeID, "region": w.Region, "identity_id": w.IdentityID, "identity_arn": identityARN}
	evidence := map[string]any{
		"env_var_names":       nonNilStrings(h.EnvVarNames),
		"env_vars_unread":     h.EnvUnread,
		"layer_names":         nonNilStrings(h.LayerNames),
		"readable_model_keys": keys,
		"readable_basis":      "declared grants; conditions not evaluated",
		"names_only":          true,
		"note":                "configuration hints only: a possible AI workload, never a suggested agent",
	}
	return findingDraft{Kind: FindingAIConfigHint, SubjectKey: w.NativeID, IdentityID: w.IdentityID,
		Subject: subject, Evidence: evidence}
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// applyConfigHints opens or refreshes the connector's ai_config_hint findings
// and resolves those whose hints are gone (not merely unknown). tx is a
// transaction under row-level security for ws.
func (s *AgentRuntimeService) applyConfigHints(tx *gorm.DB, ws uuid.UUID, conn arConnector, secrets *modelKeySecrets,
	now time.Time, res *AgentInferenceResult) error {
	var wls []*arWorkload
	if err := tx.Table("cloud_workload").
		Select("id, connector_id, identity_id, runtime_kind, native_id, name, region, attrs").
		Where("workspace_id = ? AND connector_id = ?", ws, conn.ID).Order("native_id, id").Scan(&wls).Error; err != nil {
		return fmt.Errorf("read workloads: %w", err)
	}
	var idIDs []uuid.UUID
	for _, w := range wls {
		if w.IdentityID != nil {
			idIDs = append(idIDs, *w.IdentityID)
		}
	}
	arns := map[uuid.UUID]string{}
	if len(idIDs) > 0 {
		var rows []struct {
			ID       uuid.UUID
			NativeID string
		}
		if err := tx.Table("cloud_identity").Select("id, native_id").
			Where("workspace_id = ? AND id IN ?", ws, idIDs).Scan(&rows).Error; err != nil {
			return fmt.Errorf("read identities: %w", err)
		}
		for _, r := range rows {
			arns[r.ID] = r.NativeID
		}
	}

	seen := map[string]bool{}
	envUnread := map[string]bool{}
	secretsKnown := secrets != nil && secrets.known
	for _, w := range wls {
		if w.NativeID == "" {
			continue
		}
		h := configHintsFor(w, secrets)
		if h.EnvUnread {
			envUnread[w.NativeID] = true
		}
		if !h.any() {
			continue
		}
		arn := ""
		if w.IdentityID != nil {
			arn = arns[*w.IdentityID]
		}
		if err := upsertAgentFinding(tx, ws, conn.ID, configHintDraft(w, arn, h), now); err != nil {
			return err
		}
		seen[w.NativeID] = true
		res.ConfigHintsOpen++
	}

	var open []struct {
		ID         uuid.UUID
		SubjectKey string
		Evidence   json.RawMessage
	}
	if err := tx.Table("agent_finding").Select("id, subject_key, evidence").
		Where("workspace_id = ? AND connector_id = ? AND kind = ? AND state = ?", ws, conn.ID, FindingAIConfigHint, FindingOpen).
		Scan(&open).Error; err != nil {
		return fmt.Errorf("read open config hints: %w", err)
	}
	for _, f := range open {
		if seen[f.SubjectKey] {
			continue
		}
		// A hint that cannot be read this run is unknown, not gone.
		var prev struct {
			EnvVarNames []string          `json:"env_var_names"`
			ModelKeys   []json.RawMessage `json:"readable_model_keys"`
		}
		_ = json.Unmarshal(f.Evidence, &prev)
		if (len(prev.EnvVarNames) > 0 && envUnread[f.SubjectKey]) || (len(prev.ModelKeys) > 0 && !secretsKnown) {
			continue
		}
		r := tx.Exec(`UPDATE agent_finding SET state = 'resolved', resolved_at = ?, updated_at = ?
			WHERE workspace_id = ? AND id = ? AND state = 'open'`, now, now, ws, f.ID)
		if r.Error != nil {
			return fmt.Errorf("resolve config hint: %w", r.Error)
		}
		res.ConfigHintsResolved += int(r.RowsAffected)
	}
	return nil
}

// arFinding is an open ai_config_hint or ai_network_traffic finding naming an
// identity, as labels read it.
type arFinding struct {
	ID         uuid.UUID
	Kind       string
	IdentityID uuid.UUID
	Subject    json.RawMessage
	Evidence   json.RawMessage
}

// AIFindingRef is a finding an AI workload's label rests on.
type AIFindingRef struct {
	ID       uuid.UUID       `json:"finding_id"`
	Kind     string          `json:"kind"`
	Subject  json.RawMessage `json:"subject"`
	Evidence json.RawMessage `json:"evidence"`
}

func aiFindingRefs(fs []*arFinding) []AIFindingRef {
	out := []AIFindingRef{}
	for _, f := range fs {
		out = append(out, AIFindingRef{ID: f.ID, Kind: f.Kind, Subject: f.Subject, Evidence: f.Evidence})
	}
	return out
}
