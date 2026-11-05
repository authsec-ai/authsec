package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

/* agent_runtime_suggest.go is rule aws_agent_suggest_v1 and the suggestion
   lifecycle (SPEC-agent-runtime-visibility.md §5.3, §10 Q1/Q2):

     pending    -- proposed; shown as "Suggested agent"
     confirmed  -- a person ran Classify as agent through it (same transaction)
     dismissed  -- a person rejected it: never proposed again for this
                   workload incarnation
     superseded -- the system closed it: the workload was classified elsewhere
                   or retired (final), or its role became shared (re-proposed
                   once the role is split, §10 Q1). */

/* ---------------------------------- the rule -------------------------------- */

// arTelemetrySources are event sources that are a workload's own telemetry,
// not action on other resources, so they never satisfy "also acted on other
// resources" (§5.3). Model calls themselves (every bedrock* source) are the
// rule's first half and never count for the second.
var arTelemetrySources = map[string]bool{
	"logs.amazonaws.com":       true,
	"monitoring.amazonaws.com": true,
	"xray.amazonaws.com":       true,
}

// actedElsewhere is the other-services evidence that counts for the rule:
// successful calls by the identity to services that are neither a model
// endpoint nor its own telemetry. The caller passes the windowed usage
// (arUsage.windowed), so these are the calls of the same
// AgentRuntimeWindowDays days as the model calls (§5.3 "in the same window").
func actedElsewhere(u agentruntime.ModelCallUsage) map[string]int {
	out := map[string]int{}
	for src, n := range u.OtherServices {
		if n <= 0 || arTelemetrySources[src] || strings.HasPrefix(src, "bedrock") {
			continue
		}
		out[src] = n
	}
	return out
}

// Why a workload is not suggested (diagnostics; never shown as a claim).
const (
	suggestNoModelCalls   = "no_model_calls"
	suggestSharedRole     = "shared_role"
	suggestNotProjected   = "not_projected"
	suggestClassified     = "already_classified"
	suggestNoOtherService = "no_other_services"
)

// suggestEligible applies rule aws_agent_suggest_v1 to one AI workload: model
// calls (or refusals) by its identity inside the evaluation window, exactly
// one principal on that identity (candidates counts its workloads, its EKS
// service accounts and any other assumer: §10 Q1, never on a shared role),
// that workload in the graph and still unclassified, and the identity also
// acting on other services inside the same window. u is the WINDOWED usage
// (arUsage.windowed), never the all-time totals. Names, env vars and secrets
// are supporting evidence only.
func suggestEligible(u agentruntime.ModelCallUsage, one *arWorkload, candidates int) (bool, string) {
	switch {
	case !isAIWorkload(u):
		return false, suggestNoModelCalls
	case candidates != 1 || one == nil:
		return false, suggestSharedRole
	case one.GraphID == nil:
		return false, suggestNotProjected
	case one.Classification != models.ClassificationUnclassified:
		return false, suggestClassified
	case len(actedElsewhere(u)) == 0:
		return false, suggestNoOtherService
	}
	return true, ""
}

/* ---------------------------- supporting evidence --------------------------- */

var (
	agentEnvPrefixes = []string{"LANGCHAIN_", "LANGSMITH_", "MCP_"}
	agentEnvNames    = map[string]bool{"OPENAI_API_KEY": true, "ANTHROPIC_API_KEY": true}
)

// AgentEnvVarNames are the environment variable NAMES (never values) of agent
// frameworks or model keys: LANGCHAIN_*, LANGSMITH_*, MCP_*, OPENAI_API_KEY,
// ANTHROPIC_API_KEY. Supporting evidence only (§3).
func AgentEnvVarNames(names []string) []string {
	out := []string{}
	for _, n := range names {
		u := strings.ToUpper(n)
		if agentEnvNames[u] {
			out = append(out, n)
			continue
		}
		for _, p := range agentEnvPrefixes {
			if strings.HasPrefix(u, p) {
				out = append(out, n)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// workloadLayerNames reads Lambda layer names from a workload's attrs when the
// collector stored them ("layers": names or ARNs). The collector does not
// store them today, so this is empty until it does.
func workloadLayerNames(attrs json.RawMessage) []string {
	var a struct {
		Layers []string `json:"layers"`
	}
	if len(attrs) > 0 {
		_ = json.Unmarshal(attrs, &a)
	}
	out := []string{}
	for _, l := range a.Layers {
		name := l
		// arn:aws:lambda:region:acct:layer:NAME:VERSION
		if parts := strings.Split(l, ":"); len(parts) >= 7 && parts[5] == "layer" {
			name = parts[6]
		}
		if name != "" {
			out = arAppendUnique(out, name)
		}
	}
	return out
}

// modelKeySecretPattern matches Secrets Manager NAMES that suggest a model
// provider key (§5.5). Names only: no value is ever read.
var modelKeySecretPattern = regexp.MustCompile(`(?i)(openai|anthropic|gemini|llm|api[-_]?key)`)

// IsModelKeySecretName reports whether a secret name looks like a model key.
func IsModelKeySecretName(name string) bool { return modelKeySecretPattern.MatchString(name) }

// arSecretSuffix is the six-character suffix Secrets Manager appends to a
// secret's ARN.
var arSecretSuffix = regexp.MustCompile(`-[A-Za-z0-9]{6}$`)

// SecretNameFromARN is a Secrets Manager secret's name from its ARN
// (arn:aws:secretsmanager:region:acct:secret:NAME-AbCdEf).
func SecretNameFromARN(arn string) string {
	i := strings.Index(arn, ":secret:")
	if i < 0 {
		return ""
	}
	return arSecretSuffix.ReplaceAllString(arn[i+len(":secret:"):], "")
}

/* -------------------------------- the evidence ------------------------------ */

// suggestionEvidence is the evidence a suggestion stores: references to the
// rows it rests on (cloud_usage, cloud_observation) and the summary numbers,
// never a secret value or a request body.
func suggestionEvidence(ai *AIWorkload, one *arWorkload, secrets []modelKeySecret, observations []uuid.UUID) json.RawMessage {
	u := ai.win
	attrs := models.CloudWorkload{Attrs: one.Attrs}
	readable := []map[string]string{}
	for _, s := range secrets {
		readable = append(readable, map[string]string{"arn": s.ARN, "name": s.Name})
	}
	ev := map[string]any{
		"rule": AgentSuggestRule, "rule_version": AgentSuggestRuleVersion,
		"window": map[string]any{"from": u.CoveredFrom, "to": u.CoveredTo, "partial": u.Partial,
			"days": AgentRuntimeWindowDays},
		"model_calls": map[string]any{
			"calls": u.Calls, "denied": u.Denied, "errors": u.Errors, "tokens": u.Tokens,
			"models": arNonNil(u.Models), "endpoints": arNonNil(u.Endpoints),
			"first_call_at": u.FirstCallAt, "last_call_at": u.LastCallAt,
		},
		"other_services": actedElsewhere(u),
		"references": map[string]any{
			"cloud_usage":       []uuid.UUID{ai.UsageID},
			"cloud_observation": nonNilUUIDs(observations),
		},
		"identity": map[string]any{"id": ai.Identity.ID, "arn": ai.Identity.ARN, "name": ai.Identity.Name},
		"workload": map[string]any{"cloud_workload_id": one.ID, "name": one.Name,
			"runtime_kind": one.RuntimeKind, "native_id": one.NativeID, "region": one.Region},
		"supporting": map[string]any{
			"env_var_names":        AgentEnvVarNames(attrs.AWSAttrs().EnvVarNames),
			"env_vars_unread":      attrs.AWSAttrs().EnvVarsUnread,
			"layer_names":          workloadLayerNames(one.Attrs),
			"readable_model_keys":  readable,
			"readable_basis":       "declared grants; conditions not evaluated",
			"supporting_only_note": "names and env vars never decide a suggestion",
		},
		"session_names": ai.SessionNames,
	}
	raw, _ := json.Marshal(ev)
	return raw
}

func nonNilUUIDs(s []uuid.UUID) []uuid.UUID {
	if s == nil {
		return []uuid.UUID{}
	}
	return s
}

// cloudTrailObservations are the newest CloudTrail evidence rows attributed
// to the identity (cloud_observation), referenced by id.
func cloudTrailObservations(tx *gorm.DB, ws, identityID uuid.UUID) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	err := tx.Table("cloud_observation").Select("id").
		Where("workspace_id = ? AND identity_id = ? AND source_api LIKE ?", ws, identityID, "cloudtrail:%").
		Order("observed_at DESC, id").Limit(5).Pluck("id", &ids).Error
	return ids, err
}

/* ------------------------------ the inference pass -------------------------- */

// applySuggestions proposes, refreshes, re-proposes and supersedes the
// connector's suggestions. Every write is conditional on the state it read,
// so a person's concurrent Confirm or Dismiss is never overwritten.
func (s *AgentRuntimeService) applySuggestions(tx *gorm.DB, ws, connectorID uuid.UUID, st *agentRuntimeState,
	ais []*AIWorkload, secrets *modelKeySecrets, now time.Time, res *AgentInferenceResult) error {
	shared := map[uuid.UUID]bool{}
	byWorkload := map[uuid.UUID]*AIWorkload{}
	for _, ai := range ais {
		if one := ai.single(); one != nil && one.GraphID != nil {
			byWorkload[*one.GraphID] = ai
		}
		if ai.SharedRole || ai.others {
			for _, w := range ai.wls {
				if w.GraphID != nil {
					shared[*w.GraphID] = true
				}
			}
			continue
		}
		one := ai.single()
		if ok, _ := suggestEligible(ai.win, one, ai.candidates()); !ok {
			continue
		}
		obs, err := cloudTrailObservations(tx, ws, ai.Identity.ID)
		if err != nil {
			return fmt.Errorf("observations: %w", err)
		}
		ev := suggestionEvidence(ai, one, secrets.readableBy(ai.Identity.ID), obs)
		existing := st.suggestions[*one.GraphID]
		switch {
		case existing == nil:
			r := tx.Exec(`INSERT INTO agent_suggestion
				  (workspace_id, workload_id, connector_id, identity_id, rule, rule_version, evidence, state, created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, ?, ?::jsonb, 'pending', ?, ?)
				ON CONFLICT (workspace_id, workload_id) DO NOTHING`,
				ws, *one.GraphID, connectorID, ai.Identity.ID, AgentSuggestRule, AgentSuggestRuleVersion, string(ev), now, now)
			if r.Error != nil {
				return fmt.Errorf("insert suggestion: %w", r.Error)
			}
			res.SuggestionsNew += int(r.RowsAffected)
		case existing.State == SuggestionPending:
			if err := tx.Exec(`UPDATE agent_suggestion
				SET evidence = ?::jsonb, connector_id = ?, identity_id = ?, rule_version = ?, updated_at = ?
				WHERE workspace_id = ? AND id = ? AND state = 'pending'`,
				string(ev), connectorID, ai.Identity.ID, AgentSuggestRuleVersion, now, ws, existing.ID).Error; err != nil {
				return fmt.Errorf("refresh suggestion: %w", err)
			}
		case existing.State == SuggestionSuperseded && suggestionReproposable(existing.Reason):
			// What closed it (a shared role, another identity, lapsed model
			// calls) no longer holds: the incarnation is proposed again.
			r := tx.Exec(`UPDATE agent_suggestion
				SET state = 'pending', decided_by = NULL, decided_at = NULL, reason = '',
				    evidence = ?::jsonb, connector_id = ?, identity_id = ?, rule_version = ?,
				    version = version + 1, updated_at = ?
				WHERE workspace_id = ? AND id = ? AND state = 'superseded' AND reason = ?`,
				string(ev), connectorID, ai.Identity.ID, AgentSuggestRuleVersion, now, ws, existing.ID, existing.Reason)
			if r.Error != nil {
				return fmt.Errorf("re-propose suggestion: %w", r.Error)
			}
			res.SuggestionsNew += int(r.RowsAffected)
		}
		// Dismissed, confirmed or superseded by a classification: never again.
	}

	// Close what no longer holds: a workload classified elsewhere or retired
	// (final), now on a shared role (§10 Q1), now running as another identity,
	// or whose identity made no model call inside the window.
	var pending []struct {
		ID             uuid.UUID
		WorkloadID     uuid.UUID
		IdentityID     *uuid.UUID
		Classification string
		Lifecycle      string
	}
	if err := tx.Table("agent_suggestion s").
		Select("s.id, s.workload_id, s.identity_id, w.classification, w.lifecycle").
		Joins("JOIN iga_workload w ON w.workspace_id = s.workspace_id AND w.id = s.workload_id").
		Where("s.workspace_id = ? AND s.connector_id = ? AND s.state = ?", ws, connectorID, SuggestionPending).
		Scan(&pending).Error; err != nil {
		return fmt.Errorf("read pending suggestions: %w", err)
	}
	for _, p := range pending {
		reason := ""
		switch {
		case p.Classification != models.ClassificationUnclassified:
			reason = SupersededClassified
		case p.Lifecycle != models.IGALifecycleActive:
			reason = "retired"
		case shared[p.WorkloadID]:
			reason = SupersededSharedRole
		case byWorkload[p.WorkloadID] != nil && p.IdentityID != nil &&
			byWorkload[p.WorkloadID].Identity.ID != *p.IdentityID:
			reason = SupersededIdentityChanged
		case byWorkload[p.WorkloadID] == nil || !isAIWorkload(byWorkload[p.WorkloadID].win):
			reason = SupersededNoModelCalls
		default:
			continue
		}
		r := tx.Exec(`UPDATE agent_suggestion
			SET state = 'superseded', reason = ?, decided_at = ?, version = version + 1, updated_at = ?
			WHERE workspace_id = ? AND id = ? AND state = 'pending'`, reason, now, now, ws, p.ID)
		if r.Error != nil {
			return fmt.Errorf("supersede suggestion: %w", r.Error)
		}
		res.Superseded += int(r.RowsAffected)
	}
	var open int64
	if err := tx.Table("agent_suggestion").
		Where("workspace_id = ? AND connector_id = ? AND state = ?", ws, connectorID, SuggestionPending).
		Count(&open).Error; err != nil {
		return fmt.Errorf("count suggestions: %w", err)
	}
	res.SuggestionsOpen = int(open)
	return nil
}

/* ---------------------------------- the reads ------------------------------- */

// AgentSuggestion is one suggestion as the API returns it.
type AgentSuggestion struct {
	ID          uuid.UUID               `json:"id"`
	Workload    AgentSuggestionWorkload `json:"workload"`
	ConnectorID uuid.UUID               `json:"connector_id"`
	IdentityID  *uuid.UUID              `json:"identity_id"`
	Rule        string                  `json:"rule"`
	RuleVersion int                     `json:"rule_version"`
	Evidence    json.RawMessage         `json:"evidence"`
	State       string                  `json:"state"`
	DecidedBy   *uuid.UUID              `json:"decided_by"`
	DecidedAt   *time.Time              `json:"decided_at"`
	Reason      string                  `json:"reason"`
	DecisionID  *uuid.UUID              `json:"decision_id"`
	OperationID *uuid.UUID              `json:"operation_id"`
	Version     int                     `json:"version"`
	CreatedAt   time.Time               `json:"created_at"`
	UpdatedAt   time.Time               `json:"updated_at"`
}

// AgentSuggestionWorkload is the workload a suggestion is about. Its
// classification_version is what Confirm's version must equal.
type AgentSuggestionWorkload struct {
	ID                    uuid.UUID `json:"id"`
	Name                  string    `json:"name"`
	RuntimeKind           string    `json:"runtime_kind"`
	Region                string    `json:"region"`
	Classification        string    `json:"classification"`
	ClassificationVersion int64     `json:"classification_version"`
	Lifecycle             string    `json:"lifecycle"`
}

type suggestionRow struct {
	ID                    uuid.UUID
	WorkloadID            uuid.UUID
	ConnectorID           uuid.UUID
	IdentityID            *uuid.UUID
	Rule                  string
	RuleVersion           int
	Evidence              json.RawMessage
	State                 string
	DecidedBy             *uuid.UUID
	DecidedAt             *time.Time
	Reason                string
	DecisionID            *uuid.UUID
	OperationID           *uuid.UUID
	Version               int
	CreatedAt             time.Time
	UpdatedAt             time.Time
	DisplayName           string
	RuntimeKind           string
	Region                string
	Classification        string
	ClassificationVersion int64
	Lifecycle             string
}

func (r suggestionRow) view() AgentSuggestion {
	return AgentSuggestion{
		ID: r.ID, ConnectorID: r.ConnectorID, IdentityID: r.IdentityID,
		Workload: AgentSuggestionWorkload{ID: r.WorkloadID, Name: r.DisplayName, RuntimeKind: r.RuntimeKind,
			Region: r.Region, Classification: r.Classification, ClassificationVersion: r.ClassificationVersion,
			Lifecycle: r.Lifecycle},
		Rule: r.Rule, RuleVersion: r.RuleVersion, Evidence: r.Evidence, State: r.State,
		DecidedBy: r.DecidedBy, DecidedAt: r.DecidedAt, Reason: r.Reason,
		DecisionID: r.DecisionID, OperationID: r.OperationID, Version: r.Version,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}

const suggestionSelect = `s.id, s.workload_id, s.connector_id, s.identity_id, s.rule, s.rule_version, s.evidence,
	s.state, s.decided_by, s.decided_at, s.reason, s.decision_id, s.operation_id, s.version, s.created_at, s.updated_at,
	w.display_name, w.runtime_kind, w.region, w.classification, w.classification_version, w.lifecycle`

// SuggestionStates are the state filter's legal values.
var SuggestionStates = map[string]bool{
	SuggestionPending: true, SuggestionConfirmed: true, SuggestionDismissed: true, SuggestionSuperseded: true,
}

// SuggestionFilter is GET /agent-runtime/suggestions's parameters.
type SuggestionFilter struct {
	State       string
	ConnectorID *uuid.UUID
	Cursor      string
	Limit       int
}

// ListSuggestions returns the workspace's suggestions, newest first.
func (s *AgentRuntimeService) ListSuggestions(ctx context.Context, ws uuid.UUID, f SuggestionFilter) ([]AgentSuggestion, *string, error) {
	if f.State != "" && !SuggestionStates[f.State] {
		return nil, nil, GovBadParam("state", "state must be pending, confirmed, dismissed or superseded.")
	}
	var after *arCursor
	if f.Cursor != "" {
		c, err := decodeARCursor(f.Cursor)
		if err != nil {
			return nil, nil, GovBadParam("cursor", "cursor is not one this server issued.")
		}
		after = c
	}
	limit := f.Limit
	if limit <= 0 {
		limit = DefaultAgentRuntimePage
	}
	var rows []suggestionRow
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		q := tx.Table("agent_suggestion s").Select(suggestionSelect).
			Joins("JOIN iga_workload w ON w.workspace_id = s.workspace_id AND w.id = s.workload_id").
			// A revoked connector's suggestions stay for audit but are not listed.
			Joins("JOIN cloud_connector cc ON cc.workspace_id = s.workspace_id AND cc.id = s.connector_id AND cc.status <> ?", models.CloudConnectorRevoked).
			Where("s.workspace_id = ?", ws)
		if f.State != "" {
			q = q.Where("s.state = ?", f.State)
		}
		if f.ConnectorID != nil {
			q = q.Where("s.connector_id = ?", *f.ConnectorID)
		}
		if after != nil {
			q = q.Where("(s.created_at, s.id) < (?, ?)", after.At, after.ID)
		}
		return q.Order("s.created_at DESC, s.id DESC").Limit(limit + 1).Scan(&rows).Error
	})
	if err != nil {
		return nil, nil, err
	}
	out := make([]AgentSuggestion, 0, len(rows))
	var next *string
	for i, r := range rows {
		if i == limit {
			c := encodeARCursor(rows[i-1].CreatedAt, rows[i-1].ID)
			next = &c
			break
		}
		out = append(out, r.view())
	}
	return out, next, nil
}

// GetSuggestion returns one suggestion of the workspace; another workspace's
// id, or an unknown one, is 404.
func (s *AgentRuntimeService) GetSuggestion(ctx context.Context, ws, id uuid.UUID) (*AgentSuggestion, error) {
	var out *AgentSuggestion
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		out, err = getSuggestion(tx, ws, id)
		return err
	})
	return out, err
}

func getSuggestion(tx *gorm.DB, ws, id uuid.UUID) (*AgentSuggestion, error) {
	var rows []suggestionRow
	if err := tx.Table("agent_suggestion s").Select(suggestionSelect).
		Joins("JOIN iga_workload w ON w.workspace_id = s.workspace_id AND w.id = s.workload_id").
		Where("s.workspace_id = ? AND s.id = ?", ws, id).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, GovNotFound()
	}
	v := rows[0].view()
	return &v, nil
}

/* -------------------------------- the decisions ----------------------------- */

// ConfirmSuggestionRequest is POST .../suggestions/:id/confirm. ActorUserID is
// the VERIFIED human; OperationID and ExpectedVersion are the classification
// contract's (POST /workloads/:id/classification): one operation id per
// intent, and the workload's classification_version the person saw.
type ConfirmSuggestionRequest struct {
	SuggestionID    uuid.UUID
	ActorUserID     uuid.UUID
	OperationID     uuid.UUID
	ExpectedVersion int64
	Purpose         string
	Reason          string
}

// ConfirmSuggestionResult is the confirm's 200: the classification decision
// (the classify POST's data, replayed on a retry) and the closed suggestion.
type ConfirmSuggestionResult struct {
	Classification *igaread.ClassifyResult `json:"classification"`
	Suggestion     *AgentSuggestion        `json:"suggestion"`
}

// DefaultConfirmReason is the decision record's reason when the person gave
// none: the decision names the suggestion it came from.
func DefaultConfirmReason(rule string) string {
	return "Confirmed AuthSec suggestion (" + rule + "): observed model calls and actions on other resources."
}

// ConfirmSuggestion runs the existing classification decision on the
// suggestion's workload (decision classified_agent, the same operation-id and
// version contract) and closes the suggestion in THE SAME transaction: the
// classification lands only with the suggestion confirmed, and a suggestion
// is confirmed only by a decision that landed.
//
// Refusals: 404 (no such suggestion in the workspace); the classify contract's
// 409 classification_conflict, 422 provider_native / invalid_decision /
// operation_id_reused, 504; 409 suggestion_not_pending when the suggestion is
// dismissed, superseded, or confirmed by another decision.
func (s *AgentRuntimeService) ConfirmSuggestion(ctx context.Context, ws uuid.UUID, in ConfirmSuggestionRequest) (*ConfirmSuggestionResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if tc, err := tenancy.FromContext(ctx); err == nil {
		if tc.WorkspaceID != ws {
			return nil, GovNotFound()
		}
	} else {
		ctx = tenancy.WithContext(ctx, tenancy.Context{WorkspaceID: ws})
	}
	sugg, err := s.GetSuggestion(ctx, ws, in.SuggestionID)
	if err != nil {
		return nil, err
	}
	reason := strings.TrimSpace(in.Reason)
	if reason == "" {
		reason = DefaultConfirmReason(sugg.Rule)
	}
	cls := s.classifier
	if cls == nil {
		// TENANT-EXEMPT: not a statement: the classification service runs its
		// decision in its own tenancy.RLSTransaction for ctx's workspace.
		cls = NewClassificationService(s.db)
	}
	req := ClassifyRequest{
		WorkloadID: sugg.Workload.ID, ActorUserID: in.ActorUserID, OperationID: in.OperationID,
		Decision: models.ClassificationClassified, Purpose: in.Purpose, Reason: reason,
		ExpectedVersion: in.ExpectedVersion,
	}
	res, err := cls.ClassifyThen(ctx, req, func(tx *gorm.DB, txWS uuid.UUID, res *igaread.ClassifyResult) error {
		return closeConfirmedSuggestion(tx, txWS, in.SuggestionID, req, res)
	})
	if err != nil {
		return nil, err
	}
	after, err := s.GetSuggestion(ctx, ws, in.SuggestionID)
	if err != nil {
		return nil, err
	}
	// The Agents-list mirror follows the graph's classification: refresh it
	// now rather than at the connector's next projection. Best effort; the
	// next inference pass converges it anyway.
	// TENANT-EXEMPT: not a statement: inference opens its own workspace transaction for ws.
	if s.db != nil {
		go RunAgentInferenceAfterScan(context.Background(), s.db, ws, after.ConnectorID) // TENANT-EXEMPT: inference runs under RLS for ws
	}
	return &ConfirmSuggestionResult{Classification: res, Suggestion: after}, nil
}

// closeConfirmedSuggestion runs inside the classification transaction, after
// its decision (new or replayed) and before its commit; an error rolls the
// decision back. It locks the suggestion, so a concurrent Dismiss or a second
// Confirm serializes on it.
func closeConfirmedSuggestion(tx *gorm.DB, ws, id uuid.UUID, req ClassifyRequest, res *igaread.ClassifyResult) error {
	var rows []struct {
		ID         uuid.UUID
		WorkloadID uuid.UUID
		State      string
		DecisionID *uuid.UUID
	}
	if err := tx.Raw(`SELECT id, workload_id, state, decision_id FROM agent_suggestion
		WHERE workspace_id = ? AND id = ? FOR UPDATE`, ws, id).Scan(&rows).Error; err != nil {
		return err
	}
	if len(rows) == 0 || rows[0].WorkloadID != req.WorkloadID {
		return igaread.NotFound()
	}
	r := rows[0]
	switch r.State {
	case SuggestionPending:
		upd := tx.Exec(`UPDATE agent_suggestion
			SET state = 'confirmed', decided_by = ?, decided_at = now(), reason = ?,
			    decision_id = ?, operation_id = ?, version = version + 1, updated_at = now()
			WHERE workspace_id = ? AND id = ? AND state = 'pending'`,
			req.ActorUserID, res.Decision.Reason, res.Decision.ID, req.OperationID, ws, id)
		if upd.Error != nil {
			return upd.Error
		}
		if upd.RowsAffected != 1 {
			return fmt.Errorf("confirm suggestion touched %d rows", upd.RowsAffected)
		}
		return nil
	case SuggestionConfirmed:
		if r.DecisionID != nil && *r.DecisionID == res.Decision.ID {
			return nil // a retry of the confirm that landed
		}
	}
	e := igaread.Conflict("suggestion_not_pending", "This suggestion is "+r.State+"; it can no longer be confirmed.")
	e.Extra = map[string]any{"state": r.State}
	return e
}

// DismissSuggestion records a person's rejection: who, when and why. The row
// stays dismissed, so the workload incarnation is never proposed again.
// Dismissing a dismissed suggestion returns it unchanged (replayed = true);
// a confirmed or superseded one is 409 suggestion_not_pending.
func (s *AgentRuntimeService) DismissSuggestion(ctx context.Context, ws, id, actor uuid.UUID, reason string) (*AgentSuggestion, bool, error) {
	reason = strings.TrimSpace(reason)
	switch {
	case reason == "":
		return nil, false, GovBadParam("reason", "reason is required: it is the audit record.")
	case strings.ContainsRune(reason, 0):
		return nil, false, GovBadParam("reason", "reason must not contain a NUL (U+0000) character.")
	case utf8.RuneCountInString(reason) > MaxClassificationReason:
		return nil, false, GovBadParam("reason", fmt.Sprintf("reason must be at most %d characters.", MaxClassificationReason))
	case actor == uuid.Nil:
		return nil, false, GovForbidden("Dismissing a suggestion requires a verified workspace member.")
	}
	var out *AgentSuggestion
	replayed := false
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var rows []struct {
			ID    uuid.UUID
			State string
		}
		if err := tx.Raw(`SELECT id, state FROM agent_suggestion WHERE workspace_id = ? AND id = ? FOR UPDATE`,
			ws, id).Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return GovNotFound()
		}
		switch rows[0].State {
		case SuggestionPending:
			if err := tx.Exec(`UPDATE agent_suggestion
				SET state = 'dismissed', decided_by = ?, decided_at = now(), reason = ?,
				    version = version + 1, updated_at = now()
				WHERE workspace_id = ? AND id = ? AND state = 'pending'`, actor, reason, ws, id).Error; err != nil {
				return err
			}
		case SuggestionDismissed:
			replayed = true
		default:
			return govErr(http.StatusConflict, "suggestion_not_pending",
				"This suggestion is "+rows[0].State+"; it can no longer be dismissed.",
				map[string]any{"state": rows[0].State})
		}
		var err error
		out, err = getSuggestion(tx, ws, id)
		return err
	})
	if err != nil {
		return nil, false, err
	}
	return out, replayed, nil
}

/* --------------------------------- the cursor ------------------------------- */

type arCursor struct {
	At time.Time
	ID uuid.UUID
}

func encodeARCursor(at time.Time, id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(at.UTC().Format(time.RFC3339Nano) + "|" + id.String()))
}

func decodeARCursor(s string) (*arCursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	at, id, ok := strings.Cut(string(raw), "|")
	if !ok {
		return nil, fmt.Errorf("malformed cursor")
	}
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return nil, err
	}
	u, err := uuid.Parse(id)
	if err != nil {
		return nil, err
	}
	return &arCursor{At: t, ID: u}, nil
}
