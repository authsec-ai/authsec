package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// One agent id (SPEC-secops-backend-upgrade.md W7, P16; migration 177).
//
// An agent is one row of `agent`, whatever saw it: its source rows
// (iga_workload, discovered_agents -- Agent Kit sightings included --,
// iga_agents, agent clients) are its aliases. The linking rules live in one
// place, the SQL function agent_identity_link (177), which the migration's
// backfill, the projection hooks (classification, the AWS agents mirror,
// sightings, IGA promotion) and the periodic sweep all call.
//
// Decisions are about the agent, so every alias moves with it: retire, merge
// (the merged agent's aliases are re-pointed at the survivor), transfer and
// "not an agent" (a reason is required whatever the source). Deleted at
// source is not a person's decision: the sweep marks it when every source
// reports the agent gone, and raises agent.ask_needed (TODO(W4): an ask).
//
// Every statement runs in a transaction under row-level security for the
// caller's workspace (tenancy.InWorkspace): another workspace's agent is 404.

// Agent states.
const (
	AgentStateActive          = "active"
	AgentStateRetired         = "retired"
	AgentStateMerged          = "merged"
	AgentStateTransferred     = "transferred"
	AgentStateDeletedAtSource = "deleted_at_source"
	AgentStateNotAnAgent      = "not_an_agent"
)

// Agent ending actions (POST /agent-identities/:id/<action>).
const (
	AgentEndRetire     = "retire"
	AgentEndMerge      = "merge"
	AgentEndTransfer   = "transfer"
	AgentEndNotAnAgent = "not-an-agent"
)

// Risk classes (decision for W7): the EU AI Act's four tiers. Chosen over
// low/medium/high/critical because the obligations a class carries (human
// oversight, logging, transparency) are the regulation's, and a customer
// mapping its register to AuthSec needs the same words.
var agentRiskRank = map[string]int{"minimal": 0, "limited": 1, "high": 2, "prohibited": 3}

// Limits on free text.
const (
	maxAgentReason  = 2000
	maxAgentPurpose = 2000
)

// AgentIdentityService serves agents, their endings, purpose and risk class,
// and the tier-3 pending changes of W7.
type AgentIdentityService struct{ db *gorm.DB }

// NewAgentIdentityService builds the service over db.
func NewAgentIdentityService(db *gorm.DB) *AgentIdentityService { return &AgentIdentityService{db: db} }

func (s *AgentIdentityService) inWS(ctx context.Context, ws uuid.UUID, fn func(tx *gorm.DB) error) error {
	return tenancy.InWorkspace(ctx, s.db, ws, fn)
}

func (s *AgentIdentityService) readWS(ctx context.Context, ws uuid.UUID, fn func(tx *gorm.DB) error) error {
	return tenancy.InWorkspaceRead(ctx, s.db, ws, fn)
}

/* ------------------------------------------------------------------------- */
/*                                  Linking                                   */
/* ------------------------------------------------------------------------- */

// agentIdentityReady reports whether migration 177's linking function exists.
// The hooks run inside other features' transactions: on a database without
// 177 they do nothing rather than abort the caller's transaction.
func agentIdentityReady(tx *gorm.DB) bool {
	var ok bool
	if err := tx.Raw(`SELECT to_regprocedure('public.agent_identity_link(uuid,text,text)') IS NOT NULL`).Scan(&ok).Error; err != nil {
		return false
	}
	return ok
}

// LinkAgentSources links ws's unlinked source rows to agents (agent_identity_link):
// all of them (table and id empty), one table's, or one row. It returns how
// many aliases it wrote. tx must be a transaction under row-level security
// for ws (the hooks are called from one).
func LinkAgentSources(tx *gorm.DB, ws uuid.UUID, table, id string) (int, error) {
	if ws == uuid.Nil || !agentIdentityReady(tx) {
		return 0, nil
	}
	var t, i *string
	if table != "" {
		t = &table
	}
	if id != "" {
		i = &id
	}
	var n int
	err := tx.Raw(`SELECT public.agent_identity_link(?::uuid, ?::text, ?::text)`, ws, t, i).Scan(&n).Error
	return n, err
}

// LinkAgentSourcesInWorkspace is LinkAgentSources in its own transaction
// (hooks outside one, the sweep).
func LinkAgentSourcesInWorkspace(ctx context.Context, db *gorm.DB, ws uuid.UUID, table, id string) (int, error) {
	var n int
	err := tenancy.InWorkspace(ctx, db, ws, func(tx *gorm.DB) error {
		var err error
		n, err = LinkAgentSources(tx, ws, table, id)
		return err
	})
	return n, err
}

// agentIDForSource is the agent a source row is an alias of (nil: none).
func agentIDForSource(tx *gorm.DB, ws uuid.UUID, table, id string) (*uuid.UUID, error) {
	var ids []uuid.UUID
	if err := tx.Raw(`SELECT agent_id FROM agent_alias WHERE workspace_id = ? AND source_table = ? AND source_id = ?`,
		ws, table, id).Scan(&ids).Error; err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}
	return &ids[0], nil
}

/* ------------------------------------------------------------------------- */
/*                                   Reads                                    */
/* ------------------------------------------------------------------------- */

// AgentRow is one agent row.
type AgentRow struct {
	ID            uuid.UUID  `json:"id" gorm:"column:id"`
	DisplayName   string     `json:"display_name" gorm:"column:display_name"`
	Kind          string     `json:"kind" gorm:"column:kind"`
	State         string     `json:"state" gorm:"column:state"`
	EndedReason   string     `json:"ended_reason" gorm:"column:ended_reason"`
	EndedBy       *uuid.UUID `json:"ended_by" gorm:"column:ended_by"`
	EndedAt       *time.Time `json:"ended_at" gorm:"column:ended_at"`
	MergedInto    *uuid.UUID `json:"merged_into" gorm:"column:merged_into"`
	TransferredTo string     `json:"transferred_to" gorm:"column:transferred_to"`
	OwnerUserID   *uuid.UUID `json:"owner_user_id" gorm:"column:owner_user_id"`
	SponsorUserID *uuid.UUID `json:"sponsor_user_id" gorm:"column:sponsor_user_id"`
	Version       int64      `json:"version" gorm:"column:version"`
	CreatedAt     time.Time  `json:"created_at" gorm:"column:created_at"`
	UpdatedAt     time.Time  `json:"updated_at" gorm:"column:updated_at"`
}

// AgentAliasView is one alias with what its source row says now.
type AgentAliasView struct {
	ID          uuid.UUID `json:"id" gorm:"column:id"`
	SourceTable string    `json:"source_table" gorm:"column:source_table"`
	SourceID    string    `json:"source_id" gorm:"column:source_id"`
	LinkedBy    string    `json:"linked_by" gorm:"column:linked_by"`
	LinkedAt    time.Time `json:"linked_at" gorm:"column:linked_at"`
	Name        string    `json:"name" gorm:"column:name"`
	// SourceState is the source row's own lifecycle (iga_workload and
	// iga_agents lifecycle, discovered_agents runtime_status); "missing" when
	// the row is gone, "" for a source with no lifecycle.
	SourceState string `json:"source_state" gorm:"column:source_state"`
}

// AgentPurposeVersion is one agent_purpose_version row.
type AgentPurposeVersion struct {
	ID             uuid.UUID `json:"id" gorm:"column:id"`
	Version        int       `json:"version" gorm:"column:version"`
	Purpose        string    `json:"purpose" gorm:"column:purpose"`
	AssessorUserID uuid.UUID `json:"assessor_user_id" gorm:"column:assessor_user_id"`
	AssessedAt     time.Time `json:"assessed_at" gorm:"column:assessed_at"`
}

// AgentRiskClassVersion is one agent_risk_class row.
type AgentRiskClassVersion struct {
	ID               uuid.UUID       `json:"id" gorm:"column:id"`
	Version          int             `json:"version" gorm:"column:version"`
	RiskClass        string          `json:"risk_class" gorm:"column:risk_class"`
	Obligations      json.RawMessage `json:"obligations" gorm:"column:obligations"`
	Reason           string          `json:"reason" gorm:"column:reason"`
	AssessorUserID   uuid.UUID       `json:"assessor_user_id" gorm:"column:assessor_user_id"`
	ApprovedByUserID *uuid.UUID      `json:"approved_by_user_id" gorm:"column:approved_by_user_id"`
	PendingChangeID  *uuid.UUID      `json:"pending_change_id" gorm:"column:pending_change_id"`
	AssessedAt       time.Time       `json:"assessed_at" gorm:"column:assessed_at"`
}

// AgentInstanceView is one iga_agent_instances row of an agent.
type AgentInstanceView struct {
	ID               uuid.UUID  `json:"id" gorm:"column:id"`
	SourceTable      string     `json:"source_table" gorm:"column:source_table"`
	SourceID         string     `json:"source_id" gorm:"column:source_id"`
	NativeWorkloadID string     `json:"native_workload_id" gorm:"column:native_workload_id"`
	RuntimeKind      string     `json:"runtime_kind" gorm:"column:runtime_kind"`
	Stage            string     `json:"stage" gorm:"column:stage"`
	ArtifactDigest   string     `json:"artifact_digest" gorm:"column:artifact_digest"`
	ArtifactVersion  string     `json:"artifact_version" gorm:"column:artifact_version"`
	Model            string     `json:"model" gorm:"column:model"`
	ModelVersion     string     `json:"model_version" gorm:"column:model_version"`
	Environment      string     `json:"environment" gorm:"column:environment"`
	Deployer         string     `json:"deployer" gorm:"column:deployer"`
	SpawnedBy        string     `json:"spawned_by" gorm:"column:spawned_by"`
	CloudIdentityID  *uuid.UUID `json:"cloud_identity_id" gorm:"column:cloud_identity_id"`
	FirstSeenAt      time.Time  `json:"first_seen_at" gorm:"column:first_seen_at"`
	LastSeenAt       time.Time  `json:"last_seen_at" gorm:"column:last_seen_at"`
}

// AgentListItem is one row of GET /agent-identities.
type AgentListItem struct {
	AgentRow
	AliasCount int    `json:"alias_count" gorm:"column:alias_count"`
	RiskClass  string `json:"risk_class" gorm:"column:risk_class"`
	Purpose    string `json:"purpose" gorm:"column:purpose"`
}

// AgentIdentityDetail is GET /agent-identities/:id.
type AgentIdentityDetail struct {
	AgentRow
	Aliases        []AgentAliasView        `json:"aliases"`
	Purpose        *AgentPurposeVersion    `json:"purpose"`
	PurposeHistory []AgentPurposeVersion   `json:"purpose_history"`
	RiskClass      *AgentRiskClassVersion  `json:"risk_class"`
	RiskHistory    []AgentRiskClassVersion `json:"risk_class_history"`
	Instances      []AgentInstanceView     `json:"instances"`
	Deployers      []string                `json:"deployers"`
	ResponderGroup *ResponderResolution    `json:"responder_group"`
	PendingChanges []AgentPendingChange    `json:"pending_changes"`
}

// AgentListFilter is GET /agent-identities's query.
type AgentListFilter struct {
	State  string
	Kind   string
	Cursor string
	Limit  int
}

func encodeAgentCursor(t time.Time, id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(t.UTC().Format(time.RFC3339Nano) + "|" + id.String()))
}

func decodeAgentCursor(c string) (time.Time, uuid.UUID, error) {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return time.Time{}, uuid.Nil, err
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 {
		return time.Time{}, uuid.Nil, errors.New("bad cursor")
	}
	t, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, uuid.Nil, err
	}
	id, err := uuid.Parse(parts[1])
	return t, id, err
}

var validAgentStates = map[string]bool{AgentStateActive: true, AgentStateRetired: true, AgentStateMerged: true,
	AgentStateTransferred: true, AgentStateDeletedAtSource: true, AgentStateNotAnAgent: true}

// ListAgents lists ws's agents, newest first.
func (s *AgentIdentityService) ListAgents(ctx context.Context, ws uuid.UUID, f AgentListFilter) ([]AgentListItem, string, error) {
	if f.State != "" && !validAgentStates[f.State] {
		return nil, "", GovBadParam("state", "state must be one of active, retired, merged, transferred, deleted_at_source, not_an_agent.")
	}
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	var out []AgentListItem
	err := s.readWS(ctx, ws, func(tx *gorm.DB) error {
		q := `SELECT a.*,
		        (SELECT count(*) FROM agent_alias x WHERE x.workspace_id = a.workspace_id AND x.agent_id = a.id) AS alias_count,
		        COALESCE((SELECT r.risk_class FROM agent_risk_class r WHERE r.workspace_id = a.workspace_id AND r.agent_id = a.id
		                   ORDER BY r.version DESC LIMIT 1), '') AS risk_class,
		        COALESCE((SELECT p.purpose FROM agent_purpose_version p WHERE p.workspace_id = a.workspace_id AND p.agent_id = a.id
		                   ORDER BY p.version DESC LIMIT 1), '') AS purpose
		      FROM agent a WHERE a.workspace_id = ?`
		args := []any{ws}
		if f.State != "" {
			q += ` AND a.state = ?`
			args = append(args, f.State)
		}
		if f.Kind != "" {
			q += ` AND a.kind = ?`
			args = append(args, f.Kind)
		}
		if f.Cursor != "" {
			t, id, err := decodeAgentCursor(f.Cursor)
			if err != nil {
				return GovBadParam("cursor", "cursor is not one this endpoint returned.")
			}
			q += ` AND (a.created_at, a.id) < (?, ?)`
			args = append(args, t, id)
		}
		q += ` ORDER BY a.created_at DESC, a.id DESC LIMIT ?`
		args = append(args, f.Limit+1)
		return tx.Raw(q, args...).Scan(&out).Error
	})
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > f.Limit {
		out = out[:f.Limit]
		last := out[len(out)-1]
		next = encodeAgentCursor(last.CreatedAt, last.ID)
	}
	if out == nil {
		out = []AgentListItem{}
	}
	return out, next, nil
}

func loadAgent(tx *gorm.DB, ws, id uuid.UUID, lock bool) (*AgentRow, error) {
	q := `SELECT * FROM agent WHERE workspace_id = ? AND id = ?`
	if lock {
		q += ` FOR UPDATE`
	}
	var rows []AgentRow
	if err := tx.Raw(q, ws, id).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, GovNotFound()
	}
	return &rows[0], nil
}

func agentAliases(tx *gorm.DB, ws, id uuid.UUID) ([]AgentAliasView, error) {
	var out []AgentAliasView
	err := tx.Raw(`SELECT a.id, a.source_table, a.source_id, a.linked_by, a.linked_at,
	        COALESCE(w.display_name, d.display_name, g.display_name, '') AS name,
	        CASE a.source_table
	          WHEN 'iga_workload' THEN COALESCE(w.lifecycle, 'missing')
	          WHEN 'discovered_agents' THEN COALESCE(d.runtime_status, 'missing')
	          WHEN 'iga_agents' THEN COALESCE(g.lifecycle, 'missing')
	          ELSE '' END AS source_state
	      FROM agent_alias a
	      LEFT JOIN iga_workload w ON a.source_table = 'iga_workload' AND w.workspace_id = a.workspace_id AND w.id::text = a.source_id
	      LEFT JOIN discovered_agents d ON a.source_table = 'discovered_agents' AND d.workspace_id = a.workspace_id AND d.id::text = a.source_id
	      LEFT JOIN iga_agents g ON a.source_table = 'iga_agents' AND g.workspace_id = a.workspace_id AND g.id::text = a.source_id
	     WHERE a.workspace_id = ? AND a.agent_id = ?
	     ORDER BY a.linked_at, a.id`, ws, id).Scan(&out).Error
	if out == nil {
		out = []AgentAliasView{}
	}
	return out, err
}

// GetAgent is one agent with its aliases, purpose, risk class, instances,
// deployers, the responder group that decides for it and its pending changes.
func (s *AgentIdentityService) GetAgent(ctx context.Context, ws, id uuid.UUID) (*AgentIdentityDetail, error) {
	var out AgentIdentityDetail
	err := s.readWS(ctx, ws, func(tx *gorm.DB) error {
		a, err := loadAgent(tx, ws, id, false)
		if err != nil {
			return err
		}
		out.AgentRow = *a
		if out.Aliases, err = agentAliases(tx, ws, id); err != nil {
			return err
		}
		if err := tx.Raw(`SELECT id, version, purpose, assessor_user_id, assessed_at FROM agent_purpose_version
		                  WHERE workspace_id = ? AND agent_id = ? ORDER BY version DESC`, ws, id).Scan(&out.PurposeHistory).Error; err != nil {
			return err
		}
		if len(out.PurposeHistory) > 0 {
			out.Purpose = &out.PurposeHistory[0]
		}
		if err := tx.Raw(`SELECT id, version, risk_class, obligations, reason, assessor_user_id, approved_by_user_id, pending_change_id, assessed_at
		                  FROM agent_risk_class WHERE workspace_id = ? AND agent_id = ? ORDER BY version DESC`, ws, id).Scan(&out.RiskHistory).Error; err != nil {
			return err
		}
		if len(out.RiskHistory) > 0 {
			out.RiskClass = &out.RiskHistory[0]
		}
		if err := tx.Raw(`SELECT id, source_table, source_id, native_workload_id, runtime_kind, stage, artifact_digest, artifact_version,
		                         model, model_version, environment, deployer, spawned_by, cloud_identity_id, first_seen_at, last_seen_at
		                  FROM iga_agent_instances WHERE workspace_id = ? AND agent_ref = ?
		                  ORDER BY last_seen_at DESC, id`, ws, id).Scan(&out.Instances).Error; err != nil {
			return err
		}
		if err := tx.Raw(`SELECT deployer FROM agent_deployer WHERE workspace_id = ? AND agent_id = ? ORDER BY deployer`,
			ws, id).Scan(&out.Deployers).Error; err != nil {
			return err
		}
		if err := tx.Raw(`SELECT * FROM agent_pending_change WHERE workspace_id = ? AND subject_id = ? AND kind = 'agent_risk_class_lower'
		                  ORDER BY requested_at DESC`, ws, id).Scan(&out.PendingChanges).Error; err != nil {
			return err
		}
		res, err := resolveResponder(tx, ws, id, time.Now())
		if err != nil {
			return err
		}
		out.ResponderGroup = res
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, p := range []*[]AgentPurposeVersion{&out.PurposeHistory} {
		if *p == nil {
			*p = []AgentPurposeVersion{}
		}
	}
	if out.RiskHistory == nil {
		out.RiskHistory = []AgentRiskClassVersion{}
	}
	if out.Instances == nil {
		out.Instances = []AgentInstanceView{}
	}
	if out.Deployers == nil {
		out.Deployers = []string{}
	}
	if out.PendingChanges == nil {
		out.PendingChanges = []AgentPendingChange{}
	}
	return &out, nil
}

/* ------------------------------------------------------------------------- */
/*                                  Endings                                   */
/* ------------------------------------------------------------------------- */

// AgentEndRequest is POST /agent-identities/:id/{retire,merge,transfer,not-an-agent}.
type AgentEndRequest struct {
	Action          string
	Reason          string
	MergeInto       uuid.UUID // merge
	TransferTo      string    // transfer
	ExpectedVersion *int64
}

// checkReason trims and validates a required reason.
func checkReason(field, reason string, max int) (string, error) {
	reason = strings.TrimSpace(reason)
	switch {
	case reason == "":
		return "", GovBadParam(field, field+" is required: it is the audit record.")
	case strings.ContainsRune(reason, 0):
		return "", GovBadParam(field, field+" must not contain a NUL character.")
	case utf8.RuneCountInString(reason) > max:
		return "", GovBadParam(field, fmt.Sprintf("%s must be at most %d characters.", field, max))
	}
	return reason, nil
}

// EndAgent records a person's ending of an agent. The agent must be active
// or deleted at source (a person may confirm what the sweep saw); every alias
// moves with it. A merge re-points the merged agent's aliases, instances and
// deployers at the survivor and keeps the merged row (state merged,
// merged_into) so its id still resolves.
func (s *AgentIdentityService) EndAgent(ctx context.Context, ws, id, actor uuid.UUID, req AgentEndRequest) (*AgentRow, error) {
	reason, err := checkReason("reason", req.Reason, maxAgentReason)
	if err != nil {
		return nil, err
	}
	state, event := "", ""
	switch req.Action {
	case AgentEndRetire:
		state, event = AgentStateRetired, GovEventAgentRetired
	case AgentEndMerge:
		state, event = AgentStateMerged, GovEventAgentMerged
		if req.MergeInto == uuid.Nil {
			return nil, GovBadParam("merge_into", "merge_into is required: the agent that survives.")
		}
		if req.MergeInto == id {
			return nil, GovBadParam("merge_into", "An agent cannot be merged into itself.")
		}
	case AgentEndTransfer:
		state, event = AgentStateTransferred, GovEventAgentTransferred
		req.TransferTo = strings.TrimSpace(req.TransferTo)
		if req.TransferTo == "" || utf8.RuneCountInString(req.TransferTo) > 200 {
			return nil, GovBadParam("transfer_to", "transfer_to is required (at most 200 characters): who takes the agent.")
		}
	case AgentEndNotAnAgent:
		state, event = AgentStateNotAnAgent, GovEventAgentNotAnAgent
	default:
		return nil, GovNotFound()
	}
	var out *AgentRow
	err = s.inWS(ctx, ws, func(tx *gorm.DB) error {
		a, err := loadAgent(tx, ws, id, true)
		if err != nil {
			return err
		}
		if req.ExpectedVersion != nil && *req.ExpectedVersion != a.Version {
			return govConflict("version_conflict", "The agent changed since you read it; re-read it and decide again.",
				map[string]any{"current_version": a.Version, "state": a.State})
		}
		if a.State != AgentStateActive && a.State != AgentStateDeletedAtSource {
			return govConflict("agent_ended", "The agent has already ended.", map[string]any{"state": a.State})
		}
		aliases, err := agentAliases(tx, ws, id)
		if err != nil {
			return err
		}
		var mergeInto *uuid.UUID
		transferTo := ""
		if state == AgentStateMerged {
			surv, err := loadAgent(tx, ws, req.MergeInto, true)
			if err != nil {
				var ge *GovError
				if errors.As(err, &ge) && ge.Status == 404 {
					return GovBadParam("merge_into", "merge_into names no agent of this workspace.")
				}
				return err
			}
			if surv.State != AgentStateActive {
				return govConflict("merge_target_ended", "The agent to merge into has ended.", map[string]any{"state": surv.State})
			}
			mergeInto = &surv.ID
			for _, stmt := range []string{
				`UPDATE agent_alias SET agent_id = ? WHERE workspace_id = ? AND agent_id = ?`,
				`UPDATE iga_agent_instances SET agent_ref = ? WHERE workspace_id = ? AND agent_ref = ?
				    AND NOT EXISTS (SELECT 1 FROM iga_agent_instances s WHERE s.workspace_id = iga_agent_instances.workspace_id
				      AND s.agent_ref = ? AND s.native_workload_id = iga_agent_instances.native_workload_id
				      AND s.artifact_digest = iga_agent_instances.artifact_digest)`,
				`INSERT INTO agent_deployer (workspace_id, agent_id, deployer, recorded_by)
				   SELECT workspace_id, ?::uuid, deployer, recorded_by FROM agent_deployer WHERE workspace_id = ? AND agent_id = ?
				   ON CONFLICT (workspace_id, agent_id, deployer) DO NOTHING`,
			} {
				args := []any{surv.ID, ws, id}
				if strings.Contains(stmt, "s.agent_ref = ?") {
					args = append(args, surv.ID)
				}
				if err := tx.Exec(stmt, args...).Error; err != nil {
					return err
				}
			}
			// The merged agent's own responder scope goes with it unless the
			// survivor has one.
			if err := tx.Exec(`UPDATE responder_group_scope SET scope_ref = ? WHERE workspace_id = ? AND scope_kind = 'agent' AND scope_ref = ?
			      AND NOT EXISTS (SELECT 1 FROM responder_group_scope x WHERE x.workspace_id = ? AND x.scope_kind = 'agent' AND x.scope_ref = ?)`,
				surv.ID.String(), ws, id.String(), ws, surv.ID.String()).Error; err != nil {
				return err
			}
			if err := tx.Exec(`UPDATE agent SET version = version + 1, updated_at = now() WHERE workspace_id = ? AND id = ?`, ws, surv.ID).Error; err != nil {
				return err
			}
		}
		if state == AgentStateTransferred {
			transferTo = req.TransferTo
		}
		if err := tx.Exec(`UPDATE agent SET state = ?, ended_reason = ?, ended_by = ?, ended_at = now(), merged_into = ?,
		        transferred_to = ?, version = version + 1, updated_at = now() WHERE workspace_id = ? AND id = ?`,
			state, reason, actor, mergeInto, transferTo, ws, id).Error; err != nil {
			return err
		}
		// Endings close the agent's open hygiene findings: there is nothing
		// left to act on.
		if err := tx.Exec(`UPDATE agent_hygiene_finding SET state = 'resolved', resolved_at = now()
		        WHERE workspace_id = ? AND agent_id = ? AND state = 'open'`, ws, id).Error; err != nil {
			return err
		}
		payload := map[string]any{"agent_id": id, "reason": reason, "previous_state": a.State, "aliases": aliasRefs(aliases)}
		if mergeInto != nil {
			payload["merged_into"] = *mergeInto
		}
		if transferTo != "" {
			payload["transferred_to"] = transferTo
		}
		if err := appendGovEvent(tx, ws, event, models.GovActorUser, actor.String(), govEventRefs{}, payload); err != nil {
			return err
		}
		out, err = loadAgent(tx, ws, id, false)
		return err
	})
	return out, err
}

func aliasRefs(aliases []AgentAliasView) []map[string]string {
	out := make([]map[string]string, 0, len(aliases))
	for _, a := range aliases {
		out = append(out, map[string]string{"source_table": a.SourceTable, "source_id": a.SourceID})
	}
	return out
}

// markNotAnAgentFromSource follows a source's own "not an agent" decision
// (an AWS workload's classification undone, whose reason the classification
// contract already requires): when every alias of the workload's agent is
// that workload, the agent becomes not_an_agent with the same reason. Called
// in the decision's transaction.
func markNotAnAgentFromSource(tx *gorm.DB, ws uuid.UUID, table, sourceID string, actor uuid.UUID, reason string) error {
	if !agentIdentityReady(tx) {
		return nil
	}
	aid, err := agentIDForSource(tx, ws, table, sourceID)
	if err != nil || aid == nil {
		return err
	}
	var others int64
	if err := tx.Raw(`SELECT count(*) FROM agent_alias WHERE workspace_id = ? AND agent_id = ?
	        AND NOT (source_table = ? AND source_id = ?) AND source_table IN ('iga_workload','discovered_agents','iga_agents')
	        AND NOT (source_table = 'discovered_agents' AND source_id IN (
	              SELECT d.id::text FROM discovered_agents d WHERE d.workspace_id = ? AND d.metadata->>'iga_workload_id' = ?))`,
		ws, *aid, table, sourceID, ws, sourceID).Scan(&others).Error; err != nil {
		return err
	}
	if others > 0 {
		return nil // another source still says agent: a person decides on the agent itself
	}
	res := tx.Exec(`UPDATE agent SET state = 'not_an_agent', ended_reason = ?, ended_by = ?, ended_at = now(),
	        version = version + 1, updated_at = now() WHERE workspace_id = ? AND id = ? AND state IN ('active', 'deleted_at_source')`,
		reason, actor, ws, *aid)
	if res.Error != nil || res.RowsAffected == 0 {
		return res.Error
	}
	return appendGovEvent(tx, ws, GovEventAgentNotAnAgent, models.GovActorUser, actor.String(), govEventRefs{},
		map[string]any{"agent_id": *aid, "reason": reason, "via": table, "source_id": sourceID})
}

/* ------------------------------------------------------------------------- */
/*                           Purpose and risk class                           */
/* ------------------------------------------------------------------------- */

// SetPurpose records a new purpose version with its assessor.
func (s *AgentIdentityService) SetPurpose(ctx context.Context, ws, id, actor uuid.UUID, purpose string) (*AgentPurposeVersion, error) {
	purpose, err := checkReason("purpose", purpose, maxAgentPurpose)
	if err != nil {
		return nil, err
	}
	var out AgentPurposeVersion
	err = s.inWS(ctx, ws, func(tx *gorm.DB) error {
		if _, err := loadAgent(tx, ws, id, true); err != nil {
			return err
		}
		if err := tx.Raw(`INSERT INTO agent_purpose_version (workspace_id, agent_id, version, purpose, assessor_user_id)
		        VALUES (?, ?, (SELECT COALESCE(max(version), 0) + 1 FROM agent_purpose_version WHERE workspace_id = ? AND agent_id = ?), ?, ?)
		        RETURNING id, version, purpose, assessor_user_id, assessed_at`, ws, id, ws, id, purpose, actor).Scan(&out).Error; err != nil {
			return err
		}
		return appendGovEvent(tx, ws, GovEventAgentPurposeSet, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"agent_id": id, "version": out.Version})
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// RiskClassRequest is PUT /agent-identities/:id/risk-class.
type RiskClassRequest struct {
	RiskClass   string
	Obligations []string
	Reason      string
}

// RiskClassResult is either the new version (raised or unchanged rank: tier
// 1, applied) or the pending change a lowering waits in (tier 3).
type RiskClassResult struct {
	Applied       *AgentRiskClassVersion `json:"applied,omitempty"`
	PendingChange *AgentPendingChange    `json:"pending_change,omitempty"`
}

// SetRiskClass records a risk class. Raising it (or a first class, or the
// same rank with new obligations) applies at once; lowering it is tier 3 and
// creates a pending change a second person with governance:approve applies.
func (s *AgentIdentityService) SetRiskClass(ctx context.Context, ws, id, actor uuid.UUID, req RiskClassRequest) (*RiskClassResult, error) {
	rank, ok := agentRiskRank[req.RiskClass]
	if !ok {
		return nil, GovBadParam("risk_class", "risk_class must be one of minimal, limited, high, prohibited.")
	}
	reason, err := checkReason("reason", req.Reason, maxAgentReason)
	if err != nil {
		return nil, err
	}
	obligations := []string{}
	for _, o := range req.Obligations {
		if o = strings.TrimSpace(o); o != "" {
			if utf8.RuneCountInString(o) > 500 {
				return nil, GovBadParam("obligations", "each obligation must be at most 500 characters.")
			}
			obligations = append(obligations, o)
		}
	}
	if len(obligations) > 50 {
		return nil, GovBadParam("obligations", "at most 50 obligations.")
	}
	obl, _ := json.Marshal(obligations)
	var out RiskClassResult
	err = s.inWS(ctx, ws, func(tx *gorm.DB) error {
		if _, err := loadAgent(tx, ws, id, true); err != nil {
			return err
		}
		var cur []string
		if err := tx.Raw(`SELECT risk_class FROM agent_risk_class WHERE workspace_id = ? AND agent_id = ? ORDER BY version DESC LIMIT 1`,
			ws, id).Scan(&cur).Error; err != nil {
			return err
		}
		if len(cur) > 0 && rank < agentRiskRank[cur[0]] {
			payload := map[string]any{"risk_class": req.RiskClass, "obligations": obligations, "previous": cur[0]}
			pc, err := createPendingChange(tx, ws, PendingRiskClassLower, id, actor, reason, payload)
			if err != nil {
				return err
			}
			out.PendingChange = pc
			return nil
		}
		v, err := insertRiskClass(tx, ws, id, req.RiskClass, obl, reason, actor, nil, nil)
		if err != nil {
			return err
		}
		out.Applied = v
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func insertRiskClass(tx *gorm.DB, ws, id uuid.UUID, class string, obligations json.RawMessage, reason string,
	assessor uuid.UUID, approvedBy, pendingChange *uuid.UUID) (*AgentRiskClassVersion, error) {
	var out AgentRiskClassVersion
	if err := tx.Raw(`INSERT INTO agent_risk_class (workspace_id, agent_id, version, risk_class, obligations, reason, assessor_user_id,
	            approved_by_user_id, pending_change_id)
	        VALUES (?, ?, (SELECT COALESCE(max(version), 0) + 1 FROM agent_risk_class WHERE workspace_id = ? AND agent_id = ?),
	                ?, ?::jsonb, ?, ?, ?, ?)
	        RETURNING id, version, risk_class, obligations, reason, assessor_user_id, approved_by_user_id, pending_change_id, assessed_at`,
		ws, id, ws, id, class, string(obligations), reason, assessor, approvedBy, pendingChange).Scan(&out).Error; err != nil {
		return nil, err
	}
	actor := assessor
	if approvedBy != nil {
		actor = *approvedBy
	}
	if err := appendGovEvent(tx, ws, GovEventAgentRiskClassSet, models.GovActorUser, actor.String(), govEventRefs{},
		map[string]any{"agent_id": id, "version": out.Version, "risk_class": class, "approved_by": approvedBy}); err != nil {
		return nil, err
	}
	return &out, nil
}

/* ------------------------------------------------------------------------- */
/*                     Pending changes (tier 3, second person)                */
/* ------------------------------------------------------------------------- */

// Pending change kinds.
const (
	PendingRiskClassLower      = "agent_risk_class_lower"
	PendingClassificationLower = "resource_classification_lower"
)

// AgentPendingChange is one agent_pending_change row.
type AgentPendingChange struct {
	ID             uuid.UUID       `json:"id" gorm:"column:id"`
	Kind           string          `json:"kind" gorm:"column:kind"`
	SubjectID      uuid.UUID       `json:"subject_id" gorm:"column:subject_id"`
	Payload        json.RawMessage `json:"payload" gorm:"column:payload"`
	Reason         string          `json:"reason" gorm:"column:reason"`
	RequestedBy    uuid.UUID       `json:"requested_by" gorm:"column:requested_by"`
	RequestedAt    time.Time       `json:"requested_at" gorm:"column:requested_at"`
	State          string          `json:"state" gorm:"column:state"`
	DecidedBy      *uuid.UUID      `json:"decided_by" gorm:"column:decided_by"`
	DecidedAt      *time.Time      `json:"decided_at" gorm:"column:decided_at"`
	DecisionReason string          `json:"decision_reason" gorm:"column:decision_reason"`
}

func createPendingChange(tx *gorm.DB, ws uuid.UUID, kind string, subject, actor uuid.UUID, reason string, payload map[string]any) (*AgentPendingChange, error) {
	var open []AgentPendingChange
	if err := tx.Raw(`SELECT * FROM agent_pending_change WHERE workspace_id = ? AND kind = ? AND subject_id = ? AND state = 'pending'`,
		ws, kind, subject).Scan(&open).Error; err != nil {
		return nil, err
	}
	if len(open) > 0 {
		return nil, govConflict("change_pending", "A change of this kind is already waiting for a second person; it must be decided or withdrawn first.",
			map[string]any{"pending_change_id": open[0].ID})
	}
	raw, _ := json.Marshal(payload)
	var out AgentPendingChange
	if err := tx.Raw(`INSERT INTO agent_pending_change (workspace_id, kind, subject_id, payload, reason, requested_by)
	        VALUES (?, ?, ?, ?::jsonb, ?, ?) RETURNING *`, ws, kind, subject, string(raw), reason, actor).Scan(&out).Error; err != nil {
		return nil, err
	}
	if err := appendGovEvent(tx, ws, GovEventAgentChangeRequested, models.GovActorUser, actor.String(), govEventRefs{},
		map[string]any{"pending_change_id": out.ID, "kind": kind, "subject_id": subject}); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListPendingChanges lists ws's pending changes (state "" = pending).
func (s *AgentIdentityService) ListPendingChanges(ctx context.Context, ws uuid.UUID, state string) ([]AgentPendingChange, error) {
	if state == "" {
		state = "pending"
	}
	switch state {
	case "pending", "applied", "rejected", "withdrawn":
	default:
		return nil, GovBadParam("state", "state must be one of pending, applied, rejected, withdrawn.")
	}
	var out []AgentPendingChange
	err := s.readWS(ctx, ws, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT * FROM agent_pending_change WHERE workspace_id = ? AND state = ? ORDER BY requested_at DESC, id LIMIT 500`,
			ws, state).Scan(&out).Error
	})
	if out == nil {
		out = []AgentPendingChange{}
	}
	return out, err
}

// Pending change decisions.
const (
	PendingDecisionApprove  = "approve"
	PendingDecisionReject   = "reject"
	PendingDecisionWithdraw = "withdraw"
)

// DecidePendingChange applies, rejects or withdraws a pending change. Approve
// and reject need a second person (never the requester: 403 self_approval)
// who holds governance:approve now (read from the database); withdraw is the
// requester's alone.
//
// TODO(W5): break-glass for a workspace with exactly one admin (decision 4)
// belongs to W5's pending_change; until then such a workspace cannot lower.
func (s *AgentIdentityService) DecidePendingChange(ctx context.Context, ws, id, actor uuid.UUID, decision, reason string) (*AgentPendingChange, error) {
	reason = strings.TrimSpace(reason)
	if utf8.RuneCountInString(reason) > maxAgentReason {
		return nil, GovBadParam("reason", fmt.Sprintf("reason must be at most %d characters.", maxAgentReason))
	}
	switch decision {
	case PendingDecisionApprove, PendingDecisionReject, PendingDecisionWithdraw:
	default:
		return nil, GovNotFound()
	}
	var out *AgentPendingChange
	err := s.inWS(ctx, ws, func(tx *gorm.DB) error {
		var rows []AgentPendingChange
		if err := tx.Raw(`SELECT * FROM agent_pending_change WHERE workspace_id = ? AND id = ? FOR UPDATE`, ws, id).Scan(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return GovNotFound()
		}
		pc := rows[0]
		if pc.State != "pending" {
			return govConflict("change_decided", "The change has already been decided.", map[string]any{"state": pc.State})
		}
		newState, event := "", ""
		switch decision {
		case PendingDecisionWithdraw:
			if actor != pc.RequestedBy {
				return GovForbidden("Only the requester can withdraw a change.")
			}
			newState, event = "withdrawn", GovEventAgentChangeWithdrawn
		default:
			if actor == pc.RequestedBy {
				return govErr(403, "self_approval", "A tier-3 change needs a second person: the requester cannot decide it.", nil)
			}
			ok, err := holdsPermission(tx, ws, actor, "governance", "approve")
			if err != nil {
				return err
			}
			if !ok {
				return GovForbidden("Deciding a tier-3 change requires governance:approve.")
			}
			newState, event = "rejected", GovEventAgentChangeRejected
			if decision == PendingDecisionApprove {
				newState, event = "applied", GovEventAgentChangeApplied
				if err := applyPendingChange(tx, ws, pc, actor); err != nil {
					return err
				}
			}
		}
		var upd []AgentPendingChange
		if err := tx.Raw(`UPDATE agent_pending_change SET state = ?, decided_by = ?, decided_at = now(), decision_reason = ?
		        WHERE workspace_id = ? AND id = ? RETURNING *`, newState, actor, reason, ws, id).Scan(&upd).Error; err != nil {
			return err
		}
		if len(upd) != 1 {
			return fmt.Errorf("pending change update touched %d rows", len(upd))
		}
		out = &upd[0]
		return appendGovEvent(tx, ws, event, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"pending_change_id": id, "kind": pc.Kind, "subject_id": pc.SubjectID, "requested_by": pc.RequestedBy})
	})
	return out, err
}

func applyPendingChange(tx *gorm.DB, ws uuid.UUID, pc AgentPendingChange, approver uuid.UUID) error {
	switch pc.Kind {
	case PendingRiskClassLower:
		var p struct {
			RiskClass   string   `json:"risk_class"`
			Obligations []string `json:"obligations"`
		}
		if err := json.Unmarshal(pc.Payload, &p); err != nil {
			return err
		}
		if _, err := loadAgent(tx, ws, pc.SubjectID, true); err != nil {
			return err
		}
		obl, _ := json.Marshal(p.Obligations)
		if p.Obligations == nil {
			obl = []byte("[]")
		}
		_, err := insertRiskClass(tx, ws, pc.SubjectID, p.RiskClass, obl, pc.Reason, pc.RequestedBy, &approver, &pc.ID)
		return err
	case PendingClassificationLower:
		var c ResourceClassification
		if err := json.Unmarshal(pc.Payload, &c); err != nil {
			return err
		}
		return writeResourceClassification(tx, ws, pc.SubjectID, c, pc.RequestedBy, approver, pc.Reason)
	}
	return fmt.Errorf("unknown pending change kind %q", pc.Kind)
}
