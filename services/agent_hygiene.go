package services

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// The agent identity sweep (SPEC-secops-backend-upgrade.md W7): one pass per
// workspace, every AgentIdentitySweepInterval, in one transaction under that
// workspace's row-level security. It
//
//  1. links every unlinked source row to an agent (agent_identity_link) --
//     the safety net under the projection hooks (IGA promotion has none);
//  2. creates the default responder group with the workspace admins;
//  3. marks an active agent deleted_at_source when every source it has
//     reports it gone, writing agent.deleted_at_source and agent.ask_needed
//     (and an ask, W4); an agent seen again is active once more;
//  4. hygiene, stale agents: an active agent whose instances act as cloud
//     identities with recorded calls (cloud_usage), and whose last call is
//     more than 30 days old, gets a stale_agent finding and its iga_agents
//     aliases rollup_state 'stale' (the agent's state stays active); a call
//     again resolves it and restores the rollup state;
//  5. hygiene, overdue keys: an active IAM access key whose creation (its
//     last rotation: AWS rotates by creating a new key; the credential
//     report's access_key_N_last_rotated is the same date) is more than 90
//     days ago gets an overdue_key finding and credential.rotation_overdue.
//
// AUTHSEC_DISABLE_AGENT_IDENTITY_SWEEP=true stops the worker.

// Sweep thresholds.
const (
	AgentStaleAfter            = 30 * 24 * time.Hour
	AccessKeyRotationOverdue   = 90 * 24 * time.Hour
	AgentIdentitySweepInterval = 15 * time.Minute
)

// AgentSweepResult counts what one sweep did.
type AgentSweepResult struct {
	Linked          int `json:"linked"`
	DeletedAtSource int `json:"deleted_at_source"`
	Reappeared      int `json:"reappeared"`
	StaleOpened     int `json:"stale_opened"`
	StaleResolved   int `json:"stale_resolved"`
	OverdueOpened   int `json:"overdue_opened"`
	OverdueResolved int `json:"overdue_resolved"`
}

// RunAgentIdentitySweep runs the sweep for one workspace at now.
func RunAgentIdentitySweep(ctx context.Context, db *gorm.DB, ws uuid.UUID, now time.Time) (AgentSweepResult, error) {
	var res AgentSweepResult
	err := tenancy.InWorkspace(ctx, db, ws, func(tx *gorm.DB) error {
		if !agentIdentityReady(tx) {
			return nil
		}
		var err error
		if res.Linked, err = LinkAgentSources(tx, ws, "", ""); err != nil {
			return err
		}
		if err := ensureDefaultResponderGroup(tx, ws); err != nil {
			return err
		}
		if err := sweepDeletedAtSource(tx, ws, &res); err != nil {
			return err
		}
		if err := sweepStaleAgents(tx, ws, now, &res); err != nil {
			return err
		}
		return sweepOverdueKeys(tx, ws, now, &res)
	})
	return res, err
}

// aliveAliasSQL is true when an alias's source row still reports the agent.
const aliveAliasSQL = `EXISTS (SELECT 1 FROM agent_alias x
	   LEFT JOIN iga_workload w ON x.source_table = 'iga_workload' AND w.workspace_id = x.workspace_id AND w.id::text = x.source_id
	   LEFT JOIN discovered_agents d ON x.source_table = 'discovered_agents' AND d.workspace_id = x.workspace_id AND d.id::text = x.source_id
	   LEFT JOIN iga_agents g ON x.source_table = 'iga_agents' AND g.workspace_id = x.workspace_id AND g.id::text = x.source_id
	  WHERE x.workspace_id = a.workspace_id AND x.agent_id = a.id
	    AND ((x.source_table = 'iga_workload' AND w.lifecycle = 'active')
	      OR (x.source_table = 'discovered_agents' AND d.runtime_status <> 'gone')
	      OR (x.source_table = 'iga_agents' AND g.lifecycle = 'active')))`

func sweepDeletedAtSource(tx *gorm.DB, ws uuid.UUID, res *AgentSweepResult) error {
	var gone []uuid.UUID
	if err := tx.Raw(`SELECT a.id FROM agent a WHERE a.workspace_id = ? AND a.state = 'active'
	      AND EXISTS (SELECT 1 FROM agent_alias x WHERE x.workspace_id = a.workspace_id AND x.agent_id = a.id
	                   AND x.source_table IN ('iga_workload', 'discovered_agents', 'iga_agents'))
	      AND NOT `+aliveAliasSQL+` ORDER BY a.id`, ws).Scan(&gone).Error; err != nil {
		return err
	}
	for _, id := range gone {
		if err := tx.Exec(`UPDATE agent SET state = 'deleted_at_source', ended_reason = 'Every source of the agent reports it gone.',
		        ended_by = NULL, ended_at = now(), version = version + 1, updated_at = now()
		        WHERE workspace_id = ? AND id = ? AND state = 'active'`, ws, id).Error; err != nil {
			return err
		}
		if err := appendGovEvent(tx, ws, GovEventAgentDeletedAtSource, models.GovActorSystem, "", govEventRefs{},
			map[string]any{"agent_id": id}); err != nil {
			return err
		}
		if err := appendGovEvent(tx, ws, GovEventAgentAskNeeded, models.GovActorSystem, "", govEventRefs{},
			map[string]any{"agent_id": id, "reason": AskReasonDeletedAtSource,
				"subject": map[string]any{"question": "The agent is gone from every source: retire it, or say where it went."}}); err != nil {
			return err
		}
		raiseAgentAskNeeded(tx, ws, id, AskReasonDeletedAtSource, nil)
		res.DeletedAtSource++
	}
	var back []uuid.UUID
	if err := tx.Raw(`SELECT a.id FROM agent a WHERE a.workspace_id = ? AND a.state = 'deleted_at_source' AND `+aliveAliasSQL+` ORDER BY a.id`,
		ws).Scan(&back).Error; err != nil {
		return err
	}
	for _, id := range back {
		if err := tx.Exec(`UPDATE agent SET state = 'active', ended_reason = '', ended_by = NULL, ended_at = NULL,
		        version = version + 1, updated_at = now() WHERE workspace_id = ? AND id = ? AND state = 'deleted_at_source'`, ws, id).Error; err != nil {
			return err
		}
		if err := appendGovEvent(tx, ws, GovEventAgentReappeared, models.GovActorSystem, "", govEventRefs{},
			map[string]any{"agent_id": id}); err != nil {
			return err
		}
		res.Reappeared++
	}
	return nil
}

func sweepStaleAgents(tx *gorm.DB, ws uuid.UUID, now time.Time, res *AgentSweepResult) error {
	// Agents on a source that sees calls: their instances' cloud identities
	// have cloud_usage rows. last_call is the latest of them.
	var rows []struct {
		ID       uuid.UUID
		LastCall *time.Time
	}
	if err := tx.Raw(`SELECT a.id, max(u.last_used_at) AS last_call
	      FROM agent a
	      JOIN iga_agent_instances i ON i.workspace_id = a.workspace_id AND i.agent_ref = a.id AND i.cloud_identity_id IS NOT NULL
	      JOIN cloud_usage u ON u.workspace_id = a.workspace_id AND u.identity_id = i.cloud_identity_id
	     WHERE a.workspace_id = ? AND a.state = 'active'
	     GROUP BY a.id ORDER BY a.id`, ws).Scan(&rows).Error; err != nil {
		return err
	}
	cutoff := now.Add(-AgentStaleAfter)
	for _, r := range rows {
		stale := r.LastCall == nil || r.LastCall.Before(cutoff)
		key := r.ID.String()
		var open []struct {
			ID       uuid.UUID
			Evidence json.RawMessage
		}
		if err := tx.Raw(`SELECT id, evidence FROM agent_hygiene_finding WHERE workspace_id = ? AND kind = 'stale_agent'
		        AND subject_key = ? AND state = 'open'`, ws, key).Scan(&open).Error; err != nil {
			return err
		}
		if stale {
			if len(open) > 0 {
				if err := tx.Exec(`UPDATE agent_hygiene_finding SET last_seen = now() WHERE workspace_id = ? AND id = ?`, ws, open[0].ID).Error; err != nil {
					return err
				}
				continue
			}
			var prev []struct {
				ID          uuid.UUID
				RollupState string
			}
			if err := tx.Raw(`SELECT g.id, g.rollup_state FROM agent_alias x JOIN iga_agents g ON g.workspace_id = x.workspace_id
			        AND g.id::text = x.source_id WHERE x.workspace_id = ? AND x.agent_id = ? AND x.source_table = 'iga_agents'`,
				ws, r.ID).Scan(&prev).Error; err != nil {
				return err
			}
			previous := map[string]string{}
			for _, p := range prev {
				previous[p.ID.String()] = p.RollupState
				if err := tx.Exec(`UPDATE iga_agents SET rollup_state = 'stale', updated_at = now() WHERE workspace_id = ? AND id = ?`,
					ws, p.ID).Error; err != nil {
					return err
				}
			}
			ev, _ := json.Marshal(map[string]any{"last_call_at": r.LastCall, "threshold_days": int(AgentStaleAfter.Hours() / 24),
				"previous_rollup_states": previous})
			subj, _ := json.Marshal(map[string]any{"agent_id": r.ID})
			if err := tx.Exec(`INSERT INTO agent_hygiene_finding (workspace_id, kind, subject_key, agent_id, subject, evidence)
			        VALUES (?, 'stale_agent', ?, ?, ?::jsonb, ?::jsonb)
			        ON CONFLICT (workspace_id, kind, subject_key) DO UPDATE SET state = 'open', resolved_at = NULL,
			          last_seen = now(), evidence = EXCLUDED.evidence`, ws, key, r.ID, string(subj), string(ev)).Error; err != nil {
				return err
			}
			if err := appendGovEvent(tx, ws, GovEventAgentStale, models.GovActorSystem, "", govEventRefs{},
				map[string]any{"agent_id": r.ID, "last_call_at": r.LastCall}); err != nil {
				return err
			}
			res.StaleOpened++
			continue
		}
		if len(open) == 0 {
			continue
		}
		var ev struct {
			Previous map[string]string `json:"previous_rollup_states"`
		}
		_ = json.Unmarshal(open[0].Evidence, &ev)
		for id, st := range ev.Previous {
			if st == "" || st == "stale" {
				st = "unknown"
			}
			if err := tx.Exec(`UPDATE iga_agents SET rollup_state = ?, updated_at = now() WHERE workspace_id = ? AND id::text = ? AND rollup_state = 'stale'`,
				st, ws, id).Error; err != nil {
				return err
			}
		}
		if err := tx.Exec(`UPDATE agent_hygiene_finding SET state = 'resolved', resolved_at = now() WHERE workspace_id = ? AND id = ?`,
			ws, open[0].ID).Error; err != nil {
			return err
		}
		res.StaleResolved++
	}
	return nil
}

func sweepOverdueKeys(tx *gorm.DB, ws uuid.UUID, now time.Time, res *AgentSweepResult) error {
	cutoff := now.Add(-AccessKeyRotationOverdue)
	var keys []struct {
		NativeID    string
		IdentityID  uuid.UUID
		ConnectorID uuid.UUID
		CreatedAt   time.Time
		Arn         string
	}
	if err := tx.Raw(`SELECT s.native_id, s.identity_id, s.connector_id, s.created_at, COALESCE(i.native_id, '') AS arn
	      FROM cloud_secret s LEFT JOIN cloud_identity i ON i.id = s.identity_id AND i.workspace_id = s.workspace_id
	     WHERE s.workspace_id = ? AND s.kind = 'access_key' AND s.status = 'active'
	       AND s.created_at IS NOT NULL AND s.created_at < ?
	     ORDER BY s.native_id`, ws, cutoff).Scan(&keys).Error; err != nil {
		return err
	}
	overdue := map[string]bool{}
	for _, k := range keys {
		overdue[k.NativeID] = true
		subj, _ := json.Marshal(map[string]any{"access_key_id": k.NativeID, "identity_id": k.IdentityID,
			"identity_arn": k.Arn, "connector_id": k.ConnectorID})
		ev, _ := json.Marshal(map[string]any{"last_rotated_at": k.CreatedAt,
			"age_days": int(now.Sub(k.CreatedAt).Hours() / 24), "threshold_days": int(AccessKeyRotationOverdue.Hours() / 24)})
		var prior []string
		if err := tx.Raw(`SELECT state FROM agent_hygiene_finding WHERE workspace_id = ? AND kind = 'overdue_key' AND subject_key = ?`,
			ws, k.NativeID).Scan(&prior).Error; err != nil {
			return err
		}
		if err := tx.Exec(`INSERT INTO agent_hygiene_finding (workspace_id, kind, subject_key, subject, evidence)
		        VALUES (?, 'overdue_key', ?, ?::jsonb, ?::jsonb)
		        ON CONFLICT (workspace_id, kind, subject_key) DO UPDATE SET last_seen = now(), evidence = EXCLUDED.evidence,
		          state = 'open', resolved_at = NULL`, ws, k.NativeID, string(subj), string(ev)).Error; err != nil {
			return err
		}
		if len(prior) == 0 || prior[0] == "resolved" {
			if err := appendGovEvent(tx, ws, GovEventCredentialOverdue, models.GovActorSystem, "", govEventRefs{},
				map[string]any{"access_key_id": k.NativeID, "identity_id": k.IdentityID, "last_rotated_at": k.CreatedAt}); err != nil {
				return err
			}
			res.OverdueOpened++
		}
	}
	var open []struct {
		ID         uuid.UUID
		SubjectKey string
	}
	if err := tx.Raw(`SELECT id, subject_key FROM agent_hygiene_finding WHERE workspace_id = ? AND kind = 'overdue_key' AND state = 'open'`,
		ws).Scan(&open).Error; err != nil {
		return err
	}
	for _, f := range open {
		if overdue[f.SubjectKey] {
			continue
		}
		if err := tx.Exec(`UPDATE agent_hygiene_finding SET state = 'resolved', resolved_at = now() WHERE workspace_id = ? AND id = ?`,
			ws, f.ID).Error; err != nil {
			return err
		}
		res.OverdueResolved++
	}
	return nil
}

// AgentHygieneFinding is one agent_hygiene_finding row.
type AgentHygieneFinding struct {
	ID         uuid.UUID       `json:"id" gorm:"column:id"`
	Kind       string          `json:"kind" gorm:"column:kind"`
	SubjectKey string          `json:"subject_key" gorm:"column:subject_key"`
	AgentID    *uuid.UUID      `json:"agent_id" gorm:"column:agent_id"`
	Subject    json.RawMessage `json:"subject" gorm:"column:subject"`
	Evidence   json.RawMessage `json:"evidence" gorm:"column:evidence"`
	State      string          `json:"state" gorm:"column:state"`
	FirstSeen  time.Time       `json:"first_seen" gorm:"column:first_seen"`
	LastSeen   time.Time       `json:"last_seen" gorm:"column:last_seen"`
	ResolvedAt *time.Time      `json:"resolved_at" gorm:"column:resolved_at"`
}

// ListHygieneFindings lists ws's hygiene findings (kind and state optional).
func (s *AgentIdentityService) ListHygieneFindings(ctx context.Context, ws uuid.UUID, kind, state string) ([]AgentHygieneFinding, error) {
	switch kind {
	case "", "stale_agent", "overdue_key", "unknown_deployer":
	default:
		return nil, GovBadParam("kind", "kind must be one of stale_agent, overdue_key, unknown_deployer.")
	}
	switch state {
	case "", "open", "resolved":
	default:
		return nil, GovBadParam("state", "state must be open or resolved.")
	}
	var out []AgentHygieneFinding
	err := s.readWS(ctx, ws, func(tx *gorm.DB) error {
		q := `SELECT * FROM agent_hygiene_finding WHERE workspace_id = ?`
		args := []any{ws}
		if kind != "" {
			q += ` AND kind = ?`
			args = append(args, kind)
		}
		if state != "" {
			q += ` AND state = ?`
			args = append(args, state)
		}
		return tx.Raw(q+` ORDER BY last_seen DESC, id LIMIT 500`, args...).Scan(&out).Error
	})
	if out == nil {
		out = []AgentHygieneFinding{}
	}
	return out, err
}

// RunAgentIdentityWorker sweeps every workspace each interval until ctx ends.
func RunAgentIdentityWorker(ctx context.Context, db *gorm.DB) {
	if os.Getenv("AUTHSEC_DISABLE_AGENT_IDENTITY_SWEEP") == "true" {
		log.Printf("[agent-identity] sweep worker not started: AUTHSEC_DISABLE_AGENT_IDENTITY_SWEEP=true")
		return
	}
	for {
		var wss []uuid.UUID
		// TENANT-EXEMPT: the sweep runs across workspaces (no request tenant) and lists workspace ids only; each workspace is swept in its own workspace-bound transaction (tenancy.InWorkspace).
		if err := db.WithContext(ctx).Raw(`SELECT id FROM workspaces ORDER BY id`).Scan(&wss).Error; err != nil && ctx.Err() == nil {
			log.Printf("[agent-identity] list workspaces: %v", err)
		}
		for _, ws := range wss {
			if ctx.Err() != nil {
				return
			}
			if _, err := RunAgentIdentitySweep(ctx, db, ws, time.Now()); err != nil {
				log.Printf("[agent-identity] sweep workspace %s: %v", ws, err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(AgentIdentitySweepInterval):
		}
	}
}
