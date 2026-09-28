package services

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/internal/runtimepolicy/compile"
	"github.com/authsec-ai/authsec/internal/runtimepolicy/precedence"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type simulationRequest struct {
	GraphRevision int64 `json:"graph_revision"`
	EventWindow   struct {
		Start time.Time `json:"start"`
		End   time.Time `json:"end"`
	} `json:"event_window"`
}

// Simulate evaluates the current revision against a recorded event window.
// An engine error or an undefined result is a deny. validated moves to
// simulated. A later state gains another simulation row and does not move
// backward. A draft is refused.
func (s *RuntimePolicyService) Simulate(ctx context.Context, actor Actor, id uuid.UUID, key, ifMatch string, body []byte) (int, []byte, error) {
	var req simulationRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			return 0, nil, statusErr(http.StatusBadRequest, "invalid_document", "The simulation body is not JSON.")
		}
	}
	if !req.EventWindow.Start.IsZero() && !req.EventWindow.End.IsZero() {
		start, end := req.EventWindow.Start.UTC(), req.EventWindow.End.UTC()
		if end.Before(start) || end.Sub(start) > maxSimulationWindow {
			return 0, nil, statusErr(http.StatusBadRequest, "window_too_long", "The event window must be at most 30 days.")
		}
	}
	route := "POST /api/iga/v2/runtime-policies/:id/simulations"
	return s.onceLocked(ctx, actor, id, key, route, ifMatch, body, func(tx *gorm.DB, head policyHead, cur revisionHead) (int, []byte, error) {
		if etag(cur.Revision, cur.ContentHash) != ifMatch {
			return 0, nil, statusErr(http.StatusPreconditionFailed, "precondition_failed", "If-Match does not match the current revision.")
		}
		if cur.State == models.RuntimePolicyStateDraft {
			return 0, nil, statusErr(http.StatusConflict, "invalid_transition", "Simulation requires a validated revision.")
		}
		doc, err := compile.Parse([]byte(cur.Document))
		if err != nil {
			return 0, nil, statusFrom(err)
		}
		result, err := compile.Compile(ctx, s.reg, dbCatalog{tx: tx}, actor.WorkspaceID, cur.Revision, doc)
		if err != nil {
			return 0, nil, statusFrom(err)
		}
		end := s.clock()
		start := end.Add(-7 * 24 * time.Hour)
		if !req.EventWindow.Start.IsZero() && !req.EventWindow.End.IsZero() {
			start, end = req.EventWindow.Start.UTC(), req.EventWindow.End.UTC()
		}
		graph := cur.GraphRevision
		if req.GraphRevision != 0 {
			graph = req.GraphRevision
		}
		summary, coverage, err := s.evaluateWindow(ctx, tx, actor.WorkspaceID, doc, result, cur, start, end, graph)
		if err != nil {
			return 0, nil, err
		}
		simID := uuid.New()
		window, _ := json.Marshal(map[string]any{"start": start, "end": end})
		sum, _ := json.Marshal(summary)
		cov, _ := json.Marshal(coverage)
		if err := tx.Exec(`INSERT INTO runtime_policy_simulations
			(id, workspace_id, policy_id, revision, revision_hash, graph_revision, event_window, target_digest, input_coverage, result_summary, artifact_refs)
			VALUES (?, ?, ?, ?, ?, ?, CAST(? AS jsonb), ?, CAST(? AS jsonb), CAST(? AS jsonb), '[]'::jsonb)`,
			simID, actor.WorkspaceID, id, cur.Revision, cur.ContentHash, graph, string(window), result.TargetDigest, string(cov), string(sum),
		).Error; err != nil {
			return 0, nil, err
		}
		state := cur.State
		if cur.State == models.RuntimePolicyStateValidated && RuntimePolicyTransitionAllowed(cur.State, models.RuntimePolicyStateSimulated) {
			if err := tx.Exec(`UPDATE runtime_policy_revisions SET state = 'simulated' WHERE workspace_id = ? AND policy_id = ? AND revision = ?`,
				actor.WorkspaceID, id, cur.Revision).Error; err != nil {
				return 0, nil, err
			}
			if err := tx.Exec(`UPDATE runtime_policies SET lifecycle = 'simulated', updated_at = now() WHERE workspace_id = ? AND id = ?`,
				actor.WorkspaceID, id).Error; err != nil {
				return 0, nil, err
			}
			state = models.RuntimePolicyStateSimulated
		}
		if err := writeAudit(tx, actor, &id, "simulate", "", requestHash(route, ifMatch, body), doc.Targets.WorkloadIDs,
			map[string]any{"state": cur.State}, map[string]any{"state": state, "simulation_id": simID}); err != nil {
			return 0, nil, err
		}
		out, _ := json.Marshal(map[string]any{
			"etag": etag(cur.Revision, cur.ContentHash),
			"data": map[string]any{
				"simulation_id": simID, "policy_id": id, "revision": cur.Revision, "state": state,
				"revision_hash": cur.ContentHash, "target_digest": result.TargetDigest,
				"graph_revision": graph, "result_summary": summary,
			},
		})
		return http.StatusCreated, out, nil
	})
}

// GetSimulation reads one simulation in the caller's workspace.
func (s *RuntimePolicyService) GetSimulation(ctx context.Context, ws, id uuid.UUID) (int, []byte, error) {
	var rows []struct {
		ID            uuid.UUID
		PolicyID      uuid.UUID
		Revision      int
		RevisionHash  string
		GraphRevision int64
		EventWindow   string
		TargetDigest  string
		InputCoverage string
		ResultSummary string
		ArtifactRefs  string
	}
	err := s.db.WithContext(ctx).Raw(`SELECT id, policy_id, revision, revision_hash, graph_revision,
		event_window::text AS event_window, target_digest, input_coverage::text AS input_coverage,
		result_summary::text AS result_summary, artifact_refs::text AS artifact_refs
		FROM runtime_policy_simulations WHERE workspace_id = ? AND id = ?`, ws, id).Scan(&rows).Error
	if err != nil {
		return 0, nil, statusFrom(err)
	}
	if len(rows) == 0 {
		return 0, nil, statusErr(http.StatusNotFound, "not_found", "Not found.")
	}
	row := rows[0]
	out, _ := json.Marshal(map[string]any{"data": map[string]any{
		"simulation_id": row.ID, "policy_id": row.PolicyID, "revision": row.Revision,
		"revision_hash": row.RevisionHash, "graph_revision": row.GraphRevision,
		"target_digest":  row.TargetDigest,
		"event_window":   json.RawMessage(row.EventWindow),
		"input_coverage": json.RawMessage(row.InputCoverage),
		"result_summary": json.RawMessage(row.ResultSummary),
		"artifact_refs":  json.RawMessage(row.ArtifactRefs),
	}})
	return http.StatusOK, out, nil
}

type simSummary struct {
	Allow     int         `json:"allow"`
	Deny      int         `json:"deny"`
	WouldDeny int         `json:"would_deny"`
	Samples   []simSample `json:"samples"`
}

type simSample struct {
	Action      string   `json:"action"`
	Effect      string   `json:"effect"`
	ReasonCodes []string `json:"reason_codes"`
	ResourceID  string   `json:"resource_id"`
	WorkloadID  string   `json:"workload_id"`
}

const (
	maxSimulationWindow = 30 * 24 * time.Hour
	maxSimulationRows   = 50000
)

func (s *RuntimePolicyService) evaluateWindow(ctx context.Context, tx *gorm.DB, ws uuid.UUID, doc compile.Document, result *compile.Result, cur revisionHead, start, end time.Time, graph int64) (simSummary, map[string]any, error) {
	summary := simSummary{Samples: []simSample{}}
	if len(doc.Targets.WorkloadIDs) == 0 {
		return summary, map[string]any{"observations": 0}, nil
	}
	var rows []struct {
		WorkloadID string
		RuntimeID  string
		Action     string
		ResourceID string
		Meta       string
	}
	err := tx.Raw(`SELECT o.workload_id::text AS workload_id, o.runtime_instance_id::text AS runtime_id,
		o.action, o.resource_id::text AS resource_id, COALESCE(res.kind_metadata::text, '{}') AS meta
		FROM iga_observed_access o
		JOIN iga_resources res ON res.workspace_id = o.workspace_id AND res.id = o.resource_id
		WHERE o.workspace_id = ? AND o.workload_id = ANY(?::uuid[]) AND o.observed_at >= ? AND o.observed_at <= ?
		ORDER BY o.observed_at
		LIMIT ?`,
		ws, pgUUIDArray(doc.Targets.WorkloadIDs), start, end, maxSimulationRows+1).Scan(&rows).Error
	if err != nil {
		return summary, nil, err
	}
	truncated := false
	if len(rows) > maxSimulationRows {
		truncated = true
		rows = rows[:maxSimulationRows]
	}
	mode := doc.Mode
	if mode == "" {
		mode = "observe"
	}
	data := result.Data
	factsByWorkload := map[string][]precedence.Fact{}
	for _, row := range rows {
		meta := map[string]any{}
		_ = json.Unmarshal([]byte(row.Meta), &meta)
		path, _ := meta["path"].(string)
		facts, ok := factsByWorkload[row.WorkloadID]
		if !ok {
			facts, err = loadPrecedence(tx, ws, row.WorkloadID, doc, s.clock())
			if err != nil {
				return summary, nil, err
			}
			factsByWorkload[row.WorkloadID] = facts
		}
		outcome := precedence.Resolve(s.clock(), facts)
		input := map[string]any{
			"workspace_id": ws.String(), "workload_id": row.WorkloadID, "runtime_instance_id": row.RuntimeID,
			"action": row.Action, "resource_id": row.ResourceID,
			"native_target":   map[string]any{"path": path},
			"policy_revision": cur.Revision, "graph_revision": graph,
			"quarantined": outcome.Source == precedence.SourceQuarantine && outcome.Effect == "deny",
		}
		decision := s.engine().Eval(ctx, ws.String(), cur.ContentHash, data, input)
		effect := decision.Effect
		if effect != "allow" {
			effect = "deny"
		}
		switch effect {
		case "allow":
			summary.Allow++
		default:
			summary.Deny++
			if mode == "observe" {
				summary.WouldDeny++
			}
		}
		if len(summary.Samples) < 20 {
			reasons := decision.ReasonCodes
			if reasons == nil {
				reasons = []string{}
			}
			summary.Samples = append(summary.Samples, simSample{
				Action: row.Action, Effect: effect, ReasonCodes: reasons,
				ResourceID: row.ResourceID, WorkloadID: row.WorkloadID,
			})
		}
	}
	return summary, map[string]any{"observations": len(rows), "truncated": truncated}, nil
}

func pgUUIDArray(ids []string) string {
	if len(ids) == 0 {
		return "{}"
	}
	out := make([]byte, 0, 2+len(ids)*37)
	out = append(out, '{')
	for i, id := range ids {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, id...)
	}
	out = append(out, '}')
	return string(out)
}
