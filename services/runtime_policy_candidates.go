package services

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/authsec-ai/authsec/internal/runtimepolicy/candidates"
	"github.com/authsec-ai/authsec/internal/runtimepolicy/compile"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type candidateRequest struct {
	WorkloadIDs   []string `json:"workload_ids"`
	GraphRevision int64    `json:"graph_revision"`
	Window        *struct {
		Start time.Time `json:"start"`
		End   time.Time `json:"end"`
	} `json:"window"`
	Profile string `json:"profile"`
}

// CreateCandidate builds a draft from observed access, declared edges and
// coverage. The author is the candidate system actor, which cannot approve.
// The same graph revision and window return the same draft. An admin edit of
// that draft is left in place.
func (s *RuntimePolicyService) CreateCandidate(ctx context.Context, caller Actor, key string, body []byte) (int, []byte, error) {
	var req candidateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return 0, nil, statusErr(http.StatusBadRequest, "invalid_document", "The candidate body is not JSON.")
	}
	if len(req.WorkloadIDs) == 0 {
		return 0, nil, statusErr(http.StatusBadRequest, "invalid_document", "workload_ids are required.")
	}
	for _, id := range req.WorkloadIDs {
		if _, err := uuid.Parse(id); err != nil {
			return 0, nil, statusErr(http.StatusBadRequest, "invalid_document", "workload_ids must be uuids.")
		}
	}
	end := s.clock()
	start := end.Add(-candidates.BaselineWindow)
	if req.Window != nil && !req.Window.Start.IsZero() && !req.Window.End.IsZero() {
		start, end = req.Window.Start.UTC(), req.Window.End.UTC()
	}
	profile := req.Profile
	if profile == "" {
		profile = "linux-managed-v1"
	}
	route := "POST /api/iga/v2/runtime-policies/candidates"
	return s.once(ctx, caller, key, route, "", body, func(tx *gorm.DB) (int, []byte, error) {
		in, err := loadCandidateInput(tx, caller.WorkspaceID, req.WorkloadIDs, req.GraphRevision, start, end)
		if err != nil {
			return 0, nil, err
		}
		gen, err := candidates.Generate(in)
		if err != nil {
			if candidates.IsInputError(err) {
				return 0, nil, statusErr(http.StatusBadRequest, "invalid_document", err.Error())
			}
			return 0, nil, err
		}
		doc := candidateDocument(gen, req.WorkloadIDs, profile, req.GraphRevision)
		canonical, hash, err := compile.Canonical(doc)
		if err != nil {
			return 0, nil, err
		}
		sys := Actor{
			UserID: models.RuntimePolicyCandidateSystemUserID, WorkspaceID: caller.WorkspaceID,
			Kind: models.RuntimePolicyActorCandidateSystem,
		}
		name := doc.Name
		var existing []struct {
			ID       uuid.UUID
			Owner    uuid.UUID
			Revision int
			State    string
			Hash     string
			Author   uuid.UUID
		}
		if err := tx.Raw(`SELECT p.id, p.owner_user_id AS owner, p.current_draft_revision AS revision,
			r.state, r.content_hash AS hash, r.author_user_id AS author
			FROM runtime_policies p
			JOIN runtime_policy_revisions r
			  ON r.workspace_id = p.workspace_id AND r.policy_id = p.id AND r.revision = p.current_draft_revision
			WHERE p.workspace_id = ? AND p.name = ?`, caller.WorkspaceID, name).Scan(&existing).Error; err != nil {
			return 0, nil, err
		}
		var policyID uuid.UUID
		revision := 1
		status := http.StatusCreated
		if len(existing) == 1 {
			row := existing[0]
			policyID = row.ID
			revision = row.Revision
			if row.Owner != sys.UserID || row.Author != sys.UserID {
				return 0, nil, statusErr(http.StatusConflict, "admin_revision_preserved", "An administrator edited this candidate. It was not overwritten.")
			}
			if row.Hash == hash {
				status = http.StatusOK
			} else if row.State != models.RuntimePolicyStateDraft {
				return 0, nil, statusErr(http.StatusConflict, "admin_revision_preserved", "This candidate has left draft and was not overwritten.")
			} else {
				revision = row.Revision + 1
				if err := insertRevision(tx, sys, policyID, revision, canonical, hash, req.GraphRevision, models.RuntimePolicyStateDraft); err != nil {
					return 0, nil, err
				}
				if err := tx.Exec(`UPDATE runtime_policies SET current_draft_revision = ?, lifecycle = 'draft', updated_at = now()
					WHERE workspace_id = ? AND id = ?`, revision, caller.WorkspaceID, policyID).Error; err != nil {
					return 0, nil, err
				}
				status = http.StatusCreated
			}
		} else {
			policyID = uuid.New()
			if err := tx.Exec(`INSERT INTO runtime_policies
				(id, workspace_id, name, owner_user_id, current_draft_revision, lifecycle)
				VALUES (?, ?, ?, ?, 1, 'draft')`,
				policyID, caller.WorkspaceID, name, sys.UserID).Error; err != nil {
				return 0, nil, err
			}
			if err := insertRevision(tx, sys, policyID, 1, canonical, hash, req.GraphRevision, models.RuntimePolicyStateDraft); err != nil {
				return 0, nil, err
			}
		}
		if status == http.StatusCreated {
			if err := writeAudit(tx, sys, &policyID, "candidate", "", requestHash(route, "", body), req.WorkloadIDs,
				map[string]any{}, map[string]any{
					"revision": revision, "state": "draft", "input_hash": gen.InputHash,
					"partial": gen.Partial, "requested_by": caller.UserID,
				}); err != nil {
				return 0, nil, err
			}
		}
		out, _ := json.Marshal(map[string]any{
			"etag": etag(revision, hash),
			"data": candidateResponse(policyID, revision, hash, gen, start, end, req.GraphRevision),
		})
		return status, out, nil
	})
}

func candidateResponse(id uuid.UUID, revision int, hash string, gen candidates.Result, start, end time.Time, graph int64) map[string]any {
	return map[string]any{
		"policy_id": id, "revision": revision, "lifecycle": models.RuntimePolicyStateDraft, "content_hash": hash,
		"partial": gen.Partial, "limited_observation": gen.LimitedObservation,
		"generator_version": candidates.GeneratorVersion, "input_hash": gen.InputHash,
		"window":               map[string]any{"start": start.UTC(), "end": end.UTC()},
		"graph_revision":       graph,
		"coverage":             gen.Coverage,
		"rules":                gen.Rules,
		"denied":               gen.Denied,
		"detections":           gen.Detections,
		"review":               gen.Review,
		"unobserved_scheduled": gen.UnobservedScheduled,
	}
}

func candidateDocument(gen candidates.Result, workloads []string, profile string, graph int64) compile.Document {
	rules := make([]compile.Rule, 0, len(gen.Rules))
	controls := map[string]bool{}
	for _, rule := range gen.Rules {
		rules = append(rules, compile.Rule{
			ID: rule.ID, Action: rule.Action, ResourceID: rule.ResourceID, Path: rule.Path, Effect: "allow",
		})
		for _, c := range controlsForAction(rule.Action) {
			controls[c] = true
		}
	}
	need := make([]string, 0, len(controls))
	for c := range controls {
		need = append(need, c)
	}
	sort.Strings(need)
	if need == nil {
		need = []string{}
	}
	if rules == nil {
		rules = []compile.Rule{}
	}
	name := "candidate-" + gen.InputHash
	if len(gen.InputHash) > 20 {
		name = "candidate-" + gen.InputHash[:20]
	}
	return compile.Document{
		Name: name, Format: models.RuntimePolicyFormatV1,
		Targets:               compile.TargetSet{WorkloadIDs: append([]string(nil), workloads...)},
		Profile:               profile,
		DefaultEffect:         "deny",
		Rules:                 rules,
		RequiredControls:      need,
		EvidenceGraphRevision: graph,
		Mode:                  "observe",
	}
}

func controlsForAction(action string) []string {
	switch action {
	case "network.connect":
		return []string{"egress"}
	case "file.read", "file.write":
		return []string{"filesystem"}
	case "exec":
		return []string{"exec", "privilege"}
	case "secret.read":
		return []string{"secret"}
	case "admission":
		return []string{"admission"}
	default:
		return nil
	}
}

func loadCandidateInput(tx *gorm.DB, ws uuid.UUID, workloads []string, graph int64, start, end time.Time) (candidates.Input, error) {
	in := candidates.Input{
		WorkloadIDs: workloads, GraphRevision: graph, WindowStart: start, WindowEnd: end,
	}
	var obs []struct {
		ID         string
		WorkloadID string
		RuntimeID  string
		Action     string
		Outcome    string
		ResourceID string
		ObservedAt time.Time
		NativeKind string
		Meta       string
		Attrib     string
		RuntimeKey string
		Kind       string
		Attrs      string
	}
	err := tx.Raw(`SELECT o.id::text AS id, o.workload_id::text AS workload_id, o.runtime_instance_id::text AS runtime_id,
		o.action, o.outcome, o.resource_id::text AS resource_id, o.observed_at, o.attribution AS attrib,
		COALESCE(res.native_kind, '') AS native_kind, COALESCE(res.kind_metadata::text, '{}') AS meta,
		COALESCE(ri.runtime_key, '') AS runtime_key, COALESCE(ri.runtime_kind, '') AS kind,
		COALESCE(ri.native_attributes::text, '{}') AS attrs
		FROM iga_observed_access o
		JOIN iga_resources res ON res.workspace_id = o.workspace_id AND res.id = o.resource_id
		LEFT JOIN iga_runtime_instances ri ON ri.workspace_id = o.workspace_id AND ri.id = o.runtime_instance_id
		WHERE o.workspace_id = ? AND o.workload_id = ANY(?::uuid[]) AND o.observed_at >= ? AND o.observed_at <= ?`,
		ws, pgUUIDArray(workloads), start, end).Scan(&obs).Error
	if err != nil {
		return in, err
	}
	for _, row := range obs {
		meta := map[string]any{}
		_ = json.Unmarshal([]byte(row.Meta), &meta)
		attrs := map[string]any{}
		_ = json.Unmarshal([]byte(row.Attrs), &attrs)
		traits := candidates.Interpret(candidates.InterpretInput{
			Action: row.Action, Outcome: row.Outcome, Attribution: row.Attrib, NativeKind: row.NativeKind, Metadata: meta,
		})
		exe, _ := attrs["exe"].(string)
		if exe == "" {
			exe, _ = attrs["image"].(string)
		}
		if exe == "" {
			exe = row.RuntimeKey
		}
		env, _ := attrs["env"].(string)
		if env == "" {
			env = row.Kind
		}
		in.Observations = append(in.Observations, candidates.Observation{
			ID: row.ID, WorkloadID: row.WorkloadID, RuntimeInstanceID: row.RuntimeID,
			Executable: exe, Environment: env, Action: traits.Action, Outcome: row.Outcome,
			ResourceID: row.ResourceID, NativeKind: row.NativeKind, Address: traits.Address, Path: traits.Path,
			ObservedAt: row.ObservedAt, Incident: traits.Incident, Sensitive: traits.Sensitive,
			Internet: traits.Internet, Privilege: traits.Privilege, Wildcard: traits.Wildcard, Schedule: traits.Schedule,
		})
	}
	var deps []struct {
		WorkloadID  string
		ResourceID  string
		BindingKind string
		NativeKind  string
		Meta        string
	}
	if err := tx.Raw(`SELECT b.workload_id::text AS workload_id, b.resource_id::text AS resource_id, b.binding_kind,
		COALESCE(res.native_kind, '') AS native_kind, COALESCE(res.kind_metadata::text, '{}') AS meta
		FROM iga_workload_resource_bindings b
		JOIN iga_resources res ON res.workspace_id = b.workspace_id AND res.id = b.resource_id
		WHERE b.workspace_id = ? AND b.workload_id = ANY(?::uuid[]) AND b.state = 'current'`,
		ws, pgUUIDArray(workloads)).Scan(&deps).Error; err != nil {
		return in, err
	}
	for _, row := range deps {
		meta := map[string]any{}
		_ = json.Unmarshal([]byte(row.Meta), &meta)
		traits := candidates.Interpret(candidates.InterpretInput{
			BindingKind: row.BindingKind, NativeKind: row.NativeKind, Metadata: meta,
		})
		in.Declared = append(in.Declared, candidates.Dependency{
			WorkloadID: row.WorkloadID, ResourceID: row.ResourceID, BindingKind: row.BindingKind,
			Action: traits.Action, NativeKind: row.NativeKind, Address: traits.Address, Path: traits.Path,
			Sensitive: traits.Sensitive, Internet: traits.Internet, Privilege: traits.Privilege,
			Wildcard: traits.Wildcard, Schedule: traits.Schedule,
		})
	}
	var cov []struct {
		CollectorID string
		Class       string
		State       string
	}
	if err := tx.Raw(`SELECT ci.id::text AS collector_id, c.object_class AS class, c.state
		FROM iga_coverage_states c
		JOIN collector_instances ci ON ci.workspace_id = c.workspace_id AND ci.integration_id = c.integration_id
		WHERE c.workspace_id = ? AND ci.status = 'active'`, ws).Scan(&cov).Error; err != nil {
		return in, err
	}
	for _, row := range cov {
		in.Coverage = append(in.Coverage, candidates.Coverage{CollectorID: row.CollectorID, Class: row.Class, State: row.State})
	}
	return in, nil
}
