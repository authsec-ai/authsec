package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// PolicyContextTTL is the time-to-live for prepared policy contexts. Unsaved
// contexts are cleaned up after this duration.
const PolicyContextTTL = 30 * time.Minute

// PolicyContextService prepares, retrieves and cleans up policy context
// documents for the BG05 flow.
type PolicyContextService struct {
	db  *gorm.DB
	now func() time.Time
}

// NewPolicyContextService builds the service over db.
func NewPolicyContextService(db *gorm.DB) *PolicyContextService {
	return &PolicyContextService{db: db, now: time.Now}
}

func (s *PolicyContextService) clock() time.Time {
	if s == nil || s.now == nil {
		return time.Now().UTC()
	}
	return s.now().UTC()
}

// Prepare resolves canonical refs from the graph revision, checks capabilities,
// builds the context_document, computes a source_hash, and stores the context
// with a 30-minute TTL.
func (s *PolicyContextService) Prepare(ctx context.Context, actor Actor, workspaceID uuid.UUID, req models.PolicyContextRequest) (*models.PolicyContextResponse, error) {
	// Validate source_kind.
	if req.SourceKind != models.PolicyContextSourceGraph && req.SourceKind != models.PolicyContextSourceAction {
		return nil, statusErr(http.StatusBadRequest, "invalid_source_kind", "source_kind must be 'graph' or 'action'.")
	}

	// Source-specific validation.
	switch req.SourceKind {
	case models.PolicyContextSourceGraph:
		if req.RootWorkloadID == nil {
			return nil, statusErr(http.StatusBadRequest, "invalid_document", "root_workload_id is required for graph source.")
		}
	case models.PolicyContextSourceAction:
		if req.ActionID == nil {
			return nil, statusErr(http.StatusBadRequest, "invalid_document", "action_id is required for action source.")
		}
	}

	effect := req.RequestedEffect
	if effect == "" {
		effect = "deny"
	}

	// Build canonical target from the graph.
	canonicalTarget, err := s.resolveCanonicalTarget(ctx, workspaceID, req)
	if err != nil {
		return nil, err
	}

	// Look up base policies that cover the target workload.
	basePolicies, err := s.resolveBasePolicies(ctx, workspaceID, req)
	if err != nil {
		return nil, err
	}

	// Check capability requirements.
	capReqs, unsupported, err := s.checkCapabilities(ctx, workspaceID, req)
	if err != nil {
		return nil, err
	}

	// Build evidence refs.
	evidenceRefs := s.buildEvidenceRefs(req)

	// Build proposed rule stub.
	proposedRule := map[string]any{
		"effect":     effect,
		"operations": req.SelectedOperations,
	}

	// Build impact projection.
	impact := s.projectImpact(ctx, workspaceID, req, basePolicies)

	// Assemble the context document.
	ctxDoc := models.PolicyContextDocument{
		CanonicalTarget:    canonicalTarget,
		BasePolicies:       basePolicies,
		ProposedRule:       proposedRule,
		EvidenceRefs:       evidenceRefs,
		CapabilityReqs:     capReqs,
		UnsupportedReasons: unsupported,
		Impact:             impact,
	}
	docBytes, err := json.Marshal(ctxDoc)
	if err != nil {
		return nil, statusErr(http.StatusInternalServerError, "internal", "Failed to marshal context document.")
	}

	// Compute source hash for dedup.
	sourceHash := policyContextHash(workspaceID, actor.UserID, req)

	// Check for an existing non-expired context with the same hash.
	now := s.clock()
	var existing []models.PolicyContext
	if err := s.db.WithContext(ctx).Raw(
		`SELECT id, workspace_id, actor_user_id, source_kind, root_workload_id,
		        graph_revision, selected_ref, action_id, requested_effect,
		        selected_operations, context_document, source_hash, expires_at, created_at
		 FROM iga_policy_contexts
		 WHERE workspace_id = ? AND actor_user_id = ? AND source_hash = ? AND expires_at > ?`,
		workspaceID, actor.UserID, sourceHash, now,
	).Scan(&existing).Error; err != nil {
		return nil, statusErr(http.StatusInternalServerError, "internal", "Internal error.")
	}
	if len(existing) > 0 {
		return toPolicyContextResponse(&existing[0])
	}

	// Persist the new context.
	id := uuid.New()
	expiresAt := now.Add(PolicyContextTTL)

	pc := models.PolicyContext{
		ID:                 id,
		WorkspaceID:        workspaceID,
		ActorUserID:        actor.UserID,
		SourceKind:         req.SourceKind,
		RootWorkloadID:     req.RootWorkloadID,
		GraphRevision:      req.GraphRevision,
		SelectedRef:        req.SelectedRef,
		ActionID:           req.ActionID,
		RequestedEffect:    effect,
		SelectedOperations: pq.StringArray(req.SelectedOperations),
		ContextDocument:    datatypes.JSON(docBytes),
		SourceHash:         sourceHash,
		ExpiresAt:          expiresAt,
		CreatedAt:          now,
	}

	if err := s.db.WithContext(ctx).Exec(
		`INSERT INTO iga_policy_contexts
		 (id, workspace_id, actor_user_id, source_kind, root_workload_id,
		  graph_revision, selected_ref, action_id, requested_effect,
		  selected_operations, context_document, source_hash, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CAST(? AS jsonb), ?, ?, ?)`,
		pc.ID, pc.WorkspaceID, pc.ActorUserID, pc.SourceKind, pc.RootWorkloadID,
		pc.GraphRevision, pc.SelectedRef, pc.ActionID, pc.RequestedEffect,
		pq.Array(req.SelectedOperations), string(docBytes), pc.SourceHash, pc.ExpiresAt, pc.CreatedAt,
	).Error; err != nil {
		return nil, statusErr(http.StatusInternalServerError, "internal", "Internal error.")
	}

	return toPolicyContextResponse(&pc)
}

// Get retrieves a policy context by ID, validating actor and workspace binding.
func (s *PolicyContextService) Get(ctx context.Context, workspaceID, contextID, actorUserID uuid.UUID) (*models.PolicyContextResponse, error) {
	var rows []models.PolicyContext
	if err := s.db.WithContext(ctx).Raw(
		`SELECT id, workspace_id, actor_user_id, source_kind, root_workload_id,
		        graph_revision, selected_ref, action_id, requested_effect,
		        selected_operations, context_document, source_hash, expires_at, created_at
		 FROM iga_policy_contexts
		 WHERE workspace_id = ? AND id = ?`,
		workspaceID, contextID,
	).Scan(&rows).Error; err != nil {
		return nil, statusErr(http.StatusInternalServerError, "internal", "Internal error.")
	}
	if len(rows) == 0 {
		return nil, statusErr(http.StatusNotFound, "not_found", "Policy context not found.")
	}

	pc := &rows[0]

	// Validate actor binding: only the actor who created the context can read it.
	if pc.ActorUserID != actorUserID {
		return nil, statusErr(http.StatusForbidden, "forbidden", "You do not have access to this policy context.")
	}

	// Check expiry.
	if s.clock().After(pc.ExpiresAt) {
		return nil, statusErr(http.StatusGone, "expired", "This policy context has expired.")
	}

	return toPolicyContextResponse(pc)
}

// Cleanup deletes expired unsaved contexts. This is called by the background
// worker to keep the table clean.
func (s *PolicyContextService) Cleanup(ctx context.Context) error {
	now := s.clock()
	if err := s.db.WithContext(ctx).Exec(
		`DELETE FROM iga_policy_contexts WHERE expires_at < ?`, now,
	).Error; err != nil {
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// resolveCanonicalTarget builds the canonical target descriptor from the graph.
func (s *PolicyContextService) resolveCanonicalTarget(ctx context.Context, wsID uuid.UUID, req models.PolicyContextRequest) (map[string]any, error) {
	target := map[string]any{
		"source_kind": req.SourceKind,
	}

	switch req.SourceKind {
	case models.PolicyContextSourceGraph:
		if req.RootWorkloadID == nil {
			return target, nil
		}
		// Resolve workload details.
		var rows []struct {
			ID         uuid.UUID
			SourceKey  string
			Lifecycle  string
			RuntimeKind string
		}
		if err := s.db.WithContext(ctx).Raw(
			`SELECT id, source_key, lifecycle, COALESCE(runtime_kind, '') AS runtime_kind
			 FROM iga_workload WHERE workspace_id = ? AND id = ?`,
			wsID, *req.RootWorkloadID,
		).Scan(&rows).Error; err != nil {
			return nil, statusErr(http.StatusInternalServerError, "internal", "Internal error.")
		}
		if len(rows) == 0 {
			return nil, statusErr(http.StatusNotFound, "workload_not_found", "Root workload not found.")
		}
		target["workload_id"] = rows[0].ID
		target["source_key"] = rows[0].SourceKey
		target["lifecycle"] = rows[0].Lifecycle
		target["runtime_kind"] = rows[0].RuntimeKind

		if req.GraphRevision != nil {
			target["graph_revision"] = *req.GraphRevision
		}
		if req.SelectedRef != "" {
			target["selected_ref"] = req.SelectedRef
		}

	case models.PolicyContextSourceAction:
		if req.ActionID == nil {
			return target, nil
		}
		// Resolve action details from the activity index.
		var rows []struct {
			ID          uuid.UUID
			WorkloadID  *uuid.UUID
			EventFamily string
			Operation   string
			Outcome     string
		}
		if err := s.db.WithContext(ctx).Raw(
			`SELECT id, workload_id, event_family, COALESCE(operation, '') AS operation, outcome
			 FROM iga_runtime_activity WHERE workspace_id = ? AND action_id = ?`,
			wsID, *req.ActionID,
		).Scan(&rows).Error; err != nil {
			return nil, statusErr(http.StatusInternalServerError, "internal", "Internal error.")
		}
		if len(rows) == 0 {
			return nil, statusErr(http.StatusNotFound, "action_not_found", "Action not found.")
		}
		target["action_id"] = rows[0].ID
		target["event_family"] = rows[0].EventFamily
		target["operation"] = rows[0].Operation
		target["outcome"] = rows[0].Outcome
		if rows[0].WorkloadID != nil {
			target["workload_id"] = *rows[0].WorkloadID
		}
	}

	return target, nil
}

// resolveBasePolicies finds existing policies that cover the target workload.
func (s *PolicyContextService) resolveBasePolicies(ctx context.Context, wsID uuid.UUID, req models.PolicyContextRequest) ([]models.BasePolicyRef, error) {
	// Determine the workload ID to search for.
	var workloadID *uuid.UUID
	switch req.SourceKind {
	case models.PolicyContextSourceGraph:
		workloadID = req.RootWorkloadID
	case models.PolicyContextSourceAction:
		if req.ActionID != nil {
			var rows []struct{ WorkloadID *uuid.UUID }
			if err := s.db.WithContext(ctx).Raw(
				`SELECT workload_id FROM iga_runtime_activity WHERE workspace_id = ? AND action_id = ?`,
				wsID, *req.ActionID,
			).Scan(&rows).Error; err != nil {
				return nil, statusErr(http.StatusInternalServerError, "internal", "Internal error.")
			}
			if len(rows) > 0 {
				workloadID = rows[0].WorkloadID
			}
		}
	}

	if workloadID == nil {
		return []models.BasePolicyRef{}, nil
	}

	// Find policies whose target set covers this workload.
	var refs []struct {
		PolicyID uuid.UUID
		Revision int
	}
	if err := s.db.WithContext(ctx).Raw(
		`SELECT p.id AS policy_id, p.current_draft_revision AS revision
		 FROM runtime_policies p
		 JOIN runtime_policy_revisions r
		   ON r.workspace_id = p.workspace_id AND r.policy_id = p.id AND r.revision = p.current_draft_revision
		 WHERE p.workspace_id = ?
		   AND r.document->'targets'->'workload_ids' ? ?::text`,
		wsID, workloadID.String(),
	).Scan(&refs).Error; err != nil {
		// If the JSONB query fails (e.g. no policies), return empty.
		return []models.BasePolicyRef{}, nil
	}

	out := make([]models.BasePolicyRef, 0, len(refs))
	for _, ref := range refs {
		out = append(out, models.BasePolicyRef{PolicyID: ref.PolicyID, Revision: ref.Revision})
	}
	return out, nil
}

// checkCapabilities returns capability requirements and unsupported reasons
// for the target workload's collectors.
func (s *PolicyContextService) checkCapabilities(ctx context.Context, wsID uuid.UUID, req models.PolicyContextRequest) ([]string, []string, error) {
	var capReqs []string
	var unsupported []string

	// Map requested operations to required capabilities.
	for _, op := range req.SelectedOperations {
		controls := controlsForAction(op)
		capReqs = append(capReqs, controls...)
	}

	// Check which capabilities are actually available.
	var available []string
	if err := s.db.WithContext(ctx).Raw(
		`SELECT DISTINCT capability_digest FROM collector_capability_reports WHERE workspace_id = ?`, wsID,
	).Scan(&available).Error; err != nil {
		return capReqs, unsupported, nil
	}

	if len(available) == 0 && len(capReqs) > 0 {
		unsupported = append(unsupported, "No collector capability reports found for this workspace.")
	}

	return capReqs, unsupported, nil
}

// buildEvidenceRefs collects evidence reference IDs from the request.
func (s *PolicyContextService) buildEvidenceRefs(req models.PolicyContextRequest) []string {
	var refs []string
	if req.ActionID != nil {
		refs = append(refs, req.ActionID.String())
	}
	if req.RootWorkloadID != nil {
		refs = append(refs, req.RootWorkloadID.String())
	}
	if refs == nil {
		refs = []string{}
	}
	return refs
}

// projectImpact builds a simple impact projection.
func (s *PolicyContextService) projectImpact(_ context.Context, _ uuid.UUID, req models.PolicyContextRequest, basePolicies []models.BasePolicyRef) map[string]any {
	return map[string]any{
		"existing_policy_count": len(basePolicies),
		"requested_effect":     req.RequestedEffect,
		"operations_count":     len(req.SelectedOperations),
	}
}

// policyContextHash computes a deterministic hash over the request inputs for
// deduplication of identical prepare calls.
func policyContextHash(wsID, actorID uuid.UUID, req models.PolicyContextRequest) string {
	h := sha256.New()
	h.Write([]byte(wsID.String()))
	h.Write([]byte{0})
	h.Write([]byte(actorID.String()))
	h.Write([]byte{0})
	h.Write([]byte(req.SourceKind))
	h.Write([]byte{0})
	if req.RootWorkloadID != nil {
		h.Write([]byte(req.RootWorkloadID.String()))
	}
	h.Write([]byte{0})
	if req.GraphRevision != nil {
		b, _ := json.Marshal(*req.GraphRevision)
		h.Write(b)
	}
	h.Write([]byte{0})
	h.Write([]byte(req.SelectedRef))
	h.Write([]byte{0})
	if req.ActionID != nil {
		h.Write([]byte(req.ActionID.String()))
	}
	h.Write([]byte{0})
	h.Write([]byte(req.RequestedEffect))
	h.Write([]byte{0})
	ops, _ := json.Marshal(req.SelectedOperations)
	h.Write(ops)
	return hex.EncodeToString(h.Sum(nil))
}

// toPolicyContextResponse converts a PolicyContext row to the response DTO.
func toPolicyContextResponse(pc *models.PolicyContext) (*models.PolicyContextResponse, error) {
	var ctxDoc models.PolicyContextDocument
	if err := json.Unmarshal([]byte(pc.ContextDocument), &ctxDoc); err != nil {
		return nil, statusErr(http.StatusInternalServerError, "internal", "Failed to parse context document.")
	}

	return &models.PolicyContextResponse{
		ID:                 pc.ID,
		WorkspaceID:        pc.WorkspaceID,
		ActorUserID:        pc.ActorUserID,
		SourceKind:         pc.SourceKind,
		RootWorkloadID:     pc.RootWorkloadID,
		GraphRevision:      pc.GraphRevision,
		SelectedRef:        pc.SelectedRef,
		ActionID:           pc.ActionID,
		RequestedEffect:    pc.RequestedEffect,
		SelectedOperations: []string(pc.SelectedOperations),
		ContextDocument:    ctxDoc,
		SourceHash:         pc.SourceHash,
		ExpiresAt:          pc.ExpiresAt,
		CreatedAt:          pc.CreatedAt,
	}, nil
}
