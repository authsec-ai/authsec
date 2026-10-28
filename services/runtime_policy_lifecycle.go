package services

import (
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// runtimePolicyEdges is the §13.1 state machine. A6 performs the edges up
// to approved. The simulator sets simulated. Delivery owns published,
// superseded and revoked. A new draft is a new revision, not an edge back
// to draft.
var runtimePolicyEdges = map[[2]string]bool{
	{models.RuntimePolicyStateDraft, models.RuntimePolicyStateValidated}:      true,
	{models.RuntimePolicyStateValidated, models.RuntimePolicyStateSimulated}:  true,
	{models.RuntimePolicyStateSimulated, models.RuntimePolicyStateApproved}:   true,
	{models.RuntimePolicyStateApproved, models.RuntimePolicyStatePublished}:   true,
	{models.RuntimePolicyStatePublished, models.RuntimePolicyStateSuperseded}: true,
	{models.RuntimePolicyStatePublished, models.RuntimePolicyStateRevoked}:    true,
}

// RuntimePolicyTransitionAllowed reports whether a revision may move from
// one state to another. Same-state and every edge not in the table are forbidden.
func RuntimePolicyTransitionAllowed(from, to string) bool {
	return runtimePolicyEdges[[2]string{from, to}]
}

// ---------------------------------------------------------------------------
// BG06 — Context linkage for Create / PutDraft
// ---------------------------------------------------------------------------

// ContextLinkage carries the optional origin context reference that the caller
// supplies on Create or PutDraft. When present the service validates the
// context and stores its provenance on the revision metadata.
type ContextLinkage struct {
	OriginContextID *uuid.UUID `json:"origin_context_id,omitempty"`
}

// ContextProvenance is the metadata stored on the revision when an origin
// context is linked. It records the graph revision, selected refs, and
// evidence/action IDs from the context at link time.
type ContextProvenance struct {
	OriginContextID *uuid.UUID `json:"origin_context_id,omitempty"`
	GraphRevision   *int64     `json:"graph_revision,omitempty"`
	SelectedRef     string     `json:"selected_ref,omitempty"`
	EvidenceRefs    []string   `json:"evidence_refs,omitempty"`
	ActionID        *uuid.UUID `json:"action_id,omitempty"`
	SourceKind      string     `json:"source_kind,omitempty"`
	SourceHash      string     `json:"source_hash,omitempty"`
}

// validateContextLinkage checks the origin context: not expired, same actor and
// workspace, source hash matches. Returns provenance metadata on success or a
// context_stale error when the context has changed.
func validateContextLinkage(tx *gorm.DB, now time.Time, wsID, actorID uuid.UUID, contextID uuid.UUID) (*ContextProvenance, error) {
	var rows []models.PolicyContext
	if err := tx.Raw(
		`SELECT id, workspace_id, actor_user_id, source_kind, root_workload_id,
		        graph_revision, selected_ref, action_id, requested_effect,
		        selected_operations, context_document, source_hash, expires_at, created_at
		 FROM iga_policy_contexts
		 WHERE id = ?`, contextID,
	).Scan(&rows).Error; err != nil {
		return nil, statusErr(http.StatusInternalServerError, "internal", "Internal error.")
	}
	if len(rows) == 0 {
		return nil, statusErr(http.StatusNotFound, "context_not_found", "Origin policy context not found.")
	}

	pc := &rows[0]

	// Workspace binding.
	if pc.WorkspaceID != wsID {
		return nil, statusErr(http.StatusForbidden, "forbidden", "Context does not belong to this workspace.")
	}

	// Actor binding.
	if pc.ActorUserID != actorID {
		return nil, statusErr(http.StatusForbidden, "forbidden", "Context does not belong to this actor.")
	}

	// Expiry check.
	if now.After(pc.ExpiresAt) {
		return nil, statusErr(http.StatusGone, "context_stale", "The origin policy context has expired.")
	}

	// Rebuild source hash and compare.
	req := models.PolicyContextRequest{
		SourceKind:    pc.SourceKind,
		RootWorkloadID: pc.RootWorkloadID,
		GraphRevision: pc.GraphRevision,
		SelectedRef:   pc.SelectedRef,
		ActionID:      pc.ActionID,
		RequestedEffect: pc.RequestedEffect,
		SelectedOperations: []string(pc.SelectedOperations),
	}
	currentHash := policyContextHash(wsID, actorID, req)
	if currentHash != pc.SourceHash {
		return nil, &StatusError{
			Status:  http.StatusConflict,
			Code:    "context_stale",
			Message: "The origin policy context inputs have changed since preparation.",
			Extra:   map[string]any{"expected_hash": pc.SourceHash, "current_hash": currentHash},
		}
	}

	// Build evidence refs from the context document.
	var evidenceRefs []string
	if pc.ActionID != nil {
		evidenceRefs = append(evidenceRefs, pc.ActionID.String())
	}
	if pc.RootWorkloadID != nil {
		evidenceRefs = append(evidenceRefs, pc.RootWorkloadID.String())
	}
	if evidenceRefs == nil {
		evidenceRefs = []string{}
	}

	return &ContextProvenance{
		OriginContextID: &pc.ID,
		GraphRevision:   pc.GraphRevision,
		SelectedRef:     pc.SelectedRef,
		EvidenceRefs:    evidenceRefs,
		ActionID:        pc.ActionID,
		SourceKind:      pc.SourceKind,
		SourceHash:      pc.SourceHash,
	}, nil
}
