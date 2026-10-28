package services

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Sentinel errors the controller maps onto HTTP statuses.
var (
	ErrGraphReviewNotFound = errors.New("graph review not found")
	ErrInvalidDecision     = errors.New("invalid decision: must be attest, remediate, or reject")
)

// GraphReview records a governance decision (attest, remediate, reject) against
// a specific entity at a specific graph revision. It is the audit record that
// proves a human looked at a graph diff and acted on it.
type GraphReview struct {
	ID            string    `json:"id"`
	WorkspaceID   string    `json:"workspace_id"`
	EntityID      string    `json:"entity_id"`
	EntityType    string    `json:"entity_type"`
	GraphRevision int64     `json:"graph_revision"`
	Decision      string    `json:"decision"` // attest, remediate, reject
	Reason        string    `json:"reason"`
	DecidedBy     string    `json:"decided_by"`
	CreatedAt     time.Time `json:"created_at"`
}

// GraphReviewService manages graph review decisions in memory.
//
// Storage is in-memory (a map guarded by a sync.Mutex), because the database
// migration is a separate concern. The interface is the same one a DB-backed
// implementation would expose, so swapping the backing store later changes
// nothing above the service layer.
type GraphReviewService struct {
	mu      sync.Mutex
	reviews map[string]*GraphReview // keyed by ID
}

// NewGraphReviewService constructs the service with an empty in-memory store.
func NewGraphReviewService() *GraphReviewService {
	return &GraphReviewService{reviews: make(map[string]*GraphReview)}
}

// CreateGraphReviewInput is what the caller provides to record a decision.
type CreateGraphReviewInput struct {
	EntityID      string `json:"entity_id"`
	EntityType    string `json:"entity_type"`
	GraphRevision int64  `json:"graph_revision"`
	Decision      string `json:"decision"`
	Reason        string `json:"reason"`
}

// Create records a new graph review decision.
func (s *GraphReviewService) Create(_ context.Context, workspaceID, decidedBy string, in CreateGraphReviewInput) (*GraphReview, error) {
	switch in.Decision {
	case "attest", "remediate", "reject":
	default:
		return nil, ErrInvalidDecision
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	r := &GraphReview{
		ID:            "grev_" + uuid.New().String(),
		WorkspaceID:   workspaceID,
		EntityID:      in.EntityID,
		EntityType:    in.EntityType,
		GraphRevision: in.GraphRevision,
		Decision:      in.Decision,
		Reason:        in.Reason,
		DecidedBy:     decidedBy,
		CreatedAt:     time.Now().UTC(),
	}
	s.reviews[r.ID] = r
	return r, nil
}

// Get returns a single graph review by ID, scoped to workspace.
func (s *GraphReviewService) Get(_ context.Context, workspaceID, id string) (*GraphReview, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r, ok := s.reviews[id]
	if !ok || r.WorkspaceID != workspaceID {
		return nil, ErrGraphReviewNotFound
	}
	return r, nil
}
