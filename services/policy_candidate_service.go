package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

var (
	ErrCandidateNotFound = errors.New("policy_candidate: not found")
	ErrCandidateState    = errors.New("policy_candidate: invalid state transition")
	ErrCandidateInput    = errors.New("policy_candidate: invalid input")
)

// CandidateState tracks the lifecycle of a candidate generation job.
type CandidateState string

const (
	CandidateStatePending    CandidateState = "pending"
	CandidateStateGenerating CandidateState = "generating"
	CandidateStateCompleted  CandidateState = "completed"
	CandidateStateFailed     CandidateState = "failed"
)

// CandidateJob represents a policy candidate generation job.
type CandidateJob struct {
	CandidateID      uuid.UUID      `json:"candidate_id"`
	WorkspaceID      uuid.UUID      `json:"workspace_id"`
	WorkloadIDs      []string       `json:"workload_ids"`
	GraphRevision    int64          `json:"graph_revision"`
	EvidenceWindow   string         `json:"evidence_window"`
	TemplateVersion  string         `json:"template_version"`
	GeneratorVersion string         `json:"generator_version"`
	InputDigest      string         `json:"input_digest"`
	State            CandidateState `json:"state"`
	Warnings         []string       `json:"warnings,omitempty"`
	DraftPolicyID    *uuid.UUID     `json:"draft_policy_id,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
	CompletedAt      *time.Time     `json:"completed_at,omitempty"`
	Error            string         `json:"error,omitempty"`
}

// CandidateRequest is the input for creating a candidate job.
type CandidateRequest struct {
	WorkloadIDs    []string `json:"workload_ids"`
	GraphRevision  int64    `json:"graph_revision"`
	EvidenceWindow string   `json:"evidence_window"`
}

// PolicyCandidateService manages candidate generation jobs.
type PolicyCandidateService struct {
	db        *gorm.DB
	generator *PolicyGenerator
}

// NewPolicyCandidateService creates a new candidate service.
func NewPolicyCandidateService(db *gorm.DB) *PolicyCandidateService {
	return &PolicyCandidateService{
		db:        db,
		generator: NewPolicyGenerator(),
	}
}

// Create starts a new candidate generation job.
func (s *PolicyCandidateService) Create(ctx context.Context, wsID uuid.UUID, req CandidateRequest) (*CandidateJob, error) {
	if len(req.WorkloadIDs) == 0 {
		return nil, fmt.Errorf("%w: workload_ids required", ErrCandidateInput)
	}

	inputBytes, _ := json.Marshal(req)
	inputHash := sha256.Sum256(inputBytes)

	job := &CandidateJob{
		CandidateID:      uuid.New(),
		WorkspaceID:      wsID,
		WorkloadIDs:      req.WorkloadIDs,
		GraphRevision:    req.GraphRevision,
		EvidenceWindow:   req.EvidenceWindow,
		TemplateVersion:  "baseline.v1",
		GeneratorVersion: GeneratorVersion,
		InputDigest:      hex.EncodeToString(inputHash[:]),
		State:            CandidateStatePending,
		CreatedAt:        time.Now(),
	}

	// Persist the initial job row.
	wlJSON, _ := json.Marshal(job.WorkloadIDs)
	if err := s.db.WithContext(ctx).Exec(`INSERT INTO policy_candidate_jobs
		(id, workspace_id, workload_ids, graph_revision, evidence_window, template_version, generator_version, input_digest, state, created_at)
		VALUES (?, ?, CAST(? AS jsonb), ?, ?, ?, ?, ?, ?, ?)`,
		job.CandidateID, wsID, string(wlJSON), job.GraphRevision, job.EvidenceWindow,
		job.TemplateVersion, job.GeneratorVersion, job.InputDigest, job.State, job.CreatedAt,
	).Error; err != nil {
		return nil, err
	}

	// Start generation synchronously (in production, this would be async).
	job.State = CandidateStateGenerating
	result, err := s.generator.Generate(ctx, s.db, wsID, req)
	if err != nil {
		job.State = CandidateStateFailed
		job.Error = err.Error()
		now := time.Now()
		job.CompletedAt = &now
	} else {
		job.State = CandidateStateCompleted
		job.Warnings = result.Warnings
		job.DraftPolicyID = result.DraftPolicyID
		now := time.Now()
		job.CompletedAt = &now
	}

	// Persist the final state.
	warningsJSON, _ := json.Marshal(job.Warnings)
	s.db.WithContext(ctx).Exec(`UPDATE policy_candidate_jobs SET state = ?, warnings = CAST(? AS jsonb), draft_policy_id = ?, error_message = ?, completed_at = ? WHERE id = ?`,
		job.State, string(warningsJSON), job.DraftPolicyID, job.Error, job.CompletedAt, job.CandidateID)

	return job, nil
}

// Get retrieves a candidate job by ID.
func (s *PolicyCandidateService) Get(ctx context.Context, wsID, candidateID uuid.UUID) (*CandidateJob, error) {
	var rows []struct {
		ID               uuid.UUID
		WorkspaceID      uuid.UUID
		WorkloadIDs      string
		GraphRevision    int64
		EvidenceWindow   string
		TemplateVersion  string
		GeneratorVersion string
		InputDigest      string
		State            string
		Warnings         string
		DraftPolicyID    *uuid.UUID
		ErrorMessage     string
		CreatedAt        time.Time
		CompletedAt      *time.Time
	}
	err := s.db.WithContext(ctx).Raw(`SELECT id, workspace_id, workload_ids::text AS workload_ids,
		graph_revision, evidence_window, template_version, generator_version, input_digest,
		state, warnings::text AS warnings, draft_policy_id, error_message, created_at, completed_at
		FROM policy_candidate_jobs WHERE workspace_id = ? AND id = ?`, wsID, candidateID).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrCandidateNotFound
	}
	row := rows[0]
	var wlIDs []string
	_ = json.Unmarshal([]byte(row.WorkloadIDs), &wlIDs)
	var warnings []string
	_ = json.Unmarshal([]byte(row.Warnings), &warnings)
	if warnings == nil {
		warnings = []string{}
	}
	return &CandidateJob{
		CandidateID:      row.ID,
		WorkspaceID:      row.WorkspaceID,
		WorkloadIDs:      wlIDs,
		GraphRevision:    row.GraphRevision,
		EvidenceWindow:   row.EvidenceWindow,
		TemplateVersion:  row.TemplateVersion,
		GeneratorVersion: row.GeneratorVersion,
		InputDigest:      row.InputDigest,
		State:            CandidateState(row.State),
		Warnings:         warnings,
		DraftPolicyID:    row.DraftPolicyID,
		CreatedAt:        row.CreatedAt,
		CompletedAt:      row.CompletedAt,
		Error:            row.ErrorMessage,
	}, nil
}
