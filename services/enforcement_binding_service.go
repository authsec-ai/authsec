package services

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

var (
	ErrBindingNotFound      = errors.New("enforcement binding not found")
	ErrBindingConflict      = errors.New("enforcement binding conflict")
	ErrBindingTransition    = errors.New("invalid binding state transition")
)

// EnforcementBindingService manages enforcement bindings for discovered agents.
type EnforcementBindingService struct {
	db *gorm.DB
}

// NewEnforcementBindingService creates a new enforcement binding service.
func NewEnforcementBindingService(db *gorm.DB) *EnforcementBindingService {
	return &EnforcementBindingService{db: db}
}

// Get retrieves the current enforcement binding for an agent.
func (s *EnforcementBindingService) Get(ctx context.Context, workspaceID, agentID uuid.UUID) (*models.EnforcementBinding, error) {
	var binding models.EnforcementBinding
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND agent_id = ? AND state != ?", workspaceID, agentID, models.BindingStateSuperseded).
		Order("created_at DESC").
		First(&binding).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrBindingNotFound
		}
		return nil, err
	}
	return &binding, nil
}

// PutDraft creates or replaces the draft enforcement binding for an agent.
// Requires If-Match with the current binding revision for updates.
func (s *EnforcementBindingService) PutDraft(ctx context.Context, workspaceID, agentID uuid.UUID, ifMatch string, req PutBindingRequest) (*models.EnforcementBinding, error) {
	// Validate backend and identity mode.
	if !isValidBackend(req.Backend) {
		return nil, &StatusError{Status: http.StatusBadRequest, Code: "invalid_backend", Message: "backend must be authsec or openshell"}
	}
	if !isValidIdentityMode(req.IdentityMode) {
		return nil, &StatusError{Status: http.StatusBadRequest, Code: "invalid_identity_mode", Message: "identity_mode must be spiffe or enrolled_mtls"}
	}

	var binding *models.EnforcementBinding
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Check for existing binding.
		var existing models.EnforcementBinding
		err := tx.Where("workspace_id = ? AND agent_id = ? AND state != ?", workspaceID, agentID, models.BindingStateSuperseded).
			Order("created_at DESC").First(&existing).Error

		if err == nil {
			// Existing binding found — verify If-Match.
			expectedEtag := fmt.Sprintf("%d", existing.BindingRevision)
			if ifMatch != "" && ifMatch != expectedEtag {
				return &StatusError{Status: http.StatusPreconditionFailed, Code: "precondition_failed", Message: "If-Match does not match current binding revision"}
			}

			// Transition to draft if needed.
			if existing.State != models.BindingStateDraft {
				if !models.EnforcementBindingTransitionAllowed(existing.State, models.BindingStateDraft) {
					return &StatusError{Status: http.StatusConflict, Code: "invalid_transition", Message: "cannot draft from state " + existing.State}
				}
			}

			// Update existing binding.
			existing.Backend = req.Backend
			existing.BackendProfile = req.BackendProfile
			existing.IdentityMode = req.IdentityMode
			existing.PolicyRefs = req.PolicyRefs
			existing.TargetExecutionSelector = req.TargetExecutionSelector
			existing.State = models.BindingStateDraft
			existing.BindingRevision++

			if err := tx.Save(&existing).Error; err != nil {
				return err
			}
			binding = &existing
		} else if errors.Is(err, gorm.ErrRecordNotFound) {
			// No binding exists — create new draft.
			b := models.EnforcementBinding{
				ID:                      uuid.New(),
				WorkspaceID:             workspaceID,
				AgentID:                 agentID,
				BindingRevision:         1,
				Backend:                 req.Backend,
				BackendProfile:          req.BackendProfile,
				IdentityMode:            req.IdentityMode,
				PolicyRefs:              req.PolicyRefs,
				TargetExecutionSelector: req.TargetExecutionSelector,
				State:                   models.BindingStateDraft,
			}
			if err := tx.Create(&b).Error; err != nil {
				return err
			}
			binding = &b
		} else {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return binding, nil
}

// Resolve determines the effective enforcement binding for an agent following
// the resolution order: approved agent binding → policy default → workspace default.
func (s *EnforcementBindingService) Resolve(ctx context.Context, workspaceID, agentID uuid.UUID) (*models.BindingResolution, error) {
	// 1. Check for approved/active agent-specific binding.
	var agentBinding models.EnforcementBinding
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND agent_id = ? AND state IN ?", workspaceID, agentID, []string{models.BindingStateApproved, models.BindingStateActive}).
		Order("created_at DESC").
		First(&agentBinding).Error

	if err == nil {
		return &models.BindingResolution{
			Source:         "agent_binding",
			BindingID:      &agentBinding.ID,
			Backend:        agentBinding.Backend,
			BackendProfile: agentBinding.BackendProfile,
			IdentityMode:   agentBinding.IdentityMode,
		}, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	// 2. Check policy defaults (look at contributing policies for this agent's workload).
	var policyDefaults []struct {
		Backend string
		Profile string
	}
	err = s.db.WithContext(ctx).Raw(`
		SELECT DISTINCT
			(rev.document->>'enforcement'->>'backend') AS backend,
			(rev.document->>'enforcement'->>'profile') AS profile
		FROM runtime_policies rp
		JOIN runtime_policy_revisions rev ON rev.policy_id = rp.id
			AND rev.workspace_id = rp.workspace_id
			AND rev.revision = rp.current_draft_revision
		WHERE rp.workspace_id = ?
			AND rev.compiler_format = ?
			AND rev.state IN ('approved', 'published')
	`, workspaceID, models.RuntimePolicyFormatV2).Scan(&policyDefaults).Error

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	if len(policyDefaults) == 1 && policyDefaults[0].Backend != "" {
		return &models.BindingResolution{
			Source:         "policy_default",
			Backend:        policyDefaults[0].Backend,
			BackendProfile: policyDefaults[0].Profile,
			IdentityMode:   models.IdentityModeSPIFFE, // default
		}, nil
	}

	// 3. Workspace default.
	return &models.BindingResolution{
		Source:         "workspace_default",
		Backend:        models.EnforcementBackendAuthSec,
		BackendProfile: "linux-managed-v1",
		IdentityMode:   models.IdentityModeSPIFFE,
	}, nil
}

// Transition moves a binding through the state machine.
func (s *EnforcementBindingService) Transition(ctx context.Context, workspaceID, bindingID uuid.UUID, targetState string) (*models.EnforcementBinding, error) {
	var binding models.EnforcementBinding
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("workspace_id = ? AND id = ?", workspaceID, bindingID).First(&binding).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrBindingNotFound
			}
			return err
		}
		if !models.EnforcementBindingTransitionAllowed(binding.State, targetState) {
			return &StatusError{
				Status:  http.StatusConflict,
				Code:    "invalid_transition",
				Message: fmt.Sprintf("cannot transition from %s to %s", binding.State, targetState),
			}
		}
		binding.State = targetState
		return tx.Save(&binding).Error
	})
	if err != nil {
		return nil, err
	}
	return &binding, nil
}

// PutBindingRequest is the request body for creating/updating a binding draft.
type PutBindingRequest struct {
	Backend                 string   `json:"backend"`
	BackendProfile          string   `json:"backend_profile"`
	IdentityMode            string   `json:"identity_mode"`
	PolicyRefs              []string `json:"policy_refs"`
	TargetExecutionSelector string   `json:"target_execution_selector,omitempty"`
}

func isValidBackend(b string) bool {
	for _, v := range models.ValidEnforcementBackends() {
		if v == b {
			return true
		}
	}
	return false
}

func isValidIdentityMode(m string) bool {
	for _, v := range models.ValidIdentityModes() {
		if v == m {
			return true
		}
	}
	return false
}
