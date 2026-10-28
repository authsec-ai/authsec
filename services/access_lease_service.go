package services

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// Sentinel errors the controller maps onto HTTP statuses.
var (
	ErrAccessRequestNotFound = errors.New("access request not found")
	ErrAccessRequestState    = errors.New("access request is not in the required state")
	ErrAccessLeaseNotFound   = errors.New("access lease not found")
	ErrAccessLeaseState      = errors.New("access lease is not in the required state")
	ErrAccessLeaseExhausted  = errors.New("access lease max_uses reached")
	ErrAccessRedeemDuplicate = errors.New("duplicate redeem operation")
	ErrAccessRequestInvalid  = errors.New("access request is invalid")
)

// AccessLeaseService manages governance access requests and the leases they produce.
//
// Storage is in-memory (maps guarded by a sync.Mutex), because the database
// migration is a separate concern. The interface is the same one a DB-backed
// implementation would expose, so swapping the backing store later changes
// nothing above the service layer.
//
// Batch 15 extensions:
//   - Escalation config integration: max TTL, max uses, self-approval rule, MFA requirement.
//   - Atomic redemption with operation_id dedup.
//   - Session adapters: enforce expiry + termination.
//   - Revocation cascade from escalation request invalidation.
type AccessLeaseService struct {
	mu       sync.Mutex
	requests map[string]*models.GovAccessRequest // keyed by request ID
	leases   map[string]*models.AccessLease      // keyed by lease ID
	redeems  map[string]bool                     // operationID dedup set, keyed by "leaseID:operationID"
	sessions map[string]*LeaseSession             // keyed by lease ID → active session

	// Escalation integration (Batch 15).
	escalation *EscalationService
}

// LeaseSession tracks an active adapter session bound to a lease.
// The gateway enforces expiry + termination on session-bearing leases.
type LeaseSession struct {
	SessionID    string    `json:"session_id"`
	LeaseID      string    `json:"lease_id"`
	Principal    string    `json:"principal"`
	Resource     string    `json:"resource"`
	OperationID  string    `json:"operation_id"`
	StartedAt    time.Time `json:"started_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Terminated   bool      `json:"terminated"`
	TerminatedAt *time.Time `json:"terminated_at,omitempty"`
}

// NewAccessLeaseService constructs the service with empty in-memory stores.
func NewAccessLeaseService() *AccessLeaseService {
	return &AccessLeaseService{
		requests: make(map[string]*models.GovAccessRequest),
		leases:   make(map[string]*models.AccessLease),
		redeems:  make(map[string]bool),
		sessions: make(map[string]*LeaseSession),
	}
}

// SetEscalationService attaches the escalation service for policy-configured
// escalation integration. This is optional — when nil, the service operates
// in the pre-Batch-15 mode without escalation config enforcement.
func (s *AccessLeaseService) SetEscalationService(esc *EscalationService) {
	if s != nil {
		s.escalation = esc
	}
}

// CreateAccessRequestInput is what the caller provides to open a request.
type CreateAccessRequestInput struct {
	RequesterID string    `json:"requester_id"`
	SubjectID   string    `json:"subject_id"`
	ResourceID  string    `json:"resource_id"`
	Action      string    `json:"action"`
	Reason      string    `json:"reason"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// CreateAccessRequest opens a new governance access request in the pending state.
func (s *AccessLeaseService) CreateAccessRequest(_ context.Context, workspaceID string, in CreateAccessRequestInput) (*models.GovAccessRequest, error) {
	if in.RequesterID == "" || in.SubjectID == "" || in.ResourceID == "" || in.Action == "" {
		return nil, fmt.Errorf("%w: requester_id, subject_id, resource_id and action are required", ErrAccessRequestInvalid)
	}
	now := time.Now().UTC()
	if in.ExpiresAt.IsZero() {
		in.ExpiresAt = now.Add(24 * time.Hour)
	}
	req := &models.GovAccessRequest{
		ID:          uuid.New().String(),
		WorkspaceID: workspaceID,
		RequesterID: in.RequesterID,
		SubjectID:   in.SubjectID,
		ResourceID:  in.ResourceID,
		Action:      in.Action,
		Reason:      in.Reason,
		State:       models.GovRequestPending,
		ExpiresAt:   in.ExpiresAt,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	s.mu.Lock()
	s.requests[req.ID] = req
	s.mu.Unlock()

	return req, nil
}

// GetAccessRequest returns a single governance access request by ID, scoped to workspace.
func (s *AccessLeaseService) GetAccessRequest(_ context.Context, workspaceID, id string) (*models.GovAccessRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[id]
	if !ok || req.WorkspaceID != workspaceID {
		return nil, ErrAccessRequestNotFound
	}
	return req, nil
}

// ApproveAccessRequestInput extends the basic approval with escalation-aware
// fields for policy-configured leases.
type ApproveAccessRequestInput struct {
	DecidedBy       string `json:"decided_by"`
	Reason          string `json:"reason"`
	EscalationRef   string `json:"escalation_ref,omitempty"`
	MFAVerified     bool   `json:"mfa_verified,omitempty"`
	ChallengeID     string `json:"challenge_id,omitempty"`
	PolicyRevision  string `json:"policy_revision,omitempty"`
	OperationScope  string `json:"operation_scope,omitempty"`
}

// ApproveAccessRequest transitions a pending request to approved and creates a lease.
func (s *AccessLeaseService) ApproveAccessRequest(_ context.Context, workspaceID, id, decidedBy, reason string) (*models.AccessLease, error) {
	return s.ApproveAccessRequestWithConfig(context.Background(), workspaceID, id, ApproveAccessRequestInput{
		DecidedBy: decidedBy,
		Reason:    reason,
	})
}

// ApproveAccessRequestWithConfig transitions a pending request to approved
// and creates a lease, integrating escalation config when available.
// It enforces: max TTL, max uses, self-approval rule, and MFA requirement
// from the policy escalation configuration.
func (s *AccessLeaseService) ApproveAccessRequestWithConfig(_ context.Context, workspaceID, id string, in ApproveAccessRequestInput) (*models.AccessLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[id]
	if !ok || req.WorkspaceID != workspaceID {
		return nil, ErrAccessRequestNotFound
	}
	if req.State != models.GovRequestPending {
		return nil, fmt.Errorf("%w: expected pending, got %s", ErrAccessRequestState, req.State)
	}

	now := time.Now().UTC()

	// Default lease parameters.
	maxUses := 0  // 0 means unlimited
	expiresAt := req.ExpiresAt
	policyRevision := in.PolicyRevision

	// Apply escalation config constraints if an escalation reference is given
	// and the escalation service is wired.
	if in.EscalationRef != "" && s.escalation != nil {
		cfg, err := s.escalation.ResolveConfig(context.Background(), workspaceID, in.EscalationRef)
		if err != nil {
			return nil, err
		}

		// Enforce self-approval rule.
		if in.DecidedBy == req.RequesterID {
			switch cfg.SelfApproval {
			case "deny", "":
				return nil, ErrEscalationSelfApproval
			case "require_mfa":
				if !in.MFAVerified {
					return nil, ErrEscalationMFARequired
				}
			}
		}

		// Enforce MFA requirement.
		if cfg.MFAProvider != "" && !in.MFAVerified {
			return nil, ErrEscalationMFARequired
		}

		// Apply max TTL from escalation config.
		if cfg.MaxTTLSeconds > 0 {
			maxTTL := time.Duration(cfg.MaxTTLSeconds) * time.Second
			configuredExpiry := now.Add(maxTTL)
			if configuredExpiry.Before(expiresAt) {
				expiresAt = configuredExpiry
			}
		}

		// Apply max uses from escalation config.
		if cfg.MaxUses > 0 {
			maxUses = cfg.MaxUses
		}
	}

	req.State = models.GovRequestApproved
	req.DecidedBy = in.DecidedBy
	req.DecidedAt = &now
	req.DecisionReason = in.Reason
	req.UpdatedAt = now

	lease := &models.AccessLease{
		ID:             uuid.New().String(),
		WorkspaceID:    workspaceID,
		RequestID:      req.ID,
		SubjectID:      req.SubjectID,
		ResourceID:     req.ResourceID,
		Action:         req.Action,
		State:          models.LeaseStateActive,
		NotBefore:      now,
		ExpiresAt:      expiresAt,
		MaxUses:        maxUses,
		UseCount:       0,
		ApprovalIDs:    []string{in.DecidedBy},
		PolicyRevision: policyRevision,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	s.leases[lease.ID] = lease
	req.LeaseID = lease.ID

	return lease, nil
}

// DenyAccessRequest transitions a pending request to denied.
func (s *AccessLeaseService) DenyAccessRequest(_ context.Context, workspaceID, id, decidedBy, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[id]
	if !ok || req.WorkspaceID != workspaceID {
		return ErrAccessRequestNotFound
	}
	if req.State != models.GovRequestPending {
		return fmt.Errorf("%w: expected pending, got %s", ErrAccessRequestState, req.State)
	}

	now := time.Now().UTC()
	req.State = models.GovRequestDenied
	req.DecidedBy = decidedBy
	req.DecidedAt = &now
	req.DecisionReason = reason
	req.UpdatedAt = now
	return nil
}

// CancelAccessRequest transitions a pending request to cancelled.
func (s *AccessLeaseService) CancelAccessRequest(_ context.Context, workspaceID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[id]
	if !ok || req.WorkspaceID != workspaceID {
		return ErrAccessRequestNotFound
	}
	if req.State != models.GovRequestPending {
		return fmt.Errorf("%w: expected pending, got %s", ErrAccessRequestState, req.State)
	}

	now := time.Now().UTC()
	req.State = models.GovRequestCancelled
	req.UpdatedAt = now
	return nil
}

// GetLease returns a single lease by ID, scoped to workspace.
func (s *AccessLeaseService) GetLease(_ context.Context, workspaceID, id string) (*models.AccessLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	lease, ok := s.leases[id]
	if !ok || lease.WorkspaceID != workspaceID {
		return nil, ErrAccessLeaseNotFound
	}
	return lease, nil
}

// RedeemLease atomically increments use_count with deduplication by operationID.
// If max_uses > 0 and use_count reaches max_uses, the lease transitions to consumed.
// Batch 15: Also checks expiry window before redemption.
func (s *AccessLeaseService) RedeemLease(_ context.Context, workspaceID, id, operationID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	lease, ok := s.leases[id]
	if !ok || lease.WorkspaceID != workspaceID {
		return ErrAccessLeaseNotFound
	}
	if lease.State != models.LeaseStateActive {
		return fmt.Errorf("%w: expected active, got %s", ErrAccessLeaseState, lease.State)
	}

	now := time.Now().UTC()

	// Check not_before and expiry window.
	if now.Before(lease.NotBefore) {
		return fmt.Errorf("%w: lease is not yet valid", ErrAccessLeaseState)
	}
	if !now.Before(lease.ExpiresAt) {
		lease.State = models.LeaseStateExpired
		lease.UpdatedAt = now
		return fmt.Errorf("%w: lease has expired", ErrAccessLeaseState)
	}

	// Atomic dedup: the same operationID for the same lease is a no-op.
	dedupKey := lease.ID + ":" + operationID
	if s.redeems[dedupKey] {
		return ErrAccessRedeemDuplicate
	}

	if lease.MaxUses > 0 && lease.UseCount >= lease.MaxUses {
		return ErrAccessLeaseExhausted
	}

	lease.UseCount++
	lease.UpdatedAt = now
	s.redeems[dedupKey] = true

	if lease.MaxUses > 0 && lease.UseCount >= lease.MaxUses {
		lease.State = models.LeaseStateConsumed
	}
	return nil
}

// RevokeLease transitions an active or issued lease to revoked and
// terminates any associated session.
func (s *AccessLeaseService) RevokeLease(_ context.Context, workspaceID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	lease, ok := s.leases[id]
	if !ok || lease.WorkspaceID != workspaceID {
		return ErrAccessLeaseNotFound
	}
	if lease.State != models.LeaseStateActive && lease.State != models.LeaseStateIssued {
		return fmt.Errorf("%w: expected active or issued, got %s", ErrAccessLeaseState, lease.State)
	}

	now := time.Now().UTC()
	lease.State = models.LeaseStateRevoked
	lease.UpdatedAt = now

	// Terminate any active session bound to this lease.
	if sess, ok := s.sessions[id]; ok && !sess.Terminated {
		sess.Terminated = true
		sess.TerminatedAt = &now
	}

	return nil
}

// --- Batch 15: Session adapter integration ---

// OpenSession creates a session bound to a lease for adapter-mediated access.
// The session enforces the lease expiry and supports termination.
func (s *AccessLeaseService) OpenSession(_ context.Context, workspaceID, leaseID, principal, resource, operationID string) (*LeaseSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	lease, ok := s.leases[leaseID]
	if !ok || lease.WorkspaceID != workspaceID {
		return nil, ErrAccessLeaseNotFound
	}
	if lease.State != models.LeaseStateActive {
		return nil, fmt.Errorf("%w: expected active, got %s", ErrAccessLeaseState, lease.State)
	}

	now := time.Now().UTC()
	sess := &LeaseSession{
		SessionID:   uuid.New().String(),
		LeaseID:     leaseID,
		Principal:   principal,
		Resource:    resource,
		OperationID: operationID,
		StartedAt:   now,
		ExpiresAt:   lease.ExpiresAt,
		Terminated:  false,
	}
	s.sessions[leaseID] = sess

	return sess, nil
}

// TerminateSession terminates an active session bound to a lease.
func (s *AccessLeaseService) TerminateSession(_ context.Context, workspaceID, leaseID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	lease, ok := s.leases[leaseID]
	if !ok || lease.WorkspaceID != workspaceID {
		return ErrAccessLeaseNotFound
	}
	_ = lease // confirm workspace scoping

	sess, ok := s.sessions[leaseID]
	if !ok {
		return fmt.Errorf("no active session for lease %s", leaseID)
	}
	if sess.Terminated {
		return fmt.Errorf("session already terminated")
	}

	now := time.Now().UTC()
	sess.Terminated = true
	sess.TerminatedAt = &now

	return nil
}

// GetSession returns the session bound to a lease, if any.
func (s *AccessLeaseService) GetSession(_ context.Context, workspaceID, leaseID string) (*LeaseSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	lease, ok := s.leases[leaseID]
	if !ok || lease.WorkspaceID != workspaceID {
		return nil, ErrAccessLeaseNotFound
	}
	_ = lease

	sess, ok := s.sessions[leaseID]
	if !ok {
		return nil, fmt.Errorf("no session for lease %s", leaseID)
	}
	return sess, nil
}

// RevokeCascade revokes all active leases tied to a specific access request.
// This is used when an escalation request is invalidated (e.g. policy revision
// change) to cascade the revocation to all downstream leases and sessions.
func (s *AccessLeaseService) RevokeCascade(_ context.Context, workspaceID, requestID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	count := 0
	for _, lease := range s.leases {
		if lease.WorkspaceID != workspaceID || lease.RequestID != requestID {
			continue
		}
		if lease.State != models.LeaseStateActive && lease.State != models.LeaseStateIssued {
			continue
		}

		lease.State = models.LeaseStateRevoked
		lease.UpdatedAt = now
		count++

		// Terminate any active session.
		if sess, ok := s.sessions[lease.ID]; ok && !sess.Terminated {
			sess.Terminated = true
			sess.TerminatedAt = &now
		}
	}

	return count, nil
}

// ExpireLeases transitions active leases past their ExpiresAt to expired
// and terminates their sessions. Call periodically from a background goroutine.
func (s *AccessLeaseService) ExpireLeases(_ context.Context) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	count := 0
	for _, lease := range s.leases {
		if lease.State == models.LeaseStateActive || lease.State == models.LeaseStateIssued {
			if !now.Before(lease.ExpiresAt) {
				lease.State = models.LeaseStateExpired
				lease.UpdatedAt = now
				count++

				// Terminate session on expiry.
				if sess, ok := s.sessions[lease.ID]; ok && !sess.Terminated {
					sess.Terminated = true
					sess.TerminatedAt = &now
				}
			}
		}
	}
	return count
}
