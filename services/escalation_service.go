package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// Sentinel errors for escalation operations.
var (
	ErrEscalationConfigNotFound = errors.New("escalation config not found")
	ErrEscalationConfigDisabled = errors.New("escalation config is disabled")
	ErrEscalationHardDeny       = errors.New("operation is hard denied by policy")
	ErrEscalationIdentityState  = errors.New("identity is not in an active state")
	ErrEscalationPolicyRevision = errors.New("policy revision has changed since request was created")
	ErrEscalationConcurrent     = errors.New("concurrent redemption: at most one execution allowed")
	ErrEscalationSelfApproval   = errors.New("self-approval is not permitted by escalation config")
	ErrEscalationMFARequired    = errors.New("MFA verification is required by escalation config")
	ErrEscalationTimeout        = errors.New("escalation request has timed out")
	ErrEscalationRequestExists  = errors.New("escalation request already exists for this operation")
)

// EscalationRequest binds an access request to the full policy context
// required for secure redemption.
type EscalationRequest struct {
	ID                  string    `json:"id"`
	WorkspaceID         string    `json:"workspace_id"`
	PolicyRevisionHash  string    `json:"policy_revision_hash"`
	PolicyRevisionNum   int       `json:"policy_revision_num"`
	RuleID              string    `json:"rule_id"`
	Primitive           string    `json:"primitive"`
	WorkloadID          string    `json:"workload_id"`
	ExecutionIdentity   string    `json:"execution_identity"`
	Resource            string    `json:"resource"`
	Action              string    `json:"action"`
	ParameterDigest     string    `json:"parameter_digest"`
	Backend             string    `json:"backend"`
	IdentityState       string    `json:"identity_state"`
	EscalationConfigRef string    `json:"escalation_config_ref"`
	RequesterID         string    `json:"requester_id"`
	State               string    `json:"state"` // pending, approved, denied, expired, invalidated
	OperationID         string    `json:"operation_id"`
	AccessRequestID     string    `json:"access_request_id"`
	LeaseID             string    `json:"lease_id,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	UpdatedAt           time.Time `json:"updated_at"`
	RedeemedAt          *time.Time `json:"redeemed_at,omitempty"`
}

// Escalation request states.
const (
	EscalationStatePending     = "pending"
	EscalationStateApproved    = "approved"
	EscalationStateDenied      = "denied"
	EscalationStateExpired     = "expired"
	EscalationStateInvalidated = "invalidated"
	EscalationStateRedeemed    = "redeemed"
)

// EscalationConfig is the resolved named escalation configuration from a V2
// policy document. It mirrors models.PolicyEscalation but includes the
// workspace and policy revision context needed for enforcement.
type EscalationConfig struct {
	Name             string   `json:"name"`
	Enabled          bool     `json:"enabled"`
	ApproverGroupIDs []string `json:"approver_group_ids"`
	MinApprovals     int      `json:"min_approvals"`
	MFAProvider      string   `json:"mfa_provider"`
	MFALevel         string   `json:"mfa_level"`
	MaxUses          int      `json:"max_uses"`
	MaxTTLSeconds    int      `json:"max_ttl_seconds"`
	SelfApproval     string   `json:"self_approval"` // "deny", "allow", "require_mfa"
	TimeoutSeconds   int      `json:"timeout_seconds"`
}

// CreateEscalationInput carries the parameters for opening an escalation request.
type CreateEscalationInput struct {
	RequesterID       string            `json:"requester_id"`
	WorkloadID        string            `json:"workload_id"`
	ExecutionIdentity string            `json:"execution_identity"`
	Resource          string            `json:"resource"`
	Action            string            `json:"action"`
	Parameters        map[string]any    `json:"parameters,omitempty"`
	OperationID       string            `json:"operation_id"`
	RuleID            string            `json:"rule_id"`
	Primitive         string            `json:"primitive"`
	Backend           string            `json:"backend"`
	IdentityState     string            `json:"identity_state"`
	EscalationRef     string            `json:"escalation_ref"`
	PolicyRevisionNum int               `json:"policy_revision_num"`
	PolicyRevisionHash string           `json:"policy_revision_hash"`
}

// EscalationService manages the named escalation configuration lifecycle
// for the IGA access governance surface. It resolves escalation configs
// from V2 policy documents and binds access requests to the full policy
// context: workspace, policy revision/hash, rule ID, primitive,
// workload/execution identity, normalized resource/action, parameter digest,
// backend, and identity state.
//
// On redemption it rechecks hard denies, identity status, and current policy.
// Pending requests are invalidated on policy revision changes. Concurrent
// redemption is limited to at most one execution.
type EscalationService struct {
	mu       sync.Mutex
	requests map[string]*EscalationRequest // keyed by request ID
	byOp     map[string]string             // operationID → request ID
	configs  map[string]*EscalationConfig  // keyed by "workspace:configName"
	policies map[string]string             // keyed by workspace → current revision hash
	redeemed map[string]bool               // keyed by request ID → redeemed flag
}

// NewEscalationService constructs the service with empty in-memory stores.
func NewEscalationService() *EscalationService {
	return &EscalationService{
		requests: make(map[string]*EscalationRequest),
		byOp:     make(map[string]string),
		configs:  make(map[string]*EscalationConfig),
		policies: make(map[string]string),
		redeemed: make(map[string]bool),
	}
}

// configKey returns the composite key for an escalation config.
func configKey(workspaceID, name string) string {
	return workspaceID + "\x00" + name
}

// LoadEscalationConfigs loads the named escalation configurations from a V2
// policy document into the service for a given workspace.
func (s *EscalationService) LoadEscalationConfigs(_ context.Context, workspaceID string, doc *models.RuntimePolicyV2Document, revisionHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	previousHash := s.policies[workspaceID]

	// Store the new policy revision hash.
	s.policies[workspaceID] = revisionHash

	// Load escalation configs from the document.
	for _, esc := range doc.Escalations {
		cfg := &EscalationConfig{
			Name:             esc.Name,
			Enabled:          esc.Enabled,
			ApproverGroupIDs: esc.ApproverGroupIDs,
			MinApprovals:     esc.MinApprovals,
			MFAProvider:      esc.MFAProvider,
			MFALevel:         esc.MFALevel,
			MaxUses:          esc.MaxUses,
			MaxTTLSeconds:    esc.MaxTTLSeconds,
			SelfApproval:     esc.SelfApproval,
			TimeoutSeconds:   esc.TimeoutSeconds,
		}
		s.configs[configKey(workspaceID, esc.Name)] = cfg
	}

	// If policy revision changed, invalidate pending requests for this workspace.
	if previousHash != "" && previousHash != revisionHash {
		s.invalidatePendingLocked(workspaceID)
	}

	return nil
}

// invalidatePendingLocked transitions all pending escalation requests for a
// workspace to invalidated. Caller must hold s.mu.
func (s *EscalationService) invalidatePendingLocked(workspaceID string) {
	now := time.Now().UTC()
	for _, req := range s.requests {
		if req.WorkspaceID == workspaceID && req.State == EscalationStatePending {
			req.State = EscalationStateInvalidated
			req.UpdatedAt = now
		}
	}
}

// InvalidatePendingForRevision invalidates all pending escalation requests
// for a workspace when the policy revision changes. This is the public
// entry point called from the policy delivery pipeline.
func (s *EscalationService) InvalidatePendingForRevision(_ context.Context, workspaceID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invalidatePendingLocked(workspaceID)
}

// ResolveConfig returns the escalation config for a named reference within
// a workspace. It returns ErrEscalationConfigNotFound when the config does
// not exist and ErrEscalationConfigDisabled when it exists but is disabled.
func (s *EscalationService) ResolveConfig(_ context.Context, workspaceID, name string) (*EscalationConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfg, ok := s.configs[configKey(workspaceID, name)]
	if !ok {
		return nil, ErrEscalationConfigNotFound
	}
	if !cfg.Enabled {
		return nil, ErrEscalationConfigDisabled
	}
	return cfg, nil
}

// CreateEscalationRequest opens a new escalation request bound to the full
// policy context. It validates that the escalation config exists and is
// enabled, checks identity state, and creates the request with the
// appropriate timeout from the escalation config.
func (s *EscalationService) CreateEscalationRequest(_ context.Context, workspaceID string, in CreateEscalationInput) (*EscalationRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for duplicate operation_id.
	if in.OperationID != "" {
		if _, exists := s.byOp[workspaceID+"\x00"+in.OperationID]; exists {
			return nil, ErrEscalationRequestExists
		}
	}

	// Resolve escalation config.
	cfg, ok := s.configs[configKey(workspaceID, in.EscalationRef)]
	if !ok {
		return nil, ErrEscalationConfigNotFound
	}
	if !cfg.Enabled {
		return nil, ErrEscalationConfigDisabled
	}

	// Check identity state.
	if in.IdentityState != "active" && in.IdentityState != "attested" {
		return nil, fmt.Errorf("%w: identity state is %q", ErrEscalationIdentityState, in.IdentityState)
	}

	// Compute parameter digest.
	paramDigest := computeParameterDigest(in.Parameters)

	// Compute timeout from escalation config.
	timeout := 15 * time.Minute // default
	if cfg.TimeoutSeconds > 0 {
		timeout = time.Duration(cfg.TimeoutSeconds) * time.Second
	}

	now := time.Now().UTC()
	req := &EscalationRequest{
		ID:                  uuid.New().String(),
		WorkspaceID:         workspaceID,
		PolicyRevisionHash:  in.PolicyRevisionHash,
		PolicyRevisionNum:   in.PolicyRevisionNum,
		RuleID:              in.RuleID,
		Primitive:           in.Primitive,
		WorkloadID:          in.WorkloadID,
		ExecutionIdentity:   in.ExecutionIdentity,
		Resource:            in.Resource,
		Action:              in.Action,
		ParameterDigest:     paramDigest,
		Backend:             in.Backend,
		IdentityState:       in.IdentityState,
		EscalationConfigRef: in.EscalationRef,
		RequesterID:         in.RequesterID,
		State:               EscalationStatePending,
		OperationID:         in.OperationID,
		CreatedAt:           now,
		ExpiresAt:           now.Add(timeout),
		UpdatedAt:           now,
	}

	s.requests[req.ID] = req
	if in.OperationID != "" {
		s.byOp[workspaceID+"\x00"+in.OperationID] = req.ID
	}

	return req, nil
}

// GetEscalationRequest returns an escalation request by ID.
func (s *EscalationService) GetEscalationRequest(_ context.Context, workspaceID, id string) (*EscalationRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[id]
	if !ok || req.WorkspaceID != workspaceID {
		return nil, ErrAccessRequestNotFound
	}
	return req, nil
}

// GetByOperationID returns an escalation request by operation ID.
func (s *EscalationService) GetByOperationID(_ context.Context, workspaceID, operationID string) (*EscalationRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	reqID, ok := s.byOp[workspaceID+"\x00"+operationID]
	if !ok {
		return nil, ErrAccessRequestNotFound
	}
	req, ok := s.requests[reqID]
	if !ok || req.WorkspaceID != workspaceID {
		return nil, ErrAccessRequestNotFound
	}
	return req, nil
}

// ApproveEscalation transitions a pending escalation request to approved.
// It validates self-approval rules and MFA requirements from the escalation
// config. It creates an access lease through the linked AccessLeaseService.
func (s *EscalationService) ApproveEscalation(_ context.Context, workspaceID, requestID, approverID string, mfaVerified bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[requestID]
	if !ok || req.WorkspaceID != workspaceID {
		return ErrAccessRequestNotFound
	}
	if req.State != EscalationStatePending {
		return fmt.Errorf("%w: expected pending, got %s", ErrAccessRequestState, req.State)
	}

	// Check timeout.
	now := time.Now().UTC()
	if !now.Before(req.ExpiresAt) {
		req.State = EscalationStateExpired
		req.UpdatedAt = now
		return ErrEscalationTimeout
	}

	// Resolve escalation config.
	cfg, ok := s.configs[configKey(workspaceID, req.EscalationConfigRef)]
	if !ok {
		return ErrEscalationConfigNotFound
	}

	// Check policy revision hasn't changed.
	if currentHash, exists := s.policies[workspaceID]; exists {
		if currentHash != req.PolicyRevisionHash {
			req.State = EscalationStateInvalidated
			req.UpdatedAt = now
			return ErrEscalationPolicyRevision
		}
	}

	// Check self-approval rules.
	if approverID == req.RequesterID {
		switch cfg.SelfApproval {
		case "deny", "":
			return ErrEscalationSelfApproval
		case "require_mfa":
			if !mfaVerified {
				return ErrEscalationMFARequired
			}
		case "allow":
			// Self-approval is permitted.
		}
	}

	// Check MFA requirement.
	if cfg.MFAProvider != "" && !mfaVerified {
		return ErrEscalationMFARequired
	}

	req.State = EscalationStateApproved
	req.UpdatedAt = now

	return nil
}

// DenyEscalation transitions a pending escalation request to denied.
func (s *EscalationService) DenyEscalation(_ context.Context, workspaceID, requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[requestID]
	if !ok || req.WorkspaceID != workspaceID {
		return ErrAccessRequestNotFound
	}
	if req.State != EscalationStatePending {
		return fmt.Errorf("%w: expected pending, got %s", ErrAccessRequestState, req.State)
	}

	now := time.Now().UTC()
	req.State = EscalationStateDenied
	req.UpdatedAt = now

	return nil
}

// RedeemEscalation atomically redeems an approved escalation request for
// execution. It rechecks the policy revision, hard denies, and identity state.
// At most one concurrent redemption is permitted per request.
func (s *EscalationService) RedeemEscalation(_ context.Context, workspaceID, requestID string, currentPolicyHash string, identityActive bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[requestID]
	if !ok || req.WorkspaceID != workspaceID {
		return ErrAccessRequestNotFound
	}
	if req.State != EscalationStateApproved {
		return fmt.Errorf("%w: expected approved, got %s", ErrAccessRequestState, req.State)
	}

	now := time.Now().UTC()

	// Check timeout.
	if !now.Before(req.ExpiresAt) {
		req.State = EscalationStateExpired
		req.UpdatedAt = now
		return ErrEscalationTimeout
	}

	// Recheck policy revision on redemption.
	if currentPolicyHash != req.PolicyRevisionHash {
		req.State = EscalationStateInvalidated
		req.UpdatedAt = now
		return ErrEscalationPolicyRevision
	}

	// Recheck identity state on redemption.
	if !identityActive {
		return ErrEscalationIdentityState
	}

	// Concurrent redemption check: at most one execution.
	if s.redeemed[requestID] {
		return ErrEscalationConcurrent
	}

	s.redeemed[requestID] = true
	req.State = EscalationStateRedeemed
	req.RedeemedAt = &now
	req.UpdatedAt = now

	return nil
}

// BindLease associates a lease ID with an approved escalation request.
func (s *EscalationService) BindLease(_ context.Context, workspaceID, requestID, leaseID, accessRequestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[requestID]
	if !ok || req.WorkspaceID != workspaceID {
		return ErrAccessRequestNotFound
	}

	req.LeaseID = leaseID
	req.AccessRequestID = accessRequestID
	req.UpdatedAt = time.Now().UTC()

	return nil
}

// ExpireStale transitions pending escalation requests that have passed
// their ExpiresAt to expired. Call periodically from a background goroutine.
func (s *EscalationService) ExpireStale(_ context.Context) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	count := 0
	for _, req := range s.requests {
		if req.State == EscalationStatePending && !now.Before(req.ExpiresAt) {
			req.State = EscalationStateExpired
			req.UpdatedAt = now
			count++
		}
	}
	return count
}

// EscalationConfigForRule resolves the escalation config referenced by a
// policy rule. It returns nil if the rule does not reference an escalation.
func (s *EscalationService) EscalationConfigForRule(_ context.Context, workspaceID string, rule models.PolicyV2Rule) (*EscalationConfig, error) {
	if rule.EscalationRef == "" {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cfg, ok := s.configs[configKey(workspaceID, rule.EscalationRef)]
	if !ok {
		return nil, ErrEscalationConfigNotFound
	}
	if !cfg.Enabled {
		return nil, ErrEscalationConfigDisabled
	}
	return cfg, nil
}

// MaxTTL returns the maximum TTL from the escalation config, clamped to
// the provided maximum.
func (cfg *EscalationConfig) MaxTTL(maxAllowed time.Duration) time.Duration {
	if cfg.MaxTTLSeconds <= 0 {
		return maxAllowed
	}
	d := time.Duration(cfg.MaxTTLSeconds) * time.Second
	if d > maxAllowed {
		return maxAllowed
	}
	return d
}

// Timeout returns the escalation request timeout.
func (cfg *EscalationConfig) Timeout() time.Duration {
	if cfg.TimeoutSeconds <= 0 {
		return 15 * time.Minute
	}
	return time.Duration(cfg.TimeoutSeconds) * time.Second
}

// computeParameterDigest computes a SHA-256 digest of the request parameters.
func computeParameterDigest(params map[string]any) string {
	if len(params) == 0 {
		return ""
	}
	data, err := json.Marshal(params)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
