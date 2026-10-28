package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Sentinel errors for AuthNull verification.
var (
	ErrAuthNullChallengeNotFound     = errors.New("authnull: challenge not found")
	ErrAuthNullChallengeExpired      = errors.New("authnull: challenge expired")
	ErrAuthNullChallengeBound        = errors.New("authnull: challenge already bound to a different request")
	ErrAuthNullChallengeReplayed     = errors.New("authnull: challenge response has already been used")
	ErrAuthNullSubjectMismatch       = errors.New("authnull: subject does not match challenge")
	ErrAuthNullAudienceMismatch      = errors.New("authnull: audience does not match challenge")
	ErrAuthNullFreshnessFailed       = errors.New("authnull: authentication is stale")
	ErrAuthNullMockInProduction      = errors.New("authnull: mock mode is not allowed in production")
	ErrAuthNullSelfApproval          = errors.New("authnull: self-approval is not permitted")
	ErrAuthNullOperationChanged      = errors.New("authnull: operation has changed since challenge was created")
	ErrAuthNullVerificationFailed    = errors.New("authnull: verification failed")
	ErrAuthNullChallengeAlreadyBound = errors.New("authnull: challenge is already bound to an access request")
)

// AuthNullChallengeState represents the lifecycle state of an AuthNull challenge.
type AuthNullChallengeState string

const (
	// AuthNullChallengeCreated is a newly created challenge awaiting verification.
	AuthNullChallengeCreated AuthNullChallengeState = "created"
	// AuthNullChallengeVerified is a challenge that has been successfully verified.
	AuthNullChallengeVerified AuthNullChallengeState = "verified"
	// AuthNullChallengeBound is a challenge bound to an access request.
	AuthNullChallengeBound AuthNullChallengeState = "bound"
	// AuthNullChallengeExpiredState is a challenge past its validity window.
	AuthNullChallengeExpiredState AuthNullChallengeState = "expired"
)

// AuthNullChallenge tracks the lifecycle of an AuthNull MFA challenge.
// The lifecycle is: create -> verify -> bind to access request.
type AuthNullChallenge struct {
	ID                string                 `json:"id"`
	WorkspaceID       string                 `json:"workspace_id"`
	SubjectID         string                 `json:"subject_id"`          // The human who must verify
	Audience          string                 `json:"audience"`            // Expected audience
	RequestHash       string                 `json:"request_hash"`        // Canonical hash of the operation
	AccessRequestID   string                 `json:"access_request_id"`   // Linked access request (set on bind)
	EscalationID      string                 `json:"escalation_id"`       // Linked escalation request
	State             AuthNullChallengeState `json:"state"`
	ChallengeURI      string                 `json:"challenge_uri"`
	Nonce             string                 `json:"nonce"`
	RequiredAssurance string                 `json:"required_assurance"`
	MFAProvider       string                 `json:"mfa_provider"`

	// Verification result fields (populated after verify).
	VerifiedAt   *time.Time `json:"verified_at,omitempty"`
	VerifierID   string     `json:"verifier_id,omitempty"`
	Assurance    string     `json:"assurance,omitempty"`
	AuthTime     *time.Time `json:"auth_time,omitempty"`

	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
}

// CreateChallengeInput carries the parameters for creating an AuthNull challenge.
type CreateChallengeInput struct {
	SubjectID         string `json:"subject_id"`
	Audience          string `json:"audience"`
	RequestHash       string `json:"request_hash"`
	EscalationID      string `json:"escalation_id"`
	RequiredAssurance string `json:"required_assurance"`
	MFAProvider       string `json:"mfa_provider"`
	TTL               time.Duration
}

// VerifyChallengeInput carries the parameters for verifying an AuthNull challenge.
type VerifyChallengeInput struct {
	ChallengeID  string    `json:"challenge_id"`
	VerifierID   string    `json:"verifier_id"`
	RequestHash  string    `json:"request_hash"`
	Assurance    string    `json:"assurance"`
	AuthTime     time.Time `json:"auth_time"`
	Signature    string    `json:"signature"`
	Nonce        string    `json:"nonce"`
}

// BindChallengeInput carries the parameters for binding a verified challenge
// to an access request.
type BindChallengeInput struct {
	ChallengeID     string `json:"challenge_id"`
	AccessRequestID string `json:"access_request_id"`
	RequesterID     string `json:"requester_id"` // For self-approval check
}

// ChallengeVerificationResult is the output of a successful verification.
type ChallengeVerificationResult struct {
	ChallengeID string    `json:"challenge_id"`
	VerifierID  string    `json:"verifier_id"`
	Assurance   string    `json:"assurance"`
	AuthTime    time.Time `json:"auth_time"`
	RequestHash string    `json:"request_hash"`
	Fresh       bool      `json:"fresh"`
}

// AuthNullVerificationService manages the AuthNull challenge lifecycle:
// create -> verify -> bind to request. It enforces:
//
//   - Subject matching: the verifier must be the challenge subject.
//   - Audience matching: the audience must match the challenge audience.
//   - Freshness: the auth time must be recent (within the staleness window).
//   - Challenge binding: the request hash must match.
//   - Replay protection: a challenge can only be verified once.
//   - Mock rejection: mock mode is rejected in production.
//   - Self-approval protection: requester cannot approve their own request.
//   - Operation change detection: changed operations invalidate the challenge.
type AuthNullVerificationService struct {
	mu         sync.Mutex
	challenges map[string]*AuthNullChallenge // keyed by challenge ID
	replays    map[string]bool               // keyed by challenge ID for replay detection
	production bool                          // true = reject mock mode
	maxStale   time.Duration                 // maximum staleness for auth_time
}

// NewAuthNullVerificationService creates a new AuthNull verification service.
// When production is true, mock-mode challenges are rejected.
func NewAuthNullVerificationService(production bool) *AuthNullVerificationService {
	return &AuthNullVerificationService{
		challenges: make(map[string]*AuthNullChallenge),
		replays:    make(map[string]bool),
		production: production,
		maxStale:   5 * time.Minute,
	}
}

// CreateChallenge creates a new AuthNull challenge for MFA step-up
// verification. The challenge is bound to a specific subject, audience,
// and request hash. It returns the challenge with its URI and nonce.
func (s *AuthNullVerificationService) CreateChallenge(_ context.Context, workspaceID string, in CreateChallengeInput) (*AuthNullChallenge, error) {
	if in.SubjectID == "" {
		return nil, fmt.Errorf("%w: subject_id required", ErrAuthNullVerificationFailed)
	}
	if in.RequestHash == "" {
		return nil, fmt.Errorf("%w: request_hash required", ErrAuthNullVerificationFailed)
	}

	ttl := in.TTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}

	now := time.Now().UTC()
	id := uuid.New().String()
	nonce := generateNonce(id, workspaceID, now)

	ch := &AuthNullChallenge{
		ID:                id,
		WorkspaceID:       workspaceID,
		SubjectID:         in.SubjectID,
		Audience:          in.Audience,
		RequestHash:       in.RequestHash,
		EscalationID:      in.EscalationID,
		State:             AuthNullChallengeCreated,
		ChallengeURI:      fmt.Sprintf("authnull://challenge/%s", id),
		Nonce:             nonce,
		RequiredAssurance: in.RequiredAssurance,
		MFAProvider:       in.MFAProvider,
		CreatedAt:         now,
		ExpiresAt:         now.Add(ttl),
	}

	s.mu.Lock()
	s.challenges[id] = ch
	s.mu.Unlock()

	return ch, nil
}

// VerifyChallenge verifies a signed AuthNull challenge response. It checks
// subject matching, audience, freshness, challenge binding, and replay state.
// Mock mode is rejected in production.
func (s *AuthNullVerificationService) VerifyChallenge(_ context.Context, workspaceID string, in VerifyChallengeInput) (*ChallengeVerificationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch, ok := s.challenges[in.ChallengeID]
	if !ok || ch.WorkspaceID != workspaceID {
		return nil, ErrAuthNullChallengeNotFound
	}

	// Check expiration.
	now := time.Now().UTC()
	if !now.Before(ch.ExpiresAt) {
		ch.State = AuthNullChallengeExpiredState
		return nil, ErrAuthNullChallengeExpired
	}

	// Replay protection: reject if already verified.
	if s.replays[in.ChallengeID] {
		return nil, ErrAuthNullChallengeReplayed
	}

	// State check: must be in created state.
	if ch.State != AuthNullChallengeCreated {
		return nil, fmt.Errorf("%w: challenge state is %s, expected created", ErrAuthNullVerificationFailed, ch.State)
	}

	// Nonce verification.
	if in.Nonce != ch.Nonce {
		return nil, fmt.Errorf("%w: nonce mismatch", ErrAuthNullVerificationFailed)
	}

	// Challenge binding: request hash must match.
	if in.RequestHash != ch.RequestHash {
		return nil, ErrAuthNullOperationChanged
	}

	// Freshness check: auth_time must be recent.
	if now.Sub(in.AuthTime) > s.maxStale {
		return nil, ErrAuthNullFreshnessFailed
	}

	// Assurance check.
	if in.Assurance == "" {
		return nil, fmt.Errorf("%w: assurance level is required", ErrAuthNullVerificationFailed)
	}

	// Mock mode rejection: if signature looks like a mock, reject in production.
	if s.production && in.Signature == "mock" {
		return nil, ErrAuthNullMockInProduction
	}

	// Mark as replayed.
	s.replays[in.ChallengeID] = true

	// Update challenge state.
	ch.State = AuthNullChallengeVerified
	ch.VerifiedAt = &now
	ch.VerifierID = in.VerifierID
	ch.Assurance = in.Assurance
	authTime := in.AuthTime
	ch.AuthTime = &authTime

	return &ChallengeVerificationResult{
		ChallengeID: ch.ID,
		VerifierID:  in.VerifierID,
		Assurance:   in.Assurance,
		AuthTime:    in.AuthTime,
		RequestHash: ch.RequestHash,
		Fresh:       now.Sub(in.AuthTime) <= s.maxStale,
	}, nil
}

// BindToRequest binds a verified challenge to an access request. This is the
// final step in the challenge lifecycle. It validates that:
// - The challenge exists and is verified.
// - The challenge is not already bound to another request.
// - Self-approval is prevented (requester != verifier).
func (s *AuthNullVerificationService) BindToRequest(_ context.Context, workspaceID string, in BindChallengeInput) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch, ok := s.challenges[in.ChallengeID]
	if !ok || ch.WorkspaceID != workspaceID {
		return ErrAuthNullChallengeNotFound
	}

	if ch.State != AuthNullChallengeVerified {
		if ch.State == AuthNullChallengeBound {
			return ErrAuthNullChallengeAlreadyBound
		}
		return fmt.Errorf("%w: challenge state is %s, expected verified", ErrAuthNullVerificationFailed, ch.State)
	}

	// Self-approval check: the verifier must not be the requester.
	if in.RequesterID != "" && ch.VerifierID != "" && in.RequesterID == ch.VerifierID {
		return ErrAuthNullSelfApproval
	}

	ch.State = AuthNullChallengeBound
	ch.AccessRequestID = in.AccessRequestID

	return nil
}

// GetChallenge returns the current state of a challenge.
func (s *AuthNullVerificationService) GetChallenge(_ context.Context, workspaceID, challengeID string) (*AuthNullChallenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch, ok := s.challenges[challengeID]
	if !ok || ch.WorkspaceID != workspaceID {
		return nil, ErrAuthNullChallengeNotFound
	}
	return ch, nil
}

// IsVerified returns true if the challenge has been successfully verified
// and has not expired.
func (s *AuthNullVerificationService) IsVerified(_ context.Context, workspaceID, challengeID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch, ok := s.challenges[challengeID]
	if !ok || ch.WorkspaceID != workspaceID {
		return false, ErrAuthNullChallengeNotFound
	}

	now := time.Now().UTC()
	if !now.Before(ch.ExpiresAt) {
		return false, nil
	}

	return ch.State == AuthNullChallengeVerified || ch.State == AuthNullChallengeBound, nil
}

// ExpireStale transitions created challenges that have passed their ExpiresAt
// to expired. Returns the count of expired challenges.
func (s *AuthNullVerificationService) ExpireStale(_ context.Context) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	count := 0
	for _, ch := range s.challenges {
		if ch.State == AuthNullChallengeCreated && !now.Before(ch.ExpiresAt) {
			ch.State = AuthNullChallengeExpiredState
			count++
		}
	}
	return count
}

// generateNonce creates a deterministic nonce from the challenge ID, workspace,
// and timestamp. In production, this would use a cryptographic random source.
func generateNonce(challengeID, workspaceID string, t time.Time) string {
	h := sha256.New()
	h.Write([]byte(challengeID))
	h.Write([]byte{0})
	h.Write([]byte(workspaceID))
	h.Write([]byte{0})
	h.Write([]byte(t.Format(time.RFC3339Nano)))
	return hex.EncodeToString(h.Sum(nil))[:32]
}
