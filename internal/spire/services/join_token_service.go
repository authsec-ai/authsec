package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
	"github.com/authsec-ai/authsec/internal/spire/domain/repositories"
	"github.com/authsec-ai/authsec/internal/spire/errors"
)

const (
	// DefaultJoinTokenTTL is how long a join token stays usable when the
	// admin does not say.
	DefaultJoinTokenTTL = time.Hour
	// MaxJoinTokenTTL bounds a join token's life.
	MaxJoinTokenTTL = 7 * 24 * time.Hour
)

// JoinTokenService mints, lists and revokes node attestation join tokens of
// the workspace carried by ctx.
type JoinTokenService struct {
	repo   repositories.JoinTokenRepository
	logger *logrus.Entry
}

// NewJoinTokenService creates the join token service.
func NewJoinTokenService(repo repositories.JoinTokenRepository, logger *logrus.Entry) *JoinTokenService {
	return &JoinTokenService{repo: repo, logger: logger}
}

// HashJoinToken is the stored form of a join token.
func HashJoinToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Mint creates a token for ctx's workspace and returns it with its secret,
// which is shown once and never stored.
func (s *JoinTokenService) Mint(ctx context.Context, description, createdBy string, ttl time.Duration) (*models.JoinToken, string, error) {
	if ttl <= 0 {
		ttl = DefaultJoinTokenTTL
	}
	if ttl > MaxJoinTokenTTL {
		return nil, "", errors.NewBadRequestError("ttl exceeds the 7 day maximum", nil)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", errors.NewInternalError("Failed to generate join token", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	t := &models.JoinToken{
		Description: description,
		CreatedBy:   createdBy,
		ExpiresAt:   time.Now().Add(ttl),
	}
	if err := s.repo.Create(ctx, t, HashJoinToken(secret)); err != nil {
		return nil, "", asAppError(err, "Failed to store join token")
	}
	return t, secret, nil
}

// List returns ctx's workspace's tokens (never their secrets or hashes).
func (s *JoinTokenService) List(ctx context.Context) ([]*models.JoinToken, error) {
	return s.repo.List(ctx)
}

// Revoke revokes a token of ctx's workspace; another workspace's is 404.
func (s *JoinTokenService) Revoke(ctx context.Context, id string) error {
	return s.repo.Revoke(ctx, id)
}
