package repositories

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	// DiscoveryIngestTokenPrefix starts every discovery ingest token, so a
	// leaked one is recognisable in a log or a secret scanner.
	DiscoveryIngestTokenPrefix = "aid_"
	// discoveryIngestTokenLen is "aid_" plus 43 base64url characters (32
	// random bytes, unpadded).
	discoveryIngestTokenLen = len(DiscoveryIngestTokenPrefix) + 43
	// discoveryIngestTokenShown is how much of a token is kept in clear for an
	// operator to tell tokens apart.
	discoveryIngestTokenShown = 8
	// DiscoveryIngestTouchInterval bounds how often a token's last_used_at is
	// written: at most once per interval per token, so a fleet of agents
	// heartbeating every few seconds is not a write per request.
	DiscoveryIngestTouchInterval = time.Minute
)

var (
	// ErrIngestTokenNotFound means no token with that id exists in the
	// caller's workspace.
	ErrIngestTokenNotFound = errors.New("ingest token not found")
	// ErrIngestTokenSourceNotFound means the discovery source a token was to be
	// bound to is not a source of the caller's workspace.
	ErrIngestTokenSourceNotFound = errors.New("discovery source not found in this workspace")
)

// discoveryIngestTokenColumns is every column EXCEPT token_hash: what a list or
// a revoke reads back. The hash is never selected where it is not needed.
var discoveryIngestTokenColumns = []string{
	"id", "workspace_id", "discovery_source_id", "token_prefix", "label",
	"created_by", "created_at", "last_used_at", "revoked_at",
}

// DiscoveryIngestTokenRepository stores the credentials a discovery agent
// presents on the ingress. It holds hashes only.
type DiscoveryIngestTokenRepository interface {
	// Mint creates a token for a workspace, optionally bound to one of its
	// discovery sources, and returns the stored row and the plaintext. The
	// plaintext is not recoverable afterwards.
	Mint(workspaceID uuid.UUID, sourceID *uuid.UUID, label, createdBy string) (*models.DiscoveryIngestToken, string, error)
	// List returns the workspace's tokens, newest first, revoked ones included
	// (with revoked_at set). Hashes are never read.
	List(workspaceID uuid.UUID) ([]models.DiscoveryIngestToken, error)
	// Revoke stamps revoked_at. Revoking a revoked token is a no-op that
	// returns the row; a token of another workspace is ErrIngestTokenNotFound.
	Revoke(workspaceID, id uuid.UUID) (*models.DiscoveryIngestToken, error)
	// Verify resolves a presented token to its live (unrevoked) row, or nil
	// when it is not a valid token. It records last_used_at at most once per
	// DiscoveryIngestTouchInterval. An error is a database failure, never an
	// invalid token.
	Verify(token string) (*models.DiscoveryIngestToken, error)
}

type discoveryIngestTokenRepository struct{ db *gorm.DB }

// NewDiscoveryIngestTokenRepository constructs the repository.
func NewDiscoveryIngestTokenRepository(db *gorm.DB) DiscoveryIngestTokenRepository {
	return &discoveryIngestTokenRepository{db}
}

// GenerateDiscoveryIngestToken returns a new token: "aid_" + base64url (no
// padding) of 32 bytes from crypto/rand.
func GenerateDiscoveryIngestToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate ingest token: %w", err)
	}
	return DiscoveryIngestTokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// HashDiscoveryIngestToken is the stored form of a token: sha256, lower-case
// hex. A token is high-entropy random, so an unsalted fast hash is the right
// tool: it makes the lookup an index probe, and there is nothing to brute-force.
func HashDiscoveryIngestToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// wellFormedIngestToken is a shape check before any database work, so a
// garbage Authorization header costs no query.
func wellFormedIngestToken(token string) bool {
	if len(token) != discoveryIngestTokenLen || !strings.HasPrefix(token, DiscoveryIngestTokenPrefix) {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(token[len(DiscoveryIngestTokenPrefix):])
	return err == nil
}

func (r *discoveryIngestTokenRepository) Mint(workspaceID uuid.UUID, sourceID *uuid.UUID, label, createdBy string) (*models.DiscoveryIngestToken, string, error) {
	if sourceID != nil {
		var n int64
		if err := r.db.Table("discovery_sources").
			Where("workspace_id = ? AND id = ?", workspaceID, *sourceID).
			Count(&n).Error; err != nil {
			return nil, "", err
		}
		if n == 0 {
			return nil, "", ErrIngestTokenSourceNotFound
		}
	}
	plain, err := GenerateDiscoveryIngestToken()
	if err != nil {
		return nil, "", err
	}
	row := &models.DiscoveryIngestToken{
		ID:                uuid.New(),
		WorkspaceID:       workspaceID,
		DiscoverySourceID: sourceID,
		TokenHash:         HashDiscoveryIngestToken(plain),
		TokenPrefix:       plain[:discoveryIngestTokenShown],
		Label:             strings.TrimSpace(label),
		CreatedBy:         createdBy,
	}
	if err := r.db.Create(row).Error; err != nil {
		return nil, "", err
	}
	return row, plain, nil
}

func (r *discoveryIngestTokenRepository) List(workspaceID uuid.UUID) ([]models.DiscoveryIngestToken, error) {
	out := []models.DiscoveryIngestToken{}
	err := r.db.Select(discoveryIngestTokenColumns).
		Where("workspace_id = ?", workspaceID).
		Order("created_at DESC, id").
		Find(&out).Error
	return out, err
}

func (r *discoveryIngestTokenRepository) Revoke(workspaceID, id uuid.UUID) (*models.DiscoveryIngestToken, error) {
	// Conditional on revoked_at IS NULL so a second revoke keeps the first
	// timestamp: when a token stopped working is evidence.
	if err := r.db.Model(&models.DiscoveryIngestToken{}).
		Where("workspace_id = ? AND id = ? AND revoked_at IS NULL", workspaceID, id).
		Update("revoked_at", gorm.Expr("now()")).Error; err != nil {
		return nil, err
	}
	var out models.DiscoveryIngestToken
	err := r.db.Select(discoveryIngestTokenColumns).
		Where("workspace_id = ? AND id = ?", workspaceID, id).
		Take(&out).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrIngestTokenNotFound
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *discoveryIngestTokenRepository) Verify(token string) (*models.DiscoveryIngestToken, error) {
	if !wellFormedIngestToken(token) {
		return nil, nil
	}
	h := HashDiscoveryIngestToken(token)
	var row models.DiscoveryIngestToken
	err := r.db.Where("token_hash = ? AND revoked_at IS NULL", h).Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// The lookup is by hash, so the comparison that decides is the index's.
	// Comparing again in constant time costs nothing and keeps the decision
	// from ever resting on a variable-time string compare in Go.
	if subtle.ConstantTimeCompare([]byte(row.TokenHash), []byte(h)) != 1 {
		return nil, nil
	}
	row.TokenHash = ""

	// At most one write per token per interval, decided by the database in one
	// statement, so concurrent replicas cannot each write it. Its error is
	// deliberately dropped: last_used_at is a convenience for an operator, not
	// part of the decision, and a failed touch must not fail an authenticated
	// call.
	_ = r.db.Model(&models.DiscoveryIngestToken{}).
		Where("id = ? AND revoked_at IS NULL AND (last_used_at IS NULL OR last_used_at < now() - make_interval(secs => ?))",
			row.ID, DiscoveryIngestTouchInterval.Seconds()).
		Update("last_used_at", gorm.Expr("now()")).Error
	return &row, nil
}
