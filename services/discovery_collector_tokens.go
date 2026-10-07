package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// CollectorTokenPrefix marks a per-workspace discovery collector credential.
const CollectorTokenPrefix = "authsec_col_"

// ErrInvalidCollectorToken covers unknown and revoked collector tokens alike.
var ErrInvalidCollectorToken = errors.New("invalid collector credential")

// DiscoveryCollectorToken is one per-workspace credential for the discovery
// ingress (067, AS-014). Only the SHA-256 hash of the token is stored.
type DiscoveryCollectorToken struct {
	ID          uuid.UUID  `json:"id" gorm:"column:id;type:uuid;primaryKey"`
	WorkspaceID uuid.UUID  `json:"workspace_id" gorm:"column:workspace_id;type:uuid"`
	Name        string     `json:"name" gorm:"column:name"`
	TokenHash   string     `json:"-" gorm:"column:token_hash"`
	TokenPrefix string     `json:"token_prefix" gorm:"column:token_prefix"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty" gorm:"column:created_by;type:uuid"`
	CreatedAt   time.Time  `json:"created_at" gorm:"column:created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty" gorm:"column:last_used_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty" gorm:"column:revoked_at"`
}

// TableName is the discovery_collector_tokens table.
func (DiscoveryCollectorToken) TableName() string { return "discovery_collector_tokens" }

// MintCollectorToken creates a collector credential in the workspace carried
// by ctx and returns the plaintext once.
func MintCollectorToken(ctx context.Context, db *gorm.DB, name string, createdBy *uuid.UUID) (*DiscoveryCollectorToken, string, error) {
	tc, err := tenancy.FromContext(ctx)
	if err != nil {
		return nil, "", err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", fmt.Errorf("generate collector token: %w", err)
	}
	token := CollectorTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	row := &DiscoveryCollectorToken{
		ID:          uuid.New(),
		WorkspaceID: tc.WorkspaceID,
		Name:        strings.TrimSpace(name),
		TokenHash:   hashActuationToken(token),
		TokenPrefix: token[:len(CollectorTokenPrefix)+6],
		CreatedBy:   createdBy,
		CreatedAt:   time.Now().UTC(),
	}
	err = tenancy.Transaction(ctx, db, func(tx *gorm.DB) error { return tx.Create(row).Error })
	if err != nil {
		return nil, "", err
	}
	return row, token, nil
}

// ListCollectorTokens lists the workspace's collector credentials (no secrets).
func ListCollectorTokens(ctx context.Context, db *gorm.DB) ([]DiscoveryCollectorToken, error) {
	var rows []DiscoveryCollectorToken
	err := tenancy.Transaction(ctx, db, func(tx *gorm.DB) error {
		return tx.Order("created_at DESC").Find(&rows).Error
	})
	return rows, err
}

// RevokeCollectorToken revokes one of the workspace's collector credentials.
// Another workspace's id is tenancy.ErrNotFound.
func RevokeCollectorToken(ctx context.Context, db *gorm.DB, id uuid.UUID) error {
	return tenancy.Transaction(ctx, db, func(tx *gorm.DB) error {
		res := tx.Model(&DiscoveryCollectorToken{}).
			Where("id = ? AND revoked_at IS NULL", id).
			Update("revoked_at", time.Now().UTC())
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return tenancy.ErrNotFound
		}
		return nil
	})
}

// AuthenticateCollectorToken resolves a presented collector token to its
// workspace. It runs before any workspace is known: the token is the only
// input, matched by hash.
func AuthenticateCollectorToken(db *gorm.DB, token string) (*DiscoveryCollectorToken, error) {
	if !strings.HasPrefix(token, CollectorTokenPrefix) {
		return nil, ErrInvalidCollectorToken
	}
	var row DiscoveryCollectorToken
	err := db.Where("token_hash = ? AND revoked_at IS NULL", hashActuationToken(token)).First(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCollectorToken
		}
		return nil, err
	}
	now := time.Now().UTC()
	if row.LastUsedAt == nil || now.Sub(*row.LastUsedAt) > time.Minute {
		db.Model(&DiscoveryCollectorToken{}).Where("id = ? AND workspace_id = ?", row.ID, row.WorkspaceID).
			Update("last_used_at", now)
	}
	return &row, nil
}
