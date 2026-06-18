package tokens

import (
	"context"
	"errors"
	"time"

	"github.com/authsec-ai/authsec/models"
	"gorm.io/gorm"
)

// LookupNativeToken returns the authoritative native_tokens row for a jti, or
// (nil, nil) if not found. The JWT proves signature + jti; this row is the
// source of truth for workspace/subject/rs/family/scope at introspection.
func LookupNativeToken(ctx context.Context, db *gorm.DB, jti string) (*models.NativeToken, error) {
	var row models.NativeToken
	err := db.WithContext(ctx).Where("jti = ?", jti).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// IsRevoked reports whether (iss, kind, jti) is present in revoked_tokens — the
// revocation source of truth.
func IsRevoked(ctx context.Context, db *gorm.DB, iss, kind, jti string) (bool, error) {
	var count int64
	err := db.WithContext(ctx).
		Model(&models.RevokedToken{}).
		Where("iss = ? AND kind = ? AND jti = ?", iss, kind, jti).
		Count(&count).Error
	return count > 0, err
}

// RevokeAccessToken records a native access-token revocation (source of truth)
// and stamps native_tokens.revoked_at for display/audit, in one transaction.
// If the two ever disagree, revoked_tokens wins (introspection only checks it).
func RevokeAccessToken(ctx context.Context, db *gorm.DB, iss, jti, reason string, expiresAt time.Time) error {
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		rev := models.RevokedToken{
			Iss:       iss,
			Kind:      models.RevokedKindAccessToken,
			JTI:       jti,
			RevokedAt: time.Now().UTC(),
			ExpiresAt: expiresAt,
		}
		if reason != "" {
			rev.Reason = &reason
		}
		// Idempotent: a repeat revoke is a no-op.
		if err := tx.Where("iss = ? AND kind = ? AND jti = ?", iss, models.RevokedKindAccessToken, jti).
			FirstOrCreate(&rev).Error; err != nil {
			return err
		}
		now := time.Now().UTC()
		return tx.Model(&models.NativeToken{}).
			Where("jti = ?", jti).
			Update("revoked_at", now).Error
	})
}

// MarkIDJAGSeen atomically records a redeemed ID-JAG as seen (replay guard).
// Returns seen=true when the jti was ALREADY present (i.e. this is a replay →
// caller must reject without minting). Intended to run inside the issuance tx.
func MarkIDJAGSeen(tx *gorm.DB, iss, jti string, expiresAt time.Time) (seen bool, err error) {
	res := tx.Exec(
		`INSERT INTO id_jag_replay_cache (iss, jti, expires_at) VALUES (?, ?, ?) ON CONFLICT (iss, jti) DO NOTHING`,
		iss, jti, expiresAt,
	)
	if res.Error != nil {
		return false, res.Error
	}
	// RowsAffected == 0 means the (iss,jti) was already present → replay.
	return res.RowsAffected == 0, nil
}
