package services

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// DefaultConsentTTL is the default time-to-live for a remembered consent grant.
const DefaultConsentTTL = 30 * 24 * time.Hour // 30 days

// ConsentService manages OAuth consent grants (remembered consent).
type ConsentService struct {
	db *gorm.DB
}

func NewConsentService(db *gorm.DB) *ConsentService {
	return &ConsentService{db: db}
}

// CheckExistingConsent looks for an active (non-expired, non-revoked) consent grant
// that covers all requestedScopes. It also validates each RS scope in the stored grant
// against userEffectiveScopes (RBAC revocation) and rsSupportedScopes (RS withdrawal).
// A stored grant containing a scope missing from either set is revoked in the DB (stale).
//
// Returns:
//   - grant non-nil: valid, up-to-date grant found and covers all requestedScopes
//   - stale true: a grant existed but was revoked (RBAC or RS withdrawal detected)
//   - err non-nil: unexpected DB error (ErrRecordNotFound is normalized to nil, false, nil)
func (s *ConsentService) CheckExistingConsent(
	workspaceID, userID, clientID, resourceServerID uuid.UUID,
	requestedScopes []string,
	userEffectiveScopes []string,
	rsSupportedScopes []string,
) (*models.OAuthConsentGrant, bool, error) {
	var grant models.OAuthConsentGrant
	err := s.db.Where(
		"workspace_id = ? AND user_id = ? AND oauth_client_id = ? AND resource_server_id = ? AND revoked_at IS NULL AND expires_at > ?",
		workspaceID, userID, clientID, resourceServerID, time.Now(),
	).First(&grant).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, nil // no active grant — normal control flow, not an error
	}
	if err != nil {
		return nil, false, err
	}

	// Build lookup sets for staleness check
	effectiveSet := make(map[string]struct{}, len(userEffectiveScopes))
	for _, s := range userEffectiveScopes {
		effectiveSet[s] = struct{}{}
	}
	rsSet := make(map[string]struct{}, len(rsSupportedScopes))
	for _, s := range rsSupportedScopes {
		rsSet[s] = struct{}{}
	}

	// Staleness check: verify each RS scope in the stored grant is still grantable.
	// OIDC core scopes are AS-level and not governed by RBAC or RS scopes_supported.
	var staleScopes []string
	for _, s := range grant.GrantedScopes {
		if IsOIDCCoreScope(s) {
			continue
		}
		if _, ok := effectiveSet[s]; !ok {
			staleScopes = append(staleScopes, s+" (rbac_revoked)")
			continue
		}
		if _, ok := rsSet[s]; !ok {
			staleScopes = append(staleScopes, s+" (rs_withdrawn)")
		}
	}
	if len(staleScopes) > 0 {
		now := time.Now()
		if err := s.db.Model(&grant).Update("revoked_at", now).Error; err != nil {
			// The grant is stale but the revocation failed to persist — return the error
			// so the caller knows the stale grant may still be active in the DB.
			log.Printf("[CONSENT] grant %s revocation write failed (stale scopes: %v): %v", grant.ID, staleScopes, err)
			return nil, false, fmt.Errorf("revoking stale grant %s: %w", grant.ID, err)
		}
		log.Printf("[CONSENT] grant %s revoked (stale scopes: %v)", grant.ID, staleScopes)
		return nil, true, nil
	}

	// Coverage check: stored grant must cover all requested scopes
	grantedSet := make(map[string]struct{}, len(grant.GrantedScopes))
	for _, s := range grant.GrantedScopes {
		grantedSet[s] = struct{}{}
	}
	for _, s := range requestedScopes {
		if _, ok := grantedSet[s]; !ok {
			return nil, false, nil // coverage gap → need re-consent
		}
	}

	return &grant, false, nil
}

// UpsertConsent creates or updates a consent grant for the given (user x client x RS).
// If a grant already exists, it's updated with the new scopes and TTL.
func (s *ConsentService) UpsertConsent(
	workspaceID, userID, clientID, resourceServerID uuid.UUID,
	grantedScopes []string,
	ttl time.Duration,
) (*models.OAuthConsentGrant, error) {
	if ttl == 0 {
		ttl = DefaultConsentTTL
	}

	grant := models.OAuthConsentGrant{
		WorkspaceID:      workspaceID,
		UserID:           userID,
		OAuthClientID:    clientID,
		ResourceServerID: resourceServerID,
		GrantedScopes:    pq.StringArray(grantedScopes),
		ExpiresAt:        time.Now().Add(ttl),
	}

	// Upsert: on conflict (workspace_id, user_id, oauth_client_id, resource_server_id) → update
	result := s.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "workspace_id"},
			{Name: "user_id"},
			{Name: "oauth_client_id"},
			{Name: "resource_server_id"},
		},
		DoUpdates: clause.AssignmentColumns([]string{"granted_scopes", "expires_at", "revoked_at", "updated_at"}),
	}).Create(&grant)

	if result.Error != nil {
		return nil, result.Error
	}

	// Clear any prior revocation on upsert
	if grant.RevokedAt != nil {
		s.db.Model(&grant).Update("revoked_at", nil)
	}

	return &grant, nil
}

// RevokeConsent revokes a consent grant by ID.
func (s *ConsentService) RevokeConsent(grantID uuid.UUID) error {
	now := time.Now()
	result := s.db.Model(&models.OAuthConsentGrant{}).
		Where("id = ? AND revoked_at IS NULL", grantID).
		Update("revoked_at", now)
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return result.Error
}

// RevokeConsentByUser revokes a consent grant, ensuring the caller is the owner.
func (s *ConsentService) RevokeConsentByUser(grantID, userID uuid.UUID) error {
	now := time.Now()
	result := s.db.Model(&models.OAuthConsentGrant{}).
		Where("id = ? AND user_id = ? AND revoked_at IS NULL", grantID, userID).
		Update("revoked_at", now)
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return result.Error
}

// RevokeConsentByTenant revokes a consent grant only when it belongs to workspaceID (admin path).
func (s *ConsentService) RevokeConsentByTenant(grantID, workspaceID uuid.UUID) error {
	now := time.Now()
	result := s.db.Model(&models.OAuthConsentGrant{}).
		Where("id = ? AND workspace_id = ? AND revoked_at IS NULL", grantID, workspaceID).
		Update("revoked_at", now)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// ListByUser returns all active (non-revoked) consent grants for a user.
func (s *ConsentService) ListByUser(workspaceID, userID uuid.UUID) ([]models.OAuthConsentGrant, error) {
	var grants []models.OAuthConsentGrant
	err := s.db.Where(
		"workspace_id = ? AND user_id = ? AND revoked_at IS NULL AND expires_at > ?",
		workspaceID, userID, time.Now(),
	).Order("created_at DESC").Find(&grants).Error
	return grants, err
}

// ListByTenant returns all consent grants for a tenant (admin view), with optional filters.
func (s *ConsentService) ListByTenant(workspaceID uuid.UUID, userID, clientID, rsID *uuid.UUID) ([]models.OAuthConsentGrant, error) {
	query := s.db.Where("workspace_id = ?", workspaceID)
	if userID != nil {
		query = query.Where("user_id = ?", *userID)
	}
	if clientID != nil {
		query = query.Where("oauth_client_id = ?", *clientID)
	}
	if rsID != nil {
		query = query.Where("resource_server_id = ?", *rsID)
	}

	var grants []models.OAuthConsentGrant
	err := query.Order("created_at DESC").Find(&grants).Error
	return grants, err
}
