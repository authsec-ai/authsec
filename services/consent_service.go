package services

import (
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
// that covers all requested scopes. Returns the grant if found, nil otherwise.
func (s *ConsentService) CheckExistingConsent(
	tenantID, userID, clientID, resourceServerID uuid.UUID,
	requestedScopes []string,
) (*models.OAuthConsentGrant, error) {
	var grant models.OAuthConsentGrant
	err := s.db.Where(
		"tenant_id = ? AND user_id = ? AND client_id = ? AND resource_server_id = ? AND revoked_at IS NULL AND expires_at > ?",
		tenantID, userID, clientID, resourceServerID, time.Now(),
	).First(&grant).Error

	if err != nil {
		return nil, err
	}

	// Check if granted scopes are a superset of requested scopes
	grantedSet := make(map[string]struct{}, len(grant.GrantedScopes))
	for _, s := range grant.GrantedScopes {
		grantedSet[s] = struct{}{}
	}
	for _, s := range requestedScopes {
		if _, ok := grantedSet[s]; !ok {
			// Requested scope not covered by existing consent — need re-consent
			return nil, nil
		}
	}

	return &grant, nil
}

// UpsertConsent creates or updates a consent grant for the given (user x client x RS).
// If a grant already exists, it's updated with the new scopes and TTL.
func (s *ConsentService) UpsertConsent(
	tenantID, userID, clientID, resourceServerID uuid.UUID,
	grantedScopes []string,
	ttl time.Duration,
) (*models.OAuthConsentGrant, error) {
	if ttl == 0 {
		ttl = DefaultConsentTTL
	}

	grant := models.OAuthConsentGrant{
		TenantID:         tenantID,
		UserID:           userID,
		ClientID:         clientID,
		ResourceServerID: resourceServerID,
		GrantedScopes:    pq.StringArray(grantedScopes),
		ExpiresAt:        time.Now().Add(ttl),
	}

	// Upsert: on conflict (tenant_id, user_id, client_id, resource_server_id) → update
	result := s.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "tenant_id"},
			{Name: "user_id"},
			{Name: "client_id"},
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

// ListByUser returns all active (non-revoked) consent grants for a user.
func (s *ConsentService) ListByUser(tenantID, userID uuid.UUID) ([]models.OAuthConsentGrant, error) {
	var grants []models.OAuthConsentGrant
	err := s.db.Where(
		"tenant_id = ? AND user_id = ? AND revoked_at IS NULL AND expires_at > ?",
		tenantID, userID, time.Now(),
	).Order("created_at DESC").Find(&grants).Error
	return grants, err
}

// ListByTenant returns all consent grants for a tenant (admin view), with optional filters.
func (s *ConsentService) ListByTenant(tenantID uuid.UUID, userID, clientID, rsID *uuid.UUID) ([]models.OAuthConsentGrant, error) {
	query := s.db.Where("tenant_id = ?", tenantID)
	if userID != nil {
		query = query.Where("user_id = ?", *userID)
	}
	if clientID != nil {
		query = query.Where("client_id = ?", *clientID)
	}
	if rsID != nil {
		query = query.Where("resource_server_id = ?", *rsID)
	}

	var grants []models.OAuthConsentGrant
	err := query.Order("created_at DESC").Find(&grants).Error
	return grants, err
}
