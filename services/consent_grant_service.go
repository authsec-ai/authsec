package services

import (
	"errors"
	"fmt"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ConsentGrantService manages oauth_consent_grants rows on the prod-mcp-v2
// backport. The table itself was created in migration tenant/024 alongside
// the OAuth v2 surface; this service is the JWT-authenticated read/revoke
// API the admin UI's "Consent Grants" tab uses.
//
// Scope semantics:
//   - User-scope: a logged-in end-user can list/revoke THEIR OWN grants.
//   - Admin-scope: a tenant admin can list/revoke ALL grants in the tenant,
//     filtered by application_id.
// Currently we expose the union via the same endpoint and let the JWT's
// claims gate which rows are returned (filter by user_id when admin=false,
// no user filter when admin=true). The handler decides.
//
// PHASE7-NOTE: dev's implementation also calls Hydra
// /admin/oauth2/auth/sessions/consent on revoke to invalidate the upstream
// consent session. We do the same here so revoked grants take effect on
// the next access-token refresh.
type ConsentGrantService struct{}

func NewConsentGrantService() *ConsentGrantService { return &ConsentGrantService{} }

var ErrConsentGrantNotFound = errors.New("consent grant not found")

// UpsertGrant is the consent-handler-side write: when the user clicks
// "Approve + remember", we record (user, client, application, granted_scopes)
// so the next /authorize request for the same triple can auto-approve
// without showing the consent screen.
//
// Idempotent: same (user_id, client_id, resource_server_id) tuple updates
// in place. Resets `revoked=false` on re-grant so a previously-revoked
// grant can be re-granted by re-confirming on the consent screen.
func (s *ConsentGrantService) UpsertGrant(
	tenantID string,
	userID uuid.UUID,
	clientID string,
	applicationID uuid.UUID,
	grantedScopes []string,
) (*models.OAuthConsentGrant, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	now := time.Now().UTC()
	row := models.OAuthConsentGrant{
		TenantID:         tenantID,
		UserID:           userID,
		ClientID:         clientID,
		ResourceServerID: &applicationID,
		GrantedScopes:    grantedScopes,
	}
	err = tenantDB.
		Where("user_id = ? AND client_id = ? AND resource_server_id = ?",
			userID, clientID, applicationID).
		Assign(map[string]interface{}{
			"granted_scopes": row.GrantedScopes,
			"revoked":        false,
			"revoked_at":     nil,
			"updated_at":     now,
		}).
		FirstOrCreate(&row).Error
	if err != nil {
		return nil, fmt.Errorf("upsert consent grant: %w", err)
	}
	return &row, nil
}

// LookupActiveGrant returns the non-revoked consent grant for a
// (user, client, application) triple if one exists. Used by the consent
// GET handler to auto-approve when the user previously remembered consent.
func (s *ConsentGrantService) LookupActiveGrant(
	tenantID string,
	userID uuid.UUID,
	clientID string,
	applicationID uuid.UUID,
) (*models.OAuthConsentGrant, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	var row models.OAuthConsentGrant
	err = tenantDB.Where(
		"user_id = ? AND client_id = ? AND resource_server_id = ? AND revoked = false",
		userID, clientID, applicationID,
	).First(&row).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &row, nil
}

// ListFilters constrains which grants are returned.
type ListFilters struct {
	// UserID, when non-Nil, restricts results to grants for that user.
	// End-users always pass their own user_id; admins may omit it to see
	// every grant in the tenant.
	UserID uuid.UUID
	// ApplicationID, when non-Nil, restricts results to grants against a
	// specific Application (used by the UI's per-application tab).
	ApplicationID uuid.UUID
	// IncludeRevoked: by default we exclude revoked grants. Pass true to
	// include them (admin audit view).
	IncludeRevoked bool
}

// List returns matching consent grants ordered by created_at DESC.
func (s *ConsentGrantService) List(tenantID string, f ListFilters) ([]models.OAuthConsentGrant, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}
	q := tenantDB.Where("tenant_id = ?", tenantID)
	if f.UserID != uuid.Nil {
		q = q.Where("user_id = ?", f.UserID)
	}
	if f.ApplicationID != uuid.Nil {
		q = q.Where("resource_server_id = ?", f.ApplicationID)
	}
	if !f.IncludeRevoked {
		q = q.Where("revoked = ?", false)
	}
	var rows []models.OAuthConsentGrant
	if err := q.Order("created_at DESC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list consent grants: %w", err)
	}
	return rows, nil
}

// Revoke marks the grant revoked and calls Hydra to invalidate the upstream
// consent session. If callingUserID is non-Nil, enforces user-ownership
// (a user can only revoke their own grants); pass uuid.Nil for admin
// revocation (skips the ownership check).
//
// Idempotent: revoking an already-revoked grant returns nil.
func (s *ConsentGrantService) Revoke(tenantID string, grantID uuid.UUID, callingUserID uuid.UUID) error {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return fmt.Errorf("get tenant db: %w", err)
	}
	var grant models.OAuthConsentGrant
	if err := tenantDB.Where("id = ? AND tenant_id = ?", grantID, tenantID).
		First(&grant).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrConsentGrantNotFound
		}
		return err
	}
	if callingUserID != uuid.Nil && grant.UserID != callingUserID {
		return ErrConsentGrantNotFound // hide existence from cross-user lookups
	}
	if grant.Revoked {
		return nil
	}
	now := time.Now().UTC()
	if err := tenantDB.Model(&grant).Updates(map[string]interface{}{
		"revoked":    true,
		"revoked_at": now,
		"updated_at": now,
	}).Error; err != nil {
		return fmt.Errorf("mark revoked: %w", err)
	}

	// Best-effort Hydra consent-session invalidation. Failure is logged but
	// not returned — the DB row is the source of truth; introspection will
	// fail on the next access-token validation regardless.
	if err := hydraV2AdminRevokeConsentSession(grant.UserID.String(), grant.ClientID); err != nil {
		// Don't return the error — the grant IS revoked DB-side, and
		// the introspection check on next call will deny.
		_ = err
	}
	return nil
}
