package repositories

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// CloudIdentityRepository stores the identity foundation: what code runs as,
// and the long-lived secrets that prove it.
//
// Every method is workspace-scoped. An identity row names a customer's IAM
// principal; a missing tenant predicate here is a cross-tenant read of their
// estate.
type CloudIdentityRepository interface {
	// UpsertIdentity records one identity, keyed on (workspace_id, native_id).
	// A repeat scan updates the same row and stamps the generation; it never
	// creates a duplicate. Reports whether the row was newly created.
	UpsertIdentity(i *models.CloudIdentity) (stored *models.CloudIdentity, created bool, err error)

	// UpsertSecret records one secret, keyed on (workspace_id, native_id).
	UpsertSecret(s *models.CloudSecret) (stored *models.CloudSecret, created bool, err error)

	GetIdentity(workspaceID, id uuid.UUID) (*models.CloudIdentity, error)
	GetIdentityByNativeID(workspaceID uuid.UUID, nativeID string) (*models.CloudIdentity, error)
	ListIdentities(workspaceID uuid.UUID, f CloudIdentityFilter) ([]models.CloudIdentity, int64, error)
	ListSecrets(workspaceID uuid.UUID, identityID *uuid.UUID) ([]models.CloudSecret, error)

	// CountsForConnector reports how many identities and secrets a connector
	// currently holds, for the scan report.
	CountsForConnector(workspaceID, connectorID uuid.UUID) (identities, secrets int64, err error)

	// ReconcileGeneration removes rows this connector did NOT see in the given
	// generation.
	//
	// The caller must only invoke this after a scan in which EVERY surface was
	// reached. There is no guard inside a DELETE that can know whether the scan
	// was allowed to look — see the comment on the implementation.
	ReconcileGeneration(workspaceID, connectorID uuid.UUID, generation int) (identitiesRemoved, secretsRemoved int64, err error)
}

// CloudIdentityFilter narrows an identity listing.
type CloudIdentityFilter struct {
	ConnectorID *uuid.UUID
	Kind        string
	Limit       int
	Offset      int
}

type cloudIdentityRepository struct{ db *gorm.DB }

// NewCloudIdentityRepository constructs the repository.
func NewCloudIdentityRepository(db *gorm.DB) CloudIdentityRepository {
	return &cloudIdentityRepository{db: db}
}

func (r *cloudIdentityRepository) UpsertIdentity(i *models.CloudIdentity) (*models.CloudIdentity, bool, error) {
	if i.WorkspaceID == uuid.Nil || i.ConnectorID == uuid.Nil {
		return nil, false, errors.New("workspace_id and connector_id are required")
	}
	if i.NativeID == "" || i.Kind == "" {
		return nil, false, errors.New("native_id and kind are required")
	}
	if i.ID == uuid.Nil {
		i.ID = uuid.New()
	}
	normaliseAttrs(&i.Attrs)
	proposed := i.ID
	now := time.Now()

	// first_seen_at is absent on purpose: it records when AuthSec FIRST saw this
	// principal, and a later scan must not move it. That is the value that makes
	// "this role appeared last Tuesday" answerable.
	//
	// connector_id IS refreshed, so an identity visible through two connectors
	// records the one that most recently saw it.
	assignments := map[string]interface{}{
		"connector_id":         i.ConnectorID,
		"kind":                 i.Kind,
		"name":                 i.Name,
		"created_at":           i.ProviderCreatedAt,
		"enabled":              i.Enabled,
		"attrs":                i.Attrs,
		"last_seen_generation": i.LastSeenGeneration,
		"last_seen_at":         now,
		"row_updated_at":       now,
	}
	// last_used_at is only advanced, never cleared. AWS reports it from
	// different places with different freshness — GetRole's RoleLastUsed, the
	// credential report, CloudTrail — and a source that happens not to know must
	// not erase what another source already established. Null means unknown, so
	// overwriting a known date with null would manufacture a gap.
	if i.LastUsedAt != nil {
		assignments["last_used_at"] = gorm.Expr(
			`CASE WHEN cloud_identity.last_used_at IS NULL
			        OR excluded.last_used_at > cloud_identity.last_used_at
			      THEN excluded.last_used_at ELSE cloud_identity.last_used_at END`)
	}

	err := r.db.Clauses(
		clause.OnConflict{
			Columns:   []clause.Column{{Name: "workspace_id"}, {Name: "native_id"}},
			DoUpdates: clause.Assignments(assignments),
		},
		clause.Returning{},
	).Create(i).Error
	if err != nil {
		return nil, false, err
	}
	return i, i.ID == proposed, nil
}

func (r *cloudIdentityRepository) UpsertSecret(s *models.CloudSecret) (*models.CloudSecret, bool, error) {
	if s.WorkspaceID == uuid.Nil || s.ConnectorID == uuid.Nil || s.IdentityID == uuid.Nil {
		return nil, false, errors.New("workspace_id, connector_id and identity_id are required")
	}
	if s.NativeID == "" || s.Kind == "" {
		return nil, false, errors.New("native_id and kind are required")
	}
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	normaliseAttrs(&s.Attrs)
	proposed := s.ID
	now := time.Now()

	assignments := map[string]interface{}{
		"connector_id":         s.ConnectorID,
		"identity_id":          s.IdentityID,
		"kind":                 s.Kind,
		"created_at":           s.ProviderCreatedAt,
		"expires_at":           s.ExpiresAt,
		"status":               s.Status,
		"attrs":                s.Attrs,
		"last_seen_generation": s.LastSeenGeneration,
		"last_seen_at":         now,
		"row_updated_at":       now,
	}
	if s.LastUsedAt != nil {
		assignments["last_used_at"] = gorm.Expr(
			`CASE WHEN cloud_secret.last_used_at IS NULL
			        OR excluded.last_used_at > cloud_secret.last_used_at
			      THEN excluded.last_used_at ELSE cloud_secret.last_used_at END`)
	}

	err := r.db.Clauses(
		clause.OnConflict{
			Columns:   []clause.Column{{Name: "workspace_id"}, {Name: "native_id"}},
			DoUpdates: clause.Assignments(assignments),
		},
		clause.Returning{},
	).Create(s).Error
	if err != nil {
		return nil, false, err
	}
	return s, s.ID == proposed, nil
}

func (r *cloudIdentityRepository) GetIdentity(workspaceID, id uuid.UUID) (*models.CloudIdentity, error) {
	var out models.CloudIdentity
	err := r.db.Where("workspace_id = ? AND id = ?", workspaceID, id).First(&out).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrCloudIdentityNotFound
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *cloudIdentityRepository) GetIdentityByNativeID(workspaceID uuid.UUID, nativeID string) (*models.CloudIdentity, error) {
	var out models.CloudIdentity
	err := r.db.Where("workspace_id = ? AND native_id = ?", workspaceID, nativeID).First(&out).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrCloudIdentityNotFound
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *cloudIdentityRepository) ListIdentities(workspaceID uuid.UUID, f CloudIdentityFilter) ([]models.CloudIdentity, int64, error) {
	q := r.db.Model(&models.CloudIdentity{}).Where("workspace_id = ?", workspaceID)
	if f.ConnectorID != nil {
		q = q.Where("connector_id = ?", *f.ConnectorID)
	}
	if f.Kind != "" {
		q = q.Where("kind = ?", f.Kind)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []models.CloudIdentity
	if err := q.Order("kind, name").Limit(limit).Offset(f.Offset).Find(&out).Error; err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func (r *cloudIdentityRepository) ListSecrets(workspaceID uuid.UUID, identityID *uuid.UUID) ([]models.CloudSecret, error) {
	q := r.db.Where("workspace_id = ?", workspaceID)
	if identityID != nil {
		q = q.Where("identity_id = ?", *identityID)
	}
	var out []models.CloudSecret
	// Oldest first: age is the finding.
	if err := q.Order("created_at NULLS LAST").Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (r *cloudIdentityRepository) CountsForConnector(workspaceID, connectorID uuid.UUID) (int64, int64, error) {
	var identities, secrets int64
	if err := r.db.Model(&models.CloudIdentity{}).
		Where("workspace_id = ? AND connector_id = ?", workspaceID, connectorID).
		Count(&identities).Error; err != nil {
		return 0, 0, err
	}
	if err := r.db.Model(&models.CloudSecret{}).
		Where("workspace_id = ? AND connector_id = ?", workspaceID, connectorID).
		Count(&secrets).Error; err != nil {
		return 0, 0, err
	}
	return identities, secrets, nil
}

// ReconcileGeneration removes what this connector did not see.
//
// THE GUARD IS THE CALLER'S, AND IT IS DELIBERATE. This method cannot tell a
// principal that was deleted in AWS from one that a denied ListRoles simply
// never returned. Both look identical from here: a row with a stale generation.
// Only the scan knows whether it was allowed to look, which is why
// ScanCoverage.Complete() gates the call and why an incomplete scan skips it
// entirely rather than deleting "just the ones we are confident about".
//
// Secrets are deleted explicitly rather than left to the FK cascade, so the
// count returned is real. A cascade would silently remove rows this function
// then reports as zero.
func (r *cloudIdentityRepository) ReconcileGeneration(
	workspaceID, connectorID uuid.UUID, generation int,
) (int64, int64, error) {

	var identitiesRemoved, secretsRemoved int64
	err := r.db.Transaction(func(tx *gorm.DB) error {
		res := tx.Where(`workspace_id = ? AND connector_id = ? AND last_seen_generation < ?`,
			workspaceID, connectorID, generation).Delete(&models.CloudSecret{})
		if res.Error != nil {
			return res.Error
		}
		secretsRemoved = res.RowsAffected

		res = tx.Where(`workspace_id = ? AND connector_id = ? AND last_seen_generation < ?`,
			workspaceID, connectorID, generation).Delete(&models.CloudIdentity{})
		if res.Error != nil {
			return res.Error
		}
		identitiesRemoved = res.RowsAffected
		return nil
	})
	return identitiesRemoved, secretsRemoved, err
}

// ErrCloudIdentityNotFound is returned when no identity matches.
var ErrCloudIdentityNotFound = errors.New("cloud identity not found")

// normaliseAttrs replaces a nil jsonb with an empty object.
//
// The INSERT and the conflict UPDATE disagree about nil otherwise, and only on
// the second scan: GORM omits a zero-valued field on insert so the column
// default applies, but the upsert's DoUpdates assignment writes the nil
// through as NULL, which a NOT NULL jsonb column rejects. The result is a first
// scan that succeeds and every later scan that fails — the worst shape of bug,
// because it passes every test that only scans once.
func normaliseAttrs(attrs *json.RawMessage) {
	if len(*attrs) == 0 {
		*attrs = json.RawMessage("{}")
	}
}
