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

// ErrCloudConnectorNotFound is returned when no connector matches the
// workspace and id. Kept distinct from gorm.ErrRecordNotFound so a caller can
// map it to a 404 without importing GORM.
var ErrCloudConnectorNotFound = errors.New("cloud connector not found")

// CloudConnectorRepository provides workspace-scoped storage for onboarded
// cloud scopes. Every method takes workspaceID and every query filters on it:
// a connector is the address of a customer's cloud account, and a missing
// tenant predicate here would be a cross-tenant read of exactly the thing that
// must never leak.
type CloudConnectorRepository interface {
	// Upsert records an onboarded scope, keyed on
	// (workspace_id, provider, scope_id). Re-onboarding an account already
	// connected UPDATES that row. Reports whether the row was newly created —
	// which the onboarding service needs, because it decides whether a failure
	// afterwards may roll the stored secret back.
	Upsert(c *models.CloudConnector) (stored *models.CloudConnector, created bool, err error)

	Get(workspaceID, id uuid.UUID) (*models.CloudConnector, error)
	GetByScope(workspaceID uuid.UUID, provider, scopeID string) (*models.CloudConnector, error)
	List(workspaceID uuid.UUID, provider string) ([]models.CloudConnector, error)

	// MarkVerified records a successful proof of the connection: status active,
	// verified_at now, last_error cleared, and attrs replaced.
	//
	// attrs is raw JSON rather than a provider struct on purpose — this
	// repository serves all three clouds, and typing it to the AWS shape here
	// would make the Azure and GCP connectors either cast around it or fork the
	// method. Shaping attrs is the calling service's job.
	MarkVerified(workspaceID, id uuid.UUID, attrs json.RawMessage) (*models.CloudConnector, error)

	// MarkError records that the connection could not be used, and why.
	//
	// It deliberately does NOT touch verified_at: the last time the connection
	// genuinely worked is evidence, and overwriting it would erase the only
	// thing that distinguishes "broken since this morning" from "never worked".
	MarkError(workspaceID, id uuid.UUID, reason string) (*models.CloudConnector, error)

	// Delete removes a connector and returns the auth_ref that should now be
	// purged from the secrets store, or "" when there was nothing stored.
	//
	// The purge is the CALLER's job, not this method's: the repository has no
	// secrets client, and doing it here would put a network call inside a
	// database transaction.
	Delete(workspaceID, id uuid.UUID) (authRef string, err error)
}

type cloudConnectorRepository struct{ db *gorm.DB }

// NewCloudConnectorRepository constructs the repository.
func NewCloudConnectorRepository(db *gorm.DB) CloudConnectorRepository {
	return &cloudConnectorRepository{db: db}
}

func (r *cloudConnectorRepository) Upsert(c *models.CloudConnector) (*models.CloudConnector, bool, error) {
	if c.WorkspaceID == uuid.Nil {
		return nil, false, errors.New("workspace_id is required")
	}
	if c.Provider == "" || c.ScopeID == "" {
		return nil, false, errors.New("provider and scope_id are required")
	}
	// The id is minted here rather than left to the column default, because it is
	// the only way to tell an insert from an update below.
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	proposedID := c.ID

	// scan_generation and coverage are absent on purpose. Re-onboarding an
	// account already being scanned must not reset its reconciliation counter or
	// erase what the last scan could and could not read — that would make every
	// existing row look stale and turn a re-onboard into a silent inventory wipe.
	//
	// created_by and created_at are absent for the same class of reason: the row
	// records who first connected the account, not who last touched it.
	assignments := map[string]interface{}{
		"scope_kind":      c.ScopeKind,
		"parent_scope_id": c.ParentScopeID,
		"auth_ref":        c.AuthRef,
		"status":          c.Status,
		"attrs":           c.Attrs,
		"verified_at":     c.VerifiedAt,
		"last_error":      c.LastError,
		"updated_at":      time.Now(),
	}

	err := r.db.Clauses(
		clause.OnConflict{
			Columns: []clause.Column{
				{Name: "workspace_id"}, {Name: "provider"}, {Name: "scope_id"},
			},
			DoUpdates: clause.Assignments(assignments),
		},
		clause.Returning{},
	).Create(c).Error
	if err != nil {
		return nil, false, err
	}
	// RETURNING hands back the row that actually ended up in the table. Its id
	// differs from the one we proposed exactly when the conflict clause updated
	// an existing row — which is the only reliable signal available here, since
	// RowsAffected is 1 for both an insert and an upsert-update.
	created := c.ID == proposedID
	return c, created, nil
}

func (r *cloudConnectorRepository) Get(workspaceID, id uuid.UUID) (*models.CloudConnector, error) {
	var c models.CloudConnector
	err := r.db.Where("workspace_id = ? AND id = ?", workspaceID, id).First(&c).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrCloudConnectorNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *cloudConnectorRepository) GetByScope(workspaceID uuid.UUID, provider, scopeID string) (*models.CloudConnector, error) {
	var c models.CloudConnector
	err := r.db.Where("workspace_id = ? AND provider = ? AND scope_id = ?",
		workspaceID, provider, scopeID).First(&c).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrCloudConnectorNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *cloudConnectorRepository) List(workspaceID uuid.UUID, provider string) ([]models.CloudConnector, error) {
	q := r.db.Where("workspace_id = ?", workspaceID)
	if provider != "" {
		q = q.Where("provider = ?", provider)
	}
	var out []models.CloudConnector
	if err := q.Order("provider, scope_id").Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (r *cloudConnectorRepository) MarkVerified(workspaceID, id uuid.UUID, attrs json.RawMessage) (*models.CloudConnector, error) {
	now := time.Now()
	updates := map[string]interface{}{
		"status":      models.CloudConnectorActive,
		"verified_at": now,
		"last_error":  "",
		"updated_at":  now,
	}
	// An empty blob leaves attrs alone rather than erasing it. A verification is
	// evidence that the connection works; it is not a licence to forget which
	// role and regions it was configured with.
	if len(attrs) > 0 {
		updates["attrs"] = attrs
	}
	err := r.db.Model(&models.CloudConnector{}).
		Where("workspace_id = ? AND id = ?", workspaceID, id).
		Updates(updates).Error
	if err != nil {
		return nil, err
	}
	return r.Get(workspaceID, id)
}

func (r *cloudConnectorRepository) MarkError(workspaceID, id uuid.UUID, reason string) (*models.CloudConnector, error) {
	if reason == "" {
		// The CHECK constraint refuses status='error' with an empty reason, and a
		// constraint violation here would be a confusing 500. Say what happened.
		reason = "connection failed; no reason reported"
	}
	err := r.db.Model(&models.CloudConnector{}).
		Where("workspace_id = ? AND id = ?", workspaceID, id).
		Updates(map[string]interface{}{
			"status":     models.CloudConnectorError,
			"last_error": reason,
			"updated_at": time.Now(),
		}).Error
	if err != nil {
		return nil, err
	}
	return r.Get(workspaceID, id)
}

func (r *cloudConnectorRepository) Delete(workspaceID, id uuid.UUID) (string, error) {
	c, err := r.Get(workspaceID, id)
	if err != nil {
		return "", err
	}
	if err := r.db.Where("workspace_id = ? AND id = ?", workspaceID, id).
		Delete(&models.CloudConnector{}).Error; err != nil {
		return "", err
	}
	return c.AuthRef, nil
}
