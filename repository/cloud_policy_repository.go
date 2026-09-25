package repositories

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/authsec-ai/authsec/models"
)

// CloudPolicyRepository writes the AWS collection model of migration 035:
// policies as objects, their attachments, and group memberships.
//
// Every write and every delete is fenced to the run that owns it, exactly like
// the identity and permission repositories (§2.10A): a superseded worker's
// writes are refused, and so are its deletes.
type CloudPolicyRepository interface {
	// UpsertPolicy records one policy as THIS connector read it, keyed by
	// (connector_id, native_id). Returns the stored row, with the id of the
	// surviving row after a conflict.
	UpsertPolicy(p *models.CloudPolicy) (*models.CloudPolicy, error)
	// UpsertAttachment records policy -> principal (attached | inline | boundary).
	UpsertAttachment(a *models.CloudPolicyAttachment) error
	// UpsertMembership records user -> group.
	UpsertMembership(m *models.CloudGroupMembership) error

	// ReconcilePolicies deletes this connector's policies and attachments that
	// the run at `generation` did not see. Attachments go with their policy
	// through the FK cascade, and on their own when only the attachment went.
	ReconcilePolicies(workspaceID, connectorID uuid.UUID, generation int) (policies, attachments int64, err error)
	// ReconcileMemberships deletes memberships the run did not see.
	ReconcileMemberships(workspaceID, connectorID uuid.UUID, generation int) (int64, error)

	Fenced(f ScanFence) CloudPolicyRepository
}

type cloudPolicyRepository struct {
	db    *gorm.DB
	fence *ScanFence
}

func NewCloudPolicyRepository(db *gorm.DB) CloudPolicyRepository {
	return &cloudPolicyRepository{db: db}
}

func (r *cloudPolicyRepository) Fenced(f ScanFence) CloudPolicyRepository {
	copy := *r
	copy.fence = &f
	return &copy
}

func (r *cloudPolicyRepository) UpsertPolicy(p *models.CloudPolicy) (*models.CloudPolicy, error) {
	now := time.Now()
	p.LastSeenAt = now
	if p.FirstSeenAt.IsZero() {
		p.FirstSeenAt = now
	}
	err := runFenced(r.db, r.fence, func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "connector_id"}, {Name: "native_id"}},
			// Named columns only. first_seen_at is never advanced.
			DoUpdates: clause.AssignmentColumns([]string{
				"policy_kind", "holder_identity_id", "name", "policy_id",
				"aws_managed", "version_id", "document", "document_hash",
				"document_error", "last_seen_generation", "last_seen_at",
			}),
		}).Create(p).Error; err != nil {
			return err
		}
		// The SURVIVING row's id: after a conflict the struct still holds the
		// id GORM generated, and attachments written against it would point at
		// nothing.
		return tx.Raw(`SELECT id FROM cloud_policy WHERE connector_id = ? AND native_id = ?`,
			p.ConnectorID, p.NativeID).Row().Scan(&p.ID)
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (r *cloudPolicyRepository) UpsertAttachment(a *models.CloudPolicyAttachment) error {
	now := time.Now()
	a.LastSeenAt = now
	if a.FirstSeenAt.IsZero() {
		a.FirstSeenAt = now
	}
	return runFenced(r.db, r.fence, func(tx *gorm.DB) error {
		return tx.Clauses(clause.OnConflict{
			Columns: []clause.Column{
				{Name: "policy_row_id"}, {Name: "principal_identity_id"}, {Name: "attachment_kind"},
			},
			DoUpdates: clause.AssignmentColumns([]string{"last_seen_generation", "last_seen_at"}),
		}).Create(a).Error
	})
}

func (r *cloudPolicyRepository) UpsertMembership(m *models.CloudGroupMembership) error {
	now := time.Now()
	m.LastSeenAt = now
	if m.FirstSeenAt.IsZero() {
		m.FirstSeenAt = now
	}
	return runFenced(r.db, r.fence, func(tx *gorm.DB) error {
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_identity_id"}, {Name: "group_identity_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"last_seen_generation", "last_seen_at"}),
		}).Create(m).Error
	})
}

func (r *cloudPolicyRepository) ReconcilePolicies(
	workspaceID, connectorID uuid.UUID, generation int,
) (int64, int64, error) {
	var policies, attachments int64
	err := runFencedTx(r.db, r.fence, func(tx *gorm.DB) error {
		res := tx.Where(`workspace_id = ? AND connector_id = ? AND last_seen_generation < ?`,
			workspaceID, connectorID, generation).Delete(&models.CloudPolicyAttachment{})
		if res.Error != nil {
			return res.Error
		}
		attachments = res.RowsAffected
		res = tx.Where(`workspace_id = ? AND connector_id = ? AND last_seen_generation < ?`,
			workspaceID, connectorID, generation).Delete(&models.CloudPolicy{})
		if res.Error != nil {
			return res.Error
		}
		policies = res.RowsAffected
		return nil
	})
	return policies, attachments, err
}

func (r *cloudPolicyRepository) ReconcileMemberships(
	workspaceID, connectorID uuid.UUID, generation int,
) (int64, error) {
	var n int64
	err := runFencedTx(r.db, r.fence, func(tx *gorm.DB) error {
		res := tx.Where(`workspace_id = ? AND connector_id = ? AND last_seen_generation < ?`,
			workspaceID, connectorID, generation).Delete(&models.CloudGroupMembership{})
		n = res.RowsAffected
		return res.Error
	})
	return n, err
}
