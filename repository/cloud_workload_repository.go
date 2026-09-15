package repositories

import (
	"errors"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// CloudWorkloadRepository stores the compute that runs as a cloud identity, and
// the evidence that an identity actually exercised a service: cloud_workload
// and cloud_usage.
//
// Both tables are workspace-scoped and generation-reconciled, identical in
// shape to CloudIdentityRepository and CloudPermissionRepository, and for the
// same reasons.
type CloudWorkloadRepository interface {
	// UpsertWorkload records one workload, keyed on (workspace_id, native_id).
	// A re-scan of an unchanged function updates the same row.
	UpsertWorkload(w *models.CloudWorkload) (stored *models.CloudWorkload, created bool, err error)

	// UpsertUsage records one identity's activity against one service, keyed on
	// (identity_id, service, source).
	UpsertUsage(u *models.CloudUsage) (stored *models.CloudUsage, created bool, err error)

	ListWorkloads(workspaceID uuid.UUID, f CloudWorkloadFilter) ([]models.CloudWorkload, int64, error)
	ListUsage(workspaceID uuid.UUID, f CloudWorkloadFilter) ([]models.CloudUsage, int64, error)

	// CountsForConnector reports how many rows of each kind a connector holds,
	// for the scan report.
	CountsForConnector(workspaceID, connectorID uuid.UUID) (workloads, usage int64, err error)

	// ReconcileGeneration removes rows this connector did NOT see in the given
	// generation. Same contract as every other ReconcileGeneration here: the
	// caller must only invoke it after a scan in which every surface the table
	// depends on was actually reached.
	ReconcileGeneration(workspaceID, connectorID uuid.UUID, generation int) (workloadsRemoved, usageRemoved int64, err error)
}

// CloudWorkloadFilter narrows a workload or usage listing. ConnectorID scopes
// to one connected AWS account -- without it a workspace with several
// connectors returns every account's workloads and usage mixed together.
type CloudWorkloadFilter struct {
	IdentityID  *uuid.UUID
	ConnectorID *uuid.UUID
	Limit       int
	Offset      int
}

type cloudWorkloadRepository struct{ db *gorm.DB }

// NewCloudWorkloadRepository constructs the repository.
func NewCloudWorkloadRepository(db *gorm.DB) CloudWorkloadRepository {
	return &cloudWorkloadRepository{db: db}
}

func (r *cloudWorkloadRepository) UpsertWorkload(w *models.CloudWorkload) (*models.CloudWorkload, bool, error) {
	if w.WorkspaceID == uuid.Nil || w.ConnectorID == uuid.Nil {
		return nil, false, errors.New("workspace_id and connector_id are required")
	}
	if w.NativeID == "" || w.RuntimeKind == "" {
		return nil, false, errors.New("native_id and runtime_kind are required")
	}
	if w.ID == uuid.Nil {
		w.ID = uuid.New()
	}
	normaliseAttrs(&w.Attrs)
	proposed := w.ID
	now := time.Now()

	err := r.db.Clauses(
		clause.OnConflict{
			Columns: []clause.Column{{Name: "workspace_id"}, {Name: "native_id"}},
			DoUpdates: clause.Assignments(map[string]interface{}{
				"connector_id": w.ConnectorID,
				// identity_id IS refreshed: a Lambda's execution role can be
				// changed in place, and a workload that became unattributed
				// (role deleted, or IAM denied this run) must stop claiming the
				// old one.
				"identity_id":          w.IdentityID,
				"runtime_kind":         w.RuntimeKind,
				"name":                 w.Name,
				"region":               w.Region,
				"attrs":                w.Attrs,
				"last_seen_generation": w.LastSeenGeneration,
				"last_seen_at":         now,
				"row_updated_at":       now,
			}),
		},
		clause.Returning{},
	).Create(w).Error
	if err != nil {
		return nil, false, err
	}
	return w, w.ID == proposed, nil
}

func (r *cloudWorkloadRepository) UpsertUsage(u *models.CloudUsage) (*models.CloudUsage, bool, error) {
	if u.WorkspaceID == uuid.Nil || u.ConnectorID == uuid.Nil || u.IdentityID == uuid.Nil {
		return nil, false, errors.New("workspace_id, connector_id and identity_id are required")
	}
	if u.Service == "" {
		return nil, false, errors.New("service is required")
	}
	if u.Source == "" {
		u.Source = models.UsageSourceServiceLastAccessed
	}
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	normaliseAttrs(&u.Attrs)
	proposed := u.ID
	now := time.Now()

	err := r.db.Clauses(
		clause.OnConflict{
			Columns: []clause.Column{
				{Name: "identity_id"}, {Name: "service"}, {Name: "source"},
			},
			DoUpdates: clause.Assignments(map[string]interface{}{
				"connector_id": u.ConnectorID,
				// last_used_at IS refreshed, including back to NULL. AWS's
				// tracking window rolls, so a service that ages out of it
				// genuinely becomes "never accessed in the window" again, and
				// pinning the old date would report activity AWS no longer
				// claims.
				"last_used_at":         u.LastUsedAt,
				"generated_at":         u.GeneratedAt,
				"attrs":                u.Attrs,
				"last_seen_generation": u.LastSeenGeneration,
				"last_seen_at":         now,
				"row_updated_at":       now,
			}),
		},
		clause.Returning{},
	).Create(u).Error
	if err != nil {
		return nil, false, err
	}
	return u, u.ID == proposed, nil
}

func (r *cloudWorkloadRepository) ListWorkloads(workspaceID uuid.UUID, f CloudWorkloadFilter) ([]models.CloudWorkload, int64, error) {
	q := r.db.Model(&models.CloudWorkload{}).Where("workspace_id = ?", workspaceID)
	if f.IdentityID != nil {
		q = q.Where("identity_id = ?", *f.IdentityID)
	}
	if f.ConnectorID != nil {
		q = q.Where("connector_id = ?", *f.ConnectorID)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var out []models.CloudWorkload
	if err := q.Order("runtime_kind, name").Limit(clampLimit(f.Limit)).Offset(f.Offset).Find(&out).Error; err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func (r *cloudWorkloadRepository) ListUsage(workspaceID uuid.UUID, f CloudWorkloadFilter) ([]models.CloudUsage, int64, error) {
	q := r.db.Model(&models.CloudUsage{}).Where("workspace_id = ?", workspaceID)
	if f.IdentityID != nil {
		q = q.Where("identity_id = ?", *f.IdentityID)
	}
	if f.ConnectorID != nil {
		q = q.Where("connector_id = ?", *f.ConnectorID)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var out []models.CloudUsage
	// Never-accessed first: a NULL last_used_at is the row worth acting on, and
	// NULLS FIRST states that rather than leaving it to the default.
	if err := q.Order("last_used_at ASC NULLS FIRST, service").Limit(clampLimit(f.Limit)).Offset(f.Offset).Find(&out).Error; err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func (r *cloudWorkloadRepository) CountsForConnector(workspaceID, connectorID uuid.UUID) (int64, int64, error) {
	var workloads, usage int64
	if err := r.db.Model(&models.CloudWorkload{}).
		Where("workspace_id = ? AND connector_id = ?", workspaceID, connectorID).
		Count(&workloads).Error; err != nil {
		return 0, 0, err
	}
	if err := r.db.Model(&models.CloudUsage{}).
		Where("workspace_id = ? AND connector_id = ?", workspaceID, connectorID).
		Count(&usage).Error; err != nil {
		return 0, 0, err
	}
	return workloads, usage, nil
}

// ReconcileGeneration removes what this connector did not see. Usage before
// workloads only for tidiness -- neither references the other, so there is no
// foreign-key ordering to respect here, unlike cloud_permission and
// cloud_resource.
func (r *cloudWorkloadRepository) ReconcileGeneration(
	workspaceID, connectorID uuid.UUID, generation int,
) (int64, int64, error) {

	var workloadsRemoved, usageRemoved int64
	err := r.db.Transaction(func(tx *gorm.DB) error {
		res := tx.Where(`workspace_id = ? AND connector_id = ? AND last_seen_generation < ?`,
			workspaceID, connectorID, generation).Delete(&models.CloudUsage{})
		if res.Error != nil {
			return res.Error
		}
		usageRemoved = res.RowsAffected

		res = tx.Where(`workspace_id = ? AND connector_id = ? AND last_seen_generation < ?`,
			workspaceID, connectorID, generation).Delete(&models.CloudWorkload{})
		if res.Error != nil {
			return res.Error
		}
		workloadsRemoved = res.RowsAffected
		return nil
	})
	return workloadsRemoved, usageRemoved, err
}
