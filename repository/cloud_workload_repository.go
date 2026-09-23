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

	// ReconcileWorkloads and ReconcileUsage are ReconcileGeneration's two
	// halves, gated SEPARATELY (T3.7): the compute surfaces license deleting
	// workloads, Access Advisor licenses deleting usage. One gate for both let
	// an activity read that is permanently partial above its identity cap veto
	// workload reconciliation forever -- the connector-wide veto §1.3 removes
	// for unoffered regions, in another costume.
	ReconcileWorkloads(workspaceID, connectorID uuid.UUID, generation int) (int64, error)
	ReconcileUsage(workspaceID, connectorID uuid.UUID, generation int) (int64, error)

	// CountWorkloads counts a connector's rows of one runtime kind in one
	// region, whatever their generation: whether an earlier scan ever found
	// that service there.
	CountWorkloads(workspaceID, connectorID uuid.UUID, runtimeKind, region string) (int64, error)

	// ActivitySample is the connector's identities whose activity (cloud_usage)
	// one scan reads: the first limit by ARN, byte order, and the total.
	ActivitySample(workspaceID, connectorID uuid.UUID, limit int) ([]models.CloudIdentity, int64, error)

	// Fenced returns a view whose mutations refuse to commit unless the
	// given run is still owned by the caller (§2.10A). Reads are unaffected.
	Fenced(f ScanFence) CloudWorkloadRepository
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

type cloudWorkloadRepository struct {
	db    *gorm.DB
	fence *ScanFence
}

// NewCloudWorkloadRepository constructs the repository.
func NewCloudWorkloadRepository(db *gorm.DB) CloudWorkloadRepository {
	return &cloudWorkloadRepository{db: db}
}

func (r *cloudWorkloadRepository) Fenced(f ScanFence) CloudWorkloadRepository {
	copy := *r
	copy.fence = &f
	return &copy
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

	err := runFenced(r.db, r.fence, func(tx *gorm.DB) error {
		return tx.Clauses(
			clause.OnConflict{
				Columns: []clause.Column{{Name: "workspace_id"}, {Name: "native_id"}},
				DoUpdates: clause.Assignments(map[string]interface{}{
					"connector_id": w.ConnectorID,
					// identity_id IS refreshed: a Lambda's execution role can be
					// changed in place, and a workload that became unattributed
					// (role deleted, or IAM denied this run) must stop claiming the
					// old one.
					//
					// EXCEPT when the detail call that names the role FAILED this
					// run (attrs.detail_incomplete, T3.6): then the role is
					// unknown, not gone, and the previous attribution stands --
					// "attrs merge, never blank" (§1.3), and D-53's "left as the
					// previous row had it". Decided from EXCLUDED in the same
					// statement, so there is no read-then-write race.
					"identity_id":          gorm.Expr(workloadIdentityMerge),
					"runtime_kind":         w.RuntimeKind,
					"name":                 w.Name,
					"region":               w.Region,
					"attrs":                gorm.Expr(workloadAttrsMerge),
					"last_seen_generation": w.LastSeenGeneration,
					"last_seen_at":         now,
					"row_updated_at":       now,
				}),
			},
			clause.Returning{},
		).Create(w).Error
	})
	if err != nil {
		return nil, false, err
	}
	return w, w.ID == proposed, nil
}

// workloadIdentityMerge keeps the previous attribution when this run's detail
// call failed; see UpsertWorkload.
const workloadIdentityMerge = `CASE WHEN (EXCLUDED.attrs->>'detail_incomplete')::boolean IS TRUE
	THEN cloud_workload.identity_id ELSE EXCLUDED.identity_id END`

// workloadAttrsMerge is the attrs half of UpsertWorkload's conflict update.
//
//   - detail_incomplete: the previous attrs, with this run's listed values
//     laid over them. jsonb || takes the right side's keys, and the collector
//     omits every empty field, so only what the listing actually returned
//     (status, the detail_incomplete flag and its error) replaces anything;
//     the role, model and env-var names the last good read recorded survive.
//   - targets_incomplete (a gateway whose ListGatewayTargets failed): this
//     run's attrs, with the previous target list kept -- an unread target list
//     is unknown, never empty.
//   - otherwise: replaced wholesale, as before. A successful detail read is
//     the whole truth, and clears the incomplete flags with it.
const workloadAttrsMerge = `CASE
	WHEN (EXCLUDED.attrs->>'detail_incomplete')::boolean IS TRUE
		THEN cloud_workload.attrs || EXCLUDED.attrs
	WHEN (EXCLUDED.attrs->>'targets_incomplete')::boolean IS TRUE
		THEN EXCLUDED.attrs || jsonb_strip_nulls(jsonb_build_object(
			'gateway_targets', cloud_workload.attrs->'gateway_targets'))
	ELSE EXCLUDED.attrs END`

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

	err := runFenced(r.db, r.fence, func(tx *gorm.DB) error {
		return tx.Clauses(
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
	})
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
	if err := q.Order("runtime_kind, name, id").Limit(clampLimit(f.Limit)).Offset(f.Offset).Find(&out).Error; err != nil {
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
	if err := q.Order("last_used_at ASC NULLS FIRST, service, id").Limit(clampLimit(f.Limit)).Offset(f.Offset).Find(&out).Error; err != nil {
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
	err := runFencedTx(r.db, r.fence, func(tx *gorm.DB) error {
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

func (r *cloudWorkloadRepository) CountWorkloads(
	workspaceID, connectorID uuid.UUID, runtimeKind, region string,
) (int64, error) {
	var n int64
	err := r.db.Model(&models.CloudWorkload{}).
		Where("workspace_id = ? AND connector_id = ? AND runtime_kind = ? AND region = ?",
			workspaceID, connectorID, runtimeKind, region).
		Count(&n).Error
	return n, err
}

// ReconcileWorkloads removes the workloads this connector did not see in the
// given generation. The caller invokes it only when every compute surface was
// reached (or deliberately not read: not_selected, unsupported).
func (r *cloudWorkloadRepository) ReconcileWorkloads(
	workspaceID, connectorID uuid.UUID, generation int,
) (int64, error) {
	var removed int64
	err := runFencedTx(r.db, r.fence, func(tx *gorm.DB) error {
		res := tx.Where(`workspace_id = ? AND connector_id = ? AND last_seen_generation < ?`,
			workspaceID, connectorID, generation).Delete(&models.CloudWorkload{})
		removed = res.RowsAffected
		return res.Error
	})
	return removed, err
}

// ReconcileUsage removes the usage rows this connector did not see in the
// given generation. The caller invokes it only when activity was reached.
func (r *cloudWorkloadRepository) ReconcileUsage(
	workspaceID, connectorID uuid.UUID, generation int,
) (int64, error) {
	var removed int64
	err := runFencedTx(r.db, r.fence, func(tx *gorm.DB) error {
		res := tx.Where(`workspace_id = ? AND connector_id = ? AND last_seen_generation < ?`,
			workspaceID, connectorID, generation).Delete(&models.CloudUsage{})
		removed = res.RowsAffected
		return res.Error
	})
	return removed, err
}

// ActivitySample returns the identities one scan reads Access Advisor for: at
// most limit of the connector's identities, in BYTE order of their ARN
// (native_id COLLATE "C", then id), and how many the connector holds.
//
// Deterministic by ARN (D-86), so the sample a capped scan read is one a
// reader can name: the scanner stamps the last ARN it read on the activity
// coverage (SurfaceCoverage.CappedAfter), and an identity that sorts after it
// was not sampled. "C" collation because it is Go's string order too, so that
// comparison means the same thing in SQL and in code; the default collation
// would order case and punctuation by locale.
func (r *cloudWorkloadRepository) ActivitySample(
	workspaceID, connectorID uuid.UUID, limit int,
) ([]models.CloudIdentity, int64, error) {
	q := r.db.Model(&models.CloudIdentity{}).
		Where("workspace_id = ? AND connector_id = ?", workspaceID, connectorID)
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var out []models.CloudIdentity
	if err := q.Order(`native_id COLLATE "C", id`).Limit(clampLimit(limit)).Find(&out).Error; err != nil {
		return nil, 0, err
	}
	return out, total, nil
}
