package repositories

import (
	"errors"
	"strings"
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

	// RegionsForConnector lists the regions this connector holds workloads in
	// -- the regions an earlier scan read compute from. A region deselected
	// since must still get its not_selected stand-in, or its results are never
	// marked stale (§2.14.13).
	RegionsForConnector(workspaceID, connectorID uuid.UUID) ([]string, error)

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
	//
	// ReconcileWorkloads is narrower still: it deletes only within the given
	// scopes, one (runtime kind, region) per compute surface that was REACHED
	// this run. A partial, denied or throttled surface blocks deletion "for
	// that surface" (§1.4) and for nothing else; an empty list deletes nothing.
	ReconcileWorkloads(workspaceID, connectorID uuid.UUID, generation int, scopes []WorkloadScope) (int64, error)
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

// WorkloadScope is the slice of cloud_workload ONE compute surface speaks for:
// its runtime kind in its region ("lambda:eu-west-1" is lambda_function rows
// in eu-west-1). Absence is inferred only inside a scope whose surface was
// reached (§1.4).
type WorkloadScope struct {
	RuntimeKind string
	Region      string
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

	err := runFencedTx(r.db, r.fence, func(tx *gorm.DB) error {
		if err := adoptBareIDRow(tx, w); err != nil {
			return err
		}
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

// adoptBareIDRow folds a row an earlier collector keyed by a BARE id into the
// row this one keys by the ARN, before the upsert below.
//
// Before T3.6 a Bedrock agent whose GetAgent failed, and every AgentCore
// gateway (the role template has never granted GetGateway), were stored under
// the bare agent or gateway id; they are now keyed by the ARN, constructed when
// the detail call fails (§1.3, E7). cloud_workload is unique on (workspace_id,
// native_id), so without this the ARN row is inserted BESIDE the old one and
// Cloud Inventory lists the object twice -- indefinitely for a gateway, whose
// surface stays partial (and so never reconciled) until the stack grants
// GetGateway. The bare row is re-keyed in place, keeping its id and every
// observation that names it; if an ARN row already exists, the bare one is a
// duplicate and is removed. Scoped to this connector, runtime kind and region,
// and to the exact id the ARN ends in, so it can only ever touch the one
// object's old row; a no-op for every other row. The graph needs none of this:
// it already keyed bare-id rows by the constructed ARN (WorkloadKey).
func adoptBareIDRow(tx *gorm.DB, w *models.CloudWorkload) error {
	bare := legacyBareID(w.RuntimeKind, w.NativeID)
	if bare == "" {
		return nil
	}
	if err := tx.Exec(`DELETE FROM cloud_workload
	                    WHERE workspace_id = ? AND connector_id = ? AND runtime_kind = ? AND region = ? AND native_id = ?
	                      AND EXISTS (SELECT 1 FROM cloud_workload WHERE workspace_id = ? AND native_id = ?)`,
		w.WorkspaceID, w.ConnectorID, w.RuntimeKind, w.Region, bare, w.WorkspaceID, w.NativeID).Error; err != nil {
		return err
	}
	return tx.Exec(`UPDATE cloud_workload SET native_id = ?
	                 WHERE workspace_id = ? AND connector_id = ? AND runtime_kind = ? AND region = ? AND native_id = ?`,
		w.NativeID, w.WorkspaceID, w.ConnectorID, w.RuntimeKind, w.Region, bare).Error
}

// legacyBareID is the bare id an earlier collector stored a row of this kind
// under, when nativeID is the ARN it is keyed by now; "" for every kind that
// was always keyed by its ARN (or, like EC2, always by its bare id).
func legacyBareID(runtimeKind, nativeID string) string {
	var marker string
	switch runtimeKind {
	case models.WorkloadBedrockAgent:
		marker = ":agent/"
	case models.WorkloadBedrockAgentCoreGW:
		marker = ":gateway/"
	default:
		return ""
	}
	i := strings.LastIndex(nativeID, marker)
	if !strings.HasPrefix(nativeID, "arn:") || i < 0 {
		return ""
	}
	id := nativeID[i+len(marker):]
	if id == "" || strings.ContainsAny(id, ":/") {
		return ""
	}
	return id
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
//     A gateway's TARGET list is not part of that detail: ListGatewayTargets
//     is its own call, so its answer is taken as the target branch below
//     would take it -- this run's list when it was read in full (the old list
//     and any old targets_incomplete flag are dropped first, or a stale flag
//     would outlive a complete read and an emptied list would never clear),
//     the previous list when it was not.
//   - targets_incomplete (a gateway whose ListGatewayTargets failed): this
//     run's attrs, with the previous target list kept -- an unread target list
//     is unknown, never empty, and a list cut short after its first page is
//     not the gateway's list.
//   - otherwise: replaced wholesale, as before. A successful detail read is
//     the whole truth, and clears the incomplete flags with it.
//
// Both "previous list" arms are jsonb_strip_nulls: with no earlier list
// there is nothing to keep, and this run's (partial, flagged) list stands.
const workloadAttrsMerge = `CASE
	WHEN (EXCLUDED.attrs->>'detail_incomplete')::boolean IS TRUE
		THEN ((cloud_workload.attrs - 'gateway_targets' - 'targets_incomplete') || EXCLUDED.attrs)
			|| CASE WHEN (EXCLUDED.attrs->>'targets_incomplete')::boolean IS TRUE
				THEN jsonb_strip_nulls(jsonb_build_object(
					'gateway_targets', cloud_workload.attrs->'gateway_targets'))
				ELSE '{}'::jsonb END
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

func (r *cloudWorkloadRepository) RegionsForConnector(workspaceID, connectorID uuid.UUID) ([]string, error) {
	var regions []string
	err := r.db.Model(&models.CloudWorkload{}).
		Where("workspace_id = ? AND connector_id = ? AND region <> ''", workspaceID, connectorID).
		Distinct().Order("region").Pluck("region", &regions).Error
	return regions, err
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
// given generation, within the given scopes only: the caller passes one scope
// per compute surface this run REACHED. A row outside every scope -- its
// surface partial, denied or throttled, its region not selected any more
// ("earlier results are kept and marked stale", §2.14.13), or its session
// never created -- is kept, whatever its generation.
func (r *cloudWorkloadRepository) ReconcileWorkloads(
	workspaceID, connectorID uuid.UUID, generation int, scopes []WorkloadScope,
) (int64, error) {
	if len(scopes) == 0 {
		return 0, nil // nothing was reached, so nothing can be absent
	}
	pairs := make([][]interface{}, 0, len(scopes))
	for _, sc := range scopes {
		pairs = append(pairs, []interface{}{sc.RuntimeKind, sc.Region})
	}
	var removed int64
	err := runFencedTx(r.db, r.fence, func(tx *gorm.DB) error {
		res := tx.Where(`workspace_id = ? AND connector_id = ? AND last_seen_generation < ?
		                 AND (runtime_kind, region) IN ?`,
			workspaceID, connectorID, generation, pairs).Delete(&models.CloudWorkload{})
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
	// Two independent statements, never one builder reused across a Count and
	// a Find: GORM mutates a chained statement in place.
	scoped := func() *gorm.DB {
		return r.db.Model(&models.CloudIdentity{}).
			Where("workspace_id = ? AND connector_id = ?", workspaceID, connectorID)
	}
	var total int64
	if err := scoped().Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var out []models.CloudIdentity
	if err := scoped().Order(`native_id COLLATE "C", id`).Limit(clampLimit(limit)).Find(&out).Error; err != nil {
		return nil, 0, err
	}
	return out, total, nil
}
