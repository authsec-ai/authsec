package repositories

import (
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// CloudObservationRepository reads evidence: why a cloud_* row exists, or --
// for a subject-less fact like an AgentCore Workload Identity -- what was
// observed even though nothing in inventory names it.
//
// Read-only on purpose. Every observation is written exactly once, by
// ObservationWriter, at scan time; nothing about serving it back to a caller
// needs an Upsert or a ReconcileGeneration, and adding one would invite a
// write path this table's evidence guarantee (see migration 022) does not
// need and should not have.
type CloudObservationRepository interface {
	// ListObservations returns the observations one subject or one source API
	// has recorded, newest first -- the order the "why do you believe this"
	// question is asked in, and the order migration 022's own per-subject
	// indexes are built for.
	ListObservations(workspaceID uuid.UUID, f CloudObservationFilter) ([]models.CloudObservation, int64, error)
}

// CloudObservationFilter narrows a listing. At most one of the four subject
// fields is normally set -- an observation has at most one subject itself,
// per the relaxed check migration 024 introduced -- but nothing here
// enforces that; a caller asking for two subjects at once just gets rows
// matching either, same as any other AND-of-ORs would read confusingly, so
// callers are expected to pass one.
type CloudObservationFilter struct {
	IdentityID   *uuid.UUID
	PermissionID *uuid.UUID
	ResourceID   *uuid.UUID
	WorkloadID   *uuid.UUID
	// SourceAPI narrows to one AWS call, e.g. "cloudtrail:LookupEvents" -- the
	// filter every one of items 2-4 in Akash's review needs: CloudTrail
	// activity, credential-report facts and resource-policy denies are told
	// apart by which call produced them, not by anything else on the row.
	SourceAPI string
	Limit     int
	Offset    int
}

type cloudObservationRepository struct{ db *gorm.DB }

// NewCloudObservationRepository constructs the repository.
func NewCloudObservationRepository(db *gorm.DB) CloudObservationRepository {
	return &cloudObservationRepository{db: db}
}

func (r *cloudObservationRepository) ListObservations(
	workspaceID uuid.UUID, f CloudObservationFilter,
) ([]models.CloudObservation, int64, error) {
	q := r.db.Model(&models.CloudObservation{}).Where("workspace_id = ?", workspaceID)
	if f.IdentityID != nil {
		q = q.Where("identity_id = ?", *f.IdentityID)
	}
	if f.PermissionID != nil {
		q = q.Where("permission_id = ?", *f.PermissionID)
	}
	if f.ResourceID != nil {
		q = q.Where("resource_id = ?", *f.ResourceID)
	}
	if f.WorkloadID != nil {
		q = q.Where("workload_id = ?", *f.WorkloadID)
	}
	if f.SourceAPI != "" {
		q = q.Where("source_api = ?", f.SourceAPI)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var out []models.CloudObservation
	// Ends in `id`, per the rule stated on ListIdentities: offset paging is only
	// coherent over a TOTAL order, and observed_at alone is not one.
	//
	// The ties are real, not theoretical. Most Record calls pass their own
	// time.Now(), which rarely collides -- but CloudTrail events are stamped
	// with e.EventTime, the event's own timestamp, which AWS reports to the
	// second. A busy account produces many events per second, and CloudTrail is
	// both the highest-volume source here and the one the Events tab pages
	// through. Without a tiebreaker, page two can repeat a row page one already
	// showed and omit one it never did, and the console's "newest observation
	// per key" dedupe relies on this order being stable.
	//
	// `id DESC` rather than ASC to match the DESC direction of the four
	// (workspace_id, <subject>, observed_at DESC) indexes, so the requested
	// order stays on the same physical direction those indexes already provide.
	if err := q.Order("observed_at DESC, id DESC").Limit(clampLimit(f.Limit)).Offset(f.Offset).
		Find(&out).Error; err != nil {
		return nil, 0, err
	}
	return out, total, nil
}
