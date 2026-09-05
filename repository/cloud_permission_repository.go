package repositories

import (
	"errors"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// CloudPermissionRepository stores who may assume an identity, what it is
// granted, and what those grants point at: cloud_assume_edge, cloud_permission
// and cloud_resource.
//
// Every method is workspace-scoped, same as CloudIdentityRepository and for the
// same reason.
type CloudPermissionRepository interface {
	// UpsertAssumeEdge records one principal, keyed on
	// (identity_id, subject_kind, subject). A repeat scan of an unchanged trust
	// policy updates the same row.
	UpsertAssumeEdge(e *models.CloudAssumeEdge) (stored *models.CloudAssumeEdge, created bool, err error)

	// UpsertResource records one resource, keyed on (workspace_id, native_id).
	// Called only when a permission statement actually names an ARN -- never
	// speculatively.
	UpsertResource(r *models.CloudResource) (stored *models.CloudResource, created bool, err error)

	// UpsertPermission records one grant, keyed on
	// (identity_id, native_id, resource_id).
	UpsertPermission(p *models.CloudPermission) (stored *models.CloudPermission, created bool, err error)

	ListAssumeEdges(workspaceID uuid.UUID, identityID *uuid.UUID) ([]models.CloudAssumeEdge, error)
	ListPermissions(workspaceID uuid.UUID, identityID *uuid.UUID) ([]models.CloudPermission, error)
	ListResources(workspaceID uuid.UUID, connectorID *uuid.UUID) ([]models.CloudResource, error)

	// CountsForConnector reports how many rows of each kind a connector
	// currently holds, for the scan report.
	CountsForConnector(workspaceID, connectorID uuid.UUID) (edges, permissions, resources int64, err error)

	// ReconcileGeneration removes rows this connector did NOT see in the given
	// generation. Same contract as CloudIdentityRepository.ReconcileGeneration:
	// the caller must only invoke this after a scan in which every surface this
	// table depends on was reached.
	ReconcileGeneration(workspaceID, connectorID uuid.UUID, generation int) (edgesRemoved, permissionsRemoved, resourcesRemoved int64, err error)
}

type cloudPermissionRepository struct{ db *gorm.DB }

// NewCloudPermissionRepository constructs the repository.
func NewCloudPermissionRepository(db *gorm.DB) CloudPermissionRepository {
	return &cloudPermissionRepository{db: db}
}

func (r *cloudPermissionRepository) UpsertAssumeEdge(e *models.CloudAssumeEdge) (*models.CloudAssumeEdge, bool, error) {
	if e.WorkspaceID == uuid.Nil || e.ConnectorID == uuid.Nil || e.IdentityID == uuid.Nil {
		return nil, false, errors.New("workspace_id, connector_id and identity_id are required")
	}
	if e.SubjectKind == "" || e.Subject == "" {
		return nil, false, errors.New("subject_kind and subject are required")
	}
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	normaliseAttrs(&e.Attrs)
	proposed := e.ID
	now := time.Now()

	err := r.db.Clauses(
		clause.OnConflict{
			Columns: []clause.Column{{Name: "identity_id"}, {Name: "subject_kind"}, {Name: "subject"}},
			DoUpdates: clause.Assignments(map[string]interface{}{
				"connector_id":         e.ConnectorID,
				"issuer":               e.Issuer,
				"mechanism":            e.Mechanism,
				"k8s_ref":              e.K8sRef,
				"attrs":                e.Attrs,
				"last_seen_generation": e.LastSeenGeneration,
				"last_seen_at":         now,
				"row_updated_at":       now,
			}),
			DoNothing: false,
		},
		clause.Returning{},
	).Create(e).Error
	if err != nil {
		return nil, false, err
	}
	return e, e.ID == proposed, nil
}

func (r *cloudPermissionRepository) UpsertResource(res *models.CloudResource) (*models.CloudResource, bool, error) {
	if res.WorkspaceID == uuid.Nil || res.ConnectorID == uuid.Nil {
		return nil, false, errors.New("workspace_id and connector_id are required")
	}
	if res.NativeID == "" || res.Kind == "" {
		return nil, false, errors.New("native_id and kind are required")
	}
	if res.ID == uuid.Nil {
		res.ID = uuid.New()
	}
	proposed := res.ID
	now := time.Now()

	err := r.db.Clauses(
		clause.OnConflict{
			Columns: []clause.Column{{Name: "workspace_id"}, {Name: "native_id"}},
			DoUpdates: clause.Assignments(map[string]interface{}{
				"connector_id": res.ConnectorID,
				"kind":         res.Kind,
				// name IS refreshed: a resource renamed in place (e.g. an S3
				// bucket's ARN never changes, but the plan may later type a
				// service where it can) should not keep showing a stale label.
				"name": res.Name,
				// sensitivity is NOT refreshed here deliberately -- see
				// UpsertPermission's identical note. A later ticket may raise it
				// from tags or activity, and this scan must not stamp it back
				// down to the rule-based default on every repeat run.
				"last_seen_generation": res.LastSeenGeneration,
				"last_seen_at":         now,
				"row_updated_at":       now,
			}),
		},
		clause.Returning{},
	).Create(res).Error
	if err != nil {
		return nil, false, err
	}
	return res, res.ID == proposed, nil
}

func (r *cloudPermissionRepository) UpsertPermission(p *models.CloudPermission) (*models.CloudPermission, bool, error) {
	if p.WorkspaceID == uuid.Nil || p.ConnectorID == uuid.Nil || p.IdentityID == uuid.Nil {
		return nil, false, errors.New("workspace_id, connector_id and identity_id are required")
	}
	if p.NativeID == "" || p.Effect == "" || p.ScopeKind == "" || len(p.Actions) == 0 {
		return nil, false, errors.New("native_id, effect, scope_kind and actions are required")
	}
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	proposed := p.ID
	now := time.Now()

	err := r.db.Clauses(
		clause.OnConflict{
			// Matches uq_cloud_permission_grant, whose NULLS NOT DISTINCT is
			// what lets two account_wide/prefix grants from the same statement
			// (both resource_id NULL) collide as one conflict target instead of
			// duplicating on every scan.
			Columns: []clause.Column{{Name: "identity_id"}, {Name: "native_id"}, {Name: "resource_id"}},
			DoUpdates: clause.Assignments(map[string]interface{}{
				"connector_id": p.ConnectorID,
				"plane":        p.Plane,
				"effect":       p.Effect,
				"role_name":    p.RoleName,
				"actions":      p.Actions,
				"scope_kind":   p.ScopeKind,
				"derivation":   p.Derivation,
				// sensitivity is NOT refreshed on conflict. It starts as the
				// rule-based default this scan computed, but a reviewer may have
				// since raised it by hand (once that exists), and a re-scan of
				// an unchanged statement must not silently revert that call.
				"last_seen_generation": p.LastSeenGeneration,
				"last_seen_at":         now,
				"row_updated_at":       now,
			}),
		},
		clause.Returning{},
	).Create(p).Error
	if err != nil {
		return nil, false, err
	}
	return p, p.ID == proposed, nil
}

func (r *cloudPermissionRepository) ListAssumeEdges(workspaceID uuid.UUID, identityID *uuid.UUID) ([]models.CloudAssumeEdge, error) {
	q := r.db.Where("workspace_id = ?", workspaceID)
	if identityID != nil {
		q = q.Where("identity_id = ?", *identityID)
	}
	var out []models.CloudAssumeEdge
	if err := q.Order("subject_kind, subject").Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (r *cloudPermissionRepository) ListPermissions(workspaceID uuid.UUID, identityID *uuid.UUID) ([]models.CloudPermission, error) {
	q := r.db.Where("workspace_id = ?", workspaceID)
	if identityID != nil {
		q = q.Where("identity_id = ?", *identityID)
	}
	var out []models.CloudPermission
	if err := q.Order("native_id").Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (r *cloudPermissionRepository) ListResources(workspaceID uuid.UUID, connectorID *uuid.UUID) ([]models.CloudResource, error) {
	q := r.db.Where("workspace_id = ?", workspaceID)
	if connectorID != nil {
		q = q.Where("connector_id = ?", *connectorID)
	}
	var out []models.CloudResource
	if err := q.Order("kind, name").Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

func (r *cloudPermissionRepository) CountsForConnector(workspaceID, connectorID uuid.UUID) (int64, int64, int64, error) {
	var edges, permissions, resources int64
	if err := r.db.Model(&models.CloudAssumeEdge{}).
		Where("workspace_id = ? AND connector_id = ?", workspaceID, connectorID).
		Count(&edges).Error; err != nil {
		return 0, 0, 0, err
	}
	if err := r.db.Model(&models.CloudPermission{}).
		Where("workspace_id = ? AND connector_id = ?", workspaceID, connectorID).
		Count(&permissions).Error; err != nil {
		return 0, 0, 0, err
	}
	if err := r.db.Model(&models.CloudResource{}).
		Where("workspace_id = ? AND connector_id = ?", workspaceID, connectorID).
		Count(&resources).Error; err != nil {
		return 0, 0, 0, err
	}
	return edges, permissions, resources, nil
}

// ReconcileGeneration removes what this connector did not see, in the order
// that respects the foreign keys: permissions before the resources they may
// point at, then edges. Resources are deleted explicitly rather than left to
// no cascade -- a resource can be shared by permissions from more than one
// identity, so it is only removed once nothing this connector currently holds
// still names it.
func (r *cloudPermissionRepository) ReconcileGeneration(
	workspaceID, connectorID uuid.UUID, generation int,
) (int64, int64, int64, error) {

	var edgesRemoved, permissionsRemoved, resourcesRemoved int64
	err := r.db.Transaction(func(tx *gorm.DB) error {
		res := tx.Where(`workspace_id = ? AND connector_id = ? AND last_seen_generation < ?`,
			workspaceID, connectorID, generation).Delete(&models.CloudAssumeEdge{})
		if res.Error != nil {
			return res.Error
		}
		edgesRemoved = res.RowsAffected

		res = tx.Where(`workspace_id = ? AND connector_id = ? AND last_seen_generation < ?`,
			workspaceID, connectorID, generation).Delete(&models.CloudPermission{})
		if res.Error != nil {
			return res.Error
		}
		permissionsRemoved = res.RowsAffected

		// A resource this connector still uses was just re-stamped to the
		// current generation by the permission upsert that ran before
		// reconciliation, so this delete only catches resources nothing
		// references any more.
		res = tx.Where(`workspace_id = ? AND connector_id = ? AND last_seen_generation < ?`,
			workspaceID, connectorID, generation).Delete(&models.CloudResource{})
		if res.Error != nil {
			return res.Error
		}
		resourcesRemoved = res.RowsAffected
		return nil
	})
	return edgesRemoved, permissionsRemoved, resourcesRemoved, err
}
