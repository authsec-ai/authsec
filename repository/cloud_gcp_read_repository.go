package repositories

import (
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// CloudGCPReadRepository serves the Google Cloud console views: identities,
// IAM bindings and the resources those bindings name.
//
// The shared AWS lists (ListPermissions, ListResources) deliberately leave GCP
// rows out, because a GCP binding names a role and a condition their consumers
// do not render. These reads are the other half of that rule: every query is
// fenced to the workspace AND to the workspace's GCP connectors, so an AWS or
// Azure row can never surface here, and another workspace's rows never can.
type CloudGCPReadRepository struct {
	db *gorm.DB
}

// NewCloudGCPReadRepository constructs the repository.
func NewCloudGCPReadRepository(db *gorm.DB) *CloudGCPReadRepository {
	return &CloudGCPReadRepository{db: db}
}

// GCPIdentityFilter narrows the GCP identity list. Kinds is an allow-list of
// cloud_identity.kind values; empty means every GCP kind.
type GCPIdentityFilter struct {
	ID          *uuid.UUID
	ConnectorID *uuid.UUID
	Kinds       []string
	Limit       int
	Offset      int
}

// GCPBindingFilter narrows the binding list.
type GCPBindingFilter struct {
	IdentityID  *uuid.UUID
	ResourceID  *uuid.UUID
	ConnectorID *uuid.UUID
	Limit       int
	Offset      int
}

// GCPBindingView is one binding row plus the names a console needs to render it
// without a second round trip: who holds it and, for a resource-level binding,
// what it is on. The joined fields are empty when the row has no resource.
type GCPBindingView struct {
	models.CloudPermission
	IdentityName     string `json:"identity_name"`
	IdentityKind     string `json:"identity_kind"`
	IdentityNativeID string `json:"identity_native_id"`
	ResourceName     string `json:"resource_name,omitempty"`
	ResourceKind     string `json:"resource_kind,omitempty"`
	ResourceNativeID string `json:"resource_native_id,omitempty"`
}

// GCPResourceView is a resource plus how many bindings name it.
type GCPResourceView struct {
	models.CloudResource
	BindingCount int64 `json:"binding_count"`
}

// gcpConnectorIDs is the subquery every read is fenced by.
func (r *CloudGCPReadRepository) gcpConnectorIDs(workspaceID uuid.UUID) *gorm.DB {
	return r.db.Model(&models.CloudConnector{}).Select("id").
		Where("workspace_id = ? AND provider = ?", workspaceID, models.CloudProviderGCP)
}

// ListIdentities lists GCP identities: service accounts, the principals named
// only in bindings, and the synthetic project owner of API keys.
func (r *CloudGCPReadRepository) ListIdentities(workspaceID uuid.UUID, f GCPIdentityFilter) ([]models.CloudIdentity, int64, error) {
	q := r.db.Model(&models.CloudIdentity{}).
		Where("workspace_id = ? AND connector_id IN (?)", workspaceID, r.gcpConnectorIDs(workspaceID))
	if f.ID != nil {
		q = q.Where("id = ?", *f.ID)
	}
	if f.ConnectorID != nil {
		q = q.Where("connector_id = ?", *f.ConnectorID)
	}
	if len(f.Kinds) > 0 {
		q = q.Where("kind IN (?)", f.Kinds)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var out []models.CloudIdentity
	if err := q.Order("kind, name, id").Limit(clampLimit(f.Limit)).Offset(f.Offset).Find(&out).Error; err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// ListBindings lists GCP IAM bindings (cloud_permission rows of GCP connectors)
// with the holder's and the resource's names.
func (r *CloudGCPReadRepository) ListBindings(workspaceID uuid.UUID, f GCPBindingFilter) ([]GCPBindingView, int64, error) {
	q := r.db.Table("cloud_permission AS p").
		Where("p.workspace_id = ? AND p.connector_id IN (?)", workspaceID, r.gcpConnectorIDs(workspaceID))
	if f.IdentityID != nil {
		q = q.Where("p.identity_id = ?", *f.IdentityID)
	}
	if f.ResourceID != nil {
		q = q.Where("p.resource_id = ?", *f.ResourceID)
	}
	if f.ConnectorID != nil {
		q = q.Where("p.connector_id = ?", *f.ConnectorID)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var out []GCPBindingView
	// Both joins repeat the workspace predicate: a foreign key already ties the
	// rows together, and the predicate keeps the join honest if it ever did not.
	err := q.Select("p.*, i.name AS identity_name, i.kind AS identity_kind, i.native_id AS identity_native_id, " +
		"COALESCE(r.name, '') AS resource_name, COALESCE(r.kind, '') AS resource_kind, COALESCE(r.native_id, '') AS resource_native_id").
		Joins("JOIN cloud_identity AS i ON i.id = p.identity_id AND i.workspace_id = p.workspace_id").
		Joins("LEFT JOIN cloud_resource AS r ON r.id = p.resource_id AND r.workspace_id = p.workspace_id").
		Order("p.role_name, i.name, p.native_id, p.id").
		Limit(clampLimit(f.Limit)).Offset(f.Offset).
		Scan(&out).Error
	if err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// ListResources lists the GCP resources that carry their own IAM policy, with
// the number of bindings on each.
func (r *CloudGCPReadRepository) ListResources(workspaceID uuid.UUID, f GCPIdentityFilter) ([]GCPResourceView, int64, error) {
	q := r.db.Table("cloud_resource AS r").
		Where("r.workspace_id = ? AND r.connector_id IN (?)", workspaceID, r.gcpConnectorIDs(workspaceID))
	if f.ID != nil {
		q = q.Where("r.id = ?", *f.ID)
	}
	if f.ConnectorID != nil {
		q = q.Where("r.connector_id = ?", *f.ConnectorID)
	}
	if len(f.Kinds) > 0 {
		q = q.Where("r.kind IN (?)", f.Kinds)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var out []GCPResourceView
	err := q.Select("r.*, (SELECT COUNT(*) FROM cloud_permission AS p " +
		"WHERE p.resource_id = r.id AND p.workspace_id = r.workspace_id) AS binding_count").
		Order("r.kind, r.name, r.id").
		Limit(clampLimit(f.Limit)).Offset(f.Offset).
		Scan(&out).Error
	if err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

/* ------------------------------ GCP-4: trust edges ----------------------------- */

// GCPBindingRow is one binding with the kind and name of the resource it sits
// on (empty for an organization, folder or project binding).
type GCPBindingRow struct {
	models.CloudPermission
	ResourceKind     string `json:"resource_kind"`
	ResourceNativeID string `json:"resource_native_id"`
}

// BindingsForConnector returns every binding row of one GCP connector, unpaged:
// the edge phase derives from all of them. Workspace- and connector-fenced.
func (r *CloudGCPReadRepository) BindingsForConnector(workspaceID, connectorID uuid.UUID) ([]GCPBindingRow, error) {
	var out []GCPBindingRow
	err := r.db.Table("cloud_permission AS p").
		Select("p.*, COALESCE(r.kind, '') AS resource_kind, COALESCE(r.native_id, '') AS resource_native_id").
		Joins("LEFT JOIN cloud_resource AS r ON r.id = p.resource_id AND r.workspace_id = p.workspace_id").
		Where("p.workspace_id = ? AND p.connector_id = ?", workspaceID, connectorID).
		Order("p.id").
		Scan(&out).Error
	return out, err
}

// IdentitiesForConnector returns every identity row of one connector, unpaged.
func (r *CloudGCPReadRepository) IdentitiesForConnector(workspaceID, connectorID uuid.UUID) ([]models.CloudIdentity, error) {
	var out []models.CloudIdentity
	err := r.db.Where("workspace_id = ? AND connector_id = ?", workspaceID, connectorID).
		Order("id").Find(&out).Error
	return out, err
}

// GCPEdgeFilter narrows the edge list. IdentityIDs are the targets ("who can
// become these"); SubjectIdentityID is the subject ("what can this become").
type GCPEdgeFilter struct {
	IdentityIDs       []uuid.UUID
	SubjectIdentityID *uuid.UUID
	ConnectorID       *uuid.UUID
	Limit             int
	Offset            int
}

// GCPEdgeView is an edge plus the name and kind of the identity it leads to.
type GCPEdgeView struct {
	models.CloudAssumeEdge
	IdentityName     string `json:"identity_name"`
	IdentityKind     string `json:"identity_kind"`
	IdentityNativeID string `json:"identity_native_id"`
}

// ListEdges lists GCP trust edges, fenced to the workspace and its GCP connectors.
func (r *CloudGCPReadRepository) ListEdges(workspaceID uuid.UUID, f GCPEdgeFilter) ([]GCPEdgeView, int64, error) {
	q := r.db.Table("cloud_assume_edge AS e").
		Where("e.workspace_id = ? AND e.connector_id IN (?)", workspaceID, r.gcpConnectorIDs(workspaceID))
	if len(f.IdentityIDs) > 0 {
		q = q.Where("e.identity_id IN ?", f.IdentityIDs)
	}
	if f.SubjectIdentityID != nil {
		q = q.Where("e.attrs->>'subject_identity_id' = ?", f.SubjectIdentityID.String())
	}
	if f.ConnectorID != nil {
		q = q.Where("e.connector_id = ?", *f.ConnectorID)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var out []GCPEdgeView
	err := q.Select("e.*, i.name AS identity_name, i.kind AS identity_kind, i.native_id AS identity_native_id").
		Joins("JOIN cloud_identity AS i ON i.id = e.identity_id AND i.workspace_id = e.workspace_id").
		Order("e.mechanism, e.subject_kind, e.subject, e.id").
		Limit(clampLimit(f.Limit)).Offset(f.Offset).
		Scan(&out).Error
	if err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// ScopeIdentityIDsAbove returns the ids of the scope rows (project, folders,
// organization) that sit above a service account, for "who can become this
// through a project-, folder- or organization-level grant". nativeIDs are the
// scope rows' native ids, computed by the caller from the connector's tree.
func (r *CloudGCPReadRepository) ScopeIdentityIDsAbove(workspaceID, connectorID uuid.UUID, nativeIDs []string) ([]uuid.UUID, error) {
	if len(nativeIDs) == 0 {
		return nil, nil
	}
	var ids []uuid.UUID
	err := r.db.Model(&models.CloudIdentity{}).
		Where("workspace_id = ? AND connector_id = ? AND native_id IN ?", workspaceID, connectorID, nativeIDs).
		Pluck("id", &ids).Error
	return ids, err
}

// StoredActions returns the actions a binding row already holds, for a scan
// that could not read the row's role this time: the last known expansion is
// kept rather than overwritten with nothing. found is false for a new row.
func (r *CloudGCPReadRepository) StoredActions(workspaceID, identityID uuid.UUID, nativeID string, resourceID *uuid.UUID) ([]string, bool, error) {
	var rows []models.CloudPermission
	q := r.db.Select("actions").Where("workspace_id = ? AND identity_id = ? AND native_id = ?", workspaceID, identityID, nativeID)
	if resourceID == nil {
		q = q.Where("resource_id IS NULL")
	} else {
		q = q.Where("resource_id = ?", *resourceID)
	}
	if err := q.Limit(1).Find(&rows).Error; err != nil {
		return nil, false, err
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	return rows[0].Actions, true, nil
}
