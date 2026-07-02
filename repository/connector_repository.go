package repositories

import (
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ConnectorRepository provides workspace-scoped CRUD for connectors and
// read access to the provider catalog.
type ConnectorRepository interface {
	ListProviders() ([]models.ConnectorProvider, error)
	GetProvider(key string) (*models.ConnectorProvider, error)

	Create(c *models.Connector) error
	GetByID(workspaceID uuid.UUID, id uuid.UUID) (*models.Connector, error)
	ListByWorkspace(workspaceID uuid.UUID) ([]models.Connector, error)
	Update(c *models.Connector) error
	Delete(workspaceID uuid.UUID, id uuid.UUID) error

	CreateConnection(conn *models.ConnectorConnection) error
	ListConnections(connectorID uuid.UUID) ([]models.ConnectorConnection, error)
	GetWorkspaceConnection(connectorID uuid.UUID) (*models.ConnectorConnection, error)
	GetUserConnection(connectorID uuid.UUID, subjectUserID string) (*models.ConnectorConnection, error)

	CreateAssignment(a *models.ConnectorAssignment) error
	ListAssignments(connectorID uuid.UUID) ([]models.ConnectorAssignment, error)
	DeleteAssignment(workspaceID, id uuid.UUID) error
	// AssignmentAllows reports whether client_id may invoke action on connector:
	// an all-actions row (action_key IS NULL) OR a row matching the action.
	AssignmentAllows(connectorID uuid.UUID, clientID, actionKey string) (bool, error)

	ListActions(providerKey string) ([]models.ConnectorAction, error)
	GetAction(providerKey, actionKey string) (*models.ConnectorAction, error)
}

type connectorRepository struct{ db *gorm.DB }

// NewConnectorRepository constructs a ConnectorRepository.
func NewConnectorRepository(db *gorm.DB) ConnectorRepository {
	return &connectorRepository{db}
}

func (r *connectorRepository) ListProviders() ([]models.ConnectorProvider, error) {
	var providers []models.ConnectorProvider
	err := r.db.Order("display_name").Find(&providers).Error
	return providers, err
}

func (r *connectorRepository) GetProvider(key string) (*models.ConnectorProvider, error) {
	var p models.ConnectorProvider
	err := r.db.First(&p, "key = ?", key).Error
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (r *connectorRepository) Create(c *models.Connector) error {
	return r.db.Create(c).Error
}

func (r *connectorRepository) GetByID(workspaceID, id uuid.UUID) (*models.Connector, error) {
	var c models.Connector
	err := r.db.First(&c, "id = ? AND workspace_id = ?", id, workspaceID).Error
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *connectorRepository) ListByWorkspace(workspaceID uuid.UUID) ([]models.Connector, error) {
	var conns []models.Connector
	err := r.db.Where("workspace_id = ?", workspaceID).Order("created_at DESC").Find(&conns).Error
	return conns, err
}

func (r *connectorRepository) Update(c *models.Connector) error {
	return r.db.Save(c).Error
}

func (r *connectorRepository) Delete(workspaceID, id uuid.UUID) error {
	return r.db.Delete(&models.Connector{}, "id = ? AND workspace_id = ?", id, workspaceID).Error
}

func (r *connectorRepository) CreateConnection(conn *models.ConnectorConnection) error {
	return r.db.Create(conn).Error
}

func (r *connectorRepository) ListConnections(connectorID uuid.UUID) ([]models.ConnectorConnection, error) {
	var conns []models.ConnectorConnection
	err := r.db.Where("connector_id = ?", connectorID).Order("scope, created_at").Find(&conns).Error
	return conns, err
}

func (r *connectorRepository) GetWorkspaceConnection(connectorID uuid.UUID) (*models.ConnectorConnection, error) {
	var conn models.ConnectorConnection
	err := r.db.First(&conn, "connector_id = ? AND scope = ?", connectorID, models.ConnectionScopeWorkspace).Error
	if err != nil {
		return nil, err
	}
	return &conn, nil
}

func (r *connectorRepository) GetUserConnection(connectorID uuid.UUID, subjectUserID string) (*models.ConnectorConnection, error) {
	var conn models.ConnectorConnection
	err := r.db.First(&conn, "connector_id = ? AND scope = ? AND subject_user_id = ?",
		connectorID, models.ConnectionScopeUser, subjectUserID).Error
	if err != nil {
		return nil, err
	}
	return &conn, nil
}

func (r *connectorRepository) CreateAssignment(a *models.ConnectorAssignment) error {
	return r.db.Create(a).Error
}

func (r *connectorRepository) ListAssignments(connectorID uuid.UUID) ([]models.ConnectorAssignment, error) {
	var as []models.ConnectorAssignment
	err := r.db.Where("connector_id = ?", connectorID).Order("created_at").Find(&as).Error
	return as, err
}

func (r *connectorRepository) DeleteAssignment(workspaceID, id uuid.UUID) error {
	return r.db.Delete(&models.ConnectorAssignment{}, "id = ? AND workspace_id = ?", id, workspaceID).Error
}

func (r *connectorRepository) AssignmentAllows(connectorID uuid.UUID, clientID, actionKey string) (bool, error) {
	var count int64
	err := r.db.Model(&models.ConnectorAssignment{}).
		Where("connector_id = ? AND client_id = ? AND (action_key IS NULL OR action_key = ?)",
			connectorID, clientID, actionKey).
		Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *connectorRepository) ListActions(providerKey string) ([]models.ConnectorAction, error) {
	var actions []models.ConnectorAction
	err := r.db.Where("provider_key = ?", providerKey).Order("action_key").Find(&actions).Error
	return actions, err
}

func (r *connectorRepository) GetAction(providerKey, actionKey string) (*models.ConnectorAction, error) {
	var a models.ConnectorAction
	err := r.db.First(&a, "provider_key = ? AND action_key = ?", providerKey, actionKey).Error
	if err != nil {
		return nil, err
	}
	return &a, nil
}
