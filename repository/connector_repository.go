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
