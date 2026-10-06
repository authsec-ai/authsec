package repositories

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// ExternalService is the GORM model for the services table (per-tenant DB).
type ExternalService struct {
	ID              string         `json:"id" gorm:"primaryKey"`
	Name            string         `json:"name" gorm:"not null"`
	Type            string         `json:"type"`
	URL             string         `json:"url"`
	Description     string         `json:"description"`
	Tags            pq.StringArray `json:"tags" gorm:"type:text[]" swaggertype:"array,string"`
	ResourceID      string         `json:"resource_id" gorm:"not null"`
	AuthType        string         `json:"auth_type" gorm:"not null"`
	AuthConfig      string         `json:"auth_config"` // JSON blob
	VaultPath       string         `json:"vault_path"`
	CreatedBy       string         `json:"created_by" gorm:"not null"`
	WorkspaceID     *uuid.UUID     `json:"workspace_id,omitempty" gorm:"type:uuid"` // owner; set from the caller's token (047)
	AgentAccessible bool           `json:"agent_accessible" gorm:"default:true"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

func (ExternalService) TableName() string { return "services" }

// ExternalServiceRepository provides CRUD operations for ExternalService.
type ExternalServiceRepository interface {
	Create(svc *ExternalService) error
	GetByID(id string) (*ExternalService, error)
	GetByIDForWorkspace(id, workspaceID string) (*ExternalService, error)
	ListByClient(clientID string) ([]ExternalService, error)
	Update(svc *ExternalService) error
	Delete(id string) error
}

type externalServiceRepository struct{ db *gorm.DB }

func NewExternalServiceRepository(db *gorm.DB) ExternalServiceRepository {
	return &externalServiceRepository{db}
}

func (r *externalServiceRepository) Create(svc *ExternalService) error {
	return r.db.Create(svc).Error
}

func (r *externalServiceRepository) GetByID(id string) (*ExternalService, error) {
	var svc ExternalService
	err := r.db.First(&svc, "id = ?", id).Error
	return &svc, err
}

// GetByIDForWorkspace loads a service only when its creator belongs to
// workspaceID. The services table has no workspace column; created_by holds the
// creator's token client_id, which is the workspace id itself (admin tokens), a
// user's id or legacy client_id, or an OAuth client's client_id.
func (r *externalServiceRepository) GetByIDForWorkspace(id, workspaceID string) (*ExternalService, error) {
	var svc ExternalService
	err := r.db.Where("id = ?", id).
		Where(`(created_by = ?
			OR EXISTS (SELECT 1 FROM users u WHERE u.workspace_id::text = ?
				AND (u.id::text = services.created_by OR u.client_id::text = services.created_by))
			OR EXISTS (SELECT 1 FROM workspace_memberships m WHERE m.workspace_id::text = ?
				AND m.status = 'active' AND m.user_id::text = services.created_by)
			OR EXISTS (SELECT 1 FROM mcp_oauth_clients c WHERE c.home_workspace_id::text = ?
				AND c.client_id = services.created_by))`,
			workspaceID, workspaceID, workspaceID, workspaceID).
		First(&svc).Error
	return &svc, err
}

func (r *externalServiceRepository) ListByClient(clientID string) ([]ExternalService, error) {
	var svcs []ExternalService
	err := r.db.Where("created_by = ?", clientID).Find(&svcs).Error
	return svcs, err
}

func (r *externalServiceRepository) Update(svc *ExternalService) error {
	return r.db.Save(svc).Error
}

func (r *externalServiceRepository) Delete(id string) error {
	return r.db.Delete(&ExternalService{}, "id = ?", id).Error
}
