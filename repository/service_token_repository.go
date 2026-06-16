package repositories

import (
	"time"

	"github.com/lib/pq"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ServiceUserToken is the GORM model for the service_user_tokens table.
type ServiceUserToken struct {
	ID           string         `json:"id" gorm:"primaryKey"`
	ServiceID    string         `json:"service_id" gorm:"not null"`
	UserID       string         `json:"user_id" gorm:"not null"`
	WorkspaceID  string         `json:"workspace_id" gorm:"not null"`
	VaultPath    string         `json:"-" gorm:"not null"`
	Scopes       pq.StringArray `json:"scopes" gorm:"type:text[]" swaggertype:"array,string"`
	ExpiresAt    *time.Time     `json:"expires_at"`
	RefreshError string         `json:"refresh_error"`
	ConnectedAt  time.Time      `json:"connected_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
}

func (ServiceUserToken) TableName() string { return "service_user_tokens" }

// ServiceUserTokenRepository provides CRUD for service_user_tokens.
type ServiceUserTokenRepository interface {
	Upsert(token *ServiceUserToken) error
	GetByServiceAndUser(serviceID, userID, workspaceID string) (*ServiceUserToken, error)
	ListByService(serviceID string) ([]ServiceUserToken, error)
	DeleteByServiceAndUser(serviceID, userID, workspaceID string) error
	Update(token *ServiceUserToken) error
}

type serviceUserTokenRepository struct{ db *gorm.DB }

// NewServiceUserTokenRepository constructs a ServiceUserTokenRepository.
func NewServiceUserTokenRepository(db *gorm.DB) ServiceUserTokenRepository {
	return &serviceUserTokenRepository{db}
}

func (r *serviceUserTokenRepository) Upsert(token *ServiceUserToken) error {
	return r.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "service_id"}, {Name: "user_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"vault_path", "scopes", "expires_at", "refresh_error", "updated_at",
		}),
	}).Create(token).Error
}

func (r *serviceUserTokenRepository) GetByServiceAndUser(serviceID, userID, workspaceID string) (*ServiceUserToken, error) {
	var t ServiceUserToken
	err := r.db.Where("service_id = ? AND user_id = ? AND workspace_id = ?", serviceID, userID, workspaceID).First(&t).Error
	return &t, err
}

func (r *serviceUserTokenRepository) ListByService(serviceID string) ([]ServiceUserToken, error) {
	var tokens []ServiceUserToken
	err := r.db.Where("service_id = ?", serviceID).Find(&tokens).Error
	return tokens, err
}

func (r *serviceUserTokenRepository) DeleteByServiceAndUser(serviceID, userID, workspaceID string) error {
	return r.db.Where("service_id = ? AND user_id = ? AND workspace_id = ?", serviceID, userID, workspaceID).
		Delete(&ServiceUserToken{}).Error
}

func (r *serviceUserTokenRepository) Update(token *ServiceUserToken) error {
	return r.db.Save(token).Error
}
