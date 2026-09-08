package repositories

import (
	"errors"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrAzureAppConfigNotFound means this workspace has not submitted an
// application, which is not an error condition: the deployment-wide env vars
// are the documented fallback.
var ErrAzureAppConfigNotFound = errors.New("no azure application configured for this workspace")

// AzureAppConfigRepository stores a workspace's own Entra App Registration.
//
// It never sees the client secret. The caller writes that to Vault and passes
// the resulting path as authRef, so a repository bug cannot put a secret in
// Postgres -- there is no parameter it could arrive through.
type AzureAppConfigRepository interface {
	// Upsert replaces the workspace's application. One row per workspace, so
	// submitting new details is an UPDATE and there is never an ambiguous
	// "which application is this workspace using".
	Upsert(cfg *models.AzureAppConfig) (*models.AzureAppConfig, error)

	// Get returns the workspace's application, or ErrAzureAppConfigNotFound.
	Get(workspaceID uuid.UUID) (*models.AzureAppConfig, error)

	// MarkChecked records when the registration was last verified against
	// Microsoft. The verdict itself is deliberately not stored: it can change in
	// the portal at any moment with nothing telling us, so a cached "ok" would
	// be a claim the code cannot stand behind.
	MarkChecked(workspaceID uuid.UUID) error

	// Delete removes it, returning the workspace to the env-var fallback.
	Delete(workspaceID uuid.UUID) error
}

type azureAppConfigRepository struct{ db *gorm.DB }

func NewAzureAppConfigRepository(db *gorm.DB) AzureAppConfigRepository {
	return &azureAppConfigRepository{db: db}
}

func (r *azureAppConfigRepository) Upsert(cfg *models.AzureAppConfig) (*models.AzureAppConfig, error) {
	now := time.Now().UTC()
	if err := r.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "workspace_id"}},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"client_id":    cfg.ClientID,
			"home_tenant":  cfg.HomeTenant,
			"redirect_uri": cfg.RedirectURI,
			"auth_ref":     cfg.AuthRef,
			"created_by":   cfg.CreatedBy,
			"updated_at":   now,
			// Cleared on purpose: new details have not been checked yet, and
			// carrying the previous timestamp forward would date this
			// application by a verification of a different one.
			"checked_at": nil,
		}),
	}).Create(cfg).Error; err != nil {
		return nil, err
	}
	return r.Get(cfg.WorkspaceID)
}

func (r *azureAppConfigRepository) Get(workspaceID uuid.UUID) (*models.AzureAppConfig, error) {
	var row models.AzureAppConfig
	err := r.db.Where("workspace_id = ?", workspaceID).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrAzureAppConfigNotFound
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func (r *azureAppConfigRepository) MarkChecked(workspaceID uuid.UUID) error {
	now := time.Now().UTC()
	return r.db.Model(&models.AzureAppConfig{}).
		Where("workspace_id = ?", workspaceID).
		Updates(map[string]interface{}{"checked_at": now, "updated_at": now}).Error
}

func (r *azureAppConfigRepository) Delete(workspaceID uuid.UUID) error {
	return r.db.Where("workspace_id = ?", workspaceID).
		Delete(&models.AzureAppConfig{}).Error
}
