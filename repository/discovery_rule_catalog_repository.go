package repositories

import (
	"errors"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrRuleCatalogNotFound means the workspace has no overlay, which is the
// normal state: it runs the built-in catalogue unchanged.
var ErrRuleCatalogNotFound = errors.New("no rule catalog overlay for this workspace")

// DiscoveryRuleCatalogRepository persists per-workspace detection-pattern
// overlays.
type DiscoveryRuleCatalogRepository interface {
	Get(workspaceID uuid.UUID) (*models.DiscoveryRuleCatalog, error)
	Upsert(cat *models.DiscoveryRuleCatalog) error
	// Delete resets the workspace to the built-in catalogue. Deleting the row IS
	// the reset, which is why there is no way to edit into an unrecoverable
	// state.
	Delete(workspaceID uuid.UUID) error
}

type discoveryRuleCatalogRepository struct{ db *gorm.DB }

// NewDiscoveryRuleCatalogRepository constructs the repository.
func NewDiscoveryRuleCatalogRepository(db *gorm.DB) DiscoveryRuleCatalogRepository {
	return &discoveryRuleCatalogRepository{db}
}

func (r *discoveryRuleCatalogRepository) Get(workspaceID uuid.UUID) (*models.DiscoveryRuleCatalog, error) {
	var out models.DiscoveryRuleCatalog
	if err := r.db.First(&out, "workspace_id = ?", workspaceID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRuleCatalogNotFound
		}
		return nil, err
	}
	return &out, nil
}

func (r *discoveryRuleCatalogRepository) Upsert(cat *models.DiscoveryRuleCatalog) error {
	if cat.WorkspaceID == uuid.Nil {
		return errors.New("workspace is required")
	}
	return r.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "workspace_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"overlay", "based_on", "overlay_hash", "updated_by", "updated_at",
		}),
	}).Create(cat).Error
}

func (r *discoveryRuleCatalogRepository) Delete(workspaceID uuid.UUID) error {
	return r.db.Where("workspace_id = ?", workspaceID).
		Delete(&models.DiscoveryRuleCatalog{}).Error
}
