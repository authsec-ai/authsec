package repositories

import (
	"errors"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/authsec-ai/authsec/models"
)

// ErrIGAGovNotFound is returned when a Phase 3 row does not exist IN THE
// CALLER'S WORKSPACE -- another workspace's row is indistinguishable from no
// row.
var ErrIGAGovNotFound = errors.New("not found")

// IGAGovSettingsRepository reads and writes iga_gov_settings (055).
//
// Thin by design: every write rule here is the schema's (one row per
// workspace, CHECK ranges). WHO may switch a workspace to enforce
// (governance:enforce) is the service's decision, not this repository's.
type IGAGovSettingsRepository interface {
	// Get returns the workspace's settings, or the column defaults (unsaved)
	// when the workspace has no row: absence means every default.
	Get(ws uuid.UUID) (*models.IGAGovSettings, error)
	// Save writes the whole row (insert or update), stamping updated_at.
	SaveTx(tx *gorm.DB, s *models.IGAGovSettings) error
}

type igaGovSettingsRepository struct{ db *gorm.DB }

func NewIGAGovSettingsRepository(db *gorm.DB) IGAGovSettingsRepository {
	return &igaGovSettingsRepository{db: db}
}

func (r *igaGovSettingsRepository) Get(ws uuid.UUID) (*models.IGAGovSettings, error) {
	var s models.IGAGovSettings
	err := r.db.Where("workspace_id = ?", ws).Take(&s).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		d := models.DefaultIGAGovSettings(ws)
		return &d, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *igaGovSettingsRepository) SaveTx(tx *gorm.DB, s *models.IGAGovSettings) error {
	return tx.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "workspace_id"}},
		DoUpdates: clause.Assignments(map[string]any{
			"enforcement_mode":         s.EnforcementMode,
			"default_window_days":      s.DefaultWindowDays,
			"default_observation_days": s.DefaultObservationDays,
			"owner_review_days":        s.OwnerReviewDays,
			"approval_valid_days":      s.ApprovalValidDays,
			"canary_hours":             s.CanaryHours,
			"iac_apply_hours":          s.IaCApplyHours,
			"evidence_retention_revs":  s.EvidenceRetentionRevs,
			"updated_by":               s.UpdatedBy,
			"updated_at":               gorm.Expr("now()"),
		}),
	}).Create(s).Error
}
