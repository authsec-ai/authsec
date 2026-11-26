package repositories

import (
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// IGAGovFindingRuleRepository reads and writes iga_gov_finding_rule (048):
// workspace configuration of finding rules (require_review_date,
// unused_window). Thin by design; what a rule's scope and params MEAN, and
// applying them during evaluation, is T3.05 / T3.06 / T3.07.
type IGAGovFindingRuleRepository interface {
	Create(r *models.IGAGovFindingRule) error
	List(ws uuid.UUID) ([]models.IGAGovFindingRule, error)
	SetEnabled(ws, id uuid.UUID, enabled bool) error
}

type igaGovFindingRuleRepository struct{ db *gorm.DB }

func NewIGAGovFindingRuleRepository(db *gorm.DB) IGAGovFindingRuleRepository {
	return &igaGovFindingRuleRepository{db: db}
}

// write runs fn in one transaction under row-level security for ws on the
// repository's handle (a savepoint inside a caller's transaction) (AS-108).
func (r *igaGovFindingRuleRepository) write(ws uuid.UUID, fn func(tx *gorm.DB) error) error {
	return tenancy.InWorkspace(wsTxContext(r.db), r.db, ws, wsTxGuard(r.db, ws, fn))
}

func (r *igaGovFindingRuleRepository) Create(rule *models.IGAGovFindingRule) error {
	return r.write(rule.WorkspaceID, func(tx *gorm.DB) error { return tx.Create(rule).Error })
}

func (r *igaGovFindingRuleRepository) List(ws uuid.UUID) ([]models.IGAGovFindingRule, error) {
	var out []models.IGAGovFindingRule
	err := r.write(ws, func(tx *gorm.DB) error {
		return tx.Where("workspace_id = ?", ws).Order("kind, created_at").Find(&out).Error
	})
	return out, err
}

func (r *igaGovFindingRuleRepository) SetEnabled(ws, id uuid.UUID, enabled bool) error {
	return r.write(ws, func(tx *gorm.DB) error {
		return affectedOne(tx.Model(&models.IGAGovFindingRule{}).
			Where("workspace_id = ? AND id = ?", ws, id).Update("enabled", enabled))
	})
}
