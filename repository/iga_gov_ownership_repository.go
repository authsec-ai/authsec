package repositories

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

// IGAGovOwnershipRepository reads and writes owners and owner tag rules
// (047, SPEC-iga-phase3-policy.md §2.9).
//
// Thin by design. The schema fixes every write rule used here: an owner
// belongs to exactly one workload or identity of the same workspace, a
// tag_rule owner names its rule (and goes when the rule is deleted), and one
// (object, user, role) appears once. What is NOT here is service semantics
// (T3.07): evaluating rules after a publication, resolving a role's owners
// as its own plus the accountable owners of every workload running as it,
// and raising missing_owner.
type IGAGovOwnershipRepository interface {
	CreateRule(r *models.IGAGovOwnerRule) error
	ListRules(ws uuid.UUID) ([]models.IGAGovOwnerRule, error)
	SetRuleEnabled(ws, id uuid.UUID, enabled bool) error
	// DeleteRule deletes the rule and, by FK cascade, the owners it assigned.
	DeleteRule(ws, id uuid.UUID) error

	AddOwner(o *models.IGAGovOwner) error
	// ListOwners returns the owners recorded directly on one object.
	ListOwners(ws uuid.UUID, objectKind string, objectID uuid.UUID) ([]models.IGAGovOwner, error)
	SetReviewDue(ws, id uuid.UUID, due *time.Time) error
	RemoveOwner(ws, id uuid.UUID) error
}

type igaGovOwnershipRepository struct{ db *gorm.DB }

func NewIGAGovOwnershipRepository(db *gorm.DB) IGAGovOwnershipRepository {
	return &igaGovOwnershipRepository{db: db}
}

func (r *igaGovOwnershipRepository) CreateRule(rule *models.IGAGovOwnerRule) error {
	return r.db.Create(rule).Error
}

func (r *igaGovOwnershipRepository) ListRules(ws uuid.UUID) ([]models.IGAGovOwnerRule, error) {
	var out []models.IGAGovOwnerRule
	err := r.db.Where("workspace_id = ?", ws).Order("tag_key, applies_to, role").Find(&out).Error
	return out, err
}

func (r *igaGovOwnershipRepository) SetRuleEnabled(ws, id uuid.UUID, enabled bool) error {
	return affectedOne(r.db.Model(&models.IGAGovOwnerRule{}).
		Where("workspace_id = ? AND id = ?", ws, id).Update("enabled", enabled))
}

func (r *igaGovOwnershipRepository) DeleteRule(ws, id uuid.UUID) error {
	return affectedOne(r.db.Where("workspace_id = ? AND id = ?", ws, id).Delete(&models.IGAGovOwnerRule{}))
}

func (r *igaGovOwnershipRepository) AddOwner(o *models.IGAGovOwner) error {
	return r.db.Create(o).Error
}

func (r *igaGovOwnershipRepository) ListOwners(ws uuid.UUID, objectKind string, objectID uuid.UUID) ([]models.IGAGovOwner, error) {
	col := "workload_id"
	if objectKind == models.GovObjectIdentityAccount {
		col = "identity_account_id"
	}
	var out []models.IGAGovOwner
	err := r.db.Where("workspace_id = ? AND object_kind = ? AND "+col+" = ?", ws, objectKind, objectID).
		Order("role, created_at").Find(&out).Error
	return out, err
}

func (r *igaGovOwnershipRepository) SetReviewDue(ws, id uuid.UUID, due *time.Time) error {
	return affectedOne(r.db.Model(&models.IGAGovOwner{}).Where("workspace_id = ? AND id = ?", ws, id).
		Updates(map[string]any{"review_due_at": due, "updated_at": gorm.Expr("now()")}))
}

func (r *igaGovOwnershipRepository) RemoveOwner(ws, id uuid.UUID) error {
	return affectedOne(r.db.Where("workspace_id = ? AND id = ?", ws, id).Delete(&models.IGAGovOwner{}))
}

// affectedOne maps "no row in this workspace" to ErrIGAGovNotFound.
func affectedOne(res *gorm.DB) error {
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrIGAGovNotFound
	}
	return nil
}
