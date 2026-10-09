package repositories

import (
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

// IGAGovEventRepository appends to and reads iga_gov_event (052), the
// append-only audit behind Logs.
//
// Thin by design: the table refuses UPDATE, and DELETE outside a workspace
// purge (trigger iga_gov_event_immutable), so append and read are the only
// operations there are. Events are appended in the SAME transaction as the
// mutation they record (AppendTx), so a recorded change and its event commit
// or roll back together. Which events exist and what they carry is T3.20.
type IGAGovEventRepository interface {
	AppendTx(tx *gorm.DB, e *models.IGAGovEvent) error
	// List returns a workspace's events after the id cursor (0 = from the
	// start), oldest first, at most limit (1..500).
	List(ws uuid.UUID, afterID int64, limit int) ([]models.IGAGovEvent, error)
	// ListByPolicy is List for one policy.
	ListByPolicy(ws, policyID uuid.UUID, afterID int64, limit int) ([]models.IGAGovEvent, error)
}

// MaxIGAGovEventPage bounds one page of events.
const MaxIGAGovEventPage = 500

type igaGovEventRepository struct{ db *gorm.DB }

func NewIGAGovEventRepository(db *gorm.DB) IGAGovEventRepository {
	return &igaGovEventRepository{db: db}
}

func (r *igaGovEventRepository) AppendTx(tx *gorm.DB, e *models.IGAGovEvent) error {
	if e.ID != 0 {
		// id is GENERATED ALWAYS; an event is never re-appended.
		return gorm.ErrInvalidData
	}
	return tx.Create(e).Error
}

func (r *igaGovEventRepository) List(ws uuid.UUID, afterID int64, limit int) ([]models.IGAGovEvent, error) {
	return r.page(r.db.Where("workspace_id = ?", ws), afterID, limit)
}

func (r *igaGovEventRepository) ListByPolicy(ws, policyID uuid.UUID, afterID int64, limit int) ([]models.IGAGovEvent, error) {
	return r.page(r.db.Where("workspace_id = ? AND policy_id = ?", ws, policyID), afterID, limit)
}

func (r *igaGovEventRepository) page(q *gorm.DB, afterID int64, limit int) ([]models.IGAGovEvent, error) {
	if limit < 1 || limit > MaxIGAGovEventPage {
		limit = MaxIGAGovEventPage
	}
	var out []models.IGAGovEvent
	err := q.Where("id > ?", afterID).Order("id").Limit(limit).Find(&out).Error
	return out, err
}
