package services

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ResourceServerDriftService emits and reads drift events for ready RSes.
// Drift events record post-activation destructive admin edits so the workspace
// banner can surface "what changed since activation."
type ResourceServerDriftService struct {
	db *gorm.DB
}

func NewResourceServerDriftService(db *gorm.DB) *ResourceServerDriftService {
	return &ResourceServerDriftService{db: db}
}

// EmitEvent writes a drift event row in the provided transaction (or the
// service's own DB connection if tx is nil). Must be called inside the same
// transaction as the underlying mutation so the event is atomic with the change.
func (s *ResourceServerDriftService) EmitEvent(
	tx *gorm.DB,
	rsID uuid.UUID,
	eventType string,
	payload interface{},
	occurredBy *uuid.UUID,
) error {
	db := s.db
	if tx != nil {
		db = tx
	}

	var payloadBytes []byte
	if payload != nil {
		var err error
		payloadBytes, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal drift event payload: %w", err)
		}
	}

	event := models.ResourceServerDriftEvent{
		RSID:         rsID,
		EventType:    eventType,
		EventPayload: payloadBytes,
		OccurredAt:   time.Now().UTC(),
		OccurredBy:   occurredBy,
	}
	return db.Create(&event).Error
}

// ListUndismissed returns drift events for rsID that occurred after
// setup_completed_at AND have not been dismissed by adminUserID.
func (s *ResourceServerDriftService) ListUndismissed(
	rsID uuid.UUID,
	adminUserID uuid.UUID,
	setupCompletedAt *time.Time,
) ([]models.ResourceServerDriftEvent, error) {
	q := s.db.Where("rs_id = ?", rsID)
	if setupCompletedAt != nil {
		q = q.Where("occurred_at >= ?", *setupCompletedAt)
	}
	q = q.Where(`
		id NOT IN (
			SELECT event_id
			  FROM resource_server_drift_event_dismissals
			 WHERE admin_user_id = ?
		)
	`, adminUserID)
	q = q.Order("occurred_at ASC")

	var events []models.ResourceServerDriftEvent
	if err := q.Find(&events).Error; err != nil {
		return nil, err
	}
	return events, nil
}

// Dismiss records a dismissal of eventID by adminUserID.
func (s *ResourceServerDriftService) Dismiss(eventID, adminUserID uuid.UUID) error {
	dismissal := models.ResourceServerDriftEventDismissal{
		EventID:     eventID,
		AdminUserID: adminUserID,
		DismissedAt: time.Now().UTC(),
	}
	return s.db.
		Where("event_id = ? AND admin_user_id = ?", eventID, adminUserID).
		FirstOrCreate(&dismissal).Error
}
