package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// DriftService writes + reads drift events for Applications post-activation.
// Lean tenant-scoped equivalent of dev's ResourceServerDriftService.
//
// Emit semantics on the backport:
//   - We only emit when the Application is in state=ready. Pre-activation
//     mutations are part of setup, not drift, so they don't generate events.
//   - Emit failures are logged but do NOT block the originating mutation —
//     drift logging is observability, not authoritative state.
type DriftService struct{}

func NewDriftService() *DriftService { return &DriftService{} }

// EmitEvent records a drift event for the given Application. Best-effort:
// errors are returned but callers should NOT abort their primary mutation
// on a drift-emit failure. Pass occurredBy=nil for system-triggered events
// (e.g. reconciler-driven secret_rotated retries).
//
// If the Application is not currently in state=ready, this is a no-op
// (returns nil). This matches dev's behavior of only surfacing "what
// changed since activation" in the banner.
func (s *DriftService) EmitEvent(
	tenantID string,
	applicationID uuid.UUID,
	eventType string,
	payload interface{},
	occurredBy *uuid.UUID,
) error {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return fmt.Errorf("get tenant db: %w", err)
	}

	// Check Application state — only emit if ready.
	var rs models.ResourceServer
	if err := tenantDB.Select("id, state").
		Where("id = ? AND tenant_id = ?", applicationID, tenantID).
		First(&rs).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil // no application => no event; not an error
		}
		return fmt.Errorf("load application: %w", err)
	}
	if rs.State != models.RSStateReady {
		return nil
	}

	var payloadBytes datatypes.JSON
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal payload: %w", err)
		}
		payloadBytes = datatypes.JSON(b)
	}

	event := models.ApplicationDriftEvent{
		TenantID:      tenantID,
		ApplicationID: applicationID,
		EventType:     eventType,
		EventPayload:  payloadBytes,
		OccurredAt:    time.Now().UTC(),
		OccurredBy:    occurredBy,
	}
	if err := tenantDB.Create(&event).Error; err != nil {
		return fmt.Errorf("insert drift event: %w", err)
	}
	return nil
}

// DriftEventView is the read shape — adds dismissed-by-me flag.
type DriftEventView struct {
	models.ApplicationDriftEvent
	DismissedByMe bool `json:"dismissed_by_me"`
}

// List returns drift events for an Application, optionally filtered to
// "undismissed by the calling admin." Returns empty slice (not nil) when
// no events match. When adminUserID is uuid.Nil, returns all events without
// the dismissed filter.
//
// undismissedOnly=true filters out events the calling admin has dismissed.
// Useful for the banner. Pass false to see the full audit log.
func (s *DriftService) List(
	tenantID string,
	applicationID uuid.UUID,
	adminUserID uuid.UUID,
	undismissedOnly bool,
) ([]DriftEventView, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}

	// Load the Application's setup_completed_at so we don't surface
	// pre-activation events that slipped in (shouldn't happen — EmitEvent
	// gates on state=ready — but cheap defence).
	var rs models.ResourceServer
	if err := tenantDB.Select("id, setup_completed_at").
		Where("id = ? AND tenant_id = ?", applicationID, tenantID).
		First(&rs).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrResourceServerNotFound
		}
		return nil, err
	}

	q := tenantDB.Where("application_id = ?", applicationID)
	if rs.SetupCompletedAt != nil {
		q = q.Where("occurred_at >= ?", *rs.SetupCompletedAt)
	}
	if undismissedOnly && adminUserID != uuid.Nil {
		q = q.Where(`id NOT IN (
            SELECT event_id FROM application_drift_event_dismissals
             WHERE admin_user_id = ?
        )`, adminUserID)
	}

	var events []models.ApplicationDriftEvent
	if err := q.Order("occurred_at DESC").Find(&events).Error; err != nil {
		return nil, fmt.Errorf("list drift events: %w", err)
	}

	// Fetch dismissals for this admin to fill DismissedByMe.
	dismissedByMe := map[uuid.UUID]struct{}{}
	if adminUserID != uuid.Nil && len(events) > 0 {
		ids := make([]uuid.UUID, 0, len(events))
		for _, e := range events {
			ids = append(ids, e.ID)
		}
		var rows []models.ApplicationDriftEventDismissal
		if err := tenantDB.Where("event_id IN ? AND admin_user_id = ?", ids, adminUserID).
			Find(&rows).Error; err != nil {
			return nil, fmt.Errorf("load dismissals: %w", err)
		}
		for _, r := range rows {
			dismissedByMe[r.EventID] = struct{}{}
		}
	}

	out := make([]DriftEventView, 0, len(events))
	for _, e := range events {
		_, dismissed := dismissedByMe[e.ID]
		out = append(out, DriftEventView{
			ApplicationDriftEvent: e,
			DismissedByMe:         dismissed,
		})
	}
	return out, nil
}

// Dismiss records that adminUserID has dismissed eventID. Idempotent —
// re-dismissing is a no-op. Returns ErrResourceServerNotFound if the event
// doesn't exist (or doesn't belong to the tenant).
func (s *DriftService) Dismiss(
	tenantID string,
	eventID uuid.UUID,
	adminUserID uuid.UUID,
) error {
	if adminUserID == uuid.Nil {
		return fmt.Errorf("admin_user_id required")
	}
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return fmt.Errorf("get tenant db: %w", err)
	}
	// Verify event exists in this tenant.
	var event models.ApplicationDriftEvent
	if err := tenantDB.Where("id = ? AND tenant_id = ?", eventID, tenantID).
		First(&event).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrResourceServerNotFound
		}
		return err
	}
	dismissal := models.ApplicationDriftEventDismissal{
		EventID:     eventID,
		AdminUserID: adminUserID,
		DismissedAt: time.Now().UTC(),
	}
	return tenantDB.Where("event_id = ? AND admin_user_id = ?", eventID, adminUserID).
		FirstOrCreate(&dismissal).Error
}
