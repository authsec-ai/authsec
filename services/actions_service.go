package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

// ---------------------------------------------------------------------------
// Filter & cursor types
// ---------------------------------------------------------------------------

// ActionFilter selects activity rows for a list query.
type ActionFilter struct {
	TimeFrom    *time.Time `form:"time_from"`
	TimeTo      *time.Time `form:"time_to"`
	EventFamily string     `form:"event_family"`
	Operation   string     `form:"operation"`
	Outcome     string     `form:"outcome"`
	Source      string     `form:"source"`
	PolicyRef   *uuid.UUID `form:"policy_ref"`
}

// actionCursor is the internal representation of a cursor token. It is
// base64-encoded JSON in the wire format.
type actionCursor struct {
	Workspace uuid.UUID `json:"w"`
	Scope     string    `json:"s"` // "workload", "collector", or "changes"
	ScopeID   uuid.UUID `json:"si"`
	Sequence  int64     `json:"q"`
	Direction string    `json:"d"` // "forward"
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

// ActionPage is a cursor-paginated list of action summaries.
type ActionPage struct {
	Items   []ActionSummary `json:"items"`
	Cursor  string          `json:"cursor,omitempty"`
	HasMore bool            `json:"has_more"`
}

// ActionSummary is the wire representation of one activity row in a list.
type ActionSummary struct {
	ActionID          uuid.UUID  `json:"action_id"`
	ObservedAt        time.Time  `json:"observed_at"`
	EventFamily       string     `json:"event_family"`
	Operation         string     `json:"operation,omitempty"`
	ResourceID        *uuid.UUID `json:"resource_id,omitempty"`
	IdentityAccountID *uuid.UUID `json:"identity_account_id,omitempty"`
	Outcome           string     `json:"outcome"`
	Phase             string     `json:"phase,omitempty"`
	Result            string     `json:"result,omitempty"`
	PolicyRef         *uuid.UUID `json:"policy_ref,omitempty"`
	Count             int        `json:"count"`
	Source            string     `json:"source,omitempty"`
	RuntimeInstanceID *uuid.UUID `json:"runtime_instance_id,omitempty"`
}

// ActionDetail is the full representation of one activity row.
type ActionDetail struct {
	models.IGARuntimeActivity
}

// ActionChangesPage is a forward catch-up page keyed on activity_sequence.
type ActionChangesPage struct {
	Items   []ActionSummary `json:"items"`
	Cursor  string          `json:"cursor,omitempty"`
	HasMore bool            `json:"has_more"`
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

const (
	actionsDefaultLimit = 100
	actionsMaxLimit     = 500
)

// ActionsService queries the activity index (iga_runtime_activity) for the
// Actions API surface.
type ActionsService struct {
	db *gorm.DB
}

// NewActionsService constructs the service.
func NewActionsService(db *gorm.DB) *ActionsService {
	return &ActionsService{db: db}
}

// ListForWorkload returns actions attributed to a workload, ordered newest
// first by activity_sequence.
func (s *ActionsService) ListForWorkload(
	ctx context.Context,
	workspaceID, workloadID uuid.UUID,
	cursor string,
	limit int,
	filters ActionFilter,
) (*ActionPage, error) {
	limit = clampLimit(limit)
	q := s.baseQuery(ctx, workspaceID, filters).
		Where("workload_id = ?", workloadID)

	if cursor != "" {
		cur, err := decodeActionCursor(cursor)
		if err != nil {
			return nil, fmt.Errorf("invalid cursor: %w", err)
		}
		q = q.Where("activity_sequence < ?", cur.Sequence)
	}

	rows, err := s.fetch(q, limit)
	if err != nil {
		return nil, err
	}

	return s.buildPage(rows, limit, "workload", workspaceID, workloadID), nil
}

// ListForCollector returns actions from a collector, including unattributed
// events (workload_id IS NULL), ordered newest first.
func (s *ActionsService) ListForCollector(
	ctx context.Context,
	workspaceID, collectorID uuid.UUID,
	cursor string,
	limit int,
	filters ActionFilter,
) (*ActionPage, error) {
	limit = clampLimit(limit)
	q := s.baseQuery(ctx, workspaceID, filters).
		Where("collector_id = ?", collectorID)

	if cursor != "" {
		cur, err := decodeActionCursor(cursor)
		if err != nil {
			return nil, fmt.Errorf("invalid cursor: %w", err)
		}
		q = q.Where("activity_sequence < ?", cur.Sequence)
	}

	rows, err := s.fetch(q, limit)
	if err != nil {
		return nil, err
	}

	return s.buildPage(rows, limit, "collector", workspaceID, collectorID), nil
}

// Get returns the full detail of one action by its action_id.
func (s *ActionsService) Get(
	ctx context.Context,
	workspaceID, actionID uuid.UUID,
) (*ActionDetail, error) {
	var row models.IGARuntimeActivity
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND action_id = ?", workspaceID, actionID).
		First(&row).Error
	if err != nil {
		return nil, err
	}
	return &ActionDetail{IGARuntimeActivity: row}, nil
}

// Changes returns a forward catch-up page ordered by ascending
// activity_sequence — suitable for consumers that want every activity event
// since a known position.
func (s *ActionsService) Changes(
	ctx context.Context,
	workspaceID uuid.UUID,
	cursor string,
	limit int,
) (*ActionChangesPage, error) {
	limit = clampLimit(limit)
	q := s.db.WithContext(ctx).
		Model(&models.IGARuntimeActivity{}).
		Where("workspace_id = ?", workspaceID)

	if cursor != "" {
		cur, err := decodeActionCursor(cursor)
		if err != nil {
			return nil, fmt.Errorf("invalid cursor: %w", err)
		}
		q = q.Where("activity_sequence > ?", cur.Sequence)
	}

	var rows []models.IGARuntimeActivity
	if err := q.Order("activity_sequence ASC").Limit(limit + 1).Find(&rows).Error; err != nil {
		return nil, err
	}

	hasMore := len(rows) > limit
	if hasMore {
		rows = rows[:limit]
	}

	items := make([]ActionSummary, len(rows))
	for i, r := range rows {
		items[i] = toSummary(r)
	}

	var nextCursor string
	if hasMore && len(rows) > 0 {
		last := rows[len(rows)-1]
		nextCursor = encodeActionCursor(actionCursor{
			Workspace: workspaceID,
			Scope:     "changes",
			ScopeID:   uuid.Nil,
			Sequence:  last.ActivitySequence,
			Direction: "forward",
		})
	}

	return &ActionChangesPage{
		Items:   items,
		Cursor:  nextCursor,
		HasMore: hasMore,
	}, nil
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

func (s *ActionsService) baseQuery(ctx context.Context, workspaceID uuid.UUID, f ActionFilter) *gorm.DB {
	q := s.db.WithContext(ctx).
		Model(&models.IGARuntimeActivity{}).
		Where("workspace_id = ?", workspaceID)

	if f.TimeFrom != nil {
		q = q.Where("observed_at >= ?", *f.TimeFrom)
	}
	if f.TimeTo != nil {
		q = q.Where("observed_at <= ?", *f.TimeTo)
	}
	if f.EventFamily != "" {
		q = q.Where("event_family = ?", f.EventFamily)
	}
	if f.Operation != "" {
		q = q.Where("operation = ?", f.Operation)
	}
	if f.Outcome != "" {
		q = q.Where("outcome = ?", f.Outcome)
	}
	if f.Source != "" {
		q = q.Where("source = ?", f.Source)
	}
	if f.PolicyRef != nil {
		q = q.Where("policy_ref = ?", *f.PolicyRef)
	}
	return q
}

func (s *ActionsService) fetch(q *gorm.DB, limit int) ([]models.IGARuntimeActivity, error) {
	var rows []models.IGARuntimeActivity
	if err := q.Order("activity_sequence DESC").Limit(limit + 1).Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

func (s *ActionsService) buildPage(rows []models.IGARuntimeActivity, limit int, scope string, workspaceID, scopeID uuid.UUID) *ActionPage {
	hasMore := len(rows) > limit
	if hasMore {
		rows = rows[:limit]
	}

	items := make([]ActionSummary, len(rows))
	for i, r := range rows {
		items[i] = toSummary(r)
	}

	var nextCursor string
	if hasMore && len(rows) > 0 {
		last := rows[len(rows)-1]
		nextCursor = encodeActionCursor(actionCursor{
			Workspace: workspaceID,
			Scope:     scope,
			ScopeID:   scopeID,
			Sequence:  last.ActivitySequence,
			Direction: "forward",
		})
	}

	return &ActionPage{
		Items:   items,
		Cursor:  nextCursor,
		HasMore: hasMore,
	}
}

func toSummary(r models.IGARuntimeActivity) ActionSummary {
	return ActionSummary{
		ActionID:          r.ActionID,
		ObservedAt:        r.ObservedAt,
		EventFamily:       r.EventFamily,
		Operation:         r.Operation,
		ResourceID:        r.ResourceID,
		IdentityAccountID: r.IdentityAccountID,
		Outcome:           r.Outcome,
		Phase:             r.Phase,
		Result:            r.Result,
		PolicyRef:         r.PolicyRef,
		Count:             r.Count,
		Source:            r.Source,
		RuntimeInstanceID: r.RuntimeInstanceID,
	}
}

func clampLimit(limit int) int {
	if limit <= 0 {
		return actionsDefaultLimit
	}
	if limit > actionsMaxLimit {
		return actionsMaxLimit
	}
	return limit
}

func encodeActionCursor(c actionCursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeActionCursor(s string) (*actionCursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	var c actionCursor
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
