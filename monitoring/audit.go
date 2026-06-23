package monitoring

import (
	"encoding/json"
	"time"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// AuditEvent represents an auditable event
type AuditEvent struct {
	ID          uint   `json:"id" gorm:"primaryKey"`
	RequestID   string `json:"request_id" gorm:"index"`
	WorkspaceID string `json:"workspace_id" gorm:"index"`
	// ActorRealm records which login surface the event came from
	// (admin / enduser / service / system). Keeps workspace_id clean — see
	// migrations/master/001_bootstrap.sql audit_events.
	ActorRealm string    `json:"actor_realm"`
	UserID     string    `json:"user_id" gorm:"index"`
	Action     string    `json:"action" gorm:"index"`
	Resource   string    `json:"resource" gorm:"index"`
	ResourceID string    `json:"resource_id"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	UserAgent  string    `json:"user_agent"`
	ClientIP   string    `json:"client_ip"`
	StatusCode int       `json:"status_code"`
	Duration   int64     `json:"duration_ms"` // in milliseconds
	OldValues  *string   `json:"old_values,omitempty" gorm:"type:jsonb"`
	NewValues  *string   `json:"new_values,omitempty" gorm:"type:jsonb"`
	Error      string    `json:"error,omitempty"`
	Timestamp  time.Time `json:"timestamp" gorm:"index"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// AuditLogger handles audit logging operations
type AuditLogger struct {
	db     *gorm.DB
	logger *logrus.Logger
}

// NewAuditLogger creates a new audit logger instance
func NewAuditLogger(db *gorm.DB) *AuditLogger {
	return &AuditLogger{
		db:     db,
		logger: GetLogger(),
	}
}

// InitAuditTable is a deliberate no-op: the audit_events table is created by
// migrations/master/001_bootstrap.sql. GORM AutoMigrate is reserved for
// migration_logs only (see cmd/main.go and CLAUDE.md). Kept as a no-op for
// API compatibility; any caller that depended on it will continue to compile.
func (al *AuditLogger) InitAuditTable() error {
	return nil
}

// LogEvent logs an audit event
func (al *AuditLogger) LogEvent(event *AuditEvent) {
	// Set timestamp if not set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Log to database asynchronously
	go func() {
		if err := al.db.Create(event).Error; err != nil {
			al.logger.WithFields(logrus.Fields{
				"error":      err.Error(),
				"request_id": event.RequestID,
				"action":     event.Action,
			}).Error("Failed to save audit event to database")
		}
	}()

	// Log to structured logger
	al.logger.WithFields(logrus.Fields{
		"request_id":   event.RequestID,
		"workspace_id": event.WorkspaceID,
		"user_id":      event.UserID,
		"action":       event.Action,
		"resource":     event.Resource,
		"resource_id":  event.ResourceID,
		"method":       event.Method,
		"path":         event.Path,
		"status_code":  event.StatusCode,
		"duration_ms":  event.Duration,
		"client_ip":    event.ClientIP,
		"error":        event.Error,
	}).Info("Audit event")
}

// LogAuthentication logs authentication events.
//
// workspaceID must be a real workspace UUID, or "" when the flow has no
// workspace yet (e.g. a pre-auth admin login failure). Do NOT pass the realm
// here — that's what actorRealm is for ("admin" / "enduser" / "service" /
// "system"). This separation keeps audit_events.workspace_id queryable.
func (al *AuditLogger) LogAuthentication(requestID, workspaceID, actorRealm, userID, action, clientIP, userAgent string, success bool, errorMsg string) {
	status := "success"
	if !success {
		status = "failure"
	}

	event := &AuditEvent{
		RequestID:   requestID,
		WorkspaceID: workspaceID,
		ActorRealm:  actorRealm,
		UserID:      userID,
		Action:      action,
		Resource:    "authentication",
		ClientIP:    clientIP,
		UserAgent:   userAgent,
		StatusCode:  200,
		Error:       errorMsg,
	}

	// Add status to action
	event.Action = action + "_" + status

	al.LogEvent(event)
}

// LogAdminAction logs administrative actions
func (al *AuditLogger) LogAdminAction(requestID, workspaceID, userID, action, resource, resourceID, method, path, clientIP, userAgent string, statusCode int, duration time.Duration, oldValues, newValues interface{}, errorMsg string) {
	event := &AuditEvent{
		RequestID:   requestID,
		WorkspaceID: workspaceID,
		UserID:      userID,
		Action:      action,
		Resource:    resource,
		ResourceID:  resourceID,
		Method:      method,
		Path:        path,
		ClientIP:    clientIP,
		UserAgent:   userAgent,
		StatusCode:  statusCode,
		Duration:    duration.Milliseconds(),
		Error:       errorMsg,
	}

	// Serialize old/new values to JSON if provided
	if oldValues != nil {
		if jsonData, err := json.Marshal(oldValues); err == nil {
			jsonStr := string(jsonData)
			event.OldValues = &jsonStr
		} else {
			// If marshaling fails, set to NULL (empty string causes jsonb error in PostgreSQL)
			event.OldValues = nil
		}
	}

	if newValues != nil {
		if jsonData, err := json.Marshal(newValues); err == nil {
			jsonStr := string(jsonData)
			event.NewValues = &jsonStr
		} else {
			// If marshaling fails, set to NULL (empty string causes jsonb error in PostgreSQL)
			event.NewValues = nil
		}
	}

	al.LogEvent(event)
}

// LogTenantAction logs tenant-specific actions
func (al *AuditLogger) LogTenantAction(requestID, workspaceID, userID, action, resource, resourceID, method, path, clientIP, userAgent string, statusCode int, duration time.Duration, errorMsg string) {
	event := &AuditEvent{
		RequestID:   requestID,
		WorkspaceID: workspaceID,
		UserID:      userID,
		Action:      action,
		Resource:    resource,
		ResourceID:  resourceID,
		Method:      method,
		Path:        path,
		ClientIP:    clientIP,
		UserAgent:   userAgent,
		StatusCode:  statusCode,
		Duration:    duration.Milliseconds(),
		Error:       errorMsg,
	}

	al.LogEvent(event)
}

// GetAuditEvents retrieves audit events with filtering
func (al *AuditLogger) GetAuditEvents(workspaceID, userID, action, resource string, limit, offset int) ([]AuditEvent, int64, error) {
	var events []AuditEvent
	var total int64

	query := al.db.Model(&AuditEvent{})

	// Apply filters
	if workspaceID != "" {
		query = query.Where("workspace_id = ?", workspaceID)
	}
	if userID != "" {
		query = query.Where("user_id = ?", userID)
	}
	if action != "" {
		query = query.Where("action = ?", action)
	}
	if resource != "" {
		query = query.Where("resource = ?", resource)
	}

	// Get total count
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get paginated results
	err := query.Order("timestamp DESC").
		Limit(limit).
		Offset(offset).
		Find(&events).Error

	return events, total, err
}

// CleanupOldEvents removes audit events older than the specified duration
func (al *AuditLogger) CleanupOldEvents(olderThan time.Duration) error {
	cutoff := time.Now().Add(-olderThan)
	result := al.db.Where("timestamp < ?", cutoff).Delete(&AuditEvent{})

	if result.Error != nil {
		return result.Error
	}

	al.logger.WithFields(logrus.Fields{
		"deleted_count": result.RowsAffected,
		"cutoff_date":   cutoff,
	}).Info("Cleaned up old audit events")

	return nil
}
