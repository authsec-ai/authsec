package monitoring

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// AuditEvent represents an auditable event.
//
// Seq, PrevHash and Hash are the row's link in its workspace's hash chain
// (migration 167): the database trigger assigns them on insert, so they are
// read-only here and a writer can never choose them.
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
	// RecordClass decides the row's retention (audit_retention_policy):
	// admin_change, auth, access_decision, export or default. Set from the
	// action by ClassifyAuditRecord when empty.
	RecordClass string  `json:"record_class,omitempty"`
	Seq         *int64  `json:"seq,omitempty" gorm:"<-:false"`
	PrevHash    *string `json:"prev_hash,omitempty" gorm:"<-:false"`
	Hash        *string `json:"hash,omitempty" gorm:"<-:false"`
}

// Audit record classes (migration 167's CHECK).
const (
	AuditClassAdminChange    = "admin_change"
	AuditClassAuth           = "auth"
	AuditClassAccessDecision = "access_decision"
	AuditClassExport         = "export"
	AuditClassDefault        = "default"
)

// AuditRecordClasses lists every record class.
var AuditRecordClasses = []string{AuditClassAdminChange, AuditClassAuth, AuditClassAccessDecision, AuditClassExport, AuditClassDefault}

// ClassifyAuditRecord is the record class of e: authentication events are
// auth; an export is export; an approval, denial or other decision on access
// is access_decision; any other write (a method that changes state, or an
// actor) is admin_change; everything else is default.
func ClassifyAuditRecord(e *AuditEvent) string {
	a := strings.ToLower(e.Action)
	r := strings.ToLower(e.Resource)
	switch {
	case r == "authentication" || strings.Contains(a, "login") || strings.Contains(a, "logout") ||
		strings.HasPrefix(a, "mfa") || strings.Contains(a, "webauthn"):
		return AuditClassAuth
	case strings.Contains(a, "export") || strings.Contains(r, "export"):
		return AuditClassExport
	case r == "access_request" || r == "agent_action" || r == "consent_grant" ||
		strings.Contains(a, "approve") || strings.Contains(a, "denied") || strings.Contains(a, "deny") ||
		strings.Contains(a, "reject") || strings.Contains(a, "decide") || strings.Contains(a, "decision"):
		return AuditClassAccessDecision
	}
	switch strings.ToUpper(e.Method) {
	case "POST", "PUT", "PATCH", "DELETE":
		return AuditClassAdminChange
	}
	if e.UserID != "" && e.UserID != "system" {
		return AuditClassAdminChange
	}
	return AuditClassDefault
}

// AuditWriteFailure is an audit event that could not be written after the
// writer's retries (migration 167). The whole event is kept so the audit
// governance job replays it into the chain; until then the loss is visible
// (GET /api/iga/v1/audit/write-failures, a governance event, the metric).
type AuditWriteFailure struct {
	ID          uuid.UUID       `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID *uuid.UUID      `gorm:"type:uuid"`
	Event       json.RawMessage `gorm:"type:jsonb"`
	Error       string
	Attempts    int
	State       string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// TableName is audit_write_failure.
func (AuditWriteFailure) TableName() string { return "audit_write_failure" }

// Write retries: a failed insert is tried auditWriteAttempts times, waiting
// auditWriteBackoff between tries, each bounded by auditWriteTimeout.
var (
	auditWriteAttempts = 3
	auditWriteBackoff  = []time.Duration{50 * time.Millisecond, 200 * time.Millisecond}
	auditWriteTimeout  = 3 * time.Second
)

// auditWriteFailures counts audit events not written on the request path
// (stage "write": recorded in audit_write_failure for replay) and events
// that could not even be recorded (stage "record": only the error log holds
// them). Alert on any increase of stage="record".
var (
	auditWriteFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "authsec_audit_write_failures_total",
		Help: "Audit events whose insert failed after retries (stage=write, recorded for replay) or could not be recorded at all (stage=record).",
	}, []string{"stage"})
	auditWriteFailuresRegister sync.Once
)

func countAuditWriteFailure(stage string) {
	auditWriteFailuresRegister.Do(func() {
		if err := prometheus.Register(auditWriteFailures); err != nil {
			var are prometheus.AlreadyRegisteredError
			if !errors.As(err, &are) {
				log.Printf("could not register authsec_audit_write_failures_total: %v", err)
			}
		}
	})
	auditWriteFailures.WithLabelValues(stage).Inc()
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

func (al *AuditLogger) log() *logrus.Logger {
	if al.logger != nil {
		return al.logger
	}
	if l := GetLogger(); l != nil {
		return l
	}
	return logrus.StandardLogger()
}

// prepareAuditEvent fills the timestamp and the record class.
func prepareAuditEvent(event *AuditEvent) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	if event.RecordClass == "" {
		event.RecordClass = ClassifyAuditRecord(event)
	}
}

// LogEvent writes an audit event SYNCHRONOUSLY (F7: it used to be a
// goroutine whose failures were only logged). See Write.
func (al *AuditLogger) LogEvent(event *AuditEvent) {
	_ = al.Write(event)
}

// Write inserts the event and returns once it is in audit_events (and so in
// its workspace's hash chain), retrying a failed insert.
//
// Callers on the request path (auditAdminMutation and the rest) write AFTER
// their mutation committed, so a failure here cannot undo the mutation and
// must not be reported to the client as the mutation failing. Instead the
// loss is never silent: the event is recorded in audit_write_failure for
// replay into the chain, counted (authsec_audit_write_failures_total) and
// logged at error with the whole event, and Write returns the error.
// Where the change is made in one transaction, WriteTx writes the audit row
// in that same transaction instead.
func (al *AuditLogger) Write(event *AuditEvent) error {
	prepareAuditEvent(event)
	al.logStructured(event)
	if al.db == nil {
		countAuditWriteFailure("record")
		return errors.New("audit logger has no database")
	}
	var err error
	for attempt := 1; attempt <= auditWriteAttempts; attempt++ {
		row := *event
		row.ID = 0
		ctx, cancel := context.WithTimeout(context.Background(), auditWriteTimeout)
		err = al.db.WithContext(ctx).Clauses(chainReturning).Create(&row).Error
		cancel()
		if err == nil {
			event.ID, event.Seq, event.PrevHash, event.Hash = row.ID, row.Seq, row.PrevHash, row.Hash
			return nil
		}
		if attempt < auditWriteAttempts && attempt <= len(auditWriteBackoff) {
			time.Sleep(auditWriteBackoff[attempt-1])
		}
	}
	al.recordFailure(event, err, auditWriteAttempts)
	return err
}

// WriteTx inserts the event in tx, the caller's own transaction: the audit
// row commits or rolls back with the change it records.
func (al *AuditLogger) WriteTx(tx *gorm.DB, event *AuditEvent) error {
	return WriteAuditTx(tx, event)
}

// WriteAuditTx is WriteTx without a logger (services that own a transaction).
func WriteAuditTx(tx *gorm.DB, event *AuditEvent) error {
	prepareAuditEvent(event)
	return tx.Clauses(chainReturning).Create(event).Error
}

// chainReturning reads back the link the chain trigger assigned.
var chainReturning = clause.Returning{Columns: []clause.Column{{Name: "id"}, {Name: "seq"}, {Name: "prev_hash"}, {Name: "hash"}}}

// recordFailure makes a failed write visible: metric, error log with the
// whole event, and an audit_write_failure row for the replay job.
func (al *AuditLogger) recordFailure(event *AuditEvent, writeErr error, attempts int) {
	countAuditWriteFailure("write")
	raw, _ := json.Marshal(event)
	al.log().WithFields(logrus.Fields{
		"error":        writeErr.Error(),
		"request_id":   event.RequestID,
		"workspace_id": event.WorkspaceID,
		"action":       event.Action,
		"attempts":     attempts,
		"event":        string(raw),
	}).Error("audit event not written; recording it in audit_write_failure for replay")

	f := AuditWriteFailure{Event: raw, Error: truncate(writeErr.Error(), 2000), Attempts: attempts, State: "pending"}
	if ws, err := uuid.Parse(event.WorkspaceID); err == nil {
		f.WorkspaceID = &ws
	}
	ctx, cancel := context.WithTimeout(context.Background(), auditWriteTimeout)
	defer cancel()
	err := al.db.WithContext(ctx).Create(&f).Error
	if err != nil && f.WorkspaceID != nil {
		// A workspace that no longer exists fails the foreign key: keep the
		// event as a platform failure rather than lose it.
		f.WorkspaceID, f.ID = nil, uuid.Nil
		err = al.db.WithContext(ctx).Create(&f).Error
	}
	if err != nil {
		countAuditWriteFailure("record")
		al.log().WithFields(logrus.Fields{
			"error":       err.Error(),
			"write_error": writeErr.Error(),
			"event":       string(raw),
		}).Error("AUDIT EVENT LOST: neither audit_events nor audit_write_failure accepted it; this log line is its only record")
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (al *AuditLogger) logStructured(event *AuditEvent) {
	al.log().WithFields(logrus.Fields{
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
		"record_class": event.RecordClass,
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
