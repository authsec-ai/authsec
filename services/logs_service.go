package services

import (
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/monitoring"
	"gorm.io/gorm"
)

// LogsService is the read layer behind the Logs UI. It serves the existing,
// already-workspace-scoped audit tables — it does NOT introduce a new event
// store. Sources:
//   - audit_events          → auth logs (resource='authentication') + admin/config audit
//   - auth_issuance_audit   → M2M token-issuance logs
//
// SPIRE audit logs are served separately by SpireController.
type LogsService struct {
	db *gorm.DB
}

// NewLogsService builds a LogsService over the shared DB handle.
func NewLogsService(db *gorm.DB) *LogsService {
	return &LogsService{db: db}
}

const (
	defaultLogLimit = 50
	maxLogLimit     = 200
	resourceAuthn   = "authentication"
)

func clampPage(page, limit int) (int, int) {
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > maxLogLimit {
		limit = defaultLogLimit
	}
	return page, limit
}

// AuthLogs returns authentication events for a workspace (most recent first).
// status is optional ("success"/"failure"); action is an optional exact match.
func (s *LogsService) AuthLogs(workspaceID, status, action string, page, limit int) ([]monitoring.AuditEvent, int64, error) {
	page, limit = clampPage(page, limit)

	q := s.db.Model(&monitoring.AuditEvent{}).
		Where("workspace_id = ? AND resource = ?", workspaceID, resourceAuthn)
	if action != "" {
		q = q.Where("action = ?", action)
	}
	switch status {
	case "success":
		q = q.Where("error = '' OR error IS NULL")
	case "failure":
		q = q.Where("error <> ''")
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var rows []monitoring.AuditEvent
	err := q.Order("timestamp DESC").
		Offset((page - 1) * limit).Limit(limit).
		Find(&rows).Error
	return rows, total, err
}

// AuditLogs returns admin/config audit events for a workspace — everything in
// audit_events that is NOT an authentication event.
func (s *LogsService) AuditLogs(workspaceID, action, resource string, page, limit int) ([]monitoring.AuditEvent, int64, error) {
	page, limit = clampPage(page, limit)

	q := s.db.Model(&monitoring.AuditEvent{}).
		Where("workspace_id = ? AND resource <> ?", workspaceID, resourceAuthn)
	if action != "" {
		q = q.Where("action = ?", action)
	}
	if resource != "" {
		q = q.Where("resource = ?", resource)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var rows []monitoring.AuditEvent
	err := q.Order("timestamp DESC").
		Offset((page - 1) * limit).Limit(limit).
		Find(&rows).Error
	return rows, total, err
}

// M2MLogs returns machine-to-machine token-issuance records for a workspace.
func (s *LogsService) M2MLogs(workspaceID, clientID string, page, limit int) ([]models.AuthIssuanceAudit, int64, error) {
	page, limit = clampPage(page, limit)

	q := s.db.Model(&models.AuthIssuanceAudit{}).
		Where("workspace_id = ?", workspaceID)
	if clientID != "" {
		q = q.Where("client_id = ?", clientID)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var rows []models.AuthIssuanceAudit
	err := q.Order("created_at DESC").
		Offset((page - 1) * limit).Limit(limit).
		Find(&rows).Error
	return rows, total, err
}
