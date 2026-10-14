package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
	"github.com/authsec-ai/authsec/internal/spire/domain/repositories"
	"github.com/authsec-ai/authsec/internal/spire/errors"
	"github.com/authsec-ai/authsec/internal/tenancy"
)

// PostgresAuditRepository stores the attest / renew / revoke audit trail
// (spire_icp_audit_logs, append-only) of the workspace carried by ctx.
type PostgresAuditRepository struct {
	db *sql.DB
}

// NewPostgresAuditRepository creates the audit repository.
func NewPostgresAuditRepository(db *sql.DB) repositories.AuditRepository {
	return &PostgresAuditRepository{db: db}
}

// Create appends an audit record for ctx's workspace.
func (r *PostgresAuditRepository) Create(ctx context.Context, log *models.AuditLog) error {
	ws, err := workspaceOf(ctx)
	if err != nil {
		return err
	}
	if log.ID == "" {
		log.ID = uuid.NewString()
	}
	log.WorkspaceID = ws.String()
	log.CreatedAt = time.Now()
	metadata, err := json.Marshal(log.Metadata)
	if err != nil {
		return errors.NewInternalError("Failed to marshal metadata", err)
	}
	_, err = tenancy.InsertContext(ctx, r.db, `
		INSERT INTO spire_icp_audit_logs (
			workspace_id, id, event_type, workload_id, certificate_id, spiffe_id, success,
			error_message, metadata, ip_address, user_agent, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		log.ID, string(log.EventType), nullString(log.WorkloadID), nullString(log.CertificateID),
		nullString(log.SpiffeID), log.Success, nullString(log.ErrorMessage), metadata,
		nullString(log.IPAddress), nullString(log.UserAgent), log.CreatedAt)
	if err != nil {
		return errors.NewInternalError("Failed to create audit log", err)
	}
	return nil
}

// List returns ctx's workspace's audit records, newest first.
func (r *PostgresAuditRepository) List(ctx context.Context, limit, offset int) ([]*models.AuditLog, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := tenancy.QueryContext(ctx, r.db, `
		SELECT id::text, workspace_id::text, event_type, COALESCE(workload_id, ''), COALESCE(certificate_id, ''),
		       COALESCE(spiffe_id, ''), success, COALESCE(error_message, ''), metadata,
		       COALESCE(ip_address, ''), COALESCE(user_agent, ''), created_at
		  FROM spire_icp_audit_logs
		 WHERE workspace_id = $1
		 ORDER BY created_at DESC
		 LIMIT $2 OFFSET $3`, limit, offset)
	if err != nil {
		return nil, errors.NewInternalError("Failed to query audit logs", err)
	}
	defer rows.Close()
	var logs []*models.AuditLog
	for rows.Next() {
		l := &models.AuditLog{}
		var eventType string
		var metadata []byte
		if err := rows.Scan(&l.ID, &l.WorkspaceID, &eventType, &l.WorkloadID, &l.CertificateID, &l.SpiffeID,
			&l.Success, &l.ErrorMessage, &metadata, &l.IPAddress, &l.UserAgent, &l.CreatedAt); err != nil {
			return nil, errors.NewInternalError("Failed to scan audit log", err)
		}
		l.EventType = models.AuditEventType(eventType)
		if len(metadata) > 0 {
			_ = json.Unmarshal(metadata, &l.Metadata)
		}
		logs = append(logs, l)
	}
	return logs, rows.Err()
}
