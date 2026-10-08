package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	stderrors "errors"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
	"github.com/authsec-ai/authsec/internal/spire/domain/repositories"
	"github.com/authsec-ai/authsec/internal/spire/errors"
	"github.com/authsec-ai/authsec/internal/tenancy"
)

// PostgresCertificateRepository stores certificates issued to attested
// workloads (spire_certificates) of the workspace carried by ctx.
type PostgresCertificateRepository struct {
	db *sql.DB
}

// NewPostgresCertificateRepository creates the certificate repository.
func NewPostgresCertificateRepository(db *sql.DB) repositories.CertificateRepository {
	return &PostgresCertificateRepository{db: db}
}

const certificateColumns = `id::text, workspace_id::text, workload_id::text, serial_number,
	COALESCE(sha256_fingerprint, ''), spiffe_id, cert_pem, ca_chain, issued_at, expires_at,
	revoked_at, status, issue_type, created_at`

// GetBySerialNumber returns a certificate of ctx's workspace.
func (r *PostgresCertificateRepository) GetBySerialNumber(ctx context.Context, serialNumber string) (*models.Certificate, error) {
	return r.getOne(ctx, `SELECT `+certificateColumns+` FROM spire_certificates
		WHERE workspace_id = $1 AND serial_number = $2`, serialNumber)
}

// GetActiveByWorkload returns the newest active certificate of a workload of
// ctx's workspace.
func (r *PostgresCertificateRepository) GetActiveByWorkload(ctx context.Context, workloadID string) (*models.Certificate, error) {
	if _, err := uuid.Parse(workloadID); err != nil {
		return nil, errors.NewNotFoundError("Certificate not found", nil)
	}
	return r.getOne(ctx, `SELECT `+certificateColumns+` FROM spire_certificates
		WHERE workspace_id = $1 AND workload_id = $2 AND status = 'active'
		ORDER BY issued_at DESC LIMIT 1`, workloadID)
}

func (r *PostgresCertificateRepository) getOne(ctx context.Context, query string, arg interface{}) (*models.Certificate, error) {
	c := &models.Certificate{}
	var chain []byte
	var revoked sql.NullTime
	err := tenancy.QueryRowContext(ctx, r.db, query, []interface{}{arg},
		&c.ID, &c.WorkspaceID, &c.WorkloadID, &c.SerialNumber, &c.SHA256Fingerprint, &c.SpiffeID,
		&c.CertPEM, &chain, &c.IssuedAt, &c.ExpiresAt, &revoked, &c.Status, &c.IssueType, &c.CreatedAt)
	if stderrors.Is(err, tenancy.ErrNotFound) {
		return nil, errors.NewNotFoundError("Certificate not found", err)
	}
	if err != nil {
		return nil, errors.NewInternalError("Failed to get certificate", err)
	}
	if revoked.Valid {
		c.RevokedAt = &revoked.Time
	}
	if len(chain) > 0 {
		_ = json.Unmarshal(chain, &c.CAChain)
	}
	return c, nil
}

// Create inserts a certificate for ctx's workspace.
func (r *PostgresCertificateRepository) Create(ctx context.Context, cert *models.Certificate) error {
	ws, err := workspaceOf(ctx)
	if err != nil {
		return err
	}
	if cert.ID == "" {
		cert.ID = uuid.NewString()
	}
	cert.WorkspaceID = ws.String()
	cert.CreatedAt = time.Now()
	chain, err := json.Marshal(cert.CAChain)
	if err != nil {
		return errors.NewInternalError("Failed to marshal CA chain", err)
	}
	_, err = tenancy.InsertContext(ctx, r.db, `
		INSERT INTO spire_certificates (
			workspace_id, id, workload_id, serial_number, sha256_fingerprint, spiffe_id, cert_pem,
			ca_chain, issued_at, expires_at, status, issue_type, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		cert.ID, cert.WorkloadID, cert.SerialNumber, nullString(cert.SHA256Fingerprint), cert.SpiffeID,
		cert.CertPEM, chain, cert.IssuedAt, cert.ExpiresAt, cert.Status, cert.IssueType, cert.CreatedAt)
	if err != nil {
		return errors.NewInternalError("Failed to create certificate", err)
	}
	return nil
}

// Revoke marks a certificate of ctx's workspace revoked.
func (r *PostgresCertificateRepository) Revoke(ctx context.Context, id string) error {
	if _, err := uuid.Parse(id); err != nil {
		return errors.NewNotFoundError("Certificate not found", nil)
	}
	res, err := tenancy.ExecContext(ctx, r.db, `
		UPDATE spire_certificates SET status = 'revoked', revoked_at = now()
		 WHERE workspace_id = $1 AND id = $2 AND revoked_at IS NULL`, id)
	if err != nil {
		return errors.NewInternalError("Failed to revoke certificate", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.NewNotFoundError("Certificate not found", nil)
	}
	return nil
}
