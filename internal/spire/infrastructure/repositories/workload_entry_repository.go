package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
	"github.com/authsec-ai/authsec/internal/spire/domain/repositories"
	"github.com/authsec-ai/authsec/internal/spire/errors"
	"github.com/authsec-ai/authsec/internal/tenancy"
)

// PostgresWorkloadEntryRepository stores registration entries
// (spire_workload_entries) and issued workload SVIDs (spire_workload_svids)
// of the workspace carried by ctx.
type PostgresWorkloadEntryRepository struct {
	db     *sql.DB
	logger *logrus.Entry
}

// NewPostgresWorkloadEntryRepository creates the workload entry repository.
func NewPostgresWorkloadEntryRepository(db *sql.DB, logger *logrus.Entry) repositories.WorkloadEntryRepository {
	return &PostgresWorkloadEntryRepository{db: db, logger: logger}
}

const entryColumns = `id::text, workspace_id::text, spiffe_id, parent_id, selectors, ttl, admin, downstream, created_at, updated_at`

func scanEntry(scan func(...interface{}) error) (*models.WorkloadEntry, error) {
	var e models.WorkloadEntry
	var selectors []byte
	var ttl sql.NullInt64
	if err := scan(&e.ID, &e.WorkspaceID, &e.SpiffeID, &e.ParentID, &selectors, &ttl,
		&e.Admin, &e.Downstream, &e.CreatedAt, &e.UpdatedAt); err != nil {
		return nil, err
	}
	if ttl.Valid {
		v := int(ttl.Int64)
		e.TTL = &v
	}
	if err := json.Unmarshal(selectors, &e.Selectors); err != nil {
		return nil, fmt.Errorf("failed to unmarshal selectors: %w", err)
	}
	return &e, nil
}

func (r *PostgresWorkloadEntryRepository) queryEntries(ctx context.Context, query string, args ...interface{}) ([]*models.WorkloadEntry, error) {
	rows, err := tenancy.QueryContext(ctx, r.db, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query workload entries: %w", err)
	}
	defer rows.Close()
	var out []*models.WorkloadEntry
	for rows.Next() {
		e, err := scanEntry(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("failed to scan workload entry: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Create inserts an entry for ctx's workspace.
func (r *PostgresWorkloadEntryRepository) Create(ctx context.Context, entry *models.WorkloadEntry) error {
	ws, err := workspaceOf(ctx)
	if err != nil {
		return err
	}
	if entry.ID == "" {
		entry.ID = uuid.NewString()
	}
	entry.WorkspaceID = ws.String()
	if err := entry.Validate(); err != nil {
		return err
	}
	selectors, err := json.Marshal(entry.Selectors)
	if err != nil {
		return fmt.Errorf("failed to marshal selectors: %w", err)
	}
	now := time.Now()
	entry.CreatedAt, entry.UpdatedAt = now, now
	_, err = tenancy.InsertContext(ctx, r.db, `
		INSERT INTO spire_workload_entries (
			workspace_id, id, spiffe_id, parent_id, selectors, ttl, admin, downstream, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		entry.ID, entry.SpiffeID, entry.ParentID, selectors, entry.TTL, entry.Admin,
		entry.Downstream, entry.CreatedAt, entry.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "uq_spire_workload_entries_workspace_spiffe") {
			return errors.NewConflictError("A workload entry with this SPIFFE ID already exists", err)
		}
		return fmt.Errorf("failed to create workload entry: %w", err)
	}
	return nil
}

// GetByID returns the entry with this id in ctx's workspace, or (nil, nil).
func (r *PostgresWorkloadEntryRepository) GetByID(ctx context.Context, id string) (*models.WorkloadEntry, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, nil
	}
	return r.getOne(ctx, `SELECT `+entryColumns+` FROM spire_workload_entries WHERE workspace_id = $1 AND id = $2`, id)
}

// GetBySpiffeID returns the entry with this SPIFFE ID in ctx's workspace, or (nil, nil).
func (r *PostgresWorkloadEntryRepository) GetBySpiffeID(ctx context.Context, spiffeID string) (*models.WorkloadEntry, error) {
	return r.getOne(ctx, `SELECT `+entryColumns+` FROM spire_workload_entries WHERE workspace_id = $1 AND spiffe_id = $2`, spiffeID)
}

func (r *PostgresWorkloadEntryRepository) getOne(ctx context.Context, query string, arg interface{}) (*models.WorkloadEntry, error) {
	entries, err := r.queryEntries(ctx, query, arg)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}
	return entries[0], nil
}

// filterSQL renders the optional filters; args continue after the caller's.
func filterSQL(filter *models.WorkloadEntryFilter, args []interface{}) (string, []interface{}) {
	var b strings.Builder
	next := func(v interface{}) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args)+1) // $1 is the workspace
	}
	if filter.ParentID != "" {
		b.WriteString(" AND parent_id = " + next(filter.ParentID))
	}
	if filter.SpiffeID != "" {
		if filter.SpiffeIDPartial {
			b.WriteString(" AND spiffe_id ILIKE " + next("%"+filter.SpiffeID+"%"))
		} else {
			b.WriteString(" AND spiffe_id = " + next(filter.SpiffeID))
		}
	}
	if filter.Admin != nil {
		b.WriteString(" AND admin = " + next(*filter.Admin))
	}
	switch filter.SelectorType {
	case "unix":
		b.WriteString(" AND selectors ?| array['unix:uid','unix:gid','unix:pid','unix:user','unix:group']")
	case "kubernetes":
		b.WriteString(" AND selectors ?| array['k8s:ns','k8s:sa','k8s:pod-name','k8s:pod-uid','k8s:pod-label:app']")
	case "docker":
		b.WriteString(" AND selectors ?| array['docker:label','docker:env','docker:image_id']")
	}
	return b.String(), args
}

// List returns ctx's workspace's entries matching filter.
func (r *PostgresWorkloadEntryRepository) List(ctx context.Context, filter *models.WorkloadEntryFilter) ([]*models.WorkloadEntry, error) {
	where, args := filterSQL(filter, nil)
	query := `SELECT ` + entryColumns + ` FROM spire_workload_entries WHERE workspace_id = $1` + where + ` ORDER BY created_at DESC`
	if filter.Limit > 0 {
		args = append(args, filter.Limit)
		query += fmt.Sprintf(" LIMIT $%d", len(args)+1)
	}
	if filter.Offset > 0 {
		args = append(args, filter.Offset)
		query += fmt.Sprintf(" OFFSET $%d", len(args)+1)
	}
	return r.queryEntries(ctx, query, args...)
}

// Count counts ctx's workspace's entries matching filter (no paging).
func (r *PostgresWorkloadEntryRepository) Count(ctx context.Context, filter *models.WorkloadEntryFilter) (int, error) {
	where, args := filterSQL(filter, nil)
	var n int
	err := tenancy.QueryRowContext(ctx, r.db,
		`SELECT COUNT(*) FROM spire_workload_entries WHERE workspace_id = $1`+where, args, &n)
	if err != nil {
		return 0, fmt.Errorf("failed to count workload entries: %w", err)
	}
	return n, nil
}

// ListByParent returns the entries of this agent, plus unassigned ones.
func (r *PostgresWorkloadEntryRepository) ListByParent(ctx context.Context, parentID string) ([]*models.WorkloadEntry, error) {
	return r.queryEntries(ctx, `SELECT `+entryColumns+` FROM spire_workload_entries
		WHERE workspace_id = $1 AND (parent_id = $2 OR parent_id = '') ORDER BY created_at DESC`, parentID)
}

// Update rewrites an entry of ctx's workspace.
func (r *PostgresWorkloadEntryRepository) Update(ctx context.Context, entry *models.WorkloadEntry) error {
	ws, err := workspaceOf(ctx)
	if err != nil {
		return err
	}
	if _, err := uuid.Parse(entry.ID); err != nil {
		return errors.NewNotFoundError("Workload entry not found", nil)
	}
	entry.WorkspaceID = ws.String()
	if err := entry.Validate(); err != nil {
		return err
	}
	selectors, err := json.Marshal(entry.Selectors)
	if err != nil {
		return fmt.Errorf("failed to marshal selectors: %w", err)
	}
	entry.UpdatedAt = time.Now()
	res, err := tenancy.ExecContext(ctx, r.db, `
		UPDATE spire_workload_entries
		   SET spiffe_id = $3, parent_id = $4, selectors = $5, ttl = $6, admin = $7,
		       downstream = $8, updated_at = $9
		 WHERE workspace_id = $1 AND id = $2`,
		entry.ID, entry.SpiffeID, entry.ParentID, selectors, entry.TTL, entry.Admin,
		entry.Downstream, entry.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "uq_spire_workload_entries_workspace_spiffe") {
			return errors.NewConflictError("A workload entry with this SPIFFE ID already exists", err)
		}
		return fmt.Errorf("failed to update workload entry: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.NewNotFoundError("Workload entry not found", nil)
	}
	return nil
}

// Delete removes an entry of ctx's workspace.
func (r *PostgresWorkloadEntryRepository) Delete(ctx context.Context, id string) error {
	if _, err := uuid.Parse(id); err != nil {
		return errors.NewNotFoundError("Workload entry not found", nil)
	}
	res, err := tenancy.ExecContext(ctx, r.db, `DELETE FROM spire_workload_entries WHERE workspace_id = $1 AND id = $2`, id)
	if err != nil {
		return fmt.Errorf("failed to delete workload entry: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.NewNotFoundError("Workload entry not found", nil)
	}
	return nil
}

// FindMatchingEntries returns entries of ctx's workspace whose selectors are
// all among the given ones.
func (r *PostgresWorkloadEntryRepository) FindMatchingEntries(ctx context.Context, selectors map[string]string) ([]*models.WorkloadEntry, error) {
	sel, err := json.Marshal(selectors)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal selectors: %w", err)
	}
	return r.queryEntries(ctx, `SELECT `+entryColumns+` FROM spire_workload_entries
		WHERE workspace_id = $1 AND $2::jsonb @> selectors ORDER BY created_at DESC`, sel)
}

// RecordSVID stores an issued workload SVID for ctx's workspace.
func (r *PostgresWorkloadEntryRepository) RecordSVID(ctx context.Context, s *models.WorkloadSVID) error {
	_, err := tenancy.InsertContext(ctx, r.db, `
		INSERT INTO spire_workload_svids (
			workspace_id, entry_id, agent_spiffe_id, spiffe_id, serial_number, ttl, issued_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, now(), $7)
		ON CONFLICT (workspace_id, serial_number) DO NOTHING`,
		s.EntryID, nullString(s.AgentSpiffeID), s.SpiffeID, s.SerialNumber, s.TTL, nullTime(s.ExpiresAt))
	return err
}

// GetSVIDBySerial returns an SVID of ctx's workspace by serial number.
func (r *PostgresWorkloadEntryRepository) GetSVIDBySerial(ctx context.Context, serial string) (*models.WorkloadSVID, error) {
	s := &models.WorkloadSVID{}
	var ttl sql.NullInt64
	var expires, revoked sql.NullTime
	err := tenancy.QueryRowContext(ctx, r.db, `
		SELECT id::text, workspace_id::text, entry_id::text, COALESCE(agent_spiffe_id, ''), spiffe_id,
		       serial_number, ttl, expires_at, revoked_at
		  FROM spire_workload_svids WHERE workspace_id = $1 AND serial_number = $2`,
		[]interface{}{serial}, &s.ID, &s.WorkspaceID, &s.EntryID, &s.AgentSpiffeID, &s.SpiffeID,
		&s.SerialNumber, &ttl, &expires, &revoked)
	if stderrors.Is(err, tenancy.ErrNotFound) {
		return nil, errors.NewNotFoundError("Workload SVID not found", nil)
	}
	if err != nil {
		return nil, errors.NewInternalError("Failed to get workload SVID", err)
	}
	s.TTL = int(ttl.Int64)
	s.ExpiresAt = expires.Time
	if revoked.Valid {
		s.RevokedAt = &revoked.Time
	}
	return s, nil
}

// MarkSVIDRevoked records the revocation of an SVID of ctx's workspace.
func (r *PostgresWorkloadEntryRepository) MarkSVIDRevoked(ctx context.Context, serial string) error {
	_, err := tenancy.ExecContext(ctx, r.db, `
		UPDATE spire_workload_svids SET revoked_at = now()
		 WHERE workspace_id = $1 AND serial_number = $2 AND revoked_at IS NULL`, serial)
	return err
}
