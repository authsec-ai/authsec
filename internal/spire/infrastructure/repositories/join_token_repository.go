package repositories

import (
	"context"
	"database/sql"
	stderrors "errors"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
	"github.com/authsec-ai/authsec/internal/spire/domain/repositories"
	"github.com/authsec-ai/authsec/internal/spire/errors"
	"github.com/authsec-ai/authsec/internal/tenancy"
)

// PostgresJoinTokenRepository stores node attestation join tokens
// (spire_join_tokens). Only the SHA-256 of a token is stored.
type PostgresJoinTokenRepository struct {
	db *sql.DB
}

// NewPostgresJoinTokenRepository creates the join token repository.
func NewPostgresJoinTokenRepository(db *sql.DB) repositories.JoinTokenRepository {
	return &PostgresJoinTokenRepository{db: db}
}

// Create stores a token for ctx's workspace.
func (r *PostgresJoinTokenRepository) Create(ctx context.Context, t *models.JoinToken, tokenHash string) error {
	ws, err := workspaceOf(ctx)
	if err != nil {
		return err
	}
	if t.ID == "" {
		t.ID = uuid.NewString()
	}
	t.WorkspaceID = ws.String()
	t.CreatedAt = time.Now()
	var createdBy interface{}
	if id, err := uuid.Parse(t.CreatedBy); err == nil {
		createdBy = id
	}
	_, err = tenancy.InsertContext(ctx, r.db, `
		INSERT INTO spire_join_tokens (workspace_id, id, token_hash, description, created_by, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		t.ID, tokenHash, nullString(t.Description), createdBy, t.ExpiresAt, t.CreatedAt)
	if err != nil {
		return errors.NewInternalError("Failed to store join token", err)
	}
	return nil
}

// List returns ctx's workspace's tokens, newest first, without hashes.
func (r *PostgresJoinTokenRepository) List(ctx context.Context) ([]*models.JoinToken, error) {
	rows, err := tenancy.QueryContext(ctx, r.db, `
		SELECT id::text, workspace_id::text, COALESCE(description, ''), COALESCE(created_by::text, ''),
		       expires_at, used_at, COALESCE(used_by_node_id, ''), revoked_at, created_at
		  FROM spire_join_tokens
		 WHERE workspace_id = $1
		 ORDER BY created_at DESC
		 LIMIT 500`)
	if err != nil {
		return nil, errors.NewInternalError("Failed to list join tokens", err)
	}
	defer rows.Close()
	out := []*models.JoinToken{}
	for rows.Next() {
		t := &models.JoinToken{}
		var used, revoked sql.NullTime
		if err := rows.Scan(&t.ID, &t.WorkspaceID, &t.Description, &t.CreatedBy, &t.ExpiresAt,
			&used, &t.UsedByNodeID, &revoked, &t.CreatedAt); err != nil {
			return nil, errors.NewInternalError("Failed to scan join token", err)
		}
		if used.Valid {
			t.UsedAt = &used.Time
		}
		if revoked.Valid {
			t.RevokedAt = &revoked.Time
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.NewInternalError("Failed to list join tokens", err)
	}
	return out, nil
}

// Revoke revokes an unused token of ctx's workspace. Another workspace's
// token, or none, is not found.
func (r *PostgresJoinTokenRepository) Revoke(ctx context.Context, id string) error {
	if _, err := uuid.Parse(id); err != nil {
		return errors.NewNotFoundError("Join token not found", nil)
	}
	res, err := tenancy.ExecContext(ctx, r.db, `
		UPDATE spire_join_tokens SET revoked_at = now()
		 WHERE workspace_id = $1 AND id = $2 AND revoked_at IS NULL`, id)
	if err != nil {
		return errors.NewInternalError("Failed to revoke join token", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.NewNotFoundError("Join token not found", nil)
	}
	return nil
}

// Consume marks the token used, atomically: one UPDATE that matches only an
// unused, unexpired, unrevoked token, so two concurrent attestations with
// the same token cannot both succeed.
func (r *PostgresJoinTokenRepository) Consume(ctx context.Context, tokenHash, nodeID, assertedWorkspace string) (*models.JoinToken, error) {
	t := &models.JoinToken{}
	var used sql.NullTime
	// TENANT-EXEMPT: node attestation precedes any workspace; the token, selected by the SHA-256 of 32 random bytes, decides it.
	err := r.db.QueryRowContext(ctx, `
		UPDATE spire_join_tokens
		   SET used_at = now(), used_by_node_id = $2
		 WHERE token_hash = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > now()
		   AND ($3 = '' OR workspace_id::text = $3)
		RETURNING id::text, workspace_id::text, expires_at, used_at, created_at`,
		tokenHash, nodeID, assertedWorkspace).Scan(&t.ID, &t.WorkspaceID, &t.ExpiresAt, &used, &t.CreatedAt)
	if stderrors.Is(err, sql.ErrNoRows) {
		return nil, errors.NewUnauthorizedError("Join token is invalid, expired, revoked or already used", nil)
	}
	if err != nil {
		return nil, errors.NewInternalError("Failed to consume join token", err)
	}
	if used.Valid {
		t.UsedAt = &used.Time
	}
	t.UsedByNodeID = nodeID
	return t, nil
}
