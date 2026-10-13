package tenancy

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// InWorkspace runs fn in one transaction under row-level security for ws:
// app.workspace_id set and the restricted role assumed (see RLSTransaction).
// It is for code that knows its workspace without a request (background
// jobs, verified callbacks) and for services handed a workspace by their
// handler. Every statement fn runs on tx sees and writes only ws's rows,
// whatever its SQL says.
func InWorkspace(ctx context.Context, db *gorm.DB, ws uuid.UUID, fn func(tx *gorm.DB) error) error {
	return inWorkspace(ctx, db, ws, nil, fn)
}

// InWorkspaceRead is InWorkspace in a read-only transaction.
func InWorkspaceRead(ctx context.Context, db *gorm.DB, ws uuid.UUID, fn func(tx *gorm.DB) error) error {
	return inWorkspace(ctx, db, ws, &sql.TxOptions{ReadOnly: true}, fn)
}

func inWorkspace(ctx context.Context, db *gorm.DB, ws uuid.UUID, opts *sql.TxOptions, fn func(tx *gorm.DB) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if ws == uuid.Nil {
		return ErrNoTenant
	}
	ctx = WithContext(ctx, Context{WorkspaceID: ws})
	return RLSTransaction(ctx, db, opts, func(tx *gorm.DB, _ uuid.UUID) error { return fn(tx) })
}
