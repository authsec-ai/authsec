package database

import (
	"context"
	"database/sql"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/google/uuid"
)

// WithWorkspace returns ctx carrying workspace ws as its tenant, for code that
// resolved the workspace from a credential or a row it already trusts (a login
// ticket, an OAuth client, a CIBA request, a background job's row) rather than
// from an authenticated request, whose context already carries it.
func WithWorkspace(ctx context.Context, ws uuid.UUID) context.Context {
	if tc, err := tenancy.FromContext(ctx); err == nil && tc.WorkspaceID == ws {
		return ctx
	}
	return tenancy.WithContext(ctx, tenancy.Context{WorkspaceID: ws})
}

// ctxWorkspace returns the workspace carried by ctx.
func ctxWorkspace(ctx context.Context) (uuid.UUID, error) {
	tc, err := tenancy.FromContext(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	return tc.WorkspaceID, nil
}

// queryScoped runs a SELECT whose $1 is ctx's workspace (tenancy.CheckScoped
// refuses one that does not bind workspace_id = $1) inside a row-level
// security transaction, and calls each for every row. args start at $2.
func queryScoped(ctx context.Context, db *sql.DB, query string, args []interface{}, each func(*sql.Rows) error) error {
	ws, err := ctxWorkspace(ctx)
	if err != nil {
		return err
	}
	return tenancy.WithTx(ctx, db, ws, func(tx *sql.Tx) error {
		rows, err := tenancy.QueryContext(ctx, tx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			if err := each(rows); err != nil {
				return err
			}
		}
		return rows.Err()
	})
}

// insertScoped runs an INSERT whose $1 is ctx's workspace inside a row-level
// security transaction: the policy's WITH CHECK refuses a row for any other
// workspace. args start at $2.
func insertScoped(ctx context.Context, db *sql.DB, query string, args ...interface{}) error {
	ws, err := ctxWorkspace(ctx)
	if err != nil {
		return err
	}
	return tenancy.WithTx(ctx, db, ws, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, query, append([]interface{}{ws}, args...)...)
		return err
	})
}

// affected returns the rows a statement changed, for "updated nothing"
// checks; a driver that cannot tell counts as one.
func affected(res sql.Result) int64 {
	n, err := res.RowsAffected()
	if err != nil {
		return 1
	}
	return n
}
