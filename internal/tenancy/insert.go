package tenancy

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
)

// ErrNotInsert is returned by InsertContext for a statement that is not an
// INSERT.
var ErrNotInsert = errors.New("tenancy: InsertContext runs INSERT statements only")

var insertStatement = regexp.MustCompile(`(?is)^\s*INSERT\s+INTO\s`)

// InsertContext runs an INSERT whose $1 is ctx's workspace (the row's
// workspace_id column takes $1), inside a row-level security transaction:
// the policy's WITH CHECK refuses a row for any other workspace. The caller's
// arguments start at $2. Use it for INSERT ... VALUES, which cannot carry
// the workspace_id = $1 predicate ExecContext requires.
func InsertContext(ctx context.Context, db *sql.DB, query string, args ...interface{}) (sql.Result, error) {
	if !insertStatement.MatchString(query) {
		return nil, ErrNotInsert
	}
	tc, err := FromContext(ctx)
	if err != nil {
		return nil, err
	}
	var res sql.Result
	err = WithTx(ctx, db, tc.WorkspaceID, func(tx *sql.Tx) error {
		var e error
		res, e = tx.ExecContext(ctx, query, append([]interface{}{tc.WorkspaceID}, args...)...)
		return e
	})
	return res, err
}
