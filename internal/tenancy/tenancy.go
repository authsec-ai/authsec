// Package tenancy is the single place a request's workspace (the tenant) is
// carried and applied to data access (ADR-0001 §4).
//
// The workspace is resolved once, by the auth middleware, from the verified
// token, and stored with Set. Everything below reads it with From and lets
// this package add the workspace predicate:
//
//   - GORM:          tenancy.DB(c, config.DB).Where(...).Find(&rows)
//   - database/sql:  tenancy.QueryRow(c, db, "SELECT ... WHERE workspace_id = $1 AND id = $2", id)
//   - lookups by id: tenancy.Get(c, config.DB, &model, id)  -> ErrNotFound for other workspaces
//   - RLS:           tenancy.WithTx(ctx, db, ws, func(tx *sql.Tx) error { ... })
//
// A raw query that deliberately bypasses this package must carry a
// "// TENANT-EXEMPT: <reason>" comment (see scripts/check-tenant-exempt.sh).
package tenancy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Context is the tenant context of one request.
type Context struct {
	WorkspaceID   uuid.UUID
	PrincipalID   uuid.UUID
	PrincipalKind string // "user", "service_account", ...
	Realm         string // "admin", "enduser", "sdk", ...
}

const ginKey = "tenancy.context"

var (
	// ErrNoTenant means no workspace was resolved for the request: the
	// handler is reachable without authentication or the middleware is missing.
	ErrNoTenant = errors.New("tenancy: no workspace in request context")
	// ErrNotFound is returned for rows that do not exist in the caller's
	// workspace, including rows that exist in another one. Map it to 404.
	ErrNotFound = errors.New("tenancy: not found")
	// ErrUnscopedQuery rejects raw SQL that does not bind workspace_id to $1.
	ErrUnscopedQuery = errors.New("tenancy: query must filter on workspace_id = $1")
)

// Set stores the tenant context. Only authentication middleware calls it.
func Set(c *gin.Context, tc Context) {
	c.Set(ginKey, tc)
	c.Request = c.Request.WithContext(WithContext(c.Request.Context(), tc))
}

// From returns the request's tenant context.
func From(c *gin.Context) (Context, error) {
	if v, ok := c.Get(ginKey); ok {
		if tc, ok := v.(Context); ok && tc.WorkspaceID != uuid.Nil {
			return tc, nil
		}
	}
	return Context{}, ErrNoTenant
}

type ctxKey struct{}

// WithContext attaches the tenant context to a context.Context, for code
// below the HTTP layer (services, jobs).
func WithContext(ctx context.Context, tc Context) context.Context {
	return context.WithValue(ctx, ctxKey{}, tc)
}

// FromContext reads the tenant context from a context.Context.
func FromContext(ctx context.Context) (Context, error) {
	if tc, ok := ctx.Value(ctxKey{}).(Context); ok && tc.WorkspaceID != uuid.Nil {
		return tc, nil
	}
	return Context{}, ErrNoTenant
}

// Scope is a GORM scope that restricts a query to one workspace.
func Scope(workspaceID uuid.UUID) func(*gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("workspace_id = ?", workspaceID)
	}
}

// DB returns db restricted to the request's workspace.
func DB(c *gin.Context, db *gorm.DB) (*gorm.DB, error) {
	tc, err := From(c)
	if err != nil {
		return nil, err
	}
	return db.WithContext(c.Request.Context()).Scopes(Scope(tc.WorkspaceID)), nil
}

// Get loads the row with primary key id into dst, only if it belongs to the
// request's workspace. Another workspace's row is ErrNotFound.
func Get(c *gin.Context, db *gorm.DB, dst interface{}, id interface{}) error {
	scoped, err := DB(c, db)
	if err != nil {
		return err
	}
	if err := scoped.Where("id = ?", id).First(dst).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

// workspacePredicate matches "workspace_id = $1", optionally table-qualified.
var workspacePredicate = regexp.MustCompile(`(?i)(^|[^a-z0-9_])([a-z0-9_]+\.)?workspace_id\s*=\s*\$1([^0-9]|$)`)

// CheckScoped reports whether a raw statement binds workspace_id to $1.
func CheckScoped(query string) error {
	if !workspacePredicate.MatchString(query) {
		return ErrUnscopedQuery
	}
	return nil
}

// Querier is satisfied by *sql.DB, *sql.Tx and *sql.Conn.
type Querier interface {
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

func scopedArgs(c *gin.Context, query string, args []interface{}) (context.Context, []interface{}, error) {
	if err := CheckScoped(query); err != nil {
		return nil, nil, err
	}
	tc, err := From(c)
	if err != nil {
		return nil, nil, err
	}
	return c.Request.Context(), append([]interface{}{tc.WorkspaceID}, args...), nil
}

// Query runs a statement whose $1 is the request's workspace; args start at $2.
func Query(c *gin.Context, q Querier, query string, args ...interface{}) (*sql.Rows, error) {
	ctx, all, err := scopedArgs(c, query, args)
	if err != nil {
		return nil, err
	}
	return q.QueryContext(ctx, query, all...)
}

// Exec runs a statement whose $1 is the request's workspace; args start at $2.
func Exec(c *gin.Context, q Querier, query string, args ...interface{}) (sql.Result, error) {
	ctx, all, err := scopedArgs(c, query, args)
	if err != nil {
		return nil, err
	}
	return q.ExecContext(ctx, query, all...)
}

// QueryRow scans one row of a statement whose $1 is the request's workspace.
// No row (including another workspace's) is ErrNotFound.
func QueryRow(c *gin.Context, q Querier, query string, args []interface{}, dest ...interface{}) error {
	ctx, all, err := scopedArgs(c, query, args)
	if err != nil {
		return err
	}
	if err := q.QueryRowContext(ctx, query, all...).Scan(dest...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

// WithTx runs fn in a transaction whose session variable app.workspace_id is
// the given workspace, which Postgres row-level security policies check
// (ADR-0001 §4.4). SET LOCAL scope ends with the transaction, so this is safe
// on pooled connections.
func WithTx(ctx context.Context, db *sql.DB, workspaceID uuid.UUID, fn func(*sql.Tx) error) error {
	if workspaceID == uuid.Nil {
		return ErrNoTenant
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.workspace_id', $1, true)`, workspaceID.String()); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("tenancy: set app.workspace_id: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// HTTPStatus maps an error from this package to the status a handler should
// answer: 401 when no workspace was resolved, 404 for another workspace's (or
// a missing) row, 500 otherwise.
func HTTPStatus(err error) int {
	switch {
	case err == nil:
		return 200
	case errors.Is(err, ErrNoTenant):
		return 401
	case errors.Is(err, ErrNotFound), errors.Is(err, gorm.ErrRecordNotFound), errors.Is(err, sql.ErrNoRows):
		return 404
	default:
		return 500
	}
}

// Workspace returns the request's workspace id, or ErrNoTenant.
func Workspace(c *gin.Context) (uuid.UUID, error) {
	tc, err := From(c)
	if err != nil {
		return uuid.Nil, err
	}
	return tc.WorkspaceID, nil
}
