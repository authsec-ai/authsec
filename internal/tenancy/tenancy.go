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
// Repositories and services below the HTTP layer use the context.Context
// forms (DBContext, QueryContext, ExecContext, QueryRowContext) with the
// request's context, which carries the same tenant context.
//
// A raw query that deliberately bypasses this package must carry a
// "// TENANT-EXEMPT: <reason>" comment (see scripts/check-tenant-exempt.sh).
package tenancy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sync"

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

// DB returns db restricted to the request's workspace. The result is a new
// session, so it can be reused for several queries without one query's
// conditions leaking into the next.
func DB(c *gin.Context, db *gorm.DB) (*gorm.DB, error) {
	return DBContext(c.Request.Context(), db)
}

// DBContext is DB for code below the HTTP layer: the workspace comes from the
// tenant context carried by ctx (see WithContext).
func DBContext(ctx context.Context, db *gorm.DB) (*gorm.DB, error) {
	tc, err := FromContext(ctx)
	if err != nil {
		return nil, err
	}
	return db.WithContext(ctx).Scopes(Scope(tc.WorkspaceID)).Session(&gorm.Session{}), nil
}

// Get loads the row with primary key id into dst, only if it belongs to the
// request's workspace. Another workspace's row is ErrNotFound. It runs under
// row-level security (see Transaction).
func Get(c *gin.Context, db *gorm.DB, dst interface{}, id interface{}) error {
	err := Transaction(c.Request.Context(), db, func(tx *gorm.DB) error {
		return tx.Where("id = ?", id).First(dst).Error
	})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	return err
}

// Transaction runs fn in a GORM transaction for the workspace carried by ctx,
// with the workspace predicate applied and Postgres row-level security in
// force (app.workspace_id set, and the restricted role when available), so a
// query that forgets its own scoping still cannot reach another workspace.
func Transaction(ctx context.Context, db *gorm.DB, fn func(tx *gorm.DB) error) error {
	tc, err := FromContext(ctx)
	if err != nil {
		return err
	}
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		sqlDB, _ := db.DB()
		if err := tx.Exec(`SELECT set_config('app.workspace_id', ?, true)`, tc.WorkspaceID.String()).Error; err != nil {
			return fmt.Errorf("tenancy: set app.workspace_id: %w", err)
		}
		if role := rlsRole(ctx, sqlDB); role != "" {
			if err := tx.Exec(`SET LOCAL ROLE ` + role).Error; err != nil {
				return fmt.Errorf("tenancy: set role: %w", err)
			}
		}
		return fn(tx.Scopes(Scope(tc.WorkspaceID)).Session(&gorm.Session{}))
	})
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

func scopedArgs(ctx context.Context, query string, args []interface{}) ([]interface{}, error) {
	if err := CheckScoped(query); err != nil {
		return nil, err
	}
	tc, err := FromContext(ctx)
	if err != nil {
		return nil, err
	}
	return append([]interface{}{tc.WorkspaceID}, args...), nil
}

// Query runs a statement whose $1 is the request's workspace; args start at $2.
func Query(c *gin.Context, q Querier, query string, args ...interface{}) (*sql.Rows, error) {
	return QueryContext(c.Request.Context(), q, query, args...)
}

// Exec runs a statement whose $1 is the request's workspace; args start at $2.
func Exec(c *gin.Context, q Querier, query string, args ...interface{}) (sql.Result, error) {
	return ExecContext(c.Request.Context(), q, query, args...)
}

// QueryRow scans one row of a statement whose $1 is the request's workspace.
// No row (including another workspace's) is ErrNotFound.
func QueryRow(c *gin.Context, q Querier, query string, args []interface{}, dest ...interface{}) error {
	return QueryRowContext(c.Request.Context(), q, query, args, dest...)
}

// QueryContext is Query for code below the HTTP layer (repositories,
// services): the workspace comes from the tenant context carried by ctx.
func QueryContext(ctx context.Context, q Querier, query string, args ...interface{}) (*sql.Rows, error) {
	all, err := scopedArgs(ctx, query, args)
	if err != nil {
		return nil, err
	}
	return q.QueryContext(ctx, query, all...)
}

// ExecContext is Exec for code below the HTTP layer. Given a *sql.DB it runs
// under row-level security (see WithTx).
func ExecContext(ctx context.Context, q Querier, query string, args ...interface{}) (sql.Result, error) {
	all, err := scopedArgs(ctx, query, args)
	if err != nil {
		return nil, err
	}
	if db, ok := q.(*sql.DB); ok {
		var res sql.Result
		err := WithTx(ctx, db, all[0].(uuid.UUID), func(tx *sql.Tx) error {
			var e error
			res, e = tx.ExecContext(ctx, query, all...)
			return e
		})
		return res, err
	}
	return q.ExecContext(ctx, query, all...)
}

// QueryRowContext is QueryRow for code below the HTTP layer.
func QueryRowContext(ctx context.Context, q Querier, query string, args []interface{}, dest ...interface{}) error {
	all, err := scopedArgs(ctx, query, args)
	if err != nil {
		return err
	}
	if db, ok := q.(*sql.DB); ok {
		err = WithTx(ctx, db, all[0].(uuid.UUID), func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, query, all...).Scan(dest...)
		})
	} else {
		err = q.QueryRowContext(ctx, query, all...).Scan(dest...)
	}
	if err != nil {
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
	if role := rlsRole(ctx, db); role != "" {
		if _, err := tx.ExecContext(ctx, `SET LOCAL ROLE `+role); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("tenancy: set role: %w", err)
		}
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

// rlsRole returns the restricted role scoped transactions switch to, or "" when
// it does not exist or this connection cannot assume it (migration 054 creates
// it; scripts/create-tenant-role.sql does when the migration could not).
// Switching matters because Postgres exempts superusers from row-level
// security. AUTHSEC_RLS_ROLE=off disables the switch.
func rlsRole(ctx context.Context, db *sql.DB) string {
	name := os.Getenv("AUTHSEC_RLS_ROLE")
	if name == "off" || db == nil {
		return ""
	}
	if name == "" {
		name = "authsec_tenant"
	}
	if !roleNamePattern.MatchString(name) {
		return ""
	}
	key := roleCacheKey{db: db, role: name}
	if v, ok := roleCache.Load(key); ok {
		if v.(bool) {
			return name
		}
		return ""
	}
	var ok bool
	err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)
		AND pg_has_role(current_user, (SELECT oid FROM pg_roles WHERE rolname = $1), 'MEMBER')`, name).Scan(&ok)
	if err != nil {
		return "" // not cached: retried on the next transaction
	}
	roleCache.Store(key, ok)
	if ok {
		return name
	}
	return ""
}

type roleCacheKey struct {
	db   *sql.DB
	role string
}

var (
	roleCache       sync.Map
	roleNamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
)
