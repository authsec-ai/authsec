package tenancy

import (
	"context"

	"gorm.io/gorm"
)

// GORM forms of the scoped statements, for code that already holds a
// *gorm.DB (often a GORM transaction). Like ExecContext and QueryRowContext,
// the statement must bind workspace_id to $1, which is set to the workspace
// of ctx's tenant context; the caller's arguments start at $2. Run on the
// tx of RLSTransaction they are also enforced by row-level security.
//
// A statement that is not scoped, or a ctx without a tenant, yields a
// *gorm.DB whose Error is set and which runs nothing.

// GormExec runs a scoped statement.
func GormExec(ctx context.Context, db *gorm.DB, query string, args ...interface{}) *gorm.DB {
	all, err := scopedArgs(ctx, query, args)
	if err != nil {
		return failed(db, err)
	}
	return db.WithContext(ctx).Exec(query, all...)
}

// GormRaw prepares a scoped query; finish it with Scan, Row or Rows.
func GormRaw(ctx context.Context, db *gorm.DB, query string, args ...interface{}) *gorm.DB {
	all, err := scopedArgs(ctx, query, args)
	if err != nil {
		return failed(db, err)
	}
	return db.WithContext(ctx).Raw(query, all...)
}

func failed(db *gorm.DB, err error) *gorm.DB {
	tx := db.Session(&gorm.Session{NewDB: true})
	_ = tx.AddError(err)
	return tx
}
