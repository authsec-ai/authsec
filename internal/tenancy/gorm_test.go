package tenancy

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestGormForms_RefuseUnscopedOrTenantless(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`CREATE TABLE things (workspace_id TEXT, id TEXT)`).Error; err != nil {
		t.Fatal(err)
	}
	ctx := WithContext(context.Background(), Context{WorkspaceID: uuid.New()})

	if err := GormExec(ctx, db, `DELETE FROM things WHERE id = $1`, "x").Error; !errors.Is(err, ErrUnscopedQuery) {
		t.Errorf("unscoped exec: %v, want ErrUnscopedQuery", err)
	}
	var n int64
	if err := GormRaw(ctx, db, `SELECT COUNT(*) FROM things`).Scan(&n).Error; !errors.Is(err, ErrUnscopedQuery) {
		t.Errorf("unscoped raw: %v, want ErrUnscopedQuery", err)
	}
	if err := GormExec(context.Background(), db, `DELETE FROM things WHERE workspace_id = $1`).Error; !errors.Is(err, ErrNoTenant) {
		t.Errorf("tenantless exec: %v, want ErrNoTenant", err)
	}
	// A refused statement runs nothing: the table is still there and empty,
	// and the shared handle carries no error afterwards.
	if err := db.Exec(`INSERT INTO things VALUES ('w', 'i')`).Error; err != nil {
		t.Fatalf("handle poisoned by a refused statement: %v", err)
	}
}

func TestInsertContext_RefusesNonInsertAndTenantless(t *testing.T) {
	ctx := WithContext(context.Background(), Context{WorkspaceID: uuid.New()})
	if _, err := InsertContext(ctx, nil, `UPDATE t SET a = 1`); !errors.Is(err, ErrNotInsert) {
		t.Errorf("update: %v, want ErrNotInsert", err)
	}
	if _, err := InsertContext(context.Background(), nil, `INSERT INTO t (workspace_id) VALUES ($1)`); !errors.Is(err, ErrNoTenant) {
		t.Errorf("tenantless: %v, want ErrNoTenant", err)
	}
}
