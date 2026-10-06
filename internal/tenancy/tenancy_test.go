package tenancy

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestCheckScoped(t *testing.T) {
	ok := []string{
		"SELECT * FROM users WHERE workspace_id = $1 AND id = $2",
		"select id from roles r where r.workspace_id=$1",
		"UPDATE groups SET name = $2 WHERE workspace_id = $1 AND id = $3",
	}
	bad := []string{
		"SELECT * FROM users WHERE id = $1",
		"SELECT * FROM users WHERE workspace_id = $2 AND id = $1",
		"SELECT * FROM users WHERE workspace_id = $10",
		"SELECT * FROM users WHERE parent_workspace_id = $1",
	}
	for _, q := range ok {
		if err := CheckScoped(q); err != nil {
			t.Errorf("should be accepted: %q", q)
		}
	}
	for _, q := range bad {
		if err := CheckScoped(q); !errors.Is(err, ErrUnscopedQuery) {
			t.Errorf("should be rejected: %q", q)
		}
	}
}

func testContext() *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/", nil)
	return c
}

func TestSetAndFrom(t *testing.T) {
	c := testContext()
	if _, err := From(c); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("empty context must be ErrNoTenant, got %v", err)
	}
	ws := uuid.New()
	Set(c, Context{WorkspaceID: ws, Realm: "admin"})
	got, err := From(c)
	if err != nil || got.WorkspaceID != ws {
		t.Fatalf("From = %v, %v", got, err)
	}
	if got, err := FromContext(c.Request.Context()); err != nil || got.WorkspaceID != ws {
		t.Fatalf("FromContext = %v, %v", got, err)
	}
}

func TestScopedQueriesRefuseWithoutTenant(t *testing.T) {
	c := testContext()
	if _, err := Query(c, nil, "SELECT 1 FROM users WHERE workspace_id = $1"); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("want ErrNoTenant, got %v", err)
	}
	Set(c, Context{WorkspaceID: uuid.New()})
	if _, err := Query(c, nil, "SELECT 1 FROM users WHERE id = $1"); !errors.Is(err, ErrUnscopedQuery) {
		t.Fatalf("want ErrUnscopedQuery, got %v", err)
	}
}

type row struct {
	ID          uuid.UUID
	WorkspaceID uuid.UUID
}

func TestScopeAddsPredicate(t *testing.T) {
	db, err := gorm.Open(postgres.New(postgres.Config{DSN: "host=invalid"}), &gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatal(err)
	}
	ws := uuid.New()
	stmt := db.Scopes(Scope(ws)).Where("id = ?", uuid.New()).Find(&[]row{}).Statement
	sql := stmt.SQL.String()
	if !strings.Contains(sql, "workspace_id = $") {
		t.Fatalf("scope did not add the workspace predicate: %s", sql)
	}
	found := false
	for _, v := range stmt.Vars {
		if v == ws {
			found = true
		}
	}
	if !found {
		t.Fatalf("the workspace is not bound: %v", stmt.Vars)
	}
}
