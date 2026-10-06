package tenancy

import (
	"context"
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

func TestHTTPStatus(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{nil, 200},
		{ErrNoTenant, 401},
		{ErrNotFound, 404},
		{gorm.ErrRecordNotFound, 404},
		{errors.New("boom"), 500},
	}
	for _, tc := range cases {
		if got := HTTPStatus(tc.err); got != tc.want {
			t.Errorf("HTTPStatus(%v) = %d, want %d", tc.err, got, tc.want)
		}
	}
}

func dryRunDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.New(postgres.Config{DSN: "host=invalid"}), &gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// A scoped handle is reused for several queries in one handler; conditions of
// one query must not carry into the next.
func TestDBIsReusable(t *testing.T) {
	c := testContext()
	Set(c, Context{WorkspaceID: uuid.New()})
	scoped, err := DB(c, dryRunDB(t))
	if err != nil {
		t.Fatal(err)
	}
	first := scoped.Where("id = ?", 1).Find(&[]row{}).Statement.SQL.String()
	second := scoped.Where("name = ?", "x").Find(&[]row{}).Statement.SQL.String()
	if strings.Contains(second, "WHERE id = $") || !strings.Contains(second, "name = $") {
		t.Fatalf("second query inherited the first one's conditions:\n%s\n%s", first, second)
	}
	for _, q := range []string{first, second} {
		if !strings.Contains(q, "workspace_id = $") {
			t.Fatalf("workspace predicate missing: %s", q)
		}
	}
}

func TestWorkspace(t *testing.T) {
	c := testContext()
	if _, err := Workspace(c); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("no tenant: got %v", err)
	}
	ws := uuid.New()
	Set(c, Context{WorkspaceID: ws})
	if got, err := Workspace(c); err != nil || got != ws {
		t.Fatalf("Workspace = %v, %v; want %v", got, err, ws)
	}
}

func TestContextFormsUseTheContextTenant(t *testing.T) {
	ctx := context.Background()
	if _, err := DBContext(ctx, dryRunDB(t)); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("DBContext without tenant: want ErrNoTenant, got %v", err)
	}
	if _, err := QueryContext(ctx, nil, "SELECT 1 FROM users WHERE workspace_id = $1"); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("QueryContext without tenant: want ErrNoTenant, got %v", err)
	}
	if _, err := ExecContext(ctx, nil, "DELETE FROM users WHERE workspace_id = $1"); !errors.Is(err, ErrNoTenant) {
		t.Fatalf("ExecContext without tenant: want ErrNoTenant, got %v", err)
	}
	ws := uuid.New()
	ctx = WithContext(ctx, Context{WorkspaceID: ws})
	if err := QueryRowContext(ctx, nil, "SELECT 1 FROM users WHERE id = $1", nil); !errors.Is(err, ErrUnscopedQuery) {
		t.Fatalf("unscoped statement: want ErrUnscopedQuery, got %v", err)
	}
	scoped, err := DBContext(ctx, dryRunDB(t))
	if err != nil {
		t.Fatal(err)
	}
	stmt := scoped.Find(&[]row{}).Statement
	if len(stmt.Vars) != 1 || stmt.Vars[0] != ws {
		t.Fatalf("workspace from ctx not bound: %v", stmt.Vars)
	}
}
