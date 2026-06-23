// Package ownership contains regression tests that prove the workspace
// ownership model is enforced by the database schema itself — not merely by
// application convention. They bootstrap the canonical schema
// (migrations/master/001_bootstrap.sql) into a throwaway Postgres and assert
// that cross-workspace and orphan rows are rejected.
//
// These tests require a Postgres instance. Set TEST_DATABASE_URL to a
// connection string for a database you are willing to have its `public` schema
// dropped and rebuilt, e.g.:
//
//	TEST_DATABASE_URL="postgres://postgres:test@localhost:55432/authtest?sslmode=disable" \
//	    go test ./tests/ownership/...
//
// When TEST_DATABASE_URL is unset the suite skips, so `go test ./...` stays
// green in environments without a database.
package ownership

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/lib/pq"
)

const (
	wsA = "11111111-1111-1111-1111-111111111111"
	wsB = "22222222-2222-2222-2222-222222222222"
)

// setupSchema connects to TEST_DATABASE_URL, rebuilds the public schema, and
// applies the canonical bootstrap. It returns a ready *sql.DB or skips the test.
func setupSchema(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping schema ownership tests")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}

	// Rebuild a clean public schema, then create the one GORM-managed table the
	// bootstrap assumes already exists (migration_logs).
	for _, stmt := range []string{
		"DROP SCHEMA IF EXISTS public CASCADE",
		"CREATE SCHEMA public",
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("reset schema (%q): %v", stmt, err)
		}
	}

	bootstrapPath, err := filepath.Abs(filepath.Join("..", "..", "migrations", "master", "001_bootstrap.sql"))
	if err != nil {
		t.Fatalf("resolve bootstrap path: %v", err)
	}
	sqlBytes, err := os.ReadFile(bootstrapPath)
	if err != nil {
		t.Fatalf("read bootstrap: %v", err)
	}
	if _, err := db.Exec(string(sqlBytes)); err != nil {
		t.Fatalf("apply bootstrap: %v", err)
	}

	t.Cleanup(func() { db.Close() })
	return db
}

// seedWorkspaces inserts the two reference workspaces plus a user in A.
func seedBaseline(t *testing.T, db *sql.DB) {
	t.Helper()
	exec(t, db, "INSERT INTO workspaces (id, name) VALUES ($1,'ws-A')", wsA)
	exec(t, db, "INSERT INTO workspaces (id, name) VALUES ($1,'ws-B')", wsB)
	exec(t, db,
		"INSERT INTO users (id, email, workspace_id) VALUES ($1,'u@a.com',$2)",
		"aaaaaaaa-0000-0000-0000-000000000001", wsA)
}

func exec(t *testing.T, db *sql.DB, q string, args ...interface{}) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

// mustFail asserts a statement is rejected by the database.
func mustFail(t *testing.T, db *sql.DB, what, q string, args ...interface{}) {
	t.Helper()
	if _, err := db.Exec(q, args...); err == nil {
		t.Fatalf("%s: expected the database to reject this, but it succeeded", what)
	}
}

// TestUserGroup_CrossWorkspaceRejected proves a user cannot be added to a group
// that belongs to a different workspace (composite FK fk_ug_group).
func TestUserGroup_CrossWorkspaceRejected(t *testing.T) {
	db := setupSchema(t)
	seedBaseline(t, db)

	// A group in workspace B.
	exec(t, db,
		"INSERT INTO groups (id, name, workspace_id) VALUES ($1,'grp-B',$2)",
		"bbbbbbbb-0000-0000-0000-000000000001", wsB)

	// A's user → B's group, tagged as workspace A: must violate fk_ug_group.
	mustFail(t, db, "cross-workspace group membership",
		"INSERT INTO user_groups (workspace_id, user_id, group_id) VALUES ($1,$2,$3)",
		wsA, "aaaaaaaa-0000-0000-0000-000000000001", "bbbbbbbb-0000-0000-0000-000000000001")
}

// TestUserGroup_SameWorkspaceAllowed proves the legitimate same-workspace path
// still works (no over-restriction).
func TestUserGroup_SameWorkspaceAllowed(t *testing.T) {
	db := setupSchema(t)
	seedBaseline(t, db)

	exec(t, db,
		"INSERT INTO groups (id, name, workspace_id) VALUES ($1,'grp-A',$2)",
		"cccccccc-0000-0000-0000-000000000001", wsA)
	exec(t, db,
		"INSERT INTO user_groups (workspace_id, user_id, group_id) VALUES ($1,$2,$3)",
		wsA, "aaaaaaaa-0000-0000-0000-000000000001", "cccccccc-0000-0000-0000-000000000001")
}

// TestRoleBinding_NullWorkspaceRejected proves role_bindings.workspace_id is
// NOT NULL, so a binding cannot escape workspace scope.
func TestRoleBinding_NullWorkspaceRejected(t *testing.T) {
	db := setupSchema(t)
	seedBaseline(t, db)

	mustFail(t, db, "role_binding with NULL workspace_id",
		"INSERT INTO role_bindings (id, user_id, role_id, workspace_id) VALUES (gen_random_uuid(),$1,gen_random_uuid(),NULL)",
		"aaaaaaaa-0000-0000-0000-000000000001")
}

// TestAppSpiffeIdentity_CrossWorkspaceRejected proves an application's SPIFFE
// identity cannot bind to an application in a different workspace
// (composite FK fk_app_spiffe_application).
func TestAppSpiffeIdentity_CrossWorkspaceRejected(t *testing.T) {
	db := setupSchema(t)
	seedBaseline(t, db)

	// A resource server (application) in workspace B.
	exec(t, db,
		"INSERT INTO resource_servers (id, workspace_id, resource_uri, name, public_base_url) VALUES ($1,$2,'https://b.example/api','app-B','https://b.example')",
		"dddddddd-0000-0000-0000-000000000001", wsB)

	// SPIFFE identity tagged workspace A pointing at B's application: must fail.
	mustFail(t, db, "cross-workspace application_spiffe_identities binding",
		`INSERT INTO application_spiffe_identities (workspace_id, application_id, spiffe_id, trust_domain)
		 VALUES ($1,$2,'spiffe://td/wl/x','td')`,
		wsA, "dddddddd-0000-0000-0000-000000000001")
}

// TestNoTenantsTable proves the legacy tenants table is gone from the canonical
// schema (workspace-only model).
func TestNoTenantsTable(t *testing.T) {
	db := setupSchema(t)
	var exists bool
	if err := db.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='tenants')",
	).Scan(&exists); err != nil {
		t.Fatalf("query: %v", err)
	}
	if exists {
		t.Fatal("legacy `tenants` table should not exist in the workspace-only schema")
	}
}
