//go:build integration

package flows

import (
	"context"
	"database/sql"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/tenancy"
)

// ADR-0001 §4.4: every workspace-owned table carries the row-level security
// policy, forced, so new tables cannot silently miss it.
func Test_RLS_EveryWorkspaceTableHasThePolicy(t *testing.T) {
	rows, err := config.GetDatabase().DB.Query(`
		SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
		       EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname = 'public' AND p.tablename = c.relname AND p.policyname = 'tenancy_isolation')
		  FROM pg_class c
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		  JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'workspace_id' AND NOT a.attisdropped
		 WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var name string
		var enabled, forced, policy bool
		if err := rows.Scan(&name, &enabled, &forced, &policy); err != nil {
			t.Fatal(err)
		}
		n++
		if !enabled || !forced || !policy {
			t.Errorf("%s: rls=%v forced=%v policy=%v; call tenancy_enable_rls in its migration", name, enabled, forced, policy)
		}
	}
	if n < 100 {
		t.Fatalf("only %d workspace tables found; expected the full schema", n)
	}
}

// Even a scoped statement that tries to reach past its workspace predicate
// (an OR naming another workspace's row) is stopped by the database.
func Test_RLS_ScopedQueriesCannotReachAnotherWorkspace(t *testing.T) {
	a, b := TwoTenants(t)
	db := config.GetDatabase().DB
	ctxA := tenancy.WithContext(context.Background(), tenancy.Context{WorkspaceID: a.WS.WorkspaceID})

	var email string
	err := tenancy.QueryRowContext(ctxA, db,
		`SELECT email FROM users WHERE workspace_id = $1 OR id = $2 ORDER BY (id = $2) DESC LIMIT 1`,
		[]interface{}{b.EndUser.UserID}, &email)
	if err == nil && email == b.EndUser.Email {
		t.Fatalf("RLS let workspace A read B's user")
	}

	res, err := tenancy.ExecContext(ctxA, db,
		`UPDATE users SET name = 'rls-bypass' WHERE workspace_id = $1 OR id = $2`, b.EndUser.UserID)
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	_ = res
	var name sql.NullString
	db.QueryRow(`SELECT name FROM users WHERE id = $1`, b.EndUser.UserID).Scan(&name)
	if name.String == "rls-bypass" {
		t.Fatalf("RLS let workspace A update B's user")
	}

	// Writing a row into another workspace is refused outright.
	_, err = tenancy.ExecContext(ctxA, db,
		`INSERT INTO groups (id, workspace_id, name) SELECT gen_random_uuid(), $2, 'planted' WHERE $1::uuid IS NOT NULL`,
		b.WS.WorkspaceID)
	if err == nil {
		t.Fatalf("RLS allowed inserting a row for another workspace")
	}

	// The restricted role is in use (the harness connects as a superuser,
	// which Postgres exempts from RLS).
	var role string
	if err := tenancy.WithTx(ctxA, db, a.WS.WorkspaceID, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT current_user`).Scan(&role)
	}); err != nil {
		t.Fatal(err)
	}
	if role != "authsec_tenant" {
		t.Fatalf("scoped transactions run as %q, want authsec_tenant", role)
	}
}
