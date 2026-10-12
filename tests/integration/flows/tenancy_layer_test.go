//go:build integration

package flows

import (
	"context"
	"database/sql"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func requestFor(ws uuid.UUID) *gin.Context {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/", nil)
	tenancy.Set(c, tenancy.Context{WorkspaceID: ws})
	return c
}

// The scoped layer returns ErrNotFound, not the row, for another workspace's id.
func Test_TenancyLayer_LookupsAreScoped(t *testing.T) {
	a, b := TwoTenants(t)
	ca := requestFor(a.WS.WorkspaceID)

	var u models.User
	if err := tenancy.Get(ca, config.DB, &u, a.EndUser.UserID); err != nil {
		t.Fatalf("own user: %v", err)
	}
	if err := tenancy.Get(ca, config.DB, &u, b.EndUser.UserID); !errors.Is(err, tenancy.ErrNotFound) {
		t.Fatalf("other workspace's user: want ErrNotFound, got %v", err)
	}

	var email string
	q := `SELECT email FROM users WHERE workspace_id = $1 AND id = $2`
	if err := tenancy.QueryRow(ca, config.GetDatabase().DB, q, []interface{}{b.EndUser.UserID}, &email); !errors.Is(err, tenancy.ErrNotFound) {
		t.Fatalf("raw lookup of another workspace's user: want ErrNotFound, got %v (%s)", err, email)
	}
}

// WithTx sets app.workspace_id so Postgres row-level security can enforce
// isolation underneath the application (ADR-0001 §4.4). Exercised on a
// scratch table with the policy shape Phase 3 applies to tenant tables.
func Test_TenancyLayer_RLSPolicyEnforcedThroughWithTx(t *testing.T) {
	db := config.GetDatabase().DB
	ctx := context.Background()
	a, b := uuid.New(), uuid.New()

	// The harness connects as the database owner, which bypasses RLS even
	// with FORCE; a non-owner role is how the application will connect.
	stmts := []string{
		`DROP TABLE IF EXISTS rls_probe`,
		`CREATE TABLE rls_probe (id serial PRIMARY KEY, workspace_id uuid NOT NULL, v text)`,
		`ALTER TABLE rls_probe ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE rls_probe FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY rls_probe_ws ON rls_probe
		   USING (workspace_id = current_setting('app.workspace_id', true)::uuid)
		   WITH CHECK (workspace_id = current_setting('app.workspace_id', true)::uuid)`,
		`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rls_probe_app') THEN CREATE ROLE rls_probe_app NOLOGIN; END IF; END $$`,
		`GRANT SELECT, INSERT ON rls_probe TO rls_probe_app`,
		`GRANT USAGE ON SEQUENCE rls_probe_id_seq TO rls_probe_app`,
	}
	for _, s := range stmts {
		if _, err := db.ExecContext(ctx, s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	t.Cleanup(func() { db.Exec(`DROP TABLE IF EXISTS rls_probe`) })

	asApp := func(ws uuid.UUID, fn func(tx *sql.Tx) error) error {
		return tenancy.WithTx(ctx, db, ws, func(tx *sql.Tx) error {
			if _, err := tx.Exec(`SET LOCAL ROLE rls_probe_app`); err != nil {
				return err
			}
			return fn(tx)
		})
	}

	for _, ws := range []uuid.UUID{a, b} {
		ws := ws
		if err := asApp(ws, func(tx *sql.Tx) error {
			_, err := tx.Exec(`INSERT INTO rls_probe (workspace_id, v) VALUES ($1, 'x')`, ws)
			return err
		}); err != nil {
			t.Fatalf("insert own row: %v", err)
		}
	}

	var visible int
	if err := asApp(a, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT count(*) FROM rls_probe`).Scan(&visible)
	}); err != nil {
		t.Fatal(err)
	}
	if visible != 1 {
		t.Fatalf("workspace A sees %d rows, want only its own 1", visible)
	}

	err := asApp(a, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO rls_probe (workspace_id, v) VALUES ($1, 'planted')`, b)
		return err
	})
	if err == nil {
		t.Fatalf("RLS must refuse writing a row for another workspace")
	}
}
