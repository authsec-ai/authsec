//go:build integration

package flows

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// Phase 3 schema hardening (migrations 045-048, ADR-0001 §6).

// schemaTenant is a workspace with an admin and one resource server (and its
// scope), enough to exercise the tenancy constraints.
type schemaTenant struct {
	WS *WorkspaceScenario
	RS *RSScenario
}

func schemaTenants(t *testing.T) (a, b schemaTenant) {
	t.Helper()
	testsupport.Get(t)
	mk := func(suffix string) schemaTenant {
		n := emailSafeNonce() + suffix
		ws, err := SeedWorkspaceWithAdmin(config.DB, n)
		if err != nil {
			t.Fatalf("seed workspace %s: %v", suffix, err)
		}
		rs, err := AddResourceServer(config.DB, ws, "https://rs-"+n+".test", n)
		if err != nil {
			t.Fatalf("seed resource server %s: %v", suffix, err)
		}
		return schemaTenant{WS: ws, RS: rs}
	}
	return mk("a"), mk("b")
}

func sqlState(err error) string {
	var s interface{ SQLState() string }
	if errors.As(err, &s) {
		return s.SQLState()
	}
	return ""
}

func wsOf(t *testing.T, query string, args ...interface{}) uuid.NullUUID {
	t.Helper()
	var ws uuid.NullUUID
	if err := config.GetDatabase().DB.QueryRow(query, args...).Scan(&ws); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return ws
}

func wantWS(t *testing.T, what string, got uuid.NullUUID, want uuid.UUID) {
	t.Helper()
	if !got.Valid || got.UUID != want {
		t.Fatalf("%s: workspace_id = %v, want %s", what, got, want)
	}
}

// Rows written through the existing code paths carry their workspace.
func Test_TenancySchema_NewRowsAreAttributed(t *testing.T) {
	a, _ := schemaTenants(t)
	ws := a.WS
	db := config.GetDatabase().DB

	// External service: the manager stamps the caller's workspace.
	svc := &repositories.ExternalService{Name: "svc-" + emailSafeNonce(), AuthType: "none", ResourceID: uuid.NewString()}
	out, err := services.NewExternalServiceManager(repositories.NewExternalServiceRepository(config.DB), nil).
		Create(svc, ws.AdminUserID.String(), ws.WorkspaceID.String(), nil)
	if err != nil {
		t.Fatalf("create service: %v", err)
	}
	wantWS(t, "services", wsOf(t, `SELECT workspace_id FROM services WHERE id = $1`, out.ID), ws.WorkspaceID)

	// WebAuthn credential and MFA method, keyed by the user's id (the
	// handlers/webauthn_handler.go and repository/mfa_repository.go paths).
	cred := &webauthn.Credential{ID: []byte("cred-" + emailSafeNonce()), PublicKey: []byte("pk"), AttestationType: "none"}
	if err := repositories.NewCredentialRepository(config.DB).AddCredential(ws.AdminUserID.String(), cred); err != nil {
		t.Fatalf("add credential: %v", err)
	}
	wantWS(t, "credentials", wsOf(t, `SELECT workspace_id FROM credentials WHERE credential_id = $1`, cred.ID), ws.WorkspaceID)
	if err := repositories.NewMFARepository(config.DB).EnableMethod(ws.AdminUserID.String(), "webauthn", map[string]string{}, ws.AdminUserID); err != nil {
		t.Fatalf("enable webauthn: %v", err)
	}
	wantWS(t, "mfa_methods", wsOf(t, `SELECT workspace_id FROM mfa_methods WHERE client_id = $1 AND method_type = 'webauthn'`, ws.AdminUserID), ws.WorkspaceID)

	// MFA keyed by the legacy users.client_id resolves through that column.
	if err := repositories.NewMFARepository(config.DB).EnableMethod(ws.ClientID.String(), "totp", map[string]string{"k": "v"}, ws.AdminUserID); err != nil {
		t.Fatalf("enable totp: %v", err)
	}
	wantWS(t, "mfa_methods (client_id)", wsOf(t, `SELECT workspace_id FROM mfa_methods WHERE client_id = $1 AND method_type = 'totp'`, ws.ClientID), ws.WorkspaceID)

	// Join tables written without a workspace take their parent's.
	var permID uuid.UUID
	if err := db.QueryRow(`
		INSERT INTO permissions (id, workspace_id, resource, action, created_at)
		VALUES (gen_random_uuid(), $1, $2, 'read', NOW()) RETURNING id`, ws.WorkspaceID, "res-"+emailSafeNonce()).Scan(&permID); err != nil {
		t.Fatalf("insert permission: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)`, ws.AdminRoleID, permID); err != nil {
		t.Fatalf("insert role_permissions: %v", err)
	}
	wantWS(t, "role_permissions", wsOf(t, `SELECT workspace_id FROM role_permissions WHERE role_id = $1 AND permission_id = $2`, ws.AdminRoleID, permID), ws.WorkspaceID)

	scopeID := a.RS.ScopeIDs[0]
	if _, err := db.Exec(`INSERT INTO oauth_scope_permissions (scope_id, permission_id) VALUES ($1, $2)`, scopeID, permID); err != nil {
		t.Fatalf("insert oauth_scope_permissions: %v", err)
	}
	wantWS(t, "oauth_scope_permissions", wsOf(t, `SELECT workspace_id FROM oauth_scope_permissions WHERE scope_id = $1 AND permission_id = $2`, scopeID, permID), ws.WorkspaceID)

	toolID := insertTool(t, ws.WorkspaceID, a.RS.RSID)
	if _, err := db.Exec(`INSERT INTO mcp_tool_scope_map (tool_id, scope_id) VALUES ($1, $2)`, toolID, scopeID); err != nil {
		t.Fatalf("insert mcp_tool_scope_map: %v", err)
	}
	wantWS(t, "mcp_tool_scope_map", wsOf(t, `SELECT workspace_id FROM mcp_tool_scope_map WHERE tool_id = $1 AND scope_id = $2`, toolID, scopeID), ws.WorkspaceID)
}

func insertTool(t *testing.T, ws, rsID uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := config.GetDatabase().DB.QueryRow(`
		INSERT INTO mcp_tools (id, workspace_id, resource_server_id, name)
		VALUES (gen_random_uuid(), $1, $2, $3) RETURNING id`, ws, rsID, "tool-"+emailSafeNonce()).Scan(&id); err != nil {
		t.Fatalf("insert tool: %v", err)
	}
	return id
}

// The NOT VALID constraints still refuse new rows without a workspace, with a
// workspace that does not exist, or with one that disagrees with the parent.
func Test_TenancySchema_RejectsMissingOrMismatchedWorkspace(t *testing.T) {
	a, b := schemaTenants(t)
	db := config.GetDatabase().DB
	n := emailSafeNonce()
	toolA := insertTool(t, a.WS.WorkspaceID, a.RS.RSID)

	var permB uuid.UUID
	if err := db.QueryRow(`
		INSERT INTO permissions (id, workspace_id, resource, action, created_at)
		VALUES (gen_random_uuid(), $1, $2, 'read', NOW()) RETURNING id`, b.WS.WorkspaceID, "res-"+n).Scan(&permB); err != nil {
		t.Fatalf("insert permission: %v", err)
	}

	cases := []struct {
		name  string
		state string
		sql   string
		args  []interface{}
	}{
		{"user without workspace", "23514",
			`INSERT INTO users (id, client_id, email, provider, active, created_at, updated_at)
			 VALUES (gen_random_uuid(), gen_random_uuid(), $1, 'local', true, NOW(), NOW())`,
			[]interface{}{"nows-" + n + "@x.test"}},
		{"user in a workspace that does not exist", "23503",
			`INSERT INTO users (id, client_id, workspace_id, email, provider, active, created_at, updated_at)
			 VALUES (gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), $1, 'local', true, NOW(), NOW())`,
			[]interface{}{"ghost-" + n + "@x.test"}},
		{"credential of no known user", "23514",
			`INSERT INTO credentials (client_id, credential_id, public_key) VALUES (gen_random_uuid(), $1, 'pk')`,
			[]interface{}{[]byte("orphan-" + n)}},
		{"mfa method of no known user", "23514",
			`INSERT INTO mfa_methods (client_id, method_type) VALUES (gen_random_uuid(), 'totp')`, nil},
		{"service without workspace", "23514",
			`INSERT INTO services (name, type, created_by) VALUES ('s', 'http', 'nobody')`, nil},
		{"spire workload without workspace", "23514",
			`INSERT INTO spire_workloads (id, spiffe_id, owner) VALUES ((SELECT COALESCE(max(id), 0) + 1 FROM spire_workloads), $1, 'o')`,
			[]interface{}{"/legacy/" + n}},
		{"role grant stamped with another workspace", "23503",
			`INSERT INTO role_permissions (role_id, permission_id, workspace_id) VALUES ($1, $2, $3)`,
			[]interface{}{a.WS.AdminRoleID, permB, b.WS.WorkspaceID}},
		{"role granted another workspace's permission", "23514",
			`INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)`,
			[]interface{}{a.WS.AdminRoleID, permB}},
		{"tool mapped to another workspace's scope", "23503",
			`INSERT INTO mcp_tool_scope_map (tool_id, scope_id) VALUES ($1, $2)`,
			[]interface{}{toolA, b.RS.ScopeIDs[0]}},
		{"scope permission stamped with another workspace", "23503",
			`INSERT INTO oauth_scope_permissions (scope_id, permission_id, workspace_id) VALUES ($1, $2, $3)`,
			[]interface{}{a.RS.ScopeIDs[0], permB, b.WS.WorkspaceID}},
		{"clearing a user's workspace", "23514",
			`UPDATE users SET workspace_id = NULL WHERE id = $1`,
			[]interface{}{a.WS.AdminUserID}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := db.Exec(tc.sql, tc.args...)
			if got := sqlState(err); got != tc.state {
				t.Fatalf("want SQLSTATE %s, got %q (%v)", tc.state, got, err)
			}
		})
	}
}

// Backup codes and device tokens are unique per workspace (per user for
// codes), not across all workspaces.
func Test_TenancySchema_PerWorkspaceUniques(t *testing.T) {
	a, b := schemaTenants(t)
	db := config.GetDatabase().DB
	code := "code-" + emailSafeNonce()
	token := "device-" + emailSafeNonce()

	insCode := `INSERT INTO workspace_totp_backup_codes (user_id, workspace_id, code, created_at) VALUES ($1, $2, $3, 0)`
	insLegacyCode := `INSERT INTO totp_backup_codes (id, user_id, workspace_id, code, created_at) VALUES (gen_random_uuid(), $1, $2, $3, 0)`
	insToken := `INSERT INTO workspace_device_tokens (user_id, workspace_id, device_token, platform, created_at, updated_at) VALUES ($1, $2, $3, 'ios', 0, 0)`

	for _, q := range []string{insCode, insLegacyCode} {
		if _, err := db.Exec(q, a.WS.AdminUserID, a.WS.WorkspaceID, code); err != nil {
			t.Fatalf("code in A: %v", err)
		}
		if _, err := db.Exec(q, b.WS.AdminUserID, b.WS.WorkspaceID, code); err != nil {
			t.Fatalf("same code in B must be allowed: %v", err)
		}
		if _, err := db.Exec(q, a.WS.AdminUserID, a.WS.WorkspaceID, code); sqlState(err) != "23505" {
			t.Fatalf("same code twice for one user: want 23505, got %v", err)
		}
	}

	if _, err := db.Exec(insToken, a.WS.AdminUserID, a.WS.WorkspaceID, token); err != nil {
		t.Fatalf("device token in A: %v", err)
	}
	if _, err := db.Exec(insToken, b.WS.AdminUserID, b.WS.WorkspaceID, token); err != nil {
		t.Fatalf("same device token in B must be allowed: %v", err)
	}
	if _, err := db.Exec(insToken, a.WS.AdminUserID, a.WS.WorkspaceID, token); sqlState(err) != "23505" {
		t.Fatalf("same device token twice in A: want 23505, got %v", err)
	}
}

// resource_uri and workload issuers stay globally unique on purpose: the AS
// resolves them before the workspace is known (see 048's header). This pins
// the decision so a later change to per-workspace uniques is deliberate.
func Test_TenancySchema_PreAuthIdentifiersStayGlobal(t *testing.T) {
	a, b := schemaTenants(t)
	db := config.GetDatabase().DB

	_, err := db.Exec(`
		INSERT INTO resource_servers (id, workspace_id, name, public_base_url, resource_uri)
		VALUES (gen_random_uuid(), $1, 'dup', 'https://dup.test', $2)`, b.WS.WorkspaceID, a.RS.ResourceURI)
	if sqlState(err) != "23505" {
		t.Fatalf("resource_uri reused in another workspace: want 23505, got %v", err)
	}

	issuer := "https://issuer-" + emailSafeNonce() + ".test"
	ins := `INSERT INTO workload_identity_providers (workspace_id, name, issuer) VALUES ($1, 'p', $2)`
	if _, err := db.Exec(ins, a.WS.WorkspaceID, issuer); err != nil {
		t.Fatalf("issuer in A: %v", err)
	}
	if _, err := db.Exec(ins, b.WS.WorkspaceID, issuer); sqlState(err) != "23505" {
		t.Fatalf("issuer reused in another workspace: want 23505, got %v", err)
	}
}

// The backfill attributes legacy rows from their parents and reports the rest
// in tenancy_backfill_orphans; it never guesses. Legacy rows are written with
// triggers and constraints disabled, inside a transaction that is rolled back.
func Test_TenancySchema_BackfillAttributesAndReportsOrphans(t *testing.T) {
	a, b := schemaTenants(t)
	ctx := context.Background()
	tx, err := config.GetDatabase().DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	exec := func(q string, args ...interface{}) {
		t.Helper()
		if _, err := tx.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	for _, tbl := range []string{"credentials", "mfa_methods", "services", "mcp_tool_scope_map", "spire_workloads"} {
		exec(`ALTER TABLE ` + tbl + ` DROP CONSTRAINT IF EXISTS ck_` + tbl + `_tenancy_ws_nn`)
	}
	exec(`SET LOCAL session_replication_role = replica`) // no fill triggers, no FK checks

	credOK, credOrphan := uuid.New(), uuid.New()
	exec(`INSERT INTO credentials (id, client_id, credential_id, public_key) VALUES ($1, $2, $3, 'pk'), ($4, gen_random_uuid(), $5, 'pk')`,
		credOK, a.WS.AdminUserID, []byte("bf-"+credOK.String()), credOrphan, []byte("bf-"+credOrphan.String()))
	mfaOK, mfaConflict := uuid.New(), uuid.New()
	exec(`INSERT INTO mfa_methods (id, client_id, user_id, method_type) VALUES ($1, $2, NULL, 'sms'), ($3, $4, $5, 'email')`,
		mfaOK, b.WS.ClientID, mfaConflict, a.WS.AdminUserID, b.WS.AdminUserID)
	svcOK, svcOrphan := uuid.New(), uuid.New()
	exec(`INSERT INTO services (id, name, type, created_by) VALUES ($1, 's', 'http', $2), ($3, 's', 'http', 'not-a-user')`,
		svcOK, a.WS.AdminUserID.String(), svcOrphan)
	toolA := insertToolTx(t, tx, a.WS.WorkspaceID, a.RS.RSID)
	exec(`INSERT INTO mcp_tool_scope_map (tool_id, scope_id) VALUES ($1, $2), ($1, $3)`, toolA, a.RS.ScopeIDs[0], b.RS.ScopeIDs[0])
	var wlOK, wlOrphan int64
	if err := tx.QueryRow(`SELECT COALESCE(max(id), 0) + 1, COALESCE(max(id), 0) + 2 FROM spire_workloads`).Scan(&wlOK, &wlOrphan); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO spire_workloads (id, spiffe_id, owner) VALUES ($1, $2, 'o'), ($3, '/legacy/x', 'o')`,
		wlOK, "/workspaces/"+b.WS.WorkspaceID.String()+"/applications/"+uuid.NewString(), wlOrphan)
	exec(`SET LOCAL session_replication_role = origin`)

	if _, err := tx.Exec(`SELECT * FROM tenancy_backfill_workspace_ids()`); err != nil {
		t.Fatalf("backfill: %v", err)
	}

	ws := func(q string, args ...interface{}) uuid.NullUUID {
		var v uuid.NullUUID
		if err := tx.QueryRow(q, args...).Scan(&v); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return v
	}
	wantWS(t, "credential by user id", ws(`SELECT workspace_id FROM credentials WHERE id = $1`, credOK), a.WS.WorkspaceID)
	wantWS(t, "mfa by users.client_id", ws(`SELECT workspace_id FROM mfa_methods WHERE id = $1`, mfaOK), b.WS.WorkspaceID)
	wantWS(t, "service by creator", ws(`SELECT workspace_id FROM services WHERE id = $1`, svcOK), a.WS.WorkspaceID)
	wantWS(t, "tool/scope in one workspace", ws(`SELECT workspace_id FROM mcp_tool_scope_map WHERE tool_id = $1 AND scope_id = $2`, toolA, a.RS.ScopeIDs[0]), a.WS.WorkspaceID)
	wantWS(t, "spire workload by SPIFFE path", ws(`SELECT workspace_id FROM spire_workloads WHERE id = $1`, wlOK), b.WS.WorkspaceID)

	orphans := map[string]string{
		"credentials":        credOrphan.String(),
		"mfa_methods":        mfaConflict.String(),
		"services":           svcOrphan.String(),
		"mcp_tool_scope_map": toolA.String() + ":" + b.RS.ScopeIDs[0].String(),
		"spire_workloads":    fmt.Sprint(wlOrphan),
	}
	for tbl, rowID := range orphans {
		var reason string
		err := tx.QueryRow(`SELECT reason FROM tenancy_backfill_orphans WHERE table_name = $1 AND row_id = $2`, tbl, rowID).Scan(&reason)
		if errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("%s %s: not reported as an orphan", tbl, rowID)
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if got := ws(`SELECT workspace_id FROM credentials WHERE id = $1`, credOrphan); got.Valid {
		t.Fatalf("orphan credential was assigned workspace %s", got.UUID)
	}
	if got := ws(`SELECT workspace_id FROM mfa_methods WHERE id = $1`, mfaConflict); got.Valid {
		t.Fatalf("conflicting mfa method was assigned workspace %s", got.UUID)
	}
}

func insertToolTx(t *testing.T, tx *sql.Tx, ws, rsID uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := tx.QueryRow(`
		INSERT INTO mcp_tools (id, workspace_id, resource_server_id, name)
		VALUES (gen_random_uuid(), $1, $2, $3) RETURNING id`, ws, rsID, "tool-"+emailSafeNonce()).Scan(&id); err != nil {
		t.Fatalf("insert tool: %v", err)
	}
	return id
}
