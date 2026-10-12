// Cross-workspace isolation of the governance repository's revocation path.
//
// A subject id is not a workspace boundary: an operator holding memberships in
// two workspaces is the same user (the same subject_id) in both, and each
// workspace mints its own native tokens for that subject. Revocation in one
// workspace must touch that workspace's tokens and bindings only.
//
// Requires TEST_DATABASE_URL, and skips without it, like the rest of this package.
package ownership

import (
	"database/sql"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

// seedLiveTokenIn inserts an unexpired native token of workspace ws for the
// service account subject govSA, with a resource server of that workspace.
func seedLiveTokenIn(t *testing.T, raw *sql.DB, ws string, jti uuid.UUID) {
	t.Helper()
	rsID := uuid.New()
	exec(t, raw, `INSERT INTO resource_servers (id,workspace_id,name,resource_uri,public_base_url)
	              VALUES ($1,$2,'payments',$3,'https://payments.example')`,
		rsID, ws, "authsec://rs/payments-"+rsID.String())
	exec(t, raw, `INSERT INTO native_tokens
	    (jti,iss,workspace_id,token_family,subject_type,subject_id,client_id,
	     resource_server_id,aud,scope,issued_at,expires_at)
	    VALUES ($1,'https://issuer',$2,'m2m','service_account',$3,'client-1',
	            $4,'authsec://rs/payments','read',now(),now() + interval '55 minutes')`,
		jti, ws, govSA, rsID)
}

// LiveTokenJTIsForSubject lists the subject's tokens of the asked workspace
// only. Before it took the workspace it returned every workspace's tokens for
// the subject id, and every revocation path revoked them all.
func TestLiveTokensForSubjectAreTheWorkspacesOwn(t *testing.T) {
	raw, repo, _, ws := govFixture(t)
	jtiA, jtiB := uuid.New(), uuid.New()
	seedLiveTokenIn(t, raw, wsA, jtiA)
	seedLiveTokenIn(t, raw, wsB, jtiB)

	tokens, err := repo.LiveTokenJTIsForSubject(ws, uuid.MustParse(govSA), "service_account")
	if err != nil {
		t.Fatalf("list live tokens: %v", err)
	}
	if len(tokens) != 1 || tokens[0].JTI != jtiA.String() {
		t.Fatalf("workspace A's live tokens = %+v, want only %s (workspace B's %s must not be listed)",
			tokens, jtiA, jtiB)
	}
}

// End to end: a grant lapsing in workspace A revokes A's token and leaves the
// same subject's token in workspace B working.
func TestExpirySweepLeavesAnotherWorkspacesTokensAlone(t *testing.T) {
	raw, _, pm, ws := govFixture(t)
	binding := bindRole(t, raw, future(time.Hour))
	jtiA, jtiB := uuid.New(), uuid.New()
	seedLiveTokenIn(t, raw, wsA, jtiA)
	seedLiveTokenIn(t, raw, wsB, jtiB)

	p, err := openGrant(t, pm, ws, binding, future(time.Hour), false, "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	exec(t, raw, "UPDATE entitlement_provenance SET expires_at = now() - interval '1 minute' WHERE id = $1", p.ID)
	exec(t, raw, "UPDATE role_bindings SET expires_at = now() - interval '1 minute' WHERE id = $1", binding)

	res := services.NewExpiryWorker(gormFor(t, raw), time.Minute, 100).RunOnce()
	if res.Errors != 0 {
		t.Fatalf("sweep reported %d errors", res.Errors)
	}
	if res.TokensRevoked != 1 {
		t.Errorf("tokens_revoked = %d, want 1 (workspace A's token only)", res.TokensRevoked)
	}
	for jti, want := range map[uuid.UUID]int{jtiA: 1, jtiB: 0} {
		var n int
		if err := raw.QueryRow(`SELECT count(*) FROM revoked_tokens WHERE jti = $1::text AND kind = 'access_token'`,
			jti).Scan(&n); err != nil {
			t.Fatalf("count revoked: %v", err)
		}
		if n != want {
			t.Errorf("revoked_tokens rows for %s = %d, want %d", jti, n, want)
		}
	}
}

// DeleteRoleBindingTx removes a binding of the named workspace only: another
// workspace's binding, named by its id, is left in place.
func TestDeleteRoleBindingIsScopedToItsWorkspace(t *testing.T) {
	raw, repo, _, ws := govFixture(t)
	roleB, saB, bindingB := uuid.New(), uuid.New(), uuid.New()
	exec(t, raw, "INSERT INTO roles (id,name,workspace_id) VALUES ($1,'agent-role',$2)", roleB, wsB)
	exec(t, raw, "INSERT INTO service_accounts (id,workspace_id,name,status) VALUES ($1,$2,'sa-b','active')", saB, wsB)
	exec(t, raw, `INSERT INTO role_bindings (id,workspace_id,role_id,service_account_id,role_name)
	              VALUES ($1,$2,$3,$4,'agent-role')`, bindingB, wsB, roleB, saB)

	g := gormFor(t, raw)
	if err := repo.DeleteRoleBindingTx(g, ws, bindingB); err != nil {
		t.Fatalf("delete as workspace A: %v", err)
	}
	var n int
	if err := raw.QueryRow("SELECT count(*) FROM role_bindings WHERE id = $1", bindingB).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatal("workspace A deleted workspace B's role binding by its id")
	}

	if err := repo.DeleteRoleBindingTx(g, uuid.MustParse(wsB), bindingB); err != nil {
		t.Fatalf("delete as workspace B: %v", err)
	}
	if err := raw.QueryRow("SELECT count(*) FROM role_bindings WHERE id = $1", bindingB).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Error("workspace B could not delete its own role binding")
	}
}
