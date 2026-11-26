//go:build integration

package flows

import (
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
)

// OIDC sign-up creates the workspace, its admin, role bindings and membership
// in one transaction under row-level security for the new workspace.

type oidcSignupRows struct {
	users, bindings, memberships, adminMemberships int64
}

func oidcSignupState(t *testing.T, email string) (uuid.UUID, oidcSignupRows) {
	t.Helper()
	var ws uuid.UUID
	if err := config.DB.Raw(`SELECT workspace_id FROM users WHERE LOWER(email) = LOWER($1)`, email).Row().Scan(&ws); err != nil {
		t.Fatalf("no user created for %s: %v", email, err)
	}
	var r oidcSignupRows
	config.DB.Raw(`SELECT COUNT(*) FROM users WHERE workspace_id = $1`, ws).Row().Scan(&r.users)
	config.DB.Raw(`SELECT COUNT(*) FROM role_bindings WHERE workspace_id = $1`, ws).Row().Scan(&r.bindings)
	config.DB.Raw(`SELECT COUNT(*) FROM workspace_memberships WHERE workspace_id = $1`, ws).Row().Scan(&r.memberships)
	config.DB.Raw(`SELECT COUNT(*) FROM workspace_memberships m JOIN roles r ON r.id = m.role_id
		WHERE m.workspace_id = $1 AND r.workspace_id = $1 AND r.name = 'admin' AND m.status = 'active'`, ws).Row().Scan(&r.adminMemberships)
	var exists bool
	config.DB.Raw(`SELECT EXISTS (SELECT 1 FROM workspaces WHERE id = $1)`, ws).Row().Scan(&exists)
	if !exists {
		t.Fatalf("workspace %s row missing", ws)
	}
	return ws, r
}

func Test_OIDCCompleteRegistration_CreatesWorkspaceScoped(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	email := "crowner-" + n + "@example.test"
	sub := "sub-cr-" + n
	idp := newFakeIdP(t, email, sub)
	provider := "pcr" + n
	insertOIDCProvider(t, nil, provider, "cid-cr-"+n, idp.srv.URL)

	stateTok := "st-cr-" + n
	insertOIDCState(t, stateTok, provider, "discover", nil, "")
	w := env.Do("POST", "/authsec/uflow/oidc/exchange-code", map[string]string{"code": "c", "state": stateTok}, "")
	assertStatus(t, w, http.StatusNotFound)
	pd, _ := decodeJSON(t, w)["provider_data"].(map[string]interface{})
	regState, _ := pd["state_token"].(string)
	if regState == "" {
		t.Fatalf("needs_domain response carries no state_token: %s", w.Body.String())
	}

	w = env.Do("POST", "/authsec/uflow/oidc/complete-registration", map[string]string{
		"workspace_domain": "cr" + n, "provider": provider, "email": email,
		"name": "Owner", "provider_user_id": sub, "state_token": regState,
	}, "")
	assertStatus(t, w, http.StatusOK)
	resp := decodeJSON(t, w)

	ws, r := oidcSignupState(t, email)
	if resp["workspace_id"] != ws.String() {
		t.Fatalf("response workspace %v, user created in %s", resp["workspace_id"], ws)
	}
	if r.users != 1 || r.bindings != 1 || r.memberships != 1 || r.adminMemberships != 1 {
		t.Fatalf("complete-registration rows: %+v (want 1 user, 1 binding, 1 admin membership)", r)
	}
}

func Test_OIDCRegisterCallback_CreatesWorkspaceScoped(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	email := "regowner-" + n + "@example.test"
	idp := newFakeIdP(t, email, "sub-reg-"+n)
	provider := "preg" + n
	insertOIDCProvider(t, nil, provider, "cid-reg-"+n, idp.srv.URL)

	stateTok := "st-reg-" + n
	insertOIDCState(t, stateTok, provider, "register", nil, "reg"+n)
	w := env.Do("POST", "/authsec/uflow/oidc/exchange-code", map[string]string{"code": "c", "state": stateTok}, "")
	assertStatus(t, w, http.StatusOK)

	_, r := oidcSignupState(t, email)
	// Workspace-wide admin, one binding per core service, and the wildcard.
	wantBindings := int64(1 + 7 + 1)
	if r.users != 1 || r.bindings != wantBindings || r.memberships != 1 || r.adminMemberships != 1 {
		t.Fatalf("register callback rows: %+v (want 1 user, %d bindings, 1 admin membership)", r, wantBindings)
	}
}
