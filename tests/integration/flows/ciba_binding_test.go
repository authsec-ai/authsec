//go:build integration

package flows

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
)

// AS-044 / AS-015: CIBA requests are client-authenticated, looked up in the
// client's workspace, RBAC-intersected, and bound to the initiating client
// and resource server.

// addWorkspaceCIBADevice registers a workspace-plane push device for a user.
func addWorkspaceCIBADevice(t *testing.T, ws *WorkspaceScenario, userID uuid.UUID) {
	t.Helper()
	now := time.Now().Unix()
	mustExec(t, `INSERT INTO workspace_device_tokens (id, user_id, workspace_id, device_token, platform, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'test', true, $5, $5)`, uuid.New(), userID, ws.WorkspaceID, "dev-"+userID.String(), now)
}

// grantUserRSScope binds the user to a role that maps to the resource
// server's first scope, scoped to that resource server.
func grantUserRSScope(t *testing.T, ws *WorkspaceScenario, rs *RSScenario, userID uuid.UUID) {
	t.Helper()
	roleID, permID := uuid.New(), uuid.New()
	n := strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	mustExec(t, `INSERT INTO roles (id, workspace_id, name, description, is_system, created_at, updated_at)
		VALUES ($1, $2, $3, 'ciba user role', false, NOW(), NOW())`, roleID, ws.WorkspaceID, "ciba-role-"+n)
	mustExec(t, `INSERT INTO permissions (id, resource, action, full_permission_string, workspace_id, created_at, updated_at)
		VALUES ($1, $2, 'read', $3, $4, NOW(), NOW())`, permID, "ciba-"+n, "ciba-"+n+":read", ws.WorkspaceID)
	mustExec(t, `INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)`, roleID, permID)
	mustExec(t, `INSERT INTO oauth_scope_permissions (scope_id, permission_id) VALUES ($1, $2)`, rs.ScopeIDs[0], permID)
	mustExec(t, `INSERT INTO role_bindings (id, workspace_id, user_id, role_id, role_name, scope_type, scope_id, conditions, assignment_source, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, 'resource_server', $6, '{}'::jsonb, 'manual_admin', NOW(), NOW())`,
		uuid.New(), ws.WorkspaceID, userID, roleID, "ciba-role-"+n, rs.RSID)
}

type cibaFixture struct {
	ws   *WorkspaceScenario
	rs   *RSScenario
	sa   *SAScenario
	user *EndUserScenario
}

// newCIBAFixture: one workspace, one RS, one approved confidential client and
// an ordinary end user (users.client_id is NOT the client) with a device.
func newCIBAFixture(t *testing.T) *cibaFixture {
	t.Helper()
	n := emailSafeNonce()
	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := AddResourceServer(config.DB, ws, "https://rs-cibab-"+n+".example.com", n)
	if err != nil {
		t.Fatal(err)
	}
	sa, err := AddServiceAccountWithScopes(config.DB, ws, rs, n)
	if err != nil {
		t.Fatal(err)
	}
	u, err := AddEndUserWithRole(config.DB, ws, n)
	if err != nil {
		t.Fatal(err)
	}
	addWorkspaceCIBADevice(t, ws, u.UserID)
	return &cibaFixture{ws: ws, rs: rs, sa: sa, user: u}
}

func (f *cibaFixture) bcAuthorize(t *testing.T, sa *SAScenario, loginHint, scope string) (int, map[string]interface{}) {
	t.Helper()
	w := testsupport.Get(t).DoBasicAuth("POST", "/oauth/bc-authorize",
		formBody("login_hint", loginHint, "scope", scope, "resource", f.rs.ResourceURI), sa.ClientIDString, sa.ClientSecret)
	return w.Code, parseResp(w).Body
}

func (f *cibaFixture) approve(t *testing.T, authReqID string) {
	t.Helper()
	env := testsupport.Get(t)
	tok := env.MustAsUser(f.user.UserID, f.ws.WorkspaceID, f.user.Email)
	w := env.Do("POST", "/authsec/uflow/auth/workspace/ciba/respond",
		map[string]interface{}{"auth_req_id": authReqID, "approved": true}, tok)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"success":true`) {
		t.Fatalf("respond: %d %s", w.Code, w.Body.String())
	}
}

func (f *cibaFixture) poll(t *testing.T, sa *SAScenario, authReqID string) (int, map[string]interface{}) {
	t.Helper()
	w := testsupport.Get(t).DoBasicAuth("POST", "/oauth/token", formBody(
		"grant_type", "urn:openid:params:grant-type:ciba",
		"auth_req_id", authReqID,
		"resource", f.rs.ResourceURI,
	), sa.ClientIDString, sa.ClientSecret)
	return w.Code, parseResp(w).Body
}

// The user is found by (workspace, email), not by users.client_id.
func Test_CIBA_AS044_UserLookupByWorkspace(t *testing.T) {
	f := newCIBAFixture(t)
	code, body := f.bcAuthorize(t, f.sa, f.user.Email, "")
	if code != http.StatusOK || body["auth_req_id"] == nil {
		t.Fatalf("bc-authorize for a workspace user: got %d %v, want 200 with auth_req_id", code, body)
	}

	// A user of another workspace is never found through this client.
	_, other := TwoTenants(t)
	addWorkspaceCIBADevice(t, other.WS, other.EndUser.UserID)
	code, body = f.bcAuthorize(t, f.sa, other.EndUser.Email, "")
	if code != http.StatusBadRequest || body["error"] != "user_not_found" {
		t.Fatalf("bc-authorize for another workspace's user: got %d %v, want 400 user_not_found", code, body)
	}
}

// Requested scopes are intersected with the user's RBAC on the resource.
func Test_CIBA_AS044_ScopesIntersectedWithRBAC(t *testing.T) {
	f := newCIBAFixture(t)
	scope := f.rs.ScopeStrings[0]

	code, body := f.bcAuthorize(t, f.sa, f.user.Email, scope)
	if code != http.StatusBadRequest || body["error"] != "invalid_scope" {
		t.Fatalf("scope the user does not hold: got %d %v, want 400 invalid_scope", code, body)
	}

	grantUserRSScope(t, f.ws, f.rs, f.user.UserID)
	code, body = f.bcAuthorize(t, f.sa, f.user.Email, scope+" admin:everything")
	if code != http.StatusOK {
		t.Fatalf("bc-authorize with a held scope: got %d %v", code, body)
	}
	id := body["auth_req_id"].(string)
	f.approve(t, id)
	code, body = f.poll(t, f.sa, id)
	if code != http.StatusOK {
		t.Fatalf("poll: got %d %v", code, body)
	}
	if body["scope"] != scope {
		t.Fatalf("token scope = %v, want exactly %q", body["scope"], scope)
	}
}

// Only the initiating client may redeem the auth_req_id.
func Test_CIBA_AS044_PollBoundToInitiatingClient(t *testing.T) {
	f := newCIBAFixture(t)
	other, err := AddServiceAccountWithScopes(config.DB, f.ws, f.rs, emailSafeNonce())
	if err != nil {
		t.Fatal(err)
	}

	code, body := f.bcAuthorize(t, f.sa, f.user.Email, "")
	if code != http.StatusOK {
		t.Fatalf("bc-authorize: %d %v", code, body)
	}
	id := body["auth_req_id"].(string)
	f.approve(t, id)

	code, body = f.poll(t, other, id)
	if code == http.StatusOK || body["access_token"] != nil {
		t.Fatalf("another client redeemed the auth_req_id: %d %v", code, body)
	}
	if body["error"] != "invalid_grant" {
		t.Fatalf("other client poll: got %v, want invalid_grant", body)
	}

	code, body = f.poll(t, f.sa, id)
	if code != http.StatusOK || body["access_token"] == nil {
		t.Fatalf("initiating client poll: got %d %v, want 200 with a token", code, body)
	}
}

// The workspace CIBA endpoints require client authentication; a bare
// client_id is accepted only with CIBA_ALLOW_UNAUTHENTICATED_CLIENTS=true.
func Test_CIBA_AS044_WorkspaceSurfaceRequiresClientAuth(t *testing.T) {
	f := newCIBAFixture(t)
	env := testsupport.Get(t)
	body := map[string]interface{}{"client_id": f.sa.ClientIDString, "email": f.user.Email}

	w := env.Do("POST", "/authsec/uflow/auth/workspace/ciba/initiate", body, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated initiate: got %d %s, want 401", w.Code, w.Body.String())
	}
	w = env.DoBasicAuth("POST", "/authsec/uflow/auth/workspace/ciba/initiate", body, f.sa.ClientIDString, "wrong")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: got %d %s, want 401", w.Code, w.Body.String())
	}
	w = env.DoBasicAuth("POST", "/authsec/uflow/auth/workspace/ciba/initiate", body, f.sa.ClientIDString, f.sa.ClientSecret)
	if w.Code != http.StatusOK {
		t.Fatalf("authenticated initiate: got %d %s, want 200", w.Code, w.Body.String())
	}
	id := parseResp(w).Body["auth_req_id"].(string)

	w = env.Do("POST", "/authsec/uflow/auth/workspace/ciba/token",
		map[string]interface{}{"client_id": f.sa.ClientIDString, "auth_req_id": id}, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated poll: got %d %s, want 401", w.Code, w.Body.String())
	}

	t.Setenv("CIBA_ALLOW_UNAUTHENTICATED_CLIENTS", "true")
	w = env.Do("POST", "/authsec/uflow/auth/workspace/ciba/token",
		map[string]interface{}{"client_id": f.sa.ClientIDString, "auth_req_id": id}, "")
	if w.Code != http.StatusAccepted {
		t.Fatalf("compat-mode poll: got %d %s, want 202 authorization_pending", w.Code, w.Body.String())
	}
	w = env.DoBasicAuth("POST", "/authsec/uflow/auth/workspace/ciba/token",
		map[string]interface{}{"client_id": f.sa.ClientIDString, "auth_req_id": id}, f.sa.ClientIDString, "wrong")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("compat mode must still verify a sent credential: got %d", w.Code)
	}
}
