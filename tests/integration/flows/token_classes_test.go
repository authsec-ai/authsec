//go:build integration

package flows

import (
	"net/http"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/sessiontoken"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// consoleTokenFor mints a console-class (admin typ) session token for any
// workspace member, with no roles: what the console holds for a member who is
// not an admin.
func consoleTokenFor(t *testing.T, userID, workspaceID uuid.UUID, email string) string {
	t.Helper()
	tok, err := testsupport.MintClassToken(sessiontoken.Admin, testsupport.UserTokenParams{
		UserID: userID, WorkspaceID: workspaceID, Email: email,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// AS-033: admin, end-user and SDK session tokens are not interchangeable.
// The harness configures the same value for JWT_DEF_SECRET, JWT_SDK_SECRET
// and JWT_SECRET, so these assertions hold only because each class is
// verified under its own key and its own typ/aud.
func Test_SessionTokenClasses_PerSurface(t *testing.T) {
	env := testsupport.Get(t)
	a, _ := TwoTenants(t)
	user := testsupport.UserTokenParams{UserID: a.EndUser.UserID, WorkspaceID: a.WS.WorkspaceID, Email: a.EndUser.Email}
	adminUser := testsupport.UserTokenParams{UserID: a.WS.AdminUserID, WorkspaceID: a.WS.WorkspaceID, Email: a.WS.AdminEmail}

	const console = "/authsec/workspaces"
	const selfService = "/authsec/uflow/auth/workspace/totp/devices"

	// Console: admin only.
	assertStatus(t, env.Do("GET", console, nil, a.AdminToken), http.StatusOK)
	assertStatus(t, env.Do("GET", console, nil, a.EndUserToken), http.StatusUnauthorized)
	sdkTok, err := testsupport.MintClassToken(sessiontoken.SDK, adminUser)
	if err != nil {
		t.Fatal(err)
	}
	assertStatus(t, env.Do("GET", console, nil, sdkTok), http.StatusUnauthorized)

	// End-user self-service: end-user and admin tokens, not SDK tokens.
	if w := env.Do("GET", selfService, nil, a.EndUserToken); w.Code == http.StatusUnauthorized {
		t.Errorf("end-user token refused on end-user surface: %s", w.Body.String())
	}
	if w := env.Do("GET", selfService, nil, a.AdminToken); w.Code == http.StatusUnauthorized {
		t.Errorf("admin token refused on end-user surface: %s", w.Body.String())
	}
	sdkUser, _ := testsupport.MintClassToken(sessiontoken.SDK, user)
	assertStatus(t, env.Do("GET", selfService, nil, sdkUser), http.StatusUnauthorized)
}

// AS-033: no raw secret verifies a classed token, and aud must match typ.
func Test_SessionTokenClasses_RawSecretAndAudienceRefused(t *testing.T) {
	env := testsupport.Get(t)
	a, _ := TwoTenants(t)
	mk := func(typ, aud string) string {
		tok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"iss": "authsec-ai/auth-manager", "typ": typ, "aud": aud, "jti": "t-" + typ + aud,
			"sub": a.WS.AdminUserID.String(), "workspace_id": a.WS.WorkspaceID.String(),
			"email_id": a.WS.AdminEmail, "exp": time.Now().Add(time.Hour).Unix(),
		}).SignedString([]byte(testsupport.HarnessJWTSecret))
		return tok
	}
	assertStatus(t, env.Do("GET", "/authsec/workspaces", nil, mk("admin", "authsec-admin")), http.StatusUnauthorized)
	assertStatus(t, env.Do("GET", "/authsec/workspaces", nil, mk("enduser", "authsec-admin")), http.StatusUnauthorized)
}

// AS-033 transition: a legacy (typ-less) token from the previous release is
// still accepted until it expires.
func Test_SessionTokenClasses_LegacyTokenStillAccepted(t *testing.T) {
	env := testsupport.Get(t)
	a, _ := TwoTenants(t)
	legacy, err := testsupport.MintLegacyAdminToken(testsupport.AdminTokenParams{
		UserID: a.WS.AdminUserID, WorkspaceID: a.WS.WorkspaceID, Email: a.WS.AdminEmail, Roles: []string{"admin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertStatus(t, env.Do("GET", "/authsec/workspaces", nil, legacy), http.StatusOK)
}

// AS-033: tokens minted by the platform carry typ and the class audience.
func Test_SessionTokenClasses_LoginMintsClassedToken(t *testing.T) {
	env := testsupport.Get(t)
	a, _ := TwoTenants(t)
	w := env.Do("POST", "/authsec/uflow/auth/admin/login", map[string]string{
		"email": a.WS.AdminEmail, "password": a.WS.AdminPassword, "workspace_domain": a.WS.WorkspaceDomain,
	}, "")
	assertStatus(t, w, http.StatusOK)
	token, _ := decodeJSON(t, w)["token"].(string)
	claims := jwt.MapClaims{}
	_, _, _ = jwt.NewParser().ParseUnverified(token, claims)
	if claims["typ"] != "admin" || claims["aud"] != "authsec-admin" {
		t.Fatalf("admin login minted typ=%v aud=%v", claims["typ"], claims["aud"])
	}
}
