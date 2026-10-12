//go:build integration

package flows

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Test_E2E_AgentBooksFlightOnBehalfOfUser_TwoTenants is the product's core
// story, run across two tenants (Phase 6):
//
// TravelCo (tenant A): Alice asks her booking agent to book a flight. The
// agent exchanges Alice's session for an ID-JAG naming Alice, redeems it at
// TravelCo's "flights" resource server for a scoped, short-lived token, and
// the flights API introspects that token before acting.
//
// OtherCo (tenant B) has its own admin, agent and resource server, and tries
// every way across: introspecting Alice's token, redeeming Alice's ID-JAG,
// minting its own token for TravelCo's API, reading TravelCo's API config,
// and revoking TravelCo's token. All of it must fail. Then TravelCo's own
// controls must work: a deny policy blocks the agent, revocation ends the
// token, and every decision is audited in TravelCo's workspace only.
func Test_E2E_AgentBooksFlightOnBehalfOfUser_TwoTenants(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)

	// ── TravelCo (A): Alice, the flights API, Alice's booking agent ─────────
	travel, err := SeedWorkspaceWithAdmin(config.DB, "tc"+n)
	if err != nil {
		t.Fatalf("seed TravelCo: %v", err)
	}
	flights, err := AddResourceServer(config.DB, travel, "https://flights-"+n+".travelco.example", "tc"+n)
	if err != nil {
		t.Fatalf("flights API: %v", err)
	}
	agent, err := AddServiceAccountWithScopes(config.DB, travel, flights, "tc"+n)
	if err != nil {
		t.Fatalf("booking agent: %v", err)
	}
	bookScope := flights.ScopeStrings[0]
	grantUserScope(t, travel, flights, "book-"+n)

	// ── OtherCo (B): its own admin, agent and API ───────────────────────────
	other, err := SeedWorkspaceWithAdmin(config.DB, "oc"+n)
	if err != nil {
		t.Fatalf("seed OtherCo: %v", err)
	}
	otherAPI, err := AddResourceServer(config.DB, other, "https://api-"+n+".otherco.example", "oc"+n)
	if err != nil {
		t.Fatalf("OtherCo API: %v", err)
	}
	otherAgent, err := AddServiceAccountWithScopes(config.DB, other, otherAPI, "oc"+n)
	if err != nil {
		t.Fatalf("OtherCo agent: %v", err)
	}
	otherAdmin := env.MustAsAdmin(other.AdminUserID, other.WorkspaceID, other.AdminEmail)
	travelAdmin := env.MustAsAdmin(travel.AdminUserID, travel.WorkspaceID, travel.AdminEmail)

	// Alice's session, as Hydra would confirm it to the token-exchange step.
	alice := env.MustAsAdmin(travel.AdminUserID, travel.WorkspaceID, travel.AdminEmail)
	env.Fakes.Hydra.OnIntrospect(func(_ string) map[string]interface{} {
		return map[string]interface{}{
			"active":    true,
			"sub":       travel.AdminUserID.String(),
			"client_id": agent.ClientIDString,
			"ext":       map[string]interface{}{"workspace_id": travel.WorkspaceID.String()},
		}
	})
	defer env.Fakes.Hydra.ResetIntrospect()

	// ── 1. Alice delegates to her agent; the agent gets a booking token ─────
	idJAG := issueIDJAG(t, env, alice, agent.ClientIDString, agent.ClientSecret)
	redeem := func(clientID, secret, resource string) *httpResult {
		w := env.DoBasicAuth(http.MethodPost, "/oauth/token", formBody(
			"grant_type", jwtBearerGrantType,
			"assertion", idJAG,
			"resource", resource,
			"scope", bookScope,
		), clientID, secret)
		return &httpResult{code: w.Code, body: w.Body.Bytes()}
	}
	res := redeem(agent.ClientIDString, agent.ClientSecret, flights.ResourceURI)
	if res.code != http.StatusOK {
		t.Fatalf("agent could not get a booking token: %d %s", res.code, res.body)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(res.body, &tok)
	if tok.AccessToken == "" {
		t.Fatalf("no access token: %s", res.body)
	}

	// ── 2. The flights API checks the token before booking ──────────────────
	w := env.DoBasicAuth("POST", "/oauth/introspect", formBody("token", tok.AccessToken), flights.RSID.String(), flights.IntrospectionSecret)
	assertActiveTrue(t, w)
	assertAudience(t, w, flights.ResourceURI)

	// ── 3. OtherCo cannot use, see or touch any of it ───────────────────────
	// a. OtherCo's API is told Alice's token is not active.
	w = env.DoBasicAuth("POST", "/oauth/introspect", formBody("token", tok.AccessToken), otherAPI.RSID.String(), otherAPI.IntrospectionSecret)
	assertActiveFalse(t, w)

	// b. OtherCo's agent cannot redeem Alice's ID-JAG anywhere.
	for _, target := range []string{flights.ResourceURI, otherAPI.ResourceURI} {
		if r := redeem(otherAgent.ClientIDString, otherAgent.ClientSecret, target); r.code == http.StatusOK {
			t.Fatalf("OtherCo's agent redeemed Alice's delegation at %s: %s", target, r.body)
		}
	}

	// c. OtherCo's agent cannot mint its own token for TravelCo's API.
	w = env.DoBasicAuth("POST", "/oauth/token", formBody(
		"grant_type", "client_credentials", "scope", bookScope, "resource", flights.ResourceURI,
	), otherAgent.ClientIDString, otherAgent.ClientSecret)
	if w.Code == http.StatusOK {
		t.Fatalf("OtherCo's agent got a token for TravelCo's flights API")
	}

	// d. OtherCo's admin cannot read TravelCo's API config or revoke its token.
	AssertCrossTenantNotFound(t, "GET", "/authsec/resource-servers/"+flights.RSID.String(), nil, otherAdmin)
	jti := tokenJTI(t, tok.AccessToken)
	AssertCrossTenantNotFound(t, "DELETE", "/authsec/tokens/"+jti, nil, otherAdmin)
	w = env.DoBasicAuth("POST", "/oauth/introspect", formBody("token", tok.AccessToken), flights.RSID.String(), flights.IntrospectionSecret)
	assertActiveTrue(t, w) // still valid: OtherCo's revoke did nothing

	// ── 4. TravelCo's own controls work ─────────────────────────────────────
	// a. A deny policy stops the agent from getting new booking tokens.
	mustExec(t, `INSERT INTO policies (workspace_id, name, client_id, resource_server_id, token_family, effect)
		VALUES (?, 'no-booking-agent', ?, ?, 'xaa', 'deny')`, travel.WorkspaceID, agent.ClientIDString, flights.RSID)
	if r := redeem(agent.ClientIDString, agent.ClientSecret, flights.ResourceURI); r.code == http.StatusOK {
		t.Fatalf("deny policy did not stop the booking agent: %s", r.body)
	}

	// b. TravelCo's admin revokes the outstanding token; the API sees it end.
	w = env.Do("DELETE", "/authsec/tokens/"+jti, nil, travelAdmin)
	if w.Code >= 300 {
		t.Fatalf("TravelCo admin could not revoke its own token: %d %s", w.Code, w.Body.String())
	}
	w = env.DoBasicAuth("POST", "/oauth/introspect", formBody("token", tok.AccessToken), flights.RSID.String(), flights.IntrospectionSecret)
	assertActiveFalse(t, w)

	// c. Every issuance decision was audited in TravelCo, none in OtherCo.
	var inTravel, inOther int64
	config.DB.Raw(`SELECT COUNT(*) FROM auth_issuance_audit WHERE workspace_id = ? AND client_id = ?`, travel.WorkspaceID, agent.ClientIDString).Scan(&inTravel)
	config.DB.Raw(`SELECT COUNT(*) FROM auth_issuance_audit WHERE workspace_id = ? AND client_id = ?`, other.WorkspaceID, agent.ClientIDString).Scan(&inOther)
	if inTravel == 0 {
		t.Errorf("TravelCo's issuance decisions were not audited")
	}
	if inOther != 0 {
		t.Errorf("TravelCo's agent decisions leaked into OtherCo's audit log (%d rows)", inOther)
	}
}

type httpResult struct {
	code int
	body []byte
}

// grantUserScope gives the workspace admin's role the RS's first scope, the
// same permission bridge the XAA same-workspace test uses.
func grantUserScope(t *testing.T, ws *WorkspaceScenario, rs *RSScenario, label string) {
	t.Helper()
	permID := uuid.New()
	mustExec(t, `INSERT INTO permissions (id, resource, action, full_permission_string, workspace_id, created_at, updated_at)
		VALUES (?, ?, 'read', ?, ?, NOW(), NOW())`, permID, label, label+":read", ws.WorkspaceID)
	mustExec(t, `INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?) ON CONFLICT DO NOTHING`, ws.AdminRoleID, permID)
	mustExec(t, `INSERT INTO oauth_scope_permissions (scope_id, permission_id) VALUES (?, ?) ON CONFLICT DO NOTHING`, rs.ScopeIDs[0], permID)
}

func tokenJTI(t *testing.T, token string) string {
	t.Helper()
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
		t.Fatalf("parse token: %v", err)
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		t.Fatalf("token has no jti")
	}
	return jti
}
