//go:build integration

package flows

import (
	"net/http"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
)

// Cross-tenant isolation for the agent / resource plane (Phase 3): every
// route that takes an id of an application / resource server, its clients,
// tools, roles, bindings, or of a brokering policy, delegation policy,
// consent grant or connector is called as workspace A's admin with workspace
// B's ids. None may succeed, and nothing of B may change.

type planeB struct {
	rs, sa                                    uuid.UUID
	saClient                                  string
	brokering, delegation, consent, connector uuid.UUID
	rsName                                    string
}

func seedPlaneB(t *testing.T, b *Tenant, n string) planeB {
	t.Helper()
	rs, err := AddResourceServer(config.DB, b.WS, "https://plane-"+n+".example.com", "pl"+n)
	if err != nil {
		t.Fatalf("rs: %v", err)
	}
	sa, err := AddServiceAccountWithScopes(config.DB, b.WS, rs, "pl"+n)
	if err != nil {
		t.Fatalf("sa: %v", err)
	}
	p := planeB{rs: rs.RSID, sa: sa.SAID, saClient: sa.ClientIDString, brokering: uuid.New(), delegation: uuid.New(), consent: uuid.New(), connector: uuid.New()}
	config.DB.Raw(`SELECT name FROM resource_servers WHERE id = ?`, rs.RSID).Scan(&p.rsName)
	mustExec(t, `INSERT INTO a2a_brokering_policies (id, workspace_id, side, client_id, resource_server_id, effect)
		VALUES (?, ?, 'redemption', ?, ?, 'permit')`, p.brokering, b.WS.WorkspaceID, sa.ClientIDString, rs.RSID)
	mustExec(t, `INSERT INTO delegation_policies (id, workspace_id, role_name, agent_type)
		VALUES (?, ?, 'admin', ?)`, p.delegation, b.WS.WorkspaceID, "booking-"+n)
	mustExec(t, `INSERT INTO oauth_consent_grants (id, workspace_id, user_id, oauth_client_id, resource_server_id, granted_scopes, expires_at)
		VALUES (?, ?, ?, ?, ?, ARRAY['read'], now() + interval '1 day')`, p.consent, b.WS.WorkspaceID, b.EndUser.UserID, sa.ClientID, rs.RSID)
	mustExec(t, `INSERT INTO connectors (id, workspace_id, provider_key, name, created_by)
		VALUES (?, ?, 'github', ?, ?)`, p.connector, b.WS.WorkspaceID, "gh-"+n, b.WS.AdminUserID.String())
	return p
}

func Test_Isolation_AgentPlane_ByIDRoutes(t *testing.T) {
	env := testsupport.Get(t)
	a, b := TwoTenants(t)
	p := seedPlaneB(t, b, emailSafeNonce())

	rs, sa := p.rs.String(), p.sa.String()
	body := map[string]interface{}{"name": "hijacked", "scopes": []string{"x"}, "redirect_uris": []string{"https://evil.example/cb"}}
	routes := []struct{ method, path string }{}
	for _, base := range []string{"/authsec/resource-servers/", "/authsec/applications/"} {
		for _, r := range []struct{ m, suffix string }{
			{"GET", ""}, {"PUT", ""}, {"DELETE", ""},
			{"POST", "/rotate-introspection-secret"},
			{"GET", "/access-policy"}, {"PUT", "/access-policy"},
			{"GET", "/scope-matrix"}, {"GET", "/scopes"}, {"POST", "/scopes"},
			{"PUT", "/tool-scope-map"}, {"GET", "/setup"}, {"POST", "/activate"},
			{"POST", "/tools"}, {"GET", "/roles"}, {"GET", "/bindings"}, {"POST", "/bindings"},
			{"GET", "/eligible-users"}, {"GET", "/activation-preview"},
		} {
			routes = append(routes, struct{ method, path string }{r.m, base + rs + r.suffix})
		}
	}
	routes = append(routes,
		struct{ method, path string }{"GET", "/authsec/resource-servers/" + rs + "/clients"},
		struct{ method, path string }{"DELETE", "/authsec/resource-servers/" + rs + "/clients/" + p.saClient},
		struct{ method, path string }{"PUT", "/authsec/resource-servers/" + rs + "/clients/" + p.saClient + "/approve-redirects"},
		struct{ method, path string }{"GET", "/authsec/applications/" + rs + "/connections"},
		struct{ method, path string }{"PUT", "/authsec/applications/" + rs + "/connections/" + sa + "/approve"},
		struct{ method, path string }{"DELETE", "/authsec/applications/" + rs + "/connections/" + sa},
		struct{ method, path string }{"DELETE", "/authsec/brokering-policies/" + p.brokering.String()},
		struct{ method, path string }{"GET", "/authsec/uflow/delegation-policies/" + p.delegation.String()},
		struct{ method, path string }{"PUT", "/authsec/uflow/delegation-policies/" + p.delegation.String()},
		struct{ method, path string }{"DELETE", "/authsec/uflow/delegation-policies/" + p.delegation.String()},
		struct{ method, path string }{"DELETE", "/authsec/consent-grants/" + p.consent.String()},
		struct{ method, path string }{"GET", "/authsec/connectors/" + p.connector.String()},
		struct{ method, path string }{"PUT", "/authsec/connectors/" + p.connector.String()},
		struct{ method, path string }{"DELETE", "/authsec/connectors/" + p.connector.String()},
		struct{ method, path string }{"GET", "/authsec/connectors/" + p.connector.String() + "/config"},
		struct{ method, path string }{"GET", "/authsec/connectors/" + p.connector.String() + "/assignments"},
		struct{ method, path string }{"POST", "/authsec/connectors/" + p.connector.String() + "/assignments"},
	)

	for _, r := range routes {
		w := env.Do(r.method, r.path, body, a.AdminToken)
		if w.Code < 300 || w.Code >= 500 {
			t.Errorf("A's admin on B's object %s %s: got %d (%s)", r.method, r.path, w.Code, truncate(w.Body.String()))
		}
		if w.Code < 300 && strings.Contains(w.Body.String(), p.rsName) {
			t.Errorf("%s %s leaked B's data", r.method, r.path)
		}
	}

	// Nothing of B changed.
	var name string
	config.DB.Raw(`SELECT name FROM resource_servers WHERE id = ?`, p.rs).Scan(&name)
	if name != p.rsName {
		t.Errorf("B's resource server changed or vanished: %q -> %q", p.rsName, name)
	}
	AssertRowCount(t, "a2a_brokering_policies", "id", p.brokering, 1)
	AssertRowCount(t, "delegation_policies", "id", p.delegation, 1)
	AssertRowCount(t, "connectors", "id", p.connector, 1)
	var revoked int64
	config.DB.Raw(`SELECT COUNT(*) FROM oauth_consent_grants WHERE id = ? AND revoked_at IS NULL`, p.consent).Scan(&revoked)
	if revoked != 1 {
		t.Errorf("B's consent grant was revoked by A")
	}
	var regStatus string
	config.DB.Raw(`SELECT status FROM resource_server_client_registrations WHERE resource_server_id = ? LIMIT 1`, p.rs).Scan(&regStatus)
	if regStatus != "" && regStatus != "approved" {
		t.Errorf("B's client registration changed to %q", regStatus)
	}
}

// List endpoints of the plane never show another workspace's objects.
func Test_Isolation_AgentPlane_ListsAreScoped(t *testing.T) {
	env := testsupport.Get(t)
	a, b := TwoTenants(t)
	p := seedPlaneB(t, b, emailSafeNonce())
	for _, path := range []string{
		"/authsec/resource-servers", "/authsec/applications", "/authsec/clients",
		"/authsec/brokering-policies", "/authsec/consent-grants", "/authsec/connectors",
		"/authsec/uflow/delegation-policies",
	} {
		w := env.Do("GET", path, nil, a.AdminToken)
		if w.Code >= 500 {
			t.Errorf("GET %s: %d", path, w.Code)
			continue
		}
		s := w.Body.String()
		for _, id := range []string{p.rs.String(), p.brokering.String(), p.delegation.String(), p.consent.String(), p.connector.String(), p.saClient} {
			if strings.Contains(s, id) {
				t.Errorf("GET %s as A lists B's object %s", path, id)
			}
		}
	}
}

func truncate(s string) string {
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

var _ = http.StatusOK
