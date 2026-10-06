//go:build integration

package flows

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
)

// Regression tests for AS-013, AS-014, AS-025, AS-026 and AS-027: a record
// belonging to another workspace must behave as not found.

func seedWorkspace(t *testing.T, n string) *WorkspaceScenario {
	t.Helper()
	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	return ws
}

// mustExec is defined in tenant_boundary_test.go.

// grantAllPermissions gives the workspace's seeded admin role every permission,
// so routes gated by middlewares.Require can be reached.
func grantAllPermissions(t *testing.T, ws *WorkspaceScenario) {
	t.Helper()
	mustExec(t, `INSERT INTO permissions (id, workspace_id, resource, action)
		VALUES (?, ?, '*', '*') ON CONFLICT DO NOTHING`, uuid.New(), ws.WorkspaceID)
	mustExec(t, `INSERT INTO role_permissions (role_id, permission_id)
		SELECT ?, id FROM permissions WHERE workspace_id = ? AND resource = '*' AND action = '*'
		ON CONFLICT DO NOTHING`, ws.AdminRoleID, ws.WorkspaceID)
}

func seedDiscoveredAgent(t *testing.T, ws *WorkspaceScenario, fingerprint string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	mustExec(t, `INSERT INTO discovered_agents (id, workspace_id, source, fingerprint, display_name)
		VALUES (?, ?, 'k8s_webhook', ?, 'agent')`, id, ws.WorkspaceID, fingerprint)
	return id
}

func scalar(t *testing.T, query string, args ...interface{}) string {
	t.Helper()
	var out *string
	if err := config.DB.Raw(query, args...).Scan(&out).Error; err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	if out == nil {
		return ""
	}
	return *out
}

// AS-026: claim must not bind another workspace's OAuth client, and a claim made
// before the fix must not let provision/deprovision take that client over.
func Test_DiscoveryClaim_ForeignClientIsNotFound(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	wsA := seedWorkspace(t, n+"a")
	wsB := seedWorkspace(t, n+"b")
	grantAllPermissions(t, wsA)
	rsB, err := AddResourceServer(config.DB, wsB, "https://rs-"+n+"b.example", n+"b")
	if err != nil {
		t.Fatalf("rs B: %v", err)
	}
	saB, err := AddServiceAccountWithScopes(config.DB, wsB, rsB, n+"b")
	if err != nil {
		t.Fatalf("sa B: %v", err)
	}
	tokA := env.MustAsAdmin(wsA.AdminUserID, wsA.WorkspaceID, wsA.AdminEmail)

	agentID := seedDiscoveredAgent(t, wsA, "fp-claim-"+n)
	w := env.Do("POST", "/authsec/discovery/agents/"+agentID.String()+"/claim", map[string]interface{}{
		"matched_client_id": saB.ClientID.String(),
		"owner_user_id":     wsA.AdminUserID.String(),
	}, tokA)
	assertStatus(t, w, http.StatusNotFound)
	if got := scalar(t, `SELECT status FROM discovered_agents WHERE id = ?`, agentID); got != "unregistered" {
		t.Fatalf("agent status = %q after a refused claim", got)
	}

	// A client of the caller's own workspace is still accepted.
	own := uuid.New()
	mustExec(t, `INSERT INTO mcp_oauth_clients (id, client_id, hydra_client_id, client_name, home_workspace_id, client_kind)
		VALUES (?, ?, ?, 'own-agent', ?, 'agent')`, own, own.String(), own.String(), wsA.WorkspaceID)
	w = env.Do("POST", "/authsec/discovery/agents/"+agentID.String()+"/claim", map[string]interface{}{
		"matched_client_id": own.String(),
		"owner_user_id":     wsA.AdminUserID.String(),
	}, tokA)
	assertStatus(t, w, http.StatusOK)
}

func Test_Provisioning_ForeignClientIsNotFound(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	wsA := seedWorkspace(t, n+"a")
	wsB := seedWorkspace(t, n+"b")
	grantAllPermissions(t, wsA)
	rsA, err := AddResourceServer(config.DB, wsA, "https://rs-"+n+"a.example", n+"a")
	if err != nil {
		t.Fatalf("rs A: %v", err)
	}
	rsB, err := AddResourceServer(config.DB, wsB, "https://rs-"+n+"b.example", n+"b")
	if err != nil {
		t.Fatalf("rs B: %v", err)
	}
	saB, err := AddServiceAccountWithScopes(config.DB, wsB, rsB, n+"b")
	if err != nil {
		t.Fatalf("sa B: %v", err)
	}
	roleA := uuid.New()
	mustExec(t, `INSERT INTO roles (id, workspace_id, name, created_at, updated_at)
		VALUES (?, ?, ?, NOW(), NOW())`, roleA, wsA.WorkspaceID, "agent-"+n)

	// The state an unchecked claim left behind: A's agent bound to B's client.
	agentID := uuid.New()
	mustExec(t, `INSERT INTO discovered_agents (id, workspace_id, source, fingerprint, status,
			matched_client_id, owner_user_id)
		VALUES (?, ?, 'k8s_webhook', ?, 'registered', ?, ?)`,
		agentID, wsA.WorkspaceID, "fp-prov-"+n, saB.ClientID, wsA.AdminUserID)
	govBefore := scalar(t, `SELECT governance_status FROM mcp_oauth_clients WHERE id = ?`, saB.ClientID)
	tokA := env.MustAsAdmin(wsA.AdminUserID, wsA.WorkspaceID, wsA.AdminEmail)

	w := env.Do("POST", "/authsec/provisioning/agents/"+agentID.String()+"/provision", map[string]interface{}{
		"resource_server_id": rsA.RSID.String(),
		"role_id":            roleA.String(),
		"expires_at":         time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}, tokA)
	assertStatus(t, w, http.StatusNotFound)
	if got := scalar(t, `SELECT owner_user_id::text FROM mcp_oauth_clients WHERE id = ?`, saB.ClientID); got != "" {
		t.Fatalf("B's client was given an owner from A: %s", got)
	}

	w = env.Do("POST", "/authsec/provisioning/agents/"+agentID.String()+"/deprovision",
		map[string]interface{}{"reason": "test"}, tokA)
	assertStatus(t, w, http.StatusNotFound)
	if got := scalar(t, `SELECT status FROM resource_server_client_registrations
		WHERE oauth_client_id = ? AND resource_server_id = ?`, saB.ClientID, rsB.RSID); got != "approved" {
		t.Fatalf("B's registration was changed by A: status %q", got)
	}
	if got := scalar(t, `SELECT governance_status FROM mcp_oauth_clients WHERE id = ?`, saB.ClientID); got != govBefore {
		t.Fatalf("B's client governance_status changed from %q to %q", govBefore, got)
	}
}

// AS-027: approve-redirects must not reach a client that is not registered on
// the caller's resource server or that another workspace owns.
func Test_ApproveRedirects_ForeignClientIsNotFound(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	wsA := seedWorkspace(t, n+"a")
	wsB := seedWorkspace(t, n+"b")
	rsA, err := AddResourceServer(config.DB, wsA, "https://rs-"+n+"a.example", n+"a")
	if err != nil {
		t.Fatalf("rs A: %v", err)
	}
	rsB, err := AddResourceServer(config.DB, wsB, "https://rs-"+n+"b.example", n+"b")
	if err != nil {
		t.Fatalf("rs B: %v", err)
	}
	saB, err := AddServiceAccountWithScopes(config.DB, wsB, rsB, n+"b")
	if err != nil {
		t.Fatalf("sa B: %v", err)
	}
	pending := "https://app-" + n + ".example/cb"
	mustExec(t, `UPDATE mcp_oauth_clients SET redirect_review_pending = true,
		pending_redirect_uris = ARRAY[?]::text[] WHERE id = ?`, pending, saB.ClientID)
	stillPending := func() bool {
		return scalar(t, `SELECT redirect_review_pending::text FROM mcp_oauth_clients WHERE id = ?`,
			saB.ClientID) == "true"
	}
	tokA := env.MustAsAdmin(wsA.AdminUserID, wsA.WorkspaceID, wsA.AdminEmail)
	path := func(rs uuid.UUID) string {
		return "/authsec/resource-servers/" + rs.String() + "/clients/" + saB.ClientIDString + "/approve-redirects"
	}

	// Not registered on A's resource server.
	assertStatus(t, env.Do("PUT", path(rsA.RSID), nil, tokA), http.StatusNotFound)
	if !stillPending() {
		t.Fatalf("A approved B's pending redirect URIs")
	}

	// Registered on A's resource server, but B's client: still not A's to change.
	mustExec(t, `INSERT INTO resource_server_client_registrations
			(id, resource_server_id, oauth_client_id, workspace_id, status, registration_type)
		VALUES (?, ?, ?, ?, 'pending_approval', 'dcr')`, uuid.New(), rsA.RSID, saB.ClientID, wsA.WorkspaceID)
	assertStatus(t, env.Do("PUT", path(rsA.RSID), nil, tokA), http.StatusNotFound)
	if !stillPending() {
		t.Fatalf("A approved B's pending redirect URIs through a cross-workspace registration")
	}

	// B approves its own client on its own resource server.
	tokB := env.MustAsAdmin(wsB.AdminUserID, wsB.WorkspaceID, wsB.AdminEmail)
	assertStatus(t, env.Do("PUT", path(rsB.RSID), nil, tokB), http.StatusOK)
	if stillPending() {
		t.Fatalf("own-workspace approval did not apply")
	}
}

// AS-013: a SPIFFE SVID only reaches services created in its own workspace.
func Test_ExtSvcCredentials_SVIDCannotReadOtherWorkspace(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	wsA := seedWorkspace(t, n+"a")
	wsB := seedWorkspace(t, n+"b")
	keyA, err := env.Fakes.JWKS.RegisterWorkspace(wsA.WorkspaceID.String())
	if err != nil {
		t.Fatalf("register A: %v", err)
	}
	keyB, err := env.Fakes.JWKS.RegisterWorkspace(wsB.WorkspaceID.String())
	if err != nil {
		t.Fatalf("register B: %v", err)
	}
	svcB := uuid.New()
	mustExec(t, `INSERT INTO services (id, name, type, created_by, agent_accessible, vault_path, workspace_id)
		VALUES (?, ?, 'api', ?, true, ?, ?)`, svcB, "svc-"+n, wsB.AdminUserID.String(), "secret/svc-"+n, wsB.WorkspaceID)

	svid := func(ws *WorkspaceScenario, key *rsa.PrivateKey) string {
		tok, err := testsupport.MintSVID(testsupport.SVIDParams{
			SpiffeID:    "spiffe://" + ws.WorkspaceDomain + "/agent",
			WorkspaceID: ws.WorkspaceID.String(),
			Permissions: []string{"external-service:credentials"},
			PrivateKey:  key,
		})
		if err != nil {
			t.Fatalf("mint svid: %v", err)
		}
		return tok
	}
	path := "/authsec/exsvc/services/" + svcB.String() + "/credentials"

	assertStatus(t, env.Do("GET", path, nil, svid(wsA, keyA)), http.StatusNotFound)

	// B's own SVID gets past the lookup (the harness has no Vault, so it fails
	// later, but not with not-found).
	w := env.Do("GET", path, nil, svid(wsB, keyB))
	if w.Code == http.StatusNotFound || w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
		t.Fatalf("own-workspace SVID refused: %d %s", w.Code, w.Body.String())
	}
}

// AS-025: a delegated token is readable by the user who delegated it and by
// workspace owners/admins only.
func Test_DelegationToken_OnlyOwnerOrAdmin(t *testing.T) {
	env := testsupport.Get(t)
	ws, owner := seedEndUser(t)
	other, err := AddEndUserWithRole(config.DB, ws, emailSafeNonce())
	if err != nil {
		t.Fatalf("seed other user: %v", err)
	}
	agent := uuid.New()
	secret := "delegated-svid-" + emailSafeNonce()
	mustExec(t, `INSERT INTO delegation_tokens (id, client_id, workspace_id, token, spiffe_id,
			expires_at, delegated_by, ttl_seconds)
		VALUES (?, ?, ?, ?, 'spiffe://test/agent', ?, ?, 3600)`,
		uuid.New(), agent, ws.WorkspaceID, secret, time.Now().Add(time.Hour), owner.UserID)
	path := "/authsec/uflow/sdk/delegation-token?client_id=" + agent.String()

	w := env.Do("GET", path, nil, env.MustAsUser(other.UserID, ws.WorkspaceID, other.Email))
	assertStatus(t, w, http.StatusNotFound)
	if strings.Contains(w.Body.String(), secret) {
		t.Fatalf("another member received the delegated token")
	}

	w = env.Do("GET", path, nil, env.MustAsUser(owner.UserID, ws.WorkspaceID, owner.Email))
	assertStatus(t, w, http.StatusOK)
	w = env.Do("GET", path, nil, env.MustAsAdmin(ws.AdminUserID, ws.WorkspaceID, ws.AdminEmail))
	assertStatus(t, w, http.StatusOK)
}

// AS-014: a connector that holds a credential cannot be spoken for without it,
// and a presented credential, not the body, decides the workspace.
func Test_DiscoveryIngress_ConnectorCredential(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	wsA := seedWorkspace(t, n+"a")
	wsB := seedWorkspace(t, n+"b")
	token := "authsec_act_" + n + "credential"
	sum := sha256.Sum256([]byte(token))
	src := uuid.New()
	cluster := "cluster-" + n
	mustExec(t, `INSERT INTO discovery_sources (id, workspace_id, kind, display_name, instance_id,
			cluster_name, self_registered, actuation_token_hash, actuation_enabled_at)
		VALUES (?, ?, 'k8s_webhook', ?, ?, ?, true, ?, NOW())`,
		src, wsA.WorkspaceID, cluster, "inst-"+n, cluster, hex.EncodeToString(sum[:]))
	a := wsA.WorkspaceID.String()

	for _, r := range []struct {
		path string
		body map[string]interface{}
	}{
		{"/authsec/discovery/sightings", map[string]interface{}{
			"workspace_id": a, "source": "k8s_webhook", "discovery_source_id": src.String(), "fingerprint": "fp-" + n}},
		{"/authsec/discovery/agent-registration", map[string]interface{}{
			"workspace_id": a, "kind": "k8s_webhook", "instance_id": "inst-" + n, "cluster_name": cluster}},
		{"/authsec/discovery/lifecycle", map[string]interface{}{
			"workspace_id": a, "source": "k8s_webhook", "cluster": cluster, "fingerprint": "fp-" + n, "event": "deleted"}},
		{"/authsec/discovery/resync-manifest", map[string]interface{}{
			"workspace_id": a, "source": "k8s_webhook", "cluster": cluster, "complete": true,
			"namespaces": []string{"default"}, "fingerprints": []string{}}},
	} {
		if w := env.Do("POST", r.path, r.body, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("%s without the connector credential: got %d, want 401 (%s)", r.path, w.Code, w.Body.String())
		}
	}

	// The credential is A's: naming B is not found and writes nothing there.
	fp := "fp-cred-" + n
	w := env.Do("POST", "/authsec/discovery/sightings", map[string]interface{}{
		"workspace_id": wsB.WorkspaceID.String(), "source": "k8s_webhook", "fingerprint": fp}, token)
	assertStatus(t, w, http.StatusNotFound)
	if got := scalar(t, `SELECT COUNT(*)::text FROM discovered_agents WHERE fingerprint = ?`, fp); got != "0" {
		t.Fatalf("a sighting was written although the request was refused")
	}

	w = env.Do("POST", "/authsec/discovery/sightings", map[string]interface{}{
		"workspace_id": a, "source": "k8s_webhook", "fingerprint": fp}, token)
	assertStatus(t, w, http.StatusCreated)
	if got := scalar(t, `SELECT discovery_source_id::text FROM discovered_agents
		WHERE workspace_id = ? AND fingerprint = ?`, wsA.WorkspaceID, fp); got != src.String() {
		t.Fatalf("sighting not attributed to the credential's connector: %q", got)
	}

	// A connector credential that does not verify is refused, not ignored.
	assertStatus(t, env.Do("POST", "/authsec/discovery/sightings", map[string]interface{}{
		"workspace_id": a, "source": "k8s_webhook", "fingerprint": fp}, "authsec_act_not-a-real-one"),
		http.StatusUnauthorized)
}

// AS-014: an unauthenticated caller no longer reads inventory rows back.
func Test_DiscoveryIngress_UnauthenticatedGetsNoRowsBack(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	ws := seedWorkspace(t, n)
	a := ws.WorkspaceID.String()

	w := env.Do("POST", "/authsec/discovery/sightings", map[string]interface{}{
		"workspace_id": a, "source": "k8s_webhook", "fingerprint": "fp-" + n,
		"metadata": map[string]interface{}{"note": "x"}}, "")
	assertStatus(t, w, http.StatusCreated)
	var sighting struct {
		Agent map[string]interface{} `json:"agent"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &sighting); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(sighting.Agent) != 1 || sighting.Agent["id"] == nil {
		t.Fatalf("unauthenticated sighting returned the inventory row: %s", w.Body.String())
	}

	w = env.Do("POST", "/authsec/discovery/agent-registration", map[string]interface{}{
		"workspace_id": a, "kind": "k8s_webhook", "instance_id": "inst-" + n, "cluster_name": "c-" + n}, "")
	assertStatus(t, w, http.StatusCreated)
	body := parseBody(t, w)
	if body["discovery_source_id"] == nil {
		t.Fatalf("registration must still return discovery_source_id: %s", w.Body.String())
	}
	if _, leaked := body["source"]; leaked {
		t.Fatalf("unauthenticated registration returned the connector row: %s", w.Body.String())
	}
}
