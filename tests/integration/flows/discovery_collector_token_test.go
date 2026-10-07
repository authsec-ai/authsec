//go:build integration

package flows

import (
	"net/http"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/testsupport"
)

// AS-014: the discovery ingress takes its workspace from a per-workspace
// collector credential; reports without one are refused by default.
func Test_DiscoveryIngress_CollectorCredential(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	wsA := seedWorkspace(t, n+"a")
	wsB := seedWorkspace(t, n+"b")
	grantAllPermissions(t, wsA)
	grantAllPermissions(t, wsB)
	tokA := env.MustAsAdmin(wsA.AdminUserID, wsA.WorkspaceID, wsA.AdminEmail)
	tokB := env.MustAsAdmin(wsB.AdminUserID, wsB.WorkspaceID, wsB.AdminEmail)
	a := wsA.WorkspaceID.String()

	// Without a credential: refused, with directions, and nothing written.
	fp := "fp-col-" + n
	w := env.Do("POST", "/authsec/discovery/sightings", map[string]interface{}{
		"workspace_id": a, "source": "k8s_webhook", "fingerprint": fp}, "")
	assertStatus(t, w, http.StatusUnauthorized)
	for _, want := range []string{"/authsec/discovery/collector-tokens", "controlPlane.sourceToken", "DISCOVERY_ALLOW_UNAUTHENTICATED_INGRESS"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("refusal does not mention %q: %s", want, w.Body.String())
		}
	}
	if got := scalar(t, `SELECT COUNT(*)::text FROM discovered_agents WHERE fingerprint = ?`, fp); got != "0" {
		t.Fatalf("an unauthenticated sighting was written")
	}
	// An unknown bearer value is not a credential either.
	assertStatus(t, env.Do("POST", "/authsec/discovery/sightings", map[string]interface{}{
		"workspace_id": a, "source": "k8s_webhook", "fingerprint": fp}, "some-old-source-token"), http.StatusUnauthorized)

	// Workspace A's admin mints a collector credential.
	w = env.Do("POST", "/authsec/discovery/collector-tokens", map[string]interface{}{"name": "cluster-1"}, tokA)
	assertStatus(t, w, http.StatusCreated)
	body := parseBody(t, w)
	col, _ := body["token"].(string)
	if !strings.HasPrefix(col, "authsec_col_") {
		t.Fatalf("mint: no token in %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "token_hash") {
		t.Fatalf("mint response exposes the hash: %s", w.Body.String())
	}
	if got := scalar(t, `SELECT COUNT(*)::text FROM discovery_collector_tokens WHERE token_hash = ?`, col); got != "0" {
		t.Fatalf("collector token stored in plaintext")
	}
	id := body["collector_token"].(map[string]interface{})["id"].(string)

	// The credential decides the workspace (the body must agree), and
	// naming another workspace is not found.
	w = env.Do("POST", "/authsec/discovery/sightings", map[string]interface{}{
		"workspace_id": a, "source": "k8s_webhook", "fingerprint": fp}, col)
	assertStatus(t, w, http.StatusCreated)
	if got := scalar(t, `SELECT workspace_id::text FROM discovered_agents WHERE fingerprint = ?`, fp); got != a {
		t.Fatalf("sighting landed in workspace %q, want %s", got, a)
	}
	w = env.Do("POST", "/authsec/discovery/sightings", map[string]interface{}{
		"workspace_id": wsB.WorkspaceID.String(), "source": "k8s_webhook", "fingerprint": fp + "b"}, col)
	assertStatus(t, w, http.StatusNotFound)
	w = env.Do("POST", "/authsec/discovery/agent-registration", map[string]interface{}{
		"workspace_id": a, "kind": "k8s_webhook", "instance_id": "inst-" + n, "cluster_name": "c-" + n}, col)
	assertStatus(t, w, http.StatusCreated)

	// B cannot see or revoke A's credential.
	w = env.Do("GET", "/authsec/discovery/collector-tokens", nil, tokB)
	assertStatus(t, w, http.StatusOK)
	if strings.Contains(w.Body.String(), id) {
		t.Fatalf("workspace B lists A's collector credential")
	}
	assertStatus(t, env.Do("DELETE", "/authsec/discovery/collector-tokens/"+id, nil, tokB), http.StatusNotFound)

	// Revoked by A: refused from then on.
	assertStatus(t, env.Do("DELETE", "/authsec/discovery/collector-tokens/"+id, nil, tokA), http.StatusNoContent)
	assertStatus(t, env.Do("POST", "/authsec/discovery/sightings", map[string]interface{}{
		"workspace_id": a, "source": "k8s_webhook", "fingerprint": fp + "c"}, col), http.StatusUnauthorized)
}
