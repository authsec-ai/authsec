//go:build integration

package flows

import (
	"crypto/rsa"
	"net/http"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// mintDelegatedSVID signs a JWT-SVID shaped like the ones
// /uflow/admin/agents/:id/delegate-token issues.
func mintDelegatedSVID(t *testing.T, ws *WorkspaceScenario, agent uuid.UUID, key *rsa.PrivateKey, ttl time.Duration) string {
	t.Helper()
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":          "spiffe://" + ws.WorkspaceID.String(),
		"sub":          "spiffe://example.org/tenants/" + ws.WorkspaceID.String() + "/agents/mcp-agent/" + agent.String(),
		"aud":          []string{"authsec-api"},
		"iat":          now.Unix(),
		"nbf":          now.Unix(),
		"exp":          now.Add(ttl).Unix(),
		"jti":          uuid.NewString(),
		"user_id":      ws.AdminUserID.String(),
		"workspace_id": ws.WorkspaceID.String(),
		"agent_type":   "mcp-agent",
		"client_id":    agent.String(),
		"permissions":  []string{"external-service:read"},
	})
	tok.Header["kid"] = "spiffe-" + ws.WorkspaceID.String()
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign delegated svid: %v", err)
	}
	return s
}

// AS-069: a delegated JWT-SVID stops working when it is revoked or replaced,
// and one issued for longer than 24h is refused.
func Test_DelegatedSVID_RevocationEnforced(t *testing.T) {
	env := testsupport.Get(t)
	ws := seedWorkspace(t, emailSafeNonce())
	key, err := env.Fakes.JWKS.RegisterWorkspace(ws.WorkspaceID.String())
	if err != nil {
		t.Fatalf("register jwks: %v", err)
	}
	agent := seedAIAgent(t, ws, emailSafeNonce())
	svid := mintDelegatedSVID(t, ws, agent, key, time.Hour)
	mustExec(t, `INSERT INTO delegation_tokens (id, client_id, workspace_id, token, spiffe_id,
			expires_at, delegated_by, ttl_seconds)
		VALUES (?, ?, ?, ?, 'spiffe://example.org/agent', ?, ?, 3600)`,
		uuid.New(), agent, ws.WorkspaceID, svid, time.Now().Add(time.Hour), ws.AdminUserID)

	const path = "/authsec/exsvc/services"
	if w := env.Do(http.MethodGet, path, nil, svid); w.Code == http.StatusUnauthorized {
		t.Fatalf("active delegated token refused: %s", w.Body.String())
	}

	// A token for the same agent that is not the stored one (superseded or
	// never recorded) is refused.
	other := mintDelegatedSVID(t, ws, agent, key, time.Hour)
	assertStatus(t, env.Do(http.MethodGet, path, nil, other), http.StatusUnauthorized)

	// Revoking it through the admin API takes effect on the next request.
	admin := env.MustAsAdmin(ws.AdminUserID, ws.WorkspaceID, ws.AdminEmail)
	assertStatus(t, env.Do(http.MethodPost, "/authsec/uflow/admin/agents/"+agent.String()+"/revoke-token", nil, admin), http.StatusOK)
	assertStatus(t, env.Do(http.MethodGet, path, nil, svid), http.StatusUnauthorized)

	// A delegated token living longer than 24h is refused even if recorded.
	long := mintDelegatedSVID(t, ws, agent, key, 48*time.Hour)
	mustExec(t, `UPDATE delegation_tokens SET token = ?, status = 'active', expires_at = ? WHERE client_id = ?`,
		long, time.Now().Add(48*time.Hour), agent)
	assertStatus(t, env.Do(http.MethodGet, path, nil, long), http.StatusUnauthorized)
}
