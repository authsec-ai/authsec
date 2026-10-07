//go:build integration

package flows

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/delegation"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
)

// AS-025: delegation tokens are stored encrypted. A row written in
// plaintext before the change is re-sealed on first read, and the
// revocation check keeps accepting the token afterwards.
func Test_DelegationToken_StoredEncrypted(t *testing.T) {
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

	admin := env.MustAsAdmin(ws.AdminUserID, ws.WorkspaceID, ws.AdminEmail)
	w := env.Do("GET", "/authsec/uflow/sdk/delegation-token?client_id="+agent.String(), nil, admin)
	assertStatus(t, w, http.StatusOK)
	if got := parseBody(t, w)["token"]; got != svid {
		t.Fatalf("delegation-token returned %v, want the plaintext JWT", got)
	}

	stored := scalar(t, `SELECT token FROM delegation_tokens WHERE workspace_id = ? AND client_id = ?`, ws.WorkspaceID, agent)
	if stored == svid || strings.Contains(stored, ".") {
		t.Fatalf("delegation token is still stored in plaintext after read")
	}
	if plain, legacy, err := delegation.OpenToken(stored); err != nil || legacy || plain != svid {
		t.Fatalf("stored value does not open to the token: legacy=%v err=%v", legacy, err)
	}

	// The revocation check reads the sealed row.
	if w := env.Do(http.MethodGet, "/authsec/exsvc/services", nil, svid); w.Code == http.StatusUnauthorized {
		t.Fatalf("active delegated token refused after sealing: %s", w.Body.String())
	}
	other := mintDelegatedSVID(t, ws, agent, key, time.Hour)
	assertStatus(t, env.Do(http.MethodGet, "/authsec/exsvc/services", nil, other), http.StatusUnauthorized)
}
