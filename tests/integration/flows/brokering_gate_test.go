//go:build integration

package flows

import (
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/google/uuid"
)

// AS-074: an issuance brokering deny that names a resource server applies to
// that resource server only; a client-wide deny still blocks everything.
func Test_BrokeringIssuanceGate_RespectsTargetRS(t *testing.T) {
	env := testsupport.Get(t)
	n := nonce(t)
	ws, err := SeedWorkspaceWithAdmin(config.DB, n)
	if err != nil {
		t.Fatal(err)
	}
	target, err := AddResourceServer(config.DB, ws, "https://target-"+n+".example.com", n+"t")
	if err != nil {
		t.Fatal(err)
	}
	other, err := AddResourceServer(config.DB, ws, "https://other-"+n+".example.com", n+"o")
	if err != nil {
		t.Fatal(err)
	}
	sa, err := AddServiceAccountWithScopes(config.DB, ws, target, n)
	if err != nil {
		t.Fatal(err)
	}
	adminToken := env.MustAsAdmin(ws.AdminUserID, ws.WorkspaceID, ws.AdminEmail)
	env.Fakes.Hydra.OnIntrospect(func(_ string) map[string]interface{} {
		return map[string]interface{}{
			"active": true, "sub": ws.AdminUserID.String(), "client_id": sa.ClientIDString,
			"ext": map[string]interface{}{"workspace_id": ws.WorkspaceID.String()},
		}
	})
	defer env.Fakes.Hydra.ResetIntrospect()

	exchange := func() int {
		w := env.DoBasicAuth(http.MethodPost, "/oauth/token", formBody(
			"grant_type", tokenExchangeGrantType,
			"requested_token_type", idJAGTokenType,
			"subject_token", adminToken,
			"subject_token_type", accessTokenType,
			"resource", target.ResourceURI,
		), sa.ClientIDString, sa.ClientSecret)
		return w.Code
	}
	deny := func(rsID *uuid.UUID) uuid.UUID {
		id := uuid.New()
		mustExec(t, `INSERT INTO a2a_brokering_policies (id, workspace_id, side, client_id, resource_server_id, effect)
			VALUES (?, ?, 'issuance', ?, ?, 'deny')`, id, ws.WorkspaceID, sa.ClientIDString, rsID)
		return id
	}

	// A deny for another resource server does not block this one.
	otherDeny := deny(&other.RSID)
	if code := exchange(); code != http.StatusOK {
		t.Fatalf("deny on another RS blocked issuance for the target: %d", code)
	}
	mustExec(t, `DELETE FROM a2a_brokering_policies WHERE id = ?`, otherDeny)

	// A deny for the target blocks it, and so does a client-wide deny.
	targetDeny := deny(&target.RSID)
	if code := exchange(); code != http.StatusForbidden {
		t.Fatalf("deny on the target RS did not block: %d", code)
	}
	mustExec(t, `DELETE FROM a2a_brokering_policies WHERE id = ?`, targetDeny)
	deny(nil)
	if code := exchange(); code != http.StatusForbidden {
		t.Fatalf("client-wide deny did not block: %d", code)
	}
}
