//go:build integration

package flows

import (
	"net/http"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
)

// AS-006: handlers that read workspace_id from the request let an admin of
// workspace A write into workspace B. Every authenticated request may now
// only name the workspace its token was issued for; any other answers 404.
func Test_TokenWorkspace_BodyQueryAndPathMustMatchToken(t *testing.T) {
	env := testsupport.Get(t)
	n := emailSafeNonce()
	wsA, err := SeedWorkspaceWithAdmin(config.DB, n+"a")
	if err != nil {
		t.Fatalf("seed A: %v", err)
	}
	wsB, err := SeedWorkspaceWithAdmin(config.DB, n+"b")
	if err != nil {
		t.Fatalf("seed B: %v", err)
	}
	tokA := env.MustAsAdmin(wsA.AdminUserID, wsA.WorkspaceID, wsA.AdminEmail)
	groupName := "planted-" + n

	// The exploit reproduced live in Phase 0: body names workspace B.
	w := env.Do("POST", "/authsec/uflow/admin/groups", map[string]interface{}{
		"workspace_id": wsB.WorkspaceID.String(),
		"groups":       []string{groupName},
	}, tokA)
	assertStatus(t, w, http.StatusNotFound)
	var planted int64
	config.DB.Raw(`SELECT COUNT(*) FROM groups WHERE name = ?`, groupName).Scan(&planted)
	if planted != 0 {
		t.Fatalf("a group was written although the request was rejected")
	}

	// tenant_id spelling, query parameter and path parameter are held to the same rule.
	assertStatus(t, env.Do("POST", "/authsec/uflow/admin/groups", map[string]interface{}{
		"tenant_id": wsB.WorkspaceID.String(), "groups": []string{groupName},
	}, tokA), http.StatusNotFound)
	assertStatus(t, env.Do("GET", "/authsec/uflow/admin/groups/"+wsB.WorkspaceID.String(), nil, tokA), http.StatusNotFound)
	assertStatus(t, env.Do("GET", "/authsec/uflow/admin/users/list?workspace_id="+wsB.WorkspaceID.String(), nil, tokA), http.StatusNotFound)

	// Naming the caller's own workspace still works.
	w = env.Do("POST", "/authsec/uflow/admin/groups", map[string]interface{}{
		"workspace_id": wsA.WorkspaceID.String(),
		"groups":       []string{groupName},
	}, tokA)
	if w.Code == http.StatusNotFound || w.Code == http.StatusUnauthorized {
		t.Fatalf("own-workspace request rejected: %d %s", w.Code, w.Body.String())
	}

	// Switching names another workspace by design; membership decides, not this check.
	w = env.Do("POST", "/authsec/workspaces/"+wsB.WorkspaceID.String()+"/switch", nil, tokA)
	if w.Code == http.StatusOK {
		t.Fatalf("switch into a workspace A is not a member of must not succeed")
	}
	if w.Code == http.StatusNotFound && w.Body.String() == `{"error":"not found"}` {
		t.Fatalf("switch must be decided by membership, not by the token-workspace check")
	}
}
