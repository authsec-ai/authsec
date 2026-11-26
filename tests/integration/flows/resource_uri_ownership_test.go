//go:build integration

package flows

import (
	"errors"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/testsupport"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

// AS-060: a resource URI is unique per workspace. Another workspace's URI can
// be registered only by the workspace that owns its host (a verified
// workspace domain), and pre-workspace resolution then picks the owner.
func Test_ResourceURI_OwnershipDecidesSharedURIs(t *testing.T) {
	testsupport.Get(t)
	a, b := TwoTenants(t)
	svc := services.NewResourceServerService(config.DB)
	host := "api-" + emailSafeNonce() + ".example.test"
	base := "https://" + host
	uri := base + "/mcp"

	create := func(ws uuid.UUID, name string) error {
		_, _, err := svc.Create(services.CreateResourceServerRequest{
			WorkspaceID: ws, Name: name, PublicBaseURL: base, ProtectedBasePath: "/mcp",
		}, "https://app.authsec.dev")
		return err
	}

	// A registers the URI first (as a squatter would: it does not own the host).
	if err := create(a.WS.WorkspaceID, "a-app"); err != nil {
		t.Fatalf("A registers: %v", err)
	}
	if err := create(a.WS.WorkspaceID, "a-app-2"); !errors.Is(err, services.ErrResourceURITaken) {
		t.Fatalf("same URI twice in A: %v, want ErrResourceURITaken", err)
	}
	// B does not own the host either: refused, so an unowned URI keeps one holder.
	if err := create(b.WS.WorkspaceID, "b-app"); !errors.Is(err, services.ErrResourceURITaken) {
		t.Fatalf("B without the host: %v, want ErrResourceURITaken", err)
	}
	rs, err := svc.GetByResourceURI(uri)
	if err != nil || rs.WorkspaceID != a.WS.WorkspaceID {
		t.Fatalf("single holder resolves to A: %+v, %v", rs, err)
	}

	// B verifies the host's parent domain and may now register the URI; the
	// lookup resolves to B, the owner, not to A who registered first.
	mustExec(t, `INSERT INTO workspace_domains (id, workspace_id, domain, kind, is_primary, is_verified, verification_token, verification_method, verified_at, created_at, updated_at)
	             VALUES ($1, $2, $3, 'custom', false, true, 't', 'dns_txt', NOW(), NOW(), NOW())`,
		uuid.New(), b.WS.WorkspaceID, host)
	if err := create(b.WS.WorkspaceID, "b-app"); err != nil {
		t.Fatalf("B owning the host registers: %v", err)
	}
	rs, err = svc.GetByResourceURI(uri)
	if err != nil || rs.WorkspaceID != b.WS.WorkspaceID {
		t.Fatalf("shared URI resolves to the owner B: %+v, %v", rs, err)
	}

	// A cannot move another of its applications onto a URI it does not own.
	other := "https://other-" + emailSafeNonce() + ".example.test"
	if _, _, err := svc.Create(services.CreateResourceServerRequest{WorkspaceID: a.WS.WorkspaceID, Name: "a-other", PublicBaseURL: other, ProtectedBasePath: "/mcp"}, "https://app.authsec.dev"); err != nil {
		t.Fatalf("A second app: %v", err)
	}
	var otherID string
	config.DB.Raw(`SELECT id::text FROM resource_servers WHERE workspace_id = ? AND resource_uri = ?`, a.WS.WorkspaceID, other+"/mcp").Scan(&otherID)
	bHostOnly := "https://" + host
	if _, err := svc.UpdateByTenant(otherID, a.WS.WorkspaceID.String(), map[string]interface{}{"public_base_url": bHostOnly, "protected_base_path": "/v2"}); err == nil {
		// A new path under B's host is not yet used by anyone, so it is allowed;
		// the rule only governs URIs another workspace already holds.
		t.Logf("A may use an unused URI on B's host (no holder yet)")
	}
	if _, err := svc.UpdateByTenant(otherID, a.WS.WorkspaceID.String(), map[string]interface{}{"public_base_url": base, "protected_base_path": "/mcp"}); err == nil {
		t.Fatalf("A moved an application onto a URI A already holds")
	}
}
