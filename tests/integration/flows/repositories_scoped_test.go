//go:build integration

package flows

import (
	"context"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/database"
	"github.com/authsec-ai/authsec/models"
)

// Repository-level checks for the data-access repositories moved onto the
// scoped layer (internal/tenancy, row-level security).

// CreateOIDCEndUser creates the identity in ctx's workspace only, and returns
// the workspace's existing identity for the same email instead of a new one.
func Test_ScopedRepo_CreateOIDCEndUser(t *testing.T) {
	a, b := TwoTenants(t)
	repo := database.NewUserRepository(config.GetDatabase())
	n := emailSafeNonce()
	info := &models.OIDCUserInfo{Sub: "sub-" + n, Email: "Fed-" + n + "@example.com", Name: "Fed " + n}
	ctxA := database.WithWorkspace(context.Background(), a.WS.WorkspaceID)
	ctxB := database.WithWorkspace(context.Background(), b.WS.WorkspaceID)

	u1, err := repo.CreateOIDCEndUser(ctxA, "google", info)
	if err != nil {
		t.Fatalf("create in A: %v", err)
	}
	if u1.WorkspaceID != a.WS.WorkspaceID {
		t.Fatalf("created in workspace %s, want A", u1.WorkspaceID)
	}
	u2, err := repo.CreateOIDCEndUser(ctxA, "google", info)
	if err != nil {
		t.Fatalf("second create in A: %v", err)
	}
	if u2.ID != u1.ID {
		t.Errorf("second create returned %s, want the existing %s", u2.ID, u1.ID)
	}
	uB, err := repo.CreateOIDCEndUser(ctxB, "google", info)
	if err != nil {
		t.Fatalf("create in B: %v", err)
	}
	if uB.ID == u1.ID || uB.WorkspaceID != b.WS.WorkspaceID {
		t.Errorf("B's identity is %s in %s, want a new one in B", uB.ID, uB.WorkspaceID)
	}
	assertCount(t, 1, "users", "workspace_id = ? AND LOWER(email) = LOWER(?)", a.WS.WorkspaceID, info.Email)

	// An existing user of A with that email is returned, not duplicated.
	existing := &models.OIDCUserInfo{Sub: "sub2-" + n, Email: a.EndUser.Email}
	u3, err := repo.CreateOIDCEndUser(ctxA, "google", existing)
	if err != nil {
		t.Fatalf("create for existing email: %v", err)
	}
	if u3.ID != a.EndUser.UserID {
		t.Errorf("existing email returned %s, want A's end user %s", u3.ID, a.EndUser.UserID)
	}

	if _, err := repo.CreateOIDCEndUser(context.Background(), "google", info); err == nil {
		t.Error("create without a workspace in ctx succeeded")
	}
}

// Workspace domains: every by-id statement runs in the caller's workspace, so
// another workspace's domain id reads, verifies, promotes and deletes nothing.
func Test_ScopedRepo_WorkspaceDomains(t *testing.T) {
	a, b := TwoTenants(t)
	repo := database.NewWorkspaceDomainsRepository(config.GetDatabase())
	ctxA := database.WithWorkspace(context.Background(), a.WS.WorkspaceID)
	ctxB := database.WithWorkspace(context.Background(), b.WS.WorkspaceID)
	n := emailSafeNonce()
	host := "login-" + n + ".example.com"

	d, err := repo.CreateDomain(a.WS.WorkspaceID, "Login-"+n+".Example.com.", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if d.Domain != host || d.WorkspaceID != a.WS.WorkspaceID {
		t.Fatalf("created %q in %s", d.Domain, d.WorkspaceID)
	}
	if _, err := repo.Create(ctxB, host, nil); err == nil {
		t.Error("workspace B claimed A's domain")
	}

	if _, err := repo.Get(ctxB, d.ID); err == nil {
		t.Error("B read A's domain by id")
	}
	if err := repo.MarkVerified(ctxB, d.ID, nil); err == nil {
		t.Error("B verified A's domain")
	}
	if err := repo.SetPrimary(ctxB, d.ID, nil); err == nil {
		t.Error("B made A's domain its primary")
	}
	if err := repo.RecordVerification(ctxB, d.ID, true, nil); err == nil {
		t.Error("B recorded a verification on A's domain")
	}
	if err := repo.Delete(ctxB, d.ID); err == nil {
		t.Error("B deleted A's domain")
	}
	assertCount(t, 1, "workspace_domains", "id = ? AND is_verified = false AND is_primary = false", d.ID)

	// The workspace's own calls, through the older entry points too.
	if err := repo.VerifyDomain(d.ID, nil); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := repo.SetPrimaryDomain(a.WS.WorkspaceID, d.ID, nil); err != nil {
		t.Fatalf("set primary: %v", err)
	}
	got, err := repo.GetDomainByID(d.ID)
	if err != nil || !got.IsVerified || !got.IsPrimary {
		t.Fatalf("after verify + primary: %+v, %v", got, err)
	}
	if p, err := repo.GetPrimaryDomainByWorkspaceID(a.WS.WorkspaceID); err != nil || p.ID != d.ID {
		t.Errorf("primary of A: %+v, %v", p, err)
	}
	if _, err := repo.Primary(ctxB); err == nil {
		t.Error("B sees a primary domain")
	}
	if owned, _ := repo.IsDomainOwnedByTenant(a.WS.WorkspaceID, host); !owned {
		t.Error("A does not own its verified domain")
	}
	if owned, _ := repo.OwnsVerifiedDomain(ctxB, host); owned {
		t.Error("B owns A's domain")
	}
	if list, _ := repo.ListWorkspaceDomains(b.WS.WorkspaceID); len(list) != 0 {
		t.Errorf("B lists %d domains", len(list))
	}
	if vd, _ := repo.VerifiedDomains(ctxA); len(vd) != 1 || vd[0] != host {
		t.Errorf("A's verified domains: %v", vd)
	}
	if hd, err := repo.GetDomainByHostname(host); err != nil || hd.WorkspaceID != a.WS.WorkspaceID {
		t.Errorf("host resolution: %+v, %v", hd, err)
	}
	if err := repo.DeleteDomain(d.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	assertCount(t, 0, "workspace_domains", "id = ?", d.ID)
	if _, err := repo.GetDomainByID(d.ID); err == nil {
		t.Error("deleted domain still found")
	}
}
