//go:build integration

package flows

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/database"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
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

// Admin users: listing, lookup by id, updates and creation stay in ctx's
// workspace and among holders of its admin role.
func Test_ScopedRepo_AdminUsers(t *testing.T) {
	a, b := TwoTenants(t)
	repo := database.NewAdminUserRepository(config.GetDatabase())
	ctxA := database.WithWorkspace(context.Background(), a.WS.WorkspaceID)

	list, err := repo.ListAdminUsersInWorkspace(ctxA, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	ids := map[uuid.UUID]bool{}
	for _, u := range list {
		ids[u.ID] = true
	}
	if !ids[a.WS.AdminUserID] || ids[b.WS.AdminUserID] || ids[a.EndUser.UserID] {
		t.Errorf("A's admin list: %v (want A's admin only, not B's admin or A's end user)", ids)
	}
	if l, err := repo.ListAdminUsersInWorkspace(ctxA, "no-such-provider"); err != nil || len(l) != 0 {
		t.Errorf("provider filter: %d users, %v", len(l), err)
	}

	if u, err := repo.GetAdminUserInWorkspace(ctxA, a.WS.AdminUserID); err != nil || u.ID != a.WS.AdminUserID {
		t.Errorf("get own admin: %v", err)
	}
	for _, id := range []uuid.UUID{b.WS.AdminUserID, a.EndUser.UserID} {
		if _, err := repo.GetAdminUserInWorkspace(ctxA, id); !errors.Is(err, tenancy.ErrNotFound) {
			t.Errorf("get %s in A: %v, want ErrNotFound", id, err)
		}
	}
	nameB := columnValue(t, "users", "name", "id = ?", b.WS.AdminUserID)
	if err := repo.UpdateAdminUserInWorkspace(ctxA, b.WS.AdminUserID, map[string]interface{}{"name": "taken"}); !errors.Is(err, tenancy.ErrNotFound) {
		t.Errorf("update B's admin from A: %v, want ErrNotFound", err)
	}
	if got := columnValue(t, "users", "name", "id = ?", b.WS.AdminUserID); got != nameB {
		t.Errorf("B's admin renamed to %q", got)
	}

	n := emailSafeNonce()
	ws := a.WS.WorkspaceID
	nu := &models.AdminUser{Email: "adm-" + n + "@example.com", Name: "Adm " + n, PasswordHash: "x", Provider: "local",
		Active: true, WorkspaceID: &ws, ClientID: &a.WS.ClientID, WorkspaceDomain: a.WS.WorkspaceDomain}
	other := b.WS.WorkspaceID
	if err := repo.CreateAdminUser(ctxA, &models.AdminUser{Email: "x-" + n + "@example.com", PasswordHash: "x", WorkspaceID: &other}); err == nil {
		t.Error("created a user of workspace B under A's context")
	}
	if err := repo.CreateAdminUser(ctxA, nu); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if _, err := repo.GetAdminUserInWorkspace(ctxA, nu.ID); err != nil {
		t.Errorf("new admin is not an admin of A: %v", err)
	}
}

// OIDC providers, states and identities: the workspace-owned rows are read
// and written only in the named workspace.
func Test_ScopedRepo_OIDC(t *testing.T) {
	a, b := TwoTenants(t)
	db := config.GetDatabase()
	n := emailSafeNonce()

	// Providers.
	prov := "oidc" + n[:8]
	mustExec(t, `INSERT INTO oidc_providers (provider_name, display_name, client_id, client_secret_vault_path,
		authorization_url, token_url, userinfo_url, workspace_id) VALUES (?, 'B IdP', 'cid-b', 'p', 'https://i/a', 'https://i/t', 'https://i/u', ?)`,
		prov, b.WS.WorkspaceID)
	providers := database.NewOIDCProviderRepository(db)
	if _, err := providers.GetProviderByWorkspaceAndName(a.WS.WorkspaceID, prov); err == nil {
		t.Error("A read B's OIDC provider")
	}
	if p, err := providers.GetProviderByWorkspaceAndName(b.WS.WorkspaceID, prov); err != nil || p.ClientID != "cid-b" {
		t.Errorf("B's own provider: %+v, %v", p, err)
	}
	if l, _ := providers.GetWorkspaceProviders(a.WS.WorkspaceID); len(l) != 0 {
		t.Errorf("A lists %d providers", len(l))
	}
	if l, _ := providers.GetWorkspaceProviders(b.WS.WorkspaceID); len(l) != 1 {
		t.Errorf("B lists %d providers, want 1", len(l))
	}
	if err := providers.UpdateProvider(a.WS.WorkspaceID, prov, &models.OIDCProviderUpdateInput{ClientID: "hijacked"}); err == nil {
		t.Error("A updated B's provider")
	}
	if err := providers.UpdateProvider(b.WS.WorkspaceID, prov, &models.OIDCProviderUpdateInput{ClientID: "cid-b2"}); err != nil {
		t.Errorf("B updates its provider: %v", err)
	}
	assertCount(t, 1, "oidc_providers", "provider_name = ? AND client_id = 'cid-b2'", prov)

	// States: a workspace's state is written in it; a platform one has none.
	states := database.NewOIDCStateRepository(db)
	wsA := a.WS.WorkspaceID
	st := &models.OIDCState{StateToken: "st-a-" + n, WorkspaceID: &wsA, WorkspaceDomain: "a", ProviderName: "google",
		Action: "login", ExpiresAt: time.Now().Add(time.Minute)}
	if err := states.CreateState(st); err != nil {
		t.Fatalf("create state: %v", err)
	}
	got, err := states.GetStateByToken(st.StateToken)
	if err != nil || got.WorkspaceID == nil || *got.WorkspaceID != wsA || got.ID != st.ID {
		t.Errorf("state read back: %+v, %v", got, err)
	}
	pst := &models.OIDCState{StateToken: "st-p-" + n, WorkspaceDomain: "p", ProviderName: "google",
		Action: "register", ExpiresAt: time.Now().Add(time.Minute)}
	if err := states.CreateState(pst); err != nil {
		t.Fatalf("create platform state: %v", err)
	}
	assertCount(t, 1, "oidc_states", "state_token = ? AND workspace_id IS NULL", pst.StateToken)
	if c, err := states.ConsumeState(pst.StateToken, "register"); err != nil || c.ProviderName != "google" {
		t.Errorf("consume: %+v, %v", c, err)
	}
	if _, err := states.ConsumeState(pst.StateToken, "register"); err == nil {
		t.Error("state consumed twice")
	}

	// Identities.
	ids := database.NewOIDCUserIdentityRepository(db)
	ident := &models.OIDCUserIdentity{WorkspaceID: a.WS.WorkspaceID, UserID: a.EndUser.UserID, ProviderName: "google",
		ProviderUserID: "sub-" + n, Email: a.EndUser.Email, ProfileData: "{}"}
	if err := ids.CreateIdentity(ident); err != nil {
		t.Fatalf("create identity: %v", err)
	}
	again := *ident
	again.ID = uuid.Nil
	if err := ids.CreateIdentity(&again); err != nil || again.ID != ident.ID {
		t.Errorf("re-link: id %s, want %s (%v)", again.ID, ident.ID, err)
	}
	if i, err := ids.GetIdentityByTenantAndProviderUser(b.WS.WorkspaceID, "google", "sub-"+n); err != nil || i != nil {
		t.Errorf("B found A's identity: %+v, %v", i, err)
	}
	if i, err := ids.GetIdentityByTenantAndProviderUser(a.WS.WorkspaceID, "google", "sub-"+n); err != nil || i == nil || i.ID != ident.ID {
		t.Errorf("A's identity: %+v, %v", i, err)
	}
	if l, _ := ids.GetIdentitiesByUserID(b.WS.WorkspaceID, a.EndUser.UserID); len(l) != 0 {
		t.Errorf("B lists %d of A's identities", len(l))
	}
	if err := ids.UpdateLastLogin(ident.ID); err != nil {
		t.Errorf("update last login: %v", err)
	}
	if err := ids.DeleteIdentity(b.WS.WorkspaceID, a.EndUser.UserID, "google"); err == nil {
		t.Error("B unlinked A's identity")
	}
	assertCount(t, 1, "oidc_user_identities", "id = ?", ident.ID)
	if err := ids.DeleteIdentity(a.WS.WorkspaceID, a.EndUser.UserID, "google"); err != nil {
		t.Errorf("unlink: %v", err)
	}
	assertCount(t, 0, "oidc_user_identities", "id = ?", ident.ID)
}

// DeleteTenant removes the ctx workspace's rows and registry row and nothing
// of another workspace.
func Test_ScopedRepo_DeleteTenant(t *testing.T) {
	a, b := TwoTenants(t)
	repo := database.NewWorkspaceRepository(config.GetDatabase())
	usersB := countWhere(t, "users", "workspace_id = ?", b.WS.WorkspaceID)
	bindingsB := countWhere(t, "role_bindings", "workspace_id = ?", b.WS.WorkspaceID)
	if usersB == 0 || bindingsB == 0 {
		t.Fatalf("B seeded with %d users, %d bindings", usersB, bindingsB)
	}

	if _, err := repo.DeleteTenant(context.Background()); err == nil {
		t.Fatal("DeleteTenant without a workspace in ctx succeeded")
	}
	counts, err := repo.DeleteTenant(database.WithWorkspace(context.Background(), a.WS.WorkspaceID))
	if err != nil {
		t.Fatalf("delete A: %v", err)
	}
	if counts["workspaces"] != 1 || counts["users"] == 0 {
		t.Errorf("deleted counts: %v", counts)
	}
	assertCount(t, 0, "users", "workspace_id = ?", a.WS.WorkspaceID)
	assertCount(t, 0, "workspaces", "id = ?", a.WS.WorkspaceID)
	assertCount(t, usersB, "users", "workspace_id = ?", b.WS.WorkspaceID)
	assertCount(t, bindingsB, "role_bindings", "workspace_id = ?", b.WS.WorkspaceID)
	assertCount(t, 1, "workspaces", "id = ?", b.WS.WorkspaceID)
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
