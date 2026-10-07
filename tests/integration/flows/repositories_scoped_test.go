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
