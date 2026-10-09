package integration

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/controllers/platform"
)

// P2-0 proof 1, the actor rule (§2.14.3).
//
// The rule is the part most likely to be gotten wrong, because every obvious
// shortcut is wrong in a way that still "works":
//
//   - rejecting on client_id refuses real humans, because a workspace session
//     token carries client_id too;
//   - accepting on user_id admits end-user, admin, CIBA and device tokens,
//     none of which is a workspace member acting in the console;
//   - ResolveUserID / IGAController.workspace() always return SOMETHING --
//     they fall back to sub, then client_id, then the workspace id -- so a
//     machine token would be recorded as the decider.
//
// What actually distinguishes a human workspace session is
// workspace_membership_id, whose only setter is GenerateWorkspaceToken, AND a
// membership row that is live right now.
func TestClassifyActorRule(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-classify-actor")

	// One membership per (workspace, user), so each status needs its own user.
	userID := uuid.New()
	seedUser(t, db, ws, userID, "human@test.local")
	activeMembership := seedMembership(t, db, ws, userID, "active")

	invitedUser := uuid.New()
	seedUser(t, db, ws, invitedUser, "invited@test.local")
	invitedMembership := seedMembership(t, db, ws, invitedUser, "invited")

	suspendedUser := uuid.New()
	seedUser(t, db, ws, suspendedUser, "suspended@test.local")
	suspendedMembership := seedMembership(t, db, ws, suspendedUser, "suspended")

	otherWS := newWorkspace(t, db, "ws-classify-other")
	otherUser := uuid.New()
	seedUser(t, db, otherWS, otherUser, "other@test.local")
	foreignMembership := seedMembership(t, db, otherWS, otherUser, "active")

	for _, tc := range []struct {
		name         string
		membershipID string
		userID       string
		wantActor    bool
		why          string
	}{
		{
			name: "human workspace session", membershipID: activeMembership.String(),
			userID: userID.String(), wantActor: true,
			why: "a real session carries BOTH user_id and client_id; it must not be refused for having client_id",
		},
		{
			name: "machine-only token", membershipID: "", userID: "",
			wantActor: false, why: "no workspace_membership_id: only GenerateWorkspaceToken sets it",
		},
		{
			name: "end-user token (user_id but no membership)", membershipID: "",
			userID: userID.String(), wantActor: false,
			why: "user_id alone is set by end-user, admin, CIBA and device tokens",
		},
		{
			name: "invited member", membershipID: invitedMembership.String(),
			userID: invitedUser.String(), wantActor: false,
			why: "had a membership, is not a member now",
		},
		{
			name: "suspended member", membershipID: suspendedMembership.String(),
			userID: suspendedUser.String(), wantActor: false,
			why: "suspended must not decide",
		},
		{
			name: "membership from another workspace", membershipID: foreignMembership.String(),
			userID: otherUser.String(), wantActor: false,
			why: "the membership must belong to THIS workspace",
		},
		{
			name: "membership id with a mismatched user", membershipID: activeMembership.String(),
			userID: uuid.New().String(), wantActor: false,
			why: "the membership must belong to the user the token names",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(nil)
			if tc.membershipID != "" {
				c.Set("workspace_membership_id", tc.membershipID)
			}
			if tc.userID != "" {
				c.Set("user_id", tc.userID)
			}
			// Every case sets client_id, because a real human session has one.
			// A rule that rejects on its presence fails the first case.
			c.Set("client_id", "console-client")

			actor, err := platform.HumanActorForTest(c, db, ws)
			if tc.wantActor {
				if err != nil {
					t.Fatalf("want an actor (%s), got error: %v", tc.why, err)
				}
				if actor != tc.userID {
					t.Errorf("must record the USER id, got %q want %q", actor, tc.userID)
				}
			} else {
				if err == nil {
					t.Fatalf("want refusal (%s), got actor %q", tc.why, actor)
				}
			}
		})
	}
}

func seedUser(t *testing.T, db *gorm.DB, ws, id uuid.UUID, email string) {
	t.Helper()
	if err := db.Exec(
		`INSERT INTO users (id, email, workspace_id) VALUES (?, ?, ?)`, id, email, ws).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

func seedMembership(t *testing.T, db *gorm.DB, ws, user uuid.UUID, status string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if err := db.Exec(`
		INSERT INTO workspace_memberships (id, workspace_id, user_id, role_id, status)
		VALUES (?, ?, ?, ?, ?)`, id, ws, user, seedRole(t, db, ws), status).Error; err != nil {
		t.Fatalf("seed membership(%s): %v", status, err)
	}
	return id
}

// seedRole returns a role id to hang memberships on. The actor rule turns on
// membership STATUS, not on the role, so any role serves.
func seedRole(t *testing.T, db *gorm.DB, ws uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	// The role must belong to the SAME workspace: workspace_memberships FKs
	// (role_id, workspace_id) together.
	if err := db.Exec(`INSERT INTO roles (id, name, workspace_id) VALUES (?, ?, ?)`,
		id, "member-"+id.String()[:8], ws).Error; err != nil {
		t.Fatalf("seed role: %v", err)
	}
	return id
}
