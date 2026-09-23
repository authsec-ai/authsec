package platform

import (
	"errors"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// humanActor is the user id behind a request, or an error explaining why this
// token is not a person.
//
// THE ACTOR RULE, and why each obvious shortcut is wrong:
//
//   - Do NOT reject on client_id being present. GenerateWorkspaceToken sets
//     client_id on a real human session (defaulting it to the user id), so
//     "has client_id" does not mean "machine".
//   - Do NOT accept on user_id being present. End-user, admin, CIBA and device
//     tokens all set it, and none of them is a workspace member acting in the
//     console.
//   - Do NOT use ResolveUserID or IGAController.workspace(). Both fall back
//     through sub, then client_id, and finally the workspace id itself -- so
//     they always return SOMETHING, and a machine token would be recorded as
//     the decider.
//
// What actually distinguishes a human workspace session is
// workspace_membership_id: GenerateWorkspaceToken is its only setter
// (services/authmanager_token_service.go). Requiring the claim AND confirming
// the membership row is live closes the gap between "had a membership once"
// and "is a member now" -- an invited or suspended member must not decide.
func humanActor(c *gin.Context, db *gorm.DB, ws uuid.UUID) (string, error) {
	membershipID := c.GetString("workspace_membership_id")
	if membershipID == "" {
		return "", errors.New("this endpoint requires a workspace member session")
	}
	mid, err := uuid.Parse(membershipID)
	if err != nil {
		return "", errors.New("invalid workspace membership")
	}
	userID := c.GetString("user_id")
	if userID == "" {
		return "", errors.New("this endpoint requires a workspace member session")
	}

	// The membership must be THIS workspace's, THIS user's, and ACTIVE.
	var live int64
	if err := db.Raw(`
		SELECT count(*) FROM workspace_memberships
		 WHERE id = ? AND workspace_id = ? AND user_id = ? AND status = 'active'`,
		mid, ws, userID).Scan(&live).Error; err != nil {
		return "", fmt.Errorf("verify membership: %w", err)
	}
	if live == 0 {
		return "", errors.New("no active workspace membership for this session")
	}
	// The USER id, not the email: an email is a display string that can be
	// reassigned, and a decision record has to survive that.
	return userID, nil
}

// The classification WRITE route (POST /estate/:id/classification) was removed:
// SPEC §6.1 replaces it with POST /workloads/:id/classification and its
// operation-id contract (§5.5, T6.6). The actor rule below is KEPT -- it is
// the part of that handler the spec verified -- and is what the new route
// will call.

// HumanActorForTest exposes the actor rule to the integration suite.
//
// Exported deliberately and named for its purpose: the rule is the part of
// this endpoint most likely to be gotten wrong, and testing it through the
// full HTTP stack would prove the routing rather than the rule.
func HumanActorForTest(c *gin.Context, db *gorm.DB, ws uuid.UUID) (string, error) {
	return humanActor(c, db, ws)
}
