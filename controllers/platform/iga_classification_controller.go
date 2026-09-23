package platform

import (
	"errors"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igaread"
)

// errNotWorkspaceHuman is every refusal of the actor rule: the token is not a
// live human member of this workspace. It is 403 forbidden (§5.2). Anything
// else humanActor returns is a database error -- 500, never a refusal, so an
// outage is not reported to a person as "you may not".
var errNotWorkspaceHuman = errors.New("not a verified workspace member session")

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
//
// Every refusal wraps errNotWorkspaceHuman; any other error is the database's.
func humanActor(c *gin.Context, db *gorm.DB, ws uuid.UUID) (string, error) {
	membershipID := c.GetString("workspace_membership_id")
	if membershipID == "" {
		return "", fmt.Errorf("%w: this endpoint requires a workspace member session", errNotWorkspaceHuman)
	}
	mid, err := uuid.Parse(membershipID)
	if err != nil {
		return "", fmt.Errorf("%w: invalid workspace membership", errNotWorkspaceHuman)
	}
	userID := c.GetString("user_id")
	if userID == "" {
		return "", fmt.Errorf("%w: this endpoint requires a workspace member session", errNotWorkspaceHuman)
	}
	// A user id that is not a UUID names no user (user_id can fall back to sub,
	// middlewares/auth.go). Refused here, as the spec's requireWorkspaceHuman
	// does with uuid.Parse, rather than handed to PostgreSQL as a uuid literal
	// -- which would fail as a database error and answer 500 to a token that is
	// simply not a person.
	uid, err := uuid.Parse(userID)
	if err != nil {
		return "", fmt.Errorf("%w: invalid user id", errNotWorkspaceHuman)
	}

	// The membership must be THIS workspace's, THIS user's, and ACTIVE.
	var live int64
	if err := db.Raw(`
		SELECT count(*) FROM workspace_memberships
		 WHERE id = ? AND workspace_id = ? AND user_id = ? AND status = 'active'`,
		mid, ws, uid).Scan(&live).Error; err != nil {
		return "", fmt.Errorf("verify membership: %w", err)
	}
	if live == 0 {
		return "", fmt.Errorf("%w: no active workspace membership for this session", errNotWorkspaceHuman)
	}
	// The USER id, not the email: an email is a display string that can be
	// reassigned, and a decision record has to survive that.
	return uid.String(), nil
}

// The classification WRITE route (POST /estate/:id/classification) was removed:
// SPEC §6.1 replaces it with POST /workloads/:id/classification and its
// operation-id contract (§5.5, T6.6), served in iga_graph_read_classification.go.
// The actor rule above is KEPT -- it is the part of that handler the spec
// verified -- and is what the new route calls.

// HumanActorForTest exposes the actor rule to the integration suite.
//
// Exported deliberately and named for its purpose: the rule is the part of
// this endpoint most likely to be gotten wrong, and testing it through the
// full HTTP stack would prove the routing rather than the rule.
func HumanActorForTest(c *gin.Context, db *gorm.DB, ws uuid.UUID) (string, error) {
	return humanActor(c, db, ws)
}

// ClassifyCallerForTest exposes classifyCaller -- what can_classify is computed
// from -- for the same reason: the workload detail that renders it is another
// route, and this is the part that decides.
func (ctl *IGAGraphReadController) ClassifyCallerForTest(c *gin.Context, ws uuid.UUID) (igaread.ClassifyCaller, error) {
	return ctl.classifyCaller(c, ws)
}
