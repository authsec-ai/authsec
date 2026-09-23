package platform

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

// classifyRequest is a person's decision about what a workload IS.
type classifyRequest struct {
	// Decision is classified_agent, or unclassified to undo.
	Decision string `json:"decision"`
	Purpose  string `json:"purpose"`
	Reason   string `json:"reason"`
	// ExpectedVersion is optimistic concurrency: the classification_version
	// the caller saw. A decision made against a stale view is REJECTED rather
	// than silently overwriting a newer one.
	ExpectedVersion int64 `json:"expected_version"`
}

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

// ClassifyWorkload records a person's decision about what a workload is.
//
// POST /api/iga/v1/estate/:workload_id/classification
func (ctl *IGAController) ClassifyWorkload(c *gin.Context) {
	ws, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, igaProblem("unauthenticated", err.Error(), http.StatusUnauthorized, c))
		return
	}
	actor, err := humanActor(c, ctl.db, ws)
	if err != nil {
		c.JSON(http.StatusForbidden, igaProblem("not_a_member", err.Error(), http.StatusForbidden, c))
		return
	}
	workloadID, err := uuid.Parse(c.Param("workload_id"))
	if err != nil {
		igaError(c, err)
		return
	}
	var req classifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		igaError(c, err)
		return
	}
	if req.Decision != models.ClassificationClassified &&
		req.Decision != models.ClassificationUnclassified {
		c.JSON(http.StatusUnprocessableEntity, igaProblem("bad_decision",
			"decision must be classified_agent or unclassified", http.StatusUnprocessableEntity, c))
		return
	}

	var newVersion int64
	err = ctl.db.Transaction(func(tx *gorm.DB) error {
		var w models.IGAWorkload
		if err := tx.First(&w, "workspace_id = ? AND id = ?", ws, workloadID).Error; err != nil {
			return err
		}
		// provider_native_agent is DERIVED from the provider -- a Bedrock agent
		// is one by construction. A person cannot edit it, in either
		// direction, or the graph would disagree with the account.
		if w.Classification == models.ClassificationProviderAgent {
			return errProviderNative
		}
		if req.ExpectedVersion != w.ClassificationVersion {
			return errStaleVersion
		}

		// The decision record and the state change commit TOGETHER. A
		// classification without its record is unexplainable; a record without
		// the change is a decision that did not take effect.
		if err := tx.Create(&models.IGAWorkloadClassification{
			WorkspaceID: ws, WorkloadID: workloadID,
			Decision: req.Decision, Purpose: req.Purpose,
			DecidedBy: actor, DecidedAt: time.Now(), Reason: req.Reason,
		}).Error; err != nil {
			return err
		}
		res := tx.Model(&models.IGAWorkload{}).
			Where("workspace_id = ? AND id = ? AND classification_version = ?",
				ws, workloadID, req.ExpectedVersion).
			Updates(map[string]any{
				"classification":         req.Decision,
				"classification_version": gorm.Expr("classification_version + 1"),
				"updated_at":             time.Now(),
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			// Someone else moved it between the read and the write.
			return errStaleVersion
		}
		newVersion = w.ClassificationVersion + 1
		return nil
	})

	switch {
	case errors.Is(err, errProviderNative):
		c.JSON(http.StatusUnprocessableEntity, igaProblem("provider_native",
			"a provider-native agent's classification is derived and cannot be edited",
			http.StatusUnprocessableEntity, c))
		return
	case errors.Is(err, errStaleVersion):
		c.JSON(http.StatusConflict, igaProblem("stale_version",
			"the workload changed since you read it; re-read and decide again",
			http.StatusConflict, c))
		return
	case errors.Is(err, gorm.ErrRecordNotFound):
		c.JSON(http.StatusNotFound, igaProblem("not_found",
			"no such workload in this workspace", http.StatusNotFound, c))
		return
	case err != nil:
		igaError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"workload_id":            workloadID,
			"classification":         req.Decision,
			"classification_version": newVersion,
			"decided_by":             actor,
		},
		"meta": gin.H{"as_of": time.Now().UTC()},
	})
}

var (
	errProviderNative = errors.New("provider-native classification is not editable")
	errStaleVersion   = errors.New("classification version is stale")
)

// HumanActorForTest exposes the actor rule to the integration suite.
//
// Exported deliberately and named for its purpose: the rule is the part of
// this endpoint most likely to be gotten wrong, and testing it through the
// full HTTP stack would prove the routing rather than the rule.
func HumanActorForTest(c *gin.Context, db *gorm.DB, ws uuid.UUID) (string, error) {
	return humanActor(c, db, ws)
}
