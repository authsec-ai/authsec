package shared

import (
	"errors"
	"net/http"

	"github.com/authsec-ai/authsec/database"
	"github.com/gin-gonic/gin"
)

// RespondUserAuditHistory answers 409 user_has_audit_history when err is a
// user delete refused because audit records still name the user
// (database.ClassifyUserDeleteError; review P0-1) and reports whether it
// answered. Any other error is left to the caller.
func RespondUserAuditHistory(c *gin.Context, err error) bool {
	// Another workspace refers to the user: 409 without naming it.
	if errors.Is(err, database.ErrUserInAnotherWorkspace) {
		c.JSON(http.StatusConflict, gin.H{
			"error": "Another workspace still refers to this user (a membership or its records), so the user cannot be deleted here. Remove the user from that workspace first.",
			"code":  database.UserInAnotherWorkspaceCode,
		})
		return true
	}
	ae, ok := database.AsUserAuditHistory(database.ClassifyUserDeleteError(err))
	if !ok {
		return false
	}
	c.JSON(http.StatusConflict, gin.H{
		"error":  ae.Message(),
		"code":   database.UserHasAuditHistoryCode,
		"detail": gin.H{"table": ae.Table, "constraint": ae.Constraint},
	})
	return true
}
