package shared

import (
	"net/http"

	"github.com/authsec-ai/authsec/database"
	"github.com/gin-gonic/gin"
)

// RespondUserAuditHistory answers 409 user_has_audit_history when err is a
// user delete refused because audit records still name the user
// (database.ClassifyUserDeleteError; review P0-1) and reports whether it
// answered. Any other error is left to the caller.
func RespondUserAuditHistory(c *gin.Context, err error) bool {
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
