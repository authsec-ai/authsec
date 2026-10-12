package handlers

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/lockout"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// guardSecondFactor runs one second-factor check under the account lockout
// and replay rules (AS-004): see lockout.GuardCode. It answers the request
// itself when the account is locked (429 + Retry-After) or the check could
// not run (500); handled reports that a response was written. ok is the
// verification result otherwise.
func guardSecondFactor(c *gin.Context, workspaceID string, userID uuid.UUID, kind lockout.Kind, match func() (int64, bool)) (ok, handled bool) {
	ws, _ := uuid.Parse(workspaceID)
	var db *sql.DB
	if conn := config.GetDatabase(); conn != nil {
		db = conn.DB
	}
	ok, err := lockout.GuardCode(c.Request.Context(), db, ws, userID, kind, match)
	if errors.Is(err, lockout.ErrLocked) {
		c.Header("Retry-After", lockout.RetryAfterSeconds(lockoutUntil(c, db, ws, kind, userID)))
		c.JSON(http.StatusTooManyRequests, ErrorResponse{Error: lockout.Message})
		return false, true
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: "failed to verify code"})
		return false, true
	}
	return ok, false
}

func lockoutUntil(c *gin.Context, db *sql.DB, ws uuid.UUID, kind lockout.Kind, userID uuid.UUID) (until time.Time) {
	_, until, _ = lockout.Locked(c.Request.Context(), db, ws, kind, userID.String())
	return until
}
