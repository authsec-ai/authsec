package lockout

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/authsec-ai/authsec/config"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func sqlDB() *sql.DB {
	if conn := config.GetDatabase(); conn != nil {
		return conn.DB
	}
	return nil
}

// Refuse answers 429 (with Retry-After) when the account is locked and
// reports whether it answered. Call it before checking the credential.
func Refuse(c *gin.Context, ws uuid.UUID, kind Kind, subject string) bool {
	locked, until, err := Locked(c.Request.Context(), sqlDB(), ws, kind, subject)
	if err != nil {
		log.Printf("lockout: check failed: %v", err)
	}
	if !locked {
		return false
	}
	c.Header("Retry-After", RetryAfterSeconds(until))
	c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": Message})
	return true
}

// RecordFailure counts a failed attempt. When that locks the account it
// answers 429 and returns true; otherwise the caller answers as usual.
func RecordFailure(c *gin.Context, ws uuid.UUID, kind Kind, subject string) bool {
	locked, until, err := Fail(c.Request.Context(), sqlDB(), ws, kind, subject)
	if err != nil {
		log.Printf("lockout: failed to record a failed attempt: %v", err)
		return false
	}
	if !locked {
		return false
	}
	c.Header("Retry-After", RetryAfterSeconds(until))
	c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": Message})
	return true
}

// RecordSuccess clears the account's counter after a successful attempt.
func RecordSuccess(c *gin.Context, ws uuid.UUID, kind Kind, subject string) {
	if err := Succeed(c.Request.Context(), sqlDB(), ws, kind, subject); err != nil {
		log.Printf("lockout: failed to reset counter: %v", err)
	}
}
