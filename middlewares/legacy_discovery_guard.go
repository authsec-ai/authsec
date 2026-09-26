package middlewares

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"

	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// LegacyDiscoveryIngressGuard bounds the unauthenticated /authsec/discovery
// ingress and optionally closes it.
//
// Order is deliberate: rate limit first (no body), then a size cap, then the
// workspace switch. When the switch is off the handler runs unchanged.
// When the global flag or the workspace setting is on, the handler is not
// called and no inventory row is written. The response is 410 Gone.
func LegacyDiscoveryIngressGuard(db *gorm.DB, limit int, window time.Duration, maxBody int64) gin.HandlerFunc {
	var repo *repositories.CollectorRepository
	if db != nil {
		repo = repositories.NewCollectorRepository(db)
	}
	return func(c *gin.Context) {
		key := "legacy-discovery:" + c.ClientIP() + ":" + c.FullPath()
		if !memStore.checkLimit(key, limit, window) {
			secs := int(window.Seconds())
			if secs < 1 {
				secs = 1
			}
			c.Header("Retry-After", itoa(secs))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate_limited"})
			return
		}
		if services.LegacyIngressGloballyDisabled() {
			c.AbortWithStatusJSON(http.StatusGone, gin.H{"error": "legacy_discovery_ingress_disabled"})
			return
		}
		if c.Request.Body == nil || c.Request.ContentLength == 0 && c.Request.Body == http.NoBody {
			c.Next()
			return
		}
		body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxBody+1))
		_ = c.Request.Body.Close()
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
			return
		}
		if int64(len(body)) > maxBody {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "payload_too_large"})
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(body))
		if repo == nil || len(body) == 0 {
			c.Next()
			return
		}
		var peek struct {
			WorkspaceID string `json:"workspace_id"`
		}
		if err := json.Unmarshal(body, &peek); err != nil || peek.WorkspaceID == "" {
			// The handler owns malformed-body errors. Do not turn them into a
			// disable decision.
			c.Next()
			return
		}
		ws, err := uuid.Parse(peek.WorkspaceID)
		if err != nil {
			c.Next()
			return
		}
		disabled, err := repo.LegacyIngressDisabled(ws)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "unavailable"})
			return
		}
		if disabled {
			c.AbortWithStatusJSON(http.StatusGone, gin.H{"error": "legacy_discovery_ingress_disabled"})
			return
		}
		c.Next()
	}
}
