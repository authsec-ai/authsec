package middlewares

import (
	"net/http"
	"strings"

	"github.com/didip/tollbooth/v7"
	"github.com/didip/tollbooth/v7/limiter"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// RateLimitMiddleware creates rate limiting middleware with different limits for different endpoints
func RateLimitMiddleware() gin.HandlerFunc {
	// General API rate limiter (100 requests per minute per IP)
	generalLimiter := tollbooth.NewLimiter(1.67, nil) // 100 requests per minute = 1.67 per second
	generalLimiter.SetIPLookups([]string{"X-Real-IP", "X-Forwarded-For", "RemoteAddr"})
	generalLimiter.SetMethods([]string{"GET", "POST", "PUT", "DELETE", "PATCH"})
	generalLimiter.SetMessage(`{"error": "Rate limit exceeded", "message": "Too many requests. Please try again later."}`)

	// Authentication endpoints rate limiter (100 requests per minute per IP)
	authLimiter := tollbooth.NewLimiter(1.67, nil) // 100 requests per minute = 1.67 per second
	authLimiter.SetIPLookups([]string{"X-Real-IP", "X-Forwarded-For", "RemoteAddr"})
	authLimiter.SetMethods([]string{"POST"})
	authLimiter.SetMessage(`{"error": "Authentication rate limit exceeded", "message": "Too many authentication attempts. Please wait before trying again."}`)

	// Admin endpoints rate limiter (100 requests per minute per IP)
	adminLimiter := tollbooth.NewLimiter(1.67, nil) // 100 requests per minute = 1.67 per second
	adminLimiter.SetIPLookups([]string{"X-Real-IP", "X-Forwarded-For", "RemoteAddr"})
	adminLimiter.SetMethods([]string{"GET", "POST", "PUT", "DELETE", "PATCH"})
	adminLimiter.SetMessage(`{"error": "Admin rate limit exceeded", "message": "Too many admin requests. Please try again later."}`)

	return func(c *gin.Context) {
		requestID := c.GetString("request_id")
		clientIP := c.ClientIP()
		path := c.Request.URL.Path

		// Determine which limiter to use based on the path
		var selectedLimiter *limiter.Limiter
		var limitType string

		if strings.HasPrefix(path, "/api/v1/auth/") {
			selectedLimiter = authLimiter
			limitType = "auth"
		} else if strings.HasPrefix(path, "/api/v1/admin/") {
			selectedLimiter = adminLimiter
			limitType = "admin"
		} else {
			selectedLimiter = generalLimiter
			limitType = "general"
		}

		// Check rate limit
		httpError := tollbooth.LimitByRequest(selectedLimiter, c.Writer, c.Request)
		if httpError != nil {
			// Rate limit exceeded
			logrus.WithFields(logrus.Fields{
				"request_id": requestID,
				"client_ip":  clientIP,
				"path":       path,
				"method":     c.Request.Method,
				"limit_type": limitType,
				"user_agent": c.GetHeader("User-Agent"),
			}).Warn("Rate limit exceeded")

			// The tollbooth library already sent the response, so we just need to abort
			//c.Abort()
			return
		}

		// Log successful requests (with rate limit info)
		// Note: tollbooth v7 doesn't expose remaining/reset info directly
		logrus.WithFields(logrus.Fields{
			"request_id": requestID,
			"client_ip":  clientIP,
			"path":       path,
			"method":     c.Request.Method,
			"limit_type": limitType,
		}).Debug("Rate limit check passed")

		c.Next()
	}
}

// TenantRateLimitMiddleware provides per-workspace rate limiting.
// Function name preserved to avoid churning route registrations.
func TenantRateLimitMiddleware() gin.HandlerFunc {
	// Workspace-specific rate limiter (1000 requests per minute per workspace per IP)
	workspaceLimiter := tollbooth.NewLimiter(16.67, nil) // 1000 requests per minute = 16.67 per second
	workspaceLimiter.SetIPLookups([]string{"X-Real-IP", "X-Forwarded-For", "RemoteAddr"})
	workspaceLimiter.SetMethods([]string{"GET", "POST", "PUT", "DELETE", "PATCH"})
	workspaceLimiter.SetMessage(`{"error": "Workspace rate limit exceeded", "message": "Too many requests for this workspace. Please try again later."}`)

	return func(c *gin.Context) {
		workspaceID := c.GetHeader("X-Workspace-ID")
		if workspaceID == "" {
			// No workspace specified, skip workspace-specific rate limiting
			c.Next()
			return
		}

		requestID := c.GetString("request_id")
		clientIP := c.ClientIP()
		path := c.Request.URL.Path

		// Create a composite key for workspace + IP rate limiting
		workspaceIPKey := workspaceID + ":" + clientIP

		// Check workspace-specific rate limit
		httpError := tollbooth.LimitByKeys(workspaceLimiter, []string{workspaceIPKey})
		if httpError != nil {
			// Rate limit exceeded for this workspace
			logrus.WithFields(logrus.Fields{
				"request_id":   requestID,
				"client_ip":    clientIP,
				"workspace_id": workspaceID,
				"path":         path,
				"method":       c.Request.Method,
				"user_agent":   c.GetHeader("User-Agent"),
			}).Warn("Workspace rate limit exceeded")

			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":        "Workspace rate limit exceeded",
				"message":      "Too many requests for this workspace. Please try again later.",
				"request_id":   requestID,
				"workspace_id": workspaceID,
			})
			return
		}

		// Log workspace rate limit info
		// Note: tollbooth v7 doesn't expose remaining/reset info directly
		logrus.WithFields(logrus.Fields{
			"request_id":   requestID,
			"client_ip":    clientIP,
			"workspace_id": workspaceID,
			"path":         path,
			"method":       c.Request.Method,
		}).Debug("Workspace rate limit check passed")

		c.Next()
	}
}
