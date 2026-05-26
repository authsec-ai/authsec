package middlewares

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// SecurityHeadersMiddleware adds comprehensive security headers to all responses
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prevent clickjacking
		c.Header("X-Frame-Options", "DENY")

		// Prevent MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")

		// Enable XSS protection
		c.Header("X-XSS-Protection", "1; mode=block")

		// Referrer policy
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// Content Security Policy
		// Relaxed for OIDC callback page (needs inline script for OAuth redirect handling)
		path := c.Request.URL.Path
		var csp string
		if strings.HasPrefix(path, "/authsec/uflow/oidc/callback") {
			// Allow inline scripts for OAuth callback (postMessage to opener window)
			csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' https:; media-src 'none'; object-src 'none'; child-src 'self'; worker-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
		} else if strings.HasPrefix(path, "/authsec/hmgr/consent") {
			// Default CSP for the consent path. The handler overrides this just before
			// rendering to add the registered redirect_uri origins of the OAuth client —
			// browsers enforce form-action on the entire redirect chain, and the final
			// hop is the client redirect_uri, which is dynamic per client and unknown
			// to this middleware.
			csp = BuildConsentCSP(nil)
		} else {
			// Strict CSP for all other endpoints
			csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; media-src 'none'; object-src 'none'; child-src 'none'; worker-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
		}
		c.Header("Content-Security-Policy", csp)

		// HTTP Strict Transport Security (HTTPS or behind reverse proxy, or forced in production)
		if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" || os.Getenv("FORCE_HSTS") == "true" || os.Getenv("ENVIRONMENT") == "production" {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}

		// Permissions Policy (removed obsolete 'speaker' feature)
		c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), gyroscope=(), payment=()")

		c.Next()
	}
}

// RequestIDMiddleware generates and tracks request IDs for distributed tracing
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if request ID is already provided in header
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			// Generate new UUID for request ID
			requestID = uuid.New().String()
		}

		// Set request ID in context and response header
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)

		// Add request start time for duration tracking
		c.Set("request_start_time", time.Now())

		c.Next()

		// Get path and check if it's a health check or monitoring endpoint
		path := c.Request.URL.Path
		isHealthCheck := strings.HasPrefix(path, "/uflow/health") ||
			strings.HasPrefix(path, "/health") ||
			strings.Contains(path, "/api/v1/health") ||
			strings.Contains(path, "spire")

		// Log only error responses to reduce noise (skip health checks)

		statusCode := c.Writer.Status()
		if statusCode >= http.StatusBadRequest && !isHealthCheck {
			// Get error details if available
			errorMsg := ""
			if err, exists := c.Get("error"); exists {
				errorMsg = fmt.Sprintf("%v", err)
			}

			logFields := logrus.Fields{
				"url":         c.Request.URL.String(),
				"method":      c.Request.Method,
				"path":        path,
				"query":       c.Request.URL.RawQuery,
				"status_code": statusCode,
				"tenant_id":   c.GetHeader("X-Tenant-ID"),
			}

			// Add error message if available
			if errorMsg != "" {
				logFields["error"] = errorMsg
			}

			logrus.WithFields(logFields).Error("Request failed")
		}
	}
}

// BuildConsentCSP returns the Content-Security-Policy for the consent page.
// extraFormActionSources are appended verbatim to the form-action directive —
// callers pass the OAuth client's registered redirect_uri origins so the
// redirect chain after the consent POST (which terminates at the client's
// redirect_uri) is not blocked by the browser.
func BuildConsentCSP(extraFormActionSources []string) string {
	formAction := []string{"'self'"}
	if hydra := hydraPublicOrigin(); hydra != "" {
		formAction = append(formAction, hydra)
	}
	formAction = append(formAction, loopbackFormActionSources()...)
	for _, src := range extraFormActionSources {
		if src != "" {
			formAction = append(formAction, src)
		}
	}
	return "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; media-src 'none'; object-src 'none'; child-src 'none'; worker-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action " + strings.Join(formAction, " ") + ";"
}

// hydraPublicOrigin extracts the scheme+host from HYDRA_PUBLIC_URL so it can
// be injected into the form-action CSP directive on consent pages. The browser
// enforces form-action on the 302 redirect chain, so the Hydra origin must be
// explicitly listed or Safari/Chrome will refuse to complete the OAuth flow.
func hydraPublicOrigin() string {
	raw := os.Getenv("HYDRA_PUBLIC_URL")
	if raw == "" {
		return ""
	}
	// Trim any trailing path — we only need the origin (scheme+host).
	raw = strings.TrimRight(raw, "/")
	// Strip any path component after the host.
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(raw, prefix) {
			rest := raw[len(prefix):]
			if idx := strings.Index(rest, "/"); idx != -1 {
				return prefix + rest[:idx]
			}
			return raw // no path, raw is already scheme+host
		}
	}
	return raw
}

// loopbackFormActionSources returns the loopback origins used by OAuth desktop
// callbacks. CSP host sources without an explicit port only match the default port
// for the scheme, so localhost callbacks on ephemeral ports must use :*.
//
// IPv6 literals (e.g. "http://[::1]:*") are intentionally excluded — the CSP3
// host-source grammar does not permit port-wildcards with bracketed IPv6 hosts,
// and every browser silently rejects them with the warning
//
//	"form-action contains an invalid source: http://[::1]:*"
//
// Native OAuth clients that bind to [::1] should be reached via localhost (the
// dual-stack resolver) instead.
func loopbackFormActionSources() []string {
	return []string{
		"http://localhost:*",
		"https://localhost:*",
		"http://127.0.0.1:*",
		"https://127.0.0.1:*",
	}
}

// TimeoutMiddleware adds request timeout handling
func TimeoutMiddleware(timeout time.Duration) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Create a channel to signal timeout
		timeoutChan := make(chan struct{}, 1)

		// Start timeout timer
		timer := time.AfterFunc(timeout, func() {
			close(timeoutChan)
		})
		defer timer.Stop()

		// Create a done channel for the request
		doneChan := make(chan struct{})

		go func() {
			defer close(doneChan)
			c.Next()
		}()

		select {
		case <-doneChan:
			// Request completed normally
			return
		case <-timeoutChan:
			// Request timed out
			c.Abort()
			c.JSON(http.StatusRequestTimeout, gin.H{
				"error":      "Request timeout",
				"message":    "The request took too long to process",
				"request_id": c.GetString("request_id"),
			})

			logrus.WithFields(logrus.Fields{
				"request_id": c.GetString("request_id"),
				"method":     c.Request.Method,
				"path":       c.Request.URL.Path,
				"timeout":    timeout.String(),
			}).Warn("Request timeout")
		}
	})
}

// RecoveryMiddleware provides enhanced panic recovery with structured logging
func RecoveryMiddleware() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		if err, ok := recovered.(string); ok {
			logrus.WithFields(logrus.Fields{
				"request_id": c.GetString("request_id"),
				"error":      err,
				"method":     c.Request.Method,
				"path":       c.Request.URL.Path,
				"client_ip":  c.ClientIP(),
			}).Error("Panic recovered")
		}

		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error":      "Internal server error",
			"message":    "An unexpected error occurred",
			"request_id": c.GetString("request_id"),
		})
	})
}
