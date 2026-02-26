package middlewares

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// TokenBlacklistChecker interface to avoid circular dependency
type TokenBlacklistChecker interface {
	IsTokenBlacklisted(tokenString string) (bool, error)
}

// TokenBlacklistMiddleware checks if the access token has been blacklisted
func TokenBlacklistMiddleware(checker TokenBlacklistChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		if checker == nil {
			// No checker provided, skip blacklist check
			c.Next()
			return
		}
		
		// Get token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			// No token, skip blacklist check (will fail in auth middleware)
			c.Next()
			return
		}
		
		// Extract token
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			// Invalid format, skip blacklist check (will fail in auth middleware)
			c.Next()
			return
		}
		
		tokenString := parts[1]
		
		// Check if token is blacklisted
		blacklisted, err := checker.IsTokenBlacklisted(tokenString)
		if err != nil {
			// Log error but don't block request
			// Token validation will happen in auth middleware
			c.Next()
			return
		}
		
		if blacklisted {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Token has been revoked",
			})
			c.Abort()
			return
		}
		
		c.Next()
	}
}
