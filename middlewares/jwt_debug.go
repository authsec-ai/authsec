package middlewares

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// DebugJWTSecret creates a debug endpoint to help discover the correct JWT secret
// This should ONLY be used in development/debugging and never in production
func DebugJWTSecret() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only allow in non-production environments
		if os.Getenv("GIN_MODE") == "release" {
			c.JSON(403, gin.H{"error": "Debug endpoint disabled in production"})
			return
		}

		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(400, gin.H{"error": "No Authorization header provided"})
			return
		}

		// Remove "Bearer " prefix
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		// Split token into parts
		parts := strings.Split(tokenString, ".")
		if len(parts) != 3 {
			c.JSON(400, gin.H{"error": "Invalid JWT format"})
			return
		}

		// Decode header and payload
		header, _ := base64.RawURLEncoding.DecodeString(parts[0])
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		actualSig := parts[2]

		var headerMap, payloadMap map[string]interface{}
		json.Unmarshal(header, &headerMap)
		json.Unmarshal(payload, &payloadMap)

		// Try different secrets
		secretsToTry := map[string]string{
			"JWT_DEF_SECRET from env": os.Getenv("JWT_DEF_SECRET"),
			"JWT_SDK_SECRET from env": os.Getenv("JWT_SDK_SECRET"),
			"JWT_SECRET from env":     os.Getenv("JWT_SECRET"),
			"JWT_FALLBACK_SECRET":     os.Getenv("JWT_FALLBACK_SECRET"),
			"JWT_LEGACY_SECRET":       os.Getenv("JWT_LEGACY_SECRET"),
			"local-dev-secret":        "local-dev-secret-change-in-production",
		}

		results := make(map[string]interface{})
		message := parts[0] + "." + parts[1]

		for name, secret := range secretsToTry {
			if secret == "" {
				results[name] = "NOT SET"
				continue
			}

			// Compute expected signature
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write([]byte(message))
			expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

			if expectedSig == actualSig {
				results[name] = "✓ MATCH - This is the correct secret!"
			} else {
				results[name] = fmt.Sprintf("✗ No match (expected: %s..., got: %s...)",
					expectedSig[:20], actualSig[:20])
			}
		}

		c.JSON(200, gin.H{
			"header":    headerMap,
			"payload":   payloadMap,
			"signature": actualSig,
			"results":   results,
			"note":      "Add the matching secret to JWT_FALLBACK_SECRET environment variable",
		})
	}
}
