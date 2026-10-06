package middlewares

import (
	"log"
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// sessionRevoked reports whether a token's jti is on the revocation list.
// Tokens minted before jti was added carry none and expire normally.
func sessionRevoked(claims jwt.MapClaims) bool {
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return false
	}
	conn := config.GetDatabase()
	if conn == nil || conn.DB == nil {
		return false
	}
	var revoked bool
	if err := conn.DB.QueryRow(`SELECT EXISTS (SELECT 1 FROM revoked_session_tokens WHERE jti = $1)`, jti).Scan(&revoked); err != nil {
		log.Printf("auth: revocation check failed: %v", err)
		return true // fail closed
	}
	return revoked
}

// Logout revokes the presented session token (AS-031). Mount behind
// AuthMiddleware.
func Logout(c *gin.Context) {
	v, _ := c.Get("claims")
	claims, _ := v.(jwt.MapClaims)
	jti, _ := claims["jti"].(string)
	if jti == "" {
		// Legacy token without an id: nothing to list; it expires on its own.
		c.JSON(http.StatusOK, gin.H{"revoked": false, "reason": "token has no id; it expires at its exp"})
		return
	}
	exp := time.Now().Add(24 * time.Hour)
	if f, ok := claims["exp"].(float64); ok {
		exp = time.Unix(int64(f), 0)
	}
	ws, _ := c.Get("workspace_id")
	uid, _ := c.Get("user_id")
	_, err := config.GetDatabase().DB.Exec(`
		INSERT INTO revoked_session_tokens (jti, workspace_id, user_id, expires_at, reason)
		VALUES ($1, NULLIF($2, '')::uuid, NULLIF($3, '')::uuid, $4, 'logout')
		ON CONFLICT (jti) DO NOTHING`, jti, toString(ws), toString(uid), exp)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to end session"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"revoked": true})
}

func toString(v interface{}) string {
	s, _ := v.(string)
	return s
}
