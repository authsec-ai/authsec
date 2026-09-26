package middlewares

import (
	"net/http"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const (
	// CtxCollectorPrincipal is the authenticated collector, resolved from the
	// credential and never from the body.
	CtxCollectorPrincipal = "collector_principal"
	// CtxEnrollment is the enrollment row resolved from a one-time token.
	CtxEnrollment = "collector_enrollment"
)

// RequireV2Ingest rejects every v2 route with 404 when IGA_V2_INGEST is off.
// It does not read the body.
func RequireV2Ingest() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !services.V2IngestEnabled() {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "not_found"})
			return
		}
		c.Next()
	}
}

// LimitBody caps the request size before the handler parses it.
func LimitBody(n int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > n {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "payload_too_large"})
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, n)
		c.Next()
	}
}

// CollectorRateLimit limits by client IP before the body is read.
func CollectorRateLimit(limit int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := "collector:" + c.ClientIP() + ":" + c.FullPath()
		if !memStore.checkLimit(key, limit, window) {
			secs := int(window.Seconds())
			if secs < 1 {
				secs = 1
			}
			c.Header("Retry-After", itoa(secs))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate_limited"})
			return
		}
		c.Next()
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func bearerToken(c *gin.Context) string {
	h := strings.TrimSpace(c.GetHeader("Authorization"))
	if h == "" {
		return ""
	}
	const p = "Bearer "
	if len(h) < len(p) || !strings.EqualFold(h[:len(p)], p) {
		return ""
	}
	return strings.TrimSpace(h[len(p):])
}

func unauthorized(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
}

// AuthenticateEnrollment resolves a one-time enrollment token from the
// Authorization header. It does not read the body. A v1 actuation token or a
// v2 collector credential is rejected.
func AuthenticateEnrollment(db *gorm.DB, now func() time.Time) gin.HandlerFunc {
	repo := repositories.NewCollectorRepository(db)
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return func(c *gin.Context) {
		token := bearerToken(c)
		if token == "" || !strings.HasPrefix(token, services.PrefixEnrollment) {
			unauthorized(c)
			return
		}
		row, err := repo.FindEnrollmentByTokenHash(services.HashCollectorSecret(token))
		if err != nil {
			unauthorized(c)
			return
		}
		if err := services.EnrollmentAcceptable(row, now()); err != nil {
			unauthorized(c)
			return
		}
		c.Set(CtxEnrollment, row)
		c.Next()
	}
}

// AuthenticateCollector resolves a v2 credential. Actuation tokens and
// enrollment tokens are rejected before the database is consulted.
func AuthenticateCollector(db *gorm.DB, now func() time.Time) gin.HandlerFunc {
	repo := repositories.NewCollectorRepository(db)
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return func(c *gin.Context) {
		token := bearerToken(c)
		if token == "" || !strings.HasPrefix(token, services.PrefixCollector) {
			unauthorized(c)
			return
		}
		auth, err := repo.AuthenticateCredential(services.HashCollectorSecret(token), now())
		if err != nil {
			unauthorized(c)
			return
		}
		c.Set(CtxCollectorPrincipal, &models.CollectorPrincipal{
			WorkspaceID:       auth.Instance.WorkspaceID,
			CollectorID:       auth.Instance.ID,
			EstateScopeID:     auth.Instance.EstateScopeID,
			DiscoverySourceID: auth.Instance.DiscoverySourceID,
			IntegrationID:     auth.Instance.IntegrationID,
			Kind:              auth.Instance.Kind,
			Scopes:            []string(auth.Credential.Scopes),
			CredentialID:      auth.Credential.ID,
			RowVersion:        auth.Instance.RowVersion,
		})
		c.Next()
	}
}

// RequireCollectorScope demands one scope on the already-authenticated principal.
func RequireCollectorScope(scope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		p := CollectorFrom(c)
		if p == nil {
			unauthorized(c)
			return
		}
		for _, have := range p.Scopes {
			if have == scope {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":   "forbidden",
			"message": "credential scope does not allow this operation",
		})
	}
}

// CollectorFrom returns the principal set by AuthenticateCollector.
func CollectorFrom(c *gin.Context) *models.CollectorPrincipal {
	v, ok := c.Get(CtxCollectorPrincipal)
	if !ok || v == nil {
		return nil
	}
	p, _ := v.(*models.CollectorPrincipal)
	return p
}

// EnrollmentFrom returns the enrollment set by AuthenticateEnrollment.
func EnrollmentFrom(c *gin.Context) *models.CollectorEnrollment {
	v, ok := c.Get(CtxEnrollment)
	if !ok || v == nil {
		return nil
	}
	row, _ := v.(*models.CollectorEnrollment)
	return row
}
