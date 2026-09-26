package middlewares

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
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
// Defaults match the historical ingress: no rate limit, and a 32 MiB body
// cap (IGA_LEGACY_INGRESS_MAX_BODY). IGA_LEGACY_INGRESS_RATE_PER_MIN, when
// set to a positive integer, limits each workspace rather than each client
// IP. That workspace id is caller-asserted, so anyone who knows it can
// drain the bucket. A missing or unparseable workspace id falls back to
// RemoteIP when IGA_TRUSTED_PROXIES is unset, so a spoofed X-Forwarded-For
// cannot choose the bucket. When the variable is set, the fallback is
// ClientIP.
//
// Order: the process-wide kill switch (no body read), then the size cap,
// then the optional per-workspace rate limit, then the workspace switch.
// A settings lookup error fails open: the request continues and the error
// is logged. The body is not logged. When a switch is on, the handler is
// not called and the response is 410 Gone.
func LegacyDiscoveryIngressGuard(db *gorm.DB) gin.HandlerFunc {
	var repo *repositories.CollectorRepository
	if db != nil {
		repo = repositories.NewCollectorRepository(db)
	}
	return func(c *gin.Context) {
		if services.LegacyIngressGloballyDisabled() {
			c.AbortWithStatusJSON(http.StatusGone, gin.H{"error": "legacy_discovery_ingress_disabled"})
			return
		}
		maxBody := services.LegacyIngressMaxBody()
		if c.Request.Body == nil || (c.Request.ContentLength == 0 && c.Request.Body == http.NoBody) {
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

		wsID := peekLegacyWorkspace(body)
		if limit := services.LegacyIngressRatePerMin(); limit > 0 {
			if !memStore.checkLimit(legacyRateKey(c, wsID), limit, time.Minute) {
				c.Header("Retry-After", "60")
				c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate_limited"})
				return
			}
		}
		if repo == nil || wsID == uuid.Nil {
			c.Next()
			return
		}
		disabled, err := repo.LegacyIngressDisabled(wsID)
		if err != nil {
			// Fail open. A settings outage must not turn a still-enabled
			// cluster into 503s. The body is not included in the log.
			log.Printf("[collector] ERROR: legacy ingress settings lookup failed for workspace %s; failing open: %v", wsID, err)
			c.Next()
			return
		}
		if disabled {
			c.AbortWithStatusJSON(http.StatusGone, gin.H{"error": "legacy_discovery_ingress_disabled"})
			return
		}
		c.Next()
	}
}

func peekLegacyWorkspace(body []byte) uuid.UUID {
	if len(body) == 0 {
		return uuid.Nil
	}
	var peek struct {
		WorkspaceID string `json:"workspace_id"`
	}
	if err := json.Unmarshal(body, &peek); err != nil || peek.WorkspaceID == "" {
		return uuid.Nil
	}
	id, err := uuid.Parse(peek.WorkspaceID)
	if err != nil {
		return uuid.Nil
	}
	return id
}

func legacyRateKey(c *gin.Context, ws uuid.UUID) string {
	path := c.FullPath()
	if path == "" {
		path = c.Request.URL.Path
	}
	if ws == uuid.Nil {
		// No trusted proxies configured: do not use ClientIP. Gin trusts
		// every X-Forwarded-For by default, and this process does not change
		// that. RemoteIP is the TCP peer and cannot be chosen by the header.
		ip := c.RemoteIP()
		if len(services.TrustedProxyList()) > 0 {
			ip = c.ClientIP()
		}
		return "legacy-discovery:ip:" + ip + ":" + path
	}
	return "legacy-discovery:" + ws.String() + ":" + path
}

// ApplyTrustedProxies configures which reverse proxies may set
// X-Forwarded-For, and only when IGA_TRUSTED_PROXIES is set.
// Unset does not call SetTrustedProxies, so ClientIP() stays on gin's
// default. TenantRateLimitMiddleware, monitoring, admin auth audit, and
// the request log all key off ClientIP(); rewriting the default would
// change those keys app-wide. A rollout behind a load balancer should set
// IGA_TRUSTED_PROXIES to that proxy's CIDRs.
func ApplyTrustedProxies(r *gin.Engine) error {
	list := services.TrustedProxyList()
	if len(list) == 0 {
		return nil
	}
	return r.SetTrustedProxies(list)
}
