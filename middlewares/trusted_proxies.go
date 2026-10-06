package middlewares

import (
	"net"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// TrustedProxies returns the proxies named by TRUSTED_PROXIES: a
// comma-separated list of IP addresses or CIDR ranges (for example the
// ingress controller's pod range). Empty means no proxy is trusted.
func TrustedProxies() []string {
	var out []string
	for _, p := range strings.Split(os.Getenv("TRUSTED_PROXIES"), ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ConfigureTrustedProxies makes c.ClientIP() trustworthy (AS-034, AS-064).
//
// Gin trusts every proxy by default, so any client could choose its own
// address with X-Forwarded-For and dodge per-IP rate limits. With
// TRUSTED_PROXIES unset no forwarding header is honoured and ClientIP is the
// TCP peer (RemoteAddr). With it set, X-Forwarded-For / X-Real-IP are honoured
// only when the request arrives from one of those addresses.
func ConfigureTrustedProxies(r *gin.Engine) error {
	proxies := TrustedProxies()
	r.TrustedPlatform = ""
	r.ForwardedByClientIP = len(proxies) > 0
	return r.SetTrustedProxies(proxies)
}

// RequestFromTrustedProxy reports whether the request's TCP peer is one of
// the configured trusted proxies, i.e. whether its X-Forwarded-* headers may
// be believed at all.
func RequestFromTrustedProxy(c *gin.Context) bool {
	peer := net.ParseIP(c.RemoteIP())
	if peer == nil {
		return false
	}
	for _, p := range TrustedProxies() {
		if strings.Contains(p, "/") {
			if _, n, err := net.ParseCIDR(p); err == nil && n.Contains(peer) {
				return true
			}
		} else if ip := net.ParseIP(p); ip != nil && ip.Equal(peer) {
			return true
		}
	}
	return false
}
