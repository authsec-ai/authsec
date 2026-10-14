package middlewares

import (
	"net"
	"net/url"
	"strings"

	"github.com/authsec-ai/authsec/config"
	"github.com/gin-gonic/gin"
)

// Request hosts (AS-064).
//
// Host, Origin, Referer and X-Forwarded-Host are chosen by the client. They
// may decide a pre-authentication workspace or a redirect target only when
// the host is one the operator or a workspace vouches for:
//   - a host matched by CORS_ALLOW_ORIGIN (exact or "*.suffix"; a bare "*"
//     does not vouch for anything);
//   - the host of BASE_URL, the UI origin or the OAuth issuer;
//   - a workspace's own workspace_domain, or a verified custom domain;
//   - localhost, in development only.
// X-Forwarded-Host is read only from a trusted proxy (TRUSTED_PROXIES).

// EffectiveHost is the host the request was addressed to: X-Forwarded-Host
// when the TCP peer is a trusted proxy, otherwise the Host header.
func EffectiveHost(c *gin.Context) string {
	if fh := strings.TrimSpace(c.GetHeader("X-Forwarded-Host")); fh != "" && RequestFromTrustedProxy(c) {
		return strings.TrimSpace(strings.Split(fh, ",")[0])
	}
	return c.Request.Host
}

// HostOnly lower-cases a host[:port] (or a URL) and drops scheme, path and port.
func HostOnly(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if strings.Contains(h, "://") {
		if u, err := url.Parse(h); err == nil {
			h = u.Host
		}
	}
	if i := strings.IndexByte(h, '/'); i >= 0 {
		h = h[:i]
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.Trim(h, "[]")
}

// HostAllowed reports whether host may pick a workspace or be redirected to.
func HostAllowed(host string) bool {
	host = HostOnly(host)
	if host == "" {
		return false
	}
	if config.AppConfig != nil {
		if host == "localhost" || host == "127.0.0.1" {
			return strings.EqualFold(config.AppConfig.Environment, "development")
		}
		for _, entry := range strings.Split(config.AppConfig.CorsAllowOrigin, ",") {
			e := HostOnly(strings.Replace(strings.TrimSpace(entry), "*.", "wildcard.", 1))
			if e == "" || strings.TrimSpace(entry) == "*" {
				continue
			}
			if strings.HasPrefix(e, "wildcard.") {
				if suffix := strings.TrimPrefix(e, "wildcard."); strings.HasSuffix(host, "."+suffix) {
					return true
				}
				continue
			}
			if host == e {
				return true
			}
		}
		for _, u := range []string{config.AppConfig.BaseURL, config.AppConfig.UIOrigin, config.AppConfig.OAuthBaseURL()} {
			if u != "" && host == HostOnly(u) {
				return true
			}
		}
	}
	return knownWorkspaceHost(host)
}

// knownWorkspaceHost reports whether host is a workspace's domain or a
// verified custom domain.
func knownWorkspaceHost(host string) bool {
	db := config.GetDatabase()
	if db == nil || db.DB == nil {
		return false
	}
	var ok bool
	err := db.QueryRow(`SELECT EXISTS (
			SELECT 1 FROM workspaces WHERE LOWER(workspace_domain) = $1 -- TENANT-EXEMPT: pre-auth host check across workspaces
		) OR EXISTS (
			SELECT 1 FROM workspace_domains WHERE LOWER(domain) = $1 AND is_verified -- TENANT-EXEMPT: pre-auth host check across workspaces
		)`, host).Scan(&ok)
	return err == nil && ok
}

// AllowedOriginHost returns the host[:port] of the request's Origin (or,
// without one, its Referer) when that host is allowed, else "".
func AllowedOriginHost(c *gin.Context) string {
	o := strings.TrimSpace(c.GetHeader("Origin"))
	if o == "" || o == "null" {
		o = strings.TrimSpace(c.GetHeader("Referer"))
	}
	u, err := url.Parse(o)
	if err != nil || u.Host == "" || !HostAllowed(u.Host) {
		return ""
	}
	return strings.ToLower(u.Host)
}

// AllowedHostOr returns host when it is allowed, else fallback.
func AllowedHostOr(host, fallback string) string {
	if host != "" && HostAllowed(host) {
		return host
	}
	return fallback
}
