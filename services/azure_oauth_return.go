package services

import (
	"net"
	"net/url"
	"strings"

	"github.com/authsec-ai/authsec/config"
	"github.com/google/uuid"
)

/* azure_oauth_return.go decides where the browser goes back to after
   Microsoft.

   Azure onboarding leaves the page for Microsoft (a full-page redirect, not a
   popup) and comes back through AuthSec's one registered callback. That
   callback used to send the browser to the one configured UI origin
   (PUBLIC_UI_ORIGIN, e.g. https://app.authsec.ai). But an administrator works
   on their workspace's own origin (https://<workspace>.app.authsec.ai, or a
   verified custom domain): the login page moves them there, and the browser
   keeps their session for that origin only. Sent back to the configured origin,
   they had no session there and landed on its login page.

   So Start records the origin the onboarding was started from -- the browser's
   Origin header on POST /azure/oauth/start, which page script cannot set --
   and the callback returns there. It is accepted only when it is one of THIS
   workspace's own UI origins that AuthSec serves: the configured UI origin or
   the workspace's own domain under the workspace domain suffix. Verified
   custom domains are not accepted: the callback carries the onboarding
   session id, and only hosts AuthSec serves may receive it. The workspace is the token's, never the request's.
   Anything else -- another workspace's domain, a look-alike host, plain http
   outside a local host, a path or credentials -- is ignored, and the
   configured origin is used as before. The callback therefore cannot be made
   to redirect anywhere AuthSec does not serve this workspace's UI. */

// azureReturnOrigin is origin, normalised to scheme://host[:port], when it is
// one of the workspace's own UI origins; "" otherwise.
func (s *AzureOnboardingService) azureReturnOrigin(workspaceID uuid.UUID, origin string) string {
	u, ok := parseUIOrigin(origin)
	if !ok {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	// The configured UI origin: compared as a whole (scheme, host and port).
	if config.AppConfig != nil {
		if cfg, ok := parseUIOrigin(config.AppConfig.UIOrigin); ok && sameOrigin(cfg, u) {
			return originString(u)
		}
	}
	for _, d := range s.workspaceUIHosts(workspaceID) {
		if host == d {
			return originString(u)
		}
	}
	return ""
}

// workspaceUIHosts are the hosts this workspace's UI is served on BY AUTHSEC:
// its own domain (workspaces.workspace_domain), lowercased, without a port,
// and only when it lies under AuthSec's workspace domain suffix
// (TENANT_DOMAIN_SUFFIX). A verified custom domain is not one: verification
// proves control of DNS, not that AuthSec serves the host, and the callback
// carries the onboarding session id there -- a workspace admin could have a
// victim tenant's administrator consent and receive that session on a host of
// their own (review 2026-10-23).
func (s *AzureOnboardingService) workspaceUIHosts(workspaceID uuid.UUID) []string {
	if s.db == nil || workspaceID == uuid.Nil {
		return nil
	}
	suffix := ""
	if config.AppConfig != nil {
		suffix = strings.ToLower(strings.Trim(config.AppConfig.WorkspaceDomainSuffix, ". "))
	}
	if suffix == "" {
		return nil
	}
	var own string
	// TENANT-EXEMPT: workspaces is the tenant table itself (no workspace_id
	// for RLS to scope); read by the token's own workspace id.
	if err := s.db.Table("workspaces").Select("workspace_domain").
		Where("id = ?", workspaceID).Limit(1).Pluck("workspace_domain", &own).Error; err != nil {
		return nil
	}
	if h := bareHost(own); h != "" && strings.HasSuffix(h, "."+suffix) {
		return []string{h}
	}
	return nil
}

// parseUIOrigin accepts an origin and nothing more: https (http only for a
// local host), a host, no credentials, no path beyond "/", no query or
// fragment.
func parseUIOrigin(raw string) (*url.URL, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" {
		return nil, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return nil, false
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !isLocalHost(u.Hostname()) {
			return nil, false
		}
	default:
		return nil, false
	}
	return u, true
}

func isLocalHost(h string) bool {
	h = strings.ToLower(h)
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

func originString(u *url.URL) string {
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

// bareHost is a stored domain as a host: lowercased, without scheme, port or
// path ("aman.app.authsec.ai").
func bareHost(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	if d == "" {
		return ""
	}
	if strings.Contains(d, "://") {
		if u, err := url.Parse(d); err == nil {
			return u.Hostname()
		}
		return ""
	}
	if i := strings.IndexAny(d, "/"); i >= 0 {
		d = d[:i]
	}
	if h, _, err := net.SplitHostPort(d); err == nil {
		return h
	}
	return d
}
