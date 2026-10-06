package shared

import (
	"strings"

	"github.com/authsec-ai/authsec/config"
)

// NormalizeWorkspaceDomain turns what a person types as their workspace into
// the stored workspaces.workspace_domain form, so registration and login
// accept the same input (AS-082):
//
//	"Acme"                       -> "acme.<suffix>"
//	"acme.<suffix>"              -> "acme.<suffix>"
//	"https://ACME.<suffix>:443/" -> "acme.<suffix>"
//	"login.acme.com" (custom)    -> "login.acme.com"
//
// A bare label (no dot) gets the deployment's TENANT_DOMAIN_SUFFIX; anything
// with a dot is taken as a full host name. Empty input stays empty.
func NormalizeWorkspaceDomain(raw string) string {
	suffix := ""
	if config.AppConfig != nil {
		suffix = config.AppConfig.WorkspaceDomainSuffix
	}
	return normalizeWorkspaceDomain(raw, suffix)
}

func normalizeWorkspaceDomain(raw, suffix string) string {
	d := strings.ToLower(strings.TrimSpace(raw))
	if i := strings.Index(d, "://"); i >= 0 {
		d = d[i+3:]
	}
	if i := strings.IndexAny(d, "/?#"); i >= 0 {
		d = d[:i]
	}
	if i := strings.LastIndexByte(d, ':'); i >= 0 {
		d = d[:i]
	}
	d = strings.Trim(d, ".")
	if d == "" {
		return ""
	}
	suffix = strings.Trim(strings.ToLower(strings.TrimSpace(suffix)), ".")
	if !strings.Contains(d, ".") && suffix != "" {
		return d + "." + suffix
	}
	return d
}
