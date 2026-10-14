// Package githubhost maps a GitHub provider host (an integration's
// provider_host) to the REST API root every GitHub caller addresses, and
// validates it: the App JWT and installation tokens are sent to that root, so
// a malformed or hostile host must never produce one.
package githubhost

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// DotComAPI is the github.com REST API root.
const DotComAPI = "https://api.github.com"

// hostRe is a DNS name with an optional port: no userinfo, path, query,
// fragment, whitespace or backslash can pass.
var hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[0-9]{1,5})?$`)

// IsDotCom reports whether a provider host is github.com (blank means
// github.com).
func IsDotCom(providerHost string) bool {
	switch strings.ToLower(strings.TrimRight(strings.TrimSpace(providerHost), "/")) {
	case "", "github.com", "api.github.com", "https://github.com", "https://api.github.com":
		return true
	}
	return false
}

// Hostname validates a GitHub Enterprise Server host and returns it
// lower-cased (host or host:port). Only https is accepted, with no userinfo,
// path, query or fragment; IP literals and localhost are refused.
func Hostname(providerHost string) (string, error) {
	h := strings.ToLower(strings.TrimRight(strings.TrimSpace(providerHost), "/"))
	if strings.HasPrefix(h, "http://") {
		return "", errors.New("github host must use https")
	}
	h = strings.TrimPrefix(h, "https://")
	if !hostRe.MatchString(h) {
		return "", fmt.Errorf("github host %q is not a bare host name", providerHost)
	}
	u, err := url.Parse("https://" + h)
	if err != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Hostname() == "" {
		return "", fmt.Errorf("github host %q is not a bare host name", providerHost)
	}
	if name := u.Hostname(); name == "localhost" || net.ParseIP(name) != nil {
		return "", fmt.Errorf("github host %q must be a public DNS name", providerHost)
	}
	return h, nil
}

// APIBase is the REST API root of a provider host: api.github.com for
// github.com, https://<host>/api/v3 for GitHub Enterprise Server.
func APIBase(providerHost string) (string, error) {
	if IsDotCom(providerHost) {
		return DotComAPI, nil
	}
	h, err := Hostname(providerHost)
	if err != nil {
		return "", err
	}
	return "https://" + h + "/api/v3", nil
}
