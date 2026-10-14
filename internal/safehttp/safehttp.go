// Package safehttp is the one HTTP client for outbound requests to URLs that
// tenants or remote parties control: JWKS and OIDC discovery fetches, resource
// server validation and PRM re-verification, MCP discovery, policy-warning
// webhooks (AS-042).
//
// The client:
//   - has a total timeout (default 10s) and dial/TLS/header timeouts;
//   - never follows redirects (a 3xx is returned to the caller as is);
//   - never uses an HTTP proxy from the environment;
//   - connects only to public addresses. Loopback, private (RFC 1918, ULA),
//     link-local (including cloud metadata 169.254.169.254), CGNAT,
//     unspecified, multicast and reserved addresses are refused. The check runs
//     on the resolved address that is actually dialled, so DNS rebinding
//     between check and connect is not possible.
//
// Exceptions, for operators only:
//   - MCP_ALLOW_LOOPBACK=true allows loopback addresses (127.0.0.0/8, ::1);
//     the integration-test harness sets it. It does not open private ranges.
//   - OUTBOUND_ALLOWED_HOSTS: comma-separated host names (exact, or ".suffix")
//     that may resolve to private addresses, for in-cluster services such as a
//     SPIRE OIDC discovery provider.
//   - OUTBOUND_ALLOWED_CIDRS: comma-separated CIDR ranges that may be dialled.
//   - hosts of operator-configured URLs registered with TrustOperatorURL
//     (SPIFFE_OIDC_ISSUER).
package safehttp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// DefaultTimeout bounds a whole request (connect, headers and body).
const DefaultTimeout = 10 * time.Second

// ErrBlockedAddress is returned when a destination resolves to an address the
// client may not reach.
var ErrBlockedAddress = errors.New("safehttp: destination address is not allowed")

var shared = New(DefaultTimeout)

// Client returns the shared client.
func Client() *http.Client { return shared }

// New returns a client with the given total timeout.
func New(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           DialContext,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: timeout,
			MaxIdleConns:          20,
			IdleConnTimeout:       30 * time.Second,
			ForceAttemptHTTP2:     true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

var dialer = &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}

// DialContext resolves addr, refuses blocked addresses and dials a checked
// address directly. Use it as http.Transport.DialContext.
func DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("safehttp: invalid address %q: %w", addr, err)
	}
	privateOK := hostAllowed(host)
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("safehttp: resolve %s: %w", host, err)
	}
	var lastErr error = ErrBlockedAddress
	for _, ip := range ips {
		if !privateOK && !Allowed(ip.IP) {
			lastErr = fmt.Errorf("%w: %s resolves to %s", ErrBlockedAddress, host, ip.IP)
			continue
		}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

var blockedNets = mustCIDRs(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "64:ff9b::/96", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
)

// Allowed reports whether ip may be dialled under the current configuration.
func Allowed(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, n := range envCIDRs("OUTBOUND_ALLOWED_CIDRS") {
		if n.Contains(ip) {
			return true
		}
	}
	if ip.IsLoopback() {
		return os.Getenv("MCP_ALLOW_LOOPBACK") == "true"
	}
	for _, n := range blockedNets {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

var (
	operatorMu    sync.RWMutex
	operatorHosts = map[string]bool{}
)

// TrustOperatorURL lets the host of a URL that the operator configured (not a
// tenant), such as SPIFFE_OIDC_ISSUER, resolve to private addresses.
func TrustOperatorURL(raw string) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return
	}
	operatorMu.Lock()
	operatorHosts[strings.ToLower(u.Hostname())] = true
	operatorMu.Unlock()
}

func hostAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	operatorMu.RLock()
	trusted := operatorHosts[host]
	operatorMu.RUnlock()
	if trusted {
		return true
	}
	for _, h := range strings.Split(os.Getenv("OUTBOUND_ALLOWED_HOSTS"), ",") {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if host == h || (strings.HasPrefix(h, ".") && strings.HasSuffix(host, h)) {
			return true
		}
	}
	return false
}

func envCIDRs(name string) []*net.IPNet {
	var out []*net.IPNet
	for _, c := range strings.Split(os.Getenv(name), ",") {
		if c = strings.TrimSpace(c); c == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func mustCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}
