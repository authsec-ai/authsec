package safehttp

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAllowedAddresses(t *testing.T) {
	t.Setenv("MCP_ALLOW_LOOPBACK", "")
	t.Setenv("OUTBOUND_ALLOWED_CIDRS", "")
	blocked := []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1"}
	for _, ip := range blocked {
		if Allowed(net.ParseIP(ip)) {
			t.Errorf("%s must be blocked", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !Allowed(net.ParseIP(ip)) {
			t.Errorf("%s must be allowed", ip)
		}
	}
	t.Setenv("MCP_ALLOW_LOOPBACK", "true")
	if !Allowed(net.ParseIP("127.0.0.1")) {
		t.Errorf("loopback must be allowed with MCP_ALLOW_LOOPBACK=true")
	}
	if Allowed(net.ParseIP("10.0.0.1")) {
		t.Errorf("MCP_ALLOW_LOOPBACK must not open private ranges")
	}
	t.Setenv("OUTBOUND_ALLOWED_CIDRS", "10.0.0.0/8")
	if !Allowed(net.ParseIP("10.0.0.1")) {
		t.Errorf("OUTBOUND_ALLOWED_CIDRS must allow listed ranges")
	}
}

func TestClientRefusesLoopbackAndRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("MCP_ALLOW_LOOPBACK", "")
	if _, err := New(DefaultTimeout).Get(srv.URL); err == nil || !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("loopback fetch must be blocked, got %v", err)
	}

	t.Setenv("MCP_ALLOW_LOOPBACK", "true")
	resp, err := New(DefaultTimeout).Get(srv.URL + "/redirect")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("redirects must not be followed, got %d", resp.StatusCode)
	}
}

func TestOperatorAndAllowedHosts(t *testing.T) {
	t.Setenv("OUTBOUND_ALLOWED_HOSTS", ".svc.cluster.local")
	if !hostAllowed("spire-oidc.spire.svc.cluster.local") || hostAllowed("evil.example") {
		t.Fatalf("OUTBOUND_ALLOWED_HOSTS suffix matching is wrong")
	}
	TrustOperatorURL("https://issuer.internal.example/")
	if !hostAllowed("issuer.internal.example") {
		t.Fatalf("operator-configured URL host must be trusted")
	}
}
