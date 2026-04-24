package config

import (
	"net/url"
	"testing"
)

func TestResolveUIConfig_ExplicitOriginAndBasePath(t *testing.T) {
	t.Parallel()

	origin, basePath, err := resolveUIConfig("https://dev.dev.authsec.dev", "/authsec", "")
	if err != nil {
		t.Fatalf("resolveUIConfig returned error: %v", err)
	}
	if origin != "https://dev.dev.authsec.dev" {
		t.Fatalf("unexpected origin: %q", origin)
	}
	if basePath != "/authsec" {
		t.Fatalf("unexpected base path: %q", basePath)
	}
}

func TestResolveUIConfig_RejectsPathfulExplicitOrigin(t *testing.T) {
	t.Parallel()

	if _, _, err := resolveUIConfig("https://dev.dev.authsec.dev/oidc/auth", "", ""); err == nil {
		t.Fatal("expected error for pathful PUBLIC_UI_ORIGIN, got nil")
	}
}

func TestResolveUIConfig_LegacyReactAppURLRejectsPathfulValue(t *testing.T) {
	t.Parallel()

	if _, _, err := resolveUIConfig("", "", "https://dev.dev.authsec.dev/oidc/auth"); err == nil {
		t.Fatal("expected error for pathful legacy REACT_APP_URL, got nil")
	}
}

func TestBuildUIRouteURL(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		UIOrigin:   "https://dev.dev.authsec.dev",
		UIBasePath: "/authsec",
	}

	query := url.Values{}
	query.Set("login_challenge", "abc123")

	got := cfg.BuildUIRouteURL("/oidc/login", query)
	want := "https://dev.dev.authsec.dev/authsec/oidc/login?login_challenge=abc123"
	if got != want {
		t.Fatalf("unexpected route URL: got %q want %q", got, want)
	}
}

func TestBuildUILoginURLFromRedirectURI_PreservesBasePath(t *testing.T) {
	t.Parallel()

	got, err := BuildUILoginURLFromRedirectURI(
		"https://dev.dev.authsec.dev/authsec/oidc/auth/callback/github",
		"abc123",
	)
	if err != nil {
		t.Fatalf("BuildUILoginURLFromRedirectURI returned error: %v", err)
	}

	want := "https://dev.dev.authsec.dev/authsec/oidc/login?login_challenge=abc123"
	if got != want {
		t.Fatalf("unexpected login URL: got %q want %q", got, want)
	}
}
