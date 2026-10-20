package config

import (
	"net/url"
	"testing"
)

func TestBuildUIRouteURLAt(t *testing.T) {
	c := &Config{UIOrigin: "https://app.authsec.ai"}
	q := url.Values{"session_id": {"abc"}}

	if got := c.BuildUIRouteURLAt("https://aman.app.authsec.ai", "/discovery/cloud/azure/oauth/callback", q); got !=
		"https://aman.app.authsec.ai/discovery/cloud/azure/oauth/callback?session_id=abc" {
		t.Fatalf("on the workspace origin: %s", got)
	}
	// No origin recorded: the configured UI origin, as BuildUIRouteURL.
	if got, want := c.BuildUIRouteURLAt("", "/discovery/cloud/azure/oauth/callback", q),
		c.BuildUIRouteURL("/discovery/cloud/azure/oauth/callback", q); got != want {
		t.Fatalf("without an origin = %s, want %s", got, want)
	}
	if got := c.BuildUIRouteURLAt("not a url", "/x", nil); got != "https://app.authsec.ai/x" {
		t.Fatalf("an unusable origin falls back: %s", got)
	}
}
