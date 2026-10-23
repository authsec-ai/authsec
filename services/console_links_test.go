package services

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// consoleRoutes are the console pages the backend may link to: a path equal
// to an exact entry, or starting with a prefix entry (an id follows). Keep it
// in sync with the routes in Authsec-ui src/App.tsx; a link to a page the
// console removed opens a wrong page (an id route) or Not Found (AS-124).
var consoleRoutes = struct{ exact, prefix []string }{
	exact: []string{"/iga/policy", "/iga/policy/setup/notifications", "/iga/connections"},
	// /iga/policy/<id> is an access policy; /iga/policy/setup/<section>
	// forwards to a connection's tab.
	prefix: []string{"/iga/policy/", "/iga/policy/setup/notifications?", "/iga/connections/", "/iga/identities/"},
}

var reConsolePath = regexp.MustCompile(`"(/iga/[^"]*)"`)

// TestConsoleLinksNameServedPages reads every console path literal in the
// backend and requires it to name a page the console serves. A literal that
// is a prefix ("/iga/policy/" + id) must end where the dynamic part starts.
func TestConsoleLinksNameServedPages(t *testing.T) {
	found := 0
	for _, dir := range []string{".", filepath.Join("..", "controllers", "platform")} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range reConsolePath.FindAllStringSubmatch(string(src), -1) {
				found++
				if !servedConsolePath(m[1]) {
					t.Errorf("%s links to %s, which the console does not serve", f, m[1])
				}
			}
		}
	}
	if found < 10 {
		t.Fatalf("found only %d console paths; the scan is not seeing the links", found)
	}
}

func servedConsolePath(p string) bool {
	for _, e := range consoleRoutes.exact {
		if p == e {
			return true
		}
	}
	for _, pre := range consoleRoutes.prefix {
		if p == pre {
			return true
		}
	}
	// A literal with more after a prefix is a fixed page under it: only the
	// setup forward takes one (its query).
	return strings.HasPrefix(p, "/iga/policy/setup/notifications?")
}
