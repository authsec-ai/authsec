package azureonboard

import (
	"net/url"
	"strings"
	"testing"
)

// An ARM assignment scope is concatenated onto ARMBase and sent as a PUT with
// the operator's bearer token attached. That makes it a URL, not a label, and
// an unvalidated URL fragment supplied by a caller relocates the request.
//
// The trick is not obvious by reading the concatenation. "https://management
// .azure.com" + "@10.0.0.7" is a syntactically valid URL whose HOST is 10.0.0.7
// and whose userinfo is the string that looks like ARM. Nothing about the
// resulting text reads as wrong.

func TestValidateARMScope_AcceptsTheTwoRealScopes(t *testing.T) {
	for _, ok := range []string{
		"/subscriptions/8f7d3c2a-1b4e-4c6f-9a2d-5e8b7c1f0a39",
		"/subscriptions/8F7D3C2A-1B4E-4C6F-9A2D-5E8B7C1F0A39",
		"/providers/Microsoft.Management/managementGroups/29a47f2c-634e-46f0-9303-a1a6161e9fc5",
		"/providers/Microsoft.Management/managementGroups/contoso-root",
		"", // empty means "every subscription the operator can see"
	} {
		if err := ValidateARMScope(ok); err != nil {
			t.Errorf("rejected a real scope %q: %v", ok, err)
		}
	}
}

// Each of these was constructed against the actual concatenation in AssignRole.
func TestValidateARMScope_RefusesAnythingThatMovesTheRequest(t *testing.T) {
	cases := map[string]string{
		"userinfo trick, internal host": "@10.0.0.7:8080",
		"userinfo trick, metadata":      "@169.254.169.254",
		"userinfo with a path":          "@evil.example/subscriptions/x",
		"absolute url":                  "https://evil.example",
		"protocol relative":             "//evil.example",
		"path traversal":                "/subscriptions/../../evil",
		"query injection":               "/subscriptions/8f7d3c2a-1b4e-4c6f-9a2d-5e8b7c1f0a39?x=1",
		"fragment":                      "/subscriptions/8f7d3c2a-1b4e-4c6f-9a2d-5e8b7c1f0a39#f",
		"no leading slash":              "subscriptions/8f7d3c2a-1b4e-4c6f-9a2d-5e8b7c1f0a39",
		"resource group scope":          "/subscriptions/8f7d3c2a-1b4e-4c6f-9a2d-5e8b7c1f0a39/resourceGroups/rg",
		"not a guid":                    "/subscriptions/not-a-subscription",
		"management group with a slash": "/providers/Microsoft.Management/managementGroups/a/b",
		"different provider":            "/providers/Microsoft.Authorization/roleAssignments/x",
		"newline":                       "/subscriptions/8f7d3c2a-1b4e-4c6f-9a2d-5e8b7c1f0a39\n",
	}
	for name, bad := range cases {
		if err := ValidateARMScope(bad); err == nil {
			t.Errorf("%s: accepted %q", name, bad)
		}
	}
}

// The reason the validator has to exist, stated as a test: without it, these
// inputs really do produce a URL pointing somewhere else.
func TestARMScope_TheUserinfoTrickReallyRelocatesTheRequest(t *testing.T) {
	const armBase = "https://management.azure.com"
	for _, scope := range []string{"@10.0.0.7:8080", "@169.254.169.254"} {
		u, err := url.Parse(armBase + scope + "/providers/x")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if strings.Contains(u.Host, "management.azure.com") {
			t.Fatalf("expected the host to move, got %q -- if this ever fails the "+
				"premise of ValidateARMScope has changed", u.Host)
		}
		if err := ValidateARMScope(scope); err == nil {
			t.Fatalf("%q moves the host to %q and was accepted", scope, u.Host)
		}
	}
}

// The second check, at the point of sending. It exists so that a future caller
// who forgets the first one does not hand the operator's bearer token to a host
// of the caller's choosing.
func TestSameHostAsARM(t *testing.T) {
	base := ARMBase
	if err := sameHostAsARM(base + "/subscriptions/x/providers/y"); err != nil {
		t.Errorf("refused a genuine ARM url: %v", err)
	}
	for name, bad := range map[string]string{
		"userinfo":     base + "@10.0.0.7/providers/y",
		"other host":   "https://evil.example/providers/y",
		"plain http":   strings.Replace(base, "https://", "http://", 1) + "/providers/y",
		"unparseable":  "://not a url",
		"empty string": "",
	} {
		if err := sameHostAsARM(bad); err == nil {
			t.Errorf("%s: would have sent to %q", name, bad)
		}
	}
}

// The ARM scopes must follow ARMBase. Hardcoding management.azure.com meant a
// sovereign deployment that set all three endpoint variables, as .env.example
// instructs, still asked its own authority for a PUBLIC cloud resource.
func TestARMScopes_FollowTheConfiguredEndpoint(t *testing.T) {
	for _, scope := range []string{ScopeARMDelegated, ScopeARMDefault} {
		if !strings.HasPrefix(scope, ARMBase+"/") {
			t.Errorf("%q does not use the configured ARM endpoint %q", scope, ARMBase)
		}
	}
	if !strings.Contains(ScopeARMDelegated, "offline_access") {
		t.Error("the delegated scope lost offline_access, so no refresh token is issued")
	}
	if !strings.HasSuffix(ScopeARMDefault, "/.default") {
		t.Error("the app-only scope is no longer a .default scope")
	}
}

// One definition of the required permission set. Two lists drift: a permission
// added to the check and not to the guidance leaves an operator granting a set
// that will not pass, with nothing saying which one is short.
func TestRequiredGraphRoles_IsDerivedFromTheIDMap(t *testing.T) {
	names := RequiredGraphRoles()
	ids := RequiredGraphRoleIDs()
	if len(names) != len(ids) {
		t.Fatalf("%d names for %d ids: %v vs %v", len(names), len(ids), names, ids)
	}
	for _, n := range names {
		if _, ok := ids[n]; !ok {
			t.Errorf("%q is named but has no app-role id", n)
		}
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Fatalf("not sorted, so two identical answers differ: %v", names)
		}
	}
}
