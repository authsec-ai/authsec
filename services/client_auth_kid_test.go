package services

import "testing"

// AS-066: a kid must match exactly; only a single-key JWKS verifies a token
// without one.
func TestSelectJWK(t *testing.T) {
	two := map[string]interface{}{"a": "key-a", "b": "key-b"}
	if k, ok := selectJWK(two, "b"); !ok || k != "key-b" {
		t.Fatalf("exact kid: %v %v", k, ok)
	}
	if _, ok := selectJWK(two, "c"); ok {
		t.Fatal("unknown kid fell back to another key")
	}
	if _, ok := selectJWK(two, ""); ok {
		t.Fatal("token without kid picked a key from a multi-key JWKS")
	}
	// A single key the JWKS left unnamed verifies any token.
	unnamed := map[string]interface{}{"key-0": "only"}
	if k, ok := selectJWK(unnamed, ""); !ok || k != "only" {
		t.Fatalf("unnamed single key, no kid: %v %v", k, ok)
	}
	if k, ok := selectJWK(unnamed, "other"); !ok || k != "only" {
		t.Fatalf("unnamed single key, named kid: %v %v", k, ok)
	}
	// A single named key only verifies its own kid (or a token without one).
	named := map[string]interface{}{"a": "key-a"}
	if _, ok := selectJWK(named, "other"); ok {
		t.Fatal("named kid matched a differently named single key")
	}
	if k, ok := selectJWK(named, ""); !ok || k != "key-a" {
		t.Fatalf("named single key, no kid: %v %v", k, ok)
	}
}
