package gcp

import "testing"

// TestIAMScope_IsDedicatedIAMScope pins the IAM client to its own narrower
// scope, not ReadOnlyScope. Live-testing against real GCP proved
// ReadOnlyScope (cloud-platform.read-only) insufficient for the IAM Admin
// API's GetServiceAccount call (403 ACCESS_TOKEN_SCOPE_INSUFFICIENT); the IAM
// Admin API publishes no read-only scope of its own, so
// https://www.googleapis.com/auth/iam is the narrowest correct scope. This
// test guards against silently widening the IAM client back to ReadOnlyScope
// (which would reintroduce the live-confirmed failure) or to full
// cloud-platform (which would widen it beyond what's needed).
func TestIAMScope_IsDedicatedIAMScope(t *testing.T) {
	const want = "https://www.googleapis.com/auth/iam"
	if IAMScope != want {
		t.Fatalf("IAMScope = %q, want %q", IAMScope, want)
	}
	if IAMScope == ReadOnlyScope {
		t.Fatal("IAMScope must not equal ReadOnlyScope — that scope is live-confirmed insufficient for IAM Admin API calls")
	}
}
