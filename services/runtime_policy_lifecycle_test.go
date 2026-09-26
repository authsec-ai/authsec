package services

import "testing"

func TestRuntimePolicyTransitionTable(t *testing.T) {
	states := []string{"draft", "validated", "simulated", "approved", "published", "superseded", "revoked"}
	allowed := map[[2]string]bool{
		{"draft", "validated"}:      true,
		{"validated", "simulated"}:  true,
		{"simulated", "approved"}:   true,
		{"approved", "published"}:   true,
		{"published", "superseded"}: true,
		{"published", "revoked"}:    true,
	}
	for _, from := range states {
		for _, to := range states {
			got := RuntimePolicyTransitionAllowed(from, to)
			want := allowed[[2]string{from, to}]
			if got != want {
				t.Errorf("%s → %s = %v, want %v", from, to, got, want)
			}
		}
	}
	if RuntimePolicyTransitionAllowed("draft", "approved") {
		t.Fatal("draft must not skip to approved")
	}
	if RuntimePolicyTransitionAllowed("approved", "draft") {
		t.Fatal("approved must not return to draft; a draft edit is a new revision")
	}
	if RuntimePolicyTransitionAllowed("nope", "draft") {
		t.Fatal("unknown state was allowed")
	}
}
