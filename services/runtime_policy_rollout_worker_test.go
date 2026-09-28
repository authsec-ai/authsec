package services

import "testing"

func TestNextCanaryPhase(t *testing.T) {
	if phase, reason := nextCanaryPhase(1, 1, 1, false); phase != "paused" || reason != "" {
		t.Fatalf("threshold phase %s reason %s", phase, reason)
	}
	if phase, reason := nextCanaryPhase(2, 5, 3, false); phase != "canary" || reason != "" {
		t.Fatalf("under threshold inside window phase %s reason %s", phase, reason)
	}
	if phase, reason := nextCanaryPhase(0, 0, 1, true); phase != "canary" || reason != "no_canary_receipts" {
		t.Fatalf("empty window phase %s reason %s", phase, reason)
	}
	if phase, reason := nextCanaryPhase(0, 2, 1, true); phase != "rest" || reason != "" {
		t.Fatalf("promote phase %s reason %s", phase, reason)
	}
	if phase, reason := nextCanaryPhase(0, 0, 1, false); phase != "canary" || reason != "" {
		t.Fatalf("inside window phase %s reason %s", phase, reason)
	}
}
