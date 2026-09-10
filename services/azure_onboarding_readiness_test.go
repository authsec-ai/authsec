package services

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/azureonboard"
)

// Regression: an unconfigured service crashed the process instead of refusing.
//
// The constructor used to fail when AZURE_* was absent, so the Microsoft client
// was never nil. Making a workspace able to submit its own application through
// POST /api/azure/config removed that guarantee -- the deployment-wide variables
// became optional -- and one entry point was left without a readiness check:
// /api/azure/callback, which is unauthenticated by necessity because a redirect
// from Microsoft cannot carry a bearer token.
//
// The result was a remote unauthenticated crash. A valid state plus no
// configuration reached the code exchange with a nil client and took the whole
// process down. Reproduced, then fixed in two places: the callback handler now
// treats a failure to bind as fatal, and HandleCallback checks Ready() itself so
// the guarantee does not depend on every future caller remembering.
//
// These tests assert the SERVICE half. A panic here fails the test by crashing
// the run, which is exactly the signal wanted.

func TestNotReady_HandleCallbackRefusesInsteadOfPanicking(t *testing.T) {
	// Deliberately zero-valued: no client id, no redirect uri, nil Microsoft
	// client. This is what an unconfigured deployment holds.
	svc := &AzureOnboardService{}

	_, err := svc.HandleCallback(context.Background(), AzureCallbackInput{
		Code:  "SOMECODE",
		State: "login:whatever",
	})
	if err == nil {
		t.Fatal("expected a refusal from an unconfigured service, got nil error")
	}
	if !errors.Is(err, azureonboard.ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured so the handler maps it to a clean status, got %v", err)
	}
}

func TestReady_NamesEveryMissingPiece(t *testing.T) {
	// Each field is reported by name. An operator reading the error should not
	// have to guess which of the three is absent.
	err := (&AzureOnboardService{}).Ready()
	if err == nil {
		t.Fatal("a zero-valued service is not ready")
	}
	for _, want := range []string{"client id", "redirect uri", "client secret"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Ready() should name %q; got %q", want, err.Error())
		}
	}

	// A client alone is not enough, and neither is an id alone. Ready() must not
	// pass on a partially configured service -- that is how the nil client got
	// past the constructor in the first place.
	partial := &AzureOnboardService{clientID: "0e95f70c-1796-4f53-87ca-59922e465d2e"}
	if partial.Ready() == nil {
		t.Error("a service with only a client id must not report ready")
	}
}
