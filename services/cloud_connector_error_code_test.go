package services

import (
	"errors"
	"fmt"
	"testing"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/gcp"
)

// The codes are a contract with the console's code→phrase map. A rename here
// that is not mirrored there silently degrades every stored row to raw prose,
// which is the failure this whole column exists to remove — so pin the wire
// values rather than trusting the constants to stay put.
func TestConnectorErrorCodeWireValues(t *testing.T) {
	for _, tc := range []struct{ got, want string }{
		{ConnErrAuthRefused, "auth_refused"},
		{ConnErrThrottled, "throttled"},
		{ConnErrTimeout, "timeout"},
		{ConnErrPolicyBlocked, "policy_blocked"},
		{ConnErrDeployment, "deployment_misconfigured"},
		{ConnErrExternalIDNotIssued, "external_id_not_issued"},
		{ConnErrCredentialInvalid, "credential_invalid"},
		{ConnErrScopeInvalid, "scope_invalid"},
	} {
		if tc.got != tc.want {
			t.Errorf("wire value changed: got %q, want %q", tc.got, tc.want)
		}
	}
}

func TestClassifyConnectorError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"nil is unclassified", nil, ""},

		// Both clouds' "the customer's account refused us" collapse to one code
		// on purpose: an operator reading a mixed list should not have to learn
		// two vocabularies for one problem.
		{"aws assume refused", awsdiscovery.ErrNotAssumable, ConnErrAuthRefused},
		{"gcp pool mismatch", gcp.ErrWIFPoolMissing, ConnErrAuthRefused},
		{"gcp permission denied", gcp.ErrPermissionDenied, ConnErrAuthRefused},

		{"aws throttled", awsdiscovery.ErrThrottled, ConnErrThrottled},
		{"gcp throttled", gcp.ErrThrottled, ConnErrThrottled},
		{"probe timeout", ErrAWSProbeTimeout, ConnErrTimeout},
		{"external id", ErrExternalIDNotIssued, ConnErrExternalIDNotIssued},

		// Deployment-side faults must never read as the customer's mistake.
		{"aws has no creds", awsdiscovery.ErrNoBaseCredentials, ConnErrDeployment},
		{"wif issuer not https", gcp.ErrWIFIssuerNotHTTPS, ConnErrDeployment},
		{"wif issuer unreachable", gcp.ErrWIFIssuerUnreachable, ConnErrDeployment},

		// A perimeter or org policy is a deliberate refusal whose remedy is a
		// different team's, so it must not collapse into auth_refused.
		{"vpc service controls", gcp.ErrVPCServiceControls, ConnErrPolicyBlocked},
		{"org policy", gcp.ErrOrgPolicyConstrained, ConnErrPolicyBlocked},

		{"malformed key", gcp.ErrKeyInvalid, ConnErrCredentialInvalid},
		{"bad scope", ErrInvalidScopeID, ConnErrScopeInvalid},

		// Wrapping is how every real call site produces these.
		{"wrapped", fmt.Errorf("verify: %w", awsdiscovery.ErrNotAssumable), ConnErrAuthRefused},

		// An unrecognised error stays unclassified. Empty is a real answer: the
		// console then shows the provider's prose, which beats a wrong label.
		{"unknown", errors.New("something else entirely"), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyConnectorError(tc.err); got != tc.want {
				t.Errorf("ClassifyConnectorError(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// Our own probe budget firing is reported as a timeout even when AWS was
// throttling underneath, matching mapAWSOnboardingError's ladder so the HTTP
// fault and the stored code never disagree.
//
// Both wrap shapes are exercised on purpose: VerifyConnector and Onboard wrap
// with "%w: %v" (the inner sentinel does not reach the chain at all), while
// probeRegions uses "%w: %w" (it does). An earlier version of this test only
// built the second shape and asserted the opposite precedence — it passed
// while production, which mostly produces the first shape, did the reverse.
func TestClassifyConnectorErrorTimeoutBeatsThrottle(t *testing.T) {
	t.Run("inner sentinel dropped by %v, as VerifyConnector does", func(t *testing.T) {
		err := fmt.Errorf("%w: %v", ErrAWSProbeTimeout, awsdiscovery.ErrThrottled)
		if got := ClassifyConnectorError(err); got != ConnErrTimeout {
			t.Errorf("got %q, want %q", got, ConnErrTimeout)
		}
	})

	t.Run("both sentinels in the chain, as probeRegions does", func(t *testing.T) {
		err := fmt.Errorf("%w: %w", ErrAWSProbeTimeout, awsdiscovery.ErrThrottled)
		if got := ClassifyConnectorError(err); got != ConnErrTimeout {
			t.Errorf("got %q, want %q", got, ConnErrTimeout)
		}
	})

	// A throttle with no timeout is still a throttle.
	t.Run("throttle alone", func(t *testing.T) {
		if got := ClassifyConnectorError(fmt.Errorf("verify: %w", awsdiscovery.ErrThrottled)); got != ConnErrThrottled {
			t.Errorf("got %q, want %q", got, ConnErrThrottled)
		}
	})
}

// ClassifyConstraint matches on message text, so it is the last resort — a
// sentinel match is always better evidence and must win.
func TestClassifyConnectorErrorConstraintFallback(t *testing.T) {
	if got := ClassifyConnectorError(errors.New("denied by constraints/iam.disableServiceAccountKeyCreation")); got != ConnErrPolicyBlocked {
		t.Errorf("raw org-policy text = %q, want %q", got, ConnErrPolicyBlocked)
	}
}
