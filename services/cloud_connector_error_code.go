package services

import (
	"errors"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/gcp"
)

// Stable classes for cloud_connector.last_error_code (migration 039).
//
// These are a contract with the console, which maps each to a short phrase.
// Renaming one silently degrades every stored row to the raw prose fallback,
// so treat them the way the HTTP `fault` values are treated: additive only.
//
// Provider-neutral by design. "The role could not be assumed" and "the
// workload identity pool does not match" are the same problem wearing two
// vendors' clothes — the customer's own account refused the connection — and
// an operator reading a mixed list should not have to learn both vocabularies.
const (
	// ConnErrAuthRefused: the customer's account refused the connection.
	// AWS's ErrNotAssumable, GCP's ErrWIFPoolMissing / ErrPermissionDenied.
	ConnErrAuthRefused = "auth_refused"

	// ConnErrThrottled: the provider rate-limited the attempt after retries.
	ConnErrThrottled = "throttled"

	// ConnErrTimeout: the provider did not answer inside the probe budget.
	ConnErrTimeout = "timeout"

	// ConnErrPolicyBlocked: a deliberate policy refused the call — a VPC
	// Service Controls perimeter or an org policy constraint. Split from
	// ConnErrAuthRefused because the remedy is a different team's, not a role
	// grant (see gcp.ClassifyConstraint).
	ConnErrPolicyBlocked = "policy_blocked"

	// ConnErrDeployment: an AuthSec-side configuration problem, never the
	// customer's. AWS's ErrNoBaseCredentials, GCP's ErrWIFIssuerNotHTTPS /
	// ErrWIFIssuerUnreachable.
	ConnErrDeployment = "deployment_misconfigured"

	// ConnErrExternalIDNotIssued: the ExternalId presented belongs to another
	// workspace, so onboarding has to restart from this one.
	ConnErrExternalIDNotIssued = "external_id_not_issued"

	// ConnErrCredentialInvalid: the supplied credential is structurally
	// unusable — a malformed service-account key — as opposed to refused.
	ConnErrCredentialInvalid = "credential_invalid"

	// ConnErrScopeInvalid: the request itself was malformed (bad scope_kind,
	// missing reader project, unrecognised auth method).
	ConnErrScopeInvalid = "scope_invalid"
)

// ClassifyConnectorError reduces an onboarding or verification failure to one
// of the codes above, or "" when it matches no known sentinel.
//
// Empty is a legitimate answer, not a bug to paper over: the console falls
// back to showing last_error verbatim, which is strictly better than an
// invented class. Guessing from message text is what this exists to avoid —
// every branch below is an errors.Is against a sentinel the provider layer
// deliberately wraps.
//
// Order matters where sentinels overlap, and it deliberately mirrors
// mapAWSOnboardingError's ladder: our own probe budget firing is reported as a
// timeout ahead of whatever AWS was doing underneath. Diverging would let the
// HTTP response call a failure a timeout while the row stored "throttled" —
// two answers to one question, which is the thing this column removes.
// A policy refusal is checked before a plain denial because both surface as a
// 403 and only the narrower one names a remedy that works.
func ClassifyConnectorError(err error) string {
	if err == nil {
		return ""
	}

	switch {
	case errors.Is(err, ErrAWSProbeTimeout):
		return ConnErrTimeout

	case errors.Is(err, awsdiscovery.ErrThrottled), errors.Is(err, gcp.ErrThrottled):
		return ConnErrThrottled

	case errors.Is(err, ErrExternalIDNotIssued):
		return ConnErrExternalIDNotIssued

	case errors.Is(err, awsdiscovery.ErrNoBaseCredentials),
		errors.Is(err, gcp.ErrWIFIssuerNotHTTPS),
		errors.Is(err, gcp.ErrWIFIssuerUnreachable):
		return ConnErrDeployment

	case errors.Is(err, gcp.ErrVPCServiceControls), errors.Is(err, gcp.ErrOrgPolicyConstrained):
		return ConnErrPolicyBlocked

	case errors.Is(err, gcp.ErrKeyInvalid):
		return ConnErrCredentialInvalid

	case errors.Is(err, awsdiscovery.ErrNotAssumable),
		errors.Is(err, gcp.ErrWIFPoolMissing),
		errors.Is(err, gcp.ErrPermissionDenied),
		errors.Is(err, gcp.ErrInvalidGrant):
		return ConnErrAuthRefused

	case errors.Is(err, ErrInvalidScopeID):
		return ConnErrScopeInvalid
	}

	// A constraint refusal that arrived as a raw provider error rather than an
	// already-wrapped sentinel. Checked last because it inspects message text,
	// and a sentinel match above is always the better evidence.
	if c := gcp.ClassifyConstraint(err); c != nil {
		return ConnErrPolicyBlocked
	}
	return ""
}
