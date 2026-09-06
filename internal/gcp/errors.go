package gcp

import (
	"errors"

	"google.golang.org/api/googleapi"
)

// Sentinel errors this package returns. The service layer (and, once GCP-04
// lands, the controller) maps these to sanitized codes and an HTTP fault
// classification — mirroring internal/awsdiscovery's ErrNotAssumable /
// ErrThrottled / ErrNoBaseCredentials pattern — never the raw GCP/STS error
// text these wrap internally. Every constructor below that classifies a raw
// provider error discards that error's own message; only a static, sanitized
// string is ever returned or logged from this package, per this ticket's
// explicit instruction that raw GCP/STS text and token material must never
// reach a log or a response.
var (
	// ErrInvalidGrant means a token exchange (WIF's STS call) was rejected —
	// the minted subject token was not accepted, or the exchange otherwise
	// failed on GCP's side in a way that is not one of the more specific cases
	// below. Maps to fault:"gcp" — not something the customer's own account
	// configuration explains on its own.
	ErrInvalidGrant = errors.New("gcp: the credential exchange was rejected")

	// ErrWIFPoolMissing means the customer's pool/provider/binding does not
	// exist, or does not match what AuthSec derived for this
	// (workspace, scope) pair via DeriveWIFParams. A real, expected failure
	// mode now that WIF is fully implemented (GCP-D9) — not a stub-era
	// placeholder — so it maps to fault:"customer_account", mirroring AWS's
	// ErrNotAssumable rather than the v1-era authsec-side classification.
	ErrWIFPoolMissing = errors.New("gcp: the workload identity pool, provider or binding does not match what was derived")

	// ErrKeyInvalid means an uploaded json_key service-account key failed
	// structural validation (missing required field, malformed private key)
	// BEFORE any Vault write or GCP call was attempted.
	ErrKeyInvalid = errors.New("gcp: the service account key is malformed or unusable")

	// ErrPermissionDenied means GCP (or GCP's STS) reached and understood the
	// request but refused it on authorization grounds — the reader identity,
	// once resolved, lacks a permission this ticket's connectivity check
	// needs, or impersonation itself was denied.
	ErrPermissionDenied = errors.New("gcp: permission denied")

	// ErrWIFIssuerNotHTTPS means this AuthSec deployment's configured WIF
	// OIDC issuer (see issuer.go's WIFIssuerEnv) is not HTTPS. Google Cloud
	// unconditionally rejects a non-HTTPS issuer when creating a Workload
	// Identity Pool provider, so WIF cannot succeed here regardless of
	// anything the customer does — this is squarely an AuthSec deployment-
	// configuration problem, never the customer's GCP setup. Caught in
	// ResolveWIFCredential BEFORE any token is minted or GCP/STS call is
	// attempted. Maps to fault:"authsec", not fault:"customer_account" or
	// fault:"gcp" — the deployment-side counterpart to AWS's
	// ErrNoBaseCredentials.
	ErrWIFIssuerNotHTTPS = errors.New("gcp: workload identity federation requires a publicly reachable https issuer, which this deployment is not configured with")

	// ErrWIFIssuerUnreachable means Google Cloud could not reach the WIF
	// provider's configured issuer to complete a credential exchange — GCP's
	// own error_description for this exact case is "Error connecting to the
	// given credential's issuer." (live-confirmed 2026-09-02 against a real
	// GCP project whose WIF provider trusted a Cloudflare quick-tunnel
	// hostname that had since gone offline).
	//
	// This is a live reachability problem with whatever issuer AuthSec (or,
	// in local dev, a developer's tunnel) is currently serving — never a
	// paste mismatch. GCP-04's own pre-flight cross-check
	// (services/cloud_gcp_onboarding.go's resolveOnboardingCredential)
	// already proves the pasted provider_resource is byte-correct before
	// this call is ever reached, so classifyIAMError previously conflated
	// this into ErrWIFPoolMissing (via its broad invalid_grant branch),
	// which told an operator to re-check a value that was already provably
	// correct. Maps to fault:"authsec" — the deployment's issuer is the
	// problem, never the customer's GCP configuration.
	ErrWIFIssuerUnreachable = errors.New("gcp: google cloud could not reach the configured wif issuer to complete the credential exchange")
)

/* ----------------------- google authentication errors ---------------------- */

// ErrGoogleOAuthExchangeFailed means Google rejected or could not complete
// the authorization-code-for-token exchange. Sanitized: never carries the
// authorization code, the client secret, or any token material -- only this
// static sentinel and (for operator logs, not customer-facing responses) the
// bare OAuth "error" field Google returned.
var ErrGoogleOAuthExchangeFailed = errors.New("gcp: google rejected the authorization code exchange")

// ErrGoogleOAuthProvisioningFailed wraps an unexpected failure from a
// provisioning write call that isn't one of the sanitized internal/gcp
// sentinels above (ErrPermissionDenied, etc, reused via errors.Is/As by the
// caller where applicable).
var ErrGoogleOAuthProvisioningFailed = errors.New("gcp: google authentication provisioning failed")

/* --------------------------- error classification -------------------------- */

func isNotFound(err error) bool {
	var gerr *googleapi.Error
	return errors.As(err, &gerr) && gerr.Code == 404
}

func isConflict(err error) bool {
	var gerr *googleapi.Error
	return errors.As(err, &gerr) && (gerr.Code == 409 || gerr.Code == 400)
}
