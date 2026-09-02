package gcp

import "errors"

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
)
