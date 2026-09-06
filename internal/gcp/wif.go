// Package gcp is the GCP adapter for cloud discovery onboarding: it knows
// about Google's IAM, Cloud Asset and Resource Manager APIs and about GCP's
// workload identity federation mechanism, and nothing about AuthSec beyond
// the one narrow seam (CloudOnboardingTokenIssuer, in credentials.go) it needs
// to mint the bearer it presents to GCP's own token exchange.
//
// Mirrors the internal/awsdiscovery split: policy (what to persist, when to
// call which function, the connector row) belongs in
// services/gcp_auth_service.go, not here.
package gcp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"strings"

	"github.com/authsec-ai/authsec/config"
	"github.com/google/uuid"
)

// wifDerivationSeparator matches the "." join services/cloud_aws_onboarding.go
// uses for its own HMAC inputs (workspace_id + "." + nonce). Consistency here
// is cosmetic — the two HMACs are computed with different keys-in-practice
// scoping (see hmacKey's doc comment) and are never compared to each other —
// but keeping the shape identical means a reader who already knows one
// convention reads the other for free.
const wifDerivationSeparator = "."

// poolIDPrefix and providerID are fixed per prompt.md's GCP-D9 design: AuthSec
// names the pool and provider deterministically, so the customer never invents
// or reports a name — the setup script and the backend derive the identical
// strings independently, and the console cross-checks the customer's pasted
// provider_resource against what it (re-)derives before ever calling GCP.
const (
	poolIDPrefix = "authsec-"
	// ProviderID is fixed, not derived — GCP-D9's design names exactly one
	// provider per pool, so there is nothing to disambiguate.
	ProviderID = "authsec-provider"
)

// wifSubjectPrefix marks a wif_subject as AuthSec-derived, matching the shape
// prompt.md's design shows in the WIF principal binding
// (principal://.../subject/<wif_subject>).
const wifSubjectPrefix = "authsec:"

// DeriveWIFParams computes the pool id, provider id and WIF subject for a
// (workspace, scope) pair — a PURE function of its inputs, no randomness, no
// I/O beyond reading the (already-resolved, effectively static) HMAC key.
// Called from both the onboarding-package renderer (GCP-04, which embeds
// these into setup-reader.sh) and the connector-create/verify path (GCP-03,
// GCP-04) so the two never compute them two different ways — that divergence
// is exactly what would make a customer-pasted provider_resource fail the
// cross-check for no reason a support engineer could explain.
//
// Per prompt.md's GCP-D9 design:
//
//	pool_id     = "authsec-" + hex(HMAC(key, workspace_id + "." + scope_id))[:16]
//	provider_id = "authsec-provider"                                  (fixed)
//	wif_subject = "authsec:" + hex(HMAC(key, workspace_id + "." + scope_id + ".subject"))[:32]
func DeriveWIFParams(workspaceID uuid.UUID, scopeID string) (poolID, providerID, subject string) {
	key := hmacKey()

	poolSum := hmacSum(key, workspaceID.String()+wifDerivationSeparator+scopeID)
	poolID = poolIDPrefix + hex.EncodeToString(poolSum)[:16]

	subjSum := hmacSum(key, workspaceID.String()+wifDerivationSeparator+scopeID+wifDerivationSeparator+"subject")
	subject = wifSubjectPrefix + hex.EncodeToString(subjSum)[:32]

	return poolID, ProviderID, subject
}

// hmacKey resolves the key used to derive WIF pool/provider/subject values.
//
// Deliberately a SEPARATE function from services.cloudDiscoveryHMACKey rather
// than an import of it: that function is unexported in package services, and
// services is the policy layer that depends on this adapter package (mirroring
// the awsdiscovery/cloud_aws_onboarding split) — this package importing
// services back would be a cycle, and exporting the AWS file's helper just to
// reach across that boundary was out of this ticket's scope (see GCP-03's
// validation list: no changes to services/cloud_aws_onboarding.go). The
// resolution order is copied verbatim from that function because it genuinely
// is provider-neutral, as services/cloud_aws_onboarding.go's own comment says:
//
//  1. AUTHSEC_CLOUD_DISCOVERY_HMAC_KEY
//  2. config.AppConfig.JWTSecret (so a local deployment works out of the box)
//  3. a development constant
//
// If this drifts from services.cloudDiscoveryHMACKey in a future edit, GCP-04
// (which will also need to re-derive these values, server-side, from the same
// key) is the forcing function that will catch it — both sides compute the
// same three strings from the same inputs, or a customer's onboarding attempt
// fails its cross-check every time.
func hmacKey() []byte {
	if v := os.Getenv("AUTHSEC_CLOUD_DISCOVERY_HMAC_KEY"); v != "" {
		return []byte(v)
	}
	if config.AppConfig != nil && config.AppConfig.JWTSecret != "" {
		return []byte(config.AppConfig.JWTSecret)
	}
	return []byte("authsec-cloud-discovery-dev-key")
}

func hmacSum(key []byte, msg string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	return mac.Sum(nil)
}

/* ------------------------- provider resource parsing ----------------------- */

// providerResourcePattern matches a bare WIF provider resource name (no
// "//iam.googleapis.com/" scheme prefix — see credentials.go's audiencePrefix
// doc comment for why the bare form is what's stored and pasted), capturing
// the pool id and provider id segments:
//
//	projects/<NUM>/locations/global/workloadIdentityPools/<pool_id>/providers/<provider_id>
var providerResourcePattern = regexp.MustCompile(
	`^projects/\d+/locations/global/workloadIdentityPools/([^/]+)/providers/([^/]+)$`)

// ParseProviderResource extracts the pool id and provider id segments from a
// bare WIF provider resource name. ok is false when providerResource does not
// match the expected shape at all (not this function's job to say why —
// the caller's cross-check against DeriveWIFParams's own output is what
// actually validates it; this only splits the string apart).
func ParseProviderResource(providerResource string) (poolID, providerID string, ok bool) {
	m := providerResourcePattern.FindStringSubmatch(providerResource)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

/* ------------------------------- wif issuer -------------------------------- */

// WIFIssuerEnv independently configures the OIDC issuer AuthSec presents to
// Google Cloud for Workload Identity Federation — separate from the general
// application base URL (BASE_URL / OAUTH_ISSUER_URL, config.Config.OAuthBaseURL).
// Google requires this specific value to be a real, HTTPS-reachable endpoint
// whose OIDC discovery document and JWKS resolve there — live-confirmed
// against a real GCP WIF provider-creation call: a non-HTTPS issuer is
// rejected outright ("Invalid OIDC issuer URI. The scheme must be https.").
// That is stricter than what the app's base URL needs to satisfy elsewhere
// (cookies, general OAuth redirects, etc.), so it gets its own setting
// rather than forcing the whole app onto HTTPS locally.
//
// Local development: leave BASE_URL at http://localhost:7001 for everything
// else, and set GCP_WIF_ISSUER_URL to a public HTTPS tunnel (e.g. a
// Cloudflare Tunnel or ngrok host) that forwards to that same local server —
// so the real WIF flow can be tested without ever making localhost itself a
// GCP OIDC issuer, and without touching production behavior.
//
// Production: leave unset. Falls back to whatever the caller's own
// OAuthBaseURL() already resolves to — already a real HTTPS URL there, so
// no new configuration is required in production, and production can never
// accidentally fall back to a localhost value this way.
const WIFIssuerEnv = "GCP_WIF_ISSUER_URL"

// ResolveWIFIssuerURL returns the OIDC issuer to use for GCP WIF: the
// explicit GCP_WIF_ISSUER_URL override if set, else defaultIssuerURL
// unchanged (trailing slash trimmed either way). Callers pass their own
// already-resolved app issuer (config.AppConfig.OAuthBaseURL()) as
// defaultIssuerURL — this function never reads that itself, so it has no
// opinion about, and cannot regress, anything unrelated to WIF.
func ResolveWIFIssuerURL(defaultIssuerURL string) string {
	if v := strings.TrimSpace(os.Getenv(WIFIssuerEnv)); v != "" {
		return strings.TrimRight(v, "/")
	}
	return strings.TrimRight(strings.TrimSpace(defaultIssuerURL), "/")
}

// IsHTTPSIssuer reports whether issuerURL is HTTPS — the one thing Google
// Cloud unconditionally requires of a Workload Identity Federation OIDC
// issuer. A non-HTTPS issuer can never work for WIF in any environment, so
// callers check this BEFORE minting a token or handing the customer a setup
// script GCP is guaranteed to reject, rather than letting the failure
// surface only after a wasted round trip.
func IsHTTPSIssuer(issuerURL string) bool {
	return strings.HasPrefix(issuerURL, "https://")
}
