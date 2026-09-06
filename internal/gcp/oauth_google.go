// oauth_google.go is the Google Authentication bootstrap's OAuth adapter --
// a human's one-time Authorization Code + PKCE consent, used ONLY to obtain a
// short-lived access token that provision.go spends immediately to configure
// the same Workload Identity Federation resources setup-reader.sh already
// creates by hand. Deliberately independent of
// services/connector_oauth_service.go (the third-party connector broker's
// OAuth engine): that engine persists a long-lived Connection to Vault by
// design and hardcodes access_type=offline&prompt=consent for its
// provider.Key=="google" catalog entry -- the opposite of what a one-time,
// discard-after-use bootstrap needs. Nothing in this file is used by, or
// changes the behaviour of, wif.go/wif_parse.go/roles.go/credentials.go/
// issuer.go or setup-reader.sh.
package gcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// GoogleOAuthAuthorizeURL is Google's own OAuth 2.0 authorization endpoint --
// distinct from AuthSec's own OIDC issuer (issuer.go) and from the Hydra
// instance services/connector_oauth_service.go's provider catalog points at.
const GoogleOAuthAuthorizeURL = "https://accounts.google.com/o/oauth2/v2/auth"

// GoogleOAuthTokenURL is Google's token endpoint.
const GoogleOAuthTokenURL = "https://oauth2.googleapis.com/token"

// googleOAuthTokenURL is the var ExchangeGoogleCode actually calls --
// overridable from within this package's own tests (oauth_google_test.go)
// directly, and from other packages' tests (e.g.
// services/gcp_oauth_provision_service_test.go) via
// SetGoogleOAuthTokenURLForTesting below, to point at an httptest.Server
// instead of the real Google endpoint -- the same package-var-seam
// convention services/cloud_gcp_onboarding.go already uses for
// newIAMClientFunc/newResourceManagerClientFunc.
var googleOAuthTokenURL = GoogleOAuthTokenURL

// SetGoogleOAuthTokenURLForTesting overrides the endpoint ExchangeGoogleCode
// calls. FOR TESTS ONLY (exported so other packages' tests can fake Google's
// token endpoint end-to-end); production code never calls this. Returns the
// previous value so a caller can restore it via defer/t.Cleanup.
func SetGoogleOAuthTokenURLForTesting(url string) string {
	prev := googleOAuthTokenURL
	googleOAuthTokenURL = url
	return prev
}

// GoogleOAuthScopes is the exact, narrow scope set this bootstrap requests --
// deliberately NOT https://www.googleapis.com/auth/cloud-platform. Each
// scope below is the documented "Authorization scopes" entry for the
// specific Google API write call provision.go makes with it:
//   - "iam": Workload Identity Pool/Provider create, service-account create,
//     and IAM-policy binding on IAM API resources (the IAM Admin API's
//     documented scope set is exactly {cloud-platform, iam} -- see
//     internal/gcp/client.go's IAMScope doc comment, live-confirmed there
//     already for the WIF path's own IAM calls).
//   - "cloudplatformprojects": Cloud Resource Manager's projects.setIamPolicy
//     and projects.testIamPermissions (and, by the same API surface,
//     folders/organizations equivalents).
//   - "service.management": Service Usage's services.enable /
//     services.batchEnable.
//   - "openid", "email", "profile": identify the signed-in human, nothing
//     about their Google Cloud resources.
var GoogleOAuthScopes = []string{
	"openid",
	"email",
	"profile",
	"https://www.googleapis.com/auth/iam",
	"https://www.googleapis.com/auth/cloudplatformprojects",
	"https://www.googleapis.com/auth/service.management",
}

// ErrGoogleOAuthExchangeFailed means Google rejected or could not complete
// the authorization-code-for-token exchange. Sanitized: never carries the
// authorization code, the client secret, or any token material -- only this
// static sentinel and (for operator logs, not customer-facing responses) the
// bare OAuth "error" field Google returned.
var ErrGoogleOAuthExchangeFailed = errors.New("gcp: google rejected the authorization code exchange")

// GoogleAuthorizeURL builds the Google OAuth 2.0 Authorization Code + PKCE
// consent URL. access_type is deliberately "online" and prompt is left
// unset (no "consent") -- unlike
// services/connector_oauth_service.go's own provider.Key=="google" branch,
// this bootstrap must never receive a refresh token, so it never asks for
// offline access in the first place. There is nothing to discard later
// because Google never issues anything long-lived here.
func GoogleAuthorizeURL(clientID, redirectURI, state, codeChallenge string) string {
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(GoogleOAuthScopes, " "))
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("access_type", "online")
	return GoogleOAuthAuthorizeURL + "?" + q.Encode()
}

// googleTokenResponse is the subset of Google's token-endpoint response this
// bootstrap reads. There is deliberately no refresh_token field here:
// access_type=online (GoogleAuthorizeURL) means Google never sends one for
// this flow, and even if a future Google API response ever included one,
// this struct has nowhere to put it -- json.Unmarshal ignores unknown
// fields, so an accidental refresh_token in the wire response is silently
// dropped, not stored.
type googleTokenResponse struct {
	AccessToken      string `json:"access_token"`
	IDToken          string `json:"id_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// ExchangeGoogleCode exchanges an authorization code for a Google OAuth
// access token (and, since "openid" is in GoogleOAuthScopes, an ID token --
// used only to read the signed-in user's email for audit provenance, never
// as an access credential). Returns only what the caller needs to keep, for
// only as long as the caller chooses to keep it -- this function itself
// stores nothing.
func ExchangeGoogleCode(ctx context.Context, clientID, clientSecret, redirectURI, code, verifier string) (accessToken, idToken string, err error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, googleOAuthTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", fmt.Errorf("gcp: build google token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("gcp: google token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	var body googleTokenResponse
	if derr := json.NewDecoder(resp.Body).Decode(&body); derr != nil {
		return "", "", fmt.Errorf("%w: unreadable response body", ErrGoogleOAuthExchangeFailed)
	}
	if resp.StatusCode != http.StatusOK || body.Error != "" || body.AccessToken == "" {
		return "", "", ErrGoogleOAuthExchangeFailed
	}
	return body.AccessToken, body.IDToken, nil
}

// DecodeGoogleIDTokenEmail extracts the "email" claim from a Google ID
// token's payload segment for DISPLAY/AUDIT PROVENANCE ONLY -- it does not
// verify the token's signature, exactly like the frontend's own
// OIDCCallbackPage.tsx already decodes a JWT client-side for display
// purposes, not as a trust decision. The token was already obtained directly
// from Google's token endpoint over TLS in ExchangeGoogleCode, so there is no
// untrusted party between AuthSec and Google to forge it here; this function
// exists only to avoid a second network round-trip to a userinfo endpoint
// for a value already sitting in the response, not to establish authenticity.
// Returns "" (never an error) if the token is malformed or has no email
// claim -- provenance metadata is optional, not load-bearing.
func DecodeGoogleIDTokenEmail(idToken string) string {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64URLDecodeSegment(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Email
}

// base64URLDecodeSegment decodes one dot-separated JWT segment, tolerating
// both the padded and unpadded base64url forms different issuers emit.
func base64URLDecodeSegment(seg string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(seg); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(seg)
}
