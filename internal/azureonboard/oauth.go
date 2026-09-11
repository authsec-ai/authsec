// Package azureonboard is the Azure half of cloud onboarding: sign an operator
// in with their own Azure work account, list the Entra tenants that account can
// see, admin-consent the AuthSec application into the chosen ones, and prove
// whether the consent bought ARM Reader.
//
// Like internal/awsdiscovery, nothing here touches the database, imports gin, or
// knows what a workspace is. Microsoft is reached through interfaces so the
// service layer can be exercised against fakes.
//
// WHAT THIS PACKAGE DELIBERATELY DOES NOT DO. It never calls Microsoft Graph's
// /applications or /servicePrincipals. The application object is AuthSec's own
// and is managed in the portal; reading it back would add a directory-write-
// shaped permission requirement to a flow whose entire claim is that it only
// reads. Admin consent is performed by redirecting a human to Microsoft's own
// consent page, which is the only surface that can grant it anyway.
package azureonboard

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// Microsoft endpoints.
//
// Variables rather than constants because Azure is not one cloud: Azure
// Government and Azure China run the identity platform and Resource Manager on
// entirely different hostnames (login.microsoftonline.us /
// management.usgovcloudapi.net, login.chinacloudapi.cn /
// management.chinacloudapi.cn). A deployment in either has to be able to point
// at them, and hardcoding the public cloud would make that a code change.
//
// Read once at startup. Both default to the public cloud, so a deployment that
// sets neither behaves exactly as before.
var (
	AuthorityBase = envOr("AZURE_AUTHORITY_HOST", "https://login.microsoftonline.com")
	ARMBase       = envOr("AZURE_ARM_ENDPOINT", "https://management.azure.com")

	// GraphBase is the third of the three, and it used to be missing.
	//
	// Identity and Resource Manager were configurable and Microsoft Graph was
	// hardcoded in four places, so a sovereign deployment signed in, read ARM,
	// and then sent every Graph call to the public cloud -- where its tenant
	// does not exist. Half-working is worse than not supported: the failure
	// arrives three steps later and names the wrong thing.
	GraphBase = envOr("AZURE_GRAPH_ENDPOINT", "https://graph.microsoft.com")

	// Admin consent asks for every application permission configured on the app
	// registration. /.default is the only scope value the adminconsent endpoint
	// accepts -- it means "whatever this app is registered to need", which is
	// exactly right here: the permission set is decided in the portal, reviewed
	// there, and must not be widened from a query string.
	//
	// A var rather than a const because it carries the Graph host.
	ScopeGraphDefault = GraphBase + "/.default"

	// SignInTenant is the authority segment the delegated sign-in uses.
	//
	// The default, "organizations", accepts a work or school account from any
	// directory and is what a multi-tenant deployment wants: the operator signs
	// in once and every tenant their account can reach shows up.
	//
	// It rejects personal Microsoft accounts, and that is usually correct -- a
	// consumer account has no directory to enumerate. But there is a real case
	// it gets wrong. An account that signed up for Azure with a personal address
	// gets a directory created for it and becomes that directory's administrator
	// as an EXTERNAL guest (UPN ...#EXT#@...onmicrosoft.com). The identity still
	// lives in the consumer system, so "organizations" turns it away even though
	// it genuinely administers a tenant. Guests invited from another company hit
	// the same wall.
	//
	// Setting this to a tenant GUID switches the sign-in to that tenant's own
	// authority, which is how the Azure portal authenticates exactly these
	// accounts. The trade is that sign-in is then pinned to that one directory.
	// Default "common" rather than "organizations". Microsoft's own table pairs
	// an authority with an audience, and the pairing is not advisory:
	//
	//	AzureADMultipleOrgs                  ->  /organizations
	//	AzureADandPersonalMicrosoftAccount   ->  /common
	//	PersonalMicrosoftAccount             ->  /consumers
	//
	// /common accepts both, so it is correct for either audience -- while
	// /organizations turns away a consumer-backed account even when the
	// application permits it, which is the whole of "You can't sign in here with
	// a personal account". An account that signed up for Azure with a Gmail or
	// Outlook address is exactly that: its credential lives in the consumer
	// system while it administers a directory, and /organizations cannot reach it.
	//
	// A deployment that wants the narrower behaviour sets this to "organizations".
	SignInTenant = envOr("AZURE_SIGNIN_TENANT", "common")
)

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return strings.TrimSuffix(v, "/")
	}
	return fallback
}

const (

	// API versions, pinned. An unpinned ARM call silently changes shape.
	APIVersionTenants       = "2022-12-01"
	APIVersionSubscriptions = "2020-01-01"

	// Role assignment reads, writes and deletes. The same version throughout, so
	// that an assignment created here can be found and removed by the same id.
	APIVersionRoleAssignments = "2022-04-01"

	// elevateAccess is pinned separately and much older. Microsoft documents
	// 2016-07-01 as the minimum for it and 2015-07-01 on the operation reference;
	// it is a different operation from role assignments and there is no reason to
	// assume one version spans both.
	APIVersionElevateAccess = "2016-07-01"
)

// Failure modes a caller maps to HTTP status codes.
var (
	// ErrConsentDenied means an administrator saw the consent page and refused,
	// or Microsoft refused on their behalf. Not an AuthSec fault.
	ErrConsentDenied = errors.New("admin consent was not granted")

	// ErrTenantMismatch means the tenant Microsoft named in the callback is not
	// the tenant the state was issued for. Either a stale browser tab or a
	// forged callback; both must fail closed.
	ErrTenantMismatch = errors.New("callback tenant does not match the tenant consent was requested for")

	// ErrNoSession means there is no usable delegated token for this operator:
	// they never signed in, or the sign-in has expired and cannot be refreshed.
	ErrNoSession = errors.New("no active azure sign-in; start at /api/azure/login")

	// ErrARMForbidden means the app authenticated into the tenant but ARM
	// refused the read. Reader is not assigned, or not assigned at a scope this
	// app can see.
	ErrARMForbidden = errors.New("azure resource manager refused the read")

	// ErrAppNotInTenant means the client-credentials grant failed because the
	// application has no service principal in that tenant -- consent was never
	// completed, or it was revoked.
	ErrAppNotInTenant = errors.New("the AuthSec application is not consented in this tenant")

	// ErrNotConfigured means the deployment is missing Entra app settings.
	ErrNotConfigured = errors.New("azure onboarding is not configured on this deployment")
)

// guidPattern matches the canonical 8-4-4-4-12 form. Tenant and subscription ids
// are interpolated into URLs, so they are validated before they get near one.
var guidPattern = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`,
)

// ValidateTenantID rejects anything that is not a GUID.
//
// Microsoft also accepts a verified domain name in the authority position, but
// this flow always has the id available from the tenant listing, and accepting
// free text here would put caller-controlled characters into a URL path.
func ValidateTenantID(tenantID string) error {
	if strings.TrimSpace(tenantID) == "" {
		return errors.New("tenantId is required")
	}
	if !guidPattern.MatchString(tenantID) {
		return fmt.Errorf("tenantId %q is not a tenant GUID", tenantID)
	}
	return nil
}

// armScopePattern accepts the only two ARM scopes this product assigns Reader
// at: one subscription, or a management group.
//
// It is strict because the value is concatenated onto ARMBase and sent as a PUT
// with the operator's bearer token attached. A scope beginning with "@" is
// enough to move the whole request: "https://management.azure.com" + "@10.0.0.7"
// parses with host 10.0.0.7 and the real ARM host as userinfo, which turns a
// role assignment into a server-side request to any address the deployment can
// route to -- with the token, and with the remote error reflected back to the
// caller. The sibling GCP path already validates its scope id; this did not.
var armScopePattern = regexp.MustCompile(
	`^/subscriptions/[0-9a-fA-F-]{36}$` +
		`|^/providers/Microsoft\.Management/managementGroups/[A-Za-z0-9._()-]{1,90}$`)

// ValidateARMScope checks an operator-supplied ARM assignment scope.
//
// Empty is allowed and means "every subscription the operator can see", which
// the caller expands itself from ARM's own answer rather than from input.
func ValidateARMScope(scope string) error {
	if strings.TrimSpace(scope) == "" {
		return nil
	}
	// Matched as GIVEN, not trimmed. Trimming first means this returns nil for
	// a string that still carries the whitespace when the caller uses it, and
	// a trailing newline in a URL is exactly the kind of thing a validator is
	// for. A caller that wants trimming does it before asking.
	if !armScopePattern.MatchString(scope) {
		return fmt.Errorf("scope %q is not an assignable ARM scope: expected "+
			"/subscriptions/<guid> or "+
			"/providers/Microsoft.Management/managementGroups/<name>", scope)
	}
	return nil
}

// signInTenantPattern accepts a tenant GUID or a domain. Deliberately strict:
// this value is interpolated into the authority URL PATH, where a slash would
// let a caller redirect the sign-in at a host of their choosing.
var signInTenantPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}[A-Za-z0-9]$`)

// ValidateSignInTenant checks an operator-supplied sign-in authority.
func ValidateSignInTenant(t string) error {
	t = strings.TrimSpace(t)
	if t == "" {
		return nil
	}
	if !signInTenantPattern.MatchString(t) {
		return fmt.Errorf("tenant %q is not a tenant GUID or domain", t)
	}
	return nil
}

/* --------------------------------- state --------------------------------- */

// State prefixes. The callback has no other way to tell which of the two
// redirects came back, because Microsoft's own parameters differ only by
// presence.
const (
	statePrefixLogin   = "login"
	statePrefixConsent = "consent"

	// Modes mark a redirect as belonging to the automatic setup, on BOTH legs of
	// it, and say which Reader strategy was chosen.
	//
	// They ride in the state because the callback carries nothing else of ours:
	// Microsoft echoes state, code and admin_consent, and nothing a caller put
	// in the original URL. The choice is made at POST /api/azure/auto-setup and
	// has to survive two round trips through Microsoft to reach the callback
	// that acts on it.
	//
	// Putting it here is safe for the same reason the nonce is: a state is only
	// honoured if it matches a one-shot row keyed on the WHOLE string, so
	// rewriting "login:auto:x" into "login:autowide:x" produces a state that
	// redeems against nothing.
	//
	// modeAuto assigns Reader once per subscription the operator can see.
	// modeAutoWide assigns it once at the tenant root management group, which
	// covers subscriptions created later -- and can require briefly raising the
	// operator's own privilege to root User Access Administrator, so it is never
	// the default and never inferred.
	modeAuto     = "auto"
	modeAutoWide = "autowide"
)

// isAutoMode reports whether a state segment is one of the automatic-setup
// modes. Anything else in that position is not a mode and the state is not ours.
func isAutoMode(segment string) bool {
	return segment == modeAuto || segment == modeAutoWide
}

// NewLoginState mints an unguessable state for the delegated sign-in redirect.
//
// The spec this was built from asked for the literal string "login". A constant
// cannot be validated -- anyone can put it in a URL -- so the prefix is kept for
// readability and a 256-bit random suffix carries the actual security. What
// makes it valid is the matching one-shot row in azure_oauth_state, not the
// string's shape.
// autoSetup marks this as the first leg of the automatic setup; tenantWide
// records which Reader strategy the operator asked for. tenantWide without
// autoSetup is meaningless and is ignored.
func NewLoginState(autoSetup, tenantWide bool) (string, error) {
	nonce, err := nonce32()
	if err != nil {
		return "", err
	}
	if autoSetup {
		return statePrefixLogin + ":" + autoMode(tenantWide) + ":" + nonce, nil
	}
	return statePrefixLogin + ":" + nonce, nil
}

func autoMode(tenantWide bool) string {
	if tenantWide {
		return modeAutoWide
	}
	return modeAuto
}

// LoginStateAutoSetup reports whether this sign-in is the first leg of the
// automatic setup. Shape only; the state must still be redeemed.
func LoginStateAutoSetup(state string) bool {
	parts := strings.Split(state, ":")
	return len(parts) == 3 && parts[0] == statePrefixLogin && isAutoMode(parts[1])
}

// LoginStateTenantWide reports whether that sign-in asked for the tenant-wide
// Reader grant. False for a plain state, so a caller cannot read privilege
// escalation out of a state that never requested it.
func LoginStateTenantWide(state string) bool {
	parts := strings.Split(state, ":")
	return len(parts) == 3 && parts[0] == statePrefixLogin && parts[1] == modeAutoWide
}

// NewConsentState mints the state for one tenant's admin-consent redirect.
//
// The tenant is inside the state as well as in the state row, so a callback that
// disagrees with either is rejected. Microsoft appends its own tenant query
// parameter; that parameter is compared against this, never trusted on its own.
//
// autoSetup marks this as the SECOND leg of the automatic setup, so the callback
// knows to start the chain. It is a separate state from the sign-in's because
// the two redirects are separate: one authorization code, one consent grant, and
// a one-shot row for each.
// tenantWide carries the Reader strategy across to the second leg, which is the
// callback that actually acts on it.
func NewConsentState(tenantID string, autoSetup, tenantWide bool) (string, error) {
	if err := ValidateTenantID(tenantID); err != nil {
		return "", err
	}
	nonce, err := nonce32()
	if err != nil {
		return "", err
	}
	if autoSetup {
		return statePrefixConsent + ":" + autoMode(tenantWide) + ":" + tenantID + ":" + nonce, nil
	}
	return statePrefixConsent + ":" + tenantID + ":" + nonce, nil
}

// ConsentStateAutoSetup reports whether this consent is the second leg of the
// automatic setup. Shape only; the state must still be redeemed.
func ConsentStateAutoSetup(state string) bool {
	parts := strings.Split(state, ":")
	return len(parts) == 4 && parts[0] == statePrefixConsent && isAutoMode(parts[1])
}

// ConsentStateTenantWide reports whether the tenant-wide Reader grant was asked
// for. This is the value the chain acts on, and the only thing that can make it
// true is an operator who chose it at POST /api/azure/auto-setup.
func ConsentStateTenantWide(state string) bool {
	parts := strings.Split(state, ":")
	return len(parts) == 4 && parts[0] == statePrefixConsent && parts[1] == modeAutoWide
}

// StatePurpose reports which redirect a state belongs to, and for a consent
// state, the tenant it names. Shape only -- the caller must still redeem it.
func StatePurpose(state string) (purpose, tenantID string, ok bool) {
	parts := strings.Split(state, ":")

	// The nonce is what carries the security, so a state without one is not a
	// state. Redemption would reject it anyway -- nothing was ever minted with
	// an empty nonce -- but a shape check that accepts "login:" invites a reader
	// to believe the shape means something.
	if len(parts) < 2 || parts[len(parts)-1] == "" {
		return "", "", false
	}
	switch {
	case len(parts) == 2 && parts[0] == statePrefixLogin:
		return statePrefixLogin, "", true
	case len(parts) == 3 && parts[0] == statePrefixLogin && isAutoMode(parts[1]):
		return statePrefixLogin, "", true
	case len(parts) == 3 && parts[0] == statePrefixConsent:
		if ValidateTenantID(parts[1]) != nil {
			return "", "", false
		}
		return statePrefixConsent, parts[1], true
	case len(parts) == 4 && parts[0] == statePrefixConsent && isAutoMode(parts[1]):
		if ValidateTenantID(parts[2]) != nil {
			return "", "", false
		}
		return statePrefixConsent, parts[2], true
	}
	return "", "", false
}

func nonce32() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

/* ---------------------------------- URLs --------------------------------- */

// The ARM scopes follow ARMBase rather than hardcoding the public cloud.
//
// AuthorityBase, ARMBase and GraphBase are all env-configurable so a sovereign
// deployment (Gov, China) can point at its own hostnames, and .env.example says
// all three must be set together. These two constants used to name
// management.azure.com anyway -- so a fully configured sovereign deployment
// asked its own authority for a PUBLIC cloud resource, on every delegated
// sign-in, every refresh and every app-only ARM token. Graph had this exact bug
// once already, which is why GraphBase exists.
var (
	// Delegated sign-in. offline_access is what makes the refresh token appear,
	// which is what lets a tenant listing survive the hour an ARM access token
	// lasts without sending the operator back through a browser redirect.
	ScopeARMDelegated = ARMBase + "/user_impersonation offline_access"

	// Client credentials for the ARM Reader probe.
	ScopeARMDefault = ARMBase + "/.default"
)

// AuthorizeURL is where the operator's browser is sent to sign in.
//
// It does NOT merge admin consent into the sign-in, and cannot.
//
// prompt=admin_consent used to be set here for exactly that, and Microsoft
// refuses it outright:
//
//	AADSTS901001: Invalid request. The prompt request parameter value
//	'admin_consent' is invalid.
//
// That value belongs to the v1.0 endpoint. v2.0 -- which this is, and which the
// app registration's requestedAccessTokenVersion requires -- accepts only login,
// none, consent and select_account. prompt=consent is no substitute either: it
// consents the scopes in THIS request, and this request asks for ARM's delegated
// user_impersonation. The application permissions the discovery needs are
// Microsoft Graph, a different resource, and one /authorize call carries exactly
// one resource.
//
// So the two grants are two redirects, and the automatic setup chains them:
// sign in here, then AdminConsentURL for the tenant the token names. One click
// for the operator, two Microsoft screens.
//
// signInTenant, when non-empty, replaces the process-wide SignInTenant for this
// one sign-in. It exists because /organizations cannot always disambiguate an
// address: Microsoft permits the same address to exist BOTH as a work account in
// a directory and as a consumer Microsoft account, and when it does,
// /organizations can resolve to the personal one -- which produces "You can't
// sign in here with a personal account" with no way forward, since the picker
// keeps offering the same wrong identity.
//
// Naming the directory removes the ambiguity, because only that directory is
// consulted. It is per-request rather than configuration precisely so that one
// deployment still serves every customer: pinning it in the environment would
// make the product single-tenant.
//
// Accepts a tenant GUID or a verified domain. The caller validates it; it lands
// in the URL path.
func AuthorizeURL(
	clientID, redirectURI, state, signInTenant, loginHint string, pickAccount bool,
) string {
	authority := SignInTenant
	if t := strings.TrimSpace(signInTenant); t != "" {
		authority = t
	}
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", redirectURI)
	q.Set("response_mode", "query")
	q.Set("scope", ScopeARMDelegated)
	q.Set("state", state)

	// login_hint pre-fills the username box and, more importantly, tells Entra
	// which identity to resolve BEFORE anyone types anything. For an externally
	// backed account that is the difference between working and not: the real
	// address does not resolve in the directory, the rewritten one does.
	if h := strings.TrimSpace(loginHint); h != "" {
		q.Set("login_hint", h)
	}
	if pickAccount {
		// Force the account picker, ON REQUEST ONLY.
		//
		// It was briefly unconditional and that was a regression. Silent SSO is
		// usually the RIGHT behaviour: an account whose credential lives outside
		// the directory is represented there under a rewritten name
		// (someone_gmail.com#EXT#@tenant.onmicrosoft.com), and nobody knows their
		// own. SSO reuses the identity the browser already holds, so it works
		// without anyone typing anything. Forcing the picker replaced that with a
		// blank box, where typing the real address hands it to the consumer
		// identity system and fails -- turning a working sign-in into a dead end.
		//
		// It remains worth offering, for the opposite case: the browser holds an
		// account the operator does not want to use, and nothing was ever going
		// to ask them.
		q.Set("prompt", "select_account")
	}
	return AuthorityBase + "/" + authority + "/oauth2/v2.0/authorize?" + q.Encode()
}

// AdminConsentURL is where a tenant administrator is sent to grant the
// application's permissions in their directory.
//
// Caller must have validated tenantID; it lands in the URL path.
func AdminConsentURL(clientID, redirectURI, tenantID, state string) string {
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", ScopeGraphDefault)
	q.Set("state", state)
	return AuthorityBase + "/" + tenantID + "/v2.0/adminconsent?" + q.Encode()
}

// TokenURL is the delegated token endpoint. It MUST use the same authority the
// sign-in used -- an authorization code is issued by one authority and is not
// redeemable at another -- which is why both read SignInTenant rather than
// hardcoding a segment.
func TokenURL() string {
	return AuthorityBase + "/" + SignInTenant + "/oauth2/v2.0/token"
}

// TenantTokenURL is the per-tenant token endpoint used by client credentials.
func TenantTokenURL(tenantID string) string {
	return AuthorityBase + "/" + tenantID + "/oauth2/v2.0/token"
}
