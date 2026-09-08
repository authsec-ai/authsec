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
	SignInTenant = envOr("AZURE_SIGNIN_TENANT", "organizations")
)

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return strings.TrimSuffix(v, "/")
	}
	return fallback
}

const (
	// Delegated sign-in. offline_access is what makes the refresh token appear,
	// which is what lets a tenant listing survive the hour an ARM access token
	// lasts without sending the operator back through a browser redirect.
	ScopeARMDelegated = "https://management.azure.com/user_impersonation offline_access"

	// Admin consent asks for every application permission configured on the app
	// registration. /.default is the only scope value the adminconsent endpoint
	// accepts -- it means "whatever this app is registered to need", which is
	// exactly right here: the permission set is decided in the portal, reviewed
	// there, and must not be widened from a query string.
	ScopeGraphDefault = "https://graph.microsoft.com/.default"

	// Client credentials for the ARM Reader probe.
	ScopeARMDefault = "https://management.azure.com/.default"

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
)

// NewLoginState mints an unguessable state for the delegated sign-in redirect.
//
// The spec this was built from asked for the literal string "login". A constant
// cannot be validated -- anyone can put it in a URL -- so the prefix is kept for
// readability and a 256-bit random suffix carries the actual security. What
// makes it valid is the matching one-shot row in azure_oauth_state, not the
// string's shape.
func NewLoginState() (string, error) {
	nonce, err := nonce32()
	if err != nil {
		return "", err
	}
	return statePrefixLogin + ":" + nonce, nil
}

// NewConsentState mints the state for one tenant's admin-consent redirect.
//
// The tenant is inside the state as well as in the state row, so a callback that
// disagrees with either is rejected. Microsoft appends its own tenant query
// parameter; that parameter is compared against this, never trusted on its own.
func NewConsentState(tenantID string) (string, error) {
	if err := ValidateTenantID(tenantID); err != nil {
		return "", err
	}
	nonce, err := nonce32()
	if err != nil {
		return "", err
	}
	return statePrefixConsent + ":" + tenantID + ":" + nonce, nil
}

// StatePurpose reports which redirect a state belongs to, and for a consent
// state, the tenant it names. Shape only -- the caller must still redeem it.
func StatePurpose(state string) (purpose, tenantID string, ok bool) {
	parts := strings.Split(state, ":")
	switch {
	case len(parts) == 2 && parts[0] == statePrefixLogin:
		return statePrefixLogin, "", true
	case len(parts) == 3 && parts[0] == statePrefixConsent:
		if ValidateTenantID(parts[1]) != nil {
			return "", "", false
		}
		return statePrefixConsent, parts[1], true
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

// AuthorizeURL is where the operator's browser is sent to sign in.
//
// adminConsent collapses sign-in and tenant-wide admin consent into a single
// Microsoft screen: the administrator signs in and grants the application
// permissions in one pass, and an authorization code still comes back, so the
// tenant listing works immediately afterwards.
//
// It is opt-in because it is strictly narrower. prompt=admin_consent requires
// the person signing in to be a Global Administrator of the tenant; anyone else
// is refused at sign-in rather than merely being unable to consent. Left off,
// any work account can sign in and consent stays a separate per-tenant step,
// which is the only thing that works when one operator onboards tenants they do
// not administer.
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
func AuthorizeURL(clientID, redirectURI, state string, adminConsent bool, signInTenant string) string {
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
	if adminConsent {
		q.Set("prompt", "admin_consent")
	} else {
		// Always show the account picker.
		//
		// Without it Microsoft silently reuses whatever account the browser is
		// already signed in with. When that is a personal account -- outlook.com,
		// live.com, an Xbox login -- the operator gets "You can't sign in here
		// with a personal account" and no way to choose a different one, because
		// nothing ever asked them. That is not a real failure and it is not
		// something the app registration can accommodate: an Azure directory and
		// its subscriptions only exist behind a work or school account, so
		// /organizations correctly refuses. The fix is to let them pick.
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
