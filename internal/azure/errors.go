package azure

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// Sentinel errors this package returns. The service layer maps them to a
// stable connector error code (services.ClassifyConnectorError) and the
// controller maps them to an {error, hint, fault} response, exactly as
// internal/gcp's sentinels are handled. A raw Microsoft response is wrapped in
// *APIError and only ever surfaces as its code and a truncated message --
// never a token, assertion or secret, none of which is ever in an error body.
var (
	// ErrNotConfigured means the AZURE_AUTHSEC_* deployment configuration or
	// Redis is missing. Fault: authsec.
	ErrNotConfigured = errors.New("azure: microsoft entra id onboarding is not configured in this deployment")

	// ErrConsentDenied means the admin-consent leg came back without
	// admin_consent=True: the admin declined, or the signed-in account cannot
	// grant tenant-wide consent.
	ErrConsentDenied = errors.New("azure: tenant-wide admin consent was not granted")

	// ErrSignInFailed means the delegated sign-in leg was refused or its
	// authorization code could not be redeemed.
	ErrSignInFailed = errors.New("azure: the microsoft sign-in could not be completed")

	// ErrConsentRequired means Entra refused a token because the delegated
	// Azure Service Management permission has not been consented
	// (AADSTS65001). The app registration must declare user_impersonation so
	// the admin-consent leg grants it.
	ErrConsentRequired = errors.New("azure: the azure service management permission has not been consented in this tenant")

	// ErrTenantMismatch means the tenant proven by the signed-in token differs
	// from the tenant the consent leg reported.
	ErrTenantMismatch = errors.New("azure: the signed-in account does not belong to the consented tenant")

	// ErrAppNotInTenant means the AuthSec application has no service
	// principal in the customer tenant -- admin consent has not been granted
	// there, or the enterprise application was deleted (AADSTS700016).
	ErrAppNotInTenant = errors.New("azure: the authsec application is not consented in this tenant")

	// ErrCredentialRejected means Entra refused AuthSec's own client
	// credential (AADSTS7000215 / 7000222 / invalid_client). Fault: authsec.
	ErrCredentialRejected = errors.New("azure: the authsec application credential was rejected")

	// ErrGraphPermissionsMissing means one or more required Microsoft Graph
	// application permissions are not granted to the AuthSec service
	// principal in the customer tenant.
	ErrGraphPermissionsMissing = errors.New("azure: required microsoft graph permissions are not granted")

	// ErrNotAuthorizedToBind means the signed-in user may not attach this
	// tenant to an AuthSec workspace: a guest account, or a member holding no
	// directory role that can grant tenant-wide consent.
	ErrNotAuthorizedToBind = errors.New("azure: the signed-in account is not allowed to connect this tenant")

	// ErrARMForbidden means Azure Resource Manager refused the request
	// (401/403 AuthorizationFailed).
	ErrARMForbidden = errors.New("azure: azure resource manager denied the request")

	// ErrRBACPending means a Reader assignment exists but AuthSec's own
	// service principal cannot read the subscription yet. Azure RBAC changes
	// take minutes to apply; a later verify normally succeeds.
	ErrRBACPending = errors.New("azure: the reader assignment has not taken effect yet")

	// ErrThrottled means Microsoft kept answering 429 after the transport's
	// retries were spent.
	ErrThrottled = errors.New("azure: microsoft throttled the request")

	// ErrInvalidInput means a caller-supplied identifier (subscription id,
	// tenant hint) is malformed. Checked before any network call.
	ErrInvalidInput = errors.New("azure: invalid input")
)

// APIError is a non-success answer from login.microsoftonline.com, Microsoft
// Graph or Azure Resource Manager.
type APIError struct {
	Service string // "login", "graph", "arm"
	Status  int
	Code    string // Microsoft's own code: "AuthorizationFailed", "invalid_grant", "AADSTS700016"
	Message string // Microsoft's prose, truncated
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("azure %s: http %d: %s", e.Service, e.Status, e.Message)
	}
	return fmt.Sprintf("azure %s: http %d %s: %s", e.Service, e.Status, e.Code, e.Message)
}

// Unwrap lets errors.Is match a classified API error against the sentinels
// above without the caller parsing codes.
func (e *APIError) Unwrap() error { return classifyAPIError(e) }

var aadstsCode = regexp.MustCompile(`AADSTS(\d+)`)

// classifyAPIError maps Microsoft's codes to a sentinel, or nil when the
// failure matches none of them.
func classifyAPIError(e *APIError) error {
	if e.Status == http.StatusTooManyRequests {
		return ErrThrottled
	}
	if e.Service == "login" {
		code := e.Code
		if m := aadstsCode.FindStringSubmatch(e.Message); m != nil {
			code = "AADSTS" + m[1]
		}
		switch code {
		case "AADSTS700016", "AADSTS7000229":
			return ErrAppNotInTenant
		case "AADSTS7000215", "AADSTS7000222", "AADSTS700027", "invalid_client":
			return ErrCredentialRejected
		case "AADSTS65001":
			return ErrConsentRequired
		}
		if e.Code == "invalid_client" {
			return ErrCredentialRejected
		}
		return nil
	}
	if e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden {
		if e.Service == "arm" {
			return ErrARMForbidden
		}
	}
	return nil
}

// truncate keeps a provider message without letting a pathological one fill a
// log line or a connector row.
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// IsAPICode reports whether err is an *APIError carrying Microsoft code code
// (case-insensitive).
func IsAPICode(err error, code string) bool {
	var ae *APIError
	return errors.As(err, &ae) && strings.EqualFold(ae.Code, code)
}

// APIStatus returns the HTTP status of an *APIError in err's chain, or 0.
func APIStatus(err error) int {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Status
	}
	return 0
}
