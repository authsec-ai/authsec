package azureonboard

import (
	"errors"
	"net/http"
	"sort"
	"strings"
)

// Diagnose turns a refusal from Microsoft into something the operator can act
// on, in the backend, once.
//
// The raw text is not enough and never was. "azure returned 403
// (Authorization_RequestDenied): Insufficient privileges to complete the
// operation" is true, useless, and easy to read as "the credential is wrong" --
// which sends whoever is debugging to regenerate a certificate that was working
// perfectly. The two failures look alike and are fixed in different blades of
// the portal:
//
//	401 invalid_client         the credential is wrong        Certificates & secrets
//	403 Authorization_Request  the credential is RIGHT and    API permissions
//	                           nothing has been granted to it
//
// This lived in one console's JavaScript first. That was the wrong place: the
// console is one client of this API, the diagnosis is a property of the answer
// Microsoft gave, and every other caller got the raw string and no help at all.
type Diagnosis struct {
	// Code is stable and machine-readable. Clients branch on this; the prose
	// below is for people and may be reworded.
	Code string `json:"code"`

	// Title is one line: what is actually wrong.
	Title string `json:"title"`

	// Fix is what to go and do, naming the portal blade where possible.
	Fix string `json:"fix"`

	// Fault says whose problem it is, in the vocabulary the rest of this
	// controller already uses: authsec, operator, customer_tenant, azure.
	Fault string `json:"fault"`

	// Permissions is filled in only when the fix is granting them, so a client
	// renders the list rather than hardcoding one that drifts from the code.
	Permissions []string `json:"permissions,omitempty"`
}

// Fault values, so the strings are written once.
const (
	FaultAuthSec        = "authsec"
	FaultOperator       = "operator"
	FaultCustomerTenant = "customer_tenant"
	FaultAzure          = "azure"
)

// Diagnosis codes. Stable: clients branch on them.
const (
	DiagCertificateNotUploaded = "certificate_not_uploaded"
	DiagSecretRejected         = "client_secret_rejected"
	DiagApplicationNotFound    = "application_not_found"
	DiagTenantNotFound         = "tenant_not_found"
	DiagNoApplicationRoles     = "no_application_permissions"
	DiagConsentRequired        = "admin_consent_required"
	DiagARMForbidden           = "arm_reader_missing"
	DiagThrottled              = "throttled"
	DiagCredentialRejected     = "credential_rejected"
)

// Diagnose returns nil when the error is not a refusal it can name -- a caller
// keeps showing the underlying message either way, because a diagnosis replaces
// nothing and only adds to it.
func Diagnose(err error) *Diagnosis {
	if err == nil {
		return nil
	}
	msg := err.Error()

	var apiErr *APIError
	status, code := 0, ""
	if errors.As(err, &apiErr) {
		status, code = apiErr.Status, apiErr.Code
	}

	switch {
	// The assertion was signed with a key Microsoft has no certificate for.
	// Distinct from every other 401: the client id and tenant are fine.
	case has(msg, "AADSTS700027", "certificate with identifier"):
		return &Diagnosis{
			Code:  DiagCertificateNotUploaded,
			Title: "The certificate this application signs with is not on the registration",
			Fault: FaultOperator,
			Fix: "Download the certificate from the app configuration and upload it at " +
				"portal > your app > Certificates & secrets > Certificates > Upload " +
				"certificate. Its thumbprint must match the one this error quotes. If a " +
				"different certificate is already uploaded it belongs to an earlier key " +
				"pair -- delete it. The client id and tenant id are not the problem.",
		}

	case has(msg, "AADSTS7000215", "invalid client secret"):
		return &Diagnosis{
			Code:  DiagSecretRejected,
			Title: "The client secret is wrong",
			Fault: FaultOperator,
			Fix: "Submit the Value of the secret, not its Secret ID, and check it has not " +
				"expired. A certificate is the better credential here: the private key " +
				"never leaves the secrets store.",
		}

	case has(msg, "AADSTS700016", "was not found in the directory"):
		return &Diagnosis{
			Code:  DiagApplicationNotFound,
			Title: "No application with that client id exists in that directory",
			Fault: FaultOperator,
			Fix: "An application object exists only in the directory it was created in. " +
				"Check the Directory (tenant) ID is that directory, and that the client id " +
				"is the Application (client) ID from the registration Overview page.",
		}

	case has(msg, "AADSTS90002"):
		return &Diagnosis{
			Code:  DiagTenantNotFound,
			Title: "That tenant does not exist",
			Fault: FaultOperator,
			Fix:   "The Directory (tenant) ID is not a directory Microsoft knows.",
		}

	// The credential WORKED -- a token was issued -- and the token carries no
	// roles, so every read is refused. This is the one that reads as a broken
	// credential and is not.
	case status == http.StatusForbidden,
		has(msg, "Authorization_RequestDenied", "Insufficient privileges"):
		return &Diagnosis{
			Code: DiagNoApplicationRoles,
			Title: "Microsoft issued a token, then refused the read: no application " +
				"permissions are granted",
			Fault: FaultCustomerTenant,
			Fix: "The client id, tenant id and credential are all correct -- a token was " +
				"issued. The application has no Microsoft Graph application permissions " +
				"consented to it, so its token carries no roles at all. Portal > your app " +
				"> API permissions > Add a permission > Microsoft Graph > APPLICATION " +
				"permissions (not Delegated -- a delegated grant consents fine and grants " +
				"nothing to an application signing in as itself), add the permissions " +
				"listed here, then press Grant admin consent. Adding them is not granting " +
				"them.",
			Permissions: requiredGraphRoleNames(),
		}

	case has(msg, "AADSTS65001"):
		return &Diagnosis{
			Code:  DiagConsentRequired,
			Title: "This tenant has not consented to the application",
			Fault: FaultCustomerTenant,
			Fix: "An administrator of that tenant must accept the admin consent page. " +
				"Consenting replaces that tenant's existing grants for this application " +
				"rather than adding to them, so everything the application needs must be " +
				"declared on the registration first.",
		}

	case status == http.StatusTooManyRequests:
		return &Diagnosis{
			Code:  DiagThrottled,
			Title: "Microsoft is throttling this application",
			Fault: FaultAzure,
			Fix:   "Requests are retried automatically. Nothing to fix; try again shortly.",
		}

	// Anything else that refused the credential itself.
	case status == http.StatusUnauthorized, code == "invalid_client":
		return &Diagnosis{
			Code:  DiagCredentialRejected,
			Title: "Microsoft would not issue a token for this application",
			Fault: FaultOperator,
			Fix: "The client id, the Directory (tenant) ID or the credential is wrong. An " +
				"application object exists only in the directory it was created in.",
		}
	}
	return nil
}

// DiagnoseARMForbidden is the one case that is not a Microsoft error string:
// ARM answers a missing Reader role with a plain 403 that says nothing about
// roles, and the fix is in a different plane from every case above.
func DiagnoseARMForbidden() *Diagnosis {
	return &Diagnosis{
		Code:  DiagARMForbidden,
		Title: "The application cannot see this subscription",
		Fault: FaultCustomerTenant,
		Fix: "Azure resource access is not granted by consent. Assign the built-in Reader " +
			"role to the AuthSec application on the subscription, or on the tenant root " +
			"management group to cover every subscription including ones created later.",
	}
}

// requiredGraphRoleNames lists the permissions from the same place the check
// reads them, sorted so the output does not shuffle between calls. Hardcoding
// the list in a message is how a message ends up naming a permission the code
// stopped requiring two releases ago.
func requiredGraphRoleNames() []string {
	roles := RequiredGraphRoleIDs()
	names := make([]string, 0, len(roles))
	for name := range roles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func has(msg string, needles ...string) bool {
	low := strings.ToLower(msg)
	for _, n := range needles {
		if strings.Contains(low, strings.ToLower(n)) {
			return true
		}
	}
	return false
}
