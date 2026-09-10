package azureonboard

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// Every message below is real, copied from a live tenant during onboarding.
// They are here because the difference between two of them cost an afternoon:
// a 401 saying the certificate is not registered, and a 403 saying the read
// was denied, look like the same "Azure said no" and are fixed in different
// blades of the portal. Diagnosing them by eye went wrong in the direction
// that does damage -- regenerating a credential that was working, which
// invalidates the certificate already uploaded and produces a new, unfamiliar
// thumbprint in the next error.

const (
	errNoCertificate = "azure returned 401 (invalid_client): AADSTS700027: The certificate " +
		"with identifier used to sign the client assertion is not registered on application. " +
		"[Reason - The key was not found., Thumbprint of key used by client: " +
		"'F67FC15AAB51409AE929074F1149A81FD7C9CD3C', Please visit the Azure Portal, Graph " +
		"Explorer or directly use MS Graph to see configured keys for app Id " +
		"'0cf6bee1-60c1-4874-8877-b68ee6d30b94']. Trace ID: c4e1de21-a0e1-4d50-94bb-a485cce84800"

	errNoRoles = "azure returned 403 (Authorization_RequestDenied): Insufficient privileges " +
		"to complete the operation."
)

func TestDiagnose_TellsAWrongCredentialApartFromAnUngrantedOne(t *testing.T) {
	notUploaded := Diagnose(errors.New(errNoCertificate))
	if notUploaded == nil {
		t.Fatal("AADSTS700027 was not recognised at all")
	}
	if notUploaded.Code != DiagCertificateNotUploaded {
		t.Errorf("AADSTS700027 diagnosed as %q", notUploaded.Code)
	}

	denied := Diagnose(&APIError{
		Status:      http.StatusForbidden,
		Code:        "Authorization_RequestDenied",
		Description: "Insufficient privileges to complete the operation.",
	})
	if denied == nil {
		t.Fatal("a 403 from Graph was not recognised at all")
	}
	if denied.Code != DiagNoApplicationRoles {
		t.Fatalf("a 403 diagnosed as %q, which is the confusion this exists to end",
			denied.Code)
	}

	// The 403 must not send anyone near the credential. That is the specific
	// wrong turn: the credential is provably fine, because Microsoft issued a
	// token before refusing the read.
	low := strings.ToLower(denied.Fix)
	for _, wrong := range []string{"upload", "regenerate", "replace the certificate"} {
		if strings.Contains(low, wrong) {
			t.Errorf("the 403 fix mentions %q, sending the operator to the credential", wrong)
		}
	}
	if !strings.Contains(low, "grant admin consent") {
		t.Error("the 403 fix does not name the button that fixes it")
	}
	if !strings.Contains(low, "application permissions") {
		t.Error("the 403 fix does not say APPLICATION permissions, and a delegated grant " +
			"consents fine while granting nothing")
	}
}

// The permission list has to come from the code that requires them. A list
// typed into a message is a list that keeps naming a permission the check
// stopped asking for.
func TestDiagnose_ListsExactlyThePermissionsTheCheckRequires(t *testing.T) {
	d := Diagnose(errors.New(errNoRoles))
	if d == nil {
		t.Fatal("not recognised")
	}
	required := RequiredGraphRoleIDs()
	if len(d.Permissions) != len(required) {
		t.Fatalf("listed %d permissions, the check requires %d: %v",
			len(d.Permissions), len(required), d.Permissions)
	}
	for _, name := range d.Permissions {
		if _, ok := required[name]; !ok {
			t.Errorf("listed %q, which the check does not require", name)
		}
	}
	// Sorted, so two identical answers are byte-identical.
	for i := 1; i < len(d.Permissions); i++ {
		if d.Permissions[i-1] > d.Permissions[i] {
			t.Fatalf("not sorted: %v", d.Permissions)
		}
	}
}

func TestDiagnose_NamesTheRestOfTheRefusals(t *testing.T) {
	cases := map[string]struct {
		err  error
		want string
	}{
		"no such application": {
			err: errors.New("azure returned 400 (unauthorized_client): AADSTS700016: " +
				"Application with identifier '0cf6bee1' was not found in the directory " +
				"'contoso.onmicrosoft.com'."),
			want: DiagApplicationNotFound,
		},
		"no such tenant": {
			err: errors.New("azure returned 400 (invalid_request): AADSTS90002: Tenant " +
				"'not-a-tenant' not found."),
			want: DiagTenantNotFound,
		},
		"secret rejected": {
			err: errors.New("azure returned 401 (invalid_client): AADSTS7000215: Invalid " +
				"client secret provided."),
			want: DiagSecretRejected,
		},
		"tenant has not consented": {
			err: errors.New("azure returned 400 (invalid_grant): AADSTS65001: The user or " +
				"administrator has not consented to use the application."),
			want: DiagConsentRequired,
		},
		"throttled": {
			err:  &APIError{Status: http.StatusTooManyRequests, Code: "TooManyRequests"},
			want: DiagThrottled,
		},
		"credential refused, no code to go on": {
			err:  &APIError{Status: http.StatusUnauthorized, Code: "invalid_client"},
			want: DiagCredentialRejected,
		},
	}
	for name, c := range cases {
		d := Diagnose(c.err)
		if d == nil {
			t.Errorf("%s: not recognised", name)
			continue
		}
		if d.Code != c.want {
			t.Errorf("%s: diagnosed as %q, want %q", name, d.Code, c.want)
		}
		if strings.TrimSpace(d.Title) == "" || strings.TrimSpace(d.Fix) == "" {
			t.Errorf("%s: recognised but says nothing useful: %+v", name, d)
		}
		if d.Fault == "" {
			t.Errorf("%s: does not say whose problem it is", name)
		}
	}
}

// A diagnosis is an addition, never a replacement, so an unrecognised error has
// to come back as nothing rather than as a guess. Guessing here means telling
// someone confidently to go and change the wrong thing.
func TestDiagnose_SaysNothingRatherThanGuessing(t *testing.T) {
	for name, err := range map[string]error{
		"nil":                nil,
		"a local failure":    errors.New("vault is not configured"),
		"a parse failure":    errors.New("parse certificate: x509: malformed certificate"),
		"an unmapped 500":    &APIError{Status: http.StatusInternalServerError, Code: "unknown"},
		"a plain 404 from a": &APIError{Status: http.StatusNotFound, Code: "Request_ResourceNotFound"},
	} {
		if d := Diagnose(err); d != nil {
			t.Errorf("%s was diagnosed as %q: %s", name, d.Code, d.Fix)
		}
	}
}

// Errors reach the mapper wrapped. Matching only the outermost message would
// quietly stop recognising anything the moment a caller adds context.
func TestDiagnose_SeesThroughWrapping(t *testing.T) {
	inner := &APIError{
		Status:      http.StatusForbidden,
		Code:        "Authorization_RequestDenied",
		Description: "Insufficient privileges to complete the operation.",
	}
	wrapped := fmt.Errorf("read application registration: %w", inner)

	d := Diagnose(wrapped)
	if d == nil || d.Code != DiagNoApplicationRoles {
		t.Fatalf("a wrapped 403 was not recognised: %+v", d)
	}
}

// ARM refuses a missing Reader role with a 403 that says nothing about roles,
// and its fix is in a different plane from consent entirely -- so it must not
// borrow the Graph advice.
func TestDiagnoseARMForbidden_PointsAtRBACNotConsent(t *testing.T) {
	d := DiagnoseARMForbidden()
	low := strings.ToLower(d.Fix)
	if !strings.Contains(low, "reader") {
		t.Error("does not name the role to assign")
	}
	if strings.Contains(low, "api permissions") || strings.Contains(low, "graph") {
		t.Error("sends the operator to consent, which does not grant resource access")
	}
	if len(d.Permissions) != 0 {
		t.Error("lists Graph permissions for an ARM problem")
	}
}
