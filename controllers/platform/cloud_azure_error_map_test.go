package platform

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/services"
)

// The customer's own app: every failure of theirs is a 400 with fault
// customer_account and a hint about their app, never AuthSec's deployment.
func TestMapAzureOnboardingErrorCustomApp(t *testing.T) {
	cases := []struct {
		err      error
		code     string
		mentions string
	}{
		{fmt.Errorf("%w: AADSTS7000215", services.ErrAzureCustomCredentialRejected), "credential_invalid", "client secret"},
		{fmt.Errorf("%w: AADSTS90002", services.ErrAzureCustomTenantNotFound), "scope_invalid", "tenant id"},
		{fmt.Errorf("%w: not found", services.ErrAzureCustomAppNotInTenant), "auth_refused", "client id"},
		{fmt.Errorf("%w: Directory.Read.All", services.ErrAzureCustomPermissionsMissing), "auth_refused", "application permissions"},
	}
	for _, c := range cases {
		status, body := mapAzureOnboardingError(c.err)
		if status != http.StatusBadRequest {
			t.Errorf("%v: status %d, want 400", c.err, status)
		}
		if body["fault"] != "customer_account" || body["error_code"] != c.code {
			t.Errorf("%v: fault %v code %v, want customer_account %s", c.err, body["fault"], body["error_code"], c.code)
		}
		hint, _ := body["hint"].(string)
		if !strings.Contains(hint, c.mentions) || strings.Contains(hint, "AZURE_AUTHSEC") {
			t.Errorf("%v: hint %q", c.err, hint)
		}
		if msg, _ := body["error"].(string); !strings.Contains(msg, strings.SplitN(c.err.Error(), ": ", 2)[1]) {
			t.Errorf("%v: the detail is lost from error: %q", c.err, msg)
		}
	}
}

// An unexpected failure never returns its text: it can name a Vault path or
// a database error.
func TestMapAzureOnboardingErrorHidesInternals(t *testing.T) {
	status, body := mapAzureOnboardingError(errors.New("vault write error at https://vault.internal:8200/v1/kv/data/secret/workspaces/x"))
	if status != http.StatusInternalServerError {
		t.Fatalf("status %d", status)
	}
	if msg, _ := body["error"].(string); strings.Contains(msg, "vault") || strings.Contains(msg, "workspaces") {
		t.Fatalf("internals returned: %q", msg)
	}
	status, body = mapAzureOnboardingError(services.ErrAzureCustomCredentialsStore)
	if status != http.StatusInternalServerError || body["fault"] != "authsec" {
		t.Fatalf("store failure: %d %v", status, body)
	}
}

// The managed app's own credential failure stays AuthSec's to fix.
func TestMapAzureOnboardingErrorManagedCredential(t *testing.T) {
	status, body := mapAzureOnboardingError(azure.ErrCredentialRejected)
	if status != http.StatusBadGateway || body["fault"] != "authsec" {
		t.Fatalf("managed credential: %d %v", status, body)
	}
}
