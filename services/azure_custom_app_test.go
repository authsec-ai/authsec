package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/azure"
)

func TestCustomAppErrorIsTheCustomersToFix(t *testing.T) {
	cases := []struct {
		name string
		in   error
		want error
		code string
	}{
		{"wrong or expired secret", azure.ErrCredentialRejected, ErrAzureCustomCredentialRejected, ConnErrCredentialInvalid},
		{"unknown tenant", azure.ErrTenantNotFound, ErrAzureCustomTenantNotFound, ConnErrScopeInvalid},
		{"app not in tenant", azure.ErrAppNotInTenant, ErrAzureCustomAppNotInTenant, ConnErrAuthRefused},
		{"graph permissions missing", fmt.Errorf("%w: Directory.Read.All", azure.ErrGraphPermissionsMissing), ErrAzureCustomPermissionsMissing, ConnErrAuthRefused},
		{"graph refuses the directory read", &azure.APIError{Service: "graph", Status: 403, Code: "Authorization_RequestDenied"}, ErrAzureCustomPermissionsMissing, ConnErrAuthRefused},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := customAppError(c.in)
			if !errors.Is(got, c.want) {
				t.Fatalf("customAppError(%v) = %v, want %v", c.in, got, c.want)
			}
			// Never AuthSec's deployment: that is the managed app's code.
			if code := ClassifyConnectorError(got); code != c.code {
				t.Fatalf("code = %q, want %q", code, c.code)
			}
		})
	}
	if got := customAppError(nil); got != nil {
		t.Fatalf("customAppError(nil) = %v", got)
	}
	other := errors.New("something else")
	if got := customAppError(other); got != other {
		t.Fatalf("an unrelated error was rewritten: %v", got)
	}
}

func TestCustomAppPermissionsMissingNamesThem(t *testing.T) {
	got := customAppError(fmt.Errorf("%w: Application.Read.All, AuditLog.Read.All", azure.ErrGraphPermissionsMissing))
	if !strings.Contains(got.Error(), "Application.Read.All, AuditLog.Read.All") {
		t.Fatalf("the missing permissions are not named: %v", got)
	}
}

func TestWriteCapableGraphRoles(t *testing.T) {
	granted := map[string]bool{
		"Directory.Read.All":                 true,
		"Application.Read.All":               true,
		"DeviceManagementApps.Read.All":      true,
		"Directory.ReadWrite.All":            true,
		"Mail.Send":                          true,
		"Sites.Manage.All":                   true,
		"Sites.FullControl.All":              true,
		"RoleManagement.ReadWrite.Directory": true,
		"User.ReadWrite.All":                 false,
	}
	got := strings.Join(writeCapableGraphRoles(granted), ",")
	want := "Directory.ReadWrite.All,Mail.Send,RoleManagement.ReadWrite.Directory,Sites.FullControl.All,Sites.Manage.All"
	if got != want {
		t.Fatalf("write-capable = %s, want %s", got, want)
	}
}

func TestPrivilegedAzureRoles(t *testing.T) {
	ra := func(def string) azure.RoleAssignment {
		var a azure.RoleAssignment
		a.Properties.RoleDefinitionID = def
		return a
	}
	got := privilegedAzureRoles([]azure.RoleAssignment{
		ra("/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"), // Reader
		ra("/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/8E3AF657-A8FF-443C-A75C-2FE8C4BCB635"), // Owner
		ra("/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"),                 // Contributor
		ra("/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"),                 // Owner again
	})
	if strings.Join(got, ",") != "Contributor,Owner" {
		t.Fatalf("privileged = %v, want Contributor and Owner once each, Reader not", got)
	}
}

func TestAzureTransient(t *testing.T) {
	if !azureTransient(azure.ErrThrottled) || !azureTransient(context.DeadlineExceeded) ||
		!azureTransient(&azure.APIError{Service: "graph", Status: 503}) {
		t.Fatal("throttling, a timeout and a 5xx are passing failures")
	}
	if azureTransient(azure.ErrCredentialRejected) || azureTransient(&azure.APIError{Service: "graph", Status: 403}) || azureTransient(nil) {
		t.Fatal("a rejected credential or a 403 is a fact about the connection, not a passing failure")
	}
}

func TestSubscriptionTargetsCoverOnlyTheRun(t *testing.T) {
	ids := azureTargetIDs([]azureScanTarget{{SubscriptionID: "AAAA"}, {SubscriptionID: "bbbb"}})
	if !ids["aaaa"] || !ids["bbbb"] || len(ids) != 2 {
		t.Fatalf("ids = %v", ids)
	}
}
