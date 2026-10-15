package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"

	"github.com/authsec-ai/authsec/internal/azure"
	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

/* azure_custom_app.go is what the "your own app" onboarding (ConnectCustom)
   needs beyond the managed flow: its own errors, which are the customer's to
   fix rather than AuthSec's; warnings when the customer's app can do more
   than read; the lifecycle of the client secret it stores in Vault; and
   moving a tenant's subscriptions to the new credentials when a tenant
   switches between the AuthSec app and the customer's own app. */

// Errors of the customer's own app. Each is the customer's to fix, so none
// reads as AuthSec's deployment being wrong (the managed flow's
// azure.ErrCredentialRejected and friends do).
var (
	ErrAzureCustomCredentialRejected = errors.New("microsoft entra id rejected the client id or client secret of your app")
	ErrAzureCustomTenantNotFound     = errors.New("no microsoft entra id tenant has this tenant id")
	ErrAzureCustomAppNotInTenant     = errors.New("your app has no service principal in this tenant")
	ErrAzureCustomPermissionsMissing = errors.New("your app is missing microsoft graph application permissions")
	// ErrAzureCustomCredentialsStore: the secret could not be stored. Its
	// cause (which names Vault's address and path) is logged, not returned.
	ErrAzureCustomCredentialsStore = errors.New("authsec could not store your app's credentials")
)

// customAppError restates an error of the customer's own app as theirs to
// fix. Anything else is returned as it is.
func customAppError(err error) error {
	if err == nil {
		return nil
	}
	var ae *azure.APIError
	switch {
	case errors.Is(err, azure.ErrCredentialRejected):
		return fmt.Errorf("%w: %s", ErrAzureCustomCredentialRejected, err.Error())
	case errors.Is(err, azure.ErrTenantNotFound):
		return fmt.Errorf("%w: %s", ErrAzureCustomTenantNotFound, err.Error())
	case errors.Is(err, azure.ErrAppNotInTenant):
		return fmt.Errorf("%w: %s", ErrAzureCustomAppNotInTenant, err.Error())
	case errors.Is(err, azure.ErrGraphPermissionsMissing):
		return fmt.Errorf("%w: %s", ErrAzureCustomPermissionsMissing, strings.TrimPrefix(err.Error(), azure.ErrGraphPermissionsMissing.Error()+": "))
	case errors.As(err, &ae) && ae.Service == "graph" && (ae.Status == 401 || ae.Status == 403):
		// Graph refused the directory reads the check itself needs: the app
		// does not hold Application.Read.All / Directory.Read.All.
		return fmt.Errorf("%w: microsoft graph refused the directory read (%s)", ErrAzureCustomPermissionsMissing, err.Error())
	}
	return err
}

/* -------------------------------- privileges --------------------------------- */

// writeCapableGraphRoles are the granted Microsoft Graph application
// permissions that can change data or act as someone: AuthSec only reads, so
// it says when the customer's app holds more than that. Sorted.
func writeCapableGraphRoles(granted map[string]bool) []string {
	var out []string
	for name, ok := range granted {
		if !ok {
			continue
		}
		l := strings.ToLower(name)
		if strings.Contains(l, "readwrite") || strings.HasSuffix(l, ".write") || strings.Contains(l, ".write.") ||
			strings.Contains(l, "fullcontrol") || strings.HasSuffix(l, ".send") || strings.Contains(l, ".send.") ||
			strings.Contains(l, ".manage.") {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// azurePrivilegedRoleIDs are built-in Azure roles that can change resources or
// grant access, by their role definition id (the GUID is the same in every
// tenant). AuthSec needs Reader only.
var azurePrivilegedRoleIDs = map[string]string{
	"8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
	"b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
	"18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
	"f58310d9-a9f6-439a-9e8d-f62e7b41a168": "Role Based Access Control Administrator",
}

// privilegedAzureRoles names the privileged built-in roles among a
// principal's role assignments. Sorted, each once.
func privilegedAzureRoles(assignments []azure.RoleAssignment) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range assignments {
		def := strings.ToLower(a.Properties.RoleDefinitionID)
		if i := strings.LastIndex(def, "/"); i >= 0 {
			def = def[i+1:]
		}
		if name, ok := azurePrivilegedRoleIDs[def]; ok && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

/* ----------------------------- the stored secret ----------------------------- */

// destroyCustomAppSecret removes a tenant's stored client secret from Vault,
// every version of it where Vault allows. Best effort: a failure is logged
// with the path, never returned to the caller, and never blocks a revoke.
func (s *AzureOnboardingService) destroyCustomAppSecret(workspaceID uuid.UUID, tenantID string) {
	if s.vault == nil {
		return
	}
	path := azureCustomAppVaultPath(workspaceID, strings.ToLower(tenantID))
	destroyed, err := vault.Destroy(s.vault, path)
	switch {
	case err != nil:
		log.Printf("[azure] could not remove the custom app credentials of tenant %s from Vault (%s): %v", tenantID, path, err)
	case !destroyed:
		log.Printf("[azure] custom app credentials of tenant %s soft-deleted in Vault (%s): this client cannot destroy every version", tenantID, path)
	}
}

// usesCustomApp reports whether a tenant connector reads with the customer's
// own app (credentials in Vault).
func usesCustomApp(c *models.CloudConnector) bool {
	return c != nil && c.AzureTenantAttrs().ProvisionedVia == models.AzureProvisionedViaClientCredentials
}

/* ------------------------------ switching modes ------------------------------ */

// retargetTenantSubscriptions moves every subscription of the tenant that this
// connect did not record (keep) and that still reads with other credentials
// onto the tenant's new ones, as not readable: the Reader assignment it had
// belongs to the other app. It stays in error, out of discovery, until it is
// connected again with the new app. Returns how many it moved.
func (s *AzureOnboardingService) retargetTenantSubscriptions(workspaceID uuid.UUID, tenantID, authRef, mode string, keep map[string]bool) int {
	all, err := s.connectors.List(workspaceID, models.CloudProviderAzure)
	if err != nil {
		log.Printf("[azure] could not list subscriptions of tenant %s to move them to the new credentials: %v", tenantID, err)
		return 0
	}
	n := 0
	for i := range all {
		c := &all[i]
		if c.ScopeKind != models.CloudScopeSubscription || c.ParentScopeID == nil ||
			!strings.EqualFold(*c.ParentScopeID, tenantID) || keep[strings.ToLower(c.ScopeID)] ||
			c.Status == models.CloudConnectorRevoked || c.AuthRef == authRef {
			continue
		}
		reason := "the tenant now connects with " + mode + ", which cannot read this subscription yet: " +
			"assign it the Reader role here, then verify the subscription or connect the tenant again"
		if err := s.db.Model(&models.CloudConnector{}).
			Where("workspace_id = ? AND id = ?", workspaceID, c.ID).
			Updates(map[string]interface{}{
				"auth_ref": authRef, "status": models.CloudConnectorError,
				"last_error": reason, "last_error_code": ConnErrAuthRefused,
			}).Error; err != nil {
			log.Printf("[azure] could not move subscription %s to the new credentials: %v", c.ScopeID, err)
			continue
		}
		n++
	}
	return n
}

// azureTransient reports whether err is a passing failure -- throttling,
// Microsoft answering 5xx, a timeout or a dropped connection -- rather than
// a fact about the connection.
func azureTransient(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, azure.ErrThrottled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ae *azure.APIError
	if errors.As(err, &ae) && ae.Status >= 500 {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne)
}
