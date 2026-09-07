package azureonboard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Assigning ARM Reader is the one step of Azure onboarding that AuthSec cannot
// perform. Entra consent and Azure RBAC are separate systems: consent creates
// the service principal in the customer's directory, but nothing about that
// grants it access to any resource. Only a person holding Owner or User Access
// Administrator on the target scope can assign a role, and Azure offers no API
// by which an application grants one to itself -- which is the whole point.
//
// What this file does is remove the searching. Instead of "open IAM, find the
// app, pick a role", the customer gets the exact command or template with the
// principal, role and scope already filled in.
//
// This mirrors what the AWS connector does with its CloudFormation template,
// and for the same reason: an operator following prose instructions across a
// cloud console is where onboarding stalls.

// ReaderRoleDefinitionID is the built-in Reader role. This GUID is identical in
// every Azure tenant -- built-in role definitions are global, so it can be
// hardcoded rather than looked up (a lookup would need ARM access, which is the
// very thing not working yet at this point in the flow).
const ReaderRoleDefinitionID = "acdd72a7-3385-48ef-bd42-f606fba81ae7"

// ReaderSetup is everything a customer needs to grant ARM Reader, in the three
// forms people actually use. Same assignment, three routes to it.
type ReaderSetup struct {
	// PrincipalObjectID is the service principal's object id in the customer's
	// tenant -- what a role assignment names. Not the application (client) id;
	// using that produces "principal not found".
	PrincipalObjectID string `json:"principal_object_id"`
	TenantID          string `json:"tenant_id"`

	// Scopes the commands target. Populated with whatever ARM already lets the
	// app see; empty when it can see nothing yet, which is the normal case here.
	Scopes []string `json:"scopes"`

	AzCLI       string          `json:"az_cli"`
	PowerShell  string          `json:"powershell"`
	ARMTemplate json.RawMessage `json:"arm_template"`

	// AzCLIAllSubscriptions grants Reader once at the tenant's ROOT management
	// group, which covers every subscription in the tenant -- including ones
	// created later. One action per tenant instead of one per subscription.
	//
	// It needs more privilege than the per-subscription form: the caller must
	// hold User Access Administrator at the root group, which an administrator
	// grants themselves through "Access management for Azure resources" in Entra
	// properties. That is a deliberate gate, not an oversight.
	AzCLIAllSubscriptions string `json:"az_cli_all_subscriptions"`

	// RootManagementGroupScope is that scope, spelled out.
	RootManagementGroupScope string `json:"root_management_group_scope"`

	// Portal is the click path, for anyone who would rather not run anything.
	Portal []string `json:"portal_steps"`
}

// BuildReaderSetup produces the assignment instructions for one tenant.
//
// scope is the ARM scope to target: "/subscriptions/<id>" or
// "/providers/Microsoft.Management/managementGroups/<id>". When it is empty --
// which it will be whenever the app cannot yet see any subscription -- the
// commands carry a clearly marked placeholder rather than a wrong value.
func BuildReaderSetup(tenantID, principalObjectID, scope string, scopes []string) ReaderSetup {
	if scope == "" {
		scope = "/subscriptions/<SUBSCRIPTION_ID>"
	}
	if principalObjectID == "" {
		principalObjectID = "<SERVICE_PRINCIPAL_OBJECT_ID>"
	}
	if scopes == nil {
		scopes = []string{}
	}

	tmpl := map[string]any{
		// SUBSCRIPTION-scoped deployment schema, not the resource-group one.
		// A role assignment inherits the scope of the deployment that creates it:
		// with the resource-group schema the portal asks for a resource group and
		// the grant lands there, covering one resource group instead of the
		// subscription -- which silently does not do what onboarding needs.
		"$schema":        "https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json#",
		"contentVersion": "1.0.0.0",
		"parameters": map[string]any{
			"principalId": map[string]any{
				"type":         "string",
				"defaultValue": principalObjectID,
				"metadata": map[string]any{
					"description": "Object id of the AuthSec service principal in this tenant",
				},
			},
		},
		"resources": []any{
			map[string]any{
				"type":       "Microsoft.Authorization/roleAssignments",
				"apiVersion": "2022-04-01",
				// A role assignment name must be a GUID and must be stable, or a
				// re-deploy creates a duplicate instead of being a no-op.
				"name": "[guid(subscription().id, parameters('principalId'), '" + ReaderRoleDefinitionID + "')]",
				"properties": map[string]any{
					"roleDefinitionId": "[subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '" +
						ReaderRoleDefinitionID + "')]",
					"principalId": "[parameters('principalId')]",
					// Required, and the reason a fresh service principal sometimes
					// fails without it: ARM will not wait for directory replication
					// unless it is told the principal is a service principal.
					"principalType": "ServicePrincipal",
				},
			},
		},
	}
	raw, _ := json.MarshalIndent(tmpl, "", "  ")

	// A tenant's root management group id IS the tenant id. So the
	// all-subscriptions scope needs no extra input from anyone.
	rootMG := "/providers/Microsoft.Management/managementGroups/" + tenantID

	return ReaderSetup{
		PrincipalObjectID:        principalObjectID,
		TenantID:                 tenantID,
		Scopes:                   scopes,
		RootManagementGroupScope: rootMG,
		AzCLIAllSubscriptions: fmt.Sprintf(
			"az role assignment create \\\n"+
				"  --assignee-object-id %s \\\n"+
				"  --assignee-principal-type ServicePrincipal \\\n"+
				"  --role Reader \\\n"+
				"  --scope %s",
			principalObjectID, rootMG),
		AzCLI: fmt.Sprintf(
			"az role assignment create \\\n"+
				"  --assignee-object-id %s \\\n"+
				"  --assignee-principal-type ServicePrincipal \\\n"+
				"  --role Reader \\\n"+
				"  --scope %s",
			principalObjectID, scope),
		PowerShell: fmt.Sprintf(
			"New-AzRoleAssignment "+
				"-ObjectId %s "+
				"-RoleDefinitionName Reader "+
				"-Scope %s",
			principalObjectID, scope),
		ARMTemplate: raw,
		Portal: []string{
			"Azure portal -> Management groups -> the tenant root group " +
				"(covers every subscription, now and in future) -- or Subscriptions -> one subscription",
			"Access control (IAM) -> Add -> Add role assignment",
			"Role: Reader (built-in)",
			"Assign access to: User, group, or service principal",
			"Select members -> search for the AuthSec application. If it cannot be found, " +
				"admin consent has not completed in this tenant and the service principal does not exist yet",
			"Review + assign",
		},
	}
}

/* --------------------- checking our own app registration --------------------- */

// Well-known Microsoft Graph identifiers. Constant in every Azure tenant.
const (
	GraphResourceAppID = "00000003-0000-0000-c000-000000000000"

	// Graph app-role ids for the permissions this connector requires. Read from
	// the Graph service principal to confirm, rather than transcribed from
	// documentation: appRoles[?value=='<name>'].id
	roleApplicationReadAll    = "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"
	roleDirectoryReadAll      = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"
	roleRoleManagementReadDir = "483bed4a-2ad3-4361-a73b-c83ccdbdc53c"
	roleAuditLogReadAll       = "b0afded3-3588-46d8-8b3d-9842eff778da"
)

// RequiredGraphRoleIDs maps each required permission to its Graph app-role id,
// which is what an application object actually stores in requiredResourceAccess.
// The names never appear there -- only these ids -- so a check that compares
// names would have nothing to compare against.
func RequiredGraphRoleIDs() map[string]string {
	return map[string]string{
		"Application.Read.All":          roleApplicationReadAll,
		"Directory.Read.All":            roleDirectoryReadAll,
		"RoleManagement.Read.Directory": roleRoleManagementReadDir,
		"AuditLog.Read.All":             roleAuditLogReadAll,
	}
}

// AppRegistration is the subset of our own application object worth asserting on.
type AppRegistration struct {
	DisplayName    string `json:"displayName"`
	AppID          string `json:"appId"`
	SignInAudience string `json:"signInAudience"`
	Web            struct {
		RedirectURIs []string `json:"redirectUris"`
	} `json:"web"`
	RequiredResourceAccess []struct {
		ResourceAppID  string `json:"resourceAppId"`
		ResourceAccess []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"resourceAccess"`
	} `json:"requiredResourceAccess"`
	PasswordCredentials []struct {
		DisplayName string     `json:"displayName"`
		EndDateTime *time.Time `json:"endDateTime"`
	} `json:"passwordCredentials"`
	KeyCredentials []struct {
		DisplayName string     `json:"displayName"`
		EndDateTime *time.Time `json:"endDateTime"`
	} `json:"keyCredentials"`
}

// ReadOwnApp reads OUR application object from the home tenant.
//
// Needs only Application.Read.All, which this connector already requires for
// discovery -- so a configuration self-check costs no additional permission and
// in particular needs no write access. The application object exists ONLY in the
// home tenant; a customer tenant holds a service principal instead, so this call
// must use a home-tenant token.
//
// This is the one place the package reads /applications, and it reads exactly
// one: its own. The promise it keeps is not "never call this endpoint" but
// "never enumerate a customer's directory objects with it".
func (c *HTTPClient) ReadOwnApp(ctx context.Context, accessToken, appID string) (*AppRegistration, error) {
	q := url.Values{}
	q.Set("$filter", "appId eq '"+appID+"'")
	q.Set("$select", "displayName,appId,signInAudience,web,requiredResourceAccess,"+
		"passwordCredentials,keyCredentials")
	endpoint := "https://graph.microsoft.com/v1.0/applications?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build graph request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reach microsoft graph: %v", redactURLError(err))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))

	if resp.StatusCode != http.StatusOK {
		var gErr struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(body, &gErr)
		return nil, &APIError{
			Status:      resp.StatusCode,
			Code:        orDefault(gErr.Error.Code, fmt.Sprintf("http %d", resp.StatusCode)),
			Description: truncate(firstLine(gErr.Error.Message), maxErrorBody),
		}
	}

	var page struct {
		Value []AppRegistration `json:"value"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("decode graph response: %w", err)
	}
	if len(page.Value) == 0 {
		return nil, fmt.Errorf("application %s not found in this tenant -- "+
			"is this the home tenant the app registration was created in?", appID)
	}
	return &page.Value[0], nil
}
