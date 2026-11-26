package azure

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/microsoftgraph/msgraph-sdk-go/policies"
	"github.com/microsoftgraph/msgraph-sdk-go/serviceprincipals"
	"github.com/microsoftgraph/msgraph-sdk-go/subscribedskus"
)

// Graph reads behind the access half of identity discovery: what each
// principal may call (API permissions), who may become it (federated
// credentials), whether it is used (sign-in activity), and which tenant-wide
// guardrails apply (app management and Conditional Access policies). All with
// AuthSec's app-only Graph token.
//
// Two of these live only on Graph's beta endpoint (service principal sign-in
// activity and sign-in logs filtered by event type); Microsoft offers no v1.0
// equivalent. Both need an Entra ID P1/P2 licence in the tenant, and a tenant
// without one answers 403 Authentication_RequestFromNonPremiumTenantOrB2CTenant
// -- see IsLicenseRequired.

/* ------------------------------ API permissions ------------------------------ */

// ResourceAppRoleAssignment is one app role assignment ON a resource service
// principal: a user, group or service principal granted one app role (an
// application permission, or app access for a user) the resource exposes.
type ResourceAppRoleAssignment struct {
	ID                   string     `json:"id"`
	AppRoleID            string     `json:"appRoleId"`
	PrincipalID          string     `json:"principalId"`
	PrincipalType        string     `json:"principalType"`
	PrincipalDisplayName string     `json:"principalDisplayName"`
	ResourceID           string     `json:"resourceId"`
	ResourceDisplayName  string     `json:"resourceDisplayName"`
	CreatedDateTime      *time.Time `json:"createdDateTime"`
}

// DefaultAccessAppRoleID is the app role id Entra records when a principal is
// assigned to an application that defines no roles ("default access").
const DefaultAccessAppRoleID = "00000000-0000-0000-0000-000000000000"

// ListAppRoleAssignedTo returns every app role assignment granted ON the
// resource service principal resourceSPID.
func (c *Client) ListAppRoleAssignedTo(ctx context.Context, graphToken, resourceSPID string) ([]ResourceAppRoleAssignment, error) {
	g, err := c.graph()
	if err != nil {
		return nil, err
	}
	ri, err := g.ServicePrincipals().ByServicePrincipalId(resourceSPID).AppRoleAssignedTo().ToGetRequestInformation(ctx,
		&serviceprincipals.ItemAppRoleAssignedToRequestBuilderGetRequestConfiguration{
			QueryParameters: &serviceprincipals.ItemAppRoleAssignedToRequestBuilderGetQueryParameters{Top: to.Ptr(int32(graphPageSize))}})
	return graphPaged[ResourceAppRoleAssignment](ctx, c, graphToken, ri, err, maxPages)
}

// OAuth2PermissionGrant is one delegated permission grant: the client service
// principal may call the resource with these scopes ON BEHALF OF a signed-in
// user -- every user (consentType AllPrincipals) or one (Principal).
type OAuth2PermissionGrant struct {
	ID          string `json:"id"`
	ClientID    string `json:"clientId"`
	ConsentType string `json:"consentType"`
	PrincipalID string `json:"principalId"`
	ResourceID  string `json:"resourceId"`
	Scope       string `json:"scope"`
}

// Scopes splits the grant's space-separated scope list.
func (g OAuth2PermissionGrant) Scopes() []string { return strings.Fields(g.Scope) }

// ListOAuth2PermissionGrants returns every delegated permission grant in the
// tenant.
func (c *Client) ListOAuth2PermissionGrants(ctx context.Context, graphToken string) ([]OAuth2PermissionGrant, error) {
	// No $top: the endpoint's paging parameters are not documented, and the
	// default page follows @odata.nextLink like every other listing.
	g, err := c.graph()
	if err != nil {
		return nil, err
	}
	ri, err := g.Oauth2PermissionGrants().ToGetRequestInformation(ctx, nil)
	return graphPaged[OAuth2PermissionGrant](ctx, c, graphToken, ri, err, maxPages)
}

/* ---------------------------- federated credentials --------------------------- */

// FederatedCredential is one trust an app registration places in an external
// token issuer: a token from Issuer whose subject is Subject may be exchanged
// for one of this application's tokens, with no secret.
type FederatedCredential struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Issuer      string   `json:"issuer"`
	Subject     string   `json:"subject"`
	Audiences   []string `json:"audiences"`
	Description string   `json:"description"`
}

// ListFederatedCredentials returns an application's federated identity
// credentials. appObjectID is the APPLICATION's object id, not its appId.
func (c *Client) ListFederatedCredentials(ctx context.Context, graphToken, appObjectID string) ([]FederatedCredential, error) {
	g, err := c.graph()
	if err != nil {
		return nil, err
	}
	ri, err := g.Applications().ByApplicationId(appObjectID).FederatedIdentityCredentials().ToGetRequestInformation(ctx, nil)
	return graphPaged[FederatedCredential](ctx, c, graphToken, ri, err, maxPages)
}

/* ------------------------------ sign-in activity ------------------------------ */

// SignInActivity is the most recent sign-in of one kind.
type SignInActivity struct {
	LastSignInDateTime *time.Time `json:"lastSignInDateTime"`
}

// ServicePrincipalSignInActivity is Entra's own per-application summary of
// when a service principal last signed in, split by how.
type ServicePrincipalSignInActivity struct {
	AppID                                           string          `json:"appId"`
	LastSignInActivity                              *SignInActivity `json:"lastSignInActivity"`
	DelegatedClientSignInActivity                   *SignInActivity `json:"delegatedClientSignInActivity"`
	DelegatedResourceSignInActivity                 *SignInActivity `json:"delegatedResourceSignInActivity"`
	ApplicationAuthenticationClientSignInActivity   *SignInActivity `json:"applicationAuthenticationClientSignInActivity"`
	ApplicationAuthenticationResourceSignInActivity *SignInActivity `json:"applicationAuthenticationResourceSignInActivity"`
}

// ListServicePrincipalSignInActivities returns the sign-in summary of every
// application that signed in within Entra's retention. Beta only.
func (c *Client) ListServicePrincipalSignInActivities(ctx context.Context, graphToken string) ([]ServicePrincipalSignInActivity, error) {
	ri, err := graphURL(GraphEndpoint + "/beta/reports/servicePrincipalSignInActivities")
	return graphPaged[ServicePrincipalSignInActivity](ctx, c, graphToken, ri, err, maxPages)
}

// AppCredentialSignInActivity is when one client secret or certificate was
// last used to sign in.
type AppCredentialSignInActivity struct {
	KeyID                    string          `json:"keyId"`
	KeyType                  string          `json:"keyType"`
	KeyUsage                 string          `json:"keyUsage"`
	AppID                    string          `json:"appId"`
	AppObjectID              string          `json:"appObjectId"`
	ServicePrincipalObjectID string          `json:"servicePrincipalObjectId"`
	CredentialOrigin         string          `json:"credentialOrigin"`
	SignInActivity           *SignInActivity `json:"signInActivity"`
}

// ListAppCredentialSignInActivities returns per-credential sign-in activity.
// Beta only.
func (c *Client) ListAppCredentialSignInActivities(ctx context.Context, graphToken string) ([]AppCredentialSignInActivity, error) {
	ri, err := graphURL(GraphEndpoint + "/beta/reports/appCredentialSignInActivities")
	return graphPaged[AppCredentialSignInActivity](ctx, c, graphToken, ri, err, maxPages)
}

// SignIn is one non-interactive sign-in by a service principal or a managed
// identity: which identity got a token, for which resource, from where.
type SignIn struct {
	CreatedDateTime     *time.Time `json:"createdDateTime"`
	AppID               string     `json:"appId"`
	ServicePrincipalID  string     `json:"servicePrincipalId"`
	ResourceID          string     `json:"resourceId"`
	ResourceDisplayName string     `json:"resourceDisplayName"`
	IPAddress           string     `json:"ipAddress"`
	Status              struct {
		ErrorCode int `json:"errorCode"`
	} `json:"status"`
	// Agent says whether an Entra agent signed in: agentType is "notAgentic"
	// for anything else. Beta.
	Agent *struct {
		AgentType string `json:"agentType"`
	} `json:"agent,omitempty"`
}

// AgentType is the sign-in's agent type, "" when it was not an agent.
func (s SignIn) AgentType() string {
	if s.Agent == nil || strings.EqualFold(s.Agent.AgentType, "notAgentic") {
		return ""
	}
	return s.Agent.AgentType
}

// Sign-in event types AuthSec reads. Interactive and non-interactive USER
// sign-ins are deliberately not read: they are people, not workloads.
const (
	SignInEventServicePrincipal = "servicePrincipal"
	SignInEventManagedIdentity  = "managedIdentity"
)

// ListSignIns returns sign-ins of one event type since the given time, newest
// first, stopping after maxPages pages (ErrPageLimit, with the rows read).
// Beta only: v1.0 returns interactive user sign-ins and cannot filter by type.
func (c *Client) ListSignIns(ctx context.Context, graphToken, eventType string, since time.Time, maxPages int) ([]SignIn, error) {
	q := url.Values{}
	q.Set("$filter", "createdDateTime ge "+since.UTC().Format(time.RFC3339)+
		" and signInEventTypes/any(t: t eq '"+eventType+"')")
	q.Set("$top", "1000")
	ri, err := graphURL(GraphEndpoint + "/beta/auditLogs/signIns?" + q.Encode())
	return graphPaged[SignIn](ctx, c, graphToken, ri, err, maxPages)
}

/* ---------------------------------- licences ---------------------------------- */

// SubscribedSku is one licence the tenant holds.
type SubscribedSku struct {
	SkuPartNumber    string `json:"skuPartNumber"`
	CapabilityStatus string `json:"capabilityStatus"`
	ServicePlans     []struct {
		ServicePlanName    string `json:"servicePlanName"`
		ProvisioningStatus string `json:"provisioningStatus"`
	} `json:"servicePlans"`
}

// ListSubscribedSkus returns the licences the tenant holds.
func (c *Client) ListSubscribedSkus(ctx context.Context, graphToken string) ([]SubscribedSku, error) {
	g, err := c.graph()
	if err != nil {
		return nil, err
	}
	ri, err := g.SubscribedSkus().ToGetRequestInformation(ctx, &subscribedskus.SubscribedSkusRequestBuilderGetRequestConfiguration{
		QueryParameters: &subscribedskus.SubscribedSkusRequestBuilderGetQueryParameters{
			Select: []string{"skuPartNumber", "capabilityStatus", "servicePlans"},
		}})
	return graphPaged[SubscribedSku](ctx, c, graphToken, ri, err, maxPages)
}

/* -------------------------------- organization -------------------------------- */

// Organization is the tenant's own directory record.
type Organization struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

// GetOrganization returns the tenant's organization record, for its display
// name (Directory.Read.All, which discovery already holds).
func (c *Client) GetOrganization(ctx context.Context, graphToken string) (Organization, error) {
	ri, err := graphURL(GraphEndpoint + "/v1.0/organization?$select=id,displayName")
	orgs, err := graphPaged[Organization](ctx, c, graphToken, ri, err, 1)
	if err != nil {
		return Organization{}, err
	}
	if len(orgs) == 0 {
		return Organization{}, fmt.Errorf("azure graph: the tenant returned no organization record")
	}
	return orgs[0], nil
}

/* --------------------------------- guardrails --------------------------------- */

// AppManagementRestriction is one credential rule of an app management policy:
// passwordAddition, passwordLifetime, customPasswordAddition,
// symmetricKeyAddition, symmetricKeyLifetime, asymmetricKeyLifetime, ...
type AppManagementRestriction struct {
	RestrictionType                     string     `json:"restrictionType"`
	State                               string     `json:"state,omitempty"`
	MaxLifetime                         *string    `json:"maxLifetime"`
	RestrictForAppsCreatedAfterDateTime *time.Time `json:"restrictForAppsCreatedAfterDateTime"`
}

// AppManagementRestrictions are the password and key rules of one policy.
type AppManagementRestrictions struct {
	PasswordCredentials []AppManagementRestriction `json:"passwordCredentials"`
	KeyCredentials      []AppManagementRestriction `json:"keyCredentials"`
}

// DefaultAppManagementPolicy is the tenant-wide app management policy.
type DefaultAppManagementPolicy struct {
	IsEnabled                    bool                       `json:"isEnabled"`
	ApplicationRestrictions      *AppManagementRestrictions `json:"applicationRestrictions"`
	ServicePrincipalRestrictions *AppManagementRestrictions `json:"servicePrincipalRestrictions"`
}

// AppManagementPolicy is one app management policy applied to chosen apps.
type AppManagementPolicy struct {
	ID           string                     `json:"id"`
	DisplayName  string                     `json:"displayName"`
	IsEnabled    bool                       `json:"isEnabled"`
	Restrictions *AppManagementRestrictions `json:"restrictions"`
}

// GetDefaultAppManagementPolicy reads the tenant-wide policy. Policy.Read.All.
func (c *Client) GetDefaultAppManagementPolicy(ctx context.Context, graphToken string) (*DefaultAppManagementPolicy, error) {
	g, err := c.graph()
	if err != nil {
		return nil, err
	}
	ri, err := g.Policies().DefaultAppManagementPolicy().ToGetRequestInformation(ctx, nil)
	return graphGet[DefaultAppManagementPolicy](ctx, c, graphToken, ri, err)
}

// ListAppManagementPolicies returns the per-app policies. Policy.Read.All.
func (c *Client) ListAppManagementPolicies(ctx context.Context, graphToken string) ([]AppManagementPolicy, error) {
	g, err := c.graph()
	if err != nil {
		return nil, err
	}
	ri, err := g.Policies().AppManagementPolicies().ToGetRequestInformation(ctx, nil)
	return graphPaged[AppManagementPolicy](ctx, c, graphToken, ri, err, maxPages)
}

// ListAppManagementPolicyTargets returns the applications and service
// principals one policy applies to.
func (c *Client) ListAppManagementPolicyTargets(ctx context.Context, graphToken, policyID string) ([]DirectoryObject, error) {
	g, err := c.graph()
	if err != nil {
		return nil, err
	}
	ri, err := g.Policies().AppManagementPolicies().ByAppManagementPolicyId(policyID).AppliesTo().ToGetRequestInformation(ctx,
		&policies.AppManagementPoliciesItemAppliesToRequestBuilderGetRequestConfiguration{
			QueryParameters: &policies.AppManagementPoliciesItemAppliesToRequestBuilderGetQueryParameters{Select: []string{"id"}}})
	return graphPaged[DirectoryObject](ctx, c, graphToken, ri, err, maxPages)
}

// ConditionalAccessPolicy is the part of a Conditional Access policy that says
// whether it targets workload identities (service principals) or agents, from
// where, and with what effect.
type ConditionalAccessPolicy struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	State       string `json:"state"`
	Conditions  struct {
		ClientApplications *struct {
			IncludeServicePrincipals []string `json:"includeServicePrincipals"`
			ExcludeServicePrincipals []string `json:"excludeServicePrincipals"`
			// Agent identities (Microsoft Entra Agent ID), by object id -- an
			// agent identity's or a blueprint principal's, which covers every
			// agent made from that blueprint -- or a keyword for all of them.
			IncludeAgentIDServicePrincipals []string `json:"includeAgentIdServicePrincipals"`
			ExcludeAgentIDServicePrincipals []string `json:"excludeAgentIdServicePrincipals"`
			// AgentIDServicePrincipalFilter selects agents by custom security
			// attributes, which AuthSec does not read.
			AgentIDServicePrincipalFilter *ConditionalAccessFilter `json:"agentIdServicePrincipalFilter"`
		} `json:"clientApplications"`
		Users *struct {
			IncludeUsers []string `json:"includeUsers"`
			ExcludeUsers []string `json:"excludeUsers"`
		} `json:"users"`
		Applications *struct {
			IncludeApplications []string `json:"includeApplications"`
			ExcludeApplications []string `json:"excludeApplications"`
		} `json:"applications"`
		Locations *struct {
			IncludeLocations []string `json:"includeLocations"`
			ExcludeLocations []string `json:"excludeLocations"`
		} `json:"locations"`
		// AgentIDRiskLevels is the agent risk the policy applies at, comma
		// separated ("high", "medium,high").
		AgentIDRiskLevels string `json:"agentIdRiskLevels"`
	} `json:"conditions"`
	GrantControls *struct {
		BuiltInControls []string `json:"builtInControls"`
	} `json:"grantControls"`
}

// ConditionalAccessFilter is a rule over custom security attributes.
type ConditionalAccessFilter struct {
	Mode string `json:"mode"`
	Rule string `json:"rule"`
}

// ListConditionalAccessPolicies returns every Conditional Access policy.
// Policy.Read.All. Beta: the agent conditions exist only there, and the
// policies are otherwise the ones v1.0 returns.
func (c *Client) ListConditionalAccessPolicies(ctx context.Context, graphToken string) ([]ConditionalAccessPolicy, error) {
	ri, err := graphURL(GraphEndpoint + "/beta/identity/conditionalAccess/policies")
	return graphPaged[ConditionalAccessPolicy](ctx, c, graphToken, ri, err, maxPages)
}

/* ------------------------------------ errors ----------------------------------- */

// IsLicenseRequired reports whether err is Graph refusing a read because the
// tenant's Entra licence does not include the data, as opposed to a missing
// permission. Sign-in logs and sign-in activity answer this way on a tenant
// without Entra ID P1/P2.
func IsLicenseRequired(err error) bool {
	if APIStatus(err) != 403 {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "nonpremium") || strings.Contains(msg, "premium license") ||
		strings.Contains(msg, "premium licence")
}
