package azure

import (
	"context"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/microsoftgraph/msgraph-sdk-go/applications"
	"github.com/microsoftgraph/msgraph-sdk-go/groups"
	"github.com/microsoftgraph/msgraph-sdk-go/rolemanagement"
	"github.com/microsoftgraph/msgraph-sdk-go/serviceprincipals"
	"github.com/microsoftgraph/msgraph-sdk-go/users"
)

// Directory listings read by identity discovery, all with AuthSec's app-only
// Graph token. Each selects only the properties AuthSec stores.

// Credential is the METADATA of an application or service principal secret or
// certificate. There is deliberately no field for the value: Graph never
// returns a secret's value after creation, and the `hint` (the first
// characters of a client secret) and `key` (certificate bytes) properties it
// does return are left undeclared, so JSON decoding drops them.
type Credential struct {
	KeyID         string     `json:"keyId"`
	DisplayName   string     `json:"displayName"`
	StartDateTime *time.Time `json:"startDateTime"`
	EndDateTime   *time.Time `json:"endDateTime"`
	// Type and Usage are set on certificates only ("AsymmetricX509Cert", "Verify").
	Type  string `json:"type"`
	Usage string `json:"usage"`
}

// GraphUser is one directory user.
type GraphUser struct {
	ID                string     `json:"id"`
	DisplayName       string     `json:"displayName"`
	UserPrincipalName string     `json:"userPrincipalName"`
	Mail              string     `json:"mail"`
	UserType          string     `json:"userType"`
	AccountEnabled    *bool      `json:"accountEnabled"`
	CreatedDateTime   *time.Time `json:"createdDateTime"`
	ExternalUserState string     `json:"externalUserState"`
	// ODataType is set when the object is a subtype ("#microsoft.graph.agentUser").
	ODataType string `json:"@odata.type,omitempty"`
}

// GraphGroup is one directory group.
type GraphGroup struct {
	ID                 string     `json:"id"`
	DisplayName        string     `json:"displayName"`
	Description        string     `json:"description"`
	SecurityEnabled    bool       `json:"securityEnabled"`
	MailEnabled        bool       `json:"mailEnabled"`
	GroupTypes         []string   `json:"groupTypes"`
	IsAssignableToRole *bool      `json:"isAssignableToRole"`
	CreatedDateTime    *time.Time `json:"createdDateTime"`
}

// GraphApplication is one app registration owned by the tenant.
type GraphApplication struct {
	ID                  string       `json:"id"`
	AppID               string       `json:"appId"`
	DisplayName         string       `json:"displayName"`
	SignInAudience      string       `json:"signInAudience"`
	CreatedDateTime     *time.Time   `json:"createdDateTime"`
	PasswordCredentials []Credential `json:"passwordCredentials"`
	KeyCredentials      []Credential `json:"keyCredentials"`
	// ODataType is set when the object is a subtype
	// ("#microsoft.graph.agentIdentityBlueprint").
	ODataType string `json:"@odata.type,omitempty"`
}

// DirectoryRoleAssignment is one active Microsoft Entra role assignment
// (unifiedRoleAssignment). DirectoryScopeID is "/" for the whole tenant, or
// "/administrativeUnits/{id}" or "/{objectId}" (one application or service
// principal) for a scoped one. AppScopeID is not read (not selectable on the
// directory provider) and stays empty.
type DirectoryRoleAssignment struct {
	ID               string `json:"id"`
	PrincipalID      string `json:"principalId"`
	RoleDefinitionID string `json:"roleDefinitionId"`
	DirectoryScopeID string `json:"directoryScopeId"`
	AppScopeID       string `json:"appScopeId"`
}

// DirectoryRoleDefinition is one Microsoft Entra role (unifiedRoleDefinition),
// built-in or custom, with what it allows.
type DirectoryRoleDefinition struct {
	ID              string `json:"id"`
	DisplayName     string `json:"displayName"`
	TemplateID      string `json:"templateId"`
	IsBuiltIn       bool   `json:"isBuiltIn"`
	IsEnabled       *bool  `json:"isEnabled"`
	RolePermissions []struct {
		AllowedResourceActions []string `json:"allowedResourceActions"`
	} `json:"rolePermissions"`
}

// DirectoryObject is a member reference: its id and its type
// ("#microsoft.graph.user", "#microsoft.graph.group", ...).
type DirectoryObject struct {
	ODataType string `json:"@odata.type"`
	ID        string `json:"id"`
}

// ListUsers returns every user in the directory.
func (c *Client) ListUsers(ctx context.Context, graphToken string) ([]GraphUser, error) {
	g, err := c.graph()
	if err != nil {
		return nil, err
	}
	ri, err := g.Users().ToGetRequestInformation(ctx, &users.UsersRequestBuilderGetRequestConfiguration{
		QueryParameters: &users.UsersRequestBuilderGetQueryParameters{
			Select: []string{"id", "displayName", "userPrincipalName", "mail", "userType", "accountEnabled", "createdDateTime", "externalUserState"},
			Top:    to.Ptr(int32(graphPageSize)),
		}})
	return graphPaged[GraphUser](ctx, c, graphToken, ri, err, maxPages)
}

// ListGroups returns every group in the directory.
func (c *Client) ListGroups(ctx context.Context, graphToken string) ([]GraphGroup, error) {
	g, err := c.graph()
	if err != nil {
		return nil, err
	}
	ri, err := g.Groups().ToGetRequestInformation(ctx, &groups.GroupsRequestBuilderGetRequestConfiguration{
		QueryParameters: &groups.GroupsRequestBuilderGetQueryParameters{
			Select: []string{"id", "displayName", "description", "securityEnabled", "mailEnabled", "groupTypes", "isAssignableToRole", "createdDateTime"},
			Top:    to.Ptr(int32(graphPageSize)),
		}})
	return graphPaged[GraphGroup](ctx, c, graphToken, ri, err, maxPages)
}

// ListGroupMembers returns a group's DIRECT members.
func (c *Client) ListGroupMembers(ctx context.Context, graphToken, groupID string) ([]DirectoryObject, error) {
	g, err := c.graph()
	if err != nil {
		return nil, err
	}
	ri, err := g.Groups().ByGroupId(groupID).Members().ToGetRequestInformation(ctx, &groups.ItemMembersRequestBuilderGetRequestConfiguration{
		QueryParameters: &groups.ItemMembersRequestBuilderGetQueryParameters{
			Select: []string{"id"},
			Top:    to.Ptr(int32(graphPageSize)),
		}})
	return graphPaged[DirectoryObject](ctx, c, graphToken, ri, err, maxPages)
}

// ListApplications returns every app registration the tenant owns.
func (c *Client) ListApplications(ctx context.Context, graphToken string) ([]GraphApplication, error) {
	g, err := c.graph()
	if err != nil {
		return nil, err
	}
	ri, err := g.Applications().ToGetRequestInformation(ctx, &applications.ApplicationsRequestBuilderGetRequestConfiguration{
		QueryParameters: &applications.ApplicationsRequestBuilderGetQueryParameters{
			Select: []string{"id", "appId", "displayName", "signInAudience", "createdDateTime", "passwordCredentials", "keyCredentials"},
			Top:    to.Ptr(int32(graphPageSize)),
		}})
	return graphPaged[GraphApplication](ctx, c, graphToken, ri, err, maxPages)
}

// ListServicePrincipals returns every service principal in the tenant:
// enterprise applications, Microsoft first-party apps and managed identities.
func (c *Client) ListServicePrincipals(ctx context.Context, graphToken string) ([]ServicePrincipal, error) {
	return c.listServicePrincipals(ctx, graphToken, graphPageSize,
		"id", "appId", "displayName", "servicePrincipalType", "accountEnabled", "appOwnerOrganizationId", "alternativeNames", "passwordCredentials", "keyCredentials")
}

// appRolesPageSize keeps one page of service principals WITH their app roles
// small: Microsoft's first-party APIs define hundreds of roles each, and a
// 999-row page of them took Graph past the request timeout (seen live).
const appRolesPageSize = 100

// ListServicePrincipalAppRoles returns every service principal's id and the
// app roles (application permissions) it defines, so an app role assignment's
// appRoleId resolves to the permission's name ("Mail.Read").
func (c *Client) ListServicePrincipalAppRoles(ctx context.Context, graphToken string) ([]ServicePrincipal, error) {
	return c.listServicePrincipals(ctx, graphToken, appRolesPageSize, "id", "displayName", "appId", "appRoles")
}

func (c *Client) listServicePrincipals(ctx context.Context, graphToken string, top int32, sel ...string) ([]ServicePrincipal, error) {
	g, err := c.graph()
	if err != nil {
		return nil, err
	}
	ri, err := g.ServicePrincipals().ToGetRequestInformation(ctx, &serviceprincipals.ServicePrincipalsRequestBuilderGetRequestConfiguration{
		QueryParameters: &serviceprincipals.ServicePrincipalsRequestBuilderGetQueryParameters{Select: sel, Top: &top}})
	return graphPaged[ServicePrincipal](ctx, c, graphToken, ri, err, maxPages)
}

// ListDirectoryRoleAssignments returns every active Microsoft Entra role
// assignment: built-in and custom roles, tenant-wide and scoped. Read with
// Directory.Read.All (RoleManagement.Read.Directory is the least-privileged
// alternative). PIM-eligible assignments are not assignments until activated
// and are not listed here.
func (c *Client) ListDirectoryRoleAssignments(ctx context.Context, graphToken string) ([]DirectoryRoleAssignment, error) {
	g, err := c.graph()
	if err != nil {
		return nil, err
	}
	ri, err := g.RoleManagement().Directory().RoleAssignments().ToGetRequestInformation(ctx, &rolemanagement.DirectoryRoleAssignmentsRequestBuilderGetRequestConfiguration{
		QueryParameters: &rolemanagement.DirectoryRoleAssignmentsRequestBuilderGetQueryParameters{
			// appScopeId is not selectable on the directory provider's
			// assignments (Graph answers 400); an assignment scoped to one
			// application or service principal names it in directoryScopeId.
			Select: []string{"id", "principalId", "roleDefinitionId", "directoryScopeId"},
		}})
	return graphPaged[DirectoryRoleAssignment](ctx, c, graphToken, ri, err, maxPages)
}

// ListDirectoryRoleDefinitions returns every Microsoft Entra role definition,
// built-in and custom, with its allowed resource actions.
func (c *Client) ListDirectoryRoleDefinitions(ctx context.Context, graphToken string) ([]DirectoryRoleDefinition, error) {
	g, err := c.graph()
	if err != nil {
		return nil, err
	}
	ri, err := g.RoleManagement().Directory().RoleDefinitions().ToGetRequestInformation(ctx, &rolemanagement.DirectoryRoleDefinitionsRequestBuilderGetRequestConfiguration{
		QueryParameters: &rolemanagement.DirectoryRoleDefinitionsRequestBuilderGetQueryParameters{
			Select: []string{"id", "displayName", "templateId", "isBuiltIn", "isEnabled", "rolePermissions"},
		}})
	return graphPaged[DirectoryRoleDefinition](ctx, c, graphToken, ri, err, maxPages)
}
