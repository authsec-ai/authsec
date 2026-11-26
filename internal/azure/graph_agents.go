package azure

import (
	"context"
	"time"
)

// Microsoft Entra Agent ID: agents as directory objects of their own.
//
//	blueprint            an application: the template agents are created from.
//	                     It HOLDS the credentials (secrets, certificates,
//	                     federated credentials); agents have none of their own.
//	blueprint principal  the blueprint's service principal in a tenant. What
//	                     it is granted, its agents may inherit.
//	agent identity       a service principal (servicePrincipalType
//	                     "ServiceIdentity") created from a blueprint. The
//	                     blueprint's credentials obtain its tokens.
//	agent user           an optional user account an agent acts as, linked to
//	                     its agent identity by identityParentId.
//
// Each listing is a type cast of the base collection, so it returns that type
// only. All read-only. The agent identity and blueprint listings need their
// own permissions (AgentIdentity.Read.All, AgentIdentityBlueprint.Read.All,
// AgentIdentityBlueprintPrincipal.Read.All); agent users are users and read
// with Directory.Read.All, on beta only.

// agentPageSize is the documented maximum page of the agent listings.
const agentPageSize = "100"

// AgentIdentity is one agent's own identity.
type AgentIdentity struct {
	ID             string `json:"id"`
	DisplayName    string `json:"displayName"`
	AccountEnabled *bool  `json:"accountEnabled"`
	// AgentIdentityBlueprintID is the blueprint's appId, not its object id.
	AgentIdentityBlueprintID  string     `json:"agentIdentityBlueprintId"`
	CreatedByAppID            string     `json:"createdByAppId"`
	CreatedDateTime           *time.Time `json:"createdDateTime"`
	DisabledByMicrosoftStatus string     `json:"disabledByMicrosoftStatus"`
	ServicePrincipalType      string     `json:"servicePrincipalType"`
	Tags                      []string   `json:"tags"`
}

// AgentBlueprint is one agent identity blueprint: an application.
type AgentBlueprint struct {
	ID                        string       `json:"id"`
	AppID                     string       `json:"appId"`
	DisplayName               string       `json:"displayName"`
	SignInAudience            string       `json:"signInAudience"`
	PublisherDomain           string       `json:"publisherDomain"`
	CreatedByAppID            string       `json:"createdByAppId"`
	CreatedDateTime           *time.Time   `json:"createdDateTime"`
	DisabledByMicrosoftStatus string       `json:"disabledByMicrosoftStatus"`
	Tags                      []string     `json:"tags"`
	PasswordCredentials       []Credential `json:"passwordCredentials"`
	KeyCredentials            []Credential `json:"keyCredentials"`
}

// AgentBlueprintPrincipal is a blueprint's service principal in the tenant.
type AgentBlueprintPrincipal struct {
	ID                     string   `json:"id"`
	AppID                  string   `json:"appId"`
	DisplayName            string   `json:"displayName"`
	AccountEnabled         *bool    `json:"accountEnabled"`
	AppOwnerOrganizationID string   `json:"appOwnerOrganizationId"`
	ServicePrincipalType   string   `json:"servicePrincipalType"`
	Tags                   []string `json:"tags"`
}

// AgentUser is the user account an agent acts as.
type AgentUser struct {
	ID                string     `json:"id"`
	DisplayName       string     `json:"displayName"`
	UserPrincipalName string     `json:"userPrincipalName"`
	Mail              string     `json:"mail"`
	AccountEnabled    *bool      `json:"accountEnabled"`
	CreatedDateTime   *time.Time `json:"createdDateTime"`
	// IdentityParentID is the object id of the agent identity it belongs to.
	IdentityParentID string `json:"identityParentId"`
}

// ListAgentIdentities returns every agent identity in the tenant.
func (c *Client) ListAgentIdentities(ctx context.Context, graphToken string) ([]AgentIdentity, error) {
	ri, err := graphList("/v1.0/servicePrincipals/microsoft.graph.agentIdentity",
		"id,displayName,accountEnabled,agentIdentityBlueprintId,createdByAppId,createdDateTime,disabledByMicrosoftStatus,servicePrincipalType,tags", agentPageSize)
	return graphPaged[AgentIdentity](ctx, c, graphToken, ri, err, maxPages)
}

// ListAgentBlueprints returns every agent identity blueprint the tenant owns,
// with the METADATA of its secrets and certificates (never a value).
func (c *Client) ListAgentBlueprints(ctx context.Context, graphToken string) ([]AgentBlueprint, error) {
	ri, err := graphList("/v1.0/applications/microsoft.graph.agentIdentityBlueprint",
		"id,appId,displayName,signInAudience,publisherDomain,createdByAppId,createdDateTime,disabledByMicrosoftStatus,tags,passwordCredentials,keyCredentials", agentPageSize)
	return graphPaged[AgentBlueprint](ctx, c, graphToken, ri, err, maxPages)
}

// ListAgentBlueprintPrincipals returns every blueprint's service principal in
// the tenant, including those of blueprints another tenant owns.
func (c *Client) ListAgentBlueprintPrincipals(ctx context.Context, graphToken string) ([]AgentBlueprintPrincipal, error) {
	ri, err := graphList("/v1.0/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal",
		"id,appId,displayName,accountEnabled,appOwnerOrganizationId,servicePrincipalType,tags", agentPageSize)
	return graphPaged[AgentBlueprintPrincipal](ctx, c, graphToken, ri, err, maxPages)
}

// ListAgentUsers returns every agent user. Beta only.
func (c *Client) ListAgentUsers(ctx context.Context, graphToken string) ([]AgentUser, error) {
	ri, err := graphList("/beta/users/microsoft.graph.agentUser",
		"id,displayName,userPrincipalName,mail,accountEnabled,createdDateTime,identityParentId", agentPageSize)
	return graphPaged[AgentUser](ctx, c, graphToken, ri, err, maxPages)
}
