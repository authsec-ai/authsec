package azure

import (
	"context"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cognitiveservices/armcognitiveservices/v2"
)

// Microsoft Foundry (Azure AI Foundry) and the other Cognitive Services
// accounts, read through armcognitiveservices with AuthSec's app-only ARM
// token under Reader. Management plane only: what an account is, which models
// it serves, which projects it holds, and what each connection points at and
// how it authenticates. The agents themselves live in Foundry's data plane,
// which Reader does not reach and AuthSec does not read.
//
// A connection's credentials sit only in its auth-type subclass; this file
// reads the shared base properties (GetConnectionPropertiesV2), so no secret,
// key or token can be copied out of a response.

// ManagedIdentityRef is who a resource runs as: its system-assigned identity
// and the user-assigned identities attached to it, by their ARM ids.
type ManagedIdentityRef struct {
	PrincipalID  string
	UserAssigned map[string]UserAssignedRef
}

// UserAssignedRef is one user-assigned identity attached to a resource.
type UserAssignedRef struct {
	PrincipalID string
	ClientID    string
}

func identityRefFrom(id *armcognitiveservices.Identity) *ManagedIdentityRef {
	if id == nil {
		return nil
	}
	out := &ManagedIdentityRef{PrincipalID: strings.ToLower(str(id.PrincipalID))}
	for rid, u := range id.UserAssignedIdentities {
		if out.UserAssigned == nil {
			out.UserAssigned = map[string]UserAssignedRef{}
		}
		ref := UserAssignedRef{}
		if u != nil {
			ref = UserAssignedRef{PrincipalID: strings.ToLower(str(u.PrincipalID)), ClientID: strings.ToLower(str(u.ClientID))}
		}
		out.UserAssigned[strings.ToLower(rid)] = ref
	}
	if out.PrincipalID == "" && len(out.UserAssigned) == 0 {
		return nil
	}
	return out
}

// CognitiveAccount is one Cognitive Services account: a Foundry resource
// (kind AIServices with project management), an Azure OpenAI resource, or a
// single-service account (Speech, Vision, ...).
type CognitiveAccount struct {
	ID            string
	Name          string
	Kind          string
	Location      string
	ResourceGroup string
	SKU           string
	Identity      *ManagedIdentityRef
	// Foundry is allowProjectManagement: the account holds Foundry projects.
	Foundry bool
	// LocalAuthEnabled is whether API keys are accepted next to Entra tokens.
	// Nil when the account does not say.
	LocalAuthEnabled     *bool
	PublicNetworkAccess  string
	NetworkDefaultAction string
	RestrictOutbound     bool
	Endpoint             string
}

// ServesModels reports whether the account kind deploys models.
func (a CognitiveAccount) ServesModels() bool {
	return strings.EqualFold(a.Kind, "AIServices") || strings.EqualFold(a.Kind, "OpenAI")
}

// ListCognitiveAccounts returns every Cognitive Services account in the
// subscription.
func (c *Client) ListCognitiveAccounts(ctx context.Context, armToken, subscriptionID string) ([]CognitiveAccount, error) {
	cl, err := armcognitiveservices.NewAccountsClient(subscriptionID, staticToken(armToken), c.armOptions())
	if err != nil {
		return nil, err
	}
	return collect(ctx, cl.NewListPager(nil), maxPages, func(p armcognitiveservices.AccountsClientListResponse) []CognitiveAccount {
		out := make([]CognitiveAccount, 0, len(p.Value))
		for _, a := range p.Value {
			if a == nil || a.ID == nil {
				continue
			}
			acc := CognitiveAccount{
				ID: strings.ToLower(*a.ID), Name: str(a.Name), Kind: str(a.Kind), Location: str(a.Location),
				Identity: identityRefFrom(a.Identity),
			}
			if rid, err := arm.ParseResourceID(*a.ID); err == nil {
				acc.ResourceGroup = rid.ResourceGroupName
			}
			if a.SKU != nil {
				acc.SKU = str(a.SKU.Name)
			}
			if p := a.Properties; p != nil {
				acc.Foundry = p.AllowProjectManagement != nil && *p.AllowProjectManagement
				if p.DisableLocalAuth != nil {
					enabled := !*p.DisableLocalAuth
					acc.LocalAuthEnabled = &enabled
				}
				if p.PublicNetworkAccess != nil {
					acc.PublicNetworkAccess = string(*p.PublicNetworkAccess)
				}
				if p.NetworkACLs != nil && p.NetworkACLs.DefaultAction != nil {
					acc.NetworkDefaultAction = string(*p.NetworkACLs.DefaultAction)
				}
				acc.RestrictOutbound = p.RestrictOutboundNetworkAccess != nil && *p.RestrictOutboundNetworkAccess
				acc.Endpoint = str(p.Endpoint)
			}
			out = append(out, acc)
		}
		return out
	})
}

// FoundryDeployment is one model deployment on an account.
type FoundryDeployment struct {
	Name           string
	Model          string
	ModelVersion   string
	ModelFormat    string
	ModelPublisher string
	SKU            string
	Capacity       int32
	// ContentFilter is the deployment's responsible-AI policy name.
	ContentFilter     string
	VersionUpgrade    string
	ProvisioningState string
}

// ListFoundryDeployments returns the model deployments of one account.
func (c *Client) ListFoundryDeployments(ctx context.Context, armToken, subscriptionID, resourceGroup, account string) ([]FoundryDeployment, error) {
	cl, err := armcognitiveservices.NewDeploymentsClient(subscriptionID, staticToken(armToken), c.armOptions())
	if err != nil {
		return nil, err
	}
	return collect(ctx, cl.NewListPager(resourceGroup, account, nil), maxPages, func(p armcognitiveservices.DeploymentsClientListResponse) []FoundryDeployment {
		out := make([]FoundryDeployment, 0, len(p.Value))
		for _, d := range p.Value {
			if d == nil {
				continue
			}
			fd := FoundryDeployment{Name: str(d.Name)}
			if d.SKU != nil {
				fd.SKU = str(d.SKU.Name)
				if d.SKU.Capacity != nil {
					fd.Capacity = *d.SKU.Capacity
				}
			}
			if pr := d.Properties; pr != nil {
				if m := pr.Model; m != nil {
					fd.Model, fd.ModelVersion, fd.ModelFormat, fd.ModelPublisher = str(m.Name), str(m.Version), str(m.Format), str(m.Publisher)
				}
				fd.ContentFilter = str(pr.RaiPolicyName)
				if pr.VersionUpgradeOption != nil {
					fd.VersionUpgrade = string(*pr.VersionUpgradeOption)
				}
				if pr.ProvisioningState != nil {
					fd.ProvisioningState = string(*pr.ProvisioningState)
				}
			}
			out = append(out, fd)
		}
		return out
	})
}

// FoundryProject is one Foundry project under an account.
type FoundryProject struct {
	ID          string
	Name        string
	Location    string
	DisplayName string
	IsDefault   bool
	Identity    *ManagedIdentityRef
}

// ListFoundryProjects returns the projects of one Foundry account.
func (c *Client) ListFoundryProjects(ctx context.Context, armToken, subscriptionID, resourceGroup, account string) ([]FoundryProject, error) {
	cl, err := armcognitiveservices.NewProjectsClient(subscriptionID, staticToken(armToken), c.armOptions())
	if err != nil {
		return nil, err
	}
	return collect(ctx, cl.NewListPager(resourceGroup, account, nil), maxPages, func(p armcognitiveservices.ProjectsClientListResponse) []FoundryProject {
		out := make([]FoundryProject, 0, len(p.Value))
		for _, pr := range p.Value {
			if pr == nil || pr.ID == nil {
				continue
			}
			fp := FoundryProject{ID: strings.ToLower(*pr.ID), Location: str(pr.Location), Identity: identityRefFrom(pr.Identity)}
			// A child resource's name comes back as "<account>/<project>".
			fp.Name = str(pr.Name)
			if i := strings.LastIndex(fp.Name, "/"); i >= 0 {
				fp.Name = fp.Name[i+1:]
			}
			if props := pr.Properties; props != nil {
				fp.DisplayName = str(props.DisplayName)
				fp.IsDefault = props.IsDefault != nil && *props.IsDefault
			}
			out = append(out, fp)
		}
		return out
	})
}

// FoundryConnection is one connection of an account or project: a target an
// agent or tool reaches, and how it authenticates. Never its credentials.
type FoundryConnection struct {
	Name     string
	Category string
	AuthType string
	Target   string
	// TargetResourceID is the ARM id of the target, when the connection
	// records one (metadata ResourceId).
	TargetResourceID string
	SharedToAll      bool
	ExpiresAt        *time.Time
	// UsesProjectIdentity is useWorkspaceManagedIdentity: the connection
	// authenticates as the project's own managed identity.
	UsesProjectIdentity bool
}

// SecretBased reports whether the connection's auth type stores a secret in
// Foundry (a key, a password, a token, a SAS) rather than using an identity.
func (f FoundryConnection) SecretBased() bool {
	switch strings.ToLower(f.AuthType) {
	case "apikey", "accesskey", "accountkey", "customkeys", "pat", "sas", "serviceprincipal", "usernamepassword", "oauth2":
		return true
	}
	return false
}

func connectionsFrom(v []*armcognitiveservices.ConnectionPropertiesV2BasicResource) []FoundryConnection {
	out := make([]FoundryConnection, 0, len(v))
	for _, r := range v {
		if r == nil || r.Properties == nil {
			continue
		}
		base := r.Properties.GetConnectionPropertiesV2()
		if base == nil {
			continue
		}
		fc := FoundryConnection{Name: str(r.Name), Target: str(base.Target), ExpiresAt: base.ExpiryTime}
		if i := strings.LastIndex(fc.Name, "/"); i >= 0 {
			fc.Name = fc.Name[i+1:]
		}
		if base.Category != nil {
			fc.Category = string(*base.Category)
		}
		if base.AuthType != nil {
			fc.AuthType = string(*base.AuthType)
		}
		fc.SharedToAll = base.IsSharedToAll != nil && *base.IsSharedToAll
		fc.UsesProjectIdentity = base.UseWorkspaceManagedIdentity != nil && *base.UseWorkspaceManagedIdentity
		for k, v := range base.Metadata {
			if strings.EqualFold(k, "ResourceId") && v != nil {
				fc.TargetResourceID = strings.ToLower(*v)
			}
		}
		out = append(out, fc)
	}
	return out
}

// ListFoundryAccountConnections returns the connections of one account,
// shared with its projects.
func (c *Client) ListFoundryAccountConnections(ctx context.Context, armToken, subscriptionID, resourceGroup, account string) ([]FoundryConnection, error) {
	cl, err := armcognitiveservices.NewAccountConnectionsClient(subscriptionID, staticToken(armToken), c.armOptions())
	if err != nil {
		return nil, err
	}
	return collect(ctx, cl.NewListPager(resourceGroup, account, nil), maxPages, func(p armcognitiveservices.AccountConnectionsClientListResponse) []FoundryConnection {
		return connectionsFrom(p.Value)
	})
}

// ListFoundryProjectConnections returns the connections of one project.
func (c *Client) ListFoundryProjectConnections(ctx context.Context, armToken, subscriptionID, resourceGroup, account, project string) ([]FoundryConnection, error) {
	cl, err := armcognitiveservices.NewProjectConnectionsClient(subscriptionID, staticToken(armToken), c.armOptions())
	if err != nil {
		return nil, err
	}
	return collect(ctx, cl.NewListPager(resourceGroup, account, project, nil), maxPages, func(p armcognitiveservices.ProjectConnectionsClientListResponse) []FoundryConnection {
		return connectionsFrom(p.Value)
	})
}
