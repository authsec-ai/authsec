package azure

import (
	"context"
	"strings"
	"time"

	armfoundry "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cognitiveservices/armcognitiveservices/v4"
)

// Foundry agents that Azure Resource Manager lists: a published agent is an
// Agent Application under its project (accounts/projects/applications), with
// its own Entra agent identity blueprint and agent identity, and the
// deployments that run its agent versions (applications/agentDeployments).
// Read with AuthSec's app-only ARM token under Reader, through the official
// armcognitiveservices/v4 preview SDK -- the stable v2 has no client for them.
// Lists only: never the listAgents action, nor anything that starts, stops or
// invokes an agent.
//
// An unpublished agent and an agent of Foundry's newer agent model are
// data-plane objects ARM does not list; their identities are Entra agent
// identities, found by the tenant pass, whose blueprint trusts the project's
// managed identity.

// AgentIdentityRef is one Entra identity an Agent Application names.
type AgentIdentityRef struct {
	PrincipalID string
	ClientID    string
	// Kind is Microsoft's: AgentBlueprint, AgentInstance, AgenticUser, Managed.
	Kind string
}

// FoundryAgentApplication is one published agent of a Foundry project.
type FoundryAgentApplication struct {
	ID          string
	Name        string
	DisplayName string
	Description string
	// Enabled is nil when the application does not say.
	Enabled           *bool
	ProvisioningState string
	BaseURL           string
	// Authorization is how callers are authorized: Default (Azure RBAC),
	// OrganizationScope, Channels (Microsoft 365 and Teams), Custom.
	Authorization string
	// Agents are the names of the agents the application exposes.
	Agents        []string
	Blueprint     *AgentIdentityRef
	AgentIdentity *AgentIdentityRef
	CreatedBy     string
	CreatedAt     *time.Time
	ModifiedAt    *time.Time
}

// FoundryAgentVersion is one agent version a deployment runs.
type FoundryAgentVersion struct {
	Name    string
	Version string
}

// FoundryAgentDeployment is one deployment of an Agent Application.
type FoundryAgentDeployment struct {
	Name        string
	DisplayName string
	// Type is Managed (a prompt agent) or Hosted (a container).
	Type              string
	State             string
	ProvisioningState string
	Agents            []FoundryAgentVersion
	Protocols         []string
}

// AgentApplicationsUnavailable reports whether a list of Agent Applications
// failed because the API is not offered for the account (its region, or a
// subscription the preview API version has not reached), not because the read
// went wrong: there is nothing to read there.
func AgentApplicationsUnavailable(err error) bool {
	switch APIStatus(err) {
	case 404:
		return true
	case 400:
		return IsAPICode(err, "InvalidApiVersionParameter") || IsAPICode(err, "NoRegisteredProviderFound") ||
			IsAPICode(err, "InvalidResourceType")
	}
	return false
}

func agentIdentityRefFrom(a *armfoundry.AssignedIdentity) *AgentIdentityRef {
	if a == nil || a.PrincipalID == nil {
		return nil
	}
	ref := &AgentIdentityRef{PrincipalID: strings.ToLower(*a.PrincipalID), ClientID: strings.ToLower(str(a.ClientID))}
	if a.Kind != nil {
		ref.Kind = string(*a.Kind)
	}
	return ref
}

// childName is a child resource's own name: ARM returns "<parent>/<child>".
func childName(n string) string {
	if i := strings.LastIndex(n, "/"); i >= 0 {
		return n[i+1:]
	}
	return n
}

// ListFoundryAgentApplications returns the published agents of one Foundry
// project.
func (c *Client) ListFoundryAgentApplications(ctx context.Context, armToken, subscriptionID, resourceGroup, account, project string) ([]FoundryAgentApplication, error) {
	cl, err := armfoundry.NewAgentApplicationsClient(subscriptionID, staticToken(armToken), c.armOptions())
	if err != nil {
		return nil, err
	}
	return collect(ctx, cl.NewListPager(resourceGroup, account, project, nil), maxPages, func(p armfoundry.AgentApplicationsClientListResponse) []FoundryAgentApplication {
		out := make([]FoundryAgentApplication, 0, len(p.Value))
		for _, a := range p.Value {
			if a == nil || a.ID == nil {
				continue
			}
			app := FoundryAgentApplication{ID: strings.ToLower(*a.ID), Name: childName(str(a.Name))}
			if sd := a.SystemData; sd != nil {
				app.CreatedBy, app.CreatedAt, app.ModifiedAt = str(sd.CreatedBy), sd.CreatedAt, sd.LastModifiedAt
			}
			if pr := a.Properties; pr != nil {
				app.DisplayName, app.Description, app.BaseURL = str(pr.DisplayName), str(pr.Description), str(pr.BaseURL)
				app.Enabled = pr.IsEnabled
				if pr.ProvisioningState != nil {
					app.ProvisioningState = string(*pr.ProvisioningState)
				}
				if pol := pr.AuthorizationPolicy; pol != nil {
					if t := pol.GetApplicationAuthorizationPolicy().Type; t != nil {
						app.Authorization = string(*t)
					}
				}
				for _, ag := range pr.Agents {
					if ag != nil && ag.AgentName != nil {
						app.Agents = append(app.Agents, *ag.AgentName)
					}
				}
				app.Blueprint = agentIdentityRefFrom(pr.AgentIdentityBlueprint)
				app.AgentIdentity = agentIdentityRefFrom(pr.DefaultInstanceIdentity)
			}
			out = append(out, app)
		}
		return out
	})
}

// ListFoundryAgentDeployments returns the deployments of one Agent
// Application.
func (c *Client) ListFoundryAgentDeployments(ctx context.Context, armToken, subscriptionID, resourceGroup, account, project, application string) ([]FoundryAgentDeployment, error) {
	cl, err := armfoundry.NewAgentDeploymentsClient(subscriptionID, staticToken(armToken), c.armOptions())
	if err != nil {
		return nil, err
	}
	return collect(ctx, cl.NewListPager(resourceGroup, account, project, application, nil), maxPages, func(p armfoundry.AgentDeploymentsClientListResponse) []FoundryAgentDeployment {
		out := make([]FoundryAgentDeployment, 0, len(p.Value))
		for _, d := range p.Value {
			if d == nil {
				continue
			}
			fd := FoundryAgentDeployment{Name: childName(str(d.Name))}
			if d.Properties != nil {
				pr := d.Properties.GetAgentDeploymentProperties()
				fd.DisplayName = str(pr.DisplayName)
				if pr.DeploymentType != nil {
					fd.Type = string(*pr.DeploymentType)
				}
				if pr.State != nil {
					fd.State = string(*pr.State)
				}
				if pr.ProvisioningState != nil {
					fd.ProvisioningState = string(*pr.ProvisioningState)
				}
				for _, ag := range pr.Agents {
					if ag != nil && ag.AgentName != nil {
						fd.Agents = append(fd.Agents, FoundryAgentVersion{Name: *ag.AgentName, Version: str(ag.AgentVersion)})
					}
				}
				for _, pv := range pr.Protocols {
					if pv != nil && pv.Protocol != nil {
						fd.Protocols = append(fd.Protocols, strings.TrimSpace(string(*pv.Protocol)+" "+str(pv.Version)))
					}
				}
			}
			out = append(out, fd)
		}
		return out
	})
}
