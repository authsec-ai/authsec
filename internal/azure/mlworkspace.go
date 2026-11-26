package azure

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/machinelearning/armmachinelearning/v4"
)

// Azure Machine Learning workspaces, through armmachinelearning (the official
// Resource Manager SDK), under Reader. Hub-based Foundry -- what Microsoft now
// calls Foundry (classic) -- is built on them: a hub is a workspace of kind
// "Hub", each hub-based project a workspace of kind "Project" naming its hub.
// A classic Machine Learning workspace is kind "Default".

// Machine Learning workspace kinds.
const (
	MLKindHub     = "hub"
	MLKindProject = "project"
)

// MLWorkspace is one Machine Learning workspace: a hub, a hub-based project,
// or a classic workspace.
type MLWorkspace struct {
	ID            string
	Name          string
	Location      string
	ResourceGroup string
	// Kind is lowercased: "hub", "project", "default", "featurestore".
	Kind         string
	FriendlyName string
	// HubResourceID is a project's hub.
	HubResourceID string
	// The resources a hub (or classic workspace) keeps its data and secrets
	// in, by ARM id.
	StorageAccount      string
	KeyVault            string
	ContainerRegistry   string
	ApplicationInsights string
	PublicNetworkAccess string
	// IsolationMode is the managed network's outbound rule: "Disabled",
	// "AllowInternetOutbound" or "AllowOnlyApprovedOutbound".
	IsolationMode string
	Identity      *ManagedIdentityRef
}

// HubBased reports whether the workspace is part of hub-based Foundry.
func (w MLWorkspace) HubBased() bool {
	return w.Kind == MLKindHub || w.Kind == MLKindProject
}

func mlIdentityRef(id *armmachinelearning.ManagedServiceIdentity) *ManagedIdentityRef {
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

// ListMLWorkspaces returns every Machine Learning workspace in the
// subscription.
func (c *Client) ListMLWorkspaces(ctx context.Context, armToken, subscriptionID string) ([]MLWorkspace, error) {
	cl, err := armmachinelearning.NewWorkspacesClient(subscriptionID, staticToken(armToken), c.armOptions())
	if err != nil {
		return nil, err
	}
	return collect(ctx, cl.NewListBySubscriptionPager(nil), maxPages, func(p armmachinelearning.WorkspacesClientListBySubscriptionResponse) []MLWorkspace {
		out := make([]MLWorkspace, 0, len(p.Value))
		for _, w := range p.Value {
			if w == nil || w.ID == nil {
				continue
			}
			ws := MLWorkspace{
				ID: strings.ToLower(*w.ID), Name: str(w.Name), Location: str(w.Location),
				Kind: strings.ToLower(str(w.Kind)), Identity: mlIdentityRef(w.Identity),
			}
			if rid, err := arm.ParseResourceID(*w.ID); err == nil {
				ws.ResourceGroup = rid.ResourceGroupName
			}
			if pr := w.Properties; pr != nil {
				ws.FriendlyName = str(pr.FriendlyName)
				ws.HubResourceID = strings.ToLower(str(pr.HubResourceID))
				ws.StorageAccount = strings.ToLower(str(pr.StorageAccount))
				ws.KeyVault = strings.ToLower(str(pr.KeyVault))
				ws.ContainerRegistry = strings.ToLower(str(pr.ContainerRegistry))
				ws.ApplicationInsights = strings.ToLower(str(pr.ApplicationInsights))
				if pr.PublicNetworkAccess != nil {
					ws.PublicNetworkAccess = string(*pr.PublicNetworkAccess)
				}
				if pr.ManagedNetwork != nil && pr.ManagedNetwork.IsolationMode != nil {
					ws.IsolationMode = string(*pr.ManagedNetwork.IsolationMode)
				}
			}
			out = append(out, ws)
		}
		return out
	})
}

// ListMLWorkspaceConnections returns one workspace's connections: what a hub
// or project reaches and how it authenticates, read through each connection's
// base properties only -- never its credentials, nor the legacy Value field.
func (c *Client) ListMLWorkspaceConnections(ctx context.Context, armToken, subscriptionID, resourceGroup, workspace string) ([]FoundryConnection, error) {
	cl, err := armmachinelearning.NewWorkspaceConnectionsClient(subscriptionID, staticToken(armToken), c.armOptions())
	if err != nil {
		return nil, err
	}
	return collect(ctx, cl.NewListPager(resourceGroup, workspace, nil), maxPages, func(p armmachinelearning.WorkspaceConnectionsClientListResponse) []FoundryConnection {
		out := make([]FoundryConnection, 0, len(p.Value))
		for _, r := range p.Value {
			if r == nil || r.Properties == nil {
				continue
			}
			base := r.Properties.GetWorkspaceConnectionPropertiesV2()
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
			for k, v := range base.Metadata {
				if strings.EqualFold(k, "ResourceId") && v != nil {
					fc.TargetResourceID = strings.ToLower(*v)
				}
			}
			out = append(out, fc)
		}
		return out
	})
}
