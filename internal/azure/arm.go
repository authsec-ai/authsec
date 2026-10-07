package azure

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
)

// Azure Resource Manager, through the Azure SDK. Every method keeps the
// signature and return types it had over plain REST, and every failure is an
// *APIError (armError), so callers did not change.

// Subscription is one Azure subscription.
type Subscription struct {
	SubscriptionID string `json:"subscriptionId"`
	DisplayName    string `json:"displayName"`
	State          string `json:"state"`
	TenantID       string `json:"tenantId"`
}

func subscriptionFrom(s *armsubscriptions.Subscription) Subscription {
	out := Subscription{
		SubscriptionID: str(s.SubscriptionID),
		DisplayName:    str(s.DisplayName),
		TenantID:       str(s.TenantID),
	}
	if s.State != nil {
		out.State = string(*s.State)
	}
	return out
}

// ListSubscriptions returns every subscription the token's principal can see.
func (c *Client) ListSubscriptions(ctx context.Context, armToken string) ([]Subscription, error) {
	cl, err := armsubscriptions.NewClient(staticToken(armToken), c.armOptions())
	if err != nil {
		return nil, err
	}
	return collect(ctx, cl.NewListPager(nil), maxPages, func(p armsubscriptions.ClientListResponse) []Subscription {
		out := make([]Subscription, 0, len(p.Value))
		for _, s := range p.Value {
			if s != nil {
				out = append(out, subscriptionFrom(s))
			}
		}
		return out
	})
}

// GetSubscription reads one subscription. A 403/404 means the principal has no
// read access to it.
func (c *Client) GetSubscription(ctx context.Context, armToken, subscriptionID string) (*Subscription, error) {
	cl, err := armsubscriptions.NewClient(staticToken(armToken), c.armOptions())
	if err != nil {
		return nil, err
	}
	resp, err := cl.Get(ctx, subscriptionID, nil)
	if err != nil {
		return nil, armError(err)
	}
	s := subscriptionFrom(&resp.Subscription)
	return &s, nil
}

// Permission is one entry of the caller's effective permissions at a scope.
type Permission struct {
	Actions    []string `json:"actions"`
	NotActions []string `json:"notActions"`
}

// CallerPermissions returns the token principal's own effective permissions on
// a subscription (Microsoft.Authorization/permissions), used to tell in
// advance whether the signed-in administrator can create a role assignment.
// armauthorization lists permissions only for a resource group or a resource,
// so this one goes through azcore's generic Resource Manager client: the same
// pipeline, retries and errors as every typed client.
func (c *Client) CallerPermissions(ctx context.Context, armToken, subscriptionID string) ([]Permission, error) {
	cl, err := arm.NewClient("authsec.azure", "v1.0.0", staticToken(armToken), c.armOptions())
	if err != nil {
		return nil, err
	}
	type page struct {
		Value    []Permission `json:"value"`
		NextLink string       `json:"nextLink"`
	}
	first := runtime.JoinPaths(cl.Endpoint(), "subscriptions", url.PathEscape(subscriptionID),
		"providers/Microsoft.Authorization/permissions") + "?api-version=" + apiVersionAuthorization
	pager := runtime.NewPager(runtime.PagingHandler[page]{
		More: func(p page) bool { return p.NextLink != "" },
		Fetcher: func(ctx context.Context, prev *page) (page, error) {
			next := first
			if prev != nil {
				next = prev.NextLink
			}
			req, err := runtime.NewRequest(ctx, http.MethodGet, next)
			if err != nil {
				return page{}, err
			}
			req.Raw().Header.Set("Accept", "application/json")
			resp, err := cl.Pipeline().Do(req)
			if err != nil {
				return page{}, err
			}
			if !runtime.HasStatusCode(resp, http.StatusOK) {
				return page{}, runtime.NewResponseError(resp)
			}
			var p page
			return p, runtime.UnmarshalAsJSON(resp, &p)
		},
	})
	return collect(ctx, pager, maxPages, func(p page) []Permission { return p.Value })
}

// RoleAssignment is one Azure RBAC role assignment.
type RoleAssignment struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		Scope            string `json:"scope"`
		RoleDefinitionID string `json:"roleDefinitionId"`
		PrincipalID      string `json:"principalId"`
		PrincipalType    string `json:"principalType"`
		// Condition is an ABAC condition expression; empty when unconditional.
		Condition string `json:"condition"`
	} `json:"properties"`
}

func roleAssignmentFrom(a *armauthorization.RoleAssignment) RoleAssignment {
	var out RoleAssignment
	out.ID, out.Name = str(a.ID), str(a.Name)
	if p := a.Properties; p != nil {
		out.Properties.Scope = str(p.Scope)
		out.Properties.RoleDefinitionID = str(p.RoleDefinitionID)
		out.Properties.PrincipalID = str(p.PrincipalID)
		out.Properties.Condition = str(p.Condition)
		if p.PrincipalType != nil {
			out.Properties.PrincipalType = string(*p.PrincipalType)
		}
	}
	return out
}

func (c *Client) listRoleAssignments(ctx context.Context, armToken, subscriptionID, filter string) ([]RoleAssignment, error) {
	cl, err := armauthorization.NewRoleAssignmentsClient(subscriptionID, staticToken(armToken), c.armOptions())
	if err != nil {
		return nil, err
	}
	opts := &armauthorization.RoleAssignmentsClientListForSubscriptionOptions{}
	if filter != "" {
		// This client appends $filter to the query unencoded.
		opts.Filter = to.Ptr(url.QueryEscape(filter))
	}
	return collect(ctx, cl.NewListForSubscriptionPager(opts), maxPages, func(p armauthorization.RoleAssignmentsClientListForSubscriptionResponse) []RoleAssignment {
		out := make([]RoleAssignment, 0, len(p.Value))
		for _, a := range p.Value {
			if a != nil {
				out = append(out, roleAssignmentFrom(a))
			}
		}
		return out
	})
}

// ListRoleAssignmentsForPrincipal returns the principal's role assignments at,
// above (management groups) and below the subscription.
func (c *Client) ListRoleAssignmentsForPrincipal(ctx context.Context, armToken, subscriptionID, principalID string) ([]RoleAssignment, error) {
	return c.listRoleAssignments(ctx, armToken, subscriptionID, fmt.Sprintf("principalId eq '%s'", principalID))
}

// CreateRoleAssignment PUTs a role assignment named name. The caller derives
// name deterministically (RoleAssignmentName), so repeating the call is safe.
// Returns the created assignment's resource id.
func (c *Client) CreateRoleAssignment(ctx context.Context, armToken, scope, name, roleDefinitionID, principalID string) (string, error) {
	cl, err := armauthorization.NewRoleAssignmentsClient("", staticToken(armToken), c.armOptions())
	if err != nil {
		return "", err
	}
	resp, err := cl.Create(ctx, strings.TrimPrefix(scope, "/"), name, armauthorization.RoleAssignmentCreateParameters{
		Properties: &armauthorization.RoleAssignmentProperties{
			RoleDefinitionID: to.Ptr(roleDefinitionID),
			PrincipalID:      to.Ptr(principalID),
			// Declaring the type lets ARM accept a service principal that was
			// created seconds ago by admin consent and has not replicated yet,
			// instead of failing with PrincipalNotFound.
			PrincipalType: to.Ptr(armauthorization.PrincipalTypeServicePrincipal),
		},
	}, nil)
	if err != nil {
		return "", armError(err)
	}
	return str(resp.ID), nil
}
