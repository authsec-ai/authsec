package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
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
		Condition        string `json:"condition"`
		ConditionVersion string `json:"conditionVersion,omitempty"`
		Description      string `json:"description,omitempty"`
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
		out.Properties.ConditionVersion = str(p.ConditionVersion)
		out.Properties.Description = str(p.Description)
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

// ListRoleAssignments returns every role assignment that applies to the
// subscription: at it, inherited from above it, and below it.
func (c *Client) ListRoleAssignments(ctx context.Context, armToken, subscriptionID string) ([]RoleAssignment, error) {
	return c.listRoleAssignments(ctx, armToken, subscriptionID, "")
}

// ListRoleAssignmentsForPrincipal returns the principal's role assignments at,
// above (management groups) and below the subscription.
func (c *Client) ListRoleAssignmentsForPrincipal(ctx context.Context, armToken, subscriptionID, principalID string) ([]RoleAssignment, error) {
	return c.listRoleAssignments(ctx, armToken, subscriptionID, fmt.Sprintf("principalId eq '%s'", principalID))
}

// RoleDefinition is one Azure role (built-in or custom) and what it allows.
type RoleDefinition struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		RoleName    string `json:"roleName"`
		Type        string `json:"type"`
		Permissions []struct {
			Actions        []string `json:"actions"`
			NotActions     []string `json:"notActions"`
			DataActions    []string `json:"dataActions"`
			NotDataActions []string `json:"notDataActions"`
		} `json:"permissions"`
	} `json:"properties"`
}

func roleDefinitionFrom(d *armauthorization.RoleDefinition) RoleDefinition {
	var out RoleDefinition
	out.ID, out.Name = str(d.ID), str(d.Name)
	p := d.Properties
	if p == nil {
		return out
	}
	out.Properties.RoleName = str(p.RoleName)
	out.Properties.Type = str(p.RoleType)
	for _, perm := range p.Permissions {
		if perm == nil {
			continue
		}
		out.Properties.Permissions = append(out.Properties.Permissions, struct {
			Actions        []string `json:"actions"`
			NotActions     []string `json:"notActions"`
			DataActions    []string `json:"dataActions"`
			NotDataActions []string `json:"notDataActions"`
		}{strs(perm.Actions), strs(perm.NotActions), strs(perm.DataActions), strs(perm.NotDataActions)})
	}
	return out
}

// ListRoleDefinitions returns the roles assignable in the subscription,
// built-in and custom.
func (c *Client) ListRoleDefinitions(ctx context.Context, armToken, subscriptionID string) ([]RoleDefinition, error) {
	cl, err := armauthorization.NewRoleDefinitionsClient(staticToken(armToken), c.armOptions())
	if err != nil {
		return nil, err
	}
	// The SDK's path is "/{scope}/...": the scope goes in without its leading slash.
	pager := cl.NewListPager("subscriptions/"+url.PathEscape(subscriptionID), nil)
	return collect(ctx, pager, maxPages, func(p armauthorization.RoleDefinitionsClientListResponse) []RoleDefinition {
		out := make([]RoleDefinition, 0, len(p.Value))
		for _, d := range p.Value {
			if d != nil {
				out = append(out, roleDefinitionFrom(d))
			}
		}
		return out
	})
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

// GraphResource is one row of an Azure Resource Graph result.
type GraphResource struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Type           string            `json:"type"`
	Location       string            `json:"location"`
	ResourceGroup  string            `json:"resourceGroup"`
	SubscriptionID string            `json:"subscriptionId"`
	Tags           map[string]string `json:"tags"`
}

// ResourceGraphPageOf is one page of an Azure Resource Graph query whose rows
// decode into T.
type ResourceGraphPageOf[T any] struct {
	TotalRecords    int64  `json:"totalRecords"`
	Count           int64  `json:"count"`
	ResultTruncated string `json:"resultTruncated"`
	SkipToken       string `json:"$skipToken"`
	Data            []T    `json:"data"`
}

// ResourceGraphPage is one page of the resource inventory query.
type ResourceGraphPage = ResourceGraphPageOf[GraphResource]

// QueryResources runs one Azure Resource Graph page against the given
// subscriptions. Pass the previous page's SkipToken to continue.
func (c *Client) QueryResources(ctx context.Context, armToken string, subscriptionIDs []string, query, skipToken string, top int) (*ResourceGraphPage, error) {
	return QueryResourceGraph[GraphResource](ctx, c, armToken, subscriptionIDs, query, skipToken, top)
}

// QueryResourceGraph runs one Azure Resource Graph page and decodes its rows
// into T. A package function rather than a method: Go methods cannot take type
// parameters.
//
// The rows are decoded from the raw response rather than the SDK's untyped
// Data, so each query's own row type reads them exactly as it always has.
func QueryResourceGraph[T any](ctx context.Context, c *Client, armToken string, subscriptionIDs []string, query, skipToken string, top int) (*ResourceGraphPageOf[T], error) {
	cl, err := armresourcegraph.NewClient(staticToken(armToken), c.armOptions())
	if err != nil {
		return nil, err
	}
	opts := &armresourcegraph.QueryRequestOptions{
		ResultFormat: to.Ptr(armresourcegraph.ResultFormatObjectArray),
		Top:          to.Ptr(int32(top)),
	}
	if skipToken != "" {
		opts.SkipToken = to.Ptr(skipToken)
	}
	var raw *http.Response
	_, err = cl.Resources(policy.WithCaptureResponse(ctx, &raw), armresourcegraph.QueryRequest{
		Query:         to.Ptr(query),
		Subscriptions: to.SliceOfPtrs(subscriptionIDs...),
		Options:       opts,
	}, nil)
	if err != nil {
		return nil, armError(err)
	}
	body, err := runtime.Payload(raw)
	if err != nil {
		return nil, fmt.Errorf("azure arm: unreadable response: %w", err)
	}
	var page ResourceGraphPageOf[T]
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("azure arm: unreadable response: %w", err)
	}
	return &page, nil
}

// ActivityLogEvent is one Azure Activity Log (management plane) entry: who
// called which operation, on what, when, with what outcome.
type ActivityLogEvent struct {
	Caller         string                 `json:"caller"`
	Claims         map[string]interface{} `json:"claims"`
	EventTimestamp *time.Time             `json:"eventTimestamp"`
	ResourceID     string                 `json:"resourceId"`
	Authorization  *struct {
		Action string `json:"action"`
		Scope  string `json:"scope"`
	} `json:"authorization"`
	Status *struct {
		Value string `json:"value"`
	} `json:"status"`
}

func activityEventFrom(e *armmonitor.EventData) ActivityLogEvent {
	out := ActivityLogEvent{
		Caller:         str(e.Caller),
		EventTimestamp: e.EventTimestamp,
		ResourceID:     str(e.ResourceID),
	}
	if e.Claims != nil {
		out.Claims = make(map[string]interface{}, len(e.Claims))
		for k, v := range e.Claims {
			if v != nil {
				out.Claims[k] = *v
			}
		}
	}
	if a := e.Authorization; a != nil {
		out.Authorization = &struct {
			Action string `json:"action"`
			Scope  string `json:"scope"`
		}{str(a.Action), str(a.Scope)}
	}
	if st := e.Status; st != nil {
		out.Status = &struct {
			Value string `json:"value"`
		}{str(st.Value)}
	}
	return out
}

// objectIDClaim is where Entra puts the caller's object id in a token, and so
// in an Activity Log entry's claims.
const objectIDClaim = "http://schemas.microsoft.com/identity/claims/objectidentifier"

// CallerObjectID is the Entra object id of the identity that made the call,
// from its token claims; "" when the entry carries none.
func (e ActivityLogEvent) CallerObjectID() string {
	if v, ok := e.Claims[objectIDClaim].(string); ok {
		return strings.ToLower(v)
	}
	if v, ok := e.Claims["oid"].(string); ok {
		return strings.ToLower(v)
	}
	return ""
}

// ListActivityLog returns a subscription's management-plane events since the
// given time, newest first, stopping after maxPages (ErrPageLimit, with the
// rows read). Reader covers it (Microsoft.Insights/eventtypes/values/read).
func (c *Client) ListActivityLog(ctx context.Context, armToken, subscriptionID string, since, until time.Time, maxPages int) ([]ActivityLogEvent, error) {
	cl, err := armmonitor.NewActivityLogsClient(subscriptionID, staticToken(armToken), c.armOptions())
	if err != nil {
		return nil, err
	}
	filter := fmt.Sprintf("eventTimestamp ge '%s' and eventTimestamp le '%s'",
		since.UTC().Format(time.RFC3339), until.UTC().Format(time.RFC3339))
	pager := cl.NewListPager(filter, &armmonitor.ActivityLogsClientListOptions{
		Select: to.Ptr("caller,claims,authorization,eventTimestamp,status,resourceId"),
	})
	return collect(ctx, pager, maxPages, func(p armmonitor.ActivityLogsClientListResponse) []ActivityLogEvent {
		out := make([]ActivityLogEvent, 0, len(p.Value))
		for _, e := range p.Value {
			if e != nil {
				out = append(out, activityEventFrom(e))
			}
		}
		return out
	})
}

// UserAssignedIdentityFederatedCredential is one federated credential on a
// user-assigned managed identity -- the ARM-side twin of an application's
// federatedIdentityCredentials, and the join key AKS workload identity uses.
type UserAssignedIdentityFederatedCredential struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		Issuer    string   `json:"issuer"`
		Subject   string   `json:"subject"`
		Audiences []string `json:"audiences"`
	} `json:"properties"`
}

// ListUserAssignedIdentityFederatedCredentials returns the federated
// credentials of one user-assigned managed identity (its full ARM id). Reader.
func (c *Client) ListUserAssignedIdentityFederatedCredentials(ctx context.Context, armToken, identityID string) ([]UserAssignedIdentityFederatedCredential, error) {
	rid, err := arm.ParseResourceID(identityID)
	if err != nil || rid.SubscriptionID == "" || rid.ResourceGroupName == "" || rid.Name == "" {
		return nil, fmt.Errorf("%w: not a user-assigned identity id: %q", ErrInvalidInput, identityID)
	}
	cl, err := armmsi.NewFederatedIdentityCredentialsClient(rid.SubscriptionID, staticToken(armToken), c.armOptions())
	if err != nil {
		return nil, err
	}
	pager := cl.NewListPager(rid.ResourceGroupName, rid.Name, nil)
	return collect(ctx, pager, maxPages, func(p armmsi.FederatedIdentityCredentialsClientListResponse) []UserAssignedIdentityFederatedCredential {
		out := make([]UserAssignedIdentityFederatedCredential, 0, len(p.Value))
		for _, f := range p.Value {
			if f == nil {
				continue
			}
			var fc UserAssignedIdentityFederatedCredential
			fc.ID, fc.Name = str(f.ID), str(f.Name)
			if pr := f.Properties; pr != nil {
				fc.Properties.Issuer = str(pr.Issuer)
				fc.Properties.Subject = str(pr.Subject)
				fc.Properties.Audiences = strs(pr.Audiences)
			}
			out = append(out, fc)
		}
		return out
	})
}

// GetResourceProperties reads one ARM resource's properties at apiVersion
// (the resource provider's own version): nil when the resource does not
// exist. Access policies read a vault's permission model and a search
// service's authentication options with it.
func (c *Client) GetResourceProperties(ctx context.Context, armToken, resourceID, apiVersion string) (map[string]any, error) {
	cl, err := arm.NewClient("authsec.azure", "v1.0.0", staticToken(armToken), c.armOptions())
	if err != nil {
		return nil, err
	}
	u := runtime.JoinPaths(cl.Endpoint(), resourceID) + "?api-version=" + url.QueryEscape(apiVersion)
	req, err := runtime.NewRequest(ctx, http.MethodGet, u)
	if err != nil {
		return nil, err
	}
	req.Raw().Header.Set("Accept", "application/json")
	resp, err := cl.Pipeline().Do(req)
	if err != nil {
		return nil, armError(err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return nil, armError(runtime.NewResponseError(resp))
	}
	var body struct {
		Properties map[string]any `json:"properties"`
	}
	if err := runtime.UnmarshalAsJSON(resp, &body); err != nil {
		return nil, err
	}
	if body.Properties == nil {
		body.Properties = map[string]any{}
	}
	return body.Properties, nil
}

// RoleAssignmentScheduleInstance is one Privileged Identity Management
// schedule instance of a role assignment (Microsoft.Authorization
// roleAssignmentScheduleInstances, api 2020-10-01): AssignmentType is
// "Assigned" or "Activated" (a PIM activation), and EndDateTime is set for a
// time-bound one.
type RoleAssignmentScheduleInstance struct {
	OriginRoleAssignmentID string `json:"originRoleAssignmentId"`
	AssignmentType         string `json:"assignmentType"`
	EndDateTime            string `json:"endDateTime"`
	MemberType             string `json:"memberType"`
}

// TimeBound reports an activation or an assignment with an end: one that
// expires on its own.
func (i RoleAssignmentScheduleInstance) TimeBound() bool {
	return strings.EqualFold(i.AssignmentType, "Activated") || i.EndDateTime != ""
}

// ListRoleAssignmentScheduleInstances returns the principal's PIM schedule
// instances at scope and below ($filter=assignedTo, the documented filter for
// one principal), following nextLink.
func (c *Client) ListRoleAssignmentScheduleInstances(ctx context.Context, armToken, scope, principalID string) ([]RoleAssignmentScheduleInstance, error) {
	cl, err := arm.NewClient("authsec.azure", "v1.0.0", staticToken(armToken), c.armOptions())
	if err != nil {
		return nil, err
	}
	u := runtime.JoinPaths(cl.Endpoint(), scope, "providers/Microsoft.Authorization/roleAssignmentScheduleInstances") +
		"?api-version=2020-10-01&$filter=" + url.QueryEscape("assignedTo('"+principalID+"')")
	var out []RoleAssignmentScheduleInstance
	for page := 0; u != "" && page < 50; page++ {
		req, err := runtime.NewRequest(ctx, http.MethodGet, u)
		if err != nil {
			return nil, err
		}
		req.Raw().Header.Set("Accept", "application/json")
		resp, err := cl.Pipeline().Do(req)
		if err != nil {
			return nil, armError(err)
		}
		if !runtime.HasStatusCode(resp, http.StatusOK) {
			return nil, armError(runtime.NewResponseError(resp))
		}
		var body struct {
			Value []struct {
				Properties RoleAssignmentScheduleInstance `json:"properties"`
			} `json:"value"`
			NextLink string `json:"nextLink"`
		}
		if err := runtime.UnmarshalAsJSON(resp, &body); err != nil {
			return nil, err
		}
		for _, v := range body.Value {
			out = append(out, v.Properties)
		}
		u = body.NextLink
	}
	return out, nil
}
