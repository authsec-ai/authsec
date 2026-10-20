package azure

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Who owns and sponsors an agent, what it inherits, and what changed it: the
// Agent ID detail reads. All read-only, all with AuthSec's app-only Graph
// token.
//
//	owners       may modify the object. A blueprint's owners can add a
//	             credential to it, and so act as every agent made from it.
//	             Application.Read.All (SDK builders).
//	sponsors     the people Entra records as responsible for an agent. A
//	             blueprint's sponsors are required when it is created and read
//	             with Application.Read.All; an agent identity's own sponsors are
//	             documented as needing AgentIdentity.ReadWrite.All, which AuthSec
//	             does not request -- see ListAgentIdentitySponsors.
//	inheritable  which of the blueprint principal's grants flow to every agent
//	             made from it. AgentIdentityBlueprint.Read.All.
//	audit        directory changes to or by an agent (beta, AuditLog.Read.All).
//
// Graph has no request builders for the Agent ID casts, so those go through
// the same SDK adapter with an explicit URL, as the Agent ID listings do.

// DirectoryRef is a directory object another one points at: an owner or a
// sponsor. Default properties only; AuthSec keeps who it is, never more.
type DirectoryRef struct {
	ID string `json:"id"`
	// ODataType is "#microsoft.graph.user", ".group", ".servicePrincipal", ...
	ODataType         string `json:"@odata.type"`
	DisplayName       string `json:"displayName"`
	UserPrincipalName string `json:"userPrincipalName"`
	AccountEnabled    *bool  `json:"accountEnabled"`
}

// Kind is the referenced object's type without its namespace ("user",
// "group", "servicePrincipal", "agentIdentity", ...).
func (r DirectoryRef) Kind() string {
	return strings.TrimPrefix(r.ODataType, "#microsoft.graph.")
}

// agentObjectURL is an Agent ID cast's sub-collection of one object, for the
// reads no SDK builder covers. The id must be an object id (a GUID).
func agentObjectURL(base, id, cast, rel string) (string, error) {
	if !IsGUID(id) {
		return "", fmt.Errorf("%w: %q is not an object id", ErrInvalidInput, id)
	}
	return GraphEndpoint + "/v1.0/" + base + "/" + id + "/microsoft.graph." + cast + "/" + rel, nil
}

// ListBlueprintSponsors returns an agent identity blueprint's sponsors.
// Application.Read.All.
func (c *Client) ListBlueprintSponsors(ctx context.Context, graphToken, blueprintObjectID string) ([]DirectoryRef, error) {
	raw, err := agentObjectURL("applications", blueprintObjectID, "agentIdentityBlueprint", "sponsors")
	if err != nil {
		return nil, err
	}
	ri, err := graphURL(raw)
	return graphPaged[DirectoryRef](ctx, c, graphToken, ri, err, maxPages)
}

// ListAgentIdentitySponsors returns an agent identity's own sponsors.
// Microsoft documents AgentIdentity.ReadWrite.All as the only application
// permission for this read; AuthSec asks for read permissions only, so a
// tenant normally answers 403 here and the caller falls back to the
// blueprint's sponsors.
func (c *Client) ListAgentIdentitySponsors(ctx context.Context, graphToken, agentObjectID string) ([]DirectoryRef, error) {
	raw, err := agentObjectURL("servicePrincipals", agentObjectID, "agentIdentity", "sponsors")
	if err != nil {
		return nil, err
	}
	ri, err := graphURL(raw)
	return graphPaged[DirectoryRef](ctx, c, graphToken, ri, err, maxPages)
}

// ListApplicationOwners returns an app registration's (or a blueprint's)
// owners. Application.Read.All.
func (c *Client) ListApplicationOwners(ctx context.Context, graphToken, appObjectID string) ([]DirectoryRef, error) {
	if !IsGUID(appObjectID) {
		return nil, fmt.Errorf("%w: %q is not an object id", ErrInvalidInput, appObjectID)
	}
	g, err := c.graph()
	if err != nil {
		return nil, err
	}
	ri, err := g.Applications().ByApplicationId(appObjectID).Owners().ToGetRequestInformation(ctx, nil)
	return graphPaged[DirectoryRef](ctx, c, graphToken, ri, err, maxPages)
}

// ListServicePrincipalOwners returns a service principal's (or an agent
// identity's) owners. Application.Read.All.
func (c *Client) ListServicePrincipalOwners(ctx context.Context, graphToken, spObjectID string) ([]DirectoryRef, error) {
	if !IsGUID(spObjectID) {
		return nil, fmt.Errorf("%w: %q is not an object id", ErrInvalidInput, spObjectID)
	}
	g, err := c.graph()
	if err != nil {
		return nil, err
	}
	ri, err := g.ServicePrincipals().ByServicePrincipalId(spObjectID).Owners().ToGetRequestInformation(ctx, nil)
	return graphPaged[DirectoryRef](ctx, c, graphToken, ri, err, maxPages)
}

// ListUserSponsors returns a user's (an agent user's) sponsors.
// User.Read.All, which Directory.Read.All includes.
func (c *Client) ListUserSponsors(ctx context.Context, graphToken, userObjectID string) ([]DirectoryRef, error) {
	if !IsGUID(userObjectID) {
		return nil, fmt.Errorf("%w: %q is not an object id", ErrInvalidInput, userObjectID)
	}
	g, err := c.graph()
	if err != nil {
		return nil, err
	}
	ri, err := g.Users().ByUserId(userObjectID).Sponsors().ToGetRequestInformation(ctx, nil)
	return graphPaged[DirectoryRef](ctx, c, graphToken, ri, err, maxPages)
}

/* --------------------------- inheritable permissions --------------------------- */

// InheritablePermission is one resource app whose permissions, once granted
// to the blueprint's principal, flow to every agent identity made from the
// blueprint without further consent. Microsoft does not show inherited
// permissions on the agent identity anywhere in Graph -- they appear only in
// its tokens -- so AuthSec derives them from this and the principal's grants.
type InheritablePermission struct {
	ResourceAppID string          `json:"resourceAppId"`
	Scopes        *InheritableSet `json:"inheritableScopes"`
	Roles         *InheritableSet `json:"inheritableRoles"`
}

// InheritableSet is one half (delegated scopes, or app roles) of an
// inheritable permission. Kind is "allAllowed", "enumerated" or "none".
type InheritableSet struct {
	Kind   string   `json:"kind"`
	Scopes []string `json:"scopes"`
	Roles  []string `json:"roles"`
}

// Allows reports whether a permission value (a scope like "Mail.Read", or an
// app role value) is inherited under this set. A missing set inherits nothing.
func (s *InheritableSet) Allows(value string) bool {
	if s == nil {
		return false
	}
	switch strings.ToLower(s.Kind) {
	case "allallowed":
		return true
	case "enumerated":
		for _, v := range append(append([]string{}, s.Scopes...), s.Roles...) {
			if strings.EqualFold(v, value) {
				return true
			}
		}
	}
	return false
}

// ListInheritablePermissions returns a blueprint's inheritable permissions.
// AgentIdentityBlueprint.Read.All.
func (c *Client) ListInheritablePermissions(ctx context.Context, graphToken, blueprintObjectID string) ([]InheritablePermission, error) {
	raw, err := agentObjectURL("applications", blueprintObjectID, "agentIdentityBlueprint", "inheritablePermissions")
	if err != nil {
		return nil, err
	}
	ri, err := graphURL(raw)
	return graphPaged[InheritablePermission](ctx, c, graphToken, ri, err, maxPages)
}

/* ------------------------------------ audit ------------------------------------ */

// DirectoryAudit is one Entra audit event, reduced to what AuthSec keeps: who
// did what to which object, when, and which properties changed -- by name.
// The old and new values are left undeclared so decoding drops them.
type DirectoryAudit struct {
	ID                  string         `json:"id"`
	Category            string         `json:"category"`
	ActivityDisplayName string         `json:"activityDisplayName"`
	ActivityDateTime    *time.Time     `json:"activityDateTime"`
	Result              string         `json:"result"`
	InitiatedBy         AuditInitiator `json:"initiatedBy"`
	TargetResources     []AuditTarget  `json:"targetResources"`
}

// AuditInitiator is who performed an audited change: a user or an app.
type AuditInitiator struct {
	User *struct {
		ID                string `json:"id"`
		DisplayName       string `json:"displayName"`
		UserPrincipalName string `json:"userPrincipalName"`
		AgentType         string `json:"agentType"`
	} `json:"user"`
	App *struct {
		AppID                string `json:"appId"`
		DisplayName          string `json:"displayName"`
		ServicePrincipalID   string `json:"servicePrincipalId"`
		ServicePrincipalName string `json:"servicePrincipalName"`
		AgentType            string `json:"agentType"`
	} `json:"app"`
}

// AuditTarget is one object an audited change touched.
type AuditTarget struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	Type              string `json:"type"`
	UserPrincipalName string `json:"userPrincipalName"`
	// AgentType is "notAgentic" or the Agent ID object kind; beta.
	AgentType          string `json:"agentType"`
	BlueprintID        string `json:"blueprintId"`
	ModifiedProperties []struct {
		DisplayName string `json:"displayName"`
	} `json:"modifiedProperties"`
}

// ListDirectoryAudits returns directory audit events since the given time,
// newest first, stopping after maxPages pages (ErrPageLimit, with the rows
// read). Beta, for the agentType and blueprintId Agent ID adds to each event;
// AuditLog.Read.All.
func (c *Client) ListDirectoryAudits(ctx context.Context, graphToken string, since time.Time, maxPages int) ([]DirectoryAudit, error) {
	q := url.Values{}
	q.Set("$filter", "activityDateTime ge "+since.UTC().Format(time.RFC3339))
	q.Set("$top", "500")
	ri, err := graphURL(GraphEndpoint + "/beta/auditLogs/directoryAudits?" + q.Encode())
	return graphPaged[DirectoryAudit](ctx, c, graphToken, ri, err, maxPages)
}
