package azure

import (
	"context"
	"net/http"
	"net/url"
)

// Service principal accountEnabled through Microsoft Graph (SecOps W2 C9,
// the entra containment level). The write is AuthSec's only Graph write:
// PATCH /v1.0/servicePrincipals/{id} {"accountEnabled": bool}, which needs
// the application permission Application.ReadWrite.All. An agent identity
// is a service principal too, so the same call names it (the agent
// identity's own permissions, AgentIdentity.*, are UNVERIFIED: Graph's agent
// identity API is in preview).

// ServicePrincipalAccountEnabled reads accountEnabled. A missing object is an
// *APIError with Status 404.
func (c *Client) ServicePrincipalAccountEnabled(ctx context.Context, graphToken, objectID string) (bool, error) {
	var out struct {
		AccountEnabled *bool `json:"accountEnabled"`
	}
	u := GraphEndpoint + "/v1.0/servicePrincipals/" + url.PathEscape(objectID) + "?$select=accountEnabled"
	if _, err := c.do(ctx, "graph", http.MethodGet, u, graphToken, nil, nil, &out); err != nil {
		return false, err
	}
	return out.AccountEnabled == nil || *out.AccountEnabled, nil
}

// SetServicePrincipalAccountEnabled writes accountEnabled.
func (c *Client) SetServicePrincipalAccountEnabled(ctx context.Context, graphToken, objectID string, enabled bool) error {
	u := GraphEndpoint + "/v1.0/servicePrincipals/" + url.PathEscape(objectID)
	_, err := c.do(ctx, "graph", http.MethodPatch, u, graphToken, nil, map[string]any{"accountEnabled": enabled}, nil)
	return err
}
