package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Agent sources beyond Microsoft Entra Agent ID and the Microsoft 365 agent
// registry, none of which needs a licence. All read-only:
//
//	Logic Apps workflows  a Consumption workflow's definition, under Reader
//	                      (Microsoft.Logic/workflows/read), to find agent loops
//	Teams app catalog     the organization's Teams apps and their bots
//	                      (AppCatalog.Read.All): Copilot Studio agents and
//	                      custom bots published to Teams
//	Foundry agents        a Foundry project's agents, from its data plane
//	                      (GET {project}/agents), which needs a Foundry
//	                      data-plane role on the account: ARM Reader does not
//	                      reach it

// ScopeFoundry is the app-only scope of the Foundry data plane.
const ScopeFoundry = "https://ai.azure.com/.default"

/* ------------------------------- Logic Apps -------------------------------- */

// logicWorkflowAPIVersion is the Microsoft.Logic/workflows API version read.
const logicWorkflowAPIVersion = "2019-05-01"

// LogicWorkflow is a Consumption Logic Apps workflow as ARM returns it: its
// definition and the connections its parameters bind.
type LogicWorkflow struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Location   string `json:"location"`
	Properties struct {
		State      string          `json:"state"`
		Definition json.RawMessage `json:"definition"`
		Parameters json.RawMessage `json:"parameters"`
	} `json:"properties"`
}

// GetLogicWorkflow reads one workflow by its ARM id.
func (c *Client) GetLogicWorkflow(ctx context.Context, armToken, id string) (*LogicWorkflow, error) {
	if !strings.HasPrefix(strings.ToLower(id), "/subscriptions/") {
		return nil, fmt.Errorf("%w: not an ARM id: %q", ErrInvalidInput, id)
	}
	var out LogicWorkflow
	u := ARMEndpoint + id + "?api-version=" + logicWorkflowAPIVersion
	if _, err := c.do(ctx, "arm", http.MethodGet, u, armToken, nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

/* ---------------------------- Teams app catalog ---------------------------- */

// TeamsApp is one app in the tenant's Teams app catalog with its definitions.
type TeamsApp struct {
	ID                 string               `json:"id"`
	ExternalID         string               `json:"externalId"`
	DisplayName        string               `json:"displayName"`
	DistributionMethod string               `json:"distributionMethod"`
	AppDefinitions     []TeamsAppDefinition `json:"appDefinitions"`
}

// TeamsAppDefinition is one version of a Teams app.
type TeamsAppDefinition struct {
	ID                   string     `json:"id"`
	TeamsAppID           string     `json:"teamsAppId"`
	DisplayName          string     `json:"displayName"`
	Version              string     `json:"version"`
	PublishingState      string     `json:"publishingState"`
	Description          string     `json:"description"`
	LastModifiedDateTime *time.Time `json:"lastModifiedDateTime"`
	CreatedBy            *struct {
		User *struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
		} `json:"user"`
		Application *struct {
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
		} `json:"application"`
	} `json:"createdBy"`
	// Bot is the app's bot: its id is the bot's Microsoft Entra app (client) id.
	Bot *struct {
		ID string `json:"id"`
	} `json:"bot"`
}

// ListOrganizationTeamsApps returns the apps the organization published to its
// own Teams app catalog (distributionMethod organization), each with its
// definitions and their bots. AppCatalog.Read.All.
func (c *Client) ListOrganizationTeamsApps(ctx context.Context, graphToken string) ([]TeamsApp, error) {
	q := url.Values{}
	q.Set("$filter", "distributionMethod eq 'organization'")
	q.Set("$expand", "appDefinitions($expand=bot)")
	ri, err := graphURL(GraphEndpoint + "/v1.0/appCatalogs/teamsApps?" + q.Encode())
	return graphPaged[TeamsApp](ctx, c, graphToken, ri, err, maxPages)
}

/* ------------------------------ Foundry agents ----------------------------- */

// foundryAgentsPage is one page of a project's agents.
type foundryAgentsPage struct {
	Data    []FoundryAgent `json:"data"`
	LastID  string         `json:"last_id"`
	HasMore bool           `json:"has_more"`
}

// FoundryAgent is one agent of a Foundry project, as the data plane lists it.
// Versions, InstanceIdentity and Blueprint are kept raw: the caller keeps only
// the facts it names (never instructions, never a tool's headers or keys).
type FoundryAgent struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	State            string          `json:"state"`
	Versions         json.RawMessage `json:"versions"`
	InstanceIdentity json.RawMessage `json:"instance_identity"`
	Blueprint        json.RawMessage `json:"blueprint"`
}

// foundryAgentsPageLimit is the documented maximum page.
const foundryAgentsPageLimit = 100

// ListFoundryProjectAgents lists a project's agents from its data-plane
// endpoint (https://{subdomain}.services.ai.azure.com/api/projects/{project}).
// A 401 or 403 means no Foundry data-plane role is assigned to AuthSec.
func (c *Client) ListFoundryProjectAgents(ctx context.Context, foundryToken, projectEndpoint string) ([]FoundryAgent, error) {
	base := strings.TrimSuffix(projectEndpoint, "/")
	if !strings.HasPrefix(base, "https://") {
		return nil, fmt.Errorf("%w: not an https endpoint: %q", ErrInvalidInput, projectEndpoint)
	}
	var out []FoundryAgent
	after := ""
	for page := 0; page < maxPages; page++ {
		q := url.Values{}
		q.Set("api-version", "v1")
		q.Set("limit", fmt.Sprint(foundryAgentsPageLimit))
		if after != "" {
			q.Set("after", after)
		}
		var p foundryAgentsPage
		if _, err := c.do(ctx, "foundry", http.MethodGet, base+"/agents?"+q.Encode(), foundryToken, nil, nil, &p); err != nil {
			return out, err
		}
		out = append(out, p.Data...)
		if !p.HasMore || p.LastID == "" {
			return out, nil
		}
		after = p.LastID
	}
	return out, ErrPageLimit
}

// FoundryProjectEndpoint is a project's data-plane endpoint, from its
// account's endpoint (https://{subdomain}.cognitiveservices.azure.com/ or
// .services.ai.azure.com/) and the project's name; "" when the account has no
// custom subdomain to build it from.
func FoundryProjectEndpoint(accountEndpoint, project string) string {
	u, err := url.Parse(strings.TrimSpace(accountEndpoint))
	if err != nil || u.Host == "" || project == "" {
		return ""
	}
	sub, _, ok := strings.Cut(strings.ToLower(u.Host), ".")
	if !ok || sub == "" {
		return ""
	}
	return "https://" + sub + ".services.ai.azure.com/api/projects/" + url.PathEscape(project)
}

// IsAccessDenied reports whether err is Microsoft answering 401 or 403.
func IsAccessDenied(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.Status == http.StatusUnauthorized || apiErr.Status == http.StatusForbidden
}
