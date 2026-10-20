package azure

import (
	"context"
	"fmt"
	"net/url"
	"time"
)

// The Microsoft 365 agent registry: every agent in the tenant's Copilot
// catalog -- Copilot Studio agents, Microsoft 365 Copilot Agent Builder
// agents, declarative and custom engine agents, from any publisher. Read with
// the Package Management API (Microsoft Agent 365), which replaced the Graph
// agentRegistry APIs. CopilotPackages.Read.All; the tenant needs a Microsoft
// Agent 365 licence for the API to answer. No SDK request builder covers it,
// so it goes through the Graph SDK adapter with an explicit URL.

// CopilotPackage is one package in the tenant's Copilot catalog.
type CopilotPackage struct {
	ID               string `json:"id"`
	DisplayName      string `json:"displayName"`
	Type             string `json:"type"`
	ShortDescription string `json:"shortDescription"`
	Publisher        string `json:"publisher"`
	// Platform is the host platform the package targets ("teams",
	// "outlook", "web"); ElementTypes says what it contains ("bot",
	// "declarativeAgent").
	Platform       string   `json:"platform"`
	Version        string   `json:"version"`
	IsBlocked      bool     `json:"isBlocked"`
	SupportedHosts []string `json:"supportedHosts"`
	ElementTypes   []string `json:"elementTypes"`
	// AvailableTo / DeployedTo: who may use it, and to whom it is deployed
	// (allowedForAll/Some/None, acquiredForAll/Some/None).
	AvailableTo string `json:"availableTo"`
	DeployedTo  string `json:"deployedTo"`
	// AppID is the Entra application registration behind it; AgentIdentityID
	// its Microsoft Entra Agent ID agent identity, when it has one.
	AppID           string `json:"appId"`
	AgentIdentityID string `json:"agentIdentityId"`
	// AgentClass is Microsoft's classification of the agent
	// (governanceMetadata: PromptAgent, HostedAgent, WorkflowAgent,
	// ManagedAgent, Unmanaged, AIApp).
	AgentClass           string     `json:"governanceMetadata"`
	CreatedDateTime      *time.Time `json:"createdDateTime"`
	LastModifiedDateTime *time.Time `json:"lastModifiedDateTime"`
}

// CopilotPackageDetail adds one package's use over the last 30 days.
type CopilotPackageDetail struct {
	CopilotPackage
	ActiveUsers         *int       `json:"activeUsers"`
	TotalSessions       *int       `json:"totalSessions"`
	TotalRunTimeInHours *float64   `json:"totalRunTimeInHours"`
	LastUsedDateTime    *time.Time `json:"lastUsedDateTime"`
	Sensitivity         string     `json:"sensitivity"`
	Categories          []string   `json:"categories"`
}

// copilotPackagesPath is the catalog, filtered to agents (packages that run
// in Copilot), as Microsoft documents listing all agents.
const copilotPackagesPath = "/v1.0/copilot/admin/catalog/packages"

// ListCopilotAgents returns every agent in the tenant's Copilot catalog.
func (c *Client) ListCopilotAgents(ctx context.Context, graphToken string) ([]CopilotPackage, error) {
	q := url.Values{}
	q.Set("$filter", "supportedHosts/any(h:h eq 'Copilot')")
	ri, err := graphURL(GraphEndpoint + copilotPackagesPath + "?" + q.Encode())
	return graphPaged[CopilotPackage](ctx, c, graphToken, ri, err, maxPages)
}

// GetCopilotPackage returns one package with its use.
func (c *Client) GetCopilotPackage(ctx context.Context, graphToken, id string) (*CopilotPackageDetail, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: empty package id", ErrInvalidInput)
	}
	ri, err := graphURL(GraphEndpoint + copilotPackagesPath + "/" + url.PathEscape(id))
	return graphGet[CopilotPackageDetail](ctx, c, graphToken, ri, err)
}
