package services

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// mintGovernedIdentity creates the OAuth client a claimed agent is bound to.
//
// WHY THIS EXISTS
// Claiming used to require an operator to pick an existing agent-kind OAuth client.
// For the overwhelming majority of discovered agents that is ceremony blocking the
// only decision that actually needs a human: who is accountable.
//
// Most agents found in a cluster are workloads that never authenticate to AuthSec at
// all — no SPIRE agent, so no SVID; no mounted secret, so no client_secret_basic.
// Asking someone to hand-pick a credential-holder for a workload that holds no
// credential inverted the ergonomics: it demanded information the operator did not
// have, to satisfy a foreign key the system could satisfy itself.
//
// The client is still REQUIRED, and that part was never wrong: service_accounts is
// keyed on oauth_client_id, so without it there is no entitlement anchor to hang a
// role binding, a revocation, or a certification decision on. A fingerprint is a
// description, not a principal. What changed is who supplies it.
//
// The identity minted here mirrors CreateWorkloadAccess rather than
// RegisterAgentClient: client_credentials, no redirect URIs, no secret, spiffe-svid
// as the only auth method. That is the honest shape for a headless workload — and it
// means nothing can authenticate as it until a real workload identity is wired up,
// which is exactly the truth of the situation rather than a secret nobody will use.
//
// No Hydra registration, also mirroring CreateWorkloadAccess: Hydra is the
// authorization server for interactive flows, and this client has none.
func mintGovernedIdentity(tx *gorm.DB, workspaceID uuid.UUID,
	agent *models.DiscoveredAgent) (*models.MCPOAuthClient, error) {

	id := uuid.New()
	now := time.Now().UTC()

	client := &models.MCPOAuthClient{
		ID:            id,
		ClientID:      id.String(),
		HydraClientID: id.String(),
		ClientName:    governedIdentityName(agent),
		RedirectURIs:  pq.StringArray{},
		// A workload asks for its own token; it never carries a user through a
		// browser, so authorization_code would be a grant it can never use.
		GrantTypes:    pq.StringArray{"client_credentials"},
		ResponseTypes: pq.StringArray{},
		// 'admin' rather than 'dcr': this client was created by the platform on an
		// operator's behalf, not self-registered by the agent.
		RegistrationType: "admin",
		// Deliberately NOT client_secret_basic. Minting a secret that is never
		// delivered anywhere would be a credential nobody rotates, held by nothing.
		AllowedTokenEndpointAuthMethods: pq.StringArray{
			"urn:authsec:params:oauth:client-assertion-type:spiffe-svid",
		},
		// The bit CreateWorkloadAccess forgot. Without it the client defaults to
		// 'human_app' and the claim dialog -- which filters on 'agent' -- cannot see
		// the very identity it needs.
		ClientKind:      models.ClientKindAgent,
		SyncStatus:      "active",
		IsConfidential:  true,
		HomeWorkspaceID: &workspaceID,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := tx.Create(client).Error; err != nil {
		return nil, fmt.Errorf("mint governed identity for agent %s: %w", agent.ID, err)
	}
	return client, nil
}

// governedIdentityName prefers the name the connector suggested, because it was
// derived from the workload itself (e.g. "research-agent/agent") and is what an
// operator will recognise in a client list. Falls back to the display name, then to
// a fingerprint prefix -- never to a shared constant, which would make several
// agents indistinguishable in an audit trail.
func governedIdentityName(agent *models.DiscoveredAgent) string {
	if n := suggestedClientNameFrom(agent.Metadata); n != "" {
		return n + " (agent)"
	}
	if strings.TrimSpace(agent.DisplayName) != "" {
		return agent.DisplayName + " (agent)"
	}
	fp := agent.Fingerprint
	if len(fp) > 12 {
		fp = fp[:12]
	}
	return "discovered-agent-" + fp
}

// suggestedClientNameFrom reads metadata.provisioning_hints.suggested_client_name.
//
// The Kubernetes connector has always sent this -- "<workload>/<container>" -- and
// nothing on this side ever read it. It is exactly the hint needed to name a minted
// identity after the thing it represents.
func suggestedClientNameFrom(metadata json.RawMessage) string {
	if len(metadata) == 0 {
		return ""
	}
	var m struct {
		ProvisioningHints struct {
			SuggestedClientName string `json:"suggested_client_name"`
		} `json:"provisioning_hints"`
	}
	if err := json.Unmarshal(metadata, &m); err != nil {
		return ""
	}
	return strings.TrimSpace(m.ProvisioningHints.SuggestedClientName)
}
