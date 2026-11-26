package dto

import "time"

// AgentRenewRequest represents an agent SVID renewal request. The agent is
// the one whose certificate authenticated the request; agent_id is optional
// and must name it.
type AgentRenewRequest struct {
	AgentID string `json:"agent_id,omitempty"`
	CSR     string `json:"csr"`
}

// AgentRenewResponse represents an agent SVID renewal response
type AgentRenewResponse struct {
	SpiffeID    string    `json:"spiffe_id"`
	Certificate string    `json:"certificate"`
	CABundle    string    `json:"ca_bundle"`
	TTL         int       `json:"ttl"`
	CAChain     []string  `json:"ca_chain,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
}
