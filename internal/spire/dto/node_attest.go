package dto

import "time"

// NodeAttestRequest represents a node attestation request. The join token
// decides the workspace; workspace_id is optional and must be the token's.
type NodeAttestRequest struct {
	JoinToken       string                 `json:"join_token"`
	WorkspaceID     string                 `json:"workspace_id,omitempty"`
	NodeID          string                 `json:"node_id"`
	AttestationType string                 `json:"attestation_type"` // "join_token", "kubernetes", "unix", "docker"
	Evidence        map[string]interface{} `json:"evidence"`
	CSR             string                 `json:"csr"`
}

// NodeAttestResponse represents a node attestation response
type NodeAttestResponse struct {
	AgentID     string `json:"agent_id"`
	SpiffeID    string `json:"spiffe_id"`
	WorkspaceID string `json:"workspace_id"`
	Certificate string `json:"certificate"`
	CABundle    string `json:"ca_bundle"` // Joined CA chain as single PEM string
	TTL         int    `json:"ttl"`       // Certificate TTL in seconds
}

// CreateJoinTokenRequest mints a node attestation join token.
type CreateJoinTokenRequest struct {
	Description string `json:"description,omitempty"`
	TTLSeconds  int    `json:"ttl_seconds,omitempty"` // default 3600, max 7 days
}

// JoinTokenResponse describes a join token. Token is set only in the mint
// response: it is shown once and only its hash is stored.
type JoinTokenResponse struct {
	ID           string     `json:"id"`
	Token        string     `json:"token,omitempty"`
	Description  string     `json:"description,omitempty"`
	ExpiresAt    time.Time  `json:"expires_at"`
	UsedAt       *time.Time `json:"used_at,omitempty"`
	UsedByNodeID string     `json:"used_by_node_id,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}
