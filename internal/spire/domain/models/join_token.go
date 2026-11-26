package models

import "time"

// JoinToken is a single-use, expiring credential an admin mints for one
// node attestation. The token's workspace is the workspace the node joins;
// only its SHA-256 is stored.
type JoinToken struct {
	ID           string     `json:"id"`
	WorkspaceID  string     `json:"workspace_id"`
	Description  string     `json:"description,omitempty"`
	CreatedBy    string     `json:"created_by,omitempty"`
	ExpiresAt    time.Time  `json:"expires_at"`
	UsedAt       *time.Time `json:"used_at,omitempty"`
	UsedByNodeID string     `json:"used_by_node_id,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// WorkloadSVID records an X.509 SVID an agent obtained for a workload.
type WorkloadSVID struct {
	ID            string     `json:"id"`
	WorkspaceID   string     `json:"workspace_id"`
	EntryID       string     `json:"entry_id"`
	AgentSpiffeID string     `json:"agent_spiffe_id"`
	SpiffeID      string     `json:"spiffe_id"`
	SerialNumber  string     `json:"serial_number"`
	TTL           int        `json:"ttl"`
	ExpiresAt     time.Time  `json:"expires_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
}
