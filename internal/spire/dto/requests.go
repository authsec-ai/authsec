package dto

// AttestRequest represents the HTTP request for attestation
type AttestRequest struct {
	WorkspaceID        string            `json:"workspace_id"`
	CSR             string            `json:"csr"`
	AttestationType string            `json:"attestation_type"`
	Selectors       map[string]string `json:"selectors"`
	VaultMount      string            `json:"vault_mount,omitempty"` // Optional: PKI mount path
}

// RenewRequest represents the HTTP request for renewal
type RenewRequest struct {
	WorkspaceID       string `json:"workspace_id"`
	WorkloadID     string `json:"workload_id"`
	CSR            string `json:"csr"`
	OldCertificate string `json:"old_certificate,omitempty"`
}

// RevokeRequest represents the HTTP request for revocation
type RevokeRequest struct {
	WorkspaceID     string `json:"workspace_id"`
	SerialNumber string `json:"serial_number"`
	Reason       string `json:"reason,omitempty"`
}

// UpdateWorkloadRequest represents the HTTP request for updating a workload
type UpdateWorkloadRequest struct {
	WorkspaceID        string            `json:"workspace_id"`
	Selectors       map[string]string `json:"selectors,omitempty"`
	VaultRole       string            `json:"vault_role,omitempty"`
	Status          string            `json:"status,omitempty"`
	AttestationType string            `json:"attestation_type,omitempty"`
}
