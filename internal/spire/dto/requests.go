package dto

// The workspace of every request below is the authenticated one (a verified
// certificate). A workspace_id in the body is optional and, when present,
// must repeat it; any other value is answered 404.

// AttestRequest represents the HTTP request for attestation
type AttestRequest struct {
	WorkspaceID     string            `json:"workspace_id,omitempty"`
	CSR             string            `json:"csr"`
	AttestationType string            `json:"attestation_type"`
	Selectors       map[string]string `json:"selectors"`
}

// RenewRequest represents the HTTP request for renewal
type RenewRequest struct {
	WorkspaceID    string `json:"workspace_id,omitempty"`
	WorkloadID     string `json:"workload_id"`
	CSR            string `json:"csr"`
	OldCertificate string `json:"old_certificate,omitempty"`
}

// RevokeRequest represents the HTTP request for revocation
type RevokeRequest struct {
	WorkspaceID  string `json:"workspace_id,omitempty"`
	SerialNumber string `json:"serial_number"`
	Reason       string `json:"reason,omitempty"`
}
