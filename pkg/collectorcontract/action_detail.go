// Package collectorcontract — ActionDetail and provenance types added in 2.2.0.
// All fields are optional so old collectors that omit them still validate.
package collectorcontract

// ActionDetail carries canonical action semantics for an observation.
// It is always optional on the wire; old collectors send observations
// without it and those observations remain valid.
type ActionDetail struct {
	// Operation is the canonical verb (e.g. "file.write", "process.exec").
	Operation string `json:"operation,omitempty"`
	// Phase is attempt / exec / complete.
	Phase string `json:"phase,omitempty"`
	// Result is the canonical outcome detail (success / denied / error / unknown).
	Result string `json:"result,omitempty"`
	// PolicyDecision is the policy evaluation outcome if available.
	PolicyDecision string `json:"policy_decision,omitempty"`
	// OperationID is a correlation ID for multi-phase operations.
	OperationID string `json:"operation_id,omitempty"`
	// SourceSequence is the sensor-local ordering token.
	SourceSequence int64 `json:"source_sequence,omitempty"`
	// Count is >= 1 when the sensor aggregated multiple identical events.
	Count int64 `json:"count,omitempty"`
	// Aggregation describes how events were combined (e.g. "count", "sample").
	Aggregation string `json:"aggregation,omitempty"`
	// Errno is the OS errno when Result is "error".
	Errno int `json:"errno,omitempty"`
	// ExecutableDigest is the SHA-256 of the executable image, if available.
	ExecutableDigest string `json:"executable_digest,omitempty"`
	// SourceSensor identifies the producing sensor (e.g. "tetragon", "auditd").
	SourceSensor string `json:"source_sensor,omitempty"`
	// SourceVersion is the sensor/driver build version.
	SourceVersion string `json:"source_version,omitempty"`
	// EnforcementRefs links to applied control receipt entries.
	EnforcementRefs []EnforcementRef `json:"enforcement_refs,omitempty"`
}

// EnforcementRef links an action to an applied policy control.
type EnforcementRef struct {
	AssignmentID string `json:"assignment_id,omitempty"`
	RuleID       string `json:"rule_id,omitempty"`
	ControlID    string `json:"control_id,omitempty"`
}

// CredentialProvenance describes how an identity credential was obtained.
type CredentialProvenance struct {
	Method string `json:"method,omitempty"` // e.g. "nss_passwd", "nss_group", "sssd_cache", "k8s_sa"
	Source string `json:"source,omitempty"` // e.g. "/etc/passwd", "nss_sss", "kube-apiserver"
	// ResolvedAt is the RFC 3339 time the credential was resolved.
	ResolvedAt string `json:"resolved_at,omitempty"`
}

// MappingProvenance describes how a UID was mapped to a directory identity.
type MappingProvenance struct {
	Resolver string `json:"resolver,omitempty"` // e.g. "sssd", "winbind", "nss"
	Source   string `json:"source,omitempty"`   // e.g. "nss_sss", "wbclient"
	// MappedAt is the RFC 3339 time the mapping was resolved.
	MappedAt string `json:"mapped_at,omitempty"`
	// Ambiguous is true when the resolver found multiple candidates.
	Ambiguous bool `json:"ambiguous,omitempty"`
}
