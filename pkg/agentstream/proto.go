package agentstream

import "time"

// SchemaVersion is the protocol version for stream messages.
const SchemaVersion = "stream.v1"

// MessageKind identifies the type of stream message.
type MessageKind string

const (
	KindHello            MessageKind = "hello"
	KindObservationBatch MessageKind = "observation_batch"
	KindBatchAck         MessageKind = "batch_ack"
	KindDesiredManifest  MessageKind = "desired_manifest"
	KindAppliedReceipt   MessageKind = "applied_receipt"
	KindReceiptAck       MessageKind = "receipt_ack"
	KindHealth           MessageKind = "health"
	KindRevocation       MessageKind = "revocation"
	KindResumeRequired   MessageKind = "resume_required"
)

// StreamMessage is the envelope for all stream protocol messages.
type StreamMessage struct {
	SchemaVersion   string      `json:"schema_version"`
	Kind            MessageKind `json:"kind"`
	MessageID       string      `json:"message_id"`
	CollectorEpoch  string      `json:"collector_epoch"`
	StreamSessionID string      `json:"stream_session_id"`
	Sequence        int64       `json:"sequence"`
	Timestamp       time.Time   `json:"timestamp"`
	Payload         any         `json:"payload"`
}

// Hello is sent by the agent on connection to establish the session.
type Hello struct {
	PreviousAcks        []string `json:"previous_acks"`
	CapabilityDigest    string   `json:"capability_digest"`
	SupportedSchemas    []string `json:"supported_schemas"`
	AppliedPublications []string `json:"applied_publications"`
	CollectorKind       string   `json:"collector_kind"`
	CollectorVersion    string   `json:"collector_version"`
}

// ObservationBatch carries evidence from the agent.
type ObservationBatch struct {
	BatchID      string `json:"batch_id"`
	Observations []any  `json:"observations"`
	Objects      []any  `json:"objects"`
	Partitions   []any  `json:"partitions,omitempty"`
}

// BatchAck acknowledges a batch of observations.
type BatchAck struct {
	BatchID   string `json:"batch_id"`
	ReceiptID string `json:"receipt_id"`
	Accepted  bool   `json:"accepted"`
	Reason    string `json:"reason,omitempty"`
}

// DesiredManifest sends desired state to the agent.
type DesiredManifest struct {
	ManifestID       string `json:"manifest_id"`
	DeliveryRevision int64  `json:"delivery_revision"`
	DeliveryEpoch    string `json:"delivery_epoch"`
	PolicyFormat     string `json:"policy_format"`
	ArtifactSHA256   string `json:"artifact_sha256,omitempty"`
	ArtifactURL      string `json:"artifact_url,omitempty"`
	Controls         any    `json:"controls"`
}

// AppliedReceipt reports the result of applying desired state.
type AppliedReceipt struct {
	ManifestID       string `json:"manifest_id"`
	DeliveryRevision int64  `json:"delivery_revision"`
	Applied          bool   `json:"applied"`
	ControlResults   []any  `json:"control_results,omitempty"`
	FailureReason    string `json:"failure_reason,omitempty"`
}

// ReceiptAck acknowledges an applied receipt.
type ReceiptAck struct {
	ManifestID string `json:"manifest_id"`
	Accepted   bool   `json:"accepted"`
}

// Health is a bidirectional liveness probe.
type Health struct {
	Status string `json:"status"` // "ok", "degraded"
}

// Revocation instructs the agent to revoke identity or policy.
type Revocation struct {
	Reason    string   `json:"reason"`
	Scope     string   `json:"scope"` // "identity", "policy", "all"
	TargetIDs []string `json:"target_ids,omitempty"`
}

// ResumeRequired tells the agent to reconnect with full state.
type ResumeRequired struct {
	Reason string `json:"reason"`
}
