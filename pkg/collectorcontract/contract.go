// Package collectorcontract is the public TRD 2 agent-sync wire contract.
// Agents pin a copy of this package; pkg/collectorcontract/SHA256SUMS is the
// drift check. Schema version is "2.0", independent of the policy format.
package collectorcontract

import "encoding/json"

const (
	// SchemaVersion is the only schema this server accepts.
	SchemaVersion = "2.0"
	// PackageVersion is the pin agents record. It is not the wire schema string.
	PackageVersion = "2.0.0"
	// DecompressedMaxBytes is the 2 MiB uncompressed cap from §11.1.
	DecompressedMaxBytes = 2 << 20
	// CompressedMaxBytes is the cap on a gzip body before it is inflated.
	CompressedMaxBytes = 512 << 10
	// NormalizerVersion is stamped on observations this server writes.
	NormalizerVersion = "trd2-ingest-1"
)

// SyncRequest is one agent-sync batch (§11.2, example §11.3).
type SyncRequest struct {
	SchemaVersion    string           `json:"schema_version"`
	BatchID          string           `json:"batch_id"`
	CollectorEpoch   string           `json:"collector_epoch"`
	Sequence         int64            `json:"sequence"`
	SentAt           string           `json:"sent_at"`
	Capabilities     json.RawMessage  `json:"capabilities,omitempty"`
	CapabilityDigest string           `json:"capability_digest,omitempty"`
	Snapshot         *Snapshot        `json:"snapshot,omitempty"`
	Objects          []Object         `json:"objects"`
	Observations     []Observation    `json:"observations"`
	Applied          []AppliedReceipt `json:"applied"`
	Health           Health           `json:"health"`
	// Identity fields are not part of the wire schema. If a caller sends them
	// the server compares them to the credential and returns 403 on conflict.
	WorkspaceID string `json:"workspace_id,omitempty"`
	HostID      string `json:"host_id,omitempty"`
	EstateID    string `json:"estate_id,omitempty"`
}

// Snapshot is one chunk of a configuration snapshot (§9.3).
type Snapshot struct {
	SnapshotID         string `json:"snapshot_id"`
	CollectorEpoch     string `json:"collector_epoch"`
	ScopeKey           string `json:"scope_key"`
	ObjectClass        string `json:"object_class"`
	Generation         int64  `json:"generation"`
	ChunkNo            int    `json:"chunk_no"`
	TerminalChunkCount int    `json:"terminal_chunk_count"`
	Digest             string `json:"digest"`
	Complete           bool   `json:"complete"`
}

// Object is a native object with a batch-local ref. The server assigns
// recognition keys; ref is not a canonical id.
type Object struct {
	Ref        string         `json:"ref"`
	Kind       string         `json:"kind"`
	Native     map[string]any `json:"native"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// Observation is one source-local fact.
type Observation struct {
	EventID     string         `json:"event_id"`
	Kind        string         `json:"kind"`
	SubjectRef  string         `json:"subject_ref,omitempty"`
	IdentityRef string         `json:"identity_ref,omitempty"`
	ResourceRef string         `json:"resource_ref,omitempty"`
	Runtime     map[string]any `json:"runtime,omitempty"`
	ObservedAt  string         `json:"observed_at"`
	Outcome     string         `json:"outcome"`
	Attribution string         `json:"attribution,omitempty"`
}

// AppliedReceipt is the §22.3 control receipt carried in applied[].
type AppliedReceipt struct {
	WorkloadID        string           `json:"workload_id"`
	DeliveryRevision  int64            `json:"delivery_revision"`
	RuntimeGeneration string           `json:"runtime_generation"`
	State             string           `json:"state"`
	Controls          []ControlReceipt `json:"controls"`
	ObservedAt        string           `json:"observed_at"`
}

// ControlReceipt is one control inside an applied receipt.
type ControlReceipt struct {
	Kind           string `json:"kind"`
	State          string `json:"state"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	Test           string `json:"test"`
}

// Health is collector liveness. It is not authorization.
type Health struct {
	EventsLost     int64 `json:"events_lost"`
	QueueDepth     int64 `json:"queue_depth"`
	WatchGaps      int64 `json:"watch_gaps,omitempty"`
	SourceFailures int64 `json:"source_failures,omitempty"`
}

// SyncResponse is the durable receipt (§11.4). desired is null until policy
// packages exist; the field is always present.
type SyncResponse struct {
	ReceiptID              string          `json:"receipt_id"`
	AcceptedSequence       int64           `json:"accepted_sequence"`
	ReceiptState           string          `json:"receipt_state,omitempty"`
	ProjectionState        string          `json:"projection_state"`
	PublishedGraphRevision int64           `json:"published_graph_revision"`
	MappingURL             string          `json:"mapping_url"`
	Desired                json.RawMessage `json:"desired"`
	NextSyncSeconds        int             `json:"next_sync_seconds"`
}

// ReceiptView is GET /api/iga/v2/receipts/:id.
type ReceiptView struct {
	ReceiptID              string    `json:"receipt_id"`
	State                  string    `json:"state"`
	ProjectionState        string    `json:"projection_state"`
	PublishedGraphRevision int64     `json:"published_graph_revision"`
	Mappings               []Mapping `json:"mappings"`
}

// Mapping is a source-key to canonical-id row. P0 ingestion does not project,
// so the list is empty and ready for a later cursor.
type Mapping struct {
	SourceKey   string `json:"source_key"`
	CanonicalID string `json:"canonical_id"`
}

// FieldError is one bounded 422 entry.
type FieldError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// ContractError is a wire rejection. Kind is "invalid" or "upgrade".
type ContractError struct {
	Kind      string
	Fields    []FieldError
	Supported []string
}

func (e *ContractError) Error() string {
	if e == nil {
		return ""
	}
	return e.Kind
}
