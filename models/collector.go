package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Collector installation kinds. These are discovery_sources.kind values added
// by migration 038. They are deliberately NOT in ValidDiscoverySourceKinds:
// the unauthenticated legacy registration path must not be able to mint one.
const (
	CollectorKindLinux = "linux_collector"
	CollectorKindK8s   = "k8s_collector"
	CollectorKindNode  = "node_sensor"
)

// Evidence trust (§2.3). unverified_legacy is the default for every row the
// unauthenticated discovery ingress writes. authenticated_collector and
// human_asserted are the only values that may feed policy, authoritative
// edges, ownership or enrollment.
const (
	EvidenceTrustUnverifiedLegacy       = "unverified_legacy"
	EvidenceTrustAuthenticatedCollector = "authenticated_collector"
	EvidenceTrustHumanAsserted          = "human_asserted"
)

// Credential scopes. A v1 actuation token is not one of these.
const (
	CollectorScopeIngest       = "ingest"
	CollectorScopePolicyRead   = "policy_read"
	CollectorScopeReceiptWrite = "receipt_write"
	CollectorScopeActuation    = "actuation"
)

const (
	CollectorStatusActive  = "active"
	CollectorStatusRevoked = "revoked"

	// Producer modes added to iga_observations.mode and iga_scan_runs.mode.
	ProducerModeRuntimeBatch          = "runtime_batch"
	ProducerModeConfigurationSnapshot = "configuration_snapshot"
	ReceiptStateAccepted              = "accepted"
	ReceiptStateProjecting            = "projecting"
	ReceiptStatePublished             = "published"
	ReceiptStateFailed                = "failed"
	ProjectionStateQueued             = "queued"
	ProjectionStatePublished          = "published"
	OutboxKindCollectorProject        = "collector_project"
)

// EstateScopeKind values an enrollment may bind.
const (
	EstateKindHost    = "host"
	EstateKindCluster = "cluster"
	EstateKindNode    = "node"
)

// ValidCollectorKinds returns the kinds an enrollment token may be bound to.
func ValidCollectorKinds() []string {
	return []string{CollectorKindLinux, CollectorKindK8s, CollectorKindNode}
}

// ValidCollectorScopes returns the credential scope vocabulary.
func ValidCollectorScopes() []string {
	return []string{
		CollectorScopeIngest, CollectorScopePolicyRead,
		CollectorScopeReceiptWrite, CollectorScopeActuation,
	}
}

// ValidEvidenceTrusts returns the evidence_trust vocabulary.
func ValidEvidenceTrusts() []string {
	return []string{
		EvidenceTrustUnverifiedLegacy,
		EvidenceTrustAuthenticatedCollector,
		EvidenceTrustHumanAsserted,
	}
}

// StringList is a JSON array stored in jsonb.
type StringList []string

// Value implements driver.Valuer.
func (s StringList) Value() (driver.Value, error) {
	if s == nil {
		s = StringList{}
	}
	b, err := json.Marshal([]string(s))
	if err != nil {
		return nil, err
	}
	// A string, not []byte, so the driver binds it as jsonb text rather than bytea.
	return string(b), nil
}

// Scan implements sql.Scanner.
func (s *StringList) Scan(src any) error {
	if src == nil {
		*s = StringList{}
		return nil
	}
	var raw []byte
	switch v := src.(type) {
	case []byte:
		raw = v
	case string:
		raw = []byte(v)
	default:
		return errors.New("collector string list: unexpected type")
	}
	if len(raw) == 0 {
		*s = StringList{}
		return nil
	}
	return json.Unmarshal(raw, s)
}

// Contains reports whether the list holds v.
func (s StringList) Contains(v string) bool {
	for _, item := range s {
		if item == v {
			return true
		}
	}
	return false
}

// CollectorEnrollment is a single-use, kind-and-scope-bound bootstrap token.
// Only token_hash is stored.
type CollectorEnrollment struct {
	ID                 uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID        uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	TokenHash          string          `json:"-" gorm:"not null"`
	Kind               string          `json:"kind" gorm:"not null"`
	EstateScopeID      *uuid.UUID      `json:"estate_scope_id,omitempty" gorm:"type:uuid"`
	EstateScopeKind    string          `json:"estate_scope_kind" gorm:"not null"`
	EstateDisplayName  string          `json:"estate_display_name" gorm:"not null;default:''"`
	NamespaceAllowlist StringList      `json:"namespace_allowlist" gorm:"type:jsonb;not null"`
	CapabilityCeiling  json.RawMessage `json:"capability_ceiling" gorm:"type:jsonb;not null"`
	ExpiresAt          time.Time       `json:"expires_at" gorm:"not null"`
	UsedAt             *time.Time      `json:"used_at,omitempty"`
	CreatedBy          string          `json:"created_by" gorm:"not null;default:''"`
	CreatedAt          time.Time       `json:"created_at"`
}

func (CollectorEnrollment) TableName() string { return "collector_enrollments" }

// CollectorEnrollmentRecovery is the encrypted enroll response, keyed by the
// hash of the installation public key and nonce.
type CollectorEnrollmentRecovery struct {
	ID           uuid.UUID `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID  uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	EnrollmentID uuid.UUID `json:"enrollment_id" gorm:"type:uuid;not null"`
	KeyHash      string    `json:"-" gorm:"not null"`
	Ciphertext   []byte    `json:"-" gorm:"not null"`
	ExpiresAt    time.Time `json:"expires_at" gorm:"not null"`
	CreatedAt    time.Time `json:"created_at"`
}

func (CollectorEnrollmentRecovery) TableName() string { return "collector_enrollment_recoveries" }

// CollectorInstance is one enrolled collector. InstallationPublicKey is a
// public key, stored so rotation can demand proof of possession. It is not a
// credential and is never returned by the read API.
type CollectorInstance struct {
	ID                    uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID           uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	DiscoverySourceID     uuid.UUID       `json:"discovery_source_id" gorm:"type:uuid;not null"`
	EstateScopeID         uuid.UUID       `json:"estate_scope_id" gorm:"type:uuid;not null"`
	IntegrationID         uuid.UUID       `json:"integration_id" gorm:"type:uuid;not null"`
	Kind                  string          `json:"kind" gorm:"not null"`
	InstallationKeyID     string          `json:"installation_key_id" gorm:"not null"`
	InstallationPublicKey []byte          `json:"-" gorm:"not null"`
	ApprovedScope         json.RawMessage `json:"approved_scope" gorm:"type:jsonb;not null"`
	Epoch                 *uuid.UUID      `json:"epoch,omitempty" gorm:"type:uuid"`
	AuthorizedNextEpoch   *uuid.UUID      `json:"-" gorm:"type:uuid"`
	LastSequence          int64           `json:"last_sequence" gorm:"not null;default:0"`
	Version               string          `json:"version" gorm:"not null;default:''"`
	RowVersion            int64           `json:"row_version" gorm:"not null;default:1"`
	CapabilityDigest      string          `json:"capability_digest" gorm:"not null;default:''"`
	LastSeenAt            *time.Time      `json:"last_seen_at,omitempty"`
	Status                string          `json:"status" gorm:"not null;default:'active'"`
	RevokedAt             *time.Time      `json:"revoked_at,omitempty"`
	RevokeReason          string          `json:"revoke_reason" gorm:"not null;default:''"`
	CreatedAt             time.Time       `json:"created_at"`
	UpdatedAt             time.Time       `json:"updated_at"`
}

func (CollectorInstance) TableName() string { return "collector_instances" }

// CollectorCredential is the hash of a scoped bearer credential. The plaintext
// is returned once, at issue or rotation, and is never stored.
type CollectorCredential struct {
	ID             uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID    uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	CollectorID    uuid.UUID  `json:"collector_id" gorm:"type:uuid;not null"`
	CredentialHash string     `json:"-" gorm:"not null"`
	Scopes         StringList `json:"scopes" gorm:"type:jsonb;not null"`
	ExpiresAt      time.Time  `json:"expires_at" gorm:"not null"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	PredecessorID  *uuid.UUID `json:"predecessor_id,omitempty" gorm:"type:uuid"`
	CreatedAt      time.Time  `json:"created_at"`
}

func (CollectorCredential) TableName() string { return "collector_credentials" }

// CollectorIntegration binds one discovery source to one iga_integrations row.
type CollectorIntegration struct {
	WorkspaceID       uuid.UUID `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	DiscoverySourceID uuid.UUID `json:"discovery_source_id" gorm:"type:uuid;primaryKey"`
	IntegrationID     uuid.UUID `json:"integration_id" gorm:"type:uuid;not null"`
	CollectorID       uuid.UUID `json:"collector_id" gorm:"type:uuid;not null"`
	CreatedAt         time.Time `json:"created_at"`
}

func (CollectorIntegration) TableName() string { return "collector_integrations" }

// CollectorBatch is one accepted agent-sync payload and its durable receipt.
type CollectorBatch struct {
	ID              uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID     uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	CollectorID     uuid.UUID       `json:"collector_id" gorm:"type:uuid;not null"`
	Epoch           uuid.UUID       `json:"epoch" gorm:"type:uuid;not null"`
	Sequence        int64           `json:"sequence" gorm:"not null"`
	BatchID         uuid.UUID       `json:"batch_id" gorm:"type:uuid;not null"`
	PayloadHash     string          `json:"payload_hash" gorm:"not null"`
	ReceiptID       uuid.UUID       `json:"receipt_id" gorm:"type:uuid;not null"`
	ReceiptState    string          `json:"receipt_state" gorm:"not null"`
	ProjectionState string          `json:"projection_state" gorm:"not null"`
	IGAScanRunID    *uuid.UUID      `json:"iga_scan_run_id,omitempty" gorm:"column:iga_scan_run_id;type:uuid"`
	GraphRevision   int64           `json:"graph_revision" gorm:"not null;default:0"`
	ReceivedAt      time.Time       `json:"received_at"`
	ErrorCode       string          `json:"error_code" gorm:"not null;default:''"`
	ReceiptBody     json.RawMessage `json:"-" gorm:"type:jsonb;not null"`
}

func (CollectorBatch) TableName() string { return "collector_batches" }

// CollectorSnapshot is a configuration snapshot whose completeness the server
// decides. Collector-supplied complete=true is not enough.
type CollectorSnapshot struct {
	ID             uuid.UUID `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID    uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	CollectorID    uuid.UUID `json:"collector_id" gorm:"type:uuid;not null"`
	SnapshotID     uuid.UUID `json:"snapshot_id" gorm:"type:uuid;not null"`
	Epoch          uuid.UUID `json:"epoch" gorm:"type:uuid;not null"`
	ScopeKey       string    `json:"scope_key" gorm:"not null"`
	ObjectClass    string    `json:"object_class" gorm:"not null"`
	Generation     int64     `json:"generation" gorm:"not null"`
	ExpectedChunks int       `json:"expected_chunks" gorm:"not null"`
	ReceivedDigest string    `json:"received_digest" gorm:"not null;default:''"`
	Complete       bool      `json:"complete" gorm:"not null;default:false"`
	GapBlocked     bool      `json:"gap_blocked" gorm:"not null;default:false"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func (CollectorSnapshot) TableName() string { return "collector_snapshots" }

// CollectorSnapshotChunk is one validated chunk of a snapshot.
type CollectorSnapshotChunk struct {
	WorkspaceID   uuid.UUID `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	SnapshotRowID uuid.UUID `json:"snapshot_row_id" gorm:"type:uuid;primaryKey"`
	ChunkNo       int       `json:"chunk_no" gorm:"primaryKey"`
	PayloadHash   string    `json:"payload_hash" gorm:"not null"`
	Validated     bool      `json:"validated" gorm:"not null;default:false"`
	CreatedAt     time.Time `json:"created_at"`
}

func (CollectorSnapshotChunk) TableName() string { return "collector_snapshot_chunks" }

// CollectorSequenceGap records a hole in the per-epoch sequence. A gap never
// deletes anything; it blocks snapshot completeness.
type CollectorSequenceGap struct {
	ID               uuid.UUID `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID      uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	CollectorID      uuid.UUID `json:"collector_id" gorm:"type:uuid;not null"`
	Epoch            uuid.UUID `json:"epoch" gorm:"type:uuid;not null"`
	ExpectedSequence int64     `json:"expected_sequence" gorm:"not null"`
	ReceivedSequence int64     `json:"received_sequence" gorm:"not null"`
	BatchID          uuid.UUID `json:"batch_id" gorm:"type:uuid;not null"`
	CreatedAt        time.Time `json:"created_at"`
}

func (CollectorSequenceGap) TableName() string { return "collector_sequence_gaps" }

// CollectorOutbox is the durable job written in the same transaction as a receipt.
type CollectorOutbox struct {
	ID            uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID   uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	IntegrationID uuid.UUID  `json:"integration_id" gorm:"type:uuid;not null"`
	CollectorID   uuid.UUID  `json:"collector_id" gorm:"type:uuid;not null"`
	BatchRowID    uuid.UUID  `json:"batch_row_id" gorm:"type:uuid;not null"`
	JobKind       string     `json:"job_kind" gorm:"not null"`
	DedupeKey     string     `json:"dedupe_key" gorm:"not null"`
	State         string     `json:"state" gorm:"not null;default:'ready'"`
	AvailableAt   time.Time  `json:"available_at"`
	LeaseOwner    *string    `json:"lease_owner,omitempty"`
	LeasedUntil   *time.Time `json:"leased_until,omitempty"`
	AttemptCount  int        `json:"attempt_count" gorm:"not null;default:0"`
	LastError     string     `json:"last_error" gorm:"not null;default:''"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

func (CollectorOutbox) TableName() string { return "collector_outbox" }

// WorkspaceCollectorSettings holds the per-workspace legacy-ingress switch.
type WorkspaceCollectorSettings struct {
	WorkspaceID                    uuid.UUID `json:"workspace_id" gorm:"type:uuid;primaryKey"`
	LegacyDiscoveryIngressDisabled bool      `json:"legacy_discovery_ingress_disabled" gorm:"not null;default:false"`
	UpdatedAt                      time.Time `json:"updated_at"`
	UpdatedBy                      string    `json:"updated_by" gorm:"not null;default:''"`
}

func (WorkspaceCollectorSettings) TableName() string { return "workspace_collector_settings" }

// CollectorPrincipal is the authority a v2 credential resolves to.
// Workspace, estate and scopes come from the credential, never from the body.
type CollectorPrincipal struct {
	WorkspaceID       uuid.UUID
	CollectorID       uuid.UUID
	EstateScopeID     uuid.UUID
	DiscoverySourceID uuid.UUID
	IntegrationID     uuid.UUID
	Kind              string
	Scopes            []string
	CredentialID      uuid.UUID
	RowVersion        int64
}

// ApprovedScope is the JSON shape stored on collector_instances.approved_scope.
type ApprovedScope struct {
	Namespaces        []string        `json:"namespaces"`
	EstateScopeKind   string          `json:"estate_scope_kind"`
	CapabilityCeiling json.RawMessage `json:"capability_ceiling,omitempty"`
	NativeHints       map[string]any  `json:"native_hints,omitempty"`
	BoundNodeName     string          `json:"bound_node_name,omitempty"`
}
