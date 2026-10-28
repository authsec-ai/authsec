package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Identity binding states. The binding follows the lifecycle:
//
//	reserved → registration_pending → registration_confirmed →
//	attestation_pending → attested → enrollment_verified
//
// Terminal / administrative states: disabled, revoked.
const (
	IdentityBindingReserved              = "reserved"
	IdentityBindingRegistrationPending   = "registration_pending"
	IdentityBindingRegistrationConfirmed = "registration_confirmed"
	IdentityBindingAttestationPending    = "attestation_pending"
	IdentityBindingAttested              = "attested"
	IdentityBindingEnrollmentVerified    = "enrollment_verified"
	IdentityBindingDisabled              = "disabled"
	IdentityBindingRevoked               = "revoked"
)

// ValidIdentityBindingStates returns all valid identity binding states.
func ValidIdentityBindingStates() []string {
	return []string{
		IdentityBindingReserved,
		IdentityBindingRegistrationPending,
		IdentityBindingRegistrationConfirmed,
		IdentityBindingAttestationPending,
		IdentityBindingAttested,
		IdentityBindingEnrollmentVerified,
		IdentityBindingDisabled,
		IdentityBindingRevoked,
	}
}

// IdentityBindingTransitionAllowed reports whether a state transition
// from → to is valid in the identity binding lifecycle.
func IdentityBindingTransitionAllowed(from, to string) bool {
	switch from {
	case IdentityBindingReserved:
		return to == IdentityBindingRegistrationPending || to == IdentityBindingDisabled
	case IdentityBindingRegistrationPending:
		return to == IdentityBindingRegistrationConfirmed || to == IdentityBindingDisabled
	case IdentityBindingRegistrationConfirmed:
		return to == IdentityBindingAttestationPending || to == IdentityBindingDisabled
	case IdentityBindingAttestationPending:
		return to == IdentityBindingAttested || to == IdentityBindingDisabled
	case IdentityBindingAttested:
		return to == IdentityBindingEnrollmentVerified || to == IdentityBindingDisabled || to == IdentityBindingRevoked
	case IdentityBindingEnrollmentVerified:
		return to == IdentityBindingDisabled || to == IdentityBindingRevoked
	case IdentityBindingDisabled:
		return to == IdentityBindingRevoked
	case IdentityBindingRevoked:
		return false
	}
	return false
}

// MachineIdentityBinding links a machine/agent to an identity. It supports
// both SPIFFE and enrolled_mtls identity modes.
type MachineIdentityBinding struct {
	ID                uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey"`
	WorkspaceID       uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null;index"`
	AgentID           uuid.UUID  `json:"agent_id" gorm:"type:uuid;not null"`
	WorkloadID        *uuid.UUID `json:"workload_id,omitempty" gorm:"type:uuid"`
	IdentityMode      string     `json:"identity_mode" gorm:"type:text;not null"` // spiffe, enrolled_mtls
	PrimarySPIFFEID   string     `json:"primary_spiffe_id,omitempty" gorm:"type:text"`
	VerifiedPrincipalID string   `json:"verified_principal_id,omitempty" gorm:"type:text"`
	BindingGeneration int        `json:"binding_generation" gorm:"not null;default:1"`
	State             string     `json:"state" gorm:"type:text;not null;default:'reserved'"`
	Assurance         string     `json:"assurance" gorm:"type:text;not null;default:'attestation_pending'"`
	CertSerial        *string    `json:"cert_serial,omitempty" gorm:"type:text"`
	KeyIdentifier     *string    `json:"key_identifier,omitempty" gorm:"type:text"`
	PublicKeyHash     *string    `json:"public_key_hash,omitempty" gorm:"type:text"`
	CreatedAt         time.Time  `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt         time.Time  `json:"updated_at" gorm:"autoUpdateTime"`
}

func (MachineIdentityBinding) TableName() string { return "machine_identity_bindings" }

func (b *MachineIdentityBinding) BeforeCreate(tx *gorm.DB) error {
	if b.ID == uuid.Nil {
		b.ID = uuid.New()
	}
	return nil
}

// ExecutionIdentityBinding is a per-execution identity scope derived from a
// parent MachineIdentityBinding. Each execution (e.g. a process, container,
// or workload instance) gets its own binding with its own SPIFFE URI and
// principal URI.
type ExecutionIdentityBinding struct {
	ID                uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey"`
	ParentBindingID   uuid.UUID  `json:"parent_binding_id" gorm:"type:uuid;not null"`
	WorkspaceID       uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null;index"`
	ExecutionID       string     `json:"execution_id" gorm:"type:text;not null"`
	SPIFFEURI         string     `json:"spiffe_uri,omitempty" gorm:"type:text"`
	PrincipalURI      string     `json:"principal_uri,omitempty" gorm:"type:text"`
	BindingGeneration int        `json:"binding_generation" gorm:"not null"`
	State             string     `json:"state" gorm:"type:text;not null;default:'reserved'"`
	IssuedAt          *time.Time `json:"issued_at,omitempty"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at" gorm:"autoCreateTime"`
}

func (ExecutionIdentityBinding) TableName() string { return "execution_identity_bindings" }

func (b *ExecutionIdentityBinding) BeforeCreate(tx *gorm.DB) error {
	if b.ID == uuid.Nil {
		b.ID = uuid.New()
	}
	return nil
}
