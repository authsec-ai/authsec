package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// CloudObservation is why a cloud_* row exists.
//
// Every identity, permission, resource and workload row is an assertion about
// someone's account. Without evidence, a reviewer asked to act on one has to
// take it on trust: there is no record of which API returned it, when AWS
// considered it true, or how complete the read was.
//
// Exactly one subject is set. Typed columns rather than a (kind, id) pair
// because a text discriminator beside a bare uuid is not a foreign key — the
// database cannot stop it naming another workspace's row, which is the open
// cross-tenant defect in the iga_* tables.
type CloudObservation struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null"`
	ConnectorID uuid.UUID `json:"connector_id" gorm:"type:uuid;not null"`

	// ScanRunID is the provenance anchor. Not nullable: an observation with no
	// run behind it cannot be explained, and unexplained evidence is not
	// evidence.
	ScanRunID  uuid.UUID `json:"scan_run_id" gorm:"type:uuid;not null"`
	Generation int       `json:"generation" gorm:"not null"`

	IdentityID   *uuid.UUID `json:"identity_id,omitempty" gorm:"type:uuid"`
	PermissionID *uuid.UUID `json:"permission_id,omitempty" gorm:"type:uuid"`
	ResourceID   *uuid.UUID `json:"resource_id,omitempty" gorm:"type:uuid"`
	WorkloadID   *uuid.UUID `json:"workload_id,omitempty" gorm:"type:uuid"`

	// SourceAPI is the AWS call, e.g. "iam:GetRole". Named as the API rather
	// than as our own surface so a reader can go and make the same call.
	SourceAPI string `json:"source_api" gorm:"not null"`

	// Surface and SurfaceState record how complete the read was AT THE TIME.
	// Without them, yesterday's degraded read is indistinguishable from today's
	// clean one once both are rows in a table.
	Surface      string `json:"surface" gorm:"not null;default:''"`
	SurfaceState string `json:"surface_state" gorm:"not null;default:''"`

	// ObservedAt is when the provider's data was true; IngestedAt is when we
	// stored it. Conflating them makes a delayed scan look like a change in the
	// account.
	ObservedAt time.Time `json:"observed_at" gorm:"not null"`
	IngestedAt time.Time `json:"ingested_at" gorm:"not null;default:now()"`

	// SanitizedFacts is what AWS said, after redaction. Never a raw response.
	SanitizedFacts json.RawMessage `json:"sanitized_facts" gorm:"type:jsonb;not null;default:'{}'"`
	// ContentHash is of SanitizedFacts, computed AFTER redaction — see
	// services.HashObservation for why the order matters.
	ContentHash string `json:"content_hash" gorm:"not null"`
}

func (CloudObservation) TableName() string { return "cloud_observation" }

// Subject returns the one id that is set, and which column it came from.
func (o CloudObservation) Subject() (kind string, id uuid.UUID) {
	switch {
	case o.IdentityID != nil:
		return "identity", *o.IdentityID
	case o.PermissionID != nil:
		return "permission", *o.PermissionID
	case o.ResourceID != nil:
		return "resource", *o.ResourceID
	case o.WorkloadID != nil:
		return "workload", *o.WorkloadID
	}
	return "", uuid.Nil
}
