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

	// These four are SET NULL, not CASCADE: reconciliation hard-deletes stale
	// inventory by generation, and this evidence must outlive that delete
	// rather than vanish with it. At most one is set -- never exactly one --
	// because a legitimately reconciled-away subject leaves all four null.
	IdentityID   *uuid.UUID `json:"identity_id,omitempty" gorm:"type:uuid"`
	PermissionID *uuid.UUID `json:"permission_id,omitempty" gorm:"type:uuid"`
	ResourceID   *uuid.UUID `json:"resource_id,omitempty" gorm:"type:uuid"`
	WorkloadID   *uuid.UUID `json:"workload_id,omitempty" gorm:"type:uuid"`
	// PolicyID (035) makes a policy VERSION an evidence subject, qualified by
	// (workspace, connector) like every other. It is the fifth subject, and the
	// at-most-one check and both dedupe indexes were widened with it.
	PolicyID *uuid.UUID `json:"policy_id,omitempty" gorm:"type:uuid"`

	// SubjectNativeID is the AWS-native id (ARN, role name, ...) captured at
	// write time. It is what keeps this row legible as "evidence for X" after
	// the subject FK above is SET NULL by a later reconciliation delete --
	// without it, an orphaned observation would say nothing at all about what
	// it once was evidence for.
	SubjectNativeID string `json:"subject_native_id" gorm:"not null"`

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

	// LastConfirmedRunID/At record the most recent run that re-read this exact
	// fact without it changing. The dedupe index (022) means a re-read like
	// that writes no new row, which used to mean it left no trace at all --
	// reconciliation could not tell "confirmed again today" from "not looked
	// at since it was first written". ObservationWriter.Record updates these on
	// the conflict path instead of doing nothing.
	LastConfirmedRunID *uuid.UUID `json:"last_confirmed_run_id,omitempty" gorm:"type:uuid"`
	LastConfirmedAt    *time.Time `json:"last_confirmed_at,omitempty"`
	// ConfirmationCount is a floor on how many runs have seen this fact, not a
	// full history -- the history is ScanRunID plus every run that later
	// touched LastConfirmedRunID, which this table does not enumerate.
	ConfirmationCount int `json:"confirmation_count" gorm:"not null;default:1"`
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
	case o.PolicyID != nil:
		return "policy", *o.PolicyID
	}
	return "", uuid.Nil
}
