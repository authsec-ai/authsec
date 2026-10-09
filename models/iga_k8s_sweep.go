package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Sweep statuses. A sweep is never deleted: a failed projection must leave the
// previous graph standing AND leave a record of why it did.
const (
	K8sSweepReceived  = "received"
	K8sSweepProjected = "projected"
	K8sSweepFailed    = "failed"
)

// IGAK8sSweep is one complete reading of a cluster's authorization model, and
// the Kubernetes counterpart of cloud_scan_run.
//
// WHY THIS IS DURABLE RATHER THAN A FLAG ON THE REQUEST
// SPEC-iga-phase2-graph §2.7 condition 3 requires that a partition's source
// surface was read BY THE RUN THAT IS RETIRING THINGS, "because content dedupe
// means the absence of a fresh observation row proves nothing". The agent
// reports a snapshot rather than a diff, so two identical sweeps are
// indistinguishable on the wire. A durable row with a generation is what lets a
// support row name the reading that last confirmed it, and what lets a late
// snapshot be recognised as late instead of applied over a newer one.
type IGAK8sSweep struct {
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID `json:"workspace_id" gorm:"type:uuid;not null;index"`

	DiscoverySourceID uuid.UUID `json:"discovery_source_id" gorm:"type:uuid;not null"`
	Cluster           string    `json:"cluster" gorm:"not null"`
	// ClusterUID and OIDCIssuer are what the agent reported for this reading
	// (043). '' when it could not read them.
	ClusterUID string `json:"cluster_uid" gorm:"column:cluster_uid;not null;default:''"`
	OIDCIssuer string `json:"oidc_issuer" gorm:"column:oidc_issuer;not null;default:''"`

	// Monotonic per (workspace, source, cluster). Writes and retirements are
	// fenced to it, so a snapshot arriving mid-projection cannot have its rows
	// closed by the older reading still running.
	Generation int64 `json:"generation" gorm:"not null"`

	ScanKind string `json:"scan_kind" gorm:"not null;default:'rbac'"`

	// The three facts that decide whether absence means anything (§2.7).
	// Stored, never re-derived from the payload: an empty namespace and an
	// unread namespace look identical in a list of objects, and only one of
	// them licenses a retirement.
	Complete      bool           `json:"complete" gorm:"not null;default:false"`
	ClusterScoped bool           `json:"cluster_scoped" gorm:"not null;default:false"`
	Namespaces    pq.StringArray `json:"namespaces" gorm:"type:text[];not null;default:'{}'"`

	SweepStartedAt time.Time `json:"sweep_started_at" gorm:"not null"`
	ObservedAt     time.Time `json:"observed_at" gorm:"not null"`
	ReceivedAt     time.Time `json:"received_at" gorm:"not null;default:now()"`

	Status      string     `json:"status" gorm:"not null;default:'received'"`
	ProjectedAt *time.Time `json:"projected_at,omitempty"`
	Error       string     `json:"error" gorm:"not null;default:''"`
}

func (IGAK8sSweep) TableName() string { return "iga_k8s_sweep" }
