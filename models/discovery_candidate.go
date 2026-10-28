package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// DiscoveryCandidate is one observed workload that has not been assumed to be
// an agent. decision=hold keeps it out of discovered_agents. decision=promote
// means a discovered_agents row was created or an existing one was linked.
type DiscoveryCandidate struct {
	ID                uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID       uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null;index"`
	Source            string          `json:"source" gorm:"not null"`
	Fingerprint       string          `json:"fingerprint" gorm:"not null"`
	LogicalKey        string          `json:"logical_key" gorm:"not null;default:''"`
	Kind              string          `json:"kind" gorm:"not null;default:''"`
	DisplayName       string          `json:"display_name" gorm:"not null;default:''"`
	Signals           json.RawMessage `json:"signals" gorm:"type:jsonb;not null;default:'[]'"`
	Frameworks        json.RawMessage `json:"frameworks" gorm:"type:jsonb;not null;default:'[]'"`
	Confidence        string          `json:"confidence" gorm:"not null"`
	Decision          string          `json:"decision" gorm:"not null"`
	Reasons           json.RawMessage `json:"reasons" gorm:"type:jsonb;not null;default:'[]'"`
	DiscoveredAgentID *uuid.UUID      `json:"discovered_agent_id,omitempty" gorm:"type:uuid"`
	Metadata          json.RawMessage `json:"metadata" gorm:"type:jsonb;not null;default:'{}'"`
	ObservedAt        time.Time       `json:"observed_at" gorm:"not null"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

func (DiscoveryCandidate) TableName() string { return "discovery_candidates" }
