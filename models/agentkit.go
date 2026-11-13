package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// AgentKit (authsec-cli) event types: what a machine's daemon reports.
const (
	AgentKitEventDecision     = "decision"      // an enforcement decision (allow, deny, quarantine, kill)
	AgentKitEventDetection    = "detection"     // a threat detection (artex_present, offensive_tool, ...)
	AgentKitEventAgentStarted = "agent_started" // an agent began on the machine
	AgentKitEventAgentStopped = "agent_stopped"
	AgentKitEventSensor       = "sensor" // the daemon started, stopped or lost events
	AgentKitEventAccess       = "access" // a periodic summary of what one agent reached
)

// ValidAgentKitEventTypes returns the event types a machine may report.
func ValidAgentKitEventTypes() []string {
	return []string{
		AgentKitEventDecision, AgentKitEventDetection, AgentKitEventAgentStarted,
		AgentKitEventAgentStopped, AgentKitEventSensor, AgentKitEventAccess,
	}
}

// AgentKitEvent is one record a machine's daemon reported (migration 147).
// The indexed columns are copied out of Record, which is kept whole.
type AgentKitEvent struct {
	ID                uuid.UUID       `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID       uuid.UUID       `json:"workspace_id" gorm:"type:uuid;not null"`
	DiscoverySourceID uuid.UUID       `json:"discovery_source_id" gorm:"type:uuid;not null"`
	ObservedAt        time.Time       `json:"observed_at" gorm:"not null"`
	ReceivedAt        time.Time       `json:"received_at" gorm:"not null;default:now()"`
	Type              string          `json:"type" gorm:"not null"`
	Kind              string          `json:"kind"`
	Action            string          `json:"action"`
	Rule              string          `json:"rule"`
	Severity          string          `json:"severity"`
	Enforced          bool            `json:"enforced"`
	AgentID           string          `json:"agent_id"`
	AgentName         string          `json:"agent_name"`
	AgentPID          int             `json:"agent_pid" gorm:"column:agent_pid"`
	Record            json.RawMessage `json:"record" gorm:"type:jsonb;not null"`
}

func (AgentKitEvent) TableName() string { return "agentkit_events" }

// AgentKitPolicy is one version of an agent policy (authsec.ai/v1
// AgentPolicy YAML) kept for the workspace's machines (migration 147).
type AgentKitPolicy struct {
	ID          uuid.UUID  `json:"id" gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	WorkspaceID uuid.UUID  `json:"workspace_id" gorm:"type:uuid;not null"`
	AgentID     string     `json:"agent_id" gorm:"not null"`
	Version     int        `json:"version" gorm:"not null"`
	Document    string     `json:"document" gorm:"not null"`
	SHA256      string     `json:"sha256" gorm:"column:sha256;not null"`
	Comment     string     `json:"comment"`
	CreatedBy   *uuid.UUID `json:"created_by,omitempty" gorm:"type:uuid"`
	CreatedAt   time.Time  `json:"created_at" gorm:"not null;default:now()"`
}

func (AgentKitPolicy) TableName() string { return "agentkit_policies" }
