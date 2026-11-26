package services

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// The case timeline (agent_runtime_cases.go, DECISIONS): every case change is
// an iga_gov_event row whose payload carries case_id, read here through
// idx_iga_gov_event_case (migration 186). Kept apart from the case tables so
// this file names the governance event log only.

// AgentCaseLogEntry is one timeline entry (payload redacted as in Logs).
type AgentCaseLogEntry struct {
	ID         int64           `json:"id" gorm:"column:id"`
	OccurredAt time.Time       `json:"occurred_at" gorm:"column:occurred_at"`
	Event      string          `json:"event" gorm:"column:event"`
	ActorKind  string          `json:"actor_kind" gorm:"column:actor_kind"`
	ActorID    string          `json:"actor_id" gorm:"column:actor_id"`
	Payload    json.RawMessage `json:"payload" gorm:"column:payload"`
}

// readAgentCaseLog reads case caseID's timeline, oldest first; withoutExports
// leaves out "case.exported" entries.
func readAgentCaseLog(tx *gorm.DB, ws, caseID uuid.UUID, withoutExports bool) ([]AgentCaseLogEntry, error) {
	q := `SELECT id, occurred_at, event, actor_kind, actor_id, payload FROM iga_gov_event
	       WHERE workspace_id = ? AND (payload->>'case_id') = ?`
	args := []any{ws, caseID.String()}
	if withoutExports {
		q += ` AND event <> ?`
		args = append(args, GovEventAgentCaseExported)
	}
	q += ` ORDER BY id`
	var rows []AgentCaseLogEntry
	if err := tx.Raw(q, args...).Scan(&rows).Error; err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i].Payload = RedactGovEventPayload(rows[i].Payload)
	}
	if rows == nil {
		rows = []AgentCaseLogEntry{}
	}
	return rows, nil
}
