package services

import (
	"encoding/json"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RecordCollectorCapability inserts one capability digest for a collector.
// A repeated digest refreshes last_seen_at and the report. The caller decides
// whether the flag is on and treats an error as best-effort: a failed insert
// must not change the sync result.
func RecordCollectorCapability(tx *gorm.DB, workspaceID, collectorID uuid.UUID, digest string, report []byte) error {
	if tx == nil || digest == "" || len(digest) != 64 {
		return nil
	}
	if len(report) == 0 || !json.Valid(report) {
		report = []byte(`{}`)
	}
	return tx.Exec(`INSERT INTO collector_capability_reports
		(id, workspace_id, collector_id, capability_digest, report)
		VALUES (?, ?, ?, ?, CAST(? AS jsonb))
		ON CONFLICT (workspace_id, collector_id, capability_digest)
		DO UPDATE SET last_seen_at = now(), report = EXCLUDED.report`,
		uuid.New(), workspaceID, collectorID, digest, string(report)).Error
}
