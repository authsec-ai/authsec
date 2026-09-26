package services

import (
	"encoding/json"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RecordCollectorCapability inserts one capability digest for a collector.
// A repeated digest refreshes last_seen_at and the report. A database that
// has not applied migration 043 is left unchanged: the digest is already
// stored on collector_instances, and sync must keep accepting batches.
func RecordCollectorCapability(tx *gorm.DB, workspaceID, collectorID uuid.UUID, digest string, report []byte) error {
	if tx == nil || digest == "" || len(digest) != 64 {
		return nil
	}
	var present int64
	if err := tx.Raw(`SELECT count(*) FROM information_schema.tables
		WHERE table_schema = 'public' AND table_name = 'collector_capability_reports'`).Scan(&present).Error; err != nil {
		return err
	}
	if present == 0 {
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
