package igaread

import (
	"time"

	"github.com/google/uuid"
)

// StuckSnapshotDeferralThreshold is N in "deferred longer than N
// microbatches". The collector projector increments collector_outbox.attempt_count
// once per claim and then requeues an incomplete or gap-blocked snapshot.
// A snapshot is reported when that count is greater than this value, so three
// attempts are still inside the window and the fourth is stuck.
const StuckSnapshotDeferralThreshold = 3

// CollectorDeferralBlock is the opt-in /pipeline block. Slices are empty, not
// null, when nothing is stuck.
type CollectorDeferralBlock struct {
	DeferralThreshold int                    `json:"deferral_threshold"`
	StuckSnapshots    []StuckSnapshot        `json:"stuck_snapshots"`
	SupersededBatches []SupersededBatchCount `json:"superseded_batches"`
}

// StuckSnapshot is one collector snapshot the projector has deferred past
// the threshold and still will not publish: a missing chunk, a failed or
// isolated chunk, or gap_blocked.
//
// FirstDeferredAt is the earliest collector_outbox.created_at for the
// snapshot's batches. That is when the batch became deferrable, not a
// dedicated column: the projector is not changed here. LastAttempt is the
// latest outbox updated_at.
type StuckSnapshot struct {
	CollectorID            uuid.UUID `json:"collector_id"`
	IntegrationID          uuid.UUID `json:"integration_id"`
	SnapshotID             uuid.UUID `json:"snapshot_id"`
	Scope                  string    `json:"scope"`
	Class                  string    `json:"class"`
	Generation             int64     `json:"generation"`
	ExpectedChunks         int       `json:"expected_chunks"`
	ReceivedChunks         int       `json:"received_chunks"`
	FailedOrIsolatedChunks int       `json:"failed_or_isolated_chunks"`
	FirstDeferredAt        any       `json:"first_deferred_at"`
	LastAttempt            any       `json:"last_attempt"`
	Deferrals              int       `json:"deferrals"`
	Reason                 string    `json:"reason"`
}

// SupersededBatchCount is how many batches for one collector were rejected
// by the generation fence (collector_batches.superseded_at).
type SupersededBatchCount struct {
	CollectorID   uuid.UUID `json:"collector_id"`
	IntegrationID uuid.UUID `json:"integration_id"`
	Count         int       `json:"count"`
}

type stuckSnapshotRow struct {
	CollectorID            uuid.UUID
	IntegrationID          uuid.UUID
	SnapshotID             uuid.UUID
	Scope                  string
	Class                  string
	Generation             int64
	ExpectedChunks         int
	ReceivedChunks         int
	FailedOrIsolatedChunks int
	FirstDeferredAt        time.Time
	LastAttempt            time.Time
	Deferrals              int
	GapBlocked             bool
}

// CollectorDeferrals reads stuck snapshots and superseded batch counts for
// the workspace. It is a read of collector tables inside the caller's
// snapshot. It does not project anything and it does not discard a snapshot.
func (q *Query) CollectorDeferrals() (*CollectorDeferralBlock, error) {
	var rows []stuckSnapshotRow
	err := q.DB().Raw(`
		SELECT s.collector_id,
		       ci.integration_id,
		       s.snapshot_id,
		       s.scope_key AS scope,
		       s.object_class AS class,
		       s.generation,
		       s.expected_chunks,
		       (SELECT count(*)::int FROM collector_snapshot_chunks c
		         WHERE c.workspace_id = s.workspace_id AND c.snapshot_row_id = s.id) AS received_chunks,
		       (
		         (SELECT count(*)::int FROM collector_snapshot_chunks c
		           WHERE c.workspace_id = s.workspace_id AND c.snapshot_row_id = s.id
		             AND c.validated = false)
		         +
		         (SELECT count(*)::int FROM collector_batches fb
		            JOIN collector_outbox fo
		              ON fo.workspace_id = fb.workspace_id AND fo.batch_row_id = fb.id
		           WHERE fb.workspace_id = s.workspace_id
		             AND fb.collector_id = s.collector_id
		             AND fb.snapshot_id = s.snapshot_id
		             AND (fo.state IN ('failed', 'dead') OR fb.receipt_state = 'failed'))
		       ) AS failed_or_isolated_chunks,
		       MIN(o.created_at) AS first_deferred_at,
		       MAX(o.updated_at) AS last_attempt,
		       MAX(o.attempt_count) AS deferrals,
		       s.gap_blocked
		  FROM collector_snapshots s
		  JOIN collector_instances ci
		    ON ci.workspace_id = s.workspace_id AND ci.id = s.collector_id
		  JOIN collector_batches b
		    ON b.workspace_id = s.workspace_id
		   AND b.collector_id = s.collector_id
		   AND b.snapshot_id = s.snapshot_id
		  JOIN collector_outbox o
		    ON o.workspace_id = b.workspace_id AND o.batch_row_id = b.id
		 WHERE s.workspace_id = ?
		   AND (s.complete = false OR s.gap_blocked)
		 GROUP BY s.id, s.collector_id, ci.integration_id, s.snapshot_id, s.scope_key,
		          s.object_class, s.generation, s.expected_chunks, s.gap_blocked
		HAVING MAX(o.attempt_count) > ?
		 ORDER BY s.collector_id, s.snapshot_id`,
		q.WS, StuckSnapshotDeferralThreshold).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	stuck := make([]StuckSnapshot, 0, len(rows))
	for _, row := range rows {
		reason := "incomplete"
		switch {
		case row.GapBlocked:
			reason = "gap_blocked"
		case row.ReceivedChunks < row.ExpectedChunks:
			reason = "missing_chunk"
		}
		stuck = append(stuck, StuckSnapshot{
			CollectorID:            row.CollectorID,
			IntegrationID:          row.IntegrationID,
			SnapshotID:             row.SnapshotID,
			Scope:                  row.Scope,
			Class:                  row.Class,
			Generation:             row.Generation,
			ExpectedChunks:         row.ExpectedChunks,
			ReceivedChunks:         row.ReceivedChunks,
			FailedOrIsolatedChunks: row.FailedOrIsolatedChunks,
			FirstDeferredAt:        T(row.FirstDeferredAt),
			LastAttempt:            T(row.LastAttempt),
			Deferrals:              row.Deferrals,
			Reason:                 reason,
		})
	}
	var superseded []SupersededBatchCount
	err = q.DB().Raw(`
		SELECT b.collector_id, ci.integration_id, count(*)::int AS count
		  FROM collector_batches b
		  JOIN collector_instances ci
		    ON ci.workspace_id = b.workspace_id AND ci.id = b.collector_id
		 WHERE b.workspace_id = ? AND b.superseded_at IS NOT NULL
		 GROUP BY b.collector_id, ci.integration_id
		 ORDER BY b.collector_id`, q.WS).Scan(&superseded).Error
	if err != nil {
		return nil, err
	}
	if superseded == nil {
		superseded = []SupersededBatchCount{}
	}
	return &CollectorDeferralBlock{
		DeferralThreshold: StuckSnapshotDeferralThreshold,
		StuckSnapshots:    stuck,
		SupersededBatches: superseded,
	}, nil
}
