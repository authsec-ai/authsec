package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// ErrCollectorStopped is returned when a test stops the worker after the
// barrier is acquired. The job stays running and the barrier stays projecting.
var ErrCollectorStopped = errors.New("collector projection stopped after the barrier was acquired")

// CollectorGraphWriter is what a Linux, Kubernetes or AD normalizer implements.
// WP-A3 ships SupportWriter and FixtureWriter. The normalizers themselves are
// WP-A4.
type CollectorGraphWriter interface {
	Project(tx *gorm.DB, in CollectorPass) error
}

// CollectorPass is one fenced publication of collector facts.
type CollectorPass struct {
	WorkspaceID   uuid.UUID
	IntegrationID uuid.UUID
	CollectorID   uuid.UUID
	ScanRunID     uuid.UUID
	ScanRunIDs    []uuid.UUID
	Mode          string
	ScopeKey      string
	ObjectClass   string
	Authoritative bool
	Generation    int64
	Sequence      int64
	Epoch         uuid.UUID
	// SnapshotID is the logical collector snapshot. Nil for a runtime batch.
	// Absence and the fence use this id, not the batch sequence.
	SnapshotID *uuid.UUID
	At         time.Time
	Repo       repositories.IGAGraphRepository
}

// OutboxKindCandidateEval is the enqueue-only handoff to policy evaluation.
// The collector claimer does not take it.
const OutboxKindCandidateEval = "candidate_eval"

type collectorBatch struct {
	OutboxID      uuid.UUID
	WorkspaceID   uuid.UUID
	IntegrationID uuid.UUID
	CollectorID   uuid.UUID
	BatchRowID    uuid.UUID
	Epoch         uuid.UUID
	Sequence      int64
	ScanRunID     uuid.UUID
	SnapshotID    *uuid.UUID
	AvailableAt   time.Time
	Mode          string
	ScopeKey      string
	ObjectClass   string
	Generation    int64
	Authoritative bool
	Deferred      bool
}

type collectorWatermark struct {
	found       bool
	generation  int64
	sequence    int64
	reconciled  bool
	epoch       uuid.UUID
	epochSet    bool
	snapshot    uuid.UUID
	snapshotSet bool
}

// A watermark read says whether this pass may write the graph.
const (
	watermarkProject = iota
	watermarkStale
	watermarkReplay
)

// projectCollectorOnce claims one microbatch, projects the union of its runs,
// and publishes them under the workspace fence.
func (s *ProjectionService) projectCollectorOnce(ctx context.Context) (bool, error) {
	batches, err := s.claimCollectorGroup(ctx)
	if err != nil || len(batches) == 0 {
		return false, err
	}
	if batches[0].Deferred {
		return true, s.deferOutbox(ctx, batches, s.now().Add(CollectorMicrobatch()))
	}
	for i := range batches {
		if batches[i].ScanRunID != uuid.Nil {
			continue
		}
		id, err := s.ensureCollectorRun(ctx, batches[i])
		if err != nil {
			_ = s.releaseOutbox(ctx, batches, "failed", err.Error())
			return true, err
		}
		batches[i].ScanRunID = id
		if err := s.db.WithContext(ctx).Exec(`
			UPDATE collector_batches SET iga_scan_run_id = ?
			 WHERE workspace_id = ? AND id = ? AND iga_scan_run_id IS NULL`,
			id, batches[i].WorkspaceID, batches[i].BatchRowID).Error; err != nil {
			return true, err
		}
	}
	head := batches[0]
	gen := head.Generation
	if gen < 1 {
		gen = 1
	}
	job := &models.IGAProjectionJob{
		WorkspaceID: head.WorkspaceID, IGAScanRunID: &head.ScanRunID,
		Generation: int(gen), Status: models.ProjectionQueued,
	}
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return s.jobs.EnqueueTx(tx, job)
	}); err != nil {
		_ = s.requeueOutbox(ctx, batches, s.now())
		return true, err
	}
	claimed, err := s.jobs.ClaimCollectorRun(s.owner, head.ScanRunID, s.lease, s.now())
	if err != nil {
		_ = s.requeueOutbox(ctx, batches, s.now())
		return false, err
	}
	if claimed == nil {
		// An abandoned job still conflicts with EnqueueTx, so Claim returns
		// nothing and a requeue would reset available_at every tick.
		if fail, reason := s.collectorOutboxShouldFail(ctx, head); fail {
			_ = s.releaseOutbox(ctx, batches, "failed", reason)
			return false, nil
		}
		_ = s.requeueOutbox(ctx, batches, s.now())
		return false, nil
	}
	version, err := s.pipeline.AcquireForCollectorProjection(
		head.WorkspaceID, head.ScanRunID, claimed.ID, s.barrierLease, s.now())
	if err != nil {
		_ = s.jobs.Requeue(claimed.ID, s.owner, claimed.LeaseVersion)
		_ = s.requeueOutbox(ctx, batches, s.now())
		if errors.Is(err, repositories.ErrPipelineLost) {
			return false, nil
		}
		return true, err
	}
	if s.beforeCollectorTx != nil {
		s.beforeCollectorTx()
	}
	if s.stopAfterBarrier {
		return true, ErrCollectorStopped
	}
	stop := s.heartbeatCollector(ctx, claimed, version)
	defer stop()
	pubErr := s.publishCollector(ctx, batches, claimed, version)
	if pubErr == nil {
		return true, nil
	}
	if errors.Is(pubErr, repositories.ErrPipelineLost) {
		return true, pubErr
	}
	if claimed.Attempts >= s.maxAttempts {
		return true, s.abandonCollector(ctx, claimed, version, batches, pubErr.Error())
	}
	_ = s.jobs.Fail(claimed.ID, s.owner, claimed.LeaseVersion, pubErr.Error())
	_ = s.requeueOutbox(ctx, batches, s.now().Add(repositories.ProjectionRetryBackoff))
	return true, pubErr
}

func (s *ProjectionService) claimCollectorGroup(ctx context.Context) ([]collectorBatch, error) {
	now := s.now()
	until := now.Add(s.lease)
	var head collectorBatch
	var released bool
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var outboxID, ws, integ, collector, batchID uuid.UUID
		err := tx.Raw(`UPDATE collector_outbox SET
			state = 'leased', lease_owner = ?, leased_until = ?,
			attempt_count = attempt_count + 1, updated_at = ?
			WHERE id = (
				SELECT o.id FROM collector_outbox o
				JOIN collector_batches b
				  ON b.workspace_id = o.workspace_id AND b.id = o.batch_row_id
				WHERE o.job_kind = ?
				  AND b.receipt_state = 'accepted'
				  AND b.projection_state = 'queued'
				  AND b.superseded_at IS NULL
				  AND ((o.state = 'ready' AND o.available_at <= ?)
				    OR (o.state = 'leased' AND o.leased_until IS NOT NULL AND o.leased_until < ?))
				ORDER BY o.available_at, b.sequence
				FOR UPDATE OF o SKIP LOCKED
				LIMIT 1)
			RETURNING id, workspace_id, integration_id, collector_id, batch_row_id`,
			s.owner, until, now, models.OutboxKindCollectorProject, now, now).
			Row().Scan(&outboxID, &ws, &integ, &collector, &batchID)
		if err != nil {
			return err
		}
		loaded, err := loadCollectorBatch(tx, outboxID, ws, integ, collector, batchID)
		if err != nil {
			return err
		}
		head = loaded
		if head.Authoritative && head.SnapshotID != nil {
			got, err := claimWholeSnapshot(tx, head, s.owner, until, now)
			if err != nil {
				return err
			}
			if !got.ok {
				// Give the rows back in this transaction. A missing chunk waits
				// out the microbatch. The replica that holds the lowest sequence
				// retries at once so the others do not split the snapshot.
				retry := now.Add(CollectorMicrobatch())
				if got.leader {
					retry = now
				}
				if err := releaseSnapshotClaim(tx, head, s.owner, retry); err != nil {
					return err
				}
				released = true
			}
			return nil
		}
		return claimCollectorSiblings(tx, head, s.owner, until, now)
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if released {
		return nil, nil
	}
	return listOwnedCollectorGroup(s.db.WithContext(ctx), head, s.owner)
}

// snapshotClaim is the result of trying to lease every chunk of one snapshot.
type snapshotClaim struct {
	ok     bool
	leader bool
}

// claimWholeSnapshot leases every outbox row of an authoritative snapshot.
// There is no available_at window: a chunk that is merely not due yet is
// still part of the snapshot. ok is false when a chunk is missing or another
// owner holds one. The caller gives back whatever this transaction took.
func claimWholeSnapshot(tx *gorm.DB, head collectorBatch, owner string, until, now time.Time) (snapshotClaim, error) {
	var expected int
	err := tx.Raw(`SELECT expected_chunks FROM collector_snapshots
		WHERE workspace_id = ? AND collector_id = ? AND snapshot_id = ?`,
		head.WorkspaceID, head.CollectorID, *head.SnapshotID).Row().Scan(&expected)
	if err != nil {
		return snapshotClaim{}, err
	}
	var pending int
	if err := tx.Raw(`SELECT count(*) FROM collector_outbox o
		JOIN collector_batches b ON b.workspace_id = o.workspace_id AND b.id = o.batch_row_id
		WHERE o.job_kind = ?
		  AND o.workspace_id = ? AND o.collector_id = ? AND o.integration_id = ?
		  AND b.epoch = ? AND b.snapshot_id = ?
		  AND b.receipt_state = 'accepted' AND b.projection_state = 'queued'
		  AND b.superseded_at IS NULL
		  AND o.state IN ('ready', 'leased')`,
		models.OutboxKindCollectorProject,
		head.WorkspaceID, head.CollectorID, head.IntegrationID, head.Epoch, *head.SnapshotID).
		Scan(&pending).Error; err != nil {
		return snapshotClaim{}, err
	}
	if pending < expected {
		return snapshotClaim{}, nil
	}
	// The head row is already leased by owner. Do not increment its attempt
	// again. SKIP LOCKED skips a chunk another replica holds instead of waiting.
	if err := tx.Exec(`UPDATE collector_outbox SET
		state = 'leased', lease_owner = ?, leased_until = ?,
		attempt_count = CASE WHEN lease_owner = ? AND state = 'leased' THEN attempt_count ELSE attempt_count + 1 END,
		updated_at = ?
		WHERE id IN (
			SELECT o.id FROM collector_outbox o
			JOIN collector_batches b
			  ON b.workspace_id = o.workspace_id AND b.id = o.batch_row_id
			WHERE o.job_kind = ?
			  AND o.workspace_id = ? AND o.collector_id = ? AND o.integration_id = ?
			  AND b.epoch = ? AND b.snapshot_id = ?
			  AND b.receipt_state = 'accepted' AND b.projection_state = 'queued'
			  AND b.superseded_at IS NULL
			  AND o.state IN ('ready', 'leased')
			  AND (o.lease_owner IS NULL OR o.lease_owner = ?
			    OR o.leased_until IS NULL OR o.leased_until < ?)
			FOR UPDATE OF o SKIP LOCKED)`,
		owner, until, owner, now,
		models.OutboxKindCollectorProject,
		head.WorkspaceID, head.CollectorID, head.IntegrationID, head.Epoch, *head.SnapshotID,
		owner, now).Error; err != nil {
		return snapshotClaim{}, err
	}
	var owned int
	if err := tx.Raw(`SELECT count(*) FROM collector_outbox o
		JOIN collector_batches b ON b.workspace_id = o.workspace_id AND b.id = o.batch_row_id
		WHERE o.lease_owner = ? AND o.state = 'leased' AND o.job_kind = ?
		  AND o.workspace_id = ? AND o.collector_id = ? AND b.epoch = ? AND b.snapshot_id = ?`,
		owner, models.OutboxKindCollectorProject, head.WorkspaceID, head.CollectorID, head.Epoch, *head.SnapshotID).
		Scan(&owned).Error; err != nil {
		return snapshotClaim{}, err
	}
	if owned >= expected && owned >= pending {
		return snapshotClaim{ok: true}, nil
	}
	leader, err := snapshotClaimLeader(tx, head, owner)
	if err != nil {
		return snapshotClaim{}, err
	}
	return snapshotClaim{leader: leader}, nil
}

func snapshotClaimLeader(tx *gorm.DB, head collectorBatch, owner string) (bool, error) {
	var pending, owned sql.NullInt64
	err := tx.Raw(`SELECT MIN(b.sequence) FROM collector_outbox o
		JOIN collector_batches b ON b.workspace_id = o.workspace_id AND b.id = o.batch_row_id
		WHERE o.job_kind = ?
		  AND o.workspace_id = ? AND o.collector_id = ? AND b.epoch = ? AND b.snapshot_id = ?
		  AND b.projection_state = 'queued' AND b.superseded_at IS NULL
		  AND o.state IN ('ready', 'leased')`,
		models.OutboxKindCollectorProject, head.WorkspaceID, head.CollectorID, head.Epoch, *head.SnapshotID).
		Row().Scan(&pending)
	if err != nil {
		return false, err
	}
	err = tx.Raw(`SELECT MIN(b.sequence) FROM collector_outbox o
		JOIN collector_batches b ON b.workspace_id = o.workspace_id AND b.id = o.batch_row_id
		WHERE o.lease_owner = ? AND o.state = 'leased' AND o.job_kind = ?
		  AND o.workspace_id = ? AND o.collector_id = ? AND b.epoch = ? AND b.snapshot_id = ?`,
		owner, models.OutboxKindCollectorProject, head.WorkspaceID, head.CollectorID, head.Epoch, *head.SnapshotID).
		Row().Scan(&owned)
	if err != nil {
		return false, err
	}
	return pending.Valid && owned.Valid && owned.Int64 == pending.Int64, nil
}

func releaseSnapshotClaim(tx *gorm.DB, head collectorBatch, owner string, until time.Time) error {
	return tx.Exec(`UPDATE collector_outbox o SET
		state = 'ready', lease_owner = NULL, leased_until = NULL, available_at = ?, updated_at = now()
		FROM collector_batches b
		WHERE b.workspace_id = o.workspace_id AND b.id = o.batch_row_id
		  AND o.lease_owner = ? AND o.state = 'leased' AND o.job_kind = ?
		  AND o.workspace_id = ? AND o.collector_id = ? AND b.epoch = ? AND b.snapshot_id = ?`,
		until, owner, models.OutboxKindCollectorProject,
		head.WorkspaceID, head.CollectorID, head.Epoch, *head.SnapshotID).Error
}

func claimCollectorSiblings(tx *gorm.DB, head collectorBatch, owner string, until, now time.Time) error {
	window := head.AvailableAt.Add(CollectorMicrobatch())
	return tx.Exec(`UPDATE collector_outbox SET
		state = 'leased', lease_owner = ?, leased_until = ?,
		attempt_count = attempt_count + 1, updated_at = ?
		WHERE id IN (
			SELECT o.id FROM collector_outbox o
			JOIN collector_batches b
			  ON b.workspace_id = o.workspace_id AND b.id = o.batch_row_id
			WHERE o.job_kind = ?
			  AND o.workspace_id = ? AND o.collector_id = ? AND o.integration_id = ?
			  AND b.epoch = ?
			  AND b.receipt_state = 'accepted'
			  AND b.projection_state = 'queued'
			  AND b.superseded_at IS NULL
			  AND b.snapshot_id IS NOT DISTINCT FROM ?::uuid
			  AND o.id <> ?
			  AND ((o.state = 'ready' AND o.available_at <= ?)
			    OR (o.state = 'leased' AND o.leased_until IS NOT NULL AND o.leased_until < ?))
			FOR UPDATE OF o SKIP LOCKED)`,
		owner, until, now,
		models.OutboxKindCollectorProject,
		head.WorkspaceID, head.CollectorID, head.IntegrationID, head.Epoch,
		head.SnapshotID, head.OutboxID, window, now).Error
}

func listOwnedCollectorGroup(db *gorm.DB, head collectorBatch, owner string) ([]collectorBatch, error) {
	rows, err := db.Raw(`SELECT o.id, o.workspace_id, o.integration_id, o.collector_id, o.batch_row_id,
		b.epoch, b.sequence, b.iga_scan_run_id, b.snapshot_id, o.available_at
		FROM collector_outbox o
		JOIN collector_batches b ON b.workspace_id = o.workspace_id AND b.id = o.batch_row_id
		WHERE o.lease_owner = ? AND o.state = 'leased' AND o.job_kind = ?
		  AND o.workspace_id = ? AND o.collector_id = ? AND o.integration_id = ?
		  AND b.epoch = ?
		  AND b.snapshot_id IS NOT DISTINCT FROM ?::uuid`,
		owner, models.OutboxKindCollectorProject,
		head.WorkspaceID, head.CollectorID, head.IntegrationID, head.Epoch, head.SnapshotID).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []collectorBatch
	for rows.Next() {
		var b collectorBatch
		var epoch uuid.UUID
		var runID, snapID nullUUID
		if err := rows.Scan(&b.OutboxID, &b.WorkspaceID, &b.IntegrationID, &b.CollectorID, &b.BatchRowID,
			&epoch, &b.Sequence, &runID, &snapID, &b.AvailableAt); err != nil {
			return nil, err
		}
		b.Epoch = epoch
		if runID.Valid {
			b.ScanRunID = runID.UUID
		}
		if snapID.Valid {
			id := snapID.UUID
			b.SnapshotID = &id
		}
		b.Mode, b.ScopeKey, b.ObjectClass = head.Mode, head.ScopeKey, head.ObjectClass
		b.Generation, b.Authoritative, b.Deferred = head.Generation, head.Authoritative, head.Deferred
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Sequence < out[j].Sequence })
	return out, nil
}

func loadCollectorBatch(tx *gorm.DB, outboxID, ws, integ, collector, batchID uuid.UUID) (collectorBatch, error) {
	var b collectorBatch
	var epoch uuid.UUID
	var runID, snapID nullUUID
	err := tx.Raw(`SELECT b.epoch, b.sequence, b.iga_scan_run_id, b.snapshot_id, o.available_at
		FROM collector_batches b
		JOIN collector_outbox o ON o.workspace_id = b.workspace_id AND o.batch_row_id = b.id
		WHERE b.workspace_id = ? AND b.id = ? AND o.id = ?`,
		ws, batchID, outboxID).Row().Scan(&epoch, &b.Sequence, &runID, &snapID, &b.AvailableAt)
	if err != nil {
		return collectorBatch{}, err
	}
	b.OutboxID, b.WorkspaceID, b.IntegrationID, b.CollectorID, b.BatchRowID = outboxID, ws, integ, collector, batchID
	b.Epoch = epoch
	if runID.Valid {
		b.ScanRunID = runID.UUID
	}
	if snapID.Valid {
		id := snapID.UUID
		b.SnapshotID = &id
	}
	if err := fillCollectorMode(tx, &b); err != nil {
		return collectorBatch{}, err
	}
	return b, nil
}

// fillCollectorMode reads the batch's own snapshot. A runtime batch (no
// snapshot_id) is never authoritative, even when the epoch also holds one.
// An incomplete snapshot defers only the batches that name it.
func fillCollectorMode(tx *gorm.DB, b *collectorBatch) error {
	if b.SnapshotID == nil {
		b.Mode, b.ScopeKey, b.ObjectClass = "runtime_batch", "collector", ""
		b.Authoritative = false
		return nil
	}
	var scope, class string
	var generation int64
	var complete, gap bool
	err := tx.Raw(`SELECT scope_key, object_class, generation, complete, gap_blocked
		FROM collector_snapshots
		WHERE workspace_id = ? AND collector_id = ? AND snapshot_id = ?`,
		b.WorkspaceID, b.CollectorID, *b.SnapshotID).Row().Scan(&scope, &class, &generation, &complete, &gap)
	if errors.Is(err, sql.ErrNoRows) {
		b.Deferred = true
		b.Mode = "configuration_snapshot"
		return nil
	}
	if err != nil {
		return err
	}
	b.ScopeKey, b.ObjectClass, b.Generation = scope, class, generation
	b.Mode = "configuration_snapshot"
	if !complete || gap {
		b.Deferred = true
		return nil
	}
	b.Authoritative = true
	return nil
}

func (s *ProjectionService) publishCollector(ctx context.Context, batches []collectorBatch, job *models.IGAProjectionJob, version int64) error {
	head := batches[0]
	runIDs := make([]uuid.UUID, 0, len(batches))
	var maxSeq int64
	refs := make([]models.SourceManifestRef, 0, len(batches))
	for _, b := range batches {
		runIDs = append(runIDs, b.ScanRunID)
		if b.Sequence > maxSeq {
			maxSeq = b.Sequence
		}
		id := b.ScanRunID
		refs = append(refs, models.SourceManifestRef{
			Kind: models.ManifestKindIGAScanRun, ID: id, IntegrationID: &head.IntegrationID,
		})
	}
	pass := CollectorPass{
		WorkspaceID: head.WorkspaceID, IntegrationID: head.IntegrationID, CollectorID: head.CollectorID,
		ScanRunID: head.ScanRunID, ScanRunIDs: runIDs,
		Mode: head.Mode, ScopeKey: head.ScopeKey, ObjectClass: head.ObjectClass,
		Authoritative: head.Authoritative, Generation: head.Generation, Sequence: maxSeq,
		Epoch: head.Epoch, SnapshotID: head.SnapshotID, At: s.now(), Repo: s.graph,
	}
	fence := s.collectorFence(job, version)
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := s.pipeline.AssertHeldTx(tx, fence); err != nil {
			return err
		}
		if err := s.jobs.AssertOwnedTx(tx, job.ID, s.owner, job.LeaseVersion); err != nil {
			return err
		}
		if err := assertOutboxLease(tx, batches, s.owner, pass.At); err != nil {
			return err
		}
		if err := tx.SavePoint("collector_pub").Error; err != nil {
			return err
		}
		var existing int
		if err := tx.Raw(`SELECT count(*) FROM iga_publication WHERE workspace_id = ? AND iga_scan_run_id = ?`,
			head.WorkspaceID, head.ScanRunID).Scan(&existing).Error; err != nil {
			return err
		}
		if existing > 0 {
			if err := tx.RollbackTo("collector_pub").Error; err != nil {
				return err
			}
			return s.finishPublished(tx, batches, job, fence, pass, 0)
		}
		decision, wm, err := readCollectorWatermark(tx, pass)
		if err != nil {
			return err
		}
		if decision == watermarkStale {
			if err := tx.RollbackTo("collector_pub").Error; err != nil {
				return err
			}
			return s.finishSuperseded(tx, batches, job, fence, pass.At)
		}
		if decision == watermarkReplay {
			if err := tx.RollbackTo("collector_pub").Error; err != nil {
				return err
			}
			rev, err := snapshotPublicationRev(tx, pass)
			if err != nil {
				return err
			}
			return s.finishPublished(tx, batches, job, fence, pass, rev)
		}
		if err := expandSnapshotRuns(tx, &pass, &refs); err != nil {
			return err
		}
		writer := s.collector
		if writer == nil {
			writer = ProviderWriter{}
		}
		if err := writer.Project(tx, pass); err != nil {
			return err
		}
		rev, err := s.graph.NextRevision(tx, head.WorkspaceID)
		if err != nil {
			return err
		}
		manifest, err := collectorCloudManifest(tx, s.graph, pass)
		if err != nil {
			return err
		}
		v2, err := json.Marshal(refs)
		if err != nil {
			return err
		}
		if err := s.graph.InsertPublication(tx, &models.IGAPublication{
			WorkspaceID: head.WorkspaceID, Rev: rev, PublishedAt: pass.At,
			IGAScanRunID: &head.ScanRunID, Manifest: manifest, SourceManifestV2: v2,
		}); err != nil {
			if publicationConflict(err) {
				if rb := tx.RollbackTo("collector_pub").Error; rb != nil {
					return rb
				}
				return s.finishPublished(tx, batches, job, fence, pass, 0)
			}
			return err
		}
		if err := writeCollectorWatermark(tx, s.graph, pass, wm); err != nil {
			return err
		}
		if err := s.enqueueCandidateEval(tx, head, rev); err != nil {
			return err
		}
		return s.finishPublished(tx, batches, job, fence, pass, rev)
	})
}

func (s *ProjectionService) finishPublished(tx *gorm.DB, batches []collectorBatch, job *models.IGAProjectionJob, fence repositories.PipelineFence, pass CollectorPass, rev int64) error {
	if rev == 0 {
		if err := tx.Raw(`SELECT rev FROM iga_publication WHERE workspace_id = ? AND iga_scan_run_id = ?`,
			pass.WorkspaceID, pass.ScanRunID).Scan(&rev).Error; err != nil {
			return err
		}
	}
	for _, b := range batches {
		if err := tx.Exec(`UPDATE collector_outbox
			SET state = 'done', lease_owner = NULL, leased_until = NULL, last_error = '', updated_at = ?
			WHERE workspace_id = ? AND id = ? AND lease_owner = ?`,
			pass.At, b.WorkspaceID, b.OutboxID, s.owner).Error; err != nil {
			return err
		}
		// Keep each batch's own iga_scan_run_id. graph_revision records which
		// publication covered it.
		if err := tx.Exec(`UPDATE collector_batches
			SET projection_state = 'published', receipt_state = 'published', graph_revision = ?
			WHERE workspace_id = ? AND id = ?`,
			rev, b.WorkspaceID, b.BatchRowID).Error; err != nil {
			return err
		}
	}
	if err := s.jobs.CompleteTx(tx, job.ID, s.owner, job.LeaseVersion); err != nil {
		return err
	}
	return s.pipeline.ReleaseTx(tx, fence)
}

func (s *ProjectionService) finishSuperseded(tx *gorm.DB, batches []collectorBatch, job *models.IGAProjectionJob, fence repositories.PipelineFence, at time.Time) error {
	for _, b := range batches {
		if err := tx.Exec(`UPDATE collector_outbox
			SET state = 'done', lease_owner = NULL, leased_until = NULL, last_error = 'superseded', updated_at = ?
			WHERE workspace_id = ? AND id = ? AND lease_owner = ?`,
			at, b.WorkspaceID, b.OutboxID, s.owner).Error; err != nil {
			return err
		}
		if err := tx.Exec(`UPDATE collector_batches SET superseded_at = ?
			WHERE workspace_id = ? AND id = ?`,
			at, b.WorkspaceID, b.BatchRowID).Error; err != nil {
			return err
		}
	}
	if err := s.jobs.CompleteTx(tx, job.ID, s.owner, job.LeaseVersion); err != nil {
		return err
	}
	return s.pipeline.ReleaseTx(tx, fence)
}

func (s *ProjectionService) abandonCollector(ctx context.Context, job *models.IGAProjectionJob, version int64, batches []collectorBatch, reason string) error {
	fence := s.collectorFence(job, version)
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := s.jobs.AbandonTx(tx, job.ID, s.owner, job.LeaseVersion, reason); err != nil {
			return err
		}
		if err := s.pipeline.AbandonTx(tx, fence, reason); err != nil {
			return err
		}
		for _, b := range batches {
			if err := tx.Exec(`UPDATE collector_outbox
				SET state = 'failed', last_error = ?, lease_owner = NULL, leased_until = NULL, updated_at = now()
				WHERE workspace_id = ? AND id = ?`,
				reason, b.WorkspaceID, b.OutboxID).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *ProjectionService) collectorFence(job *models.IGAProjectionJob, version int64) repositories.PipelineFence {
	run := uuid.Nil
	if job.IGAScanRunID != nil {
		run = *job.IGAScanRunID
	}
	return repositories.PipelineFence{
		WorkspaceID: job.WorkspaceID,
		Phase:       models.PipelineProjecting,
		RunID:       run,
		Version:     version,
		Holder:      models.PipelineJobHolder(job.ID),
		RunKind:     models.RunKindCollector,
	}
}

func (s *ProjectionService) heartbeatCollector(ctx context.Context, job *models.IGAProjectionJob, version int64) func() {
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(s.lease / 3)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				if err := s.jobs.Renew(job.ID, s.owner, job.LeaseVersion, s.lease); err != nil {
					return
				}
				if err := s.pipeline.RenewHeld(s.collectorFence(job, version), s.barrierLease, s.now()); err != nil {
					return
				}
			}
		}
	}()
	return func() { close(done) }
}

func assertOutboxLease(tx *gorm.DB, batches []collectorBatch, owner string, at time.Time) error {
	ids := make([]uuid.UUID, len(batches))
	for i, b := range batches {
		ids[i] = b.OutboxID
	}
	res := tx.Exec(`UPDATE collector_outbox SET updated_at = ?
		WHERE workspace_id = ? AND state = 'leased' AND lease_owner = ? AND id IN ?`,
		at, batches[0].WorkspaceID, owner, ids)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected != int64(len(batches)) {
		return fmt.Errorf("%w: collector outbox lease lost", repositories.ErrPipelineLost)
	}
	return nil
}

func readCollectorWatermark(tx *gorm.DB, pass CollectorPass) (int, collectorWatermark, error) {
	var gen, seq int64
	var reconciled bool
	var epoch, snap nullUUID
	err := tx.Raw(`SELECT last_generation, ordering_sequence, reconciled, ordering_epoch, ordering_snapshot
		FROM iga_projection_state
		WHERE workspace_id = ? AND integration_id = ? AND partition_key = ?
		FOR UPDATE`,
		pass.WorkspaceID, pass.IntegrationID, collectorPartition(pass)).Row().Scan(&gen, &seq, &reconciled, &epoch, &snap)
	if errors.Is(err, sql.ErrNoRows) {
		return watermarkProject, collectorWatermark{}, nil
	}
	if err != nil {
		return 0, collectorWatermark{}, err
	}
	wm := collectorWatermark{
		found: true, generation: gen, sequence: seq, reconciled: reconciled,
		epochSet: epoch.Valid, snapshotSet: snap.Valid,
	}
	if epoch.Valid {
		wm.epoch = epoch.UUID
	}
	if snap.Valid {
		wm.snapshot = snap.UUID
	}
	// Runtime batches never end support and never lose to a snapshot.
	// The fence compares snapshot generations. The same snapshot_id is a
	// replay. A different snapshot of the same generation is not stale:
	// batch sequence is not a tie-break and must not drop chunks.
	if !pass.Authoritative {
		return watermarkProject, wm, nil
	}
	if pass.SnapshotID != nil && wm.snapshotSet && wm.snapshot == *pass.SnapshotID && wm.reconciled {
		return watermarkReplay, wm, nil
	}
	if pass.Generation < gen {
		return watermarkStale, wm, nil
	}
	return watermarkProject, wm, nil
}

// expandSnapshotRuns replaces the pass's runs with every batch of the snapshot
// so absence is computed from the whole snapshot, including a chunk this
// statement did not originate.
func expandSnapshotRuns(tx *gorm.DB, pass *CollectorPass, refs *[]models.SourceManifestRef) error {
	if !pass.Authoritative || pass.SnapshotID == nil {
		return nil
	}
	rows, err := tx.Raw(`SELECT iga_scan_run_id FROM collector_batches
		WHERE workspace_id = ? AND collector_id = ? AND epoch = ? AND snapshot_id = ? AND iga_scan_run_id IS NOT NULL`,
		pass.WorkspaceID, pass.CollectorID, pass.Epoch, *pass.SnapshotID).Rows()
	if err != nil {
		return err
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	pass.ScanRunIDs = ids
	out := make([]models.SourceManifestRef, 0, len(ids))
	for _, id := range ids {
		id := id
		out = append(out, models.SourceManifestRef{
			Kind: models.ManifestKindIGAScanRun, ID: id, IntegrationID: &pass.IntegrationID,
		})
	}
	*refs = out
	return nil
}

func snapshotPublicationRev(tx *gorm.DB, pass CollectorPass) (int64, error) {
	var rev int64
	if pass.SnapshotID != nil {
		err := tx.Raw(`SELECT COALESCE(MAX(graph_revision), 0) FROM collector_batches
			WHERE workspace_id = ? AND collector_id = ? AND epoch = ? AND snapshot_id = ?`,
			pass.WorkspaceID, pass.CollectorID, pass.Epoch, *pass.SnapshotID).Scan(&rev).Error
		if err != nil {
			return 0, err
		}
		if rev > 0 {
			return rev, nil
		}
	}
	err := tx.Raw(`SELECT COALESCE(MAX(p.rev), 0) FROM iga_publication p
		JOIN iga_projection_state s
		  ON s.workspace_id = p.workspace_id AND s.last_iga_scan_run_id = p.iga_scan_run_id
		WHERE s.workspace_id = ? AND s.integration_id = ? AND s.partition_key = ?`,
		pass.WorkspaceID, pass.IntegrationID, collectorPartition(pass)).Scan(&rev).Error
	return rev, err
}

func writeCollectorWatermark(tx *gorm.DB, repo repositories.IGAGraphRepository, pass CollectorPass, wm collectorWatermark) error {
	scopeID, err := scanUUID(tx, `SELECT estate_scope_id FROM collector_instances
		WHERE workspace_id = ? AND id = ?`, pass.WorkspaceID, pass.CollectorID)
	if err != nil {
		return err
	}
	if scopeID == uuid.Nil {
		return fmt.Errorf("collector %s has no estate scope", pass.CollectorID)
	}
	gen, seq := pass.Generation, pass.Sequence
	reconciled := pass.Authoritative
	var epoch, snap *uuid.UUID
	if pass.Authoritative {
		e := pass.Epoch
		epoch = &e
		if pass.SnapshotID != nil {
			id := *pass.SnapshotID
			snap = &id
		}
	} else if wm.found {
		gen, seq, reconciled = wm.generation, wm.sequence, wm.reconciled
		if wm.epochSet {
			e := wm.epoch
			epoch = &e
		}
		if wm.snapshotSet {
			id := wm.snapshot
			snap = &id
		}
	} else {
		gen, seq = 0, 0
	}
	return repo.UpsertProjectionState(tx, &models.IGAProjectionState{
		WorkspaceID: pass.WorkspaceID, EstateScopeID: scopeID,
		IntegrationID: &pass.IntegrationID, PartitionKey: collectorPartition(pass),
		ObjectClass: pass.ObjectClass, LastIGAScanRunID: &pass.ScanRunID,
		LastGeneration: gen, OrderingSequence: seq, OrderingEpoch: epoch, OrderingSnapshot: snap,
		CoverageState: "reached", Reconciled: reconciled, UpdatedAt: pass.At,
	})
}

func collectorCloudManifest(tx *gorm.DB, repo repositories.IGAGraphRepository, pass CollectorPass) (json.RawMessage, error) {
	prev, err := repo.LatestManifest(tx, pass.WorkspaceID)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	if len(prev) > 0 && string(prev) != "null" {
		_ = json.Unmarshal(prev, &m)
	}
	m[collectorManifestKey(pass)] = pass.ScanRunID.String()
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func publicationConflict(err error) bool {
	return err != nil && strings.Contains(err.Error(), "uq_iga_publication_iga_run")
}

func (s *ProjectionService) ensureCollectorRun(ctx context.Context, b collectorBatch) (uuid.UUID, error) {
	id := uuid.New()
	err := s.db.WithContext(ctx).Exec(`
		INSERT INTO iga_scan_runs
			(id, workspace_id, integration_id, mode, generation, status, is_authoritative, started_at, completed_at)
		VALUES (?, ?, ?, ?,
		        COALESCE((SELECT max(generation) + 1 FROM iga_scan_runs WHERE workspace_id = ? AND integration_id = ?), 1),
		        'succeeded', ?, now(), now())`,
		id, b.WorkspaceID, b.IntegrationID, b.Mode, b.WorkspaceID, b.IntegrationID, b.Authoritative).Error
	if err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

func (s *ProjectionService) enqueueCandidateEval(tx *gorm.DB, b collectorBatch, rev int64) error {
	return tx.Exec(`
		INSERT INTO collector_outbox
			(id, workspace_id, integration_id, collector_id, batch_row_id, job_kind, dedupe_key, state, available_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'ready', now())
		ON CONFLICT (workspace_id, dedupe_key) DO NOTHING`,
		uuid.New(), b.WorkspaceID, b.IntegrationID, b.CollectorID, b.BatchRowID,
		OutboxKindCandidateEval, fmt.Sprintf("rev:%s:%d", b.WorkspaceID, rev)).Error
}

func (s *ProjectionService) releaseOutbox(ctx context.Context, batches []collectorBatch, state, reason string) error {
	for _, b := range batches {
		if err := s.db.WithContext(ctx).Exec(`
			UPDATE collector_outbox SET state = ?, last_error = ?, lease_owner = NULL, leased_until = NULL, updated_at = now()
			 WHERE workspace_id = ? AND id = ?`, state, reason, b.WorkspaceID, b.OutboxID).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *ProjectionService) requeueOutbox(ctx context.Context, batches []collectorBatch, until time.Time) error {
	for _, b := range batches {
		if err := s.db.WithContext(ctx).Exec(`
			UPDATE collector_outbox
			   SET state = 'ready', lease_owner = NULL, leased_until = NULL, available_at = ?, updated_at = now()
			 WHERE workspace_id = ? AND id = ? AND lease_owner = ?`,
			until, b.WorkspaceID, b.OutboxID, s.owner).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *ProjectionService) deferOutbox(ctx context.Context, batches []collectorBatch, until time.Time) error {
	return s.requeueOutbox(ctx, batches, until)
}

func collectorPartition(p CollectorPass) string {
	scope := p.ScopeKey
	if scope == "" {
		scope = "collector"
	}
	class := p.ObjectClass
	if class == "" {
		class = "object"
	}
	return scope + "/" + class
}

// collectorManifestKey is the cloud-shaped manifest entry. projection_state
// stays on collectorPartition, which is already keyed by integration_id.
// Two integrations that share a scope and class must not overwrite each other.
func collectorManifestKey(p CollectorPass) string {
	return "collector:" + p.IntegrationID.String() + "/" + collectorPartition(p)
}

// collectorOutboxShouldFail reports that this run's projection job will never
// be claimed again, so its outbox rows must stop returning to ready.
func (s *ProjectionService) collectorOutboxShouldFail(ctx context.Context, head collectorBatch) (bool, string) {
	var status string
	var attempts int
	var expires sql.NullTime
	err := s.db.WithContext(ctx).Raw(`SELECT status, attempts, lease_expires_at FROM iga_projection_job
		WHERE workspace_id = ? AND iga_scan_run_id = ?`,
		head.WorkspaceID, head.ScanRunID).Row().Scan(&status, &attempts, &expires)
	if err != nil {
		return false, ""
	}
	if status == models.ProjectionAbandoned {
		return true, "projection job abandoned"
	}
	live := status == models.ProjectionRunning && expires.Valid && expires.Time.After(s.now())
	if attempts >= s.maxAttempts && !live {
		return true, "projection job abandoned"
	}
	return false, ""
}

// failCollectorProjectOutbox marks a collector run's project rows failed so
// recovery cannot leave them ready after the job is abandoned.
func failCollectorProjectOutbox(tx *gorm.DB, ws, run uuid.UUID, reason string) error {
	return tx.Exec(`UPDATE collector_outbox o
		SET state = 'failed', last_error = ?, lease_owner = NULL, leased_until = NULL, updated_at = now()
		FROM collector_batches b
		WHERE b.workspace_id = o.workspace_id AND b.id = o.batch_row_id
		  AND o.workspace_id = ? AND b.iga_scan_run_id = ?
		  AND o.job_kind = ? AND o.state IN ('ready', 'leased')`,
		reason, ws, run, models.OutboxKindCollectorProject).Error
}

type nullUUID struct {
	UUID  uuid.UUID
	Valid bool
}

func (n *nullUUID) Scan(src any) error {
	if src == nil {
		n.UUID, n.Valid = uuid.Nil, false
		return nil
	}
	n.Valid = true
	return n.UUID.Scan(src)
}

func scanUUID(db *gorm.DB, query string, args ...any) (uuid.UUID, error) {
	var id uuid.UUID
	err := db.Raw(query, args...).Row().Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, nil
	}
	return id, err
}

// SupportWriter writes support for canonical rows that already exist. It does
// not create identity or workload nodes and it does not choose a provider.
// An observation with no canonical row stays in iga_observations for WP-A4.
// Absence runs only for a complete snapshot whose object class is already a
// canonical class.
type SupportWriter struct{}

func (SupportWriter) Project(tx *gorm.DB, in CollectorPass) error {
	if in.Repo == nil {
		return fmt.Errorf("collector pass has no graph repository")
	}
	rows, err := collectorObservations(tx, in)
	if err != nil {
		return err
	}
	part := collectorPartition(in)
	seen := map[string]map[uuid.UUID]bool{}
	for _, row := range rows {
		key := collectorSourceKey(in.IntegrationID, row.ObjectType, row.RecognitionKey)
		class, objectID, err := existingCanonical(tx, in.WorkspaceID, key)
		if err != nil {
			return err
		}
		if objectID == uuid.Nil {
			continue
		}
		support := models.SupportFromIntegration(in.WorkspaceID, in.IntegrationID, in.ScanRunID, part, in.At)
		if !support.SetObject(class, objectID) {
			continue
		}
		if err := in.Repo.UpsertObjectSupport(tx, support); err != nil {
			return err
		}
		if seen[class] == nil {
			seen[class] = map[uuid.UUID]bool{}
		}
		seen[class][objectID] = true
	}
	if in.Authoritative && models.SupportColumn(in.ObjectClass) != "" {
		return endAbsentSupport(tx, in, part, in.ObjectClass, seen[in.ObjectClass])
	}
	return nil
}

type collectorObserved struct {
	ObjectType     string
	RecognitionKey string
}

func collectorObservations(tx *gorm.DB, in CollectorPass) ([]collectorObserved, error) {
	ids := in.ScanRunIDs
	if len(ids) == 0 && in.ScanRunID != uuid.Nil {
		ids = []uuid.UUID{in.ScanRunID}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	var rows []collectorObserved
	err := tx.Raw(`SELECT so.object_type, so.recognition_key
		FROM iga_observations o
		JOIN iga_source_objects so ON so.workspace_id = o.workspace_id AND so.id = o.source_object_id
		WHERE o.workspace_id = ? AND o.scan_run_id IN ?`,
		in.WorkspaceID, ids).Scan(&rows).Error
	return rows, err
}

func existingCanonical(tx *gorm.DB, ws uuid.UUID, key string) (string, uuid.UUID, error) {
	id, err := scanUUID(tx, `SELECT id FROM iga_identity_accounts WHERE workspace_id = ? AND source_key = ? LIMIT 1`, ws, key)
	if err != nil {
		return "", uuid.Nil, err
	}
	if id != uuid.Nil {
		return models.ObjectIdentity, id, nil
	}
	id, err = scanUUID(tx, `SELECT id FROM iga_workload WHERE workspace_id = ? AND source_key = ? LIMIT 1`, ws, key)
	if err != nil || id == uuid.Nil {
		return "", uuid.Nil, err
	}
	return models.ObjectWorkload, id, nil
}

func collectorClass(objectType string) string {
	low := strings.ToLower(objectType)
	switch {
	case strings.Contains(low, "identity"), strings.Contains(low, "user"),
		strings.Contains(low, "group"), strings.Contains(low, "serviceaccount"):
		return models.ObjectIdentity
	default:
		return models.ObjectWorkload
	}
}

func collectorSourceKey(integration uuid.UUID, objectType, recognition string) string {
	return "collector:" + integration.String() + ":" + objectType + ":" + recognition
}

func endAbsentSupport(tx *gorm.DB, in CollectorPass, partition, class string, seen map[uuid.UUID]bool) error {
	col := models.SupportColumn(class)
	if col == "" {
		class = collectorClass(class)
		col = models.SupportColumn(class)
	}
	if col == "" {
		return nil
	}
	q := tx.Table("iga_object_support").
		Where("workspace_id = ? AND integration_id = ? AND partition_key = ? AND "+col+" IS NOT NULL AND state <> 'ended'",
			in.WorkspaceID, in.IntegrationID, partition)
	if len(seen) > 0 {
		ids := make([]uuid.UUID, 0, len(seen))
		for id := range seen {
			ids = append(ids, id)
		}
		q = q.Where(col+" NOT IN ?", ids)
	}
	return q.Updates(map[string]any{
		"state": "ended", "ended_reason": "absent", "last_confirmed_at": in.At,
	}).Error
}

// FixtureWriter is the test double that creates canonical nodes. Production
// leaves that to WP-A4. It then writes the same support rows SupportWriter
// would, plus one executes_as relationship.
type FixtureWriter struct{}

func (w FixtureWriter) Project(tx *gorm.DB, in CollectorPass) error {
	if err := w.materialize(tx, in); err != nil {
		return err
	}
	if err := (SupportWriter{}).Project(tx, in); err != nil {
		return err
	}
	if in.Authoritative && models.SupportColumn(in.ObjectClass) == "" {
		part := collectorPartition(in)
		class := collectorClass(in.ObjectClass)
		seen, err := confirmedSupport(tx, in, part, class)
		if err != nil {
			return err
		}
		if err := endAbsentSupport(tx, in, part, class, seen); err != nil {
			return err
		}
	}
	return w.relate(tx, in)
}

func (FixtureWriter) materialize(tx *gorm.DB, in CollectorPass) error {
	if in.Repo == nil {
		return fmt.Errorf("collector pass has no graph repository")
	}
	scopeID, err := in.Repo.UpsertEstateScope(tx, &models.IGAEstateScope{
		WorkspaceID: in.WorkspaceID, ScopeKind: "host", DisplayName: in.ScopeKey,
		SourceKey: "collector:" + in.IntegrationID.String() + ":" + collectorPartition(in),
	})
	if err != nil {
		return err
	}
	rows, err := collectorObservationRows(tx, in)
	if err != nil {
		return err
	}
	for _, row := range rows {
		class := collectorClass(row.ObjectType)
		key := collectorSourceKey(in.IntegrationID, row.ObjectType, row.RecognitionKey)
		switch class {
		case models.ObjectIdentity:
			_, err = in.Repo.UpsertIdentity(tx, &models.IGAIdentityAccount{
				WorkspaceID: in.WorkspaceID, EstateScopeID: &scopeID, DisplayName: row.RecognitionKey,
				AccountKind: "k8s_service_account", Provider: "kubernetes", SourceKey: key,
				ProviderAttrs: json.RawMessage(`{}`),
				FirstSeenAt:   in.At, LastSeenAt: in.At,
			})
		default:
			_, err = in.Repo.UpsertWorkload(tx, &models.IGAWorkload{
				WorkspaceID: in.WorkspaceID, EstateScopeID: &scopeID, Provider: "kubernetes",
				RuntimeKind: "process", DisplayName: row.RecognitionKey, SourceKey: key,
				ProviderAttrs: json.RawMessage(`{}`),
				FirstSeenAt:   in.At, LastSeenAt: in.At,
			})
		}
		if err != nil {
			return err
		}
	}
	return nil
}

type collectorObservationRow struct {
	ObjectType     string
	RecognitionKey string
	ObservationID  uuid.UUID
}

func collectorObservationRows(tx *gorm.DB, in CollectorPass) ([]collectorObservationRow, error) {
	ids := in.ScanRunIDs
	if len(ids) == 0 && in.ScanRunID != uuid.Nil {
		ids = []uuid.UUID{in.ScanRunID}
	}
	var rows []collectorObservationRow
	if len(ids) == 0 {
		return nil, nil
	}
	err := tx.Raw(`SELECT so.object_type, so.recognition_key, o.id AS observation_id
		FROM iga_observations o
		JOIN iga_source_objects so ON so.workspace_id = o.workspace_id AND so.id = o.source_object_id
		WHERE o.workspace_id = ? AND o.scan_run_id IN ?`,
		in.WorkspaceID, ids).Scan(&rows).Error
	return rows, err
}

func confirmedSupport(tx *gorm.DB, in CollectorPass, partition, class string) (map[uuid.UUID]bool, error) {
	col := models.SupportColumn(class)
	if col == "" {
		return nil, nil
	}
	rows, err := tx.Raw(`SELECT `+col+` FROM iga_object_support
		WHERE workspace_id = ? AND integration_id = ? AND partition_key = ?
		  AND confirming_iga_scan_run_id = ? AND `+col+` IS NOT NULL AND state <> 'ended'`,
		in.WorkspaceID, in.IntegrationID, partition, in.ScanRunID).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[uuid.UUID]bool{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		seen[id] = true
	}
	return seen, rows.Err()
}

func (FixtureWriter) relate(tx *gorm.DB, in CollectorPass) error {
	workloadID, err := scanUUID(tx, `SELECT workload_id FROM iga_object_support
		WHERE workspace_id = ? AND integration_id = ? AND workload_id IS NOT NULL
		ORDER BY first_seen_at LIMIT 1`, in.WorkspaceID, in.IntegrationID)
	if err != nil {
		return err
	}
	identityID, err := scanUUID(tx, `SELECT identity_account_id FROM iga_object_support
		WHERE workspace_id = ? AND integration_id = ? AND identity_account_id IS NOT NULL
		ORDER BY first_seen_at LIMIT 1`, in.WorkspaceID, in.IntegrationID)
	if err != nil || workloadID == uuid.Nil || identityID == uuid.Nil {
		return err
	}
	obsID, err := scanUUID(tx, `SELECT id FROM iga_observations WHERE workspace_id = ? AND scan_run_id = ? LIMIT 1`,
		in.WorkspaceID, in.ScanRunID)
	if err != nil {
		return err
	}
	relID, err := in.Repo.UpsertRelationship(tx, &models.IGARelationship{
		WorkspaceID: in.WorkspaceID, RelationshipType: models.RelTypeExecutesAs,
		SourceWorkloadID: &workloadID, TargetIdentityAccountID: &identityID,
		Basis: models.BasisDeclared, State: models.RelCurrent,
		ValidFrom: in.At, LastConfirmedAt: in.At,
		SourceKey:    collectorSourceKey(in.IntegrationID, "executes_as", workloadID.String()),
		PartitionKey: collectorPartition(in), IntegrationID: &in.IntegrationID,
		ConfirmingIGAScanRunID: &in.ScanRunID,
	})
	if err != nil || obsID == uuid.Nil {
		return err
	}
	return in.Repo.LinkRelationshipCollectorEvidence(tx, in.WorkspaceID, relID, obsID, "supports")
}
