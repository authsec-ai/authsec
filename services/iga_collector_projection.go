package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

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
	ScanRunID     uuid.UUID
	Mode          string
	ScopeKey      string
	ObjectClass   string
	Authoritative bool
	At            time.Time
	Repo          repositories.IGAGraphRepository
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
	AvailableAt   time.Time
}

// projectCollectorOnce claims ready collector_project outbox rows, groups a
// microbatch, and publishes them under the workspace fence. It returns false
// when nothing is ready.
func (s *ProjectionService) projectCollectorOnce(ctx context.Context) (bool, error) {
	batches, err := s.claimCollectorBatches(ctx)
	if err != nil || len(batches) == 0 {
		return false, err
	}
	head := batches[0]
	mode, authoritative, scope, class, err := s.collectorMode(ctx, head)
	if err != nil {
		return true, s.releaseOutbox(ctx, batches, "failed", err.Error())
	}
	if mode == "" {
		// An incomplete snapshot stays queued, past the microbatch window, so
		// the claimer does not spin on it.
		return true, s.deferOutbox(ctx, batches, s.now().Add(CollectorMicrobatch()))
	}
	runID, err := s.ensureCollectorRun(ctx, head, mode, authoritative)
	if err != nil {
		if rel := s.releaseOutbox(ctx, batches, "failed", err.Error()); rel != nil {
			return true, fmt.Errorf("%w (and outbox release: %v)", err, rel)
		}
		return true, err
	}
	job := &models.IGAProjectionJob{
		WorkspaceID:  head.WorkspaceID,
		IGAScanRunID: &runID,
		Generation:   1,
		Status:       models.ProjectionQueued,
	}
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return s.jobs.EnqueueTx(tx, job)
	}); err != nil {
		return true, err
	}
	version, err := s.pipeline.AcquireForCollectorProjection(
		head.WorkspaceID, runID, job.ID, s.barrierLease, s.now())
	if err != nil {
		return true, err
	}
	fence := repositories.PipelineFence{
		WorkspaceID: head.WorkspaceID, Phase: models.PipelineProjecting,
		RunID: runID, Version: version, Holder: models.PipelineJobHolder(job.ID),
		RunKind: models.RunKindCollector,
	}
	writer := s.collector
	if writer == nil {
		writer = SupportWriter{}
	}
	pass := CollectorPass{
		WorkspaceID: head.WorkspaceID, IntegrationID: head.IntegrationID, ScanRunID: runID,
		Mode: mode, ScopeKey: scope, ObjectClass: class, Authoritative: authoritative,
		At: s.now(), Repo: s.graph,
	}
	if s.beforeCollectorTx != nil {
		s.beforeCollectorTx()
	}
	pubErr := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := s.pipeline.AssertHeldTx(tx, fence); err != nil {
			return err
		}
		if err := writer.Project(tx, pass); err != nil {
			return err
		}
		rev, err := s.graph.NextRevision(tx, head.WorkspaceID)
		if err != nil {
			return err
		}
		manifest, err := json.Marshal([]models.SourceManifestRef{{
			Kind: models.ManifestKindIGAScanRun, ID: runID, IntegrationID: &head.IntegrationID,
		}})
		if err != nil {
			return err
		}
		if err := s.graph.InsertPublication(tx, &models.IGAPublication{
			WorkspaceID: head.WorkspaceID, Rev: rev, PublishedAt: pass.At,
			IGAScanRunID: &runID, Manifest: json.RawMessage(`{}`), SourceManifestV2: manifest,
		}); err != nil {
			return err
		}
		if err := s.graph.UpsertProjectionState(tx, &models.IGAProjectionState{
			WorkspaceID: head.WorkspaceID, EstateScopeID: passScope(tx, pass),
			IntegrationID: &head.IntegrationID, PartitionKey: collectorPartition(pass),
			ObjectClass: class, LastIGAScanRunID: &runID, LastGeneration: 1,
			CoverageState: "reached", Reconciled: authoritative, UpdatedAt: pass.At,
		}); err != nil {
			return err
		}
		if err := s.enqueueCandidateEval(tx, head, rev); err != nil {
			return err
		}
		if err := tx.Exec(`
			UPDATE iga_projection_job
			   SET status = ?, completed_at = ?, lease_owner = '', lease_expires_at = NULL
			 WHERE workspace_id = ? AND id = ? AND iga_scan_run_id = ? AND status = ?`,
			models.ProjectionComplete, pass.At, head.WorkspaceID, job.ID, runID, models.ProjectionQueued).Error; err != nil {
			return err
		}
		if err := s.pipeline.ReleaseTx(tx, fence); err != nil {
			return err
		}
		for _, b := range batches {
			if err := tx.Exec(`UPDATE collector_outbox SET state = 'done', updated_at = ? WHERE workspace_id = ? AND id = ?`,
				pass.At, b.WorkspaceID, b.OutboxID).Error; err != nil {
				return err
			}
			if err := tx.Exec(`UPDATE collector_batches SET projection_state = 'published', receipt_state = 'published', iga_scan_run_id = ?, graph_revision = ? WHERE workspace_id = ? AND id = ?`,
				runID, rev, b.WorkspaceID, b.BatchRowID).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if pubErr != nil {
		if pubErr != repositories.ErrPipelineLost && !errors.Is(pubErr, repositories.ErrPipelineLost) {
			_ = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
				return s.pipeline.AbandonTx(tx, fence, pubErr.Error())
			})
		}
		return true, pubErr
	}
	return true, nil
}

func (s *ProjectionService) claimCollectorBatches(ctx context.Context) ([]collectorBatch, error) {
	var head collectorBatch
	err := s.db.WithContext(ctx).Raw(`
		SELECT o.id AS outbox_id, o.workspace_id, o.integration_id, o.collector_id,
		       o.batch_row_id, b.epoch, o.available_at
		  FROM collector_outbox o
		  JOIN collector_batches b
		    ON b.workspace_id = o.workspace_id AND b.id = o.batch_row_id
		 WHERE o.job_kind = ? AND o.state = 'ready' AND o.available_at <= ?
		   AND b.receipt_state = 'accepted'
		 ORDER BY o.available_at
		 LIMIT 1`, models.OutboxKindCollectorProject, s.now()).Scan(&head).Error
	if err != nil {
		return nil, err
	}
	if head.OutboxID == uuid.Nil {
		return nil, nil
	}
	window := head.AvailableAt.Add(CollectorMicrobatch())
	var rows []collectorBatch
	err = s.db.WithContext(ctx).Raw(`
		SELECT o.id AS outbox_id, o.workspace_id, o.integration_id, o.collector_id,
		       o.batch_row_id, b.epoch, o.available_at
		  FROM collector_outbox o
		  JOIN collector_batches b
		    ON b.workspace_id = o.workspace_id AND b.id = o.batch_row_id
		 WHERE o.job_kind = ? AND o.state = 'ready'
		   AND o.workspace_id = ? AND o.integration_id = ? AND o.collector_id = ?
		   AND b.epoch = ? AND b.receipt_state = 'accepted'
		   AND o.available_at <= ?
		 ORDER BY o.available_at`,
		models.OutboxKindCollectorProject, head.WorkspaceID, head.IntegrationID, head.CollectorID,
		head.Epoch, window).Scan(&rows).Error
	return rows, err
}

// collectorMode returns "" when a snapshot for this epoch is not complete.
// No snapshot row means a runtime batch.
func (s *ProjectionService) collectorMode(ctx context.Context, b collectorBatch) (mode string, authoritative bool, scope, class string, err error) {
	var snaps []struct {
		Complete    bool
		GapBlocked  bool
		ScopeKey    string
		ObjectClass string
	}
	err = s.db.WithContext(ctx).Raw(`
		SELECT complete, gap_blocked, scope_key, object_class
		  FROM collector_snapshots
		 WHERE workspace_id = ? AND collector_id = ? AND epoch = ?`,
		b.WorkspaceID, b.CollectorID, b.Epoch).Scan(&snaps).Error
	if err != nil {
		return "", false, "", "", err
	}
	if len(snaps) == 0 {
		return "runtime_batch", false, "collector", "", nil
	}
	for _, sn := range snaps {
		if !sn.Complete || sn.GapBlocked {
			return "", false, sn.ScopeKey, sn.ObjectClass, nil
		}
		scope, class = sn.ScopeKey, sn.ObjectClass
	}
	return "configuration_snapshot", true, scope, class, nil
}

func (s *ProjectionService) ensureCollectorRun(ctx context.Context, b collectorBatch, mode string, authoritative bool) (uuid.UUID, error) {
	existing, err := scanUUID(s.db.WithContext(ctx), `
		SELECT iga_scan_run_id FROM collector_batches
		 WHERE workspace_id = ? AND id = ? AND iga_scan_run_id IS NOT NULL`,
		b.WorkspaceID, b.BatchRowID)
	if err != nil {
		return uuid.Nil, err
	}
	if existing != uuid.Nil {
		return existing, nil
	}
	id := uuid.New()
	err = s.db.WithContext(ctx).Exec(`
		INSERT INTO iga_scan_runs
			(id, workspace_id, integration_id, mode, generation, status, is_authoritative, started_at, completed_at)
		VALUES (?, ?, ?, ?,
		        COALESCE((SELECT max(generation) + 1 FROM iga_scan_runs WHERE workspace_id = ? AND integration_id = ?), 1),
		        'succeeded', ?, now(), now())`,
		id, b.WorkspaceID, b.IntegrationID, mode, b.WorkspaceID, b.IntegrationID, authoritative).Error
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
			UPDATE collector_outbox SET state = ?, last_error = ?, updated_at = now()
			 WHERE workspace_id = ? AND id = ?`, state, reason, b.WorkspaceID, b.OutboxID).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *ProjectionService) deferOutbox(ctx context.Context, batches []collectorBatch, until time.Time) error {
	for _, b := range batches {
		if err := s.db.WithContext(ctx).Exec(`
			UPDATE collector_outbox SET available_at = ?, updated_at = now()
			 WHERE workspace_id = ? AND id = ? AND state = 'ready'`,
			until, b.WorkspaceID, b.OutboxID).Error; err != nil {
			return err
		}
	}
	return nil
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

func passScope(tx *gorm.DB, p CollectorPass) uuid.UUID {
	id, _ := scanUUID(tx, `SELECT id FROM iga_estate_scopes WHERE workspace_id = ? AND source_key = ? LIMIT 1`,
		p.WorkspaceID, "collector:"+p.IntegrationID.String()+":"+collectorPartition(p))
	return id
}

// scanUUID reads one uuid. GORM's Scan treats uuid.UUID as a byte array and
// rejects the text driver value; database/sql uses the Scanner.
func scanUUID(db *gorm.DB, query string, args ...any) (uuid.UUID, error) {
	var id uuid.UUID
	err := db.Raw(query, args...).Row().Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, nil
	}
	return id, err
}

// SupportWriter writes typed-arm support for the source objects a run observed.
// It ends support only for a complete authoritative snapshot of the same
// source, scope and object class.
type SupportWriter struct{}

func (SupportWriter) Project(tx *gorm.DB, in CollectorPass) error {
	if in.Repo == nil {
		return fmt.Errorf("collector pass has no graph repository")
	}
	scopeID, err := in.Repo.UpsertEstateScope(tx, &models.IGAEstateScope{
		WorkspaceID: in.WorkspaceID,
		ScopeKind:   "host",
		DisplayName: in.ScopeKey,
		SourceKey:   "collector:" + in.IntegrationID.String() + ":" + collectorPartition(in),
	})
	if err != nil {
		return err
	}
	type src struct {
		ID             uuid.UUID
		ObjectType     string
		RecognitionKey string
		ObservationID  uuid.UUID
	}
	var rows []src
	if err := tx.Raw(`
		SELECT so.id, so.object_type, so.recognition_key, o.id AS observation_id
		  FROM iga_observations o
		  JOIN iga_source_objects so
		    ON so.workspace_id = o.workspace_id AND so.id = o.source_object_id
		 WHERE o.workspace_id = ? AND o.scan_run_id = ?`,
		in.WorkspaceID, in.ScanRunID).Scan(&rows).Error; err != nil {
		return err
	}
	part := collectorPartition(in)
	seen := map[string]map[uuid.UUID]bool{}
	for _, row := range rows {
		class := collectorClass(row.ObjectType)
		key := collectorSourceKey(in.IntegrationID, row.ObjectType, row.RecognitionKey)
		var objectID uuid.UUID
		switch class {
		case models.ObjectIdentity:
			objectID, err = in.Repo.UpsertIdentity(tx, &models.IGAIdentityAccount{
				WorkspaceID: in.WorkspaceID, EstateScopeID: &scopeID, DisplayName: row.RecognitionKey,
				AccountKind: "user", Provider: "kubernetes", SourceKey: key,
				ProviderAttrs: json.RawMessage(`{}`),
				FirstSeenAt:   in.At, LastSeenAt: in.At,
			})
		default:
			class = models.ObjectWorkload
			objectID, err = in.Repo.UpsertWorkload(tx, &models.IGAWorkload{
				WorkspaceID: in.WorkspaceID, EstateScopeID: &scopeID, Provider: "kubernetes",
				RuntimeKind: "process", DisplayName: row.RecognitionKey, SourceKey: key,
				ProviderAttrs: json.RawMessage(`{}`),
				FirstSeenAt:   in.At, LastSeenAt: in.At,
			})
		}
		if err != nil {
			return err
		}
		support := models.SupportFromIntegration(in.WorkspaceID, in.IntegrationID, in.ScanRunID, part, in.At)
		if !support.SetObject(class, objectID) {
			return fmt.Errorf("unsupported object class %s", class)
		}
		if err := in.Repo.UpsertObjectSupport(tx, support); err != nil {
			return err
		}
		if seen[class] == nil {
			seen[class] = map[uuid.UUID]bool{}
		}
		seen[class][objectID] = true
		_ = row.ObservationID
	}
	if in.Authoritative {
		class := in.ObjectClass
		if class == "" {
			class = models.ObjectWorkload
		}
		return endAbsentSupport(tx, in, part, class, seen[collectorClass(class)])
	}
	return nil
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
	class = collectorClass(class)
	col := models.SupportColumn(class)
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

// FixtureWriter is SupportWriter plus one executes_as relationship and its
// iga_observations evidence, so fencing tests can see both arms without a
// Linux or Kubernetes normalizer.
type FixtureWriter struct{ SupportWriter }

func (w FixtureWriter) Project(tx *gorm.DB, in CollectorPass) error {
	if err := w.SupportWriter.Project(tx, in); err != nil {
		return err
	}
	workloadID, err := scanUUID(tx, `
		SELECT workload_id FROM iga_object_support
		 WHERE workspace_id = ? AND integration_id = ? AND workload_id IS NOT NULL
		 ORDER BY first_seen_at LIMIT 1`, in.WorkspaceID, in.IntegrationID)
	if err != nil {
		return err
	}
	identityID, err := scanUUID(tx, `
		SELECT identity_account_id FROM iga_object_support
		 WHERE workspace_id = ? AND integration_id = ? AND identity_account_id IS NOT NULL
		 ORDER BY first_seen_at LIMIT 1`, in.WorkspaceID, in.IntegrationID)
	if err != nil {
		return err
	}
	if workloadID == uuid.Nil || identityID == uuid.Nil {
		return nil
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
	if err != nil {
		return err
	}
	if obsID != uuid.Nil {
		return in.Repo.LinkRelationshipCollectorEvidence(tx, in.WorkspaceID, relID, obsID, "supports")
	}
	return nil
}
