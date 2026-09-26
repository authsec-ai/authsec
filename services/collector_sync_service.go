package services

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/pkg/collectorcontract"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const defaultCollectorQuotaPerMinute = 120

// ErrSyncForbidden, ErrSyncConflict, ErrSyncUnavailable and ErrSyncNotFound are
// the agent-sync failures the controller maps onto HTTP. Bodies stay generic.
var (
	ErrSyncForbidden   = errors.New("collector sync forbidden")
	ErrSyncConflict    = errors.New("collector sync conflict")
	ErrSyncUnavailable = errors.New("collector sync unavailable")
	ErrSyncNotFound    = errors.New("collector sync not found")
)

// QuotaError is a per-collector budget miss. RetryAfter is at least one second.
type QuotaError struct{ RetryAfter int }

func (e *QuotaError) Error() string { return "collector quota exceeded" }
func (e *QuotaError) Unwrap() error { return ErrSyncUnavailable }

// CollectorSyncService accepts agent-sync batches. It never writes canonical
// graph nodes. Projection is a later package; this service durably queues work.
//
// Epoch rule: the first accepted batch binds collector_epoch. The same epoch
// is accepted afterwards. A different epoch is 409 unless an administrator has
// set authorized_next_epoch to that value (POST /api/iga/v2/collectors/:id/epoch).
// On an authorized change the server swaps the epoch, clears the authorization,
// and resets last_sequence so the new stream starts at 1. Sequence gaps are
// stored and mark snapshots in that epoch incomplete. They never delete rows.
type CollectorSyncService struct {
	db               *gorm.DB
	now              func() time.Time
	QuotaPerMinute   int
	FailBeforeCommit func() error
	ProcessFail      func() error
	LastPersistErr   error
}

// NewCollectorSyncService constructs the ingest service. now may be nil.
func NewCollectorSyncService(db *gorm.DB, now func() time.Time) *CollectorSyncService {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &CollectorSyncService{db: db, now: now, QuotaPerMinute: defaultCollectorQuotaPerMinute}
}

func (s *CollectorSyncService) clock() time.Time { return s.now().UTC() }

// Accept validates and durably stores one decompressed batch. On success the
// returned bytes are the receipt JSON. A storage failure returns
// ErrSyncUnavailable and leaves no receipt row.
func (s *CollectorSyncService) Accept(p *models.CollectorPrincipal, raw []byte) ([]byte, error) {
	if p == nil || !containsString(p.Scopes, models.CollectorScopeIngest) {
		return nil, ErrSyncForbidden
	}
	var ident struct {
		WorkspaceID string `json:"workspace_id"`
		HostID      string `json:"host_id"`
		EstateID    string `json:"estate_id"`
	}
	_ = json.Unmarshal(raw, &ident)
	if ident.HostID != "" ||
		(ident.WorkspaceID != "" && ident.WorkspaceID != p.WorkspaceID.String()) ||
		(ident.EstateID != "" && ident.EstateID != p.EstateScopeID.String()) {
		return nil, ErrSyncForbidden
	}
	req, cerr := collectorcontract.Validate(raw)
	if cerr != nil {
		if cerr.Kind == "forbidden" {
			return nil, ErrSyncForbidden
		}
		return nil, cerr
	}
	if err := s.enforceScope(p, req); err != nil {
		return nil, err
	}
	if req.Snapshot != nil {
		sum, err := collectorcontract.ObjectsDigest(req.Objects)
		if err != nil {
			return nil, err
		}
		if !strings.EqualFold(sum, req.Snapshot.Digest) {
			return nil, &collectorcontract.ContractError{Kind: "invalid", Fields: []collectorcontract.FieldError{{
				Path: "snapshot.digest", Message: "does not match the objects array",
			}}}
		}
	}
	hash := collectorcontract.PayloadHash(raw)
	var body []byte
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var err error
		body, err = s.persist(tx, p, req, raw, hash)
		return err
	})
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (s *CollectorSyncService) persist(tx *gorm.DB, p *models.CollectorPrincipal, req *collectorcontract.SyncRequest, raw []byte, hash string) ([]byte, error) {
	repo := repositories.NewCollectorRepository(tx)
	inst, err := repo.LockInstance(p.WorkspaceID, p.CollectorID)
	if err != nil {
		return nil, ErrSyncForbidden
	}
	batchID, err := uuid.Parse(req.BatchID)
	if err != nil {
		return nil, err
	}
	var existing struct {
		PayloadHash string
		ReceiptBody []byte
	}
	err = tx.Raw(`SELECT payload_hash, receipt_body FROM collector_batches
		WHERE workspace_id = ? AND collector_id = ? AND batch_id = ?`,
		p.WorkspaceID, p.CollectorID, batchID).Scan(&existing).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		s.note(err)
		return nil, ErrSyncUnavailable
	}
	if len(existing.ReceiptBody) > 0 || existing.PayloadHash != "" {
		if existing.PayloadHash == hash {
			return existing.ReceiptBody, nil
		}
		return nil, ErrSyncConflict
	}
	presented, err := uuid.Parse(req.CollectorEpoch)
	if err != nil {
		return nil, err
	}
	epoch, lastSeq, err := authorizeEpoch(inst, presented)
	if err != nil {
		return nil, err
	}
	gap := false
	if req.Sequence <= lastSeq {
		return nil, ErrSyncConflict
	}
	if req.Sequence > lastSeq+1 {
		gap = true
	}
	quota := s.QuotaPerMinute
	if quota <= 0 {
		quota = defaultCollectorQuotaPerMinute
	}
	var recent int64
	if err := tx.Raw(`SELECT count(*) FROM collector_batches
		WHERE workspace_id = ? AND collector_id = ? AND received_at > ?`,
		p.WorkspaceID, p.CollectorID, s.clock().Add(-time.Minute)).Scan(&recent).Error; err != nil {
		s.note(err)
		return nil, ErrSyncUnavailable
	}
	if recent >= int64(quota) {
		return nil, &QuotaError{RetryAfter: 1}
	}
	if s.FailBeforeCommit != nil {
		if err := s.FailBeforeCommit(); err != nil {
			s.note(err)
			return nil, ErrSyncUnavailable
		}
	}
	now := s.clock()
	rev, err := publishedRevision(tx, p.WorkspaceID)
	if err != nil {
		s.note(err)
		return nil, ErrSyncUnavailable
	}
	receiptID := uuid.New()
	resp := collectorcontract.SyncResponse{
		ReceiptID: receiptID.String(), AcceptedSequence: req.Sequence,
		ReceiptState: models.ReceiptStateAccepted, ProjectionState: models.ProjectionStateQueued,
		PublishedGraphRevision: rev,
		MappingURL:             "/api/iga/v2/receipts/" + receiptID.String(),
		Desired:                json.RawMessage("null"),
		NextSyncSeconds:        NextSyncSeconds(),
	}
	respBody, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	mode := models.ProducerModeRuntimeBatch
	if req.Snapshot != nil {
		mode = models.ProducerModeConfigurationSnapshot
	}
	runID := uuid.New()
	health, _ := json.Marshal(req.Health)
	if err := tx.Exec(`INSERT INTO iga_scan_runs
		(id, workspace_id, integration_id, mode, generation, status, requested_by, normalizer_version, counters, is_authoritative, started_at, completed_at)
		VALUES (?, ?, ?, ?, ?, 'succeeded', 'collector', ?, CAST(? AS jsonb), false, ?, ?)`,
		runID, p.WorkspaceID, p.IntegrationID, mode, req.Sequence, collectorcontract.NormalizerVersion, string(health), now, now).Error; err != nil {
		s.note(err)
		return nil, ErrSyncUnavailable
	}
	scopeID, err := integrationScopeID(tx, p.WorkspaceID, p.IntegrationID)
	if err != nil {
		s.note(err)
		return nil, ErrSyncUnavailable
	}
	refs, err := s.storeObjects(tx, p, req, scopeID, runID, now)
	if err != nil {
		s.note(err)
		return nil, classifyPersist(err)
	}
	if err := s.storeObservations(tx, p, req, refs, scopeID, runID, mode, now); err != nil {
		s.note(err)
		return nil, classifyPersist(err)
	}
	if err := s.storeApplied(tx, p, req, scopeID, runID, mode, now); err != nil {
		s.note(err)
		return nil, classifyPersist(err)
	}
	if gap {
		if err := tx.Exec(`INSERT INTO collector_sequence_gaps
			(id, workspace_id, collector_id, epoch, expected_sequence, received_sequence, batch_id, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			uuid.New(), p.WorkspaceID, p.CollectorID, epoch, lastSeq+1, req.Sequence, batchID, now).Error; err != nil {
			s.note(err)
			return nil, ErrSyncUnavailable
		}
	}
	if req.Snapshot != nil {
		if err := s.storeSnapshot(tx, p, req, epoch, gap, now); err != nil {
			return nil, err
		}
	} else if gap {
		if err := tx.Exec(`UPDATE collector_snapshots SET gap_blocked = true, complete = false, updated_at = ?
			WHERE workspace_id = ? AND collector_id = ? AND epoch = ?`,
			now, p.WorkspaceID, p.CollectorID, epoch).Error; err != nil {
			s.note(err)
			return nil, ErrSyncUnavailable
		}
	}
	batchRow := uuid.New()
	if err := tx.Exec(`INSERT INTO collector_batches
		(id, workspace_id, collector_id, epoch, sequence, batch_id, payload_hash, receipt_id,
		 receipt_state, projection_state, iga_scan_run_id, graph_revision, received_at, receipt_body)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'accepted', 'queued', ?, ?, ?, CAST(? AS jsonb))`,
		batchRow, p.WorkspaceID, p.CollectorID, epoch, req.Sequence, batchID, hash, receiptID,
		runID, rev, now, string(respBody)).Error; err != nil {
		s.note(err)
		return nil, classifyPersist(err)
	}
	if err := tx.Exec(`INSERT INTO collector_outbox
		(id, workspace_id, integration_id, collector_id, batch_row_id, job_kind, dedupe_key, state, available_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'ready', ?, ?, ?)`,
		uuid.New(), p.WorkspaceID, p.IntegrationID, p.CollectorID, batchRow,
		models.OutboxKindCollectorProject, "batch:"+batchRow.String(), now, now, now).Error; err != nil {
		s.note(err)
		return nil, ErrSyncUnavailable
	}
	digest := inst.CapabilityDigest
	if req.CapabilityDigest != "" {
		digest = req.CapabilityDigest
	} else if len(req.Capabilities) > 0 {
		sum := sha256.Sum256(req.Capabilities)
		digest = hex.EncodeToString(sum[:])
	}
	swapped := inst.AuthorizedNextEpoch != nil && epoch == presented && (inst.Epoch == nil || *inst.Epoch != presented)
	var nextEpoch *uuid.UUID
	if !swapped {
		nextEpoch = inst.AuthorizedNextEpoch
	}
	if err := tx.Exec(`UPDATE collector_instances SET epoch = ?, authorized_next_epoch = ?, last_sequence = ?,
		last_seen_at = ?, capability_digest = ?, updated_at = ?
		WHERE id = ? AND workspace_id = ?`,
		epoch, nextEpoch, req.Sequence, now, digest, now, inst.ID, inst.WorkspaceID).Error; err != nil {
		s.note(err)
		return nil, ErrSyncUnavailable
	}
	return respBody, nil
}

func authorizeEpoch(inst *models.CollectorInstance, presented uuid.UUID) (uuid.UUID, int64, error) {
	if inst.Epoch == nil {
		return presented, inst.LastSequence, nil
	}
	if *inst.Epoch == presented {
		return presented, inst.LastSequence, nil
	}
	if inst.AuthorizedNextEpoch != nil && *inst.AuthorizedNextEpoch == presented {
		return presented, 0, nil
	}
	return uuid.Nil, 0, ErrSyncConflict
}

func publishedRevision(tx *gorm.DB, ws uuid.UUID) (int64, error) {
	var rev int64
	err := tx.Raw(`SELECT COALESCE(MAX(rev), 0) FROM iga_publication WHERE workspace_id = ?`, ws).Scan(&rev).Error
	return rev, err
}

func integrationScopeID(tx *gorm.DB, ws, integration uuid.UUID) (*uuid.UUID, error) {
	var idStr string
	err := tx.Raw(`SELECT id::text FROM iga_integration_scopes
		WHERE workspace_id = ? AND integration_id = ? AND native_scope_kind <> 'namespace'
		ORDER BY created_at LIMIT 1`, ws, integration).Scan(&idStr).Error
	if err != nil || idStr == "" {
		if errors.Is(err, gorm.ErrRecordNotFound) || idStr == "" {
			return nil, nil
		}
		return nil, err
	}
	id, err := uuid.Parse(idStr)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

func (s *CollectorSyncService) storeObjects(tx *gorm.DB, p *models.CollectorPrincipal, req *collectorcontract.SyncRequest, scopeID *uuid.UUID, runID uuid.UUID, now time.Time) (map[string]uuid.UUID, error) {
	refs := map[string]uuid.UUID{}
	gen := req.Sequence
	for _, obj := range req.Objects {
		payload := map[string]any{"native": obj.Native}
		if obj.Attributes != nil {
			payload["attributes"] = obj.Attributes
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(body)
		keyHash := hex.EncodeToString(sum[:])
		recKey := obj.Kind + ":" + keyHash
		locator, _ := json.Marshal(map[string]string{"ref": obj.Ref})
		var idStr string
		err = tx.Raw(`INSERT INTO iga_source_objects
			(id, workspace_id, integration_id, integration_scope_id, object_type, recognition_key,
			 native_id, locator, normalized_payload, raw_hash, source_version, source_subject_key,
			 scan_generation, lifecycle, first_seen_at, last_seen_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, CAST(? AS jsonb), CAST(? AS jsonb), ?, '2.0', '', ?, 'active', ?, ?)
			ON CONFLICT (workspace_id, integration_id, object_type, recognition_key)
			DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at, normalized_payload = EXCLUDED.normalized_payload,
				raw_hash = EXCLUDED.raw_hash, scan_generation = EXCLUDED.scan_generation
			RETURNING id::text`,
			uuid.New(), p.WorkspaceID, p.IntegrationID, scopeID, obj.Kind, recKey,
			keyHash, string(locator), string(body), keyHash, gen, now, now).Scan(&idStr).Error
		if err != nil {
			return nil, err
		}
		id, err := uuid.Parse(idStr)
		if err != nil {
			return nil, err
		}
		refs[obj.Ref] = id
	}
	return refs, nil
}

func (s *CollectorSyncService) storeObservations(tx *gorm.DB, p *models.CollectorPrincipal, req *collectorcontract.SyncRequest, refs map[string]uuid.UUID, scopeID *uuid.UUID, runID uuid.UUID, mode string, now time.Time) error {
	for _, ob := range req.Observations {
		sourceID, ok := refs[ob.SubjectRef]
		if !ok {
			var err error
			sourceID, err = s.eventSource(tx, p, scopeID, ob.Kind, ob.EventID, req.Sequence, now)
			if err != nil {
				return err
			}
		}
		// The payload is the observation itself, including preview=true
		// telemetry. Preview is not an existence fact: a dry-run admission
		// does not become a canonical graph node. This path never writes one.
		body, err := json.Marshal(ob)
		if err != nil {
			return err
		}
		observed, err := time.Parse(time.RFC3339, ob.ObservedAt)
		if err != nil {
			return err
		}
		dedupe := fmt.Sprintf("collector:%s:%s:%s", p.CollectorID, req.CollectorEpoch, ob.EventID)
		if err := tx.Exec(`INSERT INTO iga_observations
			(id, workspace_id, source_object_id, scan_run_id, mode, fact_payload, evidence_ref,
			 observed_at, ingested_at, normalizer_version, dedupe_key,
			 evidence_trust, schema_version, received_at, discovery_source_id)
			VALUES (?, ?, ?, ?, ?, CAST(? AS jsonb), ?, ?, ?, ?, ?, 'authenticated_collector', '2.0', ?, ?)
			ON CONFLICT (workspace_id, dedupe_key) DO NOTHING`,
			uuid.New(), p.WorkspaceID, sourceID, runID, mode, string(body), ob.EventID,
			observed, now, collectorcontract.NormalizerVersion, dedupe, now, p.DiscoverySourceID).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *CollectorSyncService) eventSource(tx *gorm.DB, p *models.CollectorPrincipal, scopeID *uuid.UUID, kind, eventID string, gen int64, now time.Time) (uuid.UUID, error) {
	recKey := "event:" + eventID
	var idStr string
	err := tx.Raw(`INSERT INTO iga_source_objects
		(id, workspace_id, integration_id, integration_scope_id, object_type, recognition_key,
		 native_id, locator, normalized_payload, raw_hash, source_version, lifecycle, first_seen_at, last_seen_at, scan_generation)
		VALUES (?, ?, ?, ?, ?, ?, ?, '{}', '{}', ?, '2.0', 'active', ?, ?, ?)
		ON CONFLICT (workspace_id, integration_id, object_type, recognition_key)
		DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at
		RETURNING id::text`,
		uuid.New(), p.WorkspaceID, p.IntegrationID, scopeID, kind, recKey, eventID, eventID, now, now, gen).Scan(&idStr).Error
	if err != nil {
		return uuid.Nil, err
	}
	return uuid.Parse(idStr)
}

func (s *CollectorSyncService) storeApplied(tx *gorm.DB, p *models.CollectorPrincipal, req *collectorcontract.SyncRequest, scopeID *uuid.UUID, runID uuid.UUID, mode string, now time.Time) error {
	for _, ap := range req.Applied {
		body, err := json.Marshal(ap)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		key := hex.EncodeToString(sum[:])
		sourceID, err := s.eventSource(tx, p, scopeID, "applied_receipt", key, req.Sequence, now)
		if err != nil {
			return err
		}
		observed, err := time.Parse(time.RFC3339, ap.ObservedAt)
		if err != nil {
			return err
		}
		dedupe := fmt.Sprintf("collector:%s:%s:applied:%s", p.CollectorID, req.CollectorEpoch, key)
		if err := tx.Exec(`INSERT INTO iga_observations
			(id, workspace_id, source_object_id, scan_run_id, mode, fact_payload,
			 observed_at, ingested_at, normalizer_version, dedupe_key,
			 evidence_trust, schema_version, received_at, discovery_source_id)
			VALUES (?, ?, ?, ?, ?, CAST(? AS jsonb), ?, ?, ?, ?, 'authenticated_collector', '2.0', ?, ?)
			ON CONFLICT (workspace_id, dedupe_key) DO NOTHING`,
			uuid.New(), p.WorkspaceID, sourceID, runID, mode, string(body),
			observed, now, collectorcontract.NormalizerVersion, dedupe, now, p.DiscoverySourceID).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *CollectorSyncService) storeSnapshot(tx *gorm.DB, p *models.CollectorPrincipal, req *collectorcontract.SyncRequest, epoch uuid.UUID, gap bool, now time.Time) error {
	snap := req.Snapshot
	snapID, err := uuid.Parse(snap.SnapshotID)
	if err != nil {
		return err
	}
	rowID := uuid.New()
	if err := tx.Exec(`INSERT INTO collector_snapshots
		(id, workspace_id, collector_id, snapshot_id, epoch, scope_key, object_class, generation,
		 expected_chunks, received_digest, complete, gap_blocked, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, false, ?, ?, ?)
		ON CONFLICT (workspace_id, collector_id, snapshot_id) DO NOTHING`,
		rowID, p.WorkspaceID, p.CollectorID, snapID, epoch, snap.ScopeKey, snap.ObjectClass, snap.Generation,
		snap.TerminalChunkCount, snap.Digest, gap, now, now).Error; err != nil {
		s.note(err)
		return ErrSyncUnavailable
	}
	var existing struct {
		ID             uuid.UUID
		Epoch          uuid.UUID
		ScopeKey       string
		ObjectClass    string
		Generation     int64
		ExpectedChunks int
		GapBlocked     bool
	}
	if err := tx.Raw(`SELECT id, epoch, scope_key, object_class, generation, expected_chunks, gap_blocked
		FROM collector_snapshots WHERE workspace_id = ? AND collector_id = ? AND snapshot_id = ? FOR UPDATE`,
		p.WorkspaceID, p.CollectorID, snapID).Scan(&existing).Error; err != nil {
		s.note(err)
		return ErrSyncUnavailable
	}
	if existing.ExpectedChunks != snap.TerminalChunkCount || existing.ScopeKey != snap.ScopeKey ||
		existing.ObjectClass != snap.ObjectClass || existing.Generation != snap.Generation || existing.Epoch != epoch {
		return ErrSyncConflict
	}
	res := tx.Exec(`INSERT INTO collector_snapshot_chunks
		(workspace_id, snapshot_row_id, chunk_no, payload_hash, validated, created_at)
		VALUES (?, ?, ?, ?, true, ?)
		ON CONFLICT (workspace_id, snapshot_row_id, chunk_no) DO NOTHING`,
		p.WorkspaceID, existing.ID, snap.ChunkNo, snap.Digest, now)
	if res.Error != nil {
		s.note(res.Error)
		return ErrSyncUnavailable
	}
	var storedHash string
	if err := tx.Raw(`SELECT payload_hash FROM collector_snapshot_chunks
		WHERE workspace_id = ? AND snapshot_row_id = ? AND chunk_no = ?`,
		p.WorkspaceID, existing.ID, snap.ChunkNo).Scan(&storedHash).Error; err != nil {
		s.note(err)
		return ErrSyncUnavailable
	}
	if storedHash != snap.Digest {
		return ErrSyncConflict
	}
	if gap || existing.GapBlocked {
		if err := tx.Exec(`UPDATE collector_snapshots SET gap_blocked = true, complete = false, updated_at = ?
			WHERE workspace_id = ? AND collector_id = ? AND epoch = ?`,
			now, p.WorkspaceID, p.CollectorID, epoch).Error; err != nil {
			s.note(err)
			return ErrSyncUnavailable
		}
		return nil
	}
	var nums []int
	if err := tx.Raw(`SELECT chunk_no FROM collector_snapshot_chunks
		WHERE workspace_id = ? AND snapshot_row_id = ? AND validated
		ORDER BY chunk_no`, p.WorkspaceID, existing.ID).Scan(&nums).Error; err != nil {
		s.note(err)
		return ErrSyncUnavailable
	}
	complete := len(nums) == existing.ExpectedChunks
	for i, n := range nums {
		if n != i+1 {
			complete = false
			break
		}
	}
	if err := tx.Exec(`UPDATE collector_snapshots SET complete = ?, updated_at = ? WHERE id = ? AND workspace_id = ?`,
		complete, now, existing.ID, p.WorkspaceID).Error; err != nil {
		s.note(err)
		return ErrSyncUnavailable
	}
	return nil
}

func (s *CollectorSyncService) enforceScope(p *models.CollectorPrincipal, req *collectorcontract.SyncRequest) error {
	inst, err := repositories.NewCollectorRepository(s.db).GetInstance(p.WorkspaceID, p.CollectorID)
	if err != nil {
		return ErrSyncForbidden
	}
	var scope models.ApprovedScope
	_ = json.Unmarshal(inst.ApprovedScope, &scope)
	switch p.Kind {
	case models.CollectorKindNode:
		for _, ob := range req.Observations {
			if ob.Kind != "collector.health" && !strings.HasPrefix(ob.Kind, "runtime.") {
				return ErrSyncForbidden
			}
		}
		for _, obj := range req.Objects {
			if !nodeSensorObject(obj.Kind) {
				return ErrSyncForbidden
			}
			if scope.BoundNodeName != "" && nativeConflicts(obj.Native, scope.BoundNodeName) {
				return ErrSyncForbidden
			}
		}
	case models.CollectorKindK8s:
		allow := map[string]bool{}
		for _, ns := range scope.Namespaces {
			allow[ns] = true
		}
		for _, obj := range req.Objects {
			if strings.HasPrefix(obj.Kind, "linux.") {
				return ErrSyncForbidden
			}
			if collectorcontract.NamespacedKind(obj.Kind) {
				ns, _ := obj.Native["namespace"].(string)
				if ns == "" || (!allow[ns] && !allow["*"]) {
					return ErrSyncForbidden
				}
			}
			if collectorcontract.ClusterScopedKind(obj.Kind) && !allow["*"] && !collectorcontract.OpenClusterKind(obj.Kind) {
				return ErrSyncForbidden
			}
		}
	default:
		for _, obj := range req.Objects {
			if strings.HasPrefix(obj.Kind, "k8s.") {
				return ErrSyncForbidden
			}
		}
	}
	return nil
}

func nodeSensorObject(kind string) bool {
	switch kind {
	case "linux.systemd_workload", "linux.process_group", "linux.local_account", "linux.local_group",
		"linux.file", "network.endpoint", "secret.reference",
		"k8s.pod", "k8s.workload", "k8s.service_account", "k8s.node":
		return true
	default:
		return false
	}
}

func nativeConflicts(native map[string]any, bound string) bool {
	for _, key := range []string{"node", "node_name", "host", "host_id"} {
		if v, ok := native[key].(string); ok && v != "" && v != bound {
			return true
		}
	}
	return false
}

func classifyPersist(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrSyncConflict) || errors.Is(err, ErrSyncForbidden) || errors.Is(err, ErrSyncUnavailable) {
		return err
	}
	msg := err.Error()
	if strings.Contains(msg, "collector_batches_batch_key") || strings.Contains(msg, "duplicate key") {
		return ErrSyncConflict
	}
	return ErrSyncUnavailable
}

func (s *CollectorSyncService) note(err error) { s.LastPersistErr = err }

// Receipt returns the current receipt for this collector. Another collector's
// receipt is not found.
func (s *CollectorSyncService) Receipt(p *models.CollectorPrincipal, id uuid.UUID) ([]byte, error) {
	if p == nil || !containsString(p.Scopes, models.CollectorScopeReceiptWrite) {
		return nil, ErrSyncForbidden
	}
	var row struct {
		ReceiptState    string
		ProjectionState string
		GraphRevision   int64
		JobState        string
	}
	err := s.db.Raw(`SELECT b.receipt_state, b.projection_state, b.graph_revision, COALESCE(o.state, '')
		FROM collector_batches b
		LEFT JOIN collector_outbox o ON o.workspace_id = b.workspace_id AND o.batch_row_id = b.id
		WHERE b.workspace_id = ? AND b.collector_id = ? AND b.receipt_id = ?`,
		p.WorkspaceID, p.CollectorID, id).Row().Scan(&row.ReceiptState, &row.ProjectionState, &row.GraphRevision, &row.JobState)
	if err != nil {
		return nil, ErrSyncNotFound
	}
	state := "accepted"
	switch row.JobState {
	case "leased":
		state = "projecting"
	case "done":
		state = "published"
	case "failed", "dead":
		state = "failed"
	}
	view := collectorcontract.ReceiptView{
		ReceiptID: id.String(), State: state, ProjectionState: row.ProjectionState,
		PublishedGraphRevision: row.GraphRevision, Mappings: []collectorcontract.Mapping{},
	}
	return json.Marshal(view)
}

// AuthorizeEpoch lets a discovery:admin name the only epoch a collector may
// switch to. The collector presents that epoch on a later sync.
func (s *CollectorSyncService) AuthorizeEpoch(ws, id uuid.UUID, expected int64, next uuid.UUID) (int64, error) {
	if next == uuid.Nil {
		return 0, fmt.Errorf("%w: epoch", ErrCollectorInvalid)
	}
	var version int64
	err := s.db.Transaction(func(tx *gorm.DB) error {
		inst, err := repositories.NewCollectorRepository(tx).LockInstance(ws, id)
		if err != nil {
			if errors.Is(err, repositories.ErrCollectorNotFound) {
				return ErrCollectorNotFound
			}
			return err
		}
		if inst.RowVersion != expected {
			return ErrCollectorVersion
		}
		if inst.Epoch != nil && *inst.Epoch == next {
			return fmt.Errorf("%w: epoch is already current", ErrCollectorInvalid)
		}
		res := tx.Exec(`UPDATE collector_instances
			SET authorized_next_epoch = ?, row_version = row_version + 1, updated_at = ?
			WHERE id = ? AND workspace_id = ? AND row_version = ?`,
			next, s.clock(), id, ws, expected)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected != 1 {
			return ErrCollectorVersion
		}
		version = expected + 1
		return nil
	})
	return version, err
}

// RunWorkerOnce claims one collector_outbox job. ProcessFail, when set, leaves
// the lease in place so a crash between commit and completion loses nothing.
// Completion marks the job done. It does not write canonical graph rows and
// does not bump iga_publication.
func (s *CollectorSyncService) RunWorkerOnce(owner string) error {
	now := s.clock()
	var jobID, batchID uuid.UUID
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var jobText, batchText string
		err := tx.Raw(`UPDATE collector_outbox SET
			state = 'leased', lease_owner = ?, leased_until = ?, attempt_count = attempt_count + 1, updated_at = ?
			WHERE id = (
				SELECT id FROM collector_outbox
				WHERE (state = 'ready' AND available_at <= ?)
				   OR (state = 'leased' AND leased_until IS NOT NULL AND leased_until < ?)
				ORDER BY available_at
				FOR UPDATE SKIP LOCKED
				LIMIT 1
			)
			RETURNING id::text, batch_row_id::text`,
			owner, now.Add(time.Minute), now, now, now).Row().Scan(&jobText, &batchText)
		if err != nil {
			return err
		}
		jobID, err = uuid.Parse(jobText)
		if err != nil {
			return err
		}
		batchID, err = uuid.Parse(batchText)
		if err != nil {
			return err
		}
		return tx.Exec(`UPDATE collector_batches SET receipt_state = 'projecting'
			WHERE id = ?`, batchID).Error
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return err
	}
	if s.ProcessFail != nil {
		if err := s.ProcessFail(); err != nil {
			return err
		}
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`UPDATE collector_outbox SET state = 'done', lease_owner = NULL, leased_until = NULL, updated_at = ?
			WHERE id = ?`, now, jobID).Error; err != nil {
			return err
		}
		return tx.Exec(`UPDATE collector_batches SET receipt_state = 'published', projection_state = 'published'
			WHERE id = ?`, batchID).Error
	})
}
