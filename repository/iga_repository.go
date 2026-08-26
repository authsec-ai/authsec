package repositories

import (
	"errors"
	"fmt"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Errors the API layer maps to specific status codes. They exist so a caller
// can tell "you may not" from "it is not there" from "someone changed it".
var (
	ErrIGANotFound      = errors.New("not found")
	ErrIGAVersionStale  = errors.New("version conflict: re-read and retry")
	ErrIGABindingFailed = errors.New("installation binding could not be verified")
	ErrIGASignature     = errors.New("webhook signature verification failed")
)

// IGARepository is the persistence surface for the Agentic IGA model. Every
// method takes an explicit workspaceID; none reads it from ambient state.
type IGARepository interface {
	// Integrations
	CreateIntegration(in *models.IGAIntegration) error
	GetIntegration(workspaceID, id uuid.UUID) (*models.IGAIntegration, error)
	ListIntegrations(workspaceID uuid.UUID) ([]models.IGAIntegration, error)
	// VerifyIntegration is the moment an untrusted installation id becomes a
	// trusted binding. It fails if another workspace already owns it.
	VerifyIntegration(workspaceID, id uuid.UUID, installationID, accountNativeID string, granted []byte) (*models.IGAIntegration, error)
	DisconnectIntegration(workspaceID, id uuid.UUID) error
	// DeleteIntegration removes the binding outright. Distinct from
	// DisconnectIntegration, which is the governance action on a live
	// integration and deliberately retains history.
	//
	// This is for the two cases where there is no history worth keeping: rolling
	// back a create that failed before it verified, and removing an integration
	// whose discovery source is being deleted. Its scan runs, coverage and
	// source objects cascade with it; discovered agents do not -- they are
	// ON DELETE SET NULL, because a finding must outlive the scanner that
	// found it.
	DeleteIntegration(workspaceID, id uuid.UUID) error
	// ResolveBinding maps a provider-side (app registration, installation) pair
	// to a verified integration. This is how a webhook learns its workspace —
	// never from the payload.
	ResolveBinding(appRegistrationID, installationID string) (*models.IGAIntegration, error)

	// Scopes and coverage
	UpsertScope(s *models.IGAIntegrationScope) error
	ListScopes(workspaceID, integrationID uuid.UUID) ([]models.IGAIntegrationScope, error)
	UpsertCoverage(c *models.IGACoverageState) error
	ListCoverage(workspaceID, integrationID uuid.UUID) ([]models.IGACoverageState, error)

	// Scans
	CreateScanRun(r *models.IGAScanRun) error
	GetScanRun(workspaceID, id uuid.UUID) (*models.IGAScanRun, error)
	NextGeneration(workspaceID, integrationID uuid.UUID) (int64, error)
	SaveCheckpoint(cp *models.IGAScanCheckpoint) error
	ListCheckpoints(workspaceID, scanRunID uuid.UUID) ([]models.IGAScanCheckpoint, error)
	// PublishScan is the scan-publication transaction: mark succeeded, publish
	// coverage and advance the authoritative generation together, or not at all.
	PublishScan(workspaceID, scanRunID uuid.UUID, coverage []models.IGACoverageState) error
	FailScan(workspaceID, scanRunID uuid.UUID, code string) error

	// Evidence. IngestEvidence is the projection transaction: observations are
	// appended BEFORE anything canonical moves.
	UpsertSourceObject(o *models.IGASourceObject) (*models.IGASourceObject, error)
	GetSourceObject(workspaceID, id uuid.UUID) (*models.IGASourceObject, error)
	// FindSourceObjectByKey powers the cheap-refresh check: if the stored
	// raw_hash still matches the blob SHA the tree listing already gave us,
	// the file has not changed and the fetch can be skipped entirely.
	FindSourceObjectByKey(workspaceID, integrationID uuid.UUID, objectType, recognitionKey string) (*models.IGASourceObject, error)
	// TouchSourceObject marks an unchanged object as seen in this generation.
	// It updates ONLY the liveness columns — the previously extracted facts
	// must survive, since skipping a fetch means we learned nothing new, not
	// that the old knowledge is gone.
	TouchSourceObject(workspaceID, integrationID uuid.UUID, objectType, recognitionKey string, generation int64) error
	AppendObservation(o *models.IGAObservation) (*models.IGAObservation, error)
	ListObservations(workspaceID, sourceObjectID uuid.UUID) ([]models.IGAObservation, error)
	// ListObservationsForTarget walks observation_links to return the evidence
	// behind a canonical object — the drill-down every displayed fact needs.
	ListObservationsForTarget(workspaceID uuid.UUID, targetKind string, targetID uuid.UUID) ([]models.IGAObservation, error)

	// Candidates
	UpsertCandidate(c *models.IGACandidate) (*models.IGACandidate, error)
	GetCandidate(workspaceID, id uuid.UUID) (*models.IGACandidate, error)
	ListCandidates(workspaceID uuid.UUID, state string, limit, offset int) ([]models.IGACandidate, int64, error)
	// DecideCandidate uses optimistic concurrency: a stale expectedVersion is
	// rejected rather than silently overwriting someone else's decision.
	DecideCandidate(workspaceID, id uuid.UUID, expectedVersion int64, state, reason, decidedBy string) (*models.IGACandidate, error)

	// Canonical graph
	CreateAgent(a *models.IGAAgent) error
	GetAgent(workspaceID, id uuid.UUID) (*models.IGAAgent, error)
	ListAgents(workspaceID uuid.UUID, rollup string, limit, offset int) ([]models.IGAAgent, int64, error)
	UpsertIdentityAccount(a *models.IGAIdentityAccount) error
	UpsertCredential(c *models.IGACredential) error
	UpsertResource(r *models.IGAResource) error
	UpsertEntitlement(e *models.IGAEntitlement) error
	UpsertAccessEdge(e *models.IGAAccessEdge) error
	ListAccessEdges(workspaceID uuid.UUID, subjectID uuid.UUID) ([]models.IGAAccessEdge, error)
	LinkObservation(l *models.IGAObservationLink) error
	ListObservationLinks(workspaceID uuid.UUID, targetKind string, targetID uuid.UUID) ([]models.IGAObservationLink, error)
	CreateCorrelation(c *models.IGACorrelation) error

	// Ownership
	UpsertOwnershipCandidate(o *models.IGAOwnershipCandidate) error
	ListOwnershipCandidates(workspaceID uuid.UUID, subjectID uuid.UUID) ([]models.IGAOwnershipCandidate, error)
	DecideOwnership(workspaceID, id uuid.UUID, expectedVersion int64, state, decidedBy string) (*models.IGAOwnershipCandidate, error)

	// Ingress. AcceptDelivery is the webhook-acceptance transaction: the
	// delivery row and its job commit together, before any 2xx is returned.
	AcceptDelivery(d *models.IGAWebhookDelivery, job *models.IGADurableJob) (accepted bool, existing bool, err error)
	RecordRejectedDelivery(d *models.IGAWebhookDelivery) error
	ClaimJob(worker string, lease time.Duration) (*models.IGADurableJob, error)
	CompleteJob(workspaceID, jobID uuid.UUID, state, lastErr string) error

	// Operational issues, kept apart from agent findings.
	RecordIssue(i *models.IGAOperationalIssue) error
	ListIssues(workspaceID uuid.UUID, integrationID *uuid.UUID) ([]models.IGAOperationalIssue, error)

	// Deletion safety. CountGenerationDrift reports how many objects the latest
	// authoritative generation saw versus missed, so the caller can refuse to
	// tombstone when too many vanish at once.
	CountGenerationDrift(workspaceID, integrationID uuid.UUID, objectType string, generation int64) (alive, missing int64, err error)
	TombstoneAbsent(workspaceID, integrationID uuid.UUID, objectType string, generation int64) (int, error)

	// Attribute survivorship.
	GetSurvivingAttribute(workspaceID uuid.UUID, entityKind string, entityID uuid.UUID, attribute string) (*models.IGAAttributeValue, error)
	AppendAttributeValue(v *models.IGAAttributeValue) error
	SupersedeAttribute(workspaceID, id uuid.UUID) error
	ListAttributeValues(workspaceID uuid.UUID, entityKind string, entityID uuid.UUID) ([]models.IGAAttributeValue, error)

	// Cursor pagination. Offset pagination is prohibited for changing
	// inventories, so these return an opaque cursor built from the sort key.
	ListAgentsCursor(workspaceID uuid.UUID, rollup string, after *CursorKeyT, limit int) ([]models.IGAAgent, error)
	ListCandidatesCursor(workspaceID uuid.UUID, state string, after *CursorKeyT, limit int) ([]models.IGACandidate, error)
	ListIdentityAccounts(workspaceID uuid.UUID, after *CursorKeyT, limit int) ([]models.IGAIdentityAccount, error)
	CountAgents(workspaceID uuid.UUID, rollup string) (int64, error)
	CountCandidates(workspaceID uuid.UUID, state string) (int64, error)

	// Access paths for a subject, plus their entitlement and resource.
	ListAccessPaths(workspaceID uuid.UUID, subjectID uuid.UUID) ([]AccessPath, error)
	ListCredentialsFor(workspaceID, identityAccountID uuid.UUID) ([]models.IGACredential, error)
	ListCorrelationsFor(workspaceID uuid.UUID, canonicalKind string, canonicalID uuid.UUID) ([]models.IGACorrelation, error)

	// Idempotency for POST scan and decision routes.
	GetIdempotent(workspaceID uuid.UUID, key string) (*IdempotencyRecord, error)
	PutIdempotent(rec *IdempotencyRecord) error
}

// cursorKey is the opaque pagination position: the sort key plus a
// deterministic tie-breaker, so a row inserted mid-page cannot cause a skip or
// a repeat the way an offset would.
type CursorKeyT struct {
	CreatedAt time.Time
	ID        uuid.UUID
}

// NewCursorKey builds a cursor position.
func NewCursorKey(createdAt time.Time, id uuid.UUID) *CursorKeyT {
	return &CursorKeyT{CreatedAt: createdAt, ID: id}
}

// CursorParts exposes the position for encoding by the API layer.
func (c *CursorKeyT) CursorParts() (time.Time, uuid.UUID) { return c.CreatedAt, c.ID }

// AccessPath is one subject -> entitlement -> resource hop, joined for display.
type AccessPath struct {
	Edge        models.IGAAccessEdge   `json:"edge"`
	Entitlement *models.IGAEntitlement `json:"entitlement,omitempty"`
	Resource    *models.IGAResource    `json:"resource,omitempty"`
}

// IdempotencyRecord is a stored response for a replayed request.
type IdempotencyRecord struct {
	WorkspaceID    uuid.UUID `gorm:"column:workspace_id"`
	IdempotencyKey string    `gorm:"column:idempotency_key"`
	Route          string    `gorm:"column:route"`
	RequestHash    string    `gorm:"column:request_hash"`
	ResponseStatus int       `gorm:"column:response_status"`
	ResponseBody   []byte    `gorm:"column:response_body"`
	CreatedAt      time.Time `gorm:"column:created_at"`
}

func (IdempotencyRecord) TableName() string { return "iga_idempotency_keys" }

type igaRepository struct{ db *gorm.DB }

// NewIGARepository constructs an IGARepository.
func NewIGARepository(db *gorm.DB) IGARepository { return &igaRepository{db} }

func notFound(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrIGANotFound
	}
	return err
}

/* ----------------------------- integrations ---------------------------- */

func (r *igaRepository) CreateIntegration(in *models.IGAIntegration) error {
	return r.db.Create(in).Error
}

func (r *igaRepository) GetIntegration(workspaceID, id uuid.UUID) (*models.IGAIntegration, error) {
	var out models.IGAIntegration
	if err := r.db.First(&out, "id = ? AND workspace_id = ?", id, workspaceID).Error; err != nil {
		return nil, notFound(err)
	}
	return &out, nil
}

func (r *igaRepository) ListIntegrations(workspaceID uuid.UUID) ([]models.IGAIntegration, error) {
	var out []models.IGAIntegration
	err := r.db.Where("workspace_id = ?", workspaceID).Order("created_at DESC").Find(&out).Error
	return out, err
}

func (r *igaRepository) VerifyIntegration(workspaceID, id uuid.UUID, installationID, accountNativeID string, granted []byte) (*models.IGAIntegration, error) {
	now := time.Now()
	fields := map[string]interface{}{
		"installation_id":     installationID,
		"account_native_id":   accountNativeID,
		"granted_permissions": granted,
		"status":              "active",
		"verified_at":         now,
		"updated_at":          now,
	}

	res := r.db.Model(&models.IGAIntegration{}).
		Where("id = ? AND workspace_id = ?", id, workspaceID).
		Updates(fields)
	if res.Error != nil {
		// uq_iga_integrations_verified_installation deliberately excludes
		// workspace_id, so this is the cross-workspace rebinding guard firing.
		return nil, fmt.Errorf("%w: %v", ErrIGABindingFailed, res.Error)
	}
	if res.RowsAffected == 0 {
		return nil, ErrIGANotFound
	}
	return r.GetIntegration(workspaceID, id)
}

func (r *igaRepository) DisconnectIntegration(workspaceID, id uuid.UUID) error {
	// Disable future reads but retain governed history — the spec is explicit
	// that disconnect is not deletion.
	res := r.db.Model(&models.IGAIntegration{}).
		Where("id = ? AND workspace_id = ?", id, workspaceID).
		Updates(map[string]interface{}{
			"status": "disconnected", "verified_at": nil, "updated_at": time.Now(),
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrIGANotFound
	}
	return nil
}

func (r *igaRepository) DeleteIntegration(workspaceID, id uuid.UUID) error {
	res := r.db.Delete(&models.IGAIntegration{}, "id = ? AND workspace_id = ?", id, workspaceID)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrIGANotFound
	}
	return nil
}

func (r *igaRepository) ResolveBinding(appRegistrationID, installationID string) (*models.IGAIntegration, error) {
	var out models.IGAIntegration
	err := r.db.First(&out,
		"app_registration_id = ? AND installation_id = ? AND verified_at IS NOT NULL AND status = ?",
		appRegistrationID, installationID, "active").Error
	if err != nil {
		return nil, notFound(err)
	}
	return &out, nil
}

/* -------------------------- scopes and coverage ------------------------ */

func (r *igaRepository) UpsertScope(s *models.IGAIntegrationScope) error {
	return r.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "workspace_id"}, {Name: "integration_id"},
			{Name: "native_scope_kind"}, {Name: "native_scope_id"},
		},
		DoUpdates: clause.AssignmentColumns([]string{
			"selection_state", "filters", "effective_permissions", "estate_scope_id", "updated_at",
		}),
	}).Create(s).Error
}

func (r *igaRepository) ListScopes(workspaceID, integrationID uuid.UUID) ([]models.IGAIntegrationScope, error) {
	var out []models.IGAIntegrationScope
	err := r.db.Where("workspace_id = ? AND integration_id = ?", workspaceID, integrationID).
		Order("native_scope_kind, native_scope_id").Find(&out).Error
	return out, err
}

func (r *igaRepository) UpsertCoverage(c *models.IGACoverageState) error {
	return r.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "workspace_id"}, {Name: "integration_id"},
			{Name: "integration_scope_id"}, {Name: "object_class"},
		},
		DoUpdates: clause.AssignmentColumns([]string{
			"state", "reason_code", "last_success_at", "last_attempt_at",
			"watermark", "inspected_count", "denied_count", "updated_at",
		}),
	}).Create(c).Error
}

func (r *igaRepository) ListCoverage(workspaceID, integrationID uuid.UUID) ([]models.IGACoverageState, error) {
	var out []models.IGACoverageState
	err := r.db.Where("workspace_id = ? AND integration_id = ?", workspaceID, integrationID).
		Order("object_class").Find(&out).Error
	return out, err
}

/* -------------------------------- scans -------------------------------- */

func (r *igaRepository) CreateScanRun(run *models.IGAScanRun) error {
	return r.db.Create(run).Error
}

func (r *igaRepository) GetScanRun(workspaceID, id uuid.UUID) (*models.IGAScanRun, error) {
	var out models.IGAScanRun
	if err := r.db.First(&out, "id = ? AND workspace_id = ?", id, workspaceID).Error; err != nil {
		return nil, notFound(err)
	}
	return &out, nil
}

func (r *igaRepository) NextGeneration(workspaceID, integrationID uuid.UUID) (int64, error) {
	var maxGen *int64
	err := r.db.Model(&models.IGAScanRun{}).
		Where("workspace_id = ? AND integration_id = ?", workspaceID, integrationID).
		Select("MAX(generation)").Scan(&maxGen).Error
	if err != nil {
		return 0, err
	}
	if maxGen == nil {
		return 1, nil
	}
	return *maxGen + 1, nil
}

func (r *igaRepository) SaveCheckpoint(cp *models.IGAScanCheckpoint) error {
	cp.UpdatedAt = time.Now()
	return r.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "workspace_id"}, {Name: "scan_run_id"},
			{Name: "object_class"}, {Name: "partition_key"},
		},
		DoUpdates: clause.AssignmentColumns([]string{
			"cursor", "watermark", "lease_owner", "leased_until", "attempt_count", "updated_at",
		}),
	}).Create(cp).Error
}

func (r *igaRepository) ListCheckpoints(workspaceID, scanRunID uuid.UUID) ([]models.IGAScanCheckpoint, error) {
	var out []models.IGAScanCheckpoint
	err := r.db.Where("workspace_id = ? AND scan_run_id = ?", workspaceID, scanRunID).
		Order("object_class, partition_key").Find(&out).Error
	return out, err
}

// PublishScan: succeeded + coverage + authoritative generation, atomically.
// An interrupted scan cannot leave a half-published coverage picture behind.
func (r *igaRepository) PublishScan(workspaceID, scanRunID uuid.UUID, coverage []models.IGACoverageState) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		now := time.Now()
		res := tx.Model(&models.IGAScanRun{}).
			Where("id = ? AND workspace_id = ? AND status = ?", scanRunID, workspaceID, models.ScanRunning).
			Updates(map[string]interface{}{
				"status": models.ScanSucceeded, "completed_at": now, "is_authoritative": true,
			})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return fmt.Errorf("%w: scan is not running", ErrIGANotFound)
		}

		for i := range coverage {
			c := coverage[i]
			c.UpdatedAt = now
			if err := tx.Clauses(clause.OnConflict{
				Columns: []clause.Column{
					{Name: "workspace_id"}, {Name: "integration_id"},
					{Name: "integration_scope_id"}, {Name: "object_class"},
				},
				DoUpdates: clause.AssignmentColumns([]string{
					"state", "reason_code", "last_success_at", "last_attempt_at",
					"watermark", "inspected_count", "denied_count", "updated_at",
				}),
			}).Create(&c).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *igaRepository) FailScan(workspaceID, scanRunID uuid.UUID, code string) error {
	now := time.Now()
	return r.db.Model(&models.IGAScanRun{}).
		Where("id = ? AND workspace_id = ?", scanRunID, workspaceID).
		Updates(map[string]interface{}{
			"status": models.ScanFailed, "failure_code": code, "completed_at": now,
		}).Error
}

/* ------------------------------- evidence ------------------------------ */

func (r *igaRepository) UpsertSourceObject(o *models.IGASourceObject) (*models.IGASourceObject, error) {
	err := r.db.Clauses(
		clause.OnConflict{
			Columns: []clause.Column{
				{Name: "workspace_id"}, {Name: "integration_id"},
				{Name: "object_type"}, {Name: "recognition_key"},
			},
			// A rename changes the locator, never the identity — so locator is
			// refreshed while the recognition key holds the row steady.
			DoUpdates: clause.Assignments(map[string]interface{}{
				"locator":            gorm.Expr("excluded.locator"),
				"normalized_payload": gorm.Expr("excluded.normalized_payload"),
				"raw_hash":           gorm.Expr("excluded.raw_hash"),
				"source_version":     gorm.Expr("excluded.source_version"),
				"scan_generation":    gorm.Expr("excluded.scan_generation"),
				"last_seen_at":       time.Now(),
				// A previously tombstoned object seen again is active again.
				"lifecycle":     models.LifecycleActive,
				"tombstoned_at": nil,
			}),
		},
		clause.Returning{},
	).Create(o).Error
	if err != nil {
		return nil, err
	}
	return o, nil
}

func (r *igaRepository) GetSourceObject(workspaceID, id uuid.UUID) (*models.IGASourceObject, error) {
	var out models.IGASourceObject
	if err := r.db.First(&out, "id = ? AND workspace_id = ?", id, workspaceID).Error; err != nil {
		return nil, notFound(err)
	}
	return &out, nil
}

// AppendObservation is append-only and idempotent by dedupe_key. A replayed
// webhook or a re-run scan segment is a no-op rather than a duplicate fact.
func (r *igaRepository) AppendObservation(o *models.IGAObservation) (*models.IGAObservation, error) {
	err := r.db.Clauses(
		clause.OnConflict{
			Columns:   []clause.Column{{Name: "workspace_id"}, {Name: "dedupe_key"}},
			DoNothing: true,
		},
		clause.Returning{},
	).Create(o).Error
	if err != nil {
		return nil, err
	}
	// DoNothing yields a zero id; fetch the row that won.
	if o.ID == uuid.Nil {
		var existing models.IGAObservation
		if err := r.db.First(&existing, "workspace_id = ? AND dedupe_key = ?",
			o.WorkspaceID, o.DedupeKey).Error; err != nil {
			return nil, err
		}
		return &existing, nil
	}
	return o, nil
}

func (r *igaRepository) ListObservations(workspaceID, sourceObjectID uuid.UUID) ([]models.IGAObservation, error) {
	var out []models.IGAObservation
	err := r.db.Where("workspace_id = ? AND source_object_id = ?", workspaceID, sourceObjectID).
		Order("observed_at DESC").Find(&out).Error
	return out, err
}

func (r *igaRepository) FindSourceObjectByKey(workspaceID, integrationID uuid.UUID, objectType, recognitionKey string) (*models.IGASourceObject, error) {
	var out models.IGASourceObject
	err := r.db.First(&out,
		"workspace_id = ? AND integration_id = ? AND object_type = ? AND recognition_key = ?",
		workspaceID, integrationID, objectType, recognitionKey).Error
	if err != nil {
		return nil, notFound(err)
	}
	return &out, nil
}

func (r *igaRepository) TouchSourceObject(workspaceID, integrationID uuid.UUID, objectType, recognitionKey string, generation int64) error {
	return r.db.Model(&models.IGASourceObject{}).
		Where("workspace_id = ? AND integration_id = ? AND object_type = ? AND recognition_key = ?",
			workspaceID, integrationID, objectType, recognitionKey).
		Updates(map[string]interface{}{
			"last_seen_at":    time.Now(),
			"scan_generation": generation,
			"lifecycle":       models.LifecycleActive,
		}).Error
}

func (r *igaRepository) ListObservationsForTarget(workspaceID uuid.UUID, targetKind string, targetID uuid.UUID) ([]models.IGAObservation, error) {
	var out []models.IGAObservation
	err := r.db.
		Joins("JOIN iga_observation_links l ON l.observation_id = iga_observations.id AND l.workspace_id = iga_observations.workspace_id").
		Where("iga_observations.workspace_id = ? AND l.target_kind = ? AND l.target_id = ?",
			workspaceID, targetKind, targetID).
		Order("iga_observations.observed_at DESC").
		Find(&out).Error
	return out, err
}

/* ------------------------------ candidates ----------------------------- */

func (r *igaRepository) UpsertCandidate(c *models.IGACandidate) (*models.IGACandidate, error) {
	// The partial unique index allows one PENDING row per signature. A repeat
	// proposal for an already-pending signature is a no-op, not an error.
	var existing models.IGACandidate
	err := r.db.First(&existing, "workspace_id = ? AND proposal_signature = ? AND state = ?",
		c.WorkspaceID, c.ProposalSignature, models.CandidatePending).Error
	if err == nil {
		return &existing, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	if err := r.db.Create(c).Error; err != nil {
		return nil, err
	}
	return c, nil
}

func (r *igaRepository) GetCandidate(workspaceID, id uuid.UUID) (*models.IGACandidate, error) {
	var out models.IGACandidate
	if err := r.db.First(&out, "id = ? AND workspace_id = ?", id, workspaceID).Error; err != nil {
		return nil, notFound(err)
	}
	return &out, nil
}

func (r *igaRepository) ListCandidates(workspaceID uuid.UUID, state string, limit, offset int) ([]models.IGACandidate, int64, error) {
	q := r.db.Model(&models.IGACandidate{}).Where("workspace_id = ?", workspaceID)
	if state != "" {
		q = q.Where("state = ?", state)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var out []models.IGACandidate
	err := q.Order("created_at DESC, id").Limit(limit).Offset(offset).Find(&out).Error
	return out, total, err
}

func (r *igaRepository) DecideCandidate(workspaceID, id uuid.UUID, expectedVersion int64, state, reason, decidedBy string) (*models.IGACandidate, error) {
	now := time.Now()
	res := r.db.Model(&models.IGACandidate{}).
		Where("id = ? AND workspace_id = ? AND version = ?", id, workspaceID, expectedVersion).
		Updates(map[string]interface{}{
			"state": state, "reason": reason, "decided_by": decidedBy,
			"decided_at": now, "version": expectedVersion + 1, "updated_at": now,
		})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		// Either it is gone or someone decided first. Distinguish, so the API
		// can return 404 vs 409 rather than a vague error.
		if _, err := r.GetCandidate(workspaceID, id); err != nil {
			return nil, err
		}
		return nil, ErrIGAVersionStale
	}
	return r.GetCandidate(workspaceID, id)
}

/* --------------------------- canonical graph --------------------------- */

func (r *igaRepository) CreateAgent(a *models.IGAAgent) error { return r.db.Create(a).Error }

func (r *igaRepository) GetAgent(workspaceID, id uuid.UUID) (*models.IGAAgent, error) {
	var out models.IGAAgent
	if err := r.db.First(&out, "id = ? AND workspace_id = ?", id, workspaceID).Error; err != nil {
		return nil, notFound(err)
	}
	return &out, nil
}

func (r *igaRepository) ListAgents(workspaceID uuid.UUID, rollup string, limit, offset int) ([]models.IGAAgent, int64, error) {
	q := r.db.Model(&models.IGAAgent{}).Where("workspace_id = ?", workspaceID)
	if rollup != "" {
		q = q.Where("rollup_state = ?", rollup)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var out []models.IGAAgent
	// Deterministic tie-breaker so cursor pagination is stable.
	err := q.Order("created_at DESC, id").Limit(limit).Offset(offset).Find(&out).Error
	return out, total, err
}

func (r *igaRepository) UpsertIdentityAccount(a *models.IGAIdentityAccount) error {
	return r.db.Create(a).Error
}
func (r *igaRepository) UpsertCredential(c *models.IGACredential) error {
	return r.db.Create(c).Error
}
func (r *igaRepository) UpsertResource(res *models.IGAResource) error {
	return r.db.Create(res).Error
}
func (r *igaRepository) UpsertEntitlement(e *models.IGAEntitlement) error {
	return r.db.Create(e).Error
}
func (r *igaRepository) UpsertAccessEdge(e *models.IGAAccessEdge) error {
	return r.db.Create(e).Error
}

func (r *igaRepository) ListAccessEdges(workspaceID uuid.UUID, subjectID uuid.UUID) ([]models.IGAAccessEdge, error) {
	var out []models.IGAAccessEdge
	err := r.db.Where("workspace_id = ? AND subject_id = ?", workspaceID, subjectID).
		Order("direction, created_at").Find(&out).Error
	return out, err
}

func (r *igaRepository) LinkObservation(l *models.IGAObservationLink) error {
	return r.db.Clauses(clause.OnConflict{DoNothing: true}).Create(l).Error
}

func (r *igaRepository) ListObservationLinks(workspaceID uuid.UUID, targetKind string, targetID uuid.UUID) ([]models.IGAObservationLink, error) {
	var out []models.IGAObservationLink
	err := r.db.Where("workspace_id = ? AND target_kind = ? AND target_id = ?",
		workspaceID, targetKind, targetID).Order("created_at").Find(&out).Error
	return out, err
}

func (r *igaRepository) CreateCorrelation(c *models.IGACorrelation) error {
	return r.db.Create(c).Error
}

/* ------------------------------- ownership ----------------------------- */

func (r *igaRepository) UpsertOwnershipCandidate(o *models.IGAOwnershipCandidate) error {
	return r.db.Create(o).Error
}

func (r *igaRepository) ListOwnershipCandidates(workspaceID uuid.UUID, subjectID uuid.UUID) ([]models.IGAOwnershipCandidate, error) {
	var out []models.IGAOwnershipCandidate
	err := r.db.Where("workspace_id = ? AND subject_id = ?", workspaceID, subjectID).
		Order("rank DESC, created_at").Find(&out).Error
	return out, err
}

func (r *igaRepository) DecideOwnership(workspaceID, id uuid.UUID, expectedVersion int64, state, decidedBy string) (*models.IGAOwnershipCandidate, error) {
	now := time.Now()
	res := r.db.Model(&models.IGAOwnershipCandidate{}).
		Where("id = ? AND workspace_id = ? AND version = ?", id, workspaceID, expectedVersion).
		Updates(map[string]interface{}{
			"state": state, "decided_by": decidedBy, "decided_at": now,
			"version": expectedVersion + 1, "updated_at": now,
		})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		var probe models.IGAOwnershipCandidate
		if err := r.db.First(&probe, "id = ? AND workspace_id = ?", id, workspaceID).Error; err != nil {
			return nil, notFound(err)
		}
		return nil, ErrIGAVersionStale
	}
	var out models.IGAOwnershipCandidate
	if err := r.db.First(&out, "id = ? AND workspace_id = ?", id, workspaceID).Error; err != nil {
		return nil, notFound(err)
	}
	return &out, nil
}

/* -------------------------------- ingress ------------------------------ */

// AcceptDelivery commits the delivery record and its job in ONE transaction.
// The caller returns 2xx only after this succeeds — acknowledging first would
// lose the event if the process died before the durable write.
//
// Returns existing=true for a redelivery, which must produce no second effect.
func (r *igaRepository) AcceptDelivery(d *models.IGAWebhookDelivery, job *models.IGADurableJob) (bool, bool, error) {
	var existing bool
	err := r.db.Transaction(func(tx *gorm.DB) error {
		res := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "app_registration_id"}, {Name: "delivery_id"}},
			DoNothing: true,
		}).Create(d)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			existing = true
			return nil // redelivery: previously committed acceptance stands
		}
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "workspace_id"}, {Name: "integration_id"}, {Name: "dedupe_key"}},
			DoNothing: true,
		}).Create(job).Error
	})
	if err != nil {
		return false, false, err
	}
	return true, existing, nil
}

func (r *igaRepository) RecordRejectedDelivery(d *models.IGAWebhookDelivery) error {
	return r.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "app_registration_id"}, {Name: "delivery_id"}},
		DoNothing: true,
	}).Create(d).Error
}

// ClaimJob leases one ready job. The UPDATE ... WHERE state='ready' is the
// mutual exclusion: two workers racing cannot both win the same row.
func (r *igaRepository) ClaimJob(worker string, lease time.Duration) (*models.IGADurableJob, error) {
	var claimed models.IGADurableJob
	now := time.Now()
	until := now.Add(lease)

	err := r.db.Transaction(func(tx *gorm.DB) error {
		var candidate models.IGADurableJob
		err := tx.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Where("state = ? AND available_at <= ?", models.JobReady, now).
			Or("state = ? AND leased_until < ?", models.JobLeased, now). // reclaim a dead worker's lease
			Order("available_at").First(&candidate).Error
		if err != nil {
			return err
		}
		res := tx.Model(&models.IGADurableJob{}).
			Where("id = ?", candidate.ID).
			Updates(map[string]interface{}{
				"state": models.JobLeased, "lease_owner": worker, "leased_until": until,
				"attempt_count": candidate.AttemptCount + 1, "updated_at": now,
			})
		if res.Error != nil {
			return res.Error
		}
		return tx.First(&claimed, "id = ?", candidate.ID).Error
	})
	if err != nil {
		return nil, notFound(err)
	}
	return &claimed, nil
}

func (r *igaRepository) CompleteJob(workspaceID, jobID uuid.UUID, state, lastErr string) error {
	return r.db.Model(&models.IGADurableJob{}).
		Where("id = ? AND workspace_id = ?", jobID, workspaceID).
		Updates(map[string]interface{}{
			"state": state, "last_error": lastErr, "lease_owner": nil,
			"leased_until": nil, "updated_at": time.Now(),
		}).Error
}

/* --------------------------- operational issues ------------------------ */

func (r *igaRepository) RecordIssue(i *models.IGAOperationalIssue) error {
	return r.db.Create(i).Error
}

func (r *igaRepository) ListIssues(workspaceID uuid.UUID, integrationID *uuid.UUID) ([]models.IGAOperationalIssue, error) {
	q := r.db.Where("workspace_id = ?", workspaceID)
	if integrationID != nil {
		q = q.Where("integration_id = ?", *integrationID)
	}
	var out []models.IGAOperationalIssue
	err := q.Order("last_seen_at DESC").Find(&out).Error
	return out, err
}

/* --------------------------- deletion safety --------------------------- */

func (r *igaRepository) CountGenerationDrift(workspaceID, integrationID uuid.UUID, objectType string, generation int64) (int64, int64, error) {
	var alive, missing int64
	base := r.db.Model(&models.IGASourceObject{}).
		Where("workspace_id = ? AND integration_id = ? AND object_type = ? AND lifecycle = ?",
			workspaceID, integrationID, objectType, models.LifecycleActive)
	if err := base.Session(&gorm.Session{}).
		Where("scan_generation = ?", generation).Count(&alive).Error; err != nil {
		return 0, 0, err
	}
	if err := base.Session(&gorm.Session{}).
		Where("scan_generation IS NULL OR scan_generation < ?", generation).Count(&missing).Error; err != nil {
		return 0, 0, err
	}
	return alive, missing, nil
}

func (r *igaRepository) TombstoneAbsent(workspaceID, integrationID uuid.UUID, objectType string, generation int64) (int, error) {
	now := time.Now()
	res := r.db.Model(&models.IGASourceObject{}).
		Where(`workspace_id = ? AND integration_id = ? AND object_type = ? AND lifecycle = ?
		       AND (scan_generation IS NULL OR scan_generation < ?)`,
			workspaceID, integrationID, objectType, models.LifecycleActive, generation).
		Updates(map[string]interface{}{
			"lifecycle": models.LifecycleTombstoned, "tombstoned_at": now,
		})
	return int(res.RowsAffected), res.Error
}

/* ------------------------- attribute survivorship ---------------------- */

func (r *igaRepository) GetSurvivingAttribute(workspaceID uuid.UUID, entityKind string, entityID uuid.UUID, attribute string) (*models.IGAAttributeValue, error) {
	var out models.IGAAttributeValue
	err := r.db.First(&out,
		"workspace_id = ? AND entity_kind = ? AND entity_id = ? AND attribute = ? AND state = ?",
		workspaceID, entityKind, entityID, attribute, "surviving").Error
	if err != nil {
		return nil, notFound(err)
	}
	return &out, nil
}

func (r *igaRepository) AppendAttributeValue(v *models.IGAAttributeValue) error {
	return r.db.Create(v).Error
}

func (r *igaRepository) SupersedeAttribute(workspaceID, id uuid.UUID) error {
	return r.db.Model(&models.IGAAttributeValue{}).
		Where("id = ? AND workspace_id = ?", id, workspaceID).
		Update("state", "superseded").Error
}

func (r *igaRepository) ListAttributeValues(workspaceID uuid.UUID, entityKind string, entityID uuid.UUID) ([]models.IGAAttributeValue, error) {
	var out []models.IGAAttributeValue
	err := r.db.Where("workspace_id = ? AND entity_kind = ? AND entity_id = ?",
		workspaceID, entityKind, entityID).
		Order("authority_rank DESC, created_at DESC").Find(&out).Error
	return out, err
}

/* --------------------------- cursor pagination -------------------------- */

// afterCursor applies the keyset predicate. Ordering is (created_at DESC, id
// DESC) with the id as a deterministic tie-breaker, so concurrent inserts
// cannot cause a page to skip or repeat a row — which is exactly what offset
// pagination gets wrong on a changing inventory.
func afterCursor(q *gorm.DB, after *CursorKeyT) *gorm.DB {
	if after == nil {
		return q
	}
	return q.Where("(created_at, id) < (?, ?)", after.CreatedAt, after.ID)
}

func (r *igaRepository) ListAgentsCursor(workspaceID uuid.UUID, rollup string, after *CursorKeyT, limit int) ([]models.IGAAgent, error) {
	q := r.db.Where("workspace_id = ?", workspaceID)
	if rollup != "" {
		q = q.Where("rollup_state = ?", rollup)
	}
	var out []models.IGAAgent
	err := afterCursor(q, after).Order("created_at DESC, id DESC").Limit(limit).Find(&out).Error
	return out, err
}

func (r *igaRepository) ListCandidatesCursor(workspaceID uuid.UUID, state string, after *CursorKeyT, limit int) ([]models.IGACandidate, error) {
	q := r.db.Where("workspace_id = ?", workspaceID)
	if state != "" {
		q = q.Where("state = ?", state)
	}
	var out []models.IGACandidate
	err := afterCursor(q, after).Order("created_at DESC, id DESC").Limit(limit).Find(&out).Error
	return out, err
}

func (r *igaRepository) ListIdentityAccounts(workspaceID uuid.UUID, after *CursorKeyT, limit int) ([]models.IGAIdentityAccount, error) {
	q := r.db.Where("workspace_id = ?", workspaceID)
	var out []models.IGAIdentityAccount
	err := afterCursor(q, after).Order("created_at DESC, id DESC").Limit(limit).Find(&out).Error
	return out, err
}

func (r *igaRepository) CountAgents(workspaceID uuid.UUID, rollup string) (int64, error) {
	q := r.db.Model(&models.IGAAgent{}).Where("workspace_id = ?", workspaceID)
	if rollup != "" {
		q = q.Where("rollup_state = ?", rollup)
	}
	var n int64
	return n, q.Count(&n).Error
}

func (r *igaRepository) CountCandidates(workspaceID uuid.UUID, state string) (int64, error) {
	q := r.db.Model(&models.IGACandidate{}).Where("workspace_id = ?", workspaceID)
	if state != "" {
		q = q.Where("state = ?", state)
	}
	var n int64
	return n, q.Count(&n).Error
}

/* ------------------------------ access paths ---------------------------- */

func (r *igaRepository) ListAccessPaths(workspaceID uuid.UUID, subjectID uuid.UUID) ([]AccessPath, error) {
	edges, err := r.ListAccessEdges(workspaceID, subjectID)
	if err != nil {
		return nil, err
	}
	out := make([]AccessPath, 0, len(edges))
	for i := range edges {
		p := AccessPath{Edge: edges[i]}
		if edges[i].EntitlementID != nil {
			var e models.IGAEntitlement
			if err := r.db.First(&e, "id = ? AND workspace_id = ?",
				*edges[i].EntitlementID, workspaceID).Error; err == nil {
				p.Entitlement = &e
			}
		}
		if edges[i].ResourceID != nil {
			var res models.IGAResource
			if err := r.db.First(&res, "id = ? AND workspace_id = ?",
				*edges[i].ResourceID, workspaceID).Error; err == nil {
				p.Resource = &res
			}
		}
		out = append(out, p)
	}
	return out, nil
}

func (r *igaRepository) ListCredentialsFor(workspaceID, identityAccountID uuid.UUID) ([]models.IGACredential, error) {
	var out []models.IGACredential
	err := r.db.Where("workspace_id = ? AND identity_account_id = ?", workspaceID, identityAccountID).
		Order("created_at DESC").Find(&out).Error
	return out, err
}

func (r *igaRepository) ListCorrelationsFor(workspaceID uuid.UUID, canonicalKind string, canonicalID uuid.UUID) ([]models.IGACorrelation, error) {
	var out []models.IGACorrelation
	err := r.db.Where("workspace_id = ? AND canonical_kind = ? AND canonical_id = ?",
		workspaceID, canonicalKind, canonicalID).Order("created_at").Find(&out).Error
	return out, err
}

/* ------------------------------ idempotency ----------------------------- */

func (r *igaRepository) GetIdempotent(workspaceID uuid.UUID, key string) (*IdempotencyRecord, error) {
	var out IdempotencyRecord
	err := r.db.First(&out, "workspace_id = ? AND idempotency_key = ?", workspaceID, key).Error
	if err != nil {
		return nil, notFound(err)
	}
	return &out, nil
}

func (r *igaRepository) PutIdempotent(rec *IdempotencyRecord) error {
	// DoNothing so a concurrent duplicate does not error; the first writer wins
	// and the second reads back the stored response.
	return r.db.Clauses(clause.OnConflict{DoNothing: true}).Create(rec).Error
}
