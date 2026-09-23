package repositories

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/authsec-ai/authsec/models"
)

// IGAGraphRepository is the write layer of the cloud_* -> iga_* projection
// (SPEC-iga-phase2-graph.md §4.9). Every method takes the projection
// transaction explicitly: the projector runs ONE transaction per pass.
//
// THE UPSERT TRAP, STATED ONCE. Every node and edge upsert targets a PARTIAL
// unique index. Postgres will not infer a partial index from a bare
// ON CONFLICT (cols): the predicate must be restated, and in GORM that is
// TargetWhere, NOT Where. And GORM returns the id it generated, not the
// surviving row's, so every upsert reads the id back with RETURNING.
type IGAGraphRepository interface {
	UpsertEstateScope(tx *gorm.DB, s *models.IGAEstateScope) (uuid.UUID, error)

	UpsertIdentity(tx *gorm.DB, a *models.IGAIdentityAccount) (uuid.UUID, error)
	RestoreIdentity(tx *gorm.DB, ws, id uuid.UUID, immutableKey string, desc *models.IGAIdentityAccount, now time.Time) (uuid.UUID, error)
	RetireIdentity(tx *gorm.DB, ws, id uuid.UUID, reason string, now time.Time) error
	EndEdgesOnSubject(tx *gorm.DB, ws, identityID uuid.UUID, reason string, now time.Time) error
	SuspendAssertions(tx *gorm.DB, ws, identityID uuid.UUID, reason string) error
	MarkAssertionsPendingReconfirm(tx *gorm.DB, ws, identityID uuid.UUID) error

	UpsertWorkload(tx *gorm.DB, w *models.IGAWorkload) (uuid.UUID, error)
	SetExecutionRoleState(tx *gorm.DB, ws, workloadID uuid.UUID, state, arn string) error

	UpsertResource(tx *gorm.DB, r *models.IGAResource) (uuid.UUID, error)

	UpsertPolicy(tx *gorm.DB, p *models.IGAPolicy) (uuid.UUID, error)
	RestorePolicy(tx *gorm.DB, ws, id uuid.UUID, immutableKey string, desc *models.IGAPolicy, now time.Time) (uuid.UUID, error)
	RetirePolicyIncarnation(tx *gorm.DB, ws, policyID uuid.UUID, now time.Time) ([]uuid.UUID, error)

	UpsertStatement(tx *gorm.DB, e *models.IGAEntitlement) (uuid.UUID, error)
	RestoreStatement(tx *gorm.DB, ws, id uuid.UUID, immutableKey string, now time.Time) (uuid.UUID, error)
	RecordRevision(tx *gorm.DB, ws, entitlementID uuid.UUID, hash string, statement json.RawMessage,
		policyVersionID string, runID uuid.UUID, now time.Time) error
	ReplaceTargets(tx *gorm.DB, ws, entitlementID uuid.UUID, rows []models.IGAEntitlementTarget) error

	UpsertCredential(tx *gorm.DB, c *models.IGACredential) (uuid.UUID, error)

	UpsertAssignment(tx *gorm.DB, a *models.IGAPolicyAssignment) (uuid.UUID, error)
	UpsertGrant(tx *gorm.DB, e *models.IGAAccessEdge, statementEffect string) (uuid.UUID, error)
	UpsertRelationship(tx *gorm.DB, r *models.IGARelationship) (uuid.UUID, error)

	UpsertObjectSupport(tx *gorm.DB, s *models.IGAObjectSupport) error
	UpsertProjectionState(tx *gorm.DB, s *models.IGAProjectionState) error

	LinkAccessEdgeEvidence(tx *gorm.DB, ws, edgeID, obsID uuid.UUID, relation string) error
	LinkRelationshipEvidence(tx *gorm.DB, ws, relID, obsID uuid.UUID, relation string) error
	LinkAssignmentEvidence(tx *gorm.DB, ws, assignmentID, obsID uuid.UUID, relation string) error

	PublicationForRun(tx *gorm.DB, ws, runID uuid.UUID) (*models.IGAPublication, error)
	NextRevision(tx *gorm.DB, ws uuid.UUID) (int64, error)
	InsertPublication(tx *gorm.DB, p *models.IGAPublication) error
	InsertLifecycleEvents(tx *gorm.DB, events []models.IGALifecycleEvent) error
}

type igaGraphRepository struct{}

// NewIGAGraphRepository returns the graph writer. It holds no database handle:
// the transaction is passed per call, because the projector owns it.
func NewIGAGraphRepository() IGAGraphRepository { return &igaGraphRepository{} }

// ErrNotRestorable means a guarded restore matched no row -- a concurrent
// restore, or a row no longer retired-as-unsupported. The pass FAILS rather
// than silently inserting a duplicate object.
var ErrNotRestorable = errors.New("object is not restorable")

// ErrNotAGrant means the projector tried to write a grant for a statement
// whose effect is not allow. The rule is checked again at the write (§4.10
// contract table): a Deny is a restriction, never access.
var ErrNotAGrant = errors.New("only Allow statements are grants")

var returningID = clause.Returning{Columns: []clause.Column{{Name: "id"}}}

// onKey is the conflict target shared by every source-keyed table. predicate
// MUST match that table's partial unique index exactly.
func onKey(predicate string, update []string) clause.OnConflict {
	return clause.OnConflict{
		Columns:     []clause.Column{{Name: "workspace_id"}, {Name: "source_key"}},
		TargetWhere: clause.Where{Exprs: []clause.Expression{clause.Expr{SQL: predicate}}},
		// NAMED COLUMNS ONLY. UpdateAll would reset first_seen_at and clobber
		// human-owned state (classification, asserted resolutions).
		DoUpdates: clause.AssignmentColumns(update),
	}
}

const (
	liveNode = "source_key <> '' AND lifecycle <> 'retired'"
	liveEdge = "state <> 'ended'"
)

func (r *igaGraphRepository) UpsertEstateScope(tx *gorm.DB, s *models.IGAEstateScope) (uuid.UUID, error) {
	err := tx.Clauses(returningID,
		onKey("source_key <> ''", []string{"display_name", "scope_kind", "updated_at"})).Create(s).Error
	return s.ID, err
}

func (r *igaGraphRepository) UpsertIdentity(tx *gorm.DB, a *models.IGAIdentityAccount) (uuid.UUID, error) {
	err := tx.Clauses(returningID, onKey(liveNode, []string{
		"display_name", "account_kind", "identity_backing", "estate_scope_id",
		"continuity", "immutable_key", "provider_attrs", "last_seen_at", "updated_at",
	})).Create(a).Error
	return a.ID, err
}

func (r *igaGraphRepository) RestoreIdentity(
	tx *gorm.DB, ws, id uuid.UUID, immutableKey string, desc *models.IGAIdentityAccount, now time.Time,
) (uuid.UUID, error) {
	res := tx.Model(&models.IGAIdentityAccount{}).
		Where(`workspace_id = ? AND id = ? AND lifecycle = 'retired'
		       AND retired_reason = ? AND immutable_key = ?`,
			ws, id, models.RetiredUnsupported, immutableKey).
		Updates(map[string]any{
			"lifecycle": models.IGALifecycleActive, "retired_reason": "",
			"display_name": desc.DisplayName, "account_kind": desc.AccountKind,
			"identity_backing": desc.IdentityBacking, "provider_attrs": desc.ProviderAttrs,
			"last_seen_at": desc.LastSeenAt, "updated_at": now,
		})
	if res.Error != nil {
		return uuid.Nil, res.Error
	}
	if res.RowsAffected == 0 {
		return uuid.Nil, fmt.Errorf("%w: identity %s", ErrNotRestorable, id)
	}
	return id, nil
}

func (r *igaGraphRepository) RetireIdentity(tx *gorm.DB, ws, id uuid.UUID, reason string, now time.Time) error {
	return tx.Model(&models.IGAIdentityAccount{}).
		Where("workspace_id = ? AND id = ?", ws, id).
		Updates(map[string]any{
			"lifecycle": models.IGALifecycleRetired, "retired_reason": reason, "updated_at": now,
		}).Error
}

// EndEdgesOnSubject ends every live edge incident on a retired identity, in the
// transaction that retired it: the grants it HOLDS, the assignments to it, and
// the relationships it is an endpoint of. Missing any leaves an edge pointing
// at a retired object and reading current.
func (r *igaGraphRepository) EndEdgesOnSubject(tx *gorm.DB, ws, identityID uuid.UUID, reason string, now time.Time) error {
	end := map[string]any{"state": models.RelEnded, "valid_to": now, "ended_reason": reason}
	if err := tx.Model(&models.IGAAccessEdge{}).
		Where("workspace_id = ? AND subject_identity_account_id = ? AND state <> ?", ws, identityID, models.RelEnded).
		Updates(end).Error; err != nil {
		return err
	}
	if err := tx.Model(&models.IGAPolicyAssignment{}).
		Where("workspace_id = ? AND holder_identity_account_id = ? AND state <> ?", ws, identityID, models.RelEnded).
		Updates(end).Error; err != nil {
		return err
	}
	return tx.Model(&models.IGARelationship{}).
		Where(`workspace_id = ? AND state <> ? AND
		       (source_identity_account_id = ? OR target_identity_account_id = ?)`,
			ws, models.RelEnded, identityID, identityID).
		Updates(end).Error
}

// SuspendAssertions: ASSERTED resolutions only. A derived one is re-derived
// every pass; suspending it would freeze a stale answer.
func (r *igaGraphRepository) SuspendAssertions(tx *gorm.DB, ws, identityID uuid.UUID, reason string) error {
	return tx.Model(&models.IGAExternalPrincipal{}).
		Where(`workspace_id = ? AND resolved_identity_account_id = ?
		       AND resolution_basis = ? AND resolution_state = ?`,
			ws, identityID, models.BasisAsserted, models.ResolutionActive).
		Update("resolution_state", models.ResolutionSuspended).Error
}

// MarkAssertionsPendingReconfirm is what a RESTORED object gets -- never
// straight back to active.
func (r *igaGraphRepository) MarkAssertionsPendingReconfirm(tx *gorm.DB, ws, identityID uuid.UUID) error {
	return tx.Model(&models.IGAExternalPrincipal{}).
		Where(`workspace_id = ? AND resolved_identity_account_id = ?
		       AND resolution_basis = ? AND resolution_state = ?`,
			ws, identityID, models.BasisAsserted, models.ResolutionSuspended).
		Update("resolution_state", models.ResolutionPendingReconfirmation).Error
}

// UpsertWorkload NEVER updates classification: provider_native_agent is
// written on insert only, and a person's decision survives every scan.
func (r *igaGraphRepository) UpsertWorkload(tx *gorm.DB, w *models.IGAWorkload) (uuid.UUID, error) {
	err := tx.Clauses(returningID, onKey("lifecycle <> 'retired'", []string{
		"display_name", "runtime_kind", "region", "estate_scope_id",
		"continuity", "immutable_key", "provider_attrs", "last_seen_at", "updated_at",
	})).Create(w).Error
	return w.ID, err
}

func (r *igaGraphRepository) SetExecutionRoleState(tx *gorm.DB, ws, workloadID uuid.UUID, state, arn string) error {
	return tx.Model(&models.IGAWorkload{}).
		Where("workspace_id = ? AND id = ?", ws, workloadID).
		Updates(map[string]any{"execution_role_state": state, "execution_role_arn": arn}).Error
}

func (r *igaGraphRepository) UpsertResource(tx *gorm.DB, res *models.IGAResource) (uuid.UUID, error) {
	err := tx.Clauses(returningID, onKey(liveNode, []string{
		"display_name", "resource_kind", "estate_scope_id",
		"continuity", "immutable_key", "provider_attrs", "last_seen_at", "updated_at",
	})).Create(res).Error
	return res.ID, err
}

func (r *igaGraphRepository) UpsertPolicy(tx *gorm.DB, p *models.IGAPolicy) (uuid.UUID, error) {
	err := tx.Clauses(returningID, onKey("lifecycle <> 'retired'", []string{
		"policy_kind", "display_name", "native_ref", "continuity", "immutable_key",
		"version_id", "document_hash", "last_seen_at",
	})).Create(p).Error
	return p.ID, err
}

func (r *igaGraphRepository) RestorePolicy(
	tx *gorm.DB, ws, id uuid.UUID, immutableKey string, desc *models.IGAPolicy, now time.Time,
) (uuid.UUID, error) {
	res := tx.Model(&models.IGAPolicy{}).
		Where(`workspace_id = ? AND id = ? AND lifecycle = 'retired'
		       AND retired_reason = ? AND immutable_key = ?`,
			ws, id, models.RetiredUnsupported, immutableKey).
		Updates(map[string]any{
			"lifecycle": models.IGALifecycleActive, "retired_reason": "",
			"display_name": desc.DisplayName, "version_id": desc.VersionID,
			"document_hash": desc.DocumentHash, "last_seen_at": now,
		})
	if res.Error != nil {
		return uuid.Nil, res.Error
	}
	if res.RowsAffected == 0 {
		return uuid.Nil, fmt.Errorf("%w: policy %s", ErrNotRestorable, id)
	}
	return id, nil
}

// RetirePolicyIncarnation retires a policy that was RECREATED and cascades, in
// the caller's transaction (§4.7):
//
//	statements   retired, support ended      policy_recreated
//	assignments  ended                       policy_recreated
//	grants       ended                       policy_recreated
//	revisions    closed (valid_to)
//
// Returns the statements it retired, for the lifecycle log.
func (r *igaGraphRepository) RetirePolicyIncarnation(tx *gorm.DB, ws, policyID uuid.UUID, now time.Time) ([]uuid.UUID, error) {
	if err := tx.Model(&models.IGAPolicy{}).Where("workspace_id = ? AND id = ?", ws, policyID).
		Updates(map[string]any{"lifecycle": models.IGALifecycleRetired, "retired_reason": models.RetiredRecreated}).
		Error; err != nil {
		return nil, err
	}
	var stmts []uuid.UUID
	if err := tx.Raw(`UPDATE iga_entitlements SET lifecycle = 'retired', retired_reason = ?, updated_at = ?
	                   WHERE workspace_id = ? AND policy_id = ? AND lifecycle <> 'retired'
	                   RETURNING id`, models.RetiredPolicyRecreated, now, ws, policyID).
		Scan(&stmts).Error; err != nil {
		return nil, err
	}
	end := map[string]any{"state": models.RelEnded, "valid_to": now, "ended_reason": models.EndedPolicyRecreated}
	if err := tx.Model(&models.IGAAccessEdge{}).
		Where(`workspace_id = ? AND state <> ? AND assignment_id IN
		       (SELECT id FROM iga_policy_assignment WHERE workspace_id = ? AND policy_id = ?)`,
			ws, models.RelEnded, ws, policyID).Updates(end).Error; err != nil {
		return nil, err
	}
	if err := tx.Model(&models.IGAPolicyAssignment{}).
		Where("workspace_id = ? AND policy_id = ? AND state <> ?", ws, policyID, models.RelEnded).
		Updates(end).Error; err != nil {
		return nil, err
	}
	endSupport := map[string]any{"state": models.RelEnded, "ended_reason": models.EndedPolicyRecreated}
	if err := tx.Model(&models.IGAObjectSupport{}).
		Where("workspace_id = ? AND policy_id = ? AND state <> ?", ws, policyID, models.RelEnded).
		Updates(endSupport).Error; err != nil {
		return nil, err
	}
	if len(stmts) > 0 {
		if err := tx.Model(&models.IGAObjectSupport{}).
			Where("workspace_id = ? AND entitlement_id IN ? AND state <> ?", ws, stmts, models.RelEnded).
			Updates(endSupport).Error; err != nil {
			return nil, err
		}
		if err := tx.Model(&models.IGAStatementRevision{}).
			Where("workspace_id = ? AND entitlement_id IN ? AND valid_to IS NULL", ws, stmts).
			Update("valid_to", now).Error; err != nil {
			return nil, err
		}
	}
	return stmts, nil
}

func (r *igaGraphRepository) UpsertStatement(tx *gorm.DB, e *models.IGAEntitlement) (uuid.UUID, error) {
	err := tx.Clauses(returningID, onKey(liveNode, []string{
		"policy_id", "statement_key", "sid", "statement_index", "effect", "content_hash",
		"negated", "conditional", "native_grant_kind", "native_rights", "normalized_rights",
		"continuity", "immutable_key", "last_seen_at", "updated_at",
	})).Create(e).Error
	return e.ID, err
}

func (r *igaGraphRepository) RestoreStatement(tx *gorm.DB, ws, id uuid.UUID, immutableKey string, now time.Time) (uuid.UUID, error) {
	res := tx.Model(&models.IGAEntitlement{}).
		Where(`workspace_id = ? AND id = ? AND lifecycle = 'retired'
		       AND retired_reason = ? AND immutable_key = ?`,
			ws, id, models.RetiredUnsupported, immutableKey).
		Updates(map[string]any{"lifecycle": models.IGALifecycleActive, "retired_reason": "", "updated_at": now})
	if res.Error != nil {
		return uuid.Nil, res.Error
	}
	if res.RowsAffected == 0 {
		return uuid.Nil, fmt.Errorf("%w: statement %s", ErrNotRestorable, id)
	}
	return id, nil
}

// RecordRevision: if the live revision's hash equals the new hash, touch
// NOTHING; otherwise close it and open a new one. A closed revision is never
// rewritten.
func (r *igaGraphRepository) RecordRevision(
	tx *gorm.DB, ws, entitlementID uuid.UUID, hash string, statement json.RawMessage,
	policyVersionID string, runID uuid.UUID, now time.Time,
) error {
	var live []models.IGAStatementRevision
	if err := tx.Where("workspace_id = ? AND entitlement_id = ? AND valid_to IS NULL", ws, entitlementID).
		Find(&live).Error; err != nil {
		return err
	}
	if len(live) == 1 && live[0].ContentHash == hash {
		return nil
	}
	if len(live) > 0 {
		if err := tx.Model(&models.IGAStatementRevision{}).
			Where("workspace_id = ? AND entitlement_id = ? AND valid_to IS NULL", ws, entitlementID).
			Update("valid_to", now).Error; err != nil {
			return err
		}
	}
	if len(statement) == 0 {
		statement = json.RawMessage(`{}`)
	}
	return tx.Create(&models.IGAStatementRevision{
		WorkspaceID: ws, EntitlementID: entitlementID, ContentHash: hash,
		Statement: statement, PolicyVersionID: policyVersionID,
		ValidFrom: now, FirstSeenRunID: runID,
	}).Error
}

// ReplaceTargets replaces a statement's targets ONLY when the wanted set
// differs from the stored one, so an unchanged statement's target rows keep
// their ids.
func (r *igaGraphRepository) ReplaceTargets(tx *gorm.DB, ws, entitlementID uuid.UUID, rows []models.IGAEntitlementTarget) error {
	var have []models.IGAEntitlementTarget
	if err := tx.Where("workspace_id = ? AND entitlement_id = ?", ws, entitlementID).Find(&have).Error; err != nil {
		return err
	}
	type key struct {
		res  uuid.UUID
		mode string
		ord  int
	}
	want := map[key]bool{}
	for _, t := range rows {
		want[key{t.ResourceID, t.TargetMode, t.Ordinal}] = true
	}
	same := len(have) == len(want)
	for _, t := range have {
		if !want[key{t.ResourceID, t.TargetMode, t.Ordinal}] {
			same = false
		}
	}
	if same {
		return nil
	}
	if err := tx.Where("workspace_id = ? AND entitlement_id = ?", ws, entitlementID).
		Delete(&models.IGAEntitlementTarget{}).Error; err != nil {
		return err
	}
	seen := map[key]bool{}
	for _, t := range rows {
		k := key{t.ResourceID, t.TargetMode, t.Ordinal}
		if seen[k] {
			continue
		}
		seen[k] = true
		t := t
		t.WorkspaceID = ws
		t.EntitlementID = entitlementID
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&t).Error; err != nil {
			return err
		}
	}
	return nil
}

func (r *igaGraphRepository) UpsertCredential(tx *gorm.DB, c *models.IGACredential) (uuid.UUID, error) {
	err := tx.Clauses(returningID, onKey("source_key <> '' AND lifecycle NOT IN ('revoked', 'expired')", []string{
		"credential_type", "issuer", "key_identifier", "expires_at", "last_used_at",
		"rotation_posture", "lifecycle", "last_seen_at", "updated_at",
	})).Create(c).Error
	return c.ID, err
}

// UpsertAssignment: a detached-then-reattached policy matches NO live row
// (the ended period is excluded by the index predicate), so a reattach is a
// NEW row and the ended period stays exactly as it was.
func (r *igaGraphRepository) UpsertAssignment(tx *gorm.DB, a *models.IGAPolicyAssignment) (uuid.UUID, error) {
	err := tx.Clauses(returningID, onKey(liveEdge, []string{
		"state", "basis", "last_confirmed_at", "last_confirmed_by", "partition_key", "connector_id",
	})).Create(a).Error
	return a.ID, err
}

func (r *igaGraphRepository) UpsertGrant(tx *gorm.DB, e *models.IGAAccessEdge, statementEffect string) (uuid.UUID, error) {
	if statementEffect != models.EffectAllow {
		return uuid.Nil, fmt.Errorf("%w: effect %q", ErrNotAGrant, statementEffect)
	}
	err := tx.Clauses(returningID, onKey("source_key <> '' AND "+liveEdge, []string{
		"entitlement_id", "assignment_id", "calculation_state", "effective_conclusion",
		"state", "last_confirmed_at", "last_confirmed_by", "partition_key", "connector_id", "updated_at",
	})).Create(e).Error
	return e.ID, err
}

func (r *igaGraphRepository) UpsertRelationship(tx *gorm.DB, rel *models.IGARelationship) (uuid.UUID, error) {
	err := tx.Clauses(returningID, onKey(liveEdge, []string{
		"state", "basis", "last_confirmed_at", "last_confirmed_by", "partition_key", "connector_id",
		"statement_key", "conditions", "mechanism", "updated_at",
	})).Create(rel).Error
	return rel.ID, err
}

// UpsertObjectSupport records that this connector, in this partition, still
// vouches for this object. Conflict target: the TYPED partial index for the
// row's class. DoUpdates clears ended_reason -- what makes reappearance
// correct -- and never touches first_seen_at.
func (r *igaGraphRepository) UpsertObjectSupport(tx *gorm.DB, s *models.IGAObjectSupport) error {
	var col string
	switch {
	case s.IdentityAccountID != nil:
		col = "identity_account_id"
	case s.WorkloadID != nil:
		col = "workload_id"
	case s.ResourceID != nil:
		col = "resource_id"
	case s.EntitlementID != nil:
		col = "entitlement_id"
	case s.PolicyID != nil:
		col = "policy_id"
	default:
		return fmt.Errorf("object support row names no object")
	}
	return tx.Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "workspace_id"}, {Name: col}, {Name: "connector_id"}, {Name: "partition_key"},
		},
		TargetWhere: clause.Where{Exprs: []clause.Expression{clause.Expr{SQL: col + " IS NOT NULL"}}},
		DoUpdates: clause.Assignments(map[string]any{
			"state":                 models.RelCurrent,
			"ended_reason":          "",
			"last_confirmed_run_id": s.LastConfirmedRunID,
			"last_confirmed_at":     s.LastConfirmedAt,
		}),
	}).Create(s).Error
}

func (r *igaGraphRepository) UpsertProjectionState(tx *gorm.DB, s *models.IGAProjectionState) error {
	return tx.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "workspace_id"}, {Name: "connector_id"}, {Name: "partition_key"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"estate_scope_id", "object_class", "relationship_type", "last_run_id",
			"last_generation", "coverage_state", "reconciled", "updated_at",
		}),
	}).Create(s).Error
}

func (r *igaGraphRepository) LinkAccessEdgeEvidence(tx *gorm.DB, ws, edgeID, obsID uuid.UUID, relation string) error {
	return tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&models.IGAAccessEdgeEvidence{
		WorkspaceID: ws, AccessEdgeID: edgeID, ObservationID: obsID, Relation: relation,
	}).Error
}

func (r *igaGraphRepository) LinkRelationshipEvidence(tx *gorm.DB, ws, relID, obsID uuid.UUID, relation string) error {
	return tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&models.IGARelationshipEvidence{
		WorkspaceID: ws, RelationshipID: relID, ObservationID: obsID, Relation: relation,
	}).Error
}

func (r *igaGraphRepository) LinkAssignmentEvidence(tx *gorm.DB, ws, assignmentID, obsID uuid.UUID, relation string) error {
	return tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&models.IGAAssignmentEvidence{
		WorkspaceID: ws, AssignmentID: assignmentID, ObservationID: obsID, Relation: relation,
	}).Error
}

// PublicationForRun answers "did THIS run's projection already commit?".
// Trustworthy only because InsertPublication commits in the same transaction
// as the graph writes.
func (r *igaGraphRepository) PublicationForRun(tx *gorm.DB, ws, runID uuid.UUID) (*models.IGAPublication, error) {
	var out models.IGAPublication
	err := tx.Where("workspace_id = ? AND scan_run_id = ?", ws, runID).First(&out).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// NextRevision is max(rev)+1 for the workspace -- safe because the caller holds
// the barrier row FOR UPDATE (AssertHeldTx), which serializes projection per
// workspace. UNIQUE (workspace_id, scan_run_id) backstops a double publish.
func (r *igaGraphRepository) NextRevision(tx *gorm.DB, ws uuid.UUID) (int64, error) {
	var next int64
	err := tx.Raw(`SELECT COALESCE(max(rev), 0) + 1 FROM iga_publication WHERE workspace_id = ?`, ws).
		Scan(&next).Error
	return next, err
}

func (r *igaGraphRepository) InsertPublication(tx *gorm.DB, p *models.IGAPublication) error {
	if len(p.Manifest) == 0 {
		p.Manifest = json.RawMessage(`{}`)
	}
	return tx.Create(p).Error
}

// InsertLifecycleEvents appends the pass's events. Their FK to the
// publication is DEFERRED (036): they commit only together with it.
func (r *igaGraphRepository) InsertLifecycleEvents(tx *gorm.DB, events []models.IGALifecycleEvent) error {
	if len(events) == 0 {
		return nil
	}
	return tx.CreateInBatches(events, 500).Error
}
