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

	UpsertExternalPrincipal(tx *gorm.DB, e *models.IGAExternalPrincipal) (uuid.UUID, error)
	SetDerivedResolution(tx *gorm.DB, ws, externalID, identityID uuid.UUID, rule string) error

	UpsertObjectSupport(tx *gorm.DB, s *models.IGAObjectSupport) error
	UpsertProjectionState(tx *gorm.DB, s *models.IGAProjectionState) error

	LinkAccessEdgeEvidence(tx *gorm.DB, ws, edgeID, obsID uuid.UUID, relation string) error
	LinkRelationshipEvidence(tx *gorm.DB, ws, relID, obsID uuid.UUID, relation string) error
	LinkAssignmentEvidence(tx *gorm.DB, ws, assignmentID, obsID uuid.UUID, relation string) error
	LinkRelationshipCollectorEvidence(tx *gorm.DB, ws, relID, obsID uuid.UUID, relation string) error

	PublicationForRun(tx *gorm.DB, ws, runID uuid.UUID) (*models.IGAPublication, error)
	PublicationForIGARun(tx *gorm.DB, ws, runID uuid.UUID) (*models.IGAPublication, error)
	NextRevision(tx *gorm.DB, ws uuid.UUID) (int64, error)
	LatestManifest(tx *gorm.DB, ws uuid.UUID) (json.RawMessage, error)
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

// ErrNoPassTime means a node, edge, support, revision, lifecycle-event or
// publication row reached the write without the projection pass's timestamp. Refused, never defaulted: the column default
// now() is the TRANSACTION's start, which no publication carries, so a row
// written with it could never be joined to the revision and run that started
// it (D-26: one pass, one timestamp -- the publication's published_at).
var ErrNoPassTime = errors.New("graph write without the pass timestamp")

// requirePassTime refuses a zero pass timestamp on a row about to be written.
func requirePassTime(what string, ts ...time.Time) error {
	for _, t := range ts {
		if t.IsZero() {
			return fmt.Errorf("%w: %s", ErrNoPassTime, what)
		}
	}
	return nil
}

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
	if err := requirePassTime("identity "+a.SourceKey, a.FirstSeenAt, a.LastSeenAt); err != nil {
		return uuid.Nil, err
	}
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
	if err := requirePassTime("workload "+w.SourceKey, w.FirstSeenAt, w.LastSeenAt); err != nil {
		return uuid.Nil, err
	}
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
	if err := requirePassTime("resource "+res.SourceKey, res.FirstSeenAt, res.LastSeenAt); err != nil {
		return uuid.Nil, err
	}
	err := tx.Clauses(returningID, onKey(liveNode, []string{
		"display_name", "resource_kind", "estate_scope_id",
		"continuity", "immutable_key", "provider_attrs", "last_seen_at", "updated_at",
	})).Create(res).Error
	return res.ID, err
}

func (r *igaGraphRepository) UpsertPolicy(tx *gorm.DB, p *models.IGAPolicy) (uuid.UUID, error) {
	if err := requirePassTime("policy "+p.SourceKey, p.FirstSeenAt, p.LastSeenAt); err != nil {
		return uuid.Nil, err
	}
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
	if err := requirePassTime("statement "+e.SourceKey, e.FirstSeenAt, e.LastSeenAt); err != nil {
		return uuid.Nil, err
	}
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
	if err := requirePassTime("statement revision", now); err != nil {
		return err
	}
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

// UpsertCredential writes one access key's metadata ON ITS EXISTING ROW,
// found by source key REGARDLESS OF LIFECYCLE (D-64), and inserts only a key
// that has no row at all.
//
// An upsert alone cannot do this. Its conflict target is 028's partial index
// uq_iga_credentials_source_key, which EXCLUDES revoked and expired rows, so a
// key the provider reports Inactive (written lifecycle 'revoked') never
// conflicts: every pass inserted another 'revoked' row beside the original,
// and the original stayed 'active', frozen at its last reading -- one key
// shown twice, once as a claim no current scan makes.
//
// Which row: the live one when there is one (the index allows at most one),
// else the most recently seen -- so a key that turned Inactive keeps its one
// row, and one that turns Active again reopens that same row (no live row can
// exist for it to collide with). first_seen_at is never rewritten.
func (r *igaGraphRepository) UpsertCredential(tx *gorm.DB, c *models.IGACredential) (uuid.UUID, error) {
	if err := requirePassTime("credential "+c.SourceKey, c.FirstSeenAt, c.LastSeenAt); err != nil {
		return uuid.Nil, err
	}
	if c.SourceKey != "" {
		var ids []uuid.UUID
		if err := tx.Raw(`
			UPDATE iga_credentials
			   SET credential_type = ?, issuer = ?, key_identifier = ?, expires_at = ?, last_used_at = ?,
			       rotation_posture = ?, lifecycle = ?, last_seen_at = ?, updated_at = ?
			 WHERE id = (SELECT id FROM iga_credentials
			              WHERE workspace_id = ? AND provider = ? AND source_key = ?
			              ORDER BY (lifecycle NOT IN ('revoked', 'expired')) DESC,
			                       last_seen_at DESC, created_at DESC, id
			              LIMIT 1)
			RETURNING id`,
			c.CredentialType, c.Issuer, c.KeyIdentifier, c.ExpiresAt, c.LastUsedAt,
			c.RotationPosture, c.Lifecycle, c.LastSeenAt, c.LastSeenAt,
			c.WorkspaceID, c.Provider, c.SourceKey).Scan(&ids).Error; err != nil {
			return uuid.Nil, err
		}
		if len(ids) == 1 {
			c.ID = ids[0]
			return c.ID, nil
		}
	}
	// No row for this key yet: insert. The conflict clause stays as a guard
	// against a second live row, which the workspace barrier already excludes.
	err := tx.Clauses(returningID, onKey("source_key <> '' AND lifecycle NOT IN ('revoked', 'expired')", []string{
		"credential_type", "issuer", "key_identifier", "expires_at", "last_used_at",
		"rotation_posture", "lifecycle", "last_seen_at", "updated_at",
	})).Create(c).Error
	return c.ID, err
}

// UpsertAssignment: a detached-then-reattached policy matches NO live row
// (the ended period is excluded by the index predicate), so a reattach is a
// NEW row and the ended period stays exactly as it was.
//
// valid_from is the caller's pass timestamp (D-26) and is written on INSERT
// only: DoUpdates never names it, so a confirmed period keeps its start.
func (r *igaGraphRepository) UpsertAssignment(tx *gorm.DB, a *models.IGAPolicyAssignment) (uuid.UUID, error) {
	if err := requirePassTime("assignment "+a.SourceKey, a.ValidFrom, a.LastConfirmedAt); err != nil {
		return uuid.Nil, err
	}
	if err := rejectBareCollectorRun(a.IntegrationID, a.ConfirmingIGAScanRunID); err != nil {
		return uuid.Nil, err
	}
	q := tx
	if a.IntegrationID == nil {
		q = q.Omit("IntegrationID", "ConfirmingIGAScanRunID")
	} else if a.ConnectorID != nil {
		return uuid.Nil, fmt.Errorf("assignment names both provenance arms")
	}
	err := q.Clauses(returningID, onKey(liveEdge, []string{
		"state", "basis", "last_confirmed_at", "last_confirmed_by", "partition_key", "connector_id",
	})).Create(a).Error
	return a.ID, err
}

func (r *igaGraphRepository) UpsertGrant(tx *gorm.DB, e *models.IGAAccessEdge, statementEffect string) (uuid.UUID, error) {
	if statementEffect != models.EffectAllow {
		return uuid.Nil, fmt.Errorf("%w: effect %q", ErrNotAGrant, statementEffect)
	}
	// valid_from: the pass timestamp, on insert only (as UpsertAssignment).
	if err := requirePassTime("grant "+e.SourceKey, e.ValidFrom, e.LastConfirmedAt); err != nil {
		return uuid.Nil, err
	}
	if err := rejectBareCollectorRun(e.IntegrationID, e.ConfirmingIGAScanRunID); err != nil {
		return uuid.Nil, err
	}
	q := tx
	if e.IntegrationID == nil {
		q = q.Omit("IntegrationID", "ConfirmingIGAScanRunID")
	} else if e.ConnectorID != nil {
		return uuid.Nil, fmt.Errorf("grant names both provenance arms")
	}
	err := q.Clauses(returningID, onKey("source_key <> '' AND "+liveEdge, []string{
		"entitlement_id", "assignment_id", "calculation_state", "effective_conclusion",
		"state", "last_confirmed_at", "last_confirmed_by", "partition_key", "connector_id", "updated_at",
	})).Create(e).Error
	return e.ID, err
}

// UpsertRelationship refreshes a live edge in place. It never writes a SOURCE
// column: every edge key names its source endpoint, so a live row found by key
// already has the source the caller computed, and no edge is ever re-pointed
// from one source to another (P2-DECISIONS D-41). valid_from is the pass
// timestamp, on insert only (as UpsertAssignment).
func (r *igaGraphRepository) UpsertRelationship(tx *gorm.DB, rel *models.IGARelationship) (uuid.UUID, error) {
	if err := requirePassTime("relationship "+rel.SourceKey, rel.ValidFrom, rel.LastConfirmedAt); err != nil {
		return uuid.Nil, err
	}
	// The database still allows neither arm, so GitHub rows with a null
	// connector_id stay valid. A confirming collector run without
	// integration_id is refused here; the collector writer always sets it.
	if err := rejectBareCollectorRun(rel.IntegrationID, rel.ConfirmingIGAScanRunID); err != nil {
		return uuid.Nil, err
	}
	q := tx
	if rel.IntegrationID == nil {
		q = q.Omit("IntegrationID", "ConfirmingIGAScanRunID")
	} else if rel.ConnectorID != nil {
		return uuid.Nil, fmt.Errorf("relationship names both provenance arms")
	}
	err := q.Clauses(returningID, onKey(liveEdge, []string{
		"state", "basis", "last_confirmed_at", "last_confirmed_by", "partition_key", "connector_id",
		"statement_key", "conditions", "mechanism", "updated_at",
	})).Create(rel).Error
	return rel.ID, err
}

// rejectBareCollectorRun is the Go side of the neither-arm grandfather. The
// database allows a row with no connector_id and no integration_id. A
// confirming collector run is not that row: it has to name its integration.
func rejectBareCollectorRun(integration, confirming *uuid.UUID) error {
	if confirming != nil && integration == nil {
		return fmt.Errorf("a confirming collector run requires integration_id")
	}
	return nil
}

// UpsertExternalPrincipal writes the node for a principal a trust policy or
// pod-identity association names (034, §4.7). The conflict target is
// uq_iga_external_principal_key, which is NOT partial: an external principal
// never retires (D-47), so there is no predicate to restate.
//
// DoUpdates names descriptive columns only -- mechanism, a function of the
// key, and last_seen_at. NEVER first_seen_at, and NEVER the resolution
// columns: an asserted resolution is a person's decision (Rules the DDL cannot
// express, 5), and a derived one is written by SetDerivedResolution alone.
func (r *igaGraphRepository) UpsertExternalPrincipal(tx *gorm.DB, e *models.IGAExternalPrincipal) (uuid.UUID, error) {
	if err := requirePassTime("external principal "+e.SourceKey, e.FirstSeenAt, e.LastSeenAt); err != nil {
		return uuid.Nil, err
	}
	err := tx.Clauses(returningID, clause.OnConflict{
		Columns:   []clause.Column{{Name: "workspace_id"}, {Name: "source_key"}},
		DoUpdates: clause.AssignmentColumns([]string{"mechanism", "last_seen_at"}),
	}).Create(e).Error
	return e.ID, err
}

// SetDerivedResolution records an exact-match resolution (§2.3: derived, rule
// recorded). Guarded in SQL, whatever the caller believed: a row a person
// asserted is never touched.
func (r *igaGraphRepository) SetDerivedResolution(tx *gorm.DB, ws, externalID, identityID uuid.UUID, rule string) error {
	return tx.Model(&models.IGAExternalPrincipal{}).
		Where("workspace_id = ? AND id = ? AND resolution_basis IN ?", ws, externalID, []string{"", models.BasisDerived}).
		Updates(map[string]any{
			"resolved_identity_account_id": identityID, "resolved_workload_id": nil,
			"resolution_basis": models.BasisDerived, "resolution_rule": rule,
		}).Error
}

// UpsertObjectSupport records that this connector, in this partition, still
// vouches for this object. Conflict target: the TYPED partial index for the
// row's class. DoUpdates clears ended_reason -- what makes reappearance
// correct -- and never touches first_seen_at, which is the pass timestamp of
// the insert (D-26).
func (r *igaGraphRepository) UpsertObjectSupport(tx *gorm.DB, s *models.IGAObjectSupport) error {
	var confirmed time.Time
	if s.LastConfirmedAt != nil {
		confirmed = *s.LastConfirmedAt
	}
	if err := requirePassTime("object support "+s.PartitionKey, s.FirstSeenAt, confirmed); err != nil {
		return err
	}
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
	if err := s.ValidateArm(); err != nil {
		return err
	}
	if s.IntegrationID != nil {
		// uq_iga_os_<class>_integration. connector_id stays NULL.
		return tx.Omit("ConnectorID").Clauses(clause.OnConflict{
			Columns: []clause.Column{
				{Name: "workspace_id"}, {Name: col}, {Name: "integration_id"}, {Name: "partition_key"},
			},
			TargetWhere: clause.Where{Exprs: []clause.Expression{
				clause.Expr{SQL: col + " IS NOT NULL AND integration_id IS NOT NULL"},
			}},
			DoUpdates: clause.Assignments(map[string]any{
				"state":                      models.RelCurrent,
				"ended_reason":               "",
				"confirming_iga_scan_run_id": s.ConfirmingIGAScanRunID,
				"last_confirmed_at":          s.LastConfirmedAt,
			}),
		}).Create(s).Error
	}
	return tx.Omit("IntegrationID", "ConfirmingIGAScanRunID").Clauses(clause.OnConflict{
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
	if s.IntegrationID != nil {
		if s.ConnectorID != uuid.Nil || s.LastRunID != uuid.Nil || s.LastIGAScanRunID == nil {
			return fmt.Errorf("projection state integration arm is incomplete")
		}
		return tx.Omit("ConnectorID", "LastRunID").Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "workspace_id"}, {Name: "integration_id"}, {Name: "partition_key"}},
			TargetWhere: clause.Where{Exprs: []clause.Expression{
				clause.Expr{SQL: "integration_id IS NOT NULL"},
			}},
			DoUpdates: clause.AssignmentColumns([]string{
				"estate_scope_id", "object_class", "relationship_type", "last_iga_scan_run_id",
				"last_generation", "ordering_sequence", "ordering_epoch",
				"coverage_state", "reconciled", "updated_at",
			}),
		}).Create(s).Error
	}
	return tx.Omit("IntegrationID", "LastIGAScanRunID", "OrderingSequence", "OrderingEpoch").Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "workspace_id"}, {Name: "connector_id"}, {Name: "partition_key"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"estate_scope_id", "object_class", "relationship_type", "last_run_id",
			"last_generation", "coverage_state", "reconciled", "updated_at",
		}),
	}).Create(s).Error
}

func (r *igaGraphRepository) LinkAccessEdgeEvidence(tx *gorm.DB, ws, edgeID, obsID uuid.UUID, relation string) error {
	return tx.Omit("IGAObservationID").Clauses(clause.OnConflict{DoNothing: true}).Create(&models.IGAAccessEdgeEvidence{
		WorkspaceID: ws, AccessEdgeID: edgeID, ObservationID: &obsID, Relation: relation,
	}).Error
}

func (r *igaGraphRepository) LinkRelationshipEvidence(tx *gorm.DB, ws, relID, obsID uuid.UUID, relation string) error {
	return tx.Omit("IGAObservationID").Clauses(clause.OnConflict{DoNothing: true}).Create(&models.IGARelationshipEvidence{
		WorkspaceID: ws, RelationshipID: relID, ObservationID: &obsID, Relation: relation,
	}).Error
}

func (r *igaGraphRepository) LinkAssignmentEvidence(tx *gorm.DB, ws, assignmentID, obsID uuid.UUID, relation string) error {
	return tx.Omit("IGAObservationID").Clauses(clause.OnConflict{DoNothing: true}).Create(&models.IGAAssignmentEvidence{
		WorkspaceID: ws, AssignmentID: assignmentID, ObservationID: &obsID, Relation: relation,
	}).Error
}

// LinkRelationshipCollectorEvidence records an iga_observations row as the
// evidence for a relationship. observation_id stays NULL.
func (r *igaGraphRepository) LinkRelationshipCollectorEvidence(tx *gorm.DB, ws, relID, obsID uuid.UUID, relation string) error {
	return tx.Omit("ObservationID").Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "workspace_id"}, {Name: "relationship_id"}, {Name: "iga_observation_id"}, {Name: "relation"},
		},
		TargetWhere: clause.Where{Exprs: []clause.Expression{clause.Expr{SQL: "iga_observation_id IS NOT NULL"}}},
		DoNothing:   true,
	}).Create(&models.IGARelationshipEvidence{
		WorkspaceID: ws, RelationshipID: relID, IGAObservationID: &obsID, Relation: relation,
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

// LatestManifest is the current revision's manifest, or nil when nothing is
// published: the base the next publication's cumulative manifest is built on
// (D-57). Read under the same barrier as NextRevision.
func (r *igaGraphRepository) LatestManifest(tx *gorm.DB, ws uuid.UUID) (json.RawMessage, error) {
	var rows []struct{ Manifest json.RawMessage }
	if err := tx.Raw(`SELECT manifest FROM iga_publication WHERE workspace_id = ? ORDER BY rev DESC LIMIT 1`, ws).
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return rows[0].Manifest, nil
}

func (r *igaGraphRepository) InsertPublication(tx *gorm.DB, p *models.IGAPublication) error {
	if err := requirePassTime("publication", p.PublishedAt); err != nil {
		return err
	}
	if len(p.Manifest) == 0 {
		p.Manifest = json.RawMessage(`{}`)
	}
	cloud := p.ScanRunID != uuid.Nil
	collector := p.IGAScanRunID != nil
	if cloud == collector {
		return fmt.Errorf("publication must name exactly one run arm")
	}
	if collector {
		return tx.Omit("ScanRunID").Create(p).Error
	}
	return tx.Omit("IGAScanRunID", "SourceManifestV2").Create(p).Error
}

// PublicationForIGARun is PublicationForRun for the collector arm.
func (r *igaGraphRepository) PublicationForIGARun(tx *gorm.DB, ws, runID uuid.UUID) (*models.IGAPublication, error) {
	var out models.IGAPublication
	err := tx.Where("workspace_id = ? AND iga_scan_run_id = ?", ws, runID).First(&out).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// InsertLifecycleEvents appends the pass's events. Their FK to the
// publication is DEFERRED (036): they commit only together with it.
func (r *igaGraphRepository) InsertLifecycleEvents(tx *gorm.DB, events []models.IGALifecycleEvent) error {
	if len(events) == 0 {
		return nil
	}
	for i := range events {
		if err := requirePassTime("lifecycle event", events[i].OccurredAt); err != nil {
			return err
		}
	}
	return tx.CreateInBatches(events, 500).Error
}
