package repositories

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/authsec-ai/authsec/models"
)

// IGAGraphRepository is the write layer of the cloud_* -> iga_* projection.
//
// Every method takes the projection transaction explicitly. The projector runs
// ONE transaction per pass and must not be able to open its own -- separate
// transactions would publish a graph in which nothing has been closed yet.
//
// THE UPSERT TRAP, STATED ONCE. Every node upsert targets a PARTIAL unique
// index (... WHERE source_key <> '' AND lifecycle <> 'retired'). Postgres will
// not infer a partial index from a bare ON CONFLICT (cols): the predicate must
// be restated, and in GORM that is TargetWhere, NOT Where. `Where` emits the
// DO UPDATE ... WHERE condition, a different clause that silently does not
// help inference. SQLite accepts all of it and enforces none, so these paths
// need Postgres to be tested at all.
type IGAGraphRepository interface {
	UpsertEstateScope(tx *gorm.DB, s *models.IGAEstateScope) (uuid.UUID, error)

	UpsertIdentity(tx *gorm.DB, a *models.IGAIdentityAccount) (uuid.UUID, error)
	UpsertWorkload(tx *gorm.DB, w *models.IGAWorkload) (uuid.UUID, error)
	UpsertResource(tx *gorm.DB, r *models.IGAResource) (uuid.UUID, error)
	UpsertEntitlement(tx *gorm.DB, e *models.IGAEntitlement) (uuid.UUID, error)
	UpsertAgent(tx *gorm.DB, a *models.IGAAgent) (uuid.UUID, error)
	UpsertAgentInstance(tx *gorm.DB, i *models.IGAAgentInstance) (uuid.UUID, error)
	UpsertCredential(tx *gorm.DB, c *models.IGACredential) (uuid.UUID, error)

	UpsertAccessEdge(tx *gorm.DB, e *models.IGAAccessEdge) (uuid.UUID, error)
	UpsertRelationship(tx *gorm.DB, r *models.IGARelationship) (uuid.UUID, error)

	UpsertObjectSupport(tx *gorm.DB, s *models.IGAObjectSupport) error
	UpsertProjectionState(tx *gorm.DB, s *models.IGAProjectionState) error

	LinkAccessEdgeEvidence(tx *gorm.DB, ws, edgeID, obsID uuid.UUID, relation string) error
	LinkRelationshipEvidence(tx *gorm.DB, ws, relID, obsID uuid.UUID, relation string) error

	RetireIdentity(tx *gorm.DB, ws, id uuid.UUID, reason string, now time.Time) error
	EndEdgesOnSubject(tx *gorm.DB, ws, identityID uuid.UUID, reason string, now time.Time, runID uuid.UUID) error
}

type igaGraphRepository struct{}

// NewIGAGraphRepository returns the graph writer. It holds no database handle:
// the transaction is passed per call, because the projector owns it.
func NewIGAGraphRepository() IGAGraphRepository { return &igaGraphRepository{} }

// nodeConflict is the conflict target every node table shares. The predicate
// MUST match that table's partial unique index exactly.
func nodeConflict(update []string) clause.OnConflict {
	return clause.OnConflict{
		Columns: []clause.Column{{Name: "workspace_id"}, {Name: "source_key"}},
		TargetWhere: clause.Where{Exprs: []clause.Expression{
			clause.Expr{SQL: "source_key <> '' AND lifecycle <> 'retired'"},
		}},
		// NAMED COLUMNS ONLY. UpdateAll would reset first_seen_at and clobber
		// human-owned state -- ownership, review status, classification, and
		// origin once it reads 'registered' -- which is exactly what the exit
		// gate tests for.
		DoUpdates: clause.AssignmentColumns(update),
	}
}

// graphReturningID reads the SURVIVING row's id back after a conflict. Without
// it the struct keeps the id GORM generated, which on a conflict names no row,
// and every edge written afterwards points at nothing.
var graphReturningID = clause.Returning{Columns: []clause.Column{{Name: "id"}}}

func (r *igaGraphRepository) UpsertEstateScope(tx *gorm.DB, s *models.IGAEstateScope) (uuid.UUID, error) {
	err := tx.Clauses(graphReturningID, clause.OnConflict{
		Columns: []clause.Column{{Name: "workspace_id"}, {Name: "source_key"}},
		TargetWhere: clause.Where{Exprs: []clause.Expression{
			clause.Expr{SQL: "source_key <> ''"},
		}},
		DoUpdates: clause.AssignmentColumns([]string{"display_name", "scope_kind", "updated_at"}),
	}).Create(s).Error
	return s.ID, err
}

func (r *igaGraphRepository) UpsertIdentity(tx *gorm.DB, a *models.IGAIdentityAccount) (uuid.UUID, error) {
	err := tx.Clauses(graphReturningID, nodeConflict([]string{
		"display_name", "account_kind", "identity_backing",
		"estate_scope_id", "continuity", "immutable_key",
		"last_seen_at", "updated_at",
	})).Create(a).Error
	return a.ID, err
}

func (r *igaGraphRepository) UpsertWorkload(tx *gorm.DB, w *models.IGAWorkload) (uuid.UUID, error) {
	err := tx.Clauses(graphReturningID, clause.OnConflict{
		Columns: []clause.Column{{Name: "workspace_id"}, {Name: "source_key"}},
		// iga_workload's index has no source_key <> '' arm: the column is
		// NOT NULL with a non-empty CHECK from the start (028), because
		// nothing predates this table.
		TargetWhere: clause.Where{Exprs: []clause.Expression{
			clause.Expr{SQL: "lifecycle <> 'retired'"},
		}},
		DoUpdates: clause.AssignmentColumns([]string{
			"display_name", "runtime_kind", "estate_scope_id",
			"continuity", "immutable_key", "last_seen_at", "updated_at",
		}),
	}).Create(w).Error
	return w.ID, err
}

func (r *igaGraphRepository) UpsertResource(tx *gorm.DB, res *models.IGAResource) (uuid.UUID, error) {
	err := tx.Clauses(graphReturningID, nodeConflict([]string{
		"display_name", "resource_kind", "estate_scope_id",
		"continuity", "immutable_key", "last_seen_at", "updated_at",
	})).Create(res).Error
	return res.ID, err
}

func (r *igaGraphRepository) UpsertEntitlement(tx *gorm.DB, e *models.IGAEntitlement) (uuid.UUID, error) {
	err := tx.Clauses(graphReturningID, nodeConflict([]string{
		"native_grant_kind", "native_rights", "normalized_rights",
		"native_scope", "remediable", "resource_id", "last_seen_at", "updated_at",
	})).Create(e).Error
	return e.ID, err
}

// UpsertAgent deliberately does NOT update `origin` or `classification`.
//
// A discovered agent a human later registers keeps its id and flips origin,
// with the decision recorded; letting the projector write origin back to
// 'discovered' on the next scan would silently undo that decision, and the
// exit gate's "registered is distinguished from native discovery" would fail
// intermittently -- on whichever scan ran last.
func (r *igaGraphRepository) UpsertAgent(tx *gorm.DB, a *models.IGAAgent) (uuid.UUID, error) {
	err := tx.Clauses(graphReturningID, nodeConflict([]string{
		"display_name", "estate_scope_id", "continuity", "immutable_key",
		"last_seen_at", "updated_at",
	})).Create(a).Error
	return a.ID, err
}

func (r *igaGraphRepository) UpsertAgentInstance(tx *gorm.DB, i *models.IGAAgentInstance) (uuid.UUID, error) {
	err := tx.Clauses(graphReturningID, clause.OnConflict{
		Columns: []clause.Column{{Name: "workspace_id"}, {Name: "source_key"}},
		TargetWhere: clause.Where{Exprs: []clause.Expression{
			clause.Expr{SQL: "source_key <> '' AND lifecycle <> 'retired'"},
		}},
		// origin is omitted for the same reason as UpsertAgent.
		DoUpdates: clause.AssignmentColumns([]string{
			"agent_id", "workload_id", "runtime_kind", "native_workload_id",
			"estate_scope_id", "last_seen_at",
		}),
	}).Create(i).Error
	return i.ID, err
}

func (r *igaGraphRepository) UpsertCredential(tx *gorm.DB, c *models.IGACredential) (uuid.UUID, error) {
	err := tx.Clauses(graphReturningID, clause.OnConflict{
		Columns: []clause.Column{{Name: "workspace_id"}, {Name: "source_key"}},
		TargetWhere: clause.Where{Exprs: []clause.Expression{
			clause.Expr{SQL: "source_key <> '' AND lifecycle NOT IN ('revoked', 'expired')"},
		}},
		DoUpdates: clause.AssignmentColumns([]string{
			"credential_type", "issuer", "key_identifier", "expires_at",
			"last_used_at", "rotation_posture", "last_seen_at", "updated_at",
		}),
	}).Create(c).Error
	return c.ID, err
}

func (r *igaGraphRepository) UpsertAccessEdge(tx *gorm.DB, e *models.IGAAccessEdge) (uuid.UUID, error) {
	err := tx.Clauses(graphReturningID, clause.OnConflict{
		Columns: []clause.Column{{Name: "workspace_id"}, {Name: "source_key"}},
		TargetWhere: clause.Where{Exprs: []clause.Expression{
			clause.Expr{SQL: "source_key <> '' AND state <> 'ended'"},
		}},
		// state returns to 'current' on confirmation: a relationship that went
		// stale during an outage and is seen again is current again, and
		// leaving it stale would make every outage permanent.
		DoUpdates: clause.AssignmentColumns([]string{
			"entitlement_id", "resource_id", "direction", "path_kind",
			"calculation_state", "effective_conclusion", "native_scope",
			"state", "last_confirmed_at", "last_confirmed_by",
			"partition_key", "connector_id", "observed_at", "updated_at",
		}),
	}).Create(e).Error
	return e.ID, err
}

func (r *igaGraphRepository) UpsertRelationship(tx *gorm.DB, rel *models.IGARelationship) (uuid.UUID, error) {
	err := tx.Clauses(graphReturningID, clause.OnConflict{
		Columns: []clause.Column{{Name: "workspace_id"}, {Name: "source_key"}},
		TargetWhere: clause.Where{Exprs: []clause.Expression{
			clause.Expr{SQL: "state <> 'ended'"},
		}},
		DoUpdates: clause.AssignmentColumns([]string{
			"state", "basis", "last_confirmed_at", "last_confirmed_by",
			"partition_key", "connector_id", "updated_at",
		}),
	}).Create(rel).Error
	return rel.ID, err
}

// UpsertObjectSupport records that this connector, in this partition, still
// vouches for this object.
//
// THIS IS THE STEP THAT MAKES A NODE VISIBLE TO RECONCILIATION. A node pass
// that upserts the node and returns its id but skips this compiles, passes an
// unchanged-rescan test, and silently never reconciles.
func (r *igaGraphRepository) UpsertObjectSupport(tx *gorm.DB, s *models.IGAObjectSupport) error {
	return tx.Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "workspace_id"}, {Name: "object_type"}, {Name: "object_id"},
			{Name: "connector_id"}, {Name: "partition_key"},
		},
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
		Columns: []clause.Column{
			{Name: "workspace_id"}, {Name: "connector_id"}, {Name: "partition_key"},
		},
		DoUpdates: clause.AssignmentColumns([]string{
			"estate_scope_id", "object_class", "relationship_type",
			"last_run_id", "last_generation", "coverage_state",
			"reconciled", "updated_at",
		}),
	}).Create(s).Error
}

func (r *igaGraphRepository) LinkAccessEdgeEvidence(tx *gorm.DB, ws, edgeID, obsID uuid.UUID, relation string) error {
	return tx.Clauses(clause.OnConflict{DoNothing: true}).
		Create(&models.IGAAccessEdgeEvidence{
			WorkspaceID: ws, AccessEdgeID: edgeID, ObservationID: obsID, Relation: relation,
		}).Error
}

func (r *igaGraphRepository) LinkRelationshipEvidence(tx *gorm.DB, ws, relID, obsID uuid.UUID, relation string) error {
	return tx.Clauses(clause.OnConflict{DoNothing: true}).
		Create(&models.IGARelationshipEvidence{
			WorkspaceID: ws, RelationshipID: relID, ObservationID: obsID, Relation: relation,
		}).Error
}

// RetireIdentity marks the old object retired, KEEPING its source_key.
//
// The key must stay: the partial unique index is what lets the new row take
// the same key while only one of them is live, and that is the whole mechanism
// of delete-and-recreate. Nothing is ever deleted.
func (r *igaGraphRepository) RetireIdentity(tx *gorm.DB, ws, id uuid.UUID, reason string, now time.Time) error {
	return tx.Model(&models.IGAIdentityAccount{}).
		Where("workspace_id = ? AND id = ?", ws, id).
		Updates(map[string]any{
			"lifecycle":      models.IGALifecycleRetired,
			"retired_reason": reason,
			"updated_at":     now,
		}).Error
}

// EndEdgesOnSubject ends every live edge incident on a retired identity, in
// the same transaction that retired it.
//
// Both tables, deliberately: the access edges the identity HOLDS and the
// relationships it is an endpoint of. Missing either leaves an edge pointing
// at a retired object and reading `current`.
func (r *igaGraphRepository) EndEdgesOnSubject(tx *gorm.DB, ws, identityID uuid.UUID, reason string, now time.Time, runID uuid.UUID) error {
	end := map[string]any{
		"state":        models.RelEnded,
		"valid_to":     now,
		"ended_reason": reason,
		"updated_at":   now,
	}
	if err := tx.Model(&models.IGAAccessEdge{}).
		Where("workspace_id = ? AND subject_identity_account_id = ? AND state <> ?",
			ws, identityID, models.RelEnded).
		Updates(end).Error; err != nil {
		return err
	}
	return tx.Model(&models.IGARelationship{}).
		Where(`workspace_id = ? AND state <> ? AND
		       (source_identity_account_id = ? OR target_identity_account_id = ?)`,
			ws, models.RelEnded, identityID, identityID).
		Updates(end).Error
}
