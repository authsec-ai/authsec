package igagraph

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

// ErrSuperseded means a newer scan has already advanced the connector past
// this job's generation. The newer run's job will do the work, with better
// data, so this job ABANDONS -- recorded, never silent.
var ErrSuperseded = errors.New("igagraph: snapshot superseded by a newer generation")

// Load reads one published run's collected state.
//
// Rows are read AT THIS RUN'S GENERATION, not "all rows for the connector": a
// later scan may already have written generation+1 rows, and projecting those
// under this job's generation would attribute another run's findings to this
// one -- and then reconcile against the wrong baseline.
//
// REPEATABLE READ makes the reads one consistent view, which is NECESSARY AND
// NOT SUFFICIENT. See "why isolation alone cannot fix this" below.
func Load(ctx context.Context, db *gorm.DB, jobRunID uuid.UUID) (*Snapshot, error) {
	var run models.CloudScanRun
	if err := db.WithContext(ctx).First(&run, "id = ?", jobRunID).Error; err != nil {
		return nil, fmt.Errorf("load scan run: %w", err)
	}
	var conn models.CloudConnector
	if err := db.WithContext(ctx).First(&conn, "id = ?", run.ConnectorID).Error; err != nil {
		return nil, fmt.Errorf("load connector: %w", err)
	}

	snap := &Snapshot{Run: run, Connector: conn, Generation: run.Generation}

	tx := db.WithContext(ctx).Begin(&sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer func() { _ = tx.Rollback() }()

	gen := run.Generation
	cid := run.ConnectorID
	q := func(dst any) error {
		return tx.Where("connector_id = ? AND last_seen_generation = ?", cid, gen).
			Find(dst).Error
	}
	if err := q(&snap.Identities); err != nil {
		return nil, fmt.Errorf("load identities: %w", err)
	}
	if err := q(&snap.Workloads); err != nil {
		return nil, fmt.Errorf("load workloads: %w", err)
	}
	if err := q(&snap.Resources); err != nil {
		return nil, fmt.Errorf("load resources: %w", err)
	}
	if err := q(&snap.Permissions); err != nil {
		return nil, fmt.Errorf("load permissions: %w", err)
	}
	if err := q(&snap.AssumeEdges); err != nil {
		return nil, fmt.Errorf("load assume edges: %w", err)
	}
	if err := q(&snap.Secrets); err != nil {
		return nil, fmt.Errorf("load secrets: %w", err)
	}

	// Coverage is the run's OWN report (024), decoded from the jsonb column
	// stamped at publish. NEVER cloud_connector.coverage, which a later scan
	// has overwritten -- that was D1.
	snap.Coverage = models.DecodeScanCoverage(run.Coverage).Surfaces
	if snap.Coverage == nil {
		snap.Coverage = map[string]models.SurfaceCoverage{}
	}

	// Which observations THIS run confirmed. Content dedupe means a re-read of
	// unchanged data writes no row, so the question cannot be answered by
	// scan_run_id; 024 added last_confirmed_run_id for exactly this (D4).
	var obs []models.CloudObservation
	if err := tx.
		Select("id", "subject_native_id", "identity_id", "permission_id",
			"resource_id", "workload_id").
		Where("workspace_id = ? AND last_confirmed_run_id = ?", run.WorkspaceID, run.ID).
		Find(&obs).Error; err != nil {
		return nil, fmt.Errorf("load confirmed observations: %w", err)
	}
	snap.ConfirmedBy = indexObservations(obs)

	// Index identities by source key, for cloud_assume_edge.Subject.
	snap.identityByKey = make(map[string]uuid.UUID, len(snap.Identities))
	snap.identityNativeByID = make(map[uuid.UUID]string, len(snap.Identities))
	for _, ci := range snap.Identities {
		snap.identityByKey[IdentityKey(ci)] = ci.ID
		snap.identityNativeByID[ci.ID] = ci.NativeID
	}

	// Native ids for the identities this run's WORKLOADS reference, REGARDLESS
	// OF GENERATION. A workload whose role sits at an older generation is not
	// in snap.Identities, and without this the not_in_scan state could not
	// name the role -- which is the whole point of distinguishing it from
	// "no role configured".
	var refs []uuid.UUID
	for _, w := range snap.Workloads {
		if w.IdentityID != nil {
			if _, known := snap.identityNativeByID[*w.IdentityID]; !known {
				refs = append(refs, *w.IdentityID)
			}
		}
	}
	if len(refs) > 0 {
		var rows []models.CloudIdentity
		if err := tx.Select("id", "native_id").
			Where("workspace_id = ? AND id IN ?", run.WorkspaceID, refs).
			Find(&rows).Error; err != nil {
			return nil, fmt.Errorf("load referenced identities: %w", err)
		}
		for _, ci := range rows {
			snap.identityNativeByID[ci.ID] = ci.NativeID
		}
	}

	// A DEFENCE IN DEPTH, NOT THE GUARANTEE.
	//
	// The connector's generation only moves at commitScan, so this catches a
	// NEXT scan that already FINISHED -- it cannot catch one still in flight:
	//
	//   1. run at generation 7 publishes; its projection job is queued
	//   2. scan 8 starts; generation := 7 + 1 = 8
	//   3. scan 8 rewrites one identity  -> last_seen_generation = 8
	//   4. connector.scan_generation is STILL 7 -- commitScan has not run
	//   5. the loader selects generation 7 and silently omits that identity
	//   6. this check sees 7 > 7 = false and accepts the snapshot
	//
	// The row was already gone BEFORE the snapshot opened, so no isolation
	// level helps: that is a MISSING read, not a torn one. The real guarantee
	// is §2.10A's pipeline barrier -- a durable iga_pipeline_lease row, not an
	// advisory lock, because publication and projection are different
	// transactions and a session lock cannot span them.
	var fresh models.CloudConnector
	if err := tx.First(&fresh, "id = ?", cid).Error; err != nil {
		return nil, fmt.Errorf("re-read connector: %w", err)
	}
	if fresh.ScanGeneration > gen {
		return nil, ErrSuperseded
	}
	return snap, tx.Commit().Error
}

// indexObservations groups confirmed observation ids by the subject key they
// were written against.
//
// OBSERVATIONS WHOSE KEY LACKS THE SEPARATOR ARE SKIPPED. Those predate the
// qualifying writer, and matching them on a bare native id would be a GUESS:
// two holders of the same managed policy share a statement identifier, so the
// orphan could belong to either, and attaching it to one -- or to both --
// manufactures evidence. Worse, it would let ambiguous history satisfy the
// "every projected edge has evidence" gate, turning the gate into a rubber
// stamp.
//
// Those rows stay queryable as history and the read path surfaces them as
// UNATTRIBUTED evidence: "this was observed, we cannot say for which grant",
// which is a true statement and a useful one.
func indexObservations(obs []models.CloudObservation) map[SubjectRef][]uuid.UUID {
	out := make(map[SubjectRef][]uuid.UUID, len(obs))
	for _, o := range obs {
		kind, _ := o.Subject()
		if kind == "" {
			// Subject reconciled away and the FK set to NULL. Still history,
			// never evidence for a specific edge.
			continue
		}
		if kind == "permission" && !Qualified(o.SubjectNativeID) {
			continue
		}
		ref := SubjectRef{Kind: kind, NativeID: o.SubjectNativeID}
		out[ref] = append(out[ref], o.ID)
	}
	return out
}

// existing holds the workspace's live graph objects, keyed by source_key, so
// the projection does ZERO per-row SELECTs.
//
// Recreate detection needs the current object for every incoming row. Doing
// that as a SELECT ... WHERE source_key = ? per row is one round trip per
// identity -- 107 today, thousands on a real estate, all inside one
// transaction holding locks.
type existing struct {
	identity    map[string]*models.IGAIdentityAccount
	workload    map[string]*models.IGAWorkload
	resource    map[string]*models.IGAResource
	entitlement map[string]*models.IGAEntitlement
	credential  map[string]*models.IGACredential
	agent       map[string]*models.IGAAgent

	// retiredIdentity holds rows retired as UNSUPPORTED, keyed by
	// (source_key, immutable_key). Both, because the recognition key alone
	// would "restore" a RECREATED object -- a different principal wearing the
	// old name -- which is the one thing restoration must never do.
	retiredIdentity map[string]*models.IGAIdentityAccount
}

// retiredKey is the restoration lookup. Both halves, deliberately: see
// existing.retiredIdentity.
func retiredKey(sourceKey, immutableKey string) string {
	return sourceKey + Sep + immutableKey
}

// LoadExisting reads the workspace's live objects ONCE, before the projection
// transaction opens.
//
// One query per type, WHERE lifecycle <> 'retired' -- matching the partial
// unique indexes, so what is loaded is exactly what a conflict could hit. The
// transaction still sees its own writes because the upserts go through tx;
// this is only the PRE-TRANSACTION baseline, which is all the recreate
// comparison needs.
func LoadExisting(ctx context.Context, db *gorm.DB, ws uuid.UUID) (*existing, error) {
	ex := &existing{
		identity:        map[string]*models.IGAIdentityAccount{},
		workload:        map[string]*models.IGAWorkload{},
		resource:        map[string]*models.IGAResource{},
		entitlement:     map[string]*models.IGAEntitlement{},
		credential:      map[string]*models.IGACredential{},
		agent:           map[string]*models.IGAAgent{},
		retiredIdentity: map[string]*models.IGAIdentityAccount{},
	}
	live := func(dst any) error {
		return db.WithContext(ctx).
			Where("workspace_id = ? AND source_key <> '' AND lifecycle <> 'retired'", ws).
			Find(dst).Error
	}

	var ids []models.IGAIdentityAccount
	if err := live(&ids); err != nil {
		return nil, err
	}
	for i := range ids {
		ex.identity[ids[i].SourceKey] = &ids[i]
	}

	var wls []models.IGAWorkload
	if err := live(&wls); err != nil {
		return nil, err
	}
	for i := range wls {
		ex.workload[wls[i].SourceKey] = &wls[i]
	}

	var res []models.IGAResource
	if err := live(&res); err != nil {
		return nil, err
	}
	for i := range res {
		ex.resource[res[i].SourceKey] = &res[i]
	}

	var ents []models.IGAEntitlement
	if err := live(&ents); err != nil {
		return nil, err
	}
	for i := range ents {
		ex.entitlement[ents[i].SourceKey] = &ents[i]
	}

	var agents []models.IGAAgent
	if err := live(&agents); err != nil {
		return nil, err
	}
	for i := range agents {
		ex.agent[agents[i].SourceKey] = &agents[i]
	}

	// Credentials use a different liveness predicate: their vocabulary is
	// active|expired|revoked|rotated, so "gone" is revoked/expired rather than
	// 'retired'. Matching uq_iga_credentials_source_key exactly.
	var creds []models.IGACredential
	if err := db.WithContext(ctx).
		Where("workspace_id = ? AND source_key <> '' AND lifecycle NOT IN ('revoked','expired')", ws).
		Find(&creds).Error; err != nil {
		return nil, err
	}
	for i := range creds {
		ex.credential[creds[i].SourceKey] = &creds[i]
	}

	// Retired identities, for RESTORATION. Only those retired as
	// 'unsupported': a row retired as 'recreated' is a different principal and
	// must never come back under the returning object's id.
	var retired []models.IGAIdentityAccount
	if err := db.WithContext(ctx).
		Where(`workspace_id = ? AND lifecycle = 'retired' AND retired_reason = ?
		       AND source_key <> '' AND immutable_key <> ''`,
			ws, models.RetiredUnsupported).
		Find(&retired).Error; err != nil {
		return nil, err
	}
	for i := range retired {
		ex.retiredIdentity[retiredKey(retired[i].SourceKey, retired[i].ImmutableKey)] = &retired[i]
	}
	return ex, nil
}

// resolved maps a cloud_* row id to the iga_* object id it projected to.
//
// This is the whole trick of the projection. Nodes are projected BEFORE the
// edges that reference them, so by the time an edge is written both of its
// endpoints are already in here and need no lookup. Without it, every edge
// costs two SELECTs by source_key.
type resolved struct {
	identity    map[uuid.UUID]uuid.UUID // cloud_identity.id   -> iga_identity_accounts.id
	workload    map[uuid.UUID]uuid.UUID // cloud_workload.id   -> iga_workload.id
	resource    map[uuid.UUID]uuid.UUID // cloud_resource.id   -> iga_resources.id
	entitlement map[uuid.UUID]uuid.UUID // cloud_permission.id -> iga_entitlements.id

	// cloud_permission.id -> iga_access_edges.id. Populated by
	// projectAccessEdges and consumed by attachEvidence, which has to know
	// which edge an observation is evidence for. WITHOUT THIS the evidence
	// pass reads an empty map and silently writes nothing -- a broken pipeline
	// that looks like a working one.
	accessEdge map[uuid.UUID]uuid.UUID
	// cloud_workload.id -> iga_relationship.id, for executes_as evidence.
	executesAs map[uuid.UUID]uuid.UUID
	// cloud_assume_edge.id -> iga_relationship.id, for can_assume evidence.
	canAssume map[uuid.UUID]uuid.UUID

	// Keys of the iga objects written, so an edge can name its endpoint's key
	// without a lookup.
	identityKey map[uuid.UUID]string // iga_identity_accounts.id -> source_key
	resourceKey map[uuid.UUID]string // iga_resources.id -> source_key
	// Immutable key of a projected identity, for the relationship key's target
	// segment -- see projectRelationships.
	identityImmutable map[uuid.UUID]string

	// Live iga_* objects by source_key, loaded ONCE before the transaction.
	existing *existing
}

func newResolved(ex *existing) *resolved {
	return &resolved{
		identity:          map[uuid.UUID]uuid.UUID{},
		workload:          map[uuid.UUID]uuid.UUID{},
		resource:          map[uuid.UUID]uuid.UUID{},
		entitlement:       map[uuid.UUID]uuid.UUID{},
		accessEdge:        map[uuid.UUID]uuid.UUID{},
		executesAs:        map[uuid.UUID]uuid.UUID{},
		canAssume:         map[uuid.UUID]uuid.UUID{},
		identityKey:       map[uuid.UUID]string{},
		resourceKey:       map[uuid.UUID]string{},
		identityImmutable: map[uuid.UUID]string{},
		existing:          ex,
	}
}
