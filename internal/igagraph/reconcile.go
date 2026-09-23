package igagraph

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

// Reconciler decides what to do about what a run did NOT see (§4.10).
//
// The naive version -- "end everything older than this generation" -- is wrong
// and dangerous: a denied surface produces no rows, so every relationship
// behind it looks absent, and a credential outage reads as a cleanup. Hence
// canEnd.
type Reconciler struct {
	now func() time.Time
}

func NewReconciler(now func() time.Time) *Reconciler {
	if now == nil {
		now = time.Now
	}
	return &Reconciler{now: now}
}

// Reconcile closes what this run SHOULD have seen and did not, in the caller's
// transaction. Node partitions act on SUPPORT rows; edge partitions on the
// edge tables. ex names what unreadable documents declared; events receives
// every retirement so the Changes history survives the node row.
//
// Every valid_to it writes is the PASS's timestamp, taken from events -- the
// publication's published_at (D-26) -- never a clock read now: an end stamped
// after publication joins to no revision, and the Changes view could not say
// which run ended it. Only a Reconcile outside a projection pass (no event
// log) falls back to the reconciler's own clock.
func (rc *Reconciler) Reconcile(tx *gorm.DB, snap *Snapshot, ex Exclusions, events *EventLog) error {
	at := PassTime(rc.now())
	if events != nil {
		at = events.At()
	}
	for _, part := range Partitions(snap) {
		stale := !rc.canEnd(snap, part)
		var err error
		if part.Target == "" {
			err = rc.reconcileNodes(tx, part, snap, ex, stale)
		} else {
			err = rc.reconcileEdges(tx, part, snap, ex, stale, at)
		}
		if err != nil {
			return fmt.Errorf("reconcile %s: %w", part.Key(), err)
		}
	}
	// Only now, with every partition's support settled, is it safe to ask
	// which objects have no support left (§2.10B).
	if err := rc.retireUnsupported(tx, snap, events, at); err != nil {
		return err
	}
	return rc.markReconciled(tx, snap)
}

// canEnd gates every close. All four conditions of §2.7 must hold.
func (rc *Reconciler) canEnd(snap *Snapshot, part Partition) bool {
	// 1. The run reached status 'published' (there is no 'complete').
	if snap.Run.Status != models.CloudScanRunPublished {
		return false
	}
	// 2/3. POSITIVE EVIDENCE THAT THE SCANNER RAN, FIRST. permission_scan /
	// workload_scan are written ONLY when a scanner died before producing a
	// snapshot, so their PRESENCE proves failure and vetoes the partition.
	for _, gate := range part.RequiredScanners {
		if cov, ok := snap.Coverage[gate]; ok && cov.State != models.CloudCoverageReached {
			return false
		}
	}
	for _, name := range part.RequiredSurfaces {
		cov, ok := snap.Coverage[name]
		if name == models.SurfacePolicyDocuments {
			// Present => something was dropped; absent => nothing was.
			if ok && cov.State != models.CloudCoverageReached {
				return false
			}
			continue
		}
		// Every other surface: ABSENT MEANS DID NOT LOOK.
		if !ok || cov.State != models.CloudCoverageReached {
			return false
		}
	}
	// 4. The job owns the partition's generation: asserted by the projector
	// before any write, and the barrier holds for the whole transaction.
	return true
}

// CanEnd exposes the gate for testing. The decision is pure.
func (rc *Reconciler) CanEnd(snap *Snapshot, part Partition) bool { return rc.canEnd(snap, part) }

// scope selects exactly the rows an EDGE partition is responsible for, by the
// membership the projector stamped on them. No joins, no endpoint union.
//
// EXHAUSTIVE. A default that fell through to iga_relationship would send an
// assignment partition to the wrong table: grants would end, their assignment
// would stay current, and a reattach would revive the old period.
func (rc *Reconciler) scope(tx *gorm.DB, part Partition, snap *Snapshot) (*gorm.DB, error) {
	var model any
	switch part.Target {
	case "relationship":
		model = &models.IGARelationship{}
	case "assignment":
		model = &models.IGAPolicyAssignment{}
	case "access_edge":
		model = &models.IGAAccessEdge{}
	default:
		return nil, fmt.Errorf("partition %s: no edge table for target %q", part.Key(), part.Target)
	}
	return tx.Model(model).
		Where("workspace_id = ? AND connector_id = ? AND partition_key = ?",
			snap.Run.WorkspaceID, part.ConnectorID, part.Key()), nil
}

// ScopeForTest exposes scope's table decision for the exhaustiveness test.
func (rc *Reconciler) ScopeForTest(tx *gorm.DB, part Partition, snap *Snapshot) error {
	_, err := rc.scope(tx, part, snap)
	return err
}

// protected returns the predicate for rows of this partition that an
// UNREADABLE document declared. Exhaustive: every partition answers.
//
// When a partition CAN end, protected rows this run did not confirm move
// current -> stale BEFORE the end statement runs, and the end statement
// excludes them. So an unreadable document's statements, grants and the
// support of resources only it names are never ended, while a genuinely
// detached policy in the same account still ends.
func protected(part Partition, ex Exclusions) (string, []any, bool) {
	pol := ex.UnreadablePolicies
	switch {
	case part.Target == "access_edge":
		return `entitlement_id IN (SELECT id FROM iga_entitlements
		          WHERE workspace_id = iga_access_edges.workspace_id AND policy_id = ANY(?))`,
			[]any{pq.Array(pol)}, len(pol) > 0
	case part.Target == "relationship" && part.RelationshipType == models.RelTypeCanAssume && part.Kind == "trust":
		return `target_identity_account_id = ANY(?)`,
			[]any{pq.Array(ex.UnreadableTrust)}, len(ex.UnreadableTrust) > 0
	case part.Target == "relationship" && part.RelationshipType == models.RelTypeCanAssume &&
		part.Kind == models.MechanismEKSPodIdentity:
		// A pod-identity association no cluster could be named for wrote no
		// edge (trust.go); what that role's associations declared before
		// must not look absent.
		return `target_identity_account_id = ANY(?)`,
			[]any{pq.Array(ex.UnattributedPodIdentity)}, len(ex.UnattributedPodIdentity) > 0
	case part.Class == models.ObjectEntitlement:
		return `entitlement_id IN (SELECT id FROM iga_entitlements
		          WHERE workspace_id = iga_object_support.workspace_id AND policy_id = ANY(?))`,
			[]any{pq.Array(pol)}, len(pol) > 0
	case part.Class == models.ObjectResource:
		// A resource another statement still names is confirmed anyway; one
		// named ONLY by an unreadable policy must not lose this source's support.
		return `resource_id IN (SELECT t.resource_id FROM iga_entitlement_target t
		          JOIN iga_entitlements e ON e.workspace_id = t.workspace_id AND e.id = t.entitlement_id
		          WHERE t.workspace_id = iga_object_support.workspace_id AND e.policy_id = ANY(?))`,
			[]any{pq.Array(pol)}, len(pol) > 0
	default:
		// identities, workloads, policies (still listed), assignments
		// (attachment lists are read independently of documents), member_of,
		// executes_as, task_execution_role
		return "", nil, false
	}
}

// reconcileEdges: stale when we could not look, ended when we could and it was
// not there. Protected rows first: stale, never ended.
func (rc *Reconciler) reconcileEdges(tx *gorm.DB, part Partition, snap *Snapshot, ex Exclusions, stale bool, at time.Time) error {
	if stale {
		return rc.markStale(tx, part, snap, "")
	}
	if p, args, ok := protected(part, ex); ok {
		if err := rc.markStale(tx, part, snap, p, args...); err != nil {
			return err
		}
		return rc.endOlderThan(tx, part, snap, at, models.EndedNotSeen, "NOT ("+p+")", args...)
	}
	return rc.endOlderThan(tx, part, snap, at, models.EndedNotSeen, "")
}

// markStale: we could not look at THIS partition. Rows this run DID confirm
// are excluded, and last_confirmed_at is NOT touched -- it is the honest
// answer to "how old is this?", and refreshing it launders an outage.
func (rc *Reconciler) markStale(tx *gorm.DB, part Partition, snap *Snapshot, extra string, args ...any) error {
	q, err := rc.scope(tx, part, snap)
	if err != nil {
		return err
	}
	q = q.Where("state = ?", models.RelCurrent).
		Where("last_confirmed_by IS DISTINCT FROM ?", snap.Run.ID)
	if extra != "" {
		q = q.Where(extra, args...)
	}
	return q.Update("state", models.RelStale).Error
}

// endOlderThan: we looked properly at this partition and it was not there.
// IS DISTINCT FROM, never <>: last_confirmed_by is nullable, and NULL <> uuid
// is NULL, which would leave pre-graph rows current forever.
func (rc *Reconciler) endOlderThan(tx *gorm.DB, part Partition, snap *Snapshot, at time.Time, reason, extra string, args ...any) error {
	q, err := rc.scope(tx, part, snap)
	if err != nil {
		return err
	}
	if extra != "" {
		q = q.Where(extra, args...)
	}
	return q.Where("state <> ?", models.RelEnded).
		Where("last_confirmed_by IS DISTINCT FROM ?", snap.Run.ID).
		Updates(map[string]any{
			"state":        models.RelEnded,
			"valid_to":     at, // D-26: the pass's one timestamp
			"ended_reason": reason,
		}).Error
}

// reconcileNodes -- STEP 1: end this partition's SUPPORT, never the object. A
// node touched here may still be held by another account (§2.10B).
func (rc *Reconciler) reconcileNodes(tx *gorm.DB, part Partition, snap *Snapshot, ex Exclusions, stale bool) error {
	col := models.SupportColumn(part.Class)
	if col == "" {
		return fmt.Errorf("no support column for node class %q", part.Class) // a programming error, never a no-op
	}
	base := func() *gorm.DB {
		return tx.Model(&models.IGAObjectSupport{}).
			Where("workspace_id = ? AND connector_id = ? AND partition_key = ?",
				snap.Run.WorkspaceID, part.ConnectorID, part.Key()).
			Where(col+" IS NOT NULL").
			Where("state <> ?", models.RelEnded).
			Where("last_confirmed_run_id IS DISTINCT FROM ?", snap.Run.ID)
	}
	if stale {
		return base().Where("state = ?", models.RelCurrent).Update("state", models.RelStale).Error
	}
	q := base()
	if p, args, ok := protected(part, ex); ok {
		if err := base().Where("state = ?", models.RelCurrent).Where(p, args...).
			Update("state", models.RelStale).Error; err != nil {
			return err
		}
		q = q.Where("NOT ("+p+")", args...)
	}
	return q.Updates(map[string]any{"state": models.RelEnded, "ended_reason": models.EndedNotSeen}).Error
}

// retireUnsupported -- STEP 2: derive each object's lifecycle from what support
// REMAINS, then cascade what depends on it, in the same transaction:
//
//	retired      ends                                  ended_reason
//	identity     its relationships, assignments,       subject_retired
//	             grants
//	workload     its executes_as / task_execution_role subject_retired
//	policy       its assignments, and their grants     policy_retired
//	statement    its grants                            statement_retired
//	resource     nothing: targets are statement content
func (rc *Reconciler) retireUnsupported(tx *gorm.DB, snap *Snapshot, events *EventLog, now time.Time) error {
	ws := snap.Run.WorkspaceID
	retiredBy := map[string][]uuid.UUID{}
	for _, class := range models.NodeClasses {
		col, table := models.SupportColumn(class), models.NodeTable(class)
		if col == "" || table == "" {
			return fmt.Errorf("unmapped node class %q", class)
		}
		// The first EXISTS matters: an object with NO support rows at all is
		// pre-graph, not unsupported. provider = 'aws': GitHub's rows share
		// these tables and are never retired by this pass.
		stmt := fmt.Sprintf(`
			UPDATE %[1]s n
			   SET lifecycle = 'retired', retired_reason = ?
			 WHERE n.workspace_id = ? AND n.provider = 'aws'
			   AND n.lifecycle = 'active'
			   AND EXISTS (SELECT 1 FROM iga_object_support s
			                WHERE s.workspace_id = n.workspace_id AND s.%[2]s = n.id)
			   AND NOT EXISTS (SELECT 1 FROM iga_object_support s
			                    WHERE s.workspace_id = n.workspace_id AND s.%[2]s = n.id
			                      AND s.state <> 'ended')
			RETURNING n.id`, table, col)
		var ids []uuid.UUID
		if err := tx.Raw(stmt, models.RetiredUnsupported, ws).Scan(&ids).Error; err != nil {
			return fmt.Errorf("retire unsupported %s: %w", table, err)
		}
		for _, id := range ids {
			events.Retired(class, id, models.RetiredUnsupported)
		}
		retiredBy[class] = ids
	}

	end := map[string]any{"state": models.RelEnded, "valid_to": now}
	endWith := func(reason string) map[string]any {
		m := map[string]any{"ended_reason": reason}
		for k, v := range end {
			m[k] = v
		}
		return m
	}
	if ids := retiredBy[models.ObjectIdentity]; len(ids) > 0 {
		if err := tx.Model(&models.IGARelationship{}).
			Where("workspace_id = ? AND state <> ? AND (source_identity_account_id IN ? OR target_identity_account_id IN ?)",
				ws, models.RelEnded, ids, ids).Updates(endWith(models.EndedSubjectRetired)).Error; err != nil {
			return err
		}
		if err := tx.Model(&models.IGAPolicyAssignment{}).
			Where("workspace_id = ? AND state <> ? AND holder_identity_account_id IN ?", ws, models.RelEnded, ids).
			Updates(endWith(models.EndedSubjectRetired)).Error; err != nil {
			return err
		}
		if err := tx.Model(&models.IGAAccessEdge{}).
			Where("workspace_id = ? AND state <> ? AND subject_identity_account_id IN ?", ws, models.RelEnded, ids).
			Updates(endWith(models.EndedSubjectRetired)).Error; err != nil {
			return err
		}
	}
	if ids := retiredBy[models.ObjectWorkload]; len(ids) > 0 {
		if err := tx.Model(&models.IGARelationship{}).
			Where("workspace_id = ? AND state <> ? AND source_workload_id IN ?", ws, models.RelEnded, ids).
			Updates(endWith(models.EndedSubjectRetired)).Error; err != nil {
			return err
		}
	}
	if ids := retiredBy[models.ObjectPolicy]; len(ids) > 0 {
		if err := tx.Model(&models.IGAAccessEdge{}).
			Where(`workspace_id = ? AND state <> ? AND assignment_id IN
			       (SELECT id FROM iga_policy_assignment WHERE workspace_id = ? AND policy_id IN ?)`,
				ws, models.RelEnded, ws, ids).Updates(endWith(models.EndedPolicyRetired)).Error; err != nil {
			return err
		}
		if err := tx.Model(&models.IGAPolicyAssignment{}).
			Where("workspace_id = ? AND state <> ? AND policy_id IN ?", ws, models.RelEnded, ids).
			Updates(endWith(models.EndedPolicyRetired)).Error; err != nil {
			return err
		}
	}
	if ids := retiredBy[models.ObjectEntitlement]; len(ids) > 0 {
		if err := tx.Model(&models.IGAAccessEdge{}).
			Where("workspace_id = ? AND state <> ? AND entitlement_id IN ?", ws, models.RelEnded, ids).
			Updates(endWith(models.EndedStatementRetired)).Error; err != nil {
			return err
		}
		// A retired statement's live revision closes: its content is history.
		if err := tx.Model(&models.IGAStatementRevision{}).
			Where("workspace_id = ? AND valid_to IS NULL AND entitlement_id IN ?", ws, ids).
			Update("valid_to", now).Error; err != nil {
			return err
		}
	}

	// A person's association with an object that just retired is SUSPENDED,
	// not cleared (§2.12); a derived one is re-derived now -- unresolved.
	for class, epCol := range map[string]string{
		models.ObjectIdentity: "resolved_identity_account_id",
		models.ObjectWorkload: "resolved_workload_id",
	} {
		ids := retiredBy[class]
		if len(ids) == 0 {
			continue
		}
		if err := tx.Exec(`UPDATE iga_external_principal SET resolution_state = ?
		                    WHERE workspace_id = ? AND resolution_basis = ? AND resolution_state = ?
		                      AND `+epCol+` IN ?`,
			models.ResolutionSuspended, ws, models.BasisAsserted, models.ResolutionActive, ids).Error; err != nil {
			return fmt.Errorf("suspend assertions on retired %s: %w", class, err)
		}
		if err := tx.Exec(`UPDATE iga_external_principal
		                      SET `+epCol+` = NULL, resolution_basis = '', resolution_rule = ''
		                    WHERE workspace_id = ? AND resolution_basis = ? AND `+epCol+` IN ?`,
			ws, models.BasisDerived, ids).Error; err != nil {
			return fmt.Errorf("re-derive resolutions on retired %s: %w", class, err)
		}
	}
	return nil
}

// markReconciled flips every partition's watermark, in the transaction that
// did the closing.
func (rc *Reconciler) markReconciled(tx *gorm.DB, snap *Snapshot) error {
	for _, part := range Partitions(snap) {
		if err := tx.Model(&models.IGAProjectionState{}).
			Where("workspace_id = ? AND connector_id = ? AND partition_key = ?",
				snap.Run.WorkspaceID, part.ConnectorID, part.Key()).
			Updates(map[string]any{"reconciled": true, "updated_at": rc.now()}).Error; err != nil {
			return err
		}
	}
	return nil
}

// LastGenerationFor reads a partition's watermark -- keyed exactly as 033 keys
// the table and as scope() filters rows.
func LastGenerationFor(tx *gorm.DB, part Partition, ws uuid.UUID) (int64, error) {
	var st models.IGAProjectionState
	err := tx.Where("workspace_id = ? AND connector_id = ? AND partition_key = ?",
		ws, part.ConnectorID, part.Key()).First(&st).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, nil
	}
	return st.LastGeneration, err
}
