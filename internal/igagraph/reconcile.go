package igagraph

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

// Reconciler decides what to do about what a run did NOT see.
//
// The naive version -- "end everything older than this generation" -- is wrong
// and dangerous: a denied surface produces no rows, so every relationship
// behind it looks absent, and a credential outage reads as a successful
// cleanup. Hence canEnd.
type Reconciler struct {
	now func() time.Time
}

func NewReconciler(now func() time.Time) *Reconciler {
	if now == nil {
		now = time.Now
	}
	return &Reconciler{now: now}
}

// Reconcile closes what this run SHOULD have seen and did not.
//
// Runs in the CALLER'S transaction -- see ProjectAndReconcile. Separate
// transactions would publish a graph in which nothing has been closed yet.
func (rc *Reconciler) Reconcile(tx *gorm.DB, snap *Snapshot) error {
	for _, part := range Partitions(snap) {
		stale := !rc.canEnd(snap, part)
		var err error
		// Routing on part.Target matters: a NODE partition sent through the
		// edge helpers matches nothing -- its relationship_type is empty -- and
		// silently reconciles nothing.
		if part.Target == "" {
			err = rc.reconcileNodes(tx, part, snap, stale)
		} else {
			err = rc.reconcileEdges(tx, part, snap, stale)
		}
		if err != nil {
			return fmt.Errorf("reconcile %s: %w", part.Key(), err)
		}
	}
	// Only NOW, with every partition's support settled, is it safe to ask
	// which objects have no support left (§2.10B).
	if err := rc.retireUnsupported(tx, snap); err != nil {
		return err
	}
	return rc.markReconciled(tx, snap)
}

// canEnd gates every close. All four conditions of §2.7 must hold.
func (rc *Reconciler) canEnd(snap *Snapshot, part Partition) bool {
	// 1. The run reached status 'published'. The value is 'published' -- the
	//    cloud_scan_run CHECK is
	//    ('queued','running','published','failed','abandoned') and there is no
	//    'complete'.
	if snap.Run.Status != models.CloudScanRunPublished {
		return false
	}

	// 2/3. POSITIVE EVIDENCE THAT THE SCANNER RAN, FIRST.
	//
	// policy_documents is written ONLY when parsing dropped something
	// (cloud_aws_permission_scan.go), so its ABSENCE is ambiguous: either
	// parsing was clean, or parsing never happened. This fixture must NOT
	// license closing anything, and a bare "absent means clean" rule lets it:
	//
	//     iam_roles        reached
	//     iam_policies     reached
	//     permission_scan  denied      <- the scanner died before parsing
	//     policy_documents absent
	//
	// permission_scan / workload_scan are written by FinalizeCoverage ONLY
	// when a scanner failed before producing a snapshot at all. Their PRESENCE
	// is therefore proof of failure, and must veto every partition that
	// depends on that scanner.
	for _, gate := range part.RequiredScanners {
		if cov, ok := snap.Coverage[gate]; ok && cov.State != models.CloudCoverageReached {
			return false
		}
	}

	for _, name := range part.RequiredSurfaces {
		cov, ok := snap.Coverage[name]

		if name == models.SurfacePolicyDocuments {
			// Only meaningful once RequiredScanners has established that the
			// permission scanner actually ran. Present => something was
			// dropped; absent => nothing was.
			if ok && cov.State != models.CloudCoverageReached {
				return false
			}
			continue
		}

		// Every other surface: an ABSENT report means DID NOT LOOK.
		if !ok || cov.State != models.CloudCoverageReached {
			return false
		}
	}

	// 4. Generation ownership is asserted by the projector before any write
	//    (ErrObsoleteGeneration), and the pipeline fence holds for the whole
	//    transaction, so by the time Reconcile runs this job owns the
	//    generation for every partition it touches.
	//
	//    NOTE: snap.Generation is cloud_scan_run.Generation for ONE connector's
	//    run. Two connectors in one workspace advance independently, so a
	//    generation number is only comparable within part.ConnectorID -- never
	//    order two integrations' generations against each other.
	return true
}

// CanEnd exposes the gate for testing. The decision is pure: it reads only the
// snapshot's own coverage report and the partition's requirements.
func (rc *Reconciler) CanEnd(snap *Snapshot, part Partition) bool { return rc.canEnd(snap, part) }

// scope selects exactly the rows this partition is responsible for, BY THE
// MEMBERSHIP THE PROJECTOR STAMPED ON THEM.
//
// Not a join through endpoint tables. Three reasons, each of which was a
// defect in an earlier draft:
//
//   - filtering on (workspace_id, relationship_type) ends ANOTHER ACCOUNT'S
//     relationships, because a scan of account A does not confirm account B's;
//   - adding only estate_scope_id still crosses REGIONS AND CONNECTORS: a clean
//     lambda:us-east-1 read would license closing lambda:eu-west-1 rows in the
//     same account;
//   - the endpoint union has to enumerate every source type, and missing one
//     silently excludes it -- `realizes` starts at an agent_instance, which a
//     union of workloads and identities does not contain, so those rows would
//     never reconcile at all.
func (rc *Reconciler) scope(tx *gorm.DB, part Partition, snap *Snapshot) *gorm.DB {
	var model any = &models.IGARelationship{}
	if part.Target == "access_edge" {
		model = &models.IGAAccessEdge{}
	}
	return tx.Model(model).
		Where("workspace_id = ? AND connector_id = ? AND partition_key = ?",
			snap.Run.WorkspaceID, part.ConnectorID, part.Key())
}

// reconcileEdges: stale when we could not look, ended when we could and it was
// not there.
func (rc *Reconciler) reconcileEdges(tx *gorm.DB, part Partition, snap *Snapshot, stale bool) error {
	if stale {
		return rc.markStale(tx, part, snap)
	}
	return rc.endOlderThan(tx, part, snap, models.EndedNotSeen)
}

// markStale: we could not look at THIS partition.
//
// Two rules, both learned the hard way:
//
//   - Rows this run DID confirm are excluded. Without that, a denied us-west
//     partition marks us-east's freshly-confirmed relationships stale as well,
//     because the update matched on partition membership alone.
//   - last_confirmed_at is NOT touched. It is the honest answer to "how old is
//     this?", and refreshing it would launder an outage into a confirmation.
func (rc *Reconciler) markStale(tx *gorm.DB, part Partition, snap *Snapshot) error {
	return rc.scope(tx, part, snap).
		Where("state = ?", models.RelCurrent).
		Where("last_confirmed_by IS DISTINCT FROM ?", snap.Run.ID).
		Update("state", models.RelStale).Error
}

// endOlderThan: we looked properly at this partition and it was not there.
func (rc *Reconciler) endOlderThan(tx *gorm.DB, part Partition, snap *Snapshot, reason string) error {
	return rc.scope(tx, part, snap).
		Where("state <> ?", models.RelEnded).
		// IS DISTINCT FROM, never <>. last_confirmed_by is nullable, and
		// NULL <> uuid evaluates to NULL rather than true -- a plain <> would
		// silently skip every row that never carried a run id and leave
		// pre-graph rows `current` forever.
		Where("last_confirmed_by IS DISTINCT FROM ?", snap.Run.ID).
		Updates(map[string]any{
			"state":        models.RelEnded,
			"valid_to":     rc.now(),
<<<<<<< HEAD
			"ended_reason": reason, // never empty: 031's CHECK enforces it
=======
			"ended_reason": reason, // never empty: 030's CHECK enforces it
>>>>>>> 5bc580923b6db60cc95c9aa818bc95aa102d923e
			"updated_at":   rc.now(),
		}).Error
}

// reconcileNodes -- STEP 1: end this partition's SUPPORT, not the object.
//
// Never the node directly: a node touched by this partition may still be held
// by another account (§2.10B).
func (rc *Reconciler) reconcileNodes(tx *gorm.DB, part Partition, snap *Snapshot, stale bool) error {
<<<<<<< HEAD
	// The TYPED column for this class. One mapping (models.SupportColumn),
	// shared with the upsert's conflict target, so a support row cannot be
	// written against one column and reconciled against another.
	col := models.SupportColumn(part.Class)
	if col == "" {
		return fmt.Errorf("no support column for node class %q", part.Class)
	}
	q := tx.Model(&models.IGAObjectSupport{}).
		Where("workspace_id = ? AND "+col+" IS NOT NULL AND connector_id = ? AND partition_key = ?",
			snap.Run.WorkspaceID, part.ConnectorID, part.Key()).
=======
	q := tx.Model(&models.IGAObjectSupport{}).
		Where("workspace_id = ? AND object_type = ? AND connector_id = ? AND partition_key = ?",
			snap.Run.WorkspaceID, part.Class, part.ConnectorID, part.Key()).
>>>>>>> 5bc580923b6db60cc95c9aa818bc95aa102d923e
		Where("state <> ?", models.RelEnded).
		Where("last_confirmed_run_id IS DISTINCT FROM ?", snap.Run.ID)

	if stale {
		return q.Where("state = ?", models.RelCurrent).
			Update("state", models.RelStale).Error
	}
	return q.Updates(map[string]any{
		"state":        models.RelEnded,
		"ended_reason": models.EndedNotSeen,
	}).Error
}

// retireUnsupported -- STEP 2: derive each object's lifecycle from what
// support REMAINS.
//
// Same transaction, after every partition's support has been reconciled, so an
// object is retired only when NO SOURCE ANYWHERE still holds it.
func (rc *Reconciler) retireUnsupported(tx *gorm.DB, snap *Snapshot) error {
	// The first EXISTS matters: an object with NO support rows at all is
<<<<<<< HEAD
	// pre-graph, not unsupported, and must not be retired by this pass -- 035
	// handles those deliberately.
	// %s is the node table, %s its typed support column. Both come from the
	// same class, so the join column and the table cannot drift apart.
=======
	// pre-graph, not unsupported, and must not be retired by this pass -- 034
	// handles those deliberately.
>>>>>>> 5bc580923b6db60cc95c9aa818bc95aa102d923e
	const stmt = `
		UPDATE %s n
		   SET lifecycle = 'retired', retired_reason = ?, updated_at = now()
		 WHERE n.workspace_id = ?
		   AND n.lifecycle = 'active'
		   AND EXISTS (SELECT 1 FROM iga_object_support s
		                WHERE s.workspace_id = n.workspace_id
<<<<<<< HEAD
		                  AND s.%s = n.id)
		   AND NOT EXISTS (SELECT 1 FROM iga_object_support s
		                    WHERE s.workspace_id = n.workspace_id
		                      AND s.%s = n.id
		                      AND s.state <> 'ended')`

	for _, t := range []struct{ table, class string }{
=======
		                  AND s.object_type = ? AND s.object_id = n.id)
		   AND NOT EXISTS (SELECT 1 FROM iga_object_support s
		                    WHERE s.workspace_id = n.workspace_id
		                      AND s.object_type = ? AND s.object_id = n.id
		                      AND s.state <> 'ended')`

	for _, t := range []struct{ table, objectType string }{
>>>>>>> 5bc580923b6db60cc95c9aa818bc95aa102d923e
		{"iga_identity_accounts", models.ObjectIdentity},
		{"iga_workload", models.ObjectWorkload},
		{"iga_resources", models.ObjectResource},
		{"iga_entitlements", models.ObjectEntitlement},
		{"iga_agents", models.ObjectAgent},
	} {
<<<<<<< HEAD
		col := models.SupportColumn(t.class)
		if col == "" {
			return fmt.Errorf("no support column for node class %q", t.class)
		}
		if err := tx.Exec(fmt.Sprintf(stmt, t.table, col, col),
			models.RetiredUnsupported, snap.Run.WorkspaceID).Error; err != nil {
=======
		if err := tx.Exec(fmt.Sprintf(stmt, t.table),
			models.RetiredUnsupported, snap.Run.WorkspaceID,
			t.objectType, t.objectType).Error; err != nil {
>>>>>>> 5bc580923b6db60cc95c9aa818bc95aa102d923e
			return fmt.Errorf("retire unsupported %s: %w", t.table, err)
		}
	}

	// Retiring a node ends its incident relationships, in the same
	// transaction. An edge pointing at a retired object and reading `current`
	// is a lie the read path would repeat.
<<<<<<< HEAD
	if err := rc.endEdgesOnRetiredIdentities(tx, snap); err != nil {
		return err
	}

	// And it settles the resolutions pointing at what just retired -- IN THIS
	// SAME TRANSACTION. Deferring it to the next pass would leave a resolution
	// in force, pointing at a retired row, for a full scan cycle.
	//
	// The two bases settle differently, and that asymmetry is the point:
	//   * DERIVED is recomputed from evidence every pass, so it is simply
	//     cleared -- the next pass re-derives it, or leaves it unresolved.
	//   * ASSERTED is a person's decision. It is PRESERVED, still pointing at
	//     the retired row so it stays explicable, but SUSPENDED so it is no
	//     longer in force. It never returns to active on its own.
	return rc.settleResolutionsOnRetired(tx, snap)
=======
	return rc.endEdgesOnRetiredIdentities(tx, snap)
>>>>>>> 5bc580923b6db60cc95c9aa818bc95aa102d923e
}

func (rc *Reconciler) endEdgesOnRetiredIdentities(tx *gorm.DB, snap *Snapshot) error {
	now := rc.now()
	if err := tx.Exec(`
		UPDATE iga_access_edges e
		   SET state = 'ended', valid_to = ?, ended_reason = ?, updated_at = ?
		 WHERE e.workspace_id = ?
		   AND e.state <> 'ended'
		   AND EXISTS (SELECT 1 FROM iga_identity_accounts a
		                WHERE a.workspace_id = e.workspace_id
		                  AND a.id = e.subject_identity_account_id
		                  AND a.lifecycle = 'retired')`,
		now, models.EndedSubjectRetired, now, snap.Run.WorkspaceID).Error; err != nil {
		return err
	}
	return tx.Exec(`
		UPDATE iga_relationship r
		   SET state = 'ended', valid_to = ?, ended_reason = ?, updated_at = ?
		 WHERE r.workspace_id = ?
		   AND r.state <> 'ended'
		   AND (EXISTS (SELECT 1 FROM iga_identity_accounts a
		                 WHERE a.workspace_id = r.workspace_id
		                   AND a.id IN (r.source_identity_account_id, r.target_identity_account_id)
		                   AND a.lifecycle = 'retired')
		     OR EXISTS (SELECT 1 FROM iga_workload w
		                 WHERE w.workspace_id = r.workspace_id
		                   AND w.id IN (r.source_workload_id, r.target_workload_id)
		                   AND w.lifecycle = 'retired'))`,
		now, models.EndedSubjectRetired, now, snap.Run.WorkspaceID).Error
}

<<<<<<< HEAD
// settleResolutionsOnRetired suspends asserted resolutions and clears derived
// ones whose target has just retired.
func (rc *Reconciler) settleResolutionsOnRetired(tx *gorm.DB, snap *Snapshot) error {
	// Asserted: preserved and suspended, target intact.
	if err := tx.Exec(`
		UPDATE iga_external_principal ep
		   SET resolution_state = ?
		 WHERE ep.workspace_id = ?
		   AND ep.resolution_basis = ?
		   AND ep.resolution_state = ?
		   AND EXISTS (SELECT 1 FROM iga_identity_accounts a
		                WHERE a.workspace_id = ep.workspace_id
		                  AND a.id = ep.resolved_identity_account_id
		                  AND a.lifecycle = 'retired')`,
		models.ResolutionSuspended, snap.Run.WorkspaceID,
		models.BasisAsserted, models.ResolutionActive).Error; err != nil {
		return fmt.Errorf("suspend asserted resolutions: %w", err)
	}

	// Derived: cleared, so the next pass re-derives from evidence rather than
	// leaving a computed answer standing over a retired object. The CHECK
	// requires basis and target to go together, so both clear at once.
	return tx.Exec(`
		UPDATE iga_external_principal ep
		   SET resolved_identity_account_id = NULL,
		       resolution_basis = '',
		       resolution_rule  = ''
		 WHERE ep.workspace_id = ?
		   AND ep.resolution_basis = ?
		   AND EXISTS (SELECT 1 FROM iga_identity_accounts a
		                WHERE a.workspace_id = ep.workspace_id
		                  AND a.id = ep.resolved_identity_account_id
		                  AND a.lifecycle = 'retired')`,
		snap.Run.WorkspaceID, models.BasisDerived).Error
}

=======
>>>>>>> 5bc580923b6db60cc95c9aa818bc95aa102d923e
// markReconciled flips every partition's watermark, in the same transaction
// that did the closing.
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

// LastGenerationFor reads a partition's watermark.
//
<<<<<<< HEAD
// Keyed EXACTLY as 033 keys the table and exactly as scope() filters rows --
=======
// Keyed EXACTLY as 032 keys the table and exactly as scope() filters rows --
>>>>>>> 5bc580923b6db60cc95c9aa818bc95aa102d923e
// one value, three call sites, no predicate to keep in agreement.
func LastGenerationFor(tx *gorm.DB, part Partition, ws uuid.UUID) (int64, error) {
	var st models.IGAProjectionState
	err := tx.Where("workspace_id = ? AND connector_id = ? AND partition_key = ?",
		ws, part.ConnectorID, part.Key()).First(&st).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, nil
	}
	return st.LastGeneration, err
}
