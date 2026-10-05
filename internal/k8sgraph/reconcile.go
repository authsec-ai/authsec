package k8sgraph

import (
	"fmt"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Reconciler decides what a sweep did NOT see, and whether that is evidence.
//
// THE DEFECT THIS EXISTS TO PREVENT
// Before this, the Kubernetes projector wrote every row 'current'/'active' and
// never closed anything. A RoleBinding deleted in the cluster stayed in the
// graph forever, so the product answered "who can read secrets in production"
// with a list that only ever grew. For an IGA product that is the worst
// available failure: it is the one answer a reviewer acts on.
//
// The opposite mistake is just as bad and far easier to make. If absence were
// taken at face value, a single denied LIST would retire a cluster's whole
// authorization model and restore it on the next sweep -- a permissions outage
// rendered as a mass revocation, complete with governance alerts. So every path
// here falls to `stale`, and only the four conditions in Scope.CanEnd license
// `ended`.
type Reconciler struct {
	now func() time.Time
}

func NewReconciler(now func() time.Time) *Reconciler {
	if now == nil {
		now = time.Now
	}
	return &Reconciler{now: now}
}

// ReconcileInput is one sweep's authority to close rows.
type ReconcileInput struct {
	WorkspaceID uuid.UUID
	SweepID     uuid.UUID
	Scope       Scope
}

// ReconcileResult is what the sweep changed, so the agent's logs, the console
// and the sweep row agree on what happened.
type ReconcileResult struct {
	SupportEnded   int `json:"support_ended"`
	SupportStale   int `json:"support_stale"`
	EdgesEnded     int `json:"edges_ended"`
	EdgesStale     int `json:"edges_stale"`
	ObjectsRetired int `json:"objects_retired"`

	// PartitionsClosed and PartitionsStale say WHY, which is the part an
	// operator needs when a number looks wrong. A sweep that could not read
	// cluster-wide reports every cluster partition stale, and that single line
	// explains an otherwise alarming "0 retired".
	PartitionsClosed int `json:"partitions_closed"`
	PartitionsStale  int `json:"partitions_stale"`
}

// Reconcile runs in the caller's transaction, after the sweep's rows are
// upserted. Both halves must commit together: support ended without the
// retirement it implies leaves objects alive with no evidence, and a retirement
// without its support change re-retires on every sweep.
func (rc *Reconciler) Reconcile(tx *gorm.DB, in ReconcileInput) (*ReconcileResult, error) {
	at := rc.now()
	res := &ReconcileResult{}

	for _, part := range Partitions(in.Scope) {
		closing := in.Scope.CanEnd(part)
		if closing {
			res.PartitionsClosed++
		} else {
			res.PartitionsStale++
		}

		if part.Target != "" {
			n, err := rc.reconcileEdges(tx, in, part, closing, at)
			if err != nil {
				return nil, fmt.Errorf("edges %s: %w", part.Key(), err)
			}
			if closing {
				res.EdgesEnded += n
			} else {
				res.EdgesStale += n
			}
			continue
		}

		n, err := rc.reconcileSupport(tx, in, part, closing)
		if err != nil {
			return nil, fmt.Errorf("support %s: %w", part.Key(), err)
		}
		if closing {
			res.SupportEnded += n
		} else {
			res.SupportStale += n
		}
	}

	retired, err := rc.retireUnsupported(tx, in, at)
	if err != nil {
		return nil, fmt.Errorf("retire unsupported: %w", err)
	}
	res.ObjectsRetired = retired
	return res, nil
}

// reconcileSupport -- STEP 1: end this partition's SUPPORT, never the object.
//
// A node touched here may still be held by another source: a second cluster, or
// a second agent watching this one (§2.10B). Ending the object here would make
// one agent's blindness delete what another can plainly see.
func (rc *Reconciler) reconcileSupport(tx *gorm.DB, in ReconcileInput, part Partition, closing bool) (int, error) {
	col := models.SupportColumn(part.Class)
	if col == "" {
		// A programming error, never a silent no-op: an unknown class means
		// some rows have no partition that owns them, so they are never
		// reconciled and live forever.
		return 0, fmt.Errorf("no support column for node class %q", part.Class)
	}

	q := tx.Model(&models.IGAObjectSupport{}).
		Where("workspace_id = ? AND discovery_source_id = ? AND partition_key = ?",
			in.WorkspaceID, in.Scope.SourceID, part.Key()).
		Where(col+" IS NOT NULL").
		Where("state <> ?", models.RelEnded).
		// IS DISTINCT FROM, never <>: last_confirmed_sweep_id is nullable, and
		// NULL <> uuid is NULL, which would leave every pre-041 row current
		// forever -- the rows most in need of reconciling.
		Where("last_confirmed_sweep_id IS DISTINCT FROM ?", in.SweepID)

	if !closing {
		r := q.Where("state = ?", models.RelCurrent).Update("state", models.RelStale)
		return int(r.RowsAffected), r.Error
	}
	r := q.Updates(map[string]any{
		"state":        models.RelEnded,
		"ended_reason": models.EndedNotSeen,
	})
	return int(r.RowsAffected), r.Error
}

// reconcileEdges closes assignments and grants the sweep did not reconfirm.
//
// Edges are NOT support-backed: a binding is one cluster's fact, so absence
// from the partition that owns it is conclusive on its own.
func (rc *Reconciler) reconcileEdges(tx *gorm.DB, in ReconcileInput, part Partition, closing bool, at time.Time) (int, error) {
	if part.Target == TargetExecutesAs {
		return rc.reconcileExecutesAs(tx, in, part, closing, at)
	}

	var model any
	switch part.Target {
	case TargetAssignment:
		model = &models.IGAPolicyAssignment{}
	case TargetAccessEdge:
		model = &models.IGAAccessEdge{}
	default:
		return 0, fmt.Errorf("unknown edge target %q", part.Target)
	}

	q := tx.Model(model).
		Where("workspace_id = ? AND discovery_source_id = ? AND partition_key = ?",
			in.WorkspaceID, in.Scope.SourceID, part.Key()).
		Where("state <> ?", models.RelEnded).
		Where("last_confirmed_sweep_id IS DISTINCT FROM ?", in.SweepID)

	if !closing {
		r := q.Where("state = ?", models.RelCurrent).Update("state", models.RelStale)
		return int(r.RowsAffected), r.Error
	}
	r := q.Updates(map[string]any{
		"state":        models.RelEnded,
		"valid_to":     at, // the pass's one timestamp, so a period is readable
		"ended_reason": models.EndedNotSeen,
	})
	return int(r.RowsAffected), r.Error
}

// reconcileExecutesAs closes workload -> identity edges the sweep did not
// reconfirm.
//
// iga_relationship has no discovery_source_id or last_confirmed_sweep_id (its
// provenance columns are AWS's connector_id and last_confirmed_by), so "this
// sweep confirmed it" is read from last_confirmed_at, which the writer stamps
// with the very instant this pass runs at. The source is still fenced: it is
// part of the partition key. IS DISTINCT FROM rather than <, so an agent clock
// that ran backwards cannot keep an unconfirmed edge alive.
func (rc *Reconciler) reconcileExecutesAs(tx *gorm.DB, in ReconcileInput, part Partition, closing bool, at time.Time) (int, error) {
	q := tx.Model(&models.IGARelationship{}).
		Where("workspace_id = ? AND partition_key = ? AND relationship_type = ?",
			in.WorkspaceID, part.Key(), models.RelTypeExecutesAs).
		Where("state <> ?", models.RelEnded).
		Where("last_confirmed_at IS DISTINCT FROM ?", at)

	if !closing {
		r := q.Where("state = ?", models.RelCurrent).Update("state", models.RelStale)
		return int(r.RowsAffected), r.Error
	}
	r := q.Updates(map[string]any{
		"state":        models.RelEnded,
		"valid_to":     at,
		"ended_reason": models.EndedNotSeen,
	})
	return int(r.RowsAffected), r.Error
}

// retireUnsupported -- STEP 2: derive each object's lifecycle from what support
// REMAINS, then cascade what depends on it, in the same transaction.
//
//	retired     ends                              ended_reason
//	identity    its assignments and its grants    subject_retired
//	policy      its assignments, and their grants policy_retired
//	statement   its grants                        statement_retired
//	workload    its executes_as edges             subject_retired
//
// "What remains" is the whole point: an object retires only when NO source
// still supports it. One agent going blind marks its own support stale and
// changes nothing else.
func (rc *Reconciler) retireUnsupported(tx *gorm.DB, in ReconcileInput, at time.Time) (int, error) {
	ws := in.WorkspaceID
	total := 0

	// The four node tables a Kubernetes sweep owns, with the column that
	// points at them and the reason an edge carries when they go.
	for _, t := range []struct {
		table      string
		supportCol string
		endReason  string
		// everSupported narrows retirement to rows that have had support at
		// all. Workloads were written for releases before they carried any,
		// so for them "no live support" can mean "never had evidence" -- a
		// row of another cluster that its own sweep has not adopted yet --
		// and retiring that would re-create it under a new id next sweep.
		everSupported bool
	}{
		{"iga_identity_accounts", "identity_account_id", models.EndedSubjectRetired, false},
		{"iga_policy", "policy_id", models.EndedPolicyRetired, false},
		{"iga_entitlements", "entitlement_id", models.EndedStatementRetired, false},
		{"iga_workload", "workload_id", models.EndedSubjectRetired, true},
	} {
		ever := ""
		if t.everSupported {
			ever = `
			   AND EXISTS (
			         SELECT 1 FROM iga_object_support s
			          WHERE s.workspace_id = o.workspace_id
			            AND s.` + t.supportCol + ` = o.id)`
		}
		// Retire every live k8s node of this class with no surviving support.
		// NOT EXISTS over non-ended support is the multi-source rule (§2.10B)
		// stated once, in SQL, rather than counted in Go where a miscount
		// deletes a customer's graph.
		r := tx.Exec(`
			UPDATE `+t.table+` o
			   SET lifecycle = ?, retired_reason = ?
			 WHERE o.workspace_id = ?
			   AND o.provider = ?
			   AND o.lifecycle = ?
			   AND NOT EXISTS (
			         SELECT 1 FROM iga_object_support s
			          WHERE s.workspace_id = o.workspace_id
			            AND s.`+t.supportCol+` = o.id
			            AND s.state <> ?)`+ever,
			models.IGALifecycleRetired, models.RetiredUnsupported,
			ws, models.ProviderK8s, models.IGALifecycleActive, models.RelEnded)
		if r.Error != nil {
			return total, fmt.Errorf("retire %s: %w", t.table, r.Error)
		}
		total += int(r.RowsAffected)

		if err := rc.cascade(tx, ws, t.table, t.supportCol, t.endReason, at); err != nil {
			return total, err
		}
	}
	return total, nil
}

// cascade ends the edges that a just-retired node made meaningless.
//
// Done in SQL against the retired set rather than from the Go-side list,
// because a node may have been retired by an earlier sweep whose cascade failed
// -- and an edge left current under a retired node is a path the console will
// happily draw.
func (rc *Reconciler) cascade(tx *gorm.DB, ws uuid.UUID, table, supportCol, reason string, at time.Time) error {
	retired := `SELECT id FROM ` + table + `
	             WHERE workspace_id = ? AND provider = ? AND lifecycle = ?`

	// A retired workload no longer runs as anything. Its executes_as edges are
	// the only edges hanging off it, and they live in iga_relationship.
	if supportCol == "workload_id" {
		if err := tx.Exec(`
			UPDATE iga_relationship
			   SET state = ?, valid_to = ?, ended_reason = ?
			 WHERE workspace_id = ? AND relationship_type = ? AND state <> ?
			   AND source_workload_id IN (`+retired+`)`,
			models.RelEnded, at, reason, ws, models.RelTypeExecutesAs, models.RelEnded,
			ws, models.ProviderK8s, models.IGALifecycleRetired).Error; err != nil {
			return fmt.Errorf("cascade executes_as from %s: %w", table, err)
		}
		return nil
	}

	// Which edge column points at this node class.
	var assignCol, edgeCol string
	switch supportCol {
	case "identity_account_id":
		assignCol, edgeCol = "holder_identity_account_id", "subject_identity_account_id"
	case "policy_id":
		assignCol, edgeCol = "policy_id", ""
	case "entitlement_id":
		assignCol, edgeCol = "", "entitlement_id"
	}

	if assignCol != "" {
		if err := tx.Exec(`
			UPDATE iga_policy_assignment
			   SET state = ?, valid_to = ?, ended_reason = ?
			 WHERE workspace_id = ? AND state <> ?
			   AND `+assignCol+` IN (`+retired+`)`,
			models.RelEnded, at, reason, ws, models.RelEnded,
			ws, models.ProviderK8s, models.IGALifecycleRetired).Error; err != nil {
			return fmt.Errorf("cascade assignments from %s: %w", table, err)
		}

		// A grant hangs off its assignment, so ending the assignment must end
		// the grant too -- otherwise the path survives its own authorization.
		if err := tx.Exec(`
			UPDATE iga_access_edges
			   SET state = ?, valid_to = ?, ended_reason = ?
			 WHERE workspace_id = ? AND provider = ? AND state <> ?
			   AND assignment_id IN (
			         SELECT id FROM iga_policy_assignment
			          WHERE workspace_id = ? AND state = ?)`,
			models.RelEnded, at, reason, ws, models.ProviderK8s, models.RelEnded,
			ws, models.RelEnded).Error; err != nil {
			return fmt.Errorf("cascade grants via assignment from %s: %w", table, err)
		}
	}

	if edgeCol != "" {
		if err := tx.Exec(`
			UPDATE iga_access_edges
			   SET state = ?, valid_to = ?, ended_reason = ?
			 WHERE workspace_id = ? AND provider = ? AND state <> ?
			   AND `+edgeCol+` IN (`+retired+`)`,
			models.RelEnded, at, reason, ws, models.ProviderK8s, models.RelEnded,
			ws, models.ProviderK8s, models.IGALifecycleRetired).Error; err != nil {
			return fmt.Errorf("cascade grants from %s: %w", table, err)
		}
	}
	return nil
}
