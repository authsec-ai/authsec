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
//
// THE FENCE. A sweep reads the cluster over a span of time, and sightings keep
// arriving while it does. A support row or relationship confirmed AFTER the
// sweep started (a sighting projected while the sweep ran) is newer evidence
// than anything the sweep holds, so the sweep may neither end it nor mark it
// stale: only rows last confirmed before the sweep's sweep_started_at are
// candidates. Read from the sweep row, never from the caller, so it is the
// value the sweep was recorded with. An agent clock that runs backwards can
// only make the fence keep a row one sweep longer, never end one early.
func (rc *Reconciler) Reconcile(tx *gorm.DB, in ReconcileInput) (*ReconcileResult, error) {
	at := rc.now()
	res := &ReconcileResult{}

	var sweep struct{ SweepStartedAt time.Time }
	if err := tx.Table("iga_k8s_sweep").Select("sweep_started_at").
		Where("workspace_id = ? AND id = ?", in.WorkspaceID, in.SweepID).
		Take(&sweep).Error; err != nil {
		return nil, fmt.Errorf("read sweep %s: %w", in.SweepID, err)
	}
	started := sweep.SweepStartedAt

	for _, part := range Partitions(in.Scope) {
		closing := in.Scope.CanEnd(part)
		if closing {
			res.PartitionsClosed++
		} else {
			res.PartitionsStale++
		}

		if part.Target != "" {
			n, err := rc.reconcileEdges(tx, in, part, closing, at, started)
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

		n, err := rc.reconcileSupport(tx, in, part, closing, started)
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

// confirmedBefore is the fence predicate: the row was last confirmed before
// the sweep started, or never. NULL counts as before -- a row nothing has
// confirmed (a pre-041 row, an adopted one) is exactly the row most in need of
// reconciling.
const confirmedBefore = "(last_confirmed_at IS NULL OR last_confirmed_at < ?)"

// reconcileSupport -- STEP 1: end this partition's SUPPORT, never the object.
//
// A node touched here may still be held by another source: a second cluster, or
// a second agent watching this one (§2.10B). Ending the object here would make
// one agent's blindness delete what another can plainly see.
func (rc *Reconciler) reconcileSupport(tx *gorm.DB, in ReconcileInput, part Partition,
	closing bool, started time.Time) (int, error) {
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
		Where("last_confirmed_sweep_id IS DISTINCT FROM ?", in.SweepID).
		Where(confirmedBefore, started)

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
func (rc *Reconciler) reconcileEdges(tx *gorm.DB, in ReconcileInput, part Partition,
	closing bool, at, started time.Time) (int, error) {
	switch part.Target {
	case TargetExecutesAs:
		return rc.reconcileRelationships(tx, in, part, models.RelTypeExecutesAs, closing, at, started)
	case TargetMemberOf:
		return rc.reconcileRelationships(tx, in, part, models.RelTypeMemberOf, closing, at, started)
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
		Where("last_confirmed_sweep_id IS DISTINCT FROM ?", in.SweepID).
		Where(confirmedBefore, started)

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

// reconcileRelationships closes the iga_relationship rows of one partition the
// sweep did not reconfirm: workload -> identity (executes_as) or
// ServiceAccount -> implicit group (member_of).
//
// iga_relationship has no discovery_source_id or last_confirmed_sweep_id (its
// provenance columns are AWS's connector_id and last_confirmed_by), so "this
// sweep confirmed it" is read from last_confirmed_at, which the writer stamps
// with the very instant this pass runs at. The source and cluster are still
// fenced: both are part of the partition key. IS DISTINCT FROM rather than <
// for "this sweep confirmed it", and the sweep-start fence on top, so a row a
// sighting confirmed while the sweep ran survives it.
func (rc *Reconciler) reconcileRelationships(tx *gorm.DB, in ReconcileInput, part Partition,
	relType string, closing bool, at, started time.Time) (int, error) {
	q := tx.Model(&models.IGARelationship{}).
		Where("workspace_id = ? AND partition_key = ? AND relationship_type = ?",
			in.WorkspaceID, part.Key(), relType).
		Where("state <> ?", models.RelEnded).
		Where("last_confirmed_at IS DISTINCT FROM ?", at).
		Where(confirmedBefore, started)

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

// nodeTables are the four node tables a Kubernetes sweep owns, with the
// support column that points at them and the reason an edge carries when they
// go.
var nodeTables = []struct {
	table      string
	supportCol string
	endReason  string
}{
	{"iga_identity_accounts", "identity_account_id", models.EndedSubjectRetired},
	{"iga_policy", "policy_id", models.EndedPolicyRetired},
	{"iga_entitlements", "entitlement_id", models.EndedStatementRetired},
	{"iga_workload", "workload_id", models.EndedSubjectRetired},
}

// retireUnsupported -- STEP 2: derive each object's lifecycle from what support
// REMAINS, then cascade what depends on it, in the same transaction.
//
//	retired     ends                                         ended_reason
//	identity    its assignments, grants and relationships    subject_retired
//	policy      its assignments, and their grants            policy_retired
//	statement   its grants                                   statement_retired
//	workload    its executes_as edges                        subject_retired
//
// "What remains" is the whole point: an object retires only when NO source
// still supports it. One agent going blind marks its own support stale and
// changes nothing else.
//
// SCOPED TO THIS SWEEP'S CLUSTER AND SOURCE. A candidate is an object this
// source supported in one of THIS sweep's partitions -- which name the source
// and the cluster. Retiring "every k8s object in the workspace with no live
// support" instead let one cluster's sweep retire another cluster's objects
// whenever those had no support: rows projected from an unattributed snapshot,
// or rows whose source was removed. Such rows are this sweep's business only
// once its own cluster's sweep has adopted them (see the service).
func (rc *Reconciler) retireUnsupported(tx *gorm.DB, in ReconcileInput, at time.Time) (int, error) {
	ws := in.WorkspaceID
	total := 0

	parts := Partitions(in.Scope)
	keys := make([]string, 0, len(parts))
	for _, p := range parts {
		if p.Target == "" {
			keys = append(keys, p.Key())
		}
	}
	if len(keys) == 0 {
		return 0, nil
	}

	for _, t := range nodeTables {
		// NOT EXISTS over non-ended support is the multi-source rule (§2.10B)
		// stated once, in SQL, rather than counted in Go where a miscount
		// deletes a customer's graph.
		r := tx.Exec(`
			UPDATE `+t.table+` o
			   SET lifecycle = ?, retired_reason = ?
			 WHERE o.workspace_id = ?
			   AND o.provider = ?
			   AND o.lifecycle = ?
			   AND EXISTS (
			         SELECT 1 FROM iga_object_support s
			          WHERE s.workspace_id = o.workspace_id
			            AND s.`+t.supportCol+` = o.id
			            AND s.discovery_source_id = ?
			            AND s.partition_key IN ?)
			   AND NOT EXISTS (
			         SELECT 1 FROM iga_object_support s
			          WHERE s.workspace_id = o.workspace_id
			            AND s.`+t.supportCol+` = o.id
			            AND s.state <> ?)`,
			models.IGALifecycleRetired, models.RetiredUnsupported,
			ws, models.ProviderK8s, models.IGALifecycleActive,
			in.Scope.SourceID, keys, models.RelEnded)
		if r.Error != nil {
			return total, fmt.Errorf("retire %s: %w", t.table, r.Error)
		}
		total += int(r.RowsAffected)

		if err := rc.cascade(tx, ws, ClusterPrefix(in.Scope.Cluster), t.table, t.supportCol,
			t.endReason, at); err != nil {
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
//
// clusterPrefix narrows the retired set, and every edge ended, to one cluster's
// keys (ClusterPrefix). Only the removal of a whole source, which may span
// clusters, passes the provider prefix alone.
func (rc *Reconciler) cascade(tx *gorm.DB, ws uuid.UUID, clusterPrefix, table, supportCol,
	reason string, at time.Time) error {
	retired := `SELECT id FROM ` + table + `
	             WHERE workspace_id = ? AND provider = ? AND lifecycle = ?
	               AND left(source_key, ?) = ?`
	retiredArgs := []any{ws, models.ProviderK8s, models.IGALifecycleRetired,
		len([]rune(clusterPrefix)), clusterPrefix}
	// The same narrowing for the edge being ended.
	edgeScope := `left(source_key, ?) = ?`
	edgeArgs := []any{len([]rune(clusterPrefix)), clusterPrefix}

	args := func(head []any, tail ...[]any) []any {
		out := append([]any{}, head...)
		for _, t := range tail {
			out = append(out, t...)
		}
		return out
	}

	// A retired workload no longer runs as anything. Its executes_as edges are
	// the only edges hanging off it, and they live in iga_relationship.
	if supportCol == "workload_id" {
		if err := tx.Exec(`
			UPDATE iga_relationship
			   SET state = ?, valid_to = ?, ended_reason = ?
			 WHERE workspace_id = ? AND relationship_type = ? AND state <> ?
			   AND source_workload_id IN (`+retired+`)`,
			args([]any{models.RelEnded, at, reason, ws, models.RelTypeExecutesAs, models.RelEnded},
				retiredArgs)...).Error; err != nil {
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

	if supportCol == "identity_account_id" {
		// An identity's relationships go with it, from either end: its
		// memberships (as member or as group), and any workload's claim to run
		// as it -- a workload cannot execute as an identity that is gone.
		if err := tx.Exec(`
			UPDATE iga_relationship
			   SET state = ?, valid_to = ?, ended_reason = ?
			 WHERE workspace_id = ? AND state <> ?
			   AND relationship_type IN ?
			   AND (source_identity_account_id IN (`+retired+`)
			     OR target_identity_account_id IN (`+retired+`))`,
			args([]any{models.RelEnded, at, reason, ws, models.RelEnded,
				[]string{models.RelTypeMemberOf, models.RelTypeExecutesAs}},
				retiredArgs, retiredArgs)...).Error; err != nil {
			return fmt.Errorf("cascade relationships from %s: %w", table, err)
		}
	}

	if assignCol != "" {
		if err := tx.Exec(`
			UPDATE iga_policy_assignment
			   SET state = ?, valid_to = ?, ended_reason = ?
			 WHERE workspace_id = ? AND state <> ?
			   AND `+assignCol+` IN (`+retired+`)`,
			args([]any{models.RelEnded, at, reason, ws, models.RelEnded}, retiredArgs)...).Error; err != nil {
			return fmt.Errorf("cascade assignments from %s: %w", table, err)
		}

		// A grant hangs off its assignment, so ending the assignment must end
		// the grant too -- otherwise the path survives its own authorization.
		//
		// Driven from THIS cluster's live grants, looking each one's assignment
		// up by id -- never from "every ended assignment of the workspace". The
		// old IN (SELECT id ... WHERE state = 'ended') read every ended
		// assignment of every provider (AWS keeps its history there too) twice
		// per sweep, to find the few this cluster's grants point at. The
		// scalar subquery is deliberately not an IN/EXISTS: Postgres does not
		// flatten it into a join, so it is always one probe of the (workspace_id,
		// id) unique index per candidate grant, whatever the planner thinks of
		// the table's size. Semantics are unchanged: a grant of this cluster
		// whose assignment exists and is ended is ended; the assignment is
		// additionally required to be a Kubernetes binding of the same cluster,
		// which every assignment a Kubernetes grant points at is (the projector
		// resolves it by this cluster's binding key).
		if err := tx.Exec(`
			UPDATE iga_access_edges e
			   SET state = ?, valid_to = ?, ended_reason = ?
			 WHERE e.workspace_id = ? AND e.provider = ? AND e.state <> ?
			   AND `+edgeScope+`
			   AND e.assignment_id IS NOT NULL
			   AND (SELECT a.state FROM iga_policy_assignment a
			         WHERE a.workspace_id = e.workspace_id AND a.id = e.assignment_id
			           AND a.assignment_kind IN ?
			           AND left(a.source_key, ?) = ?) = ?`,
			args([]any{models.RelEnded, at, reason, ws, models.ProviderK8s, models.RelEnded},
				edgeArgs, []any{K8sAssignmentKinds}, edgeArgs, []any{models.RelEnded})...).Error; err != nil {
			return fmt.Errorf("cascade grants via assignment from %s: %w", table, err)
		}
	}

	if edgeCol != "" {
		if err := tx.Exec(`
			UPDATE iga_access_edges
			   SET state = ?, valid_to = ?, ended_reason = ?
			 WHERE workspace_id = ? AND provider = ? AND state <> ?
			   AND `+edgeCol+` IN (`+retired+`)`,
			args([]any{models.RelEnded, at, reason, ws, models.ProviderK8s, models.RelEnded},
				retiredArgs)...).Error; err != nil {
			return fmt.Errorf("cascade grants from %s: %w", table, err)
		}
	}
	return nil
}

// RetireSource withdraws everything one discovery source vouched for, because
// the source (the connection) is being removed. It runs in the caller's
// transaction, BEFORE the source row is deleted: the foreign keys cascade-delete
// the source's support rows, sweeps, assignments and grants, and after that
// nothing is left to tell which objects it supported.
//
// Without this the objects outlive their only evidence: no support row names
// them any more, so no sweep's reconciliation ever reaches them, and they stay
// active -- hidden from every view that joins support, and counted by every
// one that does not.
//
//   - Its support ends (connection_removed).
//   - Every Kubernetes object it supported that no OTHER source still supports
//     is retired (connection_removed), and the edges hanging off it end by the
//     usual cascade.
//   - Its own claims -- assignments, grants, and the relationships in its
//     partitions -- end (connection_removed) and are detached from the source,
//     so the delete keeps them as history instead of erasing them.
//
// Returns how many objects were retired.
func RetireSource(tx *gorm.DB, workspaceID, sourceID uuid.UUID, at time.Time) (int, error) {
	ws := workspaceID
	retired := 0

	// Which objects this source supported, captured before its support ends.
	for _, t := range nodeTables {
		r := tx.Exec(`
			UPDATE `+t.table+` o
			   SET lifecycle = ?, retired_reason = ?
			 WHERE o.workspace_id = ?
			   AND o.provider = ?
			   AND o.lifecycle = ?
			   AND EXISTS (
			         SELECT 1 FROM iga_object_support s
			          WHERE s.workspace_id = o.workspace_id
			            AND s.`+t.supportCol+` = o.id
			            AND s.discovery_source_id = ?)
			   AND NOT EXISTS (
			         SELECT 1 FROM iga_object_support s
			          WHERE s.workspace_id = o.workspace_id
			            AND s.`+t.supportCol+` = o.id
			            AND s.state <> ?
			            AND s.discovery_source_id IS DISTINCT FROM ?)`,
			models.IGALifecycleRetired, models.RetiredConnectionRemoved,
			ws, models.ProviderK8s, models.IGALifecycleActive,
			sourceID, models.RelEnded, sourceID)
		if r.Error != nil {
			return retired, fmt.Errorf("retire %s: %w", t.table, r.Error)
		}
		retired += int(r.RowsAffected)
	}

	if err := tx.Exec(`
		UPDATE iga_object_support
		   SET state = ?, ended_reason = ?
		 WHERE workspace_id = ? AND discovery_source_id = ? AND state <> ?`,
		models.RelEnded, models.EndedConnectionRemoved, ws, sourceID, models.RelEnded).Error; err != nil {
		return retired, fmt.Errorf("end support: %w", err)
	}

	// The source's own claims end, then let go of the source so its delete
	// does not take them with it.
	for _, table := range []string{"iga_policy_assignment", "iga_access_edges"} {
		if err := tx.Exec(`
			UPDATE `+table+`
			   SET state = ?, valid_to = ?, ended_reason = ?
			 WHERE workspace_id = ? AND discovery_source_id = ? AND state <> ?`,
			models.RelEnded, at, models.EndedConnectionRemoved, ws, sourceID, models.RelEnded).Error; err != nil {
			return retired, fmt.Errorf("end %s: %w", table, err)
		}
		if err := tx.Exec(`
			UPDATE `+table+`
			   SET discovery_source_id = NULL, last_confirmed_sweep_id = NULL
			 WHERE workspace_id = ? AND discovery_source_id = ?`,
			ws, sourceID).Error; err != nil {
			return retired, fmt.Errorf("detach %s: %w", table, err)
		}
	}
	// Relationships carry the source only in their partition key.
	if err := tx.Exec(`
		UPDATE iga_relationship
		   SET state = ?, valid_to = ?, ended_reason = ?
		 WHERE workspace_id = ? AND state <> ? AND relationship_type IN ?
		   AND partition_key LIKE ?`,
		models.RelEnded, at, models.EndedConnectionRemoved, ws, models.RelEnded,
		[]string{models.RelTypeExecutesAs, models.RelTypeMemberOf},
		sourceID.String()+"|%").Error; err != nil {
		return retired, fmt.Errorf("end relationships: %w", err)
	}

	// Whatever still hangs off a retired object ends with it.
	rc := NewReconciler(func() time.Time { return at })
	for _, t := range nodeTables {
		if err := rc.cascade(tx, ws, models.ProviderK8s+Sep, t.table, t.supportCol,
			t.endReason, at); err != nil {
			return retired, err
		}
	}
	return retired, nil
}

// K8sAssignmentKinds are the assignment kinds a Kubernetes sweep writes:
// iga_policy_assignment has no provider column, and these are how the schema
// itself tells a Kubernetes binding from an AWS attachment
// (iga_pa_confirm_provider_chk).
var K8sAssignmentKinds = []string{models.K8sAssignmentRoleBinding, models.K8sAssignmentClusterRoleBinding}
