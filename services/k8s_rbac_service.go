package services

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/k8sgraph"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

/*
Kubernetes RBAC → the shared IGA graph.

The in-cluster agent posts a whole snapshot of the cluster's authorization
model; this projects it into iga_* under provider 'k8s', alongside the GitHub
and AWS rows already there. The model is provider-neutral by design (SPEC §1.5,
which names Kubernetes), so this adds no tables — only rows and one widened
CHECK.

WHOLE SNAPSHOT, NOT DELTAS, for the same reason the enforcement plan is whole: a
missed delta leaves the graph describing access that changed, silently, and
nothing downstream can tell. A snapshot is self-correcting on the next sweep.

NOTHING IS RETIRED FROM AN INCOMPLETE SNAPSHOT. One transient 403 during a sweep
would otherwise delete a cluster's entire authorization model and restore it six
hours later, with a governance alert in between and a reviewer chasing a change
that never happened.
*/

// K8sRBACManager ingests RBAC snapshots and projects them into the graph.
type K8sRBACManager interface {
	// Ingest projects one snapshot. Returns what it wrote.
	Ingest(workspaceID uuid.UUID, snap models.K8sRBACSnapshot) (*K8sRBACResult, error)
}

// K8sRBACResult reports one ingest.
type K8sRBACResult struct {
	Cluster string `json:"cluster"`
	// Accepted is false when the snapshot was rejected outright — the only case
	// being a snapshot that names no cluster, which cannot be attributed.
	Accepted bool `json:"accepted"`

	Identities  int `json:"identities"`
	Policies    int `json:"policies"`
	Statements  int `json:"statements"`
	Assignments int `json:"assignments"`
	Edges       int `json:"edges"`

	// Complete and ClusterScoped echo what the agent reported, because every
	// consumer of this data has to know how much of the cluster it describes.
	Complete      bool `json:"complete"`
	ClusterScoped bool `json:"cluster_scoped"`

	// Unresolved counts bindings whose role was not in the snapshot. On a
	// complete sweep that means a dangling reference in the cluster; on a
	// partial one it is the visible edge of what was missed.
	Unresolved int `json:"unresolved"`

	// Retired is how many previously-seen rows were marked gone. Always 0 for an
	// incomplete snapshot.
	Retired int `json:"retired"`

	// Reconciled says whether absence was acted on at all, and Reason says why
	// not. Mirrors ManifestResult: a sweep that retired nothing because it was
	// incomplete and a sweep that retired nothing because nothing was gone are
	// the same number and opposite facts, and an operator needs to tell them
	// apart without reading the code.
	Reconciled bool   `json:"reconciled"`
	Reason     string `json:"reason,omitempty"`

	// Generation is the sweep's fencing token, echoed so the agent's logs and
	// the sweep row agree.
	Generation int64 `json:"generation,omitempty"`

	Stale int `json:"stale"`

	// Workloads and ExecutesAs are the runtime half: which Pods run as these
	// identities. Projected from the discovered-agent inventory, not from the
	// RBAC sweep, which never lists a Pod.
	Workloads  int `json:"workloads"`
	ExecutesAs int `json:"executes_as"`
	// Unanchored counts workloads whose ServiceAccount could not be resolved.
	// A gap in the answer, reported rather than rendered as "no access".
	Unanchored int `json:"unanchored"`
}

// sweepRef is one accepted sweep's authority to write and to close rows.
type sweepRef struct {
	SourceID uuid.UUID
	SweepID  uuid.UUID
	Scope    k8sgraph.Scope
}

type k8sRBACManager struct {
	db   *gorm.DB
	gate *GraphProjectionGate
}

// NewK8sRBACManager builds the manager.
func NewK8sRBACManager(db *gorm.DB, gate *GraphProjectionGate) K8sRBACManager {
	return &k8sRBACManager{db: db, gate: gate}
}

func (m *k8sRBACManager) Ingest(workspaceID uuid.UUID,
	snap models.K8sRBACSnapshot) (*K8sRBACResult, error) {

	cluster := strings.TrimSpace(snap.Cluster)
	if cluster == "" {
		// Every key is namespaced by cluster. Without one, two clusters'
		// identically-named ServiceAccounts would merge into a single identity
		// and one cluster's access would be attributed to the other.
		return nil, errors.New("snapshot names no cluster; it cannot be attributed")
	}

	res := &K8sRBACResult{
		Cluster:       cluster,
		Accepted:      true,
		Complete:      snap.Complete,
		ClusterScoped: snap.ClusterScoped,
	}

	// The projection gate is the same switch the AWS pipeline uses. With it off
	// the snapshot is accepted and acknowledged but nothing is written — so an
	// agent enabled ahead of the control plane does not accumulate errors, and
	// turning the gate on later back-fills from the next sweep.
	if m.gate == nil || !m.gate.Enabled() {
		res.Accepted = false
		return res, nil
	}

	out := k8sgraph.Project(snap)
	res.Identities = len(out.Identities)
	res.Policies = len(out.Policies)
	res.Statements = len(out.Statements)
	res.Assignments = len(out.Assignments)
	res.Edges = len(out.Edges)
	res.Unresolved = len(out.Unresolved)

	observed := parseSnapshotTime(snap.ObservedAt)

	// ONE TRANSACTION for the whole snapshot. A half-projected cluster is worse
	// than an unprojected one: an assignment whose policy landed but whose edges
	// did not would read as a grant of nothing, which is a confident wrong
	// answer rather than a visible gap.
	// The sweep is what gives this snapshot the authority to CLOSE rows. Without
	// a resolvable discovery source there is no evidence stream to attribute the
	// reading to, so the snapshot is still projected -- new access is still worth
	// recording -- but nothing may be retired from it, and the result says so
	// rather than reporting a quiet zero.
	sourceID := m.resolveSource(workspaceID, snap, cluster)
	if sourceID == uuid.Nil {
		res.Reason = "snapshot could not be attributed to a discovery source, so absence " +
			"is not evidence of deletion; rows were projected but none retired"
	}

	err := m.db.Transaction(func(tx *gorm.DB) error {
		var ref *sweepRef
		if sourceID != uuid.Nil {
			r, err := m.openSweep(tx, workspaceID, sourceID, cluster, snap, observed)
			if err != nil {
				return fmt.Errorf("open sweep: %w", err)
			}
			ref = r
			res.Generation = r.Scope.Generation
		}

		if err := m.upsertIdentities(tx, workspaceID, out.Identities, observed); err != nil {
			return fmt.Errorf("identities: %w", err)
		}
		if err := m.upsertPolicies(tx, workspaceID, out.Policies, observed); err != nil {
			return fmt.Errorf("policies: %w", err)
		}

		// The nodes are in; resolve their ids so the edges can reference them.
		// Read back rather than remember what we just wrote: an upsert that
		// collided with an existing row returns that row's id, and assuming our
		// generated one would attach every edge to a node that does not exist.
		//
		// Policies first: a statement names the role that declares it
		// (policy_id), so the role's id must be known before the rule is written.
		policyIDs, err := m.idsBySourceKey(tx, workspaceID, "iga_policy")
		if err != nil {
			return fmt.Errorf("resolve policy ids: %w", err)
		}
		if err := m.upsertStatements(tx, workspaceID, out.Statements, policyIDs, observed); err != nil {
			return fmt.Errorf("statements: %w", err)
		}
		identityIDs, err := m.idsBySourceKey(tx, workspaceID, "iga_identity_accounts")
		if err != nil {
			return fmt.Errorf("resolve identity ids: %w", err)
		}
		statementIDs, err := m.idsBySourceKey(tx, workspaceID, "iga_entitlements")
		if err != nil {
			return fmt.Errorf("resolve statement ids: %w", err)
		}

		assignmentIDs, err := m.upsertAssignments(tx, workspaceID, out.Assignments,
			policyIDs, identityIDs, observed, ref)
		if err != nil {
			return fmt.Errorf("assignments: %w", err)
		}
		if err := m.upsertEdges(tx, workspaceID, snap.Cluster, out.Edges, out.Assignments,
			identityIDs, statementIDs, assignmentIDs, observed, ref); err != nil {
			return fmt.Errorf("edges: %w", err)
		}

		// Workloads: who RUNS as these identities. The RBAC sweep never lists a
		// Pod, so this comes from the discovered-agent inventory and joins on
		// the anchor both sides already spell identically.
		sight, err := m.loadSightings(tx, workspaceID, cluster)
		if err != nil {
			return fmt.Errorf("load sightings: %w", err)
		}
		wres := k8sgraph.ProjectWorkloads(cluster, sight)
		workloadIDs, n, err := m.upsertWorkloads(tx, workspaceID, wres, identityIDs, observed, ref)
		if err != nil {
			return fmt.Errorf("workloads: %w", err)
		}
		res.Workloads = len(wres.Workloads)
		res.ExecutesAs = n
		res.Unanchored = len(wres.Unanchored)

		if ref == nil {
			return nil
		}

		// Support rows are what make a node visible to reconciliation. A node
		// written without one is never reconciled -- it simply lives forever,
		// which is the defect this whole path exists to close.
		if err := m.upsertSupport(tx, workspaceID, ref, out, wres,
			identityIDs, policyIDs, statementIDs, workloadIDs, observed); err != nil {
			return fmt.Errorf("support: %w", err)
		}
		if err := m.adoptUnreconciled(tx, workspaceID, cluster, ref, observed); err != nil {
			return fmt.Errorf("adopt unreconciled rows: %w", err)
		}

		rr, err := k8sgraph.NewReconciler(func() time.Time { return observed }).
			Reconcile(tx, k8sgraph.ReconcileInput{
				WorkspaceID: workspaceID, SweepID: ref.SweepID, Scope: ref.Scope,
			})
		if err != nil {
			return fmt.Errorf("reconcile: %w", err)
		}
		res.Reconciled = true
		res.Retired = rr.ObjectsRetired
		res.Stale = rr.SupportStale + rr.EdgesStale
		if !snap.Complete {
			res.Reason = "sweep was incomplete, so absence is not evidence of deletion; " +
				"what could not be confirmed was marked stale, not ended"
		} else if !snap.ClusterScoped {
			res.Reason = "sweep could not read cluster-scoped objects, so ClusterRoles and " +
				"ClusterRoleBindings were marked stale rather than retired"
		}

		// The sweep is only 'projected' once its rows and its retirements are
		// both in. A failed transaction leaves it 'received', which is the
		// honest record that a reading arrived and was never applied.
		return tx.Model(&models.IGAK8sSweep{}).
			Where("workspace_id = ? AND id = ?", workspaceID, ref.SweepID).
			Updates(map[string]any{
				"status":       models.K8sSweepProjected,
				"projected_at": observed,
			}).Error
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// resolveSource finds the evidence stream this snapshot belongs to.
//
// Returns uuid.Nil rather than an error: a snapshot that cannot be attributed
// is still worth projecting, it simply may not retire anything. Failing the
// whole ingest would throw away the new access it reports as well.
func (m *k8sRBACManager) resolveSource(workspaceID uuid.UUID,
	snap models.K8sRBACSnapshot, cluster string) uuid.UUID {

	if id, err := uuid.Parse(strings.TrimSpace(snap.DiscoverySourceID)); err == nil {
		var n int64
		if m.db.Table("discovery_sources").
			Where("workspace_id = ? AND id = ?", workspaceID, id).
			Count(&n).Error == nil && n == 1 {
			return id
		}
	}
	// Fall back to the cluster name. The agent registers its source before it
	// ever sweeps, so this resolves for every normally-deployed agent whose
	// payload simply predates the discovery_source_id field.
	var row struct{ ID uuid.UUID }
	if err := m.db.Table("discovery_sources").Select("id").
		Where("workspace_id = ? AND cluster_name = ?", workspaceID, cluster).
		Order("created_at ASC").Limit(1).Scan(&row).Error; err != nil {
		return uuid.Nil
	}
	return row.ID
}

// openSweep records this reading and takes the next generation for the cluster.
//
// The generation is read and written inside the caller's transaction, so two
// snapshots arriving together cannot take the same one -- the unique index on
// (workspace, source, cluster, generation) makes the loser fail rather than
// silently share a fencing token with the winner.
func (m *k8sRBACManager) openSweep(tx *gorm.DB, workspaceID, sourceID uuid.UUID,
	cluster string, snap models.K8sRBACSnapshot, observed time.Time) (*sweepRef, error) {

	var last int64
	if err := tx.Table("iga_k8s_sweep").
		Select("COALESCE(MAX(generation), 0)").
		Where("workspace_id = ? AND discovery_source_id = ? AND cluster = ?",
			workspaceID, sourceID, cluster).
		Scan(&last).Error; err != nil {
		return nil, err
	}

	started := observed
	if t := parseSnapshotTime(snap.SweepStartedAt); !t.IsZero() {
		started = t
	}

	row := &models.IGAK8sSweep{
		ID:                uuid.New(),
		WorkspaceID:       workspaceID,
		DiscoverySourceID: sourceID,
		Cluster:           cluster,
		Generation:        last + 1,
		ScanKind:          defaultString(snap.ScanKind, "rbac"),
		Complete:          snap.Complete,
		ClusterScoped:     snap.ClusterScoped,
		Namespaces:        snap.Namespaces,
		SweepStartedAt:    started,
		ObservedAt:        observed,
		Status:            models.K8sSweepReceived,
	}
	if err := tx.Create(row).Error; err != nil {
		return nil, err
	}
	return &sweepRef{
		SourceID: sourceID,
		SweepID:  row.ID,
		Scope:    k8sgraph.ScopeOf(snap, sourceID, row.Generation),
	}, nil
}

// idsBySourceKey maps every live source_key in a graph table to its row id.
//
// Scoped to this provider: another provider's keys cannot collide with ours
// (every k8s key starts "k8s␟"), but reading the whole workspace would load
// every AWS row on every Kubernetes sweep for nothing.
//
// LIVE means not retired. A key deleted and recreated has a retired row and a
// live one; reading both into one map let whichever came back last win, and a
// retired id attaches this sweep's edges and support to an object that is gone.
func (m *k8sRBACManager) idsBySourceKey(tx *gorm.DB, workspaceID uuid.UUID,
	table string) (map[string]uuid.UUID, error) {

	var rows []struct {
		ID        uuid.UUID
		SourceKey string
	}
	if err := tx.Table(table).
		Select("id, source_key").
		Where("workspace_id = ? AND provider = ? AND lifecycle <> ?",
			workspaceID, models.ProviderK8s, models.IGALifecycleRetired).
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]uuid.UUID, len(rows))
	for _, r := range rows {
		out[r.SourceKey] = r.ID
	}
	return out, nil
}

// upsertAssignments writes binding→holder rows and returns their ids by source
// key, so the edges can point at them.
//
// An assignment whose policy or holder did not resolve is SKIPPED rather than
// written with a null: both columns are NOT NULL, so the alternative is a failed
// transaction that loses the whole snapshot over one dangling reference. The
// edge for that binding still lands, as partial — which is the honest record
// that something was bound to something we could not see.
func (m *k8sRBACManager) upsertAssignments(tx *gorm.DB, workspaceID uuid.UUID,
	as []k8sgraph.Assignment, policyIDs, identityIDs map[string]uuid.UUID,
	observed time.Time, ref *sweepRef) (map[string]uuid.UUID, error) {

	out := make(map[string]uuid.UUID, len(as))
	for i := range as {
		a := as[i]
		policyID, okP := policyIDs[a.PolicyKey]
		holderID, okH := identityIDs[a.HolderKey]
		if !okP || !okH {
			continue
		}
		row := map[string]any{
			"id":                         uuid.New(),
			"workspace_id":               workspaceID,
			"policy_id":                  policyID,
			"holder_identity_account_id": holderID,
			"assignment_kind":            a.Kind,
			// A RoleBinding is configuration we READ, not something we were told
			// about — but 'declared' is the only non-asserted value this column
			// allows, and a binding IS a declaration in the cluster's own terms.
			"basis":             "declared",
			"state":             "current",
			"valid_from":        observed,
			"last_confirmed_at": observed,
			"source_key":        a.SourceKey,
			// The partition this binding belongs to, spelled by the same code
			// the reconciler uses. A bare namespace here -- which is what this
			// was -- means no retirement query ever matches the row, so the
			// binding lives forever however carefully the sweep looked.
			"partition_key": partitionKeyFor(ref, a.Namespace, k8sgraph.TargetAssignment),
		}
		update := map[string]any{
			"policy_id":                  policyID,
			"holder_identity_account_id": holderID,
			"assignment_kind":            a.Kind,
			"last_confirmed_at":          observed,
			"state":                      "current",
		}
		if ref != nil {
			row["discovery_source_id"] = ref.SourceID
			row["last_confirmed_sweep_id"] = ref.SweepID
			update["discovery_source_id"] = ref.SourceID
			update["last_confirmed_sweep_id"] = ref.SweepID
		}
		if err := tx.Table("iga_policy_assignment").
			Clauses(conflictOn(liveAssignment, update)).Create(row).Error; err != nil {
			return nil, err
		}
		out[a.SourceKey] = row["id"].(uuid.UUID)
	}

	// Read back for the same reason as the nodes: a conflicting upsert kept the
	// existing row's id, not the one we generated.
	live, err := m.assignmentIDs(tx, workspaceID)
	if err != nil {
		return nil, err
	}
	for k, v := range live {
		out[k] = v
	}
	return out, nil
}

// assignmentIDs maps live assignment source keys to ids. iga_policy_assignment
// has no provider column of its own, so it is narrowed by the key prefix every
// Kubernetes key carries.
func (m *k8sRBACManager) assignmentIDs(tx *gorm.DB,
	workspaceID uuid.UUID) (map[string]uuid.UUID, error) {

	var rows []struct {
		ID        uuid.UUID
		SourceKey string
	}
	if err := tx.Table("iga_policy_assignment").
		Select("id, source_key").
		Where("workspace_id = ? AND source_key LIKE ?", workspaceID,
			models.ProviderK8s+k8sgraph.Sep+"%").
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]uuid.UUID, len(rows))
	for _, r := range rows {
		out[r.SourceKey] = r.ID
	}
	return out, nil
}

// upsertEdges writes the subject→statement grants.
//
// THE HONESTY COLUMNS ARE NOT DECORATION. calculation_state and
// effective_conclusion are enforced against each other by
// iga_access_edges_honesty_chk: a conclusion may only be drawn from a complete
// calculation. The projector already decided both; this writes them unchanged
// rather than upgrading a partial edge to look resolved.
func (m *k8sRBACManager) upsertEdges(tx *gorm.DB, workspaceID uuid.UUID, cluster string,
	edges []k8sgraph.Edge, assignments []k8sgraph.Assignment,
	identityIDs, statementIDs, assignmentIDs map[string]uuid.UUID,
	observed time.Time, ref *sweepRef) error {

	// A grant is owned by the partition of the BINDING that produced it, not of
	// the role it points at: a RoleBinding in one namespace may reference a
	// cluster-wide ClusterRole, and it is the binding that disappears when that
	// namespace is swept.
	ns := make(map[string]string, len(assignments))
	for _, a := range assignments {
		ns[a.SourceKey] = a.Namespace
	}

	for i := range edges {
		e := edges[i]
		subjectID, ok := identityIDs[e.SubjectKey]
		if !ok {
			// No subject means no edge worth writing: an access edge whose holder
			// is unknown names nobody.
			continue
		}

		row := map[string]any{
			"id":           uuid.New(),
			"workspace_id": workspaceID,
			// All three must agree — iga_access_edges_subject_agree_chk requires
			// subject_kind 'identity_account' and subject_id equal to the typed
			// column whenever the typed one is set.
			"subject_kind":                "identity_account",
			"subject_id":                  subjectID,
			"subject_identity_account_id": subjectID,
			"provider":                    models.ProviderK8s,
			// Outbound: this subject reaches that permission. Kubernetes RBAC has
			// no inbound direction — nothing grants access TO a ServiceAccount.
			"direction": "outbound",
			"path_kind": "k8s_rbac",
			// Read from the cluster, not declared to us.
			"basis":                "observed",
			"calculation_state":    e.CalculationState,
			"effective_conclusion": e.EffectiveConclusion,
			"native_scope":         cluster,
			"state":                "current",
			"valid_from":           observed,
			"last_confirmed_at":    observed,
			"observed_at":          observed,
			"source_key":           e.SourceKey,
			"partition_key":        partitionKeyFor(ref, ns[e.AssignmentKey], k8sgraph.TargetAccessEdge),
			"created_at":           observed,
			"updated_at":           observed,
		}
		if id, ok := statementIDs[e.StatementKey]; ok && e.StatementKey != "" {
			row["entitlement_id"] = id
		}
		if id, ok := assignmentIDs[e.AssignmentKey]; ok {
			row["assignment_id"] = id
		}

		update := map[string]any{
			"calculation_state":    e.CalculationState,
			"effective_conclusion": e.EffectiveConclusion,
			"last_confirmed_at":    observed,
			"observed_at":          observed,
			"state":                "current",
			"updated_at":           observed,
		}
		if ref != nil {
			row["discovery_source_id"] = ref.SourceID
			row["last_confirmed_sweep_id"] = ref.SweepID
			update["discovery_source_id"] = ref.SourceID
			update["last_confirmed_sweep_id"] = ref.SweepID
		}
		if err := tx.Table("iga_access_edges").
			Clauses(conflictOn(liveEdge, update)).Create(row).Error; err != nil {
			return err
		}
	}
	return nil
}

/* --------------------------------- upserts -------------------------------- */

// conflictOn builds an ON CONFLICT target for one of the graph tables.
//
// EVERY unique index on these tables is PARTIAL — `WHERE source_key <> ” AND
// lifecycle <> 'retired'`, or the state equivalent. Postgres will not infer a
// partial index from its columns alone, so the predicate has to be restated
// here or the upsert fails outright with "no unique or exclusion constraint
// matching the ON CONFLICT specification".
//
// The predicate is also load-bearing rather than ceremonial: it is what lets a
// retired row keep its source_key without blocking a live row from reclaiming
// it, which is how an identity deleted and recreated under the same name gets a
// new row instead of resurrecting the old one.
func conflictOn(predicate string, updates map[string]any) clause.OnConflict {
	return clause.OnConflict{
		Columns:     []clause.Column{{Name: "workspace_id"}, {Name: "source_key"}},
		TargetWhere: clause.Where{Exprs: []clause.Expression{gorm.Expr(predicate)}},
		DoUpdates:   clause.Assignments(updates),
	}
}

// The partial-index predicates, spelled once each so a table's upsert and its
// index cannot drift apart.
const (
	liveByLifecycle = "source_key <> '' AND lifecycle <> 'retired'"
	livePolicy      = "lifecycle <> 'retired'"
	liveAssignment  = "state <> 'ended'"
	liveEdge        = "source_key <> '' AND state <> 'ended'"
)

// upsertIdentities writes ServiceAccount, User and Group nodes.
//
// source_key is the conflict target, matching the partial unique index the graph
// tables carry (`WHERE lifecycle <> 'retired'`). continuity is
// 'recognition_only' for every Kubernetes node: a ServiceAccount has a UID, but
// a delete-and-recreate under the same name yields a NEW uid, and treating that
// as the same identity — or as a different one — are both claims we have not
// earned from a six-hourly snapshot. Recording the weaker, true claim is the
// house rule.
func (m *k8sRBACManager) upsertIdentities(tx *gorm.DB, workspaceID uuid.UUID,
	nodes []k8sgraph.Node, observed time.Time) error {

	for i := range nodes {
		n := nodes[i]
		attrs, err := jsonAttrs(n.Attrs)
		if err != nil {
			return err
		}
		row := map[string]any{
			"id":               uuid.New(),
			"workspace_id":     workspaceID,
			"display_name":     n.DisplayName,
			"account_kind":     n.Kind,
			"identity_backing": "provider",
			"lifecycle":        "active",
			"provider":         models.ProviderK8s,
			"source_key":       n.SourceKey,
			"continuity":       models.ContinuityRecognitionOnly,
			"provider_attrs":   attrs,
			"first_seen_at":    observed,
			"last_seen_at":     observed,
			"created_at":       observed,
			"updated_at":       observed,
		}
		if err := tx.Table("iga_identity_accounts").
			// first_seen_at is deliberately NOT updated: it is when we first saw
			// this identity, and overwriting it every sweep would erase the only
			// evidence of how long it has existed.
			Clauses(conflictOn(liveByLifecycle, map[string]any{
				"display_name":   n.DisplayName,
				"provider_attrs": attrs,
				"last_seen_at":   observed,
				"updated_at":     observed,
				"lifecycle":      "active",
			})).Create(row).Error; err != nil {
			return err
		}
	}
	return nil
}

// upsertPolicies writes Role and ClusterRole nodes.
func (m *k8sRBACManager) upsertPolicies(tx *gorm.DB, workspaceID uuid.UUID,
	nodes []k8sgraph.Node, observed time.Time) error {

	for i := range nodes {
		n := nodes[i]
		row := map[string]any{
			"id":            uuid.New(),
			"workspace_id":  workspaceID,
			"provider":      models.ProviderK8s,
			"policy_kind":   n.Kind,
			"display_name":  n.DisplayName,
			"native_ref":    n.SourceKey,
			"source_key":    n.SourceKey,
			"continuity":    models.ContinuityRecognitionOnly,
			"lifecycle":     "active",
			"first_seen_at": observed,
			"last_seen_at":  observed,
		}
		if err := tx.Table("iga_policy").
			Clauses(conflictOn(livePolicy, map[string]any{
				"display_name": n.DisplayName,
				"last_seen_at": observed,
				"lifecycle":    "active",
			})).Create(row).Error; err != nil {
			return err
		}
	}
	return nil
}

// upsertStatements writes one entitlement per PolicyRule.
//
// The verbs go into normalized_rights.verbs — the generic slot the model already
// carries — and the Kubernetes-shaped detail (apiGroups, resources,
// resourceNames) into native_rights, so nothing is lost and nothing is
// flattened into a vocabulary it does not fit.
//
// policy_id links the rule to the Role or ClusterRole that declares it, as the
// AWS statements are linked to theirs. A rule always arrives with its role, so
// the id resolves; were it ever missing, the column is left as it was rather
// than written null (no CHECK requires it for provider 'k8s').
func (m *k8sRBACManager) upsertStatements(tx *gorm.DB, workspaceID uuid.UUID,
	sts []k8sgraph.Statement, policyIDs map[string]uuid.UUID, observed time.Time) error {

	for i := range sts {
		s := sts[i]

		native, err := jsonAttrs(map[string]any{
			"api_groups":        s.APIGroups,
			"resources":         s.Resources,
			"resource_names":    s.ResourceNames,
			"non_resource_urls": s.NonResourceURLs,
			"verbs":             s.Verbs,
		})
		if err != nil {
			return err
		}
		normalized, err := jsonAttrs(map[string]any{
			"verbs": s.Verbs,
			// Constrained means the rule is narrowed to named instances, so it
			// grants far less than the same rule without them. The console ranks
			// on this, which is why it is computed here rather than inferred
			// from a string later.
			"constrained": len(s.ResourceNames) > 0,
			"wildcard":    s.Wildcard,
		})
		if err != nil {
			return err
		}

		row := map[string]any{
			"id":                uuid.New(),
			"workspace_id":      workspaceID,
			"native_grant_kind": "k8s_policy_rule",
			"native_rights":     native,
			"normalized_rights": normalized,
			"lifecycle":         "active",
			"provider":          models.ProviderK8s,
			"source_key":        s.StatementKey,
			"continuity":        models.ContinuityRecognitionOnly,
			"statement_key":     s.StatementKey,
			// Kubernetes RBAC is allow-only: there is no deny rule and no
			// condition. Recording that explicitly is what lets a reader trust an
			// observed grant rather than treating it as merely configured.
			"effect":        "allow",
			"negated":       false,
			"conditional":   false,
			"first_seen_at": observed,
			"last_seen_at":  observed,
			"created_at":    observed,
			"updated_at":    observed,
		}
		update := map[string]any{
			"native_rights":     native,
			"normalized_rights": normalized,
			"last_seen_at":      observed,
			"lifecycle":         "active",
			"updated_at":        observed,
		}
		if id, ok := policyIDs[s.PolicyKey]; ok {
			row["policy_id"] = id
			update["policy_id"] = id
		}
		if err := tx.Table("iga_entitlements").
			Clauses(conflictOn(liveByLifecycle, update)).Create(row).Error; err != nil {
			return err
		}
	}
	return nil
}

/* --------------------------------- helpers -------------------------------- */

func jsonAttrs(v map[string]any) ([]byte, error) {
	return marshalDiscoveryConfig(v)
}

// parseSnapshotTime reads the agent's timestamp, falling back to now.
//
// The agent's clock bounds what the snapshot proves, so it is preferred — but a
// skewed or missing one must not make the row unwritable.
//
// Truncated to the microsecond Postgres stores. The executes_as reconciler
// recognises "confirmed by this sweep" by last_confirmed_at EQUAL to this
// instant. The value written and the value compared pass through the same
// driver encoding today, so they agree anyway; truncating here makes that
// equality hold by construction rather than by the driver's rounding.
func parseSnapshotTime(s string) time.Time {
	if s == "" {
		return time.Now().UTC().Truncate(time.Microsecond)
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Now().UTC().Truncate(time.Microsecond)
	}
	return t.UTC().Truncate(time.Microsecond)
}

/* ------------------------------- support ---------------------------------- */

// partitionKeyFor spells the partition a row belongs to.
//
// ONE SPELLING, used by the writer and the reconciler alike. Two spellings is
// the duplication bug in its most expensive form here: a support row written
// under a key no retirement query matches reads as "nothing supports this
// object", and the object is retired on the next complete sweep -- a revocation
// the cluster never made.
//
// With no sweep (an unattributable snapshot) the key falls back to the bare
// namespace, which no reconciler scope will ever match. That is deliberate: the
// rows are projected, and nothing can retire them.
func partitionKeyFor(ref *sweepRef, namespace, target string) string {
	if ref == nil {
		return namespace
	}
	return k8sgraph.PartitionForEdge(ref.Scope, namespace, target).Key()
}

// upsertSupport records, per object, that THIS sweep saw it.
//
// Support is what reconciliation reads: an object survives exactly as long as
// some source still supports it (§2.10B). The upsert is idempotent on
// (workspace, object, source_ref, partition) -- the partial unique indexes 041
// rebuilt on source_ref -- so a re-delivered snapshot refreshes the row rather
// than adding a second one.
//
// A workload is supported while its sighting is live in discovered_agents. A
// gone or vanished sighting is simply not confirmed here, and the reconciler
// ends its support exactly as it ends an identity's.
func (m *k8sRBACManager) upsertSupport(tx *gorm.DB, workspaceID uuid.UUID, ref *sweepRef,
	out k8sgraph.Result, wres k8sgraph.WorkloadResult,
	identityIDs, policyIDs, statementIDs, workloadIDs map[string]uuid.UUID,
	observed time.Time) error {

	// A statement belongs to the partition of the role that declares it: a
	// ClusterRole's rules are cluster-scoped, a Role's are namespaced. Resolving
	// it from the policy rather than guessing is what keeps a namespaced sweep
	// from retiring a ClusterRole's rules.
	policyNS := make(map[string]string, len(out.Policies))
	for _, p := range out.Policies {
		policyNS[p.SourceKey] = p.Namespace
	}

	type item struct {
		col       string
		id        uuid.UUID
		partition k8sgraph.Partition
	}
	var items []item

	for _, n := range out.Identities {
		if id, ok := identityIDs[n.SourceKey]; ok {
			items = append(items, item{"identity_account_id", id,
				k8sgraph.PartitionForIdentity(ref.Scope, n.Namespace)})
		}
	}
	for _, n := range out.Policies {
		if id, ok := policyIDs[n.SourceKey]; ok {
			items = append(items, item{"policy_id", id,
				k8sgraph.PartitionForRole(ref.Scope, n.Namespace)})
		}
	}
	for _, st := range out.Statements {
		id, ok := statementIDs[st.StatementKey]
		if !ok {
			continue
		}
		items = append(items, item{"entitlement_id", id, k8sgraph.Partition{
			SourceID: ref.Scope.SourceID, Cluster: ref.Scope.Cluster,
			Namespace: policyNS[st.PolicyKey], Class: k8sgraph.ClassEntitlement,
		}})
	}
	for _, w := range wres.Workloads {
		if !w.Live {
			continue
		}
		if id, ok := workloadIDs[w.SourceKey]; ok {
			items = append(items, item{"workload_id", id,
				k8sgraph.PartitionForWorkload(ref.Scope, w.Namespace)})
		}
	}

	for _, it := range items {
		row := map[string]any{
			"id":                      uuid.New(),
			"workspace_id":            workspaceID,
			it.col:                    it.id,
			"discovery_source_id":     ref.SourceID,
			"partition_key":           it.partition.Key(),
			"state":                   models.RelCurrent,
			"first_seen_at":           observed,
			"last_confirmed_sweep_id": ref.SweepID,
			"last_confirmed_at":       observed,
		}
		if err := tx.Table("iga_object_support").
			Clauses(clause.OnConflict{
				Columns: []clause.Column{
					{Name: "workspace_id"}, {Name: it.col},
					{Name: "source_ref"}, {Name: "partition_key"},
				},
				TargetWhere: clause.Where{Exprs: []clause.Expression{
					gorm.Expr(it.col + " IS NOT NULL"),
				}},
				DoUpdates: clause.Assignments(map[string]any{
					// Re-confirming revives a row that a previous sweep ended or
					// marked stale: the object is plainly here again, and
					// leaving it ended would retire a live object forever.
					"state":                   models.RelCurrent,
					"ended_reason":            "",
					"last_confirmed_sweep_id": ref.SweepID,
					"last_confirmed_at":       observed,
				}),
			}).Create(row).Error; err != nil {
			return fmt.Errorf("%s support: %w", it.col, err)
		}
	}
	return nil
}

/* ------------------------------- workloads -------------------------------- */

// loadSightings reads the discovered agents belonging to one cluster.
//
// The cluster and namespace live in metadata, spelled exactly as the agent
// policy selector reads them (agent_policy_service.go) -- the same two paths,
// because two spellings of "which cluster is this in" would silently split the
// inventory in half.
//
// Only the Kubernetes webhook's sightings: the fingerprint that keys a workload
// is unique per (workspace, source), so another source's row could otherwise
// claim the same key.
func (m *k8sRBACManager) loadSightings(tx *gorm.DB, workspaceID uuid.UUID,
	cluster string) ([]k8sgraph.WorkloadSighting, error) {

	var rows []k8sgraph.WorkloadSighting
	err := tx.Table("discovered_agents").
		Select(`fingerprint,
		        display_name,
		        COALESCE(metadata->'kubernetes'->>'namespace', '') AS namespace,
		        COALESCE(metadata->'kubernetes'->>'workload_kind', '') AS workload_kind,
		        COALESCE(metadata->'provisioning_hints'->>'identity_anchor', '') AS identity_anchor,
		        observed_service_account,
		        runtime_status,
		        archetype`).
		Where("workspace_id = ? AND source = ? AND metadata->'cluster'->>'name' = ?",
			workspaceID, models.DiscoverySourceK8sWebhook, cluster).
		Scan(&rows).Error
	return rows, err
}

// upsertWorkloads writes the runtime objects and their execution identities,
// and returns the live workloads' ids by source key.
//
// A gone sighting is retired here, at once: it is a positive observation by the
// resync manifest, not an absence, so it needs no complete sweep to prove it.
// A sighting that has VANISHED is a different fact -- an absence -- and is left
// to the reconciler, which ends its support only on a complete sweep that
// covered its namespace.
func (m *k8sRBACManager) upsertWorkloads(tx *gorm.DB, workspaceID uuid.UUID,
	res k8sgraph.WorkloadResult, identityIDs map[string]uuid.UUID,
	observed time.Time, ref *sweepRef) (map[string]uuid.UUID, int, error) {

	// Rows written under the old name key move to the fingerprint key first,
	// so the upserts below find them rather than inserting beside them.
	if err := m.rekeyWorkloads(tx, workspaceID, res.Workloads, observed); err != nil {
		return nil, 0, err
	}

	// LIVE ROWS ARE UPSERTED; DEAD ONES ARE UPDATED. Never the other way round.
	//
	// Every uniqueness index on these tables is PARTIAL and excludes the dead
	// state -- iga_workload's on `lifecycle <> 'retired'`, iga_relationship's on
	// `state <> 'ended'`. An INSERT ... ON CONFLICT whose new row is already
	// dead does not satisfy the index predicate, so Postgres finds no arbiter,
	// detects no conflict, and inserts a SECOND row. The original stays live.
	//
	// The symptom is the worst kind: a workload reported both active and
	// retired at once, and a revoked execution identity still drawn as current.
	var live []k8sgraph.Workload
	var dead []string
	for _, w := range res.Workloads {
		if w.Live {
			live = append(live, w)
			continue
		}
		dead = append(dead, w.SourceKey)
	}

	for i := range live {
		w := live[i]
		attrs, err := jsonAttrs(w.Attrs)
		if err != nil {
			return nil, 0, err
		}
		row := map[string]any{
			"id":             uuid.New(),
			"workspace_id":   workspaceID,
			"provider":       models.ProviderK8s,
			"runtime_kind":   w.RuntimeKind,
			"display_name":   w.DisplayName,
			"lifecycle":      models.IGALifecycleActive,
			"retired_reason": "",
			"source_key":     w.SourceKey,
			"continuity":     models.ContinuityRecognitionOnly,
			"provider_attrs": attrs,
			"first_seen_at":  observed,
			"last_seen_at":   observed,
			"created_at":     observed,
			"updated_at":     observed,
		}
		if err := tx.Table("iga_workload").
			Clauses(conflictOn(liveByLifecycle, map[string]any{
				// The kind may arrive only on a later sighting; a row first
				// written as k8s_workload is corrected, not left generic.
				"runtime_kind":   w.RuntimeKind,
				"display_name":   w.DisplayName,
				"provider_attrs": attrs,
				"last_seen_at":   observed,
				"updated_at":     observed,
			})).Create(row).Error; err != nil {
			return nil, 0, fmt.Errorf("workload %s: %w", w.SourceKey, err)
		}
	}

	if len(dead) > 0 {
		if err := tx.Table("iga_workload").
			Where("workspace_id = ? AND provider = ? AND source_key IN ? AND lifecycle = ?",
				workspaceID, models.ProviderK8s, dead, models.IGALifecycleActive).
			Updates(map[string]any{
				"lifecycle":      models.IGALifecycleRetired,
				"retired_reason": models.EndedNotSeen,
				"updated_at":     observed,
			}).Error; err != nil {
			return nil, 0, fmt.Errorf("retire workloads: %w", err)
		}
		// Their support ends with them, from every source: "gone" is the
		// workspace's inventory speaking, not one agent's view. Support left
		// current on a retired row would list a dead workload as confirmed.
		if err := tx.Exec(`
			UPDATE iga_object_support
			   SET state = ?, ended_reason = ?
			 WHERE workspace_id = ? AND state <> ?
			   AND workload_id IN (
			         SELECT id FROM iga_workload
			          WHERE workspace_id = ? AND provider = ?
			            AND source_key IN ? AND lifecycle = ?)`,
			models.RelEnded, models.EndedNotSeen, workspaceID, models.RelEnded,
			workspaceID, models.ProviderK8s, dead, models.IGALifecycleRetired).Error; err != nil {
			return nil, 0, fmt.Errorf("end gone workload support: %w", err)
		}
	}

	workloadIDs, err := m.idsBySourceKey(tx, workspaceID, "iga_workload")
	if err != nil {
		return nil, 0, fmt.Errorf("resolve workload ids: %w", err)
	}

	written := 0
	var ended []string
	for i := range res.ExecutesAs {
		e := res.ExecutesAs[i]
		if !e.Live {
			ended = append(ended, e.SourceKey)
			continue
		}
		wID, okW := workloadIDs[e.WorkloadKey]
		iID, okI := identityIDs[e.IdentityKey]
		if !okW || !okI {
			// The ServiceAccount was not in this sweep's scope. The workload
			// still runs as something; the edge waits for a sweep that can see
			// it rather than being invented now.
			continue
		}
		row := map[string]any{
			"id":                         uuid.New(),
			"workspace_id":               workspaceID,
			"relationship_type":          models.RelTypeExecutesAs,
			"source_workload_id":         wID,
			"target_identity_account_id": iID,
			"basis":                      e.Basis,
			"state":                      models.RelCurrent,
			"valid_from":                 observed,
			"last_confirmed_at":          observed,
			"source_key":                 e.SourceKey,
		}
		update := map[string]any{
			"basis":             e.Basis,
			"state":             models.RelCurrent,
			"last_confirmed_at": observed,
		}
		if ref != nil {
			// Owned by the WORKLOAD's namespace partition, which Partitions()
			// emits -- so the reconciler closes an edge no sighting confirms.
			// Updated on conflict too, so an edge written under an earlier
			// spelling moves into a partition that is actually reconciled.
			pk := k8sgraph.PartitionForEdge(ref.Scope, e.Namespace, k8sgraph.TargetExecutesAs).Key()
			row["partition_key"] = pk
			update["partition_key"] = pk
		}
		if err := tx.Table("iga_relationship").
			Clauses(clause.OnConflict{
				Columns:     []clause.Column{{Name: "workspace_id"}, {Name: "source_key"}},
				TargetWhere: clause.Where{Exprs: []clause.Expression{gorm.Expr("state <> 'ended'")}},
				DoUpdates:   clause.Assignments(update),
			}).Create(row).Error; err != nil {
			return nil, written, fmt.Errorf("executes_as %s: %w", e.SourceKey, err)
		}
		written++
	}

	if len(ended) > 0 {
		// valid_to and ended_reason together: iga_relationship_ended_chk and
		// iga_relationship_ended_reason_chk each require one, so setting the
		// state without both is rejected rather than half-applied.
		if err := tx.Table("iga_relationship").
			Where("workspace_id = ? AND source_key IN ? AND state <> ?",
				workspaceID, ended, models.RelEnded).
			Updates(map[string]any{
				"state":        models.RelEnded,
				"valid_to":     observed,
				"ended_reason": models.EndedNotSeen,
			}).Error; err != nil {
			return nil, written, fmt.Errorf("end executes_as: %w", err)
		}
	}
	return workloadIDs, written, nil
}

// rekeyWorkloads moves rows written under the name key to the fingerprint key,
// IN PLACE.
//
// Same row, same id: classifications, lifecycle events and every other
// reference to the workload survive. Inserting a fresh row instead would orphan
// all of them and leave the old row live under a key nothing writes any more.
//
// A row is moved only when its recorded fingerprint is this sighting's. Two
// workloads that shared a name were merged into ONE old row, carrying whichever
// fingerprint wrote last; that sighting reclaims the row and the other gets a
// row of its own. Moving on the name alone would hand the first sighting to
// arrive the other workload's history.
func (m *k8sRBACManager) rekeyWorkloads(tx *gorm.DB, workspaceID uuid.UUID,
	ws []k8sgraph.Workload, observed time.Time) error {

	for _, w := range ws {
		if w.LegacyKey == "" || w.LegacyKey == w.SourceKey {
			continue
		}
		var moved []struct{ ID uuid.UUID }
		if err := tx.Raw(`
			UPDATE iga_workload o
			   SET source_key = ?, updated_at = ?
			 WHERE o.workspace_id = ? AND o.provider = ?
			   AND o.source_key = ? AND o.lifecycle <> ?
			   AND o.provider_attrs->>'fingerprint' = ?
			   AND NOT EXISTS (
			         SELECT 1 FROM iga_workload n
			          WHERE n.workspace_id = o.workspace_id
			            AND n.source_key = ? AND n.lifecycle <> ?)
			RETURNING o.id`,
			w.SourceKey, observed, workspaceID, models.ProviderK8s,
			w.LegacyKey, models.IGALifecycleRetired, w.Fingerprint,
			w.SourceKey, models.IGALifecycleRetired).Scan(&moved).Error; err != nil {
			return fmt.Errorf("re-key workload %s: %w", w.SourceKey, err)
		}

		// Its execution edges follow it: their keys embed the workload's, and
		// an edge left under the old key would never be re-confirmed while a
		// duplicate was written beside it.
		oldPrefix, newPrefix := k8sgraph.RelKeyPrefix(w.LegacyKey), k8sgraph.RelKeyPrefix(w.SourceKey)
		for _, mv := range moved {
			var rels []struct {
				ID        uuid.UUID
				SourceKey string
			}
			if err := tx.Table("iga_relationship").Select("id, source_key").
				Where("workspace_id = ? AND source_workload_id = ? AND relationship_type = ? AND state <> ?",
					workspaceID, mv.ID, models.RelTypeExecutesAs, models.RelEnded).
				Scan(&rels).Error; err != nil {
				return fmt.Errorf("re-key executes_as of %s: %w", w.SourceKey, err)
			}
			for _, r := range rels {
				if !strings.HasPrefix(r.SourceKey, oldPrefix) {
					continue
				}
				if err := tx.Table("iga_relationship").Where("id = ?", r.ID).
					Updates(map[string]any{
						"source_key": newPrefix + strings.TrimPrefix(r.SourceKey, oldPrefix),
						"updated_at": observed,
					}).Error; err != nil {
					return fmt.Errorf("re-key executes_as %s: %w", r.SourceKey, err)
				}
			}
		}
	}
	return nil
}

// legacyExecutesAsTarget is the partition target executes_as edges were once
// written under. Partitions() never emitted it, so no sweep reconciled them.
const legacyExecutesAsTarget = "workload"

// adoptUnreconciled brings this cluster's rows that no sweep could reconcile
// into this sweep's partitions.
//
// Two kinds, both written before workloads were reconciled at all:
//
//   - an active workload with no support from this source. Given support that
//     NO sweep has confirmed (last_confirmed_sweep_id NULL), it is exactly as
//     reconcilable as everything else: a complete sweep covering its namespace
//     ends it, anything less marks it stale. A workload whose sighting is live
//     was confirmed above and is never adopted.
//   - an executes_as edge in the legacy partition, or in none (written by an
//     unattributed snapshot). Moved to its workload's namespace partition and
//     left otherwise untouched; the reconciler then decides it like any other.
//
// Scoped to this cluster by provider_attrs.cluster, so one cluster's sweep
// never claims another cluster's rows.
func (m *k8sRBACManager) adoptUnreconciled(tx *gorm.DB, workspaceID uuid.UUID,
	cluster string, ref *sweepRef, observed time.Time) error {

	var wls []struct {
		ID        uuid.UUID
		Namespace string
	}
	if err := tx.Raw(`
		SELECT w.id, COALESCE(w.provider_attrs->>'namespace', '') AS namespace
		  FROM iga_workload w
		 WHERE w.workspace_id = ? AND w.provider = ? AND w.lifecycle = ?
		   AND w.provider_attrs->>'cluster' = ?
		   AND NOT EXISTS (
		         SELECT 1 FROM iga_object_support s
		          WHERE s.workspace_id = w.workspace_id
		            AND s.workload_id = w.id
		            AND s.discovery_source_id = ?)`,
		workspaceID, models.ProviderK8s, models.IGALifecycleActive, cluster, ref.SourceID).
		Scan(&wls).Error; err != nil {
		return fmt.Errorf("find unsupported workloads: %w", err)
	}
	for _, w := range wls {
		if err := tx.Table("iga_object_support").
			Clauses(clause.OnConflict{DoNothing: true}).
			Create(map[string]any{
				"id":                  uuid.New(),
				"workspace_id":        workspaceID,
				"workload_id":         w.ID,
				"discovery_source_id": ref.SourceID,
				"partition_key":       k8sgraph.PartitionForWorkload(ref.Scope, w.Namespace).Key(),
				"state":               models.RelCurrent,
				"first_seen_at":       observed,
			}).Error; err != nil {
			return fmt.Errorf("adopt workload %s: %w", w.ID, err)
		}
	}

	legacy := k8sgraph.Partition{SourceID: ref.SourceID, Cluster: cluster,
		Target: legacyExecutesAsTarget}.Key()
	var rels []struct {
		ID        uuid.UUID
		Namespace string
	}
	if err := tx.Raw(`
		SELECT r.id, COALESCE(w.provider_attrs->>'namespace', '') AS namespace
		  FROM iga_relationship r
		  JOIN iga_workload w
		    ON w.workspace_id = r.workspace_id AND w.id = r.source_workload_id
		 WHERE r.workspace_id = ? AND r.relationship_type = ? AND r.state <> ?
		   AND r.partition_key IN ('', ?)
		   AND w.provider = ? AND w.provider_attrs->>'cluster' = ?`,
		workspaceID, models.RelTypeExecutesAs, models.RelEnded, legacy,
		models.ProviderK8s, cluster).Scan(&rels).Error; err != nil {
		return fmt.Errorf("find unpartitioned executes_as: %w", err)
	}
	for _, r := range rels {
		if err := tx.Table("iga_relationship").Where("id = ?", r.ID).
			Update("partition_key",
				k8sgraph.PartitionForEdge(ref.Scope, r.Namespace, k8sgraph.TargetExecutesAs).Key()).
			Error; err != nil {
			return fmt.Errorf("adopt executes_as %s: %w", r.ID, err)
		}
	}
	return nil
}
