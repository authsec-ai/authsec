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
	err := m.db.Transaction(func(tx *gorm.DB) error {
		if err := m.upsertIdentities(tx, workspaceID, out.Identities, observed); err != nil {
			return fmt.Errorf("identities: %w", err)
		}
		if err := m.upsertPolicies(tx, workspaceID, out.Policies, observed); err != nil {
			return fmt.Errorf("policies: %w", err)
		}
		if err := m.upsertStatements(tx, workspaceID, out.Statements, observed); err != nil {
			return fmt.Errorf("statements: %w", err)
		}

		// The nodes are in; resolve their ids so the edges can reference them.
		// Read back rather than remember what we just wrote: an upsert that
		// collided with an existing row returns that row's id, and assuming our
		// generated one would attach every edge to a node that does not exist.
		identityIDs, err := m.idsBySourceKey(tx, workspaceID, "iga_identity_accounts")
		if err != nil {
			return fmt.Errorf("resolve identity ids: %w", err)
		}
		policyIDs, err := m.idsBySourceKey(tx, workspaceID, "iga_policy")
		if err != nil {
			return fmt.Errorf("resolve policy ids: %w", err)
		}
		statementIDs, err := m.idsBySourceKey(tx, workspaceID, "iga_entitlements")
		if err != nil {
			return fmt.Errorf("resolve statement ids: %w", err)
		}

		assignmentIDs, err := m.upsertAssignments(tx, workspaceID, out.Assignments,
			policyIDs, identityIDs, observed)
		if err != nil {
			return fmt.Errorf("assignments: %w", err)
		}
		if err := m.upsertEdges(tx, workspaceID, snap.Cluster, out.Edges,
			identityIDs, statementIDs, assignmentIDs, observed); err != nil {
			return fmt.Errorf("edges: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// idsBySourceKey maps every live source_key in a graph table to its row id.
//
// Scoped to this provider: another provider's keys cannot collide with ours
// (every k8s key starts "k8s␟"), but reading the whole workspace would load
// every AWS row on every Kubernetes sweep for nothing.
func (m *k8sRBACManager) idsBySourceKey(tx *gorm.DB, workspaceID uuid.UUID,
	table string) (map[string]uuid.UUID, error) {

	var rows []struct {
		ID        uuid.UUID
		SourceKey string
	}
	if err := tx.Table(table).
		Select("id, source_key").
		Where("workspace_id = ? AND provider = ?", workspaceID, models.ProviderK8s).
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
	observed time.Time) (map[string]uuid.UUID, error) {

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
			"partition_key":     a.Namespace,
		}
		if err := tx.Table("iga_policy_assignment").
			Clauses(conflictOn(liveAssignment, map[string]any{
				"policy_id":                  policyID,
				"holder_identity_account_id": holderID,
				"assignment_kind":            a.Kind,
				"last_confirmed_at":          observed,
				"state":                      "current",
			})).Create(row).Error; err != nil {
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
	edges []k8sgraph.Edge, identityIDs, statementIDs, assignmentIDs map[string]uuid.UUID,
	observed time.Time) error {

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
			"partition_key":        cluster,
			"created_at":           observed,
			"updated_at":           observed,
		}
		if id, ok := statementIDs[e.StatementKey]; ok && e.StatementKey != "" {
			row["entitlement_id"] = id
		}
		if id, ok := assignmentIDs[e.AssignmentKey]; ok {
			row["assignment_id"] = id
		}

		if err := tx.Table("iga_access_edges").
			Clauses(conflictOn(liveEdge, map[string]any{
				"calculation_state":    e.CalculationState,
				"effective_conclusion": e.EffectiveConclusion,
				"last_confirmed_at":    observed,
				"observed_at":          observed,
				"state":                "current",
				"updated_at":           observed,
			})).Create(row).Error; err != nil {
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
func (m *k8sRBACManager) upsertStatements(tx *gorm.DB, workspaceID uuid.UUID,
	sts []k8sgraph.Statement, observed time.Time) error {

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
		if err := tx.Table("iga_entitlements").
			Clauses(conflictOn(liveByLifecycle, map[string]any{
				"native_rights":     native,
				"normalized_rights": normalized,
				"last_seen_at":      observed,
				"lifecycle":         "active",
				"updated_at":        observed,
			})).Create(row).Error; err != nil {
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
func parseSnapshotTime(s string) time.Time {
	if s == "" {
		return time.Now().UTC()
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Now().UTC()
	}
	return t.UTC()
}
