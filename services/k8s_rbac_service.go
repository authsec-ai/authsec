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
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

/* --------------------------------- upserts -------------------------------- */

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
			Clauses(clause.OnConflict{
				Columns: []clause.Column{{Name: "workspace_id"}, {Name: "source_key"}},
				// first_seen_at is deliberately NOT updated: it is when we first
				// saw this identity, and overwriting it on every sweep would
				// erase the only evidence of how long it has existed.
				DoUpdates: clause.Assignments(map[string]any{
					"display_name":   n.DisplayName,
					"provider_attrs": attrs,
					"last_seen_at":   observed,
					"updated_at":     observed,
					"lifecycle":      "active",
				}),
			}).Create(row).Error; err != nil {
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
			Clauses(clause.OnConflict{
				Columns: []clause.Column{{Name: "workspace_id"}, {Name: "source_key"}},
				DoUpdates: clause.Assignments(map[string]any{
					"display_name": n.DisplayName,
					"last_seen_at": observed,
					"lifecycle":    "active",
				}),
			}).Create(row).Error; err != nil {
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
			Clauses(clause.OnConflict{
				Columns: []clause.Column{{Name: "workspace_id"}, {Name: "source_key"}},
				DoUpdates: clause.Assignments(map[string]any{
					"native_rights":     native,
					"normalized_rights": normalized,
					"last_seen_at":      observed,
					"lifecycle":         "active",
					"updated_at":        observed,
				}),
			}).Create(row).Error; err != nil {
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
