package integration

// Re-creating a cluster's connection must not lose the grants of what existed
// before it (production, 2026-10-30): removing a connection ends its bindings'
// assignment rows (connection_removed), and the new connection's sweep writes
// new live ones under the same source keys. The sweep read assignment ids back
// by source key without the live predicate, so a key could resolve to the
// ended row -- which one depended on scan order -- and the grant attached to it
// was ended by the reconcile cascade on every sweep ("0 rules" for an agent
// that held a role). services.TestAssignmentIDsAreLiveOnly pins the lookup;
// this is the whole remove-and-reconnect flow.

import (
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// liveGrants is how many current grants the live identity of a ServiceAccount
// holds, and how many of those hang off an ended assignment (always 0).
func (k *k8sGraphLab) liveGrants(sa string) (current, onEnded int64) {
	k.t.Helper()
	q := `SELECT count(*) FROM iga_access_edges e
	        JOIN iga_identity_accounts i ON i.workspace_id = e.workspace_id AND i.id = e.subject_identity_account_id
	   LEFT JOIN iga_policy_assignment a ON a.workspace_id = e.workspace_id AND a.id = e.assignment_id
	       WHERE e.workspace_id = ? AND e.state = 'current' AND i.lifecycle <> 'retired'
	         AND i.display_name = ?`
	anchor := "system:serviceaccount:" + k8sGraphNS + ":" + sa
	if err := k.db.Raw(q, k.ws, anchor).Scan(&current).Error; err != nil {
		k.t.Fatal(err)
	}
	if err := k.db.Raw(q+` AND a.state = 'ended'`, k.ws, anchor).Scan(&onEnded).Error; err != nil {
		k.t.Fatal(err)
	}
	return current, onEnded
}

func TestP2K8sReconnectKeepsGrants(t *testing.T) {
	k := newK8sGraphLab(t, "kg-reconnect")
	k.agent("research-agent", k8sGraphNS, "system:serviceaccount:"+k8sGraphNS+":research", "Deployment")
	k.sweep(k8sFullWorld())
	before, _ := k.liveGrants("research")
	if before == 0 {
		t.Fatal("the first connection's sweep wrote no grant")
	}

	// Remove the connection, as the console does.
	if _, err := repositories.NewDiscoveryRepository(k.db).DeleteSource(k.ws, k.src); err != nil {
		t.Fatalf("delete source: %v", err)
	}
	if n, _ := k.liveGrants("research"); n != 0 {
		t.Fatalf("removing the connection must end its grants, %d left", n)
	}

	// The same cluster connects again under a new connection.
	k.src = uuid.New()
	if err := k.db.Exec(`INSERT INTO discovery_sources (id, workspace_id, kind, display_name, cluster_name)
	                     VALUES (?, ?, ?, ?, ?)`, k.src, k.ws, models.DiscoverySourceK8sWebhook,
		"agent-"+k.src.String()[:8], k8sGraphCluster).Error; err != nil {
		t.Fatal(err)
	}
	// Its agent re-reports the workload first (the webhook or a resync),
	// before the RBAC sweep.
	if err := k.db.Exec(`UPDATE discovered_agents SET discovery_source_id = ? WHERE workspace_id = ?`, k.src, k.ws).Error; err != nil {
		t.Fatal(err)
	}
	if err := k.mgr.ProjectSighting(k.ws, "fp-research-agent"); err != nil {
		t.Fatalf("project sighting: %v", err)
	}
	for sweep := 1; sweep <= 2; sweep++ {
		k.sweep(k8sFullWorld())
		after, onEnded := k.liveGrants("research")
		if after != before || onEnded != 0 {
			var rows []struct{ State, EndedReason, Identity, IdentityLifecycle, AssignmentState string }
			k.db.Raw(`SELECT e.state, e.ended_reason, i.id::text AS identity, i.lifecycle AS identity_lifecycle, COALESCE(a.state,'') AS assignment_state
			            FROM iga_access_edges e JOIN iga_identity_accounts i ON i.id = e.subject_identity_account_id
			       LEFT JOIN iga_policy_assignment a ON a.id = e.assignment_id
			           WHERE e.workspace_id = ? ORDER BY e.created_at`, k.ws).Scan(&rows)
			t.Logf("grants: %+v", rows)
			t.Fatalf("sweep %d after reconnecting: %d current grants (want %d), %d on an ended assignment", sweep, after, before, onEnded)
		}
	}
}
