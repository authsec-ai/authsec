package services

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/k8sgraph"
	"github.com/authsec-ai/authsec/models"
)

// A binding's key can have an ended assignment row (its connection was removed:
// connection_removed) beside the live one the new connection's sweep wrote. The
// sweep attaches each grant to the id assignmentIDs returns for the key; the
// ended row's id put the grant on an ended assignment, and the reconcile
// cascade ended the grant on every sweep (production, 2026-10-30: an agent
// holding a role showed "0 rules" after its cluster was reconnected).
//
// The ended row is written last, so a lookup without the live predicate
// returns it: which row a key resolves to must not depend on scan order.
func TestAssignmentIDsAreLiveOnly(t *testing.T) {
	// A fresh bootstrap on the throwaway TEST_DATABASE_URL (skips without it).
	db := setupReturnOriginDB(t)
	ws, identity, policy := uuid.New(), uuid.New(), uuid.New()
	exec := func(q string, args ...any) {
		t.Helper()
		if err := db.Exec(q, args...).Error; err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO workspaces (id, name) VALUES (?, ?)`, ws, "assignment-ids-"+ws.String()[:8])
	exec(`INSERT INTO iga_identity_accounts (id, workspace_id, account_kind, display_name, provider, source_key, continuity, lifecycle)
	      VALUES (?, ?, 'service_account', 'sa', 'k8s', ?, 'recognition_only', 'active')`, identity, ws, "k8s"+k8sgraph.Sep+"c"+k8sgraph.Sep+"sa")
	exec(`INSERT INTO iga_policy (id, workspace_id, provider, policy_kind, display_name, source_key, continuity)
	      VALUES (?, ?, 'k8s', 'k8s_role', 'r', ?, 'recognition_only')`, policy, ws, "k8s"+k8sgraph.Sep+"c"+k8sgraph.Sep+"r")

	key := models.ProviderK8s + k8sgraph.Sep + "c" + k8sgraph.Sep + "rolebinding" + k8sgraph.Sep + "ns" + k8sgraph.Sep + "b"
	live, ended := uuid.New(), uuid.New()
	now := time.Now().UTC()
	insert := func(id uuid.UUID, state, reason string, validTo *time.Time) {
		exec(`INSERT INTO iga_policy_assignment (id, workspace_id, policy_id, holder_identity_account_id, assignment_kind,
		        basis, state, ended_reason, valid_from, valid_to, last_confirmed_at, source_key, partition_key)
		      VALUES (?, ?, ?, ?, ?, 'declared', ?, ?, ?, ?, ?, ?, 'p')`,
			id, ws, policy, identity, models.K8sAssignmentRoleBinding, state, reason, now, validTo, now, key)
	}
	insert(live, "current", "", nil)
	insert(ended, "ended", "connection_removed", &now)

	ids, err := (&k8sRBACManager{db: db}).assignmentIDs(db, ws)
	if err != nil {
		t.Fatal(err)
	}
	if ids[key] != live {
		t.Fatalf("the key resolved to %s, want the live row %s (ended row %s)", ids[key], live, ended)
	}
}
