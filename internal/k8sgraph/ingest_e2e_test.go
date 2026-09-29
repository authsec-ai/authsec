//go:build e2e

// End-to-end projection against a real Postgres.
//
// The unit tests in project_test.go prove the MAPPING is right. This proves the
// mapping survives contact with the schema — every NOT NULL satisfied, every
// CHECK passed, every foreign key resolvable, and the honesty columns agreeing
// with each other. Those are exactly the failures a pure-Go test cannot see, and
// exactly the ones that would otherwise be found by a customer's first sweep.
//
// Build-tagged and skipped without K8S_GRAPH_TEST_DSN, so it never runs in an
// ordinary build.
//
//	docker run -d -e POSTGRES_PASSWORD=pw -p 55442:5432 postgres:16
//	# apply migrations/master/*.sql in version order, then:
//	K8S_GRAPH_TEST_DSN="postgres://postgres:pw@localhost:55442/authsec?sslmode=disable" \
//	  go test -tags e2e ./internal/k8sgraph/
package k8sgraph_test

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"
)

func dsn(t *testing.T) *sql.DB {
	t.Helper()
	d := os.Getenv("K8S_GRAPH_TEST_DSN")
	if d == "" {
		t.Skip("K8S_GRAPH_TEST_DSN not set; skipping the projection e2e")
	}
	db, err := sql.Open("postgres", d)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	return db
}

// The shapes the projector produces must be storable. Each insert below mirrors
// one row the service writes, with the same columns and values.
func TestProjectedShapesSatisfyTheSchema(t *testing.T) {
	db := dsn(t)
	defer func() { _ = db.Close() }()

	ws := "33333333-3333-3333-3333-333333333333"
	mustExec(t, db, `INSERT INTO workspaces (id,name) VALUES ($1,'k8s-e2e')
	                 ON CONFLICT (id) DO NOTHING`, ws)

	// --- an identity ---------------------------------------------------------
	var identityID string
	mustQuery(t, db, &identityID, `
		INSERT INTO iga_identity_accounts
		  (workspace_id, display_name, account_kind, identity_backing, lifecycle,
		   provider, source_key, continuity, provider_attrs)
		VALUES ($1,'system:serviceaccount:prod:agent','k8s_service_account','provider',
		        'active','k8s','k8s|prod|sa|agent','recognition_only','{}'::jsonb)
		ON CONFLICT (workspace_id, source_key) WHERE source_key <> '' AND lifecycle <> 'retired'
		  DO UPDATE SET display_name = EXCLUDED.display_name
		RETURNING id`, ws)

	// --- a policy ------------------------------------------------------------
	var policyID string
	mustQuery(t, db, &policyID, `
		INSERT INTO iga_policy
		  (workspace_id, provider, policy_kind, display_name, native_ref, source_key,
		   continuity, lifecycle)
		VALUES ($1,'k8s','k8s_cluster_role','secret-reader','ref','k8s|prod|cr|secret-reader',
		        'recognition_only','active')
		ON CONFLICT (workspace_id, source_key) WHERE lifecycle <> 'retired'
		  DO UPDATE SET display_name = EXCLUDED.display_name
		RETURNING id`, ws)

	// --- a statement ---------------------------------------------------------
	var entitlementID string
	mustQuery(t, db, &entitlementID, `
		INSERT INTO iga_entitlements
		  (workspace_id, native_grant_kind, native_rights, normalized_rights, lifecycle,
		   provider, source_key, continuity, statement_key, effect, negated, conditional)
		VALUES ($1,'k8s_policy_rule','{"verbs":["get"]}'::jsonb,'{"verbs":["get"]}'::jsonb,
		        'active','k8s','k8s|stmt|1','recognition_only','k8s|stmt|1','allow',false,false)
		ON CONFLICT (workspace_id, source_key) WHERE source_key <> '' AND lifecycle <> 'retired'
		  DO UPDATE SET effect = EXCLUDED.effect
		RETURNING id`, ws)

	// --- an assignment -------------------------------------------------------
	var assignmentID string
	mustQuery(t, db, &assignmentID, `
		INSERT INTO iga_policy_assignment
		  (workspace_id, policy_id, holder_identity_account_id, assignment_kind,
		   basis, state, source_key, partition_key)
		VALUES ($1,$2,$3,'k8s_cluster_role_binding','declared','current','k8s|bind|1','prod')
		ON CONFLICT (workspace_id, source_key) WHERE state <> 'ended'
		  DO UPDATE SET state = EXCLUDED.state
		RETURNING id`, ws, policyID, identityID)

	// --- a RESOLVED edge: complete + effective -------------------------------
	mustExec(t, db, `
		INSERT INTO iga_access_edges
		  (workspace_id, subject_kind, subject_id, subject_identity_account_id, provider,
		   entitlement_id, assignment_id, direction, path_kind, basis,
		   calculation_state, effective_conclusion, native_scope, state,
		   source_key, partition_key)
		VALUES ($1,'identity_account',$2,$2,'k8s',$3,$4,'outbound','k8s_rbac','observed',
		        'complete','effective','k3s','current','k8s|edge|1','k3s')
		ON CONFLICT (workspace_id, source_key) WHERE source_key <> '' AND state <> 'ended'
		  DO NOTHING`,
		ws, identityID, entitlementID, assignmentID)

	// --- a PARTIAL edge: no entitlement, no assignment ------------------------
	// The row 039 exists to permit. If the CHECK were stricter this would fail,
	// and the projector would silently lose every unresolved binding.
	mustExec(t, db, `
		INSERT INTO iga_access_edges
		  (workspace_id, subject_kind, subject_id, subject_identity_account_id, provider,
		   direction, path_kind, basis, calculation_state, effective_conclusion,
		   native_scope, state, source_key, partition_key)
		VALUES ($1,'identity_account',$2,$2,'k8s','outbound','k8s_rbac','observed',
		        'partial','unknown','k3s','current','k8s|edge|2','k3s')
		ON CONFLICT (workspace_id, source_key) WHERE source_key <> '' AND state <> 'ended'
		  DO NOTHING`, ws, identityID)

	// --- the honesty CHECK must REFUSE a conclusion without a calculation ----
	_, err := db.Exec(`
		INSERT INTO iga_access_edges
		  (workspace_id, subject_kind, subject_id, subject_identity_account_id, provider,
		   direction, path_kind, basis, calculation_state, effective_conclusion,
		   native_scope, state, source_key, partition_key)
		VALUES ($1,'identity_account',$2,$2,'k8s','outbound','k8s_rbac','observed',
		        'partial','effective','k3s','current','k8s|edge|3','k3s')`, ws, identityID)
	if err == nil {
		t.Error("a partial calculation claiming an effective conclusion was accepted; " +
			"iga_access_edges_honesty_chk is not doing its job")
	}

	// --- and a k8s edge must not name a resource -----------------------------
	_, err = db.Exec(`
		INSERT INTO iga_access_edges
		  (workspace_id, subject_kind, subject_id, subject_identity_account_id, provider,
		   direction, path_kind, basis, calculation_state, effective_conclusion,
		   native_scope, state, source_key, partition_key, resource_id)
		VALUES ($1,'identity_account',$2,$2,'k8s','outbound','k8s_rbac','observed',
		        'partial','unknown','k3s','current','k8s|edge|4','k3s',
		        '44444444-4444-4444-4444-444444444444')`, ws, identityID)
	if err == nil {
		t.Error("a Kubernetes edge naming a resource was accepted; RBAC grants verbs " +
			"on resource TYPES, so a resource_id here would be invented")
	}

	// --- AWS rows must still be storable (nothing regressed) -----------------
	mustExec(t, db, `
		INSERT INTO iga_policy
		  (workspace_id, provider, policy_kind, display_name, native_ref, source_key,
		   continuity, lifecycle)
		VALUES ($1,'aws','customer_managed','x','arn','aws|e2e|1','recognition_only','active')
		ON CONFLICT (workspace_id, source_key) WHERE lifecycle <> 'retired'
		  DO NOTHING`, ws)
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("exec failed: %v\n%s", err, q)
	}
}

func mustQuery(t *testing.T, db *sql.DB, out *string, q string, args ...any) {
	t.Helper()
	if err := db.QueryRow(q, args...).Scan(out); err != nil {
		t.Fatalf("query failed: %v\n%s", err, q)
	}
}
