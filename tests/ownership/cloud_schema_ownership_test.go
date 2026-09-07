// GCP-02 conformance regression tests: proves the claims in
// authsec/docs/gcp/schema-conformance-review.md against the database itself,
// not just in prose. These assert what the AWS-landed cloud_* schema
// (migrations/master/010-013) already guarantees; GCP-02 lands nothing new.
//
// A separate file from schema_ownership_test.go on purpose (per GCP-02's own
// scope: additive only, no edit to the existing suite), but it shares that
// file's package-level setupSchema/seedBaseline/exec/mustFail helpers and the
// wsA/wsB constants.
//
// Requires TEST_DATABASE_URL, and skips without it, like the rest of this
// package — see schema_ownership_test.go's header for the connection-string
// convention.
package ownership

import (
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// setupCloudSchema layers the AWS-landed cloud discovery migrations
// (010-013) on top of the schema setupSchema(t) just built from
// 001_bootstrap.sql. Bootstrap has not been regenerated to fold these four
// files in yet (confirmed in schema-conformance-review.md: grepping
// cloud_connector/cloud_identity/etc. against 001_bootstrap.sql finds
// nothing), so a GCP-02 conformance test needs both, applied in the same
// numeric order internal/migration/runner.go uses at boot.
func setupCloudSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, name := range []string{
		"010_cloud_discovery_connector.sql",
		"011_cloud_identity_and_secret.sql",
		"012_cloud_assume_edge.sql",
		"013_cloud_permission_and_resource.sql",
	} {
		p, err := filepath.Abs(filepath.Join("..", "..", "migrations", "master", name))
		if err != nil {
			t.Fatalf("resolve %s: %v", name, err)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if _, err := db.Exec(string(b)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
}

// columnsOf returns the set of column names Postgres actually has for table,
// read from information_schema rather than assumed from the migration source
// — the point of this file is to check what landed, not what was intended.
func columnsOf(t *testing.T, db *sql.DB, table string) map[string]bool {
	t.Helper()
	rows, err := db.Query(
		`SELECT column_name FROM information_schema.columns
		 WHERE table_schema = 'public' AND table_name = $1`,
		table)
	if err != nil {
		t.Fatalf("query columns of %s: %v", table, err)
	}
	defer rows.Close()

	cols := map[string]bool{}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatalf("scan column of %s: %v", table, err)
		}
		cols[c] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate columns of %s: %v", table, err)
	}
	return cols
}

// TestCloudChildTables_CarryConnectorAndGeneration proves the reconciliation
// columns (connector_id, last_seen_generation) exist on every cloud_* child
// table -- and, just as important, do NOT exist on cloud_connector itself.
// cloud_connector carries scan_generation instead: its OWN scan counter, a
// different column with a different meaning from "when was this child row
// last seen by a scan".
//
// discovered_agents.cloud_identity_id is deliberately NOT asserted anywhere
// in this file. It does not exist on this branch -- confirmed directly
// against migrations/master/001_bootstrap.sql and
// migrations/master/002_agent_discovery.sql's discovered_agents DDL, neither
// of which defines it -- and asserting it would fail against the actually-
// landed schema. It is tracked as a dependency on the AWS track's own
// tickets 5/6/9 (which would populate and consume the join), not a GCP-02
// blocker; see schema-conformance-review.md's "discovered_agents" section.
func TestCloudChildTables_CarryConnectorAndGeneration(t *testing.T) {
	db := setupSchema(t)
	setupCloudSchema(t, db)

	childTables := []string{
		"cloud_identity", "cloud_secret", "cloud_assume_edge",
		"cloud_permission", "cloud_resource",
	}
	for _, table := range childTables {
		cols := columnsOf(t, db, table)
		if !cols["connector_id"] {
			t.Errorf("%s: missing connector_id", table)
		}
		if !cols["last_seen_generation"] {
			t.Errorf("%s: missing last_seen_generation", table)
		}
	}

	connectorCols := columnsOf(t, db, "cloud_connector")
	if connectorCols["connector_id"] {
		t.Error("cloud_connector: must not carry its own connector_id -- it IS the connector every child table points at")
	}
	if connectorCols["last_seen_generation"] {
		t.Error("cloud_connector: must not carry last_seen_generation -- it carries scan_generation instead")
	}
	if !connectorCols["scan_generation"] {
		t.Error("cloud_connector: missing scan_generation")
	}
}

// TestCloudSecret_NoSecretValueColumn proves cloud_secret is metadata-only --
// there is no column anywhere on it that could hold a credential value.
// Asserted structurally, as the exact expected column set from migration
// 011, rather than a blacklist of guessed dangerous names: a blacklist only
// catches a column named "value" or "secret", and would miss one named
// something else entirely that still ends up holding key material.
func TestCloudSecret_NoSecretValueColumn(t *testing.T) {
	db := setupSchema(t)
	setupCloudSchema(t, db)

	want := []string{
		"id", "workspace_id", "connector_id", "identity_id", "kind",
		"native_id", "created_at", "expires_at", "last_used_at", "status",
		"attrs", "last_seen_generation", "first_seen_at", "last_seen_at",
		"row_updated_at",
	}
	wantSet := map[string]bool{}
	for _, w := range want {
		wantSet[w] = true
	}

	got := columnsOf(t, db, "cloud_secret")
	for _, w := range want {
		if !got[w] {
			t.Errorf("cloud_secret: expected column %q missing", w)
		}
	}

	var extra []string
	for c := range got {
		if !wantSet[c] {
			extra = append(extra, c)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		t.Errorf("cloud_secret: unexpected column(s) %v -- if one of these holds secret material, this table has stopped being metadata-only", extra)
	}
}

// TestCloudConnector_ProviderCheck_IncludesGCP proves the landed
// cloud_connector_provider_chk CHECK constraint (migration 010) accepts
// provider='gcp' -- required before GCP onboarding (GCP-04) can write its
// first row -- while still rejecting an unrecognised provider, so the CHECK
// is proven to actually enforce something rather than merely permit
// everything.
func TestCloudConnector_ProviderCheck_IncludesGCP(t *testing.T) {
	db := setupSchema(t)
	setupCloudSchema(t, db)
	seedBaseline(t, db)

	exec(t, db,
		`INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, auth_ref, status)
		 VALUES (gen_random_uuid(), $1, 'gcp', 'project', 'gcp-provider-chk-1', 'wif:x', 'active')`,
		wsA)

	mustFail(t, db, "cloud_connector with an unrecognised provider",
		`INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, auth_ref, status)
		 VALUES (gen_random_uuid(), $1, 'not_a_real_provider', 'project', 'gcp-provider-chk-2', 'wif:x', 'active')`,
		wsA)
}

// TestCloudConnector_ScopeKindCheck_IncludesGCPScopes proves the landed
// cloud_connector_scope_kind_chk CHECK allows all three GCP scope kinds --
// project, folder and org -- since GCP is the first connector to exercise
// scope hierarchy (plan section 10; GCP-D7).
func TestCloudConnector_ScopeKindCheck_IncludesGCPScopes(t *testing.T) {
	db := setupSchema(t)
	setupCloudSchema(t, db)
	seedBaseline(t, db)

	for _, tc := range []struct{ scopeKind, scopeID string }{
		{"project", "gcp-scope-kind-chk-project"},
		{"folder", "gcp-scope-kind-chk-folder"},
		{"org", "gcp-scope-kind-chk-org"},
	} {
		exec(t, db,
			`INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, auth_ref, status)
			 VALUES (gen_random_uuid(), $1, 'gcp', $2, $3, 'wif:x', 'active')`,
			wsA, tc.scopeKind, tc.scopeID)
	}

	mustFail(t, db, "cloud_connector with an unrecognised scope_kind",
		`INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, auth_ref, status)
		 VALUES (gen_random_uuid(), $1, 'gcp', 'not_a_real_scope', 'gcp-scope-kind-chk-bad', 'wif:x', 'active')`,
		wsA)
}
