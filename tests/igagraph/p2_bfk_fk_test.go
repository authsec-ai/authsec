package igagraph_test

// B9 and B20 (SPEC-iga-phase2-graph.md §7.3), against real PostgreSQL at 036.
//
// B9: every foreign key on the graph's tables rejects a row that names another
// workspace's parent. §2.9 (l.654-664) is the rule: "no single-column foreign
// key to a workspace-scoped table. Every reference is (workspace_id, id)
// against a UNIQUE (workspace_id, id)". B20 (l.6533; T3.2 l.6293): 035's
// collection facts (a membership's user and group, an inline policy's holder,
// an attachment's policy and principal, an observation's policy) are one
// account's facts about its own rows. So they also reject a parent in the
// SAME workspace under ANOTHER integration.
//
// Each foreign key in bfkCases gets these subtests:
//
//	control              every reference names workspace A's rows under
//	                     integration A.conn: ACCEPTED, with deferred
//	                     constraints checked too
//	foreign_workspace    the reference under test names a row that exists
//	                     ONLY in workspace B: SQLSTATE 23503 from THAT constraint
//	foreign_integration  (integration-qualified keys, B20) the row is in
//	                     workspace A under integration A2: 23503 from it
//	absent_workspace     (the workspaces anchor) a workspace that does not exist
//	absent_parent,       (bfkLegacy) what a pre-§2.9 single-column key does
//	known_gap_foreign_   enforce (PASS), and the cross-workspace row it admits:
//	workspace_admitted   a known gap (spec question), reported as SKIP so it
//	                     cannot read as a pass. It FAILS once the gap closes.
//
// WHY THE NAME, NOT JUST THE CODE. Some rows fail two constraints at once by
// construction. One case is a connector reference on a table whose other
// references also carry connector_id. Another is the workspaces anchor: moving
// the child to a missing workspace breaks every composite reference with it.
// There, "the insert was rejected" would still hold with the constraint under
// test deleted. So every negative must name the expected constraint (lib/pq's
// Error.Constraint). And the constraints the same change breaks are dropped
// first, inside the subtest's own transaction. PostgreSQL DDL is transactional,
// so the rollback restores them. That leaves the constraint under test as the
// only thing that can refuse the row. The lifted names are logged. The
// constraint under test is never lifted, and a control never lifts anything.
//
// TestB9ForeignKeyCatalogGuard is what makes "every" true. Its scope is by
// table name, not by form: every foreign key on an iga_* or cloud_* table
// (Phase 1's included) and every key from any other table that points into
// one (bfkForeignKeys). It reads pg_constraint and fails when such a key has no
// case, when a case's kind does not match its key's shape, when a
// single-column reference to a workspace-scoped table is not an exemption
// listed with its reason, when a composite reference does not lead with
// workspace_id on both sides, when a reference to a collection fact is not
// integration-qualified, when a uuid column references nothing unlisted, and
// when a cloud_* table is not classified in bfkCloudTables. A planted instance
// of each, in a rolled-back transaction, proves on every run that the checks
// can fail: among them the A3 pattern in a new cloud_* table, in a Phase 1
// table and in a table outside the graph.
//
// WHAT A GREEN RUN DOES NOT SHOW. At 036, bfkLegacySingleColumn lists the
// single-column references §2.9 forbids that no migration converted. They are
// spec questions (P2-DECISIONS D-95, with the composite DDL proposed for
// each); the migrations are verbatim from the spec and not this test's to
// change. B9 does NOT hold for them: each one's
// known_gap_foreign_workspace_admitted subtest shows another workspace's
// parent going in and reports SKIP, and the guard's
// known_gap_open_section_2_9_exemptions subtest SKIPs with the whole list,
// grouped. So "B9 and B20 pass" means that every key NOT in that list rejects
// a foreign row, and that the list is exact. It does not mean §2.9 holds, and
// it does not mean every single-column reference to cloud_identity (B20's
// "Catches") is caught: six are in the list.
//
// Home: tests/igagraph, which rebuilds public from migrations/master on every
// run (setupSchema). Nothing here edits a migration.

import (
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/lib/pq"
)

// bfkCloudTable says where a cloud_* table's references come from.
type bfkCloudTable struct {
	// phase2: created by 027-036, or given §2.9's target or references by them.
	// A Phase 1 table was written before the rule, and none of 027-036
	// converted it.
	phase2 bool
	origin string
}

// bfkCloudTables classifies every cloud_* table in the schema. The guard
// requires the catalog's cloud_* tables to be exactly these, so a new one fails
// until someone classifies it (and the coverage check until its keys have
// cases). The classification does NOT decide scope: every foreign key on every
// cloud_* table is in scope whatever its form (bfkForeignKeys). An earlier
// version took its cloud scope from the tables already holding a composite
// key, and so could not see a new table written with single-column references
// only, which is the A3 pattern itself. It only groups the open exemptions
// (bfkOpenGaps).
var bfkCloudTables = map[string]bfkCloudTable{
	"cloud_connector":         {true, "010; 027 added UNIQUE (workspace_id, id), the target of every connector reference"},
	"cloud_scan_run":          {true, "020; 027 converted its connector reference and added UNIQUE (workspace_id, id)"},
	"cloud_observation":       {true, "022; 027 converted run and connector, 035 added the integration-qualified policy_id"},
	"cloud_identity":          {true, "011; 035 made it the target of every collection reference (cloud_identity_scope_key)"},
	"cloud_group_membership":  {true, "035"},
	"cloud_policy":            {true, "035"},
	"cloud_policy_attachment": {true, "035"},
	"cloud_secret":            {false, "011"},
	"cloud_assume_edge":       {false, "012"},
	"cloud_permission":        {false, "013"},
	"cloud_resource":          {false, "013"},
	"cloud_workload":          {false, "015"},
	"cloud_usage":             {false, "016"},
	"cloud_scan_checkpoint":   {false, "017"},
}

// Reasons shared by the exemptions below. Each proposal keeps the key's
// current ON DELETE action; a SET NULL key nulls only its own column
// (PostgreSQL 15's SET NULL (column)), never workspace_id or connector_id.
// The same proposals are recorded in P2-DECISIONS D-95.
const (
	bfkConnectorProposal = ". Proposed: (workspace_id, connector_id) REFERENCES cloud_connector " +
		"(workspace_id, id) ON DELETE CASCADE, against 027's cloud_connector_workspace_id_key"
	bfkPhase1Connector = ": Phase 1, never converted" + bfkConnectorProposal
	bfkPhase1Identity  = ": Phase 1, never converted; a single-column reference to cloud_identity (B20's " +
		"Catches). Proposed: (workspace_id, connector_id, identity_id) REFERENCES cloud_identity " +
		"(workspace_id, connector_id, id) ON DELETE CASCADE, against 035's cloud_identity_scope_key"
	// cloud_permission, cloud_resource and cloud_workload have no workspace-led
	// UNIQUE for a composite key to name.
	bfkNoScopeKey = ". Proposed: first UNIQUE (workspace_id, connector_id, id) on the parent " +
		"(cloud_<parent>_scope_key, as 035 gave cloud_identity and cloud_policy), then "
	bfkObservationSubject = "024: subject key re-declared single-column (ON DELETE SET NULL); 027 converted " +
		"only run and connector"
)

// bfkLegacySingleColumn: the single-column references to workspace-scoped
// tables that §2.9 forbids and 027-036 did not convert. They are spec questions
// (P2-DECISIONS D-95), not accepted design. Each is covered by a bfkLegacy
// case that demonstrates the gap (SKIP) rather than asserting it, and the
// guard states the whole list (known_gap_open_section_2_9_exemptions).
var bfkLegacySingleColumn = map[string]string{
	"iga_observations_delivery_fkey": "004: iga_webhook_deliveries has no UNIQUE (workspace_id, id) and a " +
		"nullable workspace_id (a delivery is stored before it is bound), so no composite key can name an " +
		"unbound one. Needs a ruling on whether an observation may cite an unbound delivery",
	"cloud_identity_connector_id_fkey": "011: never converted. 035 added cloud_identity_scope_key " +
		"(workspace_id, connector_id, id) as a target, but the row's own (workspace_id, connector_id) pair " +
		"is anchored only by this single-column key" + bfkConnectorProposal,
	"cloud_observation_identity_id_fkey": bfkObservationSubject + ". A single-column reference to " +
		"cloud_identity on a table B20 covers. Proposed: (workspace_id, connector_id, identity_id) REFERENCES " +
		"cloud_identity (workspace_id, connector_id, id) ON DELETE SET NULL (identity_id)",
	"cloud_observation_permission_id_fkey": bfkObservationSubject + bfkNoScopeKey + "(workspace_id, " +
		"connector_id, permission_id) REFERENCES cloud_permission (workspace_id, connector_id, id) " +
		"ON DELETE SET NULL (permission_id)",
	"cloud_observation_resource_id_fkey": bfkObservationSubject + bfkNoScopeKey + "(workspace_id, " +
		"connector_id, resource_id) REFERENCES cloud_resource (workspace_id, connector_id, id) " +
		"ON DELETE SET NULL (resource_id)",
	"cloud_observation_workload_id_fkey": bfkObservationSubject + bfkNoScopeKey + "(workspace_id, " +
		"connector_id, workload_id) REFERENCES cloud_workload (workspace_id, connector_id, id) " +
		"ON DELETE SET NULL (workload_id)",

	// Phase 1's cloud_* tables (bfkCloudTables): 027-036 converted none of them.
	"cloud_secret_connector_id_fkey":          "011" + bfkPhase1Connector,
	"cloud_secret_identity_id_fkey":           "011" + bfkPhase1Identity,
	"cloud_assume_edge_connector_id_fkey":     "012" + bfkPhase1Connector,
	"cloud_assume_edge_identity_id_fkey":      "012" + bfkPhase1Identity,
	"cloud_permission_connector_id_fkey":      "013" + bfkPhase1Connector,
	"cloud_permission_identity_id_fkey":       "013" + bfkPhase1Identity,
	"cloud_resource_connector_id_fkey":        "013" + bfkPhase1Connector,
	"cloud_workload_connector_id_fkey":        "015" + bfkPhase1Connector,
	"cloud_usage_connector_id_fkey":           "016" + bfkPhase1Connector,
	"cloud_usage_identity_id_fkey":            "016" + bfkPhase1Identity,
	"cloud_scan_checkpoint_connector_id_fkey": "017" + bfkPhase1Connector,
	// 015 declared it ON DELETE SET NULL: a workload outlives its role.
	"cloud_workload_identity_id_fkey": "015: Phase 1, never converted; a single-column reference to " +
		"cloud_identity (B20's Catches). Proposed: (workspace_id, connector_id, identity_id) REFERENCES " +
		"cloud_identity (workspace_id, connector_id, id) ON DELETE SET NULL (identity_id), against 035's " +
		"cloud_identity_scope_key",
	"cloud_permission_resource_id_fkey": "013: Phase 1, never converted" + bfkNoScopeKey + "(workspace_id, " +
		"connector_id, resource_id) REFERENCES cloud_resource (workspace_id, connector_id, id) ON DELETE CASCADE",
}

// bfkNoForeignKey: the uuid columns in scope that reference nothing at all.
// That is worse than a single-column key: the A3 pattern of a bare uuid.
// Listing them keeps a new one from landing unreviewed. The polymorphic
// (kind, id) pairs are 004's GitHub path and are not graph references.
var bfkNoForeignKey = map[string]string{
	"iga_access_edges.subject_id":              "004 polymorphic (subject_kind, subject_id); 030's typed subject_identity_account_id carries the key",
	"iga_canonical_attribute_values.entity_id": "004 polymorphic (entity_kind, entity_id)",
	"iga_correlations.canonical_id":            "004 polymorphic (canonical_kind, canonical_id)",
	"iga_observation_links.target_id":          "004 polymorphic (target_kind, target_id); P2-1 forbids new writers",
	"iga_ownership_candidates.subject_id":      "004 polymorphic (subject_kind, subject_id)",
	"iga_workload_classification.operation_id": "029: a client-generated idempotency key (§5.5), not a reference",
	"iga_workload_classification.decided_by_user_id": "029 (spec verbatim): the deciding user's id; users is " +
		"not an iga_* table and §3 declares no key",
	"iga_agent_instances.linked_by": "042: the human who registered the instance. users is not an iga_* table; " +
		"recorded like iga_workload_classification.decided_by_user_id, not a foreign key",
	"iga_agent_instances.owner_user_id": "042: the accountable owner named by the registration. Same bare-uuid " +
		"treatment as linked_by",
	"iga_webhook_deliveries.integration_id": "004: filled when a delivery binds; SPEC QUESTION: no key",
	"iga_source_objects.integration_scope_id": "004: SPEC QUESTION: no key to iga_integration_scopes " +
		"(workspace_id, id)",
	"iga_pipeline_lease.scan_run_id": "027: SPEC QUESTION: no key at all, so a barrier can name another " +
		"workspace's run or none (§2.9)",
	// 040: copied watermarks, not parents. collector_snapshots.epoch is not
	// unique (many snapshots share one epoch). snapshot_id is unique only
	// together with workspace_id and collector_id. The fence compares
	// generation, then snapshot_id. Neither column is a foreign key.
	"iga_projection_state.ordering_epoch": "040: ordering watermark copied from the collector snapshot's epoch. " +
		"Not a foreign key: epoch is not unique on collector_snapshots",
	"iga_projection_state.ordering_snapshot": "040: snapshot_id that set the generation watermark. " +
		"Not a foreign key: collector_snapshots uniqueness is (workspace_id, collector_id, snapshot_id)",
	"cloud_identity.workspace_id": "011: SPEC QUESTION: anchored by nothing. cloud_identity_connector_id_fkey " +
		"is single-column, so an identity can name a workspace that does not exist, or one its connector " +
		"is not in, and 035's cloud_identity_scope_key then pairs that workspace with that connector",
	"cloud_connector.workspace_id": "001 and 010: SPEC QUESTION: no key to workspaces. Every (workspace_id, " +
		"connector_id) reference 027-036 added is against cloud_connector (workspace_id, id), so it proves " +
		"the pair agrees, not that the workspace exists",

	// Phase 1's tables: the workspace_id no key covers, because each table's
	// connector reference is single-column (bfkLegacySingleColumn).
	"cloud_secret.workspace_id":          "011" + bfkPhase1Workspace,
	"cloud_assume_edge.workspace_id":     "012" + bfkPhase1Workspace,
	"cloud_permission.workspace_id":      "013" + bfkPhase1Workspace,
	"cloud_resource.workspace_id":        "013" + bfkPhase1Workspace,
	"cloud_workload.workspace_id":        "015" + bfkPhase1Workspace,
	"cloud_usage.workspace_id":           "016" + bfkPhase1Workspace,
	"cloud_scan_checkpoint.workspace_id": "017" + bfkPhase1Workspace,
}

// bfkPhase1Workspace: why a Phase 1 table's workspace_id is bare.
const bfkPhase1Workspace = ": Phase 1, SPEC QUESTION: anchored by nothing. The connector key is single-column, " +
	"so nothing ties the row's workspace to its connector's; the composite connector reference proposed in " +
	"bfkLegacySingleColumn would"

/* -------------------------------- catalog --------------------------------- */

// bfkFK is one foreign key as pg_constraint states it.
type bfkFK struct {
	table, name, refTable string
	cols, refCols         []string
	deferred              bool // DEFERRABLE INITIALLY DEFERRED
	refScoped             bool // the referenced table has a workspace_id column
}

type bfkQuerier interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

// bfkForeignKeys reads every foreign key in scope, keyed by constraint name:
// every key whose child is an iga_* or cloud_* table, and every key from any
// other table whose parent is one. The scope is by name, not by form, so a
// table written entirely in the pre-§2.9 form is in it (the A3 pattern), and
// so is a reference into the graph from a table outside it. A reference from
// outside the graph to outside it (Discovery's own keys, say) is not.
func bfkForeignKeys(t *testing.T, q bfkQuerier) map[string]bfkFK {
	t.Helper()
	rows, err := q.Query(`
		SELECT r.relname::text, c.conname::text, fr.relname::text,
		       ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY AS k(num, ord)
		               JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.num ORDER BY k.ord),
		       ARRAY(SELECT a.attname::text FROM unnest(c.confkey) WITH ORDINALITY AS k(num, ord)
		               JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.num ORDER BY k.ord),
		       c.condeferrable AND c.condeferred,
		       EXISTS (SELECT 1 FROM pg_attribute a
		                WHERE a.attrelid = c.confrelid AND a.attname = 'workspace_id' AND NOT a.attisdropped)
		  FROM pg_constraint c
		  JOIN pg_class r      ON r.oid = c.conrelid
		  JOIN pg_namespace n  ON n.oid = r.relnamespace
		  JOIN pg_class fr     ON fr.oid = c.confrelid
		 WHERE c.contype = 'f' AND n.nspname = 'public'
		   AND (r.relname LIKE 'iga\_%' OR r.relname LIKE 'cloud\_%'
		        OR fr.relname LIKE 'iga\_%' OR fr.relname LIKE 'cloud\_%')`)
	if err != nil {
		t.Fatalf("read foreign keys: %v", err)
	}
	defer rows.Close()
	out := map[string]bfkFK{}
	for rows.Next() {
		var fk bfkFK
		var cols, refCols pq.StringArray
		if err := rows.Scan(&fk.table, &fk.name, &fk.refTable, &cols, &refCols, &fk.deferred, &fk.refScoped); err != nil {
			t.Fatalf("scan foreign key: %v", err)
		}
		fk.cols, fk.refCols = cols, refCols
		out[fk.name] = fk
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read foreign keys: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("the catalog holds no foreign keys in scope; the schema was not built")
	}
	return out
}

// bfkShape is the kind a foreign key's own definition implies. A case whose
// kind differs would skip the subtest its key needs, for example a B20
// reference tested for cross-workspace only.
func bfkShape(fk bfkFK) bfkKind {
	switch {
	case fk.refTable == "workspaces":
		return bfkAnchor
	case len(fk.cols) == 1:
		return bfkLegacy
	case len(fk.cols) >= 3 && fk.cols[1] == "connector_id" && fk.refCols[1] == "connector_id":
		return bfkIntegration
	default:
		return bfkWorkspace
	}
}

// bfkCoViolated names the other foreign keys of fk's table that the foreign
// row breaks by construction. The foreign row changes one column: the
// reference's own, which is the last of the key's columns (workspace_id and,
// for an integration-qualified key, connector_id are the child's own and stay
// A's; for the anchor it is workspace_id itself). Every other key over that
// column breaks with it, as long as all of its columns are non-NULL (MATCH
// SIMPLE skips the rest).
func bfkCoViolated(fks map[string]bfkFK, fk bfkFK, row bfkRow) []string {
	changed := fk.cols[len(fk.cols)-1]
	var out []string
	for _, other := range fks {
		if other.table != fk.table || other.name == fk.name {
			continue
		}
		if slices.Contains(other.cols, changed) && row.setsAll(other.cols) {
			out = append(out, other.name)
		}
	}
	sort.Strings(out)
	return out
}

/* --------------------------------- probe ---------------------------------- */

// attempt inserts row in a transaction of its own and rolls it back, so no
// subtest sees another's rows. It first drops the constraints in lift inside
// that transaction (the rollback restores them). Deferred constraints are
// forced with SET CONSTRAINTS ALL IMMEDIATE, so nil means every constraint
// accepted the row. Harness failures are fatal. The database's answer is
// returned.
func (w *bfkWorld) attempt(t *testing.T, row bfkRow, lift []string) error {
	t.Helper()
	tx, err := w.f.db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, name := range lift {
		if _, err := tx.Exec(fmt.Sprintf("ALTER TABLE %s DROP CONSTRAINT %s",
			pq.QuoteIdentifier(row.table), pq.QuoteIdentifier(name))); err != nil {
			t.Fatalf("lift %s: %v", name, err)
		}
	}
	if err := bfkInsert(tx, row); err != nil {
		return err
	}
	_, err = tx.Exec(`SET CONSTRAINTS ALL IMMEDIATE`)
	return err
}

// attemptCommit inserts row and COMMITs: the path a deferred constraint is
// checked on. It returns the INSERT's and the COMMIT's answers separately.
func (w *bfkWorld) attemptCommit(t *testing.T, row bfkRow) (insertErr, commitErr error) {
	t.Helper()
	tx, err := w.f.db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := bfkInsert(tx, row); err != nil {
		_ = tx.Rollback()
		return err, nil
	}
	return nil, tx.Commit()
}

// bfkWantFK requires err to be SQLSTATE 23503 raised by constraint.
func bfkWantFK(t *testing.T, err error, constraint string) {
	t.Helper()
	if err == nil {
		t.Fatalf("the database ACCEPTED the row; %s must reject it", constraint)
	}
	var pe *pq.Error
	if !errors.As(err, &pe) {
		t.Fatalf("want SQLSTATE 23503 from %s, got a non-database error: %v", constraint, err)
	}
	if pe.Code != "23503" || pe.Constraint != constraint {
		t.Fatalf("want SQLSTATE 23503 from %s, got %s from %q: %s", constraint, pe.Code, pe.Constraint, pe.Message)
	}
}

// mustReject requires fk, and only fk, to refuse row.
func (w *bfkWorld) mustReject(t *testing.T, fks map[string]bfkFK, c bfkCase, fk bfkFK, row bfkRow) {
	t.Helper()
	lift := bfkCoViolated(fks, fk, row)
	if c.deferred {
		// Never COMMIT with a lifted constraint: an unexpected success would
		// make the drop permanent. No deferred key needs one today.
		if len(lift) > 0 {
			t.Fatalf("harness: deferred %s would need %v lifted", fk.name, lift)
		}
		insertErr, commitErr := w.attemptCommit(t, row)
		if insertErr != nil {
			t.Fatalf("deferred %s refused the INSERT (%v); 036 needs it to wait for COMMIT, "+
				"where the publication row lands in the same transaction", fk.name, insertErr)
		}
		bfkWantFK(t, commitErr, fk.name)
		return
	}
	if len(lift) > 0 {
		t.Logf("lifted, co-violated by construction: %s", strings.Join(lift, ", "))
	}
	bfkWantFK(t, w.attempt(t, row, lift), fk.name)
}

/* --------------------------------- B9/B20 --------------------------------- */

// TestB9B20ForeignKeysRejectForeignRows runs every case in bfkCases.
func TestB9B20ForeignKeysRejectForeignRows(t *testing.T) {
	w := bfkNewWorld(t)
	fks := bfkForeignKeys(t, w.f.db)
	for _, c := range bfkCases {
		t.Run(c.fk, func(t *testing.T) {
			fk, ok := fks[c.fk]
			if !ok {
				t.Fatalf("%s is not a foreign key in the schema", c.fk)
			}
			if c.deferred != fk.deferred {
				t.Fatalf("%s: case says deferred=%v, catalog says %v", c.fk, c.deferred, fk.deferred)
			}
			// The kind picks the negatives, so a wrong one would silently skip
			// B20's foreign_integration. Not fatal: the probes below still run
			// and show what the key actually does.
			if shape := bfkShape(fk); shape != c.kind {
				t.Errorf("%s: case kind %s, but the catalog's key is %s-shaped", c.fk, c.kind, shape)
			}
			t.Run("control", func(t *testing.T) {
				if err := w.attempt(t, c.build(w, w.A), nil); err != nil {
					t.Fatalf("the same-workspace, same-integration control was rejected: %v", err)
				}
			})
			switch c.kind {
			case bfkWorkspace, bfkIntegration:
				t.Run("foreign_workspace", func(t *testing.T) {
					w.mustReject(t, fks, c, fk, c.build(w, w.B))
				})
				if c.kind == bfkIntegration {
					t.Run("foreign_integration", func(t *testing.T) {
						w.mustReject(t, fks, c, fk, c.build(w, w.A2))
					})
				}
			case bfkAnchor:
				t.Run("absent_workspace", func(t *testing.T) {
					w.mustReject(t, fks, c, fk, c.build(w, w.absent))
				})
			case bfkLegacy:
				t.Run("absent_parent", func(t *testing.T) {
					w.mustReject(t, fks, c, fk, c.build(w, w.absent))
				})
				t.Run("known_gap_foreign_workspace_admitted", func(t *testing.T) {
					// The same lifting as mustReject, so the answer is this key's
					// alone. Without it, converting ANOTHER key on the same
					// column (cloud_usage's identity key, which carries
					// connector_id once composite) would refuse the row and read
					// as this key's gap closing.
					row := c.build(w, w.B)
					lift := bfkCoViolated(fks, fk, row)
					if len(lift) > 0 {
						t.Logf("lifted, co-violated by construction: %s", strings.Join(lift, ", "))
					}
					if err := w.attempt(t, row, lift); err != nil {
						var pe *pq.Error
						if errors.As(err, &pe) && pe.Constraint == fk.name {
							t.Fatalf("%s now rejects another workspace's parent (%v): the §2.9 gap is closed, so "+
								"move it from bfkLegacySingleColumn to a composite case", fk.name, err)
						}
						t.Fatalf("harness: workspace B's parent for %s was refused by something else: %v", fk.name, err)
					}
					// Admitted, as pinned. SKIP, not PASS: what this subtest
					// shows is that B9 does NOT hold for this key, and a green
					// run must not read as if it did.
					t.Skipf("KNOWN GAP (§2.9, spec question): %s ADMITTED workspace B's parent for a row in A. %s",
						fk.name, bfkLegacySingleColumn[fk.name])
				})
			}
		})
	}
}

/* ------------------------------ catalog guard ------------------------------ */

// bfkCoverageProblems: every foreign key has exactly one case of the right kind
// and deferral, and every case names a foreign key.
func bfkCoverageProblems(fks map[string]bfkFK) []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range bfkCases {
		if seen[c.fk] {
			out = append(out, fmt.Sprintf("%s has two cases", c.fk))
		}
		seen[c.fk] = true
		fk, ok := fks[c.fk]
		if !ok {
			out = append(out, fmt.Sprintf("case %s names no foreign key in the schema", c.fk))
			continue
		}
		if shape := bfkShape(fk); c.kind != shape {
			out = append(out, fmt.Sprintf("%s (%s(%s) -> %s(%s)): case kind %s, but its shape is %s",
				fk.name, fk.table, strings.Join(fk.cols, ","), fk.refTable, strings.Join(fk.refCols, ","), c.kind, shape))
		}
		if c.deferred != fk.deferred {
			out = append(out, fmt.Sprintf("%s: case deferred=%v, catalog deferred=%v", fk.name, c.deferred, fk.deferred))
		}
	}
	for name, fk := range fks {
		if !seen[name] {
			out = append(out, fmt.Sprintf("%s on %s(%s) has no subtest: add a bfkCases entry",
				name, fk.table, strings.Join(fk.cols, ",")))
		}
	}
	sort.Strings(out)
	return out
}

// bfkSingleColumnProblems is §2.9's rule: no single-column foreign key to a
// workspace-scoped table, except the listed legacy ones. The list must be
// exact, so an exemption cannot outlive its gap.
func bfkSingleColumnProblems(fks map[string]bfkFK) []string {
	var out []string
	for name, fk := range fks {
		if len(fk.cols) != 1 || !fk.refScoped {
			continue
		}
		if _, exempt := bfkLegacySingleColumn[name]; !exempt {
			out = append(out, fmt.Sprintf("§2.9: %s is a single-column reference %s(%s) -> %s(%s), "+
				"and %s is workspace-scoped", name, fk.table, fk.cols[0], fk.refTable, fk.refCols[0], fk.refTable))
		}
	}
	for name := range bfkLegacySingleColumn {
		if fk, ok := fks[name]; !ok || len(fk.cols) != 1 || !fk.refScoped {
			out = append(out, fmt.Sprintf("exemption %s no longer matches the schema: remove it", name))
		}
	}
	sort.Strings(out)
	return out
}

// bfkQualificationProblems: a composite reference to a workspace-scoped table
// pairs the child's workspace_id with the parent's. A reference to a collection
// fact (a cloud_identity or cloud_policy row, keyed per integration since 035)
// also pairs connector_id with connector_id (B20). A composite key that led
// with some other column would pass the single-column rule and still admit
// another workspace's row.
func bfkQualificationProblems(fks map[string]bfkFK) []string {
	var out []string
	for name, fk := range fks {
		if !fk.refScoped {
			continue
		}
		if len(fk.cols) > 1 && (fk.cols[0] != "workspace_id" || fk.refCols[0] != "workspace_id") {
			out = append(out, fmt.Sprintf("%s: (%s) -> %s(%s) does not pair workspace_id with workspace_id",
				name, strings.Join(fk.cols, ","), fk.refTable, strings.Join(fk.refCols, ",")))
		}
		if _, legacy := bfkLegacySingleColumn[name]; legacy {
			continue
		}
		if (fk.refTable == "cloud_identity" || fk.refTable == "cloud_policy") && bfkShape(fk) != bfkIntegration {
			out = append(out, fmt.Sprintf("%s: a reference to a %s row must be (workspace_id, connector_id, id) (B20), "+
				"got (%s)", name, fk.refTable, strings.Join(fk.cols, ",")))
		}
	}
	sort.Strings(out)
	return out
}

// bfkBareUUIDColumns lists table.column for every uuid column of an iga_* or
// cloud_* table, other than a table's own id, that no foreign key covers.
func bfkBareUUIDColumns(t *testing.T, q bfkQuerier) []string {
	t.Helper()
	rows, err := q.Query(`
		SELECT r.relname::text || '.' || a.attname::text
		  FROM pg_class r
		  JOIN pg_namespace n ON n.oid = r.relnamespace
		  JOIN pg_attribute a ON a.attrelid = r.oid AND a.attnum > 0 AND NOT a.attisdropped
		 WHERE n.nspname = 'public' AND r.relkind = 'r'
		   AND a.atttypid = 'uuid'::regtype AND a.attname <> 'id'
		   AND (r.relname LIKE 'iga\_%' OR r.relname LIKE 'cloud\_%')
		   AND NOT EXISTS (SELECT 1 FROM pg_constraint c
		                    WHERE c.contype = 'f' AND c.conrelid = r.oid AND a.attnum = ANY (c.conkey))
		 ORDER BY 1`)
	if err != nil {
		t.Fatalf("read uuid columns: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			t.Fatalf("scan uuid column: %v", err)
		}
		out = append(out, col)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read uuid columns: %v", err)
	}
	return out
}

// bfkCloudTablesInCatalog lists every cloud_* table, whatever its keys: a
// table with none at all, or with single-column ones only, is listed too.
func bfkCloudTablesInCatalog(t *testing.T, q bfkQuerier) []string {
	t.Helper()
	rows, err := q.Query(`
		SELECT r.relname::text
		  FROM pg_class r
		  JOIN pg_namespace n ON n.oid = r.relnamespace
		 WHERE n.nspname = 'public' AND r.relkind IN ('r', 'p') AND r.relname LIKE 'cloud\_%'
		 ORDER BY 1`)
	if err != nil {
		t.Fatalf("read cloud tables: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan table: %v", err)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read cloud tables: %v", err)
	}
	return out
}

// bfkCloudTableProblems: bfkCloudTables is exactly the catalog's cloud_* tables.
func bfkCloudTableProblems(inCatalog []string) []string {
	var out []string
	for _, name := range inCatalog {
		if _, known := bfkCloudTables[name]; !known {
			out = append(out, fmt.Sprintf("%s is a cloud_* table bfkCloudTables does not classify: say whether "+
				"its references are Phase 1's or Phase 2's, and give each of its foreign keys a case", name))
		}
	}
	for name := range bfkCloudTables {
		if !slices.Contains(inCatalog, name) {
			out = append(out, fmt.Sprintf("%s is in bfkCloudTables but not in the schema: remove it", name))
		}
	}
	sort.Strings(out)
	return out
}

// bfkGapGroups are the open exemptions grouped the way evidence has to state
// them: by where they sit (the Phase 2 cloud_* tables B9 and B20 cover,
// Phase 1's cloud_* tables, the iga_* tables, any other table) and, across all
// of them, the single-column references to cloud_identity that B20's
// "Catches" names. Each list is sorted.
type bfkGapGroups struct {
	phase2, phase1, iga, other, identity []string
}

// bfkOpenGaps groups bfkLegacySingleColumn. Whether that list is exact is
// bfkSingleColumnProblems' job.
func bfkOpenGaps(fks map[string]bfkFK) bfkGapGroups {
	var g bfkGapGroups
	for name := range bfkLegacySingleColumn {
		fk := fks[name]
		class, cloud := bfkCloudTables[fk.table]
		switch {
		case cloud && class.phase2:
			g.phase2 = append(g.phase2, name)
		case cloud:
			g.phase1 = append(g.phase1, name)
		case strings.HasPrefix(fk.table, "iga_"):
			g.iga = append(g.iga, name)
		default:
			g.other = append(g.other, name)
		}
		if fk.refTable == "cloud_identity" {
			g.identity = append(g.identity, name)
		}
	}
	for _, names := range [][]string{g.phase2, g.phase1, g.iga, g.other, g.identity} {
		sort.Strings(names)
	}
	return g
}

// located is every exemption, each in the one group for where it sits.
func (g bfkGapGroups) located() [][]string { return [][]string{g.phase2, g.phase1, g.iga, g.other} }

func bfkGapList(names []string) string {
	if len(names) == 0 {
		return "(0) none"
	}
	return fmt.Sprintf("(%d) %s", len(names), strings.Join(names, ", "))
}

func (g bfkGapGroups) String() string {
	return fmt.Sprintf("%d single-column references to workspace-scoped tables ADMIT another workspace's parent "+
		"(§2.9; spec questions, P2-DECISIONS D-95, proposed DDL in bfkLegacySingleColumn). "+
		"On Phase 2 cloud_* tables %s. On Phase 1 cloud_* tables %s. On iga_* tables %s. On other tables %s. "+
		"Among them, the single-column references to cloud_identity that B20 says it catches %s",
		len(bfkLegacySingleColumn), bfkGapList(g.phase2), bfkGapList(g.phase1), bfkGapList(g.iga),
		bfkGapList(g.other), bfkGapList(g.identity))
}

// bfkGapStatementProblems: the statement names every exemption exactly once
// by location, and every exempt reference to cloud_identity in B20's group, so
// evidence quoted from a run cannot silently drop one.
func bfkGapStatementProblems(fks map[string]bfkFK, g bfkGapGroups) []string {
	var out []string
	stated := g.String()
	placed := map[string]int{}
	for _, names := range g.located() {
		if !strings.Contains(stated, bfkGapList(names)) {
			out = append(out, fmt.Sprintf("the known-gap statement omits the group %s", bfkGapList(names)))
		}
		for _, name := range names {
			placed[name]++
		}
	}
	if !strings.Contains(stated, bfkGapList(g.identity)) {
		out = append(out, fmt.Sprintf("the known-gap statement omits B20's group %s", bfkGapList(g.identity)))
	}
	for name := range bfkLegacySingleColumn {
		if placed[name] != 1 {
			out = append(out, fmt.Sprintf("the known-gap statement places %s %d times, not once", name, placed[name]))
		}
		if fks[name].refTable == "cloud_identity" && !slices.Contains(g.identity, name) {
			out = append(out, fmt.Sprintf("%s references cloud_identity but is missing from B20's group", name))
		}
	}
	sort.Strings(out)
	return out
}

func bfkBareUUIDProblems(bare []string) []string {
	var out []string
	for _, col := range bare {
		if _, listed := bfkNoForeignKey[col]; !listed {
			out = append(out, fmt.Sprintf("%s is a uuid that references nothing: give it a composite key, "+
				"or list it in bfkNoForeignKey with its reason", col))
		}
	}
	for col := range bfkNoForeignKey {
		if !slices.Contains(bare, col) {
			out = append(out, fmt.Sprintf("%s is no longer a bare uuid: remove it from bfkNoForeignKey", col))
		}
	}
	sort.Strings(out)
	return out
}

// bfkMentions reports whether one problem names every part: the planted
// object AND the check's own wording, so a problem raised for some other
// reason about the same object does not count.
func bfkMentions(problems []string, parts ...string) bool {
	for _, p := range problems {
		all := true
		for _, part := range parts {
			all = all && strings.Contains(p, part)
		}
		if all {
			return true
		}
	}
	return false
}

// TestB9ForeignKeyCatalogGuard is what makes B9's "every composite FK" true:
// the subtests above cover exactly what the catalog holds, and the rule
// they test holds for every key in scope.
func TestB9ForeignKeyCatalogGuard(t *testing.T) {
	w := bfkNewWorld(t)
	fks := bfkForeignKeys(t, w.f.db)
	t.Logf("%d foreign keys in scope, %d cases", len(fks), len(bfkCases))

	t.Run("every_foreign_key_has_a_subtest", func(t *testing.T) {
		for _, p := range bfkCoverageProblems(fks) {
			t.Error(p)
		}
	})
	t.Run("no_single_column_reference_to_a_workspace_scoped_table", func(t *testing.T) {
		for _, p := range bfkSingleColumnProblems(fks) {
			t.Error(p)
		}
	})
	t.Run("every_composite_reference_is_workspace_qualified", func(t *testing.T) {
		for _, p := range bfkQualificationProblems(fks) {
			t.Error(p)
		}
	})
	t.Run("no_bare_uuid_reference", func(t *testing.T) {
		for _, p := range bfkBareUUIDProblems(bfkBareUUIDColumns(t, w.f.db)) {
			t.Error(p)
		}
	})
	t.Run("every_cloud_table_is_classified", func(t *testing.T) {
		for _, p := range bfkCloudTableProblems(bfkCloudTablesInCatalog(t, w.f.db)) {
			t.Error(p)
		}
	})
	// What a green run does NOT show (header: WHAT A GREEN RUN DOES NOT SHOW).
	// SKIP, not PASS, while any exemption stands, naming every one grouped, so
	// evidence written from this run cannot claim that §2.9 holds. A statement
	// that dropped one would FAIL here instead.
	t.Run("known_gap_open_section_2_9_exemptions", func(t *testing.T) {
		if len(bfkLegacySingleColumn) == 0 {
			return // §2.9 holds for every key in scope: nothing to state
		}
		gaps := bfkOpenGaps(fks)
		for _, p := range bfkGapStatementProblems(fks, gaps) {
			t.Error(p)
		}
		t.Skipf("NOT DEMONSTRATED: %s", gaps)
	})

	// Non-vacuity, rerun on every run: plant the A3 pattern in a rolled-back
	// transaction and require the guard AND the probe to see it. The planted
	// key replaces cloud_pa_principal_fkey with the single-column form a
	// careless migration would write. It keeps the name, so only the checks
	// on shape can notice. Beside it:
	//   - a bare uuid column, and a new composite key no case covers that pairs
	//     the child's workspace_id with the parent's id;
	//   - a new cloud_* table written the Phase 1 way, with single-column
	//     references only, to cloud_connector, cloud_identity and cloud_policy
	//     (review of bfk: the guard once derived its cloud scope from composite
	//     keys, so this table was invisible to every check), and one to a
	//     workspace-scoped table outside the graph (discovered_agents). No
	//     cloud_* key at 036 points outside the graph, so only that last one
	//     shows the child-side scope (r.relname LIKE 'cloud\_%') is needed: the
	//     others are read through their parent either way;
	//   - a new single-column reference to cloud_policy from a Phase 1 table,
	//     and one to cloud_identity from a table outside the graph.
	t.Run("a_planted_single_column_reference_is_caught", func(t *testing.T) {
		tx, err := w.f.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		for _, ddl := range []string{
			`ALTER TABLE cloud_policy_attachment DROP CONSTRAINT cloud_pa_principal_fkey,
			   ADD CONSTRAINT cloud_pa_principal_fkey FOREIGN KEY (principal_identity_id)
			   REFERENCES cloud_identity (id) ON DELETE CASCADE`,
			`ALTER TABLE iga_policy ADD COLUMN bfk_planted_run_id uuid`,
			// Every existing row's new column is NULL, so MATCH SIMPLE lets the
			// key be added. The column order is what is wrong with it.
			`ALTER TABLE iga_policy ADD COLUMN bfk_planted_conn_id uuid,
			   ADD CONSTRAINT bfk_planted_misqualified_fkey FOREIGN KEY (workspace_id, bfk_planted_conn_id)
			   REFERENCES cloud_connector (id, workspace_id)`,
			// Column-level REFERENCES, as a careless migration writes them:
			// PostgreSQL names each key <table>_<column>_fkey.
			`CREATE TABLE cloud_bfk_planted (
			   id uuid PRIMARY KEY, workspace_id uuid NOT NULL,
			   connector_id uuid NOT NULL REFERENCES cloud_connector (id),
			   identity_id uuid NOT NULL REFERENCES cloud_identity (id),
			   policy_row_id uuid REFERENCES cloud_policy (id),
			   agent_ref_id uuid REFERENCES discovered_agents (id))`,
			`ALTER TABLE cloud_workload ADD COLUMN bfk_planted_policy_id uuid REFERENCES cloud_policy (id)`,
			`ALTER TABLE discovered_agents ADD COLUMN bfk_planted_identity_id uuid REFERENCES cloud_identity (id)`,
		} {
			if _, err := tx.Exec(ddl); err != nil {
				t.Fatalf("plant: %v", err)
			}
		}
		planted := bfkForeignKeys(t, tx)
		if !bfkMentions(bfkSingleColumnProblems(planted), "cloud_pa_principal_fkey", "single-column reference") {
			t.Error("the single-column rule did not report the planted cloud_pa_principal_fkey")
		}
		if !bfkMentions(bfkCoverageProblems(planted), "cloud_pa_principal_fkey", "but its shape is legacy") {
			t.Error("the coverage check did not see that cloud_pa_principal_fkey changed shape")
		}
		if !bfkMentions(bfkQualificationProblems(planted), "cloud_pa_principal_fkey", "(B20)") {
			t.Error("the qualification check did not report the planted cloud_pa_principal_fkey")
		}
		if !bfkMentions(bfkCoverageProblems(planted), "bfk_planted_misqualified_fkey", "has no subtest") {
			t.Error("the coverage check did not report the planted, uncovered bfk_planted_misqualified_fkey")
		}
		if !bfkMentions(bfkQualificationProblems(planted), "bfk_planted_misqualified_fkey",
			"does not pair workspace_id with workspace_id") {
			t.Error("the qualification check did not report bfk_planted_misqualified_fkey pairing workspace_id with id")
		}
		bare := bfkBareUUIDProblems(bfkBareUUIDColumns(t, tx))
		for _, col := range []string{"iga_policy.bfk_planted_run_id", "cloud_bfk_planted.workspace_id"} {
			if !bfkMentions(bare, col, "references nothing") {
				t.Errorf("the bare-uuid check did not report the planted %s", col)
			}
		}
		if !bfkMentions(bfkCloudTableProblems(bfkCloudTablesInCatalog(t, tx)), "cloud_bfk_planted", "does not classify") {
			t.Error("the table check did not report the planted, unclassified cloud_bfk_planted")
		}
		// The A3 pattern outside the tables that were already in §2.9's form.
		// Every one is a single-column reference no exemption lists and no case
		// covers; the ones to a collection fact also break B20.
		for _, p := range []struct {
			fk  string
			b20 bool
		}{
			{"cloud_bfk_planted_connector_id_fkey", false},
			{"cloud_bfk_planted_identity_id_fkey", true},
			{"cloud_bfk_planted_policy_row_id_fkey", true},
			{"cloud_bfk_planted_agent_ref_id_fkey", false},
			{"cloud_workload_bfk_planted_policy_id_fkey", true},
			{"discovered_agents_bfk_planted_identity_id_fkey", true},
		} {
			if _, ok := planted[p.fk]; !ok {
				t.Errorf("bfkForeignKeys does not read the planted %s: it is outside the guard's scope", p.fk)
				continue
			}
			if !bfkMentions(bfkSingleColumnProblems(planted), p.fk, "single-column reference") {
				t.Errorf("the single-column rule did not report the planted %s", p.fk)
			}
			if !bfkMentions(bfkCoverageProblems(planted), p.fk, "has no subtest") {
				t.Errorf("the coverage check did not report the planted, uncovered %s", p.fk)
			}
			if p.b20 && !bfkMentions(bfkQualificationProblems(planted), p.fk, "(B20)") {
				t.Errorf("the B20 check did not report the planted single-column collection reference %s", p.fk)
			}
		}
		// And the rows cloud_pa_principal_fkey's subtests insert now go in: the
		// probe those subtests run would fail, which is the point of them.
		for _, p := range []*bfkSide{w.B, w.A2} {
			if _, err := tx.Exec(`SAVEPOINT planted`); err != nil {
				t.Fatal(err)
			}
			if err := bfkInsert(tx, w.A.attachment("principal_identity_id", p.id("cuser"))); err != nil {
				t.Errorf("with the planted single-column key, the %s principal was still rejected (%v): "+
					"the probe cannot tell the two keys apart", p.name, err)
			}
			if _, err := tx.Exec(`ROLLBACK TO SAVEPOINT planted`); err != nil {
				t.Fatal(err)
			}
		}
	})

	// B20's own non-vacuity. A collection reference that is workspace-qualified
	// but NOT integration-qualified is the review defect 035 was revised for
	// (§7.6): it passes §2.9's rule and every foreign_workspace negative, and
	// still lets one account's membership name another account's user. Plant
	// it and require the guard to see it, and the probe to show that only the
	// A2 side can tell the two keys apart.
	t.Run("a_planted_workspace_only_collection_reference_is_caught", func(t *testing.T) {
		tx, err := w.f.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		for _, ddl := range []string{
			`ALTER TABLE cloud_identity ADD CONSTRAINT bfk_planted_ws_id_key UNIQUE (workspace_id, id)`,
			`ALTER TABLE cloud_group_membership DROP CONSTRAINT cloud_gm_user_fkey,
			   ADD CONSTRAINT cloud_gm_user_fkey FOREIGN KEY (workspace_id, user_identity_id)
			   REFERENCES cloud_identity (workspace_id, id) ON DELETE CASCADE`,
		} {
			if _, err := tx.Exec(ddl); err != nil {
				t.Fatalf("plant: %v", err)
			}
		}
		planted := bfkForeignKeys(t, tx)
		if !bfkMentions(bfkCoverageProblems(planted), "cloud_gm_user_fkey", "but its shape is workspace") {
			t.Error("the coverage check did not see that cloud_gm_user_fkey lost connector_id")
		}
		if !bfkMentions(bfkQualificationProblems(planted), "cloud_gm_user_fkey", "(B20)") {
			t.Error("the qualification check did not report the workspace-only cloud_gm_user_fkey")
		}
		probe := func(p *bfkSide) error {
			if _, err := tx.Exec(`SAVEPOINT planted`); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := tx.Exec(`ROLLBACK TO SAVEPOINT planted`); err != nil {
					t.Fatal(err)
				}
			}()
			return bfkInsert(tx, w.A.membership("user_identity_id", p.id("cuser")))
		}
		if err := probe(w.A2); err != nil {
			t.Errorf("with the workspace-only key, the A2 user was still rejected (%v): "+
				"foreign_integration cannot tell the two keys apart", err)
		}
		bfkWantFK(t, probe(w.B), "cloud_gm_user_fkey")
	})
}
