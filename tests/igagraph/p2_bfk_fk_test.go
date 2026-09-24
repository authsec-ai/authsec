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
//	foreign_workspace_   enforce, and the cross-workspace row it admits. The
//	admitted             second pins a known gap (spec question).
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
// TestB9ForeignKeyCatalogGuard is what makes "every" true. It reads
// pg_constraint and fails when a foreign key has no case, when a case's kind
// does not match its key's shape, and when any single-column reference to a
// workspace-scoped table is not an exemption listed with its reason.
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

// bfkPhase2CloudTables are the cloud_* tables whose references Phase 2 wrote
// or rewrote. 027 converted cloud_scan_run's and cloud_observation's. 035
// created the collection model and widened cloud_observation with policy_id.
// It also made cloud_identity the target of every integration-qualified
// reference (cloud_identity_scope_key), so its own reference to its
// integration is in scope too. The other cloud_* tables are Phase 1's and are
// not covered here.
var bfkPhase2CloudTables = []string{
	"cloud_scan_run", "cloud_observation", "cloud_identity",
	"cloud_group_membership", "cloud_policy", "cloud_policy_attachment",
}

// bfkLegacySingleColumn: the single-column references to workspace-scoped
// tables that §2.9 forbids and 027-036 did not convert. They are spec questions
// (reported with this test). They are not accepted design. Each is covered by a
// bfkLegacy case that demonstrates the gap rather than asserting it.
var bfkLegacySingleColumn = map[string]string{
	"iga_observations_delivery_fkey": "004: iga_webhook_deliveries has no UNIQUE (workspace_id, id) and a " +
		"nullable workspace_id (a delivery is stored before it is bound)",
	"cloud_identity_connector_id_fkey": "011: never converted. 035 added cloud_identity_scope_key " +
		"(workspace_id, connector_id, id) as a target, but the row's own (workspace_id, connector_id) pair " +
		"is anchored only by this single-column key",
	"cloud_observation_identity_id_fkey":   "024: subject key re-declared single-column (ON DELETE SET NULL); 027 converted only run and connector",
	"cloud_observation_permission_id_fkey": "024: subject key re-declared single-column (ON DELETE SET NULL); 027 converted only run and connector",
	"cloud_observation_resource_id_fkey":   "024: subject key re-declared single-column (ON DELETE SET NULL); 027 converted only run and connector",
	"cloud_observation_workload_id_fkey":   "024: subject key re-declared single-column (ON DELETE SET NULL); 027 converted only run and connector",
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
	"iga_webhook_deliveries.integration_id": "004: filled when a delivery binds; SPEC QUESTION: no key",
	"iga_source_objects.integration_scope_id": "004: SPEC QUESTION: no key to iga_integration_scopes " +
		"(workspace_id, id)",
	"iga_pipeline_lease.scan_run_id": "027: SPEC QUESTION: no key at all, so a barrier can name another " +
		"workspace's run or none (§2.9)",
	"cloud_identity.workspace_id": "011: SPEC QUESTION: anchored by nothing. cloud_identity_connector_id_fkey " +
		"is single-column, so an identity can name a workspace that does not exist, or one its connector " +
		"is not in, and 035's cloud_identity_scope_key then pairs that workspace with that connector",
}

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

// bfkForeignKeys reads every foreign key on the iga_* tables and on
// bfkPhase2CloudTables, keyed by constraint name.
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
		   AND (r.relname LIKE 'iga\_%' OR r.relname = ANY ($1))`, pq.Array(bfkPhase2CloudTables))
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
				t.Run("foreign_workspace_admitted", func(t *testing.T) {
					if err := w.attempt(t, c.build(w, w.B), nil); err != nil {
						t.Fatalf("%s now rejects another workspace's parent (%v): the §2.9 gap is closed, so "+
							"move it from bfkLegacySingleColumn to a composite case", fk.name, err)
					}
					t.Logf("KNOWN GAP (§2.9, spec question): %s admits workspace B's parent for a row in A. %s",
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

// bfkBareUUIDColumns lists table.column for every uuid column in scope, other
// than a table's own id, that no foreign key covers.
func bfkBareUUIDColumns(t *testing.T, q bfkQuerier) []string {
	t.Helper()
	rows, err := q.Query(`
		SELECT r.relname::text || '.' || a.attname::text
		  FROM pg_class r
		  JOIN pg_namespace n ON n.oid = r.relnamespace
		  JOIN pg_attribute a ON a.attrelid = r.oid AND a.attnum > 0 AND NOT a.attisdropped
		 WHERE n.nspname = 'public' AND r.relkind = 'r'
		   AND a.atttypid = 'uuid'::regtype AND a.attname <> 'id'
		   AND (r.relname LIKE 'iga\_%' OR r.relname = ANY ($1))
		   AND NOT EXISTS (SELECT 1 FROM pg_constraint c
		                    WHERE c.contype = 'f' AND c.conrelid = r.oid AND a.attnum = ANY (c.conkey))
		 ORDER BY 1`, pq.Array(bfkPhase2CloudTables))
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

	// Non-vacuity, rerun on every run: plant the A3 pattern in a rolled-back
	// transaction and require the guard AND the probe to see it. The planted
	// key replaces cloud_pa_principal_fkey with the single-column form a
	// careless migration would write. It keeps the name, so only the checks
	// on shape can notice.
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
		} {
			if _, err := tx.Exec(ddl); err != nil {
				t.Fatalf("plant: %v", err)
			}
		}
		planted := bfkForeignKeys(t, tx)
		mentions := func(problems []string, what string) bool {
			for _, p := range problems {
				if strings.Contains(p, what) {
					return true
				}
			}
			return false
		}
		if !mentions(bfkSingleColumnProblems(planted), "cloud_pa_principal_fkey") {
			t.Error("the single-column rule did not report the planted cloud_pa_principal_fkey")
		}
		if !mentions(bfkCoverageProblems(planted), "cloud_pa_principal_fkey") {
			t.Error("the coverage check did not see that cloud_pa_principal_fkey changed shape")
		}
		if !mentions(bfkQualificationProblems(planted), "cloud_pa_principal_fkey") {
			t.Error("the qualification check did not report the planted cloud_pa_principal_fkey")
		}
		if !mentions(bfkBareUUIDProblems(bfkBareUUIDColumns(t, tx)), "iga_policy.bfk_planted_run_id") {
			t.Error("the bare-uuid check did not report the planted iga_policy.bfk_planted_run_id")
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
}
