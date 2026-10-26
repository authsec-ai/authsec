package igagovschema_test

// TestPhase3ForeignKeyCatalogGuard is Phase 3's counterpart of the graph's B9
// guard (tests/igagraph, TestB9ForeignKeyCatalogGuard), which leaves Phase 3's
// tables out of its scope (bfkPhase3Tables) because their rules are §6.1's,
// not the graph spec's §2.9 verbatim. It reads pg_constraint for every Phase 3
// table -- each relation VerifyPolicySchema lists, and any iga_gov_* table by
// prefix, so a new one is caught -- and fails when:
//
//   - a table is not anchored to workspaces(id) ON DELETE CASCADE by its
//     workspace_id (§6.1 "Every table");
//   - a composite reference does not lead with workspace_id on both sides
//     (§6.1 "composite FKs for every cross-object reference");
//   - a single-column reference names anything but workspaces(id), or names
//     users(id) from a column not listed in phase3UserRefs;
//   - a uuid column references nothing and is not listed in phase3BareUUID;
//   - a table with an id has no UNIQUE (workspace_id, id) and is not listed.
//
// The lists record what §6.2's DDL does that the graph's §2.9 forbids, so it
// is visible rather than silently accepted: OPEN QUESTION for the spec owner
// (T3.01 report), not a ruling. A planted table proves each check can fail.

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/lib/pq"

	"github.com/authsec-ai/authsec/services"
)

// phase3UserRefs: single-column references to users(id), as §6.2 writes them.
// users carries a workspace_id, so the graph's §2.9 would require
// (workspace_id, <col>) REFERENCES users (workspace_id, id); whether a member
// of a workspace is always a users row OF that workspace (memberships span
// workspaces) is the open question that decides it.
var phase3UserRefs = map[string]string{
	"cloud_enforcement_binding.consented_by":    "053: who consented to the enforcement role",
	"iga_gov_acceptance.accepted_by":            "051: who accepted the uncertainty",
	"iga_gov_approval.decided_by":               "050: the approver",
	"iga_gov_deployment.emergency_by":           "051: break-glass actor",
	"iga_gov_finding_rule.created_by":           "048",
	"iga_gov_health_report.reported_by":         "051",
	"iga_gov_iac_source.created_by":             "053",
	"iga_gov_owner.created_by":                  "047",
	"iga_gov_owner.user_id":                     "047: the owner (ON DELETE CASCADE)",
	"iga_gov_owner_response.user_id":            "050: the responding owner",
	"iga_gov_owner_review.exception_by":         "050",
	"iga_gov_owner_rule.created_by":             "047",
	"iga_gov_policy.created_by":                 "049: the author (self-approval is refused in code, §2.10)",
	"iga_gov_policy.owner_user_id":              "049 (ON DELETE SET NULL)",
	"iga_gov_policy_version.created_by":         "049: the version's author",
	"iga_gov_settings.updated_by":               "055",
	"iga_gov_validation.created_by":             "051",
	"workspace_slack_integration.installed_by":  "054",
	"slack_user_link.user_id":                   "054: the linked member (ON DELETE CASCADE)",
	"iga_gov_runtime_agentcore_push.pushed_by":  "062: who pushed the runtime policy to AgentCore",
	"iga_gov_runtime_broker_role.created_by":    "062: who registered the broker role",
	"iga_gov_runtime_broker_role.disabled_by":   "062: who disabled the broker role",
	"iga_gov_runtime_hold.decided_by":           "062: who decided the hold",
	"iga_gov_runtime_routing_proof.recorded_by": "062: who recorded the routing proof",
	"iga_gov_runtime_routing_proof.revoked_by":  "062: who revoked the routing proof",
	"iga_gov_runtime_settings.updated_by":       "062: who last changed the runtime settings",
	"iga_gov_runtime_version.created_by":        "062: the runtime version's author",
	"iga_gov_runtime_version.decided_by":        "062: who approved or rejected the runtime version",
	"iga_gov_session_revocation.decided_by":     "061: the revocation's approver",
	"iga_gov_session_revocation.ended_by":       "061: who lifted the revocation",
	"iga_gov_session_revocation.requested_by":   "061: the revocation's requester",
	"iga_gov_access_policy_version.created_by":  "137: who applied the version",
	"iga_gov_azure_access.created_by":           "144: who applied the policy",
	"iga_gov_k8s_access.created_by":             "146: who applied the policy",
	"iga_gov_temp_grant.decided_by":             "061: the grant's approver",
	"iga_gov_temp_grant.ended_by":               "061: who ended the grant",
	"iga_gov_temp_grant.requested_by":           "061: the grant's requester",
}

// phase3BareUUID: uuid columns §6.2 gives no key at all.
var phase3BareUUID = map[string]string{
	"iga_gov_event.policy_id":     "052: append-only audit must outlive, and never block deleting, what it names",
	"iga_gov_event.version_id":    "052: as policy_id",
	"iga_gov_event.deployment_id": "052: as policy_id",
	"iga_gov_event.finding_id":    "052: as policy_id",
	"iga_gov_finding.connector_id": "048: no key declared; (workspace_id, connector_id) REFERENCES " +
		"cloud_connector (workspace_id, id) would fit (spec question)",
	"iga_gov_finding.resolved_by_deployment_id": "048 precedes iga_gov_deployment (051); no key declared " +
		"(spec question: a composite key added in 051)",
	"iga_gov_job.subject_id":                         "052: polymorphic subject, typed by kind",
	"iga_gov_notification.subject_id":                "054: polymorphic subject, typed by subject_kind",
	"iga_gov_runtime_decision.policy_id":             "062: a decision is an append-only record (frozen by trigger) that outlives the policy it applied",
	"iga_gov_runtime_decision.version_id":            "062: as policy_id",
	"iga_gov_runtime_decision.approval_ref":          "062: the idempotency reference of an approved hold's resumed call, not a row key",
	"iga_gov_runtime_decision.human_user_id":         "062: the delegating human from the delegation token, recorded as it was; may be an operator homed in another workspace (ADR-0001 §3)",
	"iga_gov_runtime_hold.human_user_id":             "062: as iga_gov_runtime_decision.human_user_id",
	"iga_gov_runtime_broker_session.human_user_id":   "062: as iga_gov_runtime_decision.human_user_id",
	"iga_gov_temp_grant.connector_id":                "061: the grant is a record of what was attached in AWS; it outlives the connector and is scoped by RLS",
	"iga_gov_temp_grant.identity_account_id":         "061: projected identities are rebuilt by projection; the grant keeps the id it was made for",
	"iga_gov_session_revocation.connector_id":        "061: as iga_gov_temp_grant.connector_id",
	"iga_gov_session_revocation.identity_account_id": "061: as iga_gov_temp_grant.identity_account_id",
	"iga_gov_azure_access.connector_id":              "144: as iga_gov_temp_grant.connector_id (a record of what was changed in Azure; written from the workspace's own connector under RLS)",
	"iga_gov_azure_access.identity_account_id":       "144: as iga_gov_temp_grant.identity_account_id",
	"iga_gov_k8s_access.connector_id":                "146: the discovery source (in-cluster agent) that acts; as iga_gov_azure_access.connector_id",
	"iga_gov_k8s_access.identity_account_id":         "146: as iga_gov_temp_grant.identity_account_id",
	"iga_gov_k8s_access.instruction_id":              "146: the provisioning_instructions row the job waits on; that table has no UNIQUE (workspace_id, id) to reference, and the job reads it under RLS in its own workspace",
}

// phase3NoWorkspaceIDKey: tables with an id but no UNIQUE (workspace_id, id).
var phase3NoWorkspaceIDKey = map[string]string{
	"iga_gov_event": "052: bigint identity id; an append-only log nothing references",
}

type p3fk struct {
	table, name, refTable string
	cols, refCols         []string
	onDelete              string
}

type p3catalog struct {
	tables  []string
	fks     []p3fk
	bare    []string // table.column
	noWSKey []string // tables with an id and no UNIQUE (workspace_id, id)
	anchor  map[string]bool
}

type querier interface {
	Query(string, ...any) (*sql.Rows, error)
}

func phase3Catalog(t *testing.T, q querier) p3catalog {
	t.Helper()
	listed := pq.Array(services.PolicySchemaRelations())
	scope := `n.nspname = 'public' AND r.relkind = 'r' AND (r.relname = ANY ($1) OR r.relname LIKE 'iga\_gov\_%')`
	var c p3catalog
	c.anchor = map[string]bool{}
	scan := func(sqlText string, f func(*sql.Rows) error) {
		rows, err := q.Query(sqlText, listed)
		if err != nil {
			t.Fatalf("catalog: %v", err)
		}
		defer rows.Close()
		for rows.Next() {
			if err := f(rows); err != nil {
				t.Fatal(err)
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
	}
	scan(`SELECT r.relname FROM pg_class r JOIN pg_namespace n ON n.oid = r.relnamespace WHERE `+scope+` ORDER BY 1`,
		func(rs *sql.Rows) error {
			var n string
			err := rs.Scan(&n)
			c.tables = append(c.tables, n)
			return err
		})
	scan(`SELECT r.relname, c.conname, fr.relname,
	             ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(num, ord)
	                     JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.num ORDER BY k.ord),
	             ARRAY(SELECT a.attname::text FROM unnest(c.confkey) WITH ORDINALITY k(num, ord)
	                     JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.num ORDER BY k.ord),
	             c.confdeltype::text
	        FROM pg_constraint c JOIN pg_class r ON r.oid = c.conrelid JOIN pg_namespace n ON n.oid = r.relnamespace
	        JOIN pg_class fr ON fr.oid = c.confrelid
	       WHERE c.contype = 'f' AND `+scope+` ORDER BY 1, 2`,
		func(rs *sql.Rows) error {
			var fk p3fk
			var cols, refCols pq.StringArray
			err := rs.Scan(&fk.table, &fk.name, &fk.refTable, &cols, &refCols, &fk.onDelete)
			fk.cols, fk.refCols = cols, refCols
			c.fks = append(c.fks, fk)
			if fk.refTable == "workspaces" && len(fk.cols) == 1 && fk.cols[0] == "workspace_id" && fk.onDelete == "c" {
				c.anchor[fk.table] = true
			}
			return err
		})
	scan(`SELECT r.relname || '.' || a.attname FROM pg_class r JOIN pg_namespace n ON n.oid = r.relnamespace
	        JOIN pg_attribute a ON a.attrelid = r.oid AND a.attnum > 0 AND NOT a.attisdropped
	       WHERE `+scope+` AND a.atttypid = 'uuid'::regtype AND a.attname <> 'id'
	         AND NOT EXISTS (SELECT 1 FROM pg_constraint k WHERE k.contype = 'f' AND k.conrelid = r.oid AND a.attnum = ANY (k.conkey))
	       ORDER BY 1`,
		func(rs *sql.Rows) error {
			var col string
			err := rs.Scan(&col)
			c.bare = append(c.bare, col)
			return err
		})
	scan(`SELECT r.relname FROM pg_class r JOIN pg_namespace n ON n.oid = r.relnamespace
	       WHERE `+scope+`
	         AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = r.oid AND a.attname = 'id')
	         AND NOT EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conrelid = r.oid AND k.contype IN ('u', 'p')
	               AND (SELECT array_agg(a.attname::text ORDER BY a.attname) FROM pg_attribute a
	                     WHERE a.attrelid = r.oid AND a.attnum = ANY (k.conkey)) = ARRAY['id', 'workspace_id'])
	       ORDER BY 1`,
		func(rs *sql.Rows) error {
			var n string
			err := rs.Scan(&n)
			c.noWSKey = append(c.noWSKey, n)
			return err
		})
	return c
}

func phase3CatalogProblems(c p3catalog) []string {
	var out []string
	for _, tbl := range c.tables {
		if !c.anchor[tbl] {
			out = append(out, fmt.Sprintf("%s is not anchored: workspace_id needs REFERENCES workspaces(id) ON DELETE CASCADE", tbl))
		}
	}
	seenUser := map[string]bool{}
	for _, fk := range c.fks {
		switch {
		case fk.refTable == "workspaces":
			if len(fk.cols) != 1 || fk.cols[0] != "workspace_id" {
				out = append(out, fmt.Sprintf("%s: a workspaces reference must be the workspace_id anchor", fk.name))
			}
		case len(fk.cols) == 1:
			col := fk.table + "." + fk.cols[0]
			if fk.refTable == "users" && len(fk.refCols) == 1 && fk.refCols[0] == "id" {
				if _, ok := phase3UserRefs[col]; !ok {
					out = append(out, fmt.Sprintf("%s: %s is a single-column reference to users(id) not listed in phase3UserRefs", fk.name, col))
				}
				seenUser[col] = true
			} else {
				out = append(out, fmt.Sprintf("%s: %s is a single-column reference to %s; reference (workspace_id, ...) instead", fk.name, col, fk.refTable))
			}
		default:
			if fk.cols[0] != "workspace_id" || fk.refCols[0] != "workspace_id" {
				out = append(out, fmt.Sprintf("%s: composite reference %s(%s) -> %s(%s) does not lead with workspace_id",
					fk.name, fk.table, strings.Join(fk.cols, ","), fk.refTable, strings.Join(fk.refCols, ",")))
			}
		}
	}
	for col := range phase3UserRefs {
		if !seenUser[col] {
			out = append(out, fmt.Sprintf("%s is listed in phase3UserRefs but is no longer a single-column users reference", col))
		}
	}
	bare := map[string]bool{}
	for _, col := range c.bare {
		bare[col] = true
		if _, ok := phase3BareUUID[col]; !ok {
			out = append(out, fmt.Sprintf("%s is a uuid that references nothing: give it a composite key, or list it in phase3BareUUID", col))
		}
	}
	for col := range phase3BareUUID {
		if !bare[col] {
			out = append(out, fmt.Sprintf("%s is listed in phase3BareUUID but is no longer a bare uuid", col))
		}
	}
	for _, tbl := range c.noWSKey {
		if _, ok := phase3NoWorkspaceIDKey[tbl]; !ok {
			out = append(out, fmt.Sprintf("%s has an id but no UNIQUE (workspace_id, id)", tbl))
		}
	}
	sort.Strings(out)
	return out
}

func TestPhase3ForeignKeyCatalogGuard(t *testing.T) {
	db, _ := testDB(t)
	c := phase3Catalog(t, db)
	// 047-056's 43 tables, plus 059_tidy_eval_pruned (fix/p3-tidy), plus
	// the 13 of 060-062 (R1b action evidence, R2 time-bound access, R3
	// runtime controls), plus access policies' iga_gov_access_policy_version
	// (137), iga_gov_azure_access (144) and iga_gov_k8s_access (146).
	if len(c.tables) != 60 {
		t.Fatalf("%d Phase 3 tables in scope, want 60", len(c.tables))
	}
	for _, p := range phase3CatalogProblems(c) {
		t.Error(p)
	}
	composite := 0
	for _, fk := range c.fks {
		if len(fk.cols) > 1 {
			composite++
		}
	}
	t.Logf("%d tables, %d foreign keys (%d composite, %d users references listed), %d bare uuids listed",
		len(c.tables), len(c.fks), composite, len(phase3UserRefs), len(phase3BareUUID))

	// The checks can fail: a planted iga_gov_* table breaking each rule, in a
	// transaction that is rolled back.
	t.Run("planted_violations_are_caught", func(t *testing.T) {
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`CREATE TABLE iga_gov_zz_planted (
		    id uuid PRIMARY KEY, workspace_id uuid NOT NULL REFERENCES workspaces(id),
		    approver uuid REFERENCES users(id), subject uuid,
		    control_id uuid REFERENCES iga_gov_control(id),
		    policy_id uuid, FOREIGN KEY (policy_id, workspace_id) REFERENCES iga_gov_policy (id, workspace_id))`); err != nil {
			t.Fatalf("plant: %v", err)
		}
		problems := phase3CatalogProblems(phase3Catalog(t, tx))
		for _, want := range [][]string{
			{"iga_gov_zz_planted is not anchored"},
			{"iga_gov_zz_planted.approver", "not listed in phase3UserRefs"},
			{"iga_gov_zz_planted.subject", "references nothing"},
			{"iga_gov_zz_planted.control_id", "single-column reference to iga_gov_control"},
			{"iga_gov_zz_planted", "does not lead with workspace_id"},
			{"iga_gov_zz_planted has an id but no UNIQUE (workspace_id, id)"},
		} {
			found := false
			for _, p := range problems {
				all := true
				for _, part := range want {
					all = all && strings.Contains(p, part)
				}
				found = found || all
			}
			if !found {
				t.Errorf("the guard missed a planted violation %q; problems: %v", want, problems)
			}
		}
	})
}
