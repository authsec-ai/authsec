package igagraph_test

// The fixture behind B9 and B20 (p2_bfk_fk_test.go): two workspaces that each
// hold one complete set of parent rows, and a second integration in workspace
// A with its own collection facts.
//
// Every row goes through the same per-table builder: the world's parents and
// each subtest's child row alike. So a child's defaults are the world's own
// rows in workspace A, and a case changes exactly the one reference it tests.
// The builders set only what each table's NOT NULL columns and CHECKs demand
// (read off the catalog at 036). Every unique key gets a fresh value, so a
// child row can only fail on the reference under test.
//
// Rows are inserted directly, not through the scan worker and projector: B9
// and B20 are about what the DATABASE refuses, and a correct writer would never
// produce the rows being refused. No lab fake can create them.

import (
	"database/sql"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

/* ---------------------------------- rows ---------------------------------- */

// bfkRow is one INSERT: a table and its column/value pairs, in order. A nil
// value is SQL NULL.
type bfkRow struct {
	table string
	cols  []string
	vals  []any
}

// bfkRowOf builds a row from base column/value pairs, then applies set: each
// pair replaces the base value of its column, or adds the column.
func bfkRowOf(table string, base []any, set []any) bfkRow {
	r := bfkRow{table: table}
	put := func(col string, v any) {
		for i, have := range r.cols {
			if have == col {
				r.vals[i] = v
				return
			}
		}
		r.cols = append(r.cols, col)
		r.vals = append(r.vals, v)
	}
	for _, pairs := range [][]any{base, set} {
		if len(pairs)%2 != 0 {
			panic(fmt.Sprintf("bfk: odd column/value list for %s", table))
		}
		for i := 0; i < len(pairs); i += 2 {
			put(pairs[i].(string), pairs[i+1])
		}
	}
	return r
}

// get returns a column's value and whether the row sets it to non-NULL.
func (r bfkRow) get(col string) (any, bool) {
	for i, have := range r.cols {
		if have == col {
			return r.vals[i], r.vals[i] != nil
		}
	}
	return nil, false
}

// setsAll reports whether every column is present and non-NULL. Only then can
// a foreign key over those columns be checked at all: PostgreSQL's default
// MATCH SIMPLE skips a reference with any NULL column.
func (r bfkRow) setsAll(cols []string) bool {
	for _, c := range cols {
		if _, ok := r.get(c); !ok {
			return false
		}
	}
	return true
}

func (r bfkRow) insertSQL() string {
	cols := make([]string, len(r.cols))
	params := make([]string, len(r.cols))
	for i, c := range r.cols {
		cols[i] = pq.QuoteIdentifier(c)
		params[i] = fmt.Sprintf("$%d", i+1)
	}
	return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		pq.QuoteIdentifier(r.table), strings.Join(cols, ", "), strings.Join(params, ", "))
}

// bfkExecer is a *sql.DB or a *sql.Tx.
type bfkExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func bfkInsert(q bfkExecer, r bfkRow) error {
	_, err := q.Exec(r.insertSQL(), r.vals...)
	return err
}

// bfkFresh is a value no unique key has seen.
func bfkFresh(prefix string) string { return prefix + "-" + uuid.NewString() }

// bfkRevSeq numbers the child publications. The world's own revisions are 1
// (A) and 7 (B), so no child collides with them.
var bfkRevSeq atomic.Int64

func bfkNextRev() int64 { return 100 + bfkRevSeq.Add(1) }

/* ---------------------------------- sides --------------------------------- */

// bfkSide is one owner of parent rows: a workspace, the integration
// (cloud_connector) that collected its rows, and those rows by name.
type bfkSide struct {
	name     string
	ws, conn uuid.UUID
	acct     string
	rev      int64 // the rev of this side's iga_publication
	ids      map[string]uuid.UUID
	// absent marks a side that owns nothing. Its workspace, connector and every
	// id are fresh on each call, so a reference to any of them names no row.
	absent bool
}

// id is the id of this side's row named key.
func (s *bfkSide) id(key string) uuid.UUID {
	if s.absent {
		return uuid.New()
	}
	id, ok := s.ids[key]
	if !ok {
		panic(fmt.Sprintf("bfk: side %s owns no %q row (a bfkCases bug)", s.name, key))
	}
	return id
}

// put inserts r as this side's row named key.
func (s *bfkSide) put(t *testing.T, db *sql.DB, key string, r bfkRow) {
	t.Helper()
	if err := bfkInsert(db, r); err != nil {
		t.Fatalf("seed %s.%s (%s): %v", s.name, key, r.table, err)
	}
	id, _ := r.get("id")
	s.ids[key] = id.(uuid.UUID)
}

// bfkWorld is the fixture: A is the workspace every child row is written in,
// under integration A.conn (f.connector). B is another workspace with the same
// parents. A2 is a second integration IN workspace A with its own collection
// facts (B20). absent owns nothing.
type bfkWorld struct {
	f                *fixture
	A, B, A2, absent *bfkSide
}

func bfkNewWorld(t *testing.T) *bfkWorld {
	t.Helper()
	f := newFixture(t)
	w := &bfkWorld{f: f}
	wsB, connB := uuid.New(), uuid.New()
	f.exec(`INSERT INTO workspaces (id, name) VALUES ($1, 'ws-b')`, wsB)
	f.exec(`INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, auth_ref)
	        VALUES ($1, $2, 'aws', 'account', '222222222222', 'vault://b')`, connB, wsB)
	// Revisions 1 and 7: a lifecycle event in A naming rev 7 names a
	// publication that exists only in B.
	w.A = bfkSeedSide(t, f.db, "A", f.workspace, f.connector, "111111111111", 1)
	w.B = bfkSeedSide(t, f.db, "B", wsB, connB, "222222222222", 7)
	w.A2 = bfkSeedCollection(t, f.db, "A2", f.workspace, f.addConnector("333333333333"), "333333333333")
	w.absent = &bfkSide{name: "absent", ws: uuid.New(), conn: uuid.New(), acct: "999999999999", rev: 999, absent: true}
	return w
}

// bfkSeedCollection seeds the collection facts 035's integration-qualified
// references point at: a user, a group and a managed policy, all under conn.
func bfkSeedCollection(t *testing.T, db *sql.DB, name string, ws, conn uuid.UUID, acct string) *bfkSide {
	t.Helper()
	s := &bfkSide{name: name, ws: ws, conn: conn, acct: acct, ids: map[string]uuid.UUID{}}
	s.put(t, db, "cuser", s.cloudIdentity())
	s.put(t, db, "cgroup", s.cloudIdentity("kind", "iam_group", "native_id", s.arn("group")))
	s.put(t, db, "cpol", s.cloudPolicy())
	return s
}

// bfkSeedSide seeds one row of every table a foreign key in scope references,
// in dependency order.
func bfkSeedSide(t *testing.T, db *sql.DB, name string, ws, conn uuid.UUID, acct string, rev int64) *bfkSide {
	t.Helper()
	s := bfkSeedCollection(t, db, name, ws, conn, acct)
	s.rev = rev
	for _, p := range []struct {
		key string
		row func() bfkRow
	}{
		// cloud_*
		{"run", func() bfkRow { return s.scanRun() }},
		{"run2", func() bfkRow { return s.scanRun("generation", 2) }},
		{"obs", func() bfkRow { return s.observation() }},
		{"cperm", func() bfkRow { return s.cloudPermission() }},
		{"cres", func() bfkRow { return s.cloudResource() }},
		{"cwl", func() bfkRow { return s.cloudWorkload() }},
		// 004's estate and GitHub-path tables
		{"scope", func() bfkRow { return s.estateScope() }},
		{"integ", func() bfkRow { return s.integration() }},
		{"iscope", func() bfkRow { return s.integrationScope() }},
		{"iscan", func() bfkRow { return s.igaScanRun() }},
		{"delivery", func() bfkRow { return s.delivery() }},
		{"srcobj", func() bfkRow { return s.sourceObject() }},
		{"iobs", func() bfkRow { return s.igaObservation() }},
		{"agent", func() bfkRow { return s.agent() }},
		// the graph's nodes and edges
		{"ident", func() bfkRow { return s.identity() }},
		{"res", func() bfkRow { return s.resource() }},
		{"pol", func() bfkRow { return s.policy() }},
		{"ent", func() bfkRow { return s.statement() }},
		{"assign", func() bfkRow { return s.assignment() }},
		{"edge", func() bfkRow { return s.grant() }},
		{"wl", func() bfkRow { return s.workload() }},
		{"wc", func() bfkRow { return s.classification() }},
		{"ep", func() bfkRow { return s.externalPrincipal() }},
		{"rel", func() bfkRow { return s.relationship() }},
	} {
		s.put(t, db, p.key, p.row())
	}
	if err := bfkInsert(db, s.publication("rev", rev, "scan_run_id", s.id("run"))); err != nil {
		t.Fatalf("seed %s publication: %v", name, err)
	}
	return s
}

func (s *bfkSide) arn(kind string) string {
	return fmt.Sprintf("arn:aws:iam::%s:%s/bfk-%s", s.acct, kind, uuid.NewString())
}

/* -------------------------- builders: cloud_* ------------------------------ */

func (s *bfkSide) cloudIdentity(set ...any) bfkRow {
	return bfkRowOf("cloud_identity", []any{"id", uuid.New(), "workspace_id", s.ws, "connector_id", s.conn,
		"kind", "iam_user", "native_id", s.arn("user"), "name", "bfk"}, set)
}

// cloudPolicy is a managed policy (holder NULL, cloud_policy_inline_chk).
func (s *bfkSide) cloudPolicy(set ...any) bfkRow {
	return bfkRowOf("cloud_policy", []any{"id", uuid.New(), "workspace_id", s.ws, "connector_id", s.conn,
		"policy_kind", "managed", "native_id", s.arn("policy"), "name", "bfk", "document", "{}",
		"last_seen_generation", 1}, set)
}

func (s *bfkSide) membership(set ...any) bfkRow {
	return bfkRowOf("cloud_group_membership", []any{"id", uuid.New(), "workspace_id", s.ws, "connector_id", s.conn,
		"user_identity_id", s.id("cuser"), "group_identity_id", s.id("cgroup"), "last_seen_generation", 1}, set)
}

func (s *bfkSide) attachment(set ...any) bfkRow {
	return bfkRowOf("cloud_policy_attachment", []any{"id", uuid.New(), "workspace_id", s.ws, "connector_id", s.conn,
		"policy_row_id", s.id("cpol"), "principal_identity_id", s.id("cuser"), "attachment_kind", "attached",
		"last_seen_generation", 1}, set)
}

// scanRun is published: uq_cloud_scan_run_live admits one queued or running
// run per connector, and a published run is what every provenance column names.
func (s *bfkSide) scanRun(set ...any) bfkRow {
	return bfkRowOf("cloud_scan_run", []any{"id", uuid.New(), "workspace_id", s.ws, "connector_id", s.conn,
		"generation", 1, "status", "published", "published_at", time.Now()}, set)
}

// observation has no subject: cloud_observation_subject_chk admits at most one,
// and a case that tests a subject reference sets exactly that one.
func (s *bfkSide) observation(set ...any) bfkRow {
	return bfkRowOf("cloud_observation", []any{"id", uuid.New(), "workspace_id", s.ws, "connector_id", s.conn,
		"scan_run_id", s.id("run"), "generation", 1, "source_api", "bfk:probe", "observed_at", time.Now(),
		"content_hash", bfkFresh("h"), "subject_native_id", "bfk"}, set)
}

func (s *bfkSide) cloudPermission(set ...any) bfkRow {
	return bfkRowOf("cloud_permission", []any{"id", uuid.New(), "workspace_id", s.ws, "connector_id", s.conn,
		"identity_id", s.id("cuser"), "effect", "allow", "actions", pq.Array([]string{"s3:GetObject"}),
		"scope_kind", "account_wide", "native_id", bfkFresh("perm")}, set)
}

func (s *bfkSide) cloudResource(set ...any) bfkRow {
	return bfkRowOf("cloud_resource", []any{"id", uuid.New(), "workspace_id", s.ws, "connector_id", s.conn,
		"kind", "s3_bucket", "native_id", "arn:aws:s3:::" + bfkFresh("bfk")}, set)
}

func (s *bfkSide) cloudWorkload(set ...any) bfkRow {
	return bfkRowOf("cloud_workload", []any{"id", uuid.New(), "workspace_id", s.ws, "connector_id", s.conn,
		"runtime_kind", "lambda_function",
		"native_id", fmt.Sprintf("arn:aws:lambda:eu-central-1:%s:function:%s", s.acct, bfkFresh("bfk"))}, set)
}

/* ------------------- builders: 004's estate and GitHub path ---------------- */

func (s *bfkSide) estateScope(set ...any) bfkRow {
	return bfkRowOf("iga_estate_scopes", []any{"id", uuid.New(), "workspace_id", s.ws, "scope_kind", "aws_account"}, set)
}

func (s *bfkSide) integration(set ...any) bfkRow {
	return bfkRowOf("iga_integrations", []any{"id", uuid.New(), "workspace_id", s.ws, "provider", "github",
		"provider_host", "github.com", "app_registration_id", bfkFresh("app")}, set)
}

func (s *bfkSide) integrationScope(set ...any) bfkRow {
	return bfkRowOf("iga_integration_scopes", []any{"id", uuid.New(), "workspace_id", s.ws,
		"integration_id", s.id("integ"), "native_scope_kind", "org", "native_scope_id", bfkFresh("org")}, set)
}

func (s *bfkSide) igaScanRun(set ...any) bfkRow {
	return bfkRowOf("iga_scan_runs", []any{"id", uuid.New(), "workspace_id", s.ws, "integration_id", s.id("integ"),
		"mode", "full", "generation", 1}, set)
}

// scanCheckpoint has no id column: its key is (workspace, run, class, partition).
func (s *bfkSide) scanCheckpoint(set ...any) bfkRow {
	return bfkRowOf("iga_scan_checkpoints", []any{"workspace_id", s.ws, "scan_run_id", s.id("iscan"),
		"object_class", "bfk", "partition_key", bfkFresh("p")}, set)
}

func (s *bfkSide) coverageState(set ...any) bfkRow {
	return bfkRowOf("iga_coverage_states", []any{"id", uuid.New(), "workspace_id", s.ws, "integration_id", s.id("integ"),
		"integration_scope_id", s.id("iscope"), "object_class", bfkFresh("class")}, set)
}

// delivery is bound to its side's workspace. 004 also admits an unbound one
// (workspace_id NULL) until its signature and binding are checked.
func (s *bfkSide) delivery(set ...any) bfkRow {
	return bfkRowOf("iga_webhook_deliveries", []any{"id", uuid.New(), "app_registration_id", bfkFresh("app"),
		"delivery_id", bfkFresh("d"), "workspace_id", s.ws}, set)
}

func (s *bfkSide) durableJob(set ...any) bfkRow {
	return bfkRowOf("iga_durable_jobs", []any{"id", uuid.New(), "workspace_id", s.ws, "integration_id", s.id("integ"),
		"job_kind", "bfk", "dedupe_key", bfkFresh("job")}, set)
}

func (s *bfkSide) sourceObject(set ...any) bfkRow {
	return bfkRowOf("iga_source_objects", []any{"id", uuid.New(), "workspace_id", s.ws, "integration_id", s.id("integ"),
		"object_type", "repository", "recognition_key", bfkFresh("repo")}, set)
}

func (s *bfkSide) igaObservation(set ...any) bfkRow {
	return bfkRowOf("iga_observations", []any{"id", uuid.New(), "workspace_id", s.ws,
		"source_object_id", s.id("srcobj"), "scan_run_id", s.id("iscan"), "mode", "platform_declared",
		"observed_at", time.Now(), "dedupe_key", bfkFresh("obs")}, set)
}

func (s *bfkSide) candidate(set ...any) bfkRow {
	return bfkRowOf("iga_classification_candidates", []any{"id", uuid.New(), "workspace_id", s.ws,
		"source_object_id", s.id("srcobj"), "proposed_object_kind", "agent", "proposal_signature", bfkFresh("sig")}, set)
}

func (s *bfkSide) correlation(set ...any) bfkRow {
	return bfkRowOf("iga_correlations", []any{"id", uuid.New(), "workspace_id", s.ws,
		"source_object_id", s.id("srcobj"), "canonical_kind", "agent", "canonical_id", uuid.New()}, set)
}

func (s *bfkSide) agent(set ...any) bfkRow {
	return bfkRowOf("iga_agents", []any{"id", uuid.New(), "workspace_id", s.ws}, set)
}

func (s *bfkSide) agentInstance(set ...any) bfkRow {
	return bfkRowOf("iga_agent_instances", []any{"id", uuid.New(), "workspace_id", s.ws, "agent_id", s.id("agent")}, set)
}

func (s *bfkSide) canonicalValue(set ...any) bfkRow {
	return bfkRowOf("iga_canonical_attribute_values", []any{"id", uuid.New(), "workspace_id", s.ws,
		"entity_kind", "agent", "entity_id", uuid.New(), "attribute", bfkFresh("attr")}, set)
}

func (s *bfkSide) authorityPolicy(set ...any) bfkRow {
	return bfkRowOf("iga_attribute_authority_policies", []any{"id", uuid.New(), "workspace_id", s.ws,
		"entity_kind", "agent", "attribute", bfkFresh("attr")}, set)
}

func (s *bfkSide) observationLink(set ...any) bfkRow {
	return bfkRowOf("iga_observation_links", []any{"id", uuid.New(), "workspace_id", s.ws,
		"observation_id", s.id("iobs"), "target_kind", "agent", "target_id", uuid.New(), "relation", "supports"}, set)
}

func (s *bfkSide) ownershipCandidate(set ...any) bfkRow {
	return bfkRowOf("iga_ownership_candidates", []any{"id", uuid.New(), "workspace_id", s.ws,
		"subject_kind", "agent", "subject_id", uuid.New(), "candidate_kind", "user", "candidate_ref", "bfk"}, set)
}

func (s *bfkSide) operationalIssue(set ...any) bfkRow {
	return bfkRowOf("iga_operational_issues", []any{"id", uuid.New(), "workspace_id", s.ws,
		"integration_id", s.id("integ"), "issue_kind", "api_failure"}, set)
}

func (s *bfkSide) idempotencyKey(set ...any) bfkRow {
	return bfkRowOf("iga_idempotency_keys", []any{"workspace_id", s.ws, "idempotency_key", bfkFresh("k"),
		"route", "/bfk", "request_hash", "bfk", "response_status", 200}, set)
}

/* ---------------------- builders: the graph (028-036) ---------------------- */

func (s *bfkSide) identity(set ...any) bfkRow {
	return bfkRowOf("iga_identity_accounts", []any{"id", uuid.New(), "workspace_id", s.ws,
		"account_kind", "iam_role", "provider", "aws", "source_key", bfkFresh("aws:identity")}, set)
}

func (s *bfkSide) credential(set ...any) bfkRow {
	return bfkRowOf("iga_credentials", []any{"id", uuid.New(), "workspace_id", s.ws,
		"identity_account_id", s.id("ident"), "credential_type", "access_key"}, set)
}

func (s *bfkSide) resource(set ...any) bfkRow {
	return bfkRowOf("iga_resources", []any{"id", uuid.New(), "workspace_id", s.ws,
		"resource_kind", "s3_bucket", "provider", "aws", "source_key", bfkFresh("aws:resource")}, set)
}

func (s *bfkSide) policy(set ...any) bfkRow {
	return bfkRowOf("iga_policy", []any{"id", uuid.New(), "workspace_id", s.ws, "provider", "aws",
		"policy_kind", "customer_managed", "display_name", "bfk", "source_key", bfkFresh("aws:policy"),
		"continuity", "recognition_only"}, set)
}

// statement is an AWS statement: iga_entitlements_aws_statement_chk demands a
// policy, a statement key, an effect and a content hash.
func (s *bfkSide) statement(set ...any) bfkRow {
	return bfkRowOf("iga_entitlements", []any{"id", uuid.New(), "workspace_id", s.ws,
		"native_grant_kind", "aws_statement", "provider", "aws", "policy_id", s.id("pol"),
		"statement_key", bfkFresh("stmt"), "effect", "allow", "content_hash", "bfk",
		"source_key", bfkFresh("aws:statement")}, set)
}

func (s *bfkSide) assignment(set ...any) bfkRow {
	return bfkRowOf("iga_policy_assignment", []any{"id", uuid.New(), "workspace_id", s.ws,
		"policy_id", s.id("pol"), "holder_identity_account_id", s.id("ident"), "assignment_kind", "attached",
		"source_key", bfkFresh("aws:assignment"), "partition_key", "bfk"}, set)
}

// grant is an AWS grant: iga_access_edges_aws_grant_chk demands the
// assignment, the statement and the typed subject, and no resource.
func (s *bfkSide) grant(set ...any) bfkRow {
	return bfkRowOf("iga_access_edges", []any{"id", uuid.New(), "workspace_id", s.ws,
		"subject_kind", "identity_account", "subject_id", s.id("ident"), "subject_identity_account_id", s.id("ident"),
		"direction", "outbound", "provider", "aws", "entitlement_id", s.id("ent"), "assignment_id", s.id("assign"),
		"source_key", bfkFresh("aws:grant")}, set)
}

func (s *bfkSide) workload(set ...any) bfkRow {
	return bfkRowOf("iga_workload", []any{"id", uuid.New(), "workspace_id", s.ws,
		"runtime_kind", "lambda_function", "source_key", bfkFresh("aws:workload")}, set)
}

func (s *bfkSide) classification(set ...any) bfkRow {
	return bfkRowOf("iga_workload_classification", []any{"id", uuid.New(), "workspace_id", s.ws,
		"workload_id", s.id("wl"), "operation_id", uuid.New(), "decision", "unclassified",
		"previous", "classified_agent", "reason", "bfk", "decided_by_user_id", uuid.New(),
		"against_version", 1, "request_hash", "bfk", "result_version", 2}, set)
}

func (s *bfkSide) classificationClock(set ...any) bfkRow {
	return bfkRowOf("iga_classification_clock", []any{"workspace_id", s.ws}, set)
}

func (s *bfkSide) pipelineLease(set ...any) bfkRow {
	return bfkRowOf("iga_pipeline_lease", []any{"workspace_id", s.ws}, set)
}

func (s *bfkSide) externalPrincipal(set ...any) bfkRow {
	return bfkRowOf("iga_external_principal", []any{"id", uuid.New(), "workspace_id", s.ws,
		"issuer", "token.actions.githubusercontent.com", "subject_claim", bfkFresh("repo:bfk"),
		"mechanism", "oidc", "source_key", bfkFresh("aws:principal")}, set)
}

// relationship is an executes_as: a workload source, an identity target
// (iga_relationship_pair_chk).
func (s *bfkSide) relationship(set ...any) bfkRow {
	return bfkRowOf("iga_relationship", []any{"id", uuid.New(), "workspace_id", s.ws,
		"relationship_type", "executes_as", "source_workload_id", s.id("wl"),
		"target_identity_account_id", s.id("ident"), "source_key", bfkFresh("aws:rel")}, set)
}

func (s *bfkSide) edgeEvidence(set ...any) bfkRow {
	return bfkRowOf("iga_access_edge_evidence", []any{"id", uuid.New(), "workspace_id", s.ws,
		"access_edge_id", s.id("edge"), "observation_id", s.id("obs")}, set)
}

func (s *bfkSide) relationshipEvidence(set ...any) bfkRow {
	return bfkRowOf("iga_relationship_evidence", []any{"id", uuid.New(), "workspace_id", s.ws,
		"relationship_id", s.id("rel"), "observation_id", s.id("obs")}, set)
}

func (s *bfkSide) assignmentEvidence(set ...any) bfkRow {
	return bfkRowOf("iga_assignment_evidence", []any{"id", uuid.New(), "workspace_id", s.ws,
		"assignment_id", s.id("assign"), "observation_id", s.id("obs")}, set)
}

// support supports an identity; iga_object_support_one_chk admits exactly one
// object column, so a case testing another object clears identity_account_id.
func (s *bfkSide) support(set ...any) bfkRow {
	return bfkRowOf("iga_object_support", []any{"id", uuid.New(), "workspace_id", s.ws, "connector_id", s.conn,
		"partition_key", bfkFresh("p"), "identity_account_id", s.id("ident")}, set)
}

func (s *bfkSide) projectionJob(set ...any) bfkRow {
	return bfkRowOf("iga_projection_job", []any{"id", uuid.New(), "workspace_id", s.ws,
		"scan_run_id", s.id("run"), "connector_id", s.conn, "generation", 1}, set)
}

func (s *bfkSide) projectionState(set ...any) bfkRow {
	return bfkRowOf("iga_projection_state", []any{"id", uuid.New(), "workspace_id", s.ws,
		"estate_scope_id", s.id("scope"), "connector_id", s.conn, "partition_key", bfkFresh("p"),
		"last_run_id", s.id("run"), "last_generation", 1, "coverage_state", "reached"}, set)
}

// publication names run2 by default: run already has this side's publication,
// and iga_publication_run_key admits one per run.
func (s *bfkSide) publication(set ...any) bfkRow {
	return bfkRowOf("iga_publication", []any{"workspace_id", s.ws, "rev", bfkNextRev(),
		"published_at", time.Now(), "scan_run_id", s.id("run2"), "manifest", "{}"}, set)
}

func (s *bfkSide) statementRevision(set ...any) bfkRow {
	return bfkRowOf("iga_statement_revision", []any{"id", uuid.New(), "workspace_id", s.ws,
		"entitlement_id", s.id("ent"), "content_hash", "bfk", "statement", "{}", "valid_from", time.Now(),
		"first_seen_run_id", s.id("run")}, set)
}

func (s *bfkSide) target(set ...any) bfkRow {
	return bfkRowOf("iga_entitlement_target", []any{"id", uuid.New(), "workspace_id", s.ws,
		"entitlement_id", s.id("ent"), "resource_id", s.id("res"), "target_mode", "resource", "ordinal", 0}, set)
}

// lifecycleEvent is an identity's first_seen at this side's revision
// (iga_le_one_chk: exactly one object column).
func (s *bfkSide) lifecycleEvent(set ...any) bfkRow {
	return bfkRowOf("iga_lifecycle_event", []any{"id", uuid.New(), "workspace_id", s.ws, "rev", s.rev,
		"scan_run_id", s.id("run"), "occurred_at", time.Now(), "event", "first_seen",
		"identity_account_id", s.id("ident")}, set)
}
