//go:build e2e

// The cascade's "grants of ended assignments" statement, measured against a
// workspace full of AWS history.
//
// It used to find its rows with assignment_id IN (SELECT id FROM
// iga_policy_assignment WHERE workspace_id = ? AND state = 'ended') -- every
// ended assignment of every provider, read twice per sweep, to find the few a
// Kubernetes cluster's grants point at. These tests pin that the statement the
// reconciler actually issues reaches iga_policy_assignment only by index probe,
// one per candidate grant, and that it still ends what it ended before and
// nothing else.
//
//	K8S_GRAPH_TEST_DSN="postgres://authsec:pw@localhost:55433/kf_k_ident?sslmode=disable" \
//	  go test -tags e2e -run Cascade ./internal/k8sgraph/
package k8sgraph

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	awsHistory = 6000
	// liveGrants is the size of the sweeping cluster: current bindings, each
	// with its grant -- the candidates the cascade probes, one each.
	liveGrants = 3000
)

type sqlLog struct {
	mu  sync.Mutex
	sql []string
}

func (l *sqlLog) LogMode(logger.LogLevel) logger.Interface      { return l }
func (l *sqlLog) Info(context.Context, string, ...interface{})  {}
func (l *sqlLog) Warn(context.Context, string, ...interface{})  {}
func (l *sqlLog) Error(context.Context, string, ...interface{}) {}
func (l *sqlLog) Trace(_ context.Context, _ time.Time, fc func() (string, int64), _ error) {
	s, _ := fc()
	l.mu.Lock()
	l.sql = append(l.sql, s)
	l.mu.Unlock()
}

type cascadeFixture struct {
	db                 *gorm.DB
	ws                 uuid.UUID
	edgeMine, edgeElse uuid.UUID
}

func seedCascade(t *testing.T) *cascadeFixture {
	t.Helper()
	d := os.Getenv("K8S_GRAPH_TEST_DSN")
	if d == "" {
		t.Skip("K8S_GRAPH_TEST_DSN not set; skipping the cascade e2e")
	}
	db, err := gorm.Open(postgres.Open(d), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	f := &cascadeFixture{db: db, ws: uuid.New()}
	exec := func(q string, args ...any) {
		t.Helper()
		if err := db.Exec(q, args...).Error; err != nil {
			t.Fatalf("seed: %v\n%s", err, q)
		}
	}
	exec(`INSERT INTO workspaces (id,name) VALUES (?,?)`, f.ws, "k8s-cascade-"+f.ws.String()[:8])

	// AWS: one role, one policy, and a long history of ended attachments.
	awsIdent, awsPolicy := uuid.New(), uuid.New()
	exec(`INSERT INTO iga_identity_accounts (id,workspace_id,display_name,account_kind,identity_backing,
	        lifecycle,provider,source_key,continuity,provider_attrs)
	      VALUES (?,?,'role/app','aws_iam_role','provider','active','aws','aws|role|app','recognition_only','{}')`,
		awsIdent, f.ws)
	exec(`INSERT INTO iga_policy (id,workspace_id,provider,policy_kind,display_name,native_ref,source_key,
	        continuity,lifecycle)
	      VALUES (?,?,'aws','aws_managed','ReadOnly','arn','aws|policy|ro','recognition_only','active')`,
		awsPolicy, f.ws)
	exec(`INSERT INTO iga_policy_assignment (workspace_id,policy_id,holder_identity_account_id,assignment_kind,
	        basis,state,valid_to,ended_reason,source_key,partition_key)
	      SELECT ?, ?, ?, 'attached', 'declared', 'ended', now(), 'not_seen',
	             'aws|attach|' || g, 'aws|p'
	        FROM generate_series(1, ?) g`, f.ws, awsPolicy, awsIdent, awsHistory)

	// Two Kubernetes clusters, each with a retired ServiceAccount whose
	// binding has ended and whose grant is still current.
	for _, c := range []struct {
		cluster string
		edge    *uuid.UUID
	}{{"c1", &f.edgeMine}, {"c2", &f.edgeElse}} {
		ident, policy, stmt, assign, edge := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
		*c.edge = edge
		saKey := ServiceAccountKey(c.cluster, "ns", "sa")
		roleKey := Key(c.cluster, "clusterrole", "reader")
		bindKey := Key(c.cluster, "clusterrolebinding", "b") + Sep + saKey
		exec(`INSERT INTO iga_identity_accounts (id,workspace_id,display_name,account_kind,identity_backing,
		        lifecycle,retired_reason,provider,source_key,continuity,provider_attrs)
		      VALUES (?,?,'system:serviceaccount:ns:sa','k8s_service_account','provider','retired',
		              'unsupported','k8s',?,'recognition_only','{}')`, ident, f.ws, saKey)
		exec(`INSERT INTO iga_policy (id,workspace_id,provider,policy_kind,display_name,native_ref,source_key,
		        continuity,lifecycle)
		      VALUES (?,?,'k8s','k8s_cluster_role','reader','ref',?,'recognition_only','active')`,
			policy, f.ws, roleKey)
		exec(`INSERT INTO iga_entitlements (id,workspace_id,native_grant_kind,native_rights,normalized_rights,
		        lifecycle,provider,source_key,continuity,statement_key,effect,negated,conditional,policy_id)
		      VALUES (?,?,'k8s_policy_rule','{}','{}','active','k8s',?,'recognition_only',?,'allow',false,false,?)`,
			stmt, f.ws, roleKey+Sep+"r1", roleKey+Sep+"r1", policy)
		exec(`INSERT INTO iga_policy_assignment (id,workspace_id,policy_id,holder_identity_account_id,
		        assignment_kind,basis,state,valid_to,ended_reason,source_key,partition_key)
		      VALUES (?,?,?,?,'k8s_cluster_role_binding','declared','ended',now(),'subject_retired',?,'')`,
			assign, f.ws, policy, ident, bindKey)
		exec(`INSERT INTO iga_access_edges (id,workspace_id,subject_kind,subject_id,subject_identity_account_id,
		        provider,entitlement_id,assignment_id,direction,path_kind,basis,calculation_state,
		        effective_conclusion,native_scope,state,source_key,partition_key)
		      VALUES (?,?,'identity_account',?,?,'k8s',?,?,'outbound','k8s_rbac','declared','partial',
		              'unknown',?,'current',?,'')`,
			edge, f.ws, ident, ident, stmt, assign, c.cluster, bindKey+Sep+roleKey+Sep+"r1")
	}
	// The rest of c1: live bindings and their grants, none of which ends.
	liveIdent, livePolicy, liveStmt := uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO iga_identity_accounts (id,workspace_id,display_name,account_kind,identity_backing,
	        lifecycle,provider,source_key,continuity,provider_attrs)
	      VALUES (?,?,'system:serviceaccount:ns:live','k8s_service_account','provider','active','k8s',?,
	              'recognition_only','{}')`, liveIdent, f.ws, ServiceAccountKey("c1", "ns", "live"))
	exec(`INSERT INTO iga_policy (id,workspace_id,provider,policy_kind,display_name,native_ref,source_key,
	        continuity,lifecycle)
	      VALUES (?,?,'k8s','k8s_cluster_role','live','ref',?,'recognition_only','active')`,
		livePolicy, f.ws, Key("c1", "clusterrole", "live"))
	exec(`INSERT INTO iga_entitlements (id,workspace_id,native_grant_kind,native_rights,normalized_rights,
	        lifecycle,provider,source_key,continuity,statement_key,effect,negated,conditional,policy_id)
	      VALUES (?,?,'k8s_policy_rule','{}','{}','active','k8s',?,'recognition_only',?,'allow',false,false,?)`,
		liveStmt, f.ws, Key("c1", "clusterrole", "live", "r"), Key("c1", "clusterrole", "live", "r"), livePolicy)
	exec(`INSERT INTO iga_policy_assignment (id,workspace_id,policy_id,holder_identity_account_id,
	        assignment_kind,basis,state,source_key,partition_key)
	      SELECT md5(?::text || g)::uuid, ?, ?, ?, 'k8s_cluster_role_binding', 'declared', 'current',
	             ? || g, ''
	        FROM generate_series(1, ?) g`,
		f.ws.String(), f.ws, livePolicy, liveIdent, Key("c1", "clusterrolebinding", "live"), liveGrants)
	exec(`INSERT INTO iga_access_edges (workspace_id,subject_kind,subject_id,subject_identity_account_id,
	        provider,entitlement_id,assignment_id,direction,path_kind,basis,calculation_state,
	        effective_conclusion,native_scope,state,source_key,partition_key)
	      SELECT ?, 'identity_account', ?, ?, 'k8s', ?, md5(?::text || g)::uuid, 'outbound', 'k8s_rbac',
	             'declared', 'partial', 'unknown', 'c1', 'current', ? || g, ''
	        FROM generate_series(1, ?) g`,
		f.ws, liveIdent, liveIdent, liveStmt, f.ws.String(), Key("c1", "grant", "live"), liveGrants)

	for _, tbl := range []string{"iga_policy_assignment", "iga_access_edges", "iga_identity_accounts"} {
		exec(`ANALYZE ` + tbl)
	}
	return f
}

// planNode is the part of EXPLAIN (FORMAT JSON) this test reads.
type planNode struct {
	NodeType     string     `json:"Node Type"`
	Relation     string     `json:"Relation Name"`
	IndexName    string     `json:"Index Name"`
	ActualRows   float64    `json:"Actual Rows"`
	ActualLoops  float64    `json:"Actual Loops"`
	RowsFiltered float64    `json:"Rows Removed by Filter"`
	Plans        []planNode `json:"Plans"`
}

// assignmentReads is every iga_policy_assignment access in a plan, and the
// rows those accesses read (returned plus filtered out, over all loops).
func assignmentReads(n planNode, out *[]planNode) float64 {
	read := 0.0
	if n.Relation == "iga_policy_assignment" {
		*out = append(*out, n)
		read += (n.ActualRows + n.RowsFiltered) * n.ActualLoops
	}
	for _, c := range n.Plans {
		read += assignmentReads(c, out)
	}
	return read
}

// explain runs EXPLAIN (ANALYZE, FORMAT JSON) in a transaction it rolls back,
// after the planner settings given ("" for none).
func explain(t *testing.T, db *gorm.DB, settings, q string, args ...any) (planNode, string) {
	t.Helper()
	tx := db.Begin()
	defer tx.Rollback()
	if settings != "" {
		if err := tx.Exec(settings).Error; err != nil {
			t.Fatalf("settings: %v", err)
		}
	}
	var js string
	if err := tx.Raw(`EXPLAIN (ANALYZE, FORMAT JSON) `+q, args...).Row().Scan(&js); err != nil {
		t.Fatalf("explain: %v\n%s", err, q)
	}
	var plans []struct {
		Plan planNode `json:"Plan"`
	}
	if err := json.Unmarshal([]byte(js), &plans); err != nil || len(plans) != 1 {
		t.Fatalf("explain json: %v", err)
	}
	var text []string
	rows, err := tx.Raw(`EXPLAIN `+q, args...).Rows()
	if err == nil {
		for rows.Next() {
			var l string
			_ = rows.Scan(&l)
			text = append(text, l)
		}
		rows.Close()
	}
	return plans[0].Plan, strings.Join(text, "\n")
}

// The cascade the reconciler issues touches iga_policy_assignment only by
// index probe -- one per live grant of the sweeping cluster, which the sweep
// writes anyway -- however much AWS history the workspace holds; the statement
// it replaced read all of it.
func TestCascadeGrantsViaAssignmentDoesNotScanOtherProviders(t *testing.T) {
	f := seedCascade(t)

	// Run the real cascade, capturing the statements it issues.
	rec := &sqlLog{}
	capDB, err := gorm.Open(postgres.Open(os.Getenv("K8S_GRAPH_TEST_DSN")), &gorm.Config{Logger: rec})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	tx := capDB.Begin()
	if err := NewReconciler(func() time.Time { return at }).cascade(tx, f.ws, ClusterPrefix("c1"),
		"iga_identity_accounts", "identity_account_id", models.EndedSubjectRetired, at); err != nil {
		tx.Rollback()
		t.Fatalf("cascade: %v", err)
	}
	var mine, other string
	tx.Raw(`SELECT state FROM iga_access_edges WHERE id = ?`, f.edgeMine).Scan(&mine)
	tx.Raw(`SELECT state FROM iga_access_edges WHERE id = ?`, f.edgeElse).Scan(&other)
	tx.Rollback()
	if mine != "ended" {
		t.Errorf("c1's grant of an ended binding is %q after c1's cascade, want ended", mine)
	}
	if other != "current" {
		t.Errorf("c2's grant is %q after c1's cascade, want current (another cluster's row)", other)
	}

	var stmt string
	for _, s := range rec.sql {
		if strings.Contains(s, "UPDATE iga_access_edges") && strings.Contains(s, "iga_policy_assignment") {
			stmt = s
		}
	}
	if stmt == "" {
		t.Fatalf("the cascade issued no grants-via-assignment statement; captured:\n%s",
			strings.Join(rec.sql, "\n---\n"))
	}

	// Whatever the planner estimates. With this fixture's statistics it probes
	// anyway; once it believes a cluster has many grants it joins by hash
	// instead, which for the replaced statement meant reading every ended
	// assignment of the workspace. enable_nestloop = off stands in for that
	// estimate. The cascade's scalar subquery cannot become a join at all, so
	// its plan must be the same index probe either way.
	const hashing = "SET LOCAL enable_nestloop = off"
	var read float64
	for _, settings := range []string{"", hashing} {
		plan, text := explain(t, f.db, settings, stmt)
		var nodes []planNode
		read = assignmentReads(plan, &nodes)
		t.Logf("cascade plan [%s] (%d AWS ended assignments in the workspace):\n%s",
			settings, awsHistory, text)
		if len(nodes) == 0 {
			t.Fatal("the plan never reads iga_policy_assignment; the test is not measuring the cascade")
		}
		for _, n := range nodes {
			if n.NodeType != "Index Scan" && n.NodeType != "Index Only Scan" {
				t.Errorf("[%s] iga_policy_assignment read by %s, want an index probe", settings, n.NodeType)
			}
		}
		// One probe per live c1 grant, each returning that grant's own (c1)
		// assignment: no AWS row and no other cluster's row is ever read.
		if read > liveGrants+1 {
			t.Errorf("[%s] the cascade read %.0f assignment rows, want at most the %d c1's grants point at",
				settings, read, liveGrants+1)
		}
	}

	// The statement it replaced, on the same data: every ended assignment.
	old := `UPDATE iga_access_edges
	           SET state = 'ended', valid_to = now(), ended_reason = 'subject_retired'
	         WHERE workspace_id = ? AND provider = 'k8s' AND state <> 'ended'
	           AND left(source_key, ?) = ?
	           AND assignment_id IN (
	                 SELECT id FROM iga_policy_assignment
	                  WHERE workspace_id = ? AND state = 'ended')`
	prefix := ClusterPrefix("c1")
	oldPlan, oldText := explain(t, f.db, hashing, old, f.ws, len([]rune(prefix)), prefix, f.ws)
	var oldNodes []planNode
	oldRead := assignmentReads(oldPlan, &oldNodes)
	t.Logf("the replaced statement's plan:\n%s", oldText)
	t.Logf("assignment rows read: replaced statement %.0f, cascade now %.0f", oldRead, read)
	if oldRead < awsHistory {
		t.Errorf("the replaced statement read only %.0f assignment rows; the fixture does not reproduce the scan",
			oldRead)
	}
}
