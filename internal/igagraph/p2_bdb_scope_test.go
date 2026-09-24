package igagraph

// The two §4.10 unit tests (SPEC-iga-phase2-graph.md l.5041 and l.5122; B18's
// "scope() rejects an unknown target"): every Target that Partitions() emits
// resolves in scope() -- to the RIGHT table -- and nothing else does; and every
// models.NodeClasses entry resolves in SupportColumn and NodeTable, to the
// column the support and lifecycle rows are written under and the table the
// class's model lives in. Pure: no database is opened (gorm DryRun renders the
// statement without a connection).

import (
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"github.com/authsec-ai/authsec/models"
)

// bdbDryRun is a gorm handle that renders SQL and never connects: pgx's
// stdlib pool opens lazily, DryRun executes nothing, and no default
// transaction is begun around a write.
func bdbDryRun(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.New(postgres.Config{DSN: "host=127.0.0.1 port=1 user=none dbname=none sslmode=disable"}),
		&gorm.Config{DryRun: true, DisableAutomaticPing: true, SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("dry-run gorm: %v", err)
	}
	return db
}

// bdbFullSnapshot is a published run whose coverage names two regions, so
// Partitions() emits every partition kind: identities, policies, statements,
// resources, assignments, grants, member_of, both can_assume families, and per
// region every workload service's workload and executes_as partitions plus
// task_execution_role.
func bdbFullSnapshot() *Snapshot {
	return snapWith(map[string]models.SurfaceCoverage{
		models.SurfaceIAMRoles: reached(1), "lambda:us-east-1": reached(1), "ecs:eu-west-1": reached(1),
	})
}

// bdbScopeTable renders the UPDATE a partition's reconciliation would issue
// and returns the table it names, and the arguments it binds.
func bdbScopeTable(t *testing.T, rc *Reconciler, db *gorm.DB, part Partition, snap *Snapshot) (string, []any, error) {
	t.Helper()
	q, err := rc.scope(db, part, snap)
	if err != nil {
		return "", nil, err
	}
	res := q.Session(&gorm.Session{DryRun: true}).Update("state", models.RelStale)
	if res.Error != nil {
		t.Fatalf("render the scoped update: %v", res.Error)
	}
	stmt := res.Statement
	sql := stmt.SQL.String()
	if !strings.HasPrefix(sql, "UPDATE ") {
		t.Fatalf("scope rendered %q, want an UPDATE", sql)
	}
	table := strings.Trim(strings.Fields(sql)[1], `"`)
	return table, stmt.Vars, nil
}

// §4.10 l.5041: every Target Partitions() emits resolves in scope(), each to
// its own table, filtered to exactly this partition (workspace, connector,
// partition key); node partitions (Target "") and an unknown target are
// REJECTED -- never sent to a default table, where an assignment partition
// would end grants and leave its assignment current (B18).
//
// Safeguard (mutation-checked): scope() is exhaustive, with no default table.
func TestP2BdbEveryPartitionTargetResolvesInScope(t *testing.T) {
	snap := bdbFullSnapshot()
	rc := NewReconciler(nil)
	db := bdbDryRun(t)
	want := map[string]string{
		"relationship": "iga_relationship",
		"assignment":   "iga_policy_assignment",
		"access_edge":  "iga_access_edges",
	}
	seen := map[string]int{}
	nodes := 0
	for _, part := range Partitions(snap) {
		if part.Target == "" {
			nodes++
			if err := rc.ScopeForTest(db, part, snap); err == nil {
				t.Errorf("node partition %s resolved to an edge table; nodes reconcile on support rows", part.Key())
			}
			continue
		}
		table, vars, err := bdbScopeTable(t, rc, db, part, snap)
		if err != nil {
			t.Errorf("partition %s (target %q) does not resolve in scope(): %v", part.Key(), part.Target, err)
			continue
		}
		if table != want[part.Target] {
			t.Errorf("partition %s (target %q) scoped to table %q, want %q", part.Key(), part.Target, table, want[part.Target])
		}
		if len(vars) < 3 || vars[len(vars)-3] != snap.Run.WorkspaceID || vars[len(vars)-2] != part.ConnectorID ||
			vars[len(vars)-1] != part.Key() {
			t.Errorf("partition %s scoped with %v, want its workspace, connector and partition key", part.Key(), vars)
		}
		seen[part.Target]++
	}
	// Non-vacuity: the snapshot really produced every edge target, and nodes.
	for target := range want {
		if seen[target] == 0 {
			t.Errorf("Partitions() emitted no %q partition: the fixture proves nothing about it", target)
		}
	}
	if nodes == 0 || seen["relationship"] < 5 {
		t.Errorf("partitions: %d node, %v edge -- want every kind (member_of, both can_assume, executes_as, task_execution_role)",
			nodes, seen)
	}

	for _, bogus := range []string{"bogus", "Relationship", "access_edges", "grant", "node"} {
		if err := rc.ScopeForTest(db, Partition{Target: bogus, ConnectorID: uuid.New()}, snap); err == nil {
			t.Errorf("scope() accepted the unknown target %q: a default table is the B18 defect", bogus)
		}
	}
}

// §4.10 l.5122: every models.NodeClasses entry resolves in SupportColumn and
// NodeTable -- and consistently: the column is the one SetObject fills on a
// support row AND on a lifecycle event (so a row is written against the column
// it is reconciled and retired by), and the table is the class's model's.
// Every node partition's class is one of them, and an unknown class resolves
// to nothing (never a default).
//
// Safeguard (mutation-checked): each mapping names a real class; a missing
// entry makes retireUnsupported fail loudly instead of skipping a class.
func TestP2BdbEveryNodeClassResolves(t *testing.T) {
	byClass := map[string]any{ // each class's model, independently of NodeTable
		models.ObjectIdentity:    &models.IGAIdentityAccount{},
		models.ObjectWorkload:    &models.IGAWorkload{},
		models.ObjectResource:    &models.IGAResource{},
		models.ObjectEntitlement: &models.IGAEntitlement{},
		models.ObjectPolicy:      &models.IGAPolicy{},
	}
	cache := &sync.Map{}
	supportCols := bdbColumns(t, &models.IGAObjectSupport{}, cache)
	eventCols := bdbColumns(t, &models.IGALifecycleEvent{}, cache)
	if len(models.NodeClasses) != len(byClass) {
		t.Errorf("models.NodeClasses = %v, want the %d node classes", models.NodeClasses, len(byClass))
	}
	for _, class := range models.NodeClasses {
		col, table := models.SupportColumn(class), models.NodeTable(class)
		if col == "" || table == "" {
			t.Errorf("node class %q: SupportColumn %q, NodeTable %q -- both must resolve", class, col, table)
			continue
		}
		if got := bdbTableOf(byClass[class]); got != table {
			t.Errorf("node class %q: NodeTable %q, but its model's table is %q", class, table, got)
		}
		support := &models.IGAObjectSupport{}
		if got := bdbFilledColumn(t, class, support, support.SetObject, supportCols); got != col {
			t.Errorf("node class %q: SupportColumn %q, but IGAObjectSupport.SetObject fills %q", class, col, got)
		}
		event := &models.IGALifecycleEvent{}
		if got := bdbFilledColumn(t, class, event, event.SetObject, eventCols); got != col {
			t.Errorf("node class %q: SupportColumn %q, but IGALifecycleEvent.SetObject fills %q", class, col, got)
		}
	}
	classes := map[string]bool{}
	for _, c := range models.NodeClasses {
		classes[c] = true
	}
	for _, part := range Partitions(bdbFullSnapshot()) {
		if part.Target == "" && !classes[part.Class] {
			t.Errorf("node partition %s has class %q, which is not in models.NodeClasses (never retired)", part.Key(), part.Class)
		}
	}
	for _, bogus := range []string{"", "external_principal", "credential", "Identity"} {
		if c, tb := models.SupportColumn(bogus), models.NodeTable(bogus); c != "" || tb != "" {
			t.Errorf("unknown class %q resolved (%q, %q): the mapping must not default", bogus, c, tb)
		}
	}
}

func bdbTableOf(m any) string {
	if tn, ok := m.(interface{ TableName() string }); ok {
		return tn.TableName()
	}
	return ""
}

// bdbColumns maps a model's Go field names to their column names.
func bdbColumns(t *testing.T, m any, cache *sync.Map) map[string]string {
	t.Helper()
	s, err := schema.Parse(m, cache, schema.NamingStrategy{})
	if err != nil {
		t.Fatalf("parse %T: %v", m, err)
	}
	out := map[string]string{}
	for _, f := range s.Fields {
		out[f.Name] = f.DBName
	}
	return out
}

// bdbFilledColumn calls set(class) on a fresh row and returns the column of
// the ONE typed subject field it filled ("" when set refuses the class).
func bdbFilledColumn(t *testing.T, class string, row any, set func(string, uuid.UUID) bool, cols map[string]string) string {
	t.Helper()
	id := uuid.New()
	if !set(class, id) {
		return ""
	}
	v := reflect.ValueOf(row).Elem()
	var filled []string
	for i := 0; i < v.NumField(); i++ {
		if u, ok := v.Field(i).Interface().(*uuid.UUID); ok && u != nil && *u == id {
			filled = append(filled, cols[v.Type().Field(i).Name])
		}
	}
	if len(filled) != 1 {
		t.Errorf("SetObject(%q) filled %v, want exactly one typed subject column", class, filled)
		return ""
	}
	return filled[0]
}
