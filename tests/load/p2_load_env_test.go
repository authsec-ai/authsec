package load

// The T6.10 environment (SPEC-iga-phase2-graph.md §5.6): the database, the
// fixture (built once per process, reused across runs when the database
// already holds exactly this build of it), and the REAL §5.3 route table
// (platform.RegisterIGAGraphReadRoutes) over a gin engine, so every measured
// read goes through the handler, the §5.1 snapshot and its 3 s budget, and the
// JSON encoder -- never raw SQL alone.
//
// Skipped unless IGA_LOAD_DSN names a database: the fixture is about a
// million rows and must only ever land in a database someone chose for it.
// It must be a Phase 2 database at 036 (the gate verifies the schema) that
// is the load test's alone -- NEVER the integration package's IGA_TEST_DSN or
// tests/igagraph's TEST_DATABASE_URL, at the same time or at any other:
// every p2 lab empties cloud_observation and cloud_scan_run wholesale, which
// the fixture's evidence junctions and publications forbid, so a fixture left
// there breaks that suite. loadEnvFor refuses both (loadDSNRefusal). The
// fixture is wiped when the run ends unless IGA_LOAD_KEEP=1.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	platform "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/services"
)

const (
	// loadDSNEnv names the database the fixture is built in.
	loadDSNEnv = "IGA_LOAD_DSN"
	// loadKeepEnv=1 keeps the fixture after the run, so the next run reuses it
	// (a rebuild takes minutes). Only in a database dedicated to the load
	// test: no other suite can use the database while the fixture is there.
	loadKeepEnv = "IGA_LOAD_KEEP"
	// loadIterEnv overrides the measured iterations per read (never below
	// loadMinIterations: fewer cannot support a p95).
	loadIterEnv = "IGA_LOAD_ITERATIONS"
	// loadReportEnv names a file the measurement table is also written to.
	loadReportEnv = "IGA_LOAD_REPORT"
	// loadOnlyEnv narrows a run to the reads whose names match a regular
	// expression: a diagnostic run (TestP2LoadTargets).
	loadOnlyEnv = "IGA_LOAD_ONLY"
	// loadSQLDirEnv names a directory each read's slowest traced statements
	// are written to, bind values inlined, for EXPLAIN ANALYZE.
	loadSQLDirEnv = "IGA_LOAD_SQL_DIR"
)

// loadSeed fixes the generator: the same seed builds the same fixture, byte
// for byte, which is what lets a run reuse the previous run's rows.
const (
	loadSeedMain  = 20260924
	loadSeedNoise = 20260925
)

// loadMainAccounts are the measured workspace's three connected accounts,
// half, three tenths and a fifth of every per-account count. B and C carry the
// last cycle's partial coverage (loadGen.coverage): B's ecs:us-west-2 denied,
// C's lambda:us-east-1 partial and resource_policies denied -- so B needs
// us-west-2 and C us-east-1. Forty Lambda names in B repeat A's (staging
// mirrors production), so names are duplicated across accounts.
func loadMainAccounts() []loadAcct {
	return []loadAcct{
		{id: "111111111111", label: "production", regions: []string{"us-east-1", "us-west-2"}, share: 0.5},
		{id: "222222222222", label: "staging", regions: []string{"us-east-1", "us-west-2"}, share: 0.3},
		{id: "333333333333", label: "sandbox", regions: []string{"eu-west-1", "us-east-1"}, share: 0.2},
	}
}

// loadNoiseAccounts are the second tenant's accounts (loadNoiseShape).
func loadNoiseAccounts() []loadAcct {
	return []loadAcct{
		{id: "611111111111", label: "noise-prod", regions: []string{"us-east-1", "us-west-2"}, share: 0.5},
		{id: "622222222222", label: "noise-stage", regions: []string{"us-east-1", "us-west-2"}, share: 0.3},
		{id: "633333333333", label: "noise-dev", regions: []string{"eu-west-1", "us-east-1"}, share: 0.2},
	}
}

// loadEnv is one process's fixture and route table.
type loadEnv struct {
	db    *gorm.DB
	sqlDB *sql.DB
	main  *loadGen
	noise *loadGen
	api   *loadAPI
	// built is how long writing the fixture took; 0 when a previous run's
	// identical fixture was reused.
	built    time.Duration
	generate time.Duration
	rows     int
}

var (
	loadEnvOnce sync.Once
	loadEnvVal  *loadEnv
	loadEnvErr  error
)

// loadEnvFor returns the process's environment, building the fixture on first
// use. Every test that calls it holds the fixture until TestMain's wipe.
func loadEnvFor(t *testing.T) *loadEnv {
	t.Helper()
	dsn := os.Getenv(loadDSNEnv)
	if dsn == "" {
		t.Skipf("%s not set; skipping the T6.10 load test (point it at a Phase 2 database at 036 that nothing else is using)", loadDSNEnv)
	}
	// Before anything is written: never in a database another suite uses.
	if why := loadDSNRefusal(dsn, os.Getenv); why != "" {
		t.Fatalf("refusing to build the T6.10 fixture: %s", why)
	}
	loadEnvOnce.Do(func() { loadEnvVal, loadEnvErr = loadOpen(dsn) })
	if loadEnvErr != nil {
		t.Fatalf("load fixture: %v", loadEnvErr)
	}
	return loadEnvVal
}

// loadSharedDSNEnvs name the databases the other Phase 2 suites write to: the
// integration package's (IGA_TEST_DSN; every p2 lab empties cloud_observation
// and cloud_scan_run wholesale) and tests/igagraph's (TEST_DATABASE_URL; it
// rebuilds its schema). The fixture's evidence junctions and publications
// reference those tables, so a fixture in either database breaks that suite
// (its first lab's DELETE fails on the foreign keys) and that suite would
// break the fixture -- whether or not the two run at the same time, once
// IGA_LOAD_KEEP=1 has left the fixture in place.
var loadSharedDSNEnvs = []string{"IGA_TEST_DSN", "TEST_DATABASE_URL"}

// loadDSNRefusal is why the fixture must not be built in dsn, or "" when
// nothing forbids it: dsn names the same database as one of
// loadSharedDSNEnvs, however either is spelled (URL or key=value, localhost
// or 127.0.0.1, with or without parameters). A DSN that cannot be read is
// refused too -- not being able to tell the databases apart is not proof that
// they differ. getenv reads the environment (os.Getenv; tests pass their own).
func loadDSNRefusal(dsn string, getenv func(string) string) string {
	mine, err := loadDatabaseOf(dsn)
	if err != nil {
		return fmt.Sprintf("%s: %v", loadDSNEnv, err)
	}
	for _, env := range loadSharedDSNEnvs {
		other := getenv(env)
		if other == "" {
			continue
		}
		theirs, err := loadDatabaseOf(other)
		if err != nil {
			return fmt.Sprintf("%s cannot be read (%v), so it cannot be shown to be a different database from %s; unset it or fix it",
				env, err, loadDSNEnv)
		}
		if theirs == mine {
			return fmt.Sprintf("%s and %s both name %s; the fixture needs a database of its own (for example one created from the 036 template)",
				loadDSNEnv, env, mine)
		}
	}
	return ""
}

// loadDatabaseOf is the database a PostgreSQL DSN names, as "host:port/dbname",
// with libpq's defaults filled in (port 5432, host localhost, dbname = user)
// and the loopback spellings folded into "localhost". It reads both the URL
// form (postgres://user:pw@host:port/db?...) and the key=value form. Its
// errors never repeat the DSN, which may carry a password.
func loadDatabaseOf(dsn string) (string, error) {
	host, port, db, user := "", "", "", ""
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return "", errors.New("not a valid postgres:// URL") // never echo the DSN: it may carry a password
		}
		host, port, db = u.Hostname(), u.Port(), strings.TrimPrefix(u.Path, "/")
		if u.User != nil {
			user = u.User.Username()
		}
		// libpq lets the query override the authority.
		q := u.Query()
		for key, dst := range map[string]*string{"host": &host, "port": &port, "dbname": &db, "user": &user} {
			if v := q.Get(key); v != "" {
				*dst = v
			}
		}
	} else {
		for _, f := range strings.Fields(dsn) {
			key, v, ok := strings.Cut(f, "=")
			if !ok {
				return "", errors.New("neither a postgres:// URL nor key=value pairs")
			}
			v = strings.Trim(v, "'")
			switch key {
			case "host":
				host = v
			case "port":
				port = v
			case "dbname":
				db = v
			case "user":
				user = v
			}
		}
	}
	if db == "" {
		db = user
	}
	if db == "" {
		return "", errors.New("names no database")
	}
	switch strings.ToLower(host) {
	case "", "localhost", "127.0.0.1", "::1":
		host = "localhost"
	}
	if port == "" {
		port = "5432"
	}
	return strings.ToLower(host) + ":" + port + "/" + db, nil
}

// TestMain wipes the fixture once every test has run, unless IGA_LOAD_KEEP=1.
func TestMain(m *testing.M) {
	code := m.Run()
	if loadEnvVal != nil && os.Getenv(loadKeepEnv) != "1" {
		if err := loadWipe(loadEnvVal.sqlDB, loadFixtureName); err != nil {
			fmt.Fprintf(os.Stderr, "load: wipe the fixture: %v\n", err)
			if code == 0 {
				code = 1
			}
		}
	}
	os.Exit(code)
}

func loadOpen(dsn string) (*loadEnv, error) {
	sqlDB, err := sql.Open("postgres", dsn) // lib/pq, for COPY
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(4)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: loadLogger})
	if err != nil {
		return nil, err
	}
	env := &loadEnv{db: db, sqlDB: sqlDB}

	start := time.Now()
	env.main = loadBuild(loadSeedMain, "", loadFullShape, loadMainAccounts())
	env.noise = loadBuild(loadSeedNoise, "", loadNoiseShape, loadNoiseAccounts())
	env.generate = time.Since(start)
	env.rows = env.main.rows.total() + env.noise.rows.total()

	// The workspace name carries the fixture's fingerprint: a database holding
	// a workspace of that name holds exactly these rows (one COPY transaction
	// wrote them all or nothing), so a run can reuse them.
	fp := loadFingerprint(env.main.rows, env.noise.rows)
	mainName, noiseName := loadFixtureName+"-main-"+fp, loadFixtureName+"-noise-"+fp
	env.main.setName(mainName)
	env.noise.setName(noiseName)

	var have int64
	if err := db.Raw(`SELECT count(*) FROM workspaces WHERE name IN (?, ?)`, mainName, noiseName).Scan(&have).Error; err != nil {
		return nil, err
	}
	if have != 2 {
		start = time.Now()
		if err := loadWipe(sqlDB, loadFixtureName); err != nil {
			return nil, err
		}
		for _, g := range []*loadGen{env.noise, env.main} {
			if err := g.rows.write(sqlDB); err != nil {
				return nil, fmt.Errorf("write %s: %w", g.name, err)
			}
		}
		// The planner needs statistics for the new rows, as autovacuum would
		// have gathered them on an estate that grew to this size.
		if _, err := sqlDB.Exec(`ANALYZE`); err != nil {
			return nil, err
		}
		env.built = time.Since(start)
	}

	api, err := newLoadAPI(db, env.main.ws)
	if err != nil {
		return nil, err
	}
	env.api = api
	return env, nil
}

// setName renames the generated workspace row before it is written.
func (g *loadGen) setName(name string) {
	g.name = name
	ws := g.rows.byName["workspaces"]
	for _, row := range ws.rows {
		row[1] = name
	}
}

// total is the number of generated rows.
func (r *loadRows) total() int {
	n := 0
	for _, t := range r.byName {
		n += len(t.rows)
	}
	return n
}

// loadFingerprint digests every generated row (the workspace names aside,
// which carry the digest), in table order.
func loadFingerprint(sets ...*loadRows) string {
	h := sha256.New()
	for _, r := range sets {
		for _, spec := range loadTableOrder {
			t := r.byName[spec.name]
			fmt.Fprintf(h, "%s:%d\n", t.name, len(t.rows))
			for _, row := range t.rows {
				for i, v := range row {
					if t.name == "workspaces" && i == 1 {
						continue
					}
					if tm, ok := v.(time.Time); ok {
						v = tm.UTC().Format(time.RFC3339Nano)
					}
					fmt.Fprintf(h, "%v\x1f", v)
				}
				h.Write([]byte{'\n'})
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

/* --------------------------------- the API --------------------------------- */

// loadCursorKey signs the measured lists' cursors.
var loadCursorKey = []byte("p2-load-cursor-key")

// loadAPI is the production route table over the fixture database, with the
// token's workspace set the way AuthMiddleware sets it. Permission checks are
// a pass-through: authorization is not what §5.6 measures, and the real one
// calls an external service.
type loadAPI struct {
	eng *gin.Engine
	ws  uuid.UUID
}

func newLoadAPI(db *gorm.DB, ws uuid.UUID) (*loadAPI, error) {
	gin.SetMode(gin.ReleaseMode)
	gate := services.NewGraphProjectionGate(true, "")
	if err := gate.Verify(db); err != nil {
		return nil, fmt.Errorf("the load database must be a Phase 2 database at 036: %w", err)
	}
	ctl := platform.NewIGAGraphReadControllerWith(db, gate, loadCursorKey)
	a := &loadAPI{eng: gin.New(), ws: ws}
	g := a.eng.Group("/api/iga/v1")
	g.Use(func(c *gin.Context) {
		c.Set("workspace_id", a.ws.String())
		c.Next()
	})
	platform.RegisterIGAGraphReadRoutes(g, ctl, func(string, string) gin.HandlerFunc {
		return func(c *gin.Context) { c.Next() }
	})
	return a, nil
}

// get serves one GET through the engine and times it: routing, the handler,
// every query of the snapshot, and rendering the body.
func (a *loadAPI) get(path string) (int, []byte, time.Duration) {
	req := httptest.NewRequest(http.MethodGet, "/api/iga/v1"+path, nil)
	w := httptest.NewRecorder()
	start := time.Now()
	a.eng.ServeHTTP(w, req)
	return w.Code, w.Body.Bytes(), time.Since(start)
}

/* ------------------------------ statement log ------------------------------ */

// loadStatement is one SQL statement a traced request ran.
type loadStatement struct {
	sql     string
	elapsed time.Duration
}

// loadTrace records the statements of the requests made while it is on, so a
// slow read names its slowest statement (the one to EXPLAIN ANALYZE).
type loadTrace struct {
	mu   sync.Mutex
	on   bool
	stmt []loadStatement
}

func (l *loadTrace) start() {
	l.mu.Lock()
	l.on, l.stmt = true, nil
	l.mu.Unlock()
}

// stop ends the trace and returns its statements in the order they ran.
func (l *loadTrace) stop() []loadStatement {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.on = false
	out := l.stmt
	l.stmt = nil
	return out
}

func (l *loadTrace) record(sql string, elapsed time.Duration) {
	l.mu.Lock()
	if l.on {
		l.stmt = append(l.stmt, loadStatement{sql: loadOneLine(sql), elapsed: elapsed})
	}
	l.mu.Unlock()
}

func loadOneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// loadTracer is the process's statement trace, fed by loadLogger.
var loadTracer = &loadTrace{}

// loadLogger is gorm's logger for the fixture database: silent, except that
// it hands every statement to loadTracer while a trace is on.
var loadLogger logger.Interface = loadGormLogger{}

type loadGormLogger struct{}

func (l loadGormLogger) LogMode(logger.LogLevel) logger.Interface { return l }
func (loadGormLogger) Info(context.Context, string, ...any)       {}
func (loadGormLogger) Warn(context.Context, string, ...any)       {}
func (loadGormLogger) Error(context.Context, string, ...any)      {}
func (loadGormLogger) Trace(_ context.Context, begin time.Time, fc func() (string, int64), _ error) {
	loadTracer.mu.Lock()
	on := loadTracer.on
	loadTracer.mu.Unlock()
	if on {
		sql, _ := fc()
		loadTracer.record(sql, time.Since(begin))
	}
}
