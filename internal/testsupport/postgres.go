package testsupport

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	pgUser     = "authtest"
	pgPassword = "authtest"
	pgDB       = "authtest"
	pgImage    = "postgres:16-alpine"
)

// PGContainer holds the testcontainers Postgres instance and connection details.
type PGContainer struct {
	Container *tcpostgres.PostgresContainer
	Host      string
	Port      string
	DSN       string // points at the working (cloned) DB
	AdminDSN  string // connects to the superuser DB for management
}

// StartPostgres starts a Postgres container, builds the bootstrap_template via
// the real MasterMigrationRunner, then clones one working DB from it.
// Returns the container; caller MUST call pg.Terminate() in TestMain after m.Run().
func StartPostgres(migrationsDir string) (*PGContainer, error) {
	ctx := context.Background()

	pg, err := tcpostgres.Run(ctx, pgImage,
		tcpostgres.WithDatabase(pgDB),
		tcpostgres.WithUsername(pgUser),
		tcpostgres.WithPassword(pgPassword),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(90*time.Second),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("start postgres container: %w", err)
	}

	host, err := pg.Host(ctx)
	if err != nil {
		return nil, fmt.Errorf("get container host: %w", err)
	}
	port, err := pg.MappedPort(ctx, "5432")
	if err != nil {
		return nil, fmt.Errorf("get container port: %w", err)
	}
	portStr := port.Port()

	adminDSN := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, portStr, pgUser, pgPassword, pgDB)

	const (
		templateName = "bootstrap_template"
		workingName  = "authtest_work"
	)

	if err := buildBootstrapTemplate(adminDSN, templateName, migrationsDir, host, portStr); err != nil {
		return nil, fmt.Errorf("build bootstrap template: %w", err)
	}

	if err := cloneDB(adminDSN, templateName, workingName); err != nil {
		return nil, fmt.Errorf("clone working DB: %w", err)
	}

	workDSN := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, portStr, pgUser, pgPassword, workingName)

	return &PGContainer{
		Container: pg,
		Host:      host,
		Port:      portStr,
		DSN:       workDSN,
		AdminDSN:  adminDSN,
	}, nil
}

// Terminate stops the container. Call in TestMain after m.Run() via env.Teardown().
func (p *PGContainer) Terminate() {
	if p.Container != nil {
		_ = p.Container.Terminate(context.Background())
	}
}

// cloneDB creates workingName as a copy of templateName using TEMPLATE syntax.
func cloneDB(adminDSN, templateName, workingName string) error {
	db, err := sql.Open("postgres", adminDSN)
	if err != nil {
		return fmt.Errorf("open admin DB: %w", err)
	}
	defer db.Close()

	// Drop if exists (idempotent for retries).
	_, _ = db.Exec(fmt.Sprintf(`DROP DATABASE IF EXISTS %q`, workingName))
	if _, err := db.Exec(fmt.Sprintf(`CREATE DATABASE %q TEMPLATE %q`, workingName, templateName)); err != nil {
		return fmt.Errorf("CREATE DATABASE ... TEMPLATE: %w", err)
	}
	return nil
}

// TestNonce returns a short deterministic string derived from t.Name(), safe for
// embedding in email addresses, domains, and other unique natural keys.
func TestNonce(t testing.TB) string {
	n := t.Name()
	n = strings.NewReplacer("/", "_", " ", "_", ".", "_").Replace(n)
	n = strings.ToLower(n)
	if len(n) > 32 {
		n = n[len(n)-32:]
	}
	return n
}
