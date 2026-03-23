package migration

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// MigrationFile represents a parsed SQL migration file.
type MigrationFile struct {
	Version  int
	Name     string
	FilePath string
	Content  string
}

// MigrationRunner executes versioned SQL migrations against a database.
type MigrationRunner struct {
	db            *sql.DB
	gormDB        *gorm.DB
	migrationsDir string
	dbType        string
	tenantID      *string
	masterDB      *sql.DB
}

// NewMasterMigrationRunner creates a runner for the master database.
func NewMasterMigrationRunner(migrationsDir string, rawDB *sql.DB, gormDB *gorm.DB) *MigrationRunner {
	return &MigrationRunner{
		db:            rawDB,
		gormDB:        gormDB,
		migrationsDir: migrationsDir,
		dbType:        "master",
	}
}

// NewTenantMigrationRunner creates a runner for a tenant database.
// masterDB is used solely for writing tenant migration logs to the master DB.
func NewTenantMigrationRunner(tenantID string, tenantDBConn *sql.DB, migrationsDir string, masterDB *sql.DB) *MigrationRunner {
	return &MigrationRunner{
		db:            tenantDBConn,
		migrationsDir: migrationsDir,
		dbType:        "tenant",
		tenantID:      &tenantID,
		masterDB:      masterDB,
	}
}

// LoadMigrationFiles loads and sorts all SQL files from the runner's V3 migrations directory.
func (mr *MigrationRunner) LoadMigrationFiles() ([]MigrationFile, error) {
	migrations, err := mr.loadMigrationsFromDir(mr.migrationsDir)
	if err != nil {
		return nil, err
	}

	if err := validateUniqueVersions(mr.dbType, migrations); err != nil {
		return nil, err
	}

	sort.SliceStable(migrations, func(i, j int) bool {
		if migrations[i].Version == migrations[j].Version {
			return migrations[i].FilePath < migrations[j].FilePath
		}
		return migrations[i].Version < migrations[j].Version
	})

	log.Printf("[Migration] Loaded %d total migration files for %s", len(migrations), mr.dbType)
	return migrations, nil
}

func validateUniqueVersions(dbType string, migrations []MigrationFile) error {
	versionToFiles := make(map[int][]string)
	for _, migration := range migrations {
		versionToFiles[migration.Version] = append(versionToFiles[migration.Version], migration.FilePath)
	}

	var duplicates []string
	for version, files := range versionToFiles {
		if len(files) <= 1 {
			continue
		}
		sort.Strings(files)
		duplicates = append(duplicates, fmt.Sprintf("v%d: %s", version, strings.Join(files, ", ")))
	}

	if len(duplicates) == 0 {
		return nil
	}

	sort.Strings(duplicates)
	return fmt.Errorf("duplicate %s migration versions detected: %s", dbType, strings.Join(duplicates, "; "))
}

func filterRunnableMigrations(_ string, migrations []MigrationFile) []MigrationFile {
	return migrations
}

func (mr *MigrationRunner) loadMigrationsFromDir(dir string) ([]MigrationFile, error) {
	if !isV3MigrationDir(dir) {
		return nil, fmt.Errorf("unsupported migration directory %q: only migrations/v3/<dbType> is allowed", dir)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read migration directory %s: %w", dir, err)
	}

	migrations := make([]MigrationFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		version, name, err := parseMigrationFileName(entry.Name())
		if err != nil {
			return nil, fmt.Errorf("parse V3 migration %s: %w", entry.Name(), err)
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read V3 migration %s: %w", entry.Name(), err)
		}

		migrations = append(migrations, MigrationFile{
			Version:  version,
			Name:     name,
			FilePath: path,
			Content:  string(content),
		})
	}

	return migrations, nil
}

// parseMigrationFileName extracts the integer version and descriptive name from a filename.
// Expected format: 001_create_users_table.sql
func parseMigrationFileName(filename string) (int, string, error) {
	base := strings.TrimSuffix(filename, ".sql")
	parts := strings.SplitN(base, "_", 2)
	if len(parts) < 2 {
		return 0, "", fmt.Errorf("invalid migration filename format: %s", filename)
	}
	version, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, "", fmt.Errorf("invalid version number in %s: %w", filename, err)
	}
	return version, parts[1], nil
}

func isV3MigrationDir(dir string) bool {
	clean := filepath.ToSlash(filepath.Clean(dir))
	return strings.HasSuffix(clean, "migrations/v3/master") || strings.HasSuffix(clean, "migrations/v3/tenant")
}

// RunMigrations executes all pending migrations with retry logic.
func (mr *MigrationRunner) RunMigrations() error {
	log.Printf("[Migration] Starting %s database migrations", mr.dbType)

	allMigrations, err := mr.LoadMigrationFiles()
	if err != nil {
		return err
	}
	if err := mr.ensureBootstrapSafe(allMigrations); err != nil {
		return err
	}

	migrations := filterRunnableMigrations(mr.dbType, allMigrations)
	if len(migrations) == 0 {
		log.Printf("[Migration] No migration files found for %s", mr.dbType)
		return nil
	}

	const maxRetries = 3
	executedCount := 0
	tenantSeeded := false

	if mr.dbType == "tenant" && mr.tenantID != nil && mr.isMigrationExecuted(0) {
		if err := mr.seedTenantSelfReference(); err != nil {
			return err
		}
		tenantSeeded = true
	}

	for _, m := range migrations {
		if mr.isMigrationExecuted(m.Version) {
			log.Printf("[Migration] %s v%d (%s) already applied, skipping", mr.dbType, m.Version, m.Name)
			continue
		}

		log.Printf("[Migration] Applying %s v%d: %s", mr.dbType, m.Version, m.Name)

		var lastErr error
		var executionMS int64
		succeeded := false

		for attempt := 1; attempt <= maxRetries; attempt++ {
			start := time.Now()
			err := mr.executeSQLContent(m.Content)
			executionMS = time.Since(start).Milliseconds()

			if err == nil {
				succeeded = true
				executedCount++
				log.Printf("[Migration] %s v%d completed in %dms", mr.dbType, m.Version, executionMS)
				break
			}

			lastErr = err
			log.Printf("[Migration] %s v%d attempt %d/%d failed: %v", mr.dbType, m.Version, attempt, maxRetries, err)
			if attempt < maxRetries {
				time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
			}
		}

		if !succeeded {
			errMsg := fmt.Sprintf("FAILED after %d attempts: %v", maxRetries, lastErr)
			log.Printf("[Migration] ERROR: %s v%d %s", mr.dbType, m.Version, errMsg)
			mr.logMigration(m.Version, m.Name, false, errMsg, executionMS)
			return fmt.Errorf("%s migration v%d (%s) failed: %w", mr.dbType, m.Version, m.Name, lastErr)
		}

		mr.logMigration(m.Version, m.Name, true, "", executionMS)

		// Tenant seed data depends on the schema baseline existing first.
		if mr.dbType == "tenant" && mr.tenantID != nil && !tenantSeeded && m.Version == 0 {
			if err := mr.seedTenantSelfReference(); err != nil {
				return err
			}
			tenantSeeded = true
		}
	}

	log.Printf("[Migration] %s done: %d applied, 0 failed", mr.dbType, executedCount)
	return nil
}

func (mr *MigrationRunner) ensureBootstrapSafe(migrations []MigrationFile) error {
	if len(migrations) == 0 {
		return nil
	}
	if mr.isMigrationExecuted(migrations[0].Version) {
		return nil
	}

	var existingTableCount int
	if err := mr.db.QueryRow(`
		SELECT COUNT(*)
		FROM information_schema.tables
		WHERE table_schema = 'public'
		  AND table_type = 'BASE TABLE'
		  AND table_name <> 'migration_logs'
	`).Scan(&existingTableCount); err != nil {
		return fmt.Errorf("check existing schema state: %w", err)
	}

	if existingTableCount > 0 {
		return fmt.Errorf("%s database is not empty; V3 bootstrap requires a clean database", mr.dbType)
	}

	return nil
}

func (mr *MigrationRunner) seedTenantSelfReference() error {
	seedSQL := `INSERT INTO tenants (id, tenant_id, email, tenant_domain, status, created_at, updated_at)
	            VALUES ($1::uuid, $1::uuid, $2, $3, 'active', NOW(), NOW())
	            ON CONFLICT (id) DO NOTHING`
	seedEmail := fmt.Sprintf("bootstrap+%s@authsec.local", strings.ReplaceAll(*mr.tenantID, "-", ""))
	if _, err := mr.db.Exec(seedSQL, *mr.tenantID, seedEmail, "authsec.local"); err != nil {
		return fmt.Errorf("seed tenant self-reference row: %w", err)
	}
	log.Printf("[Migration] Seeded tenant self-reference row for tenant %s", *mr.tenantID)
	return nil
}

// executeSQLContent executes arbitrary SQL content in a single transaction.
func (mr *MigrationRunner) executeSQLContent(content string) error {
	tx, err := mr.db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		}
	}()

	for _, stmt := range splitSQLStatements(content) {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := tx.Exec(stmt); err != nil {
			tx.Rollback()
			return fmt.Errorf("execute statement: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

// isMigrationExecuted returns true if the given version is already recorded as successful.
func (mr *MigrationRunner) isMigrationExecuted(version int) bool {
	if mr.dbType == "tenant" && mr.masterDB == nil {
		return false
	}

	query := `SELECT COUNT(*) FROM migration_logs WHERE version = $1 AND db_type = $2 AND success = true`
	args := []interface{}{version, mr.dbType}

	var queryDB *sql.DB
	if mr.dbType == "tenant" && mr.masterDB != nil {
		queryDB = mr.masterDB
		query += ` AND tenant_id = $3`
		args = append(args, *mr.tenantID)
	} else {
		queryDB = mr.db
		query += ` AND tenant_id IS NULL`
	}

	var count int64
	if err := queryDB.QueryRow(query, args...).Scan(&count); err != nil {
		return false
	}
	return count > 0
}

// logMigration records a migration execution in migration_logs.
func (mr *MigrationRunner) logMigration(version int, name string, success bool, errorMsg string, executionMS int64) {
	if mr.gormDB != nil {
		mr.gormDB.Create(&MigrationLog{
			ID:          uuid.New(),
			Version:     version,
			Name:        name,
			ExecutedAt:  time.Now().UTC(),
			Success:     success,
			ErrorMsg:    errorMsg,
			DBType:      mr.dbType,
			TenantID:    mr.tenantID,
			ExecutionMS: executionMS,
		})
		return
	}

	if mr.dbType == "tenant" && mr.masterDB == nil {
		return
	}

	logDB := mr.db
	if mr.masterDB != nil {
		logDB = mr.masterDB
	}

	tenantIDVal := sql.NullString{}
	if mr.tenantID != nil {
		tenantIDVal = sql.NullString{String: *mr.tenantID, Valid: true}
	}

	_, err := logDB.Exec(
		`INSERT INTO migration_logs (id, version, name, executed_at, success, error_msg, db_type, tenant_id, execution_ms)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		uuid.New().String(), version, name, time.Now().UTC(), success, errorMsg, mr.dbType, tenantIDVal, executionMS,
	)
	if err != nil {
		log.Printf("[Migration] Warning: failed to log migration v%d: %v", version, err)
	}
}

// GetMigrationStatus returns a summary of migration progress.
func (mr *MigrationRunner) GetMigrationStatus() (*MigrationStatusResponse, error) {
	migrations, err := mr.LoadMigrationFiles()
	if err != nil {
		return nil, err
	}
	migrations = filterRunnableMigrations(mr.dbType, migrations)

	queryDB := mr.db
	if mr.dbType == "tenant" && mr.masterDB != nil {
		queryDB = mr.masterDB
	}

	baseQuery := `SELECT version, executed_at FROM migration_logs WHERE db_type = $1 AND success = true`
	args := []interface{}{mr.dbType}
	if mr.tenantID != nil {
		baseQuery += ` AND tenant_id = $2`
		args = append(args, *mr.tenantID)
	} else {
		baseQuery += ` AND tenant_id IS NULL`
	}

	var lastMigration int
	var lastExecuted time.Time
	_ = queryDB.QueryRow(baseQuery+` ORDER BY version DESC LIMIT 1`, args...).Scan(&lastMigration, &lastExecuted)

	var executedCount int
	countQuery := strings.Replace(baseQuery, "version, executed_at", "COUNT(*)", 1)
	_ = queryDB.QueryRow(countQuery, args...).Scan(&executedCount)

	status := "pending"
	if executedCount == len(migrations) {
		status = "completed"
	} else if executedCount > 0 {
		status = "in_progress"
	}

	return &MigrationStatusResponse{
		DBType:          mr.dbType,
		TenantID:        mr.tenantID,
		LastMigration:   lastMigration,
		TotalMigrations: len(migrations),
		Status:          status,
		LastExecuted:    lastExecuted,
	}, nil
}

// BackfillTenantMigrationLogs records successful tenant migrations for a cloned
// database so status checks remain consistent with template-based provisioning.
func BackfillTenantMigrationLogs(tenantID, migrationsDir string, masterDB *sql.DB) (int, int, error) {
	if masterDB == nil {
		return 0, 0, fmt.Errorf("master database connection is required")
	}

	runner := &MigrationRunner{
		migrationsDir: migrationsDir,
		dbType:        "tenant",
		tenantID:      &tenantID,
		masterDB:      masterDB,
	}

	migrations, err := runner.LoadMigrationFiles()
	if err != nil {
		return 0, 0, err
	}
	migrations = filterRunnableMigrations("tenant", migrations)

	lastVersion := 0
	inserted := 0
	for _, migration := range migrations {
		if migration.Version > lastVersion {
			lastVersion = migration.Version
		}
		if runner.isMigrationExecuted(migration.Version) {
			continue
		}
		runner.logMigration(migration.Version, migration.Name, true, "", 0)
		inserted++
	}

	return lastVersion, inserted, nil
}

// MigrationsDir resolves the canonical V3 migrations directory path at runtime.
func MigrationsDir(dbType string) string {
	execPath, err := os.Executable()
	if err == nil {
		v3 := filepath.Join(filepath.Dir(execPath), "migrations", "v3", dbType)
		if _, err := os.Stat(v3); err == nil {
			return v3
		}
	}
	cwd, _ := os.Getwd()
	v3 := filepath.Join(cwd, "migrations", "v3", dbType)
	if _, err := os.Stat(v3); err == nil {
		return v3
	}
	return filepath.Join("migrations", "v3", dbType)
}

// splitSQLStatements intelligently splits SQL into individual statements,
// handling dollar-quoted strings, single-quoted strings, and comments.
func splitSQLStatements(content string) []string {
	var statements []string
	var current strings.Builder
	runes := []rune(content)
	i := 0

	for i < len(runes) {
		if runes[i] == '$' {
			if tag := extractDollarTag(runes, i); tag != "" {
				for j := 0; j < len(tag); j++ {
					current.WriteRune(runes[i])
					i++
				}
				for i < len(runes) {
					current.WriteRune(runes[i])
					if i+len(tag) <= len(runes) && string(runes[i:i+len(tag)]) == tag {
						for j := 1; j < len(tag); j++ {
							i++
							if i < len(runes) {
								current.WriteRune(runes[i])
							}
						}
						i++
						break
					}
					i++
				}
				continue
			}
		}

		if i+1 < len(runes) && runes[i] == '-' && runes[i+1] == '-' {
			for i < len(runes) && runes[i] != '\n' {
				current.WriteRune(runes[i])
				i++
			}
			if i < len(runes) {
				current.WriteRune(runes[i])
				i++
			}
			continue
		}

		if i+1 < len(runes) && runes[i] == '/' && runes[i+1] == '*' {
			current.WriteRune(runes[i])
			current.WriteRune(runes[i+1])
			i += 2
			for i+1 < len(runes) {
				current.WriteRune(runes[i])
				if runes[i] == '*' && runes[i+1] == '/' {
					i++
					current.WriteRune(runes[i])
					i++
					break
				}
				i++
			}
			continue
		}

		if runes[i] == '\'' {
			current.WriteRune(runes[i])
			i++
			for i < len(runes) {
				current.WriteRune(runes[i])
				if runes[i] == '\'' {
					if i+1 < len(runes) && runes[i+1] == '\'' {
						i++
						current.WriteRune(runes[i])
					} else {
						i++
						break
					}
				}
				i++
			}
			continue
		}

		if runes[i] == ';' {
			if stmt := strings.TrimSpace(current.String()); stmt != "" {
				statements = append(statements, stmt)
			}
			current.Reset()
			i++
			continue
		}

		current.WriteRune(runes[i])
		i++
	}

	if stmt := strings.TrimSpace(current.String()); stmt != "" {
		statements = append(statements, stmt)
	}
	return statements
}

func extractDollarTag(runes []rune, i int) string {
	if i >= len(runes) || runes[i] != '$' {
		return ""
	}
	j := i + 1
	for j < len(runes) && j < i+100 {
		if runes[j] == '$' {
			return string(runes[i : j+1])
		}
		if !((runes[j] >= 'a' && runes[j] <= 'z') ||
			(runes[j] >= 'A' && runes[j] <= 'Z') ||
			(runes[j] >= '0' && runes[j] <= '9') ||
			runes[j] == '_') {
			return ""
		}
		j++
	}
	return ""
}
