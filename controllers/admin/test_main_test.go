package admin

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/config"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

var seededWorkspaceID uuid.UUID

func TestMain(m *testing.M) {
	if os.Getenv("RUN_INTEGRATION") == "1" {
		dbName, cleanup, err := createAdminTempDB()
		if err != nil {
			log.Fatalf("Failed to create temp test database: %v", err)
		}
		defer cleanup()

		// Set all required DB env vars for config.LoadConfig()
		os.Setenv("DB_NAME", dbName)
		if os.Getenv("DB_HOST") == "" {
			os.Setenv("DB_HOST", "localhost")
		}
		if os.Getenv("DB_PORT") == "" {
			os.Setenv("DB_PORT", "5432")
		}
		if os.Getenv("DB_USER") == "" {
			os.Setenv("DB_USER", "postgres")
		}
		if os.Getenv("DB_PASSWORD") == "" {
			os.Setenv("DB_PASSWORD", "postgres")
		}
		os.Unsetenv("SKIP_DB_INIT")
		os.Unsetenv("SKIP_MIGRATIONS")
		os.Unsetenv("SKIP_CONTROLLER_DB_SETUP")
		os.Setenv("REQUIRE_SERVER_AUTH", "false")
		os.Setenv("JWT_DEF_SECRET", "test-jwt-secret-key-for-testing-purposes-only")
		os.Setenv("JWT_SDK_SECRET", "test-jwt-secret-key-for-testing-purposes-only")

		cfg := config.LoadConfig()
		config.InitDatabaseWithoutGORM(cfg)

		if err := seedAdminTestData(dbName, cfg); err != nil {
			log.Fatalf("Failed to seed test admin: %v", err)
		}
	}

	code := m.Run()
	os.Exit(code)
}

func createAdminTempDB() (string, func(), error) {
	host := adminGetenvDefault("DB_HOST", "localhost")
	port := adminGetenvDefault("DB_PORT", "5432")
	user := adminGetenvDefault("DB_USER", "postgres")
	pass := adminGetenvDefault("DB_PASSWORD", "postgres")

	dbName := "test_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	adminDSN := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=postgres sslmode=disable", host, port, user, pass)

	adminDB, err := sql.Open("postgres", adminDSN)
	if err != nil {
		return "", nil, fmt.Errorf("open admin DB: %w", err)
	}
	if err := adminDB.Ping(); err != nil {
		adminDB.Close()
		return "", nil, fmt.Errorf("ping admin DB: %w", err)
	}

	if _, err := adminDB.Exec(`CREATE DATABASE "` + dbName + `"`); err != nil {
		adminDB.Close()
		return "", nil, fmt.Errorf("create test db: %w", err)
	}

	cleanup := func() {
		_, _ = adminDB.Exec(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1`, dbName)
		_, _ = adminDB.Exec(`DROP DATABASE IF EXISTS "` + dbName + `"`)
		adminDB.Close()
	}

	return dbName, cleanup, nil
}

func adminGetenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func seedAdminTestData(dbName string, cfg *config.Config) error {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
		cfg.DBHost, cfg.DBUser, cfg.DBPassword, dbName, cfg.DBPort)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	workspaceID := uuid.New()
	seededWorkspaceID = workspaceID
	userID := workspaceID
	clientID := workspaceID

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS tenants (workspace_id uuid PRIMARY KEY, email text, workspace_domain text, workspace_db text);`); err != nil {
		return err
	}

	// Create users table (needed for group operations that look up users)
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS users (id uuid PRIMARY KEY, email text, name text, provider text, password_hash text, client_id uuid, workspace_id uuid, workspace_domain text, active boolean DEFAULT true, temporary_password boolean DEFAULT false, temporary_password_expires_at timestamptz, failed_login_attempts integer DEFAULT 0, account_locked_at timestamptz, password_reset_required boolean DEFAULT false, created_at timestamptz DEFAULT now(), updated_at timestamptz DEFAULT now());`)

	_, _ = db.Exec(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS workspace_db text;`)
	_, _ = db.Exec(`ALTER TABLE users ADD COLUMN IF NOT EXISTS client_id uuid;`)
	_, _ = db.Exec(`ALTER TABLE users ADD COLUMN IF NOT EXISTS workspace_id uuid;`)
	_, _ = db.Exec(`ALTER TABLE users ADD COLUMN IF NOT EXISTS workspace_domain text;`)
	_, _ = db.Exec(`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash text;`)
	_, _ = db.Exec(`ALTER TABLE users ADD COLUMN IF NOT EXISTS active boolean DEFAULT true;`)
	_, _ = db.Exec(`ALTER TABLE users ADD COLUMN IF NOT EXISTS temporary_password boolean DEFAULT false;`)
	_, _ = db.Exec(`ALTER TABLE users ADD COLUMN IF NOT EXISTS temporary_password_expires_at timestamp with time zone;`)

	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS roles (id uuid PRIMARY KEY, workspace_id uuid, name text NOT NULL, description text, created_at timestamptz default now(), updated_at timestamptz default now(), UNIQUE(workspace_id,name));`)
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS role_bindings (id uuid PRIMARY KEY, workspace_id uuid, user_id uuid, role_id uuid, scope_type text, scope_id uuid, created_at timestamptz default now(), updated_at timestamptz default now());`)

	// Create groups table (for group controller operations)
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS groups (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL, description text, workspace_id uuid, created_at timestamptz DEFAULT now(), updated_at timestamptz DEFAULT now());`)

	// Create user_groups table (for group-user membership)
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS user_groups (user_id uuid NOT NULL, group_id uuid NOT NULL, workspace_id uuid, created_at timestamptz DEFAULT now(), updated_at timestamptz DEFAULT now(), PRIMARY KEY (user_id, group_id));`)

	// Create projects table (for project controller operations)
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS projects (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL, description text, user_id uuid, workspace_id uuid, active boolean DEFAULT true, created_at timestamptz DEFAULT now(), updated_at timestamptz DEFAULT now(), deleted_at timestamptz);`)

	_, _ = db.Exec(`INSERT INTO tenants (workspace_id, email, workspace_domain, workspace_db) VALUES ($1,$2,$3,$4) ON CONFLICT (workspace_id) DO UPDATE SET workspace_db=EXCLUDED.workspace_db`, workspaceID, "admin@test.local", "test.local", dbName)
	_, _ = db.Exec(`INSERT INTO users (id, email, password_hash, client_id, workspace_id, workspace_domain, active) VALUES ($1,$2,'', $3, $4, $5, true) ON CONFLICT (id) DO NOTHING`,
		userID, "admin@test.local", clientID, workspaceID, "test.local")

	var roleID uuid.UUID
	if err := db.QueryRow(`INSERT INTO roles (id, workspace_id, name, description) VALUES ($1, $2, 'admin', 'admin role') ON CONFLICT (workspace_id, name) DO UPDATE SET name=EXCLUDED.name RETURNING id`,
		uuid.New(), workspaceID).Scan(&roleID); err != nil {
		return err
	}
	bindingID := uuid.New()
	_, _ = db.Exec(`INSERT INTO role_bindings (id, workspace_id, user_id, role_id, scope_type, scope_id, created_at, updated_at) SELECT $1,$2,$3,$4,NULL,NULL,now(),now() WHERE NOT EXISTS (SELECT 1 FROM role_bindings WHERE workspace_id=$2 AND user_id=$3 AND role_id=$4)`, bindingID, workspaceID, userID, roleID)

	return nil
}
