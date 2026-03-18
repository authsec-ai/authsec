package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/database"
	"github.com/authsec-ai/authsec/internal/migration"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load()

	cfg := config.LoadConfig()
	config.InitDatabaseWithoutGORM(cfg)

	tenantID := getEnv("SEED_TENANT_ID", "11111111-1111-1111-1111-111111111111")
	adminEmail := strings.ToLower(getEnv("LOCAL_DEMO_ADMIN_EMAIL", "admin@test.com"))
	adminPassword := getEnv("LOCAL_DEMO_ADMIN_PASSWORD", "")
	adminName := getEnv("LOCAL_DEMO_ADMIN_NAME", "Local Admin")
	tenantDomain := getEnv("LOCAL_DEMO_ADMIN_TENANT_DOMAIN", "test.authsec.dev")

	if adminPassword == "" {
		log.Fatal("LOCAL_DEMO_ADMIN_PASSWORD is required for local seeding")
	}

	if err := ensureTenantRecord(tenantID, adminEmail, tenantDomain); err != nil {
		log.Fatalf("local seed: ensure tenant record: %v", err)
	}
	if err := ensureTenantDatabase(cfg, tenantID); err != nil {
		log.Fatalf("local seed: ensure tenant database: %v", err)
	}
	if err := ensureAdminCredentials(tenantID, tenantDomain, adminEmail, adminPassword, adminName); err != nil {
		log.Fatalf("local seed: ensure admin credentials: %v", err)
	}

	log.Printf("local seed complete: tenant=%s admin=%s domain=%s", tenantID, adminEmail, tenantDomain)
}

func ensureTenantRecord(tenantID, adminEmail, tenantDomain string) error {
	db := config.GetDatabase()
	if db == nil {
		return fmt.Errorf("database not initialized")
	}

	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return fmt.Errorf("parse tenant id: %w", err)
	}

	now := time.Now().UTC()
	dbName := migration.GenerateTenantDBName(tenantID)

	var existingID uuid.UUID
	err = db.QueryRow(`
		SELECT id
		FROM tenants
		WHERE tenant_id = $1 OR id = $1
		LIMIT 1
	`, tenantUUID).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("lookup tenant record: %w", err)
	}

	if err == sql.ErrNoRows {
		_, err = db.Exec(`
			INSERT INTO tenants (id, tenant_id, tenant_db, email, tenant_domain, name, status, migration_status, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, 'active', 'pending', $7, $7)
		`, tenantUUID, tenantUUID, dbName, adminEmail, tenantDomain, "Local SDK Demo", now)
		if err != nil {
			return fmt.Errorf("insert tenant record: %w", err)
		}
		return nil
	}

	_, err = db.Exec(`
		UPDATE tenants
		SET tenant_db = $2,
		    email = $3,
		    tenant_domain = $4,
		    name = $5,
		    status = 'active',
		    updated_at = $6
		WHERE id = $1
	`, existingID, dbName, adminEmail, tenantDomain, "Local SDK Demo", now)
	if err != nil {
		return fmt.Errorf("update tenant record: %w", err)
	}

	return nil
}

func ensureTenantDatabase(cfg *config.Config, tenantID string) error {
	dbName := migration.GenerateTenantDBName(tenantID)
	if _, err := migration.CreateDatabase(cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, dbName); err != nil {
		return err
	}
	if err := migration.RunTenantMigrationsInProcess(
		tenantID,
		cfg.DBHost,
		cfg.DBPort,
		cfg.DBUser,
		cfg.DBPassword,
		dbName,
		config.GetDatabase().DB,
		migration.MigrationsDir("tenant"),
	); err != nil {
		return err
	}

	_, err := config.GetDatabase().Exec(`
		UPDATE tenants
		SET tenant_db = $2,
		    migration_status = 'completed',
		    updated_at = NOW()
		WHERE tenant_id = $1
	`, tenantID, dbName)
	if err != nil {
		return fmt.Errorf("mark tenant migration complete: %w", err)
	}

	return nil
}

func ensureAdminCredentials(tenantID, tenantDomain, email, password, name string) error {
	db := config.GetDatabase()
	if db == nil {
		return fmt.Errorf("database not initialized")
	}

	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return fmt.Errorf("parse tenant id: %w", err)
	}

	adminRepo := database.NewAdminUserRepository(db)
	existing, err := adminRepo.GetAdminUserByEmail(email)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("lookup admin user: %w", err)
	}
	if err == sql.ErrNoRows {
		existing, err = lookupExistingTenantUser(tenantUUID, email)
		if err != nil {
			return fmt.Errorf("lookup existing tenant user: %w", err)
		}
	}

	passwordHolder := &models.AdminUser{Password: password}
	if err := passwordHolder.HashPassword(); err != nil {
		return fmt.Errorf("hash admin password: %w", err)
	}

	projectID := tenantUUID
	clientID := tenantUUID
	username := strings.Split(email, "@")[0]

	if existing == nil {
		user := &models.AdminUser{
			Email:        email,
			Username:     username,
			PasswordHash: passwordHolder.PasswordHash,
			Name:         name,
			ClientID:     &clientID,
			TenantID:     &tenantUUID,
			ProjectID:    &projectID,
			TenantDomain: tenantDomain,
			Provider:     "local",
			Active:       true,
		}
		if err := adminRepo.CreateAdminUser(user); err != nil {
			return fmt.Errorf("create admin user: %w", err)
		}
	} else {
		updates := map[string]interface{}{
			"email":                         email,
			"username":                      username,
			"password_hash":                 passwordHolder.PasswordHash,
			"name":                          name,
			"client_id":                     clientID,
			"tenant_id":                     tenantUUID,
			"project_id":                    projectID,
			"tenant_domain":                 tenantDomain,
			"provider":                      "local",
			"active":                        true,
			"temporary_password":            false,
			"temporary_password_expires_at": nil,
			"failed_login_attempts":         0,
			"account_locked_at":             nil,
			"password_reset_required":       false,
		}
		if err := adminRepo.UpdateAdminUser(existing.ID, updates); err != nil {
			return fmt.Errorf("update admin user: %w", err)
		}
	}

	if err := adminRepo.EnsureTenantAdminRoleAssignment(tenantUUID); err != nil {
		return fmt.Errorf("ensure admin role assignment: %w", err)
	}

	return nil
}

func lookupExistingTenantUser(tenantID uuid.UUID, email string) (*models.AdminUser, error) {
	db := config.GetDatabase()
	if db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	var existingID uuid.UUID
	err := db.QueryRow(`
		SELECT id
		FROM users
		WHERE tenant_id = $1
		  AND LOWER(email) = LOWER($2)
		ORDER BY created_at ASC
		LIMIT 1
	`, tenantID, email).Scan(&existingID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &models.AdminUser{ID: existingID}, nil
}

func getEnv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
