package database

import (
	"database/sql"
	"fmt"
	"log"
)

// tenantProvisionContext is the minimal data, reconstructed from the master DB,
// needed to (re)seed a tenant's own database to a usable state.
type tenantProvisionContext struct {
	tenantID     string
	tenantDB     string
	email        string
	name         string
	provider     string
	source       string
	tenantDomain string

	// admin user (created in the same master transaction as the tenant)
	userID       string
	userEmail    string
	userName     string
	projectID    string
	clientID     string
	userProvider string
	providerID   string
}

// loadTenantProvisionContext reconstructs provisioning context for a tenant from
// the master DB: the tenant row plus its admin user (the user created alongside
// the tenant during registration). Returns an error if either is missing, so a
// tenant that cannot be fully reconstructed is left 'pending' and retried rather
// than falsely marked complete.
func (s *TenantDBService) loadTenantProvisionContext(tenantID string) (*tenantProvisionContext, error) {
	ctx := &tenantProvisionContext{tenantID: tenantID}

	err := s.masterDB.DB.QueryRow(
		`SELECT COALESCE(tenant_db,''), COALESCE(email,''), COALESCE(name,''),
		        COALESCE(provider,''), COALESCE(source,''), COALESCE(tenant_domain,'')
		 FROM tenants WHERE tenant_id = $1::uuid`, tenantID,
	).Scan(&ctx.tenantDB, &ctx.email, &ctx.name, &ctx.provider, &ctx.source, &ctx.tenantDomain)
	if err != nil {
		return nil, fmt.Errorf("load tenant row: %w", err)
	}

	// The admin user created with the tenant. There is one at registration time;
	// pick the earliest to be deterministic.
	err = s.masterDB.DB.QueryRow(
		`SELECT id, COALESCE(email,''), COALESCE(name,''),
		        COALESCE(project_id::text,''), COALESCE(client_id::text,''),
		        COALESCE(provider,''), COALESCE(provider_id,'')
		 FROM users
		 WHERE tenant_id = $1::uuid AND deleted_at IS NULL
		 ORDER BY created_at ASC
		 LIMIT 1`, tenantID,
	).Scan(&ctx.userID, &ctx.userEmail, &ctx.userName, &ctx.projectID,
		&ctx.clientID, &ctx.userProvider, &ctx.providerID)
	if err != nil {
		return nil, fmt.Errorf("load tenant admin user: %w", err)
	}

	// client_id == tenant_id for the default client (registration convention);
	// fall back to that if the stored client_id is empty.
	if ctx.clientID == "" {
		ctx.clientID = tenantID
	}
	if ctx.source == "" {
		ctx.source = "provisioning_resume"
	}
	if ctx.provider == "" {
		ctx.provider = ctx.userProvider
	}
	return ctx, nil
}

// seedTenantDBResources idempotently (re)creates the tenant-DB rows that the
// registration handlers create post-commit: the tenant record, default project,
// default client, the admin user, and the admin role binding. Every statement is
// ON CONFLICT / existence-guarded so it is safe to run against a partially- or
// fully-seeded tenant DB. Mirrors the inline SQL in the registration handlers;
// kept here (not shared with them) so the live signup flow is untouched.
func (s *TenantDBService) seedTenantDBResources(tdb *sql.DB, c *tenantProvisionContext) error {
	hydraClientID := fmt.Sprintf("%s-main-client", c.clientID)

	// Tenant record in the tenant DB.
	if _, err := tdb.Exec(
		`INSERT INTO tenants (id, tenant_id, email, password_hash, name, provider, source, status, tenant_domain, tenant_db, created_at, updated_at)
		 VALUES ($1::uuid, $1::uuid, $2, '', $3, $4, $5, 'active', $6, $7, NOW(), NOW())
		 ON CONFLICT (id) DO NOTHING`,
		c.tenantID, c.email, c.name, c.provider, c.source, c.tenantDomain, c.tenantDB); err != nil {
		return fmt.Errorf("seed tenant record: %w", err)
	}

	// Default project.
	if c.projectID != "" {
		if _, err := tdb.Exec(
			`INSERT INTO projects (id, tenant_id, name, description, user_id, active, created_at, updated_at)
			 VALUES ($1::uuid, $2::uuid, 'Default Project', 'Default project', $2::uuid, true, NOW(), NOW())
			 ON CONFLICT (id) DO NOTHING`,
			c.projectID, c.tenantID); err != nil {
			return fmt.Errorf("seed project: %w", err)
		}
	}

	// Default client.
	if c.projectID != "" {
		if _, err := tdb.Exec(
			`INSERT INTO clients (id, client_id, tenant_id, project_id, owner_id, org_id, name, description, hydra_client_id, active, created_at, updated_at)
			 VALUES ($1::uuid, $1::uuid, $2::uuid, $3::uuid, $2::uuid, $2::uuid, 'Default Client', 'Default client', $4, true, NOW(), NOW())
			 ON CONFLICT (id) DO NOTHING`,
			c.clientID, c.tenantID, c.projectID, hydraClientID); err != nil {
			return fmt.Errorf("seed default client: %w", err)
		}
	}

	// Admin user in the tenant DB.
	if c.projectID != "" {
		if _, err := tdb.Exec(
			`INSERT INTO users (id, email, name, tenant_id, client_id, project_id, tenant_domain, provider, provider_id, active, created_at, updated_at)
			 VALUES ($1::uuid, $2, $3, $4::uuid, $5::uuid, $6::uuid, $7, $8, NULLIF($9,''), true, NOW(), NOW())
			 ON CONFLICT (id) DO NOTHING`,
			c.userID, c.userEmail, c.userName, c.tenantID, c.clientID, c.projectID,
			c.tenantDomain, c.provider, c.providerID); err != nil {
			return fmt.Errorf("seed tenant user: %w", err)
		}
	}

	// Admin role + binding (mirrors OIDCController.assignAdminRoleToUser).
	var adminRoleID string
	err := tdb.QueryRow(`SELECT id FROM roles WHERE name = 'admin' AND tenant_id = $1::uuid`, c.tenantID).Scan(&adminRoleID)
	if err == sql.ErrNoRows {
		if err = tdb.QueryRow(
			`INSERT INTO roles (name, description, tenant_id) VALUES ('admin', 'Administrator role with full access', $1::uuid) RETURNING id`,
			c.tenantID).Scan(&adminRoleID); err != nil {
			return fmt.Errorf("seed admin role: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("check admin role: %w", err)
	}

	var bindingExists int
	err = tdb.QueryRow(
		`SELECT 1 FROM role_bindings WHERE user_id = $1::uuid AND role_id = $2::uuid AND tenant_id = $3::uuid AND scope_type IS NULL`,
		c.userID, adminRoleID, c.tenantID).Scan(&bindingExists)
	if err == sql.ErrNoRows {
		if _, err = tdb.Exec(
			`INSERT INTO role_bindings (id, tenant_id, user_id, role_id, scope_type, scope_id, created_at, updated_at)
			 VALUES (gen_random_uuid(), $1::uuid, $2::uuid, $3::uuid, NULL, NULL, NOW(), NOW())`,
			c.tenantID, c.userID, adminRoleID); err != nil {
			return fmt.Errorf("seed admin role binding: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("check admin role binding: %w", err)
	}

	return nil
}

// ProvisionTenantInfra (re)runs the idempotent, post-commit infrastructure
// provisioning for a tenant so it is usable for login and tenant-scoped RBAC:
// ensure the tenant DB exists and is fully migrated, reconstruct context from
// the master DB, (re)seed the tenant-DB records (tenant/project/client/user/
// admin role), ensure the master tenant_mappings row, then mark
// provisioning_state = 'complete'. Idempotent and safe to call repeatedly.
//
// Hydra client + Vault secret + PKI are intentionally NOT (re)done here — those
// are reconciled by their own workers (Hydra reconciler v2, PKI retry worker)
// and are not required for basic login. This function does only DB-level work,
// so it never needs the services layer.
func (s *TenantDBService) ProvisionTenantInfra(tenantID string) error {
	// 1. Ensure the tenant DB exists and every migration is applied. Idempotent:
	//    skips CREATE DATABASE if present and always re-runs migrations.
	dbName, err := s.CreateTenantDatabase(tenantID)
	if err != nil {
		return fmt.Errorf("ensure tenant database: %w", err)
	}

	// 2. Reconstruct provisioning context from the master DB.
	ctx, err := s.loadTenantProvisionContext(tenantID)
	if err != nil {
		return fmt.Errorf("reconstruct context: %w", err)
	}
	if ctx.tenantDB == "" {
		ctx.tenantDB = dbName
	}

	// 3. (Re)seed the tenant DB records.
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		s.dbHost, s.dbPort, s.dbUser, s.dbPassword, dbName)
	tdb, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("open tenant DB: %w", err)
	}
	defer tdb.Close()
	if err := tdb.Ping(); err != nil {
		return fmt.Errorf("ping tenant DB: %w", err)
	}
	if err := s.seedTenantDBResources(tdb, ctx); err != nil {
		return err
	}

	// 4. Ensure the client_id -> tenant_id mapping exists (client_id == tenant_id).
	if _, err := s.masterDB.DB.Exec(
		`INSERT INTO tenant_mappings (tenant_id, client_id, created_at, updated_at)
		 VALUES ($1::uuid, $1::uuid, NOW(), NOW())
		 ON CONFLICT (client_id) DO NOTHING`, tenantID); err != nil {
		return fmt.Errorf("ensure tenant_mappings: %w", err)
	}

	// 5. Mark provisioning complete (only reached if all of the above succeeded).
	if _, err := s.masterDB.DB.Exec(
		`UPDATE tenants SET provisioning_state = 'complete', updated_at = NOW() WHERE tenant_id = $1::uuid`,
		tenantID); err != nil {
		return fmt.Errorf("mark provisioning_state=complete: %w", err)
	}
	return nil
}

// ResumePendingTenants finds tenants whose post-commit provisioning never
// completed and re-runs it idempotently. A tenant is a repair candidate when,
// at least 10 minutes after creation (to avoid racing an in-flight
// registration), it is either explicitly marked 'pending' OR its tenant
// database does not physically exist. The 'pending' marker covers interruptions
// detected by the registration handlers; the missing-database check is
// saga-agnostic and also catches the email/password path and any pre-existing
// orphan. Returns the number of tenants successfully repaired; per-tenant errors
// are logged and do not abort the sweep.
func (s *TenantDBService) ResumePendingTenants() (int, error) {
	rows, err := s.masterDB.DB.Query(
		`SELECT t.tenant_id
		 FROM tenants t
		 WHERE COALESCE(t.tenant_db, '') <> ''
		   AND t.created_at < NOW() - INTERVAL '10 minutes'
		   AND (
		     t.provisioning_state = 'pending'
		     OR NOT EXISTS (SELECT 1 FROM pg_database d WHERE d.datname = t.tenant_db)
		   )`)
	if err != nil {
		return 0, fmt.Errorf("query pending tenants: %w", err)
	}

	var pending []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan pending tenant: %w", err)
		}
		pending = append(pending, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	if len(pending) == 0 {
		return 0, nil
	}
	log.Printf("[provisioning-resume] found %d tenant(s) with incomplete provisioning; repairing", len(pending))

	repaired := 0
	for _, id := range pending {
		if err := s.ProvisionTenantInfra(id); err != nil {
			log.Printf("[provisioning-resume] tenant %s repair failed (will retry next sweep): %v", id, err)
			continue
		}
		log.Printf("[provisioning-resume] tenant %s repaired (provisioning_state=complete)", id)
		repaired++
	}
	return repaired, nil
}
