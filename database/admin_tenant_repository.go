package database

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// AdminTenantRepository handles workspace identity database operations from
// admin contexts.
//
// Phase 6 collapse: queries now target the `workspaces` table rather than the
// dropped `tenants` table. Type name preserved for source-compat; rename to
// AdminWorkspaceRepository is tracked as Phase 9/10 cosmetic.
type AdminTenantRepository struct {
	db *DBConnection
}

// NewAdminTenantRepository creates a new admin workspace repository.
func NewAdminTenantRepository(db *DBConnection) *AdminTenantRepository {
	return &AdminTenantRepository{db: db}
}

// GetAllTenants retrieves all workspace identity rows.
func (atr *AdminTenantRepository) GetAllTenants() ([]models.Tenant, error) {
	query := `SELECT ` + workspaceSelectCols + ` FROM workspaces ORDER BY created_at DESC`
	rows, err := atr.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query workspaces: %w", err)
	}
	defer rows.Close()

	var tenants []models.Tenant
	for rows.Next() {
		var t models.Tenant
		if err := scanWorkspaceRow(rows, &t); err != nil {
			return nil, fmt.Errorf("failed to scan workspace row: %w", err)
		}
		tenants = append(tenants, t)
	}
	return tenants, nil
}

// GetTenantByID retrieves a workspace by its ID.
func (atr *AdminTenantRepository) GetTenantByID(workspaceID string) (*models.Tenant, error) {
	query := `SELECT ` + workspaceSelectCols + ` FROM workspaces WHERE id = $1`
	var t models.Tenant
	err := scanWorkspaceRow(atr.db.QueryRow(query, workspaceID), &t)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("workspace not found")
		}
		return nil, fmt.Errorf("failed to get workspace: %w", err)
	}
	return &t, nil
}

// CreateTenant inserts a new workspace identity row.
func (atr *AdminTenantRepository) CreateTenant(t *models.Tenant) error {
	query := `
		INSERT INTO workspaces (id, name, email, password_hash, provider, source, status, workspace_domain, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	now := time.Now()
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	if t.UpdatedAt.IsZero() {
		t.UpdatedAt = now
	}
	_, err := atr.db.Exec(query,
		t.ID, t.Name, t.Email, t.PasswordHash, t.Provider, t.Source, t.Status, t.TenantDomain, t.CreatedAt, t.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create workspace: %w", err)
	}
	return nil
}

// UpdateTenant updates fields on the workspace identity row keyed by id.
func (atr *AdminTenantRepository) UpdateTenant(workspaceID string, updates map[string]interface{}) error {
	if len(updates) == 0 {
		return fmt.Errorf("no updates provided")
	}

	query := "UPDATE workspaces SET "
	args := []interface{}{}
	argCount := 1

	for field, value := range updates {
		query += field + " = $" + fmt.Sprintf("%d", argCount) + ", "
		args = append(args, value)
		argCount++
	}

	query += "updated_at = $" + fmt.Sprintf("%d", argCount)
	args = append(args, time.Now())
	argCount++

	query += " WHERE id = $" + fmt.Sprintf("%d", argCount)
	args = append(args, workspaceID)

	_, err := atr.db.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("failed to update workspace: %w", err)
	}
	return nil
}

// GetTenantUsers retrieves all users for a specific workspace.
// Returns empty slice; admin user listing has dedicated repositories now.
func (atr *AdminTenantRepository) GetTenantUsers(workspaceID string) ([]models.User, error) {
	return []models.User{}, nil
}

// GetTenantByDomain retrieves a workspace by its domain. Supports
// custom domains via the tenant_domains join.
func (atr *AdminTenantRepository) GetTenantByDomain(workspaceDomain string) (*models.Tenant, error) {
	log.Printf("DEBUG GetTenantByDomain: Looking up domain='%s'", workspaceDomain)

	// First try via tenant_domains (custom-domain mapping).
	query := `
		SELECT ` + workspaceSelectCols + `
		FROM workspaces w
		INNER JOIN tenant_domains td ON w.id = td.workspace_id
		WHERE LOWER(td.domain) = LOWER($1) AND td.is_verified = true
		LIMIT 1
	`
	var t models.Tenant
	err := scanWorkspaceRow(atr.db.QueryRow(query, workspaceDomain), &t)
	if err == nil {
		log.Printf("DEBUG GetTenantByDomain: Found via tenant_domains: workspace_id=%s, workspace_domain=%s", t.WorkspaceID, t.TenantDomain)
		return &t, nil
	}
	log.Printf("DEBUG GetTenantByDomain: Not found in tenant_domains (error: %v), trying fallback", err)

	// Fallback: direct lookup on workspaces.workspace_domain
	fallbackQuery := `SELECT ` + workspaceSelectCols + ` FROM workspaces WHERE workspace_domain LIKE $1 OR workspace_domain = $2`
	err = scanWorkspaceRow(atr.db.QueryRow(fallbackQuery, workspaceDomain+"%", workspaceDomain), &t)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("workspace not found")
		}
		return nil, fmt.Errorf("failed to get workspace by domain: %w", err)
	}
	return &t, nil
}

// GetTenantByUUID retrieves a workspace by UUID.
func (atr *AdminTenantRepository) GetTenantByUUID(workspaceID uuid.UUID) (*models.Tenant, error) {
	return atr.GetTenantByID(workspaceID.String())
}

// CreateTenantTx inserts a workspace identity row within a transaction.
func (atr *AdminTenantRepository) CreateTenantTx(tx *sql.Tx, t *models.Tenant) error {
	query := `
		INSERT INTO workspaces (id, name, email, password_hash, provider, source, status, workspace_domain, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	now := time.Now()
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	if t.UpdatedAt.IsZero() {
		t.UpdatedAt = now
	}
	_, err := tx.Exec(query,
		t.ID, t.Name, t.Email, t.PasswordHash, t.Provider, t.Source, t.Status, t.TenantDomain, t.CreatedAt, t.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create workspace: %w", err)
	}
	return nil
}

// CreateProjectTx creates a new project within a transaction.
func (atr *AdminTenantRepository) CreateProjectTx(tx *sql.Tx, projectID, workspaceID, userID uuid.UUID, name string) error {
	query := `
		INSERT INTO projects (id, workspace_id, name, description, user_id, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	now := time.Now()
	_, err := tx.Exec(query,
		projectID, workspaceID, name, "Default project", userID, true, now, now,
	)
	if err != nil {
		return fmt.Errorf("failed to create project: %w", err)
	}
	return nil
}

// CreateAdminUserTx creates a new admin user within a transaction.
func (atr *AdminTenantRepository) CreateAdminUserTx(tx *sql.Tx, user *models.AdminUser) error {
	query := `
		INSERT INTO users (id, email, username, password_hash, name, workspace_id, project_id,
			client_id, tenant_domain, provider, provider_id, avatar_url, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`
	now := time.Now()
	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}
	_, err := tx.Exec(query,
		user.ID, user.Email, user.Username, user.PasswordHash, user.Name,
		user.WorkspaceID, user.ProjectID, user.ClientID, user.TenantDomain,
		user.Provider, user.ProviderID, user.AvatarURL, user.Active, now, now,
	)
	if err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}
	return nil
}

// GetAdminUserByID retrieves an admin user by ID.
func (atr *AdminTenantRepository) GetAdminUserByID(userID uuid.UUID) (*models.AdminUser, error) {
	query := `
		SELECT id, email, username, password_hash, name, workspace_id, project_id,
			client_id, tenant_domain, provider, provider_id, avatar_url, active,
			created_at, updated_at
		FROM users
		WHERE id = $1
	`
	var user models.AdminUser
	var workspaceID, projectID, clientID sql.NullString
	var providerID, avatarURL sql.NullString

	err := atr.db.QueryRow(query, userID).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.Name,
		&workspaceID,
		&projectID,
		&clientID,
		&user.TenantDomain,
		&user.Provider,
		&providerID,
		&avatarURL,
		&user.Active,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("admin user not found")
		}
		return nil, fmt.Errorf("failed to get admin user: %w", err)
	}

	if workspaceID.Valid {
		id, _ := uuid.Parse(workspaceID.String)
		user.WorkspaceID = &id
	}
	if projectID.Valid {
		id, _ := uuid.Parse(projectID.String)
		user.ProjectID = &id
	}
	if clientID.Valid {
		id, _ := uuid.Parse(clientID.String)
		user.ClientID = &id
	}
	if providerID.Valid {
		user.ProviderID = providerID.String
	}
	if avatarURL.Valid {
		user.AvatarURL = avatarURL.String
	}
	return &user, nil
}
