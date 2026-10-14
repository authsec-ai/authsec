package database

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// AdminWorkspaceRepository handles workspace identity database operations from
// admin contexts.
//
// Phase 6 collapse: queries now target the `workspaces` table rather than the
// dropped `tenants` table. Type name preserved for source-compat; rename to
// AdminWorkspaceRepository is tracked as Phase 9/10 cosmetic.
type AdminWorkspaceRepository struct {
	db *DBConnection
}

// NewAdminWorkspaceRepository creates a new admin workspace repository.
func NewAdminWorkspaceRepository(db *DBConnection) *AdminWorkspaceRepository {
	return &AdminWorkspaceRepository{db: db}
}

// GetWorkspaceByID retrieves a workspace by its ID.
func (atr *AdminWorkspaceRepository) GetWorkspaceByID(workspaceID string) (*models.Tenant, error) {
	// TENANT-EXEMPT: registry row of a workspace the caller already resolved.
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

// GetWorkspaceByDomain retrieves a workspace by its domain. Supports
// custom domains via the workspace_domains join.
func (atr *AdminWorkspaceRepository) GetWorkspaceByDomain(workspaceDomain string) (*models.Tenant, error) {
	log.Printf("DEBUG GetWorkspaceByDomain: Looking up domain='%s'", workspaceDomain)

	// TENANT-EXEMPT: pre-auth resolution of a host name to its workspace
	// (login pages choose the identity provider and branding from it).
	query := `
		SELECT ` + workspaceSelectColsFromAlias + `
		FROM workspaces w
		INNER JOIN workspace_domains td ON w.id = td.workspace_id
		WHERE LOWER(td.domain) = LOWER($1) AND td.is_verified = true
		LIMIT 1
	`
	var t models.Tenant
	err := scanWorkspaceRow(atr.db.QueryRow(query, workspaceDomain), &t)
	if err == nil {
		log.Printf("DEBUG GetWorkspaceByDomain: Found via workspace_domains: workspace_id=%s, workspace_domain=%s", t.WorkspaceID, t.WorkspaceDomain)
		return &t, nil
	}
	log.Printf("DEBUG GetWorkspaceByDomain: Not found in workspace_domains (error: %v), trying fallback", err)

	// Fallback: direct lookup on workspaces.workspace_domain
	// TENANT-EXEMPT: pre-auth registry lookup by host name, as above.
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

// GetWorkspaceByUUID retrieves a workspace by UUID.
func (atr *AdminWorkspaceRepository) GetWorkspaceByUUID(workspaceID uuid.UUID) (*models.Tenant, error) {
	return atr.GetWorkspaceByID(workspaceID.String())
}

// CreateTenantTx inserts a workspace identity row within a transaction.
func (atr *AdminWorkspaceRepository) CreateTenantTx(tx *sql.Tx, t *models.Tenant) error {
	// TENANT-EXEMPT: workspaces is the tenant registry itself; this creates
	// a new tenant at sign-up.
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
		t.ID, t.Name, t.Email, t.PasswordHash, t.Provider, t.Source, t.Status, t.WorkspaceDomain, t.CreatedAt, t.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create workspace: %w", err)
	}
	return nil
}
