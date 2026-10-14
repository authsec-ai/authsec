package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/spire/domain/models"
	"github.com/authsec-ai/authsec/internal/spire/domain/repositories"
	"github.com/authsec-ai/authsec/internal/spire/errors"
	"github.com/authsec-ai/authsec/internal/tenancy"
)

// PostgresPolicyRepository stores attestation policies
// (spire_attestation_policies) of the workspace carried by ctx.
type PostgresPolicyRepository struct {
	db *sql.DB
}

// NewPostgresPolicyRepository creates the attestation policy repository.
func NewPostgresPolicyRepository(db *sql.DB) repositories.PolicyRepository {
	return &PostgresPolicyRepository{db: db}
}

// Create inserts a policy for ctx's workspace.
func (r *PostgresPolicyRepository) Create(ctx context.Context, p *models.AttestationPolicy) error {
	ws, err := workspaceOf(ctx)
	if err != nil {
		return err
	}
	if p.ID == "" {
		p.ID = uuid.NewString()
	}
	p.WorkspaceID = ws.String()
	now := time.Now()
	p.CreatedAt, p.UpdatedAt = now, now
	rules, err := json.Marshal(p.SelectorRules)
	if err != nil {
		return errors.NewInternalError("Failed to marshal selector rules", err)
	}
	_, err = tenancy.InsertContext(ctx, r.db, `
		INSERT INTO spire_attestation_policies (
			workspace_id, id, name, description, attestation_type, selector_rules, vault_role,
			ttl, priority, enabled, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		p.ID, p.Name, nullString(p.Description), p.AttestationType, rules, p.VaultRole,
		p.TTL, p.Priority, p.Enabled, p.CreatedAt, p.UpdatedAt)
	if err != nil {
		return errors.NewInternalError("Failed to create policy", err)
	}
	return nil
}

// FindMatchingPolicy returns the highest-priority enabled policy of ctx's
// workspace for this attestation type whose rules the selectors satisfy.
func (r *PostgresPolicyRepository) FindMatchingPolicy(ctx context.Context, attestationType string, selectors map[string]string) (*models.AttestationPolicy, error) {
	rows, err := tenancy.QueryContext(ctx, r.db, `
		SELECT id::text, workspace_id::text, name, COALESCE(description, ''), attestation_type,
		       selector_rules, vault_role, ttl, priority, enabled, created_at, updated_at
		  FROM spire_attestation_policies
		 WHERE workspace_id = $1 AND attestation_type = $2 AND enabled = true
		 ORDER BY priority DESC`, attestationType)
	if err != nil {
		return nil, errors.NewInternalError("Failed to query policies", err)
	}
	defer rows.Close()
	for rows.Next() {
		p := &models.AttestationPolicy{}
		var rules []byte
		if err := rows.Scan(&p.ID, &p.WorkspaceID, &p.Name, &p.Description, &p.AttestationType,
			&rules, &p.VaultRole, &p.TTL, &p.Priority, &p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, errors.NewInternalError("Failed to scan policy", err)
		}
		if err := json.Unmarshal(rules, &p.SelectorRules); err != nil {
			return nil, errors.NewInternalError("Failed to unmarshal selector rules", err)
		}
		if p.MatchesSelectors(selectors) {
			return p, nil
		}
	}
	if err := rows.Err(); err != nil {
		return nil, errors.NewInternalError("Error iterating policies", err)
	}
	return nil, errors.NewNotFoundError("No matching policy found", nil)
}
