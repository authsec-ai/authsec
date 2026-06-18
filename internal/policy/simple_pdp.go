package policy

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// policyRow is the DB shape for a single policies row.
type policyRow struct {
	ID               uuid.UUID
	SubjectType      *string
	SubjectID        *uuid.UUID
	ClientID         *string
	ResourceServerID *uuid.UUID
	TokenFamily      string
	Effect           string
	Priority         int
}

// SimplePDP evaluates the `policies` table with explicit-deny-wins semantics:
//   - Rows matched = those where every non-null selector equals the request value.
//   - If any matched row has effect='deny' → EffectDeny (deny wins regardless of permits).
//   - If any matched row has effect='permit' → EffectPermit.
//   - No matched rows → EffectNoPolicy (defers to the existing thin gates).
type SimplePDP struct {
	db *gorm.DB
}

// NewSimplePDP creates a PDP backed by the provided GORM connection.
func NewSimplePDP(db *gorm.DB) *SimplePDP {
	return &SimplePDP{db: db}
}

func (p *SimplePDP) Decide(ctx context.Context, req PolicyRequest) (PolicyDecision, error) {
	rows, err := p.loadMatchingPolicies(ctx, req)
	if err != nil {
		return PolicyDecision{Effect: EffectNoPolicy, Reason: fmt.Sprintf("policy load error: %v", err)}, err
	}

	if len(rows) == 0 {
		return PolicyDecision{Effect: EffectNoPolicy, Reason: "no policy matched"}, nil
	}

	for _, r := range rows {
		if r.Effect == "deny" {
			return PolicyDecision{
				Effect: EffectDeny,
				Reason: fmt.Sprintf("policy %s: explicit deny (priority %d)", r.ID, r.Priority),
			}, nil
		}
	}

	return PolicyDecision{Effect: EffectPermit, Reason: "permit policy matched"}, nil
}

// loadMatchingPolicies fetches active policies for the workspace ordered by
// priority DESC (highest first) so deny rules at high priority are evaluated
// first and can be short-circuited.
//
// For xaa family requests it also UNIONs a2a_brokering_policies (side='redemption')
// as synthetic policy rows so the PDP subsumes the thin brokering gate — this
// allows shadow-mode verification and enforce-mode authority without removing
// the P3 gate in one step.
func (p *SimplePDP) loadMatchingPolicies(ctx context.Context, req PolicyRequest) ([]policyRow, error) {
	query := `
		SELECT id, subject_type, subject_id, client_id, resource_server_id, token_family, effect, priority
		FROM policies
		WHERE workspace_id = $1
		  AND is_active = true
		  AND (subject_type IS NULL OR subject_type = '*' OR subject_type = $2)
		  AND (subject_id IS NULL OR subject_id = $3)
		  AND (client_id IS NULL OR client_id = $4)
		  AND (resource_server_id IS NULL OR resource_server_id = $5)
		  AND (token_family = '*' OR token_family = $6)

		UNION ALL

		-- a2a_brokering_policies side='redemption' treated as synthetic permit/deny rows
		-- when evaluating XAA token requests. client_id stored as text in policies but
		-- as uuid in a2a_brokering_policies — cast to text for the union.
		SELECT id, NULL::text, NULL::uuid,
		       client_id::text, resource_server_id, 'xaa'::text, effect, 0
		FROM a2a_brokering_policies
		WHERE workspace_id = $1
		  AND side = 'redemption'
		  AND $6 = 'xaa'
		  AND (client_id IS NULL OR client_id::text = $4)
		  AND (resource_server_id IS NULL OR resource_server_id = $5)

		UNION ALL

		-- delegation_policies are plane-C residuals: workspace-scoped allow rules
		-- with client_id (uuid) + allowed_permissions. We fold them in as synthetic
		-- permit rows (enabled=true) or deny rows (enabled=false) for the m2m/xaa
		-- families that were the intended consumers. Cast uuid client_id to text.
		SELECT id, NULL::text, NULL::uuid,
		       client_id::text, NULL::uuid, 'xaa'::text,
		       CASE WHEN enabled THEN 'permit' ELSE 'deny' END, 0
		FROM delegation_policies
		WHERE workspace_id = $1
		  AND $6 IN ('m2m','xaa')
		  AND (client_id IS NULL OR client_id::text = $4)

		ORDER BY priority DESC
	`

	sqlDB, err := p.db.DB()
	if err != nil {
		return nil, fmt.Errorf("get sql.DB: %w", err)
	}

	dbRows, err := sqlDB.QueryContext(ctx, query,
		req.WorkspaceID,
		req.SubjectType,
		req.SubjectID,
		req.ClientID,
		req.ResourceServerID,
		req.TokenFamily,
	)
	if err != nil {
		return nil, fmt.Errorf("query policies: %w", err)
	}
	defer dbRows.Close()

	var result []policyRow
	for dbRows.Next() {
		var r policyRow
		if err := dbRows.Scan(
			&r.ID, &r.SubjectType, &r.SubjectID, &r.ClientID,
			&r.ResourceServerID, &r.TokenFamily, &r.Effect, &r.Priority,
		); err != nil {
			return nil, fmt.Errorf("scan policy row: %w", err)
		}
		result = append(result, r)
	}
	if err := dbRows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// IssuanceAuditRow is written to auth_issuance_audit by RecordAudit.
type IssuanceAuditRow struct {
	WorkspaceID      uuid.UUID
	TokenFamily      string
	ClientID         string
	SubjectType      string
	SubjectID        *uuid.UUID
	ResourceServerID uuid.UUID
	PDPEffect        string
	GateEffect       string
	PDPAgrees        bool
	ScopesRequested  string
	ScopesGranted    string
	PDPReason        string
}

// RecordAudit writes a shadow-mode comparison record. Errors are non-fatal and
// logged via fmt.Printf because audit failures must never block issuance.
func RecordAudit(ctx context.Context, db *gorm.DB, a IssuanceAuditRow) {
	sqlDB, err := db.DB()
	if err != nil {
		fmt.Printf("[policy audit] get sql.DB: %v\n", err)
		return
	}
	var subjectID interface{}
	if a.SubjectID != nil {
		subjectID = *a.SubjectID
	} else {
		subjectID = sql.NullString{}
	}
	_, err = sqlDB.ExecContext(ctx, `
		INSERT INTO auth_issuance_audit
			(workspace_id, token_family, client_id, subject_type, subject_id,
			 resource_server_id, pdp_effect, gate_effect, pdp_agrees,
			 scopes_requested, scopes_granted, pdp_reason)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		a.WorkspaceID, a.TokenFamily, a.ClientID, a.SubjectType, subjectID,
		a.ResourceServerID, a.PDPEffect, a.GateEffect, a.PDPAgrees,
		a.ScopesRequested, a.ScopesGranted, a.PDPReason,
	)
	if err != nil {
		fmt.Printf("[policy audit] insert failed: %v\n", err)
	}
}
