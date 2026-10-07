package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
)

// AgentActionRepository handles agent action request and risk policy database operations
type AgentActionRepository struct {
	db *DBConnection
}

// NewAgentActionRepository creates a new agent action repository
func NewAgentActionRepository(db *DBConnection) *AgentActionRepository {
	return &AgentActionRepository{db: db}
}

// GetDB returns the underlying database connection for direct queries
func (r *AgentActionRepository) GetDB() *DBConnection {
	return r.db
}

// in returns a context whose tenant is workspace ws. Every statement of this
// repository runs through the scoped layer in that workspace (workspace_id =
// $1), inside a row-level security transaction.
func (r *AgentActionRepository) in(ws uuid.UUID) context.Context {
	return WithWorkspace(context.Background(), ws)
}

// ========================================
// Risk Policy Operations
// ========================================

// CreateRiskPolicy creates a new risk policy for a tenant
func (r *AgentActionRepository) CreateRiskPolicy(policy *models.RiskPolicy) error {
	now := time.Now().Unix()
	policy.CreatedAt = now
	policy.UpdatedAt = now

	query := `
		INSERT INTO risk_policies (
			id, workspace_id, name, description,
			action_pattern, resource_pattern, environment_pattern,
			base_score, scope_bulk_threshold, scope_bulk_modifier,
			pii_modifier, financial_modifier, off_hours_modifier, first_time_modifier,
			auto_approve_below, require_approval_above, require_multi_approval_above,
			is_active, priority, created_at, updated_at
		) VALUES ($2, $1, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
	`

	err := insertScoped(r.in(policy.WorkspaceID), r.db.DB, query,
		policy.ID,
		policy.Name,
		policy.Description,
		policy.ActionPattern,
		policy.ResourcePattern,
		policy.EnvironmentPattern,
		policy.BaseScore,
		policy.ScopeBulkThreshold,
		policy.ScopeBulkModifier,
		policy.PIIModifier,
		policy.FinancialModifier,
		policy.OffHoursModifier,
		policy.FirstTimeModifier,
		policy.AutoApproveBelow,
		policy.RequireApprovalAbove,
		policy.RequireMultiApprovalAbove,
		policy.IsActive,
		policy.Priority,
		policy.CreatedAt,
		policy.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create risk policy: %w", err)
	}

	return nil
}

// GetRiskPoliciesByTenant retrieves all active risk policies for a tenant, ordered by priority
func (r *AgentActionRepository) GetRiskPoliciesByTenant(workspaceID uuid.UUID) ([]models.RiskPolicy, error) {
	query := `
		SELECT id, workspace_id, name, description,
		       action_pattern, resource_pattern, environment_pattern,
		       base_score, scope_bulk_threshold, scope_bulk_modifier,
		       pii_modifier, financial_modifier, off_hours_modifier, first_time_modifier,
		       auto_approve_below, require_approval_above, require_multi_approval_above,
		       is_active, priority, created_at, updated_at
		FROM risk_policies
		WHERE workspace_id = $1 AND is_active = TRUE
		ORDER BY priority DESC, created_at ASC
	`

	var policies []models.RiskPolicy
	err := queryScoped(r.in(workspaceID), r.db.DB, query, nil, func(rows *sql.Rows) error {
		var p models.RiskPolicy
		if err := rows.Scan(
			&p.ID, &p.WorkspaceID, &p.Name, &p.Description,
			&p.ActionPattern, &p.ResourcePattern, &p.EnvironmentPattern,
			&p.BaseScore, &p.ScopeBulkThreshold, &p.ScopeBulkModifier,
			&p.PIIModifier, &p.FinancialModifier, &p.OffHoursModifier, &p.FirstTimeModifier,
			&p.AutoApproveBelow, &p.RequireApprovalAbove, &p.RequireMultiApprovalAbove,
			&p.IsActive, &p.Priority, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return fmt.Errorf("failed to scan risk policy: %w", err)
		}
		policies = append(policies, p)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query risk policies: %w", err)
	}

	return policies, nil
}

// GetRiskPolicyByID retrieves a single risk policy
func (r *AgentActionRepository) GetRiskPolicyByID(policyID uuid.UUID, workspaceID uuid.UUID) (*models.RiskPolicy, error) {
	query := `
		SELECT id, workspace_id, name, description,
		       action_pattern, resource_pattern, environment_pattern,
		       base_score, scope_bulk_threshold, scope_bulk_modifier,
		       pii_modifier, financial_modifier, off_hours_modifier, first_time_modifier,
		       auto_approve_below, require_approval_above, require_multi_approval_above,
		       is_active, priority, created_at, updated_at
		FROM risk_policies
		WHERE workspace_id = $1 AND id = $2
	`

	var p models.RiskPolicy
	err := tenancy.QueryRowContext(r.in(workspaceID), r.db.DB, query, []interface{}{policyID},
		&p.ID, &p.WorkspaceID, &p.Name, &p.Description,
		&p.ActionPattern, &p.ResourcePattern, &p.EnvironmentPattern,
		&p.BaseScore, &p.ScopeBulkThreshold, &p.ScopeBulkModifier,
		&p.PIIModifier, &p.FinancialModifier, &p.OffHoursModifier, &p.FirstTimeModifier,
		&p.AutoApproveBelow, &p.RequireApprovalAbove, &p.RequireMultiApprovalAbove,
		&p.IsActive, &p.Priority, &p.CreatedAt, &p.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, tenancy.ErrNotFound) {
			return nil, fmt.Errorf("risk policy not found")
		}
		return nil, fmt.Errorf("failed to get risk policy: %w", err)
	}

	return &p, nil
}

// UpdateRiskPolicy updates an existing risk policy
func (r *AgentActionRepository) UpdateRiskPolicy(policy *models.RiskPolicy) error {
	now := time.Now().Unix()
	policy.UpdatedAt = now

	query := `
		UPDATE risk_policies SET
			name = $2, description = $3,
			action_pattern = $4, resource_pattern = $5, environment_pattern = $6,
			base_score = $7, scope_bulk_threshold = $8, scope_bulk_modifier = $9,
			pii_modifier = $10, financial_modifier = $11, off_hours_modifier = $12, first_time_modifier = $13,
			auto_approve_below = $14, require_approval_above = $15, require_multi_approval_above = $16,
			is_active = $17, priority = $18, updated_at = $19
		WHERE workspace_id = $1 AND id = $20
	`

	result, err := tenancy.ExecContext(r.in(policy.WorkspaceID), r.db.DB, query,
		policy.Name, policy.Description,
		policy.ActionPattern, policy.ResourcePattern, policy.EnvironmentPattern,
		policy.BaseScore, policy.ScopeBulkThreshold, policy.ScopeBulkModifier,
		policy.PIIModifier, policy.FinancialModifier, policy.OffHoursModifier, policy.FirstTimeModifier,
		policy.AutoApproveBelow, policy.RequireApprovalAbove, policy.RequireMultiApprovalAbove,
		policy.IsActive, policy.Priority, policy.UpdatedAt,
		policy.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update risk policy: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("risk policy not found")
	}

	return nil
}

// DeleteRiskPolicy soft-deletes a risk policy
func (r *AgentActionRepository) DeleteRiskPolicy(policyID uuid.UUID, workspaceID uuid.UUID) error {
	now := time.Now().Unix()
	query := `
		UPDATE risk_policies SET is_active = FALSE, updated_at = $2
		WHERE workspace_id = $1 AND id = $3
	`

	result, err := tenancy.ExecContext(r.in(workspaceID), r.db.DB, query, now, policyID)
	if err != nil {
		return fmt.Errorf("failed to delete risk policy: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("risk policy not found")
	}

	return nil
}

// ========================================
// Agent Guard Settings Operations
// ========================================

// GetOrCreateSettings retrieves tenant settings, creating defaults if needed
func (r *AgentActionRepository) GetOrCreateSettings(workspaceID uuid.UUID) (*models.AgentGuardSettings, error) {
	query := `
		SELECT id, workspace_id,
		       auto_approve_below, require_approval_above, require_multi_approval_above,
		       approval_timeout_seconds, polling_interval_seconds,
		       business_hours_start, business_hours_end, business_hours_timezone,
		       default_approver_user_id, require_biometric,
		       created_at, updated_at
		FROM agent_guard_settings
		WHERE workspace_id = $1
	`

	var s models.AgentGuardSettings
	err := tenancy.QueryRowContext(r.in(workspaceID), r.db.DB, query, nil,
		&s.ID, &s.WorkspaceID,
		&s.AutoApproveBelow, &s.RequireApprovalAbove, &s.RequireMultiApprovalAbove,
		&s.ApprovalTimeoutSeconds, &s.PollingIntervalSeconds,
		&s.BusinessHoursStart, &s.BusinessHoursEnd, &s.BusinessHoursTimezone,
		&s.DefaultApproverUserID, &s.RequireBiometric,
		&s.CreatedAt, &s.UpdatedAt,
	)

	if err == nil {
		return &s, nil
	}

	if !errors.Is(err, tenancy.ErrNotFound) {
		return nil, fmt.Errorf("failed to get agent guard settings: %w", err)
	}

	// Create defaults
	now := time.Now().Unix()
	s = models.AgentGuardSettings{
		ID:                        uuid.New(),
		WorkspaceID:               workspaceID,
		AutoApproveBelow:          30,
		RequireApprovalAbove:      31,
		RequireMultiApprovalAbove: 81,
		ApprovalTimeoutSeconds:    300,
		PollingIntervalSeconds:    5,
		BusinessHoursStart:        9,
		BusinessHoursEnd:          17,
		BusinessHoursTimezone:     "UTC",
		RequireBiometric:          true,
		CreatedAt:                 now,
		UpdatedAt:                 now,
	}

	insertQuery := `
		INSERT INTO agent_guard_settings (
			id, workspace_id,
			auto_approve_below, require_approval_above, require_multi_approval_above,
			approval_timeout_seconds, polling_interval_seconds,
			business_hours_start, business_hours_end, business_hours_timezone,
			default_approver_user_id, require_biometric,
			created_at, updated_at
		) VALUES ($2, $1, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (workspace_id) DO NOTHING
	`

	err = insertScoped(r.in(workspaceID), r.db.DB, insertQuery,
		s.ID,
		s.AutoApproveBelow, s.RequireApprovalAbove, s.RequireMultiApprovalAbove,
		s.ApprovalTimeoutSeconds, s.PollingIntervalSeconds,
		s.BusinessHoursStart, s.BusinessHoursEnd, s.BusinessHoursTimezone,
		s.DefaultApproverUserID, s.RequireBiometric,
		s.CreatedAt, s.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create default agent guard settings: %w", err)
	}

	return &s, nil
}

// UpdateSettings updates tenant agent guard settings
func (r *AgentActionRepository) UpdateSettings(settings *models.AgentGuardSettings) error {
	now := time.Now().Unix()
	settings.UpdatedAt = now

	query := `
		UPDATE agent_guard_settings SET
			auto_approve_below = $2, require_approval_above = $3, require_multi_approval_above = $4,
			approval_timeout_seconds = $5, polling_interval_seconds = $6,
			business_hours_start = $7, business_hours_end = $8, business_hours_timezone = $9,
			default_approver_user_id = $10, require_biometric = $11,
			updated_at = $12
		WHERE workspace_id = $1
	`

	_, err := tenancy.ExecContext(r.in(settings.WorkspaceID), r.db.DB, query,
		settings.AutoApproveBelow, settings.RequireApprovalAbove, settings.RequireMultiApprovalAbove,
		settings.ApprovalTimeoutSeconds, settings.PollingIntervalSeconds,
		settings.BusinessHoursStart, settings.BusinessHoursEnd, settings.BusinessHoursTimezone,
		settings.DefaultApproverUserID, settings.RequireBiometric,
		settings.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update agent guard settings: %w", err)
	}

	return nil
}

// ========================================
// Agent Action Request Operations
// ========================================

// CreateActionRequest creates a new agent action request
func (r *AgentActionRepository) CreateActionRequest(req *models.AgentActionRequest) error {
	now := time.Now().Unix()
	req.CreatedAt = now

	riskFactorsJSON, err := json.Marshal(req.RiskFactors)
	if err != nil {
		return fmt.Errorf("failed to marshal risk factors: %w", err)
	}

	metadataJSON, err := json.Marshal(req.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO agent_action_requests (
			id, action_req_id, workspace_id, user_id, user_email,
			agent_id, agent_name, agent_framework, session_id,
			action, resource, detail, metadata,
			risk_score, risk_level, risk_factors, matched_policy_id,
			status, approval_type, required_approvals, received_approvals,
			ciba_auth_req_id, device_token_id,
			expires_at, created_at
		) VALUES ($2, $3, $1, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25)
	`

	err = insertScoped(r.in(req.WorkspaceID), r.db.DB, query,
		req.ID, req.ActionReqID, req.UserID, req.UserEmail,
		req.AgentID, req.AgentName, req.AgentFramework, req.SessionID,
		req.Action, req.Resource, req.Detail, metadataJSON,
		req.RiskScore, req.RiskLevel, riskFactorsJSON, req.MatchedPolicyID,
		req.Status, req.ApprovalType, req.RequiredApprovals, req.ReceivedApprovals,
		req.CIBAAuthReqID, req.DeviceTokenID,
		req.ExpiresAt, req.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create agent action request: %w", err)
	}

	return nil
}

// GetActionRequestByID retrieves an agent action request of workspace ws by
// action_req_id; another workspace's request is not found.
func (r *AgentActionRepository) GetActionRequestByID(ws uuid.UUID, actionReqID string) (*models.AgentActionRequest, error) {
	query := `
		SELECT id, action_req_id, workspace_id, user_id, user_email,
		       agent_id, agent_name, agent_framework, session_id,
		       action, resource, detail, metadata,
		       risk_score, risk_level, risk_factors, matched_policy_id,
		       status, approval_type, required_approvals, received_approvals,
		       ciba_auth_req_id, device_token_id,
		       expires_at, created_at, decided_at, last_polled_at
		FROM agent_action_requests
		WHERE workspace_id = $1 AND action_req_id = $2
	`

	var req models.AgentActionRequest
	var metadataJSON, riskFactorsJSON []byte

	err := tenancy.QueryRowContext(r.in(ws), r.db.DB, query, []interface{}{actionReqID},
		&req.ID, &req.ActionReqID, &req.WorkspaceID, &req.UserID, &req.UserEmail,
		&req.AgentID, &req.AgentName, &req.AgentFramework, &req.SessionID,
		&req.Action, &req.Resource, &req.Detail, &metadataJSON,
		&req.RiskScore, &req.RiskLevel, &riskFactorsJSON, &req.MatchedPolicyID,
		&req.Status, &req.ApprovalType, &req.RequiredApprovals, &req.ReceivedApprovals,
		&req.CIBAAuthReqID, &req.DeviceTokenID,
		&req.ExpiresAt, &req.CreatedAt, &req.DecidedAt, &req.LastPolledAt,
	)

	if err != nil {
		if errors.Is(err, tenancy.ErrNotFound) {
			return nil, fmt.Errorf("agent action request not found")
		}
		return nil, fmt.Errorf("failed to get agent action request: %w", err)
	}

	// Unmarshal JSONB fields
	if metadataJSON != nil {
		json.Unmarshal(metadataJSON, &req.Metadata)
	}
	if riskFactorsJSON != nil {
		json.Unmarshal(riskFactorsJSON, &req.RiskFactors)
	}

	return &req, nil
}

// GetPendingActionsByUser returns all non-expired pending action requests for a specific user in a tenant.
// Filters by both workspace_id and user_id so only the affected user sees their notifications.
func (r *AgentActionRepository) GetPendingActionsByUser(workspaceID uuid.UUID, userID uuid.UUID) ([]models.AgentActionRequest, error) {
	now := time.Now().Unix()
	query := `
		SELECT id, action_req_id, workspace_id, user_id, user_email,
		       agent_id, agent_name, agent_framework, session_id,
		       action, resource, detail, metadata,
		       risk_score, risk_level, risk_factors, matched_policy_id,
		       status, approval_type, required_approvals, received_approvals,
		       ciba_auth_req_id, device_token_id,
		       expires_at, created_at, decided_at, last_polled_at
		FROM agent_action_requests
		WHERE workspace_id = $1 AND user_id = $2 AND status = 'pending' AND expires_at > $3
		ORDER BY created_at DESC
	`

	var results []models.AgentActionRequest
	err := queryScoped(r.in(workspaceID), r.db.DB, query, []interface{}{userID, now}, func(rows *sql.Rows) error {
		var req models.AgentActionRequest
		var metadataJSON, riskFactorsJSON []byte
		var matchedPolicyID, deviceTokenID sql.NullString
		var decidedAt, lastPolledAt sql.NullInt64

		err := rows.Scan(
			&req.ID, &req.ActionReqID, &req.WorkspaceID, &req.UserID, &req.UserEmail,
			&req.AgentID, &req.AgentName, &req.AgentFramework, &req.SessionID,
			&req.Action, &req.Resource, &req.Detail, &metadataJSON,
			&req.RiskScore, &req.RiskLevel, &riskFactorsJSON, &matchedPolicyID,
			&req.Status, &req.ApprovalType, &req.RequiredApprovals, &req.ReceivedApprovals,
			&req.CIBAAuthReqID, &deviceTokenID,
			&req.ExpiresAt, &req.CreatedAt, &decidedAt, &lastPolledAt,
		)
		if err != nil {
			return fmt.Errorf("failed to scan pending action: %w", err)
		}

		if matchedPolicyID.Valid {
			id := uuid.MustParse(matchedPolicyID.String)
			req.MatchedPolicyID = &id
		}
		if deviceTokenID.Valid {
			id := uuid.MustParse(deviceTokenID.String)
			req.DeviceTokenID = &id
		}
		if decidedAt.Valid {
			req.DecidedAt = &decidedAt.Int64
		}
		if lastPolledAt.Valid {
			req.LastPolledAt = &lastPolledAt.Int64
		}
		if metadataJSON != nil {
			json.Unmarshal(metadataJSON, &req.Metadata)
		}
		if riskFactorsJSON != nil {
			json.Unmarshal(riskFactorsJSON, &req.RiskFactors)
		}

		results = append(results, req)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query pending actions: %w", err)
	}

	return results, nil
}

// UpdateActionRequestStatus updates the status of an action request of workspace ws
func (r *AgentActionRepository) UpdateActionRequestStatus(ws uuid.UUID, actionReqID string, status string) error {
	now := time.Now().Unix()
	query := `
		UPDATE agent_action_requests
		SET status = $2, decided_at = $3
		WHERE workspace_id = $1 AND action_req_id = $4
	`

	_, err := tenancy.ExecContext(r.in(ws), r.db.DB, query, status, now, actionReqID)
	if err != nil {
		return fmt.Errorf("failed to update action request status: %w", err)
	}

	return nil
}


// UpdateLastPolled updates the last_polled_at timestamp of a request of workspace ws
func (r *AgentActionRepository) UpdateLastPolled(ws uuid.UUID, actionReqID string) error {
	now := time.Now().Unix()
	_, err := tenancy.ExecContext(r.in(ws), r.db.DB,
		`UPDATE agent_action_requests SET last_polled_at = $2 WHERE workspace_id = $1 AND action_req_id = $3`,
		now, actionReqID)
	return err
}

// ExpireOldActionRequests marks expired pending requests
func (r *AgentActionRepository) ExpireOldActionRequests() (int64, error) {
	now := time.Now().Unix()
	// TENANT-EXEMPT: platform sweeper; expires pending requests of every workspace by time alone
	query := `
		UPDATE agent_action_requests
		SET status = 'expired', decided_at = $1
		WHERE expires_at < $1 AND status = 'pending'
	`

	result, err := r.db.Exec(query, now)
	if err != nil {
		return 0, fmt.Errorf("failed to expire old action requests: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	return rowsAffected, nil
}

// HasPriorAction checks if an agent has previously executed this action+resource combo
func (r *AgentActionRepository) HasPriorAction(agentID string, action string, resource string, workspaceID uuid.UUID) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM agent_action_audit_log
			WHERE workspace_id = $1 AND agent_id = $2 AND action = $3 AND resource = $4
			AND final_status IN ('approved', 'auto_approved')
		)
	`

	var exists bool
	err := tenancy.QueryRowContext(r.in(workspaceID), r.db.DB, query, []interface{}{agentID, action, resource}, &exists)
	if err != nil {
		return false, fmt.Errorf("failed to check prior action: %w", err)
	}

	return exists, nil
}

// ========================================
// Agent Action Decision Operations
// ========================================

// CreateDecision records a human's approval/denial on a request of workspace ws.
// Returns (true, nil) if the row was inserted, (false, nil) if the approver already voted
// (the unique constraint on (action_request_id, approver_user_id) enforces one vote per user)
// or the request is not one of the workspace's.
func (r *AgentActionRepository) CreateDecision(ws uuid.UUID, decision *models.AgentActionDecision) (bool, error) {
	now := time.Now().Unix()
	decision.CreatedAt = now

	// agent_action_decisions has no workspace_id: the decision is written only
	// for a request of the workspace.
	query := `
		INSERT INTO agent_action_decisions (
			id, action_request_id, approver_user_id, approver_email,
			decision, reason, biometric_verified, created_at
		)
		SELECT $2, ar.id, $4, $5, $6, $7, $8, $9
		  FROM agent_action_requests ar
		 WHERE ar.workspace_id = $1 AND ar.id = $3
		ON CONFLICT (action_request_id, approver_user_id) DO NOTHING
	`

	result, err := tenancy.ExecContext(r.in(ws), r.db.DB, query,
		decision.ID, decision.ActionRequestID, decision.ApproverUserID, decision.ApproverEmail,
		decision.Decision, decision.Reason, decision.BiometricVerified, decision.CreatedAt,
	)

	if err != nil {
		return false, fmt.Errorf("failed to create decision: %w", err)
	}

	rows, _ := result.RowsAffected()
	return rows > 0, nil
}

// CountDistinctApprovers returns (distinctApproveVotes, requiredApprovals) for the request.
// It counts only decisions with decision='approved' to prevent a single deny vote from
// blocking the threshold count.
func (r *AgentActionRepository) CountDistinctApprovers(ws uuid.UUID, actionReqID string) (int, int, error) {
	query := `
		SELECT
			COUNT(DISTINCT d.approver_user_id),
			r.required_approvals
		FROM agent_action_requests r
		LEFT JOIN agent_action_decisions d
			ON d.action_request_id = r.id AND d.decision = 'approved'
		WHERE r.workspace_id = $1 AND r.action_req_id = $2
		GROUP BY r.required_approvals
	`

	var received, required int
	err := tenancy.QueryRowContext(r.in(ws), r.db.DB, query, []interface{}{actionReqID}, &received, &required)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to count approvers: %w", err)
	}

	return received, required, nil
}

// ========================================
// Audit Log Operations
// ========================================

// CreateAuditEntry writes an immutable audit log entry
func (r *AgentActionRepository) CreateAuditEntry(entry *models.AgentActionAuditLog) error {
	now := time.Now().Unix()
	entry.CreatedAt = now

	metadataJSON, err := json.Marshal(entry.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal audit metadata: %w", err)
	}

	decidedByJSON, err := json.Marshal(entry.DecidedBy)
	if err != nil {
		return fmt.Errorf("failed to marshal decided_by: %w", err)
	}

	query := `
		INSERT INTO agent_action_audit_log (
			id, workspace_id, action_request_id,
			agent_id, agent_name, user_id, user_email,
			action, resource, detail, metadata,
			risk_score, risk_level, final_status, decided_by,
			requested_at, decided_at, execution_duration_ms, created_at
		) VALUES ($2, $1, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
	`

	err = insertScoped(r.in(entry.WorkspaceID), r.db.DB, query,
		entry.ID, entry.ActionRequestID,
		entry.AgentID, entry.AgentName, entry.UserID, entry.UserEmail,
		entry.Action, entry.Resource, entry.Detail, metadataJSON,
		entry.RiskScore, entry.RiskLevel, entry.FinalStatus, decidedByJSON,
		entry.RequestedAt, entry.DecidedAt, entry.ExecutionDurationMs, entry.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create audit entry: %w", err)
	}

	return nil
}

// GetAuditLog retrieves paginated audit entries for a tenant
func (r *AgentActionRepository) GetAuditLog(workspaceID uuid.UUID, page, perPage int) ([]models.AgentActionAuditLog, int, error) {
	// Count total
	ctx := r.in(workspaceID)
	var total int
	err := tenancy.QueryRowContext(ctx, r.db.DB, `SELECT COUNT(*) FROM agent_action_audit_log WHERE workspace_id = $1`, nil, &total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count audit entries: %w", err)
	}

	offset := (page - 1) * perPage
	query := `
		SELECT id, workspace_id, action_request_id,
		       agent_id, agent_name, user_id, user_email,
		       action, resource, detail, metadata,
		       risk_score, risk_level, final_status, decided_by,
		       requested_at, decided_at, execution_duration_ms, created_at
		FROM agent_action_audit_log
		WHERE workspace_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	var entries []models.AgentActionAuditLog
	err = queryScoped(ctx, r.db.DB, query, []interface{}{perPage, offset}, func(rows *sql.Rows) error {
		var e models.AgentActionAuditLog
		var metadataJSON, decidedByJSON []byte

		err := rows.Scan(
			&e.ID, &e.WorkspaceID, &e.ActionRequestID,
			&e.AgentID, &e.AgentName, &e.UserID, &e.UserEmail,
			&e.Action, &e.Resource, &e.Detail, &metadataJSON,
			&e.RiskScore, &e.RiskLevel, &e.FinalStatus, &decidedByJSON,
			&e.RequestedAt, &e.DecidedAt, &e.ExecutionDurationMs, &e.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to scan audit entry: %w", err)
		}

		if metadataJSON != nil {
			json.Unmarshal(metadataJSON, &e.Metadata)
		}
		if decidedByJSON != nil {
			json.Unmarshal(decidedByJSON, &e.DecidedBy)
		}

		entries = append(entries, e)
		return nil
	})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query audit log: %w", err)
	}

	return entries, total, nil
}
