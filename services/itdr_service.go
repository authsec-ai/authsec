package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ITDRService implements the ITDR detection rules, findings, response plans,
// escalation leases, and alert deliveries API (TRD 2, Section 19-20, WP-A8).
//
// Patterns follow RuntimePolicyService: raw SQL queries, StatusError returns,
// workspace-scoped composite keys, isLockTimeout retries.
type ITDRService struct {
	db    *gorm.DB
	clock Clock
}

// NewITDRService builds the service.
func NewITDRService(db *gorm.DB) *ITDRService {
	return &ITDRService{db: db}
}

// ── Detection rules ────────────────────────────────────────────────────

// ListDetectionRules returns all rules in a workspace.
func (s *ITDRService) ListDetectionRules(ctx context.Context, wsID uuid.UUID) (int, []byte, error) {
	var rows []map[string]any
	err := s.db.WithContext(ctx).Raw(`
		SELECT id, workspace_id, rule_key, name, description, severity,
		       confidence, enabled, config, version, created_at, updated_at
		  FROM itdr_detection_rules
		 WHERE workspace_id = ?
		 ORDER BY created_at`, wsID).Scan(&rows).Error
	if err != nil {
		return 0, nil, err
	}
	if rows == nil {
		rows = []map[string]any{}
	}
	body, _ := json.Marshal(map[string]any{"rules": rows})
	return http.StatusOK, body, nil
}

// GetDetectionRule returns a single detection rule.
func (s *ITDRService) GetDetectionRule(ctx context.Context, wsID, ruleID uuid.UUID) (int, []byte, error) {
	var row map[string]any
	err := s.db.WithContext(ctx).Raw(`
		SELECT id, workspace_id, rule_key, name, description, severity,
		       confidence, enabled, config, version, created_at, updated_at
		  FROM itdr_detection_rules
		 WHERE workspace_id = ? AND id = ?`, wsID, ruleID).Scan(&row).Error
	if err != nil {
		return 0, nil, err
	}
	if row == nil {
		return 0, nil, &StatusError{Status: http.StatusNotFound, Code: "not_found", Message: "Detection rule not found."}
	}
	body, _ := json.Marshal(row)
	return http.StatusOK, body, nil
}

// CreateDetectionRuleInput is the body for creating a detection rule.
type CreateDetectionRuleInput struct {
	RuleKey     string          `json:"rule_key"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Severity    string          `json:"severity"`
	Confidence  string          `json:"confidence"`
	Enabled     *bool           `json:"enabled"`
	Config      json.RawMessage `json:"config"`
}

// CreateDetectionRule creates a new detection rule in the workspace.
func (s *ITDRService) CreateDetectionRule(ctx context.Context, actor Actor, body []byte) (int, []byte, error) {
	var input CreateDetectionRuleInput
	if err := json.Unmarshal(body, &input); err != nil {
		return 0, nil, &StatusError{Status: http.StatusBadRequest, Code: "invalid_body", Message: "Invalid request body."}
	}
	if input.RuleKey == "" || input.Name == "" || input.Severity == "" || input.Confidence == "" {
		return 0, nil, &StatusError{Status: http.StatusBadRequest, Code: "missing_fields", Message: "rule_key, name, severity, and confidence are required."}
	}

	id := uuid.New()
	now := s.clock.Now()
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	cfg := json.RawMessage("{}")
	if input.Config != nil {
		cfg = input.Config
	}

	err := s.db.WithContext(ctx).Exec(`
		INSERT INTO itdr_detection_rules
		       (id, workspace_id, rule_key, name, description, severity,
		        confidence, enabled, config, version, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
		id, actor.WorkspaceID, input.RuleKey, input.Name, input.Description,
		input.Severity, input.Confidence, enabled, string(cfg), now, now).Error
	if err != nil {
		if isLockTimeout(err) {
			return 0, nil, &StatusError{Status: http.StatusConflict, Code: "conflict", Message: "Duplicate rule_key."}
		}
		return 0, nil, err
	}

	return s.GetDetectionRule(ctx, actor.WorkspaceID, id)
}

// UpdateDetectionRule updates a detection rule.
func (s *ITDRService) UpdateDetectionRule(ctx context.Context, actor Actor, ruleID uuid.UUID, body []byte) (int, []byte, error) {
	var input CreateDetectionRuleInput
	if err := json.Unmarshal(body, &input); err != nil {
		return 0, nil, &StatusError{Status: http.StatusBadRequest, Code: "invalid_body", Message: "Invalid request body."}
	}
	now := s.clock.Now()

	result := s.db.WithContext(ctx).Exec(`
		UPDATE itdr_detection_rules
		   SET name = COALESCE(NULLIF(?, ''), name),
		       description = COALESCE(?, description),
		       severity = COALESCE(NULLIF(?, ''), severity),
		       confidence = COALESCE(NULLIF(?, ''), confidence),
		       enabled = COALESCE(?, enabled),
		       config = COALESCE(NULLIF(?, '{}')::jsonb, config),
		       version = version + 1,
		       updated_at = ?
		 WHERE workspace_id = ? AND id = ?`,
		input.Name, input.Description, input.Severity, input.Confidence,
		input.Enabled, string(input.Config), now, actor.WorkspaceID, ruleID)
	if result.Error != nil {
		return 0, nil, result.Error
	}
	if result.RowsAffected == 0 {
		return 0, nil, &StatusError{Status: http.StatusNotFound, Code: "not_found", Message: "Detection rule not found."}
	}

	return s.GetDetectionRule(ctx, actor.WorkspaceID, ruleID)
}

// ── Findings ───────────────────────────────────────────────────────────

// ListFindings returns findings in a workspace, optionally filtered by status.
func (s *ITDRService) ListFindings(ctx context.Context, wsID uuid.UUID, status string) (int, []byte, error) {
	query := `
		SELECT f.id, f.workspace_id, f.rule_id, f.rule_version, f.severity,
		       f.confidence, f.status, f.outcome, f.workload_id,
		       f.runtime_instance_id, f.resource_id, f.graph_revision,
		       f.first_seen, f.last_seen, f.event_count,
		       f.finding_window_seconds, f.recommended_response,
		       f.created_at, f.updated_at,
		       r.rule_key, r.name AS rule_name
		  FROM itdr_findings f
		  JOIN itdr_detection_rules r ON r.workspace_id = f.workspace_id AND r.id = f.rule_id
		 WHERE f.workspace_id = ?`
	args := []any{wsID}
	if status != "" {
		query += ` AND f.status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY f.last_seen DESC`

	var rows []map[string]any
	if err := s.db.WithContext(ctx).Raw(query, args...).Scan(&rows).Error; err != nil {
		return 0, nil, err
	}
	if rows == nil {
		rows = []map[string]any{}
	}
	body, _ := json.Marshal(map[string]any{"findings": rows})
	return http.StatusOK, body, nil
}

// GetFinding returns a single finding with its identities and policy revisions.
func (s *ITDRService) GetFinding(ctx context.Context, wsID, findingID uuid.UUID) (int, []byte, error) {
	var row map[string]any
	err := s.db.WithContext(ctx).Raw(`
		SELECT f.*, r.rule_key, r.name AS rule_name
		  FROM itdr_findings f
		  JOIN itdr_detection_rules r ON r.workspace_id = f.workspace_id AND r.id = f.rule_id
		 WHERE f.workspace_id = ? AND f.id = ?`, wsID, findingID).Scan(&row).Error
	if err != nil {
		return 0, nil, err
	}
	if row == nil {
		return 0, nil, &StatusError{Status: http.StatusNotFound, Code: "not_found", Message: "Finding not found."}
	}

	// Attach identities.
	var identities []map[string]any
	s.db.WithContext(ctx).Raw(`
		SELECT identity_account_id FROM itdr_finding_identities
		 WHERE workspace_id = ? AND finding_id = ?`, wsID, findingID).Scan(&identities)
	if identities == nil {
		identities = []map[string]any{}
	}
	row["identities"] = identities

	// Attach policy revisions.
	var policyRevs []map[string]any
	s.db.WithContext(ctx).Raw(`
		SELECT policy_revision_id FROM itdr_finding_policy_revisions
		 WHERE workspace_id = ? AND finding_id = ?`, wsID, findingID).Scan(&policyRevs)
	if policyRevs == nil {
		policyRevs = []map[string]any{}
	}
	row["policy_revisions"] = policyRevs

	body, _ := json.Marshal(row)
	return http.StatusOK, body, nil
}

// CreateFindingInput is the body for creating or updating a finding.
type CreateFindingInput struct {
	RuleID              uuid.UUID   `json:"rule_id"`
	Severity            string      `json:"severity"`
	Confidence          string      `json:"confidence"`
	Outcome             string      `json:"outcome"`
	WorkloadID          *uuid.UUID  `json:"workload_id"`
	RuntimeInstanceID   *uuid.UUID  `json:"runtime_instance_id"`
	ResourceID          *uuid.UUID  `json:"resource_id"`
	GraphRevision       int64       `json:"graph_revision"`
	ObservationIDs      []uuid.UUID `json:"observation_ids"`
	RecommendedResponse string      `json:"recommended_response"`
	IdentityAccountIDs  []uuid.UUID `json:"identity_account_ids"`
	PolicyRevisionIDs   []uuid.UUID `json:"policy_revision_ids"`
}

// CreateFinding creates a new finding.
func (s *ITDRService) CreateFinding(ctx context.Context, actor Actor, body []byte) (int, []byte, error) {
	var input CreateFindingInput
	if err := json.Unmarshal(body, &input); err != nil {
		return 0, nil, &StatusError{Status: http.StatusBadRequest, Code: "invalid_body", Message: "Invalid request body."}
	}
	if input.RuleID == uuid.Nil || input.Severity == "" || input.Confidence == "" {
		return 0, nil, &StatusError{Status: http.StatusBadRequest, Code: "missing_fields", Message: "rule_id, severity, and confidence are required."}
	}

	id := uuid.New()
	now := s.clock.Now()
	outcome := input.Outcome
	if outcome == "" {
		outcome = "unknown"
	}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec(`
			INSERT INTO itdr_findings
			       (id, workspace_id, rule_id, severity, confidence, outcome,
			        workload_id, runtime_instance_id, resource_id,
			        graph_revision, recommended_response,
			        first_seen, last_seen, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, actor.WorkspaceID, input.RuleID, input.Severity, input.Confidence,
			outcome, input.WorkloadID, input.RuntimeInstanceID, input.ResourceID,
			input.GraphRevision, input.RecommendedResponse,
			now, now, now, now).Error; err != nil {
			return err
		}

		for _, identityID := range input.IdentityAccountIDs {
			if err := tx.Exec(`
				INSERT INTO itdr_finding_identities (finding_id, workspace_id, identity_account_id)
				VALUES (?, ?, ?)`, id, actor.WorkspaceID, identityID).Error; err != nil {
				return err
			}
		}

		for _, policyRevID := range input.PolicyRevisionIDs {
			if err := tx.Exec(`
				INSERT INTO itdr_finding_policy_revisions (finding_id, workspace_id, policy_revision_id)
				VALUES (?, ?, ?)`, id, actor.WorkspaceID, policyRevID).Error; err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return 0, nil, err
	}

	return s.GetFinding(ctx, actor.WorkspaceID, id)
}

// UpdateFindingStatus transitions a finding's status.
func (s *ITDRService) UpdateFindingStatus(ctx context.Context, actor Actor, findingID uuid.UUID, body []byte) (int, []byte, error) {
	var input struct {
		Status  string `json:"status"`
		Outcome string `json:"outcome"`
	}
	if err := json.Unmarshal(body, &input); err != nil {
		return 0, nil, &StatusError{Status: http.StatusBadRequest, Code: "invalid_body", Message: "Invalid request body."}
	}

	now := s.clock.Now()
	setClauses := "status = ?, updated_at = ?"
	args := []any{input.Status, now}
	if input.Outcome != "" {
		setClauses += ", outcome = ?"
		args = append(args, input.Outcome)
	}
	args = append(args, actor.WorkspaceID, findingID)

	result := s.db.WithContext(ctx).Exec(
		fmt.Sprintf("UPDATE itdr_findings SET %s WHERE workspace_id = ? AND id = ?", setClauses),
		args...)
	if result.Error != nil {
		return 0, nil, result.Error
	}
	if result.RowsAffected == 0 {
		return 0, nil, &StatusError{Status: http.StatusNotFound, Code: "not_found", Message: "Finding not found."}
	}

	return s.GetFinding(ctx, actor.WorkspaceID, findingID)
}

// ── Response plans ─────────────────────────────────────────────────────

// ListResponsePlans returns response plans for a finding.
func (s *ITDRService) ListResponsePlans(ctx context.Context, wsID, findingID uuid.UUID) (int, []byte, error) {
	var rows []map[string]any
	err := s.db.WithContext(ctx).Raw(`
		SELECT * FROM itdr_response_plans
		 WHERE workspace_id = ? AND finding_id = ?
		 ORDER BY created_at`, wsID, findingID).Scan(&rows).Error
	if err != nil {
		return 0, nil, err
	}
	if rows == nil {
		rows = []map[string]any{}
	}
	body, _ := json.Marshal(map[string]any{"response_plans": rows})
	return http.StatusOK, body, nil
}

// CreateResponsePlanInput is the body for creating a response plan.
type CreateResponsePlanInput struct {
	FindingID        uuid.UUID       `json:"finding_id"`
	Targets          json.RawMessage `json:"targets"`
	Actions          json.RawMessage `json:"actions"`
	SharedUseImpact  string          `json:"shared_use_impact"`
	Expiry           *time.Time      `json:"expiry"`
	RollbackBehavior string          `json:"rollback_behavior"`
	Reason           string          `json:"reason"`
}

// CreateResponsePlan creates a response plan for a finding.
func (s *ITDRService) CreateResponsePlan(ctx context.Context, actor Actor, body []byte) (int, []byte, error) {
	var input CreateResponsePlanInput
	if err := json.Unmarshal(body, &input); err != nil {
		return 0, nil, &StatusError{Status: http.StatusBadRequest, Code: "invalid_body", Message: "Invalid request body."}
	}
	if input.FindingID == uuid.Nil {
		return 0, nil, &StatusError{Status: http.StatusBadRequest, Code: "missing_fields", Message: "finding_id is required."}
	}

	id := uuid.New()
	now := s.clock.Now()
	targets := json.RawMessage("[]")
	if input.Targets != nil {
		targets = input.Targets
	}
	actions := json.RawMessage("[]")
	if input.Actions != nil {
		actions = input.Actions
	}

	err := s.db.WithContext(ctx).Exec(`
		INSERT INTO itdr_response_plans
		       (id, workspace_id, finding_id, status, targets, actions,
		        shared_use_impact, expiry, rollback_behavior,
		        actor_id, reason, created_at, updated_at)
		VALUES (?, ?, ?, 'requested', ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, actor.WorkspaceID, input.FindingID,
		string(targets), string(actions),
		input.SharedUseImpact, input.Expiry, input.RollbackBehavior,
		actor.UserID, input.Reason, now, now).Error
	if err != nil {
		return 0, nil, err
	}

	var row map[string]any
	s.db.WithContext(ctx).Raw(`SELECT * FROM itdr_response_plans WHERE workspace_id = ? AND id = ?`,
		actor.WorkspaceID, id).Scan(&row)
	b, _ := json.Marshal(row)
	return http.StatusCreated, b, nil
}

// ApproveResponsePlan approves a response plan.
func (s *ITDRService) ApproveResponsePlan(ctx context.Context, actor Actor, planID uuid.UUID) (int, []byte, error) {
	now := s.clock.Now()
	result := s.db.WithContext(ctx).Exec(`
		UPDATE itdr_response_plans
		   SET status = 'approved', approved_by = ?, approved_at = ?, updated_at = ?
		 WHERE workspace_id = ? AND id = ? AND status = 'requested'`,
		actor.UserID, now, now, actor.WorkspaceID, planID)
	if result.Error != nil {
		return 0, nil, result.Error
	}
	if result.RowsAffected == 0 {
		return 0, nil, &StatusError{Status: http.StatusConflict, Code: "invalid_state", Message: "Plan is not in requested state."}
	}

	var row map[string]any
	s.db.WithContext(ctx).Raw(`SELECT * FROM itdr_response_plans WHERE workspace_id = ? AND id = ?`,
		actor.WorkspaceID, planID).Scan(&row)
	b, _ := json.Marshal(row)
	return http.StatusOK, b, nil
}

// TransitionResponsePlan transitions a response plan status.
func (s *ITDRService) TransitionResponsePlan(ctx context.Context, actor Actor, planID uuid.UUID, body []byte) (int, []byte, error) {
	var input struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &input); err != nil {
		return 0, nil, &StatusError{Status: http.StatusBadRequest, Code: "invalid_body", Message: "Invalid request body."}
	}

	now := s.clock.Now()
	result := s.db.WithContext(ctx).Exec(`
		UPDATE itdr_response_plans SET status = ?, updated_at = ?
		 WHERE workspace_id = ? AND id = ?`,
		input.Status, now, actor.WorkspaceID, planID)
	if result.Error != nil {
		return 0, nil, result.Error
	}
	if result.RowsAffected == 0 {
		return 0, nil, &StatusError{Status: http.StatusNotFound, Code: "not_found", Message: "Response plan not found."}
	}

	var row map[string]any
	s.db.WithContext(ctx).Raw(`SELECT * FROM itdr_response_plans WHERE workspace_id = ? AND id = ?`,
		actor.WorkspaceID, planID).Scan(&row)
	b, _ := json.Marshal(row)
	return http.StatusOK, b, nil
}

// ── Escalation leases ──────────────────────────────────────────────────

// ListEscalationLeases returns active leases for a workspace.
func (s *ITDRService) ListEscalationLeases(ctx context.Context, wsID uuid.UUID, status string) (int, []byte, error) {
	query := `SELECT * FROM itdr_escalation_leases WHERE workspace_id = ?`
	args := []any{wsID}
	if status != "" {
		query += ` AND status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY created_at DESC`

	var rows []map[string]any
	if err := s.db.WithContext(ctx).Raw(query, args...).Scan(&rows).Error; err != nil {
		return 0, nil, err
	}
	if rows == nil {
		rows = []map[string]any{}
	}
	body, _ := json.Marshal(map[string]any{"leases": rows})
	return http.StatusOK, body, nil
}

// CreateEscalationLeaseInput is the body for creating a lease.
type CreateEscalationLeaseInput struct {
	ClientIdentityID uuid.UUID  `json:"client_identity_id"`
	WorkloadID       *uuid.UUID `json:"workload_id"`
	ResourceID       *uuid.UUID `json:"resource_id"`
	Action           string     `json:"action"`
	PolicyRevisionID *uuid.UUID `json:"policy_revision_id"`
	Audience         string     `json:"audience"`
	ExpiryMinutes    int        `json:"expiry_minutes"`
	MaxUses          int        `json:"max_uses"`
}

// CreateEscalationLease creates a new escalation lease.
func (s *ITDRService) CreateEscalationLease(ctx context.Context, actor Actor, body []byte) (int, []byte, error) {
	var input CreateEscalationLeaseInput
	if err := json.Unmarshal(body, &input); err != nil {
		return 0, nil, &StatusError{Status: http.StatusBadRequest, Code: "invalid_body", Message: "Invalid request body."}
	}
	if input.ClientIdentityID == uuid.Nil || input.Action == "" {
		return 0, nil, &StatusError{Status: http.StatusBadRequest, Code: "missing_fields", Message: "client_identity_id and action are required."}
	}

	id := uuid.New()
	now := s.clock.Now()
	expiryMinutes := input.ExpiryMinutes
	if expiryMinutes <= 0 {
		expiryMinutes = 15 // default 15 minutes per TRD
	}
	expiry := now.Add(time.Duration(expiryMinutes) * time.Minute)
	maxUses := input.MaxUses
	if maxUses <= 0 {
		maxUses = 1 // default one-shot per TRD
	}
	nonce := uuid.New().String()

	err := s.db.WithContext(ctx).Exec(`
		INSERT INTO itdr_escalation_leases
		       (id, workspace_id, workload_id, client_identity_id, resource_id,
		        action, policy_revision_id, approver_id, audience,
		        expiry, nonce, max_uses, uses_remaining, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)`,
		id, actor.WorkspaceID, input.WorkloadID, input.ClientIdentityID,
		input.ResourceID, input.Action, input.PolicyRevisionID,
		actor.UserID, input.Audience, expiry, nonce,
		maxUses, maxUses, now).Error
	if err != nil {
		return 0, nil, err
	}

	var row map[string]any
	s.db.WithContext(ctx).Raw(`SELECT * FROM itdr_escalation_leases WHERE workspace_id = ? AND id = ?`,
		actor.WorkspaceID, id).Scan(&row)
	b, _ := json.Marshal(row)
	return http.StatusCreated, b, nil
}

// RedeemEscalationLease redeems one use of a lease.
func (s *ITDRService) RedeemEscalationLease(ctx context.Context, wsID uuid.UUID, leaseID uuid.UUID, nonce string) (int, []byte, error) {
	now := s.clock.Now()
	result := s.db.WithContext(ctx).Exec(`
		UPDATE itdr_escalation_leases
		   SET uses_remaining = uses_remaining - 1,
		       status = CASE WHEN uses_remaining - 1 <= 0 THEN 'redeemed' ELSE status END,
		       redeemed_at = ?
		 WHERE workspace_id = ? AND id = ? AND nonce = ?
		   AND status IN ('pending', 'approved')
		   AND uses_remaining > 0
		   AND expiry > ?`,
		now, wsID, leaseID, nonce, now)
	if result.Error != nil {
		return 0, nil, result.Error
	}
	if result.RowsAffected == 0 {
		return 0, nil, &StatusError{Status: http.StatusConflict, Code: "lease_invalid", Message: "Lease is not redeemable (expired, denied, exhausted, or wrong nonce)."}
	}

	var row map[string]any
	s.db.WithContext(ctx).Raw(`SELECT * FROM itdr_escalation_leases WHERE workspace_id = ? AND id = ?`,
		wsID, leaseID).Scan(&row)
	b, _ := json.Marshal(row)
	return http.StatusOK, b, nil
}
