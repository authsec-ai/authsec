package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentgateway"
	"github.com/authsec-ai/authsec/internal/tenancy"
)

// Tool policies and the PDP decision (SPEC-agent-runtime-gateway.md §6).
// The evaluation itself is agentgateway.Evaluate (pure); this file loads a
// workspace's policies (cached agentGatewayPolicyCacheTTL, dropped at once on
// a change in this process), keeps the per-policy rate buckets, answers
// AuthZEN evaluations and records every PDP decision.

// AgentToolPolicyView is a policy as the admin API shows it.
type AgentToolPolicyView struct {
	agentgateway.Policy
	CreatedBy uuid.UUID  `json:"created_by"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	Version   int        `json:"version"`
}

// AgentToolPolicyInput is a create or replace body.
type AgentToolPolicyInput struct {
	Name         string                   `json:"name"`
	Description  string                   `json:"description"`
	Effect       string                   `json:"effect"`
	Kind         string                   `json:"kind"`
	Subject      agentgateway.Selector    `json:"subject"`
	Target       agentgateway.Target      `json:"target"`
	Conditions   *agentgateway.Conditions `json:"conditions"`
	DenyUnlisted bool                     `json:"deny_unlisted"`
	Priority     int                      `json:"priority"`
	Enabled      *bool                    `json:"enabled"`
	// Version is required on replace: the version being replaced.
	Version *int `json:"version"`
}

func (in AgentToolPolicyInput) policy() agentgateway.Policy {
	p := agentgateway.Policy{Name: in.Name, Description: in.Description, Effect: in.Effect, Kind: in.Kind,
		Subject: in.Subject, Target: in.Target, DenyUnlisted: in.DenyUnlisted, Priority: in.Priority, Enabled: true}
	if in.Conditions != nil {
		p.Conditions = *in.Conditions
	}
	if in.Enabled != nil {
		p.Enabled = *in.Enabled
	}
	return p
}

type agentToolPolicyRow struct {
	ID                uuid.UUID
	Name              string
	Description       string
	SubjectIdentityID *uuid.UUID
	SubjectWorkloadID *uuid.UUID
	SubjectAgentLabel string
	SubjectClientID   string
	GatewayID         *uuid.UUID
	Effect            string
	Kind              string
	TargetServer      string
	TargetServerURL   string `gorm:"column:target_server_url"`
	TargetTool        string
	TargetProvider    string
	TargetModel       string
	Conditions        string
	DenyUnlisted      bool
	Priority          int
	Enabled           bool
	CreatedBy         uuid.UUID
	UpdatedBy         *uuid.UUID
	CreatedAt         time.Time
	UpdatedAt         time.Time
	Version           int
}

const agentToolPolicyCols = `id, name, description, subject_identity_id, subject_workload_id, subject_agent_label,
	subject_client_id, gateway_id, effect, kind, target_server, target_server_url, target_tool, target_provider,
	target_model, conditions::text AS conditions, deny_unlisted, priority, enabled, created_by, updated_by,
	created_at, updated_at, version`

func agwUUIDStr(u *uuid.UUID) string {
	if u == nil {
		return ""
	}
	return u.String()
}

func (r agentToolPolicyRow) view() AgentToolPolicyView {
	conds, err := agentgateway.ParseConditions([]byte(r.Conditions))
	if err != nil {
		// Stored conditions were validated; an unreadable one is treated as
		// a window that never opens (the policy never matches).
		conds = agentgateway.Conditions{TimeWindow: &agentgateway.TimeWindow{Timezone: "invalid/zone"}}
	}
	p := agentgateway.Policy{ID: r.ID.String(), Name: r.Name, Description: r.Description, Effect: r.Effect, Kind: r.Kind,
		Subject: agentgateway.Selector{IdentityID: agwUUIDStr(r.SubjectIdentityID), WorkloadID: agwUUIDStr(r.SubjectWorkloadID),
			AgentLabel: r.SubjectAgentLabel, ClientID: r.SubjectClientID, GatewayID: agwUUIDStr(r.GatewayID)},
		Target: agentgateway.Target{Kind: r.Kind, Server: r.TargetServer, ServerURL: r.TargetServerURL, Tool: r.TargetTool,
			Provider: r.TargetProvider, Model: r.TargetModel},
		Conditions: conds, DenyUnlisted: r.DenyUnlisted, Priority: r.Priority, Enabled: r.Enabled}
	return AgentToolPolicyView{Policy: p, CreatedBy: r.CreatedBy, UpdatedBy: r.UpdatedBy,
		CreatedAt: r.CreatedAt.UTC(), UpdatedAt: r.UpdatedAt.UTC(), Version: r.Version}
}

func readAgentToolPolicy(tx *gorm.DB, ws, id uuid.UUID) (*agentToolPolicyRow, error) {
	var row agentToolPolicyRow
	res := tx.Raw(`SELECT `+agentToolPolicyCols+` FROM agent_tool_policy WHERE workspace_id = ? AND id = ?`, ws, id).Scan(&row)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, GovNotFound()
	}
	return &row, nil
}

func readAgentToolPolicies(tx *gorm.DB, ws uuid.UUID) ([]agentToolPolicyRow, error) {
	var rows []agentToolPolicyRow
	err := tx.Raw(`SELECT `+agentToolPolicyCols+` FROM agent_tool_policy WHERE workspace_id = ?
		ORDER BY priority DESC, name, id`, ws).Scan(&rows).Error
	return rows, err
}

func nullUUID(s string) *uuid.UUID {
	if s == "" {
		return nil
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return nil
	}
	return &id
}

// validatePolicyInput validates the policy and that a named gateway is the
// workspace's own.
func validatePolicyInput(tx *gorm.DB, ws uuid.UUID, p *agentgateway.Policy) error {
	if errs := p.Validate(); len(errs) > 0 {
		return govErr(http.StatusUnprocessableEntity, "validation_failed", errs[0].Error(),
			map[string]any{"field": errs[0].Field, "errors": errs})
	}
	if p.Subject.GatewayID != "" {
		ok, err := gatewayExists(tx, ws, uuid.MustParse(p.Subject.GatewayID))
		if err != nil {
			return err
		}
		if !ok {
			return govErr(http.StatusUnprocessableEntity, "validation_failed", "subject.gateway_id names no gateway of this workspace.",
				map[string]any{"field": "subject.gateway_id"})
		}
	}
	return nil
}

func policyNameTaken(err error) error {
	if isUniqueViolation(err, "uq_agent_tool_policy_name") {
		return govErr(http.StatusConflict, "name_taken", "A tool policy already has this name.", map[string]any{"field": "name"})
	}
	return err
}

// ListPolicies lists the workspace's tool policies in evaluation order.
func (s *AgentGatewayService) ListPolicies(ctx context.Context, ws uuid.UUID) ([]AgentToolPolicyView, error) {
	var rows []agentToolPolicyRow
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		rows, err = readAgentToolPolicies(tx, ws)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := make([]AgentToolPolicyView, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.view())
	}
	return out, nil
}

// GetPolicy reads one policy; another workspace's is 404.
func (s *AgentGatewayService) GetPolicy(ctx context.Context, ws, id uuid.UUID) (AgentToolPolicyView, error) {
	var row *agentToolPolicyRow
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		row, err = readAgentToolPolicy(tx, ws, id)
		return err
	})
	if err != nil {
		return AgentToolPolicyView{}, err
	}
	return row.view(), nil
}

func conditionsJSON(c agentgateway.Conditions) (string, error) {
	b, err := json.Marshal(c)
	return string(b), err
}

// CreatePolicy stores a new policy.
func (s *AgentGatewayService) CreatePolicy(ctx context.Context, ws, actor uuid.UUID, in AgentToolPolicyInput) (AgentToolPolicyView, error) {
	p := in.policy()
	var row *agentToolPolicyRow
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		if err := validatePolicyInput(tx, ws, &p); err != nil {
			return err
		}
		var n int64
		if err := tx.Raw(`SELECT count(*) FROM agent_tool_policy WHERE workspace_id = ?`, ws).Scan(&n).Error; err != nil {
			return err
		}
		if n >= agentgateway.MaxPoliciesPerWS {
			return govConflict("policy_limit", fmt.Sprintf("A workspace has at most %d tool policies.", agentgateway.MaxPoliciesPerWS), nil)
		}
		conds, err := conditionsJSON(p.Conditions)
		if err != nil {
			return err
		}
		id := uuid.New()
		if err := tx.Exec(`INSERT INTO agent_tool_policy (id, workspace_id, name, description, subject_identity_id,
			    subject_workload_id, subject_agent_label, subject_client_id, gateway_id, effect, kind, target_server,
			    target_server_url, target_tool, target_provider, target_model, conditions, deny_unlisted, priority,
			    enabled, created_by)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?)`,
			id, ws, p.Name, p.Description, nullUUID(p.Subject.IdentityID), nullUUID(p.Subject.WorkloadID),
			p.Subject.AgentLabel, p.Subject.ClientID, nullUUID(p.Subject.GatewayID), p.Effect, p.Kind,
			p.Target.Server, p.Target.ServerURL, p.Target.Tool, p.Target.Provider, p.Target.Model, conds,
			p.DenyUnlisted, p.Priority, p.Enabled, actor).Error; err != nil {
			return err
		}
		row, err = readAgentToolPolicy(tx, ws, id)
		return err
	})
	if err != nil {
		return AgentToolPolicyView{}, policyNameTaken(err)
	}
	s.invalidatePolicies(ws)
	return row.view(), nil
}

// UpdatePolicy replaces a policy at the expected version (in.Version).
func (s *AgentGatewayService) UpdatePolicy(ctx context.Context, ws, id, actor uuid.UUID, in AgentToolPolicyInput) (AgentToolPolicyView, AgentToolPolicyView, error) {
	if in.Version == nil {
		return AgentToolPolicyView{}, AgentToolPolicyView{}, govErr(http.StatusUnprocessableEntity, "validation_failed",
			"version is required.", map[string]any{"field": "version"})
	}
	p := in.policy()
	var before, after *agentToolPolicyRow
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		if before, err = readAgentToolPolicy(tx, ws, id); err != nil {
			return err
		}
		if before.Version != *in.Version {
			return govConflict(GovCodeVersionConflict, "The policy changed since you opened it.",
				map[string]any{"version": before.Version})
		}
		if err := validatePolicyInput(tx, ws, &p); err != nil {
			return err
		}
		conds, err := conditionsJSON(p.Conditions)
		if err != nil {
			return err
		}
		if err := tx.Exec(`UPDATE agent_tool_policy SET name = ?, description = ?, subject_identity_id = ?,
			    subject_workload_id = ?, subject_agent_label = ?, subject_client_id = ?, gateway_id = ?, effect = ?,
			    kind = ?, target_server = ?, target_server_url = ?, target_tool = ?, target_provider = ?,
			    target_model = ?, conditions = ?::jsonb, deny_unlisted = ?, priority = ?, enabled = ?,
			    updated_by = ?, updated_at = now(), version = version + 1
			WHERE workspace_id = ? AND id = ?`,
			p.Name, p.Description, nullUUID(p.Subject.IdentityID), nullUUID(p.Subject.WorkloadID),
			p.Subject.AgentLabel, p.Subject.ClientID, nullUUID(p.Subject.GatewayID), p.Effect, p.Kind,
			p.Target.Server, p.Target.ServerURL, p.Target.Tool, p.Target.Provider, p.Target.Model, conds,
			p.DenyUnlisted, p.Priority, p.Enabled, actor, ws, id).Error; err != nil {
			return err
		}
		after, err = readAgentToolPolicy(tx, ws, id)
		return err
	})
	if err != nil {
		return AgentToolPolicyView{}, AgentToolPolicyView{}, policyNameTaken(err)
	}
	s.invalidatePolicies(ws)
	return before.view(), after.view(), nil
}

// DeletePolicy deletes a policy and returns it as it was.
func (s *AgentGatewayService) DeletePolicy(ctx context.Context, ws, id uuid.UUID) (AgentToolPolicyView, error) {
	var before *agentToolPolicyRow
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var err error
		if before, err = readAgentToolPolicy(tx, ws, id); err != nil {
			return err
		}
		return tx.Exec(`DELETE FROM agent_tool_policy WHERE workspace_id = ? AND id = ?`, ws, id).Error
	})
	if err != nil {
		return AgentToolPolicyView{}, err
	}
	s.invalidatePolicies(ws)
	return before.view(), nil
}

/* ------------------------------ policy cache ------------------------------ */

// policySet returns the workspace's enabled-or-not policies (sorted) and
// settings, from the cache when fresh.
func (s *AgentGatewayService) policySet(ctx context.Context, ws uuid.UUID) (*agentGatewayPolicySet, error) {
	now := s.now()
	s.polMu.Lock()
	if set, ok := s.pols[ws]; ok && now.Sub(set.loaded) < agentGatewayPolicyCacheTTL {
		s.polMu.Unlock()
		return set, nil
	}
	s.polMu.Unlock()
	set := &agentGatewayPolicySet{loaded: now}
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		rows, err := readAgentToolPolicies(tx, ws)
		if err != nil {
			return err
		}
		for _, r := range rows {
			set.policies = append(set.policies, r.view().Policy)
		}
		set.settings, err = readAgentGatewaySettings(tx, ws)
		return err
	})
	if err != nil {
		return nil, err
	}
	agentgateway.SortPolicies(set.policies)
	s.polMu.Lock()
	s.pols[ws] = set
	s.polMu.Unlock()
	return set, nil
}

/* ------------------------------ rate buckets ------------------------------ */

// agentGatewayBuckets are the max_calls_per_minute buckets: one token bucket
// per (policy, rate, gateway, agent, target) in this process.
type agentGatewayBuckets struct {
	mu sync.Mutex
	m  map[string]*rate.Limiter
}

func newAgentGatewayBuckets() *agentGatewayBuckets {
	return &agentGatewayBuckets{m: map[string]*rate.Limiter{}}
}

const agentGatewayMaxBuckets = 100000

// Take implements agentgateway.RateLimiter.
func (b *agentGatewayBuckets) Take(policyID, key string, perMinute int) bool {
	k := fmt.Sprintf("%s\x1f%d\x1f%s", policyID, perMinute, key)
	b.mu.Lock()
	defer b.mu.Unlock()
	l, ok := b.m[k]
	if !ok {
		if len(b.m) >= agentGatewayMaxBuckets {
			// Drop full (idle) buckets; a full bucket is the same as a new one.
			for kk, ll := range b.m {
				if ll.Tokens() >= float64(ll.Burst()) {
					delete(b.m, kk)
				}
			}
		}
		l = rate.NewLimiter(rate.Limit(float64(perMinute)/60.0), perMinute)
		b.m[k] = l
	}
	return l.Allow()
}

/* --------------------------------- decide --------------------------------- */

// AgentGatewayDecision is one PDP answer.
type AgentGatewayDecision struct {
	Response agentgateway.EvaluationResponse
	Result   agentgateway.Result
	Request  agentgateway.Request
}

func decisionContext(id uuid.UUID, res agentgateway.Result, mode string, ttl int) map[string]any {
	admin := map[string]any{"reason": res.Reason}
	if res.PolicyID != "" {
		admin["policy_id"] = res.PolicyID
		admin["policy_name"] = res.PolicyName
	}
	ctx := map[string]any{
		"reason_admin": admin,
		"reason_user":  map[string]any{"reason": res.Reason},
		"ttl_seconds":  ttl,
		"mode":         mode,
	}
	if id != uuid.Nil {
		ctx["decision_id"] = id.String()
	}
	return ctx
}

func cacheTTL(res agentgateway.Result, settingTTL int) int {
	if !res.Cacheable {
		return 0
	}
	ttl := settingTTL
	if res.TTLCap > 0 {
		capS := int(res.TTLCap / time.Second)
		if capS < ttl {
			ttl = capS
		}
	}
	return ttl
}

// Decide answers one AuthZEN evaluation for an authenticated gateway and
// records the decision (source pdp). An agentgateway.ErrInvalid error is
// the caller's 400 (or a per-evaluation error in a batch).
func (s *AgentGatewayService) Decide(ctx context.Context, p AgentGatewayPrincipal, e agentgateway.EvaluationRequest) (AgentGatewayDecision, error) {
	start := time.Now()
	req, err := agentgateway.FromAuthZEN(e)
	if err != nil {
		return AgentGatewayDecision{}, err
	}
	req.GatewayID = p.GatewayID.String()
	set, err := s.policySet(ctx, p.WorkspaceID)
	if err != nil {
		return AgentGatewayDecision{}, err
	}
	now := s.now()
	res := agentgateway.Evaluate(set.policies, req, set.settings.Mode, now, s.buckets)
	id := uuid.New()
	ttl := cacheTTL(res, set.settings.CacheTTLSeconds)
	latency := float64(time.Since(start).Microseconds()) / 1000.0
	s.writer.enqueue(pdpDecisionRow(p, id, now, req, res, latency))
	resp := agentgateway.EvaluationResponse{Decision: res.Allowed, Context: decisionContext(id, res, set.settings.Mode, ttl)}
	return AgentGatewayDecision{Response: resp, Result: res, Request: req}, nil
}

// AgentGatewayDryRun is a dry-run answer: the decision and every policy's
// part in it. Nothing is recorded and no rate token is taken.
type AgentGatewayDryRun struct {
	Decision  bool                 `json:"decision"`
	Reason    string               `json:"reason"`
	PolicyID  string               `json:"policy_id,omitempty"`
	Policy    string               `json:"policy_name,omitempty"`
	Mode      string               `json:"mode"`
	TTL       int                  `json:"ttl_seconds"`
	Request   map[string]any       `json:"request"`
	Trace     []agentgateway.Trace `json:"policies"`
	Evaluated time.Time            `json:"evaluated_at"`
}

// DryRun evaluates without recording. gatewayID, when set, must be the
// workspace's own gateway (it simulates that gateway asking).
func (s *AgentGatewayService) DryRun(ctx context.Context, ws uuid.UUID, gatewayID string, e agentgateway.EvaluationRequest) (AgentGatewayDryRun, error) {
	req, err := agentgateway.FromAuthZEN(e)
	if err != nil {
		return AgentGatewayDryRun{}, GovBadParam("body", strings.TrimPrefix(err.Error(), agentgateway.ErrInvalid.Error()+": "))
	}
	if gatewayID != "" {
		gid, perr := uuid.Parse(gatewayID)
		if perr != nil {
			return AgentGatewayDryRun{}, GovBadParam("gateway_id", "gateway_id must be a UUID.")
		}
		if _, err := s.GetGateway(ctx, ws, gid); err != nil {
			return AgentGatewayDryRun{}, err
		}
		req.GatewayID = gid.String()
	}
	set, err := s.policySet(ctx, ws)
	if err != nil {
		return AgentGatewayDryRun{}, err
	}
	now := s.now()
	res := agentgateway.Evaluate(set.policies, req, set.settings.Mode, now, nil)
	return AgentGatewayDryRun{Decision: res.Allowed, Reason: res.Reason, PolicyID: res.PolicyID, Policy: res.PolicyName,
		Mode: set.settings.Mode, TTL: cacheTTL(res, set.settings.CacheTTLSeconds),
		Request: map[string]any{"subject_id": req.SubjectID, "subject": req.SubjectProps(), "kind": req.Kind,
			"resource_id": req.ResourceID(), "resource": req.ResourceProps(), "gateway_id": req.GatewayID},
		Trace: res.Trace, Evaluated: now.UTC()}, nil
}

// AgentGatewayPolicyHints is what a gateway needs for its auto fail mode:
// the workspace mode and the deny policies' targets (no subjects, no names).
type AgentGatewayPolicyHints struct {
	Mode        string                `json:"mode"`
	DenyTargets []agentgateway.Target `json:"deny_targets"`
	TTLSeconds  int                   `json:"ttl_seconds"`
	AsOf        time.Time             `json:"as_of"`
}

// PolicyHints returns the hints for an authenticated gateway.
func (s *AgentGatewayService) PolicyHints(ctx context.Context, p AgentGatewayPrincipal) (AgentGatewayPolicyHints, error) {
	set, err := s.policySet(ctx, p.WorkspaceID)
	if err != nil {
		return AgentGatewayPolicyHints{}, err
	}
	var applicable []agentgateway.Policy
	for _, pol := range set.policies {
		if pol.Subject.GatewayID == "" || strings.EqualFold(pol.Subject.GatewayID, p.GatewayID.String()) {
			applicable = append(applicable, pol)
		}
	}
	t := agentgateway.DenyTargets(applicable)
	if t == nil {
		t = []agentgateway.Target{}
	}
	return AgentGatewayPolicyHints{Mode: set.settings.Mode, DenyTargets: t, TTLSeconds: 60, AsOf: s.now().UTC()}, nil
}

// IsInvalidEvaluation reports an AuthZEN mapping error.
func IsInvalidEvaluation(err error) bool { return errors.Is(err, agentgateway.ErrInvalid) }
