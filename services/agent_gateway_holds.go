package services

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentgateway"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

/* agent_gateway_holds.go: calls held for a person (W6, P17).

   A gateway that finds a call outside the argument bounds of the policy
   that allowed it, where that policy says "hold", asks AuthSec to hold it
   (POST /authsec/pdp/v1/holds). AuthSec:
     - checks the policy is the workspace's and really holds on violation
       (the hold's lifetime is the policy's, never the gateway's);
     - names the approver: the responder resolution of the agent's W7 agent
       when its agent key names one (GatewayHoldResponder; default W7's
       resolveResponder), else the workspace's default responder group --
       never the agent's own human principal;
     - records the hold with the bounded fields' values (held_values, for
       the approver only) and a decision-log row "ask" naming the violated
       paths and rules (never values), in one transaction;
     - asks: GatewayHoldAsker (default: governance event gateway.ask_needed;
       W4 replaces it with an agent_ask through SetGatewayHoldAsker).
   A person with governance:approve who is one of the hold's deciders (and
   not the agent's principal) approves or denies it
   (POST /api/iga/v1/agent-runtime/gateway-holds/:id/decide). The gateway
   either waits, polling GET /authsec/pdp/v1/holds/:id, or answers the agent
   "held" and lets it retry with X-AuthSec-Hold-Id; an approved hold is
   consumed once (POST /authsec/pdp/v1/holds/:id/consume) by a call with the
   same agent, target and arguments digest. held_values are cleared when the
   hold ends (denied, expired, consumed). */

// Hold states.
const (
	GatewayHoldPending  = "pending"
	GatewayHoldApproved = "approved"
	GatewayHoldDenied   = "denied"
	GatewayHoldExpired  = "expired"
	GatewayHoldConsumed = "consumed"
)

// GatewayHoldAsk is what an asker is told about a new hold (no values).
type GatewayHoldAsk struct {
	HoldID           uuid.UUID
	GatewayID        uuid.UUID
	SubjectID        string
	ResourceID       string
	AgentID          *uuid.UUID
	ResponderGroupID *uuid.UUID
	ResponderVia     string
	ApproverUserID   *uuid.UUID
	Deciders         []uuid.UUID
	Violations       []agentgateway.BoundViolation
	ExpiresAt        time.Time
	RunID            string
}

// GatewayHoldAsker raises the ask for a new hold, in the hold's transaction.
// W4 installs its CreateAsk-backed asker with SetGatewayHoldAsker.
type GatewayHoldAsker interface {
	AskForHold(tx *gorm.DB, ws uuid.UUID, ask GatewayHoldAsk) error
}

// GatewayHoldResponder names who decides a hold for an agent (nil agent:
// the workspace default). W7's responder resolution is the default.
type GatewayHoldResponder interface {
	ResolveHoldResponder(tx *gorm.DB, ws uuid.UUID, agentID *uuid.UUID, now time.Time) (*ResponderResolution, error)
}

type eventHoldAsker struct{}

// AskForHold records gateway.ask_needed: the hold, its approver and expiry,
// the violated paths. Never a value.
func (eventHoldAsker) AskForHold(tx *gorm.DB, ws uuid.UUID, a GatewayHoldAsk) error {
	return appendGovEvent(tx, ws, GovEventGatewayAskNeeded, models.GovActorSystem, "agent_gateway", govEventRefs{},
		map[string]any{"hold_id": a.HoldID, "gateway_id": a.GatewayID, "subject_id": a.SubjectID, "resource_id": a.ResourceID,
			"agent_id": a.AgentID, "responder_group_id": a.ResponderGroupID, "responder_via": a.ResponderVia,
			"approver_user_id": a.ApproverUserID, "deciders": a.Deciders, "violations": a.Violations,
			"expires_at": a.ExpiresAt, "run_id": a.RunID})
}

type w7HoldResponder struct{}

func (w7HoldResponder) ResolveHoldResponder(tx *gorm.DB, ws uuid.UUID, agentID *uuid.UUID, now time.Time) (*ResponderResolution, error) {
	if err := ensureDefaultResponderGroup(tx, ws); err != nil {
		return nil, err
	}
	if agentID != nil {
		if _, err := loadAgent(tx, ws, *agentID, false); err == nil {
			return resolveResponder(tx, ws, *agentID, now)
		}
	}
	out := &ResponderResolution{Via: ResponderViaNone, Deciders: []ResponderDecider{}}
	var def []struct {
		ID   uuid.UUID
		Name string
	}
	if err := tx.Raw(`SELECT id, name FROM responder_group WHERE workspace_id = ? AND is_default`, ws).Scan(&def).Error; err != nil {
		return nil, err
	}
	if len(def) == 0 {
		return out, nil
	}
	id := def[0].ID
	out.GroupID, out.GroupName, out.Via = &id, def[0].Name, ResponderViaDefault
	d, err := groupDeciders(tx, ws, id, now)
	out.Deciders = d
	return out, err
}

var gatewayHoldDeps = struct {
	sync.RWMutex
	asker     GatewayHoldAsker
	responder GatewayHoldResponder
}{asker: eventHoldAsker{}, responder: w7HoldResponder{}}

// SetGatewayHoldAsker installs the asker (W4); nil restores the default.
// It returns the undo.
func SetGatewayHoldAsker(a GatewayHoldAsker) (restore func()) {
	gatewayHoldDeps.Lock()
	prev := gatewayHoldDeps.asker
	if a == nil {
		a = eventHoldAsker{}
	}
	gatewayHoldDeps.asker = a
	gatewayHoldDeps.Unlock()
	return func() { SetGatewayHoldAsker(prev) }
}

// SetGatewayHoldResponder installs the responder resolution; nil restores
// W7's. It returns the undo.
func SetGatewayHoldResponder(r GatewayHoldResponder) (restore func()) {
	gatewayHoldDeps.Lock()
	prev := gatewayHoldDeps.responder
	if r == nil {
		r = w7HoldResponder{}
	}
	gatewayHoldDeps.responder = r
	gatewayHoldDeps.Unlock()
	return func() { SetGatewayHoldResponder(prev) }
}

func holdDeps() (GatewayHoldAsker, GatewayHoldResponder) {
	gatewayHoldDeps.RLock()
	defer gatewayHoldDeps.RUnlock()
	return gatewayHoldDeps.asker, gatewayHoldDeps.responder
}

/* ------------------------------------ PDP side ------------------------------ */

// AgentGatewayHoldRequest is POST /pdp/v1/holds.
type AgentGatewayHoldRequest struct {
	Subject    *agentgateway.Entity          `json:"subject"`
	Action     *agentgateway.Action          `json:"action"`
	Resource   *agentgateway.Entity          `json:"resource"`
	ArgsDigest string                        `json:"args_digest"`
	RunID      string                        `json:"run_id,omitempty"`
	RequestID  string                        `json:"request_id,omitempty"`
	PolicyID   string                        `json:"policy_id"`
	Violations []agentgateway.BoundViolation `json:"violations"`
	// HeldValues are the bounded fields' values, kept for the approver.
	HeldValues map[string]json.RawMessage `json:"held_values,omitempty"`
}

// AgentGatewayHoldTicket is what the gateway learns about a hold.
type AgentGatewayHoldTicket struct {
	HoldID         uuid.UUID  `json:"hold_id"`
	State          string     `json:"state"`
	ExpiresAt      time.Time  `json:"expires_at"`
	ApproverUserID *uuid.UUID `json:"approver_user_id,omitempty"`
	DecisionReason string     `json:"decision_reason,omitempty"`
}

func badHold(msg string) error { return govErr(http.StatusBadRequest, "invalid_hold", msg, nil) }

// CreateHold records a held call for the authenticated gateway.
func (s *AgentGatewayService) CreateHold(ctx context.Context, p AgentGatewayPrincipal, in AgentGatewayHoldRequest) (AgentGatewayHoldTicket, error) {
	ctxMap := map[string]any{"args_digest": in.ArgsDigest}
	if in.RunID != "" {
		ctxMap["run_id"] = in.RunID
	}
	if in.RequestID != "" {
		ctxMap["request_id"] = in.RequestID
	}
	req, err := agentgateway.FromAuthZEN(agentgateway.EvaluationRequest{Subject: in.Subject, Action: in.Action,
		Resource: in.Resource, Context: ctxMap})
	if err != nil {
		return AgentGatewayHoldTicket{}, badHold(strings.TrimPrefix(err.Error(), agentgateway.ErrInvalid.Error()+": "))
	}
	if req.Kind != agentgateway.KindMCPTool || req.ArgsDigest == "" {
		return AgentGatewayHoldTicket{}, badHold("a hold is of an MCP tool call with its args_digest")
	}
	if len(in.Violations) == 0 {
		return AgentGatewayHoldTicket{}, badHold("violations are required")
	}
	if why := checkViolations(in.Violations); why != "" {
		return AgentGatewayHoldTicket{}, badHold(why)
	}
	if len(in.HeldValues) > agentgateway.MaxBoundFields {
		return AgentGatewayHoldTicket{}, badHold("too many held values")
	}
	policyID, err := uuid.Parse(in.PolicyID)
	if err != nil {
		return AgentGatewayHoldTicket{}, badHold("policy_id must be the policy that allowed the call")
	}
	asker, responder := holdDeps()
	now := s.now().UTC()
	var ticket AgentGatewayHoldTicket
	err = tenancy.InWorkspace(ctx, s.db, p.WorkspaceID, func(tx *gorm.DB) error {
		pol, err := readAgentToolPolicy(tx, p.WorkspaceID, policyID)
		if err != nil {
			return badHold("policy_id is not one of the workspace's policies")
		}
		pv := pol.view()
		b := pv.Conditions.ArgBounds
		if !pv.Enabled || pv.Effect != agentgateway.EffectAllow || !b.Hold() {
			return govErr(http.StatusConflict, "policy_does_not_hold", "The policy does not hold calls outside its bounds.", nil)
		}
		// Keep only values of fields the policy bounds.
		values := map[string]json.RawMessage{}
		for _, f := range b.Fields {
			if v, ok := in.HeldValues[f.Path]; ok && len(v) <= agentgateway.MaxHeldValueBytes && json.Valid(v) {
				values[f.Path] = v
			}
		}
		var key []struct {
			ID              uuid.UUID
			AgentID         *uuid.UUID
			PrincipalUserID *uuid.UUID
		}
		if err := tx.Raw(`SELECT id, agent_id, principal_user_id FROM agent_gateway_agent_key
		                   WHERE workspace_id = ? AND client_id = ? AND revoked_at IS NULL LIMIT 1`,
			p.WorkspaceID, req.SubjectID).Scan(&key).Error; err != nil {
			return err
		}
		var keyID, agentID, principal *uuid.UUID
		if len(key) == 1 {
			k := key[0]
			keyID, agentID, principal = &k.ID, k.AgentID, k.PrincipalUserID
		}
		res, err := responder.ResolveHoldResponder(tx, p.WorkspaceID, agentID, now)
		if err != nil {
			return err
		}
		var deciders []uuid.UUID
		for _, d := range res.Deciders {
			if principal != nil && d.UserID == *principal {
				continue // never the agent's own human
			}
			deciders = append(deciders, d.UserID)
		}
		if deciders == nil {
			deciders = []uuid.UUID{}
		}
		var approver *uuid.UUID
		if len(deciders) > 0 {
			a := deciders[0]
			approver = &a
		}
		id := uuid.New()
		expires := now.Add(time.Duration(b.HoldFor()) * time.Minute)
		if err := tx.Exec(`INSERT INTO agent_gateway_hold
			  (id, workspace_id, gateway_id, subject_id, subject, kind, resource_id, resource, policy_id, args_digest, run_id,
			   request_id, violations, held_values, agent_key_id, agent_id, principal_user_id, responder_group_id, responder_via,
			   approver_user_id, deciders, state, expires_at, created_at)
			VALUES (?, ?, ?, ?, ?::jsonb, ?, ?, ?::jsonb, ?, ?, ?, ?, ?::jsonb, ?::jsonb, ?, ?, ?, ?, ?, ?, ?::jsonb, 'pending', ?, ?)`,
			id, p.WorkspaceID, p.GatewayID, req.SubjectID, agwJSON(req.SubjectProps()), req.Kind, req.ResourceID(),
			agwJSON(req.ResourceProps()), policyID, req.ArgsDigest, req.RunID, req.RequestID, agwJSON(in.Violations),
			agwJSON(values), keyID, agentID, principal, res.GroupID, res.Via, approver, agwJSON(deciders), expires, now).Error; err != nil {
			return err
		}
		viol := agwJSON(in.Violations)
		row := agentGatewayDecisionRow{ID: uuid.New(), WorkspaceID: p.WorkspaceID, GatewayID: p.GatewayID,
			RecordType: AgentGatewayRecordDecision, Source: AgentGatewaySourceGateway, DecidedAt: now,
			SubjectType: agentgateway.SubjectTypeAgent, SubjectID: req.SubjectID, Subject: agwJSON(req.SubjectProps()),
			Action: agentgateway.ActionToolsCall, Kind: req.Kind, ResourceID: req.ResourceID(), Resource: agwJSON(req.ResourceProps()),
			Decision: agentgateway.DecisionAsk, Reason: agentgateway.ReasonArgumentHeld, PolicyID: &policyID,
			ArgsDigest: agwStrPtr(req.ArgsDigest), RequestID: req.RequestID, RunID: req.RunID, HoldID: &id, Violations: &viol}
		if _, err := insertDecisionRowsTx(tx, p.WorkspaceID, []agentGatewayDecisionRow{row}); err != nil {
			return err
		}
		if err := asker.AskForHold(tx, p.WorkspaceID, GatewayHoldAsk{HoldID: id, GatewayID: p.GatewayID, SubjectID: req.SubjectID,
			ResourceID: req.ResourceID(), AgentID: agentID, ResponderGroupID: res.GroupID, ResponderVia: res.Via,
			ApproverUserID: approver, Deciders: deciders, Violations: in.Violations, ExpiresAt: expires, RunID: req.RunID}); err != nil {
			return err
		}
		ticket = AgentGatewayHoldTicket{HoldID: id, State: GatewayHoldPending, ExpiresAt: expires, ApproverUserID: approver}
		return nil
	})
	return ticket, err
}

type gatewayHoldRow struct {
	ID               uuid.UUID
	GatewayID        uuid.UUID
	SubjectID        string
	Subject          string
	Kind             string
	ResourceID       string
	Resource         string
	PolicyID         *uuid.UUID
	ArgsDigest       string
	RunID            string
	RequestID        string
	Violations       string
	HeldValues       *string
	AgentKeyID       *uuid.UUID
	AgentID          *uuid.UUID
	PrincipalUserID  *uuid.UUID
	ResponderGroupID *uuid.UUID
	ResponderVia     string
	ApproverUserID   *uuid.UUID
	Deciders         string
	State            string
	ExpiresAt        time.Time
	CreatedAt        time.Time
	DecidedBy        *uuid.UUID
	DecidedAt        *time.Time
	DecisionReason   string
	ConsumedAt       *time.Time
}

const gatewayHoldCols = `id, gateway_id, subject_id, subject::text AS subject, kind, resource_id, resource::text AS resource,
	policy_id, args_digest, run_id, request_id, violations::text AS violations, held_values::text AS held_values, agent_key_id,
	agent_id, principal_user_id, responder_group_id, responder_via, approver_user_id, deciders::text AS deciders, state,
	expires_at, created_at, decided_by, decided_at, decision_reason, consumed_at`

func readGatewayHold(tx *gorm.DB, ws, id uuid.UUID, lock bool) (*gatewayHoldRow, error) {
	q := `SELECT ` + gatewayHoldCols + ` FROM agent_gateway_hold WHERE workspace_id = ? AND id = ?`
	if lock {
		q += ` FOR UPDATE`
	}
	var rows []gatewayHoldRow
	if err := tx.Raw(q, ws, id).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, GovNotFound()
	}
	return &rows[0], nil
}

// expireHoldTx ends a pending or approved hold past its expiry: state
// expired, values cleared, an event. It reports whether it did.
func expireHoldTx(tx *gorm.DB, ws uuid.UUID, h *gatewayHoldRow, now time.Time) (bool, error) {
	if (h.State != GatewayHoldPending && h.State != GatewayHoldApproved) || now.Before(h.ExpiresAt) {
		return false, nil
	}
	if err := tx.Exec(`UPDATE agent_gateway_hold SET state = 'expired', held_values = NULL
	                    WHERE workspace_id = ? AND id = ? AND state IN ('pending', 'approved')`, ws, h.ID).Error; err != nil {
		return false, err
	}
	h.State, h.HeldValues = GatewayHoldExpired, nil
	return true, appendGovEvent(tx, ws, GovEventGatewayHoldExpired, models.GovActorSystem, "agent_gateway", govEventRefs{},
		map[string]any{"hold_id": h.ID, "subject_id": h.SubjectID, "resource_id": h.ResourceID})
}

func (h *gatewayHoldRow) ticket() AgentGatewayHoldTicket {
	return AgentGatewayHoldTicket{HoldID: h.ID, State: h.State, ExpiresAt: h.ExpiresAt.UTC(), ApproverUserID: h.ApproverUserID,
		DecisionReason: h.DecisionReason}
}

// HoldStatus is GET /pdp/v1/holds/:id for the gateway that opened it
// (another gateway's or workspace's hold is 404).
func (s *AgentGatewayService) HoldStatus(ctx context.Context, p AgentGatewayPrincipal, id uuid.UUID) (AgentGatewayHoldTicket, error) {
	var out AgentGatewayHoldTicket
	err := tenancy.InWorkspace(ctx, s.db, p.WorkspaceID, func(tx *gorm.DB) error {
		h, err := readGatewayHold(tx, p.WorkspaceID, id, true)
		if err != nil {
			return err
		}
		if h.GatewayID != p.GatewayID {
			return GovNotFound()
		}
		if _, err := expireHoldTx(tx, p.WorkspaceID, h, s.now().UTC()); err != nil {
			return err
		}
		out = h.ticket()
		return nil
	})
	return out, err
}

// AgentGatewayHoldConsume is POST /pdp/v1/holds/:id/consume: the call the
// gateway is about to forward, which must be the held one.
type AgentGatewayHoldConsume struct {
	SubjectID  string `json:"subject_id"`
	ResourceID string `json:"resource_id"`
	ArgsDigest string `json:"args_digest"`
	RunID      string `json:"run_id,omitempty"`
}

// ConsumeHold lets an approved hold's call through once: same agent,
// target and arguments digest, before expiry. The values are cleared and
// the decision log records the allow (reason hold_approved).
func (s *AgentGatewayService) ConsumeHold(ctx context.Context, p AgentGatewayPrincipal, id uuid.UUID, in AgentGatewayHoldConsume) (AgentGatewayHoldTicket, error) {
	var out AgentGatewayHoldTicket
	now := s.now().UTC()
	err := tenancy.InWorkspace(ctx, s.db, p.WorkspaceID, func(tx *gorm.DB) error {
		h, err := readGatewayHold(tx, p.WorkspaceID, id, true)
		if err != nil {
			return err
		}
		if h.GatewayID != p.GatewayID {
			return GovNotFound()
		}
		if _, err := expireHoldTx(tx, p.WorkspaceID, h, now); err != nil {
			return err
		}
		if h.State != GatewayHoldApproved {
			out = h.ticket()
			return govErr(http.StatusConflict, "hold_not_approved", "The hold is "+h.State+".", map[string]any{"state": h.State})
		}
		if in.SubjectID != h.SubjectID || in.ResourceID != h.ResourceID || in.ArgsDigest != h.ArgsDigest {
			return govErr(http.StatusConflict, "hold_mismatch", "The call is not the held one (agent, tool or arguments differ).", nil)
		}
		if err := tx.Exec(`UPDATE agent_gateway_hold SET state = 'consumed', consumed_at = ?, held_values = NULL
		                    WHERE workspace_id = ? AND id = ?`, now, p.WorkspaceID, id).Error; err != nil {
			return err
		}
		h.State = GatewayHoldConsumed
		runID := h.RunID
		if in.RunID != "" && agentgateway.ValidRunID(in.RunID) {
			runID = in.RunID
		}
		row := agentGatewayDecisionRow{ID: uuid.New(), WorkspaceID: p.WorkspaceID, GatewayID: p.GatewayID,
			RecordType: AgentGatewayRecordDecision, Source: AgentGatewaySourceGateway, DecidedAt: now,
			SubjectType: agentgateway.SubjectTypeAgent, SubjectID: h.SubjectID, Subject: h.Subject, Action: agentgateway.ActionToolsCall,
			Kind: h.Kind, ResourceID: h.ResourceID, Resource: h.Resource, Decision: agentgateway.EffectAllow,
			Reason: agentgateway.ReasonHoldApproved, PolicyID: h.PolicyID, ArgsDigest: agwStrPtr(h.ArgsDigest), RunID: runID, HoldID: &h.ID}
		if _, err := insertDecisionRowsTx(tx, p.WorkspaceID, []agentGatewayDecisionRow{row}); err != nil {
			return err
		}
		out = h.ticket()
		return nil
	})
	return out, err
}

/* ----------------------------------- admin side ----------------------------- */

// AgentGatewayHoldView is a hold as the console shows it. HeldValues are
// present only while the hold is pending or approved.
type AgentGatewayHoldView struct {
	ID               uuid.UUID       `json:"id"`
	GatewayID        uuid.UUID       `json:"gateway_id"`
	SubjectID        string          `json:"subject_id"`
	Subject          json.RawMessage `json:"subject"`
	Kind             string          `json:"kind"`
	ResourceID       string          `json:"resource_id"`
	Resource         json.RawMessage `json:"resource"`
	PolicyID         *uuid.UUID      `json:"policy_id"`
	ArgsDigest       string          `json:"args_digest"`
	RunID            string          `json:"run_id,omitempty"`
	Violations       json.RawMessage `json:"violations"`
	HeldValues       json.RawMessage `json:"held_values,omitempty"`
	AgentID          *uuid.UUID      `json:"agent_id"`
	PrincipalUserID  *uuid.UUID      `json:"principal_user_id"`
	ResponderGroupID *uuid.UUID      `json:"responder_group_id"`
	ResponderVia     string          `json:"responder_via"`
	ApproverUserID   *uuid.UUID      `json:"approver_user_id"`
	Deciders         json.RawMessage `json:"deciders"`
	State            string          `json:"state"`
	ExpiresAt        time.Time       `json:"expires_at"`
	CreatedAt        time.Time       `json:"created_at"`
	DecidedBy        *uuid.UUID      `json:"decided_by"`
	DecidedAt        *time.Time      `json:"decided_at"`
	DecisionReason   string          `json:"decision_reason"`
	ConsumedAt       *time.Time      `json:"consumed_at"`
}

func (h *gatewayHoldRow) view(withValues bool) AgentGatewayHoldView {
	v := AgentGatewayHoldView{ID: h.ID, GatewayID: h.GatewayID, SubjectID: h.SubjectID, Subject: json.RawMessage(h.Subject),
		Kind: h.Kind, ResourceID: h.ResourceID, Resource: json.RawMessage(h.Resource), PolicyID: h.PolicyID,
		ArgsDigest: h.ArgsDigest, RunID: h.RunID, Violations: json.RawMessage(h.Violations), AgentID: h.AgentID,
		PrincipalUserID: h.PrincipalUserID, ResponderGroupID: h.ResponderGroupID, ResponderVia: h.ResponderVia,
		ApproverUserID: h.ApproverUserID, Deciders: json.RawMessage(h.Deciders), State: h.State,
		ExpiresAt: h.ExpiresAt.UTC(), CreatedAt: h.CreatedAt.UTC(), DecidedBy: h.DecidedBy, DecidedAt: utcPtr(h.DecidedAt),
		DecisionReason: h.DecisionReason, ConsumedAt: utcPtr(h.ConsumedAt)}
	if withValues && h.HeldValues != nil {
		v.HeldValues = json.RawMessage(*h.HeldValues)
	}
	return v
}

// ListHolds lists the workspace's holds, newest first (no values: open one
// to see them).
func (s *AgentGatewayService) ListHolds(ctx context.Context, ws uuid.UUID, state string) ([]AgentGatewayHoldView, error) {
	switch state {
	case "", GatewayHoldPending, GatewayHoldApproved, GatewayHoldDenied, GatewayHoldExpired, GatewayHoldConsumed:
	default:
		return nil, GovBadParam("state", "state must be pending, approved, denied, expired or consumed.")
	}
	var rows []gatewayHoldRow
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		q := `SELECT ` + gatewayHoldCols + ` FROM agent_gateway_hold WHERE workspace_id = ?`
		args := []any{ws}
		if state != "" {
			q, args = q+` AND state = ?`, append(args, state)
		}
		return tx.Raw(q+` ORDER BY created_at DESC, id DESC LIMIT 200`, args...).Scan(&rows).Error
	})
	out := make([]AgentGatewayHoldView, 0, len(rows))
	now := s.now()
	for i := range rows {
		if (rows[i].State == GatewayHoldPending || rows[i].State == GatewayHoldApproved) && !now.Before(rows[i].ExpiresAt) {
			rows[i].State = GatewayHoldExpired
		}
		out = append(out, rows[i].view(false))
	}
	return out, err
}

// GetHold reads one hold with its values (while it is open); another
// workspace's is 404.
func (s *AgentGatewayService) GetHold(ctx context.Context, ws, id uuid.UUID) (AgentGatewayHoldView, error) {
	var out AgentGatewayHoldView
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		h, err := readGatewayHold(tx, ws, id, true)
		if err != nil {
			return err
		}
		if _, err := expireHoldTx(tx, ws, h, s.now().UTC()); err != nil {
			return err
		}
		out = h.view(true)
		return nil
	})
	return out, err
}

// Hold decisions.
const (
	GatewayHoldApprove = "approve"
	GatewayHoldDeny    = "deny"
)

// DecideHold approves or denies a pending hold. The decider is never the
// agent's own human principal, and is one of the hold's deciders when it
// names any. An expired hold cannot be decided.
func (s *AgentGatewayService) DecideHold(ctx context.Context, ws, id, actor uuid.UUID, decision, reason string) (AgentGatewayHoldView, AgentGatewayHoldView, error) {
	if decision != GatewayHoldApprove && decision != GatewayHoldDeny {
		return AgentGatewayHoldView{}, AgentGatewayHoldView{}, GovBadParam("decision", "decision must be approve or deny.")
	}
	reason = strings.TrimSpace(reason)
	if len(reason) > 2000 {
		return AgentGatewayHoldView{}, AgentGatewayHoldView{}, GovBadParam("reason", "reason is at most 2000 characters.")
	}
	now := s.now().UTC()
	var before, after AgentGatewayHoldView
	var expired bool
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		h, err := readGatewayHold(tx, ws, id, true)
		if err != nil {
			return err
		}
		before = h.view(false)
		if expired, err = expireHoldTx(tx, ws, h, now); err != nil {
			return err
		}
		if h.State != GatewayHoldPending {
			return nil
		}
		if h.PrincipalUserID != nil && *h.PrincipalUserID == actor {
			return govErr(http.StatusForbidden, "approver_is_principal",
				"The agent acts for you: someone else must decide its held call.", nil)
		}
		var deciders []uuid.UUID
		_ = json.Unmarshal([]byte(h.Deciders), &deciders)
		if len(deciders) > 0 {
			in := false
			for _, d := range deciders {
				if d == actor {
					in = true
					break
				}
			}
			if !in {
				return govErr(http.StatusForbidden, "not_a_decider",
					"Only a member of the agent's responder group decides this held call.", map[string]any{"approver_user_id": h.ApproverUserID})
			}
		}
		state, values := GatewayHoldApproved, "held_values"
		if decision == GatewayHoldDeny {
			state, values = GatewayHoldDenied, "NULL"
		}
		if err := tx.Exec(`UPDATE agent_gateway_hold SET state = ?, decided_by = ?, decided_at = ?, decision_reason = ?,
		                     held_values = `+values+` WHERE workspace_id = ? AND id = ? AND state = 'pending'`,
			state, actor, now, reason, ws, id).Error; err != nil {
			return err
		}
		if decision == GatewayHoldDeny {
			row := agentGatewayDecisionRow{ID: uuid.New(), WorkspaceID: ws, GatewayID: h.GatewayID,
				RecordType: AgentGatewayRecordDecision, Source: AgentGatewaySourcePDP, DecidedAt: now,
				SubjectType: agentgateway.SubjectTypeAgent, SubjectID: h.SubjectID, Subject: h.Subject, Action: agentgateway.ActionToolsCall,
				Kind: h.Kind, ResourceID: h.ResourceID, Resource: h.Resource, Decision: agentgateway.EffectDeny,
				Reason: agentgateway.ReasonHoldDenied, PolicyID: h.PolicyID, ArgsDigest: agwStrPtr(h.ArgsDigest), RunID: h.RunID, HoldID: &h.ID}
			if _, err := insertDecisionRowsTx(tx, ws, []agentGatewayDecisionRow{row}); err != nil {
				return err
			}
		}
		if err := appendGovEvent(tx, ws, GovEventGatewayHoldDecided, models.GovActorUser, actor.String(), govEventRefs{},
			map[string]any{"hold_id": id, "decision": decision, "reason": truncate(reason, 500), "subject_id": h.SubjectID,
				"resource_id": h.ResourceID}); err != nil {
			return err
		}
		h2, err := readGatewayHold(tx, ws, id, false)
		if err != nil {
			return err
		}
		after = h2.view(false)
		return nil
	})
	if err != nil {
		return before, after, err
	}
	if after.ID == uuid.Nil {
		code, msg := "hold_not_pending", "The held call was already decided."
		if expired || before.State == GatewayHoldExpired {
			code, msg = "hold_expired", "The held call expired before it was decided."
		}
		return before, after, govConflict(code, msg, map[string]any{"state": before.State})
	}
	return before, after, nil
}

/* ------------------------------------ sweeper ------------------------------- */

// SweepExpiredHolds expires due holds (clearing their values) across
// workspaces, each in its own workspace transaction. It returns how many.
func (s *AgentGatewayService) SweepExpiredHolds(ctx context.Context) (int, error) {
	var due []struct {
		WorkspaceID uuid.UUID
		ID          uuid.UUID
	}
	now := s.now().UTC()
	// TENANT-EXEMPT: the hold sweeper runs across workspaces (no request tenant) and lists due hold ids only; each is expired in its own workspace_id-bound transaction (tenancy.InWorkspace).
	if err := s.db.WithContext(ctx).Raw(`SELECT workspace_id, id FROM agent_gateway_hold
	                                      WHERE state IN ('pending', 'approved') AND expires_at <= ?
	                                      ORDER BY expires_at LIMIT 500`, now).Scan(&due).Error; err != nil {
		return 0, err
	}
	n := 0
	for _, d := range due {
		err := tenancy.InWorkspace(ctx, s.db, d.WorkspaceID, func(tx *gorm.DB) error {
			h, err := readGatewayHold(tx, d.WorkspaceID, d.ID, true)
			if err != nil {
				return err
			}
			did, err := expireHoldTx(tx, d.WorkspaceID, h, now)
			if did {
				n++
			}
			return err
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("[agent-gateway] hold sweep workspace=%s hold=%s: %v", d.WorkspaceID, d.ID, err)
		}
	}
	return n, nil
}

// RunGatewayHoldSweeper expires due holds every minute until ctx ends.
// AUTHSEC_DISABLE_GATEWAY_HOLD_SWEEP=true turns it off (reads still expire
// a due hold).
func RunGatewayHoldSweeper(ctx context.Context, db *gorm.DB) {
	if os.Getenv("AUTHSEC_DISABLE_GATEWAY_HOLD_SWEEP") == "true" {
		log.Printf("[agent-gateway] hold sweeper not started: AUTHSEC_DISABLE_GATEWAY_HOLD_SWEEP=true")
		return
	}
	s := AgentGatewayServiceFor(db)
	for {
		if _, err := s.SweepExpiredHolds(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[agent-gateway] hold sweep: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
	}
}
