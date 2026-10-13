package services

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/authsec-ai/authsec/internal/awsbroker"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// R3 runtime decisions (SPEC-iga-phase3-policy.md §12.4; requirements R-02,
// R-03, R-05, R-06, R-07, R-09, R-11, R-08 via DECISION R2-1; DECISION R3-3
// .. R3-10, R3-12, R3-14 in internal/igagov/r3.go).
//
//	decide    agent (delegated JWT-SVID) -> allow | deny | hold, one record per (agent, idempotency_key)
//	redeem    the PEP spends an allow once: token, arguments digest, tool, action and target must match
//	outcome   the agent reports what happened (tool / AWS), apart from AuthSec's decision; budgets settle
//	hold      pending --approve (governance:approve, not the initiating human)--> approved --decide again,
//	          same key and digest--> resumed (exactly one allow) ; pending|approved --timeout--> expired ;
//	          pending --reject--> rejected
//	session   an allow of a tool with an aws scope -> sts:AssumeRole credentials, once
//
// The workspace, the agent and the human always come from the verified
// credential (the controller); nothing in a body names them. Another
// workspace's or another agent's decision or hold is 404. Every statement
// runs in a transaction under row-level security for that workspace
// (tenancy.InWorkspace / InWorkspaceRead); only the sweeper's due scans span
// workspaces.

// R3 runtime event names (vocabulary: iga_gov_event_vocabulary.go).
const (
	GovEventRuntimeDecided         = "runtime_decision.decided"
	GovEventRuntimeRedeemed        = "runtime_decision.redeemed"
	GovEventRuntimeOutcome         = "runtime_decision.outcome_reported"
	GovEventRuntimeHoldOpened      = "runtime_hold.opened"
	GovEventRuntimeHoldApproved    = "runtime_hold.approved"
	GovEventRuntimeHoldRejected    = "runtime_hold.rejected"
	GovEventRuntimeHoldExpired     = "runtime_hold.expired"
	GovEventRuntimeHoldResumed     = "runtime_hold.resumed"
	GovEventRuntimeBudgetSwept     = "runtime_budget.swept"
	GovEventRuntimeArgsPruned      = "runtime_arguments.pruned"
	GovEventBrokerSessionIssued    = "broker_session.issued"
	GovEventBrokerSessionFailed    = "broker_session.failed"
	GovEventBrokerSessionRequested = "broker_session.requested"
)

// R3 runtime error codes.
const (
	GovCodeDelegatedAgentRequired = "delegated_agent_required"
	GovCodeIdempotencyConflict    = "idempotency_conflict"
	GovCodeIdempotencyInFlight    = "idempotency_in_flight"
	GovCodeAlreadyResumed         = "already_resumed"
	GovCodeDecisionReplayed       = "decision_replayed"
	GovCodeDecisionExpired        = "decision_expired"
	GovCodeDecisionNotAllow       = "decision_not_allow"
	GovCodeTokenInvalid           = "decision_token_invalid"
	GovCodeBindingMismatch        = "binding_mismatch"
	GovCodeNotRedeemed            = "decision_not_redeemed"
	GovCodeOutcomeRecorded        = "outcome_recorded"
	GovCodeToolNotBrokered        = "tool_not_brokered"
	GovCodeBrokerRoleNotBound     = "broker_role_not_bound"
	GovCodeBrokerUnavailable      = "broker_unavailable"
	GovCodeBrokerFailed           = "broker_failed"
	runtimeCredentialKind         = "delegated_jwt_svid"
	runtimeSettleOverdue          = time.Hour
)

// RuntimeAgent is the verified caller of a runtime route (DECISION R3-3).
type RuntimeAgent struct {
	SpiffeID    string
	ClientID    string
	HumanUserID uuid.UUID
}

// RuntimeDecideRequest is POST /authsec/runtime/decide. Unknown members
// (a prompt, a workspace, an agent) are refused by the controller.
type RuntimeDecideRequest struct {
	Tool            string          `json:"tool"`
	Action          string          `json:"action"`
	Target          string          `json:"target"`
	Arguments       json.RawMessage `json:"arguments,omitempty"`
	ArgumentsDigest string          `json:"arguments_digest,omitempty"`
	SessionID       string          `json:"session_id,omitempty"`
	IdempotencyKey  string          `json:"idempotency_key"`
	Context         map[string]any  `json:"context,omitempty"`
}

// RuntimeDecisionPolicy names the version that decided.
type RuntimeDecisionPolicy struct {
	PolicyID   uuid.UUID `json:"policy_id"`
	VersionID  uuid.UUID `json:"version_id"`
	IntentHash string    `json:"intent_hash"`
}

// RuntimeHoldView is a hold as an agent or approver sees it.
type RuntimeHoldView struct {
	ID                 uuid.UUID  `json:"id"`
	State              string     `json:"state"`
	Reason             string     `json:"reason"`
	ExpiresAt          time.Time  `json:"expires_at"`
	ApprovalValidUntil *time.Time `json:"approval_valid_until,omitempty"`
	ResumedDecisionID  *uuid.UUID `json:"resumed_decision_id,omitempty"`
}

// RuntimeBudgetView is one ledger after the decision.
type RuntimeBudgetView struct {
	Name         string    `json:"name"`
	Unit         string    `json:"unit"`
	Limit        int64     `json:"limit"`
	Reserved     int64     `json:"reserved"`
	Spent        int64     `json:"spent"`
	Remaining    int64     `json:"remaining"`
	WindowEndsAt time.Time `json:"window_ends_at"`
}

// RuntimeDecideResult is the decision as returned to the agent.
type RuntimeDecideResult struct {
	Decision      string                 `json:"decision"`
	DecisionID    uuid.UUID              `json:"decision_id"`
	Reason        string                 `json:"reason"`
	Reasons       json.RawMessage        `json:"reasons"`
	ArgsDigest    string                 `json:"arguments_digest"`
	ExpiresAt     time.Time              `json:"expires_at"`
	DecisionToken string                 `json:"decision_token,omitempty"`
	BindingHash   string                 `json:"binding_hash"`
	Policy        *RuntimeDecisionPolicy `json:"policy,omitempty"`
	ApprovalRef   *uuid.UUID             `json:"approval_ref,omitempty"`
	Hold          *RuntimeHoldView       `json:"hold,omitempty"`
	Budgets       []RuntimeBudgetView    `json:"budgets,omitempty"`
	Replayed      bool                   `json:"replayed"`
	Posture       map[string]any         `json:"posture"`
}

// runtimePosture is DECISION R3-7, returned with every decision (R-05).
func runtimePosture(st models.IGAGovRuntimeSettings) map[string]any {
	return map[string]any{
		"fail_mode":         "closed",
		"on_error":          "deny",
		"cache_ttl_seconds": st.DecisionTTLSeconds,
		"single_use":        true,
		"outage":            "a 5xx, a timeout or runtime_unavailable means deny; never proceed without an allow",
		"revocation": "a new approved version, a paused or archived policy, a rejected or expired hold and a revoked " +
			"delegation token apply at the next decide; an allow already issued stays redeemable until expires_at",
		"enforcement": "advisory unless GET /api/iga/v1/policy/runtime/coverage reports enforced for the gateway",
	}
}

type runtimeGov struct {
	policy  models.IGAGovPolicy
	version models.IGAGovRuntimeVersion
	intent  *igagov.RuntimeIntent
}

// governing are the approved runtime versions of active runtime policies
// that govern the agent (DECISION R3-6: more than one is a conflict).
func (s *GovR3) governing(tx *gorm.DB, ws uuid.UUID, ag RuntimeAgent) ([]runtimeGov, error) {
	var vs []models.IGAGovRuntimeVersion
	if err := tx.Table("iga_gov_runtime_version v").Select("v.*").
		Joins("JOIN iga_gov_policy p ON p.workspace_id = v.workspace_id AND p.id = v.policy_id").
		Where("v.workspace_id = ? AND v.status = ? AND p.family = ? AND p.lifecycle = ?", ws, runtimeStatusApproved, runtimeFamily, "active").
		Order("v.policy_id").Find(&vs).Error; err != nil {
		return nil, err
	}
	var out []runtimeGov
	for _, v := range vs {
		in, _, _, err := igagov.ParseRuntimeIntent(v.Intent)
		if err != nil {
			// An approved intent this build cannot read governs nothing it
			// can decide; fail closed for its agents is "no policy", so say it.
			log.Printf("[runtime] workspace %s: approved runtime version %s is unreadable: %v", ws, v.ID, err)
			continue
		}
		if !in.MatchesAgent(ag.SpiffeID, ag.ClientID) {
			continue
		}
		var p models.IGAGovPolicy
		if err := tx.Where("workspace_id = ? AND id = ?", ws, v.PolicyID).Take(&p).Error; err != nil {
			return nil, err
		}
		out = append(out, runtimeGov{policy: p, version: v, intent: in})
	}
	return out, nil
}

func newDecisionToken() (token, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	token = "rtd_" + base64.RawURLEncoding.EncodeToString(b)
	return token, r3SHA256(token), nil
}

func tokenMatches(token string, hash *string) bool {
	if hash == nil || token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(r3SHA256(token)), []byte(*hash)) == 1
}

func reasonsJSON(code string, detail map[string]any) json.RawMessage {
	r := map[string]any{"code": code}
	for k, v := range detail {
		r[k] = v
	}
	raw, _ := json.Marshal([]map[string]any{r})
	return raw
}

func validateDecide(req *RuntimeDecideRequest) (digest string, err error) {
	req.Tool, req.Action, req.Target = strings.TrimSpace(req.Tool), strings.TrimSpace(req.Action), strings.TrimSpace(req.Target)
	switch {
	case req.Tool == "" || len(req.Tool) > 200:
		return "", GovBadParam("tool", "tool is required (at most 200 characters).")
	case len(req.Action) > 200:
		return "", GovBadParam("action", "action is at most 200 characters.")
	case len(req.Target) > 1024:
		return "", GovBadParam("target", "target is at most 1024 characters.")
	case req.IdempotencyKey == "" || len(req.IdempotencyKey) > 200:
		return "", GovBadParam("idempotency_key", "idempotency_key is required (1..200 characters).")
	case len(req.SessionID) > 200:
		return "", GovBadParam("session_id", "session_id is at most 200 characters.")
	case len(req.Arguments) > 256*1024:
		return "", GovBadParam("arguments", "arguments are at most 256 KiB; send arguments_digest instead.")
	}
	if len(req.Arguments) > 0 {
		d, err := igagov.DigestArguments(req.Arguments)
		if err != nil {
			return "", GovBadParam("arguments", "arguments must be JSON.")
		}
		if req.ArgumentsDigest != "" && req.ArgumentsDigest != d {
			return "", GovBadParam("arguments_digest", "arguments_digest does not match the arguments.")
		}
		return d, nil
	}
	if !igagov.ValidArgsDigest(req.ArgumentsDigest) {
		return "", GovBadParam("arguments_digest", "Send arguments, or arguments_digest as sha256:<64 hex> of their RFC 8785 form.")
	}
	return req.ArgumentsDigest, nil
}

// Decide is the runtime decision (R-01..R-03, R-05, R-06, R-09, R-11).
func (s *GovR3) Decide(ctx context.Context, ws uuid.UUID, ag RuntimeAgent, req RuntimeDecideRequest) (*RuntimeDecideResult, error) {
	if ag.SpiffeID == "" || ag.HumanUserID == uuid.Nil {
		return nil, govErr(http.StatusForbidden, GovCodeDelegatedAgentRequired,
			"Runtime decisions need a delegated agent credential (an agent acting for a human).", nil)
	}
	digest, err := validateDecide(&req)
	if err != nil {
		return nil, err
	}
	kept, ctxDigest, err := igagov.FilterRuntimeContext(req.Context)
	if err != nil {
		return nil, GovBadParam("context", "context must be a JSON object.")
	}
	ctxRaw, _ := json.Marshal(kept)
	ctxW := inWorkspace(ctx, ws)
	st, err := s.RuntimeSettings(ctxW, ws)
	if err != nil {
		return nil, err
	}
	var argsKept json.RawMessage
	if st.ArgumentRetention == "redacted" && len(req.Arguments) > 0 {
		if argsKept, err = igagov.RedactArguments(req.Arguments, redactKeys(st)); err != nil {
			return nil, GovBadParam("arguments", "arguments must be JSON.")
		}
	}
	var out *RuntimeDecideResult
	for attempt := 0; attempt < 2; attempt++ {
		err = tenancy.InWorkspace(ctxW, s.db, ws, func(tx *gorm.DB) error {
			var first models.IGAGovRuntimeDecision
			ferr := tx.Where("workspace_id = ? AND agent_ref = ? AND idempotency_key = ? AND approval_ref IS NULL",
				ws, ag.SpiffeID, req.IdempotencyKey).Clauses(lockForUpdate()).Take(&first).Error
			if ferr == nil {
				var e error
				out, e = s.replay(ctxW, tx, ws, ag, req, digest, st, &first)
				return e
			}
			if !errors.Is(ferr, gorm.ErrRecordNotFound) {
				return ferr
			}
			base := models.IGAGovRuntimeDecision{ID: uuid.New(), WorkspaceID: ws, AgentRef: ag.SpiffeID, AgentClientID: ag.ClientID,
				HumanUserID: &ag.HumanUserID, CredentialKind: runtimeCredentialKind, Tool: req.Tool, Action: req.Action,
				Target: req.Target, ArgsDigest: digest, ContextDigest: ctxDigest, Context: ctxRaw, ArgsRedacted: argsKept,
				SessionKey: req.SessionID, IdempotencyKey: req.IdempotencyKey}
			var e error
			out, e = s.decideNew(ctxW, tx, ws, ag, st, base)
			return e
		})
		if err != nil && (isUniqueViolation(err, "uq_iga_gov_runtime_decision_idem") || isUniqueViolation(err, "uq_iga_gov_runtime_decision_resume")) {
			// A concurrent decide with the same key won; replay it.
			continue
		}
		break
	}
	if err != nil {
		if isUniqueViolation(err, "uq_iga_gov_runtime_decision_idem") || isUniqueViolation(err, "uq_iga_gov_runtime_decision_resume") {
			return nil, govConflict(GovCodeIdempotencyInFlight, "Another decision with this idempotency_key is in flight; retry.", nil)
		}
		return nil, err
	}
	return out, nil
}

// decideNew decides a first request.
func (s *GovR3) decideNew(ctxW context.Context, tx *gorm.DB, ws uuid.UUID, ag RuntimeAgent, st models.IGAGovRuntimeSettings,
	d models.IGAGovRuntimeDecision) (*RuntimeDecideResult, error) {
	now := s.now()
	d.CreatedAt = now
	d.ExpiresAt = now.Add(time.Duration(st.DecisionTTLSeconds) * time.Second)
	govs, err := s.governing(tx, ws, ag)
	if err != nil {
		return nil, err
	}
	deny := func(code string, detail map[string]any) (*RuntimeDecideResult, error) {
		d.Decision, d.ReasonCode, d.Reasons = igagov.RuntimeDeny, code, reasonsJSON(code, detail)
		return s.insertDecision(tx, ws, d, "", nil, st, nil)
	}
	switch len(govs) {
	case 0:
		return deny(igagov.RuntimeReasonNoPolicy, map[string]any{"message": "no approved, active runtime policy governs this agent (default deny)"})
	case 1:
	default:
		ids := make([]string, 0, len(govs))
		for _, g := range govs {
			ids = append(ids, g.policy.ID.String())
		}
		return deny(igagov.RuntimeReasonPolicyConflict, map[string]any{"policy_ids": ids,
			"message": "more than one runtime policy governs this agent; AuthSec fails closed (DECISION R3-6)"})
	}
	g := govs[0]
	d.PolicyID, d.VersionID, d.IntentHash = &g.policy.ID, &g.version.ID, &g.version.IntentHash
	v := g.intent.EvaluateTool(d.Tool, d.Action, d.Target)
	switch v.Decision {
	case igagov.RuntimeDeny:
		return deny(v.Reason, v.Detail)
	case igagov.RuntimeHold:
		d.Decision, d.ReasonCode = igagov.RuntimeHold, v.Reason
		d.ExpiresAt = now.Add(time.Duration(st.HoldTimeoutMinutes) * time.Minute)
		d.Reasons = reasonsJSON(v.Reason, map[string]any{"tool": d.Tool, "approval_reason": v.Tool.ApprovalReason})
		h := models.IGAGovRuntimeHold{ID: uuid.New(), WorkspaceID: ws, DecisionID: d.ID, PolicyID: g.policy.ID, VersionID: g.version.ID,
			AgentRef: d.AgentRef, HumanUserID: ag.HumanUserID, Tool: d.Tool, Action: d.Action, Target: d.Target, ArgsDigest: d.ArgsDigest,
			IdempotencyKey: d.IdempotencyKey, Reason: v.Tool.ApprovalReason, State: models.RuntimeHoldPending, ExpiresAt: d.ExpiresAt,
			CreatedAt: now, UpdatedAt: now}
		return s.insertDecision(tx, ws, d, "", nil, st, &h)
	}
	if len(v.Budgets) > 0 && d.SessionKey == "" {
		return deny(igagov.RuntimeReasonSessionRequired, map[string]any{"message": "this tool is budgeted per session; send session_id"})
	}
	if err := tx.SavePoint("r3budget").Error; err != nil {
		return nil, err
	}
	res, code, detail, err := s.reserve(ctxW, tx, ws, g, d.AgentRef, d.SessionKey, v.Budgets, v.Tool, now)
	if err != nil {
		return nil, err
	}
	if code != "" {
		if err := tx.RollbackTo("r3budget").Error; err != nil {
			return nil, err
		}
		return deny(code, detail)
	}
	d.Decision, d.ReasonCode, d.Reasons = igagov.RuntimeAllow, igagov.RuntimeReasonAllowed, reasonsJSON(igagov.RuntimeReasonAllowed, nil)
	token, hash, err := newDecisionToken()
	if err != nil {
		return nil, err
	}
	d.TokenHash = &hash
	return s.insertDecision(tx, ws, d, token, res, st, nil)
}

type runtimeReservation struct {
	budgetID uuid.UUID
	amount   int64
}

// reserve reserves every applicable budget atomically (R-09, DECISION R3-9):
// one UPDATE per ledger whose WHERE carries the limit. A refusal returns its
// reason code; the caller rolls the savepoint back.
func (s *GovR3) reserve(ctxW context.Context, tx *gorm.DB, ws uuid.UUID, g runtimeGov, agentRef, session string,
	budgets []igagov.RuntimeBudget, tool *igagov.RuntimeTool, now time.Time) ([]runtimeReservation, string, map[string]any, error) {
	var out []runtimeReservation
	for _, b := range budgets {
		amt := igagov.BudgetReservation(b, tool)
		if amt == 0 {
			continue
		}
		ledger := models.IGAGovRuntimeBudget{ID: uuid.New(), WorkspaceID: ws, PolicyID: g.policy.ID, VersionID: g.version.ID,
			AgentRef: agentRef, SessionKey: session, BudgetKey: b.Name, Unit: b.Unit, LimitAmount: b.Limit,
			WindowEndsAt: now.Add(time.Duration(b.WindowMinutes) * time.Minute), CreatedAt: now, UpdatedAt: now}
		if err := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "workspace_id"}, {Name: "policy_id"},
			{Name: "agent_ref"}, {Name: "session_key"}, {Name: "budget_key"}}, DoNothing: true}).Create(&ledger).Error; err != nil {
			return nil, "", nil, err
		}
		var cur models.IGAGovRuntimeBudget
		if err := tx.Where("workspace_id = ? AND policy_id = ? AND agent_ref = ? AND session_key = ? AND budget_key = ?",
			ws, g.policy.ID, agentRef, session, b.Name).Take(&cur).Error; err != nil {
			return nil, "", nil, err
		}
		if !now.Before(cur.WindowEndsAt) {
			return nil, igagov.RuntimeReasonSessionExpired, map[string]any{"budget": b.Name, "window_ends_at": cur.WindowEndsAt,
				"message": "this session's budget window has ended; start a new session_id"}, nil
		}
		r := tenancy.GormExec(ctxW, tx, `UPDATE iga_gov_runtime_budget SET reserved = reserved + $2, updated_at = now()
		     WHERE workspace_id = $1 AND id = $3 AND reserved + spent + $2 <= limit_amount AND window_ends_at > now()`, amt, cur.ID)
		if r.Error != nil {
			return nil, "", nil, r.Error
		}
		if r.RowsAffected != 1 {
			return nil, igagov.RuntimeReasonBudgetExhausted, map[string]any{"budget": b.Name, "unit": cur.Unit, "limit": cur.LimitAmount,
				"reserved": cur.Reserved, "spent": cur.Spent, "requested": amt}, nil
		}
		out = append(out, runtimeReservation{budgetID: cur.ID, amount: amt})
	}
	return out, "", nil, nil
}

// insertDecision binds, stores and reports one decision (and its hold or
// budget entries).
func (s *GovR3) insertDecision(tx *gorm.DB, ws uuid.UUID, d models.IGAGovRuntimeDecision, token string,
	res []runtimeReservation, st models.IGAGovRuntimeSettings, hold *models.IGAGovRuntimeHold) (*RuntimeDecideResult, error) {
	if d.Reasons == nil {
		d.Reasons = json.RawMessage(`[]`)
	}
	if d.Context == nil {
		d.Context = json.RawMessage(`{}`)
	}
	b := igagov.RuntimeBinding{DecisionID: d.ID.String(), WorkspaceRef: GovWorkspaceRef(ws), AgentRef: d.AgentRef,
		Tool: d.Tool, Action: d.Action, Target: d.Target, ArgsDigest: d.ArgsDigest, Decision: d.Decision, ExpiresAt: d.ExpiresAt}
	if d.HumanUserID != nil {
		b.HumanUserID = d.HumanUserID.String()
	}
	if d.VersionID != nil {
		b.VersionID, b.IntentHash = d.VersionID.String(), *d.IntentHash
	}
	if d.ApprovalRef != nil {
		b.ApprovalRef = d.ApprovalRef.String()
	}
	d.ExpiresAt = d.ExpiresAt.UTC().Truncate(time.Microsecond)
	b.ExpiresAt = d.ExpiresAt
	h, err := b.Hash()
	if err != nil {
		return nil, err
	}
	d.BindingHash = h
	if err := tx.Create(&d).Error; err != nil {
		return nil, err
	}
	for _, r := range res {
		e := models.IGAGovRuntimeBudgetEntry{ID: uuid.New(), WorkspaceID: ws, BudgetID: r.budgetID, DecisionID: d.ID,
			ReservedAmount: r.amount, State: "reserved"}
		if err := tx.Create(&e).Error; err != nil {
			return nil, err
		}
	}
	if hold != nil {
		if err := tx.Create(hold).Error; err != nil {
			return nil, err
		}
	}
	payload := map[string]any{"decision_id": d.ID, "decision": d.Decision, "reason": d.ReasonCode, "agent_ref": d.AgentRef,
		"agent_client_id": d.AgentClientID, "human_user_id": d.HumanUserID, "tool": d.Tool, "action": d.Action, "target": d.Target,
		"args_digest": d.ArgsDigest, "binding_hash": d.BindingHash, "expires_at": d.ExpiresAt, "session_id": d.SessionKey,
		"approval_ref": d.ApprovalRef, "reserved": len(res)}
	if err := s.event(tx, ws, GovEventRuntimeDecided, nil, d.PolicyID, d.VersionID, payload); err != nil {
		return nil, err
	}
	if hold != nil {
		if err := s.event(tx, ws, GovEventRuntimeHoldOpened, nil, d.PolicyID, d.VersionID, map[string]any{"hold_id": hold.ID,
			"decision_id": d.ID, "tool": d.Tool, "agent_ref": d.AgentRef, "human_user_id": hold.HumanUserID, "expires_at": hold.ExpiresAt}); err != nil {
			return nil, err
		}
	}
	out := s.resultOf(d, st, hold)
	out.DecisionToken = token
	if out.Budgets, err = s.budgetViews(tx, ws, res); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *GovR3) resultOf(d models.IGAGovRuntimeDecision, st models.IGAGovRuntimeSettings, hold *models.IGAGovRuntimeHold) *RuntimeDecideResult {
	out := &RuntimeDecideResult{Decision: d.Decision, DecisionID: d.ID, Reason: d.ReasonCode, Reasons: d.Reasons, ArgsDigest: d.ArgsDigest,
		ExpiresAt: d.ExpiresAt, BindingHash: d.BindingHash, ApprovalRef: d.ApprovalRef, Posture: runtimePosture(st)}
	if d.VersionID != nil {
		out.Policy = &RuntimeDecisionPolicy{PolicyID: *d.PolicyID, VersionID: *d.VersionID, IntentHash: *d.IntentHash}
	}
	if hold != nil {
		out.Hold = holdView(*hold)
	}
	return out
}

func holdView(h models.IGAGovRuntimeHold) *RuntimeHoldView {
	return &RuntimeHoldView{ID: h.ID, State: h.State, Reason: h.Reason, ExpiresAt: h.ExpiresAt,
		ApprovalValidUntil: h.ApprovalValidUntil, ResumedDecisionID: h.ResumedDecisionID}
}

func (s *GovR3) budgetViews(tx *gorm.DB, ws uuid.UUID, res []runtimeReservation) ([]RuntimeBudgetView, error) {
	if len(res) == 0 {
		return nil, nil
	}
	ids := make([]uuid.UUID, 0, len(res))
	for _, r := range res {
		ids = append(ids, r.budgetID)
	}
	var ls []models.IGAGovRuntimeBudget
	if err := tx.Where("workspace_id = ? AND id IN ?", ws, ids).Order("budget_key").Find(&ls).Error; err != nil {
		return nil, err
	}
	out := make([]RuntimeBudgetView, 0, len(ls))
	for _, l := range ls {
		out = append(out, RuntimeBudgetView{Name: l.BudgetKey, Unit: l.Unit, Limit: l.LimitAmount, Reserved: l.Reserved, Spent: l.Spent,
			Remaining: l.LimitAmount - l.Reserved - l.Spent, WindowEndsAt: l.WindowEndsAt})
	}
	return out, nil
}

// expireHoldIfDue moves a pending hold past its timeout, or an approved one
// past its approval validity, to expired (lazily; the sweeper does the rest).
func (s *GovR3) expireHoldIfDue(tx *gorm.DB, ws uuid.UUID, h *models.IGAGovRuntimeHold, now time.Time) error {
	due := (h.State == models.RuntimeHoldPending && now.After(h.ExpiresAt)) ||
		(h.State == models.RuntimeHoldApproved && h.ApprovalValidUntil != nil && now.After(*h.ApprovalValidUntil))
	if !due {
		return nil
	}
	from := h.State
	if err := tx.Model(&models.IGAGovRuntimeHold{}).Where("workspace_id = ? AND id = ? AND state = ?", ws, h.ID, from).
		Updates(map[string]any{"state": models.RuntimeHoldExpired, "updated_at": now}).Error; err != nil {
		return err
	}
	h.State = models.RuntimeHoldExpired
	return s.event(tx, ws, GovEventRuntimeHoldExpired, nil, &h.PolicyID, &h.VersionID, map[string]any{"hold_id": h.ID,
		"decision_id": h.DecisionID, "from": from})
}

// replay answers a request whose (agent, idempotency_key) was decided before:
// the same decision, never a new authorization -- except the one resume of
// an approved hold (DECISION R3-5, R3-8).
func (s *GovR3) replay(ctxW context.Context, tx *gorm.DB, ws uuid.UUID, ag RuntimeAgent, req RuntimeDecideRequest, digest string,
	st models.IGAGovRuntimeSettings, first *models.IGAGovRuntimeDecision) (*RuntimeDecideResult, error) {
	if first.ArgsDigest != digest || first.Tool != req.Tool || first.Action != req.Action || first.Target != req.Target || first.SessionKey != req.SessionID {
		return nil, govConflict(GovCodeIdempotencyConflict,
			"This idempotency_key was decided for different arguments, tool, action, target or session; nothing is substituted.",
			map[string]any{"decision_id": first.ID})
	}
	if first.HumanUserID == nil || *first.HumanUserID != ag.HumanUserID {
		return nil, govConflict(GovCodeIdempotencyConflict, "This idempotency_key was decided for another initiating human.", nil)
	}
	if first.Decision != igagov.RuntimeHold {
		out := s.resultOf(*first, st, nil)
		out.Replayed = true
		return out, nil
	}
	var h models.IGAGovRuntimeHold
	if err := tx.Where("workspace_id = ? AND decision_id = ?", ws, first.ID).Clauses(lockForUpdate()).Take(&h).Error; err != nil {
		return nil, err
	}
	now := s.now()
	if err := s.expireHoldIfDue(tx, ws, &h, now); err != nil {
		return nil, err
	}
	out := s.resultOf(*first, st, &h)
	out.Replayed = true
	switch h.State {
	case models.RuntimeHoldPending:
		return out, nil
	case models.RuntimeHoldRejected:
		out.Decision, out.Reason = igagov.RuntimeDeny, igagov.RuntimeReasonApprovalRejected
		out.Reasons = reasonsJSON(igagov.RuntimeReasonApprovalRejected, map[string]any{"decision_reason": h.DecisionReason})
		return out, nil
	case models.RuntimeHoldExpired, models.RuntimeHoldCancelled:
		out.Decision, out.Reason = igagov.RuntimeDeny, igagov.RuntimeReasonApprovalExpired
		out.Reasons = reasonsJSON(igagov.RuntimeReasonApprovalExpired, nil)
		return out, nil
	case models.RuntimeHoldResumed:
		return nil, govConflict(GovCodeAlreadyResumed, "The approved operation was already resumed; it executes at most once.",
			map[string]any{"hold_id": h.ID, "resumed_decision_id": h.ResumedDecisionID})
	}
	// Approved: the one resume. The approval binds the version that held the
	// request; it must still be the approved version of an active policy.
	govs, err := s.governing(tx, ws, ag)
	if err != nil {
		return nil, err
	}
	var g *runtimeGov
	for i := range govs {
		if govs[i].version.ID == h.VersionID {
			g = &govs[i]
		}
	}
	d := models.IGAGovRuntimeDecision{ID: uuid.New(), WorkspaceID: ws, AgentRef: first.AgentRef, AgentClientID: ag.ClientID,
		HumanUserID: &ag.HumanUserID, CredentialKind: runtimeCredentialKind, Tool: first.Tool, Action: first.Action, Target: first.Target,
		ArgsDigest: first.ArgsDigest, ContextDigest: first.ContextDigest, Context: first.Context, SessionKey: first.SessionKey,
		IdempotencyKey: first.IdempotencyKey, ApprovalRef: &h.ID, CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(st.DecisionTTLSeconds) * time.Second)}
	if h.ApprovalValidUntil != nil && h.ApprovalValidUntil.Before(d.ExpiresAt) {
		d.ExpiresAt = *h.ApprovalValidUntil
	}
	resume := func(r *RuntimeDecideResult, err error) (*RuntimeDecideResult, error) {
		if err != nil {
			return nil, err
		}
		if err := tx.Model(&models.IGAGovRuntimeHold{}).Where("workspace_id = ? AND id = ? AND state = ?", ws, h.ID, models.RuntimeHoldApproved).
			Updates(map[string]any{"state": models.RuntimeHoldResumed, "resumed_decision_id": d.ID, "resumed_at": now, "updated_at": now}).Error; err != nil {
			return nil, err
		}
		h.State, h.ResumedDecisionID, h.ResumedAt = models.RuntimeHoldResumed, &d.ID, &now
		if err := s.event(tx, ws, GovEventRuntimeHoldResumed, nil, &h.PolicyID, &h.VersionID, map[string]any{"hold_id": h.ID,
			"decision_id": d.ID, "decision": d.Decision, "reason": d.ReasonCode}); err != nil {
			return nil, err
		}
		r.Hold = holdView(h)
		return r, nil
	}
	if g == nil || len(govs) != 1 {
		d.Decision, d.ReasonCode = igagov.RuntimeDeny, igagov.RuntimeReasonApprovalExpired
		d.Reasons = reasonsJSON(igagov.RuntimeReasonApprovalExpired, map[string]any{
			"message": "the policy version that held this request is no longer the approved version of an active policy"})
		if g != nil {
			d.PolicyID, d.VersionID, d.IntentHash = &g.policy.ID, &g.version.ID, &g.version.IntentHash
		}
		return resume(s.insertDecision(tx, ws, d, "", nil, st, nil))
	}
	d.PolicyID, d.VersionID, d.IntentHash = &g.policy.ID, &g.version.ID, &g.version.IntentHash
	v := g.intent.EvaluateTool(d.Tool, d.Action, d.Target)
	if v.Decision == igagov.RuntimeDeny {
		d.Decision, d.ReasonCode, d.Reasons = igagov.RuntimeDeny, v.Reason, reasonsJSON(v.Reason, v.Detail)
		return resume(s.insertDecision(tx, ws, d, "", nil, st, nil))
	}
	if len(v.Budgets) > 0 && d.SessionKey == "" {
		d.Decision, d.ReasonCode = igagov.RuntimeDeny, igagov.RuntimeReasonSessionRequired
		d.Reasons = reasonsJSON(d.ReasonCode, nil)
		return resume(s.insertDecision(tx, ws, d, "", nil, st, nil))
	}
	if err := tx.SavePoint("r3resume").Error; err != nil {
		return nil, err
	}
	res, code, detail, err := s.reserve(ctxW, tx, ws, *g, d.AgentRef, d.SessionKey, v.Budgets, v.Tool, now)
	if err != nil {
		return nil, err
	}
	if code != "" {
		if err := tx.RollbackTo("r3resume").Error; err != nil {
			return nil, err
		}
		d.Decision, d.ReasonCode, d.Reasons = igagov.RuntimeDeny, code, reasonsJSON(code, detail)
		return resume(s.insertDecision(tx, ws, d, "", nil, st, nil))
	}
	token, hash, err := newDecisionToken()
	if err != nil {
		return nil, err
	}
	d.Decision, d.ReasonCode, d.TokenHash = igagov.RuntimeAllow, igagov.RuntimeReasonApproved, &hash
	d.Reasons = reasonsJSON(igagov.RuntimeReasonApproved, map[string]any{"hold_id": h.ID, "approved_by": h.DecidedBy})
	return resume(s.insertDecision(tx, ws, d, token, res, st, nil))
}

/* ---------------------------------------------------------------------------- */
/*                               Redeem and outcome                             */
/* ---------------------------------------------------------------------------- */

// RuntimeRedeemRequest is POST /authsec/runtime/decisions/:id/redeem.
type RuntimeRedeemRequest struct {
	DecisionToken   string `json:"decision_token"`
	ArgumentsDigest string `json:"arguments_digest"`
	Tool            string `json:"tool"`
	Action          string `json:"action"`
	Target          string `json:"target"`
}

// loadAgentDecision loads the caller's own decision (another agent's or
// workspace's is 404).
func (s *GovR3) loadAgentDecision(tx *gorm.DB, ws uuid.UUID, ag RuntimeAgent, id uuid.UUID) (*models.IGAGovRuntimeDecision, error) {
	var d models.IGAGovRuntimeDecision
	if err := tx.Where("workspace_id = ? AND id = ? AND agent_ref = ?", ws, id, ag.SpiffeID).Clauses(lockForUpdate()).Take(&d).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, GovNotFound()
		}
		return nil, err
	}
	return &d, nil
}

func (s *GovR3) checkSpendable(d *models.IGAGovRuntimeDecision, token string, now time.Time) error {
	if d.Decision != igagov.RuntimeAllow {
		return govConflict(GovCodeDecisionNotAllow, "Only an allow can be redeemed.", map[string]any{"decision": d.Decision})
	}
	if !tokenMatches(token, d.TokenHash) {
		return govErr(http.StatusForbidden, GovCodeTokenInvalid, "The decision token does not match.", nil)
	}
	if d.ConsumedAt != nil {
		return govConflict(GovCodeDecisionReplayed, "The decision was already used; it is single-use.",
			map[string]any{"consumed_at": d.ConsumedAt, "consumed_by": d.ConsumedBy})
	}
	if !now.Before(d.ExpiresAt) {
		return govConflict(GovCodeDecisionExpired, "The decision expired; decide again.", map[string]any{"expires_at": d.ExpiresAt})
	}
	return nil
}

// consume marks an allow used, once (the WHERE is the guard; the 062
// trigger refuses a second consumption as well).
func (s *GovR3) consume(ctxW context.Context, tx *gorm.DB, d *models.IGAGovRuntimeDecision, by string) error {
	r := tenancy.GormExec(ctxW, tx, `UPDATE iga_gov_runtime_decision SET consumed_at = now(), consumed_by = $2
	     WHERE workspace_id = $1 AND id = $3 AND consumed_at IS NULL AND expires_at > now() AND decision = 'allow'`, by, d.ID)
	if r.Error != nil {
		return r.Error
	}
	if r.RowsAffected != 1 {
		return govConflict(GovCodeDecisionReplayed, "The decision was already used or expired; it is single-use.", nil)
	}
	now := s.now()
	d.ConsumedAt, d.ConsumedBy = &now, &by
	return nil
}

// Redeem spends an allow once (R-03): the PEP presents the token and what it
// is about to execute; anything different is 409 binding_mismatch.
func (s *GovR3) Redeem(ctx context.Context, ws uuid.UUID, ag RuntimeAgent, id uuid.UUID, req RuntimeRedeemRequest) (*models.IGAGovRuntimeDecision, error) {
	ctxW := inWorkspace(ctx, ws)
	var out *models.IGAGovRuntimeDecision
	err := tenancy.InWorkspace(ctxW, s.db, ws, func(tx *gorm.DB) error {
		d, err := s.loadAgentDecision(tx, ws, ag, id)
		if err != nil {
			return err
		}
		if err := s.checkSpendable(d, req.DecisionToken, s.now()); err != nil {
			return err
		}
		var mism []string
		if req.ArgumentsDigest != d.ArgsDigest {
			mism = append(mism, "arguments_digest")
		}
		if strings.TrimSpace(req.Tool) != d.Tool {
			mism = append(mism, "tool")
		}
		if strings.TrimSpace(req.Action) != d.Action {
			mism = append(mism, "action")
		}
		if strings.TrimSpace(req.Target) != d.Target {
			mism = append(mism, "target")
		}
		if len(mism) > 0 {
			return govConflict(GovCodeBindingMismatch, "What is being executed is not what was decided.", map[string]any{"mismatched": mism})
		}
		if err := s.consume(ctxW, tx, d, "redeem"); err != nil {
			return err
		}
		out = d
		return s.event(tx, ws, GovEventRuntimeRedeemed, nil, d.PolicyID, d.VersionID, map[string]any{"decision_id": d.ID,
			"agent_ref": d.AgentRef, "binding_hash": d.BindingHash, "approval_ref": d.ApprovalRef})
	})
	return out, err
}

// RuntimeAWSOutcome is what the agent reports AWS answered (agent-reported,
// unverified; DECISION R3-10).
type RuntimeAWSOutcome struct {
	Service   string `json:"service,omitempty"`
	Operation string `json:"operation,omitempty"`
	Region    string `json:"region,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	Status    string `json:"status,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// RuntimeOutcomeRequest is POST /authsec/runtime/decisions/:id/outcome.
type RuntimeOutcomeRequest struct {
	DecisionToken string             `json:"decision_token"`
	ToolOutcome   string             `json:"tool_outcome"`
	AWSOutcome    *RuntimeAWSOutcome `json:"aws_outcome,omitempty"`
	ActualCost    *int64             `json:"actual_cost,omitempty"`
}

// ReportOutcome records what happened (R-07) and settles the decision's
// budget reservations (R-09). not_executed releases; succeeded, failed and
// unknown settle (unknown at the reservation); a final report after unknown
// is recorded without settling again.
func (s *GovR3) ReportOutcome(ctx context.Context, ws uuid.UUID, ag RuntimeAgent, id uuid.UUID, req RuntimeOutcomeRequest) (*models.IGAGovRuntimeDecision, error) {
	switch req.ToolOutcome {
	case "succeeded", "failed", "not_executed", "unknown":
	default:
		return nil, GovBadParam("tool_outcome", "tool_outcome is succeeded, failed, not_executed or unknown.")
	}
	if req.ActualCost != nil && (*req.ActualCost < 0 || *req.ActualCost > 1_000_000_000_000) {
		return nil, GovBadParam("actual_cost", "actual_cost is 0..1e12.")
	}
	var awsRaw json.RawMessage
	if a := req.AWSOutcome; a != nil {
		for _, f := range []string{a.Service, a.Operation, a.Region, a.RequestID, a.Status, a.ErrorCode} {
			if len(f) > 256 {
				return nil, GovBadParam("aws_outcome", "aws_outcome fields are at most 256 characters.")
			}
		}
		awsRaw, _ = json.Marshal(a)
	}
	ctxW := inWorkspace(ctx, ws)
	var out *models.IGAGovRuntimeDecision
	err := tenancy.InWorkspace(ctxW, s.db, ws, func(tx *gorm.DB) error {
		d, err := s.loadAgentDecision(tx, ws, ag, id)
		if err != nil {
			return err
		}
		if d.Decision != igagov.RuntimeAllow {
			return govConflict(GovCodeDecisionNotAllow, "Outcomes are reported for allows only.", map[string]any{"decision": d.Decision})
		}
		if !tokenMatches(req.DecisionToken, d.TokenHash) {
			return govErr(http.StatusForbidden, GovCodeTokenInvalid, "The decision token does not match.", nil)
		}
		if d.ToolOutcome != nil && *d.ToolOutcome != "unknown" {
			return govConflict(GovCodeOutcomeRecorded, "The outcome was already reported.", map[string]any{"tool_outcome": *d.ToolOutcome})
		}
		firstReport := d.ToolOutcome == nil
		if d.ConsumedAt == nil {
			if req.ToolOutcome != "not_executed" {
				return govConflict(GovCodeNotRedeemed, "Redeem the decision before executing; only not_executed can be reported for an unredeemed allow.", nil)
			}
			// Close it: an allow reported not executed can no longer be spent.
			if s.now().Before(d.ExpiresAt) {
				if err := s.consume(ctxW, tx, d, "redeem"); err != nil {
					return err
				}
			}
		}
		settled := []map[string]any{}
		if firstReport {
			if settled, err = s.settle(ctxW, tx, ws, d.ID, req.ToolOutcome, req.ActualCost); err != nil {
				return err
			}
		}
		now := s.now()
		src := "agent_reported"
		upd := map[string]any{"tool_outcome": req.ToolOutcome, "outcome_source": src, "outcome_reported_at": now}
		if awsRaw != nil {
			upd["aws_outcome"] = awsRaw
		}
		if req.ActualCost != nil {
			upd["actual_cost"] = *req.ActualCost
		}
		if err := tx.Model(&models.IGAGovRuntimeDecision{}).Where("workspace_id = ? AND id = ?", ws, d.ID).Updates(upd).Error; err != nil {
			return err
		}
		to := req.ToolOutcome
		d.ToolOutcome, d.OutcomeSource, d.OutcomeReportedAt, d.AWSOutcome, d.ActualCost = &to, &src, &now, awsRaw, req.ActualCost
		out = d
		return s.event(tx, ws, GovEventRuntimeOutcome, nil, d.PolicyID, d.VersionID, map[string]any{"decision_id": d.ID,
			"authsec_decision": d.Decision, "tool_outcome": req.ToolOutcome, "aws_outcome": req.AWSOutcome,
			"actual_cost": req.ActualCost, "source": src, "agent_ref": d.AgentRef, "settled": settled})
	})
	return out, err
}

// settle settles (or releases) every open reservation of a decision.
func (s *GovR3) settle(ctxW context.Context, tx *gorm.DB, ws, decisionID uuid.UUID, outcome string, actual *int64) ([]map[string]any, error) {
	var es []models.IGAGovRuntimeBudgetEntry
	if err := tx.Where("workspace_id = ? AND decision_id = ? AND state = ?", ws, decisionID, "reserved").
		Clauses(lockForUpdate()).Order("id").Find(&es).Error; err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, e := range es {
		var l models.IGAGovRuntimeBudget
		if err := tx.Where("workspace_id = ? AND id = ?", ws, e.BudgetID).Take(&l).Error; err != nil {
			return nil, err
		}
		spend, state := e.ReservedAmount, "settled"
		switch {
		case outcome == "not_executed":
			spend, state = 0, "released"
		case outcome == "unknown":
		case l.Unit == igagov.BudgetUnitCalls:
			spend = 1
		case actual != nil:
			spend = *actual
		}
		var overrun int64
		if spend > e.ReservedAmount {
			overrun = spend - e.ReservedAmount
		}
		r := tenancy.GormExec(ctxW, tx, `UPDATE iga_gov_runtime_budget SET reserved = reserved - $2, spent = spent + $3, updated_at = now()
		     WHERE workspace_id = $1 AND id = $4 AND reserved >= $2`, e.ReservedAmount, spend, e.BudgetID)
		if r.Error != nil {
			return nil, r.Error
		}
		if r.RowsAffected != 1 {
			return nil, fmt.Errorf("budget %s: reservation %s is not held", e.BudgetID, e.ID)
		}
		now := s.now()
		upd := map[string]any{"state": state, "settled_at": now, "overrun": overrun}
		if state == "settled" {
			upd["settled_amount"] = spend
		}
		if err := tx.Model(&models.IGAGovRuntimeBudgetEntry{}).Where("workspace_id = ? AND id = ?", ws, e.ID).Updates(upd).Error; err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"budget": l.BudgetKey, "state": state, "reserved": e.ReservedAmount, "spent": spend, "overrun": overrun})
	}
	return out, nil
}

/* ---------------------------------------------------------------------------- */
/*                                     Holds                                    */
/* ---------------------------------------------------------------------------- */

// AgentHold is GET /authsec/runtime/holds/:id for the agent that is held.
func (s *GovR3) AgentHold(ctx context.Context, ws uuid.UUID, ag RuntimeAgent, id uuid.UUID) (*RuntimeHoldView, error) {
	var out *RuntimeHoldView
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var h models.IGAGovRuntimeHold
		if err := tx.Where("workspace_id = ? AND id = ? AND agent_ref = ?", ws, id, ag.SpiffeID).Clauses(lockForUpdate()).Take(&h).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return GovNotFound()
			}
			return err
		}
		if err := s.expireHoldIfDue(tx, ws, &h, s.now()); err != nil {
			return err
		}
		out = holdView(h)
		return nil
	})
	return out, err
}

// ListHolds lists holds (governance:read), newest first; due holds are
// shown expired.
func (s *GovR3) ListHolds(ctx context.Context, ws uuid.UUID, state string, limit int) ([]models.IGAGovRuntimeHold, error) {
	if limit <= 0 || limit > MaxGovPage {
		limit = MaxGovPage
	}
	out := []models.IGAGovRuntimeHold{}
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		q := tx.Where("workspace_id = ?", ws)
		if state != "" {
			q = q.Where("state = ?", state)
		}
		return q.Order("created_at DESC").Limit(limit).Find(&out).Error
	}); err != nil {
		return nil, err
	}
	now := s.now()
	for i := range out {
		h := &out[i]
		if (h.State == models.RuntimeHoldPending && now.After(h.ExpiresAt)) ||
			(h.State == models.RuntimeHoldApproved && h.ApprovalValidUntil != nil && now.After(*h.ApprovalValidUntil)) {
			h.State = models.RuntimeHoldExpired
		}
	}
	return out, nil
}

// GetHold reads one hold (governance:read).
func (s *GovR3) GetHold(ctx context.Context, ws, id uuid.UUID) (*models.IGAGovRuntimeHold, error) {
	var h models.IGAGovRuntimeHold
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Where("workspace_id = ? AND id = ?", ws, id).Take(&h).Error
	}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, GovNotFound()
		}
		return nil, err
	}
	return &h, nil
}

// DecideHold approves or rejects a pending hold (governance:approve, never
// the initiating human; DECISION R3-8).
func (s *GovR3) DecideHold(ctx context.Context, ws, approver, id uuid.UUID, approve bool, reason string) (*models.IGAGovRuntimeHold, error) {
	reason = strings.TrimSpace(reason)
	if !approve && reason == "" {
		return nil, GovBadParam("reason", "A rejection needs a reason.")
	}
	var out models.IGAGovRuntimeHold
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		if err := tx.Where("workspace_id = ? AND id = ?", ws, id).Clauses(lockForUpdate()).Take(&out).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return GovNotFound()
			}
			return err
		}
		now := s.now()
		if err := s.expireHoldIfDue(tx, ws, &out, now); err != nil {
			return err
		}
		if out.State != models.RuntimeHoldPending {
			return govConflict(GovCodeNotPending, "Only a pending hold can be decided.", map[string]any{"state": out.State})
		}
		if out.HumanUserID == approver {
			return govErr(http.StatusForbidden, GovCodeSelfApproval, "You initiated this operation; another approver must decide.", nil)
		}
		ok, err := WorkspaceUserHoldsPermission(tx, ws, approver, "governance", "approve")
		if err != nil {
			return err
		}
		if !ok {
			return GovForbidden("governance:approve is required.")
		}
		st, err := s.runtimeSettingsTx(tx, ws)
		if err != nil {
			return err
		}
		upd := map[string]any{"decided_by": approver, "decided_at": now, "decision_reason": reason, "updated_at": now}
		event := GovEventRuntimeHoldRejected
		if approve {
			until := now.Add(time.Duration(st.ApprovalValidMinutes) * time.Minute)
			upd["state"], upd["approval_valid_until"] = models.RuntimeHoldApproved, until
			out.State, out.ApprovalValidUntil = models.RuntimeHoldApproved, &until
			event = GovEventRuntimeHoldApproved
		} else {
			upd["state"] = models.RuntimeHoldRejected
			out.State = models.RuntimeHoldRejected
		}
		if err := tx.Model(&models.IGAGovRuntimeHold{}).Where("workspace_id = ? AND id = ?", ws, id).Updates(upd).Error; err != nil {
			return err
		}
		out.DecidedBy, out.DecidedAt, out.DecisionReason = &approver, &now, reason
		return s.event(tx, ws, event, &approver, &out.PolicyID, &out.VersionID, map[string]any{"hold_id": id,
			"decision_id": out.DecisionID, "tool": out.Tool, "agent_ref": out.AgentRef, "human_user_id": out.HumanUserID,
			"args_digest": out.ArgsDigest, "approval_valid_until": out.ApprovalValidUntil, "reason": reason})
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

/* ---------------------------------------------------------------------------- */
/*                               Decisions, budgets                             */
/* ---------------------------------------------------------------------------- */

// RuntimeDecisionFilter filters GET /runtime/decisions.
type RuntimeDecisionFilter struct {
	AgentRef, Tool, Decision string
	Limit                    int
}

// ListDecisions lists decisions (governance:read), newest first.
func (s *GovR3) ListDecisions(ctx context.Context, ws uuid.UUID, f RuntimeDecisionFilter) ([]models.IGAGovRuntimeDecision, error) {
	if f.Limit <= 0 || f.Limit > MaxGovPage {
		f.Limit = MaxGovPage
	}
	out := []models.IGAGovRuntimeDecision{}
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		q := tx.Where("workspace_id = ?", ws)
		if f.AgentRef != "" {
			q = q.Where("agent_ref = ?", f.AgentRef)
		}
		if f.Tool != "" {
			q = q.Where("tool = ?", f.Tool)
		}
		if f.Decision != "" {
			q = q.Where("decision = ?", f.Decision)
		}
		return q.Order("created_at DESC").Limit(f.Limit).Find(&out).Error
	})
	return out, err
}

// GetDecision reads one decision (governance:read).
func (s *GovR3) GetDecision(ctx context.Context, ws, id uuid.UUID) (*models.IGAGovRuntimeDecision, error) {
	var d models.IGAGovRuntimeDecision
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Where("workspace_id = ? AND id = ?", ws, id).Take(&d).Error
	}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, GovNotFound()
		}
		return nil, err
	}
	return &d, nil
}

// ListBudgets lists ledgers (governance:read).
func (s *GovR3) ListBudgets(ctx context.Context, ws uuid.UUID, agentRef, session string, limit int) ([]models.IGAGovRuntimeBudget, error) {
	if limit <= 0 || limit > MaxGovPage {
		limit = MaxGovPage
	}
	out := []models.IGAGovRuntimeBudget{}
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		q := tx.Where("workspace_id = ?", ws)
		if agentRef != "" {
			q = q.Where("agent_ref = ?", agentRef)
		}
		if session != "" {
			q = q.Where("session_key = ?", session)
		}
		return q.Order("updated_at DESC").Limit(limit).Find(&out).Error
	})
	return out, err
}

/* ---------------------------------------------------------------------------- */
/*                               Brokered sessions                              */
/* ---------------------------------------------------------------------------- */

// RuntimeSessionRequest is POST /authsec/runtime/decisions/:id/aws-session.
type RuntimeSessionRequest struct {
	DecisionToken string `json:"decision_token"`
}

// RuntimeSessionResult is the brokered session, credentials included once.
type RuntimeSessionResult struct {
	SessionID       uuid.UUID              `json:"session_id"`
	RoleARN         string                 `json:"role_arn"`
	SessionName     string                 `json:"session_name"`
	SourceIdentity  string                 `json:"source_identity"`
	DurationSeconds int                    `json:"duration_seconds"`
	SessionPolicy   json.RawMessage        `json:"session_policy"`
	Tags            map[string]string      `json:"session_tags"`
	Credentials     *awsbroker.Credentials `json:"credentials"`
	Verified        bool                   `json:"verified_against_aws"`
}

// BrokerSession exchanges an allow of a tool with an aws scope for
// short-lived credentials (R-08, DECISION R3-12). The decision is consumed
// before STS is called (write-ahead session row): a failure spends it, and
// the agent decides again. UNVERIFIED against AWS.
func (s *GovR3) BrokerSession(ctx context.Context, ws uuid.UUID, ag RuntimeAgent, id uuid.UUID, req RuntimeSessionRequest) (*RuntimeSessionResult, error) {
	deps := CurrentRuntimeBrokerDeps()
	if deps == nil || deps.Broker == nil || deps.Inputs == nil {
		return nil, govErr(http.StatusServiceUnavailable, GovCodeBrokerUnavailable,
			"Brokered AWS sessions are not configured on this server (needs Vault and AuthSec's AWS identity).", nil)
	}
	ctxW := inWorkspace(ctx, ws)
	var row models.IGAGovRuntimeBrokerSession
	var role models.IGAGovRuntimeBrokerRole
	var areq awsbroker.Request
	var policyDoc string
	var d *models.IGAGovRuntimeDecision
	err := tenancy.InWorkspace(ctxW, s.db, ws, func(tx *gorm.DB) error {
		var err error
		d, err = s.loadAgentDecision(tx, ws, ag, id)
		if err != nil {
			return err
		}
		if err := s.checkSpendable(d, req.DecisionToken, s.now()); err != nil {
			return err
		}
		var v models.IGAGovRuntimeVersion
		if err := tx.Where("workspace_id = ? AND id = ?", ws, *d.VersionID).Take(&v).Error; err != nil {
			return err
		}
		in, _, _, err := igagov.ParseRuntimeIntent(v.Intent)
		if err != nil {
			return err
		}
		var tool *igagov.RuntimeTool
		for i := range in.Tools {
			if in.Tools[i].Tool == d.Tool {
				tool = &in.Tools[i]
			}
		}
		if tool == nil || tool.AWS == nil {
			return govUnprocessable(GovCodeToolNotBrokered, "The decided tool has no AWS session scope in its policy version.", nil)
		}
		if err := tx.Where("workspace_id = ? AND role_arn = ? AND state = ?", ws, tool.AWS.RoleARN, "active").Take(&role).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return govUnprocessable(GovCodeBrokerRoleNotBound, "The role is not bound for brokered sessions in this workspace.",
					map[string]any{"role_arn": tool.AWS.RoleARN})
			}
			return err
		}
		dur := role.MaxSessionSeconds
		if tool.AWS.MaxSeconds > 0 && tool.AWS.MaxSeconds < dur {
			dur = tool.AWS.MaxSeconds
		}
		if dur > igagov.MaxBrokerSeconds {
			dur = igagov.MaxBrokerSeconds
		}
		if policyDoc, err = igagov.SessionPolicy(tool.AWS); err != nil {
			return govUnprocessable(GovCodeToolNotBrokered, err.Error(), nil)
		}
		short := strings.ReplaceAll(d.ID.String(), "-", "")[:16]
		human := strings.ReplaceAll(d.HumanUserID.String(), "-", "")
		agentTag := ag.ClientID
		if agentTag == "" {
			agentTag = ag.SpiffeID
		}
		if len(agentTag) > 256 {
			agentTag = agentTag[:256]
		}
		tags := map[string]string{"authsec-agent": agentTag, "authsec-human": d.HumanUserID.String(),
			"authsec-decision": d.ID.String(), "authsec-workspace": GovWorkspaceRef(ws)}
		areq = awsbroker.Request{RoleARN: role.RoleARN, SessionName: "authsec-rt-" + short, SourceIdentity: "authsec-" + human[:24],
			SessionPolicy: policyDoc, DurationSeconds: int32(dur), Tags: tags}
		if err := awsbroker.Validate(awsbroker.Request{RoleARN: areq.RoleARN, ExternalID: "x", SessionName: areq.SessionName,
			SourceIdentity: areq.SourceIdentity, SessionPolicy: areq.SessionPolicy, DurationSeconds: areq.DurationSeconds, Tags: tags}); err != nil {
			return govUnprocessable(GovCodeToolNotBrokered, err.Error(), nil)
		}
		if err := s.consume(ctxW, tx, d, "broker"); err != nil {
			return err
		}
		tagsRaw, _ := json.Marshal(tags)
		now := s.now()
		row = models.IGAGovRuntimeBrokerSession{ID: uuid.New(), WorkspaceID: ws, BrokerRoleID: role.ID, DecisionID: d.ID,
			AgentRef: d.AgentRef, HumanUserID: *d.HumanUserID, RoleARN: role.RoleARN, SessionName: areq.SessionName,
			SourceIdentity: areq.SourceIdentity, SessionPolicyHash: r3SHA256(policyDoc), SessionTags: tagsRaw,
			DurationSeconds: dur, State: "requested", CreatedAt: now, UpdatedAt: now}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		return s.event(tx, ws, GovEventBrokerSessionRequested, nil, d.PolicyID, d.VersionID, map[string]any{"broker_session_id": row.ID,
			"decision_id": d.ID, "role_arn": row.RoleARN, "session_name": row.SessionName, "duration_seconds": dur,
			"session_policy_hash": row.SessionPolicyHash})
	})
	if err != nil {
		return nil, err
	}
	finish := func(state, msg string, creds *awsbroker.Credentials) error {
		return tenancy.InWorkspace(ctxW, s.db, ws, func(tx *gorm.DB) error {
			upd := map[string]any{"state": state, "error": truncate(msg, 2000), "updated_at": s.now()}
			event := GovEventBrokerSessionFailed
			payload := map[string]any{"broker_session_id": row.ID, "decision_id": row.DecisionID, "role_arn": row.RoleARN,
				"session_name": row.SessionName, "verified_against_aws": false}
			if creds != nil {
				upd["assumed_role_arn"], upd["expires_at"] = creds.AssumedRoleARN, creds.Expiration
				event = GovEventBrokerSessionIssued
				payload["assumed_role_arn"], payload["expires_at"] = creds.AssumedRoleARN, creds.Expiration
			} else {
				payload["error"] = truncate(msg, 500)
			}
			if err := tx.Model(&models.IGAGovRuntimeBrokerSession{}).Where("workspace_id = ? AND id = ?", ws, row.ID).Updates(upd).Error; err != nil {
				return err
			}
			return s.event(tx, ws, event, nil, d.PolicyID, d.VersionID, payload)
		})
	}
	in, err := deps.Inputs(ctxW, ws, role.ConnectorID)
	if err == nil && in.AccountID != role.AccountID {
		err = fmt.Errorf("the connector is bound to account %s, not the role's %s", in.AccountID, role.AccountID)
	}
	if err != nil {
		if ferr := finish("failed", "connector: "+err.Error(), nil); ferr != nil {
			log.Printf("[runtime] workspace %s: broker session %s: recording failure: %v", ws, row.ID, ferr)
		}
		return nil, govConflict(GovCodeBrokerFailed, "The account's connector cannot be used for brokering.", map[string]any{"broker_session_id": row.ID})
	}
	areq.ExternalID, areq.Region = in.ExternalID, in.Region
	creds, aerr := deps.Broker.Assume(ctxW, areq)
	if aerr != nil {
		if ferr := finish("failed", aerr.Error(), nil); ferr != nil {
			log.Printf("[runtime] workspace %s: broker session %s: recording failure: %v", ws, row.ID, ferr)
		}
		return nil, govErr(http.StatusBadGateway, GovCodeBrokerFailed, "sts:AssumeRole failed; the decision is spent, decide again.",
			map[string]any{"broker_session_id": row.ID})
	}
	if err := finish("issued", "", creds); err != nil {
		// The credentials exist in AWS; returning them is still correct, the
		// row stays 'requested' (may have been issued).
		log.Printf("[runtime] workspace %s: broker session %s: recording issue: %v", ws, row.ID, err)
	}
	return &RuntimeSessionResult{SessionID: row.ID, RoleARN: row.RoleARN, SessionName: row.SessionName, SourceIdentity: row.SourceIdentity,
		DurationSeconds: row.DurationSeconds, SessionPolicy: json.RawMessage(policyDoc), Tags: areq.Tags, Credentials: creds}, nil
}

/* ---------------------------------------------------------------------------- */
/*                                    Sweeper                                   */
/* ---------------------------------------------------------------------------- */

// RunR3Sweeper expires holds, releases and settles overdue reservations and
// prunes retained arguments, every interval, until ctx ends. It is started
// once the R3 schema verified; it does nothing while R3 is unavailable.
func RunR3Sweeper(ctx context.Context, db *gorm.DB, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	s := NewGovR3(db)
	for {
		if PolicyR3On() {
			if err := s.Sweep(ctx); err != nil {
				log.Printf("[runtime] sweep: %v", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// Sweep is one pass. It reads due rows across workspaces, then handles each
// in its own workspace-bound transaction.
func (s *GovR3) Sweep(ctx context.Context) error {
	now := s.now()
	var holds []models.IGAGovRuntimeHold
	// TENANT-EXEMPT: the R3 sweeper runs across workspaces (no request tenant); each due hold is then expired in its own workspace_id-bound transaction
	if err := s.db.WithContext(ctx).Where("(state = ? AND expires_at < ?) OR (state = ? AND approval_valid_until < ?)",
		models.RuntimeHoldPending, now, models.RuntimeHoldApproved, now).Order("expires_at").Limit(500).Find(&holds).Error; err != nil {
		return err
	}
	for _, h := range holds {
		h := h
		if err := tenancy.InWorkspace(ctx, s.db, h.WorkspaceID, func(tx *gorm.DB) error {
			if err := tx.Where("workspace_id = ? AND id = ?", h.WorkspaceID, h.ID).Clauses(lockForUpdate()).Take(&h).Error; err != nil {
				return err
			}
			return s.expireHoldIfDue(tx, h.WorkspaceID, &h, now)
		}); err != nil {
			return fmt.Errorf("workspace %s: hold %s: %w", h.WorkspaceID, h.ID, err)
		}
	}
	type due struct {
		ID          uuid.UUID
		WorkspaceID uuid.UUID
		DecisionID  uuid.UUID
		Consumed    bool
	}
	var entries []due
	// TENANT-EXEMPT: the R3 sweeper runs across workspaces; each reservation is settled in its own workspace_id-bound transaction
	if err := s.db.WithContext(ctx).Table("iga_gov_runtime_budget_entry e").
		Select("e.id, e.workspace_id, e.decision_id, d.consumed_at IS NOT NULL AS consumed").
		Joins("JOIN iga_gov_runtime_decision d ON d.workspace_id = e.workspace_id AND d.id = e.decision_id").
		Where("e.state = ? AND ((d.consumed_at IS NULL AND d.expires_at < ?) OR (d.consumed_at IS NOT NULL AND d.tool_outcome IS NULL AND d.expires_at < ?))",
			"reserved", now, now.Add(-runtimeSettleOverdue)).Limit(500).Scan(&entries).Error; err != nil {
		return err
	}
	seen := map[uuid.UUID]bool{}
	byWS := map[uuid.UUID][]map[string]any{}
	for _, e := range entries {
		if seen[e.DecisionID] {
			continue
		}
		seen[e.DecisionID] = true
		outcome := "not_executed" // never redeemed: release
		if e.Consumed {
			outcome = "unknown" // redeemed, never reported: settle at the reservation
		}
		ctxW := inWorkspace(ctx, e.WorkspaceID)
		var settled []map[string]any
		if err := tenancy.InWorkspace(ctxW, s.db, e.WorkspaceID, func(tx *gorm.DB) error {
			var err error
			settled, err = s.settle(ctxW, tx, e.WorkspaceID, e.DecisionID, outcome, nil)
			return err
		}); err != nil {
			return fmt.Errorf("workspace %s: decision %s: %w", e.WorkspaceID, e.DecisionID, err)
		}
		for _, x := range settled {
			x["decision_id"] = e.DecisionID
			byWS[e.WorkspaceID] = append(byWS[e.WorkspaceID], x)
		}
	}
	wss := make([]uuid.UUID, 0, len(byWS))
	for ws := range byWS {
		wss = append(wss, ws)
	}
	sort.Slice(wss, func(i, j int) bool { return wss[i].String() < wss[j].String() })
	for _, ws := range wss {
		if err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
			return s.event(tx, ws, GovEventRuntimeBudgetSwept, nil, nil, nil, map[string]any{"entries": byWS[ws]})
		}); err != nil {
			return fmt.Errorf("workspace %s: budget sweep event: %w", ws, err)
		}
	}
	// Retention (R-11): prune retained arguments past each workspace's
	// retention_days (30 without a settings row).
	type wsRet struct {
		WorkspaceID uuid.UUID
		Days        int
	}
	var rets []wsRet
	// TENANT-EXEMPT: the R3 sweeper finds workspaces with retained arguments across workspaces; each prune is a workspace_id = $1 bound statement
	if err := s.db.WithContext(ctx).Table("iga_gov_runtime_decision d").
		Select("DISTINCT d.workspace_id, COALESCE(st.retention_days, 30) AS days").
		Joins("LEFT JOIN iga_gov_runtime_settings st ON st.workspace_id = d.workspace_id").
		Where("d.args_redacted IS NOT NULL").Scan(&rets).Error; err != nil {
		return err
	}
	for _, r := range rets {
		ctxW := inWorkspace(ctx, r.WorkspaceID)
		cut := now.Add(-time.Duration(r.Days) * 24 * time.Hour)
		if err := tenancy.InWorkspace(ctxW, s.db, r.WorkspaceID, func(tx *gorm.DB) error {
			res := tenancy.GormExec(ctxW, tx, `UPDATE iga_gov_runtime_decision SET args_redacted = NULL
			     WHERE workspace_id = $1 AND args_redacted IS NOT NULL AND created_at < $2`, cut)
			if res.Error != nil || res.RowsAffected == 0 {
				return res.Error
			}
			return s.event(tx, r.WorkspaceID, GovEventRuntimeArgsPruned, nil, nil, nil, map[string]any{"decisions": res.RowsAffected,
				"older_than": cut, "retention_days": r.Days})
		}); err != nil {
			return fmt.Errorf("workspace %s: argument retention: %w", r.WorkspaceID, err)
		}
	}
	return nil
}
