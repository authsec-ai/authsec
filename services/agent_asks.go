package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// Asks (SPEC-secops-backend-upgrade.md W4 / P1; migration 220).
//
// An ask is a question a person must answer: about an agent, an alert, a key,
// a case, a containment, a remediation or a held gateway call. The server,
// never the request body, picks who decides and when it is due:
//
//	Decider: the ask's agent (named, or found through the alert's / case's /
//	containment's workloads) goes through W7's responder resolution ("who
//	decides for agent X": the group holding the agent, then its estate
//	scopes); when that gives no group of its own, the estate scope of the
//	object (the alert's or containment's connector account or subscription);
//	else the workspace default group. The path (escalation chain) is that
//	group, then its leads, then the default group, then the workspace admins;
//	steps whose deciders are all excluded are skipped. The requester of the
//	underlying action and the ask's creator are excluded (decision 1:
//	separation excludes the person who acted).
//
//	Due: the workspace's agent_ask_policy hours for the severity of the
//	ask's object (alert / case severity; a containment, remediation or held
//	gateway call is high), from now; or an external deadline with its
//	recorded source, when earlier. A deadline can only shorten the policy.
//
// Answering: only a person who decides at the current step (live: an accepted
// member of the step's group, or its delegate; never an excluded person),
// with one of the ask's choices. "Not mine" moves the ask to the next step
// and excludes the person. The creator, or a holder of governance:approve,
// withdraws. An answer from Slack to a tier-2+ ask is recorded as
// pending_step_up; it takes effect when the same person confirms it in the
// console (askAnswerNeedsStepUp is the local tier check W5's map replaces).
//
// Every statement runs in a transaction under row-level security for the
// ask's workspace; another workspace's ask is 404.

// About kinds.
const (
	AskAboutAgent       = "agent"
	AskAboutAlert       = "alert"
	AskAboutKey         = "key"
	AskAboutCase        = "case"
	AskAboutContainment = "containment"
	AskAboutRemediation = "remediation"
	AskAboutGatewayCall = "gateway_call"
)

// States.
const (
	AskStateOpen          = "open"
	AskStatePendingStepUp = "pending_step_up"
	AskStateAnswered      = "answered"
	AskStateWithdrawn     = "withdrawn"
	AskStateExpired       = "expired"
)

// Answer channels.
const (
	AskChannelConsole = "console"
	AskChannelSlack   = "slack"
	AskChannelEmail   = "email"
)

// Decider roles.
const (
	AskRoleOwner     = "owner"
	AskRoleResponder = "responder"
	AskRoleCodeOwner = "code_owner"
	AskRoleApprover  = "approver"
)

// Path step kinds.
const (
	AskStepGroup      = "group"
	AskStepGroupLeads = "group_leads"
	AskStepUsers      = "users"
	AskStepAdmins     = "admins"
)

// agent_ask_event kinds.
const (
	AskEventAsked           = "asked"
	AskEventDelivered       = "delivered"
	AskEventDeliveryFailed  = "delivery_failed"
	AskEventEscalated       = "escalated"
	AskEventOverdue         = "overdue"
	AskEventDisputed        = "disputed"
	AskEventStepUpPending   = "step_up_pending"
	AskEventStepUpConfirmed = "step_up_confirmed"
	AskEventStepUpLapsed    = "step_up_lapsed"
	AskEventAnswered        = "answered"
	AskEventWithdrawn       = "withdrawn"
	AskEventExpired         = "expired"
	AskEventTicketOpened    = "ticket_opened"
	AskEventTicketResolved  = "ticket_resolved"
	AskEventPaged           = "paged"
	AskEventPageResolved    = "page_resolved"
	AskEventExternalFailed  = "external_failed"
)

// Error codes.
const (
	GovCodeAskNotOpen        = "ask_not_open"
	GovCodeNotDecider        = "not_decider"
	GovCodeRequesterDecides  = "requester_cannot_decide"
	GovCodeNoNextStep        = "no_next_step"
	GovCodeAskChanged        = "ask_changed"
	GovCodeStepUpNotPending  = "step_up_not_pending"
	GovCodeStepUpOtherPerson = "step_up_other_person"
	GovCodeAgentAsksOff      = "agent_asks_unavailable"
	AgentAsksSchemaHead      = "220 (over 181 and 186)"
)

// iga_gov_event names (vocabulary below).
const (
	GovCatAgentAsk = "agent_ask"
	GovObjAgentAsk = "agent_ask"

	GovEventAskCreated            = "ask.created"
	GovEventAskEscalated          = "ask.escalated"
	GovEventAskOverdue            = "ask.overdue"
	GovEventAskDisputed           = "ask.disputed"
	GovEventAskStepUpPending      = "ask.step_up_pending"
	GovEventAskAnswered           = "ask.answered"
	GovEventAskWithdrawn          = "ask.withdrawn"
	GovEventAskExpired            = "ask.expired"
	GovEventAskPolicyChanged      = "ask.policy_changed"
	GovEventAskPolicyRequested    = "ask.policy_change_requested"
	GovEventAskIntegrationSet     = "ask.integration_set"
	GovEventAskIntegrationRemoved = "ask.integration_removed"
	GovEventAskExternalOpened     = "ask.external_opened"
	GovEventAskExternalResolved   = "ask.external_resolved"
	GovEventAskExternalFailed     = "ask.external_failed"
)

var agentAskVocabulary = []GovEventKind{
	{GovEventAskCreated, GovCatAgentAsk, GovObjAgentAsk, "An ask was raised; the server chose its deciders and due time."},
	{GovEventAskEscalated, GovCatAgentAsk, GovObjAgentAsk, "An ask passed its due time and moved to the next step of its path."},
	{GovEventAskOverdue, GovCatAgentAsk, GovObjAgentAsk, "An ask passed its due time at the end of its path (or had no one to decide); it stays open."},
	{GovEventAskDisputed, GovCatAgentAsk, GovObjAgentAsk, "A decider said the ask is not theirs; it moved to the next step."},
	{GovEventAskStepUpPending, GovCatAgentAsk, GovObjAgentAsk, "A tier-2+ ask was answered from Slack; the answer waits for the same person's console confirmation."},
	{GovEventAskAnswered, GovCatAgentAsk, GovObjAgentAsk, "An ask was answered (choice, channel and decider in the entry)."},
	{GovEventAskWithdrawn, GovCatAgentAsk, GovObjAgentAsk, "An ask was withdrawn by its creator or a holder of governance:approve."},
	{GovEventAskExpired, GovCatAgentAsk, GovObjAgentAsk, "An ask was closed unanswered by the system that raised it (its subject ended)."},
	{GovEventAskPolicyChanged, GovCatAgentAsk, "", "The workspace's ask policy (due times, escalation step, channels) changed."},
	{GovEventAskPolicyRequested, GovCatAgentAsk, "", "A loosening of the ask policy waits for a second person (tier 3)."},
	{GovEventAskIntegrationSet, GovCatAgentAsk, "", "A ticketing or paging integration was configured (its secret is in Vault, never here)."},
	{GovEventAskIntegrationRemoved, GovCatAgentAsk, "", "A ticketing or paging integration was removed and its secret destroyed."},
	{GovEventAskExternalOpened, GovCatAgentAsk, GovObjAgentAsk, "A ticket or page was opened for an ask or a case."},
	{GovEventAskExternalResolved, GovCatAgentAsk, GovObjAgentAsk, "A ticket was resolved in the external tool, or a page was resolved after its ask closed."},
	{GovEventAskExternalFailed, GovCatAgentAsk, GovObjAgentAsk, "A ticket or page could not be opened or synced after its retries."},
}

func init() {
	GovEventVocabulary = append(GovEventVocabulary, agentAskVocabulary...)
	govEventObjectFilters[GovObjAgentAsk] = struct{ column, payloadKey string }{payloadKey: "ask_id"}
}

/* ------------------------------------------------------------------------- */
/*                                Schema gate                                 */
/* ------------------------------------------------------------------------- */

var agentAsksGate = &agentSchemaGate{head: AgentAsksSchemaHead, relations: []string{"agent_ask", "agent_ask_event",
	"agent_ask_policy", "agent_ask_integration", "agent_ask_external", "responder_group", "agent", "agent_case"}}

// AgentAsksStatus is whether asks can run (migration 220).
func AgentAsksStatus(db *gorm.DB) (bool, string) { return agentAsksGate.status(db) }

// AgentAsksCapabilities is /capabilities' agent_asks block.
func AgentAsksCapabilities(db *gorm.DB) map[string]any {
	ok, reason := AgentAsksStatus(db)
	return map[string]any{"available": ok, "reason": nullable(reason)}
}

// RequireAgentAsks is nil while asks can run, else the 503.
func RequireAgentAsks(db *gorm.DB) error {
	if ok, reason := AgentAsksStatus(db); !ok {
		return govErr(http.StatusServiceUnavailable, GovCodeAgentAsksOff, "Asks are not available on this server.",
			map[string]any{"reason": reason})
	}
	return nil
}

/* ------------------------------------------------------------------------- */
/*                                   Types                                    */
/* ------------------------------------------------------------------------- */

// AskChoice is one answer an ask offers.
type AskChoice struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// AskStep is one step of an ask's escalation path.
type AskStep struct {
	Kind    string      `json:"kind"`
	GroupID *uuid.UUID  `json:"group_id,omitempty"`
	UserIDs []uuid.UUID `json:"user_ids,omitempty"`
	Label   string      `json:"label"`
}

// AskInput is an ask raised by AuthSec itself (CreateAsk) or, through
// AgentAskService.Create, by a console user. Deciders and due time are never
// taken from it: Severity, Deciders, AgentID and Tier are server facts set
// by the raising code (the HTTP route sets none of Severity, Deciders,
// AgentID).
type AskInput struct {
	AboutKind string
	AboutID   string
	// CaseID links the ask to a case (asks about a case or an alert in a case
	// are linked without it).
	CaseID *uuid.UUID
	// AgentID is the agent the ask is about, when the raising code knows it.
	AgentID  *uuid.UUID
	Question string
	Choices  []AskChoice
	// Severity overrides the severity read from the about object ("" reads it).
	Severity string
	// Tier is the tier of what the answer decides (0 = the kind's default;
	// never below the kind's default).
	Tier int
	Role string
	// Deciders names people who decide first (e.g. code owners), before the
	// responder path.
	Deciders []uuid.UUID
	// RequesterUserID is the person whose action the ask is about: never a
	// decider. ExcludeUserIDs are further people who must not decide.
	RequesterUserID *uuid.UUID
	ExcludeUserIDs  []uuid.UUID
	// CreatedBy is the console user raising the ask (nil: AuthSec).
	CreatedBy *uuid.UUID
	// ExternalDeadline (with its source) shortens the policy's due time.
	ExternalDeadline       *time.Time
	ExternalDeadlineSource string
	// DedupeKey makes a system ask idempotent: while an ask with the key is
	// open, CreateAsk returns it.
	DedupeKey string
	Context   map[string]any
}

// AgentAskView is an ask as the API shows it.
type AgentAskView struct {
	ID                     uuid.UUID            `json:"id"`
	AboutKind              string               `json:"about_kind"`
	AboutID                string               `json:"about_id"`
	AgentID                *uuid.UUID           `json:"agent_id"`
	CaseID                 *uuid.UUID           `json:"case_id"`
	Question               string               `json:"question"`
	Choices                []AskChoice          `json:"choices"`
	Severity               string               `json:"severity"`
	Tier                   int                  `json:"tier"`
	Role                   string               `json:"role"`
	DeciderGroupID         *uuid.UUID           `json:"decider_group_id"`
	DeciderUserID          *uuid.UUID           `json:"decider_user_id"`
	Deciders               []uuid.UUID          `json:"deciders"`
	ResolvedVia            string               `json:"resolved_via"`
	Path                   []AskStep            `json:"path"`
	Step                   int                  `json:"step"`
	RequesterUserID        *uuid.UUID           `json:"requester_user_id"`
	DueAt                  time.Time            `json:"due_at"`
	DueSource              string               `json:"due_source"`
	ExternalDeadlineAt     *time.Time           `json:"external_deadline_at"`
	ExternalDeadlineSource string               `json:"external_deadline_source"`
	HoursPerStep           int                  `json:"hours_per_step"`
	State                  string               `json:"state"`
	Overdue                bool                 `json:"overdue"`
	OverdueAt              *time.Time           `json:"overdue_at"`
	PendingChoice          *string              `json:"pending_choice"`
	PendingBy              *uuid.UUID           `json:"pending_by"`
	PendingAt              *time.Time           `json:"pending_at"`
	AnswerChoice           *string              `json:"answer_choice"`
	AnsweredBy             *uuid.UUID           `json:"answered_by"`
	AnsweredAt             *time.Time           `json:"answered_at"`
	AnswerChannel          *string              `json:"answer_channel"`
	AnswerNote             string               `json:"answer_note"`
	WithdrawnBy            *uuid.UUID           `json:"withdrawn_by"`
	WithdrawnAt            *time.Time           `json:"withdrawn_at"`
	WithdrawReason         string               `json:"withdraw_reason"`
	CreatedByKind          string               `json:"created_by_kind"`
	CreatedBy              *uuid.UUID           `json:"created_by"`
	Context                json.RawMessage      `json:"context"`
	CreatedAt              time.Time            `json:"created_at"`
	UpdatedAt              time.Time            `json:"updated_at"`
	Mine                   bool                 `json:"mine"`
	CanAnswer              *bool                `json:"can_answer,omitempty"`
	Events                 []AgentAskEvent      `json:"events,omitempty"`
	External               []AgentAskExternalVw `json:"external,omitempty"`
}

// AgentAskEvent is one agent_ask_event row.
type AgentAskEvent struct {
	ID        uuid.UUID       `json:"id" gorm:"column:id"`
	Kind      string          `json:"kind" gorm:"column:kind"`
	Step      int             `json:"step" gorm:"column:step"`
	ActorKind string          `json:"actor_kind" gorm:"column:actor_kind"`
	ActorID   string          `json:"actor_id" gorm:"column:actor_id"`
	Channel   string          `json:"channel" gorm:"column:channel"`
	Detail    json.RawMessage `json:"detail" gorm:"column:detail"`
	CreatedAt time.Time       `json:"created_at" gorm:"column:created_at"`
}

// AgentAskExternalVw is a ticket or page of an ask or a case.
type AgentAskExternalVw struct {
	ID          uuid.UUID  `json:"id" gorm:"column:id"`
	Provider    string     `json:"provider" gorm:"column:provider"`
	Kind        string     `json:"kind" gorm:"column:kind"`
	AskID       *uuid.UUID `json:"ask_id" gorm:"column:ask_id"`
	CaseID      *uuid.UUID `json:"case_id" gorm:"column:case_id"`
	ExternalKey string     `json:"external_key" gorm:"column:external_key"`
	ExternalURL string     `json:"external_url" gorm:"column:external_url"`
	State       string     `json:"state" gorm:"column:state"`
	LastStatus  string     `json:"last_status" gorm:"column:last_status"`
	Attempts    int        `json:"attempts" gorm:"column:attempts"`
	LastError   string     `json:"last_error" gorm:"column:last_error"`
	CreatedAt   time.Time  `json:"created_at" gorm:"column:created_at"`
	UpdatedAt   time.Time  `json:"updated_at" gorm:"column:updated_at"`
	ResolvedAt  *time.Time `json:"resolved_at" gorm:"column:resolved_at"`
}

// AgentAskSummary is an ask as a case shows it.
type AgentAskSummary struct {
	ID            uuid.UUID  `json:"id" gorm:"column:id"`
	AboutKind     string     `json:"about_kind" gorm:"column:about_kind"`
	AboutID       string     `json:"about_id" gorm:"column:about_id"`
	Question      string     `json:"question" gorm:"column:question"`
	Severity      string     `json:"severity" gorm:"column:severity"`
	State         string     `json:"state" gorm:"column:state"`
	Overdue       bool       `json:"overdue" gorm:"column:overdue"`
	DueAt         time.Time  `json:"due_at" gorm:"column:due_at"`
	Step          int        `json:"step" gorm:"column:step"`
	AnswerChoice  *string    `json:"answer_choice" gorm:"column:answer_choice"`
	AnsweredBy    *uuid.UUID `json:"answered_by" gorm:"column:answered_by"`
	AnsweredAt    *time.Time `json:"answered_at" gorm:"column:answered_at"`
	AnswerChannel *string    `json:"answer_channel" gorm:"column:answer_channel"`
	CreatedAt     time.Time  `json:"created_at" gorm:"column:created_at"`
}

type agentAskRow struct {
	ID                     uuid.UUID      `gorm:"column:id"`
	WorkspaceID            uuid.UUID      `gorm:"column:workspace_id"`
	AboutKind              string         `gorm:"column:about_kind"`
	AboutID                string         `gorm:"column:about_id"`
	AgentID                *uuid.UUID     `gorm:"column:agent_id"`
	CaseID                 *uuid.UUID     `gorm:"column:case_id"`
	Question               string         `gorm:"column:question"`
	Choices                string         `gorm:"column:choices"`
	Severity               string         `gorm:"column:severity"`
	Tier                   int            `gorm:"column:tier"`
	Role                   string         `gorm:"column:role"`
	DeciderGroupID         *uuid.UUID     `gorm:"column:decider_group_id"`
	DeciderUserID          *uuid.UUID     `gorm:"column:decider_user_id"`
	Deciders               string         `gorm:"column:deciders"`
	ResolvedVia            string         `gorm:"column:resolved_via"`
	Path                   string         `gorm:"column:path"`
	Step                   int            `gorm:"column:step"`
	ExcludedUserIDs        string         `gorm:"column:excluded_user_ids"`
	RequesterUserID        *uuid.UUID     `gorm:"column:requester_user_id"`
	DueAt                  time.Time      `gorm:"column:due_at"`
	DueSource              string         `gorm:"column:due_source"`
	ExternalDeadlineAt     *time.Time     `gorm:"column:external_deadline_at"`
	ExternalDeadlineSource string         `gorm:"column:external_deadline_source"`
	HoursPerStep           int            `gorm:"column:hours_per_step"`
	State                  string         `gorm:"column:state"`
	Overdue                bool           `gorm:"column:overdue"`
	OverdueAt              *time.Time     `gorm:"column:overdue_at"`
	PendingChoice          *string        `gorm:"column:pending_choice"`
	PendingBy              *uuid.UUID     `gorm:"column:pending_by"`
	PendingAt              *time.Time     `gorm:"column:pending_at"`
	AnswerChoice           *string        `gorm:"column:answer_choice"`
	AnsweredBy             *uuid.UUID     `gorm:"column:answered_by"`
	AnsweredAt             *time.Time     `gorm:"column:answered_at"`
	AnswerChannel          *string        `gorm:"column:answer_channel"`
	AnswerNote             string         `gorm:"column:answer_note"`
	WithdrawnBy            *uuid.UUID     `gorm:"column:withdrawn_by"`
	WithdrawnAt            *time.Time     `gorm:"column:withdrawn_at"`
	WithdrawReason         string         `gorm:"column:withdraw_reason"`
	CreatedByKind          string         `gorm:"column:created_by_kind"`
	CreatedBy              *uuid.UUID     `gorm:"column:created_by"`
	DedupeKey              *string        `gorm:"column:dedupe_key"`
	Context                string         `gorm:"column:context"`
	CreatedAt              time.Time      `gorm:"column:created_at"`
	UpdatedAt              time.Time      `gorm:"column:updated_at"`
}

const agentAskCols = `id, workspace_id, about_kind, about_id, agent_id, case_id, question, choices::text AS choices, severity, tier,
	role, decider_group_id, decider_user_id, array_to_json(deciders)::text AS deciders, resolved_via, path::text AS path, step,
	array_to_json(excluded_user_ids)::text AS excluded_user_ids, requester_user_id, due_at, due_source, external_deadline_at,
	external_deadline_source, hours_per_step, state, overdue, overdue_at, pending_choice, pending_by, pending_at,
	answer_choice, answered_by, answered_at, answer_channel, answer_note, withdrawn_by, withdrawn_at, withdraw_reason,
	created_by_kind, created_by, dedupe_key, context::text AS context, created_at, updated_at`

// uuidsOf reads a uuid[] selected as array_to_json(...)::text.
func uuidsOf(raw string) []uuid.UUID {
	var ss []string
	_ = json.Unmarshal([]byte(raw), &ss)
	out := make([]uuid.UUID, 0, len(ss))
	for _, s := range ss {
		if id, err := uuid.Parse(s); err == nil {
			out = append(out, id)
		}
	}
	return out
}

func uuidStrings(ids []uuid.UUID) pq.StringArray {
	out := make(pq.StringArray, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	return out
}

func (r *agentAskRow) choices() []AskChoice {
	var cs []AskChoice
	_ = json.Unmarshal([]byte(r.Choices), &cs)
	if cs == nil {
		cs = []AskChoice{}
	}
	return cs
}

func (r *agentAskRow) path() []AskStep {
	var ps []AskStep
	_ = json.Unmarshal([]byte(r.Path), &ps)
	if ps == nil {
		ps = []AskStep{}
	}
	return ps
}

func (r *agentAskRow) excluded() map[uuid.UUID]bool {
	out := map[uuid.UUID]bool{}
	for _, id := range uuidsOf(r.ExcludedUserIDs) {
		out[id] = true
	}
	if r.RequesterUserID != nil {
		out[*r.RequesterUserID] = true
	}
	return out
}

func (r *agentAskRow) live() bool {
	return r.State == AskStateOpen || r.State == AskStatePendingStepUp
}

func (r *agentAskRow) view(actor uuid.UUID) AgentAskView {
	ctxRaw := json.RawMessage(r.Context)
	if len(ctxRaw) == 0 {
		ctxRaw = json.RawMessage(`{}`)
	}
	v := AgentAskView{ID: r.ID, AboutKind: r.AboutKind, AboutID: r.AboutID, AgentID: r.AgentID, CaseID: r.CaseID,
		Question: r.Question, Choices: r.choices(), Severity: r.Severity, Tier: r.Tier, Role: r.Role,
		DeciderGroupID: r.DeciderGroupID, DeciderUserID: r.DeciderUserID, Deciders: uuidsOf(r.Deciders),
		ResolvedVia: r.ResolvedVia, Path: r.path(), Step: r.Step, RequesterUserID: r.RequesterUserID,
		DueAt: r.DueAt.UTC(), DueSource: r.DueSource, ExternalDeadlineAt: utcPtr(r.ExternalDeadlineAt),
		ExternalDeadlineSource: r.ExternalDeadlineSource, HoursPerStep: r.HoursPerStep, State: r.State,
		Overdue: r.Overdue, OverdueAt: utcPtr(r.OverdueAt), PendingChoice: r.PendingChoice, PendingBy: r.PendingBy,
		PendingAt: utcPtr(r.PendingAt), AnswerChoice: r.AnswerChoice, AnsweredBy: r.AnsweredBy,
		AnsweredAt: utcPtr(r.AnsweredAt), AnswerChannel: r.AnswerChannel, AnswerNote: r.AnswerNote,
		WithdrawnBy: r.WithdrawnBy, WithdrawnAt: utcPtr(r.WithdrawnAt), WithdrawReason: r.WithdrawReason,
		CreatedByKind: r.CreatedByKind, CreatedBy: r.CreatedBy, Context: ctxRaw, CreatedAt: r.CreatedAt.UTC(),
		UpdatedAt: r.UpdatedAt.UTC()}
	if actor != uuid.Nil && r.live() && !r.excluded()[actor] {
		for _, d := range v.Deciders {
			if d == actor {
				v.Mine = true
			}
		}
	}
	return v
}

func readAgentAsk(tx *gorm.DB, ws, id uuid.UUID, lock bool) (*agentAskRow, error) {
	q := `SELECT ` + agentAskCols + ` FROM agent_ask WHERE workspace_id = ? AND id = ?`
	if lock {
		q += ` FOR UPDATE`
	}
	var rows []agentAskRow
	if err := tx.Raw(q, ws, id).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, GovNotFound()
	}
	return &rows[0], nil
}

/* ------------------------------------------------------------------------- */
/*                                   Policy                                   */
/* ------------------------------------------------------------------------- */

// AgentAskPolicy is the workspace's ask policy (agent_ask_policy; defaults
// when the workspace has no row: version 0).
type AgentAskPolicy struct {
	DueHighHours   int        `json:"due_high_hours" gorm:"column:due_high_hours"`
	DueMediumHours int        `json:"due_medium_hours" gorm:"column:due_medium_hours"`
	DueLowHours    int        `json:"due_low_hours" gorm:"column:due_low_hours"`
	HoursPerStep   int        `json:"hours_per_step" gorm:"column:hours_per_step"`
	ChannelSlack   bool       `json:"channel_slack" gorm:"column:channel_slack"`
	ChannelEmail   bool       `json:"channel_email" gorm:"column:channel_email"`
	ChannelWebhook bool       `json:"channel_webhook" gorm:"column:channel_webhook"`
	Version        int64      `json:"version" gorm:"column:version"`
	UpdatedBy      *uuid.UUID `json:"updated_by" gorm:"column:updated_by"`
	UpdatedAt      *time.Time `json:"updated_at" gorm:"column:updated_at"`
}

// DefaultAgentAskPolicy is the policy of a workspace that set none: due in
// 4 h (high), 24 h (medium), 72 h (low); 4 h per escalation step; Slack and
// e-mail on, the workspace webhook off.
func DefaultAgentAskPolicy() AgentAskPolicy {
	return AgentAskPolicy{DueHighHours: 4, DueMediumHours: 24, DueLowHours: 72, HoursPerStep: 4,
		ChannelSlack: true, ChannelEmail: true}
}

// DueHours is the policy's hours for a severity (anything else is low).
func (p AgentAskPolicy) DueHours(severity string) int {
	switch severity {
	case "high":
		return p.DueHighHours
	case "medium":
		return p.DueMediumHours
	}
	return p.DueLowHours
}

func readAgentAskPolicy(tx *gorm.DB, ws uuid.UUID) (AgentAskPolicy, error) {
	var rows []AgentAskPolicy
	if err := tx.Raw(`SELECT due_high_hours, due_medium_hours, due_low_hours, hours_per_step, channel_slack, channel_email,
	        channel_webhook, version, updated_by, updated_at FROM agent_ask_policy WHERE workspace_id = ?`, ws).Scan(&rows).Error; err != nil {
		return AgentAskPolicy{}, err
	}
	if len(rows) == 0 {
		return DefaultAgentAskPolicy(), nil
	}
	return rows[0], nil
}

// AgentAskDue is when an ask is due: the policy's hours for its severity
// from now, or an external deadline when that is earlier ("policy" or
// "external_deadline" says which).
func AgentAskDue(p AgentAskPolicy, severity string, now time.Time, external *time.Time) (time.Time, string) {
	due := now.Add(time.Duration(p.DueHours(severity)) * time.Hour)
	if external != nil && external.Before(due) {
		return external.UTC(), "external_deadline"
	}
	return due.UTC(), "policy"
}

/* ------------------------------------------------------------------------- */
/*                                 Validation                                 */
/* ------------------------------------------------------------------------- */

var askChoiceIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,39}$`)

// Limits.
const (
	AskMaxQuestion      = 2000
	AskMaxChoiceLabel   = 200
	AskMaxReason        = 1000
	AskMaxDeadlineAhead = 366 * 24 * time.Hour
	askMaxDeliveries    = 25
)

func validAskAbout(kind string) bool {
	switch kind {
	case AskAboutAgent, AskAboutAlert, AskAboutKey, AskAboutCase, AskAboutContainment, AskAboutRemediation, AskAboutGatewayCall:
		return true
	}
	return false
}

// askKindTier is the lowest tier of an ask about a kind (SPEC P3): a
// containment or a held gateway call is a wider stop (tier 2), a
// remediation writes to the customer's cloud (tier 4).
func askKindTier(kind string) int {
	switch kind {
	case AskAboutRemediation:
		return 4
	case AskAboutContainment, AskAboutGatewayCall:
		return 2
	}
	return 1
}

// askAnswerNeedsStepUp is the local tier check (TODO(W5): W5's static
// action -> tier map and its step-up helper replace it): an answer given in
// Slack to a tier-2+ ask must be confirmed by the same person in the console.
func askAnswerNeedsStepUp(tier int, channel string) bool {
	return channel == AskChannelSlack && tier >= 2
}

// ValidateAskInput checks and normalises what an ask says (not who decides).
func ValidateAskInput(in *AskInput, now time.Time) error {
	in.AboutKind = strings.TrimSpace(in.AboutKind)
	in.AboutID = strings.TrimSpace(in.AboutID)
	if !validAskAbout(in.AboutKind) {
		return GovBadParam("about.kind", "about.kind must be one of agent, alert, key, case, containment, remediation, gateway_call.")
	}
	if in.AboutID == "" || len(in.AboutID) > 512 || strings.ContainsRune(in.AboutID, 0) {
		return GovBadParam("about.id", "about.id is required (at most 512 characters).")
	}
	in.Question = strings.TrimSpace(in.Question)
	if in.Question == "" || utf8.RuneCountInString(in.Question) > AskMaxQuestion || strings.ContainsRune(in.Question, 0) {
		return GovBadParam("question", "question is required (at most 2000 characters).")
	}
	if len(in.Choices) < 2 || len(in.Choices) > 10 {
		return GovBadParam("choices", "choices must list 2 to 10 answers.")
	}
	seen := map[string]bool{}
	for i := range in.Choices {
		c := &in.Choices[i]
		c.ID, c.Label = strings.TrimSpace(c.ID), strings.TrimSpace(c.Label)
		if !askChoiceIDRe.MatchString(c.ID) {
			return GovBadParam("choices", "a choice id is 1-40 lowercase letters, digits or underscores.")
		}
		if seen[c.ID] {
			return GovBadParam("choices", "choice ids must be unique.")
		}
		seen[c.ID] = true
		if c.Label == "" || utf8.RuneCountInString(c.Label) > AskMaxChoiceLabel || strings.ContainsRune(c.Label, 0) {
			return GovBadParam("choices", "a choice label is required (at most 200 characters).")
		}
	}
	switch in.Severity {
	case "", "high", "medium", "low":
	default:
		return GovBadParam("severity", "severity must be high, medium or low.")
	}
	if in.Tier < 0 || in.Tier > 4 {
		return GovBadParam("tier", "tier is 0 to 4.")
	}
	if floor := askKindTier(in.AboutKind); in.Tier < floor {
		in.Tier = floor
	}
	switch in.Role {
	case "":
		in.Role = AskRoleResponder
	case AskRoleOwner, AskRoleResponder, AskRoleCodeOwner, AskRoleApprover:
	default:
		return GovBadParam("role", "role must be owner, responder, code_owner or approver.")
	}
	in.ExternalDeadlineSource = strings.TrimSpace(in.ExternalDeadlineSource)
	switch {
	case in.ExternalDeadline == nil && in.ExternalDeadlineSource != "":
		return GovBadParam("external_deadline.at", "an external deadline needs its time.")
	case in.ExternalDeadline != nil:
		if in.ExternalDeadlineSource == "" || utf8.RuneCountInString(in.ExternalDeadlineSource) > 500 {
			return GovBadParam("external_deadline.source", "an external deadline needs its source (who set it; at most 500 characters).")
		}
		if !in.ExternalDeadline.After(now) || in.ExternalDeadline.Sub(now) > AskMaxDeadlineAhead {
			return GovBadParam("external_deadline.at", "an external deadline is a future time at most a year away.")
		}
	}
	if len(in.DedupeKey) > 300 {
		return GovBadParam("dedupe_key", "dedupe_key is at most 300 characters.")
	}
	return nil
}

/* ------------------------------------------------------------------------- */
/*                        What the ask is about (server)                      */
/* ------------------------------------------------------------------------- */

// askSubject is what the server reads about the ask's object.
type askSubject struct {
	agentID  *uuid.UUID
	caseID   *uuid.UUID
	severity string
	scopes   []ResponderGroupScope
}

func askAboutNotFound(kind string) error {
	return GovBadParam("about.id", "about.id names no "+kind+" of this workspace.")
}

// askAgentForWorkloads is the agent (W7) of one of the workloads, active first.
func askAgentForWorkloads(tx *gorm.DB, ws uuid.UUID, workloads []string) (*uuid.UUID, error) {
	if len(workloads) == 0 {
		return nil, nil
	}
	var ids []uuid.UUID
	if err := tx.Raw(`SELECT a.agent_id FROM agent_alias a JOIN agent g ON g.workspace_id = a.workspace_id AND g.id = a.agent_id
	        WHERE a.workspace_id = ? AND a.source_table = 'iga_workload' AND a.source_id IN ?
	        ORDER BY (g.state = 'active') DESC, a.agent_id LIMIT 1`, ws, workloads).Scan(&ids).Error; err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}
	return &ids[0], nil
}

// askConnectorScopes is a connector's estate scope (account / subscription).
func askConnectorScopes(tx *gorm.DB, ws uuid.UUID, connector uuid.UUID) ([]ResponderGroupScope, error) {
	var rows []struct {
		Kind string `gorm:"column:kind"`
		Ref  string `gorm:"column:ref"`
	}
	if err := tx.Raw(`SELECT CASE WHEN scope_kind = 'subscription' THEN 'subscription' ELSE 'account' END AS kind, scope_id AS ref
	        FROM cloud_connector WHERE workspace_id = ? AND id = ? AND scope_kind IN ('account', 'subscription')`, ws, connector).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := []ResponderGroupScope{}
	for _, r := range rows {
		if r.Ref != "" {
			out = append(out, ResponderGroupScope{ScopeKind: r.Kind, ScopeRef: r.Ref})
		}
	}
	return out, nil
}

func readAskSubject(tx *gorm.DB, ws uuid.UUID, kind, id string) (askSubject, error) {
	s := askSubject{severity: "medium"}
	parse := func() (uuid.UUID, error) {
		u, err := uuid.Parse(id)
		if err != nil {
			return uuid.Nil, askAboutNotFound(kind)
		}
		return u, nil
	}
	switch kind {
	case AskAboutAgent:
		u, err := parse()
		if err != nil {
			return s, err
		}
		if _, err := loadAgent(tx, ws, u, false); err != nil {
			var ge *GovError
			if errors.As(err, &ge) && ge.Status == http.StatusNotFound {
				return s, askAboutNotFound(kind)
			}
			return s, err
		}
		s.agentID = &u
	case AskAboutAlert:
		u, err := parse()
		if err != nil {
			return s, err
		}
		var rows []struct {
			Severity    string    `gorm:"column:severity"`
			ConnectorID uuid.UUID `gorm:"column:connector_id"`
			Workloads   string    `gorm:"column:workloads"`
			CaseID      *uuid.UUID
		}
		if err := tx.Raw(`SELECT a.severity, a.connector_id, a.workload_ids::text AS workloads,
		        (SELECT ca.case_id FROM agent_case_alert ca WHERE ca.workspace_id = a.workspace_id AND ca.alert_id = a.id) AS case_id
		        FROM agent_alert a WHERE a.workspace_id = ? AND a.id = ?`, ws, u).Scan(&rows).Error; err != nil {
			return s, err
		}
		if len(rows) == 0 {
			return s, askAboutNotFound(kind)
		}
		s.severity, s.caseID = rows[0].Severity, rows[0].CaseID
		var wl []string
		_ = json.Unmarshal([]byte(rows[0].Workloads), &wl)
		if s.agentID, err = askAgentForWorkloads(tx, ws, wl); err != nil {
			return s, err
		}
		if s.scopes, err = askConnectorScopes(tx, ws, rows[0].ConnectorID); err != nil {
			return s, err
		}
	case AskAboutCase:
		u, err := parse()
		if err != nil {
			return s, err
		}
		c, err := getAgentCase(tx, ws, u)
		if err != nil {
			var ge *GovError
			if errors.As(err, &ge) && ge.Status == http.StatusNotFound {
				return s, askAboutNotFound(kind)
			}
			return s, err
		}
		s.severity, s.caseID = c.Severity, &u
		var rows []struct {
			ConnectorID uuid.UUID `gorm:"column:connector_id"`
			Workloads   string    `gorm:"column:workloads"`
		}
		if err := tx.Raw(`SELECT a.connector_id, a.workload_ids::text AS workloads FROM agent_case_alert ca
		        JOIN agent_alert a ON a.workspace_id = ca.workspace_id AND a.id = ca.alert_id
		        WHERE ca.workspace_id = ? AND ca.case_id = ? ORDER BY a.created_at, a.id LIMIT 100`, ws, u).Scan(&rows).Error; err != nil {
			return s, err
		}
		var wl []string
		for _, r := range rows {
			var w []string
			_ = json.Unmarshal([]byte(r.Workloads), &w)
			wl = append(wl, w...)
		}
		if s.agentID, err = askAgentForWorkloads(tx, ws, wl); err != nil {
			return s, err
		}
		if len(rows) > 0 {
			if s.scopes, err = askConnectorScopes(tx, ws, rows[0].ConnectorID); err != nil {
				return s, err
			}
		}
	case AskAboutContainment:
		u, err := parse()
		if err != nil {
			return s, err
		}
		var rows []struct {
			ConnectorID uuid.UUID `gorm:"column:connector_id"`
			Workloads   string    `gorm:"column:workloads"`
		}
		if err := tx.Raw(`SELECT connector_id, array_to_json(workload_ids)::text AS workloads FROM agent_containment
		        WHERE workspace_id = ? AND id = ?`, ws, u).Scan(&rows).Error; err != nil {
			return s, err
		}
		if len(rows) == 0 {
			return s, askAboutNotFound(kind)
		}
		s.severity = "high"
		var wl []string
		_ = json.Unmarshal([]byte(rows[0].Workloads), &wl)
		if s.agentID, err = askAgentForWorkloads(tx, ws, wl); err != nil {
			return s, err
		}
		if s.scopes, err = askConnectorScopes(tx, ws, rows[0].ConnectorID); err != nil {
			return s, err
		}
	case AskAboutRemediation, AskAboutGatewayCall:
		s.severity = "high"
	}
	return s, nil
}

/* ------------------------------------------------------------------------- */
/*                             Deciders and path                              */
/* ------------------------------------------------------------------------- */

// askRoute is the responder group an ask goes to and why.
type askRoute struct {
	agentID   *uuid.UUID
	groupID   *uuid.UUID
	groupName string
	via       string
}

func askScopeGroup(tx *gorm.DB, ws uuid.UUID, kind, ref string) (*uuid.UUID, string, error) {
	var hs []struct {
		GroupID uuid.UUID `gorm:"column:group_id"`
		Name    string    `gorm:"column:name"`
	}
	if err := tx.Raw(`SELECT s.group_id, g.name FROM responder_group_scope s
	        JOIN responder_group g ON g.workspace_id = s.workspace_id AND g.id = s.group_id
	        WHERE s.workspace_id = ? AND s.scope_kind = ? AND s.scope_ref = ?`, ws, kind, ref).Scan(&hs).Error; err != nil {
		return nil, "", err
	}
	if len(hs) == 0 {
		return nil, "", nil
	}
	return &hs[0].GroupID, hs[0].Name, nil
}

func askDefaultGroup(tx *gorm.DB, ws uuid.UUID) (*uuid.UUID, string, error) {
	var hs []struct {
		ID   uuid.UUID `gorm:"column:id"`
		Name string    `gorm:"column:name"`
	}
	if err := tx.Raw(`SELECT id, name FROM responder_group WHERE workspace_id = ? AND is_default`, ws).Scan(&hs).Error; err != nil {
		return nil, "", err
	}
	if len(hs) == 0 {
		return nil, "", nil
	}
	return &hs[0].ID, hs[0].Name, nil
}

// resolveAskRoute applies the precedence: W7's resolution for the agent
// (agent scope, then its estate scopes), then the object's estate scope,
// then the default group.
func resolveAskRoute(tx *gorm.DB, ws uuid.UUID, subj askSubject, hint *uuid.UUID, now time.Time) (askRoute, error) {
	r := askRoute{via: ResponderViaNone}
	if err := ensureDefaultResponderGroup(tx, ws); err != nil {
		return r, err
	}
	agent := subj.agentID
	if hint != nil {
		if _, err := loadAgent(tx, ws, *hint, false); err == nil {
			agent = hint
		}
	}
	r.agentID = agent
	if agent != nil {
		res, err := resolveResponder(tx, ws, *agent, now)
		if err != nil {
			return r, err
		}
		if res.GroupID != nil && res.Via != ResponderViaDefault && res.Via != ResponderViaNone {
			r.groupID, r.groupName, r.via = res.GroupID, res.GroupName, res.Via
			return r, nil
		}
	}
	for _, sc := range subj.scopes {
		g, name, err := askScopeGroup(tx, ws, sc.ScopeKind, sc.ScopeRef)
		if err != nil {
			return r, err
		}
		if g != nil {
			r.groupID, r.groupName, r.via = g, name, sc.ScopeKind
			return r, nil
		}
	}
	g, name, err := askDefaultGroup(tx, ws)
	if err != nil {
		return r, err
	}
	if g != nil {
		r.groupID, r.groupName, r.via = g, name, ResponderViaDefault
	}
	return r, nil
}

// workspaceAdmins are the active members holding an admin role.
func workspaceAdmins(tx *gorm.DB, ws uuid.UUID) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	err := tx.Raw(`SELECT DISTINCT m.user_id FROM workspace_memberships m JOIN roles r ON r.id = m.role_id
	        WHERE m.workspace_id = ? AND m.status = 'active' AND m.user_id IS NOT NULL AND LOWER(r.name) IN ?`,
		ws, workspaceAdminRoles).Scan(&ids).Error
	return ids, err
}

// buildAskPath is the escalation chain: named deciders, the group, its leads
// (when the group has other members too), the default group, the admins.
func buildAskPath(tx *gorm.DB, ws uuid.UUID, route askRoute, named []uuid.UUID, now time.Time) ([]AskStep, error) {
	var path []AskStep
	if len(named) > 0 {
		path = append(path, AskStep{Kind: AskStepUsers, UserIDs: named, Label: "Named deciders"})
	}
	def, defName, err := askDefaultGroup(tx, ws)
	if err != nil {
		return nil, err
	}
	if route.groupID != nil {
		g := *route.groupID
		path = append(path, AskStep{Kind: AskStepGroup, GroupID: &g, Label: route.groupName})
		ds, err := groupDeciders(tx, ws, g, now)
		if err != nil {
			return nil, err
		}
		leads := 0
		for _, d := range ds {
			if d.Role == "lead" {
				leads++
			}
		}
		if leads > 0 && leads < len(ds) {
			path = append(path, AskStep{Kind: AskStepGroupLeads, GroupID: &g, Label: "Leads of " + route.groupName})
		}
	}
	if def != nil && (route.groupID == nil || *route.groupID != *def) {
		d := *def
		path = append(path, AskStep{Kind: AskStepGroup, GroupID: &d, Label: defName})
	}
	path = append(path, AskStep{Kind: AskStepAdmins, Label: "Workspace administrators"})
	return path, nil
}

// askStepDeciders are the people who decide at a step now: active members,
// never an excluded person.
func askStepDeciders(tx *gorm.DB, ws uuid.UUID, st AskStep, excluded map[uuid.UUID]bool, now time.Time) ([]uuid.UUID, error) {
	var cand []uuid.UUID
	switch st.Kind {
	case AskStepGroup, AskStepGroupLeads:
		if st.GroupID == nil {
			return nil, nil
		}
		ds, err := groupDeciders(tx, ws, *st.GroupID, now)
		if err != nil {
			return nil, err
		}
		for _, d := range ds {
			if st.Kind == AskStepGroupLeads && d.Role != "lead" {
				continue
			}
			cand = append(cand, d.UserID)
		}
	case AskStepUsers:
		cand = st.UserIDs
	case AskStepAdmins:
		var err error
		if cand, err = workspaceAdmins(tx, ws); err != nil {
			return nil, err
		}
	}
	seen := map[uuid.UUID]bool{}
	var keep []uuid.UUID
	for _, id := range cand {
		if id == uuid.Nil || seen[id] || excluded[id] {
			continue
		}
		seen[id] = true
		keep = append(keep, id)
	}
	if len(keep) == 0 {
		return []uuid.UUID{}, nil
	}
	active, err := WorkspaceMemberDirectory{}.ActiveMembers(tx, ws, keep)
	if err != nil {
		return nil, err
	}
	out := make([]uuid.UUID, 0, len(keep))
	for _, id := range keep {
		if _, ok := active[id]; ok {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}

// pickAskStep is the first step at or after from with someone to decide
// (-1 when none).
func pickAskStep(tx *gorm.DB, ws uuid.UUID, path []AskStep, from int, excluded map[uuid.UUID]bool, now time.Time) (int, []uuid.UUID, error) {
	for i := from; i < len(path); i++ {
		ds, err := askStepDeciders(tx, ws, path[i], excluded, now)
		if err != nil {
			return -1, nil, err
		}
		if len(ds) > 0 {
			return i, ds, nil
		}
	}
	return -1, nil, nil
}

func askStepFields(st AskStep, deciders []uuid.UUID) (group, user *uuid.UUID) {
	if st.Kind == AskStepGroup || st.Kind == AskStepGroupLeads {
		group = st.GroupID
	}
	if st.Kind == AskStepUsers && len(deciders) == 1 {
		u := deciders[0]
		user = &u
	}
	return group, user
}

/* ------------------------------------------------------------------------- */
/*                                   Create                                   */
/* ------------------------------------------------------------------------- */

func appendAskEvent(tx *gorm.DB, ws, askID uuid.UUID, kind string, step int, actorKind, actorID, channel string, detail map[string]any) error {
	if detail == nil {
		detail = map[string]any{}
	}
	raw, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	return tx.Exec(`INSERT INTO agent_ask_event (workspace_id, ask_id, kind, step, actor_kind, actor_id, channel, detail)
	        VALUES (?, ?, ?, ?, ?, ?, ?, ?::jsonb)`, ws, askID, kind, step, actorKind, actorID, channel, string(raw)).Error
}

func askGovPayload(r *agentAskRow, extra map[string]any) map[string]any {
	p := map[string]any{"ask_id": r.ID, "about_kind": r.AboutKind, "about_id": r.AboutID, "severity": r.Severity,
		"tier": r.Tier, "step": r.Step, "state": r.State}
	if r.AgentID != nil {
		p["agent_id"] = *r.AgentID
	}
	if r.CaseID != nil {
		p["case_id"] = *r.CaseID
	}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

// CreateAsk raises an ask in the caller's transaction (a savepoint under
// row-level security for ws): the server resolves the deciders and the due
// time, logs it and queues its delivery. With a DedupeKey, an open ask of
// that key is returned instead of a new one. W6's gateway holds and W2's
// platform stops call it.
func CreateAsk(ctx context.Context, tx *gorm.DB, ws uuid.UUID, in AskInput) (uuid.UUID, error) {
	if ctx == nil {
		ctx = tx.Statement.Context
	}
	var id uuid.UUID
	err := tenancy.InWorkspace(ctx, tx, ws, func(tx *gorm.DB) error {
		row, _, err := createAskTx(tx, ws, in, time.Now().UTC())
		if row != nil {
			id = row.ID
		}
		return err
	})
	return id, err
}

// raiseSystemAskTx raises an ask for a governance event writer (W7's
// agent.ask_needed): the event stays the record; an ask that cannot be raised
// (e.g. the schema is not there yet) is logged and never fails the writer.
func raiseSystemAskTx(tx *gorm.DB, ws uuid.UUID, in AskInput) {
	err := tx.Transaction(func(sp *gorm.DB) error {
		_, err := CreateAsk(sp.Statement.Context, sp, ws, in)
		return err
	})
	if err != nil {
		log.Printf("[agent-asks] workspace %s: ask about %s %s not raised: %v", ws, in.AboutKind, in.AboutID, err)
	}
}

func createAskTx(tx *gorm.DB, ws uuid.UUID, in AskInput, now time.Time) (*agentAskRow, bool, error) {
	if err := ValidateAskInput(&in, now); err != nil {
		return nil, false, err
	}
	if in.DedupeKey != "" {
		var ids []uuid.UUID
		if err := tx.Raw(`SELECT id FROM agent_ask WHERE workspace_id = ? AND dedupe_key = ? AND state IN ('open', 'pending_step_up')`,
			ws, in.DedupeKey).Scan(&ids).Error; err != nil {
			return nil, false, err
		}
		if len(ids) > 0 {
			r, err := readAgentAsk(tx, ws, ids[0], false)
			return r, false, err
		}
	}
	subj, err := readAskSubject(tx, ws, in.AboutKind, in.AboutID)
	if err != nil {
		return nil, false, err
	}
	caseID := subj.caseID
	if caseID == nil && in.CaseID != nil {
		if _, err := getAgentCase(tx, ws, *in.CaseID); err != nil {
			var ge *GovError
			if errors.As(err, &ge) && ge.Status == http.StatusNotFound {
				return nil, false, GovBadParam("case_id", "case_id names no case of this workspace.")
			}
			return nil, false, err
		}
		caseID = in.CaseID
	}
	severity := in.Severity
	if severity == "" {
		severity = subj.severity
	}
	route, err := resolveAskRoute(tx, ws, subj, in.AgentID, now)
	if err != nil {
		return nil, false, err
	}
	var named []uuid.UUID
	for _, d := range in.Deciders {
		if d != uuid.Nil {
			named = append(named, d)
		}
	}
	path, err := buildAskPath(tx, ws, route, named, now)
	if err != nil {
		return nil, false, err
	}
	excludedSet := map[uuid.UUID]bool{}
	var excluded []uuid.UUID
	add := func(id *uuid.UUID) {
		if id != nil && *id != uuid.Nil && !excludedSet[*id] {
			excludedSet[*id] = true
			excluded = append(excluded, *id)
		}
	}
	add(in.RequesterUserID)
	add(in.CreatedBy)
	for i := range in.ExcludeUserIDs {
		add(&in.ExcludeUserIDs[i])
	}
	step, deciders, err := pickAskStep(tx, ws, path, 0, excludedSet, now)
	if err != nil {
		return nil, false, err
	}
	noDecider := step < 0
	if noDecider {
		step, deciders = len(path)-1, []uuid.UUID{}
	}
	group, user := askStepFields(path[step], deciders)
	policy, err := readAgentAskPolicy(tx, ws)
	if err != nil {
		return nil, false, err
	}
	due, dueSource := AgentAskDue(policy, severity, now, in.ExternalDeadline)
	choices, _ := json.Marshal(in.Choices)
	pathRaw, _ := json.Marshal(path)
	if in.Context == nil {
		in.Context = map[string]any{}
	}
	ctxRaw, err := json.Marshal(in.Context)
	if err != nil {
		return nil, false, GovBadParam("context", "context must be JSON.")
	}
	createdKind := "system"
	if in.CreatedBy != nil {
		createdKind = "user"
	}
	var dedupe *string
	if in.DedupeKey != "" {
		dedupe = &in.DedupeKey
	}
	var extAt any
	if in.ExternalDeadline != nil {
		extAt = in.ExternalDeadline.UTC()
	}
	id := uuid.New()
	res := tx.Exec(`INSERT INTO agent_ask (id, workspace_id, about_kind, about_id, agent_id, case_id, question, choices, severity,
	        tier, role, decider_group_id, decider_user_id, deciders, resolved_via, path, step, excluded_user_ids, requester_user_id,
	        due_at, due_source, external_deadline_at, external_deadline_source, hours_per_step, created_by_kind, created_by,
	        dedupe_key, context, created_at, updated_at)
	        VALUES (?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?, ?::uuid[], ?, ?::jsonb, ?, ?::uuid[], ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?)
	        ON CONFLICT (workspace_id, dedupe_key) WHERE dedupe_key IS NOT NULL AND state IN ('open', 'pending_step_up') DO NOTHING`,
		id, ws, in.AboutKind, in.AboutID, route.agentID, caseID, in.Question, string(choices), severity, in.Tier, in.Role,
		group, user, uuidStrings(deciders), route.via, string(pathRaw), step, uuidStrings(excluded), in.RequesterUserID,
		due, dueSource, extAt, in.ExternalDeadlineSource, policy.HoursPerStep, createdKind, in.CreatedBy, dedupe,
		string(ctxRaw), now, now)
	if res.Error != nil {
		return nil, false, res.Error
	}
	if res.RowsAffected == 0 { // a concurrent raise of the same key won
		var ids []uuid.UUID
		if err := tx.Raw(`SELECT id FROM agent_ask WHERE workspace_id = ? AND dedupe_key = ? AND state IN ('open', 'pending_step_up')`,
			ws, in.DedupeKey).Scan(&ids).Error; err != nil || len(ids) == 0 {
			return nil, false, fmt.Errorf("ask dedupe conflict without an open ask: %v", err)
		}
		r, err := readAgentAsk(tx, ws, ids[0], false)
		return r, false, err
	}
	row, err := readAgentAsk(tx, ws, id, false)
	if err != nil {
		return nil, false, err
	}
	actorKind, actorID := "system", ""
	if in.CreatedBy != nil {
		actorKind, actorID = "user", in.CreatedBy.String()
	}
	detail := map[string]any{"via": route.via, "deciders": len(deciders), "due_source": dueSource}
	if noDecider {
		detail["no_decider"] = true
	}
	if err := appendAskEvent(tx, ws, id, AskEventAsked, step, actorKind, actorID, "", detail); err != nil {
		return nil, false, err
	}
	govKind := models.GovActorSystem
	if in.CreatedBy != nil {
		govKind = models.GovActorUser
	}
	if err := appendGovEvent(tx, ws, GovEventAskCreated, govKind, actorID, govEventRefs{}, askGovPayload(row,
		map[string]any{"via": route.via, "deciders": len(deciders), "due_at": due, "due_source": dueSource, "no_decider": noDecider})); err != nil {
		return nil, false, err
	}
	enqueueAskDeliveriesTx(tx, ws, row, policy, false)
	enqueueAskExternalsTx(tx, ws, row)
	return row, true, nil
}

/* ------------------------------------------------------------------------- */
/*                                  Service                                   */
/* ------------------------------------------------------------------------- */

// AgentAskService serves the ask routes and runs the escalation pass.
type AgentAskService struct {
	db  *gorm.DB
	now func() time.Time
}

// NewAgentAskService builds the service over db.
func NewAgentAskService(db *gorm.DB) *AgentAskService {
	return &AgentAskService{db: db, now: time.Now}
}

// WithClock replaces the clock (tests).
func (s *AgentAskService) WithClock(now func() time.Time) *AgentAskService {
	s.now = now
	return s
}

// AskCreateRequest is POST /asks. Who decides and when it is due are not
// in it.
type AskCreateRequest struct {
	AboutKind              string
	AboutID                string
	CaseID                 *uuid.UUID
	Question               string
	Choices                []AskChoice
	Tier                   int
	RequesterUserID        *uuid.UUID
	ExternalDeadline       *time.Time
	ExternalDeadlineSource string
}

// Create is POST /asks by a console member (tier 1). A remediation or a
// gateway call ask is raised by AuthSec only.
func (s *AgentAskService) Create(ctx context.Context, ws, actor uuid.UUID, req AskCreateRequest) (*AgentAskView, error) {
	switch req.AboutKind {
	case AskAboutRemediation, AskAboutGatewayCall:
		return nil, GovBadParam("about.kind", "Asks about a remediation or a gateway call are raised by AuthSec.")
	}
	a := actor
	in := AskInput{AboutKind: req.AboutKind, AboutID: req.AboutID, CaseID: req.CaseID, Question: req.Question,
		Choices: req.Choices, Tier: req.Tier, RequesterUserID: req.RequesterUserID, CreatedBy: &a,
		ExternalDeadline: req.ExternalDeadline, ExternalDeadlineSource: req.ExternalDeadlineSource}
	var out *AgentAskView
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		row, _, err := createAskTx(tx, ws, in, s.now().UTC())
		if err != nil {
			return err
		}
		v := row.view(actor)
		out = &v
		return nil
	})
	return out, err
}

// AgentAskFilter narrows GET /asks.
type AgentAskFilter struct {
	State     string
	Mine      bool
	Overdue   *bool
	AboutKind string
	AboutID   string
	CaseID    *uuid.UUID
	Cursor    string
	Limit     int
}

// List is GET /asks, newest first.
func (s *AgentAskService) List(ctx context.Context, ws, actor uuid.UUID, f AgentAskFilter) ([]AgentAskView, string, error) {
	switch f.State {
	case "", AskStateOpen, AskStatePendingStepUp, AskStateAnswered, AskStateWithdrawn, AskStateExpired:
	default:
		return nil, "", GovBadParam("state", "state must be open, pending_step_up, answered, withdrawn or expired.")
	}
	if f.AboutKind != "" && !validAskAbout(f.AboutKind) {
		return nil, "", GovBadParam("about_kind", "about_kind is not a kind of ask.")
	}
	if f.Limit <= 0 || f.Limit > MaxGovPage {
		f.Limit = 50
	}
	q := `SELECT ` + agentAskCols + ` FROM agent_ask WHERE workspace_id = ?`
	args := []any{ws}
	if f.State != "" {
		q += ` AND state = ?`
		args = append(args, f.State)
	}
	if f.Mine {
		q += ` AND state IN ('open', 'pending_step_up') AND ?::uuid = ANY(deciders) AND NOT (?::uuid = ANY(excluded_user_ids))
		       AND (requester_user_id IS NULL OR requester_user_id <> ?::uuid)`
		args = append(args, actor, actor, actor)
	}
	if f.Overdue != nil {
		q += ` AND overdue = ?`
		args = append(args, *f.Overdue)
	}
	if f.AboutKind != "" {
		q += ` AND about_kind = ?`
		args = append(args, f.AboutKind)
	}
	if f.AboutID != "" {
		q += ` AND about_id = ?`
		args = append(args, f.AboutID)
	}
	if f.CaseID != nil {
		q += ` AND case_id = ?`
		args = append(args, *f.CaseID)
	}
	if f.Cursor != "" {
		t, id, err := decodeAgentCursor(f.Cursor)
		if err != nil {
			return nil, "", GovBadParam("cursor", "cursor is not one this API returned.")
		}
		q += ` AND (created_at, id) < (?, ?)`
		args = append(args, t, id)
	}
	q += ` ORDER BY created_at DESC, id DESC LIMIT ?`
	args = append(args, f.Limit+1)
	var rows []agentAskRow
	if err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		return tx.Raw(q, args...).Scan(&rows).Error
	}); err != nil {
		return nil, "", err
	}
	next := ""
	if len(rows) > f.Limit {
		rows = rows[:f.Limit]
		last := rows[len(rows)-1]
		next = encodeAgentCursor(last.CreatedAt, last.ID)
	}
	out := make([]AgentAskView, 0, len(rows))
	for i := range rows {
		out = append(out, rows[i].view(actor))
	}
	return out, next, nil
}

// Get is GET /asks/:id with its log and external items; can_answer says
// whether the actor decides it now.
func (s *AgentAskService) Get(ctx context.Context, ws, actor, id uuid.UUID) (*AgentAskView, error) {
	var out *AgentAskView
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		row, err := readAgentAsk(tx, ws, id, false)
		if err != nil {
			return err
		}
		v := row.view(actor)
		if err := tx.Raw(`SELECT id, kind, step, actor_kind, actor_id, channel, detail, created_at FROM agent_ask_event
		        WHERE workspace_id = ? AND ask_id = ? ORDER BY created_at, id`, ws, id).Scan(&v.Events).Error; err != nil {
			return err
		}
		if v.Events == nil {
			v.Events = []AgentAskEvent{}
		}
		if err := tx.Raw(`SELECT `+agentAskExternalCols+` FROM agent_ask_external WHERE workspace_id = ? AND ask_id = ?
		        ORDER BY created_at, id`, ws, id).Scan(&v.External).Error; err != nil {
			return err
		}
		if v.External == nil {
			v.External = []AgentAskExternalVw{}
		}
		can := false
		if actor != uuid.Nil && row.live() {
			can = checkAskDecider(tx, ws, row, actor, s.now()) == nil
		}
		v.CanAnswer = &can
		out = &v
		return nil
	})
	return out, err
}

const agentAskExternalCols = `id, provider, kind, ask_id, case_id, external_key, external_url, state, last_status, attempts,
	last_error, created_at, updated_at, resolved_at`

// readCaseAsks lists a case's asks for its detail (empty while 220 is absent).
func readCaseAsks(tx *gorm.DB, ws, caseID uuid.UUID) ([]AgentAskSummary, error) {
	out := []AgentAskSummary{}
	var present bool
	if err := tx.Raw(`SELECT to_regclass('public.agent_ask') IS NOT NULL`).Scan(&present).Error; err != nil || !present {
		return out, err
	}
	if err := tx.Raw(`SELECT id, about_kind, about_id, question, severity, state, overdue, due_at, step, answer_choice, answered_by,
	        answered_at, answer_channel, created_at FROM agent_ask WHERE workspace_id = ? AND case_id = ?
	        ORDER BY created_at, id`, ws, caseID).Scan(&out).Error; err != nil {
		return nil, err
	}
	if out == nil {
		out = []AgentAskSummary{}
	}
	return out, nil
}

/* ------------------------------------------------------------------------- */
/*                                  Answers                                   */
/* ------------------------------------------------------------------------- */

// checkAskDecider is nil when user decides row's current step now.
func checkAskDecider(tx *gorm.DB, ws uuid.UUID, row *agentAskRow, user uuid.UUID, now time.Time) error {
	if row.RequesterUserID != nil && *row.RequesterUserID == user {
		return govErr(http.StatusForbidden, GovCodeRequesterDecides, "You asked for what this ask decides; someone else must answer it.", nil)
	}
	path := row.path()
	if row.Step < 0 || row.Step >= len(path) {
		return govErr(http.StatusForbidden, GovCodeNotDecider, "You do not decide this ask now.", nil)
	}
	ds, err := askStepDeciders(tx, ws, path[row.Step], row.excluded(), now)
	if err != nil {
		return err
	}
	for _, d := range ds {
		if d == user {
			return nil
		}
	}
	return govErr(http.StatusForbidden, GovCodeNotDecider, "You do not decide this ask now.", nil)
}

func askNotOpen(state string) error {
	return govConflict(GovCodeAskNotOpen, "This ask is no longer open.", map[string]any{"state": state})
}

func askChoiceValid(row *agentAskRow, choice string) bool {
	for _, c := range row.choices() {
		if c.ID == choice {
			return true
		}
	}
	return false
}

// AskAnsweredHook runs in the answering transaction when an ask about its
// kind takes effect (W6's held gateway calls, W8's remediations).
type AskAnsweredHook func(tx *gorm.DB, ws uuid.UUID, ask AgentAskView) error

var (
	askHooksMu sync.RWMutex
	askHooks   = map[string][]AskAnsweredHook{}
)

// RegisterAskAnsweredHook adds a hook for asks about kind (init time).
func RegisterAskAnsweredHook(kind string, h AskAnsweredHook) {
	askHooksMu.Lock()
	defer askHooksMu.Unlock()
	askHooks[kind] = append(askHooks[kind], h)
}

func askAnsweredHooks(kind string) []AskAnsweredHook {
	askHooksMu.RLock()
	defer askHooksMu.RUnlock()
	return append([]AskAnsweredHook(nil), askHooks[kind]...)
}

// closeAskPagesTx resolves the pages of an ask that closed: an untriggered
// page is not needed; a triggered one is resolved by the external worker.
func closeAskPagesTx(tx *gorm.DB, ws, askID uuid.UUID, now time.Time) error {
	return tx.Exec(`UPDATE agent_ask_external SET
	          state = CASE WHEN state = 'pending' THEN 'resolved' ELSE 'resolving' END,
	          resolved_at = CASE WHEN state = 'pending' THEN ?::timestamptz ELSE NULL END,
	          last_status = CASE WHEN state = 'pending' THEN 'not_needed' ELSE last_status END,
	          next_attempt_at = ?, attempts = 0, updated_at = ?
	        WHERE workspace_id = ? AND ask_id = ? AND kind = 'page' AND state IN ('pending', 'open')`,
		now, now, now, ws, askID).Error
}

// answerAskTx records an answer taking effect.
func answerAskTx(tx *gorm.DB, ws uuid.UUID, row *agentAskRow, user uuid.UUID, choice, note, channel string, confirmed bool, now time.Time) (*agentAskRow, error) {
	if err := tx.Exec(`UPDATE agent_ask SET state = 'answered', answer_choice = ?, answered_by = ?, answered_at = ?, answer_channel = ?,
	        answer_note = ?, pending_choice = NULL, pending_by = NULL, pending_at = NULL, updated_at = ?
	        WHERE workspace_id = ? AND id = ?`, choice, user, now, channel, note, now, ws, row.ID).Error; err != nil {
		return nil, err
	}
	actorKind := "user"
	if confirmed {
		if err := appendAskEvent(tx, ws, row.ID, AskEventStepUpConfirmed, row.Step, actorKind, user.String(), AskChannelConsole,
			map[string]any{"choice": choice}); err != nil {
			return nil, err
		}
	}
	if err := appendAskEvent(tx, ws, row.ID, AskEventAnswered, row.Step, actorKind, user.String(), channel,
		map[string]any{"choice": choice, "confirmed_in_console": confirmed}); err != nil {
		return nil, err
	}
	after, err := readAgentAsk(tx, ws, row.ID, false)
	if err != nil {
		return nil, err
	}
	if err := appendGovEvent(tx, ws, GovEventAskAnswered, models.GovActorUser, user.String(), govEventRefs{},
		askGovPayload(after, map[string]any{"choice": choice, "channel": channel, "confirmed_in_console": confirmed})); err != nil {
		return nil, err
	}
	if err := closeAskPagesTx(tx, ws, row.ID, now); err != nil {
		return nil, err
	}
	v := after.view(user)
	for _, h := range askAnsweredHooks(after.AboutKind) {
		if err := h(tx, ws, v); err != nil {
			return nil, err
		}
	}
	return after, nil
}

// Answer is POST /asks/:id/answer from the console.
func (s *AgentAskService) Answer(ctx context.Context, ws, id, actor uuid.UUID, choice, note string) (*AgentAskView, error) {
	note = strings.TrimSpace(note)
	if utf8.RuneCountInString(note) > AskMaxReason {
		return nil, GovBadParam("note", "note is at most 1000 characters.")
	}
	now := s.now().UTC()
	var out *AgentAskView
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		row, err := readAgentAsk(tx, ws, id, true)
		if err != nil {
			return err
		}
		if !row.live() {
			return askNotOpen(row.State)
		}
		if err := checkAskDecider(tx, ws, row, actor, now); err != nil {
			return err
		}
		if !askChoiceValid(row, choice) {
			return GovBadParam("choice", "choice must be one of the ask's choices.")
		}
		after, err := answerAskTx(tx, ws, row, actor, choice, note, AskChannelConsole, false, now)
		if err != nil {
			return err
		}
		v := after.view(actor)
		out = &v
		return nil
	})
	return out, err
}

// AnswerFromSlack records a Slack answer: in effect at once for tier 0-1;
// for tier 2+ it waits (pending_step_up) for the same person's console
// confirmation. step is the step the clicked message was posted for.
func (s *AgentAskService) AnswerFromSlack(ctx context.Context, ws, id, actor uuid.UUID, choice string, step int) (*AgentAskView, bool, error) {
	now := s.now().UTC()
	var out *AgentAskView
	pending := false
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		row, err := readAgentAsk(tx, ws, id, true)
		if err != nil {
			return err
		}
		if !row.live() {
			return askNotOpen(row.State)
		}
		if row.Step != step {
			return govConflict(GovCodeAskChanged, "The ask moved on since this message was posted; open AuthSec.", nil)
		}
		if err := checkAskDecider(tx, ws, row, actor, now); err != nil {
			return err
		}
		if !askChoiceValid(row, choice) {
			return GovBadParam("choice", "choice must be one of the ask's choices.")
		}
		if !askAnswerNeedsStepUp(row.Tier, AskChannelSlack) {
			after, err := answerAskTx(tx, ws, row, actor, choice, "", AskChannelSlack, false, now)
			if err != nil {
				return err
			}
			v := after.view(actor)
			out = &v
			return nil
		}
		pending = true
		if err := tx.Exec(`UPDATE agent_ask SET state = 'pending_step_up', pending_choice = ?, pending_by = ?, pending_at = ?, updated_at = ?
		        WHERE workspace_id = ? AND id = ?`, choice, actor, now, now, ws, id).Error; err != nil {
			return err
		}
		if err := appendAskEvent(tx, ws, id, AskEventStepUpPending, row.Step, "user", actor.String(), AskChannelSlack,
			map[string]any{"choice": choice, "tier": row.Tier}); err != nil {
			return err
		}
		after, err := readAgentAsk(tx, ws, id, false)
		if err != nil {
			return err
		}
		if err := appendGovEvent(tx, ws, GovEventAskStepUpPending, models.GovActorUser, actor.String(), govEventRefs{},
			askGovPayload(after, map[string]any{"choice": choice, "channel": AskChannelSlack})); err != nil {
			return err
		}
		v := after.view(actor)
		out = &v
		return nil
	})
	return out, pending, err
}

// Confirm is POST /asks/:id/confirm: the person who answered a tier-2+ ask
// from Slack confirms it in the console, where it takes effect.
func (s *AgentAskService) Confirm(ctx context.Context, ws, id, actor uuid.UUID) (*AgentAskView, error) {
	now := s.now().UTC()
	var out *AgentAskView
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		row, err := readAgentAsk(tx, ws, id, true)
		if err != nil {
			return err
		}
		if row.State != AskStatePendingStepUp {
			return govConflict(GovCodeStepUpNotPending, "No Slack answer waits for confirmation on this ask.", map[string]any{"state": row.State})
		}
		if row.PendingBy == nil || *row.PendingBy != actor {
			return govErr(http.StatusForbidden, GovCodeStepUpOtherPerson, "Only the person who answered in Slack confirms it.", nil)
		}
		if err := checkAskDecider(tx, ws, row, actor, now); err != nil {
			return err
		}
		if row.PendingChoice == nil || !askChoiceValid(row, *row.PendingChoice) {
			return govConflict(GovCodeAskChanged, "The answer waiting is no longer one of the ask's choices.", nil)
		}
		after, err := answerAskTx(tx, ws, row, actor, *row.PendingChoice, "", AskChannelSlack, true, now)
		if err != nil {
			return err
		}
		v := after.view(actor)
		out = &v
		return nil
	})
	return out, err
}

// NotMine is POST /asks/:id/not-mine: a decider says the ask is not theirs;
// it moves to the next step with someone to decide, and they are excluded.
func (s *AgentAskService) NotMine(ctx context.Context, ws, id, actor uuid.UUID, reason string) (*AgentAskView, error) {
	return s.notMine(ctx, ws, id, actor, reason, AskChannelConsole, -1)
}

func (s *AgentAskService) notMine(ctx context.Context, ws, id, actor uuid.UUID, reason, channel string, step int) (*AgentAskView, error) {
	reason = strings.TrimSpace(reason)
	if utf8.RuneCountInString(reason) > AskMaxReason {
		return nil, GovBadParam("reason", "reason is at most 1000 characters.")
	}
	now := s.now().UTC()
	var out *AgentAskView
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		row, err := readAgentAsk(tx, ws, id, true)
		if err != nil {
			return err
		}
		if !row.live() {
			return askNotOpen(row.State)
		}
		if step >= 0 && row.Step != step {
			return govConflict(GovCodeAskChanged, "The ask moved on since this message was posted; open AuthSec.", nil)
		}
		if err := checkAskDecider(tx, ws, row, actor, now); err != nil {
			return err
		}
		excl := row.excluded()
		excl[actor] = true
		moved, err := moveAskTx(tx, ws, row, excl, now, AskEventDisputed, "user", actor.String(), channel,
			map[string]any{"reason": reason})
		if err != nil {
			return err
		}
		if !moved {
			return govConflict(GovCodeNoNextStep, "No one after you can decide this ask; answer it, or ask a workspace administrator.", nil)
		}
		after, err := readAgentAsk(tx, ws, id, false)
		if err != nil {
			return err
		}
		v := after.view(actor)
		out = &v
		return nil
	})
	return out, err
}

// Withdraw is POST /asks/:id/withdraw: the creator, or a holder of
// governance:approve.
func (s *AgentAskService) Withdraw(ctx context.Context, ws, id, actor uuid.UUID, reason string) (*AgentAskView, error) {
	reason = strings.TrimSpace(reason)
	if utf8.RuneCountInString(reason) > AskMaxReason {
		return nil, GovBadParam("reason", "reason is at most 1000 characters.")
	}
	now := s.now().UTC()
	var out *AgentAskView
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		row, err := readAgentAsk(tx, ws, id, true)
		if err != nil {
			return err
		}
		if row.CreatedBy == nil || *row.CreatedBy != actor {
			ok, err := WorkspaceUserHoldsPermission(tx, ws, actor, "governance", "approve")
			if err != nil {
				return err
			}
			if !ok {
				return govErr(http.StatusForbidden, GovCodeApproverRequired, "Only the ask's creator or a holder of governance:approve withdraws it.", nil)
			}
		}
		if !row.live() {
			return askNotOpen(row.State)
		}
		after, err := closeAskTx(tx, ws, row, AskStateWithdrawn, &actor, reason, now)
		if err != nil {
			return err
		}
		v := after.view(actor)
		out = &v
		return nil
	})
	return out, err
}

// closeAskTx withdraws or expires a live ask.
func closeAskTx(tx *gorm.DB, ws uuid.UUID, row *agentAskRow, state string, actor *uuid.UUID, reason string, now time.Time) (*agentAskRow, error) {
	ev, gov := AskEventWithdrawn, GovEventAskWithdrawn
	if state == AskStateExpired {
		ev, gov = AskEventExpired, GovEventAskExpired
	}
	var by any
	actorKind, actorID, govKind := "system", "", models.GovActorSystem
	if actor != nil {
		by, actorKind, actorID, govKind = *actor, "user", actor.String(), models.GovActorUser
	}
	// withdrawn_at records when the ask was closed unanswered (withdrawn or
	// expired); the state says which.
	q := `UPDATE agent_ask SET state = ?, withdrawn_by = ?, withdrawn_at = ?, withdraw_reason = ?, pending_choice = NULL,
	        pending_by = NULL, pending_at = NULL, updated_at = ? WHERE workspace_id = ? AND id = ?`
	if state == AskStateExpired {
		q = `UPDATE agent_ask SET state = ?, withdrawn_by = ?, withdrawn_at = NULL, withdraw_reason = ?, pending_choice = NULL,
	        pending_by = NULL, pending_at = NULL, updated_at = ? WHERE workspace_id = ? AND id = ?`
		if err := tx.Exec(q, state, by, reason, now, ws, row.ID).Error; err != nil {
			return nil, err
		}
	} else if err := tx.Exec(q, state, by, now, reason, now, ws, row.ID).Error; err != nil {
		return nil, err
	}
	if err := appendAskEvent(tx, ws, row.ID, ev, row.Step, actorKind, actorID, "", map[string]any{"reason": reason}); err != nil {
		return nil, err
	}
	after, err := readAgentAsk(tx, ws, row.ID, false)
	if err != nil {
		return nil, err
	}
	if err := appendGovEvent(tx, ws, gov, govKind, actorID, govEventRefs{}, askGovPayload(after, map[string]any{"reason": reason})); err != nil {
		return nil, err
	}
	return after, closeAskPagesTx(tx, ws, row.ID, now)
}

// ExpireAsk closes a live ask unanswered because its subject ended (W6: the
// held call timed out). An ask already closed is left as it is.
func ExpireAsk(ctx context.Context, tx *gorm.DB, ws, id uuid.UUID, reason string) error {
	if ctx == nil {
		ctx = tx.Statement.Context
	}
	return tenancy.InWorkspace(ctx, tx, ws, func(tx *gorm.DB) error {
		row, err := readAgentAsk(tx, ws, id, true)
		if err != nil || !row.live() {
			return err
		}
		_, err = closeAskTx(tx, ws, row, AskStateExpired, nil, clipText(reason, AskMaxReason), time.Now().UTC())
		return err
	})
}

/* ------------------------------------------------------------------------- */
/*                                 Escalation                                 */
/* ------------------------------------------------------------------------- */

// moveAskTx moves a live ask to the next step with someone to decide (with
// excl as its excluded people), due again hours_per_step from now, and queues
// its delivery to the new deciders. kind is escalated (due) or disputed
// (not mine). It reports false, changing nothing, when no step is left.
func moveAskTx(tx *gorm.DB, ws uuid.UUID, row *agentAskRow, excl map[uuid.UUID]bool, now time.Time, kind, actorKind, actorID,
	channel string, detail map[string]any) (bool, error) {
	path := row.path()
	next, deciders, err := pickAskStep(tx, ws, path, row.Step+1, excl, now)
	if err != nil || next < 0 {
		return false, err
	}
	group, user := askStepFields(path[next], deciders)
	excluded := make([]uuid.UUID, 0, len(excl))
	for id := range excl {
		excluded = append(excluded, id)
	}
	sort.Slice(excluded, func(i, j int) bool { return excluded[i].String() < excluded[j].String() })
	due := now.Add(time.Duration(row.HoursPerStep) * time.Hour)
	lapsed := row.State == AskStatePendingStepUp
	if err := tx.Exec(`UPDATE agent_ask SET step = ?, decider_group_id = ?, decider_user_id = ?, deciders = ?::uuid[],
	        excluded_user_ids = ?::uuid[], due_at = ?, state = 'open', pending_choice = NULL, pending_by = NULL, pending_at = NULL,
	        updated_at = ? WHERE workspace_id = ? AND id = ?`,
		next, group, user, uuidStrings(deciders), uuidStrings(excluded), due, now, ws, row.ID).Error; err != nil {
		return false, err
	}
	if lapsed {
		if err := appendAskEvent(tx, ws, row.ID, AskEventStepUpLapsed, row.Step, "system", "", "",
			map[string]any{"choice": row.PendingChoice, "pending_by": row.PendingBy}); err != nil {
			return false, err
		}
	}
	if detail == nil {
		detail = map[string]any{}
	}
	detail["from_step"], detail["to_step"], detail["deciders"], detail["due_at"] = row.Step, next, len(deciders), due
	if err := appendAskEvent(tx, ws, row.ID, kind, next, actorKind, actorID, channel, detail); err != nil {
		return false, err
	}
	after, err := readAgentAsk(tx, ws, row.ID, false)
	if err != nil {
		return false, err
	}
	gov, govKind := GovEventAskEscalated, models.GovActorSystem
	if kind == AskEventDisputed {
		gov, govKind = GovEventAskDisputed, models.GovActorUser
	}
	if err := appendGovEvent(tx, ws, gov, govKind, actorID, govEventRefs{}, askGovPayload(after,
		map[string]any{"from_step": row.Step, "to_step": next, "deciders": len(deciders), "due_at": due})); err != nil {
		return false, err
	}
	policy, err := readAgentAskPolicy(tx, ws)
	if err != nil {
		return false, err
	}
	enqueueAskDeliveriesTx(tx, ws, after, policy, true)
	return true, nil
}

// escalateAskTx is the due pass of one ask: the next step, or overdue at
// the end of its path (it stays open).
func escalateAskTx(tx *gorm.DB, ws uuid.UUID, row *agentAskRow, now time.Time) (bool, error) {
	moved, err := moveAskTx(tx, ws, row, row.excluded(), now, AskEventEscalated, "system", "", "", nil)
	if err != nil || moved {
		return moved, err
	}
	if err := tx.Exec(`UPDATE agent_ask SET overdue = true, overdue_at = ?, updated_at = ? WHERE workspace_id = ? AND id = ?`,
		now, now, ws, row.ID).Error; err != nil {
		return false, err
	}
	if err := appendAskEvent(tx, ws, row.ID, AskEventOverdue, row.Step, "system", "", "", map[string]any{"due_at": row.DueAt}); err != nil {
		return false, err
	}
	after, err := readAgentAsk(tx, ws, row.ID, false)
	if err != nil {
		return false, err
	}
	return false, appendGovEvent(tx, ws, GovEventAskOverdue, models.GovActorSystem, "", govEventRefs{},
		askGovPayload(after, map[string]any{"due_at": row.DueAt, "end_of_path": true}))
}

// EscalateWorkspace runs the due pass for one workspace; it returns how many
// asks moved and how many became overdue.
func (s *AgentAskService) EscalateWorkspace(ctx context.Context, ws uuid.UUID) (moved, overdue int, err error) {
	now := s.now().UTC()
	err = tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		var rows []agentAskRow
		if err := tx.Raw(`SELECT `+agentAskCols+` FROM agent_ask WHERE workspace_id = ? AND state IN ('open', 'pending_step_up')
		        AND NOT overdue AND due_at <= ? ORDER BY due_at, id LIMIT 200 FOR UPDATE SKIP LOCKED`, ws, now).Scan(&rows).Error; err != nil {
			return err
		}
		for i := range rows {
			m, err := escalateAskTx(tx, ws, &rows[i], now)
			if err != nil {
				return err
			}
			if m {
				moved++
			} else {
				overdue++
			}
		}
		return nil
	})
	return moved, overdue, err
}

// EscalateDue runs the due pass for every workspace with a due ask.
func (s *AgentAskService) EscalateDue(ctx context.Context) (int, error) {
	now := s.now().UTC()
	var wss []uuid.UUID
	// TENANT-EXEMPT: the escalation worker runs across workspaces (no request tenant) and lists workspace ids only; each workspace's asks are escalated in its own workspace-bound transaction (tenancy.InWorkspace).
	if err := s.db.WithContext(ctx).Raw(`SELECT DISTINCT workspace_id FROM agent_ask
	        WHERE state IN ('open', 'pending_step_up') AND NOT overdue AND due_at <= ?`, now).Scan(&wss).Error; err != nil {
		return 0, err
	}
	n := 0
	var first error
	for _, ws := range wss {
		if ctx.Err() != nil {
			break
		}
		m, o, err := s.EscalateWorkspace(ctx, ws)
		n += m + o
		if err != nil && first == nil {
			first = fmt.Errorf("workspace %s: %w", ws, err)
		}
	}
	return n, first
}
