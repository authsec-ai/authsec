package igagov

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Phase 3 R3 -- agent runtime controls (SPEC-iga-phase3-policy.md §12.4,
// requirements R-01..R-11; R-08's brokered sessions moved here by DECISION
// R2-1). This file is pure: the runtime_controls intent, its validation and
// hash, the decision function, the Cedar compilation for AgentCore, and the
// brokered-session policy. The database, the routes and AWS live behind
// IGA_POLICY_R3 (services/iga_gov_r3*.go, internal/agentcore,
// internal/awsbroker).
//
// THERE IS NO R3 IMPLEMENTATION SPEC. §12.4 requires four contracts to be
// established in a lab account before one can be written (AgentCore policy
// API surface; the approval flow; gateway-only routing proof; the budget
// decision path). None has been established. Everything below is therefore a
// DECISION for review (Aditya), and everything that touches AgentCore or STS
// is UNVERIFIED against a real account.
//
// DECISION R3-1 (rules engine, requirements §5.3): AuthSec's runtime
//   decision endpoint evaluates the typed runtime_controls intent itself (a
//   fixed evaluator: allow-list match, approval designation, budgets) rather
//   than embedding Cedar or OPA. The same intent is COMPILED to Cedar for
//   AgentCore Policy, which is the engine §12.4 says to evaluate; AuthSec does
//   not re-implement Cedar. Default deny, and a forbid-wins reading of
//   several policies is replaced by DECISION R3-6.
// DECISION R3-2 (policy model): a runtime policy is an iga_gov_policy row of
//   family 'runtime' (049 already admits it; provider stays 'aws' because the
//   049 CHECK admits only aws and AgentCore is AWS). Its versions live in
//   iga_gov_runtime_version (062), not iga_gov_policy_version: R1a's version
//   table requires an evidence revision and its approval binds plans and
//   bundles that runtime intents do not have. Versions are immutable
//   (trigger), hashed like R1a intents (IntentHash, RFC 8785), created
//   straight into review (no compile step), approved with governance:approve
//   by someone other than the author, one approved per policy; approval
//   supersedes the previous approved version. Pausing or archiving the policy
//   through the R1a routes takes it out of force (fail closed: its agents get
//   no_policy).
// DECISION R3-3 (credential, R-02): the runtime endpoints accept ONLY a
//   delegated SPIFFE JWT-SVID (SpiffeAuthMiddleware: signature against the
//   workspace's trust bundle, audience, and the delegation token being the
//   agent's ACTIVE one). The workspace is the bundle that verified it; the
//   workload is the SVID's spiffe:// subject; the initiating human is the
//   signed user_id claim of that exact, active delegation token. A
//   non-delegated SVID, a human session or any other credential is refused
//   (403 delegated_agent_required). Nothing in the body names a workspace,
//   an agent or a human.
// DECISION R3-4 (arguments, R-03 / R-11): the agent sends either the
//   arguments (AuthSec digests them: sha256 of their RFC 8785 form) or only
//   their digest. Every decision binds the digest; a PEP redeeming the
//   decision must present the same digest. Argument values are kept only when
//   the workspace chose 'redacted' retention, with its redact keys replaced,
//   strings truncated, and pruned after retention_days. Prompts are never
//   accepted; context is limited to RuntimeContextKeys.
// DECISION R3-5 (decision record, R-03): an allow carries a random,
//   single-use decision token (only its sha256 is stored) and expires after
//   the workspace's decision_ttl_seconds (5..300, default 60). Its
//   binding_hash covers workspace, agent, human, tool, action, target,
//   arguments digest, policy version, intent hash, approval and expiry. The
//   row's binding columns are immutable (062 trigger). Redeeming checks token,
//   digest, tool and target and consumes it once; a second redeem is 409
//   decision_replayed. The same (agent, idempotency_key) returns the same
//   decision, and a different digest under the same key is 409
//   idempotency_conflict (no substitution).
// DECISION R3-6 (several policies): at most one approved runtime policy may
//   govern an agent. If more than one matches, the decision is deny
//   policy_conflict (fail closed) rather than an implicit union.
// DECISION R3-7 (outage and caching, R-05): the posture is fail-closed and is
//   returned with every decision: a PEP must treat a 5xx, a timeout or an
//   expired allow as deny; it may reuse an allow only until expires_at and
//   only once. Revocation (a new approved version, pause, archive, a revoked
//   delegation token) takes effect at the next decide; an unredeemed allow
//   issued before it stays valid until its expiry (at most 300 s). While R3
//   is unavailable every runtime route answers 503 runtime_unavailable with
//   fail_closed: true.
// DECISION R3-8 (human in the loop, R-06): a tool designated
//   require_approval yields 'hold' with a durable iga_gov_runtime_hold row
//   (expires after hold_timeout_minutes). A workspace member with
//   governance:approve who is NOT the initiating human approves or rejects it
//   (UI routes; iga_gov_event; no Slack -- the Slack app's approval cards are
//   bound to policy versions and are not trivially reusable). The agent
//   resumes by calling decide again with the same idempotency_key and the
//   same arguments digest within approval_valid_minutes: that issues exactly
//   one allow bound to the approval (a unique index enforces one resume per
//   approval); later calls return 409 already_resumed. Holds expire lazily on
//   read and in the R3 sweeper.
// DECISION R3-9 (budgets, R-09): budgets are per (policy, agent, session_id,
//   budget name); unit 'calls' reserves 1 per allowed call, unit 'cost'
//   reserves the tool's declared cost (a tool without a cost reserves
//   nothing against a cost budget). The reservation is one UPDATE whose
//   WHERE carries the limit check, in the decide transaction; a hold reserves
//   nothing until it resumes. Settlement happens on the outcome report:
//   succeeded/failed/unknown settle at the reported actual_cost (calls: 1);
//   not_executed releases. An allow never redeemed is released at expiry;
//   one redeemed without an outcome is settled at its reservation one hour
//   after expiry (the sweeper). Overruns are recorded, not refused.
// DECISION R3-10 (outcomes, R-07): the AuthSec decision (decision, reason)
//   and what the agent reports happened (tool_outcome, aws_outcome,
//   actual_cost) are separate columns and separate events; reported
//   outcomes are labelled outcome_source 'agent_reported' -- AuthSec has not
//   verified them (a brokered session's CloudTrail can be correlated by its
//   session name later; not built).
// DECISION R3-11 (AgentCore, R-01 / R-04): the allow-list is compiled to one
//   Cedar permit per tool (CompileCedar) and pushed to a customer-named
//   AgentCore policy engine; read back and compared. Approval and budgets are
//   NOT compilable to Cedar and are enforced only at AuthSec's decide
//   endpoint. Coverage is 'advisory' for every control unless a recorded,
//   unexpired, unrevoked routing proof covers the gateway AND the last push
//   read back equal AND the gateway's policy engine is in ENFORCE mode; then
//   (and only for the allow-list) 'enforced'. Approval and budget controls
//   stay 'advisory' -- the agent calls decide voluntarily, and an optional
//   SDK is not mandatory enforcement -- until a gateway interceptor that calls
//   decide is proven (lab contract).
// DECISION R3-12 (brokered sessions, R-08 from R2-1): opt-in per role
//   (iga_gov_runtime_broker_role, governance:enforce). The customer creates a
//   broker role that trusts AuthSec's AWS principal with the account
//   connector's ExternalId and allows sts:AssumeRole, sts:TagSession and
//   sts:SetSourceIdentity. A tool may name aws.role_arn with actions and
//   resources; an allow for that tool can be exchanged ONCE (it is consumed)
//   for credentials from sts:AssumeRole with a session policy of exactly those
//   actions and resources, session tags (authsec-agent, authsec-human,
//   authsec-decision, authsec-workspace) and SourceIdentity
//   authsec-<human>, DurationSeconds <= min(role max, tool max, 3600),
//   RoleSessionName authsec-rt-<decision> (CloudTrail attribution). Not the
//   enforcement binding: the enforcement role administers IAM boundaries and
//   must never be handed to an agent.
// DECISION R3-13 (NL drafting, R-10 SHOULD): not built. Only typed
//   runtime_controls intents are accepted.
// DECISION R3-14 (budget ledger and versions): a ledger is keyed by policy,
//   not version, so re-approving a policy does not reset an open session's
//   spend; the limit of the version that opened the ledger applies to that
//   session until its window ends. A session past its window is denied
//   session_expired (the agent starts a new session id).
// DECISION R3-15 (autonomous workloads): R-02 requires an initiating human;
//   a workload acting for no human cannot be decided in R3.
// DECISION R3-16 (event actor): iga_gov_event.actor_kind admits no 'agent'
//   (052 CHECK) and R3 does not widen it: AuthSec's own decisions are
//   recorded as actor system / runtime-pdp with the agent and the human in
//   the payload; human approvals and policy changes are actor user. Runtime
//   calls also write audit_events with the initiating human as the user and
//   the agent in the values.
// DECISION R3-17 (mounting): see controllers/platform/iga_gov_r3_controller.go.
// DECISION R3-18 (answers): a decision is a 200 whose body says allow, deny
//   or hold -- a deny is a successful answer, not an error; refusals of the
//   REQUEST (bad credential, idempotency conflict, replay) are 4xx; an
//   AuthSec failure is 5xx and means deny (R3-7).
// DECISION R3-19 (decision record retention): decisions, holds, ledgers
//   and events are kept (audit); only retained argument values are pruned.
//   No row stores a credential, a decision token or a prompt.

// IntentRuntimeControls is the R3 intent kind.
const IntentRuntimeControls = "runtime_controls"

// Runtime decisions and reason codes.
const (
	RuntimeAllow = "allow"
	RuntimeDeny  = "deny"
	RuntimeHold  = "hold"

	RuntimeReasonAllowed          = "allowed"
	RuntimeReasonApproved         = "approved"
	RuntimeReasonNoPolicy         = "no_policy"
	RuntimeReasonPolicyConflict   = "policy_conflict"
	RuntimeReasonToolNotAllowed   = "tool_not_allowed"
	RuntimeReasonActionNotAllowed = "action_not_allowed"
	RuntimeReasonTargetNotAllowed = "target_not_allowed"
	RuntimeReasonApprovalRequired = "approval_required"
	RuntimeReasonApprovalRejected = "approval_rejected"
	RuntimeReasonApprovalExpired  = "approval_expired"
	RuntimeReasonBudgetExhausted  = "budget_exhausted"
	RuntimeReasonSessionExpired   = "session_expired"
	RuntimeReasonSessionRequired  = "session_required"
)

// Budget units.
const (
	BudgetUnitCalls = "calls"
	BudgetUnitCost  = "cost"
)

// RuntimeContextKeys are the only context keys a decision keeps (R-11).
var RuntimeContextKeys = map[string]bool{
	"gateway_arn": true, "gateway_target": true, "source": true, "environment": true, "region": true,
	"request_origin": true, "trace_id": true,
}

// MaxBrokerSeconds is the hard cap of a brokered session (R-08: <= 1 h).
const MaxBrokerSeconds = 3600

// RuntimeSubject names the agents a policy governs (R-02): a SPIFFE ID
// (exact, or a prefix ending "/*") and/or an agent client id. Both given:
// both must match.
type RuntimeSubject struct {
	SpiffeID string `json:"spiffe_id,omitempty"`
	ClientID string `json:"client_id,omitempty"`
}

// RuntimeAWS is a tool's brokered-session scope (DECISION R3-12).
type RuntimeAWS struct {
	RoleARN    string   `json:"role_arn"`
	Actions    []string `json:"actions"`
	Resources  []string `json:"resources"`
	MaxSeconds int      `json:"max_seconds,omitempty"`
}

// RuntimeTool is one allow-listed tool (R-01). Tool is the gateway tool
// name (for AgentCore: "<target>___<tool>"); Actions and Targets narrow it
// ("*" suffix wildcards); empty means any.
type RuntimeTool struct {
	Tool            string      `json:"tool"`
	Actions         []string    `json:"actions,omitempty"`
	Targets         []string    `json:"targets,omitempty"`
	RequireApproval bool        `json:"require_approval,omitempty"`
	ApprovalReason  string      `json:"approval_reason,omitempty"`
	Cost            int64       `json:"cost,omitempty"`
	AWS             *RuntimeAWS `json:"aws,omitempty"`
}

// RuntimeBudget is one per-session budget (R-09).
type RuntimeBudget struct {
	Name          string   `json:"name"`
	Unit          string   `json:"unit"`
	Limit         int64    `json:"limit"`
	WindowMinutes int      `json:"window_minutes"`
	Tools         []string `json:"tools,omitempty"`
}

// RuntimeGateway is an AgentCore gateway the allow-list is pushed to.
type RuntimeGateway struct {
	GatewayARN     string `json:"gateway_arn"`
	PolicyEngineID string `json:"policy_engine_id"`
}

// RuntimeIntent is the runtime_controls intent.
type RuntimeIntent struct {
	Kind     string           `json:"kind"`
	Subjects []RuntimeSubject `json:"subjects"`
	Tools    []RuntimeTool    `json:"tools"`
	Budgets  []RuntimeBudget  `json:"budgets,omitempty"`
	Gateways []RuntimeGateway `json:"gateways,omitempty"`
	Reason   string           `json:"reason,omitempty"`
}

var (
	reRuntimeTool    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/\-]{0,199}$`)
	reRuntimePattern = regexp.MustCompile(`^[^\s*]{0,512}\*?$`)
	reBudgetName     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	reGatewayARN     = regexp.MustCompile(`^arn:aws[a-z-]*:bedrock-agentcore:[a-z0-9-]+:[0-9]{12}:gateway/[A-Za-z0-9_\-]+$`)
	reRoleARN        = regexp.MustCompile(`^arn:aws[a-z-]*:iam::([0-9]{12}):role/[\w+=,.@/\-]+$`)
	reIAMAction      = regexp.MustCompile(`^[a-z0-9\-]+:[A-Za-z0-9*]+$`)
	reEngineID       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_\-]{0,99}$`)
	reArgsDigest     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// ParseRuntimeIntent parses and validates a runtime_controls intent and
// returns it with its canonical bytes and intent hash.
func ParseRuntimeIntent(raw []byte) (*RuntimeIntent, []byte, string, error) {
	canon, err := Canonicalize(raw)
	if err != nil {
		return nil, nil, "", IntentErrors{{Field: "", Code: "not_json", Message: err.Error()}}
	}
	if err := checkStorable(canon); err != nil {
		return nil, nil, "", IntentErrors{{Field: "", Code: "not_storable", Message: err.Error()}}
	}
	var in RuntimeIntent
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&in); err != nil {
		return nil, nil, "", IntentErrors{{Field: "", Code: "shape", Message: err.Error()}}
	}
	if errs := ValidateRuntimeIntent(&in); len(errs) > 0 {
		return nil, nil, "", errs
	}
	h, err := IntentHash(canon)
	if err != nil {
		return nil, nil, "", err
	}
	return &in, canon, h, nil
}

// ValidateRuntimeIntent checks a runtime_controls intent.
func ValidateRuntimeIntent(in *RuntimeIntent) IntentErrors {
	var errs IntentErrors
	add := func(field, code, msg string) {
		errs = append(errs, IntentError{Field: field, Code: code, Message: msg})
	}
	if in.Kind != IntentRuntimeControls {
		add("kind", "unknown_kind", "kind must be runtime_controls")
	}
	if len(in.Subjects) == 0 || len(in.Subjects) > 50 {
		add("subjects", "count", "1..50 subjects (agents by spiffe_id and/or client_id)")
	}
	for i, s := range in.Subjects {
		f := fmt.Sprintf("subjects[%d]", i)
		if s.SpiffeID == "" && s.ClientID == "" {
			add(f, "empty", "name the agent by spiffe_id and/or client_id")
		}
		if s.SpiffeID != "" && (!strings.HasPrefix(s.SpiffeID, "spiffe://") || strings.Count(s.SpiffeID, "*") > 1 ||
			(strings.Contains(s.SpiffeID, "*") && !strings.HasSuffix(s.SpiffeID, "/*"))) {
			add(f+".spiffe_id", "invalid", "a spiffe:// ID, optionally ending /* for a prefix")
		}
		if len(s.ClientID) > 200 {
			add(f+".client_id", "invalid", "client_id is too long")
		}
	}
	if len(in.Tools) == 0 || len(in.Tools) > 200 {
		add("tools", "count", "1..200 allow-listed tools")
	}
	seen := map[string]bool{}
	for i, t := range in.Tools {
		f := fmt.Sprintf("tools[%d]", i)
		if !reRuntimeTool.MatchString(t.Tool) {
			add(f+".tool", "invalid", "a tool name of [A-Za-z0-9_.:/-], at most 200 characters")
		}
		if seen[t.Tool] {
			add(f+".tool", "duplicate", "each tool is listed once")
		}
		seen[t.Tool] = true
		for j, p := range append(append([]string{}, t.Actions...), t.Targets...) {
			if p == "" || !reRuntimePattern.MatchString(p) {
				add(fmt.Sprintf("%s.patterns[%d]", f, j), "invalid", "actions/targets are literals with an optional trailing *")
			}
		}
		if t.Cost < 0 || t.Cost > 1_000_000_000 {
			add(f+".cost", "range", "cost is 0..1e9")
		}
		if len(t.ApprovalReason) > 500 {
			add(f+".approval_reason", "range", "at most 500 characters")
		}
		if t.AWS != nil {
			if !reRoleARN.MatchString(t.AWS.RoleARN) {
				add(f+".aws.role_arn", "invalid", "an IAM role ARN")
			}
			if len(t.AWS.Actions) == 0 || len(t.AWS.Actions) > 50 {
				add(f+".aws.actions", "count", "1..50 IAM actions")
			}
			for j, a := range t.AWS.Actions {
				if !reIAMAction.MatchString(a) || a == "*:*" || strings.HasPrefix(a, "iam:") || strings.HasPrefix(a, "sts:") {
					add(fmt.Sprintf("%s.aws.actions[%d]", f, j), "invalid", "service:Action; iam:* and sts:* are never brokered")
				}
			}
			if len(t.AWS.Resources) == 0 || len(t.AWS.Resources) > 20 {
				add(f+".aws.resources", "count", "1..20 resources (ARNs or *)")
			}
			for j, r := range t.AWS.Resources {
				if r != "*" && !strings.HasPrefix(r, "arn:") {
					add(fmt.Sprintf("%s.aws.resources[%d]", f, j), "invalid", "an ARN or *")
				}
			}
			if t.AWS.MaxSeconds != 0 && (t.AWS.MaxSeconds < 900 || t.AWS.MaxSeconds > MaxBrokerSeconds) {
				add(f+".aws.max_seconds", "range", "900..3600")
			}
		}
	}
	names := map[string]bool{}
	if len(in.Budgets) > 20 {
		add("budgets", "count", "at most 20 budgets")
	}
	for i, b := range in.Budgets {
		f := fmt.Sprintf("budgets[%d]", i)
		if !reBudgetName.MatchString(b.Name) || names[b.Name] {
			add(f+".name", "invalid", "a unique lower_snake name")
		}
		names[b.Name] = true
		if b.Unit != BudgetUnitCalls && b.Unit != BudgetUnitCost {
			add(f+".unit", "invalid", "calls or cost")
		}
		if b.Limit <= 0 || b.Limit > 1_000_000_000_000 {
			add(f+".limit", "range", "1..1e12")
		}
		if b.WindowMinutes < 1 || b.WindowMinutes > 10080 {
			add(f+".window_minutes", "range", "1..10080 (one week)")
		}
		for j, t := range b.Tools {
			if !seen[t] {
				add(fmt.Sprintf("%s.tools[%d]", f, j), "unknown_tool", "a budget names allow-listed tools only")
			}
		}
	}
	if len(in.Gateways) > 20 {
		add("gateways", "count", "at most 20 gateways")
	}
	for i, g := range in.Gateways {
		f := fmt.Sprintf("gateways[%d]", i)
		if !reGatewayARN.MatchString(g.GatewayARN) {
			add(f+".gateway_arn", "invalid", "an AgentCore gateway ARN")
		}
		if !reEngineID.MatchString(g.PolicyEngineID) {
			add(f+".policy_engine_id", "invalid", "the AgentCore policy engine id")
		}
	}
	if len(in.Reason) > 2000 {
		add("reason", "range", "at most 2000 characters")
	}
	return errs
}

// MatchesAgent reports whether the intent governs the agent.
func (in *RuntimeIntent) MatchesAgent(spiffeID, clientID string) bool {
	for _, s := range in.Subjects {
		if s.SpiffeID != "" && !matchSpiffe(s.SpiffeID, spiffeID) {
			continue
		}
		if s.ClientID != "" && s.ClientID != clientID {
			continue
		}
		return true
	}
	return false
}

func matchSpiffe(pattern, id string) bool {
	if strings.HasSuffix(pattern, "/*") {
		return strings.HasPrefix(id, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == id
}

func matchPattern(pattern, v string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(v, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == v
}

func matchAny(patterns []string, v string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if matchPattern(p, v) {
			return true
		}
	}
	return false
}

// RuntimeVerdict is the policy part of a decision (before holds and budgets).
type RuntimeVerdict struct {
	Decision string
	Reason   string
	Tool     *RuntimeTool
	Budgets  []RuntimeBudget
	Detail   map[string]any
}

// EvaluateTool is the allow-list evaluation (R-01): the tool must be listed,
// and its actions and targets must match. A listed tool designated
// require_approval yields hold; budgets that apply to it are returned.
func (in *RuntimeIntent) EvaluateTool(tool, action, target string) RuntimeVerdict {
	for i := range in.Tools {
		t := &in.Tools[i]
		if t.Tool != tool {
			continue
		}
		if !matchAny(t.Actions, action) {
			return RuntimeVerdict{Decision: RuntimeDeny, Reason: RuntimeReasonActionNotAllowed, Tool: t,
				Detail: map[string]any{"allowed_actions": t.Actions}}
		}
		if !matchAny(t.Targets, target) {
			return RuntimeVerdict{Decision: RuntimeDeny, Reason: RuntimeReasonTargetNotAllowed, Tool: t,
				Detail: map[string]any{"allowed_targets": t.Targets}}
		}
		v := RuntimeVerdict{Decision: RuntimeAllow, Reason: RuntimeReasonAllowed, Tool: t}
		for _, b := range in.Budgets {
			if len(b.Tools) == 0 || containsString(b.Tools, tool) {
				v.Budgets = append(v.Budgets, b)
			}
		}
		if t.RequireApproval {
			v.Decision, v.Reason = RuntimeHold, RuntimeReasonApprovalRequired
		}
		return v
	}
	return RuntimeVerdict{Decision: RuntimeDeny, Reason: RuntimeReasonToolNotAllowed}
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// BudgetReservation is what one allowed call reserves against b: 1 for a
// calls budget, the tool's declared cost for a cost budget (0 -- nothing
// reserved, the budget does not apply -- for a tool without a cost).
func BudgetReservation(b RuntimeBudget, t *RuntimeTool) int64 {
	if b.Unit == BudgetUnitCalls {
		return 1
	}
	if t == nil || t.Cost <= 0 {
		return 0
	}
	return t.Cost
}

// DigestArguments is the arguments digest (DECISION R3-4): sha256 of the
// RFC 8785 form, "sha256:<hex>".
func DigestArguments(raw []byte) (string, error) {
	c, err := Canonicalize(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ValidArgsDigest reports whether s is a "sha256:<64 hex>" digest.
func ValidArgsDigest(s string) bool { return reArgsDigest.MatchString(s) }

// RedactArguments keeps argument values with every member named in keys
// (case-insensitive, at any depth) replaced by "[redacted]" and strings
// longer than 256 bytes truncated (R-11).
func RedactArguments(raw []byte, keys []string) (json.RawMessage, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, k := range keys {
		set[strings.ToLower(k)] = true
	}
	var walk func(any) any
	walk = func(x any) any {
		switch t := x.(type) {
		case map[string]any:
			for k, val := range t {
				if set[strings.ToLower(k)] {
					t[k] = "[redacted]"
				} else {
					t[k] = walk(val)
				}
			}
			return t
		case []any:
			for i := range t {
				t[i] = walk(t[i])
			}
			return t
		case string:
			if len(t) > 256 {
				return t[:256] + "...[truncated]"
			}
			return t
		}
		return x
	}
	out, err := json.Marshal(walk(v))
	return out, err
}

// FilterRuntimeContext keeps the allow-listed context keys with string values
// of at most 512 bytes, and returns the digest of the whole context as sent.
func FilterRuntimeContext(ctx map[string]any) (map[string]string, string, error) {
	kept := map[string]string{}
	for k, v := range ctx {
		if !RuntimeContextKeys[k] {
			continue
		}
		s, ok := v.(string)
		if !ok || len(s) > 512 {
			continue
		}
		kept[k] = s
	}
	raw, err := json.Marshal(ctx)
	if err != nil {
		return nil, "", err
	}
	if ctx == nil {
		raw = []byte("{}")
	}
	d, err := DigestArguments(raw)
	return kept, d, err
}

// RuntimeBinding is what an allow binds (R-03).
type RuntimeBinding struct {
	DecisionID   string    `json:"decision_id"`
	WorkspaceRef string    `json:"workspace_ref"`
	AgentRef     string    `json:"agent_ref"`
	HumanUserID  string    `json:"human_user_id"`
	Tool         string    `json:"tool"`
	Action       string    `json:"action"`
	Target       string    `json:"target"`
	ArgsDigest   string    `json:"args_digest"`
	VersionID    string    `json:"version_id"`
	IntentHash   string    `json:"intent_hash"`
	ApprovalRef  string    `json:"approval_ref"`
	Decision     string    `json:"decision"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// DomainRuntimeBinding tags the binding hash.
const DomainRuntimeBinding = "authsec.igagov.runtime_binding.v1"

// Hash is the binding hash (domain-tagged JCS).
func (b RuntimeBinding) Hash() (string, error) {
	b.ExpiresAt = b.ExpiresAt.UTC().Truncate(time.Microsecond)
	return HashCanonicalTagged(DomainRuntimeBinding, b)
}

// CedarPolicy is one compiled AgentCore policy.
type CedarPolicy struct {
	Name      string `json:"name"`
	Tool      string `json:"tool"`
	Statement string `json:"statement"`
}

// CedarPolicyPrefix is the name prefix of every policy AuthSec owns in an
// engine for one AuthSec policy.
func CedarPolicyPrefix(policyID string) string {
	sum := sha256.Sum256([]byte(policyID))
	return "authsec_" + hex.EncodeToString(sum[:])[:12] + "_"
}

// CompileCedar compiles the allow-list to Cedar permits for one gateway
// (DECISION R3-11). UNVERIFIED: the entity types (AgentCore::Action for a
// gateway tool, AgentCore::Gateway for the resource) follow the AgentCore
// Policy documentation as read for this build and have not been validated
// against a real policy engine (§12.4 lab contract 1). The principal is left
// unconstrained -- mapping an AuthSec agent identity to the gateway's
// inbound-auth principal is part of that contract -- and actions/targets
// narrowing and approval/budget designations are NOT compiled: they are
// enforced at AuthSec's decide endpoint only.
func CompileCedar(policyID string, in *RuntimeIntent, gatewayARN string) []CedarPolicy {
	prefix := CedarPolicyPrefix(policyID)
	out := make([]CedarPolicy, 0, len(in.Tools))
	for _, t := range in.Tools {
		sum := sha256.Sum256([]byte(t.Tool))
		stmt := fmt.Sprintf("permit(\n  principal,\n  action == AgentCore::Action::%s,\n  resource == AgentCore::Gateway::%s\n);",
			cedarString(t.Tool), cedarString(gatewayARN))
		out = append(out, CedarPolicy{Name: prefix + hex.EncodeToString(sum[:])[:12], Tool: t.Tool, Statement: stmt})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func cedarString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// SessionPolicy is the brokered session's policy (DECISION R3-12): exactly
// the tool's AWS actions on its resources.
func SessionPolicy(a *RuntimeAWS) (string, error) {
	doc := map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{{
			"Sid":      "AuthSecRuntimeBroker",
			"Effect":   "Allow",
			"Action":   a.Actions,
			"Resource": a.Resources,
		}},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	if len(b) > 2048 {
		return "", fmt.Errorf("the session policy is %d bytes; AWS allows 2048 (packed)", len(b))
	}
	return string(b), nil
}

// RoleAccount is the account of a role ARN ("" when it is not one).
func RoleAccount(arn string) string {
	m := reRoleARN.FindStringSubmatch(arn)
	if m == nil {
		return ""
	}
	return m[1]
}

// GatewayAccount is the account of a gateway ARN ("" when it is not one).
func GatewayAccount(arn string) string {
	if !reGatewayARN.MatchString(arn) {
		return ""
	}
	parts := strings.Split(arn, ":")
	return parts[4]
}

// GatewayID is the gateway id of a gateway ARN.
func GatewayID(arn string) string {
	i := strings.LastIndex(arn, "gateway/")
	if i < 0 {
		return ""
	}
	return arn[i+len("gateway/"):]
}
