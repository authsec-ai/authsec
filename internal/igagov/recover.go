package igagov

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// This file is §2.8's single classifier, `igagov.Classify(plan, live)`, used
// by direct execution, recovery, IaC verification and export verification
// alike, and §8.1 / §8.5's per-op recovery classification for crash and
// unknown outcomes.
//
// A plan is decomposed into FACTS, each one native condition with a before
// value and an after value (Plan.Facts, stored in iga_gov_plan.diff.facts).
// A live read gives each fact an observed value; the plan's class follows:
//
//	before        every fact at its before value
//	intermediate  every fact at its before or after value, not all one or the
//	              other; for direct delivery only states reachable by a
//	              PREFIX of the op order count (resume at the next op); for
//	              iac_pr / export any combination counts
//	after         every fact at its after value, including the disposition
//	conflict      any fact at neither value, or (direct) a valid combination
//	              that is not a prefix of AuthSec's op order

// Fact kinds.
const (
	// FactRole: the control's incarnation (RoleId); never changes.
	FactRole = "role_incarnation"
	// FactRoleDefinition: role ARN, path, protection tags and own policies
	// (the apply precondition beyond artifact_state); apply plans only, and
	// compared only while every other fact is at its before value.
	FactRoleDefinition = "role_definition"
	// FactRoleBoundary: this role's permissions boundary ARN or "none".
	FactRoleBoundary = "role_boundary"
	// FactPolicyDocument: a policy's default-document hash or "absent"
	// (NoSuchEntity).
	FactPolicyDocument = "policy_document"
	// FactPolicyOwner: an AuthSec policy's owner tags,
	// "authsec:<workspace>:<control>", "customer" or "absent".
	FactPolicyOwner = "policy_owner"
	// FactPolicyUsers: every entity using a policy except this role's use of
	// it as its boundary (that is FactRoleBoundary). Never changes.
	FactPolicyUsers = "policy_users"
	// FactBinding: a migration subject's role (§11).
	FactBinding = "workload_binding"
	// FactNewRole: a dedicated role's definition hash or "absent" (§11).
	FactNewRole = "new_role"
)

// Fact values for absence.
const (
	ValueNone   = "none"
	ValueAbsent = "absent"
)

// Fact is one native condition of a plan with its before and after values.
type Fact struct {
	Key     string `json:"key"`
	Kind    string `json:"kind"`
	Subject string `json:"subject,omitempty"`
	Before  string `json:"before"`
	After   string `json:"after"`
	// OnlyBefore: compared only to tell `before` from `conflict`
	// (FactRoleDefinition, DECISION D33).
	OnlyBefore bool `json:"only_before,omitempty"`
}

// Changes reports whether the fact's value changes.
func (f Fact) Changes() bool { return f.Before != f.After }

func factKey(kind, subject string) string {
	if subject == "" {
		return kind
	}
	return kind + ":" + subject
}

func factRole(roleID string) Fact {
	return Fact{Key: FactRole, Kind: FactRole, Before: roleID, After: roleID}
}

func factBoundary(before, after string) Fact {
	return Fact{Key: FactRoleBoundary, Kind: FactRoleBoundary, Before: before, After: after}
}

func factPolicyDoc(arn, before, after string) Fact {
	return Fact{Key: factKey(FactPolicyDocument, arn), Kind: FactPolicyDocument, Subject: arn, Before: before, After: after}
}

func factPolicyOwner(arn, before, after string) Fact {
	return Fact{Key: factKey(FactPolicyOwner, arn), Kind: FactPolicyOwner, Subject: arn, Before: before, After: after}
}

func usersValue(set []AttachedEntity) string {
	if set == nil {
		set = []AttachedEntity{}
	}
	c, err := CanonicalizeValue(ArtifactStateFacts{RoleID: "x", AttachmentSet: set}.Normalized().AttachmentSet)
	if err != nil {
		return "\x00invalid"
	}
	return string(c)
}

func factPolicyUsers(arn string, before, after []AttachedEntity) Fact {
	return Fact{Key: factKey(FactPolicyUsers, arn), Kind: FactPolicyUsers, Subject: arn, Before: usersValue(before), After: usersValue(after)}
}

func sortFacts(fs []Fact) {
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Key < fs[j].Key })
}

// FactsFromDiff reads the fact table back from a stored iga_gov_plan.diff.
func FactsFromDiff(diff []byte) ([]Fact, error) {
	var d struct {
		Facts []Fact `json:"facts"`
	}
	if err := json.Unmarshal(diff, &d); err != nil {
		return nil, fmt.Errorf("igagov: plan diff: %w", err)
	}
	if len(d.Facts) == 0 {
		return nil, fmt.Errorf("igagov: plan diff has no facts")
	}
	return d.Facts, nil
}

/* ------------------------------------------------------------------------- */
/*                               Observation                                  */
/* ------------------------------------------------------------------------- */

// ObserveFacts gives every fact its observed value from a live read. A fact
// whose object was not read is an error (the read must cover
// Plan.PoliciesToRead and, for §11 plans, the roles and bindings named).
func ObserveFacts(facts []Fact, live LiveRead) (map[string]string, error) {
	roleID := ""
	for _, f := range facts {
		if f.Kind == FactRole {
			roleID = f.Before
		}
	}
	out := map[string]string{}
	for _, f := range facts {
		var v string
		switch f.Kind {
		case FactRole:
			v = ValueAbsent
			if live.Role != nil {
				v = live.Role.RoleID
			}
		case FactRoleDefinition:
			v = ValueAbsent
			if live.Role != nil {
				h, err := roleDefinitionHash(live.Role)
				if err != nil {
					return nil, err
				}
				v = h
			}
		case FactRoleBoundary:
			v = ValueAbsent
			if live.Role != nil {
				v = live.Role.BoundaryARN
				if v == "" {
					v = ValueNone
				}
			}
		case FactPolicyDocument, FactPolicyOwner, FactPolicyUsers:
			p, ok := live.Policies[f.Subject]
			if !ok {
				return nil, compileErr(ErrCodeLiveIncomplete, "policy "+f.Subject+" was not read")
			}
			switch {
			case p == nil && f.Kind == FactPolicyUsers:
				v = usersValue(nil)
			case p == nil:
				v = ValueAbsent
			case f.Kind == FactPolicyDocument:
				h, err := p.DocumentHash()
				if err != nil {
					return nil, err
				}
				v = h
			case f.Kind == FactPolicyOwner:
				v = ownerValue(p.Tags)
			default:
				v = usersValue(otherUsers(p.AttachmentSet, roleID))
			}
		case FactBinding:
			b, ok := live.Bindings[f.Subject]
			if !ok {
				return nil, compileErr(ErrCodeLiveIncomplete, "binding of "+f.Subject+" was not read")
			}
			v = b
		case FactNewRole:
			r, ok := live.Roles[f.Subject]
			if !ok {
				return nil, compileErr(ErrCodeLiveIncomplete, "role "+f.Subject+" was not read")
			}
			v = ValueAbsent
			if r != nil {
				h, err := dedicatedRoleHash(r)
				if err != nil {
					return nil, err
				}
				v = h
			}
		default:
			return nil, fmt.Errorf("igagov: unknown fact kind %q", f.Kind)
		}
		out[f.Key] = v
	}
	return out, nil
}

/* ------------------------------------------------------------------------- */
/*                               Classification                               */
/* ------------------------------------------------------------------------- */

// Classes (§2.8).
const (
	ClassBefore       = "before"
	ClassIntermediate = "intermediate"
	ClassAfter        = "after"
	ClassConflict     = "conflict"
)

// Positions of one fact's observed value.
const (
	AtBefore  = "before"
	AtAfter   = "after"
	AtBoth    = "both" // the fact does not change and holds
	AtNeither = "neither"
)

// Conflict reasons. The caller maps them to its state: a direct apply or
// split → blocked plan_changed; an undo / remove-control → blocked with this
// reason; IaC and export → failed: unexpected_state (§8.4, §8.9, §8.11).
const (
	ConflictRoleGone          = "role_gone"
	ConflictRoleRecreated     = "role_recreated"
	ConflictOwnedElsewhere    = "artifact_owned_elsewhere"
	ConflictConsumersChanged  = "artifact_consumers_changed"
	ConflictChangedOutside    = "artifact_changed_outside_authsec"
	ConflictPlanChanged       = "plan_changed"
	ConflictNotAPrefix        = "not_a_prefix_of_op_order"
	ConflictRoleDefinition    = "role_definition_changed"
	ConflictBindingUnexpected = "binding_unexpected"
)

// FactResult is one fact with what the read showed.
type FactResult struct {
	Fact
	Observed string `json:"observed"`
	At       string `json:"at"`
}

// Classification is Classify's result.
type Classification struct {
	Class string `json:"class"`
	// NextOp is, for direct delivery, the first op to (re)run: 0 for before,
	// the op after the matched prefix for intermediate, and for after the
	// first trailing op whose effect a read cannot see (TagPolicy), which is
	// idempotent; len(ops) when nothing is left. -1 for conflict and for
	// IaC / export.
	NextOp int `json:"next_op"`
	// Visible and Total count the changing facts at their after value
	// ("2 of 3 changes visible in AWS").
	Visible   int          `json:"visible"`
	Total     int          `json:"total"`
	Facts     []FactResult `json:"facts"`
	Conflicts []FactResult `json:"conflicts"`
	Reason    string       `json:"reason,omitempty"`
}

// opEffects returns the fact keys an op moves to their after value.
func opEffects(op Op) []string {
	switch op.Op {
	case OpCreatePolicy:
		return []string{factKey(FactPolicyDocument, op.PolicyARN), factKey(FactPolicyOwner, op.PolicyARN)}
	case OpCreatePolicyVersion:
		return []string{factKey(FactPolicyDocument, op.PolicyARN)}
	case OpDeletePolicy:
		return []string{factKey(FactPolicyDocument, op.PolicyARN), factKey(FactPolicyOwner, op.PolicyARN)}
	case OpPutRolePermissionsBoundary, OpDeleteRolePermissionsBoundary:
		if op.RoleARN != "" { // a step on another role (§11)
			return nil
		}
		return []string{FactRoleBoundary}
	case OpCreateRole, OpDeleteRole:
		return []string{factKey(FactNewRole, op.RoleARN)}
	case OpBindSubject:
		return []string{factKey(FactBinding, op.SubjectARN)}
	}
	return nil
}

// prefixStates returns, for k = 0..len(ops), the set of fact keys at their
// after value once ops[0..k) ran.
func prefixStates(ops []Op) []map[string]bool {
	out := make([]map[string]bool, 0, len(ops)+1)
	cur := map[string]bool{}
	out = append(out, cur)
	for _, op := range ops {
		next := map[string]bool{}
		for k := range cur {
			next[k] = true
		}
		for _, k := range opEffects(op) {
			next[k] = true
		}
		out = append(out, next)
		cur = next
	}
	return out
}

// Classify is §2.8's classifier: plan facts against a live read.
func Classify(p Plan, live LiveRead) (Classification, error) {
	facts := p.Facts
	if len(facts) == 0 {
		return Classification{}, fmt.Errorf("igagov: plan has no facts to classify")
	}
	obs, err := ObserveFacts(facts, live)
	if err != nil {
		return Classification{}, err
	}
	return classifyObserved(p, facts, obs), nil
}

func classifyObserved(p Plan, facts []Fact, obs map[string]string) Classification {
	c := Classification{NextOp: -1, Facts: []FactResult{}, Conflicts: []FactResult{}}
	anyBefore, anyAfter := false, false
	var defMismatch *FactResult
	at := map[string]string{}
	for _, f := range facts {
		r := FactResult{Fact: f, Observed: obs[f.Key]}
		switch {
		case r.Observed == f.Before && r.Observed == f.After:
			r.At = AtBoth
		case r.Observed == f.Before:
			r.At = AtBefore
		case r.Observed == f.After:
			r.At = AtAfter
		default:
			r.At = AtNeither
		}
		at[f.Key] = r.At
		c.Facts = append(c.Facts, r)
		if f.OnlyBefore {
			if r.At != AtBoth {
				rr := r
				defMismatch = &rr
			}
			continue
		}
		if f.Changes() {
			c.Total++
			if r.At == AtAfter {
				c.Visible++
			}
		}
		switch r.At {
		case AtBefore:
			anyBefore = true
		case AtAfter:
			anyAfter = true
		case AtNeither:
			c.Conflicts = append(c.Conflicts, r)
		}
	}
	switch {
	case len(c.Conflicts) > 0:
		c.Class = ClassConflict
		c.Reason = conflictReason(p, c.Conflicts)
		return c
	case anyBefore && !anyAfter:
		if defMismatch != nil {
			c.Class = ClassConflict
			c.Conflicts = append(c.Conflicts, *defMismatch)
			c.Reason = ConflictRoleDefinition
			return c
		}
		c.Class = ClassBefore
	case anyBefore && anyAfter:
		c.Class = ClassIntermediate
	default:
		// Every changing fact at its after value — or a plan with nothing
		// to change ("already in place"): the desired state holds
		// (DECISION D50).
		c.Class = ClassAfter
	}
	if p.Delivery != DeliveryDirect {
		return c
	}
	// Direct: the state must be reachable by a prefix of the op order.
	for k, st := range prefixStates(p.Ops) {
		match := true
		for _, f := range facts {
			if f.OnlyBefore || !f.Changes() {
				continue
			}
			want := AtBefore
			if st[f.Key] {
				want = AtAfter
			}
			if at[f.Key] != want {
				match = false
				break
			}
		}
		if match {
			c.NextOp = k
			return c
		}
	}
	c.Class = ClassConflict
	c.Reason = ConflictNotAPrefix
	c.NextOp = -1
	return c
}

func conflictReason(p Plan, cs []FactResult) string {
	has := map[string]FactResult{}
	for _, r := range cs {
		if _, ok := has[r.Kind]; !ok {
			has[r.Kind] = r
		}
	}
	if r, ok := has[FactRole]; ok {
		if r.Observed == ValueAbsent {
			return ConflictRoleGone
		}
		return ConflictRoleRecreated
	}
	if r, ok := has[FactPolicyOwner]; ok && strings.HasPrefix(r.Observed, "authsec:") {
		return ConflictOwnedElsewhere
	}
	if _, ok := has[FactPolicyUsers]; ok {
		return ConflictConsumersChanged
	}
	if _, ok := has[FactBinding]; ok {
		return ConflictBindingUnexpected
	}
	switch p.Kind {
	case PlanUndo, PlanRemoveControl, PlanSplitRevert:
		return ConflictChangedOutside
	}
	return ConflictPlanChanged
}

/* ------------------------------------------------------------------------- */
/*                         Per-op recovery (§8.1, §8.5)                       */
/* ------------------------------------------------------------------------- */

// Resolutions of an op whose outcome is unknown (iga_gov_attempt.resolved_as
// is applied | not_applied).
const (
	ResolvedApplied    = "applied"
	ResolvedNotApplied = "not_applied"
	// ResolvedUnobservable: the op changes no fact a read can see
	// (TagPolicy, a DeletePolicyVersion); it is idempotent or recognisable,
	// so re-sending it as a new attempt is safe. resolved_as comes from the
	// enforcement session's CloudTrail events, if any (§8.1 step 2).
	// DECISION D52: resolved_as has only applied / not_applied; a read
	// cannot decide these ops, so the classifier says so instead of
	// guessing.
	ResolvedUnobservable = "unobservable_idempotent"
	ResolvedConflict     = "conflict"
)

// OpResolution resolves one op whose attempt is unknown.
type OpResolution struct {
	Resolution     string         `json:"resolution"`
	Classification Classification `json:"classification"`
}

// ResolveUnknownOp is §8.1 step 2 for a direct plan: given the op whose
// attempt is unknown (no later op ran: one open attempt per deployment) and
// a live read after settle_after, decide whether the state is the one before
// the op (not_applied), after it (applied), neither (conflict), or whether
// the op cannot be told apart by a read (unobservable, re-send is safe). The
// caller requires the same answer on two reads 5 minutes apart and checks
// CloudTrail before recording resolved_as.
func ResolveUnknownOp(p Plan, opIndex int, live LiveRead) (OpResolution, error) {
	if p.Delivery != DeliveryDirect {
		return OpResolution{}, fmt.Errorf("igagov: only direct plans have AuthSec ops to resolve")
	}
	if opIndex < 0 || opIndex >= len(p.Ops) {
		return OpResolution{}, fmt.Errorf("igagov: op %d is not in the plan", opIndex)
	}
	cl, err := Classify(p, live)
	if err != nil {
		return OpResolution{}, err
	}
	res := OpResolution{Classification: cl}
	if cl.Class == ClassConflict {
		res.Resolution = ResolvedConflict
		return res, nil
	}
	if len(opEffects(p.Ops[opIndex])) == 0 {
		res.Resolution = ResolvedUnobservable
		return res, nil
	}
	states := prefixStates(p.Ops)
	before, after := states[opIndex], states[opIndex+1]
	match := func(st map[string]bool) bool {
		for _, r := range cl.Facts {
			if r.OnlyBefore || !r.Changes() {
				continue
			}
			want := AtBefore
			if st[r.Key] {
				want = AtAfter
			}
			if r.At != want {
				return false
			}
		}
		return true
	}
	switch {
	case match(after):
		res.Resolution = ResolvedApplied
	case match(before):
		res.Resolution = ResolvedNotApplied
	default:
		// A state of another prefix: not what this op alone explains.
		res.Resolution = ResolvedConflict
	}
	return res, nil
}

// Attempt outcomes (051 iga_gov_attempt.outcome) and the unknown pseudo-outcome.
const (
	OutcomeOK             = "ok"
	OutcomeRetryable      = "retryable"
	OutcomeTerminal       = "terminal"
	OutcomeRecognisedDone = "recognised_done"
	OutcomeNotNeeded      = "not_needed"
	OutcomeUnknown        = "unknown"
)

// OpOutcome is the classification of one AWS response to an op.
type OpOutcome struct {
	Outcome string `json:"outcome"`
	Reason  string `json:"reason,omitempty"`
}

// ResponseKind is how an AWS call ended, as the adapter saw it.
type ResponseKind int

// Response kinds.
const (
	// RespOK: a 2xx answer.
	RespOK ResponseKind = iota
	// RespError: a definitive AWS error with ErrorCode.
	RespError
	// RespNoAnswer: 5xx / ServiceFailure, a timeout, a connection error or
	// a lost lease mid-call: AWS may have applied the request.
	RespNoAnswer
)

// ClassifyOpResponse is §8.5's response table for one op of a direct plan.
// live is a read taken after the response (the recognition column needs
// it); it may be the zero LiveRead for RespOK and pure-throttling answers.
// Only an answer that proves the request was NOT applied is retryable; a
// mutating call without an answer is unknown and never retried.
func ClassifyOpResponse(p Plan, opIndex int, kind ResponseKind, errorCode string, live LiveRead) OpOutcome {
	if opIndex < 0 || opIndex >= len(p.Ops) {
		return OpOutcome{OutcomeTerminal, "op_not_in_plan"}
	}
	op := p.Ops[opIndex]
	switch kind {
	case RespOK:
		return OpOutcome{Outcome: OutcomeOK}
	case RespNoAnswer:
		return OpOutcome{OutcomeUnknown, "no_answer_not_retried"}
	}
	switch errorCode {
	case "Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyRequestsException":
		return OpOutcome{OutcomeRetryable, "throttled"}
	case "ServiceFailure", "InternalFailure", "ServiceUnavailable":
		return OpOutcome{OutcomeUnknown, "service_failure_not_retried"}
	}
	pol := func(arn string) (*LivePolicy, bool) {
		pp, ok := live.Policies[arn]
		return pp, ok
	}
	switch op.Op {
	case OpCreatePolicy:
		if errorCode == "EntityAlreadyExists" {
			pp, ok := pol(op.PolicyARN)
			if !ok || pp == nil {
				return OpOutcome{OutcomeTerminal, "exists_but_unreadable"}
			}
			if pp.Tags[TagManagedBy] == TagManagedByValue && op.Tags[TagWorkspace] != "" && pp.Tags[TagWorkspace] != op.Tags[TagWorkspace] {
				return OpOutcome{OutcomeTerminal, ConflictOwnedElsewhere}
			}
			h, err := pp.DocumentHash()
			if err == nil && pp.Tags[TagControl] == op.Tags[TagControl] && h == op.DocumentHash {
				return OpOutcome{Outcome: OutcomeRecognisedDone}
			}
			return OpOutcome{OutcomeTerminal, "blocked: exists with another document or control"}
		}
	case OpCreatePolicyVersion:
		if pp, ok := pol(op.PolicyARN); ok && pp != nil {
			if h, err := pp.DocumentHash(); err == nil && h == op.DocumentHash {
				return OpOutcome{Outcome: OutcomeNotNeeded}
			}
		}
		if errorCode == "LimitExceeded" {
			return OpOutcome{OutcomeTerminal, "version_limit_after_prune"}
		}
	case OpDeletePolicyVersion:
		switch errorCode {
		case "NoSuchEntity":
			return OpOutcome{Outcome: OutcomeRecognisedDone}
		case "DeleteConflict":
			return OpOutcome{OutcomeTerminal, "blocked: version is the default"}
		}
	case OpTagPolicy:
		if errorCode == "NoSuchEntity" {
			return OpOutcome{OutcomeTerminal, "blocked: policy gone"}
		}
	case OpPutRolePermissionsBoundary:
		if live.Role != nil && live.Role.BoundaryARN == op.PolicyARN {
			return OpOutcome{Outcome: OutcomeRecognisedDone}
		}
		switch errorCode {
		case "AccessDenied", "AccessDeniedException":
			return OpOutcome{OutcomeTerminal, "binding_partial"}
		case "NoSuchEntity":
			return OpOutcome{OutcomeTerminal, ConflictRoleGone}
		}
	case OpDeleteRolePermissionsBoundary:
		if live.Role != nil && live.Role.BoundaryARN == "" {
			return OpOutcome{Outcome: OutcomeRecognisedDone}
		}
		if live.Role != nil && live.Role.BoundaryARN != "" {
			for _, f := range p.Facts {
				if f.Kind == FactRoleBoundary && live.Role.BoundaryARN != f.Before {
					return OpOutcome{OutcomeTerminal, "blocked: another boundary is attached"}
				}
			}
		}
	case OpDeletePolicy:
		switch errorCode {
		case "NoSuchEntity":
			return OpOutcome{Outcome: OutcomeRecognisedDone}
		case "DeleteConflict":
			return OpOutcome{OutcomeTerminal, "attached_elsewhere"}
		}
	}
	if errorCode == "LimitExceeded" {
		return OpOutcome{OutcomeRetryable, "rate_limited"}
	}
	return OpOutcome{OutcomeTerminal, errorCode}
}
