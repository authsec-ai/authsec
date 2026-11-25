package services

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// The second-person rule (SPEC-secops-backend-upgrade.md P3, decision 4),
// defined once for every tier-3 mechanism:
//
//	pending_change                 (F5, pending_change.go)
//	agent_detection_rule_version   (F6, agent_runtime_alert_rules.go)
//	agent_alert_suppression        (F6/P6, agent_runtime_alert_suppression.go)
//	agent_capability_declaration   (W1, agent_coverage.go)
//	audit_governance_change        (F7, audit_governance*.go)
//	agent_pending_change           (W7, agent_identity.go)
//	iga_history_approval           (W9, iga_history_changes.go)
//
// Each keeps its own table; this file is the rule they all apply:
//
//   - CheckApprover: the approver (or reviewer, or the decider of a
//     rejection) is a person, not an automation identity; is not the
//     requester; is not a user the request is about (ExcludingUsers); holds
//     governance:approve NOW, read from the database (never the token); and
//     is not the subject of an open case the request concerns
//     (ConcerningCases / ConcerningIdentities).
//   - BreakGlassAllowed: the requester may apply alone only when they are
//     the workspace's ONLY holder of governance:approve (users the request
//     is about do not count as a second person). An automation identity
//     never breaks glass.
//   - ReviewDue: a break-glass change is due a review by a second person
//     within 24 hours.
//   - CheckTier3Requester: an automation identity never requests a tier-3
//     change (it may perform tier-0 and tier-1 actions only).
//   - CheckRejecter: the requester may withdraw their own request; anyone
//     else rejecting decides it and must pass CheckApprover's person and
//     permission rules.

// SecondPersonReviewWindow is how long after a break-glass change its
// review by a second person is due (decision 4).
const SecondPersonReviewWindow = 24 * time.Hour

// Second-person error codes.
const (
	GovCodeAutomationNotDecider = "automation_not_decider"
	GovCodeAutomationTier       = "automation_tier_refused"
	GovCodeCaseSubject          = "case_subject"
	GovCodeBreakGlassNotAllowed = "break_glass_not_allowed"
)

// GovCodeApproverNotAuthorized ("approver_not_authorized") is declared in
// agent_runtime_alert_rules.go and GovCodeSelfApproval ("self_approval") in
// the policy authoring service; both are used here for every mechanism.

// ReviewDue is when a break-glass change applied at now must be reviewed.
func ReviewDue(now time.Time) time.Time { return now.Add(SecondPersonReviewWindow) }

/* ------------------------------------------------------------------------- */
/*                         Who acts: the request context                      */
/* ------------------------------------------------------------------------- */

type govActorCtxKey struct{}

// WithGovActorAutomation marks ctx as carrying an automation identity's
// request (true) or a person's (false). The tier guard
// (controllers/platform/governance_tier_guard.go) sets it on every request
// of the tiered surfaces from the verified token
// (middlewares.IsAutomationIdentity).
func WithGovActorAutomation(ctx context.Context, automation bool) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, govActorCtxKey{}, automation)
}

// IsGovAutomationActor reports whether ctx was marked as an automation
// identity's request. A context nobody marked (a Slack interaction signed by
// a linked member, a worker) is not.
func IsGovAutomationActor(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(govActorCtxKey{}).(bool)
	return v
}

/* ------------------------------------------------------------------------- */
/*                                   Options                                  */
/* ------------------------------------------------------------------------- */

type secondPersonOpts struct {
	exclude    []uuid.UUID
	cases      []uuid.UUID
	identities []uuid.UUID
}

// SecondPersonOption narrows CheckApprover and BreakGlassAllowed.
type SecondPersonOption func(*secondPersonOpts)

// ExcludingUsers names users the request is about (the operator an
// unsuspension lifts): they never decide it and never count as the second
// person who could.
func ExcludingUsers(ids ...uuid.UUID) SecondPersonOption {
	return func(o *secondPersonOpts) {
		for _, id := range ids {
			if id != uuid.Nil {
				o.exclude = append(o.exclude, id)
			}
		}
	}
}

// ConcerningCases names the agent cases a request concerns (a hold release
// names its case).
func ConcerningCases(ids ...uuid.UUID) SecondPersonOption {
	return func(o *secondPersonOpts) {
		for _, id := range ids {
			if id != uuid.Nil {
				o.cases = append(o.cases, id)
			}
		}
	}
}

// ConcerningIdentities names the cloud identities a request concerns (a
// suppression names its identity): the request concerns every open case one
// of whose alerts names one of them.
func ConcerningIdentities(ids ...uuid.UUID) SecondPersonOption {
	return func(o *secondPersonOpts) {
		for _, id := range ids {
			if id != uuid.Nil {
				o.identities = append(o.identities, id)
			}
		}
	}
}

func secondPersonOptions(opts []SecondPersonOption) secondPersonOpts {
	var o secondPersonOpts
	for _, f := range opts {
		if f != nil {
			f(&o)
		}
	}
	return o
}

func (o secondPersonOpts) excluded(u uuid.UUID) bool {
	for _, x := range o.exclude {
		if x == u {
			return true
		}
	}
	return false
}

/* ------------------------------------------------------------------------- */
/*                                    Rules                                   */
/* ------------------------------------------------------------------------- */

// CheckTier3Requester refuses a tier-3 request from an automation identity
// (403 automation_tier_refused): it may perform tier-0 and tier-1 actions
// only.
func CheckTier3Requester(ctx context.Context) error {
	if IsGovAutomationActor(ctx) {
		return govErr(http.StatusForbidden, GovCodeAutomationTier,
			"An automation identity may perform tier-0 and tier-1 actions only; a person must request this change.", nil)
	}
	return nil
}

// CheckApprover is the rule every approval, decision and break-glass review
// applies (tx is a transaction under row-level security for ws):
//
//	403 automation_not_decider   the caller is an automation identity
//	403 self_approval            approver requested the change, or the change is about them
//	403 approver_not_authorized  approver does not hold governance:approve now (database)
//	403 case_subject             approver is the subject of an open case the change concerns
func CheckApprover(ctx context.Context, tx *gorm.DB, ws, requester, approver uuid.UUID, opts ...SecondPersonOption) error {
	if IsGovAutomationActor(ctx) {
		return govErr(http.StatusForbidden, GovCodeAutomationNotDecider,
			"An automation identity never approves, decides or reviews a change; a person must.", nil)
	}
	o := secondPersonOptions(opts)
	if approver == uuid.Nil || (requester != uuid.Nil && requester == approver) {
		return govErr(http.StatusForbidden, GovCodeSelfApproval,
			"A tier-3 change needs a second person: the person who requested it cannot decide it.", nil)
	}
	if o.excluded(approver) {
		return govErr(http.StatusForbidden, GovCodeSelfApproval, "This change is about you; another person must decide it.", nil)
	}
	ok, err := WorkspaceUserHoldsPermission(tx, ws, approver, "governance", "approve")
	if err != nil {
		return err
	}
	if !ok {
		return govErr(http.StatusForbidden, GovCodeApproverNotAuthorized, "Deciding a tier-3 change needs governance:approve.", nil)
	}
	subject, err := IsCaseSubject(tx, ws, approver, o.cases, o.identities)
	if err != nil {
		return err
	}
	if subject {
		return govErr(http.StatusForbidden, GovCodeCaseSubject,
			"You are the subject of an open case this change concerns; another person must decide it.", nil)
	}
	return nil
}

// CheckRejecter allows the requester to withdraw their own request; anyone
// else rejecting it decides it: a person (not an automation identity)
// holding governance:approve now.
func CheckRejecter(ctx context.Context, tx *gorm.DB, ws, requester, actor uuid.UUID) error {
	if requester != uuid.Nil && requester == actor && !IsGovAutomationActor(ctx) {
		return nil
	}
	if IsGovAutomationActor(ctx) {
		return govErr(http.StatusForbidden, GovCodeAutomationNotDecider,
			"An automation identity never approves, decides or reviews a change; a person must.", nil)
	}
	ok, err := WorkspaceUserHoldsPermission(tx, ws, actor, "governance", "approve")
	if err != nil {
		return err
	}
	if !ok {
		return govErr(http.StatusForbidden, GovCodeApproverNotAuthorized, "Rejecting someone else's request needs governance:approve.", nil)
	}
	return nil
}

// BreakGlassRefusal is nil when requester may apply a tier-3 change alone
// (decision 4): a person who holds governance:approve and is the workspace's
// only holder of it (ExcludingUsers do not count as a second person).
// Otherwise it says why: 409 second_person_available when another holder
// could approve, else 409 break_glass_not_allowed.
func BreakGlassRefusal(ctx context.Context, tx *gorm.DB, ws, requester uuid.UUID, opts ...SecondPersonOption) error {
	if IsGovAutomationActor(ctx) {
		return govErr(http.StatusForbidden, GovCodeAutomationTier, "An automation identity never applies a change alone.", nil)
	}
	o := secondPersonOptions(opts)
	holders, err := WorkspaceUsersHoldingPermission(tx, ws, "governance", "approve")
	if err != nil {
		return err
	}
	self, others := false, 0
	for _, h := range holders {
		switch {
		case h == requester:
			self = true
		case o.excluded(h):
		default:
			others++
		}
	}
	if others > 0 {
		return govConflict(GovCodeSecondPersonAvailable,
			"Another member holds governance:approve: ask them to approve instead of applying alone.",
			map[string]any{"approvers": others})
	}
	if !self {
		return govConflict(GovCodeBreakGlassNotAllowed,
			"Break-glass is only for the workspace's one holder of governance:approve; you do not hold it.",
			map[string]any{"approvers": others})
	}
	return nil
}

// BreakGlassAllowed reports whether requester may apply a tier-3 change
// alone (BreakGlassRefusal is nil).
func BreakGlassAllowed(ctx context.Context, tx *gorm.DB, ws, requester uuid.UUID, opts ...SecondPersonOption) (bool, error) {
	err := BreakGlassRefusal(ctx, tx, ws, requester, opts...)
	if err == nil {
		return true, nil
	}
	if isGovError(err, GovCodeSecondPersonAvailable) || isGovError(err, GovCodeBreakGlassNotAllowed) ||
		isGovError(err, GovCodeAutomationTier) {
		return false, nil
	}
	return false, err
}

/* ------------------------------------------------------------------------- */
/*                                Case subjects                               */
/* ------------------------------------------------------------------------- */

// IsCaseSubject reports whether user is the subject of an open agent case
// among cases, or among the open cases one of whose alerts names one of
// identities. Nothing named: false.
//
// DECISION (W5): a case has no subject column. A workspace user is a case's
// subject when one of the case's alerts names a cloud identity that is an
// IAM user (cloud_identity.kind = 'iam_user') whose name is the user's: the
// user's e-mail or its local part, or the external id, e-mail or e-mail
// local part of a directory (SCIM/Entra/Okta) record linked to the user
// (directory_person.user_id). Roles, service principals and workloads name
// no person and make nobody a subject.
func IsCaseSubject(tx *gorm.DB, ws, user uuid.UUID, cases, identities []uuid.UUID) (bool, error) {
	if len(cases) == 0 && len(identities) == 0 {
		return false, nil
	}
	caseIDs, identityIDs := uuidStrings(cases), uuidStrings(identities)
	var subject bool
	err := tx.Raw(`SELECT EXISTS (
	        SELECT 1 FROM agent_case c
	          JOIN agent_case_alert ca ON ca.workspace_id = c.workspace_id AND ca.case_id = c.id
	          JOIN agent_alert a ON a.workspace_id = ca.workspace_id AND a.id = ca.alert_id
	          JOIN cloud_identity ci ON ci.workspace_id = a.workspace_id AND ci.id = a.identity_id
	         WHERE c.workspace_id = ? AND c.state = 'open' AND ci.kind = 'iam_user' AND ci.name <> ''
	           AND (c.id::text = ANY(?::text[])
	                OR c.id IN (SELECT ca2.case_id FROM agent_case_alert ca2
	                              JOIN agent_alert a2 ON a2.workspace_id = ca2.workspace_id AND a2.id = ca2.alert_id
	                             WHERE ca2.workspace_id = ? AND a2.identity_id::text = ANY(?::text[])))
	           AND (EXISTS (SELECT 1 FROM users u WHERE u.id = ? AND u.email <> ''
	                         AND lower(ci.name) IN (lower(u.email), lower(split_part(u.email, '@', 1))))
	                OR EXISTS (SELECT 1 FROM directory_person d WHERE d.workspace_id = c.workspace_id AND d.user_id = ?
	                         AND lower(ci.name) IN (lower(d.external_id), lower(NULLIF(d.email, '')),
	                                                lower(NULLIF(split_part(d.email, '@', 1), ''))))))`,
		ws, pq.Array(caseIDs), ws, pq.Array(identityIDs), user, user).Scan(&subject).Error
	return subject, err
}

func uuidStrings(ids []uuid.UUID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	return out
}
