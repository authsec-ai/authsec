package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/slackapp"
	"github.com/authsec-ai/authsec/models"
)

// POST /authsec/integrations/slack/interactions (§7.11): Slack signature
// only. Slack must have its HTTP 200 within 3 seconds, so the request is
// answered as soon as it is known to be an authentic, fresh Slack request
// about an AuthSec notification, and the work runs after that (review fix,
// P2 Slack: "interactions do the approval work before replying").
//
// Before the answer (synchronous; a refusal is the HTTP status):
//
//  1. X-Slack-Signature (v0 HMAC-SHA256 over v0:<ts>:<body>, constant-time)
//     and X-Slack-Request-Timestamp within 5 minutes   -> 401 slack_signature_invalid
//  2. the payload names an AuthSec notification posted to Slack, of the
//     Slack team installed in that notification's workspace
//     (404 / 403 slack_user_not_linked team_not_connected)
//  3. a well-formed action_ts newer than the one recorded on the
//     notification (a read: an already recorded action is refused at
//     once)                                            -> 401 slack_signature_invalid (replayed)
//
// then 200 {data: {accepted: true, action}}. After the answer, in a
// goroutine with its own context (slackInteractionTimeout), bounded to
// slackInteractionWorkers at a time:
//
//  4. the clicked message is the notification's current one; the Slack
//     user maps to an active member through slack_user_link; a notice
//     addressed to a member is clicked by that member
//  5. the UI route's authorization for the action: governance:approve and
//     author != approver for approve / reject; an owner asked in the review
//     for acknowledge / retain / object; the health reporter (and its
//     authorizer, when it has one) for report problem / working
//  6. ONLY THEN the action_ts is claimed: atomically (a conditional UPDATE
//     of iga_gov_notification.last_action_ts, with a slack.action_received
//     event), so of two deliveries of one click exactly one proceeds
//  7. the SAME service call the UI route makes, which re-runs its own
//     checks in its own transaction: GovAuthoring.Approve / RejectVia with
//     channel slack (separation of duties again), the owner review's
//     Respond with Via slack, the health reporter
//
// Every outcome of 4-7 is answered to the clicking user through the
// payload's response_url (refusals ephemerally, in the §9.3 copy; a decision
// replaces the message with "Approved by … at …"), and the controller's
// audit_events row is written when the action succeeded.
//
// DECISIONS (T3.14, revised by the review fixes):
//   - Replay is "an action_ts not newer than the last one recorded" (a
//     numeric comparison): the row keeps one value, so equality alone would
//     let an older captured action through after a newer one. It is
//     refused with 401 slack_signature_invalid, reason "replayed" -- §7.12
//     has no separate code, and a replayed request is not a valid fresh
//     Slack request.
//   - The action_ts is claimed only after the signature AND the
//     authorization of steps 4-5 passed (review fix, P2 Slack: "action_ts
//     is claimed before authorization"). An unlinked, departed or
//     unauthorized click records nothing, so it can neither write
//     slack.action_received events nor, by recording a newer action_ts,
//     make an authorized member's click on the same message read as a
//     replay. A click refused by the service call of step 7 (e.g.
//     residuals_not_accepted) stays claimed: it got a definitive answer. A
//     refused, unclaimed click can be resent by Slack within the 5-minute
//     signature window; it then runs the same checks again.
//   - A click accepted but lost before step 6 (process stopped) recorded
//     nothing: the user clicks again.
//   - The clicked message must be the notification's (container.message_ts
//     = slack_ts); a resent notice makes the older message's buttons stale
//     (409 plan_changed: "open AuthSec").
//   - A notice addressed to a member ("user:<id>") acts only for that
//     member; the approvals-channel notice for any approver.
//   - Approval buttons carry a digest of the intent, impact, plan and
//     material hashes the message showed; a different digest now is 409
//     plan_changed. Approve is then called with the current hashes (equal
//     by the digest) and no acceptances: a version with residuals or gaps
//     is refused by Approve itself (409 residuals_not_accepted /
//     evidence_gaps_not_accepted) -- Slack never accepts items.
//   - A departed (not active) member is 403 forbidden; a member without
//     governance:approve is 403 forbidden (the permission middleware's
//     code for the UI route).
//   - Report a problem / It's working go to the health reporter T3.15
//     registers (SetGovHealthReporter): its authorization (owner of a
//     consumer, or governance:author) is that reporter's, as for the UI
//     route; a reporter that also implements GovHealthAuthorizer is asked
//     before the claim. Unregistered: 503 health_reports_unavailable.

const (
	// slackInteractionWorkers bounds the interactions running at once.
	slackInteractionWorkers = 16
	// slackInteractionTimeout bounds one interaction's work after the ack.
	slackInteractionTimeout = 2 * time.Minute
)

// GovHealthReport is a problem / working report from an owner.
type GovHealthReport struct {
	WorkspaceID uuid.UUID
	ActorID     uuid.UUID
	// SubjectKind and SubjectID are the notice's (deployment, canary_gate).
	SubjectKind string
	SubjectID   uuid.UUID
	Kind        string // problem | working
	Detail      string
	Channel     string // slack
}

// GovHealthReporter is T3.15's health-report service as Slack calls it: the
// same authorization and write as POST /deployments/:id/health-reports.
// It returns the stored report (for the audit row).
type GovHealthReporter interface {
	ReportHealth(ctx context.Context, r GovHealthReport) (any, error)
}

// GovHealthAuthorizer is optionally implemented by a GovHealthReporter: the
// reporter's authorization alone, without writing, so a Slack click is
// authorized before its action_ts is claimed.
type GovHealthAuthorizer interface {
	AuthorizeHealthReport(ctx context.Context, r GovHealthReport) error
}

var (
	govHealthMu       sync.RWMutex
	govHealthReporter GovHealthReporter
)

// SetGovHealthReporter installs T3.15's reporter; it returns a restore func.
func SetGovHealthReporter(h GovHealthReporter) (restore func()) {
	govHealthMu.Lock()
	prev := govHealthReporter
	govHealthReporter = h
	govHealthMu.Unlock()
	return func() {
		govHealthMu.Lock()
		govHealthReporter = prev
		govHealthMu.Unlock()
	}
}

func currentHealthReporter() GovHealthReporter {
	govHealthMu.RLock()
	defer govHealthMu.RUnlock()
	return govHealthReporter
}

// SlackInteractionAck is the synchronous answer to Slack.
type SlackInteractionAck struct {
	// Accepted: the action runs now; its outcome goes to the response_url.
	Accepted bool   `json:"accepted,omitempty"`
	Ignored  bool   `json:"ignored,omitempty"`
	Action   string `json:"action"`
}

// SlackInteractionResult is what one interaction did, for the controller's
// audit row.
type SlackInteractionResult struct {
	Ignored     bool      `json:"ignored,omitempty"`
	WorkspaceID uuid.UUID `json:"-"`
	UserID      uuid.UUID `json:"-"`
	Action      string    `json:"action"`
	Resource    string    `json:"resource,omitempty"`
	ResourceID  string    `json:"resource_id,omitempty"`
	Before      any       `json:"-"`
	After       any       `json:"result,omitempty"`
}

// SlackInteractionDone receives an accepted interaction's outcome once its
// work is over (the controller's audit row).
type SlackInteractionDone func(res *SlackInteractionResult, err error)

func signatureRefused(reason string) *GovError {
	return slackErr(http.StatusUnauthorized, SlackCodeSignatureInvalid, "The request is not a valid, fresh Slack request.",
		map[string]any{"reason": reason})
}

func notLinked(reason, link string) *GovError {
	d := map[string]any{"reason": reason}
	if link != "" {
		d["link_url"] = link
	}
	return slackErr(http.StatusForbidden, SlackCodeUserNotLinked, "This Slack account is not linked to a member of the workspace.", d)
}

// interactionCtx carries what the steps established.
type interactionCtx struct {
	in     *slackapp.Interaction
	act    slackapp.Action
	val    slackapp.ButtonValue
	n      models.IGAGovNotification
	integ  *models.WorkspaceSlackIntegration
	user   uuid.UUID
	member WorkspaceMember
}

// slackAction is an authorized action, run after its action_ts is claimed.
type slackAction func(ctx context.Context) (*SlackInteractionResult, error)

// WithInteractionObserver makes the service call f after every accepted
// interaction's work, with its outcome (tests; set before serving).
func (s *SlackIntegrationService) WithInteractionObserver(f func(*SlackInteractionResult, error)) *SlackIntegrationService {
	s.observer = f
	return s
}

// WaitInteractions waits for every accepted interaction to finish.
func (s *SlackIntegrationService) WaitInteractions() { s.inflight.Wait() }

// HandleInteraction runs steps 1-3 of one Slack interaction request
// (headers + raw body) and returns what to answer Slack now; an accepted
// interaction's steps 4-7 then run in the background, and done (may be nil)
// receives their outcome.
func (s *SlackIntegrationService) HandleInteraction(ctx context.Context, h http.Header, body []byte, done SlackInteractionDone) (*SlackInteractionAck, error) {
	ic, ack, err := s.acceptInteraction(ctx, h, body)
	if err != nil {
		return nil, err
	}
	if ic != nil {
		s.dispatch(ic, done)
	}
	return ack, nil
}

// acceptInteraction is steps 1-3; ic is nil for an ignored interaction.
func (s *SlackIntegrationService) acceptInteraction(ctx context.Context, h http.Header, body []byte) (*interactionCtx, *SlackInteractionAck, error) {
	if ok, _ := s.Configured(); !ok {
		// Without the signing secret nothing can be verified.
		return nil, nil, signatureRefused(slackapp.ReasonNotConfigured)
	}
	if err := slackapp.Verify(s.cfg.SigningSecret, h, body, s.now()); err != nil {
		var ve *slackapp.VerifyError
		if errors.As(err, &ve) {
			return nil, nil, signatureRefused(ve.Reason)
		}
		return nil, nil, signatureRefused("invalid")
	}
	in, err := slackapp.ParseInteraction(body)
	if err != nil {
		return nil, nil, GovBadParam("payload", "The body is not a Slack interaction payload.")
	}
	if in.Type != slackapp.TypeBlockActions || len(in.Actions) == 0 {
		return nil, &SlackInteractionAck{Ignored: true, Action: in.Type}, nil
	}
	ic := &interactionCtx{in: in, act: in.Actions[0]}
	if ic.act.ActionID == slackapp.ActionOpen {
		return nil, &SlackInteractionAck{Ignored: true, Action: slackapp.ActionOpen}, nil
	}
	if ic.val, err = slackapp.DecodeButtonValue(ic.act.Value); err != nil {
		return nil, nil, GovBadParam("actions[0].value", "The action does not belong to an AuthSec message.")
	}
	nid, err := uuid.Parse(ic.val.Notification)
	if err != nil {
		return nil, nil, GovNotFound()
	}
	db := s.db.WithContext(ctx)
	var ns []models.IGAGovNotification
	if err := db.Where("id = ? AND channel = ?", nid, GovChannelSlack).Limit(1).Find(&ns).Error; err != nil {
		return nil, nil, err
	}
	if len(ns) == 0 {
		return nil, nil, GovNotFound()
	}
	ic.n = ns[0]
	if ic.integ, err = activeSlackIntegration(db, ic.n.WorkspaceID); err != nil {
		return nil, nil, err
	}
	if ic.integ == nil || in.TeamID() == "" || in.TeamID() != ic.integ.SlackTeamID {
		// The Slack team is not the one installed in this workspace.
		return nil, nil, notLinked("team_not_connected", "")
	}
	ts := ic.act.ActionTS
	if !slackapp.ValidActionTS(ts) {
		return nil, nil, signatureRefused("bad_action_ts")
	}
	// Step 3, a read: an action already recorded is refused at once. The
	// claim itself (step 6) is atomic and comes after authorization.
	var fresh bool
	if err := db.Raw(`SELECT (last_action_ts = '' OR last_action_ts::numeric < ?::numeric) FROM iga_gov_notification WHERE workspace_id = ? AND id = ?`,
		ts, ic.n.WorkspaceID, ic.n.ID).Row().Scan(&fresh); err != nil {
		return nil, nil, err
	}
	if !fresh {
		return nil, nil, signatureRefused("replayed")
	}
	return ic, &SlackInteractionAck{Accepted: true, Action: ic.act.ActionID}, nil
}

// dispatch runs steps 4-7 of an accepted interaction after Slack has been
// answered: its own context (the request's ends with the answer), at most
// slackInteractionWorkers at a time.
func (s *SlackIntegrationService) dispatch(ic *interactionCtx, done SlackInteractionDone) {
	s.inflight.Add(1)
	go func() {
		defer s.inflight.Done()
		if s.slots != nil {
			s.slots <- struct{}{}
			defer func() { <-s.slots }()
		}
		ctx, cancel := context.WithTimeout(context.Background(), slackInteractionTimeout)
		defer cancel()
		res, err := s.runInteraction(ctx, ic)
		if done != nil {
			done(res, err)
		}
		if s.observer != nil {
			s.observer(res, err)
		}
	}()
}

// runInteraction is steps 4-7 and the answer to the clicking user.
func (s *SlackIntegrationService) runInteraction(ctx context.Context, ic *interactionCtx) (res *SlackInteractionResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[slack] workspace %s: interaction %s panicked: %v", ic.n.WorkspaceID, ic.act.ActionID, r)
			res, err = nil, fmt.Errorf("slack interaction: %v", r)
			s.answerRefusal(ctx, ic, err)
		}
	}()
	res, err = s.authenticated(ctx, ic)
	if err != nil {
		s.answerRefusal(ctx, ic, err)
		return nil, err
	}
	s.answerOutcome(ctx, ic, res)
	return res, nil
}

// authenticated is steps 4-7 for an authentic Slack user of the installed
// team.
func (s *SlackIntegrationService) authenticated(ctx context.Context, ic *interactionCtx) (*SlackInteractionResult, error) {
	db := s.db.WithContext(ctx)
	ws := ic.n.WorkspaceID
	if ic.n.SlackTS != "" && ic.in.MessageTS() != ic.n.SlackTS {
		return nil, govConflict(GovCodePlanChanged, "This message is no longer current; open AuthSec.", map[string]any{"reason": "message_superseded"})
	}
	// Step 4: map the Slack user.
	user, err := s.linkedUser(ctx, ic.integ, ic.in.User.ID)
	if err != nil {
		return nil, err
	}
	if user == uuid.Nil {
		link, _ := s.LinkURL(ws, ic.integ.SlackTeamID, ic.in.User.ID)
		return nil, notLinked("no_link", link)
	}
	m, err := s.members.ActiveMembers(db, ws, []uuid.UUID{user})
	if err != nil {
		return nil, err
	}
	member, ok := m[user]
	if !ok {
		return nil, govErr(http.StatusForbidden, "forbidden", slackapp.CopyNotMember, map[string]any{"reason": "not_active_member"})
	}
	ic.user, ic.member = user, member
	if r, isUser := GovRecipientUser(ic.n.Recipient); isUser && r != user {
		return nil, govErr(http.StatusForbidden, "forbidden", "This message was sent to another member.", map[string]any{"reason": "not_recipient"})
	}
	// Step 5: the UI route's authorization.
	var run slackAction
	switch ic.n.SubjectKind {
	case GovNoticeApprovalRequest:
		run, err = s.authorizeDecision(ctx, ic)
	case GovNoticeOwnerReview:
		run, err = s.authorizeResponse(ctx, ic)
	case GovNoticeDeployment, GovNoticeCanaryGate:
		run, err = s.authorizeHealth(ctx, ic)
	default:
		err = GovBadParam("actions[0].action_id", "This message takes no action.")
	}
	if err != nil {
		return nil, err
	}
	// Step 6: claim the action_ts, now that the click is authorized.
	if err := s.claimAction(ctx, ic); err != nil {
		return nil, err
	}
	// Step 7.
	return run(ctx)
}

// claimAction records the click's action_ts on the notification (atomic:
// only an action_ts newer than the recorded one is written) with its
// slack.action_received event; a click whose action_ts is not newer is a
// replay.
func (s *SlackIntegrationService) claimAction(ctx context.Context, ic *interactionCtx) error {
	ws, ts := ic.n.WorkspaceID, ic.act.ActionTS
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Exec(`UPDATE iga_gov_notification SET last_action_ts = ?
			WHERE workspace_id = ? AND id = ? AND (last_action_ts = '' OR last_action_ts::numeric < ?::numeric)`, ts, ws, ic.n.ID, ts)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return signatureRefused("replayed")
		}
		return appendGovEvent(tx, ws, GovEventSlackActionReceived, models.GovActorSlackUser, ic.in.User.ID, govEventRefs{}, map[string]any{
			"notification_id": ic.n.ID, "subject_kind": ic.n.SubjectKind, "subject_id": ic.n.SubjectID, "action": ic.act.ActionID,
			"action_ts": ts, "slack_user_id": ic.in.User.ID, "slack_team_id": ic.in.TeamID(), "member_id": ic.user})
	})
}

func (s *SlackIntegrationService) authoring() *GovAuthoring { return NewGovAuthoring(s.db, s.live) }

// approvalDigest is the digest an approval request's buttons carry.
func approvalDigest(h GovApprovalHashes) string {
	return slackapp.HashDigest([]string{h.IntentHash}, h.ImpactHashes, h.PlanHashes, h.MaterialHashes)
}

// authorizeDecision authorizes approve / reject of an approval request as
// the UI route does (governance:approve; the author never decides), checks
// the message's digest, and returns the decision.
func (s *SlackIntegrationService) authorizeDecision(ctx context.Context, ic *interactionCtx) (slackAction, error) {
	ws := ic.n.WorkspaceID
	if ic.act.ActionID != slackapp.ActionApprove && ic.act.ActionID != slackapp.ActionReject {
		return nil, GovBadParam("actions[0].action_id", "An approval request takes approve or reject.")
	}
	// The UI route's permission (governance:approve), read now.
	ok, err := WorkspaceUserHoldsPermission(s.db.WithContext(ctx), ws, ic.user, "governance", "approve")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, govErr(http.StatusForbidden, "forbidden", slackapp.CopyNotApprover,
			map[string]any{"required_permissions": []string{"governance:approve"}})
	}
	var v models.IGAGovPolicyVersion
	if err := s.db.WithContext(ctx).Where("workspace_id = ? AND id = ?", ws, ic.n.SubjectID).Take(&v).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, GovNotFound()
		}
		return nil, err
	}
	// Separation of duties (§2.10), as Approve / RejectVia enforce it again
	// in their transaction.
	if v.CreatedBy == ic.user {
		return nil, govErr(http.StatusForbidden, GovCodeSelfApproval, "You authored this version; another approver must decide.", nil)
	}
	a := s.authoring()
	pv, err := a.Plans(ctx, ws, v.PolicyID, v.VersionNo)
	if err != nil {
		return nil, err
	}
	if ic.val.Digest == "" || approvalDigest(pv.Hashes) != ic.val.Digest {
		return nil, govConflict(GovCodePlanChanged, "The plan changed since this message was posted; review the new version in AuthSec.",
			map[string]any{"version_no": v.VersionNo})
	}
	note := ic.in.Text(slackapp.BlockNote)
	if ic.act.ActionID == slackapp.ActionReject {
		if strings.TrimSpace(note) == "" {
			return nil, GovBadParam("reason", "A rejection needs a reason.")
		}
		return func(ctx context.Context) (*SlackInteractionResult, error) {
			ap, err := a.RejectVia(ctx, ws, ic.user, v.PolicyID, v.VersionNo, note, "slack")
			if err != nil {
				return nil, err
			}
			return &SlackInteractionResult{WorkspaceID: ws, UserID: ic.user, Action: "reject", Resource: "iga_gov_policy_version",
				ResourceID: ap.VersionID.String(), After: map[string]any{"approval_id": ap.ID, "reason": ap.Reason, "channel": ap.Channel}}, nil
		}, nil
	}
	return func(ctx context.Context) (*SlackInteractionResult, error) {
		res, err := a.Approve(ctx, ws, ic.user, v.PolicyID, v.VersionNo, GovApproveRequest{IntentHash: pv.Hashes.IntentHash,
			ImpactHashes: pv.Hashes.ImpactHashes, PlanHashes: pv.Hashes.PlanHashes, MaterialHashes: pv.Hashes.MaterialHashes,
			Acceptances: []GovAcceptanceInput{}, Reason: note, Channel: "slack"})
		if err != nil {
			return nil, err
		}
		return &SlackInteractionResult{WorkspaceID: ws, UserID: ic.user, Action: "approve", Resource: "iga_gov_policy_version",
			ResourceID: res.Version.ID.String(), After: map[string]any{"approval_id": res.Approval.ID, "channel": res.Approval.Channel,
				"plan_hashes": res.Approval.PlanHashes}}, nil
	}, nil
}

// ownerItems are the age and route items asked of user in the review view,
// with their checkbox values.
func ownerItems(v *GovReviewView, user uuid.UUID) (ages map[string]GovAgeConfirmation, routes map[string]GovRouteConfirmation, labels []slackapp.LabeledValue) {
	owned := map[uuid.UUID]bool{}
	for _, r := range v.Responses {
		if r.UserID == user {
			for _, of := range r.OwnerOf {
				owned[of.TargetID] = true
			}
		}
	}
	ages, routes = map[string]GovAgeConfirmation{}, map[string]GovRouteConfirmation{}
	if items, ok := v.Requested["age_confirmations"].([]GovAgeItem); ok {
		for _, a := range items {
			k := slackapp.ConfirmationValue("a", a.Service, "")
			if !owned[a.TargetID] || ages[k].Service != "" {
				continue
			}
			ages[k] = GovAgeConfirmation{Service: a.Service, Confirmed: true}
			labels = append(labels, slackapp.LabeledValue{Label: a.Service + " was not added recently", Value: k})
		}
	}
	if items, ok := v.Requested["route_confirmations"].([]GovRouteItem); ok {
		for _, r := range items {
			k := slackapp.ConfirmationValue("r", r.Service, r.Route)
			if !owned[r.TargetID] || routes[k].Service != "" {
				continue
			}
			routes[k] = GovRouteConfirmation{Service: r.Service, Route: r.Route, Confirmed: true}
			labels = append(labels, slackapp.LabeledValue{Label: r.Service + " is not used through " + r.Route, Value: k})
		}
	}
	return ages, routes, labels
}

// authorizeResponse authorizes acknowledge / retain / object on an owner
// review as the UI route does (an owner asked in the review) and returns
// the response.
func (s *SlackIntegrationService) authorizeResponse(ctx context.Context, ic *interactionCtx) (slackAction, error) {
	ws := ic.n.WorkspaceID
	switch ic.act.ActionID {
	case slackapp.ActionAcknowledge, slackapp.ActionRetain, slackapp.ActionObject:
	default:
		return nil, GovBadParam("actions[0].action_id", "An owner review takes acknowledge, retain or object.")
	}
	svc := NewIGAGovOwnerReviewService(s.db)
	owner, err := svc.IsOwnerOf(s.db.WithContext(ctx), ws, ic.n.SubjectID, ic.user)
	if err != nil {
		return nil, err
	}
	if !owner {
		return nil, govErr(http.StatusForbidden, "not_review_owner", slackapp.CopyNotOwner, nil)
	}
	return func(ctx context.Context) (*SlackInteractionResult, error) {
		in := GovRespondInput{Via: "slack", Comment: ic.in.Text(slackapp.BlockNote)}
		switch ic.act.ActionID {
		case slackapp.ActionAcknowledge:
			in.Response = GovResponseAcknowledge
			v, err := svc.View(ctx, ws, ic.n.SubjectID, ic.user)
			if err != nil {
				return nil, err
			}
			ages, routes, _ := ownerItems(v, ic.user)
			for _, k := range ic.in.Selected(slackapp.BlockConfirmations) {
				if a, ok := ages[k]; ok {
					in.AgeConfirmations = append(in.AgeConfirmations, a)
				} else if r, ok := routes[k]; ok {
					in.RouteConfirmations = append(in.RouteConfirmations, r)
				}
			}
		case slackapp.ActionRetain:
			in.Response = GovResponseRetain
			by := ic.in.Date(slackapp.BlockReviewBy)
			for _, svcName := range ic.in.Selected(slackapp.BlockRetainService) {
				in.RetainItems = append(in.RetainItems, GovRetainItem{Service: svcName, Reason: in.Comment, ReviewBy: by})
			}
		case slackapp.ActionObject:
			in.Response = GovResponseObject
		}
		res, err := svc.Respond(ctx, ws, ic.user, ic.n.SubjectID, in)
		if err != nil {
			if errors.Is(err, ErrNotReviewOwner) {
				return nil, govErr(http.StatusForbidden, "not_review_owner", slackapp.CopyNotOwner, nil)
			}
			return nil, err
		}
		return &SlackInteractionResult{WorkspaceID: ws, UserID: ic.user, Action: "respond", Resource: "iga_gov_owner_review",
			ResourceID: ic.n.SubjectID.String(), Before: res.Before, After: res.Response}, nil
	}, nil
}

// authorizeHealth checks a Report a problem / It's working click (the
// reporter's own authorization when it exposes one) and returns the report.
func (s *SlackIntegrationService) authorizeHealth(ctx context.Context, ic *interactionCtx) (slackAction, error) {
	kind := ""
	switch ic.act.ActionID {
	case slackapp.ActionReportProblem:
		kind = "problem"
	case slackapp.ActionWorking:
		kind = "working"
	default:
		return nil, GovBadParam("actions[0].action_id", "A deployment notice takes report_problem or working.")
	}
	h := currentHealthReporter()
	if h == nil {
		return nil, govErr(http.StatusServiceUnavailable, "health_reports_unavailable",
			"Health reports are not available in this build: rollout has not been released.", nil)
	}
	detail := ic.in.Text(slackapp.BlockNote)
	if kind == "problem" && detail == "" {
		return nil, GovBadParam("detail", "Say what broke in the box above, then Report a problem.")
	}
	r := GovHealthReport{WorkspaceID: ic.n.WorkspaceID, ActorID: ic.user, SubjectKind: ic.n.SubjectKind,
		SubjectID: ic.n.SubjectID, Kind: kind, Detail: detail, Channel: "slack"}
	if a, ok := h.(GovHealthAuthorizer); ok {
		if err := a.AuthorizeHealthReport(ctx, r); err != nil {
			return nil, err
		}
	}
	return func(ctx context.Context) (*SlackInteractionResult, error) {
		out, err := h.ReportHealth(ctx, r)
		if err != nil {
			return nil, err
		}
		return &SlackInteractionResult{WorkspaceID: ic.n.WorkspaceID, UserID: ic.user, Action: "health_report",
			Resource: "iga_gov_health_report", ResourceID: ic.n.SubjectID.String(), After: out}, nil
	}, nil
}

/* ------------------------------ answers to Slack ---------------------------- */

func (s *SlackIntegrationService) respondURL(ctx context.Context, ic *interactionCtx, msg slackapp.Message) {
	if ic.in.ResponseURL == "" || s.api == nil {
		return
	}
	if err := s.api.Respond(ctx, ic.in.ResponseURL, msg); err != nil {
		log.Printf("[slack] workspace %s: response_url: %v", ic.n.WorkspaceID, err)
	}
}

// answerRefusal tells the clicking user, ephemerally, why nothing happened
// (§9.3 copy).
func (s *SlackIntegrationService) answerRefusal(ctx context.Context, ic *interactionCtx, err error) {
	var ge *GovError
	if !errors.As(err, &ge) {
		s.respondURL(ctx, ic, slackapp.Refusal(slackapp.CopyTryAuthSec, "", ""))
		return
	}
	link := slackNoticeLink(ic.n)
	switch ge.Code {
	case SlackCodeSignatureInvalid:
		return // a replay gets no answer
	case SlackCodeUserNotLinked:
		l, _ := ge.Detail["link_url"].(string)
		s.respondURL(ctx, ic, slackapp.Refusal(slackapp.CopyLinkAccount, l, "Link your Slack account"))
	case GovCodeSelfApproval:
		s.respondURL(ctx, ic, slackapp.Refusal(slackapp.CopyAuthored, link, ""))
	case GovCodePlanChanged, GovCodeImpactChanged, GovCodeVersionConflict:
		s.respondURL(ctx, ic, slackapp.Refusal(slackapp.CopyPlanChanged, link, "Open AuthSec"))
	case GovCodeResidualsNotAccept, GovCodeGapsNotAccepted:
		s.respondURL(ctx, ic, slackapp.Refusal(slackapp.CopyAcceptInAuthSec, link, "Accept in AuthSec"))
	default:
		s.respondURL(ctx, ic, slackapp.Refusal(ge.Message, link, ""))
	}
}

// answerOutcome replaces the message with what was done.
func (s *SlackIntegrationService) answerOutcome(ctx context.Context, ic *interactionCtx, res *SlackInteractionResult) {
	if res == nil || res.Ignored {
		return
	}
	who := ic.member.Name
	if who == "" {
		who = ic.member.Email
	}
	at := s.now().UTC().Format("15:04 UTC")
	var title string
	switch ic.act.ActionID {
	case slackapp.ActionApprove:
		title = fmt.Sprintf("Approved by %s at %s", who, at)
	case slackapp.ActionReject:
		title = fmt.Sprintf("Rejected by %s at %s", who, at)
	case slackapp.ActionAcknowledge:
		title = fmt.Sprintf("You confirmed the change looks fine (%s)", at)
	case slackapp.ActionRetain:
		title = fmt.Sprintf("You kept access; the author will see a new version (%s)", at)
	case slackapp.ActionObject:
		title = fmt.Sprintf("You reported this will break something; the version is blocked (%s)", at)
	case slackapp.ActionReportProblem:
		title = fmt.Sprintf("Problem reported by %s at %s", who, at)
	case slackapp.ActionWorking:
		title = fmt.Sprintf("%s confirmed it's working at %s", who, at)
	}
	line := ""
	if note := ic.in.Text(slackapp.BlockNote); note != "" {
		line = strings.TrimSpace(note)
	}
	s.respondURL(ctx, ic, slackapp.Outcome(title, line))
}

// slackNoticeLink is the console page a notice is about.
func slackNoticeLink(n models.IGAGovNotification) string {
	switch n.SubjectKind {
	case GovNoticeApprovalRequest:
		return govConsoleLink("/iga/policy/approvals")
	case GovNoticeOwnerReview:
		return govConsoleLink("/iga/policy/reviews/" + n.SubjectID.String())
	case GovNoticeDeployment, GovNoticeCanaryGate:
		return govConsoleLink("/iga/policy/deployments")
	}
	return govConsoleLink("/iga/policy")
}
