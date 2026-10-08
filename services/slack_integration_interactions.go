package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/slackapp"
	"github.com/authsec-ai/authsec/models"
)

// POST /authsec/integrations/slack/interactions (§7.11): Slack signature
// only. The order is the spec's:
//
//  1. X-Slack-Signature (v0 HMAC-SHA256 over v0:<ts>:<body>, constant-time)
//     and X-Slack-Request-Timestamp within 5 minutes   -> 401 slack_signature_invalid
//  2. the payload names an AuthSec notification posted to Slack, of the
//     Slack team installed in that notification's workspace
//  3. the action_ts is newer than the one recorded on the notification
//     (iga_gov_notification.last_action_ts, claimed atomically, with a
//     slack.action_received event)                     -> 401 slack_signature_invalid (replayed)
//  4. the Slack user maps to an active member through slack_user_link   -> 403 slack_user_not_linked
//  5. the UI route's authorization is re-run, then the SAME service call
//     the UI route makes: GovAuthoring.Approve / RejectVia with channel
//     slack (separation of duties is enforced there), the owner review's
//     Respond with Via slack, and T3.15's health report.
//
// After step 2 every refusal is also answered to the clicking user only
// (ephemeral, through the payload's response_url) in the §9.3 copy; a
// decision replaces the message with its outcome ("Approved by … at …").
//
// DECISIONS (T3.14):
//   - Replay is "an action_ts not newer than the last one recorded" (a
//     numeric comparison): the row keeps one value, so equality alone would
//     let an older captured action through after a newer one. It is
//     refused with 401 slack_signature_invalid, reason "replayed" -- §7.12
//     has no separate code, and a replayed request is not a valid fresh
//     Slack request.
//   - The action_ts is claimed before the user is mapped or the action
//     runs, and stays claimed when the action is refused.
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
//     route. Unregistered: 503 health_reports_unavailable.

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

// SlackInteractionResult is what one interaction did, for the controller's
// audit row and response.
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

// HandleInteraction runs one Slack interaction request (headers + raw body).
func (s *SlackIntegrationService) HandleInteraction(ctx context.Context, h http.Header, body []byte) (*SlackInteractionResult, error) {
	if ok, _ := s.Configured(); !ok {
		// Without the signing secret nothing can be verified.
		return nil, signatureRefused(slackapp.ReasonNotConfigured)
	}
	if err := slackapp.Verify(s.cfg.SigningSecret, h, body, s.now()); err != nil {
		var ve *slackapp.VerifyError
		if errors.As(err, &ve) {
			return nil, signatureRefused(ve.Reason)
		}
		return nil, signatureRefused("invalid")
	}
	in, err := slackapp.ParseInteraction(body)
	if err != nil {
		return nil, GovBadParam("payload", "The body is not a Slack interaction payload.")
	}
	if in.Type != slackapp.TypeBlockActions || len(in.Actions) == 0 {
		return &SlackInteractionResult{Ignored: true, Action: in.Type}, nil
	}
	ic := &interactionCtx{in: in, act: in.Actions[0]}
	if ic.act.ActionID == slackapp.ActionOpen {
		return &SlackInteractionResult{Ignored: true, Action: slackapp.ActionOpen}, nil
	}
	if ic.val, err = slackapp.DecodeButtonValue(ic.act.Value); err != nil {
		return nil, GovBadParam("actions[0].value", "The action does not belong to an AuthSec message.")
	}
	nid, err := uuid.Parse(ic.val.Notification)
	if err != nil {
		return nil, GovNotFound()
	}
	db := s.db.WithContext(ctx)
	var ns []models.IGAGovNotification
	if err := db.Where("id = ? AND channel = ?", nid, GovChannelSlack).Limit(1).Find(&ns).Error; err != nil {
		return nil, err
	}
	if len(ns) == 0 {
		return nil, GovNotFound()
	}
	ic.n = ns[0]
	ws := ic.n.WorkspaceID
	if ic.integ, err = activeSlackIntegration(db, ws); err != nil {
		return nil, err
	}
	if ic.integ == nil || in.TeamID() == "" || in.TeamID() != ic.integ.SlackTeamID {
		// The Slack team is not the one installed in this workspace.
		return nil, notLinked("team_not_connected", "")
	}
	// From here the caller is an authentic Slack user of the installed
	// team: refusals are also answered to them.
	res, err := s.authenticated(ctx, ic)
	if err != nil {
		s.answerRefusal(ctx, ic, err)
		return nil, err
	}
	s.answerOutcome(ctx, ic, res)
	return res, nil
}

func (s *SlackIntegrationService) authenticated(ctx context.Context, ic *interactionCtx) (*SlackInteractionResult, error) {
	db := s.db.WithContext(ctx)
	ws := ic.n.WorkspaceID
	ts := ic.act.ActionTS
	if !slackapp.ValidActionTS(ts) {
		return nil, signatureRefused("bad_action_ts")
	}
	// Step 3: claim the action_ts (replay check) with its event.
	err := db.Transaction(func(tx *gorm.DB) error {
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
			"action_ts": ts, "slack_user_id": ic.in.User.ID, "slack_team_id": ic.in.TeamID()})
	})
	if err != nil {
		return nil, err
	}
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
	// Step 5.
	switch ic.n.SubjectKind {
	case GovNoticeApprovalRequest:
		return s.decide(ctx, ic)
	case GovNoticeOwnerReview:
		return s.respond(ctx, ic)
	case GovNoticeDeployment, GovNoticeCanaryGate:
		return s.reportHealth(ctx, ic)
	}
	return nil, GovBadParam("actions[0].action_id", "This message takes no action.")
}

func (s *SlackIntegrationService) authoring() *GovAuthoring { return NewGovAuthoring(s.db, s.live) }

// approvalDigest is the digest an approval request's buttons carry.
func approvalDigest(h GovApprovalHashes) string {
	return slackapp.HashDigest([]string{h.IntentHash}, h.ImpactHashes, h.PlanHashes, h.MaterialHashes)
}

// decide is approve / reject of an approval request.
func (s *SlackIntegrationService) decide(ctx context.Context, ic *interactionCtx) (*SlackInteractionResult, error) {
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
		ap, err := a.RejectVia(ctx, ws, ic.user, v.PolicyID, v.VersionNo, note, "slack")
		if err != nil {
			return nil, err
		}
		return &SlackInteractionResult{WorkspaceID: ws, UserID: ic.user, Action: "reject", Resource: "iga_gov_policy_version",
			ResourceID: ap.VersionID.String(), After: map[string]any{"approval_id": ap.ID, "reason": ap.Reason, "channel": ap.Channel}}, nil
	}
	res, err := a.Approve(ctx, ws, ic.user, v.PolicyID, v.VersionNo, GovApproveRequest{IntentHash: pv.Hashes.IntentHash,
		ImpactHashes: pv.Hashes.ImpactHashes, PlanHashes: pv.Hashes.PlanHashes, MaterialHashes: pv.Hashes.MaterialHashes,
		Acceptances: []GovAcceptanceInput{}, Reason: note, Channel: "slack"})
	if err != nil {
		return nil, err
	}
	return &SlackInteractionResult{WorkspaceID: ws, UserID: ic.user, Action: "approve", Resource: "iga_gov_policy_version",
		ResourceID: res.Version.ID.String(), After: map[string]any{"approval_id": res.Approval.ID, "channel": res.Approval.Channel,
			"plan_hashes": res.Approval.PlanHashes}}, nil
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

// respond is acknowledge / retain / object on an owner review.
func (s *SlackIntegrationService) respond(ctx context.Context, ic *interactionCtx) (*SlackInteractionResult, error) {
	ws := ic.n.WorkspaceID
	svc := NewIGAGovOwnerReviewService(s.db)
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
	default:
		return nil, GovBadParam("actions[0].action_id", "An owner review takes acknowledge, retain or object.")
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
}

// reportHealth is Report a problem / It's working.
func (s *SlackIntegrationService) reportHealth(ctx context.Context, ic *interactionCtx) (*SlackInteractionResult, error) {
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
	out, err := h.ReportHealth(ctx, GovHealthReport{WorkspaceID: ic.n.WorkspaceID, ActorID: ic.user, SubjectKind: ic.n.SubjectKind,
		SubjectID: ic.n.SubjectID, Kind: kind, Detail: detail, Channel: "slack"})
	if err != nil {
		return nil, err
	}
	return &SlackInteractionResult{WorkspaceID: ic.n.WorkspaceID, UserID: ic.user, Action: "health_report",
		Resource: "iga_gov_health_report", ResourceID: ic.n.SubjectID.String(), After: out}, nil
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
