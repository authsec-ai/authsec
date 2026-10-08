package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/internal/slackapp"
	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
)

// The Slack notification channel (T3.12's GovNotificationChannel, T3.14):
// owner reviews reach a member's Slack DM when the member is linked;
// approval requests go to the workspace's approvals channel (recipient
// "approvals_channel"); deployment and canary notices carry Report a
// problem / It's working. Delivery is the notify job's (retry x 10 min,
// dead after 5); Deliver returns the posted message ts, stored as the
// notification's slack_ts and checked on every interaction.
//
// Approval requests are enqueued by the authoring hooks WithSlackApprovalNotices
// adds (OnProposed; OnImpactChanged re-sends, so the posted hashes are the
// current ones): one notice per version (subject approval_request =
// version id) while the workspace has Slack with an approvals channel.
//
// DECISIONS (T3.14):
//   - The approval message is built at send time from the version's
//     current plans (the same Plans read GET .../plans serves): Approve is
//     offered only when no acceptance item (unanalysed form or evidence
//     gap) exists; otherwise "N residuals to accept", Accept in AuthSec and
//     Reject (§9.3 S6, §14.1 step 5).
//   - A version that is no longer in review when its notice is sent kills
//     the notice (permanent): there is nothing to decide.

// SlackNotificationChannel implements GovNotificationChannel.
type SlackNotificationChannel struct {
	svc *SlackIntegrationService
}

// NewSlackNotificationChannel is the channel over svc.
func NewSlackNotificationChannel(svc *SlackIntegrationService) *SlackNotificationChannel {
	return &SlackNotificationChannel{svc: svc}
}

// Channel implements GovNotificationChannel.
func (c *SlackNotificationChannel) Channel() string { return GovChannelSlack }

// Reaches implements GovNotificationChannel: Slack is connected and the
// member has a Slack link.
func (c *SlackNotificationChannel) Reaches(db *gorm.DB, ws, userID uuid.UUID) (bool, error) {
	var n int64
	err := db.Raw(`SELECT count(*) FROM slack_user_link l JOIN workspace_slack_integration i
	                 ON i.workspace_id = l.workspace_id AND i.revoked_at IS NULL
	                WHERE l.workspace_id = ? AND l.user_id = ?`, ws, userID).Scan(&n).Error
	return n > 0, err
}

// Deliver implements GovNotificationChannel.
func (c *SlackNotificationChannel) Deliver(ctx context.Context, db *gorm.DB, n models.IGAGovNotification, user *uuid.UUID, notice *GovNotice) (string, error) {
	s := c.svc
	if ok, reason := s.Configured(); !ok {
		return "", errors.New(reason) // retried: configuration can be fixed
	}
	in, err := activeSlackIntegration(db, n.WorkspaceID)
	if err != nil {
		return "", err
	}
	if in == nil {
		return "", GovNotifyPermanent(errors.New("Slack is not connected to this workspace"))
	}
	var channel string
	switch {
	case n.Recipient == SlackRecipientApprovals:
		if in.ApprovalsChannelID == "" {
			return "", GovNotifyPermanent(errors.New("no Slack approvals channel is set"))
		}
		channel = in.ApprovalsChannelID
	case user != nil:
		var links []models.SlackUserLink
		if err := db.Where("workspace_id = ? AND user_id = ?", n.WorkspaceID, *user).Order("linked_at DESC").Limit(1).Find(&links).Error; err != nil {
			return "", err
		}
		if len(links) == 0 {
			return "", GovNotifyPermanent(errors.New("the recipient has no linked Slack account"))
		}
		channel = links[0].SlackUserID
	default:
		return "", GovNotifyPermanent(fmt.Errorf("slack recipient %q is not supported", n.Recipient))
	}
	msg, err := c.message(ctx, db, n, user, notice)
	if err != nil {
		return "", err
	}
	token, err := s.botToken(in)
	if err != nil {
		return "", err
	}
	ts, _, err := s.api.PostMessage(ctx, token, channel, msg)
	if err != nil {
		if slackapp.IsAPIError(err, "account_inactive", "invalid_auth", "token_revoked", "channel_not_found", "is_archived", "user_not_found") {
			return "", GovNotifyPermanent(err)
		}
		return "", err
	}
	return ts, nil
}

func (c *SlackNotificationChannel) message(ctx context.Context, db *gorm.DB, n models.IGAGovNotification, user *uuid.UUID, notice *GovNotice) (slackapp.Message, error) {
	value := slackapp.ButtonValue{Notification: n.ID.String()}
	switch n.SubjectKind {
	case GovNoticeApprovalRequest:
		r, err := c.svc.approvalRequest(ctx, db, n)
		if err != nil {
			return slackapp.Message{}, err
		}
		return slackapp.BuildApprovalRequest(*r), nil
	case GovNoticeOwnerReview:
		if user == nil {
			return slackapp.Message{}, GovNotifyPermanent(errors.New("an owner review is sent to a member"))
		}
		v, err := NewIGAGovOwnerReviewService(db).View(ctx, n.WorkspaceID, n.SubjectID, *user)
		if err != nil {
			return slackapp.Message{}, err
		}
		_, _, labels := ownerItems(v, *user)
		removed := map[string]bool{}
		owned := map[uuid.UUID]bool{}
		for _, r := range v.Responses {
			if r.UserID == *user {
				for _, of := range r.OwnerOf {
					owned[of.TargetID] = true
				}
			}
		}
		for _, t := range v.Targets {
			if owned[t.TargetID] {
				for _, rm := range t.Removed {
					removed[rm.Service] = true
				}
			}
		}
		var rm []string
		for svc := range removed {
			rm = append(rm, svc)
		}
		sort.Strings(rm)
		return slackapp.BuildOwnerReview(slackapp.OwnerReview{Title: notice.Title, Lines: notice.Lines,
			Due: v.DeadlineAt.UTC().Format("Mon 2 Jan 15:04 MST"), Confirmations: labels, Removed: rm,
			Link: notice.Link, Value: value.Encode()}), nil
	case GovNoticeDeployment, GovNoticeCanaryGate:
		return slackapp.BuildNotice(slackapp.Notice{Title: notice.Title, Lines: notice.Lines, Link: notice.Link, Value: value.Encode()}), nil
	}
	return slackapp.BuildNotice(slackapp.Notice{Title: notice.Title, Lines: notice.Lines, Link: notice.Link}), nil
}

// residualLabel is how an acceptance item reads in Slack.
func residualLabel(it GovAcceptanceItem) string {
	switch it.Kind {
	case GovAcceptUnanalysed:
		if u, ok := it.Detail.(igagov.UnanalysedItem); ok {
			switch {
			case u.Form != "":
				return u.Form + " policies of " + it.RoleID + " not analysed"
			case u.Key == "other_accounts":
				return "resources in other accounts may name " + it.RoleID
			}
		}
	case GovAcceptGap:
		if g, ok := it.Detail.(igagov.Gap); ok && g.Reason != "" {
			return g.Key + " (" + g.Reason + ")"
		}
	}
	return it.ItemKey
}

// approvalRequest builds the approval message of a version from its
// current plans.
func (s *SlackIntegrationService) approvalRequest(ctx context.Context, db *gorm.DB, n models.IGAGovNotification) (*slackapp.ApprovalRequest, error) {
	var v models.IGAGovPolicyVersion
	if err := db.Where("workspace_id = ? AND id = ?", n.WorkspaceID, n.SubjectID).Take(&v).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, GovNotifyPermanent(errors.New("the version no longer exists"))
		}
		return nil, err
	}
	if v.Status != "in_review" {
		return nil, GovNotifyPermanent(fmt.Errorf("version %d is %s; nothing to approve", v.VersionNo, v.Status))
	}
	var pol models.IGAGovPolicy
	if err := db.Where("workspace_id = ? AND id = ?", n.WorkspaceID, v.PolicyID).Take(&pol).Error; err != nil {
		return nil, err
	}
	pv, err := NewGovAuthoring(db, s.live).Plans(ctx, n.WorkspaceID, v.PolicyID, v.VersionNo)
	if err != nil {
		return nil, err
	}
	r := &slackapp.ApprovalRequest{PolicyName: pol.Name, VersionNo: v.VersionNo, Link: govConsoleLink("/iga/policy/approvals"),
		Value: slackapp.ButtonValue{Notification: n.ID.String(), Digest: approvalDigest(pv.Hashes)}.Encode()}
	consumers := map[string]bool{}
	for _, p := range pv.Plans {
		if p.Kind != igagov.PlanApply {
			continue
		}
		var im igagov.Impact
		_ = json.Unmarshal(p.Impact, &im)
		var rm, keep []string
		for _, x := range im.Removed {
			rm = append(rm, x.Service)
		}
		for _, x := range im.Retained {
			keep = append(keep, x.Service)
		}
		line := fmt.Sprintf("Removes %d AWS service%s from %s", len(rm), pluralS(len(rm)), roleName(p.RoleARN))
		if len(rm) > 0 && len(rm) <= 12 {
			line += " (" + strings.Join(rm, ", ") + ")"
		}
		if len(keep) > 0 {
			line += " · keeps " + strings.Join(keep, ", ")
		}
		r.Summary = append(r.Summary, line)
		for _, c := range im.Consumers {
			consumers[c.WorkloadID] = true
		}
		if p.FirstAttachment {
			r.Summary = append(r.Summary, "Undo: removes the boundary (the role had none)")
		}
	}
	if len(consumers) > 0 {
		r.Summary = append(r.Summary, fmt.Sprintf("Affects %d workload%s", len(consumers), pluralS(len(consumers))))
	}
	var reviewIDs []uuid.UUID
	if err := db.Raw(`SELECT id FROM iga_gov_owner_review WHERE workspace_id = ? AND version_id = ?`, n.WorkspaceID, v.ID).Scan(&reviewIDs).Error; err != nil {
		return nil, err
	}
	if len(reviewIDs) == 1 {
		if rv, err := NewIGAGovOwnerReviewService(db).View(ctx, n.WorkspaceID, reviewIDs[0], uuid.Nil); err == nil {
			done := 0
			for _, x := range rv.Responses {
				if x.Response != nil {
					done++
				}
			}
			r.Summary = append(r.Summary, fmt.Sprintf("Owners %d/%d · review %s", done, len(rv.Responses), rv.Status))
		}
	}
	if m, err := s.members.ActiveMembers(db, n.WorkspaceID, []uuid.UUID{v.CreatedBy}); err == nil {
		if a, ok := m[v.CreatedBy]; ok {
			r.RequestedBy = a.Name
			if r.RequestedBy == "" {
				r.RequestedBy = a.Email
			}
		}
	}
	for _, it := range pv.AcceptanceItems {
		if it.Kind == GovAcceptGap {
			r.Gaps = append(r.Gaps, residualLabel(it))
		} else {
			r.Residuals = append(r.Residuals, residualLabel(it))
		}
	}
	return r, nil
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

/* ------------------------- approval request notices ------------------------ */

func init() {
	// approval_request's renderer (T3.13 registered none): a channel-neutral
	// notice; Slack builds its own message from the version (above).
	RegisterGovNoticeSubject(GovNoticeApprovalRequest, GovNoticeSubject{Render: renderApprovalRequestNotice})
}

func renderApprovalRequestNotice(db *gorm.DB, n *models.IGAGovNotification, _ *uuid.UUID) (*GovNotice, error) {
	var v models.IGAGovPolicyVersion
	if err := db.Where("workspace_id = ? AND id = ?", n.WorkspaceID, n.SubjectID).Take(&v).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, GovNotifyPermanent(errors.New("the version no longer exists"))
		}
		return nil, err
	}
	var pol models.IGAGovPolicy
	if err := db.Where("workspace_id = ? AND id = ?", n.WorkspaceID, v.PolicyID).Take(&pol).Error; err != nil {
		return nil, err
	}
	link := govConsoleLink("/iga/policy/approvals")
	title := fmt.Sprintf("Approval requested: %s (v%d)", pol.Name, v.VersionNo)
	text := title + "\n"
	if link != "" {
		text += "\nReview it in AuthSec:\n  " + link + "\n"
	}
	return &GovNotice{Subject: title, Text: text, Title: title, Link: link,
		Webhook: map[string]any{"type": "iga.policy.approval_request", "version": 1, "workspace_id": n.WorkspaceID.String(),
			"policy_id": pol.ID.String(), "policy_name": pol.Name, "version_no": v.VersionNo, "status": v.Status, "link": link}}, nil
}

// EnqueueSlackApprovalRequestTx queues the approval request of a version
// to the workspace's approvals channel, when Slack is available and
// connected with a channel. resend re-posts an already sent request.
func EnqueueSlackApprovalRequestTx(tx *gorm.DB, ws, versionID uuid.UUID, resend bool) error {
	if _, ok := govNoticeChannel(GovChannelSlack); !ok {
		return nil
	}
	in, err := activeSlackIntegration(tx, ws)
	if err != nil || in == nil || in.ApprovalsChannelID == "" {
		return err
	}
	_, err = EnqueueGovNotificationTx(tx, ws, GovNoticeApprovalRequest, versionID, GovChannelSlack, SlackRecipientApprovals, resend)
	return err
}

// WithSlackApprovalNotices chains the approval-request enqueue onto h's
// OnProposed (re-sent when re-proposed) and OnImpactChanged (re-sent).
func WithSlackApprovalNotices(h GovAuthoringHooks) GovAuthoringHooks {
	prevP, prevI := h.OnProposed, h.OnImpactChanged
	h.OnProposed = func(tx *gorm.DB, p GovProposedVersion) error {
		if prevP != nil {
			if err := prevP(tx, p); err != nil {
				return err
			}
		}
		return EnqueueSlackApprovalRequestTx(tx, p.WorkspaceID, p.VersionID, p.Reproposed)
	}
	h.OnImpactChanged = func(tx *gorm.DB, c GovImpactChange) error {
		if prevI != nil {
			if err := prevI(tx, c); err != nil {
				return err
			}
		}
		return EnqueueSlackApprovalRequestTx(tx, c.WorkspaceID, c.VersionID, true)
	}
	return h
}

/* ------------------------------- installation ------------------------------ */

// InstallSlackApp registers svc's notification channel and chains the
// approval-request hooks onto the process-wide authoring hooks. Call once
// at startup, after any other SetGovAuthoringHooks. It returns a function
// undoing both (tests).
func InstallSlackApp(svc *SlackIntegrationService) (restore func()) {
	RegisterGovNotificationChannel(GovChannelSlack, NewSlackNotificationChannel(svc))
	prev := SetGovAuthoringHooks(GovAuthoringHooks{})
	SetGovAuthoringHooks(WithSlackApprovalNotices(prev))
	return func() {
		SetGovAuthoringHooks(prev)
		RegisterGovNotificationChannel(GovChannelSlack, nil)
	}
}

// SlackAvailable is the capabilities "slack" flag: the Slack app is
// installed in this process (configured: signing secret, Vault, API).
func SlackAvailable() (bool, string) {
	if _, ok := govNoticeChannel(GovChannelSlack); ok {
		return true, ""
	}
	return false, "Slack is not configured on this server: set " + SlackSigningSecretEnv +
		" and the Slack app's client_id / client_secret in Vault."
}

// SlackStatusForSettings is the Slack block of GET /policy/settings.
func SlackStatusForSettings(db *gorm.DB, ws uuid.UUID) *SlackStatusView {
	return slackStatusFor(db, ws)
}

// SlackConsoleLink is a console URL for path ("" when no base URL is set).
func SlackConsoleLink(path string) string { return govConsoleLink(path) }

var defaultSlack *SlackIntegrationService

// SlackFromEnv builds the production Slack app: the signing secret and
// paths from the environment, Vault from VAULT_ADDR / VAULT_TOKEN, the
// Slack Web API over HTTPS. The result may be unconfigured (Configured
// says why); it is never nil.
func SlackFromEnv(db *gorm.DB) *SlackIntegrationService {
	var vc vault.VaultClient
	if addr, tok := os.Getenv("VAULT_ADDR"), os.Getenv("VAULT_TOKEN"); addr != "" && tok != "" {
		if c, err := vault.NewClient(addr, tok); err == nil {
			vc = c
		} else {
			log.Printf("[slack] Vault client: %v", err)
		}
	}
	return NewSlackIntegrationService(db, vc, slackapp.NewHTTPAPI(), SlackConfigFromEnv())
}

// SetDefaultSlackService records the process's Slack app (startup); the
// routes use it. Nil: not configured.
func SetDefaultSlackService(s *SlackIntegrationService) { defaultSlack = s }

// DefaultSlackService is the process's Slack app, or nil.
func DefaultSlackService() *SlackIntegrationService { return defaultSlack }
