package services

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/slackapp"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
)

// Delivery of asks (SPEC-secops-backend-upgrade.md W4, C13) through the
// governance notification outbox (iga_gov_notify.go): one
// iga_gov_notification per (ask, channel, recipient), delivered by the
// notify job (attempt x 10 min, dead after 5), re-sent to the new deciders
// when the ask moves on.
//
//   - E-mail (the application's mailer) to each decider, with the console
//     link: the answer is given in the console.
//   - Slack, to each decider with a linked Slack account: an interactive
//     message with one button per choice and "Not mine". Each button's value
//     carries the notification id, the choice and a server HMAC over
//     (notification, ask, step, choice) keyed with the Slack signing secret;
//     the request itself is verified as every Slack interaction is
//     (slack_integration_interactions.go: signature, freshness, the replay
//     claim of action_ts, the clicked message being the notification's
//     current one, the clicking member being its recipient). A click on a
//     message posted for an earlier step is refused (ask_changed). A Slack
//     answer to a tier-2+ ask is recorded as pending_step_up and takes effect
//     when the same person confirms it in the console.
//   - The workspace webhook, signed as the agent runtime SIEM webhook is
//     (X-AuthSec-Timestamp, HMAC over timestamp + "." + body,
//     X-AuthSec-Delivery = the notification id), when the policy turns it on.
//
// Channels are the workspace's agent_ask_policy (Slack and e-mail on, the
// webhook off by default). Queueing never loses the ask: it runs in a
// savepoint and a failure is logged.

// GovNoticeAgentAsk is the subject kind of an ask's notices (220 admits it).
const GovNoticeAgentAsk = "agent_ask"

// askNotMineChoice is the token choice of the "Not mine" button.
const askNotMineChoice = "-not_mine"

func init() {
	RegisterGovNoticeSubject(GovNoticeAgentAsk, GovNoticeSubject{
		Render:             renderAgentAskNotice,
		WebhookTimestamped: true,
		OnSent: func(tx *gorm.DB, n *models.IGAGovNotification, user *uuid.UUID) error {
			return askDeliveryEvent(tx, n, user, AskEventDelivered, "")
		},
		OnDead: func(tx *gorm.DB, n *models.IGAGovNotification, user *uuid.UUID) error {
			return askDeliveryEvent(tx, n, user, AskEventDeliveryFailed, "delivery failed after its retries")
		},
	})
}

func askDeliveryEvent(tx *gorm.DB, n *models.IGAGovNotification, user *uuid.UUID, kind, why string) error {
	var steps []int
	if err := tx.Raw(`SELECT step FROM agent_ask WHERE workspace_id = ? AND id = ?`, n.WorkspaceID, n.SubjectID).Scan(&steps).Error; err != nil {
		return err
	}
	if len(steps) == 0 {
		return nil // the ask is gone with its workspace
	}
	d := map[string]any{"notification_id": n.ID}
	if user != nil {
		d["recipient_user_id"] = *user
	} else {
		d["recipient"] = n.Recipient
	}
	if why != "" {
		d["error"] = why
	}
	return appendAskEvent(tx, n.WorkspaceID, n.SubjectID, kind, steps[0], "system", "", n.Channel, d)
}

// AgentAskConsoleLink is the console page of an ask ("" without a base URL).
func AgentAskConsoleLink(id uuid.UUID) string {
	return govConsoleLink("/iga/agent-runtime/asks/" + id.String())
}

func askChoiceLabels(cs []AskChoice) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Label)
	}
	return out
}

func renderAgentAskNotice(db *gorm.DB, n *models.IGAGovNotification, _ *uuid.UUID) (*GovNotice, error) {
	var row *agentAskRow
	if err := tenancy.InWorkspaceRead(db.Statement.Context, db, n.WorkspaceID, func(tx *gorm.DB) error {
		var err error
		row, err = readAgentAsk(tx, n.WorkspaceID, n.SubjectID, false)
		return err
	}); err != nil {
		var ge *GovError
		if errors.As(err, &ge) && ge.Status == http.StatusNotFound {
			return nil, GovNotifyPermanent(errors.New("the ask no longer exists"))
		}
		return nil, err
	}
	if !row.live() {
		return nil, GovNotifyPermanent(fmt.Errorf("the ask is %s; nothing to decide", row.State))
	}
	link := AgentAskConsoleLink(row.ID)
	path := row.path()
	title := "AuthSec asks: " + clipText(row.Question, 120)
	lines := []string{
		fmt.Sprintf("About %s %s", strings.ReplaceAll(row.AboutKind, "_", " "), row.AboutID),
		"Answers: " + strings.Join(askChoiceLabels(row.choices()), " / "),
		fmt.Sprintf("Due %s (%s)", row.DueAt.UTC().Format("Mon 2 Jan 15:04 MST"), row.Severity),
	}
	if row.Step < len(path) {
		lines = append(lines, fmt.Sprintf("Asked of %s (step %d of %d)", path[row.Step].Label, row.Step+1, len(path)))
	}
	if row.Overdue {
		lines = append(lines, "Overdue")
	}
	text := title + "\n\n" + row.Question + "\n\n" + strings.Join(lines, "\n") + "\n"
	if link != "" {
		text += "\nAnswer it in AuthSec:\n  " + link + "\n"
	}
	return &GovNotice{Subject: title, Text: text, Title: title, Lines: lines, Link: link,
		Webhook: map[string]any{"type": "authsec.agent_runtime.ask", "version": 1, "workspace_id": row.WorkspaceID.String(),
			"ask_id": row.ID.String(), "about": map[string]any{"kind": row.AboutKind, "id": row.AboutID},
			"question": row.Question, "choices": row.choices(), "severity": row.Severity, "tier": row.Tier,
			"state": row.State, "step": row.Step, "due_at": row.DueAt.UTC(), "overdue": row.Overdue, "link": link}}, nil
}

// enqueueAskDeliveriesTx queues an ask's notices to its current deciders on
// the policy's channels (resend re-delivers a notice already sent).
func enqueueAskDeliveriesTx(tx *gorm.DB, ws uuid.UUID, row *agentAskRow, p AgentAskPolicy, resend bool) {
	deciders := uuidsOf(row.Deciders)
	if len(deciders) > askMaxDeliveries {
		deciders = deciders[:askMaxDeliveries]
	}
	err := tx.Transaction(func(sp *gorm.DB) error {
		if p.ChannelEmail {
			for _, d := range deciders {
				if _, err := EnqueueGovNotificationTx(sp, ws, GovNoticeAgentAsk, row.ID, GovChannelEmail, GovUserRecipient(d), resend); err != nil {
					return err
				}
			}
		}
		if ch, ok := govNoticeChannel(GovChannelSlack); ok && p.ChannelSlack {
			for _, d := range deciders {
				reach, err := ch.Reaches(sp, ws, d)
				if err != nil {
					return err
				}
				if !reach {
					continue
				}
				if _, err := EnqueueGovNotificationTx(sp, ws, GovNoticeAgentAsk, row.ID, GovChannelSlack, GovUserRecipient(d), resend); err != nil {
					return err
				}
			}
		}
		if p.ChannelWebhook && GovWorkspaceWebhookConfigured(sp, ws) {
			if _, err := EnqueueGovNotificationTx(sp, ws, GovNoticeAgentAsk, row.ID, GovChannelWebhook, GovRecipientWorkspaceWebhook, resend); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("[agent-asks] workspace %s: ask %s: notices not queued: %v", ws, row.ID, err)
	}
}

/* ---------------------------------- Slack ---------------------------------- */

// agentAskButtonToken binds a button to its notification, ask, step and
// choice (hex HMAC-SHA256 under the Slack signing secret, 32 characters).
func agentAskButtonToken(secret string, notification, ask uuid.UUID, step int, choice string) string {
	mac := hmac.New(sha256.New, []byte("authsec-agent-ask:"+secret))
	mac.Write([]byte(notification.String() + "|" + ask.String() + "|" + strconv.Itoa(step) + "|" + choice))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

// askMessage is an ask's interactive Slack message, read under row-level
// security on db (the channel's read transaction).
func (c *SlackNotificationChannel) askMessage(db *gorm.DB, n models.IGAGovNotification, notice *GovNotice) (slackapp.Message, error) {
	row, err := readAgentAsk(db, n.WorkspaceID, n.SubjectID, false)
	if err != nil {
		var ge *GovError
		if errors.As(err, &ge) && ge.Status == http.StatusNotFound {
			return slackapp.Message{}, GovNotifyPermanent(errors.New("the ask no longer exists"))
		}
		return slackapp.Message{}, err
	}
	if !row.live() {
		return slackapp.Message{}, GovNotifyPermanent(fmt.Errorf("the ask is %s; nothing to decide", row.State))
	}
	secret := c.svc.cfg.SigningSecret
	a := slackapp.Ask{Title: notice.Title, Lines: append([]string{row.Question}, notice.Lines...), Link: notice.Link}
	for _, ch := range row.choices() {
		a.Choices = append(a.Choices, slackapp.LabeledValue{Label: ch.Label, Value: slackapp.ButtonValue{Notification: n.ID.String(),
			Digest: agentAskButtonToken(secret, n.ID, row.ID, row.Step, ch.ID), Choice: ch.ID}.Encode()})
	}
	a.NotMineValue = slackapp.ButtonValue{Notification: n.ID.String(),
		Digest: agentAskButtonToken(secret, n.ID, row.ID, row.Step, askNotMineChoice)}.Encode()
	return slackapp.BuildAsk(a), nil
}

// authorizeAsk authorizes an ask button click as the console route does (a
// person who decides the ask's current step; never the requester), checks
// the button's token against the ask's current step, and returns the answer
// (or the pass-on).
func (s *SlackIntegrationService) authorizeAsk(ctx context.Context, ic *interactionCtx) (slackAction, error) {
	ws := ic.n.WorkspaceID
	notMine := ic.act.ActionID == slackapp.ActionAskNotMine
	if !notMine && !strings.HasPrefix(ic.act.ActionID, slackapp.ActionAskChoicePrefix) {
		return nil, GovBadParam("actions[0].action_id", "An ask takes one of its answers or Not mine.")
	}
	choice := ic.val.Choice
	if notMine {
		choice = askNotMineChoice
	}
	var row *agentAskRow
	if err := s.read(ctx, ws, func(db *gorm.DB) error {
		var err error
		if row, err = readAgentAsk(db, ws, ic.n.SubjectID, false); err != nil {
			return err
		}
		if !row.live() {
			return askNotOpen(row.State)
		}
		want := agentAskButtonToken(s.cfg.SigningSecret, ic.n.ID, row.ID, row.Step, choice)
		if ic.val.Digest == "" || !hmac.Equal([]byte(want), []byte(ic.val.Digest)) {
			return govConflict(GovCodeAskChanged, "This ask moved on since this message was posted; open AuthSec.", nil)
		}
		if !notMine && !askChoiceValid(row, choice) {
			return GovBadParam("choice", "choice must be one of the ask's choices.")
		}
		return checkAskDecider(db, ws, row, ic.user, s.now())
	}); err != nil {
		return nil, err
	}
	svc := NewAgentAskService(s.handle()).WithClock(s.now)
	step, askID := row.Step, row.ID
	label := choice
	for _, c := range row.choices() {
		if c.ID == choice {
			label = c.Label
		}
	}
	if notMine {
		return func(ctx context.Context) (*SlackInteractionResult, error) {
			v, err := svc.notMine(ctx, ws, askID, ic.user, ic.in.Text(slackapp.BlockNote), AskChannelSlack, step)
			if err != nil {
				return nil, err
			}
			return &SlackInteractionResult{WorkspaceID: ws, UserID: ic.user, Action: "ask_not_mine", Resource: "agent_ask",
				ResourceID: askID.String(), After: map[string]any{"step": v.Step, "state": v.State},
				OutcomeTitle: "Passed on: the ask went to the next people who decide."}, nil
		}, nil
	}
	return func(ctx context.Context) (*SlackInteractionResult, error) {
		v, pending, err := svc.AnswerFromSlack(ctx, ws, askID, ic.user, choice, step)
		if err != nil {
			return nil, err
		}
		res := &SlackInteractionResult{WorkspaceID: ws, UserID: ic.user, Action: "ask_answer", Resource: "agent_ask",
			ResourceID: askID.String(), After: map[string]any{"choice": choice, "state": v.State, "channel": AskChannelSlack}}
		if pending {
			res.OutcomeTitle = fmt.Sprintf("You chose %q. Confirm it in AuthSec to put it into effect.", label)
		} else {
			res.OutcomeTitle = fmt.Sprintf("Answered %q at %s", label, s.now().UTC().Format("15:04 UTC"))
		}
		return res, nil
	}, nil
}

// askOutcomeLine is the line under a Slack outcome: the console link.
func askOutcomeLine(n models.IGAGovNotification) string {
	if n.SubjectKind != GovNoticeAgentAsk {
		return ""
	}
	return AgentAskConsoleLink(n.SubjectID)
}
