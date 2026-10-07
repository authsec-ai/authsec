package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/notify"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/utils"
)

// The Phase 3 notification outbox (SPEC-iga-phase3-policy.md §8.1 job
// table, `notify`; 054 iga_gov_notification; T3.12).
//
// A notice is one iga_gov_notification row -- (subject_kind, subject_id,
// channel, recipient), unique -- and one `notify` job (dedupe
// notification:<id>) that delivers it. The row IS the delivery record: state
// pending -> sent, or failed (retrying) -> ... -> dead after 5 attempts,
// with attempt_count, last_error, available_at (the next try) and sent_at.
// Retry is §8.1's table: attempt x 10 minutes. Every outcome writes an
// iga_gov_event (notification.sent / .failed / .dead) in the same fenced
// transaction as the row.
//
// What a notice says is rendered at SEND time from its subject (the subject
// kind's GovNoticeSubject), so a retried or reminded notice describes the
// subject as it is, and the outbox stores no message bodies.
//
// Recipients (DECISION, 054 does not define the format):
//   - "user:<uuid>" -- a workspace member, for owner-addressed channels
//     (email, and Slack through T3.14's channel). The address is resolved at
//     send time (the member's current email), so the row never holds stale
//     contact data and the subject's hooks can map an outcome back to the
//     person (iga_gov_owner_response.delivery).
//   - "workspace_webhook" -- the workspace's notification webhook (the
//     settings' channel store), resolved at send time.

// Notification states (054).
const (
	GovNotifyPending = "pending"
	GovNotifySent    = "sent"
	GovNotifyFailed  = "failed"
	GovNotifyDead    = "dead"
)

// Notification channels (054) and subject kinds.
const (
	GovChannelEmail   = notify.ChannelEmail
	GovChannelWebhook = notify.ChannelWebhook
	GovChannelSlack   = "slack"

	GovNoticeOwnerReview     = "owner_review"
	GovNoticeApprovalRequest = "approval_request"
	GovNoticeDeployment      = "deployment"
	GovNoticeDrift           = "drift"
	GovNoticeCanaryGate      = "canary_gate"
	GovNoticeFindingDigest   = "finding_digest"

	// GovRecipientWorkspaceWebhook is the recipient of a workspace webhook notice.
	GovRecipientWorkspaceWebhook = "workspace_webhook"
)

// §8.1: "Deliver; retry attempt x 10 min; dead after 5".
const (
	GovNotifyMaxAttempts = 5
	GovNotifyRetryStep   = 10 * time.Minute
)

// GovNotifyBackoff is the notify job's retry delay after `attempts` tries.
func GovNotifyBackoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	return time.Duration(attempts) * GovNotifyRetryStep
}

// GovUserRecipient is the recipient string for a workspace member.
func GovUserRecipient(user uuid.UUID) string { return "user:" + user.String() }

// GovRecipientUser parses a "user:<uuid>" recipient.
func GovRecipientUser(recipient string) (uuid.UUID, bool) {
	if !strings.HasPrefix(recipient, "user:") {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(strings.TrimPrefix(recipient, "user:"))
	return id, err == nil && id != uuid.Nil
}

// GovNotice is a notification rendered for one recipient.
type GovNotice struct {
	// Subject and Text are the email.
	Subject string
	Text    string
	// Webhook is the webhook's JSON document (rendered for the workspace
	// webhook only).
	Webhook map[string]any
	// Title, Lines and Link are a structured form for chat channels (Slack,
	// T3.14).
	Title string
	Lines []string
	Link  string
}

// GovNoticeSubject is what one subject kind contributes to delivery: how to
// render it, and what an outcome means for the subject (an owner review
// records per-owner delivery). Registered with RegisterGovNoticeSubject.
type GovNoticeSubject struct {
	// Render renders n for recipientUser (nil for the workspace webhook).
	// A GovNotifyPermanent error kills the notice at once.
	Render func(db *gorm.DB, n *models.IGAGovNotification, recipientUser *uuid.UUID) (*GovNotice, error)
	// OnSent and OnDead run in the outcome's transaction (optional).
	OnSent func(tx *gorm.DB, n *models.IGAGovNotification, recipientUser *uuid.UUID) error
	OnDead func(tx *gorm.DB, n *models.IGAGovNotification, recipientUser *uuid.UUID) error
}

// GovNotificationChannel is a delivery channel beyond email and webhook:
// Slack, which T3.14 implements and registers with
// RegisterGovNotificationChannel. The owner review enqueues a notice on every
// registered channel that Reaches an owner.
type GovNotificationChannel interface {
	// Channel is the 054 channel name ("slack").
	Channel() string
	// Reaches reports whether the member can be notified on this channel
	// (e.g. a linked Slack user).
	Reaches(db *gorm.DB, ws, userID uuid.UUID) (bool, error)
	// Deliver sends the notice; ref is recorded as the row's slack_ts.
	Deliver(ctx context.Context, db *gorm.DB, n models.IGAGovNotification, recipientUser *uuid.UUID, notice *GovNotice) (ref string, err error)
}

var (
	govNoticeMu       sync.RWMutex
	govNoticeSubjects = map[string]GovNoticeSubject{}
	govNoticeChannels = map[string]GovNotificationChannel{}
)

// RegisterGovNoticeSubject installs the renderer and hooks of a subject kind
// (owner_review is registered by this package; approval_request,
// deployment, drift, canary_gate belong to T3.13 / T3.15 / T3.16).
func RegisterGovNoticeSubject(kind string, s GovNoticeSubject) {
	govNoticeMu.Lock()
	defer govNoticeMu.Unlock()
	govNoticeSubjects[kind] = s
}

// RegisterGovNotificationChannel installs an extra channel (Slack, T3.14). A
// nil channel removes the one of that name.
func RegisterGovNotificationChannel(name string, ch GovNotificationChannel) {
	govNoticeMu.Lock()
	defer govNoticeMu.Unlock()
	if ch == nil {
		delete(govNoticeChannels, name)
		return
	}
	govNoticeChannels[name] = ch
}

// govExtraChannels lists the registered extra channels, by name.
func govExtraChannels() []GovNotificationChannel {
	govNoticeMu.RLock()
	defer govNoticeMu.RUnlock()
	out := make([]GovNotificationChannel, 0, len(govNoticeChannels))
	for _, ch := range govNoticeChannels {
		out = append(out, ch)
	}
	return out
}

func govNoticeSubject(kind string) (GovNoticeSubject, bool) {
	govNoticeMu.RLock()
	defer govNoticeMu.RUnlock()
	s, ok := govNoticeSubjects[kind]
	return s, ok
}

func govNoticeChannel(name string) (GovNotificationChannel, bool) {
	govNoticeMu.RLock()
	defer govNoticeMu.RUnlock()
	c, ok := govNoticeChannels[name]
	return c, ok
}

// govPermanent marks a delivery error that no retry can fix (the recipient
// left the workspace, the subject is gone): the notice is dead at once.
type govPermanent struct{ err error }

func (e *govPermanent) Error() string { return e.err.Error() }
func (e *govPermanent) Unwrap() error { return e.err }

// GovNotifyPermanent wraps err as permanent.
func GovNotifyPermanent(err error) error { return &govPermanent{err: err} }

// EnqueueGovNotificationTx records a notice and its notify job in the
// caller's transaction. An existing row for the same (subject, channel,
// recipient) is returned untouched, unless resend: then a row that is not
// already pending is reset to pending (attempt_count 0, the previous
// outcome stays in the event log) and a job is enqueued again (DECISION:
// a reminder or a reopen is a new delivery cycle with its own 5 attempts).
func EnqueueGovNotificationTx(tx *gorm.DB, ws uuid.UUID, subjectKind string, subjectID uuid.UUID, channel, recipient string, resend bool) (*models.IGAGovNotification, error) {
	var rows []models.IGAGovNotification
	err := tx.Raw(`
		INSERT INTO iga_gov_notification (workspace_id, subject_kind, subject_id, channel, recipient)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (subject_kind, subject_id, channel, recipient) DO NOTHING
		RETURNING *`, ws, subjectKind, subjectID, channel, recipient).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	created := len(rows) == 1
	if !created {
		if err := tx.Raw(`SELECT * FROM iga_gov_notification
			WHERE workspace_id = ? AND subject_kind = ? AND subject_id = ? AND channel = ? AND recipient = ?`,
			ws, subjectKind, subjectID, channel, recipient).Scan(&rows).Error; err != nil {
			return nil, err
		}
		if len(rows) != 1 {
			return nil, fmt.Errorf("notification (%s %s %s %s) belongs to another workspace", subjectKind, subjectID, channel, recipient)
		}
		if !resend {
			return &rows[0], nil
		}
		if rows[0].State != GovNotifyPending {
			if err := tx.Raw(`UPDATE iga_gov_notification
				SET state = 'pending', attempt_count = 0, last_error = '', available_at = now(), sent_at = NULL
				WHERE workspace_id = ? AND id = ? RETURNING *`, ws, rows[0].ID).Scan(&rows).Error; err != nil {
				return nil, err
			}
		}
	}
	n := rows[0]
	sub := n.ID
	job := &models.IGAGovJob{WorkspaceID: ws, Kind: repositories.GovJobNotify, SubjectID: &sub,
		DedupeKey: "notification:" + n.ID.String(), MaxAttempts: GovNotifyMaxAttempts}
	if _, err := repositories.NewIGAGovJobRepository(tx).EnqueueTx(tx, job); err != nil {
		return nil, err
	}
	return &n, nil
}

// GovWebhookTarget is the workspace's notification webhook.
type GovWebhookTarget struct {
	URL    string
	Secret string
}

// GovNotifier delivers notify jobs.
type GovNotifier struct {
	db      *gorm.DB
	members WorkspaceMemberDirectory
	// Email and Webhook are the transports (internal/notify).
	Email   notify.Sender
	Webhook notify.Sender
	// WebhookTarget resolves the workspace webhook at send time.
	WebhookTarget func(db *gorm.DB, ws uuid.UUID) (*GovWebhookTarget, error)
	now           func() time.Time
}

// NewGovNotifier is the production notifier: email through the
// application's relay, webhooks through notify.Webhook, the webhook target
// from the notification settings store.
func NewGovNotifier(db *gorm.DB) *GovNotifier {
	return &GovNotifier{
		db:            db,
		Email:         &notify.SMTP{Config: utils.AppSMTPConfig},
		Webhook:       &notify.Webhook{Client: &http.Client{Timeout: notify.DefaultWebhookTimeout}},
		WebhookTarget: GovWorkspaceWebhookTarget,
		now:           time.Now,
	}
}

// WithTransports replaces the email and webhook transports (tests).
func (g *GovNotifier) WithTransports(email, webhook notify.Sender) *GovNotifier {
	if email != nil {
		g.Email = email
	}
	if webhook != nil {
		g.Webhook = webhook
	}
	return g
}

// JobKind is the notify job registration: this notifier's handler and
// §8.1's backoff (attempt x 10 min).
func (g *GovNotifier) JobKind() PolicyJobKind {
	return PolicyJobKind{Kind: repositories.GovJobNotify, Handler: g.Handle, Backoff: GovNotifyBackoff, Timeout: 90 * time.Second}
}

// errNotifyFailed is what Handle returns for a failed, retryable attempt.
var errNotifyFailed = errors.New("notification delivery failed")

// Handle is the notify job: one delivery attempt of one notice.
func (g *GovNotifier) Handle(ctx context.Context, run *PolicyJobRun) error {
	if run.Job.SubjectID == nil {
		return PolicyJobAbandon("notify job without a notification id")
	}
	var n models.IGAGovNotification
	res := run.DB().WithContext(ctx).Where("workspace_id = ? AND id = ?", run.Job.WorkspaceID, *run.Job.SubjectID).Limit(1).Find(&n)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return PolicyJobAbandon("notification no longer exists")
	}
	if n.State == GovNotifySent || n.State == GovNotifyDead {
		return nil // already settled (a duplicate job, or a reset raced)
	}
	user, isUser := GovRecipientUser(n.Recipient)
	var userPtr *uuid.UUID
	if isUser {
		userPtr = &user
	}

	ref := ""
	sendErr := run.External(ctx, 0, func(ctx context.Context) error {
		var err error
		ref, err = g.deliver(ctx, &n, userPtr)
		return err
	})
	if errors.Is(sendErr, repositories.ErrPolicyJobLeaseLost) {
		return sendErr // another worker owns it; write nothing
	}
	if errors.Is(sendErr, repositories.ErrPolicyJobLeaseShort) {
		return PolicyJobRetryLater(time.Minute, "lease margin short before sending")
	}

	attempt := n.AttemptCount + 1
	var perm *govPermanent
	dead := sendErr != nil && (attempt >= GovNotifyMaxAttempts || run.Job.Attempts >= run.Job.MaxAttempts || errors.As(sendErr, &perm))
	now := g.now()
	err := run.InTx(ctx, func(tx *gorm.DB) error {
		subj, _ := govNoticeSubject(n.SubjectKind)
		payload := map[string]any{"notification_id": n.ID, "subject_kind": n.SubjectKind, "subject_id": n.SubjectID,
			"channel": n.Channel, "attempt": attempt}
		if userPtr != nil {
			payload["recipient_user_id"] = *userPtr
		} else {
			payload["recipient"] = n.Recipient
		}
		var event string
		switch {
		case sendErr == nil:
			if err := tx.Exec(`UPDATE iga_gov_notification SET state = 'sent', attempt_count = ?, last_error = '', sent_at = ?, slack_ts = ?
				WHERE workspace_id = ? AND id = ?`, attempt, now, ref, n.WorkspaceID, n.ID).Error; err != nil {
				return err
			}
			if subj.OnSent != nil {
				if err := subj.OnSent(tx, &n, userPtr); err != nil {
					return err
				}
			}
			event = GovEventNotificationSent
		case dead:
			if err := tx.Exec(`UPDATE iga_gov_notification SET state = 'dead', attempt_count = ?, last_error = ?
				WHERE workspace_id = ? AND id = ?`, attempt, truncate(sendErr.Error(), 1000), n.WorkspaceID, n.ID).Error; err != nil {
				return err
			}
			if subj.OnDead != nil {
				if err := subj.OnDead(tx, &n, userPtr); err != nil {
					return err
				}
			}
			payload["error"] = truncate(sendErr.Error(), 300)
			event = GovEventNotificationDead
		default:
			next := now.Add(GovNotifyBackoff(attempt))
			if err := tx.Exec(`UPDATE iga_gov_notification SET state = 'failed', attempt_count = ?, last_error = ?, available_at = ?
				WHERE workspace_id = ? AND id = ?`, attempt, truncate(sendErr.Error(), 1000), next, n.WorkspaceID, n.ID).Error; err != nil {
				return err
			}
			payload["error"] = truncate(sendErr.Error(), 300)
			payload["next_attempt_at"] = next
			event = GovEventNotificationFailed
		}
		return appendGovEvent(tx, n.WorkspaceID, event, models.GovActorSystem, "policy-worker", govEventRefs{}, payload)
	})
	if err != nil {
		return err
	}
	switch {
	case sendErr == nil:
		return nil
	case dead && run.Job.Attempts >= run.Job.MaxAttempts:
		return fmt.Errorf("%w (dead after %d attempts): %v", errNotifyFailed, attempt, sendErr)
	case dead:
		return PolicyJobAbandon(fmt.Sprintf("notification dead after %d attempts: %v", attempt, sendErr))
	default:
		return fmt.Errorf("%w (attempt %d): %v", errNotifyFailed, attempt, sendErr)
	}
}

// deliver renders and sends one notice.
func (g *GovNotifier) deliver(ctx context.Context, n *models.IGAGovNotification, user *uuid.UUID) (string, error) {
	subj, ok := govNoticeSubject(n.SubjectKind)
	if !ok || subj.Render == nil {
		return "", GovNotifyPermanent(fmt.Errorf("no renderer for %s notices", n.SubjectKind))
	}
	notice, err := subj.Render(g.db.WithContext(ctx), n, user)
	if err != nil {
		return "", err
	}
	switch n.Channel {
	case GovChannelEmail:
		if user == nil {
			return "", GovNotifyPermanent(fmt.Errorf("email recipient %q is not a member", n.Recipient))
		}
		m, err := g.members.ActiveMembers(g.db.WithContext(ctx), n.WorkspaceID, []uuid.UUID{*user})
		if err != nil {
			return "", err
		}
		member, ok := m[*user]
		if !ok || strings.TrimSpace(member.Email) == "" {
			return "", GovNotifyPermanent(errors.New("the recipient is no longer an active member of the workspace"))
		}
		return "", g.Email.Send(ctx, notify.Message{Channel: notify.ChannelEmail, To: member.Email,
			Subject: notice.Subject, Body: []byte(notice.Text)})
	case GovChannelWebhook:
		if g.WebhookTarget == nil {
			return "", GovNotifyPermanent(errors.New("no workspace webhook is configured"))
		}
		t, err := g.WebhookTarget(g.db.WithContext(ctx), n.WorkspaceID)
		if err != nil {
			return "", err
		}
		if t == nil || t.URL == "" {
			return "", GovNotifyPermanent(errors.New("no workspace webhook is configured"))
		}
		body, err := json.Marshal(notice.Webhook)
		if err != nil {
			return "", GovNotifyPermanent(err)
		}
		return "", g.Webhook.Send(ctx, notify.Message{Channel: notify.ChannelWebhook, To: t.URL, Body: body,
			Secret: t.Secret, UserAgent: notify.DefaultUserAgent})
	default:
		ch, ok := govNoticeChannel(n.Channel)
		if !ok {
			return "", fmt.Errorf("the %s channel is not available in this build", n.Channel)
		}
		return ch.Deliver(ctx, g.db.WithContext(ctx), *n, user, notice)
	}
}
