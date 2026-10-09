package services

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

/*
Pre-deadline warnings — phase 1B of ENFORCEMENT-ARCHITECTURE.md §7, implementing
§3A.9.

THE LOOKAHEAD IS THE SYSTEM OF RECORD. GET /governance/policies/upcoming answers
"what will this system do to my cluster this week", it is a PULL, and it is correct
the moment it is read -- no delivery to fail, no channel to configure. Everything in
this file is escalation on top of it, and is allowed to fail without taking the
guarantee with it.

A FAILED WARNING NEVER BLOCKS THE ACTION. That is the uncomfortable half and it is
deliberate: blocking would mean an SMTP outage quietly turns every destructive
policy into a no-op, which is exactly the silent-non-execution failure §3A.4 exists
to prevent -- and the operator would believe it was handled. The failure is recorded
instead. A destructive action that executed with no delivered warning is a
GOVERNANCE EXCEPTION (agent_policy_actions.warning_delivered = false), an auditable
finding rather than a swallowed error.
*/

// PolicyWarningManager schedules and delivers pre-deadline warnings.
type PolicyWarningManager interface {
	// Settings returns a workspace's notification configuration, defaulted when no
	// row exists — a workspace that never configured anything still gets warned.
	Settings(workspaceID uuid.UUID) (*models.GovernanceNotificationSettings, error)
	SaveSettings(workspaceID uuid.UUID, in NotificationSettingsInput) (*models.GovernanceNotificationSettings, error)

	// Schedule creates warning rows for destructive deadlines inside the lead
	// window. Idempotent: re-running mints nothing new.
	Schedule(workspaceID uuid.UUID) (int, error)

	// Deliver sends warnings that are due. Returns how many were attempted.
	Deliver(limit int) (*WarningDeliveryResult, error)

	// List returns a policy's warnings, newest deadline first.
	List(workspaceID uuid.UUID, policyID *uuid.UUID, limit int) ([]models.AgentPolicyWarning, error)

	// WasWarned reports whether a delivered warning exists for this agent and
	// deadline. Read by the reconciler when it records a destructive action.
	WasWarned(workspaceID, agentID uuid.UUID, deadline time.Time) (bool, error)
}

// WarningSender delivers one warning. An interface so tests do not need SMTP and so
// the webhook channel is a second implementation rather than a branch.
type WarningSender interface {
	Send(w *models.AgentPolicyWarning, body WarningBody) error
}

// WarningBody is everything a channel needs to render a message. Resolved once at
// send time so the email and the webhook cannot describe the same deadline
// differently.
type WarningBody struct {
	WorkspaceID uuid.UUID
	PolicyID    uuid.UUID
	PolicyName  string
	AgentID     uuid.UUID
	AgentLabel  string
	Namespace   string
	Cluster     string
	OnExpiry    string
	Deadline    time.Time
	Reason      string
	// Confirmed is false when this agent is NOT covered by the policy's
	// confirmation, which means the action will be refused rather than executed.
	// Included because "this will be deleted" and "this will be refused" are
	// different messages and the recipient acts differently on each.
	Confirmed bool
	// GitOpsManaged means deleting the workload will not stick — a reconciler
	// recreates it. Worth saying while there is still time to change the policy.
	GitOpsManaged bool
	WebhookURL    string
	WebhookSecret string
}

// NotificationSettingsInput is the console's update body.
type NotificationSettingsInput struct {
	WarningLead   *time.Duration
	WebhookURL    *string
	WebhookSecret *string
	EmailEnabled  *bool
}

// WarningDeliveryResult reports one delivery pass.
type WarningDeliveryResult struct {
	Attempted int
	Sent      int
	Failed    int
	Dead      int
	Errors    []string
}

type policyWarningManager struct {
	db       *gorm.DB
	policies AgentPolicyManager
	email    WarningSender
	webhook  WarningSender
}

// NewPolicyWarningManager builds the manager with the default senders.
func NewPolicyWarningManager(db *gorm.DB) PolicyWarningManager {
	return &policyWarningManager{
		db:       db,
		policies: NewAgentPolicyManager(db),
		email:    &SMTPWarningSender{},
		webhook:  &HTTPWarningSender{},
	}
}

// NewPolicyWarningManagerWith injects senders, for tests.
func NewPolicyWarningManagerWith(db *gorm.DB, email, webhook WarningSender) PolicyWarningManager {
	return &policyWarningManager{
		db: db, policies: NewAgentPolicyManager(db), email: email, webhook: webhook,
	}
}

/* -------------------------------- settings ------------------------------- */

func (m *policyWarningManager) Settings(
	workspaceID uuid.UUID) (*models.GovernanceNotificationSettings, error) {

	var s models.GovernanceNotificationSettings
	err := m.db.First(&s, "workspace_id = ?", workspaceID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// Defaults, not an error. A workspace that never configured notification
		// must still be warned before its workloads are deleted — requiring
		// configuration first would make the safe path the one you have to opt into.
		return &models.GovernanceNotificationSettings{
			WorkspaceID:  workspaceID,
			WarningLead:  models.PGInterval(models.DefaultWarningLead),
			EmailEnabled: true,
		}, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (m *policyWarningManager) SaveSettings(workspaceID uuid.UUID,
	in NotificationSettingsInput) (*models.GovernanceNotificationSettings, error) {

	cur, err := m.Settings(workspaceID)
	if err != nil {
		return nil, err
	}
	if in.WarningLead != nil {
		if *in.WarningLead < time.Hour || *in.WarningLead > 90*24*time.Hour {
			// Mirrors the CHECK. Refused here too so the caller gets a sentence
			// rather than a constraint name.
			return nil, errors.New("warning lead must be between 1h and 90 days: a " +
				"shorter lead is not a warning, and a longer one sits pending until " +
				"it looks like the system has gone quiet")
		}
		cur.WarningLead = models.PGInterval(*in.WarningLead)
	}
	if in.WebhookURL != nil {
		u := strings.TrimSpace(*in.WebhookURL)
		if u != "" && !strings.HasPrefix(u, "https://") {
			return nil, errors.New("the notification webhook must be https: a warning " +
				"naming the workload about to be deleted is a map of what to attack " +
				"during the window in which nobody is watching it")
		}
		cur.WebhookURL = u
	}
	if in.WebhookSecret != nil {
		cur.WebhookSecret = *in.WebhookSecret
	}
	if in.EmailEnabled != nil {
		cur.EmailEnabled = *in.EmailEnabled
	}
	cur.WorkspaceID = workspaceID

	err = m.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "workspace_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"warning_lead", "webhook_url", "webhook_secret", "email_enabled", "updated_at",
		}),
	}).Create(cur).Error
	if err != nil {
		return nil, err
	}
	return m.Settings(workspaceID)
}

/* -------------------------------- schedule ------------------------------- */

func (m *policyWarningManager) Schedule(workspaceID uuid.UUID) (int, error) {
	settings, err := m.Settings(workspaceID)
	if err != nil {
		return 0, err
	}
	lead := settings.Lead()

	// Look one lead window ahead, in days, because that is the granularity
	// Upcoming takes. Rounded UP so a lead that is not a whole number of days
	// still sees its own window.
	days := int((lead + 24*time.Hour - time.Nanosecond) / (24 * time.Hour))
	if days < 1 {
		days = 1
	}
	upcoming, err := m.policies.Upcoming(workspaceID, days)
	if err != nil {
		return 0, err
	}

	created := 0
	for i := range upcoming {
		u := &upcoming[i]
		// Only DESTRUCTIVE deadlines are warned about. A revoke-on-expiry lapses an
		// entitlement and is reversible by re-provisioning; warning about every one
		// of those would bury the deletions in noise, and noise is how a real
		// warning gets filtered.
		if !models.OnExpiryIsDestructive(u.Action) {
			continue
		}
		recipients, rerr := m.recipients(workspaceID, u, settings)
		if rerr != nil {
			return created, rerr
		}
		availableAt := u.At.Add(-lead)
		for _, r := range recipients {
			row := &models.AgentPolicyWarning{
				ID:                uuid.New(),
				WorkspaceID:       workspaceID,
				PolicyID:          u.PolicyID,
				DiscoveredAgentID: u.AgentID,
				Deadline:          u.At,
				OnExpiry:          u.Action,
				Channel:           r.channel,
				Recipient:         r.address,
				RecipientRole:     r.role,
				AvailableAt:       availableAt,
				State:             models.WarningPending,
			}
			res := m.db.Clauses(clause.OnConflict{DoNothing: true}).Create(row)
			if res.Error != nil {
				return created, res.Error
			}
			created += int(res.RowsAffected)
		}
	}
	return created, nil
}

type warningRecipient struct {
	channel string
	address string
	role    string
}

// recipients resolves who to tell, in §3A.9's order: who will be surprised.
//
// Duplicates are collapsed on address, so the owner who also authored the policy is
// mailed once, under the role that explains best why they are being told.
func (m *policyWarningManager) recipients(workspaceID uuid.UUID, u *UpcomingAction,
	settings *models.GovernanceNotificationSettings) ([]warningRecipient, error) {

	var out []warningRecipient
	seen := map[string]bool{}
	add := func(channel, address, role string) {
		address = strings.TrimSpace(address)
		if address == "" || seen[channel+"|"+address] {
			return
		}
		seen[channel+"|"+address] = true
		out = append(out, warningRecipient{channel: channel, address: address, role: role})
	}

	if settings.EmailEnabled {
		// 1. The accountable human, whose workload disappears.
		var agent models.DiscoveredAgent
		if err := m.db.First(&agent, "id = ? AND workspace_id = ?",
			u.AgentID, workspaceID).Error; err == nil && agent.OwnerUserID != nil {
			add(models.WarningChannelEmail, m.emailOf(*agent.OwnerUserID), models.RecipientOwner)
		}

		// 2. The author and the confirmer. Both signed up for this consequence.
		var policy models.AgentPolicy
		if err := m.db.First(&policy, "id = ? AND workspace_id = ?",
			u.PolicyID, workspaceID).Error; err == nil {
			if id, perr := uuid.Parse(policy.CreatedBy); perr == nil {
				add(models.WarningChannelEmail, m.emailOf(id), models.RecipientAuthor)
			}
			if policy.ConfirmedBy != nil {
				add(models.WarningChannelEmail, m.emailOf(*policy.ConfirmedBy), models.RecipientConfirmer)
			}
		}

		// 3. Workspace owners, as the backstop for when everyone above has left.
		// Bounded: a large workspace should not turn one deadline into a hundred
		// emails, and past a handful of admins nobody reads them anyway.
		var admins []string
		if err := m.db.Table("users").
			Where("workspace_id = ? AND active AND role IN ?", workspaceID,
				[]string{"owner", "admin"}).
			Limit(5).Pluck("email", &admins).Error; err == nil {
			for _, a := range admins {
				add(models.WarningChannelEmail, a, models.RecipientWorkspaceAdmin)
			}
		}
	}

	if settings.WebhookURL != "" {
		add(models.WarningChannelWebhook, settings.WebhookURL, models.RecipientWebhook)
	}
	return out, nil
}

// emailOf resolves a user id to an address, or "" — which `add` drops.
func (m *policyWarningManager) emailOf(id uuid.UUID) string {
	var email string
	// `active` only: mailing a deactivated account is not a warning, it is a
	// bounce, and it would count as a delivered warning if we did not filter here.
	if err := m.db.Table("users").
		Where("id = ? AND active", id).Limit(1).Pluck("email", &email).Error; err != nil {
		return ""
	}
	return email
}

/* -------------------------------- deliver -------------------------------- */

func (m *policyWarningManager) Deliver(limit int) (*WarningDeliveryResult, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	res := &WarningDeliveryResult{}

	for i := 0; i < limit; i++ {
		w, err := m.claim()
		if err != nil {
			return res, err
		}
		if w == nil {
			return res, nil // nothing due
		}
		res.Attempted++

		body, berr := m.body(w)
		if berr != nil {
			m.fail(w, berr.Error(), res)
			res.Errors = append(res.Errors, berr.Error())
			continue
		}

		sender := m.email
		if w.Channel == models.WarningChannelWebhook {
			sender = m.webhook
		}
		if serr := sender.Send(w, body); serr != nil {
			m.fail(w, serr.Error(), res)
			res.Errors = append(res.Errors, serr.Error())
			continue
		}

		now := time.Now()
		if uerr := m.db.Model(&models.AgentPolicyWarning{}).Where("id = ?", w.ID).
			Updates(map[string]interface{}{
				"state": models.WarningSent, "sent_at": now,
				"last_error": "", "updated_at": now,
			}).Error; uerr != nil {
			return res, uerr
		}
		res.Sent++
	}
	return res, nil
}

// claim takes one due warning under a row lock, so two replicas cannot both send it.
//
// FOR UPDATE SKIP LOCKED rather than a lease column: the send is short and the
// transaction is the whole unit of work, so a crashed worker releases the row when
// its connection dies instead of leaving it stuck until a lease expires.
func (m *policyWarningManager) claim() (*models.AgentPolicyWarning, error) {
	var out *models.AgentPolicyWarning
	err := m.db.Transaction(func(tx *gorm.DB) error {
		var w models.AgentPolicyWarning
		err := tx.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Where("state IN ? AND available_at <= ?",
				[]string{models.WarningPending, models.WarningFailed}, time.Now()).
			Order("available_at").First(&w).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if uerr := tx.Model(&models.AgentPolicyWarning{}).Where("id = ?", w.ID).
			Updates(map[string]interface{}{
				"attempt_count": w.AttemptCount + 1, "updated_at": time.Now(),
			}).Error; uerr != nil {
			return uerr
		}
		w.AttemptCount++
		out = &w
		return nil
	})
	return out, err
}

func (m *policyWarningManager) fail(w *models.AgentPolicyWarning, msg string,
	res *WarningDeliveryResult) {

	state := models.WarningFailed
	if w.AttemptCount >= models.MaxWarningAttempts {
		// Give up retrying — but note what this does NOT do: it does not stop the
		// deadline. The action still fires, and executes as a governance exception.
		state = models.WarningDead
		res.Dead++
	} else {
		res.Failed++
	}
	_ = m.db.Model(&models.AgentPolicyWarning{}).Where("id = ?", w.ID).
		Updates(map[string]interface{}{
			"state": state, "last_error": truncateWarning(msg), "updated_at": time.Now(),
			// Back off linearly on the attempt count. The lead window is days, so
			// there is room for several tries without an exponential curve pushing
			// the last attempt past the deadline it was warning about.
			"available_at": time.Now().Add(time.Duration(w.AttemptCount) * 10 * time.Minute),
		}).Error
}

// body resolves everything a channel needs to render the message.
func (m *policyWarningManager) body(w *models.AgentPolicyWarning) (WarningBody, error) {
	var policy models.AgentPolicy
	if err := m.db.First(&policy, "id = ? AND workspace_id = ?",
		w.PolicyID, w.WorkspaceID).Error; err != nil {
		return WarningBody{}, fmt.Errorf("policy %s: %w", w.PolicyID, err)
	}
	var agent models.DiscoveredAgent
	if err := m.db.First(&agent, "id = ? AND workspace_id = ?",
		w.DiscoveredAgentID, w.WorkspaceID).Error; err != nil {
		return WarningBody{}, fmt.Errorf("agent %s: %w", w.DiscoveredAgentID, err)
	}
	settings, err := m.Settings(w.WorkspaceID)
	if err != nil {
		return WarningBody{}, err
	}

	confirmed := true
	if models.OnExpiryIsDestructive(w.OnExpiry) {
		confirmed, _ = m.confirmationCovers(w.WorkspaceID, w.PolicyID, w.DiscoveredAgentID)
	}
	ns, _, _, _ := k8sCoordinates(agent.Metadata)

	return WarningBody{
		WorkspaceID: w.WorkspaceID,
		PolicyID:    w.PolicyID, PolicyName: policy.Name,
		AgentID: w.DiscoveredAgentID, AgentLabel: agent.DisplayName,
		Namespace: ns, Cluster: clusterOf(agent.Metadata),
		OnExpiry: w.OnExpiry, Deadline: w.Deadline, Reason: policy.Reason,
		Confirmed: confirmed, GitOpsManaged: gitOpsManaged(agent.Metadata),
		WebhookURL: settings.WebhookURL, WebhookSecret: settings.WebhookSecret,
	}, nil
}

// confirmationCovers duplicates the policy manager's check against the same table.
// Kept local rather than widening that interface for one read.
func (m *policyWarningManager) confirmationCovers(workspaceID, policyID,
	agentID uuid.UUID) (bool, error) {

	var n int64
	err := m.db.Model(&models.AgentPolicyConfirmation{}).
		Where(`workspace_id = ? AND policy_id = ? AND ? = ANY(expanded_agent_ids)`,
			workspaceID, policyID, agentID).Count(&n).Error
	return n > 0, err
}

/* --------------------------------- reads --------------------------------- */

func (m *policyWarningManager) List(workspaceID uuid.UUID, policyID *uuid.UUID,
	limit int) ([]models.AgentPolicyWarning, error) {

	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := m.db.Where("workspace_id = ?", workspaceID)
	if policyID != nil {
		q = q.Where("policy_id = ?", *policyID)
	}
	var out []models.AgentPolicyWarning
	err := q.Order("deadline DESC").Limit(limit).Find(&out).Error
	return out, err
}

// WasWarned reports whether a warning for this agent and deadline was DELIVERED.
//
// Any channel counts: the question is whether a human could have known, not which
// pipe carried it. Matched on a window rather than an exact timestamp, because the
// deadline recorded on the warning is the policy's expiry at scheduling time and a
// second's drift in how it is recomputed must not read as "never warned".
func (m *policyWarningManager) WasWarned(workspaceID, agentID uuid.UUID,
	deadline time.Time) (bool, error) {

	var n int64
	err := m.db.Model(&models.AgentPolicyWarning{}).
		Where(`workspace_id = ? AND discovered_agent_id = ? AND state = ?
		       AND deadline BETWEEN ? AND ?`,
			workspaceID, agentID, models.WarningSent,
			deadline.Add(-time.Minute), deadline.Add(time.Minute)).
		Count(&n).Error
	return n > 0, err
}

func truncateWarning(s string) string {
	if len(s) > 500 {
		return s[:500]
	}
	return s
}
