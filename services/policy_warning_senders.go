package services

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/utils"
)

/*
The two warning channels.

Both are OUTBOUND, which is why neither costs anything against EN-0: the control
plane calling a customer's mail server or their Slack is not the control plane
calling into their cluster. Nothing here opens a path inward.
*/

// SMTPWarningSender delivers a warning by email, through the same SMTP path the
// rest of governance already uses.
//
// One more sender in the shape of utils.SendAccessRequestNotificationEmail, rather
// than a notification subsystem: a second mail stack would be a second place for
// From headers, TLS settings, and delivery failures to diverge.
type SMTPWarningSender struct{}

// Send renders and sends the warning.
func (s *SMTPWarningSender) Send(w *models.AgentPolicyWarning, b WarningBody) error {
	if w.Channel != models.WarningChannelEmail {
		return fmt.Errorf("SMTP sender got a %s warning", w.Channel)
	}
	return utils.SendPolicyExpiryWarningEmail(utils.PolicyExpiryWarning{
		To:            w.Recipient,
		RecipientRole: w.RecipientRole,
		PolicyName:    b.PolicyName,
		AgentLabel:    b.AgentLabel,
		Namespace:     b.Namespace,
		Cluster:       b.Cluster,
		Action:        b.OnExpiry,
		Deadline:      b.Deadline,
		Reason:        b.Reason,
		Confirmed:     b.Confirmed,
		GitOpsManaged: b.GitOpsManaged,
		PolicyID:      b.PolicyID.String(),
		AgentID:       b.AgentID.String(),
	})
}

// WarningWebhookPayload is what an outbound webhook receives.
//
// A stable, documented shape rather than an internal struct: customers build Slack
// and PagerDuty routing on it, and those break silently when a field is renamed.
type WarningWebhookPayload struct {
	// Type identifies the event for a router that receives more than one kind.
	Type    string `json:"type"`
	Version int    `json:"version"`

	WorkspaceID string `json:"workspace_id"`
	PolicyID    string `json:"policy_id"`
	PolicyName  string `json:"policy_name"`
	AgentID     string `json:"agent_id"`
	AgentLabel  string `json:"agent_label"`
	Namespace   string `json:"namespace,omitempty"`
	Cluster     string `json:"cluster,omitempty"`

	// Action is what will happen: evict, quarantine, revoke.
	Action string `json:"action"`
	// DeadlineAt is when. SecondsRemaining is included so a receiver can route on
	// urgency without doing date arithmetic in a Slack workflow.
	DeadlineAt       time.Time `json:"deadline_at"`
	SecondsRemaining int64     `json:"seconds_remaining"`
	Reason           string    `json:"reason,omitempty"`

	// Confirmed false means the action will be REFUSED rather than executed --
	// a materially different message, and the receiver should say so.
	Confirmed bool `json:"confirmed"`
	// GitOpsManaged true means deleting the workload will not stick.
	GitOpsManaged bool `json:"gitops_managed"`
}

// HTTPWarningSender posts a warning to a customer's endpoint.
type HTTPWarningSender struct {
	// Client is optional; a sane default is used when nil.
	Client *http.Client
}

// Send posts the payload, signed when a secret is configured.
func (s *HTTPWarningSender) Send(w *models.AgentPolicyWarning, b WarningBody) error {
	if w.Channel != models.WarningChannelWebhook {
		return fmt.Errorf("webhook sender got a %s warning", w.Channel)
	}
	if b.WebhookURL == "" {
		return errors.New("no webhook url configured")
	}

	payload := WarningWebhookPayload{
		Type: "governance.policy_expiry_warning", Version: 1,
		WorkspaceID: b.WorkspaceID.String(),
		PolicyID:    b.PolicyID.String(), PolicyName: b.PolicyName,
		AgentID: b.AgentID.String(), AgentLabel: b.AgentLabel,
		Namespace: b.Namespace, Cluster: b.Cluster,
		Action: b.OnExpiry, DeadlineAt: b.Deadline.UTC(),
		SecondsRemaining: int64(time.Until(b.Deadline).Seconds()),
		Reason:           b.Reason,
		Confirmed:        b.Confirmed, GitOpsManaged: b.GitOpsManaged,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

	client := s.Client
	if client == nil {
		// A customer endpoint that hangs must not hold the delivery worker. Ten
		// seconds is generous for a webhook and short enough that one bad endpoint
		// cannot stall the queue behind it.
		client = &http.Client{Timeout: 10 * time.Second}
	}

	req, err := http.NewRequest(http.MethodPost, b.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "authsec-governance")
	if b.WebhookSecret != "" {
		// Same HMAC scheme the IGA webhook ingress already verifies, so a customer
		// who has integrated one has integrated both.
		mac := hmac.New(sha256.New, []byte(b.WebhookSecret))
		mac.Write(body)
		req.Header.Set("X-AuthSec-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post webhook: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}
