package integration

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/authsec-ai/authsec/utils"
)

// The ORACLE for T3.12's byte-identity proof (p3_notify_legacy_test.go):
// verbatim copies of the legacy warning transport as it was BEFORE the
// extraction into internal/notify -- services/policy_warning_senders.go's
// SMTPWarningSender.Send, HTTPWarningSender.Send and WarningWebhookPayload,
// and utils/otp.go's SendPolicyExpiryWarningEmail and buildEmailMessage at
// feat/p3-int eef366a -- renamed only (oracle*) and re-qualified for this
// package. Never edit these bodies: they are the "before" the adapters are
// compared with.

type oracleWarningWebhookPayload struct {
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

func oracleSMTPSend(w *models.AgentPolicyWarning, b services.WarningBody) error {
	if w.Channel != models.WarningChannelEmail {
		return fmt.Errorf("SMTP sender got a %s warning", w.Channel)
	}
	return oracleSendPolicyExpiryWarningEmail(utils.PolicyExpiryWarning{
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

func oracleHTTPSend(s *services.HTTPWarningSender, w *models.AgentPolicyWarning, b services.WarningBody) error {
	if w.Channel != models.WarningChannelWebhook {
		return fmt.Errorf("webhook sender got a %s warning", w.Channel)
	}
	if b.WebhookURL == "" {
		return errors.New("no webhook url configured")
	}

	payload := oracleWarningWebhookPayload{
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

func oracleSendPolicyExpiryWarningEmail(w utils.PolicyExpiryWarning) error {
	smtpHost := config.AppConfig.SMTPHost
	smtpPort := config.AppConfig.SMTPPort
	smtpUser := config.AppConfig.SMTPUser
	smtpPass := config.AppConfig.SMTPPassword
	if smtpHost == "" || smtpPort == "" || smtpUser == "" || smtpPass == "" {
		log.Printf("SendPolicyExpiryWarningEmail: SMTP not configured")
		return fmt.Errorf("SMTP configuration is incomplete")
	}

	where := w.AgentLabel
	if w.Namespace != "" {
		where = fmt.Sprintf("%s (namespace %s)", where, w.Namespace)
	}
	if w.Cluster != "" {
		where = fmt.Sprintf("%s in cluster %s", where, w.Cluster)
	}

	// The subject has to survive being read on a phone lock screen, so the verb and
	// the deadline come first and the policy name last.
	var subject string
	switch {
	case w.Action == "evict" && !w.Confirmed:
		subject = "AuthSec: scheduled deletion of " + w.AgentLabel + " will be REFUSED"
	case w.Action == "evict":
		subject = "Action required: " + w.AgentLabel + " will be DELETED on " +
			w.Deadline.UTC().Format("2 Jan 15:04 MST")
	case w.Action == "quarantine":
		subject = "AuthSec: " + w.AgentLabel + " will be quarantined on " +
			w.Deadline.UTC().Format("2 Jan 15:04 MST")
	default:
		subject = "AuthSec: access for " + w.AgentLabel + " expires on " +
			w.Deadline.UTC().Format("2 Jan 15:04 MST")
	}

	whyYou := map[string]string{
		"owner":           "You are the accountable owner of this agent.",
		"author":          "You created the policy that schedules this.",
		"confirmer":       "You confirmed the destructive expiry on this policy.",
		"workspace_admin": "You are an administrator of this workspace.",
	}[w.RecipientRole]

	var sb strings.Builder
	fmt.Fprintf(&sb, "Hello,\n\nA governance policy is scheduled to act on an AI agent.\n\n")
	fmt.Fprintf(&sb, "- Agent:     %s\n", where)
	fmt.Fprintf(&sb, "- Action:    %s\n", strings.ToUpper(w.Action))
	fmt.Fprintf(&sb, "- When:      %s\n", w.Deadline.UTC().Format(time.RFC1123))
	fmt.Fprintf(&sb, "- Policy:    %s\n", w.PolicyName)
	if w.Reason != "" {
		fmt.Fprintf(&sb, "- Reason:    %s\n", w.Reason)
	}
	if whyYou != "" {
		fmt.Fprintf(&sb, "\n%s\n", whyYou)
	}

	if w.Action == "evict" {
		if !w.Confirmed {
			// The most important sentence in the message when it applies: the
			// recipient must not spend the week bracing for a deletion that will
			// not happen, nor assume it is handled when it is not.
			sb.WriteString("\nNOTE: this agent is NOT covered by the confirmation on that policy, " +
				"so the deletion will be REFUSED rather than carried out. It was authorised " +
				"against a different set of agents. If you intend it to be deleted, confirm " +
				"the policy again against the current set.\n")
		} else {
			sb.WriteString("\nThis will DELETE the workload from the cluster. If that is not " +
				"what you want, edit or disable the policy before the deadline.\n")
		}
		if w.GitOpsManaged {
			sb.WriteString("\nNOTE: this workload appears to be managed by GitOps. Deleting it " +
				"will not stick — the reconciler will recreate it. Remove it from the source " +
				"repository as well, or the deletion will be undone within minutes.\n")
		}
	}

	// The lookahead link is the most useful thing in the message: it is the system
	// of record, it shows everything else about to happen, and it is correct even
	// if this mail arrived late. Omitted rather than rendered broken when no base
	// URL is configured — a dead link reads as a broken product.
	if base := strings.TrimRight(strings.TrimSpace(config.AppConfig.BaseURL), "/"); base != "" {
		if !strings.HasPrefix(strings.ToLower(base), "http") {
			base = "https://" + base
		}
		fmt.Fprintf(&sb, "\nSee everything scheduled for the coming week at:\n"+
			"  %s/governance/policies/upcoming\n", base)
	}
	fmt.Fprintf(&sb, "\nPolicy ID: %s\nAgent ID:  %s\n", w.PolicyID, w.AgentID)
	sb.WriteString("\nRegards,\nAuthSec Team\n")

	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
	err := smtp.SendMail(
		fmt.Sprintf("%s:%s", smtpHost, smtpPort),
		auth, smtpUser, []string{w.To},
		oracleBuildEmailMessage(w.To, subject, sb.String()),
	)
	if err != nil {
		log.Printf("SendPolicyExpiryWarningEmail: failed to warn %s about %s on %s: %v",
			w.To, w.Action, w.AgentLabel, err)
		return err
	}
	return nil
}

func oracleBuildEmailMessage(toEmail, subject, body string) []byte {
	fromAddr := config.AppConfig.SMTPUser
	if fromName := strings.TrimSpace(config.AppConfig.SMTPFromName); fromName != "" {
		fromAddr = fmt.Sprintf("%s <%s>", fromName, config.AppConfig.SMTPUser)
	}
	messageID := fmt.Sprintf("<%s@authsec.ai>", uuid.NewString())
	date := time.Now().UTC().Format(time.RFC1123Z)

	var sb strings.Builder
	sb.WriteString("From: " + fromAddr + "\r\n")
	sb.WriteString("To: " + toEmail + "\r\n")
	sb.WriteString("Subject: " + subject + "\r\n")
	sb.WriteString("Date: " + date + "\r\n")
	sb.WriteString("Message-ID: " + messageID + "\r\n")
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	sb.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(body)
	return []byte(sb.String())
}
