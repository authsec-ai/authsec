// Package notify is the outbound email (SMTP) and HMAC-signed webhook
// transport (SPEC-iga-phase3-policy.md §4.2 `internal/notify`), extracted
// from services/policy_warning_senders.go so the legacy policy-expiry
// warnings and the Phase 3 notification outbox share one mail stack and one
// webhook signing scheme.
//
// It is transport only: what a message says (subject, body, the webhook's
// JSON document), who receives it, and the retry table around it belong to
// the caller. The legacy senders (SMTPWarningSender, HTTPWarningSender) are
// thin adapters over Send with byte-identical behaviour; the Phase 3 `notify`
// job (services/iga_gov_notify.go) owns retries (attempt x 10 min, dead after
// 5) and delivery rows in iga_gov_notification (054).
//
// The package imports nothing from this module, so utils (the legacy mail
// helpers) and services can both depend on it without a cycle.
package notify

import (
	"context"
	"fmt"
)

// Channels this package delivers (054 iga_gov_notification.channel; Slack is
// delivered by the Slack app, T3.14, not here).
const (
	ChannelEmail   = "email"
	ChannelWebhook = "webhook"
)

// Message is one outbound notice.
type Message struct {
	// Channel is ChannelEmail or ChannelWebhook.
	Channel string
	// To is the email address, or the webhook URL.
	To string
	// Subject is the email subject (unused for a webhook).
	Subject string
	// Body is the text/plain email body, or the webhook's request body, sent
	// verbatim (the signature is computed over exactly these bytes).
	Body []byte
	// Secret is the webhook HMAC key; empty sends the webhook unsigned.
	Secret string
	// UserAgent is the webhook's User-Agent; empty means DefaultUserAgent.
	UserAgent string
}

// Sender delivers one message. An error means it was not (known to be)
// delivered; the caller decides whether and when to retry.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// SenderFunc adapts a function to Sender (tests, fakes).
type SenderFunc func(ctx context.Context, m Message) error

// Send calls f.
func (f SenderFunc) Send(ctx context.Context, m Message) error { return f(ctx, m) }

// Mux routes a message to the sender registered for its channel.
type Mux map[string]Sender

// Send delivers m through the sender for m.Channel.
func (x Mux) Send(ctx context.Context, m Message) error {
	s, ok := x[m.Channel]
	if !ok || s == nil {
		return fmt.Errorf("notify: no sender for channel %q", m.Channel)
	}
	return s.Send(ctx, m)
}
