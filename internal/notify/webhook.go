package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/internal/safehttp"
)

// DefaultUserAgent is the webhook User-Agent (the legacy sender's).
const DefaultUserAgent = "authsec-governance"

// SignatureHeader carries "sha256=" + hex(HMAC-SHA256(secret, body)): the
// same scheme the IGA webhook ingress verifies, so a customer who has
// integrated one has integrated both.
const SignatureHeader = "X-AuthSec-Signature"

// TimestampHeader and DeliveryHeader are sent with a timestamped signature
// (Message.Timestamp), as on the agent runtime SIEM webhook.
const (
	TimestampHeader = "X-AuthSec-Timestamp"
	DeliveryHeader  = "X-AuthSec-Delivery"
)

// SignTimestamped is the SignatureHeader value of a timestamped delivery:
// "sha256=" + hex(HMAC-SHA256(secret, timestamp + "." + body)).
func SignTimestamped(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// DefaultWebhookTimeout bounds one POST: a customer endpoint that hangs must
// not hold the delivery worker.
const DefaultWebhookTimeout = 10 * time.Second

// Sign is the SignatureHeader value for body under secret.
func Sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Webhook POSTs a JSON body to a customer endpoint, signed when a secret is
// configured. Any non-2xx answer is a failure.
type Webhook struct {
	// Client is optional; nil means an SSRF-safe client (internal/safehttp)
	// with DefaultWebhookTimeout: the URL is customer-supplied (AS-042).
	Client *http.Client
}

// Send posts m.Body to m.To. Error texts are the legacy sender's.
func (w *Webhook) Send(ctx context.Context, m Message) error {
	if m.Channel != ChannelWebhook {
		return fmt.Errorf("webhook sender got a %s message", m.Channel)
	}
	if m.To == "" {
		return errors.New("no webhook url configured")
	}
	var client *http.Client
	if w != nil {
		client = w.Client
	}
	if client == nil {
		client = safehttp.New(DefaultWebhookTimeout)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.To, bytes.NewReader(m.Body))
	if err != nil {
		return fmt.Errorf("build webhook request: %w", err)
	}
	ua := m.UserAgent
	if ua == "" {
		ua = DefaultUserAgent
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", ua)
	if m.DeliveryID != "" {
		req.Header.Set(DeliveryHeader, m.DeliveryID)
	}
	switch {
	case m.Secret != "" && m.Timestamp != "":
		req.Header.Set(TimestampHeader, m.Timestamp)
		req.Header.Set(SignatureHeader, SignTimestamped(m.Secret, m.Timestamp, m.Body))
	case m.Secret != "":
		req.Header.Set(SignatureHeader, Sign(m.Secret, m.Body))
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
