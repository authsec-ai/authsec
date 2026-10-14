// Package slackapp is the AuthSec Slack app's pure half
// (SPEC-iga-phase3-policy.md §4.2, §7.11, §10; T3.14): request signature
// verification, interaction payload parsing, Block Kit message builders and
// the Slack Web API contract (with an HTTP implementation). It knows nothing
// about workspaces, policies or the database: services/slack_integration_service.go
// owns those.
package slackapp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// MaxRequestAge is §7.11's window: a request whose X-Slack-Request-Timestamp
// is more than 5 minutes away from now is refused.
const MaxRequestAge = 5 * time.Minute

// Header names Slack signs requests with.
const (
	HeaderSignature = "X-Slack-Signature"
	HeaderTimestamp = "X-Slack-Request-Timestamp"
)

// Reasons a request fails verification (VerifyError.Reason).
const (
	ReasonNotConfigured = "not_configured"
	ReasonMissing       = "missing_signature"
	ReasonBadTimestamp  = "bad_timestamp"
	ReasonStale         = "stale_timestamp"
	ReasonMismatch      = "signature_mismatch"
)

// VerifyError is a refused request; Reason is one of the Reason* constants.
type VerifyError struct{ Reason string }

func (e *VerifyError) Error() string { return "slack request signature invalid: " + e.Reason }

// IsVerifyError reports whether err is a VerifyError.
func IsVerifyError(err error) bool {
	var ve *VerifyError
	return errors.As(err, &ve)
}

// Sign is Slack's v0 signature: "v0=" + hex(HMAC-SHA256(secret, "v0:" +
// timestamp + ":" + body)).
func Sign(secret, timestamp string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("v0:" + timestamp + ":"))
	m.Write(body)
	return "v0=" + hex.EncodeToString(m.Sum(nil))
}

// Verify checks a request's signature headers against the raw body: the
// signing secret must be configured; the timestamp must be an integer
// within MaxRequestAge of now (DECISION: in either direction -- a timestamp
// from the future is as unverifiable as a stale one); the signature is
// compared in constant time. The timestamp is checked before the HMAC so a
// replay of an old, correctly signed request is reported as stale.
func Verify(secret string, h http.Header, body []byte, now time.Time) error {
	if secret == "" {
		return &VerifyError{ReasonNotConfigured}
	}
	sig, ts := strings.TrimSpace(h.Get(HeaderSignature)), strings.TrimSpace(h.Get(HeaderTimestamp))
	if sig == "" || ts == "" {
		return &VerifyError{ReasonMissing}
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || sec <= 0 {
		return &VerifyError{ReasonBadTimestamp}
	}
	age := now.Sub(time.Unix(sec, 0))
	if age > MaxRequestAge || age < -MaxRequestAge {
		return &VerifyError{ReasonStale}
	}
	want := Sign(secret, ts, body)
	if !hmac.Equal([]byte(sig), []byte(want)) {
		return &VerifyError{ReasonMismatch}
	}
	return nil
}
