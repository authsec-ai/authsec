package models

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"

	"gorm.io/gorm"
)

// iga_gov_event payload redaction (SPEC-iga-phase3-policy.md §7.8 "redacted
// payloads"; review fix R1a P2 "Events: redact before insert").
//
// iga_gov_event is append-only: whatever is inserted stays for the life of
// the workspace. So a payload is redacted BEFORE it is stored, here, in the
// model's BeforeCreate hook: every writer -- the repository's AppendTx, the
// services' appendGovEvent and the binding service's appendEvent, and any
// future gorm Create of an IGAGovEvent -- goes through it, so there is one
// redaction function and no writer can skip it. The events API and its
// export apply the same function on the way out (services.RedactGovEventPayload),
// which still covers rows written before this fix.
//
// What is redacted, at any depth:
//   - by KEY (the whole value): secret, token, password, credential,
//     external_id / externalid, signature, authorization, private_key,
//     api_key / apikey, cookie; email addresses ("email", "emails",
//     "*_email"; not "email_enabled"); and a webhook address (a STRING under
//     a key containing "webhook" -- "webhook_signed": true stays).
//   - by VALUE, under any key: an e-mail address inside a string; a URL
//     carrying credentials (user info), a query string (signed URLs,
//     tokens) or a webhook host (hooks.slack.com, *.webhook.office.com,
//     discord webhooks); and well-known credential shapes (Slack xox?-,
//     GitHub ghp_/gho_/ghs_/ghu_/ghr_/github_pat_, AWS AKIA/ASIA access key
//     ids, JWTs, "Bearer ...").
// Identifiers AuthSec needs to correlate events (uuids, ARNs, role ids,
// revision numbers, request ids, plain https links without a query such as
// a pull request URL) are kept.

// GovRedacted replaces a redacted value.
const GovRedacted = "[redacted]"

var govRedactKeyParts = []string{"secret", "token", "password", "credential", "external_id", "externalid",
	"signature", "authorization", "private_key", "api_key", "apikey", "cookie"}

// GovRedactKey reports whether a payload key's value is never stored or
// shown. webhook keys are handled by value type (see govRedactValue).
func GovRedactKey(k string) bool {
	lk := strings.ToLower(k)
	for _, s := range govRedactKeyParts {
		if strings.Contains(lk, s) {
			return true
		}
	}
	return lk == "email" || lk == "emails" || strings.HasSuffix(lk, "_email") || strings.HasSuffix(lk, "_emails")
}

var (
	govEmailRe = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}`)
	govTokenRe = regexp.MustCompile(`(?i)\b(xox[abposr]-[A-Za-z0-9-]{8,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|` +
		`(AKIA|ASIA)[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*|bearer\s+[A-Za-z0-9._~+/=-]{8,})`)
	govURLRe = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>]+`)
)

func govSensitiveURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return true // unparseable: do not risk it
	}
	if u.User != nil || u.RawQuery != "" {
		return true
	}
	h := strings.ToLower(u.Hostname())
	return h == "hooks.slack.com" || strings.HasSuffix(h, ".webhook.office.com") ||
		((h == "discord.com" || h == "discordapp.com") && strings.Contains(u.Path, "/webhooks/"))
}

// govRedactString redacts the sensitive parts of a free-text value.
func govRedactString(s string) string {
	if !strings.ContainsAny(s, "@:_-.") && !strings.Contains(strings.ToLower(s), "bearer") {
		return s
	}
	s = govURLRe.ReplaceAllStringFunc(s, func(m string) string {
		if govSensitiveURL(m) {
			return GovRedacted
		}
		return m
	})
	s = govEmailRe.ReplaceAllString(s, GovRedacted)
	return govTokenRe.ReplaceAllString(s, GovRedacted)
}

func govRedactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			switch {
			case GovRedactKey(k):
				t[k] = GovRedacted
			case strings.Contains(strings.ToLower(k), "webhook"):
				if _, isString := x.(string); isString && x != "" {
					t[k] = GovRedacted
				} else {
					t[k] = govRedactValue(x)
				}
			default:
				t[k] = govRedactValue(x)
			}
		}
		return t
	case []any:
		for i := range t {
			t[i] = govRedactValue(t[i])
		}
		return t
	case string:
		return govRedactString(t)
	}
	return v
}

// ErrGovEventPayloadNotJSON refuses an event whose payload is not JSON.
var ErrGovEventPayloadNotJSON = errors.New("iga_gov_event payload is not a JSON value")

// RedactGovEventPayloadStrict redacts payload (empty is {}); it fails when
// the payload is not JSON. Numbers are kept exactly (no float rounding).
func RedactGovEventPayloadStrict(payload json.RawMessage) (json.RawMessage, error) {
	if len(bytes.TrimSpace(payload)) == 0 {
		return json.RawMessage(`{}`), nil
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil || dec.More() {
		return nil, ErrGovEventPayloadNotJSON
	}
	out, err := json.Marshal(govRedactValue(v))
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RedactGovEventPayload is RedactGovEventPayloadStrict for reads: an
// unparseable stored payload is shown as {"unreadable": true}.
func RedactGovEventPayload(payload json.RawMessage) json.RawMessage {
	out, err := RedactGovEventPayloadStrict(payload)
	if err != nil {
		return json.RawMessage(`{"unreadable":true}`)
	}
	return out
}

// BeforeCreate redacts the payload before the row is inserted (see above).
func (e *IGAGovEvent) BeforeCreate(*gorm.DB) error {
	p, err := RedactGovEventPayloadStrict(e.Payload)
	if err != nil {
		return err
	}
	e.Payload = p
	return nil
}
