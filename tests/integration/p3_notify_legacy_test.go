package integration

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/notify"
	"github.com/authsec-ai/authsec/internal/notify/notifytest"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// T3.12 (SPEC-iga-phase3-policy.md §4.2 internal/notify): the legacy warning
// senders are thin adapters over internal/notify with BYTE-IDENTICAL
// behaviour. Every case runs twice -- once through the oracle (a verbatim
// copy of the pre-extraction code, p3_notify_legacy_oracle_test.go) and once
// through the production adapter -- against the same recording SMTP relay
// and the same recording HTTP endpoint, and the recorded requests are
// compared byte for byte: the SMTP command sequence (EHLO, AUTH PLAIN
// credentials, MAIL FROM, RCPT TO), the DATA payload, the webhook method,
// path, every header (signature included) and body; and the error each
// returns.
//
// Normalised, and only these: the Date and Message-ID header VALUES of an
// email (wall clock and a random UUID in both implementations; their format
// is asserted instead). Webhook bodies are compared raw: the deadline is
// placed mid-second so seconds_remaining is the same integer in both runs.
//
// Safeguard (mutation-checked): any change to the adapters' payload, header
// or signature (e.g. a different User-Agent) fails this test.

var (
	p3DateHdr  = regexp.MustCompile(`(?m)^Date: [A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} \+0000\r$`)
	p3MsgIDHdr = regexp.MustCompile(`(?m)^Message-ID: <[0-9a-f-]{36}@authsec\.ai>\r$`)
)

func p3NormaliseMail(t *testing.T, data []byte) string {
	t.Helper()
	s := string(data)
	if !p3DateHdr.MatchString(s) || !p3MsgIDHdr.MatchString(s) {
		t.Fatalf("Date or Message-ID header malformed:\n%s", s)
	}
	s = p3DateHdr.ReplaceAllString(s, "Date: <date>\r")
	return p3MsgIDHdr.ReplaceAllString(s, "Message-ID: <id>\r")
}

type p3RecordedHTTP struct {
	Method, Path string
	Header       http.Header
	Body         []byte
}

func TestP3NotifyLegacySendersByteIdentical(t *testing.T) {
	rec, err := notifytest.NewSMTPRecorder()
	if err != nil {
		t.Fatal(err)
	}
	defer rec.Close()

	prev := config.AppConfig
	t.Cleanup(func() { config.AppConfig = prev })
	cfg := config.Config{}
	if prev != nil {
		cfg = *prev
	}
	cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPassword = rec.Host(), rec.Port(), "noreply@authsec.ai", "relay-pw"
	cfg.SMTPFromName = "AuthSec"
	cfg.BaseURL = "app.authsec.test/" // exercises the https:// and trailing-slash branches
	config.AppConfig = &cfg

	deadline := time.Now().Add(72 * time.Hour).Truncate(time.Second).Add(500 * time.Millisecond)
	base := services.WarningBody{
		WorkspaceID: uuid.New(), PolicyID: uuid.New(), PolicyName: "retire stale agents",
		AgentID: uuid.New(), AgentLabel: "refund-agent", Namespace: "payments", Cluster: "prod-eu",
		OnExpiry: "evict", Deadline: deadline, Reason: "unused 90 days", Confirmed: true,
	}
	type mailCase struct {
		name string
		role string
		edit func(*services.WarningBody)
	}
	mails := []mailCase{
		{"evict confirmed, owner", models.RecipientOwner, nil},
		{"evict refused + gitops, author", models.RecipientAuthor, func(b *services.WarningBody) { b.Confirmed = false; b.GitOpsManaged = true }},
		{"evict confirmed + gitops, confirmer", models.RecipientConfirmer, func(b *services.WarningBody) { b.GitOpsManaged = true }},
		{"quarantine, admin", models.RecipientWorkspaceAdmin, func(b *services.WarningBody) { b.OnExpiry = "quarantine"; b.Namespace = "" }},
		{"revoke, unknown role, no reason", "someone", func(b *services.WarningBody) { b.OnExpiry = "revoke"; b.Reason = ""; b.Cluster = "" }},
	}
	adapter := &services.SMTPWarningSender{}
	for _, mc := range mails {
		b := base
		if mc.edit != nil {
			mc.edit(&b)
		}
		w := &models.AgentPolicyWarning{Channel: models.WarningChannelEmail, Recipient: "owner@customer.test", RecipientRole: mc.role}
		n := len(rec.Sessions())
		oErr := oracleSMTPSend(w, b)
		aErr := adapter.Send(w, b)
		if (oErr == nil) != (aErr == nil) {
			t.Fatalf("%s: errors differ: oracle %v, adapter %v", mc.name, oErr, aErr)
		}
		ss := rec.Sessions()
		if len(ss) != n+2 {
			t.Fatalf("%s: %d sessions recorded, want 2", mc.name, len(ss)-n)
		}
		o, a := ss[n], ss[n+1]
		if o.From != a.From || o.Auth != a.Auth || len(o.To) != 1 || len(a.To) != 1 || o.To[0] != a.To[0] {
			t.Fatalf("%s: envelope differs:\noracle  %+v\nadapter %+v", mc.name, o, a)
		}
		if len(o.Commands) != len(a.Commands) {
			t.Fatalf("%s: SMTP command sequences differ:\n%q\n%q", mc.name, o.Commands, a.Commands)
		}
		for i := range o.Commands {
			if o.Commands[i] != a.Commands[i] {
				t.Fatalf("%s: SMTP command %d differs: %q vs %q", mc.name, i, o.Commands[i], a.Commands[i])
			}
		}
		if on, an := p3NormaliseMail(t, o.Data), p3NormaliseMail(t, a.Data); on != an {
			t.Fatalf("%s: SMTP payload differs:\n--- oracle\n%s\n--- adapter\n%s", mc.name, on, an)
		}
	}
	// Error paths: a wrong channel, and an incomplete relay configuration.
	wrong := &models.AgentPolicyWarning{Channel: models.WarningChannelWebhook}
	if o, a := oracleSMTPSend(wrong, base), adapter.Send(wrong, base); o == nil || a == nil || o.Error() != a.Error() {
		t.Fatalf("wrong channel: oracle %v, adapter %v", o, a)
	}
	cfg.SMTPPassword = ""
	em := &models.AgentPolicyWarning{Channel: models.WarningChannelEmail, Recipient: "x@customer.test"}
	if o, a := oracleSMTPSend(em, base), adapter.Send(em, base); o == nil || a == nil || o.Error() != a.Error() {
		t.Fatalf("incomplete SMTP config: oracle %v, adapter %v", o, a)
	}
	cfg.SMTPPassword = "relay-pw"
	// A relay rejection surfaces the same error from both.
	rec.SetRejectData(true)
	if o, a := oracleSMTPSend(em, base), adapter.Send(em, base); o == nil || a == nil || o.Error() != a.Error() {
		t.Fatalf("relay rejection: oracle %v, adapter %v", o, a)
	}
	rec.SetRejectData(false)

	// Webhook: the same body, headers and signature.
	var mu sync.Mutex
	var got []p3RecordedHTTP
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, p3RecordedHTTP{Method: r.Method, Path: r.URL.RequestURI(), Header: r.Header.Clone(), Body: raw})
		st := status
		mu.Unlock()
		w.WriteHeader(st)
	}))
	defer srv.Close()
	hooks := []struct {
		name   string
		secret string
		edit   func(*services.WarningBody)
	}{
		{"signed", "whsec-123", nil},
		{"unsigned", "", nil},
		{"refused, gitops, no namespace/cluster", "whsec-456", func(b *services.WarningBody) {
			b.Confirmed = false
			b.GitOpsManaged = true
			b.Namespace, b.Cluster = "", ""
		}},
	}
	httpAdapter := &services.HTTPWarningSender{Client: srv.Client()}
	for _, hc := range hooks {
		b := base
		b.WebhookURL = srv.URL + "/hooks/authsec?team=refunds"
		b.WebhookSecret = hc.secret
		if hc.edit != nil {
			hc.edit(&b)
		}
		w := &models.AgentPolicyWarning{Channel: models.WarningChannelWebhook, Recipient: b.WebhookURL}
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if err := oracleHTTPSend(httpAdapter, w, b); err != nil {
			t.Fatalf("%s: oracle: %v", hc.name, err)
		}
		if err := httpAdapter.Send(w, b); err != nil {
			t.Fatalf("%s: adapter: %v", hc.name, err)
		}
		mu.Lock()
		o, a := got[n], got[n+1]
		mu.Unlock()
		if o.Method != a.Method || o.Path != a.Path || string(o.Body) != string(a.Body) {
			t.Fatalf("%s: request differs:\noracle  %s %s %s\nadapter %s %s %s", hc.name, o.Method, o.Path, o.Body, a.Method, a.Path, a.Body)
		}
		if len(o.Header) != len(a.Header) {
			t.Fatalf("%s: header sets differ:\n%v\n%v", hc.name, o.Header, a.Header)
		}
		for k, v := range o.Header {
			if av := a.Header.Values(k); len(av) != len(v) || (len(v) > 0 && av[0] != v[0]) {
				t.Fatalf("%s: header %s differs: %v vs %v", hc.name, k, v, av)
			}
		}
		sig := a.Header.Get(notify.SignatureHeader)
		if (hc.secret == "") != (sig == "") || (sig != "" && sig != notify.Sign(hc.secret, a.Body)) {
			t.Fatalf("%s: signature %q", hc.name, sig)
		}
	}
	// Error paths: wrong channel, no URL, a non-2xx answer.
	b := base
	b.WebhookURL = srv.URL
	wrongHook := &models.AgentPolicyWarning{Channel: models.WarningChannelEmail}
	if o, a := oracleHTTPSend(httpAdapter, wrongHook, b), httpAdapter.Send(wrongHook, b); o == nil || a == nil || o.Error() != a.Error() {
		t.Fatalf("wrong channel: oracle %v, adapter %v", o, a)
	}
	hook := &models.AgentPolicyWarning{Channel: models.WarningChannelWebhook}
	noURL := base
	if o, a := oracleHTTPSend(httpAdapter, hook, noURL), httpAdapter.Send(hook, noURL); o == nil || a == nil || o.Error() != a.Error() {
		t.Fatalf("no url: oracle %v, adapter %v", o, a)
	}
	mu.Lock()
	status = http.StatusServiceUnavailable
	mu.Unlock()
	if o, a := oracleHTTPSend(httpAdapter, hook, b), httpAdapter.Send(hook, b); o == nil || a == nil || o.Error() != a.Error() {
		t.Fatalf("503: oracle %v, adapter %v", o, a)
	}
}
