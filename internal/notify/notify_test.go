package notify_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/notify"
	"github.com/authsec-ai/authsec/internal/notify/notifytest"
)

func TestBuildEmailHeaders(t *testing.T) {
	got := string(notify.BuildEmail("AuthSec <a@authsec.ai>", "b@x.test", "Hi", "line1\nline2\n",
		"Wed, 07 Oct 2026 10:00:00 +0000", "<id@authsec.ai>"))
	want := "From: AuthSec <a@authsec.ai>\r\nTo: b@x.test\r\nSubject: Hi\r\nDate: Wed, 07 Oct 2026 10:00:00 +0000\r\n" +
		"Message-ID: <id@authsec.ai>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n" +
		"Content-Transfer-Encoding: 8bit\r\n\r\nline1\nline2\n"
	if got != want {
		t.Fatalf("BuildEmail:\n%q\nwant\n%q", got, want)
	}
	if h := (notify.SMTPConfig{User: "a@authsec.ai"}).FromHeader(); h != "a@authsec.ai" {
		t.Fatalf("bare From: %q", h)
	}
	if h := (notify.SMTPConfig{User: "a@authsec.ai", FromName: "  AuthSec "}).FromHeader(); h != "AuthSec <a@authsec.ai>" {
		t.Fatalf("named From: %q", h)
	}
}

func TestSMTPSendRecorded(t *testing.T) {
	rec, err := notifytest.NewSMTPRecorder()
	if err != nil {
		t.Fatal(err)
	}
	defer rec.Close()
	cfg := notify.SMTPConfig{Host: rec.Host(), Port: rec.Port(), User: "noreply@authsec.ai", Password: "pw", FromName: "AuthSec"}
	at := time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)
	s := &notify.SMTP{Config: func() notify.SMTPConfig { return cfg }, Now: func() time.Time { return at },
		MessageID: func() string { return "<fixed@authsec.ai>" }}
	if err := s.Send(context.Background(), notify.Message{Channel: notify.ChannelEmail, To: "owner@x.test",
		Subject: "Review", Body: []byte("Hello\n")}); err != nil {
		t.Fatal(err)
	}
	ss := rec.Sessions()
	if len(ss) != 1 {
		t.Fatalf("sessions %d", len(ss))
	}
	if ss[0].From != "noreply@authsec.ai" || len(ss[0].To) != 1 || ss[0].To[0] != "owner@x.test" || ss[0].Auth != "\x00noreply@authsec.ai\x00pw" {
		t.Fatalf("envelope %+v", ss[0])
	}
	want := string(notify.BuildEmail("AuthSec <noreply@authsec.ai>", "owner@x.test", "Review", "Hello\r\n",
		"Wed, 07 Oct 2026 10:00:00 +0000", "<fixed@authsec.ai>"))
	if string(ss[0].Data) != want {
		t.Fatalf("data:\n%q\nwant\n%q", ss[0].Data, want)
	}
	// Incomplete configuration: the legacy error, nothing sent.
	bad := &notify.SMTP{Config: func() notify.SMTPConfig { return notify.SMTPConfig{Host: rec.Host()} }}
	if err := bad.Send(context.Background(), notify.Message{Channel: notify.ChannelEmail, To: "x@x.test"}); err != notify.ErrSMTPNotConfigured {
		t.Fatalf("incomplete config: %v", err)
	}
	if err := s.Send(context.Background(), notify.Message{Channel: notify.ChannelWebhook}); err == nil {
		t.Fatal("SMTP accepted a webhook message")
	}
	// A relay rejection is an error.
	rec.SetRejectData(true)
	if err := s.Send(context.Background(), notify.Message{Channel: notify.ChannelEmail, To: "owner@x.test", Subject: "x", Body: []byte("x")}); err == nil {
		t.Fatal("a 554 at DATA was not an error")
	}
}

func TestWebhookSignedPost(t *testing.T) {
	type got struct {
		method, ct, ua, sig string
		body                []byte
	}
	ch := make(chan got, 4)
	status := http.StatusNoContent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- got{r.Method, r.Header.Get("Content-Type"), r.Header.Get("User-Agent"), r.Header.Get(notify.SignatureHeader), b}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	wh := &notify.Webhook{Client: srv.Client()}
	body := []byte(`{"type":"x","version":1}`)
	if err := wh.Send(context.Background(), notify.Message{Channel: notify.ChannelWebhook, To: srv.URL, Body: body, Secret: "s3cret"}); err != nil {
		t.Fatal(err)
	}
	g := <-ch
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(body)
	if g.method != "POST" || g.ct != "application/json" || g.ua != notify.DefaultUserAgent || string(g.body) != string(body) ||
		g.sig != "sha256="+hex.EncodeToString(mac.Sum(nil)) || g.sig != notify.Sign("s3cret", body) {
		t.Fatalf("request %+v", g)
	}
	// Unsigned without a secret.
	if err := wh.Send(context.Background(), notify.Message{Channel: notify.ChannelWebhook, To: srv.URL, Body: body}); err != nil {
		t.Fatal(err)
	}
	if g := <-ch; g.sig != "" {
		t.Fatalf("unsigned request carried %q", g.sig)
	}
	// Non-2xx is an error with the legacy text.
	status = http.StatusBadGateway
	err := wh.Send(context.Background(), notify.Message{Channel: notify.ChannelWebhook, To: srv.URL, Body: body})
	<-ch
	if err == nil || !strings.HasPrefix(err.Error(), "webhook returned 502") {
		t.Fatalf("502: %v", err)
	}
	if err := wh.Send(context.Background(), notify.Message{Channel: notify.ChannelWebhook}); err == nil || err.Error() != "no webhook url configured" {
		t.Fatalf("no url: %v", err)
	}
	// Mux routes by channel and refuses an unknown one.
	var hit string
	mux := notify.Mux{notify.ChannelEmail: notify.SenderFunc(func(_ context.Context, m notify.Message) error { hit = m.To; return nil })}
	if err := mux.Send(context.Background(), notify.Message{Channel: notify.ChannelEmail, To: "a"}); err != nil || hit != "a" {
		t.Fatalf("mux: %v %q", err, hit)
	}
	if err := mux.Send(context.Background(), notify.Message{Channel: "slack"}); err == nil {
		t.Fatal("mux accepted an unknown channel")
	}
}
