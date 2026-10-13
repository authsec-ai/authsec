package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/authsec-ai/authsec/internal/notify"
)

// A workspace chooses its governance webhook URL. The production notifier
// must send it through the SSRF-safe client: a loopback or private target is
// refused before any request leaves (it used a plain http.Client).
func TestGovNotifierWebhookRefusesInternalTargets(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	n := NewGovNotifier(nil)
	err := n.Webhook.Send(context.Background(), notify.Message{
		Channel: notify.ChannelWebhook,
		To:      srv.URL, // http://127.0.0.1:<port>
		Body:    []byte(`{}`),
	})
	if err == nil || atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("webhook to a loopback address was sent (err=%v, hits=%d)", err, hits)
	}
	if !strings.Contains(err.Error(), "post webhook") {
		t.Fatalf("unexpected error: %v", err)
	}
}
