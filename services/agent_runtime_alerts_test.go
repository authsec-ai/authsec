package services

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/agentruntime/detect"
)

// Unit tests of the agent runtime alert service that need no database.
// The database paths (alerts per workspace, isolation, delivery) are in
// tests/integration/agent_runtime_alerts_test.go.

func TestAgentAlertSettingsDefaultsAndConfig(t *testing.T) {
	s := DefaultAgentAlertSettings()
	if len(s.Detections) != len(detect.All) || !s.SlackEnabled || s.DedupeWindowMinutes != 60 || s.RetentionDays != 90 {
		t.Fatalf("defaults %+v", s)
	}
	cfg := s.DetectConfig()
	if cfg.DenialBurst != 10 || cfg.DenialWindow != 5*time.Minute || cfg.SpikeFactor != 5 || len(cfg.Disabled) != 0 {
		t.Fatalf("default config %+v", cfg)
	}
	off, n, m, k := false, 3, 2, 7.5
	next, err := AgentAlertSettingsUpdate{Detections: map[string]*AgentAlertDetectionUpdate{
		"D1": {Enabled: &off}, "D5": {N: &n, Minutes: &m}, "D6": {K: &k}}}.apply(s)
	if err != nil {
		t.Fatal(err)
	}
	cfg = next.DetectConfig()
	if !cfg.Disabled[detect.D1] || cfg.Enabled(detect.D1) || cfg.DenialBurst != 3 || cfg.DenialWindow != 2*time.Minute || cfg.SpikeFactor != 7.5 {
		t.Fatalf("updated config %+v", cfg)
	}
}

func TestAgentAlertSettingsValidation(t *testing.T) {
	bad := func(u AgentAlertSettingsUpdate) {
		t.Helper()
		_, err := u.apply(DefaultAgentAlertSettings())
		var ge *GovError
		if !errors.As(err, &ge) || ge.Status != http.StatusBadRequest {
			t.Errorf("%+v: err %v, want 400", u, err)
		}
	}
	n0, n2000, k0, w1, r1 := 0, 2000, 0.5, 1, 1
	bad(AgentAlertSettingsUpdate{Detections: map[string]*AgentAlertDetectionUpdate{"D9": {}}})
	bad(AgentAlertSettingsUpdate{Detections: map[string]*AgentAlertDetectionUpdate{"D5": {N: &n0}}})
	bad(AgentAlertSettingsUpdate{Detections: map[string]*AgentAlertDetectionUpdate{"D5": {N: &n2000}}})
	bad(AgentAlertSettingsUpdate{Detections: map[string]*AgentAlertDetectionUpdate{"D6": {K: &k0}}})
	bad(AgentAlertSettingsUpdate{Detections: map[string]*AgentAlertDetectionUpdate{"D1": {N: &n2000}}})
	bad(AgentAlertSettingsUpdate{DedupeWindowMinutes: &w1})
	bad(AgentAlertSettingsUpdate{RetentionDays: &r1})
}

func TestMergeAgentAlertFindings(t *testing.T) {
	out := mergeAgentAlertFindings([]detect.Finding{
		{Detection: detect.D6, Severity: detect.SeverityMedium, Detail: "first call to model m"},
		{Detection: detect.D8, Severity: detect.SeverityMedium, Detail: "new region"},
		{Detection: detect.D6, Severity: detect.SeverityHigh, Detail: "spike"},
	})
	if len(out) != 2 || out[0].Detection != detect.D6 || out[0].Severity != detect.SeverityHigh ||
		out[0].Detail != "first call to model m; spike" {
		t.Fatalf("merged %+v", out)
	}
}

func TestAgentAlertEvidenceCapped(t *testing.T) {
	var raw json.RawMessage
	var err error
	for i := 0; i < 40; i++ {
		raw, err = appendAgentAlertEvidence(raw, AgentAlertEventRef{EventID: string(rune('A' + i))})
		if err != nil {
			t.Fatal(err)
		}
	}
	var refs []AgentAlertEventRef
	if err := json.Unmarshal(raw, &refs); err != nil {
		t.Fatal(err)
	}
	if len(refs) != agentAlertEvidenceHead+agentAlertEvidenceTail {
		t.Fatalf("%d refs kept", len(refs))
	}
	if refs[0].EventID != "A" || refs[4].EventID != "E" || refs[len(refs)-1].EventID != string(rune('A'+39)) {
		t.Errorf("kept %v ... %v", refs[0], refs[len(refs)-1])
	}
}

// The evidence a SIEM receives carries event references only; nothing from
// a request body (there is none on an Event) and no secret value.
func TestAgentAlertSIEMPayloadShape(t *testing.T) {
	ref := agentAlertRef(agentAlertHit{f: detect.Finding{Detection: detect.D1, Severity: detect.SeverityHigh, Detail: "secretsmanager:GetSecretValue"},
		e: agentruntime.Event{EventID: "ev-1", EventTime: time.Unix(1700000000, 0), EventSource: "secretsmanager.amazonaws.com",
			EventName: "GetSecretValue", SourceIP: "203.0.113.5", Region: "us-east-1",
			RequestFacts: map[string]string{agentruntime.FactSecretID: "prod/openai-key"}}})
	ev, _ := appendAgentAlertEvidence(nil, ref)
	a := AgentAlert{ID: uuid.New(), WorkspaceID: uuid.New(), IdentityID: uuid.New(), Detection: "D1", Severity: "high",
		Title: "Read a secret: order-agent (AI workload)", State: AgentAlertOpen, EventCount: 1, Evidence: ev}
	body, err := BuildAgentAlertSIEMPayload(a, "d-1", time.Unix(1700000100, 0))
	if err != nil {
		t.Fatal(err)
	}
	var p AgentAlertSIEMPayload
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatal(err)
	}
	if p.Type != AgentAlertSIEMType || p.Alert.ID != a.ID || p.Alert.DetectionName != "Read a secret" || len(p.Evidence) != 1 ||
		p.Evidence[0].EventID != "ev-1" || string(p.Alert.WorkloadIDs) != "[]" {
		t.Fatalf("payload %s", body)
	}
	if strings.Contains(string(body), "prod/openai-key") {
		t.Errorf("the payload names the secret: %s", body)
	}
}

func TestSignAgentAlertSIEM(t *testing.T) {
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write([]byte("1700000000.{\"a\":1}"))
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if got := SignAgentAlertSIEM("s3cret", "1700000000", []byte(`{"a":1}`)); got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

// PostAgentAlertSIEM signs timestamp + "." + body and sends the headers.
func TestPostAgentAlertSIEMHeaders(t *testing.T) {
	var gotSig, gotTS, gotDelivery, gotUA string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig, gotTS = r.Header.Get(AgentAlertSIEMSignatureHeader), r.Header.Get(AgentAlertSIEMTimestampHeader)
		gotDelivery, gotUA = r.Header.Get(AgentAlertSIEMDeliveryHeader), r.Header.Get("User-Agent")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	now := time.Unix(1700000000, 0)
	body := []byte(`{"type":"x"}`)
	status, err := PostAgentAlertSIEM(context.Background(), srv.Client(), srv.URL, "k", "d-9", body, now)
	if err != nil || status != http.StatusAccepted {
		t.Fatalf("status %d err %v", status, err)
	}
	if gotTS != "1700000000" || gotDelivery != "d-9" || gotUA != AgentAlertSIEMUserAgent || string(gotBody) != string(body) {
		t.Fatalf("headers ts=%q delivery=%q ua=%q body=%s", gotTS, gotDelivery, gotUA, gotBody)
	}
	if gotSig != SignAgentAlertSIEM("k", gotTS, gotBody) {
		t.Fatalf("signature %q does not verify", gotSig)
	}

	// A non-2xx answer is a (retryable) failure.
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	defer fail.Close()
	if status, err := PostAgentAlertSIEM(context.Background(), fail.Client(), fail.URL, "k", "", body, now); err == nil || status != http.StatusBadGateway {
		t.Fatalf("502: status %d err %v", status, err)
	}
}

// The default SIEM client is safehttp's: a loopback endpoint is refused,
// permanently.
func TestAgentAlertSIEMClientRefusesPrivateAddresses(t *testing.T) {
	t.Setenv("MCP_ALLOW_LOOPBACK", "false")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the request reached a loopback server")
	}))
	defer srv.Close()
	_, err := PostAgentAlertSIEM(context.Background(), agentAlertSIEMClient(), srv.URL, "k", "", []byte(`{}`), time.Now())
	var perm *agentAlertPermanent
	if err == nil || !errors.As(err, &perm) {
		t.Fatalf("err %v, want a permanent blocked-address error", err)
	}
}

func TestValidateAgentAlertSIEMURL(t *testing.T) {
	for _, u := range []string{"", "http://siem.example.com/hook", "https://user:pw@siem.example.com/", "ftp://x", "https:///nohost", "https://siem.example.com/#frag"} {
		if _, err := validateAgentAlertSIEMURL(u); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
	if got, err := validateAgentAlertSIEMURL(" https://siem.example.com/hook?x=1 "); err != nil || got != "https://siem.example.com/hook?x=1" {
		t.Errorf("valid URL: %q %v", got, err)
	}
}

func TestAgentAlertSIEMBackoff(t *testing.T) {
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 32 * time.Minute, time.Hour, time.Hour}
	for i, w := range want {
		if got := agentAlertSIEMBackoff(i + 1); got != w {
			t.Errorf("attempt %d: %v want %v", i+1, got, w)
		}
	}
}

type stubResolver struct {
	subj  agentruntime.Subject
	calls int
}

func (r *stubResolver) Resolve(context.Context, uuid.UUID, uuid.UUID, agentruntime.Attribution) (agentruntime.Subject, error) {
	r.calls++
	return r.subj, nil
}

// No resolver, an unresolved identity, or an identity that is not an AI
// workload / suggested agent / agent: nothing is read or written (the sink
// here has no database at all).
func TestAgentAlertSinkSkipsWithoutAQualifyingSubject(t *testing.T) {
	t.Cleanup(agentruntime.ResetSinks)
	sink := NewAgentAlertSink(nil)
	if sink.Name() != "agent_alerts" {
		t.Fatalf("name %q", sink.Name())
	}
	ws, conn := uuid.New(), uuid.New()
	ev := []agentruntime.Event{{EventID: "e1", EventTime: time.Now(), EventSource: "secretsmanager.amazonaws.com",
		EventName: "GetSecretValue", EventType: "AwsApiCall",
		SessionIssuerARN: "arn:aws:iam::111111111111:role/app", SessionIssuerPrincipalID: "AROAEXAMPLE"}}

	agentruntime.ResetSinks()
	if err := sink.Process(context.Background(), ws, conn, ev); err != nil {
		t.Fatalf("nil resolver: %v", err)
	}
	for _, subj := range []agentruntime.Subject{
		{IdentityID: uuid.Nil, Label: agentruntime.LabelAgent},
		{IdentityID: uuid.New(), Label: ""},
		{IdentityID: uuid.New(), Label: "workload"},
	} {
		r := &stubResolver{subj: subj}
		agentruntime.SetResolver(r)
		if err := sink.Process(context.Background(), ws, conn, ev); err != nil {
			t.Fatalf("%+v: %v", subj, err)
		}
		if r.calls != 1 {
			t.Errorf("resolver called %d times", r.calls)
		}
	}
	// An event with no attribution is never resolved.
	r := &stubResolver{subj: agentruntime.Subject{IdentityID: uuid.New(), Label: agentruntime.LabelAgent}}
	agentruntime.SetResolver(r)
	if err := sink.Process(context.Background(), ws, conn, []agentruntime.Event{{EventID: "e2", EventName: "X"}}); err != nil || r.calls != 0 {
		t.Fatalf("unattributed: err %v calls %d", err, r.calls)
	}
}
