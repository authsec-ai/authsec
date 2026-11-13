package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Unit tests of the agent runtime event stream that need no database: the
// secret's shape and hash, the body split, the per-event account check, the
// silence rule, the rate limit, and the templates' API.

func ebEvent(envAccount, recipient, eventID, detailType string) string {
	return fmt.Sprintf(`{"version":"0","id":"%s","detail-type":%q,"source":"aws.bedrock",
		"account":%q,"time":"2026-11-05T10:00:00Z","region":"us-east-1",
		"detail":{"eventVersion":"1.09","eventID":%q,"eventTime":"2026-11-05T10:00:00Z",
		"eventSource":"bedrock.amazonaws.com","eventName":"Converse","eventType":"AwsApiCall",
		"recipientAccountId":%q,"awsRegion":"us-east-1",
		"userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::%s:assumed-role/app/fn",
		"sessionContext":{"sessionIssuer":{"type":"Role","arn":"arn:aws:iam::%s:role/app","principalId":"AROAEXAMPLE"}}},
		"requestParameters":{"modelId":"anthropic.claude"}}}`,
		uuid.NewString(), detailType, envAccount, eventID, recipient, recipient, recipient)
}

func TestAgentEventSecret_ShapeAndHash(t *testing.T) {
	s, err := GenerateAgentEventSecret()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s, AgentEventSecretPrefix) || len(s) != agentEventSecretLen {
		t.Fatalf("secret %q has the wrong shape", s[:8])
	}
	if !wellFormedAgentEventSecret(s) {
		t.Fatal("a generated secret must be well formed")
	}
	for _, bad := range []string{"", "aev_", "aid_" + s[4:], s + "x", s[:len(s)-1] + "!"} {
		if wellFormedAgentEventSecret(bad) {
			t.Errorf("%q must not be well formed", bad)
		}
	}
	h := HashAgentEventSecret(s)
	if len(h) != 64 || h != strings.ToLower(h) || h != HashAgentEventSecret(s) {
		t.Fatalf("hash must be stable lower-case sha256 hex, got %q", h)
	}
	s2, _ := GenerateAgentEventSecret()
	if s2 == s || HashAgentEventSecret(s2) == h {
		t.Fatal("two secrets must differ")
	}
}

func TestSplitAgentEventBody(t *testing.T) {
	one := ebEvent("111111111111", "111111111111", uuid.NewString(), "AWS API Call via CloudTrail")
	if raws, err := splitAgentEventBody([]byte("  " + one + "\n")); err != nil || len(raws) != 1 {
		t.Fatalf("single event: %v %d", err, len(raws))
	}
	if raws, err := splitAgentEventBody([]byte("[" + one + "," + one + "]")); err != nil || len(raws) != 2 {
		t.Fatalf("array: %v %d", err, len(raws))
	}
	for name, body := range map[string]string{
		"empty": "", "spaces": "   ", "empty array": "[]", "string": `"x"`, "number": "1",
		"broken object": "{", "broken array": "[{}",
	} {
		if _, err := splitAgentEventBody([]byte(body)); !errors.Is(err, ErrAgentEventBadBody) {
			t.Errorf("%s: got %v, want ErrAgentEventBadBody", name, err)
		}
	}
	big := `{"pad":"` + strings.Repeat("a", AgentEventMaxEventBytes) + `"}`
	if _, err := splitAgentEventBody([]byte(big)); !errors.Is(err, ErrAgentEventTooLarge) {
		t.Errorf("an event over 256 KB: got %v, want ErrAgentEventTooLarge", err)
	}
	many := "[" + strings.TrimSuffix(strings.Repeat("{},", AgentEventMaxEventsPerRequest+1), ",") + "]"
	if _, err := splitAgentEventBody([]byte(many)); !errors.Is(err, ErrAgentEventTooLarge) {
		t.Errorf("too many events: got %v, want ErrAgentEventTooLarge", err)
	}
}

func TestClassifyAgentEvent_AccountFromTheConnectorOnly(t *testing.T) {
	const acct, other = "111111111111", "222222222222"
	id := uuid.NewString()
	e, reason := classifyAgentEvent(json.RawMessage(ebEvent(acct, acct, id, "AWS API Call via CloudTrail")), acct)
	if reason != "" || e.EventID != id || e.AccountID != acct || !e.IsModelCall() {
		t.Fatalf("own account: reason=%q event=%+v", reason, e)
	}
	cases := map[string]struct {
		raw  string
		want string
	}{
		"another account":           {ebEvent(other, other, id, "AWS API Call via CloudTrail"), agentEventRejectAccount},
		"forged envelope account":   {ebEvent(acct, other, id, "AWS API Call via CloudTrail"), agentEventRejectAccount},
		"forged recipient account":  {ebEvent(other, acct, id, "AWS API Call via CloudTrail"), agentEventRejectAccount},
		"not a CloudTrail event":    {ebEvent(acct, acct, id, "EC2 Instance State-change Notification"), agentEventRejectInvalid},
		"no eventID":                {ebEvent(acct, acct, "", "AWS API Call via CloudTrail"), agentEventRejectInvalid},
		"eventID longer than 128":   {ebEvent(acct, acct, strings.Repeat("x", 129), "AWS API Call via CloudTrail"), agentEventRejectInvalid},
		"not json":                  {"{not json", agentEventRejectInvalid},
		"over 256 KB in an array":   {`{"pad":"` + strings.Repeat("a", AgentEventMaxEventBytes) + `"}`, agentEventRejectOversize},
		"workspace in body ignored": {strings.Replace(ebEvent(other, other, id, "AWS API Call via CloudTrail"), `"version":"0"`, `"version":"0","workspace_id":"`+uuid.NewString()+`"`, 1), agentEventRejectAccount},
	}
	for name, c := range cases {
		if _, reason := classifyAgentEvent(json.RawMessage(c.raw), acct); reason != c.want {
			t.Errorf("%s: reason %q, want %q", name, reason, c.want)
		}
	}
}

func TestStreamSilence(t *testing.T) {
	created := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	after := 6 * time.Hour
	at := func(h int) time.Time { return created.Add(time.Duration(h) * time.Hour) }
	tp := func(t time.Time) *time.Time { return &t }

	if s, _ := streamSilence(AgentEventStreamActive, created, nil, nil, after, at(5)); s {
		t.Error("never delivered, within silent_after: not silent yet")
	}
	if s, since := streamSilence(AgentEventStreamActive, created, nil, nil, after, at(7)); !s || !since.Equal(created) {
		t.Errorf("never delivered: silent since created, got %v %v", s, since)
	}
	if s, since := streamSilence(AgentEventStreamActive, created, tp(at(2)), nil, after, at(9)); !s || !since.Equal(at(2)) {
		t.Errorf("rotated, never delivered: silent since rotation, got %v %v", s, since)
	}
	if s, _ := streamSilence(AgentEventStreamActive, created, nil, tp(at(10)), after, at(12)); s {
		t.Error("delivered 2 h ago: not silent")
	}
	if s, since := streamSilence(AgentEventStreamActive, created, nil, tp(at(10)), after, at(17)); !s || !since.Equal(at(10)) {
		t.Errorf("delivered 7 h ago: silent since the last event, got %v %v", s, since)
	}
	if s, _ := streamSilence(AgentEventStreamRevoked, created, nil, nil, after, at(100)); s {
		t.Error("a revoked stream is revoked, not silent")
	}
}

func TestAgentEventRateLimit_PerConnector(t *testing.T) {
	svc := (&AgentRuntimeIngestService{limiters: nil}).WithRateLimit(0.0001, 2)
	a, b := uuid.New(), uuid.New()
	if !svc.Allow(a) || !svc.Allow(a) {
		t.Fatal("the burst must be allowed")
	}
	if svc.Allow(a) {
		t.Fatal("over the burst must be refused")
	}
	if !svc.Allow(b) {
		t.Fatal("another connector has its own limit")
	}
}

func TestEventStreamStackParameters_NeverTheSecret(t *testing.T) {
	id := uuid.New()
	get := func(ps []CFNParameter, k string) string {
		for _, p := range ps {
			if p.ParameterKey == k {
				return p.ParameterValue
			}
		}
		return "<missing>"
	}
	ps := EventStreamStackParameters("https://x.example/authsec/ingest/aws/events", "", id)
	if get(ps, "EventSecret") != EventStreamSecretPlaceholder || get(ps, "ConnectorId") != id.String() {
		t.Fatalf("parameters without a secret: %+v", ps)
	}
	ps = EventStreamStackParameters("https://x.example/authsec/ingest/aws/events", EventStreamSecretInResponse, id)
	if get(ps, "EventSecret") != EventStreamSecretInResponse {
		t.Fatalf("create-response parameters: %+v", ps)
	}
	if doc := EventStreamTemplate(id); strings.Contains(fmt.Sprint(doc.Parameters), "aev_secret") || doc.Template == "" {
		t.Fatal("the template document must carry the stack and never a secret")
	}
}

func TestModelAccessTemplate_ModesAndForms(t *testing.T) {
	doc, err := ModelAccessTemplate("", "")
	if err != nil || doc.Mode != ModelAccessModeAudit || doc.Form != ModelAccessFormSCP || doc.Denies || doc.Template != "" {
		t.Fatalf("default must be audit/scp with no template: %+v %v", doc, err)
	}
	var audit map[string]any
	if err := json.Unmarshal(doc.Audit, &audit); err != nil {
		t.Fatalf("audit document: %v", err)
	}
	if audit["form"] != "scp" || audit["denies"] != false || audit["tagging_guide"] == nil {
		t.Fatalf("audit document: %v", audit)
	}
	for _, form := range []string{ModelAccessFormSCP, ModelAccessFormPolicy} {
		d, err := ModelAccessTemplate("deny", form)
		if err != nil || !d.Denies || d.Template == "" || len(d.Audit) != 0 {
			t.Fatalf("deny/%s: %+v %v", form, d, err)
		}
		if !strings.Contains(d.Template, "AdminPrincipalArns") || !strings.Contains(d.Template, "aws:PrincipalTag/authsec:agent") {
			t.Errorf("deny/%s: missing the tag gate or the administrator parameter", form)
		}
		if strings.Contains(d.Template, "PermissionsBoundary") {
			t.Errorf("deny/%s: there is no permissions-boundary form (spec §10)", form)
		}
	}
	for _, bad := range [][2]string{{"block", "scp"}, {"deny", "boundary"}, {"audit", "permissions-boundary"}} {
		if _, err := ModelAccessTemplate(bad[0], bad[1]); !errors.Is(err, ErrModelAccessParam) {
			t.Errorf("%v: got %v, want ErrModelAccessParam", bad, err)
		}
	}
}
