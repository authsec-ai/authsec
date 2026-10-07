package services

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/google/uuid"
)

// T3.09: the callback consumer routes Custom::AuthSecEnforcementRegistration
// to the enforcement handler, and without one rejects it exactly as any
// unknown resource (never answered, left for the DLQ). Discovery messages
// never reach the enforcement handler.

type stubEnfHandler struct{ calls int }

func (s *stubEnfHandler) HandleEnforcementCallback(context.Context, *awsdiscovery.SNSEnvelope, bool) CallbackOutcome {
	s.calls++
	return CallbackDone
}

func enfEnvelope(h *qcHarness) string {
	req, _ := json.Marshal(map[string]any{
		"RequestType": "Create", "RequestId": "r1", "ResponseURL": qcResponseURL,
		"StackId":           "arn:aws:cloudformation:ap-south-1:" + qcAccount + ":stack/AuthSec-Enforcement-x/1",
		"ResourceType":      awsdiscovery.EnforcementRegistrationResourceType,
		"LogicalResourceId": awsdiscovery.EnforcementRegistrationLogicalID,
	})
	env, _ := json.Marshal(map[string]string{"Type": "Notification", "MessageId": uuid.NewString(),
		"TopicArn": qcTopicAPS, "Message": string(req), "Timestamp": h.clock.Format(time.RFC3339Nano)})
	return string(env)
}

func TestP3EnfCallbackDispatch(t *testing.T) {
	h := newQCHarness(t)
	if out := h.svc.HandleCallbackMessage(context.Background(), enfEnvelope(h)); out != CallbackReject || h.transport.count() != 0 {
		t.Fatalf("no handler: %s with %d answers, want reject and none", out, h.transport.count())
	}
	stub := &stubEnfHandler{}
	h.svc.WithEnforcementHandler(stub)
	if out := h.svc.HandleCallbackMessage(context.Background(), enfEnvelope(h)); out != CallbackDone || stub.calls != 1 {
		t.Fatalf("with handler: %s, %d calls", out, stub.calls)
	}
	// A message through a topic that is not AuthSec's never reaches it.
	env := enfEnvelope(h)
	var m map[string]string
	_ = json.Unmarshal([]byte(env), &m)
	m["TopicArn"] = "arn:aws:sns:ap-south-1:999999999999:attacker"
	raw, _ := json.Marshal(m)
	if out := h.svc.HandleCallbackMessage(context.Background(), string(raw)); out != CallbackReject || stub.calls != 1 {
		t.Fatalf("foreign topic: %s, %d calls", out, stub.calls)
	}
	// A discovery message still goes to the discovery path.
	sess := h.start(t, "ap-south-1")
	h.svc.HandleCallbackMessage(context.Background(), h.body(sess, cfnMsg{}))
	if stub.calls != 1 || h.onboards != 1 {
		t.Fatalf("discovery message: enforcement calls %d, onboards %d", stub.calls, h.onboards)
	}
}
