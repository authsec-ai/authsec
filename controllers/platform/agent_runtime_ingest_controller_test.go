package platform

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/services"
)

// The create/rotate response carries the event secret in data.secret and in
// no other field (lab 2026-11-05: the stack parameters repeated it).
func TestEventStreamCreatedBodyShowsTheSecretOnce(t *testing.T) {
	secret, err := services.GenerateAgentEventSecret()
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	view := services.AgentEventStreamView{ConnectorID: id, State: services.AgentEventStreamActive,
		SecretPrefix: secret[:8], EndpointURL: "https://x.example/authsec/ingest/aws/events",
		SecretHeader: services.AgentEventSecretHeader}
	raw, err := json.Marshal(eventStreamCreatedBody(view, secret, false, id, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(raw), secret); n != 1 {
		t.Fatalf("the secret occurs %d times in the response, want 1: %s", n, raw)
	}
	var body struct {
		Data struct {
			Secret         string `json:"secret"`
			CloudFormation struct {
				Parameters []services.CFNParameter `json:"parameters"`
			} `json:"cloudformation"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body.Data.Secret != secret {
		t.Fatal("data.secret is not the secret")
	}
	found := false
	for _, p := range body.Data.CloudFormation.Parameters {
		if p.ParameterKey == "EventSecret" {
			found = true
			if p.ParameterValue != services.EventStreamSecretInResponse {
				t.Fatalf("EventSecret parameter %q, want the placeholder", p.ParameterValue)
			}
		}
	}
	if !found {
		t.Fatal("no EventSecret parameter")
	}
}
