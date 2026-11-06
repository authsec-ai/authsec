package agentruntime

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

const converseRecord = `{
 "eventVersion":"1.10","eventID":"e-1","eventTime":"2026-11-05T10:00:00Z",
 "eventSource":"bedrock.amazonaws.com","eventName":"Converse","eventType":"AwsApiCall",
 "eventCategory":"Management","readOnly":true,"recipientAccountId":"220171243705",
 "awsRegion":"us-east-1","sourceIPAddress":"203.0.113.9","userAgent":"Boto3/1.35",
 "userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::220171243705:assumed-role/order-agent/order-fn",
  "principalId":"AROAEXAMPLE:order-fn",
  "sessionContext":{"sessionIssuer":{"type":"Role","arn":"arn:aws:iam::220171243705:role/order-agent","principalId":"AROAEXAMPLE"}}},
 "requestParameters":{"modelId":"anthropic.claude-sonnet","messages":[{"role":"user"}]},
 "resources":[{"ARN":"arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-sonnet"}]
}`

func TestParseCloudTrailRecord(t *testing.T) {
	e, err := ParseCloudTrailRecord([]byte(converseRecord))
	if err != nil {
		t.Fatal(err)
	}
	if e.EventID != "e-1" || e.EventName != "Converse" || e.AccountID != "220171243705" || e.Region != "us-east-1" ||
		e.EventTime.IsZero() || e.SessionName != "order-fn" || e.ReadOnly == nil || !*e.ReadOnly {
		t.Fatalf("fields: %+v", e)
	}
	if got := e.RequestFacts[FactModelID]; got != "anthropic.claude-sonnet" {
		t.Fatalf("model fact %q", got)
	}
	if _, ok := e.RequestFacts["messages"]; ok {
		t.Fatal("a body field was kept")
	}
	if a := e.Attribution(); a.How != AttributionSessionIssuer || a.ARN != "arn:aws:iam::220171243705:role/order-agent" || a.UniqueID != "AROAEXAMPLE" {
		t.Fatalf("attribution %+v", a)
	}
	if !e.IsModelCall() || len(e.Resources) != 1 {
		t.Fatalf("model call %v resources %v", e.IsModelCall(), e.Resources)
	}
}

func TestStreamCompletionIsNotAModelCall(t *testing.T) {
	e := Event{EventSource: SourceBedrock, EventName: "ConverseStream", EventType: "AwsServiceEvent"}
	if e.IsModelCall() || e.IsAPICall() {
		t.Fatal("a stream-completion record counted as a call")
	}
	e.EventType = "AwsApiCall"
	if !e.IsModelCall() {
		t.Fatal("the call itself is a model call")
	}
	if (Event{EventSource: SourceBedrock, EventName: "ListFoundationModels", EventType: "AwsApiCall"}).IsModelCall() {
		t.Fatal("a control-plane call counted as a model call")
	}
	if !(Event{EventSource: SourceBedrockMantle, EventName: "CreateChatCompletion", EventType: "AwsApiCall"}).IsModelCall() {
		t.Fatal("a mantle call is a model call")
	}
}

func TestAttributionNeverByName(t *testing.T) {
	user := Event{PrincipalType: "IAMUser", PrincipalARN: "arn:aws:iam::1:user/bob", PrincipalID: "AIDA1", UserName: "bob"}
	if a := user.Attribution(); a.How != AttributionPrincipalARN || a.UniqueID != "AIDA1" {
		t.Fatalf("user %+v", a)
	}
	for _, e := range []Event{
		{PrincipalType: "Root", PrincipalARN: "arn:aws:iam::1:root"},
		{PrincipalType: "AWSService", InvokedBy: "lambda.amazonaws.com"},
		{PrincipalType: "AssumedRole", PrincipalARN: "arn:aws:sts::1:assumed-role/r/s"}, // issuer omitted
		{UserName: "bob"},
	} {
		if a := e.Attribution(); a.How != "" {
			t.Fatalf("%+v attributed: %+v", e, a)
		}
	}
}

func TestParseEventBridge(t *testing.T) {
	env := `{"id":"x","detail-type":"AWS API Call via CloudTrail","source":"aws.bedrock","account":"220171243705","region":"us-east-1","detail":` + converseRecord + `}`
	e, err := ParseEventBridge([]byte(env))
	if err != nil || e.EventID != "e-1" {
		t.Fatalf("%+v %v", e, err)
	}
	if _, err := ParseEventBridge([]byte(`{"detail-type":"EC2 Instance State-change Notification","detail":{}}`)); err == nil {
		t.Fatal("a non-CloudTrail event was accepted")
	}
	if _, err := ParseCloudTrailRecord([]byte(`{"eventName":"X"}`)); err == nil {
		t.Fatal("a record without eventID was accepted")
	}
}

func TestTrailNameFactOnlyForCloudTrail(t *testing.T) {
	e, _ := ParseCloudTrailRecord([]byte(`{"eventID":"1","eventName":"StopLogging","eventSource":"cloudtrail.amazonaws.com","requestParameters":{"name":"main"}}`))
	if e.RequestFacts[FactTrailName] != "main" || e.RequestFacts[FactParameter] != "" {
		t.Fatalf("cloudtrail name: %v", e.RequestFacts)
	}
	e, _ = ParseCloudTrailRecord([]byte(`{"eventID":"2","eventName":"GetParameter","eventSource":"ssm.amazonaws.com","requestParameters":{"name":"/db/pass","withDecryption":true}}`))
	if e.RequestFacts[FactParameter] != "/db/pass" || e.RequestFacts[FactWithDecryption] != "true" {
		t.Fatalf("ssm name: %v", e.RequestFacts)
	}
}

// withDecryption is a JSON bool: kept as "true" / "false", absent when the
// record does not state it.
func TestParseWithDecryption(t *testing.T) {
	for _, c := range []struct{ param, want string }{
		{`,"withDecryption":true`, "true"},
		{`,"withDecryption":false`, "false"},
		{``, ""},
	} {
		raw := `{"eventID":"wd","eventName":"GetParameter","eventSource":"ssm.amazonaws.com","requestParameters":{"name":"/db/pass"` + c.param + `}}`
		e, err := ParseCloudTrailRecord([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		got, ok := e.RequestFacts[FactWithDecryption]
		if got != c.want || ok != (c.want != "") {
			t.Fatalf("%s: with_decryption=%q (present %v), want %q", c.param, got, ok, c.want)
		}
		if e.RequestFacts[FactParameter] != "/db/pass" {
			t.Fatalf("parameter fact: %v", e.RequestFacts)
		}
	}
}

type sinkFunc struct {
	name string
	fn   func([]Event) error
}

func (s sinkFunc) Name() string { return s.name }
func (s sinkFunc) Process(_ context.Context, _, _ uuid.UUID, ev []Event) error {
	return s.fn(ev)
}

func TestDispatchRunsEverySinkOnce(t *testing.T) {
	ResetSinks()
	defer ResetSinks()
	var a, b int
	RegisterSink(sinkFunc{"a", func(ev []Event) error { a += len(ev); return errors.New("a failed") }})
	RegisterSink(sinkFunc{"b", func(ev []Event) error { b += len(ev); return nil }})
	RegisterSink(sinkFunc{"a", func(ev []Event) error { a += 100; return nil }}) // same name: ignored
	err := Dispatch(context.Background(), uuid.New(), uuid.New(), []Event{{EventID: "1"}, {EventID: "2"}})
	if err == nil || a != 2 || b != 2 {
		t.Fatalf("a=%d b=%d err=%v", a, b, err)
	}
	if err := Dispatch(context.Background(), uuid.New(), uuid.New(), nil); err != nil {
		t.Fatal(err)
	}
}
