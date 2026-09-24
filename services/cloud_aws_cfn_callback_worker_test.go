package services

import (
	"context"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

type fakeSQS struct {
	mu         sync.Mutex
	messages   []sqstypes.Message
	deleted    []string
	visibility map[string]int32
	visibleFor int32
}

func (f *fakeSQS) ReceiveMessage(_ context.Context, in *sqs.ReceiveMessageInput, _ ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.visibleFor = in.VisibilityTimeout
	out := &sqs.ReceiveMessageOutput{Messages: f.messages}
	f.messages = nil
	return out, nil
}

func (f *fakeSQS) DeleteMessage(_ context.Context, in *sqs.DeleteMessageInput, _ ...func(*sqs.Options)) (*sqs.DeleteMessageOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, aws.ToString(in.ReceiptHandle))
	return &sqs.DeleteMessageOutput{}, nil
}

func (f *fakeSQS) ChangeMessageVisibility(_ context.Context, in *sqs.ChangeMessageVisibilityInput, _ ...func(*sqs.Options)) (*sqs.ChangeMessageVisibilityOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.visibility[aws.ToString(in.ReceiptHandle)] = in.VisibilityTimeout
	return &sqs.ChangeMessageVisibilityOutput{}, nil
}

// A handled message is deleted; a rejected one is left visible so it reaches
// the DLQ; a transient failure comes back soon. The receive itself must hide
// messages for longer than one message can take.
func TestAWSCallbackWorkerSettlesByOutcome(t *testing.T) {
	h := newQCHarness(t)
	sess := h.start(t, "ap-south-1")
	h.transport.status = 503 // the answer to CloudFormation fails transiently

	q := &fakeSQS{visibility: map[string]int32{}, messages: []sqstypes.Message{
		{Body: aws.String(h.body(nil, cfnMsg{requestType: "Delete"})), ReceiptHandle: aws.String("delete")},
		{Body: aws.String("not json"), ReceiptHandle: aws.String("junk")},
		{Body: aws.String(h.body(sess, cfnMsg{})), ReceiptHandle: aws.String("create")},
	}}
	w := &AWSCallbackWorker{svc: h.svc, client: q, queueURL: "https://sqs.us-east-1.amazonaws.com/1/q"}

	n, err := w.RunOnce(context.Background())
	if err != nil || n != 3 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if q.visibleFor != int32(awsCallbackVisibility.Seconds()) {
		t.Fatalf("receive visibility %d", q.visibleFor)
	}
	if v, ok := q.visibility["junk"]; !ok || v != 0 {
		t.Fatalf("a malformed message must be released for the DLQ, got %v %v", v, ok)
	}
	if v := q.visibility["create"]; v != int32(awsCallbackRetryVisibility.Seconds()) {
		t.Fatalf("a transient failure must come back soon, got %d", v)
	}
	// The Delete answer also hit the 503, so it is retried rather than deleted;
	// nothing in this batch is deleted.
	if len(q.deleted) != 0 {
		t.Fatalf("deleted %v", q.deleted)
	}

	h.transport.status = 200
	q.messages = []sqstypes.Message{{Body: aws.String(h.body(nil, cfnMsg{requestType: "Delete"})), ReceiptHandle: aws.String("delete2")}}
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(q.deleted) != 1 || q.deleted[0] != "delete2" {
		t.Fatalf("a handled message must be deleted, got %v", q.deleted)
	}
}
