package services

import (
	"context"
	"errors"
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
	redrive    string
	redriveErr error
}

func (f *fakeSQS) ReceiveMessage(_ context.Context, in *sqs.ReceiveMessageInput, _ ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.visibleFor = in.VisibilityTimeout
	n := int(in.MaxNumberOfMessages)
	if n > len(f.messages) {
		n = len(f.messages)
	}
	out := &sqs.ReceiveMessageOutput{Messages: f.messages[:n]}
	f.messages = f.messages[n:]
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

func (f *fakeSQS) GetQueueAttributes(_ context.Context, _ *sqs.GetQueueAttributesInput, _ ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error) {
	if f.redriveErr != nil {
		return nil, f.redriveErr
	}
	return &sqs.GetQueueAttributesOutput{Attributes: map[string]string{"RedrivePolicy": f.redrive}}, nil
}

func sqsMsg(body, receipt string, receives string) sqstypes.Message {
	return sqstypes.Message{
		Body: aws.String(body), ReceiptHandle: aws.String(receipt),
		Attributes: map[string]string{"ApproximateReceiveCount": receives},
	}
}

// A handled message is deleted; a rejected one is left visible so it reaches
// the DLQ; a transient failure comes back soon. The receive asks for the
// receive count and hides messages only briefly (the heartbeat extends them).
func TestAWSCallbackWorkerSettlesByOutcome(t *testing.T) {
	h := newQCHarness(t)
	sess := h.start(t, "ap-south-1")
	h.transport.status = 503 // the answer to CloudFormation fails transiently

	q := &fakeSQS{visibility: map[string]int32{}, messages: []sqstypes.Message{
		sqsMsg(h.body(nil, cfnMsg{requestType: "Delete"}), "delete", "1"),
		sqsMsg("not json", "junk", "1"),
		sqsMsg(h.body(sess, cfnMsg{}), "create", "1"),
	}}
	w := newAWSCallbackWorker(h.svc, q, "https://sqs.us-east-1.amazonaws.com/1/q")

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
	if len(q.deleted) != 0 {
		t.Fatalf("deleted %v", q.deleted)
	}
	if len(w.slots) != 0 {
		t.Fatalf("every slot must be released after the batch, %d still held", len(w.slots))
	}

	h.transport.status = 200
	q.messages = []sqstypes.Message{sqsMsg(h.body(nil, cfnMsg{requestType: "Delete"}), "delete2", "1")}
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(q.deleted) != 1 || q.deleted[0] != "delete2" {
		t.Fatalf("a handled message must be deleted, got %v", q.deleted)
	}
}

// On its last delivery before the DLQ, a message that would otherwise be
// retried is answered FAILED instead, so the stack fails with a reason rather
// than timing out in silence.
func TestAWSCallbackWorkerAnswersOnLastChance(t *testing.T) {
	h := newQCHarness(t)
	sess := h.start(t, "ap-south-1")
	// Make the session store fail after the session was created: every lookup
	// is then a transient error.
	h.mr.SetError("LOADING Redis is loading the dataset in memory")

	q := &fakeSQS{visibility: map[string]int32{}}
	w := newAWSCallbackWorker(h.svc, q, "https://sqs.us-east-1.amazonaws.com/1/q")
	w.maxReceives = 3

	q.messages = []sqstypes.Message{sqsMsg(h.body(sess, cfnMsg{}), "early", "1")}
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if q.visibility["early"] != int32(awsCallbackRetryVisibility.Seconds()) || h.transport.count() != 0 {
		t.Fatal("an early transient failure must be retried, not answered")
	}

	q.messages = []sqstypes.Message{sqsMsg(h.body(sess, cfnMsg{}), "last", "3")}
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(q.deleted) != 1 || q.deleted[0] != "last" {
		t.Fatalf("the last-chance message must be answered and deleted, got %v", q.deleted)
	}
	if r := h.transport.last(t); r.Status != "FAILED" {
		t.Fatalf("last chance must answer FAILED, got %+v", r)
	}
}

func TestAWSCallbackWorkerReadsRedrivePolicy(t *testing.T) {
	w := newAWSCallbackWorker(nil, &fakeSQS{redrive: `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:1:dlq","maxReceiveCount":"12"}`}, "q")
	if got := w.readMaxReceives(context.Background()); got != 12 {
		t.Fatalf("maxReceives %d", got)
	}
	w = newAWSCallbackWorker(nil, &fakeSQS{redrive: `{"maxReceiveCount":7}`}, "q")
	if got := w.readMaxReceives(context.Background()); got != 7 {
		t.Fatalf("numeric maxReceiveCount: %d", got)
	}
	w = newAWSCallbackWorker(nil, &fakeSQS{redriveErr: errors.New("denied")}, "q")
	if got := w.readMaxReceives(context.Background()); got != awsCallbackDefaultMaxReceives {
		t.Fatalf("fallback %d", got)
	}
}
