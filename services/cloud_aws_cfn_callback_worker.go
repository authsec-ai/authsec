package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

// The Quick Create callback worker: drains the central SQS queue every
// regional callback topic delivers to, and hands each message to
// AWSQuickCreateService.HandleCallbackDelivery.
//
// Safe on every replica. SQS hides a received message from other consumers
// while it is being handled, and the service takes a per-session Redis lock,
// so two replicas never connect the same launch twice. A message is deleted
// only once it is handled; anything else comes back.
const (
	// awsCallbackVisibility is how long a received message stays hidden. Short,
	// and extended every awsCallbackHeartbeat while the message is still being
	// handled: a worker that crashes or is redeployed releases its messages
	// within minutes, well inside the stack's 600s ServiceTimeout, instead of
	// stranding them for the whole handling budget.
	awsCallbackVisibility = 2 * time.Minute
	awsCallbackHeartbeat  = time.Minute
	// awsCallbackRetryVisibility is how soon a transiently failed message
	// becomes visible again. Well inside the callback deadline, so several
	// retries fit before AuthSec must answer.
	awsCallbackRetryVisibility = 30 * time.Second
	awsCallbackWait            = 20 // seconds; SQS long-poll maximum
	awsCallbackMaxBatch        = 10 // SQS maximum per receive
	// awsCallbackConcurrency bounds how many callbacks one replica handles at
	// once. Each can spend minutes retrying Onboard; the bound keeps a burst from
	// exhausting STS and database connections, while a slow one never blocks the
	// rest (there is no per-batch barrier).
	awsCallbackConcurrency    = 16
	awsCallbackMaxConcurrency = 128
	envAWSCallbackConcurrency = "AUTHSEC_AWS_CFN_CALLBACK_CONCURRENCY"
	// awsCallbackDefaultMaxReceives is assumed when the queue's redrive policy
	// cannot be read. It matches the runbook's recommended setting.
	awsCallbackDefaultMaxReceives = 25
	awsCallbackErrorBackoff       = 10 * time.Second
)

// sqsAPI is the slice of the SQS client the worker uses, so it can be
// exercised without AWS.
type sqsAPI interface {
	ReceiveMessage(ctx context.Context, in *sqs.ReceiveMessageInput, opts ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error)
	DeleteMessage(ctx context.Context, in *sqs.DeleteMessageInput, opts ...func(*sqs.Options)) (*sqs.DeleteMessageOutput, error)
	ChangeMessageVisibility(ctx context.Context, in *sqs.ChangeMessageVisibilityInput, opts ...func(*sqs.Options)) (*sqs.ChangeMessageVisibilityOutput, error)
	GetQueueAttributes(ctx context.Context, in *sqs.GetQueueAttributesInput, opts ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error)
}

// AWSCallbackWorker consumes the callback queue.
type AWSCallbackWorker struct {
	svc      *AWSQuickCreateService
	client   sqsAPI
	queueURL string
	// maxReceives is the queue's redrive maxReceiveCount: the delivery on which
	// a message would next go to the DLQ is its last chance to be answered.
	maxReceives int
	slots       chan struct{}
	heartbeat   time.Duration
}

// NewAWSCallbackWorker builds the worker against real SQS, using AuthSec's own
// AWS identity from the ambient environment — the same base credentials the
// onboarding verifier assumes customer roles with.
func NewAWSCallbackWorker(ctx context.Context, svc *AWSQuickCreateService) (*AWSCallbackWorker, error) {
	queueURL := svc.Config().QueueURL
	region, err := awsdiscovery.QueueRegion(queueURL)
	if err != nil {
		return nil, err
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws callback worker: %w", err)
	}
	w := newAWSCallbackWorker(svc, sqs.NewFromConfig(cfg), queueURL)
	// Bounded: an unreachable SQS endpoint must not hold up the caller for the
	// SDK's full retry budget. The default is used if the read times out.
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	w.maxReceives = w.readMaxReceives(rctx)
	return w, nil
}

func newAWSCallbackWorker(svc *AWSQuickCreateService, client sqsAPI, queueURL string) *AWSCallbackWorker {
	return &AWSCallbackWorker{
		svc: svc, client: client, queueURL: queueURL,
		maxReceives: awsCallbackDefaultMaxReceives,
		slots:       make(chan struct{}, awsCallbackConcurrencyFromEnv()),
		heartbeat:   awsCallbackHeartbeat,
	}
}

// awsCallbackConcurrencyFromEnv reads AUTHSEC_AWS_CFN_CALLBACK_CONCURRENCY,
// the callbacks one replica handles at once. Raise it (with replicas) for a
// large onboarding burst: slots needed ≈ arrivals per second × seconds each
// callback holds a slot. Bounded so a typo cannot open thousands of STS calls.
func awsCallbackConcurrencyFromEnv() int {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(envAWSCallbackConcurrency)))
	if err != nil || n < 1 {
		return awsCallbackConcurrency
	}
	if n > awsCallbackMaxConcurrency {
		return awsCallbackMaxConcurrency
	}
	return n
}

// readMaxReceives reads the queue's redrive policy. Without one there is no
// DLQ and no last chance to detect; the default then only decides when the
// worker stops waiting for a transient failure to clear.
func (w *AWSCallbackWorker) readMaxReceives(ctx context.Context) int {
	out, err := w.client.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
		QueueUrl:       aws.String(w.queueURL),
		AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameRedrivePolicy},
	})
	if err != nil {
		log.Printf("[aws-onb] ALERT stage=worker outcome=no_redrive_policy err=%v (assuming maxReceiveCount=%d)",
			err, awsCallbackDefaultMaxReceives)
		return awsCallbackDefaultMaxReceives
	}
	raw := out.Attributes[string(sqstypes.QueueAttributeNameRedrivePolicy)]
	var policy struct {
		MaxReceiveCount json.Number `json:"maxReceiveCount"`
	}
	if raw == "" || json.Unmarshal([]byte(raw), &policy) != nil {
		log.Printf("[aws-onb] ALERT stage=worker outcome=no_redrive_policy (assuming maxReceiveCount=%d)",
			awsCallbackDefaultMaxReceives)
		return awsCallbackDefaultMaxReceives
	}
	n, err := strconv.Atoi(policy.MaxReceiveCount.String())
	if err != nil || n < 1 {
		return awsCallbackDefaultMaxReceives
	}
	if n < 10 {
		log.Printf("[aws-onb] ALERT stage=worker queue maxReceiveCount=%d is low: transient failures reach the "+
			"DLQ within minutes. The runbook recommends %d.", n, awsCallbackDefaultMaxReceives)
	}
	return n
}

// Run consumes until the context ends. Each message is handled as soon as it
// arrives, up to awsCallbackConcurrency at once; a slow one never holds up the
// rest.
func (w *AWSCallbackWorker) Run(ctx context.Context) {
	log.Printf("aws callback worker started on %s (maxReceiveCount=%d)", w.queueURL, w.maxReceives)
	for {
		select {
		case <-ctx.Done():
			log.Printf("aws callback worker stopping")
			return
		default:
		}
		if _, err := w.receiveAndDispatch(ctx, nil); err != nil {
			log.Printf("[aws-onb] ALERT stage=worker outcome=receive_failed err=%v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(awsCallbackErrorBackoff):
			}
		}
	}
}

// RunOnce receives one batch, handles it, and waits for it to finish. For
// tests and one-shot use; Run does not wait.
func (w *AWSCallbackWorker) RunOnce(ctx context.Context) (int, error) {
	var wg sync.WaitGroup
	n, err := w.receiveAndDispatch(ctx, &wg)
	wg.Wait()
	return n, err
}

// receiveAndDispatch waits for a free slot, receives as many messages as there
// are free slots (up to SQS's batch maximum), and starts each one.
func (w *AWSCallbackWorker) receiveAndDispatch(ctx context.Context, wg *sync.WaitGroup) (int, error) {
	// Block until at least one slot is free, so the worker never holds a
	// message it cannot start.
	select {
	case w.slots <- struct{}{}:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	free := 1 + (cap(w.slots) - len(w.slots))
	if free > awsCallbackMaxBatch {
		free = awsCallbackMaxBatch
	}
	out, err := w.client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
		QueueUrl:            aws.String(w.queueURL),
		MaxNumberOfMessages: int32(free),
		WaitTimeSeconds:     awsCallbackWait,
		VisibilityTimeout:   int32(awsCallbackVisibility / time.Second),
		MessageSystemAttributeNames: []sqstypes.MessageSystemAttributeName{
			sqstypes.MessageSystemAttributeNameApproximateReceiveCount,
		},
	})
	if err != nil || len(out.Messages) == 0 {
		<-w.slots
		return 0, err
	}
	for i, m := range out.Messages {
		if i > 0 {
			// The first message uses the slot taken above; each further one
			// takes its own. There were at least `free` slots, so this does not
			// block for long.
			w.slots <- struct{}{}
		}
		if wg != nil {
			wg.Add(1)
		}
		go w.handle(ctx, m, wg)
	}
	return len(out.Messages), nil
}

// handle processes one message: keeps it hidden while it is being worked on,
// passes the last-chance flag, settles it, and frees its slot.
func (w *AWSCallbackWorker) handle(ctx context.Context, m sqstypes.Message, wg *sync.WaitGroup) {
	receipt := aws.ToString(m.ReceiptHandle)
	stop := make(chan struct{})
	beatDone := make(chan struct{})
	go func() {
		defer close(beatDone)
		t := time.NewTicker(w.heartbeat)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if _, err := w.client.ChangeMessageVisibility(ctx, &sqs.ChangeMessageVisibilityInput{
					QueueUrl: aws.String(w.queueURL), ReceiptHandle: aws.String(receipt),
					VisibilityTimeout: int32(awsCallbackVisibility / time.Second),
				}); err != nil {
					log.Printf("[aws-onb] stage=worker outcome=heartbeat_failed err=%v", err)
				}
			}
		}
	}()
	// The heartbeat is stopped and joined BEFORE the message is settled: a
	// tick landing after settle would reset the visibility settle just chose
	// (30s for a retry, 0 for a reject) back to two minutes.
	var stopOnce sync.Once
	stopBeat := func() {
		stopOnce.Do(func() {
			close(stop)
			<-beatDone
		})
	}
	defer func() {
		stopBeat()
		<-w.slots
		if wg != nil {
			wg.Done()
		}
	}()
	// A panic in one message must not take the backend down with it. Hand the
	// message back for a prompt retry.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[aws-onb] ALERT stage=worker outcome=panic err=%v", r)
			stopBeat()
			w.settle(ctx, receipt, CallbackRetry)
		}
	}()

	receives, _ := strconv.Atoi(m.Attributes[string(sqstypes.MessageSystemAttributeNameApproximateReceiveCount)])
	lastChance := receives >= w.maxReceives
	outcome := w.svc.HandleCallbackDelivery(ctx, aws.ToString(m.Body), lastChance)
	stopBeat()
	w.settle(ctx, receipt, outcome)
}

// settle applies an outcome to a message.
//
//   - Done: delete it.
//   - Retry: make it visible again shortly, for another attempt.
//   - Reject: make it visible immediately and leave it. It is never answered;
//     after the queue's maxReceiveCount it moves to the DLQ, whose alarm is how
//     a forged or malformed callback reaches a person.
func (w *AWSCallbackWorker) settle(ctx context.Context, receipt string, outcome CallbackOutcome) {
	var err error
	switch outcome {
	case CallbackDone:
		_, err = w.client.DeleteMessage(ctx, &sqs.DeleteMessageInput{
			QueueUrl: aws.String(w.queueURL), ReceiptHandle: aws.String(receipt),
		})
	case CallbackRetry:
		_, err = w.client.ChangeMessageVisibility(ctx, &sqs.ChangeMessageVisibilityInput{
			QueueUrl: aws.String(w.queueURL), ReceiptHandle: aws.String(receipt),
			VisibilityTimeout: int32(awsCallbackRetryVisibility / time.Second),
		})
	case CallbackReject:
		_, err = w.client.ChangeMessageVisibility(ctx, &sqs.ChangeMessageVisibilityInput{
			QueueUrl: aws.String(w.queueURL), ReceiptHandle: aws.String(receipt),
			VisibilityTimeout: 0,
		})
	}
	if err != nil {
		// Not fatal: an undeleted message comes back after the visibility
		// timeout and its stored result is replayed.
		log.Printf("[aws-onb] stage=worker outcome=settle_failed result=%s err=%v", outcome, err)
	}
}
