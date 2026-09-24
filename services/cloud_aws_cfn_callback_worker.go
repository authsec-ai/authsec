package services

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

// The Quick Create callback worker: drains the central SQS queue every
// regional callback topic delivers to, and hands each message to
// AWSQuickCreateService.HandleCallbackMessage.
//
// Safe on every replica. SQS hides a received message from other consumers
// for the visibility timeout, and the service takes a per-session Redis lock,
// so two replicas never connect the same launch twice. A message is deleted
// only once it is handled; anything else comes back.
const (
	// awsCallbackVisibility outlasts the longest a single message can take:
	// the 540s callback deadline plus the regional probes. Shorter, and a slow
	// message would reappear to a second worker while the first still holds it.
	awsCallbackVisibility = 15 * time.Minute
	// awsCallbackRetryVisibility is how soon a transiently failed message
	// becomes visible again. Well inside the callback deadline, so several
	// retries fit before AuthSec must answer.
	awsCallbackRetryVisibility = 30 * time.Second
	awsCallbackWait            = 20 // seconds; SQS long-poll maximum
	awsCallbackBatch           = 5
	awsCallbackErrorBackoff    = 10 * time.Second
)

// sqsAPI is the slice of the SQS client the worker uses, so it can be
// exercised without AWS.
type sqsAPI interface {
	ReceiveMessage(ctx context.Context, in *sqs.ReceiveMessageInput, opts ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error)
	DeleteMessage(ctx context.Context, in *sqs.DeleteMessageInput, opts ...func(*sqs.Options)) (*sqs.DeleteMessageOutput, error)
	ChangeMessageVisibility(ctx context.Context, in *sqs.ChangeMessageVisibilityInput, opts ...func(*sqs.Options)) (*sqs.ChangeMessageVisibilityOutput, error)
}

// AWSCallbackWorker consumes the callback queue.
type AWSCallbackWorker struct {
	svc      *AWSQuickCreateService
	client   sqsAPI
	queueURL string
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
	return &AWSCallbackWorker{svc: svc, client: sqs.NewFromConfig(cfg), queueURL: queueURL}, nil
}

// Run consumes until the context ends.
func (w *AWSCallbackWorker) Run(ctx context.Context) {
	log.Printf("aws callback worker started on %s", w.queueURL)
	for {
		select {
		case <-ctx.Done():
			log.Printf("aws callback worker stopping")
			return
		default:
		}
		if _, err := w.RunOnce(ctx); err != nil {
			log.Printf("[aws-onb] ALERT stage=worker outcome=receive_failed err=%v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(awsCallbackErrorBackoff):
			}
		}
	}
}

// RunOnce receives one batch and handles it. Messages in a batch are handled
// concurrently: each can spend minutes retrying Onboard, and handling them one
// after another would push later ones past their callback deadline.
func (w *AWSCallbackWorker) RunOnce(ctx context.Context) (int, error) {
	out, err := w.client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
		QueueUrl:            aws.String(w.queueURL),
		MaxNumberOfMessages: awsCallbackBatch,
		WaitTimeSeconds:     awsCallbackWait,
		VisibilityTimeout:   int32(awsCallbackVisibility / time.Second),
	})
	if err != nil {
		return 0, err
	}
	var wg sync.WaitGroup
	for _, m := range out.Messages {
		wg.Add(1)
		go func(body, receipt string) {
			defer wg.Done()
			w.settle(ctx, receipt, w.svc.HandleCallbackMessage(ctx, body))
		}(aws.ToString(m.Body), aws.ToString(m.ReceiptHandle))
	}
	wg.Wait()
	return len(out.Messages), nil
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
