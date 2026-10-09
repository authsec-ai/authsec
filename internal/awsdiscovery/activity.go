package awsdiscovery

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// Activity: whether a permission was ever actually EXERCISED, as opposed to
// merely granted. The difference between "this role may read every bucket" and
// "this role has not touched S3 in 400 days" is what turns an inventory into a
// least-privilege recommendation.
//
// WHY THIS FILE LOOKS DIFFERENT FROM EVERY OTHER READER HERE. Every other AWS
// read in this package is a synchronous request inside a loop.
// iam:GenerateServiceLastAccessedDetails is not: it returns a JobId, and the
// caller polls iam:GetServiceLastAccessedDetails until the job reports
// COMPLETED. That is a real structural constraint, not an inconvenience -- it
// means one identity's activity costs a submit plus an unbounded number of
// polls, so both the poll interval and the total wait have to be bounded here
// or a scan of a large account never finishes.
//
// WHAT THIS DATA CAN AND CANNOT SUPPORT. AWS reports per SERVICE, not per
// action: "s3, last accessed 400 days ago". It can support "this role has never
// touched S3"; it cannot support "it used GetObject but never PutObject".
// TrackedActionsLastAccessed does carry action-level detail for a small set of
// services AWS has opted in, and is deliberately not read here -- a table whose
// rows were per-action for three services and per-service for everything else
// would be read as per-action throughout. CloudTrail is the honest source for
// action granularity, and it is rate-capped at roughly two requests a second,
// which makes it an opt-in upgrade rather than this default path.

// ServiceLastAccessedAPI is the slice of IAM used for activity.
//
// Separate from IAMAPI for the same reason InstanceProfileAPI is: it is needed
// only here, and folding it into that interface would force every IAM fake in
// the test suite to grow two methods it never calls.
type ServiceLastAccessedAPI interface {
	GenerateServiceLastAccessedDetails(ctx context.Context, in *iam.GenerateServiceLastAccessedDetailsInput, opts ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error)
	GetServiceLastAccessedDetails(ctx context.Context, in *iam.GetServiceLastAccessedDetailsInput, opts ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error)
}

// NewServiceLastAccessedClient builds a real IAM client for activity reads.
// IAM is global, so this is not region-bound.
func NewServiceLastAccessedClient(cfg aws.Config) ServiceLastAccessedAPI {
	return iam.NewFromConfig(cfg)
}

// ErrActivityJobFailed means AWS reported the report job as FAILED. Distinct
// from a denied or throttled read: the call was permitted and AWS accepted the
// job, then could not complete it.
var ErrActivityJobFailed = errors.New("the service-last-accessed job failed")

// ErrActivityJobTimeout means the job did not reach COMPLETED inside the
// budget. The report may still complete later; nothing was learned now.
var ErrActivityJobTimeout = errors.New("the service-last-accessed job did not complete in time")

// Activity polling bounds.
//
// AWS typically completes one of these jobs in a few seconds. The interval is
// short enough that the common case costs one or two polls, and the total wait
// is capped so one wedged job cannot consume a scan's whole budget -- an
// identity whose report times out is reported as unread, which the caller turns
// into incomplete coverage rather than "no activity".
const (
	activityPollInterval = 2 * time.Second
	activityPollTimeout  = 30 * time.Second
)

// ServiceActivity is one service's last-used date for one principal.
type ServiceActivity struct {
	// Service is the AWS namespace as AWS reports it: "s3", "dynamodb".
	Service string
	// LastUsedAt is nil when AWS reports the service was NEVER accessed in the
	// tracking window. That is a positive finding and the most actionable row
	// this surface produces -- it must not be coerced to a zero time, and an
	// identity whose report could not be read must produce no rows at all
	// rather than rows with nil dates.
	LastUsedAt *time.Time
	// GeneratedAt is when AWS produced the report, which can be meaningfully
	// older than the scan that read it.
	GeneratedAt *time.Time
	// AuthenticatedEntities is how many entities AWS saw using the service.
	AuthenticatedEntities int32
}

// ActivityReader reads service-last-accessed reports.
type ActivityReader struct {
	api ServiceLastAccessedAPI
	// sleep is the delay between polls, swappable so a test does not wait.
	sleep func(context.Context, time.Duration) error
}

// NewActivityReader constructs a reader over the given API.
func NewActivityReader(api ServiceLastAccessedAPI) *ActivityReader {
	return &ActivityReader{api: api, sleep: sleepCtx}
}

// WithSleep replaces the inter-poll delay. The seam that lets the polling loop
// be tested without a real wait.
func (r *ActivityReader) WithSleep(f func(context.Context, time.Duration) error) *ActivityReader {
	r.sleep = f
	return r
}

// ServiceActivityFor submits a report job for one principal ARN and polls until
// it completes.
//
// Returns every service AWS tracked for that principal, including the ones it
// reports as never accessed. An error means nothing was learned about this
// principal -- the caller must record no rows rather than an empty result, or a
// denied read would look identical to an identity that has used nothing.
func (r *ActivityReader) ServiceActivityFor(ctx context.Context, principalARN string) ([]ServiceActivity, error) {
	if r.api == nil {
		return nil, nil
	}
	if principalARN == "" {
		return nil, errors.New("service activity needs a principal arn")
	}

	// Every failure below names its call (withCallName), because coverage must say
	// WHICH call failed and with which AWS code (§2.14.13) -- the submit and
	// the poll fail for different reasons and are fixed in different places.
	submitted, err := r.api.GenerateServiceLastAccessedDetails(ctx,
		&iam.GenerateServiceLastAccessedDetailsInput{Arn: aws.String(principalARN)})
	if err != nil {
		return nil, withCallName("iam:GenerateServiceLastAccessedDetails", err)
	}
	jobID := aws.ToString(submitted.JobId)
	if jobID == "" {
		return nil, fmt.Errorf("%w: AWS accepted the request without returning a job id", ErrActivityJobFailed)
	}

	deadline := time.Now().Add(activityPollTimeout)
	for {
		out, err := r.api.GetServiceLastAccessedDetails(ctx,
			&iam.GetServiceLastAccessedDetailsInput{JobId: aws.String(jobID)})
		if err != nil {
			return nil, withCallName("iam:GetServiceLastAccessedDetails", err)
		}

		switch out.JobStatus {
		case iamtypes.JobStatusTypeCompleted:
			return r.drainReport(ctx, jobID, out)

		case iamtypes.JobStatusTypeFailed:
			// AWS's own reason, when it gave one, so an operator is not left
			// guessing at a job it cannot retry usefully.
			reason := ""
			if out.Error != nil {
				reason = aws.ToString(out.Error.Message)
			}
			return nil, fmt.Errorf("%w: %s", ErrActivityJobFailed, reason)

		case iamtypes.JobStatusTypeInProgress:
			// Fall through to the wait below.

		default:
			// An unknown status is not progress. Treat it as a failure rather
			// than polling forever against a value this build does not know.
			return nil, fmt.Errorf("%w: unexpected job status %q", ErrActivityJobFailed, out.JobStatus)
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%w: %s after %s", ErrActivityJobTimeout, jobID, activityPollTimeout)
		}
		if err := r.sleep(ctx, activityPollInterval); err != nil {
			return nil, err
		}
	}
}

// drainReport reads every page of a completed report.
//
// GetServiceLastAccessedDetails returns at most MaxItems entries -- default
// 100 -- and sets IsTruncated with a Marker when more remain. A role granted
// broad access (anything approaching "*" on "*") lists far more service
// namespaces than that, so a single page silently omits activity while the scan
// reports success. Stopping at page one understates usage, and understated
// usage is what an "unused access" finding is built on.
func (r *ActivityReader) drainReport(
	ctx context.Context, jobID string, first *iam.GetServiceLastAccessedDetailsOutput,
) ([]ServiceActivity, error) {
	activity := activityFromReport(first)

	out := first
	for page := 1; out.IsTruncated && out.Marker != nil; page++ {
		if page >= maxPages {
			return activity, fmt.Errorf("%w: service last accessed report", errTooManyPages)
		}
		next, err := r.api.GetServiceLastAccessedDetails(ctx,
			&iam.GetServiceLastAccessedDetailsInput{
				JobId:  aws.String(jobID),
				Marker: out.Marker,
			})
		if err != nil {
			// Partial activity with an error is better than silently returning
			// page one as though it were everything: the caller records the
			// surface as incomplete rather than complete-and-wrong.
			return activity, withCallName("iam:GetServiceLastAccessedDetails", err)
		}
		activity = append(activity, activityFromReport(next)...)
		out = next
	}
	return activity, nil
}

// activityFromReport normalises one page of a completed report.
func activityFromReport(out *iam.GetServiceLastAccessedDetailsOutput) []ServiceActivity {
	generated := out.JobCompletionDate
	if generated == nil {
		generated = out.JobCreationDate
	}

	activity := make([]ServiceActivity, 0, len(out.ServicesLastAccessed))
	for _, svc := range out.ServicesLastAccessed {
		namespace := aws.ToString(svc.ServiceNamespace)
		if namespace == "" {
			// Without a namespace there is nothing to key the row on. The
			// display name is not a stable identifier.
			continue
		}
		entry := ServiceActivity{
			Service: namespace,
			// nil stays nil: AWS omits the date for a service never accessed,
			// and that is the finding.
			LastUsedAt:  svc.LastAuthenticated,
			GeneratedAt: generated,
		}
		if svc.TotalAuthenticatedEntities != nil {
			entry.AuthenticatedEntities = *svc.TotalAuthenticatedEntities
		}
		// svc.TrackedActionsLastAccessed is deliberately not read -- see the
		// file header on why a mixed grain would misrepresent the data.
		activity = append(activity, entry)
	}
	return activity
}

// sleepCtx waits, but gives up the moment the scan's context is cancelled --
// the whole point of bounding a polling loop.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
