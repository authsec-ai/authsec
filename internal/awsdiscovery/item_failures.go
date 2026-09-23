package awsdiscovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/aws/smithy-go"
)

// Collection honesty (SPEC-iga-phase2-graph.md §1.3, §1.4, T3.6-T3.8).
//
// Two answers every reader here used to give silently, and which the coverage
// report must now carry instead:
//
//   - A LISTING succeeded but some items could not be read in full -- a detail
//     call per item (GetAgent, DescribeTaskDefinition, GetInstanceProfile,
//     GetAgentRuntime, GetGateway) or a per-item read (one identity's
//     service-last-accessed report, one bucket's policy). The rows returned are
//     real; the set is not known to be whole. That is `partial`, and partial
//     blocks deletion (§1.4). Reported as *ItemFailures.
//
//   - The service is not offered in the region at all. That is `unsupported`,
//     which blocks nothing because nothing there is claimed (§1.4). Reported as
//     ErrServiceNotInRegion.
//
// Both are returned as the reader's ERROR, beside whatever rows were read, so
// no caller can mistake either for a clean read.

// ErrServiceNotInRegion means the service's regional endpoint does not exist:
// the name does not resolve (NXDOMAIN). AWS publishes an endpoint for every
// region a service is offered in, so a regional endpoint that does not resolve
// is the one unambiguous, table-free signal that the service is not offered
// there. A static service/region table is the alternative and goes stale for
// the same reason onboarding.go refuses a region allow-list.
//
// Deliberately NOT inferred from AccessDenied or InvalidClientTokenId: an SCP
// or a region opt-out produces those too (§2.14.13), and a false "unsupported"
// is a state that licenses deletion.
var ErrServiceNotInRegion = errors.New("the service is not offered in this region")

// listErr classifies the error of a LIST call against a regional endpoint: an
// endpoint that does not resolve is ErrServiceNotInRegion; anything else is
// classify()'d exactly as before (ErrThrottled stays ErrThrottled, so the
// state an ordinary denial or throttle maps to does not change). Either way
// the call is NAMED, so coverage can stamp which call failed and AWS's own
// code for it as fields (D-71: api, error_code) instead of anyone parsing
// them back out of the Error text.
//
// The SDK does not retry a not-found DNS answer (aws/retry retryable_error.go),
// so this surfaces on the first attempt rather than after the retry budget.
func listErr(call string, err error) error {
	if err == nil {
		return nil
	}
	var dns *net.DNSError
	if errors.As(err, &dns) && dns.IsNotFound {
		return &namedCallError{call: call, raw: err,
			classified: fmt.Errorf("%w: %s does not resolve", ErrServiceNotInRegion, dns.Name)}
	}
	return withCallName(call, err)
}

// namedCallError keeps BOTH halves of a failed call: the classified sentinel
// (ErrThrottled, ErrNotAssumable, ErrServiceNotInRegion -- what errors.Is
// asks) and the raw SDK error (the AWS error code -- what coverage must name,
// §2.14.13). classify() alone keeps only the first, so "which call, which
// code" was unrecoverable.
type namedCallError struct {
	call       string
	raw        error
	classified error
}

func (e *namedCallError) Error() string   { return e.call + ": " + e.classified.Error() }
func (e *namedCallError) Unwrap() []error { return []error{e.classified, e.raw} }

// withCallName names the AWS call that failed. Nil stays nil, and an error
// that already names its call keeps the name it has.
func withCallName(call string, err error) error {
	if err == nil {
		return nil
	}
	var already *namedCallError
	if errors.As(err, &already) {
		return err
	}
	return &namedCallError{call: call, raw: err, classified: classify(err)}
}

// ErrorCode is the AWS error code of a failed call ("AccessDeniedException",
// "ThrottlingException"), for coverage text and for the stable detail_error
// fact. Never the message: messages carry request ids, which would make an
// unchanged failure look like a changed fact on every scan.
//
// Errors that are not AWS API errors get a fixed label of their own, so the
// value is always short and stable.
func ErrorCode(err error) string {
	if err == nil {
		return ""
	}
	var apiErr smithy.APIError
	switch {
	case errors.As(err, &apiErr) && apiErr.ErrorCode() != "":
		return apiErr.ErrorCode()
	case errors.Is(err, ErrServiceNotInRegion):
		return "ServiceNotInRegion"
	case errors.Is(err, ErrActivityJobFailed):
		return "JobFailed"
	case errors.Is(err, ErrActivityJobTimeout):
		return "JobTimeout"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "RequestTimeout"
	case errors.Is(err, ErrThrottled):
		return "Throttling"
	case errors.Is(err, ErrNotAssumable):
		return "AccessDenied"
	}
	return "UnknownError"
}

// AWSErrorCode is the error code AWS itself returned, or "" when the failure
// carried none (a DNS failure, a timeout, a job AWS reported FAILED). Unlike
// ErrorCode it never substitutes a label of ours: it is what coverage stores
// as error_code, "exactly as the SDK reported it" (D-71).
func AWSErrorCode(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	return ""
}

// CallFailure is one AWS call's share of an ItemFailures report.
type CallFailure struct {
	// Call is the AWS action, "bedrock:GetAgent".
	Call string
	// Failed is how many items this call failed for.
	Failed int
	// Code is the first failure's error code (ErrorCode: AWS's own, else a
	// fixed label of ours), for the coverage text.
	Code string
	// AWSCode is the first failure's AWS error code exactly as the SDK
	// reported it, "" when there was none (AWSErrorCode) -- what coverage
	// stores as error_code.
	AWSCode string
}

// ItemFailures reports a read whose listing succeeded but some of whose items
// could not be read in full. See the file header.
type ItemFailures struct {
	// What completes "N of M ...": "agents could not be read in detail".
	What string
	// Detail is true when the failed calls are DETAIL calls behind a listing
	// that succeeded (§1.4: "a failed detail call makes its surface partial").
	// False for a per-item surface -- Access Advisor, resource policies --
	// where every item is its own read and a throttle or a total failure is
	// reported as such (§1.3: "throttled on throttle").
	Detail bool

	// Total is how many items were attempted; Failed how many had at least one
	// failed call; Throttled how many of those failed on a throttle.
	Total     int
	Failed    int
	Throttled int
	// Calls is one entry per failing AWS call, in the order first seen.
	Calls []CallFailure

	failedItems map[string]bool
	throttled   map[string]bool
}

// NewItemFailures starts a tally.
func NewItemFailures(what string, detail bool) *ItemFailures {
	return &ItemFailures{What: what, Detail: detail,
		failedItems: map[string]bool{}, throttled: map[string]bool{}}
}

// Attempt counts one item read.
func (f *ItemFailures) Attempt() { f.Total++ }

// Fail records that `call` failed for `item`. An item that fails two calls (a
// gateway's GetGateway and ListGatewayTargets) counts once in Failed and once
// under each call.
func (f *ItemFailures) Fail(item, call string, err error) {
	if !f.failedItems[item] {
		f.failedItems[item] = true
		f.Failed++
	}
	if errors.Is(err, ErrThrottled) || errors.Is(classify(err), ErrThrottled) {
		if !f.throttled[item] {
			f.throttled[item] = true
			f.Throttled++
		}
	}
	for i := range f.Calls {
		if f.Calls[i].Call == call {
			f.Calls[i].Failed++
			return
		}
	}
	f.Calls = append(f.Calls, CallFailure{Call: call, Failed: 1, Code: ErrorCode(err), AWSCode: AWSErrorCode(err)})
}

// Merge adds another reader's tally to this one, so a surface read by many
// readers -- eks_pod_identity is one EKS reader per region, one association
// listing per cluster -- reports EVERY failure it had, not only its first
// reader's: "the report names how many" (§1.4). Items are counted as distinct
// (a cluster name is unique only within its region), and a call's first code
// is the first one seen across the merged tallies. A nil tally adds nothing.
func (f *ItemFailures) Merge(o *ItemFailures) {
	if o == nil {
		return
	}
	f.Total += o.Total
	f.Failed += o.Failed
	f.Throttled += o.Throttled
next:
	for _, oc := range o.Calls {
		for i := range f.Calls {
			if f.Calls[i].Call == oc.Call {
				f.Calls[i].Failed += oc.Failed
				continue next
			}
		}
		f.Calls = append(f.Calls, oc)
	}
}

// Error names how many items failed, and which calls with which codes:
// "2 of 7 agents could not be read in detail: bedrock:GetAgent AccessDeniedException".
// §2.14.13: name the call and the code, never a guessed permission.
func (f *ItemFailures) Error() string {
	calls := make([]string, 0, len(f.Calls))
	for _, c := range f.Calls {
		s := c.Call + " " + c.Code
		if len(f.Calls) > 1 || c.Failed != f.Failed {
			s += fmt.Sprintf(" (%d)", c.Failed)
		}
		calls = append(calls, s)
	}
	return fmt.Sprintf("%d of %d %s: %s", f.Failed, f.Total, f.What, strings.Join(calls, "; "))
}

// Err is the reader's error: the LISTING error when there is one (it is the
// larger failure, and the scanner reports it as denied or throttled); else
// this tally when any item failed; else nil.
func (f *ItemFailures) Err(listing error) error {
	if listing != nil {
		return listing
	}
	if f == nil || f.Failed == 0 {
		return nil
	}
	return f
}

// DetailErrorOf is the stable, hashable description of why ONE item's detail
// could not be read: "bedrock:GetAgent AccessDeniedException". Stored on the
// row and in its evidence, so it must not carry a message or a request id.
func DetailErrorOf(call string, err error) string {
	return call + " " + ErrorCode(err)
}

// CallName is the AWS call a reader named on its error ("" when it named
// none), so a caller tallying per-item failures (T3.7) can attribute each one
// to the call that produced it without re-deriving it.
func CallName(err error) string {
	var ce *namedCallError
	if errors.As(err, &ce) {
		return ce.call
	}
	return ""
}
