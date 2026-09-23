package awsdiscovery

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/smithy-go"
)

// The regions ENABLED in the customer's account (SPEC-iga-phase2-graph.md
// §5.3, GET /authsec/discovery/aws/connectors/:id/regions; D-54).
//
// Region selection is validated against this list rather than against a
// hard-coded one: AWS launches regions, and opt-in regions (me-central-1,
// ap-south-2 ...) exist only in accounts that enabled them. A scan of a region
// the account has not enabled fails on every call, and that failure would read
// as a denial of the customer's own making.

// RegionsAPI is the slice of the EC2 client region listing uses. Separate from
// EC2API so the workload fakes need not grow a method they never serve.
type RegionsAPI interface {
	DescribeRegions(ctx context.Context, in *ec2.DescribeRegionsInput, opts ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
}

// NewRegionsClient builds a real EC2 client for DescribeRegions.
func NewRegionsClient(cfg aws.Config) RegionsAPI { return ec2.NewFromConfig(cfg) }

// Region is one enabled region, in AWS's own words.
type Region struct {
	Name string
	// OptInStatus is opt-in-not-required or opted-in for an enabled region.
	OptInStatus string
}

var (
	// ErrRegionsDenied means AWS refused ec2:DescribeRegions to the discovery
	// role. The role WAS assumed -- this is not ErrNotAssumable, whose remedy
	// (fix the trust policy or the ExternalId) would send the customer to the
	// wrong place. FailedCall on the error names the call and the code.
	ErrRegionsDenied = errors.New("AWS refused to list the account's regions to the discovery role")
	// ErrRegionsUnavailable is any other failure to list them.
	ErrRegionsUnavailable = errors.New("the account's regions could not be listed")
)

// regionDeniedCodes are the codes an authorization refusal of DescribeRegions
// carries: EC2 says UnauthorizedOperation; AccessDenied is what a layer in
// front of it answers with. Anything else (AuthFailure, OptInRequired ...) is
// NOT called a denial -- it is reported as unavailable, with AWS's code, so
// nothing claims a cause the response did not state.
var regionDeniedCodes = map[string]bool{
	"UnauthorizedOperation": true, "AccessDenied": true, "AccessDeniedException": true,
}

// EnabledRegions lists the regions enabled in the account, sorted by name.
//
// AllRegions=false: AWS then returns exactly the regions whose opt-in status
// is opt-in-not-required or opted-in -- enabled ones -- and a region the
// account has not opted in to is simply absent.
//
// Failures are classified so the caller can tell whose problem it is:
//   - the ASSUME failed underneath the call -> classify()'s ErrNotAssumable;
//   - DescribeRegions itself was refused     -> ErrRegionsDenied;
//   - throttled after retries                -> ErrThrottled;
//   - anything else                          -> ErrRegionsUnavailable.
//
// Every one keeps the SDK error in its chain, so FailedCall still reports the
// operation and the code.
func EnabledRegions(ctx context.Context, api RegionsAPI) ([]Region, error) {
	if api == nil {
		return nil, fmt.Errorf("%w: no EC2 client", ErrRegionsUnavailable)
	}
	out, err := api.DescribeRegions(ctx, &ec2.DescribeRegionsInput{AllRegions: aws.Bool(false)})
	if err != nil {
		return nil, classifyRegionsError(err)
	}
	regions := make([]Region, 0, len(out.Regions))
	seen := map[string]bool{}
	for _, r := range out.Regions {
		name := aws.ToString(r.RegionName)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		regions = append(regions, Region{Name: name, OptInStatus: aws.ToString(r.OptInStatus)})
	}
	sort.Slice(regions, func(i, j int) bool { return regions[i].Name < regions[j].Name })
	return regions, nil
}

func classifyRegionsError(err error) error {
	if assumeFailed(err) {
		// The credential provider assumes lazily, so a refused AssumeRole
		// arrives wrapped in the DescribeRegions operation. It is the
		// connection that is broken, not the region grant.
		return classify(err)
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch {
		case regionDeniedCodes[apiErr.ErrorCode()]:
			return &classifiedError{
				msg:      fmt.Sprintf("%v: %s (%s)", ErrRegionsDenied, apiErr.ErrorMessage(), apiErr.ErrorCode()),
				sentinel: ErrRegionsDenied, cause: err,
			}
		default:
			if c := classify(err); errors.Is(c, ErrThrottled) {
				return c
			}
		}
		return &classifiedError{
			msg:      fmt.Sprintf("%v: aws %s: %s", ErrRegionsUnavailable, apiErr.ErrorCode(), apiErr.ErrorMessage()),
			sentinel: ErrRegionsUnavailable, cause: err,
		}
	}
	return &classifiedError{
		msg:      fmt.Sprintf("%v: %v", ErrRegionsUnavailable, err),
		sentinel: ErrRegionsUnavailable, cause: err,
	}
}
