package awsdiscovery

import (
	"errors"
	"net"
	"strings"
)

// When is "nothing here" a complete answer? (review P1-11)
//
// A resource-policy form recorded complete with nothing in it licenses the
// first-attachment proof and "no route" (SPEC-iga-phase3-policy.md §3.4,
// §3.9). Before this rule, ANY name-not-found answer for the form's regional
// endpoint on the first page was read as "service not offered here" and so
// complete -- but a resolver that fails, a split-horizon or VPC DNS that does
// not forward amazonaws.com, a DNS firewall, or a proxy produces exactly the
// same NXDOMAIN for an endpoint that does exist.
//
// What AWS documents, and therefore what this rule uses:
//
//   - The SDK does not say. aws-sdk-go-v2's rules-based endpoint resolver
//     builds "<prefix>.<region>.<dnsSuffix>" for ANY region of a known
//     partition; it consults no per-service region list, so it returns no
//     endpoint-resolution error for a region the service is absent from.
//     Only DNS then answers, and DNS cannot tell "absent" from "unreachable".
//   - AWS publishes, per service, the regions it is offered in: the service's
//     "endpoints and quotas" page of the AWS General Reference and the "AWS
//     Services by Region" list (also queryable as the Systems Manager public
//     parameters /aws/service/global-infrastructure/services/<svc>/regions).
//
// The rule: a form's listing failing is "not offered in this region" -- and
// the form complete with nothing -- ONLY when BOTH
//
//  1. the failure is a definitive DNS name-not-found (net.DNSError with
//     IsNotFound, and not a timeout or a temporary failure) for EXACTLY the
//     regional endpoint host the SDK addresses for that form in that region,
//     and
//  2. the region is NOT among the regions AWS documents the form's service
//     in (regionLimitedForms).
//
// Every other failure -- NXDOMAIN on the endpoint of a service AWS documents
// in that region (every service of a form not in regionLimitedForms is
// documented in every commercial, GovCloud and China region its partition
// has: S3 and S3 Control, KMS, SQS, SNS, Lambda, Secrets Manager), NXDOMAIN
// for any other host, a DNS timeout, a temporary resolver failure, a refused
// or reset connection -- is a failed listing, so the form is partial and
// names the failure (resolverCode). A stale table can only err safely: a
// region AWS has since added resolves, so condition 1 never holds there; a
// region listed here that AWS does not serve stays partial (noisy, never a
// false complete).
//
// DECISION (P1-11a). The documented-region table is kept for the one
// collected form whose service AWS offers in a subset of regions: S3 Express
// One Zone directory buckets (the s3express-control endpoint; AWS S3 user
// guide, "S3 Express One Zone Availability Zones and Regions"). Maintain it
// with that page; a region missing here only lets condition 1 decide there,
// which is the behaviour before this rule.
type regionLimitedForm struct {
	// endpointPrefix is the first label of the regional endpoint host the
	// form's list call addresses.
	endpointPrefix string
	// documented are the regions AWS documents the service in.
	documented map[string]bool
}

var regionLimitedForms = map[string]regionLimitedForm{
	FormS3DirectoryBucket: {endpointPrefix: "s3express-control", documented: setOf(
		"us-east-1", "us-west-2", "ap-northeast-1", "ap-south-1", "eu-north-1")},
}

func setOf(vs ...string) map[string]bool {
	out := make(map[string]bool, len(vs))
	for _, v := range vs {
		out[v] = true
	}
	return out
}

// awsDNSSuffixes are the partitions' endpoint DNS suffixes (aws, aws-us-gov:
// amazonaws.com; aws-cn: amazonaws.com.cn).
var awsDNSSuffixes = []string{"amazonaws.com", "amazonaws.com.cn"}

// FormNotOfferedIn reports whether err, from the first page of form's
// listing in region, is AWS's "this service is not offered in this region"
// (see the rule above). Exported for the tests that pin it.
func FormNotOfferedIn(form, region string, err error) bool {
	lim, ok := regionLimitedForms[form]
	if !ok || lim.documented[region] || region == "" {
		return false
	}
	var dns *net.DNSError
	if !errors.As(err, &dns) || !dns.IsNotFound || dns.IsTimeout || dns.IsTemporary {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(dns.Name), ".")
	for _, suffix := range awsDNSSuffixes {
		if host == lim.endpointPrefix+"."+region+"."+suffix {
			return true
		}
	}
	return false
}

// resolverCode is the stable code of a failure that reached no AWS service
// (so carries no AWS error code): the coverage reason names it instead of
// "UnknownError", so a resolver failure is never mistaken for an AWS answer.
// "" when err is not a resolver or connection failure.
func resolverCode(err error) string {
	var dns *net.DNSError
	if errors.As(err, &dns) {
		switch {
		case dns.IsTimeout:
			return "DNSTimeout"
		case dns.IsNotFound:
			return "DNSNameNotFound"
		default:
			return "DNSFailure"
		}
	}
	var op *net.OpError
	if errors.As(err, &op) {
		if op.Timeout() {
			return "ConnectionTimeout"
		}
		return "ConnectionFailed"
	}
	return ""
}
