package awsdiscovery

import (
	"errors"
	"net"
	"strings"
)

// When is "nothing here" a complete answer? (review P1-11, and the same rule
// for every regional LISTING: Lambda, ECS, EC2, EKS, Bedrock, AgentCore)
//
// A listing recorded complete or "unsupported" with nothing in it licenses the
// first-attachment proof, "no route" and the deletion of what an earlier scan
// found (SPEC-iga-phase3-policy.md §3.4, §3.9). ANY name-not-found answer for a
// regional endpoint used to be read as "service not offered here" -- but a
// resolver that fails, a split-horizon or VPC DNS that does not forward
// amazonaws.com, a DNS firewall, or a proxy produces exactly the same NXDOMAIN
// for an endpoint that does exist. DNS cannot tell "absent" from
// "unreachable"; only AWS's own documentation can.
//
// What AWS documents, and therefore what this rule uses:
//
//   - The SDK does not say. aws-sdk-go-v2's rules-based endpoint resolver
//     builds "<prefix>.<region>.<dnsSuffix>" for ANY region of a known
//     partition; it consults no per-service region list.
//   - AWS publishes, per service, the regions it is offered in: the service's
//     "endpoints and quotas" page of the AWS General Reference, and for S3
//     Express One Zone the S3 user guide's directory-bucket networking page.
//
// The rule: a listing's failure is "not offered in this region" ONLY when
// BOTH
//
//  1. the failure is a definitive DNS name-not-found (net.DNSError with
//     IsNotFound, and not a timeout or a temporary failure) for EXACTLY the
//     regional endpoint host "<prefix>.<region>.<suffix>" of a service in
//     regionLimitedEndpoints, and
//  2. that region is EXPLICITLY listed as one AWS documents the service as
//     absent from (documentedAbsent).
//
// Everything else -- NXDOMAIN on a service AWS documents in that region,
// NXDOMAIN in a region the table does not name (including a region AWS added
// after the table was written: a stale table can only err towards "failed"),
// NXDOMAIN for any other host, a DNS timeout, a temporary resolver failure, a
// refused or reset connection -- is a failed listing, so the surface is
// partial and names the failure (resolverCode). A service AWS offers in every
// region of its partition (Lambda, ECS, EC2, EKS, KMS, SQS, SNS, Secrets
// Manager, S3, S3 Control) has no entry here, so a name that does not resolve
// is never "not offered" for it.
//
// MAINTENANCE. documentedAbsent[prefix] is the aws partition's regions (as of
// 2026-10-11) minus the regions the page cited above lists the service's
// endpoint in on that date. Re-derive it from the page when AWS adds regions:
// a region listed here that AWS has since added resolves, so condition 1 never
// holds there except under a resolver failure, which is the residual (narrow)
// risk of any table. The GovCloud and China partitions are deliberately not
// listed: they stay "failed" until someone documents them.
type regionLimitedService struct {
	// documentedAbsent are the regions AWS documents the service as absent from.
	documentedAbsent map[string]bool
}

// regionLimitedEndpoints is keyed by the first label of the regional endpoint
// host the SDK addresses.
var regionLimitedEndpoints = map[string]regionLimitedService{
	// S3 Express One Zone directory buckets (the FormS3DirectoryBucket listing).
	"s3express-control": {documentedAbsent: setOf(
		"af-south-1", "ap-east-1", "ap-east-2", "ap-northeast-3", "ap-south-2", "ap-southeast-3",
		"ap-southeast-4", "ap-southeast-5", "ap-southeast-6", "ap-southeast-7", "ca-west-1",
		"eu-central-2", "eu-south-1", "eu-south-2", "eu-west-2", "il-central-1", "me-central-1",
		"me-south-1", "mx-central-1")},
	// Agents for Amazon Bedrock (bedrock:ListAgents).
	"bedrock-agent": {documentedAbsent: setOf(
		"af-south-1", "ap-east-1", "ap-east-2", "ap-northeast-3", "ap-south-2", "ap-southeast-3",
		"ap-southeast-4", "ap-southeast-5", "ap-southeast-6", "ap-southeast-7", "ca-west-1",
		"eu-central-2", "eu-north-1", "eu-south-1", "eu-south-2", "il-central-1", "me-central-1",
		"me-south-1", "mx-central-1", "us-east-2", "us-west-1")},
	// Amazon Bedrock AgentCore control plane (every bedrock-agentcore:List* the
	// reader makes). Absent only where neither the control-plane nor the
	// data-plane endpoint is documented.
	"bedrock-agentcore-control": {documentedAbsent: setOf(
		"af-south-1", "ap-east-1", "ap-east-2", "ap-northeast-3", "ap-southeast-3", "ap-southeast-4",
		"ap-southeast-6", "ca-west-1", "eu-central-2", "il-central-1", "me-central-1", "me-south-1",
		"mx-central-1")},
}

// formEndpointPrefix is the regional endpoint prefix of each resource-policy
// form whose service is in regionLimitedEndpoints.
var formEndpointPrefix = map[string]string{
	FormS3DirectoryBucket: "s3express-control",
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

// notOfferedEndpoint returns the service prefix and region of err's
// name-not-found host when that service/region pair is one AWS documents as
// absent (the rule above); ok is false for every other failure.
func notOfferedEndpoint(err error) (prefix, region string, ok bool) {
	var dns *net.DNSError
	if !errors.As(err, &dns) || !dns.IsNotFound || dns.IsTimeout || dns.IsTemporary {
		return "", "", false
	}
	host := strings.TrimSuffix(strings.ToLower(dns.Name), ".")
	for _, suffix := range awsDNSSuffixes {
		rest, found := strings.CutSuffix(host, "."+suffix)
		if !found {
			continue
		}
		prefix, region, found = strings.Cut(rest, ".")
		if !found || strings.Contains(region, ".") {
			continue
		}
		if lim, limited := regionLimitedEndpoints[prefix]; limited && lim.documentedAbsent[region] {
			return prefix, region, true
		}
	}
	return "", "", false
}

// EndpointNotOffered reports whether err is AWS's documented "this service is
// not offered in this region" answer (see the rule above). The service and
// region are read from the host the resolver was asked for, so a listing needs
// no region argument. Exported for the tests that pin it.
func EndpointNotOffered(err error) bool {
	_, _, ok := notOfferedEndpoint(err)
	return ok
}

// FormNotOfferedIn is EndpointNotOffered for the first page of form's listing
// in region: the host the error names must also be that form's endpoint in
// that region. Exported for the tests that pin it.
func FormNotOfferedIn(form, region string, err error) bool {
	prefix, region2, ok := notOfferedEndpoint(err)
	return ok && region != "" && region2 == region && formEndpointPrefix[form] == prefix
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
