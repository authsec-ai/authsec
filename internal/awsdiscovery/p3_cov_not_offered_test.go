package awsdiscovery

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"syscall"
	"testing"

	"github.com/authsec-ai/authsec/internal/awsdiscovery/rpfake"
)

// Review P1-11: only AWS's documented "not offered in this region" answer is
// complete-with-nothing; every resolver or connection failure is a failed
// listing.

func nxdomain(host string) error {
	return &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// wrapped is the shape the SDK's HTTP client returns a dial failure in.
func wrapped(host string, err error) error {
	return &url.Error{Op: "Get", URL: "https://" + host + "/", Err: &net.OpError{Op: "dial", Net: "tcp", Err: err}}
}

func TestP3CovFormNotOfferedInRule(t *testing.T) {
	cases := []struct {
		name, form, region string
		err                error
		want               bool
	}{
		{"s3express NXDOMAIN in a region AWS documents it absent from", FormS3DirectoryBucket, "eu-west-2",
			nxdomain("s3express-control.eu-west-2.amazonaws.com"), true},
		{"same, wrapped as the SDK returns it", FormS3DirectoryBucket, "eu-west-2",
			wrapped("s3express-control.eu-west-2.amazonaws.com", nxdomain("s3express-control.eu-west-2.amazonaws.com")), true},
		{"same, fully qualified name", FormS3DirectoryBucket, "eu-west-2",
			nxdomain("s3express-control.eu-west-2.amazonaws.com."), true},
		{"s3express NXDOMAIN in a region the table does not name (added since, or never documented): failure",
			FormS3DirectoryBucket, "xx-new-1", nxdomain("s3express-control.xx-new-1.amazonaws.com"), false},
		{"China partition is not in the table: failure", FormS3DirectoryBucket, "cn-north-1",
			nxdomain("s3express-control.cn-north-1.amazonaws.com.cn"), false},
		{"s3express NXDOMAIN in a region AWS documents it in", FormS3DirectoryBucket, "eu-west-1",
			nxdomain("s3express-control.eu-west-1.amazonaws.com"), false},
		{"s3express NXDOMAIN in a documented region: resolver failure", FormS3DirectoryBucket, "us-east-1",
			nxdomain("s3express-control.us-east-1.amazonaws.com"), false},
		{"NXDOMAIN for another host (proxy, VPC endpoint)", FormS3DirectoryBucket, "eu-west-2",
			nxdomain("proxy.corp.example"), false},
		{"NXDOMAIN for another region's endpoint", FormS3DirectoryBucket, "eu-west-2",
			nxdomain("s3express-control.us-east-1.amazonaws.com"), false},
		{"DNS timeout", FormS3DirectoryBucket, "eu-west-2",
			&net.DNSError{Err: "i/o timeout", Name: "s3express-control.eu-west-2.amazonaws.com", IsTimeout: true}, false},
		{"temporary resolver failure", FormS3DirectoryBucket, "eu-west-2",
			&net.DNSError{Err: "server misbehaving", Name: "s3express-control.eu-west-2.amazonaws.com", IsNotFound: true, IsTemporary: true}, false},
		{"connection refused", FormS3DirectoryBucket, "eu-west-2",
			wrapped("s3express-control.eu-west-2.amazonaws.com", syscall.ECONNREFUSED), false},
		{"an AWS error", FormS3DirectoryBucket, "eu-west-2", rpfake.APIError("AccessDenied"), false},
		{"KMS is documented in every region: NXDOMAIN is a failure", FormKMSKey, "eu-west-1",
			nxdomain("kms.eu-west-1.amazonaws.com"), false},
		{"SQS likewise", FormSQSQueue, "ap-south-2", nxdomain("sqs.ap-south-2.amazonaws.com"), false},
		{"Lambda likewise", FormLambdaFunction, "eu-west-1", nxdomain("lambda.eu-west-1.amazonaws.com"), false},
		{"nil", FormS3DirectoryBucket, "eu-west-1", nil, false},
	}
	for _, c := range cases {
		if got := FormNotOfferedIn(c.form, c.region, c.err); got != c.want {
			t.Errorf("%s: FormNotOfferedIn = %v, want %v", c.name, got, c.want)
		}
	}
}

// Through the collector: each kind of failure on the first page of a form's
// listing, and the state and reason it records.
func TestP3CovResolverFailuresArePartial(t *testing.T) {
	timeout := &net.DNSError{Err: "i/o timeout", Name: "x", IsTimeout: true}
	cases := []struct {
		name, form, region, op string
		err                    error
		state, reason          string
	}{
		{"s3express not offered", FormS3DirectoryBucket, "eu-west-2", "ListDirectoryBuckets",
			nxdomain("s3express-control.eu-west-2.amazonaws.com"), CoverageComplete, "service not offered in eu-west-2"},
		{"s3express NXDOMAIN in a region the table does not name", FormS3DirectoryBucket, "eu-west-1", "ListDirectoryBuckets",
			nxdomain("s3express-control.eu-west-1.amazonaws.com"), CoveragePartial, "(DNSNameNotFound)"},
		{"s3express NXDOMAIN where AWS documents it", FormS3DirectoryBucket, "us-east-1", "ListDirectoryBuckets",
			wrapped("s3express-control.us-east-1.amazonaws.com", nxdomain("s3express-control.us-east-1.amazonaws.com")),
			CoveragePartial, "s3express:ListAllMyDirectoryBuckets failed (DNSNameNotFound)"},
		{"kms NXDOMAIN", FormKMSKey, "eu-west-1", "ListKeys",
			nxdomain("kms.eu-west-1.amazonaws.com"), CoveragePartial, "(DNSNameNotFound)"},
		{"sqs DNS timeout", FormSQSQueue, "eu-west-1", "ListQueues", timeout, CoveragePartial, "(DNSTimeout)"},
		{"secrets connection refused", FormSecretsManagerSecret, "eu-west-1", "ListSecrets",
			wrapped("secretsmanager.eu-west-1.amazonaws.com", syscall.ECONNREFUSED), CoveragePartial, "(ConnectionFailed)"},
		{"lambda NXDOMAIN: versions and aliases follow the function listing", FormLambdaAlias, "eu-west-1", "ListFunctions",
			nxdomain("lambda.eu-west-1.amazonaws.com"), CoveragePartial, "DNSNameNotFound"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := fullRegion(c.region)
			r.Errs = map[string]error{c.op: c.err}
			cov := byKey(fastCollector().Collect(context.Background(), CollectInput{AccountID: rpAcct,
				SelectedRegions: []string{c.region}, Clients: rpClients(map[string]*rpfake.Region{c.region: r})}))
			got := cov[c.form+"/"+c.region]
			if got.State != c.state || !strings.Contains(got.Reason, c.reason) {
				t.Fatalf("%s/%s = %s %q, want %s containing %q", c.form, c.region, got.State, got.Reason, c.state, c.reason)
			}
		})
	}
}

func TestP3CovResolverCode(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{nxdomain("a"), "DNSNameNotFound"},
		{&net.DNSError{IsTimeout: true}, "DNSTimeout"},
		{&net.DNSError{IsTemporary: true}, "DNSFailure"},
		{wrapped("h", syscall.ECONNRESET), "ConnectionFailed"},
		{errors.New("other"), ""},
		{rpfake.APIError("Throttling"), ""},
	} {
		if got := resolverCode(c.err); got != c.want {
			t.Errorf("resolverCode(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

// The same rule for every regional LISTING (review P1-11, second half): a name
// that does not resolve is "not offered" only for a service/region pair AWS
// documents as absent; every other resolver or connection failure is
// ErrEndpointUnreachable, never ErrServiceNotInRegion.
func TestP3CovListErrNeverInfersNotOfferedFromDNSAlone(t *testing.T) {
	cases := []struct {
		name, call string
		err        error
		notOffered bool
		code       string
	}{
		{"lambda NXDOMAIN: offered in every region", "lambda:ListFunctions",
			wrapped("lambda.eu-west-2.amazonaws.com", nxdomain("lambda.eu-west-2.amazonaws.com")), false, "DNSNameNotFound"},
		{"ecs NXDOMAIN", "ecs:ListTaskDefinitions", nxdomain("ecs.ap-south-2.amazonaws.com"), false, "DNSNameNotFound"},
		{"ec2 NXDOMAIN", "ec2:DescribeInstances", nxdomain("ec2.us-east-1.amazonaws.com"), false, "DNSNameNotFound"},
		{"eks NXDOMAIN", "eks:ListClusters", nxdomain("eks.eu-west-1.amazonaws.com"), false, "DNSNameNotFound"},
		{"bedrock agents, region AWS documents it in", "bedrock:ListAgents",
			nxdomain("bedrock-agent.us-east-1.amazonaws.com"), false, "DNSNameNotFound"},
		{"bedrock agents, region the table does not name", "bedrock:ListAgents",
			nxdomain("bedrock-agent.xx-new-1.amazonaws.com"), false, "DNSNameNotFound"},
		{"bedrock agents, documented absent region", "bedrock:ListAgents",
			wrapped("bedrock-agent.ap-south-2.amazonaws.com", nxdomain("bedrock-agent.ap-south-2.amazonaws.com")), true, ""},
		{"agentcore, documented absent region", "bedrock-agentcore:ListAgentRuntimes",
			nxdomain("bedrock-agentcore-control.il-central-1.amazonaws.com"), true, ""},
		{"agentcore, documented region", "bedrock-agentcore:ListAgentRuntimes",
			nxdomain("bedrock-agentcore-control.us-east-1.amazonaws.com"), false, "DNSNameNotFound"},
		{"documented absent region but a DNS timeout", "bedrock:ListAgents",
			&net.DNSError{Err: "i/o timeout", Name: "bedrock-agent.ap-south-2.amazonaws.com", IsTimeout: true}, false, "DNSTimeout"},
		{"connection refused", "lambda:ListFunctions",
			wrapped("lambda.us-east-1.amazonaws.com", syscall.ECONNREFUSED), false, "ConnectionFailed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := listErr(c.call, c.err)
			if got := errors.Is(err, ErrServiceNotInRegion); got != c.notOffered {
				t.Fatalf("ErrServiceNotInRegion = %v, want %v (%v)", got, c.notOffered, err)
			}
			if c.notOffered {
				return
			}
			if !errors.Is(err, ErrEndpointUnreachable) {
				t.Fatalf("want ErrEndpointUnreachable, got %v", err)
			}
			if CallName(err) != c.call || ErrorCode(err) != c.code || AWSErrorCode(err) != "" {
				t.Fatalf("call %q code %q aws %q, want %q %q and no AWS code", CallName(err), ErrorCode(err), AWSErrorCode(err), c.call, c.code)
			}
		})
	}
}
