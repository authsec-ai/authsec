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
		{"s3express NXDOMAIN outside its documented regions", FormS3DirectoryBucket, "eu-west-1",
			nxdomain("s3express-control.eu-west-1.amazonaws.com"), true},
		{"same, wrapped as the SDK returns it", FormS3DirectoryBucket, "eu-west-1",
			wrapped("s3express-control.eu-west-1.amazonaws.com", nxdomain("s3express-control.eu-west-1.amazonaws.com")), true},
		{"same, fully qualified name", FormS3DirectoryBucket, "eu-west-1",
			nxdomain("s3express-control.eu-west-1.amazonaws.com."), true},
		{"China partition suffix", FormS3DirectoryBucket, "cn-north-1",
			nxdomain("s3express-control.cn-north-1.amazonaws.com.cn"), true},
		{"s3express NXDOMAIN in a documented region: resolver failure", FormS3DirectoryBucket, "us-east-1",
			nxdomain("s3express-control.us-east-1.amazonaws.com"), false},
		{"NXDOMAIN for another host (proxy, VPC endpoint)", FormS3DirectoryBucket, "eu-west-1",
			nxdomain("proxy.corp.example"), false},
		{"NXDOMAIN for another region's endpoint", FormS3DirectoryBucket, "eu-west-1",
			nxdomain("s3express-control.us-east-1.amazonaws.com"), false},
		{"DNS timeout", FormS3DirectoryBucket, "eu-west-1",
			&net.DNSError{Err: "i/o timeout", Name: "s3express-control.eu-west-1.amazonaws.com", IsTimeout: true}, false},
		{"temporary resolver failure", FormS3DirectoryBucket, "eu-west-1",
			&net.DNSError{Err: "server misbehaving", Name: "s3express-control.eu-west-1.amazonaws.com", IsNotFound: true, IsTemporary: true}, false},
		{"connection refused", FormS3DirectoryBucket, "eu-west-1",
			wrapped("s3express-control.eu-west-1.amazonaws.com", syscall.ECONNREFUSED), false},
		{"an AWS error", FormS3DirectoryBucket, "eu-west-1", rpfake.APIError("AccessDenied"), false},
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
		{"s3express not offered", FormS3DirectoryBucket, "eu-west-1", "ListDirectoryBuckets",
			nxdomain("s3express-control.eu-west-1.amazonaws.com"), CoverageComplete, "service not offered in eu-west-1"},
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
