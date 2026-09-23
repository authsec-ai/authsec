package awsdiscovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagent"
	bedrockagenttypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	"github.com/aws/smithy-go"
)

// Pure logic behind T3.6-T3.8: the per-item failure tally, the stable error
// code, the NXDOMAIN classification and the one workload-ARN constructor.

func s3bAPIErr(code string) error {
	return &smithy.GenericAPIError{Code: code, Message: "request 1b2c3d-4e5f: " + code}
}

func TestS3bItemFailuresCountsItemsOnceAndNamesEachCall(t *testing.T) {
	f := NewItemFailures("gateways could not be read in detail", true)
	for i := 0; i < 3; i++ {
		f.Attempt()
	}
	if f.Err(nil) != nil {
		t.Fatal("a tally with no failure must not be an error (typed nil would read as a failure)")
	}
	f.Fail("gw-1", "bedrock-agentcore:GetGateway", s3bAPIErr("AccessDeniedException"))
	f.Fail("gw-1", "bedrock-agentcore:ListGatewayTargets", s3bAPIErr("ThrottlingException"))
	f.Fail("gw-2", "bedrock-agentcore:GetGateway", s3bAPIErr("AccessDeniedException"))

	if f.Total != 3 || f.Failed != 2 || f.Throttled != 1 {
		t.Fatalf("total/failed/throttled = %d/%d/%d, want 3/2/1 (an item failing two calls counts once)",
			f.Total, f.Failed, f.Throttled)
	}
	want := "2 of 3 gateways could not be read in detail: bedrock-agentcore:GetGateway AccessDeniedException (2); " +
		"bedrock-agentcore:ListGatewayTargets ThrottlingException (1)"
	if f.Error() != want {
		t.Fatalf("Error() = %q\nwant      %q", f.Error(), want)
	}
	if f.Calls[0].AWSCode != "AccessDeniedException" || f.Calls[1].AWSCode != "ThrottlingException" {
		t.Fatalf("per-call AWS codes = %+v, want AWS's own codes for coverage's error_code", f.Calls)
	}
	var got *ItemFailures
	if err := f.Err(nil); !errors.As(err, &got) || got != f {
		t.Fatal("Err must return the tally itself when an item failed")
	}
	listing := errors.New("listing denied")
	if f.Err(listing) != listing {
		t.Fatal("a listing failure is the larger one and must win")
	}
}

// The code is stable across retries: never the message, which carries a
// request id and would make an unchanged failure hash as a changed fact.
func TestS3bErrorCodeIsStable(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{s3bAPIErr("AccessDeniedException"), "AccessDeniedException"},
		{withCallName("bedrock:GetAgent", s3bAPIErr("AccessDenied")), "AccessDenied"},
		{fmt.Errorf("wrapped: %w", ErrActivityJobFailed), "JobFailed"},
		{context.DeadlineExceeded, "RequestTimeout"},
		{errors.New("something else"), "UnknownError"},
	} {
		if got := ErrorCode(tc.err); got != tc.want {
			t.Errorf("ErrorCode(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
	if got := DetailErrorOf("ecs:DescribeTaskDefinition", s3bAPIErr("AccessDenied")); got != "ecs:DescribeTaskDefinition AccessDenied" {
		t.Fatalf("DetailErrorOf = %q", got)
	}
}

// withCallName keeps both halves: errors.Is sees the classified sentinel, and
// the raw AWS code survives for coverage.
func TestS3bCallNameKeepsSentinelAndCode(t *testing.T) {
	err := withCallName("iam:GenerateServiceLastAccessedDetails", s3bAPIErr("ThrottlingException"))
	if !errors.Is(err, ErrThrottled) {
		t.Fatal("a throttle must still be ErrThrottled")
	}
	if ErrorCode(err) != "ThrottlingException" || AWSErrorCode(err) != "ThrottlingException" ||
		CallName(err) != "iam:GenerateServiceLastAccessedDetails" {
		t.Fatalf("code %q, aws code %q, call %q", ErrorCode(err), AWSErrorCode(err), CallName(err))
	}
	// error_code is AWS's own word or nothing -- never one of our labels.
	if got := AWSErrorCode(fmt.Errorf("wrapped: %w", ErrActivityJobFailed)); got != "" {
		t.Fatalf("AWSErrorCode of a job failure = %q, want \"\" (AWS returned no code)", got)
	}
	if !strings.HasPrefix(err.Error(), "iam:GenerateServiceLastAccessedDetails: ") {
		t.Fatalf("the error must name its call: %q", err)
	}
}

// NXDOMAIN on a regional endpoint -- and only that -- is "not offered here".
func TestS3bListErrMapsOnlyNXDOMAINToNotInRegion(t *testing.T) {
	nx := &url.Error{Op: "Post", URL: "https://bedrock-agent.ap-south-2.amazonaws.com/", Err: &net.OpError{
		Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "bedrock-agent.ap-south-2.amazonaws.com", IsNotFound: true}}}
	if err := listErr("bedrock:ListAgents", nx); !errors.Is(err, ErrServiceNotInRegion) ||
		!strings.Contains(err.Error(), "does not resolve") || CallName(err) != "bedrock:ListAgents" || AWSErrorCode(err) != "" {
		t.Fatalf("NXDOMAIN = %v (call %q), want ErrServiceNotInRegion naming the list call, with no AWS code", err, CallName(err))
	}
	timeout := &net.DNSError{Err: "i/o timeout", Name: "lambda.us-east-1.amazonaws.com", IsTimeout: true}
	if errors.Is(listErr("lambda:ListFunctions", timeout), ErrServiceNotInRegion) {
		t.Fatal("a DNS timeout is not proof the service is absent")
	}
	for _, code := range []string{"AccessDenied", "AccessDeniedException", "InvalidClientTokenId", "UnrecognizedClientException"} {
		if errors.Is(listErr("lambda:ListFunctions", s3bAPIErr(code)), ErrServiceNotInRegion) {
			t.Fatalf("%s must never read as not offered: an SCP or a region opt-out produces it too", code)
		}
	}
}

func TestS3bWorkloadARNIsBuiltInThePartitionAndNeverGuesses(t *testing.T) {
	for _, tc := range []struct {
		partition, kind, region, account, id, want string
	}{
		{"", "bedrock_agent", "us-east-1", "111122223333", "A1", "arn:aws:bedrock:us-east-1:111122223333:agent/A1"},
		{"aws-us-gov", "bedrock_agentcore_gateway", "us-gov-west-1", "111122223333", "gw-1",
			"arn:aws-us-gov:bedrock-agentcore:us-gov-west-1:111122223333:gateway/gw-1"},
		{"aws-cn", "ec2_instance", "cn-north-1", "111122223333", "i-1", "arn:aws-cn:ec2:cn-north-1:111122223333:instance/i-1"},
		{"aws", "bedrock_agent", "us-east-1", "111122223333", "arn:aws:bedrock:us-east-1:9:agent/A1", "arn:aws:bedrock:us-east-1:9:agent/A1"},
		{"aws", "bedrock_agent", "us-east-1", "", "A1", "A1"},    // no account: never guessed
		{"aws", "bedrock_agent", "", "111122223333", "A1", "A1"}, // no region either
		{"aws", "lambda_function", "us-east-1", "111122223333", "fn", "fn"},
	} {
		if got := WorkloadARN(tc.partition, tc.kind, tc.region, tc.account, tc.id); got != tc.want {
			t.Errorf("WorkloadARN(%q,%q,%q,%q,%q) = %q, want %q", tc.partition, tc.kind, tc.region, tc.account, tc.id, got, tc.want)
		}
	}
}

// s3bAgents is a Bedrock agent API whose GetAgent can fail.
type s3bAgents struct {
	arn     string
	getFail error
}

func (f *s3bAgents) ListAgents(context.Context, *bedrockagent.ListAgentsInput, ...func(*bedrockagent.Options)) (*bedrockagent.ListAgentsOutput, error) {
	return &bedrockagent.ListAgentsOutput{AgentSummaries: []bedrockagenttypes.AgentSummary{{
		AgentId: aws.String("AGENT1"), AgentName: aws.String("bot"), AgentStatus: bedrockagenttypes.AgentStatusPrepared,
	}}}, nil
}

func (f *s3bAgents) GetAgent(context.Context, *bedrockagent.GetAgentInput, ...func(*bedrockagent.Options)) (*bedrockagent.GetAgentOutput, error) {
	if f.getFail != nil {
		return nil, f.getFail
	}
	return &bedrockagent.GetAgentOutput{Agent: &bedrockagenttypes.Agent{
		AgentId: aws.String("AGENT1"), AgentArn: aws.String(f.arn), AgentResourceRoleArn: aws.String("arn:aws:iam::111122223333:role/r"),
	}}, nil
}

// The key a failed GetAgent constructs is byte-for-byte the ARN a successful
// one returns, so the object's key cannot move (§1.3, E7).
func TestS3bFailedGetAgentKeysByTheSameARN(t *testing.T) {
	const arn = "arn:aws:bedrock:eu-west-1:111122223333:agent/AGENT1"
	read := func(api *s3bAgents) (Workload, error) {
		out, err := NewBedrockReader(api, nil).WithScope("aws", "eu-west-1", "111122223333").Agents(context.Background())
		if len(out) != 1 {
			t.Fatalf("agents read = %d, want 1 (a listed agent is kept either way)", len(out))
		}
		return out[0], err
	}
	ok, err := read(&s3bAgents{arn: arn})
	if err != nil || ok.NativeID != arn || ok.DetailIncomplete || ok.SourceAPI != "bedrock:GetAgent" {
		t.Fatalf("clean read = %+v, %v", ok, err)
	}
	failed, err := read(&s3bAgents{arn: arn, getFail: s3bAPIErr("AccessDeniedException")})
	var items *ItemFailures
	if !errors.As(err, &items) || !items.Detail || items.Failed != 1 || items.Total != 1 {
		t.Fatalf("a failed GetAgent must be reported as a detail failure, got %v", err)
	}
	if failed.NativeID != ok.NativeID {
		t.Fatalf("failed GetAgent keyed %q, clean read %q: the key moved", failed.NativeID, ok.NativeID)
	}
	if !failed.DetailIncomplete || failed.RoleARN != "" || failed.Status != "PREPARED" ||
		failed.SourceAPI != "bedrock:ListAgents" || failed.DetailError != "bedrock:GetAgent AccessDeniedException" {
		t.Fatalf("failed GetAgent row = %+v", failed)
	}
}
