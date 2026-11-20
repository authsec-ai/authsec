package services

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsbroker"
)

func reviewTestNow() time.Time { return time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC) }

type fakeReviewSTS struct {
	in  *sts.AssumeRoleInput
	out *sts.AssumeRoleOutput
	err error
}

func (f *fakeReviewSTS) AssumeRole(_ context.Context, in *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.in = in
	return f.out, f.err
}

func reviewKeys(f *fakeReviewSTS) *AgentReviewKeys {
	return (&AgentReviewKeys{}).WithSTS(func(context.Context, string) (awsbroker.STSAPI, error) { return f, nil })
}

func TestAgentReviewAssumeNarrowsTheSession(t *testing.T) {
	exp := reviewTestNow().Add(time.Hour)
	f := &fakeReviewSTS{out: &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("ASIA1"), SecretAccessKey: aws.String("s"), SessionToken: aws.String("t"),
		Expiration: aws.Time(exp)}}}
	conn := uuid.MustParse("11111111-2222-3333-4444-555555555555")

	creds, err := reviewKeys(f).assume(context.Background(), "arn:aws:iam::1:role/Discovery", "ext-1", "us-east-1", conn)
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(f.in.ExternalId) != "ext-1" || aws.ToString(f.in.RoleArn) != "arn:aws:iam::1:role/Discovery" {
		t.Errorf("assumed %s with external id %q, want the connector's role and ExternalId",
			aws.ToString(f.in.RoleArn), aws.ToString(f.in.ExternalId))
	}
	if aws.ToInt32(f.in.DurationSeconds) != 3600 {
		t.Errorf("duration = %d, want 3600", aws.ToInt32(f.in.DurationSeconds))
	}
	if got := aws.ToString(f.in.RoleSessionName); got != "authsec-agent-review-1111111122223333" {
		t.Errorf("session name = %q", got)
	}
	if f.in.SourceIdentity != nil || len(f.in.Tags) != 0 {
		t.Error("the discovery role's trust policy allows neither SourceIdentity nor session tags")
	}
	if aws.ToString(f.in.Policy) == "" {
		t.Fatal("the session must carry the read-only session policy")
	}
	if creds.AccessKeyID != "ASIA1" || !creds.Expiration.Equal(exp) || creds.RoleARN == "" {
		t.Errorf("credentials = %+v", creds)
	}
}

// The session policy is valid JSON, allows only reads, and covers what the
// review service calls.
func TestAgentReviewSessionPolicyIsReadOnly(t *testing.T) {
	var doc struct {
		Version   string
		Statement []struct {
			Effect   string
			Action   []string
			Resource string
		}
	}
	if err := json.Unmarshal([]byte(agentReviewSessionPolicy), &doc); err != nil {
		t.Fatalf("session policy is not JSON: %v", err)
	}
	reads := []string{":Describe", ":List", ":Get", ":Lookup", ":Filter", "logs:StartQuery", "logs:StopQuery"}
	seen := map[string]bool{}
	for _, st := range doc.Statement {
		if st.Effect != "Allow" {
			t.Errorf("unexpected effect %q", st.Effect)
		}
		for _, a := range st.Action {
			seen[a] = true
			ok := false
			for _, r := range reads {
				ok = ok || strings.Contains(a, r)
			}
			if !ok || strings.Contains(a, "*") {
				t.Errorf("action %q is not a read", a)
			}
		}
	}
	for _, need := range []string{"cloudtrail:LookupEvents", "logs:FilterLogEvents", "ec2:DescribeInstances",
		"lambda:GetFunctionConfiguration", "ecs:DescribeTasks", "ec2:DescribeFlowLogs"} {
		if !seen[need] {
			t.Errorf("session policy lacks %s, which the review service calls", need)
		}
	}
}

func TestAgentReviewAssumeFailures(t *testing.T) {
	for name, f := range map[string]*fakeReviewSTS{
		"sts refused":    {err: errors.New("AccessDenied")},
		"no credentials": {out: &sts.AssumeRoleOutput{}},
	} {
		if _, err := reviewKeys(f).assume(context.Background(), "arn:r", "x", "us-east-1", uuid.New()); !errors.Is(err, ErrAgentReviewAssumeFailed) {
			t.Errorf("%s: err = %v, want ErrAgentReviewAssumeFailed", name, err)
		}
	}
	noSTS := (&AgentReviewKeys{}).WithSTS(func(context.Context, string) (awsbroker.STSAPI, error) {
		return nil, errors.New("no ambient identity")
	})
	if _, err := noSTS.assume(context.Background(), "arn:r", "x", "us-east-1", uuid.New()); !errors.Is(err, ErrAgentReviewUnavailable) {
		t.Errorf("no AWS identity: err = %v, want ErrAgentReviewUnavailable (retry later)", err)
	}
}
