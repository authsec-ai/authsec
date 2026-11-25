package awsdiscovery

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

func TestInstanceArtifactDigests(t *testing.T) {
	if got := lambdaCodeDigest(aws.String("q1w2e3=")); got != "lambda-sha256:q1w2e3=" {
		t.Fatalf("lambda: %s", got)
	}
	if lambdaCodeDigest(nil) != "" {
		t.Fatal("no sha must be empty")
	}
	defs := []ecstypes.ContainerDefinition{
		{Image: aws.String("123.dkr.ecr.us-east-1.amazonaws.com/bot@sha256:abcd")},
		{Image: aws.String("public.ecr.aws/otel/collector:0.9")},
		{Image: nil},
	}
	if got := ecsImageDigest(defs); got != "public.ecr.aws/otel/collector:0.9,sha256:abcd" {
		t.Fatalf("ecs: %s", got)
	}
	if got := agentCoreRuntimeVersion(aws.String("3")); got != "agentcore-runtime-version:3" {
		t.Fatalf("agentcore: %s", got)
	}
}
