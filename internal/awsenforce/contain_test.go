package awsenforce

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/smithy-go"
)

// probeFake answers every containment call with one error per operation.
type probeFake struct {
	IAM
	answer map[string]error
	calls  []string
}

func (p *probeFake) ans(op string) error {
	p.calls = append(p.calls, op)
	return p.answer[op]
}

func (p *probeFake) GetFunctionConcurrency(context.Context, string) (*int32, error) {
	return nil, p.ans("GetFunctionConcurrency")
}
func (p *probeFake) PutFunctionConcurrency(context.Context, string, int32) error {
	return p.ans("PutFunctionConcurrency")
}
func (p *probeFake) DeleteFunctionConcurrency(context.Context, string) error {
	return p.ans("DeleteFunctionConcurrency")
}
func (p *probeFake) DescribeECSService(context.Context, string, string) (*ECSServiceInfo, error) {
	return nil, p.ans("DescribeServices")
}
func (p *probeFake) UpdateECSServiceDesiredCount(context.Context, string, string, int32) error {
	return p.ans("UpdateService")
}
func (p *probeFake) DescribeECSScalableTarget(context.Context, string, string) (*ScalableTargetInfo, error) {
	return nil, p.ans("DescribeScalableTargets")
}
func (p *probeFake) SetECSScalingSuspended(context.Context, string, string, bool, bool, bool) error {
	return p.ans("RegisterScalableTarget")
}
func (p *probeFake) AttachUserPolicy(context.Context, string, string) error {
	return p.ans("AttachUserPolicy")
}
func (p *probeFake) DetachUserPolicy(context.Context, string, string) error {
	return p.ans("DetachUserPolicy")
}
func (p *probeFake) ListAccessKeys(context.Context, string) ([]AccessKeyInfo, error) {
	return nil, p.ans("ListAccessKeys")
}
func (p *probeFake) UpdateAccessKey(context.Context, string, string, bool) error {
	return p.ans("UpdateAccessKey")
}

func apiErr(code string) error { return &smithy.GenericAPIError{Code: code, Message: code + " (fake)"} }

// With the parameter every call on the absent objects answers "not found":
// the capability is ok. Without it AWS refuses: denied, naming the parameter.
func TestWorkloadContainmentProbe(t *testing.T) {
	at := func() time.Time { return time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC) }
	in := SelfTestInput{AccountID: "111111111111", Partition: "aws", Region: "us-east-1"}

	withParam := &probeFake{answer: map[string]error{
		"GetFunctionConcurrency": apiErr("ResourceNotFoundException"), "PutFunctionConcurrency": apiErr("ResourceNotFoundException"),
		"UpdateService": apiErr("ClusterNotFoundException"), "ListAccessKeys": apiErr("NoSuchEntity"),
		"UpdateAccessKey": apiErr("NoSuchEntity"), "AttachUserPolicy": apiErr("NoSuchEntity"),
	}}
	if r := workloadContainmentProbe(context.Background(), withParam, in, "run1", at); r.Status != StatusOK {
		t.Fatalf("with the parameter: %+v", r)
	}
	// Release's writes are probed too: a stack that can contain but not
	// release must not report the capability.
	for _, want := range []string{"DeleteFunctionConcurrency", "RegisterScalableTarget", "DetachUserPolicy", "DescribeServices"} {
		found := false
		for _, c := range withParam.calls {
			found = found || c == want
		}
		if !found {
			t.Errorf("the probe must call %s", want)
		}
	}
	noRelease := &probeFake{answer: map[string]error{"DeleteFunctionConcurrency": apiErr("AccessDeniedException")}}
	if r := workloadContainmentProbe(context.Background(), noRelease, in, "run1", at); r.Status != StatusDenied {
		t.Fatalf("release permission missing: %+v", r)
	}

	without := &probeFake{answer: map[string]error{
		"GetFunctionConcurrency": apiErr("AccessDeniedException"),
	}}
	r := workloadContainmentProbe(context.Background(), without, in, "run1", at)
	if r.Status != StatusDenied || !strings.Contains(r.Message, "EnableWorkloadContainment") {
		t.Fatalf("without the parameter: %+v", r)
	}

	// A client without the operations is untested, never ok.
	if r := workloadContainmentProbe(context.Background(), struct{ IAM }{}, in, "run1", at); r.Status != StatusUntested {
		t.Fatalf("no operations: %+v", r)
	}

	// The feature needs exactly this capability.
	if got := V2CapabilitiesFor(FeatureWorkloadContainment); len(got) != 1 || got[0] != CapWorkloadContainment {
		t.Fatalf("V2CapabilitiesFor(workload_containment) = %v", got)
	}
	missing := MissingV2Capabilities(map[string]CapabilityResult{CapWorkloadContainment: {Status: StatusDenied, ErrorCode: "AccessDeniedException"}},
		FeatureWorkloadContainment)
	if len(missing) != 1 || !strings.Contains(missing[0], "denied") {
		t.Fatalf("missing %v", missing)
	}
}
