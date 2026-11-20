package integration

// The AWS agent review handoff (services/agent_review_queue.go,
// services/agent_review_keys.go): a scan keeps attrs.agent_review, and the
// review service's AWS keys come from the connector's role, ExternalId and
// workspace only.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"

	"github.com/authsec-ai/authsec/internal/awsbroker"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// A complete rescan replaces the scan's attrs but carries agent_review over:
// the review service's pending work and verdicts are not scan facts.
func TestWorkloadRescanKeepsAgentReview(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-agent-review-rescan")
	defer cleanWorkloadTables(t, db, ws)

	l, e, c, p := populatedWorkloads()
	scanner, snap := workloadFixture(t, db, ws, l, e, c, p)
	if _, err := scanner.ScanFromSnapshot(context.Background(), ws, snap); err != nil {
		t.Fatalf("first scan: %v", err)
	}
	review := `{"agent_review": {"status": "decided", "verdict": {"label": "AI_AGENT_CONFIRMED"}, "attempts": 0}}`
	if err := db.Exec(`UPDATE cloud_workload SET attrs = attrs || ?::jsonb WHERE workspace_id = ? AND runtime_kind = ?`,
		review, ws, models.WorkloadLambdaFunction).Error; err != nil {
		t.Fatalf("set review: %v", err)
	}
	if _, err := scanner.ScanFromSnapshot(context.Background(), ws, snap); err != nil {
		t.Fatalf("second scan: %v", err)
	}

	workloads, _, err := repositories.NewCloudWorkloadRepository(db).ListWorkloads(ws, repositories.CloudWorkloadFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range workloads {
		var attrs map[string]any
		_ = json.Unmarshal(w.Attrs, &attrs)
		rv, _ := attrs["agent_review"].(map[string]any)
		switch w.RuntimeKind {
		case models.WorkloadLambdaFunction:
			if rv["status"] != "decided" {
				t.Fatalf("agent_review after the rescan = %v, want the decided review kept", attrs["agent_review"])
			}
			if len(w.AWSAttrs().EnvVarNames) != 2 {
				t.Errorf("the scan's own attrs must still be refreshed, got %v", w.AWSAttrs().EnvVarNames)
			}
		default:
			if rv != nil {
				t.Errorf("%s gained an agent_review it never had: %v", w.RuntimeKind, rv)
			}
		}
	}
}

type reviewSTS struct {
	calls int
	in    *sts.AssumeRoleInput
}

func (f *reviewSTS) AssumeRole(_ context.Context, in *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.calls++
	f.in = in
	return &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId: aws.String("ASIAREVIEW"), SecretAccessKey: aws.String("secret"), SessionToken: aws.String("token"),
		Expiration: aws.Time(time.Now().Add(time.Hour))}}, nil
}

func TestAgentReviewKeysFollowTheConnector(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-agent-review-keys")
	other := newWorkspace(t, db, "ws-agent-review-keys-other")
	defer cleanWorkloadTables(t, db, ws)

	svc, _ := newOnboarding(db, okVerifier())
	ext := mustMint(t, ws)
	conn, _, err := svc.Onboard(context.Background(), ws, validInput(ext), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	fake := &reviewSTS{}
	keys := services.NewAgentReviewKeys(svc).WithSTS(func(context.Context, string) (awsbroker.STSAPI, error) { return fake, nil })

	creds, err := keys.Issue(context.Background(), ws, conn.ID)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if creds.AccessKeyID != "ASIAREVIEW" {
		t.Errorf("credentials = %+v", creds)
	}
	if aws.ToString(fake.in.ExternalId) != ext || aws.ToString(fake.in.RoleArn) != testRoleARN {
		t.Errorf("assumed %s with external id %q, want the connector's role and its ExternalId from the secrets store",
			aws.ToString(fake.in.RoleArn), aws.ToString(fake.in.ExternalId))
	}

	// Another workspace's view of the same connector id: not found, and STS is never called.
	calls := fake.calls
	if _, err := keys.Issue(context.Background(), other, conn.ID); !errors.Is(err, services.ErrAgentReviewConnectorNotFound) {
		t.Fatalf("cross-workspace issue: err = %v, want ErrAgentReviewConnectorNotFound", err)
	}
	if fake.calls != calls {
		t.Fatal("a cross-workspace request must not reach STS")
	}

	if err := svc.RevokeConnector(ws, conn.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := keys.Issue(context.Background(), ws, conn.ID); !errors.Is(err, services.ErrAgentReviewConnectorRevoked) {
		t.Fatalf("revoked connector: err = %v, want ErrAgentReviewConnectorRevoked", err)
	}
}
