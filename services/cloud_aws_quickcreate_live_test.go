//go:build awslive

package services

// Live Quick Create test against a real AWS account. Opt-in only:
//
//	go test -tags awslive -run TestLiveQuickCreate ./services/ -v -timeout 40m
//
// Real: the template, the Quick Create link, CloudFormation, the custom
// resource, SNS, SQS, the worker, ResponseURL validation, the PUT back to
// CloudFormation, AssumeRole with the ExternalId and GetCallerIdentity.
// Substituted: Redis (miniredis, in-process) and Onboard's Postgres + Vault
// write. The substitute performs the same AWS proof Onboard does (Verify, then
// the account cross-check) and returns a connector without persisting it.
//
// The test starts a session, writes the link and parameters to QC_LIVE_OUT,
// and then consumes the queue until the session is terminal or the timeout.
// Someone (a CLI create-stack, or a person clicking the link) creates the stack
// meanwhile. QC_LIVE_DRAIN=1 skips the session and only answers callbacks, for
// the Deletes a teardown sends.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func liveEnv(t *testing.T, key string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		t.Skipf("%s not set", key)
	}
	return v
}

func TestLiveQuickCreate(t *testing.T) {
	cfg, err := awsdiscovery.ParseCallbackConfig(
		liveEnv(t, "QC_LIVE_TOPICS"), liveEnv(t, "QC_LIVE_QUEUE_URL"),
		liveEnv(t, "QC_LIVE_TEMPLATE_BASE"), os.Getenv("QC_LIVE_TEMPLATE_OVERRIDES"), os.Getenv("QC_LIVE_OPTIN"))
	if err != nil {
		t.Fatal(err)
	}
	principal := liveEnv(t, "QC_LIVE_PRINCIPAL")
	out := liveEnv(t, "QC_LIVE_OUT")
	timeout := 25 * time.Minute
	if v := os.Getenv("QC_LIVE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			timeout = d
		}
	}
	drain := os.Getenv("QC_LIVE_DRAIN") == "1"

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()

	svc := NewAWSQuickCreateService(nil, redis.NewClient(&redis.Options{Addr: mr.Addr()}), cfg, principal)
	live := awsdiscovery.NewLiveVerifier()
	svc.verifier = live
	// The bucket is private in the lab; CloudFormation reads it with the
	// operator's own credentials. Existence is checked by the setup script.
	svc.templateCheck = func(context.Context, string) error { return nil }
	svc.onboard = func(ctx context.Context, ws uuid.UUID, in AWSOnboardInput, _ string) (*models.CloudConnector, bool, error) {
		// Onboard's AWS half, verbatim in effect: assume, read back, cross-check.
		_, arnAccount, err := awsdiscovery.ParseRoleARN(in.RoleARN)
		if err != nil {
			return nil, false, err
		}
		name, err := onboardingSessionName()
		if err != nil {
			return nil, false, err
		}
		pctx, cancel := context.WithTimeout(ctx, awsOnboardingTimeout)
		defer cancel()
		id, err := live.Verify(pctx, awsdiscovery.AssumeRequest{
			RoleARN: in.RoleARN, ExternalID: in.ExternalID, Region: in.Regions[0], SessionName: name,
		})
		if err != nil {
			if pctx.Err() == context.DeadlineExceeded {
				err = fmt.Errorf("%w: %v", ErrAWSProbeTimeout, err)
			}
			return nil, false, err
		}
		if id.AccountID != arnAccount {
			return nil, false, fmt.Errorf("the role resolved to account %s but its ARN names %s; refusing to onboard",
				id.AccountID, arnAccount)
		}
		t.Logf("PROOF: assumed %s as %s (account %s)", in.RoleARN, id.ARN, id.AccountID)
		return &models.CloudConnector{ID: uuid.New(), WorkspaceID: ws, ScopeID: id.AccountID}, true, nil
	}

	ctx := context.Background()
	var sess *AWSOnboardingSession
	record := map[string]any{"observed": []map[string]string{}}
	flush := func() {
		raw, _ := json.MarshalIndent(record, "", "  ")
		_ = os.WriteFile(out, raw, 0o600)
	}

	if !drain {
		regions := strings.Split(liveEnv(t, "QC_LIVE_REGIONS"), ",")
		sess, err = svc.StartSession(ctx, uuid.New(), "live-test", regions, os.Getenv("QC_LIVE_DEPLOY_REGION"))
		if err != nil {
			t.Fatal(err)
		}
		record["session_id"] = sess.ID.String()
		record["quick_create_url"] = sess.QuickCreateURL
		record["stack_name"] = sess.StackName
		record["role_name"] = sess.RoleName
		record["deployment_region"] = sess.DeploymentRegion
		record["regions"] = sess.Regions
		record["template_url"] = cfg.TemplateURLFor(sess.DeploymentRegion)
		record["parameters"] = map[string]string{
			"AuthSecPrincipalArn": principal, "ExternalId": sess.ExternalID,
			"CallbackTopicArn": cfg.Topics[sess.DeploymentRegion], "RoleName": sess.RoleName,
		}
		flush()
		t.Logf("session %s ready; stack %s in %s", sess.ID, sess.StackName, sess.DeploymentRegion)
	}

	queueRegion, _ := awsdiscovery.QueueRegion(cfg.QueueURL)
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(queueRegion))
	if err != nil {
		t.Fatal(err)
	}
	w := &AWSCallbackWorker{svc: svc, client: sqs.NewFromConfig(awsCfg), queueURL: cfg.QueueURL}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		msgs, err := w.client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
			QueueUrl: aws.String(w.queueURL), MaxNumberOfMessages: 5, WaitTimeSeconds: 20,
			VisibilityTimeout: int32(awsCallbackVisibility / time.Second),
		})
		if err != nil {
			t.Fatalf("receive: %v", err)
		}
		for _, m := range msgs.Messages {
			body := aws.ToString(m.Body)
			obs := map[string]string{"received_at": time.Now().UTC().Format(time.RFC3339)}
			if env, err := awsdiscovery.ParseSNSEnvelope(body); err == nil {
				obs["topic"] = env.TopicArn
				if req, err := awsdiscovery.ParseCFNRequest(env.Message); err == nil {
					obs["request_type"], obs["stack_id"] = req.RequestType, req.StackID
					if u, err := url.Parse(req.ResponseURL); err == nil {
						// Host, path and the NAMES of the query parameters only: the
						// values are a presigned write credential.
						names := make([]string, 0)
						for k := range u.Query() {
							names = append(names, k)
						}
						obs["response_host"], obs["response_path"] = u.Host, u.Path
						obs["response_query_keys"] = strings.Join(names, ",")
					}
				}
			}
			outcome := svc.HandleCallbackMessage(ctx, body)
			obs["outcome"] = outcome.String()
			w.settle(ctx, aws.ToString(m.ReceiptHandle), outcome)
			record["observed"] = append(record["observed"].([]map[string]string), obs)
			t.Logf("message: %v", obs)
			flush()
		}
		if sess != nil {
			got, err := svc.GetSession(ctx, sess.WorkspaceID, sess.ID)
			if err == nil && got.terminal() && (got.Status == AWSOnbFailed || len(got.RegionStatus) > 0) {
				record["final"] = got.View()
				flush()
				t.Logf("final session: status=%s code=%s account=%s regions=%v put_failed=%v",
					got.Status, got.Code, got.AccountID, got.RegionStatus, got.ResponsePutFailed)
				if got.Status != AWSOnbConnected {
					t.Fatalf("session ended %s (%s)", got.Status, got.Code)
				}
				return
			}
		}
	}
	if sess != nil {
		t.Fatal("timed out before the session finished")
	}
}
