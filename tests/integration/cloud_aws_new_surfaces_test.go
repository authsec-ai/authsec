package integration

import (
	"context"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	agentcoretypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// onboardWithRun onboards a connector and claims a cloud_scan_run for it,
// returning enough to build an ObservationWriter. Claimed BEFORE any scanner
// runs, so its generation is computed from the same (still-unadvanced)
// cloud_connector.scan_generation Scan() itself reads moments later -- the
// two independently arrive at the same number, same as the real worker and
// a directly-driven test both do today.
func onboardWithRun(t *testing.T, db *gorm.DB, ws uuid.UUID) (svc *services.AWSOnboardingService, connID uuid.UUID, run *models.CloudScanRun) {
	t.Helper()
	svc, _ = newOnboarding(db, okVerifier())
	conn, _, err := svc.Onboard(context.Background(), ws, singleRegionInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	runs := scanRuns(t, db)
	if _, err := runs.Enqueue(ws, conn.ID, "manual"); err != nil {
		t.Fatalf("enqueue run: %v", err)
	}
	run, err = runs.Claim("test-worker", time.Minute, time.Now())
	if err != nil || run == nil {
		t.Fatalf("claim run: %v %v", run, err)
	}
	return svc, conn.ID, run
}

// The five surfaces the CloudFormation role granted and nothing called --
// see uncollectedSurfaces' own former contents. Each test proves two things:
// the surface is actually read, and a denied read on it does not block
// reconciliation of inventory that has nothing to do with it. The second
// property is the one a naive wiring gets wrong -- see the comments on
// scanWorkloadIdentities, scanCloudTrail, and FinalizeCoverage's new
// credentialReportSurface parameter.

// --- AgentCore Gateways -----------------------------------------------------

type fakeGatewayAgentCore struct {
	gateways         []agentcoretypes.GatewaySummary
	gatewayRoleByID  map[string]string
	targetsByGateway map[string][]agentcoretypes.TargetSummary
}

func (f *fakeGatewayAgentCore) ListAgentRuntimes(context.Context, *bedrockagentcorecontrol.ListAgentRuntimesInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListAgentRuntimesOutput, error) {
	return &bedrockagentcorecontrol.ListAgentRuntimesOutput{}, nil
}
func (f *fakeGatewayAgentCore) GetAgentRuntime(context.Context, *bedrockagentcorecontrol.GetAgentRuntimeInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetAgentRuntimeOutput, error) {
	return &bedrockagentcorecontrol.GetAgentRuntimeOutput{}, nil
}
func (f *fakeGatewayAgentCore) ListGateways(context.Context, *bedrockagentcorecontrol.ListGatewaysInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListGatewaysOutput, error) {
	return &bedrockagentcorecontrol.ListGatewaysOutput{Items: f.gateways}, nil
}
func (f *fakeGatewayAgentCore) GetGateway(_ context.Context, in *bedrockagentcorecontrol.GetGatewayInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetGatewayOutput, error) {
	role := f.gatewayRoleByID[aws.ToString(in.GatewayIdentifier)]
	return &bedrockagentcorecontrol.GetGatewayOutput{
		GatewayArn: aws.String("arn:aws:bedrock-agentcore:us-east-1:491056652413:gateway/" + aws.ToString(in.GatewayIdentifier)),
		RoleArn:    aws.String(role),
	}, nil
}
func (f *fakeGatewayAgentCore) ListGatewayTargets(_ context.Context, in *bedrockagentcorecontrol.ListGatewayTargetsInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListGatewayTargetsOutput, error) {
	return &bedrockagentcorecontrol.ListGatewayTargetsOutput{Items: f.targetsByGateway[aws.ToString(in.GatewayIdentifier)]}, nil
}
func (f *fakeGatewayAgentCore) ListWorkloadIdentities(context.Context, *bedrockagentcorecontrol.ListWorkloadIdentitiesInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListWorkloadIdentitiesOutput, error) {
	return &bedrockagentcorecontrol.ListWorkloadIdentitiesOutput{}, nil
}
func (f *fakeGatewayAgentCore) ListOauth2CredentialProviders(context.Context, *bedrockagentcorecontrol.ListOauth2CredentialProvidersInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListOauth2CredentialProvidersOutput, error) {
	return &bedrockagentcorecontrol.ListOauth2CredentialProvidersOutput{}, nil
}
func (f *fakeGatewayAgentCore) ListApiKeyCredentialProviders(context.Context, *bedrockagentcorecontrol.ListApiKeyCredentialProvidersInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListApiKeyCredentialProvidersOutput, error) {
	return &bedrockagentcorecontrol.ListApiKeyCredentialProvidersOutput{}, nil
}

// A gateway is written to cloud_workload through the same path as Lambda/ECS,
// and its target is recorded as evidence under that workload -- proving the
// "agent tool-path segment" the original gap report named is no longer absent.
func TestAgentCoreGatewaysAreCollected(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-agentcore-gateways")
	defer cleanWorkloadTables(t, db, ws)

	svc, connID, run := onboardWithRun(t, db, ws)
	evidence := services.NewObservationWriter(db, ws, connID, run.ID, run.Generation)
	iamFake := populatedIAM()
	snap, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(iamFake).WithEvidence(evidence).
		Scan(context.Background(), ws, connID)
	if err != nil {
		t.Fatalf("iam scan: %v", err)
	}

	gw := &fakeGatewayAgentCore{
		gateways: []agentcoretypes.GatewaySummary{{
			GatewayId: aws.String("gw-001"), Name: aws.String("ticket-tools-gateway"),
			Status: agentcoretypes.GatewayStatusReady,
		}},
		gatewayRoleByID: map[string]string{"gw-001": agentRoleARN},
		targetsByGateway: map[string][]agentcoretypes.TargetSummary{
			"gw-001": {{TargetId: aws.String("tgt-1"), Name: aws.String("ticket-tools"), Status: agentcoretypes.TargetStatusReady}},
		},
	}
	l, e, c, p := populatedWorkloads()
	scanner := services.NewAWSWorkloadScanner(db, svc).
		WithWorkloadAPIs(l, e, c, p).WithBedrockAPIs(nil, gw).WithEvidence(evidence)
	if _, err := scanner.ScanFromSnapshot(context.Background(), ws, snap); err != nil {
		t.Fatalf("workload scan: %v", err)
	}

	var count int64
	if err := db.Raw(`SELECT count(*) FROM cloud_workload WHERE workspace_id = ? AND runtime_kind = ?`,
		ws, models.WorkloadBedrockAgentCoreGW).Scan(&count).Error; err != nil || count != 1 {
		t.Fatalf("gateway workload not written: count=%d err=%v", count, err)
	}
	var obsCount int64
	if err := db.Raw(`SELECT count(*) FROM cloud_observation WHERE workspace_id = ? AND source_api = 'bedrock-agentcore:ListGatewayTargets'`,
		ws).Scan(&obsCount).Error; err != nil || obsCount != 1 {
		t.Fatalf("gateway target evidence not written: count=%d err=%v", obsCount, err)
	}
}

// --- AgentCore Workload Identities -------------------------------------------

// Denying this surface must not stop Lambda/ECS/EC2 from reconciling -- it
// is bonus evidence, not part of any reconciled table.
func TestAgentCoreWorkloadIdentitiesDoNotGateWorkloadReconciliation(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-agentcore-workload-identities")
	defer cleanWorkloadTables(t, db, ws)

	svc, connID, run := onboardWithRun(t, db, ws)
	evidence := services.NewObservationWriter(db, ws, connID, run.ID, run.Generation)
	iamFake := populatedIAM()
	snap, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(iamFake).WithEvidence(evidence).
		Scan(context.Background(), ws, connID)
	if err != nil {
		t.Fatalf("iam scan: %v", err)
	}

	l, e, c, p := populatedWorkloads()
	noSleep := func(context.Context, time.Duration) error { return nil }
	scanner := services.NewAWSWorkloadScanner(db, svc).
		WithWorkloadAPIs(l, e, c, p).WithBedrockAPIs(nil, &deniedWorkloadIdentityAgentCore{}).
		WithActivityAPI(&fakeActivity{}, noSleep).WithEvidence(evidence)
	out, err := scanner.ScanFromSnapshot(context.Background(), ws, snap)
	if err != nil {
		t.Fatalf("workload scan: %v", err)
	}
	if !out.Complete {
		t.Fatalf("workload scan must still report complete despite a denied workload-identity read: %+v", out.Errors)
	}
}

// deniedWorkloadIdentityAgentCore denies ListWorkloadIdentities specifically,
// to prove that denial alone does not cost Lambda/ECS/EC2 reconciliation.
type deniedWorkloadIdentityAgentCore struct{ fakeGatewayAgentCore }

func (f *deniedWorkloadIdentityAgentCore) ListWorkloadIdentities(context.Context, *bedrockagentcorecontrol.ListWorkloadIdentitiesInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListWorkloadIdentitiesOutput, error) {
	return nil, denied("bedrock-agentcore:ListWorkloadIdentities")
}

// A workload identity has no cloud_identity row of its own -- see the
// AgentCoreAPI.ListWorkloadIdentities doc comment for why -- so this proves
// it is recorded as evidence instead, identifiable by subject_native_id with
// every subject FK left null.
func TestAgentCoreWorkloadIdentityIsRecordedAsEvidence(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-agentcore-workload-identity-evidence")
	defer cleanWorkloadTables(t, db, ws)

	svc, connID, run := onboardWithRun(t, db, ws)
	evidence := services.NewObservationWriter(db, ws, connID, run.ID, run.Generation)
	iamFake := populatedIAM()
	snap, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(iamFake).WithEvidence(evidence).
		Scan(context.Background(), ws, connID)
	if err != nil {
		t.Fatalf("iam scan: %v", err)
	}

	l, e, c, p := populatedWorkloads()
	scanner := services.NewAWSWorkloadScanner(db, svc).
		WithWorkloadAPIs(l, e, c, p).
		WithBedrockAPIs(nil, &fakeWorkloadIdentityAgentCore{identities: []agentcoretypes.WorkloadIdentityType{{
			Name: aws.String("support-agent-identity"),
			WorkloadIdentityArn: aws.String(
				"arn:aws:bedrock-agentcore:us-east-1:491056652413:workload-identity-directory/default/workload-identity/support-agent-identity"),
		}}}).
		WithEvidence(evidence)
	if _, err := scanner.ScanFromSnapshot(context.Background(), ws, snap); err != nil {
		t.Fatalf("workload scan: %v", err)
	}

	var (
		identityID, permissionID, resourceID, workloadID *string
		nativeID                                          string
	)
	err = db.Raw(`SELECT identity_id, permission_id, resource_id, workload_id, subject_native_id
	                FROM cloud_observation
	               WHERE workspace_id = ? AND source_api = 'bedrock-agentcore:ListWorkloadIdentities'`, ws).
		Row().Scan(&identityID, &permissionID, &resourceID, &workloadID, &nativeID)
	if err != nil {
		t.Fatalf("workload identity evidence not written: %v", err)
	}
	if identityID != nil || permissionID != nil || resourceID != nil || workloadID != nil {
		t.Fatalf("expected every subject column null, got identity=%v permission=%v resource=%v workload=%v",
			identityID, permissionID, resourceID, workloadID)
	}
	if nativeID == "" {
		t.Fatal("subject_native_id must still say what this evidence was about")
	}
}

// Before uq_cloud_observation_dedupe_no_subject (025), a subject-less
// observation's dedupe key was COALESCE(identity_id, permission_id,
// resource_id, workload_id) -- NULL for every workload identity, and
// Postgres never treats two NULLs as equal for uniqueness. Every re-scan of
// an unchanged account inserted a fresh row. This proves the fix: the same
// fact, scanned twice, is one row with confirmation_count = 2, not two rows.
func TestWorkloadIdentityEvidenceDedupesAcrossScans(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-agentcore-workload-identity-dedupe")
	defer cleanWorkloadTables(t, db, ws)

	svc, connID, run1 := onboardWithRun(t, db, ws)
	evidence1 := services.NewObservationWriter(db, ws, connID, run1.ID, run1.Generation)
	iamFake := populatedIAM()
	snap1, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(iamFake).WithEvidence(evidence1).
		Scan(context.Background(), ws, connID)
	if err != nil {
		t.Fatalf("iam scan: %v", err)
	}

	agentCore := &fakeWorkloadIdentityAgentCore{identities: []agentcoretypes.WorkloadIdentityType{{
		Name:                aws.String("support-agent-identity"),
		WorkloadIdentityArn: aws.String("arn:aws:bedrock-agentcore:us-east-1:491056652413:workload-identity-directory/default/workload-identity/support-agent-identity"),
	}}}
	l, e, c, p := populatedWorkloads()
	scanner1 := services.NewAWSWorkloadScanner(db, svc).
		WithWorkloadAPIs(l, e, c, p).WithBedrockAPIs(nil, agentCore).WithEvidence(evidence1)
	if _, err := scanner1.ScanFromSnapshot(context.Background(), ws, snap1); err != nil {
		t.Fatalf("first workload scan: %v", err)
	}

	// A second, unrelated run re-reads the exact same account. Deliberately
	// NOT scanRuns(t, db) again -- that helper clears cloud_observation as a
	// side effect (a clean table for the NEXT test to start from), and calling
	// it mid-test here would wipe the very evidence this test exists to check
	// accumulates rather than resets.
	runs := repositories.NewCloudScanRunRepository(db)
	// run1 is still "running" -- Scan()/ScanFromSnapshot() know nothing about
	// the lease lifecycle, only the worker does (see cloud_aws_scan_worker.go).
	// The live-run unique index would refuse a second Enqueue otherwise.
	if err := runs.Publish(run1.ID, "test-worker", run1.LeaseVersion); err != nil {
		t.Fatalf("publish first run: %v", err)
	}
	if _, err := runs.Enqueue(ws, connID, "manual"); err != nil {
		t.Fatalf("enqueue second run: %v", err)
	}
	run2, err := runs.Claim("test-worker-2", time.Minute, time.Now())
	if err != nil || run2 == nil {
		t.Fatalf("claim second run: %v %v", run2, err)
	}
	evidence2 := services.NewObservationWriter(db, ws, connID, run2.ID, run2.Generation)
	iamFake2 := populatedIAM()
	snap2, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(iamFake2).WithEvidence(evidence2).
		Scan(context.Background(), ws, connID)
	if err != nil {
		t.Fatalf("second iam scan: %v", err)
	}
	l2, e2, c2, p2 := populatedWorkloads()
	scanner2 := services.NewAWSWorkloadScanner(db, svc).
		WithWorkloadAPIs(l2, e2, c2, p2).WithBedrockAPIs(nil, agentCore).WithEvidence(evidence2)
	if _, err := scanner2.ScanFromSnapshot(context.Background(), ws, snap2); err != nil {
		t.Fatalf("second workload scan: %v", err)
	}

	var rowCount int64
	if err := db.Raw(`SELECT count(*) FROM cloud_observation
	                    WHERE workspace_id = ? AND source_api = 'bedrock-agentcore:ListWorkloadIdentities'`, ws).
		Scan(&rowCount).Error; err != nil {
		t.Fatalf("count evidence rows: %v", err)
	}
	if rowCount != 1 {
		t.Fatalf("two identical scans produced %d rows, want 1 -- the no-subject dedupe key is not firing", rowCount)
	}

	var confirmations int
	if err := db.Raw(`SELECT confirmation_count FROM cloud_observation
	                    WHERE workspace_id = ? AND source_api = 'bedrock-agentcore:ListWorkloadIdentities'`, ws).
		Scan(&confirmations).Error; err != nil {
		t.Fatalf("read confirmation_count: %v", err)
	}
	if confirmations != 2 {
		t.Fatalf("confirmation_count = %d, want 2 after two scans of the same fact", confirmations)
	}
}

// fakeWorkloadIdentityAgentCore returns a fixed list of workload identities
// and empty/no-op for every other AgentCore surface.
type fakeWorkloadIdentityAgentCore struct {
	identities      []agentcoretypes.WorkloadIdentityType
	oauth2Providers []agentcoretypes.Oauth2CredentialProviderItem
	apiKeyProviders []agentcoretypes.ApiKeyCredentialProviderItem
}

func (f *fakeWorkloadIdentityAgentCore) ListAgentRuntimes(context.Context, *bedrockagentcorecontrol.ListAgentRuntimesInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListAgentRuntimesOutput, error) {
	return &bedrockagentcorecontrol.ListAgentRuntimesOutput{}, nil
}
func (f *fakeWorkloadIdentityAgentCore) GetAgentRuntime(context.Context, *bedrockagentcorecontrol.GetAgentRuntimeInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetAgentRuntimeOutput, error) {
	return &bedrockagentcorecontrol.GetAgentRuntimeOutput{}, nil
}
func (f *fakeWorkloadIdentityAgentCore) ListGateways(context.Context, *bedrockagentcorecontrol.ListGatewaysInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListGatewaysOutput, error) {
	return &bedrockagentcorecontrol.ListGatewaysOutput{}, nil
}
func (f *fakeWorkloadIdentityAgentCore) GetGateway(context.Context, *bedrockagentcorecontrol.GetGatewayInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetGatewayOutput, error) {
	return &bedrockagentcorecontrol.GetGatewayOutput{}, nil
}
func (f *fakeWorkloadIdentityAgentCore) ListGatewayTargets(context.Context, *bedrockagentcorecontrol.ListGatewayTargetsInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListGatewayTargetsOutput, error) {
	return &bedrockagentcorecontrol.ListGatewayTargetsOutput{}, nil
}
func (f *fakeWorkloadIdentityAgentCore) ListWorkloadIdentities(context.Context, *bedrockagentcorecontrol.ListWorkloadIdentitiesInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListWorkloadIdentitiesOutput, error) {
	return &bedrockagentcorecontrol.ListWorkloadIdentitiesOutput{WorkloadIdentities: f.identities}, nil
}
func (f *fakeWorkloadIdentityAgentCore) ListOauth2CredentialProviders(context.Context, *bedrockagentcorecontrol.ListOauth2CredentialProvidersInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListOauth2CredentialProvidersOutput, error) {
	return &bedrockagentcorecontrol.ListOauth2CredentialProvidersOutput{CredentialProviders: f.oauth2Providers}, nil
}
func (f *fakeWorkloadIdentityAgentCore) ListApiKeyCredentialProviders(context.Context, *bedrockagentcorecontrol.ListApiKeyCredentialProvidersInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListApiKeyCredentialProvidersOutput, error) {
	return &bedrockagentcorecontrol.ListApiKeyCredentialProvidersOutput{CredentialProviders: f.apiKeyProviders}, nil
}

// --- CloudTrail --------------------------------------------------------------

type fakeCloudTrail struct {
	events []cttypes.Event
	trails []cttypes.Trail
}

func (f *fakeCloudTrail) LookupEvents(context.Context, *cloudtrail.LookupEventsInput, ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	return &cloudtrail.LookupEventsOutput{Events: f.events}, nil
}

func (f *fakeCloudTrail) DescribeTrails(context.Context, *cloudtrail.DescribeTrailsInput, ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
	return &cloudtrail.DescribeTrailsOutput{TrailList: f.trails}, nil
}

func (f *fakeCloudTrail) GetTrailStatus(_ context.Context, in *cloudtrail.GetTrailStatusInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
	return &cloudtrail.GetTrailStatusOutput{IsLogging: aws.Bool(true)}, nil
}

// A direct IAM-user call is matched by name -- the one case CloudTrail's
// Username field can confidently resolve, per the reader's own doc comment --
// and a denied call is preserved in the evidence as denied, which
// GenerateServiceLastAccessedDetails cannot show at all.
func TestCloudTrailEventsMatchAKnownUserAndPreserveDenials(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-cloudtrail-events")
	defer cleanWorkloadTables(t, db, ws)

	svc, connID, run := onboardWithRun(t, db, ws)
	evidence := services.NewObservationWriter(db, ws, connID, run.ID, run.Generation)
	iamFake := populatedIAM() // seeds IAM user "ci-deployer"
	snap, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(iamFake).WithEvidence(evidence).
		Scan(context.Background(), ws, connID)
	if err != nil {
		t.Fatalf("iam scan: %v", err)
	}

	trail := &fakeCloudTrail{events: []cttypes.Event{{
		EventId: aws.String("evt-1"), EventName: aws.String("DeleteObject"),
		EventSource: aws.String("s3.amazonaws.com"), Username: aws.String("ci-deployer"),
		EventTime:       aws.Time(time.Now()),
		CloudTrailEvent: aws.String(`{"errorCode":"AccessDenied"}`),
	}}}
	l, e, c, p := populatedWorkloads()
	scanner := services.NewAWSWorkloadScanner(db, svc).
		WithWorkloadAPIs(l, e, c, p).WithCloudTrailAPI(trail).WithEvidence(evidence)
	if _, err := scanner.ScanFromSnapshot(context.Background(), ws, snap); err != nil {
		t.Fatalf("workload scan: %v", err)
	}

	var denied bool
	var errorCode string
	dberr := db.Raw(`SELECT sanitized_facts->>'denied' = 'true', sanitized_facts->>'error_code'
	                    FROM cloud_observation
	                   WHERE workspace_id = ? AND source_api = 'cloudtrail:LookupEvents'`, ws).
		Row().Scan(&denied, &errorCode)
	if dberr != nil {
		t.Fatalf("cloudtrail evidence for the matched user was not written: %v", dberr)
	}
	if !denied || errorCode != "AccessDenied" {
		t.Fatalf("denied=%v errorCode=%q, want a preserved denial", denied, errorCode)
	}
}

// --- AgentCore credential providers ------------------------------------------

// Granted in the role template from the start (see permissions.go's
// "bedrock-agentcore" surface) but never called until this test: an OAuth2
// and an API-key credential provider each land as their own subject-less
// observation, named by the AWS action that produced them, and neither
// blocks Lambda/ECS/EC2 reconciliation when denied.
func TestAgentCoreCredentialProvidersAreCollectedAsEvidence(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-agentcore-credential-providers")
	defer cleanWorkloadTables(t, db, ws)

	svc, connID, run := onboardWithRun(t, db, ws)
	evidence := services.NewObservationWriter(db, ws, connID, run.ID, run.Generation)
	iamFake := populatedIAM()
	snap, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(iamFake).WithEvidence(evidence).
		Scan(context.Background(), ws, connID)
	if err != nil {
		t.Fatalf("iam scan: %v", err)
	}

	agentCore := &fakeWorkloadIdentityAgentCore{
		oauth2Providers: []agentcoretypes.Oauth2CredentialProviderItem{{
			Name:                     aws.String("google-oauth"),
			CredentialProviderArn:    aws.String("arn:aws:bedrock-agentcore:us-east-1:491056652413:token-vault/default/oauth2credentialprovider/google-oauth"),
			CredentialProviderVendor: agentcoretypes.CredentialProviderVendorTypeGoogleOauth2,
		}},
		apiKeyProviders: []agentcoretypes.ApiKeyCredentialProviderItem{{
			Name:                  aws.String("weather-api-key"),
			CredentialProviderArn: aws.String("arn:aws:bedrock-agentcore:us-east-1:491056652413:token-vault/default/apikeycredentialprovider/weather-api-key"),
		}},
	}
	l, e, c, p := populatedWorkloads()
	noSleep := func(context.Context, time.Duration) error { return nil }
	scanner := services.NewAWSWorkloadScanner(db, svc).
		WithWorkloadAPIs(l, e, c, p).WithBedrockAPIs(nil, agentCore).
		WithActivityAPI(&fakeActivity{}, noSleep).WithEvidence(evidence)
	snapshot, err := scanner.ScanFromSnapshot(context.Background(), ws, snap)
	if err != nil {
		t.Fatalf("workload scan: %v", err)
	}
	if !snapshot.Complete {
		t.Fatalf("bonus credential-provider evidence must not block reconciliation, got Complete=false errors=%v", snapshot.Errors)
	}

	var oauthName, oauthVendor string
	if err := db.Raw(`SELECT sanitized_facts->>'name', sanitized_facts->>'vendor' FROM cloud_observation
	                    WHERE workspace_id = ? AND source_api = 'bedrock-agentcore:ListOauth2CredentialProviders'`, ws).
		Row().Scan(&oauthName, &oauthVendor); err != nil {
		t.Fatalf("oauth2 credential provider evidence not written: %v", err)
	}
	if oauthName != "google-oauth" || oauthVendor != "GoogleOauth2" {
		t.Fatalf("oauth2 provider facts = name=%q vendor=%q, want google-oauth/GoogleOauth2", oauthName, oauthVendor)
	}

	var apiKeyName string
	if err := db.Raw(`SELECT sanitized_facts->>'name' FROM cloud_observation
	                    WHERE workspace_id = ? AND source_api = 'bedrock-agentcore:ListApiKeyCredentialProviders'`, ws).
		Row().Scan(&apiKeyName); err != nil {
		t.Fatalf("api key credential provider evidence not written: %v", err)
	}
	if apiKeyName != "weather-api-key" {
		t.Fatalf("api key provider facts name = %q, want weather-api-key", apiKeyName)
	}
}

// --- CloudTrail trail status --------------------------------------------------

// DescribeTrails/GetTrailStatus tell RecentEvents' silence apart from a blind
// account. A trail visible in the region gets its config recorded under
// cloudtrail:DescribeTrails and, separately, whether it is actually logging
// under cloudtrail:GetTrailStatus.
func TestCloudTrailStatusIsRecordedAsEvidence(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-cloudtrail-status")
	defer cleanWorkloadTables(t, db, ws)

	svc, connID, run := onboardWithRun(t, db, ws)
	evidence := services.NewObservationWriter(db, ws, connID, run.ID, run.Generation)
	iamFake := populatedIAM()
	snap, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(iamFake).WithEvidence(evidence).
		Scan(context.Background(), ws, connID)
	if err != nil {
		t.Fatalf("iam scan: %v", err)
	}

	trail := &fakeCloudTrail{trails: []cttypes.Trail{{
		Name:                       aws.String("management-events"),
		TrailARN:                   aws.String("arn:aws:cloudtrail:us-east-1:491056652413:trail/management-events"),
		HomeRegion:                 aws.String("us-east-1"),
		IsMultiRegionTrail:         aws.Bool(true),
		IncludeGlobalServiceEvents: aws.Bool(true),
	}}}
	l, e, c, p := populatedWorkloads()
	scanner := services.NewAWSWorkloadScanner(db, svc).
		WithWorkloadAPIs(l, e, c, p).WithCloudTrailAPI(trail).WithEvidence(evidence)
	if _, err := scanner.ScanFromSnapshot(context.Background(), ws, snap); err != nil {
		t.Fatalf("workload scan: %v", err)
	}

	var multiRegion bool
	if err := db.Raw(`SELECT (sanitized_facts->>'is_multi_region_trail')::boolean FROM cloud_observation
	                    WHERE workspace_id = ? AND source_api = 'cloudtrail:DescribeTrails'`, ws).
		Row().Scan(&multiRegion); err != nil {
		t.Fatalf("trail config evidence not written: %v", err)
	}
	if !multiRegion {
		t.Fatal("expected is_multi_region_trail=true recorded from the fake trail")
	}

	var logging bool
	if err := db.Raw(`SELECT (sanitized_facts->>'is_logging')::boolean FROM cloud_observation
	                    WHERE workspace_id = ? AND source_api = 'cloudtrail:GetTrailStatus'`, ws).
		Row().Scan(&logging); err != nil {
		t.Fatalf("trail status evidence not written: %v", err)
	}
	if !logging {
		t.Fatal("expected is_logging=true recorded from the fake trail status")
	}
}

// --- IAM credential report ---------------------------------------------------

type fakeCredentialReport struct {
	csv string
}

func (f *fakeCredentialReport) GenerateCredentialReport(context.Context, *iam.GenerateCredentialReportInput, ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error) {
	return &iam.GenerateCredentialReportOutput{}, nil
}
func (f *fakeCredentialReport) GetCredentialReport(context.Context, *iam.GetCredentialReportInput, ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error) {
	return &iam.GetCredentialReportOutput{Content: []byte(f.csv)}, nil
}

type fakeDeniedCredentialReport struct{}

func (f *fakeDeniedCredentialReport) GenerateCredentialReport(context.Context, *iam.GenerateCredentialReportInput, ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error) {
	return nil, denied("iam:GenerateCredentialReport")
}
func (f *fakeDeniedCredentialReport) GetCredentialReport(context.Context, *iam.GetCredentialReportInput, ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error) {
	return nil, denied("iam:GetCredentialReport")
}

// The report adds MFA and password state, invisible to
// ListAccessKeys/GetAccessKeyLastUsed, as evidence against the user this same
// scan already wrote -- and a denied report must not block reconciling that
// user if it goes stale, since the report is not what makes the user real.
func TestCredentialReportIsRecordedAsEvidenceAndDoesNotGateIdentityReconciliation(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-credential-report")
	defer cleanWorkloadTables(t, db, ws)

	svc, connID, run := onboardWithRun(t, db, ws)
	evidence := services.NewObservationWriter(db, ws, connID, run.ID, run.Generation)

	header := "user,arn,password_enabled,password_last_used,mfa_active," +
		"access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date," +
		"access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date\n"
	row := "ci-deployer," + ciUserARN + ",false,N/A,true,true,2026-01-01T00:00:00Z,N/A,false,N/A,N/A\n"

	iamFake := populatedIAM()
	snap, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(iamFake).WithEvidence(evidence).
		WithCredentialReportAPI(&fakeCredentialReport{csv: header + row}, nil).
		Scan(context.Background(), ws, connID)
	if err != nil {
		t.Fatalf("iam scan: %v", err)
	}
	if !snap.Coverage.Complete() {
		t.Fatalf("credential report must not appear in snapshot.Coverage at all: %+v", snap.Coverage)
	}
	if snap.CredentialReportSurface.State != models.CloudCoverageReached {
		t.Fatalf("credential report surface = %+v, want reached", snap.CredentialReportSurface)
	}

	var mfaActive bool
	dberr := db.Raw(`SELECT sanitized_facts->>'mfa_active' = 'true'
	                    FROM cloud_observation
	                   WHERE workspace_id = ? AND source_api = 'iam:GetCredentialReport'`, ws).
		Row().Scan(&mfaActive)
	if dberr != nil {
		t.Fatalf("credential report evidence not written: %v", dberr)
	}
	if !mfaActive {
		t.Fatal("mfa_active fact was not preserved")
	}

	// Denied credential report: identity reconciliation must still run.
	runs := scanRuns(t, db)
	if _, err := runs.Enqueue(ws, connID, "manual"); err != nil {
		t.Fatalf("enqueue second run: %v", err)
	}
	run2, err := runs.Claim("test-worker-2", time.Minute, time.Now())
	if err != nil || run2 == nil {
		t.Fatalf("claim second run: %v %v", run2, err)
	}
	evidence2 := services.NewObservationWriter(db, ws, connID, run2.ID, run2.Generation)
	iamFake2 := populatedIAM()
	snap2, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(iamFake2).WithEvidence(evidence2).
		WithCredentialReportAPI(&fakeDeniedCredentialReport{}, nil).
		Scan(context.Background(), ws, connID)
	if err != nil {
		t.Fatalf("second iam scan: %v", err)
	}
	if !snap2.Coverage.Complete() {
		t.Fatalf("a denied credential report must not make identity scan report incomplete: %+v", snap2.Coverage)
	}
	if snap2.CredentialReportSurface.State == models.CloudCoverageReached {
		t.Fatal("test setup: credential report should have been denied")
	}
}

// --- Resource policies -------------------------------------------------------

type fakeS3Policy struct {
	policyByBucket map[string]string
}

func (f *fakeS3Policy) GetBucketPolicy(_ context.Context, in *s3.GetBucketPolicyInput, _ ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	p, ok := f.policyByBucket[aws.ToString(in.Bucket)]
	if !ok {
		// NoSuchBucketPolicy in production; a plain deny exercises the same
		// "could not read" path here without needing a smithy error type
		// with that exact code.
		return nil, denied("s3:GetBucketPolicy")
	}
	return &s3.GetBucketPolicyOutput{Policy: aws.String(p)}, nil
}

type fakeKMSPolicy struct{}

func (f *fakeKMSPolicy) GetKeyPolicy(context.Context, *kms.GetKeyPolicyInput, ...func(*kms.Options)) (*kms.GetKeyPolicyOutput, error) {
	return nil, denied("kms:GetKeyPolicy")
}

// A bucket policy naming an explicit Deny is the exact false positive the gap
// report described -- invisible before this fix, and here it is recorded as
// evidence with HasDeny true.
func TestResourcePolicyDenyIsRecordedAsEvidence(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-resource-policies")
	defer cleanPermissionTables(t, db, ws)

	svc, connID, run := onboardWithRun(t, db, ws)
	evidence := services.NewObservationWriter(db, ws, connID, run.ID, run.Generation)

	iamFake := populatedIAM()
	// A statement naming the bucket, so writePermissions creates the resource
	// and getOrCreateResource queues it for a policy check.
	iamFake.inlineRolePolicies["summarizer-agent"] = map[string]string{
		"read-reports": `{"Version":"2012-10-17","Statement":[
			{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::acme-reports"}
		]}`,
	}
	snap, err := services.NewAWSIAMScanner(db, svc).WithIAMAPI(iamFake).WithEvidence(evidence).
		Scan(context.Background(), ws, connID)
	if err != nil {
		t.Fatalf("iam scan: %v", err)
	}

	bucketPolicy := `{"Version":"2012-10-17","Statement":[
		{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::acme-reports/finance/*"}
	]}`
	s3fake := &fakeS3Policy{policyByBucket: map[string]string{"acme-reports": bucketPolicy}}

	permScanner := services.NewAWSPermissionScanner(db, svc).WithIAMAPI(iamFake).
		WithEKSAPI(newFakeEKS()).
		WithResourcePolicyAPIs(s3fake, &fakeKMSPolicy{}).WithEvidence(evidence)
	out, err := permScanner.ScanFromSnapshot(context.Background(), ws, snap)
	if err != nil {
		t.Fatalf("permission scan: %v", err)
	}
	if !out.Complete {
		t.Fatalf("a resource policy read must not gate permission scan completeness: %+v", out.Surfaces)
	}

	var hasDeny bool
	dberr := db.Raw(`SELECT sanitized_facts->>'has_deny' = 'true'
	                    FROM cloud_observation
	                   WHERE workspace_id = ? AND source_api = 's3:GetBucketPolicy'`, ws).
		Row().Scan(&hasDeny)
	if dberr != nil {
		t.Fatalf("resource policy evidence not written: %v", dberr)
	}
	if !hasDeny {
		t.Fatal("the bucket's explicit Deny statement was not recorded")
	}
}
