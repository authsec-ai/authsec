package integration

// Shared plumbing for the S3b scenarios (T3.5-T3.8): the P2-0 lab's REAL scan
// worker and REAL projector, with per-test fakes for the surfaces the lab's own
// hook leaves empty -- Bedrock, AgentCore, ECS, EC2, EKS, S3/KMS policies and
// Access Advisor. Everything here is prefixed s3b so it cannot collide with
// another stream's helpers in this package.

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	bedrockagenttypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/google/uuid"
)

// s3bFakes overrides the lab account's empty fakes. Any nil field keeps the
// lab default (an empty, successful surface).
type s3bFakes struct {
	bedrock   *fakeBedrock
	agentCore *fakeAgentCore
	ecs       *fakeECS
	ec2       *fakeEC2
	profiles  *fakeInstanceProfile
	eks       *fakeEKS
	s3        awsdiscovery.S3PolicyAPI
	kms       awsdiscovery.KMSPolicyAPI
	activity  awsdiscovery.ServiceLastAccessedAPI
	// cloudTrail answers every region's LookupEvents / DescribeTrails (nil
	// keeps an empty trail).
	cloudTrail *fakeCloudTrail
	// credentialCSV is the credential report's content ("" keeps the lab's
	// empty report).
	credentialCSV string
	// agentCoreAPI, when set, wins over agentCore: a wrapper that changes one
	// call's behaviour (s3bPagedTargets) around a fakeAgentCore.
	agentCoreAPI awsdiscovery.AgentCoreAPI
}

// hook is the lab account's hook with these overrides applied on top.
func (f *s3bFakes) hook(a *p2Account) services.ScannerHook {
	base := a.hook()
	return func(iamS *services.AWSIAMScanner, perm *services.AWSPermissionScanner, wl *services.AWSWorkloadScanner) {
		base(iamS, perm, wl)
		noSleep := func(context.Context, time.Duration) error { return nil }
		if f.credentialCSV != "" {
			iamS.WithCredentialReportAPI(&fakeCredentialReport{csv: f.credentialCSV}, noSleep)
		}
		if f.eks != nil {
			perm.WithEKSAPI(f.eks)
		}
		if f.s3 != nil || f.kms != nil {
			perm.WithResourcePolicyAPIs(f.s3, f.kms)
		}
		if f.activity != nil {
			wl.WithActivityAPI(f.activity, noSleep)
		}
		wl.WithRegionalAPIs(func(region string) (awsdiscovery.LambdaAPI, awsdiscovery.ECSAPI,
			awsdiscovery.EC2API, awsdiscovery.InstanceProfileAPI, awsdiscovery.BedrockAgentAPI,
			awsdiscovery.AgentCoreAPI, awsdiscovery.CloudTrailAPI) {
			var lam awsdiscovery.LambdaAPI = &fakeLambda{}
			if l := a.lambdas[region]; l != nil {
				lam = l
			}
			var ecsAPI awsdiscovery.ECSAPI = &fakeECS{defs: map[string]ecstypes.TaskDefinition{}}
			if f.ecs != nil {
				ecsAPI = f.ecs
			}
			var ec2API awsdiscovery.EC2API = &fakeEC2{}
			if f.ec2 != nil {
				ec2API = f.ec2
			}
			var prof awsdiscovery.InstanceProfileAPI = &fakeInstanceProfile{roleByProfileName: map[string]string{}}
			if f.profiles != nil {
				prof = f.profiles
			}
			var bed awsdiscovery.BedrockAgentAPI = &fakeBedrock{agents: map[string]bedrockagenttypes.Agent{}}
			if f.bedrock != nil {
				bed = f.bedrock
			}
			var core awsdiscovery.AgentCoreAPI = &fakeAgentCore{}
			if f.agentCore != nil {
				core = f.agentCore
			}
			if f.agentCoreAPI != nil {
				core = f.agentCoreAPI
			}
			trail := &fakeCloudTrail{}
			if f.cloudTrail != nil {
				trail = f.cloudTrail
			}
			return lam, ecsAPI, ec2API, prof, bed, core, trail
		})
	}
}

// s3bScan is p2Lab.scan with the overrides: ONE scan through the REAL worker,
// required to publish.
func s3bScan(l *p2Lab, a *p2Account, f *s3bFakes, owner string) models.CloudScanRun {
	l.t.Helper()
	queued, err := l.runs.Enqueue(l.ws, a.conn, "manual")
	if err != nil {
		l.t.Fatalf("enqueue: %v", err)
	}
	w := services.NewAWSScanWorker(l.db, a.svc).WithOwner(owner).
		WithGraphProjection(l.gate).WithScannerHook(f.hook(a))
	worked, err := w.RunOnce(context.Background())
	if err != nil || !worked {
		l.t.Fatalf("scan worker %s: worked=%v err=%v", owner, worked, err)
	}
	var run models.CloudScanRun
	if err := l.db.First(&run, "id = ?", queued.ID).Error; err != nil {
		l.t.Fatalf("read run: %v", err)
	}
	if run.Status != models.CloudScanRunPublished {
		l.t.Fatalf("run %s is %s (%s), want published", run.ID, run.Status, run.LastError)
	}
	return run
}

// s3bScanAndProject is one full cycle, fresh owner names on both sides, the
// projection required to complete on its first pass.
func s3bScanAndProject(l *p2Lab, a *p2Account, f *s3bFakes) models.CloudScanRun {
	l.t.Helper()
	scanSeq++
	run := s3bScan(l, a, f, fmt.Sprintf("scan-worker-s3b-%d", scanSeq))
	l.project(fmt.Sprintf("projector-s3b-%d", scanSeq))
	return run
}

// s3bRunCoverage is THIS run's coverage, as stamped at publication -- what the
// projector's canEnd consults.
func s3bRunCoverage(t *testing.T, l *p2Lab, runID uuid.UUID) models.ScanCoverage {
	t.Helper()
	var raw []byte
	if err := l.db.Raw(`SELECT coverage FROM cloud_scan_run WHERE id = ?`, runID).Row().Scan(&raw); err != nil {
		t.Fatalf("read run coverage: %v", err)
	}
	return models.DecodeScanCoverage(json.RawMessage(raw))
}

// s3bSurface returns one surface of a coverage report, failing when absent.
func s3bSurface(t *testing.T, cov models.ScanCoverage, name string) models.SurfaceCoverage {
	t.Helper()
	s, ok := cov.Surfaces[name]
	if !ok {
		t.Fatalf("coverage has no %q surface: %+v", name, cov.Surfaces)
	}
	return s
}

// s3bObservation is one cloud_observation row, for the evidence assertions.
type s3bObservation struct {
	ID                 uuid.UUID
	IdentityID         *uuid.UUID
	WorkloadID         *uuid.UUID
	SubjectNativeID    string
	SourceAPI          string
	Surface            string
	SanitizedFacts     []byte
	ConfirmationCount  int
	LastConfirmedRunID *uuid.UUID
}

func (o s3bObservation) facts(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(o.SanitizedFacts, &m); err != nil {
		t.Fatalf("decode facts of %s: %v", o.ID, err)
	}
	return m
}

// s3bObservations lists the workspace's observations from one source API.
func s3bObservations(t *testing.T, l *p2Lab, sourceAPI string) []s3bObservation {
	t.Helper()
	var out []s3bObservation
	if err := l.db.Raw(`SELECT id, identity_id, workload_id, subject_native_id, source_api, surface,
	                           sanitized_facts, confirmation_count, last_confirmed_run_id
	                      FROM cloud_observation WHERE workspace_id = ? AND source_api = ?
	                     ORDER BY ingested_at`, l.ws, sourceAPI).Scan(&out).Error; err != nil {
		t.Fatalf("read %s observations: %v", sourceAPI, err)
	}
	return out
}

// s3bEdgeEvidence is every observation id linked as evidence to any AWS
// grant, assignment or relationship in the workspace.
func s3bEdgeEvidence(t *testing.T, l *p2Lab) map[uuid.UUID]string {
	t.Helper()
	var rows []struct {
		ObservationID uuid.UUID
		Edge          string
	}
	if err := l.db.Raw(`
		SELECT e.observation_id, 'grant' AS edge FROM iga_access_edge_evidence e
		  JOIN iga_access_edges g ON g.id = e.access_edge_id WHERE g.workspace_id = ?
		UNION ALL
		SELECT e.observation_id, 'assignment' FROM iga_assignment_evidence e
		  JOIN iga_policy_assignment a ON a.id = e.assignment_id WHERE a.workspace_id = ?
		UNION ALL
		SELECT e.observation_id, 'relationship:' || r.relationship_type FROM iga_relationship_evidence e
		  JOIN iga_relationship r ON r.id = e.relationship_id WHERE r.workspace_id = ?`,
		l.ws, l.ws, l.ws).Scan(&rows).Error; err != nil {
		t.Fatalf("read edge evidence: %v", err)
	}
	out := map[uuid.UUID]string{}
	for _, r := range rows {
		out[r.ObservationID] = r.Edge
	}
	return out
}
