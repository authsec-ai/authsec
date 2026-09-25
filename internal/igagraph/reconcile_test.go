package igagraph

import (
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// snapWith builds a published run whose coverage report is exactly `surfaces`.
func snapWith(surfaces map[string]models.SurfaceCoverage) *Snapshot {
	return &Snapshot{
		Run: models.CloudScanRun{
			ID: uuid.New(), WorkspaceID: uuid.New(), ConnectorID: uuid.New(),
			Status: models.CloudScanRunPublished, Generation: 7,
		},
		ScopeID:  uuid.New(),
		Coverage: surfaces,
	}
}

func reached(n int) models.SurfaceCoverage {
	return models.SurfaceCoverage{State: models.CloudCoverageReached, Count: n}
}

func denied() models.SurfaceCoverage {
	return models.SurfaceCoverage{State: models.CloudCoverageDenied, Error: "AccessDenied"}
}

// entitlementPart is the partition the parse-failure tests turn on.
func entitlementPart(snap *Snapshot) Partition {
	return Partition{
		ScopeID: snap.ScopeID, ConnectorID: snap.Run.ConnectorID,
		Class: models.ObjectEntitlement,
		RequiredSurfaces: []string{
			models.SurfaceIAMRoles, models.SurfaceIAMPolicies, models.SurfacePolicyDocuments},
		RequiredScanners: []string{models.SurfacePermissionScan},
	}
}

func identityRolesPart(snap *Snapshot) Partition {
	return Partition{
		ScopeID: snap.ScopeID, ConnectorID: snap.Run.ConnectorID,
		Class: models.ObjectIdentity, RequiredSurfaces: []string{models.SurfaceIAMRoles},
	}
}

// P2-7 gate 1: a DENIED scan never ends anything.
//
// A denied surface produces no rows, so every relationship behind it looks
// absent. Collapsing that into `ended` lets a permissions outage read as a
// successful cleanup.
func TestCanEndRefusesDeniedSurface(t *testing.T) {
	snap := snapWith(map[string]models.SurfaceCoverage{
		models.SurfaceIAMRoles: denied(),
	})
	rc := NewReconciler(nil)
	if rc.CanEnd(snap, identityRolesPart(snap)) {
		t.Fatal("a denied iam_roles read must not license closing identities")
	}
}

// NON-VACUITY for the test above: the SAME fixture with coverage complete DOES
// permit ending. Without this, a canEnd that returned false unconditionally
// would pass every test in this file.
func TestCanEndAllowsCleanSurface(t *testing.T) {
	snap := snapWith(map[string]models.SurfaceCoverage{
		models.SurfaceIAMRoles: reached(12),
	})
	rc := NewReconciler(nil)
	if !rc.CanEnd(snap, identityRolesPart(snap)) {
		t.Fatal("a reached iam_roles read must license closing identities")
	}
}

// P2-7 gate 2: a THROTTLED surface is stale, not ended.
func TestCanEndRefusesThrottledSurface(t *testing.T) {
	snap := snapWith(map[string]models.SurfaceCoverage{
		models.SurfaceIAMRoles: {State: models.CloudCoverageThrottled},
	})
	if NewReconciler(nil).CanEnd(snap, identityRolesPart(snap)) {
		t.Fatal("a throttled read must not license closing anything")
	}
}

// P2-7 gate 3: an ABSENT surface report means DID NOT LOOK.
//
// Any other reading makes a scan that never attempted a surface
// indistinguishable from one that read it and found nothing.
func TestCanEndRefusesAbsentSurface(t *testing.T) {
	snap := snapWith(map[string]models.SurfaceCoverage{})
	if NewReconciler(nil).CanEnd(snap, identityRolesPart(snap)) {
		t.Fatal("an absent surface report must not license closing anything")
	}
}

// P2-7 gate 4: ONE PARSE FAILURE in the owning scope closes nothing.
//
// ParseFailures/StatementsSkipped are folded into the policy_documents surface
// STATE upstream (cloud_aws_permission_scan.go), before the report is stamped.
// So a run that dropped a statement never reports policy_documents as
// `reached`, and canEnd sees that without re-deriving anything.
func TestCanEndRefusesParseFailure(t *testing.T) {
	snap := snapWith(map[string]models.SurfaceCoverage{
		models.SurfaceIAMRoles:        reached(12),
		models.SurfaceIAMPolicies:     reached(30),
		models.SurfacePolicyDocuments: {State: models.CloudCoveragePartial, Error: "1 statement unparseable"},
	})
	if NewReconciler(nil).CanEnd(snap, entitlementPart(snap)) {
		t.Fatal("a partial policy_documents surface must not license closing entitlements")
	}
}

// NON-VACUITY for the parse-failure test: with policy_documents ABSENT --
// meaning nothing was dropped -- and the scanner proven to have run, the same
// partition DOES close.
func TestCanEndAllowsCleanParse(t *testing.T) {
	snap := snapWith(map[string]models.SurfaceCoverage{
		models.SurfaceIAMRoles:    reached(12),
		models.SurfaceIAMPolicies: reached(30),
		// policy_documents absent: the permission scanner writes it ONLY when
		// parsing dropped something.
	})
	if !NewReconciler(nil).CanEnd(snap, entitlementPart(snap)) {
		t.Fatal("a clean parse must license closing entitlements")
	}
}

// THE FIXTURE THE WHOLE RequiredScanners MECHANISM EXISTS FOR.
//
// policy_documents is written only on failure, so its absence is AMBIGUOUS:
// either parsing was clean, or parsing never happened. A bare "absent means
// clean" rule closes entitlements here, on a run whose permission scanner
// DIED before it parsed anything.
//
//	iam_roles        reached
//	iam_policies     reached
//	permission_scan  denied      <- the scanner died before parsing
//	policy_documents absent
func TestCanEndRefusesWhenScannerDiedBeforeParsing(t *testing.T) {
	snap := snapWith(map[string]models.SurfaceCoverage{
		models.SurfaceIAMRoles:       reached(12),
		models.SurfaceIAMPolicies:    reached(30),
		models.SurfacePermissionScan: denied(),
	})
	if NewReconciler(nil).CanEnd(snap, entitlementPart(snap)) {
		t.Fatal("permission_scan present-and-failed must veto the entitlement partition")
	}

	// And it must NOT veto a partition that does not depend on that scanner --
	// a dead permission scanner says nothing about whether IAM roles were read.
	if !NewReconciler(nil).CanEnd(snap, identityRolesPart(snap)) {
		t.Fatal("a dead permission scanner must not block identity reconciliation")
	}
}

// A workload partition is vetoed by compute:<region>, which is the stand-in
// written when a region's client config failed or the region was never
// selected. Its PRESENCE proves the per-service reads never ran.
func TestCanEndRefusesWhenRegionUnreachable(t *testing.T) {
	snap := snapWith(map[string]models.SurfaceCoverage{
		models.SurfaceCompute("eu-central-1"): {State: models.CloudCoverageNotSelected},
	})
	part := Partition{
		ScopeID: snap.ScopeID, ConnectorID: snap.Run.ConnectorID,
		Class:            models.ObjectWorkload,
		RequiredSurfaces: []string{"lambda:eu-central-1"},
		RequiredScanners: []string{models.SurfaceWorkloadScan, models.SurfaceCompute("eu-central-1")},
	}
	if NewReconciler(nil).CanEnd(snap, part) {
		t.Fatal("an unselected region must not license closing its workloads")
	}
}

// P2-7 gate 5: a run that is not PUBLISHED closes nothing, whatever its
// coverage says. The value is 'published' -- cloud_scan_run's CHECK has no
// 'complete'.
func TestCanEndRefusesUnpublishedRun(t *testing.T) {
	snap := snapWith(map[string]models.SurfaceCoverage{
		models.SurfaceIAMRoles: reached(12),
	})
	for _, status := range []string{
		models.CloudScanRunQueued, models.CloudScanRunRunning,
		models.CloudScanRunFailed, models.CloudScanRunAbandoned,
	} {
		snap.Run.Status = status
		if NewReconciler(nil).CanEnd(snap, identityRolesPart(snap)) {
			t.Fatalf("status %q must not license closing anything", status)
		}
	}
}

// Per-region independence: a denied read in one region must not affect
// another's. These are separate partitions with separate keys, which is what
// stops one region's outage closing another region's workloads.
func TestRegionPartitionsAreIndependent(t *testing.T) {
	snap := snapWith(map[string]models.SurfaceCoverage{
		"lambda:us-east-1":                    reached(3),
		models.SurfaceCompute("eu-central-1"): denied(),
	})
	rc := NewReconciler(nil)

	clean := Partition{
		ScopeID: snap.ScopeID, ConnectorID: snap.Run.ConnectorID,
		Class: models.ObjectWorkload, RequiredSurfaces: []string{"lambda:us-east-1"},
		RequiredScanners: []string{models.SurfaceWorkloadScan, models.SurfaceCompute("us-east-1")},
	}
	broken := Partition{
		ScopeID: snap.ScopeID, ConnectorID: snap.Run.ConnectorID,
		Class: models.ObjectWorkload, RequiredSurfaces: []string{"lambda:eu-central-1"},
		RequiredScanners: []string{models.SurfaceWorkloadScan, models.SurfaceCompute("eu-central-1")},
	}
	if !rc.CanEnd(snap, clean) {
		t.Fatal("the clean region must still close")
	}
	if rc.CanEnd(snap, broken) {
		t.Fatal("the denied region must not close")
	}
	if clean.Key() == broken.Key() {
		t.Fatal("two regions must not share a partition key, or one watermark overwrites the other")
	}
}

// Partition keys must separate every partition that reconciles independently.
// Sharing a key means one partition's watermark overwrites another's, which
// licenses closing relationships nothing in the run looked at.
func TestPartitionKeysAreDistinct(t *testing.T) {
	snap := snapWith(map[string]models.SurfaceCoverage{
		"lambda:us-east-1": reached(1), "ecs:us-east-1": reached(1),
		"ec2:us-east-1": reached(1), "bedrock-agents:us-east-1": reached(1),
		"bedrock-agentcore:us-east-1": reached(1), "lambda:eu-west-1": reached(1),
		"ecs:eu-west-1": reached(1), "ec2:eu-west-1": reached(1),
		"bedrock-agents:eu-west-1": reached(1), "bedrock-agentcore:eu-west-1": reached(1),
	})
	parts := Partitions(snap)
	seen := map[string]Partition{}
	for _, p := range parts {
		if prev, dup := seen[p.Key()]; dup {
			t.Fatalf("duplicate partition key %q shared by %+v and %+v", p.Key(), prev, p)
		}
		seen[p.Key()] = p
	}
	// Roles and users must be separate, or a denied iam_users read blocks role
	// reconciliation.
	roles := Partition{ScopeID: snap.ScopeID, ConnectorID: snap.Run.ConnectorID,
		Class: models.ObjectIdentity, RequiredSurfaces: []string{models.SurfaceIAMRoles}}
	users := Partition{ScopeID: snap.ScopeID, ConnectorID: snap.Run.ConnectorID,
		Class: models.ObjectIdentity, RequiredSurfaces: []string{models.SurfaceIAMUsers}}
	if roles.Key() == users.Key() {
		t.Fatal("iam_roles and iam_users must not share a partition key")
	}
}

// Every surface a partition requires must be a name a coverage report can
// actually contain. A typo here can NEVER satisfy canEnd, so its rows stay
// stale forever -- silent, and it looks like working caution.
func TestPartitionVocabularyIsKnown(t *testing.T) {
	snap := snapWith(map[string]models.SurfaceCoverage{
		"lambda:us-east-1": reached(1), "ecs:us-east-1": reached(1),
		"ec2:us-east-1": reached(1), "bedrock-agents:us-east-1": reached(1),
		"bedrock-agentcore:us-east-1": reached(1),
	})
	if bad := AssertPartitionVocabulary(Partitions(snap), snap.RegionsAttempted()); len(bad) > 0 {
		t.Fatalf("partitions name surfaces no report can contain: %v", bad)
	}
	// Non-vacuity: a deliberately wrong name IS caught.
	rogue := []Partition{{RequiredSurfaces: []string{"iam_rolez"}}}
	if bad := AssertPartitionVocabulary(rogue, nil); len(bad) != 1 || bad[0] != "iam_rolez" {
		t.Fatalf("a typo'd surface must be reported, got %v", bad)
	}
}

// compute:<region> must never be treated as a success surface. If it were in
// RequiredSurfaces, a clean region -- which never writes that key -- could
// never close, and every workload would stay stale forever.
func TestComputeStandInIsNeverRequiredAsSurface(t *testing.T) {
	snap := snapWith(map[string]models.SurfaceCoverage{"lambda:us-east-1": reached(1)})
	for _, p := range Partitions(snap) {
		for _, s := range p.RequiredSurfaces {
			if len(s) > len(models.SurfaceComputePrefix) && s[:len(models.SurfaceComputePrefix)] == models.SurfaceComputePrefix {
				t.Fatalf("partition %q requires the compute stand-in as a surface: %q", p.Key(), s)
			}
		}
	}
}
