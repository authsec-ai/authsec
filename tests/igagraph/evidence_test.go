package igagraph_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

// The gap this file closes: every other fixture in this package builds a
// Snapshot by hand with an EMPTY ConfirmedBy, so attachEvidence has always run
// against an empty map and iga_access_edge_evidence has always come out 0 --
// which looks identical whether the evidence pipeline works or is dead. The
// original P2-2 defect (the scanner writing an unqualified subject key) would
// not have been caught here.
//
// This test drives the REAL chain end to end:
//
//	cloud_observation (qualified key)
//	  -> igagraph.Load populates ConfirmedBy
//	    -> attachEvidence links it
//	      -> iga_access_edge_evidence / iga_relationship_evidence
//
// and asserts the spec's own gate (§4.8): every projected edge has evidence.
func TestEvidenceIsAttachedThroughLoad(t *testing.T) {
	f := newFixture(t)
	gx := func(q string, a ...any) {
		if err := f.gorm.Exec(q, a...).Error; err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}

	const (
		roleARN   = "arn:aws:iam::1234:role/refund-lambda-role"
		lambdaARN = "arn:aws:lambda:eu-central-1:1234:function:refund-processor"
		bucketARN = "arn:aws:s3:::refunds-bucket/*"
		policyID  = "arn:aws:iam::1234:policy/RefundS3Access#s0"
	)
	roleID := uuid.New()
	lambdaID := uuid.New()
	bucketID := uuid.New()
	permID := uuid.New()

	run := f.publishedRun(f.connector, 1, cleanCoverage(region))
	gen := run.Generation

	// Inventory at this run's generation, exactly as the collectors would have
	// written it -- Load reads cloud_* WHERE connector_id = ? AND
	// last_seen_generation = ?.
	gx(`INSERT INTO cloud_identity
	          (id, workspace_id, connector_id, kind, native_id, name, attrs, last_seen_generation)
	        VALUES (?, ?, ?, 'iam_role', ?, 'refund-lambda-role', ?, ?)`,
		roleID, f.workspace, f.connector, roleARN, `{"unique_id":"AROAEVIDENCE0000001"}`, gen)
	gx(`INSERT INTO cloud_workload
	          (id, workspace_id, connector_id, identity_id, runtime_kind, native_id, name, region, last_seen_generation)
	        VALUES (?, ?, ?, ?, 'lambda_function', ?, 'refund-processor', ?, ?)`,
		lambdaID, f.workspace, f.connector, roleID, lambdaARN, region, gen)
	gx(`INSERT INTO cloud_resource
	          (id, workspace_id, connector_id, kind, native_id, name, last_seen_generation)
	        VALUES (?, ?, ?, 's3_bucket', ?, 'refunds-bucket', ?)`,
		bucketID, f.workspace, f.connector, bucketARN, gen)
	gx(`INSERT INTO cloud_permission
	          (id, workspace_id, connector_id, identity_id, resource_id, effect, actions, scope_kind, native_id, last_seen_generation)
	        VALUES (?, ?, ?, ?, ?, 'allow', '{"s3:GetObject"}', 'resource', ?, ?)`,
		permID, f.workspace, f.connector, roleID, bucketID, policyID, gen)

	// The evidence rows, keyed the way the scanner now writes them. The
	// permission key is FULLY QUALIFYING (holder | statement | resource);
	// indexObservations skips an unqualified permission key, so this is the
	// difference between evidence and none.
	permKey := igagraph.PermissionSubjectKey(
		models.CloudPermission{NativeID: policyID}, roleARN, bucketARN)
	gx(`INSERT INTO cloud_observation
	          (workspace_id, connector_id, scan_run_id, generation, permission_id,
	           source_api, surface, surface_state, observed_at, content_hash,
	           subject_native_id, last_confirmed_run_id, last_confirmed_at)
	        VALUES (?, ?, ?, ?, ?, 'iam:GetRolePolicy', 'iam_policies', 'reached',
	                now(), 'h-perm', ?, ?, now())`,
		f.workspace, f.connector, run.ID, gen, permID, permKey, run.ID)

	// A workload observation, so the derived executes_as edge gets evidence
	// too -- its key is the bare workload ARN (workload keys are not qualified).
	gx(`INSERT INTO cloud_observation
	          (workspace_id, connector_id, scan_run_id, generation, workload_id,
	           source_api, surface, surface_state, observed_at, content_hash,
	           subject_native_id, last_confirmed_run_id, last_confirmed_at)
	        VALUES (?, ?, ?, ?, ?, 'lambda:ListFunctions', 'lambda:eu-central-1', 'reached',
	                now(), 'h-wl', ?, ?, now())`,
		f.workspace, f.connector, run.ID, gen, lambdaID, lambdaARN, run.ID)

	// THE REAL LOAD. This is what populates ConfirmedBy from cloud_observation
	// -- the step every other fixture skips.
	snap, err := igagraph.Load(t.Context(), f.gorm, run.ID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Guard against a silently-empty map: if Load found no confirmed
	// observations, the rest of the test would pass vacuously with 0 evidence.
	if len(snap.ConfirmedBy) == 0 {
		t.Fatal("Load populated no ConfirmedBy entries -- the evidence path cannot run")
	}

	f.mustProject(snap)

	// The access edge exists AND carries evidence.
	edges := f.scalar(`SELECT count(*) FROM iga_access_edges WHERE state <> 'ended'`)
	if edges == 0 {
		t.Fatal("no access edge projected")
	}
	edgeEvidence := f.scalar(`SELECT count(*) FROM iga_access_edge_evidence`)
	if edgeEvidence == 0 {
		t.Fatal("access edge got NO evidence -- the observation -> edge chain is dead")
	}

	// SPEC §4.8 GATE: every projected access edge has at least one evidence
	// row. Counted per edge, not per class -- one evidenced edge and ten
	// thousand bare ones would pass a per-class check.
	bare := f.scalar(`
		SELECT count(*) FROM iga_access_edges e
		 WHERE e.state <> 'ended'
		   AND NOT EXISTS (SELECT 1 FROM iga_access_edge_evidence ev
		                    WHERE ev.workspace_id = e.workspace_id
		                      AND ev.access_edge_id = e.id)`)
	if bare != 0 {
		t.Errorf("%d projected access edges have no evidence; the §4.8 gate is count == 0", bare)
	}

	// The derived executes_as relationship carries its workload's evidence.
	relEvidence := f.scalar(`
		SELECT count(*) FROM iga_relationship_evidence ev
		  JOIN iga_relationship r ON r.id = ev.relationship_id
		 WHERE r.relationship_type = 'executes_as'`)
	if relEvidence == 0 {
		t.Error("the executes_as relationship got no evidence from its workload observation")
	}
}

// The negative pair: an UNQUALIFIED permission observation must attach NO
// evidence -- proving the qualified-key requirement is what carries the
// evidence, not some incidental match. Same shape as the denied-scan /
// clean-scan non-vacuity pair the spec demands.
func TestUnqualifiedObservationAttachesNoEvidence(t *testing.T) {
	f := newFixture(t)
	gx := func(q string, a ...any) {
		if err := f.gorm.Exec(q, a...).Error; err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}

	const (
		roleARN  = "arn:aws:iam::1234:role/r"
		bucket   = "arn:aws:s3:::b/*"
		policyID = "arn:aws:iam::1234:policy/P#s0"
	)
	roleID := uuid.New()
	bucketID := uuid.New()
	permID := uuid.New()
	run := f.publishedRun(f.connector, 1, cleanCoverage(region))
	gen := run.Generation

	gx(`INSERT INTO cloud_identity (id, workspace_id, connector_id, kind, native_id, name, attrs, last_seen_generation)
	        VALUES (?, ?, ?, 'iam_role', ?, 'r', ?, ?)`, roleID, f.workspace, f.connector, roleARN, `{"unique_id":"AROAEVIDENCE0000002"}`, gen)
	gx(`INSERT INTO cloud_resource (id, workspace_id, connector_id, kind, native_id, name, last_seen_generation)
	        VALUES (?, ?, ?, 's3_bucket', ?, 'b', ?)`, bucketID, f.workspace, f.connector, bucket, gen)
	gx(`INSERT INTO cloud_permission
	          (id, workspace_id, connector_id, identity_id, resource_id, effect, actions, scope_kind, native_id, last_seen_generation)
	        VALUES (?, ?, ?, ?, ?, 'allow', '{"s3:GetObject"}', 'resource', ?, ?)`,
		permID, f.workspace, f.connector, roleID, bucketID, policyID, gen)

	// The PRE-P2-2 shape: a bare nativeID, no unit separator.
	gx(`INSERT INTO cloud_observation
	          (workspace_id, connector_id, scan_run_id, generation, permission_id,
	           source_api, surface, surface_state, observed_at, content_hash,
	           subject_native_id, last_confirmed_run_id, last_confirmed_at)
	        VALUES (?, ?, ?, ?, ?, 'iam:GetRolePolicy', 'iam_policies', 'reached',
	                now(), 'h', ?, ?, now())`,
		f.workspace, f.connector, run.ID, gen, permID, policyID, run.ID)

	snap, err := igagraph.Load(t.Context(), f.gorm, run.ID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Load must have SKIPPED the unqualified permission observation.
	if len(snap.ConfirmedBy) != 0 {
		t.Fatalf("an unqualified permission observation must not be indexed, got %d", len(snap.ConfirmedBy))
	}
	f.mustProject(snap)

	if n := f.scalar(`SELECT count(*) FROM iga_access_edge_evidence`); n != 0 {
		t.Errorf("an unqualified observation attached %d evidence rows; it must attach none", n)
	}
	// The edge itself is still projected -- absence of evidence is a defect the
	// gate catches, not a reason to drop the grant.
	if n := f.scalar(`SELECT count(*) FROM iga_access_edges`); n == 0 {
		t.Error("the access edge must still be projected even with no attributable evidence")
	}
}
