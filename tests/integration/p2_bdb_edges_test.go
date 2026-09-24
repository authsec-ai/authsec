package integration

// T4.4 (SPEC-iga-phase2-graph.md §4.6, §4.10 Partitions, §4.8 evidence):
// member_of and ECS's task_execution_role, end to end through the REAL scan
// worker and projector -- written with the right endpoints and evidence,
// confirmed in place by an unchanged rescan, ended by their partition when the
// configuration goes away, kept stale (never ended) when the surface that
// would prove the absence was not read, and re-confirmed in place when it is
// read again. Neither edge had a test of its own through the pipeline.

import (
	"strings"
	"testing"
	"time"

	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// bdbRel is one relationship with its endpoints named: the source workload's
// ARN (from its source key) or the source identity's name, and the target
// identity's name.
type bdbRel struct {
	ID              uuid.UUID
	Type            string
	Source          string
	Target          string
	State           string
	ValidFrom       time.Time
	ValidTo         *time.Time
	EndedReason     string
	LastConfirmedAt time.Time
	LastConfirmedBy *uuid.UUID
	PartitionKey    string
	ConnectorID     *uuid.UUID
}

// bdbRels is every relationship of these types in the workspace, oldest first.
func bdbRels(t *testing.T, l *p2Lab, types ...string) []bdbRel {
	t.Helper()
	var out []bdbRel
	if err := l.db.Raw(`
		SELECT r.id, r.relationship_type AS type,
		       COALESCE(split_part(w.source_key, chr(31), 2), si.display_name, '') AS source,
		       ti.display_name AS target, r.state, r.valid_from, r.valid_to, r.ended_reason,
		       r.last_confirmed_at, r.last_confirmed_by, r.partition_key, r.connector_id
		  FROM iga_relationship r
		  LEFT JOIN iga_workload w ON w.workspace_id = r.workspace_id AND w.id = r.source_workload_id
		  LEFT JOIN iga_identity_accounts si ON si.workspace_id = r.workspace_id AND si.id = r.source_identity_account_id
		  JOIN iga_identity_accounts ti ON ti.workspace_id = r.workspace_id AND ti.id = r.target_identity_account_id
		 WHERE r.workspace_id = ? AND r.relationship_type IN ?
		 ORDER BY r.valid_from, r.relationship_type, source, r.id`, l.ws, types).Scan(&out).Error; err != nil {
		t.Fatalf("read relationships: %v", err)
	}
	return out
}

// bdbRelOf is the one relationship of this type between these endpoints in
// this state ("" = any state); zero or several fail the test.
func bdbRelOf(t *testing.T, rels []bdbRel, typ, source, target, state string) bdbRel {
	t.Helper()
	var hit []bdbRel
	for _, r := range rels {
		if r.Type == typ && r.Source == source && r.Target == target && (state == "" || r.State == state) {
			hit = append(hit, r)
		}
	}
	if len(hit) != 1 {
		t.Fatalf("%s %s -> %s (%s): %d rows, want exactly 1; all: %+v", typ, source, target, state, len(hit), rels)
	}
	return hit[0]
}

// bdbObs is one observation an edge's evidence links to.
type bdbObs struct {
	Subject       string
	SourceAPI     string
	ConfirmedBy   *uuid.UUID
	ConnectorID   uuid.UUID
	ObservationID uuid.UUID
}

// bdbEvidenceOf is every 'supports' observation of one edge. table is the
// junction (iga_relationship_evidence, iga_access_edge_evidence,
// iga_assignment_evidence) and column its edge column.
func bdbEvidenceOf(t *testing.T, l *p2Lab, table, column string, edge uuid.UUID) []bdbObs {
	t.Helper()
	var out []bdbObs
	if err := l.db.Raw(`SELECT o.subject_native_id AS subject, o.source_api, o.last_confirmed_run_id AS confirmed_by,
	                           o.connector_id, o.id AS observation_id
	                      FROM `+table+` e
	                      JOIN cloud_observation o ON o.workspace_id = e.workspace_id AND o.id = e.observation_id
	                     WHERE e.workspace_id = ? AND e.`+column+` = ? AND e.relation = 'supports'
	                     ORDER BY o.subject_native_id, o.source_api`, l.ws, edge).Scan(&out).Error; err != nil {
		t.Fatalf("evidence of %s: %v", edge, err)
	}
	return out
}

// bdbRequireEvidence asserts a relationship's evidence: at least one link,
// every link an observation of `subject`, and one of them confirmed by the
// run that last confirmed the edge (the fact the edge stands on NOW, D-24).
func bdbRequireEvidence(t *testing.T, l *p2Lab, rel bdbRel, subject string) {
	t.Helper()
	ev := bdbEvidenceOf(t, l, "iga_relationship_evidence", "relationship_id", rel.ID)
	if len(ev) == 0 {
		t.Errorf("%s %s -> %s has no evidence (T4.9)", rel.Type, rel.Source, rel.Target)
		return
	}
	current := false
	for _, o := range ev {
		if o.Subject != subject {
			t.Errorf("%s %s -> %s: evidence observes %q, want %q", rel.Type, rel.Source, rel.Target, o.Subject, subject)
		}
		current = current || sameRun(o.ConfirmedBy, rel.LastConfirmedBy)
	}
	if !current {
		t.Errorf("%s %s -> %s: no evidence confirmed by its confirming run %v: %+v",
			rel.Type, rel.Source, rel.Target, rel.LastConfirmedBy, ev)
	}
}

// T4.4: member_of and task_execution_role through five cycles.
//
//  1. billing:1 runs as BillingTaskRole and ECS pulls its image as
//     ImagePullRole; priya and kim are in ops. One executes_as, one
//     task_execution_role (to the EXECUTION role, never the task role), two
//     member_of -- each in its own partition, with the workload's or the user's
//     observation as evidence.
//  2. Unchanged: the same four rows, confirmed in place by the new run.
//  3. billing:2 is registered with ImagePullRoleV2 and billing:1 deregistered;
//     kim leaves ops. billing:1's two edges and kim's membership END not_seen at
//     this pass (their partitions close them, D-67); billing:2's edges are NEW
//     rows; priya's membership is the same row.
//  4. The ECS listing and the IAM Group listing are DENIED. Nothing ends: the
//     three live edges go stale with last_confirmed_at untouched (§4.10).
//  5. Read again: the SAME rows are current again -- stale is a state of a row,
//     never a reason to write a new one.
//
// Safeguards (mutation-checked): task_execution_role targets ECS's execution
// role (projectExecution); member_of's partition requires iam_groups and
// task_execution_role's requires ecs:<region> (Partitions); and the
// task_execution_role edge is handed to the evidence pass.
func TestP2BdbMemberOfAndTaskExecutionRole(t *testing.T) {
	l := newP2Lab(t, "p2-bdb-t44", true)
	a := l.account(accountA)
	taskRole := a.role("BillingTaskRole", "AROABILLINGTASKROLE1")
	pull := a.role("ImagePullRole", "AROAIMAGEPULLROLE001")
	pull2 := a.role("ImagePullRoleV2", "AROAIMAGEPULLROLE002")
	s3aGroup(a, "ops", "AGPAOPSOPSOPSOPSOPS1")
	priya := s3aUser(a, "priya", "AIDAPRIYAPRIYAPRIYA1")
	kim := s3aUser(a, "kim", "AIDAKIMKIMKIMKIMKIM1")
	s3aJoin(a, "priya", "ops")
	s3aJoin(a, "kim", "ops")
	billing1 := bdbTaskDef(a, "us-east-1", "billing", 1, taskRole, pull)
	billing1ARN := *billing1.TaskDefinitionArn
	types := []string{models.RelTypeExecutesAs, models.RelTypeTaskExecutionRole, models.RelTypeMemberOf}
	// The observation each edge stands on: the user's for member_of (it lists
	// the group), the workload's own for its execution identities (§4.8).
	subjectOf := func(r bdbRel) string {
		switch r.Source {
		case "priya":
			return priya
		case "kim":
			return kim
		}
		return r.Source // a workload, named by its ARN
	}

	// 1. The first cycle.
	run1 := bdbCycle(l, a, bdbFakes{ecs: []ecstypes.TaskDefinition{billing1}})
	rels := bdbRels(t, l, types...)
	if len(rels) != 4 {
		t.Fatalf("relationships = %+v, want executes_as, task_execution_role and two member_of", rels)
	}
	exec1 := bdbRelOf(t, rels, models.RelTypeExecutesAs, billing1ARN, "BillingTaskRole", models.RelCurrent)
	pull1 := bdbRelOf(t, rels, models.RelTypeTaskExecutionRole, billing1ARN, "ImagePullRole", models.RelCurrent)
	mPriya := bdbRelOf(t, rels, models.RelTypeMemberOf, "priya", "ops", models.RelCurrent)
	mKim := bdbRelOf(t, rels, models.RelTypeMemberOf, "kim", "ops", models.RelCurrent)
	for _, r := range []bdbRel{exec1, pull1, mPriya, mKim} {
		if !sameRun(r.LastConfirmedBy, &run1.ID) || r.ConnectorID == nil || *r.ConnectorID != a.conn {
			t.Errorf("%s %s -> %s: confirmed by %v, connector %v; want run %s of connector %s",
				r.Type, r.Source, r.Target, r.LastConfirmedBy, r.ConnectorID, run1.ID, a.conn)
		}
	}
	bdbRequireEvidence(t, l, exec1, subjectOf(exec1))
	bdbRequireEvidence(t, l, pull1, subjectOf(pull1))
	bdbRequireEvidence(t, l, mPriya, subjectOf(mPriya))
	bdbRequireEvidence(t, l, mKim, subjectOf(mKim))
	if t.Failed() {
		t.FailNow()
	}

	// 2. Unchanged: confirmed in place.
	time.Sleep(10 * time.Millisecond)
	run2 := bdbCycle(l, a, bdbFakes{ecs: []ecstypes.TaskDefinition{billing1}})
	rels = bdbRels(t, l, types...)
	if len(rels) != 4 {
		t.Fatalf("relationships after an unchanged rescan = %+v, want the same four", rels)
	}
	for _, before := range []bdbRel{exec1, pull1, mPriya, mKim} {
		r := bdbRelOf(t, rels, before.Type, before.Source, before.Target, models.RelCurrent)
		if r.ID != before.ID || !r.ValidFrom.Equal(before.ValidFrom) || !sameRun(r.LastConfirmedBy, &run2.ID) {
			t.Errorf("%s %s -> %s after an unchanged rescan = %+v, want the same row %s confirmed by run %s",
				r.Type, r.Source, r.Target, r, before.ID, run2.ID)
		}
		bdbRequireEvidence(t, l, r, subjectOf(r))
	}

	// 3. A new revision with a new execution role; kim leaves the group.
	billing2 := bdbTaskDef(a, "us-east-1", "billing", 2, taskRole, pull2)
	billing2ARN := *billing2.TaskDefinitionArn
	a.iam.userGroups["kim"] = nil
	time.Sleep(10 * time.Millisecond)
	run3 := bdbCycle(l, a, bdbFakes{ecs: []ecstypes.TaskDefinition{billing2}})
	at3 := bdbPublishedAt(t, l, run3.ID)
	rels = bdbRels(t, l, types...)
	for _, gone := range []bdbRel{exec1, pull1, mKim} {
		r := bdbRelOf(t, rels, gone.Type, gone.Source, gone.Target, "")
		if r.ID != gone.ID || r.State != models.RelEnded || r.ValidTo == nil || !r.ValidTo.Equal(at3) ||
			r.EndedReason != models.EndedNotSeen {
			t.Errorf("%s %s -> %s after it went away = %+v, want row %s ended not_seen at %s",
				gone.Type, gone.Source, gone.Target, r, gone.ID, at3)
		}
	}
	exec2 := bdbRelOf(t, rels, models.RelTypeExecutesAs, billing2ARN, "BillingTaskRole", models.RelCurrent)
	pullV2 := bdbRelOf(t, rels, models.RelTypeTaskExecutionRole, billing2ARN, "ImagePullRoleV2", models.RelCurrent)
	for _, r := range []bdbRel{exec2, pullV2} {
		if r.ID == exec1.ID || r.ID == pull1.ID || !r.ValidFrom.Equal(at3) {
			t.Errorf("%s %s -> %s = %+v, want a NEW row starting at %s", r.Type, r.Source, r.Target, r, at3)
		}
		bdbRequireEvidence(t, l, r, subjectOf(r))
	}
	if r := bdbRelOf(t, rels, models.RelTypeMemberOf, "priya", "ops", models.RelCurrent); r.ID != mPriya.ID {
		t.Errorf("priya's membership = %+v, want the same row %s", r, mPriya.ID)
	}
	for _, r := range rels {
		if r.State != models.RelEnded && r.Target == "ImagePullRole" {
			t.Errorf("%s %s -> ImagePullRole is still %s: nothing uses it as an execution role now", r.Type, r.Source, r.State)
		}
	}
	if len(rels) != 6 {
		t.Errorf("relationships after the change = %d rows, want 6 (three ended, three live): %+v", len(rels), rels)
	}
	if t.Failed() {
		t.FailNow()
	}
	live := []bdbRel{exec2, pullV2, bdbRelOf(t, rels, models.RelTypeMemberOf, "priya", "ops", models.RelCurrent)}

	// 4. ECS and the Group listing denied: stale, never ended.
	a.iam.fail["GetAccountAuthorizationDetails:Group"] = denied("iam:GetAccountAuthorizationDetails")
	time.Sleep(10 * time.Millisecond)
	run4 := bdbCycle(l, a, bdbFakes{ecs: []ecstypes.TaskDefinition{billing2}, ecsFail: denied("ecs:ListTaskDefinitions")})
	cov := models.DecodeScanCoverage(run4.Coverage).Surfaces
	if cov["ecs:us-east-1"].State == models.CloudCoverageReached || cov[models.SurfaceIAMGroups].State == models.CloudCoverageReached ||
		cov[models.SurfaceIAMUsers].State != models.CloudCoverageReached || cov[models.SurfaceIAMRoles].State != models.CloudCoverageReached {
		t.Fatalf("setup: coverage = ecs %+v, groups %+v, users %+v, roles %+v; want ecs and groups not reached, users and roles reached",
			cov["ecs:us-east-1"], cov[models.SurfaceIAMGroups], cov[models.SurfaceIAMUsers], cov[models.SurfaceIAMRoles])
	}
	rels = bdbRels(t, l, types...)
	if len(rels) != 6 {
		t.Errorf("relationships on the denied rescan = %d rows, want the same 6: %+v", len(rels), rels)
	}
	for _, before := range live {
		r := bdbRelOf(t, rels, before.Type, before.Source, before.Target, "")
		if r.ID != before.ID || r.State != models.RelStale || r.ValidTo != nil ||
			!r.LastConfirmedAt.Equal(before.LastConfirmedAt) || !sameRun(r.LastConfirmedBy, &run3.ID) {
			t.Errorf("%s %s -> %s on the denied rescan = %+v, want row %s STALE, last confirmed by run %s at %s",
				r.Type, r.Source, r.Target, r, before.ID, run3.ID, before.LastConfirmedAt)
		}
	}

	// 5. Read again: the same rows, current again.
	delete(a.iam.fail, "GetAccountAuthorizationDetails:Group")
	time.Sleep(10 * time.Millisecond)
	run5 := bdbCycle(l, a, bdbFakes{ecs: []ecstypes.TaskDefinition{billing2}})
	rels = bdbRels(t, l, types...)
	for _, before := range live {
		r := bdbRelOf(t, rels, before.Type, before.Source, before.Target, "")
		if r.ID != before.ID || r.State != models.RelCurrent || !r.ValidFrom.Equal(before.ValidFrom) ||
			!sameRun(r.LastConfirmedBy, &run5.ID) {
			t.Errorf("%s %s -> %s after the re-read = %+v, want row %s current again, confirmed by run %s",
				r.Type, r.Source, r.Target, r, before.ID, run5.ID)
		}
	}
	if len(rels) != 6 {
		t.Errorf("relationships after the re-read = %d rows, want still 6: %+v", len(rels), rels)
	}

	// The partitions behind steps 3-5, checked last so a wrong one shows as
	// the behaviour it causes above first. Each edge in its OWN partition:
	// task_execution_role's is ECS-and-region scoped and requires ecs:<region>,
	// member_of's is the account's and requires iam_groups -- the key a row is
	// reconciled under.
	if !strings.Contains(pull1.PartitionKey, "|relationship||task_execution_role|ecs|us-east-1|") ||
		!strings.Contains(pull1.PartitionKey, "ecs:us-east-1") || pull1.PartitionKey == exec1.PartitionKey {
		t.Errorf("task_execution_role partition = %q (executes_as %q), want its own ecs/us-east-1 partition",
			pull1.PartitionKey, exec1.PartitionKey)
	}
	if !strings.Contains(mPriya.PartitionKey, "|relationship||member_of|") ||
		!strings.Contains(mPriya.PartitionKey, models.SurfaceIAMGroups) || mPriya.PartitionKey != mKim.PartitionKey {
		t.Errorf("member_of partitions = %q / %q, want one account-wide member_of partition requiring iam_groups",
			mPriya.PartitionKey, mKim.PartitionKey)
	}
}
