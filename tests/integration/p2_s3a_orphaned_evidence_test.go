package integration

// S3a (T3.5, §4.8): an observation outlives the row it describes (024) -- and
// outliving it must never stop the NEXT deletion.
//
// When reconciliation deletes a cloud_policy, cloud_permission (or any other
// subject) row, the observation's subject column is SET NULL and the row falls
// under uq_cloud_observation_dedupe_no_subject (025/035), keyed only by
// (workspace_id, source_api, content_hash). Two orphans with equal facts then
// collide, the DELETE fails with a unique violation, and -- because the stale
// row keeps its colliding observation -- it fails again on every later run,
// with the worker only logging it. Equal facts are the ordinary case, not an
// edge: the same AWS-managed policy read in two accounts, a policy detached,
// reattached unchanged and detached again (scenario 5 plus one detach), and
// one statement fanned out to two resources.

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// s3aOrphanDoc names TWO tables in one statement, so its grant fans out to two
// cloud_permission rows whose observations carry one statement's facts.
const s3aOrphanDoc = `{"Version":"2012-10-17","Statement":[{"Sid":"Tables","Effect":"Allow",` +
	`"Action":"dynamodb:GetItem","Resource":["arn:aws:dynamodb:us-east-1:111122223333:table/orphan-one",` +
	`"arn:aws:dynamodb:us-east-1:111122223333:table/orphan-two"]}]}`

// s3aOrphanState is what one connector still holds of a deleted policy: its
// rows (which must be gone) and its observations (which must be kept, with no
// subject, still naming what they were evidence for).
type s3aOrphanState struct {
	PolicyRows, AttachmentRows, PermissionRows int64
	// Orphans counts the policy's observations with every subject column NULL
	// and subject_native_id still its native id.
	Orphans int64
}

func s3aOrphans(l *p2Lab, conn uuid.UUID, policyNativeID, permissionSource string) s3aOrphanState {
	l.t.Helper()
	return s3aOrphanState{
		PolicyRows: l.count(`SELECT count(*) FROM cloud_policy WHERE workspace_id = ? AND connector_id = ?
		                      AND native_id = ?`, l.ws, conn, policyNativeID),
		AttachmentRows: l.count(`SELECT count(*) FROM cloud_policy_attachment x JOIN cloud_policy p ON p.id = x.policy_row_id
		                          WHERE x.workspace_id = ? AND x.connector_id = ? AND p.native_id = ?`,
			l.ws, conn, policyNativeID),
		PermissionRows: l.count(`SELECT count(*) FROM cloud_permission WHERE workspace_id = ? AND connector_id = ?
		                          AND native_id LIKE ?`, l.ws, conn, permissionSource+"#s%"),
		Orphans: l.count(`SELECT count(*) FROM cloud_observation WHERE workspace_id = ? AND connector_id = ?
		                   AND subject_native_id = ? AND identity_id IS NULL AND permission_id IS NULL
		                   AND resource_id IS NULL AND workload_id IS NULL AND policy_id IS NULL`,
			l.ws, conn, policyNativeID),
	}
}

// The finding's two shapes end to end, through the REAL worker: (a) one
// AWS-managed policy detached from its last holder in two accounts of one
// workspace, and (b) an AWS-managed and an inline policy detached, reattached
// unchanged, and detached again. Every deletion reconciles -- no stale
// cloud_policy, attachment or cloud_permission row survives it -- and every
// deleted incarnation's observation is KEPT, subject-less, still naming the
// policy.
func TestP2S3aDeletedPolicyEvidenceNeverBlocksReconcile(t *testing.T) {
	l := newP2Lab(t, "p2-s3a-orphans", true)
	a := l.account(accountA)
	b := l.account(accountB)
	a.role("OrphanA", "AROAORPHANAORPHANA01")
	b.role("OrphanB", "AROAORPHANBORPHANB01")
	shared := s3aAWSManaged(a, "S3aOrphanAccess", s3aOrphanDoc)
	s3aAWSManaged(b, "S3aOrphanAccess", s3aOrphanDoc)
	scratch := map[string]string{"Scratch": s3aDoc("Scratch", "sqs:SendMessage",
		"arn:aws:sqs:us-east-1:"+a.id+":scratch")}
	inlineID := "inline:" + a.roleARN("OrphanA") + ":Scratch"

	holdA := func() {
		a.attach("OrphanA", shared)
		a.iam.inlineRolePolicies["OrphanA"] = scratch
	}
	dropA := func() {
		a.detach("OrphanA", shared)
		delete(a.iam.inlineRolePolicies, "OrphanA")
	}
	gone := func(step string, conn uuid.UUID, nativeID, source string, wantOrphans int64) {
		t.Helper()
		got := s3aOrphans(l, conn, nativeID, source)
		want := s3aOrphanState{Orphans: wantOrphans}
		if got != want {
			t.Errorf("%s: %s = %+v, want %+v: reconciliation did not delete the stale rows, "+
				"or did not keep each deleted incarnation's evidence", step, nativeID, got, want)
		}
	}
	held := func(step string, conn uuid.UUID, nativeID, source string) {
		t.Helper()
		if got := s3aOrphans(l, conn, nativeID, source); got.PolicyRows != 1 || got.AttachmentRows != 1 ||
			got.PermissionRows == 0 {
			t.Errorf("%s: %s = %+v, want its row, its attachment and its permissions", step, nativeID, got)
		}
	}

	holdA()
	b.attach("OrphanB", shared)
	l.scanAndProject(a)
	l.scanAndProject(b)
	held("first read", a.conn, shared, shared)
	held("first read", b.conn, shared, shared)
	held("first read", a.conn, inlineID, "inline:Scratch")

	// (a) Detached from its last holder in BOTH accounts: two deleted rows of
	// one policy with identical facts, in one workspace.
	dropA()
	l.scanAndProject(a)
	gone("A detached", a.conn, shared, shared, 1)
	gone("A detached", a.conn, inlineID, "inline:Scratch", 1)
	b.detach("OrphanB", shared)
	l.scanAndProject(b)
	gone("B detached", b.conn, shared, shared, 1)

	// (b) Reattached unchanged, then detached again: a second incarnation of
	// each policy row, with the first one's facts.
	holdA()
	l.scanAndProject(a)
	held("reattached", a.conn, shared, shared)
	held("reattached", a.conn, inlineID, "inline:Scratch")
	dropA()
	l.scanAndProject(a)
	gone("detached again", a.conn, shared, shared, 2)
	gone("detached again", a.conn, inlineID, "inline:Scratch", 2)
	// A THIRD run over the same state must reconcile as well: nothing stale is
	// left for it to trip over.
	l.scanAndProject(a)
	gone("rescan", a.conn, shared, shared, 2)

	// The graph closed what the account stopped granting: every grant of both
	// policies ended, in both accounts.
	for _, policy := range []string{"S3aOrphanAccess", "Scratch"} {
		rows := grantsOf(l.grants(), policy)
		if len(rows) == 0 {
			t.Errorf("no %s grants projected at all", policy)
		}
		for _, g := range rows {
			if g.State != models.RelEnded {
				t.Errorf("%s grant %s = %s, want ended", policy, g.ID, g.State)
			}
		}
	}
}

// The writer's own invariant, for every subject kind the reconcilers delete:
// two rows with IDENTICAL facts under one source_api -- permissions (a
// statement fanned out to two resources, or two holders of one managed
// policy) and resources -- are both deleted in ONE reconcile, which must
// succeed and keep both observations. Their facts differ only in the subject
// each one is about, which is what keeps two orphans apart.
func TestP2S3aIdenticalFactsOnDeletedSubjectsKeepBothObservations(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-s3a-orphan-writer")
	conn := connectorFor(t, db, ws)
	runs := scanRuns(t, db)
	if _, err := runs.Enqueue(ws, conn, "manual"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	run, err := runs.Claim("worker-s3a", time.Minute, time.Now())
	if err != nil || run == nil {
		t.Fatalf("claim: %v %v", run, err)
	}

	identityID := uuid.New()
	holderARN := "arn:aws:iam::491056652413:role/S3aOrphanHolder-" + identityID.String()[:8]
	if err := db.Exec(`INSERT INTO cloud_identity (id, workspace_id, connector_id, kind, native_id, name, last_seen_generation)
	                   VALUES (?, ?, ?, 'iam_role', ?, 'S3aOrphanHolder', ?)`,
		identityID, ws, conn, holderARN, run.Generation).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	w := services.NewObservationWriter(db, ws, conn, run.ID, run.Generation)
	statement := map[string]any{"source": "arn:aws:iam::aws:policy/S3aShared", "statement_index": 0,
		"effect": "allow", "actions": []string{"dynamodb:GetItem"}}
	resourceFacts := map[string]any{"kind": "s3_bucket", "has_deny": false, "parse_failed": false, "statements": 1}

	for i, table := range []string{"s3a-one", "s3a-two"} {
		permID, resID := uuid.New(), uuid.New()
		resARN := "arn:aws:s3:::" + table + "-" + permID.String()[:8]
		if err := db.Exec(`INSERT INTO cloud_resource (id, workspace_id, connector_id, kind, native_id, last_seen_generation)
		                   VALUES (?, ?, ?, 's3_bucket', ?, ?)`,
			resID, ws, conn, resARN, run.Generation).Error; err != nil {
			t.Fatalf("seed resource %d: %v", i, err)
		}
		if err := db.Exec(`INSERT INTO cloud_permission
		                     (id, workspace_id, connector_id, identity_id, resource_id, effect, actions, scope_kind, native_id, last_seen_generation)
		                   VALUES (?, ?, ?, ?, ?, 'allow', ARRAY['dynamodb:GetItem'], 'resource', ?, ?)`,
			permID, ws, conn, identityID, resID, "arn:aws:iam::aws:policy/S3aShared#s0", run.Generation).Error; err != nil {
			t.Fatalf("seed permission %d: %v", i, err)
		}
		if err := w.Record(services.PermissionSubject(permID), "iam:GetPolicyVersion", models.SurfaceIAMPolicies,
			"", time.Now(), holderARN+"|"+resARN, statement); err != nil {
			t.Fatalf("record permission evidence %d: %v", i, err)
		}
		if err := w.Record(services.ResourceSubject(resID), "s3:GetBucketPolicy", "resource_policies",
			"", time.Now(), resARN, resourceFacts); err != nil {
			t.Fatalf("record resource evidence %d: %v", i, err)
		}
	}
	// Both deleted in ONE reconcile, as ReconcileGeneration does for a stale
	// statement and its resources.
	_, permsRemoved, resRemoved, err := repositories.NewCloudPermissionRepository(db).
		ReconcileGeneration(ws, conn, run.Generation+1)
	if err != nil {
		t.Fatalf("reconcile over two subjects with identical facts: %v", err)
	}
	if permsRemoved != 2 || resRemoved != 2 {
		t.Fatalf("removed %d permissions and %d resources, want 2 and 2", permsRemoved, resRemoved)
	}
	var orphans int64
	db.Raw(`SELECT count(*) FROM cloud_observation WHERE workspace_id = ? AND identity_id IS NULL
	          AND permission_id IS NULL AND resource_id IS NULL AND workload_id IS NULL AND policy_id IS NULL`,
		ws).Scan(&orphans)
	if orphans != 4 {
		t.Errorf("orphaned observations = %d, want 4: every deleted subject keeps its evidence", orphans)
	}
}
