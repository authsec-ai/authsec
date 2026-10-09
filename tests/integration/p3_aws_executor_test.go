package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/internal/awsenforce/enforcetest"
	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// T3.10 (SPEC-iga-phase3-policy.md §3.5, §4.4, §8.1, §8.5, §2.8, §8.7; A11,
// A13, A25, A26, A27, A41, A58): the direct-delivery executor against real
// PostgreSQL. Every write is authorised by the fake account's simulation of
// the enforcement template's policy; every read goes through the discovery
// view; plans are compiled by the real compiler from that read and stored
// with their documents.
//
// Safeguards (mutation-checked, see the report): Recover before anything
// (a dispatched attempt is never re-sent); no answer -> unknown; an op AWS
// answered that a read does not yet show is never re-sent; each version is
// archived in iga_gov_document before it is deleted; the request hash after
// ${deployment_id} substitution; the ledger `intended` row before the first
// op; a classifier conflict blocks before any write.

// TestP3T310ApplyAndUndoFirstDeployment: none -> AuthSec boundary
// (CreatePolicy, PutRolePermissionsBoundary), then its undo
// (DeleteRolePermissionsBoundary, DeletePolicyVersion all_non_default,
// DeletePolicy). The session, the request hashes, the attempts, completed_ops,
// the readback and the ledger are checked.
func TestP3T310ApplyAndUndoFirstDeployment(t *testing.T) {
	l := newX3Lab(t)
	x := l.role("RefundTaskRole", "/app/", map[string]string{"team": "refunds"})
	tp := l.compile(l.fake.Discovery(), x, "ec2", "sqs")
	if tp.Undo == nil || len(tp.Apply.Ops) != 2 {
		t.Fatalf("compiled apply: %+v", tp.Apply)
	}
	s := l.store(x, tp.Apply, *tp.Undo)
	dep := l.deploy(x, s, igagov.PlanApply)
	run := l.claim(dep, "worker-a", time.Now())
	assumes := len(l.fake.Assumes)
	out := l.mustApply(l.exec, run, dep)

	// The enforcement session: once, this deployment's name, the binding's
	// ExternalId from Vault.
	if len(l.fake.Assumes) != assumes+1 {
		t.Fatalf("assumes: %d new", len(l.fake.Assumes)-assumes)
	}
	a := l.fake.Assumes[len(l.fake.Assumes)-1]
	if a.SessionName != awsenforce.DeploymentSessionName(dep) || a.ExternalID != l.extID || a.RoleARN != l.fake.RoleARN {
		t.Fatalf("assume input: %+v", a)
	}
	// AWS: the policy with this control's tags and this deployment's change
	// tag, the desired document, attached as the role's boundary.
	arn := *tp.Apply.DesiredBoundaryARN
	_, def, doc, tags, ok := l.fake.PolicyState(arn)
	if !ok || def != "v1" || tags[igagov.TagChange] != dep.String() || tags[igagov.TagControl] != x.control.String() ||
		l.fake.BoundaryOf(x.name) != arn {
		t.Fatalf("AWS after apply: ok=%v def=%s tags=%v boundary=%s", ok, def, tags, l.fake.BoundaryOf(x.name))
	}
	if h, _ := igagov.DocumentHash(doc); h != *tp.Apply.DesiredDocumentHash {
		t.Fatalf("installed document %s, want %s", h, *tp.Apply.DesiredDocumentHash)
	}
	// Attempts: one per op, completed ok, request hash of the substituted
	// request, request id recorded, the document hash on CreatePolicy.
	ats := l.attemptRows(dep)
	if len(ats) != 2 {
		t.Fatalf("attempts: %+v", ats)
	}
	for i, at := range ats {
		req, err := awsenforce.NewRequest(tp.Apply.Ops[i], dep, "", x.name)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := req.Hash()
		if at.Status != models.GovAttemptCompleted || at.Outcome == nil || *at.Outcome != "ok" || at.RequestHash != want ||
			!strings.HasPrefix(at.RequestID, "fake-req-") || at.LeaseVersion != run.Fence.Version {
			t.Errorf("attempt %d: %+v (want hash %s)", i, at, want)
		}
	}
	if ats[0].DocumentHash == nil || *ats[0].DocumentHash != *tp.Apply.DesiredDocumentHash || ats[1].DocumentHash != nil {
		t.Fatalf("attempt documents: %v %v", ats[0].DocumentHash, ats[1].DocumentHash)
	}
	if ops := l.completedOps(dep); len(ops) != 2 {
		t.Fatalf("completed_ops: %v", ops)
	}
	// Readback: both reads `after`; the ledger present with the readback.
	if out.Start.Class != igagov.ClassBefore || out.Readback == nil || len(out.Readback.Reads) != 2 ||
		out.Readback.Reads[0].Class != igagov.ClassAfter || out.Readback.Reads[1].Class != igagov.ClassAfter {
		t.Fatalf("classification: start %+v readback %+v", out.Start, out.Readback)
	}
	wantHash, _ := igagov.StatePreconditionHash(out.Readback.State)
	arts := l.artifacts(x)
	if len(arts) != 2 {
		t.Fatalf("ledger: %v", l.ledger(x))
	}
	for _, art := range arts {
		if art.State != "present" || art.OwnedBy != "authsec_direct" || art.LastDeploymentID != dep || art.LastReadbackAt == nil ||
			art.LastReadbackHash != wantHash || art.DocumentHash == nil || *art.DocumentHash != *tp.Apply.DesiredDocumentHash {
			t.Errorf("ledger row: %+v", art)
		}
		if art.Kind == "boundary_policy" && (art.NativeARN != arn || art.AWSVersionID != "v1") {
			t.Errorf("policy row: %+v", art)
		}
		if art.Kind == "boundary_attachment" && art.NativeARN != x.arn {
			t.Errorf("attachment row: %+v", art)
		}
	}
	if ev := l.eventNames(dep); !x3Has(ev, "deployment.ledger_intended") || !x3Has(ev, "deployment.readback") {
		t.Fatalf("events: %v", ev)
	}
	// The executor leaves the deployment state to T3.16.
	if d := l.deployment(dep); d.State != "applying" || d.Attempts != 2 {
		t.Fatalf("deployment: %s attempts %d", d.State, d.Attempts)
	}

	// Undo: detach, no extra versions (not needed, no attempt), delete.
	l.settle(dep, "verified")
	undo := l.deploy(x, s, igagov.PlanUndo)
	uout := l.mustApply(l.exec, l.claim(undo, "worker-a", time.Now()), undo)
	if _, _, _, _, ok := l.fake.PolicyState(arn); ok || l.fake.BoundaryOf(x.name) != "" {
		t.Fatal("undo left the policy or the boundary")
	}
	if len(uout.Ops) != 3 || uout.Ops[1].Outcome != "not_needed" || uout.Ops[1].Basis != services.OpBasisSelector || uout.Ops[1].AttemptID != nil {
		t.Fatalf("undo ops: %+v", uout.Ops)
	}
	if len(l.attemptRows(undo)) != 2 {
		t.Fatalf("undo attempts: %+v", l.attemptRows(undo))
	}
	for _, art := range l.artifacts(x) {
		if art.State != "removed" || art.LastDeploymentID != undo {
			t.Errorf("after undo: %+v", art)
		}
	}
}

// TestP3T310VersionPruneAndUndoEarlierDocument: an AuthSec boundary with 5
// versions. The apply prunes the oldest non-default AFTER archiving it, then
// creates the new default and tags it; the undo installs the earlier
// document as a new default version (pruning again: 5 versions).
func TestP3T310VersionPruneAndUndoEarlierDocument(t *testing.T) {
	l := newX3Lab(t)
	x := l.role("BillingRole", "/", nil)
	arn := x.authsecARN()
	var docs []string
	for _, s := range []string{"ec2", "kms", "ecr", "sns", "sqs"} {
		d, _, _ := igagov.ExcludeOnlyDocument([]string{s})
		docs = append(docs, string(d))
	}
	l.fake.AddPolicy("/authsec/", "AuthSecBoundary-"+x.role.RoleID, map[string]string{igagov.TagManagedBy: igagov.TagManagedByValue,
		igagov.TagWorkspace: x.ref.WorkspaceRef, igagov.TagControl: x.ref.ID}, docs...)
	l.fake.SetBoundary(x.name, arn)

	tp := l.compile(l.fake.Discovery(), x, "sns", "sqs")
	if len(tp.Apply.Ops) != 3 || tp.Apply.Ops[0].Select != igagov.SelectOldestNonDefault {
		t.Fatalf("compiled ops: %+v", tp.Apply.Ops)
	}
	s := l.store(x, tp.Apply, *tp.Undo)
	dep := l.deploy(x, s, igagov.PlanApply)
	out := l.mustApply(l.exec, l.claim(dep, "worker-a", time.Now()), dep)

	versions, def, _, tags, _ := l.fake.PolicyState(arn)
	if strings.Join(versions, ",") != "v2,v3,v4,v5,v6" || def != "v6" || tags[igagov.TagChange] != dep.String() {
		t.Fatalf("after apply: versions %v default %s tags %v", versions, def, tags)
	}
	// v1 was archived before it was deleted, and its attempt names it.
	v1Hash, _ := igagov.DocumentHash(docs[0])
	ats := l.attemptRows(dep)
	if len(ats) != 3 || ats[0].Operation != igagov.OpDeletePolicyVersion || ats[0].DocumentHash == nil || *ats[0].DocumentHash != v1Hash {
		t.Fatalf("prune attempt: %+v", ats)
	}
	var archivedAt time.Time
	if err := l.db.Raw(`SELECT first_seen_at FROM iga_gov_document WHERE workspace_id = ? AND document_hash = ?`, l.ws, v1Hash).Scan(&archivedAt).Error; err != nil ||
		archivedAt.IsZero() || archivedAt.After(ats[0].PreparedAt) {
		t.Fatalf("v1 archived at %v, prune prepared at %v (%v)", archivedAt, ats[0].PreparedAt, err)
	}
	if out.Ops[0].VersionID != "v1" {
		t.Fatalf("pruned %q", out.Ops[0].VersionID)
	}
	// The ledger: the existing artifact (no earlier row: one written now).
	if lg := l.ledger(x); len(lg) != 2 || !strings.HasSuffix(lg[0], " present") || !strings.HasSuffix(lg[1], " present") {
		t.Fatalf("ledger: %v", lg)
	}

	// Undo: the earlier document (docs[4]) as a new default version.
	l.settle(dep, "verified")
	undo := l.deploy(x, s, igagov.PlanUndo)
	l.mustApply(l.exec, l.claim(undo, "worker-a", time.Now()), undo)
	versions, def, doc, _, _ := l.fake.PolicyState(arn)
	if strings.Join(versions, ",") != "v3,v4,v5,v6,v7" || def != "v7" || doc != l.document(*tp.Undo.DesiredDocumentHash) {
		t.Fatalf("after undo: versions %v default %s", versions, def)
	}
	for _, art := range l.artifacts(x) {
		if art.State != "present" || *art.DocumentHash != *tp.Undo.DesiredDocumentHash || art.LastDeploymentID != undo {
			t.Errorf("ledger after undo: %+v", art)
		}
	}
}

// A13: the worker dies after CreatePolicy, before attaching. (a) The
// CreatePolicy answer was recorded: the replacement resumes at
// PutRolePermissionsBoundary. (b) AWS accepted CreatePolicy but the answer
// was never recorded: the replacement marks it unknown, never re-sends it,
// and after resolution attaches. Either way: one policy, one CreatePolicy,
// the ledger consistent.
func TestP3T310CrashAfterCreatePolicyA13(t *testing.T) {
	l := newX3Lab(t)
	t.Run("answer recorded", func(t *testing.T) {
		x := l.role("A13RoleA", "/", nil)
		tp := l.compile(l.fake.Discovery(), x, "sqs")
		s := l.store(x, tp.Apply, *tp.Undo)
		dep := l.deploy(x, s, igagov.PlanApply)
		t0 := time.Now()
		exec := services.NewIGAGovAWSExecutor(l.db, l.attempts, l.access).WithSleep(noSleep)
		exec.FaultBeforeOp = func(seq int, _ igagov.Op) error {
			if seq == 1 {
				return errors.New("worker killed")
			}
			return nil
		}
		if _, err := l.execute(exec, l.claim(dep, "worker-a", t0), dep); err == nil || err.Error() != "worker killed" {
			t.Fatalf("killed run: %v", err)
		}
		// The new artifact's ledger rows were written `intended` before op 0.
		if lg := l.ledger(x); len(lg) != 2 || !strings.HasSuffix(lg[0], " intended") || !strings.HasSuffix(lg[1], " intended") {
			t.Fatalf("ledger after the crash: %v", lg)
		}
		runB := l.claim(dep, "worker-b", t0.Add(3*time.Minute))
		out := l.mustApply(l.exec, runB, dep)
		if out.Start.Class != igagov.ClassIntermediate || out.Start.NextOp != 1 || len(out.Ops) != 1 || out.Ops[0].Operation != igagov.OpPutRolePermissionsBoundary {
			t.Fatalf("resume: start %+v ops %+v", out.Start, out.Ops)
		}
		x3OnePolicy(t, l, x, dep)
	})
	t.Run("answer lost", func(t *testing.T) {
		x := l.role("A13RoleB", "/", nil)
		tp := l.compile(l.fake.Discovery(), x, "sqs")
		s := l.store(x, tp.Apply, *tp.Undo)
		dep := l.deploy(x, s, igagov.PlanApply)
		t0 := time.Now()
		runB := l.killAfterApply("iam:CreatePolicy", dep, t0)
		if _, err := l.execute(l.exec, l.claim(dep, "worker-a", t0), dep); !errors.Is(err, repositories.ErrPolicyJobLeaseLost) {
			t.Fatalf("killed run: %v", err)
		}
		x3ResolveAndResume(t, l, *runB, dep, igagov.ResolvedApplied)
		x3OnePolicy(t, l, x, dep)
	})
}

func x3OnePolicy(t *testing.T, l *x3Lab, x *x3Role, dep uuid.UUID) {
	t.Helper()
	n := 0
	for a := range l.fake.Policies {
		if strings.Contains(a, x.role.RoleID) {
			n++
		}
	}
	creates := 0
	for _, c := range l.fake.Calls {
		if strings.HasPrefix(c, "iam:CreatePolicy ") && strings.Contains(c, x.role.RoleID) {
			creates++
		}
	}
	if n != 1 || creates != 1 || l.fake.BoundaryOf(x.name) != x.authsecARN() {
		t.Fatalf("policies for the role: %d, CreatePolicy calls %d, boundary %s", n, creates, l.fake.BoundaryOf(x.name))
	}
	lg := l.ledger(x)
	if len(lg) != 2 || !strings.HasSuffix(lg[0], " present") || !strings.HasSuffix(lg[1], " present") {
		t.Fatalf("ledger: %v", lg)
	}
}

// x3ResolveAndResume is the replacement worker's path through an attempt
// dispatched without an answer: Recover marks it unknown (outcome_unknown,
// settle_after = signed_at + 15 min, nothing re-sent); a second run holds;
// a discovery read classifies the unknown op (T3.16's resolve_unknown takes
// two such readings and CloudTrail); ResolveUnknown returns the deployment
// to applying; the next run recognises the op done and reads back.
func x3ResolveAndResume(t *testing.T, l *x3Lab, runB *services.PolicyJobRun, dep uuid.UUID, want string) *services.DeployOutcome {
	t.Helper()
	if runB == nil {
		t.Fatal("the replacement never claimed the job")
	}
	calls := len(l.fake.Calls)
	out, err := l.execute(l.exec, runB, dep)
	if err != nil || out.Result != services.DeployOutcomeUnknown || out.Recovery != services.RecoveryOutcomeUnknown || out.Attempt == nil {
		t.Fatalf("replacement: %+v %v", out, err)
	}
	d := l.deployment(dep)
	if d.State != "outcome_unknown" || d.SettleAfter == nil || out.Attempt.SignedAt == nil ||
		!d.SettleAfter.Equal(out.Attempt.SignedAt.Add(15*time.Minute)) {
		t.Fatalf("deployment after recover: %s settle %v signed %v", d.State, d.SettleAfter, out.Attempt.SignedAt)
	}
	// Held until resolved: nothing is sent.
	if out, err := l.execute(l.exec, runB, dep); err != nil || out.Result != services.DeployHold {
		t.Fatalf("second run: %+v %v", out, err)
	}
	if len(l.fake.Calls) != calls {
		t.Fatalf("AWS was called while the outcome was unknown: %v", l.fake.Calls[calls:])
	}
	p, _ := services.LoadIGAGovPlan(l.db, l.ws, d.PlanID)
	reading, err := l.exec.ClassifyUnknown(context.Background(), runB, d, p)
	if err != nil || reading.Resolution.Resolution != want {
		t.Fatalf("classify unknown: %+v %v", reading, err)
	}
	if want != igagov.ResolvedApplied && want != igagov.ResolvedNotApplied {
		return nil
	}
	att := reading.Attempt
	if err := l.attempts.ResolveUnknown(context.Background(), runB, &att, want); err != nil {
		t.Fatal(err)
	}
	out = l.mustApply(l.exec, runB, dep)
	if want == igagov.ResolvedApplied {
		var rec *services.DeployOpRecord
		for i := range out.Ops {
			if out.Ops[i].OpSeq == att.OpSeq {
				rec = &out.Ops[i]
			}
		}
		if rec == nil || rec.Outcome != "recognised_done" || rec.AttemptID == nil || *rec.AttemptID != att.ID {
			t.Fatalf("the resolved op was not recognised done: %+v", out.Ops)
		}
	}
	return out
}

// A25: the worker dies after PutRolePermissionsBoundary reached AWS, before
// its attempt row recorded the answer. The new owner classifies the
// post-state: recognised_done, readback, applied -- never plan_changed.
func TestP3T310CrashAfterPutBoundaryA25(t *testing.T) {
	l := newX3Lab(t)
	x := l.role("A25Role", "/", nil)
	tp := l.compile(l.fake.Discovery(), x, "sqs")
	s := l.store(x, tp.Apply, *tp.Undo)
	dep := l.deploy(x, s, igagov.PlanApply)
	t0 := time.Now()
	runB := l.killAfterApply("iam:PutRolePermissionsBoundary", dep, t0)
	if _, err := l.execute(l.exec, l.claim(dep, "worker-a", t0), dep); !errors.Is(err, repositories.ErrPolicyJobLeaseLost) {
		t.Fatalf("killed run: %v", err)
	}
	if ats := l.attemptRows(dep); len(ats) != 2 || ats[1].Status != models.GovAttemptDispatched {
		t.Fatalf("attempts after the crash: %+v", ats)
	}
	out := x3ResolveAndResume(t, l, *runB, dep, igagov.ResolvedApplied)
	if out.Start.Class != igagov.ClassAfter || out.Reason != "" || l.calls("iam:PutRolePermissionsBoundary", x.arn) != 1 {
		t.Fatalf("A25: start %+v reason %q puts %d", out.Start.Class, out.Reason, l.calls("iam:PutRolePermissionsBoundary", x.arn))
	}
	if ops := l.completedOps(dep); len(ops) != 2 || ops[1]["outcome"] != "recognised_done" || ops[1]["basis"] != "live_read" {
		t.Fatalf("completed_ops: %v", ops)
	}
}

// A26 + A58(a): a crash during a version update. (a) After CreatePolicyVersion
// reached AWS, before the answer: unknown, never re-sent, resolved applied,
// then only TagPolicy runs. (b) After its answer, before TagPolicy: resume at
// TagPolicy. (c) A prepared attempt (never dispatched) is abandoned and
// re-prepared as attempt 2. No duplicate default change in any case.
func TestP3T310CrashDuringVersionUpdateA26(t *testing.T) {
	l := newX3Lab(t)
	setup := func(name string) (*x3Role, uuid.UUID, string) {
		x := l.role(name, "/", nil)
		arn := x.authsecARN()
		d, _, _ := igagov.ExcludeOnlyDocument([]string{"ec2"})
		l.fake.AddPolicy("/authsec/", "AuthSecBoundary-"+x.role.RoleID, map[string]string{igagov.TagManagedBy: igagov.TagManagedByValue,
			igagov.TagWorkspace: x.ref.WorkspaceRef, igagov.TagControl: x.ref.ID}, string(d))
		l.fake.SetBoundary(x.name, arn)
		tp := l.compile(l.fake.Discovery(), x, "ec2", "sqs")
		s := l.store(x, tp.Apply, *tp.Undo)
		return x, l.deploy(x, s, igagov.PlanApply), arn
	}
	versionCalls := func(arn string) int {
		n := 0
		for _, c := range l.fake.Calls {
			if strings.HasPrefix(c, "iam:CreatePolicyVersion "+arn) {
				n++
			}
		}
		return n
	}
	t.Run("answer lost", func(t *testing.T) {
		_, dep, arn := setup("A26RoleA")
		t0 := time.Now()
		runB := l.killAfterApply("iam:CreatePolicyVersion", dep, t0)
		if _, err := l.execute(l.exec, l.claim(dep, "worker-a", t0), dep); !errors.Is(err, repositories.ErrPolicyJobLeaseLost) {
			t.Fatalf("killed run: %v", err)
		}
		out := x3ResolveAndResume(t, l, *runB, dep, igagov.ResolvedApplied)
		if out.Start.Class != igagov.ClassAfter || out.Start.NextOp != 1 || out.Ops[len(out.Ops)-1].Operation != igagov.OpTagPolicy {
			t.Fatalf("resume: %+v %+v", out.Start, out.Ops)
		}
		if v, def, _, _, _ := l.fake.PolicyState(arn); versionCalls(arn) != 1 || len(v) != 2 || def != "v2" {
			t.Fatalf("versions %v default %s, CreatePolicyVersion calls %d", v, def, versionCalls(arn))
		}
	})
	t.Run("answer recorded", func(t *testing.T) {
		_, dep, arn := setup("A26RoleB")
		t0 := time.Now()
		exec := services.NewIGAGovAWSExecutor(l.db, l.attempts, l.access).WithSleep(noSleep)
		exec.FaultBeforeOp = func(seq int, op igagov.Op) error {
			if op.Op == igagov.OpTagPolicy {
				return errors.New("worker killed")
			}
			return nil
		}
		if _, err := l.execute(exec, l.claim(dep, "worker-a", t0), dep); err == nil {
			t.Fatal("killed run returned no error")
		}
		out := l.mustApply(l.exec, l.claim(dep, "worker-b", t0.Add(3*time.Minute)), dep)
		if len(out.Ops) != 1 || out.Ops[0].Operation != igagov.OpTagPolicy || versionCalls(arn) != 1 {
			t.Fatalf("resume ops %+v, CreatePolicyVersion calls %d", out.Ops, versionCalls(arn))
		}
	})
	t.Run("prepared never dispatched", func(t *testing.T) {
		_, dep, arn := setup("A26RoleC")
		t0 := time.Now()
		runA := l.claim(dep, "worker-a", t0)
		// The worker died between prepare and dispatch.
		if _, err := l.attempts.Prepare(context.Background(), runA, services.AttemptRequest{WorkspaceID: l.ws, DeploymentID: dep,
			OpSeq: 0, Operation: igagov.OpCreatePolicyVersion, RequestHash: "sha256:prepared-only"}); err != nil {
			t.Fatal(err)
		}
		out := l.mustApply(l.exec, l.claim(dep, "worker-b", t0.Add(3*time.Minute)), dep)
		ats := l.attemptRows(dep)
		if out.Recovery != services.RecoveryReprepare || len(ats) != 3 || ats[0].Status != models.GovAttemptAbandoned ||
			ats[1].AttemptNo != 2 || ats[1].Status != models.GovAttemptCompleted || versionCalls(arn) != 1 {
			t.Fatalf("recovery %s attempts %+v calls %d", out.Recovery, ats, versionCalls(arn))
		}
	})
}

// A27: an undo killed after DeleteRolePermissionsBoundary, before the
// version deletes and DeletePolicy. The replacement deletes the remaining
// non-default versions (each archived first) and the policy; undo applied.
func TestP3T310CrashDuringUndoA27(t *testing.T) {
	l := newX3Lab(t)
	x := l.role("A27Role", "/", nil)
	tp := l.compile(l.fake.Discovery(), x, "sqs")
	s := l.store(x, tp.Apply, *tp.Undo)
	dep := l.deploy(x, s, igagov.PlanApply)
	l.mustApply(l.exec, l.claim(dep, "worker-a", time.Now()), dep)
	l.settle(dep, "verified")
	// Two non-default versions (not part of artifact_state).
	arn := x.authsecARN()
	for _, svc := range []string{"kms", "ecr"} {
		d, _, _ := igagov.ExcludeOnlyDocument([]string{svc})
		l.fake.AddVersion(arn, string(d), false)
	}

	undo := l.deploy(x, s, igagov.PlanUndo)
	t0 := time.Now()
	exec := services.NewIGAGovAWSExecutor(l.db, l.attempts, l.access).WithSleep(noSleep)
	exec.FaultBeforeOp = func(seq int, _ igagov.Op) error {
		if seq == 1 {
			return errors.New("worker killed")
		}
		return nil
	}
	if _, err := l.execute(exec, l.claim(undo, "worker-a", t0), undo); err == nil {
		t.Fatal("killed run returned no error")
	}
	if l.fake.BoundaryOf(x.name) != "" {
		t.Fatal("the boundary was not detached before the crash")
	}
	out := l.mustApply(l.exec, l.claim(undo, "worker-b", t0.Add(3*time.Minute)), undo)
	if out.Start.Class != igagov.ClassIntermediate || out.Start.NextOp != 1 {
		t.Fatalf("resume start: %+v", out.Start)
	}
	if _, _, _, _, ok := l.fake.PolicyState(arn); ok {
		t.Fatal("the policy survived the undo")
	}
	var deleted []string
	for _, r := range out.Ops {
		if r.Operation == igagov.OpDeletePolicyVersion {
			deleted = append(deleted, r.VersionID)
		}
	}
	if strings.Join(deleted, ",") != "v2,v3" {
		t.Fatalf("versions deleted: %v (%+v)", deleted, out.Ops)
	}
	for _, at := range l.attemptRows(undo) {
		if at.Operation == igagov.OpDeletePolicyVersion && (at.DocumentHash == nil || l.document(*at.DocumentHash) == "") {
			t.Fatalf("a version was deleted without its archived document: %+v", at)
		}
	}
	if lg := l.ledger(x); len(lg) != 2 || !strings.HasSuffix(lg[0], " removed") || !strings.HasSuffix(lg[1], " removed") {
		t.Fatalf("ledger: %v", lg)
	}
}

// A35/A40/A41 and role-only recovery: the boundary gains a second user; the
// undo is blocked (artifact_consumers_changed) before any write; the
// role-only recovery to no boundary, killed after its detach reached AWS,
// finishes with the shared policy released and never calls DeletePolicy;
// the role-only recovery to an earlier document installs a -u policy.
func TestP3T310RoleOnlyRecoveryA41(t *testing.T) {
	l := newX3Lab(t)
	l.fake.AddRole("ReportsRole", "/", nil)

	t.Run("detach, crash after the detach", func(t *testing.T) {
		x := l.role("A41Role", "/", nil)
		tp := l.compile(l.fake.Discovery(), x, "sqs")
		s := l.store(x, tp.Apply, *tp.Undo)
		dep := l.deploy(x, s, igagov.PlanApply)
		l.mustApply(l.exec, l.claim(dep, "worker-a", time.Now()), dep)
		l.settle(dep, "verified")
		arn := x.authsecARN()
		l.fake.SetBoundary("ReportsRole", arn)

		// The undo is blocked before any write.
		undo := l.deploy(x, s, igagov.PlanUndo)
		calls := len(l.fake.Calls)
		out, err := l.execute(l.exec, l.claim(undo, "worker-a", time.Now()), undo)
		if err != nil || out.Result != services.DeployBlocked || out.Reason != igagov.ConflictConsumersChanged || len(l.fake.Calls) != calls ||
			len(l.attemptRows(undo)) != 0 {
			t.Fatalf("undo with a new consumer: %+v %v", out, err)
		}
		l.settle(undo, "blocked")

		rp, err := igagov.CompileRoleOnlyRecovery(igagov.RecoveryInput{Control: x.ref, Undo: *tp.Undo, UndoneDeploymentID: dep.String(),
			Live: l.live(l.fake.Discovery(), x), Evidence: l.evidence(x, []string{"sqs"})})
		if err != nil || rp.ArtifactDisposition != igagov.DispositionRetainShared || len(rp.Ops) != 1 {
			t.Fatalf("role-only recovery: %+v %v", rp, err)
		}
		rs := l.store(x, rp)
		rec := l.deploy(x, rs, igagov.PlanUndo)
		t0 := time.Now()
		runB := l.killAfterApply("iam:DeleteRolePermissionsBoundary", rec, t0)
		if _, err := l.execute(l.exec, l.claim(rec, "worker-a", t0), rec); !errors.Is(err, repositories.ErrPolicyJobLeaseLost) {
			t.Fatalf("killed run: %v", err)
		}
		out = x3ResolveAndResume(t, l, *runB, rec, igagov.ResolvedApplied)
		if out.Start.Class != igagov.ClassAfter {
			t.Fatalf("A41 start: %+v", out.Start)
		}
		if l.calls("iam:DeletePolicy", arn) != 0 || l.fake.BoundaryOf(x.name) != "" || l.fake.BoundaryOf("ReportsRole") != arn {
			t.Fatalf("AWS after role-only recovery: deletes %d boundary %q reports %q", l.calls("iam:DeletePolicy", arn),
				l.fake.BoundaryOf(x.name), l.fake.BoundaryOf("ReportsRole"))
		}
		if _, _, _, _, ok := l.fake.PolicyState(arn); !ok {
			t.Fatal("the shared policy was deleted")
		}
		lg := l.ledger(x)
		if len(lg) != 2 || lg[0] != "boundary_attachment "+x.arn+" removed" || lg[1] != "boundary_policy "+arn+" released" {
			t.Fatalf("ledger: %v", lg)
		}
		l.fake.SetBoundary("ReportsRole", "")
	})

	t.Run("earlier document under a -u policy", func(t *testing.T) {
		x := l.role("RecoverDocRole", "/", nil)
		tp1 := l.compile(l.fake.Discovery(), x, "sqs")
		s1 := l.store(x, tp1.Apply, *tp1.Undo)
		d1 := l.deploy(x, s1, igagov.PlanApply)
		l.mustApply(l.exec, l.claim(d1, "worker-a", time.Now()), d1)
		l.settle(d1, "verified")
		tp2 := l.compile(l.fake.Discovery(), x, "sns", "sqs")
		s2 := l.store(x, tp2.Apply, *tp2.Undo)
		d2 := l.deploy(x, s2, igagov.PlanApply)
		l.mustApply(l.exec, l.claim(d2, "worker-a", time.Now()), d2)
		l.settle(d2, "verified")
		arn := x.authsecARN()
		l.fake.SetBoundary("ReportsRole", arn)

		uarn, _ := igagov.RecoveryPolicyARN("aws", testAccount, x.role.RoleID, d2.String())
		rp, err := igagov.CompileRoleOnlyRecovery(igagov.RecoveryInput{Control: x.ref, Undo: *tp2.Undo, UndoneDeploymentID: d2.String(),
			EarlierDocument: l.document(*tp2.Undo.DesiredDocumentHash), Live: l.live(l.fake.Discovery(), x, uarn),
			Evidence: l.evidence(x, []string{"sqs"})})
		if err != nil || !rp.Eligible() || len(rp.Ops) != 2 || *rp.DesiredBoundaryARN != uarn {
			t.Fatalf("role-only recovery: %+v %v", rp, err)
		}
		rs := l.store(x, rp)
		rec := l.deploy(x, rs, igagov.PlanUndo)
		l.mustApply(l.exec, l.claim(rec, "worker-a", time.Now()), rec)
		_, _, sharedDoc, _, ok := l.fake.PolicyState(arn)
		if l.fake.BoundaryOf(x.name) != uarn || l.fake.BoundaryOf("ReportsRole") != arn || !ok ||
			sharedDoc != l.document(*tp2.Apply.DesiredDocumentHash) {
			t.Fatalf("AWS: boundary %s reports %s shared ok=%v", l.fake.BoundaryOf(x.name), l.fake.BoundaryOf("ReportsRole"), ok)
		}
		got := map[string]bool{}
		for _, a := range l.artifacts(x) {
			got[a.Kind+" "+a.NativeARN+" "+a.State] = true
		}
		if !got["boundary_policy "+arn+" released"] || !got["boundary_policy "+uarn+" present"] || !got["boundary_attachment "+x.arn+" present"] {
			t.Fatalf("ledger: %v", l.ledger(x))
		}
		l.fake.SetBoundary("ReportsRole", "")
	})
}

// remove_control with an empty baseline: absent + delete.
func TestP3T310RemoveControl(t *testing.T) {
	l := newX3Lab(t)
	x := l.role("RemoveRole", "/", nil)
	tp := l.compile(l.fake.Discovery(), x, "sqs")
	s := l.store(x, tp.Apply, *tp.Undo)
	dep := l.deploy(x, s, igagov.PlanApply)
	l.mustApply(l.exec, l.claim(dep, "worker-a", time.Now()), dep)
	l.settle(dep, "verified")
	rc, err := igagov.CompileRemoveControl(igagov.RemoveControlInput{Control: x.ref, Delivery: igagov.DeliveryDirect,
		Live: l.live(l.fake.Discovery(), x), LastDeployed: igagov.BoundaryRef{ARN: x.authsecARN(), DocumentHash: *tp.Apply.DesiredDocumentHash},
		Evidence: l.evidence(x, []string{"sqs"}), ExcludedServices: []string{"sqs"}})
	if err != nil || !rc.Eligible() {
		t.Fatalf("remove control: %+v %v", rc, err)
	}
	rs := l.store(x, rc)
	rm := l.deploy(x, rs, igagov.PlanRemoveControl)
	l.mustApply(l.exec, l.claim(rm, "worker-a", time.Now()), rm)
	if _, _, _, _, ok := l.fake.PolicyState(x.authsecARN()); ok || l.fake.BoundaryOf(x.name) != "" {
		t.Fatal("remove control left the artifact")
	}
	for _, a := range l.artifacts(x) {
		if a.State != "removed" {
			t.Fatalf("ledger: %v", l.ledger(x))
		}
	}
}

// A11: an ineligible role never reaches AWS (the compiler refuses it and the
// executor refuses an ineligible plan); and a FORCED attempt -- AuthSec's
// read misled into thinking the role eligible -- is refused by AWS (the
// enforcement template's explicit denies), recorded as a terminal answer,
// with nothing else written.
func TestP3T310ForcedAttemptRefusedByAWSA11(t *testing.T) {
	l := newX3Lab(t)
	roles := []*x3Role{
		l.role("AWSServiceRoleForECS", "/aws-service-role/ecs.amazonaws.com/", nil),
		l.role("PaymentsCollector", "/", map[string]string{"ManagedBy": "AuthSec"}),
		l.role("LedgerRole", "/", map[string]string{"authsec:protected": "true"}),
	}
	// Honest read: ineligible with the reason; ExecutePlan refuses it.
	for _, x := range roles {
		tp := l.compile(l.fake.Discovery(), x, "sqs")
		if tp.Apply.Eligible() || tp.Apply.IneligibleReason == "" || len(tp.Apply.Ops) != 0 {
			t.Fatalf("%s: compiled %s %q", x.name, tp.Apply.Eligibility, tp.Apply.IneligibleReason)
		}
		dep := uuid.New()
		d := models.IGAGovDeployment{ID: dep, WorkspaceID: l.ws, ControlID: x.control, Kind: igagov.PlanApply, Delivery: igagov.DeliveryDirect}
		calls := len(l.fake.Calls)
		run := l.claim(dep, "worker-a", time.Now())
		out, err := l.exec.ExecutePlan(context.Background(), run, d, tp.Apply)
		if err != nil || out.Result != services.DeployRefused || out.Reason != services.DeployReasonIneligible || len(l.fake.Calls) != calls {
			t.Fatalf("%s: %+v %v", x.name, out, err)
		}
	}

	// Forced: each role carries an AuthSec boundary from before it became
	// ineligible; a remove_control plan compiled from a misled read starts
	// with DeleteRolePermissionsBoundary, which AWS refuses.
	hide := map[string]bool{}
	for _, x := range roles {
		hide[x.name] = true
	}
	liar := x3Liar{DiscoveryIAM: l.fake.Discovery(), hide: hide}
	exec := l.executorWith(liar)
	for _, x := range roles {
		d, h, _ := igagov.ExcludeOnlyDocument([]string{"sqs"})
		l.fake.AddPolicy("/authsec/", "AuthSecBoundary-"+x.role.RoleID, map[string]string{igagov.TagManagedBy: igagov.TagManagedByValue,
			igagov.TagWorkspace: x.ref.WorkspaceRef, igagov.TagControl: x.ref.ID}, string(d))
		l.fake.SetBoundary(x.name, x.authsecARN())
		rc, err := igagov.CompileRemoveControl(igagov.RemoveControlInput{Control: x.ref, Delivery: igagov.DeliveryDirect,
			Live: l.live(liar, x), LastDeployed: igagov.BoundaryRef{ARN: x.authsecARN(), DocumentHash: h},
			Evidence: l.evidence(x, []string{"sqs"})})
		if err != nil || !rc.Eligible() || rc.Ops[0].Op != igagov.OpDeleteRolePermissionsBoundary {
			t.Fatalf("%s: forced plan %+v %v", x.name, rc, err)
		}
		rs := l.store(x, rc)
		dep := l.deploy(x, rs, igagov.PlanRemoveControl)
		calls := len(l.fake.Calls)
		out, err := l.execute(exec, l.claim(dep, "worker-a", time.Now()), dep)
		if err != nil || out.Result != services.DeployFailed || out.Reason != "AccessDenied" {
			t.Fatalf("%s: forced attempt %+v %v", x.name, out, err)
		}
		ats := l.attemptRows(dep)
		if len(ats) != 1 || ats[0].Status != models.GovAttemptCompleted || ats[0].Outcome == nil || *ats[0].Outcome != "terminal" ||
			ats[0].ErrorCode != "AccessDenied" {
			t.Fatalf("%s: attempts %+v", x.name, ats)
		}
		newCalls := l.fake.Calls[calls:]
		if len(newCalls) != 1 || !strings.HasSuffix(newCalls[0], "-> denied") {
			t.Fatalf("%s: AWS calls %v", x.name, newCalls)
		}
		if _, _, _, _, ok := l.fake.PolicyState(x.authsecARN()); !ok || l.fake.BoundaryOf(x.name) != x.authsecARN() {
			t.Fatalf("%s: something was written", x.name)
		}
		if lg := l.ledger(x); len(lg) != 0 {
			t.Fatalf("%s: ledger %v", x.name, lg)
		}
		// Attaching is refused the same way (the template's denies).
		if dec := l.fake.Probe("iam:PutRolePermissionsBoundary", l.fake.RoleARNOf(x.role), map[string]string{
			"iam:PermissionsBoundary": x.authsecARN(), "aws:ResourceTag/ManagedBy": x.role.Tags["ManagedBy"],
			"aws:ResourceTag/authsec:protected": x.role.Tags["authsec:protected"]}); dec.Allowed {
			t.Fatalf("%s: AWS would accept an attach", x.name)
		}
	}
}

// A58(b): a CreatePolicyVersion delayed past the client timeout is unknown
// (no answer is not an answer); it is sent exactly once and never re-sent;
// (c) no other deployment can start on the role while it is unknown.
func TestP3T310TimeoutIsUnknownA58(t *testing.T) {
	l := newX3Lab(t)
	x := l.role("A58Role", "/", nil)
	arn := x.authsecARN()
	d, _, _ := igagov.ExcludeOnlyDocument([]string{"ec2"})
	l.fake.AddPolicy("/authsec/", "AuthSecBoundary-"+x.role.RoleID, map[string]string{igagov.TagManagedBy: igagov.TagManagedByValue,
		igagov.TagWorkspace: x.ref.WorkspaceRef, igagov.TagControl: x.ref.ID}, string(d))
	l.fake.SetBoundary(x.name, arn)
	tp := l.compile(l.fake.Discovery(), x, "ec2", "sqs")
	s := l.store(x, tp.Apply, *tp.Undo)
	dep := l.deploy(x, s, igagov.PlanApply)

	l.attempts.CallTimeout = 300 * time.Millisecond
	defer func() { l.attempts.CallTimeout = 0 }()
	l.fake.AfterApply["iam:CreatePolicyVersion"] = func(ctx context.Context) error {
		<-ctx.Done() // applied in AWS; the answer never arrives in time
		return ctx.Err()
	}
	run := l.claim(dep, "worker-a", time.Now())
	out, err := l.execute(l.exec, run, dep)
	delete(l.fake.AfterApply, "iam:CreatePolicyVersion")
	if err != nil || out.Result != services.DeployOutcomeUnknown || out.SettleAfter == nil {
		t.Fatalf("timeout: %+v %v", out, err)
	}
	ats := l.attemptRows(dep)
	if len(ats) != 1 || ats[0].Status != models.GovAttemptUnknown || l.calls("iam:CreatePolicyVersion", arn) != 1 {
		t.Fatalf("attempts %+v, CreatePolicyVersion calls %d", ats, l.calls("iam:CreatePolicyVersion", arn))
	}
	if dd := l.deployment(dep); dd.State != "outcome_unknown" || !strings.HasPrefix(dd.OutcomeUnknownOp, "0:CreatePolicyVersion") {
		t.Fatalf("deployment: %s %q", dd.State, dd.OutcomeUnknownOp)
	}
	// Never re-sent.
	if out, err := l.execute(l.exec, run, dep); err != nil || out.Result != services.DeployHold || l.calls("iam:CreatePolicyVersion", arn) != 1 {
		t.Fatalf("rerun: %+v %v", out, err)
	}
	// (c) The role is held: an undo cannot be created.
	err = l.db.Exec(`INSERT INTO iga_gov_deployment (id, workspace_id, version_id, plan_id, control_id, approval_id, kind, delivery, state)
		VALUES (?, ?, ?, ?, ?, ?, 'undo', 'direct', 'queued')`, uuid.New(), l.ws, s.version, s.plans[igagov.PlanUndo], x.control, s.approval).Error
	if err == nil || !strings.Contains(err.Error(), "uq_iga_gov_deployment_inflight") {
		t.Fatalf("a second deployment on a held role: %v", err)
	}
}

// §8.5 retryable answers: throttling proves the request was not applied, so
// a NEW attempt follows (after a jittered backoff); at most MaxOpAttempts.
func TestP3T310ThrottledIsRetriedAsNewAttempt(t *testing.T) {
	l := newX3Lab(t)
	x := l.role("ThrottledRole", "/", nil)
	tp := l.compile(l.fake.Discovery(), x, "sqs")
	s := l.store(x, tp.Apply, *tp.Undo)
	dep := l.deploy(x, s, igagov.PlanApply)
	run := l.claim(dep, "worker-a", time.Now())
	l.fake.Fail["iam:PutRolePermissionsBoundary"] = enforcetest.APIError("Throttling", "Rate exceeded")
	out, err := l.execute(l.exec, run, dep)
	if err != nil || out.Result != services.DeployRetryLater || out.Reason != services.DeployReasonThrottled || out.RetryAfter <= 0 {
		t.Fatalf("throttled: %+v %v", out, err)
	}
	delete(l.fake.Fail, "iam:PutRolePermissionsBoundary")
	l.mustApply(l.exec, run, dep)
	ats := l.attemptRows(dep)
	if len(ats) != 3 || *ats[1].Outcome != "retryable" || ats[1].ErrorCode != "Throttling" || ats[2].AttemptNo != 2 || *ats[2].Outcome != "ok" {
		t.Fatalf("attempts: %+v", ats)
	}

	// Exhaustion.
	y := l.role("ThrottledRole2", "/", nil)
	tp2 := l.compile(l.fake.Discovery(), y, "sqs")
	s2 := l.store(y, tp2.Apply, *tp2.Undo)
	dep2 := l.deploy(y, s2, igagov.PlanApply)
	run2 := l.claim(dep2, "worker-a", time.Now())
	exec := services.NewIGAGovAWSExecutor(l.db, l.attempts, l.access).WithSleep(noSleep)
	exec.MaxOpAttempts = 2
	l.fake.Fail["iam:PutRolePermissionsBoundary"] = enforcetest.APIError("Throttling", "Rate exceeded")
	defer delete(l.fake.Fail, "iam:PutRolePermissionsBoundary")
	for i := 0; i < 2; i++ {
		if out, err := l.execute(exec, run2, dep2); err != nil || out.Result != services.DeployRetryLater {
			t.Fatalf("try %d: %+v %v", i, out, err)
		}
	}
	if out, err := l.execute(exec, run2, dep2); err != nil || out.Result != services.DeployFailed || out.Reason != services.DeployReasonRetriesExhausted {
		t.Fatalf("exhausted: %+v %v", out, err)
	}
}

// IAM is eventually consistent: an op AWS answered `ok` that a read does not
// show yet is never re-sent (that would be a duplicate default change); the
// run is handed back until reads agree, and after ConsistencyWindow the
// state is treated as changed (blocked).
func TestP3T310EventualConsistencyNeverResends(t *testing.T) {
	l := newX3Lab(t)
	x := l.role("LagRole", "/", nil)
	arn := x.authsecARN()
	d, _, _ := igagov.ExcludeOnlyDocument([]string{"ec2"})
	l.fake.AddPolicy("/authsec/", "AuthSecBoundary-"+x.role.RoleID, map[string]string{igagov.TagManagedBy: igagov.TagManagedByValue,
		igagov.TagWorkspace: x.ref.WorkspaceRef, igagov.TagControl: x.ref.ID}, string(d))
	l.fake.SetBoundary(x.name, arn)
	tp := l.compile(l.fake.Discovery(), x, "ec2", "sqs")
	s := l.store(x, tp.Apply, *tp.Undo)
	dep := l.deploy(x, s, igagov.PlanApply)
	lag := &x3Lag{DiscoveryIAM: l.fake.Discovery(), frozen: map[string]string{}}
	exec := l.executorWith(lag)
	l.fake.AfterApply["iam:CreatePolicyVersion"] = func(context.Context) error {
		lag.frozen[arn] = "v1" // reads keep showing the old default
		return nil
	}
	run := l.claim(dep, "worker-a", time.Now())
	for i := 0; i < 2; i++ {
		out, err := l.execute(exec, run, dep)
		if err != nil || out.Result != services.DeployRetryLater || out.Reason != services.DeployReasonAwaitConsistency {
			t.Fatalf("lagging read %d: %+v %v", i, out, err)
		}
	}
	if l.calls("iam:CreatePolicyVersion", arn) != 1 {
		t.Fatalf("CreatePolicyVersion re-sent: %d", l.calls("iam:CreatePolicyVersion", arn))
	}
	// Past the window the unseen op is a changed state, not a lag.
	exec.ConsistencyWindow = time.Nanosecond
	if out, err := l.execute(exec, run, dep); err != nil || out.Result != services.DeployBlocked || out.Reason != services.DeployReasonNotVisible {
		t.Fatalf("past the window: %+v %v", out, err)
	}
	exec.ConsistencyWindow = 0
	delete(lag.frozen, arn)
	out := l.mustApply(exec, run, dep)
	if out.Ops[len(out.Ops)-1].Operation != igagov.OpTagPolicy || l.calls("iam:CreatePolicyVersion", arn) != 1 {
		t.Fatalf("after consistency: %+v", out.Ops)
	}
}

// A15: the customer changed the AuthSec policy's default document before
// the undo: blocked (artifact_changed_outside_authsec) with the diff, no
// write. And plans the executor never runs directly are refused unread.
func TestP3T310ChangedOutsideAndRefusals(t *testing.T) {
	l := newX3Lab(t)
	x := l.role("EditedRole", "/", nil)
	tp := l.compile(l.fake.Discovery(), x, "sqs")
	s := l.store(x, tp.Apply, *tp.Undo)
	dep := l.deploy(x, s, igagov.PlanApply)
	l.mustApply(l.exec, l.claim(dep, "worker-a", time.Now()), dep)
	l.settle(dep, "verified")
	l.fake.SetDefaultDocument(x.authsecARN(), x3AppDoc)
	undo := l.deploy(x, s, igagov.PlanUndo)
	calls := len(l.fake.Calls)
	out, err := l.execute(l.exec, l.claim(undo, "worker-a", time.Now()), undo)
	if err != nil || out.Result != services.DeployBlocked || out.Reason != igagov.ConflictChangedOutside || out.Detail == "" ||
		len(l.fake.Calls) != calls {
		t.Fatalf("changed outside: %+v %v", out, err)
	}

	// Refusals: a deployment not applying; a plan that is not the
	// deployment's; an export plan.
	l.settle(undo, "blocked")
	d := l.deployment(undo)
	p, _ := services.LoadIGAGovPlan(l.db, l.ws, d.PlanID)
	run := l.claim(undo, "worker-b", time.Now().Add(3*time.Minute))
	if out, err := l.exec.ExecutePlan(context.Background(), run, d, p); err != nil || out.Result != services.DeployRefused ||
		out.Reason != services.DeployReasonNotApplying {
		t.Fatalf("not applying: %+v %v", out, err)
	}
	ap, _ := services.LoadIGAGovPlan(l.db, l.ws, s.plans[igagov.PlanApply])
	if out, err := l.exec.ExecutePlan(context.Background(), run, d, ap); err != nil || out.Result != services.DeployRefused ||
		out.Reason != services.DeployReasonPlanMismatch {
		t.Fatalf("mismatch: %+v %v", out, err)
	}
	ex := p
	ex.Delivery = igagov.DeliveryExport
	d.Delivery = igagov.DeliveryExport
	if out, err := l.exec.ExecutePlan(context.Background(), run, d, ex); err != nil || out.Result != services.DeployRefused ||
		out.Reason != services.DeployReasonNotDirect {
		t.Fatalf("export: %+v %v", out, err)
	}
	if len(l.fake.Calls) != calls {
		t.Fatalf("a refusal called AWS: %v", l.fake.Calls[calls:])
	}
}

// discovery_unavailable: a connector that is not active blocks the
// deployment before anything is read or written; a binding that is no
// longer verified fails it before any write.
func TestP3T310DiscoveryAndBindingGates(t *testing.T) {
	l := newX3Lab(t)
	x := l.role("GateRole", "/", nil)
	tp := l.compile(l.fake.Discovery(), x, "sqs")
	s := l.store(x, tp.Apply, *tp.Undo)
	dep := l.deploy(x, s, igagov.PlanApply)
	run := l.claim(dep, "worker-a", time.Now())
	p3exec(t, l.db, `UPDATE cloud_connector SET status = 'error', last_error = 'AccessDenied on sts:AssumeRole' WHERE id = ?`, l.conn.ID)
	out, err := l.execute(l.exec, run, dep)
	if err != nil || out.Result != services.DeployBlocked || out.Reason != services.EnfCodeDiscoveryUnavailable {
		t.Fatalf("connector in error: %+v %v", out, err)
	}
	p3exec(t, l.db, `UPDATE cloud_connector SET status = 'active', last_error = '' WHERE id = ?`, l.conn.ID)
	p3exec(t, l.db, `UPDATE cloud_enforcement_binding SET state = 'partial' WHERE connector_id = ? AND state = 'verified'`, l.conn.ID)
	calls := len(l.fake.Calls)
	out, err = l.execute(l.exec, run, dep)
	if err != nil || out.Result != services.DeployFailed || out.Reason != services.EnfCodePartial || len(l.fake.Calls) != calls ||
		len(l.attemptRows(dep)) != 0 {
		t.Fatalf("partial binding: %+v %v", out, err)
	}
}

// §8.5: a ServiceFailure (5xx) after AWS applied the request is not an
// answer: the attempt is unknown and the op is never retried, even though
// the worker that sent it is alive and holds its lease.
func TestP3T310ServiceFailureIsUnknown(t *testing.T) {
	l := newX3Lab(t)
	x := l.role("FailureRole", "/", nil)
	tp := l.compile(l.fake.Discovery(), x, "sqs")
	s := l.store(x, tp.Apply, *tp.Undo)
	dep := l.deploy(x, s, igagov.PlanApply)
	run := l.claim(dep, "worker-a", time.Now())
	l.fake.AfterApply["iam:CreatePolicy"] = func(context.Context) error {
		return enforcetest.APIError("ServiceFailure", "We encountered an internal error")
	}
	out, err := l.execute(l.exec, run, dep)
	delete(l.fake.AfterApply, "iam:CreatePolicy")
	if err != nil || out.Result != services.DeployOutcomeUnknown || out.SettleAfter == nil {
		t.Fatalf("service failure: %+v %v", out, err)
	}
	if ats := l.attemptRows(dep); len(ats) != 1 || ats[0].Status != models.GovAttemptUnknown {
		t.Fatalf("attempts: %+v", ats)
	}
	if out, err := l.execute(l.exec, run, dep); err != nil || out.Result != services.DeployHold ||
		l.calls("iam:CreatePolicy", x.role.RoleID) != 1 || l.calls("iam:PutRolePermissionsBoundary", x.arn) != 0 {
		t.Fatalf("rerun: %+v %v", out, err)
	}
}
