package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/services"
)

const dOtherDoc = `{"Version":"2012-10-17","Statement":[{"Sid":"Edited","Effect":"Allow","NotAction":["ec2:*"],"Resource":"*"}]}`

// §8.8 drift: every classification, recorded by an enforcement observer
// (posture re-assessed, findings follow it), never reconciled: the drift
// check makes no AWS write.
//
// Safeguard (mutation-checked): no AWS write from drift_check (the call
// count); the finding reopened from the posture, not from the deployment.
func TestP3T316DriftClassificationsNeverReconciled(t *testing.T) {
	d := newDLab(t)
	d.fake.AddRole("ReportsRole", "/", nil)
	cases := []struct {
		name, want string
		mutate     func(x *x3Role, arn string)
	}{
		{"detached", services.DriftBoundaryReplaced, func(x *x3Role, _ string) { d.fake.SetBoundary(x.name, "") }},
		{"document", services.DriftDocumentChanged, func(_ *x3Role, arn string) { d.fake.AddVersion(arn, dOtherDoc, true) }},
		{"elsewhere", services.DriftAttachedElsewhere, func(_ *x3Role, arn string) { d.fake.SetBoundary("ReportsRole", arn) }},
		{"gone", services.DriftTargetGone, func(x *x3Role, _ string) { delete(d.fake.Roles, x.name) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := d.role("Drift"+c.name, "/", nil)
			tp := d.compile(d.fake.Discovery(), x, "sqs")
			f := d.finding(x, "sqs")
			dep := d.applyAndVerify(x, d.storeApproved(x, tp.Apply, *tp.Undo))
			if d.findingStatus(f) != "resolved" {
				t.Fatalf("finding before drift: %s", d.findingStatus(f))
			}
			// A clean check changes nothing.
			d.mustRun("drift_check", dep)
			if d.state(dep) != "verified" {
				t.Fatalf("clean drift check: %s", d.state(dep))
			}
			arn := *tp.Apply.DesiredBoundaryARN
			c.mutate(x, arn)
			calls := len(d.fake.Calls)
			d.mustRun("drift_check", dep)
			dd := d.deployment(dep)
			if dd.State != "drifted" || dd.StateReason != c.want {
				t.Fatalf("drift: %s %q, want %s", dd.State, dd.StateReason, c.want)
			}
			if len(d.fake.Calls) != calls {
				t.Fatalf("drift_check wrote to AWS: %v", d.fake.Calls[calls:])
			}
			p := d.posture(x)["sqs"]
			switch c.want {
			case services.DriftBoundaryReplaced:
				if p != "not_applied/not_removed" || d.findingStatus(f) != "reopened" {
					t.Fatalf("posture %s finding %s", p, d.findingStatus(f))
				}
			case services.DriftDocumentChanged:
				// The edited document still excludes ec2 only: sqs not excluded.
				if p != "not_applied/not_removed" || d.findingStatus(f) != "reopened" {
					t.Fatalf("posture %s finding %s", p, d.findingStatus(f))
				}
			case services.DriftAttachedElsewhere:
				if p != "applied/removed" {
					t.Fatalf("posture %s", p)
				}
				d.fake.SetBoundary("ReportsRole", "")
			case services.DriftTargetGone:
				if st, _ := d.controlState(x); st != "removed" || d.findingStatus(f) != "superseded" {
					t.Fatalf("control %s finding %s", st, d.findingStatus(f))
				}
			}
		})
	}
}

// A48: version 1 excludes sqs, version 2 excludes sqs and sns; undo of
// version 2 restores version 1: sqs stays removed and resolved, only sns is
// unexcluded and its finding reopened; history counts sqs +1, sns +1, sns -1.
// Also: only the latest deployment can be undone; nothing starts while one
// is in flight.
//
// Safeguard (mutation-checked): the undo's observer recomputes EVERY service
// from the restored boundary (sqs stays applied).
func TestP3T316SuccessiveDeploymentsAndUndoA48(t *testing.T) {
	d := newDLab(t)
	ctx := context.Background()
	x := d.role("A48Role", "/", nil)
	fSQS, fSNS := d.finding(x, "sqs"), d.finding(x, "sns")
	tp1 := d.compile(d.fake.Discovery(), x, "sqs")
	d1 := d.applyAndVerify(x, d.storeApproved(x, tp1.Apply, *tp1.Undo))
	tp2 := d.compile(d.fake.Discovery(), x, "sns", "sqs")
	s2 := d.storeApproved(x, tp2.Apply, *tp2.Undo)
	d2 := d.applyAndVerify(x, s2)
	if d.state(d1) != "superseded" {
		t.Fatalf("v1 after v2 verified: %s", d.state(d1))
	}
	if p := d.posture(x); p["sqs"] != "applied/removed" || p["sns"] != "applied/removed" || len(p) != 2 {
		t.Fatalf("posture after v2: %v", p)
	}
	if _, err := d.dep.Undo(ctx, d.ws, d.approver, d1, services.GovUndoRequest{}, false); govCode(err) != services.GovCodeNotLatestDeployment {
		t.Fatalf("undo of v1 while v2 is latest: %v", err)
	}
	u, err := d.dep.Undo(ctx, d.ws, d.approver, d2, services.GovUndoRequest{}, false)
	if err != nil || u.State != "queued" || u.ApprovalID == nil || *u.ApprovalID != s2.approval {
		t.Fatalf("undo: %+v %v", u, err)
	}
	if _, err := d.dep.Undo(ctx, d.ws, d.approver, d2, services.GovUndoRequest{}, false); govCode(err) != services.GovCodeDeploymentInFlight {
		t.Fatalf("second undo while one is queued: %v", err)
	}
	d.mustRun("deploy", u.ID)
	if st := d.state(u.ID); st != "applied_unverified" {
		t.Fatalf("undo deploy: %s %s", st, d.deployment(u.ID).StateReason)
	}
	arn := *tp1.Apply.DesiredBoundaryARN
	d.publish(x, d.now().Add(time.Second), arn, d.ledgerVersion(x, arn))
	d.mustRun("verify", u.ID)
	if d.state(u.ID) != "verified" || d.state(d2) != "undone" {
		t.Fatalf("after undo verified: undo %s v2 %s", d.state(u.ID), d.state(d2))
	}
	if p := d.posture(x); p["sqs"] != "applied/removed" || p["sns"] != "not_applied/not_removed" {
		t.Fatalf("posture after undo: %v", p)
	}
	if d.findingStatus(fSQS) != "resolved" || d.findingStatus(fSNS) != "reopened" {
		t.Fatalf("findings after undo: sqs %s sns %s", d.findingStatus(fSQS), d.findingStatus(fSNS))
	}
	var hist []struct{ Deployment, Service, Change string }
	d.db.Raw(`SELECT deployment_id::text AS deployment, service, change FROM iga_gov_service_outcome WHERE workspace_id = ?
		AND change <> 'already_excluded' ORDER BY updated_at, service`, d.ws).Scan(&hist)
	got := []string{}
	for _, h := range hist {
		tag := map[string]string{d1.String(): "v1", d2.String(): "v2", u.ID.String(): "undo"}[h.Deployment]
		got = append(got, tag+":"+h.Service+":"+h.Change)
	}
	if strings.Join(got, ",") != "v1:sqs:newly_excluded,v2:sns:newly_excluded,undo:sns:newly_unexcluded" {
		t.Fatalf("history (change counts): %v", got)
	}
}

// A15: the AuthSec policy's default version changed before the undo: the
// undo is blocked (409 artifact_changed_outside_authsec) with the diff, and
// nothing is created.
func TestP3T316UndoBlockedByOutsideChangeA15(t *testing.T) {
	d := newDLab(t)
	x := d.role("A15Role", "/", nil)
	tp := d.compile(d.fake.Discovery(), x, "sqs")
	dep := d.applyAndVerify(x, d.storeApproved(x, tp.Apply, *tp.Undo))
	d.fake.AddVersion(*tp.Apply.DesiredBoundaryARN, dOtherDoc, true)
	_, err := d.dep.Undo(context.Background(), d.ws, d.approver, dep, services.GovUndoRequest{}, false)
	var ge *services.GovError
	if govCode(err) != services.GovCodeChangedOutside || !asGov(err, &ge) || ge.Detail["classification"] == nil {
		t.Fatalf("A15: %v", err)
	}
	var n int64
	d.db.Raw(`SELECT count(*) FROM iga_gov_deployment WHERE control_id = ? AND kind = 'undo'`, x.control).Scan(&n)
	if n != 0 {
		t.Fatal("a blocked undo created a deployment")
	}
}

// A35 / A40: the AuthSec boundary gained a consumer (another role uses it as
// its boundary): drift artifact_attached_elsewhere; undo 409
// artifact_consumers_changed with a role-only recovery plan (absent +
// retain_shared) that the original approval does not authorise; with
// governance:emergency it runs, verifies on the disposition-aware rules
// (no boundary on this role; the policy kept, unchanged, used by the other
// role), the ledger records the policy released, and the other role is
// untouched.
//
// Safeguard (mutation-checked): the attachment-set check (the undo is
// refused, never run, while the artifact has another user).
func TestP3T316UndoConsumersChangedRoleOnlyRecoveryA35A40(t *testing.T) {
	d := newDLab(t)
	ctx := context.Background()
	d.fake.AddRole("SecondRole", "/", nil)
	x := d.role("A35Role", "/", nil)
	tp := d.compile(d.fake.Discovery(), x, "sqs")
	dep := d.applyAndVerify(x, d.storeApproved(x, tp.Apply, *tp.Undo))
	arn := *tp.Apply.DesiredBoundaryARN
	d.fake.SetBoundary("SecondRole", arn)
	d.mustRun("drift_check", dep)
	if dd := d.deployment(dep); dd.State != "drifted" || dd.StateReason != services.DriftAttachedElsewhere {
		t.Fatalf("A35 drift: %s %s", dd.State, dd.StateReason)
	}
	calls := len(d.fake.Calls)
	_, err := d.dep.Undo(ctx, d.ws, d.approver, dep, services.GovUndoRequest{}, false)
	var ge *services.GovError
	if govCode(err) != services.GovCodeConsumersChanged || !asGov(err, &ge) || ge.Detail["recovery_plan_id"] == nil {
		t.Fatalf("A35 undo: %v", err)
	}
	if len(d.fake.Calls) != calls {
		t.Fatal("a blocked undo wrote to AWS")
	}
	rpID := ge.Detail["recovery_plan_id"].(uuid.UUID)
	// Its own approval is needed: the original approval does not name it.
	if _, err := d.dep.Undo(ctx, d.ws, d.approver, dep, services.GovUndoRequest{PlanID: &rpID}, false); govCode(err) != services.GovCodeApprovalRequired {
		t.Fatalf("recovery with the original approval: %v", err)
	}
	u, err := d.dep.Undo(ctx, d.ws, d.approver, dep, services.GovUndoRequest{PlanID: &rpID, Reason: "SecondRole now depends on it"}, true)
	if err != nil || u.EmergencyBy == nil || u.ApprovalID != nil {
		t.Fatalf("emergency role-only recovery: %+v %v", u, err)
	}
	d.mustRun("deploy", u.ID)
	if st := d.state(u.ID); st != "applied_unverified" {
		t.Fatalf("recovery deploy: %s %s", st, d.deployment(u.ID).StateReason)
	}
	d.publish(x, d.now().Add(time.Second), "", "")
	d.mustRun("verify", u.ID)
	if d.state(u.ID) != "verified" || d.state(dep) != "undone" {
		t.Fatalf("A40: recovery %s (%s graph %s), apply %s", d.state(u.ID), d.dimension(u.ID, "artifact"), d.dimension(u.ID, "graph"), d.state(dep))
	}
	if d.fake.BoundaryOf(x.name) != "" || d.fake.BoundaryOf("SecondRole") != arn || d.calls("iam:DeletePolicy", arn) != 0 {
		t.Fatalf("AWS: boundary %q second %q deletes %d", d.fake.BoundaryOf(x.name), d.fake.BoundaryOf("SecondRole"), d.calls("iam:DeletePolicy", arn))
	}
	if _, _, _, _, ok := d.fake.PolicyState(arn); !ok {
		t.Fatal("the shared policy was deleted")
	}
	released := false
	for _, a := range d.artifacts(x) {
		released = released || (a.NativeARN == arn && a.State == "released")
	}
	if !released {
		t.Fatalf("ledger: %v", d.ledger(x))
	}
	if p := d.posture(x)["sqs"]; p != "not_applied/not_removed" {
		t.Fatalf("posture after recovery: %s", p)
	}
}

func asGov(err error, out **services.GovError) bool {
	ge, ok := err.(*services.GovError)
	if ok {
		*out = ge
	}
	return ok
}

// §8.10 emergency removal (§14.1 step 11) and A51: the control restores its
// baseline (absent + delete: detached and deleted), verifies on "no
// boundary, policy gone", and is retired in the same compare-and-swap; a
// worker still holding the old control loses its swap and its posture write
// is refused; a new policy's control for the same role takes over every
// posture row in its first verified deployment's swap.
//
// Safeguard (mutation-checked): the retirement in the CAS statement and the
// 049/051 triggers' fence (a stale write of the old control refused).
func TestP3T316RemoveControlAndReplacementControlA51(t *testing.T) {
	d := newDLab(t)
	ctx := context.Background()
	x := d.role("A51Role", "/", nil)
	f := d.finding(x, "sqs")
	tp := d.compile(d.fake.Discovery(), x, "sqs")
	dep := d.applyAndVerify(x, d.storeApproved(x, tp.Apply, *tp.Undo))
	arn := *tp.Apply.DesiredBoundaryARN

	res, err := d.dep.RemoveControl(ctx, d.ws, d.approver, x.policy, services.GovRemoveControlRequest{
		ControlIDs: []string{x.control.String()}, Reason: "incident"}, true)
	if err != nil || len(res.Deployments) != 1 || len(res.Plans) != 1 {
		t.Fatalf("emergency removal: %+v %v", res, err)
	}
	rp := res.Plans[0]
	if rp.DesiredAttachment != "absent" || rp.ArtifactDisposition != "delete" {
		t.Fatalf("removal plan: %s %s", rp.DesiredAttachment, rp.ArtifactDisposition)
	}
	rm := res.Deployments[0].ID
	d.mustRun("deploy", rm)
	if st := d.state(rm); st != "applied_unverified" {
		t.Fatalf("removal deploy: %s %s", st, d.deployment(rm).StateReason)
	}
	d.publish(x, d.now().Add(time.Second), "", "")
	d.retirePolicy(arn)
	_, seqBefore := d.controlState(x)
	d.mustRun("verify", rm)
	st, seq := d.controlState(x)
	if d.state(rm) != "verified" || st != "removed" || seq != seqBefore+1 {
		t.Fatalf("after removal: dep %s (graph %s) control %s seq %d->%d", d.state(rm), d.dimension(rm, "graph"), st, seqBefore, seq)
	}
	if d.fake.BoundaryOf(x.name) != "" {
		t.Fatal("boundary still attached")
	}
	if _, _, _, _, ok := d.fake.PolicyState(arn); ok {
		t.Fatal("policy not deleted")
	}
	for _, a := range d.artifacts(x) {
		if a.State != "removed" {
			t.Fatalf("ledger after removal: %v", d.ledger(x))
		}
	}
	if p := d.posture(x)["sqs"]; p != "not_applied/not_removed" || d.findingStatus(f) != "reopened" {
		t.Fatalf("posture %s finding %s", p, d.findingStatus(f))
	}
	_ = dep

	// A51: the old control is fenced.
	if res := d.db.Exec(`UPDATE iga_gov_control SET enforcement_seq = enforcement_seq + 1 WHERE id = ? AND enforcement_seq = ? AND state <> 'removed'`,
		x.control, seq); res.Error != nil || res.RowsAffected != 0 {
		t.Fatalf("old control's swap: %v rows %d", res.Error, res.RowsAffected)
	}
	if err := d.db.Exec(`UPDATE iga_gov_control SET enforcement_seq = enforcement_seq + 1 WHERE id = ?`, x.control).Error; err == nil {
		t.Fatal("a retired control's sequence advanced")
	}
	if err := d.db.Exec(`UPDATE iga_gov_service_posture SET exclusion = 'applied', enforcement_seq = ? WHERE role_id = ? AND service = 'sqs'`,
		seq+1, x.role.RoleID).Error; err == nil {
		t.Fatal("a late write of the retired control was accepted")
	}

	// A replacement control (another policy) takes the posture over.
	x2 := *x
	x2.policy, x2.control, x2.versions = uuid.New(), uuid.New(), 0
	p3exec(t, d.db, `INSERT INTO iga_gov_policy (id, workspace_id, name, family, provider, created_by) VALUES (?, ?, ?, 'cloud_access', 'aws', ?)`,
		x2.policy, d.ws, "A51 replacement", d.user)
	p3exec(t, d.db, `INSERT INTO iga_gov_control (id, workspace_id, connector_id, account_id, role_id, role_arn, identity_account_id, policy_id, boundary_policy_arn)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, x2.control, d.ws, d.conn.ID, testAccount, x.role.RoleID, x.arn, x.identity, x2.policy, arn)
	x2.ref.ID, x2.ref.PolicyID = x2.control.String(), x2.policy.String()
	tp2 := d.compile(d.fake.Discovery(), &x2, "sqs")
	d.applyAndVerify(&x2, d.storeApproved(&x2, tp2.Apply, *tp2.Undo))
	var rows []struct {
		ControlID uuid.UUID
		Outcome   string
	}
	d.db.Raw(`SELECT control_id, outcome FROM iga_gov_service_posture WHERE workspace_id = ? AND role_id = ?`, d.ws, x.role.RoleID).Scan(&rows)
	if len(rows) != 1 || rows[0].ControlID != x2.control || rows[0].Outcome != "removed" || d.findingStatus(f) != "resolved" {
		t.Fatalf("A51 handoff: %+v finding %s", rows, d.findingStatus(f))
	}
}

// §8.1 step 5: a change matching the document of an unknown attempt on the
// control, seen after the deployment verified, is drift
// late_mutation_suspected; nothing is re-applied or reverted.
func TestP3T316LateMutationSuspectedA58e(t *testing.T) {
	d := newDLab(t)
	x := d.role("A58eRole", "/", nil)
	tp := d.compile(d.fake.Discovery(), x, "sqs")
	dep := d.applyAndVerify(x, d.storeApproved(x, tp.Apply, *tp.Undo))
	canon, h, err := igagov.CanonicalDocument(dOtherDoc)
	if err != nil {
		t.Fatal(err)
	}
	p3exec(t, d.db, `INSERT INTO iga_gov_document (workspace_id, document_hash, canonical, document) VALUES (?, ?, ?, ?::jsonb)
		ON CONFLICT DO NOTHING`, d.ws, h, string(canon), string(canon))
	att := uuid.New()
	p3exec(t, d.db, `INSERT INTO iga_gov_attempt (id, workspace_id, deployment_id, op_seq, attempt_no, lease_version, operation, request_hash, document_hash, status)
		VALUES (?, ?, ?, 7, 1, 1, 'CreatePolicyVersion', 'late', ?, 'prepared')`, att, d.ws, dep, h)
	p3exec(t, d.db, `UPDATE iga_gov_attempt SET status = 'dispatched', signed_at = now(), dispatched_at = now() WHERE id = ?`, att)
	p3exec(t, d.db, `UPDATE iga_gov_attempt SET status = 'unknown' WHERE id = ?`, att)
	d.fake.AddVersion(*tp.Apply.DesiredBoundaryARN, dOtherDoc, true)
	calls := len(d.fake.Calls)
	d.mustRun("drift_check", dep)
	if dd := d.deployment(dep); dd.State != "drifted" || dd.StateReason != services.DriftLateMutation || len(d.fake.Calls) != calls {
		t.Fatalf("late mutation: %s %q calls %v", dd.State, dd.StateReason, d.fake.Calls[calls:])
	}
}
