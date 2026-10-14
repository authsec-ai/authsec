package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagov"
)

// T3.16 (SPEC-iga-phase3-policy.md §8.4, §8.5, §8.7): a queued apply goes
// through the deploy job (authority, binding, executor) to
// applied_unverified with the control's baseline; verification waits for a
// publication that agrees -- never elapsed time (A55: overdue, not
// verified); then verified writes the posture as an enforcement observer
// (removed, finding resolved by the deployment), the history and the gate
// facts T3.15 reads.
//
// Safeguards (mutation-checked): verified requires artifact AND graph
// (markVerified's guard in VerifyHandler); the overdue branch never verifies.
func TestP3T316DeployVerifyPostureA1A55(t *testing.T) {
	d := newDLab(t)
	x := d.role("A1Role", "/", nil)
	tp := d.compile(d.fake.Discovery(), x, "sqs", "sns")
	s := d.storeApproved(x, tp.Apply, *tp.Undo)
	fSQS, fSNS := d.finding(x, "sqs"), d.finding(x, "sns")
	dep := d.queue(x, s, igagov.PlanApply)

	d.mustRun("deploy", dep)
	dd := d.deployment(dep)
	if dd.State != "applied_unverified" || dd.AppliedAt == nil || dd.VerifyDeadlineAt == nil ||
		!dd.VerifyDeadlineAt.Equal(dd.AppliedAt.Add(time.Hour)) {
		t.Fatalf("after deploy: %+v", dd)
	}
	var ctl struct {
		State               string
		BaselineCapturedAt  *time.Time
		BaselineBoundaryArn *string
	}
	d.db.Raw(`SELECT state, baseline_captured_at, baseline_boundary_arn FROM iga_gov_control WHERE id = ?`, x.control).Scan(&ctl)
	if ctl.State != "active" || ctl.BaselineCapturedAt == nil || ctl.BaselineBoundaryArn != nil {
		t.Fatalf("control after first apply: %+v (baseline: no boundary)", ctl)
	}

	// No publication yet: graph awaiting, stays applied_unverified.
	if err := d.runJob("verify", dep); !isRetryLater(err) {
		t.Fatalf("verify without evidence: %v", err)
	}
	if d.state(dep) != "applied_unverified" || d.dimension(dep, "artifact") != "passed" || d.dimension(dep, "graph") != "awaiting_evidence" {
		t.Fatalf("awaiting: %s %s %s", d.state(dep), d.dimension(dep, "artifact"), d.dimension(dep, "graph"))
	}
	// A55: past the deadline with still no publication: overdue, NEVER verified.
	d.advance(2 * time.Hour)
	if err := d.runJob("verify", dep); !isRetryLater(err) {
		t.Fatalf("verify overdue: %v", err)
	}
	if d.state(dep) != "applied_unverified" || d.dimension(dep, "graph") != "overdue" {
		t.Fatalf("A55: %s graph %s", d.state(dep), d.dimension(dep, "graph"))
	}
	gf, err := d.dep.DeploymentGateFacts(context.Background(), d.ws, dep)
	if err != nil || !gf.Overdue || gf.Dimensions["artifact"].Outcome != "passed" {
		t.Fatalf("gate facts while overdue: %+v %v", gf, err)
	}
	if len(d.posture(x)) != 0 {
		t.Fatalf("posture before verification: %v", d.posture(x))
	}

	// A publication that agrees: verified; posture removed; findings resolved.
	arn := *tp.Apply.DesiredBoundaryARN
	d.publish(x, d.now().Add(time.Second), arn, d.ledgerVersion(x, arn))
	d.mustRun("verify", dep)
	dd = d.deployment(dep)
	if dd.State != "verified" || dd.VerifiedAt == nil {
		t.Fatalf("after publication: %s", dd.State)
	}
	if p := d.posture(x); p["sqs"] != "applied/removed" || p["sns"] != "applied/removed" || len(p) != 2 {
		t.Fatalf("posture: %v", p)
	}
	if d.findingStatus(fSQS) != "resolved" || d.findingStatus(fSNS) != "resolved" {
		t.Fatalf("findings: %s %s", d.findingStatus(fSQS), d.findingStatus(fSNS))
	}
	var by struct{ ResolvedByDeploymentID *uuid.UUID }
	d.db.Raw(`SELECT resolved_by_deployment_id FROM iga_gov_finding WHERE id = ?`, fSQS).Scan(&by)
	if by.ResolvedByDeploymentID == nil || *by.ResolvedByDeploymentID != dep {
		t.Fatalf("resolved_by %v", by.ResolvedByDeploymentID)
	}
	var hist []struct{ Service, Change, Outcome string }
	d.db.Raw(`SELECT service, change, outcome FROM iga_gov_service_outcome WHERE deployment_id = ? ORDER BY service`, dep).Scan(&hist)
	if len(hist) != 2 || hist[0].Change != "newly_excluded" || hist[0].Outcome != "removed" {
		t.Fatalf("history: %+v", hist)
	}
	_, seq := d.controlState(x)
	if seq != 1 {
		t.Fatalf("enforcement_seq %d, want 1 after the first observation", seq)
	}
	gf, err = d.dep.DeploymentGateFacts(context.Background(), d.ws, dep)
	if err != nil || gf.State != "verified" || gf.Dimensions["graph"].Outcome != "passed" || len(gf.Gates) != 5 ||
		gf.Dimensions["restriction"].Outcome == "passed" {
		t.Fatalf("gate facts: %+v %v", gf, err)
	}
	// A18: no traffic: restriction is not observed -- never passed by absence.
	if r := gf.Dimensions["restriction"]; r.Outcome != "awaiting_evidence" || r.Reason != "not_observed" {
		t.Fatalf("restriction with no traffic: %+v", r)
	}
}

// A12: the role is recreated between approval and deployment: blocked,
// nothing applied, the control released for a new plan.
func TestP3T316RoleRecreatedIsBlockedA12(t *testing.T) {
	d := newDLab(t)
	x := d.role("A12Role", "/", nil)
	tp := d.compile(d.fake.Discovery(), x, "sqs")
	s := d.storeApproved(x, tp.Apply, *tp.Undo)
	d.fake.Roles["A12Role"].RoleID = "AROARECREATED0000001"
	calls := len(d.fake.Calls)
	dep := d.queue(x, s, igagov.PlanApply)
	d.mustRun("deploy", dep)
	dd := d.deployment(dep)
	if dd.State != "blocked" || len(d.fake.Calls) != calls {
		t.Fatalf("A12: %s %q, AWS calls %v", dd.State, dd.StateReason, d.fake.Calls[calls:])
	}
	var n int64
	d.db.Raw(`SELECT count(*) FROM iga_gov_artifact WHERE control_id = ? AND state = 'intended'`, x.control).Scan(&n)
	if n != 0 {
		t.Fatal("intended ledger rows left by a blocked run")
	}
}

// The deploy job's authority (§2.8): an approval that is not usable blocks;
// a paused policy waits queued; a binding that is not fresh blocks with its
// code.
func TestP3T316DeployAuthorityAndGates(t *testing.T) {
	d := newDLab(t)
	x := d.role("AuthRole", "/", nil)
	tp := d.compile(d.fake.Discovery(), x, "sqs")

	t.Run("paused policy waits", func(t *testing.T) {
		s := d.storeApproved(x, tp.Apply, *tp.Undo)
		p3exec(t, d.db, `UPDATE iga_gov_policy SET lifecycle = 'paused' WHERE id = ?`, x.policy)
		dep := d.queue(x, s, igagov.PlanApply)
		if err := d.runJob("deploy", dep); !isRetryLater(err) || d.state(dep) != "queued" {
			t.Fatalf("paused: %v %s", err, d.state(dep))
		}
		p3exec(t, d.db, `UPDATE iga_gov_policy SET lifecycle = 'active' WHERE id = ?`, x.policy)
		p3exec(t, d.db, `UPDATE iga_gov_deployment SET state = 'blocked' WHERE id = ?`, dep)
	})
	t.Run("binding not verified blocks", func(t *testing.T) {
		s := d.storeApproved(x, tp.Apply, *tp.Undo)
		d.bindErr = &services_GovErr{code: "binding_partial"}
		defer func() { d.bindErr = nil }()
		dep := d.queue(x, s, igagov.PlanApply)
		d.mustRun("deploy", dep)
		if dd := d.deployment(dep); dd.State != "blocked" {
			t.Fatalf("binding: %s %s", dd.State, dd.StateReason)
		}
	})
	t.Run("approver is the author", func(t *testing.T) {
		s := d.storeApproved(x, tp.Apply, *tp.Undo)
		p3exec(t, d.db, `UPDATE iga_gov_approval SET decided_by = ? WHERE id = ?`, d.user, s.approval)
		dep := d.queue(x, s, igagov.PlanApply)
		d.mustRun("deploy", dep)
		if dd := d.deployment(dep); dd.State != "blocked" || dd.StateReason[:16] != "approval_invalid" {
			t.Fatalf("self-approved: %s %q", dd.State, dd.StateReason)
		}
	})
}

type services_GovErr struct{ code string }

func (e *services_GovErr) Error() string { return e.code }

func jsonMap(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	m := map[string]any{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}
