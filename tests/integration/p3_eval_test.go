package integration

import (
	"errors"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// T3.06 (SPEC-iga-phase3-policy.md §2.5, §8.2): finding evaluation runs
// inside the REAL projection job, between the publication commit and the
// barrier release, and writes evidence, findings and results in one
// transaction.

// The basic path: a workload-bound role granted sqs and s3, with s3 used and
// sqs never attempted in a 200-day-old role's report, is evaluated at its
// first publication: evaluation complete, evidence per service with the
// manifest run, an unused_service(sqs) finding at age_unverified (day one,
// A36), missing_owner, every result citing the role connector's run.
func TestP3T306EvaluationInsideTheProjectionJob(t *testing.T) {
	l := newP3eLab(t, "p3-t306-basic")
	a := l.account(accountA)
	arn := p3eOldRole(a, "RefundTaskRole", "AROAREFUND0001", 200*24*time.Hour, "RefundWork", p3eSQSS3)
	a.lambda("us-east-1", "refund-agent", arn)
	l.activity(a).set(arn, map[string]*time.Time{"s3": p3eTime(3 * 24 * time.Hour), "sqs": nil})

	run, rev := l.cycle(a, nil)
	ev := l.evaluation(rev)
	if ev.Status != models.GovEvalComplete || ev.Attempts != 1 || ev.FinishedAt == nil {
		t.Fatalf("evaluation %+v, want complete on attempt 1", ev)
	}
	var evidence []models.IGAGovActivityEvidence
	l.db.Where("workspace_id = ? AND rev = ?", l.ws, rev).Order("service").Find(&evidence)
	if len(evidence) != 2 {
		t.Fatalf("evidence rows %d, want s3 and sqs", len(evidence))
	}
	for _, e := range evidence {
		if e.State != igagov.EvidenceCollected || e.ScanRunID == nil || *e.ScanRunID != run.ID || e.RoleID != "AROAREFUND0001" {
			t.Fatalf("evidence %+v, want collected from run %s", e, run.ID)
		}
		if e.GrantAgeBasis != igagov.GrantAgePredatesObservation {
			t.Fatalf("day one: %s grant age basis %s, want predates_observation", e.Service, e.GrantAgeBasis)
		}
	}
	fs := l.findingsAt(rev)
	unused, ok := fs["unused_service/AROAREFUND0001/sqs"]
	if !ok || unused.ResultRev == nil || *unused.ResultRev != rev || unused.Status != igagov.StatusOpen ||
		unused.Confidence != igagov.ConfidenceAgeUnverified || unused.EvidenceScanRun == nil || *unused.EvidenceScanRun != run.ID {
		t.Fatalf("unused_service(sqs) = %+v (ok %v), want open, age_unverified, result at rev %d citing run %s", unused, ok, rev, run.ID)
	}
	if _, ok := fs["unused_service/AROAREFUND0001/s3"]; ok {
		t.Fatal("s3 was attempted 3 days ago and must not be unused")
	}
	if f, ok := fs["missing_owner/AROAREFUND0001/"]; !ok || f.ResultRev == nil {
		t.Fatalf("missing_owner = %+v (ok %v), want a result at rev %d", f, ok, rev)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_job WHERE workspace_id = ? AND kind = 'evaluate_owner_rules' AND rev = ?`, l.ws, rev); n != 1 {
		t.Fatalf("evaluate_owner_rules(%d) jobs = %d, want 1", rev, n)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ? AND event = 'evaluation_completed'`, l.ws); n != 1 {
		t.Fatalf("evaluation_completed events = %d, want 1", n)
	}
}

// Gate off: the projection job publishes exactly as before, inserts no
// evaluation row and evaluates nothing.
func TestP3T306GateOffSkipsEvaluation(t *testing.T) {
	l := newP3eLab(t, "p3-t306-gate-off")
	l.policy = services.NewPolicyGate(false, "", func() *services.GraphProjectionGate { return l.gate })
	a := l.account(accountA)
	arn := p3eOldRole(a, "RefundTaskRole", "AROAREFUND0002", 200*24*time.Hour, "RefundWork", p3eSQSS3)
	a.lambda("us-east-1", "refund-agent", arn)
	l.activity(a).set(arn, map[string]*time.Time{"sqs": nil})
	_, rev := l.cycle(a, nil)
	if rev != 1 {
		t.Fatalf("rev %d, want the publication to happen as before", rev)
	}
	for _, table := range []string{"iga_gov_evaluation", "iga_gov_activity_evidence", "iga_gov_finding", "iga_gov_finding_result", "iga_gov_job", "iga_gov_event"} {
		if n := l.count(`SELECT count(*) FROM `+table+` WHERE workspace_id = ?`, l.ws); n != 0 {
			t.Fatalf("gate off: %d rows in %s, want none", n, table)
		}
	}
}

// keep the imports honest while scenarios are added
var _ = errors.New
var _ = strings.Contains
var _ *gorm.DB
