package services

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// The verify_binding job (SPEC-iga-phase3-policy.md §3.6 "the self-test runs
// at creation, every 24 hours, and before each deployment batch"; §8.1;
// review fix R1a P2 "unscheduled verify_binding").
//
//   - At creation: the callback and the manual bind run it (T3.09).
//   - Before each deployment batch: NewEnforcementBindingDeployGate calls
//     EnsureFresh before every direct deployment starts (a cached result
//     younger than an hour is reused) -- already in place, nothing added.
//   - Every 24 hours: THIS schedule. Every bound binding (role_arn set,
//     state verified / partial / error) whose last self-test (updated_at,
//     which recordReport bumps) is older than 24 hours gets one
//     verify_binding job (dedupe binding:<id>, periodic 24 h), whose handler
//     calls EnforcementBindingService.VerifyBinding. A revoked or unbound
//     binding completes the job without probing; a self-test already running
//     hands the job back for later.
//
// This file is outside the iga_* files because it names
// cloud_enforcement_binding (scripts/ci-iga-isolation-check.sh), as
// cloud_enforcement_deploy_gate.go is.

// BindingSelfTestEvery is §3.6's periodic self-test interval.
const BindingSelfTestEvery = 24 * time.Hour

// EnforcementSelfTester is what the verify_binding job needs (T3.09's
// EnforcementBindingService implements it).
type EnforcementSelfTester interface {
	VerifyBinding(ctx context.Context, ws, bindingID uuid.UUID, actor EnforcementActor) (*models.CloudEnforcementBinding, error)
}

var (
	selfTesterMu sync.RWMutex
	selfTester   EnforcementSelfTester
)

// SetEnforcementSelfTester installs the process-wide self-tester
// (NewProductionGovDeployEnv, when Vault is configured); it returns a
// function restoring the previous one.
func SetEnforcementSelfTester(t EnforcementSelfTester) (restore func()) {
	selfTesterMu.Lock()
	prev := selfTester
	selfTester = t
	selfTesterMu.Unlock()
	return func() {
		selfTesterMu.Lock()
		selfTester = prev
		selfTesterMu.Unlock()
	}
}

func currentSelfTester() EnforcementSelfTester {
	selfTesterMu.RLock()
	defer selfTesterMu.RUnlock()
	return selfTester
}

// VerifyBindingSchedule is the verify_binding schedule.
func VerifyBindingSchedule() PolicyJobSchedule {
	return PolicyJobSchedule{Kind: repositories.GovJobVerifyBinding, Every: BindingSelfTestEvery, Due: dueBindingSelfTests}
}

func dueBindingSelfTests(ctx context.Context, db *gorm.DB, now time.Time) ([]ScheduledPolicyJob, error) {
	var rows []struct {
		WorkspaceID uuid.UUID
		ID          uuid.UUID
	}
	if err := db.Raw(`SELECT workspace_id, id FROM cloud_enforcement_binding
		WHERE role_arn <> '' AND state IN ('verified','partial','error') AND updated_at < ?
		ORDER BY workspace_id, id`, now.Add(-BindingSelfTestEvery)).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]ScheduledPolicyJob, 0, len(rows))
	for _, r := range rows {
		id := r.ID
		out = append(out, ScheduledPolicyJob{WorkspaceID: r.WorkspaceID, SubjectID: &id, DedupeKey: "binding:" + id.String()})
	}
	return out, nil
}

// VerifyBindingHandler runs the self-test of the job's binding.
func VerifyBindingHandler(ctx context.Context, run *PolicyJobRun) error {
	if run.Job.SubjectID == nil {
		return PolicyJobAbandon("verify_binding job without a binding")
	}
	t := currentSelfTester()
	if t == nil {
		// No Vault in this process: the self-test cannot read the ExternalId.
		return PolicyJobRetryLater(time.Hour, "the enforcement self-test is not configured in this process (Vault)")
	}
	_, err := t.VerifyBinding(ctx, run.Job.WorkspaceID, *run.Job.SubjectID, EnforcementActor{Kind: "system", ID: "verify_binding"})
	var ee *EnforcementError
	if errors.As(err, &ee) {
		switch ee.Code {
		case EnfCodeNotFound, EnfCodeNotBound:
			log.Printf("[aws-enf] verify_binding %s: %s; nothing to test", *run.Job.SubjectID, ee.Code)
			return nil
		case EnfCodeSelfTestInProgress:
			return PolicyJobRetryLater(5*time.Minute, "a self-test is already running")
		}
	}
	return err
}

// RegisterEnforcementBindingJobs registers verify_binding and its schedule
// (NewDefaultPolicyJobWorker).
func RegisterEnforcementBindingJobs(w *PolicyJobWorker) {
	w.Register(PolicyJobKind{Kind: repositories.GovJobVerifyBinding, Handler: VerifyBindingHandler,
		Backoff: func(n int) time.Duration { return time.Duration(n) * 10 * time.Minute }})
	w.Scheduler().Add(VerifyBindingSchedule())
}
