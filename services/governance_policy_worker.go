package services

import (
	"log"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

/*
The two loops that make agent policy act on its own.

WHAT WAS MISSING, AND WHY IT MATTERED
Phases 1-2 built the policy model and made the entitlement arm executable, but
nothing ran it: AgentPolicyManager.Reconcile was reachable only from
POST /governance/agent-policies/reconcile. So "always do what the policy says,
including deleting at a set expiration" was true only while somebody was clicking a
button. A policy with an expiry three weeks out would simply sit there.

That is the gap PolicyReconcileWorker closes. PolicyWarningWorker is its
counterpart: nothing destructive should fire unannounced, and a warning that is
never scheduled is the same as no warning at all.

ORDER MATTERS BETWEEN THEM. Warnings are scheduled on a LEAD (7 days by default)
and reconciliation acts at the DEADLINE, so the warning worker must have run at
least once inside the lead window before the reconcile worker acts. Both run on
timers rather than in sequence, and the lead is measured in days while the intervals
are measured in minutes, so in practice the warning is always long since scheduled.
The case where it is not -- a policy created with an expiry already inside its own
lead window -- is handled honestly rather than prevented: the action executes and is
recorded as a governance exception, because delaying enforcement to wait for an
email would be the silent-non-execution failure §3A.4 rejects.
*/

// PolicyWarningWorker schedules and delivers pre-deadline warnings.
type PolicyWarningWorker struct {
	db       *gorm.DB
	warnings PolicyWarningManager
	interval time.Duration
	batch    int
}

// NewPolicyWarningWorker constructs the worker.
func NewPolicyWarningWorker(db *gorm.DB, interval time.Duration, batch int) *PolicyWarningWorker {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	if batch <= 0 || batch > 500 {
		batch = 50
	}
	return &PolicyWarningWorker{
		db: db, warnings: NewPolicyWarningManager(db),
		interval: interval, batch: batch,
	}
}

// WarningSweepResult reports one pass.
type WarningSweepResult struct {
	WorkspacesScanned int
	Scheduled         int
	Attempted         int
	Sent              int
	Failed            int
	Dead              int
	Errors            int
}

// Start launches the sweep loop.
func (w *PolicyWarningWorker) Start() {
	go func() {
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()
		for range ticker.C {
			res := w.RunOnce()
			if res.Scheduled > 0 || res.Sent > 0 || res.Failed > 0 || res.Errors > 0 {
				log.Printf("policy warning sweep: scheduled=%d attempted=%d sent=%d "+
					"failed=%d dead=%d errors=%d",
					res.Scheduled, res.Attempted, res.Sent, res.Failed, res.Dead, res.Errors)
			}
			if res.Dead > 0 {
				// Loud on its own line. A dead warning does NOT stop the deadline it
				// was warning about, so this is the last chance anyone has to notice
				// before a workload disappears unannounced.
				log.Printf("policy warning sweep: %d warning(s) EXHAUSTED their retries. "+
					"The scheduled actions still execute, and will be recorded as "+
					"governance exceptions (warning_delivered = false).", res.Dead)
			}
		}
	}()
}

// RunOnce performs one schedule-then-deliver pass. Exported so an operator can
// trigger one and so tests do not wait on a ticker.
func (w *PolicyWarningWorker) RunOnce() WarningSweepResult {
	var res WarningSweepResult

	for _, ws := range activePolicyWorkspaces(w.db) {
		res.WorkspacesScanned++
		n, err := w.warnings.Schedule(ws)
		if err != nil {
			log.Printf("policy warning sweep: workspace %s: schedule: %v", ws, err)
			res.Errors++
			continue
		}
		res.Scheduled += n
	}

	// Delivery is workspace-agnostic: the queue is claimed globally so one busy
	// tenant cannot starve another behind a per-workspace loop.
	out, err := w.warnings.Deliver(w.batch)
	if err != nil {
		log.Printf("policy warning sweep: deliver: %v", err)
		res.Errors++
	}
	if out != nil {
		res.Attempted, res.Sent, res.Failed, res.Dead = out.Attempted, out.Sent, out.Failed, out.Dead
		res.Errors += len(out.Errors)
	}
	return res
}

// PolicyReconcileWorker runs agent-policy reconciliation on a timer.
//
// WITHOUT THIS, POLICY IS ADVISORY. Everything the reconciler does -- narrowing a
// role, lapsing a grant at expiry, planning a containment -- happened only when a
// human POSTed to the reconcile endpoint. A policy is a standing instruction, and a
// standing instruction that needs somebody to press a button is a reminder.
//
// FAILURE POSTURE. The reconciler only ever narrows or removes (PG-5), and each
// agent is handled independently, so one bad row cannot block the sweep. Cluster
// actions are still PLANNED rather than applied at this phase; that arrives with
// eviction.
type PolicyReconcileWorker struct {
	db       *gorm.DB
	policies AgentPolicyManager
	interval time.Duration
}

// NewPolicyReconcileWorker constructs the worker.
func NewPolicyReconcileWorker(db *gorm.DB, interval time.Duration) *PolicyReconcileWorker {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &PolicyReconcileWorker{
		db: db, policies: NewAgentPolicyManager(db), interval: interval,
	}
}

// PolicyReconcileSweepResult reports one pass.
type PolicyReconcileSweepResult struct {
	WorkspacesScanned int
	AgentsCovered     int
	BindingsNarrowed  int
	GrantsLapsed      int64
	Refused           int
	Errors            int
}

// Start launches the reconcile loop.
func (w *PolicyReconcileWorker) Start() {
	go func() {
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()
		for range ticker.C {
			res := w.RunOnce()
			if res.BindingsNarrowed > 0 || res.GrantsLapsed > 0 || res.Refused > 0 || res.Errors > 0 {
				log.Printf("agent policy reconcile: workspaces=%d agents=%d narrowed=%d "+
					"lapsed=%d refused=%d errors=%d",
					res.WorkspacesScanned, res.AgentsCovered, res.BindingsNarrowed,
					res.GrantsLapsed, res.Refused, res.Errors)
			}
		}
	}()
}

// RunOnce reconciles every workspace with an enabled policy.
func (w *PolicyReconcileWorker) RunOnce() PolicyReconcileSweepResult {
	var res PolicyReconcileSweepResult

	for _, ws := range activePolicyWorkspaces(w.db) {
		res.WorkspacesScanned++
		// dryRun=false. This is the whole point of the worker: a dry run on a timer
		// would produce a stream of plans nobody reads and change nothing.
		out, err := w.policies.Reconcile(ws, false)
		if err != nil {
			log.Printf("agent policy reconcile: workspace %s: %v", ws, err)
			res.Errors++
			continue
		}
		res.AgentsCovered += out.AgentsCovered
		res.BindingsNarrowed += out.BindingsNarrowed
		res.GrantsLapsed += out.GrantsLapsed
		res.Refused += out.Refused
		res.Errors += len(out.Errors)
		for _, e := range out.Errors {
			log.Printf("agent policy reconcile: workspace %s: %s", ws, e)
		}
	}
	return res
}

// activePolicyWorkspaces lists workspaces with at least one enabled policy.
//
// Driven off the policy table rather than the workspace table: a deployment with
// thousands of workspaces and three policies should do three workspaces of work,
// not thousands of empty reconciles.
func activePolicyWorkspaces(db *gorm.DB) []uuid.UUID {
	var out []uuid.UUID
	if err := db.Model(&models.AgentPolicy{}).
		Where("enabled").Distinct().Pluck("workspace_id", &out).Error; err != nil {
		log.Printf("agent policy worker: could not list workspaces: %v", err)
		return nil
	}
	return out
}
