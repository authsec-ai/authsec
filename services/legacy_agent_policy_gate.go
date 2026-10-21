package services

import (
	"time"

	"gorm.io/gorm"
)

// The legacy Kubernetes agent-policy stack's two workers,
// PolicyReconcileWorker and PolicyWarningWorker
// (PLAN-existing-policy-code-disposition.md §3.2). main always starts both.
// ExpiryWorker and LeaseReaper serve the AuthSec runtime generally and are
// started separately.

// LegacyWorker is a worker main starts.
type LegacyWorker interface{ Start() }

// LegacyAgentPolicyWorkers are the two workers the gate controls.
type LegacyAgentPolicyWorkers struct {
	Reconcile LegacyWorker
	Warning   LegacyWorker
}

// NewLegacyAgentPolicyWorkers builds the production workers, at the cadences
// main has always used: reconcile every 5 minutes, warnings every 5 minutes in
// batches of 50.
func NewLegacyAgentPolicyWorkers(db *gorm.DB) LegacyAgentPolicyWorkers {
	return LegacyAgentPolicyWorkers{
		Reconcile: NewPolicyReconcileWorker(db, 5*time.Minute),
		Warning:   NewPolicyWarningWorker(db, 5*time.Minute, 50),
	}
}

// StartLegacyAgentPolicyWorkers starts both workers, returning the names of
// those started.
func StartLegacyAgentPolicyWorkers(w LegacyAgentPolicyWorkers) []string {
	var started []string
	if w.Reconcile != nil {
		w.Reconcile.Start()
		started = append(started, "PolicyReconcileWorker")
	}
	if w.Warning != nil {
		w.Warning.Start()
		started = append(started, "PolicyWarningWorker")
	}
	return started
}
