package services

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
)

// IGA_LEGACY_AGENT_POLICY: the containment switch for the legacy Kubernetes
// agent-policy stack (PLAN-existing-policy-code-disposition.md §3.2,
// SPEC-iga-phase3-policy.md §4.3).
//
// It decides ONE thing: whether this process starts the two legacy policy
// workers, PolicyReconcileWorker and PolicyWarningWorker. Nothing else reads it
// except the legacy compatibility routes, which use it to decide whether they
// exist for a workspace with no legacy policies. In particular it does NOT
// stop ExpiryWorker or LeaseReaper -- both serve the AuthSec runtime generally,
// not the policy stack -- and it does not disable the legacy routes, including
// the manual POST /authsec/governance/agent-policies/reconcile and
// /policy-warnings/run.
//
// Default on, so a deployment that never sets it behaves exactly as before.
// Turning it off is a recorded per-environment release decision; turning it
// back on restores the previous behaviour.

// LegacyAgentPolicyEnv is the environment variable.
const LegacyAgentPolicyEnv = "IGA_LEGACY_AGENT_POLICY"

// LegacyAgentPolicyGate is the switch as read at startup.
type LegacyAgentPolicyGate struct {
	// On: the legacy workers run.
	On bool
	// Raw is the value as set (trimmed), "" when unset.
	Raw string
	// Unknown: Raw was neither on nor off, and was treated as on. Failing
	// toward the previous behaviour is the safe direction for a typo: the
	// workers stopping silently would be a change nobody decided.
	Unknown bool
}

// ParseLegacyAgentPolicyGate reads one value: "" or "on" is on, "off" is off,
// case-insensitive; anything else is on and Unknown.
func ParseLegacyAgentPolicyGate(raw string) LegacyAgentPolicyGate {
	v := strings.TrimSpace(raw)
	switch strings.ToLower(v) {
	case "", "on":
		return LegacyAgentPolicyGate{On: true, Raw: v}
	case "off":
		return LegacyAgentPolicyGate{On: false, Raw: v}
	default:
		return LegacyAgentPolicyGate{On: true, Raw: v, Unknown: true}
	}
}

// LegacyAgentPolicyGateFromEnv reads IGA_LEGACY_AGENT_POLICY.
func LegacyAgentPolicyGateFromEnv() LegacyAgentPolicyGate {
	return ParseLegacyAgentPolicyGate(os.Getenv(LegacyAgentPolicyEnv))
}

// State is "on" or "off".
func (g LegacyAgentPolicyGate) State() string {
	if g.On {
		return "on"
	}
	return "off"
}

// Warning is the startup warning for an unrecognised value, "" when none.
func (g LegacyAgentPolicyGate) Warning() string {
	if !g.Unknown {
		return ""
	}
	return fmt.Sprintf("%s=%q is not on or off; treating it as on (the legacy agent-policy "+
		"workers keep running). Set it to on or off.", LegacyAgentPolicyEnv, g.Raw)
}

// Decision is the startup log line: what the gate is and what it does.
func (g LegacyAgentPolicyGate) Decision() string {
	if g.On {
		return fmt.Sprintf("[legacy-agent-policy] %s=on: starting PolicyReconcileWorker and "+
			"PolicyWarningWorker (interval=5m)", LegacyAgentPolicyEnv)
	}
	return fmt.Sprintf("[legacy-agent-policy] %s=off: PolicyReconcileWorker and "+
		"PolicyWarningWorker NOT started; legacy policies are not reconciled and no "+
		"pre-deadline warnings are sent by this process (ExpiryWorker and LeaseReaper "+
		"are unaffected)", LegacyAgentPolicyEnv)
}

var (
	legacyGateMu  sync.RWMutex
	legacyGateSet bool
	legacyGate    LegacyAgentPolicyGate
)

// SetLegacyAgentPolicyGate installs the process-wide gate. Called once by main.
func SetLegacyAgentPolicyGate(g LegacyAgentPolicyGate) {
	legacyGateMu.Lock()
	defer legacyGateMu.Unlock()
	legacyGate, legacyGateSet = g, true
}

// LegacyAgentPolicy returns the process-wide gate; before main installs one it
// is read from the environment, so a caller never sees a zero value (which
// would read as off).
func LegacyAgentPolicy() LegacyAgentPolicyGate {
	legacyGateMu.RLock()
	defer legacyGateMu.RUnlock()
	if !legacyGateSet {
		return LegacyAgentPolicyGateFromEnv()
	}
	return legacyGate
}

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

// StartLegacyAgentPolicyWorkers starts both workers when the gate is on and
// neither when it is off, returning the names of those started. The only path
// by which main starts them, so the gate's effect is testable without main.
func StartLegacyAgentPolicyWorkers(g LegacyAgentPolicyGate, w LegacyAgentPolicyWorkers) []string {
	if !g.On {
		return nil
	}
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
