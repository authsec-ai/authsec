package services

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	repositories "github.com/authsec-ai/authsec/repository"
)

// The IGA_POLICY_R3 gate: Phase 3 R3, agent runtime controls
// (SPEC-iga-phase3-policy.md §12.4). There is no R3 implementation spec; the
// decisions are DECISION R3-n comments (internal/igagov/r3.go lists them).
//
//	IGA_POLICY_R3   IGA_POLICY gate    062 schema     state           R3
//	off/unset       any                any            off             nothing runs; every R1a / R1b / R2 path as before
//	on              not available      any            misconfigured   nothing runs (runtime routes 503, fail closed)
//	on              available          not verified   misconfigured   nothing runs (runtime routes 503, fail closed)
//	on              available          verified       on              runtime policies, decide / redeem / outcome,
//	                                                                  holds, budgets, routing proofs, AgentCore
//	                                                                  push and coverage, brokered sessions
//	other value     any                any            misconfigured   nothing runs
//
// FAIL CLOSED, like IGA_POLICY, IGA_POLICY_R1B and IGA_POLICY_R2: anything
// wrong leaves R3 off with a reason (/capabilities policy.runtime_controls
// and policy.brokered_sessions). R3 never takes the R1a gate down: R1a's
// schema check (VerifyPolicySchema, head 059) reads nothing of 062, and this
// gate's own check (VerifyPolicyR3Schema) is separate. R3 needs neither R1b
// nor R2.

// PolicyR3Env is the switch.
const PolicyR3Env = "IGA_POLICY_R3"

// PolicyR3SchemaHead is the migration R3 needs.
const PolicyR3SchemaHead = "062"

// PolicyR3Gate carries the switch and whether 062 has been verified.
type PolicyR3Gate struct {
	enabled  bool
	badValue string

	mu       sync.RWMutex
	verified bool
	reason   string
}

// NewPolicyR3Gate builds a gate; badValue makes it misconfigured forever.
func NewPolicyR3Gate(enabled bool, badValue string) *PolicyR3Gate {
	g := &PolicyR3Gate{enabled: enabled || badValue != "", badValue: badValue}
	if g.enabled && badValue == "" {
		g.reason = "the R3 schema (" + PolicyR3SchemaHead + ") has not been verified yet"
	}
	return g
}

// PolicyR3GateFromEnv reads IGA_POLICY_R3 once: unset, off, false, 0 are
// off; on, true, 1 are on; anything else is misconfigured.
func PolicyR3GateFromEnv() *PolicyR3Gate {
	switch v := strings.ToLower(strings.TrimSpace(os.Getenv(PolicyR3Env))); v {
	case "", "off", "false", "0":
		return NewPolicyR3Gate(false, "")
	case "on", "true", "1":
		return NewPolicyR3Gate(true, "")
	default:
		return NewPolicyR3Gate(true, fmt.Sprintf("%s=%q is not on or off", PolicyR3Env, v))
	}
}

// Enabled reports whether the switch is on (verified or not).
func (g *PolicyR3Gate) Enabled() bool { return g != nil && g.enabled }

// Status is the gate's state and the reason when it is not on. The IGA_POLICY
// gate is read live: R3 is on only while R1a is.
func (g *PolicyR3Gate) Status() (state, reason string) {
	if g == nil || !g.enabled {
		return PolicyOff, PolicyR3Env + " is off"
	}
	if g.badValue != "" {
		return PolicyMisconfigured, g.badValue
	}
	if ps, pr, _ := PolicyGateState().Status(); ps != PolicyOn {
		r := fmt.Sprintf("%s=on requires %s=on and available; the policy gate is %s", PolicyR3Env, PolicyEnv, ps)
		if pr != "" {
			r += ": " + pr
		}
		return PolicyMisconfigured, r
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if !g.verified {
		return PolicyMisconfigured, g.reason
	}
	return PolicyOn, ""
}

// Available reports whether R3 may run now.
func (g *PolicyR3Gate) Available() bool {
	state, _ := g.Status()
	return state == PolicyOn
}

// Verify runs VerifyPolicyR3Schema and records the outcome (a success is
// final; a failure is retried by VerifyUntilReady).
func (g *PolicyR3Gate) Verify(db *gorm.DB) error {
	if g == nil || !g.enabled {
		return nil
	}
	if g.badValue != "" {
		return fmt.Errorf("%s", g.badValue)
	}
	err := VerifyPolicyR3Schema(db)
	g.mu.Lock()
	defer g.mu.Unlock()
	if err != nil {
		g.reason = err.Error()
		return err
	}
	g.verified, g.reason = true, ""
	return nil
}

// VerifyUntilReady retries Verify until it succeeds or ctx ends; ready runs
// once after the first success (the R3 sweeper).
func (g *PolicyR3Gate) VerifyUntilReady(ctx context.Context, db *gorm.DB, interval time.Duration, ready func()) {
	if !g.Enabled() {
		return
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	for {
		err := g.Verify(db)
		if err == nil {
			log.Printf("[policy] %s=on: R3 schema verified at %s; agent runtime controls run while %s is available",
				PolicyR3Env, PolicyR3SchemaHead, PolicyEnv)
			if ready != nil {
				ready()
			}
			return
		}
		log.Printf("[policy] %s=on but not ready, R3 stays off (runtime routes fail closed): %v", PolicyR3Env, err)
		if g.badValue != "" {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// policyR3Relations are the relations 062 creates.
var policyR3Relations = []string{
	"iga_gov_runtime_version", "iga_gov_runtime_settings", "iga_gov_runtime_decision", "iga_gov_runtime_hold",
	"iga_gov_runtime_budget", "iga_gov_runtime_budget_entry", "iga_gov_runtime_routing_proof",
	"iga_gov_runtime_agentcore_push", "iga_gov_runtime_broker_role", "iga_gov_runtime_broker_session",
	"uq_iga_gov_runtime_version_one_approved", "uq_iga_gov_runtime_version_one_review",
	"uq_iga_gov_runtime_decision_idem", "uq_iga_gov_runtime_decision_resume", "uq_iga_gov_runtime_hold_decision",
	"uq_iga_gov_runtime_broker_role_live",
}

// policyR3Constraints are 062's named constraints (validated).
var policyR3Constraints = []string{
	"iga_gov_runtime_version.iga_gov_rtv_sod_chk", "iga_gov_runtime_version.iga_gov_rtv_decided_chk",
	"iga_gov_runtime_decision.iga_gov_rtd_allow_chk", "iga_gov_runtime_decision.iga_gov_rtd_consume_chk",
	"iga_gov_runtime_decision.iga_gov_rtd_outcome_chk", "iga_gov_runtime_decision.iga_gov_rtd_policy_chk",
	"iga_gov_runtime_hold.iga_gov_rth_sod_chk", "iga_gov_runtime_hold.iga_gov_rth_decided_chk",
	"iga_gov_runtime_hold.iga_gov_rth_resumed_chk", "iga_gov_runtime_budget_entry.iga_gov_rtbe_state_chk",
	"iga_gov_runtime_routing_proof.iga_gov_rtrp_window_chk", "iga_gov_runtime_broker_role.iga_gov_rtbr_disabled_chk",
}

// VerifyPolicyR3Schema reports what R3 needs that the database lacks: 062's
// tables, unique indexes, named constraints and its two triggers. A database
// error is returned for retry.
func VerifyPolicyR3Schema(db *gorm.DB) error {
	var missing []string
	for _, rel := range policyR3Relations {
		ok, err := repositories.HasRelation(db, rel)
		if err != nil {
			return fmt.Errorf("R3 schema verification could not run: %w", err)
		}
		if !ok {
			missing = append(missing, rel)
		}
	}
	have, err := repositories.ValidatedConstraints(db, policyR3Constraints)
	if err != nil {
		return fmt.Errorf("R3 schema verification could not run: %w", err)
	}
	missing = append(missing, absentNames(policyR3Constraints, have, "constraint ")...)
	for _, tg := range []struct{ table, name string }{
		{"iga_gov_runtime_decision", "iga_gov_runtime_decision_guard"},
		{"iga_gov_runtime_version", "iga_gov_runtime_version_immutable"},
	} {
		var n int64
		// TENANT-EXEMPT: Postgres catalog (pg_trigger), a schema precondition check.
		if err := db.Raw(`SELECT count(*) FROM pg_trigger WHERE tgrelid = to_regclass('public.`+tg.table+`') AND tgname = ? AND NOT tgisinternal`,
			tg.name).Scan(&n).Error; err != nil {
			return fmt.Errorf("R3 schema verification could not run: %w", err)
		}
		if n != 1 {
			missing = append(missing, "trigger "+tg.table+"."+tg.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s=on needs migration %s; missing: %s", PolicyR3Env, PolicyR3SchemaHead, strings.Join(missing, ", "))
	}
	return nil
}

// The process-wide gate (default off). main installs it once.
var (
	policyR3GateMu sync.RWMutex
	policyR3Gate   = NewPolicyR3Gate(false, "")
)

// PolicyR3GateState returns the process-wide R3 gate.
func PolicyR3GateState() *PolicyR3Gate {
	policyR3GateMu.RLock()
	defer policyR3GateMu.RUnlock()
	return policyR3Gate
}

// SetPolicyR3Gate installs the process-wide R3 gate (main; tests).
func SetPolicyR3Gate(g *PolicyR3Gate) {
	policyR3GateMu.Lock()
	defer policyR3GateMu.Unlock()
	policyR3Gate = g
}

// PolicyR3On reports whether R3 runs now (the gate is on).
func PolicyR3On() bool { return PolicyR3GateState().Available() }

// R3 refusal codes.
const (
	// GovCodeR3Unavailable is the 422 a management route answers while R3
	// is off.
	GovCodeR3Unavailable = "policy_r3_unavailable"
	// GovCodeRuntimeUnavailable is the 503 a runtime (agent) route answers
	// while R3 is off: an outage, which a PEP must treat as deny (R-05).
	GovCodeRuntimeUnavailable = "runtime_unavailable"
)

// RequirePolicyR3 is nil while R3 is on, else the 422 refusal.
func RequirePolicyR3() error {
	if PolicyR3On() {
		return nil
	}
	_, reason := PolicyR3GateState().Status()
	return govUnprocessable(GovCodeR3Unavailable,
		"Agent runtime controls (R3) are not available on this server.", map[string]any{"reason": reason})
}

// RequireRuntimeR3 is nil while R3 is on, else the fail-closed 503 the
// runtime routes answer (DECISION R3-7).
func RequireRuntimeR3() error {
	if PolicyR3On() {
		return nil
	}
	_, reason := PolicyR3GateState().Status()
	return govErr(http.StatusServiceUnavailable, GovCodeRuntimeUnavailable,
		"AuthSec runtime decisions are unavailable; treat every operation as denied.",
		map[string]any{"reason": reason, "fail_closed": true})
}
