package services

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	repositories "github.com/authsec-ai/authsec/repository"
)

// The IGA_POLICY_R1B gate: Phase 3 R1b, action-level right-sizing
// (SPEC-iga-phase3-policy.md §12.1). There is no R1b implementation spec;
// the decisions are DECISION R1b-n comments (internal/igagov/actions.go) and
// in the R1b report.
//
//	IGA_POLICY_R1B   IGA_POLICY gate    060 schema     state           R1b
//	off/unset        any                any            off             nothing runs; every R1a path as before
//	on               not available      any            misconfigured   nothing runs
//	on               available          not verified   misconfigured   nothing runs
//	on               available          verified       on              action evidence, unused_action, remove_actions
//	other value      any                any            misconfigured   nothing runs
//
// FAIL CLOSED, like IGA_POLICY: anything wrong leaves R1b off with a reason
// (/capabilities policy.actions). R1b never takes the R1a gate down: R1a's
// schema check (VerifyPolicySchema, head 059) reads nothing of 060, and this
// gate's own check (VerifyPolicyR1BSchema) is separate.

// PolicyR1BEnv is the switch.
const PolicyR1BEnv = "IGA_POLICY_R1B"

// PolicyR1BSchemaHead is the migration R1b needs.
const PolicyR1BSchemaHead = "060"

// PolicyR1BGate carries the switch and whether 060 has been verified.
type PolicyR1BGate struct {
	enabled  bool
	badValue string

	mu       sync.RWMutex
	verified bool
	reason   string
}

// NewPolicyR1BGate builds a gate; badValue makes it misconfigured forever.
func NewPolicyR1BGate(enabled bool, badValue string) *PolicyR1BGate {
	g := &PolicyR1BGate{enabled: enabled || badValue != "", badValue: badValue}
	if g.enabled && badValue == "" {
		g.reason = "the R1b schema (" + PolicyR1BSchemaHead + ") has not been verified yet"
	}
	return g
}

// PolicyR1BGateFromEnv reads IGA_POLICY_R1B once: unset, off, false, 0 are
// off; on, true, 1 are on; anything else is misconfigured.
func PolicyR1BGateFromEnv() *PolicyR1BGate {
	switch v := strings.ToLower(strings.TrimSpace(os.Getenv(PolicyR1BEnv))); v {
	case "", "off", "false", "0":
		return NewPolicyR1BGate(false, "")
	case "on", "true", "1":
		return NewPolicyR1BGate(true, "")
	default:
		return NewPolicyR1BGate(true, fmt.Sprintf("%s=%q is not on or off", PolicyR1BEnv, v))
	}
}

// Enabled reports whether the switch is on (verified or not).
func (g *PolicyR1BGate) Enabled() bool { return g != nil && g.enabled }

// Status is the gate's state and the reason when it is not on. The IGA_POLICY
// gate is read live: R1b is on only while R1a is.
func (g *PolicyR1BGate) Status() (state, reason string) {
	if g == nil || !g.enabled {
		return PolicyOff, PolicyR1BEnv + " is off"
	}
	if g.badValue != "" {
		return PolicyMisconfigured, g.badValue
	}
	if ps, pr, _ := PolicyGateState().Status(); ps != PolicyOn {
		r := fmt.Sprintf("%s=on requires %s=on and available; the policy gate is %s", PolicyR1BEnv, PolicyEnv, ps)
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

// Available reports whether R1b may run now.
func (g *PolicyR1BGate) Available() bool {
	state, _ := g.Status()
	return state == PolicyOn
}

// Verify runs VerifyPolicyR1BSchema and records the outcome (a success is
// final; a failure is retried by VerifyUntilReady).
func (g *PolicyR1BGate) Verify(db *gorm.DB) error {
	if g == nil || !g.enabled {
		return nil
	}
	if g.badValue != "" {
		return fmt.Errorf("%s", g.badValue)
	}
	err := VerifyPolicyR1BSchema(db)
	g.mu.Lock()
	defer g.mu.Unlock()
	if err != nil {
		g.reason = err.Error()
		return err
	}
	g.verified, g.reason = true, ""
	return nil
}

// VerifyUntilReady retries Verify until it succeeds or ctx ends.
func (g *PolicyR1BGate) VerifyUntilReady(ctx context.Context, db *gorm.DB, interval time.Duration) {
	if !g.Enabled() {
		return
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	for {
		err := g.Verify(db)
		if err == nil {
			log.Printf("[policy] %s=on: R1b schema verified at %s; action-level right-sizing runs while %s is available",
				PolicyR1BEnv, PolicyR1BSchemaHead, PolicyEnv)
			return
		}
		log.Printf("[policy] %s=on but not ready, R1b stays off: %v", PolicyR1BEnv, err)
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

// VerifyPolicyR1BSchema reports what R1b needs that the database lacks: the
// iga_gov_action_evidence table and its freeze trigger, and the 060 kind
// CHECK admitting unused_action. A database error is returned for retry.
func VerifyPolicyR1BSchema(db *gorm.DB) error {
	var missing []string
	ok, err := repositories.HasRelation(db, "iga_gov_action_evidence")
	if err != nil {
		return fmt.Errorf("R1b schema verification could not run: %w", err)
	}
	if !ok {
		missing = append(missing, "iga_gov_action_evidence")
	}
	trig, err := repositories.EnabledTriggers(db, []string{"iga_gov_action_evidence.iga_gov_action_evidence_frozen"})
	if err != nil {
		return fmt.Errorf("R1b schema verification could not run: %w", err)
	}
	if len(trig) != 1 {
		missing = append(missing, "trigger iga_gov_action_evidence.iga_gov_action_evidence_frozen")
	}
	var n int64
	// TENANT-EXEMPT: Postgres catalog (pg_constraint), a schema precondition check.
	if err := db.Raw(`SELECT count(*) FROM pg_constraint
	                   WHERE conrelid = to_regclass('public.iga_gov_finding') AND conname = 'iga_gov_finding_kind_check'
	                     AND convalidated AND pg_get_constraintdef(oid) LIKE '%unused_action%'`).Scan(&n).Error; err != nil {
		return fmt.Errorf("R1b schema verification could not run: %w", err)
	}
	if n != 1 {
		missing = append(missing, "constraint iga_gov_finding.iga_gov_finding_kind_check admitting unused_action")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s=on needs migration %s; missing: %s", PolicyR1BEnv, PolicyR1BSchemaHead, strings.Join(missing, ", "))
	}
	return nil
}

// The process-wide gate (default off). main installs it once.
var (
	policyR1BGateMu sync.RWMutex
	policyR1BGate   = NewPolicyR1BGate(false, "")
)

// PolicyR1BGateState returns the process-wide R1b gate.
func PolicyR1BGateState() *PolicyR1BGate {
	policyR1BGateMu.RLock()
	defer policyR1BGateMu.RUnlock()
	return policyR1BGate
}

// SetPolicyR1BGate installs the process-wide R1b gate (main; tests).
func SetPolicyR1BGate(g *PolicyR1BGate) {
	policyR1BGateMu.Lock()
	defer policyR1BGateMu.Unlock()
	policyR1BGate = g
}

// PolicyActionsOn reports whether R1b runs now (the gate is on).
func PolicyActionsOn() bool { return PolicyR1BGateState().Available() }

// GovCodeActionsUnavailable is the 422 an R1b request answers while R1b is
// off: a remove_actions intent, or a proposal from unused_action findings.
const GovCodeActionsUnavailable = "policy_actions_unavailable"

// RequirePolicyActions is nil while R1b is on, else the 422 refusal.
func RequirePolicyActions() error {
	if PolicyActionsOn() {
		return nil
	}
	return actionsUnavailable()
}

// actionsUnavailable is that refusal, with the gate's reason.
func actionsUnavailable() *GovError {
	_, reason := PolicyR1BGateState().Status()
	return govUnprocessable(GovCodeActionsUnavailable,
		"Action-level right-sizing (R1b) is not available on this server.", map[string]any{"reason": reason})
}
