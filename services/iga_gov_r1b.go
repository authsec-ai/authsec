package services

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	repositories "github.com/authsec-ai/authsec/repository"
)

// The Phase 3 R1b gate: action-level right-sizing (SPEC-iga-phase3-policy.md §12.1). There is no R1b
// implementation spec; the decisions are DECISION R1b-n comments (internal/igagov/actions.go) and
// in the R1b report. R1b is always on; it serves
// once the policy gate is available and its own migration has verified.
//
//	policy gate     R1b schema   state           R1b
//	not available   any         misconfigured   nothing runs
//	available       not verified misconfigured  nothing runs
//	available       verified    on              action evidence, unused_action, remove_actions
//
// FAIL CLOSED: anything missing leaves R1b unavailable with a reason
// (/capabilities policy.actions). R1b never takes the R1a gate down: R1a's schema check
// (VerifyPolicySchema, head 059) reads nothing of R1b's migration, and this
// gate's own check (VerifyPolicyR1BSchema) is separate.

// PolicyR1BSchemaHead is the migration R1b needs.
const PolicyR1BSchemaHead = "060"

// PolicyR1BGate carries whether 060 has been verified.
type PolicyR1BGate struct {
	enabled bool

	mu       sync.RWMutex
	verified bool
	reason   string
}

// NewPolicyR1BGate builds a gate: on (main, through DefaultPolicyR1BGate), or
// off (the process default before main installs one, and tests).
func NewPolicyR1BGate(enabled bool) *PolicyR1BGate {
	g := &PolicyR1BGate{enabled: enabled}
	if g.enabled {
		g.reason = "the R1b schema (" + PolicyR1BSchemaHead + ") has not been verified yet"
	}
	return g
}

// DefaultPolicyR1BGate is the gate main installs: on, serving once its schema
// verifies and the policy gate is available.
func DefaultPolicyR1BGate() *PolicyR1BGate {
	return NewPolicyR1BGate(true)
}

// Enabled reports whether the gate is on (verified or not).
func (g *PolicyR1BGate) Enabled() bool { return g != nil && g.enabled }

// Status is the gate's state and the reason when it is not on. The policy
// gate is read live: R1b is on only while R1a is.
func (g *PolicyR1BGate) Status() (state, reason string) {
	if g == nil || !g.enabled {
		return PolicyOff, "R1b is off"
	}
	if ps, pr, _ := PolicyGateState().Status(); ps != PolicyOn {
		r := fmt.Sprintf("R1b needs the policy gate available; it is %s", ps)
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
			log.Printf("[policy] R1b schema verified at %s; action-level right-sizing runs while policy is available", PolicyR1BSchemaHead)
			return
		}
		log.Printf("[policy] R1b not ready, R1b stays off: %v", err)
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
		return fmt.Errorf("R1b needs migration %s; missing: %s", PolicyR1BSchemaHead, strings.Join(missing, ", "))
	}
	return nil
}

// The process-wide gate (default off). main installs it once.
var (
	policyR1BGateMu sync.RWMutex
	policyR1BGate   = NewPolicyR1BGate(false)
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
