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

// The Phase 3 R2 gate: time-bound access and session response (SPEC-iga-phase3-policy.md §12.3). There is no R2
// implementation spec; the decisions are DECISION R2-n comments (internal/igagov/r2.go lists them) and
// in the R2 report. R2 is always on; it serves
// once the policy gate is available and its own migration has verified.
//
//	policy gate     R2 schema   state           R2
//	not available   any         misconfigured   nothing runs
//	available       not verified misconfigured  nothing runs
//	available       verified    on              time-bound retention, temporary grants,
//	                                     session revocation, direct Lambda splits, access policies
//
// FAIL CLOSED: anything missing leaves R2 unavailable with a reason
// (/capabilities policy.temporary_grants and policy.session_revoke). R2 never takes the R1a gate down: R1a's schema check
// (VerifyPolicySchema, head 059) reads nothing of R2's migration, and this
// gate's own check (VerifyPolicyR2Schema) is separate.

// PolicyR2SchemaHead is the migration R2 needs.
const PolicyR2SchemaHead = "061"

// PolicyR2Gate carries whether 061 has been verified.
type PolicyR2Gate struct {
	enabled  bool
	badValue string

	mu       sync.RWMutex
	verified bool
	reason   string
}

// NewPolicyR2Gate builds a gate; badValue makes it misconfigured forever.
func NewPolicyR2Gate(enabled bool, badValue string) *PolicyR2Gate {
	g := &PolicyR2Gate{enabled: enabled || badValue != "", badValue: badValue}
	if g.enabled && badValue == "" {
		g.reason = "the R2 schema (" + PolicyR2SchemaHead + ") has not been verified yet"
	}
	return g
}

// DefaultPolicyR2Gate is the gate main installs: on, serving once its schema
// verifies and the policy gate is available.
func DefaultPolicyR2Gate() *PolicyR2Gate {
	return NewPolicyR2Gate(true, "")
}

// Enabled reports whether the gate is on (verified or not).
func (g *PolicyR2Gate) Enabled() bool { return g != nil && g.enabled }

// Status is the gate's state and the reason when it is not on. The policy
// gate is read live: R2 is on only while R1a is.
func (g *PolicyR2Gate) Status() (state, reason string) {
	if g == nil || !g.enabled {
		return PolicyOff, "R2 is off"
	}
	if g.badValue != "" {
		return PolicyMisconfigured, g.badValue
	}
	if ps, pr, _ := PolicyGateState().Status(); ps != PolicyOn {
		r := fmt.Sprintf("R2 needs the policy gate available; it is %s", ps)
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

// Available reports whether R2 may run now.
func (g *PolicyR2Gate) Available() bool {
	state, _ := g.Status()
	return state == PolicyOn
}

// Verify runs VerifyPolicyR2Schema and records the outcome (a success is
// final; a failure is retried by VerifyUntilReady).
func (g *PolicyR2Gate) Verify(db *gorm.DB) error {
	if g == nil || !g.enabled {
		return nil
	}
	if g.badValue != "" {
		return fmt.Errorf("%s", g.badValue)
	}
	err := VerifyPolicyR2Schema(db)
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
func (g *PolicyR2Gate) VerifyUntilReady(ctx context.Context, db *gorm.DB, interval time.Duration) {
	if !g.Enabled() {
		return
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	for {
		err := g.Verify(db)
		if err == nil {
			log.Printf("[policy] R2 schema verified at %s; time-bound access and session response run while policy is available", PolicyR2SchemaHead)
			return
		}
		log.Printf("[policy] R2 not ready, R2 stays off: %v", err)
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

// policyR2Relations are the relations 061 creates.
var policyR2Relations = []string{
	"iga_gov_temp_grant", "iga_gov_session_revocation", "uq_iga_gov_temp_grant_live", "uq_iga_gov_session_revocation_live",
}

// policyR2Constraints are 061's named constraints (validated).
var policyR2Constraints = []string{
	"iga_gov_temp_grant.iga_gov_tg_sod_chk", "iga_gov_temp_grant.iga_gov_tg_decided_chk",
	"iga_gov_temp_grant.iga_gov_tg_window_chk", "iga_gov_temp_grant.iga_gov_temp_grant_workspace_id_id_key",
	"iga_gov_session_revocation.iga_gov_sr_sod_chk", "iga_gov_session_revocation.iga_gov_sr_decided_chk",
	"iga_gov_session_revocation.iga_gov_sr_window_chk",
	"iga_gov_session_revocation.iga_gov_session_revocation_workspace_id_id_key",
}

// VerifyPolicyR2Schema reports what R2 needs that the database lacks: 061's
// tables, live indexes and named constraints, the widened job-kind, plan-kind
// and notification-subject CHECKs, and the governance:grant permission. A
// database error is returned for retry.
func VerifyPolicyR2Schema(db *gorm.DB) error {
	var missing []string
	for _, rel := range policyR2Relations {
		ok, err := repositories.HasRelation(db, rel)
		if err != nil {
			return fmt.Errorf("R2 schema verification could not run: %w", err)
		}
		if !ok {
			missing = append(missing, rel)
		}
	}
	have, err := repositories.ValidatedConstraints(db, policyR2Constraints)
	if err != nil {
		return fmt.Errorf("R2 schema verification could not run: %w", err)
	}
	missing = append(missing, absentNames(policyR2Constraints, have, "constraint ")...)
	checks := []struct{ table, name, needle, what string }{
		{"iga_gov_job", "iga_gov_job_kind_check", "temp_grant", "constraint iga_gov_job.iga_gov_job_kind_check admitting the R2 job kinds"},
		{"iga_gov_plan", "iga_gov_plan_kind_chk", "lambda_function", "constraint iga_gov_plan.iga_gov_plan_kind_chk admitting direct Lambda splits"},
		{"iga_gov_notification", "iga_gov_notification_subject_kind_check", "temporary_grant", "constraint iga_gov_notification.iga_gov_notification_subject_kind_check admitting the R2 notices"},
	}
	for _, c := range checks {
		var n int64
		// TENANT-EXEMPT: Postgres catalog (pg_constraint), a schema precondition check.
		if err := db.Raw(`SELECT count(*) FROM pg_constraint
		                   WHERE conrelid = to_regclass('public.`+c.table+`') AND conname = ?
		                     AND convalidated AND pg_get_constraintdef(oid) LIKE ?`, c.name, "%"+c.needle+"%").Scan(&n).Error; err != nil {
			return fmt.Errorf("R2 schema verification could not run: %w", err)
		}
		if n != 1 {
			missing = append(missing, c.what)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("R2 needs migration %s; missing: %s", PolicyR2SchemaHead, strings.Join(missing, ", "))
	}
	return nil
}

// The process-wide gate (default off). main installs it once.
var (
	policyR2GateMu sync.RWMutex
	policyR2Gate   = NewPolicyR2Gate(false, "")
)

// PolicyR2GateState returns the process-wide R2 gate.
func PolicyR2GateState() *PolicyR2Gate {
	policyR2GateMu.RLock()
	defer policyR2GateMu.RUnlock()
	return policyR2Gate
}

// SetPolicyR2Gate installs the process-wide R2 gate (main; tests).
func SetPolicyR2Gate(g *PolicyR2Gate) {
	policyR2GateMu.Lock()
	defer policyR2GateMu.Unlock()
	policyR2Gate = g
}

// PolicyR2On reports whether R2 runs now (the gate is on).
func PolicyR2On() bool { return PolicyR2GateState().Available() }

// GovCodeR2Unavailable is the 422 an R2 request answers while R2 is off.
const GovCodeR2Unavailable = "policy_r2_unavailable"

// RequirePolicyR2 is nil while R2 is on, else the 422 refusal.
func RequirePolicyR2() error {
	if PolicyR2On() {
		return nil
	}
	return r2Unavailable()
}

// r2Unavailable is that refusal, with the gate's reason.
func r2Unavailable() *GovError {
	_, reason := PolicyR2GateState().Status()
	return govUnprocessable(GovCodeR2Unavailable,
		"Time-bound access and session response (R2) are not available on this server.", map[string]any{"reason": reason})
}
