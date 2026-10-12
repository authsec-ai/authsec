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
)

// The IGA_POLICY gate (SPEC-iga-phase3-policy.md §4.3, T3.02).
//
//	IGA_POLICY   IGA_GRAPH_PROJECTION   Phase 3 schema   state           Phase 3 routes
//	off/unset    any                    any              off             503 policy_unavailable
//	on           off / misconfigured    any              misconfigured   503 policy_unavailable
//	on           on (verified)          not verified     misconfigured   503 policy_unavailable
//	on           on (verified)          verified         on              served
//	other value  any                    any              misconfigured   503 policy_unavailable
//
// FAIL CLOSED. Every way the gate can be wrong -- a typo in the switch, the
// graph gate it depends on not verified, a Phase 3 relation missing, a
// database error during verification -- leaves it unavailable, with the
// reason /capabilities reports and every Phase 3 route returns. Nothing
// Phase 3 runs half-on. Legacy routes and workers never read this gate.
//
// The graph dependency is read LIVE on every Status call, not captured at
// startup: the graph gate verifies asynchronously (VerifyUntilReady), so a
// policy gate built before it verified becomes available the moment it does,
// and never while it is not.

// PolicyEnv is the switch.
const PolicyEnv = "IGA_POLICY"

// Policy gate states, as /api/iga/v1/capabilities reports them.
const (
	PolicyOff           = "off"
	PolicyOn            = "on"
	PolicyMisconfigured = "misconfigured"
)

// PolicyGate carries the switch, the graph gate it depends on, and whether the
// Phase 3 schema has been verified.
type PolicyGate struct {
	enabled bool
	// badValue is the reason for an unrecognised switch value: the gate is
	// then on-but-misconfigured forever, and never verifies.
	badValue string
	graph    func() *GraphProjectionGate

	mu         sync.RWMutex
	verified   bool
	reason     string // the last verification failure
	schemaHead string
}

// NewPolicyGate builds a gate. graph returns the graph gate it depends on (nil
// is read as off). badValue, when non-empty, makes the gate misconfigured.
func NewPolicyGate(enabled bool, badValue string, graph func() *GraphProjectionGate) *PolicyGate {
	g := &PolicyGate{enabled: enabled || badValue != "", badValue: badValue, graph: graph}
	if g.enabled && badValue == "" {
		g.reason = "the Phase 3 schema (047-" + PolicySchemaHead + ") has not been verified yet"
	}
	return g
}

// PolicyGateFromEnv reads IGA_POLICY ONCE, as GraphProjectionGateFromEnv reads
// its switch: unset, "off", "false" and "0" are off; "on", "true" and "1" are
// on; anything else is misconfigured rather than guessed.
func PolicyGateFromEnv(graph func() *GraphProjectionGate) *PolicyGate {
	switch v := strings.ToLower(strings.TrimSpace(os.Getenv(PolicyEnv))); v {
	case "", "off", "false", "0":
		return NewPolicyGate(false, "", graph)
	case "on", "true", "1":
		return NewPolicyGate(true, "", graph)
	default:
		return NewPolicyGate(true, fmt.Sprintf("%s=%q is not on or off", PolicyEnv, v), graph)
	}
}

// Enabled reports whether the switch is on (verified or not, valid or not).
func (g *PolicyGate) Enabled() bool { return g != nil && g.enabled }

// Status is the gate's state, the reason when it is not on, and the Phase 3
// schema head when verified. The reason is the one every Phase 3 route's 503
// carries.
func (g *PolicyGate) Status() (state, reason, schemaHead string) {
	if g == nil || !g.enabled {
		return PolicyOff, PolicyEnv + " is off", ""
	}
	if g.badValue != "" {
		return PolicyMisconfigured, g.badValue, ""
	}
	var graph *GraphProjectionGate
	if g.graph != nil {
		graph = g.graph()
	}
	if mode, greason, _ := graph.Status(); mode != GraphProjectionOn {
		r := fmt.Sprintf("%s=on requires %s=on and a verified graph schema; graph projection is %s",
			PolicyEnv, GraphProjectionEnv, mode)
		if greason != "" {
			r += ": " + greason
		}
		return PolicyMisconfigured, r, ""
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if !g.verified {
		return PolicyMisconfigured, g.reason, g.schemaHead
	}
	return PolicyOn, "", g.schemaHead
}

// Available reports whether Phase 3 may run now: on, the graph gate on, the
// Phase 3 schema verified.
func (g *PolicyGate) Available() bool {
	state, _, _ := g.Status()
	return state == PolicyOn
}

// Verify runs the Phase 3 schema check (VerifyPolicySchema) and records the
// outcome. A success is final; a failure -- a missing relation or a database
// error -- is recorded with its reason and can be retried. A gate that is off
// or has a bad switch value never verifies.
func (g *PolicyGate) Verify(db *gorm.DB) error {
	if g == nil || !g.enabled {
		return nil
	}
	if g.badValue != "" {
		return fmt.Errorf("%s", g.badValue)
	}
	return g.checkSchema(db, true)
}

// checkSchema runs VerifyPolicySchema and records a failure's reason. On
// success it marks the gate verified only when markVerified is set;
// otherwise the schema head is recorded and the gate stays unavailable
// until markReady (VerifyUntilReady's ready hooks must run first).
func (g *PolicyGate) checkSchema(db *gorm.DB, markVerified bool) error {
	g.mu.RLock()
	done := g.verified
	g.mu.RUnlock()
	if done {
		return nil
	}
	err := VerifyPolicySchema(db)
	g.mu.Lock()
	defer g.mu.Unlock()
	if err != nil {
		g.reason = err.Error()
		return err
	}
	g.schemaHead = PolicySchemaHead
	if markVerified {
		g.verified, g.reason = true, ""
	} else {
		g.reason = "the Phase 3 schema (047-" + PolicySchemaHead + ") is verified; the policy runtime is being installed"
	}
	return nil
}

// markReady makes a schema-verified gate available.
func (g *PolicyGate) markReady() {
	g.mu.Lock()
	g.verified, g.reason = true, ""
	g.mu.Unlock()
}

// VerifyUntilReady retries the schema check until it succeeds or ctx ends,
// logging each decision. A transient error is retried, never cached as an
// answer. Each onReady runs once, after the FIRST successful schema check
// (T3.08: the policy job worker starts there, never before the schema is
// verified).
//
// fix/p3-appr (P1-4): the gate reports verified -- and so serves the policy
// routes and lets the job worker claim -- only AFTER every onReady has
// returned. cmd/main.go installs the policy runtime there
// (InstallGovPolicyRuntime: the owner gate and the other authoring hooks,
// then the Slack app's chained hooks), so no request is ever served while
// those hooks are absent; until then Status is misconfigured with the
// reason "... the policy runtime is being installed".
func (g *PolicyGate) VerifyUntilReady(ctx context.Context, db *gorm.DB, interval time.Duration, onReady ...func()) {
	if !g.Enabled() {
		return
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	for {
		var err error
		if g.badValue != "" {
			err = fmt.Errorf("%s", g.badValue)
		} else {
			err = g.checkSchema(db, false)
		}
		if err == nil {
			for _, f := range onReady {
				if f != nil {
					f()
				}
			}
			g.markReady()
			state, reason, _ := g.Status()
			if state == PolicyOn {
				log.Printf("[policy] %s=on: Phase 3 schema verified at %s; policy routes served", PolicyEnv, PolicySchemaHead)
			} else {
				// Verified, but the graph gate is not (yet) on: Status re-reads
				// it on every request, so the routes open the moment it is.
				log.Printf("[policy] %s=on: Phase 3 schema verified at %s, but unavailable until the graph is: %s",
					PolicyEnv, PolicySchemaHead, reason)
			}
			return
		}
		log.Printf("[policy] %s=on but not ready, every policy route answers 503 policy_unavailable: %v", PolicyEnv, err)
		if g.badValue != "" {
			return // a bad switch value never verifies; retrying changes nothing
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// The process-wide gate. main installs it once at startup; everything else
// reads it. Defaults to off.
var (
	policyGateMu sync.RWMutex
	policyGate   = NewPolicyGate(false, "", GraphProjection)
)

// PolicyGateState returns the process-wide gate.
func PolicyGateState() *PolicyGate {
	policyGateMu.RLock()
	defer policyGateMu.RUnlock()
	return policyGate
}

// SetPolicyGate installs the process-wide gate. Called once by main; tests use
// it to stage the states.
func SetPolicyGate(g *PolicyGate) {
	policyGateMu.Lock()
	defer policyGateMu.Unlock()
	policyGate = g
}
