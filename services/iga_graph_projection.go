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

// Graph pipeline modes, as /api/iga/v1/capabilities reports them (§5.3).
const (
	GraphProjectionOff           = "off"
	GraphProjectionOn            = "on"
	GraphProjectionMisconfigured = "misconfigured"
)

// The graph pipeline is always on: the scan worker uses the workspace barrier
// and enqueues projection jobs, and the projector runs (SPEC §2.8), once the
// schema it needs has verified. Until then it fails closed (claims no scans)
// and /capabilities says why.
//
// It replaces the graph branch's table probing, which decided the same thing
// by asking whether iga_pipeline_lease existed -- and cached a transient
// database error as "absent" for the life of the process, silently disabling
// the barrier.

// GraphSchemaHead is the migration the pipeline requires, reported by
// /capabilities once verified.
const GraphSchemaHead = "036"

// graphRelations are the relations the pipeline and projector reference.
// Every one fails at PLAN time when missing, so the check is on existence, and
// the list is every table the code names -- not only 036's.
var graphRelations = []string{
	"iga_pipeline_lease",               // 027
	"iga_workload", "iga_relationship", // 029, 031
	"iga_object_support", "iga_access_edge_evidence", // 032
	"iga_relationship_evidence",                                     // 032
	"iga_projection_job", "iga_projection_state", "iga_publication", // 033
	"iga_external_principal",                                            // 034
	"cloud_policy", "cloud_policy_attachment", "cloud_group_membership", // 035
	"iga_policy", "iga_statement_revision", "iga_entitlement_target", // 036
	"iga_policy_assignment", "iga_assignment_evidence", "iga_lifecycle_event",
}

// graphColumns are columns ADDED to existing tables. An applied but
// incomplete migration is exactly the failure a relation check cannot see, so
// the ones the code writes are checked by name (§9).
var graphColumns = []string{
	"iga_identity_accounts.provider", "iga_identity_accounts.source_key",
	"iga_entitlements.policy_id", "iga_entitlements.statement_key",
	"iga_access_edges.assignment_id", "iga_access_edges.subject_identity_account_id",
	"iga_access_edges.subject_kind", // the legacy pair 030 must KEEP
	"iga_object_support.policy_id",
	"cloud_observation.policy_id",
	"cloud_identity.trust_document",
}

// VerifyGraphSchema reports what the pipeline needs that the database lacks.
//
// A database ERROR is returned as an error -- the caller retries it and never
// treats it as an answer. A MISSING relation or column is also an error, with
// the missing names: the pipeline cannot run against that schema.
func VerifyGraphSchema(db *gorm.DB) error {
	var missing []string
	for _, rel := range graphRelations {
		ok, err := repositories.HasRelation(db, rel)
		if err != nil {
			return fmt.Errorf("schema verification could not run: %w", err)
		}
		if !ok {
			missing = append(missing, rel)
		}
	}
	for _, qc := range graphColumns {
		table, col, _ := strings.Cut(qc, ".")
		ok, err := repositories.HasColumn(db, table, col)
		if err != nil {
			return fmt.Errorf("schema verification could not run: %w", err)
		}
		if !ok {
			missing = append(missing, qc)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("the graph pipeline needs migrations 027-%s; missing: %s",
			GraphSchemaHead, strings.Join(missing, ", "))
	}
	return nil
}

// GraphProjectionGate carries whether the graph schema has been verified.
//
//	verified   scan worker            projector
//	no         claims NOTHING         not started
//	yes        barrier + job enqueue  started
//
// FAIL CLOSED. Until verification succeeds the worker must not fall back to
// scanning without the barrier: that would scan while a projector elsewhere
// might run, which is the overwrite the barrier exists to prevent. It claims
// nothing, and /capabilities says why. A gate built "off" (the zero process
// default before main installs one, and some tests) is the pre-pipeline path.
type GraphProjectionGate struct {
	enabled bool
	// broken: built misconfigured (a fixed reason); it never verifies.
	broken bool

	mu         sync.RWMutex
	verified   bool
	reason     string
	schemaHead string
}

// NewGraphProjectionGate builds a gate. enabled=false is Phase 1; reason, when
// non-empty, starts the gate misconfigured (an unrecognised switch value).
func NewGraphProjectionGate(enabled bool, reason string) *GraphProjectionGate {
	g := &GraphProjectionGate{enabled: enabled}
	if reason != "" {
		g.enabled, g.reason, g.broken = true, reason, true
	} else if enabled {
		g.reason = "schema not yet verified"
	}
	return g
}

// DefaultGraphProjectionGate is the gate main installs: on, and serving once
// its schema verifies.
func DefaultGraphProjectionGate() *GraphProjectionGate {
	return NewGraphProjectionGate(true, "")
}

// Enabled reports whether the gate is on (verified or not).
func (g *GraphProjectionGate) Enabled() bool { return g != nil && g.enabled }

// PipelineMode reports whether the worker should use the barrier and enqueue
// projection jobs: on AND verified.
func (g *GraphProjectionGate) PipelineMode() bool {
	if g == nil || !g.enabled {
		return false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.verified
}

// ClaimAllowed reports whether the worker may claim scans at all: always when
// off (Phase 1), only once verified when on.
func (g *GraphProjectionGate) ClaimAllowed() bool {
	return g == nil || !g.enabled || g.PipelineMode()
}

// Status is what /capabilities reports.
func (g *GraphProjectionGate) Status() (mode, reason, schemaHead string) {
	if g == nil || !g.enabled {
		return GraphProjectionOff, "", ""
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.verified {
		return GraphProjectionOn, "", g.schemaHead
	}
	return GraphProjectionMisconfigured, g.reason, g.schemaHead
}

// Verify runs the schema check once and records the outcome. A success is
// final; a failure is recorded with its reason and can be retried.
func (g *GraphProjectionGate) Verify(db *gorm.DB) error {
	if g == nil || !g.enabled {
		return nil
	}
	g.mu.RLock()
	done, preset := g.verified, g.reason
	g.mu.RUnlock()
	if done {
		return nil
	}
	if g.broken {
		return fmt.Errorf("%s", preset) // a gate built misconfigured never verifies
	}
	err := VerifyGraphSchema(db)
	g.mu.Lock()
	defer g.mu.Unlock()
	if err != nil {
		g.reason = err.Error()
		if head, herr := repositories.MigrationHead(db); herr == nil && head > 0 {
			g.schemaHead = fmt.Sprintf("%03d", head)
		}
		return err
	}
	g.verified, g.reason, g.schemaHead = true, "", GraphSchemaHead
	return nil
}

// VerifyUntilReady retries Verify until it succeeds or ctx ends, then calls
// onReady exactly once. A transient error is RETRIED, never cached.
func (g *GraphProjectionGate) VerifyUntilReady(
	ctx context.Context, db *gorm.DB, interval time.Duration, onReady func(),
) {
	if !g.Enabled() {
		return
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	for {
		if err := g.Verify(db); err == nil {
			log.Printf("[graph] schema verified at %s; pipeline mode", GraphSchemaHead)
			if onReady != nil {
				onReady()
			}
			return
		} else {
			log.Printf("[graph] not ready, claiming no scans: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// The process-wide gate. main installs the default (on) at startup; everything
// else reads it. Before that it is off, the pre-pipeline path.
var (
	graphGateMu sync.RWMutex
	graphGate   = NewGraphProjectionGate(false, "")
)

// GraphProjection returns the process-wide gate.
func GraphProjection() *GraphProjectionGate {
	graphGateMu.RLock()
	defer graphGateMu.RUnlock()
	return graphGate
}

// SetGraphProjection installs the process-wide gate. Called once by main;
// tests use it to stage the three states.
func SetGraphProjection(g *GraphProjectionGate) {
	graphGateMu.Lock()
	defer graphGateMu.Unlock()
	graphGate = g
}
