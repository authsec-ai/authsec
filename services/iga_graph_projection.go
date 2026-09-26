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

// IGA_GRAPH_PROJECTION modes, as /api/iga/v1/capabilities reports them (§5.3).
const (
	GraphProjectionOff           = "off"
	GraphProjectionOn            = "on"
	GraphProjectionMisconfigured = "misconfigured"
)

// GraphProjectionEnv is the ONE switch that decides whether the scan worker
// uses the workspace barrier and enqueues projection jobs, and whether the
// projector runs (SPEC §2.8).
//
// It replaces the graph branch's table probing, which decided the same thing
// by asking whether iga_pipeline_lease existed -- and cached a transient
// database error as "absent" for the life of the process, silently disabling
// the barrier. It also replaces the implicit coupling that made the first scan
// in any workspace queue a job nobody would ever claim: nothing started the
// projector, so no scan could run there again.
const GraphProjectionEnv = "IGA_GRAPH_PROJECTION"

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
// the missing names, because it means the switch is on against a schema that
// cannot run it.
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
		return fmt.Errorf("%s=on needs migrations 027-%s; missing: %s",
			GraphProjectionEnv, GraphSchemaHead, strings.Join(missing, ", "))
	}
	return nil
}

// V2ProjectionEnv is the collector projection switch. Unset is off. It does
// not change GraphProjectionGate, which stays the 036 pipeline switch.
const V2ProjectionEnv = "IGA_V2_PROJECTION"

// V2ProjectionEnabled is true only for an explicit on. Anything else, including
// unset, is off, so a typo does not start collector projection.
func V2ProjectionEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(V2ProjectionEnv))) {
	case "on", "true", "1":
		return true
	default:
		return false
	}
}

// CollectorMicrobatch bounds how long collector outbox rows are grouped before
// one publication, and how long one arm may run before the scheduler offers
// the other arm a turn. IGA_V2_MICROBATCH overrides it for tests.
func CollectorMicrobatch() time.Duration {
	if v := strings.TrimSpace(os.Getenv("IGA_V2_MICROBATCH")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return 5 * time.Second
}

// v2ProjectionColumns are the 040 columns collector projection writes.
var v2ProjectionColumns = []string{
	"iga_object_support.integration_id",
	"iga_object_support.confirming_iga_scan_run_id",
	"iga_relationship.integration_id",
	"iga_access_edges.integration_id",
	"iga_policy_assignment.integration_id",
	"iga_access_edge_evidence.iga_observation_id",
	"iga_relationship_evidence.iga_observation_id",
	"iga_assignment_evidence.iga_observation_id",
	"iga_projection_job.iga_scan_run_id",
	"iga_projection_state.integration_id",
	"iga_projection_state.last_iga_scan_run_id",
	"iga_publication.iga_scan_run_id",
	"iga_publication.source_manifest_v2",
	"iga_pipeline_lease.iga_scan_run_id",
	"iga_projection_state.ordering_sequence",
	"iga_projection_state.ordering_snapshot",
	"collector_batches.snapshot_id",
	"collector_batches.superseded_at",
}

// VerifyV2ProjectionSchema fails closed when collector projection is switched
// on against a database that does not have migration 040.
func VerifyV2ProjectionSchema(db *gorm.DB) error {
	var missing []string
	for _, qc := range v2ProjectionColumns {
		table, col, _ := strings.Cut(qc, ".")
		ok, err := repositories.HasColumn(db, table, col)
		if err != nil {
			return fmt.Errorf("v2 schema verification could not run: %w", err)
		}
		if !ok {
			missing = append(missing, qc)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s=on needs migration 040; missing: %s",
			V2ProjectionEnv, strings.Join(missing, ", "))
	}
	return nil
}

// GraphProjectionGate carries the switch and whether it has been verified.
//
//	IGA_GRAPH_PROJECTION  verified   scan worker            projector
//	off (default)         --         Phase 1 exactly        not started
//	on                    no         claims NOTHING         not started
//	on                    yes        barrier + job enqueue  started
//
// FAIL CLOSED. With the switch on and verification failing or erroring, the
// worker must not fall back to Phase 1: that would scan without the barrier
// while a projector elsewhere might run, which is the overwrite the barrier
// exists to prevent. It claims nothing, and /capabilities says why.
type GraphProjectionGate struct {
	enabled bool

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
		g.enabled, g.reason = true, reason
	} else if enabled {
		g.reason = "schema not yet verified"
	}
	return g
}

// GraphProjectionGateFromEnv reads IGA_GRAPH_PROJECTION ONCE. Unset, "off",
// "false" and "0" are off; "on", "true" and "1" are on. Anything else is
// MISCONFIGURED rather than guessed: a typo must not silently mean either.
func GraphProjectionGateFromEnv() *GraphProjectionGate {
	switch v := strings.ToLower(strings.TrimSpace(os.Getenv(GraphProjectionEnv))); v {
	case "", "off", "false", "0":
		return NewGraphProjectionGate(false, "")
	case "on", "true", "1":
		return NewGraphProjectionGate(true, "")
	default:
		return NewGraphProjectionGate(true,
			fmt.Sprintf("%s=%q is not on or off", GraphProjectionEnv, v))
	}
}

// Enabled reports whether the switch is on (verified or not).
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
	if strings.Contains(preset, "is not on or off") {
		return fmt.Errorf("%s", preset) // a bad switch value never verifies
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
			log.Printf("[graph] %s=on: schema verified at %s; pipeline mode", GraphProjectionEnv, GraphSchemaHead)
			if onReady != nil {
				onReady()
			}
			return
		} else {
			log.Printf("[graph] %s=on but not ready, claiming no scans: %v", GraphProjectionEnv, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// The process-wide gate. main sets it once at startup; everything else reads
// it. Defaults to off, which is Phase 1 exactly.
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
