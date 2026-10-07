package repositories

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// CloudEvidenceReads is the collected model's READ-ONLY interface to Phase 3
// finding evaluation, evidence bundles and readiness
// (SPEC-iga-phase3-policy.md §2.5 step 2, §2.11, §3.9, §7.1).
//
// The evaluation reads, by contract, exactly these collected facts of the
// runs a publication's manifest names: each run's connector (account,
// regions), the Access Advisor rows (cloud_usage) and their generations, the
// role's IAM CreateDate (cloud_identity), and the run's immutable
// resource-policy coverage, observations and documents (056); readiness
// reads which connectors have a verified enforcement binding (053). They are
// typed reads here, on the collection side, instead of table names typed
// into IGA queries (scripts/ci-iga-isolation-check.sh): the dependency is
// declared once, it is read-only, and nothing in it writes cloud_*.
type CloudEvidenceReads struct{}

// CloudRunRow is one scan run with its connector's scope and attributes.
type CloudRunRow struct {
	ID          uuid.UUID
	ConnectorID uuid.UUID
	Generation  int
	Coverage    json.RawMessage
	PublishedAt *time.Time
	ScopeID     string
	Attrs       json.RawMessage
}

// Runs reads the given scan runs with their connectors.
func (CloudEvidenceReads) Runs(tx *gorm.DB, ws uuid.UUID, ids []uuid.UUID) ([]CloudRunRow, error) {
	var out []CloudRunRow
	if len(ids) == 0 {
		return out, nil
	}
	err := tx.Raw(`SELECT r.id, r.connector_id, r.generation, r.coverage, r.published_at, c.scope_id, c.attrs
	                 FROM cloud_scan_run r
	                 JOIN cloud_connector c ON c.workspace_id = r.workspace_id AND c.id = r.connector_id
	                WHERE r.workspace_id = ? AND r.id IN ?`, ws, ids).Scan(&out).Error
	return out, err
}

// ResourcePolicyCoverageRow is one cloud_resource_policy_coverage row.
type ResourcePolicyCoverageRow struct {
	ScanRunID    uuid.UUID
	ResourceForm string
	Region       string
	State        string
	Reason       string
}

// ResourcePolicyCoverage reads the coverage rows of the given runs.
func (CloudEvidenceReads) ResourcePolicyCoverage(tx *gorm.DB, ws uuid.UUID, runs []uuid.UUID) ([]ResourcePolicyCoverageRow, error) {
	var out []ResourcePolicyCoverageRow
	if len(runs) == 0 {
		return out, nil
	}
	err := tx.Raw(`SELECT scan_run_id, resource_form, region, state, reason FROM cloud_resource_policy_coverage
	                WHERE workspace_id = ? AND scan_run_id IN ? ORDER BY scan_run_id, resource_form, region`, ws, runs).
		Scan(&out).Error
	return out, err
}

// ResourcePolicyObservationRow is one observation with its stored document.
type ResourcePolicyObservationRow struct {
	ScanRunID     uuid.UUID
	ResourceForm  string
	Region        string
	ResourceARN   string
	PolicyPresent bool
	DocumentHash  *string
	ParseState    string
	Canonical     *string
}

// ResourcePolicyObservations reads the observations of the given runs.
func (CloudEvidenceReads) ResourcePolicyObservations(tx *gorm.DB, ws uuid.UUID, runs []uuid.UUID) ([]ResourcePolicyObservationRow, error) {
	var out []ResourcePolicyObservationRow
	if len(runs) == 0 {
		return out, nil
	}
	err := tx.Raw(`SELECT o.scan_run_id, o.resource_form, o.region, o.resource_arn, o.policy_present,
	                      o.document_hash, o.parse_state, d.canonical
	                 FROM cloud_resource_policy_observation o
	                 LEFT JOIN cloud_policy_document d ON d.workspace_id = o.workspace_id AND d.document_hash = o.document_hash
	                WHERE o.workspace_id = ? AND o.scan_run_id IN ?
	                ORDER BY o.scan_run_id, o.resource_arn`, ws, runs).Scan(&out).Error
	return out, err
}

// CloudRoleRow is one IAM role's inventory row: its id, connector, ARN,
// RoleId and IAM CreateDate.
type CloudRoleRow struct {
	ID          uuid.UUID
	ConnectorID uuid.UUID
	NativeID    string
	UniqueID    string
	CreatedAt   *time.Time
}

// Roles reads the workspace's IAM role inventory rows.
func (CloudEvidenceReads) Roles(tx *gorm.DB, ws uuid.UUID) ([]CloudRoleRow, error) {
	var out []CloudRoleRow
	err := tx.Raw(`SELECT id, connector_id, native_id, COALESCE(attrs->>'unique_id', '') AS unique_id, created_at
	                 FROM cloud_identity WHERE workspace_id = ? AND kind = 'iam_role'`, ws).Scan(&out).Error
	return out, err
}

// UsageRow is one Access Advisor row.
type UsageRow struct {
	IdentityID         uuid.UUID
	Service            string
	LastUsedAt         *time.Time
	GeneratedAt        *time.Time
	LastSeenGeneration int
}

// Usage reads the connectors' Access Advisor rows (source service_last_accessed).
func (CloudEvidenceReads) Usage(tx *gorm.DB, ws uuid.UUID, source string, connectors []uuid.UUID) ([]UsageRow, error) {
	var out []UsageRow
	if len(connectors) == 0 {
		return out, nil
	}
	err := tx.Raw(`SELECT identity_id, service, last_used_at, generated_at, last_seen_generation
	                 FROM cloud_usage
	                WHERE workspace_id = ? AND source = ? AND connector_id IN ?
	                ORDER BY identity_id, service`, ws, source, connectors).Scan(&out).Error
	return out, err
}

// ActivityGenerations is, per connector, the newest generation that touched
// its activity: a usage row carrying it, or a run whose activity surface was
// reached (it may have deleted every row and written none).
func (CloudEvidenceReads) ActivityGenerations(tx *gorm.DB, ws uuid.UUID, source string, connectors []uuid.UUID) (map[uuid.UUID]int, error) {
	out := map[uuid.UUID]int{}
	if len(connectors) == 0 {
		return out, nil
	}
	var rows []struct {
		ConnectorID uuid.UUID
		Gen         int
	}
	err := tx.Raw(`SELECT connector_id, max(gen) AS gen FROM (
	                  SELECT connector_id, max(last_seen_generation) AS gen FROM cloud_usage
	                   WHERE workspace_id = ? AND source = ? AND connector_id IN ? GROUP BY connector_id
	                  UNION ALL
	                  SELECT connector_id, max(generation) FROM cloud_scan_run
	                   WHERE workspace_id = ? AND connector_id IN ?
	                     AND coverage->'surfaces'->'activity'->>'state' = 'reached' GROUP BY connector_id) m
	                GROUP BY connector_id`, ws, source, connectors, ws, connectors).Scan(&rows).Error
	for _, r := range rows {
		out[r.ConnectorID] = r.Gen
	}
	return out, err
}

// VerifiedEnforcementConnectors are the connectors with a verified
// enforcement binding (053).
func (CloudEvidenceReads) VerifiedEnforcementConnectors(db *gorm.DB, ws uuid.UUID) ([]uuid.UUID, error) {
	var out []uuid.UUID
	err := db.Raw(`SELECT connector_id FROM cloud_enforcement_binding WHERE workspace_id = ? AND state = 'verified'`, ws).
		Scan(&out).Error
	return out, err
}
