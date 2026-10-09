package repositories

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

/* cloud_gcp_scan_repository.go owns the scan lifecycle on cloud_connector:
   allocating a generation, and writing the coverage blob that says what that
   generation could and could not read.

   WHY THIS IS A SEPARATE REPOSITORY FROM CloudConnectorRepository. That one
   owns onboarding CRUD -- upsert, verify, error, revoke. This one owns a
   scan's lifecycle. The two sets are disjoint and the scan set is GCP-only for
   now, so keeping them apart means nothing here can change the behaviour of a
   connector that is merely being onboarded, and nothing AWS does can change
   the behaviour of a GCP scan. It reads and writes the same row; it is a
   second aspect of one table rather than a duplicate abstraction.

   WHY EVERY STATEMENT CARRIES provider = 'gcp'. Structural, not defensive
   politeness: this repository cannot allocate a generation on, or overwrite
   the coverage of, an AWS or Azure connector even if a caller passes the wrong
   id. The service layer guards the provider too; this is the guard that
   survives a refactor of the service layer.

   WHY GENERATION IS ALLOCATED HERE AND NOT COMPUTED IN GO. See
   AllocateGeneration's own comment. This is the one thing in the cloud scan
   path that must be atomic, and it is the reason this file exists. */

// ErrScanSuperseded means a write was refused because the connector's
// scan_generation has moved past the generation the caller is writing for --
// another scan started while this one was running.
//
// Returned rather than reported as a bool on purpose. A bool is ignorable, and
// the failure this guards against is precisely a result that was computed
// correctly and then silently dropped: the AWS workload and permission
// scanners compute their own completeness and discard it at the call site
// (controllers/platform/cloud_aws_controller.go:414,422), which is how a denied
// EKS read ends up displayed as coverage.status == "complete". An error is
// harder to drop by accident, and `errors.Is` keeps the check explicit.
var ErrScanSuperseded = errors.New("cloud scan superseded by a newer generation")

// CloudGCPScanRepository is the scan lifecycle for a GCP connector row.
//
// Every method is workspace-scoped and provider-scoped. A connector is the
// address of a customer's cloud estate; a missing tenant predicate here would
// be a cross-tenant write to the record that decides what a scan may delete.
type CloudGCPScanRepository interface {
	// AllocateGeneration advances the connector's scan_generation by one and
	// returns the new value, in a single statement.
	//
	// ATOMICITY IS THE WHOLE POINT. The AWS scanner computes its generation in
	// Go from a value it read earlier -- `generation := connector.ScanGeneration + 1`
	// (services/cloud_aws_iam_scan.go:141) -- and writes it back at the end of
	// the scan (:485-491) with no row lock and no `AND scan_generation = <read>`
	// guard. Two scans of one connector therefore compute the SAME generation,
	// and since reconciliation deletes every row whose last_seen_generation is
	// below the current one, the first scan to finish can delete the rows the
	// second has not written yet. That is a data-loss path, not a race that
	// merely wastes work.
	//
	// The pattern here is the one this codebase already uses correctly for
	// resource-server scans (services/resource_server_service.go:555-572):
	// UPDATE ... SET n = n + 1 ... RETURNING n.
	//
	// DELIBERATE DIVERGENCE FROM AWS: the generation moves at the START of a
	// scan, not at the end. Consequences, stated plainly because they are not
	// all free:
	//
	//   - Generations are monotonic and never reused, so two scans can never
	//     share one. This is what buys concurrency safety.
	//   - A scan that crashes burns a generation. Integer space is not scarce.
	//   - It forfeits AWS's reuse-the-number trick, which exists so an
	//     interrupted scan can resume from a checkpoint at the same generation.
	//     That trick does not currently work for AWS either -- the live chain
	//     cannot produce the state it resumes from, recorded in AWS's own
	//     source at tests/integration/cloud_aws_resume_test.go:169-186 -- and
	//     GCP is shipping without resume by decision (D-15). Should resume
	//     arrive, this is the function that has to change, and the comment
	//     above is the argument it has to answer.
	//
	// PARTIAL-SCAN SAFETY IS UNAFFECTED by moving the allocation earlier.
	// Safety comes from ScanCoverage.Complete() gating reconciliation, never
	// from the timing of the increment: a partial scan advances the generation
	// and reconciles nothing, and the rows it could not see keep their older
	// generation and survive untouched.
	//
	// Returns ErrCloudConnectorNotFound when no GCP connector matches.
	AllocateGeneration(workspaceID, connectorID uuid.UUID) (int, error)

	// BeginScan records the opening coverage blob -- status running, generation
	// stamped, started_at set -- so a reader polling the connector can tell a
	// scan in flight from a stale report, and so the in-flight guard has
	// something durable to read.
	//
	// Guarded on generation: if another scan has already allocated past this
	// one, this returns ErrScanSuperseded and writes nothing.
	BeginScan(workspaceID, connectorID uuid.UUID, generation int, coverage json.RawMessage) error

	// CommitCoverage writes the final coverage report for a generation.
	//
	// It does NOT touch scan_generation -- AllocateGeneration already moved it.
	// That split is deliberate: the number that decides what reconciliation may
	// delete is set once, at a point where nothing has been read yet, and every
	// later write is a report about that number rather than a change to it.
	//
	// Guarded on generation for the same reason as BeginScan: a scan that ran
	// long and was overtaken must not overwrite the newer scan's report with
	// its own stale one. Returns ErrScanSuperseded when that happens.
	CommitCoverage(workspaceID, connectorID uuid.UUID, generation int, coverage json.RawMessage) error

	// CurrentGeneration reads the connector's scan_generation.
	//
	// Used immediately before reconciliation: a scan may only delete rows if it
	// still owns the current generation. Complete() proves the scan was allowed
	// to look everywhere; this proves nothing has started since.
	CurrentGeneration(workspaceID, connectorID uuid.UUID) (int, error)
}

type cloudGCPScanRepository struct{ db *gorm.DB }

// NewCloudGCPScanRepository constructs the repository.
func NewCloudGCPScanRepository(db *gorm.DB) CloudGCPScanRepository {
	return &cloudGCPScanRepository{db: db}
}

func (r *cloudGCPScanRepository) AllocateGeneration(workspaceID, connectorID uuid.UUID) (int, error) {
	var generation int

	// Raw rather than the GORM builder because RETURNING is the point: the
	// increment and the read of its result must be one statement, and the
	// builder's Updates() cannot express that.
	res := r.db.Raw(`
		UPDATE cloud_connector
		   SET scan_generation = scan_generation + 1,
		       updated_at      = now()
		 WHERE workspace_id = ?
		   AND id           = ?
		   AND provider     = ?
		RETURNING scan_generation
	`, workspaceID, connectorID, models.CloudProviderGCP).Scan(&generation)

	if res.Error != nil {
		return 0, res.Error
	}
	if res.RowsAffected == 0 {
		// No row matched. Either the connector does not exist in this
		// workspace, or it is not a GCP connector. Both are the same answer to
		// the only question this repository is entitled to ask.
		return 0, ErrCloudConnectorNotFound
	}
	return generation, nil
}

func (r *cloudGCPScanRepository) BeginScan(
	workspaceID, connectorID uuid.UUID, generation int, coverage json.RawMessage,
) error {
	return r.writeCoverage(workspaceID, connectorID, generation, coverage)
}

func (r *cloudGCPScanRepository) CommitCoverage(
	workspaceID, connectorID uuid.UUID, generation int, coverage json.RawMessage,
) error {
	return r.writeCoverage(workspaceID, connectorID, generation, coverage)
}

// writeCoverage is the guarded coverage write both entry points share.
//
// They are separate methods on the interface despite one implementation
// because they mean different things to a reader of the scan runner, and
// because the commit side is the one likely to grow (a status transition, a
// finished_at guard) without the begin side following it.
func (r *cloudGCPScanRepository) writeCoverage(
	workspaceID, connectorID uuid.UUID, generation int, coverage json.RawMessage,
) error {
	if len(coverage) == 0 {
		// The column is NOT NULL and a zero-length blob is not valid JSON. An
		// empty report is also a lie a scan should never tell: an absent
		// surface list and a surface list of all-reached are indistinguishable
		// to a reader, and only one of them means the estate is clean.
		return errors.New("cloud gcp scan: refusing to write an empty coverage blob")
	}

	res := r.db.Model(&models.CloudConnector{}).
		Where("workspace_id = ? AND id = ? AND provider = ? AND scan_generation = ?",
			workspaceID, connectorID, models.CloudProviderGCP, generation).
		Updates(map[string]interface{}{
			"coverage":   coverage,
			"updated_at": time.Now(),
		})

	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		// The connector still exists -- AllocateGeneration proved that moments
		// ago -- so the generation predicate is what failed. Another scan has
		// allocated past this one and its report is the current one.
		return ErrScanSuperseded
	}
	return nil
}

func (r *cloudGCPScanRepository) CurrentGeneration(workspaceID, connectorID uuid.UUID) (int, error) {
	var generation int
	res := r.db.Model(&models.CloudConnector{}).
		Where("workspace_id = ? AND id = ? AND provider = ?",
			workspaceID, connectorID, models.CloudProviderGCP).
		Select("scan_generation").
		Scan(&generation)

	if res.Error != nil {
		return 0, res.Error
	}
	if res.RowsAffected == 0 {
		return 0, ErrCloudConnectorNotFound
	}
	return generation, nil
}
