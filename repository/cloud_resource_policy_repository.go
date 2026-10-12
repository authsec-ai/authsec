package repositories

import (
	"errors"
	"fmt"
	"sort"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Resource-policy evidence (SPEC-iga-phase3-policy.md §3.9, migration 056):
// per scan, one coverage row per (form, region), one observation per
// resource read -- including "no policy" -- and the content-addressed,
// insert-once documents they reference.
//
// Nothing here updates a row. The tables refuse it (authsec_row_immutable),
// and a rescan writes its own rows under its own scan_run_id, so scan N's
// evidence is exactly what scan N read for as long as it is retained. Rows
// leave only through PruneEvidence (retention) or a workspace purge.

// CloudResourcePolicyRepository writes and reads 056.
type CloudResourcePolicyRepository interface {
	// Fenced returns a copy whose writes first assert the scan fence, so a
	// superseded worker lands nothing (§2.10A).
	Fenced(f ScanFence) CloudResourcePolicyRepository

	// RecordForm writes ONE (form, region) of one scan in one transaction:
	// the coverage row, the documents its observations reference
	// (insert-once: ON CONFLICT DO NOTHING, which by construction is the
	// same content, probe DB68), and the observations. It returns false, and
	// writes nothing, when the coverage row already exists: an earlier
	// attempt of the same run recorded this unit, and its rows are kept
	// whole rather than mixed with this attempt's (DECISION T3.03b-6).
	RecordForm(cov *models.CloudResourcePolicyCoverage, docs []models.CloudPolicyDocument,
		obs []models.CloudResourcePolicyObservation) (bool, error)

	// CoverageForScan is one scan's coverage rows, by form and region.
	CoverageForScan(workspaceID, scanRunID uuid.UUID) ([]models.CloudResourcePolicyCoverage, error)
	// ObservationsForScan is one scan's observations, by form, region, ARN.
	ObservationsForScan(workspaceID, scanRunID uuid.UUID) ([]models.CloudResourcePolicyObservation, error)
	// Documents returns the stored documents with these hashes.
	Documents(workspaceID uuid.UUID, hashes []string) (map[string]models.CloudPolicyDocument, error)

	// PruneEvidence is §3.9's retention: it deletes the coverage (and, by
	// cascade, the observations) of scans older than the newest keepRevs
	// publications, except scans those publications name and scans named by
	// any plan that is current, approved, or referenced by a deployment; then
	// the documents no remaining observation references.
	PruneEvidence(workspaceID uuid.UUID, keepRevs int) (PruneEvidenceResult, error)
}

// PruneEvidenceResult reports what one prune removed.
type PruneEvidenceResult struct {
	Scans        []uuid.UUID
	CoverageRows int64
	Documents    int64
}

type cloudResourcePolicyRepository struct {
	db    *gorm.DB
	fence *ScanFence
}

// NewCloudResourcePolicyRepository builds the repository.
func NewCloudResourcePolicyRepository(db *gorm.DB) CloudResourcePolicyRepository {
	return &cloudResourcePolicyRepository{db: db}
}

func (r *cloudResourcePolicyRepository) Fenced(f ScanFence) CloudResourcePolicyRepository {
	return &cloudResourcePolicyRepository{db: r.db, fence: &f}
}

// ErrDocumentNotStored means a document an observation references could not
// be made present (it was pruned concurrently three times in a row).
var ErrDocumentNotStored = errors.New("resource-policy document could not be stored")

func (r *cloudResourcePolicyRepository) RecordForm(
	cov *models.CloudResourcePolicyCoverage, docs []models.CloudPolicyDocument,
	obs []models.CloudResourcePolicyObservation,
) (bool, error) {
	if cov == nil {
		return false, errors.New("record resource-policy form: no coverage row")
	}
	inserted := false
	err := r.db.Transaction(func(tx *gorm.DB) error {
		if r.fence != nil {
			if err := assertScanFence(tx, *r.fence); err != nil {
				return err
			}
		}
		res := tx.Exec(`INSERT INTO cloud_resource_policy_coverage
			  (workspace_id, connector_id, scan_run_id, resource_form, region, state,
			   enumerated, read_ok, read_failed, reason)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (workspace_id, scan_run_id, resource_form, region) DO NOTHING`,
			cov.WorkspaceID, cov.ConnectorID, cov.ScanRunID, cov.ResourceForm, cov.Region, cov.State,
			cov.Enumerated, cov.ReadOK, cov.ReadFailed, cov.Reason)
		if res.Error != nil {
			return fmt.Errorf("insert coverage %s/%s: %w", cov.ResourceForm, cov.Region, res.Error)
		}
		if res.RowsAffected == 0 {
			return nil // recorded by an earlier attempt of this run: kept as is
		}
		inserted = true
		if err := storeDocuments(tx, cov.WorkspaceID, docs); err != nil {
			return err
		}
		if len(obs) > 0 {
			if err := tx.CreateInBatches(obs, 500).Error; err != nil {
				return fmt.Errorf("insert observations %s/%s: %w", cov.ResourceForm, cov.Region, err)
			}
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return inserted, nil
}

// storeDocuments inserts each document once and holds a KEY SHARE lock on
// every one until the transaction commits, so a concurrent prune cannot
// delete a document between its insert-or-exists and the observation that
// references it (the prune skips locked rows). The insert trigger rejects a
// hash that is not the sha256 of the canonical text, or a jsonb that differs
// from it (probes DB64, DB65) -- before the conflict check, so a wrong hash
// is refused even when the right one is already stored.
func storeDocuments(tx *gorm.DB, ws uuid.UUID, docs []models.CloudPolicyDocument) error {
	want := map[string]models.CloudPolicyDocument{}
	for _, d := range docs {
		want[d.DocumentHash] = d
	}
	if len(want) == 0 {
		return nil
	}
	pending := make([]string, 0, len(want))
	for h := range want {
		pending = append(pending, h)
	}
	sort.Strings(pending)
	for attempt := 0; attempt < 3 && len(pending) > 0; attempt++ {
		for _, h := range pending {
			d := want[h]
			if err := tx.Exec(`INSERT INTO cloud_policy_document (workspace_id, document_hash, canonical, document)
				VALUES (?, ?, ?, ?::jsonb)
				ON CONFLICT (workspace_id, document_hash) DO NOTHING`,
				ws, d.DocumentHash, d.Canonical, string(d.Document)).Error; err != nil {
				return fmt.Errorf("insert document %s: %w", d.DocumentHash, err)
			}
		}
		var held []string
		if err := tx.Raw(`SELECT document_hash FROM cloud_policy_document
			WHERE workspace_id = ? AND document_hash IN ? FOR KEY SHARE`, ws, pending).
			Scan(&held).Error; err != nil {
			return fmt.Errorf("lock documents: %w", err)
		}
		got := map[string]bool{}
		for _, h := range held {
			got[h] = true
		}
		var missing []string
		for _, h := range pending {
			if !got[h] {
				missing = append(missing, h)
			}
		}
		pending = missing
	}
	if len(pending) > 0 {
		return fmt.Errorf("%w: %v", ErrDocumentNotStored, pending)
	}
	return nil
}

func (r *cloudResourcePolicyRepository) CoverageForScan(ws, scan uuid.UUID) ([]models.CloudResourcePolicyCoverage, error) {
	var out []models.CloudResourcePolicyCoverage
	err := r.db.Where("workspace_id = ? AND scan_run_id = ?", ws, scan).
		Order("resource_form, region").Find(&out).Error
	return out, err
}

func (r *cloudResourcePolicyRepository) ObservationsForScan(ws, scan uuid.UUID) ([]models.CloudResourcePolicyObservation, error) {
	var out []models.CloudResourcePolicyObservation
	err := r.db.Where("workspace_id = ? AND scan_run_id = ?", ws, scan).
		Order("resource_form, region, resource_arn").Find(&out).Error
	return out, err
}

func (r *cloudResourcePolicyRepository) Documents(ws uuid.UUID, hashes []string) (map[string]models.CloudPolicyDocument, error) {
	out := map[string]models.CloudPolicyDocument{}
	if len(hashes) == 0 {
		return out, nil
	}
	var rows []models.CloudPolicyDocument
	if err := r.db.Where("workspace_id = ? AND document_hash IN ?", ws, hashes).Find(&rows).Error; err != nil {
		return nil, err
	}
	for _, d := range rows {
		out[d.DocumentHash] = d
	}
	return out, nil
}

// PruneEvidence implements §3.9 "Retention".
//
// DECISIONS (T3.03b-7):
//   - "older than evidence_retention_revs publications" = requested before
//     the oldest of the workspace's newest keepRevs publications, and named
//     by none of them (neither as the publication's own run nor in its
//     manifest). With fewer than keepRevs publications nothing is pruned.
//   - A live run (queued, running) is never pruned.
//   - "approved" = a live approve decision on the plan's version whose
//     plan_hashes include the plan's hash; "current" = not superseded;
//     "referenced by a deployment" = any iga_gov_deployment row names it.
//   - Documents are deleted only when no observation references them, and a
//     document a concurrent scan holds (KEY SHARE) is skipped, never waited
//     for: the next prune takes it.
func (r *cloudResourcePolicyRepository) PruneEvidence(ws uuid.UUID, keepRevs int) (PruneEvidenceResult, error) {
	var out PruneEvidenceResult
	if keepRevs < 1 {
		return out, fmt.Errorf("prune evidence: keepRevs must be positive, got %d", keepRevs)
	}
	err := r.db.Transaction(func(tx *gorm.DB) error {
		var victims []uuid.UUID
		if err := tx.Raw(`
			WITH retained AS (
			  SELECT rev, published_at, scan_run_id, manifest
			    FROM iga_publication WHERE workspace_id = ?
			   ORDER BY rev DESC LIMIT ?),
			window_start AS (SELECT min(published_at) AS at, count(*) AS n FROM retained),
			named AS (
			  SELECT scan_run_id::text AS id FROM retained
			  UNION
			  SELECT m.value FROM retained, jsonb_each_text(retained.manifest) AS m),
			protected AS (
			  SELECT p.resource_policy_scan_run_id AS id
			    FROM iga_gov_plan p
			   WHERE p.workspace_id = ? AND p.resource_policy_scan_run_id IS NOT NULL
			     AND (p.superseded_at IS NULL
			          OR EXISTS (SELECT 1 FROM iga_gov_deployment d
			                      WHERE d.workspace_id = p.workspace_id AND d.plan_id = p.id)
			          OR EXISTS (SELECT 1 FROM iga_gov_approval a
			                      WHERE a.workspace_id = p.workspace_id AND a.version_id = p.version_id
			                        AND a.decision = 'approve' AND a.revoked_at IS NULL
			                        AND p.plan_hash = ANY (a.plan_hashes))))
			SELECT DISTINCT c.scan_run_id
			  FROM cloud_resource_policy_coverage c
			  JOIN cloud_scan_run r ON r.workspace_id = c.workspace_id AND r.id = c.scan_run_id
			  CROSS JOIN window_start w
			 WHERE c.workspace_id = ?
			   AND w.n >= ?
			   AND r.requested_at < w.at
			   AND r.status NOT IN ('queued', 'running')
			   AND c.scan_run_id::text NOT IN (SELECT id FROM named WHERE id IS NOT NULL)
			   AND c.scan_run_id NOT IN (SELECT id FROM protected)
			 ORDER BY c.scan_run_id`,
			ws, keepRevs, ws, ws, keepRevs).Scan(&victims).Error; err != nil {
			return fmt.Errorf("select prunable scans: %w", err)
		}
		out.Scans = victims
		if len(victims) > 0 {
			res := tx.Exec(`DELETE FROM cloud_resource_policy_coverage
				WHERE workspace_id = ? AND scan_run_id IN ?`, ws, victims)
			if res.Error != nil {
				return fmt.Errorf("delete coverage: %w", res.Error)
			}
			out.CoverageRows = res.RowsAffected
		}
		res := tx.Exec(`DELETE FROM cloud_policy_document
			WHERE (workspace_id, document_hash) IN (
			  SELECT d.workspace_id, d.document_hash FROM cloud_policy_document d
			   WHERE d.workspace_id = ?
			     AND NOT EXISTS (SELECT 1 FROM cloud_resource_policy_observation o
			                      WHERE o.workspace_id = d.workspace_id AND o.document_hash = d.document_hash)
			   FOR UPDATE SKIP LOCKED)`, ws)
		if res.Error != nil {
			return fmt.Errorf("delete unreferenced documents: %w", res.Error)
		}
		out.Documents = res.RowsAffected
		return nil
	})
	return out, err
}
