package ghgraph

import (
	"fmt"
	"sort"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Reconciler decides what a scan did NOT see, and whether that is evidence.
//
// The shape is internal/k8sgraph's, restated for GitHub's evidence stream:
// support rows name an iga_integrations row and the iga_scan_runs row that last
// confirmed them; grants carry the same pair. A scan ends only what a reading
// of the owning partition did not see (Scope.CanEnd), marks everything else it
// could not confirm stale, and then retires the nodes no source supports any
// longer.
//
// THE LEGACY ROWS ARE NEVER TOUCHED. The legacy GitHub writer's rows share
// provider 'github' and these tables, have an empty source_key and no support at
// all -- so "no surviving support" is true of every one of them. Every
// statement here is therefore narrowed to keyed rows this integration has
// supported; dropping that narrowing would retire the whole legacy GitHub
// inventory on the first scan.
type Reconciler struct {
	now func() time.Time
}

func NewReconciler(now func() time.Time) *Reconciler {
	if now == nil {
		now = time.Now
	}
	return &Reconciler{now: now}
}

// ReconcileInput is one scan's authority to close rows.
type ReconcileInput struct {
	WorkspaceID uuid.UUID
	Scope       Scope
}

// ReconcileResult is what the scan changed, so the report and the operator
// agree on what happened.
type ReconcileResult struct {
	SupportEnded     int `json:"support_ended"`
	SupportStale     int `json:"support_stale"`
	EdgesEnded       int `json:"edges_ended"`
	EdgesStale       int `json:"edges_stale"`
	ObjectsRetired   int `json:"objects_retired"`
	PartitionsClosed int `json:"partitions_closed"`
	PartitionsStale  int `json:"partitions_stale"`
}

// Reconcile runs in the caller's transaction, after the scan's rows are
// upserted. Support ended without the retirement it implies leaves objects
// alive with no evidence, so both halves commit together.
func (rc *Reconciler) Reconcile(tx *gorm.DB, in ReconcileInput) (*ReconcileResult, error) {
	at := rc.now()
	res := &ReconcileResult{}

	parts, err := rc.partitions(tx, in)
	if err != nil {
		return nil, err
	}
	for _, key := range parts {
		p, ok := ParsePartition(key)
		// An unparseable key was not written by this package. It is left alone
		// -- stale-marking is cheap to get wrong in the safe direction, ending
		// is not -- and only ever marked stale.
		closing := ok && in.Scope.CanEnd(p)
		if closing {
			res.PartitionsClosed++
		} else {
			res.PartitionsStale++
		}

		n, err := rc.reconcileSupport(tx, in, key, closing)
		if err != nil {
			return nil, fmt.Errorf("support %s: %w", key, err)
		}
		e, err := rc.reconcileEdges(tx, in, key, closing, at)
		if err != nil {
			return nil, fmt.Errorf("edges %s: %w", key, err)
		}
		if closing {
			res.SupportEnded += n
			res.EdgesEnded += e
		} else {
			res.SupportStale += n
			res.EdgesStale += e
		}
	}

	retired, err := RetireUnsupported(tx, in.WorkspaceID,
		"s2.integration_id = ?", in.Scope.IntegrationID, at)
	if err != nil {
		return nil, fmt.Errorf("retire unsupported: %w", err)
	}
	res.ObjectsRetired = retired
	return res, nil
}

// partitions lists every partition this integration still has live rows in.
//
// Read from the database rather than derived from the scan, because the
// partitions most in need of reconciling are the ones the scan no longer
// mentions: a repository dropped from the installation appears nowhere in it.
func (rc *Reconciler) partitions(tx *gorm.DB, in ReconcileInput) ([]string, error) {
	var keys []string
	if err := tx.Raw(`
		SELECT partition_key FROM iga_object_support
		 WHERE workspace_id = ? AND integration_id = ? AND state <> ?
		UNION
		SELECT partition_key FROM iga_access_edges
		 WHERE workspace_id = ? AND integration_id = ? AND state <> ?`,
		in.WorkspaceID, in.Scope.IntegrationID, models.RelEnded,
		in.WorkspaceID, in.Scope.IntegrationID, models.RelEnded).Scan(&keys).Error; err != nil {
		return nil, fmt.Errorf("list partitions: %w", err)
	}
	sort.Strings(keys)
	return keys, nil
}

// reconcileSupport ends or stales this partition's SUPPORT, never the object.
// Another source may still hold the node; ending the object here would make
// one integration's blindness delete what another can see.
func (rc *Reconciler) reconcileSupport(tx *gorm.DB, in ReconcileInput, key string, closing bool) (int, error) {
	q := tx.Model(&models.IGAObjectSupport{}).
		Where("workspace_id = ? AND integration_id = ? AND partition_key = ?",
			in.WorkspaceID, in.Scope.IntegrationID, key).
		Where("state <> ?", models.RelEnded).
		// IS DISTINCT FROM, never <>: the column is nullable (ON DELETE SET
		// NULL when a scan run is removed), and NULL <> uuid is NULL, which
		// would leave exactly those rows current forever.
		Where("last_confirmed_scan_run_id IS DISTINCT FROM ?", in.Scope.ScanRunID)

	if !closing {
		r := q.Where("state = ?", models.RelCurrent).Update("state", models.RelStale)
		return int(r.RowsAffected), r.Error
	}
	r := q.Updates(map[string]any{
		"state":        models.RelEnded,
		"ended_reason": models.EndedNotSeen,
	})
	return int(r.RowsAffected), r.Error
}

// reconcileEdges closes the grants the scan did not reconfirm. A deploy key's
// grant is one repository's fact, so absence from the partition that owns it
// is conclusive on its own, exactly as for a Kubernetes binding.
func (rc *Reconciler) reconcileEdges(tx *gorm.DB, in ReconcileInput, key string, closing bool, at time.Time) (int, error) {
	q := tx.Model(&models.IGAAccessEdge{}).
		Where("workspace_id = ? AND integration_id = ? AND partition_key = ?",
			in.WorkspaceID, in.Scope.IntegrationID, key).
		Where("provider = ? AND source_key <> ''", models.ProviderGitHub).
		Where("state <> ?", models.RelEnded).
		Where("last_confirmed_scan_run_id IS DISTINCT FROM ?", in.Scope.ScanRunID)

	if !closing {
		r := q.Where("state = ?", models.RelCurrent).Update("state", models.RelStale)
		return int(r.RowsAffected), r.Error
	}
	r := q.Updates(map[string]any{
		"state":        models.RelEnded,
		"valid_to":     at,
		"ended_reason": models.EndedNotSeen,
	})
	return int(r.RowsAffected), r.Error
}

// RetireUnsupported derives each keyed GitHub node's lifecycle from the support
// that REMAINS, then ends what depended on it, in the caller's transaction.
//
// sourceCond names the evidence stream whose support may have just ended
// ("s2.integration_id = ?" for a scan, "s2.discovery_source_id = ?" for a repo
// scan), so a node is only reconsidered by a reading that ever vouched for it.
// The multi-source rule (§2.10B) is the NOT EXISTS: a node retires only when
// NO source still supports it.
func RetireUnsupported(tx *gorm.DB, ws uuid.UUID, sourceCond string, sourceID uuid.UUID, at time.Time) (int, error) {
	total := 0
	for _, t := range []struct {
		table      string
		supportCol string
	}{
		{"iga_identity_accounts", "identity_account_id"},
		{"iga_resources", "resource_id"},
		{"iga_entitlements", "entitlement_id"},
		{"iga_workload", "workload_id"},
	} {
		r := tx.Exec(`
			UPDATE `+t.table+` o
			   SET lifecycle = ?, retired_reason = ?, updated_at = ?
			 WHERE o.workspace_id = ?
			   AND o.provider = ?
			   AND o.source_key <> ''
			   AND o.lifecycle = ?
			   AND EXISTS (
			         SELECT 1 FROM iga_object_support s2
			          WHERE s2.workspace_id = o.workspace_id
			            AND s2.`+t.supportCol+` = o.id
			            AND `+sourceCond+`)
			   AND NOT EXISTS (
			         SELECT 1 FROM iga_object_support s
			          WHERE s.workspace_id = o.workspace_id
			            AND s.`+t.supportCol+` = o.id
			            AND s.state <> ?)`,
			models.IGALifecycleRetired, models.RetiredUnsupported, at,
			ws, models.ProviderGitHub, models.IGALifecycleActive, sourceID, models.RelEnded)
		if r.Error != nil {
			return total, fmt.Errorf("retire %s: %w", t.table, r.Error)
		}
		total += int(r.RowsAffected)
	}
	if err := cascade(tx, ws, at); err != nil {
		return total, err
	}
	return total, nil
}

// cascade ends the edges a retired node made meaningless, and closes the
// credential of a retired deploy key.
//
// Done in SQL against the retired set rather than from a Go-side list, because
// a node may have been retired by an earlier pass whose cascade failed -- and a
// grant left current under a retired subject is a path the console will draw.
func cascade(tx *gorm.DB, ws uuid.UUID, at time.Time) error {
	for _, c := range []struct {
		col, table, reason string
	}{
		{"subject_identity_account_id", "iga_identity_accounts", models.EndedSubjectRetired},
		{"entitlement_id", "iga_entitlements", models.EndedStatementRetired},
	} {
		if err := tx.Exec(`
			UPDATE iga_access_edges
			   SET state = ?, valid_to = ?, ended_reason = ?, updated_at = ?
			 WHERE workspace_id = ? AND provider = ? AND source_key <> '' AND state <> ?
			   AND `+c.col+` IN (SELECT id FROM `+c.table+`
			                      WHERE workspace_id = ? AND provider = ?
			                        AND source_key <> '' AND lifecycle = ?)`,
			models.RelEnded, at, c.reason, at,
			ws, models.ProviderGitHub, models.RelEnded,
			ws, models.ProviderGitHub, models.IGALifecycleRetired).Error; err != nil {
			return fmt.Errorf("cascade grants from %s: %w", c.table, err)
		}
	}

	// iga_credentials has no 'retired' lifecycle. A deploy key GitHub no longer
	// reports cannot authenticate -- deleting the key is how it is revoked -- so
	// its credential leaves the live set as 'revoked', with the reason saying
	// it was inferred from absence rather than observed.
	if err := tx.Exec(`
		UPDATE iga_credentials
		   SET lifecycle = 'revoked', retired_reason = ?, updated_at = ?
		 WHERE workspace_id = ? AND provider = ? AND source_key <> ''
		   AND lifecycle NOT IN ('revoked', 'expired')
		   AND identity_account_id IN (SELECT id FROM iga_identity_accounts
		                                WHERE workspace_id = ? AND provider = ?
		                                  AND source_key <> '' AND lifecycle = ?)`,
		models.RetiredUnsupported, at,
		ws, models.ProviderGitHub,
		ws, models.ProviderGitHub, models.IGALifecycleRetired).Error; err != nil {
		return fmt.Errorf("cascade credentials: %w", err)
	}
	return nil
}
