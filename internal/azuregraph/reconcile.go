package azuregraph

import (
	"fmt"
	"time"

	"github.com/authsec-ai/authsec/models"
	"gorm.io/gorm"
)

// ReconcileResult is what one pass's reconciliation changed, and why.
type ReconcileResult struct {
	SupportEnded   int `json:"support_ended"`
	SupportStale   int `json:"support_stale"`
	EdgesEnded     int `json:"edges_ended"`
	EdgesStale     int `json:"edges_stale"`
	ObjectsRetired int `json:"objects_retired"`
	// CredentialsRevoked are secrets and certificates the directory no longer
	// lists: removed from their app.
	CredentialsRevoked int `json:"credentials_revoked"`
	// PartitionsClosed and PartitionsStale say WHY the other numbers are what
	// they are: a pass that could not read a surface reports its partitions
	// stale, which explains an otherwise alarming "0 retired".
	PartitionsClosed int `json:"partitions_closed"`
	PartitionsStale  int `json:"partitions_stale"`
}

// reconcile closes, in the caller's transaction, what this pass did not
// confirm in the partitions it owns -- ended where its coverage licenses it
// (Pass.CanEnd), stale otherwise -- then retires objects no source supports
// any more and cascades to their edges.
func reconcile(tx *gorm.DB, p Pass, at time.Time) (*ReconcileResult, error) {
	res := &ReconcileResult{}
	for _, spec := range p.specs() {
		closing := p.CanEnd(spec)
		if closing {
			res.PartitionsClosed++
		} else {
			res.PartitionsStale++
		}
		part := p.Partition(spec.target, spec.class)

		var n int
		var err error
		switch spec.target {
		case TargetNode, TargetAgentNode:
			n, err = reconcileSupport(tx, p, part, closing)
			if closing {
				res.SupportEnded += n
			} else {
				res.SupportStale += n
			}
		default:
			table := "iga_access_edges"
			if spec.target == TargetRelationship {
				table = "iga_relationship"
			}
			n, err = reconcileEdges(tx, p, table, part, closing, at)
			if closing {
				res.EdgesEnded += n
			} else {
				res.EdgesStale += n
			}
		}
		if err != nil {
			return nil, fmt.Errorf("partition %s: %w", part.Key(), err)
		}
	}

	retired, err := retireUnsupported(tx, p, at)
	if err != nil {
		return nil, err
	}
	res.ObjectsRetired = retired

	if p.ScopeKind == models.CloudScopeTenant {
		n, err := revokeCredentials(tx, p, at)
		if err != nil {
			return nil, err
		}
		res.CredentialsRevoked = n
	}
	return res, nil
}

// reconcileSupport ends or stales this partition's SUPPORT, never the object:
// another connector may still support it.
func reconcileSupport(tx *gorm.DB, p Pass, part Partition, closing bool) (int, error) {
	col := models.SupportColumn(part.Class)
	if col == "" {
		return 0, fmt.Errorf("no support column for node class %q", part.Class)
	}
	q := tx.Table("iga_object_support").
		Where("workspace_id = ? AND connector_id = ? AND partition_key = ?", p.WorkspaceID, p.ConnectorID, part.Key()).
		Where(col+" IS NOT NULL").
		Where("state <> ?", models.RelEnded).
		// IS DISTINCT FROM, never <>: last_confirmed_run_id is nullable, and
		// NULL <> uuid is NULL, which would leave such a row current forever.
		Where("last_confirmed_run_id IS DISTINCT FROM ?", p.RunID)
	if !closing {
		r := q.Where("state = ?", models.RelCurrent).Update("state", models.RelStale)
		return int(r.RowsAffected), r.Error
	}
	r := q.Updates(map[string]interface{}{"state": models.RelEnded, "ended_reason": models.EndedNotSeen})
	return int(r.RowsAffected), r.Error
}

// reconcileEdges ends or stales the partition's edges this pass did not
// reconfirm. An edge is one connector's fact, so absence from the partition
// that owns it is conclusive on its own -- when the partition may close.
func reconcileEdges(tx *gorm.DB, p Pass, table string, part Partition, closing bool, at time.Time) (int, error) {
	q := tx.Table(table).
		Where("workspace_id = ? AND connector_id = ? AND partition_key = ?", p.WorkspaceID, p.ConnectorID, part.Key()).
		Where("state <> ?", models.RelEnded).
		Where("last_confirmed_by IS DISTINCT FROM ?", p.RunID)
	if !closing {
		r := q.Where("state = ?", models.RelCurrent).Update("state", models.RelStale)
		return int(r.RowsAffected), r.Error
	}
	r := q.Updates(map[string]interface{}{
		"state": models.RelEnded, "valid_to": at, "ended_reason": models.EndedNotSeen,
	})
	return int(r.RowsAffected), r.Error
}

// retireUnsupported retires every live Azure node whose support has all ended,
// then ends the edges that depended on it.
//
// EXISTS some support AND NOT EXISTS live support: a node that never had a
// support row (written before support existed, or by a failed write) is left
// alone rather than retired for lacking evidence nobody recorded.
func retireUnsupported(tx *gorm.DB, p Pass, at time.Time) (int, error) {
	total := 0
	for _, t := range []struct {
		table, supportCol string
	}{
		{"iga_identity_accounts", "identity_account_id"},
		{"iga_resources", "resource_id"},
		{"iga_entitlements", "entitlement_id"},
		{"iga_workload", "workload_id"},
	} {
		// TENANT-EXEMPT: bound to the pass's workspace and run on the caller's tenancy.InWorkspace transaction (Azure projection)
		r := tx.Exec(`
			UPDATE `+t.table+` o
			   SET lifecycle = ?, retired_reason = ?, updated_at = ?
			 WHERE o.workspace_id = ? AND o.provider = ? AND o.lifecycle = ?
			   AND EXISTS (SELECT 1 FROM iga_object_support s
			                WHERE s.workspace_id = o.workspace_id AND s.`+t.supportCol+` = o.id)
			   AND NOT EXISTS (SELECT 1 FROM iga_object_support s
			                    WHERE s.workspace_id = o.workspace_id AND s.`+t.supportCol+` = o.id
			                      AND s.state <> ?)`,
			models.IGALifecycleRetired, models.RetiredUnsupported, at,
			p.WorkspaceID, models.ProviderAzure, models.IGALifecycleActive, models.RelEnded)
		if r.Error != nil {
			return total, fmt.Errorf("retire %s: %w", t.table, r.Error)
		}
		total += int(r.RowsAffected)
	}
	return total, cascade(tx, p, at)
}

// cascade ends Azure edges that touch a retired node. Done in SQL over the
// whole retired set, so an edge a failed earlier cascade left current is
// caught too -- an edge left current under a retired node is a path the
// console will happily draw.
func cascade(tx *gorm.DB, p Pass, at time.Time) error {
	retired := func(table string) string {
		// TENANT-EXEMPT: bound to the pass's workspace and run on the caller's tenancy.InWorkspace transaction (Azure projection)
		return `(SELECT id FROM ` + table + ` WHERE workspace_id = ? AND provider = ? AND lifecycle = ?)`
	}
	retArgs := []interface{}{p.WorkspaceID, models.ProviderAzure, models.IGALifecycleRetired}
	end := func(table, where, reason string, extra ...interface{}) error {
		args := []interface{}{models.RelEnded, at, reason, p.WorkspaceID, models.RelEnded}
		args = append(args, extra...)
		// TENANT-EXEMPT: bound to the pass's workspace and run on the caller's tenancy.InWorkspace transaction (Azure projection)
		return tx.Exec(`UPDATE `+table+` SET state = ?, valid_to = ?, ended_reason = ?
			WHERE workspace_id = ? AND state <> ? AND `+where, args...).Error
	}
	edges := []struct {
		where, reason string
	}{
		{"provider = 'azure' AND subject_identity_account_id IN " + retired("iga_identity_accounts"), models.EndedSubjectRetired},
		{"provider = 'azure' AND entitlement_id IN " + retired("iga_entitlements"), models.EndedStatementRetired},
		{"provider = 'azure' AND resource_id IN " + retired("iga_resources"), "resource_retired"},
	}
	for _, e := range edges {
		if err := end("iga_access_edges", e.where, e.reason, retArgs...); err != nil {
			return fmt.Errorf("cascade access edges: %w", err)
		}
	}
	// iga_relationship has no provider column: Azure's are told apart by the
	// key prefix every Azure key carries.
	relArgs := append([]interface{}{models.ProviderAzure + Sep + "%"}, retArgs...)
	for _, where := range []string{
		"source_key LIKE ? AND source_identity_account_id IN " + retired("iga_identity_accounts"),
		"source_key LIKE ? AND target_identity_account_id IN " + retired("iga_identity_accounts"),
		"source_key LIKE ? AND source_workload_id IN " + retired("iga_workload"),
	} {
		if err := end("iga_relationship", where, models.EndedSubjectRetired, relArgs...); err != nil {
			return fmt.Errorf("cascade relationships: %w", err)
		}
	}
	return nil
}

// revokeCredentials marks secrets and certificates this tenant's directory no
// longer lists as revoked -- only when the pass read every app registration and
// service principal in full -- and those of retired identities too.
func revokeCredentials(tx *gorm.DB, p Pass, at time.Time) (int, error) {
	total := 0
	if p.Coverage.Status != models.ScanStatusFailed &&
		p.Coverage.Surfaces[models.SurfaceEntraApplications].Authoritative() &&
		p.Coverage.Surfaces[models.SurfaceEntraServicePrincipals].Authoritative() {
		// A blueprint only Agent ID lists keeps its credentials through a
		// pass that could not read Agent ID.
		agentHold := ""
		if !p.agentsRead() {
			// TENANT-EXEMPT: bound to the pass's workspace and run on the caller's tenancy.InWorkspace transaction (Azure projection)
			agentHold = ` AND identity_account_id NOT IN (SELECT id FROM iga_identity_accounts
			                 WHERE workspace_id = iga_credentials.workspace_id AND provider = 'azure'
			                   AND provider_attrs->>'agent_listed' = 'true')`
		}
		// TENANT-EXEMPT: bound to the pass's workspace and run on the caller's tenancy.InWorkspace transaction (Azure projection)
		r := tx.Exec(`UPDATE iga_credentials SET lifecycle = 'revoked', retired_reason = ?, updated_at = ?
			WHERE workspace_id = ? AND provider = ? AND source_key LIKE ?
			  AND lifecycle IN ('active', 'expired') AND last_seen_at < ?`+agentHold,
			models.EndedNotSeen, at, p.WorkspaceID, models.ProviderAzure,
			TenantPrefix(p.TenantID)+"credential"+Sep+"%", at)
		if r.Error != nil {
			return 0, fmt.Errorf("revoke unseen credentials: %w", r.Error)
		}
		total += int(r.RowsAffected)
	}
	// TENANT-EXEMPT: bound to the pass's workspace and run on the caller's tenancy.InWorkspace transaction (Azure projection)
	r := tx.Exec(`UPDATE iga_credentials SET lifecycle = 'revoked', retired_reason = ?, updated_at = ?
		WHERE workspace_id = ? AND provider = ? AND lifecycle IN ('active', 'expired')
		  AND identity_account_id IN (SELECT id FROM iga_identity_accounts
		                               WHERE workspace_id = ? AND provider = ? AND lifecycle = ?)`,
		models.EndedSubjectRetired, at, p.WorkspaceID, models.ProviderAzure,
		p.WorkspaceID, models.ProviderAzure, models.IGALifecycleRetired)
	if r.Error != nil {
		return total, fmt.Errorf("revoke credentials of retired identities: %w", r.Error)
	}
	return total + int(r.RowsAffected), nil
}
