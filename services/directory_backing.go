package services

import (
	"strings"

	"github.com/authsec-ai/authsec/internal/directory/adresolve"
	igraph "github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/internal/igagraph/providers"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// resolveDirectoryBacking links a Linux account to the AD object an
// authoritative NSS mapping names. It runs after writePlan, in the same
// transaction and the pass's partition. A mapping that cannot be resolved
// does not fail the pass. An authoritative snapshot of the local account or
// group class ends a link whose mapping disappeared. A partial pass, a
// runtime batch, and collector silence do not.
func resolveDirectoryBacking(tx *gorm.DB, in CollectorPass, plan *providers.Plan, ids *idMap) error {
	if plan == nil {
		return nil
	}
	var protected []uuid.UUID
	for _, idn := range plan.Identities {
		if idn.Directory == nil || idn.Provider != models.ProviderLinux {
			continue
		}
		localID := ids.get(models.ObjectIdentity, idn.SourceKey)
		if idn.Directory.Unreadable {
			if localID != uuid.Nil {
				protected = append(protected, localID)
			}
			continue
		}
		ad, reason, err := lookupDirectoryAccount(tx, in.WorkspaceID, idn.Kind, *idn.Directory)
		if err != nil {
			return err
		}
		if reason != "" {
			plan.Unresolved = append(plan.Unresolved, "directory:"+idn.SourceKey+":"+reason)
			if localID != uuid.Nil {
				protected = append(protected, localID)
			}
			continue
		}
		ids.put(models.ObjectIdentity, ad.SourceKey, ad.ID)
		relKey, err := providers.DirectoryRelationKey(idn.SourceKey, ad.SourceKey)
		if err != nil {
			return err
		}
		rel := providers.Relationship{
			SourceKey: relKey, Type: models.RelTypeBackedByDirectory, Basis: models.BasisDerived,
			DerivationRule: adresolve.Rule(idn.Directory.MappingSource),
			FromIdentity:   idn.SourceKey, ToIdentity: ad.SourceKey,
		}
		if err := writeRel(tx, in, collectorPartition(in), rel, ids); err != nil {
			return err
		}
		if err := confirmDirectoryBacking(tx, in, relKey, rel.DerivationRule); err != nil {
			return err
		}
		if err := linkDirectoryEvidence(tx, in, relKey, idn.Directory.ObservationIDs); err != nil {
			return err
		}
	}
	return endAbsentDirectoryBacking(tx, in, plan, protected)
}

type directoryAccount struct {
	ID        uuid.UUID
	SourceKey string
	Kind      string
	State     string
	SID       string
}

func lookupDirectoryAccount(tx *gorm.DB, ws uuid.UUID, localKind string, hint adresolve.Hint) (directoryAccount, string, error) {
	instances, err := loadDirectoryInstances(tx, ws)
	if err != nil {
		return directoryAccount{}, "", err
	}
	inst, err := adresolve.SelectInstance(instances, hint)
	if err != nil {
		return directoryAccount{}, err.Error(), nil
	}
	var rows []directoryAccount
	if hint.GUID != "" {
		key, err := igraph.ADIdentityKey(inst.ForestID, hint.GUID)
		if err != nil {
			return directoryAccount{}, adresolve.ErrUnknownInstance.Error(), nil
		}
		rows, err = findADAccounts(tx, ws, `source_key = ?`, key)
		if err != nil {
			return directoryAccount{}, "", err
		}
	} else {
		prefix := igraph.Key("ad", igraph.EscapeSegment(strings.TrimSpace(inst.ForestID))) + igraph.Sep
		rows, err = findADAccounts(tx, ws,
			`lower(coalesce(provider_attrs->>'object_sid','')) = lower(?) AND left(source_key, char_length(?)) = ?`,
			hint.SID, prefix, prefix)
		if err != nil {
			return directoryAccount{}, "", err
		}
	}
	if len(rows) == 0 {
		return directoryAccount{}, "not_inventoried", nil
	}
	if len(rows) != 1 {
		return directoryAccount{}, adresolve.ErrAmbiguous.Error(), nil
	}
	got := rows[0]
	if hint.SID != "" && got.SID != "" && !strings.EqualFold(got.SID, hint.SID) {
		return directoryAccount{}, "identifier_mismatch", nil
	}
	if !directoryKindOK(localKind, got.Kind) {
		return directoryAccount{}, "kind_mismatch", nil
	}
	return got, "", nil
}

func directoryKindOK(localKind, adKind string) bool {
	switch localKind {
	case models.AccountKindLocalUser:
		return adKind == models.AccountKindADUser
	case models.AccountKindLocalGroup:
		return adKind == models.AccountKindADGroup
	default:
		return false
	}
}

func loadDirectoryInstances(tx *gorm.DB, ws uuid.UUID) ([]adresolve.Instance, error) {
	rows, err := tx.Raw(`SELECT id, forest_id, domain_sid, domain_dn, dns_host_name
		FROM ad_directory_instances WHERE workspace_id = ?`, ws).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []adresolve.Instance
	for rows.Next() {
		var inst adresolve.Instance
		if err := rows.Scan(&inst.ID, &inst.ForestID, &inst.DomainSID, &inst.DomainDN, &inst.DNSHost); err != nil {
			return nil, err
		}
		out = append(out, inst)
	}
	return out, rows.Err()
}

func findADAccounts(tx *gorm.DB, ws uuid.UUID, where string, args ...any) ([]directoryAccount, error) {
	qargs := append([]any{ws}, args...)
	rows, err := tx.Raw(`SELECT id, source_key, account_kind, account_state, coalesce(provider_attrs->>'object_sid','')
		FROM iga_identity_accounts
		WHERE workspace_id = ? AND provider = 'ad' AND lifecycle <> 'retired' AND `+where, qargs...).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []directoryAccount
	for rows.Next() {
		var row directoryAccount
		if err := rows.Scan(&row.ID, &row.SourceKey, &row.Kind, &row.State, &row.SID); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func confirmDirectoryBacking(tx *gorm.DB, in CollectorPass, sourceKey, rule string) error {
	return tx.Exec(`UPDATE iga_relationship
		SET basis = 'derived', derivation_rule = ?, confirming_iga_scan_run_id = ?, last_confirmed_at = ?
		WHERE workspace_id = ? AND source_key = ? AND state <> 'ended'`,
		rule, in.ScanRunID, in.At, in.WorkspaceID, sourceKey).Error
}

func linkDirectoryEvidence(tx *gorm.DB, in CollectorPass, sourceKey string, observations []uuid.UUID) error {
	relID, err := scanUUID(tx, `SELECT id FROM iga_relationship
		WHERE workspace_id = ? AND source_key = ? AND state <> 'ended' LIMIT 1`, in.WorkspaceID, sourceKey)
	if err != nil || relID == uuid.Nil {
		return err
	}
	seen := map[uuid.UUID]bool{}
	for _, obs := range observations {
		if obs == uuid.Nil || seen[obs] {
			continue
		}
		seen[obs] = true
		if err := in.Repo.LinkRelationshipCollectorEvidence(tx, in.WorkspaceID, relID, obs, "supports"); err != nil {
			return err
		}
	}
	return nil
}

// endAbsentDirectoryBacking ends backed_by_directory edges in this pass's
// partition that this authoritative snapshot did not confirm. A local account
// whose mapping is still present but unresolved keeps its previous link.
// Collector silence never reaches this function. A non-authoritative pass
// returns before the update.
func endAbsentDirectoryBacking(tx *gorm.DB, in CollectorPass, plan *providers.Plan, protected []uuid.UUID) error {
	if in.ObjectClass != "linux.local_account" && in.ObjectClass != "linux.local_group" {
		return nil
	}
	if _, ok := igraph.MayEndSnapshotSupport(in.Authoritative, in.ObjectClass); !ok {
		return nil
	}
	if skippedPassClass(plan, in.ObjectClass) {
		return nil
	}
	q := tx.Table("iga_relationship").
		Where(`workspace_id = ? AND integration_id = ? AND partition_key = ? AND relationship_type = ? AND state <> 'ended'
			AND confirming_iga_scan_run_id IS DISTINCT FROM ?`,
			in.WorkspaceID, in.IntegrationID, collectorPartition(in), models.RelTypeBackedByDirectory, in.ScanRunID)
	if len(protected) > 0 {
		q = q.Where("source_identity_account_id NOT IN ?", protected)
	}
	return q.Updates(map[string]any{
		"state": "ended", "ended_reason": models.EndedNotSeen, "valid_to": in.At,
	}).Error
}
