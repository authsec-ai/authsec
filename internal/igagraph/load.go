package igagraph

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
)

// ErrSuperseded means a newer scan has already advanced the connector past
// this job's generation. The newer run's job will do the work with better
// data, so this job ABANDONS -- recorded, never silent.
var ErrSuperseded = errors.New("igagraph: snapshot superseded by a newer generation")

// Load reads one published run's collected state (§4.5).
//
// ONE REPEATABLE-READ, READ-ONLY SNAPSHOT, and rows AT THIS RUN'S GENERATION
// for THIS connector. Every table read is written per connector (cloud_policy
// and its attachments are keyed by connector), so no other account's scan can
// move a row out of this set. The superseded check runs inside the same
// snapshot, because a check before the read is stale by the time it runs.
//
// Isolation is necessary and not sufficient: a scan in flight writes rows at
// generation N+1 before the connector's scan_generation moves, so a row can be
// gone before the snapshot opens. The guarantee is §2.10A's workspace barrier.
func Load(ctx context.Context, db *gorm.DB, runID uuid.UUID) (*Snapshot, error) {
	tx := db.WithContext(ctx).Begin(&sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer func() { _ = tx.Rollback() }()

	var run models.CloudScanRun
	if err := tx.First(&run, "id = ?", runID).Error; err != nil {
		return nil, fmt.Errorf("load scan run: %w", err)
	}
	var conn models.CloudConnector
	if err := tx.First(&conn, "workspace_id = ? AND id = ?", run.WorkspaceID, run.ConnectorID).Error; err != nil {
		return nil, fmt.Errorf("load connector: %w", err)
	}
	snap := &Snapshot{Run: run, Connector: conn, Generation: run.Generation}

	at := func(dst any) error {
		return tx.Where("workspace_id = ? AND connector_id = ? AND last_seen_generation = ?",
			run.WorkspaceID, run.ConnectorID, run.Generation).Find(dst).Error
	}
	for name, dst := range map[string]any{
		"identities": &snap.Identities, "memberships": &snap.Memberships,
		"policies": &snap.Policies, "attachments": &snap.Attachments,
		"workloads": &snap.Workloads, "secrets": &snap.Secrets,
	} {
		if err := at(dst); err != nil {
			return nil, fmt.Errorf("load %s: %w", name, err)
		}
	}

	// EKS pod-identity associations, and NO other cloud_assume_edge row: trust
	// is read from the roles' own documents (§4.5).
	if err := tx.Where("workspace_id = ? AND connector_id = ? AND last_seen_generation = ? AND mechanism = ?",
		run.WorkspaceID, run.ConnectorID, run.Generation, models.MechanismEKSPodIdentity).
		Find(&snap.PodIdentity).Error; err != nil {
		return nil, fmt.Errorf("load pod identity: %w", err)
	}

	snap.Coverage = models.DecodeScanCoverage(run.Coverage).Surfaces
	if snap.Coverage == nil {
		snap.Coverage = map[string]models.SurfaceCoverage{}
	}
	snap.UnreadablePolicy = map[uuid.UUID]bool{}
	for _, p := range snap.Policies {
		if p.Unreadable() {
			snap.UnreadablePolicy[p.ID] = true
		}
	}
	snap.UnreadableTrust = unreadableTrust(snap.Identities)

	// Which observations THIS run confirmed (024, D4).
	var obs []models.CloudObservation
	if err := tx.Select("id", "subject_native_id", "identity_id", "permission_id",
		"resource_id", "workload_id", "policy_id").
		Where("workspace_id = ? AND last_confirmed_run_id = ?", run.WorkspaceID, run.ID).
		Find(&obs).Error; err != nil {
		return nil, fmt.Errorf("load confirmed observations: %w", err)
	}
	snap.ConfirmedBy = indexObservations(obs)

	// Native ids of identities this run's WORKLOADS reference, REGARDLESS OF
	// GENERATION -- how not_in_scan still names the role.
	snap.index()
	var refs []uuid.UUID
	for _, w := range snap.Workloads {
		if w.IdentityID != nil && snap.IdentityNativeID(*w.IdentityID) == "" {
			refs = append(refs, *w.IdentityID)
		}
	}
	if len(refs) > 0 {
		var rows []models.CloudIdentity
		if err := tx.Select("id", "native_id").
			Where("workspace_id = ? AND id IN ?", run.WorkspaceID, refs).
			Find(&rows).Error; err != nil {
			return nil, fmt.Errorf("load referenced identities: %w", err)
		}
		for _, ci := range rows {
			snap.SetReferencedIdentity(ci.ID, ci.NativeID)
		}
	}

	// Every AWS account connected in this workspace: a resource reference in
	// any other account is an EXTERNAL reference (§1.4), and a trust principal
	// in any other account never resolves to an identity (§4.7). Connected
	// means a connector exists and is not revoked -- the read side's rule
	// (D-3, D-61).
	var accounts []string
	if err := tx.Model(&models.CloudConnector{}).
		Where("workspace_id = ? AND provider = ? AND status <> ?",
			run.WorkspaceID, models.CloudProviderAWS, models.CloudConnectorRevoked).
		Pluck("scope_id", &accounts).Error; err != nil {
		return nil, fmt.Errorf("load connected accounts: %w", err)
	}
	snap.ConnectedAccounts = make(map[string]bool, len(accounts))
	for _, a := range accounts {
		snap.ConnectedAccounts[a] = true
	}

	// SUPERSEDED, decided inside this snapshot.
	var fresh models.CloudConnector
	if err := tx.First(&fresh, "id = ?", run.ConnectorID).Error; err != nil {
		return nil, fmt.Errorf("re-read connector: %w", err)
	}
	if fresh.ScanGeneration > run.Generation {
		return nil, ErrSuperseded
	}
	return snap, tx.Commit().Error
}

// unreadableTrust names the roles whose trust document this run could not
// read: the collector recorded a parse error, or recorded no document at all.
// The second is D-45's rule, and it matters: a role with no document and no
// error would otherwise read as "trusts nobody", and every trust edge it had
// would END -- ending what we never read. No cloud_* CHECK pairs the two
// columns the way cloud_policy_readable_chk does for policies.
func unreadableTrust(identities []models.CloudIdentity) map[uuid.UUID]bool {
	out := map[uuid.UUID]bool{}
	for _, ci := range identities {
		if ci.Kind != models.CloudIdentityIAMRole {
			continue
		}
		doc := strings.TrimSpace(string(ci.TrustDocument))
		if ci.TrustParseError != "" || doc == "" || doc == "null" {
			out[ci.ID] = true
		}
	}
	return out
}

// indexObservations groups confirmed observation ids by typed subject and
// subject_native_id. A subject whose FK was SET NULL by inventory churn is
// still history, never evidence for a specific edge.
func indexObservations(obs []models.CloudObservation) map[SubjectRef][]uuid.UUID {
	out := make(map[SubjectRef][]uuid.UUID, len(obs))
	for _, o := range obs {
		kind, _ := o.Subject()
		switch kind {
		case "identity", "policy", "workload":
		default:
			continue // permission observations are Cloud Inventory's (§1.5)
		}
		ref := SubjectRef{Kind: kind, NativeID: o.SubjectNativeID}
		out[ref] = append(out[ref], o.ID)
	}
	return out
}

// existing holds the workspace's live graph, prefetched ONCE before the
// projection transaction, so the projection does zero per-row SELECTs (§4.5).
//
// Two maps per type, because there are two questions:
//
//	live    -- lifecycle <> 'retired', keyed by source_key. Exactly what an
//	           upsert can hit (it matches the partial unique index).
//	retired -- lifecycle = 'retired' AND retired_reason = 'unsupported', keyed
//	           by (source_key, immutable_key). Candidates for RESTORATION.
//
// Retired-as-RECREATED rows are deliberately NOT candidates: restoring one
// would carry the old history onto a different principal wearing the name.
type existing struct {
	identity    map[string]*models.IGAIdentityAccount
	workload    map[string]*models.IGAWorkload
	resource    map[string]*models.IGAResource
	policy      map[string]*models.IGAPolicy
	entitlement map[string]*models.IGAEntitlement
	credential  map[string]*models.IGACredential

	retiredIdentity    map[string]*models.IGAIdentityAccount
	retiredPolicy      map[string]*models.IGAPolicy
	retiredEntitlement map[string]*models.IGAEntitlement
}

// retiredKey is the restoration lookup: (source_key, immutable_key). Both,
// because the recognition key alone would restore a RECREATED object.
func retiredKey(sourceKey, immutableKey string) string {
	return sourceKey + Sep + immutableKey
}

// LoadExisting reads the workspace's AWS graph objects once. Only rows this
// projector owns (provider = 'aws'): GitHub's rows share these tables and are
// never matched, updated or retired by it.
func LoadExisting(ctx context.Context, db *gorm.DB, ws uuid.UUID) (*existing, error) {
	ex := &existing{
		identity:           map[string]*models.IGAIdentityAccount{},
		workload:           map[string]*models.IGAWorkload{},
		resource:           map[string]*models.IGAResource{},
		policy:             map[string]*models.IGAPolicy{},
		entitlement:        map[string]*models.IGAEntitlement{},
		credential:         map[string]*models.IGACredential{},
		retiredIdentity:    map[string]*models.IGAIdentityAccount{},
		retiredPolicy:      map[string]*models.IGAPolicy{},
		retiredEntitlement: map[string]*models.IGAEntitlement{},
	}
	d := db.WithContext(ctx)
	live := "workspace_id = ? AND provider = 'aws' AND source_key <> '' AND lifecycle <> 'retired'"
	retired := `workspace_id = ? AND provider = 'aws' AND lifecycle = 'retired' AND retired_reason = ?
	            AND source_key <> '' AND immutable_key <> ''`

	var ids []models.IGAIdentityAccount
	if err := d.Where(live, ws).Find(&ids).Error; err != nil {
		return nil, err
	}
	for i := range ids {
		ex.identity[ids[i].SourceKey] = &ids[i]
	}
	var rids []models.IGAIdentityAccount
	if err := d.Where(retired, ws, models.RetiredUnsupported).Find(&rids).Error; err != nil {
		return nil, err
	}
	for i := range rids {
		ex.retiredIdentity[retiredKey(rids[i].SourceKey, rids[i].ImmutableKey)] = &rids[i]
	}

	var wls []models.IGAWorkload
	if err := d.Where("workspace_id = ? AND provider = 'aws' AND lifecycle <> 'retired'", ws).
		Find(&wls).Error; err != nil {
		return nil, err
	}
	for i := range wls {
		ex.workload[wls[i].SourceKey] = &wls[i]
	}

	var res []models.IGAResource
	if err := d.Where(live, ws).Find(&res).Error; err != nil {
		return nil, err
	}
	for i := range res {
		ex.resource[res[i].SourceKey] = &res[i]
	}

	var pols []models.IGAPolicy
	if err := d.Where("workspace_id = ? AND provider = 'aws' AND lifecycle <> 'retired'", ws).
		Find(&pols).Error; err != nil {
		return nil, err
	}
	for i := range pols {
		ex.policy[pols[i].SourceKey] = &pols[i]
	}
	var rpols []models.IGAPolicy
	if err := d.Where(retired, ws, models.RetiredUnsupported).Find(&rpols).Error; err != nil {
		return nil, err
	}
	for i := range rpols {
		ex.retiredPolicy[retiredKey(rpols[i].SourceKey, rpols[i].ImmutableKey)] = &rpols[i]
	}

	var ents []models.IGAEntitlement
	if err := d.Where(live, ws).Find(&ents).Error; err != nil {
		return nil, err
	}
	for i := range ents {
		ex.entitlement[ents[i].SourceKey] = &ents[i]
	}
	var rents []models.IGAEntitlement
	if err := d.Where(retired, ws, models.RetiredUnsupported).Find(&rents).Error; err != nil {
		return nil, err
	}
	for i := range rents {
		ex.retiredEntitlement[retiredKey(rents[i].SourceKey, rents[i].ImmutableKey)] = &rents[i]
	}

	// Credentials: "gone" is revoked/expired, not retired -- matching
	// uq_iga_credentials_source_key exactly.
	var creds []models.IGACredential
	if err := d.Where("workspace_id = ? AND provider = 'aws' AND source_key <> '' AND lifecycle NOT IN ('revoked','expired')", ws).
		Find(&creds).Error; err != nil {
		return nil, err
	}
	for i := range creds {
		ex.credential[creds[i].SourceKey] = &creds[i]
	}
	return ex, nil
}

// projectedStatement is one statement written this pass, for the grant pass.
type projectedStatement struct {
	ID     uuid.UUID
	Key    string
	Effect string // "allow" | "deny", lowercase
}

// resolved maps collected rows to the graph objects they projected to, so
// edges resolve endpoints without a query. Nodes are projected BEFORE edges,
// so by the time an edge is written both endpoints are in here.
type resolved struct {
	identity   map[uuid.UUID]uuid.UUID            // cloud_identity.id -> iga_identity_accounts.id
	workload   map[uuid.UUID]uuid.UUID            // cloud_workload.id -> iga_workload.id
	policy     map[uuid.UUID]uuid.UUID            // cloud_policy.id -> iga_policy.id
	incarnKey  map[uuid.UUID]string               // cloud_policy.id -> its incarnation key
	statements map[uuid.UUID][]projectedStatement // cloud_policy.id -> its statements
	resource   map[string]uuid.UUID               // resource source_key -> iga_resources.id
	assignment map[uuid.UUID]uuid.UUID            // cloud_policy_attachment.id -> iga_policy_assignment.id
	assignKey  map[uuid.UUID]string               // cloud_policy_attachment.id -> assignment key

	// Edges written this pass, retained for attachEvidence. WITHOUT these the
	// evidence pass reads an empty map and silently writes nothing -- a broken
	// pipeline that looks like a working one.
	grants     []grantRef
	executes   []relRef
	memberOf   []relRef
	assignRefs []assignRef
	canAssume  []relRef // trust and pod-identity edges, each with its evidence subject

	// The trust pass's working state (trust.go).
	trustDocs       map[uuid.UUID]*awsdiscovery.TrustDocument // cloud_identity.id -> parsed, once per pass
	external        map[string]uuid.UUID                      // external principal source_key -> id, this pass
	liveExternal    map[string]bool                           // source_key of aws_principal nodes with a live edge, at pass start
	principalByARN  map[string]*models.CloudIdentity          // this snapshot's roles and users, by ARN
	podUnattributed []uuid.UUID                               // roles with a pod association no cluster issuer could be named for

	existing *existing
}

type grantRef struct {
	ID           uuid.UUID
	PolicyNative string // cloud_policy.native_id: the policy version observation's subject
	HolderNative string
}

type relRef struct {
	ID           uuid.UUID
	SubjectKind  string // observation subject kind of the evidence
	SubjectNativ string
}

type assignRef struct {
	ID           uuid.UUID
	PolicyNative string
	HolderNative string
}

func newResolved(ex *existing) *resolved {
	return &resolved{
		identity:   map[uuid.UUID]uuid.UUID{},
		workload:   map[uuid.UUID]uuid.UUID{},
		policy:     map[uuid.UUID]uuid.UUID{},
		incarnKey:  map[uuid.UUID]string{},
		statements: map[uuid.UUID][]projectedStatement{},
		resource:   map[string]uuid.UUID{},
		assignment: map[uuid.UUID]uuid.UUID{},
		assignKey:  map[uuid.UUID]string{},
		trustDocs:  map[uuid.UUID]*awsdiscovery.TrustDocument{},
		external:   map[string]uuid.UUID{},
		existing:   ex,
	}
}
