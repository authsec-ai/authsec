package igagraph

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

// ErrObsoleteGeneration means a newer projection already advanced this
// partition's watermark. Not an error an operator must act on: the newer job
// did the work with better data. Recorded and skipped.
var ErrObsoleteGeneration = errors.New("igagraph: generation already projected")

// GraphWriter is the subset of the graph repository the projector uses.
//
// Declared here rather than imported so the projection logic can be driven by
// a fake in tests -- the hard decisions (key collisions, recreate detection,
// the ended-vs-stale call) are worth testing without a database.
type GraphWriter interface {
	UpsertEstateScope(tx *gorm.DB, s *models.IGAEstateScope) (uuid.UUID, error)
	UpsertIdentity(tx *gorm.DB, a *models.IGAIdentityAccount) (uuid.UUID, error)
	UpsertWorkload(tx *gorm.DB, w *models.IGAWorkload) (uuid.UUID, error)
	UpsertResource(tx *gorm.DB, r *models.IGAResource) (uuid.UUID, error)
	UpsertEntitlement(tx *gorm.DB, e *models.IGAEntitlement) (uuid.UUID, error)
	UpsertAgent(tx *gorm.DB, a *models.IGAAgent) (uuid.UUID, error)
	UpsertAgentInstance(tx *gorm.DB, i *models.IGAAgentInstance) (uuid.UUID, error)
	UpsertCredential(tx *gorm.DB, c *models.IGACredential) (uuid.UUID, error)
	UpsertAccessEdge(tx *gorm.DB, e *models.IGAAccessEdge) (uuid.UUID, error)
	UpsertRelationship(tx *gorm.DB, r *models.IGARelationship) (uuid.UUID, error)
	UpsertObjectSupport(tx *gorm.DB, s *models.IGAObjectSupport) error
	UpsertProjectionState(tx *gorm.DB, s *models.IGAProjectionState) error
	LinkAccessEdgeEvidence(tx *gorm.DB, ws, edgeID, obsID uuid.UUID, relation string) error
	LinkRelationshipEvidence(tx *gorm.DB, ws, relID, obsID uuid.UUID, relation string) error
	RetireIdentity(tx *gorm.DB, ws, id uuid.UUID, reason string, now time.Time) error
	EndEdgesOnSubject(tx *gorm.DB, ws, identityID uuid.UUID, reason string, now time.Time, runID uuid.UUID) error
}

// Fencer proves, inside the projection transaction, that this worker still
// owns both the job and the workspace's pipeline.
//
// Checking ownership BEFORE the transaction proves nothing: the lease can be
// lost while writes are in flight, and a Complete() rejected afterwards cannot
// un-commit a graph mutation.
type Fencer interface {
	// AssertOwnedTx locks this job's row and asserts the caller still holds
	// the claimed lease version. The row stays locked for the transaction's
	// life, so a reclaiming worker blocks rather than writing concurrently.
	AssertOwnedTx(tx *gorm.DB, jobID uuid.UUID, owner string, leaseVersion int64) error
	// AssertProjectingTx asserts this job still holds the workspace's
	// projecting state, so a reclaimed pipeline cannot have its old job commit.
	AssertProjectingTx(tx *gorm.DB, ws uuid.UUID, version int64) error
}

// Projector turns one published run's Snapshot into graph writes.
type Projector struct {
	repo     GraphWriter
	fencer   Fencer
	existing *existing

	jobID           uuid.UUID
	owner           string
	leaseVersion    int64
	pipelineVersion int64

	// now is injectable so tests can assert first_seen_at is not advanced.
	now func() time.Time

	// Reconciler is consulted for the watermark comparison before any write.
	watermark func(tx *gorm.DB, part Partition, ws uuid.UUID) (int64, error)
}

// NewProjector wires a projector for one claimed job.
func NewProjector(
	repo GraphWriter, fencer Fencer, ex *existing,
	jobID uuid.UUID, owner string, leaseVersion, pipelineVersion int64,
	now func() time.Time,
	watermark func(tx *gorm.DB, part Partition, ws uuid.UUID) (int64, error),
) *Projector {
	if now == nil {
		now = time.Now
	}
	return &Projector{
		repo: repo, fencer: fencer, existing: ex,
		jobID: jobID, owner: owner,
		leaseVersion: leaseVersion, pipelineVersion: pipelineVersion,
		now: now, watermark: watermark,
	}
}

// Project writes one run's nodes, edges and evidence.
//
// It takes a *gorm.DB it MUST NOT commit: Project and Reconcile are the two
// halves of one transaction, and committing between them would publish a graph
// in which nothing has been closed yet -- every stale edge still reading
// `current` -- with a crash leaving it that way until the next run.
func (p *Projector) Project(tx *gorm.DB, snap *Snapshot) error {
	// FENCE FIRST, INSIDE THE TRANSACTION.
	if err := p.fencer.AssertOwnedTx(tx, p.jobID, p.owner, p.leaseVersion); err != nil {
		return err // ErrLeaseLost -> rollback, write nothing
	}

	// ORDERED PUBLICATION, separate from job ownership.
	//
	// AssertOwnedTx protects THIS job's row. It does NOT order two DIFFERENT
	// jobs: generation 7 and generation 8 hold different job rows, both
	// legitimately own their leases, and nothing stops 7 from committing after
	// 8 and overwriting the newer graph with an older one.
	//
	// The workspace barrier already excludes concurrent COLLECTION; this
	// asserts this job still holds the projecting state.
	if err := p.fencer.AssertProjectingTx(tx, snap.Run.WorkspaceID, p.pipelineVersion); err != nil {
		return err
	}

	parts := Partitions(snap)

	// Assert the partition vocabulary before anything is written. A partition
	// naming a surface no report can contain never satisfies canEnd, so its
	// relationships stay stale FOREVER -- silent, and it looks like working
	// caution.
	if bad := AssertPartitionVocabulary(parts, snap.RegionsAttempted()); len(bad) > 0 {
		return fmt.Errorf("igagraph: partitions name unknown surfaces %v", bad)
	}

	for _, part := range parts {
		have, err := p.watermark(tx, part, snap.Run.WorkspaceID)
		if err != nil {
			return err
		}
		if int64(snap.Generation) <= have {
			return ErrObsoleteGeneration
		}
	}

	r := newResolved(p.existing)

	// The estate scope FIRST: every canonical node references it, and nothing
	// else in the tree populates iga_estate_scopes.
	if err := p.projectEstateScope(tx, snap); err != nil {
		return err
	}

	// Nodes, in dependency order. Each populates `r` so later passes resolve
	// endpoints without a query.
	if err := p.projectIdentities(tx, snap, r); err != nil {
		return err
	}
	if err := p.projectResources(tx, snap, r); err != nil {
		return err
	}
	if err := p.projectWorkloads(tx, snap, r); err != nil {
		return err
	}
	if err := p.projectEntitlements(tx, snap, r); err != nil {
		return err
	}
	if err := p.projectCredentials(tx, snap, r); err != nil {
		return err
	}
	if err := p.projectAgents(tx, snap, r); err != nil {
		return err
	}

	// Edges. Every endpoint is in `r` by now.
	if err := p.projectAccessEdges(tx, snap, r); err != nil {
		return err
	}
	if err := p.projectRelationships(tx, snap, r); err != nil {
		return err
	}

	if err := p.attachEvidence(tx, snap, r); err != nil {
		return err
	}
	// reconciled=false here; Reconcile flips it in the same transaction.
	return p.recordState(tx, snap, false)
}

func (p *Projector) projectEstateScope(tx *gorm.DB, snap *Snapshot) error {
	key := ScopeKey(snap.Connector.Provider, snap.Connector.ScopeKind, snap.Connector.ScopeID)
	id, err := p.repo.UpsertEstateScope(tx, &models.IGAEstateScope{
		WorkspaceID: snap.Run.WorkspaceID,
		SourceKey:   key,
		ScopeKind:   snap.Connector.ScopeKind,
		DisplayName: snap.Connector.ScopeID,
		Stage:       "unknown",
	})
	if err != nil {
		return fmt.Errorf("upsert estate scope %s: %w", key, err)
	}
	snap.ScopeID = id
	return nil
}

// support records that this connector, in this partition, still vouches for a
// node. THE STEP THAT MAKES A NODE VISIBLE TO RECONCILIATION.
func (p *Projector) support(tx *gorm.DB, snap *Snapshot, objectType string, objectID uuid.UUID, part Partition) error {
	now := p.now()
	return p.repo.UpsertObjectSupport(tx, &models.IGAObjectSupport{
		WorkspaceID:        snap.Run.WorkspaceID,
		ObjectType:         objectType,
		ObjectID:           objectID,
		ConnectorID:        snap.Run.ConnectorID,
		PartitionKey:       part.Key(),
		State:              models.RelCurrent,
		LastConfirmedRunID: &snap.Run.ID,
		LastConfirmedAt:    &now,
	})
}

// identityPartition routes a role to the iam_roles partition and a user to
// iam_users. Merged, a denied iam_users read would block role reconciliation.
func identityPartition(snap *Snapshot, kind string) Partition {
	surface := models.SurfaceIAMRoles
	if kind == models.CloudIdentityIAMUser {
		surface = models.SurfaceIAMUsers
	}
	return Partition{
		ScopeID: snap.ScopeID, ConnectorID: snap.Run.ConnectorID,
		Class: models.ObjectIdentity, RequiredSurfaces: []string{surface},
	}
}

// workloadService maps a runtime kind to the coverage surface prefix the
// scanner reports it under.
//
// The names here are the SCANNER'S, not ours: lambda, ecs, ec2,
// bedrock-agents, bedrock-agentcore. A mismatch means the partition can never
// satisfy canEnd and its workloads stay stale forever.
func workloadService(runtimeKind string) string {
	switch runtimeKind {
	case models.WorkloadLambdaFunction:
		return "lambda"
	case models.WorkloadECSTaskDefinition:
		return "ecs"
	case models.WorkloadEC2Instance:
		return "ec2"
	case models.WorkloadBedrockAgent:
		return "bedrock-agents"
	case models.WorkloadBedrockAgentCoreRT, models.WorkloadBedrockAgentCoreGW:
		return "bedrock-agentcore"
	}
	return ""
}

func workloadPartition(snap *Snapshot, w models.CloudWorkload) Partition {
	svc := workloadService(w.RuntimeKind)
	return Partition{
		ScopeID: snap.ScopeID, ConnectorID: snap.Run.ConnectorID,
		Class:            models.ObjectWorkload,
		RequiredSurfaces: []string{svc + ":" + w.Region},
		RequiredScanners: []string{models.SurfaceWorkloadScan, models.SurfaceCompute(w.Region)},
	}
}

func executesAsPartition(snap *Snapshot, w models.CloudWorkload) Partition {
	svc := workloadService(w.RuntimeKind)
	return Partition{
		ScopeID: snap.ScopeID, ConnectorID: snap.Run.ConnectorID,
		RelationshipType: models.RelTypeExecutesAs, Target: "relationship",
		RequiredSurfaces: []string{svc + ":" + w.Region, models.SurfaceIAMRoles},
		RequiredScanners: []string{models.SurfaceWorkloadScan, models.SurfaceCompute(w.Region)},
	}
}

func realizesPartition(snap *Snapshot, w models.CloudWorkload) Partition {
	svc := workloadService(w.RuntimeKind)
	return Partition{
		ScopeID: snap.ScopeID, ConnectorID: snap.Run.ConnectorID,
		RelationshipType: models.RelTypeRealizes, Target: "relationship",
		RequiredSurfaces: []string{svc + ":" + w.Region},
		RequiredScanners: []string{models.SurfaceWorkloadScan, models.SurfaceCompute(w.Region)},
	}
}

func entitlementPartition(snap *Snapshot) Partition {
	return Partition{
		ScopeID: snap.ScopeID, ConnectorID: snap.Run.ConnectorID,
		Class: models.ObjectEntitlement,
		RequiredSurfaces: []string{
			models.SurfaceIAMRoles, models.SurfaceIAMPolicies, models.SurfacePolicyDocuments},
		RequiredScanners: []string{models.SurfacePermissionScan},
	}
}

func resourcePartition(snap *Snapshot) Partition {
	return Partition{
		ScopeID: snap.ScopeID, ConnectorID: snap.Run.ConnectorID,
		Class: models.ObjectResource,
		RequiredSurfaces: []string{
			models.SurfaceIAMRoles, models.SurfaceIAMPolicies, models.SurfacePolicyDocuments},
		RequiredScanners: []string{models.SurfacePermissionScan},
	}
}

func accessEdgePartition(snap *Snapshot) Partition {
	return Partition{
		ScopeID: snap.ScopeID, ConnectorID: snap.Run.ConnectorID,
		Target: "access_edge",
		RequiredSurfaces: []string{
			models.SurfaceIAMRoles, models.SurfaceIAMPolicies, models.SurfacePolicyDocuments},
		RequiredScanners: []string{models.SurfacePermissionScan},
	}
}

func canAssumePartition(snap *Snapshot) Partition {
	return Partition{
		ScopeID: snap.ScopeID, ConnectorID: snap.Run.ConnectorID,
		RelationshipType: models.RelTypeCanAssume, Target: "relationship",
		RequiredSurfaces: []string{models.SurfaceIAMRoles, models.SurfacePolicyDocuments},
		RequiredScanners: []string{models.SurfacePermissionScan},
	}
}

func (p *Projector) projectIdentities(tx *gorm.DB, snap *Snapshot, r *resolved) error {
	now := p.now()
	for _, ci := range snap.Identities {
		key := IdentityKey(ci)
		cont := Continuity(ci.Kind)
		imm := ImmutableKey(ci)

		// Map lookup, not a query. The workspace's live objects were loaded
		// once before the transaction; a SELECT per identity here is one round
		// trip per row, inside a transaction holding locks.
		prev := r.existing.identity[key]

		// DELETE-AND-RECREATE. Same recognition key, different creation
		// boundary => a different principal wearing the old name. Carrying the
		// old row forward would carry last quarter's review decisions onto a
		// stranger.
		//
		// BOTH immutable keys must be non-empty: one empty side means we could
		// not tell, and "could not tell" is NEVER "recreated".
		if prev != nil && cont == ContinuityImmutable &&
			imm != "" && prev.ImmutableKey != "" && prev.ImmutableKey != imm {

			if err := p.repo.RetireIdentity(tx, snap.Run.WorkspaceID, prev.ID,
				models.RetiredRecreated, now); err != nil {
				return err
			}
			if err := p.repo.EndEdgesOnSubject(tx, snap.Run.WorkspaceID, prev.ID,
				models.EndedSubjectRecreate, now, snap.Run.ID); err != nil {
				return err
			}
			prev = nil // fall through to INSERT, with a fresh first_seen_at
		}

		row := &models.IGAIdentityAccount{
			WorkspaceID:     snap.Run.WorkspaceID,
			EstateScopeID:   &snap.ScopeID,
			SourceKey:       key,
			Continuity:      cont,
			ImmutableKey:    imm,
			DisplayName:     ci.Name,
			AccountKind:     ci.Kind,
			IdentityBacking: "provider_native",
			Lifecycle:       models.IGALifecycleActive,
			RollupState:     models.RollupConfirmed,
			LastSeenAt:      now,
		}
		if prev == nil {
			row.FirstSeenAt = now
		} else {
			// Carried, not advanced. DoUpdates never names first_seen_at, but
			// sending the old value keeps an INSERT-that-conflicts honest too.
			row.FirstSeenAt = prev.FirstSeenAt
		}

		id, err := p.repo.UpsertIdentity(tx, row)
		if err != nil {
			return fmt.Errorf("upsert identity %s: %w", key, err)
		}
		r.identity[ci.ID] = id
		r.identityKey[id] = key
		r.identityImmutable[id] = imm

		if err := p.support(tx, snap, models.ObjectIdentity, id,
			identityPartition(snap, ci.Kind)); err != nil {
			return err
		}
	}
	return nil
}

func (p *Projector) projectResources(tx *gorm.DB, snap *Snapshot, r *resolved) error {
	now := p.now()
	part := resourcePartition(snap)
	for _, cr := range snap.Resources {
		key := ResourceKey(cr)
		prev := r.existing.resource[key]

		row := &models.IGAResource{
			WorkspaceID:   snap.Run.WorkspaceID,
			EstateScopeID: &snap.ScopeID,
			SourceKey:     key,
			// A selector is not proof the resource exists (roadmap §3.1), and
			// Phase 2 does not enumerate. ResourceKind carries what the ARN
			// claims; existence is Phase 3's problem.
			ResourceKind: cr.Kind,
			DisplayName:  cr.Name,
			Continuity:   Continuity(cr.Kind),
			Stage:        "unknown",
			Lifecycle:    models.IGALifecycleActive,
			LastSeenAt:   now,
		}
		if prev == nil {
			row.FirstSeenAt = now
		} else {
			row.FirstSeenAt = prev.FirstSeenAt
		}

		id, err := p.repo.UpsertResource(tx, row)
		if err != nil {
			return fmt.Errorf("upsert resource %s: %w", key, err)
		}
		r.resource[cr.ID] = id
		r.resourceKey[id] = key

		if err := p.support(tx, snap, models.ObjectResource, id, part); err != nil {
			return err
		}
	}
	return nil
}

func (p *Projector) projectWorkloads(tx *gorm.DB, snap *Snapshot, r *resolved) error {
	now := p.now()
	for _, cw := range snap.Workloads {
		if workloadService(cw.RuntimeKind) == "" {
			// A runtime kind with no coverage surface has no partition, so it
			// could never be reconciled. Skipping is better than writing a row
			// nothing can ever close.
			continue
		}
		key := WorkloadKey(cw)
		prev := r.existing.workload[key]

		row := &models.IGAWorkload{
			WorkspaceID:   snap.Run.WorkspaceID,
			EstateScopeID: &snap.ScopeID,
			SourceKey:     key,
			RuntimeKind:   cw.RuntimeKind,
			DisplayName:   cw.Name,
			// Every runtime kind Phase 2 collects is recognition_only: no AWS
			// compute surface the collector reads records a creation-boundary
			// id. A Lambda deleted and recreated under the same name therefore
			// continues as ONE object, and the console says so.
			Continuity: Continuity(cw.RuntimeKind),
			Stage:      "unknown",
			Lifecycle:  models.IGALifecycleActive,
			LastSeenAt: now,
		}
		if prev == nil {
			row.FirstSeenAt = now
		} else {
			row.FirstSeenAt = prev.FirstSeenAt
		}

		id, err := p.repo.UpsertWorkload(tx, row)
		if err != nil {
			return fmt.Errorf("upsert workload %s: %w", key, err)
		}
		r.workload[cw.ID] = id

		if err := p.support(tx, snap, models.ObjectWorkload, id,
			workloadPartition(snap, cw)); err != nil {
			return err
		}
	}
	return nil
}

func (p *Projector) projectEntitlements(tx *gorm.DB, snap *Snapshot, r *resolved) error {
	now := p.now()
	part := entitlementPartition(snap)

	// The holder is needed to key an INLINE policy (§2.6), so index identities
	// by their cloud id first.
	byID := make(map[uuid.UUID]models.CloudIdentity, len(snap.Identities))
	for _, ci := range snap.Identities {
		byID[ci.ID] = ci
	}

	for _, cp := range snap.Permissions {
		holder, ok := byID[cp.IdentityID]
		if !ok {
			// The permission's identity was not read by this run. Skip: an
			// entitlement we cannot key correctly is WORSE than a missing one,
			// because the wrong key silently merges two different grants.
			continue
		}

		var resID *uuid.UUID
		resourceKey := ""
		if cp.ResourceID != nil {
			if rid, ok := r.resource[*cp.ResourceID]; ok {
				resID = &rid
				resourceKey = r.resourceKey[rid]
			}
		}
		// resourceKey stays "" for an account-wide or wildcard grant; the key
		// builder substitutes "*".
		key := EntitlementKey(cp, holder, resourceKey)
		prev := r.existing.entitlement[key]

		row := &models.IGAEntitlement{
			WorkspaceID:     snap.Run.WorkspaceID,
			SourceKey:       key,
			ResourceID:      resID,
			NativeGrantKind: cp.NativeID,
			// BOTH representations, always. NativeRights is what AWS said;
			// NormalizedRights is our reading. A reviewer must be able to see
			// the provider's own wording -- that is why 004 has both columns.
			NativeRights:     nativeRightsOf(cp),
			NormalizedRights: normalizeRights(cp),
			NativeScope:      cp.ScopeKind,
			// Revocable through a supported path. Phase 2 has no remediation,
			// so this is a statement about the grant's SHAPE, not a promise.
			Remediable: !strings.HasPrefix(cp.NativeID, "boundary:"),
			Continuity: ContinuityRecognitionOnly,
			Lifecycle:  models.IGALifecycleActive,
			LastSeenAt: now,
		}
		if prev == nil {
			row.FirstSeenAt = now
		} else {
			row.FirstSeenAt = prev.FirstSeenAt
		}

		id, err := p.repo.UpsertEntitlement(tx, row)
		if err != nil {
			return fmt.Errorf("upsert entitlement %s: %w", key, err)
		}
		r.entitlement[cp.ID] = id

		if err := p.support(tx, snap, models.ObjectEntitlement, id, part); err != nil {
			return err
		}
	}
	return nil
}

// projectCredentials writes access-key metadata, never a value (§2.5).
//
// A NEW KEY NEVER IMPLIES THE OLD ONE WAS REPLACED. AWS's documented rotation
// procedure has TWO ACTIVE KEYS AT ONCE, deliberately, so the application can
// be moved over before the old one is disabled. So a new key is simply an
// additional active credential; two active keys is a correct, common state and
// not a conflict to resolve. 'rotated' is written only when a human records
// it, with basis 'asserted'.
func (p *Projector) projectCredentials(tx *gorm.DB, snap *Snapshot, r *resolved) error {
	now := p.now()
	byID := make(map[uuid.UUID]models.CloudIdentity, len(snap.Identities))
	for _, ci := range snap.Identities {
		byID[ci.ID] = ci
	}

	for _, cs := range snap.Secrets {
		// CloudSecret.IdentityID is NOT NULL: a secret with no identity has
		// nothing to prove, so the collector never writes one.
		identityID, ok := r.identity[cs.IdentityID]
		if !ok {
			continue
		}
		holder, ok := byID[cs.IdentityID]
		if !ok {
			continue
		}
		// §2.5: the credential's own identifier, namespaced by its identity --
		// two identities can hold keys with the same id.
		key := Key("aws", holder.NativeID, cs.NativeID)

		lifecycle := models.LifecycleActive
		if cs.Status == models.CloudSecretInactive {
			// The provider itself says the key is disabled. That is a
			// provider fact, not our inference from an absence.
			lifecycle = "revoked"
		}

		row := &models.IGACredential{
			WorkspaceID:       snap.Run.WorkspaceID,
			IdentityAccountID: identityID,
			SourceKey:         key,
			Continuity:        ContinuityRecognitionOnly,
			CredentialType:    cs.Kind,
			Issuer:            "aws",
			KeyIdentifier:     cs.NativeID,
			LastUsedAt:        cs.LastUsedAt,
			Lifecycle:         lifecycle,
			RotationPosture:   "unknown",
			LastSeenAt:        now,
		}
		if prev := r.existing.credential[key]; prev == nil {
			row.FirstSeenAt = now
		} else {
			row.FirstSeenAt = prev.FirstSeenAt
		}
		if _, err := p.repo.UpsertCredential(tx, row); err != nil {
			return fmt.Errorf("upsert credential %s: %w", key, err)
		}
	}
	return nil
}

// projectAgents writes an agent and its instance for each Bedrock runtime.
//
// origin is 'discovered': this came from a native scan, not a registration. A
// registered agent is a different row with origin 'registered', and the two
// MUST NEVER MERGE even when display names match -- the upsert deliberately
// omits origin from DoUpdates so a rescan cannot undo a human's registration.
func (p *Projector) projectAgents(tx *gorm.DB, snap *Snapshot, r *resolved) error {
	now := p.now()
	for _, cw := range snap.Workloads {
		if !isAgentRuntime(cw.RuntimeKind) {
			continue
		}
		workloadID, ok := r.workload[cw.ID]
		if !ok {
			continue
		}
		key := Key("aws", "agent", cw.NativeID)
		prev := r.existing.agent[key]

		agent := &models.IGAAgent{
			WorkspaceID:   snap.Run.WorkspaceID,
			EstateScopeID: &snap.ScopeID,
			SourceKey:     key,
			DisplayName:   cw.Name,
			Continuity:    ContinuityRecognitionOnly,
			Origin:        models.OriginDiscovered,
			Lifecycle:     models.IGALifecycleActive,
			RollupState:   models.RollupConfirmed,
			LastSeenAt:    now,
		}
		if prev == nil {
			agent.FirstSeenAt = now
		} else {
			agent.FirstSeenAt = prev.FirstSeenAt
		}
		agentID, err := p.repo.UpsertAgent(tx, agent)
		if err != nil {
			return fmt.Errorf("upsert agent %s: %w", key, err)
		}
		if err := p.support(tx, snap, models.ObjectAgent, agentID,
			workloadPartition(snap, cw)); err != nil {
			return err
		}

		instKey := Key("aws", "agent_instance", cw.NativeID)
		instID, err := p.repo.UpsertAgentInstance(tx, &models.IGAAgentInstance{
			WorkspaceID:      snap.Run.WorkspaceID,
			AgentID:          agentID,
			EstateScopeID:    &snap.ScopeID,
			WorkloadID:       &workloadID,
			SourceKey:        instKey,
			NativeWorkloadID: cw.NativeID,
			RuntimeKind:      cw.RuntimeKind,
			Stage:            "unknown",
			Origin:           models.OriginDiscovered,
			Lifecycle:        models.IGALifecycleActive,
			FirstSeenAt:      now,
			LastSeenAt:       now,
		})
		if err != nil {
			return fmt.Errorf("upsert agent instance %s: %w", instKey, err)
		}

		// realizes: the instance is realized by this runtime. Both rows exist
		// deliberately -- collapsing them makes "this agent runs on this
		// runtime" inexpressible the moment one agent has two runtimes.
		part := realizesPartition(snap, cw)
		relID, err := p.repo.UpsertRelationship(tx, &models.IGARelationship{
			WorkspaceID:           snap.Run.WorkspaceID,
			RelationshipType:      models.RelTypeRealizes,
			SourceAgentInstanceID: &instID,
			TargetWorkloadID:      &workloadID,
			Basis:                 models.BasisDeclared,
			State:                 models.RelCurrent,
			LastConfirmedAt:       now,
			LastConfirmedBy:       &snap.Run.ID,
			ConnectorID:           &snap.Run.ConnectorID,
			PartitionKey:          part.Key(),
			SourceKey:             Key("aws", models.RelTypeRealizes, cw.NativeID),
		})
		if err != nil {
			return fmt.Errorf("upsert realizes for %s: %w", cw.NativeID, err)
		}
		// Evidence for the realizes edge is the workload's own observation.
		r.canAssume[cw.ID] = relID
	}
	return nil
}

func isAgentRuntime(kind string) bool {
	switch kind {
	case models.WorkloadBedrockAgent, models.WorkloadBedrockAgentCoreRT,
		models.WorkloadBedrockAgentCoreGW:
		return true
	}
	return false
}

func (p *Projector) projectAccessEdges(tx *gorm.DB, snap *Snapshot, r *resolved) error {
	now := p.now()
	part := accessEdgePartition(snap)

	byID := make(map[uuid.UUID]models.CloudIdentity, len(snap.Identities))
	for _, ci := range snap.Identities {
		byID[ci.ID] = ci
	}

	for _, cp := range snap.Permissions {
		subj, ok := r.identity[cp.IdentityID]
		if !ok {
			continue
		}
		ent, ok := r.entitlement[cp.ID]
		if !ok {
			continue // entitlement was skipped above; no edge without one
		}
		holder := byID[cp.IdentityID]

		var resID *uuid.UUID
		resourceKey := ""
		if cp.ResourceID != nil {
			if rid, ok := r.resource[*cp.ResourceID]; ok {
				resID = &rid
				resourceKey = r.resourceKey[rid]
			}
		}
		if resourceKey == "" {
			resourceKey = "*"
		}

		// PHASE 2 RUNS NO EVALUATOR, so the conclusion is ALWAYS unknown and
		// the calculation ALWAYS partial. There is no branch that promotes a
		// grant to 'effective': doing so would claim an evaluation nobody
		// performed, which is the one thing roadmap §3.5a forbids.
		//
		// What IS recorded is the statement's own allow/deny, on the
		// entitlement, as evidence of what the policy SAYS. That is a
		// different claim from "a request would succeed", and conflating the
		// two is how a dashboard starts lying.
		calc, conclusion := models.CalcPartial, models.ConclusionUnknown

		edgeID, err := p.repo.UpsertAccessEdge(tx, &models.IGAAccessEdge{
			WorkspaceID:              snap.Run.WorkspaceID,
			ConnectorID:              &snap.Run.ConnectorID,
			PartitionKey:             part.Key(),
			SubjectIdentityAccountID: &subj,
			EntitlementID:            ent,
			ResourceID:               resID,
			Direction:                "outbound",
			PathKind:                 cp.NativeID,
			Basis:                    models.BasisDeclared,
			State:                    models.RelCurrent,
			CalculationState:         calc,
			EffectiveConclusion:      conclusion,
			NativeScope:              cp.ScopeKind,
			LastConfirmedAt:          now,
			LastConfirmedBy:          &snap.Run.ID,
			ObservedAt:               &now,
			// Leads with the IDENTITY, so two roles on one managed policy
			// produce ONE entitlement and TWO edges.
			SourceKey: Key("aws", holder.NativeID, cp.NativeID, resourceKey),
		})
		if err != nil {
			return fmt.Errorf("upsert access edge %s: %w", cp.NativeID, err)
		}
		// RETAINED so attachEvidence can link observations to THIS edge.
		// Without this line the evidence pass reads an empty map and silently
		// writes nothing -- a broken pipeline that looks like a working one.
		r.accessEdge[cp.ID] = edgeID
	}
	return nil
}

func (p *Projector) projectRelationships(tx *gorm.DB, snap *Snapshot, r *resolved) error {
	now := p.now()

	// workload --executes_as--> identity
	for _, w := range snap.Workloads {
		if w.IdentityID == nil {
			continue // no configured execution identity; not an edge we can claim
		}
		src, ok := r.workload[w.ID]
		if !ok {
			continue
		}
		dst, ok := r.identity[*w.IdentityID]
		if !ok {
			// The identity was not in this run's snapshot -- a partial scan.
			// Skipping is right: an edge whose endpoint we did not read this
			// run must not be written as `current`.
			continue
		}
		part := executesAsPartition(snap, w)

		relID, err := p.repo.UpsertRelationship(tx, &models.IGARelationship{
			WorkspaceID:      snap.Run.WorkspaceID,
			RelationshipType: models.RelTypeExecutesAs,
			// MEMBERSHIP. scope() finds rows by (workspace, connector,
			// partition_key) and nothing else -- an edge written without these
			// is invisible to reconciliation and never ends, ever.
			ConnectorID:             &snap.Run.ConnectorID,
			PartitionKey:            part.Key(),
			SourceWorkloadID:        &src,
			TargetIdentityAccountID: &dst,
			// Configuration says so; we did not see it run.
			Basis:           models.BasisDeclared,
			State:           models.RelCurrent,
			LastConfirmedAt: now,
			LastConfirmedBy: &snap.Run.ID,
			// BOTH ENDPOINTS, and the TARGET'S IMMUTABLE KEY where it has one.
			//
			// A key naming only the workload means a Lambda moved from RoleA
			// to RoleB computes the SAME key, so the upsert overwrites the
			// target in place -- no ended RoleA edge, no history, and the exit
			// gate's "role replacement closes the old edge" silently fails.
			//
			// The target segment uses the immutable key rather than the ARN
			// because a role deleted and recreated under the same name has the
			// SAME ARN: an ARN-keyed endpoint would let the new role silently
			// inherit the old one's history. recognition_only targets have no
			// immutable key and fall back to the source key, which is what
			// `continuity` on the node exists to tell the reader.
			SourceKey: Key("aws", models.RelTypeExecutesAs, w.NativeID, endpointKey(r, dst)),
		})
		if err != nil {
			return fmt.Errorf("upsert executes_as for %s: %w", w.NativeID, err)
		}
		r.executesAs[w.ID] = relID
	}

	// identity --can_assume--> identity, from cloud_assume_edge.
	//
	// CloudAssumeEdge.Subject is a STRING, not a row id: the trust policy names
	// a principal that may not exist in this account, or at all. Resolve it by
	// source key and skip when unknown -- a trust statement naming a principal
	// we have never seen is NOT evidence that principal exists (roadmap §3.1).
	part := canAssumePartition(snap)
	for _, ae := range snap.AssumeEdges {
		dst, ok := r.identity[ae.IdentityID]
		if !ok {
			continue
		}
		srcCloudID, ok := snap.IdentityIDByKey(Key("aws", ae.Subject))
		if !ok {
			// Unresolved far end. §2.12 makes this an iga_external_principal
			// node in 034 rather than a dropped edge; until that path is wired
			// the edge is not written, which is the honest state -- we do not
			// claim an endpoint we cannot name.
			continue
		}
		src, ok := r.identity[srcCloudID]
		if !ok {
			continue
		}
		relID, err := p.repo.UpsertRelationship(tx, &models.IGARelationship{
			WorkspaceID:             snap.Run.WorkspaceID,
			RelationshipType:        models.RelTypeCanAssume,
			ConnectorID:             &snap.Run.ConnectorID,
			PartitionKey:            part.Key(),
			SourceIdentityAccountID: &src,
			TargetIdentityAccountID: &dst,
			Basis:                   models.BasisDeclared,
			State:                   models.RelCurrent,
			LastConfirmedAt:         now,
			LastConfirmedBy:         &snap.Run.ID,
			SourceKey: Key("aws", models.RelTypeCanAssume,
				endpointKey(r, src), endpointKey(r, dst)),
		})
		if err != nil {
			return fmt.Errorf("upsert can_assume for %s: %w", ae.Subject, err)
		}
		r.canAssume[ae.ID] = relID
	}
	return nil
}

// endpointKey names an identity endpoint by its creation boundary where it has
// one, and by its recognition key otherwise.
func endpointKey(r *resolved, identityID uuid.UUID) string {
	if imm := r.identityImmutable[identityID]; imm != "" {
		return imm
	}
	return r.identityKey[identityID]
}

// nativeRightsOf preserves the provider's own wording verbatim.
//
// Effect IS LOWERCASE. The parser stores strings.ToLower(stmt.Effect)
// (internal/awsdiscovery/policy_statements.go), so it is "allow"/"deny", never
// "Allow". Any comparison against the capitalised form is always false --
// which, in a branch deciding whether access is effective, would invert the
// answer for every Allow statement in the account. Nothing here compares it;
// it is stored as given.
//
// NotActions and NotResources MUST NOT BE DROPPED: a NotAction-only statement
// is a real grant shape (019 relaxed cloud_permission_actions_chk precisely to
// allow it), and an entitlement that silently loses the negation reads as
// BROADER access than exists.
func nativeRightsOf(cp models.CloudPermission) json.RawMessage {
	nr := models.NativeRights{
		Effect:       cp.Effect,
		Actions:      []string(cp.Actions),
		NotActions:   []string(cp.NotActions),
		NotResources: []string(cp.NotResources),
	}
	if cp.Condition != nil {
		nr.Condition = json.RawMessage(*cp.Condition)
	}
	raw, err := json.Marshal(nr)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return raw
}

// normalizeRights is our reading, kept BESIDE the native form and never
// instead of it (§2.13, bet 1).
func normalizeRights(cp models.CloudPermission) json.RawMessage {
	raw, err := json.Marshal(models.NormalizedRights{
		Verbs:       []string(cp.Actions),
		Constrained: cp.Condition != nil || cp.ConstraintState != "unconstrained",
	})
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return raw
}
