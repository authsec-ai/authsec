package igagraph

import (
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

// attachEvidence links each projected edge to the observations THIS run
// confirmed.
//
// The join is on subject_native_id, not on a cloud_* row id, because 024 made
// the subject FKs ON DELETE SET NULL -- an observation outlives the inventory
// row it describes, and the native id is what survives.
//
// EVERY PROJECTED EDGE NEEDS EVIDENCE, COUNTED PER EDGE, NOT PER CLASS. A
// non-zero count per class passes with one evidenced edge and ten thousand
// bare ones, which is exactly the shape of the bug this pass had in draft: the
// access pass never retained its edge ids, so the map was empty and the
// pipeline wrote nothing while appearing to work. P2-6's gate asserts
// count(edges without evidence) == 0 for every projected class.
func (p *Projector) attachEvidence(tx *gorm.DB, snap *Snapshot, r *resolved) error {
	byID := make(map[uuid.UUID]models.CloudIdentity, len(snap.Identities))
	for _, ci := range snap.Identities {
		byID[ci.ID] = ci
	}
	resourceNative := make(map[uuid.UUID]string, len(snap.Resources))
	for _, cr := range snap.Resources {
		resourceNative[cr.ID] = cr.NativeID
	}

	// Access edges: the permission's own observation.
	for _, cp := range snap.Permissions {
		edgeID, ok := r.accessEdge[cp.ID]
		if !ok {
			continue
		}
		holder, ok := byID[cp.IdentityID]
		if !ok {
			continue
		}
		resNative := ""
		if cp.ResourceID != nil {
			resNative = resourceNative[*cp.ResourceID]
		}
		// Built with the SAME function the observation writer uses, so the two
		// cannot drift. One shared helper, never two spellings.
		ref := SubjectRef{
			Kind:     "permission",
			NativeID: PermissionSubjectKey(cp, holder.NativeID, resNative),
		}
		for _, obsID := range snap.ConfirmedBy[ref] {
			if err := p.repo.LinkAccessEdgeEvidence(tx, snap.Run.WorkspaceID,
				edgeID, obsID, "supports"); err != nil {
				return fmt.Errorf("link access edge evidence: %w", err)
			}
		}
	}

	// DERIVED RELATIONSHIPS STILL GET EVIDENCE. executes_as comes from a field
	// on the workload, so its supporting observation is the WORKLOAD'S -- link
	// that rather than leaving the edge bare.
	for _, w := range snap.Workloads {
		relID, ok := r.executesAs[w.ID]
		if !ok {
			continue
		}
		ref := SubjectRef{Kind: "workload", NativeID: w.NativeID}
		for _, obsID := range snap.ConfirmedBy[ref] {
			if err := p.repo.LinkRelationshipEvidence(tx, snap.Run.WorkspaceID,
				relID, obsID, "supports"); err != nil {
				return fmt.Errorf("link executes_as evidence: %w", err)
			}
		}
	}

	// can_assume is evidenced by the ROLE'S trust-policy observation, which is
	// recorded against the identity the trust policy belongs to.
	identityNative := make(map[uuid.UUID]string, len(snap.Identities))
	for _, ci := range snap.Identities {
		identityNative[ci.ID] = ci.NativeID
	}
	for _, ae := range snap.AssumeEdges {
		relID, ok := r.canAssume[ae.ID]
		if !ok {
			continue
		}
		native, ok := identityNative[ae.IdentityID]
		if !ok {
			continue
		}
		ref := SubjectRef{Kind: "identity", NativeID: native}
		for _, obsID := range snap.ConfirmedBy[ref] {
			if err := p.repo.LinkRelationshipEvidence(tx, snap.Run.WorkspaceID,
				relID, obsID, "supports"); err != nil {
				return fmt.Errorf("link can_assume evidence: %w", err)
			}
		}
	}
	return nil
}

// recordState writes the per-partition watermark.
//
// reconciled=false until the Reconciler commits, so a pass interrupted between
// projection and reconciliation is visible as exactly that and gets redone.
func (p *Projector) recordState(tx *gorm.DB, snap *Snapshot, reconciled bool) error {
	for _, part := range Partitions(snap) {
		if err := p.repo.UpsertProjectionState(tx, &models.IGAProjectionState{
			WorkspaceID:      snap.Run.WorkspaceID,
			EstateScopeID:    part.ScopeID,
			ConnectorID:      part.ConnectorID,
			ObjectClass:      part.Class,
			RelationshipType: part.RelationshipType,
			// The partition's FULL identity. A partition can depend on several
			// surfaces, so no single one of them can key it.
			PartitionKey:   part.Key(),
			LastRunID:      snap.Run.ID,
			LastGeneration: int64(snap.Generation),
			CoverageState:  part.CoverageSummary(snap),
			Reconciled:     reconciled,
		}); err != nil {
			return fmt.Errorf("record projection state %s: %w", part.Key(), err)
		}
	}
	return nil
}
