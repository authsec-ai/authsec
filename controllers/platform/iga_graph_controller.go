package platform

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

// GetWorkloadAccessPath serves P2-11: the one read path over the Phase 2 graph.
//
// NOT THE CONSOLE. This exists so the team can inspect and explain the graph
// before Phase 4 builds traversal on it, and its shape follows §2.14 screen C
// so the console does not invent a second one.
//
// For a given workload it returns: the executes_as identity, that identity's
// access edges with entitlement and resource, each row's basis, state and
// last-confirmed time, the evidence ids behind it, and every surface whose
// coverage was not `reached`.
//
// THE WORKSPACE COMES FROM THE AUTHENTICATED CONTEXT, NEVER A QUERY PARAMETER.
// A foreign-workspace workload id returns 404 -- not another tenant's graph,
// and not a 403 that confirms the id exists.
func (ctl *IGAController) GetWorkloadAccessPath(c *gin.Context) {
	ws, _, err := ctl.workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, igaProblem("unauthenticated", err.Error(), http.StatusUnauthorized, c))
		return
	}
	workloadID, err := uuid.Parse(c.Param("workload_id"))
	if err != nil {
		igaError(c, err)
		return
	}

	var workload models.IGAWorkload
	if err := ctl.db.First(&workload, "workspace_id = ? AND id = ?", ws, workloadID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, igaProblem("not_found",
				"no such workload in this workspace", http.StatusNotFound, c))
			return
		}
		igaError(c, err)
		return
	}

	resp := workloadAccessPath{
		Workload: workloadNode{
			ID:          workload.ID,
			SourceKey:   workload.SourceKey,
			RuntimeKind: workload.RuntimeKind,
			DisplayName: workload.DisplayName,
			Lifecycle:   workload.Lifecycle,
			// SAID, NOT IMPLIED. For a Lambda "same name" is the strongest
			// claim available, and the console must say so rather than
			// suggesting we verified a continuity we cannot verify.
			Continuity:  workload.Continuity,
			FirstSeenAt: workload.FirstSeenAt,
			LastSeenAt:  workload.LastSeenAt,
		},
	}

	// Hop 1: executes_as. INCLUDING ended and stale edges -- history is the
	// point, and a caller that wants only live access filters on state.
	var execEdges []models.IGARelationship
	if err := ctl.db.Where(
		"workspace_id = ? AND relationship_type = ? AND source_workload_id = ?",
		ws, models.RelTypeExecutesAs, workload.ID,
	).Order("state, valid_from DESC").Find(&execEdges).Error; err != nil {
		igaError(c, err)
		return
	}

	for _, rel := range execEdges {
		hop := executesAsHop{
			RelationshipID:  rel.ID,
			State:           rel.State,
			Basis:           rel.Basis,
			ValidFrom:       rel.ValidFrom,
			ValidTo:         rel.ValidTo,
			LastConfirmedAt: rel.LastConfirmedAt,
			EndedReason:     rel.EndedReason,
			Evidence:        ctl.relationshipEvidence(ws, rel.ID),
		}
		if rel.TargetIdentityAccountID != nil {
			var identity models.IGAIdentityAccount
			if err := ctl.db.First(&identity, "workspace_id = ? AND id = ?",
				ws, *rel.TargetIdentityAccountID).Error; err == nil {
				hop.Identity = &identityNode{
					ID:           identity.ID,
					SourceKey:    identity.SourceKey,
					DisplayName:  identity.DisplayName,
					AccountKind:  identity.AccountKind,
					Lifecycle:    identity.Lifecycle,
					Continuity:   identity.Continuity,
					ImmutableKey: identity.ImmutableKey,
					FirstSeenAt:  identity.FirstSeenAt,
				}
				hop.Grants = ctl.grantsFor(ws, identity.ID)
			}
		}
		resp.ExecutesAs = append(resp.ExecutesAs, hop)
	}

	// COVERAGE HONESTY (§2.13, bet 3). Every surface this connector's latest
	// published run could not read, named with its state. A response that
	// listed grants without saying what was unreadable would let a partial
	// answer look complete -- which is the exact failure the coverage model
	// exists to prevent.
	resp.CoverageGaps = ctl.coverageGaps(ws, workload.EstateScopeID)

	c.JSON(http.StatusOK, gin.H{
		"data": resp,
		"meta": gin.H{
			"as_of": time.Now().UTC(),
			// Stated rather than assumed: Phase 2 evaluates nothing, so every
			// conclusion on every edge below reads `unknown`.
			"effective_access_evaluated": false,
			"hop_cap":                    2,
		},
	})
}

// grantsFor resolves one identity's access edges with their entitlement,
// resource and evidence.
func (ctl *IGAController) grantsFor(ws, identityID uuid.UUID) []grantRow {
	var edges []models.IGAAccessEdge
	if err := ctl.db.Where(
		"workspace_id = ? AND subject_identity_account_id = ?", ws, identityID,
	).Order("state, created_at").Find(&edges).Error; err != nil {
		return nil
	}

	out := make([]grantRow, 0, len(edges))
	for _, e := range edges {
		row := grantRow{
			AccessEdgeID:        e.ID,
			State:               e.State,
			Basis:               e.Basis,
			PathKind:            e.PathKind,
			CalculationState:    e.CalculationState,
			EffectiveConclusion: e.EffectiveConclusion,
			ValidFrom:           e.ValidFrom,
			ValidTo:             e.ValidTo,
			LastConfirmedAt:     e.LastConfirmedAt,
			EndedReason:         e.EndedReason,
			Evidence:            ctl.accessEdgeEvidence(ws, e.ID),
		}

		var ent models.IGAEntitlement
		if err := ctl.db.First(&ent, "workspace_id = ? AND id = ?", ws, e.EntitlementID).Error; err == nil {
			row.Entitlement = &entitlementNode{
				ID:              ent.ID,
				SourceKey:       ent.SourceKey,
				NativeGrantKind: ent.NativeGrantKind,
				// BOTH representations. native_rights is what AWS said;
				// normalized_rights is our reading. A reviewer must always be
				// able to see the provider's own wording (§2.13, bet 1).
				NativeRights:     ent.NativeRights,
				NormalizedRights: ent.NormalizedRights,
				NativeScope:      ent.NativeScope,
				Lifecycle:        ent.Lifecycle,
			}
		}
		if e.ResourceID != nil {
			var res models.IGAResource
			if err := ctl.db.First(&res, "workspace_id = ? AND id = ?", ws, *e.ResourceID).Error; err == nil {
				row.Resource = &resourceNode{
					ID:          res.ID,
					SourceKey:   res.SourceKey,
					Kind:        res.ResourceKind,
					DisplayName: res.DisplayName,
					Lifecycle:   res.Lifecycle,
					// A selector naming an ARN has never been proof the thing
					// is there. Phase 2 does not enumerate, so existence is
					// deliberately not claimed.
					ExistenceVerified: false,
				}
			}
		}
		out = append(out, row)
	}
	return out
}

func (ctl *IGAController) accessEdgeEvidence(ws, edgeID uuid.UUID) []evidenceRef {
	var rows []struct {
		ObservationID uuid.UUID
		Relation      string
		SourceAPI     string
		Surface       string
		SurfaceState  string
		ObservedAt    time.Time
	}
	// The surface state AT COLLECTION TIME is carried, not looked up now: a
	// fact collected during a degraded scan must still read as such a year
	// later, which is what cloud_observation.surface_state is for.
	ctl.db.Raw(`
		SELECT ev.observation_id, ev.relation,
		       o.source_api, o.surface, o.surface_state, o.observed_at
		  FROM iga_access_edge_evidence ev
		  JOIN cloud_observation o
		    ON o.workspace_id = ev.workspace_id AND o.id = ev.observation_id
		 WHERE ev.workspace_id = ? AND ev.access_edge_id = ?
		 ORDER BY o.observed_at DESC`, ws, edgeID).Scan(&rows)

	out := make([]evidenceRef, 0, len(rows))
	for _, r := range rows {
		out = append(out, evidenceRef{
			ObservationID: r.ObservationID, Relation: r.Relation,
			SourceAPI: r.SourceAPI, Surface: r.Surface,
			SurfaceStateAtCollection: r.SurfaceState, ObservedAt: r.ObservedAt,
		})
	}
	return out
}

func (ctl *IGAController) relationshipEvidence(ws, relID uuid.UUID) []evidenceRef {
	var rows []struct {
		ObservationID uuid.UUID
		Relation      string
		SourceAPI     string
		Surface       string
		SurfaceState  string
		ObservedAt    time.Time
	}
	ctl.db.Raw(`
		SELECT ev.observation_id, ev.relation,
		       o.source_api, o.surface, o.surface_state, o.observed_at
		  FROM iga_relationship_evidence ev
		  JOIN cloud_observation o
		    ON o.workspace_id = ev.workspace_id AND o.id = ev.observation_id
		 WHERE ev.workspace_id = ? AND ev.relationship_id = ?
		 ORDER BY o.observed_at DESC`, ws, relID).Scan(&rows)

	out := make([]evidenceRef, 0, len(rows))
	for _, r := range rows {
		out = append(out, evidenceRef{
			ObservationID: r.ObservationID, Relation: r.Relation,
			SourceAPI: r.SourceAPI, Surface: r.Surface,
			SurfaceStateAtCollection: r.SurfaceState, ObservedAt: r.ObservedAt,
		})
	}
	return out
}

// coverageGaps names every surface the owning scope's partitions did not reach.
//
// Read from iga_projection_state, which records the coverage each partition
// had AT PROJECTION TIME -- never recomputed from cloud_connector.coverage,
// which a later scan has overwritten.
func (ctl *IGAController) coverageGaps(ws uuid.UUID, scopeID *uuid.UUID) []coverageGap {
	if scopeID == nil {
		return nil
	}
	var states []models.IGAProjectionState
	if err := ctl.db.Where(
		"workspace_id = ? AND estate_scope_id = ? AND coverage_state <> ?",
		ws, *scopeID, models.CloudCoverageReached,
	).Find(&states).Error; err != nil {
		return nil
	}
	out := make([]coverageGap, 0, len(states))
	for _, s := range states {
		out = append(out, coverageGap{
			PartitionKey:  s.PartitionKey,
			ObjectClass:   s.ObjectClass,
			CoverageState: s.CoverageState,
			Reconciled:    s.Reconciled,
			LastRunID:     s.LastRunID,
			UpdatedAt:     s.UpdatedAt,
		})
	}
	return out
}

/* ------------------------------ response shapes --------------------------- */

type workloadAccessPath struct {
	Workload   workloadNode    `json:"workload"`
	ExecutesAs []executesAsHop `json:"executes_as"`
	// Named gaps, never a percentage. "78% covered" averages a denied IAM read
	// with an unselected region, and those have different owners and different
	// fixes (§2.14 A).
	CoverageGaps []coverageGap `json:"coverage_gaps"`
}

type workloadNode struct {
	ID          uuid.UUID `json:"id"`
	SourceKey   string    `json:"source_key"`
	RuntimeKind string    `json:"runtime_kind"`
	DisplayName string    `json:"display_name"`
	Lifecycle   string    `json:"lifecycle"`
	Continuity  string    `json:"continuity"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

type identityNode struct {
	ID           uuid.UUID `json:"id"`
	SourceKey    string    `json:"source_key"`
	DisplayName  string    `json:"display_name"`
	AccountKind  string    `json:"account_kind"`
	Lifecycle    string    `json:"lifecycle"`
	Continuity   string    `json:"continuity"`
	ImmutableKey string    `json:"immutable_key,omitempty"`
	FirstSeenAt  time.Time `json:"first_seen_at"`
}

type executesAsHop struct {
	RelationshipID uuid.UUID     `json:"relationship_id"`
	Identity       *identityNode `json:"identity"`
	State          string        `json:"state"`
	Basis          string        `json:"basis"`
	ValidFrom      time.Time     `json:"valid_from"`
	ValidTo        *time.Time    `json:"valid_to,omitempty"`
	// The honest age of the claim. Never refreshed by a scan that could not
	// look -- that would launder an outage into a confirmation.
	LastConfirmedAt time.Time     `json:"last_confirmed_at"`
	EndedReason     string        `json:"ended_reason,omitempty"`
	Evidence        []evidenceRef `json:"evidence"`
	Grants          []grantRow    `json:"grants"`
}

type grantRow struct {
	AccessEdgeID uuid.UUID        `json:"access_edge_id"`
	Entitlement  *entitlementNode `json:"entitlement"`
	Resource     *resourceNode    `json:"resource"`
	State        string           `json:"state"`
	Basis        string           `json:"basis"`
	PathKind     string           `json:"path_kind"`
	// Always partial/unknown in Phase 2: conditions are recorded, never
	// evaluated. Returned explicitly so a caller cannot mistake silence for a
	// decided answer.
	CalculationState    string        `json:"calculation_state"`
	EffectiveConclusion string        `json:"effective_conclusion"`
	ValidFrom           time.Time     `json:"valid_from"`
	ValidTo             *time.Time    `json:"valid_to,omitempty"`
	LastConfirmedAt     time.Time     `json:"last_confirmed_at"`
	EndedReason         string        `json:"ended_reason,omitempty"`
	Evidence            []evidenceRef `json:"evidence"`
}

type entitlementNode struct {
	ID               uuid.UUID `json:"id"`
	SourceKey        string    `json:"source_key"`
	NativeGrantKind  string    `json:"native_grant_kind"`
	NativeRights     []byte    `json:"native_rights"`
	NormalizedRights []byte    `json:"normalized_rights"`
	NativeScope      string    `json:"native_scope"`
	Lifecycle        string    `json:"lifecycle"`
}

type resourceNode struct {
	ID          uuid.UUID `json:"id"`
	SourceKey   string    `json:"source_key"`
	Kind        string    `json:"kind"`
	DisplayName string    `json:"display_name"`
	Lifecycle   string    `json:"lifecycle"`
	// Always false in Phase 2. A selector names a resource; it does not prove
	// one exists.
	ExistenceVerified bool `json:"existence_verified"`
}

type evidenceRef struct {
	ObservationID uuid.UUID `json:"observation_id"`
	Relation      string    `json:"relation"`
	SourceAPI     string    `json:"source_api"`
	Surface       string    `json:"surface"`
	// The coverage that surface had AT COLLECTION TIME, not now.
	SurfaceStateAtCollection string    `json:"surface_state_at_collection"`
	ObservedAt               time.Time `json:"observed_at"`
}

type coverageGap struct {
	PartitionKey  string    `json:"partition_key"`
	ObjectClass   string    `json:"object_class,omitempty"`
	CoverageState string    `json:"coverage_state"`
	Reconciled    bool      `json:"reconciled"`
	LastRunID     uuid.UUID `json:"last_run_id"`
	UpdatedAt     time.Time `json:"updated_at"`
}
