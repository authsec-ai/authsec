package igaread

import (
	"encoding/json"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// v2 edge specs. They live beside the AWS specs and are consulted only when
// the request's kind list includes them (graph=v2). The SQL still says
// provider = 'aws'; the snapshot callback widens that literal.
func init() {
	graphSpecs[GraphForward][GraphEdgeBackedByDirectory] = graphRelForward(GraphEdgeBackedByDirectory, RefIdentity)
	graphSpecs[GraphReverse][GraphEdgeBackedByDirectory] = graphRelReverse(
		GraphEdgeBackedByDirectory, "iga_identity_accounts", "source_identity_account_id", "identity_account_id")

	const observedCols = `e0.id AS claim_id,
	       e0.workload_id AS from_id, 'workload' AS from_type,
	       e0.resource_id AS to_id, 'resource' AS to_type,
	       NULL::text AS state, 'observed' AS basis, e0.outcome AS mechanism,
	       e0.observed_at AS last_confirmed_at, NULL::uuid AS connector_id,
	       '' AS partition_key, NULL::text AS policy_name`
	graphSpecs[GraphForward][GraphEdgeObservedAccess] = &graphEdgeSpec{
		kind: GraphEdgeObservedAccess, claim: RefObservedAccess,
		from: `iga_observed_access e0
		  JOIN iga_resources far ON far.workspace_id = e0.workspace_id AND far.id = e0.resource_id`,
		where:  `far.provider = 'aws' AND ` + observedEvidenceSQL("far") + ` AND ` + SupportedSQL("far", "resource_id"),
		live:   "TRUE",
		near:   map[string]string{RefWorkload: `e0.workload_id`},
		farKey: `far.source_key`,
		cols:   observedCols,
	}
	graphSpecs[GraphReverse][GraphEdgeObservedAccess] = &graphEdgeSpec{
		kind: GraphEdgeObservedAccess, claim: RefObservedAccess,
		from: `iga_observed_access e0
		  JOIN iga_workload far ON far.workspace_id = e0.workspace_id AND far.id = e0.workload_id
		  JOIN iga_resources res ON res.workspace_id = e0.workspace_id AND res.id = e0.resource_id`,
		where:  `far.provider = 'aws' AND ` + observedEvidenceSQL("res") + ` AND ` + SupportedSQL("far", "workload_id"),
		live:   "TRUE",
		near:   map[string]string{RefResource: `e0.resource_id`},
		farKey: `far.source_key`,
		cols:   observedCols,
	}
}

// observedAccess loads observed-access edges for ClaimLimitations. The claim
// is not a grant: effective access stays the graph meta's, not a conclusion
// of the walk. /evidence does not accept this type.
func (l *claimLoader) observedAccess(ids []uuid.UUID) error {
	var rows []struct{ ID uuid.UUID }
	if err := l.q.DB().Raw(`SELECT e0.id
		FROM iga_observed_access e0
		JOIN iga_resources far ON far.workspace_id = e0.workspace_id AND far.id = e0.resource_id
		WHERE e0.workspace_id = ? AND e0.id IN ?
		  AND far.provider = 'aws' AND `+observedEvidenceSQL("far"), l.q.WS, ids).Scan(&rows).Error; err != nil {
		return err
	}
	for _, r := range rows {
		ref := Ref{Type: RefObservedAccess, ID: r.ID}
		l.claims[ref.String()] = &evClaim{
			ref: ref, basis: "observed", state: StateCurrent,
		}
	}
	return nil
}

// observedEvidenceSQL keeps SQL-shaped actions out of the graph unless the
// row names a database or a broker, or the resource's native kind does.
// Traversal does not call that effective access.
func observedEvidenceSQL(resourceAlias string) string {
	return `(e0.action NOT IN ('sql','query','db_query') OR e0.attribution IN ('database','broker') OR ` +
		resourceAlias + `.native_kind IN ('database','sql'))`
}

// labelV2Edge marks declared and observed. backed_by_directory is directory
// backing: mechanism stays whatever the row stored, which is not Kerberos.
func labelV2Edge(e *GraphEdge, kind string, row graphEdgeRow) {
	switch kind {
	case GraphEdgeObservedAccess:
		e.AccessClass = "observed"
		e.Outcome = row.Mechanism
		e.Mechanism = ""
		e.Basis = "observed"
	case GraphEdgeBackedByDirectory:
		e.AccessClass = "declared"
		e.Meaning = "directory_backing"
	default:
		e.AccessClass = "declared"
	}
}

// fillGrantHonesty copies calculation_state and effective_conclusion onto
// grant edges. Kubernetes grants are partial/unknown by the 041 check; the
// columns are the stored fact, not a conclusion the traversal computed.
func (t *graphTraversal) fillGrantHonesty(lv *graphLevel, edges []*GraphEdge) error {
	if !t.q.V2 || len(edges) == 0 {
		return nil
	}
	var ids []uuid.UUID
	byID := map[uuid.UUID][]*GraphEdge{}
	for _, e := range edges {
		if e == nil || e.Kind != GraphEdgeGrant {
			continue
		}
		ids = append(ids, e.claimRef.ID)
		byID[e.claimRef.ID] = append(byID[e.claimRef.ID], e)
	}
	if len(ids) == 0 {
		return nil
	}
	tx, err := lv.db()
	if err != nil {
		return err
	}
	var rows []struct {
		ID                  uuid.UUID
		CalculationState    string
		EffectiveConclusion string
	}
	if err := tx.Raw(`SELECT id, calculation_state, effective_conclusion
	                    FROM iga_access_edges
	                   WHERE workspace_id = ? AND id IN ?`, t.q.WS, ids).Scan(&rows).Error; err != nil {
		return err
	}
	for _, r := range rows {
		for _, e := range byID[r.ID] {
			e.CalculationState = r.CalculationState
			e.EffectiveConclusion = r.EffectiveConclusion
		}
	}
	return nil
}

// fillResourceFacts sets reference_status and native_kind on resource nodes.
func (t *graphTraversal) fillResourceFacts(lv *graphLevel, nodes []*GraphNode) error {
	if !t.q.V2 {
		return nil
	}
	var ids []uuid.UUID
	set := map[uuid.UUID]*GraphNode{}
	for _, n := range nodes {
		if n == nil || n.typ != RefResource {
			continue
		}
		ids = append(ids, n.id)
		set[n.id] = n
	}
	if len(ids) == 0 {
		return nil
	}
	tx, err := lv.db()
	if err != nil {
		return err
	}
	var rows []struct {
		ID              uuid.UUID
		ReferenceStatus string
		NativeKind      string
	}
	if err := tx.Raw(`SELECT id, reference_status, native_kind
	                    FROM iga_resources
	                   WHERE workspace_id = ? AND id IN ?`, t.q.WS, ids).Scan(&rows).Error; err != nil {
		return err
	}
	for _, r := range rows {
		n := set[r.ID]
		if n == nil {
			continue
		}
		status, kind := r.ReferenceStatus, r.NativeKind
		n.ReferenceStatus = &status
		n.NativeKind = &kind
	}
	return nil
}

// endedRuntimeBasis is the TTL basis a runtime row shows once ended_at is set.
// The writer records the same constant on the support row (EndedRuntimeUnobserved).
func (q *Query) resourceFacts(id uuid.UUID) (status, kind *string, err error) {
	var rows []struct {
		ReferenceStatus string
		NativeKind      string
	}
	if err = q.DB().Raw(`SELECT reference_status, native_kind FROM iga_resources
		WHERE workspace_id = ? AND id = ?`, q.WS, id).Scan(&rows).Error; err != nil {
		return nil, nil, err
	}
	if len(rows) == 0 {
		return nil, nil, nil
	}
	s, k := rows[0].ReferenceStatus, rows[0].NativeKind
	return &s, &k, nil
}

func (q *Query) evidenceProvenance() (*EvidenceProvenance, error) {
	if q.Rev == nil {
		return nil, nil
	}
	var rows []struct {
		Manifest         []byte
		SourceManifestV2 []byte
		IGAScanRunID     *uuid.UUID
	}
	if err := q.DB().Raw(`SELECT manifest, source_manifest_v2, iga_scan_run_id
		FROM iga_publication WHERE workspace_id = ? AND rev = ?`, q.WS, q.Rev.Rev).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	manifest := rows[0].Manifest
	if len(manifest) == 0 {
		manifest = []byte(`{}`)
	}
	prov := &EvidenceProvenance{
		GraphRevision: q.Rev.Rev,
		Manifest:      json.RawMessage(manifest),
	}
	if len(rows[0].SourceManifestV2) > 0 && string(rows[0].SourceManifestV2) != "null" {
		prov.SourceManifestV2 = json.RawMessage(rows[0].SourceManifestV2)
	}
	if rows[0].IGAScanRunID != nil {
		var ids []struct{ IntegrationID *uuid.UUID }
		if err := q.DB().Raw(`SELECT integration_id FROM iga_scan_runs
			WHERE workspace_id = ? AND id = ?`, q.WS, *rows[0].IGAScanRunID).Scan(&ids).Error; err != nil {
			return nil, err
		}
		if len(ids) == 1 && ids[0].IntegrationID != nil {
			s := ids[0].IntegrationID.String()
			prov.IntegrationID = &s
		}
	}
	return prov, nil
}

func endedRuntimeBasis(ended bool) *string {
	if !ended {
		return nil
	}
	s := models.EndedRuntimeUnobserved
	return &s
}
