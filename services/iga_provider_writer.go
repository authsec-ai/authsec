package services

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	igraph "github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/internal/igagraph/providers"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ProviderWriter is the default collector writer. Known Linux, Kubernetes and
// AD kinds become canonical rows with server-computed keys. A batch whose
// kinds are all unknown delegates to SupportWriter, including absence, so
// the placeholder key used before this package stays in force for those rows.
type ProviderWriter struct{}

func (ProviderWriter) Project(tx *gorm.DB, in CollectorPass) error {
	if in.Repo == nil {
		return fmt.Errorf("collector pass has no graph repository")
	}
	provider, err := integrationProvider(tx, in)
	if err != nil {
		return err
	}
	facts, err := loadFacts(tx, in)
	if err != nil {
		return err
	}
	if !anyKnown(provider, facts) {
		if class, ok := igraph.MayEndSnapshotSupport(in.Authoritative, in.ObjectClass); ok && igraph.CollectorProvider(provider) {
			if err := endAbsentSupport(tx, in, collectorPartition(in), class, nil); err != nil {
				return err
			}
			return retireCollectorNodes(tx, in)
		}
		return (SupportWriter{}).Project(tx, in)
	}
	estate, err := collectorEstate(tx, in)
	if err != nil {
		return err
	}
	plan, err := providers.Normalize(providers.Input{
		Provider: provider, EstateID: estate.String(),
		Objects: facts.objects, Observations: facts.observations,
	})
	if err != nil {
		return err
	}
	for _, skipped := range plan.Skipped {
		log.Printf("[projection] skipped %s %s: %s", skipped.Kind, skipped.Ref, skipped.Reason)
	}
	ids := &idMap{byKey: map[string]uuid.UUID{}}
	if err := writePlan(tx, in, estate, plan, ids); err != nil {
		return err
	}
	if err := resolveDirectoryBacking(tx, in, plan, ids); err != nil {
		return err
	}
	for _, unresolved := range plan.Unresolved {
		log.Printf("[projection] unresolved %s", unresolved)
	}
	if err := joinAWSRole(tx, in, plan, ids); err != nil {
		return err
	}
	if err := writePlanSupport(tx, in, plan, ids); err != nil {
		return err
	}
	if err := supportUnknown(tx, in, facts, provider); err != nil {
		return err
	}
	class, end := igraph.MayEndSnapshotSupport(in.Authoritative, in.ObjectClass)
	if end && !skippedPassClass(plan, in.ObjectClass) {
		seen := ids.seen[class]
		if err := endAbsentSupport(tx, in, collectorPartition(in), class, seen); err != nil {
			return err
		}
	}
	if err := ageRuntimeSupport(tx, in); err != nil {
		return err
	}
	return retireCollectorNodes(tx, in)
}

type factSet struct {
	objects      []providers.Object
	observations []providers.Observation
}

func integrationProvider(tx *gorm.DB, in CollectorPass) (string, error) {
	var provider string
	err := tx.Raw(`SELECT provider FROM iga_integrations WHERE workspace_id = ? AND id = ?`,
		in.WorkspaceID, in.IntegrationID).Row().Scan(&provider)
	return provider, err
}

func collectorEstate(tx *gorm.DB, in CollectorPass) (uuid.UUID, error) {
	return scanUUID(tx, `SELECT estate_scope_id FROM collector_instances WHERE workspace_id = ? AND id = ?`,
		in.WorkspaceID, in.CollectorID)
}

func anyKnown(provider string, facts factSet) bool {
	for _, o := range facts.objects {
		if providers.KnownKind(provider, o.Kind) {
			return true
		}
	}
	return false
}

type loadedFact struct {
	ObjectType  string
	Recognition string
	Payload     []byte
	Locator     []byte
	ObsID       uuid.UUID
	Fact        []byte
	ObservedAt  time.Time
}

func loadFacts(tx *gorm.DB, in CollectorPass) (factSet, error) {
	ids := in.ScanRunIDs
	if len(ids) == 0 && in.ScanRunID != uuid.Nil {
		ids = []uuid.UUID{in.ScanRunID}
	}
	var out factSet
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := tx.Raw(`SELECT so.object_type, so.recognition_key,
		coalesce(so.normalized_payload, '{}'::jsonb), coalesce(so.locator, '{}'::jsonb),
		o.id, coalesce(o.fact_payload, '{}'::jsonb), o.observed_at
		FROM iga_observations o
		JOIN iga_source_objects so ON so.workspace_id = o.workspace_id AND so.id = o.source_object_id
		WHERE o.workspace_id = ? AND o.scan_run_id IN ?`, in.WorkspaceID, ids).Rows()
	if err != nil {
		return out, err
	}
	defer rows.Close()
	seen := map[string]int{}
	for rows.Next() {
		var row loadedFact
		if err := rows.Scan(&row.ObjectType, &row.Recognition, &row.Payload, &row.Locator, &row.ObsID, &row.Fact, &row.ObservedAt); err != nil {
			return out, err
		}
		obj := objectFrom(row)
		objKey := obj.Kind + "\x00" + obj.Recognition
		if i, ok := seen[objKey]; ok {
			if row.ObsID != uuid.Nil {
				out.objects[i].ObservationIDs = append(out.objects[i].ObservationIDs, row.ObsID)
			}
		} else {
			if row.ObsID != uuid.Nil {
				obj.ObservationIDs = []uuid.UUID{row.ObsID}
			}
			seen[objKey] = len(out.objects)
			out.objects = append(out.objects, obj)
		}
		if ob, ok := observationFrom(row); ok {
			out.observations = append(out.observations, ob)
		}
	}
	return out, rows.Err()
}

func objectFrom(row loadedFact) providers.Object {
	var wrap struct {
		Native     map[string]any `json:"native"`
		Attributes map[string]any `json:"attributes"`
	}
	_ = json.Unmarshal(row.Payload, &wrap)
	var loc struct {
		Ref string `json:"ref"`
	}
	_ = json.Unmarshal(row.Locator, &loc)
	ref := loc.Ref
	if ref == "" {
		ref = row.Recognition
	}
	obj := providers.Object{
		Ref: ref, Kind: row.ObjectType, Recognition: row.Recognition,
		Native: wrap.Native, Attrs: wrap.Attributes,
	}
	if wrap.Native == nil {
		obj.Raw = row.Payload
	}
	return obj
}

func observationFrom(row loadedFact) (providers.Observation, bool) {
	var body struct {
		Kind        string         `json:"kind"`
		SubjectRef  string         `json:"subject_ref"`
		IdentityRef string         `json:"identity_ref"`
		ResourceRef string         `json:"resource_ref"`
		Runtime     map[string]any `json:"runtime"`
		Outcome     string         `json:"outcome"`
		Attribution string         `json:"attribution"`
		Preview     bool           `json:"preview"`
	}
	if len(row.Fact) == 0 || string(row.Fact) == "{}" || string(row.Fact) == "null" {
		return providers.Observation{}, false
	}
	if err := json.Unmarshal(row.Fact, &body); err != nil || body.Kind == "" {
		return providers.Observation{}, false
	}
	return providers.Observation{
		ID: row.ObsID, Kind: body.Kind, SubjectRef: body.SubjectRef, IdentityRef: body.IdentityRef,
		ResourceRef: body.ResourceRef, Runtime: body.Runtime, ObservedAt: row.ObservedAt,
		Outcome: body.Outcome, Attribution: body.Attribution, Preview: body.Preview,
	}, true
}

type idMap struct {
	byKey map[string]uuid.UUID
	seen  map[string]map[uuid.UUID]bool
}

func (m *idMap) put(class, key string, id uuid.UUID) {
	m.byKey[class+"\x00"+key] = id
	if m.seen == nil {
		m.seen = map[string]map[uuid.UUID]bool{}
	}
	if m.seen[class] == nil {
		m.seen[class] = map[uuid.UUID]bool{}
	}
	m.seen[class][id] = true
}

func (m *idMap) get(class, key string) uuid.UUID {
	return m.byKey[class+"\x00"+key]
}

func writePlan(tx *gorm.DB, in CollectorPass, estate uuid.UUID, plan *providers.Plan, ids *idMap) error {
	scope := &estate
	if estate == uuid.Nil {
		scope = nil
	}
	for _, idn := range plan.Identities {
		if err := models.CheckProviderKind(idn.Provider, idn.Kind); err != nil {
			return err
		}
		if err := retireRecreated(tx, "iga_identity_accounts", in.WorkspaceID, idn.SourceKey, idn.ImmutableKey, in.At); err != nil {
			return err
		}
		id, err := in.Repo.UpsertIdentity(tx, &models.IGAIdentityAccount{
			WorkspaceID: in.WorkspaceID, EstateScopeID: scope, DisplayName: idn.Name,
			AccountKind: idn.Kind, IdentityBacking: or(idn.Backing, "unknown"),
			Provider: idn.Provider, SourceKey: idn.SourceKey, Continuity: or(idn.Continuity, models.ContinuityRecognitionOnly),
			ImmutableKey: idn.ImmutableKey, AccountState: or(idn.State, models.AccountStateEnabled),
			ProviderAttrs: orJSON(idn.Attrs), FirstSeenAt: in.At, LastSeenAt: in.At,
		})
		if err != nil {
			return err
		}
		if err := tx.Exec(`UPDATE iga_identity_accounts SET account_state = ? WHERE workspace_id = ? AND id = ?`,
			or(idn.State, models.AccountStateEnabled), in.WorkspaceID, id).Error; err != nil {
			return err
		}
		ids.put(models.ObjectIdentity, idn.SourceKey, id)
	}
	for _, w := range plan.Workloads {
		if err := retireRecreated(tx, "iga_workload", in.WorkspaceID, w.SourceKey, w.ImmutableKey, in.At); err != nil {
			return err
		}
		id, err := in.Repo.UpsertWorkload(tx, &models.IGAWorkload{
			WorkspaceID: in.WorkspaceID, EstateScopeID: scope, Provider: w.Provider,
			RuntimeKind: or(w.RuntimeKind, "process"), DisplayName: w.Name, SourceKey: w.SourceKey,
			Continuity: or(w.Continuity, models.ContinuityRecognitionOnly), ImmutableKey: w.ImmutableKey,
			ProviderAttrs: orJSON(w.Attrs), FirstSeenAt: in.At, LastSeenAt: in.At,
		})
		if err != nil {
			return err
		}
		ids.put(models.ObjectWorkload, w.SourceKey, id)
	}
	for _, r := range plan.Resources {
		id, err := in.Repo.UpsertResource(tx, &models.IGAResource{
			WorkspaceID: in.WorkspaceID, EstateScopeID: scope, ResourceKind: or(r.Kind, "reference"),
			DisplayName: r.Name, Provider: r.Provider, SourceKey: r.SourceKey,
			ProviderAttrs: orJSON(r.Attrs), ReferenceStatus: or(r.ReferenceStatus, models.ReferenceStatusReferenced),
			NativeKind: r.NativeKind, KindMetadata: orJSON(r.Metadata),
			FirstSeenAt: in.At, LastSeenAt: in.At,
		})
		if err != nil {
			return err
		}
		if err := tx.Exec(`UPDATE iga_resources SET reference_status = ?, native_kind = ?, kind_metadata = ? WHERE workspace_id = ? AND id = ?`,
			or(r.ReferenceStatus, models.ReferenceStatusReferenced), r.NativeKind, orJSON(r.Metadata), in.WorkspaceID, id).Error; err != nil {
			return err
		}
		ids.put(models.ObjectResource, r.SourceKey, id)
	}
	for _, pol := range plan.Policies {
		id, err := in.Repo.UpsertPolicy(tx, &models.IGAPolicy{
			WorkspaceID: in.WorkspaceID, Provider: pol.Provider, PolicyKind: pol.Kind,
			DisplayName: or(pol.Name, pol.Kind), SourceKey: pol.SourceKey,
			Continuity: or(pol.Continuity, models.ContinuityRecognitionOnly), ImmutableKey: pol.ImmutableKey,
			DocumentHash: hashJSON(pol.Document), RightsSchema: pol.RightsSchema,
			FirstSeenAt: in.At, LastSeenAt: in.At,
		})
		if err != nil {
			return err
		}
		if err := tx.Exec(`UPDATE iga_policy SET rights_schema = ? WHERE workspace_id = ? AND id = ?`,
			pol.RightsSchema, in.WorkspaceID, id).Error; err != nil {
			return err
		}
		ids.put(models.ObjectPolicy, pol.SourceKey, id)
		if len(pol.Document) > 0 && string(pol.Document) != "{}" && string(pol.Document) != "null" {
			plan.Statements = append(plan.Statements, providers.Statement{
				SourceKey: pol.SourceKey + igraph.Sep + "document", PolicyKey: pol.SourceKey,
				NativeKind: pol.RightsSchema, Rights: pol.Document,
			})
		}
	}
	for _, st := range plan.Statements {
		polID := ids.get(models.ObjectPolicy, st.PolicyKey)
		if polID == uuid.Nil {
			continue
		}
		id, err := in.Repo.UpsertStatement(tx, &models.IGAEntitlement{
			WorkspaceID: in.WorkspaceID, NativeGrantKind: or(st.NativeKind, "native"),
			NativeRights: orJSON(st.Rights), NormalizedRights: json.RawMessage(`{}`),
			Provider: providerOf(plan, st.PolicyKey), PolicyID: &polID, StatementKey: st.SourceKey,
			Effect: allowEffect(st.EffectAllow), ContentHash: hashJSON(st.Rights),
			SourceKey: st.SourceKey, FirstSeenAt: in.At, LastSeenAt: in.At,
		})
		if err != nil {
			return err
		}
		ids.put(models.ObjectEntitlement, st.SourceKey, id)
	}
	part := collectorPartition(in)
	for _, a := range plan.Assignments {
		polID := ids.get(models.ObjectPolicy, a.PolicyKey)
		holder := ids.get(models.ObjectIdentity, a.HolderKey)
		if polID == uuid.Nil || holder == uuid.Nil {
			continue
		}
		id, err := in.Repo.UpsertAssignment(tx, &models.IGAPolicyAssignment{
			WorkspaceID: in.WorkspaceID, PolicyID: polID, HolderIdentityAccountID: holder,
			AssignmentKind: a.Kind, Basis: models.BasisDeclared, State: models.RelCurrent,
			ValidFrom: in.At, LastConfirmedAt: in.At, SourceKey: a.SourceKey, PartitionKey: part,
			IntegrationID: &in.IntegrationID, ConfirmingIGAScanRunID: &in.ScanRunID,
			BindingNativeUID: a.BindingUID, AssignmentScopeKind: a.ScopeKind, NamespaceUID: a.NamespaceUID,
			AssignmentEstateScopeID: scope,
		})
		if err != nil {
			return err
		}
		if err := tx.Exec(`UPDATE iga_policy_assignment
			SET binding_native_uid = ?, assignment_scope_kind = ?, namespace_uid = ?, assignment_estate_scope_id = ?
			WHERE workspace_id = ? AND id = ?`,
			a.BindingUID, a.ScopeKind, a.NamespaceUID, scope, in.WorkspaceID, id).Error; err != nil {
			return err
		}
		ids.put("assignment", a.SourceKey, id)
	}
	for _, g := range plan.Grants {
		asg := ids.get("assignment", g.AssignmentKey)
		st := ids.get(models.ObjectEntitlement, g.StatementKey)
		holder := ids.get(models.ObjectIdentity, g.HolderKey)
		if asg == uuid.Nil || st == uuid.Nil || holder == uuid.Nil {
			continue
		}
		_, err := in.Repo.UpsertGrant(tx, &models.IGAAccessEdge{
			WorkspaceID: in.WorkspaceID, SubjectKind: "identity_account", SubjectID: holder,
			SubjectIdentityAccountID: &holder, Provider: models.ProviderKubernetes,
			EntitlementID: &st, AssignmentID: &asg, Direction: "outbound", PathKind: "k8s_rbac",
			CalculationState: models.CalcPartial, EffectiveConclusion: models.ConclusionUnknown,
			Basis: models.BasisDeclared, State: models.RelCurrent, ValidFrom: in.At, LastConfirmedAt: in.At,
			SourceKey: g.SourceKey, PartitionKey: part, IntegrationID: &in.IntegrationID,
			ConfirmingIGAScanRunID: &in.ScanRunID,
		}, models.EffectAllow)
		if err != nil {
			return err
		}
	}
	for _, rel := range plan.Relationships {
		if err := writeRel(tx, in, part, rel, ids); err != nil {
			return err
		}
	}
	for _, rt := range plan.Runtimes {
		w := ids.get(models.ObjectWorkload, rt.WorkloadKey)
		if w == uuid.Nil {
			continue
		}
		var id uuid.UUID
		err := tx.Raw(`INSERT INTO iga_runtime_instances
			(workspace_id, workload_id, estate_scope_id, runtime_key, runtime_kind, boot_or_pod_incarnation, last_observed_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (workspace_id, runtime_key) DO UPDATE
			SET last_observed_at = EXCLUDED.last_observed_at, ended_at = NULL, workload_id = EXCLUDED.workload_id
			RETURNING id`,
			in.WorkspaceID, w, scope, rt.SourceKey, rt.Kind, rt.Incarnation, orTime(rt.ObservedAt, in.At)).Row().Scan(&id)
		if err != nil {
			return err
		}
		ids.put("runtime", rt.SourceKey, id)
		ids.put(models.ObjectWorkload, rt.WorkloadKey, w)
	}
	for _, b := range plan.Bindings {
		rt := ids.get("runtime", b.RuntimeKey)
		id := ids.get(models.ObjectIdentity, b.IdentityKey)
		if rt == uuid.Nil || id == uuid.Nil || b.Observation == uuid.Nil {
			continue
		}
		if err := tx.Exec(`INSERT INTO iga_runtime_identity_bindings
			(workspace_id, runtime_instance_id, identity_account_id, binding_kind, basis, observation_id, valid_from)
			VALUES (?, ?, ?, ?, 'observed', ?, ?)
			ON CONFLICT (workspace_id, runtime_instance_id, identity_account_id, binding_kind)
			DO UPDATE SET observation_id = EXCLUDED.observation_id, valid_to = NULL`,
			in.WorkspaceID, rt, id, b.Kind, b.Observation, orTime(b.From, in.At)).Error; err != nil {
			return err
		}
	}
	for _, ob := range plan.Observed {
		row, err := models.NewObservedAccess(in.WorkspaceID,
			ids.get(models.ObjectWorkload, ob.WorkloadKey), ids.get("runtime", ob.RuntimeKey),
			ids.get(models.ObjectResource, ob.ResourceKey), ob.Observation,
			ob.Action, or(ob.Outcome, "unknown"), ob.Attribution, orTime(ob.ObservedAt, in.At))
		if err != nil {
			return err
		}
		if id := ids.get(models.ObjectIdentity, ob.IdentityKey); id != uuid.Nil {
			row.IdentityAccountID = &id
		}
		if err := tx.Exec(`INSERT INTO iga_observed_access
			(workspace_id, workload_id, runtime_instance_id, identity_account_id, resource_id, observation_id, action, outcome, observed_at, attribution)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (workspace_id, observation_id, action, resource_id) DO NOTHING`,
			row.WorkspaceID, row.WorkloadID, row.RuntimeInstanceID, row.IdentityAccountID, row.ResourceID,
			row.ObservationID, row.Action, row.Outcome, row.ObservedAt, row.Attribution).Error; err != nil {
			return err
		}
	}
	for _, b := range plan.PolicyBindings {
		if err := writeBinding(tx, in, "iga_workload_policy_bindings", "policy_id",
			b.SourceKey, b.Kind, ids.get(models.ObjectWorkload, b.WorkloadKey),
			ids.get(models.ObjectPolicy, b.PolicyKey), b.Observation); err != nil {
			return err
		}
	}
	for _, b := range plan.ResourceBindings {
		if err := writeBinding(tx, in, "iga_workload_resource_bindings", "resource_id",
			b.SourceKey, b.Kind, ids.get(models.ObjectWorkload, b.WorkloadKey),
			ids.get(models.ObjectResource, b.ResourceKey), b.Observation); err != nil {
			return err
		}
	}
	return nil
}

func writeRel(tx *gorm.DB, in CollectorPass, part string, rel providers.Relationship, ids *idMap) error {
	target := ids.get(models.ObjectIdentity, rel.ToIdentity)
	if target == uuid.Nil {
		return nil
	}
	row := &models.IGARelationship{
		WorkspaceID: in.WorkspaceID, RelationshipType: rel.Type, TargetIdentityAccountID: &target,
		Basis: rel.Basis, DerivationRule: rel.DerivationRule, State: models.RelCurrent,
		ValidFrom: in.At, LastConfirmedAt: in.At, SourceKey: rel.SourceKey, PartitionKey: part,
		IntegrationID: &in.IntegrationID, ConfirmingIGAScanRunID: &in.ScanRunID,
	}
	if rel.FromWorkload != "" {
		id := ids.get(models.ObjectWorkload, rel.FromWorkload)
		if id == uuid.Nil {
			return nil
		}
		row.SourceWorkloadID = &id
	}
	if rel.FromIdentity != "" {
		id := ids.get(models.ObjectIdentity, rel.FromIdentity)
		if id == uuid.Nil {
			return nil
		}
		row.SourceIdentityAccountID = &id
	}
	if rel.Basis == "" {
		row.Basis = models.BasisDeclared
	}
	_, err := in.Repo.UpsertRelationship(tx, row)
	return err
}

func writeBinding(tx *gorm.DB, in CollectorPass, table, col, key, kind string, left, right, obs uuid.UUID) error {
	if left == uuid.Nil || right == uuid.Nil || key == "" {
		return nil
	}
	var obsArg any
	if obs != uuid.Nil {
		obsArg = obs
	}
	return tx.Exec(`INSERT INTO `+table+`
		(workspace_id, workload_id, `+col+`, binding_kind, state, observation_id, source_key)
		VALUES (?, ?, ?, ?, 'current', ?, ?)
		ON CONFLICT (workspace_id, source_key) WHERE state <> 'ended' DO NOTHING`,
		in.WorkspaceID, left, right, kind, obsArg, key).Error
}

func joinAWSRole(tx *gorm.DB, in CollectorPass, plan *providers.Plan, ids *idMap) error {
	for _, w := range plan.Workloads {
		if w.DeclaredAWSRole == "" {
			continue
		}
		wid := ids.get(models.ObjectWorkload, w.SourceKey)
		if wid == uuid.Nil {
			continue
		}
		awsKey := igraph.IdentityARNKey(w.DeclaredAWSRole)
		awsID, err := scanUUID(tx, `SELECT id FROM iga_identity_accounts
			WHERE workspace_id = ? AND source_key = ? AND lifecycle <> 'retired' LIMIT 1`,
			in.WorkspaceID, awsKey)
		if err != nil {
			return err
		}
		if awsID == uuid.Nil {
			continue
		}
		rkey := igraph.Key("kubernetes", "executes_as", igraph.EscapeSegment(w.SourceKey), igraph.EscapeSegment(awsKey))
		_, err = in.Repo.UpsertRelationship(tx, &models.IGARelationship{
			WorkspaceID: in.WorkspaceID, RelationshipType: models.RelTypeExecutesAs,
			SourceWorkloadID: &wid, TargetIdentityAccountID: &awsID,
			Basis: models.BasisDeclared, State: models.RelCurrent,
			ValidFrom: in.At, LastConfirmedAt: in.At, SourceKey: rkey,
			PartitionKey: collectorPartition(in), IntegrationID: &in.IntegrationID,
			ConfirmingIGAScanRunID: &in.ScanRunID,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func writePlanSupport(tx *gorm.DB, in CollectorPass, plan *providers.Plan, ids *idMap) error {
	part := collectorPartition(in)
	write := func(class, key string) error {
		id := ids.get(class, key)
		if id == uuid.Nil {
			return nil
		}
		support := models.SupportFromIntegration(in.WorkspaceID, in.IntegrationID, in.ScanRunID, part, in.At)
		if !support.SetObject(class, id) {
			return nil
		}
		return in.Repo.UpsertObjectSupport(tx, support)
	}
	for _, idn := range plan.Identities {
		if err := write(models.ObjectIdentity, idn.SourceKey); err != nil {
			return err
		}
	}
	for _, w := range plan.Workloads {
		if err := write(models.ObjectWorkload, w.SourceKey); err != nil {
			return err
		}
	}
	for _, r := range plan.Resources {
		if err := write(models.ObjectResource, r.SourceKey); err != nil {
			return err
		}
	}
	for _, pol := range plan.Policies {
		if err := write(models.ObjectPolicy, pol.SourceKey); err != nil {
			return err
		}
	}
	for _, st := range plan.Statements {
		if err := write(models.ObjectEntitlement, st.SourceKey); err != nil {
			return err
		}
	}
	if part == igraph.RuntimePartition {
		return nil
	}
	for _, rt := range plan.Runtimes {
		id := ids.get(models.ObjectWorkload, rt.WorkloadKey)
		if id == uuid.Nil {
			continue
		}
		support := models.SupportFromIntegration(in.WorkspaceID, in.IntegrationID, in.ScanRunID, igraph.RuntimePartition, in.At)
		if !support.SetObject(models.ObjectWorkload, id) {
			continue
		}
		if err := in.Repo.UpsertObjectSupport(tx, support); err != nil {
			return err
		}
	}
	return nil
}

func supportUnknown(tx *gorm.DB, in CollectorPass, facts factSet, provider string) error {
	part := collectorPartition(in)
	for _, o := range facts.objects {
		if providers.KnownKind(provider, o.Kind) {
			continue
		}
		key := collectorSourceKey(in.IntegrationID, o.Kind, o.Recognition)
		class, id, err := existingCanonical(tx, in.WorkspaceID, key)
		if err != nil || id == uuid.Nil {
			continue
		}
		support := models.SupportFromIntegration(in.WorkspaceID, in.IntegrationID, in.ScanRunID, part, in.At)
		if !support.SetObject(class, id) {
			continue
		}
		if err := in.Repo.UpsertObjectSupport(tx, support); err != nil {
			return err
		}
	}
	return nil
}

func ageRuntimeSupport(tx *gorm.DB, in CollectorPass) error {
	ttl := RuntimeSupportTTL()
	if ttl <= 0 {
		return nil
	}
	cutoff := in.At.Add(-ttl)
	// Only this integration's runtime partition. Delta inventory
	// (collector/object) and snapshot partitions are not selected.
	if err := tx.Exec(`UPDATE iga_object_support
		SET state = 'ended', ended_reason = ?, last_confirmed_at = ?
		WHERE workspace_id = ? AND integration_id = ? AND partition_key = ?
		  AND state <> 'ended' AND last_confirmed_at < ?`,
		models.EndedRuntimeUnobserved, in.At, in.WorkspaceID, in.IntegrationID, igraph.RuntimePartition, cutoff).Error; err != nil {
		return err
	}
	estate, err := collectorEstate(tx, in)
	if err != nil {
		return err
	}
	// Another collector's live runtime support keeps the shared instance.
	// A pass only ages instances on its own estate.
	return tx.Exec(`UPDATE iga_runtime_instances ri SET ended_at = ?
		WHERE ri.workspace_id = ? AND ri.estate_scope_id = ? AND ri.ended_at IS NULL
		  AND ri.last_observed_at < ?
		  AND EXISTS (
		      SELECT 1 FROM iga_object_support s
		       WHERE s.workspace_id = ri.workspace_id AND s.workload_id = ri.workload_id
		         AND s.integration_id = ? AND s.partition_key = ?)
		  AND NOT EXISTS (
		      SELECT 1 FROM iga_object_support s
		       WHERE s.workspace_id = ri.workspace_id AND s.workload_id = ri.workload_id
		         AND s.partition_key = ? AND s.integration_id <> ?
		         AND s.state <> 'ended' AND s.last_confirmed_at >= ?)`,
		in.At, in.WorkspaceID, estate, cutoff,
		in.IntegrationID, igraph.RuntimePartition,
		igraph.RuntimePartition, in.IntegrationID, cutoff).Error
}

func retireCollectorNodes(tx *gorm.DB, in CollectorPass) error {
	for _, table := range []struct{ table, col string }{
		{"iga_identity_accounts", "identity_account_id"},
		{"iga_workload", "workload_id"},
		{"iga_resources", "resource_id"},
		{"iga_policy", "policy_id"},
		{"iga_entitlements", "entitlement_id"},
	} {
		err := tx.Exec(`UPDATE `+table.table+` n
			SET lifecycle = 'retired', retired_reason = 'unsupported', updated_at = ?
			WHERE n.workspace_id = ? AND n.provider IN ('linux','kubernetes','ad')
			  AND n.lifecycle <> 'retired'
			  AND EXISTS (SELECT 1 FROM iga_object_support s
			      WHERE s.workspace_id = n.workspace_id AND s.`+table.col+` = n.id
			        AND s.integration_id = ?)
			  AND NOT EXISTS (SELECT 1 FROM iga_object_support s
			      WHERE s.workspace_id = n.workspace_id AND s.`+table.col+` = n.id AND s.state <> 'ended')`,
			in.At, in.WorkspaceID, in.IntegrationID).Error
		if err != nil {
			return err
		}
	}
	return nil
}

func retireRecreated(tx *gorm.DB, table string, ws uuid.UUID, key, immutable string, at time.Time) error {
	if immutable == "" || key == "" {
		return nil
	}
	var id uuid.UUID
	var old string
	err := tx.Raw(`SELECT id, immutable_key FROM `+table+`
		WHERE workspace_id = ? AND source_key = ? AND lifecycle <> 'retired' LIMIT 1`,
		ws, key).Row().Scan(&id, &old)
	if errors.Is(err, sql.ErrNoRows) || id == uuid.Nil || old == "" || old == immutable {
		return nil
	}
	if err != nil {
		return err
	}
	if err := tx.Exec(`UPDATE `+table+` SET lifecycle = 'retired', retired_reason = 'recreated', updated_at = ? WHERE workspace_id = ? AND id = ?`,
		at, ws, id).Error; err != nil {
		return err
	}
	if table != "iga_identity_accounts" {
		return nil
	}
	return tx.Exec(`UPDATE iga_policy_assignment
		SET state = 'ended', ended_reason = 'subject_recreated', valid_to = ?
		WHERE workspace_id = ? AND holder_identity_account_id = ? AND state <> 'ended'`,
		at, ws, id).Error
}

// skippedPassClass is true when this pass dropped an object of the class it
// would otherwise treat as absent. Ending support would retire that object.
func skippedPassClass(plan *providers.Plan, objectClass string) bool {
	want := igraph.SnapshotNodeClass(objectClass)
	if plan == nil || want == "" {
		return false
	}
	for _, skipped := range plan.Skipped {
		if skipped.Kind == objectClass || igraph.SnapshotNodeClass(skipped.Kind) == want {
			return true
		}
	}
	return false
}

func providerOf(plan *providers.Plan, policyKey string) string {
	for _, p := range plan.Policies {
		if p.SourceKey == policyKey {
			return p.Provider
		}
	}
	return ""
}

func allowEffect(allow bool) string {
	if allow {
		return models.EffectAllow
	}
	return ""
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func orJSON(b []byte) json.RawMessage {
	if len(b) == 0 {
		return json.RawMessage(`{}`)
	}
	return b
}

func orTime(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	return a
}

func hashJSON(b []byte) string {
	if len(b) == 0 {
		b = []byte(`{}`)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
