package igagraph

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

// ErrInconsistentWatermark means a partition's watermark equals this run's
// generation while no publication row exists for the run. Step 2 already
// returned for the genuine replay, so this is neither a replay nor a
// supersession -- it is state that should be impossible, and it fails loudly.
var ErrInconsistentWatermark = errors.New("igagraph: watermark equals generation with no publication")

// AlreadyPublished reports that THIS run's projection already committed. It is
// SUCCESS, not failure: the graph wrote nothing on this attempt, so there is
// nothing to undo -- only the job and the barrier to settle.
type AlreadyPublished struct{ Rev int64 }

func (e *AlreadyPublished) Error() string {
	return fmt.Sprintf("igagraph: run already published at rev %d", e.Rev)
}

// GraphWriter is the write surface the projector and reconciler use, declared
// here so the projection decisions can be driven without the concrete
// repository. Every method takes the projection transaction.
type GraphWriter interface {
	UpsertEstateScope(tx *gorm.DB, s *models.IGAEstateScope) (uuid.UUID, error)

	UpsertIdentity(tx *gorm.DB, a *models.IGAIdentityAccount) (uuid.UUID, error)
	RestoreIdentity(tx *gorm.DB, ws, id uuid.UUID, immutableKey string, desc *models.IGAIdentityAccount, now time.Time) (uuid.UUID, error)
	RetireIdentity(tx *gorm.DB, ws, id uuid.UUID, reason string, now time.Time) error
	EndEdgesOnSubject(tx *gorm.DB, ws, identityID uuid.UUID, reason string, now time.Time) error
	SuspendAssertions(tx *gorm.DB, ws, identityID uuid.UUID, reason string) error
	MarkAssertionsPendingReconfirm(tx *gorm.DB, ws, identityID uuid.UUID) error

	UpsertWorkload(tx *gorm.DB, w *models.IGAWorkload) (uuid.UUID, error)
	SetExecutionRoleState(tx *gorm.DB, ws, workloadID uuid.UUID, state, arn string) error

	UpsertResource(tx *gorm.DB, r *models.IGAResource) (uuid.UUID, error)

	UpsertPolicy(tx *gorm.DB, p *models.IGAPolicy) (uuid.UUID, error)
	RestorePolicy(tx *gorm.DB, ws, id uuid.UUID, immutableKey string, desc *models.IGAPolicy, now time.Time) (uuid.UUID, error)
	RetirePolicyIncarnation(tx *gorm.DB, ws, policyID uuid.UUID, now time.Time) (statements []uuid.UUID, err error)

	UpsertStatement(tx *gorm.DB, e *models.IGAEntitlement) (uuid.UUID, error)
	RestoreStatement(tx *gorm.DB, ws, id uuid.UUID, immutableKey string, now time.Time) (uuid.UUID, error)
	RecordRevision(tx *gorm.DB, ws, entitlementID uuid.UUID, hash string, statement json.RawMessage,
		policyVersionID string, runID uuid.UUID, now time.Time) error
	ReplaceTargets(tx *gorm.DB, ws, entitlementID uuid.UUID, rows []models.IGAEntitlementTarget) error

	UpsertCredential(tx *gorm.DB, c *models.IGACredential) (uuid.UUID, error)

	UpsertAssignment(tx *gorm.DB, a *models.IGAPolicyAssignment) (uuid.UUID, error)
	UpsertGrant(tx *gorm.DB, e *models.IGAAccessEdge, statementEffect string) (uuid.UUID, error)
	UpsertRelationship(tx *gorm.DB, r *models.IGARelationship) (uuid.UUID, error)

	// External principals (034, §4.7). UpsertExternalPrincipal never touches
	// the resolution columns; SetDerivedResolution is the only projector
	// write to them, and refuses an asserted row.
	UpsertExternalPrincipal(tx *gorm.DB, e *models.IGAExternalPrincipal) (uuid.UUID, error)
	SetDerivedResolution(tx *gorm.DB, ws, externalID, identityID uuid.UUID, rule string) error

	UpsertObjectSupport(tx *gorm.DB, s *models.IGAObjectSupport) error
	UpsertProjectionState(tx *gorm.DB, s *models.IGAProjectionState) error

	LinkAccessEdgeEvidence(tx *gorm.DB, ws, edgeID, obsID uuid.UUID, relation string) error
	LinkRelationshipEvidence(tx *gorm.DB, ws, relID, obsID uuid.UUID, relation string) error
	LinkAssignmentEvidence(tx *gorm.DB, ws, assignmentID, obsID uuid.UUID, relation string) error

	PublicationForRun(tx *gorm.DB, ws, runID uuid.UUID) (*models.IGAPublication, error)
	NextRevision(tx *gorm.DB, ws uuid.UUID) (int64, error)
	LatestManifest(tx *gorm.DB, ws uuid.UUID) (json.RawMessage, error)
	InsertPublication(tx *gorm.DB, p *models.IGAPublication) error
	InsertLifecycleEvents(tx *gorm.DB, events []models.IGALifecycleEvent) error
}

// Fencer proves, inside the projection transaction, that this worker still
// owns both the job and the workspace's barrier. Checking BEFORE the
// transaction proves nothing: a Complete() rejected afterwards cannot
// un-commit a graph mutation.
type Fencer interface {
	// AssertOwnedTx locks this job's row and asserts the claimed lease version.
	AssertOwnedTx(tx *gorm.DB, jobID uuid.UUID, owner string, leaseVersion int64) error
	// AssertHeldTx asserts the barrier is PROJECTING this run, held by this
	// job, at this version, and locks it FOR UPDATE -- which is what makes
	// rev = max(rev)+1 safe.
	AssertHeldTx(tx *gorm.DB, ws, runID uuid.UUID, version int64) error
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

	now       func() time.Time
	watermark func(tx *gorm.DB, part Partition, ws uuid.UUID) (int64, error)

	rev        int64
	events     *EventLog
	exclusions Exclusions

	// EvidenceMissing counts projected edges whose supporting observation
	// could not be found, PER EDGE TYPE (§4.8, T4.9). An edge is still written
	// -- the configuration was read -- and counted; the gate asserts zero.
	EvidenceMissing map[string]int
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
		EvidenceMissing: map[string]int{},
	}
}

// Rev is the revision this pass published; valid after a successful Project.
func (p *Projector) Rev() int64 { return p.rev }

// Events is the lifecycle log this pass is building; Reconcile appends to it
// and the caller flushes it before commit.
func (p *Projector) Events() *EventLog { return p.events }

// Exclusions names what this run's unreadable documents declared, for
// Reconcile (§4.10). Valid after a successful Project.
func (p *Projector) Exclusions() Exclusions { return p.exclusions }

// Project writes one run's nodes, edges and evidence, and the publication row.
//
// It takes a *gorm.DB it MUST NOT commit: Project and Reconcile are the two
// halves of one transaction, and committing between them would publish a
// graph in which nothing has been closed yet.
func (p *Projector) Project(tx *gorm.DB, snap *Snapshot) error {
	// 1. OWNERSHIP, inside the transaction: the job lease, and the barrier
	//    (workspace, phase=projecting, holder=job:<id>, run, version), both
	//    FOR UPDATE. A reclaimed worker fails here and writes nothing.
	if err := p.fencer.AssertOwnedTx(tx, p.jobID, p.owner, p.leaseVersion); err != nil {
		return err
	}
	if err := p.fencer.AssertHeldTx(tx, snap.Run.WorkspaceID, snap.Run.ID, p.pipelineVersion); err != nil {
		return err
	}

	// 2. ALREADY PUBLISHED? Before the generation guard: a replay after commit
	//    is success, and only the publication row can tell it from
	//    supersession. After a committed pass the watermark EQUALS this
	//    generation, so a `<=` guard would fail the replay forever.
	if pub, err := p.repo.PublicationForRun(tx, snap.Run.WorkspaceID, snap.Run.ID); err != nil {
		return err
	} else if pub != nil {
		return &AlreadyPublished{Rev: pub.Rev}
	}

	// The estate scope first: it is part of every partition key (D-57), so the
	// watermark check below, the rows this pass stamps and the manifest must all
	// see the REAL scope. Resolved only after the replay check -- a replay
	// writes nothing -- and rolled back with everything else if the pass is
	// superseded.
	if err := p.projectEstateScope(tx, snap); err != nil {
		return err
	}
	parts := Partitions(snap)
	if bad := AssertPartitionVocabulary(parts, snap.RegionsAttempted()); len(bad) > 0 {
		return fmt.Errorf("igagraph: partitions name unknown surfaces %v", bad)
	}

	// 3. SUPERSEDED? Only a STRICTLY newer generation. Equality without a
	//    publication is an inconsistency and fails loudly.
	for _, part := range parts {
		have, err := p.watermark(tx, part, snap.Run.WorkspaceID)
		if err != nil {
			return err
		}
		switch {
		case int64(snap.Generation) < have:
			return ErrSuperseded
		case int64(snap.Generation) == have:
			return fmt.Errorf("partition %s at generation %d with no publication for run %s: %w",
				part.Key(), have, snap.Run.ID, ErrInconsistentWatermark)
		}
	}

	// 4. THE REVISION, allocated now: max(rev)+1 is safe because step 1 holds
	//    the barrier row FOR UPDATE. Every lifecycle event carries it.
	rev, err := p.repo.NextRevision(tx, snap.Run.WorkspaceID)
	if err != nil {
		return err
	}
	p.rev = rev
	p.events = NewEventLog(snap.Run.WorkspaceID, rev, snap.Run.ID, p.now())

	r := newResolved(p.existing)

	steps := []struct {
		name string
		fn   func(*gorm.DB, *Snapshot, *resolved) error
	}{
		// Nodes, in dependency order. Each writes its support row.
		{"identities", p.projectIdentities},
		{"workloads", p.projectWorkloads},
		{"policies", p.projectPolicies},
		{"statements", p.projectStatements},
		{"credentials", p.projectCredentials},
		// Edges. Every endpoint is in r by now.
		{"assignments", p.projectAssignments},
		{"grants", p.projectGrants},
		{"memberships", p.projectMemberships},
		{"execution", p.projectExecution},
		{"trust", p.projectTrust}, // can_assume + external principals (§4.7)
		{"evidence", p.attachEvidence},
	}
	for _, st := range steps {
		if err := st.fn(tx, snap, r); err != nil {
			return fmt.Errorf("project %s: %w", st.name, err)
		}
	}
	p.exclusions = exclusionsOf(snap, r)
	p.exclusions.UnreadableTrust, p.exclusions.UnattributedPodIdentity = trustExclusions(snap, r)
	if err := p.recordState(tx, snap, false); err != nil {
		return err
	}

	// 6. PUBLICATION, in the same transaction as every write above, so "the
	//    graph changed" and "a publication exists for this run" never disagree.
	prev, err := p.repo.LatestManifest(tx, snap.Run.WorkspaceID)
	if err != nil {
		return fmt.Errorf("read the previous manifest: %w", err)
	}
	return p.repo.InsertPublication(tx, &models.IGAPublication{
		WorkspaceID: snap.Run.WorkspaceID,
		Rev:         rev,
		ScanRunID:   snap.Run.ID,
		PublishedAt: p.now(),
		Manifest:    manifestOf(prev, snap, parts),
	})
}

// manifestOf records which run each partition came from AS OF THIS REVISION
// (033: "every partition's watermark as of this revision"): the previous
// publication's entries, with this run's partitions overlaid. A revision is
// workspace-wide, so the other accounts' partitions -- and this account's
// partitions this run did not carry -- still stand on the runs that last wrote
// them, and the manifest must say so (D-57). The keys include scope and
// connector, so one account never overwrites another's.
func manifestOf(prev json.RawMessage, snap *Snapshot, parts []Partition) json.RawMessage {
	m := map[string]string{}
	if len(prev) > 0 {
		// A manifest this build cannot decode is not carried: claiming less
		// provenance is safe, inventing it is not.
		_ = json.Unmarshal(prev, &m)
	}
	for _, part := range parts {
		m[part.Key()] = snap.Run.ID.String()
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return raw
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
	snap.partitions = nil // rebuilt with the real scope
	return nil
}

// support records that this connector, in this partition, still vouches for a
// node. THE STEP THAT MAKES A NODE VISIBLE TO RECONCILIATION (§4.10 node write
// contract, step 2): a node written without it is never reconciled.
func (p *Projector) support(tx *gorm.DB, snap *Snapshot, class string, id uuid.UUID, part Partition) error {
	now := p.now()
	row := &models.IGAObjectSupport{
		WorkspaceID:        snap.Run.WorkspaceID,
		ConnectorID:        snap.Run.ConnectorID,
		PartitionKey:       part.Key(),
		State:              models.RelCurrent,
		LastConfirmedRunID: &snap.Run.ID,
		LastConfirmedAt:    &now,
	}
	if !row.SetObject(class, id) {
		return fmt.Errorf("igagraph: no support column for object class %q", class)
	}
	return p.repo.UpsertObjectSupport(tx, row)
}

// projectIdentities: roles, users, groups -- recreate / continue / restore /
// new (§4.6). One pass in full; workloads and policies share the shape.
func (p *Projector) projectIdentities(tx *gorm.DB, snap *Snapshot, r *resolved) error {
	now := p.now()
	for _, ci := range snap.Identities {
		key := IdentityKey(ci)
		cont := Continuity(ci.Kind)
		imm := ImmutableKey(ci)
		part := snap.PartitionFor(models.ObjectIdentity, ci.Kind, "")
		live := r.existing.identity[key]

		trust, err := p.trustFlags(r, snap, ci, live)
		if err != nil {
			return err
		}
		desc := models.IGAIdentityAccount{
			WorkspaceID: snap.Run.WorkspaceID, EstateScopeID: &snap.ScopeID,
			Provider: models.ProviderAWS, SourceKey: key,
			Continuity: cont, ImmutableKey: imm,
			DisplayName: ci.Name, AccountKind: ci.Kind,
			IdentityBacking: "provider_native", Lifecycle: models.IGALifecycleActive,
			RollupState: models.RollupConfirmed, LastSeenAt: now,
			ProviderAttrs: identityProviderAttrs(ci, trust),
		}

		var id uuid.UUID
		switch {
		// (a) RECREATION. Same recognition key, different non-empty creation
		//     boundary: a different principal wearing the old name.
		case live != nil && cont == ContinuityImmutable &&
			imm != "" && live.ImmutableKey != "" && live.ImmutableKey != imm:
			if err = p.repo.RetireIdentity(tx, snap.Run.WorkspaceID, live.ID, models.RetiredRecreated, now); err != nil {
				return fmt.Errorf("retire recreated %s: %w", key, err)
			}
			p.events.Retired(models.ObjectIdentity, live.ID, models.RetiredRecreated)
			if err = p.repo.EndEdgesOnSubject(tx, snap.Run.WorkspaceID, live.ID,
				models.EndedSubjectRecreate, now); err != nil {
				return fmt.Errorf("end edges of recreated %s: %w", key, err)
			}
			// §2.12: a human's decision about X never transfers to Y.
			if err = p.repo.SuspendAssertions(tx, snap.Run.WorkspaceID, live.ID, "recreated"); err != nil {
				return err
			}
			row := desc
			row.FirstSeenAt = now
			if id, err = p.repo.UpsertIdentity(tx, &row); err != nil {
				return fmt.Errorf("insert recreated %s: %w", key, err)
			}
			p.events.FirstSeen(models.ObjectIdentity, id)

		// (b) CONTINUING. Refresh descriptive fields only.
		case live != nil:
			desc.FirstSeenAt = live.FirstSeenAt
			if id, err = p.repo.UpsertIdentity(tx, &desc); err != nil {
				return fmt.Errorf("upsert %s: %w", key, err)
			}

		// (c) RESTORATION. Same recognition AND immutable key, retired as
		//     unsupported: same id, same first_seen_at.
		case imm != "" && r.existing.retiredIdentity[retiredKey(key, imm)] != nil:
			prev := r.existing.retiredIdentity[retiredKey(key, imm)]
			if id, err = p.repo.RestoreIdentity(tx, snap.Run.WorkspaceID, prev.ID, imm, &desc, now); err != nil {
				return fmt.Errorf("restore %s: %w", key, err)
			}
			p.events.Restored(models.ObjectIdentity, id)
			// Restoring the RECORD does not reactivate a human's decision.
			if err = p.repo.MarkAssertionsPendingReconfirm(tx, snap.Run.WorkspaceID, id); err != nil {
				return err
			}

		// (d) NEW.
		default:
			row := desc
			row.FirstSeenAt = now
			if id, err = p.repo.UpsertIdentity(tx, &row); err != nil {
				return fmt.Errorf("insert %s: %w", key, err)
			}
			p.events.FirstSeen(models.ObjectIdentity, id)
		}

		if err := p.support(tx, snap, models.ObjectIdentity, id, part); err != nil {
			return fmt.Errorf("support %s: %w", key, err)
		}
		r.identity[ci.ID] = id
	}
	return nil
}

// identityProviderAttrs is display-only provider fact (§3 028): path, tags,
// permissions-boundary ARN, and for a role what its trust document says
// (trust_has_deny, trust_has_not_principal; see trustFlags) -- so the read APIs
// never read cloud_*.
func identityProviderAttrs(ci models.CloudIdentity, trust map[string]any) json.RawMessage {
	a := ci.AWSAttrs()
	out := map[string]any{"path": a.Path}
	if len(a.Tags) > 0 {
		out["tags"] = a.Tags
	}
	if a.PermissionsBoundaryARN != "" {
		out["permissions_boundary_arn"] = a.PermissionsBoundaryARN
	}
	for k, v := range trust {
		out[k] = v
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return raw
}

// workloadProviderAttrs is a workload's display-only provider facts (§1.4,
// §5.3 workload detail, D-85): its status, foundation model, environment
// variable NAMES and gateway targets [{id, name, status, type}], copied from
// what the collector stored on cloud_workload, so the read APIs never read
// cloud_* (§2.1). Display only: never an identity, a key, a filter or an input
// to reconciliation. UpsertWorkload rewrites it on every pass, so a rescan
// that sees new facts replaces the old ones.
//
// A fact the collector recorded nothing for is left out, and the detail
// renders it null: not applicable to this kind, or not collected. Two lists
// are written even when empty, because there empty is a collected answer --
// and each is left out when this scan did not read it, because an unread list
// is unknown, never empty and never the last one we saw:
//
//   - a Lambda function's variable names come with its ListFunctions entry,
//     so none listed means the function has none. When AWS returned the
//     environment as an error instead (env_vars_unread: Lambda could not
//     decrypt the variables with the function's KMS key), nothing was read.
//   - a gateway's target list read in full is its whole list. One NOT read in
//     full (targets_incomplete) is left out, although the collector keeps the
//     list of its last complete read on cloud_workload (workloadAttrsMerge):
//     that list is not confirmed by this scan, and D-85's shape has no field
//     to say so, so showing it would present an old list as the current one.
//     A list cut short after its first page is not the gateway's list either.
//
// Values are never read: EnvVarNames holds names only, by construction of the
// collector (awsdiscovery lambdaEnvVarNames).
func workloadProviderAttrs(cw models.CloudWorkload) json.RawMessage {
	a := cw.AWSAttrs()
	out := map[string]any{}
	if a.Status != "" {
		out["status"] = a.Status
	}
	if a.FoundationModel != "" {
		out["foundation_model"] = a.FoundationModel
	}
	switch {
	case a.EnvVarsUnread:
		// Not read this scan: null, whatever kind, whatever was kept.
	case cw.RuntimeKind == models.WorkloadLambdaFunction:
		names := a.EnvVarNames
		if names == nil {
			names = []string{}
		}
		out["env_var_names"] = names
	case len(a.EnvVarNames) > 0:
		out["env_var_names"] = a.EnvVarNames
	}
	if cw.RuntimeKind == models.WorkloadBedrockAgentCoreGW && !a.TargetsIncomplete {
		targets := a.GatewayTargets
		if targets == nil {
			targets = []models.AWSGatewayTarget{}
		}
		out["gateway_targets"] = targets
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return raw
}

// projectWorkloads: every runtime the collector reported, INCLUDING GATEWAYS
// (the graph branch crashed the process on them). Bedrock agents and
// AgentCore runtimes are classified provider_native_agent ON INSERT ONLY; no
// AWS row is ever written to iga_agents or iga_agent_instances (§2.2).
func (p *Projector) projectWorkloads(tx *gorm.DB, snap *Snapshot, r *resolved) error {
	now := p.now()
	account, partition := snap.Connector.ScopeID, snap.Connector.AWSAttrs().Partition
	for _, cw := range snap.Workloads {
		key := WorkloadKey(cw, partition, account)
		part := snap.PartitionFor(models.ObjectWorkload, cw.RuntimeKind, cw.Region)
		live := r.existing.workload[key]
		// D-53 / T3.6: a workload whose detail call failed has an UNKNOWN
		// execution role, and 029 has no state for unknown -- a new row would
		// default to 'none', "No execution role configured", a false finding.
		// With no prior node there is nothing to protect and nothing true to
		// say, so it is not projected this pass (its surface is partial, and
		// coverage says how many). A prior node is confirmed as usual: the
		// listing proves it exists.
		if live == nil && cw.AWSAttrs().DetailIncomplete {
			continue
		}

		row := &models.IGAWorkload{
			WorkspaceID: snap.Run.WorkspaceID, EstateScopeID: &snap.ScopeID,
			Provider: models.ProviderAWS, RuntimeKind: cw.RuntimeKind,
			DisplayName: cw.Name, Region: cw.Region,
			SourceKey: key, Continuity: Continuity(cw.RuntimeKind),
			Stage: "unknown", Lifecycle: models.IGALifecycleActive,
			LastSeenAt: now, ProviderAttrs: workloadProviderAttrs(cw),
			Classification: models.ClassificationUnclassified,
		}
		switch cw.RuntimeKind {
		case models.WorkloadBedrockAgent, models.WorkloadBedrockAgentCoreRT:
			// The provider calls it an agent. Written on insert; the upsert's
			// DoUpdates never names classification, so a person's decision
			// survives every later scan.
			row.Classification = models.ClassificationProviderAgent
		}
		if live == nil {
			row.FirstSeenAt = now
		} else {
			row.FirstSeenAt = live.FirstSeenAt
		}
		id, err := p.repo.UpsertWorkload(tx, row)
		if err != nil {
			return fmt.Errorf("upsert workload %s: %w", key, err)
		}
		if live == nil {
			p.events.FirstSeen(models.ObjectWorkload, id)
		}
		if err := p.support(tx, snap, models.ObjectWorkload, id, part); err != nil {
			return err
		}
		r.workload[cw.ID] = id
	}
	return nil
}

// projectCredentials writes access-key metadata, never a value (§2.5). A new
// key NEVER implies the old one was replaced: two active keys is a correct,
// common state. 'rotated' is only ever a human assertion.
func (p *Projector) projectCredentials(tx *gorm.DB, snap *Snapshot, r *resolved) error {
	now := p.now()
	for _, cs := range snap.Secrets {
		identityID, ok := r.identity[cs.IdentityID]
		if !ok {
			continue
		}
		holder := snap.IdentityByID(&cs.IdentityID)
		if holder == nil {
			continue
		}
		key := CredentialKey(*holder, cs.NativeID)
		lifecycle := models.LifecycleActive
		if cs.Status == models.CloudSecretInactive {
			// The provider itself says the key is disabled -- a provider fact,
			// not an inference from absence.
			lifecycle = "revoked"
		}
		row := &models.IGACredential{
			WorkspaceID: snap.Run.WorkspaceID, IdentityAccountID: identityID,
			Provider: models.ProviderAWS, SourceKey: key,
			Continuity: ContinuityRecognitionOnly, CredentialType: cs.Kind,
			Issuer: "aws", KeyIdentifier: cs.NativeID, LastUsedAt: cs.LastUsedAt,
			Lifecycle: lifecycle, RotationPosture: "unknown", LastSeenAt: now,
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

// projectMemberships writes user --member_of--> group. The group's grants
// reach the user by TRAVERSAL; nothing is copied onto the user (§2.6).
func (p *Projector) projectMemberships(tx *gorm.DB, snap *Snapshot, r *resolved) error {
	now := p.now()
	part := snap.EdgePartitionFor(models.RelTypeMemberOf, "", "")
	for _, m := range snap.Memberships {
		src, ok1 := r.identity[m.UserIdentityID]
		dst, ok2 := r.identity[m.GroupIdentityID]
		user, group := snap.IdentityByID(&m.UserIdentityID), snap.IdentityByID(&m.GroupIdentityID)
		if !ok1 || !ok2 || user == nil || group == nil {
			continue
		}
		relID, err := p.repo.UpsertRelationship(tx, &models.IGARelationship{
			WorkspaceID: snap.Run.WorkspaceID, RelationshipType: models.RelTypeMemberOf,
			SourceIdentityAccountID: &src, TargetIdentityAccountID: &dst,
			Basis: models.BasisDeclared, State: models.RelCurrent,
			LastConfirmedAt: now, LastConfirmedBy: &snap.Run.ID,
			ConnectorID: &snap.Run.ConnectorID, PartitionKey: part.Key(),
			SourceKey: RelationshipKey(models.RelTypeMemberOf, EndpointKey(*user), EndpointKey(*group)),
		})
		if err != nil {
			return fmt.Errorf("upsert member_of %s -> %s: %w", user.NativeID, group.NativeID, err)
		}
		// Evidence: the user's observation, which lists the group.
		r.memberOf = append(r.memberOf, relRef{ID: relID, SubjectKind: "identity", SubjectNativ: user.NativeID})
	}
	return nil
}

// projectExecution writes the configured execution identity of every workload
// (§4.6): executes_as, ECS's task_execution_role, and the execution-role state.
func (p *Projector) projectExecution(tx *gorm.DB, snap *Snapshot, r *resolved) error {
	now := p.now()
	account, partition := snap.Connector.ScopeID, snap.Connector.AWSAttrs().Partition
	for _, w := range snap.Workloads {
		src, ok := r.workload[w.ID]
		if !ok {
			continue
		}
		// D-53 / T3.6: the detail call that names the role failed, so this run
		// knows NOTHING about the execution identity. Leave the state as the
		// previous pass wrote it (never 'none'), and confirm no executes_as /
		// task_execution_role edge: unconfirmed, they go stale under the
		// surface's partial coverage instead of being re-asserted or ended.
		if w.AWSAttrs().DetailIncomplete {
			continue
		}
		wkey := WorkloadKey(w, partition, account)

		// DETERMINE THE ENDPOINT FIRST, then record what we know. The role is
		// the one the workload ACTS AS -- never ECS's ExecutionRoleARN.
		state, arn, dst := executionRole(snap, r, w)
		if (state == models.ExecRoleNotInScan || state == models.ExecRoleNotInInventory) && arn == "" {
			return fmt.Errorf("workload %s: execution role state %q with no ARN to name it", w.NativeID, state)
		}
		// Written on EVERY pass, state and ARN together, so the CHECK pairing
		// them is never violated mid-update and no earlier run's state survives.
		if err := p.repo.SetExecutionRoleState(tx, snap.Run.WorkspaceID, src, state, arn); err != nil {
			return err
		}
		if state == models.ExecRoleResolved {
			role := snap.IdentityByID(w.IdentityID)
			part := snap.EdgePartitionFor(models.RelTypeExecutesAs, w.RuntimeKind, w.Region)
			relID, err := p.repo.UpsertRelationship(tx, &models.IGARelationship{
				WorkspaceID: snap.Run.WorkspaceID, RelationshipType: models.RelTypeExecutesAs,
				SourceWorkloadID: &src, TargetIdentityAccountID: &dst,
				Basis: models.BasisDeclared, State: models.RelCurrent,
				LastConfirmedAt: now, LastConfirmedBy: &snap.Run.ID,
				ConnectorID: &snap.Run.ConnectorID, PartitionKey: part.Key(),
				SourceKey: RelationshipKey(models.RelTypeExecutesAs, wkey, EndpointKey(*role)),
			})
			if err != nil {
				return fmt.Errorf("upsert executes_as for %s: %w", w.NativeID, err)
			}
			r.executes = append(r.executes, relRef{ID: relID, SubjectKind: "workload", SubjectNativ: w.NativeID})
		}
		// ECS only: the role ECS itself uses to pull images and fetch secrets.
		if w.RuntimeKind == models.WorkloadECSTaskDefinition {
			if execARN := w.AWSAttrs().ExecutionRoleARN; execARN != "" {
				if ci, gid, ok := resolveRole(snap, r, execARN); ok {
					part := snap.EdgePartitionFor(models.RelTypeTaskExecutionRole, w.RuntimeKind, w.Region)
					relID, err := p.repo.UpsertRelationship(tx, &models.IGARelationship{
						WorkspaceID: snap.Run.WorkspaceID, RelationshipType: models.RelTypeTaskExecutionRole,
						SourceWorkloadID: &src, TargetIdentityAccountID: &gid,
						Basis: models.BasisDeclared, State: models.RelCurrent,
						LastConfirmedAt: now, LastConfirmedBy: &snap.Run.ID,
						ConnectorID: &snap.Run.ConnectorID, PartitionKey: part.Key(),
						SourceKey: RelationshipKey(models.RelTypeTaskExecutionRole, wkey, EndpointKey(*ci)),
					})
					if err != nil {
						return fmt.Errorf("upsert task_execution_role for %s: %w", w.NativeID, err)
					}
					r.executes = append(r.executes, relRef{ID: relID, SubjectKind: "workload", SubjectNativ: w.NativeID})
				}
			}
		}
	}
	return nil
}

// executionRole decides the four-way state (§4.6):
//
//	resolved          the edge exists
//	not_in_scan       the collector linked a role this run's snapshot lacks
//	not_in_inventory  a role ARN matching no identity in the workspace
//	none              no role configured
func executionRole(snap *Snapshot, r *resolved, w models.CloudWorkload) (string, string, uuid.UUID) {
	switch {
	case w.IdentityID != nil:
		if id, ok := r.identity[*w.IdentityID]; ok && snap.IdentityByID(w.IdentityID) != nil {
			return models.ExecRoleResolved, "", id
		}
		return models.ExecRoleNotInScan, snap.IdentityNativeID(*w.IdentityID), uuid.Nil
	case w.AWSAttrs().UnresolvedRoleARN != "":
		return models.ExecRoleNotInInventory, w.AWSAttrs().UnresolvedRoleARN, uuid.Nil
	}
	return models.ExecRoleNone, "", uuid.Nil
}

// resolveRole finds a role of this snapshot by ARN.
func resolveRole(snap *Snapshot, r *resolved, arn string) (*models.CloudIdentity, uuid.UUID, bool) {
	for i := range snap.Identities {
		ci := &snap.Identities[i]
		if ci.NativeID == arn {
			if gid, ok := r.identity[ci.ID]; ok {
				return ci, gid, true
			}
		}
	}
	return nil, uuid.Nil, false
}
