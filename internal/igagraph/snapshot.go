package igagraph

import (
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// Snapshot is one published run's collected state, loaded once.
//
// LOADED, NOT STREAMED: a run's output is thousands of rows, not millions, and
// the projection needs random access across all of it -- an access edge needs
// its identity, its resource and its entitlement resolved at once. Streaming
// would buy nothing and cost a query per edge.
type Snapshot struct {
	Run       models.CloudScanRun
	Connector models.CloudConnector
	// ScopeID is the iga_estate_scopes row for this connector's account,
	// upserted before the node passes because every canonical node references
	// it and NOTHING ELSE IN THE TREE POPULATES THAT TABLE.
	ScopeID    uuid.UUID
	Generation int

	Identities  []models.CloudIdentity
	Workloads   []models.CloudWorkload
	Resources   []models.CloudResource
	Permissions []models.CloudPermission
	AssumeEdges []models.CloudAssumeEdge
	Secrets     []models.CloudSecret

	// Coverage is THIS RUN'S OWN report, decoded from the jsonb column stamped
	// at publish (024). NEVER cloud_connector.coverage, which a later scan has
	// overwritten -- that was D1, and reading the wrong one makes a stale
	// answer look authoritative.
	Coverage map[string]models.SurfaceCoverage

	// ConfirmedBy holds the observation ids THIS run confirmed, keyed by
	// subject. Selected on last_confirmed_run_id = this run (024), because
	// content dedupe means an unchanged fact writes no new observation and the
	// observation's own scan_run_id may name a much older run.
	ConfirmedBy map[SubjectRef][]uuid.UUID

	// identityByKey indexes identities by source key, for cloud_assume_edge's
	// Subject -- which is a STRING naming a principal that may not exist.
	identityByKey map[string]uuid.UUID
}

// SubjectRef keys observations by what SURVIVES inventory deletion.
//
// Not the cloud_* row id: 024 made cloud_observation's subject FKs
// ON DELETE SET NULL, so an observation outlives its subject row and the id
// goes NULL. subject_native_id is what remains, and it must be the key the
// collector actually wrote -- see PermissionSubjectKey.
type SubjectRef struct {
	Kind     string // identity | permission | resource | workload
	NativeID string // cloud_observation.subject_native_id, verbatim
}

// IdentityIDByKey resolves a principal named by a trust policy.
//
// Returns false when the subject is unknown, which is the common and correct
// case: a trust statement naming a principal we have never seen is NOT
// evidence that principal exists (roadmap §3.1), so the edge is skipped rather
// than invented.
func (s *Snapshot) IdentityIDByKey(key string) (uuid.UUID, bool) {
	id, ok := s.identityByKey[key]
	return id, ok
}

// RegionsAttempted derives the regions this run tried, from the coverage
// report's own surface keys.
//
// Read off coverage rather than configuration because the question
// reconciliation asks is "what did THIS RUN look at", and a region added to
// the connector after the run started was not looked at by it.
func (s *Snapshot) RegionsAttempted() []string {
	seen := map[string]bool{}
	for name := range s.Coverage {
		// Per-service success keys: lambda:us-east-1, ecs:..., ec2:...,
		// bedrock-agents:..., bedrock-agentcore:...
		if svc, region, ok := strings.Cut(name, ":"); ok && region != "" {
			switch svc {
			case "lambda", "ecs", "ec2", "bedrock-agents", "bedrock-agentcore":
				seen[region] = true
			case "compute":
				// The failure/unselected stand-in. The region WAS attempted --
				// or deliberately not selected -- and either way its partitions
				// must exist so they can be marked stale rather than silently
				// omitted.
				seen[region] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	// Deterministic, so two runs over the same coverage produce the same
	// partition list and therefore the same watermark rows.
	sort.Strings(out)
	return out
}

// Partition is the unit reconciliation reasons about.
//
// Getting its definition wrong is how a scan of one account deletes another
// account's graph, so every field here is load-bearing.
type Partition struct {
	// The evidence boundary. Reconciliation NEVER crosses it: one AWS account
	// confirming its own relationships says nothing about another account's.
	ScopeID     uuid.UUID
	ConnectorID uuid.UUID

	Class            string // identity | workload | resource | entitlement
	RelationshipType string // "" for node classes and for access edges
	Target           string // "" for nodes | "relationship" | "access_edge"

	// RequiredSurfaces is every surface that must be good before this
	// partition may close anything. PLURAL, because completeness is composed:
	// a statement's grants depend on the IAM read AND on the policy documents
	// parsing.
	//
	// For these, ABSENT MEANS DID NOT LOOK.
	RequiredSurfaces []string

	// RequiredScanners are scanner-level failure markers that VETO this
	// partition if PRESENT and not reached.
	//
	// FinalizeCoverage writes these only when a scanner died before producing
	// a snapshot, so presence proves failure and absence proves nothing on its
	// own -- which is exactly why they are a separate list from the surfaces
	// above.
	RequiredScanners []string
}

// Key is the partition's stable identity: scope, connector, class,
// relationship type, target and its required surfaces, joined.
//
// It is the unique key on iga_projection_state (032), the value
// lastGenerationFor looks up, AND the value stamped on every edge's
// partition_key -- one value, three call sites, so "what this run reconciles"
// and "what this run recorded a watermark for" are the same set by
// construction rather than two predicates kept in agreement by hand.
//
// The required surfaces are IN the key deliberately: two partitions that
// differ only by region or by service must get separate watermark rows instead
// of overwriting each other's progress.
func (p Partition) Key() string {
	target := p.Target
	if target == "" {
		target = "node"
	}
	parts := []string{target, p.Class, p.RelationshipType}
	parts = append(parts, p.RequiredSurfaces...)
	return strings.Join(parts, "|")
}

// CoverageSummary reports this partition's worst surface state, for the
// watermark row. "reached" only when every required surface reached.
func (p Partition) CoverageSummary(snap *Snapshot) string {
	worst := models.CloudCoverageReached
	for _, name := range p.RequiredSurfaces {
		cov, ok := snap.Coverage[name]
		if !ok {
			if name == models.SurfacePolicyDocuments {
				// Absent means nothing was dropped -- see canEnd.
				continue
			}
			return models.CloudCoverageUnknown
		}
		if cov.State != models.CloudCoverageReached {
			worst = cov.State
		}
	}
	return worst
}

// Partitions enumerates every partition this run is responsible for.
//
// NAMED FIELDS, ALWAYS. Positional literals silently mis-assign the moment a
// field is added, and RequiredScanners was added to this struct after the list
// was first written -- every positional literal would have compiled fine with
// the veto list empty, which disables the gate entirely.
func Partitions(snap *Snapshot) []Partition {
	sc, cn := snap.ScopeID, snap.Run.ConnectorID

	ps := []Partition{
		// Roles and users are SEPARATE partitions. Merged, a denied iam_users
		// read would block role reconciliation, or a good roles read would
		// license closing users.
		{ScopeID: sc, ConnectorID: cn, Class: models.ObjectIdentity,
			RequiredSurfaces: []string{models.SurfaceIAMRoles}},
		{ScopeID: sc, ConnectorID: cn, Class: models.ObjectIdentity,
			RequiredSurfaces: []string{models.SurfaceIAMUsers}},

		{ScopeID: sc, ConnectorID: cn, Class: models.ObjectResource,
			RequiredSurfaces: []string{
				models.SurfaceIAMRoles, models.SurfaceIAMPolicies, models.SurfacePolicyDocuments},
			RequiredScanners: []string{models.SurfacePermissionScan}},

		{ScopeID: sc, ConnectorID: cn, Class: models.ObjectEntitlement,
			RequiredSurfaces: []string{
				models.SurfaceIAMRoles, models.SurfaceIAMPolicies, models.SurfacePolicyDocuments},
			// The permission scanner produces BOTH the statements and the
			// parse report. If it died before producing a snapshot at all,
			// policy_documents is absent for the WRONG reason.
			RequiredScanners: []string{models.SurfacePermissionScan}},

		{ScopeID: sc, ConnectorID: cn, RelationshipType: models.RelTypeCanAssume,
			Target:           "relationship",
			RequiredSurfaces: []string{models.SurfaceIAMRoles, models.SurfacePolicyDocuments},
			RequiredScanners: []string{models.SurfacePermissionScan}},

		// Access edges reconcile on the same evidence as the entitlements they
		// point at, and are NOT covered by the relationship partitions.
		{ScopeID: sc, ConnectorID: cn, Target: "access_edge",
			RequiredSurfaces: []string{
				models.SurfaceIAMRoles, models.SurfaceIAMPolicies, models.SurfacePolicyDocuments},
			RequiredScanners: []string{models.SurfacePermissionScan}},
	}

	// Per SERVICE per REGION, because that is the grain the scanner reports
	// at. Keyed only on region, a clean ECS read would license closing Lambda
	// workloads in the same region.
	for _, region := range snap.RegionsAttempted() {
		// compute:<region> is NOT a success key -- it appears only when the
		// region was unselected or its client config failed, standing in for
		// the five per-service surfaces that never ran. So it belongs in
		// RequiredScanners (presence = failure), NEVER in RequiredSurfaces.
		computeGate := []string{models.SurfaceWorkloadScan, models.SurfaceCompute(region)}

		for _, svc := range []string{"lambda", "ecs", "ec2"} {
			ps = append(ps,
				Partition{ScopeID: sc, ConnectorID: cn, Class: models.ObjectWorkload,
					RequiredSurfaces: []string{svc + ":" + region},
					RequiredScanners: computeGate},
				Partition{ScopeID: sc, ConnectorID: cn,
					RelationshipType: models.RelTypeExecutesAs, Target: "relationship",
					RequiredSurfaces: []string{svc + ":" + region, models.SurfaceIAMRoles},
					RequiredScanners: computeGate})
		}
		for _, svc := range []string{"bedrock-agents", "bedrock-agentcore"} {
			ps = append(ps,
				Partition{ScopeID: sc, ConnectorID: cn, Class: models.ObjectWorkload,
					RequiredSurfaces: []string{svc + ":" + region},
					RequiredScanners: computeGate},
				Partition{ScopeID: sc, ConnectorID: cn,
					RelationshipType: models.RelTypeRealizes, Target: "relationship",
					RequiredSurfaces: []string{svc + ":" + region},
					RequiredScanners: computeGate})
		}
	}
	return ps
}

// KnownSurfaces is every surface name a partition may require, for the
// startup assertion.
//
// A partition naming a surface no report ever contains can NEVER satisfy
// canEnd, so its relationships stay stale FOREVER -- silent, and it looks like
// working caution. AssertPartitionVocabulary fails loudly on a typo instead.
func KnownSurfaces(regions []string) map[string]bool {
	known := map[string]bool{
		models.SurfaceIAMRoles:        true,
		models.SurfaceIAMUsers:        true,
		models.SurfaceIAMAccessKeys:   true,
		models.SurfaceIAMPolicies:     true,
		models.SurfacePolicyDocuments: true,
		models.SurfaceOIDCProviders:   true,
		models.SurfaceEKSPodIdentity:  true,
		models.SurfacePermissionScan:  true,
		models.SurfaceWorkloadScan:    true,
	}
	for _, r := range regions {
		known[models.SurfaceCompute(r)] = true
		for _, svc := range []string{"lambda", "ecs", "ec2", "bedrock-agents", "bedrock-agentcore"} {
			known[svc+":"+r] = true
		}
	}
	return known
}

// AssertPartitionVocabulary reports every surface a partition requires that no
// coverage report could ever contain.
//
// policy_documents is exempt from the "must appear" rule in the other
// direction -- it is written ONLY on failure -- but it is a known name, so it
// is in KnownSurfaces and needs no exemption here.
func AssertPartitionVocabulary(parts []Partition, regions []string) []string {
	known := KnownSurfaces(regions)
	var bad []string
	for _, p := range parts {
		for _, name := range append(append([]string{}, p.RequiredSurfaces...), p.RequiredScanners...) {
			if !known[name] {
				bad = append(bad, name)
			}
		}
	}
	sort.Strings(bad)
	return bad
}
