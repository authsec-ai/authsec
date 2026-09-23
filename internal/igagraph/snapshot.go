package igagraph

import (
	"fmt"
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

	// partitions is the list every row's partition is LOOKED UP from, built
	// once. Rows must never construct a partition separately: a constructed
	// one can silently disagree with the reconciled set, and then the row is
	// written under one key and reconciled under another -- or never.
	partitions []Partition
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
			case "lambda", "ecs", "ec2", "bedrock-agents", "bedrock-agentcore", "agentcore-gateways":
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
// It is the unique key on iga_projection_state (033), the value
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
	// SORTED, so the key is deterministic from the struct rather than from
	// the order a caller happened to list surfaces in.
	surfaces := append([]string{}, p.RequiredSurfaces...)
	sort.Strings(surfaces)
	parts = append(parts, surfaces...)
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

		// EVERY workload surface gets a WORKLOAD partition -- Bedrock and
		// AgentCore included. With only a `realizes` edge partition, a Bedrock
		// agent's own node had nowhere to be reconciled.
		for _, svc := range workloadServices {
			ps = append(ps, Partition{ScopeID: sc, ConnectorID: cn, Class: models.ObjectWorkload,
				RequiredSurfaces: []string{svc + ":" + region},
				RequiredScanners: computeGate})
		}
		// executes_as for EVERY workload kind the collector attaches an
		// execution role to -- Lambda/ECS/EC2, Bedrock AgentResourceRoleArn,
		// and AgentCore runtime and gateway RoleArn. Covering only the first
		// three meant a Bedrock edge was stamped with a partition that
		// reconciliation never visited, so it read `current` forever: it
		// looked correct and was not.
		for _, svc := range workloadServices {
			ps = append(ps, Partition{ScopeID: sc, ConnectorID: cn,
				RelationshipType: models.RelTypeExecutesAs, Target: "relationship",
				RequiredSurfaces: []string{svc + ":" + region, models.SurfaceIAMRoles},
				RequiredScanners: computeGate})
		}
		for _, svc := range []string{"bedrock-agents", "bedrock-agentcore"} {
			ps = append(ps, Partition{ScopeID: sc, ConnectorID: cn,
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
		for _, svc := range workloadServices {
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

// workloadServices is the coverage-surface prefix for every workload kind the
// collector reports, in a stable order. One list, used by Partitions,
// KnownSurfaces and RegionsAttempted, so the three cannot disagree.
var workloadServices = []string{
	"lambda", "ecs", "ec2",
	"bedrock-agents", "bedrock-agentcore", "agentcore-gateways",
}

// workloadSurfacePrefix maps cloud_workload.RuntimeKind to the prefix its
// coverage surface is reported under.
//
// RuntimeKind and the surface prefix are DIFFERENT VOCABULARIES --
// lambda_function vs lambda, bedrock_agentcore_gateway vs agentcore-gateways
// -- so this mapping is the only correct way from one to the other. Verified
// against the collector: cloud_aws_workload_scan.go reports per service per
// region, and scanGateways reports agentcore-gateways:<region>, NOT
// bedrock-agentcore:<region>.
//
// Keep it EXHAUSTIVE. A RuntimeKind missing here makes PartitionFor panic,
// which is the point: a new runtime kind must be given a partition
// deliberately rather than falling into a default that reconciles it against
// the wrong surface -- or into "", which produced ":<region>", matched
// nothing, and left those rows stale forever with no error.
var workloadSurfacePrefix = map[string]string{
	models.WorkloadLambdaFunction:     "lambda",
	models.WorkloadECSTaskDefinition:  "ecs",
	models.WorkloadEC2Instance:        "ec2",
	models.WorkloadBedrockAgent:       "bedrock-agents",
	models.WorkloadBedrockAgentCoreRT: "bedrock-agentcore",
	models.WorkloadBedrockAgentCoreGW: "agentcore-gateways",
}

// identitySurface maps an identity kind to the surface that evidences it.
// Roles and users are separate partitions, so a denied iam_users read cannot
// block role reconciliation.
func identitySurface(kind string) string {
	if kind == models.CloudIdentityIAMUser {
		return models.SurfaceIAMUsers
	}
	return models.SurfaceIAMRoles
}

// ensurePartitions builds the partition list once per snapshot.
func (s *Snapshot) ensurePartitions() {
	if s.partitions == nil {
		s.partitions = Partitions(s)
	}
}

// PartitionFor returns the Partition that evidences a NODE of this class, from
// the SAME list Partitions() builds -- looked up, never reconstructed.
//
// That is the property that matters: the partition_key the projector stamps on
// a row and the one reconciliation filters by are the same value BY
// CONSTRUCTION, so a row cannot be written under one key and reconciled under
// another.
//
// A class/kind/region with no partition is a programming error and PANICS. It
// must never fall back to a default: a row filed under the wrong partition is
// reconciled against the wrong surface, and a clean read of one surface would
// then license ending rows another surface owns.
func (s *Snapshot) PartitionFor(class, kind, region string) Partition {
	s.ensurePartitions()
	for _, p := range s.partitions {
		if p.Target == "" && p.Matches(class, kind, region) {
			return p
		}
	}
	panic(fmt.Sprintf("igagraph: no partition for class=%q kind=%q region=%q", class, kind, region))
}

// EdgePartitionFor is PartitionFor's counterpart for edges, over the same
// list. Nodes key on Class; edges on RelationshipType or Target.
func (s *Snapshot) EdgePartitionFor(relOrTarget, kind, region string) Partition {
	s.ensurePartitions()
	for _, p := range s.partitions {
		if p.MatchesEdge(relOrTarget, kind, region) {
			return p
		}
	}
	panic(fmt.Sprintf("igagraph: no edge partition for %q kind=%q region=%q", relOrTarget, kind, region))
}

// Matches is the membership predicate for nodes -- the ONLY place that decides
// which partition a node row belongs to.
func (p Partition) Matches(class, kind, region string) bool {
	if p.Class != class {
		return false
	}
	switch class {
	case models.ObjectIdentity:
		return len(p.RequiredSurfaces) > 0 && p.RequiredSurfaces[0] == identitySurface(kind)
	case models.ObjectWorkload, models.ObjectAgent:
		// NOT kind+":"+region: the two vocabularies differ, so concatenation
		// never matches and every workload would panic here.
		prefix, ok := workloadSurfacePrefix[kind]
		return ok && len(p.RequiredSurfaces) > 0 && p.RequiredSurfaces[0] == prefix+":"+region
	default:
		// resource, entitlement: one partition per connector.
		return true
	}
}

// MatchesEdge is the membership predicate for edges.
func (p Partition) MatchesEdge(relOrTarget, kind, region string) bool {
	if relOrTarget == "access_edge" {
		return p.Target == "access_edge"
	}
	if p.Target != "relationship" || p.RelationshipType != relOrTarget {
		return false
	}
	switch relOrTarget {
	case models.RelTypeExecutesAs, models.RelTypeRealizes:
		prefix, ok := workloadSurfacePrefix[kind]
		return ok && len(p.RequiredSurfaces) > 0 && p.RequiredSurfaces[0] == prefix+":"+region
	default:
		// can_assume: one partition per connector.
		return true
	}
}
