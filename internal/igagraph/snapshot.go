package igagraph

import (
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// Snapshot is one published run's collected state, loaded once (§4.3).
//
// LOADED, NOT STREAMED: a run's output is thousands of rows, not millions, and
// the projection needs random access across all of it.
//
// RESOURCES ARE NOT LOADED FROM cloud_resource. That table is unique on
// (workspace_id, native_id) and its upsert reassigns connector_id to the last
// scanner, so on the graph branch a bucket two accounts named vanished from one
// account's snapshot and its grant became "*". Resource references are derived
// from THIS RUN'S OWN STATEMENT TEXT (§4.7), which no other connector's scan
// can remove.
type Snapshot struct {
	Run       models.CloudScanRun
	Connector models.CloudConnector
	// ScopeID is the iga_estate_scopes row for this connector's account,
	// upserted before the node passes because every canonical node references
	// it and NOTHING ELSE IN THE TREE POPULATES THAT TABLE.
	ScopeID    uuid.UUID
	Generation int

	Identities  []models.CloudIdentity        // roles, users, groups
	Memberships []models.CloudGroupMembership // user -> group
	Policies    []models.CloudPolicy          // managed and inline, with Document
	Attachments []models.CloudPolicyAttachment
	Workloads   []models.CloudWorkload
	Secrets     []models.CloudSecret // access keys

	// PodIdentity is this run's EKS pod-identity associations: cloud_assume_edge
	// rows with mechanism eks_pod_identity ONLY (§4.3, §4.5). No other
	// cloud_assume_edge row is read -- trust comes from the roles' trust
	// documents themselves, which keep the Deny statements and conditions
	// that table drops.
	PodIdentity []models.CloudAssumeEdge

	// Coverage is THIS RUN'S OWN report, decoded from the jsonb column stamped
	// at publish (024). NEVER cloud_connector.coverage, which a later scan has
	// overwritten.
	Coverage map[string]models.SurfaceCoverage

	// Documents that were UNREADABLE this run: a policy whose document could
	// not be fetched or parsed. What they declared goes stale instead of
	// ending (§4.10).
	UnreadablePolicy map[uuid.UUID]bool // cloud_policy.id
	// UnreadableTrust: a role whose trust document did not parse
	// (trust_parse_error <> ''), or was not collected at all (D-45). Its trust
	// edges go stale instead of ending (§4.10).
	UnreadableTrust map[uuid.UUID]bool // cloud_identity.id

	// ConfirmedBy holds the observation ids THIS run confirmed, keyed by
	// subject. Selected on last_confirmed_run_id = this run (024), because
	// content dedupe means an unchanged fact writes no new observation.
	ConfirmedBy map[SubjectRef][]uuid.UUID

	// ConnectedAccounts is every AWS account connected in this workspace, for
	// a resource reference's account_connected (§1.4).
	ConnectedAccounts map[string]bool

	identityByID       map[uuid.UUID]*models.CloudIdentity
	policyByID         map[uuid.UUID]*models.CloudPolicy
	identityNativeByID map[uuid.UUID]string

	// partitions is the list every row's partition is LOOKED UP from, built
	// once. Rows must never construct a partition separately.
	partitions []Partition
}

// SubjectRef keys observations by what SURVIVES inventory deletion: the typed
// subject kind and subject_native_id, verbatim.
type SubjectRef struct {
	Kind     string // identity | policy | workload
	NativeID string
}

// IdentityByID returns a collected identity of this snapshot, or nil.
func (s *Snapshot) IdentityByID(id *uuid.UUID) *models.CloudIdentity {
	if id == nil {
		return nil
	}
	s.index()
	return s.identityByID[*id]
}

// Roles returns this snapshot's IAM roles, in snapshot order: the identities
// that carry a trust document.
func (s *Snapshot) Roles() []models.CloudIdentity {
	var out []models.CloudIdentity
	for _, ci := range s.Identities {
		if ci.Kind == models.CloudIdentityIAMRole {
			out = append(out, ci)
		}
	}
	return out
}

// PolicyByID returns a collected policy of this snapshot, or nil.
func (s *Snapshot) PolicyByID(id uuid.UUID) *models.CloudPolicy {
	s.index()
	return s.policyByID[id]
}

// IdentityNativeID returns the native id of ANY cloud_identity a workload
// references, whatever generation it sits at -- how not_in_scan still names
// the role. Empty when unknown.
func (s *Snapshot) IdentityNativeID(id uuid.UUID) string {
	s.index()
	return s.identityNativeByID[id]
}

// SetReferencedIdentity records the native id of an identity outside this
// run's generation, for IdentityNativeID. Load calls it; so can a test.
func (s *Snapshot) SetReferencedIdentity(id uuid.UUID, nativeID string) {
	s.index()
	s.identityNativeByID[id] = nativeID
}

func (s *Snapshot) index() {
	if s.identityByID != nil {
		return
	}
	s.identityByID = make(map[uuid.UUID]*models.CloudIdentity, len(s.Identities))
	s.identityNativeByID = make(map[uuid.UUID]string, len(s.Identities))
	for i := range s.Identities {
		s.identityByID[s.Identities[i].ID] = &s.Identities[i]
		s.identityNativeByID[s.Identities[i].ID] = s.Identities[i].NativeID
	}
	s.policyByID = make(map[uuid.UUID]*models.CloudPolicy, len(s.Policies))
	for i := range s.Policies {
		s.policyByID[s.Policies[i].ID] = &s.Policies[i]
	}
}

// RegionsAttempted derives the regions this run tried, from the coverage
// report's own surface keys -- "what did THIS RUN look at", never config.
func (s *Snapshot) RegionsAttempted() []string {
	seen := map[string]bool{}
	for name := range s.Coverage {
		if svc, region, ok := strings.Cut(name, ":"); ok && region != "" {
			switch svc {
			case "lambda", "ecs", "ec2", "bedrock-agents", "bedrock-agentcore", "agentcore-gateways",
				"compute":
				seen[region] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// Partition is the unit reconciliation reasons about (§4.10).
//
// Getting its definition wrong is how a scan of one account deletes another
// account's graph, so every field here is load-bearing.
type Partition struct {
	// The evidence boundary. Reconciliation NEVER crosses it.
	ScopeID     uuid.UUID
	ConnectorID uuid.UUID

	Class            string // identity | workload | resource | entitlement | policy ("" for edges)
	RelationshipType string // for Target == "relationship"
	Target           string // "" for nodes | "relationship" | "assignment" | "access_edge"
	Kind             string // identity kind, workload service, or can_assume mechanism family
	Region           string // workload partitions only

	// RequiredSurfaces: every surface that must be REACHED before this
	// partition may close anything. For these, ABSENT MEANS DID NOT LOOK.
	RequiredSurfaces []string
	// RequiredScanners: scanner-level failure markers that VETO this partition
	// if PRESENT and not reached. Presence proves failure; absence proves
	// nothing on its own.
	RequiredScanners []string
}

// Key is the partition's stable identity and the value stamped on every row:
// scope, connector, target, class, relationship type, kind, region, and the
// SORTED required surfaces. It keys iga_projection_state (033),
// lastGenerationFor, every edge's partition_key and the publication manifest --
// one value, four call sites.
//
// Scope and connector are part of it (§4.8, 033: "keyed by partition, which
// covers scope and connector"). Without them two accounts produce the same
// keys, and a cumulative manifest (manifestOf) would let one account's run
// overwrite the other's under the same key (D-57). Frozen once deployed (D-60).
func (p Partition) Key() string {
	target := p.Target
	if target == "" {
		target = "node"
	}
	parts := []string{p.ScopeID.String(), p.ConnectorID.String(), target, p.Class, p.RelationshipType, p.Kind, p.Region}
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
			return models.CloudCoverageUnknown
		}
		if cov.State != models.CloudCoverageReached {
			worst = cov.State
		}
	}
	return worst
}

// Partitions enumerates every partition this run is responsible for (§4.10).
//
// NAMED FIELDS, ALWAYS. Positional literals silently mis-assign the moment a
// field is added.
func Partitions(snap *Snapshot) []Partition {
	sc, cn := snap.ScopeID, snap.Run.ConnectorID
	iam := []string{models.SurfaceIAMRoles, models.SurfaceIAMUsers, models.SurfaceIAMGroups, models.SurfaceIAMPolicies}
	// policy_documents is deliberately absent: unreadable documents are
	// protected ROW BY ROW (Exclusions), not by vetoing the whole account.
	perm := iam
	veto := []string{models.SurfacePermissionScan}

	ps := []Partition{
		// Identities, one partition per kind: a denied users read must not
		// block role reconciliation, nor a good roles read license closing users.
		{ScopeID: sc, ConnectorID: cn, Class: models.ObjectIdentity, Kind: models.CloudIdentityIAMRole,
			RequiredSurfaces: []string{models.SurfaceIAMRoles}},
		{ScopeID: sc, ConnectorID: cn, Class: models.ObjectIdentity, Kind: models.CloudIdentityIAMUser,
			RequiredSurfaces: []string{models.SurfaceIAMUsers}},
		{ScopeID: sc, ConnectorID: cn, Class: models.ObjectIdentity, Kind: models.CloudIdentityIAMGroup,
			RequiredSurfaces: []string{models.SurfaceIAMGroups}},

		// Policies, statements and resource references come from the same read
		// and reconcile on the same evidence.
		{ScopeID: sc, ConnectorID: cn, Class: models.ObjectPolicy, RequiredSurfaces: iam, RequiredScanners: veto},
		{ScopeID: sc, ConnectorID: cn, Class: models.ObjectEntitlement, RequiredSurfaces: perm, RequiredScanners: veto},
		{ScopeID: sc, ConnectorID: cn, Class: models.ObjectResource, RequiredSurfaces: perm, RequiredScanners: veto},

		{ScopeID: sc, ConnectorID: cn, Target: "assignment", RequiredSurfaces: iam, RequiredScanners: veto},
		{ScopeID: sc, ConnectorID: cn, Target: "access_edge", RequiredSurfaces: perm, RequiredScanners: veto},
		{ScopeID: sc, ConnectorID: cn, Target: "relationship", RelationshipType: models.RelTypeMemberOf,
			RequiredSurfaces: []string{models.SurfaceIAMUsers, models.SurfaceIAMGroups}},
		{ScopeID: sc, ConnectorID: cn, Target: "relationship", RelationshipType: models.RelTypeCanAssume, Kind: "trust",
			RequiredSurfaces: []string{models.SurfaceIAMRoles}, RequiredScanners: veto},
		{ScopeID: sc, ConnectorID: cn, Target: "relationship", RelationshipType: models.RelTypeCanAssume,
			Kind:             models.MechanismEKSPodIdentity,
			RequiredSurfaces: []string{models.SurfaceEKSPodIdentity, models.SurfaceIAMRoles}, RequiredScanners: veto},
	}

	// Workloads: per SERVICE per REGION -- the grain the scanner reports at.
	// compute:<region> appears only on failure or not_selected, so it is a
	// veto (presence = failure), never a required surface.
	for _, region := range snap.RegionsAttempted() {
		gate := []string{models.SurfaceWorkloadScan, models.SurfaceCompute(region)}
		for _, svc := range workloadServices {
			surf := svc + ":" + region
			ps = append(ps,
				Partition{ScopeID: sc, ConnectorID: cn, Class: models.ObjectWorkload, Kind: svc, Region: region,
					RequiredSurfaces: []string{surf}, RequiredScanners: gate},
				Partition{ScopeID: sc, ConnectorID: cn, Target: "relationship", RelationshipType: models.RelTypeExecutesAs,
					Kind: svc, Region: region,
					RequiredSurfaces: []string{surf, models.SurfaceIAMRoles}, RequiredScanners: gate})
		}
		ps = append(ps, Partition{ScopeID: sc, ConnectorID: cn, Target: "relationship",
			RelationshipType: models.RelTypeTaskExecutionRole, Kind: "ecs", Region: region,
			RequiredSurfaces: []string{"ecs:" + region, models.SurfaceIAMRoles}, RequiredScanners: gate})
	}
	return ps
}

// KnownSurfaces is every surface name a partition may require, for the
// vocabulary assertion. A partition naming a surface no report ever contains
// can NEVER satisfy canEnd, so its relationships stay stale forever -- silent,
// and it looks like working caution.
func KnownSurfaces(regions []string) map[string]bool {
	known := map[string]bool{
		models.SurfaceIAMRoles:        true,
		models.SurfaceIAMUsers:        true,
		models.SurfaceIAMGroups:       true,
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

// AssertPartitionVocabulary reports every surface a partition names that no
// coverage report could ever contain.
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
// collector reports, in a stable order.
var workloadServices = []string{
	"lambda", "ecs", "ec2",
	"bedrock-agents", "bedrock-agentcore", "agentcore-gateways",
}

// workloadSurfacePrefix maps cloud_workload.RuntimeKind to the prefix its
// coverage surface is reported under. RuntimeKind and the surface prefix are
// DIFFERENT VOCABULARIES -- lambda_function vs lambda -- so this mapping is the
// only correct way from one to the other. EXHAUSTIVE: a missing kind makes
// PartitionFor panic in tests, which is the point.
var workloadSurfacePrefix = map[string]string{
	models.WorkloadLambdaFunction:     "lambda",
	models.WorkloadECSTaskDefinition:  "ecs",
	models.WorkloadEC2Instance:        "ec2",
	models.WorkloadBedrockAgent:       "bedrock-agents",
	models.WorkloadBedrockAgentCoreRT: "bedrock-agentcore",
	models.WorkloadBedrockAgentCoreGW: "agentcore-gateways",
}

func (s *Snapshot) ensurePartitions() {
	if s.partitions == nil {
		s.partitions = Partitions(s)
	}
}

// PartitionFor returns the Partition that evidences a NODE, from the SAME list
// Partitions() builds -- looked up, never reconstructed -- so the key a row is
// written under and the key it is reconciled under are one value by
// construction. No match PANICS; it must never fall back to a default.
func (s *Snapshot) PartitionFor(class, kind, region string) Partition {
	s.ensurePartitions()
	for _, p := range s.partitions {
		if p.Target == "" && p.Matches(class, kind, region) {
			return p
		}
	}
	panic(fmt.Sprintf("igagraph: no partition for class=%q kind=%q region=%q", class, kind, region))
}

// EdgePartitionFor is PartitionFor's counterpart for edges.
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
		return p.Kind == kind
	case models.ObjectWorkload:
		prefix, ok := workloadSurfacePrefix[kind]
		return ok && p.Kind == prefix && p.Region == region
	default:
		return true // policy, entitlement, resource: one partition per connector
	}
}

// MatchesEdge is the membership predicate for edges.
func (p Partition) MatchesEdge(relOrTarget, kind, region string) bool {
	switch relOrTarget {
	case "assignment", "access_edge":
		return p.Target == relOrTarget
	}
	if p.Target != "relationship" || p.RelationshipType != relOrTarget {
		return false
	}
	switch relOrTarget {
	case models.RelTypeExecutesAs:
		prefix, ok := workloadSurfacePrefix[kind]
		return ok && p.Kind == prefix && p.Region == region
	case models.RelTypeTaskExecutionRole:
		return p.Region == region
	case models.RelTypeCanAssume:
		return p.Kind == kind
	default:
		return true // member_of: one partition per connector
	}
}
