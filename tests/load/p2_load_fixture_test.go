package load

// The T6.10 fixture (SPEC-iga-phase2-graph.md §5.6): one workspace of 10 000
// AWS workloads with the identities, policies, statements, grants, resource
// references, relationships and history such an estate carries, written
// DIRECTLY into the iga_* / cloud_* tables with COPY (p2_load_copy_test.go).
//
// Projection throughput is not a §5.6 target, so nothing here runs the
// projector. Instead the generator makes the projector's decisions itself,
// with the projector's own exported helpers wherever they exist -- source
// keys (igagraph.Key and friends), partition keys (Snapshot.PartitionFor /
// EdgePartitionFor over the run's coverage), statement keys and content
// hashes (awsdiscovery.ParsePolicyDocument + igagraph.StatementKey), trust
// principals (awsdiscovery.ParseTrustDocument + TrustStatement.Subjects) --
// so every key a read rebuilds (D-27e, D-57) matches what it finds, and every
// time is a publication's published_at (D-26), so Changes attributes each
// event to its revision and run (D-27a).
//
// The ratios are stated once, in loadFullShape; RESULTS.md repeats them.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

// loadFixtureName prefixes every workspace a fixture build creates, so a
// rebuild can find and wipe the previous one (loadWipe).
const loadFixtureName = "p2-load"

// loadShape is the fixture's size and ratios. Every count is per workspace.
type loadShape struct {
	Workloads  int // across all accounts and regions
	Roles      int
	Users      int
	Groups     int
	AWSManaged int // AWS-managed policies, one object shared by every account
	Customer   int // customer-managed policies
	Inline     int // inline policies (on roles, users and groups)
	Resources  int // distinct resource references the statements name
	Cycles     int // scan cycles; each cycle publishes one run per account
}

// loadFullShape is the §5.6 fixture: 10 000 workloads per workspace, with
// ~3 000 roles, 500 users, 50 groups, 2 000 policies of ~6 statements each
// (~12 000 statements), 10 000 distinct resource references named by ~20 000
// statement targets, and four cycles of history across three accounts (twelve
// publications).
var loadFullShape = loadShape{
	Workloads: 10000, Roles: 3000, Users: 500, Groups: 50,
	AWSManaged: 150, Customer: 1450, Inline: 400,
	Resources: 10000, Cycles: 4,
}

// loadNoiseShape is a second, smaller workspace in the same tables, so no
// plan can win by the measured workspace being the only tenant.
var loadNoiseShape = loadShape{
	Workloads: 2000, Roles: 600, Users: 100, Groups: 10,
	AWSManaged: 60, Customer: 290, Inline: 80,
	Resources: 2000, Cycles: 4,
}

// loadAllRegions is the region list the collector reports compute:<region>
// not_selected for when a region is outside the connector's selection -- the
// same seventeen the lab's coverage carries, so the partition set (one per
// service per region, ~232 per connector) is the production one.
var loadAllRegions = []string{
	"us-east-1", "us-east-2", "us-west-1", "us-west-2", "ca-central-1",
	"eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
	"ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
	"ap-southeast-1", "ap-southeast-2", "sa-east-1",
}

// loadWorkloadSurfaces are the per-region workload surfaces the collector
// reports for a selected region.
var loadWorkloadSurfaces = []string{
	"lambda", "ecs", "ec2", "bedrock-agents", "bedrock-agentcore", "agentcore-gateways",
	"agentcore-workload-identities", "agentcore-credential-providers",
	"cloudtrail-events", "cloudtrail-status",
}

// loadAcct is one connected AWS account of the workspace.
type loadAcct struct {
	k       int
	id      string
	label   string
	regions []string
	share   float64 // of every per-account count
	conn    uuid.UUID
	scope   uuid.UUID
	// snap carries the account's scope, connector and the last run's
	// coverage, which is all Partitions() reads: every partition key comes
	// from it, exactly as the projector derives them.
	snap *igagraph.Snapshot
	runs []*loadRun // by cycle-1
}

// loadRun is one published scan run and the publication it produced.
type loadRun struct {
	id    uuid.UUID
	acct  *loadAcct
	cycle int
	rev   int64
	// at is the projection pass time: iga_publication.published_at, and every
	// valid_from, valid_to, last_confirmed_at, first_seen_at and occurred_at
	// that pass wrote (D-26).
	at  time.Time
	cov models.ScanCoverage
}

// loadGen generates one workspace's fixture.
type loadGen struct {
	rng   *rand.Rand
	rows  *loadRows
	ws    uuid.UUID
	name  string
	shape loadShape
	base  time.Time
	user  uuid.UUID
	accts []*loadAcct
	pubs  []*loadRun // by rev-1

	// External accounts the estate references but does not connect.
	external []string

	idents     []*loadIdent
	identByARN map[string]*loadIdent
	policies   []*loadPolicy
	resources  map[string]*loadResource // by reference text
	resList    []*loadResource
	externals  map[string]*loadExternal // by source key
	workloads  []*loadWorkload

	grantsByHolder map[*loadIdent][]uuid.UUID

	// obsHash keeps every observation content hash unique, as the collector's
	// dedupe index requires.
	obsSeq int

	h loadHandles
}

// loadHandles are the objects the measurement reads: typical samples and the
// heaviest object of each kind, chosen from what was generated.
type loadHandles struct {
	workloads      []uuid.UUID // typical, rotated per iteration
	roles          []uuid.UUID
	users          []uuid.UUID
	resources      []uuid.UUID
	externals      []uuid.UUID
	grants         []uuid.UUID
	executes       []uuid.UUID // executes_as relationships
	canAssume      []uuid.UUID
	assignments    []uuid.UUID
	hubRole        uuid.UUID // the execution role the most workloads use
	hubRoleUsers   int
	ecsExecRole    uuid.UUID // task_execution_role of every ECS workload in account A
	ecsExecUsers   int
	hubGroup       uuid.UUID
	starResource   uuid.UUID // "*": the reference the most statements name
	hotBucket      uuid.UUID // the most-named exact resource
	lambdaService  uuid.UUID // lambda.amazonaws.com, trusted by every Lambda role
	switchedWL     []uuid.UUID
	groupedGrants  []uuid.UUID // 50 grants of one holder, one policy: a grouped edge (D-79)
	coverageClaims []string    // coverage:<run>:<surface>
	activeWL       int         // readable active workloads (the unfiltered list total)
	activeIdent    int
	activeRes      int
	firstAcct      string
}

func newLoadGen(seed int64, name string, shape loadShape, accounts []loadAcct) *loadGen {
	g := &loadGen{
		rng:        rand.New(rand.NewSource(seed)),
		rows:       newLoadRows(),
		name:       name,
		shape:      shape,
		base:       time.Date(2026, 8, 1, 6, 0, 0, 0, time.UTC),
		identByARN: map[string]*loadIdent{},
		resources:  map[string]*loadResource{},
		externals:  map[string]*loadExternal{},

		grantsByHolder: map[*loadIdent][]uuid.UUID{},
		external:   []string{"444444444444", "555555555555"},
	}
	g.ws = g.uuid()
	g.user = g.uuid()
	for i := range accounts {
		a := accounts[i]
		a.k = i
		g.accts = append(g.accts, &a)
	}
	return g
}

// uuid draws an id from the generator's seeded stream, so a rebuild with the
// same seed produces the same ids.
func (g *loadGen) uuid() uuid.UUID {
	id, err := uuid.NewRandomFromReader(g.rng)
	if err != nil {
		panic(err)
	}
	return id
}

// chance is a Bernoulli draw.
func (g *loadGen) chance(p float64) bool { return g.rng.Float64() < p }

// pick returns one element uniformly.
func loadPick[T any](g *loadGen, xs []T) T { return xs[g.rng.Intn(len(xs))] }

// zipf returns an index in [0, n) with a Zipf-like skew: index 0 is the most
// frequent. Estates are skewed this way -- one default Lambda role, one busy
// bucket -- and the heaviest object is what a tab's p95 must survive.
func (g *loadGen) zipf(n int, s float64) int {
	if n <= 1 {
		return 0
	}
	// Inverse-CDF sampling of a continuous power law over [1, n+1).
	u := g.rng.Float64()
	if s == 1 {
		return int(math.Min(float64(n-1), math.Floor(math.Pow(float64(n+1), u)-1)))
	}
	a := 1 - s
	x := math.Pow(u*(math.Pow(float64(n+1), a)-1)+1, 1/a)
	i := int(math.Floor(x)) - 1
	if i < 0 {
		i = 0
	}
	if i >= n {
		i = n - 1
	}
	return i
}

// share splits a total across the accounts by their share, the remainder to
// the first.
func (g *loadGen) share(total int) []int {
	out := make([]int, len(g.accts))
	sum := 0
	for i, a := range g.accts {
		out[i] = int(math.Round(float64(total) * a.share))
		sum += out[i]
	}
	out[0] += total - sum
	return out
}

// hash is a deterministic hex digest of the parts, for content hashes and
// document hashes the generator invents.
func loadHash(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0x1f})
	}
	return hex.EncodeToString(h.Sum(nil))
}

/* ------------------------------ time and runs ------------------------------ */

// at is the pass time of account k's run in a cycle: cycles a day apart,
// accounts twenty minutes apart within a cycle, microsecond precision (D-26
// joins on the exact value).
func (g *loadGen) at(cycle, k int) time.Time {
	return g.base.Add(time.Duration(cycle-1)*24*time.Hour + time.Duration(k)*20*time.Minute +
		time.Duration(k*1000+cycle*17)*time.Microsecond).Truncate(time.Microsecond)
}

// run is account a's run of a cycle.
func (a *loadAcct) run(cycle int) *loadRun { return a.runs[cycle-1] }

// setup writes the workspace, its user, the connectors, estate scopes, runs,
// publications and projection watermarks.
func (g *loadGen) setup() {
	g.rows.add("workspaces", g.ws, g.name, nil, g.ws, "team", g.ws.String()+".load", g.ws.String()+"@load.local",
		"active", g.base.Add(-48*time.Hour), g.base.Add(-48*time.Hour))
	g.rows.add("users", g.user, g.ws, "reviewer@"+g.ws.String()[:8]+".load", "Load Reviewer",
		g.base.Add(-48*time.Hour), g.base.Add(-48*time.Hour))

	C := g.shape.Cycles
	for _, a := range g.accts {
		a.conn, a.scope = g.uuid(), g.uuid()
		for c := 1; c <= C; c++ {
			a.runs = append(a.runs, &loadRun{id: g.uuid(), acct: a, cycle: c, at: g.at(c, a.k)})
		}
	}
	// Revisions in publication order: cycle by cycle, account by account.
	for c := 1; c <= C; c++ {
		for _, a := range g.accts {
			r := a.run(c)
			g.pubs = append(g.pubs, r)
			r.rev = int64(len(g.pubs))
		}
	}
	// Coverage needs the object counts, so it is stamped in finish(); the
	// partition keys need only which regions each run attempted, which the
	// coverage's surface NAMES fix -- so a provisional coverage builds the
	// snapshot now.
	for _, a := range g.accts {
		cov := g.coverage(a, C, nil)
		a.snap = &igagraph.Snapshot{
			Run:       models.CloudScanRun{ID: a.run(C).id, WorkspaceID: g.ws, ConnectorID: a.conn, Generation: C},
			Connector: models.CloudConnector{ID: a.conn, WorkspaceID: g.ws, Provider: "aws", ScopeKind: "account", ScopeID: a.id},
			ScopeID:   a.scope,
			Coverage:  cov.Surfaces,
		}
	}
}

// loadCounts are the per-account object counts the coverage report states.
type loadCounts struct {
	roles, users, groups, policies int
	workloads                      map[string]int // surface -> count
}

// coverage is account a's run report for a cycle. The last cycle carries the
// fixture's partial coverage: in the third account, lambda:us-east-1 is
// partial (some functions not read) and resource_policies denied; in the
// second, ecs:us-west-2 is denied. Everything else is reached, unselected
// regions not_selected, organizations unsupported -- the lab's vocabulary.
func (g *loadGen) coverage(a *loadAcct, cycle int, n *loadCounts) models.ScanCoverage {
	C := g.shape.Cycles
	count := func(get func(*loadCounts) int) int {
		if n == nil {
			return 0
		}
		return get(n)
	}
	reached := func(c int) models.SurfaceCoverage { return models.SurfaceCoverage{State: "reached", Count: c} }
	s := map[string]models.SurfaceCoverage{
		models.SurfaceIAMRoles:            reached(count(func(n *loadCounts) int { return n.roles })),
		models.SurfaceIAMUsers:            reached(count(func(n *loadCounts) int { return n.users })),
		models.SurfaceIAMGroups:           reached(count(func(n *loadCounts) int { return n.groups })),
		models.SurfaceIAMPolicies:         reached(count(func(n *loadCounts) int { return n.policies })),
		models.SurfaceIAMAccessKeys:       reached(0),
		models.SurfaceIAMCredentialReport: reached(0),
		models.SurfaceOIDCProviders:       reached(0),
		models.SurfaceEKSPodIdentity:      reached(0),
		models.SurfaceActivity:            reached(0),
		models.SurfaceResourcePolicies:    reached(0),
		models.SurfaceOrganizations: {State: "unsupported",
			Error: "AWS Organizations and service control policies (SCPs) are not collected by AuthSec"},
	}
	selected := map[string]bool{}
	for _, r := range a.regions {
		selected[r] = true
		for _, svc := range loadWorkloadSurfaces {
			name := svc + ":" + r
			c := 0
			if n != nil {
				c = n.workloads[name]
			}
			s[name] = reached(c)
		}
	}
	for _, r := range loadAllRegions {
		if !selected[r] {
			s[models.SurfaceCompute(r)] = models.SurfaceCoverage{State: "not_selected",
				Error: "region not in the connector's selected scope"}
		}
	}
	status := "complete"
	if cycle == C {
		switch a.k {
		case 1:
			s["ecs:us-west-2"] = models.SurfaceCoverage{State: "denied", API: "ecs:ListTaskDefinitions",
				ErrorCode: "AccessDenied", Error: "ecs:ListTaskDefinitions AccessDenied"}
			status = "partial"
		case 2:
			c := s["lambda:us-east-1"].Count
			s["lambda:us-east-1"] = models.SurfaceCoverage{State: "partial", Count: c, API: "lambda:GetFunction",
				ErrorCode: "ThrottlingException", Error: "some functions could not be read: lambda:GetFunction ThrottlingException"}
			s[models.SurfaceResourcePolicies] = models.SurfaceCoverage{State: "denied", API: "s3:GetBucketPolicy",
				ErrorCode: "AccessDenied", Error: "resource policies could not be read: s3:GetBucketPolicy AccessDenied"}
			status = "partial"
		}
	}
	at := g.at(cycle, a.k)
	started, finished := at.Add(-9*time.Minute), at.Add(-5*time.Second)
	return models.ScanCoverage{Generation: cycle, Status: status, StartedAt: &started, FinishedAt: &finished,
		Surfaces: s, Counters: map[string]int{"identities_total": count(func(n *loadCounts) int { return n.roles + n.users + n.groups })}}
}

// staleAtLast reports whether the last cycle's coverage left a workload of
// this kind and region unconfirmed: the partial or denied surface above.
func (g *loadGen) staleAtLast(a *loadAcct, runtimeKind, region string) bool {
	switch {
	case a.k == 1 && runtimeKind == models.WorkloadECSTaskDefinition && region == "us-west-2":
		return true // denied: nothing was read
	case a.k == 2 && runtimeKind == models.WorkloadLambdaFunction && region == "us-east-1":
		return g.chance(0.3) // partial: about a third were not read
	}
	return false
}

// nodePart is the partition key of a node on account a.
func (a *loadAcct) nodePart(class, kind, region string) string {
	return a.snap.PartitionFor(class, kind, region).Key()
}

// edgePart is the partition key of an edge on account a.
func (a *loadAcct) edgePart(relOrTarget, kind, region string) string {
	return a.snap.EdgePartitionFor(relOrTarget, kind, region).Key()
}

/* ------------------------------ node history ------------------------------- */

// loadLife is a node's history on one account: first seen in cycle first,
// retired (support ended, lifecycle retired) in cycle retired, restored in
// cycle restored; stale when the last run could not confirm it. 0 = never.
type loadLife struct {
	first, retired, restored int
	stale                    bool
}

// live reports whether the node is active at the current revision.
func (l loadLife) live() bool { return l.retired == 0 || l.restored > 0 }

// lastCycle is the cycle whose run last confirmed the node.
func (l loadLife) lastCycle(C int) int {
	switch {
	case !l.live():
		return l.retired - 1
	case l.stale:
		return C - 1
	}
	return C
}

// lifecycle is the node row's lifecycle and retired_reason.
func (l loadLife) lifecycle() (string, string) {
	if !l.live() {
		return models.IGALifecycleRetired, models.RetiredUnsupported
	}
	return models.IGALifecycleActive, ""
}

// supportState is the support row's state and ended_reason.
func (l loadLife) supportState() (string, string) {
	switch {
	case !l.live():
		return models.RelEnded, models.EndedNotSeen
	case l.stale:
		return models.RelStale, ""
	}
	return models.RelCurrent, ""
}

// support writes one iga_object_support row. column names the node's typed
// FK column (identity_account_id, workload_id, resource_id, entitlement_id,
// policy_id).
func (g *loadGen) support(a *loadAcct, column string, id uuid.UUID, part string, l loadLife) {
	var ident, wl, res, ent, pol *uuid.UUID
	switch column {
	case "identity_account_id":
		ident = &id
	case "workload_id":
		wl = &id
	case "resource_id":
		res = &id
	case "entitlement_id":
		ent = &id
	case "policy_id":
		pol = &id
	default:
		panic("load: support column " + column)
	}
	state, reason := l.supportState()
	last := a.run(l.lastCycle(g.shape.Cycles))
	g.rows.add("iga_object_support", g.uuid(), g.ws, ident, wl, res, ent, pol, a.conn, part, state,
		g.at(l.first, a.k), last.id, last.at, reason)
}

// events writes a node's lifecycle events (036): first_seen, and retired /
// restored where its history has them, each at its pass's time and revision.
func (g *loadGen) events(a *loadAcct, column string, id uuid.UUID, l loadLife) {
	add := func(cycle int, event, reason string) {
		r := a.run(cycle)
		var ident, wl, res, ent, pol *uuid.UUID
		switch column {
		case "identity_account_id":
			ident = &id
		case "workload_id":
			wl = &id
		case "resource_id":
			res = &id
		case "entitlement_id":
			ent = &id
		case "policy_id":
			pol = &id
		}
		g.rows.add("iga_lifecycle_event", g.uuid(), g.ws, r.rev, r.id, r.at, event, reason, ident, wl, res, ent, pol)
	}
	add(l.first, "first_seen", "")
	if l.retired > 0 {
		add(l.retired, "retired", models.RetiredUnsupported)
	}
	if l.restored > 0 {
		add(l.restored, "restored", "")
	}
}

/* ------------------------------ edge history ------------------------------- */

// loadSpan is one row of an edge's history: valid from cycle from until
// cycle to (0 = still valid), stale when the last run did not confirm it.
type loadSpan struct {
	from, to int
	reason   string // ended_reason when to > 0
	stale    bool
}

// state is the edge row's state and ended_reason.
func (s loadSpan) state() (string, string) {
	switch {
	case s.to > 0:
		return models.RelEnded, s.reason
	case s.stale:
		return models.RelStale, ""
	}
	return models.RelCurrent, ""
}

// lastCycle is the cycle whose run last confirmed the edge.
func (s loadSpan) lastCycle(C int) int {
	switch {
	case s.to > 0:
		return s.to - 1
	case s.stale:
		return C - 1
	}
	return C
}

// validTo is valid_to: the ending pass's time, nil while valid.
func (g *loadGen) validTo(a *loadAcct, s loadSpan) *time.Time {
	if s.to == 0 {
		return nil
	}
	t := g.at(s.to, a.k)
	return &t
}

// confirmedRuns are the runs that confirmed a span, first to last.
func (a *loadAcct) confirmedRuns(from, last int) []*loadRun {
	var out []*loadRun
	for c := from; c <= last; c++ {
		out = append(out, a.run(c))
	}
	return out
}

/* ------------------------------ observations ------------------------------- */

// loadObs is one cloud_observation: the collector's record of one fact
// version, first recorded by run first and last confirmed by run last.
type loadObs struct {
	id          uuid.UUID
	first, last int // cycles
}

// observe writes one observation for account a. subject is the typed FK
// (identity_id, workload_id or policy_id) or "" for none; native is the
// subject_native_id the evidence reader matches on.
func (g *loadGen) observe(a *loadAcct, subject string, subjectID *uuid.UUID, sourceAPI, surface, native string,
	facts map[string]any, first, last int) loadObs {
	g.obsSeq++
	var ident, wl, pol *uuid.UUID
	switch subject {
	case "identity_id":
		ident = subjectID
	case "workload_id":
		wl = subjectID
	case "policy_id":
		pol = subjectID
	}
	fr, lr := a.run(first), a.run(last)
	id := g.uuid()
	g.rows.add("cloud_observation", id, g.ws, a.conn, fr.id, first, ident, wl, pol, sourceAPI, surface, "",
		fr.at.Add(-6*time.Minute), fr.at.Add(-6*time.Minute), loadMarshal(facts),
		loadHash(g.ws.String(), native, sourceAPI, fmt.Sprint(g.obsSeq)), native, lr.id, lr.at.Add(-6*time.Minute),
		last-first+1)
	return loadObs{id: id, first: first, last: last}
}

// link writes the junction rows a projection pass writes for one edge: every
// observation of its subject that a run confirming the edge confirmed.
// Distinct by (edge, observation), as the junction's unique key requires.
func (g *loadGen) link(table string, edge uuid.UUID, span loadSpan, obs ...loadObs) {
	last := span.lastCycle(g.shape.Cycles)
	seen := map[uuid.UUID]bool{}
	for _, o := range obs {
		if o.id == uuid.Nil || seen[o.id] {
			continue
		}
		// The observation was confirmed by some run inside the span.
		if o.last < span.from || o.first > last {
			continue
		}
		seen[o.id] = true
		g.rows.add(table, g.uuid(), g.ws, edge, o.id, "supports", g.base)
	}
}

/* --------------------------- publications, state --------------------------- */

// finish stamps what needs every object first: each run's coverage (with its
// counts), the connectors, the publications' cumulative manifests (D-57) and
// the per-partition watermarks.
func (g *loadGen) finish(counts []map[int]*loadCounts) {
	C := g.shape.Cycles
	for _, a := range g.accts {
		for c := 1; c <= C; c++ {
			a.run(c).cov = g.coverage(a, c, counts[a.k][c])
		}
		last := a.run(C)
		attrs := models.AWSConnectorAttrs{DisplayName: a.label, Regions: a.regions, Partition: "aws",
			RoleARN: "arn:aws:iam::" + a.id + ":role/AuthSecCloudDiscovery"}
		created := g.base.Add(-24*time.Hour + time.Duration(a.k)*time.Minute)
		g.rows.add("cloud_connector", a.conn, g.ws, "aws", "account", a.id,
			"kv/data/secret/workspaces/"+g.ws.String()+"/cloud-discovery/aws/"+a.id, "active", C,
			loadMarshal(last.cov), loadMarshal(attrs), created, "admin", created, last.at)
		g.rows.add("iga_estate_scopes", a.scope, g.ws, "account", a.id, "unknown",
			igagraph.ScopeKey("aws", "account", a.id), created, last.at)
		for c := 1; c <= C; c++ {
			r := a.run(c)
			req := r.at.Add(-10 * time.Minute)
			started := r.at.Add(-9 * time.Minute)
			pub := r.at.Add(-2 * time.Second)
			g.rows.add("cloud_scan_run", r.id, g.ws, a.conn, c, "published", "scheduled", "", 1, 1,
				req, started, pub, pub, loadMarshal(r.cov))
		}
	}
	// Cumulative manifests: every partition of every account, at the run of
	// that account the revision was built from.
	for _, r := range g.pubs {
		manifest := map[string]string{}
		for _, a := range g.accts {
			var at *loadRun
			for c := 1; c <= C; c++ {
				if a.run(c).rev <= r.rev {
					at = a.run(c)
				}
			}
			if at == nil {
				continue
			}
			for _, p := range igagraph.Partitions(a.snap) {
				manifest[p.Key()] = at.id.String()
			}
		}
		g.rows.add("iga_publication", g.ws, r.rev, r.at, r.id, loadMarshal(manifest))
	}
	for _, a := range g.accts {
		last := a.run(C)
		snap := *a.snap
		snap.Coverage = last.cov.Surfaces
		for _, p := range igagraph.Partitions(&snap) {
			g.rows.add("iga_projection_state", g.uuid(), g.ws, a.scope, a.conn, p.Class, p.RelationshipType,
				p.Key(), last.id, C, p.CoverageSummary(&snap), true, last.at)
		}
	}
}

// sortedKeys returns a map's keys in order, for deterministic output.
func loadSortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
