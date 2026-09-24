package load

// Fixture workloads: the collector's rows and observations, the graph rows,
// executes_as and ECS task_execution_role edges (projectExecution), the
// classification history (§5.5), and the build that ties the fixture
// together.

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

// loadWorkload is one runtime.
type loadWorkload struct {
	id, cloudID uuid.UUID
	acct        *loadAcct
	kind        string
	name        string
	region      string
	native      string // cloud_workload.native_id: an ARN, or a bare id (EC2, Bedrock)
	arn         string
	life        loadLife
	role        *loadIdent // the execution role now (nil: none, or not in inventory)
	prevRole    *loadIdent // the role before switchAt
	switchAt    int
	execState   string
	execARN     string
	class       string
	classVer    int
	obs         loadObs
}

// loadKindSurface is a runtime kind's coverage-surface prefix and source API.
var loadKindSurface = map[string][2]string{
	models.WorkloadLambdaFunction:     {"lambda", "lambda:ListFunctions"},
	models.WorkloadECSTaskDefinition:  {"ecs", "ecs:DescribeTaskDefinition"},
	models.WorkloadEC2Instance:        {"ec2", "ec2:DescribeInstances"},
	models.WorkloadBedrockAgent:       {"bedrock-agents", "bedrock:GetAgent"},
	models.WorkloadBedrockAgentCoreRT: {"bedrock-agentcore", "bedrock-agentcore:GetAgentRuntime"},
	models.WorkloadBedrockAgentCoreGW: {"agentcore-gateways", "bedrock-agentcore:GetGateway"},
}

// genWorkloads generates every account's runtimes: Lambda 58%, ECS 20%, EC2
// 15%, Bedrock agents 4%, AgentCore runtimes 2%, gateways 1%. Execution roles
// are drawn with a Zipf skew, so one default role carries hundreds of
// workloads. Forty names in the second account repeat the first account's
// (staging mirrors production), and some workloads change role, arrive late,
// retire and come back.
func (g *loadGen) genWorkloads() {
	per := g.share(g.shape.Workloads)
	byService := map[*loadAcct]map[string][]*loadIdent{}
	for _, a := range g.accts {
		byService[a] = map[string][]*loadIdent{}
		for _, i := range g.idents {
			if i.acct == a && i.service != "" && i.name != "ecsTaskExecutionRole" && i.life.live() && i.life.first == 1 {
				byService[a][i.service] = append(byService[a][i.service], i)
			}
		}
	}
	var mirror []string
	for _, a := range g.accts {
		for n := 0; n < per[a.k]; n++ {
			w := &loadWorkload{id: g.uuid(), cloudID: g.uuid(), acct: a, life: loadLife{first: 1},
				class: models.ClassificationUnclassified}
			service := ""
			switch r := g.rng.Float64(); {
			case r < 0.58:
				w.kind, service = models.WorkloadLambdaFunction, "lambda.amazonaws.com"
			case r < 0.78:
				w.kind, service = models.WorkloadECSTaskDefinition, "ecs-tasks.amazonaws.com"
			case r < 0.93:
				w.kind, service = models.WorkloadEC2Instance, "ec2.amazonaws.com"
			case r < 0.97:
				w.kind, service = models.WorkloadBedrockAgent, "bedrock.amazonaws.com"
			case r < 0.99:
				w.kind, service = models.WorkloadBedrockAgentCoreRT, "bedrock.amazonaws.com"
			default:
				w.kind, service = models.WorkloadBedrockAgentCoreGW, "bedrock.amazonaws.com"
			}
			w.region = a.regions[0]
			if len(a.regions) > 1 && g.chance(0.3) {
				w.region = a.regions[1]
			}
			w.name = fmt.Sprintf("%s-%s-%d", loadPick(g, loadTeams), loadPick(g, loadComponents), n)
			if a.k == 0 && w.kind == models.WorkloadLambdaFunction && w.region == "us-east-1" && len(mirror) < 40 {
				mirror = append(mirror, w.name)
			}
			if a.k == 1 && n < len(mirror) {
				w.kind, service, w.region, w.name = models.WorkloadLambdaFunction, "lambda.amazonaws.com", "us-east-1", mirror[n]
			}
			switch w.kind {
			case models.WorkloadLambdaFunction:
				w.native = fmt.Sprintf("arn:aws:lambda:%s:%s:function:%s", w.region, a.id, w.name)
			case models.WorkloadECSTaskDefinition:
				w.native = fmt.Sprintf("arn:aws:ecs:%s:%s:task-definition/%s:%d", w.region, a.id, w.name, 1+g.rng.Intn(30))
			case models.WorkloadEC2Instance:
				w.native = fmt.Sprintf("i-0%016x", g.rng.Uint64()&0xffffffffffffffff)
			case models.WorkloadBedrockAgent:
				w.native = strings.ToUpper(fmt.Sprintf("%010x", g.rng.Uint64()))[:10]
			case models.WorkloadBedrockAgentCoreRT:
				w.native = fmt.Sprintf("%s-%010x", strings.ReplaceAll(w.name, "-", "_"), g.rng.Uint32())
			default:
				w.native = fmt.Sprintf("%s-gw-%08x", w.name, g.rng.Uint32())
			}
			w.arn = awsdiscovery.WorkloadARN("aws", w.kind, w.region, a.id, w.native)

			switch r := g.rng.Float64(); {
			case r < 0.04:
				w.life.first = 2
			case r < 0.06:
				w.life.first = 3
			case r < 0.08:
				w.life.retired = 3
				if g.chance(0.25) {
					w.life.restored = 4
				}
			}
			if w.life.live() && w.life.first < g.shape.Cycles && w.life.restored == 0 {
				w.life.stale = g.staleAtLast(a, w.kind, w.region)
			}

			// The execution identity (§4.6).
			roles := byService[a][service]
			switch {
			case w.kind == models.WorkloadEC2Instance && g.chance(0.03), len(roles) == 0:
				w.execState = models.ExecRoleNone
			case g.chance(0.01):
				w.execState = models.ExecRoleNotInInventory
				w.execARN = "arn:aws:iam::" + loadPick(g, g.external) + ":role/shared-exec-" + loadPick(g, loadTeams)
			default:
				w.execState = models.ExecRoleResolved
				w.role = roles[g.zipf(len(roles), 1.15)]
				if w.life.first == 1 && w.life.retired == 0 && g.chance(0.05) {
					w.prevRole, w.switchAt = w.role, 2
					w.role = roles[g.rng.Intn(len(roles))]
					if w.role == w.prevRole {
						w.prevRole, w.switchAt = nil, 0
					}
				}
			}
			switch w.kind {
			case models.WorkloadBedrockAgent, models.WorkloadBedrockAgentCoreRT:
				w.class = models.ClassificationProviderAgent
			}
			g.workloads = append(g.workloads, w)
		}
	}
}

// workloadRows writes every workload's rows and edges.
func (g *loadGen) workloadRows() {
	C := g.shape.Cycles
	ecsExec := map[*loadAcct]*loadIdent{}
	for _, i := range g.idents {
		if i.name == "ecsTaskExecutionRole" {
			ecsExec[i.acct] = i
		}
	}
	clock := 0
	for _, w := range g.workloads {
		a := w.acct
		surf := loadKindSurface[w.kind]
		surface := surf[0] + ":" + w.region
		last := w.life.lastCycle(C)
		attrs := map[string]any{"status": "Active"}
		pattrs := map[string]any{"status": "Active"}
		switch w.kind {
		case models.WorkloadLambdaFunction:
			names := []string{}
			if g.chance(0.6) {
				names = []string{"LOG_LEVEL", "TABLE_NAME", "QUEUE_URL"}[:1+g.rng.Intn(3)]
			}
			attrs["env_var_names"], pattrs["env_var_names"] = names, names
		case models.WorkloadECSTaskDefinition:
			attrs["status"], pattrs["status"] = "ACTIVE", "ACTIVE"
			if e := ecsExec[a]; e != nil {
				attrs["execution_role_arn"] = e.arn
			}
		case models.WorkloadEC2Instance:
			attrs["status"], pattrs["status"] = "running", "running"
		case models.WorkloadBedrockAgent, models.WorkloadBedrockAgentCoreRT:
			attrs["status"], pattrs["status"] = "PREPARED", "PREPARED"
			attrs["foundation_model"], pattrs["foundation_model"] = "anthropic.claude-sonnet-4", "anthropic.claude-sonnet-4"
		case models.WorkloadBedrockAgentCoreGW:
			targets := []models.AWSGatewayTarget{{TargetID: "t-" + w.native[len(w.native)-6:], Name: "tools", Status: "READY", Type: "lambda"}}
			attrs["gateway_targets"], pattrs["gateway_targets"] = targets, targets
			attrs["status"], pattrs["status"] = "READY", "READY"
		}
		if w.execState == models.ExecRoleNotInInventory {
			attrs["unresolved_role_arn"] = w.execARN
		}
		var cloudRef *uuid.UUID
		if w.life.live() {
			cloudRef = &w.cloudID
			var ident *uuid.UUID
			if w.role != nil {
				ident = &w.role.cloudID
			}
			g.rows.add("cloud_workload", w.cloudID, g.ws, a.conn, ident, w.kind, w.native, w.name, w.region,
				loadMarshal(attrs), last, g.at(w.life.first, a.k), a.run(last).at, a.run(last).at)
		}
		w.obs = g.observe(a, "workload_id", cloudRef, surf[1], surface, w.native,
			map[string]any{"name": w.name, "region": w.region, "native_id": w.native, "runtime_kind": w.kind,
				"attributed": w.role != nil, "observed_subject": "workload:" + w.cloudID.String()},
			w.life.first, last)

		// Classification history (§5.5): a few people's decisions, the
		// latest one on the row, the clock counting every decision.
		if w.class == models.ClassificationUnclassified && w.life.live() && g.chance(0.03) &&
			(w.kind == models.WorkloadLambdaFunction || w.kind == models.WorkloadECSTaskDefinition) {
			decide := func(decision, previous string, undoes *uuid.UUID) uuid.UUID {
				id := g.uuid()
				at := g.at(2, a.k).Add(time.Duration(w.classVer+1) * 3 * time.Hour)
				g.rows.add("iga_workload_classification", id, g.ws, w.id, g.uuid(), decision, previous, "",
					"reviewed in the load fixture", g.user, w.classVer, loadHash(id.String()), w.classVer+1, undoes, at)
				w.classVer++
				w.class = decision
				clock++
				return id
			}
			first := decide(models.ClassificationClassified, models.ClassificationUnclassified, nil)
			switch r := g.rng.Float64(); {
			case r < 0.2:
				decide(models.ClassificationClassified, models.ClassificationClassified, nil)
			case r < 0.35:
				decide(models.ClassificationUnclassified, models.ClassificationClassified, &first)
			}
		}

		lifecycle, reason := w.life.lifecycle()
		g.rows.add("iga_workload", w.id, g.ws, a.scope, "aws", w.kind, w.name, w.region, "unknown", lifecycle, reason,
			igagraph.Key("aws", w.arn), models.ContinuityRecognitionOnly, "", loadMarshal(pattrs),
			g.at(w.life.first, a.k), a.run(last).at, w.execState, w.execARN, w.class, w.classVer,
			g.at(w.life.first, a.k), a.run(last).at)
		g.support(a, "workload_id", w.id, a.nodePart(models.ObjectWorkload, w.kind, w.region), w.life)
		g.events(a, "workload_id", w.id, w.life)

		// Execution edges: the spans of the workload's life, split where its
		// role changed; a restored workload's edge is a new row.
		var spans []loadSpan
		switch {
		case !w.life.live():
			spans = []loadSpan{{from: w.life.first, to: w.life.retired, reason: models.EndedNotSeen}}
		case w.life.restored > 0:
			spans = []loadSpan{{from: w.life.first, to: w.life.retired, reason: models.EndedNotSeen}, {from: w.life.restored}}
		default:
			spans = []loadSpan{{from: w.life.first, stale: w.life.stale}}
		}
		wkey := igagraph.Key("aws", w.arn)
		edge := func(rel string, role *loadIdent, span loadSpan) uuid.UUID {
			state, reason := span.state()
			lr := a.run(span.lastCycle(C))
			id := g.uuid()
			g.rows.add("iga_relationship", id, g.ws, rel, nil, w.id, nil, role.id, models.BasisDeclared, state,
				g.at(span.from, a.k), g.validTo(a, span), lr.at, lr.id, reason,
				igagraph.RelationshipKey(rel, wkey, role.endpoint()), a.edgePart(rel, w.kind, w.region), a.conn,
				"", nil, "", g.at(span.from, a.k), lr.at)
			g.link("iga_relationship_evidence", id, span, w.obs)
			return id
		}
		if w.role != nil {
			for _, span := range spans {
				if w.prevRole != nil && span.from < w.switchAt && (span.to == 0 || span.to > w.switchAt) {
					edge(models.RelTypeExecutesAs, w.prevRole, loadSpan{from: span.from, to: w.switchAt, reason: models.EndedNotSeen})
					span.from = w.switchAt
				}
				id := edge(models.RelTypeExecutesAs, w.role, span)
				if span.to == 0 {
					w.role.users++
					if len(g.h.executes) < 60 && g.chance(0.02) {
						g.h.executes = append(g.h.executes, id)
					}
				}
			}
		}
		if w.kind == models.WorkloadECSTaskDefinition && ecsExec[a] != nil {
			for _, span := range spans {
				edge(models.RelTypeTaskExecutionRole, ecsExec[a], span)
				if span.to == 0 {
					ecsExec[a].users++
				}
			}
		}
	}
	g.rows.add("iga_classification_clock", g.ws, clock)
}

// counts are the coverage report's object counts, per account per cycle.
func (g *loadGen) counts() []map[int]*loadCounts {
	C := g.shape.Cycles
	out := make([]map[int]*loadCounts, len(g.accts))
	alive := func(l loadLife, c int) bool {
		return l.first <= c && (l.retired == 0 || c < l.retired || (l.restored > 0 && c >= l.restored))
	}
	for _, a := range g.accts {
		out[a.k] = map[int]*loadCounts{}
		for c := 1; c <= C; c++ {
			n := &loadCounts{workloads: map[string]int{}}
			for _, i := range g.idents {
				if i.acct == a && alive(i.life, c) {
					switch i.kind {
					case models.CloudIdentityIAMRole:
						n.roles++
					case models.CloudIdentityIAMUser:
						n.users++
					default:
						n.groups++
					}
				}
			}
			for _, p := range g.policies {
				if p.accts[a] && alive(p.life, c) {
					n.policies++
				}
			}
			for _, w := range g.workloads {
				if w.acct == a && alive(w.life, c) {
					n.workloads[loadKindSurface[w.kind][0]+":"+w.region]++
				}
			}
			out[a.k][c] = n
		}
	}
	return out
}

// permissionObservations are Cloud Inventory's per-permission records (§1.5,
// PermissionSubjectKey): not read by the graph, but they share the
// observation table every evidence and resource-policy read scans, so the
// table has its production volume.
func (g *loadGen) permissionObservations() {
	C := g.shape.Cycles
	for _, p := range g.policies {
		for _, a := range loadAcctsOf(g, p.accts) {
			for _, s := range p.stmts {
				if !s.live() {
					continue
				}
				res := firstOr(s.cur.Resources, "*")
				native := strings.Join([]string{a.id, fmt.Sprintf("%s#s%d", p.native, s.cur.Index), res}, igagraph.Sep)
				g.observe(a, "", nil, "iam:GetAccountAuthorizationDetails", models.SurfaceIAMPolicies, native,
					map[string]any{"sid": s.sid, "effect": s.cur.Effect, "source": p.native, "actions": s.cur.Actions,
						"resources": s.cur.Resources, "derivation": "granted"}, s.first, C)
			}
		}
	}
}

/* ---------------------------------- build ---------------------------------- */

// loadBuild generates one workspace's whole fixture in memory.
func loadBuild(seed int64, name string, shape loadShape, accounts []loadAcct) *loadGen {
	g := newLoadGen(seed, name, shape, accounts)
	g.setup()
	g.identities()
	g.trust()
	pool := g.pool()
	g.genPolicies(pool)
	assigns := g.assignments()
	g.genWorkloads()
	g.identityRows()
	g.trustAll()
	g.policyRows()
	g.resourceRows()
	g.assignmentRows(assigns)
	g.memberships()
	g.workloadRows()
	g.permissionObservations()
	g.externalRows()
	g.finish(g.counts())
	g.handles()
	return g
}

// handles chooses what the measurement reads: rotating samples of typical
// objects, and the heaviest object of each kind.
func (g *loadGen) handles() {
	h := &g.h
	h.firstAcct = g.accts[0].id
	stride := func(n, want int) int {
		if n <= want {
			return 1
		}
		return n / want
	}
	var live []*loadWorkload
	for _, w := range g.workloads {
		if w.life.live() {
			live = append(live, w)
			if w.prevRole != nil && len(h.switchedWL) < 30 {
				h.switchedWL = append(h.switchedWL, w.id)
			}
		}
	}
	h.activeWL = len(live)
	for i := 0; i < len(live) && len(h.workloads) < 50; i += stride(len(live), 50) {
		h.workloads = append(h.workloads, live[i].id)
		// A workload running as a role with a live grant: the path
		// workload -> executes_as -> role -> grant -> statement -> target ->
		// resource is declared (§5.4).
		if w := live[i]; w.role != nil && w.role.life.live() && !w.life.stale && g.reach[w.role] != nil {
			h.paths = append(h.paths, [2]uuid.UUID{w.id, g.reach[w.role].id})
		}
	}
	var roles, users []*loadIdent
	for _, i := range g.idents {
		if !i.life.live() {
			continue
		}
		h.activeIdent++
		switch i.kind {
		case models.CloudIdentityIAMRole:
			roles = append(roles, i)
			switch {
			case i.name == "ecsTaskExecutionRole":
				// Its workloads reach it through task_execution_role, never
				// executes_as: the heaviest Used-by (account A's is measured),
				// never the execution-role hub. (Picked as the hub, account
				// B's made "/graph/expand executes_as reverse (hub role)" an
				// empty page -- the Graph response sizes showed 0 nodes.)
				if i.acct == g.accts[0] {
					h.ecsExecRole, h.ecsExecUsers = i.id, i.users
				}
			case i.service != "" && i.users > h.hubRoleUsers:
				h.hubRole, h.hubRoleUsers = i.id, i.users
			}
		case models.CloudIdentityIAMUser:
			users = append(users, i)
		default:
			if h.hubGroup == uuid.Nil || i.users > g.identByID(h.hubGroup).users {
				h.hubGroup = i.id
			}
		}
	}
	for i := 0; i < len(roles) && len(h.roles) < 50; i += stride(len(roles), 50) {
		h.roles = append(h.roles, roles[i].id)
	}
	for i := 0; i < len(users) && len(h.users) < 30; i += stride(len(users), 30) {
		h.users = append(h.users, users[i].id)
	}
	h.activeRes = len(g.resList)
	best := -1
	var typical []*loadResource
	for _, r := range g.resList {
		switch {
		case r.text == "*":
			h.starResource = r.id
		case r.exact && r.named > best:
			h.hotBucket, best = r.id, r.named
		}
		if r.exact && r.named >= 1 && r.named <= 6 {
			typical = append(typical, r)
		}
	}
	for i := 0; i < len(typical) && len(h.resources) < 50; i += stride(len(typical), 50) {
		h.resources = append(h.resources, typical[i].id)
	}
	var exts []*loadExternal
	for _, k := range loadSortedKeys(g.externals) {
		e := g.externals[k]
		if e.subject == "lambda.amazonaws.com" {
			h.lambdaService = e.id
		} else if !loadIsService(e.subject) {
			exts = append(exts, e)
		}
	}
	sort.Slice(exts, func(i, j int) bool { return exts[i].key < exts[j].key })
	for i := 0; i < len(exts) && len(h.externals) < 30; i++ {
		h.externals = append(h.externals, exts[i].id)
	}
	lastA, lastC := g.accts[0].run(g.shape.Cycles), g.accts[len(g.accts)-1].run(g.shape.Cycles)
	h.coverageClaims = []string{
		"coverage:" + lastA.id.String() + ":" + models.SurfaceIAMRoles,
		"coverage:" + lastC.id.String() + ":lambda:us-east-1",
	}
}

func (g *loadGen) identByID(id uuid.UUID) *loadIdent {
	for _, i := range g.idents {
		if i.id == id {
			return i
		}
	}
	return nil
}
