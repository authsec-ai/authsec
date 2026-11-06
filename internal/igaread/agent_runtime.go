package igaread

// Agent runtime decoration of the access graph (SPEC-agent-runtime-visibility.md
// §1 labels, §5.2-§5.8): what agent runtime visibility knows about an AWS IAM
// role or user, and about the workloads that run as it, drawn on the nodes and
// edges the graph routes (/graph, /graph/expand, /graph/path) and the identity
// and workload details already return -- so the console shows it without a
// new screen.
//
//	node  agent_runtime  {label, model_calls, open_alerts, open_findings,
//	                      suggestion, containment}, ONLY when there is
//	                      something to say: an AI workload (a model call or
//	                      a refused one), a pending suggestion, an open alert
//	                      or finding, or a live containment. Absent otherwise,
//	                      so a node without agent-runtime data is byte for
//	                      byte what it always was.
//	edge  contained      {id, level} on a contained identity's grant edges
//	                      while the containment is in force: every grant at
//	                      identity level, the grants whose statement allows a
//	                      model action at model level. Absent otherwise.
//
// The facts come from agent runtime visibility itself (services, which this
// package cannot import): an AgentRuntimeSource installed at startup computes
// them with the inference service's own label rule, so the graph and the
// AI-workloads list never disagree. Without a source nothing is read and
// nothing is drawn.
//
// Batched like every decoration here: per level (or detail read), one
// statement maps the level's workloads to the role they execute as, and the
// source issues one statement per table for all of the level's identities --
// workspace_id on every statement and join, on the level's own handle, so
// inside the request's RLS transaction and the level's time allowance.

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

/* ------------------------------- the source -------------------------------- */

// AgentRuntimeSubject names one AWS identity of the graph to the source: its
// ARN and, when the graph holds one, its immutable id (RoleId / UserId), so a
// role recreated under the same ARN is not taken for its predecessor.
type AgentRuntimeSubject struct {
	ARN          string
	ImmutableKey string
}

// AgentRuntimeFacts is what agent runtime visibility knows about one AWS
// identity (a cloud_identity row).
type AgentRuntimeFacts struct {
	// Label is the identity's label by the inference service's rule
	// (agentruntime.Label*), "" when it has none.
	Label string
	// AIWorkload: seen calling a model, or refused one. The counts below are
	// its model-call evidence (agentruntime.ModelCallUsage).
	AIWorkload bool
	Calls      int
	Denied     int
	LastCallAt *time.Time
	Models     map[string]int // model id -> calls
	// OpenFindings counts its open agent_finding rows; OpenAlerts its open
	// agent_alert rows, HighestSeverity the highest of them ("" for none).
	OpenFindings    int
	OpenAlerts      int
	HighestSeverity string
	// SingleWorkload is the iga_workload the identity's calls are attributed
	// to (its one workload, §5.2), nil when it has none or several.
	SingleWorkload *uuid.UUID
	// Suggestion is the suggestion on that one workload, nil for none.
	Suggestion *AgentRuntimeSuggestion
	// Workloads are the identity's projected workloads, by iga_workload id.
	Workloads map[uuid.UUID]AgentRuntimeWorkloadFacts
	// Containments are its live containments (the slot-holding states),
	// newest first.
	Containments []AgentRuntimeContainment
}

// AgentRuntimeWorkloadFacts is one workload that runs as the identity.
type AgentRuntimeWorkloadFacts struct {
	CloudWorkloadID uuid.UUID
	// Label is the workload's label by the inference rule: agent when it is
	// classified as one, the AI workload's label when it is the identity's
	// one workload, else "".
	Label      string
	Suggestion *AgentRuntimeSuggestion
}

// AgentRuntimeSuggestion is an agent_suggestion row's id and state.
type AgentRuntimeSuggestion struct {
	ID    uuid.UUID
	State string
}

// Containment levels, as agent_containment.level writes them (agentcontain).
const (
	AgentContainLevelIdentity = "identity"
	AgentContainLevelModel    = "model"
	AgentContainLevelWorkload = "workload"
)

// agentSuggestionPending is agent_suggestion's pending state.
const agentSuggestionPending = "pending"

// AgentRuntimeContainment is one live containment of the identity.
type AgentRuntimeContainment struct {
	ID        uuid.UUID
	Level     string
	State     string
	Effective *bool
	// InForce: its AWS change may be in place (containing, contained,
	// partially contained, releasing) -- not a preview.
	InForce bool
	// WorkloadIDs are the cloud_workload rows a workload-level containment
	// stops.
	WorkloadIDs []uuid.UUID
}

// AgentRuntimeSource computes the facts for a level's identities on the
// level's handle, a transaction under row-level security for ws. The result
// is keyed by ARN; an identity it knows nothing about is absent.
type AgentRuntimeSource interface {
	AgentRuntimeFacts(tx *gorm.DB, ws uuid.UUID, subjects []AgentRuntimeSubject) (map[string]*AgentRuntimeFacts, error)
	// ModelActions are the IAM actions model-level containment denies.
	ModelActions() []string
}

var (
	agentRuntimeMu  sync.RWMutex
	agentRuntimeSrc AgentRuntimeSource
)

// SetAgentRuntimeSource installs the source (cmd/main.go; tests) and returns
// the one it replaces. nil turns the decoration off.
func SetAgentRuntimeSource(s AgentRuntimeSource) AgentRuntimeSource {
	agentRuntimeMu.Lock()
	defer agentRuntimeMu.Unlock()
	prev := agentRuntimeSrc
	agentRuntimeSrc = s
	return prev
}

// AgentRuntimeDecoration reports whether a source is installed.
func AgentRuntimeDecoration() bool { return agentRuntimeSource() != nil }

func agentRuntimeSource() AgentRuntimeSource {
	agentRuntimeMu.RLock()
	defer agentRuntimeMu.RUnlock()
	return agentRuntimeSrc
}

/* ------------------------------ response shapes ---------------------------- */

// GraphAgentRuntime is a node's agent_runtime object.
type GraphAgentRuntime struct {
	// Label is possible_ai_workload | ai_workload | suggested_agent | agent; null when the node is
	// shown only for an alert, a finding or a containment and the inference
	// rule gives it no label (a workload on a shared role, an identity whose
	// calls aged out of the evidence).
	Label        *string                `json:"label"`
	ModelCalls   *GraphModelCalls       `json:"model_calls"` // null: not an AI workload
	OpenAlerts   GraphOpenAlerts        `json:"open_alerts"`
	OpenFindings int                    `json:"open_findings"`
	Suggestion   *GraphAgentSuggestion  `json:"suggestion"`
	Containment  *GraphAgentContainment `json:"containment"`
}

// GraphModelCalls is the model-call evidence: successful and refused calls,
// the last call, and the five most-called models.
type GraphModelCalls struct {
	Calls      int               `json:"calls"`
	Denied     int               `json:"denied"`
	LastCallAt any               `json:"last_call_at"`
	Models     []GraphModelCount `json:"models"`
}

// GraphModelCount is one model and its calls.
type GraphModelCount struct {
	Model string `json:"model"`
	Calls int    `json:"calls"`
}

// GraphOpenAlerts counts open alerts; highest_severity is null for none.
type GraphOpenAlerts struct {
	Count           int     `json:"count"`
	HighestSeverity *string `json:"highest_severity"`
}

// GraphAgentSuggestion is the suggestion on the node's workload.
type GraphAgentSuggestion struct {
	ID    uuid.UUID `json:"id"`
	State string    `json:"state"`
}

// GraphAgentContainment is the live containment that bears on the node.
type GraphAgentContainment struct {
	ID        uuid.UUID `json:"id"`
	Level     string    `json:"level"`
	State     string    `json:"state"`
	Effective *bool     `json:"effective"`
}

// GraphContained is a grant edge's contained object.
type GraphContained struct {
	ID    uuid.UUID `json:"id"`
	Level string    `json:"level"`
}

// graphModelsShown is how many models model_calls lists.
const graphModelsShown = 5

/* --------------------------------- builders -------------------------------- */

// agentRuntimeOfIdentity is an identity node's decoration, nil when there is
// nothing to say. A workload-level containment stops the workload, not the
// role, and is shown on the workload.
func agentRuntimeOfIdentity(f *AgentRuntimeFacts) *GraphAgentRuntime {
	if f == nil {
		return nil
	}
	c := agentRuntimeContainmentFor(f.Containments, nil)
	if !f.AIWorkload && !agentSuggestionPendingOf(f.Suggestion) && f.OpenAlerts == 0 && f.OpenFindings == 0 && c == nil {
		return nil
	}
	return agentRuntimeView(f.Label, f, f.AIWorkload, f.OpenAlerts, f.HighestSeverity, f.OpenFindings, f.Suggestion, c)
}

// agentRuntimeOfWorkload is a workload node's decoration through the identity
// it runs as, nil when there is nothing to say. The identity's calls, alerts
// and findings are the workload's only when it is the identity's one workload
// (§5.2: on a shared role the role is the AI workload, the workloads are
// candidates); an identity- or model-level containment stops every workload
// on the role, a workload-level one the workloads it names.
func agentRuntimeOfWorkload(f *AgentRuntimeFacts, workload uuid.UUID) *GraphAgentRuntime {
	if f == nil {
		return nil
	}
	wf, ok := f.Workloads[workload]
	if !ok {
		return nil
	}
	single := f.SingleWorkload != nil && *f.SingleWorkload == workload
	ai := single && f.AIWorkload
	alerts, severity, findings := 0, "", 0
	if single {
		alerts, severity, findings = f.OpenAlerts, f.HighestSeverity, f.OpenFindings
	}
	cw := wf.CloudWorkloadID
	c := agentRuntimeContainmentFor(f.Containments, &cw)
	if !ai && !agentSuggestionPendingOf(wf.Suggestion) && alerts == 0 && findings == 0 && c == nil {
		return nil
	}
	return agentRuntimeView(wf.Label, f, ai, alerts, severity, findings, wf.Suggestion, c)
}

func agentRuntimeView(label string, f *AgentRuntimeFacts, ai bool, alerts int, severity string, findings int,
	s *AgentRuntimeSuggestion, c *AgentRuntimeContainment) *GraphAgentRuntime {
	out := &GraphAgentRuntime{
		Label:        strPtr(label),
		OpenAlerts:   GraphOpenAlerts{Count: alerts, HighestSeverity: strPtr(severity)},
		OpenFindings: findings,
	}
	if alerts == 0 {
		out.OpenAlerts.HighestSeverity = nil
	}
	if ai {
		out.ModelCalls = &GraphModelCalls{Calls: f.Calls, Denied: f.Denied, LastCallAt: TS(f.LastCallAt),
			Models: graphTopModels(f.Models, graphModelsShown)}
	}
	if s != nil {
		out.Suggestion = &GraphAgentSuggestion{ID: s.ID, State: s.State}
	}
	if c != nil {
		out.Containment = &GraphAgentContainment{ID: c.ID, Level: c.Level, State: c.State, Effective: c.Effective}
	}
	return out
}

func agentSuggestionPendingOf(s *AgentRuntimeSuggestion) bool {
	return s != nil && s.State == agentSuggestionPending
}

// graphTopModels is the n most-called models, by calls then model id.
func graphTopModels(m map[string]int, n int) []GraphModelCount {
	out := make([]GraphModelCount, 0, len(m))
	for k, v := range m {
		out = append(out, GraphModelCount{Model: k, Calls: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Calls != out[j].Calls {
			return out[i].Calls > out[j].Calls
		}
		return out[i].Model < out[j].Model
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// agentContainRank orders the levels: identity stops everything on the role,
// a workload level its workloads, model level only model calls.
var agentContainRank = map[string]int{AgentContainLevelIdentity: 0, AgentContainLevelWorkload: 1, AgentContainLevelModel: 2}

// agentRuntimeContainmentFor is the containment that bears on an identity
// (workload == nil: identity and model levels) or on one of its workloads
// (identity and model levels, and a workload level naming it): one in force
// before a preview, then by level, then the newest.
func agentRuntimeContainmentFor(cs []AgentRuntimeContainment, workload *uuid.UUID) *AgentRuntimeContainment {
	var best *AgentRuntimeContainment
	for i := range cs {
		c := &cs[i]
		rank, ok := agentContainRank[c.Level]
		if !ok {
			continue
		}
		if c.Level == AgentContainLevelWorkload {
			if workload == nil || !containsUUID(c.WorkloadIDs, *workload) {
				continue
			}
		}
		if best == nil || (c.InForce && !best.InForce) ||
			(c.InForce == best.InForce && rank < agentContainRank[best.Level]) {
			best = c
		}
	}
	return best
}

// agentRuntimeEdgeContainment is the containment a contained identity's
// grant edges carry: one in force at identity level, else at model level.
func agentRuntimeEdgeContainment(cs []AgentRuntimeContainment) *AgentRuntimeContainment {
	var best *AgentRuntimeContainment
	for i := range cs {
		c := &cs[i]
		if !c.InForce || (c.Level != AgentContainLevelIdentity && c.Level != AgentContainLevelModel) {
			continue
		}
		if best == nil || (c.Level == AgentContainLevelIdentity && best.Level != AgentContainLevelIdentity) {
			best = c
		}
	}
	return best
}

// agentRuntimeGrantContained reports whether a grant to a statement with
// these actions (its group actions: NotActions prefixed "!") is stopped by
// containment c: every grant at identity level; at model level the grants
// whose statement allows at least one of the model actions.
func agentRuntimeGrantContained(c *AgentRuntimeContainment, statementActions, modelActions []string) bool {
	switch {
	case c == nil:
		return false
	case c.Level == AgentContainLevelIdentity:
		return true
	case c.Level == AgentContainLevelModel:
		return iamActionsOverlap(statementActions, modelActions)
	}
	return false
}

// iamActionsOverlap reports whether a statement's actions (NotActions
// prefixed "!") allow at least one action a deny pattern names. Action
// patterns are IAM's: case-insensitive, * and ? wildcards. "All actions
// except N" allows a deny pattern's actions unless a NotAction covers the
// whole pattern.
func iamActionsOverlap(statementActions, deny []string) bool {
	var acts, nots []string
	for _, a := range statementActions {
		if strings.HasPrefix(a, "!") {
			nots = append(nots, a[1:])
		} else {
			acts = append(acts, a)
		}
	}
	if len(nots) > 0 {
		for _, d := range deny {
			covered := false
			for _, n := range nots {
				if iamGlobCovers(n, d) {
					covered = true
					break
				}
			}
			if !covered {
				return true
			}
		}
		return false
	}
	for _, a := range acts {
		for _, d := range deny {
			if iamGlobsIntersect(a, d) {
				return true
			}
		}
	}
	return false
}

// iamGlobCovers reports whether pattern p matches every action pattern q
// matches: p matched against q read literally, where p's * may absorb q's
// own wildcards.
func iamGlobCovers(p, q string) bool {
	p, q = strings.ToLower(p), strings.ToLower(q)
	memo := map[[2]int]bool{}
	seen := map[[2]int]bool{}
	var m func(i, j int) bool
	m = func(i, j int) bool {
		k := [2]int{i, j}
		if seen[k] {
			return memo[k]
		}
		seen[k] = true
		var r bool
		switch {
		case i == len(p):
			r = j == len(q)
		case p[i] == '*':
			r = m(i+1, j) || (j < len(q) && m(i, j+1))
		case j == len(q):
			r = false
		case p[i] == '?':
			// ? matches one character, never a run that q's * may stand for.
			r = q[j] != '*' && m(i+1, j+1)
		default:
			r = p[i] == q[j] && m(i+1, j+1)
		}
		memo[k] = r
		return r
	}
	return m(0, 0)
}

// iamGlobsIntersect reports whether some action matches both patterns.
func iamGlobsIntersect(a, b string) bool {
	a, b = strings.ToLower(a), strings.ToLower(b)
	memo := map[[2]int]bool{}
	seen := map[[2]int]bool{}
	var m func(i, j int) bool
	m = func(i, j int) bool {
		k := [2]int{i, j}
		if seen[k] {
			return memo[k]
		}
		seen[k] = true
		var r bool
		switch {
		case i == len(a) && j == len(b):
			r = true
		case i < len(a) && a[i] == '*':
			r = m(i+1, j) || (j < len(b) && m(i, j+1))
		case j < len(b) && b[j] == '*':
			r = m(i, j+1) || (i < len(a) && m(i+1, j))
		case i == len(a) || j == len(b):
			r = false
		default:
			r = (a[i] == b[j] || a[i] == '?' || b[j] == '?') && m(i+1, j+1)
		}
		memo[k] = r
		return r
	}
	return m(0, 0)
}

func containsUUID(xs []uuid.UUID, x uuid.UUID) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

/* ---------------------------------- reads ---------------------------------- */

// agentRuntimeIdentityIn is one graph identity the decoration asks about.
type agentRuntimeIdentityIn struct {
	id        uuid.UUID
	arn       string
	immutable string
}

// agentRuntimeRead is one batch's decoration, by graph id.
type agentRuntimeRead struct {
	identities map[uuid.UUID]*GraphAgentRuntime
	workloads  map[uuid.UUID]*GraphAgentRuntime
	// contain is each identity's containment in force for its grant edges.
	contain map[uuid.UUID]*AgentRuntimeContainment
	// modelActions are the source's.
	modelActions []string
}

// agentRuntimeIdentityKind: only roles and users call models; a group holds
// no session.
func agentRuntimeIdentityKind(kind string) bool {
	return kind == models.CloudIdentityIAMRole || kind == models.CloudIdentityIAMUser
}

// readAgentRuntime reads the decoration of AWS identities and workloads on
// tx: the workloads' execution roles (one statement), then the source's facts
// for every identity of the batch (one statement per table). nil, nil
// without a source or nodes.
func readAgentRuntime(tx func() (*gorm.DB, error), ws uuid.UUID, idents []agentRuntimeIdentityIn, workloads []uuid.UUID) (*agentRuntimeRead, error) {
	src := agentRuntimeSource()
	if src == nil || (len(idents) == 0 && len(workloads) == 0) {
		return nil, nil
	}
	out := &agentRuntimeRead{identities: map[uuid.UUID]*GraphAgentRuntime{}, workloads: map[uuid.UUID]*GraphAgentRuntime{},
		contain: map[uuid.UUID]*AgentRuntimeContainment{}, modelActions: src.ModelActions()}

	// A workload's facts are its execution role's: the identity its
	// executes_as relationship (not ended) names.
	type execRow struct {
		WorkloadID   uuid.UUID
		SourceKey    string
		ImmutableKey string
	}
	var execs []execRow
	if len(workloads) > 0 {
		db, err := tx()
		if err != nil {
			return nil, err
		}
		if err := db.Raw(`SELECT r.source_workload_id AS workload_id, ia.source_key, ia.immutable_key
		                    FROM iga_relationship r
		                    JOIN iga_identity_accounts ia ON ia.workspace_id = r.workspace_id AND ia.id = r.target_identity_account_id
		                   WHERE r.workspace_id = ? AND COALESCE(r.source_identity_account_id, r.source_workload_id) IN ?
		                     AND r.source_workload_id IS NOT NULL
		                     AND r.relationship_type = ? AND r.state <> 'ended' AND ia.provider = 'aws'
		                   ORDER BY r.source_workload_id, ia.source_key, ia.id`,
			ws, workloads, GraphEdgeExecutesAs).Scan(&execs).Error; err != nil {
			return nil, err
		}
	}

	seen := map[AgentRuntimeSubject]bool{}
	var subjects []AgentRuntimeSubject
	add := func(s AgentRuntimeSubject) {
		if s.ARN != "" && !seen[s] {
			seen[s] = true
			subjects = append(subjects, s)
		}
	}
	for _, n := range idents {
		add(AgentRuntimeSubject{ARN: n.arn, ImmutableKey: n.immutable})
	}
	for _, e := range execs {
		add(AgentRuntimeSubject{ARN: NativeOfKey(e.SourceKey), ImmutableKey: e.ImmutableKey})
	}
	if len(subjects) == 0 {
		return out, nil
	}
	db, err := tx()
	if err != nil {
		return nil, err
	}
	facts, err := src.AgentRuntimeFacts(db, ws, subjects)
	if err != nil {
		return nil, err
	}
	if len(facts) == 0 {
		return out, nil
	}
	for _, n := range idents {
		f := facts[n.arn]
		if v := agentRuntimeOfIdentity(f); v != nil {
			out.identities[n.id] = v
		}
		if f != nil {
			if c := agentRuntimeEdgeContainment(f.Containments); c != nil {
				out.contain[n.id] = c
			}
		}
	}
	for _, e := range execs {
		if out.workloads[e.WorkloadID] != nil {
			continue
		}
		if v := agentRuntimeOfWorkload(facts[NativeOfKey(e.SourceKey)], e.WorkloadID); v != nil {
			out.workloads[e.WorkloadID] = v
		}
	}
	return out, nil
}

/* ------------------------------ the traversal ------------------------------ */

// decorateAgentRuntime decorates a level's active AWS identity (role, user)
// and workload nodes. A retired node is not: the ARN a retired identity had
// may now name its successor (idetailActivity's rule).
func (t *graphTraversal) decorateAgentRuntime(lv *graphLevel, identities, workloads []*GraphNode) error {
	if agentRuntimeSource() == nil {
		return nil
	}
	var in []agentRuntimeIdentityIn
	byIdentity := map[uuid.UUID]*GraphNode{}
	for _, n := range identities {
		if n.side() == models.ProviderAWS && agentRuntimeIdentityKind(n.Kind) && n.ARN != "" && n.Lifecycle == models.IGALifecycleActive {
			in = append(in, agentRuntimeIdentityIn{id: n.id, arn: n.ARN, immutable: n.immutable})
			byIdentity[n.id] = n
		}
	}
	var wids []uuid.UUID
	byWorkload := map[uuid.UUID]*GraphNode{}
	for _, n := range workloads {
		if n.side() == models.ProviderAWS && n.Lifecycle == models.IGALifecycleActive {
			wids = append(wids, n.id)
			byWorkload[n.id] = n
		}
	}
	ar, err := readAgentRuntime(lv.db, t.q.WS, in, wids)
	if err != nil || ar == nil {
		return err
	}
	for id, v := range ar.identities {
		byIdentity[id].AgentRuntime = v
	}
	for id, c := range ar.contain {
		byIdentity[id].arContain = c
	}
	for id, v := range ar.workloads {
		byWorkload[id].AgentRuntime = v
	}
	t.modelActions = ar.modelActions
	return nil
}

// decorateContained marks the grant edges of a contained identity.
func (t *graphTraversal) decorateContained(edges []*GraphEdge, node func(string) *GraphNode) {
	for _, e := range edges {
		if e.Kind != GraphEdgeGrant || e.side != models.ProviderAWS {
			continue
		}
		from, to := node(e.From), node(e.To)
		if from == nil || to == nil || from.arContain == nil {
			continue
		}
		if agentRuntimeGrantContained(from.arContain, to.groupActions, t.modelActions) {
			e.Contained = &GraphContained{ID: from.arContain.ID, Level: from.arContain.Level}
		}
	}
}

/* --------------------------------- details --------------------------------- */

// identityAgentRuntime is an identity detail's decoration (nil for none).
func identityAgentRuntime(q *Query, id uuid.UUID, kind, sourceKey, immutable string) (*GraphAgentRuntime, error) {
	if agentRuntimeSource() == nil || !agentRuntimeIdentityKind(kind) {
		return nil, nil
	}
	ar, err := readAgentRuntime(func() (*gorm.DB, error) { return q.DB(), nil }, q.WS,
		[]agentRuntimeIdentityIn{{id: id, arn: NativeOfKey(sourceKey), immutable: immutable}}, nil)
	if err != nil || ar == nil {
		return nil, err
	}
	return ar.identities[id], nil
}

// workloadAgentRuntime is a workload detail's decoration (nil for none).
func workloadAgentRuntime(q *Query, id uuid.UUID) (*GraphAgentRuntime, error) {
	if agentRuntimeSource() == nil {
		return nil, nil
	}
	ar, err := readAgentRuntime(func() (*gorm.DB, error) { return q.DB(), nil }, q.WS, nil, []uuid.UUID{id})
	if err != nil || ar == nil {
		return nil, err
	}
	return ar.workloads[id], nil
}
