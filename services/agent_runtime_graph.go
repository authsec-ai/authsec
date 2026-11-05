package services

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentcontain"
	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/agentruntime/detect"
	"github.com/authsec-ai/authsec/internal/igaread"
	"github.com/authsec-ai/authsec/models"
)

/* agent_runtime_graph.go is the access graph's agent-runtime source
   (igaread.AgentRuntimeSource): for the AWS identities one graph level (or
   detail read) holds, what agent runtime visibility knows -- the label, the
   model-call evidence, open alerts and findings, the suggestion and the live
   containments -- computed by THIS package's own rules (subjectFromState,
   buildAIWorkload, label, isAIWorkload), so the graph and the AI-workloads
   list never disagree.

   Every statement runs on the handle the graph hands in: the request's
   transaction under row-level security for ws, inside the level's time
   allowance. One statement finds which of the identities have anything to
   say; only those are read in full, one statement per table for all of them
   (no per-identity reads). */

// InstallAgentRuntimeGraph installs the source (cmd/main.go).
func InstallAgentRuntimeGraph() { igaread.SetAgentRuntimeSource(AgentRuntimeGraphSource{}) }

// AgentRuntimeGraphSource implements igaread.AgentRuntimeSource.
type AgentRuntimeGraphSource struct{}

// ModelActions are what model-level containment denies (DECISION P3-5).
func (AgentRuntimeGraphSource) ModelActions() []string {
	return append([]string{}, agentcontain.ModelActions...)
}

// arInForce are the containment states whose AWS change may be in place: the
// live states but a preview.
var arInForce = map[string]bool{
	agentcontain.StateContaining: true, agentcontain.StateContained: true,
	agentcontain.StatePartial: true, agentcontain.StateReleasing: true,
}

// AgentRuntimeFacts returns the facts of the subjects that have something to
// say, keyed by ARN. A subject whose cloud identity is another incarnation
// (its unique id differs from the graph's immutable key) is not this one.
func (AgentRuntimeGraphSource) AgentRuntimeFacts(tx *gorm.DB, ws uuid.UUID, subjects []igaread.AgentRuntimeSubject) (map[string]*igaread.AgentRuntimeFacts, error) {
	out := map[string]*igaread.AgentRuntimeFacts{}
	if len(subjects) == 0 || ws == uuid.Nil {
		return out, nil
	}
	want := map[string][]string{} // ARN -> immutable keys asked for
	arns := make([]string, 0, len(subjects))
	for _, s := range subjects {
		if _, ok := want[s.ARN]; !ok {
			arns = append(arns, s.ARN)
		}
		want[s.ARN] = append(want[s.ARN], s.ImmutableKey)
	}

	// The identities, with anything to say: model-call evidence, an open
	// finding or alert, a live containment, a pending suggestion.
	var cands []struct {
		ID       uuid.UUID
		NativeID string
		UniqueID string
	}
	if err := tx.Raw(`SELECT ci.id, ci.native_id, COALESCE(ci.attrs->>'unique_id', '') AS unique_id
	                    FROM cloud_identity ci
	                   WHERE ci.workspace_id = ? AND ci.native_id IN ? AND ci.kind IN ?
	                     AND (EXISTS (SELECT 1 FROM cloud_usage u WHERE u.workspace_id = ci.workspace_id AND u.identity_id = ci.id
	                                     AND u.source = ? AND u.service = ?)
	                       OR EXISTS (SELECT 1 FROM agent_finding f WHERE f.workspace_id = ci.workspace_id AND f.identity_id = ci.id
	                                     AND f.state = ?)
	                       OR EXISTS (SELECT 1 FROM agent_alert a WHERE a.workspace_id = ci.workspace_id AND a.identity_id = ci.id
	                                     AND a.state = ?)
	                       OR EXISTS (SELECT 1 FROM agent_containment c WHERE c.workspace_id = ci.workspace_id AND c.identity_id = ci.id
	                                     AND c.state IN ?)
	                       OR EXISTS (SELECT 1 FROM agent_suggestion s WHERE s.workspace_id = ci.workspace_id AND s.identity_id = ci.id
	                                     AND s.state = ?))
	                   ORDER BY ci.id`,
		ws, arns, []string{models.CloudIdentityIAMRole, models.CloudIdentityIAMUser},
		agentruntime.UsageSource, agentruntime.UsageService, FindingOpen, AgentAlertOpen,
		agentcontain.LiveStates, SuggestionPending).Scan(&cands).Error; err != nil {
		return nil, fmt.Errorf("agent runtime graph: identities: %w", err)
	}
	var ids []uuid.UUID
	arnOf := map[uuid.UUID]string{}
	for _, c := range cands {
		match := false
		for _, imm := range want[c.NativeID] {
			// As idetailActivity: when the graph holds the immutable key,
			// the cloud row must carry the same one.
			if imm == "" || imm == c.UniqueID {
				match = true
			}
		}
		if match {
			ids = append(ids, c.ID)
			arnOf[c.ID] = c.NativeID
		}
	}
	if len(ids) == 0 {
		return out, nil
	}

	st, err := loadAgentRuntimeStateFor(tx, ws, ids)
	if err != nil {
		return nil, fmt.Errorf("agent runtime graph: %w", err)
	}
	alerts, err := arOpenAlerts(tx, ws, ids)
	if err != nil {
		return nil, err
	}
	contains, err := arLiveContainments(tx, ws, ids)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		ident := st.identities[id]
		if ident == nil {
			continue
		}
		f := arGraphFacts(st, ident)
		if a := alerts[id]; a != nil {
			f.OpenAlerts, f.HighestSeverity = a.N, a.severity()
		}
		for _, c := range contains[id] {
			// Another incarnation under the same ARN is not this identity.
			if u := ident.uniqueID(); c.UniqueID != "" && u != "" && c.UniqueID != u {
				continue
			}
			f.Containments = append(f.Containments, c.facts())
		}
		out[arnOf[id]] = f
	}
	return out, nil
}

// arGraphFacts is one identity's facts from the state, by the inference
// service's rules: the identity's label is the resolver's (subjectFromState:
// agent when any workload on it is an agent, else the AI workload's label);
// a workload's is agent when it is one, else the AI workload's label when it
// is the identity's one workload.
func arGraphFacts(st *agentRuntimeState, ident *arIdentity) *igaread.AgentRuntimeFacts {
	f := &igaread.AgentRuntimeFacts{
		Label:        subjectFromState(st, ident).Label,
		OpenFindings: st.openFindings[ident.ID],
		Workloads:    map[uuid.UUID]igaread.AgentRuntimeWorkloadFacts{},
	}
	u := st.usage[ident.ID]
	if u == nil {
		u = &arUsage{IdentityID: ident.ID, ConnectorID: ident.ConnectorID}
	}
	ai := st.buildAIWorkload(ident, u)
	if isAIWorkload(u.usage) {
		f.AIWorkload = true
		f.Calls, f.Denied, f.LastCallAt, f.Models = u.usage.Calls, u.usage.Denied, u.usage.LastCallAt, arNonNil(u.usage.Models)
	}
	one := ai.single()
	if one != nil && one.GraphID != nil {
		gid := *one.GraphID
		f.SingleWorkload = &gid
	}
	if ai.Suggestion != nil {
		f.Suggestion = &igaread.AgentRuntimeSuggestion{ID: ai.Suggestion.ID, State: ai.Suggestion.State}
	}
	for _, w := range st.workloads[ident.ID] {
		if w.GraphID == nil {
			continue
		}
		wf := igaread.AgentRuntimeWorkloadFacts{CloudWorkloadID: w.ID}
		switch {
		case w.isAgent():
			wf.Label = agentruntime.LabelAgent
		case f.AIWorkload && one == w:
			wf.Label = ai.Label
		}
		if s := st.suggestions[*w.GraphID]; s != nil {
			wf.Suggestion = &igaread.AgentRuntimeSuggestion{ID: s.ID, State: s.State}
		}
		f.Workloads[*w.GraphID] = wf
	}
	return f
}

// loadAgentRuntimeStateFor is loadAgentRuntimeState for a set of identities:
// the same statements, each for all of them at once.
func loadAgentRuntimeStateFor(tx *gorm.DB, ws uuid.UUID, ids []uuid.UUID) (*agentRuntimeState, error) {
	st := &agentRuntimeState{
		connectors: map[uuid.UUID]arConnector{}, identities: map[uuid.UUID]*arIdentity{},
		usage: map[uuid.UUID]*arUsage{}, workloads: map[uuid.UUID][]*arWorkload{},
		k8s: map[uuid.UUID][]string{}, saml: map[uuid.UUID]bool{},
		suggestions: map[uuid.UUID]*arSuggestion{}, openFindings: map[uuid.UUID]int{},
	}
	var conns []arConnector
	if err := tx.Table("cloud_connector").Select("id, scope_id, attrs").
		Where("workspace_id = ? AND provider = ?", ws, models.CloudProviderAWS).Scan(&conns).Error; err != nil {
		return nil, fmt.Errorf("read connectors: %w", err)
	}
	if len(conns) == 0 {
		return st, nil
	}
	connIDs := make([]uuid.UUID, 0, len(conns))
	for _, c := range conns {
		st.connectors[c.ID] = c
		connIDs = append(connIDs, c.ID)
	}

	var usage []*arUsage
	if err := tx.Table("cloud_usage").Select("id, connector_id, identity_id, attrs").
		Where("workspace_id = ? AND source = ? AND service = ? AND connector_id IN ? AND identity_id IN ?",
			ws, agentruntime.UsageSource, agentruntime.UsageService, connIDs, ids).Scan(&usage).Error; err != nil {
		return nil, fmt.Errorf("read model-call usage: %w", err)
	}
	for _, u := range usage {
		if len(u.Attrs) > 0 {
			_ = json.Unmarshal(u.Attrs, &u.usage)
		}
		st.usage[u.IdentityID] = u
	}

	var idents []*arIdentity
	if err := tx.Table("cloud_identity").Select("id, connector_id, kind, native_id, name, attrs").
		Where("workspace_id = ? AND id IN ?", ws, ids).Scan(&idents).Error; err != nil {
		return nil, fmt.Errorf("read identities: %w", err)
	}
	for _, i := range idents {
		st.identities[i.ID] = i
	}

	var wls []*arWorkload
	if err := tx.Table("cloud_workload").
		Select("id, connector_id, identity_id, runtime_kind, native_id, name, region, attrs").
		Where("workspace_id = ? AND identity_id IN ?", ws, ids).Order("name, id").Scan(&wls).Error; err != nil {
		return nil, fmt.Errorf("read workloads: %w", err)
	}
	if err := attachGraph(tx, ws, st.connectors, wls); err != nil {
		return nil, err
	}
	for _, w := range wls {
		if w.IdentityID != nil {
			st.workloads[*w.IdentityID] = append(st.workloads[*w.IdentityID], w)
		}
	}

	var edges []arEdge
	if err := tx.Table("cloud_assume_edge").Select("identity_id, subject_kind, subject, mechanism, k8s_ref").
		Where("workspace_id = ? AND identity_id IN ? AND (subject_kind = ? OR mechanism = ?)",
			ws, ids, models.AssumeSubjectK8sSA, arMechanismSAML).Scan(&edges).Error; err != nil {
		return nil, fmt.Errorf("read assume edges: %w", err)
	}
	for _, e := range edges {
		switch {
		case e.SubjectKind == models.AssumeSubjectK8sSA:
			ref := e.Subject
			if e.K8sRef != nil && *e.K8sRef != "" {
				ref = *e.K8sRef
			}
			st.k8s[e.IdentityID] = arAppendUnique(st.k8s[e.IdentityID], ref)
		case e.Mechanism == arMechanismSAML:
			st.saml[e.IdentityID] = true
		}
	}

	var graphIDs []uuid.UUID
	for _, w := range wls {
		if w.GraphID != nil {
			graphIDs = append(graphIDs, *w.GraphID)
		}
	}
	if len(graphIDs) > 0 {
		var sugg []*arSuggestion
		if err := tx.Table("agent_suggestion").Select("id, workload_id, state, reason").
			Where("workspace_id = ? AND workload_id IN ?", ws, graphIDs).Scan(&sugg).Error; err != nil {
			return nil, fmt.Errorf("read suggestions: %w", err)
		}
		for _, s := range sugg {
			st.suggestions[s.WorkloadID] = s
		}
	}

	var counts []struct {
		IdentityID uuid.UUID
		N          int
	}
	if err := tx.Table("agent_finding").Select("identity_id, count(*) AS n").
		Where("workspace_id = ? AND state = ? AND identity_id IN ?", ws, FindingOpen, ids).
		Group("identity_id").Scan(&counts).Error; err != nil {
		return nil, fmt.Errorf("count findings: %w", err)
	}
	for _, c := range counts {
		st.openFindings[c.IdentityID] = c.N
	}
	return st, nil
}

// arAlertCount is one identity's open alerts and their highest severity.
type arAlertCount struct {
	IdentityID uuid.UUID
	N          int
	Rank       int
}

func (a *arAlertCount) severity() string {
	switch a.Rank {
	case 2:
		return detect.SeverityHigh
	case 1:
		return detect.SeverityMedium
	}
	return ""
}

func arOpenAlerts(tx *gorm.DB, ws uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]*arAlertCount, error) {
	var rows []*arAlertCount
	if err := tx.Table("agent_alert").
		Select("identity_id, count(*) AS n, max(CASE severity WHEN ? THEN 2 WHEN ? THEN 1 ELSE 0 END) AS rank",
			detect.SeverityHigh, detect.SeverityMedium).
		Where("workspace_id = ? AND state = ? AND identity_id IN ?", ws, AgentAlertOpen, ids).
		Group("identity_id").Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("agent runtime graph: alerts: %w", err)
	}
	out := map[uuid.UUID]*arAlertCount{}
	for _, r := range rows {
		out[r.IdentityID] = r
	}
	return out, nil
}

// arContainRow is one live agent_containment row.
type arContainRow struct {
	ID          uuid.UUID
	IdentityID  uuid.UUID
	UniqueID    string
	Level       string
	State       string
	Effective   *bool
	WorkloadIDs pq.StringArray `gorm:"column:workload_ids;type:uuid[]"`
}

func (c arContainRow) facts() igaread.AgentRuntimeContainment {
	out := igaread.AgentRuntimeContainment{ID: c.ID, Level: c.Level, State: c.State, Effective: c.Effective,
		InForce: arInForce[c.State]}
	for _, s := range c.WorkloadIDs {
		if id, err := uuid.Parse(s); err == nil {
			out.WorkloadIDs = append(out.WorkloadIDs, id)
		}
	}
	return out
}

func arLiveContainments(tx *gorm.DB, ws uuid.UUID, ids []uuid.UUID) (map[uuid.UUID][]arContainRow, error) {
	var rows []arContainRow
	if err := tx.Table("agent_containment").
		Select("id, identity_id, unique_id, level, state, effective, workload_ids").
		Where("workspace_id = ? AND identity_id IN ? AND state IN ?", ws, ids, agentcontain.LiveStates).
		Order("created_at DESC, id").Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("agent runtime graph: containments: %w", err)
	}
	out := map[uuid.UUID][]arContainRow{}
	for _, r := range rows {
		out[r.IdentityID] = append(out[r.IdentityID], r)
	}
	return out, nil
}
