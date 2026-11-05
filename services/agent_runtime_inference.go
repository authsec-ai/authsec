package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/agentruntime"
	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

/* agent_runtime_inference.go turns the model-call evidence an AWS scan stores
   (cloud_usage, source='cloudtrail', service='bedrock';
   agentruntime.ModelCallUsage) into what the console shows
   (SPEC-agent-runtime-visibility.md §5.2, §5.3, §5.5, §10):

     - AI workload: an identity seen calling a model (calls > 0 or refused
       calls > 0), tied to the workloads that run as it (cloud_workload, and
       the EKS service accounts of IRSA / Pod Identity edges). Evidence only.
     - Suggested agent: an AI workload that is the ONLY workload on its
       identity and whose identity also called other services in the same
       window (rule aws_agent_suggest_v1). Stored in agent_suggestion, one row
       per workload incarnation; never sets classification.
     - Agent: iga_workload.classification provider_native_agent (projector)
       or classified_agent (a person, the existing Classify action).

   Attribution is by the identity CloudTrail names (session issuer ARN and
   RoleId), never by a name: session names are recorded as unverified weak
   evidence only (§10 "§5.2 change"). A role with several workloads gets a
   shared_role finding and no suggestion (§10 Q1).

   Every statement runs in one transaction under row-level security for the
   workspace (tenancy.InWorkspace / InWorkspaceRead). */

// Rule identity (§5.3).
const (
	AgentSuggestRule        = "aws_agent_suggest_v1"
	AgentSuggestRuleVersion = 1
)

// agent_suggestion states.
const (
	SuggestionPending    = "pending"
	SuggestionConfirmed  = "confirmed"
	SuggestionDismissed  = "dismissed"
	SuggestionSuperseded = "superseded"
)

// Reasons a suggestion is superseded by the system.
const (
	SupersededClassified = "classified"
	SupersededSharedRole = "shared_role"
)

// agent_finding kinds and states (§5.5).
const (
	FindingSharedRole       = "shared_role"
	FindingHumanCredentials = "human_credentials"
	FindingLongLivedKey     = "long_lived_key"
	FindingModelKeySecret   = "model_key_secret"

	FindingOpen     = "open"
	FindingResolved = "resolved"
)

// AgentRuntimeService is inference, its reads and the suggestion decisions.
type AgentRuntimeService struct {
	db  *gorm.DB
	now func() time.Time
	// classifier is the classification decision service Confirm runs; nil
	// builds one over db.
	classifier *ClassificationService
}

// NewAgentRuntimeService builds the service over db.
func NewAgentRuntimeService(db *gorm.DB) *AgentRuntimeService {
	return &AgentRuntimeService{db: db, now: time.Now}
}

// WithClassifier installs the classification service Confirm runs (tests).
func (s *AgentRuntimeService) WithClassifier(c *ClassificationService) *AgentRuntimeService {
	cp := *s
	cp.classifier = c
	return &cp
}

// WithClock overrides the clock (tests).
func (s *AgentRuntimeService) WithClock(f func() time.Time) *AgentRuntimeService {
	cp := *s
	cp.now = f
	return &cp
}

/* ------------------------------- the scan hook ------------------------------ */

// AgentInferenceResult reports one inference run.
type AgentInferenceResult struct {
	AIWorkloads      int
	SuggestionsNew   int
	SuggestionsOpen  int
	Superseded       int
	FindingsOpen     int
	FindingsResolved int
	AgentsMirrored   int
}

// RunAgentInferenceAfterScan is the scan worker's hook: it runs inference for
// the connector a scan just published, logs the outcome, and never fails or
// panics the scan -- inference reads only what discovery already stored.
func RunAgentInferenceAfterScan(ctx context.Context, db *gorm.DB, ws, connectorID uuid.UUID) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("agent runtime inference: ws=%s connector=%s: panic: %v", ws, connectorID, r)
		}
	}()
	res, err := NewAgentRuntimeService(db).RunAgentInference(ctx, ws, connectorID)
	if err != nil {
		log.Printf("agent runtime inference: ws=%s connector=%s: %v", ws, connectorID, err)
		return
	}
	log.Printf("agent runtime inference: ws=%s connector=%s: %d AI workloads, %d new suggestions (%d pending), %d superseded, %d findings open, %d resolved, %d agents mirrored",
		ws, connectorID, res.AIWorkloads, res.SuggestionsNew, res.SuggestionsOpen, res.Superseded,
		res.FindingsOpen, res.FindingsResolved, res.AgentsMirrored)
}

// RunAgentInference recomputes one connector's AI workloads, suggestions,
// findings and the Agents-list mirror, in one transaction under row-level
// security for ws: all of it lands, or (on an error) none of it.
func (s *AgentRuntimeService) RunAgentInference(ctx context.Context, ws, connectorID uuid.UUID) (AgentInferenceResult, error) {
	var res AgentInferenceResult
	if ws == uuid.Nil || connectorID == uuid.Nil {
		return res, errors.New("agent runtime inference: workspace and connector are required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	now := s.now().UTC()
	err := tenancy.InWorkspace(ctx, s.db, ws, func(tx *gorm.DB) error {
		res = AgentInferenceResult{}
		st, err := loadAgentRuntimeState(tx, ws, &connectorID, nil)
		if err != nil {
			return err
		}
		if _, ok := st.connectors[connectorID]; !ok {
			return nil // not an AWS connector of this workspace: nothing to infer
		}
		ais := st.aiWorkloads()
		res.AIWorkloads = len(ais)

		secrets, err := loadModelKeySecrets(tx, ws, st.connectors[connectorID])
		if err != nil {
			return fmt.Errorf("model-key secrets: %w", err)
		}
		if err := s.applySuggestions(tx, ws, connectorID, st, ais, secrets, now, &res); err != nil {
			return fmt.Errorf("suggestions: %w", err)
		}
		if err := s.applyFindings(tx, ws, connectorID, st, ais, secrets, now, &res); err != nil {
			return fmt.Errorf("findings: %w", err)
		}
		n, err := mirrorAWSAgents(tx, ws, st.connectors[connectorID], now)
		if err != nil {
			return fmt.Errorf("agents mirror: %w", err)
		}
		res.AgentsMirrored = n
		return nil
	})
	return res, err
}

/* --------------------------------- the state -------------------------------- */

type arConnector struct {
	ID      uuid.UUID
	ScopeID string
	Attrs   json.RawMessage
}

func (c arConnector) partition() string {
	cc := models.CloudConnector{Attrs: c.Attrs}
	return cc.AWSAttrs().Partition
}

type arIdentity struct {
	ID          uuid.UUID
	ConnectorID uuid.UUID
	Kind        string
	NativeID    string
	Name        string
	Attrs       json.RawMessage
}

func (i *arIdentity) uniqueID() string {
	ci := models.CloudIdentity{Attrs: i.Attrs}
	return ci.AWSAttrs().UniqueID
}

// subjectKey is the identity's finding key: its ARN and, when collected, the
// immutable id, so a role recreated under the same ARN is a new subject.
func (i *arIdentity) subjectKey() string {
	if u := i.uniqueID(); u != "" {
		return i.NativeID + "#" + u
	}
	return i.NativeID
}

func (i *arIdentity) displayName() string {
	if i.Name != "" {
		return i.Name
	}
	return i.NativeID
}

type arWorkload struct {
	ID          uuid.UUID
	ConnectorID uuid.UUID
	IdentityID  *uuid.UUID
	RuntimeKind string
	NativeID    string
	Name        string
	Region      string
	Attrs       json.RawMessage

	// The graph's row for this workload (iga_workload): nil until projected.
	GraphID               *uuid.UUID
	Classification        string
	ClassificationVersion int64
}

func (w *arWorkload) isAgent() bool {
	return w.Classification == models.ClassificationProviderAgent ||
		w.Classification == models.ClassificationClassified
}

type arUsage struct {
	ID          uuid.UUID
	ConnectorID uuid.UUID
	IdentityID  uuid.UUID
	Attrs       json.RawMessage
	usage       agentruntime.ModelCallUsage
}

type arEdge struct {
	IdentityID  uuid.UUID
	SubjectKind string
	Subject     string
	Mechanism   string
	K8sRef      *string
}

type arSuggestion struct {
	ID         uuid.UUID
	WorkloadID uuid.UUID
	State      string
	Reason     string
}

// agentRuntimeState is what one read loads: the AWS connectors in scope, the
// model-call usage, the identities and workloads it names, the graph's
// classification of those workloads, and the suggestions on them.
type agentRuntimeState struct {
	connectors   map[uuid.UUID]arConnector
	identities   map[uuid.UUID]*arIdentity
	usage        map[uuid.UUID]*arUsage      // by identity
	workloads    map[uuid.UUID][]*arWorkload // by identity
	k8s          map[uuid.UUID][]string      // k8s service accounts, by identity
	saml         map[uuid.UUID]bool          // identities a SAML provider may assume
	suggestions  map[uuid.UUID]*arSuggestion // by graph workload id
	openFindings map[uuid.UUID]int           // open findings, by identity
}

// loadAgentRuntimeState reads the state for the workspace, optionally only one
// connector's and/or one identity's. Every statement is workspace-qualified
// and runs on tx, a transaction under row-level security for ws.
func loadAgentRuntimeState(tx *gorm.DB, ws uuid.UUID, connector, identity *uuid.UUID) (*agentRuntimeState, error) {
	st := &agentRuntimeState{
		connectors: map[uuid.UUID]arConnector{}, identities: map[uuid.UUID]*arIdentity{},
		usage: map[uuid.UUID]*arUsage{}, workloads: map[uuid.UUID][]*arWorkload{},
		k8s: map[uuid.UUID][]string{}, saml: map[uuid.UUID]bool{},
		suggestions: map[uuid.UUID]*arSuggestion{}, openFindings: map[uuid.UUID]int{},
	}

	var conns []arConnector
	q := tx.Table("cloud_connector").Select("id, scope_id, attrs").
		Where("workspace_id = ? AND provider = ?", ws, models.CloudProviderAWS)
	if connector != nil {
		q = q.Where("id = ?", *connector)
	}
	if err := q.Scan(&conns).Error; err != nil {
		return nil, fmt.Errorf("read connectors: %w", err)
	}
	for _, c := range conns {
		st.connectors[c.ID] = c
	}
	if len(conns) == 0 {
		return st, nil
	}
	connIDs := make([]uuid.UUID, 0, len(conns))
	for _, c := range conns {
		connIDs = append(connIDs, c.ID)
	}

	// Model-call evidence (P1a's contract).
	var usage []*arUsage
	uq := tx.Table("cloud_usage").Select("id, connector_id, identity_id, attrs").
		Where("workspace_id = ? AND source = ? AND service = ? AND connector_id IN ?",
			ws, agentruntime.UsageSource, agentruntime.UsageService, connIDs)
	if identity != nil {
		uq = uq.Where("identity_id = ?", *identity)
	}
	if err := uq.Scan(&usage).Error; err != nil {
		return nil, fmt.Errorf("read model-call usage: %w", err)
	}
	idSet := map[uuid.UUID]bool{}
	for _, u := range usage {
		if len(u.Attrs) > 0 {
			_ = json.Unmarshal(u.Attrs, &u.usage)
		}
		st.usage[u.IdentityID] = u
		idSet[u.IdentityID] = true
	}
	if identity != nil {
		idSet[*identity] = true
	}
	if len(idSet) == 0 {
		return st, nil
	}
	ids := make([]uuid.UUID, 0, len(idSet))
	for id := range idSet {
		ids = append(ids, id)
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

// arMechanismSAML is the trust edge of a role a SAML provider may assume
// (awsdiscovery.MechanismSAMLFederation): a federated human session.
const arMechanismSAML = "saml_federation"

// attachGraph sets each workload's iga_workload row: the active AWS row whose
// source key is the workload's recognition key (igagraph.WorkloadKey, the one
// formatter of that key).
func attachGraph(tx *gorm.DB, ws uuid.UUID, conns map[uuid.UUID]arConnector, wls []*arWorkload) error {
	byKey := map[string][]*arWorkload{}
	var keys []string
	for _, w := range wls {
		c, ok := conns[w.ConnectorID]
		if !ok {
			// A workload of another connector on this identity: read its
			// connector too (rare: a cross-account role).
			var cc []arConnector
			if err := tx.Table("cloud_connector").Select("id, scope_id, attrs").
				Where("workspace_id = ? AND id = ?", ws, w.ConnectorID).Scan(&cc).Error; err != nil {
				return fmt.Errorf("read connector: %w", err)
			}
			if len(cc) == 0 {
				continue
			}
			c = cc[0]
			conns[c.ID] = c
		}
		key := igagraph.WorkloadKey(models.CloudWorkload{RuntimeKind: w.RuntimeKind, Region: w.Region, NativeID: w.NativeID},
			c.partition(), c.ScopeID)
		if _, seen := byKey[key]; !seen {
			keys = append(keys, key)
		}
		byKey[key] = append(byKey[key], w)
	}
	for start := 0; start < len(keys); start += 500 {
		end := start + 500
		if end > len(keys) {
			end = len(keys)
		}
		var rows []struct {
			ID                    uuid.UUID
			SourceKey             string
			Classification        string
			ClassificationVersion int64
		}
		if err := tx.Table("iga_workload").Select("id, source_key, classification, classification_version").
			Where("workspace_id = ? AND provider = ? AND lifecycle = ? AND source_key IN ?",
				ws, models.ProviderAWS, models.IGALifecycleActive, keys[start:end]).Scan(&rows).Error; err != nil {
			return fmt.Errorf("read graph workloads: %w", err)
		}
		for _, r := range rows {
			for _, w := range byKey[r.SourceKey] {
				id := r.ID
				w.GraphID, w.Classification, w.ClassificationVersion = &id, r.Classification, r.ClassificationVersion
			}
		}
	}
	return nil
}

/* ------------------------------ the AI workloads ---------------------------- */

// AIWorkload is one identity seen calling a model, with what runs as it.
type AIWorkload struct {
	Identity           AIIdentityRef    `json:"identity"`
	Workloads          []AIWorkloadRef  `json:"workloads"`
	K8sServiceAccounts []string         `json:"k8s_service_accounts"`
	Label              string           `json:"label"`
	SharedRole         bool             `json:"shared_role"`
	Calls              int              `json:"calls"`
	Errors             int              `json:"errors"`
	Denied             int              `json:"denied"`
	Tokens             int64            `json:"tokens"`
	Models             map[string]int   `json:"models"`
	Endpoints          map[string]int   `json:"endpoints"`
	OtherServices      map[string]int   `json:"other_services"`
	FirstCallAt        *time.Time       `json:"first_call_at"`
	LastCallAt         *time.Time       `json:"last_call_at"`
	Coverage           AICoverage       `json:"coverage"`
	SessionNames       AISessionNames   `json:"session_names"`
	Suggestion         *AISuggestionRef `json:"suggestion"`
	OpenFindings       int              `json:"open_findings"`
	UsageID            uuid.UUID        `json:"usage_id"`
	// Live is what the event stream showed since the scan's coverage
	// (agent_runtime_live.go); SeenLive: a model call of it was ever seen
	// live.
	Live     AILiveEvidence `json:"live"`
	SeenLive bool           `json:"seen_live"`

	ident  *arIdentity
	wls    []*arWorkload
	usageR *arUsage
}

// AILiveEvidence is the live model-call evidence not yet in the scan's exact
// counts (ModelCallUsage.Live*).
type AILiveEvidence struct {
	Calls      int            `json:"calls"`
	Denied     int            `json:"denied"`
	LastCallAt *time.Time     `json:"last_call_at"`
	Models     map[string]int `json:"models"`
}

// AIIdentityRef is the identity the calls are attributed to.
type AIIdentityRef struct {
	ID          uuid.UUID `json:"id"`
	ConnectorID uuid.UUID `json:"connector_id"`
	Kind        string    `json:"kind"`
	ARN         string    `json:"arn"`
	Name        string    `json:"name"`
}

// AIWorkloadRef is one workload that runs as the identity.
type AIWorkloadRef struct {
	CloudWorkloadID uuid.UUID  `json:"cloud_workload_id"`
	WorkloadID      *uuid.UUID `json:"workload_id"` // iga_workload; null until projected
	Name            string     `json:"name"`
	RuntimeKind     string     `json:"runtime_kind"`
	NativeID        string     `json:"native_id"`
	Region          string     `json:"region"`
	Classification  string     `json:"classification"`
}

// AICoverage is what the evidence covers; "no calls" is never claimed past it.
type AICoverage struct {
	From    *time.Time `json:"from"`
	To      *time.Time `json:"to"`
	Partial bool       `json:"partial"`
}

// AISessionNames are the role session names seen: unverified weak evidence,
// never attribution (§10 "§5.2 change").
type AISessionNames struct {
	Values   []string          `json:"values"`
	Verified bool              `json:"verified"`
	Matches  []AISessionNameOn `json:"matches"`
}

// AISessionNameOn is a session name equal to a candidate workload's name.
type AISessionNameOn struct {
	SessionName     string    `json:"session_name"`
	CloudWorkloadID uuid.UUID `json:"cloud_workload_id"`
	Strength        string    `json:"strength"` // always "weak_unverified"
}

// AISuggestionRef is the suggestion on the AI workload's one workload.
type AISuggestionRef struct {
	ID    uuid.UUID `json:"id"`
	State string    `json:"state"`
}

// isAIWorkload: seen calling a model, or refused one (the tag-gated template's
// deny mode makes the untagged AI workloads show as refusals, §5.4), by the
// scan or live (the event stream, before the next scan).
func isAIWorkload(u agentruntime.ModelCallUsage) bool {
	return u.Calls > 0 || u.Denied > 0 || u.LiveCalls > 0 || u.LiveDenied > 0
}

// aiWorkloads builds every AI workload of the state, sorted by identity id.
func (st *agentRuntimeState) aiWorkloads() []*AIWorkload {
	var out []*AIWorkload
	for idID, u := range st.usage {
		if !isAIWorkload(u.usage) {
			continue
		}
		ident := st.identities[idID]
		if ident == nil {
			continue
		}
		out = append(out, st.buildAIWorkload(ident, u))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identity.ID.String() < out[j].Identity.ID.String() })
	return out
}

func (st *agentRuntimeState) buildAIWorkload(ident *arIdentity, u *arUsage) *AIWorkload {
	wls := st.workloads[ident.ID]
	k8s := st.k8s[ident.ID]
	ai := &AIWorkload{
		Identity: AIIdentityRef{ID: ident.ID, ConnectorID: ident.ConnectorID, Kind: ident.Kind,
			ARN: ident.NativeID, Name: ident.displayName()},
		Workloads: []AIWorkloadRef{}, K8sServiceAccounts: append([]string{}, k8s...),
		SharedRole: len(wls)+len(k8s) > 1,
		Calls:      u.usage.Calls, Errors: u.usage.Errors, Denied: u.usage.Denied, Tokens: u.usage.Tokens,
		Models: arNonNil(u.usage.Models), Endpoints: arNonNil(u.usage.Endpoints),
		OtherServices: arNonNil(u.usage.OtherServices),
		FirstCallAt:   u.usage.FirstCallAt, LastCallAt: u.usage.LastCallAt,
		Coverage:     AICoverage{From: u.usage.CoveredFrom, To: u.usage.CoveredTo, Partial: u.usage.Partial},
		OpenFindings: st.openFindings[ident.ID],
		UsageID:      u.ID,
		Live: AILiveEvidence{Calls: u.usage.LiveCalls, Denied: u.usage.LiveDenied,
			LastCallAt: u.usage.LiveLastCallAt, Models: arNonNil(u.usage.LiveModels)},
		SeenLive: u.usage.LiveLastCallAt != nil,
		ident:    ident, wls: wls, usageR: u,
	}
	for _, w := range wls {
		ai.Workloads = append(ai.Workloads, AIWorkloadRef{CloudWorkloadID: w.ID, WorkloadID: w.GraphID,
			Name: w.Name, RuntimeKind: w.RuntimeKind, NativeID: w.NativeID, Region: w.Region,
			Classification: arClassification(w)})
	}
	ai.SessionNames = sessionNameEvidence(u.usage.SessionNames, wls)
	if one := ai.single(); one != nil && one.GraphID != nil {
		if s := st.suggestions[*one.GraphID]; s != nil {
			ai.Suggestion = &AISuggestionRef{ID: s.ID, State: s.State}
		}
	}
	ai.Label = st.label(ai)
	return ai
}

// single is the AI workload's one workload: exactly one candidate on the
// identity and it is a collected workload (not an EKS service account).
func (ai *AIWorkload) single() *arWorkload {
	if len(ai.wls) == 1 && len(ai.K8sServiceAccounts) == 0 {
		return ai.wls[0]
	}
	return nil
}

// label is the strongest label (§1): agent when its one workload is an agent
// (provider-native or classified), suggested agent when it has a pending
// suggestion or the rule matches and the incarnation was never dismissed or
// confirmed, otherwise AI workload. A shared role is never more than an AI
// workload (§10 Q1): the calls cannot be tied to one of its workloads.
func (st *agentRuntimeState) label(ai *AIWorkload) string {
	one := ai.single()
	if one == nil {
		return agentruntime.LabelAIWorkload
	}
	if one.isAgent() {
		return agentruntime.LabelAgent
	}
	if one.GraphID != nil {
		if s := st.suggestions[*one.GraphID]; s != nil {
			switch {
			case s.State == SuggestionPending:
				return agentruntime.LabelSuggestedAgent
			case s.State == SuggestionSuperseded && s.Reason == SupersededSharedRole:
				// The role was split since: the rule decides again below.
			default:
				// Dismissed, confirmed, or superseded by a classification: this
				// incarnation is never suggested again.
				return agentruntime.LabelAIWorkload
			}
		}
	}
	if ok, _ := suggestEligible(ai.usageR.usage, ai.single(), len(ai.wls)+len(ai.K8sServiceAccounts)); ok {
		return agentruntime.LabelSuggestedAgent
	}
	return agentruntime.LabelAIWorkload
}

func arClassification(w *arWorkload) string {
	if w.GraphID == nil {
		return ""
	}
	return w.Classification
}

// sessionNameEvidence records the session names and which candidate's name
// equals one: weak, unverified evidence (the Lambda = function name and ECS =
// task id claims are in the P1 lab acceptance, §10).
func sessionNameEvidence(names []string, wls []*arWorkload) AISessionNames {
	out := AISessionNames{Values: append([]string{}, names...), Verified: false, Matches: []AISessionNameOn{}}
	for _, n := range names {
		for _, w := range wls {
			if n != "" && (n == w.Name || strings.HasSuffix(w.NativeID, "/"+n) || strings.HasSuffix(w.NativeID, ":"+n)) {
				out.Matches = append(out.Matches, AISessionNameOn{SessionName: n, CloudWorkloadID: w.ID, Strength: "weak_unverified"})
			}
		}
	}
	return out
}

/* ------------------------------- the API reads ------------------------------ */

// AIWorkloadFilter is GET /agent-runtime/ai-workloads's parameters.
type AIWorkloadFilter struct {
	ConnectorID *uuid.UUID
	Label       string
	Cursor      string // the last identity id of the previous page
	Limit       int
}

// AIWorkloadLabels are the label filter's legal values.
var AIWorkloadLabels = map[string]bool{
	agentruntime.LabelAIWorkload: true, agentruntime.LabelSuggestedAgent: true, agentruntime.LabelAgent: true,
}

// DefaultAgentRuntimePage is a list page when no limit is given.
const DefaultAgentRuntimePage = 50

// ListAIWorkloads returns the workspace's AI workloads, by identity id, with
// a cursor to the next page. The workspace is the token's: every statement
// runs under row-level security for it.
func (s *AgentRuntimeService) ListAIWorkloads(ctx context.Context, ws uuid.UUID, f AIWorkloadFilter) ([]*AIWorkload, *string, error) {
	if f.Label != "" && !AIWorkloadLabels[f.Label] {
		return nil, nil, GovBadParam("label", "label must be ai_workload, suggested_agent or agent.")
	}
	if f.Cursor != "" {
		if _, err := uuid.Parse(f.Cursor); err != nil {
			return nil, nil, GovBadParam("cursor", "cursor is not one this server issued.")
		}
	}
	limit := f.Limit
	if limit <= 0 {
		limit = DefaultAgentRuntimePage
	}
	var all []*AIWorkload
	err := tenancy.InWorkspaceRead(ctx, s.db, ws, func(tx *gorm.DB) error {
		st, err := loadAgentRuntimeState(tx, ws, f.ConnectorID, nil)
		if err != nil {
			return err
		}
		all = st.aiWorkloads()
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	out := []*AIWorkload{}
	var next *string
	for _, ai := range all {
		if f.Cursor != "" && ai.Identity.ID.String() <= f.Cursor {
			continue
		}
		if f.Label != "" && ai.Label != f.Label {
			continue
		}
		if len(out) == limit {
			c := out[len(out)-1].Identity.ID.String()
			next = &c
			break
		}
		out = append(out, ai)
	}
	return out, next, nil
}

/* ------------------------------ the resolver ------------------------------- */

// agentRuntimeResolver implements agentruntime.SubjectResolver for detections
// and containment: an event's attribution (session issuer or IAM user, by ARN
// and immutable id, never by name) to the identity, its workloads, its label
// and whether its role is shared, within one workspace.
type agentRuntimeResolver struct{ db *gorm.DB }

// InstallAgentRuntimeResolver installs the resolver (cmd/main.go).
func InstallAgentRuntimeResolver(db *gorm.DB) {
	agentruntime.SetResolver(&agentRuntimeResolver{db: db})
}

// NewAgentRuntimeResolver returns the resolver over db (tests).
func NewAgentRuntimeResolver(db *gorm.DB) agentruntime.SubjectResolver {
	return &agentRuntimeResolver{db: db}
}

// Resolve returns the subject; an attribution that names no identity of the
// workspace (or a different incarnation of it) is the zero subject with the
// connector set, never an error.
func (r *agentRuntimeResolver) Resolve(ctx context.Context, ws, connectorID uuid.UUID, a agentruntime.Attribution) (agentruntime.Subject, error) {
	out := agentruntime.Subject{ConnectorID: connectorID}
	if a.How == "" || a.ARN == "" || ws == uuid.Nil {
		return out, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	err := tenancy.InWorkspaceRead(ctx, r.db, ws, func(tx *gorm.DB) error {
		var idents []*arIdentity
		if err := tx.Table("cloud_identity").Select("id, connector_id, kind, native_id, name, attrs").
			Where("workspace_id = ? AND native_id = ?", ws, a.ARN).Limit(1).Scan(&idents).Error; err != nil {
			return err
		}
		if len(idents) == 0 {
			return nil
		}
		ident := idents[0]
		// Another incarnation under the same ARN is not this identity.
		if u := ident.uniqueID(); a.UniqueID != "" && u != "" && u != a.UniqueID {
			return nil
		}
		st, err := loadAgentRuntimeState(tx, ws, nil, &ident.ID)
		if err != nil {
			return err
		}
		out = subjectFromState(st, ident)
		return nil
	})
	if err != nil {
		return agentruntime.Subject{ConnectorID: connectorID}, err
	}
	return out, nil
}

// subjectFromState is the Subject of one identity. The label is the strongest
// of agent (any workload on it is an agent: the role is an agent's even when
// other workloads share it), suggested agent, AI workload, or "".
func subjectFromState(st *agentRuntimeState, ident *arIdentity) agentruntime.Subject {
	wls := st.workloads[ident.ID]
	sub := agentruntime.Subject{IdentityID: ident.ID, ConnectorID: ident.ConnectorID,
		SharedRole: len(wls)+len(st.k8s[ident.ID]) > 1, Name: ident.displayName()}
	for _, w := range wls {
		sub.WorkloadIDs = append(sub.WorkloadIDs, w.ID)
		if w.isAgent() {
			sub.Label = agentruntime.LabelAgent
		}
	}
	if len(wls) == 1 && len(st.k8s[ident.ID]) == 0 && wls[0].Name != "" {
		sub.Name = wls[0].Name
	}
	if sub.Label != "" {
		return sub
	}
	if u := st.usage[ident.ID]; u != nil && isAIWorkload(u.usage) {
		sub.Label = st.buildAIWorkload(ident, u).Label
	}
	return sub
}

/* --------------------------- the Agents-list mirror ------------------------- */

// AWSAgentFingerprint is a mirrored AWS agent's discovered_agents fingerprint.
func AWSAgentFingerprint(account, runtimeKind, nativeID string) string {
	return "aws:" + account + ":" + runtimeKind + ":" + nativeID
}

// mirrorAWSAgents upserts the connector's agents -- provider-native
// (declared) and classified (inferred) -- into discovered_agents through
// UpsertSighting, so the Agents page lists them (§5.3, Q5 build default). The
// graph stays authoritative for classification; a sighting never moves a
// row's status, owner or claim (UpsertSighting does not update them).
func mirrorAWSAgents(tx *gorm.DB, ws uuid.UUID, conn arConnector, now time.Time) (int, error) {
	var wls []*arWorkload
	if err := tx.Table("cloud_workload").
		Select("id, connector_id, identity_id, runtime_kind, native_id, name, region, attrs").
		Where("workspace_id = ? AND connector_id = ?", ws, conn.ID).Order("id").Scan(&wls).Error; err != nil {
		return 0, fmt.Errorf("read workloads: %w", err)
	}
	if err := attachGraph(tx, ws, map[uuid.UUID]arConnector{conn.ID: conn}, wls); err != nil {
		return 0, err
	}
	var identityARN = map[uuid.UUID]string{}
	var idIDs []uuid.UUID
	for _, w := range wls {
		if w.isAgent() && w.GraphID != nil && w.IdentityID != nil {
			idIDs = append(idIDs, *w.IdentityID)
		}
	}
	if len(idIDs) > 0 {
		var rows []struct {
			ID       uuid.UUID
			NativeID string
		}
		if err := tx.Table("cloud_identity").Select("id, native_id").
			Where("workspace_id = ? AND id IN ?", ws, idIDs).Scan(&rows).Error; err != nil {
			return 0, fmt.Errorf("read identities: %w", err)
		}
		for _, r := range rows {
			identityARN[r.ID] = r.NativeID
		}
	}
	repo := repositories.NewDiscoveryRepository(tx)
	n := 0
	for _, w := range wls {
		if w.GraphID == nil || !w.isAgent() {
			continue
		}
		if _, _, err := repo.UpsertSighting(awsAgentSighting(ws, conn, w, identityARN, now)); err != nil {
			return n, fmt.Errorf("mirror %s: %w", w.NativeID, err)
		}
		n++
	}
	return n, nil
}

func awsAgentSighting(ws uuid.UUID, conn arConnector, w *arWorkload, identityARN map[uuid.UUID]string, now time.Time) *models.DiscoveredAgent {
	mode := models.EvidenceInferred
	if w.Classification == models.ClassificationProviderAgent {
		mode = models.EvidenceDeclared
	}
	role := ""
	if w.IdentityID != nil {
		role = identityARN[*w.IdentityID]
	}
	meta, _ := json.Marshal(map[string]any{
		"provider":        models.CloudProviderAWS,
		"account_id":      conn.ScopeID,
		"connector_id":    conn.ID,
		"region":          w.Region,
		"runtime_kind":    w.RuntimeKind,
		"native_id":       w.NativeID,
		"iga_workload_id": w.GraphID,
		"classification":  w.Classification,
		"role_arn":        role,
	})
	name := w.Name
	if name == "" {
		name = w.NativeID
	}
	return &models.DiscoveredAgent{
		ID: uuid.New(), WorkspaceID: ws, Source: models.DiscoverySourceAWS,
		Fingerprint: AWSAgentFingerprint(conn.ScopeID, w.RuntimeKind, w.NativeID),
		DisplayName: name, Metadata: meta,
		DeploymentOrigin: models.DeploymentOriginUnknown,
		EvidenceMode:     mode,
		// No LastObservedRunningAt: a declared row may not carry one (database
		// constraint), and classification is not an observation that it ran.
		Status:        models.DiscoveredAgentUnregistered,
		RuntimeStatus: models.RuntimeStatusUnknown,
		FirstSeenAt:   now, LastSeenAt: now, SightingCount: 1,
		CreatedBy: "aws-discovery",
	}
}

/* --------------------------------- helpers ---------------------------------- */

func arNonNil(m map[string]int) map[string]int {
	if m == nil {
		return map[string]int{}
	}
	return m
}

func arAppendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
